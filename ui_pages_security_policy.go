package login

// 步骤 72：root 敏感操作目录、策略覆盖/恢复默认页面与安全通知设置交互。
//
// 安全不变量：
//   - 全部路由 UIAccessManagement：宿主 UISessionService 必须用真实
//     session.AuthorizeManagement 判定完整会话与强认证新鲜度；页面不信任任何前端
//     自报的 is_root/角色/权限。
//   - 只有真实 root 能修改系统敏感策略。普通管理员的读取也需要明确独立许可；
//     没有读取许可时不渲染目录内容。页面能力位只影响控件呈现，每次读取与写入都由
//     适配器重建可信 Caller 交给真实 policy.Service，root/再次认证/版本/字段白名单/
//     审计由领域服务强制执行。
//   - 页面不能关闭基础授权、审计、root 保护或 ImmutableSensitive；不提供“关闭授权”
//     “关闭审计”“解除 root 保护”控件，直接提交越权字段也会被字段白名单拒绝。
//   - 默认/覆盖/有效值分列且来源明确；覆盖为 nil 时显示“未设置覆盖”，不用默认值
//     副本伪装覆盖。差异按同快照 Default/Effective 逐字段比较。
//   - 预览不是执行。保存/恢复预览页必须绑定实际操作、作用域、版本与完整拟提交字段；
//     确认不是授权，服务端提交时重新检查身份、root、再次认证、版本与审计。
//   - 每次写入绑定 ExpectedVersion；冲突返回 CONFLICT 后必须重新读取比较，不自动
//     覆盖、不自动合并、不提供“强制覆盖最新版本”。
//   - 修改 security.policy.change 自身保护（或整体恢复包含它）必须额外确认；该确认
//     只是阅读确认，不替代再次认证。
//   - 邮件模板/投递设置区分系统秘密与普通字段；秘密永不回显，只允许在真实替换契约
//     存在时提交新值；空值表示不修改。运行时编辑能力未提供时只显示只读事实，不渲染
//     可提交假表单。
//   - 测试邮件必须由用户明确输入测试收件地址，使用合成内容与已注入的发送器；未配置
//     发送器时显示真实未配置状态，绝不默认向 root/用户资料邮箱外发。

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// UISecurityPolicySystemScope 是步骤 72 固定开放的系统作用域。领域方法仍要求调用者
// 提供 scopeID；页面只使用系统作用域，不开放任意作用域输入或跨应用枚举。
const UISecurityPolicySystemScope = "system"

// UIPageSecurityPolicyOptions 是步骤 72 敏感策略与安全通知页配置。
type UIPageSecurityPolicyOptions struct {
	Backend UISecurityPolicyBackend
	// ValidateCSRF 是宿主提供的页面表单令牌校验器（生产应接
	// session.ValidateCSRFToken 或等价服务端校验）。为 nil 时拒绝构造：页面写/动作
	// 路由不能只依赖可能默认关闭的 transport CSRF 中间件。
	ValidateCSRF func(ctx context.Context, request *http.Request, token string) error
}

// UISecurityPolicyCapabilities 是服务端为当前管理员判定的页面能力位（只是交互辅助；
// 每次读取/写入仍由领域服务重新授权）。
type UISecurityPolicyCapabilities struct {
	ReadPolicies      bool
	WritePolicies     bool
	ReadNotifications bool
	TestMail          bool
	ReplaceSecret     bool
}

// UISecurityPolicyValues 是一条敏感策略的六个可配置字段（机器值）。
type UISecurityPolicyValues struct {
	Sensitive            bool
	ReauthRequired       bool
	MaxAuthAgeSeconds    int64
	Strength             string
	ConfirmationRequired bool
	NotificationRequired bool
}

// StrengthKey 返回认证强度的 i18n 键（未知值安全回退）。
func (v UISecurityPolicyValues) StrengthKey() string {
	switch v.Strength {
	case "none":
		return "page.admin.security_policy.strength.none"
	case "password":
		return "page.admin.security_policy.strength.password"
	case "strong":
		return "page.admin.security_policy.strength.strong"
	default:
		return "page.admin.security_policy.strength.unknown"
	}
}

// UISecurityPolicyOperation 是一条敏感操作在系统作用域下的三值与不可覆盖约束。
type UISecurityPolicyOperation struct {
	OperationID string
	Domain      string
	Name        string
	Description string
	Default     UISecurityPolicyValues
	// HasDefault 报告是否有系统默认值；应用声明操作没有系统默认值。
	HasDefault bool
	// Override 为 nil 表示当前没有覆盖行；存在时是完整覆盖策略。
	Override  *UISecurityPolicyValues
	Effective UISecurityPolicyValues
	// Source 为 default/override/application。
	Source string
	// 以下为不可覆盖约束。
	PermissionKey      string
	RootOnly           bool
	ImmutableSensitive bool
	AuditRequired      bool
	Implemented        bool
	// StrengthAvailable 报告当前环境能否满足该操作有效策略要求的认证强度。
	StrengthAvailable bool
	// ChangedFields 是 Default 与 Effective 不同的字段机器名。
	ChangedFields []string
}

// SourceKey 返回策略来源的 i18n 键。
func (o UISecurityPolicyOperation) SourceKey() string {
	switch o.Source {
	case "default":
		return "page.admin.security_policy.source.default"
	case "override":
		return "page.admin.security_policy.source.override"
	case "application":
		return "page.admin.security_policy.source.application"
	default:
		return "page.admin.security_policy.source.unknown"
	}
}

// DomainKey 返回业务域的 i18n 键。
func (o UISecurityPolicyOperation) DomainKey() string {
	switch o.Domain {
	case "password":
		return "page.admin.security_policy.domain.password"
	case "email":
		return "page.admin.security_policy.domain.email"
	case "mfa":
		return "page.admin.security_policy.domain.mfa"
	case "permission":
		return "page.admin.security_policy.domain.permission"
	case "application":
		return "page.admin.security_policy.domain.application"
	case "backup":
		return "page.admin.security_policy.domain.backup"
	case "audit":
		return "page.admin.security_policy.domain.audit"
	case "session":
		return "page.admin.security_policy.domain.session"
	case "profile":
		return "page.admin.security_policy.domain.profile"
	case "recovery":
		return "page.admin.security_policy.domain.recovery"
	default:
		return "page.admin.security_policy.domain.unknown"
	}
}

// UISecurityPolicySnapshot 是系统作用域当前有效策略快照。
type UISecurityPolicySnapshot struct {
	ScopeID            string
	ScopeName          string
	Version            int64
	CatalogVersion     string
	AvailableStrengths []string
	Operations         []UISecurityPolicyOperation
	// Declared 是应用声明的敏感操作（仅应用作用域；系统作用域通常为空）。
	Declared []UISecurityPolicyOperation
}

// ChangedCount 返回当前确有默认差异的覆盖操作数。
func (s UISecurityPolicySnapshot) ChangedCount() int {
	count := 0
	for _, operation := range s.Operations {
		if operation.Source == "override" && len(operation.ChangedFields) > 0 {
			count++
		}
	}
	return count
}

// OperationCount 返回当前读取到的操作数（不推算全局数量）。
func (s UISecurityPolicySnapshot) OperationCount() int { return len(s.Operations) }

// UISecurityPolicyPreview 是提交前预览（未执行，最终以服务端校验为准）。
type UISecurityPolicyPreview struct {
	OperationID   string
	HasDefault    bool
	Default       UISecurityPolicyValues
	Current       UISecurityPolicyValues
	Proposed      UISecurityPolicyValues
	ChangedFields []string
	DerivedFields []string
	// Token 是服务端签发的一次性预览令牌，绑定 Scope/Operation/版本/完整拟提交值；
	// 保存必须带回，换目标/换参数/重复使用都会被拒绝。
	Token           string
	SelfProtection  bool
	StrengthWarning bool
	NoChanges       bool
}

// UISecurityPolicyWriteResult 是一次真实写入的结果；通知状态不由策略响应提供。
type UISecurityPolicyWriteResult struct {
	Snapshot           UISecurityPolicySnapshot
	Changed            bool
	NotificationStatus string
}

// UISecurityPolicyRestorePreview 是逐项/整体恢复默认的提交前预览。
type UISecurityPolicyRestorePreview struct {
	ScopeID     string
	ScopeName   string
	Version     int64
	All         bool
	OperationID string
	Operations  []UISecurityPolicyOperation
	Declared    []UISecurityPolicyOperation
	// Token 是服务端签发的一次性恢复预览令牌，绑定作用域/版本/真实覆盖清单与
	// 自身保护位；执行必须带回，范围变化或重复使用都会被拒绝。
	Token          string
	SelfProtection bool
	NoChanges      bool
}

// UISecurityPolicyActionBinding 是服务端一次性预览/动作绑定摘要：绑定真实操作者、
// 动作、作用域、目标、版本与完整拟提交值/影响范围摘要。再次认证回调必须把它作为
// 参数摘要使用；目标或参数变化后旧绑定失效（服务端重算比较并一次性消费）。
type UISecurityPolicyActionBinding struct {
	Action             string
	UserID             string
	ScopeID            string
	OperationID        string
	Version            int64
	ChangeDigest       string
	All                bool
	AffectedOperations []string
	AffectedCount      int
	SelfProtection     bool
	// RecipientDigest/Kind 仅用于测试邮件动作（目标摘要，不含明文）。
	RecipientDigest string
	Kind            string
}

// UISecurityPolicyError 是适配层返回的稳定公开错误。
type UISecurityPolicyError struct {
	Code              string
	RetryAfterSeconds int
}

// Error 实现 error。
func (e *UISecurityPolicyError) Error() string { return "敏感策略页面操作失败: " + e.Code }

// UISecurityPolicyBackend 是敏感策略与安全通知页面调用真实服务的最小契约。适配器
// 负责可信 Caller、root/读取许可复核、再次认证与版本；页面层不实现授权。
type UISecurityPolicyBackend interface {
	Capabilities(ctx context.Context, userID string) (UISecurityPolicyCapabilities, error)

	Snapshot(ctx context.Context, userID, scopeID string) (UISecurityPolicySnapshot, error)
	PreviewPolicy(ctx context.Context, userID, scopeID, operationID string,
		change UISecurityPolicyValues) (UISecurityPolicyPreview, error)
	SavePolicy(ctx context.Context, userID, scopeID, operationID string,
		change UISecurityPolicyValues, expectedVersion int64, previewToken,
		requestID string) (UISecurityPolicyWriteResult, error)
	PreviewRestore(ctx context.Context, userID, scopeID, operationID string,
		all bool) (UISecurityPolicyRestorePreview, error)
	RestorePolicy(ctx context.Context, userID, scopeID, operationID string, all bool,
		expectedVersion int64, previewToken, requestID string) (UISecurityPolicyWriteResult, error)

	NotificationSettings(ctx context.Context, userID string) (UINotificationSettings, error)
	PreviewTemplate(ctx context.Context, userID, kind string) (UINotificationTemplatePreview, error)
	SendTestMail(ctx context.Context, userID, recipient, kind, idempotencyKey,
		requestID string) (UINotificationTestResult, error)
	ReplaceSMTPSecret(ctx context.Context, userID, newSecret, idempotencyKey,
		requestID string) (UINotificationSecretResult, error)
}

// UINotificationCapabilities 是通知设置页面能力位（只是交互辅助）。
type UINotificationCapabilities struct {
	Read          bool
	TestMail      bool
	ReplaceSecret bool
}

// UINotificationTemplate 是当前运行时已编译模板的只读投影（不含渲染数据）。
type UINotificationTemplate struct {
	Kind     string
	Subject  string
	Body     string
	Source   string
	Editable bool
}

// UINotificationNotice 是当前操作者本人一条安全告知结果（服务端脱敏）。
type UINotificationNotice struct {
	OperationID     string
	Outcome         string
	State           string
	ErrorCode       string
	RecipientMasked string
	CreatedAt       time.Time
}

// UINotificationSettings 是安全通知设置页的真实只读事实与可用能力。
type UINotificationSettings struct {
	Capabilities UINotificationCapabilities

	From                      string
	SMTPAddr                  string
	SMTPHost                  string
	TLSMode                   string
	SMTPTimeoutSeconds        int
	MaxAttempts               int
	DeliveryTimeoutSeconds    int
	AllowPlaintextLocal       bool
	TrustedRootsConfigured    bool
	SenderConfigured          bool
	SecretConfigured          bool
	SecretStatusKnown         bool
	TemplatesConfigured       bool
	TemplateSource            string
	Templates                 []UINotificationTemplate
	TemplateEditingAvailable  bool
	SettingsEditingAvailable  bool
	SettingsUnavailableReason string
	// NotificationRequiredOperations 是当前成功后要求安全告知的敏感操作数（只读事实）。
	NotificationRequiredOperations int
	// NotificationRequiredKnown 表示该计数是否真实读取成功（未知不等于 0）。
	NotificationRequiredKnown bool
	Notices                   []UINotificationNotice
	NoticesAvailable          bool
}

// UINotificationTemplatePreview 是合成数据模板预览（未保存、未发送）。
type UINotificationTemplatePreview struct {
	Kind      string
	Subject   string
	TextBody  string
	Valid     bool
	ErrorCode string
}

// UINotificationTestResult 是一次真实测试发送尝试的结果（同步调用注入发送器）。
type UINotificationTestResult struct {
	Status          string
	ErrorCode       string
	Kind            string
	RecipientMasked string
	AttemptedAt     time.Time
	// Duplicate 表示相同幂等键的测试请求已处理过，本次未重复发送。
	Duplicate bool
}

// UINotificationSecretResult 是一次 SMTP 秘密替换的真实结果（不回显秘密）。
type UINotificationSecretResult struct {
	Replaced         bool
	SecretConfigured bool
	// Duplicate 表示相同幂等键的替换请求已处理过，本次未再次调用宿主。
	Duplicate bool
}

// newPageSecurityPolicyPages 构造步骤 72 路由/处理器。
func newPageSecurityPolicyPages(options UIPageSecurityPolicyOptions) (*pageSecurityPolicyPages, error) {
	if isNilUIValue(options.Backend) {
		return nil, fmt.Errorf("敏感策略页面缺少后端适配器")
	}
	if options.ValidateCSRF == nil {
		return nil, fmt.Errorf("敏感策略页面缺少 CSRF 校验器：必须接入 session.ValidateCSRFToken 等服务器端校验，不能只依赖可能关闭的 transport CSRF")
	}
	pages := &pageSecurityPolicyPages{handlers: map[string]UIPageHandler{}, options: options}
	handler := &securityPolicyPageHandlers{pages: pages}
	routes := []UIRoute{
		{Name: "admin.security_policies", Method: http.MethodGet, Path: "/admin/security/policies",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/security_policies"},
		{Name: "admin.security_policy_detail", Method: http.MethodGet, Path: "/admin/security/policies/detail",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/security_policy_detail"},
		{Name: "admin.security_policy_preview", Method: http.MethodPost, Path: "/admin/security/policies/preview",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/security_policy_preview"},
		{Name: "admin.security_policy_save", Method: http.MethodPost, Path: "/admin/security/policies/save",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/security_policy_detail"},
		{Name: "admin.security_policy_diff", Method: http.MethodGet, Path: "/admin/security/policies/diff",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/security_policy_diff"},
		{Name: "admin.security_policy_restore_preview", Method: http.MethodPost,
			Path:   "/admin/security/policies/restore/preview",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/security_policy_restore"},
		{Name: "admin.security_policy_restore", Method: http.MethodPost, Path: "/admin/security/policies/restore",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/security_policy_diff"},
		{Name: "admin.notification_mail", Method: http.MethodGet, Path: "/admin/notifications/mail",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/notification_mail"},
		{Name: "admin.notification_mail_template_preview", Method: http.MethodPost,
			Path:   "/admin/notifications/mail/template/preview",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/notification_mail"},
		{Name: "admin.notification_mail_test", Method: http.MethodPost, Path: "/admin/notifications/mail/test",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/notification_mail"},
		{Name: "admin.notification_mail_secret", Method: http.MethodPost, Path: "/admin/notifications/mail/secret",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/notification_mail"},
	}
	for _, route := range routes {
		pages.routes = append(pages.routes, route)
		pages.handlers[route.Name] = handler
	}
	return pages, nil
}

// pageSecurityPolicyPages 是敏感策略/安全通知页实现。
type pageSecurityPolicyPages struct {
	routes   []UIRoute
	handlers map[string]UIPageHandler
	options  UIPageSecurityPolicyOptions
}

// securityPolicyErrorOutcome 把适配器错误映射为稳定状态码与已翻译摘要。
func securityPolicyErrorOutcome(err error, data any, fallbackKey string) UIPageOutcome {
	outcome := UIPageOutcome{Data: data, StatusCode: http.StatusBadRequest,
		ErrorSummary: text(fallbackKey)}
	var publicErr *UISecurityPolicyError
	if errors.As(err, &publicErr) {
		outcome.ErrorCode = publicErr.Code
		switch publicErr.Code {
		case "ACCESS_DENIED":
			outcome.StatusCode = http.StatusForbidden
			outcome.ErrorSummary = text("page.admin.security_policy.common.forbidden")
		case "REAUTH_REQUIRED":
			outcome.StatusCode = http.StatusForbidden
			outcome.ErrorSummary = text("page.admin.security_policy.common.reauth_required")
		case "MFA_REQUIRED":
			outcome.StatusCode = http.StatusForbidden
			outcome.ErrorSummary = text("page.admin.security_policy.common.strength_unavailable")
		case "CONFLICT":
			outcome.StatusCode = http.StatusConflict
			outcome.ErrorSummary = text("page.admin.security_policy.common.conflict")
		case "CHALLENGE_INVALID":
			outcome.StatusCode = http.StatusConflict
			outcome.ErrorSummary = text("page.admin.security_policy.preview.stale")
		case "RATE_LIMITED":
			outcome.StatusCode = http.StatusTooManyRequests
			outcome.ErrorSummary = text("page.admin.security_policy.common.rate_limited")
		case "DB_UNAVAILABLE", "AUDIT_WRITE_FAILED":
			outcome.StatusCode = http.StatusServiceUnavailable
			outcome.ErrorSummary = text("page.admin.security_policy.common.unavailable")
		case "MAIL_INVALID_MESSAGE", "MAIL_ADDRESS_REJECTED":
			outcome.StatusCode = http.StatusBadRequest
			outcome.ErrorSummary = text("page.admin.security_policy.common.mail_invalid")
		case "MAIL_AUTH_FAILED", "MAIL_TLS_FAILED":
			outcome.StatusCode = http.StatusBadGateway
			outcome.ErrorSummary = text("page.admin.security_policy.common.mail_config_failed")
		case "MAIL_SEND_TIMEOUT", "MAIL_SEND_UNAVAILABLE", "MAIL_SEND_REJECTED",
			"MAIL_SEND_CANCELLED", "MAIL_QUEUE_FAILED":
			outcome.StatusCode = http.StatusBadGateway
			outcome.ErrorSummary = text("page.admin.security_policy.common.mail_failed")
		case "REQ_INVALID":
			outcome.StatusCode = http.StatusBadRequest
			outcome.ErrorSummary = text(fallbackKey)
		default:
			outcome.StatusCode = http.StatusInternalServerError
			outcome.ErrorSummary = text("common.state.error")
		}
	}
	return outcome
}

// NormalizeSecurityPolicyChange 应用领域联动规则并返回派生字段列表：取消敏感标记
// 只取消额外要求（基础授权/审计/root 保护仍生效）；未要求再次认证时新鲜度置 0、
// 强度置 none。派生不能静默发生，必须在预览中显示。
func NormalizeSecurityPolicyChange(change UISecurityPolicyValues) (UISecurityPolicyValues, []string) {
	derived := []string{}
	next := change
	if !next.Sensitive {
		if next.ReauthRequired {
			next.ReauthRequired = false
			derived = append(derived, "reauth_required")
		}
		if next.MaxAuthAgeSeconds != 0 {
			next.MaxAuthAgeSeconds = 0
			derived = append(derived, "max_auth_age_seconds")
		}
		if next.Strength != "none" {
			next.Strength = "none"
			derived = append(derived, "strength")
		}
		if next.ConfirmationRequired {
			next.ConfirmationRequired = false
			derived = append(derived, "confirmation_required")
		}
		return next, derived
	}
	if !next.ReauthRequired {
		if next.MaxAuthAgeSeconds != 0 {
			next.MaxAuthAgeSeconds = 0
			derived = append(derived, "max_auth_age_seconds")
		}
		if next.Strength != "none" {
			next.Strength = "none"
			derived = append(derived, "strength")
		}
	}
	return next, derived
}

// SecurityPolicyChangedFields 比较两条策略并返回不同的字段机器名。
func SecurityPolicyChangedFields(before, after UISecurityPolicyValues) []string {
	fields := []string{}
	if before.Sensitive != after.Sensitive {
		fields = append(fields, "sensitive")
	}
	if before.ReauthRequired != after.ReauthRequired {
		fields = append(fields, "reauth_required")
	}
	if before.MaxAuthAgeSeconds != after.MaxAuthAgeSeconds {
		fields = append(fields, "max_auth_age_seconds")
	}
	if before.Strength != after.Strength {
		fields = append(fields, "strength")
	}
	if before.ConfirmationRequired != after.ConfirmationRequired {
		fields = append(fields, "confirmation_required")
	}
	if before.NotificationRequired != after.NotificationRequired {
		fields = append(fields, "notification_required")
	}
	return fields
}

// UISecurityPolicyFieldRow 是一条操作/预览的字段对照行（模板统一渲染）。
type UISecurityPolicyFieldRow struct {
	Field     string
	Default   UISecurityPolicyFieldValue
	Override  *UISecurityPolicyFieldValue
	Effective UISecurityPolicyFieldValue
	Proposed  *UISecurityPolicyFieldValue
	Changed   bool
}

// UISecurityPolicyFieldValue 是字段值的安全展示投影：布尔/强度用 i18n 键，秒数用
// 原始数字（模板换算为秒与中文时长）。
type UISecurityPolicyFieldValue struct {
	IsNumber   bool
	Number     int64
	DisplayKey string
	// Empty 表示应用声明操作没有系统默认值/没有覆盖。
	Empty bool
}

// securityPolicyFieldValue 把单个字段转为展示投影。
func securityPolicyFieldValue(values UISecurityPolicyValues, field string) UISecurityPolicyFieldValue {
	switch field {
	case "sensitive":
		return UISecurityPolicyFieldValue{DisplayKey: boolKey(values.Sensitive)}
	case "reauth_required":
		return UISecurityPolicyFieldValue{DisplayKey: boolKey(values.ReauthRequired)}
	case "max_auth_age_seconds":
		return UISecurityPolicyFieldValue{IsNumber: true, Number: values.MaxAuthAgeSeconds}
	case "strength":
		return UISecurityPolicyFieldValue{DisplayKey: values.StrengthKey()}
	case "confirmation_required":
		return UISecurityPolicyFieldValue{DisplayKey: boolKey(values.ConfirmationRequired)}
	case "notification_required":
		return UISecurityPolicyFieldValue{DisplayKey: boolKey(values.NotificationRequired)}
	default:
		return UISecurityPolicyFieldValue{Empty: true}
	}
}

// boolKey 返回布尔值的 i18n 键。
func boolKey(value bool) string {
	if value {
		return "page.admin.security_policy.value.required"
	}
	return "page.admin.security_policy.value.not_required"
}

// securityPolicyFieldRows 为一条操作构造六字段对照行；override/proposed 为 nil 时
// 对应列显示“未设置”。hasDefault=false 时默认列显示“无系统默认值”。
func securityPolicyFieldRows(operation UISecurityPolicyOperation,
	proposed *UISecurityPolicyValues) []UISecurityPolicyFieldRow {
	fields := []string{"sensitive", "reauth_required", "max_auth_age_seconds",
		"strength", "confirmation_required", "notification_required"}
	rows := make([]UISecurityPolicyFieldRow, 0, len(fields))
	for _, field := range fields {
		row := UISecurityPolicyFieldRow{Field: field,
			Effective: securityPolicyFieldValue(operation.Effective, field),
			Changed:   containsString(operation.ChangedFields, field)}
		if operation.HasDefault {
			row.Default = securityPolicyFieldValue(operation.Default, field)
		} else {
			row.Default = UISecurityPolicyFieldValue{Empty: true}
		}
		if operation.Override != nil {
			value := securityPolicyFieldValue(*operation.Override, field)
			row.Override = &value
		}
		if proposed != nil {
			value := securityPolicyFieldValue(*proposed, field)
			row.Proposed = &value
		}
		rows = append(rows, row)
	}
	return rows
}

// containsString 报告字符串切片是否包含目标值。
func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// securityPolicyPrecisionKey 返回字段的 i18n 标签键。
func securityPolicyFieldLabelKey(field string) string {
	switch field {
	case "sensitive", "reauth_required", "max_auth_age_seconds", "strength",
		"confirmation_required", "notification_required":
		return "page.admin.security_policy.field." + field + ".label"
	default:
		return "page.admin.security_policy.field.unknown.label"
	}
}

// securityPolicyDurationLabel 把秒数格式化为直白中文时长（与真实秒数并列显示）。
func securityPolicyDurationLabel(seconds int64) string {
	if seconds <= 0 {
		return ""
	}
	duration := time.Duration(seconds) * time.Second
	switch {
	case duration%(24*time.Hour) == 0:
		return fmt.Sprintf("%d 天", int64(duration/(24*time.Hour)))
	case duration%time.Hour == 0:
		return fmt.Sprintf("%d 小时", int64(duration/time.Hour))
	case duration%time.Minute == 0:
		return fmt.Sprintf("%d 分钟", int64(duration/time.Minute))
	default:
		return fmt.Sprintf("%d 秒", seconds)
	}
}

// parseSecurityPolicyValues 解析六个白名单表单字段；勾选框缺失表示 false。
func parseSecurityPolicyValues(form url.Values) (UISecurityPolicyValues, bool) {
	values := UISecurityPolicyValues{
		Sensitive:            form.Get("sensitive") == "on" || form.Get("sensitive") == "1",
		ReauthRequired:       form.Get("reauth_required") == "on" || form.Get("reauth_required") == "1",
		ConfirmationRequired: form.Get("confirmation_required") == "on" || form.Get("confirmation_required") == "1",
		NotificationRequired: form.Get("notification_required") == "on" || form.Get("notification_required") == "1",
		Strength:             strings.TrimSpace(form.Get("strength")),
	}
	if values.Strength == "" {
		values.Strength = "none"
	}
	switch values.Strength {
	case "none", "password", "strong":
	default:
		return UISecurityPolicyValues{}, false
	}
	rawAge := strings.TrimSpace(form.Get("max_auth_age_seconds"))
	if rawAge == "" {
		rawAge = "0"
	}
	age, err := strconv.ParseInt(rawAge, 10, 64)
	if err != nil || age < 0 || age > 30*24*60*60 {
		return UISecurityPolicyValues{}, false
	}
	values.MaxAuthAgeSeconds = age
	return values, true
}

// parseExpectedVersion 解析并发版本号（非负整数）。
func parseExpectedVersion(raw string) (int64, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < 0 {
		return 0, false
	}
	return value, true
}

// newSecurityPolicyIdempotencyKey 生成页面动作的幂等键（秘密替换/测试邮件重复提交
// 由适配器按该键返回同一结果，不重复调用宿主/发送）。随机源不可用时返回空串，
// 适配器回退请求编号。
func newSecurityPolicyIdempotencyKey() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return ""
	}
	return "idem_" + hex.EncodeToString(buffer)
}

// safeSecurityPolicyValue 读取有界、无控制字符的操作/模板标识等定位值。
func safeSecurityPolicyValue(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || len(trimmed) > 128 || strings.ContainsAny(trimmed, "\r\n\x00") {
		return "", false
	}
	return trimmed, true
}

// builtinSecurityPolicyMessages 是敏感策略/安全通知页摘要使用的中文基线。
var builtinSecurityPolicyMessages = map[string]string{
	"page.admin.security_policy.common.forbidden":              "你没有读取敏感操作策略或安全通知设置的许可，或当前会话无权写入；服务端已拒绝，页面不披露受限内容",
	"page.admin.security_policy.common.reauth_required":        "需要为本次实际操作重新完成符合要求的身份验证；确认框本身不是授权",
	"page.admin.security_policy.common.strength_unavailable":   "要求“强认证”而当前环境尚未支持该强度：相关操作将不满足，不会自动降级为密码",
	"page.admin.security_policy.common.conflict":               "此作用域的策略已被其他操作修改，本次未保存；请重新读取并逐字段比较，不提供强制覆盖",
	"page.admin.security_policy.common.rate_limited":           "请求过于频繁，请稍后重试；不会自动重复发送邮件",
	"page.admin.security_policy.common.unavailable":            "服务暂时无法完成请求（存储/审计不可用），操作按未完成处理",
	"page.admin.security_policy.common.mail_invalid":           "测试目标或模板未通过校验，本次未发送",
	"page.admin.security_policy.common.mail_config_failed":     "SMTP 认证或 TLS 校验失败；不提供跳过证书校验或明文降级",
	"page.admin.security_policy.common.mail_failed":            "测试邮件未能确认发送成功；请按真实可公开错误码与状态处理",
	"page.admin.security_policy.load_failed":                   "无法读取敏感操作策略快照；旧数据可能已过期，禁止基于未知版本写入",
	"page.admin.security_policy.operation_unknown":             "该敏感操作未在目录中登记，或不在当前作用域可见范围",
	"page.admin.security_policy.preview.invalid":               "策略预览未通过字段与联动校验，请按字段说明修改",
	"page.admin.security_policy.save.confirm_required":         "请先核对提交前预览，并确认实际目标、作用域与拟提交值。",
	"page.admin.security_policy.save.failed":                   "策略保存未完成；服务端已重新校验 root 身份、再次认证、版本、字段白名单与审计。",
	"page.admin.security_policy.preview.required":              "写入前必须先获取服务端一次性预览令牌；参数、目标或版本变化后旧预览失效，请重新预览。",
	"page.admin.security_policy.preview.stale":                 "预览已过期或与提交内容不一致（目标/参数/版本变化）；本次未写入，请重新读取并预览。",
	"page.admin.security_policy.csrf.invalid":                  "表单安全令牌缺失或无效，本次请求被拒绝；请重新打开页面后再操作。",
	"page.admin.security_policy.save.self_confirm_required":    "本次包含敏感策略管理自身的保护变化，必须单独勾选已核对。",
	"page.admin.security_policy.save.conflict":                 "版本冲突：本次未保存。页面已重新读取最新快照，请比较后重新预览，不自动覆盖。",
	"page.admin.security_policy.restore.preview_required":      "恢复默认必须先预览实际影响范围；预览未执行，确认不是授权。",
	"page.admin.security_policy.restore.stale":                 "提交的恢复范围或版本已与最新快照不一致，旧确认已失效；请重新预览。",
	"page.admin.security_policy.restore.confirm_required":      "请先确认实际恢复范围与后果。",
	"page.admin.security_policy.restore.self_confirm_required": "本次整体恢复包含敏感策略管理自身的保护变化，必须单独勾选已核对。",
	"page.admin.notification_mail.load_failed":                 "无法读取安全通知设置；未配置、读取失败与能力未提供分别显示，不合并成“一切正常”。",
	"page.admin.notification_mail.template.invalid":            "模板用途无效或运行时不提供该模板；不接受浏览器自造第四类用途。",
	"page.admin.notification_mail.template.preview_failed":     "模板合成预览失败；这不代表已保存或已发送任何内容。",
	"page.admin.notification_mail.test.recipient_required":     "必须明确填写本次测试收件地址；不会自动使用 root、账户资料或任意用户邮箱。",
	"page.admin.notification_mail.test.recipient_invalid":      "测试收件地址格式无效，本次未发送。",
	"page.admin.notification_mail.test.confirm_required":       "请先核对完整测试目标、模板用途与合成内容说明。",
	"page.admin.notification_mail.test.not_configured":         "邮件发送器或发件地址尚未配置，当前不能发送测试邮件。",
	"page.admin.notification_mail.test.failed":                 "测试邮件发送失败；页面显示真实可公开错误码，不伪造已发送。",
	"page.admin.notification_mail.secret.unavailable":          "运行时 SMTP 秘密替换能力尚未提供；本页只显示已配置/未配置状态，且现有秘密不可查看。",
	"page.admin.notification_mail.secret.invalid":              "新密码输入无效；空值表示不修改，秘密不会回显。",
	"page.admin.notification_mail.secret.confirm_required":     "替换 SMTP 秘密必须再次确认实际动作与后果。",
	"page.admin.notification_mail.secret.failed":               "秘密替换未完成；页面不回显任何输入，请重新输入。",
}

func init() {
	for key, message := range builtinSecurityPolicyMessages {
		if _, exists := builtinAuthMessages[key]; !exists {
			builtinAuthMessages[key] = message
		}
	}
}
