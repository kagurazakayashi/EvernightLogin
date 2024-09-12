package ui

// 步骤 71：客服求助、人工恢复申请与独立审批页面。
//
// 安全不变量：
//   - 全部路由 UIAccessManagement：宿主 UISessionService 必须用真实
//     session.AuthorizeManagement 判定完整会话与强认证新鲜度；工作人员身份以
//     服务端会话为准，页面不信任任何前端自报角色。
//   - 每次读取与写入都由 UISupportBackend 适配器重新构造可信 Caller，调用真实
//     support/manualrecovery 服务；功能权限、数据范围、目标保护、再次认证与
//     独立审批由领域服务判定，页面层不实现放行。
//   - 客服只看到获准普通用户与必要脱敏信息：目标稳定 ID、服务端脱敏用户名/邮箱、
//     账户状态与渠道事实；不显示电话、完整邮箱、密码、验证码、重置链接、Token、
//     MFA 秘密、恢复代码或证据原文；不提供“以该用户登录”或改收件地址入口。
//   - 求助单处理历史与人工恢复生命周期均为追加式，页面不提供编辑/删除入口。
//   - 人工恢复默认关闭时，创建/审批/执行区域只显示真实未启用原因，不渲染可提交
//     的假控件；制度值（等待期/有效期/核验依据/交付方式）来自服务端真实配置。
//   - 审批页只对候选独立审批人开放待审批申请；发起者/目标本人不能自批；执行页
//     显示真实目标、操作、后果和时间窗口，并明确“确认不是授权”。
//   - 申请内容/目标安全状态变化、批准等待期未满、批准过期、权限撤销与执行冲突
//     都按服务端返回的真实结果呈现；重复执行只有在重新读取确认已完成时才显示
//     幂等提示。

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// UIPageSupportOptions 是步骤 71 客服/人工恢复页配置。
type UIPageSupportOptions struct {
	Backend UISupportBackend
}

// UISupportEvidence 是页面再次认证回调返回的服务端认证事实（步骤 188）。页面/适配器
// 不信任前端自报时间或强度；Strength 只允许 "strong"。
type UISupportEvidence struct {
	VerifiedAt time.Time
	Strength   string
	Complete   bool
	Confirmed  bool
}

// UISupportActionBinding 是客服/人工恢复页面动作的再次认证绑定参数。
type UISupportActionBinding struct {
	Action          string
	ScopeAppID      string
	TargetUserID    string
	RequestID       string
	TargetSessionID string
	Reason          string
}

// UISupportRecoveryListItem 是列表最小必要字段（Q6：ID/类型/脱敏目标/时间/状态/关系）。
type UISupportRecoveryListItem struct {
	RequestID     string
	SupportCaseID string
	Operation     string
	Status        string
	TargetMasked  string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	MyRelation    string
}

// UISupportRecoveryPage 是审批/执行工作台列表结果。
type UISupportRecoveryPage struct {
	Items      []UISupportRecoveryListItem
	HasMore    bool
	NextOffset int
}

// UISupportRecoveryLister 是可选列表能力：适配器实现后页面工作台展示真实待办；
// 旧适配器未实现时页面明确显示“列表能力未提供”，不伪造条目。
type UISupportRecoveryLister interface {
	ListRecoveryForPage(ctx context.Context, staffUserID, mode, operation string,
		offset, limit int) (UISupportRecoveryPage, error)
}

// UISupportCapabilities 是服务端为当前工作人员判定的页面能力位（只是交互辅助；
// 每次写操作仍由领域服务重新授权）。
type UISupportCapabilities struct {
	ReadCases       bool
	CreateCase      bool
	UpdateCase      bool
	SendReset       bool
	RequestRecovery bool
	ApprovePassword bool
	ApproveMFA      bool
	ExecuteRecovery bool
}

// UISupportCaseQuery 是求助单列表筛选/分页。
type UISupportCaseQuery struct {
	Status string
	Limit  int
	Offset int
	// Search 是可选的字面子串搜索（工单编号/原因；空不过滤）。服务端在授权范围
	// 过滤后执行，不搜索脱敏邮箱/用户名。
	Search string
}

// UISupportCaseView 是求助单公开脱敏视图（不含电话/完整邮箱/秘密）。
type UISupportCaseView struct {
	ID                   string
	TargetUserID         string
	TargetMaskedUsername string
	TargetMaskedEmail    string
	Reason               string
	Status               string
	AssigneeUserID       string
	CreatedByUserID      string
	CreatedAt            time.Time
	UpdatedAt            time.Time
	RowVersion           int64
}

// UISupportCasePage 是求助单分页结果（只有 HasMore，不伪造总数）。
type UISupportCasePage struct {
	Cases      []UISupportCaseView
	HasMore    bool
	NextOffset int
}

// UISupportEventView 是一条追加式处理历史。
type UISupportEventView struct {
	Seq        int64
	Action     string
	ActorType  string
	ActorID    string
	FromStatus string
	ToStatus   string
	Detail     string
	CreatedAt  time.Time
}

// UISupportHistoryPage 是处理历史分页结果。
type UISupportHistoryPage struct {
	Events     []UISupportEventView
	HasMore    bool
	NextOffset int
}

// UISupportTargetView 是实时读取目标账户得到的必要脱敏资料。
type UISupportTargetView struct {
	UserID           string
	MaskedUsername   string
	MaskedEmail      string
	Status           string
	HasPassword      bool
	HasVerifiedEmail bool
	CanRequestReset  bool
}

// UISupportCaseDetail 是求助单详情的组合投影。
type UISupportCaseDetail struct {
	Case               UISupportCaseView
	History            UISupportHistoryPage
	HistoryUnavailable bool
	Target             UISupportTargetView
	TargetUnread       bool
	Capabilities       UISupportCapabilities
}

// UISupportSendResult 是“向原验证邮箱发送入口”的真实结果。
type UISupportSendResult struct {
	Sent         bool
	ManualReview bool
	Status       string
}

// UISupportRecoveryPolicy 是人工恢复制度的页面安全摘要（来自服务端真实配置）。
type UISupportRecoveryPolicy struct {
	Enabled                    bool
	WaitPeriodSeconds          int64
	ApprovalTTLSeconds         int64
	RequestTTLSeconds          int64
	VerificationBases          []string
	DeliveryChannels           []string
	RequireIndependentApproval bool
}

// UISupportRecoveryCreate 是人工恢复申请创建白名单；目标与操作由服务端复核。
type UISupportRecoveryCreate struct {
	TargetUserID          string
	Operation             string
	VerificationBasis     string
	VerificationReference string
	EvidenceSummary       string
	Reason                string
	Delivery              string
	SupportCaseID         string
}

// UISupportApprovalView 是批准公开视图（不含内容摘要原文）。
type UISupportApprovalView struct {
	ID                string
	ApproverUserID    string
	Status            string
	ApprovedAt        time.Time
	NotBefore         time.Time
	ExpiresAt         time.Time
	InvalidatedReason string
}

// UISupportExecutionView 是执行结果公开视图（不含一次性凭证内容）。
type UISupportExecutionView struct {
	ID               string
	ExecutorUserID   string
	Status           string
	SessionsRevoked  int
	FactorsReset     bool
	CredentialIssued bool
	Notification     string
	// ErrorCode 是执行失败时的稳定公开错误码（不含底层消息/秘密），仅用于页面显示
	// 失败原因与后续处理指引；成功时为空。
	ErrorCode  string
	StartedAt  time.Time
	FinishedAt time.Time
}

// UISupportRecoveryView 是人工恢复申请的组合公开视图。
type UISupportRecoveryView struct {
	ID                    string
	TargetUserID          string
	InitiatorUserID       string
	Operation             string
	Status                string
	VerificationBasis     string
	VerificationReference string
	EvidenceRegistered    bool
	Reason                string
	Delivery              string
	DeliveryBound         string
	ContentConsistent     bool
	TargetSecurityVersion int64
	TargetHighPrivilege   bool
	SupportCaseID         string
	RowVersion            int64
	ExpiresAt             time.Time
	ClosedReason          string
	CreatedAt             time.Time
	UpdatedAt             time.Time
	Approval              UISupportApprovalView
	HasApproval           bool
	// ContentDigestHex 是内容摘要（十六进制，非秘密），供 CLI approve/execute 的
	// 186 证明绑定与页面核对使用；不泄露证据明文。
	ContentDigestHex string
	// ApprovalID 是当前/最近批准 ID（仅参与者读取时返回，用于 execute 参数绑定）。
	ApprovalID   string
	Execution    UISupportExecutionView
	HasExecution bool
	// HistoryUnavailable 表示完整生命周期/历史批准查询投影尚未提供（不伪造历史）。
	HistoryUnavailable bool
}

// UISupportError 是客服页面适配层返回的稳定公开错误。
type UISupportError struct {
	Code              string
	RetryAfterSeconds int
}

// Error 实现 error。
func (e *UISupportError) Error() string { return "客服页面操作失败: " + e.Code }

// UISupportBackend 是客服/人工恢复页面调用真实服务的最小契约；适配器负责可信
// Caller、管理授权、数据范围、再次认证与独立审批复核。页面层不实现授权。
type UISupportBackend interface {
	Capabilities(ctx context.Context, staffUserID string) (UISupportCapabilities, error)

	ListCases(ctx context.Context, staffUserID string, query UISupportCaseQuery) (UISupportCasePage, error)
	GetCase(ctx context.Context, staffUserID, caseID string) (UISupportCaseDetail, error)
	LookupTarget(ctx context.Context, staffUserID, targetUserID, requestID string) (UISupportTargetView, error)
	CreateCase(ctx context.Context, staffUserID, targetUserID, reason, requestID string) (UISupportCaseView, error)
	ReassignCase(ctx context.Context, staffUserID, caseID, newAssigneeUserID, requestID string) (UISupportCaseView, error)
	TransitionCase(ctx context.Context, staffUserID, caseID, toStatus, note, requestID string) (UISupportCaseView, error)
	SendReset(ctx context.Context, staffUserID, caseID, requestID string) (UISupportSendResult, error)

	RecoveryPolicy(ctx context.Context, staffUserID string) (UISupportRecoveryPolicy, error)
	CreateRecoveryRequest(ctx context.Context, staffUserID string, create UISupportRecoveryCreate,
		requestID string) (UISupportRecoveryView, error)
	GetRecoveryRequest(ctx context.Context, staffUserID, requestID string) (UISupportRecoveryView, error)
	ApproveRecovery(ctx context.Context, staffUserID, requestID, note, traceID string) (UISupportApprovalView, error)
	RejectRecovery(ctx context.Context, staffUserID, requestID, reason, traceID string) error
	CancelRecovery(ctx context.Context, staffUserID, requestID, reason, traceID string) error
	ExecuteRecovery(ctx context.Context, staffUserID, requestID, traceID string) (UISupportExecutionView, error)
}

// newPageSupportPages 构造步骤 71 路由/处理器。
func newPageSupportPages(options UIPageSupportOptions) (*pageSupportPages, error) {
	if isNilUIValue(options.Backend) {
		return nil, fmt.Errorf("客服页面缺少后端适配器")
	}
	pages := &pageSupportPages{handlers: map[string]UIPageHandler{}, options: options}
	handler := &supportPageHandlers{pages: pages}
	routes := []UIRoute{
		{Name: "support.cases", Method: http.MethodGet, Path: "/support/cases",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/support/cases"},
		{Name: "support.case_create", Method: http.MethodGet, Path: "/support/cases/create",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/support/case_create"},
		{Name: "support.case_create.submit", Method: http.MethodPost, Path: "/support/cases/create",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/support/case_create"},
		{Name: "support.case_detail", Method: http.MethodGet, Path: "/support/cases/detail",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/support/case_detail"},
		{Name: "support.case_reassign.submit", Method: http.MethodPost, Path: "/support/cases/reassign",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/support/case_detail"},
		{Name: "support.case_transition.submit", Method: http.MethodPost, Path: "/support/cases/transition",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/support/case_detail"},
		{Name: "support.case_send.submit", Method: http.MethodPost, Path: "/support/cases/send",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/support/case_detail"},
		{Name: "support.recovery_create.submit", Method: http.MethodPost, Path: "/support/recovery/request",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/support/recovery_detail"},
		{Name: "support.recovery_request", Method: http.MethodGet, Path: "/support/recovery/request",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/support/recovery_detail"},
		{Name: "support.recovery_cancel.submit", Method: http.MethodPost, Path: "/support/recovery/cancel",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/support/recovery_detail"},
		{Name: "support.recovery_inbox", Method: http.MethodGet, Path: "/support/recovery",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/support/recovery_inbox"},
		{Name: "support.recovery_approval", Method: http.MethodGet, Path: "/support/recovery/approval",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/support/recovery_approval"},
		{Name: "support.recovery_approve.submit", Method: http.MethodPost, Path: "/support/recovery/approval",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/support/recovery_detail"},
		{Name: "support.recovery_reject.submit", Method: http.MethodPost, Path: "/support/recovery/reject",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/support/recovery_action_result"},
		{Name: "support.recovery_execute", Method: http.MethodGet, Path: "/support/recovery/execute",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/support/recovery_execute"},
		{Name: "support.recovery_execute.submit", Method: http.MethodPost, Path: "/support/recovery/execute",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/support/recovery_detail"},
	}
	for _, route := range routes {
		pages.routes = append(pages.routes, route)
		pages.handlers[route.Name] = handler
	}
	return pages, nil
}

// pageSupportPages 是客服/人工恢复页实现。
type pageSupportPages struct {
	routes   []UIRoute
	handlers map[string]UIPageHandler
	options  UIPageSupportOptions
}

// supportErrorOutcome 把适配器错误映射为稳定状态码/已翻译文案。
func supportErrorOutcome(err error, data any, fallbackKey string) UIPageOutcome {
	outcome := UIPageOutcome{Data: data, StatusCode: http.StatusBadRequest,
		ErrorSummary: text(fallbackKey)}
	var publicErr *UISupportError
	if errors.As(err, &publicErr) {
		outcome.ErrorCode = publicErr.Code
		switch publicErr.Code {
		case "ACCESS_DENIED":
			outcome.StatusCode = http.StatusForbidden
			outcome.ErrorSummary = text("page.support.common.forbidden")
		case "SUPPORT_TARGET_PROTECTED":
			outcome.StatusCode = http.StatusForbidden
			outcome.ErrorSummary = text("page.support.common.target_protected")
		case "USER_DISABLED":
			outcome.StatusCode = http.StatusConflict
			outcome.ErrorSummary = text("page.support.common.user_disabled")
		case "REAUTH_REQUIRED", "MFA_REQUIRED":
			outcome.StatusCode = http.StatusForbidden
			outcome.ErrorSummary = text("page.support.common.reauth_required")
		case "CONFLICT":
			outcome.StatusCode = http.StatusConflict
			outcome.ErrorSummary = text("page.support.common.conflict")
		case "CHALLENGE_INVALID":
			outcome.StatusCode = http.StatusConflict
			outcome.ErrorSummary = text("page.support.common.invalid")
		case "RATE_LIMITED":
			outcome.StatusCode = http.StatusTooManyRequests
			outcome.ErrorSummary = text("page.support.common.rate_limited")
		case "MAIL_DELIVERY_FAILED":
			outcome.StatusCode = http.StatusBadGateway
			outcome.ErrorSummary = text("page.support.common.mail_failed")
		case "AUTHZ_UNAVAILABLE", "DB_UNAVAILABLE", "AUDIT_WRITE_FAILED":
			outcome.StatusCode = http.StatusServiceUnavailable
			outcome.ErrorSummary = text("page.support.common.unavailable")
		case "DISABLED":
			outcome.StatusCode = http.StatusConflict
			outcome.ErrorSummary = text("page.support.recovery_request.not_enabled")
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

// supportQueryValue 读取有界、无控制字符的查询/表单值（只作为定位依据）。
func supportQueryValue(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || len(trimmed) > 256 || strings.ContainsAny(trimmed, "\r\n\x00") {
		return "", false
	}
	return trimmed, true
}

// supportParseOffset 解析非负分页偏移。
func supportParseOffset(raw string) (int, bool) {
	if raw == "" {
		return 0, true
	}
	offset, err := strconv.Atoi(raw)
	if err != nil || offset < 0 || offset > 1_000_000 {
		return 0, false
	}
	return offset, true
}

// supportCaseStatusLabel 返回求助单状态的 i18n 键（未知状态安全回退）。
func supportCaseStatusLabel(status string) string {
	switch status {
	case "pending_verification":
		return "support.status.pending_verification"
	case "sent":
		return "support.status.sent"
	case "manual_review":
		return "support.status.manual_review"
	case "closed":
		return "support.status.closed"
	case "cancelled":
		return "support.status.cancelled"
	default:
		return "support.status.unknown"
	}
}

// supportRecoveryStatusLabel 返回人工恢复状态的 i18n 键。
func supportRecoveryStatusLabel(status string) string {
	switch status {
	case "pending_approval":
		return "manual_recovery.status.pending_approval"
	case "approved":
		return "manual_recovery.status.approved"
	case "executing":
		return "manual_recovery.status.executing"
	case "completed":
		return "manual_recovery.status.completed"
	case "rejected":
		return "manual_recovery.status.rejected"
	case "cancelled":
		return "manual_recovery.status.cancelled"
	case "failed":
		return "manual_recovery.status.failed"
	case "expired":
		return "manual_recovery.status.expired"
	default:
		return "manual_recovery.status.unknown"
	}
}

// supportOperationLabel 返回操作类型 i18n 键。
func supportOperationLabel(operation string) string {
	switch operation {
	case "password_reset":
		return "manual_recovery.operation.password_reset"
	case "mfa_reset":
		return "manual_recovery.operation.mfa_reset"
	default:
		return "manual_recovery.operation.unknown"
	}
}

// supportBasisLabel 返回核验依据 i18n 键。
func supportBasisLabel(basis string) string {
	switch basis {
	case "in_person_identity_document":
		return "manual_recovery.basis.in_person_identity_document"
	case "notarized_declaration":
		return "manual_recovery.basis.notarized_declaration"
	default:
		return "manual_recovery.basis.unknown"
	}
}

// supportDeliveryLabel 返回交付方式 i18n 键。
func supportDeliveryLabel(delivery string) string {
	if delivery == "verified_email" {
		return "manual_recovery.delivery.verified_email"
	}
	return "manual_recovery.delivery.unknown"
}

// supportEventActionLabel 返回处理历史动作 i18n 键。
func supportEventActionLabel(action string) string {
	switch action {
	case "support.case.created":
		return "support.event.created"
	case "support.case.assigned":
		return "support.event.assigned"
	case "support.case.status_changed":
		return "support.event.status_changed"
	case "support.case.reset_requested":
		return "support.event.reset_requested"
	case "support.case.manual_review":
		return "support.event.manual_review"
	default:
		return "support.event.unknown"
	}
}

// supportTimeWindow 把秒数格式化为直白中文时长（页面显示真实服务端配置）。
func supportDurationLabel(seconds int64) string {
	if seconds <= 0 {
		return "—"
	}
	duration := time.Duration(seconds) * time.Second
	switch {
	case duration%(24*time.Hour) == 0:
		return fmt.Sprintf("%d 天", int64(duration/(24*time.Hour)))
	case duration%time.Hour == 0:
		return fmt.Sprintf("%d 小时", int64(duration/time.Hour))
	default:
		return fmt.Sprintf("%d 分钟", int64(duration/time.Minute))
	}
}

// builtinSupportMessages 是客服页面摘要使用的中文基线（模板静态文案走 i18n 键）。
var builtinSupportMessages = map[string]string{
	"page.support.common.forbidden":                   "你没有查看或处理该对象的权限，或当前数据范围已变化；服务端已拒绝",
	"page.support.common.target_protected":            "该账户不能走普通客服恢复流程：root 仅由受控本地应急流程处理，其他高权限账户请转交获授权的安全管理员；没有继续旁路",
	"page.support.common.user_disabled":               "目标账户当前不可用于此操作；不显示额外账户秘密",
	"page.support.common.reauth_required":             "需要重新完成符合要求的身份验证（强认证/两步验证）；确认框本身不是授权",
	"page.support.common.conflict":                    "对象已被其他操作修改或当前状态不允许该动作；请重新读取后再决定",
	"page.support.common.invalid":                     "申请、批准或验证请求无效或已失效；请重新读取真实状态",
	"page.support.common.rate_limited":                "请求过于频繁，请稍后重试；不会自动重复发送邮件",
	"page.support.common.mail_failed":                 "本次找回邮件未能确认投递，未显示为已发送；请重新读取工单真实状态",
	"page.support.common.unavailable":                 "服务暂时无法完成请求（授权/存储/审计不可用），操作按未完成处理",
	"page.support.cases.load_failed":                  "无法读取分配给你的求助单列表",
	"page.support.cases.invalid_query":                "筛选或分页参数无效，已回到第一页",
	"page.support.case_create.invalid":                "登记请求未通过校验，请按字段说明修改",
	"page.support.case_create.lookup_failed":          "无法定位该账户，或你没有获准处理该账户",
	"page.support.case_create.submit_failed":          "登记求助单未完成；服务端已重新校验权限、目标范围与再次认证",
	"page.support.case_detail.load_failed":            "无法读取该求助单；只有当前分配给你的工单可见",
	"page.support.case_detail.invalid":                "求助单请求未通过校验",
	"page.support.case_detail.action_failed":          "本次处理未完成；服务端已重新校验权限、状态与再次认证",
	"page.support.case_detail.confirm_required":       "请先确认本次动作的实际目标与后果",
	"page.support.case_create.confirm_required":       "请先确认目标、求助原因与处理边界。",
	"page.support.recovery_request.confirm_required":  "请先确认实际目标、操作、核验依据与后果；提交不代表已批准或已执行。",
	"page.support.recovery_approval.confirm_required": "请先确认本次审批的实际目标与后果。",
	"page.support.recovery_request.load_failed":       "无法读取该人工恢复申请",
	"page.support.recovery_request.not_enabled":       "人工恢复流程尚未由 root/宿主启用，当前不能创建、审批或执行申请；请由负责配置的管理员完成制度配置。",
	"page.support.recovery_request.invalid":           "人工恢复申请请求未通过校验",
	"page.support.recovery_request.create_failed":     "创建人工恢复申请未完成；服务端已重新校验权限、目标与再次认证",
	"page.support.recovery_request.cancel_failed":     "取消申请未完成",
	"page.support.recovery_inbox.unavailable":         "审批列表能力尚未提供：不能通过枚举申请 ID 或静态卡片代替真实待审批列表",
	"page.support.recovery_approval.load_failed":      "无法读取待审批申请；仅当前具备审批资格且不是发起者/目标本人的工作人员可读取",
	"page.support.recovery_approval.invalid":          "审批请求未通过校验",
	"page.support.recovery_approval.denied":           "你不能审批本人发起或本人账户的恢复申请；服务端已拒绝",
	"page.support.recovery_approval.approve_failed":   "批准未完成；服务端会重新校验内容绑定、目标状态、等待期与再次认证",
	"page.support.recovery_approval.reject_failed":    "拒绝未完成",
	"page.support.recovery_execute.load_failed":       "无法读取执行确认所需资料",
	"page.support.recovery_execute.invalid":           "执行请求未通过校验",
	"page.support.recovery_execute.confirm_required":  "请先确认实际目标、操作、后果与时间窗口",
	"page.support.recovery_execute.failed":            "执行未完成；结果未知时请先重新读取申请与执行状态，不要重复提交",
	"page.support.recovery_execute.already_executed":  "该申请已执行，本次未再次执行",
	"page.support.recovery_execute.unknown":           "执行状态尚未确认，请勿重复提交；请手动重新读取",
}

func init() {
	for key, message := range builtinSupportMessages {
		if _, exists := builtinAuthMessages[key]; !exists {
			builtinAuthMessages[key] = message
		}
	}
}
