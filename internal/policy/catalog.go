package policy

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	// MaxAuthAgeLimitSeconds 是认证新鲜度上限（30 天）。
	MaxAuthAgeLimitSeconds int64 = 30 * 24 * 60 * 60
	// MinAuthAgeSeconds 是要求再次验证时允许的最小新鲜度（30 秒）：过短的新鲜度
	// 无法覆盖一次正常敏感操作所需的时间，容易把正常请求误判为过期。
	MinAuthAgeSeconds int64 = 30
	// MaxOperationIDBytes 是稳定操作标识长度上限。
	MaxOperationIDBytes = 128
	// MaxNameRunes 是应用声明操作名称的长度上限。
	MaxNameRunes = 128
	// MaxDescriptionRunes 是应用声明操作说明的长度上限。
	MaxDescriptionRunes = 1024
)

// Strength 是策略允许要求的认证强度。
//
// 强度等级为 none < password < strong。strong 指第二因素/Passkey/安全密钥等
// 强认证；“当前环境是否已实现该强度”由 Service 的可用强度集合决定，未实现的
// 强度不会被当作可满足。
type Strength string

const (
	// StrengthNone 表示不要求完成额外认证（仅基础权限与审计仍生效）。
	StrengthNone Strength = "none"
	// StrengthPassword 表示密码/近期主认证级别，可由宿主 ReauthVerifier 满足。
	StrengthPassword Strength = "password"
	// StrengthStrong 表示第二因素/Passkey 等强认证级别；MFA 实现前不可满足。
	StrengthStrong Strength = "strong"
)

// Rank 返回强度等级数值，用于比较是否达到要求。
func (s Strength) rank() int {
	switch s {
	case StrengthStrong:
		return 2
	case StrengthPassword:
		return 1
	case StrengthNone:
		return 0
	default:
		return -1
	}
}

// Known 报告强度枚举是否合法。
func (s Strength) Known() bool { return s.rank() >= 0 }

// Domain 是敏感操作所属业务域，用于直白展示与分组，不参与授权。
type Domain string

const (
	DomainPassword    Domain = "password"
	DomainEmail       Domain = "email"
	DomainMFA         Domain = "mfa"
	DomainPermission  Domain = "permission"
	DomainApplication Domain = "application"
	DomainBackup      Domain = "backup"
	DomainAudit       Domain = "audit"
	DomainSession     Domain = "session"
	DomainProfile     Domain = "profile"
	DomainRecovery    Domain = "recovery"
	DomainReport      Domain = "report"
)

// knownDomains 是允许的业务域集合。
var knownDomains = map[Domain]bool{
	DomainPassword: true, DomainEmail: true, DomainMFA: true,
	DomainPermission: true, DomainApplication: true, DomainBackup: true,
	DomainAudit: true, DomainSession: true, DomainProfile: true,
	DomainRecovery: true, DomainReport: true,
}

// Policy 是一条敏感操作的可配置策略。
type Policy struct {
	// Sensitive 表示该操作是否被视为敏感操作；false 只取消额外验证/确认要求，
	// 不取消基础权限、root 专属限制与审计。
	Sensitive bool
	// ReauthRequired 表示执行前必须完成近期身份验证。
	ReauthRequired bool
	// MaxAuthAgeSeconds 是允许的认证新鲜度（秒）；仅在 ReauthRequired 时非 0。
	MaxAuthAgeSeconds int64
	// Strength 是允许满足再次验证的最低认证强度。
	Strength Strength
	// ConfirmationRequired 表示执行前必须显式确认操作内容。
	ConfirmationRequired bool
	// NotificationRequired 表示成功执行后必须按策略发送安全告知。
	NotificationRequired bool
}

// Equal 比较两条策略的全部可配置字段。
func (p Policy) Equal(other Policy) bool {
	return p.Sensitive == other.Sensitive &&
		p.ReauthRequired == other.ReauthRequired &&
		p.MaxAuthAgeSeconds == other.MaxAuthAgeSeconds &&
		p.Strength == other.Strength &&
		p.ConfirmationRequired == other.ConfirmationRequired &&
		p.NotificationRequired == other.NotificationRequired
}

// Operation 是敏感操作目录中的一条稳定定义。ID、基础权限、root 专属与审计要求
// 属于不可被策略覆盖的安全约束。
type Operation struct {
	// ID 是稳定操作标识（小写标识符，创建后不可修改）。
	ID string
	// Domain 是所属业务域。
	Domain Domain
	// Name 是中文名称。
	Name string
	// Description 是直白说明：能做什么、影响什么、不能做什么。
	Description string
	// Default 是系统默认策略。
	Default Policy
	// PermissionKey 是执行该操作必须持有的既有权限标识；空表示目录不硬编码权限
	// 标识，基础权限由宿主注入的专用授权器判定（例如邀请创建/注册审核的授权器，
	// 或只能由 root 通道执行的 root 恢复）。空值不代表无授权要求。
	PermissionKey string
	// RootOnly 表示该操作只能由 root 执行，策略不能解除该限制。
	RootOnly bool
	// ImmutableSensitive 表示不允许通过策略取消敏感标记（高风险 root 操作）。
	ImmutableSensitive bool
	// Implemented 表示对应业务执行器是否已实现；未实现时仍登记目录与默认策略，
	// 但不得让业务调用伪装成功。
	Implemented bool
}

// Catalog 是版本化、机器可读的敏感操作目录。默认目录内置在第一版代码中；
// 宿主可注入自定义目录用于升级测试，但必须通过 Validate。
type Catalog struct {
	// Version 是目录版本，格式为 主.次.修订。
	Version string
	// Operations 是系统内置敏感操作定义。
	Operations []Operation
}

// DefaultCatalog 返回第一版内置目录（新副本，调用方修改不影响内置数据）。
func DefaultCatalog() *Catalog {
	return &Catalog{Version: "1.0.0", Operations: defaultOperations()}
}

// DefaultPolicyFor 返回内置目录中某操作的默认策略。
func DefaultPolicyFor(operationID string) (Policy, bool) {
	catalog := DefaultCatalog()
	operation, ok := catalog.Lookup(operationID)
	if !ok {
		return Policy{}, false
	}
	return operation.Default, true
}

// Lookup 按稳定标识查找操作定义。
func (c *Catalog) Lookup(operationID string) (Operation, bool) {
	if c == nil {
		return Operation{}, false
	}
	for _, operation := range c.Operations {
		if operation.ID == operationID {
			return operation, true
		}
	}
	return Operation{}, false
}

// Validate 校验目录完整性与安全不变式：标识唯一稳定、策略合法、不可覆盖约束
// 不自相矛盾。失败时服务拒绝构造，避免以半合法目录运行。
func (c *Catalog) Validate() error {
	if c == nil {
		return fmt.Errorf("%w: 目录为空", ErrOptionsInvalid)
	}
	if !validVersion(c.Version) {
		return fmt.Errorf("%w: 目录版本 %q 不是 主.次.修订 格式", ErrOptionsInvalid, c.Version)
	}
	if len(c.Operations) == 0 {
		return fmt.Errorf("%w: 目录没有登记任何敏感操作", ErrOptionsInvalid)
	}
	seen := make(map[string]struct{}, len(c.Operations))
	for _, operation := range c.Operations {
		if !validOperationID(operation.ID) {
			return fmt.Errorf("%w: 操作标识 %q 非法", ErrOptionsInvalid, operation.ID)
		}
		if _, duplicated := seen[operation.ID]; duplicated {
			return fmt.Errorf("%w: 操作标识 %q 重复", ErrOptionsInvalid, operation.ID)
		}
		seen[operation.ID] = struct{}{}
		if !knownDomains[operation.Domain] {
			return fmt.Errorf("%w: 操作 %q 的业务域 %q 未知", ErrOptionsInvalid, operation.ID, operation.Domain)
		}
		if err := validateText("中文名称", operation.Name, MaxNameRunes, false); err != nil {
			return fmt.Errorf("%w: 操作 %q %w", ErrOptionsInvalid, operation.ID, err)
		}
		if err := validateText("说明", operation.Description, MaxDescriptionRunes, true); err != nil {
			return fmt.Errorf("%w: 操作 %q %w", ErrOptionsInvalid, operation.ID, err)
		}
		if err := validatePolicy(operation.Default, operation.ImmutableSensitive); err != nil {
			return fmt.Errorf("%w: 操作 %q 默认策略无效: %w", ErrOptionsInvalid, operation.ID, err)
		}
		if operation.PermissionKey != "" && !validPermissionKey(operation.PermissionKey) {
			return fmt.Errorf("%w: 操作 %q 的基础权限标识非法", ErrOptionsInvalid, operation.ID)
		}
		if operation.RootOnly && operation.PermissionKey != "" && !strings.HasPrefix(operation.PermissionKey, "security.") &&
			operation.PermissionKey != "backups.restore" && operation.PermissionKey != "audit.purge" &&
			operation.PermissionKey != "recovery.approve" {
			// root 专属操作只能使用既有高风险权限标识；这条规则防止把普通业务权限
			// 误标成 root 专属后仍被普通角色组合。
			return fmt.Errorf("%w: 操作 %q 的 root 专属基础权限 %q 不是高风险权限",
				ErrOptionsInvalid, operation.ID, operation.PermissionKey)
		}
	}
	return nil
}

// validVersion 校验 主.次.修订 版本格式。
func validVersion(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 {
			return false
		}
	}
	return true
}

// validOperationID 校验稳定操作标识：小写字母/数字开头，仅允许小写字母、数字、
// 点、下划线与连字符，长度有界。
func validOperationID(id string) bool {
	if len(id) < 3 || len(id) > MaxOperationIDBytes {
		return false
	}
	for index := 0; index < len(id); index++ {
		character := id[index]
		switch {
		case character >= 'a' && character <= 'z':
		case character >= '0' && character <= '9':
		case character == '.' || character == '_' || character == '-':
		default:
			return false
		}
	}
	first := id[0]
	if (first >= 'a' && first <= 'z') || (first >= '0' && first <= '9') {
		return true
	}
	return false
}

// validPermissionKey 校验权限标识格式（lower_snake，以点分段）。
func validPermissionKey(key string) bool {
	if len(key) < 3 || len(key) > 128 {
		return false
	}
	for _, segment := range strings.Split(key, ".") {
		if segment == "" {
			return false
		}
		for index := 0; index < len(segment); index++ {
			character := segment[index]
			if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '_') {
				return false
			}
		}
	}
	return true
}

// validateText 校验中文名称/说明：去除首尾空白后非空、码点有界、无控制字符。
func validateText(label, value string, maxRunes int, allowNewline bool) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fmt.Errorf("%s不能为空", label)
	}
	if len([]rune(trimmed)) > maxRunes {
		return fmt.Errorf("%s不能超过 %d 个字符", label, maxRunes)
	}
	for _, character := range trimmed {
		if character == '\n' || character == '\t' {
			if allowNewline {
				continue
			}
			return fmt.Errorf("%s不能包含换行", label)
		}
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("%s包含不允许的控制字符", label)
		}
	}
	return nil
}

// ValidatePolicy 校验一条策略组合是否合法。它与服务端写入使用同一语义，供页面
// 在提交前给出与服务端一致的可纠正提示；它不检查不可变敏感约束，也不代表已授权。
func ValidatePolicy(value Policy) error { return validatePolicy(value, false) }

// validatePolicy 校验策略组合是否合法。规则在默认目录与覆盖合并后都适用，保证
// 任何被接受的策略都能被后续执行器一致解释。
func validatePolicy(value Policy, immutableSensitive bool) error {
	if !value.Strength.Known() {
		return fmt.Errorf("%w: 认证强度 %q 未知", ErrInvalidChange, value.Strength)
	}
	if value.MaxAuthAgeSeconds < 0 || value.MaxAuthAgeSeconds > MaxAuthAgeLimitSeconds {
		return fmt.Errorf("%w: 认证新鲜度必须在 0～%d 秒之间", ErrInvalidChange, MaxAuthAgeLimitSeconds)
	}
	if immutableSensitive && !value.Sensitive {
		return fmt.Errorf("%w: 高风险 root 操作不能取消敏感标记", ErrInvalidChange)
	}
	if !value.Sensitive {
		// 取消敏感标记只取消额外安全要求；基础权限/root 限制/审计不在可覆盖字段内。
		if value.ReauthRequired || value.MaxAuthAgeSeconds != 0 ||
			value.Strength != StrengthNone || value.ConfirmationRequired {
			return fmt.Errorf("%w: 非敏感操作不能再要求再次验证/强度/确认", ErrInvalidChange)
		}
		return nil
	}
	if value.ReauthRequired {
		if value.MaxAuthAgeSeconds < MinAuthAgeSeconds {
			return fmt.Errorf("%w: 要求再次验证时认证新鲜度必须在 %d～%d 秒之间",
				ErrInvalidChange, MinAuthAgeSeconds, MaxAuthAgeLimitSeconds)
		}
		if value.Strength == StrengthNone {
			return fmt.Errorf("%w: 要求再次验证时必须声明认证强度", ErrInvalidChange)
		}
	} else {
		if value.MaxAuthAgeSeconds != 0 {
			return fmt.Errorf("%w: 未要求再次验证时认证新鲜度必须为 0", ErrInvalidChange)
		}
		if value.Strength != StrengthNone {
			return fmt.Errorf("%w: 未要求再次验证时认证强度必须为 none", ErrInvalidChange)
		}
	}
	return nil
}

// defaultOperations 返回第一版内置敏感操作定义。默认策略刻意保守：高风险与
// root 专属操作默认要求强认证；MFA/Passkey 尚未实现时这些要求 fail-closed，
// 不会因实现缺失而降级为密码。
func defaultOperations() []Operation {
	passwordStrong := Policy{Sensitive: true, ReauthRequired: true, MaxAuthAgeSeconds: 300,
		Strength: StrengthPassword, ConfirmationRequired: true, NotificationRequired: true}
	passwordChange := passwordStrong
	passwordChange.MaxAuthAgeSeconds = 600

	strongReauth := Policy{Sensitive: true, ReauthRequired: true, MaxAuthAgeSeconds: 300,
		Strength: StrengthStrong, ConfirmationRequired: true, NotificationRequired: true}
	strongReauthShort := strongReauth
	strongReauthShort.MaxAuthAgeSeconds = 120
	strongReauthNoNotify := strongReauth
	strongReauthNoNotify.NotificationRequired = false
	strongReauthNoConfirm := strongReauth
	strongReauthNoConfirm.ConfirmationRequired = false
	strongReauthNoConfirm.NotificationRequired = false
	// mfaAdd：添加首个第二因素用近期主密码认证（防止先有鸡还是先有蛋）；首次
	// 绑定仍需近期确认与告知，TOTP 执行器已实现。
	mfaAdd := Policy{Sensitive: true, ReauthRequired: true, MaxAuthAgeSeconds: 300,
		Strength: StrengthPassword, ConfirmationRequired: false, NotificationRequired: true}
	// oauthConsent：用户批准第三方/应用 OAuth 授权。要求近期主认证（300 秒）与敏感
	// 操作策略；显式确认由授权确认页本身完成，不再额外要求通用确认字段；不发送
	// 邮件告知（避免把授权页面操作变成通知噪声），拒绝路径不签发授权码。
	oauthConsent := Policy{Sensitive: true, ReauthRequired: true, MaxAuthAgeSeconds: 300,
		Strength: StrengthPassword, ConfirmationRequired: false, NotificationRequired: false}

	return []Operation{
		{
			ID: "password.change", Domain: DomainPassword, Name: "修改自己的密码",
			Description:   "修改当前账户的登录密码；需要近期主认证并确认，成功后发送安全告知。不能用于重置他人密码或绕过 MFA。",
			Default:       passwordChange,
			PermissionKey: "self.credentials.manage",
			Implemented:   true,
		},
		{
			ID: "password.admin_reset", Domain: DomainPassword, Name: "管理员重置或发起密码找回",
			Description:   "由获准的管理/客服通道为他人发起密码重置或找回；不能读取原密码，不能绕过 MFA，必须再次验证与确认并告知用户。",
			Default:       strongReauth,
			PermissionKey: "users.update",
			Implemented:   false,
		},
		{
			ID: "mfa.add", Domain: DomainMFA, Name: "新增两步验证因素",
			Description:   "为当前账户绑定 TOTP 等第二因素：首次绑定只需近期主密码认证（避免先有鸡还是先有蛋），绑定需验证渠道控制权，成功后告知；高权限账户仍须强认证但不能仅靠邮件。",
			Default:       mfaAdd,
			PermissionKey: "self.credentials.manage",
			Implemented:   true,
		},
		{
			ID: "mfa.remove", Domain: DomainMFA, Name: "移除两步验证因素",
			Description:        "移除当前账户的某个第二因素；必须先验证替代方式与近期主密码，禁止移除最后一个可用因素导致降级。强认证实现前默认按近期主密码判定以避免功能死锁，高权限账户应由宿主加严为 strong。",
			Default:            passwordStrong,
			PermissionKey:      "self.credentials.manage",
			ImmutableSensitive: true,
			Implemented:        true,
		},
		{
			ID: "passkey.register", Domain: DomainMFA, Name: "注册 Passkey",
			Description:   "为当前账户注册 WebAuthn Passkey；与 mfa.add 同理，首个强因素建立只需要近期主密码认证（避免先有鸡还是先有蛋），注册需认证器验证并写安全告知。已绑定强因素的高权限账户应由宿主把该操作加严为 strong。",
			Default:       mfaAdd,
			PermissionKey: "self.credentials.manage",
			Implemented:   true,
		},
		{
			ID: "passkey.remove", Domain: DomainMFA, Name: "删除 Passkey",
			Description:        "删除当前账户的 Passkey；需要近期主密码认证并写安全告知，执行器检查不能删除最后一个可用登录方式（仍有其他 Passkey 或主密码才允许），执行器未实现前 fail-closed。",
			Default:            mfaAdd,
			PermissionKey:      "self.credentials.manage",
			ImmutableSensitive: true,
			Implemented:        true,
		},
		{
			ID: "recovery.codes.rotate", Domain: DomainMFA, Name: "更新恢复代码",
			Description:   "生成新的一组一次性恢复代码并作废旧组；需要近期身份验证与安全告知（执行器为 internal/recovery，恢复代码只替代第二步、使用后进入受限恢复并要求重新绑定）。强认证实现前默认按近期主密码判定以避免功能死锁，高权限账户应由宿主加严为 strong。",
			Default:       mfaAdd,
			PermissionKey: "self.credentials.manage",
			Implemented:   true,
		},
		{
			ID: "email.change.request", Domain: DomainEmail, Name: "申请变更已验证邮箱",
			Description:   "向新地址发送验证入口并在验证后切换；必须近期身份验证与确认，并告知旧邮箱。不能仅凭新地址自证接管账户。",
			Default:       passwordChange,
			PermissionKey: "self.credentials.manage",
			Implemented:   true,
		},
		{
			ID: "profile.username.change", Domain: DomainProfile, Name: "受控修改用户名",
			Description:   "修改全局唯一用户名；需要近期身份验证与确认，受冷却、保留名与唯一性限制，稳定用户 ID 不变。",
			Default:       passwordChange,
			PermissionKey: "self.profile.update",
			Implemented:   true,
		},
		{
			ID: "permission.role.assign", Domain: DomainPermission, Name: "分配或变更角色权限",
			Description:   "给用户/用户组分配角色或改变角色权限组合；必须经委派资格复核、强认证与确认，不能让自己或同组间接提权。",
			Default:       strongReauth,
			PermissionKey: "roles.assign",
			Implemented:   false,
		},
		{
			ID: "permission.catalog.change", Domain: DomainPermission, Name: "修改权限目录与启停",
			Description:   "登记、修改或启停权限定义；必须强认证并确认，内置与 root_only 权限受额外保护，不能扩大普通角色能力。",
			Default:       strongReauth,
			PermissionKey: "permissions.manage",
			Implemented:   false,
		},
		{
			ID: "application.credential.rotate", Domain: DomainApplication, Name: "轮换应用凭证",
			Description:   "轮换应用密钥或公钥凭证；必须强认证并确认，成功后告知，不包含服务器 HTTPS 私钥。",
			Default:       strongReauth,
			PermissionKey: "applications.credentials.manage",
			Implemented:   true,
		},
		{
			ID: "oauth.client.register", Domain: DomainApplication, Name: "登记 OAuth 客户端安全设置",
			Description:   "为应用登记 OAuth 客户端类型、授权类型、精确回调/退出回调、Scope、允许的目标资源、客户端身份验证方式与 PKCE 要求；必须强认证与确认并告知，公开客户端不得使用密钥假装保密。",
			Default:       strongReauth,
			PermissionKey: "applications.update",
			Implemented:   true,
		},
		{
			ID: "user.bulk.import", Domain: DomainApplication,
			Name:          "批量导入普通用户",
			Description:   "通过受控 CSV 批量创建普通用户（仅资料白名单：用户名/昵称/简介/语言/时区）；必须强认证与确认，幂等键绑定调用者与文件摘要；禁止导入密码/哈希/root/管理资格/已验证状态/MFA/角色，重复用户按稳定规则跳过或报冲突且不更新既有资料。",
			Default:       strongReauth,
			PermissionKey: "users.create",
			Implemented:   true,
		},
		{
			ID: "user.bulk.export", Domain: DomainApplication,
			Name:          "批量导出普通用户资料",
			Description:   "按字段许可与数据范围逐用户判定导出普通用户资料（CSV，防公式注入）；必须强认证与确认，默认不含邮箱/电话/密码哈希/MFA/令牌；报告只含授权范围内成功/失败与稳定错误码，导出文件写入宿主受控目录并记录摘要。",
			Default:       strongReauth,
			PermissionKey: "users.export",
			Implemented:   true,
		},
		{
			ID: "oauth.authorization.approve", Domain: DomainApplication,
			Name:          "批准 OAuth 应用授权请求",
			Description:   "用户在授权确认页批准应用以本人身份访问其账户数据；必须绑定真实用户会话并完成近期身份验证，确认页清晰显示应用与请求范围，范围与目标资源不能超出客户端登记；拒绝不签发授权码，取消确认不改变安全状态。",
			Default:       oauthConsent,
			PermissionKey: "",
			Implemented:   true,
		},
		{
			ID: "oauth.authorization.revoke.self", Domain: DomainApplication,
			Name:        "撤回自己的 OAuth 应用授权",
			Description: "用户撤回本人对某应用的授权；必须近期主密码验证与确认，只能撤回本人 AuthorizationID，撤销未兑换授权码、刷新令牌族与在线撤销标记，但已签发离线 Access Token 可能到原到期前仍可用。",
			Default:     passwordStrong,
			Implemented: true,
		},
		{
			ID: "oauth.device.authorization.approve", Domain: DomainApplication,
			Name:          "批准设备码授权请求",
			Description:   "电视或无浏览器 CLI 展示短码后，用户在另一台设备登录并核对短码，批准该设备以本人身份访问其账户数据；必须绑定真实完整会话并完成近期身份验证，确认页清晰显示应用与请求范围，等待/过期/拒绝/取消是流程状态而非系统故障；二维码只辅助打开确认页，绝不自动批准。",
			Default:       oauthConsent,
			PermissionKey: "",
			Implemented:   true,
		},
		{
			ID: "managed_api.policy.manage", Domain: DomainApplication,
			Name:          "配置应用托管管理 API 委托策略",
			Description:   "受信管理员为某个应用配置托管管理 API 的允许操作、对象范围、可读/可写字段与分页批量上限；必须近期强认证与确认并告知，策略严格校验（未知操作/字段、系统作用域、硬禁敏感字段与越界上限拒绝），修改与审计同事务并写行版本。",
			Default:       strongReauth,
			PermissionKey: "",
			Implemented:   true,
		},
		{
			ID: "app.qr_login.approve", Domain: DomainApplication,
			Name:          "批准 APP 扫码登录网页请求",
			Description:   "已登录 APP 扫描网页二维码后，用户核对发起端信息与应用范围并批准该网页以本人身份登录；必须绑定真实完整会话与近期身份验证，二维码只含一次性请求标识、不自动批准，确认页提醒不要确认他人发来的二维码，拒绝/取消/过期是流程状态而非系统故障。",
			Default:       oauthConsent,
			PermissionKey: "",
			Implemented:   true,
		},
		{
			ID: "application.webhook.endpoint.change", Domain: DomainApplication,
			Name:          "登记或修改应用安全事件 Webhook 端点",
			Description:   "为应用登记/修改/启停签名 Webhook 端点（URL、描述、状态）；必须强认证与确认，地址经出站安全策略校验（仅 https、拒绝回环/内网/保留地址、默认不跟随重定向），变更与拒绝写审计；不能把 Webhook 当作 OIDC 标准退出来声明。",
			Default:       strongReauth,
			PermissionKey: "applications.credentials.manage",
			Implemented:   true,
		},
		{
			ID: "application.webhook.secret.rotate", Domain: DomainApplication,
			Name:          "轮换或撤销应用 Webhook 签名密钥",
			Description:   "创建/轮换/撤销应用 Webhook 的 HMAC 签名密钥；必须强认证与确认，密钥明文只返回一次、库里只存认证加密密文，轮换保留明确过渡期（旧密钥过渡期内仍参与多签），撤销后立即失效，变更写审计且不记录密钥明文。",
			Default:       strongReauth,
			PermissionKey: "applications.credentials.manage",
			Implemented:   true,
		},
		{
			ID: "application.delete", Domain: DomainApplication, Name: "删除应用（逻辑删除）",
			Description:   "对已停用应用执行逻辑删除：立即拒绝该应用全部客户端凭证/旧令牌/会话与权限判定，成员/角色/权限/客户端/授权记录与审计保留供追溯；停用可恢复、删除是终态，物理清理只允许受控本地/系统通道在保留期后执行。必须强认证与确认，不能删除共享账户或安全审计记录。",
			Default:       strongReauth,
			PermissionKey: "applications.update",
			Implemented:   true,
		},
		{
			ID: "oauth.client.settings.change", Domain: DomainApplication, Name: "修改 OAuth 客户端安全设置",
			Description:   "修改已登记客户端的授权类型、回调、Scope、允许目标资源与 PKCE 要求；必须强认证与确认并告知，回调精确匹配、禁止通配与开放重定向，不能借修改安全设置转移应用权限。",
			Default:       strongReauth,
			PermissionKey: "applications.update",
			Implemented:   true,
		},
		{
			ID: "data.sensitive.export", Domain: DomainApplication, Name: "导出敏感数据",
			Description:   "导出用户或审计等敏感数据；必须强认证并确认，按当前许可范围限制字段与数据量，CSV 防公式注入。",
			Default:       strongReauth,
			PermissionKey: "users.export",
			Implemented:   false,
		},
		{
			ID: "backup.create", Domain: DomainBackup, Name: "创建加密备份",
			Description:   "创建系统范围的加密热备份并发布受控产物；必须强认证并确认，同一时刻只允许一个备份写入，失败/取消/超时不得使最后可用旧备份失去保护，执行身份每次尝试前重新复核权限。",
			Default:       strongReauth,
			PermissionKey: "backups.create",
			Implemented:   true,
		},
		{
			ID: "backup.export", Domain: DomainBackup, Name: "下载备份",
			Description:   "下载受控备份成品；必须强认证并确认，下载需要独立权限（查看列表不等于可下载），每次下载重新鉴权，短期一次性入口、no-store，不提供公开分享或永久链接。",
			Default:       strongReauth,
			PermissionKey: "backups.export",
			Implemented:   true,
		},
		{
			ID: "backup.retention.change", Domain: DomainBackup, Name: "修改备份保留策略",
			Description:   "设置数量/天数/容量保留上限与责任身份；必须强认证并确认，修改不追溯改写既有产物的创建时策略版本，不提供原始审计清理，策略保存不自动删除备份。",
			Default:       strongReauth,
			PermissionKey: "backups.retention",
			Implemented:   true,
		},
		{
			ID: "backup.cleanup", Domain: DomainBackup, Name: "清理备份产物",
			Description:   "按保留策略删除备份成品文件；必须强认证并确认，保护规则优先（最后可用备份、校验状态未知/失败、活动任务、执行时状态变化均跳过），只删除备份产物与受控元数据，不删除原始审计。",
			Default:       strongReauth,
			PermissionKey: "backups.cleanup",
			Implemented:   true,
		},
		{
			ID: "backup.restore", Domain: DomainBackup, Name: "恢复备份",
			Description:        "用备份恢复系统数据；仅 root 或受控本地应急管理员可执行（不开放匿名远程接口），必须强认证与确认并告知；先预演校验解密/完整性/数据库版本/容量/外部密钥，进入维护状态并在库外排他锁下创建回退备份后暂存验证、原子切换；失败默认保持维护并回退到恢复前状态；恢复后旧会话/刷新族/授权码/恢复代码/验证链接/扫码请求与签名密钥全部失效，审计独立保存后合并。",
			Default:            strongReauth,
			PermissionKey:      "backups.restore",
			RootOnly:           true,
			ImmutableSensitive: true,
			Implemented:        true,
		},
		{
			ID: "audit.export", Domain: DomainAudit, Name: "导出安全审计记录",
			Description:   "按获准数据范围导出脱敏审计记录（CSV/JSON）；必须强认证与确认并告知，导出单独授权、字段白名单、行数与字节上限、受控目录与随机文件名，不导出受限内部原因或秘密。",
			Default:       strongReauth,
			PermissionKey: "audit.export",
			Implemented:   true,
		},
		{
			ID: "audit.purge", Domain: DomainAudit, Name: "清理安全审计记录",
			Description:        "按保留策略清理安全审计记录；仅 root 可执行，必须强认证与确认并告知，分批、有边界、可取消，保存请求/执行者/范围/计数/结果，清理审计保留于受保护追加记录，不能批量掩盖敏感操作历史。",
			Default:            strongReauth,
			PermissionKey:      "audit.purge",
			RootOnly:           true,
			ImmutableSensitive: true,
			Implemented:        true,
		},
		{
			ID: "reports.export", Domain: DomainReport, Name: "生成并导出统计报告",
			Description:   "基于固定统计快照生成并下载统计报告产物（HTML/CSV/JSON/PDF/Markdown）；PDF 嵌入受信中文字体、Markdown 带机器可读元数据与不可信数据边界；必须强认证与确认并告知，所有格式生成与下载都需要 reports.export 权限，报告按当前权限与数据范围裁剪、产物带校验和与受控存储引用、下载再次鉴权；不导出原始审计全量记录、凭证、秘密或隐藏字段。执行器已在 internal/reports 实现，cmd/login-server 装配与页面属后续步骤。",
			Default:       strongReauth,
			PermissionKey: "reports.export",
			Implemented:   true,
		},
		{
			ID: "reports.cleanup", Domain: DomainReport, Name: "清理已过期报告文件",
			Description:   "按服务端保留策略清理已到期且超过宽限期的报告产物文件；必须强认证与确认并告知，服务端重新计算目标与范围、单次数量有界、只删除受控输出目录中的报告文件并推进历史清理状态，记录真实操作者/数量/失败结果；不删除原始安全审计记录，原始审计清理是独立的 root 受控流程。",
			Default:       strongReauth,
			PermissionKey: "reports.cleanup",
			Implemented:   true,
		},
		{
			ID: "root.recovery", Domain: DomainRecovery, Name: "root 受控恢复",
			Description:        "仅限本地受控应急通道处理的 root 恢复；必须强认证与确认并告知，不开放匿名远程入口，不能读取原密码或秘密。",
			Default:            strongReauthShort,
			RootOnly:           true,
			ImmutableSensitive: true,
			Implemented:        false,
		},
		{
			ID: "support.case.create", Domain: DomainRecovery, Name: "登记客服求助单",
			Description:   "客服在授权数据范围内登记求助单并定位普通用户；必须强认证并绑定操作/目标，root 与实际高权限账户拒绝处理，不能读取用户秘密或把求助单变成账户接管。",
			Default:       strongReauthNoConfirm,
			PermissionKey: "support.cases.create",
			Implemented:   true,
		},
		{
			ID: "support.case.update", Domain: DomainRecovery, Name: "更新客服求助单",
			Description:   "转派或结束客服求助单并追加不可覆盖的处理历史；必须强认证并绑定操作/目标，只能处理分配给自己的求助单。",
			Default:       strongReauthNoConfirm,
			PermissionKey: "support.cases.update",
			Implemented:   true,
		},
		{
			ID: "support.reset.send", Domain: DomainRecovery, Name: "客服向原验证邮箱发起找回",
			Description:   "由客服向目标此前已验证的邮箱发送一次性密码找回入口；必须强认证，不能指定新地址、读取链接/验证码或解除 MFA，发送不立即失效原密码，高权限账户拒绝。",
			Default:       strongReauthNoConfirm,
			PermissionKey: "recovery.request",
			Implemented:   true,
		},
		{
			ID: "support.recovery.request", Domain: DomainRecovery, Name: "发起人工核验恢复申请",
			Description:   "客服在获准范围内为既有渠道不可用的普通账户发起人工核验恢复申请；必须强认证并绑定目标/操作类型/核验依据/交付渠道；密码恢复与 MFA 恢复分别申请，root 与实际高权限账户拒绝。",
			Default:       strongReauthNoConfirm,
			PermissionKey: "recovery.request",
			Implemented:   true,
		},
		{
			ID: "support.recovery.approve", Domain: DomainRecovery, Name: "审批客服人工核验恢复",
			Description:   "独立审批人批准普通用户的人工核验恢复申请；必须强认证与确认并绑定申请内容摘要/操作类型，发起者与目标本人不得自批，批准有等待期与有效期，内容变化或审批人资格撤销后批准失效。",
			Default:       strongReauth,
			PermissionKey: "recovery.approve",
			Implemented:   true,
		},
		{
			ID: "support.recovery.execute", Domain: DomainRecovery, Name: "执行人工核验恢复",
			Description:   "在批准等待期已满且未过期时一次性执行密码恢复或 MFA 恢复；必须强认证并绑定请求/批准/内容摘要，执行前复核审批人与目标状态，执行人不得是发起者或审批人，双执行竞争只成功一次，成功后撤销旧凭证/会话并要求重新登录。",
			Default:       strongReauth,
			PermissionKey: "recovery.execute",
			Implemented:   true,
		},
		{
			ID: "session.management.access", Domain: DomainSession, Name: "访问管理接口",
			Description: "管理接口统一入口；必须完成强认证（MFA 未实现前默认拒绝），策略不能替代每个管理接口自己的权限检查。",
			Default:     strongReauthNoConfirm,
			Implemented: false,
		},
		{
			ID: "session.revoke.self", Domain: DomainSession, Name: "退出自己的会话",
			Description: "用户退出自己的指定会话、其他会话或全部会话；必须近期主密码验证与确认，只能作用于本人会话，不撤销 OAuth 应用授权或刷新令牌族，管理员强制下线另用 session.revoke.other。",
			Default:     passwordStrong,
			Implemented: true,
		},
		{
			ID: "session.revoke.other", Domain: DomainSession, Name: "强制下线其他会话",
			Description:   "按授权范围撤销其他用户或应用的在线会话；必须强认证，root 与受保护目标拒绝，不能用于窃取会话。",
			Default:       strongReauthNoNotify,
			PermissionKey: "sessions.revoke",
			Implemented:   true,
		},
		{
			ID: "security.policy.change", Domain: DomainPermission, Name: "修改敏感操作策略",
			Description:        "查看、修改与恢复敏感操作安全策略；仅 root 可执行，必须强认证与确认并告知；取消其他操作的敏感标记不取消基础权限、审计或 root 限制。",
			Default:            passwordStrong,
			PermissionKey:      "security.policy.manage",
			RootOnly:           true,
			ImmutableSensitive: true,
			Implemented:        true,
		},
		{
			ID: "onboarding.invite.create", Domain: DomainPermission, Name: "创建受控邀请",
			Description: "创建邀请并指定目标、应用与允许角色；基础授权由宿主 InviteAuthorizer 判定，必须近期身份验证与确认，角色赋权仍经委派 Guard 复核，不能借邀请提权。",
			Default:     passwordChange,
			Implemented: true,
		},
		{
			ID: "onboarding.registration.review", Domain: DomainPermission, Name: "审核注册申请",
			Description: "批准或拒绝待审核注册；基础授权由管理强认证授权器判定，必须强认证与确认，申请人不可自批，审核与角色变更同事务审计。",
			Default:     strongReauth,
			Implemented: true,
		},
		{
			ID: "email.change.verify", Domain: DomainEmail, Name: "确认邮箱变更",
			Description: "持一次性验证令牌把已申请的新邮箱切换为已验证地址；令牌本身是持有证明，不要求再次主认证，但成功后发送安全告知，且不能替代对目标的授权检查。",
			Default: Policy{Sensitive: true, ReauthRequired: false, MaxAuthAgeSeconds: 0,
				Strength: StrengthNone, ConfirmationRequired: false, NotificationRequired: true},
			PermissionKey: "self.credentials.manage",
			Implemented:   true,
		},
		{
			ID: "role.permission.change", Domain: DomainPermission, Name: "变更角色权限组合",
			Description:   "向角色添加或移除权限；必须经委派资格复核、强认证与确认，不能扩大超出可转授范围的权限。",
			Default:       strongReauth,
			PermissionKey: "roles.manage",
			Implemented:   false,
		},
		{
			ID: "role.state.change", Domain: DomainPermission, Name: "启用或停用含权角色",
			Description:   "启用/停用角色（启用会让其权限组合重新生效）；必须强认证并复核可转授范围与目标，不能借重新启用恢复被收回的能力。",
			Default:       strongReauth,
			PermissionKey: "roles.manage",
			Implemented:   false,
		},
		{
			ID: "group.member.change", Domain: DomainPermission, Name: "变更用户组成员",
			Description:   "批量加入或移除用户组成员（组角色会带来权限）；必须经委派资格复核、强认证与确认，不能向自身或自身所在组间接提权。",
			Default:       strongReauth,
			PermissionKey: "groups.manage",
			Implemented:   false,
		},
		{
			ID: "authn.root_password.setup", Domain: DomainPassword, Name: "设置 root 正式密码",
			Description: "仅限本地受控初始化流程为 root 设置正式密码；以一次性本机配置凭证为验证依据，不要求尚不存在的第二因素，必须确认并告知，不能开放远程匿名入口。",
			Default: Policy{Sensitive: true, ReauthRequired: false, MaxAuthAgeSeconds: 0,
				Strength: StrengthNone, ConfirmationRequired: true, NotificationRequired: true},
			RootOnly:           true,
			ImmutableSensitive: true,
			Implemented:        true,
		},
	}
}
