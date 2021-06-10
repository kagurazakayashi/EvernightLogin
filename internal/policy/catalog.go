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
)

// knownDomains 是允许的业务域集合。
var knownDomains = map[Domain]bool{
	DomainPassword: true, DomainEmail: true, DomainMFA: true,
	DomainPermission: true, DomainApplication: true, DomainBackup: true,
	DomainAudit: true, DomainSession: true, DomainProfile: true,
	DomainRecovery: true,
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
			Description:        "移除当前账户的某个第二因素；必须先验证替代方式，禁止移除最后一个可用因素导致降级，执行器未实现前 fail-closed。",
			Default:            strongReauth,
			PermissionKey:      "self.credentials.manage",
			ImmutableSensitive: true,
			Implemented:        false,
		},
		{
			ID: "passkey.register", Domain: DomainMFA, Name: "注册 Passkey",
			Description:   "为当前账户注册 WebAuthn Passkey；必须完成强认证与确认，执行器未实现前 fail-closed。",
			Default:       strongReauth,
			PermissionKey: "self.credentials.manage",
			Implemented:   false,
		},
		{
			ID: "passkey.remove", Domain: DomainMFA, Name: "删除 Passkey",
			Description:        "删除当前账户的 Passkey；必须强认证并确认，不能删除最后一个可用登录方式，执行器未实现前 fail-closed。",
			Default:            strongReauth,
			PermissionKey:      "self.credentials.manage",
			ImmutableSensitive: true,
			Implemented:        false,
		},
		{
			ID: "recovery.codes.rotate", Domain: DomainMFA, Name: "更新恢复代码",
			Description:   "生成新的一组一次性恢复代码并作废旧组；必须强认证并确认，成功告知，执行器未实现前 fail-closed。",
			Default:       strongReauth,
			PermissionKey: "self.credentials.manage",
			Implemented:   false,
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
			Implemented:   false,
		},
		{
			ID: "data.sensitive.export", Domain: DomainApplication, Name: "导出敏感数据",
			Description:   "导出用户或审计等敏感数据；必须强认证并确认，按当前许可范围限制字段与数据量，CSV 防公式注入。",
			Default:       strongReauth,
			PermissionKey: "users.export",
			Implemented:   false,
		},
		{
			ID: "backup.export", Domain: DomainBackup, Name: "导出备份",
			Description:   "生成并导出受控备份；必须强认证并确认，备份内容含密钥时按单独受保护导出策略处理。",
			Default:       strongReauth,
			PermissionKey: "backups.export",
			Implemented:   false,
		},
		{
			ID: "backup.restore", Domain: DomainBackup, Name: "恢复备份",
			Description:        "用备份恢复系统数据；仅 root 可执行，必须强认证与确认并告知，需要维护/停机与排他锁，失败必须回滚且记录真实操作者。",
			Default:            strongReauth,
			PermissionKey:      "backups.restore",
			RootOnly:           true,
			ImmutableSensitive: true,
			Implemented:        false,
		},
		{
			ID: "audit.purge", Domain: DomainAudit, Name: "清理安全审计记录",
			Description:        "按保留策略清理安全审计记录；仅 root 可执行，必须强认证与确认并告知，不能批量掩盖敏感操作历史。",
			Default:            strongReauth,
			PermissionKey:      "audit.purge",
			RootOnly:           true,
			ImmutableSensitive: true,
			Implemented:        false,
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
			ID: "support.recovery.approve", Domain: DomainRecovery, Name: "审批客服人工核验恢复",
			Description:   "审批普通用户的人工核验恢复申请；必须强认证与确认，目标/操作/接收地址改变后原审批失效，不能单人接管高权限账户。",
			Default:       strongReauth,
			PermissionKey: "recovery.approve",
			Implemented:   false,
		},
		{
			ID: "session.management.access", Domain: DomainSession, Name: "访问管理接口",
			Description: "管理接口统一入口；必须完成强认证（MFA 未实现前默认拒绝），策略不能替代每个管理接口自己的权限检查。",
			Default:     strongReauthNoConfirm,
			Implemented: false,
		},
		{
			ID: "session.revoke.other", Domain: DomainSession, Name: "强制下线其他会话",
			Description:   "按授权范围撤销其他用户或应用的在线会话；必须强认证，root 与受保护目标拒绝，不能用于窃取会话。",
			Default:       strongReauthNoNotify,
			PermissionKey: "sessions.revoke",
			Implemented:   false,
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
