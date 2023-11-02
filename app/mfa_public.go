package app

// 认证因素与安全中心公开门面（步骤 222）。
//
// 目标：让嵌入宿主不需要导入 internal/ 或触摸页面/HTTP 依赖，也能完成安全中心
// 的认证因素生命周期：
//   - 因素清单（TOTP / 邮件 / Passkey / 恢复代码 / 强因素状态）全部脱敏；
//   - 邮件因素的启用、验证、移除；
//   - Passkey 的主登录/第二步凭证注册、列出、重命名、撤销，以及免密码登录；
//   - TOTP 绑定清单与撤销（撤销要求当前 TOTP 验证码，证明持有因素）；
//   - 恢复代码只读概览（生成仍走 SecurityService.GenerateRecoveryCodes；消费后
//     只能进入受限恢复会话，由 AuthService.BeginRecovery 完成）。
//
// 安全边界：
//   - 所有敏感操作都要求完整（非受限）会话；会话秘密只来自宿主可信边界，结果不回显；
//   - 敏感操作（Passkey 注册/撤销）按既有 reauth 策略要求近期密码/强认证证据，
//     本门面不提供“直接标记已通过 MFA/再认证”的入口；
//   - 失败一律按领域稳定错误码投影并携带请求编号；
//   - 返回结构不含 TOTP 种子、Passkey 公钥/凭证 ID、恢复代码明文、会话秘密以外的
//     任何秘密；注册/绑定开始结果中的一次性数据（TOTP 种子、WebAuthn 选项）只返回
//     一次，宿主必须只展示给当前用户且不得记录。

import (
	"context"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/mfa"
	"github.com/kagurazakayashi/EvernightLogin/internal/passkey"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/recovery"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	"github.com/kagurazakayashi/EvernightLogin/internal/totp"
)

// MFAService 是认证因素管理门面（步骤 222）。
type MFAService interface {
	// List 返回当前会话主体的脱敏因素清单与恢复代码概览。
	List(ctx context.Context, req MFAFactorListRequest) (MFAFactorList, error)
	// RemoveTOTP 用当前 TOTP 验证码撤销活动绑定（证明持有因素；强制 MFA 且无其他
	// 强因素时由领域服务拒绝）。
	RemoveTOTP(ctx context.Context, req MFATOTPRemoveRequest) error
	// BeginEmailEnrollment 向已验证邮箱发送一次性验证码（需要完整会话；邮件通道
	// 未配置时以稳定错误拒绝，不伪造成功）。
	BeginEmailEnrollment(ctx context.Context, req MFAEmailEnrollBeginRequest) (MFAEmailEnrollStart, error)
	// ConfirmEmailEnrollment 验证渠道控制权并启用邮件第二因素。
	ConfirmEmailEnrollment(ctx context.Context, req MFAEmailEnrollConfirmRequest) (MFAEmailFactor, error)
	// RemoveEmail 停用邮件因素；强制 MFA 且没有其他强因素时由领域服务拒绝。
	RemoveEmail(ctx context.Context, req MFAEmailRemoveRequest) error
	// ListPasskeys 返回当前主体的 Passkey 凭证元数据（不含公钥/凭证 ID）。
	ListPasskeys(ctx context.Context, req MFAPasskeyListRequest) ([]MFAPasskeyCredential, error)
	// BeginPasskeyRegistration 开始 Passkey 注册 ceremony；Purpose 为空表示主登录
	// 用途，可显式指定 "login"/"second_factor"/"both"。
	BeginPasskeyRegistration(ctx context.Context, req MFAPasskeyRegisterBeginRequest) (MFAPasskeyRegisterStart, error)
	// FinishPasskeyRegistration 校验认证器注册响应并创建凭证（需要近期密码/强认证）。
	FinishPasskeyRegistration(ctx context.Context, req MFAPasskeyRegisterFinishRequest) (MFAPasskeyCredential, error)
	// RenamePasskey 修改凭证显示名。
	RenamePasskey(ctx context.Context, req MFAPasskeyRenameRequest) (MFAPasskeyCredential, error)
	// RemovePasskey 撤销本人 Passkey 凭证（需要近期密码/强认证；最后一个登录方式或
	// 强制 MFA 下最后强因素由领域服务拒绝）。
	RemovePasskey(ctx context.Context, req MFAPasskeyRemoveRequest) error
	// BeginPasskeyLogin 开始免密码 Passkey 登录 ceremony；Username 为空表示可发现
	// 凭证登录（不泄露账户存在性，统一失败）。
	BeginPasskeyLogin(ctx context.Context, req MFAPasskeyLoginBeginRequest) (MFAPasskeyLoginStart, error)
	// FinishPasskeyLogin 校验认证器断言并签发完整会话；秘密只返回一次。
	FinishPasskeyLogin(ctx context.Context, req MFAPasskeyLoginFinishRequest) (MFAPasskeyLoginResult, error)
	// RecoveryCodes 返回恢复代码组只读概览（不含代码明文/摘要）。
	RecoveryCodes(ctx context.Context, req MFARecoveryCodesRequest) (MFARecoveryCodesStatus, error)
}

// MFAFactorListRequest 读取因素清单；SessionSecret 必须是完整登录会话。
type MFAFactorListRequest struct {
	SessionSecret []byte
	RequestID     string
}

// MFATOTPFactor 是脱敏的 TOTP 绑定元数据。
type MFATOTPFactor struct {
	ID            string
	Status        string
	Digits        int
	PeriodSeconds int
	CreatedAt     time.Time
	ActivatedAt   time.Time
}

// MFAEmailFactor 是脱敏的邮件因素元数据。
type MFAEmailFactor struct {
	ID        string
	Type      string
	State     string
	CreatedAt time.Time
}

// MFAPasskeyCredential 是脱敏的 Passkey 凭证元数据（不含公钥/凭证 ID）。
type MFAPasskeyCredential struct {
	ID             string
	Name           string
	BackupEligible bool
	BackedUp       bool
	Transports     []string
	CreatedAt      time.Time
	LastUsedAt     time.Time
}

// MFAFactorList 是脱敏因素清单。
type MFAFactorList struct {
	TOTP                   []MFATOTPFactor
	EmailActive            bool
	EmailFactors           []MFAEmailFactor
	Passkeys               []MFAPasskeyCredential
	RecoveryCodesActive    bool
	RecoveryCodesRemaining int
	StrongFactorBound      bool
}

// MFATOTPRemoveRequest 撤销活动 TOTP 绑定；Code 是当前验证器显示的一次性验证码。
type MFATOTPRemoveRequest struct {
	SessionSecret []byte
	Code          string
	RequestID     string
}

// MFAEmailEnrollBeginRequest 开始邮件因素启用（需要完整会话）。
type MFAEmailEnrollBeginRequest struct {
	SessionSecret []byte
	RequestID     string
}

// MFAEmailEnrollStart 是验证码投递结果；AttemptToken 只返回一次。
type MFAEmailEnrollStart struct {
	ChallengeID  string
	AttemptToken []byte
	MaskedEmail  string
	ExpiresAt    time.Time
}

// MFAEmailEnrollConfirmRequest 用投递验证码确认邮件因素启用。
type MFAEmailEnrollConfirmRequest struct {
	SessionSecret []byte
	ChallengeID   string
	AttemptToken  []byte
	Code          string
	RequestID     string
}

// MFAEmailRemoveRequest 停用当前邮件因素。
type MFAEmailRemoveRequest struct {
	SessionSecret []byte
	RequestID     string
}

// MFAPasskeyListRequest 列出 Passkey 凭证。
type MFAPasskeyListRequest struct {
	SessionSecret []byte
	RequestID     string
}

// MFAPasskeyRegisterBeginRequest 开始 Passkey 注册 ceremony。
type MFAPasskeyRegisterBeginRequest struct {
	SessionSecret []byte
	// Purpose 为空表示主登录用途；允许 "login"、"second_factor"、"both"。
	Purpose   string
	RequestID string
}

// MFAPasskeyRegisterStart 是注册 ceremony 选项；PublicKey 只用于当前浏览器的
// navigator.credentials.create()，不含秘密，但仍不应写入普通日志。
type MFAPasskeyRegisterStart struct {
	CeremonyID string
	PublicKey  []byte
	ExpiresAt  time.Time
	RPID       string
	Purpose    string
}

// MFAPasskeyRegisterFinishRequest 完成 Passkey 注册；Password/TOTPCode 只用于本次
// 敏感操作再次认证，不保存、不回显。
type MFAPasskeyRegisterFinishRequest struct {
	SessionSecret []byte
	CeremonyID    string
	Response      []byte
	Name          string
	Password      string
	TOTPCode      string
	RequestID     string
}

// MFAPasskeyRenameRequest 修改凭证显示名。
type MFAPasskeyRenameRequest struct {
	SessionSecret []byte
	CredentialID  string
	Name          string
	RequestID     string
}

// MFAPasskeyRemoveRequest 撤销 Passkey 凭证；Password/TOTPCode 只用于本次敏感操作
// 再次认证，不保存、不回显。
type MFAPasskeyRemoveRequest struct {
	SessionSecret []byte
	CredentialID  string
	Password      string
	TOTPCode      string
	RequestID     string
}

// MFAPasskeyLoginBeginRequest 开始 Passkey 免密码登录。
type MFAPasskeyLoginBeginRequest struct {
	// Username 为空表示可发现凭证登录；非空时统一失败语义，不泄露账户存在性。
	Username   string
	AppID      string
	RememberMe bool
	ClientIP   string
	UserAgent  string
	RequestID  string
}

// MFAPasskeyLoginStart 是登录 ceremony 选项；PublicKey 用于当前浏览器的
// navigator.credentials.get()。
type MFAPasskeyLoginStart struct {
	CeremonyID string
	PublicKey  []byte
	ExpiresAt  time.Time
	RPID       string
}

// MFAPasskeyLoginFinishRequest 完成 Passkey 登录。
type MFAPasskeyLoginFinishRequest struct {
	CeremonyID string
	Response   []byte
	// ExistingSession 是本次出示的旧会话秘密（登录轮换），可为空。
	ExistingSession []byte
	RequestID       string
}

// MFAPasskeyLoginResult 是 Passkey 登录结果；会话秘密只返回一次。
type MFAPasskeyLoginResult struct {
	UserID        string
	SessionID     string
	SessionSecret []byte
	CSRFSecret    []byte
	ExpiresAt     time.Time
	Method        string
	Strength      string
	Credential    MFAPasskeyCredential
}

// MFARecoveryCodesRequest 读取恢复代码概览。
type MFARecoveryCodesRequest struct {
	SessionSecret []byte
	RequestID     string
}

// MFARecoveryCodesStatus 是恢复代码组只读概览（不含代码明文/摘要）。
type MFARecoveryCodesStatus struct {
	HasActiveGroup bool
	CodesRemaining int
	Generation     int64
	CreatedAt      time.Time
}

// mfaPublicFacade 实现 MFAService。
type mfaPublicFacade struct{ r *Runtime }

// List 返回当前会话主体的脱敏因素清单。
func (f *mfaPublicFacade) List(ctx context.Context,
	req MFAFactorListRequest) (MFAFactorList, error) {
	r := f.r
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return MFAFactorList{}, err
	}
	security := r.securityDomains()
	if security == nil {
		return MFAFactorList{}, configError("安全域服务未装配", requestID)
	}
	record, err := r.requireSession(ctx, req.SessionSecret, true, requestID)
	if err != nil {
		return MFAFactorList{}, err
	}
	result := MFAFactorList{}
	if security.TOTP != nil {
		caller, callerErr := totp.UserCaller(record.UserID)
		if callerErr != nil {
			return MFAFactorList{}, configError("会话主体无效", requestID)
		}
		bindings, bindErr := security.TOTP.Bindings(ctx, caller)
		if bindErr != nil {
			return MFAFactorList{}, mapDomainError("读取 TOTP 绑定失败",
				string(totp.CodeOf(bindErr)), requestID)
		}
		for _, binding := range bindings {
			result.TOTP = append(result.TOTP, MFATOTPFactor{
				ID: binding.ID, Status: binding.Status,
				Digits: binding.Digits, PeriodSeconds: binding.PeriodSeconds,
				CreatedAt: binding.CreatedAt, ActivatedAt: binding.ActivatedAt})
		}
	}
	if security.MFA != nil {
		caller, callerErr := mfa.UserCaller(record.UserID)
		if callerErr != nil {
			return MFAFactorList{}, configError("会话主体无效", requestID)
		}
		factors, factorsErr := security.MFA.Factors(ctx, caller)
		if factorsErr != nil {
			return MFAFactorList{}, mapDomainError("读取第二因素状态失败",
				string(mfa.CodeOf(factorsErr)), requestID)
		}
		for _, factor := range factors {
			if factor.Type != mfa.FactorEmail {
				continue
			}
			view := MFAEmailFactor{ID: factor.ID, Type: string(factor.Type),
				State: factor.State, CreatedAt: factor.CreatedAt}
			result.EmailFactors = append(result.EmailFactors, view)
			if factor.State == "active" {
				result.EmailActive = true
			}
		}
	}
	if security.Passkey != nil {
		caller, callerErr := passkey.UserCaller(record.UserID)
		if callerErr != nil {
			return MFAFactorList{}, configError("会话主体无效", requestID)
		}
		credentials, listErr := security.Passkey.List(ctx, caller)
		if listErr != nil {
			return MFAFactorList{}, mapDomainError("读取 Passkey 状态失败",
				string(passkey.CodeOf(listErr)), requestID)
		}
		for _, credential := range credentials {
			result.Passkeys = append(result.Passkeys, passkeyView(credential))
		}
	}
	if security.Recovery != nil {
		caller, callerErr := recovery.UserCaller(record.UserID)
		if callerErr != nil {
			return MFAFactorList{}, configError("会话主体无效", requestID)
		}
		inventory, inventoryErr := security.Recovery.Inventory(ctx, caller)
		if inventoryErr != nil {
			return MFAFactorList{}, mapDomainError("读取恢复代码状态失败",
				string(recovery.CodeOf(inventoryErr)), requestID)
		}
		result.RecoveryCodesActive = inventory.HasActiveGroup
		result.RecoveryCodesRemaining = inventory.CodesRemaining
	}
	if security.StrongFactors != nil {
		bound, strongErr := security.StrongFactors.HasStrongFactor(ctx, record.UserID)
		if strongErr != nil {
			return MFAFactorList{}, mapDomainError("读取强因素状态失败", "", requestID)
		}
		result.StrongFactorBound = bound
	}
	return result, nil
}

// RemoveTOTP 用当前 TOTP 验证码撤销活动绑定。
func (f *mfaPublicFacade) RemoveTOTP(ctx context.Context, req MFATOTPRemoveRequest) error {
	r := f.r
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return err
	}
	security := r.securityDomains()
	if security == nil || security.TOTP == nil {
		return configError("TOTP 服务未装配", requestID)
	}
	record, err := r.requireSession(ctx, req.SessionSecret, true, requestID)
	if err != nil {
		return err
	}
	caller, callerErr := totp.UserCaller(record.UserID)
	if callerErr != nil {
		return configError("会话主体无效", requestID)
	}
	if err := security.TOTP.RemoveBinding(ctx, caller, totp.RemoveRequest{
		Code: req.Code, RequestID: requestID}); err != nil {
		return mapDomainError("撤销 TOTP 绑定失败", string(totp.CodeOf(err)), requestID)
	}
	return nil
}

// BeginEmailEnrollment 向已验证邮箱发送一次性验证码。
func (f *mfaPublicFacade) BeginEmailEnrollment(ctx context.Context,
	req MFAEmailEnrollBeginRequest) (MFAEmailEnrollStart, error) {
	r := f.r
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return MFAEmailEnrollStart{}, err
	}
	security := r.securityDomains()
	if security == nil || security.MFA == nil {
		return MFAEmailEnrollStart{}, configError("MFA 服务未装配", requestID)
	}
	record, err := r.requireSession(ctx, req.SessionSecret, true, requestID)
	if err != nil {
		return MFAEmailEnrollStart{}, err
	}
	caller, callerErr := mfa.UserCaller(record.UserID)
	if callerErr != nil {
		return MFAEmailEnrollStart{}, configError("会话主体无效", requestID)
	}
	enrollment, enrollErr := security.MFA.BeginEmailFactorEnrollment(ctx, caller,
		mfa.FactorEnrollmentRequest{RequestID: requestID})
	if enrollErr != nil {
		return MFAEmailEnrollStart{}, mapDomainError("开始启用邮件因素失败",
			string(mfa.CodeOf(enrollErr)), requestID)
	}
	return MFAEmailEnrollStart{ChallengeID: enrollment.ChallengeID,
		AttemptToken: []byte(enrollment.AttemptToken),
		MaskedEmail:  enrollment.MaskedEmail, ExpiresAt: enrollment.ExpiresAt}, nil
}

// ConfirmEmailEnrollment 验证渠道控制权并启用邮件第二因素。
func (f *mfaPublicFacade) ConfirmEmailEnrollment(ctx context.Context,
	req MFAEmailEnrollConfirmRequest) (MFAEmailFactor, error) {
	r := f.r
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return MFAEmailFactor{}, err
	}
	security := r.securityDomains()
	if security == nil || security.MFA == nil {
		return MFAEmailFactor{}, configError("MFA 服务未装配", requestID)
	}
	record, err := r.requireSession(ctx, req.SessionSecret, true, requestID)
	if err != nil {
		return MFAEmailFactor{}, err
	}
	caller, callerErr := mfa.UserCaller(record.UserID)
	if callerErr != nil {
		return MFAEmailFactor{}, configError("会话主体无效", requestID)
	}
	factor, confirmErr := security.MFA.ConfirmEmailFactorEnrollment(ctx, caller,
		mfa.FactorVerifyRequest{ChallengeID: req.ChallengeID,
			AttemptToken: string(req.AttemptToken), Code: req.Code, RequestID: requestID})
	if confirmErr != nil {
		return MFAEmailFactor{}, mapDomainError("确认邮件因素失败",
			string(mfa.CodeOf(confirmErr)), requestID)
	}
	return MFAEmailFactor{ID: factor.ID, Type: string(factor.Type),
		State: factor.State, CreatedAt: factor.CreatedAt}, nil
}

// RemoveEmail 停用当前邮件因素。
func (f *mfaPublicFacade) RemoveEmail(ctx context.Context, req MFAEmailRemoveRequest) error {
	r := f.r
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return err
	}
	security := r.securityDomains()
	if security == nil || security.MFA == nil {
		return configError("MFA 服务未装配", requestID)
	}
	record, err := r.requireSession(ctx, req.SessionSecret, true, requestID)
	if err != nil {
		return err
	}
	caller, callerErr := mfa.UserCaller(record.UserID)
	if callerErr != nil {
		return configError("会话主体无效", requestID)
	}
	if err := security.MFA.RemoveEmailFactor(ctx, caller, requestID); err != nil {
		return mapDomainError("移除邮件因素失败", string(mfa.CodeOf(err)), requestID)
	}
	return nil
}

// ListPasskeys 返回当前主体的脱敏 Passkey 凭证列表。
func (f *mfaPublicFacade) ListPasskeys(ctx context.Context,
	req MFAPasskeyListRequest) ([]MFAPasskeyCredential, error) {
	r := f.r
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return nil, err
	}
	security := r.securityDomains()
	if security == nil || security.Passkey == nil {
		return nil, configError("Passkey 服务未装配或未启用", requestID)
	}
	record, err := r.requireSession(ctx, req.SessionSecret, true, requestID)
	if err != nil {
		return nil, err
	}
	caller, callerErr := passkey.UserCaller(record.UserID)
	if callerErr != nil {
		return nil, configError("会话主体无效", requestID)
	}
	credentials, listErr := security.Passkey.List(ctx, caller)
	if listErr != nil {
		return nil, mapDomainError("读取 Passkey 列表失败",
			string(passkey.CodeOf(listErr)), requestID)
	}
	result := make([]MFAPasskeyCredential, 0, len(credentials))
	for _, credential := range credentials {
		result = append(result, passkeyView(credential))
	}
	return result, nil
}

// BeginPasskeyRegistration 开始 Passkey 注册 ceremony。
func (f *mfaPublicFacade) BeginPasskeyRegistration(ctx context.Context,
	req MFAPasskeyRegisterBeginRequest) (MFAPasskeyRegisterStart, error) {
	r := f.r
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return MFAPasskeyRegisterStart{}, err
	}
	security := r.securityDomains()
	if security == nil || security.Passkey == nil {
		return MFAPasskeyRegisterStart{}, configError("Passkey 服务未装配或未启用", requestID)
	}
	record, err := r.requireSession(ctx, req.SessionSecret, true, requestID)
	if err != nil {
		return MFAPasskeyRegisterStart{}, err
	}
	purpose := passkey.PurposeLogin
	if raw := strings.TrimSpace(req.Purpose); raw != "" {
		purpose = passkey.Purpose(raw)
		if !purpose.Valid() {
			return MFAPasskeyRegisterStart{}, mapDomainError("Passkey 用途无效",
				"REQ_INVALID", requestID)
		}
	}
	caller, callerErr := passkey.UserCaller(record.UserID)
	if callerErr != nil {
		return MFAPasskeyRegisterStart{}, configError("会话主体无效", requestID)
	}
	start, beginErr := security.Passkey.BeginRegistrationWithPurpose(ctx, caller,
		requestID, purpose)
	if beginErr != nil {
		return MFAPasskeyRegisterStart{}, mapDomainError("开始注册 Passkey 失败",
			string(passkey.CodeOf(beginErr)), requestID)
	}
	return MFAPasskeyRegisterStart{CeremonyID: start.CeremonyID,
		PublicKey: []byte(start.PublicKey), ExpiresAt: start.ExpiresAt,
		RPID: start.RPID, Purpose: string(start.Purpose)}, nil
}

// FinishPasskeyRegistration 校验认证器响应并创建凭证（需要近期敏感认证）。
func (f *mfaPublicFacade) FinishPasskeyRegistration(ctx context.Context,
	req MFAPasskeyRegisterFinishRequest) (MFAPasskeyCredential, error) {
	r := f.r
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return MFAPasskeyCredential{}, err
	}
	security := r.securityDomains()
	if security == nil || security.Passkey == nil {
		return MFAPasskeyCredential{}, configError("Passkey 服务未装配或未启用", requestID)
	}
	record, err := r.requireSession(ctx, req.SessionSecret, true, requestID)
	if err != nil {
		return MFAPasskeyCredential{}, err
	}
	approved, approveErr := r.approveSensitive(ctx, record.UserID, "passkey.register",
		"注册 Passkey 凭证", req.Password, req.TOTPCode, requestID, policy.StrengthNone)
	if approveErr != nil {
		return MFAPasskeyCredential{}, approveErr
	}
	caller, callerErr := passkey.UserCaller(record.UserID)
	if callerErr != nil {
		return MFAPasskeyCredential{}, configError("会话主体无效", requestID)
	}
	credential, finishErr := security.Passkey.FinishRegistration(approved, caller,
		passkey.RegistrationFinishRequest{CeremonyID: req.CeremonyID,
			Response: req.Response, Name: req.Name, RequestID: requestID})
	if finishErr != nil {
		return MFAPasskeyCredential{}, mapDomainError("完成 Passkey 注册失败",
			string(passkey.CodeOf(finishErr)), requestID)
	}
	return passkeyView(credential), nil
}

// RenamePasskey 修改凭证显示名。
func (f *mfaPublicFacade) RenamePasskey(ctx context.Context,
	req MFAPasskeyRenameRequest) (MFAPasskeyCredential, error) {
	r := f.r
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return MFAPasskeyCredential{}, err
	}
	security := r.securityDomains()
	if security == nil || security.Passkey == nil {
		return MFAPasskeyCredential{}, configError("Passkey 服务未装配或未启用", requestID)
	}
	record, err := r.requireSession(ctx, req.SessionSecret, true, requestID)
	if err != nil {
		return MFAPasskeyCredential{}, err
	}
	caller, callerErr := passkey.UserCaller(record.UserID)
	if callerErr != nil {
		return MFAPasskeyCredential{}, configError("会话主体无效", requestID)
	}
	credential, renameErr := security.Passkey.Rename(ctx, caller,
		passkey.RenameRequest{CredentialID: req.CredentialID, Name: req.Name,
			RequestID: requestID})
	if renameErr != nil {
		return MFAPasskeyCredential{}, mapDomainError("重命名 Passkey 失败",
			string(passkey.CodeOf(renameErr)), requestID)
	}
	return passkeyView(credential), nil
}

// RemovePasskey 撤销本人 Passkey 凭证（需要近期敏感认证）。
func (f *mfaPublicFacade) RemovePasskey(ctx context.Context, req MFAPasskeyRemoveRequest) error {
	r := f.r
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return err
	}
	security := r.securityDomains()
	if security == nil || security.Passkey == nil {
		return configError("Passkey 服务未装配或未启用", requestID)
	}
	record, err := r.requireSession(ctx, req.SessionSecret, true, requestID)
	if err != nil {
		return err
	}
	approved, approveErr := r.approveSensitive(ctx, record.UserID, "passkey.remove",
		"撤销 Passkey 凭证", req.Password, req.TOTPCode, requestID, policy.StrengthNone)
	if approveErr != nil {
		return approveErr
	}
	caller, callerErr := passkey.UserCaller(record.UserID)
	if callerErr != nil {
		return configError("会话主体无效", requestID)
	}
	if err := security.Passkey.Revoke(approved, caller, passkey.RevokeRequest{
		CredentialID: req.CredentialID, RequestID: requestID}); err != nil {
		return mapDomainError("撤销 Passkey 失败", string(passkey.CodeOf(err)), requestID)
	}
	return nil
}

// BeginPasskeyLogin 开始免密码 Passkey 登录 ceremony。
func (f *mfaPublicFacade) BeginPasskeyLogin(ctx context.Context,
	req MFAPasskeyLoginBeginRequest) (MFAPasskeyLoginStart, error) {
	r := f.r
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return MFAPasskeyLoginStart{}, err
	}
	security := r.securityDomains()
	if security == nil || security.Passkey == nil {
		return MFAPasskeyLoginStart{}, configError("Passkey 服务未装配或未启用", requestID)
	}
	start, beginErr := security.Passkey.BeginLogin(ctx, passkey.LoginStartRequest{
		Username: req.Username, AppID: req.AppID, RememberMe: req.RememberMe,
		Client:    session.ClientInfo{UserAgent: req.UserAgent, Address: req.ClientIP},
		RequestID: requestID})
	if beginErr != nil {
		return MFAPasskeyLoginStart{}, mapDomainError("开始 Passkey 登录失败",
			string(passkey.CodeOf(beginErr)), requestID)
	}
	return MFAPasskeyLoginStart{CeremonyID: start.CeremonyID,
		PublicKey: []byte(start.PublicKey), ExpiresAt: start.ExpiresAt,
		RPID: start.RPID}, nil
}

// FinishPasskeyLogin 校验认证器断言并签发完整会话。
func (f *mfaPublicFacade) FinishPasskeyLogin(ctx context.Context,
	req MFAPasskeyLoginFinishRequest) (MFAPasskeyLoginResult, error) {
	r := f.r
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return MFAPasskeyLoginResult{}, err
	}
	security := r.securityDomains()
	if security == nil || security.Passkey == nil {
		return MFAPasskeyLoginResult{}, configError("Passkey 服务未装配或未启用", requestID)
	}
	result, finishErr := security.Passkey.FinishLogin(ctx, passkey.LoginFinishRequest{
		CeremonyID: req.CeremonyID, Response: req.Response,
		ExistingSession: string(req.ExistingSession), RequestID: requestID})
	if finishErr != nil {
		return MFAPasskeyLoginResult{}, mapDomainError("Passkey 登录失败",
			string(passkey.CodeOf(finishErr)), requestID)
	}
	login := MFAPasskeyLoginResult{UserID: result.Authenticated.UserID,
		SessionID: result.Session.Session.ID,
		ExpiresAt: result.Session.Session.AbsoluteExpiresAt,
		Method:    "passkey", Strength: "strong",
		Credential: passkeyView(result.Credential)}
	if secret := result.Session.Secret.Reveal(); secret != "" {
		login.SessionSecret = []byte(secret)
	}
	if csrf := result.Session.CSRFSecret.Reveal(); csrf != "" {
		login.CSRFSecret = []byte(csrf)
	}
	return login, nil
}

// RecoveryCodes 返回恢复代码组只读概览。
func (f *mfaPublicFacade) RecoveryCodes(ctx context.Context,
	req MFARecoveryCodesRequest) (MFARecoveryCodesStatus, error) {
	r := f.r
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return MFARecoveryCodesStatus{}, err
	}
	security := r.securityDomains()
	if security == nil || security.Recovery == nil {
		return MFARecoveryCodesStatus{}, configError("恢复服务未装配", requestID)
	}
	record, err := r.requireSession(ctx, req.SessionSecret, true, requestID)
	if err != nil {
		return MFARecoveryCodesStatus{}, err
	}
	caller, callerErr := recovery.UserCaller(record.UserID)
	if callerErr != nil {
		return MFARecoveryCodesStatus{}, configError("会话主体无效", requestID)
	}
	inventory, inventoryErr := security.Recovery.Inventory(ctx, caller)
	if inventoryErr != nil {
		return MFARecoveryCodesStatus{}, mapDomainError("读取恢复代码概览失败",
			string(recovery.CodeOf(inventoryErr)), requestID)
	}
	return MFARecoveryCodesStatus{HasActiveGroup: inventory.HasActiveGroup,
		CodesRemaining: inventory.CodesRemaining, Generation: inventory.Generation,
		CreatedAt: inventory.CreatedAt}, nil
}

// passkeyView 把 Passkey 元数据投影为公开脱敏视图。
func passkeyView(credential passkey.CredentialMetadata) MFAPasskeyCredential {
	return MFAPasskeyCredential{ID: credential.ID, Name: credential.Name,
		BackupEligible: credential.BackupEligible, BackedUp: credential.BackedUp,
		Transports: append([]string(nil), credential.Transports...),
		CreatedAt:  credential.CreatedAt, LastUsedAt: credential.LastUsedAt}
}
