// Package uisecurityadapter 把步骤 67 安全中心页面契约接到真实 mfa/totp/passkey/
// recovery/session/oauthflow/reauth 服务（模块内适配器；生产宿主按同一契约装配）。
//
// 安全边界：只构造可信用户 Caller；敏感操作先以操作 ID+目标+参数做 reauth 挑战，
// 成功后才把批准信号放入上下文调用真实服务；强认证不足 fail-closed 返回
// MFA_REQUIRED，不降级；页面传入的当前密码只用于该挑战，不写日志/存储。
package uisecurityadapter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/mfa"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
	"github.com/kagurazakayashi/EvernightLogin/internal/passkey"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/recovery"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	"github.com/kagurazakayashi/EvernightLogin/internal/totp"
)

// ReauthChallenger 是适配器需要的再次认证子集（生产实现 *reauth.Service）。
type ReauthChallenger interface {
	BeginChallenge(ctx context.Context, caller reauth.Caller,
		request reauth.ChallengeRequest) (reauth.Challenge, error)
	VerifyChallenge(ctx context.Context, caller reauth.Caller,
		request reauth.VerifyChallengeRequest) (reauth.ApprovalGrant, error)
	NotifyOutcome(ctx context.Context, result reauth.Result, outcome reauth.Outcome) error
}

// Options 是适配器依赖：MFA/TOTP/Recovery/Sessions/Reauth 是安全中心核心必需；
// Passkeys/OAuth 为可选子能力，nil 表示未启用，对应方法返回 FEATURE_NOT_ENABLED，
// 不 panic、不伪造空列表。核心缺失时拒绝构造（fail-closed）。
type Options struct {
	MFA      *mfa.Service
	TOTP     *totp.Service
	Passkeys *passkey.Service
	Recovery *recovery.Service
	Sessions *session.Service
	OAuth    *oauthflow.Service
	Reauth   ReauthChallenger
	// ApplicationNames 是受控 client_id -> 应用展示名目录；缺失回退 ClientID。
	ApplicationNames map[string]string
	Now              func() time.Time
	Logger           *slog.Logger
}

// Adapter 实现 login.UIPageSecurityBackend。
type Adapter struct{ opts Options }

// New 校验依赖并构造适配器。
func New(options Options) (*Adapter, error) {
	if options.MFA == nil || options.TOTP == nil ||
		options.Recovery == nil || options.Sessions == nil || options.Reauth == nil {
		return nil, fmt.Errorf("安全中心页面适配器缺少核心服务")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Adapter{opts: options}, nil
}

// featureNotEnabled 返回可选子能力未启用的稳定错误；调用方映射为 403 与明确提示，
// 不把它伪装成空数据或成功。
func featureNotEnabled() error { return mapped("FEATURE_NOT_ENABLED") }

// GetOverview 返回真实事实摘要（不输出安全结论）。
func (a *Adapter) GetOverview(ctx context.Context, userID string) (login.UISecurityOverview, error) {
	overview := login.UISecurityOverview{
		MFAAvailable: true, TOTPAvailable: true,
		RecoveryCodesAvailable: true, SessionsAvailable: true,
		PasskeyAvailable: a.opts.Passkeys != nil, OAuthAvailable: a.opts.OAuth != nil,
	}
	factors, err := a.factors(ctx, userID)
	if err != nil {
		return overview, err
	}
	overview.EmailMFAEnabled = len(factors) > 0
	totpState, err := a.GetTOTP(ctx, userID)
	if err != nil {
		return overview, err
	}
	overview.TOTPEnabled = totpState.Enabled
	if a.opts.Passkeys != nil {
		passkeys, listErr := a.ListPasskeys(ctx, userID)
		if listErr != nil {
			return overview, listErr
		}
		overview.PasskeyCount = len(passkeys)
	}
	recoveryInventory, err := a.GetRecoveryCodes(ctx, userID)
	if err != nil {
		return overview, err
	}
	overview.RecoveryAvailable = recoveryInventory.HasActiveGroup
	overview.RecoveryRemaining = recoveryInventory.CodesRemaining
	// 会话总数由会话页单独读取，概览不猜测；ActiveSessions 保持 0 表示未查询。
	return overview, nil
}

// ListMFA 返回真实邮件因素。
func (a *Adapter) ListMFA(ctx context.Context, userID string) ([]login.UIMFAFactor, error) {
	factors, err := a.factors(ctx, userID)
	if err != nil {
		return nil, err
	}
	return factors, nil
}

func (a *Adapter) factors(ctx context.Context, userID string) ([]login.UIMFAFactor, error) {
	caller, err := mfa.UserCaller(userID)
	if err != nil {
		return nil, securityErr("ACCESS_DENIED")
	}
	factors, listErr := a.opts.MFA.Factors(ctx, caller)
	if listErr != nil {
		return nil, mapMFAError(listErr)
	}
	result := make([]login.UIMFAFactor, 0, len(factors))
	for _, factor := range factors {
		result = append(result, login.UIMFAFactor{Type: string(factor.Type),
			State: factor.State, CreatedAt: factor.CreatedAt})
	}
	return result, nil
}

// BeginMFAEnrollment 发送真实邮件验证码。
func (a *Adapter) BeginMFAEnrollment(ctx context.Context, userID, requestID string) (login.UIMFAEnrollment, error) {
	caller, err := mfa.UserCaller(userID)
	if err != nil {
		return login.UIMFAEnrollment{}, securityErr("ACCESS_DENIED")
	}
	enrollment, beginErr := a.opts.MFA.BeginEmailFactorEnrollment(ctx, caller,
		mfa.FactorEnrollmentRequest{RequestID: requestID})
	if beginErr != nil {
		return login.UIMFAEnrollment{}, mapMFAError(beginErr)
	}
	return login.UIMFAEnrollment{ChallengeID: enrollment.ChallengeID,
		AttemptToken: enrollment.AttemptToken, MaskedEmail: enrollment.MaskedEmail,
		ExpiresAt: enrollment.ExpiresAt}, nil
}

// ConfirmMFAEnrollment 验证码通过才启用邮件因素。
func (a *Adapter) ConfirmMFAEnrollment(ctx context.Context, userID string,
	confirm login.UISecurityConfirm) error {
	caller, err := mfa.UserCaller(userID)
	if err != nil {
		return securityErr("ACCESS_DENIED")
	}
	if _, confirmErr := a.opts.MFA.ConfirmEmailFactorEnrollment(ctx, caller,
		mfa.FactorVerifyRequest{ChallengeID: confirm.ChallengeID,
			AttemptToken: confirm.AttemptToken, Code: confirm.Code,
			RequestID: newRequestID(a.opts.Now())}); confirmErr != nil {
		return mapMFAError(confirmErr)
	}
	return nil
}

// RemoveMFA 需 mfa.remove 再次认证后移除邮件因素。
func (a *Adapter) RemoveMFA(ctx context.Context, userID, currentPassword, requestID string) error {
	challengeCtx, result, err := a.approve(ctx, userID, "mfa.remove", "user", userID,
		map[string]string{"factor": "email"}, currentPassword, requestID, "移除邮件两步验证因素")
	if err != nil {
		return err
	}
	caller, callerErr := mfa.UserCaller(userID)
	if callerErr != nil {
		return securityErr("ACCESS_DENIED")
	}
	removeErr := a.opts.MFA.RemoveEmailFactor(challengeCtx, caller, requestID)
	a.notify(result, removeErr)
	if removeErr != nil {
		return mapMFAError(removeErr)
	}
	return nil
}

// GetTOTP 返回真实 TOTP 元数据（不含种子）。
func (a *Adapter) GetTOTP(ctx context.Context, userID string) (login.UITOTPState, error) {
	caller, err := totp.UserCaller(userID)
	if err != nil {
		return login.UITOTPState{}, securityErr("ACCESS_DENIED")
	}
	bindings, listErr := a.opts.TOTP.Bindings(ctx, caller)
	if listErr != nil {
		return login.UITOTPState{}, mapTOTPError(listErr)
	}
	state := login.UITOTPState{Status: "unbound"}
	for _, binding := range bindings {
		if binding.Status == "active" {
			state.Enabled = true
			state.Status = binding.Status
			state.Algorithm = string(binding.Algorithm)
			state.Digits = binding.Digits
			state.PeriodSeconds = binding.PeriodSeconds
			state.ActivatedAt = binding.ActivatedAt
			break
		}
	}
	return state, nil
}

// BeginTOTP 开始真实绑定（Secret/URI 仅一次返回）。
func (a *Adapter) BeginTOTP(ctx context.Context, userID, requestID string) (login.UITOTPBinding, error) {
	caller, err := totp.UserCaller(userID)
	if err != nil {
		return login.UITOTPBinding{}, securityErr("ACCESS_DENIED")
	}
	start, beginErr := a.opts.TOTP.BeginBinding(ctx, caller, requestID)
	if beginErr != nil {
		return login.UITOTPBinding{}, mapTOTPError(beginErr)
	}
	return login.UITOTPBinding{BindingID: start.BindingID, Secret: start.Secret,
		URI: start.URI, ExpiresAt: start.ExpiresAt}, nil
}

// BeginTOTPWithPassword 是页面级 reauth 扩展：先以当前密码完成 mfa.add 一次性
// 批准，再在同一请求上下文开始 TOTP 绑定；策略仍由真实 reauth 服务判定，缺密码/
// 弱认证/策略要求强认证时 fail-closed。
func (a *Adapter) BeginTOTPWithPassword(ctx context.Context, userID, currentPassword,
	requestID string) (login.UITOTPBinding, error) {
	challengeCtx, result, err := a.approve(ctx, userID, "mfa.add", "user", userID,
		map[string]string{"action": "totp_bind"}, currentPassword, requestID, "绑定验证器")
	if err != nil {
		return login.UITOTPBinding{}, err
	}
	caller, callerErr := totp.UserCaller(userID)
	if callerErr != nil {
		return login.UITOTPBinding{}, securityErr("ACCESS_DENIED")
	}
	start, beginErr := a.opts.TOTP.BeginBinding(challengeCtx, caller, requestID)
	a.notify(result, beginErr)
	if beginErr != nil {
		return login.UITOTPBinding{}, mapTOTPError(beginErr)
	}
	return login.UITOTPBinding{BindingID: start.BindingID, Secret: start.Secret,
		URI: start.URI, ExpiresAt: start.ExpiresAt}, nil
}

// ConfirmTOTP 用动态码确认绑定。
func (a *Adapter) ConfirmTOTP(ctx context.Context, userID string, confirm login.UISecurityConfirm) error {
	caller, err := totp.UserCaller(userID)
	if err != nil {
		return securityErr("ACCESS_DENIED")
	}
	if _, confirmErr := a.opts.TOTP.ConfirmBinding(ctx, caller, totp.BindConfirm{
		BindingID: confirm.ChallengeID, Code: confirm.Code,
		RequestID: newRequestID(a.opts.Now())}); confirmErr != nil {
		return mapTOTPError(confirmErr)
	}
	return nil
}

// RemoveTOTP 需当前动态码并由服务内部再认证后解除。
func (a *Adapter) RemoveTOTP(ctx context.Context, userID, currentPassword, code,
	requestID string) error {
	challengeCtx, result, err := a.approve(ctx, userID, "mfa.remove", "user", userID,
		map[string]string{"factor": "totp"}, currentPassword, requestID, "解除 TOTP 验证器")
	if err != nil {
		return err
	}
	caller, callerErr := totp.UserCaller(userID)
	if callerErr != nil {
		return securityErr("ACCESS_DENIED")
	}
	removeErr := a.opts.TOTP.RemoveBinding(challengeCtx, caller,
		totp.RemoveRequest{Code: code, RequestID: requestID})
	a.notify(result, removeErr)
	if removeErr != nil {
		return mapTOTPError(removeErr)
	}
	return nil
}

// ListPasskeys 返回真实 Passkey 元数据。
func (a *Adapter) ListPasskeys(ctx context.Context, userID string) ([]login.UIPasskey, error) {
	if a.opts.Passkeys == nil {
		return nil, featureNotEnabled()
	}
	caller, err := passkey.UserCaller(userID)
	if err != nil {
		return nil, securityErr("ACCESS_DENIED")
	}
	credentials, listErr := a.opts.Passkeys.List(ctx, caller)
	if listErr != nil {
		return nil, mapPasskeyError(listErr)
	}
	result := make([]login.UIPasskey, 0, len(credentials))
	for _, credential := range credentials {
		result = append(result, login.UIPasskey{ID: credential.ID, Name: credential.Name,
			BackupEligible: credential.BackupEligible, BackedUp: credential.BackedUp,
			Transports: append([]string(nil), credential.Transports...),
			CreatedAt:  credential.CreatedAt, LastUsedAt: credential.LastUsedAt})
	}
	return result, nil
}

// BeginPasskeyRegistration 由服务端选择用途后开始注册。
func (a *Adapter) BeginPasskeyRegistration(ctx context.Context, userID,
	requestID string) (login.UIPasskeyRegistration, error) {
	if a.opts.Passkeys == nil {
		return login.UIPasskeyRegistration{}, featureNotEnabled()
	}
	caller, err := passkey.UserCaller(userID)
	if err != nil {
		return login.UIPasskeyRegistration{}, securityErr("ACCESS_DENIED")
	}
	start, beginErr := a.opts.Passkeys.BeginRegistrationWithPurpose(ctx, caller, requestID,
		passkey.PurposeLogin)
	if beginErr != nil {
		return login.UIPasskeyRegistration{}, mapPasskeyError(beginErr)
	}
	return login.UIPasskeyRegistration{CeremonyID: start.CeremonyID,
		PublicKey: []byte(start.PublicKey), ExpiresAt: start.ExpiresAt}, nil
}

// FinishPasskeyRegistration 验证真实 WebAuthn 断言后启用凭证。
func (a *Adapter) FinishPasskeyRegistration(ctx context.Context, userID string,
	finish login.UIPasskeyFinish) error {
	if a.opts.Passkeys == nil {
		return featureNotEnabled()
	}
	caller, err := passkey.UserCaller(userID)
	if err != nil {
		return securityErr("ACCESS_DENIED")
	}
	if _, finishErr := a.opts.Passkeys.FinishRegistration(ctx, caller,
		passkey.RegistrationFinishRequest{CeremonyID: finish.CeremonyID,
			Response: finish.Response, Name: finish.Name,
			RequestID: newRequestID(a.opts.Now())}); finishErr != nil {
		return mapPasskeyError(finishErr)
	}
	return nil
}

// FinishPasskeyRegistrationWithPassword 是页面级 reauth 扩展：先以当前密码完成
// passkey.register 一次性批准，再调用真实 WebAuthn finish；批准与策略仍由真实
// reauth/服务层判定，绝不绕过强认证或伪造成功。
func (a *Adapter) FinishPasskeyRegistrationWithPassword(ctx context.Context, userID string,
	finish login.UIPasskeyFinish) error {
	if a.opts.Passkeys == nil {
		return featureNotEnabled()
	}
	challengeCtx, result, err := a.approve(ctx, userID, "passkey.register", "user", userID,
		map[string]string{"action": "passkey_register"}, finish.CurrentPassword,
		newRequestID(a.opts.Now()), "注册 Passkey")
	if err != nil {
		return err
	}
	caller, callerErr := passkey.UserCaller(userID)
	if callerErr != nil {
		return securityErr("ACCESS_DENIED")
	}
	_, finishErr := a.opts.Passkeys.FinishRegistration(challengeCtx, caller,
		passkey.RegistrationFinishRequest{CeremonyID: finish.CeremonyID,
			Response: finish.Response, Name: finish.Name,
			RequestID: newRequestID(a.opts.Now())})
	a.notify(result, finishErr)
	if finishErr != nil {
		return mapPasskeyError(finishErr)
	}
	return nil
}

// RenamePasskey 仅改显示名（服务不要求再次认证）。
func (a *Adapter) RenamePasskey(ctx context.Context, userID, credentialID, name,
	requestID string) error {
	if a.opts.Passkeys == nil {
		return featureNotEnabled()
	}
	caller, err := passkey.UserCaller(userID)
	if err != nil {
		return securityErr("ACCESS_DENIED")
	}
	if _, renameErr := a.opts.Passkeys.Rename(ctx, caller, passkey.RenameRequest{
		CredentialID: credentialID, Name: name, RequestID: requestID}); renameErr != nil {
		return mapPasskeyError(renameErr)
	}
	return nil
}

// RemovePasskey 由服务内部 passkey.remove 再认证并检查最后登录方式。
func (a *Adapter) RemovePasskey(ctx context.Context, userID, credentialID,
	currentPassword, requestID string) error {
	if a.opts.Passkeys == nil {
		return featureNotEnabled()
	}
	challengeCtx, result, err := a.approve(ctx, userID, "passkey.remove", "user", userID,
		map[string]string{"credential_id": credentialID}, currentPassword, requestID,
		"撤销 Passkey 凭证")
	if err != nil {
		return err
	}
	caller, callerErr := passkey.UserCaller(userID)
	if callerErr != nil {
		return securityErr("ACCESS_DENIED")
	}
	removeErr := a.opts.Passkeys.Revoke(challengeCtx, caller, passkey.RevokeRequest{
		CredentialID: credentialID, RequestID: requestID})
	a.notify(result, removeErr)
	if removeErr != nil {
		return mapPasskeyError(removeErr)
	}
	return nil
}

// GetRecoveryCodes 返回恢复代码组只读概览。
func (a *Adapter) GetRecoveryCodes(ctx context.Context, userID string) (login.UIRecoveryInventory, error) {
	caller, err := recovery.UserCaller(userID)
	if err != nil {
		return login.UIRecoveryInventory{}, securityErr("ACCESS_DENIED")
	}
	inventory, inventoryErr := a.opts.Recovery.Inventory(ctx, caller)
	if inventoryErr != nil {
		return login.UIRecoveryInventory{}, mapRecoveryError(inventoryErr)
	}
	return login.UIRecoveryInventory{HasActiveGroup: inventory.HasActiveGroup,
		Generation: inventory.Generation, CodesRemaining: inventory.CodesRemaining,
		CreatedAt: inventory.CreatedAt}, nil
}

// GenerateRecoveryCodes 需 recovery.codes.rotate 再认证后生成新组。
func (a *Adapter) GenerateRecoveryCodes(ctx context.Context, userID, currentPassword,
	totpCode, requestID string) ([]string, error) {
	challengeCtx, result, err := a.approveWithMinimum(ctx, userID, "recovery.codes.rotate", "user",
		userID, map[string]string{"action": "rotate"}, currentPassword, requestID,
		"更新恢复代码", policy.StrengthStrong, totpCode)
	if err != nil {
		return nil, err
	}
	caller, callerErr := recovery.UserCaller(userID)
	if callerErr != nil {
		return nil, securityErr("ACCESS_DENIED")
	}
	generated, generateErr := a.opts.Recovery.Generate(challengeCtx, caller,
		recovery.GenerateRequest{RequestID: requestID})
	a.notify(result, generateErr)
	if generateErr != nil {
		return nil, mapRecoveryError(generateErr)
	}
	codes := make([]string, 0, len(generated.Codes))
	for _, code := range generated.Codes {
		codes = append(codes, code.Reveal())
	}
	return codes, nil
}

// ListSessions 分页读取本人活动会话（用户身份来自服务端会话）。
func (a *Adapter) ListSessions(ctx context.Context, request *http.Request, page, pageSize int) (login.UISessionPage, error) {
	secret, err := a.sessionSecret(request)
	if err != nil {
		return login.UISessionPage{}, err
	}
	result, listErr := a.opts.Sessions.ListSessions(ctx, secret,
		session.ListOptions{Page: page, PageSize: pageSize})
	if listErr != nil {
		return login.UISessionPage{}, mapSessionError(listErr)
	}
	resultPage := login.UISessionPage{Page: result.Page, PageSize: result.PageSize,
		Total: result.Total, HasMore: result.HasMore}
	for _, summary := range result.Sessions {
		resultPage.Sessions = append(resultPage.Sessions, login.UISessionSummary{
			ID: summary.ID, Current: summary.Current, AppID: summary.AppID,
			Kind: string(summary.Kind), Reason: string(summary.Reason),
			CreatedAt: summary.CreatedAt, LastSeenAt: summary.LastSeenAt,
			IdleExpiresAt: summary.IdleExpiresAt, AbsoluteExpiresAt: summary.AbsoluteExpiresAt,
			RememberMe:  summary.RememberMe,
			ClientHint:  maskUserAgent(summary.Client.UserAgent),
			AddressHint: maskAddress(summary.Client.Address)})
	}
	return resultPage, nil
}

// RevokeSession 退出指定本人会话。
func (a *Adapter) RevokeSession(ctx context.Context, request *http.Request,
	targetSessionID, currentPassword, requestID string) error {
	secret, err := a.sessionSecret(request)
	if err != nil {
		return err
	}
	userID, userErr := a.userID(ctx, secret)
	if userErr != nil {
		return userErr
	}
	challengeCtx, result, err := a.approve(ctx, userID, "session.revoke.self", "session",
		targetSessionID, map[string]string{"target": targetSessionID}, currentPassword,
		requestID, "退出指定会话")
	if err != nil {
		return err
	}
	_, revokeErr := a.opts.Sessions.RevokeSession(challengeCtx, secret, targetSessionID)
	a.notify(result, revokeErr)
	if revokeErr != nil {
		return mapSessionError(revokeErr)
	}
	return nil
}

// RevokeOtherSessions 退出其他会话（保留当前）。
func (a *Adapter) RevokeOtherSessions(ctx context.Context, request *http.Request,
	currentPassword, requestID string) (int64, error) {
	secret, err := a.sessionSecret(request)
	if err != nil {
		return 0, err
	}
	userID, userErr := a.userID(ctx, secret)
	if userErr != nil {
		return 0, userErr
	}
	challengeCtx, result, err := a.approve(ctx, userID, "session.revoke.self", "user", userID,
		map[string]string{"keep_current": "true"}, currentPassword, requestID,
		"退出其他所有会话")
	if err != nil {
		return 0, err
	}
	count, revokeErr := a.opts.Sessions.RevokeAllOwnSessions(challengeCtx, secret, true)
	a.notify(result, revokeErr)
	if revokeErr != nil {
		return 0, mapSessionError(revokeErr)
	}
	return count, nil
}

// RevokeAllSessions 退出全部会话（含当前），返回清除 Cookie。
func (a *Adapter) RevokeAllSessions(ctx context.Context, request *http.Request,
	currentPassword, requestID string) (*http.Cookie, int64, error) {
	secret, err := a.sessionSecret(request)
	if err != nil {
		return nil, 0, err
	}
	userID, userErr := a.userID(ctx, secret)
	if userErr != nil {
		return nil, 0, userErr
	}
	challengeCtx, result, err := a.approve(ctx, userID, "session.revoke.self", "user", userID,
		map[string]string{"keep_current": "false"}, currentPassword, requestID,
		"退出全部会话（含当前）")
	if err != nil {
		return nil, 0, err
	}
	count, revokeErr := a.opts.Sessions.RevokeAllOwnSessions(challengeCtx, secret, false)
	a.notify(result, revokeErr)
	if revokeErr != nil {
		return nil, 0, mapSessionError(revokeErr)
	}
	return a.opts.Sessions.ClearCookie(), count, nil
}

// ListGrants 分页读取本人已授权应用（真实 oauthflow 查询）。
func (a *Adapter) ListGrants(ctx context.Context, request *http.Request, page,
	pageSize int) (login.UIGrantPage, error) {
	if a.opts.OAuth == nil {
		return login.UIGrantPage{}, featureNotEnabled()
	}
	secret, err := a.sessionSecret(request)
	if err != nil {
		return login.UIGrantPage{}, err
	}
	result, listErr := a.opts.OAuth.ListUserAuthorizations(ctx, secret,
		oauthflow.AuthorizationListOptions{Page: page, PageSize: pageSize})
	if listErr != nil {
		var oauthErr *oauthflow.OAuthError
		if errors.As(listErr, &oauthErr) {
			return login.UIGrantPage{}, securityErr("AUTHZ_UNAVAILABLE")
		}
		return login.UIGrantPage{}, mapOAuthError(listErr)
	}
	pageResult := login.UIGrantPage{Page: result.Page, PageSize: result.PageSize,
		Total: result.Total, HasMore: result.HasMore}
	for _, summary := range result.Authorizations {
		scopes := make([]login.UIPageScopeInfo, 0, len(summary.Scopes))
		for _, scope := range summary.Scopes {
			scopes = append(scopes, login.UIPageScopeInfo{Value: scope,
				Description: scopeDescription(scope)})
		}
		audiences := make([]login.UIPageAudienceInfo, 0, len(summary.Audiences))
		for _, audience := range summary.Audiences {
			audiences = append(audiences, login.UIPageAudienceInfo{Value: audience,
				Description: "目标资源服务"})
		}
		pageResult.Grants = append(pageResult.Grants, login.UIGrant{
			AuthorizationID: summary.AuthorizationID,
			ApplicationName: a.applicationName(summary.ClientID),
			ClientID:        summary.ClientID, Scopes: scopes, Audiences: audiences,
			ApprovedAt: summary.ApprovedAt, ExpiresAt: summary.ExpiresAt,
			ActiveRefreshFamilies: summary.ActiveRefreshFamilies})
	}
	return pageResult, nil
}

// RevokeGrant 撤回本人授权，返回真实撤销计数。
func (a *Adapter) RevokeGrant(ctx context.Context, request *http.Request,
	authorizationID, currentPassword, requestID string) (login.UIGrantRevokeResult, error) {
	if a.opts.OAuth == nil {
		return login.UIGrantRevokeResult{}, featureNotEnabled()
	}
	secret, err := a.sessionSecret(request)
	if err != nil {
		return login.UIGrantRevokeResult{}, err
	}
	userID, userErr := a.userID(ctx, secret)
	if userErr != nil {
		return login.UIGrantRevokeResult{}, userErr
	}
	challengeCtx, result, err := a.approve(ctx, userID, "oauth.authorization.revoke.self",
		"oauth_authorization", authorizationID,
		map[string]string{"authorization_id": authorizationID}, currentPassword, requestID,
		"撤回已授权应用")
	if err != nil {
		return login.UIGrantRevokeResult{}, err
	}
	revokeResult, revokeErr := a.opts.OAuth.RevokeAuthorization(challengeCtx,
		oauthflow.RevokeAuthorizationRequest{SessionSecret: secret,
			AuthorizationID: authorizationID, RequestID: requestID})
	a.notify(result, revokeErr)
	if revokeErr != nil {
		return login.UIGrantRevokeResult{}, mapOAuthError(revokeErr)
	}
	return login.UIGrantRevokeResult{RefreshFamilies: revokeResult.RefreshFamilies,
		RefreshTokens:      revokeResult.RefreshTokens,
		AuthorizationCodes: revokeResult.AuthorizationCodes}, nil
}

// ===== 内部辅助 =====

func (a *Adapter) sessionSecret(request *http.Request) (string, error) {
	if request == nil {
		return "", securityErr("AUTH_FAILED")
	}
	secret, ok := a.opts.Sessions.SessionSecretFromRequest(request)
	if !ok {
		return "", securityErr("AUTH_FAILED")
	}
	return secret, nil
}

func (a *Adapter) userID(ctx context.Context, secret string) (string, error) {
	record, err := a.opts.Sessions.Validate(ctx, secret)
	if err != nil || !record.IsNormal() {
		return "", securityErr("AUTH_FAILED")
	}
	return record.UserID, nil
}

// approve 执行绑定操作/目标/参数的 reauth 挑战并把批准信号放入上下文。
func (a *Adapter) approve(ctx context.Context, userID, operationID, targetType, targetID string,
	params map[string]string, currentPassword, requestID, description string,
	totpCode ...string) (context.Context, reauth.Result, error) {
	return a.approveWithMinimum(ctx, userID, operationID, targetType, targetID, params,
		currentPassword, requestID, description, policy.StrengthNone, totpCode...)
}

// approveWithMinimum 与 approve 相同，但允许页面适配层要求不低于策略的认证强度。
func (a *Adapter) approveWithMinimum(ctx context.Context, userID, operationID, targetType,
	targetID string, params map[string]string, currentPassword, requestID, description string,
	minimumStrength policy.Strength, totpCode ...string) (context.Context, reauth.Result, error) {
	caller, err := reauth.UserCaller(userID)
	if err != nil {
		return ctx, reauth.Result{}, securityErr("ACCESS_DENIED")
	}
	challenge, err := a.opts.Reauth.BeginChallenge(ctx, caller, reauth.ChallengeRequest{
		ScopeID: "system", OperationID: operationID, TargetType: targetType,
		TargetID: targetID, Params: params, Description: description, RequestID: requestID,
		MinimumStrength: minimumStrength})
	if err != nil {
		return ctx, reauth.Result{}, mapReauthError(err)
	}
	result := reauth.Result{OperationID: operationID, TargetType: targetType,
		TargetID: targetID, UserID: userID}
	if !challenge.Required {
		return ctx, result, nil
	}
	if currentPassword == "" {
		return ctx, reauth.Result{}, securityErr("REAUTH_REQUIRED")
	}
	secondFactor := ""
	if len(totpCode) > 0 {
		secondFactor = strings.TrimSpace(totpCode[0])
	}
	grant, verifyErr := a.opts.Reauth.VerifyChallenge(ctx, caller,
		reauth.VerifyChallengeRequest{ChallengeID: challenge.ID,
			Password: currentPassword, TOTPCode: secondFactor, RequestID: requestID})
	if verifyErr != nil {
		return ctx, reauth.Result{}, mapReauthVerifyError(verifyErr)
	}
	strength := policy.StrengthPassword
	if grant.GrantedStrength == policy.StrengthStrong {
		strength = policy.StrengthStrong
	}
	signals := reauth.Signals{VerifiedAt: a.opts.Now().UTC(), Strength: strength,
		Complete: true, Confirmed: true, ApprovalToken: grant.Token}
	return reauth.WithSignals(ctx, signals), result, nil
}

// notify 记录敏感操作结果（失败不回滚业务结果）。
func (a *Adapter) notify(result reauth.Result, failure error) {
	outcome := reauth.OutcomeSuccess
	if failure != nil {
		outcome = reauth.OutcomeFailure
	}
	if err := a.opts.Reauth.NotifyOutcome(context.Background(), result, outcome); err != nil {
		a.opts.Logger.Warn("安全中心敏感操作告知未完成", "error_category", "notify_failed")
	}
}

// applicationName 返回受控应用展示名。
func (a *Adapter) applicationName(clientID string) string {
	if name := strings.TrimSpace(a.opts.ApplicationNames[clientID]); name != "" {
		return name
	}
	return clientID
}

// scopeDescription 返回已知 scope 的中文说明；未知值只显示稳定值。
func scopeDescription(scope string) string {
	switch scope {
	case "openid":
		return "确认你的身份标识（OIDC）"
	case "profile":
		return "读取你的公开资料"
	case "email":
		return "读取你的已验证邮箱地址"
	case "offline_access":
		return "在你离线时继续代表你访问"
	default:
		return "应用声明的权限范围（服务端已登记）"
	}
}

// maskUserAgent 截断并移除控制字符；UA 不是可信设备名。
func maskUserAgent(userAgent string) string {
	trimmed := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(userAgent))
	if trimmed == "" {
		return "客户端未提供描述"
	}
	if utf8.RuneCountInString(trimmed) > 96 {
		runes := []rune(trimmed)
		trimmed = string(runes[:96]) + "…"
	}
	return trimmed
}

// maskAddress 只显示网段/本地来源，不显示完整地址，不作地理含义。
func maskAddress(address string) string {
	trimmed := strings.TrimSpace(address)
	if trimmed == "" {
		return ""
	}
	host := trimmed
	if splitHost, _, err := net.SplitHostPort(trimmed); err == nil {
		host = splitHost
	}
	parsed := net.ParseIP(host)
	if parsed == nil {
		return "来源信息不可用"
	}
	if parsed.IsLoopback() {
		return "本地来源"
	}
	if parsed.To4() != nil {
		return parsed.Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	return parsed.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// newRequestID 生成审计关联请求编号（时间 + 序号，非秘密）。
func newRequestID(now time.Time) string {
	return fmt.Sprintf("req_security_%d", now.UTC().UnixNano())
}

// securityErr 构造稳定公开错误。
func securityErr(code string) error { return &login.UIAccountError{Code: code} }

// 编译期断言：适配器实现步骤 67 页面公开契约。
var _ login.UIPageSecurityBackend = (*Adapter)(nil)
