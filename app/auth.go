package app

// 认证与安全门面的真实实现（步骤 181）。
//
// 所有流程都复用共享运行时装配的真实 internal 领域服务（authn/mfa/totp/recovery/
// reauth/session），不复制状态机、不伪造强认证结果：
//   - 密码第一步 -> 第二因素挑战/受限会话 -> VerifySecondFactor 换取完整会话；
//   - 恢复代码只替代第二步，进入受限恢复会话（不能访问业务）；
//   - TOTP 绑定等敏感操作必须经真实再次认证（密码，必要时密码+TOTP）后执行；
//   - 公开结果只包含一次性秘密（会话秘密、TOTP 种子、恢复代码）以及脱敏状态，
//     不包含任何 internal 类型。

import (
	"context"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/mfa"
	"github.com/kagurazakayashi/EvernightLogin/internal/passkey"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/recovery"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	"github.com/kagurazakayashi/EvernightLogin/internal/totp"
)

// authFacade 实现 AuthService。
type authFacade struct{ r *Runtime }

// Login 完成密码第一步。装配了 MFA 时，任何密码结果都先经真实第二步启动：
// 账户启用因素或被策略要求强认证时返回受限会话与挑战；没有可用因素时按既有
// 密码流程签发普通会话；待改密等其它受限状态 fail-closed，不签发会话。
func (f *authFacade) Login(ctx context.Context, req LoginRequest) (LoginResult, error) {
	r := f.r
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		// 非法请求编号是输入错误，不涉及账户存在性，可安全拒绝。
		return LoginResult{}, err
	}
	services := r.coreServices()
	if services == nil {
		return LoginResult{}, configError("服务未装配", requestID)
	}
	authResult, err := services.Authn.Authenticate(ctx, authn.AuthenticateRequest{
		Identifier: req.Username, Password: req.Password, ClientIP: req.ClientIP,
		RequestID: requestID,
	})
	if err != nil {
		return LoginResult{}, mapAuthError(err, requestID)
	}
	if mfaService := r.mfaService(); mfaService != nil {
		start, startErr := mfaService.BeginLogin(ctx, mfa.BeginLoginRequest{
			Result: authResult, AppID: req.AppID, RequestID: requestID,
			RememberMe: req.RememberMe,
			Client:     session.ClientInfo{UserAgent: req.UserAgent, Address: req.ClientIP},
		})
		if startErr != nil {
			return LoginResult{}, mapDomainError("登录需要完成第二因素验证",
				string(mfa.CodeOf(startErr)), requestID)
		}
		if start.RequiresSecondFactor || start.SetupRequired {
			return loginResultFromStart(authResult, start), nil
		}
	}
	complete := authResult.Outcome == authn.OutcomeComplete && !authResult.Restricted &&
		len(authResult.RequiredSteps) == 0
	if !complete {
		// 受限但非第二因素（待改密等）不能被本流程绕过：只返回受限状态与待完成
		// 步骤，不签发任何会话。
		result := LoginResult{UserID: authResult.UserID, Username: authResult.Username,
			Restricted: true}
		for _, step := range authResult.RequiredSteps {
			result.RequiredSteps = append(result.RequiredSteps, string(step))
		}
		return result, nil
	}
	issued, err := services.Sessions.Login(ctx, session.LoginRequest{
		Result: authResult, AppID: req.AppID, RememberMe: req.RememberMe,
		RequestID: requestID,
		Client:    session.ClientInfo{UserAgent: req.UserAgent, Address: req.ClientIP},
	})
	if err != nil {
		return LoginResult{}, mapDomainError("签发会话失败", string(session.CodeOf(err)), requestID)
	}
	return loginResultFromIssued(issued, authResult), nil
}

// VerifySecondFactor 用受限会话 + 挑战数据完成第二步，返回完整会话。
func (f *authFacade) VerifySecondFactor(ctx context.Context,
	req VerifySecondFactorRequest) (VerifiedSession, error) {
	r := f.r
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return VerifiedSession{}, err
	}
	mfaService := r.mfaService()
	if mfaService == nil {
		return VerifiedSession{}, configError("第二因素验证服务未装配", requestID)
	}
	if len(req.SessionSecret) == 0 {
		return VerifiedSession{}, configError("缺少第一步受限会话秘密", requestID)
	}
	result, err := mfaService.Verify(ctx, mfa.VerifyRequest{
		ChallengeID: req.ChallengeID, AttemptToken: string(req.AttemptToken),
		Code: req.Code, PasskeyCeremonyID: req.PasskeyCeremonyID,
		PasskeyResponse: req.PasskeyResponse,
		ExistingSession: string(req.SessionSecret), RequestID: requestID,
	})
	if err != nil {
		return VerifiedSession{}, mapDomainError("第二因素验证失败",
			string(mfa.CodeOf(err)), requestID)
	}
	verified := VerifiedSession{UserID: result.Authenticated.UserID,
		SessionID: result.Session.Session.ID,
		ExpiresAt: result.Session.Session.AbsoluteExpiresAt,
		Method:    result.Method, Strength: result.Strength}
	if secret := result.Session.Secret.Reveal(); secret != "" {
		verified.SessionSecret = []byte(secret)
	}
	if csrf := result.Session.CSRFSecret.Reveal(); csrf != "" {
		verified.CSRFSecret = []byte(csrf)
	}
	return verified, nil
}

// BeginRecovery 用恢复代码替代第二步，进入受限恢复会话。
func (f *authFacade) BeginRecovery(ctx context.Context,
	req BeginRecoveryRequest) (RecoverySession, error) {
	r := f.r
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return RecoverySession{}, err
	}
	mfaService := r.mfaService()
	security := r.securityDomains()
	if mfaService == nil || security == nil || security.Recovery == nil {
		return RecoverySession{}, configError("恢复服务未装配", requestID)
	}
	if len(req.SessionSecret) == 0 {
		return RecoverySession{}, configError("缺少第一步受限会话秘密", requestID)
	}
	authResult, err := mfaService.RecoveryAuthentication(ctx,
		mfa.RecoveryAuthenticationRequest{
			ChallengeID: req.ChallengeID, AttemptToken: string(req.AttemptToken),
			ExistingSession: string(req.SessionSecret), RequestID: requestID,
		})
	if err != nil {
		return RecoverySession{}, mapDomainError("恢复代码交接失败",
			string(mfa.CodeOf(err)), requestID)
	}
	begin, err := security.Recovery.Begin(ctx, recovery.BeginRequest{
		Result: authResult, Code: req.RecoveryCode,
		ExistingSession: string(req.SessionSecret), RequestID: requestID,
	})
	if err != nil {
		return RecoverySession{}, mapDomainError("恢复代码验证失败",
			string(recovery.CodeOf(err)), requestID)
	}
	recovered := RecoverySession{UserID: begin.Session.Session.UserID,
		SessionID: begin.Session.Session.ID, ExpiresAt: begin.ExpiresAt,
		CodesRemaining:   begin.CodesRemaining,
		RequiredStrength: string(begin.RequiredStrength)}
	if secret := begin.Session.Secret.Reveal(); secret != "" {
		recovered.SessionSecret = []byte(secret)
	}
	for _, method := range begin.AllowedMethods {
		recovered.AllowedMethods = append(recovered.AllowedMethods, string(method))
	}
	return recovered, nil
}

// RecoveryStatus 查询受限恢复会话状态。
func (f *authFacade) RecoveryStatus(ctx context.Context,
	req RecoveryStatusRequest) (RecoveryStatus, error) {
	r := f.r
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return RecoveryStatus{}, err
	}
	services := r.coreServices()
	security := r.securityDomains()
	if services == nil || security == nil || security.Recovery == nil {
		return RecoveryStatus{}, configError("恢复服务未装配", requestID)
	}
	if _, err := r.requireSession(ctx, req.SessionSecret, false, requestID); err != nil {
		return RecoveryStatus{}, err
	}
	snapshot, err := security.Recovery.Snapshot(ctx, string(req.SessionSecret))
	if err != nil {
		return RecoveryStatus{}, mapDomainError("恢复会话状态不可用",
			string(recovery.CodeOf(err)), requestID)
	}
	status := RecoveryStatus{HasActiveGroup: snapshot.AttemptID != "",
		CodesRemaining:   snapshot.CodesRemaining,
		ExpiresAt:        snapshot.ExpiresAt,
		RequiredStrength: string(snapshot.RequiredStrength)}
	for _, method := range snapshot.AllowedMethods {
		status.AllowedMethods = append(status.AllowedMethods, string(method))
	}
	return status, nil
}

// securityFacade 实现 SecurityService。
type securityFacade struct{ r *Runtime }

// Status 返回当前账户的认证/恢复能力概览。
func (f *securityFacade) Status(ctx context.Context,
	req SecurityStatusRequest) (SecurityStatus, error) {
	r := f.r
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return SecurityStatus{}, err
	}
	security := r.securityDomains()
	if security == nil {
		return SecurityStatus{}, configError("安全域服务未装配", requestID)
	}
	record, err := r.requireSession(ctx, req.SessionSecret, true, requestID)
	if err != nil {
		return SecurityStatus{}, err
	}
	status := SecurityStatus{PasskeyEnabled: r.base != nil && r.base.Config.Passkey.Enabled}
	if security.TOTP != nil {
		active, totpErr := security.TOTP.HasActive(ctx, record.UserID)
		if totpErr != nil {
			return SecurityStatus{}, mapDomainError("读取 TOTP 状态失败",
				string(totp.CodeOf(totpErr)), requestID)
		}
		status.TOTPActive = active
	}
	mfaCaller, callerErr := mfa.UserCaller(record.UserID)
	if callerErr != nil {
		return SecurityStatus{}, configError("会话主体无效", requestID)
	}
	if security.MFA != nil {
		factors, factorsErr := security.MFA.Factors(ctx, mfaCaller)
		if factorsErr != nil {
			return SecurityStatus{}, mapDomainError("读取第二因素状态失败",
				string(mfa.CodeOf(factorsErr)), requestID)
		}
		for _, factor := range factors {
			if factor.Type == mfa.FactorEmail && factor.State == "active" {
				status.EmailFactorActive = true
			}
		}
	}
	if security.Passkey != nil {
		passkeyCaller, passkeyErr := passkey.UserCaller(record.UserID)
		if passkeyErr != nil {
			return SecurityStatus{}, configError("会话主体无效", requestID)
		}
		credentials, listErr := security.Passkey.List(ctx, passkeyCaller)
		if listErr != nil {
			return SecurityStatus{}, mapDomainError("读取 Passkey 状态失败",
				string(passkey.CodeOf(listErr)), requestID)
		}
		status.PasskeyCount = len(credentials)
	}
	if security.Recovery != nil {
		recoveryCaller, recoveryErr := recovery.UserCaller(record.UserID)
		if recoveryErr != nil {
			return SecurityStatus{}, configError("会话主体无效", requestID)
		}
		inventory, inventoryErr := security.Recovery.Inventory(ctx, recoveryCaller)
		if inventoryErr != nil {
			return SecurityStatus{}, mapDomainError("读取恢复代码状态失败",
				string(recovery.CodeOf(inventoryErr)), requestID)
		}
		status.RecoveryCodesRemaining = inventory.CodesRemaining
	}
	if security.StrongFactors != nil {
		strong, strongErr := security.StrongFactors.HasStrongFactor(ctx, record.UserID)
		if strongErr != nil {
			return SecurityStatus{}, mapDomainError("读取强因素状态失败", "", requestID)
		}
		status.StrongFactorBound = strong
	}
	return status, nil
}

// BeginTOTPBinding 开始绑定 TOTP（敏感操作 mfa.add，需要近期密码验证）。
func (f *securityFacade) BeginTOTPBinding(ctx context.Context,
	req TOTPBindingBeginRequest) (TOTPBindingStart, error) {
	r := f.r
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return TOTPBindingStart{}, err
	}
	security := r.securityDomains()
	if security == nil || security.TOTP == nil {
		return TOTPBindingStart{}, configError("TOTP 服务未装配", requestID)
	}
	record, err := r.requireSession(ctx, req.SessionSecret, true, requestID)
	if err != nil {
		return TOTPBindingStart{}, err
	}
	caller, callerErr := totp.UserCaller(record.UserID)
	if callerErr != nil {
		return TOTPBindingStart{}, configError("会话主体无效", requestID)
	}
	approved, approveErr := r.approveSensitive(ctx, record.UserID, "mfa.add",
		"开始绑定 TOTP 验证器", req.Password, "", requestID, policy.StrengthNone)
	if approveErr != nil {
		return TOTPBindingStart{}, approveErr
	}
	start, err := security.TOTP.BeginBinding(approved, caller, requestID)
	if err != nil {
		return TOTPBindingStart{}, mapDomainError("开始绑定 TOTP 失败",
			string(totp.CodeOf(err)), requestID)
	}
	return TOTPBindingStart{BindingID: start.BindingID, Secret: start.Secret,
		OTPAuthURL: start.URI, ExpiresAt: start.ExpiresAt,
		PeriodSeconds: start.PeriodSeconds, Digits: start.Digits}, nil
}

// ConfirmTOTPBinding 用一次性验证码确认 TOTP 绑定。
func (f *securityFacade) ConfirmTOTPBinding(ctx context.Context,
	req TOTPBindingConfirmRequest) (TOTPBinding, error) {
	r := f.r
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return TOTPBinding{}, err
	}
	security := r.securityDomains()
	if security == nil || security.TOTP == nil {
		return TOTPBinding{}, configError("TOTP 服务未装配", requestID)
	}
	record, err := r.requireSession(ctx, req.SessionSecret, true, requestID)
	if err != nil {
		return TOTPBinding{}, err
	}
	caller, callerErr := totp.UserCaller(record.UserID)
	if callerErr != nil {
		return TOTPBinding{}, configError("会话主体无效", requestID)
	}
	metadata, err := security.TOTP.ConfirmBinding(ctx, caller, totp.BindConfirm{
		BindingID: req.BindingID, Code: req.Code, RequestID: requestID,
	})
	if err != nil {
		return TOTPBinding{}, mapDomainError("确认 TOTP 绑定失败",
			string(totp.CodeOf(err)), requestID)
	}
	return TOTPBinding{BindingID: metadata.ID, Status: metadata.Status,
		CreatedAt: metadata.CreatedAt, ActivatedAt: metadata.ActivatedAt}, nil
}

// GenerateRecoveryCodes 生成新一组恢复代码（敏感操作 recovery.codes.rotate）；
// 已绑定强因素的账户需要近期强认证（密码 + TOTP 动态码）。
func (f *securityFacade) GenerateRecoveryCodes(ctx context.Context,
	req RecoveryCodesRequest) (RecoveryCodes, error) {
	r := f.r
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return RecoveryCodes{}, err
	}
	security := r.securityDomains()
	if security == nil || security.Recovery == nil {
		return RecoveryCodes{}, configError("恢复服务未装配", requestID)
	}
	record, err := r.requireSession(ctx, req.SessionSecret, true, requestID)
	if err != nil {
		return RecoveryCodes{}, err
	}
	caller, callerErr := recovery.UserCaller(record.UserID)
	if callerErr != nil {
		return RecoveryCodes{}, configError("会话主体无效", requestID)
	}
	approved, approveErr := r.approveSensitive(ctx, record.UserID,
		"recovery.codes.rotate", "生成恢复代码", req.Password, req.TOTPCode, requestID,
		policy.StrengthStrong)
	if approveErr != nil {
		return RecoveryCodes{}, approveErr
	}
	generated, err := security.Recovery.Generate(approved, caller,
		recovery.GenerateRequest{RequestID: requestID})
	if err != nil {
		return RecoveryCodes{}, mapDomainError("生成恢复代码失败",
			string(recovery.CodeOf(err)), requestID)
	}
	codes := make([]string, 0, len(generated.Codes))
	for _, code := range generated.Codes {
		codes = append(codes, code.Reveal())
	}
	return RecoveryCodes{Codes: codes, Generation: generated.Generation,
		CreatedAt: generated.CreatedAt}, nil
}

// requireSession 校验会话秘密并返回会话记录；full 为 true 时只接受完整（非受限）
// 会话，防止待第二因素/受限恢复会话被用于敏感操作或状态读取。requestID 是本次
// 调用已解析的编号，会带入所有返回错误。
func (r *Runtime) requireSession(ctx context.Context, secret []byte,
	full bool, requestID string) (session.Session, error) {
	services := r.coreServices()
	if services == nil {
		return session.Session{}, configError("服务未装配", requestID)
	}
	if len(secret) == 0 {
		return session.Session{}, configError("缺少会话秘密", requestID)
	}
	record, err := services.Sessions.Validate(ctx, string(secret))
	if err != nil {
		return session.Session{}, mapDomainError("会话无效或已失效",
			string(session.CodeOf(err)), requestID)
	}
	if full && !record.IsNormal() {
		return session.Session{}, mapDomainError("该操作需要完整登录会话",
			"ACCESS_DENIED", requestID)
	}
	return record, nil
}

// approveSensitive 执行真实敏感操作再次认证：创建挑战 -> 需要时用密码（及强认证
// 要求的 TOTP 动态码）验证 -> 把批准信号放入上下文。返回的上下文只用于紧接着的
// 同一次敏感调用；不发放可复用的长期批准。requestID 是本次调用已解析的编号，
// 再次认证挑战、审计与返回错误共用它。
//
// minimumStrength 是本次操作要求的认证强度下限（只能提高、不能降低策略要求）：
// 内置目录里 recovery.codes.rotate 默认只要求近期密码，但恢复领域对已绑定强因素
// 的账户额外要求近期强认证；因此调用方必须显式传 StrengthStrong，让挑战实际要求
// 密码 + TOTP，并把 strong 事实写入批准信号，否则会被恢复领域 fail-closed 拒绝。
func (r *Runtime) approveSensitive(ctx context.Context, userID, operationID, description,
	password, totpCode, requestID string,
	minimumStrength policy.Strength) (context.Context, error) {
	gate := r.securityGate()
	if gate == nil || gate.Reauth == nil {
		return ctx, configError("敏感操作闸门未装配", requestID)
	}
	caller, err := reauth.UserCaller(userID)
	if err != nil {
		return ctx, configError("会话主体无效", requestID)
	}
	challenge, err := gate.Reauth.BeginChallenge(ctx, caller, reauth.ChallengeRequest{
		ScopeID: "system", OperationID: operationID, TargetType: "user",
		TargetID: userID, Description: description, RequestID: requestID,
		MinimumStrength: minimumStrength,
	})
	if err != nil {
		return ctx, mapDomainError("敏感操作再次认证未通过",
			string(reauth.CodeOf(err)), requestID)
	}
	if !challenge.Required {
		return ctx, nil
	}
	if strings.TrimSpace(password) == "" {
		return ctx, mapDomainError("敏感操作需要近期密码验证", "REAUTH_REQUIRED", requestID)
	}
	grant, err := gate.Reauth.VerifyChallenge(ctx, caller, reauth.VerifyChallengeRequest{
		ChallengeID: challenge.ID, Password: password, TOTPCode: totpCode,
		RequestID: requestID,
	})
	if err != nil {
		return ctx, mapDomainError("敏感操作再次认证未通过",
			string(reauth.CodeOf(err)), requestID)
	}
	strength := policy.StrengthPassword
	if grant.GrantedStrength == policy.StrengthStrong {
		strength = policy.StrengthStrong
	}
	signals := reauth.Signals{VerifiedAt: r.runtimeNow().UTC(), Strength: strength,
		Complete: true, Confirmed: true, ApprovalToken: grant.Token}
	return reauth.WithSignals(ctx, signals), nil
}

// runtimeNow 返回运行时时钟（与各领域服务共用同一可注入时钟）。
func (r *Runtime) runtimeNow() time.Time {
	if r != nil && r.nowFn != nil {
		return r.nowFn()
	}
	return time.Now()
}

// loginResultFromStart 把 mfa.LoginStart 转为公开登录结果（受限会话 + 挑战）。
func loginResultFromStart(base authn.AuthenticateResult,
	start mfa.LoginStart) LoginResult {
	restricted := start.RestrictedSession
	result := LoginResult{UserID: base.UserID, Username: base.Username,
		SessionID: restricted.Session.ID,
		ExpiresAt: restricted.Session.AbsoluteExpiresAt, Restricted: true}
	if secret := restricted.Secret.Reveal(); secret != "" {
		result.SessionSecret = []byte(secret)
	}
	if csrf := restricted.CSRFSecret.Reveal(); csrf != "" {
		result.CSRFSecret = []byte(csrf)
	}
	for _, step := range base.RequiredSteps {
		result.RequiredSteps = append(result.RequiredSteps, string(step))
	}
	challenge := &SecondFactorChallenge{ChallengeID: start.ChallengeID,
		AttemptToken: []byte(start.AttemptToken), FactorType: string(start.FactorType),
		MaskedEmail: start.MaskedEmail, ExpiresAt: start.ExpiresAt,
		PasskeyCeremonyID: start.PasskeyCeremonyID,
		PasskeyOptions:    start.PasskeyOptions,
		SetupRequired:     start.SetupRequired}
	for _, method := range start.AllowedSetupMethods {
		challenge.AllowedSetupMethods = append(challenge.AllowedSetupMethods, string(method))
	}
	result.SecondFactor = challenge
	return result
}

// loginResultFromIssued 把完整会话签发结果转为公开登录结果。
func loginResultFromIssued(issued session.IssuedSession,
	base authn.AuthenticateResult) LoginResult {
	result := LoginResult{UserID: issued.Session.UserID, Username: base.Username,
		SessionID: issued.Session.ID, ExpiresAt: issued.Session.AbsoluteExpiresAt,
		Restricted: issued.Session.IsRestricted()}
	if secret := issued.Secret.Reveal(); secret != "" {
		result.SessionSecret = []byte(secret)
	}
	if csrf := issued.CSRFSecret.Reveal(); csrf != "" {
		result.CSRFSecret = []byte(csrf)
	}
	for _, step := range base.RequiredSteps {
		result.RequiredSteps = append(result.RequiredSteps, string(step))
	}
	return result
}
