// Package uiauthadapter 把步骤 63 页面公开契约接到真实 authn/session/registration/
// onboarding 服务（模块内适配器；生产宿主按同样契约自行装配）。
//
// 安全边界：本适配器只在服务端构造可信 Caller；页面传入的只有白名单表单字段与
// 请求上下文，不包含自报身份或权限。会话 Cookie 由真实 session 服务生成。
package uiauthadapter

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	"github.com/kagurazakayashi/EvernightLogin/internal/mfa"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
	"github.com/kagurazakayashi/EvernightLogin/internal/onboarding"
	"github.com/kagurazakayashi/EvernightLogin/internal/pagestate"
	"github.com/kagurazakayashi/EvernightLogin/internal/passkey"
	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
	"github.com/kagurazakayashi/EvernightLogin/internal/qrlogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/recovery"
	"github.com/kagurazakayashi/EvernightLogin/internal/registration"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	"github.com/kagurazakayashi/EvernightLogin/internal/totp"
	"github.com/kagurazakayashi/EvernightLogin/internal/transport"
)

// Options 是适配器依赖与策略快照。
type Options struct {
	Authn        *authn.Service
	Sessions     *session.Service
	Registration *registration.Service
	Onboarding   *onboarding.Service
	// RequireReview/RequireEmailVerification 来自宿主配置，用于页面展示策略。
	RequireReview            bool
	RequireEmailVerification bool
	// ResendComponentID 是匿名重发验证邮件时使用的系统组件标识。
	ResendComponentID string
	// RegistrationStore/Credential/Now 用于“持有链接凭证”的受控重发前置校验：
	// 必须用 cid/token 与当前 pending 票据做只读绑定校验后才允许系统身份发送。
	RegistrationStore registration.Store
	Credential        *credential.Service
	// 步骤 64：第二因素/Passkey/恢复/找回页面所需真实服务；同时参与密码登录后的
	// 受限结果继续（BeginLogin），未装配时页面只显示受限状态、不伪造成功。
	MFA      *mfa.Service
	Passkeys *passkey.Service
	// TOTP 是受限初始化/人工恢复重绑中 TOTP 绑定所需真实服务（步骤 209）；nil 时
	// 页面不提供 TOTP 重绑（返回明确未启用错误），不会伪造成功。
	TOTP          *totp.Service
	Recovery      *recovery.Service
	PasswordReset *passwordreset.Service
	// PageState 是步骤 64 临时页面状态的签名编解码器；MFA 非 nil 时必填。
	PageState *pagestate.Codec
	// 步骤 65：OAuth 授权确认/设备码与扫码登录页所需真实服务与受控展示配置。
	OAuth *oauthflow.Service
	QR    *qrlogin.Service
	// Reauth 是页面级 Passkey 注册/恢复代码等敏感操作的再次认证执行器。
	Reauth     *reauth.Service
	App        *app.Service
	Account    *account.Service
	QRClientID string
	QRScopes   []string
	// ApplicationNames 是宿主受控目录聚合的 client_id -> 应用展示名映射。
	ApplicationNames map[string]string
	Now              func() time.Time
	Logger           *slog.Logger
}

// Adapter 实现 login.UIPageAuthBackend。
type Adapter struct {
	opts Options
}

// New 校验依赖并构造适配器。
func New(options Options) (*Adapter, error) {
	if options.Sessions == nil {
		return nil, fmt.Errorf("页面账户适配器缺少会话服务")
	}
	if options.MFA != nil && options.PageState == nil {
		return nil, fmt.Errorf("页面 MFA 需要签名的页面状态编解码器")
	}
	if options.ResendComponentID == "" {
		options.ResendComponentID = "web-login-page"
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Adapter{opts: options}, nil
}

// PasswordLogin 执行真实密码认证与会话签发；只有完整非受限结果才标记 Complete。
// BeginPasskeyLogin 开始可发现凭证 Passkey 密码less 登录；不在本方法签发会话。
func (a *Adapter) BeginPasskeyLogin(ctx context.Context,
	request *http.Request) (login.UIPasskeyLoginStart, error) {
	if a.opts.Passkeys == nil {
		return login.UIPasskeyLoginStart{}, &login.UIPageAuthError{Code: "FEATURE_NOT_ENABLED"}
	}
	start, err := a.opts.Passkeys.BeginLogin(ctx, passkey.LoginStartRequest{
		RequestID: requestIDFromRequest(request),
		Client:    session.ClientInfo{UserAgent: request.UserAgent(), Address: request.RemoteAddr}})
	if err != nil {
		return login.UIPasskeyLoginStart{}, publicMFAError(err)
	}
	return login.UIPasskeyLoginStart{CeremonyID: start.CeremonyID,
		PublicKey: []byte(start.PublicKey), ExpiresAt: start.ExpiresAt, RPID: start.RPID}, nil
}

// FinishPasskeyLogin 校验断言并返回真实会话 Cookie；会话由 passkey 服务在真实
// 认证器验证通过后签发，本方法不提升/伪造任何身份。
func (a *Adapter) FinishPasskeyLogin(ctx context.Context, request *http.Request,
	response []byte) (login.UIPageLoginResult, error) {
	if a.opts.Passkeys == nil {
		return login.UIPageLoginResult{}, &login.UIPageAuthError{Code: "FEATURE_NOT_ENABLED"}
	}
	ceremonyID := strings.TrimSpace(request.PostForm.Get("passkey_ceremony_id"))
	result, err := a.opts.Passkeys.FinishLogin(ctx, passkey.LoginFinishRequest{
		CeremonyID: ceremonyID, Response: response, RequestID: requestIDFromRequest(request)})
	if err != nil {
		return login.UIPageLoginResult{}, publicMFAError(err)
	}
	cookie, cookieErr := a.opts.Sessions.NewCookie(result.Session)
	if cookieErr != nil {
		return login.UIPageLoginResult{}, &login.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	return login.UIPageLoginResult{UserID: result.Authenticated.UserID,
		Username: result.Authenticated.Username, Complete: true, Cookie: cookie}, nil
}

func (a *Adapter) PasswordLogin(ctx context.Context, request *http.Request,
	loginRequest login.UIPasswordLoginRequest) (login.UIPageLoginResult, error) {
	clientIP, _ := transport.ClientIPFromContext(ctx)
	if clientIP == "" {
		// 嵌入式 Handler 未安装可信边界时 context 没有 ClientIP；仅把连接地址
		// 作为限流分桶键的回退，不把它当作可信来源用于授权。
		if host, _, splitErr := net.SplitHostPort(request.RemoteAddr); splitErr == nil {
			clientIP = host
		}
	}
	result, err := a.opts.Authn.Authenticate(ctx, authn.AuthenticateRequest{
		Identifier: loginRequest.Identifier, Password: loginRequest.Password,
		ClientIP: clientIP, RequestID: loginRequest.RequestID})
	if err != nil {
		if errors.Is(err, authn.ErrRateLimited) {
			return login.UIPageLoginResult{}, &login.UIPageAuthError{Code: "RATE_LIMITED",
				RetryAfterSeconds: 60}
		}
		return login.UIPageLoginResult{}, &login.UIPageAuthError{Code: "AUTH_FAILED"}
	}
	existing, _ := a.opts.Sessions.SessionSecretFromRequest(request)
	userAgent := strings.TrimSpace(request.UserAgent())
	if len(userAgent) > 512 {
		userAgent = userAgent[:512]
	}
	complete := result.Outcome == authn.OutcomeComplete && !result.Restricted &&
		len(result.RequiredSteps) == 0
	steps := make([]string, 0, len(result.RequiredSteps))
	for _, step := range result.RequiredSteps {
		steps = append(steps, string(step))
	}
	// 装配 MFA 时，任何密码结果都要先经真实第二因素启动：账户启用因素/强制策略
	// 时返回受限挑战；没有可用因素时 RequiresSecondFactor=false，再签发普通会话。
	if a.opts.MFA != nil {
		start, startErr := a.opts.MFA.BeginLogin(ctx, mfa.BeginLoginRequest{Result: result,
			ExistingSession: existing, RememberMe: loginRequest.RememberMe,
			RequestID: loginRequest.RequestID, Client: session.ClientInfo{
				UserAgent: userAgent, Address: clientIP}})
		if startErr != nil {
			return login.UIPageLoginResult{}, publicMFAError(startErr)
		}
		if start.RequiresSecondFactor || start.SetupRequired {
			cookie, cookieErr := a.opts.Sessions.NewCookie(start.RestrictedSession)
			if cookieErr != nil {
				return login.UIPageLoginResult{}, &login.UIPageAuthError{Code: "INTERNAL_ERROR"}
			}
			view, stateCookie, stateErr := a.mfaView(start)
			if stateErr != nil {
				return login.UIPageLoginResult{}, stateErr
			}
			return login.UIPageLoginResult{UserID: result.UserID, Username: result.Username,
				Restricted: true, RequiredSteps: steps, Cookie: cookie,
				SecondFactor: &view, StateCookie: stateCookie}, nil
		}
		if !complete {
			// 受限但非第二因素（如待改密）不能被本流程绕过：fail-closed 回页面提示。
			return login.UIPageLoginResult{UserID: result.UserID, Username: result.Username,
				Restricted: true, RequiredSteps: steps}, nil
		}
	}
	issued, loginErr := a.opts.Sessions.Login(ctx, session.LoginRequest{
		Result: result, ExistingSession: existing, RememberMe: loginRequest.RememberMe,
		RequestID: loginRequest.RequestID, Client: session.ClientInfo{UserAgent: userAgent,
			Address: clientIP}})
	if loginErr != nil {
		return login.UIPageLoginResult{}, &login.UIPageAuthError{Code: "AUTH_FAILED"}
	}
	cookie, cookieErr := a.opts.Sessions.NewCookie(issued)
	if cookieErr != nil {
		return login.UIPageLoginResult{}, &login.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	return login.UIPageLoginResult{UserID: result.UserID, Username: result.Username,
		Complete: complete, Restricted: !complete, RequiredSteps: steps,
		Cookie: cookie}, nil
}

// RegistrationAvailability 返回真实注册开关与邮箱策略。
func (a *Adapter) RegistrationAvailability(ctx context.Context) (login.UIPageRegistrationAvailability, error) {
	if err := ctx.Err(); err != nil {
		return login.UIPageRegistrationAvailability{}, err
	}
	if a.opts.Registration == nil {
		return login.UIPageRegistrationAvailability{}, nil
	}
	return login.UIPageRegistrationAvailability{
		Enabled:                  a.opts.Registration.Enabled(),
		EmailCapability:          a.opts.Registration.EmailCapabilityEnabled(),
		RequireEmailVerification: a.opts.RequireEmailVerification,
		RequireReview:            a.opts.RequireReview,
	}, nil
}

// Register 调用真实注册服务；邮箱发送失败与账户创建结果分开返回。
func (a *Adapter) Register(ctx context.Context, request login.UIRegisterRequest) (login.UIPageRegisterResult, error) {
	result, err := a.opts.Registration.Register(ctx, registration.RegisterRequest{
		Username: request.Username, Password: request.Password, Email: request.Email,
		Nickname: request.Nickname, Language: request.Language, Timezone: request.Timezone,
		RequestID: request.RequestID})
	if err != nil {
		switch {
		case errors.Is(err, registration.ErrRegistrationClosed):
			return login.UIPageRegisterResult{}, &login.UIPageAuthError{Code: "REQ_INVALID"}
		case errors.Is(err, registration.ErrRegistrationConflict):
			return login.UIPageRegisterResult{}, &login.UIPageAuthError{Code: "CONFLICT"}
		case errors.Is(err, authn.ErrRateLimited):
			return login.UIPageRegisterResult{}, &login.UIPageAuthError{Code: "RATE_LIMITED",
				RetryAfterSeconds: 60}
		default:
			return login.UIPageRegisterResult{}, &login.UIPageAuthError{Code: "REQ_INVALID"}
		}
	}
	view := login.UIPageRegisterResult{UserID: result.UserID, Username: result.Username,
		Status: string(result.Status), VerificationSent: result.VerificationSent,
		VerificationExpiresAt: result.VerificationExpiresAt,
		SendErrorCode:         result.VerificationErrorCode}
	return view, nil
}

// VerifyEmail 原子消费邮箱验证入口。
func (a *Adapter) VerifyEmail(ctx context.Context, request login.UIVerifyEmailRequest) (login.UIPageVerifyResult, error) {
	_, err := a.opts.Registration.VerifyEmail(ctx, registration.VerifyEmailRequest{
		UserID: request.UserID, CredentialID: request.CredentialID, Token: request.Token,
		RequestID: request.RequestID})
	if err != nil {
		return login.UIPageVerifyResult{}, &login.UIPageAuthError{Code: "CHALLENGE_INVALID"}
	}
	return login.UIPageVerifyResult{Verified: true}, nil
}

// ResendVerification 复用真实发送服务与冷却，并对**匿名链接凭证**做只读绑定校验：
// uid+cid+token 必须与当前 pending 验证票据及一次性凭证（不消费）匹配，校验通过才
// 允许系统身份重发；任何失败都不改变状态、不写库。对外统一返回“已受理”，真实
// 结果（成功/冷却/绑定失败/不存在）只写受限运行日志，避免账户与票据状态探测。
func (a *Adapter) ResendVerification(ctx context.Context, request *http.Request) (login.UIPageResendResult, error) {
	if err := request.ParseForm(); err != nil {
		a.opts.Logger.Info("页面重发验证未受理", "category", "invalid_form")
		return login.UIPageResendResult{Accepted: true}, nil
	}
	a.resendBestEffort(ctx, request)
	return login.UIPageResendResult{Accepted: true}, nil
}

// resendBestEffort 执行受控重发；所有差异只写运行日志。
func (a *Adapter) resendBestEffort(ctx context.Context, request *http.Request) {
	// 已登录用户按真实本人 Caller 重发。
	if secret, ok := a.opts.Sessions.SessionSecretFromRequest(request); ok {
		if record, validateErr := a.opts.Sessions.Validate(ctx, secret); validateErr == nil {
			self, callerErr := registration.SelfCaller(record.UserID)
			if callerErr != nil {
				a.opts.Logger.Info("页面重发验证未受理", "category", "caller_invalid")
				return
			}
			a.sendVerification(ctx, self, record.UserID)
			return
		}
	}
	userID := request.PostForm.Get("uid")
	credentialID := request.PostForm.Get("cid")
	tokenValue := request.PostForm.Get("token")
	if userID == "" || credentialID == "" || tokenValue == "" {
		a.opts.Logger.Info("页面重发验证未受理", "category", "missing_link_proof")
		return
	}
	if a.opts.RegistrationStore == nil || a.opts.Credential == nil {
		a.opts.Logger.Info("页面重发验证未受理", "category", "binding_check_unavailable")
		return
	}
	ticket, found, ticketErr := a.opts.RegistrationStore.GetVerificationTicket(ctx, userID)
	if ticketErr != nil {
		a.opts.Logger.Info("页面重发验证未受理", "category", "ticket_store_unavailable")
		return
	}
	if !found || ticket.UserID != userID ||
		subtle.ConstantTimeCompare([]byte(ticket.CredentialID), []byte(credentialID)) != 1 ||
		!ticket.ExpiresAt.After(a.opts.Now().UTC()) {
		a.opts.Logger.Info("页面重发验证未受理", "category", "ticket_binding_mismatch")
		return
	}
	// 只读校验一次性凭证与当前票据绑定（不消费、不记录失败尝试）。
	if _, peekErr := a.opts.Credential.Peek(ctx, credential.VerifyRequest{
		Kind: credential.KindToken, ID: credentialID,
		Purpose: registration.PurposeEmailVerify, Target: userID, Secret: tokenValue,
	}); peekErr != nil {
		a.opts.Logger.Info("页面重发验证未受理", "category", "link_credential_invalid")
		return
	}
	system, callerErr := registration.SystemCaller(a.opts.ResendComponentID)
	if callerErr != nil {
		a.opts.Logger.Info("页面重发验证未受理", "category", "system_caller_invalid")
		return
	}
	a.sendVerification(ctx, system, userID)
}

// sendVerification 调用真实发送服务并只记录受限结果类别（冷却/存储/邮件失败）。
func (a *Adapter) sendVerification(ctx context.Context, caller registration.Caller, userID string) {
	result, err := a.opts.Registration.SendEmailVerification(ctx, caller,
		registration.SendVerificationRequest{UserID: userID})
	switch {
	case err == nil && result.Sent:
		a.opts.Logger.Info("页面重发验证已交给发送方", "category", "sent")
	case errors.Is(err, registration.ErrResendTooSoon):
		a.opts.Logger.Info("页面重发验证未发送", "category", "cooldown")
	case errors.Is(err, registration.ErrUserNotFound),
		errors.Is(err, registration.ErrEmailNotAvailable),
		errors.Is(err, registration.ErrEmailAlreadyVerified),
		errors.Is(err, registration.ErrAccessDenied):
		a.opts.Logger.Info("页面重发验证未发送", "category", "not_eligible")
	default:
		a.opts.Logger.Info("页面重发验证未发送", "category", "delivery_or_store_failure")
	}
}

// AcceptInvitation 以真实会话身份或匿名新用户身份接受邀请。
func (a *Adapter) AcceptInvitation(ctx context.Context, request *http.Request,
	accept login.UIPageInvitationAcceptRequest) (login.UIPageInvitationAcceptResult, error) {
	var caller onboarding.Caller
	if secret, ok := a.opts.Sessions.SessionSecretFromRequest(request); ok {
		record, validateErr := a.opts.Sessions.Validate(ctx, secret)
		if validateErr == nil && !record.IsRestricted() {
			userCaller, callerErr := onboarding.UserCaller(record.UserID)
			if callerErr != nil {
				return login.UIPageInvitationAcceptResult{}, &login.UIPageAuthError{Code: "ACCESS_DENIED"}
			}
			caller = userCaller
		}
	}
	acceptRequest := onboarding.AcceptRequest{InvitationID: accept.InvitationID,
		CredentialID: accept.CredentialID, Token: accept.Token}
	if accept.NewUser != nil {
		acceptRequest.NewUser = &onboarding.NewUserRequest{Username: accept.NewUser.Username,
			Password: accept.NewUser.Password, Nickname: accept.NewUser.Nickname,
			Language: accept.NewUser.Language, Timezone: accept.NewUser.Timezone}
	}
	result, err := a.opts.Onboarding.AcceptInvitation(ctx, caller, acceptRequest)
	if err != nil {
		return login.UIPageInvitationAcceptResult{}, &login.UIPageAuthError{Code: "CHALLENGE_INVALID"}
	}
	roles := make([]string, 0, len(result.Roles))
	for _, role := range result.Roles {
		roles = append(roles, role.RoleID)
	}
	return login.UIPageInvitationAcceptResult{InvitationID: result.InvitationID,
		UserID: result.UserID, AppID: result.AppID, Roles: roles,
		NewUser: result.NewUser}, nil
}

// Logout 撤销真实服务端会话并返回清理 Cookie。
func (a *Adapter) Logout(ctx context.Context, request *http.Request) (*http.Cookie, error) {
	secret, ok := a.opts.Sessions.SessionSecretFromRequest(request)
	if !ok {
		return a.opts.Sessions.ClearCookie(), nil
	}
	if err := a.opts.Sessions.Logout(ctx, secret); err != nil {
		return nil, err
	}
	return a.opts.Sessions.ClearCookie(), nil
}

// 确保接口实现。
var _ login.UIPageAuthBackend = (*Adapter)(nil)
