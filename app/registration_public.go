// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

// 注册与邮箱验证公开 Go 接口（步骤 221 P0）。
//
// 边界：
//   - 复用 internal/registration 的真实注册/验证/重发语义：注册开关、重名/规范化、
//     邮箱能力、重发冷却、一次性验证入口、审计与错误码全部沿用；
//   - 身份只来自完整会话（SendEmailVerification）：不接受调用方传 userID；
//   - VerifyEmail 是匿名一次性令牌入口，不签发会话；
//   - 匿名重发（ResendEmailVerification）只接受“已登录会话”或“邮件链接证明
//     uid+cid+token”，任何失败都统一返回 Accepted，不泄露账户/票据状态（防枚举）；
//   - 注册关闭时 RegisterAccount 返回稳定 CONFIG_INVALID，不伪造成功；
//   - 访问器 Runtime.Registration() 定义在本文件，不编辑 runtime.go/admin.go/types.go。

import (
	"context"
	"crypto/subtle"
	"errors"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	"github.com/kagurazakayashi/EvernightLogin/internal/registration"
)

// RegistrationService 是注册与邮箱验证公开门面。
type RegistrationService interface {
	// Availability 返回当前部署的注册能力（开关、审核、邮箱验证要求与邮件能力）。
	Availability(ctx context.Context) (RegistrationAvailability, error)
	// RegisterAccount 匿名注册账户；不签发会话，不返回密码/令牌/验证链接。
	RegisterAccount(ctx context.Context,
		req RegisterAccountRequest) (RegisteredAccount, error)
	// SendEmailVerification 为当前会话本人重新发送验证入口（受领域冷却限制）。
	SendEmailVerification(ctx context.Context,
		req SendEmailVerificationRequest) (EmailVerificationSendResult, error)
	// VerifyEmail 消费一次性验证入口（匿名），不签发会话。
	VerifyEmail(ctx context.Context, req VerifyEmailRequest) (VerifiedEmail, error)
	// ResendEmailVerification 匿名防枚举重发：总是 Accepted=true，不暴露账户/票据
	// 状态；只接受有效会话或邮件链接证明。
	ResendEmailVerification(ctx context.Context,
		req ResendEmailVerificationRequest) (ResendEmailVerificationResult, error)
}

// RegistrationAvailability 是注册能力概览。
type RegistrationAvailability struct {
	Enabled                  bool
	RequireReview            bool
	RequireEmailVerification bool
	// EmailCapability 表示部署是否装配了可用的邮箱验证能力。
	EmailCapability bool
}

// RegisterAccountRequest 是匿名注册请求；没有 is_root/角色/已验证状态字段。
type RegisterAccountRequest struct {
	Username  string
	Password  string
	Email     string
	Nickname  string
	Language  string
	Timezone  string
	RequestID string
}

// RegisteredAccount 是注册结果（不含密码、哈希、令牌或验证链接）。
type RegisteredAccount struct {
	UserID   string
	Username string
	Email    string
	Status   string
	// VerificationSent 只表示验证入口是否交给投递通道；不代表邮箱已验证。
	VerificationSent      bool
	VerificationErrorCode string
	CreatedAt             string
}

// SendEmailVerificationRequest 是本人重发验证入口请求；可选替换未验证邮箱。
type SendEmailVerificationRequest struct {
	SessionSecret []byte
	Email         string
	RequestID     string
}

// EmailVerificationSendResult 是验证入口发送结果；Sent=false 时 ErrorCode 说明
// 邮件侧失败类别，不把“已发送”当成“邮箱已验证”。
type EmailVerificationSendResult struct {
	UserID          string
	Email           string
	Sent            bool
	ErrorCode       string
	ResendAllowedAt string
}

// VerifyEmailRequest 是验证入口参数（来自邮件链接，不含会话）。
type VerifyEmailRequest struct {
	UserID       string
	CredentialID string
	Token        string
	RequestID    string
}

// VerifiedEmail 是邮箱验证完成结果。
type VerifiedEmail struct {
	UserID     string
	Email      string
	VerifiedAt string
}

// ResendEmailVerificationRequest 是匿名重发请求：SessionSecret 或
// UserID/CredentialID/Token（链接证明）至少一个。
type ResendEmailVerificationRequest struct {
	SessionSecret []byte
	UserID        string
	CredentialID  string
	Token         string
	RequestID     string
}

// ResendEmailVerificationResult 是防枚举结果；恒为 Accepted=true。
type ResendEmailVerificationResult struct {
	Accepted bool
}

// Registration 返回注册与邮箱验证公开门面。
func (r *Runtime) Registration() RegistrationService {
	return &registrationFacade{r: r}
}

type registrationFacade struct {
	r *Runtime
}

// registrationService 返回已装配的注册领域服务。
func (f *registrationFacade) registrationService() (*registration.Service, error) {
	services := f.r.coreServices()
	if services == nil || services.Registration == nil {
		return nil, configError("注册服务未装配")
	}
	return services.Registration, nil
}

// Availability 从真实服务与配置计算注册能力。
func (f *registrationFacade) Availability(ctx context.Context) (RegistrationAvailability, error) {
	service, err := f.registrationService()
	if err != nil {
		return RegistrationAvailability{}, err
	}
	config := f.r.Config()
	return RegistrationAvailability{Enabled: service.Enabled(),
		RequireReview:            config.Registration.RequireReview,
		RequireEmailVerification: config.Registration.RequireEmailVerification,
		EmailCapability:          service.EmailCapabilityEnabled()}, nil
}

// RegisterAccount 匿名注册；注册关闭返回 CONFIG_INVALID。
func (f *registrationFacade) RegisterAccount(ctx context.Context,
	req RegisterAccountRequest) (RegisteredAccount, error) {
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return RegisteredAccount{}, err
	}
	service, err := f.registrationService()
	if err != nil {
		return RegisteredAccount{}, err
	}
	result, err := service.Register(ctx, registration.RegisterRequest{
		Username: req.Username, Password: req.Password, Email: req.Email,
		Nickname: req.Nickname, Language: req.Language, Timezone: req.Timezone,
		RequestID: requestID})
	if err != nil {
		if errors.Is(err, registration.ErrRegistrationClosed) {
			return RegisteredAccount{}, configError("注册当前未开放", requestID)
		}
		return RegisteredAccount{}, mapDomainError("注册账户失败",
			string(registration.CodeOf(err)), requestID)
	}
	return RegisteredAccount{UserID: result.UserID, Username: result.Username,
		Email: result.Email, Status: string(result.Status),
		VerificationSent:      result.VerificationSent,
		VerificationErrorCode: result.VerificationErrorCode,
		CreatedAt:             result.CreatedAt.UTC().Format(timeRFC3339)}, nil
}

// SendEmailVerification 为当前会话本人发送验证入口（受重发冷却限制）。
func (f *registrationFacade) SendEmailVerification(ctx context.Context,
	req SendEmailVerificationRequest) (EmailVerificationSendResult, error) {
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return EmailVerificationSendResult{}, err
	}
	session, err := f.r.requireSession(ctx, req.SessionSecret, true, requestID)
	if err != nil {
		return EmailVerificationSendResult{}, err
	}
	service, err := f.registrationService()
	if err != nil {
		return EmailVerificationSendResult{}, err
	}
	caller, err := registration.SelfCaller(session.UserID)
	if err != nil {
		return EmailVerificationSendResult{}, mapDomainError("会话主体无效",
			"ACCESS_DENIED", requestID)
	}
	result, err := service.SendEmailVerification(ctx, caller, registration.SendVerificationRequest{
		UserID: session.UserID, Email: req.Email, RequestID: requestID})
	if err != nil {
		return EmailVerificationSendResult{}, mapDomainError("发送验证入口失败",
			string(registration.CodeOf(err)), requestID)
	}
	return EmailVerificationSendResult{UserID: result.UserID, Email: result.Email,
		Sent: result.Sent, ErrorCode: string(result.ErrorCode),
		ResendAllowedAt: result.ResendAllowedAt.UTC().Format(timeRFC3339)}, nil
}

// VerifyEmail 消费一次性验证入口（匿名）。
func (f *registrationFacade) VerifyEmail(ctx context.Context,
	req VerifyEmailRequest) (VerifiedEmail, error) {
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return VerifiedEmail{}, err
	}
	service, err := f.registrationService()
	if err != nil {
		return VerifiedEmail{}, err
	}
	result, err := service.VerifyEmail(ctx, registration.VerifyEmailRequest{
		UserID: strings.TrimSpace(req.UserID), CredentialID: strings.TrimSpace(req.CredentialID),
		Token: req.Token, RequestID: requestID})
	if err != nil {
		return VerifiedEmail{}, mapDomainError("邮箱验证入口无效或已过期",
			string(registration.CodeOf(err)), requestID)
	}
	return VerifiedEmail{UserID: result.UserID, Email: result.Email,
		VerifiedAt: result.VerifiedAt.UTC().Format(timeRFC3339)}, nil
}

// ResendEmailVerification 匿名防枚举重发：任何失败都返回 Accepted=true；
// 只接受真实会话或邮件链接证明，不写库、不消费凭证（真实发送才走领域冷却）。
func (f *registrationFacade) ResendEmailVerification(ctx context.Context,
	req ResendEmailVerificationRequest) (ResendEmailVerificationResult, error) {
	accepted := ResendEmailVerificationResult{Accepted: true}
	services := f.r.coreServices()
	if services == nil || services.Registration == nil {
		return accepted, nil
	}
	service := services.Registration
	// 已登录用户：按真实本人身份重发。
	if len(req.SessionSecret) > 0 {
		if record, validateErr := services.Sessions.Validate(ctx, string(req.SessionSecret)); validateErr == nil {
			if caller, callerErr := registration.SelfCaller(record.UserID); callerErr == nil {
				_, _ = service.SendEmailVerification(ctx, caller,
					registration.SendVerificationRequest{UserID: record.UserID})
			}
			return accepted, nil
		}
	}
	// 匿名链接证明：uid+cid+token 必须匹配当前 pending 票据与一次性凭证（只读）。
	userID := strings.TrimSpace(req.UserID)
	credentialID := strings.TrimSpace(req.CredentialID)
	if userID == "" || credentialID == "" || req.Token == "" ||
		services.RegistrationStore == nil || services.Credential == nil {
		return accepted, nil
	}
	ticket, found, ticketErr := services.RegistrationStore.GetVerificationTicket(ctx, userID)
	if ticketErr != nil || !found || ticket.UserID != userID ||
		subtle.ConstantTimeCompare([]byte(ticket.CredentialID), []byte(credentialID)) != 1 {
		return accepted, nil
	}
	if _, peekErr := services.Credential.Peek(ctx, credential.VerifyRequest{
		Kind: credential.KindToken, ID: credentialID,
		Purpose: registration.PurposeEmailVerify, Target: userID, Secret: req.Token,
	}); peekErr != nil {
		return accepted, nil
	}
	componentID := strings.TrimSpace(f.r.opts.OperatorID)
	if componentID == "" {
		componentID = "app-registration-resend"
	}
	if system, callerErr := registration.SystemCaller(componentID); callerErr == nil {
		_, _ = service.SendEmailVerification(ctx, system,
			registration.SendVerificationRequest{UserID: userID})
	}
	return accepted, nil
}

// timeRFC3339 是公开结果统一时间格式。
const timeRFC3339 = "2006-01-02T15:04:05Z07:00"

// 保持 root 包错误码常量引用（编译期确保公开错误码存在）。
var _ = login.CodeConfigInvalid
