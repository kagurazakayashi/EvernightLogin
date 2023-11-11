// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

// 邮箱变更生命周期公开 Go 接口（步骤 221 P0）。
//
// 边界：
//   - 复用 internal/emailchange 真实实现：State/Request/Cancel/Verify、一次性令牌、
//     冷却/过期/取消语义、成功后邮箱切换与 206 安全失效链（旧找回入口随邮箱安全
//     变更失效由既有领域逻辑保证）；
//   - 身份只从完整会话派生，不接受 userID 传参；Verify 使用邮件链接中的一次性
//     参数（匿名），不签发会话；
//   - 发起变更走真实敏感操作 `email.change.request`（密码，必要时强因素动态码）；
//     验证入口不返回明文令牌；补偿重试令牌不在此公开结果中返回（宿主需重新发起，
//     如实登记边界）；
//   - 访问器 Runtime.EmailChange() 定义在本文件，不编辑 runtime.go/admin.go/types.go。

import (
	"context"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/emailchange"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
)

// EmailChangeService 是邮箱变更公开门面。
type EmailChangeService interface {
	// State 读取当前会话本人的邮箱变更状态（含 pending 申请）。
	State(ctx context.Context, req EmailChangeStateRequest) (EmailChangeState, error)
	// Request 发起邮箱变更：完整会话 + 近期再次认证（密码，必要时动态码）。
	Request(ctx context.Context, req RequestEmailChangeRequest) (EmailChangeState, error)
	// Cancel 取消 pending 邮箱变更（本人）。
	Cancel(ctx context.Context, req CancelEmailChangeRequest) error
	// Verify 消费邮件中的一次性验证入口并切换邮箱（匿名，不签发会话）。
	Verify(ctx context.Context, req VerifyEmailChangeRequest) (EmailChangeVerified, error)
}

// EmailChangeStateRequest 读取本人邮箱变更状态。
type EmailChangeStateRequest struct {
	SessionSecret []byte
	RequestID     string
}

// EmailChangeState 是邮箱变更状态视图（不含任何令牌）。
type EmailChangeState struct {
	HasEmail         bool
	OldEmail         string
	Pending          bool
	NewEmail         string
	ExpiresAt        string
	VerificationSent bool
	ErrorCode        string
}

// RequestEmailChangeRequest 发起邮箱变更。
type RequestEmailChangeRequest struct {
	SessionSecret []byte
	NewEmail      string
	// Password/TOTPCode 只用于本次真实再次认证，不保存/不记录。
	Password  string
	TOTPCode  string
	RequestID string
}

// CancelEmailChangeRequest 取消 pending 邮箱变更。
type CancelEmailChangeRequest struct {
	SessionSecret []byte
	// ChangeRequestID 为空时由门面按当前会话读取唯一 pending 申请 ID。
	ChangeRequestID string
	RequestID       string
}

// VerifyEmailChangeRequest 是邮件链接中的一次性验证参数（匿名）。
type VerifyEmailChangeRequest struct {
	// ChangeRequestID 是邮件链接里的变更申请 ID（rid）。
	ChangeRequestID string
	CredentialID    string
	Token           string
	RequestID       string
}

// EmailChangeVerified 是邮箱切换成功结果。
type EmailChangeVerified struct {
	UserID     string
	Email      string
	OldEmail   string
	SwitchedAt string
	Notified   bool
	ErrorCode  string
}

// EmailChange 返回邮箱变更公开门面。
func (r *Runtime) EmailChange() EmailChangeService {
	return &emailChangeFacade{r: r}
}

type emailChangeFacade struct {
	r *Runtime
}

// service 返回已装配的邮箱变更领域服务。
func (f *emailChangeFacade) service() (*emailchange.Service, error) {
	security := f.r.securityDomains()
	if security == nil || security.EmailChange == nil {
		return nil, configError("邮箱变更服务未装配")
	}
	return security.EmailChange, nil
}

// sessionUser 校验完整会话并返回本人用户 ID。
func (f *emailChangeFacade) sessionUser(ctx context.Context, secret []byte,
	requestID string) (string, error) {
	record, err := f.r.requireSession(ctx, secret, true, requestID)
	if err != nil {
		return "", err
	}
	return record.UserID, nil
}

// State 读取本人邮箱变更状态。
func (f *emailChangeFacade) State(ctx context.Context,
	req EmailChangeStateRequest) (EmailChangeState, error) {
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return EmailChangeState{}, err
	}
	userID, err := f.sessionUser(ctx, req.SessionSecret, requestID)
	if err != nil {
		return EmailChangeState{}, err
	}
	service, err := f.service()
	if err != nil {
		return EmailChangeState{}, err
	}
	caller, err := emailchange.UserCaller(userID)
	if err != nil {
		return EmailChangeState{}, mapDomainError("会话主体无效", "ACCESS_DENIED", requestID)
	}
	pending, found, err := service.GetPending(ctx, caller)
	if err != nil {
		return EmailChangeState{}, mapDomainError("读取邮箱变更状态失败",
			string(emailchange.CodeOf(err)), requestID)
	}
	if !found {
		return EmailChangeState{}, nil
	}
	return emailChangeStateOf(pending), nil
}

// Request 发起邮箱变更（真实再次认证 + 领域一次性令牌/冷却语义）。
func (f *emailChangeFacade) Request(ctx context.Context,
	req RequestEmailChangeRequest) (EmailChangeState, error) {
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return EmailChangeState{}, err
	}
	userID, err := f.sessionUser(ctx, req.SessionSecret, requestID)
	if err != nil {
		return EmailChangeState{}, err
	}
	service, err := f.service()
	if err != nil {
		return EmailChangeState{}, err
	}
	caller, err := emailchange.UserCaller(userID)
	if err != nil {
		return EmailChangeState{}, mapDomainError("会话主体无效", "ACCESS_DENIED", requestID)
	}
	approved, err := f.r.approveSensitive(ctx, userID, "email.change.request",
		"变更邮箱", req.Password, req.TOTPCode, requestID, policy.StrengthPassword)
	if err != nil {
		return EmailChangeState{}, err
	}
	result, err := service.RequestChange(approved, caller, req.NewEmail, requestID)
	if err != nil {
		return EmailChangeState{}, mapDomainError("发起邮箱变更失败",
			string(emailchange.CodeOf(err)), requestID)
	}
	state := emailChangeStateOf(result.Request)
	state.VerificationSent = result.VerificationSent
	if !result.VerificationSent {
		state.ErrorCode = result.ErrorCode
	}
	return state, nil
}

// Cancel 取消 pending 邮箱变更。
func (f *emailChangeFacade) Cancel(ctx context.Context,
	req CancelEmailChangeRequest) error {
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return err
	}
	userID, err := f.sessionUser(ctx, req.SessionSecret, requestID)
	if err != nil {
		return err
	}
	service, err := f.service()
	if err != nil {
		return err
	}
	caller, err := emailchange.UserCaller(userID)
	if err != nil {
		return mapDomainError("会话主体无效", "ACCESS_DENIED", requestID)
	}
	changeRequestID := strings.TrimSpace(req.ChangeRequestID)
	if changeRequestID == "" {
		pending, found, pendingErr := service.GetPending(ctx, caller)
		if pendingErr != nil {
			return mapDomainError("读取待取消的邮箱变更失败",
				string(emailchange.CodeOf(pendingErr)), requestID)
		}
		if !found {
			return newNotFoundError("email change", requestID)
		}
		changeRequestID = pending.ID
	}
	if err := service.Cancel(ctx, caller, emailchange.CancelRequest{
		RequestID: changeRequestID, RequestIDLog: requestID}); err != nil {
		return mapDomainError("取消邮箱变更失败",
			string(emailchange.CodeOf(err)), requestID)
	}
	return nil
}

// Verify 消费一次性验证入口并切换邮箱（匿名）。
func (f *emailChangeFacade) Verify(ctx context.Context,
	req VerifyEmailChangeRequest) (EmailChangeVerified, error) {
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return EmailChangeVerified{}, err
	}
	service, err := f.service()
	if err != nil {
		return EmailChangeVerified{}, err
	}
	result, err := service.Verify(ctx, emailchange.VerifyRequest{
		RequestID: req.ChangeRequestID, CredentialID: req.CredentialID,
		Token: req.Token, RequestIDLog: requestID})
	if err != nil {
		return EmailChangeVerified{}, mapDomainError("邮箱变更验证入口无效或已过期",
			string(emailchange.CodeOf(err)), requestID)
	}
	return EmailChangeVerified{UserID: result.UserID, Email: result.Email,
		OldEmail: result.OldEmail, SwitchedAt: result.SwitchedAt.UTC().Format(time.RFC3339),
		Notified: result.Notified, ErrorCode: result.ErrorCode}, nil
}

// emailChangeStateOf 转换邮箱变更视图并统一时间格式。
func emailChangeStateOf(record emailchange.Request) EmailChangeState {
	return EmailChangeState{HasEmail: record.OldEmail != "", OldEmail: record.OldEmail,
		Pending: true, NewEmail: record.NewEmail,
		ExpiresAt:        formatOptionalTime(record.ExpiresAt),
		VerificationSent: record.VerifyState == emailchange.NotifySent,
		ErrorCode:        record.VerifyError}
}
