package emailchange

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
)

// AuditRecorder 是安全审计写入契约；实现必须 fail-closed。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// Options 是邮箱变更服务依赖。
type Options struct {
	Store       Store
	Audit       AuditRecorder
	Credentials *credential.Service
	// ReauthVerifier 是近期身份验证契约；nil 时普通用户变更一律拒绝。
	ReauthVerifier ReauthVerifier
	// Mailer 是邮件发送接口；nil 表示无法发送（申请状态记录为 failed，验证入口由
	// 宿主以受控渠道传递）。
	Mailer              EmailSender
	VerificationURLBase string
	SupportURL          string
	AppName             string
	TTL                 time.Duration
	Now                 func() time.Time
	Random              io.Reader
	Logger              *slog.Logger
}

// Service 是邮箱变更服务。构造后不可变，不启动协程、不发会话。
type Service struct {
	opts Options
}

// New 校验依赖并构造服务。
func New(options Options) (*Service, error) {
	if isNil(options.Store) {
		return nil, fmt.Errorf("%w: 邮箱变更存储为空", ErrOptionsInvalid)
	}
	if isNil(options.Audit) {
		return nil, fmt.Errorf("%w: 安全审计写入器为空", ErrOptionsInvalid)
	}
	if options.Credentials == nil {
		return nil, fmt.Errorf("%w: 一次性凭证服务为空", ErrOptionsInvalid)
	}
	if isNil(options.Mailer) {
		options.Mailer = nil
	} else {
		if problem := urlProblem(options.VerificationURLBase); problem != "" {
			return nil, fmt.Errorf("%w: %s", ErrOptionsInvalid, problem)
		}
		if problem := urlProblem(options.SupportURL); problem != "" {
			return nil, fmt.Errorf("%w: 支持入口地址: %s", ErrOptionsInvalid, problem)
		}
	}
	if isNil(options.ReauthVerifier) {
		options.ReauthVerifier = nil
	}
	if options.TTL == 0 {
		options.TTL = DefaultTTL
	}
	if options.TTL < MinTTL || options.TTL > MaxTTL {
		return nil, fmt.Errorf("%w: 有效期必须在 %s～%s 之间", ErrOptionsInvalid, MinTTL, MaxTTL)
	}
	if strings.TrimSpace(options.AppName) == "" {
		options.AppName = "EvernightLogin"
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Service{opts: options}, nil
}

// RequestChange 发起邮箱变更（或首次添加）申请。
//
// 必须由用户本人发起并通过 ReauthVerifier；新地址验证成功前旧地址保持待验证状态。
// 会取消该用户既有 pending 申请并撤销其旧凭证。返回结果明确验证邮件是否发送成功。
func (s *Service) RequestChange(ctx context.Context, caller Caller, newEmail, requestIDLog string) (RequestResult, error) {
	ctx = normalizeContext(ctx)
	if !caller.IsUser() {
		return RequestResult{}, ErrAccessDenied
	}
	if err := account.ValidateRequestID(requestIDLog); err != nil {
		return RequestResult{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	userID := caller.actor.ID
	newDisplay, newNormalized, err := authn.NormalizeEmail(newEmail)
	if err != nil {
		return RequestResult{}, fmt.Errorf("%w: 新邮箱格式无效", ErrInvalidRequest)
	}
	if isNil(s.opts.ReauthVerifier) {
		return RequestResult{}, ErrReauthRequired
	}
	if err := s.opts.ReauthVerifier.VerifyReauth(ctx, caller, userID); err != nil {
		return RequestResult{}, ErrReauthRequired
	}
	old, hasOld, err := s.opts.Store.CurrentEmail(ctx, userID)
	if err != nil {
		return RequestResult{}, ErrStoreUnavailable
	}
	if hasOld && old.Normalized == newNormalized {
		return RequestResult{}, fmt.Errorf("%w: 新邮箱与当前邮箱相同", ErrInvalidRequest)
	}
	inUse, err := s.opts.Store.EmailInUse(ctx, newNormalized, userID)
	if err != nil {
		return RequestResult{}, ErrStoreUnavailable
	}
	if inUse {
		// 不在自助接口暴露他人邮箱是否存在：返回通用请求错误（HTTP 层还需统一
		// 响应形状并叠加限流）。
		return RequestResult{}, fmt.Errorf("%w: 无法使用该邮箱", ErrInvalidRequest)
	}
	now := s.now()
	requestID, err := newRequestID(s.opts.Random)
	if err != nil {
		return RequestResult{}, fmt.Errorf("%w: 无法生成申请标识", ErrStoreUnavailable)
	}
	issued, err := s.opts.Credentials.Issue(ctx, credential.IssueRequest{
		Purpose: PurposeEmailChangeVerify,
		Target:  requestID,
		Kind:    credential.KindToken,
		TTL:     s.opts.TTL,
	})
	if err != nil {
		return RequestResult{}, fmt.Errorf("%w: 无法签发验证令牌", ErrStoreUnavailable)
	}
	verificationURL, err := s.buildVerificationURL(requestID, issued.ID, issued.Secret.Reveal())
	if err != nil {
		_ = s.opts.Credentials.Cancel(context.WithoutCancel(ctx), credential.CancelRequest{
			ID: issued.ID, Purpose: PurposeEmailChangeVerify, Target: requestID})
		return RequestResult{}, fmt.Errorf("%w: 无法生成验证入口", ErrOptionsInvalid)
	}
	record := RequestRecord{
		ID: requestID, UserID: userID,
		NewEmail: newDisplay, NewEmailNormalized: newNormalized,
		CredentialID: issued.ID, CreatedAt: now, ExpiresAt: issued.ExpiresAt.UTC(),
		RequestID: requestIDLog,
	}
	if hasOld {
		record.OldEmail, record.OldEmailNormalized = old.Email, old.Normalized
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.actor, Action: "email.change.request",
			Target: audit.Target{Type: "user", ID: userID}, RequestID: requestIDLog,
			Changes: []audit.FieldChange{
				{Field: "old_email", Before: MaskEmail(record.OldEmail), After: ""},
				{Field: "new_email", After: MaskEmail(newDisplay)},
			},
		},
		FailureReasonCode:   "email.change.request_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	err = s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.opts.Store.BeginRequest(txCtx, tx, record)
	})
	if err != nil {
		_ = s.opts.Credentials.Cancel(context.WithoutCancel(ctx), credential.CancelRequest{
			ID: issued.ID, Purpose: PurposeEmailChangeVerify, Target: requestID})
		return RequestResult{}, mapCriticalError(err)
	}
	result := RequestResult{}
	if s.opts.Mailer == nil {
		result.ErrorCode = string(CodeMailDeliveryFailed)
		s.markVerify(ctx, requestID, NotifyFailed, result.ErrorCode)
	} else if sendErr := s.opts.Mailer.SendVerification(ctx, VerificationEmail{
		RequestID: requestID, Recipient: newDisplay, VerificationURL: verificationURL,
		ExpiresIn: formatDuration(s.opts.TTL), AppName: s.opts.AppName, RequestIDLog: requestIDLog,
	}); sendErr != nil {
		result.ErrorCode = string(CodeMailDeliveryFailed)
		s.markVerify(ctx, requestID, NotifyFailed, result.ErrorCode)
	} else {
		result.VerificationSent = true
		s.markVerify(ctx, requestID, NotifySent, "")
	}
	request, found, err := s.opts.Store.GetRequest(ctx, requestID)
	if err != nil || !found {
		return RequestResult{}, ErrStoreUnavailable
	}
	result.Request = request
	return result, nil
}

// Verify 消费一次性验证入口并在审计事务内完成邮箱切换。
func (s *Service) Verify(ctx context.Context, request VerifyRequest) (VerifyResult, error) {
	ctx = normalizeContext(ctx)
	if strings.TrimSpace(request.RequestID) == "" || strings.TrimSpace(request.CredentialID) == "" ||
		request.Token == "" {
		return VerifyResult{}, ErrRequestNotFound
	}
	if _, err := s.opts.Credentials.VerifyAndConsume(ctx, credential.VerifyRequest{
		Kind: credential.KindToken, ID: request.CredentialID,
		Purpose: PurposeEmailChangeVerify, Target: request.RequestID, Secret: request.Token,
	}); err != nil {
		if errors.Is(err, credential.ErrStoreUnavailable) {
			return VerifyResult{}, ErrStoreUnavailable
		}
		return VerifyResult{}, ErrRequestNotFound
	}
	now := s.now()
	// 预读申请用于审计身份与事务失败补偿；事务内仍以最新状态为准。
	preload, preloadFound, preloadErr := s.opts.Store.GetRequest(ctx, request.RequestID)
	if preloadErr != nil {
		return VerifyResult{}, ErrStoreUnavailable
	}
	switched := false
	result := VerifyResult{}
	auditActor := audit.Actor{Type: audit.ActorAnonymous}
	auditTarget := audit.Target{Type: "email_change", ID: request.RequestID}
	if preloadFound {
		auditActor = audit.Actor{Type: audit.ActorUser, ID: preload.UserID}
		auditTarget = audit.Target{Type: "user", ID: preload.UserID}
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:  auditActor,
			Action: "email.change.verify", Target: auditTarget,
			RequestID: request.RequestIDLog,
			Changes: []audit.FieldChange{
				{Field: "old_email", Before: MaskEmail(preload.OldEmail), After: ""},
				{Field: "new_email", After: MaskEmail(preload.NewEmail)},
			},
		},
		FailureReasonCode:   "email.change.verify_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		record, found, err := s.opts.Store.LoadRequestTx(txCtx, tx, request.RequestID)
		if err != nil {
			return err
		}
		if !found {
			return ErrRequestNotFound
		}
		if record.Status != StatusPending {
			switch record.Status {
			case StatusCancelled:
				return ErrRequestCancelled
			case StatusExpired:
				return ErrRequestExpired
			}
			return ErrRequestNotFound
		}
		if !now.Before(record.ExpiresAt) {
			return ErrRequestExpired
		}
		ok, err := s.opts.Store.CompleteRequestTx(txCtx, tx, CompleteParams{
			RequestID: record.ID, NewEmail: record.NewEmail,
			NewEmailNormalized: record.NewEmailNormalized, Now: now,
		})
		if err != nil {
			return err
		}
		if !ok {
			return ErrRequestNotFound
		}
		switched = true
		result = VerifyResult{UserID: record.UserID, Email: record.NewEmail, SwitchedAt: now,
			OldEmail: record.OldEmail}
		return nil
	})
	if err != nil {
		// 令牌已消费但事务失败：补偿性地在同一 pending 申请上重新签发凭证并返回给
		// 调用方，避免用户白烧链接（数据库主事务已整体回滚）。
		retry := s.issueRetryCredential(ctx, preload, preloadFound, now)
		return retry, mapCriticalError(err)
	}
	if !switched {
		return VerifyResult{}, ErrRequestNotFound
	}
	// 向旧已验证邮箱发送安全告知（不含令牌/链接）；投递失败不回滚已完成切换。
	if result.OldEmail != "" && s.opts.Mailer != nil {
		noticeErr := s.opts.Mailer.SendSecurityNotice(ctx, SecurityNoticeEmail{
			RequestID: request.RequestID, Recipient: result.OldEmail,
			Event: "邮箱地址已变更", OccurredAt: now.UTC().Format(time.RFC3339),
			AppName: s.opts.AppName, SupportURL: s.opts.SupportURL,
		})
		if noticeErr != nil {
			result.ErrorCode = string(CodeMailDeliveryFailed)
			s.markNotify(ctx, request.RequestID, NotifyFailed, result.ErrorCode)
		} else {
			result.Notified = true
			s.markNotify(ctx, request.RequestID, NotifySent, "")
		}
	} else {
		s.markNotify(ctx, request.RequestID, NotifySkipped, "")
	}
	s.opts.Logger.Info("邮箱变更已生效", "user_id", result.UserID)
	return result, nil
}

// Cancel 取消本人（或受信系统）的 pending 申请。
func (s *Service) Cancel(ctx context.Context, caller Caller, request CancelRequest) error {
	ctx = normalizeContext(ctx)
	if err := account.ValidateRequestID(request.RequestIDLog); err != nil {
		return fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if strings.TrimSpace(request.RequestID) == "" {
		return ErrInvalidRequest
	}
	record, found, err := s.opts.Store.GetRequest(ctx, request.RequestID)
	if err != nil {
		return ErrStoreUnavailable
	}
	if !found {
		return ErrRequestNotFound
	}
	if !s.canAccess(caller, record.UserID) {
		return ErrAccessDenied
	}
	cancelled := false
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.actor, Action: "email.change.cancel",
			Target: audit.Target{Type: "email_change", ID: request.RequestID}, RequestID: request.RequestIDLog,
		},
		FailureReasonCode:   "email.change.cancel_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	err = s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, err := s.opts.Store.CancelRequestTx(txCtx, tx, request.RequestID, record.UserID, s.now())
		if err != nil {
			return err
		}
		cancelled = ok
		return nil
	})
	if err != nil {
		return mapCriticalError(err)
	}
	if !cancelled {
		return ErrRequestNotFound
	}
	_ = s.opts.Credentials.Cancel(context.WithoutCancel(ctx), credential.CancelRequest{
		ID: record.CredentialID, Purpose: PurposeEmailChangeVerify, Target: record.ID})
	return nil
}

// GetPending 返回本人当前 pending 申请（不含令牌）。
func (s *Service) GetPending(ctx context.Context, caller Caller) (Request, bool, error) {
	if !caller.IsUser() {
		return Request{}, false, ErrAccessDenied
	}
	record, found, err := s.opts.Store.GetActiveRequest(ctx, caller.actor.ID)
	if err != nil {
		return Request{}, false, ErrStoreUnavailable
	}
	return record, found, nil
}

func (s *Service) canAccess(caller Caller, ownerUserID string) bool {
	switch caller.actor.Type {
	case audit.ActorUser:
		return caller.actor.ID == ownerUserID
	case audit.ActorSystem:
		return true
	default:
		return false
	}
}

func (s *Service) markVerify(ctx context.Context, requestID string, state NotifyState, code string) {
	if err := s.opts.Store.MarkVerify(context.WithoutCancel(ctx), requestID, state, code, s.now()); err != nil {
		s.opts.Logger.Warn("记录验证邮件状态失败", "request_id", requestID)
	}
}

func (s *Service) markNotify(ctx context.Context, requestID string, state NotifyState, code string) {
	if err := s.opts.Store.MarkNotify(context.WithoutCancel(ctx), requestID, state, code, s.now()); err != nil {
		s.opts.Logger.Warn("记录旧邮箱告知状态失败", "request_id", requestID)
	}
}

func (s *Service) buildVerificationURL(requestID, credentialID, token string) (string, error) {
	base, err := url.Parse(s.opts.VerificationURLBase)
	if err != nil {
		return "", err
	}
	query := base.Query()
	query.Set("rid", requestID)
	query.Set("cid", credentialID)
	query.Set("token", token)
	base.RawQuery = query.Encode()
	base.Fragment = ""
	return base.String(), nil
}

func (s *Service) now() time.Time { return s.opts.Now().UTC().Truncate(time.Millisecond) }

func newRequestID(random io.Reader) (string, error) {
	buffer := make([]byte, 16)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", err
	}
	const hexDigits = "0123456789abcdef"
	var builder strings.Builder
	builder.WriteString("ecr_")
	for _, value := range buffer {
		builder.WriteByte(hexDigits[value>>4])
		builder.WriteByte(hexDigits[value&0x0f])
	}
	return builder.String(), nil
}

func formatDuration(d time.Duration) string {
	if d%time.Hour == 0 {
		return fmt.Sprintf("%d 小时", int(d/time.Hour))
	}
	if d%time.Minute == 0 {
		return fmt.Sprintf("%d 分钟", int(d/time.Minute))
	}
	return d.String()
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func mapCriticalError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, audit.ErrAuditUnavailable):
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	case errors.Is(err, audit.ErrInvalidEvent):
		return fmt.Errorf("%w: 审计事件无效", ErrOptionsInvalid)
	case errors.Is(err, ErrEmailInUse), errors.Is(err, ErrRequestNotFound),
		errors.Is(err, ErrRequestExpired), errors.Is(err, ErrRequestCancelled),
		errors.Is(err, ErrAccessDenied), errors.Is(err, ErrInvalidRequest),
		errors.Is(err, ErrOptionsInvalid), errors.Is(err, ErrMailUnavailable):
		return err
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, ErrStoreUnavailable):
		return err
	default:
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
}

func urlProblem(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "入口地址不能为空"
	}
	if len(value) > 2048 {
		return "入口地址超过 2048 字节"
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") ||
		parsed.User != nil || parsed.Fragment != "" {
		return "入口地址必须是合法的 http/https URL 且不含凭证/片段"
	}
	return ""
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

// issueRetryCredential 在验证事务失败后为仍 pending 的申请重新签发凭证，返回给本次
// 调用方供宿主重新投递；失败时返回空补偿字段（不掩盖原错误）。
func (s *Service) issueRetryCredential(ctx context.Context, record Request, found bool, now time.Time) VerifyResult {
	if !found || record.Status != StatusPending || !now.Before(record.ExpiresAt) {
		return VerifyResult{}
	}
	remaining := record.ExpiresAt.Sub(now)
	if remaining < credential.MinTTL {
		return VerifyResult{}
	}
	issued, err := s.opts.Credentials.Issue(ctx, credential.IssueRequest{
		Purpose: PurposeEmailChangeVerify, Target: record.ID,
		Kind: credential.KindToken, TTL: remaining,
	})
	if err != nil {
		return VerifyResult{}
	}
	if err := s.opts.Store.UpdateCredential(context.WithoutCancel(ctx), record.ID, issued.ID); err != nil {
		_ = s.opts.Credentials.Cancel(context.WithoutCancel(ctx), credential.CancelRequest{
			ID: issued.ID, Purpose: PurposeEmailChangeVerify, Target: record.ID})
		return VerifyResult{}
	}
	retryURL, err := s.buildVerificationURL(record.ID, issued.ID, issued.Secret.Reveal())
	if err != nil {
		return VerifyResult{}
	}
	return VerifyResult{
		UserID: record.UserID, Email: record.NewEmail,
		RetryCredentialID: issued.ID, RetryToken: issued.Secret.Reveal(), RetryURL: retryURL,
	}
}
