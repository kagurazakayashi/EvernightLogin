package passwordreset

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
)

// SupportResetRequest 是受信客服/管理通道的找回发起请求。
//
// 与公开的 BeginReset 不同：
//   - 目标按稳定用户 ID 定位，收件地址只能来自该用户**此前已验证的邮箱**，调用方
//     不能指定或替换收件地址；
//   - 调用方是受信内部服务（客服求助单服务），因此会返回明确的结果/错误而不是
//     统一通用响应（账户存在性已在客服授权范围内确认，这里不再需要反枚举）；
//   - 只触发“向原验证邮箱发送一次性入口”，不修改密码、不解除 MFA、不签发会话，
//     也不返回邮件链接/token/验证码。原密码在用户本人完成找回前保持有效。
type SupportResetRequest struct {
	// TargetUserID 是求助单绑定的目标普通用户稳定 ID。
	TargetUserID string
	// RequestID 是请求追踪编号（可选）。
	RequestID string
}

// SupportResetResult 是受信通道发起找回的结果；不包含链接、token 或收件地址。
type SupportResetResult struct {
	// Delivered 表示一次性入口邮件已交给投递接口（不表示用户已收到或已完成找回）。
	Delivered bool
}

// SupportRatePolicy 是受信通道按目标用户限流策略，防止客服重复发起邮件轰炸。
type SupportRatePolicy struct {
	Limit  int
	Window time.Duration
}

// DefaultSupportRatePolicy 返回保守默认：同一目标用户每小时最多 3 次。
func DefaultSupportRatePolicy() SupportRatePolicy {
	return SupportRatePolicy{Limit: 3, Window: time.Hour}
}

// supportLimiter 是受信通道按目标用户的进程内滑动窗口限流器（有界容量）。
type supportLimiter struct {
	mu      sync.Mutex
	policy  SupportRatePolicy
	entries map[string][]time.Time
}

func (l *supportLimiter) allow(key string, now time.Time) bool {
	if l == nil || key == "" || l.policy.Limit <= 0 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-l.policy.Window)
	kept := l.entries[key]
	retained := kept[:0]
	for _, timestamp := range kept {
		if timestamp.After(cutoff) {
			retained = append(retained, timestamp)
		}
	}
	if len(retained) >= l.policy.Limit {
		l.entries[key] = retained
		return false
	}
	l.entries[key] = append(retained, now)
	if len(l.entries) > 10000 {
		for candidate, timestamps := range l.entries {
			if len(timestamps) == 0 || !timestamps[len(timestamps)-1].After(cutoff) {
				delete(l.entries, candidate)
			}
		}
	}
	return true
}

// SendResetForSupport 由受信客服求助单服务调用：向目标用户此前已验证的邮箱发送
// 一次性密码找回入口。只允许原已验证邮箱，调用方不能选择新地址，也不返回链接或
// 验证码；不修改密码（用户完成找回后密码才改变），不解除 MFA。重复发起按目标用户
// 有界限流并返回 RATE_LIMITED。
func (s *Service) SendResetForSupport(ctx context.Context, request SupportResetRequest) (SupportResetResult, error) {
	ctx = normalizeContext(ctx)
	if !account.ValidUserID(request.TargetUserID) {
		s.recordSupportFailure(ctx, "", "invalid_target", string(CodeReqInvalid), request.RequestID)
		return SupportResetResult{}, fmt.Errorf("%w: 目标用户标识无效", ErrInvalidRequest)
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		s.recordSupportFailure(ctx, request.TargetUserID, "invalid_request_id", string(CodeReqInvalid), request.RequestID)
		return SupportResetResult{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	now := s.now()
	// 按目标用户维度限流：同一用户窗口内重复发起只允许有限次数，防止邮件轰炸。
	if !s.supportLimiter.allow(request.TargetUserID, now) {
		s.recordSupportFailure(ctx, request.TargetUserID, "rate_limited", string(CodeRateLimited), request.RequestID)
		return SupportResetResult{}, ErrRateLimited
	}
	candidate, found, err := s.opts.Store.GetResetTarget(ctx, request.TargetUserID)
	if err != nil {
		return SupportResetResult{}, ErrStoreUnavailable
	}
	if !found || !candidate.Active {
		s.recordSupportFailure(ctx, request.TargetUserID, "target_unavailable", string(CodeUserDisabled), request.RequestID)
		return SupportResetResult{}, ErrAccountDisabled
	}
	if candidate.IsRoot {
		s.recordSupportFailure(ctx, request.TargetUserID, "target_protected", string(CodeAccessDenied), request.RequestID)
		return SupportResetResult{}, ErrAccessDenied
	}
	if !candidate.HasPassword {
		s.recordSupportFailure(ctx, request.TargetUserID, "no_password", string(CodeAccessDenied), request.RequestID)
		return SupportResetResult{}, ErrNoPassword
	}
	if candidate.Email == "" {
		s.recordSupportFailure(ctx, request.TargetUserID, "no_verified_email", string(CodeAccessDenied), request.RequestID)
		return SupportResetResult{}, ErrNoVerifiedEmail
	}
	resetID, err := newID(s.opts.Random, "prq_", 16)
	if err != nil {
		return SupportResetResult{}, err
	}
	issued, err := s.opts.Credentials.Issue(ctx, credential.IssueRequest{
		Purpose: resetPurpose, Target: candidate.UserID, Kind: credential.KindToken,
		TTL: s.opts.TokenTTL,
	})
	if err != nil {
		return SupportResetResult{}, ErrStoreUnavailable
	}
	secret := issued.Secret.Reveal()
	tokenSha := sha256.Sum256([]byte(secret))
	record := ResetRequest{
		ID: resetID, UserID: candidate.UserID, MaskedEmail: candidate.MaskedEmail,
		CredentialID: issued.ID, TokenSHA256: tokenSha[:], State: "pending",
		CreatedAt: now, ExpiresAt: now.Add(s.opts.TokenTTL),
	}
	oldPending, listErr := s.opts.Store.ListPending(ctx, candidate.UserID)
	if listErr != nil {
		return SupportResetResult{}, ErrStoreUnavailable
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:  audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
			Action: "password.reset_requested", Outcome: audit.OutcomeSuccess,
			Target:    audit.Target{Type: "user", ID: candidate.UserID},
			RequestID: validRequestID(request.RequestID),
			Changes: []audit.FieldChange{
				{Field: "channel", After: "support_case"},
				{Field: "recipient", After: candidate.MaskedEmail},
				{Field: "expires_at_ms", After: fmt.Sprint(record.ExpiresAt.UnixMilli())},
			},
		},
		FailureReasonCode:   "password.reset_request_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		if _, cancelErr := s.opts.Store.CancelPendingTx(txCtx, tx, candidate.UserID, now); cancelErr != nil {
			return cancelErr
		}
		return s.opts.Store.CreateRequestTx(txCtx, tx, record)
	}); err != nil {
		return SupportResetResult{}, mapCriticalError(err)
	}
	s.revokeCredentials(ctx, oldPending)
	token := resetID + "." + secret
	resetURL := s.opts.ResetURLBase + "?token=" + url.QueryEscape(token)
	if err := s.sendResetMail(ctx, candidate, resetURL, request.RequestID, resetID); err != nil {
		s.recordSupportFailure(ctx, candidate.UserID, "mail_failed", string(CodeMailDeliveryFailed), request.RequestID)
		return SupportResetResult{}, err
	}
	return SupportResetResult{Delivered: true}, nil
}

// recordSupportFailure 为受信通道拒绝/失败路径写失败审计；不含链接、token 或邮箱明文。
func (s *Service) recordSupportFailure(ctx context.Context, targetUserID, reason, code, requestID string) {
	event := audit.Event{
		Actor:  audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
		Action: "password.reset_requested", Outcome: audit.OutcomeFailure,
		Target:    audit.Target{Type: "user", ID: targetUserID},
		ErrorCode: code, ReasonCode: safeToken(reason), RequestID: validRequestID(requestID),
	}
	if err := s.opts.Audit.RecordFailure(ctx, event); err != nil {
		s.opts.Logger.Warn("客服找回失败审计写入失败", "error", err)
	}
}
