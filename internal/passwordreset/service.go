package passwordreset

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
)

// ChangePassword 执行本人主动改密：authn.SetPassword 负责当前密码复核、密码策略/
// 历史复用与步骤 39 敏感操作策略；成功后安全版本已递增（旧会话失效），本方法再
// 撤销该账户全部会话（默认要求重新登录）并写入 OAuth 撤销 outbox。撤销/outbox 失败
// 不回滚已成功的改密（安全版本已保证失效），但会记录失败审计与日志。
func (s *Service) ChangePassword(ctx context.Context, caller Caller, request ChangeRequest) (ChangeResult, error) {
	ctx = normalizeContext(ctx)
	if err := caller.actor.Validate(); err != nil || !caller.IsUser() {
		return ChangeResult{}, ErrAccessDenied
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return ChangeResult{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if strings.TrimSpace(request.NewPassword) == "" || len(request.NewPassword) > 1024 {
		return ChangeResult{}, fmt.Errorf("%w: 新密码长度无效", ErrInvalidRequest)
	}
	authnCaller, err := authn.UserCaller(caller.actor.ID)
	if err != nil {
		return ChangeResult{}, ErrAccessDenied
	}
	if request.RequestID != "" {
		authnCaller, err = authnCaller.WithRequestID(request.RequestID)
		if err != nil {
			return ChangeResult{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
		}
	}
	result, err := s.opts.Passwords.SetPassword(ctx, authnCaller, authn.SetPasswordRequest{
		TargetUserID: caller.actor.ID, NewPassword: request.NewPassword,
		CurrentPassword: request.CurrentPassword, ClientIP: request.ClientIP,
		RequireChange: false, RequestID: request.RequestID,
	})
	if err != nil {
		s.recordFailure(ctx, caller.actor, "password.changed", "password_change_rejected",
			string(CodeOf(err)), request.RequestID)
		return ChangeResult{}, err
	}
	// 默认安全策略：改密后要求重新登录，撤销包括当前会话在内的全部会话。安全版本
	// 已递增，因此即使撤销失败，旧会话也会在下次校验时因版本不匹配失效。
	sessionsRevoked, revokeErr := s.opts.Sessions.RevokeAllForUser(ctx, caller.actor.ID, "password_changed")
	if revokeErr != nil {
		s.opts.Logger.Warn("改密后会话撤销失败（安全版本已使旧会话失效）", "error", revokeErr)
		s.recordFailure(ctx, caller.actor, "password.changed", "session_revoke_failed",
			string(CodeDBUnavailable), request.RequestID)
	}
	// 主动改密也作废该用户所有 pending 找回入口（旧 token 立即失效）。
	s.invalidatePending(ctx, caller.actor.ID, request.RequestID, "password_changed")
	outboxID, outboxErr := s.appendOutboxWithRetry(ctx, caller.actor.ID, outboxReasonChanged, request.RequestID)
	if outboxErr != nil {
		s.opts.Logger.Warn("改密后 OAuth 撤销事件写入失败", "error", outboxErr)
	}
	return ChangeResult{
		UserID: caller.actor.ID, SecurityVersion: result.SecurityVersion,
		RequiresRelogin: true, SessionsRevoked: sessionsRevoked,
		OutboxEventID: outboxID, ChangedAt: result.PasswordChangedAt,
	}, nil
}

// BeginReset 开始邮件找回。为避免账户存在性泄露，未找到、无密码、禁用、root、
// 限流或邮件发送失败都返回相同的零值结果与 nil 错误；只有内部存储/审计失败向上
// 返回。命中与未命中都会执行签发+取消一次性凭证等主要数据库工作，缩小可观测时延
// 差异（发送邮件仍是命中路径独有，残余时序差与传输层限流待 HTTP 接线）。
func (s *Service) BeginReset(ctx context.Context, request BeginResetRequest) (BeginResult, error) {
	ctx = normalizeContext(ctx)
	normalized := strings.ToLower(strings.TrimSpace(request.Identifier))
	if normalized == "" || len(normalized) > 254 || !strings.Contains(normalized, "@") {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
			"password.reset_requested", "invalid_identifier", string(CodeReqInvalid), request.RequestID)
		return BeginResult{}, nil
	}
	now := s.now()
	// 每邮箱/每来源有界滑动窗口限流，防账户枚举与邮件轰炸；超限回统一响应。
	if !s.emailLimiter.allow(normalized, now) || !s.ipLimiter.allow(strings.TrimSpace(request.ClientIP), now) {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
			"password.reset_requested", "rate_limited", string(CodeRateLimited), request.RequestID)
		return BeginResult{}, nil
	}
	candidate, found, err := s.opts.Store.FindUserByEmail(ctx, normalized)
	if err != nil {
		return BeginResult{}, ErrStoreUnavailable
	}
	eligible := found && candidate.Active && !candidate.IsRoot && candidate.HasPassword
	if !eligible {
		// 统一响应：仍执行一次签发+取消的等量主要工作以缓解时序侧信道；发送邮件与
		// 持久化找回请求仍是命中路径独有，残余差异已在 README 说明。
		if err := s.dummyCredentialWork(ctx); err != nil {
			return BeginResult{}, err
		}
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
			"password.reset_requested", "ineligible", string(CodeAccessDenied), request.RequestID)
		return BeginResult{}, nil
	}
	resetID, err := newID(s.opts.Random, "prq_", 16)
	if err != nil {
		return BeginResult{}, err
	}
	issued, err := s.opts.Credentials.Issue(ctx, credential.IssueRequest{
		Purpose: resetPurpose, Target: candidate.UserID, Kind: credential.KindToken,
		TTL: s.opts.TokenTTL,
	})
	if err != nil {
		return BeginResult{}, ErrStoreUnavailable
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
		return BeginResult{}, ErrStoreUnavailable
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:  audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
			Action: "password.reset_requested", Outcome: audit.OutcomeSuccess,
			Target:    audit.Target{Type: "user", ID: candidate.UserID},
			RequestID: validRequestID(request.RequestID),
			Changes: []audit.FieldChange{
				{Field: "recipient", After: candidate.MaskedEmail},
				{Field: "expires_at_ms", After: fmt.Sprint(record.ExpiresAt.UnixMilli())},
			},
		},
		FailureReasonCode:   "password.reset_request_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		// 新请求作废旧 pending（同一事务内状态迁移），避免多条入口同时有效。
		if _, cancelErr := s.opts.Store.CancelPendingTx(txCtx, tx, candidate.UserID, now); cancelErr != nil {
			return cancelErr
		}
		return s.opts.Store.CreateRequestTx(txCtx, tx, record)
	}); err != nil {
		return BeginResult{}, mapCriticalError(err)
	}
	// 旧 pending 的凭证在状态迁移后尽力撤销（不存在/已消费时幂等忽略）。
	s.revokeCredentials(ctx, oldPending)
	token := resetID + "." + secret
	resetURL := s.opts.ResetURLBase + "?token=" + url.QueryEscape(token)
	if err := s.sendResetMail(ctx, candidate, resetURL, request.RequestID, resetID); err != nil {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
			"password.reset_requested", "mail_failed", string(CodeMailDeliveryFailed), request.RequestID)
		return BeginResult{}, nil
	}
	return BeginResult{}, nil
}

// dummyCredentialWork 在未命中路径执行与命中路径相近的签发+取消数据库工作，用于
// 缓解账户枚举时序侧信道；不发送邮件、不写找回请求。
func (s *Service) dummyCredentialWork(ctx context.Context) error {
	dummyID, err := newID(s.opts.Random, "prq_", 16)
	if err != nil {
		return err
	}
	issued, err := s.opts.Credentials.Issue(ctx, credential.IssueRequest{
		Purpose: resetPurpose, Target: "unknown", Kind: credential.KindToken, TTL: s.opts.TokenTTL,
	})
	if err != nil {
		return ErrStoreUnavailable
	}
	if err := s.opts.Credentials.Cancel(context.WithoutCancel(ctx), credential.CancelRequest{
		ID: issued.ID, Purpose: resetPurpose, Target: "unknown",
	}); err != nil {
		s.opts.Logger.Warn("找回未命中路径凭证取消失败", "error", err, "dummy_id", dummyID)
	}
	return nil
}

// revokeCredentials 尽力撤销给定找回请求关联的凭证（幂等；已消费/过期忽略）。
func (s *Service) revokeCredentials(ctx context.Context, requests []ResetRequest) {
	for _, request := range requests {
		if request.CredentialID == "" {
			continue
		}
		if err := s.opts.Credentials.Cancel(context.WithoutCancel(ctx), credential.CancelRequest{
			ID: request.CredentialID, Purpose: resetPurpose, Target: request.UserID,
		}); err != nil {
			s.opts.Logger.Warn("撤销旧找回凭证失败", "error", err)
		}
	}
}

// ValidateResetToken 是找回页面的只读预检查：不消费凭证、不建立会话、不改变任何
// 状态，只确认“此刻用该链接提交是否有机会成功”。为保证预检查与 CompleteReset 的
// 判断一致，这里复用同一组检查：
//   - 请求维度：token secret 摘要、请求状态（pending）与有效期；
//   - 凭证维度：复用 internal/credential 的非消费校验（Peek），覆盖用途/目标绑定、
//     凭证已消费、已撤销与凭证自身过期；
//   - 账户维度：token 发出后账户仍必须处于可找回状态（存在、启用、非 root、有密码）。
//
// 任何一项不满足或底层存储故障都按“默认拒绝”处理。本方法绝不把预检查结果当作
// CompleteReset 的最终授权：最终提交会重新验证并原子消费同一凭证。无效 token
// 计入同一限流器，避免被用于探测。
func (s *Service) ValidateResetToken(ctx context.Context, token string) error {
	ctx = normalizeContext(ctx)
	request, secret, err := s.parseToken(ctx, token)
	if err != nil {
		return err
	}
	if !s.validateLimiter().allow(hashToken(secret), s.now()) {
		return ErrTokenInvalid
	}
	// 请求维度：被成功使用、被新申请替代或被显式取消后状态不再是 pending。
	if err := s.verifyPendingRequest(request, secret); err != nil {
		return err
	}
	// 凭证维度：复用一次性凭证的非消费校验，与最终 VerifyAndConsume 使用同一套
	// 用途/目标绑定与状态判断（已消费、已撤销、过期、内容不匹配都拒绝）。
	if _, err := s.opts.Credentials.Peek(ctx, credential.VerifyRequest{
		Kind: credential.KindToken, ID: request.CredentialID,
		Purpose: resetPurpose, Target: request.UserID, Secret: secret,
	}); err != nil {
		return mapCredentialPeekError(err)
	}
	// 账户维度：token 发出后账户可能被禁用、删除、改为 root 或移除密码。
	return s.checkRecoverableTarget(ctx, request.UserID)
}

// verifyPendingRequest 统一校验找回请求的状态、token secret 摘要与有效期；不消费
// 凭证、不改变状态。摘要比较使用常量时间，避免长度/内容侧信道。
func (s *Service) verifyPendingRequest(request ResetRequest, secret string) error {
	computed := sha256.Sum256([]byte(secret))
	if len(request.TokenSHA256) != len(computed) ||
		subtle.ConstantTimeCompare(request.TokenSHA256, computed[:]) != 1 {
		return ErrTokenInvalid
	}
	if request.State != "pending" {
		return ErrTokenInvalid
	}
	if !s.now().Before(request.ExpiresAt) {
		return ErrTokenExpired
	}
	return nil
}

// checkRecoverableTarget 统一确认 token 对应的账户此刻仍可走找回：账户必须存在且
// 启用、不是 root、仍持有密码。存储故障返回 ErrStoreUnavailable（默认拒绝，绝不
// 把读取失败当作可找回）。
func (s *Service) checkRecoverableTarget(ctx context.Context, userID string) error {
	target, found, err := s.opts.Store.GetResetTarget(ctx, userID)
	if err != nil {
		return ErrStoreUnavailable
	}
	if !found || !target.Active {
		return ErrAccountDisabled
	}
	if target.IsRoot {
		return ErrAccessDenied
	}
	if !target.HasPassword {
		return ErrNoPassword
	}
	return nil
}

// recoveryRejectionReason 把“账户不可找回”错误映射为不影响公开响应的审计原因码。
func recoveryRejectionReason(err error) (string, ErrorCode) {
	switch {
	case errors.Is(err, ErrNoPassword):
		return "no_password", CodeAccessDenied
	case errors.Is(err, ErrAccessDenied):
		return "root_protected", CodeAccessDenied
	default:
		return "account_disabled", CodeUserDisabled
	}
}

// mapCredentialPeekError 把一次性凭证非消费校验的错误映射为找回域错误：存储故障
// 返回 ErrStoreUnavailable（默认拒绝并保留可诊断原因），其余失败统一为
// ErrTokenInvalid，避免外部区分“不存在/已消费/已撤销/内容不符”。
func mapCredentialPeekError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, credential.ErrStoreUnavailable):
		return ErrStoreUnavailable
	default:
		return ErrTokenInvalid
	}
}

// validateLimiter 复用邮箱限流器做 token 预检查限流（同进程有界）。
func (s *Service) validateLimiter() *windowLimiter { return s.emailLimiter }

func hashToken(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return string(sum[:])
}

// CompleteReset 校验并原子消费找回入口后重置密码：不签发任何会话（必须重新登录），
// 不解除 MFA/Passkey，也不为无密码账户添加密码。并发使用同一 token 只有一个成功。
// 成功后向已验证邮箱发送不含密码/凭证的安全告知，并作废该用户其余 pending 入口。
func (s *Service) CompleteReset(ctx context.Context, request CompleteRequest) (ResetResult, error) {
	ctx = normalizeContext(ctx)
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return ResetResult{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if strings.TrimSpace(request.NewPassword) == "" || len(request.NewPassword) > 1024 {
		return ResetResult{}, fmt.Errorf("%w: 新密码长度无效", ErrInvalidRequest)
	}
	resetRequest, secret, err := s.parseToken(ctx, request.Token)
	if err != nil {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
			"password.reset_completed", "invalid_token", string(CodeChallengeInvalid), request.RequestID)
		return ResetResult{}, err
	}
	// 与 ValidateResetToken 使用同一套请求检查（摘要/状态/期限）；预检查结果不能
	// 替代这里对最终授权的重新验证。
	if err := s.verifyPendingRequest(resetRequest, secret); err != nil {
		reason := "token_digest_mismatch"
		switch {
		case errors.Is(err, ErrTokenExpired):
			reason = "expired"
		case resetRequest.State != "pending":
			reason = "not_pending"
		}
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
			"password.reset_completed", reason, string(CodeChallengeInvalid), request.RequestID)
		return ResetResult{}, err
	}
	now := s.now()
	// 重新确认账户在 token 发出后仍可找回：禁用/删除/无密码/root 必须在完成层拒绝。
	if err := s.checkRecoverableTarget(ctx, resetRequest.UserID); err != nil {
		if errors.Is(err, ErrStoreUnavailable) {
			return ResetResult{}, err
		}
		reason, code := recoveryRejectionReason(err)
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
			"password.reset_completed", reason, string(code), request.RequestID)
		return ResetResult{}, err
	}
	// 原子消费：同一 token 并发/重放只有一个请求成功。
	if _, err := s.opts.Credentials.VerifyAndConsume(ctx, credential.VerifyRequest{
		Kind: credential.KindToken, ID: resetRequest.CredentialID, Purpose: resetPurpose,
		Target: resetRequest.UserID, Secret: secret,
	}); err != nil {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
			"password.reset_completed", "consume_failed", string(CodeChallengeInvalid), request.RequestID)
		return ResetResult{}, ErrTokenInvalid
	}
	systemCaller, err := authn.SystemCaller("passwordreset")
	if err != nil {
		return ResetResult{}, ErrOptionsInvalid
	}
	result, err := s.opts.Passwords.ResetPasswordForRecovery(ctx, systemCaller,
		authn.RecoveryResetRequest{
			UserID: resetRequest.UserID, NewPassword: request.NewPassword,
			RequestID: request.RequestID, Reason: outboxReasonReset,
		})
	if err != nil {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
			"password.reset_completed", "password_reset_rejected",
			string(CodeOf(err)), request.RequestID)
		return ResetResult{}, err
	}
	// 成功路径：标记本次请求 consumed 并作废该用户其余 pending 入口（同一事务）。
	otherPending, listErr := s.opts.Store.ListPending(ctx, resetRequest.UserID)
	if listErr != nil {
		return ResetResult{}, ErrStoreUnavailable
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:  audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
			Action: "password.reset_completed", Outcome: audit.OutcomeSuccess,
			Target:    audit.Target{Type: "user", ID: resetRequest.UserID},
			RequestID: validRequestID(request.RequestID),
			Changes: []audit.FieldChange{
				{Field: "security_version_change", After: "password_reset"},
				{Field: "requires_relogin", After: "true"},
			},
		},
		FailureReasonCode:   "password.reset_completed_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, consumeErr := s.opts.Store.ConsumeRequestTx(txCtx, tx, resetRequest.ID, now)
		if consumeErr != nil {
			return consumeErr
		}
		if !ok {
			return ErrTokenInvalid
		}
		if _, cancelErr := s.opts.Store.CancelPendingTx(txCtx, tx, resetRequest.UserID, now); cancelErr != nil {
			return cancelErr
		}
		return nil
	}); err != nil {
		return ResetResult{}, mapCriticalError(err)
	}
	s.revokeCredentials(ctx, otherPending)
	sessionsRevoked, revokeErr := s.opts.Sessions.RevokeAllForUser(ctx, resetRequest.UserID, "password_reset")
	if revokeErr != nil {
		s.opts.Logger.Warn("找回改密后会话撤销失败（安全版本已使旧会话失效）", "error", revokeErr)
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
			"password.reset_completed", "session_revoke_failed", string(CodeDBUnavailable), request.RequestID)
	}
	outboxID, outboxErr := s.appendOutboxWithRetry(ctx, resetRequest.UserID, outboxReasonReset, request.RequestID)
	if outboxErr != nil {
		s.opts.Logger.Warn("找回改密后 OAuth 撤销事件写入失败", "error", outboxErr)
	}
	// 安全告知：投递失败只记录失败审计，不回滚已成功重置；正文不含密码/token。
	s.sendResetNotice(ctx, resetRequest.UserID, request.RequestID, resetRequest.ID)
	return ResetResult{
		UserID: resetRequest.UserID, SecurityVersion: result.SecurityVersion,
		RequiresRelogin: true, SessionsRevoked: sessionsRevoked,
		OutboxEventID: outboxID, ResetAt: result.PasswordChangedAt,
	}, nil
}

// ===== 内部辅助 =====

// appendOutboxWithRetry 是有界重试的 outbox 写入（3 次尝试）；最终失败写失败审计。
func (s *Service) appendOutboxWithRetry(ctx context.Context, userID, reason, requestID string) (string, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		eventID, err := s.appendOutbox(ctx, userID, reason, requestID)
		if err == nil {
			return eventID, nil
		}
		lastErr = err
	}
	s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
		"oauth.revocation_enqueue_failed", "outbox_unavailable", string(CodeAuditWriteFailed), requestID)
	return "", lastErr
}

// invalidatePending 作废用户所有 pending 找回请求与其凭证（主动改密/新请求时调用）。
func (s *Service) invalidatePending(ctx context.Context, userID, requestID, reason string) {
	pending, err := s.opts.Store.ListPending(ctx, userID)
	if err != nil || len(pending) == 0 {
		return
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
			Action:    "password.reset_requests_cancelled",
			Target:    audit.Target{Type: "user", ID: userID},
			RequestID: validRequestID(requestID),
			Changes:   []audit.FieldChange{{Field: "reason", After: reason}},
		},
		FailureReasonCode:   "password.reset_cancel_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		_, cancelErr := s.opts.Store.CancelPendingTx(txCtx, tx, userID, s.now())
		return cancelErr
	}); err != nil {
		s.opts.Logger.Warn("作废旧找回请求失败", "error", err)
		return
	}
	s.revokeCredentials(ctx, pending)
}

// sendResetNotice 在找回重置成功后发送安全告知；失败只记录失败审计，不回滚重置。
// 步骤 197：配置可靠投递时改走 mailer 队列（失败由任务有限重试承担）；nil 时保持
// 直接 Sender 回退（单测/嵌入兼容）。enqueue 成功仅表示“已受理/排队”，不表示送达。
func (s *Service) sendResetNotice(ctx context.Context, userID, requestID, resetID string) {
	email, found, err := s.opts.Store.VerifiedEmail(ctx, userID)
	if err != nil || !found || email == "" {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
			"password.reset_notice_failed", "no_verified_email", string(CodeMailDeliveryFailed), requestID)
		return
	}
	render := mailer.RenderRequest{
		Kind: mailer.KindSecurityNotice,
		Notice: &mailer.SecurityNoticeData{
			Event:      "密码已通过邮件找回被重置",
			OccurredAt: s.now().Format(time.RFC3339),
			AppName:    s.opts.AppName, SupportURL: s.opts.SupportURL,
		},
	}
	if s.opts.Deliveries != nil {
		caller, callerErr := mailer.SystemCaller("passwordreset")
		if callerErr != nil {
			s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
				"password.reset_notice_failed", "delivery_enqueue_failed", string(CodeMailDeliveryFailed), requestID)
			return
		}
		if _, enqueueErr := s.opts.Deliveries.Enqueue(ctx, mailer.EnqueueRequest{
			Caller: caller, IdempotencyKey: "password-reset-notice-" + resetID,
			Kind: mailer.KindSecurityNotice, Recipient: email, Data: render, RequestID: requestID,
		}); enqueueErr != nil {
			s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
				"password.reset_notice_failed", "delivery_enqueue_failed", string(CodeMailDeliveryFailed), requestID)
		}
		return
	}
	content, renderErr := s.opts.Templates.Render(render)
	if renderErr != nil {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
			"password.reset_notice_failed", "template_invalid", string(CodeMailDeliveryFailed), requestID)
		return
	}
	from, fromErr := mailer.ParseAddress(s.opts.FromAddress)
	to, toErr := mailer.ParseAddress(email)
	if fromErr != nil || toErr != nil {
		return
	}
	if err := s.opts.Mailer.Send(ctx, mailer.Message{From: from, To: []mailer.Address{to},
		Subject: content.Subject, TextBody: content.TextBody}); err != nil {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
			"password.reset_notice_failed", "delivery_failed", string(CodeMailDeliveryFailed), requestID)
	}
}

// appendOutbox 在审计事务内写入 OAuth 撤销事件；失败只记录日志（不隐藏已发生改密）。
func (s *Service) appendOutbox(ctx context.Context, userID, reason, requestID string) (string, error) {
	var eventID string
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
			Action:    "oauth.revocation_enqueued",
			Target:    audit.Target{Type: "user", ID: userID},
			RequestID: validRequestID(requestID),
			Changes:   []audit.FieldChange{{Field: "reason", After: reason}},
		},
		FailureReasonCode:   "oauth.revocation_enqueue_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		event, insertErr := s.opts.Store.InsertOutboxTx(txCtx, tx, userID, reason, s.now())
		if insertErr != nil {
			return insertErr
		}
		eventID = event
		return nil
	})
	if err != nil {
		return "", mapCriticalError(err)
	}
	return eventID, nil
}

// parseToken 拆分 resetID.secret 并加载请求；只做格式与存在性校验。
func (s *Service) parseToken(ctx context.Context, token string) (ResetRequest, string, error) {
	if len(token) == 0 || len(token) > 512 {
		return ResetRequest{}, "", ErrTokenInvalid
	}
	resetID, secret, found := strings.Cut(token, ".")
	if !found || len(secret) < 16 || !validResetID(resetID) {
		return ResetRequest{}, "", ErrTokenInvalid
	}
	request, ok, err := s.opts.Store.GetRequest(ctx, resetID)
	if err != nil {
		return ResetRequest{}, "", ErrStoreUnavailable
	}
	if !ok {
		return ResetRequest{}, "", ErrTokenInvalid
	}
	return request, secret, nil
}

func validResetID(value string) bool {
	if len(value) != 4+32 || value[:4] != "prq_" {
		return false
	}
	for index := 4; index < len(value); index++ {
		character := value[index]
		if (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') {
			continue
		}
		return false
	}
	return true
}

// sendResetMail 渲染并投递找回邮件；明文 token 只出现在该邮件正文中。
// 步骤 197：配置可靠投递时改走 mailer 队列（幂等键由 resetID 绑定业务实例）；
// nil 时保持直接 Sender 回退。enqueue 成功只表示已受理，不表示已送达。
func (s *Service) sendResetMail(ctx context.Context, candidate Candidate, resetURL, requestID, resetID string) error {
	render := mailer.RenderRequest{
		Kind: mailer.KindPasswordReset,
		PasswordReset: &mailer.PasswordResetData{
			DisplayName: candidate.Username, ResetURL: resetURL,
			ExpiresIn: formatDuration(s.opts.TokenTTL), AppName: s.opts.AppName,
		},
	}
	if s.opts.Deliveries != nil {
		caller, callerErr := mailer.SystemCaller("passwordreset")
		if callerErr != nil {
			return fmt.Errorf("%w: 无法构造投递身份", ErrMailFailed)
		}
		if _, enqueueErr := s.opts.Deliveries.Enqueue(ctx, mailer.EnqueueRequest{
			Caller: caller, IdempotencyKey: "password-reset-" + resetID,
			Kind: mailer.KindPasswordReset, Recipient: candidate.Email, Data: render, RequestID: requestID,
		}); enqueueErr != nil {
			return fmt.Errorf("%w: 投递入队失败", ErrMailFailed)
		}
		return nil
	}
	content, err := s.opts.Templates.Render(render)
	if err != nil {
		return fmt.Errorf("%w: 模板渲染失败", ErrMailFailed)
	}
	from, fromErr := mailer.ParseAddress(s.opts.FromAddress)
	to, toErr := mailer.ParseAddress(candidate.Email)
	if fromErr != nil || toErr != nil {
		return fmt.Errorf("%w: 地址无效", ErrMailFailed)
	}
	if err := s.opts.Mailer.Send(ctx, mailer.Message{
		From: from, To: []mailer.Address{to},
		Subject: content.Subject, TextBody: content.TextBody,
	}); err != nil {
		return fmt.Errorf("%w: 投递失败", ErrMailFailed)
	}
	return nil
}

func formatDuration(value time.Duration) string {
	minutes := int(value / time.Minute)
	if minutes <= 0 {
		return "数分钟"
	}
	return fmt.Sprintf("%d 分钟", minutes)
}
