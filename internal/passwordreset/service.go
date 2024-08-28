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
//
// 步骤 206：只允许账户“当前最近已验证邮箱”签发，并在创建请求的审计事务内重新读取
// 目标，把当次安全版本、已验证邮箱文本与已验证邮箱身份代际（步骤 250）写入绑定；
// 提交后、发送前再复核一次。预读后发生邮箱切换/禁用等变化时安全失败（统一响应、
// 取消已签发凭证、不发送邮件），绝不向已失去资格的渠道签发可用入口。
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
	if eligible {
		// 只允许账户“当前最近已验证邮箱”作为签发渠道：多已验证邮箱的过渡态或正在切换
		// 邮箱时，非当前渠道按不可用统一处理，绝不向已失去资格的渠道签发可用入口。
		current, currentFound, currentErr := s.opts.Store.GetResetTarget(ctx, candidate.UserID)
		if currentErr != nil {
			return BeginResult{}, ErrStoreUnavailable
		}
		eligible = currentFound && current.EmailNormalized == candidate.EmailNormalized
	}
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
	// 事务外只准备与安全无关的脚手架；绑定值与收件人在事务内用 GetResetTargetTx 的
	// 一致性快照决定（见 createBoundResetEntry）。
	recordTemplate := ResetRequest{ID: resetID, CredentialID: issued.ID, TokenSHA256: tokenSha[:]}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:  audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
			Action: "password.reset_requested", Outcome: audit.OutcomeSuccess,
			Target:    audit.Target{Type: "user", ID: candidate.UserID},
			RequestID: validRequestID(request.RequestID),
			Changes: []audit.FieldChange{
				{Field: "recipient", After: candidate.MaskedEmail},
				{Field: "expires_at_ms", After: fmt.Sprint(now.Add(s.opts.TokenTTL).UnixMilli())},
			},
		},
		FailureReasonCode:   "password.reset_request_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	var boundTarget Candidate
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		target, createErr := s.createBoundResetEntry(txCtx, tx, candidate.UserID, normalized,
			recordTemplate, now)
		if createErr != nil {
			return createErr
		}
		boundTarget = target
		return nil
	}); err != nil {
		s.cancelIssuedCredential(ctx, issued.ID, candidate.UserID)
		if errors.Is(err, errResetIssueChannelChanged) || errors.Is(err, errResetIssueTargetUnavailable) {
			// 预读后提交边界前邮箱/账户状态已变化：安全失败，不发送邮件、统一响应。
			s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
				"password.reset_requested", "channel_changed", string(CodeAccessDenied), request.RequestID)
			return BeginResult{}, nil
		}
		return BeginResult{}, mapCriticalError(err)
	}
	// 提交后、发送前复核绑定：极端调度下邮箱切换/安全变更落在此窄窗口时不再发送。
	// 即使已经发出，旧地址上的链接也会在完成时因绑定不符被拒绝（不产生可用入口）。
	if !s.bindingStillCurrent(ctx, boundTarget) {
		s.cancelIssuedCredential(ctx, issued.ID, candidate.UserID)
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
			"password.reset_requested", "channel_changed", string(CodeAccessDenied), request.RequestID)
		return BeginResult{}, nil
	}
	token := resetID + "." + secret
	resetURL := s.opts.ResetURLBase + "?token=" + url.QueryEscape(token)
	if err := s.sendResetMail(ctx, boundTarget, resetURL, request.RequestID, resetID); err != nil {
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

// ===== 找回入口的安全代际/邮箱身份绑定（步骤 206） =====

// 签发事务内的内部控制流：目标在提交边界已不可用，或请求标识对应的已验证邮箱已不是
// 账户当前最近已验证邮箱。两者都包装 ErrAccessDenied，使关键审计的失败码保持
// ACCESS_DENIED；调用方按各自公开语义安全失败（公开入口统一响应、客服通道显式错误）。
var (
	errResetIssueTargetUnavailable = fmt.Errorf("%w: 找回签发目标在提交边界不可用", ErrAccessDenied)
	errResetIssueChannelChanged    = fmt.Errorf("%w: 找回签发渠道在提交边界已变化", ErrAccessDenied)
)

// createBoundResetEntry 在签发事务内完成“复核目标与绑定 → 作废旧 pending 及凭证 →
// 写入带安全代际/已验证邮箱文本/已验证邮箱身份代际的新请求”。它返回事务内读取的绑定
// 快照（收件人/版本/代际），使收件人与绑定值来自同一一致性边界；任何失败由调用方回滚
// 并取消已签发凭证。
func (s *Service) createBoundResetEntry(txCtx context.Context, tx audit.Tx, userID,
	expectedEmailNormalized string, template ResetRequest, now time.Time) (Candidate, error) {
	target, found, err := s.opts.Store.GetResetTargetTx(txCtx, tx, userID)
	if err != nil {
		return Candidate{}, err
	}
	if !found || !target.Active || target.IsRoot || !target.HasPassword ||
		target.EmailNormalized == "" {
		return Candidate{}, errResetIssueTargetUnavailable
	}
	if expectedEmailNormalized != "" && target.EmailNormalized != expectedEmailNormalized {
		return Candidate{}, errResetIssueChannelChanged
	}
	oldPending, err := s.opts.Store.ListPendingTx(txCtx, tx, userID)
	if err != nil {
		return Candidate{}, err
	}
	if _, err := s.opts.Store.CancelPendingTx(txCtx, tx, userID, now); err != nil {
		return Candidate{}, err
	}
	for _, old := range oldPending {
		if old.CredentialID == "" {
			continue
		}
		// 旧入口凭证在同一事务内撤销；已消费/已撤销/过期返回 false（幂等忽略）。
		if _, err := s.opts.Credentials.CancelTx(txCtx, tx, credential.CancelRequest{
			ID: old.CredentialID, Purpose: resetPurpose, Target: userID,
		}); err != nil {
			return Candidate{}, err
		}
	}
	record := template
	record.UserID = target.UserID
	record.MaskedEmail = target.MaskedEmail
	record.State = "pending"
	record.CreatedAt = now
	record.ExpiresAt = now.Add(s.opts.TokenTTL)
	record.SecurityVersion = target.SecurityVersion
	record.BoundEmailNormalized = target.EmailNormalized
	record.BoundEmailIdentityVersion = target.EmailIdentityVersion
	record.Bound = true
	if err := s.opts.Store.CreateRequestTx(txCtx, tx, record); err != nil {
		return Candidate{}, err
	}
	return target, nil
}

// bindingStillCurrent 在签发提交后、发送前复核绑定仍有效（安全版本、已验证邮箱文本
// 与邮箱身份代际均未变化；步骤 250 起代际也会在 A→B→A 往返后失效）。
// 存储故障按“不发送”处理（默认拒绝）；即使极端调度下已经发出，旧链接也会在完成时
// 因绑定不符被拒绝，不产生可用入口。
func (s *Service) bindingStillCurrent(ctx context.Context, bound Candidate) bool {
	latest, found, err := s.opts.Store.GetResetTarget(ctx, bound.UserID)
	if err != nil || !found {
		return false
	}
	if !latest.Active || latest.IsRoot || !latest.HasPassword {
		return false
	}
	return latest.SecurityVersion == bound.SecurityVersion &&
		latest.EmailNormalized == bound.EmailNormalized &&
		latest.EmailIdentityVersion == bound.EmailIdentityVersion
}

// cancelIssuedCredential 取消已签发但未交付/未持久化的凭证（事务回滚或渠道变化时
// 尽力清理；失败只记录日志，凭证会自行过期）。
func (s *Service) cancelIssuedCredential(ctx context.Context, credentialID, userID string) {
	if credentialID == "" {
		return
	}
	if err := s.opts.Credentials.Cancel(context.WithoutCancel(ctx), credential.CancelRequest{
		ID: credentialID, Purpose: resetPurpose, Target: userID,
	}); err != nil {
		s.opts.Logger.Warn("取消未交付找回凭证失败", "error", err)
	}
}

// verifyRequestBinding 核对签发时的安全代际、已验证邮箱文本与已验证邮箱身份代际是否
// 仍是账户当前值。未绑定（迁移前旧行，或 0051 时代缺少身份代际的行）或任一不一致一律
// 返回 ErrTokenInvalid：这是确定性失效——旧链接在新安全代际/新邮箱身份下永不可用，
// 不是可重试的并发冲突。邮箱 A→B→A 往返时文本复原但代际已前进，因此不会复活旧授权。
func verifyRequestBinding(target Candidate, request ResetRequest) error {
	if !request.Bound {
		return ErrTokenInvalid
	}
	if target.SecurityVersion != request.SecurityVersion ||
		target.EmailNormalized != request.BoundEmailNormalized ||
		target.EmailIdentityVersion != request.BoundEmailIdentityVersion {
		return ErrTokenInvalid
	}
	return nil
}

// checkRecoverableRequest 统一确认请求对应的账户此刻仍可找回，并核对绑定。存储故障
// 返回 ErrStoreUnavailable（默认拒绝）。
func (s *Service) checkRecoverableRequest(ctx context.Context, request ResetRequest) error {
	target, found, err := s.opts.Store.GetResetTarget(ctx, request.UserID)
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
	return verifyRequestBinding(target, request)
}

// checkRecoverableRequestTx 在审计事务内复核账户可找回性与请求绑定；用于完成的提交
// 边界（与邮箱切换/改密/禁用等安全变更在 SQLite 写锁下串行）。
func (s *Service) checkRecoverableRequestTx(ctx context.Context, tx audit.Tx,
	request ResetRequest) error {
	target, found, err := s.opts.Store.GetResetTargetTx(ctx, tx, request.UserID)
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
	return verifyRequestBinding(target, request)
}

// ValidateResetToken 是找回页面的只读预检查：不消费凭证、不建立会话、不改变任何
// 状态，只确认“此刻用该链接提交是否有机会成功”。为保证预检查与 CompleteReset 的
// 判断一致，这里复用同一组检查：
//   - 请求维度：token secret 摘要、请求状态（pending）与有效期；
//   - 凭证维度：复用 internal/credential 的非消费校验（Peek），覆盖用途/目标绑定、
//     凭证已消费、已撤销与凭证自身过期；
//   - 账户维度：token 发出后账户仍必须处于可找回状态（存在、启用、非 root、有密码）；
//   - 绑定维度：签发时的安全代际（users.security_version）、最近已验证邮箱文本与
//     已验证邮箱身份代际（users.email_identity_version）必须仍是账户当前值，否则旧
//     链接确定性失效（改密/MFA 变更/禁用/邮箱切换后不再可用；A→B→A 往返换绑后
//     文本虽复原、代际已前进，旧链接同样永久失效）。
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
	// 账户维度：token 发出后账户可能被禁用、删除、改为 root 或移除密码；同时核对
	// 签发时的安全代际与已验证邮箱身份绑定（旧链接在新代际/新邮箱下失效）。
	return s.checkRecoverableRequest(ctx, request)
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

// CompleteReset 在同一数据库事务内完成“一次性凭证条件消费 + 请求终态 + 其他入口作废
// 及其凭证撤销 + 密码/历史/安全版本写入 + OAuth 撤销 outbox + 关键成功审计”，提交后
// 只做会话撤销与安全告知（网络/邮件不在事务内）。不签发任何会话，不解除 MFA/Passkey，
// 也不为无密码账户添加密码；并发使用同一 token 只有一个成功。
//
// 两阶段设计（步骤 205）：
//   - 事务外：请求/凭证/秘密与账户可找回性校验，以及密码策略、历史复用与 Argon2
//     派生（慢操作不入事务）。这些失败都不消费凭证，令牌仍可重试。
//   - 事务内：重新校验并条件消费凭证、复核账户与凭证版本后写入密码，作废其余
//     pending 入口及其凭证，写 OAuth 撤销 outbox；任一步失败整体回滚，凭证不会被
//     消费（这是事务未提交，而不是“失败后恢复令牌”），可安全重试。
//
// 预检查（ValidateResetToken）与这里各自重新验证，前者不构成最终授权。
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
	// 事务外非消费校验：凭证绑定/状态/秘密（Peek 不消费）与账户可找回性。
	if _, err := s.opts.Credentials.Peek(ctx, credential.VerifyRequest{
		Kind: credential.KindToken, ID: resetRequest.CredentialID, Purpose: resetPurpose,
		Target: resetRequest.UserID, Secret: secret,
	}); err != nil {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
			"password.reset_completed", "consume_failed", string(CodeChallengeInvalid), request.RequestID)
		return ResetResult{}, mapCredentialPeekError(err)
	}
	// 重新确认账户在 token 发出后仍可找回，并核对签发时的安全代际与邮箱身份绑定：
	// 改密/MFA 变更/禁用/邮箱切换后旧链接确定性失效（不是可重试冲突）。
	if err := s.checkRecoverableRequest(ctx, resetRequest); err != nil {
		if errors.Is(err, ErrStoreUnavailable) {
			return ResetResult{}, err
		}
		if errors.Is(err, ErrTokenInvalid) {
			s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
				"password.reset_completed", "binding_stale", string(CodeChallengeInvalid), request.RequestID)
			return ResetResult{}, ErrTokenInvalid
		}
		reason, code := recoveryRejectionReason(err)
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
			"password.reset_completed", reason, string(code), request.RequestID)
		return ResetResult{}, err
	}
	// 原子提交能力是完成路径的硬要求：缺失即 fail-closed，绝不退化为
	// “先消费凭证、后改密”的非原子路径。
	committer, ok := s.opts.Passwords.(RecoveryCommitter)
	if !ok {
		return ResetResult{}, fmt.Errorf("%w: 密码服务不支持找回改密原子提交", ErrOptionsInvalid)
	}
	systemCaller, err := authn.SystemCaller("passwordreset")
	if err != nil {
		return ResetResult{}, ErrOptionsInvalid
	}
	// 事务外昂贵准备：弱密码/历史复用/哈希资源忙在这里失败，凭证尚未消费。
	prepared, err := committer.PrepareRecoveryReset(ctx, systemCaller, authn.RecoveryResetRequest{
		UserID: resetRequest.UserID, NewPassword: request.NewPassword,
		RequestID: request.RequestID, Reason: outboxReasonReset,
	})
	if err != nil {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
			"password.reset_completed", "password_reset_rejected",
			string(CodeOf(err)), request.RequestID)
		return ResetResult{}, err
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:  audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
			Action: "password.reset_completed", Outcome: audit.OutcomeSuccess,
			Target:    audit.Target{Type: "user", ID: resetRequest.UserID},
			RequestID: validRequestID(request.RequestID),
			Changes: append([]audit.FieldChange{
				{Field: "requires_relogin", After: "true"},
			}, prepared.AuditChanges()...),
		},
		FailureReasonCode:   "password.reset_completed_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	var applied authn.SetPasswordResult
	var outboxID string
	err = s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		// (0) 事务内复核账户可找回性与签发绑定：与密码/邮箱/账户状态的安全变更在
		// 同一写锁下串行；任一不一致整体回滚，凭证不被消费。
		if bindingErr := s.checkRecoverableRequestTx(txCtx, tx, resetRequest); bindingErr != nil {
			return bindingErr
		}
		// (a) 事务内重新校验并条件消费一次性凭证：并发/重放只有一个赢家。
		if _, consumeErr := s.opts.Credentials.VerifyAndConsumeTx(txCtx, tx, credential.VerifyRequest{
			Kind: credential.KindToken, ID: resetRequest.CredentialID, Purpose: resetPurpose,
			Target: resetRequest.UserID, Secret: secret,
		}); consumeErr != nil {
			return mapCredentialTransactionError(consumeErr)
		}
		// (b) 请求终态：条件 pending→consumed；失败说明已被并发使用或取消。
		consumedRequest, consumeErr := s.opts.Store.ConsumeRequestTx(txCtx, tx, resetRequest.ID, now)
		if consumeErr != nil {
			return consumeErr
		}
		if !consumedRequest {
			return ErrTokenInvalid
		}
		// (c) 其余 pending 入口作废，并在同一事务内撤销其一次性凭证。
		others, listErr := s.opts.Store.ListPendingTx(txCtx, tx, resetRequest.UserID)
		if listErr != nil {
			return listErr
		}
		if _, cancelErr := s.opts.Store.CancelPendingTx(txCtx, tx, resetRequest.UserID, now); cancelErr != nil {
			return cancelErr
		}
		for _, other := range others {
			if other.CredentialID == "" {
				continue
			}
			if _, revokeErr := s.opts.Credentials.CancelTx(txCtx, tx, credential.CancelRequest{
				ID: other.CredentialID, Purpose: resetPurpose, Target: resetRequest.UserID,
			}); revokeErr != nil {
				return revokeErr
			}
		}
		// (d) 事务内复核账户/凭证版本后写入密码、历史与安全版本。
		appliedResult, applyErr := committer.ApplyRecoveryResetTx(txCtx, systemCaller, prepared, tx)
		if applyErr != nil {
			return mapRecoveryApplyError(applyErr)
		}
		applied = appliedResult
		// (e) OAuth 撤销可靠事件与关键成功审计同一事务提交。
		eventID, outboxErr := s.opts.Store.InsertOutboxTx(txCtx, tx, resetRequest.UserID, outboxReasonReset, now)
		if outboxErr != nil {
			return outboxErr
		}
		outboxID = eventID
		return nil
	})
	if err != nil {
		return ResetResult{}, mapCriticalError(err)
	}
	// 提交后：安全版本已递增，旧会话在下次校验时失效；撤销失败不回滚已成功的改密。
	sessionsRevoked, revokeErr := s.opts.Sessions.RevokeAllForUser(ctx, resetRequest.UserID, "password_reset")
	if revokeErr != nil {
		s.opts.Logger.Warn("找回改密后会话撤销失败（安全版本已使旧会话失效）", "error", revokeErr)
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
			"password.reset_completed", "session_revoke_failed", string(CodeDBUnavailable), request.RequestID)
	}
	// 安全告知：提交后投递，失败只记录失败审计；正文不含密码/token。
	s.sendResetNotice(ctx, resetRequest.UserID, request.RequestID, resetRequest.ID)
	return ResetResult{
		UserID: resetRequest.UserID, SecurityVersion: applied.SecurityVersion,
		RequiresRelogin: true, SessionsRevoked: sessionsRevoked,
		OutboxEventID: outboxID, ResetAt: applied.PasswordChangedAt,
	}, nil
}

// mapCredentialTransactionError 把事务内一次性凭证消费失败映射为找回域错误：存储/
// 能力故障返回 ErrStoreUnavailable 或 ErrOptionsInvalid（默认拒绝），其余一律
// ErrTokenInvalid，避免外部区分“不存在/已消费/已撤销/内容不符”。
func mapCredentialTransactionError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, credential.ErrOptionsInvalid):
		return ErrOptionsInvalid
	case errors.Is(err, credential.ErrStoreUnavailable):
		return ErrStoreUnavailable
	default:
		return ErrTokenInvalid
	}
}

// mapRecoveryApplyError 把事务内密码写入/并发复核失败映射为找回域错误；存储/审计
// 故障默认拒绝且可重试，并发版本冲突映射 CONFLICT（令牌未消费）。
func mapRecoveryApplyError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, authn.ErrRecoveryStateConflict):
		return ErrConflict
	case errors.Is(err, authn.ErrUserNotFound), errors.Is(err, authn.ErrAccessDenied):
		return ErrAccessDenied
	case errors.Is(err, authn.ErrStoreUnavailable), errors.Is(err, authn.ErrAuditUnavailable):
		return ErrStoreUnavailable
	default:
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
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
