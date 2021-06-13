package recovery

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// MaxBindingPublicBytes 是新因素绑定开始数据（TOTP URI / WebAuthn publicKey 选项）
// 的有界长度，避免无界输入进入内存或日志。
const MaxBindingPublicBytes = 16 * 1024

// BeginRequest 是“第一步密码认证通过后使用恢复代码替代第二步”的请求。
//
// Result 必须来自 internal/authn 的真实认证结果且仍处于待第二因素受限状态；
// Code 是用户提交的一条恢复代码明文（一次性，不落库、不进审计/日志）。
type BeginRequest struct {
	Result          authn.AuthenticateResult
	Code            string
	ExistingSession string
	RequestID       string
	Client          session.ClientInfo
}

// BeginResult 是恢复代码成功消费的结果：AttemptID 服务端保留、客户端不可见；
// Session 是短时受限恢复会话；CodesRemaining 是旧组剩余未用代码数。
type BeginResult struct {
	AttemptID        string
	Session          session.IssuedSession
	CodesRemaining   int
	AllowedMethods   []FactorMethod
	RequiredStrength Strength
	ExpiresAt        time.Time
}

// Begin 在第一步密码认证通过后校验并原子消费一枚恢复代码，然后签发短时受限恢复
// 会话并创建恢复尝试。
//
// 安全语义：
//   - 只接受待第二因素受限认证结果（恢复代码替代的是第二步，不能替代密码）。
//   - 账户必须 active 且非 root；root 只能走后续受控本地通道。
//   - 代码验证成功后才在审计事务内条件消费并创建尝试：并发重复使用同一代码只有
//     一个成功；事务失败（审计不可用等）整体回滚，代码保持可用且不产生尝试。
//   - 新因素验证成功前不删除/不降级任何旧因素，也不撤销用户已有会话。
func (s *Service) Begin(ctx context.Context, request BeginRequest) (BeginResult, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return BeginResult{}, err
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		s.recordFailure(ctx, anonymousActor(), ActionCodeUsed, "user", request.Result.UserID,
			CodeReqInvalid, "invalid_request")
		return BeginResult{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if err := validateAuthResult(request.Result); err != nil {
		s.recordFailure(ctx, anonymousActor(), ActionCodeUsed, "user", request.Result.UserID,
			CodeOf(err), "invalid_first_step")
		return BeginResult{}, err
	}
	userID := request.Result.UserID
	// 账户维度有界限流：80 位熵下不可爆破，主要用于降噪与防滥用（默认 10 次/10 分钟）。
	if decision := s.beginLimiter.Allow(userID); !decision.Allowed {
		s.recordFailure(ctx, anonymousActor(), ActionCodeUsed, "user", userID,
			CodeRateLimited, "begin_rate_limited")
		return BeginResult{}, ErrRateLimited
	}
	state, err := s.accountState(ctx, userID)
	if err != nil {
		s.recordFailure(ctx, anonymousActor(), ActionCodeUsed, "user", userID, CodeOf(err), "account_not_eligible")
		return BeginResult{}, err
	}
	if state.SecurityVersion != request.Result.SecurityVersion {
		// 安全版本不一致说明第一步认证之后账户发生过安全相关变更：在消费任何代码
		// 之前拒绝，避免无谓烧掉用户的一次性恢复代码。
		s.recordFailure(ctx, anonymousActor(), ActionCodeUsed, "user", userID, CodeAccessDenied, "security_version_changed")
		return BeginResult{}, ErrAccessDenied
	}
	normalized, ok := normalizeCode(request.Code)
	if !ok {
		s.recordFailure(ctx, anonymousActor(), ActionCodeUsed, "user", userID, CodeChallengeInvalid, "malformed_code")
		return BeginResult{}, ErrCodeInvalid
	}
	group, found, err := s.opts.Store.ActiveGroup(ctx, userID)
	if err != nil {
		return BeginResult{}, ErrStoreUnavailable
	}
	if !found {
		s.recordFailure(ctx, anonymousActor(), ActionCodeUsed, "user", userID, CodeChallengeInvalid, "no_active_group")
		return BeginResult{}, ErrNoActiveGroup
	}
	codes, err := s.opts.Store.ListUnusedCodes(ctx, userID)
	if err != nil {
		return BeginResult{}, ErrStoreUnavailable
	}
	matched, ok := s.matchCode(codes, userID, normalized)
	if !ok {
		s.recordFailure(ctx, anonymousActor(), ActionCodeUsed, "user", userID, CodeChallengeInvalid, "code_mismatch")
		return BeginResult{}, ErrCodeInvalid
	}
	// 强度要求必须在消费代码前读取：要求不可用时 fail-closed，不能烧掉用户一枚代码。
	strength, err := s.requiredStrength(ctx, userID)
	if err != nil {
		s.recordFailure(ctx, anonymousActor(), ActionCodeUsed, "user", userID, CodeOf(err), "requirements_unavailable")
		return BeginResult{}, err
	}
	attemptID, err := newDomainID(s.random, attemptIDPrefix)
	if err != nil {
		return BeginResult{}, err
	}
	now := s.clockNow()
	expiresAt := now.Add(s.attemptTTL)
	attempt := Attempt{
		ID: attemptID, UserID: userID, GroupID: group.ID, CodeID: matched.ID,
		Status: AttemptPendingBinding, MaxAttempts: s.maxAttempts,
		ExpiresAt: expiresAt, CreatedAt: now, UpdatedAt: now,
	}
	remaining := 0
	event := audit.Event{
		Actor:     audit.Actor{Type: audit.ActorUser, ID: userID},
		Action:    ActionCodeUsed,
		Target:    audit.Target{Type: "user", ID: userID},
		RequestID: request.RequestID,
		Changes: []audit.FieldChange{
			{Field: "attempt_id", After: attemptID},
			{Field: "group_generation", After: fmt.Sprint(group.Generation)},
			{Field: "expires_at", After: expiresAt.UTC().Format(time.RFC3339)},
		},
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "recovery_code_use_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(s.mapStoreError(err)))
		},
	}
	consumeErr := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		consumed, consumeErr := s.opts.Store.ConsumeCodeTx(txCtx, tx, matched.ID, now)
		if consumeErr != nil {
			return consumeErr
		}
		if !consumed {
			return ErrCodeInvalid
		}
		count, countErr := s.opts.Store.CountUnusedCodesTx(txCtx, tx, group.ID)
		if countErr != nil {
			return countErr
		}
		remaining = count
		if count == 0 {
			// 整组代码用完时把组标记 exhausted（尽力而为；条件不满足说明已被并发
			// 重新生成取代，整体回滚由上层决定）。
			if _, invalidateErr := s.opts.Store.InvalidateGroupTx(txCtx, tx, group.ID, GroupExhausted, now); invalidateErr != nil {
				return invalidateErr
			}
		}
		return s.opts.Store.CreateAttemptTx(txCtx, tx, attempt)
	})
	if consumeErr != nil {
		mapped := s.mapStoreError(consumeErr)
		if errors.Is(mapped, ErrStoreUnavailable) {
			return BeginResult{}, mapped
		}
		// 条件消费失败：并发重复使用只有一方成功；尝试并发进行中时保留代码不被烧掉。
		if errors.Is(consumeErr, ErrAttemptInProgress) {
			s.recordFailure(ctx, anonymousActor(), ActionCodeUsed, "user", userID, CodeConflict, "attempt_in_progress")
			return BeginResult{}, ErrAttemptInProgress
		}
		s.recordFailure(ctx, anonymousActor(), ActionCodeUsed, "user", userID, CodeChallengeInvalid, "code_not_consumed")
		return BeginResult{}, ErrCodeInvalid
	}
	// 代码已消费、尝试已建立；以下签发/绑定失败会尽力把尝试置为 failed（不恢复
	// 已消费的代码，避免把已证明使用过的代码重新放回可用池）。
	issued, err := s.opts.Sessions.IssueRecoverySession(ctx, session.RecoverySessionRequest{
		UserID:          userID,
		SecurityVersion: request.Result.SecurityVersion,
		AttemptID:       attemptID,
		ExistingSession: request.ExistingSession,
		RequestID:       request.RequestID,
		Client:          request.Client,
	})
	if err != nil {
		mapped := s.mapSessionError(err)
		s.failAttempt(ctx, attempt, "session_issue_failed", mapped)
		return BeginResult{}, mapped
	}
	bound, err := s.bindAttemptSession(ctx, attemptID, issued.Session.ID)
	if err != nil || !bound {
		_ = s.opts.Sessions.Logout(ctx, issued.Secret.Reveal())
		s.failAttempt(ctx, attempt, "session_bind_failed", ErrSessionUnavailable)
		if err != nil {
			return BeginResult{}, ErrStoreUnavailable
		}
		return BeginResult{}, ErrSessionUnavailable
	}
	s.logger.Info("恢复代码已使用，进入受限恢复", "user_id", userID, "attempt_id", attemptID)
	s.notify(ctx, Notification{
		Kind: NotificationRecoveryStarted, UserID: userID,
		Username:   s.databaseUsername(ctx, userID),
		Event:      "一枚恢复代码已被使用，账户处于受限恢复状态；完成新安全方式绑定并重新登录后才能恢复完整访问。",
		OccurredAt: now,
	})
	return BeginResult{
		AttemptID:        attemptID,
		Session:          issued,
		CodesRemaining:   remaining,
		AllowedMethods:   allowedMethods(strength),
		RequiredStrength: strength,
		ExpiresAt:        expiresAt,
	}, nil
}

// bindAttemptSession 在审计事务内把恢复会话 ID 条件绑定到尝试（只允许一次）。
func (s *Service) bindAttemptSession(ctx context.Context, attemptID, sessionID string) (bool, error) {
	now := s.clockNow()
	event := audit.Event{
		Actor:  audit.Actor{Type: audit.ActorSystem, ID: "recovery-service"},
		Action: ActionRecoveryStarted,
		Target: audit.Target{Type: "recovery_attempt", ID: attemptID},
	}
	critical := audit.CriticalRequest{Event: event, FailureReasonCode: "recovery_session_bind_failed"}
	bound := false
	err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, bindErr := s.opts.Store.BindSessionTx(txCtx, tx, attemptID, sessionID, now)
		if bindErr != nil {
			return bindErr
		}
		bound = ok
		if !ok {
			return ErrAttemptNotActive
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return bound, nil
}

// AuthorizeRecoverySession 实现 session.RecoverySessionGate：只有恢复代码已原子
// 消费、尝试处于待绑定、未过期且尚未绑定过恢复会话时才授权签发受限恢复会话。
func (s *Service) AuthorizeRecoverySession(ctx context.Context, request session.RecoverySessionRequest) error {
	ctx = normalizeContext(ctx)
	if !validDomainID(request.AttemptID, attemptIDPrefix) || !account.ValidUserID(request.UserID) {
		return ErrAccessDenied
	}
	attempt, found, err := s.opts.Store.GetAttempt(ctx, request.AttemptID)
	if err != nil {
		return ErrStoreUnavailable
	}
	if !found || attempt.UserID != request.UserID {
		return ErrAccessDenied
	}
	if attempt.Status != AttemptPendingBinding || attempt.SessionID != "" {
		return ErrAttemptNotActive
	}
	if !s.clockNow().Before(attempt.ExpiresAt) {
		return ErrAttemptExpired
	}
	return nil
}

// Snapshot 是受限恢复会话可核对的状态（不含代码、摘要或会话秘密）。
type Snapshot struct {
	AttemptID        string
	ExpiresAt        time.Time
	RequiredStrength Strength
	AllowedMethods   []FactorMethod
	PlannedMethod    FactorMethod
	CodesRemaining   int
}

// Snapshot 返回当前受限恢复会话对应的恢复状态，仅允许核对；不会消费代码、不会
// 绑定因素、不会泄露旧组代码或他人信息。
func (s *Service) Snapshot(ctx context.Context, secret string) (Snapshot, error) {
	ctx = normalizeContext(ctx)
	_, attempt, err := s.resolveSession(ctx, secret)
	if err != nil {
		return Snapshot{}, err
	}
	strength, err := s.requiredStrength(ctx, attempt.UserID)
	if err != nil {
		return Snapshot{}, err
	}
	remaining := 0
	if codes, listErr := s.opts.Store.ListUnusedCodes(ctx, attempt.UserID); listErr == nil {
		remaining = len(codes)
	}
	return Snapshot{
		AttemptID:        attempt.ID,
		ExpiresAt:        attempt.ExpiresAt,
		RequiredStrength: strength,
		AllowedMethods:   allowedMethods(strength),
		PlannedMethod:    attempt.PlannedMethod,
		CodesRemaining:   remaining,
	}, nil
}

// BeginRebindRequest 是开始绑定新安全方式的请求。
type BeginRebindRequest struct {
	Method    FactorMethod
	RequestID string
}

// BeginRebind 在受限恢复会话下开始绑定一个满足账户强度要求的新安全方式。
//
// 本方法不删除任何旧因素；它只记录计划并调用宿主真实绑定适配器。要求强认证的
// 账户只允许 Passkey（WebAuthn UV），永远不允许邮件或仅 TOTP 降级。
func (s *Service) BeginRebind(ctx context.Context, secret string, request BeginRebindRequest) (FactorBindStart, error) {
	ctx = normalizeContext(ctx)
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return FactorBindStart{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	_, attempt, err := s.resolveSession(ctx, secret)
	if err != nil {
		return FactorBindStart{}, err
	}
	if !request.Method.Valid() {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: attempt.UserID}, ActionRebindStarted,
			"recovery_attempt", attempt.ID, CodeReqInvalid, "invalid_method")
		return FactorBindStart{}, fmt.Errorf("%w: 新因素方法未定义", ErrInvalidRequest)
	}
	strength, err := s.requiredStrength(ctx, attempt.UserID)
	if err != nil {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: attempt.UserID}, ActionRebindStarted,
			"recovery_attempt", attempt.ID, CodeOf(err), "requirements_unavailable")
		return FactorBindStart{}, err
	}
	if !strength.Allows(request.Method) {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: attempt.UserID}, ActionRebindStarted,
			"recovery_attempt", attempt.ID, CodeMFARebindRequired, "method_not_allowed")
		return FactorBindStart{}, ErrMethodNotAllowed
	}
	if isNilInterface(s.opts.Binder) {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: attempt.UserID}, ActionRebindStarted,
			"recovery_attempt", attempt.ID, CodeMFARebindRequired, "binder_not_configured")
		return FactorBindStart{}, ErrBinderUnavailable
	}
	start, err := s.opts.Binder.BeginRebind(ctx, FactorBindRequest{
		UserID: attempt.UserID, AttemptID: attempt.ID, Method: request.Method, RequestID: request.RequestID,
	})
	if err != nil {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: attempt.UserID}, ActionRebindFailed,
			"recovery_attempt", attempt.ID, CodeChallengeInvalid, "binder_begin_failed")
		return FactorBindStart{}, fmt.Errorf("%w: %v", ErrRebindFailed, err)
	}
	if start.Method != request.Method || start.BindingID == "" || len(start.BindingID) > MaxBindingIDBytes ||
		len(start.PublicData) > MaxBindingPublicBytes {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: attempt.UserID}, ActionRebindFailed,
			"recovery_attempt", attempt.ID, CodeChallengeInvalid, "binder_start_invalid")
		return FactorBindStart{}, ErrRebindFailed
	}
	if !start.ExpiresAt.IsZero() && !s.clockNow().Before(start.ExpiresAt) {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: attempt.UserID}, ActionRebindFailed,
			"recovery_attempt", attempt.ID, CodeChallengeInvalid, "binder_start_expired")
		return FactorBindStart{}, ErrRebindFailed
	}
	now := s.clockNow()
	event := audit.Event{
		Actor:     audit.Actor{Type: audit.ActorUser, ID: attempt.UserID},
		Action:    ActionRebindStarted,
		Target:    audit.Target{Type: "recovery_attempt", ID: attempt.ID},
		RequestID: request.RequestID,
		Changes: []audit.FieldChange{
			{Field: "planned_method", After: string(start.Method)},
			{Field: "planned_binding_id", After: start.BindingID},
			{Field: "required_strength", After: string(strength)},
		},
	}
	critical := audit.CriticalRequest{Event: event, FailureReasonCode: "recovery_rebind_plan_failed"}
	planned := false
	planErr := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, planErr := s.opts.Store.PlanRebindTx(txCtx, tx, attempt.ID, start.Method, start.BindingID, now)
		if planErr != nil {
			return planErr
		}
		planned = ok
		if !ok {
			return ErrAttemptNotActive
		}
		return nil
	})
	if planErr != nil || !planned {
		s.expireIfNeeded(ctx, attempt)
		return FactorBindStart{}, ErrAttemptNotActive
	}
	return start, nil
}

// CompleteRequest 是完成新安全方式真实验证的请求；BindingID 必须与 BeginRebind
// 返回的一致，Response 是验证器/认证器的原始响应。
type CompleteRequest struct {
	BindingID string
	Response  []byte
	RequestID string
}

// CompletionResult 是恢复完成结果：Codes 是新一组恢复代码（只返回一次）；完成后
// 必须重新正常登录（ReloginRequired 恒为 true）。
type CompletionResult struct {
	Codes                []Code
	GroupID              string
	Generation           int64
	SecurityVersion      int64
	SessionsRevoked      int64
	LegacyFactorsRevoked bool
	ReloginRequired      bool
}

// Complete 在受限恢复会话下调用宿主真实因素适配器验证新因素，成功后结束恢复：
// 作废旧代码组、生成新代码组、递增安全版本使恢复前会话失效，并撤销全部会话。
//
// 安全语义：
//   - 新因素未通过真实验证（适配器报错、强度不足、用户验证缺失）时绝不完成恢复；
//     失败次数有上限，用尽后尝试作废并告知。
//   - 完成与旧组作废、新组生成、安全版本递增、成功审计在同一事务提交；事务失败
//     整体回滚，旧代码组仍有效、恢复仍未完成。
//   - 提交后尽力撤销全部会话与旧因素、发送安全告知；这些失败不回滚已完成的恢复
//     （安全版本已递增，旧会话必然失效），但写失败审计。
func (s *Service) Complete(ctx context.Context, secret string, request CompleteRequest) (CompletionResult, error) {
	ctx = normalizeContext(ctx)
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return CompletionResult{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if len(request.BindingID) > MaxBindingIDBytes || len(request.Response) > MaxFactorResponseBytes {
		return CompletionResult{}, fmt.Errorf("%w: 新因素响应超出上限", ErrInvalidRequest)
	}
	_, attempt, err := s.resolveSession(ctx, secret)
	if err != nil {
		return CompletionResult{}, err
	}
	actor := audit.Actor{Type: audit.ActorUser, ID: attempt.UserID}
	if !attempt.PlannedMethod.Valid() || attempt.PlannedBindingID == "" {
		s.recordFailure(ctx, actor, ActionRebindFailed, "recovery_attempt", attempt.ID, CodeMFARebindRequired, "rebind_not_started")
		return CompletionResult{}, ErrRebindNotStarted
	}
	if request.BindingID != attempt.PlannedBindingID {
		s.recordFailure(ctx, actor, ActionRebindFailed, "recovery_attempt", attempt.ID, CodeChallengeInvalid, "binding_id_mismatch")
		return CompletionResult{}, ErrRebindFailed
	}
	strength, err := s.requiredStrength(ctx, attempt.UserID)
	if err != nil {
		s.recordFailure(ctx, actor, ActionRebindFailed, "recovery_attempt", attempt.ID, CodeOf(err), "requirements_unavailable")
		return CompletionResult{}, err
	}
	if isNilInterface(s.opts.Binder) {
		s.recordFailure(ctx, actor, ActionRebindFailed, "recovery_attempt", attempt.ID, CodeMFARebindRequired, "binder_not_configured")
		return CompletionResult{}, ErrBinderUnavailable
	}
	proof, err := s.opts.Binder.VerifyRebind(ctx, FactorVerifyRequest{
		UserID: attempt.UserID, AttemptID: attempt.ID, Method: attempt.PlannedMethod,
		BindingID: attempt.PlannedBindingID, Response: request.Response, RequestID: request.RequestID,
	})
	if err != nil {
		return s.failRebind(ctx, attempt, "proof_failed", fmt.Errorf("%w: %v", ErrRebindFailed, err))
	}
	now := s.clockNow()
	if err := s.validateProof(proof, attempt.PlannedMethod, strength, now); err != nil {
		return s.failRebind(ctx, attempt, "proof_rejected", err)
	}
	oldGroup, found, err := s.opts.Store.Group(ctx, attempt.GroupID)
	if err != nil {
		return CompletionResult{}, ErrStoreUnavailable
	}
	if !found {
		return CompletionResult{}, ErrStoreUnavailable
	}
	newGroupID, err := newDomainID(s.random, groupIDPrefix)
	if err != nil {
		return CompletionResult{}, err
	}
	newGeneration := oldGroup.Generation + 1
	group := Group{
		ID: newGroupID, UserID: attempt.UserID, Generation: newGeneration,
		Status: GroupActive, CodeCount: s.codeCount, CreatedAt: now,
	}
	newCodes, codeRecords, err := s.buildCodes(attempt.UserID, newGroupID, now)
	if err != nil {
		return CompletionResult{}, err
	}
	securityVersion := int64(0)
	event := audit.Event{
		Actor:     actor,
		Action:    ActionRecoveryComplete,
		Target:    audit.Target{Type: "user", ID: attempt.UserID},
		RequestID: request.RequestID,
		Changes: []audit.FieldChange{
			{Field: "attempt_id", After: attempt.ID},
			{Field: "factor_method", After: string(proof.Method)},
			{Field: "factor_ref", After: proof.FactorRef},
			{Field: "required_strength", After: string(strength)},
			{Field: "new_group_generation", After: fmt.Sprint(newGeneration)},
			{Field: "relogin_required", After: "true"},
		},
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "recovery_complete_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(s.mapStoreError(err)))
		},
	}
	completeErr := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		completed, completeErr := s.opts.Store.CompleteAttemptTx(txCtx, tx, attempt.ID, proof, now)
		if completeErr != nil {
			return completeErr
		}
		if !completed {
			return ErrAttemptNotActive
		}
		invalidated, invalidateErr := s.opts.Store.InvalidateGroupTx(txCtx, tx, oldGroup.ID, GroupSuperseded, now)
		if invalidateErr != nil {
			return invalidateErr
		}
		if !invalidated {
			// 旧组已被并发撤销/取代：不能在同一事务里再插入新 active 组（否则可能
			// 出现“旧组已 revoked 但新组生效”的不可解释状态），整体回滚 fail-closed。
			return ErrConcurrentRotation
		}
		if insertErr := s.opts.Store.InsertGroupTx(txCtx, tx, group); insertErr != nil {
			return insertErr
		}
		if insertErr := s.opts.Store.InsertCodesTx(txCtx, tx, codeRecords); insertErr != nil {
			return insertErr
		}
		version, versionErr := s.opts.Store.IncrementSecurityVersionTx(txCtx, tx, attempt.UserID, now)
		if versionErr != nil {
			return versionErr
		}
		securityVersion = version
		return nil
	})
	if completeErr != nil {
		if errors.Is(completeErr, ErrAttemptNotActive) {
			s.expireIfNeeded(ctx, attempt)
			s.recordFailure(ctx, actor, ActionRecoveryFailed, "recovery_attempt", attempt.ID, CodeChallengeInvalid, "attempt_no_longer_pending")
			return CompletionResult{}, ErrAttemptNotActive
		}
		return CompletionResult{}, s.mapStoreError(completeErr)
	}
	// 恢复已完成：以下为提交后的尽力动作，失败不改变“恢复完成、必须重新登录”的事实。
	revoked, revokeErr := s.opts.Sessions.RevokeAllForUser(ctx, attempt.UserID, "recovery_completed")
	if revokeErr != nil {
		s.logger.Warn("恢复完成后撤销会话失败", "user_id", attempt.UserID, "error_category", "session_unavailable")
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "recovery-service"},
			ActionSessionRevoke, "user", attempt.UserID, CodeDBUnavailable, "session_revoke_failed")
	}
	_ = s.opts.Sessions.Logout(ctx, secret)
	legacyRevoked := false
	if !isNilInterface(s.opts.FactorRevoker) {
		revokeErr := s.opts.FactorRevoker.RevokeLegacyFactors(ctx, LegacyFactorRevocation{
			UserID: attempt.UserID, AttemptID: attempt.ID,
			KeepMethod: proof.Method, KeepFactorRef: proof.FactorRef,
		})
		if revokeErr != nil {
			s.logger.Warn("恢复完成后撤销旧因素失败", "user_id", attempt.UserID, "error_category", "factor_revoke_failed")
			s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "recovery-service"},
				ActionFactorRevokeFail, "user", attempt.UserID, CodeInternalError, "factor_revoke_failed")
		} else {
			legacyRevoked = true
		}
	}
	s.logger.Info("恢复流程已完成，要求重新登录",
		"user_id", attempt.UserID, "attempt_id", attempt.ID,
		"factor_method", string(proof.Method), "generation", newGeneration,
		"sessions_revoked", revoked,
	)
	s.notify(ctx, Notification{
		Kind: NotificationRecoveryCompleted, UserID: attempt.UserID,
		Username:   s.databaseUsername(ctx, attempt.UserID),
		Event:      "两步验证恢复已完成：旧恢复代码已作废并生成新的一代码组，其他会话已失效，请使用新配置的安全方式重新登录。",
		OccurredAt: now,
	})
	return CompletionResult{
		Codes:                newCodes,
		GroupID:              newGroupID,
		Generation:           newGeneration,
		SecurityVersion:      securityVersion,
		SessionsRevoked:      revoked,
		LegacyFactorsRevoked: legacyRevoked,
		ReloginRequired:      true,
	}, nil
}

// CancelRequest 是取消恢复流程的请求。
type CancelRequest struct {
	RequestID string
}

// Cancel 取消当前受限恢复会话对应的恢复尝试：只结束尝试并尽力退出恢复会话；在新
// 因素验证成功前不删除/不降级任何旧因素、不生成新组，旧凭证仍按原方式有效。取消后
// 已消费的恢复代码不会恢复（一次性语义），用户可用剩余代码或正常方式重新登录。
func (s *Service) Cancel(ctx context.Context, secret string, request CancelRequest) error {
	ctx = normalizeContext(ctx)
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	_, attempt, err := s.resolveSession(ctx, secret)
	if err != nil {
		return err
	}
	now := s.clockNow()
	event := audit.Event{
		Actor:     audit.Actor{Type: audit.ActorUser, ID: attempt.UserID},
		Action:    ActionRecoveryCancel,
		Target:    audit.Target{Type: "recovery_attempt", ID: attempt.ID},
		RequestID: request.RequestID,
		Changes:   []audit.FieldChange{{Field: "status", Before: string(AttemptPendingBinding), After: string(AttemptCancelled)}},
	}
	critical := audit.CriticalRequest{Event: event, FailureReasonCode: "recovery_cancel_failed"}
	cancelled := false
	cancelErr := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, cancelErr := s.opts.Store.CancelAttemptTx(txCtx, tx, attempt.ID, now)
		if cancelErr != nil {
			return cancelErr
		}
		cancelled = ok
		if !ok {
			return ErrAttemptNotActive
		}
		return nil
	})
	if cancelErr != nil || !cancelled {
		s.expireIfNeeded(ctx, attempt)
		return ErrAttemptNotActive
	}
	if err := s.opts.Sessions.Logout(ctx, secret); err != nil {
		s.logger.Warn("取消恢复后退出恢复会话失败", "user_id", attempt.UserID, "error_category", "session_unavailable")
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "recovery-service"},
			ActionSessionRevoke, "user", attempt.UserID, CodeDBUnavailable, "session_logout_failed")
	}
	s.logger.Info("恢复流程已取消", "user_id", attempt.UserID, "attempt_id", attempt.ID)
	s.notify(ctx, Notification{
		Kind: NotificationRecoveryCancelled, UserID: attempt.UserID,
		Username:   s.databaseUsername(ctx, attempt.UserID),
		Event:      "两步验证恢复流程已取消；原有安全方式与凭证保持不变。",
		OccurredAt: now,
	})
	return nil
}

// resolveSession 校验受限恢复会话并返回其绑定的待绑定尝试。
//
// 安全边界：只接受 KindRestricted + ReasonRecovery 的会话；会话必须与尝试一一绑定
// 且属于同一用户。普通/受限初始化/待第二因素会话一律拒绝并写失败审计。
func (s *Service) resolveSession(ctx context.Context, secret string) (session.Session, Attempt, error) {
	current, err := s.opts.Sessions.Validate(ctx, secret)
	if err != nil {
		s.recordFailure(ctx, anonymousActor(), ActionRecoveryStarted, "session", "unknown",
			CodeOf(s.mapSessionError(err)), "recovery_session_invalid")
		return session.Session{}, Attempt{}, ErrSessionRequired
	}
	if !current.IsRestricted() || current.Reason != session.ReasonRecovery {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: current.UserID},
			ActionRecoveryStarted, "session", current.ID, CodeMFARebindRequired, "not_recovery_session")
		return session.Session{}, Attempt{}, ErrSessionRequired
	}
	attempt, found, err := s.opts.Store.GetAttemptBySession(ctx, current.ID)
	if err != nil {
		return session.Session{}, Attempt{}, ErrStoreUnavailable
	}
	if !found || attempt.UserID != current.UserID {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: current.UserID},
			ActionRecoveryStarted, "session", current.ID, CodeAccessDenied, "attempt_not_bound")
		return session.Session{}, Attempt{}, ErrSessionRequired
	}
	now := s.clockNow()
	if attempt.Status == AttemptPendingBinding && !now.Before(attempt.ExpiresAt) {
		s.expireAttempt(ctx, attempt)
		return session.Session{}, Attempt{}, ErrAttemptExpired
	}
	if attempt.Status != AttemptPendingBinding {
		return session.Session{}, Attempt{}, ErrAttemptNotActive
	}
	return current, attempt, nil
}

// expireIfNeeded 在操作条件失败后按当前时间惰性把过期尝试迁移为 expired。
func (s *Service) expireIfNeeded(ctx context.Context, attempt Attempt) {
	if attempt.Status != AttemptPendingBinding {
		return
	}
	if s.clockNow().Before(attempt.ExpiresAt) {
		return
	}
	s.expireAttempt(ctx, attempt)
}

// expireAttempt 用审计事务把过期尝试迁移为 expired；失败只记录日志（不授予任何
// 访问，后续读取仍会按时间拒绝）。
func (s *Service) expireAttempt(ctx context.Context, attempt Attempt) {
	now := s.clockNow()
	event := audit.Event{
		Actor:  audit.Actor{Type: audit.ActorSystem, ID: "recovery-service"},
		Action: ActionRecoveryExpired,
		Target: audit.Target{Type: "recovery_attempt", ID: attempt.ID},
		Changes: []audit.FieldChange{
			{Field: "status", Before: string(AttemptPendingBinding), After: string(AttemptExpired)},
		},
	}
	critical := audit.CriticalRequest{Event: event, FailureReasonCode: "recovery_expire_failed"}
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		_, err := s.opts.Store.ExpireAttemptTx(txCtx, tx, attempt.ID, now)
		return err
	}); err != nil {
		s.logger.Warn("恢复尝试过期迁移失败", "attempt_id", attempt.ID)
	}
}

// failAttempt 在会话签发/绑定失败时把尝试置为 failed 并写失败审计（尽力而为）。
func (s *Service) failAttempt(ctx context.Context, attempt Attempt, reason string, mapped error) {
	now := s.clockNow()
	s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "recovery-service"},
		ActionRecoveryFailed, "recovery_attempt", attempt.ID, CodeOf(mapped), reason)
	otherAttempt := attempt
	otherAttempt.MaxAttempts = 1
	if _, _, err := s.recordRebindFailureTx(ctx, otherAttempt, now); err != nil {
		s.logger.Warn("恢复尝试失败状态迁移失败", "attempt_id", attempt.ID)
	}
}

// failRebind 记录一次新因素验证失败：条件递增失败次数，用尽时迁移 failed；返回
// 对外稳定错误（尝试用尽 CHALLENGE_INVALID，否则 CHALLENGE_INVALID 亦可诊断）。
func (s *Service) failRebind(ctx context.Context, attempt Attempt, reason string, mapped error) (CompletionResult, error) {
	now := s.clockNow()
	failures, limited, err := s.recordRebindFailureTx(ctx, attempt, now)
	if err != nil {
		return CompletionResult{}, ErrStoreUnavailable
	}
	s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: attempt.UserID},
		ActionRebindFailed, "recovery_attempt", attempt.ID, CodeOf(mapped), reason)
	if limited {
		s.notify(ctx, Notification{
			Kind: NotificationRecoveryFailed, UserID: attempt.UserID,
			Username:   s.databaseUsername(ctx, attempt.UserID),
			Event:      "新安全方式验证失败次数已用尽，本次恢复尝试已作废；请重新使用恢复代码或联系管理员。",
			OccurredAt: now,
		})
		if failures >= attempt.MaxAttempts {
			return CompletionResult{}, ErrAttemptsExceeded
		}
	}
	return CompletionResult{}, mapped
}

// recordRebindFailureTx 在审计事务内条件递增失败次数并可能迁移 failed。
func (s *Service) recordRebindFailureTx(ctx context.Context, attempt Attempt, now time.Time) (int, bool, error) {
	event := audit.Event{
		Actor:   audit.Actor{Type: audit.ActorUser, ID: attempt.UserID},
		Action:  ActionRebindAttempt,
		Target:  audit.Target{Type: "recovery_attempt", ID: attempt.ID},
		Changes: []audit.FieldChange{{Field: "attempt_kind", After: "factor_verify"}},
	}
	critical := audit.CriticalRequest{Event: event, FailureReasonCode: "recovery_rebind_attempt_failed"}
	failures := 0
	limited := false
	err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		count, atLimit, ok, failErr := s.opts.Store.RecordRebindFailureTx(txCtx, tx, attempt.ID, attempt.MaxAttempts, now)
		if failErr != nil {
			return failErr
		}
		failures = count
		limited = atLimit
		if !ok {
			return ErrAttemptNotActive
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrAttemptNotActive) {
			return failures, limited, nil
		}
		return failures, limited, err
	}
	return failures, limited, nil
}

// validateProof 校验适配器返回的新因素证明：方法必须与计划一致、引用有界、验证
// 时间新鲜，并满足账户强度要求（强认证必须是 Passkey + 用户验证 UV）。
func (s *Service) validateProof(proof FactorProof, planned FactorMethod, strength Strength, now time.Time) error {
	if !proof.Valid() || proof.Method != planned {
		return ErrRebindFailed
	}
	if proof.VerifiedAt.After(now.Add(time.Minute)) || proof.VerifiedAt.Before(now.Add(-s.attemptTTL)) {
		return ErrRebindFailed
	}
	if !strength.Allows(proof.Method) {
		return ErrStrengthNotMet
	}
	if strength == StrengthStrong && !proof.UserVerified {
		return ErrStrengthNotMet
	}
	return nil
}

// matchCode 用常量时间比较提交代码的摘要与当前 active 组未使用代码记录。摘要使用
// 行内 key_id 计算（支持密钥轮换后的历史验证），不使用已使用代码。
func (s *Service) matchCode(codes []CodeRecord, userID, normalized string) (CodeRecord, bool) {
	for _, record := range codes {
		if !record.UsedAt.IsZero() {
			continue
		}
		digest, err := codeDigest(s.opts.Keyring, record.KeyID, userID, normalized)
		if err != nil {
			continue
		}
		if matchCode(record.Digest, digest) {
			return record, true
		}
	}
	return CodeRecord{}, false
}

// mapSessionError 把会话领域错误映射为恢复领域错误，不泄露会话存在性细节。
func (s *Service) mapSessionError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, session.ErrInvalidRequest):
		return ErrInvalidRequest
	case errors.Is(err, session.ErrAccountNotEligible):
		return ErrAccessDenied
	case errors.Is(err, session.ErrRecoveryNotAllowed):
		return ErrAccessDenied
	case errors.Is(err, session.ErrAccessDenied):
		return ErrAccessDenied
	case errors.Is(err, session.ErrAuditUnavailable):
		return ErrAuditUnavailable
	case errors.Is(err, session.ErrSessionInvalid):
		return ErrSessionRequired
	default:
		return ErrSessionUnavailable
	}
}
