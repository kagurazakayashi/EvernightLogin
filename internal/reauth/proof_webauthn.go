package reauth

// 步骤 255：直接管理操作的 WebAuthn 第二步验证路径。
//
// 目标绑定操作证明要求操作者本次完成两步验证。对于无密码 Passkey 账户（或没有 TOTP
// 但持有 Passkey/安全密钥的管理员），不得强制其先添加密码：本文件提供“WebAuthn
// 第二步断言”路径，经宿主演配的 StrongWebAuthnVerifier 校验真实 Passkey/安全密钥
// 断言（contextID = 本次 reauth 挑战 ID，绑定到具体挑战），达到 strong 后签发一次性
// 批准。密码 + TOTP 的既有路径保持不变。
//
// 安全边界：
//   - 只对已在挑战中绑定会话与意图的直接管理操作开放；普通敏感操作仍走
//     VerifyChallenge（密码，可选 TOTP）；
//   - 挑战状态/归属/期限/尝试次数/会话绑定在开始与完成时都重新核对；
//   - 断言必须由 verifier 给出 UserVerified=true（用户验证），否则不算强认证；
//   - 验证失败按挑战尝试次数计，超过上限后挑战作废；成功仍走 issueApproval 的
//     统一签发与并发单赢家路径。

import (
	"context"
	"fmt"

	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
)

// maxWebAuthnResponseBytes 是 WebAuthn 断言响应的上限（避免把本服务当作大对象通道）。
const maxWebAuthnResponseBytes = 64 * 1024

// BeginWebAuthnChallengeRequest 是开始直接管理证明 WebAuthn 第二步的请求。
type BeginWebAuthnChallengeRequest struct {
	ChallengeID string
	// SessionID 是操作者当前管理会话 ID；必须与挑战绑定值一致。
	SessionID string
	RequestID string
}

// BeginWebAuthnChallenge 为已创建的直接管理挑战开始 WebAuthn 第二步挑战。
func (s *Service) BeginWebAuthnChallenge(ctx context.Context, caller Caller,
	request BeginWebAuthnChallengeRequest) (StrongWebAuthnStart, error) {
	ctx = normalizeContext(ctx)
	if err := caller.actor.Validate(); err != nil {
		return StrongWebAuthnStart{}, ErrAccessDenied
	}
	if !caller.IsUser() {
		return StrongWebAuthnStart{}, ErrAccessDenied
	}
	if !validDatabaseID(request.ChallengeID, "chl_") {
		return StrongWebAuthnStart{}, fmt.Errorf("%w: 挑战标识格式非法", ErrInvalidRequest)
	}
	requestID := validRequestID(request.RequestID)
	record, found, err := s.opts.Store.GetChallenge(ctx, request.ChallengeID)
	if err != nil {
		return StrongWebAuthnStart{}, ErrStoreUnavailable
	}
	if !found || record.UserID != caller.actor.ID {
		return StrongWebAuthnStart{}, ErrChallengeInvalid
	}
	stale, checkErr := s.proofChallengeStale(record, request.SessionID)
	if checkErr != nil {
		return StrongWebAuthnStart{}, checkErr
	}
	if stale {
		return StrongWebAuthnStart{}, ErrChallengeInvalid
	}
	verifier := s.currentStrongWebAuthn()
	if isNil(verifier) {
		return StrongWebAuthnStart{}, fmt.Errorf("%w: 未配置 WebAuthn 强因素验证实现", ErrMFARequired)
	}
	start, beginErr := verifier.BeginStrongWebAuthn(ctx, caller.actor.ID, record.ID, requestID)
	if beginErr != nil {
		s.recordVerifyFailure(ctx, caller, record.ID, "webauthn_begin_failed")
		return StrongWebAuthnStart{}, fmt.Errorf("%w: 无法开始 WebAuthn 第二步", ErrMFARequired)
	}
	return start, nil
}

// FinishWebAuthnChallengeRequest 是完成直接管理证明 WebAuthn 第二步的请求。
type FinishWebAuthnChallengeRequest struct {
	ChallengeID string
	SessionID   string
	CeremonyID  string
	Response    []byte
	RequestID   string
}

// FinishWebAuthnChallenge 校验 WebAuthn 断言并在成功后签发一次性操作批准。
func (s *Service) FinishWebAuthnChallenge(ctx context.Context, caller Caller,
	request FinishWebAuthnChallengeRequest) (ApprovalGrant, error) {
	ctx = normalizeContext(ctx)
	if err := caller.actor.Validate(); err != nil {
		return ApprovalGrant{}, ErrAccessDenied
	}
	if !caller.IsUser() {
		return ApprovalGrant{}, ErrAccessDenied
	}
	if !validDatabaseID(request.ChallengeID, "chl_") || request.CeremonyID == "" ||
		len(request.CeremonyID) > 128 || len(request.Response) == 0 ||
		len(request.Response) > maxWebAuthnResponseBytes {
		return ApprovalGrant{}, fmt.Errorf("%w: WebAuthn 第二步参数非法", ErrInvalidRequest)
	}
	requestID := validRequestID(request.RequestID)
	record, found, err := s.opts.Store.GetChallenge(ctx, request.ChallengeID)
	if err != nil {
		return ApprovalGrant{}, ErrStoreUnavailable
	}
	if !found || record.UserID != caller.actor.ID {
		return ApprovalGrant{}, ErrChallengeInvalid
	}
	stale, checkErr := s.proofChallengeStale(record, request.SessionID)
	if checkErr != nil {
		return ApprovalGrant{}, checkErr
	}
	if stale {
		return ApprovalGrant{}, ErrChallengeInvalid
	}
	verifier := s.currentStrongWebAuthn()
	if isNil(verifier) {
		return ApprovalGrant{}, fmt.Errorf("%w: 未配置 WebAuthn 强因素验证实现", ErrMFARequired)
	}
	result, finishErr := verifier.FinishStrongWebAuthn(ctx, caller.actor.ID, record.ID,
		request.CeremonyID, request.Response, requestID)
	if finishErr != nil || result.UserID != caller.actor.ID || !result.UserVerified {
		attempts, increaseErr := s.opts.Store.IncreaseAttempts(ctx, record.ID, s.now())
		if increaseErr != nil {
			s.opts.Logger.Warn("WebAuthn 第二步失败后递增尝试次数失败", "error", increaseErr)
		}
		if attempts >= record.MaxAttempts {
			s.recordVerifyFailure(ctx, caller, record.ID, "attempts_exceeded")
			return ApprovalGrant{}, ErrAttemptsExceeded
		}
		s.recordVerifyFailure(ctx, caller, record.ID, "invalid_webauthn_factor")
		return ApprovalGrant{}, ErrAuthenticationFailed
	}
	now := s.now()
	completedAt := result.CompletedAt
	if completedAt.IsZero() || completedAt.After(now) {
		completedAt = now
	}
	return s.issueApproval(ctx, caller, record, policy.StrengthStrong, completedAt,
		true, requestID)
}

// proofChallengeStale 复核“可直接管理证明的挑战”仍可用于中途验证：只允许直接管理
// 操作、必须是强认证要求、状态 pending、未过期、尝试次数未耗尽，且会话完全一致。
func (s *Service) proofChallengeStale(record ChallengeRecord, sessionID string) (bool, error) {
	if !isDirectManagementOperation(record.OperationID) {
		return false, fmt.Errorf("%w: 该挑战不支持 WebAuthn 证明路径", ErrInvalidRequest)
	}
	if record.RequiredStrength != policy.StrengthStrong {
		return false, fmt.Errorf("%w: 该挑战不要求强认证", ErrInvalidRequest)
	}
	if record.State != ChallengePending || !s.now().Before(record.ExpiresAt) {
		return true, nil
	}
	if record.Attempts >= record.MaxAttempts {
		return true, nil
	}
	if !validSessionBinding(sessionID) || record.SessionID == "" || record.SessionID != sessionID {
		return false, ErrSessionMismatch
	}
	return false, nil
}
