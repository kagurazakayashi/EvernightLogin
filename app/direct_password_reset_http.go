package app

// 步骤 259：把宿主直接重置密码门面（257 直接重置 + 255 目标绑定操作证明）桥接到
// internal/serverapp 的管理 JSON API 路由。
//
// 安全边界与 258 直接改名一致：
//   - 操作者身份只来自管理 API 已校验的 caller；本桥接以 ctx 中注入的真实管理会话
//     秘密构造 AdminCaller（AdminSession），LocalAdmin/伪造调用者一律拒绝；
//   - 权限、目标状态/无密码目标拒绝、密码策略/历史复用/哈希、证明核对与消费、
//     事务一致提交（旧找回失效/OAuth 撤销 outbox/关键审计）、会话撤销与告知全部仍由
//     257 门面执行，本文件不复制判定；
//   - 新口令只用于门面策略/哈希与证明密封意图，不缓存在桥接、不写日志/响应；
//   - 一次性证明只透传给紧随其后的同一重置提交（绑定目标+新口令），不落日志。

import (
	"context"
	"errors"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/serverapp"
)

// directPasswordResetHTTPBridge 实现 serverapp.DirectPasswordResetBridge；runtime 用
// 延迟工厂取得（HTTP 装配先于 Runtime 最终构造完成，请求期 Runtime 已就绪）。
type directPasswordResetHTTPBridge struct {
	runtime func() *Runtime
}

// runtimeOrError 取得当前 Runtime；未就绪时 fail-closed。
func (b directPasswordResetHTTPBridge) runtimeOrError() (*Runtime, error) {
	if b.runtime == nil || b.runtime() == nil {
		return nil, serverapp.NewDirectManagementError("INTERNAL_ERROR",
			errors.New("运行时尚未就绪"))
	}
	return b.runtime(), nil
}

// adminCaller 用 ctx 中注入的真实管理会话秘密构造可信 AdminCaller。
func (b directPasswordResetHTTPBridge) adminCaller(ctx context.Context) (AdminCaller, error) {
	secret := serverapp.ManagementSessionSecret(ctx)
	if secret == "" {
		return AdminCaller{}, serverapp.NewDirectManagementError("ACCESS_DENIED",
			errors.New("缺少真实管理会话"))
	}
	runtime, err := b.runtimeOrError()
	if err != nil {
		return AdminCaller{}, err
	}
	return runtime.AdminSession([]byte(secret)), nil
}

// BeginPasswordResetVerification 发起目标绑定两步验证挑战（绑定新口令密封意图）。
func (b directPasswordResetHTTPBridge) BeginPasswordResetVerification(ctx context.Context,
	operatorUserID, targetUserID, newPassword, requestID string) (
	serverapp.DirectProofChallenge, error) {
	caller, err := b.adminCaller(ctx)
	if err != nil {
		return serverapp.DirectProofChallenge{}, err
	}
	runtime, err := b.runtimeOrError()
	if err != nil {
		return serverapp.DirectProofChallenge{}, err
	}
	challenge, err := runtime.OperationProof().Begin(ctx, OperationProofBeginRequest{
		Caller: caller, TargetUserID: targetUserID,
		Operation: OperationProofPasswordReset, NewPassword: newPassword,
		RequestID: requestID})
	if err != nil {
		return serverapp.DirectProofChallenge{}, mapDirectManagementError(err)
	}
	return serverapp.DirectProofChallenge{ChallengeID: challenge.ChallengeID,
		Operation: string(challenge.Operation), TargetUserID: challenge.TargetUserID,
		RequiredStrength: challenge.RequiredStrength, ExpiresAt: challenge.ExpiresAt,
		MaxAttempts:       challenge.MaxAttempts,
		WebAuthnAvailable: challenge.WebAuthnAvailable}, nil
}

// ConfirmPasswordResetVerification 完成密码+TOTP 两步验证并返回一次性证明。
func (b directPasswordResetHTTPBridge) ConfirmPasswordResetVerification(ctx context.Context,
	operatorUserID, challengeID, password, totpCode, requestID string) (
	serverapp.DirectProofGrant, error) {
	caller, err := b.adminCaller(ctx)
	if err != nil {
		return serverapp.DirectProofGrant{}, err
	}
	runtime, err := b.runtimeOrError()
	if err != nil {
		return serverapp.DirectProofGrant{}, err
	}
	grant, err := runtime.OperationProof().Confirm(ctx, OperationProofConfirmRequest{
		Caller: caller, ChallengeID: challengeID, Password: password,
		TOTPCode: totpCode, RequestID: requestID})
	if err != nil {
		return serverapp.DirectProofGrant{}, mapDirectManagementError(err)
	}
	return serverapp.DirectProofGrant{ProofToken: grant.ProofToken,
		ExpiresAt: grant.ExpiresAt, Operation: string(grant.Operation),
		TargetUserID: grant.TargetUserID, GrantedStrength: grant.GrantedStrength}, nil
}

// BeginPasswordResetWebAuthnVerification 开始 Passkey/安全密钥第二步。
func (b directPasswordResetHTTPBridge) BeginPasswordResetWebAuthnVerification(
	ctx context.Context, operatorUserID, challengeID, requestID string) (
	serverapp.DirectWebAuthnStart, error) {
	caller, err := b.adminCaller(ctx)
	if err != nil {
		return serverapp.DirectWebAuthnStart{}, err
	}
	runtime, err := b.runtimeOrError()
	if err != nil {
		return serverapp.DirectWebAuthnStart{}, err
	}
	start, err := runtime.OperationProof().BeginWebAuthn(ctx,
		OperationProofWebAuthnBeginRequest{Caller: caller, ChallengeID: challengeID,
			RequestID: requestID})
	if err != nil {
		return serverapp.DirectWebAuthnStart{}, mapDirectManagementError(err)
	}
	return serverapp.DirectWebAuthnStart{ChallengeID: start.ChallengeID,
		CeremonyID: start.CeremonyID, PublicKey: start.PublicKey, RPID: start.RPID,
		ExpiresAt: start.ExpiresAt}, nil
}

// ConfirmPasswordResetWebAuthnVerification 完成 WebAuthn 第二步。
func (b directPasswordResetHTTPBridge) ConfirmPasswordResetWebAuthnVerification(
	ctx context.Context, operatorUserID, challengeID, ceremonyID string, response []byte,
	requestID string) (serverapp.DirectProofGrant, error) {
	caller, err := b.adminCaller(ctx)
	if err != nil {
		return serverapp.DirectProofGrant{}, err
	}
	runtime, err := b.runtimeOrError()
	if err != nil {
		return serverapp.DirectProofGrant{}, err
	}
	grant, err := runtime.OperationProof().ConfirmWebAuthn(ctx,
		OperationProofWebAuthnConfirmRequest{Caller: caller, ChallengeID: challengeID,
			CeremonyID: ceremonyID, Response: response, RequestID: requestID})
	if err != nil {
		return serverapp.DirectProofGrant{}, mapDirectManagementError(err)
	}
	return serverapp.DirectProofGrant{ProofToken: grant.ProofToken,
		ExpiresAt: grant.ExpiresAt, Operation: string(grant.Operation),
		TargetUserID: grant.TargetUserID, GrantedStrength: grant.GrantedStrength}, nil
}

// CancelPasswordResetVerification 取消未完成挑战（不产生执行能力）。
func (b directPasswordResetHTTPBridge) CancelPasswordResetVerification(ctx context.Context,
	operatorUserID, challengeID, requestID string) error {
	caller, err := b.adminCaller(ctx)
	if err != nil {
		return err
	}
	runtime, err := b.runtimeOrError()
	if err != nil {
		return err
	}
	if err := runtime.OperationProof().Cancel(ctx, OperationProofCancelRequest{
		Caller: caller, ChallengeID: challengeID, RequestID: requestID}); err != nil {
		return mapDirectManagementError(err)
	}
	return nil
}

// ResetPassword 用一次性证明提交直接重置密码。
func (b directPasswordResetHTTPBridge) ResetPassword(ctx context.Context,
	request serverapp.DirectPasswordResetRequest) (serverapp.DirectPasswordResetResult, error) {
	caller, err := b.adminCaller(ctx)
	if err != nil {
		return serverapp.DirectPasswordResetResult{}, err
	}
	runtime, err := b.runtimeOrError()
	if err != nil {
		return serverapp.DirectPasswordResetResult{}, err
	}
	result, err := runtime.DirectPasswordManagement().ResetUserPassword(ctx,
		AdminResetUserPasswordRequest{Caller: caller, TargetUserID: request.TargetUserID,
			NewPassword: request.NewPassword, Reason: request.Reason,
			ProofToken: request.ProofToken, RequestID: request.RequestID})
	if err != nil {
		return serverapp.DirectPasswordResetResult{}, mapDirectManagementError(err)
	}
	return serverapp.DirectPasswordResetResult{UserID: result.UserID,
		SecurityVersion:   result.SecurityVersion,
		PasswordChangedAt: result.PasswordChangedAt, MustChange: result.MustChange,
		SessionsRevoked:            result.SessionsRevoked,
		OldResetRequestsCancelled:  result.OldResetRequestsCancelled,
		OldResetCredentialsRevoked: result.OldResetCredentialsRevoked,
		OutboxEventID:              result.OutboxEventID}, nil
}

// 编译期确认桥接满足 serverapp 契约（接入 runtime 装配后由编译器再次验证）。
var _ serverapp.DirectPasswordResetBridge = (*directPasswordResetHTTPBridge)(nil)

// 编译期确认公开错误码依赖仍被使用。
var _ = login.CodeInternalError
