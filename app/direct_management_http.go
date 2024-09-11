package app

// 步骤 258：把宿主直接管理门面（256 直接改名 + 255 目标绑定操作证明）桥接到
// internal/serverapp 的管理 JSON API 路由。
//
// 安全边界：
//   - 操作者身份只来自管理 API 已校验的 caller；本桥接以 ctx 中注入的真实管理会话
//     秘密构造 AdminCaller（AdminSession），LocalAdmin/伪造调用者一律拒绝；
//   - 权限、目标/行版本校验、两步验证挑战与证明消费、事务一致提交、审计与告知全部
//     仍由 255/256 门面执行，本文件不复制判定；
//   - 一次性证明只透传给紧随其后的同一改名提交，不缓存、不写日志；
//   - 错误统一投影为 serverapp.DirectManagementError（稳定公开码），未知错误按
//     INTERNAL_ERROR，不透出内部细节。

import (
	"context"
	"errors"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/serverapp"
)

// directManagementHTTPBridge 实现 serverapp.DirectUsernameBridge；runtime 用延迟
// 工厂取得（HTTP 装配先于 Runtime 最终构造完成，请求期 Runtime 已就绪）。
type directManagementHTTPBridge struct {
	runtime func() *Runtime
}

// runtimeOrError 取得当前 Runtime；未就绪时 fail-closed。
func (b directManagementHTTPBridge) runtimeOrError() (*Runtime, error) {
	if b.runtime == nil {
		return nil, serverapp.NewDirectManagementError("INTERNAL_ERROR",
			errors.New("运行时尚未就绪"))
	}
	runtime := b.runtime()
	if runtime == nil {
		return nil, serverapp.NewDirectManagementError("INTERNAL_ERROR",
			errors.New("运行时尚未就绪"))
	}
	return runtime, nil
}

// adminCaller 用 ctx 中注入的真实管理会话秘密构造可信 AdminCaller。
func (b directManagementHTTPBridge) adminCaller(ctx context.Context) (AdminCaller, error) {
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

// mapDirectManagementError 把公开门面错误投影为稳定码桥接错误。
func mapDirectManagementError(err error) error {
	if err == nil {
		return nil
	}
	var public *login.AppError
	if errors.As(err, &public) {
		return serverapp.NewDirectManagementError(string(public.Code()), err)
	}
	return serverapp.NewDirectManagementError(string(login.CodeInternalError), err)
}

// BeginUsernameVerification 实现 bridge：发起目标绑定两步验证挑战。
func (b directManagementHTTPBridge) BeginUsernameVerification(ctx context.Context,
	operatorUserID, targetUserID, newUsername, requestID string) (
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
		Operation: OperationProofUsernameChange, NewUsername: newUsername,
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

// ConfirmUsernameVerification 实现 bridge：密码 + TOTP 完成第二步并返回一次性证明。
func (b directManagementHTTPBridge) ConfirmUsernameVerification(ctx context.Context,
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

// BeginUsernameWebAuthnVerification 实现 bridge：Passkey/安全密钥第二步开始。
func (b directManagementHTTPBridge) BeginUsernameWebAuthnVerification(ctx context.Context,
	operatorUserID, challengeID, requestID string) (serverapp.DirectWebAuthnStart, error) {
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

// ConfirmUsernameWebAuthnVerification 实现 bridge：完成 WebAuthn 第二步。
func (b directManagementHTTPBridge) ConfirmUsernameWebAuthnVerification(ctx context.Context,
	operatorUserID, challengeID, ceremonyID string, response []byte,
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

// CancelUsernameVerification 实现 bridge：取消未完成挑战（不产生执行能力）。
func (b directManagementHTTPBridge) CancelUsernameVerification(ctx context.Context,
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

// ChangeUsername 实现 bridge：用一次性证明提交直接改名。
func (b directManagementHTTPBridge) ChangeUsername(ctx context.Context,
	request serverapp.DirectUsernameChangeRequest) (serverapp.DirectUsernameChangeResult, error) {
	caller, err := b.adminCaller(ctx)
	if err != nil {
		return serverapp.DirectUsernameChangeResult{}, err
	}
	runtime, err := b.runtimeOrError()
	if err != nil {
		return serverapp.DirectUsernameChangeResult{}, err
	}
	updated, err := runtime.DirectUserManagement().ChangeUserUsername(ctx,
		AdminChangeUserUsernameRequest{Caller: caller, TargetUserID: request.TargetUserID,
			NewUsername:        request.NewUsername,
			ExpectedRowVersion: request.ExpectedRowVersion, Reason: request.Reason,
			ProofToken: request.ProofToken, RequestID: request.RequestID})
	if err != nil {
		return serverapp.DirectUsernameChangeResult{}, mapDirectManagementError(err)
	}
	return serverapp.DirectUsernameChangeResult{UserID: updated.UserID,
		Username: updated.Username, RowVersion: updated.RowVersion,
		UpdatedAt: updated.UpdatedAt}, nil
}
