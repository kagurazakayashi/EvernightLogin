package serverapp

// 步骤 259：管理页直接重置密码桥接的 serverapp 侧实现。
//
// 页面处理器在处理器代码内取得真实管理会话秘密并作为参数传入；本包装把秘密放入
// context 交给宿主桥接（app 侧）构造 AdminSession，再调用根包 257 门面。秘密/证明/
// 新口令不会进入页面数据、模板、响应或日志。能力查询只用于按钮显示，真正提交仍由
// 宿主门面重新授权与校验。

import (
	"context"
	"errors"

	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	"github.com/kagurazakayashi/EvernightLogin/internal/uiadminadapter"
	ui "github.com/kagurazakayashi/EvernightLogin/ui"
)

// pageDirectPasswordResetBridge 实现 uiadminadapter.DirectPasswordResetBridge。
type pageDirectPasswordResetBridge struct {
	bridge  DirectPasswordResetBridge
	checker interface {
		Check(ctx context.Context, caller authz.Caller, request authz.CheckRequest) (authz.CheckResult, error)
	}
}

// newPageDirectPasswordResetBridge 构造页面桥接；缺依赖时返回 nil（页面 fail-closed）。
func newPageDirectPasswordResetBridge(bridge DirectPasswordResetBridge,
	managed *ManagedServices) uiadminadapter.DirectPasswordResetBridge {
	if bridge == nil || managed == nil || managed.Checker == nil {
		return nil
	}
	return &pageDirectPasswordResetBridge{bridge: bridge, checker: managed.Checker}
}

// directPasswordResetBridgeError 把宿主桥接错误投影为页面稳定错误码。
func directPasswordResetBridgeError(err error) error {
	if err == nil {
		return nil
	}
	var typed *DirectManagementError
	if errors.As(err, &typed) && typed.Code != "" {
		return &uiadminadapter.DirectPasswordResetError{Code: typed.Code, Err: err}
	}
	return &uiadminadapter.DirectPasswordResetError{Code: "INTERNAL_ERROR", Err: err}
}

// CanReset 检查操作者是否持有独立权限 users.password.reset.other（仅体验用途）。
func (b *pageDirectPasswordResetBridge) CanReset(ctx context.Context,
	operatorUserID string) (bool, error) {
	if b == nil || b.checker == nil {
		return false, nil
	}
	caller, err := authz.UserCaller(operatorUserID)
	if err != nil {
		return false, nil
	}
	decision, err := b.checker.Check(ctx, caller, authz.CheckRequest{
		SubjectUserID: operatorUserID, ScopeID: "system",
		Permissions: []string{"users.password.reset.other"}, Mode: authz.ModeAll})
	if err != nil {
		return false, nil
	}
	return decision.Allowed, nil
}

// Begin 发起两步验证挑战（绑定目标与新口令）。
func (b *pageDirectPasswordResetBridge) Begin(ctx context.Context, operatorUserID,
	sessionSecret, targetUserID, newPassword, requestID string) (
	uiadminadapter.DirectPasswordResetChallenge, error) {
	ctx = WithManagementSessionSecret(ctx, sessionSecret)
	challenge, err := b.bridge.BeginPasswordResetVerification(ctx, operatorUserID,
		targetUserID, newPassword, requestID)
	if err != nil {
		return uiadminadapter.DirectPasswordResetChallenge{}, directPasswordResetBridgeError(err)
	}
	return uiadminadapter.DirectPasswordResetChallenge{ChallengeID: challenge.ChallengeID,
		TargetUserID: challenge.TargetUserID, RequiredStrength: challenge.RequiredStrength,
		ExpiresAt: challenge.ExpiresAt, MaxAttempts: challenge.MaxAttempts,
		WebAuthnAvailable: challenge.WebAuthnAvailable}, nil
}

// Confirm 完成两步验证并返回一次性证明（只在处理器内存）。
func (b *pageDirectPasswordResetBridge) Confirm(ctx context.Context, operatorUserID,
	sessionSecret, challengeID, password, totpCode, requestID string) (
	uiadminadapter.DirectPasswordResetGrant, error) {
	ctx = WithManagementSessionSecret(ctx, sessionSecret)
	grant, err := b.bridge.ConfirmPasswordResetVerification(ctx, operatorUserID,
		challengeID, password, totpCode, requestID)
	if err != nil {
		return uiadminadapter.DirectPasswordResetGrant{}, directPasswordResetBridgeError(err)
	}
	return uiadminadapter.DirectPasswordResetGrant{ProofToken: grant.ProofToken}, nil
}

// Change 用一次性证明提交重置。
func (b *pageDirectPasswordResetBridge) Change(ctx context.Context, operatorUserID,
	sessionSecret, targetUserID, newPassword, reason, proofToken, requestID string) (
	ui.UIDirectPasswordResetResult, error) {
	ctx = WithManagementSessionSecret(ctx, sessionSecret)
	result, err := b.bridge.ResetPassword(ctx, DirectPasswordResetRequest{
		OperatorUserID: operatorUserID, TargetUserID: targetUserID,
		NewPassword: newPassword, Reason: reason, ProofToken: proofToken,
		RequestID: requestID})
	if err != nil {
		return ui.UIDirectPasswordResetResult{}, directPasswordResetBridgeError(err)
	}
	return ui.UIDirectPasswordResetResult{UserID: result.UserID,
		SecurityVersion: result.SecurityVersion, PasswordChangedAt: result.PasswordChangedAt,
		MustChange: result.MustChange, SessionsRevoked: result.SessionsRevoked,
		OldResetRequestsCancelled:  result.OldResetRequestsCancelled,
		OldResetCredentialsRevoked: result.OldResetCredentialsRevoked}, nil
}

// 编译期确认页面桥接满足适配器契约。
var _ uiadminadapter.DirectPasswordResetBridge = (*pageDirectPasswordResetBridge)(nil)
