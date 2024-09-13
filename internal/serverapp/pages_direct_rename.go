package serverapp

// 步骤 258：管理页直接改名桥接的 serverapp 侧实现。
//
// 页面处理器在处理器代码内取得真实管理会话秘密并作为参数传入；本包装把秘密放入
// context 交给宿主桥接（app 侧）构造 AdminSession，再调用根包门面。秘密/证明不会
// 进入页面数据、模板、响应或日志。授权能力查询只用于按钮显示，真正提交仍由宿主
// 门面重新授权与校验。

import (
	"context"
	"errors"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	"github.com/kagurazakayashi/EvernightLogin/internal/uiadminadapter"
	ui "github.com/kagurazakayashi/EvernightLogin/ui"
)

// pageDirectRenameBridge 实现 uiadminadapter.DirectRenameBridge。
type pageDirectRenameBridge struct {
	bridge  DirectUsernameBridge
	checker interface {
		Check(ctx context.Context, caller authz.Caller, request authz.CheckRequest) (authz.CheckResult, error)
	}
}

// newPageDirectRenameBridge 构造页面桥接；缺依赖时返回 nil（页面入口 fail-closed）。
func newPageDirectRenameBridge(bridge DirectUsernameBridge,
	managed *ManagedServices) uiadminadapter.DirectRenameBridge {
	if bridge == nil || managed == nil || managed.Checker == nil {
		return nil
	}
	return &pageDirectRenameBridge{bridge: bridge, checker: managed.Checker}
}

// directRenameBridgeError 把宿主桥接错误投影为页面稳定错误码。
func directRenameBridgeError(err error) error {
	if err == nil {
		return nil
	}
	var typed *DirectManagementError
	if errors.As(err, &typed) && typed.Code != "" {
		return &uiadminadapter.DirectRenameError{Code: typed.Code, Err: err}
	}
	return &uiadminadapter.DirectRenameError{Code: "INTERNAL_ERROR", Err: err}
}

// CanChange 检查操作者是否持有独立权限 users.username.change.other（仅体验用途）。
func (b *pageDirectRenameBridge) CanChange(ctx context.Context, operatorUserID string) (bool, error) {
	if b == nil || b.checker == nil {
		return false, nil
	}
	caller, err := authz.UserCaller(operatorUserID)
	if err != nil {
		return false, nil
	}
	decision, err := b.checker.Check(ctx, caller, authz.CheckRequest{
		SubjectUserID: operatorUserID, ScopeID: "system",
		Permissions: []string{"users.username.change.other"}, Mode: authz.ModeAll})
	if err != nil {
		return false, nil
	}
	return decision.Allowed, nil
}

// Begin 发起两步验证挑战。
func (b *pageDirectRenameBridge) Begin(ctx context.Context, operatorUserID, sessionSecret,
	targetUserID, newUsername, requestID string) (uiadminadapter.DirectRenameChallenge, error) {
	ctx = WithManagementSessionSecret(ctx, sessionSecret)
	challenge, err := b.bridge.BeginUsernameVerification(ctx, operatorUserID,
		targetUserID, newUsername, requestID)
	if err != nil {
		return uiadminadapter.DirectRenameChallenge{}, directRenameBridgeError(err)
	}
	return uiadminadapter.DirectRenameChallenge{ChallengeID: challenge.ChallengeID,
		TargetUserID: challenge.TargetUserID, RequiredStrength: challenge.RequiredStrength,
		ExpiresAt: challenge.ExpiresAt, MaxAttempts: challenge.MaxAttempts,
		WebAuthnAvailable: challenge.WebAuthnAvailable}, nil
}

// Confirm 完成两步验证并返回一次性证明（只在处理器内存）。
func (b *pageDirectRenameBridge) Confirm(ctx context.Context, operatorUserID,
	sessionSecret, challengeID, password, totpCode, requestID string) (
	uiadminadapter.DirectRenameGrant, error) {
	ctx = WithManagementSessionSecret(ctx, sessionSecret)
	grant, err := b.bridge.ConfirmUsernameVerification(ctx, operatorUserID,
		challengeID, password, totpCode, requestID)
	if err != nil {
		return uiadminadapter.DirectRenameGrant{}, directRenameBridgeError(err)
	}
	return uiadminadapter.DirectRenameGrant{ProofToken: grant.ProofToken,
		ExpiresAt: grant.ExpiresAt}, nil
}

// Change 用一次性证明提交改名。
func (b *pageDirectRenameBridge) Change(ctx context.Context, operatorUserID,
	sessionSecret, targetUserID, newUsername string, expectedRowVersion int64,
	reason, proofToken, requestID string) (ui.UIAdminUserView, error) {
	ctx = WithManagementSessionSecret(ctx, sessionSecret)
	result, err := b.bridge.ChangeUsername(ctx, DirectUsernameChangeRequest{
		OperatorUserID: operatorUserID, TargetUserID: targetUserID,
		NewUsername: newUsername, ExpectedRowVersion: expectedRowVersion,
		Reason: reason, ProofToken: proofToken, RequestID: requestID})
	if err != nil {
		return ui.UIAdminUserView{}, directRenameBridgeError(err)
	}
	return ui.UIAdminUserView{UserID: result.UserID, Username: result.Username,
		RowVersion: result.RowVersion}, nil
}

// 编译期确认页面桥接满足适配器契约。
var _ uiadminadapter.DirectRenameBridge = (*pageDirectRenameBridge)(nil)

// 编译期确认 account/authz 依赖仍被使用（避免未使用导入）。
var _ = account.ValidUserID
