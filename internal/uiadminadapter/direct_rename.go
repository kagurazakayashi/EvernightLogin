package uiadminadapter

// 步骤 258：管理页“直接修改他人用户名”页面后端桥接。
//
// 页面处理器（ui 包）从请求拿到真实管理会话秘密后，只在处理器代码内把秘密传给
// 本适配器；适配器再交给宿主桥接（serverapp 侧包装后调用根包门面）。秘密不进入
// 模板上下文、渲染数据、响应或日志。
//
// 授权、两步验证证明绑定/消费、目标与行版本校验、事务一致提交与审计仍由根包
// 直接管理门面执行；本文件不做第二套判定。

import (
	"context"
	"time"

	ui "github.com/kagurazakayashi/EvernightLogin/ui"
)

// DirectRenameChallenge/直接改名两步验证挑战的页面投影。
type DirectRenameChallenge struct {
	ChallengeID       string
	TargetUserID      string
	RequiredStrength  string
	ExpiresAt         time.Time
	MaxAttempts       int
	WebAuthnAvailable bool
}

// DirectRenameGrant 是一次性证明；只在处理器内存中短时存在，不进入页面数据。
type DirectRenameGrant struct {
	ProofToken string
	ExpiresAt  time.Time
}

// DirectRenameBridge 是宿主直接改名能力的页面侧接口（serverapp 实现并注入）。
type DirectRenameBridge interface {
	CanChange(ctx context.Context, operatorUserID string) (bool, error)
	Begin(ctx context.Context, operatorUserID, sessionSecret, targetUserID,
		newUsername, requestID string) (DirectRenameChallenge, error)
	Confirm(ctx context.Context, operatorUserID, sessionSecret, challengeID,
		password, totpCode, requestID string) (DirectRenameGrant, error)
	Change(ctx context.Context, operatorUserID, sessionSecret, targetUserID, newUsername string,
		expectedRowVersion int64, reason, proofToken, requestID string) (ui.UIAdminUserView, error)
}

// DirectRenameError 是页面桥接的稳定错误码载体。
type DirectRenameError struct {
	Code string
	Err  error
}

// Error 实现 error。
func (e *DirectRenameError) Error() string {
	if e == nil {
		return "直接改名失败"
	}
	return "直接改名失败：" + e.Code
}

// Unwrap 返回原始错误。
func (e *DirectRenameError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// directRenameUIError 把桥接错误投影为页面统一错误；缺能力按 ACCESS_DENIED。
func directRenameUIError(err error) error {
	if err == nil {
		return nil
	}
	if typed, ok := err.(*DirectRenameError); ok && typed.Code != "" {
		return &ui.UIAdminError{Code: typed.Code}
	}
	return &ui.UIAdminError{Code: "INTERNAL_ERROR"}
}

// CanChangeUsername 报告当前管理员是否具备直接改名能力（仅用于按钮显示；服务端
// 每次提交仍重新授权）。
func (a *Adapter) CanChangeUsername(ctx context.Context, adminUserID string) (bool, error) {
	if a == nil || a.opts.DirectRename == nil {
		return false, nil
	}
	allowed, err := a.opts.DirectRename.CanChange(ctx, adminUserID)
	if err != nil {
		return false, directRenameUIError(err)
	}
	return allowed, nil
}

// BeginDirectUsernameChange 发起两步验证挑战。
func (a *Adapter) BeginDirectUsernameChange(ctx context.Context, adminUserID,
	sessionSecret, targetUserID, newUsername, requestID string) (ui.UIDirectRenameChallenge, error) {
	if a == nil || a.opts.DirectRename == nil {
		return ui.UIDirectRenameChallenge{}, &ui.UIAdminError{Code: "ACCESS_DENIED"}
	}
	challenge, err := a.opts.DirectRename.Begin(ctx, adminUserID, sessionSecret,
		targetUserID, newUsername, requestID)
	if err != nil {
		return ui.UIDirectRenameChallenge{}, directRenameUIError(err)
	}
	return ui.UIDirectRenameChallenge{ChallengeID: challenge.ChallengeID,
		TargetUserID: challenge.TargetUserID, RequiredStrength: challenge.RequiredStrength,
		ExpiresAt: challenge.ExpiresAt, MaxAttempts: challenge.MaxAttempts,
		WebAuthnAvailable: challenge.WebAuthnAvailable}, nil
}

// ConfirmDirectUsernameChange 完成两步验证并返回一次性证明（只在处理器内存）。
func (a *Adapter) ConfirmDirectUsernameChange(ctx context.Context, adminUserID,
	sessionSecret, challengeID, password, totpCode, requestID string) (ui.UIDirectRenameGrant, error) {
	if a == nil || a.opts.DirectRename == nil {
		return ui.UIDirectRenameGrant{}, &ui.UIAdminError{Code: "ACCESS_DENIED"}
	}
	grant, err := a.opts.DirectRename.Confirm(ctx, adminUserID, sessionSecret,
		challengeID, password, totpCode, requestID)
	if err != nil {
		return ui.UIDirectRenameGrant{}, directRenameUIError(err)
	}
	return ui.UIDirectRenameGrant{ProofToken: grant.ProofToken,
		ExpiresAt: grant.ExpiresAt}, nil
}

// ApplyDirectUsernameChange 用一次性证明提交改名。
func (a *Adapter) ApplyDirectUsernameChange(ctx context.Context, adminUserID,
	sessionSecret, targetUserID, newUsername string, expectedRowVersion int64,
	reason, proofToken, requestID string) (ui.UIAdminUserView, error) {
	if a == nil || a.opts.DirectRename == nil {
		return ui.UIAdminUserView{}, &ui.UIAdminError{Code: "ACCESS_DENIED"}
	}
	view, err := a.opts.DirectRename.Change(ctx, adminUserID, sessionSecret,
		targetUserID, newUsername, expectedRowVersion, reason, proofToken, requestID)
	if err != nil {
		return ui.UIAdminUserView{}, directRenameUIError(err)
	}
	return view, nil
}
