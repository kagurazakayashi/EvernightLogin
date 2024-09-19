package uiadminadapter

// 步骤 259：管理页“直接重置他人密码”页面后端适配器（独立类型，避免改动 258 已
// 提交的 Adapter Options；由 serverapp 页面装配单独注入）。
//
// 页面处理器在处理器代码内取得真实管理会话秘密并作为参数传入；本适配器把秘密原样
// 交给宿主桥接（serverapp 侧包装后调用根包 257 门面），不进入页面数据/模板/响应/
// 日志。授权、证明绑定/消费、密码策略与历史、事务提交仍由门面执行。

import (
	"context"
	"time"

	ui "github.com/kagurazakayashi/EvernightLogin/ui"
)

// DirectPasswordResetChallenge/Grant 是宿主桥接的页面侧投影。
type DirectPasswordResetChallenge struct {
	ChallengeID       string
	TargetUserID      string
	RequiredStrength  string
	ExpiresAt         time.Time
	MaxAttempts       int
	WebAuthnAvailable bool
}

// DirectPasswordResetGrant 是一次性证明（只在处理器内存）。
type DirectPasswordResetGrant struct {
	ProofToken string
}

// DirectPasswordResetBridge 是宿主直接重置密码能力的页面侧接口（serverapp 实现）。
type DirectPasswordResetBridge interface {
	CanReset(ctx context.Context, operatorUserID string) (bool, error)
	Begin(ctx context.Context, operatorUserID, sessionSecret, targetUserID,
		newPassword, requestID string) (DirectPasswordResetChallenge, error)
	Confirm(ctx context.Context, operatorUserID, sessionSecret, challengeID,
		password, totpCode, requestID string) (DirectPasswordResetGrant, error)
	Change(ctx context.Context, operatorUserID, sessionSecret, targetUserID,
		newPassword, reason, proofToken, requestID string) (ui.UIDirectPasswordResetResult, error)
}

// DirectPasswordResetError 是页面桥接的稳定错误码载体。
type DirectPasswordResetError struct {
	Code string
	Err  error
}

// Error 实现 error。
func (e *DirectPasswordResetError) Error() string {
	if e == nil {
		return "直接重置密码失败"
	}
	return "直接重置密码失败：" + e.Code
}

// Unwrap 返回原始错误。
func (e *DirectPasswordResetError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// directPasswordResetUIError 把桥接错误投影为页面统一错误；缺能力按 ACCESS_DENIED。
func directPasswordResetUIError(err error) error {
	if err == nil {
		return nil
	}
	if typed, ok := err.(*DirectPasswordResetError); ok && typed.Code != "" {
		return &ui.UIAdminError{Code: typed.Code}
	}
	return &ui.UIAdminError{Code: "INTERNAL_ERROR"}
}

// DirectPasswordResetAdapter 实现 ui.UIDirectPasswordResetBackend。
type DirectPasswordResetAdapter struct {
	bridge DirectPasswordResetBridge
}

// NewDirectPasswordResetAdapter 构造页面适配器；bridge 为 nil 时所有操作 fail-closed。
func NewDirectPasswordResetAdapter(bridge DirectPasswordResetBridge) *DirectPasswordResetAdapter {
	if bridge == nil {
		return nil
	}
	return &DirectPasswordResetAdapter{bridge: bridge}
}

// CanResetPassword 报告是否具备直接重置权限（仅按钮显示；提交仍重新授权）。
func (a *DirectPasswordResetAdapter) CanResetPassword(ctx context.Context,
	adminUserID string) (bool, error) {
	if a == nil || a.bridge == nil {
		return false, nil
	}
	allowed, err := a.bridge.CanReset(ctx, adminUserID)
	if err != nil {
		return false, directPasswordResetUIError(err)
	}
	return allowed, nil
}

// BeginDirectPasswordReset 发起两步验证挑战（绑定目标与新口令）。
func (a *DirectPasswordResetAdapter) BeginDirectPasswordReset(ctx context.Context,
	adminUserID, sessionSecret, targetUserID, newPassword, requestID string) (
	ui.UIDirectPasswordResetChallenge, error) {
	if a == nil || a.bridge == nil {
		return ui.UIDirectPasswordResetChallenge{}, &ui.UIAdminError{Code: "ACCESS_DENIED"}
	}
	challenge, err := a.bridge.Begin(ctx, adminUserID, sessionSecret, targetUserID,
		newPassword, requestID)
	if err != nil {
		return ui.UIDirectPasswordResetChallenge{}, directPasswordResetUIError(err)
	}
	return ui.UIDirectPasswordResetChallenge{ChallengeID: challenge.ChallengeID,
		TargetUserID: challenge.TargetUserID, RequiredStrength: challenge.RequiredStrength,
		ExpiresAt: challenge.ExpiresAt, MaxAttempts: challenge.MaxAttempts,
		WebAuthnAvailable: challenge.WebAuthnAvailable}, nil
}

// ConfirmDirectPasswordReset 完成两步验证并返回一次性证明（只在处理器内存）。
func (a *DirectPasswordResetAdapter) ConfirmDirectPasswordReset(ctx context.Context,
	adminUserID, sessionSecret, challengeID, password, totpCode, requestID string) (
	ui.UIDirectPasswordResetGrant, error) {
	if a == nil || a.bridge == nil {
		return ui.UIDirectPasswordResetGrant{}, &ui.UIAdminError{Code: "ACCESS_DENIED"}
	}
	grant, err := a.bridge.Confirm(ctx, adminUserID, sessionSecret, challengeID,
		password, totpCode, requestID)
	if err != nil {
		return ui.UIDirectPasswordResetGrant{}, directPasswordResetUIError(err)
	}
	return ui.UIDirectPasswordResetGrant{ProofToken: grant.ProofToken}, nil
}

// ApplyDirectPasswordReset 用一次性证明提交重置。
func (a *DirectPasswordResetAdapter) ApplyDirectPasswordReset(ctx context.Context,
	adminUserID, sessionSecret, targetUserID, newPassword, reason, proofToken,
	requestID string) (ui.UIDirectPasswordResetResult, error) {
	if a == nil || a.bridge == nil {
		return ui.UIDirectPasswordResetResult{}, &ui.UIAdminError{Code: "ACCESS_DENIED"}
	}
	return a.bridge.Change(ctx, adminUserID, sessionSecret, targetUserID, newPassword,
		reason, proofToken, requestID)
}

// 编译期确认适配器满足页面契约。
var _ ui.UIDirectPasswordResetBackend = (*DirectPasswordResetAdapter)(nil)
