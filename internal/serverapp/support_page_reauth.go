package serverapp

// 步骤 188：客服/人工恢复页面再次认证宿主回调。
//
// 页面处理器在显式确认后调用适配器；适配器在没有 186 证明/API 信号时调用本回调。
// 回调取出页面解析时登记的新鲜管理强认证事实，按真实 support/manualrecovery 敏感
// 操作完成一次策略评估，再把服务端认证事实作为证据返回。适配器转换为
// reauth.Signals 后，领域服务会再次按真实操作/参数复核（双评估，均基于服务端事实）。
//
// 事实缺失/过期、动作不在白名单或策略拒绝一律 fail-closed；不做“页面确认即授权”。

import (
	"context"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
)

// supportPageReauthActions 是允许绑定到支持/恢复敏感操作的页面动作白名单。
var supportPageReauthActions = map[string]string{
	"support.case.create": "support.case.create",
	"support.case.update": "support.case.update",
	"support.reset.send":  "support.reset.send",
	"recovery.request":    "support.recovery.request",
	"recovery.approve":    "support.recovery.approve",
	"recovery.execute":    "support.recovery.execute",
}

// supportPageReauth 实现 uiadminadapter.SupportOptions.Reauth 的宿主实现。
func supportPageReauth(ctx context.Context, gate *SecurityGate, userID string,
	binding login.UISupportActionBinding) (login.UISupportEvidence, error) {
	if gate == nil || gate.Reauth == nil || gate.Policy == nil {
		return login.UISupportEvidence{}, reauth.ErrReauthRequired
	}
	if !account.ValidUserID(userID) {
		return login.UISupportEvidence{}, reauth.ErrAccessDenied
	}
	operationID, ok := supportPageReauthActions[binding.Action]
	if !ok {
		return login.UISupportEvidence{}, reauth.ErrAccessDenied
	}
	fact, ok := gate.takeManagementFact(userID)
	if !ok || fact.verifiedAt.IsZero() {
		return login.UISupportEvidence{}, reauth.ErrReauthRequired
	}
	caller, err := reauth.UserCaller(userID)
	if err != nil {
		return login.UISupportEvidence{}, reauth.ErrAccessDenied
	}
	safeRequestID := ""
	if account.ValidateRequestID(binding.RequestID) == nil {
		safeRequestID = binding.RequestID
	}
	targetType := "user"
	if operationID == "support.case.update" || operationID == "support.reset.send" {
		targetType = "support_case"
	}
	request := reauth.Request{
		ScopeID: "system", OperationID: operationID,
		TargetType: targetType, TargetID: binding.TargetUserID,
		Params: map[string]string{
			"action": binding.Action, "target": binding.TargetUserID,
			"request_id": safeRequestID,
		},
		Description: "客服/人工恢复敏感操作", RequestID: safeRequestID,
	}
	// 页面处理器已校验显式确认（checkbox/按钮），因此 Confirmed=true；策略仍会按
	// 目录默认复核认证强度与新鲜度，确认不能替代强认证。
	signals := reauth.Signals{VerifiedAt: fact.verifiedAt, Strength: policy.StrengthStrong,
		Complete: true, Confirmed: true}
	if _, err := gate.Reauth.Authorize(reauth.WithSignals(ctx, signals), caller, request); err != nil {
		return login.UISupportEvidence{}, err
	}
	return login.UISupportEvidence{
		VerifiedAt: fact.verifiedAt, Strength: "strong", Complete: true, Confirmed: true,
	}, nil
}
