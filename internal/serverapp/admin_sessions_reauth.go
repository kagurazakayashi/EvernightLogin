// Copyright (c) KaguraZakaYashi(KaguraZakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package serverapp

// 步骤 187：管理员强制下线页的宿主再次认证回调。
//
// 绑定关系：页面对 /admin/** 的会话解析会登记“当前请求持有新鲜管理强认证”的短时
// 事实（pageSessions.recordManagementFact）；本回调取出该事实，按真实
// session.revoke.other 敏感策略完成一次策略评估，并把服务端已校验的认证事实作为
// 页面证据返回。页面适配器再把证据转换为 reauth 信号交给 session.AdminRevoke，
// 领域服务会再次按同一操作重新评估策略——两次评估都基于服务端事实，页面确认框
// 与前端自报数据从不参与授权。
//
// 事实缺失/过期、动作名不在白名单或策略拒绝一律 fail-closed 返回错误，页面据此
// 不执行撤销，不存在“跳过再次认证”的降级路径。安全告知由领域服务在真实撤销成功
// 后统一发出，本回调不重复告知。

import (
	"context"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// adminSessionsReauth 实现 UIPageAdminSessionsOptions.Reauth 的宿主实现。
func adminSessionsReauth(ctx context.Context, gate *SecurityGate, userID string,
	binding login.UIAdminSessionActionBinding) (login.UIAdminSessionEvidence, error) {
	if gate == nil || gate.Reauth == nil || gate.Policy == nil {
		return login.UIAdminSessionEvidence{}, reauth.ErrReauthRequired
	}
	if !account.ValidUserID(userID) {
		return login.UIAdminSessionEvidence{}, reauth.ErrAccessDenied
	}
	if binding.Action != "session.admin_revoke" {
		return login.UIAdminSessionEvidence{}, reauth.ErrAccessDenied
	}
	fact, ok := gate.takeManagementFact(userID)
	if !ok || fact.verifiedAt.IsZero() {
		return login.UIAdminSessionEvidence{}, reauth.ErrReauthRequired
	}
	caller, err := reauth.UserCaller(userID)
	if err != nil {
		return login.UIAdminSessionEvidence{}, reauth.ErrAccessDenied
	}
	safeRequestID := ""
	if account.ValidateRequestID(binding.RequestID) == nil {
		safeRequestID = binding.RequestID
	}
	targetType, targetID := "user", binding.TargetUserID
	if binding.TargetSessionID != "" {
		targetType, targetID = "session", binding.TargetSessionID
	}
	request := reauth.Request{
		ScopeID: "system", OperationID: session.OperationSessionRevokeOther,
		TargetType: targetType, TargetID: targetID,
		Params: session.AdminRevokeParams(binding.ScopeAppID, binding.TargetUserID,
			binding.TargetSessionID),
		Description: "管理强制下线", RequestID: safeRequestID,
	}
	// 页面处理器已校验显式确认（checkbox/按钮），因此 Confirmed=true；策略仍会
	// 按目录默认复核认证强度与新鲜度，确认不能替代强认证。
	signals := reauth.Signals{VerifiedAt: fact.verifiedAt, Strength: policy.StrengthStrong,
		Complete: true, Confirmed: true}
	if _, err := gate.Reauth.Authorize(reauth.WithSignals(ctx, signals), caller, request); err != nil {
		return login.UIAdminSessionEvidence{}, err
	}
	return login.UIAdminSessionEvidence{
		VerifiedAt: fact.verifiedAt, Strength: "strong", Complete: true, Confirmed: true,
	}, nil
}

// adminSessionsNavigation 为管理命名空间提供“会话管理”导航入口；只对真实管理
// 会话显示，仅影响展示，不构成授权证明（页面路由与领域服务仍逐次判定）。
type adminSessionsNavigation struct{}

// Navigation 实现 login.UINavigationProvider。
func (adminSessionsNavigation) Navigation(_ context.Context,
	page login.UIPageContext) ([]login.UINavItem, error) {
	if page.Session.Kind != "management" {
		return nil, nil
	}
	return []login.UINavItem{{
		Key: "admin.sessions", Label: "会话管理", RouteName: "admin.sessions",
		Visible: true, Enabled: true, Current: page.RouteName == "admin.sessions",
	}}, nil
}
