package session_test

// 步骤 187：管理员会话查询（AdminListSessions）与强制下线参数契约测试。
// 使用真实 SQLite 会话存储与真实会话服务；审计查询只读测试库。

import (
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// TestAdminListSessionsScopeAndAudit 验证管理员按范围查询目标活动会话：
//   - 系统范围返回目标全部活动会话，应用范围只返回绑定该应用的会话；
//   - 未授权应用范围/缺少强认证一律拒绝且不返回会话；
//   - root 目标拒绝；查询写真实管理员操作者审计，不含秘密字段。
func TestAdminListSessionsScopeAndAudit(t *testing.T) {
	env := newTestEnv(t)
	const adminID = "usr_00000000000000000000000000000081"
	const targetID = "usr_00000000000000000000000000000082"
	const otherID = "usr_00000000000000000000000000000083"
	const appA = "app_00000000000000000000000000000091"
	const appB = "app_00000000000000000000000000000092"
	env.insertUser(adminID, "list-admin", account.StatusActive, 1)
	env.insertUser(targetID, "list-target", account.StatusActive, 1)
	env.insertUser(otherID, "list-other", account.StatusActive, 1)
	env.insertApplication(appA, "active")
	env.insertApplication(appB, "active")
	env.insertMembership(appA, targetID, "active")

	service := env.newServiceWith(func(options *session.Options) {
		options.Authorizer = &stubAuthorizer{allow: map[string]bool{
			adminID + "|":        true,
			adminID + "|" + appA: true,
		}}
	})
	adminSession := env.loginWith(service, adminID, "", false, session.ClientInfo{})
	env.markStrongAuth(adminSession.Session.ID)
	targetSystem := env.loginWith(service, targetID, "", false, session.ClientInfo{})
	targetAppA := env.loginWith(service, targetID, appA, false, session.ClientInfo{})
	_ = env.loginWith(service, otherID, "", false, session.ClientInfo{})

	// 系统范围：返回目标全部 2 个活动会话；不包含其他用户会话。
	page, err := service.AdminListSessions(env.ctx, adminSession.Secret.Reveal(),
		session.AdminSessionListRequest{TargetUserID: targetID, Page: 1, PageSize: 20,
			RequestID: "req-list-system"})
	if err != nil {
		t.Fatalf("系统范围查询失败: %v", err)
	}
	if page.Total != 2 || len(page.Sessions) != 2 {
		t.Fatalf("系统范围会话数 = %d/%d，期望 2", page.Total, len(page.Sessions))
	}
	for _, item := range page.Sessions {
		if item.ID == targetSystem.Session.ID || item.ID == targetAppA.Session.ID {
			continue
		}
		t.Fatalf("系统范围返回了非目标会话: %+v", item)
	}
	if page.ScopeAppID != "" || page.TargetUserID != targetID {
		t.Fatalf("范围回显 = %q/%q", page.ScopeAppID, page.TargetUserID)
	}
	// 当前会话标记：管理员查询目标，不把目标会话误标为 current。
	for _, item := range page.Sessions {
		if item.Current {
			t.Fatalf("目标会话不应被标记为管理员当前会话: %+v", item)
		}
	}

	// 应用范围 A：只返回绑定 A 的会话（系统范围会话不属于 A）。
	appPage, err := service.AdminListSessions(env.ctx, adminSession.Secret.Reveal(),
		session.AdminSessionListRequest{ScopeAppID: appA, TargetUserID: targetID,
			Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("应用范围查询失败: %v", err)
	}
	if appPage.Total != 1 || len(appPage.Sessions) != 1 ||
		appPage.Sessions[0].ID != targetAppA.Session.ID {
		t.Fatalf("应用范围 A 结果 = %+v，期望仅 %s", appPage.Sessions, targetAppA.Session.ID)
	}

	// 应用范围 B 未授权：拒绝且不泄露。
	if _, err := service.AdminListSessions(env.ctx, adminSession.Secret.Reveal(),
		session.AdminSessionListRequest{ScopeAppID: appB, TargetUserID: targetID}); !errors.Is(err, session.ErrAccessDenied) {
		t.Fatalf("未授权应用范围错误 = %v，期望 ErrAccessDenied", err)
	}

	// 缺强认证：普通密码会话拒绝。
	plainAdmin := env.loginWith(service, adminID, "", false, session.ClientInfo{})
	if _, err := service.AdminListSessions(env.ctx, plainAdmin.Secret.Reveal(),
		session.AdminSessionListRequest{TargetUserID: targetID}); !errors.Is(err, session.ErrAccessDenied) {
		t.Fatalf("缺强认证查询错误 = %v，期望 ErrAccessDenied", err)
	}

	// root 目标：拒绝（与强制下线一致）。
	const rootID = "usr_00000000000000000000000000000084"
	env.insertUser(rootID, "list-root", account.StatusActive, 1)
	env.exec(`UPDATE users SET is_root=1 WHERE id=?`, rootID)
	if _, err := service.AdminListSessions(env.ctx, adminSession.Secret.Reveal(),
		session.AdminSessionListRequest{TargetUserID: rootID}); !errors.Is(err, session.ErrAccessDenied) {
		t.Fatalf("root 目标查询错误 = %v，期望 ErrAccessDenied", err)
	}

	// 审计：成功查询记录真实管理员操作者；拒绝路径也留痕。
	if got := env.auditCount(session.ActionSessionAdminList); got < 3 {
		t.Fatalf("管理员会话查询审计数 = %d，期望至少 3（成功 2 + 拒绝）", got)
	}
	if actor := env.queryString(`SELECT actor_id FROM audit_events WHERE action=? ORDER BY rowid DESC LIMIT 1`,
		string(session.ActionSessionAdminList)); actor != adminID {
		t.Fatalf("最近查询审计操作者 = %q，期望 %q", actor, adminID)
	}
}

// TestAdminRevokeParamsStable 验证强制下线敏感参数构造器：固定三个键、空值显式
// 出现，供页面/API/CLI 生成一致的参数摘要（证明绑定与策略判定同源）。
func TestAdminRevokeParamsStable(t *testing.T) {
	params := session.AdminRevokeParams("", "usr_target", "")
	if len(params) != 3 {
		t.Fatalf("参数数量 = %d，期望 3（空值也必须显式出现）", len(params))
	}
	if params["scope_app_id"] != "" || params["target_user_id"] != "usr_target" ||
		params["target_session_id"] != "" {
		t.Fatalf("参数内容不符: %#v", params)
	}
	if session.OperationSessionRevokeOther != "session.revoke.other" {
		t.Fatalf("敏感操作 ID = %q", session.OperationSessionRevokeOther)
	}
}
