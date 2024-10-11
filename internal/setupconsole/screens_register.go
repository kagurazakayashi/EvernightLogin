package setupconsole

// WS3（步骤 286–291）画面注册入口。
//
// 由 cmd/login-setup/main.go（WS1 所有）在 M1 后调用一行注册；测试可直接用
// RegisterWS3ForTest 注入固定会话。菜单 Order 按 WS1 冻结约定 200–499。
// 菜单项在实例状态不满足时显示但不可进入（Enabled 返回 false），避免误以为可用。

import (
	"fmt"
)

// WS3 画面的稳定菜单/画面 ID。
const (
	MenuLocalUsers    = "ws3.users"
	MenuLocalIdentity = "ws3.identity"
	MenuLocalSecurity = "ws3.security"
	MenuLocalRBAC     = "ws3.rbac"
	MenuLocalApps     = "ws3.apps"
	MenuLocalAudit    = "ws3.audit"
)

// RegisterWS3 注册本地维护画面；open 必须由本机 login-setup 入口提供（生产为
// 基于 Detection/配置路径/维护锁的 OpenLocalRuntime），不得由 HTTP 请求构造。
func RegisterWS3(app *App, open WS3SessionOpener) error {
	if app == nil {
		return fmt.Errorf("控制台未初始化")
	}
	if open == nil {
		return fmt.Errorf("本地维护会话 opener 不能为空")
	}
	return registerWS3Screens(app, open)
}

// RegisterWS3ForTest 是测试辅助：与 RegisterWS3 相同，但显式给出 opener。
func registerWS3Screens(app *App, open WS3SessionOpener) error {
	entries := []struct {
		id      string
		label   string
		order   int
		factory func() ScreenController
	}{
		{MenuLocalUsers, "本地用户与账户生命周期", 210, func() ScreenController { return newWS3UsersScreen(open) }},
		{MenuLocalIdentity, "本地用户名与密码（含 root 救援）", 220, func() ScreenController { return newWS3IdentityScreen(open) }},
		{MenuLocalSecurity, "本地 MFA 清除与受限重绑", 230, func() ScreenController { return newWS3SecurityScreen(open) }},
		{MenuLocalRBAC, "本地角色/权限/用户组", 240, func() ScreenController { return newWS3RBACScreen(open) }},
		{MenuLocalApps, "本地应用/成员/凭证/会话", 250, func() ScreenController { return newWS3AppsScreen(open) }},
		{MenuLocalAudit, "本地审计/诊断/通知/报告/任务", 260, func() ScreenController { return newWS3AuditScreen(open) }},
	}
	for _, entry := range entries {
		if err := app.RegisterMenu(MenuEntry{ID: entry.id, Label: entry.label,
			Order: entry.order, Enabled: ws3MenuEnabled}); err != nil {
			return err
		}
		if err := app.RegisterScreen(entry.id, entry.factory); err != nil {
			return err
		}
	}
	return nil
}
