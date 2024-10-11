package setupconsole

// 集成回归（WS1 main.go 接线）：WS2/WS3/WS4 注册共存、无 ID 冲突、菜单顺序稳定。
// 仅测试注册路径；真正的领域会话由各 WS 测试覆盖。

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestRegistrationIntegrationAllWorkstreams 验证三工作流注册成功且菜单/画面齐全。
func TestRegistrationIntegrationAllWorkstreams(t *testing.T) {
	app := NewApp(newFakeTerminal(), "login.yaml", nil)
	if err := RegisterWS2(app); err != nil {
		t.Fatalf("注册 WS2 画面: %v", err)
	}
	opener := func(ctx context.Context) (WS3Session, error) {
		return nil, ErrLocalRuntimeUnavailable
	}
	if err := RegisterWS3(app, opener); err != nil {
		t.Fatalf("注册 WS3 画面: %v", err)
	}
	if err := RegisterWS4(app); err != nil {
		t.Fatalf("注册 WS4 画面: %v", err)
	}
	// 重复注册必须报错（不得静默覆盖）。
	if err := RegisterWS4(app); err == nil {
		t.Fatal("重复 RegisterWS4 应返回错误")
	}
	if err := RegisterWS3(app, opener); err == nil {
		t.Fatal("重复 RegisterWS3 应返回错误")
	}
	requiredIDs := []string{
		MenuStatus, MenuConfig, MenuFields, MenuPath, MenuHelp, MenuExit,
		"ws2-database", "ws2-root", "ws2-accounts", "ws2-recommend",
		MenuLocalUsers, MenuLocalIdentity, MenuLocalSecurity, MenuLocalRBAC,
		MenuLocalApps, MenuLocalAudit,
		"ws4-backup", "ws4-service",
	}
	items := app.menuItems()
	present := make(map[string]menuItem, len(items))
	for _, item := range items {
		if item.ID == "" {
			t.Fatalf("菜单项缺少 ID: %+v", item)
		}
		if _, exists := present[item.ID]; exists {
			t.Fatalf("菜单 ID 重复: %s", item.ID)
		}
		present[item.ID] = item
	}
	for _, id := range requiredIDs {
		if _, exists := present[id]; !exists {
			t.Fatalf("注册后缺少菜单项 %s；当前：%v", id, menuIDs(items))
		}
		if strings.TrimSpace(present[id].Label) == "" {
			t.Fatalf("菜单项 %s 缺少文案", id)
		}
	}
	// 顺序契约：内置 0/10/11/20/900/1000；WS2/WS3 200–260；WS4 500–520。
	positions := make(map[string]int, len(items))
	for index, item := range items {
		positions[item.ID] = index
	}
	if positions[MenuStatus] != 0 {
		t.Fatalf("状态菜单应排第一，实际索引 %d", positions[MenuStatus])
	}
	if !(positions[MenuExit] > positions["ws4-service"] && positions[MenuExit] > positions[MenuLocalUsers]) {
		t.Fatalf("退出菜单应在扩展画面之后：exit=%d", positions[MenuExit])
	}
	if !(positions["ws2-database"] < positions[MenuLocalUsers] &&
		positions[MenuLocalUsers] < positions["ws4-backup"]) {
		t.Fatalf("工作流顺序异常：ws2=%d ws3=%d ws4=%d",
			positions["ws2-database"], positions[MenuLocalUsers], positions["ws4-backup"])
	}
	// 所有注册画面都可以被打开（不执行领域操作；打开后立即 Esc 返回）。
	for _, id := range requiredIDs {
		if strings.HasPrefix(id, "ws2-") || strings.HasPrefix(id, "ws3.") ||
			strings.HasPrefix(id, "ws4-") {
			if err := app.OpenScreen(id); err != nil {
				t.Fatalf("打开画面 %s 失败: %v", id, err)
			}
			if app.screen != ScreenExternal || app.activeScreen == nil {
				t.Fatalf("画面 %s 未进入扩展画面状态", id)
			}
			app.screen = ScreenMain
			app.activeScreen = nil
		}
	}
}

// TestRegistrationWS3RequiresOpener 验证 WS3 缺少本地会话 opener 时 fail-closed。
func TestRegistrationWS3RequiresOpener(t *testing.T) {
	app := NewApp(newFakeTerminal(), "login.yaml", nil)
	if err := RegisterWS3(app, nil); err == nil {
		t.Fatal("缺少 opener 时注册应失败")
	}
	if err := RegisterWS2(nil); err == nil {
		t.Fatal("空 App 注册 WS2 应失败")
	}
	if err := RegisterWS4(nil); err == nil {
		t.Fatal("空 App 注册 WS4 应失败")
	}
	_ = errors.New
}

// menuIDs 返回菜单 ID 列表用于失败信息。
func menuIDs(items []menuItem) []string {
	ids := make([]string, 0, len(items))
	for _, item := range items {
		ids = append(ids, item.ID)
	}
	return ids
}
