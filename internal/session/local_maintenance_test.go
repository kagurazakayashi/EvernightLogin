package session_test

// 步骤 288 本地维护按用户会话列举定向测试。
//
// 覆盖：登录后本地维护可列出目标用户会话（不返回秘密）、分页 HasMore、非法用户
// ID/空本地身份拒绝、只读（不撤销会话）。

import (
	"context"
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

const localMigrationUserID = "usr_0000000000000000000000000000a101"

// TestLocalMaintenanceListUserSessions 覆盖按目标用户列出会话。
func TestLocalMaintenanceListUserSessions(t *testing.T) {
	env := newTestEnv(t)
	env.insertUser(localMigrationUserID, "maintenance-target", account.StatusActive, 1)
	issued := env.loginComplete(localMigrationUserID, 1)
	if issued.Session.ID == "" {
		t.Fatal("登录未签发会话 ID")
	}
	caller, err := session.NewLocalMaintenanceCaller("os:tester@local")
	if err != nil {
		t.Fatalf("本地维护身份: %v", err)
	}
	list, hasMore, err := env.session.LocalMaintenanceListUserSessions(context.Background(),
		caller, localMigrationUserID, 10, 0)
	if err != nil {
		t.Fatalf("列出目标会话: %v", err)
	}
	if len(list) != 1 || list[0].ID != issued.Session.ID || hasMore {
		t.Fatalf("会话列表异常: %+v hasMore=%v", list, hasMore)
	}
	// 只读：会话仍有效。
	if _, err := env.session.Validate(context.Background(), issued.Secret.Reveal()); err != nil {
		t.Fatalf("列举会话不应撤销有效会话: %v", err)
	}
	// 稳定 UserID 校验与本地身份校验。
	if _, _, err := env.session.LocalMaintenanceListUserSessions(context.Background(),
		caller, "bad-id", 10, 0); !errors.Is(err, session.ErrInvalidRequest) {
		t.Fatalf("非法用户 ID 错误 = %v，期望 ErrInvalidRequest", err)
	}
	if _, _, err := env.session.LocalMaintenanceListUserSessions(context.Background(),
		session.LocalMaintenanceCaller{}, localMigrationUserID, 10, 0); !errors.Is(
		err, session.ErrAccessDenied) {
		t.Fatalf("空本地身份错误 = %v，期望 ErrAccessDenied", err)
	}
	if _, err := session.NewLocalMaintenanceCaller(""); err == nil {
		t.Fatal("空操作者标识应构造失败")
	}
}

// TestLocalMaintenanceRevokeAllSessions 覆盖 LOW-2：本地维护强制下线记录本地
// actor/理由，并实际使旧会话失效。
func TestLocalMaintenanceRevokeAllSessions(t *testing.T) {
	env := newTestEnv(t)
	targetID := "usr_0000000000000000000000000000a102"
	env.insertUser(targetID, "revoke-target", account.StatusActive, 1)
	issued := env.loginComplete(targetID, 1)
	caller, err := session.NewLocalMaintenanceCaller("os:tester@local")
	if err != nil {
		t.Fatalf("本地维护身份: %v", err)
	}
	count, err := env.session.LocalMaintenanceRevokeAllSessions(context.Background(),
		caller, targetID, "local_maintenance_test", "req-local-session-revoke")
	if err != nil {
		t.Fatalf("本地强制下线: %v", err)
	}
	if count < 1 {
		t.Fatalf("撤销数量 = %d，期望 >=1", count)
	}
	if _, err := env.session.Validate(context.Background(),
		issued.Secret.Reveal()); err == nil {
		t.Fatal("本地强制下线后旧会话应失效")
	}
	if _, err := env.session.LocalMaintenanceRevokeAllSessions(context.Background(),
		session.LocalMaintenanceCaller{}, targetID, "local_maintenance_test",
		"req-x"); !errors.Is(err, session.ErrAccessDenied) {
		t.Fatalf("空本地身份错误 = %v，期望 ErrAccessDenied", err)
	}
	if _, err := env.session.LocalMaintenanceRevokeAllSessions(context.Background(),
		caller, targetID, "中文理由", "req-y"); !errors.Is(err, session.ErrInvalidRequest) {
		t.Fatalf("非法原因码错误 = %v，期望 ErrInvalidRequest", err)
	}
}
