package serverapp

// 步骤 255 修复二轮（F1 + N-255-7）的宿主管配级定向测试：
//   - F1：tx 权限终检必须 JOIN role_permissions——角色仍启用但“角色-权限”关联被删除时
//     必须拒绝；用户组路径（group_members→group_roles→role_permissions）仍可通过；
//   - N-255-7：账户有效期判定必须使用注入时钟（本测试注入 testNow；真实墙钟已晚于
//     测试数据的有效期末端，若实现用 time.Now 则“有效期未到期”用例会失败）。
//
// 使用真实迁移后的临时 SQLite + 真实审计事务连接；不启动服务、不发邮件、不监听端口。

import (
	"context"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// checkerTestIDs 是本测试固定的稳定 ID（只在隔离临时库内使用）。
const (
	checkerUserID       = "usr_00000000000000000000000000000c01"
	checkerPermissionID = "perm_0000000000000000000000000000c01"
	checkerRoleID       = "role_0000000000000000000000000000c01"
	checkerGroupID      = "grp_000000000000000000000000000c01"
	checkerKey          = "users.read"
)

// TestReauthPermissionCheckerTxRevalidatesLinksAndClock 覆盖 F1 JOIN 与注入时钟。
func TestReauthPermissionCheckerTxRevalidatesLinksAndClock(t *testing.T) {
	ctx := context.Background()
	base, err := OpenBase(ctx, BaseOptions{
		Config: baseTestConfig(t), Keyring: newTestKeyring(t), Migrate: true,
		Logger: baseTestLogger(), Now: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("OpenBase: %v", err)
	}
	t.Cleanup(func() { _ = base.Close(context.Background()) })
	catalog, err := newPresetPermissionCatalog()
	if err != nil {
		t.Fatalf("权限实现目录: %v", err)
	}
	checker := reauthPermissionChecker{catalog: catalog,
		now: func() time.Time { return testNow }}
	base.Store.DB().SetMaxOpenConns(1)

	mustExec := func(query string, args ...any) {
		t.Helper()
		if _, err := base.Store.DB().ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("夹具 SQL 失败: %v\n%s", err, query)
		}
	}
	nowMS := testNow.UnixMilli()
	// 账户：active、无有效期限制。
	mustExec(`INSERT INTO users(id,username,username_normalized,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'active',0,1,1,?,?)`, checkerUserID, "checker-user", "checker-user", nowMS, nowMS)
	// 权限行（系统范围、启用、非 root_only）；roles.read 在预设目录中已实现。
	mustExec(`INSERT INTO permissions(id,scope_id,permission_key,name,description,
limits_text,is_builtin,root_only,enabled,created_at_ms,updated_at_ms)
VALUES(?,'system',?,?,?,'',1,0,1,?,?)`, checkerPermissionID, checkerKey,
		"读取用户", "读取用户", nowMS, nowMS)
	mustExec(`INSERT INTO roles(id,scope_id,role_key,name,description,limits_text,
is_builtin,enabled,created_at_ms,updated_at_ms)
VALUES(?,'system','checker-role','检查角色','','',0,1,?,?)`, checkerRoleID, nowMS, nowMS)
	// 用户直授角色 + 角色-权限关联。
	mustExec(`INSERT INTO user_roles(user_id,role_id,scope_id,data_scope_json,assigned_by,
created_at_ms) VALUES(?,?,'system','{}','test',?)`, checkerUserID, checkerRoleID, nowMS)
	mustExec(`INSERT INTO role_permissions(role_id,permission_id,scope_id)
VALUES(?,?,'system')`, checkerRoleID, checkerPermissionID)

	check := func() error {
		t.Helper()
		var checkErr error
		err := base.Audit.ExecuteCritical(ctx, audit.CriticalRequest{
			Event: audit.Event{
				Actor:  audit.Actor{Type: audit.ActorUser, ID: checkerUserID},
				Action: "test.proof_permission_check",
				Target: audit.Target{Type: "user", ID: checkerUserID},
			},
			FailureReasonCode: "test_check_failed",
		}, func(txCtx context.Context, tx audit.Tx) error {
			checkErr = checker.CheckOperationPermissionTx(txCtx, tx, checkerUserID, checkerKey)
			return checkErr
		})
		if err != nil && checkErr == nil {
			checkErr = err
		}
		return checkErr
	}

	// 1) 正常授权：允许。
	if err := check(); err != nil {
		t.Fatalf("正常角色授权应允许: %v", err)
	}
	// 2) F1：角色保持启用，仅删除角色-权限关联 → 必须拒绝。
	mustExec(`DELETE FROM role_permissions WHERE role_id=? AND permission_id=?`,
		checkerRoleID, checkerPermissionID)
	if err := check(); err == nil {
		t.Fatal("F1：角色-权限关联被移除后仍通过终检（必须拒绝）")
	}
	// 3) 恢复用户角色授权；再用“用户组”路径验证 JOIN 覆盖 group_roles。
	mustExec(`INSERT INTO role_permissions(role_id,permission_id,scope_id)
VALUES(?,?,'system')`, checkerRoleID, checkerPermissionID)
	mustExec(`DELETE FROM user_roles WHERE user_id=? AND role_id=?`, checkerUserID, checkerRoleID)
	mustExec(`INSERT INTO user_groups(id,scope_id,group_key,name,description,
created_at_ms,updated_at_ms) VALUES(?,'system','checker-group','检查组','',?,?)`,
		checkerGroupID, nowMS, nowMS)
	mustExec(`INSERT INTO group_roles(group_id,role_id,scope_id,data_scope_json,created_at_ms)
VALUES(?,?,'system','{}',?)`, checkerGroupID, checkerRoleID, nowMS)
	mustExec(`INSERT INTO group_members(group_id,user_id,created_at_ms)
VALUES(?,?,?)`, checkerGroupID, checkerUserID, nowMS)
	if err := check(); err != nil {
		t.Fatalf("用户组继承路径应允许: %v", err)
	}
	// 4) N-255-7：注入时钟。valid_until=testNow+24h；真实墙钟已晚于该时刻，
	//    只有使用注入时钟才会判定“未到期 → 允许”。
	futureUntil := testNow.Add(24 * time.Hour).UnixMilli()
	mustExec(`UPDATE users SET valid_until_ms=? WHERE id=?`, futureUntil, checkerUserID)
	if err := check(); err != nil {
		t.Fatalf("有效期未到期（注入时钟）应允许，实际 %v（可能未使用注入时钟）", err)
	}
	// 5) 尚未生效（valid_from 在未来）→ 拒绝。
	mustExec(`UPDATE users SET valid_until_ms=NULL,valid_from_ms=? WHERE id=?`,
		testNow.Add(time.Hour).UnixMilli(), checkerUserID)
	if err := check(); err == nil {
		t.Fatal("账户尚未生效仍通过终检（必须拒绝）")
	}
	// 6) root 分支保持目录/启停语义：root 无需角色关联；权限行停用后拒绝。
	mustExec(`UPDATE users SET valid_from_ms=NULL,is_root=1 WHERE id=?`, checkerUserID)
	if err := check(); err != nil {
		t.Fatalf("root 正常权限应允许: %v", err)
	}
	mustExec(`UPDATE permissions SET enabled=0 WHERE id=?`, checkerPermissionID)
	if err := check(); err == nil {
		t.Fatal("root 在权限行停用后仍通过终检（必须拒绝）")
	}
}
