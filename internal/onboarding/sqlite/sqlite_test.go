package sqlite_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/onboarding"
	onboardingsqlite "github.com/kagurazakayashi/EvernightLogin/internal/onboarding/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

var testStart = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

// TestStoreInvitationLifecycle 用真实 SQLite 覆盖邀请创建/读取/取消/列表、角色可
// 分配性校验与目标既有权限读取（不经服务层替身）。
func TestStoreInvitationLifecycle(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(testutil.TempDir(t), "onboarding-sqlite-test.db")
	storage, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(path))
	if err != nil {
		t.Fatalf("打开数据库: %v", err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	migrationList, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := storage.Migrate(ctx, migrationList); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	auditStore, err := auditsqlite.New(storage)
	if err != nil {
		t.Fatalf("审计存储: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{Now: func() time.Time { return testStart }})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	store, err := onboardingsqlite.New(storage)
	if err != nil {
		t.Fatalf("入驻存储: %v", err)
	}
	inviterID := "usr_00000000000000000000000000000001"
	now := testStart.UnixMilli()
	if _, err := storage.DB().ExecContext(ctx, `INSERT INTO users(id,username,username_normalized,nickname,biography,avatar_ref,language,timezone,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'','',NULL,'zh-CN','Asia/Shanghai','active',0,1,1,?,?)`, inviterID, "inviter", "inviter", now, now); err != nil {
		t.Fatalf("用户: %v", err)
	}
	if _, err := storage.DB().ExecContext(ctx, `INSERT INTO roles(id,scope_id,role_key,name,description,limits_text,is_builtin,enabled,created_at_ms,updated_at_ms)
VALUES('role_member','system','role_member','member','','',0,1,?,?)`, now, now); err != nil {
		t.Fatalf("角色: %v", err)
	}
	record := onboarding.InvitationRecord{
		ID: "inv_00000000000000000000000000000001", InviterUserID: inviterID,
		TargetKind: onboarding.TargetEmail, TargetEmail: "target@example.test",
		Roles:   []onboarding.Role{{RoleID: "role_member", ScopeID: "system"}},
		MaxUses: 1, ExpiresAt: testStart.Add(time.Hour), Now: testStart,
	}
	// 角色可分配性：合法角色通过，未知角色拒绝。
	if err := recorder.ExecuteCritical(ctx, audit.CriticalRequest{
		Event: audit.Event{Actor: audit.Actor{Type: audit.ActorSystem, ID: "test"},
			Action: "test.invitation_seed", Target: audit.Target{Type: "invitation", ID: record.ID}},
	}, func(txCtx context.Context, tx audit.Tx) error {
		if err := store.RoleAssignableTx(txCtx, tx, record.Roles); err != nil {
			return err
		}
		return store.CreateInvitation(txCtx, tx, record)
	}); err != nil {
		t.Fatalf("创建邀请: %v", err)
	}
	loaded, found, err := store.GetInvitation(ctx, record.ID)
	if err != nil || !found {
		t.Fatalf("读取邀请: %v %v", err, found)
	}
	if loaded.TargetEmail != "target@example.test" || len(loaded.Roles) != 1 ||
		loaded.Status != onboarding.InvitationPending || loaded.NotifyState != onboarding.NotifyPending {
		t.Fatalf("邀请快照 = %+v", loaded)
	}
	list, err := store.ListInvitations(ctx, inviterID, onboarding.ListRequest{Limit: 10})
	if err != nil || len(list.Invitations) != 1 {
		t.Fatalf("邀请列表: %v %d", err, len(list.Invitations))
	}
	if err := recorder.ExecuteCritical(ctx, audit.CriticalRequest{
		Event: audit.Event{Actor: audit.Actor{Type: audit.ActorUser, ID: inviterID},
			Action: "test.invitation_cancel", Target: audit.Target{Type: "invitation", ID: record.ID}},
	}, func(txCtx context.Context, tx audit.Tx) error {
		cancelled, err := store.CancelInvitation(txCtx, tx, onboarding.CancelParams{
			InvitationID: record.ID, Reason: "test", Now: testStart,
			Actor: audit.Actor{Type: audit.ActorUser, ID: inviterID},
		})
		if err != nil {
			return err
		}
		if !cancelled {
			return errors.New("取消未生效")
		}
		return nil
	}); err != nil {
		t.Fatalf("取消邀请: %v", err)
	}
	loaded, _, err = store.GetInvitation(ctx, record.ID)
	if err != nil || loaded.Status != onboarding.InvitationCancelled {
		t.Fatalf("取消后状态 = %+v %v", loaded.Status, err)
	}
	// 角色可分配性接口存在且能识别未知角色。
	var reader onboarding.RoleAssignableReader = store
	if err := recorder.ExecuteCritical(ctx, audit.CriticalRequest{
		Event: audit.Event{Actor: audit.Actor{Type: audit.ActorSystem, ID: "test"},
			Action: "test.role_check", Target: audit.Target{Type: "invitation", ID: record.ID}},
	}, func(txCtx context.Context, tx audit.Tx) error {
		if err := reader.RoleAssignableTx(txCtx, tx,
			[]onboarding.Role{{RoleID: "role_missing", ScopeID: "system"}}); err == nil {
			return errors.New("未知角色不应通过可分配性检查")
		}
		return nil
	}); err != nil {
		t.Fatalf("角色可分配性检查: %v", err)
	}
	_ = account.StatusActive
}
