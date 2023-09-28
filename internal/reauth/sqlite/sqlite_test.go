// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package sqlite_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	reauthsqlite "github.com/kagurazakayashi/EvernightLogin/internal/reauth/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const testUserID = "usr_99999999999999999999999999999999"

// newNotificationStore 打开临时 SQLite、应用全部迁移并写入一个用户（外键前置）。
func newNotificationStore(t *testing.T) (*reauthsqlite.Store, *storagesqlite.Store) {
	t.Helper()
	ctx := context.Background()
	storage, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(testutil.TempDir(t), "reauth-notification.db")))
	if err != nil {
		t.Fatalf("打开数据库: %v", err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	list, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := storage.Migrate(ctx, list); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	now := time.Now().UTC().UnixMilli()
	if _, err := storage.DB().ExecContext(ctx, `INSERT INTO users(
id,username,username_normalized,nickname,biography,avatar_ref,language,timezone,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms
) VALUES(?,?,?,'','',NULL,'zh-CN','Asia/Shanghai','active',0,1,1,?,?)`,
		testUserID, "notice-user", "notice-user", now, now); err != nil {
		t.Fatalf("写入测试用户: %v", err)
	}
	store, err := reauthsqlite.New(storage)
	if err != nil {
		t.Fatalf("构造通知存储: %v", err)
	}
	return store, storage
}

// notificationRecord 构造一条合法的告知记录。
func notificationRecord(dedupKey string) reauth.NotificationRecord {
	return reauth.NotificationRecord{
		ID: "ntf_00000000000000000000000000000001", UserID: testUserID,
		OperationID: "password.change", TargetType: "user", TargetID: testUserID,
		Outcome: reauth.OutcomeSuccess, State: reauth.NotificationQueued,
		RecipientMasked: "n***@example.test", CreatedAt: time.Now().UTC(),
		DedupKey: dedupKey,
	}
}

// TestUpsertNotificationIdempotentAndPreservesDelivery 验证原子幂等写入：
// 同一 dedup_key 只保留一行；非空 delivery_id 覆盖、空的保留旧值。
func TestUpsertNotificationIdempotentAndPreservesDelivery(t *testing.T) {
	store, storage := newNotificationStore(t)
	ctx := context.Background()

	first := notificationRecord("security-notice-aaaaaaaaaaaaaaaa")
	first.DeliveryID = "mdl_00000000000000000000000000000001"
	if err := store.UpsertNotification(ctx, first); err != nil {
		t.Fatalf("首次写入: %v", err)
	}
	// 幂等重放：同一 dedup_key、空 delivery_id 不得清空已保存的投递标识。
	replay := notificationRecord("security-notice-aaaaaaaaaaaaaaaa")
	replay.State = reauth.NotificationFailed
	replay.ErrorCode = "delivery_enqueue_failed"
	if err := store.UpsertNotification(ctx, replay); err != nil {
		t.Fatalf("幂等重放: %v", err)
	}
	var count int
	if err := storage.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM security_notifications WHERE dedup_key=?`,
		"security-notice-aaaaaaaaaaaaaaaa").Scan(&count); err != nil {
		t.Fatalf("统计行数: %v", err)
	}
	if count != 1 {
		t.Fatalf("同一 dedup_key 记录数 = %d，期望 1", count)
	}
	var state, deliveryID string
	if err := storage.DB().QueryRowContext(ctx,
		`SELECT state,COALESCE(delivery_id,'') FROM security_notifications WHERE dedup_key=?`,
		"security-notice-aaaaaaaaaaaaaaaa").Scan(&state, &deliveryID); err != nil {
		t.Fatalf("读取记录: %v", err)
	}
	if state != string(reauth.NotificationFailed) || deliveryID == "" {
		t.Fatalf("幂等重放后 state=%q delivery_id=%q（期望 failed 且保留投递标识）", state, deliveryID)
	}
	// 带新 delivery_id 的更新可以覆盖旧值。
	relink := notificationRecord("security-notice-aaaaaaaaaaaaaaaa")
	relink.DeliveryID = "mdl_00000000000000000000000000000002"
	if err := store.UpsertNotification(ctx, relink); err != nil {
		t.Fatalf("更新投递标识: %v", err)
	}
	if err := storage.DB().QueryRowContext(ctx,
		`SELECT COALESCE(delivery_id,'') FROM security_notifications WHERE dedup_key=?`,
		"security-notice-aaaaaaaaaaaaaaaa").Scan(&deliveryID); err != nil {
		t.Fatalf("读取投递标识: %v", err)
	}
	if deliveryID != "mdl_00000000000000000000000000000002" {
		t.Fatalf("投递标识 = %q，期望被非空新值覆盖", deliveryID)
	}
}

// TestUpsertNotificationConstraintFailureIsFailClosed 验证非 dedup_key 约束失败时
// 必须返回错误且不留下任何行/不改既有行（安全审计 N1：禁止静默 fail-open）。
func TestUpsertNotificationConstraintFailureIsFailClosed(t *testing.T) {
	store, storage := newNotificationStore(t)
	ctx := context.Background()

	invalid := notificationRecord("security-notice-bbbbbbbbbbbbbbbb")
	invalid.State = reauth.NotificationState("bogus_state") // 违反 CHECK 约束
	if err := store.UpsertNotification(ctx, invalid); err == nil {
		t.Fatal("非法状态写入必须返回错误（fail-closed）")
	}
	var count int
	if err := storage.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM security_notifications`).Scan(&count); err != nil {
		t.Fatalf("统计行数: %v", err)
	}
	if count != 0 {
		t.Fatalf("约束失败后残留 %d 行，期望 0", count)
	}

	// 已存在同一 dedup_key 时，非法更新也必须失败且不破坏既有行。
	valid := notificationRecord("security-notice-cccccccccccccccc")
	if err := store.UpsertNotification(ctx, valid); err != nil {
		t.Fatalf("写入合法记录: %v", err)
	}
	invalidUpdate := notificationRecord("security-notice-cccccccccccccccc")
	invalidUpdate.State = reauth.NotificationState("bogus_state")
	if err := store.UpsertNotification(ctx, invalidUpdate); err == nil {
		t.Fatal("非法更新必须返回错误")
	}
	var state string
	if err := storage.DB().QueryRowContext(ctx,
		`SELECT state FROM security_notifications WHERE dedup_key=?`,
		"security-notice-cccccccccccccccc").Scan(&state); err != nil {
		t.Fatalf("读取既有记录: %v", err)
	}
	if state != string(reauth.NotificationQueued) {
		t.Fatalf("既有记录状态 = %q，期望保持不变", state)
	}
}
