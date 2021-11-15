package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

func openMigratedStore(t *testing.T) *storagesqlite.Store {
	t.Helper()
	ctx := context.Background()
	// 用带重试清理的测试临时目录替代 t.TempDir：Windows 上目录删除可能被安全
	// 软件/文件过滤驱动瞬时延迟，标准库清理不重试 ERROR_DIR_NOT_EMPTY。
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(filepath.Join(testTempDir(t), "app.sqlite")))
	if err != nil {
		t.Fatalf("打开临时数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	migrationSet, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移失败: %v", err)
	}
	if _, err := raw.Migrate(ctx, migrationSet); err != nil {
		t.Fatalf("执行迁移失败: %v", err)
	}
	return raw
}

func TestNewValidation(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("空存储应被拒绝")
	}
}

func TestScopeConsistencyAndQueries(t *testing.T) {
	raw := openMigratedStore(t)
	store, err := New(raw)
	if err != nil {
		t.Fatalf("构造仓储失败: %v", err)
	}
	ctx := context.Background()
	now := int64(1_700_000_000_000)
	appID := "app_00000000000000000000000000000001"
	// 插入应用但故意缺少 scope：读取必须 fail-closed。
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO applications(id,name,description,icon_ref,homepage,owner_user_id,contact_info,status,client_type,row_version,created_at_ms,updated_at_ms)
VALUES(?,?, '',NULL,NULL,NULL,NULL,'disabled','public',1,?,?)`, appID, "无 scope", now, now); err != nil {
		t.Fatalf("插入应用失败: %v", err)
	}
	if _, err := store.GetApplication(ctx, appID); !errors.Is(err, app.ErrStoreUnavailable) {
		t.Fatalf("缺少 scope 的应用错误 = %v，期望 ErrStoreUnavailable", err)
	}
	if _, err := raw.ExecContext(ctx, `INSERT INTO scopes(id,kind,app_id) VALUES(?,'application',?)`, appID, appID); err != nil {
		t.Fatalf("插入 scope 失败: %v", err)
	}
	application, err := store.GetApplication(ctx, appID)
	if err != nil {
		t.Fatalf("读取应用失败: %v", err)
	}
	if application.ScopeID != appID || application.Status != app.StatusDisabled {
		t.Errorf("应用 = %+v", application)
	}
	if _, _, err := store.ListApplications(ctx, app.ListQuery{Limit: 10, Sort: "client_type"}); !errors.Is(err, app.ErrInvalidRequest) {
		t.Fatalf("非法排序错误 = %v", err)
	}
	list, hasMore, err := store.ListApplications(ctx, app.ListQuery{Limit: 10, Sort: app.SortCreatedAt, AllApplications: true})
	if err != nil || hasMore || len(list) != 1 || list[0].ID != appID {
		t.Fatalf("列表 = %+v, hasMore=%v, err=%v", list, hasMore, err)
	}
	// 用户是否存在且可用。
	userID := "usr_00000000000000000000000000000001"
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO users(id,username,username_normalized,nickname,biography,language,timezone,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'','','zh-CN','Asia/Shanghai','active',0,1,1,?,?)`, userID, "owner", "owner", now, now); err != nil {
		t.Fatalf("插入用户失败: %v", err)
	}
	eligible, err := store.UserEligibleAsOwner(ctx, userID)
	if err != nil || !eligible {
		t.Fatalf("可用负责人检查 = %v, %v", eligible, err)
	}
	if eligible, err := store.UserEligibleAsOwner(ctx, "usr_ffffffffffffffffffffffffffffffff"); err != nil || eligible {
		t.Fatalf("不存在负责人检查 = %v, %v", eligible, err)
	}
}
