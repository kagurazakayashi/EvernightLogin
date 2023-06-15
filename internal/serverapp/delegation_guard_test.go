// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightMail is licensed under Mulan PSL v2.

package serverapp

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	bootstrapsqlite "github.com/kagurazakayashi/EvernightLogin/internal/bootstrap/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestProductionDelegationGuardRootAndTrustedBypass 验证 149 的 root-aware 包装：
// root（ActorUser）/本地/system 受信主体放行，未知/普通主体交给真实委派引擎且
// 无资格时拒绝；包装器不会全放行。
func TestProductionDelegationGuardRootAndTrustedBypass(t *testing.T) {
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx,
		storagesqlite.DefaultOptions(filepath.Join(testutil.TempDir(t), "guard.sqlite")))
	if err != nil {
		t.Fatalf("打开临时数据库: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	migrationSet, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := raw.Migrate(ctx, migrationSet); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	const rootID = "usr_44444444444444444444444444444444"
	const ordinaryID = "usr_11111111111111111111111111111111"
	nowMS := time.Now().UTC().UnixMilli()
	if _, err := raw.DB().ExecContext(ctx, `INSERT INTO users(
		id,username,username_normalized,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
		VALUES(?,?,?,'active',1,2,1,?,?)`, rootID, "root", "root", nowMS, nowMS); err != nil {
		t.Fatalf("插入 root 用户: %v", err)
	}
	if _, err := raw.DB().ExecContext(ctx, `INSERT INTO users(
		id,username,username_normalized,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
		VALUES(?,?,?,'active',0,1,1,?,?)`, ordinaryID, "ordinary", "ordinary", nowMS, nowMS); err != nil {
		t.Fatalf("插入普通用户: %v", err)
	}
	bootstrapStore, err := bootstrapsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造初始化存储: %v", err)
	}
	roots, err := newHostRootChecker(bootstrapStore)
	if err != nil {
		t.Fatalf("构造 root 识别器: %v", err)
	}
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造审计存储: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{Now: time.Now})
	if err != nil {
		t.Fatalf("构造审计记录器: %v", err)
	}
	engine, err := newDelegationService(Deps{
		Store: raw, Audit: recorder, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("构造委派服务: %v", err)
	}
	guard := productionDelegationGuard{roots: roots, engine: engine}
	scope := delegation.ScopeSystem
	permission := delegation.PermissionRef{PermissionID: "perm_11111111111111111111111111111111"}
	target := delegation.Target{Kind: delegation.TargetUser, ID: ordinaryID}
	targets := []delegation.Target{target}

	root := audit.Actor{Type: audit.ActorUser, ID: rootID}
	for name, check := range map[string]func() error{
		"access": func() error {
			return guard.CheckPermissionAccess(ctx, nil, root, scope, []delegation.PermissionRef{permission}, targets)
		},
		"assignment": func() error {
			return guard.CheckAssignment(ctx, nil, root, scope, []delegation.PermissionRef{permission}, target)
		},
		"activation": func() error {
			return guard.CheckPermissionActivation(ctx, nil, root, scope, []delegation.PermissionRef{permission}, targets)
		},
		"restoration": func() error { return guard.CheckScopeRestoration(ctx, nil, root, scope) },
	} {
		if err := check(); err != nil {
			t.Errorf("root 应放行 %s: %v", name, err)
		}
	}
	for _, actor := range []audit.Actor{
		{Type: audit.ActorLocalAdmin, ID: "test.local-admin"},
		{Type: audit.ActorSystem, ID: "system-test"},
	} {
		if err := guard.CheckAssignment(ctx, nil, actor, scope,
			[]delegation.PermissionRef{permission}, target); err != nil {
			t.Errorf("受信主体 %s 应放行: %v", actor.Type, err)
		}
	}
	ordinary := audit.Actor{Type: audit.ActorUser, ID: ordinaryID}
	if err := guard.CheckAssignment(ctx, nil, ordinary, scope,
		[]delegation.PermissionRef{permission}, target); err == nil {
		t.Fatal("普通主体无委派资格时不得放行（包装器不能全放行）")
	}
	if err := guard.CheckPermissionActivation(ctx, nil, ordinary, scope,
		[]delegation.PermissionRef{permission}, targets); err == nil {
		t.Fatal("普通主体无委派资格时不得通过启用检查")
	}
	// 缺少 root/engine 依赖必须 fail-closed，不得因 nil 而误放行。
	emptyGuard := productionDelegationGuard{}
	if err := emptyGuard.CheckAssignment(ctx, nil, ordinary, scope,
		[]delegation.PermissionRef{permission}, target); err == nil {
		t.Fatal("未装配 root/engine 的包装器必须拒绝")
	}
}
