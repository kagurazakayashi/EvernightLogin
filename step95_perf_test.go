package login_test

// 步骤 95 性能探针：对代表性路径做小规模、单进程、串行测量，不做压测。
//
// 覆盖（均在隔离临时目录内，不读写 database/login.db、不监听端口、不联网）：
//  1. 密码哈希与校验（登录关键路径，Argon2id 默认参数）；
//  2. 登录标识与邮箱规范化（认证入口的输入归一化）；
//  3. SQLite 冷启动迁移、简单列表查询与事务写入（存储/列表代表路径）；
//  4. 认证加密信封 Seal/Open（备份与秘密存储代表路径）。
//
// 运行方式（项目根目录，Windows 11 amd64 / Go 1.27.4）：
//
//	GOMAXPROCS=2 CGO_ENABLED=0 go test -count=1 -p 1 -run 'TestStep95Perf' -v .
//
// 说明：本探针只报告本机单次测量事实，不代表生产容量；不构成基线承诺。

import (
	"context"
	"crypto/rand"
	"database/sql"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// step95PerfAvg 返回样本总耗时与单次平均（毫秒），样本数必须大于 0。
func step95PerfAvg(total time.Duration, n int) float64 {
	return float64(total.Microseconds()) / 1000.0 / float64(n)
}

// TestStep95PerfPasswordHash 测量默认 Argon2id 参数下的一次哈希与一次校验耗时。
func TestStep95PerfPasswordHash(t *testing.T) {
	const rounds = 5
	const plain = "correct-horse-battery-staple-step95"
	params := authn.DefaultParams()
	if err := params.Validate(); err != nil {
		t.Fatalf("默认哈希参数非法：%v", err)
	}

	var encoded string
	hashStart := time.Now()
	for i := 0; i < rounds; i++ {
		value, err := authn.HashPassword(plain, params, nil)
		if err != nil {
			t.Fatalf("哈希失败：%v", err)
		}
		encoded = value
	}
	hashElapsed := time.Since(hashStart)

	verifyStart := time.Now()
	for i := 0; i < rounds; i++ {
		result, err := authn.VerifyPassword(encoded, plain)
		if err != nil {
			t.Fatalf("校验失败：%v", err)
		}
		if !result.Matched {
			t.Fatalf("正确密码未匹配")
		}
	}
	verifyElapsed := time.Since(verifyStart)

	wrongStart := time.Now()
	wrong, err := authn.VerifyPassword(encoded, plain+"-wrong")
	if err != nil {
		t.Fatalf("错误密码校验返回错误：%v", err)
	}
	wrongElapsed := time.Since(wrongStart)
	if wrong.Matched {
		t.Fatalf("错误密码被判定匹配")
	}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, err := authn.HashPassword(plain, params, nil); err != nil {
		t.Fatalf("哈希失败：%v", err)
	}
	runtime.ReadMemStats(&after)

	t.Logf("PASSWORD_HASH params=%s rounds=%d avg_ms=%.2f", params.String(), rounds,
		step95PerfAvg(hashElapsed, rounds))
	t.Logf("PASSWORD_VERIFY rounds=%d avg_ms=%.2f", rounds, step95PerfAvg(verifyElapsed, rounds))
	t.Logf("PASSWORD_VERIFY_WRONG one_ms=%.2f", step95PerfAvg(wrongElapsed, 1))
	t.Logf("PASSWORD_HASH heap_delta_bytes=%d", int64(after.HeapAlloc)-int64(before.HeapAlloc))
}

// TestStep95PerfIdentifierNormalization 测量认证入口标识/邮箱规范化的单次成本。
func TestStep95PerfIdentifierNormalization(t *testing.T) {
	const rounds = 20000
	email := "User.Step95@Example.Test"
	username := "  Step95_User  "
	identifier := "user.step95@example.test"

	emailStart := time.Now()
	for i := 0; i < rounds; i++ {
		if _, _, err := authn.NormalizeEmail(email); err != nil {
			t.Fatalf("邮箱规范化失败：%v", err)
		}
	}
	emailElapsed := time.Since(emailStart)

	userStart := time.Now()
	for i := 0; i < rounds; i++ {
		if _, _, err := authn.NormalizeLoginUsername(username); err != nil {
			t.Fatalf("用户名规范化失败：%v", err)
		}
	}
	userElapsed := time.Since(userStart)

	parseStart := time.Now()
	for i := 0; i < rounds; i++ {
		if _, err := authn.ParseIdentifier(identifier); err != nil {
			t.Fatalf("标识解析失败：%v", err)
		}
	}
	parseElapsed := time.Since(parseStart)

	emailNs := float64(emailElapsed.Nanoseconds()) / float64(rounds)
	userNs := float64(userElapsed.Nanoseconds()) / float64(rounds)
	parseNs := float64(parseElapsed.Nanoseconds()) / float64(rounds)
	t.Logf("IDENTIFIER_NORMALIZE rounds=%d email_ns=%.0f username_ns=%.0f parse_ns=%.0f",
		rounds, emailNs, userNs, parseNs)
}

// TestStep95PerfSQLiteStartupAndAccess 测量临时 SQLite 冷启动迁移、简单读查询与事务写入。
func TestStep95PerfSQLiteStartupAndAccess(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "step95-perf.db")

	openStart := time.Now()
	store, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(path))
	if err != nil {
		t.Fatalf("打开临时 SQLite 失败：%v", err)
	}
	openElapsed := time.Since(openStart)
	t.Cleanup(func() { _ = store.Close() })

	loadStart := time.Now()
	list, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移失败：%v", err)
	}
	loadElapsed := time.Since(loadStart)

	migrateStart := time.Now()
	result, err := store.Migrate(ctx, list)
	if err != nil {
		t.Fatalf("执行迁移失败：%v", err)
	}
	migrateElapsed := time.Since(migrateStart)

	const readRounds = 500
	readStart := time.Now()
	for i := 0; i < readRounds; i++ {
		var count int
		if err := store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events`).Scan(&count); err != nil {
			t.Fatalf("读查询失败：%v", err)
		}
	}
	readElapsed := time.Since(readStart)

	if _, err := store.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS step95_perf(id INTEGER PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		t.Fatalf("创建探针表失败：%v", err)
	}
	const writeRounds = 200
	writeStart := time.Now()
	err = store.Transaction(ctx, func(ctx context.Context, tx *sql.Tx) error {
		statement, err := tx.PrepareContext(ctx, `INSERT INTO step95_perf(value) VALUES(?)`)
		if err != nil {
			return err
		}
		defer func() { _ = statement.Close() }()
		for i := 0; i < writeRounds; i++ {
			if _, err := statement.ExecContext(ctx, "step95-value"); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("事务写入失败：%v", err)
	}
	writeElapsed := time.Since(writeStart)

	t.Logf("SQLITE_OPEN ms=%.2f", step95PerfAvg(openElapsed, 1))
	t.Logf("SQLITE_MIGRATION_LOAD ms=%.2f applied=%d", step95PerfAvg(loadElapsed, 1), len(result.Applied))
	t.Logf("SQLITE_MIGRATION_RUN ms=%.2f", step95PerfAvg(migrateElapsed, 1))
	t.Logf("SQLITE_READ_SELECT_COUNT rounds=%d avg_ms=%.3f", readRounds,
		step95PerfAvg(readElapsed, readRounds))
	t.Logf("SQLITE_TX_INSERT rows=%d avg_ms=%.3f", writeRounds,
		step95PerfAvg(writeElapsed, writeRounds))
}

// TestStep95PerfSecretEnvelope 测量 4 KiB 认证加密信封的 Seal/Open 单次成本。
func TestStep95PerfSecretEnvelope(t *testing.T) {
	ring, err := secrets.GenerateKeyring("k_step95", time.Date(2026, 11, 20, 4, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("生成密钥环失败：%v", err)
	}
	sealer, err := secrets.NewSealer(ring, nil)
	if err != nil {
		t.Fatalf("创建 Sealer 失败：%v", err)
	}
	binding := secrets.Binding{Purpose: "step95.perf", ObjectID: "obj_step95", ScopeID: "system"}
	plain := make([]byte, 4096)
	if _, err := rand.Read(plain); err != nil {
		t.Fatalf("生成随机明文失败：%v", err)
	}

	const rounds = 200
	sealStart := time.Now()
	sealed := make([][]byte, 0, rounds)
	for i := 0; i < rounds; i++ {
		value, err := sealer.Seal(binding, plain)
		if err != nil {
			t.Fatalf("Seal 失败：%v", err)
		}
		sealed = append(sealed, value)
	}
	sealElapsed := time.Since(sealStart)

	openStart := time.Now()
	for i := 0; i < rounds; i++ {
		value, err := sealer.Open(binding, sealed[i])
		if err != nil {
			t.Fatalf("Open 失败：%v", err)
		}
		if len(value) != len(plain) {
			t.Fatalf("Open 明文长度不符：%d", len(value))
		}
	}
	openElapsed := time.Since(openStart)

	t.Logf("SECRET_ENVELOPE seal_bytes=4096 rounds=%d avg_ms=%.3f", rounds,
		step95PerfAvg(sealElapsed, rounds))
	t.Logf("SECRET_ENVELOPE open_bytes=4096 rounds=%d avg_ms=%.3f", rounds,
		step95PerfAvg(openElapsed, rounds))
}
