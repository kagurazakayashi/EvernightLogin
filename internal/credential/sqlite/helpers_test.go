package sqlite_test

import (
	"context"
	"database/sql"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	credentialsqlite "github.com/kagurazakayashi/EvernightLogin/internal/credential/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	testAppA = "app_alpha"
	testAppB = "app_beta"
)

// testBaseTime 是所有测试的固定基准时间（UTC）。
var testBaseTime = time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)

// fakeClock 是可注入的测试时钟。
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

// Now 返回当前测试时间。
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance 前进时间。
func (c *fakeClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

// testEnv 汇总一次测试使用的临时 SQLite 数据库、生产仓储、服务与时钟。
type testEnv struct {
	t           *testing.T
	sqliteStore *storagesqlite.Store
	store       *credentialsqlite.Store
	service     *credential.Service
	clock       *fakeClock
	ring        *secrets.Keyring
}

// envConfig 允许测试替换密钥环或日志器。
type envConfig struct {
	ring   *secrets.Keyring
	logger *slog.Logger
}

// newTestEnv 在临时目录创建数据库、执行全部迁移并构造生产 SQLite 仓储与服务。
func newTestEnv(t *testing.T, config envConfig) *testEnv {
	t.Helper()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "credential.sqlite")
	rawStore, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(dbPath))
	if err != nil {
		t.Fatalf("打开临时 SQLite 数据库失败: %v", err)
	}
	t.Cleanup(func() {
		_ = rawStore.Close()
	})
	migrationSet, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移失败: %v", err)
	}
	if _, err := rawStore.Migrate(ctx, migrationSet); err != nil {
		t.Fatalf("执行迁移失败: %v", err)
	}
	ring := config.ring
	if ring == nil {
		ring, err = secrets.GenerateKeyring("k1", testBaseTime)
		if err != nil {
			t.Fatalf("GenerateKeyring 失败: %v", err)
		}
	}
	store, err := credentialsqlite.New(rawStore)
	if err != nil {
		t.Fatalf("构造 SQLite 仓储失败: %v", err)
	}
	clock := &fakeClock{now: testBaseTime}
	service, err := credential.New(store, credential.Options{
		Keyring: ring,
		Now:     clock.Now,
		Logger:  config.logger,
	})
	if err != nil {
		t.Fatalf("构造凭证服务失败: %v", err)
	}
	return &testEnv{
		t:           t,
		sqliteStore: rawStore,
		store:       store,
		service:     service,
		clock:       clock,
		ring:        ring,
	}
}

// serviceWith 用同一存储但不同密钥环/日志器构造新的服务，用于密钥轮换测试。
func (e *testEnv) serviceWith(ring *secrets.Keyring, logger *slog.Logger) *credential.Service {
	e.t.Helper()
	service, err := credential.New(e.store, credential.Options{
		Keyring: ring,
		Now:     e.clock.Now,
		Logger:  logger,
	})
	if err != nil {
		e.t.Fatalf("构造凭证服务失败: %v", err)
	}
	return service
}

// insertApplication 插入测试应用；应用绑定外键要求应用存在。
func (e *testEnv) insertApplication(appID string) {
	e.t.Helper()
	_, err := e.sqliteStore.ExecContext(context.Background(),
		`INSERT INTO applications(id,name,client_type,status,created_at_ms,updated_at_ms) VALUES(?,?,'confidential','active',?,?)`,
		appID, "测试应用 "+appID, testBaseTime.UnixMilli(), testBaseTime.UnixMilli())
	if err != nil {
		e.t.Fatalf("插入测试应用失败: %v", err)
	}
}

// issue 调用服务签发凭证。
func (e *testEnv) issue(request credential.IssueRequest) credential.IssuedCredential {
	e.t.Helper()
	issued, err := e.service.Issue(context.Background(), request)
	if err != nil {
		e.t.Fatalf("签发失败: %v", err)
	}
	return issued
}

// issueToken 签发默认有效期的高熵令牌。
func (e *testEnv) issueToken(purpose, target, appID string) credential.IssuedCredential {
	e.t.Helper()
	return e.issue(credential.IssueRequest{Purpose: purpose, Target: target, AppID: appID, Kind: credential.KindToken})
}

// issueCode 签发默认有效期的低熵验证码。
func (e *testEnv) issueCode(purpose, target, appID string) credential.IssuedCredential {
	e.t.Helper()
	return e.issue(credential.IssueRequest{Purpose: purpose, Target: target, AppID: appID, Kind: credential.KindCode})
}

// verifyIssued 用签发结果中的绑定信息验证凭证。
func (e *testEnv) verifyIssued(issued credential.IssuedCredential, secret string) (credential.VerifiedCredential, error) {
	return e.service.VerifyAndConsume(context.Background(), credential.VerifyRequest{
		Kind:    issued.Kind,
		ID:      issued.ID,
		Purpose: issued.Purpose,
		Target:  issued.Target,
		AppID:   issued.AppID,
		Secret:  secret,
	})
}

// verify 用显式绑定信息验证凭证（支持错误绑定测试）。
func (e *testEnv) verify(id string, kind credential.Kind, purpose, target, appID, secret string) (credential.VerifiedCredential, error) {
	return e.service.VerifyAndConsume(context.Background(), credential.VerifyRequest{
		Kind:    kind,
		ID:      id,
		Purpose: purpose,
		Target:  target,
		AppID:   appID,
		Secret:  secret,
	})
}

// rowState 返回凭证行的尝试次数、上限、消费/撤销时间与 key_id。
func (e *testEnv) rowState(id string) (attempts, maxAttempts int, consumedAt, revokedAt sql.NullInt64, keyID sql.NullString) {
	e.t.Helper()
	rows, err := e.sqliteStore.QueryContext(context.Background(),
		`SELECT attempts,max_attempts,consumed_at_ms,revoked_at_ms,key_id FROM one_time_credentials WHERE id=?`, id)
	if err != nil {
		e.t.Fatalf("读取凭证状态失败: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		e.t.Fatalf("凭证 %s 不存在", id)
	}
	if err := rows.Scan(&attempts, &maxAttempts, &consumedAt, &revokedAt, &keyID); err != nil {
		e.t.Fatalf("扫描凭证状态失败: %v", err)
	}
	return attempts, maxAttempts, consumedAt, revokedAt, keyID
}

// countCredentials 返回表内凭证总数。
func (e *testEnv) countCredentials() int {
	e.t.Helper()
	rows, err := e.sqliteStore.QueryContext(context.Background(), `SELECT count(*) FROM one_time_credentials`)
	if err != nil {
		e.t.Fatalf("统计凭证数量失败: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		e.t.Fatalf("统计凭证数量没有结果: %v", rows.Err())
	}
	var count int
	if err := rows.Scan(&count); err != nil {
		e.t.Fatalf("扫描凭证数量失败: %v", err)
	}
	return count
}
