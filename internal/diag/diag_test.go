package diag

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/config"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// syntheticSecret 是测试用合成秘密，任何输出/日志出现它即视为泄露。
const syntheticSecret = "SYNTHETIC-DIAG-SECRET-7f3a"
const syntheticToken = "SYNTHETIC-TOKEN-9b2c"
const syntheticEmail = "diag-test@example.test"

// testDB 在临时目录创建真实 SQLite 并执行迁移；返回数据库句柄与路径。
func testDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "diag.db")
	store, err := storagesqlite.Open(context.Background(), storagesqlite.DefaultOptions(path))
	if err != nil {
		t.Fatalf("打开测试数据库: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	list, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := store.Migrate(context.Background(), list); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	return store.DB(), path
}

// seedDiagnosticsRows 写入队列与审计夹具；审计 detail 与 mail 收件人含合成秘密
// 与个人资料，用于验证输出/日志脱敏。
func seedDiagnosticsRows(t *testing.T, db *sql.DB) {
	t.Helper()
	nowMS := time.Now().UTC().UnixMilli()
	for index, state := range []string{"queued", "queued", "running", "failed"} {
		if _, err := db.Exec(`INSERT INTO jobs(id,kind,state,initiated_by_type,
initiated_by_id,timeout_seconds,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?,?)`, "job-"+state+"-"+string(rune('a'+index)), "mail.delivery",
			state, "system", "diag-test", 30, nowMS, nowMS); err != nil {
			t.Fatalf("写入 jobs 夹具: %v", err)
		}
	}
	if _, err := db.Exec(`INSERT INTO mail_deliveries(id,idempotency_key,template_kind,
recipient,owner_type,owner_id,state,sealed_payload,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?,?,?,?)`, "mail-1", "idem-1", "verification", syntheticEmail,
		"user", "usr_00000000000000000000000000000001", "queued",
		[]byte("sealed-"+syntheticSecret), nowMS, nowMS); err != nil {
		t.Fatalf("写入 mail_deliveries 夹具: %v", err)
	}
	detail := `{"smtp_password":"` + syntheticSecret + `","token":"` + syntheticToken +
		`","email":"` + syntheticEmail + `"}`
	requestID := "req_diag_errors_1"
	for index := 0; index < 3; index++ {
		if _, err := db.Exec(`INSERT INTO audit_events(id,occurred_at_ms,actor_type,actor_id,
action,target_type,target_id,outcome,error_code,reason_code,request_id,detail_json)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
			"audit-diag-"+string(rune('a'+index)), nowMS+int64(index), "user",
			"usr_00000000000000000000000000000001", "diag.error", "user", "target-id",
			"failure", "AUTH_FAILED", "bad_credentials", requestID, detail); err != nil {
			t.Fatalf("写入 audit_events 夹具: %v", err)
		}
	}
}

// loggerBuffer 捕获脱敏日志输出。
func loggerBuffer() (*slog.Logger, *bytes.Buffer) {
	buffer := &bytes.Buffer{}
	return slog.New(slog.NewTextHandler(buffer, nil)), buffer
}

// TestSnapshotRedaction 验证诊断快照只输出白名单字段，不泄露秘密/个人资料/路径。
func TestSnapshotRedaction(t *testing.T) {
	db, path := testDB(t)
	seedDiagnosticsRows(t, db)
	logger, logBuffer := loggerBuffer()
	cfg := config.Default()
	collector := New(Options{Config: cfg,
		Build: login.BuildInfo{Version: "test-version", Commit: "abc123",
			BuildTime: "2026-11-25", GoVersion: "go1.27"},
		State: func() string { return "running" }, DB: db, Logger: logger,
		Now: func() time.Time { return time.Unix(1700000000, 0).UTC() }})
	report, err := collector.Snapshot(context.Background(), Scope{})
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if report.Status != StatusOK || report.Storage.Status != StatusOK {
		t.Fatalf("诊断状态异常: %+v", report)
	}
	if report.Version.Version != "test-version" || report.State != "running" {
		t.Fatalf("版本/状态异常: %+v", report.Version)
	}
	if len(report.Queues.Jobs) == 0 || len(report.Queues.MailDeliveries) == 0 {
		t.Fatalf("队列状态缺失: %+v", report.Queues)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("序列化诊断: %v", err)
	}
	output := string(raw) + logBuffer.String()
	for _, forbidden := range []string{syntheticSecret, syntheticToken, syntheticEmail,
		"sealed-", "usr_00000000000000000000000000000001", path,
		"detail_json", "smtp_password"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("诊断输出/日志泄露 %q: %s", forbidden, output)
		}
	}
	if report.Config.FeatureFlags == nil || report.Config.DatabaseDriver == "" {
		t.Fatalf("配置摘要缺失: %+v", report.Config)
	}
}

// TestRelatedErrorsRedactionAndLimit 验证关联错误查询只返回白名单并正确截断。
func TestRelatedErrorsRedactionAndLimit(t *testing.T) {
	db, _ := testDB(t)
	seedDiagnosticsRows(t, db)
	collector := New(Options{DB: db,
		Now: func() time.Time { return time.Unix(1700000000, 0).UTC() }})
	result, err := collector.RelatedErrors(context.Background(), Scope{},
		"req_diag_errors_1", 2)
	if err != nil {
		t.Fatalf("RelatedErrors: %v", err)
	}
	if result.Status != StatusOK || len(result.Entries) != 2 || !result.Truncated {
		t.Fatalf("关联错误结果异常: %+v", result)
	}
	raw, _ := json.Marshal(result)
	output := string(raw)
	for _, forbidden := range []string{syntheticSecret, syntheticToken, syntheticEmail,
		"usr_00000000000000000000000000000001", "detail", "target-id"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("关联错误泄露 %q: %s", forbidden, output)
		}
	}
	if result.Entries[0].ErrorCode != "AUTH_FAILED" || result.Entries[0].RequestID != "req_diag_errors_1" {
		t.Fatalf("白名单字段异常: %+v", result.Entries[0])
	}
	// 应用范围过滤：system 范围可见，不匹配的应用范围看不到。
	appResult, err := collector.RelatedErrors(context.Background(),
		Scope{Kind: "application", ID: "app_00000000000000000000000000000001"},
		"req_diag_errors_1", 10)
	if err != nil {
		t.Fatalf("RelatedErrors(app): %v", err)
	}
	if len(appResult.Entries) != 0 {
		t.Fatalf("跨应用范围泄露: %+v", appResult.Entries)
	}
}

// TestStorageFailureNoSecretLeak 验证依赖失败只输出稳定分类码，日志/输出不含
// 底层错误中的合成秘密。
func TestStorageFailureNoSecretLeak(t *testing.T) {
	db, _ := testDB(t)
	logger, logBuffer := loggerBuffer()
	collector := New(Options{Config: config.Default(), DB: db, Logger: logger,
		Ping: func(context.Context) error {
			return errors.New("connect failed dsn=file:" + syntheticSecret)
		}})
	report, err := collector.Snapshot(context.Background(), Scope{})
	if err != nil {
		t.Fatalf("Snapshot 不应因依赖失败返回错误: %v", err)
	}
	if report.Status != StatusDegraded || report.Storage.Status != StatusUnavailable ||
		report.Storage.ErrorCode != CodeStorageUnavailable {
		t.Fatalf("降级状态异常: %+v", report)
	}
	raw, _ := json.Marshal(report)
	for _, output := range []string{string(raw), logBuffer.String()} {
		if strings.Contains(output, syntheticSecret) {
			t.Fatalf("失败路径泄露合成秘密: %s", output)
		}
	}
	if !strings.Contains(logBuffer.String(), CodeStorageUnavailable) {
		t.Fatalf("失败日志缺少稳定分类码: %s", logBuffer.String())
	}
}

// TestConfigPendingRestart 验证待重启摘要只输出字段名/分类，不输出配置值。
func TestConfigPendingRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "login.yaml")
	if err := os.WriteFile(path, []byte("logging:\n  level: debug\n"), 0o600); err != nil {
		t.Fatalf("写入配置: %v", err)
	}
	collector := New(Options{Config: config.Default(), ConfigPath: path,
		Now: func() time.Time { return time.Unix(1700000000, 0).UTC() }})
	report, err := collector.Snapshot(context.Background(), Scope{})
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if report.Config.PendingRestartStatus != "pending" {
		t.Fatalf("待重启状态 = %q，期望 pending", report.Config.PendingRestartStatus)
	}
	found := false
	for _, field := range report.Config.PendingRestart {
		if field.Field == "logging.level" && field.Class != "" {
			found = true
		}
	}
	if !found {
		t.Fatalf("待重启字段缺少 logging.level: %+v", report.Config.PendingRestart)
	}
	raw, _ := json.Marshal(report)
	if strings.Contains(string(raw), "debug") {
		t.Fatalf("待重启摘要泄露配置值: %s", raw)
	}

	// 配置文件含合成秘密且无法解析：只标记 unverified，不输出内容/路径。
	badPath := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(badPath, []byte("smtp_password: "+syntheticSecret+
		"\ninvalid: [\n"), 0o600); err != nil {
		t.Fatalf("写入坏配置: %v", err)
	}
	badCollector := New(Options{Config: config.Default(), ConfigPath: badPath})
	badReport, err := badCollector.Snapshot(context.Background(), Scope{})
	if err != nil {
		t.Fatalf("Snapshot(bad config): %v", err)
	}
	if badReport.Config.PendingRestartStatus != StatusUnverified {
		t.Fatalf("坏配置状态 = %q", badReport.Config.PendingRestartStatus)
	}
	badRaw, _ := json.Marshal(badReport)
	if strings.Contains(string(badRaw), syntheticSecret) || strings.Contains(string(badRaw), "bad.yaml") {
		t.Fatalf("坏配置路径/秘密泄露: %s", badRaw)
	}
}

// TestScopeAndCancellation 验证作用范围校验与取消语义。
func TestScopeAndCancellation(t *testing.T) {
	collector := New(Options{})
	if _, err := collector.Snapshot(context.Background(),
		Scope{Kind: "application", ID: "bad-id"}); err == nil || !ErrInvalidScope(err) {
		t.Fatalf("非法应用范围应被拒绝: %v", err)
	}
	if normalized, err := NormalizeScope(Scope{}); err != nil ||
		normalized.Kind != "system" || normalized.ID != "system" {
		t.Fatalf("空范围规范化异常: %+v %v", normalized, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := collector.Snapshot(ctx, Scope{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("取消后应返回 context.Canceled: %v", err)
	}
	if _, err := collector.RelatedErrors(ctx, Scope{}, "req_x", 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("取消后 RelatedErrors 应返回 context.Canceled: %v", err)
	}
	if _, err := collector.RelatedErrors(context.Background(), Scope{},
		"not a valid request id", 1); err != nil {
		t.Fatalf("非法 request_id 不应报错: %v", err)
	}
}

// 确保 io 在测试构建中可用（slog handler 输出接口）。
var _ = io.Discard
