package setupconsole

// N-M2a-1 定向测试：只读操作不取 281 写门（主服务运行时可浏览），写操作在写门
// 拒绝时 fail-closed；读取审计失败/写门拒绝不会让只读列表不可用。

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/config"
	"github.com/kagurazakayashi/EvernightLogin/internal/serverapp"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
)

// openWS3GuardTestBase 构造真实临时实例（无监听/无后台任务）。
func openWS3GuardTestBase(t *testing.T) *serverapp.Base {
	t.Helper()
	ctx := context.Background()
	dir := testutil.TempDir(t)
	cfg := config.Default()
	cfg.Database.Path = filepath.Join(dir, "guard.db")
	cfg.Server.PathPrefix = ""
	base, err := serverapp.OpenBase(ctx, serverapp.BaseOptions{
		Config: cfg, MasterKeyFile: filepath.Join(dir, "master.key"),
		Migrate: true, CreateMasterKey: true, Now: time.Now,
	})
	if err != nil {
		t.Fatalf("OpenBase: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := base.Close(context.Background()); closeErr != nil {
			t.Logf("Close: %v", closeErr)
		}
	})
	return base
}

// TestWS3WriteGuardReadsAndWrites 验证只读放行、写入 fail-closed。
func TestWS3WriteGuardReadsAndWrites(t *testing.T) {
	base := openWS3GuardTestBase(t)
	ctx := context.Background()
	guard := func(context.Context) (func(), error) {
		return nil, errors.New("主服务正在运行")
	}
	maint, denyLog := newFakeMaintRecorder()
	services, err := newWS3Services(base, "os:tester@local", guard, maint)
	if err != nil {
		t.Fatalf("构造 WS3Services: %v", err)
	}
	// 只读：用户列表/审计查询/应用列表不取写门，写门拒绝仍可用。
	if _, err := services.Users.ListUsers(ctx,
		LocalUserQuery{PageRequest: LocalPageRequest{Limit: 10}}); err != nil {
		t.Fatalf("写门拒绝时只读用户列表应可用: %v", err)
	}
	if _, err := services.Audit.QueryAudit(ctx, LocalAuditFilter{Limit: 10}); err != nil {
		t.Fatalf("写门拒绝时只读审计查询应可用: %v", err)
	}
	if _, _, err := services.Apps.ListApplications(ctx,
		LocalPageRequest{Limit: 10}); err != nil {
		t.Fatalf("写门拒绝时只读应用列表应可用: %v", err)
	}
	// 写入：必须先取写门；拒绝时明确失败且不产生数据。
	if _, err := services.Users.CreateUser(ctx, LocalUserCreate{Username: "guard-user"}); err == nil {
		t.Fatal("写门拒绝时创建用户必须 fail-closed")
	}
	if _, err := services.Identity.SetPassword(ctx, "usr_missing",
		"Guard!Pass9", true); err == nil {
		t.Fatal("写门拒绝时设置密码必须 fail-closed")
	}
	// M2c MEDIUM-1：291 危险审计写/报告生成也必须经写门+维护日志。
	if _, err := services.Audit.SetRetention(ctx, 30, "deny-guard-test"); err == nil {
		t.Fatal("写门拒绝时设置审计保留策略必须 fail-closed")
	}
	if _, err := services.Audit.StartPurge(ctx, LocalPurgePreview{ScopeID: "system",
		Cutoff: time.Now().UTC().Add(-400 * 24 * time.Hour), Digest: "digest"}, "deny"); err == nil {
		t.Fatal("写门拒绝时提交清理任务必须 fail-closed")
	}
	if _, err := services.Audit.GenerateReport(ctx, LocalReportRequest{ScopeID: "system",
		Formats: []string{"json"}}); err == nil {
		t.Fatal("写门拒绝时报告生成必须 fail-closed")
	}
	denyEntries := denyLog.snapshot()
	failed := 0
	for _, entry := range denyEntries {
		if entry.Result == "failed" && entry.ErrorCode == "WRITE_GUARD_DENIED" {
			failed++
		}
	}
	if failed < 5 {
		t.Fatalf("写门拒绝时维护日志应记录 started+failed（>=5 次失败尝试），实际 %d 条", failed)
	}
	// 写门恢复后写入成功（释放函数被调用）。
	acquired := 0
	allowGuard := func(context.Context) (func(), error) {
		acquired++
		return func() {}, nil
	}
	allowMaint, allowLog := newFakeMaintRecorder()
	allowed, err := newWS3Services(base, "os:tester@local", allowGuard, allowMaint)
	if err != nil {
		t.Fatalf("构造允许写门 WS3Services: %v", err)
	}
	user, err := allowed.Users.CreateUser(ctx, LocalUserCreate{Username: "guard-user"})
	if err != nil || user.ID == "" {
		t.Fatalf("写门允许时创建用户 = %+v err=%v", user, err)
	}
	if acquired != 1 {
		t.Fatalf("写门调用次数 = %d，期望 1（每次写操作获取一次）", acquired)
	}
	if entries := allowLog.snapshot(); len(entries) < 2 {
		t.Fatalf("维护日志应记录 started+success，实际 %d 条", len(entries))
	}
	// 写门允许时：保留策略成功；清理提交/报告生成至少经过写门与维护日志（任务
	// 运行时未启用时业务层明确失败，不伪造成功）。
	if _, err := allowed.Audit.SetRetention(ctx, 30, "allow-guard-test"); err != nil {
		t.Fatalf("写门允许时设置保留策略: %v", err)
	}
	// 报告生成在默认任务运行时未启用时会业务失败，但仍应经过写门+维护日志。
	if _, err := allowed.Audit.GenerateReport(ctx, LocalReportRequest{
		ScopeID: "system", Formats: []string{"json"}}); err != nil &&
		!errors.Is(err, ErrLocalUnsupported) {
		t.Logf("报告生成业务不可用（可接受）: %v", err)
	}
	allowEntries := allowLog.snapshot()
	hasRetentionSuccess := false
	hasGenerateStarted := false
	for _, entry := range allowEntries {
		if entry.Action == "ws3.audit.retention" && entry.Result == "success" {
			hasRetentionSuccess = true
		}
		if entry.Action == "ws3.report.generate" && entry.Result == "started" {
			hasGenerateStarted = true
		}
	}
	if !hasRetentionSuccess || !hasGenerateStarted {
		t.Fatalf("写门允许时维护日志缺少 retention success / report started: %+v", allowEntries)
	}
}

// TestWS3ProductionMaintRecorder 验证生产维护日志真实落盘（LOW-1）。
func TestWS3ProductionMaintRecorder(t *testing.T) {
	dir := testutil.TempDir(t)
	recorder, err := newWS3MaintRecorder(dir)
	if err != nil {
		t.Fatalf("打开维护日志: %v", err)
	}
	if err := recorder.record(context.Background(), ws3OperationID(), "ws3.test.action",
		"user:usr_test", "success", "", time.Now().UTC(), time.Now().UTC()); err != nil {
		t.Fatalf("维护日志记录: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读取实例目录: %v", err)
	}
	found := false
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "maintenance") {
			found = true
		}
	}
	if !found {
		t.Fatalf("维护日志文件未创建: %v", entries)
	}
}
