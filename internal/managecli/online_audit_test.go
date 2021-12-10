package managecli

// 本文件是在线审计命令的真实集成测试：httptest.NewServer + 真实 adminapi Handler
// + 真实 auditops（临时 SQLite + 真实迁移）+ 真实 session.Service 管理会话秘密。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/auditops"
	auditopssqlite "github.com/kagurazakayashi/EvernightLogin/internal/auditops/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// onlineAuditEnv 是真实 auditops 在线环境。
type onlineAuditEnv struct {
	*onlineFixture
	auditService *auditops.Service
	authorizer   *onlineAuditAuthorizer
	root         *onlineRootFake
	sensitive    *onlineSensitiveFake
	enqueuer     *onlineEnqueuerFake
}

// newOnlineAuditEnv 装配真实 auditops 服务并挂到真实 adminapi Handler。
func newOnlineAuditEnv(t *testing.T) *onlineAuditEnv {
	t.Helper()
	fixture := newOnlineFixture(t)
	store, err := auditopssqlite.New(fixture.raw)
	if err != nil {
		t.Fatalf("构造 auditops 仓储: %v", err)
	}
	outputDir := filepath.Join(t.TempDir(), "exports")
	if err := os.Mkdir(outputDir, 0o700); err != nil {
		t.Fatalf("创建导出目录: %v", err)
	}
	authorizer := newOnlineAuditAuthorizer()
	root := newOnlineRootFake()
	sensitive := newOnlineSensitiveFake()
	enqueuer := &onlineEnqueuerFake{}
	canceller := &onlineCancellerFake{}
	service, err := auditops.New(auditops.Options{Store: store, Audit: fixture.recorder,
		Authorizer: authorizer, Root: root, Sensitive: sensitive,
		Enqueuer: enqueuer, Canceller: canceller,
		Tasks: newOnlineAuditTaskReader(), OutputDir: outputDir,
		MaxExportRows: 500, MaxBatchSize: 20, MaxPurgeRecords: 100,
		Now: fixedOnlineNow})
	if err != nil {
		t.Fatalf("构造 auditops 服务: %v", err)
	}
	fixture.serve(func(options *adminapi.Options) { options.Audit = service })
	return &onlineAuditEnv{onlineFixture: fixture, auditService: service,
		authorizer: authorizer, root: root, sensitive: sensitive, enqueuer: enqueuer}
}

// grantRead/grantExport 授予当前测试用户在系统范围的审计权限。
func (e *onlineAuditEnv) grant(permission string) {
	e.authorizer.grant(e.userID, permission, auditops.ScopeSystem,
		auditops.ScopeGrant{Allowed: true, AllData: true})
}

// TestOnlineAuditReadFlow 覆盖事件列表/详情、错误检索、未认证/无权限/强认证过期
// 与秘密不落输出。
func TestOnlineAuditReadFlow(t *testing.T) {
	env := newOnlineAuditEnv(t)
	env.seedAuditEvent("user.update", audit.OutcomeSuccess, testUserID(41),
		onlineTestNow.Add(-3*time.Hour))
	failedID := env.seedAuditEvent("user.update", audit.OutcomeFailure, testUserID(41),
		onlineTestNow.Add(-2*time.Hour))
	env.seedAuditEvent("login.attempt", audit.OutcomeDenied, testUserID(42),
		onlineTestNow.Add(-time.Hour))

	// 无 audit.read：服务端拒绝，退出码 5。
	stdout, stderr, exit := env.run("audit", "events", "list", "--json")
	requireOnlineFailure(t, stdout, exit, ExitForbidden, "ACCESS_DENIED")
	if !strings.Contains(stderr, "失败") {
		t.Fatalf("失败信息未写入 stderr: %s", stderr)
	}

	// 授予 audit.read 全数据范围。
	env.grant(auditops.PermissionRead)
	data := requireOnlineSuccess(t, mustRun(t, env, "audit", "events", "list", "--json"))
	events, _ := data["events"].([]any)
	if len(events) < 3 {
		t.Fatalf("事件数量 = %d，期望至少 3: %v", len(events), data)
	}

	// 事件详情包含真实事件编号。
	detail := requireOnlineSuccess(t, mustRun(t, env, "audit", "events", "detail",
		failedID, "--json"))
	event, _ := detail["event"].(map[string]any)
	if event == nil || event["id"] != failedID {
		t.Fatalf("事件详情不符: %v", detail)
	}

	// 不存在的事件：adminapi 统一映射 REQ_INVALID（400），CLI 退出码 2。
	stdout, _, exit = env.run("audit", "events", "detail", "evt_does_not_exist", "--json")
	requireOnlineFailure(t, stdout, exit, ExitUsage, "REQ_INVALID")

	// 错误检索：默认组合 failure+denied 两次查询并合并。
	errorsData := requireOnlineSuccess(t, mustRun(t, env, "audit", "errors", "search",
		"--json"))
	if errorsData["outcome_filter"] != "failure+denied" {
		t.Fatalf("错误检索组合标记不符: %v", errorsData)
	}
	rows, _ := errorsData["events"].([]any)
	failureCount, deniedCount := 0, 0
	for _, raw := range rows {
		row, _ := raw.(map[string]any)
		switch row["outcome"] {
		case "failure":
			failureCount++
		case "denied":
			deniedCount++
		default:
			t.Fatalf("错误检索返回了非错误事件: %v", row)
		}
	}
	// 除种入的 failure/denied 外，先前的拒绝访问本身也会被真实审计为 denied 事件。
	if failureCount != 1 || deniedCount < 1 {
		t.Fatalf("错误检索计数不符 failure=%d denied=%d: %v",
			failureCount, deniedCount, errorsData)
	}
	// 显式 outcome=failure 只返回失败事件。
	failureData := requireOnlineSuccess(t, mustRun(t, env, "audit", "errors", "search",
		"--outcome", "failure", "--json"))
	failureRows, _ := failureData["events"].([]any)
	if len(failureRows) != 1 {
		t.Fatalf("outcome=failure 事件数 = %d，期望 1", len(failureRows))
	}

	// 已完成强认证的管理会话通过；仅普通认证的会话被 REAUTH_REQUIRED 拒绝。
	stdout, stderr, exit = env.runWithSession(env.plainSessionFile,
		"audit", "events", "list", "--json")
	requireOnlineFailure(t, stdout, exit, ExitForbidden, "REAUTH_REQUIRED")
	if !strings.Contains(stdout+stderr, "重新完成强认证") {
		t.Fatalf("REAUTH_REQUIRED 未如实提示需要重新认证: %s%s", stdout, stderr)
	}

	// 伪造会话秘密：未认证（退出码 4）。
	forged := writeProtectedSecretFile(t, "forged.secret",
		"ses_this_is_not_a_real_session_secret")
	stdout, _, exit = env.runWithSession(forged, "audit", "events", "list", "--json")
	requireOnlineFailure(t, stdout, exit, ExitUnauthenticated, "AUTH_FAILED")

	// 缺少 --session-file：用法错误，不发请求。
	stdout, _, exit = runCLI(t, "audit", "events", "list", "--server", env.server.URL, "--json")
	requireOnlineFailure(t, stdout, exit, ExitUsage, "USAGE_INVALID")
}

// mustRun 执行命令并断言成功（--json 外壳由调用方再解析）。
func mustRun(t *testing.T, env *onlineAuditEnv, args ...string) string {
	t.Helper()
	stdout, stderr, exit := env.run(args...)
	if exit != ExitOK {
		t.Fatalf("命令 %v 退出码 = %d，stderr=%s，stdout=%s", args, exit, stderr, stdout)
	}
	return stdout
}

// TestOnlineAuditExportAndCleanup 覆盖导出创建/完成/原始字节流下载、不覆盖语义、
// 取消冲突，以及清理预览/提交/取消与 confirm/reason/digest 契约。
func TestOnlineAuditExportAndCleanup(t *testing.T) {
	env := newOnlineAuditEnv(t)
	env.seedAuditEvent("user.update", audit.OutcomeSuccess, testUserID(41),
		onlineTestNow.Add(-3*time.Hour))
	env.grant(auditops.PermissionRead)
	env.grant(auditops.PermissionExport)

	// 缺少 --confirm：用法错误，不调用服务。
	stdout, _, exit := env.run("audit", "exports", "create", "--format", "csv", "--json")
	requireOnlineFailure(t, stdout, exit, ExitUsage, "USAGE_INVALID")

	// 敏感策略（强认证）未通过：服务端拒绝，退出码 5。
	env.sensitive.deny(auditops.OperationExport)
	stdout, _, exit = env.run("audit", "exports", "create", "--format", "csv",
		"--confirm", "CREATE-EXPORT", "--json")
	requireOnlineFailure(t, stdout, exit, ExitForbidden, "ACCESS_DENIED")
	env.sensitive.allow(auditops.OperationExport)

	// 成功创建（queued 不等于完成）。
	created := requireOnlineSuccess(t, mustRun(t, env, "audit", "exports", "create",
		"--format", "csv", "--confirm", "CREATE-EXPORT", "--json"))
	exportView, _ := created["export"].(map[string]any)
	exportID, _ := exportView["id"].(string)
	taskID, _ := exportView["task_id"].(string)
	if exportID == "" || exportView["state"] != auditops.ExportQueued {
		t.Fatalf("导出创建结果不符: %v", exportView)
	}

	// 用真实导出处理器完成任务，产物落盘。
	enqueued := env.enqueuer.last
	job := task.Job{ID: taskID, Kind: enqueued.Kind, Initiator: enqueued.Actor,
		ExecutorID: "worker_online", Payload: enqueued.Payload,
		RequestID: enqueued.RequestID, MaxAttempts: enqueued.MaxAttempts}
	if err := env.auditService.ExportHandler(env.ctx, job); err != nil {
		t.Fatalf("执行导出任务: %v", err)
	}
	finishedData := requireOnlineSuccess(t, mustRun(t, env, "audit", "exports", "list",
		"--json"))
	if exports, _ := finishedData["exports"].([]any); len(exports) == 0 {
		t.Fatalf("导出列表为空: %v", finishedData)
	}

	// 原始字节流下载：保存文件、返回 sha256，且不覆盖已有文件。
	outPath := filepath.Join(t.TempDir(), "audit-export.csv")
	downloadData := requireOnlineSuccess(t, mustRun(t, env, "audit", "exports",
		"download", exportID, "--out", outPath, "--json"))
	content, err := os.ReadFile(outPath)
	if err != nil || len(content) == 0 {
		t.Fatalf("导出文件未保存或为空: %v", err)
	}
	if downloadData["bytes"] == nil || downloadData["sha256"] == "" {
		t.Fatalf("下载结果缺少字节数/摘要: %v", downloadData)
	}
	if !strings.Contains(string(content), "user.update") {
		t.Fatalf("导出内容缺少真实审计动作: %s", string(content))
	}
	stdout, _, exit = env.run("audit", "exports", "download", exportID,
		"--out", outPath, "--json")
	requireOnlineFailure(t, stdout, exit, ExitUsage, "OUTPUT_FILE_EXISTS")
	mustRun(t, env, "audit", "exports", "download", exportID,
		"--out", outPath, "--overwrite", "--json")

	// 对已完成导出请求取消：服务端按任务取消契约处理；请求被接受也不等于导出
	// 真的被取消（响应如实返回 cancel_requested）。
	cancelExportData := requireOnlineSuccess(t, mustRun(t, env, "audit", "exports",
		"cancel", exportID, "--reason", "测试取消", "--confirm", "CANCEL-EXPORT",
		"--json"))
	cancelExport, _ := cancelExportData["cancel"].(map[string]any)
	if accepted, _ := cancelExport["accepted"].(bool); !accepted {
		t.Fatalf("导出取消请求未被接受: %v", cancelExportData)
	}

	// 清理预估：非 root 拒绝（退出码 5）。
	cutoff := onlineTestNow.Add(-400 * 24 * time.Hour).Format(time.RFC3339)
	stdout, _, exit = env.run("audit", "cleanup", "preview", "--cutoff", cutoff, "--json")
	requireOnlineFailure(t, stdout, exit, ExitForbidden, "ACCESS_DENIED")

	// root 通过只读预估，返回绑定参数的 digest。
	env.root.setRoot(env.userID, true)
	previewData := requireOnlineSuccess(t, mustRun(t, env, "audit", "cleanup",
		"preview", "--cutoff", cutoff, "--json"))
	preview, _ := previewData["purge_preview"].(map[string]any)
	digest, _ := preview["digest"].(string)
	if digest == "" {
		t.Fatalf("清理预估缺少 digest: %v", previewData)
	}

	// 提交缺少 digest：用法错误。
	stdout, _, exit = env.run("audit", "cleanup", "submit", "--cutoff", cutoff,
		"--reason", "测试清理", "--confirm", "PURGE", "--json")
	requireOnlineFailure(t, stdout, exit, ExitUsage, "USAGE_INVALID")

	// 被篡改的 digest：服务端冲突，退出码 6（预览参数必须原样带回）。
	stdout, _, exit = env.run("audit", "cleanup", "submit", "--cutoff", cutoff,
		"--digest", "tampered-digest", "--reason", "测试清理",
		"--confirm", "PURGE", "--json")
	requireOnlineFailure(t, stdout, exit, ExitConflict, "CONFLICT")

	// 正确 digest：提交清理任务（queued 不等于完成）。
	submitted := requireOnlineSuccess(t, mustRun(t, env, "audit", "cleanup", "submit",
		"--cutoff", cutoff, "--digest", digest, "--reason", "测试清理",
		"--confirm", "PURGE", "--json"))
	run, _ := submitted["purge_run"].(map[string]any)
	runID, _ := run["id"].(string)
	if runID == "" || run["state"] != auditops.PurgeQueued {
		t.Fatalf("清理任务提交结果不符: %v", submitted)
	}

	// 请求取消清理运行：请求被接受，但不等于已取消。
	cancelData := requireOnlineSuccess(t, mustRun(t, env, "audit", "cleanup", "cancel",
		runID, "--reason", "测试取消清理", "--confirm", "CANCEL-PURGE", "--json"))
	cancel, _ := cancelData["cancel"].(map[string]any)
	if accepted, _ := cancel["accepted"].(bool); !accepted {
		t.Fatalf("取消请求未被接受: %v", cancelData)
	}
}

// TestOnlineUnprotectedSessionFileRejected 验证未按平台要求保护的会话文件被拒绝
// （Windows/test 环境若判定为受保护则跳过该断言）。
func TestOnlineUnprotectedSessionFileRejected(t *testing.T) {
	env := newOnlineAuditEnv(t)
	path := filepath.Join(t.TempDir(), "unprotected.secret")
	if err := os.WriteFile(path, []byte("ses_unprotected_value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := secrets.CheckProtectedFile(path); err == nil {
		t.Skip("当前环境无法构造未受保护的会话文件")
	}
	stdout, _, exit := env.runWithSession(path, "audit", "events", "list", "--json")
	requireOnlineFailure(t, stdout, exit, ExitUnauthenticated, "SESSION_FILE_INVALID")
}
