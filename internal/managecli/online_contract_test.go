package managecli

// 本文件覆盖 backups/notifications/tasks 在线命令：真实 adminapi Handler 与真实
// session.Service，领域服务使用线级契约替身（backupadmin 真实装配成本高；通知
// 本地捕获器与任务读取的替身仅替换领域接缝，传输、认证、envelope 与 CLI 均为
// 真实路径）。该边界在测试与步骤 84 报告中明确标注。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// TestOnlineBackupsContract 覆盖备份产物/计划/保留策略/清理命令与确认词、版本冲突、
// 权限拒绝和令牌兑换下载。
func TestOnlineBackupsContract(t *testing.T) {
	fixture := newOnlineFixture(t)
	backups := newOnlineBackupFake()
	fixture.serve(func(options *adminapi.Options) {
		options.Backups = backups
		// 计划写入与清理在 adminapi 层要求敏感策略（强认证）另行通过。
		options.Sensitive = newOnlineSensitiveFake()
	})

	// 产物列表与详情。
	listData := requireOnlineSuccess(t, mustRunOnline(t, fixture, "backups",
		"artifacts", "list", "--json"))
	if items, _ := listData["backups"].([]any); len(items) != 1 {
		t.Fatalf("备份产物列表不符: %v", listData)
	}
	detailData := requireOnlineSuccess(t, mustRunOnline(t, fixture, "backups",
		"artifacts", "detail", "bak_1", "--json"))
	if artifact, _ := detailData["backup"].(map[string]any); artifact["backup_id"] != "bak_1" {
		t.Fatalf("备份产物详情不符: %v", detailData)
	}

	// 下载令牌兑换：原始字节流写入文件，令牌原文不出现在输出。
	outPath := filepath.Join(t.TempDir(), "backup.bin")
	stdout := mustRunOnline(t, fixture, "backups", "artifacts", "download-token",
		"bak_1", "--confirm", "ISSUE-DOWNLOAD", "--out", outPath, "--json")
	saved, err := os.ReadFile(outPath)
	if err != nil || string(saved) != string(backups.downloadData) {
		t.Fatalf("备份下载内容不符: %v", err)
	}
	if strings.Contains(stdout, `"token"`) {
		t.Fatalf("备份下载输出泄露了令牌原文: %s", stdout)
	}

	// 计划列表/详情。
	scheduleData := requireOnlineSuccess(t, mustRunOnline(t, fixture, "backups",
		"schedules", "list", "--json"))
	if items, _ := scheduleData["schedules"].([]any); len(items) != 1 {
		t.Fatalf("备份计划列表不符: %v", scheduleData)
	}
	requireOnlineSuccess(t, mustRunOnline(t, fixture, "backups", "schedules",
		"get", "sch_1", "--json"))

	// 创建计划：缺少必填参数为用法错误；完整参数成功并到达服务端。
	stdoutOut, _, exit := fixture.run("backups", "schedules", "create", "--name", "每日",
		"--confirm", "CREATE", "--json")
	requireOnlineFailure(t, stdoutOut, exit, ExitUsage, "USAGE_INVALID")
	createArgs := []string{"backups", "schedules", "create", "--name", "每日备份",
		"--schedule-type", "daily", "--expression", "02:00", "--time-zone", "UTC",
		"--missed-policy", "skip", "--max-catch-up", "3", "--timeout-seconds", "600",
		"--max-attempts", "2", "--confirm", "CREATE", "--json"}
	requireOnlineSuccess(t, mustRunOnline(t, fixture, createArgs...))
	if backups.lastSchedule.Name != "每日备份" ||
		backups.lastSchedule.TimeZone != "UTC" {
		t.Fatalf("创建计划请求未到达服务层: %+v", backups.lastSchedule)
	}

	// 编辑计划整份替换。
	editArgs := []string{"backups", "schedules", "edit", "sch_1", "--name", "每日备份（改）",
		"--schedule-type", "daily", "--expression", "03:00", "--time-zone", "UTC",
		"--missed-policy", "skip", "--disabled", "--confirm", "EDIT", "--json"}
	requireOnlineSuccess(t, mustRunOnline(t, fixture, editArgs...))
	if backups.lastSchedule.Name != "每日备份（改）" || backups.lastSchedule.Enabled {
		t.Fatalf("编辑计划请求未到达服务层: %+v", backups.lastSchedule)
	}

	// 启停计划：缺少原因/确认词为用法错误。
	stdoutOut, _, exit = fixture.run("backups", "schedules", "enable", "sch_1",
		"--confirm", "ENABLE", "--json")
	requireOnlineFailure(t, stdoutOut, exit, ExitUsage, "USAGE_INVALID")
	requireOnlineSuccess(t, mustRunOnline(t, fixture, "backups", "schedules",
		"enable", "sch_1", "--reason", "维护结束", "--confirm", "ENABLE", "--json"))
	requireOnlineSuccess(t, mustRunOnline(t, fixture, "backups", "schedules",
		"disable", "sch_1", "--reason", "维护窗口", "--confirm", "DISABLE", "--json"))

	// 删除计划。
	stdoutOut, _, exit = fixture.run("backups", "schedules", "delete", "sch_1",
		"--confirm", "DELETE", "--json")
	requireOnlineFailure(t, stdoutOut, exit, ExitUsage, "USAGE_INVALID")
	requireOnlineSuccess(t, mustRunOnline(t, fixture, "backups", "schedules",
		"delete", "sch_1", "--reason", "不再需要", "--confirm", "DELETE", "--json"))

	// 保留策略读取与版本并发写入。
	retentionData := requireOnlineSuccess(t, mustRunOnline(t, fixture, "backups",
		"retention", "get", "--json"))
	retention, _ := retentionData["retention"].(map[string]any)
	policy, _ := retention["policy"].(map[string]any)
	if objectInt64(policy, "version") != 3 {
		t.Fatalf("保留策略版本不符: %v", retentionData)
	}
	setArgs := []string{"backups", "retention", "set", "--max-count", "5",
		"--max-age-days", "30", "--max-total-bytes", "1048576",
		"--expected-version", "3", "--reason", "收紧保留", "--confirm", "SET-RETENTION",
		"--json"}
	updated := requireOnlineSuccess(t, mustRunOnline(t, fixture, setArgs...))
	updatedRetention, _ := updated["retention"].(map[string]any)
	updatedPolicy, _ := updatedRetention["policy"].(map[string]any)
	if objectInt64(updatedPolicy, "version") != 4 {
		t.Fatalf("保留策略写入结果不符: %v", updated)
	}
	// 版本冲突：服务端返回 CONFLICT，CLI 退出码 6，需重新读取后重试。
	backups.conflictRetention = true
	stdoutOut, _, exit = fixture.run(setArgs...)
	requireOnlineFailure(t, stdoutOut, exit, ExitConflict, "CONFLICT")
	backups.conflictRetention = false

	// 清理预览与提交。
	previewData := requireOnlineSuccess(t, mustRunOnline(t, fixture, "backups",
		"cleanup", "preview", "--json"))
	if preview, _ := previewData["cleanup_preview"].(map[string]any); preview == nil {
		t.Fatalf("备份清理预览缺少对象: %v", previewData)
	}
	stdoutOut, _, exit = fixture.run("backups", "cleanup", "submit", "--json")
	requireOnlineFailure(t, stdoutOut, exit, ExitUsage, "USAGE_INVALID")
	requireOnlineSuccess(t, mustRunOnline(t, fixture, "backups", "cleanup",
		"submit", "--confirm", "CLEANUP", "--json"))

	// 服务端权限拒绝：退出码 5 且保留服务端错误码。
	backups.deny = true
	stdoutOut, _, exit = fixture.run("backups", "artifacts", "list", "--json")
	requireOnlineFailure(t, stdoutOut, exit, ExitForbidden, "ACCESS_DENIED")
}

// TestOnlineNotificationsAndTasks 覆盖通知状态/本地捕获测试、REAUTH_REQUIRED、
// 能力码（不伪成功）与任务详情权限拒绝。
func TestOnlineNotificationsAndTasks(t *testing.T) {
	fixture := newOnlineFixture(t)
	notifications := &onlineNotificationsFake{localCapture: true}
	sensitive := newOnlineSensitiveFake()
	tasks := newOnlineTaskReader()
	tasks.add(task.Job{ID: "job_online_1", Kind: "backup.create",
		State:     task.StateQueued,
		Initiator: audit.Actor{Type: audit.ActorUser, ID: fixture.userID},
		CreatedAt: onlineTestNow})
	authorizer := &onlineTaskAuthorizer{}
	fixture.serve(func(options *adminapi.Options) {
		options.Notifications = notifications
		options.Sensitive = sensitive
		options.AuditRecorder = &onlineReportsAudit{}
		options.Tasks = tasks
		options.TaskAuthorizer = authorizer
	})

	// 通知状态（脱敏）。
	statusData := requireOnlineSuccess(t, mustRunOnline(t, fixture, "notifications",
		"status", "--json"))
	status, _ := statusData["notifications"].(map[string]any)
	if status == nil || status["local_capture"] != true ||
		status["delivery_mode"] != "local_capture" {
		t.Fatalf("通知状态不符: %v", statusData)
	}

	// 通知测试缺少确认词：用法错误。
	stdout, _, exit := fixture.run("notifications", "test", "--json")
	requireOnlineFailure(t, stdout, exit, ExitUsage, "USAGE_INVALID")

	// 本地捕获模式 + 敏感策略通过 + 审计可用：成功且明确未真实外发。
	captureData := requireOnlineSuccess(t, mustRunOnline(t, fixture,
		"notifications", "test", "--confirm", "TEST-NOTIFICATION", "--json"))
	if captureData["real_delivery"] != false {
		t.Fatalf("通知测试结果不得声称真实投递: %v", captureData)
	}

	// 敏感策略拒绝：REAUTH_REQUIRED（退出码 5，提示需要重新认证）。
	sensitive.deny(adminapi.OperationNotificationTest)
	stdout, stderr, exit := fixture.run("notifications", "test",
		"--confirm", "TEST-NOTIFICATION", "--json")
	requireOnlineFailure(t, stdout, exit, ExitForbidden, "REAUTH_REQUIRED")
	if !strings.Contains(stdout+stderr, "重新完成强认证") {
		t.Fatalf("REAUTH_REQUIRED 未如实提示需要重新认证")
	}
	sensitive.allow(adminapi.OperationNotificationTest)

	// 非本地捕获模式：服务端返回稳定能力码，CLI 保留原码并失败（绝不伪成功）。
	notifications.localCapture = false
	stdout, _, exit = fixture.run("notifications", "test",
		"--confirm", "TEST-NOTIFICATION", "--json")
	requireOnlineFailure(t, stdout, exit, ExitError, "NOTIFICATION_TEST_DISABLED")
	notifications.localCapture = true

	// 任务详情：允许、拒绝、不存在三种结果。
	taskData := requireOnlineSuccess(t, mustRunOnline(t, fixture, "tasks", "get",
		"job_online_1", "--json"))
	job, _ := taskData["task"].(map[string]any)
	if job == nil || job["id"] != "job_online_1" {
		t.Fatalf("任务详情不符: %v", taskData)
	}
	stdout, _, exit = fixture.run("tasks", "get", "job_missing", "--json")
	requireOnlineFailure(t, stdout, exit, ExitUsage, "REQ_INVALID")
	authorizer.deny = true
	stdout, _, exit = fixture.run("tasks", "get", "job_online_1", "--json")
	requireOnlineFailure(t, stdout, exit, ExitForbidden, "ACCESS_DENIED")
}

// mustRunOnline 执行在线命令并断言成功。
func mustRunOnline(t *testing.T, fixture *onlineFixture, args ...string) string {
	t.Helper()
	stdout, stderr, exit := fixture.run(args...)
	if exit != ExitOK {
		t.Fatalf("命令 %v 退出码 = %d，stderr=%s，stdout=%s", args, exit, stderr, stdout)
	}
	return stdout
}

// TestOnlineHelpAndUsage 校验帮助文本与未知子命令的稳定用法错误。
func TestOnlineHelpAndUsage(t *testing.T) {
	fixture := newOnlineFixture(t)
	tasks := newOnlineTaskReader()
	tasks.add(task.Job{ID: "job_default_server", Kind: "backup.create",
		State:     task.StateQueued,
		Initiator: audit.Actor{Type: audit.ActorUser, ID: fixture.userID},
		CreatedAt: onlineTestNow})
	fixture.serve(func(options *adminapi.Options) {
		options.Tasks = tasks
		options.TaskAuthorizer = &onlineTaskAuthorizer{}
	})
	stdout, _, exit := runCLI(t, "audit", "help")
	if exit != ExitOK || !strings.Contains(stdout, "audit events list") {
		t.Fatalf("audit 帮助不符: exit=%d stdout=%s", exit, stdout)
	}
	stdout, _, exit = runCLI(t, "reports", "help")
	if exit != ExitOK || !strings.Contains(stdout, "reports history list") {
		t.Fatalf("reports 帮助不符: exit=%d stdout=%s", exit, stdout)
	}
	stdout, _, exit = runCLI(t, "backups", "help")
	if exit != ExitOK || !strings.Contains(stdout, "backups schedules") {
		t.Fatalf("backups 帮助不符: exit=%d stdout=%s", exit, stdout)
	}
	// 未知子命令：用法错误（子命令在解析 --json 前即失败，只写 stderr）。
	_, stderr, exit := fixture.run("backups", "unknown", "--json")
	if exit != ExitUsage || !strings.Contains(stderr, "未知的 backups 子命令") {
		t.Fatalf("未知子命令未返回用法错误: exit=%d stderr=%s", exit, stderr)
	}
	// 默认服务地址从 --config 的 server.listen_addr 端口推导。
	configPath := filepath.Join(t.TempDir(), "login.yaml")
	serverPort := strings.TrimPrefix(fixture.server.URL, "http://127.0.0.1:")
	configData := "server:\n  listen_addr: \"127.0.0.1:" + serverPort + "\"\n" +
		"database:\n  driver: sqlite\n  path: " + filepath.Join(t.TempDir(), "login.db") + "\n"
	if err := os.WriteFile(configPath, []byte(configData), 0o600); err != nil {
		t.Fatal(err)
	}
	// 该配置指向的数据库不存在，但命令只发 HTTP 请求、不打开数据库。
	stdout, _, exit = runCLI(t, "tasks", "get", "job_default_server", "--json",
		"--config", configPath, "--session-file", fixture.sessionFile)
	if exit != ExitOK {
		t.Fatalf("默认服务地址推导失败: exit=%d stdout=%s", exit, stdout)
	}
}
