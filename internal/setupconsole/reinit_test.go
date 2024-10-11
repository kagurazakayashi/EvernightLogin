package setupconsole

// 步骤 295 的定向测试：完整重新初始化计划/路径逃逸拒绝/确认/可恢复日志。

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func reinitTestPaths(t *testing.T) ReinitPaths {
	t.Helper()
	root := t.TempDir()
	instanceDir := filepath.Join(root, "instance")
	paths := ReinitPaths{
		InstanceDir:    instanceDir,
		ConfigPath:     filepath.Join(instanceDir, "login.yaml"),
		DatabasePath:   filepath.Join(instanceDir, "data", "login.db"),
		AttachmentsDir: filepath.Join(instanceDir, "data", "attachments"),
		StateDir:       filepath.Join(instanceDir, "state"),
		MasterKeyFile:  filepath.Join(instanceDir, "master.key"),
		LogDir:         filepath.Join(instanceDir, "logs"),
	}
	for _, dir := range []string{instanceDir, filepath.Join(instanceDir, "data"), filepath.Join(instanceDir, "state"), filepath.Join(instanceDir, "logs")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("创建测试目录失败：%v", err)
		}
	}
	writeTestFile(t, paths.ConfigPath, []byte("server: {}\n"))
	writeTestFile(t, paths.DatabasePath, []byte("db"))
	writeTestFile(t, paths.MasterKeyFile, []byte("key"))
	return paths
}

func validReinitRequest(t *testing.T, paths ReinitPaths) ReinitRequest {
	t.Helper()
	return ReinitRequest{
		Paths: paths, InstanceID: "inst_test_01",
		ConfirmText:               reinitConfirmPrefix + "inst_test_01",
		AcknowledgeOldCredentials: true, BackupAvailable: true,
	}
}

func TestPlanFullReinitListsClearAndRetainItems(t *testing.T) {
	paths := reinitTestPaths(t)
	plan, err := PlanFullReinit(validReinitRequest(t, paths))
	if err != nil {
		t.Fatalf("生成重新初始化计划失败：%v", err)
	}
	if !plan.CanExecute {
		t.Fatalf("合法计划应可执行，阻塞：%v", plan.Blocking)
	}
	if !plan.RequiresMaintenanceLock {
		t.Fatal("必须声明需要维护排他锁")
	}
	if plan.RequiredConfirm != reinitConfirmPrefix+"inst_test_01" {
		t.Fatalf("确认串错误：%s", plan.RequiredConfirm)
	}
	if len(plan.ClearItems) < 3 || len(plan.RetainItems) == 0 || len(plan.Steps) == 0 {
		t.Fatalf("清除/保留/步骤清单不完整：%+v", plan)
	}
	if plan.JournalPath == "" || !strings.HasSuffix(plan.JournalPath, reinitJournalName) {
		t.Fatalf("执行日志路径错误：%s", plan.JournalPath)
	}
	foundDatabase := false
	for _, item := range plan.ClearItems {
		if item.Label == "数据库文件" && item.Path == paths.DatabasePath {
			foundDatabase = true
		}
	}
	if !foundDatabase {
		t.Fatal("清除清单必须包含精确数据库路径")
	}
}

func TestPlanFullReinitRejectsDangerousTargets(t *testing.T) {
	paths := reinitTestPaths(t)
	// 未确认旧凭证失效。
	request := validReinitRequest(t, paths)
	request.AcknowledgeOldCredentials = false
	if plan, err := PlanFullReinit(request); err != nil || plan.CanExecute {
		t.Fatalf("未确认旧凭证失效时必须阻塞：err=%v plan=%+v", err, plan.Blocking)
	}
	// 保留路径包含数据库。
	request = validReinitRequest(t, paths)
	request.ReservedPaths = []string{filepath.Dir(paths.DatabasePath)}
	if plan, err := PlanFullReinit(request); err != nil || plan.CanExecute {
		t.Fatalf("目标位于保留路径内必须阻塞：err=%v", err)
	}
	// 代码仓库检测：在实例目录加入 .git 标记后必须拒绝。
	if err := os.MkdirAll(filepath.Join(paths.InstanceDir, ".git"), 0o700); err != nil {
		t.Fatalf("创建 .git 标记失败：%v", err)
	}
	request = validReinitRequest(t, paths)
	plan, err := PlanFullReinit(request)
	if err != nil {
		t.Fatalf("生成计划失败：%v", err)
	}
	if plan.CanExecute {
		t.Fatal("实例目录含代码仓库标记时必须拒绝完整重新初始化")
	}
}

func TestReinitJournalRoundTripAndResumeHint(t *testing.T) {
	paths := reinitTestPaths(t)
	journal, err := OpenReinitJournal(paths.InstanceDir)
	if err != nil {
		t.Fatalf("打开执行日志失败：%v", err)
	}
	if err := journal.Record("stop-service", "success", ""); err != nil {
		t.Fatalf("记录步骤失败：%v", err)
	}
	if err := journal.Record("clear-database", "failed", "E_DB_BUSY"); err != nil {
		t.Fatalf("记录失败步骤失败：%v", err)
	}
	entries, err := ReadReinitJournal(paths.InstanceDir)
	if err != nil {
		t.Fatalf("读取执行日志失败：%v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("执行日志记录数错误：%d", len(entries))
	}
	hint := ReinitResumeHint(entries)
	if !strings.Contains(hint, "未完成") || !strings.Contains(hint, "E_DB_BUSY") && !strings.Contains(hint, "failed") {
		t.Fatalf("恢复提示不准确：%s", hint)
	}
}

type fakeReinitializer struct {
	called bool
}

func (f *fakeReinitializer) ExecuteFullReinit(ctx context.Context, plan ReinitPlan, journal *ReinitJournal) (ReinitResult, error) {
	f.called = true
	_ = journal.Record("verify", "success", "")
	return ReinitResult{Completed: true, InstanceID: plan.InstanceID}, nil
}

func TestExecuteFullReinitRequiresLockConfirmAndExecutor(t *testing.T) {
	paths := reinitTestPaths(t)
	plan, err := PlanFullReinit(validReinitRequest(t, paths))
	if err != nil {
		t.Fatalf("生成计划失败：%v", err)
	}
	if _, err := ExecuteFullReinitWith(context.Background(), nil, plan, plan.RequiredConfirm, true); err == nil {
		t.Fatal("未注入执行器必须拒绝")
	}
	fake := &fakeReinitializer{}
	if _, err := ExecuteFullReinitWith(context.Background(), fake, plan, plan.RequiredConfirm, false); err == nil {
		t.Fatal("未取得维护锁必须拒绝")
	}
	if fake.called {
		t.Fatal("未取得锁时不得执行")
	}
	if _, err := ExecuteFullReinitWith(context.Background(), fake, plan, "wrong", true); err == nil {
		t.Fatal("确认串错误必须拒绝")
	}
	result, err := ExecuteFullReinitWith(context.Background(), fake, plan, plan.RequiredConfirm, true)
	if err != nil {
		t.Fatalf("执行失败：%v", err)
	}
	if !result.Completed || !fake.called {
		t.Fatal("执行器应被调用一次")
	}
	_ = time.Now()
}

func TestReinitScreenPreviewAndConfirmationGate(t *testing.T) {
	paths := reinitTestPaths(t)
	screen := NewReinitScreen()
	screen.oldCredentialsAck = true
	screen.backupConfirmed = false
	session := SessionView{Detection: Detection{
		ConfigPath: paths.ConfigPath, DatabasePath: paths.DatabasePath,
		ConfigLoaded: true,
	}}
	canvas := NewCanvas(100, 40)
	screen.preview(context.Background(), session)
	if screen.errText != "" {
		t.Fatalf("重新初始化预览失败：%s", screen.errText)
	}
	if screen.plan == nil {
		t.Fatal("预览应生成计划")
	}
	if !strings.Contains(screen.plan.RequiredConfirm, "REINITIALIZE-") {
		t.Fatalf("确认串应为 REINITIALIZE-<id>：%s", screen.plan.RequiredConfirm)
	}
	// 未输入正确确认串时必须拒绝执行，且不得进入 pending。
	screen.prepareExecute()
	if screen.pending {
		t.Fatal("确认串未匹配时不得进入确认状态")
	}
	if screen.errText == "" {
		t.Fatal("确认串未匹配时应显示错误")
	}
	screen.confirmText = screen.plan.RequiredConfirm
	screen.prepareExecute()
	if screen.errText != "" {
		t.Fatalf("确认串匹配后准备执行不应报错：%s", screen.errText)
	}
	if !screen.pending {
		t.Fatal("确认串匹配后应等待再次确认")
	}
	screen.Render(context.Background(), canvas, session)
}

func TestReinitPlanPreservesOwnEvidenceFiles(t *testing.T) {
	paths := reinitTestPaths(t)
	plan, err := PlanFullReinit(validReinitRequest(t, paths))
	if err != nil {
		t.Fatalf("生成计划失败：%v", err)
	}
	journalPath := filepath.Clean(plan.JournalPath)
	maintLogPath := filepath.Join(filepath.Clean(paths.InstanceDir), ".login-setup-maintenance.jsonl")
	for _, item := range plan.ClearItems {
		cleaned := filepath.Clean(item.Path)
		if cleaned == journalPath {
			t.Fatal("清除清单不得包含本次执行日志（危险操作需保留自身证据）")
		}
		if cleaned == maintLogPath {
			t.Fatal("清除清单不得包含维护日志（危险操作需保留自身证据）")
		}
	}
}

func TestPlanFullReinitRejectsStateDirContainingInstance(t *testing.T) {
	paths := reinitTestPaths(t)
	instanceDir := filepath.Clean(paths.InstanceDir)
	parentDir := filepath.Dir(instanceDir)
	grandParentDir := filepath.Dir(parentDir)
	cases := []struct {
		name     string
		stateDir string
	}{
		{"state-equals-instance", instanceDir},
		{"state-is-parent", parentDir},
		{"state-is-grandparent", grandParentDir},
	}
	for _, item := range cases {
		request := validReinitRequest(t, paths)
		request.Paths.StateDir = item.stateDir
		plan, err := PlanFullReinit(request)
		if err != nil {
			t.Fatalf("%s：生成计划失败：%v", item.name, err)
		}
		if plan.CanExecute {
			t.Fatalf("%s：状态目录等于/包含实例目录时必须阻塞", item.name)
		}
		if !hasBlockingContaining(plan.Blocking, "维护状态目录") {
			t.Fatalf("%s：阻塞原因需说明维护状态目录：%v", item.name, plan.Blocking)
		}
	}
	// 正常默认路径（状态目录位于实例目录内）不回归。
	normalRequest := validReinitRequest(t, paths)
	normalRequest.Paths.StateDir = filepath.Join(instanceDir, "state")
	normal, err := PlanFullReinit(normalRequest)
	if err != nil {
		t.Fatalf("正常路径生成计划失败：%v", err)
	}
	if !normal.CanExecute || len(normal.Blocking) != 0 {
		t.Fatalf("实例内状态目录不应被阻塞：%v", normal.Blocking)
	}
}

func TestReinitClearItemsGuardEvidenceAndInstanceRoot(t *testing.T) {
	paths := reinitTestPaths(t)
	journalPath := filepath.Join(paths.InstanceDir, reinitJournalName)
	maintLogPath := filepath.Join(paths.InstanceDir, ".login-setup-maintenance.jsonl")
	plan := ReinitPlan{}
	validateReinitClearItems(paths, journalPath, []ReinitItem{
		{Label: "实例目录", Path: paths.InstanceDir},
		{Label: "执行日志", Path: journalPath},
		{Label: "维护日志", Path: maintLogPath},
		{Label: "实例父目录", Path: filepath.Dir(paths.InstanceDir)},
	}, &plan)
	if len(plan.Blocking) < 4 {
		t.Fatalf("清除项包含实例根/证据日志时必须阻塞，实际：%v", plan.Blocking)
	}
	// 正常 DB/配置/状态目录项不受影响。
	normalPlan, err := PlanFullReinit(validReinitRequest(t, paths))
	if err != nil {
		t.Fatalf("正常计划失败：%v", err)
	}
	if !normalPlan.CanExecute {
		t.Fatalf("正常计划不应被证据守卫阻塞：%v", normalPlan.Blocking)
	}
}
