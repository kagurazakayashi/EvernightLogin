package setupconsole

// 步骤 292 的定向测试：只读备份列表/检查/计划与注册入口（不生成真实备份，
// 不打开数据库，不触碰生产数据）。

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/backup"
)

func writeTestFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("写入测试文件失败：%v", err)
	}
}

func TestListBackupArtifactsFiltersAndSorts(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "a-backup.elnbak"), []byte("not-a-real-backup"))
	writeTestFile(t, filepath.Join(dir, "b-backup.elnbak"), []byte(strings.Repeat("x", 32)))
	writeTestFile(t, filepath.Join(dir, "notes.txt"), []byte("ignore"))
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o700); err != nil {
		t.Fatalf("创建子目录失败：%v", err)
	}

	artifacts, err := ListBackupArtifacts(dir)
	if err != nil {
		t.Fatalf("列出备份失败：%v", err)
	}
	if len(artifacts) != 2 {
		t.Fatalf("应只列出 2 个备份产物，实际 %d：%+v", len(artifacts), artifacts)
	}
	for _, artifact := range artifacts {
		if !strings.HasSuffix(strings.ToLower(artifact.Name), backupArtifactSuffix) {
			t.Fatalf("列出非备份产物：%s", artifact.Name)
		}
		if artifact.Size <= 0 {
			t.Fatalf("产物大小应 >0：%+v", artifact)
		}
		if artifact.Problem != "" {
			t.Fatalf("普通文件不应有问题标记：%+v", artifact)
		}
	}

	if _, err := ListBackupArtifacts("relative/dir"); err == nil {
		t.Fatal("相对备份目录必须被拒绝")
	}
	if _, err := ListBackupArtifacts(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("不存在的备份目录必须报错")
	}
}

func TestInspectBackupArtifactRejectsNonArtifactAndReportsBrokenContainer(t *testing.T) {
	dir := t.TempDir()
	broken := filepath.Join(dir, "broken.elnbak")
	writeTestFile(t, broken, []byte("this-is-not-a-backup-container"))
	if _, err := InspectBackupArtifact(context.Background(), broken); err != nil {
		t.Fatalf("结构检查应返回报告而不是错误：%v", err)
	}
	inspection, err := InspectBackupArtifact(context.Background(), broken)
	if err != nil {
		t.Fatalf("结构检查失败：%v", err)
	}
	if inspection.Problem == "" {
		t.Fatal("损坏备份必须显示结构问题")
	}
	if inspection.Authenticated {
		t.Fatal("无主密钥时不得声称已认证")
	}

	if _, err := InspectBackupArtifact(context.Background(), filepath.Join(dir, "x.txt")); err == nil {
		t.Fatal("非 .elnbak 文件必须被拒绝")
	}
	if _, err := InspectBackupArtifact(context.Background(), "relative.elnbak"); err == nil {
		t.Fatal("相对备份路径必须被拒绝")
	}
}

func TestVerifyBackupArtifactRequiresUsableKeyring(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "b.elnbak")
	writeTestFile(t, artifact, []byte("placeholder"))
	if _, err := VerifyBackupArtifact(context.Background(), artifact, ""); err == nil {
		t.Fatal("缺少主密钥路径时必须报错")
	}
	if _, err := VerifyBackupArtifact(context.Background(), artifact, filepath.Join(dir, "missing.key")); err == nil {
		t.Fatal("不存在的主密钥文件必须报错")
	}
}

func TestExportBackupEntryValidatesInputsBeforeTouchingBackup(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "c.elnbak")
	writeTestFile(t, artifact, []byte("placeholder"))
	if _, err := ExportBackupEntry(context.Background(), BackupExportRequest{
		Path: artifact, MasterKeyFile: filepath.Join(dir, "missing.key"), EntryName: "",
		OutputPath: filepath.Join(dir, "out.bin"),
	}); err == nil {
		t.Fatal("缺少条目名时必须报错")
	}
	if _, err := ExportBackupEntry(context.Background(), BackupExportRequest{
		Path: artifact, MasterKeyFile: filepath.Join(dir, "missing.key"),
		EntryName: "database/main.sqlite",
	}); err == nil {
		t.Fatal("缺少导出目标时必须报错")
	}
}

func syntheticInspection(authenticated bool) BackupInspection {
	report := backup.VerifyReport{
		StructuralValid: true, Encrypted: true, Authenticated: authenticated,
		ManifestAvailable: true, FormatVersion: 1, BackupID: "bk_test_0001",
		Database: backup.DatabaseMeta{Engine: "sqlite", SchemaVersion: "0054"},
		Content: backup.ContentMeta{Database: true,
			Attachments: backup.ContentStatus{Status: backup.ContentIncluded, Count: 1},
			Config:      backup.ContentStatus{Status: backup.ContentIncluded},
			Keyring:     backup.ContentStatus{Status: backup.ContentExcluded}},
	}
	return BackupInspection{
		Path: "/backups/bk_test_0001.elnbak", FileSize: 1024,
		Report: report, Authenticated: authenticated,
		DatabaseEngine:  report.Database.Engine,
		SchemaVersion:   report.Database.SchemaVersion,
		ContentStatus:   "database=included",
		EncryptionState: "加密",
	}
}

func TestPlanControlledRestoreRequiresAuthenticationAndConfirmation(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data", "login.db")
	stateDir := filepath.Join(t.TempDir(), "state")

	unauth, err := PlanControlledRestore(RestorePlanRequest{
		Inspection: syntheticInspection(false), DatabasePath: dbPath,
		StateDir: stateDir, ConfirmText: "bk_test_0001",
	})
	if err != nil {
		t.Fatalf("生成恢复计划失败：%v", err)
	}
	if unauth.CanExecute {
		t.Fatal("未认证备份不得允许执行恢复")
	}
	if !hasBlockingContaining(unauth.Blocking, "认证") {
		t.Fatalf("阻塞原因需说明认证缺失：%v", unauth.Blocking)
	}

	wrongConfirm, err := PlanControlledRestore(RestorePlanRequest{
		Inspection: syntheticInspection(true), DatabasePath: dbPath,
		StateDir: stateDir, ConfirmText: "wrong",
	})
	if err != nil {
		t.Fatalf("生成恢复计划失败：%v", err)
	}
	if wrongConfirm.CanExecute {
		t.Fatal("确认串不匹配时不得允许执行")
	}
	if wrongConfirm.RequiredConfirm != "bk_test_0001" {
		t.Fatalf("确认串应等于备份 ID，实际 %q", wrongConfirm.RequiredConfirm)
	}

	sameDir, err := PlanControlledRestore(RestorePlanRequest{
		Inspection: syntheticInspection(true), DatabasePath: dbPath,
		StateDir: filepath.Dir(dbPath), ConfirmText: "bk_test_0001",
		AcknowledgeOutOfBand: true,
	})
	if err != nil {
		t.Fatalf("生成恢复计划失败：%v", err)
	}
	if sameDir.CanExecute {
		t.Fatal("恢复状态目录与数据库目录相同必须被拒绝")
	}

	ok, err := PlanControlledRestore(RestorePlanRequest{
		Inspection: syntheticInspection(true), DatabasePath: dbPath,
		StateDir: stateDir, ConfirmText: "bk_test_0001",
	})
	if err != nil {
		t.Fatalf("生成恢复计划失败：%v", err)
	}
	if !ok.CanExecute {
		t.Fatalf("满足全部条件时计划应可执行，阻塞：%v", ok.Blocking)
	}
	if len(ok.RequiredSteps) == 0 || len(ok.Consequences) == 0 {
		t.Fatal("计划必须列出执行前置步骤与后果")
	}
}

func TestRegisterWS4RegistersBackupScreenIdempotentlyGuarded(t *testing.T) {
	app := NewApp(NewANSITerminal(strings.NewReader(""), io.Discard), "", nil)
	if err := RegisterWS4(app); err != nil {
		t.Fatalf("RegisterWS4 首次注册失败：%v", err)
	}
	if err := RegisterWS4(app); err == nil {
		t.Fatal("重复 RegisterWS4 必须返回错误（重复菜单/画面注册）")
	}
}

func hasBlockingContaining(blocking []string, fragment string) bool {
	for _, item := range blocking {
		if strings.Contains(item, fragment) {
			return true
		}
	}
	return false
}

func TestWS4ExportTargetRestrictsPathEscapeAndOverwrite(t *testing.T) {
	instanceDir := t.TempDir()
	inside := filepath.Join(instanceDir, "exports", "entry.bin")
	if err := os.MkdirAll(filepath.Dir(inside), 0o700); err != nil {
		t.Fatalf("创建导出目录失败：%v", err)
	}
	if target, err := ws4ExportTarget(instanceDir, inside); err != nil || target != inside {
		t.Fatalf("实例内新文件应允许：target=%q err=%v", target, err)
	}
	outside := filepath.Join(t.TempDir(), "escape.bin")
	if _, err := ws4ExportTarget(instanceDir, outside); err == nil {
		t.Fatal("实例目录外的导出路径必须被拒绝")
	}
	if err := os.WriteFile(inside, []byte("existing"), 0o600); err != nil {
		t.Fatalf("写入已存在文件失败：%v", err)
	}
	if _, err := ws4ExportTarget(instanceDir, inside); err == nil {
		t.Fatal("已存在的导出目标必须拒绝覆盖")
	}
	missingParent := filepath.Join(instanceDir, "missing", "entry.bin")
	if _, err := ws4ExportTarget(instanceDir, missingParent); err == nil {
		t.Fatal("父目录不存在时必须拒绝")
	}
	if _, err := ws4ExportTarget(instanceDir, "relative.bin"); err == nil {
		t.Fatal("相对导出路径必须拒绝")
	}
}

func TestBackupScreenRestoreRequiresAuthenticatedInspection(t *testing.T) {
	screen := NewBackupScreen(BackupScreenOptions{})
	if screen.inspect == nil {
		screen.prepareRestore()
	}
	if screen.errText == "" {
		t.Fatal("未检查备份时必须阻止恢复")
	}
	screen.inspect = &BackupInspection{Path: "/x/b.elnbak", Authenticated: false}
	screen.prepareRestore()
	if screen.errText == "" || screen.pendingRestore {
		t.Fatal("未认证备份必须阻止恢复并不得进入确认状态")
	}
}

func TestExecuteControlledRestoreRejectsMissingConfirmAndRuntime(t *testing.T) {
	if _, err := ExecuteControlledRestore(context.Background(), "", "", "bk", "reason", "WRONG"); err == nil {
		t.Fatal("错误确认串必须拒绝")
	}
	if _, err := ExecuteControlledRestore(context.Background(), "", "", "bk", "", "RESTORE"); err == nil {
		t.Fatal("缺少原因必须拒绝")
	}
	if _, err := ExecuteControlledRestore(context.Background(), "", "", "", "reason", "RESTORE"); err == nil {
		t.Fatal("缺少备份编号必须拒绝")
	}
	if _, err := ExecuteControlledRestore(context.Background(), "/nonexistent/login.yaml", "/tmp/x.db", "bk", "reason", "RESTORE"); err == nil {
		t.Fatal("实例配置不存在时必须如实失败（不得假成功）")
	}
}
