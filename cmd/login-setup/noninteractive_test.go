package main

// 步骤297：非交互子命令定向测试。
//
// 覆盖：命令表/未知命令退出码、状态检测与 check 未就绪退出码、plan/apply 的确认串
// 与真实落盘、脱敏导出/导入预览与确认、秘密通道选择、一次性密码交付文件与不覆盖、
// JSON 错误结构。测试使用 t.TempDir 与合成配置，不连接真实数据库/真实用户数据。

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/setupconsole"

	_ "modernc.org/sqlite"
)

// runCLITest 执行非交互命令并返回退出码/标准输出/错误输出。
func runCLITest(t *testing.T, args []string, stdin string, configPath string) (int, string, string) {
	t.Helper()
	originalCwd, _ := os.Getwd()
	defer func() { _ = os.Chdir(originalCwd) }()
	var stdout, stderr bytes.Buffer
	code := runNonInteractive(args, cliEnv{ctx: context.Background(),
		stdin: strings.NewReader(stdin), stdout: &stdout, stderr: &stderr,
		configPath: configPath})
	return code, stdout.String(), stderr.String()
}

// decodeCLIJSON 解析单行 JSON 输出。
func decodeCLIJSON(t *testing.T, text string) map[string]any {
	t.Helper()
	line := strings.TrimSpace(text)
	if index := strings.LastIndexByte(line, '\n'); index >= 0 {
		line = strings.TrimSpace(line[index+1:])
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		t.Fatalf("JSON 解析失败: %v；输出=%q", err, text)
	}
	return payload
}

// TestNonInteractiveCommandTable 命令表 JSON 与未知命令退出码。
func TestNonInteractiveCommandTable(t *testing.T) {
	code, stdout, _ := runCLITest(t, []string{"commands", "--json"}, "", "")
	if code != cliExitOK {
		t.Fatalf("commands 退出码 = %d，期望 0", code)
	}
	payload := decodeCLIJSON(t, stdout)
	rows, ok := payload["commands"].([]any)
	if !ok || len(rows) < 15 {
		t.Fatalf("命令表条目 = %v，期望至少 15", payload["commands"])
	}
	exitCodes, ok := payload["exit_codes"].(map[string]any)
	if !ok || exitCodes["not_ready"] != float64(cliExitNotReady) {
		t.Fatalf("退出码表 = %v", payload["exit_codes"])
	}
	code, _, stderr := runCLITest(t, []string{"bogus-command"}, "", "")
	if code != cliExitUsage {
		t.Fatalf("未知命令退出码 = %d，期望 %d", code, cliExitUsage)
	}
	if !strings.Contains(stderr, "UNKNOWN_COMMAND") {
		t.Fatalf("未知命令错误输出缺少稳定错误码：%s", stderr)
	}
}

// TestNonInteractiveStatusAndCheck 零配置状态：status 成功、check 未就绪退出 3。
func TestNonInteractiveStatusAndCheck(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "login.yaml")
	code, stdout, _ := runCLITest(t, []string{"status", "--config", configPath, "--json"}, "", configPath)
	if code != cliExitOK {
		t.Fatalf("status 退出码 = %d", code)
	}
	payload := decodeCLIJSON(t, stdout)
	detection, _ := payload["detection"].(map[string]any)
	if detection["state"] != "no-config" {
		t.Fatalf("状态 = %v，期望 no-config", detection["state"])
	}
	code, _, _ = runCLITest(t, []string{"check", "--config", configPath, "--json"}, "", configPath)
	if code != cliExitNotReady {
		t.Fatalf("check 未就绪退出码 = %d，期望 %d", code, cliExitNotReady)
	}
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Fatalf("只读命令不应创建配置文件: %v", err)
	}
}

// TestNonInteractiveApplyPlanExportImport 应用推荐配置、计划、导出、导入闭环。
func TestNonInteractiveApplyPlanExportImport(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "login.yaml")
	env := func(extra ...string) []string { return append(extra, "--config", configPath) }
	// 未确认不得写盘。
	code, _, stderr := runCLITest(t, env("apply", "--profile", "local", "--json"), "", configPath)
	if code != cliExitUsage {
		t.Fatalf("无确认 apply 退出码 = %d，期望 %d（%s）", code, cliExitUsage, stderr)
	}
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Fatalf("未确认 apply 不应写配置: %v", err)
	}
	// 确认后应用。
	code, stdout, stderr := runCLITest(t, env("apply", "--profile", "local",
		"--confirm", "APPLY-RECOMMENDATION", "--json"), "", configPath)
	if code != cliExitOK {
		t.Fatalf("apply 退出码 = %d（%s）；输出=%s", code, stderr, stdout)
	}
	payload := decodeCLIJSON(t, stdout)
	if payload["saved"] != true {
		t.Fatalf("apply 未报告保存成功：%v", payload)
	}
	raw, err := os.ReadFile(configPath)
	if err != nil || len(raw) == 0 {
		t.Fatalf("配置文件未写入: %v", err)
	}
	// plan 只读且不改变文件。
	before := append([]byte(nil), raw...)
	code, stdout, _ = runCLITest(t, env("plan", "--profile", "local", "--json"), "", configPath)
	if code != cliExitOK {
		t.Fatalf("plan 退出码 = %d", code)
	}
	plan := decodeCLIJSON(t, stdout)
	if plan["config_would_change"] != false {
		t.Fatalf("apply 后 plan 应报告无变化：%v", plan["config_would_change"])
	}
	if after, _ := os.ReadFile(configPath); string(after) != string(before) {
		t.Fatal("plan 不应修改配置文件")
	}
	// 导出脱敏配置。
	exportPath := filepath.Join(dir, "exported.yaml")
	code, stdout, stderr = runCLITest(t, env("export", "config", "--masked",
		"--out", exportPath, "--json"), "", configPath)
	if code != cliExitOK {
		t.Fatalf("export 退出码 = %d（%s）；输出=%s", code, stderr, stdout)
	}
	if _, err := os.Stat(exportPath); err != nil {
		t.Fatalf("脱敏导出文件不存在: %v", err)
	}
	// 导入：错误确认串退出 4 且文件不变；正确确认串成功并创建最后有效副本。
	beforeHash := fileSHA256Test(t, configPath)
	code, stdout, _ = runCLITest(t, env("import", "config", "--file", exportPath,
		"--confirm", "WRONG", "--json"), "", configPath)
	if code != cliExitConflict {
		t.Fatalf("错误确认导入退出码 = %d，期望 %d", code, cliExitConflict)
	}
	preview := decodeCLIJSON(t, stdout)
	if preview["required_confirm"] != "IMPORT-CONFIG" {
		t.Fatalf("预览确认串 = %v", preview["required_confirm"])
	}
	if fileSHA256Test(t, configPath) != beforeHash {
		t.Fatal("错误确认导入不应修改配置文件")
	}
	code, _, stderr = runCLITest(t, env("import", "config", "--file", exportPath,
		"--confirm", "IMPORT-CONFIG", "--json"), "", configPath)
	if code != cliExitOK {
		t.Fatalf("确认导入退出码 = %d（%s）", code, stderr)
	}
	if _, err := os.Stat(configPath + ".last-valid"); err != nil {
		t.Fatalf("导入保存未创建最后有效副本: %v", err)
	}
	maintenanceLog, err := os.ReadFile(filepath.Join(dir, ".login-setup-maintenance.jsonl"))
	if err != nil {
		t.Fatalf("导入未写维护日志: %v", err)
	}
	if !strings.Contains(string(maintenanceLog), `"action":"config.import"`) ||
		!strings.Contains(string(maintenanceLog), `"result":"success"`) {
		t.Fatalf("导入维护日志缺少 success 证据：%s", maintenanceLog)
	}
}

// TestNonInteractiveSecretChannels 秘密通道：生成密码必须显式交付、互斥通道、受限文件。
func TestNonInteractiveSecretChannels(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "login.yaml")
	if code, _, _ := runCLITest(t, []string{"root", "init", "--config", configPath,
		"--confirm", "INIT-ROOT", "--generate-password", "--json"}, "", configPath); code != cliExitUsage {
		t.Fatalf("生成密码无交付通道退出码 = %d，期望 %d", code, cliExitUsage)
	}
	if code, _, _ := runCLITest(t, []string{"root", "init", "--config", configPath,
		"--confirm", "INIT-ROOT", "--generate-password", "--generated-password-file",
		filepath.Join(dir, "pwd.txt"), "--password-stdin", "--json"}, "", configPath); code != cliExitUsage {
		t.Fatalf("多个秘密通道退出码 = %d，期望 %d", code, cliExitUsage)
	}
	missing := filepath.Join(dir, "missing.pwd")
	if code, _, _ := runCLITest(t, []string{"root", "init", "--config", configPath,
		"--confirm", "INIT-ROOT", "--password-file", missing, "--json"}, "", configPath); code != cliExitUsage {
		t.Fatalf("缺失密码文件退出码 = %d，期望 %d", code, cliExitUsage)
	}
	// 从标准输入读取密码（去掉行尾 CRLF）。
	password, generated, err := readCLISecret(cliEnv{stdin: strings.NewReader("Abc123!\r\n")},
		"测试", true, "", false)
	if err != nil || generated || password != "Abc123!" {
		t.Fatalf("标准输入密码 = %q generated=%v err=%v", password, generated, err)
	}
	// 一次性密码交付：写 0600 新文件、拒绝覆盖、无通道时报错。
	env := cliEnv{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	target := filepath.Join(dir, "one-time.pwd")
	if err := deliverGeneratedPassword(env, "OneTimeSecret-1", target, false); err != nil {
		t.Fatalf("交付一次性密码: %v", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("一次性密码文件不存在: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("一次性密码文件权限 = %v，期望仅属主可读写", info.Mode())
	}
	if content, _ := os.ReadFile(target); strings.TrimSpace(string(content)) != "OneTimeSecret-1" {
		t.Fatalf("一次性密码文件内容不符")
	}
	if err := deliverGeneratedPassword(env, "SecondSecret-2", target, false); err == nil {
		t.Fatal("已存在的交付文件必须拒绝覆盖")
	}
	if err := deliverGeneratedPassword(cliEnv{stdout: &bytes.Buffer{}}, "LostSecret-3", "", false); err == nil {
		t.Fatal("无显式交付通道时必须失败，避免秘密丢失")
	}
}

// TestNonInteractiveUsageErrors 未知/缺参数/非法 flag 的稳定退出码。
func TestNonInteractiveUsageErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"db-no-sub", []string{"db"}},
		{"root-no-sub", []string{"root"}},
		{"export-without-mode", []string{"export", "config", "--out", "x.yaml"}},
		{"accounts-apply-missing", []string{"accounts", "apply", "--confirm", "APPLY-ACCOUNT"}},
		{"unknown-flag", []string{"status", "--definitely-unknown"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			code := runNonInteractive(testCase.args, cliEnv{ctx: context.Background(),
				stdin: strings.NewReader(""), stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}})
			if code != cliExitUsage {
				t.Fatalf("退出码 = %d，期望 %d", code, cliExitUsage)
			}
		})
	}
}

// fileSHA256Test 返回文件内容摘要（十六进制），读取失败直接失败测试。
func fileSHA256Test(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s: %v", path, err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// TestNonInteractivePasswordFileRejectsInsecureFile 密码文件必须是受保护普通文件；
// 非 Windows 下组/其他用户可读的文件必须拒绝（Windows DACL 用例见 _windows_test）。
func TestNonInteractivePasswordFileRejectsInsecureFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 模式位不适用；DACL 拒绝用例见 noninteractive_windows_test.go")
	}
	dir := t.TempDir()
	configPath := filepath.Join(dir, "login.yaml")
	wide := filepath.Join(dir, "wide.pwd")
	if err := os.WriteFile(wide, []byte("WeakFilePassword!\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCLITest(t, []string{"root", "init", "--config", configPath,
		"--confirm", "INIT-ROOT", "--password-file", wide, "--json"}, "", configPath)
	if code != cliExitUsage {
		t.Fatalf("宽权限密码文件退出码 = %d，期望 %d（%s）", code, cliExitUsage, stderr)
	}
	if !strings.Contains(stderr, "SECRET_READ_FAILED") {
		t.Fatalf("缺少稳定错误码：%s", stderr)
	}
}

// TestNonInteractiveGeneratedPasswordFileProtected 生成密码文件使用受保护写入，
// 且 JSON 模式禁止 --print-generated（避免明文进入自动日志）。
func TestNonInteractiveGeneratedPasswordFileProtected(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "login.yaml")
	env := cliEnv{ctx: context.Background(), stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	target := filepath.Join(dir, "one-time.pwd")
	if err := deliverGeneratedPassword(env, "Generated-Once-1", target, false); err != nil {
		t.Fatalf("生成密码文件: %v", err)
	}
	if raw, err := os.ReadFile(target); err != nil || strings.TrimSpace(string(raw)) != "Generated-Once-1" {
		t.Fatalf("生成密码文件内容不符: %v", err)
	}
	jsonEnv := cliEnv{json: true, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	err := deliverGeneratedPassword(jsonEnv, "Generated-Once-2", "", true)
	if err == nil {
		t.Fatal("JSON 模式 + --print-generated 必须拒绝")
	}
	var failure *cliFailure
	if !errors.As(err, &failure) || failure.Code != "SECRET_CHANNEL_CONFLICT" || failure.Exit != cliExitUsage {
		t.Fatalf("JSON 模式一次性密码冲突错误不符：%v", err)
	}
	code, _, _ := runCLITest(t, []string{"root", "init", "--config", configPath,
		"--confirm", "INIT-ROOT", "--generate-password", "--print-generated", "--json"}, "", configPath)
	if code == cliExitOK {
		t.Fatal("JSON 模式 + --print-generated 命令必须拒绝")
	}
}

// TestNonInteractiveIllegalPasswordFlag 非法 --password 参数必须按用法错误退出 2。
func TestNonInteractiveIllegalPasswordFlag(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "login.yaml")
	code, _, stderr := runCLITest(t, []string{"root", "init", "--config", configPath,
		"--confirm", "INIT-ROOT", "--password", "ShouldNotBeAccepted"}, "", configPath)
	if code != cliExitUsage {
		t.Fatalf("非法 --password 退出码 = %d，期望 %d（%s）", code, cliExitUsage, stderr)
	}
}

// TestNonInteractiveImportFailsClosedWhenMaintenanceLocked 维护锁被占时导入必须
// fail-closed、不写配置，并在维护日志留下 started/failed 证据。
func TestNonInteractiveImportFailsClosedWhenMaintenanceLocked(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "login.yaml")
	if code, _, stderr := runCLITest(t, []string{"apply", "--profile", "local",
		"--confirm", "APPLY-RECOMMENDATION", "--config", configPath, "--json"}, "", configPath); code != cliExitOK {
		t.Fatalf("准备配置: %d（%s）", code, stderr)
	}
	exportPath := filepath.Join(dir, "masked.yaml")
	if code, _, stderr := runCLITest(t, []string{"export", "config", "--masked",
		"--out", exportPath, "--config", configPath, "--json"}, "", configPath); code != cliExitOK {
		t.Fatalf("准备导出: %d（%s）", code, stderr)
	}
	verifyBefore := fileSHA256Test(t, configPath)
	identity, err := setupconsole.LocalMaintenanceIdentity(dir)
	if err != nil {
		t.Fatalf("本地维护身份: %v", err)
	}
	lock, err := setupconsole.AcquireMaintenanceLock(context.Background(),
		setupconsole.LockRequest{InstanceDir: dir, Purpose: "测试持有维护锁", Operator: identity})
	if err != nil {
		t.Fatalf("持有维护锁: %v", err)
	}
	defer func() { _ = lock.Release() }()
	code, _, _ := runCLITest(t, []string{"import", "config", "--config", configPath,
		"--file", exportPath, "--confirm", "IMPORT-CONFIG", "--json"}, "", configPath)
	if code == cliExitOK {
		t.Fatal("维护锁被占时导入必须失败（fail-closed）")
	}
	if fileSHA256Test(t, configPath) != verifyBefore {
		t.Fatal("维护锁被占时导入不应修改配置")
	}
	logPath := filepath.Join(dir, ".login-setup-maintenance.jsonl")
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("读取维护日志: %v", err)
	}
	text := string(raw)
	if !strings.Contains(text, `"action":"config.import"`) {
		t.Fatalf("维护日志缺少 config.import 动作：%s", text)
	}
	if !strings.Contains(text, `"result":"started"`) || !strings.Contains(text, `"result":"failed"`) {
		t.Fatalf("维护日志缺少 started/failed 证据：%s", text)
	}
}

// TestNonInteractiveRecoverFailsClosedWhenMaintenanceLocked 推荐运行配置恢复同样
// 在维护锁下 fail-closed 并留下维护证据。
func TestNonInteractiveRecoverFailsClosedWhenMaintenanceLocked(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "login.yaml")
	if code, _, stderr := runCLITest(t, []string{"apply", "--profile", "local",
		"--confirm", "APPLY-RECOMMENDATION", "--config", configPath, "--json"}, "", configPath); code != cliExitOK {
		t.Fatalf("准备配置: %d（%s）", code, stderr)
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(string(raw), "    level: info", "    level: debug", 1)
	if changed == string(raw) {
		t.Fatalf("无法构造恢复差异配置：%s", raw)
	}
	if err := os.WriteFile(configPath, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	identity, err := setupconsole.LocalMaintenanceIdentity(dir)
	if err != nil {
		t.Fatalf("本地维护身份: %v", err)
	}
	lock, err := setupconsole.AcquireMaintenanceLock(context.Background(),
		setupconsole.LockRequest{InstanceDir: dir, Purpose: "测试持有维护锁", Operator: identity})
	if err != nil {
		t.Fatalf("持有维护锁: %v", err)
	}
	defer func() { _ = lock.Release() }()
	code, _, _ := runCLITest(t, []string{"recover", "apply", "--profile", "local",
		"--confirm", "RESET-RUNTIME-CONFIG", "--config", configPath, "--json"}, "", configPath)
	if code == cliExitOK {
		t.Fatal("维护锁被占时恢复必须失败（fail-closed）")
	}
	logPath := filepath.Join(dir, ".login-setup-maintenance.jsonl")
	rawLog, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("读取维护日志: %v", err)
	}
	text := string(rawLog)
	if !strings.Contains(text, `"action":"config.restore-recommended"`) ||
		!strings.Contains(text, `"result":"failed"`) {
		t.Fatalf("维护日志缺少 config.restore-recommended failed 证据：%s", text)
	}
}

// 防止 time 导入在部分构建标签下未使用（测试保留显式等待点）。
var _ = time.Now

// TestNonInteractiveHumanOutputSanitizesANSI 普通文本输出不得把外部路径中的
// ANSI 控制序列原样写到终端（JSON 模式由 encoding/json 转义）。
func TestNonInteractiveHumanOutputSanitizesANSI(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "login.yaml")
	evil := filepath.Join(dir, "\x1b[31mred\x1b[0m.yaml")
	code, stdout, stderr := runCLITest(t, []string{"status", "--config", evil}, "", evil)
	if code != cliExitOK {
		t.Fatalf("status 退出码 = %d", code)
	}
	if strings.ContainsAny(stdout, "\x1b\x07\x00") || strings.ContainsAny(stderr, "\x1b\x07\x00") {
		t.Fatalf("人类输出含 ANSI/控制字符：stdout=%q stderr=%q", stdout, stderr)
	}
	_ = configPath
}

// prepareInstanceWithRoot 用 CLI 自身创建临时实例（配置+DB+root），供 R1 状态不变测试。
func prepareInstanceWithRoot(t *testing.T) (dir, configPath, dbPath string) {
	t.Helper()
	dir = t.TempDir()
	configPath = filepath.Join(dir, "login.yaml")
	if code, _, stderr := runCLITest(t, []string{"apply", "--profile", "local",
		"--confirm", "APPLY-RECOMMENDATION", "--init-db", "--create-master-key",
		"--config", configPath, "--json"}, "", configPath); code != cliExitOK {
		t.Fatalf("初始化配置/数据库: %d（%s）", code, stderr)
	}
	generated := filepath.Join(dir, "root.generated")
	if code, _, stderr := runCLITest(t, []string{"root", "init", "--config", configPath,
		"--confirm", "INIT-ROOT", "--username", "root", "--generate-password",
		"--generated-password-file", generated, "--json"}, "", configPath); code != cliExitOK {
		t.Fatalf("创建 root: %d（%s）", code, stderr)
	}
	if code, _, stderr := runCLITest(t, []string{"presets", "install", "--config", configPath,
		"--confirm", "INSTALL-PRESETS", "--json"}, "", configPath); code != cliExitOK {
		t.Fatalf("安装系统预设: %d（%s）", code, stderr)
	}
	return dir, configPath, filepath.Join(dir, "database", "login.db")
}

// auditSnapshot 读取审计事件总数与 root 口令哈希（只读，用于证明状态未变）。
func auditSnapshot(t *testing.T, dbPath string) (int, string) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("打开审计数据库: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec("PRAGMA query_only=ON"); err != nil {
		t.Fatalf("只读连接: %v", err)
	}
	var auditCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM audit_events").Scan(&auditCount); err != nil {
		t.Fatalf("读取审计计数: %v", err)
	}
	var rootHash string
	if err := db.QueryRow(`SELECT pc.password_hash FROM password_credentials pc
JOIN users u ON u.id=pc.user_id WHERE u.is_root=1`).Scan(&rootHash); err != nil {
		t.Fatalf("读取 root 口令哈希: %v", err)
	}
	return auditCount, rootHash
}

// TestNonInteractiveRootResetConflictDoesNotChangeState M3 MEDIUM-R1：
// root init --json --print-generated 必须在任何写/审计前拒绝，不能重置口令后丢失交付。
func TestNonInteractiveRootResetConflictDoesNotChangeState(t *testing.T) {
	_, configPath, dbPath := prepareInstanceWithRoot(t)
	beforeHash := fileSHA256Test(t, dbPath)
	beforeAudit, beforePassword := auditSnapshot(t, dbPath)
	code, _, stderr := runCLITest(t, []string{"root", "init", "--config", configPath,
		"--confirm", "INIT-ROOT", "--username", "root", "--generate-password",
		"--print-generated", "--reset-existing", "--json"}, "", configPath)
	if code != cliExitUsage || !strings.Contains(stderr, "SECRET_CHANNEL_CONFLICT") {
		t.Fatalf("冲突命令退出码/错误码 = %d/%s，期望 2 且 SECRET_CHANNEL_CONFLICT", code, stderr)
	}
	afterHash := fileSHA256Test(t, dbPath)
	afterAudit, afterPassword := auditSnapshot(t, dbPath)
	if afterHash != beforeHash {
		t.Fatal("冲突命令修改了数据库文件")
	}
	if afterAudit != beforeAudit {
		t.Fatalf("冲突命令产生审计写入：%d -> %d", beforeAudit, afterAudit)
	}
	if afterPassword != beforePassword || afterPassword == "" {
		t.Fatal("冲突命令改变了 root 口令哈希")
	}
}

// TestNonInteractiveAccountsConflictDoesNotChangeState M3 MEDIUM-R1：
// accounts apply --json --print-generated 同样必须在账户创建/审计前拒绝。
func TestNonInteractiveAccountsConflictDoesNotChangeState(t *testing.T) {
	dir, configPath, dbPath := prepareInstanceWithRoot(t)
	created := filepath.Join(dir, "helper.generated")
	if code, _, stderr := runCLITest(t, []string{"accounts", "apply", "--config", configPath,
		"--confirm", "APPLY-ACCOUNT", "--scheme", "normal_user", "--username", "helper",
		"--generate-password", "--generated-password-file", created, "--json"}, "", configPath); code != cliExitOK {
		t.Fatalf("准备账户: %d（%s）", code, stderr)
	}
	beforeHash := fileSHA256Test(t, dbPath)
	beforeAudit, beforePassword := auditSnapshot(t, dbPath)
	code, _, stderr := runCLITest(t, []string{"accounts", "apply", "--config", configPath,
		"--confirm", "APPLY-ACCOUNT", "--scheme", "normal_user", "--username", "other",
		"--generate-password", "--print-generated", "--json"}, "", configPath)
	if code != cliExitUsage || !strings.Contains(stderr, "SECRET_CHANNEL_CONFLICT") {
		t.Fatalf("冲突命令退出码/错误码 = %d/%s，期望 2 且 SECRET_CHANNEL_CONFLICT", code, stderr)
	}
	if fileSHA256Test(t, dbPath) != beforeHash {
		t.Fatal("冲突命令修改了数据库文件")
	}
	if afterAudit, afterPassword := auditSnapshot(t, dbPath); afterAudit != beforeAudit ||
		afterPassword != beforePassword {
		t.Fatalf("冲突命令产生状态变化：audit %d->%d", beforeAudit, afterAudit)
	}
}
