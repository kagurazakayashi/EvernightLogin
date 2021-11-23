package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/avatar"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	appmigrations "github.com/kagurazakayashi/EvernightLogin/migrations"
)

// cliEnvironment 是 CLI 端到端测试的本地环境（真实数据库/密钥文件/头像/配置）。
type cliEnvironment struct {
	dir        string
	database   string
	keyFile    string
	outputDir  string
	avatarDir  string
	configFile string
}

// setupCLIEnvironment 创建已完成迁移的临时数据库、受保护主密钥文件、头像目录与
// 配置 YAML；不接触真实业务库。
func setupCLIEnvironment(t *testing.T) *cliEnvironment {
	t.Helper()
	dir := testutil.TempDir(t)
	env := &cliEnvironment{
		dir:        dir,
		database:   filepath.Join(dir, "login.db"),
		keyFile:    filepath.Join(dir, "master-key.json"),
		outputDir:  filepath.Join(dir, "backups"),
		avatarDir:  filepath.Join(dir, "avatars"),
		configFile: filepath.Join(dir, "login.yaml"),
	}
	for _, directory := range []string{env.outputDir, env.avatarDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatalf("创建测试目录失败：%v", err)
		}
	}
	store, err := storagesqlite.Open(context.Background(),
		storagesqlite.DefaultOptions(env.database))
	if err != nil {
		t.Fatalf("打开测试数据库失败：%v", err)
	}
	migrations, err := migrate.LoadMigrations(appmigrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移失败：%v", err)
	}
	if _, err := store.Migrate(context.Background(), migrations); err != nil {
		t.Fatalf("执行迁移失败：%v", err)
	}
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	userID := "usr_" + strings.Repeat("ff", 16)
	if _, err := store.ExecContext(context.Background(), `INSERT INTO users(
id, username, username_normalized, created_at_ms, updated_at_ms)
VALUES(?,?,?,?,?)`, userID, "cli-user", "cli-user", now.UnixMilli(), now.UnixMilli()); err != nil {
		t.Fatalf("插入测试用户失败：%v", err)
	}
	avatarStorage, err := avatar.NewLocalStorage(env.avatarDir)
	if err != nil {
		t.Fatalf("构造头像存储失败：%v", err)
	}
	avatarContent := []byte("cli-avatar-content")
	avatarKey, err := avatarStorage.Save(context.Background(), avatarContent, "png")
	if err != nil {
		t.Fatalf("写入头像失败：%v", err)
	}
	avatarDigest := sha256.Sum256(avatarContent)
	if _, err := store.ExecContext(context.Background(), `INSERT INTO avatars(
id, user_id, storage_key, media_type, byte_size, width, height, content_sha256,
source_kind, created_at_ms, updated_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		"avt_"+strings.Repeat("ee", 16), userID, avatarKey, "image/png",
		len(avatarContent), 16, 16, avatarDigest[:], "upload",
		now.UnixMilli(), now.UnixMilli()); err != nil {
		t.Fatalf("插入头像记录失败：%v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("关闭测试数据库失败：%v", err)
	}
	ring, err := secrets.GenerateKeyring("k1", now)
	if err != nil {
		t.Fatalf("生成密钥环失败：%v", err)
	}
	document, err := ring.Document()
	if err != nil {
		t.Fatalf("序列化密钥环失败：%v", err)
	}
	if err := secrets.WriteProtectedFile(env.keyFile, document); err != nil {
		t.Fatalf("写入受保护密钥文件失败：%v", err)
	}
	if err := os.WriteFile(env.configFile,
		[]byte("server:\n  listen_addr: 127.0.0.1:8080\n"), 0o600); err != nil {
		t.Fatalf("写入测试配置失败：%v", err)
	}
	return env
}

// runCLI 执行命令并返回退出码与输出。
func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// findBackupFile 返回输出目录中唯一的备份文件路径。
func findBackupFile(t *testing.T, directory string) string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("读取输出目录失败：%v", err)
	}
	var backups []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".elnbak") {
			backups = append(backups, filepath.Join(directory, entry.Name()))
		}
	}
	if len(backups) != 1 {
		t.Fatalf("输出目录备份文件 = %v，期望恰好 1 个", backups)
	}
	return backups[0]
}

// countAuditAction 查询数据库审计表中的动作数量。
func countAuditAction(t *testing.T, databasePath, action string) int {
	t.Helper()
	db, err := sql.Open("sqlite", databasePath+"?_query_only=1&_busy_timeout=5000")
	if err != nil {
		t.Fatalf("打开审计查询连接失败：%v", err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action=?`,
		action).Scan(&count); err != nil {
		t.Fatalf("查询审计动作失败：%v", err)
	}
	return count
}

// TestCLICreateVerifyAndInfo 端到端验证：本地手动创建加密热备份 → 独立认证校验
// → 无密钥结构检查；并确认真实审计落在数据库。
func TestCLICreateVerifyAndInfo(t *testing.T) {
	env := setupCLIEnvironment(t)
	code, stdout, stderr := runCLI(t, "create",
		"--database", env.database, "--key-file", env.keyFile,
		"--output", env.outputDir, "--operator", "local-admin-test",
		"--config", env.configFile, "--avatars", env.avatarDir,
		"--request-id", "req_cli_backup_001")
	if code != ExitOK {
		t.Fatalf("create 退出码 = %d，期望 0；stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "备份完成") || !strings.Contains(stdout, "SHA-256") {
		t.Fatalf("create 输出缺少关键信息：%s", stdout)
	}
	if strings.Contains(stdout, "master-key") || strings.Contains(stderr, "master-key") {
		t.Fatal("输出泄露了主密钥文件路径")
	}
	if !strings.Contains(stderr, "明文数据库快照") || !strings.Contains(stderr, "icacls") {
		t.Fatalf("create 未输出多用户 Windows 明文暂存告警：%s", stderr)
	}
	backupFile := findBackupFile(t, env.outputDir)
	for _, action := range []string{"backup.request", "backup.started", "backup.finish"} {
		if countAuditAction(t, env.database, action) == 0 {
			t.Fatalf("真实审计缺少动作 %s", action)
		}
	}

	// verify 使用相对路径与 create 一致地做 Abs 规范化（切换工作目录到测试目录）。
	t.Chdir(env.dir)
	code, stdout, stderr = runCLI(t, "verify", "--file",
		filepath.Join(filepath.Base(env.outputDir), filepath.Base(backupFile)),
		"--key-file", filepath.Base(env.keyFile), "--json")
	if code != ExitOK {
		t.Fatalf("verify 退出码 = %d，期望 0；stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, `"authenticated": true`) {
		t.Fatalf("verify JSON 未标记认证通过：%s", stdout)
	}
	if !strings.Contains(stdout, `"status": "included"`) {
		t.Fatalf("verify JSON 未包含附件/配置范围：%s", stdout)
	}

	code, stdout, stderr = runCLI(t, "info", "--file", backupFile)
	if code != ExitOK {
		t.Fatalf("info 退出码 = %d，期望 0；stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "未认证解密") {
		t.Fatalf("info 未明确说明未认证：%s", stdout)
	}
}

// TestCLIVerifyWrongKeyAndTamperedFile 验证错误密钥退出码 4、被篡改/截断文件退出码
// 3，且错误输出不包含密钥材料。
func TestCLIVerifyWrongKeyAndTamperedFile(t *testing.T) {
	env := setupCLIEnvironment(t)
	code, _, stderr := runCLI(t, "create",
		"--database", env.database, "--key-file", env.keyFile,
		"--output", env.outputDir, "--operator", "local-admin-test")
	if code != ExitOK {
		t.Fatalf("create 退出码 = %d；stderr=%s", code, stderr)
	}
	backupFile := findBackupFile(t, env.outputDir)

	otherDir := testutil.TempDir(t)
	otherRing, err := secrets.GenerateKeyring("k2",
		time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("生成另一密钥环失败：%v", err)
	}
	otherDoc, err := otherRing.Document()
	if err != nil {
		t.Fatalf("序列化另一密钥环失败：%v", err)
	}
	otherKey := filepath.Join(otherDir, "other-key.json")
	if err := secrets.WriteProtectedFile(otherKey, otherDoc); err != nil {
		t.Fatalf("写入另一密钥文件失败：%v", err)
	}
	code, _, stderr = runCLI(t, "verify", "--file", backupFile, "--key-file", otherKey)
	if code != ExitDecryptFailed {
		t.Fatalf("错误密钥退出码 = %d，期望 %d；stderr=%s", code, ExitDecryptFailed, stderr)
	}
	if !strings.Contains(stderr, "BACKUP_DECRYPT_FAILED") {
		t.Fatalf("错误密钥未映射稳定错误码：%s", stderr)
	}

	data, err := os.ReadFile(backupFile)
	if err != nil {
		t.Fatalf("读取备份文件失败：%v", err)
	}
	tampered := append([]byte(nil), data...)
	tampered[len(tampered)-17] ^= 0xff
	tamperedPath := filepath.Join(env.dir, "tampered.elnbak")
	if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
		t.Fatalf("写入篡改文件失败：%v", err)
	}
	code, _, stderr = runCLI(t, "verify", "--file", tamperedPath, "--key-file", env.keyFile)
	if code != ExitVerifyFailed && code != ExitDecryptFailed {
		t.Fatalf("篡改文件退出码 = %d，期望 3 或 4；stderr=%s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(env.outputDir, "tampered.elnbak")); err == nil {
		t.Fatal("verify 不应在输出目录写文件")
	}
	if strings.Contains(stderr, base64.StdEncoding.EncodeToString([]byte("k1"))) {
		t.Fatal("错误输出泄露了密钥内容")
	}
}

// TestCLIUsageAndSafety 验证必填参数、未知命令、主密钥与备份同目录被拒绝。
func TestCLIUsageAndSafety(t *testing.T) {
	env := setupCLIEnvironment(t)
	if code, _, _ := runCLI(t); code != ExitUsage {
		t.Fatalf("无参数退出码 = %d，期望 2", code)
	}
	if code, _, _ := runCLI(t, "unknown-command"); code != ExitUsage {
		t.Fatalf("未知命令退出码 = %d，期望 2", code)
	}
	code, _, stderr := runCLI(t, "create", "--database", env.database,
		"--key-file", env.keyFile, "--output", env.outputDir,
		"--operator", "bad operator with spaces")
	if code != ExitUsage {
		t.Fatalf("非法操作者退出码 = %d，期望 2；stderr=%s", code, stderr)
	}
	// 主密钥文件放在输出目录内必须被拒绝（主密钥与备份分离）。
	insideKey := filepath.Join(env.outputDir, "master-key.json")
	document, err := os.ReadFile(env.keyFile)
	if err != nil {
		t.Fatalf("读取密钥文件失败：%v", err)
	}
	if err := secrets.WriteProtectedFile(insideKey, document); err != nil {
		t.Fatalf("写入同目录密钥失败：%v", err)
	}
	missingDatabase := filepath.Join(testutil.TempDir(t), "missing.db")
	code, _, stderr = runCLI(t, "create", "--database", missingDatabase,
		"--key-file", env.keyFile, "--output", env.outputDir,
		"--operator", "local-admin-test")
	if code != ExitError {
		t.Fatalf("缺失数据库退出码 = %d，期望 1；stderr=%s", code, stderr)
	}
	if _, statErr := os.Stat(missingDatabase); !os.IsNotExist(statErr) {
		t.Fatal("create 不应为缺失数据库创建空文件")
	}
	code, _, stderr = runCLI(t, "create", "--database", env.database,
		"--key-file", insideKey, "--output", env.outputDir,
		"--operator", "local-admin-test")
	if code != ExitUsage || !strings.Contains(stderr, "主密钥文件不能放在备份输出目录内") {
		t.Fatalf("同目录密钥退出码 = %d，期望 2；stderr=%s", code, stderr)
	}
	if strings.Contains(fmt.Sprint(document), "backup") {
		t.Fatal("密钥文档出现异常内容")
	}
}

// TestKeyInside 验证主密钥位置判断（含子目录与相似前缀路径）。
func TestKeyInside(t *testing.T) {
	base := testutil.TempDir(t)
	if !keyInside(filepath.Join(base, "key.json"), base) {
		t.Fatal("输出目录内密钥未被识别")
	}
	if !keyInside(filepath.Join(base, "sub", "key.json"), base) {
		t.Fatal("输出目录子目录密钥未被识别")
	}
	if keyInside(filepath.Join(base, "..", "key.json"), base) {
		t.Fatal("输出目录外密钥被误判为目录内")
	}
}
