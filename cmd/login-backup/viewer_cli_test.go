package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/backup"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
)

// cliListResult 是 list --json 的测试解析结构。
type cliListResult struct {
	Authenticated bool   `json:"authenticated"`
	IntegrityOK   bool   `json:"integrity_verified"`
	FormatVersion int    `json:"format_version"`
	BackupID      string `json:"backup_id"`
	Database      struct {
		Engine              string `json:"engine"`
		SchemaVersion       string `json:"schema_version"`
		SchemaVersionNumber int    `json:"schema_version_number"`
		SizeBytes           int64  `json:"size_bytes"`
	} `json:"database"`
	Content map[string]any `json:"content"`
	Entries []struct {
		Name      string `json:"name"`
		Kind      string `json:"kind"`
		SizeBytes int64  `json:"size_bytes"`
		SHA256    string `json:"sha256"`
	} `json:"entries"`
	Snapshot *struct {
		Supported     bool `json:"supported"`
		TableCount    int  `json:"table_count"`
		SchemaHistory []struct {
			Version     string `json:"version"`
			Description string `json:"description"`
		} `json:"schema_history"`
	} `json:"snapshot"`
	SnapshotWarning string `json:"snapshot_warning"`
}

// cliTablesResult 是 tables --json 的测试解析结构。
type cliTablesResult struct {
	Tables []struct {
		Table struct {
			Name     string `json:"name"`
			Category string `json:"category"`
		} `json:"table"`
		Available bool `json:"available"`
		Columns   []struct {
			Name      string `json:"name"`
			Sensitive bool   `json:"sensitive"`
		} `json:"columns"`
	} `json:"tables"`
}

// cliPreviewResult 是 preview --json 的测试解析结构。
type cliPreviewResult struct {
	Table     string   `json:"table"`
	Columns   []string `json:"columns"`
	Rows      [][]any  `json:"rows"`
	Excluded  []string `json:"excluded_sensitive_columns"`
	Limit     int      `json:"limit"`
	Truncated bool     `json:"truncated"`
	Sensitive bool     `json:"sensitive_included"`
}

// createBackupForViewer 用 CLI 创建一份包含头像与配置的真实备份。
func createBackupForViewer(t *testing.T, env *cliEnvironment) string {
	t.Helper()
	code, _, stderr := runCLI(t, "create",
		"--database", env.database, "--key-file", env.keyFile,
		"--output", env.outputDir, "--operator", "local-admin-test",
		"--config", env.configFile, "--avatars", env.avatarDir)
	if code != ExitOK {
		t.Fatalf("创建测试备份失败（退出码 %d）：%s", code, stderr)
	}
	return findBackupFile(t, env.outputDir)
}

// cliFileSHA256 计算文件摘要（用于证明源备份字节不变）。
func cliFileSHA256(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取文件失败：%v", err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// TestCLIViewerListTablesPreview 端到端验证离线 list/tables/preview：认证状态、
// 数据库版本与 schema_history、受限查询目录、受限预览与源文件不变。
func TestCLIViewerListTablesPreview(t *testing.T) {
	env := setupCLIEnvironment(t)
	backupFile := createBackupForViewer(t, env)
	sourceBefore := cliFileSHA256(t, backupFile)

	code, stdout, stderr := runCLI(t, "list", "--file", backupFile,
		"--key-file", env.keyFile)
	if code != ExitOK {
		t.Fatalf("list 退出码 = %d；stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "认证解密成功") ||
		!strings.Contains(stdout, "schema_history") ||
		!strings.Contains(stdout, "清单条目：3") {
		t.Fatalf("list 文本输出缺少关键信息：%s", stdout)
	}
	code, stdout, stderr = runCLI(t, "list", "--file", backupFile,
		"--key-file", env.keyFile, "--json")
	if code != ExitOK {
		t.Fatalf("list --json 退出码 = %d；stderr=%s", code, stderr)
	}
	var list cliListResult
	if err := json.Unmarshal([]byte(stdout), &list); err != nil {
		t.Fatalf("list --json 不是合法 JSON：%v", err)
	}
	if !list.Authenticated || !list.IntegrityOK || list.FormatVersion != 1 {
		t.Fatalf("list JSON 认证/格式状态异常：%+v", list)
	}
	if list.Database.Engine != "sqlite" || list.Database.SchemaVersion == "" {
		t.Fatalf("list JSON 数据库版本异常：%+v", list.Database)
	}
	if len(list.Entries) != 3 {
		t.Fatalf("list JSON 条目数 = %d，期望 3", len(list.Entries))
	}
	if list.Snapshot == nil || !list.Snapshot.Supported ||
		len(list.Snapshot.SchemaHistory) != 47 || list.Snapshot.TableCount < 50 {
		t.Fatalf("list JSON schema_history 异常：%+v warning=%s",
			list.Snapshot, list.SnapshotWarning)
	}
	if strings.Contains(stdout, env.keyFile) {
		t.Fatal("list JSON 泄露了主密钥路径")
	}

	code, stdout, stderr = runCLI(t, "tables", "--file", backupFile,
		"--key-file", env.keyFile, "--json")
	if code != ExitOK {
		t.Fatalf("tables 退出码 = %d；stderr=%s", code, stderr)
	}
	var tables cliTablesResult
	if err := json.Unmarshal([]byte(stdout), &tables); err != nil {
		t.Fatalf("tables --json 不是合法 JSON：%v", err)
	}
	if len(tables.Tables) < 20 {
		t.Fatalf("受控目录表数量异常：%d", len(tables.Tables))
	}
	var usersFound, sessionsSensitive bool
	for _, table := range tables.Tables {
		if table.Table.Name == "users" && table.Available {
			usersFound = true
		}
		if table.Table.Name == "sessions" {
			for _, column := range table.Columns {
				if column.Name == "secret_digest" && column.Sensitive {
					sessionsSensitive = true
				}
			}
		}
	}
	if !usersFound || !sessionsSensitive {
		t.Fatalf("tables 输出缺少 users/敏感标记：%+v", tables.Tables)
	}

	code, stdout, stderr = runCLI(t, "preview", "--file", backupFile,
		"--key-file", env.keyFile, "--table", "users", "--json")
	if code != ExitOK {
		t.Fatalf("preview 退出码 = %d；stderr=%s", code, stderr)
	}
	var preview cliPreviewResult
	if err := json.Unmarshal([]byte(stdout), &preview); err != nil {
		t.Fatalf("preview --json 不是合法 JSON：%v", err)
	}
	if preview.Table != "users" || len(preview.Rows) != 1 || len(preview.Columns) == 0 {
		t.Fatalf("preview JSON 结果异常：%+v", preview)
	}
	if preview.Sensitive {
		t.Fatal("默认预览不应包含高敏字段")
	}
	code, stdout, stderr = runCLI(t, "preview", "--file", backupFile,
		"--key-file", env.keyFile, "--table", "users",
		"--where", "username=cli-user", "--order-by", "created_at_ms:desc",
		"--limit", "5")
	if code != ExitOK {
		t.Fatalf("preview 过滤退出码 = %d；stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "cli-user") {
		t.Fatalf("preview 文本缺少期望数据：%s", stdout)
	}
	code, _, stderr = runCLI(t, "preview", "--file", backupFile,
		"--key-file", env.keyFile, "--table", "unknown_table")
	if code != ExitQueryInvalid {
		t.Fatalf("未知表退出码 = %d，期望 %d；stderr=%s", code,
			ExitQueryInvalid, stderr)
	}
	code, _, stderr = runCLI(t, "preview", "--file", backupFile,
		"--key-file", env.keyFile, "--table", "sessions", "--columns",
		"id,secret_digest")
	if code != ExitQueryInvalid || !strings.Contains(stderr, "include-sensitive") {
		t.Fatalf("未确认敏感字段退出码 = %d，期望 %d；stderr=%s", code,
			ExitQueryInvalid, stderr)
	}
	code, stdout, stderr = runCLI(t, "preview", "--file", backupFile,
		"--key-file", env.keyFile, "--table", "sessions", "--json")
	if code != ExitOK {
		t.Fatalf("会话默认预览退出码 = %d；stderr=%s", code, stderr)
	}
	preview = cliPreviewResult{}
	if err := json.Unmarshal([]byte(stdout), &preview); err != nil {
		t.Fatalf("会话预览 JSON 非法：%v", err)
	}
	excluded := strings.Join(preview.Excluded, ",")
	if !strings.Contains(excluded, "secret_digest") ||
		!strings.Contains(excluded, "csrf_digest") {
		t.Fatalf("会话预览未排除敏感字段：%v", preview.Excluded)
	}
	if after := cliFileSHA256(t, backupFile); after != sourceBefore {
		t.Fatalf("源备份字节被修改：%s -> %s", sourceBefore, after)
	}
}

// TestCLIViewerExportAndExtract 端到端验证 export/extract：CSV/JSON 导出、默认不
// 覆盖、高敏确认、逐项提取与源文件不变。
func TestCLIViewerExportAndExtract(t *testing.T) {
	env := setupCLIEnvironment(t)
	backupFile := createBackupForViewer(t, env)
	sourceBefore := cliFileSHA256(t, backupFile)
	exportDir := filepath.Join(env.dir, "viewer-out")
	if err := os.MkdirAll(exportDir, 0o700); err != nil {
		t.Fatalf("创建受控输出目录失败：%v", err)
	}
	code, stdout, stderr := runCLI(t, "list", "--file", backupFile,
		"--key-file", env.keyFile, "--json")
	if code != ExitOK {
		t.Fatalf("list --json 失败：%s", stderr)
	}
	var list cliListResult
	if err := json.Unmarshal([]byte(stdout), &list); err != nil {
		t.Fatalf("解析清单失败：%v", err)
	}
	var attachmentEntry, databaseEntry, configEntry struct {
		Name      string
		Kind      string
		SizeBytes int64
		SHA256    string
	}
	for index := range list.Entries {
		entry := list.Entries[index]
		switch entry.Kind {
		case "attachment":
			attachmentEntry.Name, attachmentEntry.Kind = entry.Name, entry.Kind
			attachmentEntry.SizeBytes, attachmentEntry.SHA256 = entry.SizeBytes, entry.SHA256
		case "database":
			databaseEntry.Name, databaseEntry.Kind = entry.Name, entry.Kind
			databaseEntry.SizeBytes, databaseEntry.SHA256 = entry.SizeBytes, entry.SHA256
		case "config":
			configEntry.Name, configEntry.Kind = entry.Name, entry.Kind
			configEntry.SizeBytes, configEntry.SHA256 = entry.SizeBytes, entry.SHA256
		}
	}
	if attachmentEntry.Name == "" || databaseEntry.Name == "" || configEntry.Name == "" {
		t.Fatalf("清单缺少附件/数据库/配置条目：%+v", list.Entries)
	}

	csvPath := filepath.Join(exportDir, "users.csv")
	code, stdout, stderr = runCLI(t, "export", "--file", backupFile,
		"--key-file", env.keyFile, "--table", "users", "--format", "csv",
		"--output", csvPath, "--where", "username=cli-user", "--operator",
		"viewer-cli-test")
	if code != ExitOK {
		t.Fatalf("CSV 导出退出码 = %d；stderr=%s", code, stderr)
	}
	csvData, err := os.ReadFile(csvPath)
	if err != nil {
		t.Fatalf("读取 CSV 失败：%v", err)
	}
	records, err := csv.NewReader(bytes.NewReader(csvData)).ReadAll()
	if err != nil || len(records) != 2 || records[1][0] == "" {
		t.Fatalf("CSV 内容异常：records=%v err=%v", records, err)
	}
	if !strings.Contains(stdout, "导出完成") {
		t.Fatalf("export 文本输出异常：%s", stdout)
	}
	oplogPath := filepath.Join(exportDir, ".login-backup-viewer-oplog.jsonl")
	if _, err := os.Stat(oplogPath); err != nil {
		t.Fatalf("本地操作记录缺失：%v", err)
	}
	code, _, stderr = runCLI(t, "export", "--file", backupFile,
		"--key-file", env.keyFile, "--table", "users", "--format", "csv",
		"--output", csvPath)
	if code != ExitOutputConflict {
		t.Fatalf("重复导出退出码 = %d，期望 %d；stderr=%s", code,
			ExitOutputConflict, stderr)
	}
	jsonPath := filepath.Join(exportDir, "users.json")
	code, _, stderr = runCLI(t, "export", "--file", backupFile,
		"--key-file", env.keyFile, "--table", "users", "--format", "json",
		"--output", jsonPath)
	if code != ExitOK {
		t.Fatalf("JSON 导出退出码 = %d；stderr=%s", code, stderr)
	}
	var exported struct {
		Table    string           `json:"table"`
		Rows     []map[string]any `json:"rows"`
		RowCount int              `json:"row_count"`
	}
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil || json.Unmarshal(jsonData, &exported) != nil ||
		exported.Table != "users" || exported.RowCount != 1 {
		t.Fatalf("JSON 导出内容异常：%s err=%v", jsonData, err)
	}
	code, _, stderr = runCLI(t, "export", "--file", backupFile,
		"--key-file", env.keyFile, "--table", "unknown_table", "--format", "csv",
		"--output", filepath.Join(exportDir, "bad.csv"))
	if code != ExitQueryInvalid {
		t.Fatalf("未知表导出退出码 = %d；stderr=%s", code, stderr)
	}
	code, _, _ = runCLI(t, "export", "--file", backupFile,
		"--key-file", env.keyFile, "--table", "users", "--format", "xml",
		"--output", filepath.Join(exportDir, "bad.xml"))
	if code != ExitUsage {
		t.Fatalf("非法格式退出码 = %d，期望 2", code)
	}

	// 附件逐项提取：内容摘要与清单一致。
	attachmentPath := filepath.Join(exportDir, "avatar.png")
	code, _, stderr = runCLI(t, "extract", "--file", backupFile,
		"--key-file", env.keyFile, "--entry", attachmentEntry.Name,
		"--output", attachmentPath)
	if code != ExitOK {
		t.Fatalf("附件提取退出码 = %d；stderr=%s", code, stderr)
	}
	if got := cliFileSHA256(t, attachmentPath); got != attachmentEntry.SHA256 {
		t.Fatalf("附件摘要不一致：%s vs %s", got, attachmentEntry.SHA256)
	}
	// 原始数据库条目默认拒绝；显式确认后允许。
	databasePath := filepath.Join(exportDir, "raw.sqlite")
	code, _, stderr = runCLI(t, "extract", "--file", backupFile,
		"--key-file", env.keyFile, "--entry", databaseEntry.Name,
		"--output", databasePath)
	if code != ExitQueryInvalid || !strings.Contains(stderr, "include-sensitive") {
		t.Fatalf("原始数据库条目未确认退出码 = %d；stderr=%s", code, stderr)
	}
	if _, err := os.Stat(databasePath); !os.IsNotExist(err) {
		t.Fatal("被拒绝的高敏提取不应创建输出文件")
	}
	code, _, stderr = runCLI(t, "extract", "--file", backupFile,
		"--key-file", env.keyFile, "--entry", databaseEntry.Name,
		"--output", databasePath, "--include-sensitive")
	if code != ExitOK {
		t.Fatalf("显式确认后数据库提取退出码 = %d；stderr=%s", code, stderr)
	}
	if got := cliFileSHA256(t, databasePath); got != databaseEntry.SHA256 {
		t.Fatalf("数据库摘要不一致：%s vs %s", got, databaseEntry.SHA256)
	}
	// 配置快照按高敏条目处理：默认拒绝，显式确认后成功且落地权限收紧。
	configPath := filepath.Join(exportDir, "login.yaml")
	code, _, stderr = runCLI(t, "extract", "--file", backupFile,
		"--key-file", env.keyFile, "--entry", configEntry.Name,
		"--output", configPath)
	if code != ExitQueryInvalid || !strings.Contains(stderr, "include-sensitive") {
		t.Fatalf("配置条目未确认退出码 = %d；stderr=%s", code, stderr)
	}
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Fatal("被拒绝的高敏配置提取不应创建输出文件")
	}
	code, _, stderr = runCLI(t, "extract", "--file", backupFile,
		"--key-file", env.keyFile, "--entry", configEntry.Name,
		"--output", configPath, "--include-sensitive")
	if code != ExitOK {
		t.Fatalf("显式确认后配置提取退出码 = %d；stderr=%s", code, stderr)
	}
	if err := secrets.CheckProtectedFile(configPath); err != nil {
		t.Fatalf("高敏配置提取落地权限未收紧：%v", err)
	}
	if got := cliFileSHA256(t, configPath); got != configEntry.SHA256 {
		t.Fatalf("配置摘要不一致：%s vs %s", got, configEntry.SHA256)
	}

	// 越权/路径穿越式条目名不会创建任何文件。
	escapePath := filepath.Join(exportDir, "escape.bin")
	code, _, _ = runCLI(t, "extract", "--file", backupFile,
		"--key-file", env.keyFile, "--entry", "../../etc/passwd",
		"--output", escapePath)
	if code != ExitQueryInvalid {
		t.Fatalf("路径穿越式条目名退出码 = %d，期望 %d", code, ExitQueryInvalid)
	}
	if _, err := os.Stat(escapePath); !os.IsNotExist(err) {
		t.Fatal("不存在的条目不应创建输出文件")
	}
	if after := cliFileSHA256(t, backupFile); after != sourceBefore {
		t.Fatalf("源备份字节被修改：%s -> %s", sourceBefore, after)
	}
}

// TestCLIViewerErrorCodes 验证错误密钥/篡改/截断/缺参数/取消语义的稳定退出码。
func TestCLIViewerErrorCodes(t *testing.T) {
	env := setupCLIEnvironment(t)
	backupFile := createBackupForViewer(t, env)
	// 缺参数属于用法错误。
	if code, _, _ := runCLI(t, "list", "--file", backupFile); code != ExitUsage {
		t.Fatalf("缺少 --key-file 退出码 = %d，期望 2", code)
	}
	// 错误密钥：解密失败（4），不输出秘密。
	otherRing, err := secrets.GenerateKeyring("k2", time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("生成另一密钥环失败：%v", err)
	}
	otherDocument, err := otherRing.Document()
	if err != nil {
		t.Fatalf("序列化另一密钥环失败：%v", err)
	}
	otherKey := filepath.Join(env.dir, "other-key.json")
	if err := secrets.WriteProtectedFile(otherKey, otherDocument); err != nil {
		t.Fatalf("写入另一密钥文件失败：%v", err)
	}
	code, _, stderr := runCLI(t, "list", "--file", backupFile, "--key-file", otherKey)
	if code != ExitDecryptFailed {
		t.Fatalf("错误密钥退出码 = %d，期望 %d；stderr=%s", code,
			ExitDecryptFailed, stderr)
	}
	if !strings.Contains(stderr, "BACKUP_DECRYPT_FAILED") {
		t.Fatalf("错误密钥未映射稳定错误码：%s", stderr)
	}
	// --json 失败路径输出可解析 error 对象（ok=false + 稳定错误码）。
	code, stdout, _ := runCLI(t, "list", "--file", backupFile,
		"--key-file", otherKey, "--json")
	if code != ExitDecryptFailed {
		t.Fatalf("--json 错误密钥退出码 = %d，期望 %d", code, ExitDecryptFailed)
	}
	var failure struct {
		OK    bool `json:"ok"`
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(stdout), &failure); err != nil {
		t.Fatalf("--json 失败路径不是合法 JSON：%v stdout=%s", err, stdout)
	}
	if failure.OK || failure.Error.Code != "BACKUP_DECRYPT_FAILED" ||
		failure.Error.Message == "" {
		t.Fatalf("--json 失败对象语义异常：%+v", failure)
	}
	// Windows 保留设备名/尾随点的条目名在打开备份前被拒绝，不创建输出。
	for _, entryName := range []string{"CON", "prn.txt", "NUL.png", "COM1.dat",
		"attachments/avatars/x.png.", "attachments/avatars/CON"} {
		target := filepath.Join(testutil.TempDir(t), "blocked.bin")
		code, _, _ := runCLI(t, "extract", "--file", backupFile,
			"--key-file", env.keyFile, "--entry", entryName, "--output", target)
		if code != ExitQueryInvalid {
			t.Fatalf("保留名/尾随点条目 %q 退出码 = %d，期望 %d", entryName, code,
				ExitQueryInvalid)
		}
		if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
			t.Fatalf("保留名条目 %q 不应创建输出文件", entryName)
		}
	}

	// 篡改/截断：校验失败或解密失败（3/4）。
	data, err := os.ReadFile(backupFile)
	if err != nil {
		t.Fatalf("读取备份失败：%v", err)
	}
	tamperedPath := filepath.Join(env.dir, "viewer-tampered.elnbak")
	tampered := append([]byte(nil), data...)
	tampered[len(tampered)-19] ^= 0xff
	if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
		t.Fatalf("写入篡改文件失败：%v", err)
	}
	code, _, _ = runCLI(t, "list", "--file", tamperedPath, "--key-file", env.keyFile)
	if code != ExitVerifyFailed && code != ExitDecryptFailed {
		t.Fatalf("篡改文件退出码 = %d，期望 3 或 4", code)
	}
	truncatedPath := filepath.Join(env.dir, "viewer-truncated.elnbak")
	if err := os.WriteFile(truncatedPath, data[:len(data)-32], 0o600); err != nil {
		t.Fatalf("写入截断文件失败：%v", err)
	}
	code, _, _ = runCLI(t, "list", "--file", truncatedPath, "--key-file", env.keyFile)
	if code != ExitVerifyFailed && code != ExitDecryptFailed {
		t.Fatalf("截断文件退出码 = %d，期望 3 或 4", code)
	}
}

// TestCLIViewerSensitiveExportProtection 验证高敏导出必须显式确认且输出文件在
// 落地后被收紧权限（Windows ACL / Unix 0600）。
func TestCLIViewerSensitiveExportProtection(t *testing.T) {
	env := setupCLIEnvironment(t)
	backupFile := createBackupForViewer(t, env)
	exportDir := filepath.Join(env.dir, "sensitive-out")
	if err := os.MkdirAll(exportDir, 0o700); err != nil {
		t.Fatalf("创建受控输出目录失败：%v", err)
	}
	outputPath := filepath.Join(exportDir, "sessions.csv")
	code, _, stderr := runCLI(t, "export", "--file", backupFile,
		"--key-file", env.keyFile, "--table", "sessions", "--format", "csv",
		"--columns", "id,secret_digest", "--output", outputPath)
	if code != ExitQueryInvalid {
		t.Fatalf("未确认高敏导出退出码 = %d，期望 %d；stderr=%s", code,
			ExitQueryInvalid, stderr)
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatal("被拒绝的高敏导出不应创建输出文件")
	}
	code, _, stderr = runCLI(t, "export", "--file", backupFile,
		"--key-file", env.keyFile, "--table", "sessions", "--format", "csv",
		"--columns", "id,secret_digest", "--output", outputPath,
		"--include-sensitive")
	if code != ExitOK {
		// 无会话数据时导出 0 行也是成功；仅当权限受限时失败。
		t.Fatalf("显式确认高敏导出退出码 = %d；stderr=%s", code, stderr)
	}
	if err := secrets.CheckProtectedFile(outputPath); err != nil {
		t.Fatalf("高敏导出文件权限未收紧：%v", err)
	}
}

// TestCLIViewerExportCancelledContext 验证导出前的取消不会创建输出文件。
func TestCLIViewerExportCancelledContext(t *testing.T) {
	env := setupCLIEnvironment(t)
	backupFile := createBackupForViewer(t, env)
	outputPath := filepath.Join(testutil.TempDir(t), "cancelled.csv")
	provider, err := secrets.NewFileProvider(env.keyFile)
	if err != nil {
		t.Fatalf("构造密钥提供者失败：%v", err)
	}
	ring, err := secrets.LoadKeyring(context.Background(), provider)
	if err != nil {
		t.Fatalf("加载密钥环失败：%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = backup.ExportTable(ctx, backup.ExportOptions{Path: backupFile,
		Keyring: ring, Query: backup.QueryOptions{Table: "users", Limit: 10},
		Format: backup.ExportFormatCSV, OutputPath: outputPath})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("取消导出未返回 context.Canceled：%v", err)
	}
	if _, statErr := os.Stat(outputPath); !os.IsNotExist(statErr) {
		t.Fatal("取消导出不应留下输出文件")
	}
}
