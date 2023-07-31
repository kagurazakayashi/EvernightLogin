package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
)

// viewerSourceSHA256 计算文件摘要，用于证明查看/导出全程只读源备份。
func viewerSourceSHA256(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取文件失败：%v", err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// viewerTestUserID 返回测试用户的稳定 ID（形如 usr_<两位十六进制重复>）。
func viewerTestUserID(repeat string) string {
	return "usr_" + strings.Repeat(repeat, 16)
}

// newViewerTestEnv 构造带附件与配置的测试环境，并创建一份真实备份。insertBefore
// 可在创建备份前插入额外测试数据（备份只包含创建时刻的数据）。
func newViewerTestEnv(t *testing.T, insertBefore func(*testEnv)) (*testEnv, string, []byte) {
	t.Helper()
	env := newTestEnv(t)
	config := env.writeConfig(t)
	env.service = env.newService(t, func(options *Options) {
		options.Config = config
		options.Attachments = mustAvatarSource(t, env.avatars)
	})
	avatarContent := []byte("viewer-avatar-content")
	env.insertUser(t, viewerTestUserID("11"))
	env.insertAvatar(t, viewerTestUserID("11"), avatarContent)
	env.insertUser(t, viewerTestUserID("22"))
	if insertBefore != nil {
		insertBefore(env)
	}
	result, err := env.service.Create(context.Background(),
		CreateRequest{Caller: testCaller(t)})
	if err != nil {
		t.Fatalf("创建测试备份失败：%v", err)
	}
	return env, result.Path, avatarContent
}

// TestViewerListSnapshotAndPreview 覆盖离线查看主路径：认证解密、schema_history
// 版本读取、受限预览（过滤/排序/IN/上限）与临时目录清理，且源备份字节不变。
func TestViewerListSnapshotAndPreview(t *testing.T) {
	env, backupPath, _ := newViewerTestEnv(t, nil)
	sourceBefore := viewerSourceSHA256(t, backupPath)
	tempRoot := testutil.TempDir(t)
	ctx := context.Background()
	viewer, err := OpenViewer(ctx, ViewOptions{Path: backupPath, Keyring: env.ring,
		TempRoot: tempRoot})
	if err != nil {
		t.Fatalf("打开离线查看器失败：%v", err)
	}
	tempDir := viewer.tempDirectoryPath()
	if tempDir == "" {
		t.Fatal("查看器未创建受控临时目录")
	}
	defer viewer.Close()
	report := viewer.Report()
	if !report.Authenticated {
		t.Fatal("查看器未完成认证解密")
	}
	if len(report.Entries) != 3 {
		t.Fatalf("清单条目 = %d，期望 3（数据库/附件/配置）", len(report.Entries))
	}
	snapshot, err := viewer.Snapshot(ctx)
	if err != nil {
		t.Fatalf("读取快照版本失败：%v", err)
	}
	if !snapshot.Supported || snapshot.Engine != "sqlite" {
		t.Fatalf("快照能力声明异常：%+v", snapshot)
	}
	if len(snapshot.SchemaHistory) != snapshot.SchemaVersionNumber {
		t.Fatalf("schema_history 条数 = %d，与快照最高迁移版本 %d 不一致",
			len(snapshot.SchemaHistory), snapshot.SchemaVersionNumber)
	}
	if snapshot.SchemaVersion != report.Database.SchemaVersion {
		t.Fatalf("schema 版本不一致：%s vs %s", snapshot.SchemaVersion,
			report.Database.SchemaVersion)
	}
	if snapshot.TableCount < 50 {
		t.Fatalf("表数量异常：%d", snapshot.TableCount)
	}
	// 预览：默认全部非敏感字段 + 条件 + 排序 + 上限。
	firstUser := viewerTestUserID("22")
	plan, err := viewer.BuildQueryPlan(ctx, QueryOptions{Table: "users",
		Columns: []string{"id", "username"}, Limit: 5,
		Filters: []ColumnFilter{{Column: "id", Operator: "IN",
			Values: []string{firstUser, viewerTestUserID("11")}}},
		OrderBy: []OrderSpec{{Column: "id"}}})
	if err != nil {
		t.Fatalf("构造受限查询失败：%v", err)
	}
	result, err := viewer.PreviewQuery(ctx, plan)
	if err != nil {
		t.Fatalf("受限预览失败：%v", err)
	}
	if len(result.Rows) != 2 || len(result.Columns) != 2 {
		t.Fatalf("预览结果异常：columns=%v rows=%d", result.Columns, len(result.Rows))
	}
	if result.Rows[0][0] != viewerTestUserID("11") ||
		result.Rows[1][0] != firstUser {
		t.Fatalf("排序结果异常：%v", result.Rows)
	}
	// LIKE 过滤与截断标记。
	likePlan, err := viewer.BuildQueryPlan(ctx, QueryOptions{Table: "users",
		Limit: 1, Filters: []ColumnFilter{{Column: "username", Operator: "LIKE",
			Values: []string{"user-%"}}}})
	if err != nil {
		t.Fatalf("构造 LIKE 查询失败：%v", err)
	}
	likeResult, err := viewer.PreviewQuery(ctx, likePlan)
	if err != nil {
		t.Fatalf("LIKE 预览失败：%v", err)
	}
	if len(likeResult.Rows) != 1 || !likeResult.Truncated {
		t.Fatalf("行数上限截断语义异常：rows=%d truncated=%v",
			len(likeResult.Rows), likeResult.Truncated)
	}
	if err := viewer.Close(); err != nil {
		t.Fatalf("关闭查看器失败：%v", err)
	}
	if _, statErr := os.Stat(tempDir); !os.IsNotExist(statErr) {
		t.Fatalf("关闭后临时目录仍存在：%v", statErr)
	}
	if entries, readErr := os.ReadDir(tempRoot); readErr != nil || len(entries) != 0 {
		t.Fatalf("临时目录父目录有残留：%v %v", entries, readErr)
	}
	if after := viewerSourceSHA256(t, backupPath); after != sourceBefore {
		t.Fatalf("源备份字节被修改：%s -> %s", sourceBefore, after)
	}
}

// TestViewerReadOnlyConnectionAndSensitiveDefaults 验证只读连接拒绝写、敏感字段
// 默认排除、未确认时拒绝读取。
func TestViewerReadOnlyConnectionAndSensitiveDefaults(t *testing.T) {
	env, backupPath, _ := newViewerTestEnv(t, nil)
	ctx := context.Background()
	sourceBefore := viewerSourceSHA256(t, backupPath)
	viewer, err := OpenViewer(ctx, ViewOptions{Path: backupPath, Keyring: env.ring})
	if err != nil {
		t.Fatalf("打开查看器失败：%v", err)
	}
	defer viewer.Close()
	db, err := viewer.readOnlyDatabase(ctx)
	if err != nil {
		t.Fatalf("只读连接打开失败：%v", err)
	}
	var queryOnly int
	if err := db.QueryRowContext(ctx, "PRAGMA query_only").Scan(&queryOnly); err != nil ||
		queryOnly != 1 {
		t.Fatalf("只读连接 query_only = %d err=%v", queryOnly, err)
	}
	if _, writeErr := db.ExecContext(ctx,
		`CREATE TABLE viewer_write_probe(value TEXT)`); writeErr == nil {
		t.Fatal("只读连接竟然允许写操作")
	}
	// 默认字段集合排除会话秘密/CSRF 摘要；显式请求但未确认时拒绝。
	plan, err := viewer.BuildQueryPlan(ctx, QueryOptions{Table: "sessions", Limit: 10})
	if err != nil {
		t.Fatalf("构造会话预览计划失败：%v", err)
	}
	excluded := strings.Join(plan.Excluded, ",")
	if !strings.Contains(excluded, "secret_digest") ||
		!strings.Contains(excluded, "csrf_digest") {
		t.Fatalf("会话敏感字段未被默认排除：%v", plan.Excluded)
	}
	for _, column := range plan.Columns {
		if column == "secret_digest" || column == "csrf_digest" {
			t.Fatalf("敏感字段进入了默认列：%v", plan.Columns)
		}
	}
	if _, err := viewer.BuildQueryPlan(ctx, QueryOptions{Table: "sessions",
		Columns: []string{"id", "secret_digest"}, Limit: 10}); !errors.Is(err, ErrSensitiveRequired) {
		t.Fatalf("未确认的敏感字段未按 ErrSensitiveRequired 拒绝：%v", err)
	}
	sensitivePlan, err := viewer.BuildQueryPlan(ctx, QueryOptions{Table: "sessions",
		Columns: []string{"id", "secret_digest"}, Limit: 10, IncludeSensitive: true})
	if err != nil {
		t.Fatalf("显式确认后仍无法读取敏感字段：%v", err)
	}
	if !sensitivePlan.Sensitive {
		t.Fatal("显式敏感查询未标记 Sensitive")
	}
	// 未知表/未知字段/未知操作符/越限行数全部拒绝（不执行任意 SQL）。
	if _, err := viewer.BuildQueryPlan(ctx, QueryOptions{Table: "sessions; DROP TABLE users",
		Limit: 10}); !errors.Is(err, ErrQueryInvalid) {
		t.Fatalf("未知表未拒绝：%v", err)
	}
	if _, err := viewer.BuildQueryPlan(ctx, QueryOptions{Table: "users",
		Columns: []string{"password_hash"}, Limit: 10}); !errors.Is(err, ErrQueryInvalid) {
		t.Fatalf("未知字段未拒绝：%v", err)
	}
	if _, err := viewer.BuildQueryPlan(ctx, QueryOptions{Table: "users",
		Filters: []ColumnFilter{{Column: "id", Operator: "OR 1=1 --",
			Values: []string{"x"}}}, Limit: 10}); !errors.Is(err, ErrQueryInvalid) {
		t.Fatalf("非法操作符未拒绝：%v", err)
	}
	if _, err := viewer.BuildQueryPlan(ctx, QueryOptions{Table: "users",
		Limit: MaxExportRows + 1}); !errors.Is(err, ErrQueryInvalid) {
		t.Fatalf("超限行数未拒绝：%v", err)
	}
	if _, err := ParseColumnFilter("id=1 OR 1=1"); err != nil {
		t.Fatalf("按值包含空格/操作符文本应作为参数值：%v", err)
	}
	if _, err := ParseColumnFilter("id IN (a,b,c"); !errors.Is(err, ErrQueryInvalid) {
		t.Fatalf("未闭合 IN 未拒绝：%v", err)
	}
	// IN 值单引号内逗号属于单个值。
	filter, err := ParseColumnFilter(`id IN ('a,b', c)`)
	if err != nil || len(filter.Values) != 2 || filter.Values[0] != "a,b" {
		t.Fatalf("IN 引号解析异常：%+v err=%v", filter, err)
	}
	if after := viewerSourceSHA256(t, backupPath); after != sourceBefore {
		t.Fatalf("源备份字节被修改：%s -> %s", sourceBefore, after)
	}
}

// TestViewerExportCSVJSONFormulaAndNoOverwrite 覆盖单项导出、CSV 公式注入防护、
// JSON 纯数据编码、默认不覆盖与本地操作记录。
func TestViewerExportCSVJSONFormulaAndNoOverwrite(t *testing.T) {
	formula := `=cmd|' /C calc'!A0,"quoted"`
	formulaID := viewerTestUserID("33")
	env, backupPath, _ := newViewerTestEnv(t, func(env *testEnv) {
		if _, err := env.store.ExecContext(context.Background(), `INSERT INTO users(
id, username, username_normalized, created_at_ms, updated_at_ms)
VALUES(?,?,?,?,?)`, formulaID, formula, "formula-normalized",
			backupTestTime.UnixMilli(), backupTestTime.UnixMilli()); err != nil {
			t.Fatalf("插入公式载荷用户失败：%v", err)
		}
	})
	sourceBefore := viewerSourceSHA256(t, backupPath)
	outputDir := testutil.TempDir(t)
	csvPath := filepath.Join(outputDir, "users.csv")
	query := QueryOptions{Table: "users", Columns: []string{"id", "username", "status"},
		Filters: []ColumnFilter{{Column: "id", Operator: "=", Values: []string{formulaID}}},
		Limit:   10}
	result, err := ExportTable(context.Background(), ExportOptions{Path: backupPath,
		Keyring: env.ring, Query: query, Format: ExportFormatCSV, OutputPath: csvPath,
		Operator: "viewer-test"})
	if err != nil {
		t.Fatalf("CSV 导出失败：%v", err)
	}
	if result.RowCount != 1 {
		t.Fatalf("CSV 导出行数 = %d，期望 1", result.RowCount)
	}
	csvData, err := os.ReadFile(csvPath)
	if err != nil {
		t.Fatalf("读取 CSV 失败：%v", err)
	}
	records, err := csv.NewReader(bytes.NewReader(csvData)).ReadAll()
	if err != nil {
		t.Fatalf("解析 CSV 失败：%v", err)
	}
	if len(records) != 2 {
		t.Fatalf("CSV 记录数 = %d，期望 2", len(records))
	}
	if records[1][1] != "'"+formula {
		t.Fatalf("CSV 公式载荷未被前置单引号转义：%q", records[1][1])
	}
	// 本地操作记录存在且不包含过滤值/数据内容。
	oplogPath := filepath.Join(outputDir, defaultOperationLogName)
	oplogData, err := os.ReadFile(oplogPath)
	if err != nil {
		t.Fatalf("本地操作记录缺失：%v", err)
	}
	if bytes.Contains(oplogData, []byte("calc")) {
		t.Fatal("本地操作记录泄露了过滤值/数据内容")
	}
	var record viewerOperationRecord
	if err := json.Unmarshal(bytes.TrimSpace(bytes.Split(oplogData, []byte("\n"))[0]),
		&record); err != nil {
		t.Fatalf("解析本地操作记录失败：%v", err)
	}
	if record.Outcome != "succeeded" || record.Command != "export" ||
		record.RowCount != 1 || record.Table != "users" {
		t.Fatalf("本地操作记录语义异常：%+v", record)
	}
	// 默认不覆盖已有文件。
	if _, err := ExportTable(context.Background(), ExportOptions{Path: backupPath,
		Keyring: env.ring, Query: query, Format: ExportFormatCSV,
		OutputPath: csvPath}); !errors.Is(err, ErrOutputExists) {
		t.Fatalf("重复导出未按 ErrOutputExists 拒绝：%v", err)
	}
	// JSON 导出：公式文本原样（JSON 不执行、不注入），结构可解析。
	jsonPath := filepath.Join(outputDir, "users.json")
	if _, err := ExportTable(context.Background(), ExportOptions{Path: backupPath,
		Keyring: env.ring, Query: query, Format: ExportFormatJSON,
		OutputPath: jsonPath}); err != nil {
		t.Fatalf("JSON 导出失败：%v", err)
	}
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("读取 JSON 失败：%v", err)
	}
	var parsed struct {
		FormatVersion int              `json:"format_version"`
		Table         string           `json:"table"`
		Columns       []string         `json:"columns"`
		Rows          []map[string]any `json:"rows"`
		RowCount      int              `json:"row_count"`
		Truncated     bool             `json:"truncated"`
	}
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("JSON 导出不是合法 JSON：%v", err)
	}
	if parsed.FormatVersion != 1 || parsed.Table != "users" || parsed.RowCount != 1 ||
		len(parsed.Rows) != 1 {
		t.Fatalf("JSON 导出结构异常：%+v", parsed)
	}
	if parsed.Rows[0]["username"] != formula {
		t.Fatalf("JSON 中的公式文本被改动：%v", parsed.Rows[0]["username"])
	}
	if after := viewerSourceSHA256(t, backupPath); after != sourceBefore {
		t.Fatalf("源备份字节被修改：%s -> %s", sourceBefore, after)
	}
}

// TestViewerExtractSingleEntry 覆盖附件/配置逐项提取、原数据库条目高敏确认与
// 不覆盖已有文件。
func TestViewerExtractSingleEntry(t *testing.T) {
	env, backupPath, avatarContent := newViewerTestEnv(t, nil)
	ctx := context.Background()
	tempRoot := testutil.TempDir(t)
	// 用只读查看器获取清单条目名（同时也验证了条目存在性）。
	viewer, err := OpenViewer(ctx, ViewOptions{Path: backupPath, Keyring: env.ring,
		TempRoot: tempRoot})
	if err != nil {
		t.Fatalf("打开查看器失败：%v", err)
	}
	report := viewer.Report()
	if err := viewer.Close(); err != nil {
		t.Fatalf("关闭查看器失败：%v", err)
	}
	var attachmentEntry, configEntry, databaseEntry *EntryReport
	for index := range report.Entries {
		entry := &report.Entries[index]
		switch entry.Kind {
		case EntryKindAttachment:
			attachmentEntry = entry
		case EntryKindConfig:
			configEntry = entry
		case EntryKindDatabase:
			databaseEntry = entry
		}
	}
	if attachmentEntry == nil || configEntry == nil || databaseEntry == nil {
		t.Fatalf("清单条目缺失：%+v", report.Entries)
	}
	outputDir := testutil.TempDir(t)
	attachmentPath := filepath.Join(outputDir, "avatar.bin")
	result, err := ExtractEntry(ctx, ExtractEntryOptions{Path: backupPath,
		Keyring: env.ring, EntryName: attachmentEntry.Name,
		OutputPath: attachmentPath, TempRoot: tempRoot})
	if err != nil {
		t.Fatalf("提取附件失败：%v", err)
	}
	if result.SHA256 != attachmentEntry.SHA256 {
		t.Fatalf("附件摘要不一致：%s vs %s", result.SHA256, attachmentEntry.SHA256)
	}
	extracted, err := os.ReadFile(attachmentPath)
	if err != nil {
		t.Fatalf("读取提取结果失败：%v", err)
	}
	if !bytes.Equal(extracted, avatarContent) {
		t.Fatalf("附件内容不一致：%q", extracted)
	}
	// 重复提取同一目标默认不覆盖。
	if _, err := ExtractEntry(ctx, ExtractEntryOptions{Path: backupPath,
		Keyring: env.ring, EntryName: attachmentEntry.Name,
		OutputPath: attachmentPath, TempRoot: tempRoot}); !errors.Is(err, ErrOutputExists) {
		t.Fatalf("重复提取未按 ErrOutputExists 拒绝：%v", err)
	}
	// 配置快照可能含宿主配置秘密：默认按高敏条目拒绝提取，显式确认后才允许且
	// 落地文件权限被收紧；内容与 YAML 原文一致。
	configPath := filepath.Join(outputDir, "login.yaml")
	if _, err := ExtractEntry(ctx, ExtractEntryOptions{Path: backupPath,
		Keyring: env.ring, EntryName: configEntry.Name,
		OutputPath: configPath, TempRoot: tempRoot}); !errors.Is(err, ErrSensitiveRequired) {
		t.Fatalf("配置条目未要求高敏确认：%v", err)
	}
	if _, statErr := os.Stat(configPath); !os.IsNotExist(statErr) {
		t.Fatal("被拒绝的高敏配置提取不应创建输出文件")
	}
	if _, err := ExtractEntry(ctx, ExtractEntryOptions{Path: backupPath,
		Keyring: env.ring, EntryName: configEntry.Name,
		OutputPath: configPath, IncludeSensitive: true,
		TempRoot: tempRoot}); err != nil {
		t.Fatalf("显式确认后提取配置失败：%v", err)
	}
	if err := secrets.CheckProtectedFile(configPath); err != nil {
		t.Fatalf("高敏配置提取落地权限未收紧：%v", err)
	}
	configData, err := os.ReadFile(configPath)
	if err != nil || !bytes.Contains(configData, []byte("listen_addr")) {
		t.Fatalf("配置内容异常：%q err=%v", configData, err)
	}
	// 原始数据库条目包含认证秘密：未确认时拒绝。
	databasePath := filepath.Join(outputDir, "raw.sqlite")
	if _, err := ExtractEntry(ctx, ExtractEntryOptions{Path: backupPath,
		Keyring: env.ring, EntryName: databaseEntry.Name,
		OutputPath: databasePath, TempRoot: tempRoot}); !errors.Is(err, ErrSensitiveRequired) {
		t.Fatalf("原始数据库条目未要求显式确认：%v", err)
	}
	if _, statErr := os.Stat(databasePath); !os.IsNotExist(statErr) {
		t.Fatal("被拒绝的高敏提取不应创建输出文件")
	}
	// 显式确认后允许，且内容摘要与清单一致（落地文件权限被收紧）。
	if _, err := ExtractEntry(ctx, ExtractEntryOptions{Path: backupPath,
		Keyring: env.ring, EntryName: databaseEntry.Name, OutputPath: databasePath,
		IncludeSensitive: true, TempRoot: tempRoot}); err != nil {
		t.Fatalf("显式确认后提取原始数据库失败：%v", err)
	}
	databaseSHA := viewerSourceSHA256(t, databasePath)
	if databaseSHA != databaseEntry.SHA256 {
		t.Fatalf("原始数据库摘要不一致：%s vs %s", databaseSHA, databaseEntry.SHA256)
	}
	if entries, readErr := os.ReadDir(tempRoot); readErr != nil || len(entries) != 0 {
		t.Fatalf("提取后临时目录有残留：%v %v", entries, readErr)
	}
}

// TestViewerWrongKeyTamperedTruncated 验证错误密钥、篡改、截断与缺失文件均明确
// 失败，且不留下临时明文。
func TestViewerWrongKeyTamperedTruncated(t *testing.T) {
	env, backupPath, _ := newViewerTestEnv(t, nil)
	ctx := context.Background()
	tempRoot := testutil.TempDir(t)
	otherRing, err := secrets.GenerateKeyring("k9", backupTestTime)
	if err != nil {
		t.Fatalf("生成另一密钥环失败：%v", err)
	}
	if _, err := OpenViewer(ctx, ViewOptions{Path: backupPath, Keyring: otherRing,
		TempRoot: tempRoot}); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("错误密钥未按 ErrDecryptFailed 拒绝：%v", err)
	}
	data, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("读取备份失败：%v", err)
	}
	tampered := append([]byte(nil), data...)
	tampered[len(tampered)-20] ^= 0x5a
	tamperedPath := filepath.Join(testutil.TempDir(t), "tampered.elnbak")
	if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
		t.Fatalf("写入篡改文件失败：%v", err)
	}
	if _, err := OpenViewer(ctx, ViewOptions{Path: tamperedPath, Keyring: env.ring,
		TempRoot: tempRoot}); err == nil {
		t.Fatal("篡改备份未被拒绝")
	}
	truncatedPath := filepath.Join(testutil.TempDir(t), "truncated.elnbak")
	if err := os.WriteFile(truncatedPath, data[:len(data)-64], 0o600); err != nil {
		t.Fatalf("写入截断文件失败：%v", err)
	}
	if _, err := OpenViewer(ctx, ViewOptions{Path: truncatedPath, Keyring: env.ring,
		TempRoot: tempRoot}); err == nil {
		t.Fatal("截断备份未被拒绝")
	}
	missingPath := filepath.Join(testutil.TempDir(t), "missing.elnbak")
	if _, err := OpenViewer(ctx, ViewOptions{Path: missingPath, Keyring: env.ring,
		TempRoot: tempRoot}); err == nil {
		t.Fatal("缺失备份文件未被拒绝")
	}
	// 已取消上下文：不创建残留临时目录。
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := OpenViewer(cancelled, ViewOptions{Path: backupPath,
		Keyring: env.ring, TempRoot: tempRoot}); !errors.Is(err, context.Canceled) {
		t.Fatalf("已取消上下文未返回 context.Canceled：%v", err)
	}
	if entries, readErr := os.ReadDir(tempRoot); readErr != nil || len(entries) != 0 {
		t.Fatalf("失败后临时目录有残留：%v %v", entries, readErr)
	}
}

// TestViewerMaliciousContainers 构造带恶意清单的合法容器（错误路径穿越、绝对
// 路径、重复条目、头部声明不一致），验证所有路径都在写盘前被拒绝。
func TestViewerMaliciousContainers(t *testing.T) {
	env, backupPath, _ := newViewerTestEnv(t, nil)
	ctx := context.Background()
	templateRing := env.ring
	_ = backupPath
	dbContent := []byte("sqlite-database-placeholder")
	cases := []struct {
		name    string
		entries []ManifestEntry
		content [][]byte
		headBad bool
	}{
		{name: "路径穿越", entries: []ManifestEntry{
			{Name: "../evil.bin", Kind: EntryKindAttachment, SizeBytes: 3},
		}, content: [][]byte{[]byte("bad")}},
		{name: "绝对路径", entries: []ManifestEntry{
			{Name: "/etc/passwd", Kind: EntryKindAttachment, SizeBytes: 3},
		}, content: [][]byte{[]byte("bad")}},
		{name: "反斜杠分隔", entries: []ManifestEntry{
			{Name: `attachments\..\evil.bin`, Kind: EntryKindAttachment, SizeBytes: 3},
		}, content: [][]byte{[]byte("bad")}},
		{name: "重复条目名", entries: []ManifestEntry{
			{Name: "attachments/avatars/dup.png", Kind: EntryKindAttachment,
				SizeBytes: 3},
			{Name: "attachments/avatars/dup.png", Kind: EntryKindAttachment,
				SizeBytes: 3},
		}, content: [][]byte{[]byte("aa"), []byte("bb")}},
		{name: "未定义条目类型", entries: []ManifestEntry{
			{Name: "attachments/avatars/x.png", Kind: "script", SizeBytes: 3},
		}, content: [][]byte{[]byte("bad")}},
		{name: "Windows保留设备名CON", entries: []ManifestEntry{
			{Name: "attachments/avatars/CON", Kind: EntryKindAttachment, SizeBytes: 3},
		}, content: [][]byte{[]byte("bad")}},
		{name: "Windows保留设备名prn.txt", entries: []ManifestEntry{
			{Name: "attachments/avatars/prn.txt", Kind: EntryKindAttachment,
				SizeBytes: 3},
		}, content: [][]byte{[]byte("bad")}},
		{name: "Windows保留设备名NUL.png", entries: []ManifestEntry{
			{Name: "attachments/avatars/NUL.png", Kind: EntryKindAttachment,
				SizeBytes: 3},
		}, content: [][]byte{[]byte("bad")}},
		{name: "Windows保留设备名COM1.dat", entries: []ManifestEntry{
			{Name: "attachments/avatars/COM1.dat", Kind: EntryKindAttachment,
				SizeBytes: 3},
		}, content: [][]byte{[]byte("bad")}},
		{name: "Windows保留设备名LPT9", entries: []ManifestEntry{
			{Name: "attachments/avatars/LPT9", Kind: EntryKindAttachment,
				SizeBytes: 3},
		}, content: [][]byte{[]byte("bad")}},
		{name: "尾随点", entries: []ManifestEntry{
			{Name: "attachments/avatars/x.png.", Kind: EntryKindAttachment,
				SizeBytes: 3},
		}, content: [][]byte{[]byte("bad")}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			tempRoot := testutil.TempDir(t)
			crafted := craftViewerTestBackup(t, templateRing, dbContent,
				testCase.entries, testCase.content, false)
			if _, err := OpenViewer(ctx, ViewOptions{Path: crafted,
				Keyring: env.ring, TempRoot: tempRoot}); err == nil {
				t.Fatal("恶意清单未被拒绝")
			}
			if entries, readErr := os.ReadDir(tempRoot); readErr != nil || len(entries) != 0 {
				t.Fatalf("恶意清单失败后临时目录有残留：%v %v", entries, readErr)
			}
		})
	}
	// 清单条目数与头部声明不一致（损坏清单）。
	decodeCases := []struct {
		name    string
		entries []ManifestEntry
		content [][]byte
		badHead bool
	}{
		{name: "条目数不一致", entries: []ManifestEntry{
			{Name: "attachments/avatars/a.png", Kind: EntryKindAttachment,
				SizeBytes: 3}}, content: [][]byte{[]byte("abc")}, badHead: true},
	}
	for _, testCase := range decodeCases {
		t.Run(testCase.name, func(t *testing.T) {
			crafted := craftViewerTestBackup(t, templateRing, dbContent,
				testCase.entries, testCase.content, testCase.badHead)
			if _, err := OpenViewer(ctx, ViewOptions{Path: crafted,
				Keyring: env.ring}); !errors.Is(err, ErrIntegrityFailed) {
				t.Fatalf("损坏清单未按完整性失败拒绝：%v", err)
			}
		})
	}
}

// craftViewerTestBackup 构造一个结构合法的加密容器，允许把恶意条目名/重复条目
// 放进认证清单（用于验证解包侧写盘前拒绝）。badHead 让头部声明条目数比清单多 1。
func craftViewerTestBackup(t *testing.T, ring *secrets.Keyring, databaseContent []byte,
	entries []ManifestEntry, contents [][]byte, badHead bool) string {
	t.Helper()
	backupID, err := newBackupID(nil)
	if err != nil {
		t.Fatalf("生成备份编号失败：%v", err)
	}
	dataKey, err := generateDataKey(nil)
	if err != nil {
		t.Fatalf("生成载荷密钥失败：%v", err)
	}
	keyID, envelope, err := wrapDataKey(ring, backupID, dataKey)
	if err != nil {
		t.Fatalf("封装备份密钥失败：%v", err)
	}
	dbSHA := sha256.Sum256(databaseContent)
	databaseEntry := ManifestEntry{Name: databaseEntryName,
		Kind: EntryKindDatabase, SizeBytes: int64(len(databaseContent)),
		SHA256: hex.EncodeToString(dbSHA[:])}
	allEntries := append([]ManifestEntry{databaseEntry}, entries...)
	allContents := append([][]byte{databaseContent}, contents...)
	var payload bytes.Buffer
	var length [4]byte
	manifest := Manifest{
		FormatVersion: FormatVersion,
		BackupID:      backupID,
		CreatedAt:     formatTime(backupTestTime),
		Host:          "test-host",
		AppVersion:    "test-version",
		Database: ManifestDatabase{Engine: "sqlite", SchemaVersion: "0044",
			SchemaVersionNumber: 44},
		Capture: CaptureInfo{
			DatabaseSnapshotStartedAt:  formatTime(backupTestTime),
			DatabaseSnapshotFinishedAt: formatTime(backupTestTime),
			AttachmentsCapturedAt:      formatTime(backupTestTime),
			ConfigCapturedAt:           formatTime(backupTestTime),
		},
		Content: ContentMeta{Database: true,
			Attachments: ContentStatus{Status: ContentIncluded, Count: len(entries)},
			Config:      ContentStatus{Status: ContentNotConfigured},
			Keyring:     ContentStatus{Status: ContentExcluded}},
		Entries: allEntries,
	}
	// 条目大小/摘要补全（恶意条目名保持不变）。
	for index := range manifest.Entries {
		if index == 0 {
			continue
		}
		content := allContents[index]
		manifest.Entries[index].SizeBytes = int64(len(content))
		digest := sha256.Sum256(content)
		manifest.Entries[index].SHA256 = hex.EncodeToString(digest[:])
	}
	manifestRaw, err := marshalManifest(manifest)
	if err != nil {
		t.Fatalf("序列化清单失败：%v", err)
	}
	binary.BigEndian.PutUint32(length[:], uint32(len(manifestRaw)))
	payload.Write(length[:])
	payload.Write(manifestRaw)
	for _, content := range allContents {
		payload.Write(content)
	}
	plainBytes := int64(payload.Len())
	chunkSize := DefaultChunkSize
	chunks := PayloadChunks(plainBytes, chunkSize)
	entriesCount := len(allEntries)
	if badHead {
		entriesCount++
	}
	header := Header{FormatVersion: FormatVersion, BackupID: backupID,
		CreatedAt: formatTime(backupTestTime), Host: "test-host",
		AppVersion: "test-version",
		Database: DatabaseMeta{Engine: "sqlite", SchemaVersion: "0044",
			SchemaVersionNumber: 44, SizeBytes: int64(len(databaseContent)),
			SHA256: databaseEntry.SHA256},
		Content:      manifest.Content,
		EntriesCount: entriesCount,
		ManifestSHA256: func() string {
			digest := sha256.Sum256(manifestRaw)
			return hex.EncodeToString(digest[:])
		}(),
		Encryption: EncryptionInfo{Algorithm: EncryptionAlgorithm,
			Format:             EncryptionFormat,
			ChunkSizeBytes:     chunkSize,
			NoncePrefix:        base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, NoncePrefixBytes)),
			KeyID:              keyID,
			WrappedDataKey:     base64.StdEncoding.EncodeToString(envelope),
			PayloadPlainBytes:  plainBytes,
			PayloadCipherBytes: plainBytes + int64(chunks)*int64(aeadTagBytes)},
	}
	headerRaw, err := marshalHeader(header)
	if err != nil {
		t.Fatalf("序列化头部失败：%v", err)
	}
	if _, err := decodeHeader(headerRaw); err != nil {
		t.Fatalf("测试容器头部自身不合法：%v", err)
	}
	var cipher bytes.Buffer
	_, cipherDigest, err := encryptPayload(&cipher, bytes.NewReader(payload.Bytes()),
		plainBytes, chunkSize, dataKey, bytes.Repeat([]byte{7}, NoncePrefixBytes),
		headerHash(headerRaw))
	if err != nil {
		t.Fatalf("加密测试载荷失败：%v", err)
	}
	var fileContent bytes.Buffer
	fileContent.Write(filePrefix(headerRaw))
	fileContent.Write(cipher.Bytes())
	fileContent.Write(cipherDigest[:])
	path := filepath.Join(testutil.TempDir(t), "crafted.elnbak")
	if err := os.WriteFile(path, fileContent.Bytes(), 0o600); err != nil {
		t.Fatalf("写入测试容器失败：%v", err)
	}
	return path
}

// TestViewerExtractLimitRejectsOversizeBackup 验证解包膨胀上限：解包字节上限不足
// 时明确失败且不留下临时明文。
func TestViewerExtractLimitRejectsOversizeBackup(t *testing.T) {
	env, backupPath, _ := newViewerTestEnv(t, nil)
	tempRoot := testutil.TempDir(t)
	_, err := OpenViewer(context.Background(), ViewOptions{Path: backupPath,
		Keyring: env.ring, TempRoot: tempRoot, MaxExtractedBytes: 1024})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("解包字节超限未按 ErrTooLarge 拒绝：%v", err)
	}
	if entries, readErr := os.ReadDir(tempRoot); readErr != nil || len(entries) != 0 {
		t.Fatalf("超限失败后临时目录有残留：%v %v", entries, readErr)
	}
}

// TestViewerCatalogTablesExist 验证受限查询目录与当前迁移 schema 不漂移。
func TestViewerCatalogTablesExist(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	for _, table := range PreviewTables() {
		var count int
		if err := env.store.DB().QueryRowContext(ctx,
			`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`,
			table.Name).Scan(&count); err != nil {
			t.Fatalf("查询表 %s 失败：%v", table.Name, err)
		}
		if count != 1 {
			t.Errorf("受控目录表 %s 在迁移 schema 中不存在（目录漂移）", table.Name)
		}
	}
	if len(PreviewTables()) != len(previewTableIndex) {
		t.Errorf("受控目录存在重复表名")
	}
	// 敏感规则不得把普通字段误判为敏感（抽样关键表）。
	for _, column := range []string{"id", "username", "created_at_ms", "status"} {
		if _, sensitive := sensitiveColumnReason("users", column); sensitive {
			t.Errorf("普通字段 %s 被误判为敏感", column)
		}
	}
	for _, column := range []string{"secret_digest", "csrf_digest"} {
		if _, sensitive := sensitiveColumnReason("sessions", column); !sensitive {
			t.Errorf("会话敏感字段 %s 未被识别", column)
		}
	}
}

// TestOperationLogRejectsSymlink 验证本地操作记录不会跟随预置符号链接写入。
func TestOperationLogRejectsSymlink(t *testing.T) {
	dir := testutil.TempDir(t)
	outside := filepath.Join(testutil.TempDir(t), "outside.jsonl")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatalf("写入外部文件失败：%v", err)
	}
	linkPath := filepath.Join(dir, "oplog.jsonl")
	if err := os.Symlink(outside, linkPath); err != nil {
		t.Skipf("当前环境不支持创建符号链接：%v", err)
	}
	if _, err := openOperationLog(linkPath); err == nil {
		t.Fatal("操作记录路径为符号链接时未被拒绝")
	}
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "keep" {
		t.Fatalf("外部文件被修改：%q err=%v", data, err)
	}
}

// TestViewerSnapshotUnsupportedEngine 验证非 SQLite 引擎明确声明能力边界，不伪称
// 能解析内部数据。
func TestViewerSnapshotUnsupportedEngine(t *testing.T) {
	viewer := &Viewer{report: VerifyReport{Database: DatabaseMeta{Engine: "postgresql"}}}
	if _, err := viewer.Snapshot(context.Background()); !errors.Is(err, ErrDatabaseUnsupported) {
		t.Fatalf("非 SQLite 引擎未按 ErrDatabaseUnsupported 声明能力边界：%v", err)
	}
	if _, err := viewer.readOnlyDatabase(context.Background()); !errors.Is(err, ErrDatabaseUnsupported) {
		t.Fatalf("非 SQLite 引擎只读连接未拒绝：%v", err)
	}
}

// TestExportOutputSafety 验证输出目标安全检查：父目录缺失、目标存在（含符号
// 链接）均默认拒绝。
func TestExportOutputSafety(t *testing.T) {
	dir := testutil.TempDir(t)
	if _, err := resolveOutputFile(filepath.Join(dir, "missing-dir", "out.csv")); !errors.Is(err, ErrOutputDirUnsafe) {
		t.Fatalf("缺失输出目录未按 ErrOutputDirUnsafe 拒绝：%v", err)
	}
	existing := filepath.Join(dir, "existing.csv")
	if err := os.WriteFile(existing, []byte("keep"), 0o600); err != nil {
		t.Fatalf("写入已有文件失败：%v", err)
	}
	if _, err := resolveOutputFile(existing); !errors.Is(err, ErrOutputExists) {
		t.Fatalf("已有输出文件未按 ErrOutputExists 拒绝：%v", err)
	}
	if data, err := os.ReadFile(existing); err != nil || string(data) != "keep" {
		t.Fatalf("已有文件被修改：%q err=%v", data, err)
	}
	link := filepath.Join(dir, "link.csv")
	target := filepath.Join(dir, "target.csv")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatalf("写入链接目标失败：%v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("当前环境不支持符号链接：%v", err)
	}
	if _, err := resolveOutputFile(link); !errors.Is(err, ErrOutputExists) {
		t.Fatalf("符号链接目标未按 ErrOutputExists 拒绝：%v", err)
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "target" {
		t.Fatalf("符号链接目标被修改：%q err=%v", data, err)
	}
}

// TestSafeCSVTextNormalizesLeadingWhitespaceAndBOM 验证公式注入防护在危险首字节
// 前存在前导空白/制表/回车/BOM 时仍生效；普通文本与数值类型不受影响。
func TestSafeCSVTextNormalizesLeadingWhitespaceAndBOM(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"=1+1", "'=1+1"},
		{" =1+1", "' =1+1"},
		{"\t=1+1", "'\t=1+1"},
		{"\r+1", "'\r+1"},
		{"\n@cmd", "'\n@cmd"},
		{"\uFEFF=1+1", "'\uFEFF=1+1"},
		{" \uFEFF@cmd", "' \uFEFF@cmd"},
		{"-2", "'-2"},
		{" normal", " normal"},
		{"hello =1+1", "hello =1+1"},
		{"", ""},
	}
	for _, testCase := range cases {
		if got := safeCSVText(testCase.input); got != testCase.want {
			t.Fatalf("safeCSVText(%q) = %q，期望 %q", testCase.input, got,
				testCase.want)
		}
	}
	// 数值类型保持数字文本，不因负号被当作公式前缀。
	if got := csvCell(int64(-5)); got != "-5" {
		t.Fatalf("负数单元格 = %q，期望 -5", got)
	}
	if got := csvCell(float64(1.5)); got != "1.5" {
		t.Fatalf("浮点单元格 = %q", got)
	}
}
