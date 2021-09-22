package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/backup"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

// 离线备份查看/预览/导出命令（步骤 83）。所有命令只读备份文件：认证解密后把
// 数据库条目解包到 0700 临时目录，以只读 SQLite 连接访问；退出时清理临时明文。

// repeatedFlag 是允许重复出现的字符串参数（--where/--order-by）。
type repeatedFlag []string

// String 实现 flag.Value。
func (r *repeatedFlag) String() string { return strings.Join(*r, ",") }

// Set 追加一个参数值。
func (r *repeatedFlag) Set(value string) error {
	*r = append(*r, value)
	return nil
}

// loadViewerKeyring 加载用户提供的主密钥环。密钥文件缺失/权限不安全/文档无效时
// 明确失败并返回解密失败退出码；不会生成新密钥或绕过加密。
func loadViewerKeyring(ctx context.Context, keyPath string, stderr io.Writer) (*secrets.Keyring, int) {
	trimmed := strings.TrimSpace(keyPath)
	if trimmed == "" {
		fmt.Fprintln(stderr, "错误：--key-file 必填")
		return nil, ExitUsage
	}
	keyAbs, err := filepath.Abs(trimmed)
	if err != nil {
		fmt.Fprintln(stderr, "错误：主密钥文件路径无效")
		return nil, ExitUsage
	}
	provider, err := secrets.NewFileProvider(keyAbs)
	if err != nil {
		fmt.Fprintln(stderr, "错误：主密钥文件路径无效")
		return nil, ExitUsage
	}
	ring, err := secrets.LoadKeyring(ctx, provider)
	if err != nil {
		fmt.Fprintf(stderr, "错误：无法加载主密钥环（%s）\n", backup.CodeOf(err))
		return nil, ExitDecryptFailed
	}
	return ring, ExitOK
}

// viewerJSONError 是 --json 失败路径的机器可读错误对象（不含秘密/明文数据）。
type viewerJSONError struct {
	OK    bool `json:"ok"`
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// mapViewerError 把离线查看/导出错误映射为稳定退出码并输出安全中文错误。
// jsonOutput 为 true 时额外向 stdout 输出单行可解析 JSON 错误对象（ok=false），
// 供机器调用方稳定读取；stderr 仍保留中文说明。
func mapViewerError(stdout, stderr io.Writer, err error, jsonOutput ...bool) int {
	code := backup.CodeOf(err)
	codeText := string(code)
	exitCode := ExitError
	switch {
	case errors.Is(err, context.Canceled):
		codeText = "TASK_CANCELLED"
		exitCode = ExitCancelled
	case errors.Is(err, backup.ErrDecryptFailed):
		exitCode = ExitDecryptFailed
	case errors.Is(err, backup.ErrOutputExists), errors.Is(err, backup.ErrOutputDirUnsafe):
		exitCode = ExitOutputConflict
	case errors.Is(err, backup.ErrQueryInvalid), errors.Is(err, backup.ErrSensitiveRequired):
		exitCode = ExitQueryInvalid
	case errors.Is(err, backup.ErrIntegrityFailed), errors.Is(err, backup.ErrFormatInvalid),
		errors.Is(err, backup.ErrVersionUnsupported),
		errors.Is(err, backup.ErrDatabaseUnsupported):
		exitCode = ExitVerifyFailed
	}
	fmt.Fprintf(stderr, "错误：%s（%s）\n", err, codeText)
	if errors.Is(err, context.Canceled) {
		fmt.Fprintln(stderr, "已取消：临时文件与不完整输出已清理。")
	}
	if len(jsonOutput) > 0 && jsonOutput[0] {
		payload := viewerJSONError{}
		payload.OK = false
		payload.Error.Code = codeText
		payload.Error.Message = err.Error()
		if encoded, encodeErr := json.Marshal(payload); encodeErr == nil {
			fmt.Fprintln(stdout, string(encoded))
		}
	}
	return exitCode
}

// writeJSONResult 把结果写为缩进 JSON；序列化失败不输出半截 JSON。
func writeJSONResult(stdout, stderr io.Writer, value any) int {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, "错误：结果序列化失败")
		return ExitError
	}
	fmt.Fprintln(stdout, string(encoded))
	return ExitOK
}

// absoluteFilePath 把用户提供的文件路径规范化为绝对路径。
func absoluteFilePath(path, label string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", fmt.Errorf("%s不能为空", label)
	}
	absolute, err := filepath.Abs(trimmed)
	if err != nil {
		return "", fmt.Errorf("%s路径无效", label)
	}
	return absolute, nil
}

// listOutput 是 list 命令的机器可读结果。
type listOutput struct {
	FileName        string                   `json:"file_name"`
	Authenticated   bool                     `json:"authenticated"`
	IntegrityOK     bool                     `json:"integrity_verified"`
	FormatVersion   int                      `json:"format_version"`
	BackupID        string                   `json:"backup_id"`
	CreatedAt       string                   `json:"created_at"`
	Host            string                   `json:"host"`
	AppVersion      string                   `json:"app_version"`
	Database        backup.DatabaseMeta      `json:"database"`
	Content         backup.ContentMeta       `json:"content"`
	Encryption      backup.EncryptionSummary `json:"encryption"`
	Entries         []backup.EntryReport     `json:"entries"`
	FileSHA256      string                   `json:"file_sha256"`
	FileSizeBytes   int64                    `json:"file_size_bytes"`
	ManifestSHA256  string                   `json:"manifest_sha256"`
	Snapshot        *backup.SnapshotReport   `json:"snapshot,omitempty"`
	SnapshotWarning string                   `json:"snapshot_warning,omitempty"`
}

// runList 实现 list 子命令：认证解密后展示格式/版本/时间/条目/完整性与内容范围。
func runList(args []string, stdout, stderr io.Writer) (exitCode int) {
	flags := flag.NewFlagSet(programName+" list", flag.ContinueOnError)
	flags.SetOutput(stderr)
	file := flags.String("file", "", "备份文件路径（必填）")
	keyFile := flags.String("key-file", "", "主密钥环文件路径（必填）")
	jsonOutput := flags.Bool("json", false, "以 JSON 输出结果")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "用法：login-backup list --file <备份文件> --key-file <主密钥环> [--json]")
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "错误：存在多余参数")
		return ExitUsage
	}
	fileAbs, err := absoluteFilePath(*file, "备份文件")
	if err != nil {
		fmt.Fprintln(stderr, "错误：--file 必填")
		return ExitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ring, code := loadViewerKeyring(ctx, *keyFile, stderr)
	if ring == nil {
		return code
	}
	viewer, err := backup.OpenViewer(ctx, backup.ViewOptions{Path: fileAbs, Keyring: ring})
	if err != nil {
		return mapViewerError(stdout, stderr, err, *jsonOutput)
	}
	defer func() {
		if closeErr := viewer.Close(); closeErr != nil {
			fmt.Fprintf(stderr, "警告：临时明文目录未完全清理：%v\n", closeErr)
			exitCode = ExitError
		}
	}()
	report := viewer.Report()
	output := listOutput{FileName: filepath.Base(fileAbs), Authenticated: report.Authenticated,
		IntegrityOK: report.Authenticated, FormatVersion: report.FormatVersion,
		BackupID: report.BackupID, CreatedAt: report.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		Host: report.Host, AppVersion: report.AppVersion, Database: report.Database,
		Content: report.Content, Encryption: report.Encryption, Entries: report.Entries,
		FileSHA256: report.FileSHA256, FileSizeBytes: report.FileSize,
		ManifestSHA256: report.ManifestSHA256}
	snapshot, snapshotErr := viewer.Snapshot(ctx)
	if snapshotErr == nil {
		output.Snapshot = &snapshot
	} else if errors.Is(snapshotErr, backup.ErrDatabaseUnsupported) {
		output.SnapshotWarning = snapshotErr.Error()
	} else {
		fmt.Fprintf(stderr, "错误：无法读取备份数据库版本信息（%s）：%v\n",
			backup.CodeOf(snapshotErr), snapshotErr)
		return mapViewerError(stdout, stderr, snapshotErr, *jsonOutput)
	}
	if *jsonOutput {
		return writeJSONResult(stdout, stderr, output)
	}
	fmt.Fprintln(stdout, "认证解密成功：清单与全部条目摘要一致。")
	fmt.Fprintf(stdout, "格式版本：%d；备份编号：%s\n", report.FormatVersion, report.BackupID)
	fmt.Fprintf(stdout, "创建时间：%s；主机：%s；应用版本：%s\n",
		output.CreatedAt, report.Host, report.AppVersion)
	fmt.Fprintf(stdout, "数据库引擎：%s；版本：%s（%d）；大小：%d 字节\n",
		report.Database.Engine, report.Database.SchemaVersion,
		report.Database.SchemaVersionNumber, report.Database.SizeBytes)
	fmt.Fprintf(stdout, "文件大小：%d 字节；文件 SHA-256：%s\n",
		report.FileSize, report.FileSHA256)
	fmt.Fprintf(stdout, "内容范围：数据库=是；附件=%s；配置=%s；密钥环=%s\n",
		report.Content.Attachments.Status, report.Content.Config.Status,
		report.Content.Keyring.Status)
	if output.Snapshot != nil {
		fmt.Fprintf(stdout, "schema_history：%d 条（最高 %s），表数量 %d\n",
			len(output.Snapshot.SchemaHistory), report.Database.SchemaVersion,
			output.Snapshot.TableCount)
		for _, migration := range output.Snapshot.SchemaHistory {
			fmt.Fprintf(stdout, "  %s  %s  %s\n", migration.Version,
				migration.AppliedAt.UTC().Format("2006-01-02T15:04:05Z"),
				migration.Description)
		}
	} else if output.SnapshotWarning != "" {
		fmt.Fprintf(stdout, "数据库版本解析：%s\n", output.SnapshotWarning)
	}
	fmt.Fprintf(stdout, "清单条目：%d\n", len(report.Entries))
	for _, entry := range report.Entries {
		fmt.Fprintf(stdout, "  - [%s] %s（%d 字节）%s\n", entry.Kind, entry.Name,
			entry.SizeBytes, entry.SHA256)
	}
	fmt.Fprintln(stdout, "注意：本工具只读备份，不执行备份内脚本，不连接生产数据库，不做恢复。")
	return ExitOK
}

// tablesOutput 是 tables 命令的机器可读结果。
type tablesOutput struct {
	BackupID      string               `json:"backup_id"`
	Authenticated bool                 `json:"authenticated"`
	Tables        []backup.TableSchema `json:"tables"`
}

// runTables 实现 tables 子命令：列出受限查询目录与该备份实际可用字段。
func runTables(args []string, stdout, stderr io.Writer) (exitCode int) {
	flags := flag.NewFlagSet(programName+" tables", flag.ContinueOnError)
	flags.SetOutput(stderr)
	file := flags.String("file", "", "备份文件路径（必填）")
	keyFile := flags.String("key-file", "", "主密钥环文件路径（必填）")
	jsonOutput := flags.Bool("json", false, "以 JSON 输出结果")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "用法：login-backup tables --file <备份文件> --key-file <主密钥环> [--json]")
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "错误：存在多余参数")
		return ExitUsage
	}
	fileAbs, err := absoluteFilePath(*file, "备份文件")
	if err != nil {
		fmt.Fprintln(stderr, "错误：--file 必填")
		return ExitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ring, code := loadViewerKeyring(ctx, *keyFile, stderr)
	if ring == nil {
		return code
	}
	viewer, err := backup.OpenViewer(ctx, backup.ViewOptions{Path: fileAbs, Keyring: ring})
	if err != nil {
		return mapViewerError(stdout, stderr, err, *jsonOutput)
	}
	defer func() {
		if closeErr := viewer.Close(); closeErr != nil {
			fmt.Fprintf(stderr, "警告：临时明文目录未完全清理：%v\n", closeErr)
			exitCode = ExitError
		}
	}()
	schemas, err := viewer.ListTableSchemas(ctx)
	if err != nil {
		return mapViewerError(stdout, stderr, err, *jsonOutput)
	}
	report := viewer.Report()
	output := tablesOutput{BackupID: report.BackupID,
		Authenticated: report.Authenticated, Tables: schemas}
	if *jsonOutput {
		return writeJSONResult(stdout, stderr, output)
	}
	fmt.Fprintf(stdout, "受限查询目录（备份 %s）；* 标记为默认排除的高敏字段：\n",
		report.BackupID)
	for _, schema := range schemas {
		status := "可用"
		if !schema.Available {
			status = "该备份无此表（可能是较旧版本）"
		}
		fmt.Fprintf(stdout, "\n%s [%s] %s — %s\n", schema.Table.Name,
			schema.Table.Category, schema.Table.Description, status)
		if !schema.Available {
			continue
		}
		names := make([]string, 0, len(schema.Columns))
		for _, column := range schema.Columns {
			name := column.Name
			if column.Sensitive {
				name = "*" + name
			}
			names = append(names, name)
		}
		fmt.Fprintf(stdout, "  字段：%s\n", strings.Join(names, ", "))
	}
	fmt.Fprintln(stdout, "\n受限查询不执行任意 SQL：表名来自静态白名单，字段来自认证快照的 schema，")
	fmt.Fprintln(stdout, "过滤值全部参数化；SQLite 以 mode=ro + PRAGMA query_only 只读打开。")
	return ExitOK
}

// previewOutput 是 preview 命令的机器可读结果。
type previewOutput struct {
	BackupID      string   `json:"backup_id"`
	Authenticated bool     `json:"authenticated"`
	FormatVersion int      `json:"format_version"`
	Table         string   `json:"table"`
	Columns       []string `json:"columns"`
	Rows          [][]any  `json:"rows"`
	Excluded      []string `json:"excluded_sensitive_columns,omitempty"`
	Limit         int      `json:"limit"`
	Truncated     bool     `json:"truncated"`
	Sensitive     bool     `json:"sensitive_included"`
}

// runPreview 实现 preview 子命令：受限只读预览认证解包后的 SQLite 逻辑数据。
func runPreview(args []string, stdout, stderr io.Writer) (exitCode int) {
	flags := flag.NewFlagSet(programName+" preview", flag.ContinueOnError)
	flags.SetOutput(stderr)
	file := flags.String("file", "", "备份文件路径（必填）")
	keyFile := flags.String("key-file", "", "主密钥环文件路径（必填）")
	table := flags.String("table", "", "受控目录表名（必填）")
	columns := flags.String("columns", "", "逗号分隔字段白名单；默认全部非敏感字段")
	limit := flags.Int("limit", backup.DefaultPreviewRows, "预览行数上限")
	includeSensitive := flags.Bool("include-sensitive", false, "显式包含默认排除的高敏字段")
	jsonOutput := flags.Bool("json", false, "以 JSON 输出结果")
	var whereSpecs repeatedFlag
	var orderSpecs repeatedFlag
	flags.Var(&whereSpecs, "where", "受限过滤条件，可重复；例：status=active 或 id IN (a,b)")
	flags.Var(&orderSpecs, "order-by", "受控排序，可重复；例：created_at_ms:desc")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "用法：login-backup preview --file <备份文件> --key-file <主密钥环> "+
			"--table <表名> [--columns a,b] [--where 条件]... [--order-by 字段[:asc|:desc]]... "+
			"[--limit 20] [--include-sensitive] [--json]")
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "错误：存在多余参数")
		return ExitUsage
	}
	if strings.TrimSpace(*table) == "" {
		fmt.Fprintln(stderr, "错误：--table 必填（可用 tables 命令查看受控目录）")
		return ExitUsage
	}
	if *limit < 1 || *limit > backup.MaxPreviewRows {
		fmt.Fprintf(stderr, "错误：preview 的 --limit 必须在 1..%d 之间\n",
			backup.MaxPreviewRows)
		return ExitUsage
	}
	fileAbs, err := absoluteFilePath(*file, "备份文件")
	if err != nil {
		fmt.Fprintln(stderr, "错误：--file 必填")
		return ExitUsage
	}
	query, err := buildQueryOptions(*table, *columns, whereSpecs, orderSpecs, *limit,
		*includeSensitive)
	if err != nil {
		fmt.Fprintf(stderr, "错误：查询参数无效：%v\n", err)
		return ExitUsage
	}
	if *includeSensitive {
		fmt.Fprintln(stderr, "警告：--include-sensitive 会读取默认排除的高敏字段；预览内容可能留在终端回滚缓冲/日志中。")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ring, code := loadViewerKeyring(ctx, *keyFile, stderr)
	if ring == nil {
		return code
	}
	viewer, err := backup.OpenViewer(ctx, backup.ViewOptions{Path: fileAbs, Keyring: ring})
	if err != nil {
		return mapViewerError(stdout, stderr, err, *jsonOutput)
	}
	defer func() {
		if closeErr := viewer.Close(); closeErr != nil {
			fmt.Fprintf(stderr, "警告：临时明文目录未完全清理：%v\n", closeErr)
			exitCode = ExitError
		}
	}()
	plan, err := viewer.BuildQueryPlan(ctx, query)
	if err != nil {
		return mapViewerError(stdout, stderr, err, *jsonOutput)
	}
	result, err := viewer.PreviewQuery(ctx, plan)
	if err != nil {
		return mapViewerError(stdout, stderr, err, *jsonOutput)
	}
	report := viewer.Report()
	if *jsonOutput {
		return writeJSONResult(stdout, stderr, previewOutput{BackupID: report.BackupID,
			Authenticated: report.Authenticated, FormatVersion: report.FormatVersion,
			Table: result.Table, Columns: result.Columns, Rows: result.Rows,
			Excluded: result.Excluded, Limit: result.Limit,
			Truncated: result.Truncated, Sensitive: plan.Sensitive})
	}
	if err := backup.WritePreviewText(stdout, result); err != nil {
		fmt.Fprintf(stderr, "错误：输出预览失败：%v\n", err)
		return ExitError
	}
	fmt.Fprintln(stdout, "\n注意：只读预览，不输出未确认的高敏字段，不代表可以据此回写生产数据。")
	return ExitOK
}

// exportOutput 是 export 命令的机器可读结果。
type exportOutput struct {
	BackupID        string   `json:"backup_id"`
	Authenticated   bool     `json:"authenticated"`
	Table           string   `json:"table"`
	Format          string   `json:"format"`
	OutputPath      string   `json:"output_path"`
	OutputFile      string   `json:"output_file"`
	BytesWritten    int64    `json:"bytes_written"`
	RowCount        int64    `json:"row_count"`
	Limit           int      `json:"limit"`
	Truncated       bool     `json:"truncated"`
	Columns         []string `json:"columns"`
	ExcludedColumns []string `json:"excluded_sensitive_columns,omitempty"`
	Sensitive       bool     `json:"sensitive_included"`
	OutputSHA256    string   `json:"output_sha256"`
	OperationLog    string   `json:"operation_log"`
}

// runExport 实现 export 子命令：受限查询结果导出 CSV/JSON，默认不覆盖。
func runExport(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet(programName+" export", flag.ContinueOnError)
	flags.SetOutput(stderr)
	file := flags.String("file", "", "备份文件路径（必填）")
	keyFile := flags.String("key-file", "", "主密钥环文件路径（必填）")
	table := flags.String("table", "", "受控目录表名（必填）")
	format := flags.String("format", backup.ExportFormatCSV, "导出格式：csv 或 json")
	output := flags.String("output", "", "绝对输出文件路径（必填，默认不覆盖）")
	columns := flags.String("columns", "", "逗号分隔字段白名单；默认全部非敏感字段")
	limit := flags.Int("limit", backup.DefaultExportRows, "导出行数上限")
	includeSensitive := flags.Bool("include-sensitive", false, "显式包含默认排除的高敏字段")
	operator := flags.String("operator", "", "本地操作者标识（写入本地操作记录）")
	oplog := flags.String("oplog", "", "本地操作记录文件路径（默认输出目录下）")
	jsonOutput := flags.Bool("json", false, "以 JSON 输出结果摘要")
	var whereSpecs repeatedFlag
	var orderSpecs repeatedFlag
	flags.Var(&whereSpecs, "where", "受限过滤条件，可重复")
	flags.Var(&orderSpecs, "order-by", "受控排序，可重复")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "用法：login-backup export --file <备份文件> --key-file <主密钥环> "+
			"--table <表名> --format csv|json --output <绝对输出文件> "+
			"[--columns a,b] [--where 条件]... [--order-by 字段[:asc|:desc]]... "+
			"[--limit 1000] [--include-sensitive] [--operator 标识] [--oplog 文件] [--json]")
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "错误：存在多余参数")
		return ExitUsage
	}
	if strings.TrimSpace(*table) == "" || strings.TrimSpace(*output) == "" {
		fmt.Fprintln(stderr, "错误：--table 与 --output 均必填")
		return ExitUsage
	}
	normalizedFormat := strings.ToLower(strings.TrimSpace(*format))
	if normalizedFormat != backup.ExportFormatCSV && normalizedFormat != backup.ExportFormatJSON {
		fmt.Fprintln(stderr, "错误：--format 只允许 csv 或 json")
		return ExitUsage
	}
	if *limit < 1 || *limit > backup.MaxExportRows {
		fmt.Fprintf(stderr, "错误：export 的 --limit 必须在 1..%d 之间\n",
			backup.MaxExportRows)
		return ExitUsage
	}
	fileAbs, err := absoluteFilePath(*file, "备份文件")
	if err != nil {
		fmt.Fprintln(stderr, "错误：--file 必填")
		return ExitUsage
	}
	query, err := buildQueryOptions(*table, *columns, whereSpecs, orderSpecs, *limit,
		*includeSensitive)
	if err != nil {
		fmt.Fprintf(stderr, "错误：查询参数无效：%v\n", err)
		return ExitUsage
	}
	if *includeSensitive {
		fmt.Fprintln(stderr, "警告：--include-sensitive 会导出默认排除的高敏字段或原始数据库内容；")
		fmt.Fprintln(stderr, "      请确保输出位置受保护（Windows 文件 DACL / 非 Windows 0700 目录），使用后安全处置。")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ring, code := loadViewerKeyring(ctx, *keyFile, stderr)
	if ring == nil {
		return code
	}
	result, err := backup.ExportTable(ctx, backup.ExportOptions{Path: fileAbs,
		Keyring: ring, Query: query, Format: normalizedFormat,
		OutputPath: strings.TrimSpace(*output), Operator: *operator,
		OperationLogPath: *oplog})
	if err != nil {
		return mapViewerError(stdout, stderr, err, *jsonOutput)
	}
	if *jsonOutput {
		return writeJSONResult(stdout, stderr, exportOutput{BackupID: result.BackupID,
			Authenticated: true, Table: result.Table, Format: result.Format,
			OutputPath: result.OutputPath, OutputFile: result.OutputFile,
			BytesWritten: result.BytesWritten, RowCount: result.RowCount,
			Limit: result.Limit, Truncated: result.Truncated,
			Columns: result.Columns, ExcludedColumns: result.ExcludedColumns,
			Sensitive: result.Sensitive, OutputSHA256: result.OutputSHA256,
			OperationLog: result.OperationLog})
	}
	fmt.Fprintf(stdout, "导出完成：%s（%s，%d 行，%d 字节）\n", result.OutputFile,
		result.Format, result.RowCount, result.BytesWritten)
	fmt.Fprintf(stdout, "路径：%s\n", result.OutputPath)
	fmt.Fprintf(stdout, "表：%s；字段：%s\n", result.Table,
		strings.Join(result.Columns, ", "))
	fmt.Fprintf(stdout, "输出 SHA-256：%s\n", result.OutputSHA256)
	if result.Truncated {
		fmt.Fprintf(stdout, "提示：已达到行数上限 %d，可能还有更多数据未导出。\n", result.Limit)
	}
	if len(result.ExcludedColumns) > 0 {
		fmt.Fprintf(stdout, "已排除敏感字段：%s\n",
			strings.Join(result.ExcludedColumns, ", "))
	}
	fmt.Fprintf(stdout, "本地操作记录：%s\n", result.OperationLog)
	fmt.Fprintln(stdout, "注意：单独导出不等于回写或恢复；本工具不修改生产数据库。")
	return ExitOK
}

// extractOutput 是 extract 命令的机器可读结果。
type extractOutput struct {
	BackupID      string `json:"backup_id"`
	Authenticated bool   `json:"authenticated"`
	EntryName     string `json:"entry_name"`
	EntryKind     string `json:"entry_kind"`
	SizeBytes     int64  `json:"size_bytes"`
	SHA256        string `json:"sha256"`
	OutputPath    string `json:"output_path"`
	OutputFile    string `json:"output_file"`
	Sensitive     bool   `json:"sensitive_included"`
	OperationLog  string `json:"operation_log"`
}

// runExtract 实现 extract 子命令：逐项提取清单条目（附件/配置/原始数据库）。
func runExtract(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet(programName+" extract", flag.ContinueOnError)
	flags.SetOutput(stderr)
	file := flags.String("file", "", "备份文件路径（必填）")
	keyFile := flags.String("key-file", "", "主密钥环文件路径（必填）")
	entry := flags.String("entry", "", "清单条目名（必填，可用 list 查看）")
	output := flags.String("output", "", "绝对输出文件路径（必填，默认不覆盖）")
	includeSensitive := flags.Bool("include-sensitive", false, "显式允许提取原始数据库条目")
	operator := flags.String("operator", "", "本地操作者标识（写入本地操作记录）")
	oplog := flags.String("oplog", "", "本地操作记录文件路径（默认输出目录下）")
	jsonOutput := flags.Bool("json", false, "以 JSON 输出结果摘要")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "用法：login-backup extract --file <备份文件> --key-file <主密钥环> "+
			"--entry <清单条目名> --output <绝对输出文件> [--include-sensitive] "+
			"[--operator 标识] [--oplog 文件] [--json]")
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "错误：存在多余参数")
		return ExitUsage
	}
	if strings.TrimSpace(*entry) == "" || strings.TrimSpace(*output) == "" {
		fmt.Fprintln(stderr, "错误：--entry 与 --output 均必填")
		return ExitUsage
	}
	fileAbs, err := absoluteFilePath(*file, "备份文件")
	if err != nil {
		fmt.Fprintln(stderr, "错误：--file 必填")
		return ExitUsage
	}
	if *includeSensitive {
		fmt.Fprintln(stderr, "警告：--include-sensitive 允许提取原始数据库条目（包含密码哈希、令牌等认证秘密）；")
		fmt.Fprintln(stderr, "      仅在确需离线取证/恢复时使用，并确保输出位置受保护。")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ring, code := loadViewerKeyring(ctx, *keyFile, stderr)
	if ring == nil {
		return code
	}
	result, err := backup.ExtractEntry(ctx, backup.ExtractEntryOptions{Path: fileAbs,
		Keyring: ring, EntryName: strings.TrimSpace(*entry),
		OutputPath: strings.TrimSpace(*output), IncludeSensitive: *includeSensitive,
		Operator: *operator, OperationLogPath: *oplog})
	if err != nil {
		return mapViewerError(stdout, stderr, err, *jsonOutput)
	}
	if *jsonOutput {
		return writeJSONResult(stdout, stderr, extractOutput{BackupID: result.BackupID,
			Authenticated: true, EntryName: result.EntryName, EntryKind: result.EntryKind,
			SizeBytes: result.SizeBytes, SHA256: result.SHA256,
			OutputPath: result.OutputPath, OutputFile: result.OutputFile,
			Sensitive: result.Sensitive, OperationLog: result.OperationLog})
	}
	fmt.Fprintf(stdout, "提取完成：%s（类型 %s，%d 字节）\n", result.EntryName,
		result.EntryKind, result.SizeBytes)
	fmt.Fprintf(stdout, "路径：%s\n", result.OutputPath)
	fmt.Fprintf(stdout, "SHA-256：%s\n", result.SHA256)
	fmt.Fprintf(stdout, "本地操作记录：%s\n", result.OperationLog)
	fmt.Fprintln(stdout, "注意：提取只是导出副本，不执行其中内容，也不写回生产数据库。")
	return ExitOK
}

// buildQueryOptions 把 CLI 参数转换为受限查询请求；格式错误属于用法错误。
func buildQueryOptions(table, columns string, whereSpecs, orderSpecs []string,
	limit int, includeSensitive bool) (backup.QueryOptions, error) {
	query := backup.QueryOptions{Table: strings.TrimSpace(table), Limit: limit,
		IncludeSensitive: includeSensitive}
	if strings.TrimSpace(columns) != "" {
		parsedColumns, err := backup.ParseColumnList(columns)
		if err != nil {
			return backup.QueryOptions{}, err
		}
		query.Columns = parsedColumns
	}
	for _, spec := range whereSpecs {
		filter, err := backup.ParseColumnFilter(spec)
		if err != nil {
			return backup.QueryOptions{}, err
		}
		query.Filters = append(query.Filters, filter)
	}
	for _, spec := range orderSpecs {
		order, err := backup.ParseOrderSpec(spec)
		if err != nil {
			return backup.QueryOptions{}, err
		}
		query.OrderBy = append(query.OrderBy, order)
	}
	return query, nil
}
