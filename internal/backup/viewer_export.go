package backup

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

// 离线导出与单项提取（步骤 83）。安全不变量：
//   - 输出文件必须使用绝对路径、父目录已存在且为真实目录（非符号链接）；目标
//     文件以 O_CREATE|O_EXCL|O_WRONLY 0600 独占创建，默认绝不覆盖已有文件，也
//     不会跟随预置的目标符号链接。
//   - 高敏导出（--include-sensitive 或原始数据库条目）在写入任何内容前先收紧
//     落地文件权限（Windows 显式 DACL；非 Windows 输出目录必须 0700），失败即
//     删除空文件并拒绝导出。
//   - CSV 防公式注入、JSON 只做数据编码；操作记录只写元数据（不写过滤值/数据）。
//   - 取消/失败删除不完整输出文件；临时解包目录由 Viewer/本文件清理。
const (
	// ExportFormatCSV 是 CSV 导出格式标识。
	ExportFormatCSV = "csv"
	// ExportFormatJSON 是 JSON 导出格式标识。
	ExportFormatJSON = "json"
	// defaultOperationLogName 是默认本地操作记录文件名（位于输出目录）。
	defaultOperationLogName = ".login-backup-viewer-oplog.jsonl"
)

// ExportOptions 是受限查询导出的请求。
type ExportOptions struct {
	// Path 是备份文件路径。
	Path string
	// Keyring 是用户提供的主密钥环。
	Keyring *secrets.Keyring
	// Query 是受限查询参数；IncludeSensitive 由 CLI 的 --include-sensitive 填充。
	Query QueryOptions
	// Format 是 csv 或 json。
	Format string
	// OutputPath 是导出文件绝对路径；文件必须不存在。
	OutputPath string
	// Operator 是本地操作者标识（写入本地操作记录，不做认证声明）。
	Operator string
	// OperationLogPath 是本地操作记录文件路径；为空时默认写入输出目录。
	OperationLogPath string
	// TempRoot 是临时解包目录父路径；为空使用系统临时目录。
	TempRoot string
	// MaxExtractedBytes 是临时解包字节上限；<=0 使用默认值。
	MaxExtractedBytes int64
}

// ExportResult 是导出成功后的机器可读结果（不含数据内容与秘密）。
type ExportResult struct {
	BackupID        string   `json:"backup_id"`
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

// ExtractEntryOptions 是单项条目提取的请求。
type ExtractEntryOptions struct {
	// Path 是备份文件路径。
	Path string
	// Keyring 是用户提供的主密钥环。
	Keyring *secrets.Keyring
	// EntryName 是清单中的条目名（例如 attachments/avatars/xxx）。
	EntryName string
	// OutputPath 是提取目标文件绝对路径；文件必须不存在。
	OutputPath string
	// IncludeSensitive 是原始数据库条目的显式确认；附件/配置条目不需要。
	IncludeSensitive bool
	// Operator 是本地操作者标识（写入本地操作记录）。
	Operator string
	// OperationLogPath 是本地操作记录文件路径；为空时默认写入输出目录。
	OperationLogPath string
	// TempRoot 是临时解包目录父路径；为空使用系统临时目录。
	TempRoot string
}

// ExtractEntryResult 是单项提取成功后的机器可读结果。
type ExtractEntryResult struct {
	BackupID     string `json:"backup_id"`
	EntryName    string `json:"entry_name"`
	EntryKind    string `json:"entry_kind"`
	SizeBytes    int64  `json:"size_bytes"`
	SHA256       string `json:"sha256"`
	OutputPath   string `json:"output_path"`
	OutputFile   string `json:"output_file"`
	Sensitive    bool   `json:"sensitive_included"`
	OperationLog string `json:"operation_log"`
}

// viewerOperationRecord 是本地操作记录的一行（JSONL）。它只记录元数据：不记录
// 数据行、过滤值（可能含个人信息）、主密钥或绝对备份路径。
type viewerOperationRecord struct {
	Time             string   `json:"time"`
	Operator         string   `json:"operator"`
	Command          string   `json:"command"`
	Outcome          string   `json:"outcome"`
	ErrorCode        string   `json:"error_code,omitempty"`
	BackupID         string   `json:"backup_id,omitempty"`
	BackupFileSHA256 string   `json:"backup_file_sha256,omitempty"`
	Table            string   `json:"table,omitempty"`
	EntryName        string   `json:"entry_name,omitempty"`
	EntryKind        string   `json:"entry_kind,omitempty"`
	Format           string   `json:"format,omitempty"`
	Columns          []string `json:"columns,omitempty"`
	FilterColumns    []string `json:"filter_columns,omitempty"`
	RowCount         int64    `json:"row_count"`
	Limit            int      `json:"limit,omitempty"`
	Truncated        bool     `json:"truncated,omitempty"`
	OutputFile       string   `json:"output_file"`
	OutputBytes      int64    `json:"output_bytes"`
	OutputSHA256     string   `json:"output_sha256,omitempty"`
	Sensitive        bool     `json:"sensitive_included"`
}

// resolvedOutput 是已校验的导出目标。
type resolvedOutput struct {
	absolute  string
	directory string
	baseName  string
}

// ExportTable 执行受限查询并流式导出 CSV/JSON。原备份文件只读；失败/取消时删除
// 不完整输出文件并清理临时明文。
func ExportTable(ctx context.Context, options ExportOptions) (result ExportResult, err error) {
	ctx = normalizeContext(ctx)
	if options.Keyring == nil {
		return ExportResult{}, fmt.Errorf("%w: 未提供主密钥环", ErrOptionsInvalid)
	}
	format := strings.ToLower(strings.TrimSpace(options.Format))
	if format != ExportFormatCSV && format != ExportFormatJSON {
		return ExportResult{}, fmt.Errorf("%w: 导出格式只允许 csv 或 json", ErrQueryInvalid)
	}
	output, err := resolveOutputFile(options.OutputPath)
	if err != nil {
		return ExportResult{}, err
	}
	viewer, err := OpenViewer(ctx, ViewOptions{Path: options.Path,
		Keyring: options.Keyring, TempRoot: options.TempRoot,
		MaxExtractedBytes: options.MaxExtractedBytes})
	if err != nil {
		return ExportResult{}, err
	}
	defer func() {
		if closeErr := viewer.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("%w: 清理临时目录失败：%v",
				ErrCleanupFailed, closeErr))
		}
	}()
	plan, err := viewer.BuildQueryPlan(ctx, options.Query)
	if err != nil {
		return ExportResult{}, err
	}
	report := viewer.Report()
	operationLogPath, err := resolveOperationLogPath(options.OperationLogPath,
		output.directory)
	if err != nil {
		return ExportResult{}, err
	}
	record := viewerOperationRecord{Time: time.Now().UTC().Format(time.RFC3339),
		Operator: normalizeOperator(options.Operator), Command: "export",
		BackupID: report.BackupID, BackupFileSHA256: report.FileSHA256,
		Table: plan.Table, Format: format, Columns: plan.Columns,
		FilterColumns: filterColumnSummary(plan.Filters), Limit: plan.Limit,
		OutputFile: output.baseName, Sensitive: plan.Sensitive}
	operationLog, err := openOperationLog(operationLogPath)
	if err != nil {
		return ExportResult{}, err
	}
	defer func() { _ = operationLog.Close() }()
	fail := func(cause error) (ExportResult, error) {
		record.Outcome = "failed"
		record.ErrorCode = string(CodeOf(cause))
		_ = appendOperationRecord(operationLog, record)
		return ExportResult{}, cause
	}
	if plan.Sensitive {
		if err := verifySensitiveOutputDirectory(output.directory); err != nil {
			return fail(err)
		}
	}
	stream, err := viewer.OpenQuery(ctx, plan)
	if err != nil {
		return fail(err)
	}
	defer func() { _ = stream.Close() }()
	file, err := os.OpenFile(output.absolute,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fail(fmt.Errorf("%w: 输出文件已存在", ErrOutputExists))
		}
		return fail(fmt.Errorf("%w: 无法创建输出文件", ErrOutputDirUnsafe))
	}
	removeOnError := true
	defer func() {
		if removeOnError {
			_ = file.Close()
			_ = os.Remove(output.absolute)
		}
	}()
	// 高敏导出：在写入任何数据之前先收紧空文件权限；失败则删空文件并拒绝。
	if plan.Sensitive {
		if protectErr := secrets.ProtectFile(output.absolute); protectErr != nil {
			return fail(fmt.Errorf("%w: 高敏导出文件无法收紧权限：%v",
				ErrOutputDirUnsafe, protectErr))
		}
	}
	hasher := sha256.New()
	buffered := bufio.NewWriterSize(io.MultiWriter(file, hasher), 64*1024)
	var rowCount int64
	var truncated bool
	if format == ExportFormatCSV {
		rowCount, err = writeCSVExport(buffered, stream)
		truncated = stream.Truncated()
	} else {
		rowCount, truncated, err = writeJSONExport(buffered, stream, jsonExportMeta{
			FormatVersion:       exportFormatVersionJSON,
			BackupID:            report.BackupID,
			Table:               plan.Table,
			Columns:             plan.Columns,
			ExcludedSensitive:   plan.Excluded,
			Limit:               plan.Limit,
			SensitiveIncluded:   plan.Sensitive,
			BackupFileSHA256:    report.FileSHA256,
			SchemaFormatVersion: report.FormatVersion,
		})
	}
	if err != nil {
		return fail(err)
	}
	if err := buffered.Flush(); err != nil {
		return fail(fmt.Errorf("%w: 刷新输出缓冲失败", ErrBackupIO))
	}
	if err := file.Sync(); err != nil {
		return fail(fmt.Errorf("%w: 同步输出文件失败", ErrBackupIO))
	}
	if err := file.Close(); err != nil {
		return fail(fmt.Errorf("%w: 关闭输出文件失败", ErrBackupIO))
	}
	removeOnError = false
	info, statErr := os.Stat(output.absolute)
	if statErr != nil {
		return fail(fmt.Errorf("%w: 无法确认输出文件", ErrBackupIO))
	}
	if truncated {
		record.Truncated = true
	}
	record.Outcome = "succeeded"
	record.RowCount = rowCount
	record.OutputBytes = info.Size()
	record.OutputSHA256 = hex.EncodeToString(hasher.Sum(nil))
	if logErr := appendOperationRecord(operationLog, record); logErr != nil {
		return ExportResult{}, fmt.Errorf(
			"%w: 导出文件已写入，但本地操作记录写入失败：%v", ErrBackupIO, logErr)
	}
	return ExportResult{BackupID: report.BackupID, Table: plan.Table, Format: format,
		OutputPath: output.absolute, OutputFile: output.baseName,
		BytesWritten: info.Size(), RowCount: rowCount, Limit: plan.Limit,
		Truncated: truncated, Columns: plan.Columns,
		ExcludedColumns: plan.Excluded, Sensitive: plan.Sensitive,
		OutputSHA256: record.OutputSHA256, OperationLog: operationLogPath}, nil
}

// ExtractEntry 认证解包并提取单个清单条目（附件/配置/原始数据库）到指定文件。
// 原始数据库条目包含认证秘密，必须显式 IncludeSensitive 并收紧输出权限。
func ExtractEntry(ctx context.Context, options ExtractEntryOptions) (result ExtractEntryResult, err error) {
	ctx = normalizeContext(ctx)
	if options.Keyring == nil {
		return ExtractEntryResult{}, fmt.Errorf("%w: 未提供主密钥环", ErrOptionsInvalid)
	}
	entryName := strings.TrimSpace(options.EntryName)
	// 用户提供的条目名同样经过与清单一致的形状校验：绝对路径、`..`、反斜杠、
	// Windows 保留设备名、尾随点/空格等在打开备份前就被拒绝（默认拒绝）。
	if err := validateEntryNameShape(entryName); err != nil {
		return ExtractEntryResult{}, fmt.Errorf("%w: %v", ErrQueryInvalid, err)
	}
	output, err := resolveOutputFile(options.OutputPath)
	if err != nil {
		return ExtractEntryResult{}, err
	}
	tempRoot := strings.TrimSpace(options.TempRoot)
	if tempRoot != "" {
		info, statErr := os.Lstat(tempRoot)
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return ExtractEntryResult{}, fmt.Errorf(
				"%w: 临时目录父路径必须是已存在的真实目录", ErrOutputDirUnsafe)
		}
	}
	tempDir, err := os.MkdirTemp(tempRoot, viewerTempPrefix)
	if err != nil {
		return ExtractEntryResult{}, fmt.Errorf("%w: 无法创建受控临时目录", ErrBackupIO)
	}
	defer func() {
		if cleanupErr := os.RemoveAll(tempDir); cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("%w: 清理临时目录失败：%v",
				ErrCleanupFailed, cleanupErr))
		}
	}()
	extractResult, err := Extract(ctx, ExtractOptions{Path: options.Path,
		Keyring: options.Keyring, Destination: tempDir,
		MaxSelectedBytes: MaxBackupFileBytes, MaxSelectedEntries: 1,
		OnlyEntries: func(entry ManifestEntry) bool { return entry.Name == entryName }})
	if err != nil {
		return ExtractEntryResult{}, err
	}
	var selected *ManifestEntry
	for index := range extractResult.Report.Entries {
		if extractResult.Report.Entries[index].Name == entryName {
			entry := ManifestEntry{Name: extractResult.Report.Entries[index].Name,
				Kind:      extractResult.Report.Entries[index].Kind,
				SizeBytes: extractResult.Report.Entries[index].SizeBytes,
				SHA256:    extractResult.Report.Entries[index].SHA256}
			selected = &entry
			break
		}
	}
	if selected == nil {
		return ExtractEntryResult{}, fmt.Errorf(
			"%w: 备份中没有条目 %q（可用 list 命令查看清单）", ErrQueryInvalid, entryName)
	}
	if len(extractResult.Entries) != 1 {
		return ExtractEntryResult{}, fmt.Errorf("%w: 条目提取结果数量异常", ErrIntegrityFailed)
	}
	extracted := extractResult.Entries[0]
	// 原始数据库条目包含密码哈希/令牌；配置快照可能包含宿主配置秘密（设计上应
	// 只用 env:/file: 引用，但工具不能假定），两者都按高敏条目处理，必须显式确认
	// 并收紧输出权限。附件为用户内容，不按认证秘密处理（仍默认不覆盖输出）。
	sensitive := selected.Kind == EntryKindDatabase || selected.Kind == EntryKindConfig
	if sensitive && !options.IncludeSensitive {
		label := "原始数据库条目包含密码哈希与令牌等认证秘密"
		if selected.Kind == EntryKindConfig {
			label = "配置快照可能包含宿主配置秘密或秘密引用"
		}
		return ExtractEntryResult{}, fmt.Errorf(
			"%w: %s；如确需提取请显式使用 --include-sensitive 并确保输出位置受保护",
			ErrSensitiveRequired, label)
	}
	if err := verifySensitiveOutputDirectoryConditional(sensitive, output.directory); err != nil {
		return ExtractEntryResult{}, err
	}
	report := extractResult.Report
	operationLogPath, err := resolveOperationLogPath(options.OperationLogPath,
		output.directory)
	if err != nil {
		return ExtractEntryResult{}, err
	}
	record := viewerOperationRecord{Time: time.Now().UTC().Format(time.RFC3339),
		Operator: normalizeOperator(options.Operator), Command: "extract",
		BackupID: report.BackupID, BackupFileSHA256: report.FileSHA256,
		EntryName: selected.Name, EntryKind: selected.Kind,
		OutputFile: output.baseName, Sensitive: sensitive}
	operationLog, err := openOperationLog(operationLogPath)
	if err != nil {
		return ExtractEntryResult{}, err
	}
	defer func() { _ = operationLog.Close() }()
	fail := func(cause error) (ExtractEntryResult, error) {
		record.Outcome = "failed"
		record.ErrorCode = string(CodeOf(cause))
		_ = appendOperationRecord(operationLog, record)
		return ExtractEntryResult{}, cause
	}
	source, err := os.Open(extracted.Path)
	if err != nil {
		return fail(fmt.Errorf("%w: 无法读取已解包条目", ErrBackupIO))
	}
	defer source.Close()
	file, err := os.OpenFile(output.absolute,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fail(fmt.Errorf("%w: 输出文件已存在", ErrOutputExists))
		}
		return fail(fmt.Errorf("%w: 无法创建输出文件", ErrOutputDirUnsafe))
	}
	removeOnError := true
	defer func() {
		if removeOnError {
			_ = file.Close()
			_ = os.Remove(output.absolute)
		}
	}()
	if sensitive {
		if protectErr := secrets.ProtectFile(output.absolute); protectErr != nil {
			return fail(fmt.Errorf("%w: 高敏导出文件无法收紧权限：%v",
				ErrOutputDirUnsafe, protectErr))
		}
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hasher), source)
	if copyErr != nil {
		return fail(fmt.Errorf("%w: 写入输出文件失败", ErrBackupIO))
	}
	if written != selected.SizeBytes ||
		hex.EncodeToString(hasher.Sum(nil)) != selected.SHA256 {
		return fail(fmt.Errorf("%w: 提取内容与清单摘要不一致", ErrIntegrityFailed))
	}
	if err := file.Sync(); err != nil {
		return fail(fmt.Errorf("%w: 同步输出文件失败", ErrBackupIO))
	}
	if err := file.Close(); err != nil {
		return fail(fmt.Errorf("%w: 关闭输出文件失败", ErrBackupIO))
	}
	removeOnError = false
	record.Outcome = "succeeded"
	record.OutputBytes = written
	record.OutputSHA256 = hex.EncodeToString(hasher.Sum(nil))
	record.RowCount = 1
	if logErr := appendOperationRecord(operationLog, record); logErr != nil {
		return ExtractEntryResult{}, fmt.Errorf(
			"%w: 提取文件已写入，但本地操作记录写入失败：%v", ErrBackupIO, logErr)
	}
	return ExtractEntryResult{BackupID: report.BackupID, EntryName: selected.Name,
		EntryKind: selected.Kind, SizeBytes: written, SHA256: record.OutputSHA256,
		OutputPath: output.absolute, OutputFile: output.baseName,
		Sensitive: sensitive, OperationLog: operationLogPath}, nil
}

// resolveOutputFile 校验导出目标是绝对路径、父目录存在且为真实目录、目标文件
// 尚不存在。它不创建文件；创建使用 O_EXCL，避免覆盖与跟随预置符号链接。
func resolveOutputFile(path string) (resolvedOutput, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return resolvedOutput{}, fmt.Errorf("%w: 输出文件路径为空", ErrOptionsInvalid)
	}
	if !filepath.IsAbs(trimmed) {
		return resolvedOutput{}, fmt.Errorf("%w: 输出文件必须使用绝对路径",
			ErrOutputDirUnsafe)
	}
	absolute := filepath.Clean(trimmed)
	directory := filepath.Dir(absolute)
	info, err := os.Lstat(directory)
	if err != nil {
		return resolvedOutput{}, fmt.Errorf("%w: 输出目录不存在", ErrOutputDirUnsafe)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return resolvedOutput{}, fmt.Errorf("%w: 输出目录必须是非符号链接的真实目录",
			ErrOutputDirUnsafe)
	}
	if _, statErr := os.Lstat(absolute); statErr == nil {
		return resolvedOutput{}, fmt.Errorf("%w: %s", ErrOutputExists, absolute)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return resolvedOutput{}, fmt.Errorf("%w: 无法检查输出文件状态", ErrOutputDirUnsafe)
	}
	baseName := filepath.Base(absolute)
	if baseName == "" || baseName == "." || baseName == ".." ||
		strings.ContainsAny(baseName, `/\`) {
		return resolvedOutput{}, fmt.Errorf("%w: 输出文件名不合法", ErrOutputDirUnsafe)
	}
	return resolvedOutput{absolute: absolute, directory: directory,
		baseName: baseName}, nil
}

// verifySensitiveOutputDirectory 校验高敏导出的输出目录：非 Windows 要求目录权限
// 不向组/其他用户开放（0700 等价）；Windows 由写入前对文件设置显式 DACL 承接。
func verifySensitiveOutputDirectory(directory string) error {
	if isWindowsPlatform() {
		return nil
	}
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: 高敏导出输出目录不可用", ErrOutputDirUnsafe)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: 高敏导出要求输出目录权限为 0700（不向组/其他用户开放）",
			ErrOutputDirUnsafe)
	}
	return nil
}

// verifySensitiveOutputDirectoryConditional 只在条目敏感时校验输出目录。
func verifySensitiveOutputDirectoryConditional(sensitive bool, directory string) error {
	if !sensitive {
		return nil
	}
	return verifySensitiveOutputDirectory(directory)
}

// normalizeOperator 归一化本地操作者标识：去控制字符、限制 64 字节；为空时回退
// 到操作系统用户标识（只用于本地操作记录，不是认证声明）。
func normalizeOperator(operator string) string {
	value := strings.TrimSpace(operator)
	if value == "" {
		value = strings.TrimSpace(os.Getenv("USERNAME"))
	}
	if value == "" {
		value = strings.TrimSpace(os.Getenv("USER"))
	}
	cleaned := strings.Map(func(char rune) rune {
		if char < 0x20 || char == 0x7f {
			return -1
		}
		return char
	}, value)
	if len(cleaned) > 64 {
		cleaned = cleaned[:64]
	}
	if cleaned == "" {
		cleaned = "unknown-operator"
	}
	return cleaned
}

// filterColumnSummary 只保留过滤字段名与操作符（不记录过滤值，值可能是个人信息）。
func filterColumnSummary(filters []ColumnFilter) []string {
	if len(filters) == 0 {
		return nil
	}
	summary := make([]string, 0, len(filters))
	for _, filter := range filters {
		summary = append(summary, filter.Column+filter.Operator)
	}
	return summary
}

// resolveOperationLogPath 解析本地操作记录路径；为空时默认放在输出目录。
func resolveOperationLogPath(explicit, outputDir string) (string, error) {
	if strings.TrimSpace(explicit) != "" {
		absolute, err := filepath.Abs(strings.TrimSpace(explicit))
		if err != nil {
			return "", fmt.Errorf("%w: 操作记录路径无效", ErrOptionsInvalid)
		}
		return absolute, nil
	}
	return filepath.Join(outputDir, defaultOperationLogName), nil
}

// openOperationLog 打开（必要时创建）仅追加的本地操作记录文件；记录文件只包含
// 元数据，不包含秘密或数据内容。
func openOperationLog(path string) (*os.File, error) {
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("%w: 操作记录目录不可用", ErrOutputDirUnsafe)
	}
	if existing, statErr := os.Lstat(path); statErr == nil {
		if existing.Mode()&os.ModeSymlink != 0 || !existing.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: 操作记录路径必须是普通文件", ErrOutputDirUnsafe)
		}
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法打开本地操作记录文件", ErrBackupIO)
	}
	return file, nil
}

// appendOperationRecord 追加一行 JSON 操作记录并同步。
func appendOperationRecord(file *os.File, record viewerOperationRecord) error {
	if file == nil {
		return fmt.Errorf("%w: 操作记录文件为空", ErrOptionsInvalid)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("%w: 操作记录序列化失败", ErrInternal)
	}
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("%w: 写入操作记录失败", ErrBackupIO)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("%w: 同步操作记录失败", ErrBackupIO)
	}
	return nil
}
