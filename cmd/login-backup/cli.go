package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/avatar"
	"github.com/kagurazakayashi/EvernightLogin/internal/backup"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// 稳定退出码；测试会逐项断言。
const (
	ExitOK             = 0
	ExitError          = 1
	ExitUsage          = 2
	ExitVerifyFailed   = 3
	ExitDecryptFailed  = 4
	ExitOutputConflict = 5
	ExitQueryInvalid   = 6
	ExitCancelled      = 130
)

const programName = "login-backup"

// Run 执行 login-backup 命令并返回稳定退出码。stdout 只输出成功结果，stderr 输出
// 安全错误与进度；任何路径都不打印主密钥、明文数据库内容或备份载荷。
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return ExitUsage
	}
	switch args[0] {
	case "create":
		return runCreate(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "info":
		return runInfo(args[1:], stdout, stderr)
	case "list":
		return runList(args[1:], stdout, stderr)
	case "tables":
		return runTables(args[1:], stdout, stderr)
	case "preview":
		return runPreview(args[1:], stdout, stderr)
	case "export":
		return runExport(args[1:], stdout, stderr)
	case "extract":
		return runExtract(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		printUsage(stdout)
		return ExitOK
	case "version", "--version":
		fmt.Fprintf(stdout, "%s %s\n", programName, login.CurrentBuildInfo().String())
		return ExitOK
	default:
		fmt.Fprintf(stderr, "错误：未知命令 %q\n\n", args[0])
		printUsage(stderr)
		return ExitUsage
	}
}

// printUsage 输出中文帮助与稳定退出码说明。
func printUsage(writer io.Writer) {
	fmt.Fprintln(writer, `login-backup：login 备份的本地手动触发、离线校验与只读查看/导出工具（步骤 80/83）

用法：
  login-backup create --database <SQLite 数据库路径> --key-file <主密钥环文件> \
        --output <受控输出目录> --operator <本地操作者标识> \
        [--config <YAML 配置路径>] [--avatars <头像受控目录>] \
        [--request-id <请求编号>] [--timeout 10m] [--progress] [--json]
  login-backup verify --file <备份文件> --key-file <主密钥环文件> [--json]
  login-backup info --file <备份文件> [--json]
  login-backup list --file <备份文件> --key-file <主密钥环文件> [--json]
  login-backup tables --file <备份文件> --key-file <主密钥环文件> [--json]
  login-backup preview --file <备份文件> --key-file <主密钥环文件> --table <表名> \
        [--columns a,b,c] [--where "字段=值"]... [--where "字段 IN (a,b)"]... \
        [--order-by 字段[:asc|:desc]]... [--limit 20] [--include-sensitive] [--json]
  login-backup export --file <备份文件> --key-file <主密钥环文件> --table <表名> \
        --format csv|json --output <绝对输出文件> \
        [--columns a,b] [--where ...]... [--order-by ...]... [--limit 1000] \
        [--include-sensitive] [--operator <标识>] [--oplog <记录文件>] [--json]
  login-backup extract --file <备份文件> --key-file <主密钥环文件> \
        --entry <清单条目名> --output <绝对输出文件> \
        [--include-sensitive] [--operator <标识>] [--oplog <记录文件>] [--json]
  login-backup help | version

说明：
  create 使用 SQLite 在线备份接口生成一致快照，绝不复制定行中的主数据库文件；
         备份使用 AES-256-GCM 认证加密，主密钥环必须与备份文件分开保存。
  verify 用主密钥认证解密并校验清单、条目大小与 SHA-256；失败时明确区分
         校验失败（3）与解密失败（4）。
  info   只读取明文头部做结构与密文摘要检查，不声称认证通过。
  list   认证解密后列出格式/数据库版本（含 schema_history）、创建时间、条目
         清单与大小、完整性/认证状态与内容范围；只读，不执行备份内脚本。
  tables 列出受限查询目录（静态表白名单）与该备份实际可用字段；敏感字段明确标记。
  preview 对认证解包出的 SQLite 逻辑数据做受限只读预览：只允许白名单表、受控
         操作符（= != < <= > >= LIKE IN，AND 连接）、受控排序与行数上限；禁止
         任意 SQL；SQLite 连接使用 mode=ro + PRAGMA query_only。
  export 把受限查询结果导出为 CSV（UTF-8，防公式注入）或 JSON（纯数据编码）。
         输出文件必须使用绝对路径、父目录存在、默认不覆盖已有文件；高敏字段
         默认排除，--include-sensitive 才包含且落地后收紧文件权限（Windows
         显式 DACL、非 Windows 要求输出目录 0700）。CSV 文本单元格若以
         = + - @ 制表/回车开头会前置单引号；数值列保持数字。
  extract 逐项提取清单条目（附件 attachments/...、配置 config/... 等）；原始
         数据库条目包含认证秘密，必须显式 --include-sensitive 且输出受保护。
  离线查看/导出不启动身份服务器、不联网、不自动连接或写回生产数据库；每次
  export/extract 在输出目录追加 .login-backup-viewer-oplog.jsonl 本地操作记录
  （只含元数据，不含数据内容/过滤值/密钥）。该记录不能防止主机管理员删除。
  安全提示：加密备份本身安全，但备份期间输出目录会短暂出现明文数据库快照；
         多用户 Windows 请用 NTFS ACL（icacls）限制输出目录仅当前账户访问。

退出码：0 成功；1 执行失败；2 参数/用法错误；3 备份校验失败/不支持；
        4 解密失败；5 输出冲突或输出位置不安全；6 受限查询/高敏确认被拒绝；
        130 已取消（临时文件与不完整输出已清理）。`)
}

// localOperatorAuthorizer 是本地 CLI 的授权器：只允许显式指定的本地操作者执行
// 备份创建/取消。它的安全边界是操作系统文件权限（能读数据库与主密钥文件的人
// 本就能读取全部数据），不冒充远程认证或再次验证。
type localOperatorAuthorizer struct {
	operatorID string
}

// AuthorizeScope 实现 stats.Authorizer。
func (a localOperatorAuthorizer) AuthorizeScope(_ context.Context, caller account.Caller,
	permissionKey, scopeID string) (stats.ScopeGrant, error) {
	actor := caller.Actor()
	if actor.Type != audit.ActorLocalAdmin || actor.ID != a.operatorID {
		return stats.ScopeGrant{}, nil
	}
	if scopeID != backup.ScopeSystem {
		return stats.ScopeGrant{}, nil
	}
	switch permissionKey {
	case backup.PermissionCreate, backup.PermissionCancel:
		return stats.ScopeGrant{Allowed: true, AllData: true}, nil
	default:
		return stats.ScopeGrant{}, nil
	}
}

// createOutput 是 create 的 JSON 输出投影（不含秘密与备份载荷）。
type createOutput struct {
	BackupID       string               `json:"backup_id"`
	FileName       string               `json:"file_name"`
	Path           string               `json:"path"`
	FileSHA256     string               `json:"file_sha256"`
	FileSizeBytes  int64                `json:"file_size_bytes"`
	PayloadBytes   int64                `json:"payload_bytes"`
	CreatedAt      string               `json:"created_at"`
	Database       createDatabaseInfo   `json:"database"`
	Entries        []backup.EntryReport `json:"entries"`
	Content        backup.ContentMeta   `json:"content"`
	ManifestSHA256 string               `json:"manifest_sha256"`
	Attempts       int                  `json:"attempts"`
	DurationMS     int64                `json:"duration_ms"`
}

// createDatabaseInfo 是数据库版本/大小摘要。
type createDatabaseInfo struct {
	Engine        string `json:"engine"`
	SchemaVersion string `json:"schema_version"`
	VersionNumber int    `json:"version_number"`
	SizeBytes     int64  `json:"size_bytes"`
	FileSHA256    string `json:"file_sha256"`
}

// toCreateOutput 把服务结果转换为 JSON 投影。
func toCreateOutput(result backup.Result) createOutput {
	return createOutput{
		BackupID:      result.BackupID,
		FileName:      result.FileName,
		Path:          result.Path,
		FileSHA256:    result.SHA256,
		FileSizeBytes: result.SizeBytes,
		PayloadBytes:  result.PayloadBytes,
		CreatedAt:     result.CreatedAt.UTC().Format(time.RFC3339),
		Database: createDatabaseInfo{Engine: result.Database.Engine,
			SchemaVersion: result.Database.SchemaVersion,
			VersionNumber: result.Database.SchemaVersionNumber,
			SizeBytes:     result.Database.SizeBytes,
			FileSHA256:    result.Database.SHA256},
		Entries:        result.Entries,
		Content:        result.Content,
		ManifestSHA256: result.ManifestSHA256,
		Attempts:       result.Attempts,
		DurationMS:     result.Duration.Milliseconds(),
	}
}

// runCreate 实现 create 子命令。
func runCreate(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet(programName+" create", flag.ContinueOnError)
	flags.SetOutput(stderr)
	databasePath := flags.String("database", "", "目标 SQLite 数据库文件路径（必填）")
	keyFile := flags.String("key-file", "", "主密钥环文件路径（必填，必须与备份分开）")
	outputDir := flags.String("output", "", "备份输出受控目录（必填，必须已存在）")
	operator := flags.String("operator", "", "本地操作者标识（必填，可见 ASCII）")
	configPath := flags.String("config", "", "可选：要包含进备份的 YAML 配置路径")
	avatarDir := flags.String("avatars", "", "可选：头像受控存储目录")
	requestID := flags.String("request-id", "", "可选请求编号，用于关联审计")
	timeout := flags.Duration("timeout", backup.DefaultTimeout, "备份墙钟上限")
	showProgress := flags.Bool("progress", false, "向 stderr 输出进度")
	jsonOutput := flags.Bool("json", false, "以 JSON 输出结果")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "用法：login-backup create --database <path> --key-file <path> "+
			"--output <dir> --operator <id> [--config <path>] [--avatars <dir>] "+
			"[--request-id <id>] [--timeout 10m] [--progress] [--json]")
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
	if strings.TrimSpace(*databasePath) == "" || strings.TrimSpace(*keyFile) == "" ||
		strings.TrimSpace(*outputDir) == "" || strings.TrimSpace(*operator) == "" {
		fmt.Fprintln(stderr, "错误：--database、--key-file、--output、--operator 均必填")
		return ExitUsage
	}
	databaseAbs, err := filepath.Abs(*databasePath)
	if err != nil {
		fmt.Fprintln(stderr, "错误：数据库路径无效")
		return ExitUsage
	}
	keyAbs, err := filepath.Abs(*keyFile)
	if err != nil {
		fmt.Fprintln(stderr, "错误：主密钥文件路径无效")
		return ExitUsage
	}
	outputAbs, err := filepath.Abs(*outputDir)
	if err != nil {
		fmt.Fprintln(stderr, "错误：备份输出目录无效")
		return ExitUsage
	}
	databaseInfo, statErr := os.Stat(databaseAbs)
	if statErr != nil || !databaseInfo.Mode().IsRegular() {
		fmt.Fprintln(stderr, "错误：目标数据库不存在或不是普通文件（不会创建新数据库）")
		return ExitError
	}
	if keyInside(keyAbs, outputAbs) {
		fmt.Fprintln(stderr, "错误：主密钥文件不能放在备份输出目录内（主密钥必须与备份文件分离）")
		return ExitUsage
	}
	operatorID := strings.TrimSpace(*operator)
	caller, err := account.LocalBootstrapCaller(operatorID)
	if err != nil {
		fmt.Fprintln(stderr, "错误：本地操作者标识无效（只允许可见 ASCII 稳定标识）")
		return ExitUsage
	}
	// Ctrl+C 会取消备份；服务负责清理临时文件并写真实取消/失败审计。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	logger := slog.New(slog.NewTextHandler(stderr,
		&slog.HandlerOptions{Level: slog.LevelWarn}))

	store, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(databaseAbs))
	if err != nil {
		fmt.Fprintf(stderr, "错误：无法打开目标数据库（%s）\n", backup.CodeOf(err))
		return ExitError
	}
	defer func() { _ = store.Close() }()
	var schemaTables int
	if err := store.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_history'`).
		Scan(&schemaTables); err != nil || schemaTables == 0 {
		fmt.Fprintln(stderr, "错误：目标不是已完成迁移的 login 数据库")
		return ExitError
	}
	auditStore, err := auditsqlite.New(store)
	if err != nil {
		fmt.Fprintln(stderr, "错误：无法构造审计存储")
		return ExitError
	}
	recorder, err := audit.New(auditStore, audit.Options{Logger: logger})
	if err != nil {
		fmt.Fprintln(stderr, "错误：无法构造审计写入器")
		return ExitError
	}
	snapshotter, err := backup.NewSQLiteSnapshotter(store)
	if err != nil {
		fmt.Fprintln(stderr, "错误：无法构造 SQLite 在线备份适配器")
		return ExitError
	}
	keyProvider, err := secrets.NewFileProvider(keyAbs)
	if err != nil {
		fmt.Fprintln(stderr, "错误：主密钥文件路径无效")
		return ExitUsage
	}
	options := backup.Options{
		Snapshotter: snapshotter,
		Keyring:     keyProvider,
		Authorizer:  localOperatorAuthorizer{operatorID: operatorID},
		Audit:       recorder,
		OutputDir:   outputAbs,
		AppVersion:  login.CurrentBuildInfo().Version,
		Logger:      logger,
		Timeout:     *timeout,
	}
	if *avatarDir != "" {
		avatarAbs, absErr := filepath.Abs(*avatarDir)
		if absErr != nil {
			fmt.Fprintln(stderr, "错误：头像目录无效")
			return ExitUsage
		}
		avatarStorage, storageErr := avatar.NewLocalStorage(avatarAbs)
		if storageErr != nil {
			fmt.Fprintln(stderr, "错误：无法使用头像受控目录")
			return ExitUsage
		}
		source, sourceErr := backup.NewAvatarAttachmentSource(avatarStorage)
		if sourceErr != nil {
			fmt.Fprintln(stderr, "错误：无法构造头像附件源")
			return ExitError
		}
		options.Attachments = source
	}
	if *configPath != "" {
		configAbs, absErr := filepath.Abs(*configPath)
		if absErr != nil {
			fmt.Fprintln(stderr, "错误：配置文件路径无效")
			return ExitUsage
		}
		source, sourceErr := backup.NewFileConfigSource(configAbs, 0)
		if sourceErr != nil {
			fmt.Fprintln(stderr, "错误：配置文件必须是 YAML 普通文件")
			return ExitUsage
		}
		options.Config = source
	}
	if *showProgress {
		options.Progress = func(progress backup.Progress) {
			if progress.Total > 0 {
				fmt.Fprintf(stderr, "进度 %s：%d/%d\n", progress.Phase,
					progress.Done, progress.Total)
				return
			}
			fmt.Fprintf(stderr, "进度 %s\n", progress.Phase)
		}
	}
	fmt.Fprintln(stderr, "安全提示：.elnbak 为认证加密文件，但备份期间会在输出目录短暂写入明文数据库快照；")
	fmt.Fprintln(stderr, "  多用户 Windows 请用 NTFS ACL 仅授权当前账户与必要管理员，例如（cmd）：")
	fmt.Fprintf(stderr, "  icacls \"%s\" /inheritance:r /grant:r \"%%USERNAME%%:(OI)(CI)F\"\n", outputAbs)
	service, err := backup.New(options)
	if err != nil {
		fmt.Fprintf(stderr, "错误：备份配置无效（%s）\n", backup.CodeOf(err))
		return ExitUsage
	}
	result, err := service.Create(ctx, backup.CreateRequest{Caller: caller,
		RequestID: *requestID})
	if err != nil {
		fmt.Fprintf(stderr, "错误：备份失败（%s）：%s\n", backup.CodeOf(err), err)
		return ExitError
	}
	if *jsonOutput {
		encoded, encodeErr := json.MarshalIndent(toCreateOutput(result), "", "  ")
		if encodeErr != nil {
			fmt.Fprintln(stderr, "错误：结果序列化失败")
			return ExitError
		}
		fmt.Fprintln(stdout, string(encoded))
		return ExitOK
	}
	fmt.Fprintf(stdout, "备份完成：%s\n", result.FileName)
	fmt.Fprintf(stdout, "路径：%s\n", result.Path)
	fmt.Fprintf(stdout, "文件大小：%d 字节；载荷：%d 字节\n",
		result.SizeBytes, result.PayloadBytes)
	fmt.Fprintf(stdout, "文件 SHA-256：%s\n", result.SHA256)
	fmt.Fprintf(stdout, "数据库版本：%s（%d）；条目：%d；尝试：%d\n",
		result.Database.SchemaVersion, result.Database.SchemaVersionNumber,
		len(result.Entries), result.Attempts)
	if result.Content.Attachments.Status == backup.ContentIncluded {
		fmt.Fprintf(stdout, "附件：%d 个\n", result.Content.Attachments.Count)
	} else {
		fmt.Fprintf(stdout, "附件：%s\n", result.Content.Attachments.Status)
	}
	if result.Content.Config.Status == backup.ContentIncluded {
		fmt.Fprintln(stdout, "配置：已包含（YAML）")
	} else {
		fmt.Fprintf(stdout, "配置：%s\n", result.Content.Config.Status)
	}
	fmt.Fprintln(stdout, "主密钥环未包含在备份中，请单独保管；丢失将无法解密。")
	return ExitOK
}

// verifyOutput 是 verify 的 JSON 输出投影。
type verifyOutput struct {
	Authenticated   bool                     `json:"authenticated"`
	StructuralValid bool                     `json:"structural_valid"`
	Encrypted       bool                     `json:"encrypted"`
	BackupID        string                   `json:"backup_id"`
	CreatedAt       string                   `json:"created_at"`
	Host            string                   `json:"host"`
	AppVersion      string                   `json:"app_version"`
	Database        createDatabaseInfo       `json:"database"`
	Content         backup.ContentMeta       `json:"content"`
	Entries         []backup.EntryReport     `json:"entries"`
	FileSHA256      string                   `json:"file_sha256"`
	FileSizeBytes   int64                    `json:"file_size_bytes"`
	ManifestSHA256  string                   `json:"manifest_sha256"`
	Encryption      backup.EncryptionSummary `json:"encryption"`
}

// toVerifyOutput 转换校验报告。
func toVerifyOutput(report backup.VerifyReport) verifyOutput {
	return verifyOutput{
		Authenticated:   report.Authenticated,
		StructuralValid: report.StructuralValid,
		Encrypted:       report.Encrypted,
		BackupID:        report.BackupID,
		CreatedAt:       report.CreatedAt.UTC().Format(time.RFC3339),
		Host:            report.Host,
		AppVersion:      report.AppVersion,
		Database: createDatabaseInfo{Engine: report.Database.Engine,
			SchemaVersion: report.Database.SchemaVersion,
			VersionNumber: report.Database.SchemaVersionNumber,
			SizeBytes:     report.Database.SizeBytes,
			FileSHA256:    report.Database.SHA256},
		Content:        report.Content,
		Entries:        report.Entries,
		FileSHA256:     report.FileSHA256,
		FileSizeBytes:  report.FileSize,
		ManifestSHA256: report.ManifestSHA256,
		Encryption:     report.Encryption,
	}
}

// runVerify 实现 verify 子命令：需要主密钥环，完成认证解密与完整清单校验。
func runVerify(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet(programName+" verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	file := flags.String("file", "", "备份文件路径（必填）")
	keyFile := flags.String("key-file", "", "主密钥环文件路径（必填）")
	jsonOutput := flags.Bool("json", false, "以 JSON 输出结果")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "用法：login-backup verify --file <path> --key-file <path> [--json]")
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if flags.NArg() != 0 || strings.TrimSpace(*file) == "" ||
		strings.TrimSpace(*keyFile) == "" {
		fmt.Fprintln(stderr, "错误：--file 与 --key-file 必填")
		return ExitUsage
	}
	fileAbs, absErr := filepath.Abs(*file)
	if absErr != nil {
		fmt.Fprintln(stderr, "错误：备份文件路径无效")
		return ExitUsage
	}
	keyAbs, absErr := filepath.Abs(*keyFile)
	if absErr != nil {
		fmt.Fprintln(stderr, "错误：主密钥文件路径无效")
		return ExitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	provider, err := secrets.NewFileProvider(keyAbs)
	if err != nil {
		fmt.Fprintln(stderr, "错误：主密钥文件路径无效")
		return ExitUsage
	}
	ring, err := secrets.LoadKeyring(ctx, provider)
	if err != nil {
		fmt.Fprintf(stderr, "错误：无法加载主密钥环（%s）\n", backup.CodeOf(err))
		return ExitDecryptFailed
	}
	report, err := backup.VerifyFile(ctx, fileAbs, ring)
	if err != nil {
		return reportVerifyError(stderr, err)
	}
	if *jsonOutput {
		encoded, encodeErr := json.MarshalIndent(toVerifyOutput(report), "", "  ")
		if encodeErr != nil {
			fmt.Fprintln(stderr, "错误：结果序列化失败")
			return ExitError
		}
		fmt.Fprintln(stdout, string(encoded))
		return ExitOK
	}
	fmt.Fprintln(stdout, "校验通过：认证解密成功，清单与全部条目摘要一致。")
	fmt.Fprintf(stdout, "备份编号：%s\n", report.BackupID)
	fmt.Fprintf(stdout, "创建时间：%s；主机：%s；应用版本：%s\n",
		report.CreatedAt.UTC().Format(time.RFC3339), report.Host, report.AppVersion)
	fmt.Fprintf(stdout, "数据库版本：%s（%d）；文件大小：%d 字节\n",
		report.Database.SchemaVersion, report.Database.SchemaVersionNumber,
		report.FileSize)
	fmt.Fprintf(stdout, "文件 SHA-256：%s\n", report.FileSHA256)
	fmt.Fprintf(stdout, "条目：%d\n", len(report.Entries))
	for _, entry := range report.Entries {
		fmt.Fprintf(stdout, "  - [%s] %s（%d 字节）%s\n", entry.Kind, entry.Name,
			entry.SizeBytes, entry.SHA256)
	}
	if report.Content.Attachments.Status == backup.ContentIncluded {
		fmt.Fprintf(stdout, "附件：%d 个\n", report.Content.Attachments.Count)
	}
	if report.Content.Config.Status == backup.ContentIncluded {
		fmt.Fprintln(stdout, "配置：已包含（YAML）")
	}
	fmt.Fprintln(stdout, "注意：本工具只校验文件，不执行恢复，不连接生产数据库。")
	return ExitOK
}

// reportVerifyError 把校验错误映射为稳定退出码并输出安全文本。
func reportVerifyError(stderr io.Writer, err error) int {
	code := backup.CodeOf(err)
	fmt.Fprintf(stderr, "错误：备份校验失败（%s）：%s\n", code, err)
	switch {
	case errors.Is(err, backup.ErrDecryptFailed):
		return ExitDecryptFailed
	case errors.Is(err, backup.ErrIntegrityFailed),
		errors.Is(err, backup.ErrFormatInvalid),
		errors.Is(err, backup.ErrVersionUnsupported):
		return ExitVerifyFailed
	default:
		return ExitError
	}
}

// runInfo 实现 info 子命令：无密钥结构检查，明确不声称认证通过。
func runInfo(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet(programName+" info", flag.ContinueOnError)
	flags.SetOutput(stderr)
	file := flags.String("file", "", "备份文件路径（必填）")
	jsonOutput := flags.Bool("json", false, "以 JSON 输出结果")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "用法：login-backup info --file <path> [--json]")
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if flags.NArg() != 0 || strings.TrimSpace(*file) == "" {
		fmt.Fprintln(stderr, "错误：--file 必填")
		return ExitUsage
	}
	fileAbs, absErr := filepath.Abs(*file)
	if absErr != nil {
		fmt.Fprintln(stderr, "错误：备份文件路径无效")
		return ExitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	report, err := backup.InspectFile(ctx, fileAbs)
	if err != nil {
		return reportVerifyError(stderr, err)
	}
	if *jsonOutput {
		encoded, encodeErr := json.MarshalIndent(toVerifyOutput(report), "", "  ")
		if encodeErr != nil {
			fmt.Fprintln(stderr, "错误：结果序列化失败")
			return ExitError
		}
		fmt.Fprintln(stdout, string(encoded))
		return ExitOK
	}
	fmt.Fprintln(stdout, "结构检查通过（未认证解密；认证校验请使用 verify 并提供主密钥）。")
	fmt.Fprintf(stdout, "格式版本：%d；加密：%s/%s\n", report.FormatVersion,
		report.Encryption.Algorithm, report.Encryption.Format)
	fmt.Fprintf(stdout, "备份编号：%s；创建时间：%s\n", report.BackupID,
		report.CreatedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(stdout, "主机：%s；应用版本：%s\n", report.Host, report.AppVersion)
	fmt.Fprintf(stdout, "数据库版本：%s（%d）；文件大小：%d 字节\n",
		report.Database.SchemaVersion, report.Database.SchemaVersionNumber,
		report.FileSize)
	fmt.Fprintf(stdout, "清单条目数：认证加密内，需密钥；内容范围：附件=%s 配置=%s\n",
		report.Content.Attachments.Status, report.Content.Config.Status)
	fmt.Fprintf(stdout, "密文 SHA-256：%s\n", report.CiphertextSHA256)
	return ExitOK
}

// keyInside 报告主密钥文件是否位于备份输出目录内（用于阻止主密钥与备份并置）。
func keyInside(keyPath, outputDir string) bool {
	relative, err := filepath.Rel(outputDir, keyPath)
	if err != nil {
		return false
	}
	relative = filepath.ToSlash(relative)
	return relative != ".." && !strings.HasPrefix(relative, "../")
}
