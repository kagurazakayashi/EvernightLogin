// 本文件实现 loginctl 的受控本地备份恢复命令（步骤 82）：
//
//	restore-preflight       恢复前预演（只读，不修改数据库/不进入维护）
//	restore-apply           维护模式恢复（预演→回退备份→暂存验证→切换→凭证失效→审计合并）
//	maintenance-enter       进入维护状态（阻止新写入，供手工维护前使用）
//	maintenance-exit        退出维护状态（存在未完成恢复时必须 --force）
//	restore-merge-audit     独立重试把库外恢复审计合并进数据库
//	restore-disposition     查看最近一次恢复后的暂停/取消清单
//	restore-review          标记恢复处置清单已人工审查
//	restore-reenable        受控重新启用旧调度计划/Webhook 端点
//
// 信任边界：只允许在本地服务器上、由操作系统管理员运行；不连接网络、不启动后台
// 服务、不提供匿名远程入口。恢复要求宿主已停止服务或允许排他访问数据库（Windows
// 上打开中的数据库文件无法改名，命令会明确失败并保持维护状态）。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/avatar"
	"github.com/kagurazakayashi/EvernightLogin/internal/backup"
	"github.com/kagurazakayashi/EvernightLogin/internal/restore"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	appmigrations "github.com/kagurazakayashi/EvernightLogin/migrations"
)

// restoreConfirmToken 是执行恢复所需的显式确认词（本地管理员输入，不是秘密）。
const restoreConfirmToken = "RESTORE"

// 恢复相关稳定退出码：0 成功；1 执行失败/预演不可恢复；2 参数/用法错误；
// 3 操作者未确认（未做任何修改）。
const restoreExitCancelled = 3

// localRestoreAuthorizer 是本地 CLI 授权器：只放行显式本地操作者的恢复与回退备份
// 创建/取消；安全边界是操作系统文件权限，不冒充远程认证。
type localRestoreAuthorizer struct {
	operatorID string
}

// AuthorizeScope 实现 stats.Authorizer。
func (a localRestoreAuthorizer) AuthorizeScope(_ context.Context, caller account.Caller,
	permissionKey, scopeID string) (stats.ScopeGrant, error) {
	actor := caller.Actor()
	if actor.Type != audit.ActorLocalAdmin || actor.ID != a.operatorID {
		return stats.ScopeGrant{}, nil
	}
	if scopeID != restore.ScopeSystem {
		return stats.ScopeGrant{}, nil
	}
	switch permissionKey {
	case restore.PermissionRestore, backup.PermissionCreate, backup.PermissionCancel:
		return stats.ScopeGrant{Allowed: true, AllData: true}, nil
	default:
		return stats.ScopeGrant{}, nil
	}
}

// restoreCLIConfig 是恢复命令共享的本地路径与身份参数。
type restoreCLIConfig struct {
	database     string
	stateDir     string
	keyFile      string
	backupOutput string
	attachments  string
	configPath   string
	operator     string
	requestID    string
	stdout       io.Writer
	stderr       io.Writer
}

// registerCommonFlags 注册所有恢复命令共享的 flag。
func (config *restoreCLIConfig) registerCommonFlags(flags *flag.FlagSet, requireBackup bool) {
	flags.StringVar(&config.database, "database", "", "目标 SQLite 数据库文件路径（必填）")
	flags.StringVar(&config.stateDir, "state-dir", "", "库外恢复状态目录（必填，不能是数据库目录）")
	flags.StringVar(&config.keyFile, "key-file", "", "主密钥环文件路径（预演/恢复必填）")
	flags.StringVar(&config.backupOutput, "backup-output", "",
		"回退备份受控输出目录（预演/恢复必填，必须已存在）")
	flags.StringVar(&config.attachments, "avatars", "", "可选：头像等附件受控目录")
	flags.StringVar(&config.configPath, "config", "", "可选：当前 YAML 配置文件路径（用于回退备份）")
	flags.StringVar(&config.operator, "operator", "", "本地应急管理员标识（必填，可见 ASCII）")
	flags.StringVar(&config.requestID, "request-id", "", "可选关联编号")
}

// validate 校验共享参数并返回绝对路径。
func (config *restoreCLIConfig) validate(requireBackup bool) error {
	if strings.TrimSpace(config.database) == "" || strings.TrimSpace(config.stateDir) == "" ||
		strings.TrimSpace(config.operator) == "" {
		return fmt.Errorf("--database、--state-dir、--operator 均必填")
	}
	if requireBackup {
		if strings.TrimSpace(config.keyFile) == "" || strings.TrimSpace(config.backupOutput) == "" {
			return fmt.Errorf("--key-file 与 --backup-output 必填")
		}
	}
	return nil
}

// validateWithKey 校验共享参数并要求主密钥环：状态/审计锚点由主密钥 HMAC 保护，
// 任何读写库外状态命令（维护进出/处置/审查/重新启用/审计合并/初始化）都必须提供
// 真实可用的 --key-file；缺少 keyring 时不允许降级为无校验模式。
func (config *restoreCLIConfig) validateWithKey() error {
	if err := config.validate(false); err != nil {
		return err
	}
	if strings.TrimSpace(config.keyFile) == "" {
		return fmt.Errorf("--key-file 必填（库外维护状态由主密钥 HMAC 保护，不能无密钥降级）")
	}
	return nil
}

// absolutePaths 把可选路径转换为绝对路径（空值保持空）。
func (config *restoreCLIConfig) absolutePaths() error {
	paths := []struct {
		label string
		value *string
	}{
		{"--database", &config.database},
		{"--state-dir", &config.stateDir},
		{"--operator", &config.operator},
	}
	for _, item := range paths {
		trimmed := strings.TrimSpace(*item.value)
		if trimmed == "" {
			return fmt.Errorf("%s 不能为空", item.label)
		}
		*item.value = trimmed
	}
	for _, item := range []struct {
		label string
		value *string
	}{
		{"--key-file", &config.keyFile},
		{"--backup-output", &config.backupOutput},
		{"--avatars", &config.attachments},
		{"--config", &config.configPath},
	} {
		trimmed := strings.TrimSpace(*item.value)
		if trimmed == "" {
			continue
		}
		absolute, err := filepath.Abs(trimmed)
		if err != nil {
			return fmt.Errorf("%s 路径无效", item.label)
		}
		*item.value = absolute
	}
	for _, item := range []struct {
		label string
		value *string
	}{
		{"--database", &config.database},
		{"--state-dir", &config.stateDir},
	} {
		absolute, err := filepath.Abs(*item.value)
		if err != nil {
			return fmt.Errorf("%s 路径无效", item.label)
		}
		*item.value = absolute
	}
	return nil
}

// newService 构造真实恢复服务与本地调用者。requireKey 决定是否要求主密钥环文件
// （仅预演/恢复需要；维护退出/处置/合并审计不需要解密备份）。
func (config *restoreCLIConfig) newService(requireKey bool) (*restore.Service, account.Caller, error) {
	caller, err := account.LocalBootstrapCaller(config.operator)
	if err != nil {
		return nil, account.Caller{}, fmt.Errorf("本地操作者标识无效（只允许可见 ASCII 稳定标识）")
	}
	migrations, err := loadRestoreMigrations()
	if err != nil {
		return nil, account.Caller{}, fmt.Errorf("加载内嵌迁移失败")
	}
	logger := slog.New(slog.NewTextHandler(config.stderr,
		&slog.HandlerOptions{Level: slog.LevelWarn}))
	provider := secrets.Provider(nil)
	if requireKey {
		fileProvider, providerErr := secrets.NewFileProvider(config.keyFile)
		if providerErr != nil {
			return nil, account.Caller{}, fmt.Errorf("主密钥文件路径无效")
		}
		provider = fileProvider
	} else {
		provider = secrets.ProviderFunc(func(context.Context) ([]byte, error) {
			return nil, fmt.Errorf("该命令不解密备份，未配置主密钥环")
		})
	}
	authorizer := localRestoreAuthorizer{operatorID: config.operator}
	options := restore.Options{
		DatabasePath:    config.database,
		StateDir:        config.stateDir,
		Migrations:      migrations,
		Keyring:         provider,
		BackupOutputDir: config.backupOutput,
		AttachmentsDir:  config.attachments,
		Authorizer:      authorizer,
		Logger:          logger,
		RollbackBackup: func(ctx context.Context, caller account.Caller,
			requestID string) (backup.Result, error) {
			return createCLIRollbackBackup(ctx, config, authorizer, caller, requestID)
		},
	}
	if options.BackupOutputDir == "" {
		// 不创建回退备份的命令仍需通过构造校验：指向数据库目录的兄弟路径。
		options.BackupOutputDir = filepath.Dir(config.database)
	}
	service, err := restore.New(options)
	if err != nil {
		return nil, account.Caller{}, err
	}
	return service, caller, nil
}

// loadRestoreMigrations 加载内嵌迁移集合。
func loadRestoreMigrations() ([]migrate.Migration, error) {
	return migrate.LoadMigrations(appmigrations.SQLite)
}

// createCLIRollbackBackup 打开数据库并创建一次真实回退加密备份（不覆盖用户原始备份）。
func createCLIRollbackBackup(ctx context.Context, config *restoreCLIConfig,
	authorizer localRestoreAuthorizer, caller account.Caller,
	requestID string) (backup.Result, error) {
	store, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(config.database))
	if err != nil {
		return backup.Result{}, fmt.Errorf("无法打开数据库创建回退备份")
	}
	defer func() { _ = store.Close() }()
	auditStore, err := auditsqlite.New(store)
	if err != nil {
		return backup.Result{}, fmt.Errorf("无法构造审计存储")
	}
	recorder, err := audit.New(auditStore, audit.Options{
		Logger: slog.New(slog.NewTextHandler(config.stderr,
			&slog.HandlerOptions{Level: slog.LevelWarn})),
	})
	if err != nil {
		return backup.Result{}, fmt.Errorf("无法构造审计写入器")
	}
	snapshotter, err := backup.NewSQLiteSnapshotter(store)
	if err != nil {
		return backup.Result{}, fmt.Errorf("无法构造 SQLite 快照器")
	}
	fileProvider, err := secrets.NewFileProvider(config.keyFile)
	if err != nil {
		return backup.Result{}, fmt.Errorf("主密钥文件路径无效")
	}
	backupOptions := backup.Options{
		Snapshotter: snapshotter,
		Keyring:     fileProvider,
		Authorizer:  authorizer,
		Audit:       recorder,
		OutputDir:   config.backupOutput,
		AppVersion:  login.CurrentBuildInfo().Version,
	}
	if config.attachments != "" {
		storage, storageErr := avatar.NewLocalStorage(config.attachments)
		if storageErr != nil {
			return backup.Result{}, fmt.Errorf("附件目录无效")
		}
		source, sourceErr := backup.NewAvatarAttachmentSource(storage)
		if sourceErr != nil {
			return backup.Result{}, fmt.Errorf("无法构造附件源")
		}
		backupOptions.Attachments = source
	}
	if config.configPath != "" {
		source, sourceErr := backup.NewFileConfigSource(config.configPath, 0)
		if sourceErr != nil {
			return backup.Result{}, fmt.Errorf("配置文件无效")
		}
		backupOptions.Config = source
	}
	service, err := backup.New(backupOptions)
	if err != nil {
		return backup.Result{}, err
	}
	return service.Create(ctx, backup.CreateRequest{Caller: caller, RequestID: requestID})
}

// runRestorePreflight 实现 restore-preflight：只读预演并输出结构化结果。
func runRestorePreflight(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("loginctl restore-preflight", flag.ContinueOnError)
	flags.SetOutput(stderr)
	config := &restoreCLIConfig{stdout: stdout, stderr: stderr}
	config.registerCommonFlags(flags, true)
	backupPath := flags.String("backup", "", "待恢复备份文件路径（必填）")
	jsonOutput := flags.Bool("json", false, "以 JSON 输出预演结果")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "用法：loginctl restore-preflight --database <path> --state-dir <dir> \\")
		fmt.Fprintln(stderr, "        --key-file <path> --backup <file> --backup-output <dir> \\")
		fmt.Fprintln(stderr, "        --operator <id> [--avatars <dir>] [--config <file>] [--json]")
	}
	if err := flags.Parse(args); err != nil {
		return ExitUsage
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "错误：存在多余参数")
		return ExitUsage
	}
	if err := config.validate(true); err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return ExitUsage
	}
	if strings.TrimSpace(*backupPath) == "" {
		fmt.Fprintln(stderr, "错误：--backup 必填")
		return ExitUsage
	}
	if err := config.absolutePaths(); err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return ExitUsage
	}
	backupAbsolute, err := filepath.Abs(*backupPath)
	if err != nil {
		fmt.Fprintln(stderr, "错误：备份文件路径无效")
		return ExitUsage
	}
	service, caller, err := config.newService(true)
	if err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", restore.CodeOf(err))
		return ExitError
	}
	defer func() { _ = service.Close() }()
	rehearsal, err := service.Rehearse(context.Background(), restore.Request{
		Caller: caller, BackupPath: backupAbsolute, Reason: "本地 CLI 恢复预演",
		RequestID: config.requestID})
	if err != nil {
		fmt.Fprintf(stderr, "错误：预演失败（%s）\n", restore.CodeOf(err))
		return ExitError
	}
	if *jsonOutput {
		encoded, encodeErr := json.MarshalIndent(rehearsal, "", "  ")
		if encodeErr != nil {
			fmt.Fprintln(stderr, "错误：结果序列化失败")
			return ExitError
		}
		fmt.Fprintln(stdout, string(encoded))
	} else {
		printRehearsal(stdout, rehearsal)
	}
	if !rehearsal.Restorable {
		return ExitError
	}
	return ExitOK
}

// printRehearsal 输出预演摘要（逐项检查、影响范围与容量）。
func printRehearsal(out io.Writer, rehearsal restore.Rehearsal) {
	fmt.Fprintf(out, "恢复预演：%s\n", verdictText(rehearsal.Restorable))
	fmt.Fprintf(out, "备份编号：%s；文件 SHA-256：%s\n",
		rehearsal.Backup.BackupID, rehearsal.Backup.FileSHA256)
	fmt.Fprintf(out, "备份数据库版本：%s；当前程序版本：%s；库外代际：%d；库内代际：%d\n",
		rehearsal.Backup.SchemaVersion, rehearsal.CurrentSchema,
		rehearsal.ExternalGeneration, rehearsal.DatabaseGeneration)
	for _, check := range rehearsal.Checks {
		fmt.Fprintf(out, "  [%s] %s：%s\n", check.Status, check.Label, check.Detail)
	}
	if len(rehearsal.BlockingReasons) > 0 {
		fmt.Fprintln(out, "阻塞原因：")
		for _, reason := range rehearsal.BlockingReasons {
			fmt.Fprintf(out, "  - %s\n", reason)
		}
	}
	for _, warning := range rehearsal.Warnings {
		fmt.Fprintf(out, "注意：%s\n", warning)
	}
	fmt.Fprintf(out, "影响范围：会话 %d、刷新族 %d、授权码 %d、恢复代码 %d、"+
		"验证/找回/换绑链接 %d、扫码请求 %d、一次性凭证 %d、签名密钥 %d\n",
		rehearsal.Impact.Sessions, rehearsal.Impact.RefreshFamilies,
		rehearsal.Impact.AuthorizationCodes, rehearsal.Impact.RecoveryCodes,
		rehearsal.Impact.VerificationTickets+rehearsal.Impact.PasswordResets+
			rehearsal.Impact.EmailChanges,
		rehearsal.Impact.QRLoginRequests, rehearsal.Impact.OneTimeCredentials,
		rehearsal.Impact.SigningKeys)
	fmt.Fprintf(out, "默认暂停：调度计划 %d、Webhook %d、在途任务 %d、待发邮件 %d、通知 %d\n",
		rehearsal.Impact.EnabledSchedules, rehearsal.Impact.ActiveWebhooks,
		rehearsal.Impact.PendingJobs, rehearsal.Impact.PendingMails,
		rehearsal.Impact.PendingNotifications)
	for _, consequence := range rehearsal.Consequences {
		fmt.Fprintf(out, "  - %s\n", consequence)
	}
}

// verdictText 把预演结论翻译为直白中文。
func verdictText(restorable bool) string {
	if restorable {
		return "可恢复（执行前仍需显式确认）"
	}
	return "不可恢复（存在阻塞原因，未做任何修改）"
}

// runRestoreApply 实现 restore-apply：维护模式执行完整恢复。
func runRestoreApply(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("loginctl restore-apply", flag.ContinueOnError)
	flags.SetOutput(stderr)
	config := &restoreCLIConfig{stdout: stdout, stderr: stderr}
	config.registerCommonFlags(flags, true)
	backupPath := flags.String("backup", "", "待恢复备份文件路径（必填）")
	reason := flags.String("reason", "", "恢复原因（必填，最多 500 字符）")
	confirm := flags.String("confirm", "", "显式确认：必须精确输入 RESTORE")
	serviceStopped := flags.Bool("service-stopped", false,
		"确认 login 服务已停止或已处于维护状态（必填，降低运行中执行分脑风险）")
	jsonOutput := flags.Bool("json", false, "以 JSON 输出结果")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "用法：loginctl restore-apply --database <path> --state-dir <dir> \\")
		fmt.Fprintln(stderr, "        --key-file <path> --backup <file> --backup-output <dir> \\")
		fmt.Fprintln(stderr, "        --operator <id> --reason <原因> --confirm RESTORE \\")
		fmt.Fprintln(stderr, "        --service-stopped \\")
		fmt.Fprintln(stderr, "        [--avatars <dir>] [--config <file>] [--json]")
	}
	if err := flags.Parse(args); err != nil {
		return ExitUsage
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "错误：存在多余参数")
		return ExitUsage
	}
	if err := config.validate(true); err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return ExitUsage
	}
	if strings.TrimSpace(*backupPath) == "" || strings.TrimSpace(*reason) == "" {
		fmt.Fprintln(stderr, "错误：--backup 与 --reason 必填")
		return ExitUsage
	}
	if !*serviceStopped {
		fmt.Fprintln(stderr, "错误：必须显式传 --service-stopped 确认服务已停止或处于维护状态；")
		fmt.Fprintln(stderr, "  运行中执行恢复会因数据库文件占用而失败，且存在分脑导致写入丢失的风险。")
		return ExitUsage
	}
	if strings.TrimSpace(*confirm) != restoreConfirmToken {
		fmt.Fprintln(stdout, "已取消：未确认恢复，未对数据做任何修改。")
		return restoreExitCancelled
	}
	if err := config.absolutePaths(); err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return ExitUsage
	}
	backupAbsolute, err := filepath.Abs(*backupPath)
	if err != nil {
		fmt.Fprintln(stderr, "错误：备份文件路径无效")
		return ExitUsage
	}
	service, caller, err := config.newService(true)
	if err != nil {
		fmt.Fprintf(stderr, "错误：%v（%s）\n", restore.CodeOf(err), err)
		return ExitError
	}
	defer func() { _ = service.Close() }()
	fmt.Fprintln(stderr, "警告：恢复会进入维护状态并整体替换数据库；请确认已停止服务并已备份。")
	ctx := context.Background()
	// Ctrl+C 取消：切换前取消零副作用；切换后由实现回退数据库并保持维护。
	request := restore.Request{Caller: caller, BackupPath: backupAbsolute,
		Reason: *reason, RequestID: config.requestID}
	result, err := service.Execute(ctx, request)
	if err != nil {
		fmt.Fprintf(stderr, "错误：恢复失败（%s）：%v\n", restore.CodeOf(err), err)
		fmt.Fprintln(stderr, "安全状态：失败时默认保持维护状态，不会自动对外放行；")
		fmt.Fprintln(stderr, "  请检查日志与库外状态文件，必要时执行 maintenance-exit 显式处置。")
		return ExitError
	}
	if *jsonOutput {
		encoded, encodeErr := json.MarshalIndent(result, "", "  ")
		if encodeErr != nil {
			fmt.Fprintln(stderr, "错误：结果序列化失败")
			return ExitError
		}
		fmt.Fprintln(stdout, string(encoded))
		return ExitOK
	}
	fmt.Fprintf(stdout, "恢复完成：%s\n", result.RestoreID)
	fmt.Fprintf(stdout, "  新恢复代际：%d；备份编号：%s\n", result.Generation, result.Backup.BackupID)
	fmt.Fprintf(stdout, "  已失效凭证：会话 %d、刷新族 %d、授权码 %d、恢复代码 %d、"+
		"验证/找回链接 %d、扫码请求 %d、签名密钥 %d（合计 %d）\n",
		result.Revoked.Sessions, result.Revoked.RefreshFamilies,
		result.Revoked.AuthorizationCodes, result.Revoked.RecoveryCodes,
		result.Revoked.VerificationTickets+result.Revoked.PasswordResets+
			result.Revoked.EmailChanges,
		result.Revoked.QRLoginRequests, result.Revoked.SigningKeys,
		result.Revoked.TotalDeleted)
	fmt.Fprintf(stdout, "  默认暂停：调度计划 %d、Webhook 端点 %d、Webhook 投递 %d、任务 %d、邮件 %d、通知 %d\n",
		result.Paused.Schedules, result.Paused.Webhooks, result.Paused.WebhookDeliveries,
		result.Paused.Jobs, result.Paused.MailDeliveries, result.Paused.Notifications)
	fmt.Fprintf(stdout, "  回退备份：%s（SHA-256 %s）\n",
		result.RollbackBackupPath, result.RollbackBackupSHA256)
	if result.PendingConfigPath != "" {
		fmt.Fprintf(stdout, "  配置快照未自动应用，待审查文件：%s\n", result.PendingConfigPath)
	}
	fmt.Fprintf(stdout, "  恢复审计已合并 %d 条；维护状态已退出。\n", result.AuditMerged)
	fmt.Fprintln(stdout, "  请立即审查恢复后处置清单（restore-disposition），再受控重新启用计划/Webhook。")
	return ExitOK
}

// runRestoreInitState 实现 restore-init-state：显式初始化库外恢复状态（受 HMAC 保护），
// 缺失状态不会静默重建，必须由本地应急管理员确认后创建。
func runRestoreInitState(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("loginctl restore-init-state", flag.ContinueOnError)
	flags.SetOutput(stderr)
	config := &restoreCLIConfig{stdout: stdout, stderr: stderr}
	config.registerCommonFlags(flags, true)
	reason := flags.String("reason", "", "初始化原因（必填）")
	confirm := flags.String("confirm", "", "显式确认：必须精确输入 RESTORE")
	adoptJournal := flags.Bool("adopt-journal", false,
		"受控破窗：状态文件丢失但库外审计日志有历史事件时，读取日志重算锚点（高风险，需确认）")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "用法：loginctl restore-init-state --database <path> --state-dir <dir> \\")
		fmt.Fprintln(stderr, "        --key-file <path>（必填） --operator <id> --reason <原因> --confirm RESTORE")
		fmt.Fprintln(stderr, "        [--backup-output <dir>]（可选） [--adopt-journal]")
		fmt.Fprintln(stderr, "  --adopt-journal 是受控破窗：状态文件丢失且库外审计日志已有历史事件时默认拒绝初始化；")
		fmt.Fprintln(stderr, "  仅在人工核验日志后显式使用：root/本地管理员 --confirm RESTORE，将信任现有日志并重算锚点（高风险）。")
	}
	if err := flags.Parse(args); err != nil {
		return ExitUsage
	}
	if flags.NArg() != 0 || strings.TrimSpace(*reason) == "" {
		fmt.Fprintln(stderr, "错误：存在多余参数或缺少 --reason")
		return ExitUsage
	}
	if err := config.validateWithKey(); err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return ExitUsage
	}
	if strings.TrimSpace(*confirm) != restoreConfirmToken {
		fmt.Fprintln(stdout, "已取消：未确认初始化，未创建任何状态。")
		return restoreExitCancelled
	}
	if err := config.absolutePaths(); err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return ExitUsage
	}
	service, caller, err := config.newService(true)
	if err != nil {
		fmt.Fprintf(stderr, "错误：%v（%v）\n", restore.CodeOf(err), err)
		return ExitError
	}
	defer func() { _ = service.Close() }()
	if err := service.InitState(context.Background(), restore.InitStateRequest{
		Caller: caller, Reason: *reason, RequestID: config.requestID,
		AdoptJournal: *adoptJournal}); err != nil {
		fmt.Fprintf(stderr, "错误：初始化库外恢复状态失败（%s）：%v\n",
			restore.CodeOf(err), err)
		return ExitError
	}
	fmt.Fprintln(stdout, "库外恢复状态已初始化（HMAC 保护，代际 0）。")
	return ExitOK
}

// runMaintenanceEnter 实现 maintenance-enter。
func runMaintenanceEnter(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("loginctl maintenance-enter", flag.ContinueOnError)
	flags.SetOutput(stderr)
	config := &restoreCLIConfig{stdout: stdout, stderr: stderr}
	config.registerCommonFlags(flags, false)
	reason := flags.String("reason", "", "进入维护的原因（必填）")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "用法：loginctl maintenance-enter --database <path> --state-dir <dir> \\")
		fmt.Fprintln(stderr, "        --key-file <path>（必填，状态 HMAC） --operator <id> --reason <原因> [--request-id <id>]")
	}
	if err := flags.Parse(args); err != nil {
		return ExitUsage
	}
	if flags.NArg() != 0 || strings.TrimSpace(*reason) == "" {
		fmt.Fprintln(stderr, "错误：存在多余参数或缺少 --reason")
		return ExitUsage
	}
	if err := config.validateWithKey(); err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return ExitUsage
	}
	if err := config.absolutePaths(); err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return ExitUsage
	}
	service, caller, err := config.newService(true)
	if err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", restore.CodeOf(err))
		return ExitError
	}
	defer func() { _ = service.Close() }()
	if err := service.EnterMaintenance(context.Background(), restore.MaintenanceRequest{
		Caller: caller, Reason: *reason, RequestID: config.requestID}); err != nil {
		fmt.Fprintf(stderr, "错误：进入维护状态失败（%s）：%v\n", restore.CodeOf(err), err)
		return ExitError
	}
	fmt.Fprintln(stdout, "已进入维护状态：新的写入被拒绝，在途写入已尽力收束。")
	fmt.Fprintln(stdout, "处置完成后请执行 loginctl maintenance-exit 显式退出。")
	return ExitOK
}

// runMaintenanceExit 实现 maintenance-exit。
func runMaintenanceExit(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("loginctl maintenance-exit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	config := &restoreCLIConfig{stdout: stdout, stderr: stderr}
	config.registerCommonFlags(flags, false)
	reason := flags.String("reason", "", "退出维护的原因（必填）")
	force := flags.Bool("force", false, "存在未完成恢复尝试时仍显式退出（高风险，需明确确认）")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "用法：loginctl maintenance-exit --database <path> --state-dir <dir> \\")
		fmt.Fprintln(stderr, "        --key-file <path>（必填，状态 HMAC） --operator <id> --reason <原因> [--force]")
	}
	if err := flags.Parse(args); err != nil {
		return ExitUsage
	}
	if flags.NArg() != 0 || strings.TrimSpace(*reason) == "" {
		fmt.Fprintln(stderr, "错误：存在多余参数或缺少 --reason")
		return ExitUsage
	}
	if *force {
		fmt.Fprintln(stderr, "警告：--force 会在存在未完成恢复尝试时退出维护；"+
			"旧凭证可能未按恢复规则失效，请确认已人工核查。")
	}
	if err := config.validateWithKey(); err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return ExitUsage
	}
	if err := config.absolutePaths(); err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return ExitUsage
	}
	service, caller, err := config.newService(true)
	if err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", restore.CodeOf(err))
		return ExitError
	}
	defer func() { _ = service.Close() }()
	if err := service.ExitMaintenance(context.Background(), restore.MaintenanceRequest{
		Caller: caller, Reason: *reason, RequestID: config.requestID,
		Force: *force}); err != nil {
		fmt.Fprintf(stderr, "错误：退出维护状态失败（%s）：%v\n", restore.CodeOf(err), err)
		return ExitError
	}
	fmt.Fprintln(stdout, "已退出维护状态；库外恢复审计已尽力合并。")
	return ExitOK
}

// runRestoreMergeAudit 实现 restore-merge-audit。
func runRestoreMergeAudit(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("loginctl restore-merge-audit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	config := &restoreCLIConfig{stdout: stdout, stderr: stderr}
	config.registerCommonFlags(flags, false)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "用法：loginctl restore-merge-audit --database <path> "+
			"--state-dir <dir> --key-file <path>（必填） --operator <id> [--request-id <id>]")
	}
	if err := flags.Parse(args); err != nil {
		return ExitUsage
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "错误：存在多余参数")
		return ExitUsage
	}
	if err := config.validateWithKey(); err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return ExitUsage
	}
	if err := config.absolutePaths(); err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return ExitUsage
	}
	service, caller, err := config.newService(true)
	if err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", restore.CodeOf(err))
		return ExitError
	}
	defer func() { _ = service.Close() }()
	merged, err := service.MergeAudit(context.Background(), caller)
	if err != nil {
		fmt.Fprintf(stderr, "错误：恢复审计合并失败（%s）：%v\n", restore.CodeOf(err), err)
		return ExitError
	}
	fmt.Fprintf(stdout, "恢复审计合并完成：新增 %d 条（库外日志完整保留）。\n", merged)
	return ExitOK
}

// runRestoreDisposition 实现 restore-disposition。
func runRestoreDisposition(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("loginctl restore-disposition", flag.ContinueOnError)
	flags.SetOutput(stderr)
	config := &restoreCLIConfig{stdout: stdout, stderr: stderr}
	config.registerCommonFlags(flags, false)
	jsonOutput := flags.Bool("json", false, "以 JSON 输出处置清单")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "用法：loginctl restore-disposition --database <path> "+
			"--state-dir <dir> --key-file <path>（必填） --operator <id> [--json]")
	}
	if err := flags.Parse(args); err != nil {
		return ExitUsage
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "错误：存在多余参数")
		return ExitUsage
	}
	if err := config.validateWithKey(); err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return ExitUsage
	}
	if err := config.absolutePaths(); err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return ExitUsage
	}
	service, caller, err := config.newService(true)
	if err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", restore.CodeOf(err))
		return ExitError
	}
	defer func() { _ = service.Close() }()
	report, err := service.Disposition(context.Background(), caller)
	if err != nil {
		fmt.Fprintf(stderr, "错误：读取恢复处置清单失败（%s）\n", restore.CodeOf(err))
		return ExitError
	}
	if *jsonOutput {
		encoded, encodeErr := json.MarshalIndent(report, "", "  ")
		if encodeErr != nil {
			fmt.Fprintln(stderr, "错误：结果序列化失败")
			return ExitError
		}
		fmt.Fprintln(stdout, string(encoded))
		return ExitOK
	}
	if report.RestoreID == "" {
		fmt.Fprintln(stdout, "没有已完成的恢复运行记录。")
		return ExitOK
	}
	fmt.Fprintf(stdout, "最近恢复：%s（代际 %d）\n", report.RestoreID, report.Generation)
	for kind, count := range report.Counts {
		fmt.Fprintf(stdout, "  %s：%d 项\n", kind, count)
	}
	fmt.Fprintf(stdout, "仍待审查：%t\n", report.ReviewRequired)
	for _, item := range report.Items {
		status := "未审查"
		if item.ReviewedAt != nil {
			status = "已审查"
		}
		if item.ReenabledAt != nil {
			status += "/已重新启用"
		}
		fmt.Fprintf(stdout, "  [%s] %s %s（原状态 %s）\n", item.Kind, item.TargetID,
			status, item.PreviousState)
	}
	return ExitOK
}

// runRestoreReview 实现 restore-review。
func runRestoreReview(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("loginctl restore-review", flag.ContinueOnError)
	flags.SetOutput(stderr)
	config := &restoreCLIConfig{stdout: stdout, stderr: stderr}
	config.registerCommonFlags(flags, false)
	restoreID := flags.String("restore-id", "", "可选：指定恢复运行编号（默认最近一次）")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "用法：loginctl restore-review --database <path> "+
			"--state-dir <dir> --key-file <path>（必填） --operator <id> [--restore-id <id>]")
	}
	if err := flags.Parse(args); err != nil {
		return ExitUsage
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "错误：存在多余参数")
		return ExitUsage
	}
	if err := config.validateWithKey(); err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return ExitUsage
	}
	if err := config.absolutePaths(); err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return ExitUsage
	}
	service, caller, err := config.newService(true)
	if err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", restore.CodeOf(err))
		return ExitError
	}
	defer func() { _ = service.Close() }()
	reviewed, err := service.ReviewDisposition(context.Background(), restore.ReviewRequest{
		Caller: caller, RequestID: config.requestID, RestoreID: *restoreID})
	if err != nil {
		fmt.Fprintf(stderr, "错误：标记恢复审查失败（%s）\n", restore.CodeOf(err))
		return ExitError
	}
	fmt.Fprintf(stdout, "已标记 %d 项恢复处置为已审查；重新启用必须使用 restore-reenable。\n",
		reviewed)
	return ExitOK
}

// runRestoreReenable 实现 restore-reenable。
func runRestoreReenable(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("loginctl restore-reenable", flag.ContinueOnError)
	flags.SetOutput(stderr)
	config := &restoreCLIConfig{stdout: stdout, stderr: stderr}
	config.registerCommonFlags(flags, false)
	reason := flags.String("reason", "", "重新启用的原因（必填）")
	restoreID := flags.String("restore-id", "", "可选：指定恢复运行编号（默认最近一次）")
	kinds := flags.String("kind", "schedule,webhook",
		"要重新启用的类型：schedule、webhook 或逗号分隔组合")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "用法：loginctl restore-reenable --database <path> "+
			"--state-dir <dir> --key-file <path>（必填） --operator <id> --reason <原因> \\")
		fmt.Fprintln(stderr, "        [--kind schedule,webhook] [--restore-id <id>]")
	}
	if err := flags.Parse(args); err != nil {
		return ExitUsage
	}
	if flags.NArg() != 0 || strings.TrimSpace(*reason) == "" {
		fmt.Fprintln(stderr, "错误：存在多余参数或缺少 --reason")
		return ExitUsage
	}
	if err := config.validateWithKey(); err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return ExitUsage
	}
	if err := config.absolutePaths(); err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return ExitUsage
	}
	kindList := make([]string, 0, 2)
	for _, item := range strings.Split(*kinds, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			kindList = append(kindList, trimmed)
		}
	}
	service, caller, err := config.newService(true)
	if err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", restore.CodeOf(err))
		return ExitError
	}
	defer func() { _ = service.Close() }()
	result, err := service.ReenablePaused(context.Background(), restore.ReenableRequest{
		Caller: caller, RequestID: config.requestID, Reason: *reason,
		Kinds: kindList, RestoreID: *restoreID})
	if err != nil {
		fmt.Fprintf(stderr, "错误：受控重新启用失败（%s）：%v\n", restore.CodeOf(err), err)
		return ExitError
	}
	fmt.Fprintf(stdout, "已重新启用：调度计划 %d 个、Webhook %d 个（跳过 %d 项）。\n",
		result.Schedules, result.Webhooks, result.Skipped)
	fmt.Fprintln(stdout, "取消的任务/邮件/通知不能用本命令恢复，请通过各自正常入口重新创建。")
	return ExitOK
}
