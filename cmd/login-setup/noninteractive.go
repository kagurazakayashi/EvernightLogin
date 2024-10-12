package main

// 步骤297：login-setup 同源非交互子命令。
//
// 目标（AGENTS §14、requirements-277-302 §297）：
//   - 与 CUI 复用同一 WS1–WS4 领域能力（Detect/LoadConfigReport/PlanRecommendation/
//     ApplyRecommendation/InitializeDatabase/InitializeRoot/ApplyAccountScheme/
//     EnsureSystemPresets/Export*/PreviewConfigImport/ApplyConfigImport/
//     BuildRuntimeConfigRecoveryPlan/ApplyRuntimeConfigRecovery），不另建重复事务；
//   - 不需要 PTY、不弹交互框；错误与结果有稳定退出码与 JSON；
//   - 秘密只从标准输入（--password-stdin）或受限文件（--password-file）读取，
//     不默认走命令行参数；自动生成的一次性密码只在显式受控交付通道输出；
//   - 危险写操作要求逐字确认串，未知/缺参数以用法错误退出（2），不静默执行。

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/kagurazakayashi/EvernightLogin/config"
	"github.com/kagurazakayashi/EvernightLogin/internal/securefile"
	"github.com/kagurazakayashi/EvernightLogin/internal/setupconsole"
)

// 非交互命令稳定退出码。
const (
	cliExitOK         = 0
	cliExitFailure    = 1
	cliExitUsage      = 2
	cliExitNotReady   = 3
	cliExitConflict   = 4
	cliExitSecretLost = 5
)

// 稳定退出码（供脚本与机器文档引用；与内部 cliExit* 同值）。
const (
	ExitOK         = cliExitOK
	ExitFailure    = cliExitFailure
	ExitUsage      = cliExitUsage
	ExitNotReady   = cliExitNotReady
	ExitConflict   = cliExitConflict
	ExitSecretLost = cliExitSecretLost
)

// cliEnv 是非交互命令执行环境（测试可注入缓冲/临时目录）。
type cliEnv struct {
	ctx           context.Context
	stdin         io.Reader
	stdout        io.Writer
	stderr        io.Writer
	configPath    string
	masterKeyFile string
	json          bool
	originalCwd   string
	cwdChanged    bool
}

// sanitizingWriter 把人类输出中的 ANSI/控制字符替换为空格（保留换行与制表），
// 避免外部路径/配置/日志文本操纵终端；JSON 模式不经过它。
type sanitizingWriter struct {
	writer io.Writer
}

// Write 清洗并转发；始终报告写入原始字节数，避免调用方误判短写。
func (s *sanitizingWriter) Write(data []byte) (int, error) {
	if s == nil || s.writer == nil {
		return len(data), nil
	}
	clean := setupconsole.SanitizeText(string(data))
	if _, err := io.WriteString(s.writer, clean); err != nil {
		return 0, err
	}
	return len(data), nil
}

// cliFailure 是带稳定退出码的命令错误。
type cliFailure struct {
	Code    string
	Message string
	Exit    int
	// Silent 表示命令已按 JSON/结果格式输出过完整信息，不再追加一条错误 JSON。
	Silent bool
}

func (e *cliFailure) Error() string { return e.Code + ": " + e.Message }

// runNonInteractive 执行 `login-setup <command> ...`；返回进程退出码。
func runNonInteractive(args []string, env cliEnv) int {
	defer env.restoreCwd()
	if !env.json {
		// 普通文本输出统一清洗：外部路径/配置/错误文本不得携带 ANSI 或控制字符。
		if env.stdout != nil {
			env.stdout = &sanitizingWriter{writer: env.stdout}
		}
		if env.stderr != nil {
			env.stderr = &sanitizingWriter{writer: env.stderr}
		}
	}
	if len(args) == 0 {
		fmt.Fprintln(env.stderr, "用法：login-setup <command> [flags]（command 列表见 login-setup commands）")
		return cliExitUsage
	}
	command, rest := args[0], args[1:]
	var err error
	switch command {
	case "commands", "help", "-h", "--help":
		err = cliCommandsCommand(env, rest)
	case "status":
		err = cliStatusCommand(env, rest)
	case "check":
		err = cliCheckCommand(env, rest)
	case "plan":
		err = cliPlanCommand(env, rest)
	case "apply":
		err = cliApplyCommand(env, rest)
	case "db":
		err = cliDBCommand(env, rest)
	case "root":
		err = cliRootCommand(env, rest)
	case "accounts":
		err = cliAccountsCommand(env, rest)
	case "presets":
		err = cliPresetsCommand(env, rest)
	case "export":
		err = cliExportCommand(env, rest)
	case "import":
		err = cliImportCommand(env, rest)
	case "recover":
		err = cliRecoverCommand(env, rest)
	case "selftest":
		err = cliSelftestCommand(env, rest)
	default:
		err = &cliFailure{Code: "UNKNOWN_COMMAND", Exit: cliExitUsage,
			Message: fmt.Sprintf("未知命令 %q（可用：commands/status/check/plan/apply/db/root/accounts/presets/export/import/recover/selftest）", command)}
	}
	if err == nil {
		return cliExitOK
	}
	if errors.Is(err, flag.ErrHelp) {
		// 子命令 --help 由 flag 包打印用法；按通用约定退出 0。
		return cliExitOK
	}
	var failure *cliFailure
	if errors.As(err, &failure) {
		if !(failure.Silent && env.json) {
			reportCLIError(env, failure.Code, failure.Message)
		}
		return failure.Exit
	}
	code := "COMMAND_FAILED"
	if errors.Is(err, setupconsole.ErrSaveConflict) {
		code = "CONFIG_CONFLICT"
	}
	reportCLIError(env, code, err.Error())
	if code == "CONFIG_CONFLICT" {
		return cliExitConflict
	}
	return cliExitFailure
}

// reportCLIError 输出稳定错误（JSON 或一行文本，不含秘密）。
func reportCLIError(env cliEnv, code, message string) {
	if env.json {
		writeCLIJSON(env, map[string]any{"ok": false, "code": code, "message": message})
		return
	}
	fmt.Fprintf(env.stderr, "错误 [%s]：%s\n", code, message)
}

// writeCLIJSON 输出单行 JSON 结果。
func writeCLIJSON(env cliEnv, payload map[string]any) {
	raw, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintln(env.stderr, "错误 [JSON_ENCODE]：结果序列化失败")
		return
	}
	fmt.Fprintln(env.stdout, string(raw))
}

// cliFlags 构造子命令 FlagSet，并继承全局 --config/--master-key-file/--json。
func cliFlags(env *cliEnv, name string, extra ...flagDef) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet("login-setup "+name, flag.ContinueOnError)
	fs.SetOutput(env.stderr)
	configPath := fs.String("config", env.configPath,
		"login.yaml 路径（默认当前目录 login.yaml）")
	masterKey := fs.String("master-key-file", env.masterKeyFile,
		"主密钥环文件路径（空=按配置/实例目录解析）")
	_ = masterKey
	jsonFlag := fs.Bool("json", env.json, "输出机器可读 JSON")
	for _, def := range extra {
		switch def.kind {
		case "bool":
			fs.Bool(def.name, def.boolDefault, def.usage)
		case "int":
			fs.Int(def.name, def.intDefault, def.usage)
		default:
			fs.String(def.name, def.stringDefault, def.usage)
		}
	}
	_ = jsonFlag
	return fs, configPath
}

// flagDef 是子命令附加 flag 定义。
type flagDef struct {
	name          string
	kind          string
	usage         string
	boolDefault   bool
	intDefault    int
	stringDefault string
}

func boolDef(name, usage string, defaultValue bool) flagDef {
	return flagDef{name: name, kind: "bool", usage: usage, boolDefault: defaultValue}
}

func stringDef(name, usage, defaultValue string) flagDef {
	return flagDef{name: name, kind: "string", usage: usage, stringDefault: defaultValue}
}

func intDef(name, usage string, defaultValue int) flagDef {
	return flagDef{name: name, kind: "int", usage: usage, intDefault: defaultValue}
}

// applyParsedFlags 解析并同步全局输出模式。
func applyParsedFlags(env *cliEnv, fs *flag.FlagSet, configPath *string, rest []string) error {
	if err := fs.Parse(rest); err != nil {
		return &cliFailure{Code: "USAGE", Message: err.Error(), Exit: cliExitUsage}
	}
	if fs.NArg() != 0 {
		return &cliFailure{Code: "USAGE", Exit: cliExitUsage,
			Message: "不接受位置参数：" + strings.Join(fs.Args(), " ")}
	}
	env.configPath = strings.TrimSpace(*configPath)
	if value := fs.Lookup("master-key-file"); value != nil {
		env.masterKeyFile = strings.TrimSpace(value.Value.String())
	}
	if value := fs.Lookup("json"); value != nil {
		env.json = value.Value.String() == "true"
	}
	if env.configPath == "" {
		if _, err := os.Stat("login.yaml"); err == nil {
			env.configPath = "login.yaml"
		}
	}
	env.enterInstanceDir()
	return nil
}

// enterInstanceDir 把进程工作目录切到实例目录，使配置里的相对数据库/密钥路径与
// CUI 在实例目录启动时一致；命令结束后由 restoreCwd 恢复。只读命令也会受益于
// 一致的路径解析，不改变文件内容。
func (env *cliEnv) enterInstanceDir() {
	if env.cwdChanged || strings.TrimSpace(env.configPath) == "" {
		return
	}
	absolute := mustAbs(env.configPath)
	instanceDir := filepath.Dir(absolute)
	current, err := os.Getwd()
	if err != nil || current == instanceDir {
		return
	}
	env.originalCwd = current
	if err := os.Chdir(instanceDir); err == nil {
		env.cwdChanged = true
	}
}

// restoreCwd 恢复命令开始前的工作目录；失败不影响命令结果。
func (env *cliEnv) restoreCwd() {
	if !env.cwdChanged || env.originalCwd == "" {
		return
	}
	_ = os.Chdir(env.originalCwd)
	env.cwdChanged = false
}

// ---------------------------------------------------------------- status/check

// detectionView 是检测结果的脱敏机器视图。
type detectionView struct {
	State        string                     `json:"state"`
	StateLabel   string                     `json:"state_label"`
	ConfigPath   string                     `json:"config_path,omitempty"`
	ConfigLoaded bool                       `json:"config_loaded"`
	DatabasePath string                     `json:"database_path,omitempty"`
	AppliedCount int                        `json:"applied_migrations"`
	LatestCount  int                        `json:"latest_migrations"`
	RootUserID   string                     `json:"root_user_id,omitempty"`
	Summary      string                     `json:"summary,omitempty"`
	Details      []string                   `json:"details,omitempty"`
	Issues       []setupconsole.ConfigIssue `json:"config_issues,omitempty"`
}

func newDetectionView(detection setupconsole.Detection) detectionView {
	return detectionView{
		State: string(detection.Kind), StateLabel: detection.Kind.Label(),
		ConfigPath: detection.ConfigPath, ConfigLoaded: detection.ConfigLoaded,
		DatabasePath: detection.DatabasePath, AppliedCount: detection.AppliedCount,
		LatestCount: detection.LatestCount, RootUserID: detection.RootUserID,
		Summary: detection.Summary, Details: detection.Details,
		Issues: detection.Issues,
	}
}

func cliStatusCommand(env cliEnv, args []string) error {
	fs, configPath := cliFlags(&env, "status")
	if err := applyParsedFlags(&env, fs, configPath, args); err != nil {
		return err
	}
	detection := setupconsole.Detect(env.ctx, setupconsole.DetectOptions{ConfigPath: env.configPath})
	view := newDetectionView(detection)
	if env.json {
		writeCLIJSON(env, map[string]any{"ok": true, "detection": view,
			"ready": detection.Kind == setupconsole.StateReady})
		return nil
	}
	fmt.Fprintf(env.stdout, "状态：%s（%s）\n", view.StateLabel, view.State)
	if view.ConfigPath != "" {
		fmt.Fprintf(env.stdout, "配置：%s\n", view.ConfigPath)
	}
	if view.DatabasePath != "" {
		fmt.Fprintf(env.stdout, "数据库：%s\n", view.DatabasePath)
	}
	fmt.Fprintf(env.stdout, "迁移：%d/%d；root：%s\n", view.AppliedCount, view.LatestCount,
		emptyText(view.RootUserID, "未创建"))
	if view.Summary != "" {
		fmt.Fprintf(env.stdout, "摘要：%s\n", view.Summary)
	}
	for _, issue := range view.Issues {
		fmt.Fprintf(env.stdout, "问题：%s %s %s\n", issue.Kind, issue.Field, issue.Detail)
	}
	return nil
}

func cliCheckCommand(env cliEnv, args []string) error {
	fs, configPath := cliFlags(&env, "check")
	if err := applyParsedFlags(&env, fs, configPath, args); err != nil {
		return err
	}
	detection := setupconsole.Detect(env.ctx, setupconsole.DetectOptions{ConfigPath: env.configPath})
	report := setupconsole.LoadConfigReport(env.configPath)
	view := newDetectionView(detection)
	ready := detection.Kind == setupconsole.StateReady
	if env.json {
		writeCLIJSON(env, map[string]any{"ok": ready, "ready": ready, "detection": view,
			"config_valid": report.Valid, "config_summary": report.Summary})
	} else {
		fmt.Fprintf(env.stdout, "检查结果：%s（%s）\n", view.StateLabel, view.State)
		fmt.Fprintf(env.stdout, "配置有效：%v；%s\n", report.Valid, report.Summary)
		for _, issue := range report.Issues {
			fmt.Fprintf(env.stdout, "问题：%s %s %s\n", issue.Kind, issue.Field, issue.Detail)
		}
	}
	if !ready {
		return &cliFailure{Code: "NOT_READY", Exit: cliExitNotReady, Silent: env.json,
			Message: "实例未就绪：" + detection.Kind.Label()}
	}
	return nil
}

// ---------------------------------------------------------------- plan/apply

func cliPlanCommand(env cliEnv, args []string) error {
	fs, configPath := cliFlags(&env, "plan", stringDef("profile", "推荐配置方案：local|intranet|embedding", "local"))
	if err := applyParsedFlags(&env, fs, configPath, args); err != nil {
		return err
	}
	profile := fs.Lookup("profile").Value.String()
	plan, err := setupconsole.PlanRecommendation(env.configPath, profile)
	if err != nil {
		return &cliFailure{Code: "PLAN_FAILED", Message: err.Error(), Exit: cliExitFailure}
	}
	current := setupconsole.LoadConfigReport(env.configPath)
	changed := string(current.Raw) != string(plan.Raw)
	if env.json {
		writeCLIJSON(env, map[string]any{"ok": true,
			"profile": plan.Profile.Key, "profile_label": plan.Profile.Label,
			"config_path": plan.ConfigPath, "config_exists": plan.ConfigExists,
			"config_would_change": changed, "requires_db_init": plan.RequiresDBInit,
			"pending": plan.Pending, "notes": plan.Notes, "steps": plan.Steps,
			"issues": plan.Issues})
		return nil
	}
	fmt.Fprintf(env.stdout, "方案：%s（%s）\n", plan.Profile.Label, plan.Profile.Key)
	fmt.Fprintf(env.stdout, "配置：%s（已存在=%v，将变化=%v）\n",
		plan.ConfigPath, plan.ConfigExists, changed)
	fmt.Fprintf(env.stdout, "需要数据库初始化：%v\n", plan.RequiresDBInit)
	for _, step := range plan.Steps {
		fmt.Fprintf(env.stdout, "  - %s\n", step)
	}
	for _, pending := range plan.Pending {
		fmt.Fprintf(env.stdout, "待输入：%s\n", pending)
	}
	return nil
}

func cliApplyCommand(env cliEnv, args []string) error {
	fs, configPath := cliFlags(&env, "apply",
		stringDef("profile", "推荐配置方案：local|intranet|embedding", "local"),
		stringDef("confirm", "逐字确认串 APPLY-RECOMMENDATION", ""),
		boolDef("init-db", "保存后对当前 SQLite 配置执行幂等迁移", false),
		boolDef("create-master-key", "初始化数据库时允许新实例生成主密钥", false),
		stringDef("conflict-policy", "外部修改冲突策略：fail|reload|use-draft", "fail"))
	if err := applyParsedFlags(&env, fs, configPath, args); err != nil {
		return err
	}
	if fs.Lookup("confirm").Value.String() != "APPLY-RECOMMENDATION" {
		return &cliFailure{Code: "CONFIRM_REQUIRED", Exit: cliExitUsage,
			Message: "必须显式确认：--confirm APPLY-RECOMMENDATION（确认不是授权）"}
	}
	plan, err := setupconsole.PlanRecommendation(env.configPath,
		fs.Lookup("profile").Value.String())
	if err != nil {
		return &cliFailure{Code: "PLAN_FAILED", Message: err.Error(), Exit: cliExitFailure}
	}
	options, err := cliOperatorOptions(plan.ConfigPath, plan.InstanceDir, env.masterKeyFile,
		"应用推荐配置并可选初始化数据库")
	if err != nil {
		return err
	}
	result, err := setupconsole.ApplyRecommendation(env.ctx, plan,
		setupconsole.RecommendationApplyOptions{
			ConflictPolicy:     setupconsole.ConflictPolicy(fs.Lookup("conflict-policy").Value.String()),
			CreateBackup:       true,
			InitializeDatabase: boolFlagValue(fs, "init-db"),
			DBInit: setupconsole.DBInitOptions{
				InstanceDir: plan.InstanceDir, MasterKeyFile: env.masterKeyFile,
				CreateMasterKey: boolFlagValue(fs, "create-master-key"),
				OperatorID:      options.OperatorID,
				Purpose:         "应用推荐配置并初始化数据库",
			},
		})
	if err != nil {
		return &cliFailure{Code: "APPLY_FAILED", Message: err.Error(), Exit: cliExitFailure}
	}
	if env.json {
		writeCLIJSON(env, map[string]any{"ok": true, "saved": result.Saved,
			"saved_path": plan.ConfigPath, "database_inited": result.DatabaseInited,
			"steps":         recommendationStepsJSON(result.Steps),
			"reload_result": result.SaveResult.ReloadResult,
			"backup_path":   result.SaveResult.BackupPath})
		return nil
	}
	fmt.Fprintf(env.stdout, "应用完成：saved=%v database_inited=%v\n",
		result.Saved, result.DatabaseInited)
	for _, step := range result.Steps {
		fmt.Fprintf(env.stdout, "  [%s] %s：%s\n", okMark(step.OK), step.Name, step.Detail)
	}
	return nil
}

func recommendationStepsJSON(steps []setupconsole.RecommendationStep) []map[string]any {
	out := make([]map[string]any, 0, len(steps))
	for _, step := range steps {
		out = append(out, map[string]any{"name": step.Name, "ok": step.OK, "detail": step.Detail})
	}
	return out
}

func okMark(ok bool) string {
	if ok {
		return "ok"
	}
	return "fail"
}

// ---------------------------------------------------------------- db

func cliDBCommand(env cliEnv, args []string) error {
	if len(args) == 0 {
		return &cliFailure{Code: "USAGE", Exit: cliExitUsage, Message: "用法：db test|init ..."}
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "test":
		return cliDBTest(env, rest)
	case "init":
		return cliDBInit(env, rest)
	default:
		return &cliFailure{Code: "USAGE", Exit: cliExitUsage, Message: "未知 db 子命令：" + sub}
	}
}

func cliDBTest(env cliEnv, args []string) error {
	fs, configPath := cliFlags(&env, "db test", stringDef("sqlite-path", "覆盖 SQLite 数据库路径（默认取配置文件值）", ""))
	if err := applyParsedFlags(&env, fs, configPath, args); err != nil {
		return err
	}
	report := setupconsole.LoadConfigReport(env.configPath)
	if !report.Valid {
		return &cliFailure{Code: "CONFIG_INVALID", Exit: cliExitNotReady, Message: report.Summary}
	}
	plan, err := setupconsole.BuildDBSetupPlan(env.configPath, report.Config,
		dbInputFromConfig(report.Config, fs.Lookup("sqlite-path").Value.String()))
	if err != nil {
		return &cliFailure{Code: "DB_PLAN_FAILED", Message: err.Error(), Exit: cliExitFailure}
	}
	status, err := setupconsole.TestDatabaseConnection(env.ctx, plan)
	if err != nil {
		return &cliFailure{Code: "DB_TEST_FAILED", Message: err.Error(), Exit: cliExitFailure}
	}
	if env.json {
		writeCLIJSON(env, map[string]any{"ok": true, "driver": string(plan.Config.Database.Driver),
			"database_path": status.DatabasePath, "config_valid": status.ConfigValid,
			"file_exists": status.FileExists, "runtime_tested": status.RuntimeTested,
			"migrated": status.Migrated, "pending": status.Pending,
			"message": status.Message})
	} else {
		fmt.Fprintf(env.stdout, "已迁移=%v 文件存在=%v 运行实测=%v 待迁移=%d：%s\n",
			status.Migrated, status.FileExists, status.RuntimeTested, len(status.Pending),
			status.Message)
	}
	return nil
}

func cliDBInit(env cliEnv, args []string) error {
	fs, configPath := cliFlags(&env, "db init",
		stringDef("sqlite-path", "覆盖 SQLite 数据库路径（默认取配置文件值）", ""),
		stringDef("confirm", "逐字确认串 INIT-DATABASE", ""),
		boolDef("create-master-key", "允许新实例生成受保护主密钥", false))
	if err := applyParsedFlags(&env, fs, configPath, args); err != nil {
		return err
	}
	if fs.Lookup("confirm").Value.String() != "INIT-DATABASE" {
		return &cliFailure{Code: "CONFIRM_REQUIRED", Exit: cliExitUsage,
			Message: "必须显式确认：--confirm INIT-DATABASE"}
	}
	report := setupconsole.LoadConfigReport(env.configPath)
	if !report.Valid {
		return &cliFailure{Code: "CONFIG_INVALID", Exit: cliExitNotReady, Message: report.Summary}
	}
	plan, err := setupconsole.BuildDBSetupPlan(env.configPath, report.Config,
		dbInputFromConfig(report.Config, fs.Lookup("sqlite-path").Value.String()))
	if err != nil {
		return &cliFailure{Code: "DB_PLAN_FAILED", Message: err.Error(), Exit: cliExitFailure}
	}
	instanceDir := filepath.Dir(mustAbs(env.configPath))
	operator, err := cliOperatorOptions(env.configPath, instanceDir, env.masterKeyFile, "初始化数据库结构")
	if err != nil {
		return err
	}
	result, err := setupconsole.InitializeDatabase(env.ctx, plan, setupconsole.DBInitOptions{
		InstanceDir: instanceDir, MasterKeyFile: env.masterKeyFile,
		CreateMasterKey: boolFlagValue(fs, "create-master-key"),
		OperatorID:      operator.OperatorID, Purpose: "初始化数据库结构"})
	if err != nil {
		return &cliFailure{Code: "DB_INIT_FAILED", Message: err.Error(), Exit: cliExitFailure}
	}
	if env.json {
		writeCLIJSON(env, map[string]any{"ok": true, "driver": string(result.Driver),
			"database_path": result.DatabasePath, "already_migrated": result.AlreadyMigrated,
			"applied": result.AppliedCount, "pending": result.Pending,
			"master_key_created": result.MasterKeyCreated,
			"master_key_reused":  result.MasterKeyReused, "lock_path": result.LockPath})
	} else {
		fmt.Fprintf(env.stdout, "数据库初始化完成：applied=%d already_migrated=%v 主密钥新建=%v\n",
			result.AppliedCount, result.AlreadyMigrated, result.MasterKeyCreated)
	}
	return nil
}

// dbInputFromConfig 构造数据库设置输入（只覆盖 CLI 提供的 SQLite 路径）。
func dbInputFromConfig(cfg config.Config, sqlitePath string) setupconsole.DBSetupInput {
	database := cfg.Database
	input := setupconsole.DBSetupInput{Driver: database.Driver, SQLitePath: database.Path,
		WAL: database.WAL, BusyTimeoutMS: database.BusyTimeoutMS,
		Host: database.Host, Port: database.Port, Username: database.Username,
		Password: database.Password, DatabaseName: database.Database, TLSMode: database.TLSMode}
	if strings.TrimSpace(sqlitePath) != "" {
		input.Driver = config.DatabaseDriverSQLite
		input.SQLitePath = strings.TrimSpace(sqlitePath)
	}
	return input
}

// ---------------------------------------------------------------- root

func cliRootCommand(env cliEnv, args []string) error {
	if len(args) == 0 {
		return &cliFailure{Code: "USAGE", Exit: cliExitUsage, Message: "用法：root status|init ..."}
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "status":
		return cliRootStatus(env, rest)
	case "init":
		return cliRootInit(env, rest)
	default:
		return &cliFailure{Code: "USAGE", Exit: cliExitUsage, Message: "未知 root 子命令：" + sub}
	}
}

func cliRootStatus(env cliEnv, args []string) error {
	fs, configPath := cliFlags(&env, "root status")
	if err := applyParsedFlags(&env, fs, configPath, args); err != nil {
		return err
	}
	report := setupconsole.LoadConfigReport(env.configPath)
	if !report.Valid {
		return &cliFailure{Code: "CONFIG_INVALID", Exit: cliExitNotReady, Message: report.Summary}
	}
	operator, err := cliOperatorOptions(env.configPath, filepath.Dir(mustAbs(env.configPath)),
		env.masterKeyFile, "读取 root 初始化状态")
	if err != nil {
		return err
	}
	status, err := setupconsole.InspectRootInitialization(env.ctx, report.Config,
		setupconsole.RootInitOptions{ConfigPath: report.Path,
			InstanceDir: filepath.Dir(mustAbs(report.Path)), OperatorID: operator.OperatorID,
			MasterKeyFile: env.masterKeyFile, Purpose: "读取 root 初始化状态"})
	if err != nil {
		return &cliFailure{Code: "ROOT_STATUS_FAILED", Message: err.Error(), Exit: cliExitFailure}
	}
	if env.json {
		writeCLIJSON(env, map[string]any{"ok": true, "state": string(status.State),
			"state_description": status.StateDescription, "root_exists": status.RootExists,
			"root_user_id": status.RootUserID, "root_username": status.RootUsername})
	} else {
		fmt.Fprintf(env.stdout, "root 状态：%s；存在=%v user=%s\n",
			status.StateDescription, status.RootExists, emptyText(status.RootUserID, "-"))
	}
	return nil
}

func cliRootInit(env cliEnv, args []string) error {
	fs, configPath := cliFlags(&env, "root init",
		stringDef("username", "root 保留用户名（只接受 root/空）", ""),
		stringDef("nickname", "root 昵称（可空）", ""),
		stringDef("language", "语言（可空）", ""),
		stringDef("timezone", "时区（可空）", ""),
		stringDef("confirm", "逐字确认串 INIT-ROOT", ""),
		boolDef("password-stdin", "从标准输入读取密码（不回显）", false),
		stringDef("password-file", "从 0600 受限文件读取密码", ""),
		boolDef("generate-password", "生成高熵一次性密码", false),
		stringDef("generated-password-file", "一次性密码写入的受控文件（0600，新建）", ""),
		boolDef("print-generated", "允许把一次性密码打印到标准输出（显式通道）", false),
		boolDef("reset-existing", "对已初始化 root 本地重设密码", false))
	if err := applyParsedFlags(&env, fs, configPath, args); err != nil {
		return err
	}
	if fs.Lookup("confirm").Value.String() != "INIT-ROOT" {
		return &cliFailure{Code: "CONFIRM_REQUIRED", Exit: cliExitUsage,
			Message: "必须显式确认：--confirm INIT-ROOT"}
	}
	if err := precheckGeneratedPasswordDelivery(env, fs); err != nil {
		return err
	}
	password, generate, err := readCLISecret(env, "root", boolFlagValue(fs, "password-stdin"),
		fs.Lookup("password-file").Value.String(), boolFlagValue(fs, "generate-password"))
	if err != nil {
		return err
	}
	report := setupconsole.LoadConfigReport(env.configPath)
	if !report.Valid {
		return &cliFailure{Code: "CONFIG_INVALID", Exit: cliExitNotReady, Message: report.Summary}
	}
	instanceDir := filepath.Dir(mustAbs(report.Path))
	operator, err := cliOperatorOptions(report.Path, instanceDir, env.masterKeyFile, "创建或恢复 root 账户")
	if err != nil {
		return err
	}
	result, err := setupconsole.InitializeRoot(env.ctx, report.Config,
		setupconsole.RootInitRequest{Username: fs.Lookup("username").Value.String(),
			Nickname: fs.Lookup("nickname").Value.String(),
			Language: fs.Lookup("language").Value.String(),
			Timezone: fs.Lookup("timezone").Value.String(),
			Password: password, GeneratePassword: generate,
			ResetExistingPassword: boolFlagValue(fs, "reset-existing")},
		setupconsole.RootInitOptions{ConfigPath: report.Path, InstanceDir: instanceDir,
			OperatorID: operator.OperatorID, MasterKeyFile: env.masterKeyFile,
			Purpose: "创建或恢复 root 账户"})
	if err != nil {
		return &cliFailure{Code: "ROOT_INIT_FAILED", Message: err.Error(), Exit: cliExitFailure}
	}
	if err := deliverGeneratedPassword(env, result.GeneratedPassword,
		fs.Lookup("generated-password-file").Value.String(), boolFlagValue(fs, "print-generated")); err != nil {
		return err
	}
	if env.json {
		writeCLIJSON(env, map[string]any{"ok": true, "created": result.Created,
			"reentry": result.Reentry, "password_reset": result.PasswordReset,
			"root_user_id": result.RootUserID, "root_username": result.RootUsername,
			"strong_auth_required": result.StrongAuthRequired,
			"required_steps":       result.RequiredSteps,
			"security_version":     result.SecurityVersion,
			"generated_password_delivered": result.GeneratedPassword != "" &&
				passwordDeliveryRequested(fs)})
		return nil
	}
	fmt.Fprintf(env.stdout, "root 初始化结果：created=%v reentry=%v reset=%v user=%s\n",
		result.Created, result.Reentry, result.PasswordReset, result.RootUserID)
	if result.StrongAuthRequired {
		fmt.Fprintln(env.stdout, "提示：远程强认证尚未建立时按受限流程继续；本地控制台可继续维护。")
	}
	for _, step := range result.RequiredSteps {
		fmt.Fprintf(env.stdout, "  - %s\n", step)
	}
	return nil
}

// ---------------------------------------------------------------- accounts

func cliAccountsCommand(env cliEnv, args []string) error {
	if len(args) == 0 {
		return &cliFailure{Code: "USAGE", Exit: cliExitUsage, Message: "用法：accounts list|apply ..."}
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		fs, configPath := cliFlags(&env, "accounts list")
		if err := applyParsedFlags(&env, fs, configPath, rest); err != nil {
			return err
		}
		schemes := setupconsole.AccountSchemes()
		if env.json {
			rows := make([]map[string]any, 0, len(schemes))
			for _, scheme := range schemes {
				rows = append(rows, map[string]any{"key": scheme.Key, "label": scheme.Label,
					"available": scheme.Available, "root_qualification": scheme.RootQualification,
					"roles": scheme.RoleKeys, "direct_permissions": scheme.DirectPermissionKeys,
					"unavailable_reason": scheme.UnavailableReason})
			}
			writeCLIJSON(env, map[string]any{"ok": true, "schemes": rows})
			return nil
		}
		for _, scheme := range schemes {
			fmt.Fprintf(env.stdout, "%s\t%s\tavailable=%v\troles=%s\n", scheme.Key,
				scheme.Label, scheme.Available, strings.Join(scheme.RoleKeys, ","))
		}
		return nil
	case "apply":
		return cliAccountsApply(env, rest)
	default:
		return &cliFailure{Code: "USAGE", Exit: cliExitUsage, Message: "未知 accounts 子命令：" + sub}
	}
}

func cliAccountsApply(env cliEnv, args []string) error {
	fs, configPath := cliFlags(&env, "accounts apply",
		stringDef("scheme", "账户方案 key（accounts list）", ""),
		stringDef("username", "用户名", ""),
		stringDef("nickname", "昵称（可空）", ""),
		stringDef("confirm", "逐字确认串 APPLY-ACCOUNT", ""),
		boolDef("password-stdin", "从标准输入读取密码", false),
		stringDef("password-file", "从 0600 受限文件读取密码", ""),
		boolDef("generate-password", "生成临时密码", false),
		stringDef("generated-password-file", "临时密码写入的受控文件（0600，新建）", ""),
		boolDef("print-generated", "允许把临时密码打印到标准输出（显式通道）", false))
	if err := applyParsedFlags(&env, fs, configPath, args); err != nil {
		return err
	}
	if fs.Lookup("confirm").Value.String() != "APPLY-ACCOUNT" {
		return &cliFailure{Code: "CONFIRM_REQUIRED", Exit: cliExitUsage,
			Message: "必须显式确认：--confirm APPLY-ACCOUNT"}
	}
	scheme := strings.TrimSpace(fs.Lookup("scheme").Value.String())
	username := strings.TrimSpace(fs.Lookup("username").Value.String())
	if scheme == "" || username == "" {
		return &cliFailure{Code: "USAGE", Exit: cliExitUsage, Message: "需要 --scheme 与 --username"}
	}
	if err := precheckGeneratedPasswordDelivery(env, fs); err != nil {
		return err
	}
	password, generate, err := readCLISecret(env, "accounts", boolFlagValue(fs, "password-stdin"),
		fs.Lookup("password-file").Value.String(), boolFlagValue(fs, "generate-password"))
	if err != nil {
		return err
	}
	detection := setupconsole.Detect(env.ctx, setupconsole.DetectOptions{ConfigPath: env.configPath})
	instanceDir := filepath.Dir(mustAbs(env.configPath))
	operator, err := cliOperatorOptions(env.configPath, instanceDir, env.masterKeyFile, "按方案创建常用账户")
	if err != nil {
		return err
	}
	result, err := setupconsole.ApplyAccountScheme(env.ctx, detection,
		[]setupconsole.AccountDraft{{Username: username,
			Nickname: fs.Lookup("nickname").Value.String(), SchemeKey: scheme,
			Password: password, GeneratePassword: generate}},
		setupconsole.AccountApplyOptions{ConfigPath: env.configPath, InstanceDir: instanceDir,
			OperatorID: operator.OperatorID, Purpose: "按方案创建常用账户"})
	if err != nil {
		return &cliFailure{Code: "ACCOUNT_APPLY_FAILED", Message: err.Error(), Exit: cliExitFailure}
	}
	items := make([]map[string]any, 0, len(result.Accounts))
	for _, item := range result.Accounts {
		if err := deliverGeneratedPassword(env, item.GeneratedPassword,
			fs.Lookup("generated-password-file").Value.String(),
			boolFlagValue(fs, "print-generated")); err != nil {
			return err
		}
		items = append(items, map[string]any{"username": item.Username,
			"scheme": item.SchemeKey, "user_id": item.UserID, "roles": item.RoleKeys,
			"created": item.Created, "skipped_existing": item.SkippedExisting,
			"require_change": item.RequireChange,
			"generated_password_delivered": item.GeneratedPassword != "" &&
				passwordDeliveryRequested(fs)})
	}
	if env.json {
		writeCLIJSON(env, map[string]any{"ok": len(result.Errors) == 0,
			"accounts": items, "errors": result.Errors})
	} else {
		for _, item := range items {
			fmt.Fprintf(env.stdout, "账户：%v（created=%v skipped=%v user=%v）\n",
				item["username"], item["created"], item["skipped_existing"], item["user_id"])
		}
		for _, message := range result.Errors {
			fmt.Fprintln(env.stderr, "账户错误：", message)
		}
	}
	if len(result.Errors) > 0 {
		return &cliFailure{Code: "ACCOUNT_PARTIAL", Exit: cliExitFailure,
			Silent:  env.json,
			Message: strings.Join(result.Errors, "；")}
	}
	return nil
}

// ---------------------------------------------------------------- presets

func cliPresetsCommand(env cliEnv, args []string) error {
	if len(args) == 0 || args[0] != "install" {
		return &cliFailure{Code: "USAGE", Exit: cliExitUsage, Message: "用法：presets install --confirm INSTALL-PRESETS"}
	}
	fs, configPath := cliFlags(&env, "presets install",
		stringDef("confirm", "逐字确认串 INSTALL-PRESETS", ""))
	if err := applyParsedFlags(&env, fs, configPath, args[1:]); err != nil {
		return err
	}
	if fs.Lookup("confirm").Value.String() != "INSTALL-PRESETS" {
		return &cliFailure{Code: "CONFIRM_REQUIRED", Exit: cliExitUsage,
			Message: "必须显式确认：--confirm INSTALL-PRESETS"}
	}
	report := setupconsole.LoadConfigReport(env.configPath)
	if !report.Valid {
		return &cliFailure{Code: "CONFIG_INVALID", Exit: cliExitNotReady, Message: report.Summary}
	}
	instanceDir := filepath.Dir(mustAbs(report.Path))
	operator, err := cliOperatorOptions(report.Path, instanceDir, env.masterKeyFile,
		"安装系统预设角色与权限")
	if err != nil {
		return err
	}
	result, err := setupconsole.EnsureSystemPresets(env.ctx, report.Config,
		setupconsole.PresetInstallOptions{ConfigPath: report.Path, InstanceDir: instanceDir,
			OperatorID: operator.OperatorID, Purpose: "安装系统预设角色与权限"})
	if err != nil {
		return &cliFailure{Code: "PRESET_INSTALL_FAILED", Message: err.Error(), Exit: cliExitFailure}
	}
	if env.json {
		writeCLIJSON(env, map[string]any{"ok": true, "scope_id": result.ScopeID,
			"catalog_version": result.CatalogVersion, "previous_version": result.PreviousVersion,
			"initialized": result.Initialized, "upgraded": result.Upgraded,
			"up_to_date": result.UpToDate, "created_permissions": result.CreatedPermissions,
			"created_roles": result.CreatedRoles, "created_groups": result.CreatedGroups})
	} else {
		fmt.Fprintf(env.stdout, "预设安装完成：initialized=%v upgraded=%v up_to_date=%v\n",
			result.Initialized, result.Upgraded, result.UpToDate)
	}
	return nil
}

// ---------------------------------------------------------------- export/import

func cliExportCommand(env cliEnv, args []string) error {
	if len(args) == 0 || args[0] != "config" {
		return &cliFailure{Code: "USAGE", Exit: cliExitUsage,
			Message: "用法：export config (--masked|--encrypted) --out <file> [--json]"}
	}
	fs, configPath := cliFlags(&env, "export config",
		boolDef("masked", "导出默认脱敏配置 YAML（不含秘密值）", false),
		boolDef("encrypted", "导出可还原的加密敏感配置包", false),
		stringDef("out", "导出目标路径（必须不存在）", ""))
	if err := applyParsedFlags(&env, fs, configPath, args[1:]); err != nil {
		return err
	}
	outPath := strings.TrimSpace(fs.Lookup("out").Value.String())
	if outPath == "" {
		return &cliFailure{Code: "USAGE", Exit: cliExitUsage, Message: "需要 --out <目标文件>"}
	}
	masked := boolFlagValue(fs, "masked")
	encrypted := boolFlagValue(fs, "encrypted")
	if masked == encrypted {
		return &cliFailure{Code: "USAGE", Exit: cliExitUsage,
			Message: "必须且只能选择 --masked 或 --encrypted 之一"}
	}
	absoluteConfig := mustAbs(env.configPath)
	options := setupconsole.ConfigExportOptions{ConfigPath: absoluteConfig,
		OutputPath: mustAbs(outPath), MasterKeyFile: env.masterKeyFile,
		Operator: localOperator(env.configPath)}
	if masked {
		result, err := setupconsole.ExportMaskedConfig(options)
		if err != nil {
			return &cliFailure{Code: "EXPORT_FAILED", Message: err.Error(), Exit: cliExitFailure}
		}
		if env.json {
			writeCLIJSON(env, map[string]any{"ok": true, "kind": "masked-yaml",
				"out": result.OutputPath, "size": result.SizeBytes, "sha256": result.SHA256,
				"masked_fields": len(result.Masked)})
		} else {
			fmt.Fprintf(env.stdout, "已导出脱敏配置：%s（%d 字节，%d 个字段脱敏）\n",
				result.OutputPath, result.SizeBytes, len(result.Masked))
		}
		return nil
	}
	result, err := setupconsole.ExportEncryptedConfigPackage(env.ctx, options)
	if err != nil {
		return &cliFailure{Code: "EXPORT_FAILED", Message: err.Error(), Exit: cliExitFailure}
	}
	if env.json {
		writeCLIJSON(env, map[string]any{"ok": true, "kind": "encrypted-package",
			"out": result.Path, "size": result.PackageSize, "sha256": result.PackageSHA256,
			"config_sha256": result.ConfigSHA256, "key_id": result.KeyID,
			"format_version": result.FormatVersion})
	} else {
		fmt.Fprintf(env.stdout, "已导出加密敏感配置包：%s（%d 字节）\n", result.Path, result.PackageSize)
	}
	return nil
}

func cliImportCommand(env cliEnv, args []string) error {
	if len(args) == 0 || args[0] != "config" {
		return &cliFailure{Code: "USAGE", Exit: cliExitUsage,
			Message: "用法：import config --file <pkg|yaml> --confirm IMPORT-CONFIG [--json]"}
	}
	fs, configPath := cliFlags(&env, "import config",
		stringDef("file", "导入源（.yaml 脱敏导出或 .lncfg 加密包）", ""),
		stringDef("confirm", "预览要求的确认串", ""),
		stringDef("conflict-policy", "冲突策略：fail|reload|use-draft", "fail"))
	if err := applyParsedFlags(&env, fs, configPath, args[1:]); err != nil {
		return err
	}
	importPath := strings.TrimSpace(fs.Lookup("file").Value.String())
	if importPath == "" {
		return &cliFailure{Code: "USAGE", Exit: cliExitUsage, Message: "需要 --file <导入源>"}
	}
	request := setupconsole.ConfigImportRequest{ImportPath: mustAbs(importPath),
		CurrentConfigPath: mustAbs(env.configPath), MasterKeyFile: env.masterKeyFile,
		ConfirmText:    strings.TrimSpace(fs.Lookup("confirm").Value.String()),
		ConflictPolicy: strings.TrimSpace(fs.Lookup("conflict-policy").Value.String())}
	preview, err := setupconsole.PreviewConfigImport(env.ctx, request)
	if err != nil {
		return &cliFailure{Code: "IMPORT_PREVIEW_FAILED", Message: err.Error(), Exit: cliExitFailure}
	}
	if request.ConfirmText == "" || request.ConfirmText != preview.RequiredConfirm {
		if env.json {
			writeCLIJSON(env, map[string]any{"ok": false, "code": "CONFIRM_REQUIRED",
				"preview": importPreviewJSON(preview), "required_confirm": preview.RequiredConfirm})
		} else {
			printImportPreview(env, preview)
			fmt.Fprintf(env.stdout, "确认串：--confirm %s\n", preview.RequiredConfirm)
		}
		return &cliFailure{Code: "CONFIRM_REQUIRED", Exit: cliExitConflict,
			Silent:  env.json,
			Message: "导入未应用：确认串不匹配（需 --confirm " + preview.RequiredConfirm + "）"}
	}
	// MEDIUM-2：复用 WS4 导出的 WithMaintenanceEvidence（维护日志 started → 排他
	// 维护锁 → 执行 → success/failed）；锁被占/服务运行/日志不可写时 fail-closed。
	var result setupconsole.ConfigImportApplyResult
	_, maintErr := setupconsole.WithMaintenanceEvidence(env.ctx,
		filepath.Dir(mustAbs(env.configPath)), "config.import", preview.SourceKind,
		func(ctx context.Context) (string, error) {
			applied, applyErr := setupconsole.ApplyConfigImport(ctx,
				setupconsole.DraftConfigSaver{}, request)
			if applyErr != nil {
				return "", applyErr
			}
			result = applied
			return "applied", nil
		})
	if maintErr != nil {
		return &cliFailure{Code: "MAINTENANCE_BLOCKED", Message: maintErr.Error(), Exit: cliExitFailure}
	}
	if env.json {
		writeCLIJSON(env, map[string]any{"ok": true, "applied": result.Outcome.Saved,
			"reload_result": result.Outcome.ReloadResult, "backup_path": result.Outcome.BackupPath,
			"config_valid": result.Outcome.ConfigValid,
			"preview":      importPreviewJSON(result.Preview)})
	} else {
		printImportPreview(env, result.Preview)
		fmt.Fprintf(env.stdout, "导入已应用：saved=%v reload=%s\n",
			result.Outcome.Saved, result.Outcome.ReloadResult)
	}
	return nil
}

func printImportPreview(env cliEnv, preview setupconsole.ConfigImportPreview) {
	fmt.Fprintf(env.stdout, "导入源：%s（%s）\n", preview.SourcePath, preview.SourceKind)
	fmt.Fprintf(env.stdout, "变化字段：%s\n", strings.Join(preview.ChangedPaths, ", "))
	for _, line := range preview.Diff {
		fmt.Fprintf(env.stdout, "%s %d\t%s\n", line.Kind, line.Line, line.Text)
	}
	for _, warning := range preview.Warnings {
		fmt.Fprintf(env.stdout, "警告：%s\n", warning)
	}
	for _, blocking := range preview.Blocking {
		fmt.Fprintf(env.stdout, "阻塞：%s\n", blocking)
	}
}

func importPreviewJSON(preview setupconsole.ConfigImportPreview) map[string]any {
	return map[string]any{"source_path": preview.SourcePath, "source_kind": preview.SourceKind,
		"current_path": preview.CurrentPath, "changed_paths": preview.ChangedPaths,
		"diff": preview.Diff, "warnings": preview.Warnings, "blocking": preview.Blocking,
		"database_path_change": preview.DatabasePathChange,
		"required_confirm":     preview.RequiredConfirm, "can_apply": preview.CanApply}
}

// ---------------------------------------------------------------- recover

func cliRecoverCommand(env cliEnv, args []string) error {
	if len(args) == 0 {
		return &cliFailure{Code: "USAGE", Exit: cliExitUsage,
			Message: "用法：recover (plan|apply) [--profile local] ..."}
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "plan":
		return cliRecoverPlan(env, rest)
	case "apply":
		return cliRecoverApply(env, rest)
	default:
		return &cliFailure{Code: "USAGE", Exit: cliExitUsage, Message: "未知 recover 子命令：" + sub}
	}
}

func cliRecoverPlan(env cliEnv, args []string) error {
	fs, configPath := cliFlags(&env, "recover plan",
		stringDef("profile", "推荐运行配置方案", "local"))
	if err := applyParsedFlags(&env, fs, configPath, args); err != nil {
		return err
	}
	plan, err := buildRecoveryPlan(env, fs.Lookup("profile").Value.String())
	if err != nil {
		return err
	}
	if env.json {
		writeCLIJSON(env, map[string]any{"ok": true, "plan": recoveryPlanJSON(plan)})
		return nil
	}
	printRecoveryPlan(env, plan)
	return nil
}

func cliRecoverApply(env cliEnv, args []string) error {
	fs, configPath := cliFlags(&env, "recover apply",
		stringDef("profile", "推荐运行配置方案", "local"),
		stringDef("confirm", "计划要求的确认串", ""))
	if err := applyParsedFlags(&env, fs, configPath, args); err != nil {
		return err
	}
	plan, err := buildRecoveryPlan(env, fs.Lookup("profile").Value.String())
	if err != nil {
		return err
	}
	confirm := strings.TrimSpace(fs.Lookup("confirm").Value.String())
	if !plan.CanApply || plan.Idempotent || confirm != plan.RequiredConfirm {
		if env.json {
			writeCLIJSON(env, map[string]any{"ok": false, "plan": recoveryPlanJSON(plan),
				"required_confirm": plan.RequiredConfirm, "code": "CONFIRM_REQUIRED"})
		} else {
			printRecoveryPlan(env, plan)
		}
		return &cliFailure{Code: "CONFIRM_REQUIRED", Exit: cliExitConflict,
			Silent:  env.json,
			Message: "恢复未应用：计划不可应用/已幂等/确认串不匹配"}
	}
	// MEDIUM-2：复用 WS4 导出的 WithMaintenanceEvidence 包装恢复写操作。
	var outcome setupconsole.ConfigSaveOutcome
	_, maintErr := setupconsole.WithMaintenanceEvidence(env.ctx,
		filepath.Dir(mustAbs(env.configPath)), "config.restore-recommended", "recommended-runtime",
		func(ctx context.Context) (string, error) {
			applied, applyErr := setupconsole.ApplyRuntimeConfigRecovery(ctx,
				setupconsole.DraftConfigSaver{}, plan, confirm)
			if applyErr != nil {
				return "", applyErr
			}
			outcome = applied
			return "applied", nil
		})
	if maintErr != nil {
		return &cliFailure{Code: "MAINTENANCE_BLOCKED", Message: maintErr.Error(), Exit: cliExitFailure}
	}
	if env.json {
		writeCLIJSON(env, map[string]any{"ok": true, "saved": outcome.Saved,
			"backup_path": outcome.BackupPath, "reload_result": outcome.ReloadResult,
			"plan": recoveryPlanJSON(plan)})
	} else {
		fmt.Fprintf(env.stdout, "推荐运行配置恢复已应用：saved=%v reload=%s\n",
			outcome.Saved, outcome.ReloadResult)
	}
	return nil
}

func buildRecoveryPlan(env cliEnv, profileKey string) (setupconsole.RuntimeConfigRecoveryPlan, error) {
	report := setupconsole.LoadConfigReport(env.configPath)
	if !report.Valid {
		return setupconsole.RuntimeConfigRecoveryPlan{},
			&cliFailure{Code: "CONFIG_INVALID", Exit: cliExitNotReady, Message: report.Summary}
	}
	recommendation, err := setupconsole.PlanRecommendation(env.configPath, profileKey)
	if err != nil {
		return setupconsole.RuntimeConfigRecoveryPlan{},
			&cliFailure{Code: "RECOVER_PLAN_FAILED", Message: err.Error(), Exit: cliExitFailure}
	}
	plan, err := setupconsole.BuildRuntimeConfigRecoveryPlan(report.Path, report.Raw,
		recommendation.Raw)
	if err != nil {
		return setupconsole.RuntimeConfigRecoveryPlan{},
			&cliFailure{Code: "RECOVER_PLAN_FAILED", Message: err.Error(), Exit: cliExitFailure}
	}
	return plan, nil
}

func printRecoveryPlan(env cliEnv, plan setupconsole.RuntimeConfigRecoveryPlan) {
	fmt.Fprintf(env.stdout, "保留段：%s\n", strings.Join(plan.RetainedSections, ", "))
	fmt.Fprintf(env.stdout, "重置段：%s\n", strings.Join(plan.ResetSections, ", "))
	fmt.Fprintf(env.stdout, "变化字段：%s\n", strings.Join(plan.ChangedPaths, ", "))
	fmt.Fprintf(env.stdout, "幂等=%v 可应用=%v 确认串=%s\n",
		plan.Idempotent, plan.CanApply, plan.RequiredConfirm)
	for _, blocking := range plan.Blocking {
		fmt.Fprintf(env.stdout, "阻塞：%s\n", blocking)
	}
	for _, warning := range plan.Warnings {
		fmt.Fprintf(env.stdout, "警告：%s\n", warning)
	}
}

func recoveryPlanJSON(plan setupconsole.RuntimeConfigRecoveryPlan) map[string]any {
	return map[string]any{"current_path": plan.CurrentPath,
		"retained_sections": plan.RetainedSections, "reset_sections": plan.ResetSections,
		"changed_paths": plan.ChangedPaths, "idempotent": plan.Idempotent,
		"required_confirm": plan.RequiredConfirm, "can_apply": plan.CanApply,
		"blocking": plan.Blocking, "warnings": plan.Warnings}
}

// ---------------------------------------------------------------- selftest/commands

func cliSelftestCommand(env cliEnv, args []string) error {
	fs, configPath := cliFlags(&env, "selftest")
	if err := applyParsedFlags(&env, fs, configPath, args); err != nil {
		return err
	}
	detection := setupconsole.Detect(env.ctx, setupconsole.DetectOptions{ConfigPath: env.configPath})
	report := setupconsole.LoadConfigReport(env.configPath)
	profiles := setupconsole.RecommendationProfiles()
	schemes := setupconsole.AccountSchemes()
	checks := []map[string]any{
		{"name": "detect", "ok": detection.Kind != setupconsole.StateError, "state": string(detection.Kind)},
		{"name": "config_report", "ok": report.Valid || !report.Exists, "summary": report.Summary},
		{"name": "profiles", "ok": len(profiles) == 3, "count": len(profiles)},
		{"name": "account_schemes", "ok": len(schemes) > 0, "count": len(schemes)},
	}
	ok := true
	for _, check := range checks {
		if value, _ := check["ok"].(bool); !value {
			ok = false
		}
	}
	if env.json {
		writeCLIJSON(env, map[string]any{"ok": ok, "checks": checks,
			"detection": newDetectionView(detection), "command_count": len(cliCommandTable())})
	} else {
		fmt.Fprintf(env.stdout, "自检：%s\n", map[bool]string{true: "通过", false: "失败"}[ok])
		for _, check := range checks {
			fmt.Fprintf(env.stdout, "  [%v] %v\n", check["ok"], check["name"])
		}
	}
	return nil
}

// cliCommandRow 是命令表条目。
type cliCommandRow struct {
	Name            string   `json:"name"`
	Summary         string   `json:"summary"`
	Confirm         string   `json:"confirm,omitempty"`
	Secrets         []string `json:"secrets,omitempty"`
	Writes          bool     `json:"writes"`
	NonInteractive  bool     `json:"non_interactive"`
	StableExitCodes []int    `json:"stable_exit_codes"`
}

func cliCommandTable() []cliCommandRow {
	return []cliCommandRow{
		{Name: "status", Summary: "只读状态检测", NonInteractive: true,
			StableExitCodes: []int{0, 1, 2}},
		{Name: "check", Summary: "只读检查（未就绪退出 3）", NonInteractive: true,
			StableExitCodes: []int{0, 1, 2, 3}},
		{Name: "plan", Summary: "推荐配置差异/操作计划（不写盘）", NonInteractive: true,
			StableExitCodes: []int{0, 1, 2}},
		{Name: "apply", Summary: "应用推荐配置并可选初始化数据库", Confirm: "APPLY-RECOMMENDATION",
			Writes: true, NonInteractive: true, StableExitCodes: []int{0, 1, 2, 4}},
		{Name: "db test", Summary: "数据库连接测试（只读）", NonInteractive: true,
			StableExitCodes: []int{0, 1, 2, 3}},
		{Name: "db init", Summary: "排他锁下幂等迁移", Confirm: "INIT-DATABASE", Writes: true,
			NonInteractive: true, StableExitCodes: []int{0, 1, 2, 3}},
		{Name: "root status", Summary: "root 初始化状态（只读）", NonInteractive: true,
			StableExitCodes: []int{0, 1, 2, 3}},
		{Name: "root init", Summary: "创建/恢复唯一 root（密码经 stdin/受限文件）",
			Confirm: "INIT-ROOT", Secrets: []string{"password", "generated_password"},
			Writes: true, NonInteractive: true, StableExitCodes: []int{0, 1, 2, 3}},
		{Name: "accounts list", Summary: "账户方案清单（只读）", NonInteractive: true,
			StableExitCodes: []int{0, 1, 2}},
		{Name: "accounts apply", Summary: "按方案创建账户（临时密码经受控通道）",
			Confirm: "APPLY-ACCOUNT", Secrets: []string{"password", "generated_password"},
			Writes: true, NonInteractive: true, StableExitCodes: []int{0, 1, 2, 3}},
		{Name: "presets install", Summary: "安装/升级系统预设角色与权限",
			Confirm: "INSTALL-PRESETS", Writes: true, NonInteractive: true,
			StableExitCodes: []int{0, 1, 2, 3}},
		{Name: "export config", Summary: "导出脱敏/加密配置", Writes: true,
			NonInteractive: true, StableExitCodes: []int{0, 1, 2}},
		{Name: "import config", Summary: "预览并应用配置导入",
			Confirm: "导入预览要求的确认串", Writes: true, NonInteractive: true,
			StableExitCodes: []int{0, 1, 2, 4}},
		{Name: "recover plan", Summary: "推荐运行配置恢复差异（只读）", NonInteractive: true,
			StableExitCodes: []int{0, 1, 2, 3}},
		{Name: "recover apply", Summary: "应用推荐运行配置恢复",
			Confirm: "计划要求的确认串", Writes: true, NonInteractive: true,
			StableExitCodes: []int{0, 1, 2, 4}},
		{Name: "selftest", Summary: "短自检（只读）", NonInteractive: true,
			StableExitCodes: []int{0, 1, 2}},
		{Name: "commands", Summary: "命令表（机器可读）", NonInteractive: true,
			StableExitCodes: []int{0}},
	}
}

func cliCommandsCommand(env cliEnv, args []string) error {
	fs, configPath := cliFlags(&env, "commands")
	if err := applyParsedFlags(&env, fs, configPath, args); err != nil {
		return err
	}
	rows := cliCommandTable()
	if env.json {
		writeCLIJSON(env, map[string]any{"ok": true, "commands": rows,
			"exit_codes": map[string]int{"ok": cliExitOK, "failure": cliExitFailure,
				"usage": cliExitUsage, "not_ready": cliExitNotReady,
				"conflict": cliExitConflict, "secret_delivery": cliExitSecretLost}})
		return nil
	}
	for _, row := range rows {
		confirm := ""
		if row.Confirm != "" {
			confirm = " confirm=" + row.Confirm
		}
		fmt.Fprintf(env.stdout, "%-18s %s%s\n", row.Name, row.Summary, confirm)
	}
	return nil
}

// ---------------------------------------------------------------- helpers

// mustAbs 返回绝对路径；失败时退回原值（错误由后续文件操作报告）。
func mustAbs(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return ""
	}
	absolute, err := filepath.Abs(trimmed)
	if err != nil {
		return trimmed
	}
	return absolute
}

// boolFlagValue 读取已解析布尔 flag。
func boolFlagValue(fs *flag.FlagSet, name string) bool {
	value := fs.Lookup(name)
	return value != nil && value.Value.String() == "true"
}

// emptyText 返回空值替代文本。
func emptyText(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

// localOperator 返回本地维护操作者标识（仅 OS 事实，不接受请求自报）。
func localOperator(configPath string) string {
	instanceDir := filepath.Dir(mustAbs(configPath))
	identity, err := setupconsole.LocalMaintenanceIdentity(instanceDir)
	if err != nil {
		return "local-os:unknown@unknown"
	}
	return localOperatorID(identity)
}

// cliOperatorOptions 返回本地维护身份与实例目录（不写日志秘密）。
func cliOperatorOptions(configPath, instanceDir, masterKeyFile, purpose string) (setupconsole.RootInitOptions, error) {
	instanceDir = strings.TrimSpace(instanceDir)
	if instanceDir == "" {
		instanceDir = filepath.Dir(mustAbs(configPath))
	}
	identity, err := setupconsole.LocalMaintenanceIdentity(instanceDir)
	if err != nil {
		return setupconsole.RootInitOptions{}, &cliFailure{Code: "LOCAL_IDENTITY_FAILED",
			Message: err.Error(), Exit: cliExitFailure}
	}
	return setupconsole.RootInitOptions{ConfigPath: mustAbs(configPath),
		InstanceDir: instanceDir, OperatorID: localOperatorID(identity),
		Purpose: purpose, MasterKeyFile: masterKeyFile}, nil
}

// readCLISecret 按受限通道读取密码；不使用命令行参数。
func readCLISecret(env cliEnv, label string, fromStdin bool, filePath string, generate bool) (string, bool, error) {
	channels := 0
	if fromStdin {
		channels++
	}
	if strings.TrimSpace(filePath) != "" {
		channels++
	}
	if generate {
		channels++
	}
	if channels != 1 {
		return "", false, &cliFailure{Code: "SECRET_CHANNEL_REQUIRED", Exit: cliExitUsage,
			Message: fmt.Sprintf("%s 密码必须且只能选择一种受限通道：--password-stdin、--password-file 或 --generate-password", label)}
	}
	if generate {
		return "", true, nil
	}
	if fromStdin {
		password, err := readPasswordLine(env.stdin)
		if err != nil {
			return "", false, &cliFailure{Code: "SECRET_READ_FAILED",
				Message: "从标准输入读取密码失败：" + err.Error(), Exit: cliExitUsage}
		}
		return password, false, nil
	}
	raw, err := securefile.Read(filepath.Clean(strings.TrimSpace(filePath)),
		securefile.DefaultMaxBytes)
	if err != nil {
		return "", false, &cliFailure{Code: "SECRET_READ_FAILED",
			Message: "读取密码受限文件失败（需 0600/DACL 受限普通文件，拒绝符号链接与超限）：" + err.Error(),
			Exit:    cliExitUsage}
	}
	password := firstLine(string(raw))
	if strings.TrimSpace(password) == "" {
		return "", false, &cliFailure{Code: "SECRET_EMPTY", Exit: cliExitUsage,
			Message: "密码受限文件为空"}
	}
	return password, false, nil
}

// readPasswordLine 从流读取一行密码（去掉行尾 CR/LF；不记录/回显）。
// 若标准输入是真实 TTY，使用 term.ReadPassword 关闭回显，避免密码显示在终端。
func readPasswordLine(reader io.Reader) (string, error) {
	if reader == nil {
		return "", errors.New("标准输入不可用")
	}
	if fdReader, ok := reader.(interface{ Fd() uintptr }); ok {
		fd := int(fdReader.Fd())
		if term.IsTerminal(fd) {
			raw, err := term.ReadPassword(fd)
			if err != nil {
				return "", err
			}
			password := firstLine(string(raw))
			if strings.TrimSpace(password) == "" {
				return "", errors.New("标准输入没有密码内容")
			}
			return password, nil
		}
	}
	raw, err := io.ReadAll(io.LimitReader(reader, 64<<10))
	if err != nil {
		return "", err
	}
	password := firstLine(string(raw))
	if strings.TrimSpace(password) == "" {
		return "", errors.New("标准输入没有密码内容")
	}
	return password, nil
}
func firstLine(text string) string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	if index := strings.IndexByte(text, '\n'); index >= 0 {
		text = text[:index]
	}
	text = strings.TrimSuffix(text, "\r")
	return text
}

// deliverGeneratedPassword 把一次性密码交给显式通道；没有通道时拒绝继续（避免秘密丢失）。
// 文件通道使用 securefile.Write：新建（拒绝覆盖）、平台化 ACL/0600 加固并自检，失败 fail-closed。
func deliverGeneratedPassword(env cliEnv, password, filePath string, printToStdout bool) error {
	if password == "" {
		return nil
	}
	if env.json && printToStdout {
		return &cliFailure{Code: "SECRET_CHANNEL_CONFLICT", Exit: cliExitUsage,
			Message: "JSON 模式禁止 --print-generated：一次性密码会进入自动日志/管道；请用 --generated-password-file 受控文件交付"}
	}
	delivered := false
	if path := strings.TrimSpace(filePath); path != "" {
		absolute := mustAbs(path)
		if err := securefile.Write(absolute, []byte(password+"\n")); err != nil {
			return &cliFailure{Code: "SECRET_FILE_FAILED", Exit: cliExitSecretLost,
				Message: "写入一次性密码受保护文件失败：" + err.Error()}
		}
		delivered = true
		message := fmt.Sprintf("一次性密码已写入受控文件：%s（仅当前用户/系统/管理员可访问；请立即妥善保存并删除）\n",
			absolute)
		if env.json {
			// JSON 模式不打印密码本身，只报告交付路径（stderr 提示）。
			fmt.Fprint(env.stderr, message)
		} else {
			fmt.Fprint(env.stdout, message)
		}
	}
	if printToStdout {
		fmt.Fprintln(env.stdout, "一次性密码（仅本次显示，请立即保存）：", password)
		delivered = true
	}
	if !delivered {
		return &cliFailure{Code: "SECRET_DELIVERY_REQUIRED", Exit: cliExitSecretLost,
			Message: "已生成一次性密码但没有显式交付通道：请加 --generated-password-file <受保护新文件> 或 --print-generated；本次操作结果不可重取"}
	}
	return nil
}

// precheckGeneratedPasswordDelivery 在解析参数后、任何状态变更前统一检查一次性密码
// 交付通道与 JSON 冲突，避免先生成/写库再因无法安全交付而留下半提交（M3 MEDIUM-R1）。
func precheckGeneratedPasswordDelivery(env cliEnv, fs *flag.FlagSet) error {
	if !boolFlagValue(fs, "generate-password") {
		return nil
	}
	if !passwordDeliveryRequested(fs) {
		return &cliFailure{Code: "SECRET_DELIVERY_REQUIRED", Exit: cliExitUsage,
			Message: "自动生成密码前必须指定交付通道：--generated-password-file <受保护新文件> 或 --print-generated（避免生成后无法取回）"}
	}
	if env.json && boolFlagValue(fs, "print-generated") {
		return &cliFailure{Code: "SECRET_CHANNEL_CONFLICT", Exit: cliExitUsage,
			Message: "JSON 模式禁止 --print-generated：一次性密码会进入自动日志/管道；请在状态变更前改用 --generated-password-file 受控文件交付"}
	}
	return nil
}

// passwordDeliveryRequested 报告是否提供了任何一次性密码交付通道。
func passwordDeliveryRequested(fs *flag.FlagSet) bool {
	return strings.TrimSpace(fs.Lookup("generated-password-file").Value.String()) != "" ||
		boolFlagValue(fs, "print-generated")
}

// nowUTC 供需要显式时钟的输出使用（当前命令不直接使用，保留给未来扩展测试注入）。
var _ = time.Now
