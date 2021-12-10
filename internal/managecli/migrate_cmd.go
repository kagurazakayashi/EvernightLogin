// 本文件实现 `loginctl migrate` 命令：只读迁移状态与受确认保护的迁移执行。
//
// 约束：
//   - status 只读 schema_history/schema_failures，与内嵌迁移目录比较，不执行迁移。
//   - apply 要求显式 --confirm MIGRATE 与 --service-stopped：迁移会修改数据库结构，
//     必须确认服务已停止，避免与运行中的服务并发迁移。
//   - 存在未知已应用版本（数据库来自更新版本）时拒绝执行，不做隐式降级/清除。
package managecli

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// migrateCommandUsage 是 migrate 组帮助。
const migrateCommandUsage = `用法：
  loginctl migrate status [--config <file>] [--json]
  loginctl migrate apply [--config <file>] --confirm MIGRATE --service-stopped [--json]

说明：
  - status 只读，不修改数据库；当前版本不一致时退出码为 1。
  - apply 会执行未应用的内嵌迁移，可能修改数据库结构；必须显式确认服务已停止。
  - 数据库版本高于内嵌迁移（未知已应用版本）时拒绝执行，避免降级破坏数据。`

// runMigrate 分派 migrate 子命令。
func (r *runner) runMigrate(args []string) int {
	r.usageText = migrateCommandUsage
	if len(args) == 0 {
		return r.helpText("migrate", migrateCommandUsage)
	}
	subcommand, rest := args[0], args[1:]
	r.command = "migrate " + subcommand
	switch subcommand {
	case "status":
		return r.runMigrateStatus(rest)
	case "apply":
		return r.runMigrateApply(rest)
	case "help", "-h", "--help":
		return r.helpText("migrate", migrateCommandUsage)
	default:
		return r.usage("未知的 migrate 子命令 %q（可用：status/apply）", subcommand)
	}
}

// runMigrateStatus 输出迁移状态。
func (r *runner) runMigrateStatus(args []string) int {
	values, positional, err := parseFlags(args, []flagDef{
		{name: "config", value: true}, {name: "json"},
	})
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 0 {
		return r.usage("migrate status 不接受位置参数")
	}
	r.json = boolFlag(values, "json")
	config, exit := r.loadEffectiveConfig(values)
	if exit != ExitOK {
		return exit
	}
	store, exit := r.openDatabaseReadOnly(config)
	if exit != ExitOK {
		return exit
	}
	defer func() { _ = store.Close() }()
	report, err := inspectMigrations(r.ctx, store)
	if err != nil {
		return r.fail("DB_UNAVAILABLE", ExitError, "读取迁移状态失败", nil)
	}
	if r.json {
		envelope := jsonEnvelope{OK: report.Current, Command: r.command, Data: report}
		if !report.Current {
			envelope.Error = &jsonError{Code: "MIGRATION_NOT_CURRENT",
				Message: "数据库迁移状态不是最新", Details: report}
			envelope.Data = nil
		}
		r.writeEnvelope(envelope)
	} else {
		fmt.Fprintf(r.stdout, "已应用 %d 个迁移，当前版本 %s；内嵌最新版本 %s。\n",
			report.AppliedCount, valueOrUnknown(report.AppliedVersion),
			valueOrUnknown(report.EmbeddedVersion))
		printStringList(r.stdout, "待应用", report.Pending)
		printStringList(r.stdout, "未知已应用版本", report.UnknownApplied)
		printStringList(r.stdout, "校验和不一致", report.ChecksumMismatch)
		printStringList(r.stdout, "迁移失败记录", report.Failed)
		if report.Current {
			fmt.Fprintln(r.stdout, "状态：已是最新。")
		} else {
			fmt.Fprintln(r.stdout, "状态：不是最新（见上）。")
		}
	}
	if report.Current {
		return ExitOK
	}
	return ExitError
}

// runMigrateApply 在确认服务已停止后执行迁移。
func (r *runner) runMigrateApply(args []string) int {
	values, positional, err := parseFlags(args, []flagDef{
		{name: "config", value: true}, {name: "json"},
		{name: "confirm", value: true}, {name: "service-stopped"},
	})
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 0 {
		return r.usage("migrate apply 不接受位置参数")
	}
	r.json = boolFlag(values, "json")
	if stringFlag(values, "confirm") != "MIGRATE" {
		return r.usage("执行迁移必须显式确认：--confirm MIGRATE")
	}
	if !boolFlag(values, "service-stopped") {
		return r.usage("执行迁移必须确认服务已停止：--service-stopped")
	}
	config, exit := r.loadEffectiveConfig(values)
	if exit != ExitOK {
		return exit
	}
	// migrate apply 是数据库初始化的合法入口：允许在目标文件尚不存在时创建它；
	// 仍拒绝目录不存在或非普通文件目标，避免写错路径。
	path, exit := r.dataPath(config)
	if exit != ExitOK {
		return exit
	}
	if info, statErr := os.Lstat(path); statErr == nil &&
		(info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return r.fail("DATABASE_PATH_INVALID", ExitError,
			"数据库路径不是普通文件（不接受符号链接或目录）", nil)
	}
	store, err := storagesqlite.Open(r.ctx, storagesqlite.Options{Path: path,
		WAL:         config.Database.WAL,
		BusyTimeout: time.Duration(config.Database.BusyTimeoutMS) * time.Millisecond})
	if err != nil {
		return r.fail("DB_UNAVAILABLE", ExitError, "无法打开/创建数据库", nil)
	}
	defer func() { _ = store.Close() }()
	// 先读状态：存在未知已应用版本（数据库比当前程序新）时拒绝，避免降级。
	before, err := inspectMigrations(r.ctx, store)
	if err != nil {
		return r.fail("DB_UNAVAILABLE", ExitError, "读取迁移状态失败", nil)
	}
	if len(before.UnknownApplied) > 0 {
		return r.fail("MIGRATION_DOWNGRADE_REFUSED", ExitConflict,
			"数据库包含当前程序未知的迁移版本，拒绝执行（请升级程序或恢复匹配版本）",
			before.UnknownApplied)
	}
	embedded, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		return r.fail("MIGRATION_SET_INVALID", ExitError, "加载内嵌迁移失败", nil)
	}
	result, migrateErr := store.Migrate(r.ctx, embedded)
	applied := make([]string, 0, len(result.Applied))
	for _, item := range result.Applied {
		applied = append(applied, item.Version)
	}
	output := map[string]any{"applied": applied, "up_to_date": result.UpToDate}
	if migrateErr != nil {
		return r.fail("MIGRATION_FAILED", ExitError, "迁移执行失败："+migrateErr.Error(), output)
	}
	return r.succeedWithText(output, "迁移完成：本次应用 %d 个（%v），当前已是最新：%t。\n",
		len(applied), applied, result.UpToDate)
}

// valueOrUnknown 把空版本显示为“未知”，不伪造 0。
func valueOrUnknown(value string) string {
	if value == "" {
		return "未知"
	}
	return value
}

// printStringList 输出非空列表；空列表输出“无”。
func printStringList(out io.Writer, label string, values []string) {
	if len(values) == 0 {
		fmt.Fprintf(out, "%s：无\n", label)
		return
	}
	fmt.Fprintf(out, "%s：%v\n", label, values)
}
