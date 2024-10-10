package setupconsole

// 实例状态检测（步骤277）。
//
// 目标：在**不依赖 app.Open、不启动服务、不迁移、不写库**的前提下，判断一个实例目录/
// 配置路径当前处于哪种状态：
//
//	no-config            配置文件不存在
//	config-unreadable    配置文件存在但不可读/过大
//	config-invalid       YAML 语法、重复键、类型、未知字段、校验失败等
//	db-not-configured    配置有效但数据库路径为空或非 SQLite
//	db-missing           数据库文件尚不存在
//	db-unreachable       数据库存在但无法连接/查询
//	migration-pending    数据库可连但迁移记录不完整（含空库）
//	root-missing         结构完整但没有唯一 root
//	ready                配置/数据库/结构/root 均就绪
//
// 检测失败只返回状态与结构化诊断，不尝试修复、不创建文件、不写 WAL/迁移/root 数据。

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/config"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// StateKind 是实例状态类别。
type StateKind string

const (
	StateNoConfig         StateKind = "no-config"
	StateConfigUnreadable StateKind = "config-unreadable"
	StateConfigInvalid    StateKind = "config-invalid"
	StateDatabaseNotConf  StateKind = "db-not-configured"
	StateDatabaseMissing  StateKind = "db-missing"
	StateDatabaseDown     StateKind = "db-unreachable"
	StateDatabaseInvalid  StateKind = "db-invalid"
	StateMigrationPending StateKind = "migration-pending"
	StateRootMissing      StateKind = "root-missing"
	StateReady            StateKind = "ready"
	StateError            StateKind = "error"
)

// Label 返回中文状态标签。
func (kind StateKind) Label() string {
	switch kind {
	case StateNoConfig:
		return "尚未配置（配置文件不存在）"
	case StateConfigUnreadable:
		return "配置文件不可读"
	case StateConfigInvalid:
		return "配置存在错误"
	case StateDatabaseNotConf:
		return "数据库尚未配置"
	case StateDatabaseMissing:
		return "数据库文件尚未建立"
	case StateDatabaseDown:
		return "数据库连接失败"
	case StateDatabaseInvalid:
		return "数据库文件无效（不是有效 SQLite 数据库）"
	case StateMigrationPending:
		return "数据库结构待迁移"
	case StateRootMissing:
		return "尚未创建 root 账户"
	case StateReady:
		return "实例就绪"
	default:
		return "状态未知"
	}
}

// ConfigIssue 是可直接展示的配置诊断（不含秘密值）。
type ConfigIssue struct {
	Kind       string
	Source     string
	Field      string
	Line       int
	Detail     string
	Suggestion string
}

// Detection 是一次只读检测结果。
type Detection struct {
	Kind         StateKind
	ConfigPath   string
	ConfigLoaded bool
	Config       config.Config
	Issues       []ConfigIssue
	DatabasePath string
	AppliedCount int
	LatestCount  int
	RootUserID   string
	Summary      string
	Details      []string
	Err          error
}

// DetectOptions 控制检测输入（测试可注入迁移清单）。
type DetectOptions struct {
	ConfigPath string
}

// Detect 对给定配置路径执行只读状态检测。
func Detect(ctx context.Context, options DetectOptions) Detection {
	detection := Detection{Kind: StateError, ConfigPath: options.ConfigPath}
	if ctx == nil {
		ctx = context.Background()
	}
	configPath := strings.TrimSpace(options.ConfigPath)
	if configPath == "" {
		detection.Kind = StateNoConfig
		detection.Summary = "未指定配置文件路径"
		detection.Details = append(detection.Details,
			"可先用“选择实例配置”指定 login.yaml 路径，或在实例目录放置 login.yaml。")
		return detection
	}
	detection.Details = append(detection.Details, "配置文件："+configPath)
	info, statErr := os.Stat(configPath)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			detection.Kind = StateNoConfig
			detection.Summary = "配置文件不存在"
			detection.Details = append(detection.Details,
				"这是全新实例：可退出后用本地初始化流程创建配置与数据库（后续步骤）。")
			return detection
		}
		detection.Kind = StateConfigUnreadable
		detection.Summary = "配置文件无法读取"
		detection.Details = append(detection.Details,
			"请检查文件路径、权限与占用情况；错误："+publicFileError(statErr))
		return detection
	}
	if info.IsDir() {
		detection.Kind = StateConfigUnreadable
		detection.Summary = "配置路径是目录而不是文件"
		return detection
	}
	if info.Size() > 1<<20 {
		detection.Kind = StateConfigInvalid
		detection.Summary = "配置文件过大（超过 1 MiB）"
		detection.Issues = append(detection.Issues, ConfigIssue{Kind: "invalid-options",
			Source: "loader", Detail: "配置文件超过大小上限，拒绝加载",
			Suggestion: "确认路径是否正确；不要载入非配置文件。"})
		return detection
	}
	cfg, loadErr := config.Load(config.LoadOptions{YAMLFile: configPath})
	if loadErr != nil {
		detection.Kind = StateConfigInvalid
		detection.Summary = "配置解析或校验失败"
		detection.Issues = configIssues(loadErr)
		for _, issue := range detection.Issues {
			line := ""
			if issue.Line > 0 {
				line = fmt.Sprintf("第 %d 行 ", issue.Line)
			}
			field := ""
			if issue.Field != "" {
				field = "[" + issue.Field + "] "
			}
			detection.Details = append(detection.Details,
				fmt.Sprintf("%s%s%s：%s", line, field, issue.Kind, issue.Detail))
		}
		return detection
	}
	detection.ConfigLoaded = true
	detection.Config = cfg
	// 配置存在但没有顶层 database 段：视为“数据库尚未配置”（全新实例），
	// 不和“默认路径文件缺失”混为一谈；用原始文本做保守的顶层键检测。
	if rawConfig, readErr := os.ReadFile(configPath); readErr == nil &&
		!hasTopLevelYAMLKey(rawConfig, "database") {
		detection.Kind = StateDatabaseNotConf
		detection.Summary = "配置中没有 database 段"
		detection.Details = append(detection.Details,
			"全新实例尚未选择数据库；数据库设置/连接测试归后续初始画面。")
		return detection
	}
	// 数据库：本轮运行验证只支持 SQLite；其他数据库只静态支持，如实显示未配置。
	driver := strings.ToLower(strings.TrimSpace(string(cfg.Database.Driver)))
	if driver != "" && driver != string(config.DatabaseDriverSQLite) {
		detection.Kind = StateDatabaseNotConf
		detection.Summary = "数据库驱动不是 SQLite"
		detection.Details = append(detection.Details,
			"当前控制台运行验证仅支持本地 SQLite；其他数据库适配保留但未在本平台运行。")
		return detection
	}
	databasePath := strings.TrimSpace(cfg.Database.Path)
	detection.DatabasePath = databasePath
	if databasePath == "" {
		detection.Kind = StateDatabaseNotConf
		detection.Summary = "配置未提供数据库路径"
		return detection
	}
	detection.Details = append(detection.Details, "数据库路径："+databasePath)
	if _, err := os.Stat(databasePath); err != nil {
		if os.IsNotExist(err) {
			detection.Kind = StateDatabaseMissing
			detection.Summary = "数据库文件尚不存在"
			detection.Details = append(detection.Details,
				"这是尚未初始化的实例；本地初始化/备份恢复归后续步骤。")
			return detection
		}
		detection.Kind = StateDatabaseDown
		detection.Summary = "数据库文件无法访问"
		detection.Details = append(detection.Details, "错误："+publicFileError(err))
		return detection
	}
	// 只读检测：WAL=false、单连接、只执行 SELECT；不迁移、不写审计/用户/root。
	store, openErr := storagesqlite.Open(ctx, storagesqlite.Options{
		Path: databasePath, WAL: false, MaxOpenConns: 1, MaxIdleConns: 1,
	})
	if openErr != nil {
		failureKind, failureCode := classifyDatabaseError(openErr)
		if failureKind == StateDatabaseInvalid {
			detection.Kind = StateDatabaseInvalid
			detection.Summary = "数据库文件不是有效的 SQLite 数据库"
			detection.Details = append(detection.Details,
				"底层错误码："+failureCode+"；文件可能损坏或根本不是 SQLite 数据库。")
			return detection
		}
		detection.Kind = StateDatabaseDown
		detection.Summary = "数据库连接失败"
		detection.Details = append(detection.Details, "错误："+publicFileError(openErr))
		return detection
	}
	defer func() { _ = store.Close() }()
	migrationList, migrationErr := migrate.LoadMigrations(migrations.SQLite)
	if migrationErr != nil {
		detection.Kind = StateError
		detection.Summary = "无法读取迁移清单"
		detection.Err = migrationErr
		return detection
	}
	detection.LatestCount = len(migrationList)
	applied, appliedErr := queryAppliedMigrations(ctx, store.DB())
	if appliedErr != nil {
		// 区分底层错误：非 SQLite 文件/损坏（SQLITE_NOTADB/SQLITE_CORRUPT）、
		// 缺少 schema_history 表（空库/未初始化）、其他连接/查询故障。
		failureKind, failureCode := classifyDatabaseError(appliedErr)
		switch failureKind {
		case StateDatabaseInvalid:
			detection.Kind = StateDatabaseInvalid
			detection.Summary = "数据库文件不是有效的 SQLite 数据库"
			detection.Details = append(detection.Details,
				"底层错误码："+failureCode+"；文件可能损坏或根本不是 SQLite 数据库。",
				"检测不会修复/替换/清空该文件；请先确认数据来源或用备份恢复（后续步骤）。")
			return detection
		case StateMigrationPending:
			detection.Kind = StateMigrationPending
			detection.Summary = "数据库结构未初始化（缺少迁移记录）"
			detection.Details = append(detection.Details,
				"数据库存在但没有可用的 schema_history 表（底层码 "+failureCode+
					"）；可能为空文件或未完成初始化。")
			return detection
		default:
			detection.Kind = StateDatabaseDown
			detection.Summary = "数据库查询失败"
			detection.Details = append(detection.Details,
				"底层错误码："+failureCode+"；错误："+publicFileError(appliedErr))
			return detection
		}
	}
	detection.AppliedCount = applied
	if applied < detection.LatestCount {
		detection.Kind = StateMigrationPending
		detection.Summary = fmt.Sprintf("数据库结构待迁移（已应用 %d/%d）",
			applied, detection.LatestCount)
		detection.Details = append(detection.Details,
			"需要执行迁移才能进入维护画面；迁移执行归后续初始化/维护步骤。")
		return detection
	}
	rootUserID, rootErr := queryRootUserID(ctx, store.DB())
	if rootErr != nil {
		failureKind, failureCode := classifyDatabaseError(rootErr)
		if failureKind == StateDatabaseInvalid {
			detection.Kind = StateDatabaseInvalid
			detection.Summary = "数据库文件不是有效的 SQLite 数据库"
			detection.Details = append(detection.Details,
				"底层错误码："+failureCode+"；文件可能损坏或根本不是 SQLite 数据库。")
			return detection
		}
		detection.Kind = StateDatabaseDown
		detection.Summary = "数据库查询失败"
		detection.Details = append(detection.Details,
			"底层错误码："+failureCode+"；错误："+publicFileError(rootErr))
		return detection
	}
	detection.RootUserID = rootUserID
	if rootUserID == "" {
		detection.Kind = StateRootMissing
		detection.Summary = "尚未创建 root 账户"
		detection.Details = append(detection.Details,
			"数据库中还没有唯一 root；创建 root 归本地初始化步骤（后续 WS2）。")
		return detection
	}
	detection.Kind = StateReady
	detection.Summary = "实例就绪"
	detection.Details = append(detection.Details, "root 用户 ID："+rootUserID)
	return detection
}

// configIssues 把配置错误映射为展示模型（不展开秘密值）。
func configIssues(err error) []ConfigIssue {
	var configErrors config.ConfigErrors
	if errors.As(err, &configErrors) {
		issues := make([]ConfigIssue, 0, len(configErrors))
		for _, item := range configErrors {
			if item == nil {
				continue
			}
			issues = append(issues, ConfigIssue{Kind: item.Kind.String(),
				Source: item.Source, Field: item.Field, Line: item.Line,
				Detail:     item.Detail,
				Suggestion: suggestionFor(item.Kind)})
		}
		return issues
	}
	return []ConfigIssue{{Kind: "options", Detail: "配置加载失败：" + publicFileError(err)}}
}

// suggestionFor 给出按错误种类的修复建议。
func suggestionFor(kind config.ConfigErrorKind) string {
	switch kind {
	case config.ConfigErrorYAMLSyntax:
		return "按行列提示修复缩进/引号/冒号，或从上一有效副本恢复；控制台不会自动覆盖坏文件。"
	case config.ConfigErrorDuplicateKey:
		return "删除重复键，只保留一个取值。"
	case config.ConfigErrorUnknownField:
		return "删除或改名未定义字段；控制台保留未知字段但不把它们当作已支持配置。"
	case config.ConfigErrorType:
		return "按字段类型修改取值（布尔/数字/字符串/列表）。"
	case config.ConfigErrorValue:
		return "选择允许的枚举值或修正字段内容。"
	case config.ConfigErrorRange:
		return "把数值调整到允许范围。"
	case config.ConfigErrorConflict:
		return "按提示调整互斥字段组合。"
	case config.ConfigErrorSecretSource:
		return "检查秘密来源引用（env:/file:）是否可读；控制台不显示秘密明文。"
	default:
		return "按提示修正配置后重新检测。"
	}
}

// hasTopLevelYAMLKey 保守判断 YAML 文本是否存在指定顶层键（行首、非注释）。
func hasTopLevelYAMLKey(raw []byte, key string) bool {
	prefix := key + ":"
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimRight(line, "\r")
		if strings.HasPrefix(trimmed, prefix) {
			return true
		}
	}
	return false
}

// classifyDatabaseError 把底层数据库错误归入稳定状态与稳定错误码。
//
// 只做分类，不尝试修复/打开/写库：
//   - SQLITE_NOTADB（code 26）/“file is not a database” → db-invalid；
//   - SQLITE_CORRUPT（code 11）/malformed → db-invalid（区分码 SQLITE_CORRUPT）；
//   - 缺少 schema_history 表 → migration-pending（SQLITE_NO_TABLE）；
//   - 其他连接/查询故障 → db-unreachable（DB_QUERY_FAILED 或带 SQLite 数字码）。
func classifyDatabaseError(err error) (StateKind, string) {
	if err == nil {
		return StateDatabaseDown, "DB_QUERY_FAILED"
	}
	sqliteCode := 0
	var coded interface{ Code() int }
	if errors.As(err, &coded) {
		sqliteCode = coded.Code()
	}
	message := strings.ToLower(err.Error())
	switch {
	case sqliteCode == 26 || strings.Contains(message, "not a database"):
		return StateDatabaseInvalid, "SQLITE_NOTADB"
	case sqliteCode == 11 || strings.Contains(message, "malformed"),
		strings.Contains(message, "corrupt"):
		return StateDatabaseInvalid, "SQLITE_CORRUPT"
	case strings.Contains(message, "no such table"):
		return StateMigrationPending, "SQLITE_NO_TABLE"
	default:
		return StateDatabaseDown, fmt.Sprintf("DB_QUERY_FAILED(%d)", sqliteCode)
	}
}

// queryAppliedMigrations 读取已应用迁移数量；表不存在时返回错误（空库/未初始化）。
func queryAppliedMigrations(ctx context.Context, db *sql.DB) (int, error) {
	var count int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM schema_history`).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// queryRootUserID 读取唯一 root 用户 ID；没有 root 时返回空串。
func queryRootUserID(ctx context.Context, db *sql.DB) (string, error) {
	var rootUserID string
	err := db.QueryRowContext(ctx, `SELECT root_user_id FROM root_initializations
WHERE singleton=1 AND root_user_id IS NOT NULL AND root_user_id <> '' LIMIT 1`).
		Scan(&rootUserID)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return rootUserID, nil
}

// publicFileError 把文件/数据库错误转成可展示但不含内部路径细节的描述。
func publicFileError(err error) string {
	if err == nil {
		return ""
	}
	message := strings.TrimSpace(err.Error())
	if len(message) > 240 {
		message = message[:240] + "…"
	}
	return message
}
