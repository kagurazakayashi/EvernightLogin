package setupconsole

// 步骤 285：三套推荐配置与一键初始应用。
//
// 边界（AGENTS §14.2/§14.4）：
//   - 本机快速体验、内网独立服务、嵌入业务三套版本化方案；缺域名/证书/SMTP 等
//     真实输入时列为“待配置项”或保持功能关闭，不声称已可公网 HTTPS/发邮件；
//   - 本机方案默认只监听回环地址；嵌入方案不自动监听（监听由宿主决定）；
//   - 应用前给出配置与数据库操作计划；文件保存与数据库迁移分别返回真实结果，
//     不把两者当作一个跨资源事务；
//   - 可在数据库/root 已完成后一键应用配置并补迁移；root/账户创建仍走各自显式
//     画面（需要密码/方案输入，不在本文件静默生成账户）。

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/config"
)

// 285 错误。
var (
	// ErrRecommendationInvalid 表示推荐配置草稿未通过正式校验。
	ErrRecommendationInvalid = errors.New("推荐配置未通过校验")
	// ErrRecommendationProfileUnknown 表示未知方案键。
	ErrRecommendationProfileUnknown = errors.New("未知推荐配置方案")
)

// RecommendationProfile 是一套版本化推荐配置方案。
type RecommendationProfile struct {
	Key         string
	Label       string
	Description string
	// Fields 是写入配置草稿的字段/值（点分路径）。
	Fields map[string]any
	// Unset 是必须删除的字段路径（避免继承旧实例的矛盾值）。
	Unset []string
	// Pending 是需要操作者后续提供的真实输入（域名/证书/SMTP 等）；对应功能保持
	// 关闭或标注待配置，不伪造可用。
	Pending []string
	Notes   []string
}

// RecommendationProfiles 返回三套推荐方案（顺序固定，供画面编号选择）。
func RecommendationProfiles() []RecommendationProfile {
	return []RecommendationProfile{
		{Key: "local", Label: "本机快速体验",
			Description: "默认只监听 127.0.0.1，SQLite 本地库，邮件/注册/协议等外部能力关闭。",
			Fields: map[string]any{
				"server.listen_addr":           "127.0.0.1:8080",
				"server.path_prefix":           "",
				"server.public_base_url":       "http://127.0.0.1:8080",
				"server.tls_terminating_proxy": false,
				"logging.level":                "info",
				"logging.format":               "text",
				"database.driver":              "sqlite",
				"database.path":                "database/login.db",
				"database.wal":                 true,
				"database.busy_timeout_ms":     5000,
				"registration.enabled":         false,
				"passkey.enabled":              false,
				"protocol.enabled":             false,
				"mail.enabled":                 false,
				"manual_recovery.enabled":      false,
			},
			Unset: []string{"database.host", "database.port", "database.username",
				"database.password", "database.name", "database.tls_mode"},
			Notes: []string{"只监听回环地址，不暴露到局域网/公网。",
				"邮件、注册、OAuth/OIDC 协议默认关闭；需要时在详细设置中显式配置并测试。"},
		},
		{Key: "intranet", Label: "内网独立服务",
			Description: "内网服务监听，SQLite 本地库；域名/证书/SMTP 等待配置，相关能力保持关闭。",
			Fields: map[string]any{
				"server.listen_addr":           "0.0.0.0:8080",
				"server.path_prefix":           "",
				"server.public_base_url":       "",
				"server.tls_terminating_proxy": false,
				"logging.level":                "info",
				"logging.format":               "text",
				"database.driver":              "sqlite",
				"database.path":                "database/login.db",
				"database.wal":                 true,
				"database.busy_timeout_ms":     5000,
				"registration.enabled":         false,
				"passkey.enabled":              false,
				"protocol.enabled":             false,
				"mail.enabled":                 false,
				"manual_recovery.enabled":      false,
			},
			Unset: []string{"database.host", "database.port", "database.username",
				"database.password", "database.name", "database.tls_mode"},
			Pending: []string{"对外访问域名/固定地址（server.public_base_url）",
				"TLS 证书与私钥或反向代理信任边界", "SMTP 服务器与发件人（否则邮件能力保持关闭）",
				"OAuth/OIDC Issuer 与资源服务（启用前必须配置）"},
			Notes: []string{"监听所有接口前请确认网络边界与防火墙；无 TLS 时不要让认证页面暴露在不可信网络。",
				"未提供域名/证书/SMTP 时对应能力保持关闭，不声称已可用。"},
		},
		{Key: "embedding", Label: "嵌入业务",
			Description: "作为 Go Module 嵌入宿主：配置保守默认，监听与生命周期由宿主决定。",
			Fields: map[string]any{
				"server.listen_addr":           "127.0.0.1:8080",
				"server.path_prefix":           "",
				"server.public_base_url":       "",
				"server.tls_terminating_proxy": false,
				"logging.level":                "info",
				"logging.format":               "text",
				"database.driver":              "sqlite",
				"database.path":                "database/login.db",
				"database.wal":                 true,
				"database.busy_timeout_ms":     5000,
				"registration.enabled":         false,
				"passkey.enabled":              false,
				"protocol.enabled":             false,
				"mail.enabled":                 false,
				"manual_recovery.enabled":      false,
			},
			Unset: []string{"database.host", "database.port", "database.username",
				"database.password", "database.name", "database.tls_mode"},
			Pending: []string{"宿主监听地址与公开 URL（由宿主决定）",
				"宿主主密钥与数据库路径注入方式", "宿主所需协议/邮件能力（默认关闭）"},
			Notes: []string{"嵌入模式不自动监听、不启动后台任务；由宿主显式决定生命周期。",
				"数据库路径/主密钥建议由宿主显式注入，不要依赖控制台进程当前目录。"},
		},
	}
}

// LookupRecommendationProfile 按 key 查找方案。
func LookupRecommendationProfile(key string) (RecommendationProfile, error) {
	key = strings.TrimSpace(key)
	for _, profile := range RecommendationProfiles() {
		if profile.Key == key {
			return profile, nil
		}
	}
	return RecommendationProfile{}, fmt.Errorf("%w: %q", ErrRecommendationProfileUnknown, key)
}

// RecommendationPlan 是应用前的配置与数据库操作计划。
type RecommendationPlan struct {
	Profile        RecommendationProfile
	ConfigPath     string
	InstanceDir    string
	Draft          *ConfigDraft
	Raw            []byte
	Report         ConfigReport
	Issues         []string
	Pending        []string
	Notes          []string
	Steps          []string
	RequiresDBInit bool
	ConfigExists   bool
}

// PlanRecommendation 生成配置草稿与操作计划；不写盘、不建库。
func PlanRecommendation(configPath string, profileKey string) (RecommendationPlan, error) {
	profile, err := LookupRecommendationProfile(profileKey)
	if err != nil {
		return RecommendationPlan{}, err
	}
	configPath = strings.TrimSpace(configPath)
	plan := RecommendationPlan{Profile: profile, ConfigPath: configPath,
		Pending: append([]string(nil), profile.Pending...),
		Notes:   append([]string(nil), profile.Notes...)}
	if configPath != "" {
		absoluteConfig, absErr := filepath.Abs(configPath)
		if absErr != nil {
			return plan, fmt.Errorf("配置路径无效: %w", absErr)
		}
		plan.ConfigPath = absoluteConfig
		plan.InstanceDir = filepath.Dir(absoluteConfig)
	}
	report := LoadConfigReport(plan.ConfigPath)
	plan.ConfigExists = report.Exists
	draft, draftErr := NewConfigDraft(plan.ConfigPath, report.Raw)
	if draftErr != nil {
		return plan, fmt.Errorf("配置文件解析失败: %w", draftErr)
	}
	for _, field := range profile.Unset {
		draft.Unset(field)
	}
	keys := make([]string, 0, len(profile.Fields))
	for key := range profile.Fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if setErr := draft.SetValue(key, profile.Fields[key]); setErr != nil {
			return plan, fmt.Errorf("写入推荐字段 %s 失败: %w", key, setErr)
		}
	}
	plan.Draft = draft
	plan.Raw = draft.Raw()
	plan.Report = draft.Validate()
	plan.Issues = configReportIssues(plan.Report)
	if !plan.Report.Valid {
		return plan, fmt.Errorf("%w：%s", ErrRecommendationInvalid, strings.Join(plan.Issues, "；"))
	}
	if plan.Report.Config.Database.Driver.RuntimeSupported() {
		plan.RequiresDBInit = true
		plan.Steps = append(plan.Steps, "保存配置文件（原子写入，保留上一有效副本）",
			"如数据库未创建/待迁移：在排他维护锁下执行正式迁移（不重建表）",
			"如 root 未创建：进入 root 创建画面（需要强密码/生成密码）",
			"如需要常用账户：进入账户方案画面（临时密码首次登录改密）")
	} else {
		plan.Steps = append(plan.Steps, "保存配置文件（仅配置；该驱动运行未接入，不会建库/连接）")
	}
	return plan, nil
}

// RecommendationApplyOptions 是一键应用参数。
type RecommendationApplyOptions struct {
	ConflictPolicy ConflictPolicy
	CreateBackup   bool
	// InitializeDatabase 为真时在保存配置后尝试对当前 SQLite 配置执行幂等迁移；
	// root 创建仍必须通过 root 画面显式提供密码，不在此静默执行。
	InitializeDatabase bool
	DBInit             DBInitOptions
}

// RecommendationApplyResult 分步返回真实结果；失败时保留已完成步骤供补偿/重入。
type RecommendationApplyResult struct {
	Saved          bool
	SaveResult     SaveResult
	DatabaseInited bool
	DBResult       DBInitResult
	Steps          []RecommendationStep
}

// RecommendationStep 是一个已执行/失败步骤。
type RecommendationStep struct {
	Name   string
	OK     bool
	Detail string
}

// ApplyRecommendation 保存推荐配置并可选补迁移；不伪造跨文件/数据库原子事务。
func ApplyRecommendation(ctx context.Context, plan RecommendationPlan,
	options RecommendationApplyOptions) (RecommendationApplyResult, error) {
	result := RecommendationApplyResult{}
	if ctx == nil {
		ctx = context.Background()
	}
	if plan.Draft == nil {
		return result, errors.New("缺少推荐配置草稿")
	}
	if !plan.Report.Valid {
		return result, fmt.Errorf("%w：%s", ErrRecommendationInvalid, strings.Join(plan.Issues, "；"))
	}
	saveResult, saveErr := SaveConfigDraft(ctx, SaveRequest{Draft: plan.Draft,
		ConflictPolicy: options.ConflictPolicy, CreateBackup: options.CreateBackup, Mode: 0o600})
	result.SaveResult = saveResult
	if saveErr != nil {
		result.Steps = append(result.Steps, RecommendationStep{Name: "保存配置文件", OK: false,
			Detail: saveErr.Error()})
		return result, saveErr
	}
	result.Saved = saveResult.Saved
	result.Steps = append(result.Steps, RecommendationStep{Name: "保存配置文件", OK: saveResult.Saved,
		Detail: "已原子保存；重载结果：" + saveResult.ReloadResult})
	if !options.InitializeDatabase || !plan.Report.Config.Database.Driver.RuntimeSupported() {
		return result, nil
	}
	dbPlan, planErr := BuildDBSetupPlan(plan.ConfigPath, plan.Report.Config,
		dbSetupInputFromConfig(plan.Report.Config))
	if planErr != nil {
		result.Steps = append(result.Steps, RecommendationStep{Name: "数据库初始化", OK: false,
			Detail: planErr.Error()})
		return result, planErr
	}
	dbInitOptions := options.DBInit
	if dbInitOptions.InstanceDir == "" {
		dbInitOptions.InstanceDir = plan.InstanceDir
	}
	dbResult, dbErr := InitializeDatabase(ctx, dbPlan, dbInitOptions)
	result.DBResult = dbResult
	result.DatabaseInited = dbErr == nil
	if dbErr != nil {
		result.Steps = append(result.Steps, RecommendationStep{Name: "数据库初始化", OK: false,
			Detail: dbErr.Error()})
		return result, dbErr
	}
	result.Steps = append(result.Steps, RecommendationStep{Name: "数据库初始化", OK: true,
		Detail: "迁移已应用到最新（幂等；未重建/覆盖数据）"})
	return result, nil
}

// dbSetupInputFromConfig 从已校验配置构造数据库设置输入。
func dbSetupInputFromConfig(cfg config.Config) DBSetupInput {
	database := cfg.Database
	return DBSetupInput{Driver: database.Driver, SQLitePath: database.Path,
		WAL: database.WAL, BusyTimeoutMS: database.BusyTimeoutMS,
		Host: database.Host, Port: database.Port, Username: database.Username,
		Password: database.Password, DatabaseName: database.Database, TLSMode: database.TLSMode}
}

// configReportIssues 汇总可展示配置问题（不含秘密）。
func configReportIssues(report ConfigReport) []string {
	issues := make([]string, 0, len(report.Issues))
	for _, issue := range report.Issues {
		text := strings.TrimSpace(strings.Join(nonEmpty([]string{issue.Field, issue.Detail,
			issue.Suggestion}), "："))
		if text != "" {
			issues = append(issues, text)
		}
	}
	if len(issues) == 0 && !report.Valid {
		if summary := strings.TrimSpace(report.Summary); summary != "" {
			issues = append(issues, summary)
		}
	}
	return issues
}

func nonEmpty(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
