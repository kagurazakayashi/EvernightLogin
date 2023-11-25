// Package diag 收集只读、脱敏的运行诊断信息：版本/构建、运行状态、存储健康、
// 队列状态、配置生效/待重启摘要与按 request_id 关联的错误事件。
//
// 安全边界：
//   - 本包不做授权；调用方（公开 Go 门面、管理 API、管理页面、CLI）必须先完成
//     真实身份、管理强认证、diagnostics.read 权限与作用范围检查。本包也不提供
//     写操作、不修改配置/数据库、不读取邮件正文或秘密明文。
//   - 输出只包含白名单字段与固定分类：不返回数据库连接串、路径、密钥、token、
//     密码、个人资料、完整配置或审计 detail 原文；失败只返回稳定错误分类码，
//     不包含堆栈或底层错误文本。
//   - logger 只记录“哪个组件不可用 + 稳定分类码”，绝不记录底层错误对象或秘密；
//     测试用带合成秘密的故障验证日志与输出都不泄露。
package diag

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/appids"
	"github.com/kagurazakayashi/EvernightLogin/config"
)

const (
	// DefaultErrorLimit 是关联错误查询默认条数。
	DefaultErrorLimit = 20
	// MaxErrorLimit 是关联错误查询硬上限，避免无界读取审计流水。
	MaxErrorLimit = 50
	// maxQueueStates 是队列状态输出上限（状态枚举固定少量）。
	maxQueueStates = 16
)

// 稳定组件状态/错误分类码（只用于诊断输出，不新增协议错误码）。
const (
	StatusOK          = "ok"
	StatusDegraded    = "degraded"
	StatusUnavailable = "unavailable"
	StatusUnverified  = "unverified"

	CodeStorageUnavailable = "STORAGE_UNAVAILABLE"
	CodeQueueUnavailable   = "QUEUE_UNAVAILABLE"
	CodeConfigUnverified   = "CONFIG_UNVERIFIED"
	CodeScopeInvalid       = "REQ_INVALID"
)

// Scope 是诊断的明确作用范围：system（全系统只读诊断）或单个应用范围。
type Scope struct {
	// Kind 固定为 "system" 或 "application"。
	Kind string `json:"kind"`
	// ID 是 "system" 或应用稳定 ID；应用范围必须是合法 app 前缀 ID。
	ID string `json:"id"`
}

// NormalizeScope 校验并规范化诊断作用范围；空值按 system 处理。
func NormalizeScope(scope Scope) (Scope, error) {
	kind := strings.TrimSpace(scope.Kind)
	id := strings.TrimSpace(scope.ID)
	if kind == "" {
		if id == "" || id == "system" {
			return Scope{Kind: "system", ID: "system"}, nil
		}
		kind = "application"
	}
	switch kind {
	case "system":
		if id != "" && id != "system" {
			return Scope{}, fmt.Errorf("%w: system 范围不能携带应用 ID", errInvalidScope)
		}
		return Scope{Kind: "system", ID: "system"}, nil
	case "application":
		if !appids.ValidApplicationID(id) {
			return Scope{}, fmt.Errorf("%w: 应用范围 ID 无效", errInvalidScope)
		}
		return Scope{Kind: "application", ID: id}, nil
	default:
		return Scope{}, fmt.Errorf("%w: 未知作用范围", errInvalidScope)
	}
}

// errInvalidScope 是内部错误；调用方映射为 REQ_INVALID。
var errInvalidScope = errors.New("诊断作用范围无效")

// VersionInfo 是构建信息（公开字段，可安全展示）。
type VersionInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
	GoVersion string `json:"go_version"`
}

// StorageHealth 是存储健康摘要（不包含路径/连接串/表数据）。
type StorageHealth struct {
	Status      string    `json:"status"`
	LatencyMS   int64     `json:"latency_ms"`
	Driver      string    `json:"driver"`
	JournalMode string    `json:"journal_mode,omitempty"`
	ErrorCode   string    `json:"error_code,omitempty"`
	CheckedAt   time.Time `json:"checked_at"`
}

// QueueCount 是单个队列状态的计数。
type QueueCount struct {
	State string `json:"state"`
	Count int64  `json:"count"`
}

// QueueStatus 是后台任务与邮件投递队列状态（只有状态与计数，不含载荷/收件人）。
type QueueStatus struct {
	Status          string       `json:"status"`
	Jobs            []QueueCount `json:"jobs"`
	MailDeliveries  []QueueCount `json:"mail_deliveries"`
	ErrorCode       string       `json:"error_code,omitempty"`
	TruncatedStates bool         `json:"truncated_states,omitempty"`
	CheckedAt       time.Time    `json:"checked_at"`
}

// ReloadField 是“待重启生效”的配置字段（只有字段名与重载分类，不含值）。
type ReloadField struct {
	Field string `json:"field"`
	Class string `json:"class"`
}

// ConfigSummary 是配置生效/待重启摘要；不输出完整配置或任何值。
type ConfigSummary struct {
	FeatureFlags         map[string]bool `json:"feature_flags"`
	LogLevel             string          `json:"log_level"`
	LogFormat            string          `json:"log_format"`
	DatabaseDriver       string          `json:"database_driver"`
	DatabaseWAL          bool            `json:"database_wal"`
	PendingRestartStatus string          `json:"pending_restart_status"`
	PendingRestart       []ReloadField   `json:"pending_restart"`
	CheckedAt            time.Time       `json:"checked_at"`
}

// ErrorEntry 是按 request_id 关联的错误事件白名单投影（不含审计 detail、actor ID、
// 个人资料或载荷）。
type ErrorEntry struct {
	ID         string    `json:"id"`
	OccurredAt time.Time `json:"occurred_at"`
	Action     string    `json:"action"`
	Outcome    string    `json:"outcome"`
	ErrorCode  string    `json:"error_code,omitempty"`
	ReasonCode string    `json:"reason_code,omitempty"`
	TargetType string    `json:"target_type"`
	RequestID  string    `json:"request_id,omitempty"`
	TaskID     string    `json:"task_id,omitempty"`
}

// ErrorList 是关联错误查询结果；Truncated 表示达到条数上限仍有更多。
type ErrorList struct {
	RequestID string       `json:"request_id"`
	Status    string       `json:"status"`
	Entries   []ErrorEntry `json:"entries"`
	Truncated bool         `json:"truncated"`
	CheckedAt time.Time    `json:"checked_at"`
}

// Report 是一次脱敏运行诊断快照。
type Report struct {
	GeneratedAt time.Time     `json:"generated_at"`
	Version     VersionInfo   `json:"version"`
	Scope       Scope         `json:"scope"`
	State       string        `json:"state"`
	Status      string        `json:"status"`
	Storage     StorageHealth `json:"storage"`
	Queues      QueueStatus   `json:"queues"`
	Config      ConfigSummary `json:"config"`
}

// Options 是诊断收集器依赖。所有依赖都可为空；缺失时对应区段返回 unavailable/
// unverified，不伪造 ok，也不读取默认路径或隐式凭据。
type Options struct {
	// Config 是当前生效配置（通常是启动时加载的配置快照）。
	Config config.Config
	// Build 是当前构建信息。
	Build login.BuildInfo
	// State 返回运行状态字符串（可选）；nil 时返回 unknown。
	State func() string
	// DB 是只读诊断查询使用的数据库句柄（可选）。
	DB *sql.DB
	// Ping 覆盖存储健康检查（可选，测试用）；nil 时使用 DB.PingContext。
	Ping func(ctx context.Context) error
	// ConfigPath 是磁盘配置路径（可选）。存在且可读取时计算待重启字段；
	// 否则待重启状态为 unverified。路径本身不进入输出。
	ConfigPath string
	// Logger 是脱敏诊断日志器；nil 时静默。只记录组件与稳定分类码。
	Logger *slog.Logger
	// Now 是可注入时钟；nil 使用 time.Now().UTC()。
	Now func() time.Time
}

// Collector 是只读诊断收集器；构造后不可变、可并发使用，不启动协程、不写库。
type Collector struct {
	opts Options
}

// New 构造收集器；不访问数据库、不读配置文件。
func New(options Options) *Collector {
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Collector{opts: options}
}

// Snapshot 收集一次脱敏诊断快照。只有 context 取消返回错误；依赖不可用返回
// 明确 degraded/unavailable 区段，不泄露底层错误文本。
func (c *Collector) Snapshot(ctx context.Context, scope Scope) (Report, error) {
	if c == nil {
		return Report{}, errors.New("诊断收集器未装配")
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	normalized, err := NormalizeScope(scope)
	if err != nil {
		return Report{}, err
	}
	now := c.now()
	report := Report{GeneratedAt: now, Scope: normalized, Status: StatusOK}
	report.Version = versionInfo(c.opts.Build)
	if c.opts.State != nil {
		report.State = strings.TrimSpace(c.opts.State())
	}
	if report.State == "" {
		report.State = "unknown"
	}
	report.Storage = c.storageHealth(ctx, now)
	report.Queues = c.queueStatus(ctx, now)
	report.Config = c.configSummary(now)
	if report.Storage.Status != StatusOK || report.Queues.Status != StatusOK {
		report.Status = StatusDegraded
	}
	return report, nil
}

// RelatedErrors 按 request_id 查询关联错误事件（脱敏白名单）。limit 0 使用默认；
// 超过硬上限按上限截断（不静默放大）。只有 context 取消返回错误；存储不可用时
// 返回 unavailable 状态而不是泄露底层错误。
func (c *Collector) RelatedErrors(ctx context.Context, scope Scope,
	requestID string, limit int) (ErrorList, error) {
	if c == nil {
		return ErrorList{}, errors.New("诊断收集器未装配")
	}
	if err := ctx.Err(); err != nil {
		return ErrorList{}, err
	}
	normalized, err := NormalizeScope(scope)
	if err != nil {
		return ErrorList{}, err
	}
	requestID = strings.TrimSpace(requestID)
	result := ErrorList{RequestID: requestID, Status: StatusOK,
		CheckedAt: c.now(), Entries: []ErrorEntry{}}
	if requestID == "" {
		return result, nil
	}
	if err := login.ValidateRequestID(requestID); err != nil {
		result.Status = StatusUnverified
		return result, nil
	}
	if c.opts.DB == nil || c.opts.Ping != nil {
		result.Status = StatusUnavailable
		return result, nil
	}
	if limit <= 0 {
		limit = DefaultErrorLimit
	}
	if limit > MaxErrorLimit {
		limit = MaxErrorLimit
	}
	query := `SELECT id,occurred_at_ms,action,outcome,COALESCE(error_code,''),
COALESCE(reason_code,''),target_type,COALESCE(request_id,''),COALESCE(task_id,'')
FROM audit_events WHERE request_id=?`
	args := []any{requestID}
	if normalized.Kind == "application" {
		query += ` AND app_id_snapshot=?`
		args = append(args, normalized.ID)
	}
	query += ` ORDER BY occurred_at_ms DESC, id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := c.opts.DB.QueryContext(ctx, query, args...)
	if err != nil {
		c.logComponent("audit_errors", CodeQueueUnavailable)
		result.Status = StatusUnavailable
		return result, nil
	}
	defer rows.Close()
	entries := make([]ErrorEntry, 0, limit)
	for rows.Next() {
		var entry ErrorEntry
		var occurredMS int64
		if scanErr := rows.Scan(&entry.ID, &occurredMS, &entry.Action, &entry.Outcome,
			&entry.ErrorCode, &entry.ReasonCode, &entry.TargetType,
			&entry.RequestID, &entry.TaskID); scanErr != nil {
			c.logComponent("audit_errors", CodeQueueUnavailable)
			result.Status = StatusUnavailable
			return result, nil
		}
		entry.OccurredAt = time.UnixMilli(occurredMS).UTC()
		entries = append(entries, entry)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		c.logComponent("audit_errors", CodeQueueUnavailable)
		result.Status = StatusUnavailable
		return result, nil
	}
	if len(entries) > limit {
		entries = entries[:limit]
		result.Truncated = true
	}
	result.Entries = entries
	return result, nil
}

// versionInfo 构造公开构建信息。
func versionInfo(build login.BuildInfo) VersionInfo {
	return VersionInfo{Version: valueOr(build.Version, "devel"),
		Commit:    valueOr(build.Commit, "unknown"),
		BuildTime: valueOr(build.BuildTime, "unknown"),
		GoVersion: valueOr(build.GoVersion, "unknown")}
}

// valueOr 返回非空值或默认值。
func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

// storageHealth 检查数据库可达性与 SQLite journal 模式；不输出路径或 DSN。
func (c *Collector) storageHealth(ctx context.Context, now time.Time) StorageHealth {
	health := StorageHealth{Status: StatusUnavailable, Driver: "sqlite",
		ErrorCode: CodeStorageUnavailable, CheckedAt: now}
	ping := c.opts.Ping
	if ping == nil {
		if c.opts.DB == nil {
			return health
		}
		ping = c.opts.DB.PingContext
	}
	started := time.Now()
	if err := ping(ctx); err != nil {
		c.logComponent("storage", CodeStorageUnavailable)
		health.LatencyMS = time.Since(started).Milliseconds()
		return health
	}
	health.LatencyMS = time.Since(started).Milliseconds()
	health.Status = StatusOK
	health.ErrorCode = ""
	if c.opts.DB != nil && c.opts.Ping == nil {
		var journal string
		if err := c.opts.DB.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&journal); err == nil {
			journal = strings.ToLower(strings.TrimSpace(journal))
			if journal == "wal" || journal == "delete" || journal == "truncate" ||
				journal == "persist" || journal == "memory" || journal == "off" {
				health.JournalMode = journal
			}
		}
	}
	return health
}

// queueStatus 汇总 jobs 与 mail_deliveries 的状态计数；只返回状态名与计数。
func (c *Collector) queueStatus(ctx context.Context, now time.Time) QueueStatus {
	status := QueueStatus{Status: StatusOK, CheckedAt: now}
	if c.opts.DB == nil || c.opts.Ping != nil {
		status.Status = StatusUnavailable
		status.ErrorCode = CodeQueueUnavailable
		return status
	}
	jobs, jobsErr := c.countByState(ctx, `SELECT state,COUNT(*) FROM jobs GROUP BY state`)
	if jobsErr != nil {
		status.Status = StatusUnavailable
		status.ErrorCode = CodeQueueUnavailable
		c.logComponent("queue.jobs", CodeQueueUnavailable)
		return status
	}
	mail, mailErr := c.countByState(ctx,
		`SELECT state,COUNT(*) FROM mail_deliveries GROUP BY state`)
	if mailErr != nil {
		status.Status = StatusUnavailable
		status.ErrorCode = CodeQueueUnavailable
		c.logComponent("queue.mail", CodeQueueUnavailable)
		return status
	}
	status.Jobs = jobs
	status.MailDeliveries = mail
	return status
}

// countByState 执行受状态数与条数上限约束的计数查询。
func (c *Collector) countByState(ctx context.Context, query string) ([]QueueCount, error) {
	rows, err := c.opts.DB.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := make([]QueueCount, 0, 8)
	for rows.Next() {
		var item QueueCount
		if err := rows.Scan(&item.State, &item.Count); err != nil {
			return nil, err
		}
		counts = append(counts, item)
		if len(counts) >= maxQueueStates {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return counts, nil
}

// configSummary 输出安全功能开关与待重启字段名/分类；不输出任何配置值。
func (c *Collector) configSummary(now time.Time) ConfigSummary {
	cfg := c.opts.Config
	summary := ConfigSummary{FeatureFlags: map[string]bool{
		"tls_enabled":                 cfg.Server.TLSEnabled(),
		"tls_terminating_proxy":       cfg.Server.TLSProxyMode,
		"mail_enabled":                cfg.Mail.Enabled,
		"registration_enabled":        cfg.Registration.Enabled,
		"registration_require_review": cfg.Registration.RequireReview,
		"registration_email_required": cfg.Registration.RequireEmailVerification,
		"passkey_enabled":             cfg.Passkey.Enabled,
		"app_qr_login_enabled":        cfg.AppQRLogin.Enabled,
		"oauth_protocol_enabled":      cfg.Protocol.Enabled,
		"manual_recovery_enabled":     cfg.ManualRecovery.Enabled,
		"database_wal":                cfg.Database.WAL,
	}, LogLevel: string(cfg.Logging.Level), LogFormat: string(cfg.Logging.Format),
		DatabaseDriver: string(cfg.Database.Driver), DatabaseWAL: cfg.Database.WAL,
		PendingRestartStatus: "not_configured", PendingRestart: []ReloadField{},
		CheckedAt: now}
	if c.opts.ConfigPath == "" {
		return summary
	}
	loaded, err := config.Load(config.LoadOptions{YAMLFile: c.opts.ConfigPath})
	if err != nil {
		summary.PendingRestartStatus = StatusUnverified
		c.logComponent("config_reload", CodeConfigUnverified)
		return summary
	}
	diff := config.DiffReload(cfg, loaded)
	if diff.Empty() {
		summary.PendingRestartStatus = "none"
		return summary
	}
	for _, field := range diff.Fields() {
		item := ReloadField{Field: field, Class: "restart-required"}
		if info, ok := config.LookupField(field); ok {
			item.Class = string(info.Class)
		}
		summary.PendingRestart = append(summary.PendingRestart, item)
	}
	summary.PendingRestartStatus = "pending"
	return summary
}

// logComponent 只记录组件与稳定分类码，不记录底层错误或秘密。
func (c *Collector) logComponent(component, code string) {
	if c.opts.Logger == nil {
		return
	}
	c.opts.Logger.Warn("诊断组件不可用", "component", component, "code", code)
}

// now 返回 UTC 当前时间。
func (c *Collector) now() time.Time {
	if c.opts.Now != nil {
		return c.opts.Now().UTC()
	}
	return time.Now().UTC()
}

// ErrInvalidScope 报告调用方作用范围格式错误（用于映射 REQ_INVALID）。
func ErrInvalidScope(err error) bool { return errors.Is(err, errInvalidScope) }
