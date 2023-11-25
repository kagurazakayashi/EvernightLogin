package app

// 步骤 233：脱敏运行诊断公开 Go 门面。
//
// 边界：
//   - 只读；不修改配置/数据库/任务，不读取邮件正文或秘密明文；
//   - 调用者必须是受信本机管理员（Runtime.LocalAdmin，显式本地进程信任边界）或
//     通过管理强认证、且在当前范围持有 diagnostics.read 的管理会话；受限会话、
//     普通业务会话、缺少权限一律拒绝；
//   - 详细诊断有明确 system/application 范围；返回字段是固定白名单，不包含
//     数据库连接串/路径、密钥、token、密码、个人资料、完整配置或审计 detail；
//   - 匿名存活探针仍由 HTTP /healthz 提供（只返回最小存活状态），本门面不提供
//     未授权详细诊断。

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/appids"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	"github.com/kagurazakayashi/EvernightLogin/internal/diag"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// DiagnosticsRequest 是读取脱敏运行诊断的请求。
//
// Caller 必须是 Runtime.LocalAdmin() 或 Runtime.AdminSession() 建立的可信管理
// 调用者；ScopeID 为空或 "system" 表示系统范围，否则必须是应用稳定 ID
// （app_...），权限在该范围内重新判定。RequestID 非法时返回 REQ_INVALID 且不
// 执行任何诊断查询。
type DiagnosticsRequest struct {
	Caller    AdminCaller
	ScopeID   string
	RequestID string
}

// DiagnosticsVersion 是构建信息。
type DiagnosticsVersion struct {
	Version   string
	Commit    string
	BuildTime string
	GoVersion string
}

// DiagnosticsStorageHealth 是存储健康摘要（不含路径/连接串）。
type DiagnosticsStorageHealth struct {
	Status      string
	LatencyMS   int64
	Driver      string
	JournalMode string
	ErrorCode   string
	CheckedAt   time.Time
}

// DiagnosticsQueueCount 是单个队列状态计数。
type DiagnosticsQueueCount struct {
	State string
	Count int64
}

// DiagnosticsQueueStatus 是任务与邮件投递队列状态。
type DiagnosticsQueueStatus struct {
	Status         string
	Jobs           []DiagnosticsQueueCount
	MailDeliveries []DiagnosticsQueueCount
	ErrorCode      string
	CheckedAt      time.Time
}

// DiagnosticsReloadField 是待重启生效的配置字段（只有字段名/分类）。
type DiagnosticsReloadField struct {
	Field string
	Class string
}

// DiagnosticsConfigSummary 是配置生效/待重启摘要（不包含配置值）。
type DiagnosticsConfigSummary struct {
	FeatureFlags         map[string]bool
	LogLevel             string
	LogFormat            string
	DatabaseDriver       string
	DatabaseWAL          bool
	PendingRestartStatus string
	PendingRestart       []DiagnosticsReloadField
	CheckedAt            time.Time
}

// DiagnosticsReport 是脱敏运行诊断快照。
type DiagnosticsReport struct {
	GeneratedAt time.Time
	Version     DiagnosticsVersion
	ScopeKind   string
	ScopeID     string
	State       string
	Status      string
	Storage     DiagnosticsStorageHealth
	Queues      DiagnosticsQueueStatus
	Config      DiagnosticsConfigSummary
}

// DiagnosticsErrorEntry 是按 request_id 关联的错误事件白名单投影。
type DiagnosticsErrorEntry struct {
	ID         string
	OccurredAt time.Time
	Action     string
	Outcome    string
	ErrorCode  string
	ReasonCode string
	TargetType string
	RequestID  string
	TaskID     string
}

// DiagnosticsErrorList 是关联错误查询结果。
type DiagnosticsErrorList struct {
	RequestID string
	Status    string
	Entries   []DiagnosticsErrorEntry
	Truncated bool
	CheckedAt time.Time
}

// DiagnosticsErrorsRequest 是关联错误查询请求。
type DiagnosticsErrorsRequest struct {
	Caller AdminCaller
	// ScopeID 与 DiagnosticsRequest.ScopeID 语义相同。
	ScopeID string
	// ErrorRequestID 是待查询的请求编号（req_...）；空返回空列表，非法返回
	// REQ_INVALID 且不执行查询。
	ErrorRequestID string
	// Limit 最多返回条数；0 使用默认 20，上限 50。
	Limit     int
	RequestID string
}

// DiagnosticsExport 是有界诊断导出结果：只含脱敏快照与可选关联错误列表。
type DiagnosticsExport struct {
	ExportedAt time.Time
	Report     DiagnosticsReport
	Errors     *DiagnosticsErrorList
}

// DiagnosticsService 是脱敏运行诊断公开门面。
type DiagnosticsService interface {
	// Read 返回指定范围的脱敏运行诊断快照。
	Read(ctx context.Context, req DiagnosticsRequest) (DiagnosticsReport, error)
	// RelatedErrors 按请求编号查询关联错误事件（白名单字段、有界条数）。
	RelatedErrors(ctx context.Context, req DiagnosticsErrorsRequest) (DiagnosticsErrorList, error)
	// Export 返回有界诊断导出（快照 + 可选关联错误），供受控本地导出使用。
	Export(ctx context.Context, req DiagnosticsErrorsRequest) (DiagnosticsExport, error)
}

// Diagnostics 返回脱敏运行诊断门面（只读；授权见 DiagnosticsService）。
func (r *Runtime) Diagnostics() DiagnosticsService { return &diagnosticsFacade{r: r} }

// diagnosticsFacade 实现 DiagnosticsService。
type diagnosticsFacade struct{ r *Runtime }

// Read 实现 DiagnosticsService。
func (f *diagnosticsFacade) Read(ctx context.Context,
	req DiagnosticsRequest) (DiagnosticsReport, error) {
	_, scope, requestID, err := f.authorize(ctx, req.Caller, req.ScopeID, req.RequestID)
	if err != nil {
		return DiagnosticsReport{}, err
	}
	collector, err := f.collector(requestID)
	if err != nil {
		return DiagnosticsReport{}, err
	}
	report, collectErr := collector.Snapshot(ctx, scope)
	if collectErr != nil {
		return DiagnosticsReport{}, mapDiagnosticsError(collectErr, requestID)
	}
	return toDiagnosticsReport(report), nil
}

// RelatedErrors 实现 DiagnosticsService。
func (f *diagnosticsFacade) RelatedErrors(ctx context.Context,
	req DiagnosticsErrorsRequest) (DiagnosticsErrorList, error) {
	_, scope, requestID, err := f.authorize(ctx, req.Caller, req.ScopeID, req.RequestID)
	if err != nil {
		return DiagnosticsErrorList{}, err
	}
	if strings.TrimSpace(req.ErrorRequestID) != "" {
		if err := login.ValidateRequestID(strings.TrimSpace(req.ErrorRequestID)); err != nil {
			return DiagnosticsErrorList{}, login.NewAppError(login.CodeReqInvalid,
				"错误查询请求编号格式无效", requestIDOption(requestID))
		}
	}
	collector, err := f.collector(requestID)
	if err != nil {
		return DiagnosticsErrorList{}, err
	}
	list, queryErr := collector.RelatedErrors(ctx, scope, req.ErrorRequestID, req.Limit)
	if queryErr != nil {
		return DiagnosticsErrorList{}, mapDiagnosticsError(queryErr, requestID)
	}
	return toDiagnosticsErrorList(list), nil
}

// Export 实现 DiagnosticsService：只返回有界脱敏数据，不写文件、不返回路径。
func (f *diagnosticsFacade) Export(ctx context.Context,
	req DiagnosticsErrorsRequest) (DiagnosticsExport, error) {
	reportReq := DiagnosticsRequest{Caller: req.Caller, ScopeID: req.ScopeID,
		RequestID: req.RequestID}
	report, err := f.Read(ctx, reportReq)
	if err != nil {
		return DiagnosticsExport{}, err
	}
	export := DiagnosticsExport{ExportedAt: f.r.runtimeNow().UTC(), Report: report}
	if strings.TrimSpace(req.ErrorRequestID) != "" {
		list, listErr := f.RelatedErrors(ctx, req)
		if listErr != nil {
			return DiagnosticsExport{}, listErr
		}
		export.Errors = &list
	}
	return export, nil
}

// authorize 统一完成：请求编号解析、可信管理员解析、管理强认证（会话）、范围
// 规范化与 diagnostics.read 授权判定。任何拒绝都先于诊断数据读取。
func (f *diagnosticsFacade) authorize(ctx context.Context, caller AdminCaller,
	scopeID, requestID string) (adminIdentity, diag.Scope, string, error) {
	if f == nil || f.r == nil {
		return adminIdentity{}, diag.Scope{}, "", configError("服务未装配")
	}
	admin := &adminFacade{r: f.r}
	id, err := admin.begin(ctx, caller, requestID)
	if err != nil {
		return adminIdentity{}, diag.Scope{}, "", err
	}
	resolvedScope := strings.TrimSpace(scopeID)
	if resolvedScope == "" {
		resolvedScope = "system"
	}
	scope, scopeErr := diag.NormalizeScope(diag.Scope{ID: resolvedScope})
	if scopeErr != nil {
		return adminIdentity{}, diag.Scope{}, id.requestID,
			mapDomainError("诊断作用范围无效", "REQ_INVALID", id.requestID)
	}
	services := f.r.coreServices()
	managed := f.r.managedServices()
	if services == nil || services.Sessions == nil || managed == nil || managed.Authz == nil {
		return adminIdentity{}, diag.Scope{}, id.requestID,
			configError("诊断服务未装配", id.requestID)
	}
	if id.identity.local {
		// 本机受信管理员是显式本地进程信任边界；仍只返回脱敏诊断，不返回秘密。
		return id.identity, scope, id.requestID, nil
	}
	if len(id.identity.sessionSecret) == 0 {
		return adminIdentity{}, diag.Scope{}, id.requestID,
			mapDomainError("诊断需要已认证管理会话", "ACCESS_DENIED", id.requestID)
	}
	if _, authErr := services.Sessions.AuthorizeManagement(ctx,
		string(id.identity.sessionSecret)); authErr != nil {
		return adminIdentity{}, diag.Scope{}, id.requestID,
			mapDomainError("诊断需要已完成管理强认证的会话",
				string(session.CodeOf(authErr)), id.requestID)
	}
	authzCaller, callerErr := admin.authzCaller(id.identity)
	if callerErr != nil {
		return adminIdentity{}, diag.Scope{}, id.requestID,
			mapDomainError("管理会话主体无效", "ACCESS_DENIED", id.requestID)
	}
	result, checkErr := managed.Authz.Check(ctx, authzCaller, authz.CheckRequest{
		SubjectUserID: id.identity.userID,
		ScopeID:       scope.ID,
		Permissions:   []string{"diagnostics.read"},
		Mode:          authz.ModeAll,
	})
	if checkErr != nil {
		return adminIdentity{}, diag.Scope{}, id.requestID,
			mapDomainError("诊断授权判定失败", string(authz.CodeOf(checkErr)), id.requestID)
	}
	if !result.Allowed || result.SourceLimitReached {
		return adminIdentity{}, diag.Scope{}, id.requestID,
			mapDomainError("无权查看该范围的运行诊断", "ACCESS_DENIED", id.requestID)
	}
	return id.identity, scope, id.requestID, nil
}

// collector 构造只读诊断收集器；配置路径、DB、构建信息均来自当前运行时。
func (f *diagnosticsFacade) collector(requestID string) (*diag.Collector, error) {
	r := f.r
	var db = r.diagnosticsDB()
	collector := diag.New(diag.Options{
		Config:     r.config,
		Build:      login.CurrentBuildInfo(),
		State:      func() string { return string(r.State()) },
		DB:         db,
		ConfigPath: r.opts.ConfigPath,
		Logger:     r.logger,
		Now:        r.runtimeNow,
	})
	if collector == nil {
		return nil, configError("诊断收集器未装配", requestID)
	}
	return collector, nil
}

// diagnosticsDB 返回只读诊断可用的数据库句柄；运行时未装配或已关闭时 nil。
func (r *Runtime) diagnosticsDB() *sql.DB {
	if r == nil || r.base == nil || r.base.Store == nil {
		return nil
	}
	return r.base.Store.DB()
}

// toDiagnosticsReport 把内部脱敏报告映射为公开类型（逐字段复制，不暴露 internal）。
func toDiagnosticsReport(report diag.Report) DiagnosticsReport {
	result := DiagnosticsReport{
		GeneratedAt: report.GeneratedAt,
		Version: DiagnosticsVersion{Version: report.Version.Version,
			Commit: report.Version.Commit, BuildTime: report.Version.BuildTime,
			GoVersion: report.Version.GoVersion},
		ScopeKind: report.Scope.Kind, ScopeID: report.Scope.ID,
		State: report.State, Status: report.Status,
		Storage: DiagnosticsStorageHealth{Status: report.Storage.Status,
			LatencyMS: report.Storage.LatencyMS, Driver: report.Storage.Driver,
			JournalMode: report.Storage.JournalMode, ErrorCode: report.Storage.ErrorCode,
			CheckedAt: report.Storage.CheckedAt},
		Queues: DiagnosticsQueueStatus{Status: report.Queues.Status,
			ErrorCode: report.Queues.ErrorCode, CheckedAt: report.Queues.CheckedAt},
		Config: DiagnosticsConfigSummary{FeatureFlags: map[string]bool{},
			LogLevel: report.Config.LogLevel, LogFormat: report.Config.LogFormat,
			DatabaseDriver:       report.Config.DatabaseDriver,
			DatabaseWAL:          report.Config.DatabaseWAL,
			PendingRestartStatus: report.Config.PendingRestartStatus,
			CheckedAt:            report.Config.CheckedAt},
	}
	for _, item := range report.Queues.Jobs {
		result.Queues.Jobs = append(result.Queues.Jobs,
			DiagnosticsQueueCount{State: item.State, Count: item.Count})
	}
	for _, item := range report.Queues.MailDeliveries {
		result.Queues.MailDeliveries = append(result.Queues.MailDeliveries,
			DiagnosticsQueueCount{State: item.State, Count: item.Count})
	}
	for key, value := range report.Config.FeatureFlags {
		result.Config.FeatureFlags[key] = value
	}
	for _, field := range report.Config.PendingRestart {
		result.Config.PendingRestart = append(result.Config.PendingRestart,
			DiagnosticsReloadField{Field: field.Field, Class: field.Class})
	}
	return result
}

// toDiagnosticsErrorList 把内部错误列表映射为公开类型。
func toDiagnosticsErrorList(list diag.ErrorList) DiagnosticsErrorList {
	result := DiagnosticsErrorList{RequestID: list.RequestID, Status: list.Status,
		Truncated: list.Truncated, CheckedAt: list.CheckedAt}
	for _, entry := range list.Entries {
		result.Entries = append(result.Entries, DiagnosticsErrorEntry{
			ID: entry.ID, OccurredAt: entry.OccurredAt, Action: entry.Action,
			Outcome: entry.Outcome, ErrorCode: entry.ErrorCode,
			ReasonCode: entry.ReasonCode, TargetType: entry.TargetType,
			RequestID: entry.RequestID, TaskID: entry.TaskID})
	}
	return result
}

// mapDiagnosticsError 把诊断收集器错误映射为稳定公开错误：作用范围/请求编号错误
// 为 REQ_INVALID，取消保留 context 语义，其他依赖失败为 DB_UNAVAILABLE（不泄露
// 底层错误文本）。
func mapDiagnosticsError(err error, requestID string) error {
	if err == nil {
		return nil
	}
	if diag.ErrInvalidScope(err) {
		return login.NewAppError(login.CodeReqInvalid, "诊断作用范围无效",
			requestIDOption(requestID))
	}
	if err == context.Canceled || err == context.DeadlineExceeded {
		return err
	}
	return login.NewAppError(login.CodeDBUnavailable, "诊断数据暂时不可用",
		requestIDOption(requestID))
}

// 编译期确认公开门面实现接口。
var _ DiagnosticsService = (*diagnosticsFacade)(nil)

// validApplicationIDs 报告诊断范围是否可接受（保留给宿主预校验）。
func validApplicationIDs(scopeID string) bool {
	if scopeID == "" || scopeID == "system" {
		return true
	}
	return appids.ValidApplicationID(scopeID)
}
