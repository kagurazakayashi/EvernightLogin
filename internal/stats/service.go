package stats

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// ScopeGrant 是作用范围授权结果。
type ScopeGrant struct {
	// Allowed 表示功能权限通过。
	Allowed bool
	// AllData 表示数据范围不限。
	AllData bool
	// ResourceIDs 是获准的应用快照 ID 集合；可包含 ScopeSystem 表示系统级数据。
	ResourceIDs []string
}

// Authorizer 是作用范围授权契约（生产实现可包装 internal/authz）。
type Authorizer interface {
	AuthorizeScope(ctx context.Context, caller account.Caller,
		permissionKey, scopeID string) (ScopeGrant, error)
}

// RootChecker 判定调用者是否为 root。依赖失败按非 root 处理（fail-closed）。
type RootChecker interface {
	IsRoot(ctx context.Context, caller account.Caller) (bool, error)
}

// AuditRecorder 是可选的拒绝审计写入契约（生产 *audit.Recorder）。未注入时不写
// 拒绝审计，但拒绝结论不变。
type AuditRecorder interface {
	RecordFailure(ctx context.Context, event audit.Event) error
}

// BusinessActivityAuthorizer 校验可信业务活动来源的应用归属与用户存在/成员关系。
// 生产实现必须查询真实应用/账户/成员状态；未注入、返回错误或校验失败一律默认
// 拒绝（fail-closed），不写业务活动事实。仅校验 ActorSystem 不足以证明应用归属。
type BusinessActivityAuthorizer interface {
	AuthorizeBusinessActivity(ctx context.Context, actor audit.Actor, appID, userID string) error
}

// ActionAccessDenied 是统计读取被拒绝的审计动作。
const ActionAccessDenied = "stats.access.denied"

// Metric 是统计指标稳定标识，供步骤 76 看板与后续报告引用。
type Metric string

const (
	// MetricActiveUsers 是成功认证去重活跃用户数。
	MetricActiveUsers Metric = "auth_distinct_users"
	// MetricRawEvents 是原始错误事件次数。
	MetricRawEvents Metric = "raw_events"
	// MetricDedupFailedRequests 是去重失败请求数。
	MetricDedupFailedRequests Metric = "dedup_failed_requests"
	// MetricDedupFailedTasks 是去重失败任务数。
	MetricDedupFailedTasks Metric = "dedup_failed_tasks"
	// MetricBusinessActivity 是可信业务活动次数（独立口径）。
	MetricBusinessActivity Metric = "business_activity_events"
	// MetricBusinessActiveUsers 是可信业务活动去重用户数（独立口径）。
	MetricBusinessActiveUsers Metric = "business_activity_distinct_users"
)

// DataStatus 是数据点/行的完整性状态；未知与缺失不得显示为 0。
type DataStatus string

const (
	// DataComplete 表示该桶/行覆盖完整且采样正常。
	DataComplete DataStatus = "complete"
	// DataPartial 表示数据源截断或部分采样缺失，数值不完整。
	DataPartial DataStatus = "partial"
	// DataInProgress 表示当前未结束的桶，统计截止于观测时刻。
	DataInProgress DataStatus = "in_progress"
	// DataUnknown 表示保留期不足或没有可用采样，数值未知（不是 0）。
	DataUnknown DataStatus = "unknown"
	// DataNotEnabled 表示模块/指标未启用，没有数据。
	DataNotEnabled DataStatus = "not_enabled"
)

// MissingInterval 是缺失/不可知时间区间。
type MissingInterval struct {
	Start  time.Time
	End    time.Time
	Reason string
}

// Completeness 是统计完整性信息。页面/报告必须展示它，不能用零值填充缺失。
type Completeness struct {
	// WindowWithinRetention 表示请求区间完全落在可查询保留期内。
	WindowWithinRetention bool
	RetentionDays         int
	RetentionConfigured   bool
	RetentionCutoff       time.Time
	// MissingIntervals 是因保留期不足而不可知的区间（真实值未知，不是 0）。
	MissingIntervals []MissingInterval
	// SamplingGaps 是健康采样历史中的空档（仅历史查询填充）。
	SamplingGaps []MissingInterval
	// ScopeTrimmed 表示聚合已按调用者权限裁剪，不代表全系统总量。
	ScopeTrimmed bool
	// SourceTruncated 表示数据源达到行数/分组上限，结果不完整。
	SourceTruncated bool
	// ModulesNotEnabled 是当前未启用的模块/指标。
	ModulesNotEnabled []Module
}

// ScopeInfo 是本次查询的作用范围说明。
type ScopeInfo struct {
	ID   string
	Kind string
}

// ActivityRequest 是活跃度查询。AppID 为空时按作用范围聚合；非空时限定单个应用
// 且必须落在授权数据范围内。
type ActivityRequest struct {
	Caller  account.Caller
	ScopeID string
	Window  WindowRequest
	AppID   string
}

// ActivityPoint 是一个时间桶的活跃度。
type ActivityPoint struct {
	Bucket      Bucket
	ActiveUsers int64
	DataStatus  DataStatus
}

// ActivityResult 是活跃度结果。TotalActiveUsers 是窗口内去重用户数（多应用合并
// 后按稳定用户 ID 去重，不是各应用数量之和）。
type ActivityResult struct {
	Window           Window
	Metric           Metric
	DedupeScope      string
	Points           []ActivityPoint
	TotalActiveUsers int64
	Completeness     Completeness
	GeneratedAt      time.Time
}

// GrowthKind 是增幅表达。
type GrowthKind string

const (
	// GrowthNew 表示前期为 0、本期大于 0（零基数“新增”，不显示无穷大）。
	GrowthNew GrowthKind = "new"
	// GrowthNone 表示前期与本期均为 0。
	GrowthNone GrowthKind = "none"
	// GrowthPercent 表示可计算的百分比增幅（可为负）。
	GrowthPercent GrowthKind = "percent"
	// GrowthUnavailable 表示比较数据缺失/不完整，不能计算增幅。
	GrowthUnavailable GrowthKind = "unavailable"
)

// Growth 是增幅结果；Percent 只在 GrowthPercent 时有意义。
type Growth struct {
	Kind            GrowthKind
	Percent         float64
	ComparisonStart time.Time
	ComparisonEnd   time.Time
}

// ErrorSort 是错误聚合排序白名单。
type ErrorSort string

const (
	ErrorSortRaw    ErrorSort = "raw_events"
	ErrorSortShare  ErrorSort = "share"
	ErrorSortFirst  ErrorSort = "first_seen"
	ErrorSortLast   ErrorSort = "last_seen"
	ErrorSortGrowth ErrorSort = "growth"
)

// SortOrder 是排序方向。
type SortOrder string

const (
	SortDesc SortOrder = "desc"
	SortAsc  SortOrder = "asc"
)

// ErrorRequest 是错误聚合查询。
type ErrorRequest struct {
	Caller     account.Caller
	ScopeID    string
	Window     WindowRequest
	AppID      string
	Categories []Category
	Sort       ErrorSort
	Order      SortOrder
	Limit      int
	Offset     int
	// DisableComparison 为 true 时不计算增幅（用于只需要当前窗口的轻量查询）。
	DisableComparison bool
}

// ErrorRow 是一行错误聚合（按错误码+类别+严重度+应用）。
type ErrorRow struct {
	ErrorCode      string
	Category       Category
	Severity       Severity
	AppID          string
	RawEvents      int64
	FailedRequests int64
	FailedTasks    int64
	Share          float64
	FirstSeen      time.Time
	LastSeen       time.Time
	Growth         Growth
	DataStatus     DataStatus
}

// CategorySummary 是按类别的汇总。等待授权、正常拒绝、主动取消、警告与故障
// 分开统计，不合并成“错误”。
type CategorySummary struct {
	Category       Category
	Severity       Severity
	RawEvents      int64
	FailedRequests int64
	FailedTasks    int64
}

// ErrorResult 是错误聚合结果。RawEvents 是原始事件总数；FailedRequests/
// FailedTasks 是全局去重数量（与行级去重数分开，行级数量不得相加当作全局值）。
type ErrorResult struct {
	Window           Window
	Comparison       MissingInterval
	Rows             []ErrorRow
	TotalRawEvents   int64
	FailedRequests   int64
	FailedTasks      int64
	ShareDenominator int64
	Categories       []CategorySummary
	Sort             ErrorSort
	Order            SortOrder
	Limit            int
	Offset           int
	HasMore          bool
	Completeness     Completeness
	GeneratedAt      time.Time
}

// OverviewRequest 是看板摘要查询（同一窗口/范围/截断点）。
type OverviewRequest struct {
	Caller  account.Caller
	ScopeID string
	Window  WindowRequest
	AppID   string
}

// OverviewResult 是看板摘要：活跃用户、原始错误次数、去重失败请求/任务数、
// 类别分布与完整性。它们引用同一统计上下文（窗口、时区、范围、截止点）。
type OverviewResult struct {
	Window         Window
	Scope          ScopeInfo
	ActiveUsers    int64
	TotalRawEvents int64
	FailedRequests int64
	FailedTasks    int64
	Categories     []CategorySummary
	ActivityStatus DataStatus
	Completeness   Completeness
	GeneratedAt    time.Time
}

// BusinessActivityRequest 是可信业务活动上报；仅供应用服务端使用系统身份调用。
type BusinessActivityRequest struct {
	Caller      account.Caller
	AppID       string
	UserID      string
	ActivityKey string
	OccurredAt  time.Time
	DedupeKey   string
	RequestID   string
}

// BusinessActivityQuery 是业务活动查询。
type BusinessActivityQuery struct {
	Caller      account.Caller
	ScopeID     string
	Window      WindowRequest
	AppID       string
	ActivityKey string
}

// BusinessActivityPoint 是一个时间桶的业务活动计数。
type BusinessActivityPoint struct {
	Bucket        Bucket
	Events        int64
	DistinctUsers int64
	DataStatus    DataStatus
}

// BusinessActivityResult 是可信业务活动结果；它与登录活跃分开，另标口径。
type BusinessActivityResult struct {
	Window        Window
	Source        string
	ActivityKey   string
	Points        []BusinessActivityPoint
	TotalEvents   int64
	DistinctUsers int64
	DedupeScope   string
	Completeness  Completeness
	GeneratedAt   time.Time
}

// HealthRequest 是当前健康状态查询。
type HealthRequest struct {
	Caller  account.Caller
	ScopeID string
}

// HealthResult 是当前观测健康快照；每张卡带观测时间与来源，未知/未启用如实给出。
type HealthResult struct {
	Modules      []HealthSample
	ObservedAt   time.Time
	Completeness Completeness
}

// HealthHistoryRequest 是健康采样历史查询。
type HealthHistoryRequest struct {
	Caller  account.Caller
	ScopeID string
	Window  WindowRequest
}

// HealthHistoryResult 是健康采样历史与采样空档。
type HealthHistoryResult struct {
	Window       Window
	Samples      []HealthSample
	Completeness Completeness
	GeneratedAt  time.Time
}

// Options 是统计服务依赖与边界。
type Options struct {
	Store      Store
	Authorizer Authorizer
	Root       RootChecker
	// Audit 可选：注入后拒绝读取会写失败审计，不改变拒绝结论。
	Audit AuditRecorder
	// HealthSources 是当前健康状态来源；未覆盖的必需模块以未知或未启用呈现。
	HealthSources []HealthSource
	// Now 是注入时钟；nil 使用 time.Now。统计截止点与生成时间都用它。
	Now    func() time.Time
	Logger *slog.Logger
	// RetentionDays 是未配置保留策略时的默认保留天数。
	RetentionDays int
	// MaxFactRows 是活跃事实读取上限；0 使用 MaxFactRows。
	MaxFactRows int
	// SampleInterval 是健康采样预期间隔，用于历史查询的采样空档判定。
	SampleInterval time.Duration
	// BusinessActivityApps 是允许上报可信业务活动的应用白名单。空表示未配置，
	// 此时 RecordBusinessActivity 默认拒绝，不把系统身份当作全应用授权。
	BusinessActivityApps []string
	// BusinessActivityAuthz 校验业务活动的应用归属与用户存在/成员关系；nil 时
	// RecordBusinessActivity 默认拒绝（fail-closed）。
	BusinessActivityAuthz BusinessActivityAuthorizer
}

// Service 是统计服务：构造后不可变、可并发使用；不启动协程、不提供 HTTP 路由。
type Service struct {
	opts           Options
	retentionDays  int
	maxFactRows    int
	sampleInterval time.Duration
	logger         *slog.Logger
}

// New 校验依赖并构造服务。存储、授权与 root 检查器缺失时返回 ErrOptionsInvalid。
func New(options Options) (*Service, error) {
	if isNil(options.Store) {
		return nil, fmt.Errorf("%w: 统计存储为空", ErrOptionsInvalid)
	}
	if isNil(options.Authorizer) {
		return nil, fmt.Errorf("%w: 授权检查器为空", ErrOptionsInvalid)
	}
	if isNil(options.Root) {
		return nil, fmt.Errorf("%w: root 检查器为空", ErrOptionsInvalid)
	}
	retentionDays := options.RetentionDays
	if retentionDays == 0 {
		retentionDays = 180
	}
	if retentionDays < 1 || retentionDays > MaxSampleRetentionDays+365 {
		return nil, fmt.Errorf("%w: 默认保留天数超出范围", ErrOptionsInvalid)
	}
	maxFactRows := options.MaxFactRows
	if maxFactRows == 0 {
		maxFactRows = MaxFactRows
	}
	if maxFactRows < 1 || maxFactRows > MaxFactRows {
		return nil, fmt.Errorf("%w: 活跃事实行数上限超出范围", ErrOptionsInvalid)
	}
	interval := options.SampleInterval
	if interval == 0 {
		interval = time.Minute
	}
	if interval < time.Second || interval > 24*time.Hour {
		return nil, fmt.Errorf("%w: 采样预期间隔超出范围", ErrOptionsInvalid)
	}
	// 构造期校验健康来源：模块必须已登记、不重复、数量受限；配置错误不能等到
	// 运行时才暴露成“未知健康状态”。
	if err := validateHealthSources(options.HealthSources); err != nil {
		return nil, err
	}
	seenApps := make(map[string]bool, len(options.BusinessActivityApps))
	for _, appID := range options.BusinessActivityApps {
		if !validToken(appID, MaxAppIDBytes) {
			return nil, fmt.Errorf("%w: 业务活动应用白名单包含无效应用 ID", ErrOptionsInvalid)
		}
		if seenApps[appID] {
			return nil, fmt.Errorf("%w: 业务活动应用白名单重复", ErrOptionsInvalid)
		}
		seenApps[appID] = true
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	return &Service{opts: options, retentionDays: retentionDays, maxFactRows: maxFactRows,
		sampleInterval: interval, logger: logger}, nil
}

// discardWriter 是丢弃日志输出的 io.Writer。
type discardWriter struct{}

// Write 实现 io.Writer。
func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// isNil 检测 nil 接口与 typed nil 指针。
func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

// now 返回截断到毫秒的 UTC 当前时刻（与数据库毫秒表示一致）。
func (s *Service) now() time.Time {
	clock := s.opts.Now
	if clock == nil {
		clock = time.Now
	}
	return clock().UTC().Truncate(time.Millisecond)
}

// scopeConstraint 是授权后的存储层范围约束与公开说明。
type scopeConstraint struct {
	constraint ScopeConstraint
	scope      ScopeInfo
	trimmed    bool
}

// authorize 解析作用范围并重新授权。root 通过显式 root 检查放行；非 root 依赖
// 注入的 Authorizer，依赖失败一律拒绝（fail-closed）。
func (s *Service) authorize(ctx context.Context, caller account.Caller,
	scopeID string) (scopeConstraint, error) {
	scope, err := parseScope(scopeID)
	if err != nil {
		return scopeConstraint{}, err
	}
	actor := caller.Actor()
	if err := actor.Validate(); err != nil {
		s.recordDenied(ctx, actor, scope.ID, "invalid_actor")
		return scopeConstraint{}, ErrAccessDenied
	}
	if s.isRoot(ctx, caller) {
		// root 只是绕过普通权限引擎，不能绕过调用者显式选择的“应用作用范围”：
		// root + 具体应用范围仍只聚合该应用，避免把单应用查询静默扩大为全系统。
		if scope.Kind == "app" {
			return scopeConstraint{constraint: ScopeConstraint{AppID: scope.ID,
				AppIDs: []string{scope.ID}}, scope: scope}, nil
		}
		return scopeConstraint{constraint: ScopeConstraint{AllData: true,
			IncludeSystem: true}, scope: scope}, nil
	}
	grant, err := s.opts.Authorizer.AuthorizeScope(ctx, caller, PermissionRead, scope.ID)
	if err != nil {
		s.recordDenied(ctx, actor, scope.ID, "authorizer_unavailable")
		return scopeConstraint{}, fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	if !grant.Allowed {
		s.recordDenied(ctx, actor, scope.ID, "not_granted")
		return scopeConstraint{}, ErrAccessDenied
	}
	if scope.Kind == "app" {
		// 应用作用范围：数据范围必须显式包含该应用，不能把“未声明”当全部。
		if !grant.AllData && !containsToken(grant.ResourceIDs, scope.ID) {
			s.recordDenied(ctx, actor, scope.ID, "out_of_scope")
			return scopeConstraint{}, ErrAccessDenied
		}
		return scopeConstraint{constraint: ScopeConstraint{AppID: scope.ID,
			AppIDs: []string{scope.ID}}, scope: scope}, nil
	}
	if grant.AllData {
		return scopeConstraint{constraint: ScopeConstraint{AllData: true,
			IncludeSystem: true}, scope: scope}, nil
	}
	appIDs := make([]string, 0, len(grant.ResourceIDs))
	includeSystem := false
	for _, resource := range grant.ResourceIDs {
		if resource == ScopeSystem {
			includeSystem = true
			continue
		}
		if validToken(resource, 64) {
			appIDs = append(appIDs, resource)
		}
	}
	if len(appIDs) == 0 && !includeSystem {
		s.recordDenied(ctx, actor, scope.ID, "empty_scope")
		return scopeConstraint{}, ErrAccessDenied
	}
	return scopeConstraint{constraint: ScopeConstraint{AppIDs: appIDs,
		IncludeSystem: includeSystem}, scope: scope, trimmed: true}, nil
}

// isRoot 判定调用者是否为 root；依赖失败按非 root 处理。
func (s *Service) isRoot(ctx context.Context, caller account.Caller) bool {
	if caller.Actor().Type != audit.ActorUser {
		return false
	}
	root, err := s.opts.Root.IsRoot(ctx, caller)
	if err != nil {
		return false
	}
	return root
}

// recordDenied 写入一条统计读取拒绝审计；审计不可用只告警，不改变拒绝结论。
func (s *Service) recordDenied(ctx context.Context, actor audit.Actor, scopeID, reason string) {
	if s.opts.Audit == nil {
		return
	}
	err := s.opts.Audit.RecordFailure(ctx, audit.Event{
		Actor: actor, Action: ActionAccessDenied,
		Target:     audit.Target{Type: "statistics", ID: safeToken(scopeID)},
		Outcome:    audit.OutcomeDenied,
		ErrorCode:  "ACCESS_DENIED",
		ReasonCode: safeToken(reason),
	})
	if err != nil {
		s.logger.Error("统计读取拒绝审计写入失败", "code", "AUDIT_WRITE_FAILED")
	}
}

// parseScope 解析作用范围："system" 或应用 ID。
func parseScope(raw string) (ScopeInfo, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ScopeInfo{}, fmt.Errorf("%w: 作用范围不能为空", ErrInvalidRequest)
	}
	if trimmed == ScopeSystem {
		return ScopeInfo{ID: ScopeSystem, Kind: "system"}, nil
	}
	if !validToken(trimmed, 64) {
		return ScopeInfo{}, fmt.Errorf("%w: 作用范围格式无效", ErrInvalidRequest)
	}
	return ScopeInfo{ID: trimmed, Kind: "app"}, nil
}

// validateAppFilter 校验显式应用筛选不越权。应用作用范围只能查自身；系统范围
// 必须落在授权数据范围内。
func validateAppFilter(appID string, scope scopeConstraint) error {
	if appID == "" {
		return nil
	}
	if !validToken(appID, 64) {
		return fmt.Errorf("%w: 应用 ID 格式无效", ErrInvalidRequest)
	}
	if scope.scope.Kind == "app" {
		if appID != scope.scope.ID {
			return fmt.Errorf("%w: 不能查询当前作用范围以外的应用", ErrAccessDenied)
		}
		return nil
	}
	if !scope.constraint.AllData && !containsToken(scope.constraint.AppIDs, appID) {
		return fmt.Errorf("%w: 不能查询当前数据范围以外的应用", ErrAccessDenied)
	}
	return nil
}

// constraintForApp 返回叠加显式应用筛选后的存储约束。
func constraintForApp(base ScopeConstraint, appID string) ScopeConstraint {
	if appID == "" {
		return base
	}
	return ScopeConstraint{AppID: appID, AppIDs: []string{appID}, IncludeSystem: false}
}

// retentionInfo 读取保留策略并计算过滤后的边界。
func (s *Service) retentionInfo(ctx context.Context) (Completeness, error) {
	record, found, err := s.opts.Store.GetRetention(ctx)
	if err != nil {
		return Completeness{}, fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	now := s.now()
	days := s.retentionDays
	configured := false
	cutoff := now.AddDate(0, 0, -days)
	if found {
		if record.Days < 1 || record.Days > 3650 {
			return Completeness{}, fmt.Errorf("%w: 保留策略数据无效", ErrStoreUnavailable)
		}
		days = record.Days
		configured = true
		cutoff = now.AddDate(0, 0, -days)
	}
	return Completeness{
		RetentionDays: days, RetentionConfigured: configured, RetentionCutoff: cutoff,
	}, nil
}

// finalizeCompleteness 根据窗口与保留边界填充缺失区间与权限裁剪/截断标记。
func finalizeCompleteness(base Completeness, window Window, scope scopeConstraint,
	sourceTruncated bool, modulesNotEnabled []Module) Completeness {
	base.WindowWithinRetention = !window.Start.Before(base.RetentionCutoff)
	base.MissingIntervals = nil
	if !base.WindowWithinRetention {
		missingEnd := base.RetentionCutoff
		if missingEnd.After(window.End) {
			missingEnd = window.End
		}
		base.MissingIntervals = append(base.MissingIntervals, MissingInterval{
			Start: window.Start, End: missingEnd, Reason: "retention",
		})
	}
	base.ScopeTrimmed = scope.trimmed
	base.SourceTruncated = sourceTruncated
	base.ModulesNotEnabled = append([]Module(nil), modulesNotEnabled...)
	return base
}

// Activity 聚合 [Start,End) 内成功认证的去重活跃用户，按自然日/周/月分桶。
// 只统计完整成功认证；等待第二因素/等待授权/拒绝/取消/故障不计入。
func (s *Service) Activity(ctx context.Context, request ActivityRequest) (ActivityResult, error) {
	scope, err := s.authorize(ctx, request.Caller, request.ScopeID)
	if err != nil {
		return ActivityResult{}, err
	}
	if err := validateAppFilter(request.AppID, scope); err != nil {
		return ActivityResult{}, err
	}
	window, err := NormalizeWindow(request.Window, s.now())
	if err != nil {
		return ActivityResult{}, err
	}
	completeness, err := s.retentionInfo(ctx)
	if err != nil {
		return ActivityResult{}, err
	}
	constraint := constraintForApp(scope.constraint, request.AppID)
	page, err := s.opts.Store.QueryAuthFacts(ctx, AuthFactQuery{
		From: window.Start, To: window.End, Scope: constraint, Limit: s.maxFactRows,
	})
	if err != nil {
		return ActivityResult{}, fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	points, total := aggregateActivity(window, page.Facts)
	// 完全早于保留边界的桶数值未知，必须标记 unknown（不是 0）。
	markUnknownBeforeRetention(points, completeness.RetentionCutoff)
	completeness = finalizeCompleteness(completeness, window, scope, page.Truncated, nil)
	if page.Truncated {
		for index := range points {
			if points[index].DataStatus == DataComplete {
				points[index].DataStatus = DataPartial
			}
		}
	}
	dedupeScope := "system"
	if request.AppID != "" {
		dedupeScope = "app"
	}
	return ActivityResult{
		Window: window, Metric: MetricActiveUsers, DedupeScope: dedupeScope,
		Points: points, TotalActiveUsers: total, Completeness: completeness,
		GeneratedAt: s.now(),
	}, nil
}

// aggregateActivity 把认证事实聚合到桶并计算窗口内去重用户数。事件按左闭右开
// 桶边界归属，跨午夜不会重复/漏计；多应用视角按稳定用户 ID 去重。
func aggregateActivity(window Window, facts []AuthFact) ([]ActivityPoint, int64) {
	points := make([]ActivityPoint, len(window.Buckets))
	bucketUsers := make([]map[string]struct{}, len(window.Buckets))
	for index, bucket := range window.Buckets {
		points[index] = ActivityPoint{Bucket: bucket, DataStatus: DataComplete}
		if bucket.InProgress {
			points[index].DataStatus = DataInProgress
		}
		bucketUsers[index] = make(map[string]struct{})
	}
	allUsers := make(map[string]struct{})
	for _, fact := range facts {
		if fact.UserID == "" || fact.OccurredAt.Before(window.Start) || !fact.OccurredAt.Before(window.End) {
			continue
		}
		allUsers[fact.UserID] = struct{}{}
		if index := bucketIndex(window.Buckets, fact.OccurredAt); index >= 0 {
			bucketUsers[index][fact.UserID] = struct{}{}
		}
	}
	for index := range points {
		points[index].ActiveUsers = int64(len(bucketUsers[index]))
	}
	return points, int64(len(allUsers))
}

// bucketIndex 返回包含 moment 的桶下标；不落在任何桶时返回 -1。
func bucketIndex(buckets []Bucket, moment time.Time) int {
	index := sortSearchBucket(buckets, moment)
	return index
}

// markUnknownBeforeRetention 把完全早于保留边界的桶标记为未知（不是 0）。已有
// 零散事件但覆盖不完整的桶标记 partial，避免把不可靠的已知值当成完整统计。
func markUnknownBeforeRetention(points []ActivityPoint, cutoff time.Time) {
	for index := range points {
		if points[index].Bucket.End.After(cutoff) {
			continue
		}
		if points[index].ActiveUsers > 0 {
			points[index].DataStatus = DataPartial
			continue
		}
		points[index].DataStatus = DataUnknown
	}
}

// Errors 聚合错误原始次数与去重失败请求/任务数，支持类别筛选与五种白名单排序。
func (s *Service) Errors(ctx context.Context, request ErrorRequest) (ErrorResult, error) {
	scope, err := s.authorize(ctx, request.Caller, request.ScopeID)
	if err != nil {
		return ErrorResult{}, err
	}
	if err := validateAppFilter(request.AppID, scope); err != nil {
		return ErrorResult{}, err
	}
	window, err := NormalizeWindow(request.Window, s.now())
	if err != nil {
		return ErrorResult{}, err
	}
	limit, offset, sortField, order, err := normalizeErrorQuery(request)
	if err != nil {
		return ErrorResult{}, err
	}
	categories, err := normalizeCategories(request.Categories)
	if err != nil {
		return ErrorResult{}, err
	}
	completeness, err := s.retentionInfo(ctx)
	if err != nil {
		return ErrorResult{}, err
	}
	constraint := constraintForApp(scope.constraint, request.AppID)
	groups, truncated, err := s.opts.Store.AggregateErrorGroups(ctx, ErrorGroupQuery{
		From: window.Start, To: window.End, Scope: constraint, Limit: MaxErrorGroups,
	})
	if err != nil {
		return ErrorResult{}, fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	keys, err := s.opts.Store.CountFailureKeys(ctx, FailureKeyQuery{
		From: window.Start, To: window.End, Scope: constraint,
	})
	if err != nil {
		return ErrorResult{}, fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	rows := mergeErrorGroups(groups)
	rows = filterCategories(rows, categories)
	totalRaw := int64(0)
	for _, row := range rows {
		totalRaw += row.RawEvents
	}
	// Compare 为 true 时计算与前一等长窗口的增幅。比较窗口早于保留边界或来源
	// 截断时，增幅不可用。
	compareStart := window.Start.Add(-window.Duration())
	compareEnd := window.Start
	growthAvailable := !request.DisableComparison && !compareStart.Before(completeness.RetentionCutoff)
	previous := map[errorRowKey]int64{}
	if compareStart.Before(compareEnd) {
		prevGroups, prevTruncated, prevErr := s.opts.Store.AggregateErrorGroups(ctx, ErrorGroupQuery{
			From: compareStart, To: compareEnd, Scope: constraint, Limit: MaxErrorGroups,
		})
		if prevErr != nil {
			return ErrorResult{}, fmt.Errorf("%w: %w", ErrStoreUnavailable, prevErr)
		}
		if prevTruncated {
			growthAvailable = false
		}
		for _, row := range mergeErrorGroups(prevGroups) {
			previous[row.key()] += row.RawEvents
		}
	} else {
		growthAvailable = false
	}
	withinRetention := !window.Start.Before(completeness.RetentionCutoff)
	for index := range rows {
		rows[index].Share = 0
		if totalRaw > 0 {
			rows[index].Share = float64(rows[index].RawEvents) / float64(totalRaw)
		}
		prev := previous[rows[index].key()]
		rows[index].Growth = computeGrowth(rows[index].RawEvents, prev, compareStart,
			compareEnd, growthAvailable, !withinRetention)
		rows[index].DataStatus = rowDataStatus(truncated, withinRetention)
	}
	categorySummary := summarizeCategories(rows)
	sortErrorRows(rows, sortField, order)
	pageRows, hasMore := paginate(rows, offset, limit)
	completeness = finalizeCompleteness(completeness, window, scope, truncated, nil)
	return ErrorResult{
		Window: window,
		Comparison: MissingInterval{Start: compareStart, End: compareEnd,
			Reason: comparisonReason(growthAvailable)},
		Rows: pageRows, TotalRawEvents: totalRaw,
		FailedRequests: keys.DistinctRequests, FailedTasks: keys.DistinctTasks,
		ShareDenominator: totalRaw, Categories: categorySummary,
		Sort: sortField, Order: order, Limit: limit, Offset: offset, HasMore: hasMore,
		Completeness: completeness, GeneratedAt: s.now(),
	}, nil
}

// comparisonReason 返回比较窗口不可用原因，可用时返回空字符串。
func comparisonReason(available bool) string {
	if available {
		return ""
	}
	return "comparison_unavailable"
}

// rowDataStatus 计算行完整性状态：来源截断或窗口未完全落在保留期内时为部分，
// 不把不完整数据标记为完整。
func rowDataStatus(truncated, withinRetention bool) DataStatus {
	if truncated || !withinRetention {
		return DataPartial
	}
	return DataComplete
}

// errorRowKey 是错误聚合合并键。
type errorRowKey struct {
	Code     string
	AppID    string
	Category Category
	Severity Severity
}

// key 返回行的合并键。
func (row ErrorRow) key() errorRowKey {
	return errorRowKey{Code: row.ErrorCode, AppID: row.AppID,
		Category: row.Category, Severity: row.Severity}
}

// mergeErrorGroups 把存储层原始分组按统计类别/严重度合并为错误行。未登记错误码
// 保留在未知类别（unknown/unknown），不静默丢弃也不并入故障。
func mergeErrorGroups(groups []ErrorGroupRow) []ErrorRow {
	merged := make(map[errorRowKey]*ErrorRow, len(groups))
	order := make([]errorRowKey, 0, len(groups))
	for _, group := range groups {
		classification := ClassifyEvent(group.Outcome, group.ErrorCode, group.Action)
		if !classification.Counted {
			continue
		}
		key := errorRowKey{Code: group.ErrorCode, AppID: group.AppID,
			Category: classification.Category, Severity: classification.Severity}
		row, exists := merged[key]
		if !exists {
			row = &ErrorRow{ErrorCode: group.ErrorCode, Category: classification.Category,
				Severity: classification.Severity, AppID: group.AppID}
			merged[key] = row
			order = append(order, key)
		}
		row.RawEvents += group.RawEvents
		row.FailedRequests += group.FailedRequests
		row.FailedTasks += group.FailedTasks
		if row.FirstSeen.IsZero() || (!group.FirstSeen.IsZero() && group.FirstSeen.Before(row.FirstSeen)) {
			row.FirstSeen = group.FirstSeen
		}
		if group.LastSeen.After(row.LastSeen) {
			row.LastSeen = group.LastSeen
		}
	}
	rows := make([]ErrorRow, 0, len(order))
	for _, key := range order {
		rows = append(rows, *merged[key])
	}
	return rows
}

// filterCategories 按请求类别过滤（空表示全部）。
func filterCategories(rows []ErrorRow, categories map[Category]bool) []ErrorRow {
	if len(categories) == 0 {
		return rows
	}
	filtered := make([]ErrorRow, 0, len(rows))
	for _, row := range rows {
		if categories[row.Category] {
			filtered = append(filtered, row)
		}
	}
	return filtered
}

// normalizeCategories 校验并去重类别筛选。
func normalizeCategories(categories []Category) (map[Category]bool, error) {
	if len(categories) == 0 {
		return nil, nil
	}
	result := make(map[Category]bool, len(categories))
	for _, category := range categories {
		if !category.Valid() {
			return nil, fmt.Errorf("%w: 错误类别未定义", ErrInvalidRequest)
		}
		result[category] = true
	}
	return result, nil
}

// summarizeCategories 按固定类别顺序汇总；没有事件的类别也出现（真实零值）。
func summarizeCategories(rows []ErrorRow) []CategorySummary {
	order := []Category{CategoryPending, CategoryDenied, CategoryCancelled,
		CategoryWarning, CategoryFailure, CategoryUnknown}
	summary := make([]CategorySummary, len(order))
	index := make(map[Category]int, len(order))
	for position, category := range order {
		summary[position] = CategorySummary{Category: category, Severity: categoryDefaultSeverity(category)}
		index[category] = position
	}
	for _, row := range rows {
		position, exists := index[row.Category]
		if !exists {
			continue
		}
		summary[position].RawEvents += row.RawEvents
		summary[position].FailedRequests += row.FailedRequests
		summary[position].FailedTasks += row.FailedTasks
		if summary[position].Severity == SeverityUnknown || row.Severity.Rank() > summary[position].Severity.Rank() {
			summary[position].Severity = row.Severity
		}
	}
	return summary
}

// categoryDefaultSeverity 返回类别在无样本时的默认严重度。
func categoryDefaultSeverity(category Category) Severity {
	switch category {
	case CategoryPending, CategoryDenied, CategoryCancelled:
		return SeverityInfo
	case CategoryWarning:
		return SeverityWarning
	case CategoryFailure:
		return SeverityError
	default:
		return SeverityUnknown
	}
}

// normalizeErrorQuery 校验并填充错误查询的排序/分页参数。
func normalizeErrorQuery(request ErrorRequest) (int, int, ErrorSort, SortOrder, error) {
	limit := request.Limit
	if limit == 0 {
		limit = DefaultErrorLimit
	}
	if limit < 1 || limit > MaxErrorLimit {
		return 0, 0, "", "", fmt.Errorf("%w: 每页条数必须在 1～%d 之间", ErrInvalidRequest, MaxErrorLimit)
	}
	offset := request.Offset
	if offset < 0 || offset > MaxOffset {
		return 0, 0, "", "", fmt.Errorf("%w: 分页偏移超出范围", ErrInvalidRequest)
	}
	sortField := request.Sort
	if sortField == "" {
		sortField = ErrorSortRaw
	}
	switch sortField {
	case ErrorSortRaw, ErrorSortShare, ErrorSortFirst, ErrorSortLast, ErrorSortGrowth:
	default:
		return 0, 0, "", "", fmt.Errorf("%w: 排序字段未登记", ErrInvalidRequest)
	}
	order := request.Order
	if order == "" {
		order = SortDesc
	}
	if order != SortDesc && order != SortAsc {
		return 0, 0, "", "", fmt.Errorf("%w: 排序方向只支持 desc/asc", ErrInvalidRequest)
	}
	return limit, offset, sortField, order, nil
}

// computeGrowth 计算增幅。零基数规则固定：前值为 0 且本期 > 0 为“新增”；
// 两者均为 0 为“无变化”；比较数据缺失/不完整时不可用；前值 > 0 时给百分比。
func computeGrowth(current, previous int64, compareStart, compareEnd time.Time,
	available, windowIncomplete bool) Growth {
	growth := Growth{Kind: GrowthUnavailable, ComparisonStart: compareStart, ComparisonEnd: compareEnd}
	if !available || windowIncomplete {
		return growth
	}
	switch {
	case previous == 0 && current == 0:
		growth.Kind = GrowthNone
	case previous == 0:
		growth.Kind = GrowthNew
	default:
		growth.Kind = GrowthPercent
		growth.Percent = math.Round((float64(current-previous)/float64(previous))*10000) / 100
	}
	return growth
}

// sortErrorRows 按白名单字段排序，并始终使用稳定次级键（类别、错误码、应用），
// 保证翻页不重复/不漏行。增幅排序时空值/不可用固定排最后。
func sortErrorRows(rows []ErrorRow, field ErrorSort, order SortOrder) {
	sort.SliceStable(rows, func(i, j int) bool {
		left, right := rows[i], rows[j]
		if field == ErrorSortGrowth {
			leftAvailable := left.Growth.Kind != GrowthUnavailable
			rightAvailable := right.Growth.Kind != GrowthUnavailable
			if leftAvailable != rightAvailable {
				return leftAvailable
			}
			if leftAvailable {
				leftValue, rightValue := growthSortValue(left.Growth), growthSortValue(right.Growth)
				if leftValue != rightValue {
					if order == SortAsc {
						return leftValue < rightValue
					}
					return leftValue > rightValue
				}
			}
			return stableRowLess(left, right, SortDesc)
		}
		var less, greater bool
		switch field {
		case ErrorSortFirst:
			less, greater = left.FirstSeen.Before(right.FirstSeen), left.FirstSeen.After(right.FirstSeen)
		case ErrorSortLast:
			less, greater = left.LastSeen.Before(right.LastSeen), left.LastSeen.After(right.LastSeen)
		case ErrorSortShare:
			less, greater = left.Share < right.Share, left.Share > right.Share
		default:
			less, greater = left.RawEvents < right.RawEvents, left.RawEvents > right.RawEvents
		}
		if less || greater {
			if order == SortAsc {
				return less
			}
			return greater
		}
		return stableRowLess(left, right, SortDesc)
	})
}

// growthSortValue 返回增幅排序数值：新增视为最大（正无穷的有限表示），无变化为
// 0，百分比为实际值；不可用由调用方单独排最后。
func growthSortValue(growth Growth) float64 {
	switch growth.Kind {
	case GrowthNew:
		return math.MaxFloat64
	case GrowthNone:
		return 0
	case GrowthPercent:
		return growth.Percent
	default:
		return math.Inf(-1)
	}
}

// stableRowLess 是稳定次级键：类别、错误码、应用 ID 升序。
func stableRowLess(left, right ErrorRow, order SortOrder) bool {
	if left.Category != right.Category {
		return left.Category < right.Category
	}
	if left.ErrorCode != right.ErrorCode {
		return left.ErrorCode < right.ErrorCode
	}
	return left.AppID < right.AppID
}

// paginate 对已排序行做受控分页；HasMore 由长度比较判定，不伪造总数。
func paginate(rows []ErrorRow, offset, limit int) ([]ErrorRow, bool) {
	if offset >= len(rows) {
		return []ErrorRow{}, false
	}
	end := offset + limit
	if end > len(rows) {
		end = len(rows)
	}
	return rows[offset:end], end < len(rows)
}

// Overview 返回同一统计上下文下的看板摘要。
func (s *Service) Overview(ctx context.Context, request OverviewRequest) (OverviewResult, error) {
	activity, err := s.Activity(ctx, ActivityRequest{
		Caller: request.Caller, ScopeID: request.ScopeID, Window: request.Window,
		AppID: request.AppID,
	})
	if err != nil {
		return OverviewResult{}, err
	}
	errorsResult, err := s.Errors(ctx, ErrorRequest{
		Caller: request.Caller, ScopeID: request.ScopeID, Window: request.Window,
		AppID: request.AppID, Limit: 1,
	})
	if err != nil {
		return OverviewResult{}, err
	}
	scope, _ := parseScope(request.ScopeID)
	activityStatus := DataComplete
	for _, point := range activity.Points {
		if point.DataStatus != DataComplete {
			activityStatus = point.DataStatus
			break
		}
	}
	return OverviewResult{
		Window: activity.Window, Scope: scope, ActiveUsers: activity.TotalActiveUsers,
		TotalRawEvents: errorsResult.TotalRawEvents,
		FailedRequests: errorsResult.FailedRequests, FailedTasks: errorsResult.FailedTasks,
		Categories: errorsResult.Categories, ActivityStatus: activityStatus,
		Completeness: errorsResult.Completeness, GeneratedAt: s.now(),
	}, nil
}

// RecordBusinessActivity 记录一条可信业务活动。可信来源校验是组合条件，缺一不可：
//   - 调用者必须是系统身份（应用服务端在可信边界构造），普通用户会话/浏览器参数
//     不能自称该来源；
//   - 应用必须在显式配置的白名单内（空白名单=未配置，默认拒绝）；
//   - user_id 必须是合法稳定用户 ID，并通过注入的 BusinessActivityAuthorizer 校验
//     用户存在且属于该应用（不存在/跨应用/依赖失败一律拒绝）；
//   - dedupe_key 绑定应用幂等：重复上报按幂等成功返回、不重复计数，另一个应用使用
//     相同幂等键不会吞掉本应用事件。
//
// 任一校验失败 fail-closed 并写拒绝审计；未装配授权器同样拒绝，不静默放行。
func (s *Service) RecordBusinessActivity(ctx context.Context, request BusinessActivityRequest) error {
	actor := request.Caller.Actor()
	if err := actor.Validate(); err != nil {
		return ErrAccessDenied
	}
	if actor.Type != audit.ActorSystem {
		s.recordDenied(ctx, actor, request.AppID, "business_activity_untrusted_source")
		return ErrAccessDenied
	}
	if !validToken(request.AppID, MaxAppIDBytes) {
		return fmt.Errorf("%w: 应用 ID 格式无效", ErrInvalidRequest)
	}
	allowed := false
	for _, appID := range s.opts.BusinessActivityApps {
		if appID == request.AppID {
			allowed = true
			break
		}
	}
	if len(s.opts.BusinessActivityApps) == 0 {
		s.recordDenied(ctx, actor, request.AppID, "business_activity_not_configured")
		return ErrAccessDenied
	}
	if !allowed {
		s.recordDenied(ctx, actor, request.AppID, "business_activity_app_not_allowed")
		return ErrAccessDenied
	}
	if request.UserID == "" || !account.ValidUserID(request.UserID) {
		return fmt.Errorf("%w: 业务活动用户 ID 格式无效", ErrInvalidRequest)
	}
	if isNil(s.opts.BusinessActivityAuthz) {
		s.recordDenied(ctx, actor, request.AppID, "business_activity_authz_missing")
		return ErrAccessDenied
	}
	if err := s.opts.BusinessActivityAuthz.AuthorizeBusinessActivity(ctx, actor,
		request.AppID, request.UserID); err != nil {
		s.recordDenied(ctx, actor, request.AppID, "business_activity_not_authorized")
		return ErrAccessDenied
	}
	if !validToken(request.ActivityKey, MaxActivityKeyBytes) {
		return fmt.Errorf("%w: 业务活动标识无效", ErrInvalidRequest)
	}
	if !validToken(request.DedupeKey, MaxDedupeKeyBytes) {
		return fmt.Errorf("%w: 幂等键无效", ErrInvalidRequest)
	}
	occurredAt := request.OccurredAt.UTC()
	if occurredAt.IsZero() {
		return fmt.Errorf("%w: 业务活动发生时间不能为空", ErrInvalidRequest)
	}
	if occurredAt.After(s.now().Add(time.Minute)) {
		return fmt.Errorf("%w: 业务活动发生时间不能在未来", ErrInvalidRequest)
	}
	if _, err := s.opts.Store.InsertBusinessActivity(ctx, BusinessActivityRecord{
		AppID: request.AppID, UserID: request.UserID, ActivityKey: request.ActivityKey,
		OccurredAt: occurredAt, RecordedAt: s.now(), Source: SourceAppServer,
		DedupeKey: request.DedupeKey,
	}); err != nil {
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	return nil
}

// BusinessActivity 聚合可信业务活动（独立口径，不与登录活跃相加）。
func (s *Service) BusinessActivity(ctx context.Context,
	request BusinessActivityQuery) (BusinessActivityResult, error) {
	scope, err := s.authorize(ctx, request.Caller, request.ScopeID)
	if err != nil {
		return BusinessActivityResult{}, err
	}
	if err := validateAppFilter(request.AppID, scope); err != nil {
		return BusinessActivityResult{}, err
	}
	if request.ActivityKey != "" && !validToken(request.ActivityKey, MaxActivityKeyBytes) {
		return BusinessActivityResult{}, fmt.Errorf("%w: 业务活动标识无效", ErrInvalidRequest)
	}
	window, err := NormalizeWindow(request.Window, s.now())
	if err != nil {
		return BusinessActivityResult{}, err
	}
	completeness, err := s.retentionInfo(ctx)
	if err != nil {
		return BusinessActivityResult{}, err
	}
	constraint := constraintForApp(scope.constraint, request.AppID)
	page, err := s.opts.Store.QueryBusinessActivity(ctx, BusinessActivityFactQuery{
		From: window.Start, To: window.End, Scope: constraint,
		Limit: MaxBusinessActivityRows, AppID: request.AppID,
	})
	if err != nil {
		return BusinessActivityResult{}, fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	points := make([]BusinessActivityPoint, len(window.Buckets))
	bucketEvents := make([]int64, len(window.Buckets))
	bucketUsers := make([]map[string]struct{}, len(window.Buckets))
	for index, bucket := range window.Buckets {
		points[index] = BusinessActivityPoint{Bucket: bucket, DataStatus: DataComplete}
		if bucket.InProgress {
			points[index].DataStatus = DataInProgress
		}
		bucketUsers[index] = make(map[string]struct{})
	}
	allUsers := make(map[string]struct{})
	totalEvents := int64(0)
	for _, fact := range page.Facts {
		if request.ActivityKey != "" && fact.ActivityKey != request.ActivityKey {
			continue
		}
		if fact.OccurredAt.Before(window.Start) || !fact.OccurredAt.Before(window.End) {
			continue
		}
		totalEvents++
		if fact.UserID != "" {
			allUsers[fact.UserID] = struct{}{}
		}
		if index := bucketIndex(window.Buckets, fact.OccurredAt); index >= 0 {
			bucketEvents[index]++
			if fact.UserID != "" {
				bucketUsers[index][fact.UserID] = struct{}{}
			}
		}
	}
	for index := range points {
		points[index].Events = bucketEvents[index]
		points[index].DistinctUsers = int64(len(bucketUsers[index]))
		if page.Truncated && points[index].DataStatus == DataComplete {
			points[index].DataStatus = DataPartial
		}
	}
	dedupeScope := "system"
	if request.AppID != "" {
		dedupeScope = "app"
	}
	completeness = finalizeCompleteness(completeness, window, scope, page.Truncated, nil)
	return BusinessActivityResult{
		Window: window, Source: SourceAppServer, ActivityKey: request.ActivityKey,
		Points: points, TotalEvents: totalEvents, DistinctUsers: int64(len(allUsers)),
		DedupeScope: dedupeScope, Completeness: completeness, GeneratedAt: s.now(),
	}, nil
}

// safeToken 把任意输入压缩为稳定的安全标识，用于审计目标/原因码。
func safeToken(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer(" ", "_", "\n", "_", "\r", "_")
	trimmed = replacer.Replace(trimmed)
	if len(trimmed) > 64 {
		trimmed = trimmed[:64]
	}
	var builder strings.Builder
	for _, r := range trimmed {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			builder.WriteRune(r)
		}
	}
	if builder.Len() == 0 {
		return "unknown"
	}
	return builder.String()
}

// containsToken 报告集合是否包含指定稳定标识。
func containsToken(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
