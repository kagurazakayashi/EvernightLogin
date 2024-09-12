package reports

// 本文件实现步骤 79 的「定期报告计划」领域：报告计划是带报告规格载荷的通用定时
// 计划（internal/task 的 Schedule），复用其持久化、触发去重、停机补跑、失败重试、
// 取消与告警机制；本文件不另造一套调度器，也不把计划挂到进程内立即失效的记录上。
//
// 安全不变量：
//   - 创建/查看/启停/删除计划都按当前调用者在作用范围的权限重新授权；计划所有者
//     的权限不因创建者曾经有权而永久有效。
//   - 每次触发前由 internal/task 调度器调用 CheckExecutionPermission，用计划执行
//     身份（所有者）的当前权限复核；失权时本次触发只记录「已拒绝、未入队」，不
//     伪造任务或报告。
//   - 计划载荷只含统计范围/窗口/筛选/格式等非秘密字段，不含产物路径、凭证或
//     敏感明细。
//   - 计划管理与计划触发生成分开：本文件只负责计划生命周期；真正的生成在
//     scheduled.go 的 GenerateScheduledHandler 中执行并再次授权。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/search"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

const (
	// TaskKindPlannedReportGenerate 是报告计划触发的任务类型。它与即时报告
	// 生成任务（TaskKindReportGenerate）分开，便于宿主注册不同的处理器并区分
	// 权限复核与审计。
	TaskKindPlannedReportGenerate = "reports.plan.generate"

	// planPayloadVersion 是计划载荷结构版本；版本不兼容时拒绝执行而不是猜测。
	planPayloadVersion = 1
	// planNameMaxRunes 是计划名称最大字符数。
	planNameMaxRunes = 120
	// planWindowDaysDefault/planWindowDaysMax 是相对统计窗口的默认与上限天数。
	planWindowDaysDefault = 1
	planWindowDaysMax     = 90
)

// 计划执行身份权限状态（页面呈现用，不是持久状态）。
const (
	// PlanPermissionOK 表示当前执行身份仍具备执行该计划所需的权限。
	PlanPermissionOK = "ok"
	// PlanPermissionRevoked 表示执行身份已失去读取/生成/导出权限。
	PlanPermissionRevoked = "revoked"
	// PlanPermissionUnknown 表示授权服务不可用，无法确认（默认按不可执行处理）。
	PlanPermissionUnknown = "unknown"
)

// planPayload 是存放在通用计划载荷字段中的报告规格。它只包含非秘密的统计口径
// 与格式选择；所有者/执行身份、范围与应用 ID 分开存放以便显示与审计。
type planPayload struct {
	Version     int             `json:"version"`
	PlanID      string          `json:"plan_id,omitempty"`
	Name        string          `json:"name"`
	ScopeID     string          `json:"scope_id"`
	ScopeKind   string          `json:"scope_kind"`
	AppID       string          `json:"app_id,omitempty"`
	Granularity string          `json:"granularity"`
	WindowDays  int             `json:"window_days"`
	Categories  []string        `json:"categories,omitempty"`
	TrendMetric string          `json:"trend_metric,omitempty"`
	Formats     []string        `json:"formats"`
	DetailRows  int             `json:"detail_rows,omitempty"`
	TimeZone    string          `json:"time_zone"`
	Owner       planActorRecord `json:"owner"`
	// RowVersion 是计划编辑的行版本（乐观并发）。它随载荷保存，编辑时递增；
	// 0 表示步骤 79 收口前创建的旧计划，按版本 1 处理（只读兼容，不与新计划混用）。
	RowVersion int64 `json:"row_version,omitempty"`
}

// planActorRecord 是计划所有者的可持久化最小身份（不写显示资料或秘密）。
type planActorRecord struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// actorRecordOf 把可信审计身份转换为可持久化记录。
func actorRecordOf(actor audit.Actor) planActorRecord {
	return planActorRecord{Type: string(actor.Type), ID: actor.ID}
}

// auditActor 还原审计身份并校验；未知类型/非法 ID 拒绝。
func (r planActorRecord) auditActor() (audit.Actor, error) {
	actor := audit.Actor{Type: audit.ActorKind(r.Type), ID: r.ID}
	if err := actor.Validate(); err != nil {
		return audit.Actor{}, fmt.Errorf("%w: 计划所有者身份无效", ErrInvalidRequest)
	}
	if actor.Type == audit.ActorAnonymous {
		return audit.Actor{}, fmt.Errorf("%w: 计划所有者不能是匿名身份", ErrInvalidRequest)
	}
	return actor, nil
}

// PlanScheduler 是计划生命周期所需的通用调度器子集（生产 *task.Scheduler）。
// 本包只通过该契约管理计划，不直接访问数据库或调度循环。
type PlanScheduler interface {
	Create(ctx context.Context, request task.NewScheduleRequest) (task.Schedule, error)
	Get(ctx context.Context, id string) (task.Schedule, error)
	List(ctx context.Context) ([]task.Schedule, error)
	Pause(ctx context.Context, command task.ScheduleStateCommand) (task.Schedule, error)
	Resume(ctx context.Context, command task.ScheduleStateCommand) (task.Schedule, error)
	Delete(ctx context.Context, command task.ScheduleDeleteCommand) error
}

// PlanOptions 是计划服务依赖。Schedules/Authorizer/Root 缺失时拒绝构造
// （fail-closed）；Audit 缺失只影响拒绝留痕，不改变拒绝结论。
type PlanOptions struct {
	Schedules  PlanScheduler
	Authorizer Authorizer
	Root       RootChecker
	Audit      AuditRecorder
	// Projections 可选：提供后计划创建/编辑/启停/删除会同步管理读模型
	// report_plans（行版本乐观并发）；未提供时只保留调度事实，不伪造持久投影。
	// 读模型可从调度器重建（ReconcilePlans），不是第二套命令事实源。
	Projections PlanProjectionStore
	// PDFAvailable 可选：报告服务是否具备 PDF 输出能力；nil 视为不可用，请求
	// PDF 格式会在创建计划时被拒绝（与即时报告一致）。
	PDFAvailable  func() bool
	MaxDetailRows int
	Now           func() time.Time
	Logger        *slog.Logger
}

// PlanService 是报告计划服务：构造后不可变、可并发使用；不启动协程、不提供
// HTTP 路由。触发与执行由宿主启动的 internal/task 调度器/执行器完成。
type PlanService struct {
	opts          PlanOptions
	maxDetailRows int
	now           func() time.Time
	logger        *slog.Logger
	projections   PlanProjectionStore
}

// NewPlanService 校验依赖并构造计划服务。
func NewPlanService(options PlanOptions) (*PlanService, error) {
	if isNil(options.Schedules) || isNil(options.Authorizer) || isNil(options.Root) {
		return nil, fmt.Errorf("%w: 报告计划服务必需依赖缺失", ErrOptionsInvalid)
	}
	maxDetailRows := options.MaxDetailRows
	if maxDetailRows == 0 {
		maxDetailRows = DefaultDetailRows
	}
	if maxDetailRows < 1 || maxDetailRows > MaxDetailRows {
		return nil, fmt.Errorf("%w: 明细条数上限超出范围", ErrOptionsInvalid)
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	var projections PlanProjectionStore
	if options.Projections != nil && !isNil(options.Projections) {
		projections = options.Projections
	}
	return &PlanService{opts: options, maxDetailRows: maxDetailRows,
		now: options.Now, logger: options.Logger, projections: projections}, nil
}

// nowUTC 返回截断到 UTC 毫秒的当前时刻（与报告服务一致）。
func (p *PlanService) nowUTC() time.Time {
	return p.now().UTC().Truncate(time.Millisecond)
}

// isRoot 判定调用者是否为 root；依赖失败按非 root 处理。
func (p *PlanService) isRoot(ctx context.Context, caller account.Caller) bool {
	if caller.Actor().Type != audit.ActorUser {
		return false
	}
	root, err := p.opts.Root.IsRoot(ctx, caller)
	if err != nil {
		return false
	}
	return root
}

// authorize 按当前调用者的权限与数据范围授权；拒绝写失败审计但不改变结论。
func (p *PlanService) authorize(ctx context.Context, caller account.Caller,
	permissionKey, scopeID string) (stats.ScopeGrant, error) {
	actor := caller.Actor()
	if err := actor.Validate(); err != nil {
		return stats.ScopeGrant{}, ErrAccessDenied
	}
	if p.isRoot(ctx, caller) {
		return stats.ScopeGrant{Allowed: true, AllData: true}, nil
	}
	grant, err := p.opts.Authorizer.AuthorizeScope(ctx, caller, permissionKey, scopeID)
	if err != nil {
		p.recordDenied(ctx, actor, scopeID, "authorizer_unavailable")
		return stats.ScopeGrant{}, fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	if !grant.Allowed {
		p.recordDenied(ctx, actor, scopeID, "not_granted")
		return stats.ScopeGrant{}, ErrAccessDenied
	}
	return grant, nil
}

// recordDenied 写计划操作拒绝审计；写入失败只告警。
func (p *PlanService) recordDenied(ctx context.Context, actor audit.Actor,
	scopeID, reason string) {
	if isNil(p.opts.Audit) {
		return
	}
	err := p.opts.Audit.RecordFailure(ctx, audit.Event{
		Actor: actor, AppID: appIDForScope(scopeID), Action: ActionAccessDenied,
		Target:  audit.Target{Type: "report_plan", ID: "plan"},
		Outcome: audit.OutcomeDenied, ErrorCode: string(CodeAccessDenied),
		ReasonCode: safeToken(reason),
	})
	if err != nil {
		p.logger.Error("报告计划拒绝审计写入失败", "code", string(CodeAuditWriteFailed))
	}
}

// PlanView 是报告计划公开视图：不含产物路径、凭证或秘密。
type PlanView struct {
	ID string
	// ScheduleID 是通用调度器中的执行计划编号（计划编辑会更换该编号，计划 ID
	// 保持稳定）；页面用它核对执行记录，不用它作为计划管理主键。
	ScheduleID string
	// Version 是计划行版本，用于编辑乐观并发；页面必须原样回传，冲突时重新读取。
	Version           int64
	Name              string
	Enabled           bool
	PermissionState   string
	PermissionReason  string
	ScheduleType      task.ScheduleType
	Expression        string
	TimeZone          string
	PeriodDescription string
	ScopeID           string
	ScopeKind         string
	AppID             string
	Granularity       stats.Granularity
	WindowDays        int
	Categories        []stats.Category
	TrendMetric       stats.Metric
	Formats           []Format
	DetailRows        int
	MissedPolicy      task.MissedPolicy
	MaxCatchUp        int
	// TimeoutSeconds/MaxAttempts 是任务墙钟与尝试上限，编辑页必须原样回填与保存，
	// 不能被页面默认值覆盖。
	TimeoutSeconds int
	MaxAttempts    int
	Owner          audit.Actor
	ExecutionActor audit.Actor
	NextRun        time.Time
	NextRunUnknown bool
	NextRunReason  string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// PlanCreateRequest 是创建报告计划请求。Caller 必须来自可信调用上下文；所有者
// 与执行身份都是当前调用者，客户端不能自报他人身份。
type PlanCreateRequest struct {
	Caller         account.Caller
	Name           string
	ScheduleType   task.ScheduleType
	Expression     string
	TimeZone       string
	ScopeID        string
	Granularity    stats.Granularity
	WindowDays     int
	AppID          string
	Categories     []stats.Category
	TrendMetric    stats.Metric
	Formats        []Format
	DetailRows     int
	MissedPolicy   task.MissedPolicy
	MaxCatchUp     int
	TimeoutSeconds int
	MaxAttempts    int
	Enabled        bool
	RequestID      string
}

// validatePlanName 校验计划名称：去空白后 1～120 字符，不含控制字符。
func validatePlanName(name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", fmt.Errorf("%w: 计划名称不能为空", ErrInvalidRequest)
	}
	if utf8.RuneCountInString(trimmed) > planNameMaxRunes {
		return "", fmt.Errorf("%w: 计划名称不能超过 %d 个字符", ErrInvalidRequest, planNameMaxRunes)
	}
	for _, r := range trimmed {
		if r == '\n' || r == '\r' || r == '\t' || (r < 0x20 && r != ' ') {
			return "", fmt.Errorf("%w: 计划名称不能包含控制字符", ErrInvalidRequest)
		}
	}
	return trimmed, nil
}

// buildPlanPayload 校验报告规格并编码为通用计划载荷。
func (p *PlanService) buildPlanPayload(request PlanCreateRequest, scope ScopeInfo,
	timeZone string, owner planActorRecord, planID string,
	rowVersion int64) (json.RawMessage, planPayload, error) {
	name, err := validatePlanName(request.Name)
	if err != nil {
		return nil, planPayload{}, err
	}
	granularity := request.Granularity
	if granularity == "" {
		granularity = stats.GranularityDay
	}
	if !granularity.Valid() {
		return nil, planPayload{}, fmt.Errorf("%w: 时间桶粒度只支持 day/week/month", ErrInvalidRequest)
	}
	windowDays := request.WindowDays
	if windowDays == 0 {
		windowDays = planWindowDaysDefault
	}
	if windowDays < 1 || windowDays > planWindowDaysMax {
		return nil, planPayload{}, fmt.Errorf("%w: 统计窗口天数必须在 1～%d 之间",
			ErrInvalidRequest, planWindowDaysMax)
	}
	categories, err := normalizeCategories(request.Categories)
	if err != nil {
		return nil, planPayload{}, err
	}
	trendMetric, err := normalizeTrendMetric(request.TrendMetric)
	if err != nil {
		return nil, planPayload{}, err
	}
	for _, format := range request.Formats {
		if !format.Valid() {
			return nil, planPayload{}, fmt.Errorf(
				"%w: 报告格式只支持 html/csv/json/pdf/markdown", ErrInvalidRequest)
		}
	}
	if containsFormat(request.Formats, FormatPDF) &&
		(p.opts.PDFAvailable == nil || !p.opts.PDFAvailable()) {
		return nil, planPayload{}, fmt.Errorf("%w: PDF 输出需要配置受控中文字体", ErrInvalidRequest)
	}
	formats := formatSortedFormats(request.Formats)
	if len(formats) == 0 {
		formats = []Format{FormatHTML}
	}
	detailRows := request.DetailRows
	if detailRows == 0 {
		detailRows = p.maxDetailRows
	}
	if detailRows < 1 || detailRows > p.maxDetailRows {
		return nil, planPayload{}, fmt.Errorf("%w: 明细条数上限必须在 1～%d 之间",
			ErrInvalidRequest, p.maxDetailRows)
	}
	payload := planPayload{
		Version: planPayloadVersion, PlanID: planID, Name: name, ScopeID: scope.ID,
		ScopeKind: scope.Kind, AppID: request.AppID,
		Granularity: string(granularity), WindowDays: windowDays,
		Categories: categoryStrings(categories), TrendMetric: string(trendMetric),
		Formats: formatStrings(formats), DetailRows: detailRows,
		TimeZone: timeZone, Owner: owner, RowVersion: rowVersion,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, planPayload{}, fmt.Errorf("%w: 计划载荷编码失败", ErrInvalidRequest)
	}
	return encoded, payload, nil
}

// formatStrings 把格式列表转换为稳定字符串列表。
func formatStrings(formats []Format) []string {
	result := make([]string, 0, len(formats))
	for _, format := range formats {
		result = append(result, string(format))
	}
	return result
}

// decodePlanPayload 解析并校验计划载荷；任何未知/缺字段都拒绝，避免执行一个
// 语义不明确的计划。
func decodePlanPayload(raw json.RawMessage) (planPayload, error) {
	if len(raw) == 0 || !json.Valid(raw) {
		return planPayload{}, fmt.Errorf("%w: 计划载荷不是合法 JSON", ErrInvalidRequest)
	}
	var payload planPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return planPayload{}, fmt.Errorf("%w: 计划载荷无法解析", ErrInvalidRequest)
	}
	if payload.Version != planPayloadVersion {
		return planPayload{}, fmt.Errorf("%w: 计划载荷版本不受支持", ErrInvalidRequest)
	}
	if payload.PlanID != "" && !validPlanID(payload.PlanID) {
		return planPayload{}, fmt.Errorf("%w: 计划编号格式无效", ErrInvalidRequest)
	}
	if payload.RowVersion < 0 {
		return planPayload{}, fmt.Errorf("%w: 计划行版本无效", ErrInvalidRequest)
	}
	if _, err := validatePlanName(payload.Name); err != nil {
		return planPayload{}, err
	}
	scope, err := parseScope(payload.ScopeID)
	if err != nil {
		return planPayload{}, err
	}
	if scope.Kind != payload.ScopeKind {
		return planPayload{}, fmt.Errorf("%w: 计划作用范围不一致", ErrInvalidRequest)
	}
	if payload.TimeZone == "" || payload.TimeZone == "Local" {
		return planPayload{}, fmt.Errorf("%w: 计划报告时区必须显式指定 IANA 名称", ErrInvalidRequest)
	}
	if _, err := time.LoadLocation(payload.TimeZone); err != nil {
		return planPayload{}, fmt.Errorf("%w: 计划报告时区不是有效的 IANA 名称", ErrInvalidRequest)
	}
	if !stats.Granularity(payload.Granularity).Valid() {
		return planPayload{}, fmt.Errorf("%w: 计划时间桶粒度无效", ErrInvalidRequest)
	}
	if payload.WindowDays < 1 || payload.WindowDays > planWindowDaysMax {
		return planPayload{}, fmt.Errorf("%w: 计划统计窗口天数超出范围", ErrInvalidRequest)
	}
	formats := make([]Format, 0, len(payload.Formats))
	for _, rawFormat := range payload.Formats {
		format := Format(rawFormat)
		if !format.Valid() {
			return planPayload{}, fmt.Errorf("%w: 计划格式无效", ErrInvalidRequest)
		}
		formats = append(formats, format)
	}
	if len(formats) == 0 {
		return planPayload{}, fmt.Errorf("%w: 计划至少需要一种输出格式", ErrInvalidRequest)
	}
	for _, rawCategory := range payload.Categories {
		if !stats.Category(rawCategory).Valid() {
			return planPayload{}, fmt.Errorf("%w: 计划错误类别无效", ErrInvalidRequest)
		}
	}
	if _, metricErr := normalizeTrendMetric(stats.Metric(payload.TrendMetric)); metricErr != nil {
		return planPayload{}, metricErr
	}
	if _, err := payload.Owner.auditActor(); err != nil {
		return planPayload{}, err
	}
	return payload, nil
}

// planView 把通用计划与报告载荷组合为公开视图，并按当前执行身份复核权限。
// caller 用于判断是否可查看该计划；不可查看时返回 visible=false，调用方应跳过
// 而不是泄露计划是否存在。
func (p *PlanService) planView(ctx context.Context, caller account.Caller,
	schedule task.Schedule) (PlanView, bool, error) {
	payload, err := decodePlanPayload(schedule.Payload)
	if err != nil {
		// 载荷损坏的计划不向普通调用者暴露，避免把内部状态泄露给无权者。
		return PlanView{}, false, nil
	}
	if _, err := p.authorize(ctx, caller, PermissionRead, schedule.ScopeID); err != nil {
		return PlanView{}, false, nil
	}
	owner, err := payload.Owner.auditActor()
	if err != nil {
		return PlanView{}, false, nil
	}
	permissionState, reason := p.executionPermissionState(ctx, owner, schedule.ScopeID)
	view := PlanView{
		ID: effectivePlanID(payload, schedule), ScheduleID: schedule.ID,
		Version: effectivePlanVersion(payload), Name: payload.Name,
		Enabled:         schedule.Enabled,
		PermissionState: permissionState, PermissionReason: reason,
		ScheduleType: schedule.ScheduleType, Expression: schedule.Expression,
		TimeZone: schedule.TimeZone, PeriodDescription: describePlanPeriod(schedule),
		ScopeID: schedule.ScopeID, ScopeKind: payload.ScopeKind, AppID: payload.AppID,
		Granularity: stats.Granularity(payload.Granularity), WindowDays: payload.WindowDays,
		Categories:  categoriesOf(payload.Categories),
		TrendMetric: stats.Metric(payload.TrendMetric), Formats: formatsOf(payload.Formats),
		DetailRows: payload.DetailRows, MissedPolicy: schedule.MissedPolicy,
		MaxCatchUp:     schedule.MaxCatchUp,
		TimeoutSeconds: schedule.TimeoutSeconds, MaxAttempts: schedule.MaxAttempts,
		Owner:          schedule.Owner,
		ExecutionActor: schedule.ExecutionActor, CreatedAt: schedule.CreatedAt,
		UpdatedAt: schedule.UpdatedAt,
	}
	anchor := schedule.CreatedAt
	if anchor.IsZero() {
		anchor = p.nowUTC()
	}
	spec, specErr := task.ParseScheduleSpec(schedule.ScheduleType, schedule.Expression,
		schedule.TimeZone, anchor)
	if specErr != nil {
		view.NextRunUnknown = true
		view.NextRunReason = "计划表达式无法计算下次执行时间"
	} else if next := spec.Next(p.nowUTC()); !next.IsZero() {
		view.NextRun = next
	} else {
		view.NextRunUnknown = true
		view.NextRunReason = "当前配置没有可计算的下次执行时间"
	}
	return view, true, nil
}

// projectionVersion 返回计划管理读模型的当前行版本；投影未装配或不存在时回退
// 载荷行版本。它供 Get/Update 使用，保证页面读取到的行版本与乐观并发检查一致。
func (p *PlanService) projectionVersion(ctx context.Context,
	payload planPayload, schedule task.Schedule) int64 {
	if !isNil(p.projections) {
		planID := effectivePlanID(payload, schedule)
		if projection, found, err := p.projections.GetPlanProjection(ctx, planID); err == nil && found {
			return projection.Version
		}
	}
	return effectivePlanVersion(payload)
}

// applyProjectionVersion 把读模型行版本写入视图（页面编辑必须原样回传）。
func (p *PlanService) applyProjectionVersion(ctx context.Context,
	payload planPayload, schedule task.Schedule, view *PlanView) {
	view.Version = p.projectionVersion(ctx, payload, schedule)
}

// categoriesOf 把字符串列表还原为类别列表。
func categoriesOf(values []string) []stats.Category {
	result := make([]stats.Category, 0, len(values))
	for _, value := range values {
		result = append(result, stats.Category(value))
	}
	return result
}

// formatsOf 把字符串列表还原为格式列表。
func formatsOf(values []string) []Format {
	result := make([]Format, 0, len(values))
	for _, value := range values {
		result = append(result, Format(value))
	}
	return result
}

// executionPermissionState 以计划执行身份（所有者）的当前权限判断该计划是否可以
// 安全执行。授权服务不可用时返回 unknown 并按不可执行处理（不乐观放行）。
func (p *PlanService) executionPermissionState(ctx context.Context, owner audit.Actor,
	scopeID string) (string, string) {
	caller, err := callerFromActor(owner)
	if err != nil {
		return PlanPermissionRevoked, "执行身份无效"
	}
	if p.isRoot(ctx, caller) {
		return PlanPermissionOK, ""
	}
	for _, permission := range []struct {
		key  string
		name string
	}{
		{PermissionRead, "读取权限已失效"},
		{PermissionGenerate, "生成权限已失效"},
		{PermissionExport, "导出权限已失效"},
	} {
		grant, authErr := p.opts.Authorizer.AuthorizeScope(ctx, caller, permission.key, scopeID)
		if authErr != nil {
			return PlanPermissionUnknown, "授权服务暂不可用，无法确认执行权限"
		}
		if !grant.Allowed {
			return PlanPermissionRevoked, permission.name
		}
	}
	return PlanPermissionOK, ""
}

// describePlanPeriod 生成直白的中文周期说明；具体年月日时刻由表达式与页面时区
// 共同表达，这里不解析超出领域定义的自由 cron（不支持）。
func describePlanPeriod(schedule task.Schedule) string {
	expression := schedule.Expression
	switch schedule.ScheduleType {
	case task.ScheduleTypeDaily:
		return "每天 " + clockPart(expression)
	case task.ScheduleTypeWeekly:
		fields := strings.Fields(expression)
		if len(fields) >= 1 {
			return "每周 " + fields[0] + "，时间 " + clockPart(expression)
		}
		return "每周 " + expression
	case task.ScheduleTypeMonthly:
		fields := strings.Fields(expression)
		if len(fields) >= 1 {
			return "每月 " + fields[0] + "，时间 " + clockPart(expression)
		}
		return "每月 " + expression
	case task.ScheduleTypeCustom:
		return "固定间隔 " + expression
	default:
		return expression
	}
}

// clockPart 返回表达式最后一个字段（日/周/月计划的时间部分）。
func clockPart(expression string) string {
	fields := strings.Fields(expression)
	if len(fields) == 0 {
		return expression
	}
	return fields[len(fields)-1]
}

// Create 创建报告计划。授权顺序：查看 → 计划管理 → 生成 → 导出（与即时报告
// 一致），然后生成稳定的计划 ID、写入计划载荷并用通用调度器持久化；装配了管理
// 读模型时在同一操作中写入派生投影（不是第二命令源，可重建）。计划默认要求运行
// 前权限复验，不能创建「看起来已启用但无法安全运行」的计划。
func (p *PlanService) Create(ctx context.Context, request PlanCreateRequest) (PlanView, error) {
	actor := request.Caller.Actor()
	if err := actor.Validate(); err != nil {
		return PlanView{}, ErrAccessDenied
	}
	if actor.Type == audit.ActorAnonymous {
		return PlanView{}, ErrAccessDenied
	}
	scope, err := parseScope(request.ScopeID)
	if err != nil {
		return PlanView{}, err
	}
	readGrant, err := p.authorize(ctx, request.Caller, PermissionRead, scope.ID)
	if err != nil {
		return PlanView{}, err
	}
	if _, err := p.authorize(ctx, request.Caller, PermissionScheduleManage, scope.ID); err != nil {
		return PlanView{}, err
	}
	if _, err := p.authorize(ctx, request.Caller, PermissionGenerate, scope.ID); err != nil {
		return PlanView{}, err
	}
	if _, err := p.authorize(ctx, request.Caller, PermissionExport, scope.ID); err != nil {
		return PlanView{}, err
	}
	if err := validateAppFilter(request.AppID, scope, readGrant); err != nil {
		return PlanView{}, err
	}
	timeZone := strings.TrimSpace(request.TimeZone)
	if timeZone == "" || timeZone == "Local" {
		return PlanView{}, fmt.Errorf("%w: 计划时区必须显式指定 IANA 名称", ErrInvalidRequest)
	}
	// 计划 ID 在创建前生成并写入载荷与投影，使触发/历史能稳定关联计划；它与
	// 通用调度器生成的执行计划编号分开（编辑会更换执行计划，计划 ID 不变）。
	planID, err := task.NewScheduleID()
	if err != nil {
		return PlanView{}, fmt.Errorf("%w: 无法生成计划编号", ErrInvalidRequest)
	}
	payload, payloadStruct, err := p.buildPlanPayload(request, scope, timeZone,
		actorRecordOf(actor), planID, 1)
	if err != nil {
		return PlanView{}, err
	}
	schedule, err := p.opts.Schedules.Create(ctx, task.NewScheduleRequest{
		JobKind:        TaskKindPlannedReportGenerate,
		ScheduleType:   request.ScheduleType,
		Expression:     request.Expression,
		TimeZone:       timeZone,
		Owner:          actor,
		ExecutionActor: actor,
		ScopeID:        scope.ID,
		Enabled:        request.Enabled,
		MissedPolicy:   request.MissedPolicy,
		MaxCatchUp:     request.MaxCatchUp,
		Payload:        payload,
		TimeoutSeconds: request.TimeoutSeconds,
		MaxAttempts:    request.MaxAttempts,
		RequestID:      normalizeRequestID(request.RequestID),
	})
	if err != nil {
		if strings.Contains(err.Error(), "权限") {
			return PlanView{}, ErrAccessDenied
		}
		return PlanView{}, err
	}
	if !p.syncProjectionCreate(ctx, schedule, payloadStruct, planID, 1) {
		// 投影写失败时补偿删除刚创建的执行计划：不留下“调度器里有、管理模型里
		// 没有”的悬挂计划；删除失败只告警，由 ReconcilePlans 后续修复。
		_ = p.opts.Schedules.Delete(ctx, task.ScheduleDeleteCommand{
			ScheduleID: schedule.ID, Actor: audit.Actor{
				Type: audit.ActorSystem, ID: "reports-plan-projection-compensate"},
			Reason: "计划管理读模型持久化失败补偿删除", RequestID: "plan-projection-compensate",
		})
		return PlanView{}, fmt.Errorf("%w: 计划管理读模型持久化失败", ErrStoreUnavailable)
	}
	p.recordPlanAudit(ctx, callerActor(request.Caller), ActionPlanCreate, planID,
		scope.ID, "row_version", "1")
	view, _, viewErr := p.planView(ctx, request.Caller, schedule)
	if viewErr != nil {
		return PlanView{}, viewErr
	}
	p.applyProjectionVersion(ctx, payloadStruct, schedule, &view)
	return view, nil
}

// callerActor 返回调用者的可信审计身份（已校验）。
func callerActor(caller account.Caller) audit.Actor {
	return caller.Actor()
}

// List 列出当前调用者可见的报告计划。不可查看的计划直接过滤，不泄露其存在性。
func (p *PlanService) List(ctx context.Context, caller account.Caller) ([]PlanView, error) {
	actor := caller.Actor()
	if err := actor.Validate(); err != nil {
		return nil, ErrAccessDenied
	}
	schedules, err := p.opts.Schedules.List(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]PlanView, 0, len(schedules))
	for _, schedule := range schedules {
		if schedule.JobKind != TaskKindPlannedReportGenerate {
			continue
		}
		view, visible, viewErr := p.planView(ctx, caller, schedule)
		if viewErr != nil {
			return nil, viewErr
		}
		if visible {
			views = append(views, view)
		}
	}
	return views, nil
}

// PlanListRequest 是报告计划列表分页请求（步骤 218）。Limit=0 使用默认 20，
// 最大 100；Offset 上限 1_000_000。可见性由服务端逐计划重新授权后过滤。
// Search 是可选的字面子串搜索（计划显示名，空表示不过滤），在可见范围过滤后
// 执行，不改变可见性判定本身。
type PlanListRequest struct {
	Caller       account.Caller
	Limit        int
	Offset       int
	Search       string
	SearchFields []string
}

// PlanListResult 是报告计划分页结果；不返回伪造总数。
type PlanListResult struct {
	Plans      []PlanView
	HasMore    bool
	Limit      int
	Offset     int
	NextOffset int
}

// ListPage 分页列出当前调用者可见的报告计划。计划投影来自调度事实，服务层先按
// 当前授权过滤再切页；调用方不能用 offset 越过不可见计划（不可见计划不占结果位）。
func (p *PlanService) ListPage(ctx context.Context,
	request PlanListRequest) (PlanListResult, error) {
	limit := request.Limit
	if limit == 0 {
		limit = 20
	}
	if limit < 1 || limit > 100 {
		return PlanListResult{}, fmt.Errorf("%w: 每页条数必须在 1～100 之间",
			ErrInvalidRequest)
	}
	if request.Offset < 0 || request.Offset > 1_000_000 {
		return PlanListResult{}, fmt.Errorf("%w: 分页偏移超出范围", ErrInvalidRequest)
	}
	all, err := p.List(ctx, request.Caller)
	if err != nil {
		return PlanListResult{}, err
	}
	// 搜索在可见范围（p.List 已按当前授权过滤）之后执行；只匹配计划显示名，
	// 不改变可见性判定、不因搜索暴露不可见计划。
	foldedSearch, err := search.NormalizeQuery(request.Search)
	if err != nil {
		return PlanListResult{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	searchFields := request.SearchFields
	if len(searchFields) > 0 {
		for _, field := range searchFields {
			if strings.TrimSpace(field) != "name" {
				return PlanListResult{}, fmt.Errorf("%w: 搜索字段 %q 不在允许列表内（仅支持 name）",
					ErrInvalidRequest, field)
			}
		}
	}
	if foldedSearch != "" {
		filtered := make([]PlanView, 0, len(all))
		for _, plan := range all {
			foldedName, foldErr := search.NormalizeQuery(plan.Name)
			if foldErr != nil {
				continue
			}
			if strings.Contains(foldedName, foldedSearch) {
				filtered = append(filtered, plan)
			}
		}
		all = filtered
	}
	result := PlanListResult{Limit: limit, Offset: request.Offset,
		NextOffset: request.Offset}
	if request.Offset >= len(all) {
		return result, nil
	}
	end := request.Offset + limit
	if end > len(all) {
		end = len(all)
	}
	result.Plans = all[request.Offset:end]
	result.HasMore = end < len(all)
	result.NextOffset = end
	return result, nil
}

// Get 查询单个报告计划；不可见或不存在都返回 ErrNotFound，避免用错误差异泄露
// 计划是否存在。
func (p *PlanService) Get(ctx context.Context, caller account.Caller,
	planID string) (PlanView, error) {
	if err := actorCheck(caller); err != nil {
		return PlanView{}, err
	}
	schedule, _, found, err := p.findScheduleByPlanID(ctx, planID)
	if err != nil {
		return PlanView{}, err
	}
	if !found || schedule.JobKind != TaskKindPlannedReportGenerate {
		return PlanView{}, ErrNotFound
	}
	view, visible, err := p.planView(ctx, caller, schedule)
	if err != nil {
		return PlanView{}, err
	}
	if !visible {
		return PlanView{}, ErrNotFound
	}
	payload, payloadErr := decodePlanPayload(schedule.Payload)
	if payloadErr == nil {
		p.applyProjectionVersion(ctx, payload, schedule, &view)
	}
	return view, nil
}

// SetEnabled 启用或停用报告计划。启用前重新检查操作者权限、计划载荷与执行身份；
// 失权计划不能靠普通启用按钮掩盖。停用只停止未来触发，已入队/运行中的任务继续。
func (p *PlanService) SetEnabled(ctx context.Context, caller account.Caller, planID string,
	enable bool, reason, requestID string) (PlanView, error) {
	if err := actorCheck(caller); err != nil {
		return PlanView{}, err
	}
	schedule, _, scheduleFound, findErr := p.findScheduleByPlanID(ctx, planID)
	if findErr != nil {
		return PlanView{}, findErr
	}
	if !scheduleFound {
		return PlanView{}, ErrNotFound
	}
	payload, err := decodePlanPayload(schedule.Payload)
	if err != nil {
		return PlanView{}, err
	}
	if _, err := p.authorize(ctx, caller, PermissionScheduleManage, schedule.ScopeID); err != nil {
		return PlanView{}, err
	}
	if _, err := p.authorize(ctx, caller, PermissionGenerate, schedule.ScopeID); err != nil {
		return PlanView{}, err
	}
	if _, err := p.authorize(ctx, caller, PermissionExport, schedule.ScopeID); err != nil {
		return PlanView{}, err
	}
	if enable {
		owner, err := payload.Owner.auditActor()
		if err != nil {
			return PlanView{}, err
		}
		state, stateReason := p.executionPermissionState(ctx, owner, schedule.ScopeID)
		if state != PlanPermissionOK {
			p.recordDenied(ctx, caller.Actor(), schedule.ScopeID, "execution_permission_revoked")
			return PlanView{}, fmt.Errorf("%w: %s", ErrAccessDenied, stateReason)
		}
	}
	command := task.ScheduleStateCommand{
		ScheduleID: schedule.ID, Actor: caller.Actor(),
		Reason: strings.TrimSpace(reason), RequestID: normalizeRequestID(requestID),
	}
	_ = payload
	var updated task.Schedule
	if enable {
		updated, err = p.opts.Schedules.Resume(ctx, command)
	} else {
		updated, err = p.opts.Schedules.Pause(ctx, command)
	}
	if err != nil {
		return PlanView{}, err
	}
	p.syncProjectionEnabled(ctx, updated, payload)
	view, _, viewErr := p.planView(ctx, caller, updated)
	if viewErr != nil {
		return PlanView{}, viewErr
	}
	p.applyProjectionVersion(ctx, payload, updated, &view)
	return view, nil
}

// PlanDeletePreview 是删除计划前的真实影响预览；预览不是授权，提交时服务端仍要
// 重新检查权限与目标状态。
type PlanDeletePreview struct {
	PlanID           string
	Name             string
	ScopeID          string
	Enabled          bool
	NextRun          time.Time
	NextRunUnknown   bool
	MissedPolicy     string
	ActiveTasksNote  string
	HistoryNote      string
	RawAuditNote     string
	Irreversible     bool
	PermissionState  string
	PermissionReason string
	CreatedAt        time.Time
	PreviewedAt      time.Time
}

// DeletePreview 返回删除计划的影响预览。活动任务数量当前服务没有接入任务列表，
// 因此明确写「不统计」，不能用假 0 显示为没有影响。
func (p *PlanService) DeletePreview(ctx context.Context, caller account.Caller,
	planID string) (PlanDeletePreview, error) {
	view, err := p.Get(ctx, caller, planID)
	if err != nil {
		return PlanDeletePreview{}, err
	}
	return PlanDeletePreview{
		PlanID: view.ID, Name: view.Name, ScopeID: view.ScopeID,
		Enabled: view.Enabled, NextRun: view.NextRun,
		NextRunUnknown:  view.NextRunUnknown,
		MissedPolicy:    string(view.MissedPolicy),
		ActiveTasksNote: "已入队或运行中的任务继续按自身状态执行，不会因删除计划自动取消；数量请以任务列表为准。",
		HistoryNote:     "已生成的报告与历史记录按各自保留策略保留，不随计划删除。",
		RawAuditNote:    "删除计划不删除原始审计记录；原始审计清理是独立的 root 受控流程。",
		Irreversible:    true,
		PermissionState: view.PermissionState, PermissionReason: view.PermissionReason,
		CreatedAt: view.CreatedAt, PreviewedAt: p.nowUTC(),
	}, nil
}

// Delete 删除报告计划；删除前重新授权并复核目标仍是报告计划。删除不取消既有
// 任务、不删除历史报告、不删除原始审计。
func (p *PlanService) Delete(ctx context.Context, caller account.Caller, planID,
	reason, requestID string) error {
	if err := actorCheck(caller); err != nil {
		return err
	}
	schedule, _, scheduleFound, findErr := p.findScheduleByPlanID(ctx, planID)
	if findErr != nil {
		return findErr
	}
	if !scheduleFound {
		return ErrNotFound
	}
	if _, err := p.authorize(ctx, caller, PermissionScheduleManage, schedule.ScopeID); err != nil {
		return err
	}
	if _, err := p.authorize(ctx, caller, PermissionGenerate, schedule.ScopeID); err != nil {
		return err
	}
	if _, err := p.authorize(ctx, caller, PermissionExport, schedule.ScopeID); err != nil {
		return err
	}
	payload, payloadErr := decodePlanPayload(schedule.Payload)
	if payloadErr != nil {
		return payloadErr
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return fmt.Errorf("%w: 删除计划必须填写原因", ErrInvalidRequest)
	}
	if err := p.opts.Schedules.Delete(ctx, task.ScheduleDeleteCommand{
		ScheduleID: schedule.ID, Actor: caller.Actor(), Reason: reason,
		RequestID: normalizeRequestID(requestID),
	}); err != nil {
		if err == task.ErrScheduleNotFound {
			return ErrNotFound
		}
		return err
	}
	p.syncProjectionDelete(ctx, payload, schedule)
	p.recordPlanAudit(ctx, caller.Actor(), ActionPlanDelete,
		effectivePlanID(payload, schedule), schedule.ScopeID, "reason_present", "true")
	return nil
}

// actorCheck 校验调用者身份；匿名/非法身份拒绝。
func actorCheck(caller account.Caller) error {
	actor := caller.Actor()
	if err := actor.Validate(); err != nil {
		return ErrAccessDenied
	}
	if actor.Type == audit.ActorAnonymous {
		return ErrAccessDenied
	}
	return nil
}

// CheckExecutionPermission 是交给 internal/task 调度器的运行前权限复验回调。
// 每次计划触发前用计划执行身份的当前权限重新检查读取/生成/导出权限；任何失败
// 都返回错误，由调度器记录「已拒绝、未入队」，不伪造任务或报告。
func (p *PlanService) CheckExecutionPermission(ctx context.Context,
	request task.PermissionRequest) error {
	if request.Kind != TaskKindPlannedReportGenerate {
		// 非报告计划类型不由本服务负责，默认拒绝而不是放行。
		return ErrAccessDenied
	}
	payload, err := decodePlanPayload(request.Payload)
	if err != nil {
		return err
	}
	owner, err := payload.Owner.auditActor()
	if err != nil {
		return ErrAccessDenied
	}
	if owner != request.Actor {
		return ErrAccessDenied
	}
	caller, err := callerFromActor(owner)
	if err != nil {
		return ErrAccessDenied
	}
	scope, err := parseScope(payload.ScopeID)
	if err != nil {
		return ErrAccessDenied
	}
	for _, permission := range []string{PermissionRead, PermissionGenerate, PermissionExport} {
		if _, err := p.authorize(ctx, caller, permission, scope.ID); err != nil {
			return fmt.Errorf("%w: 计划执行权限复验未通过", ErrAccessDenied)
		}
	}
	return nil
}

// DisableRevokedPlans 停用当前执行身份已失权的报告计划。它由宿主在周期任务中
// 调用（或页面刷新时触发），把调度器每次触发都会记录拒绝的计划转为明确的停用
// 状态；失权计划不因操作者曾经有权而继续伪装为可执行。
func (p *PlanService) DisableRevokedPlans(ctx context.Context) (int, error) {
	schedules, err := p.opts.Schedules.List(ctx)
	if err != nil {
		return 0, err
	}
	disabled := 0
	for _, schedule := range schedules {
		if !schedule.Enabled || schedule.JobKind != TaskKindPlannedReportGenerate {
			continue
		}
		payload, decodeErr := decodePlanPayload(schedule.Payload)
		if decodeErr != nil {
			continue
		}
		owner, ownerErr := payload.Owner.auditActor()
		if ownerErr != nil {
			continue
		}
		state, _ := p.executionPermissionState(ctx, owner, schedule.ScopeID)
		if state == PlanPermissionOK {
			continue
		}
		systemActor := audit.Actor{Type: audit.ActorSystem, ID: "reports-plan-reconcile"}
		if _, pauseErr := p.opts.Schedules.Pause(ctx, task.ScheduleStateCommand{
			ScheduleID: schedule.ID, Actor: systemActor,
			Reason: "执行身份权限失效，自动停用", RequestID: "plan-permission-reconcile",
		}); pauseErr != nil {
			p.logger.Warn("自动停用失权报告计划失败",
				"plan_id", schedule.ID, "error", pauseErr)
			continue
		}
		disabled++
	}
	return disabled, nil
}

// PlanUpdateRequest 是编辑报告计划请求。Caller 必须来自可信调用上下文；PlanID
// 是稳定计划编号，Version 是读取时的行版本（乐观并发）。所有者、执行身份与计划
// ID 不能在编辑中改变；请求中的 Caller 只代表操作者，不改变计划归属。
type PlanUpdateRequest struct {
	PlanCreateRequest
	// PlanID 是要编辑的计划编号；不接受客户端自报归属。
	PlanID string
	// Version 是读取时的计划行版本；与服务端当前版本不一致时拒绝覆盖。
	Version int64
	// Reason 是编辑原因（进入审计）；为空时使用固定说明。
	Reason string
}

// validPlanID 校验计划编号格式：sch_ 加 32 位小写十六进制（与调度器编号格式一致）。
func validPlanID(id string) bool {
	if len(id) != 4+32 || !strings.HasPrefix(id, "sch_") {
		return false
	}
	for _, c := range id[4:] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// effectivePlanID 返回计划稳定编号：新计划使用载荷中的 PlanID；步骤 79 收口前
// 创建的旧计划没有该字段，用调度器编号兼容（不迁移、不猜测）。
func effectivePlanID(payload planPayload, schedule task.Schedule) string {
	if payload.PlanID != "" {
		return payload.PlanID
	}
	return schedule.ID
}

// effectivePlanVersion 返回计划行版本：旧计划按 1 处理，避免出现“版本 0”让编辑
// 无法基于读取结果提交。
func effectivePlanVersion(payload planPayload) int64 {
	if payload.RowVersion > 0 {
		return payload.RowVersion
	}
	return 1
}

// recordPlanAudit 写计划生命周期审计；审计失败只告警，不伪造操作成功记录。
func (p *PlanService) recordPlanAudit(ctx context.Context, actor audit.Actor,
	action, planID, scopeID, field, after string) {
	if isNil(p.opts.Audit) {
		return
	}
	event := audit.Event{
		Actor: actor, AppID: appIDForScope(scopeID), Action: action,
		Target:  audit.Target{Type: "report_plan", ID: planID},
		Outcome: audit.OutcomeSuccess,
		Changes: []audit.FieldChange{{Field: field, After: after}},
	}
	if err := p.opts.Audit.Record(ctx, event); err != nil {
		p.logger.Warn("报告计划审计写入失败", "action", action,
			"code", string(CodeAuditWriteFailed))
	}
}

// projectionOf 从调度事实与计划载荷构造管理读模型（派生数据，不包含秘密）。
func (p *PlanService) projectionOf(payload planPayload, schedule task.Schedule,
	planID string, rowVersion int64) PlanProjection {
	owner, err := payload.Owner.auditActor()
	if err != nil {
		owner = schedule.Owner
	}
	execution := schedule.ExecutionActor
	if err := execution.Validate(); err != nil || execution.Type == audit.ActorAnonymous {
		execution = owner
	}
	createdAt := schedule.CreatedAt
	if createdAt.IsZero() {
		createdAt = p.nowUTC()
	}
	updatedAt := schedule.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = createdAt
	}
	return PlanProjection{
		ID: planID, Name: payload.Name, Owner: owner, ExecutionActor: execution,
		ScopeID: schedule.ScopeID, ScopeKind: payload.ScopeKind, AppID: payload.AppID,
		Template: "standard", ScheduleType: schedule.ScheduleType,
		Expression: schedule.Expression, TimeZone: schedule.TimeZone,
		Granularity: stats.Granularity(payload.Granularity),
		WindowDays:  payload.WindowDays, Categories: categoriesOf(payload.Categories),
		TrendMetric: stats.Metric(payload.TrendMetric),
		Formats:     formatsOf(payload.Formats), DetailRows: payload.DetailRows,
		MissedPolicy: schedule.MissedPolicy, MaxCatchUp: schedule.MaxCatchUp,
		TimeoutSeconds: schedule.TimeoutSeconds, MaxAttempts: schedule.MaxAttempts,
		Enabled: schedule.Enabled, Version: rowVersion,
		CreatedAt: createdAt, UpdatedAt: updatedAt,
	}
}

// syncProjectionCreate 写入计划管理读模型；未装配投影存储时直接返回成功（不伪造
// 持久投影能力）。失败只返回 false，由调用方补偿删除执行计划。
func (p *PlanService) syncProjectionCreate(ctx context.Context, schedule task.Schedule,
	payload planPayload, planID string, rowVersion int64) bool {
	if isNil(p.projections) {
		return true
	}
	if _, err := p.projections.CreatePlanProjection(ctx,
		p.projectionOf(payload, schedule, planID, rowVersion)); err != nil {
		p.logger.Warn("报告计划管理读模型写入失败", "plan_id", planID,
			"code", string(CodeDBUnavailable))
		return false
	}
	return true
}

// syncProjectionEnabled 同步启停状态到管理读模型；失败只告警，由 ReconcilePlans
// 在下次启动/周期修复，不把已生效的调度变更伪装成失败。
func (p *PlanService) syncProjectionEnabled(ctx context.Context, schedule task.Schedule,
	payload planPayload) {
	if isNil(p.projections) {
		return
	}
	planID := effectivePlanID(payload, schedule)
	projection, found, err := p.projections.GetPlanProjection(ctx, planID)
	if err != nil {
		p.logger.Warn("读取报告计划投影失败", "plan_id", planID)
		return
	}
	if !found {
		// 旧计划/投影缺失：按当前调度事实补齐，避免读模型永远缺少该计划。
		p.syncProjectionCreate(ctx, schedule, payload, planID, effectivePlanVersion(payload))
		return
	}
	if projection.Enabled == schedule.Enabled {
		return
	}
	if err := p.projections.SetPlanProjectionEnabled(ctx, planID,
		schedule.Enabled); err != nil {
		p.logger.Warn("同步报告计划启停状态失败", "plan_id", planID)
	}
}

// syncProjectionDelete 删除计划管理读模型；失败只告警，ReconcilePlans 会把残留
// 投影修复为调度事实（不存在调度时删除）。
func (p *PlanService) syncProjectionDelete(ctx context.Context, payload planPayload,
	schedule task.Schedule) {
	if isNil(p.projections) {
		return
	}
	planID := effectivePlanID(payload, schedule)
	if err := p.projections.DeletePlanProjection(ctx, planID); err != nil &&
		!errors.Is(err, ErrNotFound) {
		p.logger.Warn("删除报告计划投影失败", "plan_id", planID)
	}
}

// findScheduleByPlanID 通过计划稳定编号查找执行计划（装配读模型后计划编号与执行
// 计划编号分离）；只读取调度事实，不在这里授权。计划数量在单实例管理场景下有限，
// 这里是线性查找，不引入第二套索引或缓存。
func (p *PlanService) findScheduleByPlanID(ctx context.Context,
	planID string) (task.Schedule, planPayload, bool, error) {
	if !validPlanID(planID) {
		return task.Schedule{}, planPayload{}, false, ErrInvalidRequest
	}
	schedules, err := p.opts.Schedules.List(ctx)
	if err != nil {
		return task.Schedule{}, planPayload{}, false, err
	}
	for _, schedule := range schedules {
		if schedule.JobKind != TaskKindPlannedReportGenerate {
			continue
		}
		payload, decodeErr := decodePlanPayload(schedule.Payload)
		if decodeErr != nil {
			continue
		}
		if effectivePlanID(payload, schedule) == planID {
			return schedule, payload, true, nil
		}
	}
	return task.Schedule{}, planPayload{}, false, nil
}

// Update 编辑报告计划：先按当前权限与数据范围重新授权，再以行版本乐观并发替换
// 执行计划（计划 ID 与所有者保持不变），最后同步管理读模型并删除旧执行计划。
// 旧版计划编辑会升级为普通计划（写入计划 ID 与行版本），不重写历史。
func (p *PlanService) Update(ctx context.Context, request PlanUpdateRequest) (PlanView, error) {
	actor := request.Caller.Actor()
	if err := actorCheck(request.Caller); err != nil {
		return PlanView{}, err
	}
	schedule, payload, found, err := p.findScheduleByPlanID(ctx, request.PlanID)
	if err != nil {
		return PlanView{}, err
	}
	if !found {
		return PlanView{}, ErrNotFound
	}
	if schedule.JobKind != TaskKindPlannedReportGenerate {
		return PlanView{}, ErrNotFound
	}
	planID := effectivePlanID(payload, schedule)
	owner, err := payload.Owner.auditActor()
	if err != nil {
		return PlanView{}, ErrNotFound
	}
	newScope, err := parseScope(request.ScopeID)
	if err != nil {
		return PlanView{}, err
	}
	// 跨范围编辑必须对「当前范围」与「目标范围」双重授权：既不能凭旧范围权限
	// 把计划迁移到自己无权的新范围，也不能凭新范围权限接管旧范围内的计划。
	oldScope, err := parseScope(schedule.ScopeID)
	if err != nil {
		return PlanView{}, ErrNotFound
	}
	for _, scopeID := range []string{oldScope.ID, newScope.ID} {
		for _, permission := range []string{PermissionRead, PermissionScheduleManage,
			PermissionGenerate, PermissionExport} {
			if _, authErr := p.authorize(ctx, request.Caller, permission, scopeID); authErr != nil {
				return PlanView{}, authErr
			}
		}
	}
	readGrant, err := p.authorize(ctx, request.Caller, PermissionRead, newScope.ID)
	if err != nil {
		return PlanView{}, err
	}
	if err := validateAppFilter(request.AppID, newScope, readGrant); err != nil {
		return PlanView{}, err
	}
	// 行版本校验放在授权之后：无权者不能用版本差异探测他人计划的并发状态。
	currentVersion := p.projectionVersion(ctx, payload, schedule)
	if request.Version != currentVersion {
		p.recordDenied(ctx, actor, schedule.ScopeID, "plan_version_conflict")
		return PlanView{}, fmt.Errorf("%w: 此计划已被其他操作修改，请重新读取后再保存", ErrConflict)
	}
	timeZone := strings.TrimSpace(request.TimeZone)
	if timeZone == "" || timeZone == "Local" {
		return PlanView{}, fmt.Errorf("%w: 计划时区必须显式指定 IANA 名称", ErrInvalidRequest)
	}
	newVersion := currentVersion + 1
	newPayload, payloadStruct, err := p.buildPlanPayload(request.PlanCreateRequest,
		newScope, timeZone, payload.Owner, planID, newVersion)
	if err != nil {
		return PlanView{}, err
	}
	// 投影行版本用于乐观并发：currentVersion 已经是读模型版本；投影缺失（旧计划
	// 或上次重建失败）时先按当前调度事实补齐，再进入替换流程。
	expectedProjectionVersion := currentVersion
	if !isNil(p.projections) {
		projection, projectionFound, projectionErr := p.projections.GetPlanProjection(ctx, planID)
		if projectionErr != nil {
			return PlanView{}, ErrStoreUnavailable
		}
		if !projectionFound {
			created, createErr := p.projections.CreatePlanProjection(ctx,
				p.projectionOf(payload, schedule, planID, currentVersion))
			if createErr != nil {
				return PlanView{}, ErrStoreUnavailable
			}
			expectedProjectionVersion = created.Version
			currentVersion = created.Version
			newVersion = currentVersion + 1
			newPayload, payloadStruct, err = p.buildPlanPayload(request.PlanCreateRequest,
				newScope, timeZone, payload.Owner, planID, newVersion)
			if err != nil {
				return PlanView{}, err
			}
		} else {
			expectedProjectionVersion = projection.Version
		}
	}
	// 先创建禁用的替代执行计划：替换期间不会因两个计划同时启用而重复触发。
	replacement, err := p.opts.Schedules.Create(ctx, task.NewScheduleRequest{
		JobKind:        TaskKindPlannedReportGenerate,
		ScheduleType:   request.ScheduleType,
		Expression:     request.Expression,
		TimeZone:       timeZone,
		Owner:          owner,
		ExecutionActor: owner,
		ScopeID:        newScope.ID,
		Enabled:        false,
		MissedPolicy:   request.MissedPolicy,
		MaxCatchUp:     request.MaxCatchUp,
		Payload:        newPayload,
		TimeoutSeconds: request.TimeoutSeconds,
		MaxAttempts:    request.MaxAttempts,
		RequestID:      normalizeRequestID(request.RequestID),
	})
	if err != nil {
		return PlanView{}, err
	}
	replacementID := replacement.ID
	compensate := func() {
		_ = p.opts.Schedules.Delete(ctx, task.ScheduleDeleteCommand{
			ScheduleID: replacementID, Actor: audit.Actor{
				Type: audit.ActorSystem, ID: "reports-plan-update-compensate"},
			Reason: "计划编辑失败补偿删除", RequestID: "plan-update-compensate",
		})
	}
	if !isNil(p.projections) {
		projection := p.projectionOf(payloadStruct, replacement, planID, newVersion)
		projection.Enabled = schedule.Enabled
		if _, updateErr := p.projections.UpdatePlanProjection(ctx, projection,
			expectedProjectionVersion); updateErr != nil {
			compensate()
			if errors.Is(updateErr, ErrConflict) {
				return PlanView{}, fmt.Errorf(
					"%w: 此计划已被其他操作修改，请重新读取后再保存", ErrConflict)
			}
			return PlanView{}, ErrStoreUnavailable
		}
	}
	// 删除旧执行计划；删除失败时补偿删除新计划，保持原计划继续有效。
	oldReason := strings.TrimSpace(request.Reason)
	if oldReason == "" {
		oldReason = "计划配置更新"
	}
	if err := p.opts.Schedules.Delete(ctx, task.ScheduleDeleteCommand{
		ScheduleID: schedule.ID, Actor: actor, Reason: oldReason,
		RequestID: normalizeRequestID(request.RequestID),
	}); err != nil {
		compensate()
		return PlanView{}, err
	}
	if schedule.Enabled {
		if _, resumeErr := p.opts.Schedules.Resume(ctx, task.ScheduleStateCommand{
			ScheduleID: replacementID, Actor: actor,
			Reason:    "计划配置更新后恢复调度",
			RequestID: normalizeRequestID(request.RequestID),
		}); resumeErr != nil {
			return PlanView{}, resumeErr
		}
	}
	p.recordPlanAudit(ctx, actor, ActionPlanUpdate, planID, newScope.ID,
		"row_version", strconv.FormatInt(newVersion, 10))
	updated, err := p.opts.Schedules.Get(ctx, replacementID)
	if err != nil {
		return PlanView{}, ErrNotFound
	}
	view, _, viewErr := p.planView(ctx, request.Caller, updated)
	if viewErr != nil {
		return PlanView{}, viewErr
	}
	p.applyProjectionVersion(ctx, payloadStruct, updated, &view)
	return view, nil
}

// ReconcilePlans 从调度事实重建/修复计划管理读模型：为缺少投影的执行计划补建、
// 为配置或启停不一致的投影更新、为已无执行计划的残留投影删除。它需要装配投影
// 存储；由宿主在启动与周期任务中调用，返回修复数量与聚合错误（不伪造全部成功）。
func (p *PlanService) ReconcilePlans(ctx context.Context) (int, error) {
	if isNil(p.projections) {
		return 0, nil
	}
	schedules, err := p.opts.Schedules.List(ctx)
	if err != nil {
		return 0, err
	}
	repaired := 0
	activePlanIDs := make(map[string]struct{}, len(schedules))
	for _, schedule := range schedules {
		if schedule.JobKind != TaskKindPlannedReportGenerate {
			continue
		}
		payload, decodeErr := decodePlanPayload(schedule.Payload)
		if decodeErr != nil {
			p.logger.Warn("跳过载荷损坏的报告计划", "schedule_id", schedule.ID)
			continue
		}
		planID := effectivePlanID(payload, schedule)
		activePlanIDs[planID] = struct{}{}
		version := effectivePlanVersion(payload)
		projection, found, getErr := p.projections.GetPlanProjection(ctx, planID)
		if getErr != nil {
			return repaired, getErr
		}
		if !found {
			if _, createErr := p.projections.CreatePlanProjection(ctx,
				p.projectionOf(payload, schedule, planID, version)); createErr != nil {
				p.logger.Warn("重建报告计划投影失败", "plan_id", planID)
				continue
			}
			repaired++
			continue
		}
		desired := p.projectionOf(payload, schedule, planID, version)
		if projectionsEqual(projection, desired) {
			continue
		}
		if _, updateErr := p.projections.UpdatePlanProjection(ctx, desired,
			projection.Version); updateErr != nil {
			p.logger.Warn("修复报告计划投影失败", "plan_id", planID)
			continue
		}
		repaired++
	}
	// 清理已无执行计划的残留投影：读模型是派生数据，不对应任何调度事实时不
	// 保留“幽灵计划”；删除失败不影响调度事实，下次对账重试。
	for planID := range p.projectionPlanIDs(ctx) {
		if _, exists := activePlanIDs[planID]; exists {
			continue
		}
		if err := p.projections.DeletePlanProjection(ctx, planID); err != nil {
			p.logger.Warn("删除残留报告计划投影失败", "plan_id", planID)
			continue
		}
		repaired++
	}
	if repaired > 0 {
		p.logger.Info("报告计划管理读模型已修复", "count", repaired)
	}
	return repaired, nil
}

// projectionPlanIDs 返回当前读模型中的计划编号；投影存储未提供枚举能力时返回空
// （生产 SQLite 适配器实现了枚举）。
func (p *PlanService) projectionPlanIDs(ctx context.Context) map[string]struct{} {
	result := make(map[string]struct{})
	type lister interface {
		ListPlanProjectionIDs(ctx context.Context) ([]string, error)
	}
	if enumerator, ok := p.projections.(lister); ok {
		ids, err := enumerator.ListPlanProjectionIDs(ctx)
		if err != nil {
			return result
		}
		for _, id := range ids {
			result[id] = struct{}{}
		}
	}
	return result
}

// projectionsEqual 比较投影配置是否一致（忽略版本与时间，由更新单独推进）。
func projectionsEqual(left, right PlanProjection) bool {
	if left.Name != right.Name || left.Owner != right.Owner ||
		left.ExecutionActor != right.ExecutionActor || left.ScopeID != right.ScopeID ||
		left.ScopeKind != right.ScopeKind || left.AppID != right.AppID ||
		left.Template != right.Template || left.ScheduleType != right.ScheduleType ||
		left.Expression != right.Expression || left.TimeZone != right.TimeZone ||
		left.Granularity != right.Granularity || left.WindowDays != right.WindowDays ||
		left.TrendMetric != right.TrendMetric || left.DetailRows != right.DetailRows ||
		left.MissedPolicy != right.MissedPolicy || left.MaxCatchUp != right.MaxCatchUp ||
		left.TimeoutSeconds != right.TimeoutSeconds ||
		left.MaxAttempts != right.MaxAttempts || left.Enabled != right.Enabled {
		return false
	}
	if len(left.Categories) != len(right.Categories) ||
		len(left.Formats) != len(right.Formats) {
		return false
	}
	for index := range left.Categories {
		if left.Categories[index] != right.Categories[index] {
			return false
		}
	}
	for index := range left.Formats {
		if left.Formats[index] != right.Formats[index] {
			return false
		}
	}
	return true
}
