// Package sqlite 实现报告计划与报告历史的 SQLite 生产持久化（步骤 79）。
//
// 表由 migrations/0042_report_lifecycle.sql 创建，本包不执行迁移；调用方应在启动
// 或测试中先通过 internal/storage/migrate 应用全部迁移。本包不拥有数据库连接：
// 关闭由外层负责。构造后不可变，可被多个 goroutine 并发使用。
//
// 安全不变量：
//   - 数据范围约束直接写进 SQL WHERE 子句（AccessScope），不提供“全量读取后内存
//     过滤”的接口；无权范围返回空或 ErrNotFound，不泄露记录是否存在。
//   - 计划所有者/执行身份分开存储；本包只持久化事实，不在存储层放行权限。
//   - 报告历史只保存受控元数据与步骤 77 已裁剪的聚合快照；不保存产物宿主路径、
//     原始审计正文、凭证或自由文本秘密。
//   - 状态使用真实任务/报告状态（取消请求与实际取消分开）；本包不把请求写成终态。
//   - 计划/历史更新使用行版本乐观并发控制，版本冲突返回 reports.ErrConflict，不做
//     静默覆盖。
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/reports"
	"github.com/kagurazakayashi/EvernightLogin/internal/search"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// Store 是报告计划/历史的 SQLite 仓储。
// execWrite 是报告仓储的原生写语句入口：先登记存储维护写入门闸，再执行原生 SQL，
// 使维护状态（步骤 82 恢复）下这些历史 raw 写路径与新代码一样被拒绝。
func (s *Store) execWrite(ctx context.Context, query string, args ...any) (sql.Result, error) {
	release, err := s.store.AcquireWriteGuard(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return s.store.DB().ExecContext(ctx, query, args...)
}

type Store struct {
	store *storagesqlite.Store
}

// New 包装一个已打开并完成迁移的 SQLite 存储；store 为空时拒绝构造。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", reports.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

// 分页上限；页面只能按“创建时间倒序 + 编号倒序”稳定排序，不开放任意列排序。
const (
	// DefaultPageSize 是默认每页条数。
	DefaultPageSize = 20
	// MaxPageSize 是单页硬上限。
	MaxPageSize = 100
)

// AccessScope 是调用者当前数据范围。AllData 表示系统范围；否则 ResourceIDs 是
// 可访问的应用范围稳定 ID 集合。两者都不满足时返回空，不泄露对象存在性。
type AccessScope struct {
	AllData     bool
	ResourceIDs []string
}

// accessSQL 返回范围过滤 SQL 片段与参数；无权时使用恒假条件而不是返回全量。
func accessSQL(access AccessScope) (string, []any) {
	if access.AllData {
		return "", nil
	}
	ids := make([]string, 0, len(access.ResourceIDs))
	for _, id := range access.ResourceIDs {
		if strings.TrimSpace(id) != "" {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return " AND 1 = 0", nil
	}
	placeholders := make([]string, len(ids))
	args := make([]any, len(ids))
	for index, id := range ids {
		placeholders[index] = "?"
		args[index] = id
	}
	return " AND scope_id IN (" + strings.Join(placeholders, ",") + ")", args
}

// actorToColumns 把审计身份拆为类型/ID 两列。
func actorToColumns(actor audit.Actor) (string, string, error) {
	if err := actor.Validate(); err != nil {
		return "", "", fmt.Errorf("%w: 操作者身份无效", reports.ErrInvalidRequest)
	}
	if actor.Type == audit.ActorAnonymous || actor.ID == "" {
		return "", "", fmt.Errorf("%w: 操作者身份不能为空", reports.ErrInvalidRequest)
	}
	return string(actor.Type), actor.ID, nil
}

// actorFromColumns 还原并校验审计身份。
func actorFromColumns(actorType, actorID string) (audit.Actor, error) {
	actor := audit.Actor{Type: audit.ActorKind(actorType), ID: actorID}
	if err := actor.Validate(); err != nil {
		return audit.Actor{}, fmt.Errorf("%w: 持久化操作者身份无效", reports.ErrStoreUnavailable)
	}
	return actor, nil
}

// StringList 是报告类别/格式的稳定字符串列表。
type StringList []string

// encodeStringList 序列化为 JSON 数组；nil 编码为 []，避免 NULL 与空数组歧义。
func encodeStringList(values []string) (string, error) {
	if values == nil {
		values = []string{}
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return "", fmt.Errorf("%w: 列表编码失败", reports.ErrInvalidRequest)
	}
	return string(encoded), nil
}

// decodeStringList 解析 JSON 数组；空串按空列表处理（兼容默认值）。
func decodeStringList(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var values []string
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil, fmt.Errorf("%w: 持久化列表无法解析", reports.ErrStoreUnavailable)
	}
	return values, nil
}

// timeToMS 把时间转为 UTC 毫秒整数；零值写 0（未知），不伪造当前时间。
func timeToMS(moment time.Time) int64 {
	if moment.IsZero() {
		return 0
	}
	return moment.UTC().UnixMilli()
}

// msToTime 把毫秒整数还原为 UTC 时间；0 返回零值（未知）。
func msToTime(value int64) time.Time {
	if value <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(value).UTC()
}

// PlanRecord 是报告计划持久化记录。字段与报告计划 DTO 对齐；所有者与执行身份
// 分开，发布/启停由服务层重新授权，本仓储不做权限放行。
type PlanRecord struct {
	ID             string
	Name           string
	Owner          audit.Actor
	ExecutionActor audit.Actor
	ScopeID        string
	ScopeKind      string
	AppID          string
	Template       string
	ScheduleType   string
	Expression     string
	TimeZone       string
	Granularity    string
	WindowDays     int
	Categories     []string
	TrendMetric    string
	Formats        []string
	DetailRows     int
	MissedPolicy   string
	MaxCatchUp     int
	TimeoutSeconds int
	MaxAttempts    int
	Enabled        bool
	Version        int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// validatePlan 校验计划记录的必填值与受控枚举；数据库 CHECK 是第二道防线。
func validatePlan(plan PlanRecord) error {
	if strings.TrimSpace(plan.ID) == "" || strings.TrimSpace(plan.Name) == "" ||
		strings.TrimSpace(plan.ScopeID) == "" || strings.TrimSpace(plan.Template) == "" ||
		strings.TrimSpace(plan.Expression) == "" || strings.TrimSpace(plan.TimeZone) == "" {
		return fmt.Errorf("%w: 计划必填字段缺失", reports.ErrInvalidRequest)
	}
	if plan.TimeZone == "Local" {
		return fmt.Errorf("%w: 计划时区必须显式指定 IANA 名称", reports.ErrInvalidRequest)
	}
	if plan.ScopeKind != "system" && plan.ScopeKind != "app" {
		return fmt.Errorf("%w: 计划作用范围无效", reports.ErrInvalidRequest)
	}
	switch plan.ScheduleType {
	case "daily", "weekly", "monthly", "custom":
	default:
		return fmt.Errorf("%w: 计划类型无效", reports.ErrInvalidRequest)
	}
	switch plan.Granularity {
	case "day", "week", "month":
	default:
		return fmt.Errorf("%w: 时间桶粒度无效", reports.ErrInvalidRequest)
	}
	switch plan.MissedPolicy {
	case "skip", "latest", "all":
	default:
		return fmt.Errorf("%w: 错过策略无效", reports.ErrInvalidRequest)
	}
	if plan.WindowDays < 1 || plan.WindowDays > 90 {
		return fmt.Errorf("%w: 统计窗口天数超出范围", reports.ErrInvalidRequest)
	}
	if plan.DetailRows < 1 {
		return fmt.Errorf("%w: 明细条数上限无效", reports.ErrInvalidRequest)
	}
	if len(plan.Formats) == 0 {
		return fmt.Errorf("%w: 计划至少需要一种输出格式", reports.ErrInvalidRequest)
	}
	for _, format := range plan.Formats {
		if !reports.Format(format).Valid() {
			return fmt.Errorf("%w: 计划格式无效", reports.ErrInvalidRequest)
		}
	}
	if plan.MaxCatchUp < 1 || plan.TimeoutSeconds < 1 || plan.MaxAttempts < 1 {
		return fmt.Errorf("%w: 计划任务边界无效", reports.ErrInvalidRequest)
	}
	return nil
}

// CreatePlan 持久化一个计划；版本固定初始化为 1，重复编号返回 ErrConflict。
func (s *Store) CreatePlan(ctx context.Context, plan PlanRecord) (PlanRecord, error) {
	if err := validatePlan(plan); err != nil {
		return PlanRecord{}, err
	}
	ownerType, ownerID, err := actorToColumns(plan.Owner)
	if err != nil {
		return PlanRecord{}, err
	}
	executionType, executionID, err := actorToColumns(plan.ExecutionActor)
	if err != nil {
		return PlanRecord{}, err
	}
	categories, err := encodeStringList(plan.Categories)
	if err != nil {
		return PlanRecord{}, err
	}
	formats, err := encodeStringList(plan.Formats)
	if err != nil {
		return PlanRecord{}, err
	}
	now := time.Now().UTC()
	if plan.CreatedAt.IsZero() {
		plan.CreatedAt = now
	}
	if plan.UpdatedAt.IsZero() {
		plan.UpdatedAt = plan.CreatedAt
	}
	if _, err := s.execWrite(ctx, `INSERT INTO report_plans(
id,name,owner_type,owner_id,execution_actor_type,execution_actor_id,scope_id,scope_kind,
app_id,template,schedule_type,schedule_expression,time_zone,granularity,window_days,
categories_json,trend_metric,formats_json,detail_rows,missed_policy,max_catch_up,
timeout_seconds,max_attempts,enabled,version,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?)`,
		plan.ID, plan.Name, ownerType, ownerID, executionType, executionID,
		plan.ScopeID, plan.ScopeKind, plan.AppID, plan.Template, plan.ScheduleType,
		plan.Expression, plan.TimeZone, plan.Granularity, plan.WindowDays,
		categories, plan.TrendMetric, formats, plan.DetailRows, plan.MissedPolicy,
		plan.MaxCatchUp, plan.TimeoutSeconds, plan.MaxAttempts, boolToInt(plan.Enabled),
		timeToMS(plan.CreatedAt), timeToMS(plan.UpdatedAt)); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return PlanRecord{}, fmt.Errorf("%w: 计划编号已存在", reports.ErrConflict)
		}
		return PlanRecord{}, err
	}
	plan.Version = 1
	return plan, nil
}

// boolToInt 把布尔值写为 0/1。
func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

// planColumns 是计划读取的列顺序。
const planColumns = `id,name,owner_type,owner_id,execution_actor_type,execution_actor_id,
scope_id,scope_kind,app_id,template,schedule_type,schedule_expression,time_zone,
granularity,window_days,categories_json,trend_metric,formats_json,detail_rows,
missed_policy,max_catch_up,timeout_seconds,max_attempts,enabled,version,
created_at_ms,updated_at_ms`

// scanPlan 从一行读取计划记录；JSON 列解析失败按存储不可用处理。
func scanPlan(scanner interface{ Scan(...any) error }) (PlanRecord, error) {
	var plan PlanRecord
	var ownerType, ownerID, executionType, executionID string
	var categoriesRaw, formatsRaw string
	var enabled int
	var createdAtMS, updatedAtMS int64
	if err := scanner.Scan(&plan.ID, &plan.Name, &ownerType, &ownerID,
		&executionType, &executionID, &plan.ScopeID, &plan.ScopeKind, &plan.AppID,
		&plan.Template, &plan.ScheduleType, &plan.Expression, &plan.TimeZone,
		&plan.Granularity, &plan.WindowDays, &categoriesRaw, &plan.TrendMetric,
		&formatsRaw, &plan.DetailRows, &plan.MissedPolicy, &plan.MaxCatchUp,
		&plan.TimeoutSeconds, &plan.MaxAttempts, &enabled, &plan.Version,
		&createdAtMS, &updatedAtMS); err != nil {
		return PlanRecord{}, err
	}
	owner, err := actorFromColumns(ownerType, ownerID)
	if err != nil {
		return PlanRecord{}, err
	}
	execution, err := actorFromColumns(executionType, executionID)
	if err != nil {
		return PlanRecord{}, err
	}
	plan.Owner = owner
	plan.ExecutionActor = execution
	if plan.Categories, err = decodeStringList(categoriesRaw); err != nil {
		return PlanRecord{}, err
	}
	if plan.Formats, err = decodeStringList(formatsRaw); err != nil {
		return PlanRecord{}, err
	}
	plan.Enabled = enabled == 1
	plan.CreatedAt = msToTime(createdAtMS)
	plan.UpdatedAt = msToTime(updatedAtMS)
	return plan, nil
}

// ListPlanIDs 返回全部计划编号（仅元数据）。它供服务层重建/清理管理读模型使用；
// 不返回配置内容，也不构成权限放行。
func (s *Store) ListPlanIDs(ctx context.Context) ([]string, error) {
	rows, err := s.store.DB().QueryContext(ctx, `SELECT id FROM report_plans ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]string, 0, 64)
	for rows.Next() {
		var id string
		if scanErr := rows.Scan(&id); scanErr != nil {
			return nil, scanErr
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// GetPlan 按编号与当前数据范围读取计划；不在范围内与不存在都返回 found=false，
// 避免用错误差异泄露计划存在性。
func (s *Store) GetPlan(ctx context.Context, planID string,
	access AccessScope) (PlanRecord, bool, error) {
	if strings.TrimSpace(planID) == "" {
		return PlanRecord{}, false, fmt.Errorf("%w: 计划编号为空", reports.ErrInvalidRequest)
	}
	condition, args := accessSQL(access)
	query := `SELECT ` + planColumns + ` FROM report_plans WHERE id = ?` + condition
	plan, err := scanPlan(s.store.DB().QueryRowContext(ctx, query,
		append([]any{planID}, args...)...))
	if err != nil {
		if err == sql.ErrNoRows {
			return PlanRecord{}, false, nil
		}
		return PlanRecord{}, false, err
	}
	return plan, true, nil
}

// PlanQuery 是计划列表查询；排序固定为创建时间倒序 + 编号倒序，分页用游标而非
// 偏移，避免并发新增导致重复/漏行。Enabled 为 nil 表示不筛选启停状态。
type PlanQuery struct {
	Access          AccessScope
	OwnerType       string
	OwnerID         string
	ScopeID         string
	Enabled         *bool
	Limit           int
	BeforeCreatedAt time.Time
	BeforeID        string
}

// clampLimit 归一化分页大小。
func clampLimit(limit int) int {
	if limit <= 0 {
		return DefaultPageSize
	}
	if limit > MaxPageSize {
		return MaxPageSize
	}
	return limit
}

// ListPlans 返回当前数据范围可见的计划，按创建时间倒序 + 编号倒序稳定排序。
func (s *Store) ListPlans(ctx context.Context, query PlanQuery) ([]PlanRecord, error) {
	condition, args := accessSQL(query.Access)
	parts := []string{"1 = 1"}
	if query.OwnerType != "" {
		parts = append(parts, "owner_type = ?")
		args = append(args, query.OwnerType)
	}
	if query.OwnerID != "" {
		parts = append(parts, "owner_id = ?")
		args = append(args, query.OwnerID)
	}
	if query.ScopeID != "" {
		parts = append(parts, "scope_id = ?")
		args = append(args, query.ScopeID)
	}
	if query.Enabled != nil {
		parts = append(parts, "enabled = ?")
		args = append(args, boolToInt(*query.Enabled))
	}
	if !query.BeforeCreatedAt.IsZero() {
		parts = append(parts, "(created_at_ms < ? OR (created_at_ms = ? AND id < ?))")
		moment := timeToMS(query.BeforeCreatedAt)
		args = append(args, moment, moment, query.BeforeID)
	}
	limit := clampLimit(query.Limit)
	sqlText := `SELECT ` + planColumns + ` FROM report_plans WHERE ` +
		strings.Join(parts, " AND ") + condition +
		` ORDER BY created_at_ms DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.store.DB().QueryContext(ctx, sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	plans := make([]PlanRecord, 0, limit)
	for rows.Next() {
		plan, scanErr := scanPlan(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		plans = append(plans, plan)
	}
	return plans, rows.Err()
}

// UpdatePlan 以行版本乐观并发更新计划管理字段；旧版本返回 ErrConflict。编号、
// 所有者与创建时间不可通过本方法修改（身份与归属只能由服务层按审计流程处理）。
func (s *Store) UpdatePlan(ctx context.Context, plan PlanRecord,
	expectedVersion int64) (PlanRecord, error) {
	if err := validatePlan(plan); err != nil {
		return PlanRecord{}, err
	}
	if expectedVersion < 1 {
		return PlanRecord{}, fmt.Errorf("%w: 期望版本无效", reports.ErrInvalidRequest)
	}
	categories, err := encodeStringList(plan.Categories)
	if err != nil {
		return PlanRecord{}, err
	}
	formats, err := encodeStringList(plan.Formats)
	if err != nil {
		return PlanRecord{}, err
	}
	updatedAt := plan.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	}
	result, err := s.execWrite(ctx, `UPDATE report_plans SET
name = ?, scope_id = ?, scope_kind = ?, app_id = ?, template = ?,
schedule_type = ?, schedule_expression = ?, time_zone = ?, granularity = ?,
window_days = ?, categories_json = ?, trend_metric = ?, formats_json = ?,
detail_rows = ?, missed_policy = ?, max_catch_up = ?, timeout_seconds = ?,
max_attempts = ?, enabled = ?, version = version + 1, updated_at_ms = ?
WHERE id = ? AND version = ?`,
		plan.Name, plan.ScopeID, plan.ScopeKind, plan.AppID, plan.Template,
		plan.ScheduleType, plan.Expression, plan.TimeZone, plan.Granularity,
		plan.WindowDays, categories, plan.TrendMetric, formats, plan.DetailRows,
		plan.MissedPolicy, plan.MaxCatchUp, plan.TimeoutSeconds, plan.MaxAttempts,
		boolToInt(plan.Enabled), timeToMS(updatedAt), plan.ID, expectedVersion)
	if err != nil {
		return PlanRecord{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return PlanRecord{}, err
	}
	if affected == 0 {
		return PlanRecord{}, fmt.Errorf("%w: 计划已被其他操作修改", reports.ErrConflict)
	}
	updated, found, err := s.GetPlan(ctx, plan.ID, AccessScope{AllData: true})
	if err != nil || !found {
		return PlanRecord{}, fmt.Errorf("%w: 更新后无法读取计划", reports.ErrStoreUnavailable)
	}
	return updated, nil
}

// SetPlanEnabled 以行版本乐观并发切换启停；旧版本返回 ErrConflict。
func (s *Store) SetPlanEnabled(ctx context.Context, planID string, enabled bool,
	expectedVersion int64, now time.Time) (PlanRecord, error) {
	if strings.TrimSpace(planID) == "" || expectedVersion < 1 {
		return PlanRecord{}, fmt.Errorf("%w: 计划编号或版本无效", reports.ErrInvalidRequest)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result, err := s.execWrite(ctx,
		`UPDATE report_plans SET enabled = ?, version = version + 1, updated_at_ms = ?
WHERE id = ? AND version = ?`,
		boolToInt(enabled), timeToMS(now), planID, expectedVersion)
	if err != nil {
		return PlanRecord{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return PlanRecord{}, err
	}
	if affected == 0 {
		return PlanRecord{}, fmt.Errorf("%w: 计划不存在或已被其他操作修改", reports.ErrConflict)
	}
	updated, found, err := s.GetPlan(ctx, planID, AccessScope{AllData: true})
	if err != nil || !found {
		return PlanRecord{}, fmt.Errorf("%w: 更新后无法读取计划", reports.ErrStoreUnavailable)
	}
	return updated, nil
}

// DeletePlan 以行版本乐观并发删除计划；历史记录不级联删除（计划删除后历史保留）。
func (s *Store) DeletePlan(ctx context.Context, planID string, expectedVersion int64) error {
	if strings.TrimSpace(planID) == "" || expectedVersion < 1 {
		return fmt.Errorf("%w: 计划编号或版本无效", reports.ErrInvalidRequest)
	}
	result, err := s.execWrite(ctx,
		`DELETE FROM report_plans WHERE id = ? AND version = ?`, planID, expectedVersion)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("%w: 计划不存在或已被其他操作修改", reports.ErrConflict)
	}
	return nil
}

// HistoryRecord 是报告历史/运行记录持久化记录；plan_id 为空表示非计划触发的
// 即时报告。状态按真实任务/报告状态更新，取消请求不等于实际取消。
type HistoryRecord struct {
	ID             string
	PlanID         string
	RetryOf        string
	Name           string
	Owner          audit.Actor
	ScopeID        string
	ScopeKind      string
	AppID          string
	Template       string
	State          string
	Formats        []string
	Categories     []string
	TrendMetric    string
	DetailRows     int
	DataScopeJSON  []byte
	WindowJSON     []byte
	SnapshotJSON   []byte
	ArtifactsJSON  []byte
	TaskID         string
	ExecutorID     string
	ErrorCode      string
	FailureReason  string
	RequestID      string
	CreatedAt      time.Time
	StartedAt      time.Time
	FinishedAt     time.Time
	ExpiresAt      time.Time
	RetentionUntil time.Time
	CleanupState   string
}

// historyIDPattern 与既有报告编号一致：rpt_ 加 32 位小写十六进制。
func validHistoryID(id string) bool {
	if len(id) != 4+32 || !strings.HasPrefix(id, "rpt_") {
		return false
	}
	for _, c := range id[4:] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// validateHistoryState 校验真实任务/报告状态白名单。
func validateHistoryState(state string) error {
	switch state {
	case "queued", "running", "cancel_requested", "cancelled", "succeeded",
		"failed", "timed_out":
		return nil
	default:
		return fmt.Errorf("%w: 报告历史状态无效", reports.ErrInvalidRequest)
	}
}

// validateHistory 校验历史记录必填字段与 JSON 列。
func validateHistory(record HistoryRecord) error {
	if !validHistoryID(record.ID) {
		return fmt.Errorf("%w: 报告编号格式无效", reports.ErrInvalidRequest)
	}
	if record.RetryOf != "" && !validHistoryID(record.RetryOf) {
		return fmt.Errorf("%w: 重试来源报告编号格式无效", reports.ErrInvalidRequest)
	}
	if strings.TrimSpace(record.Name) == "" || strings.TrimSpace(record.ScopeID) == "" ||
		strings.TrimSpace(record.Template) == "" {
		return fmt.Errorf("%w: 报告历史必填字段缺失", reports.ErrInvalidRequest)
	}
	if record.ScopeKind != "system" && record.ScopeKind != "app" {
		return fmt.Errorf("%w: 报告作用范围无效", reports.ErrInvalidRequest)
	}
	if err := validateHistoryState(record.State); err != nil {
		return err
	}
	if len(record.Formats) == 0 {
		return fmt.Errorf("%w: 报告历史缺少输出格式", reports.ErrInvalidRequest)
	}
	for _, format := range record.Formats {
		if !reports.Format(format).Valid() {
			return fmt.Errorf("%w: 报告历史格式无效", reports.ErrInvalidRequest)
		}
	}
	if len(record.WindowJSON) > 0 && !json.Valid(record.WindowJSON) {
		return fmt.Errorf("%w: 报告窗口不是合法 JSON", reports.ErrInvalidRequest)
	}
	if len(record.DataScopeJSON) > 0 && !json.Valid(record.DataScopeJSON) {
		return fmt.Errorf("%w: 报告数据范围不是合法 JSON", reports.ErrInvalidRequest)
	}
	if len(record.SnapshotJSON) > 0 && !json.Valid(record.SnapshotJSON) {
		return fmt.Errorf("%w: 报告快照不是合法 JSON", reports.ErrInvalidRequest)
	}
	if len(record.ArtifactsJSON) > 0 && !json.Valid(record.ArtifactsJSON) {
		return fmt.Errorf("%w: 报告产物元数据不是合法 JSON", reports.ErrInvalidRequest)
	}
	return nil
}

// normalizeCleanupState 归一化清理状态；空值表示未到期待清理。
func normalizeCleanupState(state string) (string, error) {
	switch state {
	case "":
		return "none", nil
	case "none", "pending", "cleaned":
		return state, nil
	default:
		return "", fmt.Errorf("%w: 报告清理状态无效", reports.ErrInvalidRequest)
	}
}

// UpsertHistory 写入或更新报告历史记录（同一报告 ID 只保留一条）。状态推进遵守
// 单调规则：真实状态只能前进（queued→running→cancel_requested→终态），已完成终态
// 不会被迟到的 queued/running/取消请求覆盖，避免乱序写入把成功报告改回进行中；
// 唯一例外是“成功审计写入失败”的显式回滚（succeeded→failed/AUDIT_WRITE_FAILED）。
// 计划来源可空；不级联删除计划历史。
func (s *Store) UpsertHistory(ctx context.Context, record HistoryRecord) error {
	if err := validateHistory(record); err != nil {
		return err
	}
	ownerType, ownerID, err := actorToColumns(record.Owner)
	if err != nil {
		return err
	}
	formats, err := encodeStringList(record.Formats)
	if err != nil {
		return err
	}
	categories, err := encodeStringList(record.Categories)
	if err != nil {
		return err
	}
	cleanupState, err := normalizeCleanupState(record.CleanupState)
	if err != nil {
		return err
	}
	window := string(record.WindowJSON)
	if window == "" {
		window = "{}"
	}
	dataScope := string(record.DataScopeJSON)
	if dataScope == "" {
		dataScope = "{}"
	}
	snapshot := string(record.SnapshotJSON)
	artifacts := string(record.ArtifactsJSON)
	if artifacts == "" {
		artifacts = "[]"
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	// stateAdvance 判断本次写入是否允许推进状态；同一 SQL 片段在两处复用。
	const stateAdvance = `((CASE excluded.state WHEN 'queued' THEN 0 WHEN 'running' THEN 1
WHEN 'cancel_requested' THEN 2 ELSE 3 END) >
(CASE report_history.state WHEN 'queued' THEN 0 WHEN 'running' THEN 1
WHEN 'cancel_requested' THEN 2 ELSE 3 END))
OR excluded.state = report_history.state
OR (report_history.state = 'succeeded' AND excluded.state = 'failed'
AND excluded.error_code = 'AUDIT_WRITE_FAILED')`
	_, err = s.execWrite(ctx, `INSERT INTO report_history(
id,plan_id,retry_of,name,owner_type,owner_id,scope_id,scope_kind,app_id,template,state,
formats_json,categories_json,trend_metric,detail_rows,data_scope_json,window_json,
snapshot_json,artifacts_json,task_id,executor_id,error_code,failure_reason,request_id,
created_at_ms,started_at_ms,finished_at_ms,expires_at_ms,retention_until_ms,cleanup_state)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET
plan_id = excluded.plan_id, retry_of = excluded.retry_of, name = excluded.name,
state = CASE WHEN `+stateAdvance+` THEN excluded.state ELSE report_history.state END,
formats_json = excluded.formats_json, categories_json = excluded.categories_json,
trend_metric = excluded.trend_metric, detail_rows = excluded.detail_rows,
data_scope_json = excluded.data_scope_json,
window_json = CASE WHEN excluded.window_json <> '{}' THEN excluded.window_json ELSE report_history.window_json END,
snapshot_json = CASE WHEN excluded.snapshot_json <> '' THEN excluded.snapshot_json ELSE report_history.snapshot_json END,
artifacts_json = CASE WHEN excluded.artifacts_json <> '[]' THEN excluded.artifacts_json ELSE report_history.artifacts_json END,
task_id = CASE WHEN excluded.task_id <> '' THEN excluded.task_id ELSE report_history.task_id END,
executor_id = CASE WHEN excluded.executor_id <> '' THEN excluded.executor_id ELSE report_history.executor_id END,
error_code = CASE WHEN `+stateAdvance+` THEN excluded.error_code ELSE report_history.error_code END,
failure_reason = CASE WHEN `+stateAdvance+` THEN excluded.failure_reason ELSE report_history.failure_reason END,
started_at_ms = CASE WHEN `+stateAdvance+` AND excluded.started_at_ms > 0
THEN excluded.started_at_ms ELSE report_history.started_at_ms END,
finished_at_ms = CASE WHEN `+stateAdvance+` AND excluded.finished_at_ms > 0
THEN excluded.finished_at_ms ELSE report_history.finished_at_ms END,
expires_at_ms = CASE WHEN excluded.expires_at_ms > 0 THEN excluded.expires_at_ms ELSE report_history.expires_at_ms END,
retention_until_ms = CASE WHEN excluded.retention_until_ms > 0 THEN excluded.retention_until_ms ELSE report_history.retention_until_ms END,
cleanup_state = excluded.cleanup_state`,
		record.ID, record.PlanID, record.RetryOf, record.Name, ownerType, ownerID, record.ScopeID,
		record.ScopeKind, record.AppID, record.Template, record.State, formats,
		categories, record.TrendMetric, record.DetailRows, dataScope, window, snapshot,
		artifacts, record.TaskID, record.ExecutorID, record.ErrorCode,
		record.FailureReason, record.RequestID, timeToMS(record.CreatedAt),
		timeToMS(record.StartedAt), timeToMS(record.FinishedAt),
		timeToMS(record.ExpiresAt), timeToMS(record.RetentionUntil), cleanupState)
	return err
}

// historyColumns 是历史读取的列顺序。
const historyColumns = `id,plan_id,retry_of,name,owner_type,owner_id,scope_id,scope_kind,
app_id,template,state,formats_json,categories_json,trend_metric,detail_rows,
data_scope_json,window_json,snapshot_json,artifacts_json,task_id,executor_id,
error_code,failure_reason,request_id,created_at_ms,started_at_ms,finished_at_ms,
expires_at_ms,retention_until_ms,cleanup_state`

// scanHistory 从一行读取历史记录。
func scanHistory(scanner interface{ Scan(...any) error }) (HistoryRecord, error) {
	var record HistoryRecord
	var ownerType, ownerID, formatsRaw, categoriesRaw string
	var dataScope, window, snapshot, artifacts string
	var createdAtMS, startedAtMS, finishedAtMS, expiresAtMS, retentionAtMS int64
	if err := scanner.Scan(&record.ID, &record.PlanID, &record.RetryOf, &record.Name, &ownerType,
		&ownerID, &record.ScopeID, &record.ScopeKind, &record.AppID, &record.Template,
		&record.State, &formatsRaw, &categoriesRaw, &record.TrendMetric,
		&record.DetailRows, &dataScope, &window, &snapshot, &artifacts, &record.TaskID,
		&record.ExecutorID, &record.ErrorCode, &record.FailureReason,
		&record.RequestID, &createdAtMS, &startedAtMS, &finishedAtMS,
		&expiresAtMS, &retentionAtMS, &record.CleanupState); err != nil {
		return HistoryRecord{}, err
	}
	owner, err := actorFromColumns(ownerType, ownerID)
	if err != nil {
		return HistoryRecord{}, err
	}
	record.Owner = owner
	if record.Formats, err = decodeStringList(formatsRaw); err != nil {
		return HistoryRecord{}, err
	}
	if record.Categories, err = decodeStringList(categoriesRaw); err != nil {
		return HistoryRecord{}, err
	}
	record.DataScopeJSON = []byte(dataScope)
	record.WindowJSON = []byte(window)
	record.SnapshotJSON = []byte(snapshot)
	record.ArtifactsJSON = []byte(artifacts)
	record.CreatedAt = msToTime(createdAtMS)
	record.StartedAt = msToTime(startedAtMS)
	record.FinishedAt = msToTime(finishedAtMS)
	record.ExpiresAt = msToTime(expiresAtMS)
	record.RetentionUntil = msToTime(retentionAtMS)
	return record, nil
}

// GetHistory 按编号与当前数据范围读取报告历史；不在范围内与不存在都返回
// found=false，不泄露记录存在性。
func (s *Store) GetHistory(ctx context.Context, reportID string,
	access AccessScope) (HistoryRecord, bool, error) {
	if !validHistoryID(reportID) {
		return HistoryRecord{}, false, fmt.Errorf("%w: 报告编号格式无效", reports.ErrInvalidRequest)
	}
	condition, args := accessSQL(access)
	query := `SELECT ` + historyColumns + ` FROM report_history WHERE id = ?` + condition
	record, err := scanHistory(s.store.DB().QueryRowContext(ctx, query,
		append([]any{reportID}, args...)...))
	if err != nil {
		if err == sql.ErrNoRows {
			return HistoryRecord{}, false, nil
		}
		return HistoryRecord{}, false, err
	}
	return record, true, nil
}

// HistoryQuery 是报告历史列表查询。排序固定为创建时间倒序 + 编号倒序；分页用
// 游标，避免并发新增导致重复/漏行。State/PlanID/Owner 为空表示不筛选。
type HistoryQuery struct {
	Access          AccessScope
	PlanID          string
	State           string
	OwnerType       string
	OwnerID         string
	Limit           int
	BeforeCreatedAt time.Time
	BeforeID        string
	// Search 是已规范化的报告显示名字面搜索；SearchFields 是其字段白名单
	// （当前仅 "name"）。
	Search       string
	SearchFields []string
}

// HistoryPage 是历史列表页；HasMore 表示还有下一页（不伪造总数）。
type HistoryPage struct {
	Records []HistoryRecord
	HasMore bool
}

// ListHistory 返回当前数据范围可见的报告历史（受控分页，按创建时间倒序）。
func (s *Store) ListHistory(ctx context.Context, query HistoryQuery) (HistoryPage, error) {
	// 数据范围条件的占位符拼在 WHERE 末尾，因此它的参数也必须最后追加；
	// 若先放进 args 再追加筛选参数，owner/plan/state 与 scope 的参数会错位，
	// 导致“同时按范围与所有者筛选”的查询静默返回空页。
	condition, conditionArgs := accessSQL(query.Access)
	var args []any
	parts := []string{"1 = 1"}
	if query.PlanID != "" {
		parts = append(parts, "plan_id = ?")
		args = append(args, query.PlanID)
	}
	if query.State != "" {
		if err := validateHistoryState(query.State); err != nil {
			return HistoryPage{}, err
		}
		parts = append(parts, "state = ?")
		args = append(args, query.State)
	}
	if query.OwnerType != "" {
		parts = append(parts, "owner_type = ?")
		args = append(args, query.OwnerType)
	}
	if query.OwnerID != "" {
		parts = append(parts, "owner_id = ?")
		args = append(args, query.OwnerID)
	}
	if !query.BeforeCreatedAt.IsZero() {
		parts = append(parts, "(created_at_ms < ? OR (created_at_ms = ? AND id < ?))")
		moment := timeToMS(query.BeforeCreatedAt)
		args = append(args, moment, moment, query.BeforeID)
	}
	if query.Search != "" {
		pattern := search.ContainsPattern(query.Search)
		if pattern != "" {
			clauses := make([]string, 0, len(query.SearchFields))
			for _, field := range query.SearchFields {
				switch field {
				case "name":
					clauses = append(clauses, `LOWER(name) LIKE ? ESCAPE '!'`)
					args = append(args, pattern)
				default:
					// 服务层已按白名单校验；仓储再次 fail-closed，不生成未知列。
					return HistoryPage{}, fmt.Errorf("%w: 搜索字段不在允许列表内",
						reports.ErrInvalidRequest)
				}
			}
			if len(clauses) == 0 {
				return HistoryPage{}, fmt.Errorf("%w: 搜索字段为空", reports.ErrInvalidRequest)
			}
			parts = append(parts, `(`+strings.Join(clauses, ` OR `)+`)`)
		}
	}
	args = append(args, conditionArgs...)
	limit := clampLimit(query.Limit)
	// 多取一条判断是否有下一页；不查询总数（总数在受控筛选下才允许显示）。
	sqlText := `SELECT ` + historyColumns + ` FROM report_history WHERE ` +
		strings.Join(parts, " AND ") + condition +
		` ORDER BY created_at_ms DESC, id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := s.store.DB().QueryContext(ctx, sqlText, args...)
	if err != nil {
		return HistoryPage{}, err
	}
	defer rows.Close()
	records := make([]HistoryRecord, 0, limit+1)
	for rows.Next() {
		record, scanErr := scanHistory(rows)
		if scanErr != nil {
			return HistoryPage{}, scanErr
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return HistoryPage{}, err
	}
	page := HistoryPage{Records: records}
	if len(records) > limit {
		page.Records = records[:limit]
		page.HasMore = true
	}
	return page, nil
}

// MarkHistoryCleanup 更新报告文件清理状态（none→pending→cleaned）：只允许前进，
// 报告不存在或状态已变化返回 ErrConflict。报告文件清理与原始审计删除严格分开，
// 本方法只修改报告元数据状态，不删除任何原始审计记录。
func (s *Store) MarkHistoryCleanup(ctx context.Context, reportID, cleanupState string) error {
	if !validHistoryID(reportID) {
		return fmt.Errorf("%w: 报告编号格式无效", reports.ErrInvalidRequest)
	}
	state, err := normalizeCleanupState(cleanupState)
	if err != nil || state == "none" {
		return fmt.Errorf("%w: 报告清理状态无效", reports.ErrInvalidRequest)
	}
	// 只允许从 none/pending 前进到 pending/cleaned，避免并发回退已清理状态。
	result, err := s.execWrite(ctx, `UPDATE report_history
SET cleanup_state = ? WHERE id = ? AND cleanup_state IN('none','pending')
AND (cleanup_state = 'none' OR ? = 'cleaned')`, state, reportID, state)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("%w: 报告不存在或清理状态已变化", reports.ErrConflict)
	}
	return nil
}

// ListHistoryScopeIDs 返回当前历史中出现的全部作用范围稳定 ID。它只返回范围编号
// 元数据（不含报告内容），供服务层逐范围重新授权后再做带 SQL 范围过滤的列表查询；
// 调用方不得把结果直接当作授权放行。
func (s *Store) ListHistoryScopeIDs(ctx context.Context) ([]string, error) {
	rows, err := s.store.DB().QueryContext(ctx,
		`SELECT DISTINCT scope_id FROM report_history ORDER BY scope_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	scopes := make([]string, 0, 16)
	for rows.Next() {
		var scopeID string
		if scanErr := rows.Scan(&scopeID); scanErr != nil {
			return nil, scanErr
		}
		if scopeID != "" {
			scopes = append(scopes, scopeID)
		}
	}
	return scopes, rows.Err()
}

// ListCleanupCandidateScopes 返回存在“已过期且尚未清理”报告文件的全部作用范围
// 稳定 ID。它只返回范围元数据，供服务层按 reports.cleanup 权限逐范围授权；不能
// 直接作为清理目标或授权依据。
func (s *Store) ListCleanupCandidateScopes(ctx context.Context,
	cutoff time.Time) ([]string, error) {
	rows, err := s.store.DB().QueryContext(ctx, `SELECT DISTINCT scope_id
FROM report_history
WHERE expires_at_ms > 0 AND expires_at_ms < ?
AND cleanup_state IN('none','pending')
ORDER BY scope_id`, timeToMS(cutoff))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	scopes := make([]string, 0, 16)
	for rows.Next() {
		var scopeID string
		if scanErr := rows.Scan(&scopeID); scanErr != nil {
			return nil, scanErr
		}
		if scopeID != "" {
			scopes = append(scopes, scopeID)
		}
	}
	return scopes, rows.Err()
}

// ListCleanupCandidates 返回指定数据范围内“已过期且尚未清理”的报告历史（按到期
// 时间升序、编号升序，受 limit 限制）。结果只用于报告文件清理：本方法不删除原始
// 审计记录，也不表示报告内容仍可下载。
func (s *Store) ListCleanupCandidates(ctx context.Context, access AccessScope,
	cutoff time.Time, limit int) ([]HistoryRecord, error) {
	condition, args := accessSQL(access)
	clamped := clampLimit(limit)
	args = append([]any{timeToMS(cutoff)}, args...)
	args = append(args, clamped)
	query := `SELECT ` + historyColumns + ` FROM report_history
WHERE expires_at_ms > 0 AND expires_at_ms < ?
AND cleanup_state IN('none','pending')` + condition +
		` ORDER BY expires_at_ms, id LIMIT ?`
	rows, err := s.store.DB().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := make([]HistoryRecord, 0, clamped)
	for rows.Next() {
		record, scanErr := scanHistory(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return records, nil
}
