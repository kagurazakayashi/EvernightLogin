package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

const (
	insertScheduleSQL = `INSERT INTO schedules(
id,kind,schedule_type,expression,timezone,owner_type,owner_id,execution_type,execution_id,scope_id,
enabled,permission_required,missed_policy,max_catch_up,config_json,last_scheduled_at_ms,
created_at_ms,updated_at_ms
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

	scheduleSelectColumns = `id,kind,schedule_type,expression,timezone,owner_type,owner_id,
execution_type,execution_id,scope_id,enabled,permission_required,missed_policy,max_catch_up,
config_json,last_scheduled_at_ms,created_at_ms,updated_at_ms`

	selectScheduleSQL         = `SELECT ` + scheduleSelectColumns + ` FROM schedules WHERE id=?`
	selectEnabledSchedulesSQL = `SELECT ` + scheduleSelectColumns + ` FROM schedules WHERE enabled=1 ORDER BY created_at_ms,id`
	selectAllSchedulesSQL     = `SELECT ` + scheduleSelectColumns + ` FROM schedules ORDER BY created_at_ms,id`
	updateScheduleStateSQL    = `UPDATE schedules SET enabled=?,last_scheduled_at_ms=?,updated_at_ms=? WHERE id=?`
	deleteScheduleSQL         = `DELETE FROM schedules WHERE id=?`
	advanceScheduleCursorSQL  = `UPDATE schedules SET last_scheduled_at_ms=?,updated_at_ms=? WHERE id=? AND (last_scheduled_at_ms IS NULL OR last_scheduled_at_ms<?)`
	insertScheduleFiringSQL   = `INSERT INTO schedule_firings(schedule_id,scheduled_at_ms,job_id,outcome,error_code,reason_code,created_at_ms) VALUES(?,?,?,?,?,?,?)`
)

// errFiringDuplicate 表示同一计划触发时刻已经记录过；事务回滚后映射为
// FireResult{Fired:false}，不产生第二个任务。
var errFiringDuplicate = errors.New("task: 计划触发已记录")

// scheduleConfig 是 schedules.config_json 的内容：计划触发任务时使用的任务模板，
// 避免把载荷、互斥键等重复成独立列。
type scheduleConfig struct {
	Payload        json.RawMessage `json:"payload"`
	MutexKey       string          `json:"mutex_key,omitempty"`
	TimeoutSeconds int             `json:"timeout_seconds"`
	MaxAttempts    int             `json:"max_attempts"`
}

// 编译期确认实现 task.ScheduleStore。
var _ task.ScheduleStore = (*Store)(nil)

// CreateSchedule 插入计划并在同一事务写 schedules.created 审计。
func (s *Store) CreateSchedule(ctx context.Context, schedule task.NewSchedule) (task.Schedule, error) {
	if err := task.ValidateNewSchedule(schedule); err != nil {
		return task.Schedule{}, err
	}
	configJSON, err := encodeScheduleConfig(schedule)
	if err != nil {
		return task.Schedule{}, err
	}
	nowMS := schedule.CreatedAt.UTC().UnixMilli()
	event := scheduleAuditEvent(schedule.ID, schedule.Owner, "schedules.created",
		audit.OutcomeSuccess, "", "", schedule.RequestID)
	event.Changes = []audit.FieldChange{{Field: "enabled", Before: "", After: boolText(schedule.Enabled)}}
	change := func(txCtx context.Context, tx audit.Tx) error {
		_, err := tx.ExecContext(txCtx, insertScheduleSQL,
			schedule.ID,
			schedule.JobKind,
			string(schedule.ScheduleType),
			schedule.Expression,
			schedule.TimeZone,
			string(schedule.Owner.Type),
			schedule.Owner.ID,
			string(schedule.ExecutionActor.Type),
			schedule.ExecutionActor.ID,
			schedule.ScopeID,
			boolInt(schedule.Enabled),
			boolInt(schedule.PermissionRequired),
			string(schedule.MissedPolicy),
			schedule.MaxCatchUp,
			string(configJSON),
			nowMS,
			nowMS,
			nowMS,
		)
		return err
	}
	prepared, err := s.prepare(event)
	if err != nil {
		return task.Schedule{}, mapStoreError(err)
	}
	if err := s.auditStore.RunCritical(ctx, prepared, change); err != nil {
		return task.Schedule{}, mapStoreError(err)
	}
	return task.Schedule{
		ID:                 schedule.ID,
		JobKind:            schedule.JobKind,
		ScheduleType:       schedule.ScheduleType,
		Expression:         schedule.Expression,
		TimeZone:           schedule.TimeZone,
		Owner:              schedule.Owner,
		ExecutionActor:     schedule.ExecutionActor,
		ScopeID:            schedule.ScopeID,
		Enabled:            schedule.Enabled,
		PermissionRequired: schedule.PermissionRequired,
		MissedPolicy:       schedule.MissedPolicy,
		MaxCatchUp:         schedule.MaxCatchUp,
		Payload:            schedule.Payload,
		MutexKey:           schedule.MutexKey,
		TimeoutSeconds:     schedule.TimeoutSeconds,
		MaxAttempts:        schedule.MaxAttempts,
		LastScheduledAt:    time.UnixMilli(nowMS).UTC(),
		CreatedAt:          time.UnixMilli(nowMS).UTC(),
		UpdatedAt:          time.UnixMilli(nowMS).UTC(),
	}, nil
}

// GetSchedule 读取计划；不存在返回 (Schedule{}, false, nil)。
func (s *Store) GetSchedule(ctx context.Context, id string) (task.Schedule, bool, error) {
	if err := task.ValidateScheduleID(id); err != nil {
		return task.Schedule{}, false, err
	}
	rows, err := s.raw.QueryContext(ctx, selectScheduleSQL, id)
	if err != nil {
		return task.Schedule{}, false, mapStoreError(err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return task.Schedule{}, false, mapStoreError(err)
		}
		return task.Schedule{}, false, nil
	}
	schedule, err := scanSchedule(rows)
	if err != nil {
		return task.Schedule{}, false, mapStoreError(err)
	}
	return schedule, true, nil
}

// ListSchedules 返回计划列表；enabledOnly=true 时只返回启用计划。
func (s *Store) ListSchedules(ctx context.Context, enabledOnly bool) ([]task.Schedule, error) {
	query := selectAllSchedulesSQL
	if enabledOnly {
		query = selectEnabledSchedulesSQL
	}
	rows, err := s.raw.QueryContext(ctx, query)
	if err != nil {
		return nil, mapStoreError(err)
	}
	defer rows.Close()
	schedules := make([]task.Schedule, 0, 8)
	for rows.Next() {
		schedule, err := scanSchedule(rows)
		if err != nil {
			return nil, mapStoreError(err)
		}
		schedules = append(schedules, schedule)
	}
	if err := rows.Err(); err != nil {
		return nil, mapStoreError(err)
	}
	return schedules, nil
}

// SetScheduleEnabled 暂停或恢复计划。恢复时把触发游标重新锚定到当前时刻，
// 暂停期间的触发不补跑。只有计划所有者、系统或本地管理员可以修改。
func (s *Store) SetScheduleEnabled(ctx context.Context, command task.ScheduleStateCommand) (task.Schedule, error) {
	if err := task.ValidateScheduleCommand(command.ScheduleID, command.Actor, command.Reason, command.RequestID); err != nil {
		return task.Schedule{}, err
	}
	if command.Now.IsZero() {
		return task.Schedule{}, fmt.Errorf("%w: 计划状态变更时间不能为空", task.ErrInvalidRequest)
	}
	current, found, err := s.GetSchedule(ctx, command.ScheduleID)
	if err != nil {
		return task.Schedule{}, err
	}
	if !found {
		return task.Schedule{}, task.ErrScheduleNotFound
	}
	if !canManageSchedule(command.Actor, current.Owner) {
		return task.Schedule{}, task.ErrScheduleForbidden
	}
	if current.Enabled == command.Enable {
		return current, nil
	}
	nowMS := command.Now.UTC().UnixMilli()
	cursorMS := current.LastScheduledAt.UTC().UnixMilli()
	if command.Enable {
		// 恢复：从恢复时刻重新开始，暂停期间错过的触发不补跑。
		cursorMS = nowMS
	}
	action := "schedules.paused"
	if command.Enable {
		action = "schedules.resumed"
	}
	event := scheduleAuditEvent(command.ScheduleID, command.Actor, action,
		audit.OutcomeSuccess, "", "", command.RequestID)
	event.Changes = []audit.FieldChange{
		{Field: "enabled", Before: boolText(current.Enabled), After: boolText(command.Enable)},
		{Field: "last_scheduled_at", Before: timeText(current.LastScheduledAt), After: time.UnixMilli(cursorMS).UTC().Format(time.RFC3339Nano)},
	}
	change := func(txCtx context.Context, tx audit.Tx) error {
		result, err := tx.ExecContext(txCtx, updateScheduleStateSQL,
			boolInt(command.Enable), cursorMS, nowMS, command.ScheduleID)
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if affected != 1 {
			return task.ErrScheduleNotFound
		}
		return nil
	}
	prepared, err := s.prepare(event)
	if err != nil {
		return task.Schedule{}, mapStoreError(err)
	}
	if err := s.auditStore.RunCritical(ctx, prepared, change); err != nil {
		return task.Schedule{}, mapStoreError(err)
	}
	schedule, err := s.loadSchedule(ctx, command.ScheduleID)
	if err != nil {
		return task.Schedule{}, err
	}
	return schedule, nil
}

// DeleteSchedule 删除计划记录。已入队或运行中的任务不在此事务中修改，继续以独立
// 任务状态机执行；触发历史按外键级联删除，安全审计事件保留。
func (s *Store) DeleteSchedule(ctx context.Context, command task.ScheduleDeleteCommand) error {
	if err := task.ValidateScheduleCommand(command.ScheduleID, command.Actor, command.Reason, command.RequestID); err != nil {
		return err
	}
	current, found, err := s.GetSchedule(ctx, command.ScheduleID)
	if err != nil {
		return err
	}
	if !found {
		return task.ErrScheduleNotFound
	}
	if !canManageSchedule(command.Actor, current.Owner) {
		return task.ErrScheduleForbidden
	}
	event := scheduleAuditEvent(command.ScheduleID, command.Actor, "schedules.deleted",
		audit.OutcomeSuccess, "", "", command.RequestID)
	event.Changes = []audit.FieldChange{{Field: "enabled", Before: boolText(current.Enabled), After: "false"}}
	change := func(txCtx context.Context, tx audit.Tx) error {
		result, err := tx.ExecContext(txCtx, deleteScheduleSQL, command.ScheduleID)
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if affected != 1 {
			return task.ErrScheduleNotFound
		}
		return nil
	}
	prepared, err := s.prepare(event)
	if err != nil {
		return mapStoreError(err)
	}
	if err := s.auditStore.RunCritical(ctx, prepared, change); err != nil {
		return mapStoreError(err)
	}
	return nil
}

// FireSchedule 原子记录一次计划触发：唯一键阻止同一时刻重复触发；入队结果在
// 同一事务插入 queued 任务、推进计划游标并写审计。重复触发返回 Fired=false。
func (s *Store) FireSchedule(ctx context.Context, command task.FireCommand) (task.FireResult, error) {
	if err := validateFireCommand(command); err != nil {
		return task.FireResult{}, err
	}
	current, found, err := s.GetSchedule(ctx, command.ScheduleID)
	if err != nil {
		return task.FireResult{}, err
	}
	if !found {
		return task.FireResult{}, task.ErrScheduleNotFound
	}
	jobID := ""
	if command.Outcome == task.FireEnqueued {
		if command.Job == nil {
			return task.FireResult{}, fmt.Errorf("%w: 入队触发缺少任务参数", task.ErrInvalidRequest)
		}
		if err := validateNewJob(*command.Job); err != nil {
			return task.FireResult{}, err
		}
		jobID = command.Job.ID
	} else if command.Job != nil {
		return task.FireResult{}, fmt.Errorf("%w: 非入队触发不应携带任务参数", task.ErrInvalidRequest)
	}
	nowMS := command.Now.UTC().UnixMilli()
	scheduledMS := command.ScheduledAt.UTC().UnixMilli()
	action, outcome := firingAuditFields(command.Outcome)
	event := scheduleAuditEvent(command.ScheduleID, command.Actor, action, outcome,
		command.ErrorCode, command.ReasonCode, "")
	event.TaskID = jobID
	event.Changes = []audit.FieldChange{{
		Field:  "last_scheduled_at",
		Before: timeText(current.LastScheduledAt),
		After:  command.ScheduledAt.UTC().Format(time.RFC3339Nano),
	}}
	change := func(txCtx context.Context, tx audit.Tx) error {
		if command.Outcome == task.FireEnqueued {
			if err := insertJobRow(txCtx, tx, *command.Job); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(txCtx, insertScheduleFiringSQL,
			command.ScheduleID,
			scheduledMS,
			nullable(jobID),
			string(command.Outcome),
			nullable(command.ErrorCode),
			nullable(command.ReasonCode),
			nowMS,
		); err != nil {
			if errors.Is(err, storage.ErrUniqueViolation) {
				return errFiringDuplicate
			}
			return err
		}
		result, err := tx.ExecContext(txCtx, advanceScheduleCursorSQL, scheduledMS, nowMS, command.ScheduleID, scheduledMS)
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if affected != 1 {
			return task.ErrTransitionRejected
		}
		return nil
	}
	prepared, err := s.prepare(event)
	if err != nil {
		return task.FireResult{}, mapStoreError(err)
	}
	if err := s.auditStore.RunCritical(ctx, prepared, change); err != nil {
		// 唯一键冲突可能是重复触发（计划+时刻已记录），也可能是极小概率的任务
		// 编号冲突；只有确认触发记录已存在时才按“重复触发”静默跳过。
		if errors.Is(err, errFiringDuplicate) ||
			(errors.Is(err, storage.ErrUniqueViolation) && s.scheduleFiringExists(ctx, command.ScheduleID, scheduledMS)) {
			return task.FireResult{Fired: false}, nil
		}
		return task.FireResult{}, mapStoreError(err)
	}
	return task.FireResult{Fired: true, JobID: jobID}, nil
}

// scheduleFiringExists 报告指定计划的某触发时刻是否已有记录（用于区分重复触发
// 与其它唯一键冲突）。
func (s *Store) scheduleFiringExists(ctx context.Context, scheduleID string, scheduledMS int64) bool {
	rows, err := s.raw.QueryContext(ctx,
		`SELECT 1 FROM schedule_firings WHERE schedule_id=? AND scheduled_at_ms=?`, scheduleID, scheduledMS)
	if err != nil {
		return false
	}
	defer rows.Close()
	return rows.Next()
}

// loadSchedule 读取计划并返回存储错误（不存在视为错误）。
func (s *Store) loadSchedule(ctx context.Context, id string) (task.Schedule, error) {
	schedule, found, err := s.GetSchedule(ctx, id)
	if err != nil {
		return task.Schedule{}, err
	}
	if !found {
		return task.Schedule{}, task.ErrScheduleNotFound
	}
	return schedule, nil
}

// encodeScheduleConfig 把任务模板编码为 config_json。
func encodeScheduleConfig(schedule task.NewSchedule) ([]byte, error) {
	if len(schedule.Payload) == 0 || len(schedule.Payload) > task.MaxPayloadBytes || !json.Valid(schedule.Payload) {
		return nil, fmt.Errorf("%w: 计划载荷无效", task.ErrInvalidRequest)
	}
	config, err := json.Marshal(scheduleConfig{
		Payload:        schedule.Payload,
		MutexKey:       schedule.MutexKey,
		TimeoutSeconds: schedule.TimeoutSeconds,
		MaxAttempts:    schedule.MaxAttempts,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: 计划配置无法编码", task.ErrInvalidRequest)
	}
	return config, nil
}

// decodeScheduleConfig 解析 config_json；损坏或越界时拒绝该行而不是静默降级。
func decodeScheduleConfig(raw string) (task.Schedule, error) {
	var config scheduleConfig
	if err := json.Unmarshal([]byte(raw), &config); err != nil {
		return task.Schedule{}, fmt.Errorf("%w: 计划配置无法解析", task.ErrInvalidRequest)
	}
	payload := config.Payload
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	if len(payload) > task.MaxPayloadBytes || !json.Valid(payload) {
		return task.Schedule{}, fmt.Errorf("%w: 计划载荷无效", task.ErrInvalidRequest)
	}
	if config.MutexKey != "" {
		if err := validateSimpleToken("互斥键", config.MutexKey, task.MaxMutexKeyBytes); err != nil {
			return task.Schedule{}, err
		}
	}
	timeout := config.TimeoutSeconds
	if timeout < task.MinTimeoutSeconds || timeout > task.MaxTimeoutSeconds {
		return task.Schedule{}, fmt.Errorf("%w: 计划任务墙钟上限无效", task.ErrInvalidRequest)
	}
	maxAttempts := config.MaxAttempts
	if maxAttempts < 1 || maxAttempts > task.MaxJobAttempts {
		return task.Schedule{}, fmt.Errorf("%w: 计划最大尝试次数无效", task.ErrInvalidRequest)
	}
	return task.Schedule{Payload: payload, MutexKey: config.MutexKey, TimeoutSeconds: timeout, MaxAttempts: maxAttempts}, nil
}

// scanSchedule 从查询结果扫描计划行。
func scanSchedule(rows *sql.Rows) (task.Schedule, error) {
	var (
		schedule        task.Schedule
		scheduleType    string
		ownerType       string
		ownerID         string
		executionType   string
		executionID     string
		enabled         int
		permission      int
		missedPolicy    string
		configJSON      string
		lastScheduledAt sql.NullInt64
		createdAt       int64
		updatedAt       int64
	)
	if err := rows.Scan(
		&schedule.ID,
		&schedule.JobKind,
		&scheduleType,
		&schedule.Expression,
		&schedule.TimeZone,
		&ownerType,
		&ownerID,
		&executionType,
		&executionID,
		&schedule.ScopeID,
		&enabled,
		&permission,
		&missedPolicy,
		&schedule.MaxCatchUp,
		&configJSON,
		&lastScheduledAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return task.Schedule{}, err
	}
	template, err := decodeScheduleConfig(configJSON)
	if err != nil {
		return task.Schedule{}, err
	}
	schedule.Payload = template.Payload
	schedule.MutexKey = template.MutexKey
	schedule.TimeoutSeconds = template.TimeoutSeconds
	schedule.MaxAttempts = template.MaxAttempts
	schedule.ScheduleType = task.ScheduleType(scheduleType)
	schedule.MissedPolicy = task.MissedPolicy(missedPolicy)
	schedule.Owner = audit.Actor{Type: audit.ActorKind(ownerType), ID: ownerID}
	schedule.ExecutionActor = audit.Actor{Type: audit.ActorKind(executionType), ID: executionID}
	schedule.Enabled = enabled == 1
	schedule.PermissionRequired = permission == 1
	schedule.CreatedAt = time.UnixMilli(createdAt).UTC()
	schedule.UpdatedAt = time.UnixMilli(updatedAt).UTC()
	if lastScheduledAt.Valid {
		schedule.LastScheduledAt = time.UnixMilli(lastScheduledAt.Int64).UTC()
	}
	if !schedule.ScheduleType.Valid() || !schedule.MissedPolicy.Valid() {
		return task.Schedule{}, fmt.Errorf("%w: 计划枚举值无效", task.ErrInvalidRequest)
	}
	return schedule, nil
}

// validateFireCommand 校验计划触发命令的字段。
func validateFireCommand(command task.FireCommand) error {
	if err := task.ValidateScheduleID(command.ScheduleID); err != nil {
		return err
	}
	if !command.Outcome.Valid() {
		return fmt.Errorf("%w: 触发结果无效", task.ErrInvalidRequest)
	}
	if command.ScheduledAt.IsZero() || command.Now.IsZero() {
		return fmt.Errorf("%w: 触发时间不能为空", task.ErrInvalidRequest)
	}
	if err := command.Actor.Validate(); err != nil {
		return fmt.Errorf("%w: %v", task.ErrUntrustedActor, err)
	}
	if command.Actor.Type == audit.ActorAnonymous {
		return fmt.Errorf("%w: 匿名调用者不能记录计划触发", task.ErrUntrustedActor)
	}
	if command.ErrorCode != "" {
		if err := validateSimpleToken("错误码", command.ErrorCode, 64); err != nil {
			return err
		}
	}
	if command.ReasonCode != "" {
		if err := validateSimpleToken("原因码", command.ReasonCode, 64); err != nil {
			return err
		}
	}
	if command.Outcome == task.FireEnqueued && command.Job == nil {
		return fmt.Errorf("%w: 入队触发缺少任务参数", task.ErrInvalidRequest)
	}
	return nil
}

// scheduleAuditEvent 构造计划状态变化的安全审计事件。
func scheduleAuditEvent(scheduleID string, actor audit.Actor, action string, outcome audit.Outcome, errorCode, reasonCode, requestID string) audit.Event {
	return audit.Event{
		Actor:      actor,
		Action:     action,
		Target:     audit.Target{Type: "schedule", ID: scheduleID},
		Outcome:    outcome,
		ErrorCode:  errorCode,
		ReasonCode: reasonCode,
		RequestID:  requestID,
	}
}

// firingAuditFields 把触发结果映射为审计动作与结果；权限拒绝记为 denied。
func firingAuditFields(outcome task.FireOutcome) (string, audit.Outcome) {
	switch outcome {
	case task.FireSkipped:
		return "schedules.skipped", audit.OutcomeSuccess
	case task.FireDenied:
		return "schedules.denied", audit.OutcomeDenied
	default:
		return "schedules.fired", audit.OutcomeSuccess
	}
}

// canManageSchedule 报告调用者是否可以暂停/恢复/删除计划：计划所有者本人、系统
// 组件或本地管理员。服务层仍必须先完成自己的范围授权检查。
func canManageSchedule(actor audit.Actor, owner audit.Actor) bool {
	if actor.Type == audit.ActorSystem || actor.Type == audit.ActorLocalAdmin {
		return true
	}
	return actor.Type == owner.Type && actor.ID == owner.ID
}

// boolInt 把布尔值转换为 SQLite 0/1。
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

// boolText 把布尔值转换为审计差异文本。
func boolText(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

// timeText 把可空时间转换为审计差异文本。
func timeText(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
