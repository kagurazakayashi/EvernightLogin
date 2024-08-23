package app

import (
	"time"
)

// AdminAuditChange 是审计事件中已脱敏的字段变更。
type AdminAuditChange struct {
	Field  string
	Before string
	After  string
}

// AdminAuditEvent 是脱敏审计事件视图（不含原始 detail_json 与请求正文）。
type AdminAuditEvent struct {
	ID         string
	OccurredAt time.Time
	ActorType  string
	ActorID    string
	AppID      string
	Action     string
	TargetType string
	TargetID   string
	Outcome    string
	ErrorCode  string
	ReasonCode string
	RequestID  string
	TaskID     string
	Changes    []AdminAuditChange
}

// AdminAuditFilter 是审计事件筛选条件；时间为 [From, To)。
type AdminAuditFilter struct {
	From       time.Time
	To         time.Time
	AppID      string
	SystemOnly bool
	ActorType  string
	ActorID    string
	Action     string
	Outcome    string
	ErrorCode  string
	RequestID  string
	TaskID     string
	TargetType string
	TargetID   string
}

// AdminListAuditEventsRequest 分页查询审计事件。Order 只允许
// "occurred_desc"（默认）/"occurred_asc"；Cursor 非空时不能同时使用 offset
// （本门面只暴露游标，不暴露 offset）。
type AdminListAuditEventsRequest struct {
	Caller    AdminCaller
	ScopeID   string
	Filter    AdminAuditFilter
	Order     string
	Limit     int
	Cursor    string
	RequestID string
}

// AdminAuditEventList 是审计事件列表结果；NextCursor 由服务端签发并绑定 scope/
// 筛选/排序，客户端不得修改或跨筛选复用。
type AdminAuditEventList struct {
	Events              []AdminAuditEvent
	HasMore             bool
	Limit               int
	NextCursor          string
	Order               string
	ScopeID             string
	ScopeKind           string
	RetentionDays       int
	RetentionConfigured bool
	RetentionCutoff     time.Time
}

// AdminReportArtifact 是报告产物可用性摘要（无宿主路径）。
type AdminReportArtifact struct {
	Format    string
	Bytes     int64
	SHA256    string
	Available bool
	ExpiresAt time.Time
}

// AdminReportHistory 是脱敏历史报告视图。
type AdminReportHistory struct {
	ID            string
	PlanID        string
	Name          string
	OwnerType     string
	OwnerID       string
	ScopeID       string
	ScopeKind     string
	AppID         string
	State         string
	Formats       []string
	TaskID        string
	ExecutorID    string
	ErrorCode     string
	FailureReason string
	RequestID     string
	CreatedAt     time.Time
	StartedAt     time.Time
	FinishedAt    time.Time
	ExpiresAt     time.Time
	CleanupState  string
	Artifacts     []AdminReportArtifact
}

// AdminListReportsRequest 分页查询历史报告；Cursor 绑定 PlanID/State 筛选。
type AdminListReportsRequest struct {
	Caller    AdminCaller
	PlanID    string
	State     string
	Limit     int
	Cursor    string
	RequestID string
}

// AdminReportList 是历史报告列表结果。
type AdminReportList struct {
	Reports      []AdminReportHistory
	HasMore      bool
	Limit        int
	NextCursor   string
	ScopeTrimmed bool
}

// AdminReportPlan 是报告计划的脱敏管理视图。
type AdminReportPlan struct {
	ID              string
	Name            string
	OwnerType       string
	OwnerID         string
	ScopeID         string
	ScopeKind       string
	AppID           string
	ScheduleType    string
	Expression      string
	TimeZone        string
	Granularity     string
	Formats         []string
	Enabled         bool
	Version         int64
	CreatedAt       time.Time
	UpdatedAt       time.Time
	PermissionState string
}

// AdminReportPlanList 是报告计划列表结果。
type AdminReportPlanList struct {
	Plans   []AdminReportPlan
	HasMore bool
	Page    AdminPageInfo
}

// AdminBackupJob 是备份/清理任务脱敏视图。
type AdminBackupJob struct {
	ID            string
	Kind          string
	Origin        string
	ScheduleID    string
	State         string
	StageCode     string
	Attempt       int
	MaxAttempts   int
	InitiatorType string
	InitiatorID   string
	ErrorCode     string
	FailureReason string
	RequestID     string
	BackupID      string
	CreatedAt     time.Time
	StartedAt     time.Time
	FinishedAt    time.Time
}

// AdminListBackupJobsRequest 分页查询备份任务（offset 契约）。
type AdminListBackupJobsRequest struct {
	Caller     AdminCaller
	Kind       string
	ScheduleID string
	Page       AdminPage
	RequestID  string
}

// AdminBackupJobList 是备份任务列表结果。
type AdminBackupJobList struct {
	Jobs    []AdminBackupJob
	HasMore bool
	Page    AdminPageInfo
}

// AdminBackupArtifact 是备份产物脱敏视图（无宿主绝对路径/密钥）。
type AdminBackupArtifact struct {
	ID               string
	JobID            string
	ScheduleID       string
	Origin           string
	SizeBytes        int64
	FileSHA256       string
	Verification     string
	VerifiedAt       time.Time
	Cleanup          string
	CreatedAt        time.Time
	PublishedAt      time.Time
	FileExists       bool
	IsLastUsable     bool
	ProtectionReason string
	Downloadable     bool
}

// AdminListBackupArtifactsRequest 分页查询备份产物（offset 契约）。
type AdminListBackupArtifactsRequest struct {
	Caller       AdminCaller
	Origin       string
	Verification string
	Cleanup      string
	ScheduleID   string
	JobID        string
	Page         AdminPage
	RequestID    string
}

// AdminBackupArtifactList 是备份产物列表结果。
type AdminBackupArtifactList struct {
	Artifacts []AdminBackupArtifact
	HasMore   bool
	Page      AdminPageInfo
}

// AdminBackupSchedule 是备份计划脱敏视图。
type AdminBackupSchedule struct {
	ID                string
	Name              string
	Enabled           bool
	ScheduleType      string
	Expression        string
	TimeZone          string
	PeriodDescription string
	MissedPolicy      string
	ScopeID           string
	NextRun           time.Time
	NextRunUnknown    bool
	CreatedAt         time.Time
	UpdatedAt         time.Time
	PermissionState   string
}

// AdminListBackupSchedulesRequest 分页查询备份计划（offset 契约）。
type AdminListBackupSchedulesRequest struct {
	Caller    AdminCaller
	Page      AdminPage
	RequestID string
}

// AdminBackupScheduleList 是备份计划列表结果。
type AdminBackupScheduleList struct {
	Schedules []AdminBackupSchedule
	HasMore   bool
	Page      AdminPageInfo
}

// AdminBackupNotification 是备份通知投递记录脱敏视图。
type AdminBackupNotification struct {
	ID              string
	JobID           string
	BackupID        string
	Kind            string
	State           string
	Channel         string
	RecipientMasked string
	ErrorCode       string
	Attempts        int
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// AdminListBackupNotificationsRequest 分页查询备份通知记录（offset 契约）。
type AdminListBackupNotificationsRequest struct {
	Caller    AdminCaller
	JobID     string
	BackupID  string
	Page      AdminPage
	RequestID string
}

// AdminBackupNotificationList 是备份通知列表结果。
type AdminBackupNotificationList struct {
	Notifications []AdminBackupNotification
	HasMore       bool
	Page          AdminPageInfo
}

// AdminTask 是后台任务脱敏列表视图（不含 payload/处理器错误原文）。
type AdminTask struct {
	ID            string
	Kind          string
	State         string
	InitiatorType string
	InitiatorID   string
	ExecutorID    string
	Attempt       int
	MaxAttempts   int
	ErrorCode     string
	FailureReason string
	RequestID     string
	CreatedAt     time.Time
	StartedAt     time.Time
	FinishedAt    time.Time
}

// AdminTaskList 是后台任务列表结果。
type AdminTaskList struct {
	Tasks      []AdminTask
	HasMore    bool
	Limit      int
	NextCursor string
}
