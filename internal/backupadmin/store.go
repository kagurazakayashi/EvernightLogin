package backupadmin

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// VerificationState 是备份产物的校验状态。只有服务端完成认证校验才可写 verified；
// 有 SHA-256 字段不等于校验通过，任务成功也不等于产物已校验。
type VerificationState string

// 校验状态稳定值。
const (
	VerificationVerified   VerificationState = "verified"
	VerificationUnverified VerificationState = "unverified"
	VerificationUnknown    VerificationState = "unknown"
	VerificationFailed     VerificationState = "failed"
)

// Valid 报告校验状态是否已定义。
func (v VerificationState) Valid() bool {
	switch v {
	case VerificationVerified, VerificationUnverified, VerificationUnknown, VerificationFailed:
		return true
	default:
		return false
	}
}

// CleanupState 是产物文件保留状态；cleaned 表示文件已按保留策略清理，不代表原始
// 审计已删除。
type CleanupState string

// 保留状态稳定值。
const (
	CleanupRetained CleanupState = "retained"
	CleanupCleaned  CleanupState = "cleaned"
)

// Valid 报告保留状态是否已定义。
func (c CleanupState) Valid() bool { return c == CleanupRetained || c == CleanupCleaned }

// Origin 是任务/产物触发来源。
type Origin string

// 触发来源稳定值。
const (
	OriginManual   Origin = "manual"
	OriginSchedule Origin = "schedule"
	OriginCatchUp  Origin = "catch_up"
	OriginRetry    Origin = "retry"
	OriginSystem   Origin = "system"
)

// Valid 报告触发来源是否已定义。
func (o Origin) Valid() bool {
	switch o {
	case OriginManual, OriginSchedule, OriginCatchUp, OriginRetry, OriginSystem:
		return true
	default:
		return false
	}
}

// ContentStatus 是单个内容范围的包含状态。
type ContentStatus string

// 内容范围状态稳定值（与备份清单一致）。
const (
	ContentIncluded      ContentStatus = "included"
	ContentNoReferences  ContentStatus = "no_references"
	ContentNotConfigured ContentStatus = "not_configured"
	ContentExcluded      ContentStatus = "excluded"
)

// Valid 报告内容范围状态是否已定义。
func (c ContentStatus) Valid() bool {
	switch c {
	case ContentIncluded, ContentNoReferences, ContentNotConfigured, ContentExcluded:
		return true
	default:
		return false
	}
}

// Artifact 是一份已发布备份的受控元数据。FileName 只是受控输出目录内的文件名，
// 不是公开路径；不含密钥、明文数据库内容或宿主绝对路径。
type Artifact struct {
	BackupID         string
	JobID            string
	ScheduleID       string
	Origin           Origin
	FileName         string
	SizeBytes        int64
	PayloadBytes     int64
	FileSHA256       string
	ManifestSHA256   string
	FormatVersion    int
	SchemaVersion    string
	ContentDatabase  bool
	ContentAttach    ContentStatus
	ContentConfig    ContentStatus
	EntryCount       int
	Hostname         string
	AppVersion       string
	Verification     VerificationState
	VerifiedAt       time.Time
	RetentionVersion int64
	Cleanup          CleanupState
	CleanedAt        time.Time
	CleanedBy        *audit.Actor
	CreatedAt        time.Time
	PublishedAt      time.Time
	RequestID        string
}

// RetentionPolicy 是当前生效的备份保留策略；Version 单调递增，三项上限为 0 表示
// 该项未启用，但三项全部为 0 会被服务层拒绝（不允许无限保留被静默默认）。
type RetentionPolicy struct {
	Version       int64
	MaxCount      int
	MaxAgeDays    int
	MaxTotalBytes int64
	UpdatedAt     time.Time
	UpdatedBy     audit.Actor
	Reason        string
	RequestID     string
}

// Enabled 报告是否至少启用一项有限上限。
func (p RetentionPolicy) Enabled() bool {
	return p.MaxCount > 0 || p.MaxAgeDays > 0 || p.MaxTotalBytes > 0
}

// ScheduleMeta 是 internal/task 定时计划的附加展示配置；周期、时区与执行身份仍以
// 计划表为唯一事实源。
type ScheduleMeta struct {
	ScheduleID       string
	Name             string
	RetentionVersion int64
	NotifyFailures   bool
	NotifySuccess    bool
	NotifyTarget     string
	CreatedBy        audit.Actor
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// JobIndexEntry 是备份/清理任务索引；任务状态以 internal/task 为唯一事实源。
type JobIndexEntry struct {
	JobID      string
	Kind       string
	Origin     Origin
	ScheduleID string
	Initiator  audit.Actor
	CreatedAt  time.Time
}

// JobProgressState 是任务真实阶段、进度与通知摘要。Done/Total 未知时保持 nil，
// 不用 0 冒充；ResultSummary 只保存受控计数与结果码。
type JobProgressState struct {
	JobID            string
	BackupID         string
	StageCode        string
	ProgressDone     *int64
	ProgressTotal    *int64
	ProgressUnit     string
	NotificationStat string
	NotificationCode string
	ResultSummary    string
	UpdatedAt        time.Time
}

// Notification 是一条通知投递记录；通知失败不影响备份产物事实。
type Notification struct {
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

// ArtifactFilter 是产物查询条件（服务端白名单字段，受控分页）。
type ArtifactFilter struct {
	Origin       Origin
	Verification VerificationState
	Cleanup      CleanupState
	ScheduleID   string
	JobID        string
	Limit        int
	Offset       int
}

// JobFilter 是任务查询条件（受控分页）。
type JobFilter struct {
	Kind       string
	ScheduleID string
	Limit      int
	Offset     int
}

// Store 是步骤 81 备份生命周期持久化契约，由 internal/backupadmin/sqlite 提供生产
// 实现。所有方法传播 context；必须返回本包领域错误（ErrConflict/ErrStoreUnavailable），
// 不返回数据库细节或宿主路径。
type Store interface {
	InsertArtifact(ctx context.Context, artifact Artifact) error
	GetArtifact(ctx context.Context, backupID string) (Artifact, bool, error)
	ListArtifacts(ctx context.Context, filter ArtifactFilter) ([]Artifact, error)
	UpdateArtifactVerification(ctx context.Context, backupID string,
		state VerificationState, verifiedAt time.Time) error
	MarkArtifactCleaned(ctx context.Context, backupID string, actor audit.Actor,
		now time.Time) error

	RetentionPolicy(ctx context.Context) (RetentionPolicy, bool, error)
	SaveRetentionPolicy(ctx context.Context, policy RetentionPolicy,
		expectedVersion int64) error

	ScheduleMeta(ctx context.Context, scheduleID string) (ScheduleMeta, bool, error)
	ListScheduleMeta(ctx context.Context) ([]ScheduleMeta, error)
	SaveScheduleMeta(ctx context.Context, meta ScheduleMeta) error
	DeleteScheduleMeta(ctx context.Context, scheduleID string) error

	InsertJob(ctx context.Context, entry JobIndexEntry) error
	GetJob(ctx context.Context, jobID string) (JobIndexEntry, bool, error)
	ListJobs(ctx context.Context, filter JobFilter) ([]JobIndexEntry, error)
	JobState(ctx context.Context, jobID string) (JobProgressState, bool, error)
	SaveJobState(ctx context.Context, state JobProgressState) error

	InsertNotification(ctx context.Context, notification Notification) error
	UpdateNotification(ctx context.Context, id, state, errorCode string,
		attempts int, now time.Time) error
	ListNotifications(ctx context.Context, jobID, backupID string) ([]Notification, error)
}
