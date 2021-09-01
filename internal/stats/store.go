package stats

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// RetentionRecord 是审计保留策略持久化记录（读取 audit_retention_policy）。
type RetentionRecord struct {
	Days      int
	Version   int64
	UpdatedAt time.Time
}

// ScopeConstraint 是服务层授权结果转换后的存储层范围约束。存储实现必须把它
// 直接写进 SQL WHERE 子句，禁止先读取全量再在内存过滤。
type ScopeConstraint struct {
	// AllData 为 true 表示数据范围不限（仍受系统/应用范围约束）。
	AllData bool
	// AppIDs 是允许查看的应用快照 ID 集合；AllData 为 false 时生效。
	AppIDs []string
	// IncludeSystem 表示是否允许查看没有应用快照（app_id_snapshot 为空）的系统级
	// 事件。
	IncludeSystem bool
	// AppID 非空表示固定到单个应用范围（应用作用范围查询）。
	AppID string
}

// AuthFact 是一条“完整成功认证”事实（供活跃度聚合）。
type AuthFact struct {
	OccurredAt time.Time
	UserID     string
	AppID      string
}

// AuthFactQuery 是认证事实查询参数；Limit 是行数上限，超过时结果标记截断。
type AuthFactQuery struct {
	From    time.Time
	To      time.Time
	Scope   ScopeConstraint
	Limit   int
	AppID   string
	OnlyApp bool
}

// AuthFactPage 是认证事实查询结果。Truncated 为 true 表示达到行数上限，结果
// 不完整，调用方必须显式标注而不是把数量当作完整值。
type AuthFactPage struct {
	Facts     []AuthFact
	Truncated bool
}

// ErrorGroupRow 是错误聚合的原始分组（按错误码/应用/结果/动作分组）。服务层在
// 内存中把这些分组按统计类别与严重度合并，并计算占比、首次/最近与增幅。
type ErrorGroupRow struct {
	ErrorCode string
	AppID     string
	Outcome   audit.Outcome
	Action    string
	// RawEvents 是该分组原始审计事件次数。
	RawEvents int64
	// FailedRequests/FailedTasks 是该分组内按 request_id/task_id 去重的数量；
	// 缺失关联编号时以事件自身 ID 计一个逻辑请求/任务。
	FailedRequests int64
	FailedTasks    int64
	FirstSeen      time.Time
	LastSeen       time.Time
}

// ErrorGroupQuery 是错误聚合查询参数。
type ErrorGroupQuery struct {
	From  time.Time
	To    time.Time
	Scope ScopeConstraint
	Limit int
}

// FailureKeyQuery 是“全局去重失败请求/任务数”查询参数。它与行级去重分开计算：
// 行级去重数可能跨错误码重叠，页面不得把行级数量相加当作全局总数。
type FailureKeyQuery struct {
	From  time.Time
	To    time.Time
	Scope ScopeConstraint
}

// FailureKeyCount 是全局去重失败请求/任务数。
type FailureKeyCount struct {
	DistinctRequests int64
	DistinctTasks    int64
}

// BusinessActivityRecord 是可信业务活动上报记录。Source 固定为 app_server；
// DedupeKey 唯一，重复上报按幂等处理。
type BusinessActivityRecord struct {
	AppID       string
	UserID      string
	ActivityKey string
	OccurredAt  time.Time
	RecordedAt  time.Time
	Source      string
	DedupeKey   string
}

// BusinessActivityFact 是可聚合的业务活动事实。
type BusinessActivityFact struct {
	OccurredAt  time.Time
	UserID      string
	AppID       string
	ActivityKey string
}

// BusinessActivityFactQuery 是业务活动事实查询参数（存储层）。
type BusinessActivityFactQuery struct {
	From  time.Time
	To    time.Time
	Scope ScopeConstraint
	Limit int
	AppID string
}

// BusinessActivityPage 是业务活动查询结果；Truncated 表示达到行数上限。
type BusinessActivityPage struct {
	Facts     []BusinessActivityFact
	Truncated bool
}

// HealthSampleQuery 是健康采样历史查询参数。
type HealthSampleQuery struct {
	From    time.Time
	To      time.Time
	Modules []Module
	Limit   int
}

// HealthSamplePage 是健康采样历史查询结果；Truncated 表示达到行数上限。
type HealthSamplePage struct {
	Samples   []HealthSample
	Truncated bool
}

// Store 是统计持久化契约，由 internal/stats/sqlite 提供生产实现。
//
// 实现约定：
//   - 所有查询把范围约束写进 SQL WHERE 子句，不提供全量读取后内存过滤的接口；
//   - 认证事实与错误分组按时间正序返回（稳定顺序），行数受调用方 Limit 限制；
//   - 业务活动上报使用唯一 dedupe_key 幂等，重复上报返回 inserted=false；
//   - 健康采样写入按 (module, observed_at_ms) 主键幂等；清理按截止时间与单次
//     行数上限删除，限制存储增长；
//   - 所有方法传播 context；错误信息不包含凭据、连接串或原始事件正文。
type Store interface {
	// GetRetention 读取审计保留策略；未设置时 found=false，由服务层使用默认值。
	GetRetention(ctx context.Context) (RetentionRecord, bool, error)
	// QueryAuthFacts 返回 [From, To) 内范围约束下的完整成功认证事实。
	QueryAuthFacts(ctx context.Context, query AuthFactQuery) (AuthFactPage, error)
	// AggregateErrorGroups 返回 [From, To) 内应计入错误统计的原始分组。
	AggregateErrorGroups(ctx context.Context, query ErrorGroupQuery) ([]ErrorGroupRow, bool, error)
	// CountFailureKeys 返回 [From, To) 内全局去重失败请求/任务数。
	CountFailureKeys(ctx context.Context, query FailureKeyQuery) (FailureKeyCount, error)
	// InsertBusinessActivity 幂等写入一条可信业务活动；已存在返回 inserted=false。
	InsertBusinessActivity(ctx context.Context, record BusinessActivityRecord) (bool, error)
	// QueryBusinessActivity 返回可信业务活动事实。
	QueryBusinessActivity(ctx context.Context, query BusinessActivityFactQuery) (BusinessActivityPage, error)
	// InsertHealthSamples 写入一批健康采样（主键冲突按幂等忽略）。
	InsertHealthSamples(ctx context.Context, samples []HealthSample) error
	// QueryHealthSamples 读取健康采样历史（时间正序）。
	QueryHealthSamples(ctx context.Context, query HealthSampleQuery) (HealthSamplePage, error)
	// PruneHealthSamples 删除早于 before 的采样，单次最多 maxRows 行。
	PruneHealthSamples(ctx context.Context, before time.Time, maxRows int) (int64, error)
}
