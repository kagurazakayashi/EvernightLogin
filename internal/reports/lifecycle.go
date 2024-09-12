package reports

// 本文件定义步骤 79 报告生命周期的跨层契约：数据范围（AccessScope）、持久历史
// 读取契约（HistoryReader）、计划管理读模型（PlanProjectionStore）与下载/清理相关
// 的领域常量、错误哨兵。
//
// 安全不变量：
//   - 仓储层只返回数据范围内的行；范围条件必须写进 SQL（由 internal/reports/sqlite
//     适配器实现），不在内存里“先全量读取再过滤”。
//   - 计划管理读模型是可从调度事实重建的派生数据；它不是权限来源，每条记录使用前
//     仍由 PlanService 按当前调用者重新授权。
//   - 报告文件清理与原始审计删除严格分开：本包没有任何删除原始审计记录的能力。

import (
	"context"
	"errors"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// 报告生命周期新增的稳定标识。权限键与敏感操作 ID 与 internal/preset、
// internal/policy 目录保持一致；错误码全部复用既有注册表。
const (
	// PermissionScheduleManage 是管理定期报告计划（创建/编辑/启停/删除）的权限键。
	PermissionScheduleManage = "reports.schedule.manage"
	// PermissionCleanup 是清理已过期报告文件（不是原始审计）的权限键。
	PermissionCleanup = "reports.cleanup"
	// OperationCleanup 是 internal/policy 敏感操作 ID：清理报告文件必须强认证并
	// 绑定实际目标/数量/范围，确认框不是授权。
	OperationCleanup = "reports.cleanup"
)

// 报告生命周期审计动作稳定标识（报告生成/导出动作见 reports.go）。
const (
	// ActionPlanCreate 是创建报告计划。
	ActionPlanCreate = "reports.plan.create"
	// ActionPlanUpdate 是编辑报告计划（行版本不一致时拒绝覆盖）。
	ActionPlanUpdate = "reports.plan.update"
	// ActionPlanDelete 是删除报告计划（历史与原始审计不随计划删除）。
	ActionPlanDelete = "reports.plan.delete"
	// ActionPlanReconcile 是系统身份重建/修复计划管理读模型。
	ActionPlanReconcile = "reports.plan.reconcile"
	// ActionCleanupRequest 是清理预览/受理（意图留痕）。
	ActionCleanupRequest = "reports.cleanup.request"
	// ActionCleanupFinish 是报告文件清理结果（成功与部分失败都记录真实计数）。
	ActionCleanupFinish = "reports.cleanup.finish"
	// ActionDownloadTicketIssue 是下载短期令牌签发。
	ActionDownloadTicketIssue = "reports.download.ticket.issue"
	// ActionDownloadTicketDeny 是下载短期令牌兑换被拒绝（过期/一次性/失权）。
	ActionDownloadTicketDeny = "reports.download.ticket.deny"
)

// 报告生命周期领域错误哨兵。
var (
	// ErrTicketInvalid 表示下载令牌不存在或格式非法（含已被使用的一次性令牌，
	// 不区分“从未存在”与“已使用”，避免探测）。
	ErrTicketInvalid = errors.New("下载令牌无效或已使用")
	// ErrTicketExpired 表示下载令牌已过期。
	ErrTicketExpired = errors.New("下载令牌已过期")
	// ErrTicketAccessDenied 表示令牌绑定的调用者与当前会话不一致。
	ErrTicketAccessDenied = errors.New("下载令牌不属于当前调用者")
	// ErrTicketNotAllowed 表示当前权限/产物状态不允许签发或兑换下载令牌。
	ErrTicketNotAllowed = errors.New("当前不允许下载该报告")
)

// 下载短期令牌边界。令牌只用于“页面已获准后的一次性下载兑换”，不是分享链接：
// 到期即失效、只能兑换一次、绑定报告+格式+签发调用者，兑换时再次完整授权。
const (
	// DefaultDownloadTicketTTL 是下载令牌默认有效期（5 分钟）。
	DefaultDownloadTicketTTL = 5 * time.Minute
	// MaxDownloadTicketTTL 是下载令牌有效期硬上限（15 分钟）。
	MaxDownloadTicketTTL = 15 * time.Minute
	// MaxDownloadTickets 是进程内同时保留的未兑换令牌数量上限。
	MaxDownloadTickets = 4096
	// cleanupTicketPruneBatch 是一次修剪过期令牌的最大数量。
	cleanupTicketPruneBatch = 512
)

// 清理边界。报告文件清理只针对输出目录中已过期的受控产物；原始审计记录的保留
// 与清理是另一套 root 受控流程，本包不提供入口。
const (
	// DefaultCleanupGracePeriod 是报告文件到期后默认保留多久才允许清理（7 天）。
	DefaultCleanupGracePeriod = 7 * 24 * time.Hour
	// MaxCleanupGracePeriod 是清理宽限期硬上限（90 天）。
	MaxCleanupGracePeriod = 90 * 24 * time.Hour
	// DefaultCleanupBatch 是单次清理默认目标上限。
	DefaultCleanupBatch = 200
	// MaxCleanupBatch 是单次清理目标硬上限。
	MaxCleanupBatch = 1000
)

// AccessScope 是服务层已按调用者当前权限推导出的数据范围，直接用于仓储 SQL
// 条件。AllData 只允许 root 或可信系统范围使用；ResourceIDs 是获准的作用范围
// 稳定 ID（可含 system）。
type AccessScope struct {
	AllData     bool
	ResourceIDs []string
}

// HistoryQuery 是报告历史列表查询。排序固定为创建时间倒序 + 编号倒序；分页用
// 游标。State/PlanID/Owner 为空表示不筛选；Search 是已规范化的显示名字面搜索。
type HistoryQuery struct {
	Access          AccessScope
	PlanID          string
	State           string
	Owner           *audit.Actor
	Limit           int
	BeforeCreatedAt time.Time
	BeforeID        string
	Search          string
	SearchFields    []HistorySearchField
}

// HistoryPage 是报告历史列表页；HasMore 表示还有下一页（不伪造总数）。
type HistoryPage struct {
	Records []HistoryRecord
	HasMore bool
}

// HistoryReader 是持久报告历史读取契约。生产实现为 internal/reports/sqlite 的
// 适配器；读取必须携带服务层授权后的数据范围，仓储不自行放行权限。
type HistoryReader interface {
	// GetHistory 按编号与数据范围读取；不在范围内与不存在都返回 found=false。
	GetHistory(ctx context.Context, reportID string, access AccessScope) (HistoryRecord, bool, error)
	// ListHistory 返回数据范围内受控分页的历史列表。
	ListHistory(ctx context.Context, query HistoryQuery) (HistoryPage, error)
	// ListHistoryScopeIDs 返回历史中出现过的范围编号（仅元数据，供服务层逐范围
	// 重新授权后再查询；不得直接视为授权结果）。
	ListHistoryScopeIDs(ctx context.Context) ([]string, error)
	// ListCleanupCandidateScopes 返回存在已过期报告文件的范围编号（仅元数据）。
	ListCleanupCandidateScopes(ctx context.Context, cutoff time.Time) ([]string, error)
	// ListCleanupCandidates 返回数据范围内已过期且未清理的报告历史。
	ListCleanupCandidates(ctx context.Context, access AccessScope, cutoff time.Time,
		limit int) ([]HistoryRecord, error)
	// MarkHistoryCleanup 推进报告文件清理状态（none→pending→cleaned，只前进）。
	MarkHistoryCleanup(ctx context.Context, reportID, cleanupState string) error
}

// HistoryStore 是报告历史的完整持久化契约（写入 + 读取）。Options.History 的
// 生产实现同时实现两者；只实现 HistoryRecorder 的测试替身仍可用于验证终态写入，
// 但服务不会为它伪造读取回源能力。
type HistoryStore interface {
	HistoryRecorder
	HistoryReader
}

// PlanProjection 是报告计划的管理读模型。它从调度事实（task.Schedule 载荷 + 状态）
// 派生，可从调度器重建，不独立承载命令；所有修改仍先由调度器执行再同步投影。
type PlanProjection struct {
	ID             string
	Name           string
	Owner          audit.Actor
	ExecutionActor audit.Actor
	ScopeID        string
	ScopeKind      string
	AppID          string
	Template       string
	ScheduleType   task.ScheduleType
	Expression     string
	TimeZone       string
	Granularity    stats.Granularity
	WindowDays     int
	Categories     []stats.Category
	TrendMetric    stats.Metric
	Formats        []Format
	DetailRows     int
	MissedPolicy   task.MissedPolicy
	MaxCatchUp     int
	TimeoutSeconds int
	MaxAttempts    int
	Enabled        bool
	Version        int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// PlanProjectionStore 是报告计划管理读模型的持久化契约（可选装配）。实现必须：
//   - 编号重复返回 ErrConflict；
//   - 更新/启停/删除使用行版本乐观并发，版本不一致返回 ErrConflict，不静默覆盖；
//   - 只持久化受控配置，不保存产物路径、凭证或敏感明细。
type PlanProjectionStore interface {
	CreatePlanProjection(ctx context.Context, plan PlanProjection) (PlanProjection, error)
	GetPlanProjection(ctx context.Context, planID string) (PlanProjection, bool, error)
	UpdatePlanProjection(ctx context.Context, plan PlanProjection,
		expectedVersion int64) (PlanProjection, error)
	SetPlanProjectionEnabled(ctx context.Context, planID string, enabled bool) error
	DeletePlanProjection(ctx context.Context, planID string) error
}
