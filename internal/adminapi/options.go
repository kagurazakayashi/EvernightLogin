package adminapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/auditops"
	"github.com/kagurazakayashi/EvernightLogin/internal/backupadmin"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/reports"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// 默认值与硬上限。
const (
	// DefaultBasePath 是管理 API 的默认挂载前缀（含版本）。
	DefaultBasePath = "/admin/v1"
	// MaxBasePathBytes 是挂载前缀最大长度，避免异常配置放大路由表。
	MaxBasePathBytes = 128
	// DefaultMaxBodyBytes 是单个 JSON 请求体上限（1 MiB）；宿主可在外层再收紧。
	DefaultMaxBodyBytes int64 = 1 << 20
	// MaxMaxBodyBytes 是请求体上限允许值。
	MaxMaxBodyBytes int64 = 16 << 20
	// DefaultRequestTimeout 是单请求处理期限；宿主中间件可再收紧。
	DefaultRequestTimeout = 30 * time.Second
	// MinRequestTimeout/MaxRequestTimeout 是请求期限允许范围。
	MinRequestTimeout = 100 * time.Millisecond
	MaxRequestTimeout = 5 * time.Minute
	// DefaultPageLimit/MaxPageLimit 是列表分页默认与上限。
	DefaultPageLimit = 20
	MaxPageLimit     = 100
	// MaxOffset 是允许的最大分页偏移。
	MaxOffset = 1_000_000
	// MaxReasonBytes 是取消/清理/保留策略原因上限。
	MaxReasonBytes = 256
	// CSRFHeaderName 与会话 Cookie 名沿用 internal/transport 的既有契约。
	CSRFHeaderName = "X-CSRF-Token"
)

// ErrorCodeInfo 是根包错误码注册表在管理 API 层的只读投影。管理 API 只返回这里
// 声明的错误码，杜绝出现未登记码；HTTP 状态与默认公开消息同源于根包注册表。
type ErrorCodeInfo struct {
	Code       string
	Message    string
	HTTPStatus int
}

// ManagementSession 是管理会话边界。生产实现是 *session.Service（方法集合一致，
// 见 contracts.go 的编译期断言）；本包不解析 Cookie 摘要、不校验会话数据库状态，
// 全部交给既有会话服务。
//
// 每次请求都重新调用 AuthorizeManagement，禁止缓存“已验证”结论。
// SessionAdminRevoker 是可选的“管理员强制下线”会话能力（步骤 151）。
// 生产实现是 *session.Service；测试替身可不实现，此时管理 API 不挂载该路由，
// 不会退化为无授权放行。
type SessionAdminRevoker interface {
	AdminRevoke(ctx context.Context, adminSecret string, request session.AdminRevokeRequest) (session.AdminRevokeResult, error)
}

// DomainHandler 是宿主补充的领域路由处理器（步骤 156）。认证、CSRF、统一
// envelope/错误映射由本包统一处理；领域授权、敏感策略与审计由 DomainHandler
// 内部调用真实服务完成，禁止只依赖本层会话。
type DomainHandler func(ctx context.Context, caller account.Caller, request *http.Request) (any, error)

// DomainRoute 是宿主补充的一条管理 API 路由。未装配的领域不注册路由（404）。
type DomainRoute struct {
	Method  string
	Pattern string
	Handler DomainHandler
}

// DomainError 是领域路由返回的稳定错误；Code 必须是错误码投影中的码。
type DomainError struct {
	Code    string
	Message string
	Cause   error
}

// Error 实现 error。
func (e *DomainError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return e.Message
	}
	return e.Code
}

// Unwrap 返回底层原因（只用于内部映射，不对外输出）。
func (e *DomainError) Unwrap() error { return e.Cause }

type ManagementSession interface {
	// SessionSecretFromRequest 只从 Cookie 或 Authorization: Bearer 读取会话秘密。
	SessionSecretFromRequest(request *http.Request) (string, bool)
	// AuthorizeManagement 校验会话并要求已完成强认证且强认证仍在新鲜期内。
	AuthorizeManagement(ctx context.Context, secret string) (session.Session, error)
	// ValidateCSRFToken 校验与会话绑定的 CSRF 令牌（Cookie 会话的不安全方法必须）。
	ValidateCSRFToken(ctx context.Context, request *http.Request, token string) error
}

// AuditService 是本包使用的审计读取/导出/清理服务子集；生产实现是
// *auditops.Service。所有方法内部重新授权，并按 internal/policy 敏感策略要求
// 再次认证；本包不复制授权判断。
type AuditService interface {
	Query(ctx context.Context, request auditops.QueryRequest) (auditops.QueryResult, error)
	GetEvent(ctx context.Context, request auditops.GetRequest) (auditops.EventDetail, error)
	Retention(ctx context.Context, caller account.Caller) (auditops.RetentionInfo, error)
	ListExports(ctx context.Context, request auditops.ExportListRequest) ([]auditops.ExportView, bool, error)
	GetExport(ctx context.Context, caller account.Caller, exportID string) (auditops.ExportView, error)
	StartExport(ctx context.Context, request auditops.StartExportRequest) (auditops.ExportView, error)
	CancelExport(ctx context.Context, caller account.Caller, exportID, reason, requestID string) (task.CancelResult, error)
	OpenExportFile(ctx context.Context, caller account.Caller, exportID string) (auditops.ExportFile, error)
	ListPurgeRuns(ctx context.Context, request auditops.PurgeListRequest) ([]auditops.PurgeRunView, bool, error)
	GetPurgeRun(ctx context.Context, caller account.Caller, runID string) (auditops.PurgeRunView, error)
	PreviewPurge(ctx context.Context, request auditops.PurgePreviewRequest) (auditops.PurgePreview, error)
	StartPurge(ctx context.Context, request auditops.StartPurgeRequest) (auditops.PurgeRunView, error)
	CancelPurge(ctx context.Context, caller account.Caller, runID, reason, requestID string) (task.CancelResult, error)
	SetRetention(ctx context.Context, request auditops.SetRetentionRequest) (auditops.RetentionInfo, error)
}

// ReportService 是本包使用的报告服务子集；生产实现是 *reports.Service。
type ReportService interface {
	HistoryList(ctx context.Context, request reports.HistoryListRequest) (reports.HistoryListView, error)
	Get(ctx context.Context, caller account.Caller, reportID string) (reports.ReportView, error)
	GetSnapshot(ctx context.Context, caller account.Caller, reportID string) (reports.Snapshot, error)
	IssueDownloadTicket(ctx context.Context, caller account.Caller, reportID string, format reports.Format) (reports.DownloadTicket, error)
	RedeemDownloadTicket(ctx context.Context, caller account.Caller, token string) (reports.ArtifactFile, error)
	Cancel(ctx context.Context, caller account.Caller, reportID, reason, requestID string) (task.CancelResult, error)
	Retry(ctx context.Context, caller account.Caller, reportID, reason, requestID string) (reports.ReportView, error)
	CleanupPreview(ctx context.Context, caller account.Caller) (reports.CleanupPreview, error)
	CleanupExecute(ctx context.Context, request reports.CleanupExecuteRequest) (reports.CleanupResult, error)
}

// ReportPlanService 是本包使用的报告计划服务子集；生产实现是
// *reports.PlanService。计划写入的权限（reports.schedule.manage）、审计与
// 行版本冲突由 PlanService 判定；强认证由本包注入的 Sensitive 另行要求。
type ReportPlanService interface {
	List(ctx context.Context, caller account.Caller) ([]reports.PlanView, error)
	Get(ctx context.Context, caller account.Caller, planID string) (reports.PlanView, error)
	Create(ctx context.Context, request reports.PlanCreateRequest) (reports.PlanView, error)
	Update(ctx context.Context, request reports.PlanUpdateRequest) (reports.PlanView, error)
	SetEnabled(ctx context.Context, caller account.Caller, planID string,
		enable bool, reason, requestID string) (reports.PlanView, error)
	DeletePreview(ctx context.Context, caller account.Caller, planID string) (reports.PlanDeletePreview, error)
	Delete(ctx context.Context, caller account.Caller, planID, reason, requestID string) error
}

// BackupService 是本包使用的备份在线服务子集；生产实现是
// *backupadmin.Service。
type BackupService interface {
	CheckReadAccess(ctx context.Context, caller account.Caller) error
	Capabilities(ctx context.Context, caller account.Caller) (backupadmin.Capabilities, error)
	ListArtifacts(ctx context.Context, caller account.Caller, filter backupadmin.ArtifactFilter) ([]backupadmin.ArtifactView, bool, error)
	GetArtifact(ctx context.Context, caller account.Caller, backupID string) (backupadmin.ArtifactView, error)
	ListJobs(ctx context.Context, caller account.Caller, filter backupadmin.JobFilter) ([]backupadmin.JobView, bool, error)
	GetJob(ctx context.Context, caller account.Caller, jobID string) (backupadmin.JobView, error)
	EnqueueBackup(ctx context.Context, caller account.Caller, requestID string) (backupadmin.JobRef, error)
	CancelJob(ctx context.Context, caller account.Caller, jobID, reason, requestID string) (backupadmin.CancelView, error)
	IssueDownloadTicket(ctx context.Context, caller account.Caller, backupID, requestID string) (backupadmin.DownloadTicket, error)
	RedeemDownloadTicket(ctx context.Context, caller account.Caller, token, requestID string) (backupadmin.DownloadFile, error)
	Retention(ctx context.Context, caller account.Caller) (backupadmin.RetentionView, error)
	SaveRetention(ctx context.Context, change backupadmin.RetentionChange) (backupadmin.RetentionView, error)
	CleanupPreview(ctx context.Context, caller account.Caller) (backupadmin.CleanupPreview, error)
	EnqueueCleanup(ctx context.Context, caller account.Caller, requestID string) (backupadmin.JobRef, error)
	ListSchedules(ctx context.Context, caller account.Caller) ([]backupadmin.ScheduleView, error)
	GetSchedule(ctx context.Context, caller account.Caller, scheduleID string) (backupadmin.ScheduleView, error)
	CreateSchedule(ctx context.Context, request backupadmin.ScheduleRequest) (backupadmin.ScheduleView, error)
	UpdateSchedule(ctx context.Context, scheduleID string, request backupadmin.ScheduleRequest) (backupadmin.ScheduleView, error)
	SetScheduleEnabled(ctx context.Context, caller account.Caller, scheduleID string,
		enabled bool, reason, requestID string) (backupadmin.ScheduleView, error)
	DeleteSchedule(ctx context.Context, caller account.Caller, scheduleID, reason, requestID string) error
}

// AuditRecorder 是管理 API 自身动作的最小审计写入契约；生产实现是
// *audit.Recorder（fail-closed）。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
}

// NotificationStatus 是脱敏的通知配置/启用状态：只暴露是否存在可用投递通道、
// 是否本地捕获、渠道键与说明，不包含 SMTP 主机、账号、密钥或收件地址原文。
type NotificationStatus struct {
	Enabled      bool     `json:"enabled"`
	LocalCapture bool     `json:"local_capture"`
	Channels     []string `json:"channels,omitempty"`
	DeliveryMode string   `json:"delivery_mode"`
	Note         string   `json:"note,omitempty"`
	// TLSMode/FromDomain/AppName/DeliveryCounts/LastErrorCodes 是步骤 139 的
	// 脱敏聚合扩展：只暴露 TLS 模式、发件域名、品牌名与计数/错误码，不含
	// 完整地址、账号、密码、正文或收件人。
	TLSMode        string         `json:"tls_mode,omitempty"`
	FromDomain     string         `json:"from_domain,omitempty"`
	AppName        string         `json:"app_name,omitempty"`
	DeliveryCounts map[string]int `json:"delivery_counts,omitempty"`
	LastErrorCodes []string       `json:"last_error_codes,omitempty"`
}

// NotificationTestResult 是本地捕获测试的摘要：只返回捕获编号、渠道键、脱敏
// 接收者与时间，不返回正文、密钥或真实地址。
type NotificationTestResult struct {
	CaptureID       string    `json:"capture_id"`
	Channel         string    `json:"channel"`
	RecipientMasked string    `json:"recipient_masked,omitempty"`
	CapturedAt      time.Time `json:"captured_at"`
	Note            string    `json:"note,omitempty"`
}

// NotificationService 是宿主注入的通知读取/本地捕获测试契约。
//
// 安全约束（实现必须遵守）：
//   - NotificationStatus 只返回脱敏配置；不得读取或返回秘密。
//   - TestNotification 只允许投递到本地捕获器（内存队列/测试目录），禁止真实
//     外发邮件/Webhook；必须按 caller 重新检查通知配置读取权限，并自行在
//     捕获/审计中避免写入收件地址原文。本包另外要求 confirm、敏感策略与真实
//     审计，三者缺一即拒绝。
type NotificationService interface {
	NotificationStatus(ctx context.Context, caller account.Caller) (NotificationStatus, error)
	TestNotification(ctx context.Context, caller account.Caller, requestID string) (NotificationTestResult, error)
}

// TaskReader 是任务只读查询契约；生产实现是 *task.Executor（Get/Attempts）。
type TaskReader interface {
	Get(ctx context.Context, id string) (task.Job, error)
	Attempts(ctx context.Context, id string) ([]task.Attempt, error)
}

// TaskAuthorizer 判定当前管理会话能否读取指定任务（防止仅凭"可管理会话"读取
// 任意任务元数据的 IDOR）。
//
// 生产实现必须同时检查：
//  1. 功能权限：任务详情属于运行诊断信息，建议使用既有 diagnostics.read 权限键；
//     不得只检查"是管理会话"；
//  2. 数据范围/属主：调用者是任务发起者（job.Initiator.ID），或具备覆盖该任务
//     所属作用范围的管理诊断数据范围；
//  3. 依赖失败/无法证明范围时一律拒绝（fail-closed）。
//
// 返回错误时本包统一返回 403 ACCESS_DENIED，不区分"不存在"与"无权"，避免枚举。
type TaskAuthorizer interface {
	AuthorizeTaskRead(ctx context.Context, caller account.Caller, job task.Job) error
}

// Options 是管理 API 的显式依赖。所有资源由宿主拥有；本包不启动协程、不监听
// 端口、不写数据库（业务写入全部经领域服务）。
type Options struct {
	// BasePath 是固定挂载前缀，默认 DefaultBasePath；不允许尾斜杠。
	BasePath string
	// Version 是 API 版本字符串，默认 "v1"，只随响应返回，不参与路由匹配。
	Version string
	// Session 是管理会话边界；必填。
	Session ManagementSession
	// ErrorCodes 是根包错误码注册表投影；必填，且必须包含本包会返回的全部码。
	ErrorCodes []ErrorCodeInfo
	// Audit 为空时审计路由不挂载。
	Audit AuditService
	// Reports 为空时报告路由不挂载。
	Reports ReportService
	// Plans 为空时报告计划只读路由不挂载。
	Plans ReportPlanService
	// Backups 为空时备份路由不挂载。
	Backups BackupService
	// Tasks 为空时任务只读路由不挂载。
	Tasks TaskReader
	// TaskAuthorizer 是任务详情权限/数据范围判定；为空时任务路由不挂载
	// （fail-closed，绝不以"管理会话"代替任务读取授权）。
	TaskAuthorizer TaskAuthorizer
	// Sensitive 是管理 API 自身写操作（计划写入、通知测试等领域服务未内置
	// reauth 的动作）的敏感策略入口；为空时这些端点 fail-closed（403
	// REAUTH_REQUIRED），不会退化为只查权限。
	Sensitive reauth.OperationRunner
	// AuditRecorder 是管理 API 自身动作（通知测试）的真实审计写入器；为空时
	// 通知测试 fail-closed（审计不可用拒绝关键操作）。生产实现是 *audit.Recorder。
	AuditRecorder AuditRecorder
	// DomainRoutes 是宿主补充的领域管理路由（用户/组/角色/应用/客服等）。
	// 每个处理器必须自行调用真实领域服务与授权器；本包只负责 session/CSRF/
	// envelope/错误码映射与路径参数解析。
	DomainRoutes []DomainRoute
	// Notifications 是宿主注入的通知读取/本地捕获测试实现；为空时通知读取返回
	// MAIL_DIAGNOSTICS_UNAVAILABLE、测试返回 NOTIFICATION_TEST_DISABLED。
	Notifications NotificationService
	// Logger 是运行日志器；nil 时不写日志。
	Logger *slog.Logger
	// Now 是可注入时钟；nil 使用 time.Now。
	Now func() time.Time
	// MaxBodyBytes 是请求体上限；0 使用默认值。
	MaxBodyBytes int64
	// RequestTimeout 是单请求处理期限；0 使用默认值。
	RequestTimeout time.Duration
	// NewRequestID 生成请求编号；nil 使用内部加密随机编号。
	NewRequestID func() string
}

// Server 是管理 JSON API 处理器：构造后不可变、可并发使用。
type Server struct {
	basePath       string
	version        string
	session        ManagementSession
	sessionRevoker SessionAdminRevoker
	audit          AuditService
	reports        ReportService
	plans          ReportPlanService
	backups        BackupService
	tasks          TaskReader
	taskAuthorizer TaskAuthorizer
	sensitive      reauth.OperationRunner
	auditRecorder  AuditRecorder
	notifications  NotificationService
	domainRoutes   []DomainRoute
	logger         *slog.Logger
	now            func() time.Time
	maxBodyBytes   int64
	requestTimeout time.Duration
	newRequestID   func() string
	codes          map[string]ErrorCodeInfo
	routes         []route
}

// New 校验依赖并构造管理 API。缺少会话或错误码投影、配置越界时拒绝构造，
// 没有“默认放行”或“稍后补鉴权”的降级路径。
func New(options Options) (*Server, error) {
	basePath, err := normalizeBasePath(options.BasePath)
	if err != nil {
		return nil, err
	}
	if isNil(options.Session) {
		return nil, fmt.Errorf("%w: 管理会话边界为空", ErrOptionsInvalid)
	}
	if len(options.ErrorCodes) == 0 {
		return nil, fmt.Errorf("%w: 错误码投影为空", ErrOptionsInvalid)
	}
	codes := make(map[string]ErrorCodeInfo, len(options.ErrorCodes))
	for _, info := range options.ErrorCodes {
		if strings.TrimSpace(info.Code) == "" {
			return nil, fmt.Errorf("%w: 错误码投影包含空码", ErrOptionsInvalid)
		}
		if info.HTTPStatus != 0 && (info.HTTPStatus < 400 || info.HTTPStatus > 599) {
			return nil, fmt.Errorf("%w: 错误码 %s 的 HTTP 状态越界", ErrOptionsInvalid, info.Code)
		}
		if _, exists := codes[info.Code]; exists {
			return nil, fmt.Errorf("%w: 错误码投影重复 %s", ErrOptionsInvalid, info.Code)
		}
		codes[info.Code] = info
	}
	// 传输层固定响应码必须存在，避免返回未登记码。
	for _, required := range []string{"REQ_INVALID", "AUTH_FAILED", "ACCESS_DENIED", "REAUTH_REQUIRED", "CONFLICT", "INTERNAL_ERROR"} {
		if _, ok := codes[required]; !ok {
			return nil, fmt.Errorf("%w: 错误码投影缺少 %s", ErrOptionsInvalid, required)
		}
	}
	maxBodyBytes := options.MaxBodyBytes
	if maxBodyBytes == 0 {
		maxBodyBytes = DefaultMaxBodyBytes
	}
	if maxBodyBytes < 1 || maxBodyBytes > MaxMaxBodyBytes {
		return nil, fmt.Errorf("%w: 请求体上限越界", ErrOptionsInvalid)
	}
	timeout := options.RequestTimeout
	if timeout == 0 {
		timeout = DefaultRequestTimeout
	}
	if timeout < MinRequestTimeout || timeout > MaxRequestTimeout {
		return nil, fmt.Errorf("%w: 请求处理期限越界", ErrOptionsInvalid)
	}
	version := strings.TrimSpace(options.Version)
	if version == "" {
		version = "v1"
	}
	if len(version) > 32 {
		return nil, fmt.Errorf("%w: API 版本字符串过长", ErrOptionsInvalid)
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	newRequestID := options.NewRequestID
	if newRequestID == nil {
		newRequestID = defaultRequestID
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard,
			&slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	server := &Server{
		basePath:       basePath,
		version:        version,
		session:        options.Session,
		audit:          options.Audit,
		reports:        options.Reports,
		plans:          options.Plans,
		backups:        options.Backups,
		tasks:          options.Tasks,
		taskAuthorizer: options.TaskAuthorizer,
		sensitive:      options.Sensitive,
		auditRecorder:  options.AuditRecorder,
		notifications:  options.Notifications,
		domainRoutes:   append([]DomainRoute(nil), options.DomainRoutes...),
		logger:         logger,
		now:            now,
		maxBodyBytes:   maxBodyBytes,
		requestTimeout: timeout,
		newRequestID:   newRequestID,
		codes:          codes,
	}
	if revoker, ok := options.Session.(SessionAdminRevoker); ok {
		server.sessionRevoker = revoker
	}
	server.routes = server.buildRoutes()
	if len(server.routes) == 0 {
		return nil, fmt.Errorf("%w: 没有可挂载的路由（至少需要审计、报告、备份或任务服务之一）",
			ErrOptionsInvalid)
	}
	return server, nil
}

// BasePath 返回规范化后的挂载前缀。
func (s *Server) BasePath() string { return s.basePath }

// Version 返回 API 版本字符串。
func (s *Server) Version() string { return s.version }

// ErrorCodeStatus 返回本服务投影中指定错误码的 HTTP 状态；未投影时返回 false。
// 供宿主文档与一致性测试使用，不返回内部错误对象。
func (s *Server) ErrorCodeStatus(code string) (int, bool) {
	info, ok := s.codes[code]
	if !ok {
		return 0, false
	}
	return info.HTTPStatus, true
}

// normalizeBasePath 校验并规范化挂载前缀：必须是以单个斜杠开头的固定段序列，
// 不允许尾斜杠、空段、点段、反斜杠或百分号编码（前缀是路由权限的一部分）。
func normalizeBasePath(raw string) (string, error) {
	path := strings.TrimSpace(raw)
	if path == "" {
		path = DefaultBasePath
	}
	if len(path) > MaxBasePathBytes {
		return "", fmt.Errorf("%w: 挂载前缀过长", ErrOptionsInvalid)
	}
	if !strings.HasPrefix(path, "/") || path == "/" || strings.HasSuffix(path, "/") {
		return "", fmt.Errorf("%w: 挂载前缀格式无效", ErrOptionsInvalid)
	}
	if strings.ContainsAny(path, "\\%?#") || strings.Contains(path, "//") {
		return "", fmt.Errorf("%w: 挂载前缀包含不允许的字符", ErrOptionsInvalid)
	}
	for _, segment := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", fmt.Errorf("%w: 挂载前缀包含空段或点段", ErrOptionsInvalid)
		}
	}
	return path, nil
}

// defaultRequestID 生成不可预测的请求编号；请求编号只用于关联与排障，不是凭证。
func defaultRequestID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	return "req_" + hex.EncodeToString(raw[:])
}
