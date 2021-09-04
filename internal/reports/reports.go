// Package reports 实现基于固定统计快照的报告生成与结构化数据导出（步骤 77）。
//
// 它复用 internal/stats 的可重复计算统计结果，不复制看板截图、不重新计算另一套
// 数字：一次生成只取一个规范化窗口与一个统计截止点，图表、汇总与明细都来自同一
// 快照对象；后续 PDF/Markdown（步骤 78）与定期报告（步骤 79）可在此模型上扩展。
//
// 安全不变量：
//   - 每次生成/查看/下载/取消都由服务端重新授权并重新检查当前数据范围是否仍覆盖
//     生成时快照；权限撤销后旧产物不可下载，不因“曾有权生成”而永久公开。
//   - 查看（reports.read）、生成（reports.generate）与导出（reports.export）分开
//     授权；生成与导出还要求敏感操作确认（reports.export 策略，强认证）。
//   - 统计数据由注入的 Source 提供，生产实现是 *stats.Service，其自身按调用者授权
//     并在存储层裁剪数据范围；本包不把范围之外的明细写进报告。
//   - 报告只含聚合统计与受控明细字段，不导出原始审计全量记录、内部原因码、凭证或
//     秘密；HTML 不写隐藏字段、不嵌入原始事件，图与表同源。
//   - 产物写入宿主受控目录：服务端文件名、O_EXCL、0600、字节上限、SHA-256 与
//     大小记录，失败/取消删除临时产物；下载再次校验摘要，文件路径不进入公开视图。
//   - 异步生成复用 internal/task：提交成功只表示已受理，查询返回真实任务状态，
//     取消请求与实际取消分开；本包不启动常驻协程、不提供 HTTP 路由。
package reports

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// 权限键复用 internal/preset 已登记的 reports.read / reports.generate /
// reports.export，不新增权限。
const (
	// PermissionRead 是查看报告元数据/预览的权限。
	PermissionRead = "reports.read"
	// PermissionGenerate 是生成报告的权限。
	PermissionGenerate = "reports.generate"
	// PermissionExport 是导出报告产物（文件下载）的权限。
	PermissionExport = "reports.export"
	// OperationExport 是 internal/policy 敏感操作 ID（强认证+确认）；本步骤在
	// internal/policy 目录登记该操作，不新增权限键或错误码。
	OperationExport = "reports.export"
	// TaskKindReportGenerate 是投递到 internal/task 的稳定任务类型。
	TaskKindReportGenerate = "reports.generate"
)

// 审计动作稳定标识。
const (
	ActionGenerateRequest = "reports.generate.request"
	ActionGenerateFinish  = "reports.generate.finish"
	ActionGenerateCancel  = "reports.generate.cancel"
	// ActionExportDownload 是受控报告产物下载（成功与拒绝都记录，属敏感导出面）。
	ActionExportDownload = "reports.export.download"
	// ActionExportSnapshot 是机器可读快照读取（与 JSON 产物等价，属敏感导出面）。
	ActionExportSnapshot = "reports.export.snapshot"
	ActionAccessDenied   = "reports.access.denied"
)

// 报告状态枚举。取消请求不是终态；真实终态以任务状态收敛。
const (
	StateQueued    = "queued"
	StateRunning   = "running"
	StateSucceeded = "succeeded"
	StateFailed    = "failed"
	StateCancelled = "cancelled"
)

// 报告与快照的稳定版本标识。模板版本变化必须提升 TemplateVersion，机器可读
// SchemaVersion 只在字段语义不兼容时提升；两者都写入每份报告。
const (
	// SchemaVersion 是 JSON/CSV 机器可读结构版本。
	SchemaVersion = "report.v1"
	// TemplateVersion 是 HTML 模板与固定章节版本。
	TemplateVersion = 1
	// timeFormat 是报告中所有时间字段的格式声明（UTC）。
	timeFormat = "RFC3339_UTC"
)

// ScopeSystem 是系统范围稳定 ID。
const ScopeSystem = "system"

// 边界常量。超出硬上限一律拒绝，不静默截断。
const (
	// DefaultDetailRows/MaxDetailRows 是报告明细（错误行）条数边界；与统计服务
	// 单页上限一致，不把报告变成全量导出通道。
	DefaultDetailRows = 200
	MaxDetailRows     = stats.MaxErrorLimit
	// DefaultArtifactBytes/MaxArtifactBytes 是单个受控产物字节上限。
	DefaultArtifactBytes = 8 * 1024 * 1024
	MaxArtifactBytes     = 64 * 1024 * 1024
	// DefaultArtifactTTL 是产物默认可用期（24 小时）；清理属于独立保留策略，
	// 本步骤只标记过期，不删除文件。
	DefaultArtifactTTL = 24 * time.Hour
	// reportTaskTimeoutSeconds 是异步生成任务默认墙钟上限（10 分钟）。
	reportTaskTimeoutSeconds = 600
	// MaxReasonBytes 是取消原因上限。
	MaxReasonBytes = 256
	// reportIDPrefix/reportFilePrefix 是报告编号与受控产物文件名前缀。
	reportIDPrefix   = "rpt_"
	reportFilePrefix = "report_"
	// idRandomBytes 是编号随机字节数（128 位）。
	idRandomBytes = 16
)

// 领域错误哨兵；CodeOf 映射到根包既有错误码，不新增注册码。
var (
	ErrOptionsInvalid   = errors.New("报告服务配置无效")
	ErrInvalidRequest   = errors.New("报告请求无效")
	ErrAccessDenied     = errors.New("未获准执行该报告操作")
	ErrNotFound         = errors.New("报告不存在")
	ErrConflict         = errors.New("报告状态或产物冲突")
	ErrStoreUnavailable = errors.New("报告存储暂时不可用")
	ErrAuditUnavailable = errors.New("关键操作未能可靠记录")
	ErrArtifactUnsafe   = errors.New("报告产物不安全或已损坏")
	ErrTaskRejected     = errors.New("报告任务未能可靠提交")
	ErrTaskTerminal     = errors.New("报告任务已结束")
)

// ErrorCode 是本领域对根包错误码注册表的投影（全部复用既有码）。
type ErrorCode string

const (
	CodeReqInvalid         ErrorCode = "REQ_INVALID"
	CodeAccessDenied       ErrorCode = "ACCESS_DENIED"
	CodeConflict           ErrorCode = "CONFLICT"
	CodeDBUnavailable      ErrorCode = "DB_UNAVAILABLE"
	CodeAuditWriteFailed   ErrorCode = "AUDIT_WRITE_FAILED"
	CodeExportPathUnsafe   ErrorCode = "EXPORT_PATH_UNSAFE"
	CodeReportAccessDenied ErrorCode = "REPORT_ACCESS_DENIED"
	CodeReportGeneration   ErrorCode = "REPORT_GENERATION_FAILED"
	CodeTaskCancelled      ErrorCode = "TASK_CANCELLED"
	CodeTaskTimeout        ErrorCode = "TASK_TIMEOUT"
	CodeInternalError      ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把报告域错误映射为根包已登记错误码。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrOptionsInvalid), errors.Is(err, ErrInvalidRequest):
		return CodeReqInvalid
	case errors.Is(err, ErrAccessDenied):
		return CodeAccessDenied
	case errors.Is(err, ErrNotFound):
		return CodeReqInvalid
	case errors.Is(err, ErrConflict), errors.Is(err, ErrTaskTerminal):
		return CodeConflict
	case errors.Is(err, ErrArtifactUnsafe):
		return CodeExportPathUnsafe
	case errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	case errors.Is(err, ErrTaskRejected):
		return CodeDBUnavailable
	default:
		return CodeInternalError
	}
}

// Format 是报告产物格式。本步骤实现 HTML/CSV/JSON；PDF/Markdown 属步骤 78。
type Format string

const (
	// FormatHTML 是自包含离线 HTML 报告（内联样式与 SVG，无外部资源）。
	FormatHTML Format = "html"
	// FormatCSV 是结构化统计数据导出（UTF-8、防公式注入、正确引号/换行）。
	FormatCSV Format = "csv"
	// FormatJSON 是稳定 schema 的机器可读快照导出（数值为 JSON 数字）。
	FormatJSON Format = "json"
)

// Valid 报告格式是否已定义。
func (f Format) Valid() bool {
	return f == FormatHTML || f == FormatCSV || f == FormatJSON
}

// Authorizer 与 RootChecker 复用统计服务的授权契约，确保装配层只有一套数据范围
// 语义；实现必须 fail-closed。
type Authorizer = stats.Authorizer

// RootChecker 判定可信调用者是否为 root；缺失/失败按非 root 处理。
type RootChecker = stats.RootChecker

// SensitiveRunner 是敏感操作执行前校验（生产 *reauth.Service）。
type SensitiveRunner = reauth.OperationRunner

// AuditRecorder 是安全审计写入契约；实现必须 fail-closed。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// Enqueuer 是任务入队契约（生产 *task.Executor）。
type Enqueuer interface {
	Enqueue(ctx context.Context, request task.EnqueueRequest) (task.Job, error)
}

// Canceller 是任务取消契约（生产 *task.Executor）。
type Canceller interface {
	RequestCancel(ctx context.Context, request task.CancelRequest) (task.CancelResult, error)
}

// TaskReader 是任务状态读取契约（可选）。签名与 *task.Executor.Get 完全一致，
// 生产 Executor 可直接注入；任务不存在时返回错误，视图按“无摘要”处理。
type TaskReader interface {
	Get(ctx context.Context, id string) (task.Job, error)
}

// Source 是统计事实来源。生产实现为 *stats.Service（按调用者重新授权并裁剪数据
// 范围）；测试可用明确标注的替身验证渲染与产物语义，替身不进入生产装配。
type Source interface {
	Activity(ctx context.Context, request stats.ActivityRequest) (stats.ActivityResult, error)
	Errors(ctx context.Context, request stats.ErrorRequest) (stats.ErrorResult, error)
	ErrorTrend(ctx context.Context, request stats.ErrorTrendRequest) (stats.ErrorTrendResult, error)
}

// Options 是报告服务依赖与边界。Source/Authorizer/Root/Sensitive/Audit/Enqueuer/
// Canceller/OutputDir 缺失时拒绝构造（fail-closed）；默认不放行、不使用替身。
type Options struct {
	Source     Source
	Authorizer Authorizer
	Root       RootChecker
	Sensitive  SensitiveRunner
	Audit      AuditRecorder
	Enqueuer   Enqueuer
	Canceller  Canceller
	// Tasks 可选：提供后报告视图附带真实任务状态摘要。
	Tasks TaskReader
	// OutputDir 是报告产物受控目录（绝对路径、已存在、非符号链接）；必填。
	OutputDir string
	// MaxDetailRows/MaxArtifactBytes 是明细条数/单产物字节上限；0 使用默认值，
	// 超过硬上限拒绝构造。
	MaxDetailRows    int
	MaxArtifactBytes int64
	// ArtifactTTL 是产物默认可用期；0 使用 24 小时。
	ArtifactTTL time.Duration
	Now         func() time.Time
	Random      io.Reader
	Logger      *slog.Logger
}

// Service 是报告生成服务：构造后不可变、可并发使用；不启动协程、不提供 HTTP
// 路由。异步生成由宿主把 GenerateHandler 注册到 internal/task。
//
// 即时报告的记录保存在进程内存中，供任务完成后按编号查询结果/失败/取消；
// 历史列表、持久化与定期计划属于步骤 79，不在本步骤伪造成已完成。
type Service struct {
	opts             Options
	maxDetailRows    int
	maxArtifactBytes int64
	artifactTTL      time.Duration
	outputDir        string

	mu      sync.Mutex
	records map[string]*reportRecord
}

// New 校验依赖与边界并构造服务。
func New(options Options) (*Service, error) {
	if isNil(options.Source) || isNil(options.Authorizer) || isNil(options.Root) ||
		isNil(options.Sensitive) || isNil(options.Audit) || isNil(options.Enqueuer) ||
		isNil(options.Canceller) {
		return nil, fmt.Errorf("%w: 报告服务必需依赖缺失", ErrOptionsInvalid)
	}
	// 可选依赖也拒绝 typed-nil：接口非 nil 但底层指针为 nil 时调用会 panic。
	if options.Tasks != nil && isNil(options.Tasks) {
		return nil, fmt.Errorf("%w: 任务读取依赖为 typed-nil", ErrOptionsInvalid)
	}
	maxDetailRows := options.MaxDetailRows
	if maxDetailRows == 0 {
		maxDetailRows = DefaultDetailRows
	}
	if maxDetailRows < 1 || maxDetailRows > MaxDetailRows {
		return nil, fmt.Errorf("%w: 明细条数上限超出范围", ErrOptionsInvalid)
	}
	maxArtifactBytes := options.MaxArtifactBytes
	if maxArtifactBytes == 0 {
		maxArtifactBytes = DefaultArtifactBytes
	}
	if maxArtifactBytes < 1 || maxArtifactBytes > MaxArtifactBytes {
		return nil, fmt.Errorf("%w: 单产物字节上限超出范围", ErrOptionsInvalid)
	}
	artifactTTL := options.ArtifactTTL
	if artifactTTL == 0 {
		artifactTTL = DefaultArtifactTTL
	}
	if artifactTTL < time.Minute || artifactTTL > 30*24*time.Hour {
		return nil, fmt.Errorf("%w: 产物可用期超出范围", ErrOptionsInvalid)
	}
	if options.OutputDir == "" {
		return nil, fmt.Errorf("%w: 报告能力必须配置受控输出目录", ErrOptionsInvalid)
	}
	absolute, err := filepath.Abs(options.OutputDir)
	if err != nil {
		return nil, fmt.Errorf("%w: 报告目录无效", ErrOptionsInvalid)
	}
	info, statErr := os.Lstat(absolute)
	if statErr != nil || !info.IsDir() {
		return nil, fmt.Errorf("%w: 报告目录必须是已存在的目录", ErrOptionsInvalid)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: 报告目录不能是符号链接", ErrOptionsInvalid)
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Service{opts: options, maxDetailRows: maxDetailRows,
		maxArtifactBytes: maxArtifactBytes, artifactTTL: artifactTTL,
		outputDir: absolute, records: make(map[string]*reportRecord)}, nil
}

// now 返回截断到 UTC 毫秒的当前时刻。
func (s *Service) now() time.Time { return s.opts.Now().UTC().Truncate(time.Millisecond) }

// newID 生成带前缀的 128 位随机编号。
func (s *Service) newID(prefix string) (string, error) {
	buffer := make([]byte, idRandomBytes)
	if _, err := io.ReadFull(s.opts.Random, buffer); err != nil {
		return "", fmt.Errorf("%w: 无法生成报告编号", ErrInvalidRequest)
	}
	return prefix + hex.EncodeToString(buffer), nil
}

// callerFromActor 把可信审计身份还原为调用者，用于异步任务重新授权；匿名拒绝。
func callerFromActor(actor audit.Actor) (account.Caller, error) {
	switch actor.Type {
	case audit.ActorUser:
		return account.UserCaller(actor.ID)
	case audit.ActorSystem:
		return account.SystemCaller(actor.ID)
	case audit.ActorLocalAdmin:
		return account.LocalBootstrapCaller(actor.ID)
	default:
		return account.Caller{}, ErrAccessDenied
	}
}

// dataScope 是生成时读取数据范围的不可变快照，用于执行与下载时判断当前权限
// 是否仍覆盖当时范围（权限收缩后不因曾有权限而永久可下载）。
type dataScope struct {
	All       bool
	Resources []string
}

// scopeGrant 判定调用者在作用范围的权限与数据范围；root 走受保护通道。
// 拒绝会写失败审计（不改变拒绝结论）。
func (s *Service) authorizeScope(ctx context.Context, caller account.Caller,
	permissionKey, scopeID string) (stats.ScopeGrant, error) {
	actor := caller.Actor()
	if err := actor.Validate(); err != nil {
		return stats.ScopeGrant{}, ErrAccessDenied
	}
	if s.isRoot(ctx, caller) {
		return stats.ScopeGrant{Allowed: true, AllData: true}, nil
	}
	grant, err := s.opts.Authorizer.AuthorizeScope(ctx, caller, permissionKey, scopeID)
	if err != nil {
		s.recordDenied(ctx, actor, scopeID, permissionKey, "authorizer_unavailable")
		return stats.ScopeGrant{}, fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	if !grant.Allowed {
		s.recordDenied(ctx, actor, scopeID, permissionKey, "not_granted")
		return stats.ScopeGrant{}, ErrAccessDenied
	}
	return grant, nil
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

// recordDenied 写一条报告操作拒绝审计；写入失败只告警，不改变拒绝结论。
func (s *Service) recordDenied(ctx context.Context, actor audit.Actor, scopeID,
	permissionKey, reason string) {
	err := s.opts.Audit.RecordFailure(ctx, audit.Event{
		Actor: actor, AppID: appIDForScope(scopeID), Action: ActionAccessDenied,
		Target:  audit.Target{Type: "report", ID: safeToken(permissionKey)},
		Outcome: audit.OutcomeDenied, ErrorCode: string(CodeAccessDenied),
		ReasonCode: safeToken(reason),
	})
	if err != nil {
		s.opts.Logger.Error("报告拒绝审计写入失败", "code", string(CodeAuditWriteFailed))
	}
}

// recordFailure 记录生成/取消失败审计；写入失败只告警。
func (s *Service) recordFailure(ctx context.Context, actor audit.Actor, action, scopeID,
	reason string, code ErrorCode, requestID, reportID string) {
	err := s.opts.Audit.RecordFailure(ctx, audit.Event{
		Actor: actor, AppID: appIDForScope(scopeID), Action: action,
		Target:  audit.Target{Type: "report", ID: safeToken(reportID)},
		Outcome: audit.OutcomeFailure, ErrorCode: string(code),
		ReasonCode: safeToken(reason), RequestID: requestID,
	})
	if err != nil {
		s.opts.Logger.Error("报告失败审计写入失败", "code", string(CodeAuditWriteFailed))
	}
}

// appIDForScope 把作用范围转换为审计事件的应用归属（系统范围为空白）。
func appIDForScope(scopeID string) string {
	if scopeID == ScopeSystem {
		return ""
	}
	return scopeID
}

// grantCovers 判断当前授权是否仍覆盖生成时数据范围。
func (s *Service) grantCovers(recorded dataScope, grant stats.ScopeGrant) bool {
	if grant.AllData {
		return true
	}
	if recorded.All {
		return false
	}
	for _, resource := range recorded.Resources {
		if !containsString(grant.ResourceIDs, resource) {
			return false
		}
	}
	return true
}

// containsString 报告字符串切片是否包含指定值。
func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// normalizeRequestID 只保留合法请求编号。可信边界已校验业务请求编号，但调用方
// 可能把非法编号带入审计/任务事件；审计与任务会拒绝非法编号导致留痕丢失，因此
// 这里把非法值归一为空（不改变业务结论，也不伪造编号）。
func normalizeRequestID(requestID string) string {
	if requestID == "" {
		return ""
	}
	if err := account.ValidateRequestID(requestID); err != nil {
		return ""
	}
	return requestID
}

// safeToken 把内部原因限制为稳定短标记（ASCII 可见），不写原始错误。
func safeToken(value string) string {
	var builder strings.Builder
	for index := 0; index < len(value) && builder.Len() < 64; index++ {
		c := value[index]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' {
			builder.WriteByte(c)
		}
	}
	return builder.String()
}

// safeReason 把失败/取消说明限制为安全短文本（无控制字符），不保存堆栈或秘密。
func safeReason(reason string) string {
	var builder strings.Builder
	for _, character := range reason {
		if character < 0x20 || character == 0x7f {
			continue
		}
		builder.WriteRune(character)
		if builder.Len() >= MaxReasonBytes {
			break
		}
	}
	return strings.TrimSpace(builder.String())
}

// validateReason 校验取消原因：必填、合法 UTF-8、无控制字符、长度受限。
func validateReason(reason string) error {
	if reason == "" {
		return fmt.Errorf("%w: 原因不能为空", ErrInvalidRequest)
	}
	if len(reason) > MaxReasonBytes {
		return fmt.Errorf("%w: 原因超过 %d 字节", ErrInvalidRequest, MaxReasonBytes)
	}
	for _, character := range reason {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("%w: 原因不能包含控制字符", ErrInvalidRequest)
		}
	}
	return nil
}

// isNil 判断接口/指针依赖是否为空（含 typed-nil）。
func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func:
		return reflected.IsNil()
	default:
		return false
	}
}
