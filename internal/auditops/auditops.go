// Package auditops 实现安全审计记录的读取、受控导出与保留期清理（步骤 73）。
//
// 它是后续审计页面、错误诊断页面与统计报告使用的可靠数据入口，不是第二套审计
// 写入实现：事件仍由 internal/audit 记录，本包只读取、导出与按保留策略清理。
//
// 安全不变量：
//   - 每次读取/导出/清理都由服务端重新授权：普通用户只能查看本人安全活动；管理
//     查询必须有 audit.read；导出必须有独立的 audit.export 与敏感操作校验；清理
//     必须同时满足 root、audit.purge 敏感策略与显式截止时间。
//   - 数据范围在存储层限制：服务层把授权得到的数据范围转换为 SQL WHERE 条件，
//     不会先读取全系统事件再在内存过滤。
//   - 筛选/排序/分页全部白名单化：不接受自由 SQL、任意列排序或未登记枚举；分页
//     用“时间 + 事件 ID”稳定排序并多取一条判定 HasMore，不伪造总数。
//   - 导出单独授权、字段白名单、脱敏（差异值沿用写入期 [REDACTED]）、行数与
//     字节上限、受控目录随机文件名、CSV 防公式注入；产物路径不进入公开结果。
//   - 清理复用 internal/task 异步任务，按批删除、有记录上限、可取消；请求、执行者、
//     范围、截止时间、计数与结果持久化；清理过程与结果写入受保护追加表
//     audit_maintenance_log（禁止 UPDATE/DELETE），本次清理只删除 audit_events，
//     不能抹除自身清理审计。
//   - 原始审计保留与报告/导出产物清理分开：本包不删除导出文件、报告或备份。
package auditops

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
	"time"
	"unicode/utf8"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// 任务类型、敏感操作与权限键。权限键复用 preset 目录已登记的 audit.read /
// audit.export / audit.purge，不新增权限。
const (
	// TaskKindAuditExport/TaskKindAuditPurge 是投递到 internal/task 的稳定类型。
	TaskKindAuditExport = "audit.export"
	TaskKindAuditPurge  = "audit.purge"
	// OperationExport/OperationPurge 是 internal/policy 敏感操作 ID。
	OperationExport = "audit.export"
	OperationPurge  = "audit.purge"
	// PermissionRead/PermissionExport/PermissionPurge 是基础权限键。
	PermissionRead   = "audit.read"
	PermissionExport = "audit.export"
	PermissionPurge  = "audit.purge"
	// ScopeSystem 是系统范围的稳定 ID。
	ScopeSystem = "system"
)

// 审计动作稳定标识（写入审计事件与受保护清理日志）。
const (
	ActionExportRequest = "audit.export.request"
	ActionExportFinish  = "audit.export.finish"
	ActionExportCancel  = "audit.export.cancel"
	ActionPurgePreview  = "audit.purge.preview"
	ActionPurgeRequest  = "audit.purge.request"
	ActionPurgeStart    = "audit.purge.start"
	ActionPurgeBatch    = "audit.purge.batch"
	ActionPurgeFinish   = "audit.purge.finish"
	ActionPurgeCancel   = "audit.purge.cancel"
	ActionRetentionSet  = "audit.retention.update"
	ActionAccessDenied  = "audit.access.denied"
)

// 查询、导出与清理的边界。超出硬上限一律拒绝，不静默截断。
const (
	// DefaultLimit/MaxLimit 是审计列表单页条数边界。
	DefaultLimit = 20
	MaxLimit     = 100
	// MaxOffset 限制深分页，避免把列表变成全量导出通道。
	MaxOffset = 1_000_000
	// DefaultExportRows/MaxExportRows 是单次导出行数边界。
	DefaultExportRows = 10_000
	MaxExportRows     = 100_000
	// DefaultExportBytes/MaxExportBytes 是受控产物字节上限。
	DefaultExportBytes = 8 * 1024 * 1024
	MaxExportBytes     = 64 * 1024 * 1024
	// DefaultBatchSize/MaxBatchSize 是清理每批删除条数边界。
	DefaultBatchSize = 500
	MaxBatchSize     = 5_000
	// DefaultMaxPurgeRecords/MaxPurgeRecords 是单次清理最多删除条数边界。
	DefaultMaxPurgeRecords = 100_000
	MaxPurgeRecords        = 1_000_000
	// DefaultRetentionDays/MaxRetentionDays 是保留天数默认值与上限。
	DefaultRetentionDays = 180
	MaxRetentionDays     = 3_650
	// MaxCountCap 是清理预估的最大计数上限（超过标记截断）。
	MaxCountCap = 1_000_000
	// MaxReasonBytes 是原因/安全失败说明上限。
	MaxReasonBytes = 256
	// MaxExportFilterBytes 是筛选快照 JSON 上限。
	MaxExportFilterBytes = 8 * 1024
	// MaxExportListLimit 是导出/清理任务列表单页上限。
	MaxExportListLimit = 100
	// exportIDPrefix/purgeIDPrefix 是导出/清理编号前缀。
	exportIDPrefix = "aex_"
	purgeIDPrefix  = "amr_"
	// idRandomBytes 是编号随机字节数（128 位）。
	idRandomBytes = 16
	// exportFilePrefix 是受控产物文件名前缀。
	exportFilePrefix = "audit_export_"
	// defaultExportTTL 是导出产物默认可用期（24 小时）；产物清理属于独立策略，
	// 本包只标记过期，不删除文件。
	defaultExportTTL = 24 * time.Hour
	// defaultTaskTimeoutSeconds 是异步导出/清理任务的默认墙钟上限。
	defaultTaskTimeoutSeconds = 900
	// purgeTaskTimeoutSeconds 是清理任务的墙钟上限。
	purgeTaskTimeoutSeconds = 1800
)

// 领域错误。宿主用 CodeOf 映射到根包已登记错误码，不新增注册码。
var (
	ErrOptionsInvalid   = errors.New("审计读取/导出/清理配置无效")
	ErrInvalidRequest   = errors.New("审计读取/导出/清理请求无效")
	ErrAccessDenied     = errors.New("未获准执行该审计操作")
	ErrRootRequired     = errors.New("该审计操作仅 root 可执行")
	ErrConflict         = errors.New("审计任务状态或版本冲突")
	ErrNotFound         = errors.New("审计导出或清理任务不存在")
	ErrRetentionExpired = errors.New("记录已超过保留期")
	ErrStoreUnavailable = errors.New("审计读取存储暂时不可用")
	ErrAuditUnavailable = errors.New("关键操作未能可靠记录")
	ErrExportPathUnsafe = errors.New("导出位置不安全")
	ErrTaskRejected     = errors.New("审计任务未能可靠提交")
	ErrTaskTerminal     = errors.New("审计任务已结束")
)

// ErrorCode 是本领域对根包错误码注册表的投影（全部复用既有码）。
type ErrorCode string

const (
	CodeReqInvalid         ErrorCode = "REQ_INVALID"
	CodeAccessDenied       ErrorCode = "ACCESS_DENIED"
	CodeResourceForbidden  ErrorCode = "RESOURCE_FORBIDDEN"
	CodeConflict           ErrorCode = "CONFLICT"
	CodeDBUnavailable      ErrorCode = "DB_UNAVAILABLE"
	CodeAuditWriteFailed   ErrorCode = "AUDIT_WRITE_FAILED"
	CodeExportPathUnsafe   ErrorCode = "EXPORT_PATH_UNSAFE"
	CodeReportAccessDenied ErrorCode = "REPORT_ACCESS_DENIED"
	CodeReportGeneration   ErrorCode = "REPORT_GENERATION_FAILED"
	CodeTaskCancelConflict ErrorCode = "TASK_CANCEL_CONFLICT"
	CodeTaskCancelled      ErrorCode = "TASK_CANCELLED"
	CodeTaskTimeout        ErrorCode = "TASK_TIMEOUT"
	CodeInternalError      ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把本领域错误映射为根包已登记错误码。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrOptionsInvalid), errors.Is(err, ErrInvalidRequest):
		return CodeReqInvalid
	case errors.Is(err, ErrAccessDenied):
		return CodeAccessDenied
	case errors.Is(err, ErrRootRequired):
		return CodeAccessDenied
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrRetentionExpired):
		// 根包未单独登记“不存在/已过保留期”码：复用 REQ_INVALID；调用方应按
		// errors.Is 区分具体状态，不能靠错误码伪装成保留期或存在性。
		return CodeReqInvalid
	case errors.Is(err, ErrConflict), errors.Is(err, ErrTaskTerminal):
		return CodeConflict
	case errors.Is(err, ErrExportPathUnsafe):
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

// Authorizer 判定调用者在指定作用范围的权限与数据范围；实现必须 fail-closed。
// 生产适配 internal/authz 的 Check 结果（DataScope 映射为 ScopeGrant）。
type Authorizer interface {
	AuthorizeScope(ctx context.Context, caller account.Caller, permissionKey, scopeID string) (ScopeGrant, error)
}

// ScopeGrant 是某一权限在当前作用范围的授权结果。
type ScopeGrant struct {
	// Allowed 为 false 表示明确拒绝。
	Allowed bool
	// AllData 为 true 表示数据范围不限（数据范围 all）。
	AllData bool
	// ResourceIDs 是允许访问的资源集合（数据范围 resources）；资源标识约定：
	// 应用范围使用应用 ID，系统范围使用应用快照 ID 或无快照事件的 "system"。
	ResourceIDs []string
}

// RootChecker 判定可信调用者当前是否为受保护 root；缺失/失败一律拒绝。
type RootChecker interface {
	IsRoot(ctx context.Context, caller account.Caller) (bool, error)
}

// SensitiveRunner 是步骤 38/39 敏感操作执行前校验（生产 *reauth.Service）。
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

// TaskReader 是任务状态读取契约（生产 *task.Executor，可选）。
type TaskReader interface {
	Get(ctx context.Context, id string) (task.Job, bool, error)
}

// Options 是本包依赖与边界配置。Store/Audit/Authorizer/Root/Sensitive/Enqueuer/
// Canceller/OutputDir 缺失时拒绝构造（fail-closed）。
type Options struct {
	Store      Store
	Audit      AuditRecorder
	Authorizer Authorizer
	Root       RootChecker
	Sensitive  SensitiveRunner
	Enqueuer   Enqueuer
	Canceller  Canceller
	// Tasks 可选：提供后导出/清理视图附带真实任务状态摘要。
	Tasks TaskReader
	// OutputDir 是导出产物受控目录（绝对路径、已存在、非符号链接）；必填。
	OutputDir string
	// MaxExportRows/MaxExportBytes/MaxBatchSize/MaxPurgeRecords/RetentionDays
	// 是边界与默认保留天数；0 使用默认值，超过硬上限拒绝构造。
	MaxExportRows   int
	MaxExportBytes  int64
	MaxBatchSize    int
	MaxPurgeRecords int
	RetentionDays   int
	Now             func() time.Time
	Random          io.Reader
	Logger          *slog.Logger
}

// Service 是审计读取、导出与保留期清理服务：构造后不可变、可并发使用；不启动
// 协程、不提供 HTTP 路由。异步导出/清理由宿主把 Handler 注册到 internal/task。
type Service struct {
	opts            Options
	maxExportRows   int
	maxExportBytes  int64
	maxBatchSize    int
	maxPurgeRecords int
	retentionDays   int
	outputDir       string
}

// New 校验依赖与边界并构造服务。
func New(options Options) (*Service, error) {
	if isNil(options.Store) || isNil(options.Audit) || isNil(options.Authorizer) ||
		isNil(options.Root) || isNil(options.Sensitive) || isNil(options.Enqueuer) ||
		isNil(options.Canceller) {
		return nil, fmt.Errorf("%w: 审计读取/导出/清理必需依赖缺失", ErrOptionsInvalid)
	}
	maxExportRows := options.MaxExportRows
	if maxExportRows == 0 {
		maxExportRows = DefaultExportRows
	}
	if maxExportRows < 1 || maxExportRows > MaxExportRows {
		return nil, fmt.Errorf("%w: 导出行数上限超出范围", ErrOptionsInvalid)
	}
	maxExportBytes := options.MaxExportBytes
	if maxExportBytes == 0 {
		maxExportBytes = DefaultExportBytes
	}
	if maxExportBytes < 1 || maxExportBytes > MaxExportBytes {
		return nil, fmt.Errorf("%w: 导出字节上限超出范围", ErrOptionsInvalid)
	}
	maxBatchSize := options.MaxBatchSize
	if maxBatchSize == 0 {
		maxBatchSize = DefaultBatchSize
	}
	if maxBatchSize < 1 || maxBatchSize > MaxBatchSize {
		return nil, fmt.Errorf("%w: 清理批大小超出范围", ErrOptionsInvalid)
	}
	maxPurgeRecords := options.MaxPurgeRecords
	if maxPurgeRecords == 0 {
		maxPurgeRecords = DefaultMaxPurgeRecords
	}
	if maxPurgeRecords < 1 || maxPurgeRecords > MaxPurgeRecords {
		return nil, fmt.Errorf("%w: 清理条数上限超出范围", ErrOptionsInvalid)
	}
	retentionDays := options.RetentionDays
	if retentionDays == 0 {
		retentionDays = DefaultRetentionDays
	}
	if retentionDays < 1 || retentionDays > MaxRetentionDays {
		return nil, fmt.Errorf("%w: 默认保留天数超出范围", ErrOptionsInvalid)
	}
	outputDir := ""
	if options.OutputDir != "" {
		absolute, err := filepath.Abs(options.OutputDir)
		if err != nil {
			return nil, fmt.Errorf("%w: 导出目录无效", ErrOptionsInvalid)
		}
		info, statErr := os.Lstat(absolute)
		if statErr != nil || !info.IsDir() {
			return nil, fmt.Errorf("%w: 导出目录必须是已存在的目录", ErrOptionsInvalid)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: 导出目录不能是符号链接", ErrOptionsInvalid)
		}
		outputDir = absolute
	}
	if outputDir == "" {
		return nil, fmt.Errorf("%w: 导出能力必须配置受控输出目录", ErrOptionsInvalid)
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
	return &Service{opts: options, maxExportRows: maxExportRows,
		maxExportBytes: maxExportBytes, maxBatchSize: maxBatchSize,
		maxPurgeRecords: maxPurgeRecords, retentionDays: retentionDays,
		outputDir: outputDir}, nil
}

// now 返回截断到 UTC 毫秒的当前时间。
func (s *Service) now() time.Time { return s.opts.Now().UTC().Truncate(time.Millisecond) }

// newID 生成带前缀的 128 位随机编号。
func (s *Service) newID(prefix string) (string, error) {
	buffer := make([]byte, idRandomBytes)
	if _, err := io.ReadFull(s.opts.Random, buffer); err != nil {
		return "", fmt.Errorf("%w: 无法生成编号", ErrInvalidRequest)
	}
	return prefix + hex.EncodeToString(buffer), nil
}

// callerFromActor 把可信审计身份还原为调用者，用于异步任务重新授权；
// 匿名身份拒绝。
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

// authorizeScope 统一执行作用范围授权。root 走受保护通道（不经过普通权限引擎），
// 其余调用者必须由注入的 Authorizer 判定；依赖失败 fail-closed。读/导出/清理的
// 越权拒绝会写失败审计（不改变拒绝结果）；是否对重复拒绝限频由宿主传输层负责，
// 本包不额外吞掉拒绝记录。
func (s *Service) authorizeScope(ctx context.Context, caller account.Caller,
	permissionKey, scopeID string) (ScopeGrant, error) {
	scopeID, err := normalizeScopeID(scopeID)
	if err != nil {
		return ScopeGrant{}, err
	}
	if s.isRoot(ctx, caller) {
		return ScopeGrant{Allowed: true, AllData: true}, nil
	}
	grant, err := s.opts.Authorizer.AuthorizeScope(ctx, caller, permissionKey, scopeID)
	if err != nil {
		s.recordScopeDenied(ctx, caller.Actor(), permissionKey, scopeID, "authorizer_unavailable")
		return ScopeGrant{}, fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	if !grant.Allowed {
		s.recordScopeDenied(ctx, caller.Actor(), permissionKey, scopeID, "not_granted")
		return ScopeGrant{}, ErrAccessDenied
	}
	return grant, nil
}

// recordScopeDenied 记录一次读/导出/清理授权拒绝（失败审计写失败只告警）。
func (s *Service) recordScopeDenied(ctx context.Context, actor audit.Actor,
	permissionKey, scopeID, reason string) {
	err := s.opts.Audit.RecordFailure(ctx, audit.Event{
		Actor: actor, AppID: appIDForScope(scopeID), Action: ActionAccessDenied,
		Target:  audit.Target{Type: "audit", ID: safeToken(permissionKey)},
		Outcome: audit.OutcomeDenied, ErrorCode: string(CodeAccessDenied),
		ReasonCode: safeToken(reason),
	})
	if err != nil {
		s.opts.Logger.Error("审计读取拒绝记录写入失败", "code", string(CodeAuditWriteFailed))
	}
}

// isRoot 判定调用者是否为 root；依赖失败按非 root 处理（fail-closed）。
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

// requireRoot 强制 root；非 root 返回 ErrRootRequired 并写失败审计。
func (s *Service) requireRoot(ctx context.Context, caller account.Caller) error {
	if !s.isRoot(ctx, caller) {
		s.recordScopeDenied(ctx, caller.Actor(), PermissionPurge, ScopeSystem, "root_required")
		return ErrRootRequired
	}
	return nil
}

// authorizeSensitive 执行敏感操作校验（强认证/确认），失败映射为统一拒绝。
func (s *Service) authorizeSensitive(ctx context.Context, caller account.Caller,
	operationID, scopeID, targetType, targetID string, params map[string]string,
	description, requestID string) (reauth.Result, error) {
	reauthCaller, err := reauth.CallerFromActor(caller.Actor())
	if err != nil {
		return reauth.Result{}, ErrAccessDenied
	}
	result, err := s.opts.Sensitive.Authorize(ctx, reauthCaller, reauth.Request{
		ScopeID: scopeID, OperationID: operationID, TargetType: targetType,
		TargetID: targetID, Params: params, Description: description, RequestID: requestID,
	})
	if err != nil {
		return reauth.Result{}, fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	return result, nil
}

// notifySensitive 执行敏感操作成功告知；告知失败只记录日志，不回滚已成功变更。
func (s *Service) notifySensitive(ctx context.Context, result reauth.Result) {
	if result.OperationID == "" {
		return
	}
	if err := s.opts.Sensitive.NotifyOutcome(ctx, result, reauth.OutcomeSuccess); err != nil {
		s.opts.Logger.Warn("审计操作安全告知未完成", "reason", "notify_unavailable")
	}
}

// recordFailure 记录失败/拒绝审计；写入失败只告警，不改变拒绝结果。
func (s *Service) recordFailure(ctx context.Context, actor audit.Actor, action, scopeID,
	reason string, code ErrorCode, requestID string) {
	appID := scopeID
	if appID == ScopeSystem {
		appID = ""
	}
	err := s.opts.Audit.RecordFailure(ctx, audit.Event{
		Actor: actor, AppID: appID, Action: action,
		Target:  audit.Target{Type: "audit", ID: "system"},
		Outcome: audit.OutcomeDenied, ErrorCode: string(code),
		ReasonCode: safeToken(reason), RequestID: requestID,
	})
	if err != nil {
		s.opts.Logger.Error("审计拒绝记录写入失败", "error", CodeAuditWriteFailed)
	}
}

// safeToken 把内部原因文本限制为稳定的短标记（ASCII 可见），避免写入原始错误。
func safeToken(value string) string {
	var builder strings.Builder
	for index := 0; index < len(value) && builder.Len() < 64; index++ {
		c := value[index]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' {
			builder.WriteByte(c)
		}
	}
	return builder.String()
}

// safeReason 把失败说明限制为安全的短文本（无控制字符），不保存堆栈或秘密。
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

// validateReason 校验原因：必填、合法 UTF-8、无控制字符、长度受限。
func validateReason(reason string) error {
	if reason == "" {
		return fmt.Errorf("%w: 原因不能为空", ErrInvalidRequest)
	}
	if len(reason) > MaxReasonBytes {
		return fmt.Errorf("%w: 原因超过 %d 字节", ErrInvalidRequest, MaxReasonBytes)
	}
	if !utf8.ValidString(reason) {
		return fmt.Errorf("%w: 原因不是合法 UTF-8", ErrInvalidRequest)
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
