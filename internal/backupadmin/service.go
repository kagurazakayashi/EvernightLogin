package backupadmin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/backup"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// 权限键与系统范围。权限键在 internal/preset 登记；本包不新增权限实现之外的语义。
const (
	// PermissionRead 允许查看备份任务/产物/计划的受控摘要。
	PermissionRead = "backups.read"
	// PermissionCreate 允许触发手动备份与创建/修改备份计划。
	PermissionCreate = "backups.create"
	// PermissionCancel 允许请求取消备份任务（独立于查看与下载）。
	PermissionCancel = "backups.cancel"
	// PermissionDownload 允许下载备份成品（独立于列表/查看权限）。
	PermissionDownload = "backups.export"
	// PermissionRetention 允许修改备份保留策略。
	PermissionRetention = "backups.retention"
	// PermissionCleanup 允许执行按保留策略的产物清理（不等于可修改策略）。
	PermissionCleanup = "backups.cleanup"
	// ScopeSystem 是备份固定使用的系统范围。
	ScopeSystem = "system"
)

// 敏感操作 ID（internal/policy 目录）与审计动作稳定标识。
const (
	OperationCreate    = "backup.create"
	OperationDownload  = "backup.export"
	OperationRetention = "backup.retention.change"
	OperationCleanup   = "backup.cleanup"
	OperationRestore   = "backup.restore" // 仅用于提示“恢复尚未实现”，本包不执行。

	ActionJobEnqueued      = "backup.job.enqueued"
	ActionJobCancel        = "backup.job.cancel.request"
	ActionScheduleCreate   = "backup.schedule.create"
	ActionScheduleApplied  = "backup.schedule.applied"
	ActionScheduleUpdate   = "backup.schedule.update"
	ActionScheduleState    = "backup.schedule.state"
	ActionScheduleDelete   = "backup.schedule.delete"
	ActionRetentionUpdate  = "backup.retention.update"
	ActionCleanupRequest   = "backup.cleanup.request"
	ActionCleanupFinish    = "backup.cleanup.finish"
	ActionNotification     = "backup.notification.result"
	ActionReconcile        = "backup.reconcile"
	ActionDownloadIssued   = "backup.download.issued"
	ActionDownloadRedeemed = "backup.download.redeemed"
	ActionAccessDenied     = "backup.access.denied"
)

// 任务类型与稳定上限。
const (
	// KindBackupCreate 是创建备份的任务类型。
	KindBackupCreate = "backup.create"
	// KindBackupCleanup 是按保留策略清理产物的任务类型。
	KindBackupCleanup = "backup.cleanup"
	// DefaultBackupMutexKey 是全局备份互斥键：同一时刻只允许一个备份写入，避免
	// 多份备份同时占用磁盘与附件读取。互斥不是触发去重。
	DefaultBackupMutexKey = "backup.create"
	// DefaultCleanupMutexKey 是清理互斥键。
	DefaultCleanupMutexKey = "backup.cleanup"

	// MaxScheduleNameRunes 是计划名称长度上限。
	MaxScheduleNameRunes = 120
	// MaxReasonRunes 是操作原因长度上限。
	MaxReasonRunes = 256
	// MaxNotifyTargetBytes 是通知渠道键长度上限（不保存收件地址原文）。
	MaxNotifyTargetBytes = 64
	// DefaultDownloadTTL 是页面下载一次性令牌有效期。
	DefaultDownloadTTL = 2 * time.Minute
	// DefaultMaxPageDownloadBytes 是单次页面下载上限；超过时明确拒绝而不是把大文件
	// 读入内存或截断。
	DefaultMaxPageDownloadBytes = int64(256) << 20
	// DefaultTaskTimeoutSeconds 是备份任务墙钟上限默认值（与备份服务默认一致）。
	DefaultTaskTimeoutSeconds = 600
	// maxTaskTimeoutSeconds 与 internal/task 的上限一致（24 小时）。
	maxTaskTimeoutSeconds = 24 * 60 * 60
	// maxJobAttempts 与 internal/task 的尝试上限一致。
	maxJobAttempts = 10
	// maxListLimit 是管理列表单页硬上限。
	maxListLimit = 100
	// defaultListLimit 是管理列表默认单页条数。
	defaultListLimit = 20
	// artifactFilePrefix/Suffix 与 internal/backup 的发布文件名规则一致。
	artifactFilePrefix = "login-backup_"
	artifactFileSuffix = ".elnbak"
	// ticketRandomBytes 是一次性下载令牌随机字节数。
	ticketRandomBytes = 32
)

// Authorizer、RootChecker 与 SensitiveRunner 复用既有契约，确保装配层只有一套
// 权限、root 与再次认证语义；实现失败一律按拒绝处理。
type Authorizer = backup.Authorizer
type RootChecker = stats.RootChecker
type SensitiveRunner = reauth.OperationRunner
type AuditRecorder = backup.AuditRecorder

// Creator 是备份创建契约（生产 *backup.Service；测试可注入受控替身）。
type Creator interface {
	Create(ctx context.Context, request backup.CreateRequest) (backup.Result, error)
}

// Enqueuer/Canceller/TaskReader 与 *task.Executor 方法签名一致。
type Enqueuer interface {
	Enqueue(ctx context.Context, request task.EnqueueRequest) (task.Job, error)
}

type Canceller interface {
	RequestCancel(ctx context.Context, request task.CancelRequest) (task.CancelResult, error)
}

type TaskReader interface {
	Get(ctx context.Context, id string) (task.Job, error)
}

// Notifier 是备份结果通知契约（宿主按受控渠道解析接收者；不得记录秘密）。
type Notifier interface {
	NotifyBackup(ctx context.Context, notification BackupNotification) error
}

// ProgressBridge 把 internal/backup 的全局进度回调转发给当前备份任务。宿主构造
// backup.Service 时把 ProgressBridge.Progress 作为 backup.Options.Progress，再在
// 构造本包 Service 时把同一 bridge 注入 Options.Progress；manager 会把进度写入
// backup_job_state。单实例同一时刻只运行一个备份（全局互斥键），因此无需按备份
// 编号路由；并发备份仍会把进度写到错误的任务上，所以互斥是前置条件。
type ProgressBridge struct {
	mu   sync.Mutex
	sink func(backup.Progress)
}

// Progress 实现 backup.ProgressFunc。
func (b *ProgressBridge) Progress(progress backup.Progress) {
	if b == nil {
		return
	}
	b.mu.Lock()
	sink := b.sink
	b.mu.Unlock()
	if sink != nil {
		sink(progress)
	}
}

// SetSink 设置进度接收者（仅由本包 Service 构造时调用）。
func (b *ProgressBridge) SetSink(sink func(backup.Progress)) {
	b.mu.Lock()
	b.sink = sink
	b.mu.Unlock()
}

// EnqueueRelay 把 internal/task 调度器的成功入队回调转发给本包 Service，使计划触发
// 的任务也能登记索引与初始阶段。宿主构造调度器时把 EnqueueRelay.Handle 作为
// task.SchedulerOptions.OnJobEnqueued，再把同一 relay 注入本包 Options.SchedulerRelay。
// relay 必须在 Service 构造前创建（允许先构造调度器）。
type EnqueueRelay struct {
	mu   sync.Mutex
	sink func(ctx context.Context, schedule task.Schedule, jobID string)
}

// Handle 实现 task.SchedulerOptions.OnJobEnqueued 回调签名。
func (r *EnqueueRelay) Handle(ctx context.Context, schedule task.Schedule, jobID string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	sink := r.sink
	r.mu.Unlock()
	if sink != nil {
		sink(ctx, schedule, jobID)
	}
}

// SetSink 设置入队回调接收者（仅由本包 Service 构造时调用）。
func (r *EnqueueRelay) SetSink(sink func(ctx context.Context, schedule task.Schedule, jobID string)) {
	r.mu.Lock()
	r.sink = sink
	r.mu.Unlock()
}

// Options 是备份管理服务依赖。所有权限、审计与再次认证依赖缺失时拒绝构造
// （fail-closed），不会退化成无授权的本地放行。
type Options struct {
	Backup     Creator
	Store      Store
	Scheduler  *task.Scheduler
	Enqueuer   Enqueuer
	Canceller  Canceller
	TaskReader TaskReader
	Authorizer Authorizer
	Root       RootChecker
	Sensitive  SensitiveRunner
	Audit      AuditRecorder
	Notifier   Notifier
	Progress   *ProgressBridge
	// SchedulerRelay 转发调度器成功入队回调；缺失时计划触发的任务不会进入管理
	// 索引（页面不可见），因此要求配置。宿主必须把同一 relay 的 Handle 注入调度器。
	SchedulerRelay *EnqueueRelay
	// Inspect 读取备份明文头部用于孤儿成品对账；nil 使用 backup.InspectFile；测试可注入
	// 受控替身，生产默认不改变任何校验语义。
	Inspect func(ctx context.Context, path string) (backup.VerifyReport, error)
	// OutputDir 是备份产物受控目录（与 backup.Service 配置一致）；用于受控文件
	// 存在性检查、清理与下载。必须是已存在绝对目录。
	OutputDir string
	// AppVersion 写入通知与登记元数据的应用版本；可为空。
	AppVersion string
	// DefaultRetention 是尚未保存策略时页面显示与服务使用的默认策略；必须至少
	// 启用一项有限上限。
	DefaultRetention RetentionPolicy
	// DefaultNotifyTarget 是手动任务使用的通知渠道键；不保存收件地址原文。
	DefaultNotifyTarget string
	// DefaultNotifyFailures/DefaultNotifySuccess 是手动任务的默认通知开关。
	DefaultNotifyFailures bool
	DefaultNotifySuccess  bool
	// DownloadTTL 是一次性下载令牌有效期；0 使用默认 2 分钟。
	DownloadTTL time.Duration
	// MaxPageDownloadBytes 是单次页面下载上限；0 使用默认 256 MiB。
	MaxPageDownloadBytes int64
	Now                  func() time.Time
	Random               io.Reader
	Logger               *slog.Logger
}

// Service 是备份管理领域服务。构造后不可变、可并发使用；不启动协程、不监听端口。
type Service struct {
	opts       Options
	outputDir  string
	now        func() time.Time
	random     io.Reader
	logger     *slog.Logger
	tickets    *ticketRegistry
	progressMu sync.Mutex
	currentJob string
}

// New 校验依赖并构造服务；不访问数据库、不创建文件、不启动任务。
func New(options Options) (*Service, error) {
	if options.Backup == nil || options.Store == nil || options.Scheduler == nil ||
		options.Enqueuer == nil || options.Canceller == nil || options.TaskReader == nil ||
		options.Authorizer == nil || options.Audit == nil || options.Sensitive == nil ||
		options.SchedulerRelay == nil {
		return nil, fmt.Errorf("%w: 备份管理服务缺少必需依赖", ErrOptionsInvalid)
	}
	outputDir, err := validateManagedOutputDir(options.OutputDir)
	if err != nil {
		return nil, err
	}
	if !options.DefaultRetention.Enabled() {
		return nil, fmt.Errorf("%w: 默认保留策略必须至少启用一项有限上限", ErrOptionsInvalid)
	}
	if options.DefaultRetention.MaxAgeDays < 0 || options.DefaultRetention.MaxAgeDays > 36500 ||
		options.DefaultRetention.MaxCount < 0 || options.DefaultRetention.MaxTotalBytes < 0 {
		return nil, fmt.Errorf("%w: 默认保留策略取值非法", ErrOptionsInvalid)
	}
	if options.DefaultRetention.Version < 1 {
		options.DefaultRetention.Version = 1
	}
	if options.DownloadTTL == 0 {
		options.DownloadTTL = DefaultDownloadTTL
	}
	if options.DownloadTTL < 30*time.Second || options.DownloadTTL > 15*time.Minute {
		return nil, fmt.Errorf("%w: 下载令牌有效期必须在 30 秒～15 分钟之间", ErrOptionsInvalid)
	}
	if options.MaxPageDownloadBytes == 0 {
		options.MaxPageDownloadBytes = DefaultMaxPageDownloadBytes
	}
	if options.MaxPageDownloadBytes < 1<<20 || options.MaxPageDownloadBytes > 1<<40 {
		return nil, fmt.Errorf("%w: 页面下载上限超出允许范围", ErrOptionsInvalid)
	}
	if options.Inspect == nil {
		options.Inspect = backup.InspectFile
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard,
			&slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	if options.DefaultNotifyTarget == "" {
		options.DefaultNotifyTarget = "owner_mail"
	}
	service := &Service{
		opts:      options,
		outputDir: outputDir,
		now:       options.Now,
		random:    options.Random,
		logger:    options.Logger,
		tickets:   newTicketRegistry(),
	}
	if options.Progress != nil {
		options.Progress.SetSink(service.recordProgress)
	}
	options.SchedulerRelay.SetSink(service.registerScheduledJob)
	return service, nil
}

// registerScheduledJob 记录调度器触发入队的任务索引与初始阶段；失败只告警，任务
// 本身仍由 internal/task 持久化并执行。
func (s *Service) registerScheduledJob(ctx context.Context, schedule task.Schedule, jobID string) {
	origin := OriginSchedule
	entryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := s.opts.Store.InsertJob(entryCtx, JobIndexEntry{
		JobID: jobID, Kind: kindOrBackup(schedule.JobKind), Origin: origin,
		ScheduleID: schedule.ID, Initiator: schedule.ExecutionActor,
		CreatedAt: s.now(),
	}); err != nil {
		s.logger.Warn("计划触发任务索引写入失败", "job_id", jobID, "schedule_id", schedule.ID)
		return
	}
	if err := s.opts.Store.SaveJobState(entryCtx, JobProgressState{
		JobID: jobID, UpdatedAt: s.now(),
	}); err != nil {
		s.logger.Warn("计划触发任务状态初始化失败", "job_id", jobID)
	}
}

// kindOrBackup 返回任务类型；未知类型按备份任务处理只会影响索引展示，不会放行执行。
func kindOrBackup(kind string) string {
	if kind == KindBackupCleanup {
		return KindBackupCleanup
	}
	return KindBackupCreate
}

// validateManagedOutputDir 校验受控输出目录：绝对路径、已存在目录、非符号链接。
func validateManagedOutputDir(directory string) (string, error) {
	cleaned := strings.TrimSpace(directory)
	if cleaned == "" {
		return "", fmt.Errorf("%w: 缺少备份输出目录", ErrOptionsInvalid)
	}
	if !filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("%w: 备份输出目录必须是绝对路径", ErrOptionsInvalid)
	}
	info, err := os.Lstat(cleaned)
	if err != nil {
		return "", fmt.Errorf("%w: 备份输出目录不可用", ErrOptionsInvalid)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("%w: 备份输出目录必须是非符号链接目录", ErrOptionsInvalid)
	}
	return filepath.Clean(cleaned), nil
}

// DownloadTTL 返回页面下载令牌有效期。
func (s *Service) DownloadTTL() time.Duration { return s.opts.DownloadTTL }

// CheckReadAccess 复核当前调用者是否仍可查看备份管理数据；供只读巡检入口使用，
// 不替代各具体操作的独立授权。
func (s *Service) CheckReadAccess(ctx context.Context, caller account.Caller) error {
	return s.authorize(ctx, caller, PermissionRead)
}

// Capabilities 返回当前操作者的页面能力位（只影响呈现；每次读取/写入仍重新授权）。
type Capabilities struct {
	Read        bool
	Create      bool
	Cancel      bool
	Download    bool
	Retention   bool
	Cleanup     bool
	DownloadTTL time.Duration
}

// Capabilities 实现页面能力位查询；授权依赖失败按无权限处理。
func (s *Service) Capabilities(ctx context.Context, caller account.Caller) (Capabilities, error) {
	if err := validateCaller(caller); err != nil {
		return Capabilities{}, err
	}
	return Capabilities{
		Read:        s.allow(ctx, caller, PermissionRead),
		Create:      s.allow(ctx, caller, PermissionCreate),
		Cancel:      s.allow(ctx, caller, PermissionCancel),
		Download:    s.allow(ctx, caller, PermissionDownload),
		Retention:   s.allow(ctx, caller, PermissionRetention),
		Cleanup:     s.allow(ctx, caller, PermissionCleanup),
		DownloadTTL: s.opts.DownloadTTL,
	}, nil
}

// validateCaller 校验可信调用者身份；匿名/非法身份拒绝。
func validateCaller(caller account.Caller) error {
	actor := caller.Actor()
	if err := actor.Validate(); err != nil || actor.Type == audit.ActorAnonymous || actor.ID == "" {
		return ErrAccessDenied
	}
	return nil
}

// callerFromActor 把可信审计身份重建为调用者；未知类型拒绝。
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

// allow 判定当前调用者在系统范围内是否拥有某权限；root 通过 root 检查，其余由
// Authorizer 决定；任何依赖失败按无权限处理。
func (s *Service) allow(ctx context.Context, caller account.Caller, permission string) bool {
	if s.opts.Root != nil {
		if root, err := s.opts.Root.IsRoot(ctx, caller); err == nil && root {
			return true
		}
	}
	grant, err := s.opts.Authorizer.AuthorizeScope(ctx, caller, permission, ScopeSystem)
	return err == nil && grant.Allowed
}

// authorize 要求当前调用者拥有权限；拒绝写拒绝审计（尽力，不改变拒绝结论）。
func (s *Service) authorize(ctx context.Context, caller account.Caller, permission string) error {
	if err := validateCaller(caller); err != nil {
		return err
	}
	actor := caller.Actor()
	if s.allow(ctx, caller, permission) {
		return nil
	}
	s.recordDenied(ctx, actor, permission, caller.RequestID())
	return fmt.Errorf("%w: 缺少权限 %s", ErrAccessDenied, permission)
}

// authorizeSensitive 在权限通过后执行强认证敏感操作校验；未接线或失败按拒绝处理。
func (s *Service) authorizeSensitive(ctx context.Context, caller account.Caller,
	operationID, targetType, targetID string, params map[string]string,
	description, requestID string) (reauth.Result, error) {
	reauthCaller, err := reauth.CallerFromActor(caller.Actor())
	if err != nil {
		return reauth.Result{}, ErrAccessDenied
	}
	result, err := s.opts.Sensitive.Authorize(ctx, reauthCaller, reauth.Request{
		ScopeID: ScopeSystem, OperationID: operationID,
		TargetType: targetType, TargetID: targetID, Params: params,
		Description: description, RequestID: requestID,
	})
	if err != nil {
		s.recordDenied(ctx, caller.Actor(), operationID, requestID)
		return reauth.Result{}, fmt.Errorf("%w: 敏感操作未通过再次认证", ErrAccessDenied)
	}
	return result, nil
}

// notifySensitiveOutcome 尽力收敛再次认证的“已执行”告知；失败只告警。
func (s *Service) notifySensitiveOutcome(ctx context.Context, result reauth.Result) {
	if err := s.opts.Sensitive.NotifyOutcome(ctx, result, reauth.OutcomeSuccess); err != nil {
		s.logger.Warn("备份敏感操作告知发送失败", "operation", result.OperationID)
	}
}

// record 写入关键审计；失败返回 ErrAuditUnavailable（调用方应按 fail-closed 处理）。
func (s *Service) record(ctx context.Context, event audit.Event) error {
	if err := s.opts.Audit.Record(ctx, event); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	return nil
}

// recordBestEffort 写入非关键审计；失败只告警。
func (s *Service) recordBestEffort(ctx context.Context, event audit.Event) {
	if err := s.opts.Audit.RecordFailure(ctx, event); err != nil {
		s.logger.Warn("备份管理审计写入失败", "action", event.Action)
	}
}

// recordDenied 记录拒绝审计（尽力）。
func (s *Service) recordDenied(ctx context.Context, actor audit.Actor, reason, requestID string) {
	s.recordBestEffort(ctx, audit.Event{
		Actor: actor, Action: ActionAccessDenied,
		Target:  audit.Target{Type: "backup_admin", ID: "backup_ui"},
		Outcome: audit.OutcomeDenied, ErrorCode: string(ErrPermissionDeniedCode),
		ReasonCode: safeToken(reason), RequestID: normalizeRequestID(requestID),
	})
}

// recordChangeFailure 在“审计意图已写入、但实际变更失败”时补写失败审计（尽力），
// 保留真实失败原因；变更本身不会在审计失败时执行（见各管理变更的意图审计）。
func (s *Service) recordChangeFailure(ctx context.Context, actor audit.Actor,
	action, targetType, targetID, requestID, reason string) {
	s.recordBestEffort(ctx, audit.Event{
		Actor: actor, Action: action,
		Target:  audit.Target{Type: targetType, ID: targetID},
		Outcome: audit.OutcomeFailure, ErrorCode: string(CodeOf(ErrStoreUnavailable)),
		ReasonCode: safeToken(reason), RequestID: normalizeRequestID(requestID),
	})
}

// ErrPermissionDeniedCode 是拒绝审计使用的稳定错误码。
const ErrPermissionDeniedCode backup.ErrorCode = backup.CodeAccessDenied

// normalizeRequestID 把请求编号规范为审计可接受的安全短标识；非法值置空。
func normalizeRequestID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 64 {
		return ""
	}
	for index := 0; index < len(value); index++ {
		c := value[index]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if index == 0 && !alnum {
			return ""
		}
		if !alnum && c != '.' && c != '_' && c != '-' {
			return ""
		}
	}
	return value
}

// safeToken 把原因文本限制为稳定 token，避免写入自由文本。
func safeToken(value string) string {
	var builder strings.Builder
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '.' || r == '-' {
			builder.WriteRune(r)
		}
		if builder.Len() >= 64 {
			break
		}
	}
	return builder.String()
}

// validateReason 校验操作原因：必填、合法 UTF-8、无控制字符、长度受限。
func validateReason(reason string) (string, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return "", fmt.Errorf("%w: 修改原因不能为空", ErrInvalidRequest)
	}
	if utf8.RuneCountInString(reason) > MaxReasonRunes {
		return "", fmt.Errorf("%w: 修改原因超过 %d 个字符", ErrInvalidRequest, MaxReasonRunes)
	}
	for _, r := range reason {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("%w: 修改原因不能包含控制字符", ErrInvalidRequest)
		}
	}
	return reason, nil
}

// ===================== 计划管理 =====================

// ScheduleRequest 是创建/编辑计划的服务端白名单字段。
type ScheduleRequest struct {
	Caller           account.Caller
	Name             string
	ScheduleType     task.ScheduleType
	Expression       string
	TimeZone         string
	MissedPolicy     task.MissedPolicy
	MaxCatchUp       int
	TimeoutSeconds   int
	MaxAttempts      int
	RetentionVersion int64
	NotifyFailures   bool
	NotifySuccess    bool
	NotifyTarget     string
	Enabled          bool
	RequestID        string
}

// ScheduleView 是计划页面视图（周期/时区来自真实计划；下次执行由服务端计算）。
type ScheduleView struct {
	ID                string
	Name              string
	Enabled           bool
	ScheduleType      string
	Expression        string
	TimeZone          string
	PeriodDescription string
	MissedPolicy      string
	MaxCatchUp        int
	TimeoutSeconds    int
	MaxAttempts       int
	Owner             audit.Actor
	ExecutionActor    audit.Actor
	ScopeID           string
	NextRun           time.Time
	NextRunUnknown    bool
	RetentionVersion  int64
	NotifyFailures    bool
	NotifySuccess     bool
	LastScheduledAt   time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
	// PermissionState 只由服务端可公开的结论驱动；本步骤不自动停用计划。
	PermissionState string
}

// ListSchedules 列出计划（要求 backups.read）。
func (s *Service) ListSchedules(ctx context.Context, caller account.Caller) ([]ScheduleView, error) {
	if err := s.authorize(ctx, caller, PermissionRead); err != nil {
		return nil, err
	}
	schedules, err := s.opts.Scheduler.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	metas, err := s.opts.Store.ListScheduleMeta(ctx)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]ScheduleMeta, len(metas))
	for _, meta := range metas {
		byID[meta.ScheduleID] = meta
	}
	views := make([]ScheduleView, 0, len(schedules))
	for _, schedule := range schedules {
		views = append(views, s.scheduleView(schedule, byID[schedule.ID]))
	}
	sort.SliceStable(views, func(i, j int) bool { return views[i].CreatedAt.After(views[j].CreatedAt) })
	return views, nil
}

// GetSchedule 读取单个计划（要求 backups.read）。
func (s *Service) GetSchedule(ctx context.Context, caller account.Caller,
	scheduleID string) (ScheduleView, error) {
	if err := s.authorize(ctx, caller, PermissionRead); err != nil {
		return ScheduleView{}, err
	}
	schedule, err := s.lookupSchedule(ctx, scheduleID)
	if err != nil {
		return ScheduleView{}, err
	}
	meta, _, err := s.opts.Store.ScheduleMeta(ctx, schedule.ID)
	if err != nil {
		return ScheduleView{}, err
	}
	return s.scheduleView(schedule, meta), nil
}

// lookupSchedule 读取并校验计划编号；不存在返回 ErrNotFound。
func (s *Service) lookupSchedule(ctx context.Context, scheduleID string) (task.Schedule, error) {
	scheduleID = strings.TrimSpace(scheduleID)
	if err := task.ValidateScheduleID(scheduleID); err != nil {
		return task.Schedule{}, fmt.Errorf("%w: 计划编号无效", ErrInvalidRequest)
	}
	schedule, err := s.opts.Scheduler.Get(ctx, scheduleID)
	if err != nil {
		return task.Schedule{}, fmt.Errorf("%w: 计划不存在", ErrNotFound)
	}
	return schedule, nil
}

// scheduleView 映射计划视图；命中失败按未知处理，不猜测下次执行时间。
func (s *Service) scheduleView(schedule task.Schedule, meta ScheduleMeta) ScheduleView {
	view := ScheduleView{
		ID: schedule.ID, Name: meta.Name, Enabled: schedule.Enabled,
		ScheduleType: string(schedule.ScheduleType), Expression: schedule.Expression,
		TimeZone: schedule.TimeZone, MissedPolicy: string(schedule.MissedPolicy),
		MaxCatchUp: schedule.MaxCatchUp, TimeoutSeconds: schedule.TimeoutSeconds,
		MaxAttempts: schedule.MaxAttempts, Owner: schedule.Owner,
		ExecutionActor: schedule.ExecutionActor, ScopeID: schedule.ScopeID,
		RetentionVersion: meta.RetentionVersion, NotifyFailures: meta.NotifyFailures,
		NotifySuccess: meta.NotifySuccess, LastScheduledAt: schedule.LastScheduledAt,
		CreatedAt: schedule.CreatedAt, UpdatedAt: schedule.UpdatedAt,
	}
	spec, err := task.ParseScheduleSpec(schedule.ScheduleType, schedule.Expression,
		schedule.TimeZone, schedule.CreatedAt)
	if err != nil {
		view.NextRunUnknown = true
		return view
	}
	next := spec.Next(s.now())
	if next.IsZero() {
		view.NextRunUnknown = true
		return view
	}
	view.NextRun = next
	view.PeriodDescription = describeSchedule(schedule.ScheduleType, schedule.Expression)
	return view
}

// describeSchedule 生成直白中文周期说明；只用于展示，不替代真实表达式。
func describeSchedule(scheduleType task.ScheduleType, expression string) string {
	switch scheduleType {
	case task.ScheduleTypeDaily:
		return "每天 " + expression
	case task.ScheduleTypeWeekly:
		return "每周 " + expression
	case task.ScheduleTypeMonthly:
		return "每月 " + expression
	case task.ScheduleTypeCustom:
		return "固定间隔 " + expression
	default:
		return expression
	}
}

// CreateSchedule 创建备份计划（要求 backups.create，并按敏感操作再次认证）。
func (s *Service) CreateSchedule(ctx context.Context, request ScheduleRequest) (ScheduleView, error) {
	if err := s.authorize(ctx, request.Caller, PermissionCreate); err != nil {
		return ScheduleView{}, err
	}
	name, err := validateScheduleName(request.Name)
	if err != nil {
		return ScheduleView{}, err
	}
	payload, err := json.Marshal(struct {
		Origin           string `json:"origin"`
		ScheduleID       string `json:"schedule_id"`
		RetentionVersion int64  `json:"retention_version"`
	}{Origin: string(OriginSchedule), RetentionVersion: maxInt64(request.RetentionVersion, 1)})
	if err != nil {
		return ScheduleView{}, fmt.Errorf("%w: 计划载荷编码失败", ErrInvalidRequest)
	}
	timeout, attempts, err := s.normalizeTaskLimits(request.TimeoutSeconds, request.MaxAttempts)
	if err != nil {
		return ScheduleView{}, err
	}
	requestID := normalizeRequestID(request.RequestID)
	if _, err := s.authorizeSensitive(ctx, request.Caller, OperationCreate,
		"backup_schedule", "", map[string]string{
			"action": "create", "schedule_type": string(request.ScheduleType),
			"time_zone": request.TimeZone, "enabled": boolText(request.Enabled),
		}, "创建备份计划（每次触发都会重新复核执行身份权限）", requestID); err != nil {
		return ScheduleView{}, err
	}
	// 关键管理变更先写审计意图；审计不可用时拒绝执行，避免“计划已生效但无审计”。
	if err := s.record(ctx, audit.Event{
		Actor: request.Caller.Actor(), Action: ActionScheduleCreate,
		Target:  audit.Target{Type: "backup_schedule", ID: "pending"},
		Outcome: audit.OutcomeSuccess, RequestID: requestID,
		Changes: []audit.FieldChange{
			{Field: "schedule_type", After: string(request.ScheduleType)},
			{Field: "time_zone", After: request.TimeZone},
			{Field: "enabled", After: boolText(request.Enabled)},
			{Field: "execution_actor", After: request.Caller.Actor().ID},
		},
	}); err != nil {
		return ScheduleView{}, err
	}
	schedule, err := s.opts.Scheduler.Create(ctx, task.NewScheduleRequest{
		JobKind: KindBackupCreate, ScheduleType: request.ScheduleType,
		Expression: request.Expression, TimeZone: request.TimeZone,
		Owner: request.Caller.Actor(), ExecutionActor: request.Caller.Actor(),
		ScopeID: ScopeSystem, Enabled: request.Enabled,
		MissedPolicy: request.MissedPolicy, MaxCatchUp: request.MaxCatchUp,
		Payload: payload, MutexKey: DefaultBackupMutexKey,
		TimeoutSeconds: timeout, MaxAttempts: attempts,
		RequestID: requestID,
	})
	if err != nil {
		s.recordChangeFailure(ctx, request.Caller.Actor(), ActionScheduleCreate,
			"backup_schedule", "pending", requestID, "schedule_create_failed")
		return ScheduleView{}, mapTaskError(err)
	}
	meta := ScheduleMeta{
		ScheduleID: schedule.ID, Name: name, RetentionVersion: maxInt64(request.RetentionVersion, 1),
		NotifyFailures: request.NotifyFailures, NotifySuccess: request.NotifySuccess,
		NotifyTarget: s.normalizeNotifyTarget(request.NotifyTarget),
		CreatedBy:    request.Caller.Actor(), CreatedAt: s.now(), UpdatedAt: s.now(),
	}
	if err := s.opts.Store.SaveScheduleMeta(ctx, meta); err != nil {
		// 补偿：附加配置无法保存时删除刚创建的计划，避免出现页面无法管理的计划。
		_ = s.opts.Scheduler.Delete(ctx, task.ScheduleDeleteCommand{
			ScheduleID: schedule.ID, Actor: request.Caller.Actor(),
			Reason: "compensate_meta_save_failed", Now: s.now(),
		})
		s.recordChangeFailure(ctx, request.Caller.Actor(), ActionScheduleCreate,
			"backup_schedule", "pending", requestID, "meta_save_failed")
		return ScheduleView{}, err
	}
	// 成功后的附加“已应用”审计为尽力写入：关键意图审计已在变更前 fail-closed 记录。
	s.recordBestEffort(ctx, audit.Event{
		Actor: request.Caller.Actor(), Action: ActionScheduleApplied,
		Target:  audit.Target{Type: "backup_schedule", ID: schedule.ID},
		Outcome: audit.OutcomeSuccess, RequestID: requestID,
		Changes: []audit.FieldChange{
			{Field: "schedule_id", After: schedule.ID},
			{Field: "retention_version", After: fmt.Sprint(meta.RetentionVersion)},
		},
	})
	return s.scheduleView(schedule, meta), nil
}

// UpdateSchedule 编辑备份计划（周期、时区、补跑、重试与通知配置）。
func (s *Service) UpdateSchedule(ctx context.Context, scheduleID string,
	request ScheduleRequest) (ScheduleView, error) {
	if err := s.authorize(ctx, request.Caller, PermissionCreate); err != nil {
		return ScheduleView{}, err
	}
	current, err := s.lookupSchedule(ctx, scheduleID)
	if err != nil {
		return ScheduleView{}, err
	}
	name, err := validateScheduleName(request.Name)
	if err != nil {
		return ScheduleView{}, err
	}
	payload, err := json.Marshal(struct {
		Origin           string `json:"origin"`
		ScheduleID       string `json:"schedule_id"`
		RetentionVersion int64  `json:"retention_version"`
	}{Origin: string(OriginSchedule), ScheduleID: current.ID,
		RetentionVersion: maxInt64(request.RetentionVersion, 1)})
	if err != nil {
		return ScheduleView{}, fmt.Errorf("%w: 计划载荷编码失败", ErrInvalidRequest)
	}
	timeout, attempts, err := s.normalizeTaskLimits(request.TimeoutSeconds, request.MaxAttempts)
	if err != nil {
		return ScheduleView{}, err
	}
	// internal/task 没有原地更新计划；编辑通过“创建新计划 + 停用旧计划”实现，旧计划
	// 保留其历史触发记录，已入队/运行中的任务继续执行。
	requestID := normalizeRequestID(request.RequestID)
	if _, err := s.authorizeSensitive(ctx, request.Caller, OperationCreate,
		"backup_schedule", current.ID, map[string]string{
			"action": "update", "schedule_id": current.ID,
			"schedule_type": string(request.ScheduleType),
			"time_zone":     request.TimeZone, "enabled": boolText(request.Enabled),
		}, "编辑备份计划（含执行身份变更，需再次认证）", requestID); err != nil {
		return ScheduleView{}, err
	}
	// 审计意图（含旧/新执行身份与周期）在变更前写入；失败即拒绝，计划不会被修改。
	if err := s.record(ctx, audit.Event{
		Actor: request.Caller.Actor(), Action: ActionScheduleUpdate,
		Target:  audit.Target{Type: "backup_schedule", ID: current.ID},
		Outcome: audit.OutcomeSuccess, RequestID: requestID,
		Changes: []audit.FieldChange{
			{Field: "schedule_id", After: current.ID},
			{Field: "execution_actor_before", After: current.ExecutionActor.ID},
			{Field: "execution_actor_after", After: request.Caller.Actor().ID},
			{Field: "schedule_type", After: string(request.ScheduleType)},
			{Field: "time_zone", After: request.TimeZone},
			{Field: "enabled", After: boolText(request.Enabled)},
		},
	}); err != nil {
		return ScheduleView{}, err
	}
	created, err := s.opts.Scheduler.Create(ctx, task.NewScheduleRequest{
		JobKind: KindBackupCreate, ScheduleType: request.ScheduleType,
		Expression: request.Expression, TimeZone: request.TimeZone,
		Owner: current.Owner, ExecutionActor: request.Caller.Actor(),
		ScopeID: current.ScopeID, Enabled: request.Enabled,
		MissedPolicy: request.MissedPolicy, MaxCatchUp: request.MaxCatchUp,
		Payload: payload, MutexKey: DefaultBackupMutexKey,
		TimeoutSeconds: timeout, MaxAttempts: attempts, RequestID: requestID,
	})
	if err != nil {
		s.recordChangeFailure(ctx, request.Caller.Actor(), ActionScheduleUpdate,
			"backup_schedule", current.ID, requestID, "schedule_update_create_failed")
		return ScheduleView{}, mapTaskError(err)
	}
	if _, err := s.opts.Scheduler.Pause(ctx, task.ScheduleStateCommand{
		ScheduleID: current.ID, Actor: request.Caller.Actor(),
		Reason: "superseded_by_edit", RequestID: requestID, Now: s.now(),
	}); err != nil {
		_ = s.opts.Scheduler.Delete(ctx, task.ScheduleDeleteCommand{
			ScheduleID: created.ID, Actor: request.Caller.Actor(),
			Reason: "compensate_edit_failed", Now: s.now()})
		s.recordChangeFailure(ctx, request.Caller.Actor(), ActionScheduleUpdate,
			"backup_schedule", current.ID, requestID, "supersede_failed")
		return ScheduleView{}, mapTaskError(err)
	}
	meta := ScheduleMeta{
		ScheduleID: created.ID, Name: name,
		RetentionVersion: maxInt64(request.RetentionVersion, 1),
		NotifyFailures:   request.NotifyFailures, NotifySuccess: request.NotifySuccess,
		NotifyTarget: s.normalizeNotifyTarget(request.NotifyTarget),
		CreatedBy:    current.Owner, CreatedAt: created.CreatedAt, UpdatedAt: s.now(),
	}
	if err := s.opts.Store.SaveScheduleMeta(ctx, meta); err != nil {
		s.recordChangeFailure(ctx, request.Caller.Actor(), ActionScheduleUpdate,
			"backup_schedule", created.ID, requestID, "meta_save_failed")
		return ScheduleView{}, err
	}
	// 旧计划的附加配置保留（供历史引用），只把新计划指向当前配置。
	s.recordBestEffort(ctx, audit.Event{
		Actor: request.Caller.Actor(), Action: ActionScheduleApplied,
		Target:  audit.Target{Type: "backup_schedule", ID: created.ID},
		Outcome: audit.OutcomeSuccess, RequestID: requestID,
		Changes: []audit.FieldChange{
			{Field: "superseded_schedule", After: current.ID},
			{Field: "schedule_type", After: string(created.ScheduleType)},
			{Field: "time_zone", After: created.TimeZone},
		},
	})
	return s.scheduleView(created, meta), nil
}

// SetScheduleEnabled 启用/停用计划（停用只停止未来触发）。
func (s *Service) SetScheduleEnabled(ctx context.Context, caller account.Caller,
	scheduleID string, enabled bool, reason, requestID string) (ScheduleView, error) {
	if err := s.authorize(ctx, caller, PermissionCreate); err != nil {
		return ScheduleView{}, err
	}
	reason, err := validateReason(reason)
	if err != nil {
		return ScheduleView{}, err
	}
	command := task.ScheduleStateCommand{
		ScheduleID: strings.TrimSpace(scheduleID), Actor: caller.Actor(),
		Reason: reason, RequestID: normalizeRequestID(requestID), Now: s.now(),
	}
	if _, err := s.authorizeSensitive(ctx, caller, OperationCreate, "backup_schedule",
		command.ScheduleID, map[string]string{
			"action": "set_enabled", "schedule_id": command.ScheduleID,
			"enabled": boolText(enabled),
		}, "启用或停用备份计划（需再次认证）", command.RequestID); err != nil {
		return ScheduleView{}, err
	}
	if err := s.record(ctx, audit.Event{
		Actor: caller.Actor(), Action: ActionScheduleState,
		Target:  audit.Target{Type: "backup_schedule", ID: command.ScheduleID},
		Outcome: audit.OutcomeSuccess, RequestID: command.RequestID,
		Changes: []audit.FieldChange{
			{Field: "enabled", After: boolText(enabled)},
			{Field: "reason_present", After: "true"},
		},
	}); err != nil {
		return ScheduleView{}, err
	}
	var schedule task.Schedule
	if enabled {
		schedule, err = s.opts.Scheduler.Resume(ctx, command)
	} else {
		schedule, err = s.opts.Scheduler.Pause(ctx, command)
	}
	if err != nil {
		s.recordChangeFailure(ctx, caller.Actor(), ActionScheduleState,
			"backup_schedule", command.ScheduleID, command.RequestID, "schedule_state_failed")
		return ScheduleView{}, mapTaskError(err)
	}
	meta, _, err := s.opts.Store.ScheduleMeta(ctx, schedule.ID)
	if err != nil {
		return ScheduleView{}, err
	}
	return s.scheduleView(schedule, meta), nil
}

// DeleteSchedule 删除计划（不取消既有任务、不删除历史产物）。
func (s *Service) DeleteSchedule(ctx context.Context, caller account.Caller,
	scheduleID, reason, requestID string) error {
	if err := s.authorize(ctx, caller, PermissionCreate); err != nil {
		return err
	}
	reason, err := validateReason(reason)
	if err != nil {
		return err
	}
	scheduleID = strings.TrimSpace(scheduleID)
	if err := task.ValidateScheduleID(scheduleID); err != nil {
		return fmt.Errorf("%w: 计划编号无效", ErrInvalidRequest)
	}
	if _, err := s.authorizeSensitive(ctx, caller, OperationCreate, "backup_schedule",
		scheduleID, map[string]string{"action": "delete", "schedule_id": scheduleID},
		"删除备份计划（不取消既有任务、不删除历史备份，需再次认证）",
		normalizeRequestID(requestID)); err != nil {
		return err
	}
	if err := s.record(ctx, audit.Event{
		Actor: caller.Actor(), Action: ActionScheduleDelete,
		Target:  audit.Target{Type: "backup_schedule", ID: scheduleID},
		Outcome: audit.OutcomeSuccess, RequestID: normalizeRequestID(requestID),
		Changes: []audit.FieldChange{
			{Field: "reason_present", After: "true"},
			{Field: "active_jobs_continue", After: "true"},
		},
	}); err != nil {
		return err
	}
	if err := s.opts.Scheduler.Delete(ctx, task.ScheduleDeleteCommand{
		ScheduleID: scheduleID, Actor: caller.Actor(), Reason: reason,
		RequestID: normalizeRequestID(requestID), Now: s.now(),
	}); err != nil {
		s.recordChangeFailure(ctx, caller.Actor(), ActionScheduleDelete,
			"backup_schedule", scheduleID, requestID, "schedule_delete_failed")
		return mapTaskError(err)
	}
	if err := s.opts.Store.DeleteScheduleMeta(ctx, scheduleID); err != nil {
		return err
	}
	return nil
}

// normalizeTaskLimits 校验任务墙钟上限与尝试次数（不透传无限值）。
func (s *Service) normalizeTaskLimits(timeoutSeconds, maxAttempts int) (int, int, error) {
	if timeoutSeconds == 0 {
		timeoutSeconds = DefaultTaskTimeoutSeconds
	}
	if timeoutSeconds < 60 || timeoutSeconds > maxTaskTimeoutSeconds {
		return 0, 0, fmt.Errorf("%w: 任务墙钟上限必须在 60～%d 秒之间",
			ErrInvalidRequest, maxTaskTimeoutSeconds)
	}
	if maxAttempts == 0 {
		maxAttempts = 2
	}
	if maxAttempts < 1 || maxAttempts > maxJobAttempts {
		return 0, 0, fmt.Errorf("%w: 最大尝试次数必须在 1～%d 之间", ErrInvalidRequest, maxJobAttempts)
	}
	return timeoutSeconds, maxAttempts, nil
}

// validateScheduleName 校验计划名称。
func validateScheduleName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("%w: 计划名称不能为空", ErrInvalidRequest)
	}
	if utf8.RuneCountInString(name) > MaxScheduleNameRunes {
		return "", fmt.Errorf("%w: 计划名称超过 %d 个字符", ErrInvalidRequest, MaxScheduleNameRunes)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("%w: 计划名称不能包含控制字符", ErrInvalidRequest)
		}
	}
	return name, nil
}

// normalizeNotifyTarget 归一化通知渠道键；只接受安全 token，不保存收件地址。
func (s *Service) normalizeNotifyTarget(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return s.opts.DefaultNotifyTarget
	}
	if len(target) > MaxNotifyTargetBytes {
		return s.opts.DefaultNotifyTarget
	}
	for index := 0; index < len(target); index++ {
		c := target[index]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-') {
			return s.opts.DefaultNotifyTarget
		}
	}
	return target
}

// mapTaskError 把 internal/task 错误映射为本包稳定错误。
func mapTaskError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, task.ErrInvalidRequest), errors.Is(err, task.ErrOptionsInvalid):
		return fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	case errors.Is(err, task.ErrScheduleNotFound):
		return ErrNotFound
	case errors.Is(err, task.ErrScheduleForbidden):
		return ErrAccessDenied
	case errors.Is(err, task.ErrTaskNotFound):
		return ErrNotFound
	case errors.Is(err, task.ErrTaskTerminal):
		return fmt.Errorf("%w: %w", ErrConflict, err)
	case errors.Is(err, task.ErrTransitionRejected):
		return fmt.Errorf("%w: %w", ErrConflict, err)
	default:
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
}

// boolText 返回审计用布尔文本。
func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

// maxInt64 返回较大值。
func maxInt64(value, minimum int64) int64 {
	if value < minimum {
		return minimum
	}
	return value
}

// sha256Hex 返回字节的 SHA-256 十六进制。
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// sortArtifactsPublishedAsc 按发布时间升序（最早优先清理）。
func sortArtifactsPublishedAsc(artifacts []Artifact) {
	sort.SliceStable(artifacts, func(i, j int) bool {
		if artifacts[i].PublishedAt.Equal(artifacts[j].PublishedAt) {
			return artifacts[i].BackupID < artifacts[j].BackupID
		}
		return artifacts[i].PublishedAt.Before(artifacts[j].PublishedAt)
	})
}
