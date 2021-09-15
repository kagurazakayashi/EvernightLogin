// Package backup 实现 SQLite 一致性在线热备份、版本化加密容器、受认证加密保护的
// 清单与独立完整性校验（步骤 80）。
//
// 实现范围与安全不变量：
//   - 数据库快照只通过 SQLite 官方在线备份接口（sqlite3_backup，经
//     internal/storage/sqlite 的 modernc 驱动封装）生成，绝不复制运行中的主文件；
//     数据库持续写入时仍得到单一时间点的一致快照。
//   - 数据库、附件、配置有明确的捕获顺序与时间点：先在 T0 取得数据库一致性快照，
//     再按快照中的 avatars 引用在 T1 读取附件并逐个校验摘要（缺失/变化即失败，
//     不把互不一致的文件集合当完整备份），配置在 T2 作为独立文件读取；各时间点
//     与内容范围都写入清单。
//   - 容器格式版本化；清单包含条目路径/类型/大小/SHA-256、schema_history 最高
//     迁移、创建时间、主机与应用版本，并位于认证加密载荷内部。明文头部只含少量
//     元数据与加密参数，用于无密钥时的结构检查（明确标记未认证）。
//   - 加密使用 Go 标准库 AES-256-GCM（不做自创密码学）：每份备份随机生成 32 字节
//     载荷密钥，用项目既有 internal/secrets（主密钥环 AES-256-GCM 信封）认证加密
//     后放入头部；主密钥材料绝不进入备份文件。分块 nonce = 随机前缀 + 单调块序号，
//     AAD 绑定头部摘要、总长、块大小、块序号与最后一块标记，阻止截断/拼接/重排。
//     错误密钥、篡改与版本不支持分别映射到 BACKUP_DECRYPT_FAILED / BACKUP_INVALID /
//     BACKUP_VERSION_UNSUPPORTED，明确失败。
//   - 发布顺序固定：写受控临时文件 → fsync → 用同一校验器完整验证 → 删除明文暂存
//     目录 → 原子改名发布 → 写成功审计。审计不可用时创建请求/开始/成功/失败/
//     取消终止都按 fail-closed 处理，成功审计失败会删除已发布文件；失败/取消/
//     超时路径清理临时文件与暂存目录并把清理结果写入审计。
//   - 权限：创建需要 backups.create（系统范围），取消需要 backups.cancel 并由
//     服务端重新授权；真实取消者、发起者、取消原因与最终终止事件分别记录。取消
//     请求被接受不等于已取消：只有执行器观察到请求并完成清理后才写“已取消”终态；
//     完成与取消竞争时以真实最终状态为准。
//   - 本包不启动常驻协程、不监听端口、不提供 HTTP 路由、不执行恢复/上传；计划与
//     页面接入属于步骤 81。
package backup

import (
	"bufio"
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
)

// 权限键与稳定范围。权限键在 internal/preset 已登记（backups.create/cancel），
// 本步骤不新增权限键或错误码。
const (
	// PermissionCreate 是创建备份的权限。
	PermissionCreate = "backups.create"
	// PermissionCancel 是取消备份任务的权限。
	PermissionCancel = "backups.cancel"
	// ScopeSystem 是系统范围稳定 ID；备份覆盖整个数据库，不接受应用范围。
	ScopeSystem = "system"
	// TargetTypeBackup 是审计目标类型。
	TargetTypeBackup = "backup"
)

// 审计动作稳定标识。请求/开始/重试/成功/失败/取消请求/取消拒绝/实际取消分开。
const (
	ActionRequest        = "backup.request"
	ActionStarted        = "backup.started"
	ActionRetry          = "backup.retry"
	ActionFinish         = "backup.finish"
	ActionFailed         = "backup.failed"
	ActionCancelled      = "backup.cancelled"
	ActionCancelRequest  = "backup.cancel.request"
	ActionCancelRejected = "backup.cancel.rejected"
	ActionAccessDenied   = "backup.access.denied"
)

// 边界常量。所有上限都有硬边界，不静默截断。
const (
	// DefaultTimeout 是单次备份默认墙钟上限。
	DefaultTimeout = 10 * time.Minute
	// MinTimeout/MaxTimeout 是允许的墙钟上限范围。
	MinTimeout = 10 * time.Second
	MaxTimeout = 6 * time.Hour
	// DefaultMaxAttempts/MaxAllowedAttempts 是可重试瞬时不一致（SQLite BUSY、
	// 附件在快照后变化）的最大尝试次数；其它错误一律不重试。
	DefaultMaxAttempts = 2
	MaxAllowedAttempts = 5
	// DefaultRetryDelay/MaxRetryDelay 是重试间隔。
	DefaultRetryDelay = 2 * time.Second
	MaxRetryDelay     = 30 * time.Second
	// DefaultMaxBackupBytes/MaxAllowedBackupBytes 是单个备份载荷容量上限（防止
	// 无界写入占满磁盘；磁盘真实的 ENOSPC 也会以 BACKUP_FAILED 报告）。
	DefaultMaxBackupBytes = int64(8) << 30
	MinMaxBackupBytes     = int64(1) << 20
	MaxAllowedBackupBytes = int64(1) << 40
	// DefaultStaleTempAge 是“无法识别归属”的遗留临时文件清理门槛（默认 1 小时）；
	// 可识别备份编号的残留由运行锁立即判定活动/非活动，不等待该门槛。
	DefaultStaleTempAge = time.Hour
	MinStaleTempAge     = time.Minute
	MaxStaleTempAge     = 30 * 24 * time.Hour
	// MaxCancelReasonBytes 是取消原因上限。
	MaxCancelReasonBytes = 256
	// MaxDisplayFieldBytes 是主机名/应用版本等元数据上限。
	MaxDisplayFieldBytes = 128
	// 受控目录内临时文件/暂存目录命名前缀；清理只处理这些前缀。
	tempFilePrefix   = ".tmp-"
	tempFileSuffix   = ".elnbak.part"
	stagingDirPrefix = ".elnbak-staging-"
	// backupFilePrefix/backupFileSuffix 是最终备份文件名规则。
	backupFilePrefix = "login-backup_"
	backupFileSuffix = ".elnbak"
	// maxTempFileMode 是临时/最终备份文件的权限位（非 Windows 生效；Windows
	// 由受控输出目录 ACL 约束，文档明确该边界）。
	backupFileMode = 0o600
)

// Authorizer 复用统计服务的授权契约，确保装配层只有一套数据范围语义；实现
// 必须 fail-closed（依赖失败按拒绝处理）。
type Authorizer = stats.Authorizer

// AuditRecorder 是安全审计写入契约；实现必须 fail-closed。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
}

// Progress 是一次备份的进度快照。Phase 是稳定阶段名（snapshot/attachments/
// config/encrypt/verify/publish）；snapshot 阶段 Done/Total 是 SQLite 页数，
// 其它阶段是字节数。
type Progress struct {
	BackupID string
	Phase    string
	Done     int64
	Total    int64
}

// ProgressFunc 是进度回调。它必须快速返回；不得阻塞备份或写入秘密。
type ProgressFunc func(Progress)

// Options 是备份服务依赖与边界。Snapshotter/Keyring/Authorizer/Audit/OutputDir
// 缺失或非法时拒绝构造（fail-closed），不会使用测试替身顶替生产依赖。
type Options struct {
	// Snapshotter 生成数据库一致性快照；生产实现为 NewSQLiteSnapshotter。
	Snapshotter Snapshotter
	// Attachments 可选：提供后按数据库快照引用包含附件；未提供时清单显式记录
	// not_configured。
	Attachments AttachmentSource
	// Config 可选：提供后包含配置快照；未提供时清单显式记录 not_configured。
	Config ConfigSource
	// Keyring 是主密钥环提供者（与备份文件分离）；必填。
	Keyring secrets.Provider
	// Authorizer 复核 backups.create / backups.cancel 权限；必填。
	Authorizer Authorizer
	// Audit 是安全审计写入器；必填，写失败按 fail-closed 处理。
	Audit AuditRecorder
	// OutputDir 是备份产物受控目录：必须已存在的绝对路径目录、非符号链接；非
	// Windows 还要求不向组/其他用户开放写权限。
	OutputDir string
	// Hostname 是写入清单的主机标识；为空时使用 os.Hostname（仅元数据，非秘密）。
	Hostname string
	// AppVersion 是写入清单的应用版本；为空时记录 "unknown"。
	AppVersion string
	// Now 是可注入时钟；nil 使用 time.Now。
	Now func() time.Time
	// Random 是安全随机源；nil 使用 crypto/rand.Reader。
	Random io.Reader
	// Logger 是运行日志器；不得记录密钥、载荷、配置秘密或备份正文。
	Logger *slog.Logger
	// Timeout 是单次备份墙钟上限；0 使用默认 10 分钟。
	Timeout time.Duration
	// MaxAttempts 是瞬时不一致的最大尝试次数；0 使用默认 2，硬上限 5。
	MaxAttempts int
	// RetryDelay 是重试间隔；0 使用默认 2 秒，负数或超过上限拒绝构造。
	RetryDelay time.Duration
	// MaxBackupBytes 是单个备份载荷容量上限；0 使用默认 8 GiB。
	MaxBackupBytes int64
	// StaleTempAge 是无法识别归属的遗留临时文件年龄门槛；0 使用默认 1 小时，且必须大于备份墙钟上限。
	StaleTempAge time.Duration
	// Progress 可选进度回调。
	Progress ProgressFunc
}

// Service 是备份服务：构造后不可变，可被多个 goroutine 并发使用；不启动后台
// 协程、不提供 HTTP 路由。每个 Create 调用同步完成一次真实备份。
type Service struct {
	opts       Options
	outputDir  string
	hostname   string
	appVersion string
	chunkSize  int
	runs       *runRegistry
}

// CreateRequest 是手动触发一次备份的请求。Caller 必须来自可信调用上下文；
// 备份固定为系统范围（整个数据库），不接受应用范围参数。
type CreateRequest struct {
	Caller    account.Caller
	RequestID string
}

// Result 是一次成功备份的真实结果。Path 是宿主受控目录内的绝对路径（内部 API
// 使用；页面/HTTP 接入时必须按权限决定是否暴露，见步骤 81）。
type Result struct {
	BackupID       string
	FileName       string
	Path           string
	SHA256         string
	SizeBytes      int64
	PayloadBytes   int64
	CreatedAt      time.Time
	Database       DatabaseMeta
	Content        ContentMeta
	Entries        []EntryReport
	ManifestSHA256 string
	Attempts       int
	Duration       time.Duration
}

// CancelRequest 是取消一次活动备份的请求。取消是请求而不是立即终止：只有执行器
// 观察到请求并完成清理后才写“已取消”终态并返回 ErrCancelled。
type CancelRequest struct {
	Caller    account.Caller
	BackupID  string
	Reason    string
	RequestID string
}

// CancelResult 是取消请求被接受的结果。BackupID/RequestedAt 用于后续查询真实
// 终态；此时备份仍在运行，不能显示为已取消。
type CancelResult struct {
	BackupID    string
	RequestedAt time.Time
}

// New 校验选项并构造备份服务；不会创建输出文件、不会连接数据库、不会执行备份。
func New(options Options) (*Service, error) {
	if isNilDependency(options.Snapshotter) {
		return nil, fmt.Errorf("%w: 缺少数据库一致性快照实现", ErrOptionsInvalid)
	}
	if isNilDependency(options.Keyring) {
		return nil, fmt.Errorf("%w: 缺少主密钥环提供者", ErrOptionsInvalid)
	}
	if isNilDependency(options.Authorizer) {
		return nil, fmt.Errorf("%w: 缺少备份权限授权器", ErrOptionsInvalid)
	}
	if isNilDependency(options.Audit) {
		return nil, fmt.Errorf("%w: 缺少安全审计写入器", ErrOptionsInvalid)
	}
	outputDir, err := validateOutputDir(options.OutputDir)
	if err != nil {
		return nil, err
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Random == nil {
		options.Random = cryptorand.Reader
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard,
			&slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	if options.Timeout == 0 {
		options.Timeout = DefaultTimeout
	}
	if options.Timeout < MinTimeout || options.Timeout > MaxTimeout {
		return nil, fmt.Errorf("%w: 备份墙钟上限必须在 %s～%s 之间",
			ErrOptionsInvalid, MinTimeout, MaxTimeout)
	}
	if options.MaxAttempts == 0 {
		options.MaxAttempts = DefaultMaxAttempts
	}
	if options.MaxAttempts < 1 || options.MaxAttempts > MaxAllowedAttempts {
		return nil, fmt.Errorf("%w: 备份尝试次数必须在 1～%d 之间",
			ErrOptionsInvalid, MaxAllowedAttempts)
	}
	if options.RetryDelay == 0 {
		options.RetryDelay = DefaultRetryDelay
	}
	if options.RetryDelay < 0 || options.RetryDelay > MaxRetryDelay {
		return nil, fmt.Errorf("%w: 备份重试间隔超过上限", ErrOptionsInvalid)
	}
	if options.MaxBackupBytes == 0 {
		options.MaxBackupBytes = DefaultMaxBackupBytes
	}
	if options.MaxBackupBytes < MinMaxBackupBytes ||
		options.MaxBackupBytes > MaxAllowedBackupBytes {
		return nil, fmt.Errorf("%w: 备份容量上限超出允许范围", ErrOptionsInvalid)
	}
	if options.StaleTempAge == 0 {
		options.StaleTempAge = DefaultStaleTempAge
		if options.StaleTempAge <= options.Timeout {
			options.StaleTempAge = options.Timeout + time.Minute
		}
	}
	if options.StaleTempAge < MinStaleTempAge || options.StaleTempAge > MaxStaleTempAge {
		return nil, fmt.Errorf("%w: 临时文件清理门槛超出允许范围", ErrOptionsInvalid)
	}
	// 门槛必须严格大于单次备份墙钟上限，避免把仍在运行的备份残留当作“过期”清理；
	// 可识别归属的残留另有运行锁保护，不需要依赖该年龄门槛。
	if options.StaleTempAge <= options.Timeout {
		return nil, fmt.Errorf("%w: 临时文件清理门槛必须大于备份墙钟上限", ErrOptionsInvalid)
	}
	hostname := options.Hostname
	if hostname == "" {
		if detected, hostErr := os.Hostname(); hostErr == nil {
			hostname = detected
		}
	}
	hostname = sanitizeDisplayValue(hostname)
	if hostname == "" {
		hostname = "unknown"
	}
	appVersion := sanitizeDisplayValue(options.AppVersion)
	if appVersion == "" {
		appVersion = "unknown"
	}
	return &Service{
		opts:       options,
		outputDir:  outputDir,
		hostname:   hostname,
		appVersion: appVersion,
		chunkSize:  DefaultChunkSize,
		runs:       newRunRegistry(),
	}, nil
}

// Create 同步执行一次手动备份：授权 → 审计请求/开始 → 一致性快照 → 附件/配置 →
// 版本化清单 → 认证加密 → fsync → 完整校验 → 原子发布 → 成功审计。任何失败都会
// 清理临时文件并按真实终态写审计；成功审计写失败时删除已发布文件并返回失败。
func (s *Service) Create(ctx context.Context, request CreateRequest) (Result, error) {
	ctx = normalizeContext(ctx)
	if s == nil || s.opts.Snapshotter == nil {
		return Result{}, fmt.Errorf("%w: 备份服务未初始化", ErrOptionsInvalid)
	}
	actor := request.Caller.Actor()
	if err := actor.Validate(); err != nil {
		// 无合法可信身份：不写审计（无法归属），直接拒绝。
		return Result{}, fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	requestID := normalizeCorrelationID(request.RequestID)
	if requestID == "" {
		requestID = normalizeCorrelationID(request.Caller.RequestID())
	}
	if err := s.authorize(ctx, request.Caller, PermissionCreate); err != nil {
		s.recordDenied(ctx, actor, requestID, PermissionCreate)
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrCancelled, err)
	}
	backupID, err := newBackupID(s.opts.Random)
	if err != nil {
		return Result{}, err
	}
	state := &runState{id: backupID, initiator: actor}
	if err := s.runs.register(state); err != nil {
		return Result{}, err
	}
	defer s.runs.unregister(backupID)

	// 清理历史进程中断遗留的临时文件/暂存目录。清理失败只记录告警，不阻塞本次
	// 备份（本次文件使用新的随机名，不会被误删）。
	s.cleanupStaleTemps(ctx)

	requestEvent := audit.Event{
		Actor: actor, Action: ActionRequest, Target: audit.Target{Type: TargetTypeBackup, ID: backupID},
		Outcome: audit.OutcomeSuccess, RequestID: requestID,
		Changes: []audit.FieldChange{
			{Field: "scope", After: ScopeSystem},
			{Field: "attachments", After: s.attachmentsStatus()},
			{Field: "config", After: s.configStatus()},
		},
	}
	if err := s.record(ctx, requestEvent); err != nil {
		return Result{}, err
	}
	startedAt := s.now()
	startedEvent := audit.Event{
		Actor: actor, Action: ActionStarted, Target: audit.Target{Type: TargetTypeBackup, ID: backupID},
		Outcome: audit.OutcomeSuccess, RequestID: requestID,
		Changes: []audit.FieldChange{
			{Field: "state", After: "running"},
			{Field: "database", After: "sqlite"},
		},
	}
	if err := s.record(ctx, startedEvent); err != nil {
		return Result{}, err
	}
	// 主密钥环读取失败也算一次真实失败：写失败终态审计并返回，不进入快照阶段。
	ring, err := secrets.LoadKeyring(ctx, s.opts.Keyring)
	if err != nil {
		return s.finishFailure(ctx, state, requestID, startedAt, 1,
			&attemptError{stage: "keyring",
				cause: fmt.Errorf("%w: 无法读取主密钥环", ErrOptionsInvalid)})
	}

	workCtx, cancel := context.WithTimeoutCause(ctx, s.opts.Timeout, errTimeoutCause)
	defer cancel()
	var lastErr error
	attempts := 0
	for attempt := 1; attempt <= s.opts.MaxAttempts; attempt++ {
		attempts = attempt
		if attempt > 1 {
			if sleepErr := contextSleep(ctx, s.opts.RetryDelay); sleepErr != nil {
				lastErr = sleepErr
				break
			}
			retryEvent := audit.Event{
				Actor: actor, Action: ActionRetry,
				Target:  audit.Target{Type: TargetTypeBackup, ID: backupID},
				Outcome: audit.OutcomeFailure, RequestID: requestID,
				ErrorCode: string(CodeOf(lastErr)), ReasonCode: stageOf(lastErr),
				Changes: []audit.FieldChange{
					{Field: "attempt", After: strconv.Itoa(attempt)},
					{Field: "previous_stage", After: stageOf(lastErr)},
				},
			}
			if auditErr := s.record(ctx, retryEvent); auditErr != nil {
				lastErr = auditErr
				break
			}
		}
		result, attemptErr := s.runAttempt(workCtx, ring, state, attempt)
		if attemptErr == nil {
			return s.finishSuccess(ctx, state, requestID, startedAt, result)
		}
		lastErr = attemptErr
		if workCtx.Err() != nil {
			lastErr = terminalContextError(workCtx, attemptErr)
			break
		}
		if !retryable(attemptErr) || attempt == s.opts.MaxAttempts {
			break
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("%w: 备份未产生结果", ErrInternal)
	}
	return s.finishFailure(ctx, state, requestID, startedAt, attempts, lastErr)
}

// OutputDir 返回受控输出目录绝对路径。它只供诊断与恢复前容量检查使用，不暴露
// 密钥材料；调用方不得把它当公开下载路径。
func (s *Service) OutputDir() string {
	if s == nil {
		return ""
	}
	return s.outputDir
}

// RequestCancel 提交一次取消请求。权限、任务存在性与状态由服务端检查；请求被
// 接受只表示执行器会观察到它，不表示任务已取消。实际终止由执行器在清理完成后
// 写 ActionCancelled 终态事件。
func (s *Service) RequestCancel(ctx context.Context, request CancelRequest) (CancelResult, error) {
	ctx = normalizeContext(ctx)
	if s == nil {
		return CancelResult{}, fmt.Errorf("%w: 备份服务未初始化", ErrOptionsInvalid)
	}
	actor := request.Caller.Actor()
	if err := actor.Validate(); err != nil {
		return CancelResult{}, fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	requestID := normalizeCorrelationID(request.RequestID)
	if requestID == "" {
		requestID = normalizeCorrelationID(request.Caller.RequestID())
	}
	reason, err := validCancelReason(request.Reason)
	if err != nil {
		return CancelResult{}, err
	}
	if err := s.authorizeCancel(ctx, request.Caller); err != nil {
		s.recordCancelRejected(ctx, actor, request.RequestID, request.BackupID,
			string(CodeBackupCancelForbidden), reason)
		return CancelResult{}, err
	}
	state := s.runs.lookup(request.BackupID)
	if state == nil {
		s.recordCancelRejected(ctx, actor, requestID, request.BackupID,
			string(CodeTaskCancelConflict), reason)
		return CancelResult{}, fmt.Errorf("%w: 备份任务不存在或已结束", ErrCancelConflict)
	}
	if state.terminal() {
		s.recordCancelRejected(ctx, actor, requestID, request.BackupID,
			string(CodeTaskCancelConflict), reason)
		return CancelResult{}, fmt.Errorf("%w: 备份任务已结束", ErrCancelConflict)
	}
	// 取消请求审计必须成功才接受请求（fail-closed）；审计失败时不改变任务状态。
	requestedAt := s.now()
	cancelEvent := audit.Event{
		Actor: actor, Action: ActionCancelRequest,
		Target:  audit.Target{Type: TargetTypeBackup, ID: request.BackupID},
		Outcome: audit.OutcomeSuccess, RequestID: requestID,
		Changes: []audit.FieldChange{
			{Field: "requested_by", After: actor.ID},
			{Field: "reason", After: truncateUTF8(reason, 200)},
		},
	}
	if err := s.record(ctx, cancelEvent); err != nil {
		return CancelResult{}, err
	}
	if err := state.requestCancel(actor, reason, requestedAt); err != nil {
		s.recordCancelRejected(ctx, actor, requestID, request.BackupID,
			string(CodeTaskCancelConflict), reason)
		return CancelResult{}, err
	}
	return CancelResult{BackupID: request.BackupID, RequestedAt: requestedAt}, nil
}

// finishSuccess 在文件已发布后写成功审计。审计不可用时删除已发布文件并返回
// ErrAuditUnavailable，绝不留下一份“无成功审计”的成功结果。
func (s *Service) finishSuccess(ctx context.Context, state *runState, requestID string,
	startedAt time.Time, result Result) (Result, error) {
	auditCtx := context.WithoutCancel(normalizeContext(ctx))
	cancelled, canceller, reason, _ := state.cancelInfo()
	changes := []audit.FieldChange{
		{Field: "state", After: "succeeded"},
		{Field: "file_sha256", After: result.SHA256},
		{Field: "size_bytes", After: strconv.FormatInt(result.SizeBytes, 10)},
		{Field: "database_schema", After: result.Database.SchemaVersion},
		{Field: "entries", After: strconv.Itoa(len(result.Entries))},
		{Field: "attempts", After: strconv.Itoa(result.Attempts)},
		{Field: "duration_ms", After: strconv.FormatInt(result.Duration.Milliseconds(), 10)},
		{Field: "attachments", After: result.Content.Attachments.Status},
		{Field: "config", After: result.Content.Config.Status},
	}
	if cancelled {
		// 理论上接受取消后会在发布前终止；这里防御性记录，避免静默丢失请求。
		changes = append(changes,
			audit.FieldChange{Field: "cancel_requested_by", After: canceller.ID},
			audit.FieldChange{Field: "cancel_request_reason", After: truncateUTF8(reason, 120)},
			audit.FieldChange{Field: "cancel_effective", After: "no"})
	}
	event := audit.Event{
		Actor: state.initiator, Action: ActionFinish,
		Target:  audit.Target{Type: TargetTypeBackup, ID: result.BackupID},
		Outcome: audit.OutcomeSuccess, RequestID: requestID, Changes: changes,
	}
	if err := s.record(auditCtx, event); err != nil {
		// 删除已发布文件（best effort）。删除失败必须如实报告并提示残留风险。
		removeErr := os.Remove(result.Path)
		if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			s.opts.Logger.Error("成功审计失败且已发布备份无法回滚删除",
				"backup_id", result.BackupID, "error", removeErr)
			return Result{}, errors.Join(err,
				fmt.Errorf("%w: 已发布备份文件无法回滚删除", ErrCleanupFailed))
		}
		return Result{}, err
	}
	return result, nil
}

// finishFailure 写入失败/取消/超时的真实终态审计并返回对应错误。取消请求已接受
// 但运行以其它终态结束时，事件记录真实终态并注明取消请求未生效。
func (s *Service) finishFailure(ctx context.Context, state *runState, requestID string,
	startedAt time.Time, attempts int, cause error) (Result, error) {
	auditCtx := context.WithoutCancel(normalizeContext(ctx))
	stage := stageOf(cause)
	cleanupFailed := hasCleanupFailure(cause)
	changes := []audit.FieldChange{
		{Field: "attempts", After: strconv.Itoa(attempts)},
		{Field: "stage", After: defaultString(stage, "unknown")},
		{Field: "duration_ms", After: strconv.FormatInt(s.now().Sub(startedAt).Milliseconds(), 10)},
	}
	if cleanupFailed {
		changes = append(changes, audit.FieldChange{Field: "cleanup", After: "failed"})
	} else {
		changes = append(changes, audit.FieldChange{Field: "cleanup", After: "ok"})
	}
	cancelled, canceller, reason, _ := state.cancelInfo()
	isCancelled := errors.Is(cause, ErrCancelled) ||
		errors.Is(cause, context.Canceled)
	isTimeout := errors.Is(cause, ErrTimeout) ||
		errors.Is(cause, context.DeadlineExceeded)
	var finalErr error
	event := audit.Event{
		Actor: state.initiator, Target: audit.Target{Type: TargetTypeBackup, ID: state.id},
		Outcome: audit.OutcomeFailure, RequestID: requestID,
	}
	switch {
	case isTimeout:
		finalErr = fmt.Errorf("%w: %w", ErrTimeout, cause)
		event.Action = ActionFailed
		event.ErrorCode = string(CodeTaskTimeout)
		event.ReasonCode = sanitizeReasonCode(stage)
		changes = append(changes, audit.FieldChange{Field: "state", After: "timed_out"})
		if cancelled {
			changes = append(changes,
				audit.FieldChange{Field: "cancel_requested_by", After: canceller.ID},
				audit.FieldChange{Field: "cancel_effective", After: "no"})
		}
	case isCancelled:
		finalErr = fmt.Errorf("%w: %w", ErrCancelled, cause)
		event.Action = ActionCancelled
		event.ErrorCode = string(CodeTaskCancelled)
		event.ReasonCode = sanitizeReasonCode(stage)
		changes = append(changes, audit.FieldChange{Field: "state", After: "cancelled"})
		source := "context"
		if cancelled {
			source = "request"
			changes = append(changes,
				audit.FieldChange{Field: "cancelled_by", After: canceller.ID},
				audit.FieldChange{Field: "reason", After: truncateUTF8(reason, 160)})
		} else {
			// 没有已接受取消请求时的终止来源是发起者上下文取消/停机；记录真实
			// 来源而不是伪造一个取消者。
			canceller = state.initiator
			changes = append(changes,
				audit.FieldChange{Field: "cancelled_by", After: state.initiator.ID},
				audit.FieldChange{Field: "reason", After: "caller context cancelled"})
		}
		changes = append(changes, audit.FieldChange{Field: "cancel_source", After: source})
		_ = canceller
	default:
		finalErr = cause
		event.Action = ActionFailed
		event.ErrorCode = string(CodeOf(cause))
		event.ReasonCode = sanitizeReasonCode(stage)
		changes = append(changes, audit.FieldChange{Field: "state", After: "failed"})
		if cancelled {
			changes = append(changes,
				audit.FieldChange{Field: "cancel_requested_by", After: canceller.ID},
				audit.FieldChange{Field: "cancel_effective", After: "no"})
		}
	}
	event.Changes = changes
	if err := s.recordFailure(auditCtx, event); err != nil {
		return Result{}, errors.Join(finalErr, err)
	}
	return Result{}, finalErr
}

// runAttempt 执行一次完整的“快照 → 清单 → 加密 → fsync → 校验 → 发布”尝试。
// 所有失败路径显式清理临时文件与暂存目录，并把清理结果封装进错误供审计。
func (s *Service) runAttempt(ctx context.Context, ring *secrets.Keyring,
	state *runState, attempt int) (Result, error) {
	attemptStarted := s.now()
	// 运行锁必须先于暂存目录/临时文件创建，保证“安全清理”能把本进程或其它进程
	// 正在写入的残留与死亡进程的残留可靠区分；强杀后系统自动释放锁。
	lock, lockErr := acquireRunLock(lockFilePath(s.outputDir, state.id))
	if lockErr != nil {
		return Result{}, fmt.Errorf("%w: 无法取得备份运行锁", ErrOutputDirUnsafe)
	}
	defer lock.Release()
	stagingDir, err := os.MkdirTemp(s.outputDir, stagingDirPrefix+safeName(state.id)+"-")
	if err != nil {
		return Result{}, fmt.Errorf("%w: 无法创建受控暂存目录", ErrOutputDirUnsafe)
	}
	var tempPath string
	succeeded := false
	defer func() {
		if !succeeded {
			_ = cleanupAttemptPaths(tempPath, stagingDir)
		}
	}()
	fail := func(stage string, cause error) (Result, error) {
		cleanupErr := cleanupAttemptPaths(tempPath, stagingDir)
		return Result{}, &attemptError{stage: stage, cleanupErr: cleanupErr, cause: cause}
	}

	// 1) 数据库一致性在线快照（T0）。
	s.reportProgress(Progress{BackupID: state.id, Phase: "snapshot"})
	snapshotPath := filepath.Join(stagingDir, "database.sqlite")
	snapshotStarted := s.now()
	snapshotInfo, snapErr := s.opts.Snapshotter.Snapshot(ctx, snapshotPath,
		func(done, total int) {
			s.reportProgress(Progress{BackupID: state.id, Phase: "snapshot",
				Done: int64(done), Total: int64(total)})
		})
	if snapErr != nil {
		return fail("snapshot", fmt.Errorf("%w: %w", ErrSnapshotFailed, snapErr))
	}
	snapshotFinished := s.now()
	if err := s.checkCancelled(ctx, state); err != nil {
		return fail("snapshot", err)
	}
	databaseSize, databaseSHA, err := hashFile(ctx, snapshotPath)
	if err != nil {
		return fail("snapshot_hash", err)
	}
	if databaseSize <= 0 || databaseSize > s.opts.MaxBackupBytes {
		return fail("snapshot_size", fmt.Errorf("%w: 数据库快照超出容量上限",
			ErrTooLarge))
	}

	// 2) 附件按数据库快照中的引用读取并校验（T1）。
	content := ContentMeta{
		Database:    true,
		Attachments: ContentStatus{Status: ContentNotConfigured},
		Config:      ContentStatus{Status: ContentNotConfigured},
		Keyring:     ContentStatus{Status: ContentExcluded},
	}
	var attachments []AttachmentInfo
	attachmentsCapturedAt := ""
	if s.opts.Attachments != nil {
		s.reportProgress(Progress{BackupID: state.id, Phase: "attachments"})
		listed, listErr := s.opts.Attachments.List(ctx, snapshotPath)
		if listErr != nil {
			return fail("attachments", listErr)
		}
		attachmentsCapturedAt = formatTime(s.now())
		attachments = listed
		if len(attachments) == 0 {
			content.Attachments = ContentStatus{Status: ContentNoReferences}
		} else {
			content.Attachments = ContentStatus{Status: ContentIncluded,
				Count: len(attachments)}
		}
	}
	if err := s.checkCancelled(ctx, state); err != nil {
		return fail("attachments", err)
	}

	// 3) 配置快照（T2，独立文件，不属于数据库事务）。
	var configData []byte
	configCapturedAt := ""
	if s.opts.Config != nil {
		s.reportProgress(Progress{BackupID: state.id, Phase: "config"})
		config, configErr := s.opts.Config.SnapshotConfig(ctx)
		if configErr != nil {
			return fail("config", configErr)
		}
		if config.EntryName != configEntryName || config.Format != "yaml" ||
			len(config.Data) == 0 {
			return fail("config", fmt.Errorf("%w: 配置快照内容非法", ErrOptionsInvalid))
		}
		configData = config.Data
		content.Config = ContentStatus{Status: ContentIncluded, Count: 1, Format: "yaml"}
		configCapturedAt = formatTime(s.now())
	}
	if err := s.checkCancelled(ctx, state); err != nil {
		return fail("config", err)
	}

	// 4) 构建版本化清单与载荷来源（顺序必须与清单一致）。
	attachmentEntries := append([]AttachmentInfo(nil), attachments...)
	sort.Slice(attachmentEntries, func(left, right int) bool {
		return attachmentEntries[left].EntryName < attachmentEntries[right].EntryName
	})
	entries := make([]ManifestEntry, 0, len(attachmentEntries)+2)
	entries = append(entries, ManifestEntry{Name: databaseEntryName,
		Kind: EntryKindDatabase, SizeBytes: databaseSize, SHA256: databaseSHA})
	for _, attachment := range attachmentEntries {
		if err := validateEntryName(EntryKindAttachment, attachment.EntryName); err != nil {
			return fail("manifest", err)
		}
		if attachment.SizeBytes <= 0 {
			return fail("manifest", fmt.Errorf("%w: 附件大小非法", ErrInvalidRequest))
		}
		entries = append(entries, ManifestEntry{Name: attachment.EntryName,
			Kind: EntryKindAttachment, SizeBytes: attachment.SizeBytes,
			SHA256: hex.EncodeToString(attachment.SHA256[:])})
	}
	if len(configData) > 0 {
		configDigest := sha256.Sum256(configData)
		entries = append(entries, ManifestEntry{Name: configEntryName,
			Kind: EntryKindConfig, SizeBytes: int64(len(configData)),
			SHA256: hex.EncodeToString(configDigest[:])})
	}
	if len(entries) > MaxEntries {
		return fail("manifest", fmt.Errorf("%w: 备份条目数量超过上限", ErrTooLarge))
	}
	totalEntryBytes := int64(0)
	for _, entry := range entries {
		if entry.SizeBytes > s.opts.MaxBackupBytes ||
			totalEntryBytes > s.opts.MaxBackupBytes-entry.SizeBytes {
			return fail("manifest", fmt.Errorf("%w: 备份内容超过容量上限", ErrTooLarge))
		}
		totalEntryBytes += entry.SizeBytes
	}
	createdAt := snapshotStarted.Truncate(time.Millisecond)
	manifest := Manifest{
		FormatVersion: FormatVersion,
		BackupID:      state.id,
		CreatedAt:     formatTime(createdAt),
		Host:          s.hostname,
		AppVersion:    s.appVersion,
		Database: ManifestDatabase{Engine: "sqlite",
			SchemaVersion:       snapshotInfo.SchemaVersion,
			SchemaVersionNumber: snapshotInfo.SchemaVersionNumber},
		Capture: CaptureInfo{
			DatabaseSnapshotStartedAt:  formatTime(snapshotStarted),
			DatabaseSnapshotFinishedAt: formatTime(snapshotFinished),
			AttachmentsCapturedAt:      attachmentsCapturedAt,
			ConfigCapturedAt:           configCapturedAt,
		},
		Content: content,
		Entries: entries,
	}
	manifestRaw, err := marshalManifest(manifest)
	if err != nil {
		return fail("manifest", err)
	}
	manifestDigest := sha256.Sum256(manifestRaw)
	plainBytes := int64(4) + int64(len(manifestRaw)) + totalEntryBytes
	chunks := PayloadChunks(plainBytes, s.chunkSize)
	cipherBytes := plainBytes + chunks*int64(aeadTagBytes)
	dataKey, err := generateDataKey(s.opts.Random)
	if err != nil {
		return fail("encrypt", err)
	}
	keyID, wrappedKey, err := wrapDataKey(ring, state.id, dataKey)
	if err != nil {
		return fail("encrypt", err)
	}
	noncePrefix := make([]byte, NoncePrefixBytes)
	if _, err := io.ReadFull(s.opts.Random, noncePrefix); err != nil {
		return fail("encrypt", fmt.Errorf("%w: 无法生成备份 nonce", ErrInternal))
	}
	header := Header{
		FormatVersion: FormatVersion,
		BackupID:      state.id,
		CreatedAt:     manifest.CreatedAt,
		Host:          s.hostname,
		AppVersion:    s.appVersion,
		Database: DatabaseMeta{Engine: "sqlite",
			SchemaVersion:       snapshotInfo.SchemaVersion,
			SchemaVersionNumber: snapshotInfo.SchemaVersionNumber,
			SizeBytes:           databaseSize, SHA256: databaseSHA},
		Content:        content,
		EntriesCount:   len(entries),
		ManifestSHA256: hex.EncodeToString(manifestDigest[:]),
		Encryption: EncryptionInfo{
			Algorithm:          EncryptionAlgorithm,
			Format:             EncryptionFormat,
			ChunkSizeBytes:     s.chunkSize,
			NoncePrefix:        base64.StdEncoding.EncodeToString(noncePrefix),
			KeyID:              keyID,
			WrappedDataKey:     base64.StdEncoding.EncodeToString(wrappedKey),
			PayloadPlainBytes:  plainBytes,
			PayloadCipherBytes: cipherBytes,
		},
	}
	headerRaw, err := marshalHeader(header)
	if err != nil {
		return fail("encrypt", err)
	}

	// 5) 写临时文件：前缀 + 头部 + 分块加密载荷 + 固定 SHA-256 尾字段。
	tempPath = filepath.Join(s.outputDir, tempFilePrefix+safeName(state.id)+tempFileSuffix)
	file, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, backupFileMode)
	if err != nil {
		return fail("encrypt", fmt.Errorf("%w: 无法创建备份临时文件", ErrBackupIO))
	}
	writer := bufio.NewWriterSize(file, 256*1024)
	if _, err := writer.Write(filePrefix(headerRaw)); err != nil {
		_ = file.Close()
		return fail("encrypt", fmt.Errorf("%w: 写入备份头部失败", ErrBackupIO))
	}
	frame := make([]byte, 4)
	binary.BigEndian.PutUint32(frame, uint32(len(manifestRaw)))
	frame = append(frame, manifestRaw...)
	frameDigest := sha256.Sum256(frame)
	sources := []entrySource{
		{name: "manifest", size: int64(len(frame)), sha256: frameDigest,
			open: func(context.Context) (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(frame)), nil
			}, mismatchErr: ErrInternal},
		{name: databaseEntryName, size: databaseSize, sha256: hexDigest(databaseSHA),
			open: func(context.Context) (io.ReadCloser, error) {
				return os.Open(snapshotPath)
			}, mismatchErr: ErrIntegrityFailed},
	}
	for _, attachment := range attachmentEntries {
		info := attachment
		sources = append(sources, entrySource{name: info.EntryName,
			size: info.SizeBytes, sha256: info.SHA256, open: func(openCtx context.Context) (io.ReadCloser, error) {
				return s.opts.Attachments.Open(openCtx, info.EntryName)
			}, mismatchErr: ErrAttachmentInconsistent})
	}
	if len(configData) > 0 {
		configDigest := sha256.Sum256(configData)
		sources = append(sources, entrySource{name: configEntryName,
			size: int64(len(configData)), sha256: configDigest,
			open: func(context.Context) (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(configData)), nil
			}, mismatchErr: ErrAttachmentInconsistent})
	}
	sourceReader := &entrySourcesReader{
		ctx: ctx, sources: sources,
		check: func() error { return s.checkCancelled(ctx, state) },
	}
	digest := headerHash(headerRaw)
	cipherBytesWritten, cipherDigest, err := encryptPayload(writer, sourceReader,
		plainBytes, s.chunkSize, dataKey, noncePrefix, digest)
	if err != nil {
		_ = sourceReader.Close()
		_ = file.Close()
		return fail("encrypt", err)
	}
	if err := sourceReader.Close(); err != nil {
		_ = file.Close()
		return fail("encrypt", err)
	}
	if cipherBytesWritten != cipherBytes {
		_ = file.Close()
		return fail("encrypt", fmt.Errorf("%w: 密文字节数与头部声明不一致", ErrInternal))
	}
	// 密文后写固定 32 字节 SHA-256 尾字段；它不承担认证职责，只用于无密钥结构
	// 检查与位翻转/截断检测（认证完整性由分块 AEAD 保证）。
	if _, err := writer.Write(cipherDigest[:]); err != nil {
		_ = file.Close()
		return fail("encrypt", fmt.Errorf("%w: 写入备份密文摘要失败", ErrBackupIO))
	}
	if err := writer.Flush(); err != nil {
		_ = file.Close()
		return fail("encrypt", fmt.Errorf("%w: 刷新备份文件失败", ErrBackupIO))
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fail("encrypt", fmt.Errorf("%w: 同步备份文件失败", ErrBackupIO))
	}
	if err := file.Close(); err != nil {
		return fail("encrypt", fmt.Errorf("%w: 关闭备份文件失败", ErrBackupIO))
	}
	if err := s.checkCancelled(ctx, state); err != nil {
		return fail("encrypt", err)
	}

	// 6) 用同一校验器完整验证临时文件（解密 + 清单 + 条目摘要 + 长度）。
	s.reportProgress(Progress{BackupID: state.id, Phase: "verify",
		Done: 0, Total: cipherBytes})
	report, verifyErr := VerifyFile(ctx, tempPath, ring)
	if verifyErr != nil {
		return fail("verify", fmt.Errorf("%w: %w", ErrIntegrityFailed, verifyErr))
	}
	if err := s.checkCancelled(ctx, state); err != nil {
		return fail("verify", err)
	}

	// 7) 终态决策与发布：先原子标记“完成”，此后到达的取消请求按已结束拒绝，
	// 保证“取消请求被接受”与最终终态不会矛盾。
	if cancelled, _, _, _ := state.claimFinish(); cancelled {
		return fail("publish", fmt.Errorf("%w: 发布前收到取消请求", ErrCancelled))
	}
	if err := os.RemoveAll(stagingDir); err != nil {
		return fail("cleanup", fmt.Errorf("%w: 无法删除明文暂存目录: %w",
			ErrCleanupFailed, err))
	}
	stagingDir = ""
	if err := s.checkCancelled(ctx, state); err != nil {
		return fail("publish", err)
	}
	fileName := backupFileName(createdAt, state.id)
	finalPath, publishErr := publishFile(tempPath, s.outputDir, fileName)
	if publishErr != nil {
		return fail("publish", publishErr)
	}
	tempPath = ""
	succeeded = true
	if err := syncDir(s.outputDir); err != nil {
		// 目录项同步失败不回滚已发布的完整文件，但记录告警；文件内容已 fsync。
		s.opts.Logger.Warn("备份目录同步失败", "backup_id", state.id, "error", err)
	}
	s.reportProgress(Progress{BackupID: state.id, Phase: "done",
		Done: report.FileSize, Total: report.FileSize})
	return Result{
		BackupID:       state.id,
		FileName:       fileName,
		Path:           finalPath,
		SHA256:         report.FileSHA256,
		SizeBytes:      report.FileSize,
		PayloadBytes:   report.Encryption.PayloadPlainBytes,
		CreatedAt:      report.CreatedAt,
		Database:       report.Database,
		Content:        report.Content,
		Entries:        report.Entries,
		ManifestSHA256: report.ManifestSHA256,
		Attempts:       attempt,
		Duration:       s.now().Sub(attemptStarted),
	}, nil
}

// checkCancelled 在执行阶段边界检查已接受的取消请求与 ctx 取消/超时。取消请求
// 优先于 ctx 错误报告，以便审计记录真实取消者。
func (s *Service) checkCancelled(ctx context.Context, state *runState) error {
	if cancelled, _, _, _ := state.cancelInfo(); cancelled {
		return fmt.Errorf("%w: 执行器观察到已接受的取消请求", ErrCancelled)
	}
	if err := ctx.Err(); err != nil {
		return terminalContextError(ctx, err)
	}
	return nil
}

// terminalContextError 把 ctx 终止原因转换为领域错误：内部墙钟超时映射 ErrTimeout，
// 其它取消映射 ErrCancelled。
func terminalContextError(ctx context.Context, cause error) error {
	if ctx != nil {
		if errors.Is(context.Cause(ctx), errTimeoutCause) {
			return fmt.Errorf("%w: %w", ErrTimeout, cause)
		}
	}
	return fmt.Errorf("%w: %w", ErrCancelled, cause)
}

// authorize 复核功能权限与系统范围；依赖失败按拒绝处理。
func (s *Service) authorize(ctx context.Context, caller account.Caller, permission string) error {
	grant, err := s.opts.Authorizer.AuthorizeScope(ctx, caller, permission, ScopeSystem)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	if !grant.Allowed {
		return ErrAccessDenied
	}
	if !grant.AllData && !containsString(grant.ResourceIDs, ScopeSystem) {
		return ErrAccessDenied
	}
	return nil
}

// authorizeCancel 复核取消权限；无权取消映射为 BACKUP_CANCEL_FORBIDDEN。
func (s *Service) authorizeCancel(ctx context.Context, caller account.Caller) error {
	grant, err := s.opts.Authorizer.AuthorizeScope(ctx, caller, PermissionCancel, ScopeSystem)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCancelForbidden, err)
	}
	if !grant.Allowed || (!grant.AllData && !containsString(grant.ResourceIDs, ScopeSystem)) {
		return ErrCancelForbidden
	}
	return nil
}

// record 写审计；失败包装为 ErrAuditUnavailable（调用方 fail-closed）。
func (s *Service) record(ctx context.Context, event audit.Event) error {
	if err := s.opts.Audit.Record(normalizeContext(ctx), event); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	return nil
}

// recordFailure 使用可靠失败审计写入（不受调用方取消影响）。
func (s *Service) recordFailure(ctx context.Context, event audit.Event) error {
	if err := s.opts.Audit.RecordFailure(normalizeContext(ctx), event); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	return nil
}

// recordDenied 尽力记录权限拒绝审计；拒绝结论不因审计失败而改变。
func (s *Service) recordDenied(ctx context.Context, actor audit.Actor, requestID,
	permission string) {
	event := audit.Event{
		Actor: actor, Action: ActionAccessDenied, Target: audit.Target{Type: TargetTypeBackup},
		Outcome: audit.OutcomeDenied, ErrorCode: string(CodeAccessDenied),
		RequestID: requestID,
		Changes:   []audit.FieldChange{{Field: "permission", After: permission}},
	}
	_ = s.opts.Audit.Record(normalizeContext(ctx), event)
}

// recordCancelRejected 尽力记录取消被拒绝审计（未知/已结束/无权）。
func (s *Service) recordCancelRejected(ctx context.Context, actor audit.Actor,
	requestID, backupID, errorCode, reason string) {
	changes := []audit.FieldChange{{Field: "reason", After: truncateUTF8(reason, 160)}}
	event := audit.Event{
		Actor: actor, Action: ActionCancelRejected,
		Target:  audit.Target{Type: TargetTypeBackup, ID: backupID},
		Outcome: audit.OutcomeDenied, ErrorCode: errorCode,
		RequestID: normalizeCorrelationID(requestID), Changes: changes,
	}
	_ = s.opts.Audit.Record(normalizeContext(ctx), event)
}

// attachmentsStatus/configStatus 返回请求审计中的内容计划状态。
func (s *Service) attachmentsStatus() string {
	if s.opts.Attachments == nil {
		return ContentNotConfigured
	}
	return ContentIncluded
}

// configStatus 返回请求审计中的配置计划状态。
func (s *Service) configStatus() string {
	if s.opts.Config == nil {
		return ContentNotConfigured
	}
	return ContentIncluded
}

// now 返回注入时钟的当前时间（UTC 由调用方按需处理）。
func (s *Service) now() time.Time {
	return s.opts.Now()
}

// reportProgress 调用宿主进度回调；回调必须快速返回且不得记录秘密。
func (s *Service) reportProgress(progress Progress) {
	if s.opts.Progress != nil {
		s.opts.Progress(progress)
	}
}

// cleanupStaleTemps 在每次 Create 开始时清理历史残留：
//
//   - 有可识别备份编号的临时文件/暂存目录，先尝试取得该编号的运行锁。取得锁说明
//     原进程已死亡（强杀/崩溃，操作系统已释放锁），立即删除残留与锁文件；锁被占用
//     说明是活动备份（本进程或其它进程），跳过，绝不误删正在写入的明文快照。
//   - 无法识别编号的未知前缀条目保守地按 StaleTempAge 年龄清理，避免误删新文件。
//   - 孤立锁文件（无对应残留且可加锁）一并回收，避免长期累积。
//
// 清理失败只记录告警，不阻塞本次备份（本次使用新的随机编号与锁）。
func (s *Service) cleanupStaleTemps(ctx context.Context) {
	entries, err := os.ReadDir(s.outputDir)
	if err != nil {
		s.opts.Logger.Warn("无法扫描备份输出目录清理遗留临时文件", "error", err)
		return
	}
	residues := make(map[string][]string)
	var unknown []string
	var lockNames []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, lockFilePrefix) {
			lockNames = append(lockNames, name)
			continue
		}
		if !strings.HasPrefix(name, tempFilePrefix) &&
			!strings.HasPrefix(name, stagingDirPrefix) {
			continue
		}
		if backupID := backupIDFromResidue(name); backupID != "" {
			residues[backupID] = append(residues[backupID], name)
		} else {
			unknown = append(unknown, name)
		}
	}
	for backupID, names := range residues {
		if ctx != nil && ctx.Err() != nil {
			return
		}
		lock, lockErr := acquireRunLock(lockFilePath(s.outputDir, backupID))
		if errors.Is(lockErr, errLockBusy) {
			continue
		}
		if lockErr != nil {
			s.opts.Logger.Warn("无法加锁判断备份残留是否安全清理", "error", lockErr)
			continue
		}
		for _, name := range names {
			if removeErr := os.RemoveAll(filepath.Join(s.outputDir, name)); removeErr != nil {
				s.opts.Logger.Warn("清理遗留备份临时文件失败", "name", name,
					"error", removeErr)
				continue
			}
			s.opts.Logger.Info("已清理遗留备份临时文件", "name", name)
		}
		lock.Release()
	}
	// 未知前缀条目只能按年龄保守清理；门槛已在构造时校验大于备份墙钟上限。
	threshold := s.now().Add(-s.opts.StaleTempAge)
	for _, name := range unknown {
		info, infoErr := entryInfo(s.outputDir, name)
		if infoErr != nil || info.ModTime().After(threshold) {
			continue
		}
		if removeErr := os.RemoveAll(filepath.Join(s.outputDir, name)); removeErr != nil {
			s.opts.Logger.Warn("清理未知遗留备份文件失败", "name", name,
				"error", removeErr)
		}
	}
	// 孤立锁文件：没有对应残留且当前无持有者时回收。
	for _, name := range lockNames {
		backupID := backupIDFromLockName(name)
		if backupID == "" {
			continue
		}
		if _, exists := residues[backupID]; exists {
			continue
		}
		lock, lockErr := acquireRunLock(filepath.Join(s.outputDir, name))
		if lockErr != nil {
			continue
		}
		lock.Release()
	}
}

// entryInfo 读取输出目录内单个条目的文件信息。
func entryInfo(directory, name string) (os.FileInfo, error) {
	return os.Stat(filepath.Join(directory, name))
}

// attemptError 是一次尝试失败的结构化信息：阶段用于审计 reason_code，清理失败
// 必须进入终态事件，不能被伪装成干净失败。
type attemptError struct {
	stage      string
	cleanupErr error
	cause      error
}

// Error 返回底层安全错误文本。
func (e *attemptError) Error() string {
	if e == nil || e.cause == nil {
		return "备份尝试失败"
	}
	return e.cause.Error()
}

// Unwrap 保留 errors.Is/As 语义。
func (e *attemptError) Unwrap() error { return e.cause }

// stageOf 提取失败阶段稳定标识。
func stageOf(err error) string {
	var failure *attemptError
	if errors.As(err, &failure) && failure != nil {
		return failure.stage
	}
	return ""
}

// hasCleanupFailure 报告失败路径是否未能清理临时文件。
func hasCleanupFailure(err error) bool {
	var failure *attemptError
	return errors.As(err, &failure) && failure != nil && failure.cleanupErr != nil
}

// entrySource 是一个待写入载荷的内容来源；sha256 是清单中声明的摘要，写入时
// 重新计算并核对，检测快照后变化。mismatchErr 决定不一致时的错误类别。
type entrySource struct {
	name        string
	size        int64
	sha256      [32]byte
	mismatchErr error
	open        func(ctx context.Context) (io.ReadCloser, error)
}

// entrySourcesReader 按顺序把多个内容来源拼接成单一读取器，并在每个来源结束时
// 复核字节数与 SHA-256。它同时检查 ctx/取消请求，使大文件写入可被及时终止。
type entrySourcesReader struct {
	ctx       context.Context
	sources   []entrySource
	index     int
	current   io.ReadCloser
	remaining int64
	hasher    hash.Hash
	check     func() error
}

// Read 实现 io.Reader。
func (r *entrySourcesReader) Read(buffer []byte) (int, error) {
	if r.check != nil {
		if err := r.check(); err != nil {
			return 0, err
		}
	}
	for {
		if r.current == nil {
			if r.index >= len(r.sources) {
				return 0, io.EOF
			}
			source := r.sources[r.index]
			reader, err := source.open(r.ctx)
			if err != nil {
				return 0, err
			}
			r.current = reader
			r.hasher = sha256.New()
			r.remaining = source.size
		}
		if r.remaining == 0 {
			source := r.sources[r.index]
			sum := r.hasher.Sum(nil)
			closeErr := r.current.Close()
			r.current = nil
			r.index++
			if !bytes.Equal(sum, source.sha256[:]) {
				return 0, fmt.Errorf("%w: 条目 %s 在写入阶段摘要不一致",
					source.mismatchErr, source.name)
			}
			if closeErr != nil {
				return 0, fmt.Errorf("%w: 关闭条目 %s 失败",
					source.mismatchErr, source.name)
			}
			continue
		}
		limit := int64(len(buffer))
		if limit > r.remaining {
			limit = r.remaining
		}
		read, err := r.current.Read(buffer[:limit])
		if read > 0 {
			_, _ = r.hasher.Write(buffer[:read])
			r.remaining -= int64(read)
		}
		if err != nil && err != io.EOF {
			return read, err
		}
		if read > 0 {
			return read, nil
		}
		if r.remaining > 0 {
			source := r.sources[r.index]
			return 0, fmt.Errorf("%w: 条目 %s 在写入阶段长度不足",
				source.mismatchErr, source.name)
		}
		// 恰好读到条目边界，继续循环完成摘要校验与下一个来源。
	}
}

// Close 关闭当前来源（幂等）。
func (r *entrySourcesReader) Close() error {
	if r.current != nil {
		err := r.current.Close()
		r.current = nil
		return err
	}
	return nil
}

// cleanupAttemptPaths 删除临时文件与明文暂存目录；两者都尽力删除并返回合并错误。
func cleanupAttemptPaths(tempPath, stagingDir string) error {
	var problems []error
	if tempPath != "" {
		if err := os.Remove(tempPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			problems = append(problems, err)
		}
	}
	if stagingDir != "" {
		if err := os.RemoveAll(stagingDir); err != nil {
			problems = append(problems, err)
		}
	}
	return errors.Join(problems...)
}

// publishFile 把已校验的临时文件原子改名为最终文件名（不覆盖已有文件）并收紧
// 文件权限。
func publishFile(tempPath, outputDir, fileName string) (string, error) {
	if fileName == "" || strings.ContainsAny(fileName, `/\`) {
		return "", fmt.Errorf("%w: 备份文件名非法", ErrInvalidRequest)
	}
	finalPath := filepath.Join(outputDir, fileName)
	if _, err := os.Lstat(finalPath); err == nil {
		return "", fmt.Errorf("%w: 备份目标文件已存在", ErrOutputDirUnsafe)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("%w: 无法检查备份目标文件", ErrOutputDirUnsafe)
	}
	if err := os.Rename(tempPath, finalPath); err != nil {
		return "", fmt.Errorf("%w: 无法原子发布备份文件", ErrOutputDirUnsafe)
	}
	// 临时文件创建时已是 0600，rename 保留该权限；Windows 上权限位不是访问控制，
	// 由输出目录 ACL 约束（文档已声明），因此此处不再依赖 chmod 收紧。
	return finalPath, nil
}

// backupFileName 生成稳定、可排序且不与其它备份冲突的文件名。
func backupFileName(createdAt time.Time, backupID string) string {
	return backupFilePrefix + createdAt.UTC().Format("20060102T150405Z") + "_" +
		backupID + backupFileSuffix
}

// validateOutputDir 校验并返回受控输出目录绝对路径。
func validateOutputDir(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("%w: 备份输出目录为空", ErrOutputDirUnsafe)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("%w: 无法解析备份输出目录", ErrOutputDirUnsafe)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", fmt.Errorf("%w: 备份输出目录不存在", ErrOutputDirUnsafe)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("%w: 备份输出目录必须是非符号链接目录", ErrOutputDirUnsafe)
	}
	if runtime.GOOS != "windows" && unsafeDirectoryMode(info.Mode().Perm()) {
		return "", fmt.Errorf("%w: 备份输出目录不应对组/其他用户开放写权限",
			ErrOutputDirUnsafe)
	}
	return absolute, nil
}

// unsafeDirectoryMode 报告目录权限是否向组/其他用户开放写权限。Windows 上权限
// 位不构成访问控制，调用方必须用独立判断（本函数仅在非 Windows 被强制执行，
// 但仍可在测试中验证纯逻辑）。
func unsafeDirectoryMode(perm os.FileMode) bool {
	return perm&0o022 != 0
}

// hashFile 流式计算文件大小与 SHA-256，并遵守 ctx 取消。
func hashFile(ctx context.Context, path string) (int64, string, error) {
	ctx = normalizeContext(ctx)
	file, err := os.Open(path)
	if err != nil {
		return 0, "", fmt.Errorf("%w: 无法读取数据库快照", ErrIntegrityFailed)
	}
	defer file.Close()
	hasher := sha256.New()
	buffer := make([]byte, 256*1024)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return 0, "", terminalContextError(ctx, err)
		}
		read, readErr := file.Read(buffer)
		if read > 0 {
			hasher.Write(buffer[:read])
			total += int64(read)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return 0, "", fmt.Errorf("%w: 读取数据库快照失败", ErrIntegrityFailed)
		}
	}
	return total, hex.EncodeToString(hasher.Sum(nil)), nil
}

// validCancelReason 校验取消原因：非空、UTF-8、无控制字符、长度受限。原因可能
// 含中文，但不得包含换行等可注入内容。
func validCancelReason(reason string) (string, error) {
	trimmed := strings.TrimSpace(reason)
	if trimmed == "" {
		return "", fmt.Errorf("%w: 取消原因不能为空", ErrInvalidRequest)
	}
	if len(trimmed) > MaxCancelReasonBytes*4 {
		return "", fmt.Errorf("%w: 取消原因过长", ErrInvalidRequest)
	}
	for _, char := range trimmed {
		if char < 0x20 || char == 0x7f {
			return "", fmt.Errorf("%w: 取消原因不能包含控制字符", ErrInvalidRequest)
		}
	}
	return truncateUTF8(trimmed, MaxCancelReasonBytes), nil
}

// normalizeCorrelationID 只保留符合项目关联编号格式的值（ASCII 字母/数字/._-，
// 以字母或数字开头，长度 1～64）；非法值归一为空，避免审计写入被拒绝而丢证据。
func normalizeCorrelationID(value string) string {
	if value == "" || len(value) > 64 {
		return ""
	}
	first := value[0]
	if !(first >= '0' && first <= '9') && !(first >= 'a' && first <= 'z') &&
		!(first >= 'A' && first <= 'Z') {
		return ""
	}
	for i := 0; i < len(value); i++ {
		char := value[i]
		allowed := (char >= '0' && char <= '9') || (char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') || char == '.' || char == '_' || char == '-'
		if !allowed {
			return ""
		}
	}
	return value
}

// sanitizeReasonCode 把阶段名转换为审计内部原因码允许的字符集。
func sanitizeReasonCode(stage string) string {
	stage = strings.TrimSpace(stage)
	if stage == "" {
		return ""
	}
	var builder strings.Builder
	for _, char := range stage {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') ||
			char == '_' || char == '-' {
			builder.WriteRune(char)
		}
	}
	value := builder.String()
	if len(value) > 64 {
		value = value[:64]
	}
	return value
}

// truncateUTF8 在不超过 maxBytes 的前提下按 UTF-8 字符截断。
func truncateUTF8(value string, maxBytes int) string {
	if maxBytes <= 0 || len(value) <= maxBytes {
		return value
	}
	truncated := value[:maxBytes]
	for len(truncated) > 0 && !utf8.ValidString(truncated) {
		truncated = truncated[:len(truncated)-1]
	}
	return truncated
}

// sanitizeDisplayValue 清理主机名/应用版本等短元数据：去掉控制字符、转成合法
// UTF-8 并限制字节长度。
func sanitizeDisplayValue(value string) string {
	value = strings.ToValidUTF8(strings.TrimSpace(value), "")
	var builder strings.Builder
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			continue
		}
		builder.WriteRune(char)
	}
	return truncateUTF8(builder.String(), MaxDisplayFieldBytes)
}

// hexDigest 把十六进制摘要转换为定长数组；非法摘要返回零值（校验阶段会拒绝）。
func hexDigest(value string) [32]byte {
	var digest [32]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(digest) {
		return digest
	}
	copy(digest[:], decoded)
	return digest
}

// defaultString 返回非空字符串或回退值。
func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// containsString 报告切片是否包含给定值。
func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// safeName 把备份编号转换为安全文件名片段（编号本身只含 ASCII 十六进制与下划线，
// 这里再做一次防御性过滤）。
func safeName(value string) string {
	var builder strings.Builder
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '_' || char == '-' {
			builder.WriteRune(char)
		}
	}
	result := builder.String()
	if len(result) > 64 {
		result = result[:64]
	}
	return result
}

// runState 是进程内的一次备份运行状态，用于把取消请求关联到真实执行并记录真实
// 取消者。它不持久化、不跨进程；步骤 81 的持久任务接入时再扩展。
type runState struct {
	id        string
	initiator audit.Actor

	mu              sync.Mutex
	finished        bool
	cancelRequested bool
	canceller       audit.Actor
	cancelReason    string
	cancelAt        time.Time
}

// terminal 报告运行是否已做终态决策（完成后到达的取消请求按已结束拒绝）。
func (r *runState) terminal() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.finished
}

// cancelInfo 返回取消请求状态快照。
func (r *runState) cancelInfo() (bool, audit.Actor, string, time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cancelRequested, r.canceller, r.cancelReason, r.cancelAt
}

// requestCancel 在未结束且未被请求取消时记录取消者与原因；重复请求返回冲突。
func (r *runState) requestCancel(canceller audit.Actor, reason string,
	requestedAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.finished {
		return fmt.Errorf("%w: 备份任务已结束", ErrCancelConflict)
	}
	if r.cancelRequested {
		return fmt.Errorf("%w: 备份已有生效的取消请求", ErrCancelConflict)
	}
	r.cancelRequested = true
	r.canceller = canceller
	r.cancelReason = reason
	r.cancelAt = requestedAt
	return nil
}

// claimFinish 由执行器在发布前调用：如果已有生效取消请求则返回取消决策；否则
// 标记终态并返回完成决策。此后到达的取消请求会被拒绝，避免“已接受取消但最终
// 成功”的矛盾。
func (r *runState) claimFinish() (bool, audit.Actor, string, time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.finished = true
	return r.cancelRequested, r.canceller, r.cancelReason, r.cancelAt
}
