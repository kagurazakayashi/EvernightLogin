// Package restore 实现维护模式下的加密备份恢复、恢复前预演与恢复后凭证失效
// （步骤 82）。
//
// 设计不变量（必须与 AGENTS.md §13、需求 §7.4 一起理解）：
//   - 恢复只允许 root（在线受控入口）或本地应急管理员（本地 CLI）执行；本包不提供
//     HTTP 路由、不联网，调用者身份必须来自可信 CallContext，不能由请求参数自称。
//   - 恢复前必须完成预演：认证解密与完整性、数据库版本兼容（禁止降级/未知版本）、
//     存储容量、外部密钥依赖，并对暂存数据库真实执行迁移与一致性检查；预演失败不
//     产生任何持久副作用。
//   - 恢复在维护状态与库外排他锁下执行；先创建恢复前回退备份（新文件，绝不覆盖
//     用户原始备份），再把备份内容暂存到受控目录、再次验证，最后通过同目录原子
//     改名切换。失败或中断规则：切换前失败回退为零副作用并保持维护；切换后失败
//     自动回退到恢复前数据库并保持维护；恢复失败**默认保持维护，不自动对外放行**。
//   - 恢复代际权威副本在库外 restore-state.json；数据库记录只用于检测带外回滚。
//     每次成功恢复先推进库外代际、再在恢复后处理事务中同步库内记录；两者不一致时
//     恢复前检查 fail-closed。
//   - 恢复后处理在**同一个数据库事务**内完成：删除全部会话、刷新令牌族、授权码、
//     恢复代码与挑战、验证链接、扫码请求、一次性凭证、重认证挑战与令牌签名密钥；
//     默认暂停旧调度计划、Webhook 端点、在途任务、邮件投递与待补发通知；写恢复
//     运行记录与暂停清单。**旧备份或恢复前存在的任何上述凭证都不能复活**：数据库
//     切换后先进入维护、后处理事务提交成功后才允许退出维护；失败时回退数据库并
//     保持维护。离线 JWT 因签名密钥被删除而在签名校验处失效；客户端检查边界是
//     “不知道新密钥即拒绝”，本包不承诺已离线缓存的公钥立即失效（文档明确）。
//   - 恢复操作审计先写库外追加日志（哈希链 + fsync），恢复成功后可靠合并进恢复后
//     数据库的安全审计（幂等去重键）；合并失败保持维护、库外日志仍完整保留，可
//     重试合并。恢复过程的审计不能只存在于会被回滚的数据库里。
package restore

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

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/backup"
	"github.com/kagurazakayashi/EvernightLogin/internal/maintenance"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
)

// 权限键、稳定范围与审计动作。权限键 backups.restore 已在 internal/policy 与
// internal/preset 登记（root 专属、不可下放的强认证敏感操作）；本步骤不新增权限键。
const (
	// PermissionRestore 是执行备份恢复所需的权限键（仅 root 拥有）。
	PermissionRestore = "backups.restore"
	// ScopeSystem 是系统范围稳定 ID（恢复覆盖整个系统，不接受应用范围）。
	ScopeSystem = backup.ScopeSystem
	// TargetTypeRestore 是恢复审计目标类型。
	TargetTypeRestore = "restore"
	// TargetTypeCredential 是凭证失效审计目标类型。
	TargetTypeCredential = "credential"
	// TargetTypeDisposition 是恢复后暂停对象审计目标类型。
	TargetTypeDisposition = "disposition"
)

// 审计动作稳定标识。预演/开始/回退备份/暂存/切换/凭证失效/暂停处置/后处理完成/
// 审计合并/完成/失败/已回退/维护进入退出/审查与重新启用分开。
const (
	ActionPreflight        = "restore.preflight"
	ActionStarted          = "restore.started"
	ActionRollbackBackup   = "restore.rollback_backup"
	ActionStaged           = "restore.staged"
	ActionSwitched         = "restore.switched"
	ActionCredentialsReset = "restore.credentials.revoked"
	ActionDispositionPause = "restore.disposition.paused"
	ActionPostProcessed    = "restore.postprocessed"
	ActionAuditMerged      = "restore.audit.merged"
	ActionCompleted        = "restore.completed"
	ActionFailed           = "restore.failed"
	ActionRolledBack       = "restore.rolled_back"
	ActionMaintenanceEnter = "restore.maintenance.enter"
	ActionMaintenanceExit  = "restore.maintenance.exit"
	ActionReview           = "restore.disposition.reviewed"
	ActionReenable         = "restore.disposition.reenabled"
)

// 边界常量。所有上限都有硬边界，不静默截断。
const (
	// DefaultTimeout 是单次恢复流程的默认墙钟上限（含预演、回退备份、暂存与切换）。
	DefaultTimeout = 30 * time.Minute
	// MinTimeout/MaxTimeout 是允许的恢复墙钟上限范围。
	MinTimeout = time.Minute
	MaxTimeout = 6 * time.Hour
	// MinFreeBytes 是三个相关位置（暂存、数据库目录、回退备份目录）各自必须保留的
	// 安全余量；不足时预演明确拒绝，而不是执行到一半才因磁盘满失败。
	MinFreeBytes = int64(64) << 20
	// MaxReasonRunes 是恢复原因的最大字符数（与恢复运行记录 CHECK 一致）。
	MaxReasonRunes = 500
	// MaxRequestIDBytes 是关联编号上限。
	MaxRequestIDBytes = 64
	// stagingDirPrefix/preflightDirPrefix 是受控暂存目录命名前缀。
	stagingDirPrefix   = "staging-"
	preflightDirPrefix = "preflight-"
	// pendingConfigDirName 是未自动应用的配置快照审查目录。
	pendingConfigDirName = "pending-config"
	// preRestorePrefix/failedRestorePrefix 是数据库目录内恢复前副本/失败诊断副本前缀。
	preRestorePrefix    = ".pre-restore-"
	failedRestorePrefix = ".failed-restore-"
	// restoreAttachmentsPrefix 是恢复前头像附件备份子目录名。
	restoreAttachmentsPrefix = ".restore-attachments-"
	// restoreIDPrefix 是恢复编号前缀。
	restoreIDPrefix = "rst_"
	// restoreIDRandomBytes 是恢复编号随机位数（128 位）。
	restoreIDRandomBytes = 16
	// restoreJournalFileName 是库外追加审计日志文件名。
	restoreJournalFileName = "restore-journal.jsonl"
	// restoreJournalLockName 是库外审计日志追加锁文件名。
	restoreJournalLockName = "restore-journal.lock"
	// journalMaxLineBytes 是单条审计日志行上限。
	journalMaxLineBytes = 256 * 1024
	// journalMaxBytes 是库外审计日志文件上限（防止无界增长占满磁盘）。
	journalMaxBytes = int64(64) << 20
)

// 领域错误哨兵。错误文本不包含秘密、备份正文或宿主绝对路径。
var (
	// ErrOptionsInvalid 表示服务构造参数非法（fail-closed）。
	ErrOptionsInvalid = errors.New("恢复服务配置无效")
	// ErrInvalidRequest 表示恢复请求参数非法。
	ErrInvalidRequest = errors.New("恢复请求无效")
	// ErrAccessDenied 表示调用者无权执行恢复（非 root/非本地应急管理员）。
	ErrAccessDenied = errors.New("未获准执行备份恢复")
	// ErrMaintenanceRequired 表示恢复要求维护状态但当前不是维护状态。
	ErrMaintenanceRequired = errors.New("恢复必须在维护状态下执行")
	// ErrRestoreLocked 表示恢复排他锁被其他流程持有。
	ErrRestoreLocked = errors.New("恢复排他锁已被占用")
	// ErrPendingRestore 表示存在未完成的恢复尝试，需要先完成或显式确认。
	ErrPendingRestore = errors.New("存在未完成的恢复尝试")
	// ErrDrainTimeout 表示在途写入未能在墙钟上限内收束。
	ErrDrainTimeout = errors.New("等待在途写入收束超时")
	// ErrGenerationMismatch 表示库外恢复代际与数据库记录不一致（疑似带外回滚）。
	ErrGenerationMismatch = errors.New("库外恢复代际与数据库记录不一致")
	// ErrPreflightFailed 表示恢复前预演未通过（Restorable=false，无副作用）。
	ErrPreflightFailed = errors.New("恢复前预演未通过")
	// ErrBackupUnusable 表示备份无法认证解密/校验（错误密钥、损坏或被篡改）。
	ErrBackupUnusable = errors.New("备份无法认证校验")
	// ErrVersionIncompatible 表示备份数据库版本不支持恢复（降级/未知版本）。
	ErrVersionIncompatible = errors.New("备份数据库版本不兼容")
	// ErrStageFailed 表示暂存/再次验证阶段失败（切换前，回退为零副作用）。
	ErrStageFailed = errors.New("恢复内容暂存或再次验证失败")
	// ErrSwitchFailed 表示数据库切换失败（已尝试回退到恢复前状态）。
	ErrSwitchFailed = errors.New("数据库切换失败")
	// ErrPostProcessFailed 表示恢复后处理失败（已尝试回退到恢复前状态）。
	ErrPostProcessFailed = errors.New("恢复后凭证失效/处置失败")
	// ErrAuditUnavailable 表示关键审计不可用或恢复审计合并不完整（fail-closed）。
	ErrAuditUnavailable = errors.New("恢复审计未能可靠写入或合并")
	// ErrRollbackFailed 表示恢复失败后回退到恢复前状态也失败（必须保持维护）。
	ErrRollbackFailed = errors.New("恢复到恢复前状态失败")
	// ErrTimeout 表示恢复流程超过配置的墙钟上限（未完成切换时为零副作用）。
	ErrTimeout = errors.New("恢复执行超时")
	// ErrStoreUnavailable 表示数据库/状态存储暂时不可用。
	ErrStoreUnavailable = errors.New("恢复存储暂时不可用")
	// ErrInternal 表示未分类内部错误（只用于映射，不外泄细节）。
	ErrInternal = errors.New("恢复内部错误")
	// ErrCancelled 表示操作被调用方取消（未完成切换时为零副作用）。
	ErrCancelled = errors.New("恢复已取消")
)

// ErrorCode 是本领域对根包错误码注册表的投影。本步骤不新增根包错误码：恢复失败
// 按真实原因复用 BACKUP_*、DB_UNAVAILABLE、AUDIT_WRITE_FAILED、RESTORE_MAINTENANCE_REQUIRED
// 与 CONFLICT，具体映射见 CodeOf。
type ErrorCode string

// 错误码常量；与根包已登记码逐字一致。
const (
	CodeReqInvalid                 ErrorCode = "REQ_INVALID"
	CodeAccessDenied               ErrorCode = "ACCESS_DENIED"
	CodeConflict                   ErrorCode = "CONFLICT"
	CodeRestoreMaintenanceRequired ErrorCode = "RESTORE_MAINTENANCE_REQUIRED"
	CodeBackupFailed               ErrorCode = "BACKUP_FAILED"
	CodeBackupInvalid              ErrorCode = "BACKUP_INVALID"
	CodeBackupDecryptFailed        ErrorCode = "BACKUP_DECRYPT_FAILED"
	CodeBackupVersionUnsupported   ErrorCode = "BACKUP_VERSION_UNSUPPORTED"
	CodeAuditWriteFailed           ErrorCode = "AUDIT_WRITE_FAILED"
	CodeDBUnavailable              ErrorCode = "DB_UNAVAILABLE"
	CodeInternalError              ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把恢复域错误映射为根包已登记错误码。包装链保留 errors.Is 语义；备份域
// 哨兵错误优先按其既有映射（BACKUP_INVALID/BACKUP_DECRYPT_FAILED 等）。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrOptionsInvalid), errors.Is(err, ErrInvalidRequest):
		return CodeReqInvalid
	case errors.Is(err, ErrAccessDenied):
		return CodeAccessDenied
	case errors.Is(err, ErrMaintenanceRequired), errors.Is(err, ErrDrainTimeout):
		return CodeRestoreMaintenanceRequired
	case errors.Is(err, ErrRestoreLocked), errors.Is(err, ErrPendingRestore),
		errors.Is(err, ErrGenerationMismatch):
		return CodeConflict
	case errors.Is(err, ErrBackupUnusable):
		switch {
		case errors.Is(err, backup.ErrDecryptFailed):
			return CodeBackupDecryptFailed
		case errors.Is(err, backup.ErrVersionUnsupported):
			return CodeBackupVersionUnsupported
		default:
			return CodeBackupInvalid
		}
	case errors.Is(err, ErrVersionIncompatible):
		return CodeBackupVersionUnsupported
	case errors.Is(err, ErrStageFailed), errors.Is(err, ErrSwitchFailed),
		errors.Is(err, ErrPostProcessFailed), errors.Is(err, ErrRollbackFailed),
		errors.Is(err, ErrPreflightFailed), errors.Is(err, ErrTimeout):
		return CodeBackupFailed
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	case errors.Is(err, ErrStoreUnavailable),
		errors.Is(err, maintenance.ErrStateMissing),
		errors.Is(err, maintenance.ErrKeyringUnavailable):
		return CodeDBUnavailable
	default:
		return CodeInternalError
	}
}

// Authorizer 复用备份服务的授权契约（同一套数据范围语义）；实现必须 fail-closed。
type Authorizer = backup.Authorizer

// RollbackBackupFunc 创建恢复前回退加密备份。实现必须使用真实备份服务（SQLite 在线
// 快照 + 认证加密 + 审计），返回受控输出目录内的新文件；调用方保证宿主数据库未在
// 其他进程中打开（或已处于维护状态）。返回结果必须包含 Path/SHA256。
type RollbackBackupFunc func(ctx context.Context, caller account.Caller,
	requestID string) (backup.Result, error)

// RootChecker 判定可信调用者的用户身份是否为 root。nil 表示拒绝一切用户调用者
// （仅允许本地应急管理员）；在线 root 入口必须由宿主提供真实实现（典型为查询
// 用户 is_root 并复核账户状态），不能由请求参数自称 root。
type RootChecker interface {
	IsRoot(ctx context.Context, actor audit.Actor) (bool, error)
}

// Options 是恢复服务的构造参数。所有依赖缺失/非法时拒绝构造（fail-closed），
// 不使用测试替身顶替生产依赖。
type Options struct {
	// DatabasePath 是当前活动 SQLite 数据库文件路径（必须已存在）。
	DatabasePath string
	// StateDir 是库外受控目录：恢复状态/代际权威文件与追加审计日志所在位置，必须
	// 与数据库目录不同，且不能被数据库回滚覆盖。
	StateDir string
	// Migrations 是当前内嵌迁移集合（与应用启动时一致）；用于预演/暂存数据库的
	// 版本前缀校验与升级执行。
	Migrations []migrate.Migration
	// Keyring 是主密钥环提供者（与备份文件分离）；必填。
	Keyring secrets.Provider
	// RollbackBackup 创建恢复前回退加密备份（必须发布为受控输出目录内的新文件，
	// 绝不覆盖用户原始备份）。生产实现由本地 CLI 打开数据库、构造备份服务并调用
	// backup.Service.Create；测试使用同一真实实现的测试装配。必填。
	RollbackBackup RollbackBackupFunc
	// BackupOutputDir 是回退备份受控输出目录（用于容量检查与结果展示）。必填。
	BackupOutputDir string
	// AttachmentsDir 可选：头像等附件受控存储目录。备份包含附件时必须提供，否则
	// 预演拒绝（避免恢复出数据库引用了不存在的附件）。
	AttachmentsDir string
	// Authorizer 复核 backups.restore 权限与系统范围；必填。
	Authorizer Authorizer
	// RootChecker 复核用户调用者是 root；nil 时拒绝用户调用者，仅允许本地管理员。
	RootChecker RootChecker
	// Now 是可注入时钟；nil 使用 time.Now。
	Now func() time.Time
	// Random 是安全随机源；nil 使用 crypto/rand.Reader。
	Random io.Reader
	// Logger 是运行日志器；不得记录秘密、备份正文或明文数据库内容。
	Logger *slog.Logger
	// Timeout 是单次恢复流程（预演+执行）的墙钟上限；0 使用默认 30 分钟。
	Timeout time.Duration
	// DrainTimeout 是维护状态等待在途写入收束的墙钟上限；0 使用默认 30 秒。
	DrainTimeout time.Duration
	// FreeBytes 是可注入的可用空间探测（测试容量不足路径）；nil 使用系统实现。
	FreeBytes func(path string) (uint64, error)
	// Fault 仅供测试注入失败以保证中断/回退规则可验证；生产必须为 nil。
	Fault func(stage string) error
}

// Service 是恢复服务：构造后不可变，可被多个 goroutine 并发调用；不启动后台
// 协程、不提供 HTTP 路由。一次 Execute 在调用方 goroutine 内同步完成。
type Service struct {
	opts         Options
	databasePath string
	stateDir     string
	controller   *maintenance.Controller
	journal      *journal
	versions     map[int]migrate.Migration
	versionOrder []string
	latestNumber int
	now          func() time.Time
	logger       *slog.Logger
}

// New 校验参数并构造恢复服务与库外维护控制器；不会创建备份、不会进入维护状态、
// 不会修改数据库。
func New(options Options) (*Service, error) {
	databasePath, err := validateDatabasePath(options.DatabasePath)
	if err != nil {
		return nil, err
	}
	stateDir, err := absoluteCleanPath(options.StateDir, "库外状态目录")
	if err != nil {
		return nil, err
	}
	if len(options.Migrations) == 0 {
		return nil, fmt.Errorf("%w: 缺少迁移定义，无法校验数据库版本", ErrOptionsInvalid)
	}
	versions := make(map[int]migrate.Migration, len(options.Migrations))
	for index, migration := range options.Migrations {
		number := parseMigrationNumber(migration.Version)
		if number <= 0 || number != index+1 {
			return nil, fmt.Errorf("%w: 迁移集合必须从 0001 起连续编号", ErrOptionsInvalid)
		}
		if _, duplicated := versions[number]; duplicated {
			return nil, fmt.Errorf("%w: 迁移版本重复", ErrOptionsInvalid)
		}
		versions[number] = migration
	}
	if isNilDependency(options.Keyring) {
		return nil, fmt.Errorf("%w: 缺少主密钥环提供者", ErrOptionsInvalid)
	}
	if options.RollbackBackup == nil {
		return nil, fmt.Errorf("%w: 缺少回退备份实现（无法创建恢复前回退备份）",
			ErrOptionsInvalid)
	}
	backupOutputDir := ""
	if strings.TrimSpace(options.BackupOutputDir) != "" {
		backupOutputDir, err = absoluteDirectory(options.BackupOutputDir)
		if err != nil {
			return nil, fmt.Errorf("%w: 回退备份输出目录无效", ErrOptionsInvalid)
		}
		options.BackupOutputDir = backupOutputDir
	} else {
		return nil, fmt.Errorf("%w: 回退备份输出目录不能为空", ErrOptionsInvalid)
	}
	if isNilDependency(options.Authorizer) {
		return nil, fmt.Errorf("%w: 缺少恢复权限授权器", ErrOptionsInvalid)
	}
	if strings.TrimSpace(options.AttachmentsDir) != "" {
		attachmentsDir, err := absoluteDirectory(options.AttachmentsDir)
		if err != nil {
			return nil, fmt.Errorf("%w: 附件目录无效", ErrOptionsInvalid)
		}
		options.AttachmentsDir = attachmentsDir
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	if options.Timeout == 0 {
		options.Timeout = DefaultTimeout
	}
	if options.Timeout < MinTimeout || options.Timeout > MaxTimeout {
		return nil, fmt.Errorf("%w: 恢复墙钟上限必须在 %s～%s 之间",
			ErrOptionsInvalid, MinTimeout, MaxTimeout)
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.FreeBytes == nil {
		options.FreeBytes = maintenance.FreeBytes
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard,
			&slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	controller, err := maintenance.New(maintenance.Options{
		StateDir:     stateDir,
		DatabasePath: databasePath,
		Now:          now,
		DrainTimeout: options.DrainTimeout,
		Logger:       logger,
		Keyring:      options.Keyring,
	})
	if err != nil {
		return nil, err
	}
	restoreJournal, err := openJournal(controller)
	if err != nil {
		_ = controller.Close()
		return nil, err
	}
	service := &Service{
		opts:         options,
		databasePath: databasePath,
		stateDir:     stateDir,
		controller:   controller,
		journal:      restoreJournal,
		versions:     versions,
		versionOrder: make([]string, 0, len(options.Migrations)),
		latestNumber: len(options.Migrations),
		now:          now,
		logger:       logger,
	}
	for number := 1; number <= service.latestNumber; number++ {
		service.versionOrder = append(service.versionOrder, versions[number].Version)
	}
	return service, nil
}

// Close 释放恢复排他锁并关闭控制器；不改变库外状态。重复调用安全。
func (s *Service) Close() error {
	if s == nil || s.controller == nil {
		return nil
	}
	return s.controller.Close()
}

// StateMissing 报告库外恢复状态是否尚未初始化；为 true 时恢复/维护写操作都会
// fail-closed，必须受控初始化（见 InitState）。
func (s *Service) StateMissing() bool {
	if s == nil || s.controller == nil {
		return true
	}
	return s.controller.Missing()
}

// InitStateRequest 是显式初始化库外恢复状态的请求（仅 root/本地应急管理员）。
type InitStateRequest struct {
	Caller    account.Caller
	Reason    string
	RequestID string
	// AdoptJournal 是受控破窗：状态文件丢失但库外审计日志已有历史事件时，操作者显式
	// 确认后读取日志链末重算锚点完成重建（高风险，需强确认 + 审计）；未设置时拒绝。
	AdoptJournal bool
}

// InitState 显式初始化库外恢复状态（normal/代际 0），并写一条库外审计。状态已存在、
// 审计日志非空（存在先前恢复证据）或未取得排他锁时拒绝，避免用“重新初始化”绕过
// 恢复代际与审计锚点。
func (s *Service) InitState(ctx context.Context, request InitStateRequest) error {
	ctx = normalizeContext(ctx)
	actor, err := s.authorize(ctx, request.Caller)
	if err != nil {
		return err
	}
	reason, err := validReason(request.Reason)
	if err != nil {
		return err
	}
	requestID, err := normalizeCorrelationID(request.RequestID)
	if err != nil {
		return err
	}
	entries, err := s.journal.Entries()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	if len(entries) > 0 && !request.AdoptJournal {
		return fmt.Errorf("%w: 审计日志已存在历史事件，拒绝重新初始化；"+
			"确认人工核验日志后可使用受控破窗 --adopt-journal", ErrStoreUnavailable)
	}
	if err := s.controller.Initialize(ctx, maintenance.InitializeRequest{
		Operator: maintenance.Operator{Type: string(actor.Type), ID: actor.ID,
			Machine: s.machineName()},
		Reason: reason,
	}); err != nil {
		if errors.Is(err, maintenance.ErrStateMissing) {
			return err
		}
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	sessionID, err := s.newSessionID()
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		last := entries[len(entries)-1]
		if err := s.controller.UpdateJournalAnchor(ctx, last.Seq, last.Hash); err != nil {
			return fmt.Errorf("%w: 无法为现有审计日志重算锚点", ErrAuditUnavailable)
		}
	}
	if _, err := s.appendJournal(ctx, journalEvent{
		RestoreID: sessionID, Actor: actor, Action: "restore.state.initialized",
		TargetType: TargetTypeRestore, TargetID: sessionID, Outcome: audit.OutcomeSuccess,
		RequestID: requestID,
		Changes:   []audit.FieldChange{{Field: "reason", After: reason}},
	}); err != nil {
		return err
	}
	return nil
}

// State 返回库外维护/恢复状态副本。
func (s *Service) State() maintenance.State {
	if s == nil || s.controller == nil {
		return maintenance.State{}
	}
	return s.controller.State()
}

// JournalEntries 返回库外恢复审计日志的全部已校验条目（不含秘密）。
func (s *Service) JournalEntries() ([]JournalEntry, error) {
	if s == nil || s.journal == nil {
		return nil, fmt.Errorf("%w: 恢复服务未初始化", ErrOptionsInvalid)
	}
	return s.journal.Entries()
}

// JournalPath 返回库外追加审计日志绝对路径（诊断用）。
func (s *Service) JournalPath() string {
	if s == nil || s.journal == nil {
		return ""
	}
	return s.journal.path
}

// Request 是一次恢复/预演请求。Caller 必须来自可信调用上下文（本地 CLI 使用
// account.LocalBootstrapCaller，在线入口必须已强认证）；不能从请求参数自称 root。
type Request struct {
	// Caller 是可信调用者。
	Caller account.Caller
	// BackupPath 是待恢复备份文件路径。
	BackupPath string
	// Reason 是操作者填写的恢复原因（必填、无控制字符）。
	Reason string
	// RequestID 是可选的关联编号。
	RequestID string
	// AcknowledgeOutOfBandReplacement 允许在检测到“库外代际与数据库记录不一致
	// （疑似带外回滚/替换）”时继续恢复；必须由操作者显式选择。
	AcknowledgeOutOfBandReplacement bool
}

// CheckStatus 是预演单项检查结果状态。
type CheckStatus string

// 预演检查状态稳定取值。
const (
	CheckOK      CheckStatus = "ok"
	CheckFailed  CheckStatus = "failed"
	CheckSkipped CheckStatus = "skipped"
)

// Check 是预演中的一项可校验结果。任何 failed 都使 Restorable=false，并给出直白
// 原因；本包不把失败折叠成单个布尔值。
type Check struct {
	Name   string      `json:"name"`
	Label  string      `json:"label"`
	Status CheckStatus `json:"status"`
	// Code 是失败时建议的稳定错误码（根包已登记码）。
	Code   string `json:"code,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Impact 描述恢复会影响的范围（数据库与凭证/调度对象计数来自暂存数据库真实查询）。
type Impact struct {
	Sessions             int64 `json:"sessions"`
	RefreshFamilies      int64 `json:"refresh_token_families"`
	RefreshTokens        int64 `json:"refresh_tokens"`
	AuthorizationCodes   int64 `json:"authorization_codes"`
	RecoveryCodes        int64 `json:"recovery_codes"`
	RecoveryGroups       int64 `json:"recovery_code_groups"`
	VerificationTickets  int64 `json:"verification_tickets"`
	PasswordResets       int64 `json:"password_reset_requests"`
	EmailChanges         int64 `json:"email_change_requests"`
	QRLoginRequests      int64 `json:"qr_login_requests"`
	DeviceAuthorizations int64 `json:"device_authorizations"`
	OneTimeCredentials   int64 `json:"one_time_credentials"`
	MFAChallenges        int64 `json:"mfa_challenges"`
	WebAuthnCeremonies   int64 `json:"webauthn_ceremonies"`
	ReauthItems          int64 `json:"reauth_challenges_and_approvals"`
	Invitations          int64 `json:"invitations"`
	RecoveryApprovals    int64 `json:"recovery_approvals_and_reviews"`
	SigningKeys          int64 `json:"token_signing_keys"`
	EnabledSchedules     int64 `json:"enabled_schedules"`
	ActiveWebhooks       int64 `json:"active_webhook_endpoints"`
	PendingJobs          int64 `json:"pending_jobs"`
	PendingMails         int64 `json:"pending_mail_deliveries"`
	PendingNotifications int64 `json:"pending_notifications"`
}

// BackupSummary 是备份文件的非秘密摘要（用于审计与结果展示）。
type BackupSummary struct {
	BackupID            string    `json:"backup_id"`
	FileSHA256          string    `json:"file_sha256"`
	FileSizeBytes       int64     `json:"file_size_bytes"`
	CreatedAt           time.Time `json:"created_at"`
	Host                string    `json:"host"`
	AppVersion          string    `json:"app_version"`
	DatabaseEngine      string    `json:"database_engine"`
	SchemaVersion       string    `json:"schema_version"`
	SchemaVersionNumber int       `json:"schema_version_number"`
	AttachmentsIncluded bool      `json:"attachments_included"`
	ConfigIncluded      bool      `json:"config_included"`
}

// Rehearsal 是恢复前预演的结构化结果。Restorable 为 false 时 BlockingReasons 给出
// 全部阻塞原因，且执行流程不会产生任何持久副作用。
type Rehearsal struct {
	Restorable            bool          `json:"restorable"`
	Checks                []Check       `json:"checks"`
	BlockingReasons       []string      `json:"blocking_reasons,omitempty"`
	Warnings              []string      `json:"warnings,omitempty"`
	Backup                BackupSummary `json:"backup"`
	Impact                Impact        `json:"impact"`
	CurrentSchema         string        `json:"current_schema_version,omitempty"`
	TargetSchema          string        `json:"target_schema_version,omitempty"`
	ExternalGeneration    uint64        `json:"external_generation"`
	DatabaseGeneration    uint64        `json:"database_generation"`
	RequiredStateBytes    int64         `json:"required_state_bytes"`
	RequiredDatabaseBytes int64         `json:"required_database_bytes"`
	RequiredBackupBytes   int64         `json:"required_backup_bytes"`
	FreeStateBytes        int64         `json:"free_state_bytes"`
	FreeDatabaseBytes     int64         `json:"free_database_bytes"`
	FreeBackupBytes       int64         `json:"free_backup_bytes"`
	Consequences          []string      `json:"consequences"`
	CompletedAt           time.Time     `json:"completed_at"`
}

// RevocationCounts 记录恢复后处理真实删除/失效的凭证数量（来自事务内实际影响行数）。
type RevocationCounts struct {
	Sessions              int64 `json:"sessions"`
	RefreshFamilies       int64 `json:"refresh_token_families"`
	RefreshTokens         int64 `json:"refresh_tokens"`
	AuthorizationCodes    int64 `json:"authorization_codes"`
	AuthorizationRequests int64 `json:"authorization_requests"`
	RecoveryCodes         int64 `json:"recovery_codes"`
	RecoveryGroups        int64 `json:"recovery_code_groups"`
	RecoveryAttempts      int64 `json:"recovery_attempts"`
	VerificationTickets   int64 `json:"verification_tickets"`
	PasswordResets        int64 `json:"password_reset_requests"`
	EmailChanges          int64 `json:"email_change_requests"`
	QRLoginRequests       int64 `json:"qr_login_requests"`
	DeviceAuthorizations  int64 `json:"device_authorizations"`
	OneTimeCredentials    int64 `json:"one_time_credentials"`
	MFAChallenges         int64 `json:"mfa_challenges"`
	WebAuthnCeremonies    int64 `json:"webauthn_ceremonies"`
	ReauthItems           int64 `json:"reauth_challenges_and_approvals"`
	Invitations           int64 `json:"invitations"`
	RecoveryApprovals     int64 `json:"recovery_approvals_and_reviews"`
	SigningKeys           int64 `json:"token_signing_keys"`
	TotalDeleted          int64 `json:"total_deleted"`
}

// PausedCounts 记录恢复后默认暂停/取消的对象数量。
type PausedCounts struct {
	Schedules         int64 `json:"schedules"`
	Webhooks          int64 `json:"webhook_endpoints"`
	Jobs              int64 `json:"jobs"`
	MailDeliveries    int64 `json:"mail_deliveries"`
	Notifications     int64 `json:"notifications"`
	WebhookDeliveries int64 `json:"webhook_deliveries"`
}

// Result 是一次成功恢复的真实结果（不含秘密与备份正文）。
type Result struct {
	RestoreID            string           `json:"restore_id"`
	Generation           uint64           `json:"generation"`
	Backup               BackupSummary    `json:"backup"`
	Revoked              RevocationCounts `json:"revoked"`
	Paused               PausedCounts     `json:"paused"`
	AuditMerged          int              `json:"audit_merged"`
	RollbackBackupPath   string           `json:"rollback_backup_path,omitempty"`
	RollbackBackupSHA256 string           `json:"rollback_backup_sha256,omitempty"`
	PendingConfigPath    string           `json:"pending_config_path,omitempty"`
	AttachmentsRestored  int64            `json:"attachments_restored"`
	StartedAt            time.Time        `json:"started_at"`
	SwitchedAt           time.Time        `json:"switched_at"`
	CompletedAt          time.Time        `json:"completed_at"`
	Duration             time.Duration    `json:"-"`
	DurationMS           int64            `json:"duration_ms"`
	MaintenanceExited    bool             `json:"maintenance_exited"`
}

// authorize 校验可信调用者并复核 backups.restore 权限与系统范围。
func (s *Service) authorize(ctx context.Context, caller account.Caller) (audit.Actor, error) {
	actor := caller.Actor()
	if err := actor.Validate(); err != nil {
		return audit.Actor{}, fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	switch actor.Type {
	case audit.ActorLocalAdmin:
		// 本地应急管理员：安全边界是操作系统权限与本地 CLI 的显式确认。
	case audit.ActorUser:
		if s.opts.RootChecker == nil {
			return audit.Actor{}, fmt.Errorf("%w: 未配置 root 校验器，拒绝用户调用者",
				ErrAccessDenied)
		}
		root, err := s.opts.RootChecker.IsRoot(ctx, actor)
		if err != nil {
			return audit.Actor{}, fmt.Errorf("%w: 无法确认调用者是否为 root", ErrAccessDenied)
		}
		if !root {
			return audit.Actor{}, fmt.Errorf("%w: 只有 root 可以执行备份恢复", ErrAccessDenied)
		}
	default:
		return audit.Actor{}, fmt.Errorf("%w: 操作者类别不允许执行恢复", ErrAccessDenied)
	}
	grant, err := s.opts.Authorizer.AuthorizeScope(ctx, caller, PermissionRestore, ScopeSystem)
	if err != nil {
		return audit.Actor{}, fmt.Errorf("%w: 权限判定服务不可用", ErrAccessDenied)
	}
	if !grant.Allowed {
		return audit.Actor{}, fmt.Errorf("%w: 缺少 %s 权限或系统范围", ErrAccessDenied,
			PermissionRestore)
	}
	return actor, nil
}

// normalizeRequest 校验并规范化恢复/预演请求的公共字段。
func (s *Service) normalizeRequest(request Request) (Request, error) {
	actor := request.Caller.Actor()
	if err := actor.Validate(); err != nil {
		return Request{}, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	path := strings.TrimSpace(request.BackupPath)
	if path == "" {
		return Request{}, fmt.Errorf("%w: 备份文件路径不能为空", ErrInvalidRequest)
	}
	absolute, err := absoluteFile(path)
	if err != nil {
		return Request{}, err
	}
	reason, err := validReason(request.Reason)
	if err != nil {
		return Request{}, err
	}
	requestID, err := normalizeCorrelationID(request.RequestID)
	if err != nil {
		return Request{}, err
	}
	request.BackupPath = absolute
	request.Reason = reason
	request.RequestID = requestID
	return request, nil
}

// now 返回 UTC 毫秒精度的当前时间。
func (s *Service) nowUTC() time.Time {
	base := s.now
	if base == nil {
		base = time.Now
	}
	return base().UTC().Truncate(time.Millisecond)
}

// newRestoreID 生成恢复编号（rst_ + 128 位随机十六进制）。
func (s *Service) newRestoreID() (string, error) {
	random := s.opts.Random
	if random == nil {
		random = rand.Reader
	}
	buffer := make([]byte, restoreIDRandomBytes)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", fmt.Errorf("%w: 无法生成恢复编号", ErrInternal)
	}
	return restoreIDPrefix + hex.EncodeToString(buffer), nil
}

// fault 在测试注入失败时返回错误；生产 Fault 为 nil 时始终返回 nil。
func (s *Service) fault(stage string) error {
	if s.opts.Fault == nil {
		return nil
	}
	return s.opts.Fault(stage)
}

// validReason 校验恢复原因文本。
func validReason(reason string) (string, error) {
	trimmed := strings.TrimSpace(reason)
	if trimmed == "" {
		return "", fmt.Errorf("%w: 恢复原因不能为空", ErrInvalidRequest)
	}
	if len([]rune(trimmed)) > MaxReasonRunes {
		return "", fmt.Errorf("%w: 恢复原因不能超过 %d 个字符", ErrInvalidRequest, MaxReasonRunes)
	}
	for _, character := range trimmed {
		if character < 0x20 || character == 0x7f {
			return "", fmt.Errorf("%w: 恢复原因不能包含控制字符", ErrInvalidRequest)
		}
	}
	return trimmed, nil
}

// normalizeCorrelationID 校验并规范化关联编号：只允许可见 ASCII，长度有界。
func normalizeCorrelationID(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", nil
	}
	if len(trimmed) > MaxRequestIDBytes {
		return "", fmt.Errorf("%w: 关联编号过长", ErrInvalidRequest)
	}
	for index := 0; index < len(trimmed); index++ {
		character := trimmed[index]
		if character < 0x20 || character > 0x7e {
			return "", fmt.Errorf("%w: 关联编号只能包含可见 ASCII 字符", ErrInvalidRequest)
		}
	}
	return trimmed, nil
}

// parseMigrationNumber 解析迁移版本号（0001 → 1）。
func parseMigrationNumber(version string) int {
	if len(version) == 0 || len(version) > 8 {
		return 0
	}
	number := 0
	for index := 0; index < len(version); index++ {
		character := version[index]
		if character < '0' || character > '9' {
			return 0
		}
		number = number*10 + int(character-'0')
		if number > 1_000_000 {
			return 0
		}
	}
	return number
}

// validateDatabasePath 校验数据库路径：绝对路径、已存在的普通文件、非符号链接。
func validateDatabasePath(path string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" || !filepath.IsAbs(trimmed) {
		return "", fmt.Errorf("%w: 数据库路径必须是绝对路径", ErrOptionsInvalid)
	}
	info, err := os.Lstat(trimmed)
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("%w: 数据库文件不存在或不是普通文件", ErrOptionsInvalid)
	}
	return filepath.Clean(trimmed), nil
}

// absoluteFile 校验备份文件路径：绝对路径、已存在的普通文件、非符号链接。
func absoluteFile(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%w: 备份文件路径必须是绝对路径", ErrInvalidRequest)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("%w: 备份文件不存在", ErrInvalidRequest)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: 备份文件不能是符号链接", ErrInvalidRequest)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%w: 备份文件必须是普通文件", ErrInvalidRequest)
	}
	return filepath.Clean(path), nil
}

// absoluteCleanPath 校验路径为绝对路径并返回清理后的形式；目录是否存在由使用方
// 负责（库外状态目录允许由控制器创建）。
func absoluteCleanPath(path, label string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" || !filepath.IsAbs(trimmed) {
		return "", fmt.Errorf("%w: %s必须是绝对路径", ErrOptionsInvalid, label)
	}
	return filepath.Clean(trimmed), nil
}

// absoluteDirectory 校验目录路径：绝对路径、已存在的真实目录、非符号链接。
func absoluteDirectory(path string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" || !filepath.IsAbs(trimmed) {
		return "", fmt.Errorf("%w: 目录必须是绝对路径", ErrOptionsInvalid)
	}
	info, err := os.Lstat(trimmed)
	if err != nil {
		return "", fmt.Errorf("%w: 目录不存在", ErrOptionsInvalid)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("%w: 路径必须是非符号链接目录", ErrOptionsInvalid)
	}
	return filepath.Clean(trimmed), nil
}

// isNilDependency 报告接口依赖是否为 nil 或带类型的 nil 指针。
func isNilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return reflected.IsNil()
	default:
		return false
	}
}
