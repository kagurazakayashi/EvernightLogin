// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

// 受控本地备份恢复（步骤 231）。
//
// 安全边界（与 internal/restore、cmd/loginctl restore 一致）：
//   - 只接受 AdminCaller 中的 LocalAdmin（宿主进程可信代码）；AdminSession/受限会话
//     一律 ACCESS_DENIED，不新增任何匿名远程恢复入口；
//   - 恢复必须在宿主关闭 Runtime（Close）后执行：先 LoadBackup 在在线阶段解析受控
//     备份编号为内部路径，再 Close，最后 Configure/Initialize/Rehearse/Execute；
//   - 公开 API 不暴露任意磁盘路径：备份只按编号加载，目录配置仅由本地宿主提供且
//     状态目录不能是数据库目录/位于数据库目录内；
//   - 预演、排他锁、维护状态、失败回退、凭证代际失效与库外审计全部由
//     internal/restore + internal/maintenance 真实实现完成；本层不复制、不绕过；
//   - 恢复前回退备份使用同一真实 backup.Service（SQLite 在线快照 + 认证加密 + 审计），
//     输出到受控备份目录，不覆盖用户原始备份。

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/backup"
	"github.com/kagurazakayashi/EvernightLogin/internal/restore"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	appmigrations "github.com/kagurazakayashi/EvernightLogin/migrations"
)

// backupFacadeRegistry 按 Runtime 缓存门面：LoadBackup 在 Close 前解析路径/密钥材料，
// 恢复句柄需要跨 Close 保留；不启动任务、不隐式打开数据库。限制：单进程生效，
// Runtime 关闭后其缓存条目保留（进程级小对象，不做后台清理）。
var backupFacadeRegistry sync.Map

// BackupRecoveryService 是仅受控本地可执行的备份检查/恢复/维护服务。
type BackupRecoveryService interface {
	// Configure 设置库外状态目录、附件目录与回退备份输出目录；必须由 LocalAdmin
	// 在 Runtime 关闭前调用（需要读取主密钥环文档）。路径受控且不得位于数据库目录内。
	Configure(ctx context.Context, req BackupRecoveryConfigRequest) error
	// LoadBackup 在在线阶段按备份编号解析受控备份并记录恢复源；不返回磁盘路径。
	LoadBackup(ctx context.Context, req BackupRecoveryLoadRequest) (BackupRecoverySource, error)
	// Status 返回库外恢复状态/代际/待恢复尝试（诊断，不修改任何数据）。
	Status(ctx context.Context, req BackupRecoveryStatusRequest) (BackupRecoveryStatus, error)
	// Initialize 显式初始化库外恢复状态（状态缺失时 fail-closed，必须显式确认）。
	Initialize(ctx context.Context, req BackupRecoveryInitializeRequest) error
	// Rehearse 对已加载备份做只读预演（不修改数据库、不进入维护状态）。
	Rehearse(ctx context.Context, req BackupRecoveryRestoreRequest) (BackupRehearsal, error)
	// Execute 在排他锁+维护状态下执行恢复；失败默认保持维护状态以便处置。
	Execute(ctx context.Context, req BackupRecoveryRestoreRequest) (BackupRestoreResult, error)
	// EnterMaintenance/ExitMaintenance 供宿主在手工维护前显式进入/退出维护状态。
	EnterMaintenance(ctx context.Context, req BackupMaintenanceRequest) error
	ExitMaintenance(ctx context.Context, req BackupMaintenanceRequest) error
}

// BackupRecoveryConfigRequest 是本地恢复目录配置请求。
type BackupRecoveryConfigRequest struct {
	Caller AdminCaller
	// StateDir 是库外恢复状态目录（必须绝对路径，不能是数据库目录或位于其内）。
	StateDir string
	// AttachmentsDir 是附件受控目录；运行时备份默认不含附件，通常可留空。
	AttachmentsDir string
	// BackupOutputDir 是回退备份输出目录；留空使用数据库目录下的受控 backups 目录。
	BackupOutputDir string
	RequestID       string
}

// BackupRecoveryLoadRequest 是按备份编号加载恢复源的请求。
type BackupRecoveryLoadRequest struct {
	Caller    AdminCaller
	BackupID  string
	RequestID string
}

// BackupRecoverySource 是已加载的恢复源摘要（不含磁盘路径）。
type BackupRecoverySource struct {
	BackupID      string
	FileSHA256    string
	SizeBytes     int64
	SchemaVersion string
	CreatedAt     time.Time
	Host          string
	AppVersion    string
}

// BackupRecoveryStatusRequest 是状态查询请求。
type BackupRecoveryStatusRequest struct {
	Caller    AdminCaller
	RequestID string
}

// BackupRecoveryStatus 是库外恢复状态视图。
type BackupRecoveryStatus struct {
	StateMissing   bool
	Configured     bool
	BackupLoaded   bool
	Mode           string
	Generation     uint64
	OperatorID     string
	Machine        string
	Reason         string
	EnteredAt      time.Time
	UpdatedAt      time.Time
	JournalEntries int
	Pending        *BackupPendingRestore
}

// BackupPendingRestore 是未完成恢复尝试的公开摘要。
type BackupPendingRestore struct {
	RestoreID      string
	NextGeneration uint64
	BackupSHA256   string
	OperatorID     string
	StartedAt      time.Time
}

// BackupRecoveryInitializeRequest 是显式初始化库外恢复状态请求。
type BackupRecoveryInitializeRequest struct {
	Caller AdminCaller
	Reason string
	// Confirm 必须为 true：初始化是高危本地应急操作，不能静默重建。
	Confirm   bool
	RequestID string
}

// BackupRecoveryRestoreRequest 是预演/执行恢复请求（恢复源由 LoadBackup 提供）。
type BackupRecoveryRestoreRequest struct {
	Caller AdminCaller
	Reason string
	// ConfirmToken 执行恢复时必须显式填写 "RESTORE"；用于防误触，不是秘密。
	ConfirmToken string
	RequestID    string
}

// BackupCheck 是预演中的一项检查。
type BackupCheck struct {
	Name   string
	Label  string
	Status string
	Code   string
	Detail string
}

// BackupImpact 是恢复影响的数据库对象计数（来自暂存数据库真实查询）。
type BackupImpact struct {
	Sessions        int64
	RefreshTokens   int64
	RecoveryCodes   int64
	PendingJobs     int64
	PendingMails    int64
	SigningKeys     int64
	EnabledSchedule int64
}

// BackupSourceSummary 是恢复源摘要（与 BackupRecoverySource 一致，供预演结果展示）。
type BackupSourceSummary struct {
	BackupID            string
	FileSHA256          string
	FileSizeBytes       int64
	CreatedAt           time.Time
	Host                string
	AppVersion          string
	DatabaseEngine      string
	SchemaVersion       string
	SchemaVersionNumber int
	AttachmentsIncluded bool
	ConfigIncluded      bool
}

// BackupRehearsal 是恢复前预演结果；Restorable=false 时 BlockingReasons 为全部阻塞原因。
type BackupRehearsal struct {
	Restorable            bool
	Checks                []BackupCheck
	BlockingReasons       []string
	Warnings              []string
	Backup                BackupSourceSummary
	Impact                BackupImpact
	CurrentSchema         string
	TargetSchema          string
	ExternalGeneration    uint64
	DatabaseGeneration    uint64
	RequiredStateBytes    int64
	RequiredDatabaseBytes int64
	RequiredBackupBytes   int64
	FreeStateBytes        int64
	FreeDatabaseBytes     int64
	FreeBackupBytes       int64
	Consequences          []string
	CompletedAt           time.Time
}

// BackupRestoreResult 是恢复真实结果；不暴露回退备份/待应用配置的磁盘路径。
type BackupRestoreResult struct {
	RestoreID           string
	Generation          uint64
	Backup              BackupSourceSummary
	RevokedSessions     int64
	RevokedRefresh      int64
	RevokedRecovery     int64
	RevokedPausedItems  int64
	AuditMerged         int
	AttachmentsRestored int64
	StartedAt           time.Time
	SwitchedAt          time.Time
	CompletedAt         time.Time
	MaintenanceExited   bool
	DurationMS          int64
}

// BackupMaintenanceRequest 是显式维护状态请求；Force 仅用于退出时处置未完成恢复。
type BackupMaintenanceRequest struct {
	Caller    AdminCaller
	Reason    string
	Force     bool
	RequestID string
}

// Recovery 返回受控本地恢复服务（按 Runtime 缓存同一实例）。
func (f *backupFacade) Recovery() BackupRecoveryService {
	if f.recovery == nil {
		f.recovery = &backupRecoveryFacade{f: f}
	}
	return f.recovery
}

type backupRecoveryFacade struct {
	f  *backupFacade
	mu sync.Mutex
	// 以下字段在 Configure/LoadBackup（Runtime 未关闭时）采集，Close 后仍可使用。
	configured  bool
	stateDir    string
	attachments string
	outputDir   string
	dbPath      string
	operator    string
	keyringDoc  []byte
	loaded      *BackupRecoverySource
	loadedPath  string
	service     *restore.Service
}

// localCaller 校验受控本地操作者并返回账户 Caller；不依赖 Runtime 会话/数据库，
// 因此 Runtime.Close 后仍可用于恢复编排（身份只来自显式 LocalAdmin）。
func (s *backupRecoveryFacade) localCaller(ctx context.Context, caller AdminCaller,
	requestID string) (adminRequest, account.Caller, error) {
	r := s.f.r
	id, err := resolveRequestID(ctx, requestID)
	if err != nil {
		return adminRequest{}, account.Caller{}, err
	}
	if r == nil || caller.runtime != r || !caller.local || len(caller.sessionSecret) > 0 {
		return adminRequest{}, account.Caller{},
			mapDomainError("恢复只允许本机受信操作者", "ACCESS_DENIED", id)
	}
	operator := strings.TrimSpace(r.opts.OperatorID)
	actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: operator}
	if err := actor.Validate(); err != nil {
		return adminRequest{}, account.Caller{}, configError("本机受信操作者标识无效", id)
	}
	accountCaller, err := account.LocalBootstrapCaller(operator)
	if err != nil {
		return adminRequest{}, account.Caller{}, configError("本机受信操作者标识无效", id)
	}
	accountCaller, err = bindCaller(accountCaller, id)
	if err != nil {
		return adminRequest{}, account.Caller{}, err
	}
	return adminRequest{identity: adminIdentity{actor: actor, local: true}, requestID: id},
		accountCaller, nil
}

// runtimeClosed 报告宿主是否已 Close 运行时；恢复必须在该状态下执行。
func (s *backupRecoveryFacade) runtimeClosed() bool {
	r := s.f.r
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

// captureDatabasePath 从运行时配置/打开参数解析当前数据库绝对路径。
func (s *backupRecoveryFacade) captureDatabasePath(call adminRequest) (string, error) {
	path := strings.TrimSpace(s.f.r.opts.DatabasePath)
	if path == "" {
		path = strings.TrimSpace(s.f.r.config.Database.Path)
	}
	if path == "" {
		return "", call.configError("数据库路径未知，无法配置恢复")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", call.configError("数据库路径无效")
	}
	return filepath.Clean(absolute), nil
}

// captureKeyring 读取主密钥环文档（只保存在内存，不写日志/不落盘）。
func (s *backupRecoveryFacade) captureKeyring(call adminRequest) ([]byte, error) {
	if s.f.r.base == nil || s.f.r.base.Keyring == nil {
		return nil, call.configError("主密钥环未装配，无法执行受控恢复")
	}
	document, err := s.f.r.base.Keyring.Document()
	if err != nil {
		return nil, call.configError("主密钥环不可用，无法执行受控恢复")
	}
	copyDocument := append([]byte(nil), document...)
	for index := range document {
		document[index] = 0
	}
	return copyDocument, nil
}

// Configure 设置恢复目录并采集运行时路径/主密钥环；必须在 Close 前调用。
func (s *backupRecoveryFacade) Configure(ctx context.Context,
	req BackupRecoveryConfigRequest) error {
	call, _, err := s.localCaller(ctx, req.Caller, req.RequestID)
	if err != nil {
		return err
	}
	if s.runtimeClosed() {
		return call.configError("恢复配置必须在关闭运行时之前完成")
	}
	dbPath, err := s.captureDatabasePath(call)
	if err != nil {
		return err
	}
	stateDir, err := controlledStateDir(dbPath, req.StateDir, call)
	if err != nil {
		return err
	}
	attachments := strings.TrimSpace(req.AttachmentsDir)
	if attachments != "" {
		absolute, absErr := filepath.Abs(attachments)
		if absErr != nil {
			return call.configError("附件目录无效")
		}
		attachments = filepath.Clean(absolute)
	}
	outputDir := strings.TrimSpace(req.BackupOutputDir)
	if outputDir == "" {
		outputDir = filepath.Join(filepath.Dir(dbPath), "backups")
	} else {
		absolute, absErr := filepath.Abs(outputDir)
		if absErr != nil {
			return call.configError("回退备份目录无效")
		}
		outputDir = filepath.Clean(absolute)
	}
	if err := ensureBackupDir(stateDir, call); err != nil {
		return err
	}
	if err := ensureBackupDir(outputDir, call); err != nil {
		return err
	}
	keyringDoc, err := s.captureKeyring(call)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.configured = true
	s.stateDir = stateDir
	s.attachments = attachments
	s.outputDir = outputDir
	s.dbPath = dbPath
	s.operator = call.identity.actor.ID
	s.keyringDoc = keyringDoc
	s.service = nil
	s.mu.Unlock()
	return nil
}

// LoadBackup 在在线阶段按备份编号解析受控备份路径；公开结果不含路径。
func (s *backupRecoveryFacade) LoadBackup(ctx context.Context,
	req BackupRecoveryLoadRequest) (BackupRecoverySource, error) {
	call, accountCaller, err := s.localCaller(ctx, req.Caller, req.RequestID)
	if err != nil {
		return BackupRecoverySource{}, err
	}
	if s.runtimeClosed() {
		return BackupRecoverySource{}, call.configError("加载备份必须在关闭运行时之前完成")
	}
	managed := s.f.r.managedServices()
	if managed == nil || managed.BackupAdmin == nil {
		return BackupRecoverySource{}, call.configError("备份管理服务未装配")
	}
	view, err := managed.BackupAdmin.GetArtifact(ctx, accountCaller, req.BackupID)
	if err != nil {
		return BackupRecoverySource{}, s.f.mapBackupError(call, "读取备份产物失败", err)
	}
	path, err := managed.BackupAdmin.ArtifactPathForRecovery(ctx, accountCaller,
		req.BackupID, call.requestID)
	if err != nil {
		return BackupRecoverySource{}, s.f.mapBackupError(call, "加载恢复源失败", err)
	}
	source := BackupRecoverySource{BackupID: view.BackupID, FileSHA256: view.FileSHA256,
		SizeBytes: view.SizeBytes, SchemaVersion: view.SchemaVersion,
		CreatedAt: view.CreatedAt, Host: view.Hostname, AppVersion: view.AppVersion}
	s.mu.Lock()
	s.loaded = &source
	s.loadedPath = path
	if s.dbPath == "" {
		if dbPath, dbErr := s.captureDatabasePath(call); dbErr == nil {
			s.dbPath = dbPath
		}
	}
	if s.operator == "" {
		s.operator = call.identity.actor.ID
	}
	document, keyErr := s.captureKeyring(call)
	if keyErr != nil {
		s.mu.Unlock()
		return BackupRecoverySource{}, keyErr
	}
	if len(s.keyringDoc) == 0 {
		s.keyringDoc = document
	}
	s.mu.Unlock()
	return source, nil
}

func (s *backupRecoveryFacade) requireLoaded(call adminRequest) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.configured || s.dbPath == "" || len(s.keyringDoc) == 0 {
		return "", call.configError("恢复目录/密钥尚未配置")
	}
	if s.loadedPath == "" {
		return "", call.configError("尚未加载恢复备份；请先 LoadBackup")
	}
	return s.loadedPath, nil
}

// recoveryService 构造/复用 internal/restore 服务；不触碰运行时已关闭的存储。
func (s *backupRecoveryFacade) recoveryService(call adminRequest) (*restore.Service, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.service != nil {
		return s.service, nil
	}
	if !s.configured || s.dbPath == "" || len(s.keyringDoc) == 0 {
		return nil, call.configError("恢复目录/密钥尚未配置")
	}
	migrations, err := migrate.LoadMigrations(appmigrations.SQLite)
	if err != nil {
		return nil, call.configError("内嵌迁移不可用")
	}
	document := append([]byte(nil), s.keyringDoc...)
	keyringProvider := secrets.ProviderFunc(func(context.Context) ([]byte, error) {
		return append([]byte(nil), document...), nil
	})
	operator := s.operator
	logger := s.f.r.logger
	outputDir := s.outputDir
	attachments := s.attachments
	dbPath := s.dbPath
	service, err := restore.New(restore.Options{
		DatabasePath: dbPath, StateDir: s.stateDir, Migrations: migrations,
		Keyring: keyringProvider, BackupOutputDir: outputDir, AttachmentsDir: attachments,
		Authorizer: backupRecoveryAuthorizer{operatorID: operator},
		RollbackBackup: func(ctx context.Context, caller account.Caller,
			requestID string) (backup.Result, error) {
			return createBackupRecoveryRollback(ctx, dbPath, outputDir, operator,
				logger, document, caller, requestID)
		},
		Now: s.f.r.runtimeNow, Logger: logger,
	})
	if err != nil {
		return nil, call.configError("恢复服务不可用")
	}
	s.service = service
	return service, nil
}

// Status 返回库外状态；不修改数据库。Close 前后均可查询。
func (s *backupRecoveryFacade) Status(ctx context.Context,
	req BackupRecoveryStatusRequest) (BackupRecoveryStatus, error) {
	call, _, err := s.localCaller(ctx, req.Caller, req.RequestID)
	if err != nil {
		return BackupRecoveryStatus{}, err
	}
	service, err := s.recoveryService(call)
	if err != nil {
		return BackupRecoveryStatus{}, err
	}
	s.mu.Lock()
	status := BackupRecoveryStatus{Configured: s.configured, BackupLoaded: s.loadedPath != ""}
	s.mu.Unlock()
	status.StateMissing = service.StateMissing()
	state := service.State()
	status.Mode = state.Mode
	status.Generation = state.Generation
	status.OperatorID = state.OperatorID
	status.Machine = state.Machine
	status.Reason = state.Reason
	status.EnteredAt = state.EnteredAt
	status.UpdatedAt = state.UpdatedAt
	if state.Pending != nil {
		status.Pending = &BackupPendingRestore{RestoreID: state.Pending.RestoreID,
			NextGeneration: state.Pending.NextGeneration,
			BackupSHA256:   state.Pending.BackupSHA256, OperatorID: state.Pending.OperatorID,
			StartedAt: state.Pending.StartedAt}
	}
	if entries, journalErr := service.JournalEntries(); journalErr == nil {
		status.JournalEntries = len(entries)
	}
	return status, nil
}

// Initialize 显式初始化库外恢复状态（仅本地受信 + 显式确认）。
func (s *backupRecoveryFacade) Initialize(ctx context.Context,
	req BackupRecoveryInitializeRequest) error {
	call, accountCaller, err := s.localCaller(ctx, req.Caller, req.RequestID)
	if err != nil {
		return err
	}
	if !req.Confirm {
		return call.domainError("初始化恢复状态需要显式确认", "REQ_INVALID")
	}
	if !s.runtimeClosed() {
		return call.configError("恢复状态初始化必须在关闭运行时后执行")
	}
	service, err := s.recoveryService(call)
	if err != nil {
		return err
	}
	if err := service.InitState(ctx, restore.InitStateRequest{Caller: accountCaller,
		Reason: req.Reason, RequestID: call.requestID}); err != nil {
		return s.mapRestoreError(call, "初始化恢复状态失败", err)
	}
	return nil
}

// Rehearse 只读预演；不修改数据库、不进入维护状态。
func (s *backupRecoveryFacade) Rehearse(ctx context.Context,
	req BackupRecoveryRestoreRequest) (BackupRehearsal, error) {
	call, accountCaller, err := s.localCaller(ctx, req.Caller, req.RequestID)
	if err != nil {
		return BackupRehearsal{}, err
	}
	if !s.runtimeClosed() {
		return BackupRehearsal{}, call.configError("预演必须在关闭运行时后执行")
	}
	path, err := s.requireLoaded(call)
	if err != nil {
		return BackupRehearsal{}, err
	}
	service, err := s.recoveryService(call)
	if err != nil {
		return BackupRehearsal{}, err
	}
	rehearsal, err := service.Rehearse(ctx, restore.Request{Caller: accountCaller,
		BackupPath: path, Reason: req.Reason, RequestID: call.requestID})
	if err != nil {
		return BackupRehearsal{}, s.mapRestoreError(call, "恢复预演失败", err)
	}
	return backupRehearsalView(rehearsal), nil
}

// Execute 在排他锁+维护状态下执行恢复并返回真实结果。
func (s *backupRecoveryFacade) Execute(ctx context.Context,
	req BackupRecoveryRestoreRequest) (BackupRestoreResult, error) {
	call, accountCaller, err := s.localCaller(ctx, req.Caller, req.RequestID)
	if err != nil {
		return BackupRestoreResult{}, err
	}
	if !s.runtimeClosed() {
		return BackupRestoreResult{}, call.configError("恢复必须在关闭运行时后执行")
	}
	if strings.TrimSpace(req.ConfirmToken) != "RESTORE" {
		return BackupRestoreResult{}, call.domainError("恢复需要显式确认令牌 RESTORE",
			"REQ_INVALID")
	}
	path, err := s.requireLoaded(call)
	if err != nil {
		return BackupRestoreResult{}, err
	}
	service, err := s.recoveryService(call)
	if err != nil {
		return BackupRestoreResult{}, err
	}
	result, err := service.Execute(ctx, restore.Request{Caller: accountCaller,
		BackupPath: path, Reason: req.Reason, RequestID: call.requestID})
	if err != nil {
		return BackupRestoreResult{}, s.mapRestoreError(call, "执行恢复失败", err)
	}
	return backupRestoreResultView(result), nil
}

// EnterMaintenance 进入维护状态；ExitMaintenance 退出并合并库外审计。
func (s *backupRecoveryFacade) EnterMaintenance(ctx context.Context,
	req BackupMaintenanceRequest) error {
	call, accountCaller, err := s.localCaller(ctx, req.Caller, req.RequestID)
	if err != nil {
		return err
	}
	if !s.runtimeClosed() {
		return call.configError("维护状态操作必须在关闭运行时后执行")
	}
	service, err := s.recoveryService(call)
	if err != nil {
		return err
	}
	if err := service.EnterMaintenance(ctx, restore.MaintenanceRequest{Caller: accountCaller,
		Reason: req.Reason, RequestID: call.requestID}); err != nil {
		return s.mapRestoreError(call, "进入维护状态失败", err)
	}
	return nil
}

// ExitMaintenance 显式退出维护状态；存在未完成恢复时 Force 才能退出。
func (s *backupRecoveryFacade) ExitMaintenance(ctx context.Context,
	req BackupMaintenanceRequest) error {
	call, accountCaller, err := s.localCaller(ctx, req.Caller, req.RequestID)
	if err != nil {
		return err
	}
	if !s.runtimeClosed() {
		return call.configError("维护状态操作必须在关闭运行时后执行")
	}
	service, err := s.recoveryService(call)
	if err != nil {
		return err
	}
	if err := service.ExitMaintenance(ctx, restore.MaintenanceRequest{Caller: accountCaller,
		Reason: req.Reason, RequestID: call.requestID, Force: req.Force}); err != nil {
		return s.mapRestoreError(call, "退出维护状态失败", err)
	}
	return nil
}

// mapRestoreError 把恢复域错误映射为稳定公开错误码；优先保留恢复域错误语义。
func (s *backupRecoveryFacade) mapRestoreError(call adminRequest, message string,
	err error) error {
	if errors.Is(err, context.Canceled) {
		return call.domainError(message, "CANCELLED")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return call.domainError(message, "TIMEOUT")
	}
	code := string(restore.CodeOf(err))
	if code == "" {
		code = string(backup.CodeOf(err))
	}
	if code == "" {
		code = "INTERNAL_ERROR"
	}
	return call.domainError(message, code)
}

// controlledStateDir 校验状态目录为绝对路径且不位于数据库目录内；目录不存在时创建。
func controlledStateDir(dbPath, requested string, call adminRequest) (string, error) {
	value := strings.TrimSpace(requested)
	if value == "" {
		return "", call.configError("恢复状态目录不能为空（必须由宿主显式提供库外受控目录）")
	}
	absolute, err := filepath.Abs(value)
	if err != nil {
		return "", call.configError("恢复状态目录无效")
	}
	absolute = filepath.Clean(absolute)
	dbDir := filepath.Clean(filepath.Dir(dbPath))
	relative, err := filepath.Rel(dbDir, absolute)
	if err != nil {
		return "", call.configError("恢复状态目录无效")
	}
	if relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))) {
		return "", call.configError("恢复状态目录不能是数据库目录或位于数据库目录内")
	}
	return absolute, nil
}

// ensureBackupDir 创建/校验受控目录（0700；失败 fail-closed）。
func ensureBackupDir(path string, call adminRequest) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return call.configError("受控目录不可用")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return call.configError("受控目录无效")
	}
	return nil
}

// backupRecoveryAuthorizer 是本地恢复授权器：只放行指定本地操作者在系统范围的备份
// 恢复/创建/取消权限；安全边界是操作系统权限与显式本地调用，不冒充远程认证。
type backupRecoveryAuthorizer struct{ operatorID string }

// AuthorizeScope 实现 stats.Authorizer（backup/restore 共用契约）。
func (a backupRecoveryAuthorizer) AuthorizeScope(_ context.Context, caller account.Caller,
	permissionKey, scopeID string) (stats.ScopeGrant, error) {
	actor := caller.Actor()
	if actor.Type != audit.ActorLocalAdmin || actor.ID != a.operatorID ||
		scopeID != restore.ScopeSystem {
		return stats.ScopeGrant{}, nil
	}
	switch permissionKey {
	case restore.PermissionRestore, backup.PermissionCreate, backup.PermissionCancel:
		return stats.ScopeGrant{Allowed: true, AllData: true}, nil
	default:
		return stats.ScopeGrant{}, nil
	}
}

// createBackupRecoveryRollback 用真实备份服务创建恢复前回退备份：独立打开当前数据库
// （宿主已关闭运行时且停止写入），SQLite 一致性快照 + 认证加密 + 审计，输出受控目录。
func createBackupRecoveryRollback(ctx context.Context, dbPath, outputDir, operator string,
	logger *slog.Logger, keyringDoc []byte, caller account.Caller,
	requestID string) (backup.Result, error) {
	store, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(dbPath))
	if err != nil {
		return backup.Result{}, fmt.Errorf("无法打开数据库创建回退备份: %w", err)
	}
	defer func() { _ = store.Close() }()
	auditStore, err := auditsqlite.New(store)
	if err != nil {
		return backup.Result{}, fmt.Errorf("无法构造审计存储: %w", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{Logger: logger})
	if err != nil {
		return backup.Result{}, fmt.Errorf("无法构造审计写入器: %w", err)
	}
	snapshotter, err := backup.NewSQLiteSnapshotter(store)
	if err != nil {
		return backup.Result{}, fmt.Errorf("无法构造 SQLite 快照器: %w", err)
	}
	document := append([]byte(nil), keyringDoc...)
	provider := secrets.ProviderFunc(func(context.Context) ([]byte, error) {
		return append([]byte(nil), document...), nil
	})
	service, err := backup.New(backup.Options{Snapshotter: snapshotter,
		Keyring: provider, Authorizer: backupRecoveryAuthorizer{operatorID: operator},
		Audit: recorder, OutputDir: outputDir, Now: time.Now, Logger: logger})
	if err != nil {
		return backup.Result{}, fmt.Errorf("无法构造回退备份服务: %w", err)
	}
	result, err := service.Create(ctx, backup.CreateRequest{Caller: caller,
		RequestID: requestID})
	if err != nil {
		return backup.Result{}, fmt.Errorf("创建恢复前回退备份失败: %w", err)
	}
	return result, nil
}

// backupRehearsalView/backupRestoreResultView 把内部结果投影为不含磁盘路径的公开视图。
func backupRehearsalView(value restore.Rehearsal) BackupRehearsal {
	checks := make([]BackupCheck, 0, len(value.Checks))
	for _, check := range value.Checks {
		checks = append(checks, BackupCheck{Name: check.Name, Label: check.Label,
			Status: string(check.Status), Code: check.Code, Detail: check.Detail})
	}
	return BackupRehearsal{Restorable: value.Restorable, Checks: checks,
		BlockingReasons: append([]string(nil), value.BlockingReasons...),
		Warnings:        append([]string(nil), value.Warnings...),
		Backup: BackupSourceSummary{BackupID: value.Backup.BackupID,
			FileSHA256: value.Backup.FileSHA256, FileSizeBytes: value.Backup.FileSizeBytes,
			CreatedAt: value.Backup.CreatedAt, Host: value.Backup.Host,
			AppVersion: value.Backup.AppVersion, DatabaseEngine: value.Backup.DatabaseEngine,
			SchemaVersion:       value.Backup.SchemaVersion,
			SchemaVersionNumber: value.Backup.SchemaVersionNumber,
			AttachmentsIncluded: value.Backup.AttachmentsIncluded,
			ConfigIncluded:      value.Backup.ConfigIncluded},
		Impact: BackupImpact{Sessions: value.Impact.Sessions,
			RefreshTokens:   value.Impact.RefreshTokens,
			RecoveryCodes:   value.Impact.RecoveryCodes,
			PendingJobs:     value.Impact.PendingJobs,
			PendingMails:    value.Impact.PendingMails,
			SigningKeys:     value.Impact.SigningKeys,
			EnabledSchedule: value.Impact.EnabledSchedules},
		CurrentSchema: value.CurrentSchema, TargetSchema: value.TargetSchema,
		ExternalGeneration:    value.ExternalGeneration,
		DatabaseGeneration:    value.DatabaseGeneration,
		RequiredStateBytes:    value.RequiredStateBytes,
		RequiredDatabaseBytes: value.RequiredDatabaseBytes,
		RequiredBackupBytes:   value.RequiredBackupBytes,
		FreeStateBytes:        value.FreeStateBytes,
		FreeDatabaseBytes:     value.FreeDatabaseBytes,
		FreeBackupBytes:       value.FreeBackupBytes,
		Consequences:          append([]string(nil), value.Consequences...),
		CompletedAt:           value.CompletedAt}
}

func backupRestoreResultView(value restore.Result) BackupRestoreResult {
	var paused int64
	for _, count := range []int64{value.Paused.Schedules, value.Paused.Webhooks,
		value.Paused.Jobs, value.Paused.MailDeliveries, value.Paused.Notifications,
		value.Paused.WebhookDeliveries} {
		paused += count
	}
	return BackupRestoreResult{RestoreID: value.RestoreID, Generation: value.Generation,
		Backup: BackupSourceSummary{BackupID: value.Backup.BackupID,
			FileSHA256: value.Backup.FileSHA256, FileSizeBytes: value.Backup.FileSizeBytes,
			CreatedAt: value.Backup.CreatedAt, Host: value.Backup.Host,
			AppVersion: value.Backup.AppVersion, DatabaseEngine: value.Backup.DatabaseEngine,
			SchemaVersion:       value.Backup.SchemaVersion,
			SchemaVersionNumber: value.Backup.SchemaVersionNumber,
			AttachmentsIncluded: value.Backup.AttachmentsIncluded,
			ConfigIncluded:      value.Backup.ConfigIncluded},
		RevokedSessions: value.Revoked.Sessions, RevokedRefresh: value.Revoked.RefreshTokens,
		RevokedRecovery: value.Revoked.RecoveryCodes, RevokedPausedItems: paused,
		AuditMerged: value.AuditMerged, AttachmentsRestored: value.AttachmentsRestored,
		StartedAt: value.StartedAt, SwitchedAt: value.SwitchedAt,
		CompletedAt: value.CompletedAt, MaintenanceExited: value.MaintenanceExited,
		DurationMS: value.DurationMS}
}

// 保证排序辅助不会因未使用导入报错（恢复审计日志按时间稳定展示由调用方决定）。
