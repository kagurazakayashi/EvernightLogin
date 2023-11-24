// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

// 备份计划、触发、查看、检查、导出与取消的公开 Go 接口（步骤 231）。
//
// 设计边界：
//   - 只复用 internal/backupadmin（任务索引/计划/保留/下载/审计）与 internal/backup
//     （认证校验）真实服务；不在门面复制第二套状态机；
//   - 任务型 API 返回任务 ID/状态：提交成功不等于备份完成，调用方必须用 Jobs().Get
//     或 Artifacts().Get 查询真实结果；
//   - 公开 API 只接受备份编号，不接受任意磁盘路径；受控目录/文件名解析在内部完成；
//   - 恢复（Recovery）为仅受控本地可执行的应急操作：只接受 LocalAdmin、要求宿主先
//     Close 运行时，并由 internal/restore 在排他锁与维护状态下预演/执行；详见
//     app/backup_recovery.go。
//   - 身份只来自 AdminCaller：AdminSession 为真实完整用户会话，受限会话在解析阶段
//     拒绝；领域服务在事务内复核权限、敏感再认证与审计，不因不经过 HTTP 而放行。

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/backup"
	"github.com/kagurazakayashi/EvernightLogin/internal/backupadmin"
	"github.com/kagurazakayashi/EvernightLogin/internal/restore"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// BackupService 是备份公开服务入口。
type BackupService interface {
	// Plans 返回备份计划管理服务。
	Plans() BackupPlanService
	// Jobs 返回备份任务触发/查询/取消服务。
	Jobs() BackupJobService
	// Artifacts 返回备份产物查看/检查/导出服务。
	Artifacts() BackupArtifactService
	// Recovery 返回仅受控本地可用的恢复/维护服务。
	Recovery() BackupRecoveryService
}

// Backup 返回备份公开服务（每个 Runtime 缓存同一门面，使恢复源加载在 Close 前后可用）。
func (r *Runtime) Backup() BackupService {
	if r == nil {
		return &backupFacade{}
	}
	value, _ := backupFacadeRegistry.LoadOrStore(r, &backupFacade{
		r: r, admin: &adminFacade{r: r}})
	facade, ok := value.(*backupFacade)
	if !ok {
		return &backupFacade{r: r, admin: &adminFacade{r: r}}
	}
	return facade
}

type backupFacade struct {
	r        *Runtime
	admin    *adminFacade
	recovery *backupRecoveryFacade
}

func (f *backupFacade) begin(ctx context.Context, caller AdminCaller,
	requestID string) (adminRequest, error) {
	return f.admin.begin(ctx, caller, requestID)
}

// accountCaller 构造带请求编号的真实账户服务调用者（备份管理按账户 Caller 鉴权）。
func (f *backupFacade) accountCaller(call adminRequest) (account.Caller, error) {
	caller, err := f.admin.accountCaller(call.identity)
	if err != nil {
		return account.Caller{}, call.configError("备份服务调用者无效")
	}
	return bindCaller(caller, call.requestID)
}

func (f *backupFacade) managed(call adminRequest) (*backupadmin.Service, error) {
	managed := f.r.managedServices()
	if managed == nil || managed.BackupAdmin == nil {
		return nil, call.configError("备份管理服务未装配")
	}
	return managed.BackupAdmin, nil
}

// sensitive 为备份域的敏感操作准备可信上下文：本机受信操作者写独立审计并以本地
// 强认证事实执行；普通管理会话必须提供近期密码/动态码，失败 fail-closed。
func (f *backupFacade) sensitive(ctx context.Context, call adminRequest, operationID,
	targetType, targetID string, params map[string]string, password, totpCode string) (context.Context, error) {
	return f.admin.sensitiveContext(ctx, call.identity, operationID, targetType, targetID,
		params, password, totpCode, call.requestID)
}

// mapBackupError 统一映射备份管理领域错误；NotFound/越权按领域约定投影。
func (f *backupFacade) mapBackupError(call adminRequest, message string, err error) error {
	return publicBackupError(call.requestID, message, string(backupadmin.CodeOf(err)))
}

// publicBackupError 把备份/恢复领域稳定码投影为根包已登记错误码；未知码回退
// INTERNAL_ERROR，不把内部细节交给调用方。
func publicBackupError(requestID, message, code string) error {
	var public login.ErrorCode
	switch code {
	case string(backup.CodeReqInvalid):
		public = login.CodeReqInvalid
	case string(backup.CodeAccessDenied):
		public = login.CodeAccessDenied
	case string(backup.CodeConflict):
		public = login.CodeConflict
	case string(restore.CodeRestoreMaintenanceRequired):
		public = login.CodeRestoreMaintenanceRequired
	case string(backup.CodeTaskCancelConflict):
		public = login.CodeTaskCancelConflict
	case string(backup.CodeTaskCancelled):
		public = login.CodeTaskCancelled
	case string(backup.CodeTaskTimeout):
		public = login.CodeTaskTimeout
	case string(backup.CodeBackupFailed):
		public = login.CodeBackupFailed
	case string(backup.CodeBackupCancelForbidden):
		public = login.CodeBackupCancelForbidden
	case string(backup.CodeBackupInvalid):
		public = login.CodeBackupInvalid
	case string(backup.CodeBackupDecryptFailed):
		public = login.CodeBackupDecryptFailed
	case string(backup.CodeBackupVersionUnsupported):
		public = login.CodeBackupVersionUnsupported
	case string(backup.CodeAuditWriteFailed):
		public = login.CodeAuditWriteFailed
	case string(backup.CodeDBUnavailable):
		public = login.CodeDBUnavailable
	case string(backup.CodeExportPathUnsafe):
		public = login.CodeExportPathUnsafe
	default:
		public = login.CodeInternalError
	}
	return login.NewAppError(public, message, requestIDOption(requestID))
}

// ---------- 备份计划 ----------

// BackupPlanService 是备份计划管理服务（计划由真实任务调度器触发，本层不执行业务）。
type BackupPlanService interface {
	List(ctx context.Context, req AdminListBackupSchedulesRequest) (AdminBackupScheduleList, error)
	Get(ctx context.Context, req BackupPlanRequest) (BackupPlan, error)
	Create(ctx context.Context, req BackupPlanRequest) (BackupPlan, error)
	Update(ctx context.Context, req BackupPlanRequest) (BackupPlan, error)
	SetEnabled(ctx context.Context, req BackupPlanStateRequest) (BackupPlan, error)
	Delete(ctx context.Context, req BackupPlanRequest) error
}

// BackupPlan 是备份计划视图（不含宿主绝对路径与秘密）。
type BackupPlan struct {
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
	Owner             string
	ExecutionActor    string
	ScopeID           string
	NextRun           time.Time
	NextRunUnknown    bool
	RetentionVersion  int64
	NotifyFailures    bool
	NotifySuccess     bool
	LastScheduledAt   time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// BackupPlanRequest 是计划创建/更新/删除请求（原因用于敏感操作审计）。
type BackupPlanRequest struct {
	Caller           AdminCaller
	ScheduleID       string
	Name             string
	ScheduleType     string
	Expression       string
	TimeZone         string
	MissedPolicy     string
	MaxCatchUp       int
	TimeoutSeconds   int
	MaxAttempts      int
	RetentionVersion int64
	NotifyFailures   bool
	NotifySuccess    bool
	NotifyTarget     string
	Enabled          bool
	Reason           string
	Password         string
	TOTPCode         string
	RequestID        string
}

// BackupPlanStateRequest 是计划启停请求。
type BackupPlanStateRequest struct {
	Caller     AdminCaller
	ScheduleID string
	Enabled    bool
	Reason     string
	Password   string
	TOTPCode   string
	RequestID  string
}

// Plans 返回备份计划服务。
func (f *backupFacade) Plans() BackupPlanService { return &backupPlanFacade{f: f} }

type backupPlanFacade struct{ f *backupFacade }

func backupPlanView(view backupadmin.ScheduleView) BackupPlan {
	return BackupPlan{ID: view.ID, Name: view.Name, Enabled: view.Enabled,
		ScheduleType: view.ScheduleType, Expression: view.Expression, TimeZone: view.TimeZone,
		PeriodDescription: view.PeriodDescription, MissedPolicy: view.MissedPolicy,
		MaxCatchUp: view.MaxCatchUp, TimeoutSeconds: view.TimeoutSeconds,
		MaxAttempts: view.MaxAttempts, Owner: view.Owner.ID, ExecutionActor: view.ExecutionActor.ID,
		ScopeID: view.ScopeID, NextRun: view.NextRun, NextRunUnknown: view.NextRunUnknown,
		RetentionVersion: view.RetentionVersion, NotifyFailures: view.NotifyFailures,
		NotifySuccess: view.NotifySuccess, LastScheduledAt: view.LastScheduledAt,
		CreatedAt: view.CreatedAt, UpdatedAt: view.UpdatedAt}
}

// List 复用 AdminService 的分页实现（216/217 契约）。
func (s *backupPlanFacade) List(ctx context.Context,
	req AdminListBackupSchedulesRequest) (AdminBackupScheduleList, error) {
	return s.f.admin.ListBackupSchedules(ctx, req)
}

// Get 读取单个计划。
func (s *backupPlanFacade) Get(ctx context.Context, req BackupPlanRequest) (BackupPlan, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return BackupPlan{}, err
	}
	service, err := s.f.managed(call)
	if err != nil {
		return BackupPlan{}, err
	}
	caller, err := s.f.accountCaller(call)
	if err != nil {
		return BackupPlan{}, err
	}
	view, err := service.GetSchedule(ctx, caller, req.ScheduleID)
	if err != nil {
		return BackupPlan{}, s.f.mapBackupError(call, "读取备份计划失败", err)
	}
	return backupPlanView(view), nil
}

// Create 创建备份计划。
func (s *backupPlanFacade) Create(ctx context.Context, req BackupPlanRequest) (BackupPlan, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return BackupPlan{}, err
	}
	service, err := s.f.managed(call)
	if err != nil {
		return BackupPlan{}, err
	}
	caller, err := s.f.accountCaller(call)
	if err != nil {
		return BackupPlan{}, err
	}
	approved, err := s.f.sensitive(ctx, call, backupadmin.OperationCreate, "backup_schedule",
		"", map[string]string{"direction": "create", "name": req.Name},
		req.Password, req.TOTPCode)
	if err != nil {
		return BackupPlan{}, err
	}
	view, err := service.CreateSchedule(approved, backupadmin.ScheduleRequest{
		Caller: caller, Name: req.Name, ScheduleType: backupScheduleType(req.ScheduleType),
		Expression: req.Expression, TimeZone: req.TimeZone,
		MissedPolicy: backupMissedPolicy(req.MissedPolicy), MaxCatchUp: req.MaxCatchUp,
		TimeoutSeconds: req.TimeoutSeconds, MaxAttempts: req.MaxAttempts,
		RetentionVersion: req.RetentionVersion, NotifyFailures: req.NotifyFailures,
		NotifySuccess: req.NotifySuccess, NotifyTarget: req.NotifyTarget,
		Enabled: req.Enabled, RequestID: call.requestID,
	})
	if err != nil {
		return BackupPlan{}, s.f.mapBackupError(call, "创建备份计划失败", err)
	}
	return backupPlanView(view), nil
}

// Update 更新备份计划。
func (s *backupPlanFacade) Update(ctx context.Context, req BackupPlanRequest) (BackupPlan, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return BackupPlan{}, err
	}
	service, err := s.f.managed(call)
	if err != nil {
		return BackupPlan{}, err
	}
	caller, err := s.f.accountCaller(call)
	if err != nil {
		return BackupPlan{}, err
	}
	approved, err := s.f.sensitive(ctx, call, backupadmin.OperationCreate, "backup_schedule",
		req.ScheduleID, map[string]string{"direction": "update"},
		req.Password, req.TOTPCode)
	if err != nil {
		return BackupPlan{}, err
	}
	view, err := service.UpdateSchedule(approved, req.ScheduleID, backupadmin.ScheduleRequest{
		Caller: caller, Name: req.Name, ScheduleType: backupScheduleType(req.ScheduleType),
		Expression: req.Expression, TimeZone: req.TimeZone,
		MissedPolicy: backupMissedPolicy(req.MissedPolicy), MaxCatchUp: req.MaxCatchUp,
		TimeoutSeconds: req.TimeoutSeconds, MaxAttempts: req.MaxAttempts,
		RetentionVersion: req.RetentionVersion, NotifyFailures: req.NotifyFailures,
		NotifySuccess: req.NotifySuccess, NotifyTarget: req.NotifyTarget,
		Enabled: req.Enabled, RequestID: call.requestID,
	})
	if err != nil {
		return BackupPlan{}, s.f.mapBackupError(call, "更新备份计划失败", err)
	}
	return backupPlanView(view), nil
}

// SetEnabled 启用/停用备份计划（敏感操作经领域再次认证）。
func (s *backupPlanFacade) SetEnabled(ctx context.Context,
	req BackupPlanStateRequest) (BackupPlan, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return BackupPlan{}, err
	}
	service, err := s.f.managed(call)
	if err != nil {
		return BackupPlan{}, err
	}
	caller, err := s.f.accountCaller(call)
	if err != nil {
		return BackupPlan{}, err
	}
	approved, err := s.f.sensitive(ctx, call, backupadmin.OperationCreate, "backup_schedule",
		req.ScheduleID, map[string]string{"direction": "set_enabled"},
		req.Password, req.TOTPCode)
	if err != nil {
		return BackupPlan{}, err
	}
	view, err := service.SetScheduleEnabled(approved, caller, req.ScheduleID, req.Enabled,
		req.Reason, call.requestID)
	if err != nil {
		return BackupPlan{}, s.f.mapBackupError(call, "变更备份计划状态失败", err)
	}
	return backupPlanView(view), nil
}

// Delete 删除备份计划（保留历史任务/产物）。
func (s *backupPlanFacade) Delete(ctx context.Context, req BackupPlanRequest) error {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return err
	}
	service, err := s.f.managed(call)
	if err != nil {
		return err
	}
	caller, err := s.f.accountCaller(call)
	if err != nil {
		return err
	}
	approved, err := s.f.sensitive(ctx, call, backupadmin.OperationCreate, "backup_schedule",
		req.ScheduleID, map[string]string{"direction": "delete"},
		req.Password, req.TOTPCode)
	if err != nil {
		return err
	}
	if err := service.DeleteSchedule(approved, caller, req.ScheduleID, req.Reason,
		call.requestID); err != nil {
		return s.f.mapBackupError(call, "删除备份计划失败", err)
	}
	return nil
}

// ---------- 备份任务 ----------

// BackupJobService 是备份任务触发/查询/取消服务。
type BackupJobService interface {
	Trigger(ctx context.Context, req BackupJobTriggerRequest) (BackupJobRef, error)
	Get(ctx context.Context, req BackupJobRequest) (BackupJob, error)
	List(ctx context.Context, req AdminListBackupJobsRequest) (AdminBackupJobList, error)
	Cancel(ctx context.Context, req BackupJobCancelRequest) (BackupJobCancelResult, error)
}

// BackupJobRef 是任务提交结果；Existing 表示服务端按幂等规则返回已有活动任务。
// 提交成功只表示已受理，必须查询任务真实状态。
type BackupJobRef struct {
	JobID    string
	Existing bool
	State    string
}

// BackupJob 是任务视图（真实状态来自 internal/task；不伪造进度）。
type BackupJob struct {
	ID                string
	Kind              string
	Origin            string
	ScheduleID        string
	State             string
	StageCode         string
	StageDescription  string
	ProgressDone      *int64
	ProgressTotal     *int64
	ProgressUnit      string
	Attempt           int
	MaxAttempts       int
	Initiator         string
	Canceller         string
	ErrorCode         string
	FailureReason     string
	RequestID         string
	BackupID          string
	NotificationState string
	NotificationCode  string
	ResultSummary     string
	CreatedAt         time.Time
	StartedAt         time.Time
	FinishedAt        time.Time
	CancelRequestedAt time.Time
	UpdatedAt         time.Time
}

// BackupJobTriggerRequest 是手动触发备份请求（敏感操作；系统范围）。
type BackupJobTriggerRequest struct {
	Caller    AdminCaller
	Password  string
	TOTPCode  string
	RequestID string
}

// BackupJobRequest 是单任务查询/取消定位请求。
type BackupJobRequest struct {
	Caller    AdminCaller
	JobID     string
	RequestID string
}

// BackupJobCancelRequest 是取消请求：Accepted 只表示请求被受理，不等于已取消。
type BackupJobCancelRequest struct {
	Caller    AdminCaller
	JobID     string
	Reason    string
	RequestID string
}

// BackupJobCancelResult 是取消请求结果。
type BackupJobCancelResult struct {
	JobID            string
	Accepted         bool
	AlreadyRequested bool
	State            string
	Note             string
}

// Jobs 返回备份任务服务。
func (f *backupFacade) Jobs() BackupJobService { return &backupJobFacade{f: f} }

type backupJobFacade struct{ f *backupFacade }

func backupJobView(view backupadmin.JobView) BackupJob {
	canceller := ""
	if view.Canceller != nil {
		canceller = view.Canceller.ID
	}
	return BackupJob{ID: view.ID, Kind: view.Kind, Origin: view.Origin,
		ScheduleID: view.ScheduleID, State: view.State, StageCode: view.StageCode,
		StageDescription: view.StageDescription, ProgressDone: view.ProgressDone,
		ProgressTotal: view.ProgressTotal, ProgressUnit: view.ProgressUnit,
		Attempt: view.Attempt, MaxAttempts: view.MaxAttempts,
		Initiator: view.Initiator.ID, Canceller: canceller, ErrorCode: view.ErrorCode,
		FailureReason: view.FailureReason, RequestID: view.RequestID,
		BackupID: view.BackupID, NotificationState: view.NotificationStat,
		NotificationCode: view.NotificationCode, ResultSummary: view.ResultSummary,
		CreatedAt: view.CreatedAt, StartedAt: view.StartedAt, FinishedAt: view.FinishedAt,
		CancelRequestedAt: view.CancelRequestedAt, UpdatedAt: view.UpdatedAt}
}

// Trigger 触发一次手动备份任务（要求 backups.create + 敏感再认证）。
func (s *backupJobFacade) Trigger(ctx context.Context,
	req BackupJobTriggerRequest) (BackupJobRef, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return BackupJobRef{}, err
	}
	service, err := s.f.managed(call)
	if err != nil {
		return BackupJobRef{}, err
	}
	caller, err := s.f.accountCaller(call)
	if err != nil {
		return BackupJobRef{}, err
	}
	approved, err := s.f.sensitive(ctx, call, backupadmin.OperationCreate, "backup", "",
		map[string]string{"scope": "system", "kind": "backup.create"},
		req.Password, req.TOTPCode)
	if err != nil {
		return BackupJobRef{}, err
	}
	ref, err := service.EnqueueBackup(approved, caller, call.requestID)
	if err != nil {
		return BackupJobRef{}, s.f.mapBackupError(call, "提交备份任务失败", err)
	}
	return BackupJobRef{JobID: ref.JobID, Existing: ref.Existing, State: ref.State}, nil
}

// Get 查询任务真实状态（任务 ID 查询与取消是任务型 API 的必要配套）。
func (s *backupJobFacade) Get(ctx context.Context, req BackupJobRequest) (BackupJob, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return BackupJob{}, err
	}
	service, err := s.f.managed(call)
	if err != nil {
		return BackupJob{}, err
	}
	caller, err := s.f.accountCaller(call)
	if err != nil {
		return BackupJob{}, err
	}
	view, err := service.GetJob(ctx, caller, req.JobID)
	if err != nil {
		return BackupJob{}, s.f.mapBackupError(call, "查询备份任务失败", err)
	}
	return backupJobView(view), nil
}

// List 复用 AdminService 的分页实现。
func (s *backupJobFacade) List(ctx context.Context,
	req AdminListBackupJobsRequest) (AdminBackupJobList, error) {
	return s.f.admin.ListBackupJobs(ctx, req)
}

// Cancel 请求取消备份任务；真实终态以 Get 为准。
func (s *backupJobFacade) Cancel(ctx context.Context,
	req BackupJobCancelRequest) (BackupJobCancelResult, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return BackupJobCancelResult{}, err
	}
	service, err := s.f.managed(call)
	if err != nil {
		return BackupJobCancelResult{}, err
	}
	caller, err := s.f.accountCaller(call)
	if err != nil {
		return BackupJobCancelResult{}, err
	}
	view, err := service.CancelJob(ctx, caller, req.JobID, req.Reason, call.requestID)
	if err != nil {
		return BackupJobCancelResult{}, s.f.mapBackupError(call, "取消备份任务失败", err)
	}
	return BackupJobCancelResult{JobID: view.JobID, Accepted: view.Accepted,
		AlreadyRequested: view.AlreadyRequested, State: view.State, Note: view.Note}, nil
}

// ---------- 备份产物 ----------

// BackupArtifactService 是备份产物查看/认证检查/受控导出服务。
type BackupArtifactService interface {
	List(ctx context.Context, req AdminListBackupArtifactsRequest) (AdminBackupArtifactList, error)
	Get(ctx context.Context, req BackupArtifactRequest) (BackupArtifact, error)
	// Check 按备份编号做真实认证校验；需要主密钥环时由装配提供，缺失时如实标记未认证。
	Check(ctx context.Context, req BackupArtifactRequest) (BackupCheckReport, error)
	// Export 按备份编号返回受控字节；不返回/接受任意磁盘路径，大小受页面下载上限约束。
	Export(ctx context.Context, req BackupArtifactRequest) (BackupExport, error)
}

// BackupArtifact 是备份产物视图（不含宿主绝对路径）。
type BackupArtifact struct {
	BackupID         string
	JobID            string
	ScheduleID       string
	Origin           string
	SizeBytes        int64
	FileSHA256       string
	ManifestSHA256   string
	FormatVersion    int
	SchemaVersion    string
	ContentDatabase  bool
	ContentAttach    string
	ContentConfig    string
	EntryCount       int
	Hostname         string
	AppVersion       string
	Verification     string
	VerifiedAt       time.Time
	RetentionVersion int64
	Cleanup          string
	CleanedAt        time.Time
	CreatedAt        time.Time
	PublishedAt      time.Time
	FileExists       bool
	IsLastUsable     bool
	ProtectionReason string
	Downloadable     bool
}

// BackupArtifactRequest 是按备份编号的查看/检查/导出请求。
type BackupArtifactRequest struct {
	Caller    AdminCaller
	BackupID  string
	Password  string
	TOTPCode  string
	RequestID string
}

// BackupCheckReport 是备份认证校验结果（认证失败返回错误而不是假成功）。
type BackupCheckReport struct {
	StructuralValid   bool
	Encrypted         bool
	Authenticated     bool
	ManifestAvailable bool
	FormatVersion     int
	BackupID          string
	CreatedAt         time.Time
	Host              string
	AppVersion        string
	DatabaseEngine    string
	SchemaVersion     string
	SchemaVersionNum  int
	FileSHA256        string
	FileSize          int64
	ManifestSHA256    string
	EntryCount        int
}

// BackupExport 是受控导出的备份字节；调用方负责按自身渠道加密传输/落盘。
type BackupExport struct {
	BackupID    string
	FileName    string
	ContentType string
	SHA256      string
	Size        int64
	ExpiresAt   time.Time
	Data        []byte
}

// Artifacts 返回备份产物服务。
func (f *backupFacade) Artifacts() BackupArtifactService {
	return &backupArtifactFacade{f: f}
}

type backupArtifactFacade struct{ f *backupFacade }

func backupArtifactView(view backupadmin.ArtifactView) BackupArtifact {
	return BackupArtifact{BackupID: view.BackupID, JobID: view.JobID,
		ScheduleID: view.ScheduleID, Origin: view.Origin, SizeBytes: view.SizeBytes,
		FileSHA256: view.FileSHA256, ManifestSHA256: view.ManifestSHA256,
		FormatVersion: view.FormatVersion, SchemaVersion: view.SchemaVersion,
		ContentDatabase: view.ContentDatabase, ContentAttach: view.ContentAttach,
		ContentConfig: view.ContentConfig, EntryCount: view.EntryCount,
		Hostname: view.Hostname, AppVersion: view.AppVersion,
		Verification: view.Verification, VerifiedAt: view.VerifiedAt,
		RetentionVersion: view.RetentionVersion, Cleanup: view.Cleanup,
		CleanedAt: view.CleanedAt, CreatedAt: view.CreatedAt,
		PublishedAt: view.PublishedAt, FileExists: view.FileExists,
		IsLastUsable: view.IsLastUsable, ProtectionReason: view.ProtectionReason,
		Downloadable: view.Downloadable}
}

// List 复用 AdminService 的分页实现。
func (s *backupArtifactFacade) List(ctx context.Context,
	req AdminListBackupArtifactsRequest) (AdminBackupArtifactList, error) {
	return s.f.admin.ListBackupArtifacts(ctx, req)
}

// Get 读取单个备份产物元数据。
func (s *backupArtifactFacade) Get(ctx context.Context,
	req BackupArtifactRequest) (BackupArtifact, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return BackupArtifact{}, err
	}
	service, err := s.f.managed(call)
	if err != nil {
		return BackupArtifact{}, err
	}
	caller, err := s.f.accountCaller(call)
	if err != nil {
		return BackupArtifact{}, err
	}
	view, err := service.GetArtifact(ctx, caller, req.BackupID)
	if err != nil {
		return BackupArtifact{}, s.f.mapBackupError(call, "读取备份产物失败", err)
	}
	return backupArtifactView(view), nil
}

// Check 对备份编号指向的受控文件做真实认证校验。
func (s *backupArtifactFacade) Check(ctx context.Context,
	req BackupArtifactRequest) (BackupCheckReport, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return BackupCheckReport{}, err
	}
	service, err := s.f.managed(call)
	if err != nil {
		return BackupCheckReport{}, err
	}
	caller, err := s.f.accountCaller(call)
	if err != nil {
		return BackupCheckReport{}, err
	}
	report, err := service.VerifyArtifact(ctx, caller, req.BackupID, call.requestID)
	if err != nil {
		return BackupCheckReport{}, s.f.mapBackupError(call, "备份检查失败", err)
	}
	return BackupCheckReport{StructuralValid: report.StructuralValid,
		Encrypted: report.Encrypted, Authenticated: report.Authenticated,
		ManifestAvailable: report.ManifestAvailable, FormatVersion: report.FormatVersion,
		BackupID: report.BackupID, CreatedAt: report.CreatedAt, Host: report.Host,
		AppVersion: report.AppVersion, DatabaseEngine: report.Database.Engine,
		SchemaVersion:    report.Database.SchemaVersion,
		SchemaVersionNum: report.Database.SchemaVersionNumber,
		FileSHA256:       report.FileSHA256, FileSize: report.FileSize,
		ManifestSHA256: report.ManifestSHA256,
		EntryCount:     len(report.Entries)}, nil
}

// Export 按备份编号导出受控字节（一次性下载票据 + 大小/摘要复核，不暴露路径）。
func (s *backupArtifactFacade) Export(ctx context.Context,
	req BackupArtifactRequest) (BackupExport, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return BackupExport{}, err
	}
	service, err := s.f.managed(call)
	if err != nil {
		return BackupExport{}, err
	}
	caller, err := s.f.accountCaller(call)
	if err != nil {
		return BackupExport{}, err
	}
	approved, err := s.f.sensitive(ctx, call, backupadmin.OperationDownload, "backup",
		req.BackupID, map[string]string{"direction": "export"},
		req.Password, req.TOTPCode)
	if err != nil {
		return BackupExport{}, err
	}
	ticket, err := service.IssueDownloadTicket(approved, caller, req.BackupID, call.requestID)
	if err != nil {
		return BackupExport{}, s.f.mapBackupError(call, "申请备份导出失败", err)
	}
	file, err := service.RedeemDownloadTicket(approved, caller, ticket.Token, call.requestID)
	if err != nil {
		return BackupExport{}, s.f.mapBackupError(call, "读取备份导出内容失败", err)
	}
	return BackupExport{BackupID: file.BackupID, FileName: file.FileName,
		ContentType: file.ContentType, SHA256: file.SHA256, Size: file.Size,
		ExpiresAt: file.ExpiresAt, Data: file.Data}, nil
}

// backupScheduleType/backupMissedPolicy 把公开字符串映射为任务枚举；非法值由领域
// 服务按 REQ_INVALID 拒绝，不在门面猜测默认值。
func backupScheduleType(value string) task.ScheduleType {
	return task.ScheduleType(value)
}

func backupMissedPolicy(value string) task.MissedPolicy {
	return task.MissedPolicy(value)
}
