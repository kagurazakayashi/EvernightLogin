// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

// 用户批量导入导出公开 Go 接口（步骤 223，最小闭环）。
//
// 边界（Lead 已批准）：
//   - 复用 internal/userbatch 的真实任务机制：幂等键绑定调用者+内容摘要、逐行
//     结果（失败也保留稳定错误码）、任务队列/取消/续跑、敏感操作再次认证；
//   - 创建导入/导出是敏感操作：请求携带 Password/TOTPCode 仅用于本次真实再次
//     认证，不保存；LocalAdmin 走本地受信操作者审计路径，AdminSession 必须完成
//     密码（+强因素）挑战；
//   - owner 隔离：任务按真实调用者身份（local_admin/user）创建与查询，公开 API
//     不构造 system 调用者，因此不暴露系统级任务视图；
//   - “任务已受理”不等于完成：公开结果返回稳定状态，宿主需轮询 GetJob 到终态；
//   - 逐行结果不返回原始 CSV 行内容；明细有上限并显式返回 Truncated；
//   - 访问器 Runtime.UserBatch() 定义在本文件，不编辑 app/runtime.go。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/userbatch"
)

// UserBatchService 是用户批量管理门面（最小闭环）。
type UserBatchService interface {
	// PrecheckImport 只读预检查导入 CSV：拒绝密码/哈希/root/角色等非法表头，
	// 返回可导入性、总行数与逐行错误（不保存文件、不创建任务）。
	PrecheckImport(ctx context.Context,
		req AdminUserBatchPrecheckRequest) (AdminUserBatchPrecheckResult, error)
	// StartImport 创建幂等导入任务（敏感操作）。同幂等键同内容返回 Duplicate=true。
	StartImport(ctx context.Context,
		req AdminUserBatchImportRequest) (AdminUserBatchJobStart, error)
	// StartExport 创建幂等导出任务（敏感操作，字段只能从白名单减少）。
	StartExport(ctx context.Context,
		req AdminUserBatchExportRequest) (AdminUserBatchJobStart, error)
	// GetJob 读取任务终态/进度（owner 隔离；不存在返回 NOT_FOUND）。
	GetJob(ctx context.Context, req AdminUserBatchJobRequest) (AdminUserBatchJob, error)
	// ListJobs 分页列出调用者自己的任务。
	ListJobs(ctx context.Context, req AdminUserBatchListJobsRequest) (AdminUserBatchJobList, error)
	// ListRows 读取任务逐行结果（最多 limit 条；Truncated 表示明细上限截断）。
	ListRows(ctx context.Context, req AdminUserBatchRowsRequest) (AdminUserBatchRowList, error)
	// CancelJob 请求取消任务（真正取消由任务执行器收敛）；已终态返回 CONFLICT。
	CancelJob(ctx context.Context, req AdminUserBatchCancelRequest) (AdminUserBatchJob, error)
	// RetryJob 续跑 failed 任务（导入输入已被清理时返回 CONFLICT）。
	RetryJob(ctx context.Context, req AdminUserBatchJobRequest) (AdminUserBatchJob, error)
}

// AdminUserBatchPrecheckRequest 是导入预检查请求（Content 只在内存中解析）。
type AdminUserBatchPrecheckRequest struct {
	Caller    AdminCaller
	Content   []byte
	RequestID string
}

// AdminUserBatchParseError 是预检查错误（行号/列名/稳定码，不含用户原文）。
type AdminUserBatchParseError struct {
	Line   int
	Column string
	Code   string
	Reason string
}

// AdminUserBatchPrecheckResult 是预检查结果。
type AdminUserBatchPrecheckResult struct {
	Headers      []string
	TotalRows    int
	RejectedRows int
	CanImport    bool
	Truncated    bool
	Errors       []AdminUserBatchParseError
}

// AdminUserBatchImportRequest 是创建导入任务请求。
type AdminUserBatchImportRequest struct {
	Caller         AdminCaller
	IdempotencyKey string
	Content        []byte
	// Password/TOTPCode 只用于本次敏感操作再次认证，不被保存或记录。
	Password  string
	TOTPCode  string
	RequestID string
}

// AdminUserBatchExportRequest 是创建导出任务请求。
type AdminUserBatchExportRequest struct {
	Caller          AdminCaller
	IdempotencyKey  string
	Fields          []string
	IncludeFreeText bool
	MaxRows         int
	Password        string
	TOTPCode        string
	RequestID       string
}

// AdminUserBatchJob 是批量任务视图（不含导入文件/导出文件内容）。
type AdminUserBatchJob struct {
	ID             string
	Kind           string
	State          string
	OwnerType      string
	OwnerID        string
	ScopeID        string
	TotalRows      int
	CreatedCount   int
	SkippedCount   int
	ConflictCount  int
	FailedCount    int
	DeniedCount    int
	Truncated      bool
	ExportPath     string
	ExportSHA256   string
	ExportRows     int
	TaskID         string
	ErrorCode      string
	RequestID      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	FinishedAt     time.Time
	InputAvailable bool
}

// AdminUserBatchJobStart 是创建任务结果；Report 仅导入预检查有值。
type AdminUserBatchJobStart struct {
	Job       AdminUserBatchJob
	Duplicate bool
	Report    *AdminUserBatchPrecheckResult
}

// AdminUserBatchJobRequest 是单个任务请求。
type AdminUserBatchJobRequest struct {
	Caller    AdminCaller
	JobID     string
	RequestID string
}

// AdminUserBatchListJobsRequest 分页列出任务。
type AdminUserBatchListJobsRequest struct {
	Caller    AdminCaller
	Kind      string
	State     string
	Page      AdminPage
	RequestID string
}

// AdminUserBatchJobList 是任务列表结果。
type AdminUserBatchJobList struct {
	Jobs    []AdminUserBatchJob
	HasMore bool
	Page    AdminPageInfo
}

// AdminUserBatchRowsRequest 读取逐行结果；Limit 为本次最多返回行数。
type AdminUserBatchRowsRequest struct {
	Caller    AdminCaller
	JobID     string
	Limit     int
	RequestID string
}

// AdminUserBatchRow 是逐行结果（不含原始行内容）。
type AdminUserBatchRow struct {
	RowNumber          int
	Action             string
	ErrorCode          string
	ReasonCode         string
	UsernameNormalized string
	UserID             string
}

// AdminUserBatchRowList 是逐行结果列表；Truncated 表示明细达到上限被截断。
type AdminUserBatchRowList struct {
	Rows      []AdminUserBatchRow
	Truncated bool
}

// AdminUserBatchCancelRequest 是取消任务请求。
type AdminUserBatchCancelRequest struct {
	Caller    AdminCaller
	JobID     string
	Reason    string
	RequestID string
}

// UserBatch 返回用户批量管理门面。
func (r *Runtime) UserBatch() UserBatchService {
	return &userBatchFacade{r: r}
}

type userBatchFacade struct {
	r *Runtime
}

func (f *userBatchFacade) admin() *adminFacade {
	return &adminFacade{r: f.r}
}

// beginBatch 完成身份解析与调用者构造；返回批量服务。
func (f *userBatchFacade) beginBatch(ctx context.Context, caller AdminCaller,
	requestID string) (adminRequest, *userbatch.Service, account.Caller, error) {
	call, err := f.admin().begin(ctx, caller, requestID)
	if err != nil {
		return adminRequest{}, nil, account.Caller{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Batch == nil {
		return call, nil, account.Caller{}, call.configError("批量服务未装配")
	}
	accountCaller, err := f.admin().accountCaller(call.identity)
	if err != nil {
		return call, nil, account.Caller{}, call.configError("批量服务调用者无效")
	}
	if accountCaller, err = bindCaller(accountCaller, call.requestID); err != nil {
		return call, nil, account.Caller{}, err
	}
	return call, managed.Batch, accountCaller, nil
}

// PrecheckImport 只读预检查导入内容。
func (f *userBatchFacade) PrecheckImport(ctx context.Context,
	req AdminUserBatchPrecheckRequest) (AdminUserBatchPrecheckResult, error) {
	call, service, caller, err := f.beginBatch(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminUserBatchPrecheckResult{}, err
	}
	report, err := service.PrecheckImport(ctx, caller, req.Content)
	if err != nil {
		return AdminUserBatchPrecheckResult{}, call.domainError("导入预检查失败",
			string(userbatch.CodeOf(err)))
	}
	return adminBatchPrecheckOf(report), nil
}

// StartImport 创建导入任务（敏感操作）。
func (f *userBatchFacade) StartImport(ctx context.Context,
	req AdminUserBatchImportRequest) (AdminUserBatchJobStart, error) {
	call, service, caller, err := f.beginBatch(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminUserBatchJobStart{}, err
	}
	digest := sha256.Sum256(req.Content)
	approved, err := f.admin().sensitiveContext(ctx, call.identity,
		userbatch.OperationImport, "user_batch", "system", map[string]string{
			"kind": "import", "idempotency_key": strings.TrimSpace(req.IdempotencyKey),
			"digest": hex.EncodeToString(digest[:]), "bytes": lenString(len(req.Content)),
			"request_id": call.requestID,
		}, req.Password, req.TOTPCode, call.requestID)
	if err != nil {
		return AdminUserBatchJobStart{}, err
	}
	result, err := service.StartImport(approved, userbatch.ImportRequest{
		Caller: caller, IdempotencyKey: strings.TrimSpace(req.IdempotencyKey),
		Content: req.Content, RequestID: call.requestID})
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, userbatch.ErrNotFound,
			"user batch job"); ok {
			return AdminUserBatchJobStart{}, replaced
		}
		return AdminUserBatchJobStart{}, call.domainError("创建导入任务失败",
			string(userbatch.CodeOf(err)))
	}
	start := AdminUserBatchJobStart{Job: adminBatchJobOf(result.Job),
		Duplicate: result.Duplicate}
	report := adminBatchPrecheckOf(result.Report)
	start.Report = &report
	return start, nil
}

// StartExport 创建导出任务（敏感操作）。
func (f *userBatchFacade) StartExport(ctx context.Context,
	req AdminUserBatchExportRequest) (AdminUserBatchJobStart, error) {
	call, service, caller, err := f.beginBatch(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminUserBatchJobStart{}, err
	}
	approved, err := f.admin().sensitiveContext(ctx, call.identity,
		userbatch.OperationExport, "user_batch", "system", map[string]string{
			"kind": "export", "idempotency_key": strings.TrimSpace(req.IdempotencyKey),
			"fields":     strings.Join(req.Fields, ","),
			"free_text":  boolString(req.IncludeFreeText),
			"request_id": call.requestID,
		}, req.Password, req.TOTPCode, call.requestID)
	if err != nil {
		return AdminUserBatchJobStart{}, err
	}
	result, err := service.StartExport(approved, userbatch.ExportRequest{
		Caller: caller, IdempotencyKey: strings.TrimSpace(req.IdempotencyKey),
		Fields: req.Fields, IncludeFreeText: req.IncludeFreeText,
		MaxRows: req.MaxRows, RequestID: call.requestID})
	if err != nil {
		return AdminUserBatchJobStart{}, call.domainError("创建导出任务失败",
			string(userbatch.CodeOf(err)))
	}
	return AdminUserBatchJobStart{Job: adminBatchJobOf(result.Job),
		Duplicate: result.Duplicate}, nil
}

// GetJob 读取任务。
func (f *userBatchFacade) GetJob(ctx context.Context,
	req AdminUserBatchJobRequest) (AdminUserBatchJob, error) {
	call, service, caller, err := f.beginBatch(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminUserBatchJob{}, err
	}
	job, err := service.GetJob(ctx, caller, strings.TrimSpace(req.JobID))
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, userbatch.ErrNotFound,
			"user batch job"); ok {
			return AdminUserBatchJob{}, replaced
		}
		return AdminUserBatchJob{}, call.domainError("读取批量任务失败",
			string(userbatch.CodeOf(err)))
	}
	return adminBatchJobOf(job), nil
}

// ListJobs 分页列出任务。
func (f *userBatchFacade) ListJobs(ctx context.Context,
	req AdminUserBatchListJobsRequest) (AdminUserBatchJobList, error) {
	call, service, caller, err := f.beginBatch(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminUserBatchJobList{}, err
	}
	page, err := call.page(req.Page)
	if err != nil {
		return AdminUserBatchJobList{}, err
	}
	jobs, hasMore, err := service.ListJobs(ctx, caller, userbatch.ListJobsQuery{
		Kind:  userbatch.Kind(strings.TrimSpace(req.Kind)),
		State: userbatch.JobState(strings.TrimSpace(req.State)),
		Limit: page.Limit, Offset: page.Offset})
	if err != nil {
		return AdminUserBatchJobList{}, call.domainError("列出批量任务失败",
			string(userbatch.CodeOf(err)))
	}
	items := make([]AdminUserBatchJob, 0, len(jobs))
	for _, job := range jobs {
		items = append(items, adminBatchJobOf(job))
	}
	return AdminUserBatchJobList{Jobs: items, HasMore: hasMore,
		Page: NewAdminPageInfo(page, len(items), hasMore)}, nil
}

// ListRows 读取任务逐行结果（最多 limit 行，显式 Truncated）。
func (f *userBatchFacade) ListRows(ctx context.Context,
	req AdminUserBatchRowsRequest) (AdminUserBatchRowList, error) {
	call, service, caller, err := f.beginBatch(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminUserBatchRowList{}, err
	}
	limit := req.Limit
	if limit == 0 {
		limit = AdminDefaultPageLimit
	}
	if limit < 1 || limit > AdminMaxPageLimit {
		return AdminUserBatchRowList{}, mapDomainError("逐行结果条数必须在 1～100 之间",
			"REQ_INVALID", call.requestID)
	}
	rows, truncated, err := service.ListRows(ctx, caller,
		strings.TrimSpace(req.JobID), limit)
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, userbatch.ErrNotFound,
			"user batch job"); ok {
			return AdminUserBatchRowList{}, replaced
		}
		return AdminUserBatchRowList{}, call.domainError("读取逐行结果失败",
			string(userbatch.CodeOf(err)))
	}
	items := make([]AdminUserBatchRow, 0, len(rows))
	for _, row := range rows {
		items = append(items, AdminUserBatchRow{RowNumber: row.RowNumber,
			Action: string(row.Action), ErrorCode: string(row.ErrorCode),
			ReasonCode: row.ReasonCode, UsernameNormalized: row.UsernameNormalized,
			UserID: row.UserID})
	}
	return AdminUserBatchRowList{Rows: items, Truncated: truncated}, nil
}

// CancelJob 请求取消任务并返回最新任务视图。
func (f *userBatchFacade) CancelJob(ctx context.Context,
	req AdminUserBatchCancelRequest) (AdminUserBatchJob, error) {
	call, service, caller, err := f.beginBatch(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminUserBatchJob{}, err
	}
	jobID := strings.TrimSpace(req.JobID)
	if err := service.Cancel(ctx, caller, jobID, req.Reason, call.requestID); err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, userbatch.ErrNotFound,
			"user batch job"); ok {
			return AdminUserBatchJob{}, replaced
		}
		return AdminUserBatchJob{}, call.domainError("取消批量任务失败",
			string(userbatch.CodeOf(err)))
	}
	job, err := service.GetJob(ctx, caller, jobID)
	if err != nil {
		return AdminUserBatchJob{}, call.domainError("读取批量任务失败",
			string(userbatch.CodeOf(err)))
	}
	return adminBatchJobOf(job), nil
}

// RetryJob 续跑 failed 任务。
func (f *userBatchFacade) RetryJob(ctx context.Context,
	req AdminUserBatchJobRequest) (AdminUserBatchJob, error) {
	call, service, caller, err := f.beginBatch(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminUserBatchJob{}, err
	}
	job, err := service.Retry(ctx, caller, strings.TrimSpace(req.JobID),
		call.requestID)
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, userbatch.ErrNotFound,
			"user batch job"); ok {
			return AdminUserBatchJob{}, replaced
		}
		return AdminUserBatchJob{}, call.domainError("续跑批量任务失败",
			string(userbatch.CodeOf(err)))
	}
	return adminBatchJobOf(job), nil
}

// adminBatchPrecheckOf 转换预检查报告。
func adminBatchPrecheckOf(report userbatch.ParseReport) AdminUserBatchPrecheckResult {
	errors := make([]AdminUserBatchParseError, 0, len(report.Errors))
	for _, item := range report.Errors {
		errors = append(errors, AdminUserBatchParseError{Line: item.Line,
			Column: item.Column, Code: string(item.Code), Reason: item.Reason})
	}
	return AdminUserBatchPrecheckResult{Headers: report.Headers,
		TotalRows: report.TotalRows, RejectedRows: report.RejectedRows,
		CanImport: report.CanImport, Truncated: report.Truncated, Errors: errors}
}

// adminBatchJobOf 转换任务视图。
func adminBatchJobOf(job userbatch.Job) AdminUserBatchJob {
	return AdminUserBatchJob{ID: job.ID, Kind: string(job.Kind),
		State: string(job.State), OwnerType: string(job.OwnerType),
		OwnerID: job.OwnerID, ScopeID: job.ScopeID, TotalRows: job.TotalRows,
		CreatedCount: job.CreatedCount, SkippedCount: job.SkippedCount,
		ConflictCount: job.ConflictCount, FailedCount: job.FailedCount,
		DeniedCount: job.DeniedCount, Truncated: job.Truncated,
		ExportPath: job.ExportPath, ExportSHA256: job.ExportSHA256,
		ExportRows: job.ExportRows, TaskID: job.TaskID,
		ErrorCode: string(job.ErrorCode), RequestID: job.RequestID,
		CreatedAt: job.CreatedAt, UpdatedAt: job.UpdatedAt,
		FinishedAt: job.FinishedAt, InputAvailable: job.InputAvailable}
}

// lenString 把字节数转为十进制字符串（敏感操作参数摘要用，不包含内容）。
func lenString(value int) string {
	if value <= 0 {
		return "0"
	}
	digits := make([]byte, 0, 12)
	for value > 0 {
		digits = append(digits, byte('0'+value%10))
		value /= 10
	}
	for left, right := 0, len(digits)-1; left < right; left, right = left+1, right-1 {
		digits[left], digits[right] = digits[right], digits[left]
	}
	return string(digits)
}

// boolString 把布尔值转为稳定小写字符串。
func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
