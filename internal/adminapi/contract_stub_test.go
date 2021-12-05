package adminapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/backupadmin"
	"github.com/kagurazakayashi/EvernightLogin/internal/reports"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// 本文件用“接口契约替身”验证报告/备份/任务端点的传输映射与参数校验（字段白名单、
// confirm/原因、JSON 投影、令牌一次性语义）。领域服务本身的权限、敏感策略、状态机
// 与审计行为由 internal/reports 与 internal/backupadmin 的自身测试覆盖；管理 API
// 不复制这些规则。审计域则由 audit_test.go 用真实 SQLite + 真实服务端到端覆盖。

func unexpectedErr() error { return errors.New("测试替身未配置该方法") }

// stubReportService 是可配置的报告服务契约替身。
type stubReportService struct {
	history     func(context.Context, reports.HistoryListRequest) (reports.HistoryListView, error)
	get         func(context.Context, account.Caller, string) (reports.ReportView, error)
	snapshot    func(context.Context, account.Caller, string) (reports.Snapshot, error)
	issueTicket func(context.Context, account.Caller, string, reports.Format) (reports.DownloadTicket, error)
	redeem      func(context.Context, account.Caller, string) (reports.ArtifactFile, error)
	cancel      func(context.Context, account.Caller, string, string, string) (task.CancelResult, error)
	retry       func(context.Context, account.Caller, string, string, string) (reports.ReportView, error)
	preview     func(context.Context, account.Caller) (reports.CleanupPreview, error)
	cleanup     func(context.Context, reports.CleanupExecuteRequest) (reports.CleanupResult, error)
}

func (s *stubReportService) HistoryList(ctx context.Context, request reports.HistoryListRequest) (reports.HistoryListView, error) {
	if s.history == nil {
		return reports.HistoryListView{}, unexpectedErr()
	}
	return s.history(ctx, request)
}

func (s *stubReportService) Get(ctx context.Context, caller account.Caller, id string) (reports.ReportView, error) {
	if s.get == nil {
		return reports.ReportView{}, unexpectedErr()
	}
	return s.get(ctx, caller, id)
}

func (s *stubReportService) GetSnapshot(ctx context.Context, caller account.Caller, id string) (reports.Snapshot, error) {
	if s.snapshot == nil {
		return reports.Snapshot{}, unexpectedErr()
	}
	return s.snapshot(ctx, caller, id)
}

func (s *stubReportService) IssueDownloadTicket(ctx context.Context, caller account.Caller, id string, format reports.Format) (reports.DownloadTicket, error) {
	if s.issueTicket == nil {
		return reports.DownloadTicket{}, unexpectedErr()
	}
	return s.issueTicket(ctx, caller, id, format)
}

func (s *stubReportService) RedeemDownloadTicket(ctx context.Context, caller account.Caller, token string) (reports.ArtifactFile, error) {
	if s.redeem == nil {
		return reports.ArtifactFile{}, unexpectedErr()
	}
	return s.redeem(ctx, caller, token)
}

func (s *stubReportService) Cancel(ctx context.Context, caller account.Caller, id, reason, requestID string) (task.CancelResult, error) {
	if s.cancel == nil {
		return task.CancelResult{}, unexpectedErr()
	}
	return s.cancel(ctx, caller, id, reason, requestID)
}

func (s *stubReportService) Retry(ctx context.Context, caller account.Caller, id, reason, requestID string) (reports.ReportView, error) {
	if s.retry == nil {
		return reports.ReportView{}, unexpectedErr()
	}
	return s.retry(ctx, caller, id, reason, requestID)
}

func (s *stubReportService) CleanupPreview(ctx context.Context, caller account.Caller) (reports.CleanupPreview, error) {
	if s.preview == nil {
		return reports.CleanupPreview{}, unexpectedErr()
	}
	return s.preview(ctx, caller)
}

func (s *stubReportService) CleanupExecute(ctx context.Context, request reports.CleanupExecuteRequest) (reports.CleanupResult, error) {
	if s.cleanup == nil {
		return reports.CleanupResult{}, unexpectedErr()
	}
	return s.cleanup(ctx, request)
}

// stubPlanService 是报告计划只读契约替身。
type stubPlanService struct {
	list          func(context.Context, account.Caller) ([]reports.PlanView, error)
	get           func(context.Context, account.Caller, string) (reports.PlanView, error)
	create        func(context.Context, reports.PlanCreateRequest) (reports.PlanView, error)
	update        func(context.Context, reports.PlanUpdateRequest) (reports.PlanView, error)
	setEnabled    func(context.Context, account.Caller, string, bool, string, string) (reports.PlanView, error)
	deletePreview func(context.Context, account.Caller, string) (reports.PlanDeletePreview, error)
	deletePlan    func(context.Context, account.Caller, string, string, string) error
}

func (s *stubPlanService) Create(ctx context.Context, request reports.PlanCreateRequest) (reports.PlanView, error) {
	if s.create == nil {
		return reports.PlanView{}, unexpectedErr()
	}
	return s.create(ctx, request)
}

func (s *stubPlanService) Update(ctx context.Context, request reports.PlanUpdateRequest) (reports.PlanView, error) {
	if s.update == nil {
		return reports.PlanView{}, unexpectedErr()
	}
	return s.update(ctx, request)
}

func (s *stubPlanService) SetEnabled(ctx context.Context, caller account.Caller, planID string,
	enable bool, reason, requestID string) (reports.PlanView, error) {
	if s.setEnabled == nil {
		return reports.PlanView{}, unexpectedErr()
	}
	return s.setEnabled(ctx, caller, planID, enable, reason, requestID)
}

func (s *stubPlanService) DeletePreview(ctx context.Context, caller account.Caller, planID string) (reports.PlanDeletePreview, error) {
	if s.deletePreview == nil {
		return reports.PlanDeletePreview{}, unexpectedErr()
	}
	return s.deletePreview(ctx, caller, planID)
}

func (s *stubPlanService) Delete(ctx context.Context, caller account.Caller, planID, reason, requestID string) error {
	if s.deletePlan == nil {
		return unexpectedErr()
	}
	return s.deletePlan(ctx, caller, planID, reason, requestID)
}

func (s *stubPlanService) List(ctx context.Context, caller account.Caller) ([]reports.PlanView, error) {
	if s.list == nil {
		return nil, unexpectedErr()
	}
	return s.list(ctx, caller)
}

func (s *stubPlanService) Get(ctx context.Context, caller account.Caller, id string) (reports.PlanView, error) {
	if s.get == nil {
		return reports.PlanView{}, unexpectedErr()
	}
	return s.get(ctx, caller, id)
}

// stubBackupService 是备份在线服务契约替身。
type stubBackupService struct {
	capabilities   func(context.Context, account.Caller) (backupadmin.Capabilities, error)
	listArtifacts  func(context.Context, account.Caller, backupadmin.ArtifactFilter) ([]backupadmin.ArtifactView, bool, error)
	getArtifact    func(context.Context, account.Caller, string) (backupadmin.ArtifactView, error)
	listJobs       func(context.Context, account.Caller, backupadmin.JobFilter) ([]backupadmin.JobView, bool, error)
	getJob         func(context.Context, account.Caller, string) (backupadmin.JobView, error)
	enqueue        func(context.Context, account.Caller, string) (backupadmin.JobRef, error)
	cancel         func(context.Context, account.Caller, string, string, string) (backupadmin.CancelView, error)
	issueTicket    func(context.Context, account.Caller, string, string) (backupadmin.DownloadTicket, error)
	redeem         func(context.Context, account.Caller, string, string) (backupadmin.DownloadFile, error)
	retention      func(context.Context, account.Caller) (backupadmin.RetentionView, error)
	saveRetention  func(context.Context, backupadmin.RetentionChange) (backupadmin.RetentionView, error)
	preview        func(context.Context, account.Caller) (backupadmin.CleanupPreview, error)
	enqueueCleanup func(context.Context, account.Caller, string) (backupadmin.JobRef, error)
	listSchedules  func(context.Context, account.Caller) ([]backupadmin.ScheduleView, error)
	getSchedule    func(context.Context, account.Caller, string) (backupadmin.ScheduleView, error)
	createSchedule func(context.Context, backupadmin.ScheduleRequest) (backupadmin.ScheduleView, error)
	updateSchedule func(context.Context, string, backupadmin.ScheduleRequest) (backupadmin.ScheduleView, error)
	setEnabled     func(context.Context, account.Caller, string, bool, string, string) (backupadmin.ScheduleView, error)
	deleteSchedule func(context.Context, account.Caller, string, string, string) error
}

func (s *stubBackupService) CheckReadAccess(context.Context, account.Caller) error { return nil }

func (s *stubBackupService) Capabilities(ctx context.Context, caller account.Caller) (backupadmin.Capabilities, error) {
	if s.capabilities == nil {
		return backupadmin.Capabilities{}, unexpectedErr()
	}
	return s.capabilities(ctx, caller)
}

func (s *stubBackupService) ListArtifacts(ctx context.Context, caller account.Caller, filter backupadmin.ArtifactFilter) ([]backupadmin.ArtifactView, bool, error) {
	if s.listArtifacts == nil {
		return nil, false, unexpectedErr()
	}
	return s.listArtifacts(ctx, caller, filter)
}

func (s *stubBackupService) GetArtifact(ctx context.Context, caller account.Caller, id string) (backupadmin.ArtifactView, error) {
	if s.getArtifact == nil {
		return backupadmin.ArtifactView{}, unexpectedErr()
	}
	return s.getArtifact(ctx, caller, id)
}

func (s *stubBackupService) ListJobs(ctx context.Context, caller account.Caller, filter backupadmin.JobFilter) ([]backupadmin.JobView, bool, error) {
	if s.listJobs == nil {
		return nil, false, unexpectedErr()
	}
	return s.listJobs(ctx, caller, filter)
}

func (s *stubBackupService) GetJob(ctx context.Context, caller account.Caller, id string) (backupadmin.JobView, error) {
	if s.getJob == nil {
		return backupadmin.JobView{}, unexpectedErr()
	}
	return s.getJob(ctx, caller, id)
}

func (s *stubBackupService) EnqueueBackup(ctx context.Context, caller account.Caller, requestID string) (backupadmin.JobRef, error) {
	if s.enqueue == nil {
		return backupadmin.JobRef{}, unexpectedErr()
	}
	return s.enqueue(ctx, caller, requestID)
}

func (s *stubBackupService) CancelJob(ctx context.Context, caller account.Caller, id, reason, requestID string) (backupadmin.CancelView, error) {
	if s.cancel == nil {
		return backupadmin.CancelView{}, unexpectedErr()
	}
	return s.cancel(ctx, caller, id, reason, requestID)
}

func (s *stubBackupService) IssueDownloadTicket(ctx context.Context, caller account.Caller, id, requestID string) (backupadmin.DownloadTicket, error) {
	if s.issueTicket == nil {
		return backupadmin.DownloadTicket{}, unexpectedErr()
	}
	return s.issueTicket(ctx, caller, id, requestID)
}

func (s *stubBackupService) RedeemDownloadTicket(ctx context.Context, caller account.Caller, token, requestID string) (backupadmin.DownloadFile, error) {
	if s.redeem == nil {
		return backupadmin.DownloadFile{}, unexpectedErr()
	}
	return s.redeem(ctx, caller, token, requestID)
}

func (s *stubBackupService) Retention(ctx context.Context, caller account.Caller) (backupadmin.RetentionView, error) {
	if s.retention == nil {
		return backupadmin.RetentionView{}, unexpectedErr()
	}
	return s.retention(ctx, caller)
}

func (s *stubBackupService) SaveRetention(ctx context.Context, change backupadmin.RetentionChange) (backupadmin.RetentionView, error) {
	if s.saveRetention == nil {
		return backupadmin.RetentionView{}, unexpectedErr()
	}
	return s.saveRetention(ctx, change)
}

func (s *stubBackupService) CleanupPreview(ctx context.Context, caller account.Caller) (backupadmin.CleanupPreview, error) {
	if s.preview == nil {
		return backupadmin.CleanupPreview{}, unexpectedErr()
	}
	return s.preview(ctx, caller)
}

func (s *stubBackupService) EnqueueCleanup(ctx context.Context, caller account.Caller, requestID string) (backupadmin.JobRef, error) {
	if s.enqueueCleanup == nil {
		return backupadmin.JobRef{}, unexpectedErr()
	}
	return s.enqueueCleanup(ctx, caller, requestID)
}

func (s *stubBackupService) ListSchedules(ctx context.Context, caller account.Caller) ([]backupadmin.ScheduleView, error) {
	if s.listSchedules == nil {
		return nil, unexpectedErr()
	}
	return s.listSchedules(ctx, caller)
}

func (s *stubBackupService) GetSchedule(ctx context.Context, caller account.Caller, id string) (backupadmin.ScheduleView, error) {
	if s.getSchedule == nil {
		return backupadmin.ScheduleView{}, unexpectedErr()
	}
	return s.getSchedule(ctx, caller, id)
}

func (s *stubBackupService) CreateSchedule(ctx context.Context, request backupadmin.ScheduleRequest) (backupadmin.ScheduleView, error) {
	if s.createSchedule == nil {
		return backupadmin.ScheduleView{}, unexpectedErr()
	}
	return s.createSchedule(ctx, request)
}

func (s *stubBackupService) UpdateSchedule(ctx context.Context, id string, request backupadmin.ScheduleRequest) (backupadmin.ScheduleView, error) {
	if s.updateSchedule == nil {
		return backupadmin.ScheduleView{}, unexpectedErr()
	}
	return s.updateSchedule(ctx, id, request)
}

func (s *stubBackupService) SetScheduleEnabled(ctx context.Context, caller account.Caller, id string,
	enabled bool, reason, requestID string) (backupadmin.ScheduleView, error) {
	if s.setEnabled == nil {
		return backupadmin.ScheduleView{}, unexpectedErr()
	}
	return s.setEnabled(ctx, caller, id, enabled, reason, requestID)
}

func (s *stubBackupService) DeleteSchedule(ctx context.Context, caller account.Caller, id, reason, requestID string) error {
	if s.deleteSchedule == nil {
		return unexpectedErr()
	}
	return s.deleteSchedule(ctx, caller, id, reason, requestID)
}

// stubTaskReader 是任务只读契约替身，同时实现 TaskAuthorizer（默认拒绝）。
type stubTaskReader struct {
	job       task.Job
	attempts  []task.Attempt
	err       error
	authorize func(context.Context, account.Caller, task.Job) error
}

// AuthorizeTaskRead 默认拒绝，测试必须显式配置允许回调。
func (s *stubTaskReader) AuthorizeTaskRead(ctx context.Context, caller account.Caller,
	job task.Job) error {
	if s.authorize == nil {
		return errors.New("测试替身未配置任务授权")
	}
	return s.authorize(ctx, caller, job)
}

func (s *stubTaskReader) Get(context.Context, string) (task.Job, error) {
	return s.job, s.err
}

func (s *stubTaskReader) Attempts(context.Context, string) ([]task.Attempt, error) {
	return s.attempts, s.err
}

// newDomainStubServer 构造带报告/计划/备份/任务替身的管理 API。
func newDomainStubServer(t *testing.T, report *stubReportService, plan *stubPlanService,
	backup *stubBackupService, tasks *stubTaskReader, mutators ...func(*Options)) *Server {
	t.Helper()
	stub := &stubSession{secret: "management-secret", userID: adminTestUserID(4)}
	if tasks != nil {
		tasks.authorize = func(context.Context, account.Caller, task.Job) error { return nil }
	}
	options := Options{Session: stub, ErrorCodes: testCodes(),
		Reports: report, Plans: plan, Backups: backup, Tasks: tasks,
		TaskAuthorizer: tasks}
	for _, mutate := range mutators {
		mutate(&options)
	}
	server, err := New(options)
	if err != nil {
		t.Fatalf("构造管理 API 失败: %v", err)
	}
	return server
}

// TestReportEndpointsWiring 验证报告只读/下载令牌/清理端点的字段投影与参数校验。
func TestReportEndpointsWiring(t *testing.T) {
	issuedAt := adminBaseTime
	report := &stubReportService{
		history: func(_ context.Context, request reports.HistoryListRequest) (reports.HistoryListView, error) {
			if request.Limit != 5 {
				return reports.HistoryListView{}, fmt.Errorf("%w: limit", reports.ErrInvalidRequest)
			}
			return reports.HistoryListView{Records: []reports.ReportHistoryView{{
				ID: "rep_1", Name: "日报", Owner: audit.Actor{Type: audit.ActorUser, ID: adminTestUserID(4)},
				ScopeID: reports.ScopeSystem, ScopeKind: "system", State: reports.StateSucceeded,
				Formats: []reports.Format{reports.FormatCSV}, CreatedAt: adminBaseTime,
				Artifacts: []reports.ArtifactView{{Format: reports.FormatCSV, Bytes: 10,
					SHA256: "sha", Available: true}},
			}}, HasMore: true}, nil
		},
		issueTicket: func(_ context.Context, _ account.Caller, id string, format reports.Format) (reports.DownloadTicket, error) {
			if id != "rep_1" || format != reports.FormatCSV {
				return reports.DownloadTicket{}, fmt.Errorf("%w: 参数", reports.ErrInvalidRequest)
			}
			return reports.DownloadTicket{Token: "ticket-once", ReportID: id,
				Format: format, IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(5 * time.Minute),
				TTL: 5 * time.Minute}, nil
		},
		preview: func(context.Context, account.Caller) (reports.CleanupPreview, error) {
			return reports.CleanupPreview{Policy: reports.RetentionPolicy{
				ArtifactTTL: 24 * time.Hour, Source: "默认"}, TargetCount: 2,
				TotalBytes: 2048, PreviewedAt: adminBaseTime,
				Targets: []reports.CleanupTarget{{ReportID: "rep_old", Bytes: 1024}}}, nil
		},
		cleanup: func(_ context.Context, request reports.CleanupExecuteRequest) (reports.CleanupResult, error) {
			if request.Reason != "清理原因" || request.MaxTargets != 3 {
				return reports.CleanupResult{}, fmt.Errorf("%w: 参数", reports.ErrInvalidRequest)
			}
			return reports.CleanupResult{Operator: audit.Actor{Type: audit.ActorUser, ID: adminTestUserID(4)},
				StartedAt: adminBaseTime, FinishedAt: adminBaseTime.Add(time.Second),
				CleanedCount: 2, DeletedFiles: 2, FreedBytes: 2048,
				Policy:       reports.RetentionPolicy{ArtifactTTL: 24 * time.Hour},
				RawAuditNote: "原始审计未删除"}, nil
		},
	}
	server := newDomainStubServer(t, report, nil, nil, nil)
	authz := "Bearer management-secret"

	data := requireSuccess(t, callAPI(t, server, http.MethodGet,
		"/admin/v1/reports?limit=5", "", authz, nil))
	records, _ := data["reports"].([]any)
	if len(records) != 1 || data["has_more"] != true {
		t.Fatalf("报告列表投影不符: %v", data)
	}
	record, _ := records[0].(map[string]any)
	if record["id"] != "rep_1" || record["owner"].(map[string]any)["id"] != adminTestUserID(4) {
		t.Fatalf("报告条目投影不符: %v", record)
	}

	// 下载令牌：必须确认；响应只返回一次令牌与有效期，不落日志。
	reply := callAPI(t, server, http.MethodPost,
		"/admin/v1/reports/rep_1/download-tickets", `{"format":"csv"}`, authz, nil)
	requireErrorCode(t, reply, http.StatusBadRequest, "REQ_INVALID")
	data = requireSuccess(t, callAPI(t, server, http.MethodPost,
		"/admin/v1/reports/rep_1/download-tickets",
		`{"confirm":true,"format":"csv"}`, authz, nil))
	ticket, _ := data["ticket"].(map[string]any)
	if ticket["token"] != "ticket-once" || ticket["format"] != "csv" {
		t.Fatalf("下载令牌投影不符: %v", ticket)
	}

	// 清理预览与执行：执行必须确认 + 原因，结果如实返回删除计数。
	data = requireSuccess(t, callAPI(t, server, http.MethodGet,
		"/admin/v1/reports/cleanup-preview", "", authz, nil))
	preview, _ := data["cleanup_preview"].(map[string]any)
	if preview["target_count"].(float64) != 2 {
		t.Fatalf("清理预览投影不符: %v", preview)
	}
	reply = callAPI(t, server, http.MethodPost, "/admin/v1/reports/cleanup",
		`{"confirm":true,"reason":"清理原因","max_targets":3}`, authz, nil)
	requireSuccess(t, reply)
	reply = callAPI(t, server, http.MethodPost, "/admin/v1/reports/cleanup",
		`{"confirm":true,"max_targets":3}`, authz, nil)
	requireErrorCode(t, reply, http.StatusBadRequest, "REQ_INVALID")
}

// TestReportDownloadTicketOneTime 验证下载令牌兑换一次性与撤权语义由服务层传递：
// 首次兑换成功，第二次兑换由服务层拒绝，管理 API 不做本地缓存。
func TestReportDownloadTicketOneTime(t *testing.T) {
	artifactPath := filepath.Join(t.TempDir(), "report.csv")
	if err := os.WriteFile(artifactPath, []byte("a,b\n1,2\n"), 0o600); err != nil {
		t.Fatalf("准备报告产物失败: %v", err)
	}
	remaining := 1
	report := &stubReportService{
		redeem: func(_ context.Context, _ account.Caller, token string) (reports.ArtifactFile, error) {
			if token != "ticket-once" {
				return reports.ArtifactFile{}, fmt.Errorf("%w: 令牌", reports.ErrInvalidRequest)
			}
			if remaining == 0 {
				return reports.ArtifactFile{}, fmt.Errorf("%w: 令牌已使用", reports.ErrNotFound)
			}
			remaining--
			return reports.ArtifactFile{ReportID: "rep_1", Format: reports.FormatCSV,
				HostPath: artifactPath, Bytes: 8,
				ExpiresAt: adminBaseTime.Add(time.Minute)}, nil
		},
	}
	server := newDomainStubServer(t, report, nil, nil, nil)
	authz := "Bearer management-secret"
	reply := callAPI(t, server, http.MethodPost, "/admin/v1/reports/download-tickets/redeem",
		`{"token":"ticket-once"}`, authz, nil)
	if reply.status != http.StatusOK {
		t.Fatalf("首次兑换状态 = %d，响应=%s", reply.status, string(reply.body))
	}
	reply = callAPI(t, server, http.MethodPost, "/admin/v1/reports/download-tickets/redeem",
		`{"token":"ticket-once"}`, authz, nil)
	if reply.status < 400 || reply.status > 599 {
		t.Fatalf("重复兑换应被拒绝，实际状态 %d", reply.status)
	}
}

// TestPlanReadEndpoints 验证报告计划只读端点。
func TestPlanReadEndpoints(t *testing.T) {
	plan := &stubPlanService{
		list: func(context.Context, account.Caller) ([]reports.PlanView, error) {
			return []reports.PlanView{{ID: "plan_1", Name: "每日报告", Enabled: true,
				ScheduleType: task.ScheduleTypeDaily, Expression: "09:00", TimeZone: "UTC",
				ScopeID: reports.ScopeSystem, ScopeKind: "system",
				Formats: []reports.Format{reports.FormatHTML}, Version: 2,
				Owner: audit.Actor{Type: audit.ActorUser, ID: adminTestUserID(4)}}}, nil
		},
		get: func(_ context.Context, _ account.Caller, id string) (reports.PlanView, error) {
			if id != "plan_1" {
				return reports.PlanView{}, fmt.Errorf("%w: 计划", reports.ErrNotFound)
			}
			return reports.PlanView{ID: id, Name: "每日报告", Version: 2,
				Owner: audit.Actor{Type: audit.ActorUser, ID: adminTestUserID(4)}}, nil
		},
	}
	server := newDomainStubServer(t, nil, plan, nil, nil)
	authz := "Bearer management-secret"
	data := requireSuccess(t, callAPI(t, server, http.MethodGet, "/admin/v1/report-plans", "", authz, nil))
	plans, _ := data["plans"].([]any)
	if len(plans) != 1 || plans[0].(map[string]any)["version"].(float64) != 2 {
		t.Fatalf("计划列表投影不符: %v", data)
	}
	requireSuccess(t, callAPI(t, server, http.MethodGet, "/admin/v1/report-plans/plan_1", "", authz, nil))
	reply := callAPI(t, server, http.MethodGet, "/admin/v1/report-plans/plan_x", "", authz, nil)
	if reply.status < 400 || reply.status > 599 {
		t.Fatalf("未知计划应拒绝，实际状态 %d", reply.status)
	}
}

// TestBackupEndpointsWiring 验证备份列表/创建/取消/保留策略/清理/下载令牌端点。
func TestBackupEndpointsWiring(t *testing.T) {
	backup := &stubBackupService{
		listArtifacts: func(_ context.Context, _ account.Caller, filter backupadmin.ArtifactFilter) ([]backupadmin.ArtifactView, bool, error) {
			if filter.Limit != 5 {
				return nil, false, fmt.Errorf("%w: limit", backupadmin.ErrInvalidRequest)
			}
			return []backupadmin.ArtifactView{{BackupID: "bak_1", SizeBytes: 10,
				Verification: string(backupadmin.VerificationVerified),
				FileExists:   true, Downloadable: true}}, false, nil
		},
		enqueue: func(_ context.Context, _ account.Caller, requestID string) (backupadmin.JobRef, error) {
			if requestID == "" {
				return backupadmin.JobRef{}, fmt.Errorf("%w: request_id", backupadmin.ErrInvalidRequest)
			}
			return backupadmin.JobRef{JobID: "job_1", State: "queued"}, nil
		},
		cancel: func(_ context.Context, _ account.Caller, id, reason, _ string) (backupadmin.CancelView, error) {
			if id != "job_1" || reason != "取消原因" {
				return backupadmin.CancelView{}, fmt.Errorf("%w: 参数", backupadmin.ErrInvalidRequest)
			}
			return backupadmin.CancelView{JobID: id, Accepted: true, State: "cancel_requested"}, nil
		},
		retention: func(context.Context, account.Caller) (backupadmin.RetentionView, error) {
			return backupadmin.RetentionView{Policy: backupadmin.RetentionPolicy{
				Version: 3, MaxCount: 5, MaxAgeDays: 0, MaxTotalBytes: 0,
				UpdatedAt: adminBaseTime}}, nil
		},
		saveRetention: func(_ context.Context, change backupadmin.RetentionChange) (backupadmin.RetentionView, error) {
			if change.ExpectedVersion != 3 || change.Reason != "调整策略" || change.MaxCount != 6 {
				return backupadmin.RetentionView{}, fmt.Errorf("%w: 参数", backupadmin.ErrInvalidRequest)
			}
			return backupadmin.RetentionView{Policy: backupadmin.RetentionPolicy{
				Version: 4, MaxCount: change.MaxCount, UpdatedAt: adminBaseTime}}, nil
		},
		preview: func(context.Context, account.Caller) (backupadmin.CleanupPreview, error) {
			return backupadmin.CleanupPreview{
				Policy:        backupadmin.RetentionPolicy{Version: 4},
				TotalRetained: 2, TotalBytes: 100, TargetBytes: 20,
				PreviewedAt: adminBaseTime,
				Targets: []backupadmin.CleanupCandidate{{ArtifactView: backupadmin.ArtifactView{
					BackupID: "bak_old"}, Reason: "超过保留数量"}}}, nil
		},
		enqueueCleanup: func(_ context.Context, _ account.Caller, requestID string) (backupadmin.JobRef, error) {
			if requestID == "" {
				return backupadmin.JobRef{}, fmt.Errorf("%w: request_id", backupadmin.ErrInvalidRequest)
			}
			return backupadmin.JobRef{JobID: "job_2", State: "queued"}, nil
		},
		issueTicket: func(_ context.Context, _ account.Caller, id, _ string) (backupadmin.DownloadTicket, error) {
			if id != "bak_1" {
				return backupadmin.DownloadTicket{}, fmt.Errorf("%w: 目标", backupadmin.ErrInvalidRequest)
			}
			return backupadmin.DownloadTicket{BackupID: id, Token: "backup-ticket",
				ExpiresAt: adminBaseTime.Add(5 * time.Minute)}, nil
		},
		redeem: func(_ context.Context, _ account.Caller, token, _ string) (backupadmin.DownloadFile, error) {
			if token != "backup-ticket" {
				return backupadmin.DownloadFile{}, fmt.Errorf("%w: 令牌", backupadmin.ErrInvalidRequest)
			}
			return backupadmin.DownloadFile{BackupID: "bak_1", FileName: "bak_1.bin",
				ContentType: "application/octet-stream", Size: 4,
				Data: []byte{1, 2, 3, 4}}, nil
		},
		listJobs: func(context.Context, account.Caller, backupadmin.JobFilter) ([]backupadmin.JobView, bool, error) {
			return []backupadmin.JobView{{ID: "job_1", Kind: "backup.create",
				State: "queued", CreatedAt: adminBaseTime}}, false, nil
		},
		getJob: func(context.Context, account.Caller, string) (backupadmin.JobView, error) {
			return backupadmin.JobView{ID: "job_1", State: "running"}, nil
		},
		capabilities: func(context.Context, account.Caller) (backupadmin.Capabilities, error) {
			return backupadmin.Capabilities{Read: true, Create: true, DownloadTTL: 5 * time.Minute}, nil
		},
	}
	server := newDomainStubServer(t, nil, nil, backup, nil)
	authz := "Bearer management-secret"

	data := requireSuccess(t, callAPI(t, server, http.MethodGet, "/admin/v1/backups?limit=5", "", authz, nil))
	backups, _ := data["backups"].([]any)
	if len(backups) != 1 || backups[0].(map[string]any)["backup_id"] != "bak_1" {
		t.Fatalf("备份列表投影不符: %v", data)
	}

	// 创建备份：必须确认；提交成功只代表排队。
	reply := callAPI(t, server, http.MethodPost, "/admin/v1/backups", `{}`, authz, nil)
	requireErrorCode(t, reply, http.StatusBadRequest, "REQ_INVALID")
	data = requireSuccess(t, callAPI(t, server, http.MethodPost, "/admin/v1/backups",
		`{"confirm":true}`, authz, nil))
	job, _ := data["job"].(map[string]any)
	if job["job_id"] != "job_1" || job["state"] != "queued" {
		t.Fatalf("备份提交投影不符: %v", job)
	}

	// 取消：必须确认 + 原因。
	reply = callAPI(t, server, http.MethodPost, "/admin/v1/backups/jobs/job_1/cancel",
		`{"confirm":true}`, authz, nil)
	requireErrorCode(t, reply, http.StatusBadRequest, "REQ_INVALID")
	data = requireSuccess(t, callAPI(t, server, http.MethodPost,
		"/admin/v1/backups/jobs/job_1/cancel",
		`{"confirm":true,"reason":"取消原因"}`, authz, nil))
	cancel, _ := data["cancel"].(map[string]any)
	if cancel["accepted"] != true || cancel["state"] != "cancel_requested" {
		t.Fatalf("取消投影不符: %v", cancel)
	}

	// 保留策略：版本并发 + 确认 + 原因。
	data = requireSuccess(t, callAPI(t, server, http.MethodGet, "/admin/v1/backups/retention", "", authz, nil))
	retention, _ := data["retention"].(map[string]any)
	if retention["policy"].(map[string]any)["version"].(float64) != 3 {
		t.Fatalf("保留策略投影不符: %v", retention)
	}
	reply = callAPI(t, server, http.MethodPut, "/admin/v1/backups/retention",
		`{"confirm":true,"max_count":6,"expected_version":3,"reason":"调整策略"}`, authz, nil)
	requireSuccess(t, reply)
	reply = callAPI(t, server, http.MethodPut, "/admin/v1/backups/retention",
		`{"max_count":6,"expected_version":3,"reason":"调整策略"}`, authz, nil)
	requireErrorCode(t, reply, http.StatusBadRequest, "REQ_INVALID")

	// 清理预览与提交。
	data = requireSuccess(t, callAPI(t, server, http.MethodGet,
		"/admin/v1/backups/cleanup-preview", "", authz, nil))
	preview, _ := data["cleanup_preview"].(map[string]any)
	if preview["target_bytes"].(float64) != 20 {
		t.Fatalf("备份清理预览投影不符: %v", preview)
	}
	reply = callAPI(t, server, http.MethodPost, "/admin/v1/backups/cleanup", `{}`, authz, nil)
	requireErrorCode(t, reply, http.StatusBadRequest, "REQ_INVALID")
	requireSuccess(t, callAPI(t, server, http.MethodPost, "/admin/v1/backups/cleanup",
		`{"confirm":true}`, authz, nil))

	// 下载令牌：签发 + 兑换真实字节。
	reply = callAPI(t, server, http.MethodPost,
		"/admin/v1/backups/bak_1/download-tickets", `{}`, authz, nil)
	requireErrorCode(t, reply, http.StatusBadRequest, "REQ_INVALID")
	data = requireSuccess(t, callAPI(t, server, http.MethodPost,
		"/admin/v1/backups/bak_1/download-tickets", `{"confirm":true}`, authz, nil))
	ticket, _ := data["ticket"].(map[string]any)
	if ticket["token"] != "backup-ticket" {
		t.Fatalf("备份下载令牌投影不符: %v", ticket)
	}
	reply = callAPI(t, server, http.MethodPost, "/admin/v1/backups/download-tickets/redeem",
		`{"token":"backup-ticket"}`, authz, nil)
	if reply.status != http.StatusOK || len(reply.body) != 4 || reply.header.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("备份下载响应不符: status=%d body=%v", reply.status, reply.body)
	}
}

// TestTaskDetailEndpoint 验证任务详情不返回载荷且包含尝试历史。
func TestTaskDetailEndpoint(t *testing.T) {
	tasks := &stubTaskReader{job: task.Job{
		ID: "job_9", Kind: "backup.create", State: task.StateRunning,
		Initiator:  audit.Actor{Type: audit.ActorUser, ID: adminTestUserID(4)},
		ExecutorID: "worker_1", Attempt: 1, MaxAttempts: 3, TimeoutSeconds: 60,
		Payload:   []byte(`{"database_path":"/secret/path"}`),
		CreatedAt: adminBaseTime, UpdatedAt: adminBaseTime,
	}, attempts: []task.Attempt{{JobID: "job_9", Attempt: 1, Outcome: "running"}}}
	server := newDomainStubServer(t, nil, nil, nil, tasks)
	authz := "Bearer management-secret"
	data := requireSuccess(t, callAPI(t, server, http.MethodGet, "/admin/v1/tasks/job_9", "", authz, nil))
	job, _ := data["task"].(map[string]any)
	if job["id"] != "job_9" || job["state"] != "running" {
		t.Fatalf("任务详情投影不符: %v", job)
	}
	if _, leaked := job["payload"]; leaked {
		t.Fatalf("任务详情不应包含载荷")
	}
	attempts, _ := job["attempts"].([]any)
	if len(attempts) != 1 {
		t.Fatalf("任务尝试历史缺失: %v", job["attempts"])
	}

	// 权限/数据范围拒绝：统一 403，不返回任务元数据。
	tasks.authorize = func(context.Context, account.Caller, task.Job) error {
		return errors.New("无权读取该任务")
	}
	reply := callAPI(t, server, http.MethodGet, "/admin/v1/tasks/job_9", "", authz, nil)
	payload := requireErrorCode(t, reply, http.StatusForbidden, "ACCESS_DENIED")
	if strings.Contains(fmt.Sprint(payload), "job_9") {
		t.Fatalf("拒绝响应泄露了任务编号: %v", payload)
	}

	// 任务不存在：统一 404，不区分是否存在与无权枚举。
	tasks.authorize = func(context.Context, account.Caller, task.Job) error { return nil }
	tasks.err = task.ErrTaskNotFound
	reply = callAPI(t, server, http.MethodGet, "/admin/v1/tasks/job_x", "", authz, nil)
	requireErrorCode(t, reply, http.StatusNotFound, "REQ_INVALID")

	// 未装配 TaskAuthorizer 时任务路由不挂载（fail-closed）。
	unwired, err := New(Options{Session: &stubSession{secret: "management-secret",
		userID: adminTestUserID(4)}, ErrorCodes: testCodes(), Tasks: tasks})
	if err != nil {
		t.Fatalf("构造管理 API 失败: %v", err)
	}
	reply = callAPI(t, unwired, http.MethodGet, "/admin/v1/tasks/job_9", "", authz, nil)
	requireErrorCode(t, reply, http.StatusNotFound, "REQ_INVALID")
}

// 编译期确认替身满足管理 API 契约。
var (
	_ ReportService     = (*stubReportService)(nil)
	_ ReportPlanService = (*stubPlanService)(nil)
	_ BackupService     = (*stubBackupService)(nil)
	_ TaskReader        = (*stubTaskReader)(nil)
)
