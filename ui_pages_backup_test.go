package login_test

// 步骤 81 备份管理页面契约测试：路由注册/模板解析、列表/详情渲染、CSRF、下载响应头、
// 无权限状态与模板 i18n 键登记。使用受控页面后端替身；真实服务联调见 backupadmin
// 端到端测试与 uiadminadapter 适配器集成断言。

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
)

const (
	backupTestUserID = "usr_00000000000000000000000000000081"
	backupTestCSRF   = "csrf-backup-test"
	backupTestID     = "bkp_11111111111111111111111111111111"
	backupTestJobID  = "job_11111111111111111111111111111111"
)

// fakeBackupBackend 是页面后端替身（只验证页面契约，不进入生产装配）。
type fakeBackupBackend struct {
	caps        login.UIBackupCapabilities
	schedules   []login.UIBackupSchedule
	schedule    login.UIBackupSchedule
	job         login.UIBackupJob
	jobs        []login.UIBackupJob
	artifact    login.UIBackupArtifact
	artifacts   []login.UIBackupArtifact
	retention   login.UIBackupRetention
	preview     login.UIBackupCleanupPreview
	file        login.UIBackupDownload
	denials     []string
	cleanup     bool
	listErr     error
	saveErr     error
	downloadErr error
}

func (f *fakeBackupBackend) Capabilities(context.Context, string) (login.UIBackupCapabilities, error) {
	return f.caps, nil
}
func (f *fakeBackupBackend) RecordDenial(_ context.Context, _, reason string) error {
	f.denials = append(f.denials, reason)
	return nil
}
func (f *fakeBackupBackend) ListSchedules(context.Context, string) ([]login.UIBackupSchedule, error) {
	return f.schedules, f.listErr
}
func (f *fakeBackupBackend) GetSchedule(context.Context, string, string) (login.UIBackupSchedule, error) {
	return f.schedule, nil
}
func (f *fakeBackupBackend) SaveSchedule(_ context.Context, _, _ string,
	_ login.UIBackupScheduleRequest, _ string) (login.UIBackupSchedule, error) {
	return f.schedule, f.saveErr
}
func (f *fakeBackupBackend) SetScheduleEnabled(_ context.Context, _, _ string, _ bool,
	_, _ string) (login.UIBackupSchedule, error) {
	return f.schedule, nil
}
func (f *fakeBackupBackend) DeleteSchedule(context.Context, string, string, string, string) error {
	return nil
}
func (f *fakeBackupBackend) EnqueueBackup(context.Context, string,
	string) (login.UIBackupJobRef, error) {
	return login.UIBackupJobRef{JobID: backupTestJobID}, nil
}
func (f *fakeBackupBackend) ListJobs(context.Context, string, string, int,
	int) ([]login.UIBackupJob, bool, error) {
	return f.jobs, false, f.listErr
}
func (f *fakeBackupBackend) GetJob(context.Context, string, string) (login.UIBackupJob, error) {
	return f.job, nil
}
func (f *fakeBackupBackend) CancelJob(_ context.Context, _, jobID, _, _ string) (login.UIBackupCancelResult, error) {
	return login.UIBackupCancelResult{JobID: jobID, Accepted: true,
		State: "cancel_requested", Note: "取消请求已接受；实际结果以任务状态为准。"}, nil
}
func (f *fakeBackupBackend) ListArtifacts(_ context.Context, _ string,
	_ login.UIBackupArtifactQuery) ([]login.UIBackupArtifact, bool, error) {
	return f.artifacts, false, f.listErr
}
func (f *fakeBackupBackend) GetArtifact(context.Context, string, string) (login.UIBackupArtifact, error) {
	return f.artifact, nil
}
func (f *fakeBackupBackend) Download(context.Context, string, string) (login.UIBackupDownload, error) {
	return f.file, f.downloadErr
}
func (f *fakeBackupBackend) ListNotifications(context.Context, string, string,
	string) ([]login.UIBackupNotification, error) {
	return []login.UIBackupNotification{{ID: "ntf_1", Kind: "backup_failed",
		State: "failed", Channel: "local", RecipientMasked: "owner_mail", CreatedAt: time.Now()}}, nil
}
func (f *fakeBackupBackend) Retention(context.Context, string) (login.UIBackupRetention, error) {
	return f.retention, nil
}
func (f *fakeBackupBackend) SaveRetention(_ context.Context, _ string,
	_ login.UIBackupRetentionRequest, _ string) (login.UIBackupRetention, error) {
	return f.retention, nil
}
func (f *fakeBackupBackend) CleanupPreview(context.Context, string) (login.UIBackupCleanupPreview, error) {
	return f.preview, nil
}
func (f *fakeBackupBackend) RunCleanup(context.Context, string,
	string) (login.UIBackupJobRef, error) {
	return login.UIBackupJobRef{JobID: backupTestJobID}, nil
}
func (f *fakeBackupBackend) Reconcile(context.Context, string) (login.UIBackupReconcileResult, error) {
	return login.UIBackupReconcileResult{Scanned: 1, Orphans: 1}, nil
}

// backupPageSessions 提供管理会话。
type backupPageSessions struct{}

func (backupPageSessions) ResolvePageSession(context.Context,
	*http.Request) (login.UISession, error) {
	return login.UISession{Authenticated: true, UserID: backupTestUserID,
		Kind: "management", ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (backupPageSessions) IssueCSRFToken(context.Context, *http.Request) (string, error) {
	return backupTestCSRF, nil
}

// backupPageEnv 是备份页面测试环境。
type backupPageEnv struct {
	handler http.Handler
	backend *fakeBackupBackend
}

// newBackupPageEnv 构造测试环境。
func newBackupPageEnv(t *testing.T) *backupPageEnv {
	t.Helper()
	now := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	schedule := login.UIBackupSchedule{ID: "sch_11111111111111111111111111111111",
		Name: "每日备份", Enabled: true, ScheduleType: "daily", Expression: "02:30",
		TimeZone: "Asia/Shanghai", PeriodDescription: "每天 02:30", MissedPolicy: "latest",
		MaxCatchUp: 10, TimeoutSeconds: 3600, MaxAttempts: 1,
		Owner: "user · x", ExecutionActor: "user · " + backupTestUserID,
		ScopeID: "system", NextRun: now.Add(10 * time.Hour), RetentionVersion: 1,
		NotifyFailures: true, CreatedAt: now, UpdatedAt: now}
	artifact := login.UIBackupArtifact{BackupID: backupTestID, JobID: backupTestJobID,
		Origin: "manual", SizeBytes: 4096, FileSHA256: strings.Repeat("a", 64),
		FormatVersion: 1, SchemaVersion: "0043", ContentDatabase: true,
		ContentAttach: "not_configured", ContentConfig: "not_configured",
		Verification: "verified", VerifiedAt: now, RetentionVersion: 1,
		Cleanup: "retained", PublishedAt: now, FileExists: true, IsLastUsable: true,
		ProtectionReason: "受保护：这是当前范围最后一份可用备份。", Downloadable: true}
	job := login.UIBackupJob{ID: backupTestJobID, Kind: "backup.create",
		Origin: "manual", State: "running", StageCode: "snapshot",
		StageDescription: "正在建立数据库一致性快照", Attempt: 1, MaxAttempts: 2,
		Initiator: "user · x", CreatedAt: now, UpdatedAt: now}
	backend := &fakeBackupBackend{
		caps: login.UIBackupCapabilities{Read: true, Create: true, Cancel: true,
			Download: true, Retention: true, Cleanup: true, DownloadTTL: 2 * time.Minute},
		schedules: []login.UIBackupSchedule{schedule},
		schedule:  schedule,
		job:       job,
		jobs:      []login.UIBackupJob{job},
		artifact:  artifact,
		artifacts: []login.UIBackupArtifact{artifact},
		retention: login.UIBackupRetention{Version: 3, MaxCount: 5, MaxAgeDays: 30,
			MaxTotalBytes: 1 << 30, UpdatedBy: "user · x", UpdatedAt: now,
			LastCleanup: &login.UIBackupCleanupSummary{JobID: backupTestJobID,
				State: "succeeded", RequestedCount: 2, CleanedCount: 2, FreedBytes: 8192,
				FinishedAt: now}},
		preview: login.UIBackupCleanupPreview{
			Policy:  login.UIBackupRetention{Version: 3, MaxCount: 5},
			Targets: []login.UIBackupCleanupCandidate{{Artifact: artifact, Reason: "超过最多保留数量"}},
			Protected: []login.UIBackupCleanupCandidate{
				{Artifact: artifact, Reason: "受保护：这是当前范围最后一份可用备份。"}},
			TotalRetained: 2, TotalBytes: 8192, TargetBytes: 4096,
			PreviewedAt: now, Note: "预览不是删除授权"},
		file: login.UIBackupDownload{BackupID: backupTestID,
			FileName: "login-backup_20261119T100000Z_" + backupTestID + ".elnbak",
			SHA256:   strings.Repeat("a", 64), Size: 4, Data: []byte("data")},
	}
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session: backupPageSessions{},
		Logger:  slog.New(slog.NewTextHandler(os.Stderr, nil)),
		PageBackups: &login.UIPageBackupOptions{
			Backend: backend,
			ValidateCSRF: func(context.Context, *http.Request, string) error {
				return nil
			},
		}})
	if err != nil {
		t.Fatalf("备份页面框架: %v", err)
	}
	return &backupPageEnv{handler: ui, backend: backend}
}

// request 发送测试请求。
func (e *backupPageEnv) request(method, target string, body []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "http://example.test"+target, bytes.NewReader(body))
	if body != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	recorder := httptest.NewRecorder()
	e.handler.ServeHTTP(recorder, request)
	return recorder
}

func (e *backupPageEnv) get(target string) *httptest.ResponseRecorder {
	return e.request(http.MethodGet, target, nil)
}

func (e *backupPageEnv) post(target string, values url.Values) *httptest.ResponseRecorder {
	values.Set("csrf_token", backupTestCSRF)
	return e.request(http.MethodPost, target, []byte(values.Encode()))
}

// TestBackupPagesRenderAndStates 验证模板解析、列表/详情渲染、无权限与下载响应头。
func TestBackupPagesRenderAndStates(t *testing.T) {
	env := newBackupPageEnv(t)
	checks := []struct {
		target string
		want   string
	}{
		{"/admin/backups/schedules", "每日备份"},
		{"/admin/backups/schedules/new", "新建备份计划"},
		{"/admin/backups/schedules/edit?schedule_id=sch_11111111111111111111111111111111", "编辑备份计划"},
		{"/admin/backups/jobs", backupTestJobID},
		{"/admin/backups/jobs/detail?job_id=" + backupTestJobID, "正在建立数据库一致性快照"},
		{"/admin/backups", backupTestID},
		{"/admin/backups/detail?backup_id=" + backupTestID, "受保护：这是当前范围最后一份可用备份。"},
		{"/admin/backups/retention", "数量、天数和容量上限产生清理候选；保护规则优先，原始审计不受影响。"},
		{"/admin/backups/cleanup/preview", "预览不是删除授权"},
	}
	for _, check := range checks {
		response := env.get(check.target)
		if response.Code != http.StatusOK {
			t.Fatalf("%s 状态=%d", check.target, response.Code)
		}
		if !strings.Contains(response.Body.String(), check.want) {
			t.Fatalf("%s 缺少期望内容 %q", check.target, check.want)
		}
	}
	// 下载：POST + CSRF，禁止缓存与嗅探，正文为受控字节。
	download := env.post("/admin/backups/download", url.Values{"backup_id": {backupTestID}})
	if download.Code != http.StatusOK || download.Body.String() != "data" {
		t.Fatalf("下载状态=%d body=%q", download.Code, download.Body.String())
	}
	for header, want := range map[string]string{
		"Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
		"X-Content-Type-Options": "nosniff", "X-Content-SHA256": strings.Repeat("a", 64),
		"Content-Security-Policy": "default-src 'none'; sandbox",
		"Content-Type":            "application/octet-stream",
	} {
		if got := download.Header().Get(header); !strings.Contains(got, want) {
			t.Fatalf("下载响应头 %s = %q，期望包含 %q", header, got, want)
		}
	}
	// 无 CSRF 的写操作被拒绝并记录拒绝原因。
	noToken := env.request(http.MethodPost, "/admin/backups/cleanup",
		[]byte("action=cleanup"))
	if noToken.Code != http.StatusForbidden {
		t.Fatalf("缺少 CSRF 的清理请求状态=%d，期望 403", noToken.Code)
	}
	if len(env.backend.denials) == 0 {
		t.Fatal("CSRF 失败应记录页面级拒绝")
	}
	// 无权限：读取被拒绝且不渲染敏感内容。
	env.backend.caps = login.UIBackupCapabilities{}
	forbidden := env.get("/admin/backups")
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("无权限历史列表状态=%d，期望 403", forbidden.Code)
	}
	if strings.Contains(forbidden.Body.String(), backupTestID) {
		t.Fatal("无权限页面不得渲染备份编号")
	}
}

// TestBackupTemplateI18nKeysRegistered 校验模板引用的每个静态 i18n 键都已在 zh-CN
// 目录登记，防止裸键或整包渲染失败。
func TestBackupTemplateI18nKeysRegistered(t *testing.T) {
	raw, err := os.ReadFile("web/i18n/zh-CN.json")
	if err != nil {
		t.Fatalf("读取 zh-CN 目录失败: %v", err)
	}
	catalog := map[string]string{}
	if err := json.Unmarshal(raw, &catalog); err != nil {
		t.Fatalf("解析 zh-CN 目录失败: %v", err)
	}
	files := []string{
		"web/templates/page/admin/backup_schedules.html",
		"web/templates/page/admin/backup_schedule_form.html",
		"web/templates/page/admin/backup_jobs.html",
		"web/templates/page/admin/backup_job_detail.html",
		"web/templates/page/admin/backups.html",
		"web/templates/page/admin/backup_detail.html",
		"web/templates/page/admin/backup_retention.html",
	}
	quotedKey := regexp.MustCompile(`\bt "[a-z0-9_.]+"`)
	staticKeys := map[string]struct{}{}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("读取模板 %s 失败: %v", path, err)
		}
		for _, match := range quotedKey.FindAllString(string(data), -1) {
			key := strings.TrimSuffix(strings.TrimPrefix(match, `t "`), `"`)
			staticKeys[key] = struct{}{}
		}
	}
	missing := make([]string, 0, len(staticKeys))
	for key := range staticKeys {
		if _, ok := catalog[key]; !ok {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("备份模板引用了未登记 i18n 键: %v", missing)
	}
	// 动态键：周期/补跑策略/通知状态必须覆盖全部稳定值。
	for _, key := range []string{
		"page.admin.backups.schedules.daily", "page.admin.backups.schedules.weekly",
		"page.admin.backups.schedules.monthly", "page.admin.backups.schedules.custom",
		"page.admin.backups.schedules.missed_skip", "page.admin.backups.schedules.missed_latest",
		"page.admin.backups.schedules.missed_all",
		"page.admin.backups.notification.not_configured", "page.admin.backups.notification.pending",
		"page.admin.backups.notification.accepted", "page.admin.backups.notification.failed",
		"page.admin.backups.notification.unknown",
		"page.admin.backups.job_state.queued", "page.admin.backups.job_state.running",
		"page.admin.backups.job_state.cancel_requested", "page.admin.backups.job_state.cancelled",
		"page.admin.backups.job_state.succeeded", "page.admin.backups.job_state.failed",
		"page.admin.backups.job_state.timed_out",
	} {
		if _, ok := catalog[key]; !ok {
			t.Fatalf("动态 i18n 键未登记: %s", key)
		}
	}
}
