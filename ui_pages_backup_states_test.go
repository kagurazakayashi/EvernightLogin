package login_test

// 步骤 81 修复轮页面状态矩阵测试：空态、加载失败、冲突（409）、取消请求措辞、会话
// 过期与下载超限拒绝。

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	login "github.com/kagurazakayashi/EvernightLogin"
)

// expiredSessions 返回会话过期错误。
type expiredSessions struct{}

func (expiredSessions) ResolvePageSession(context.Context, *http.Request) (login.UISession, error) {
	return login.UISession{}, login.ErrUISessionExpired
}

func (expiredSessions) IssueCSRFToken(context.Context, *http.Request) (string, error) {
	return backupTestCSRF, nil
}

// TestBackupPageStateMatrix 验证空态、加载失败、冲突、取消措辞、下载超限与会话过期。
func TestBackupPageStateMatrix(t *testing.T) {
	env := newBackupPageEnv(t)
	// 空态：分别说明尚无计划/任务/历史备份。
	env.backend.schedules = nil
	env.backend.artifacts = nil
	env.backend.jobs = nil
	for target, want := range map[string]string{
		"/admin/backups/schedules": "当前范围内还没有备份计划",
		"/admin/backups/jobs":      "当前范围内还没有备份任务",
		"/admin/backups":           "当前范围内还没有历史备份",
	} {
		response := env.get(target)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), want) {
			t.Fatalf("%s 空态应为 200 且包含 %q，得到 %d", target, want, response.Code)
		}
	}
	// 加载失败：503 且显示失败摘要，不伪造成空列表。
	env.backend.listErr = &login.UIBackupError{Code: "UNAVAILABLE"}
	loadFailed := env.get("/admin/backups")
	if loadFailed.Code != http.StatusServiceUnavailable ||
		!strings.Contains(loadFailed.Body.String(), "无法读取备份数据") {
		t.Fatalf("加载失败状态=%d", loadFailed.Code)
	}
	env.backend.listErr = nil
	// 版本/状态冲突：409，不静默覆盖。
	env.backend.saveErr = &login.UIBackupError{Code: "CONFLICT"}
	conflict := env.post("/admin/backups/schedules/save", url.Values{
		"name": {"计划"}, "schedule_type": {"daily"}, "expression": {"02:30"},
		"time_zone": {"Asia/Shanghai"}, "missed_policy": {"skip"},
		"max_catch_up": {"1"}, "timeout_seconds": {"3600"}, "max_attempts": {"1"},
	})
	if conflict.Code != http.StatusConflict {
		t.Fatalf("冲突保存状态=%d，期望 409", conflict.Code)
	}
	env.backend.saveErr = nil
	// 取消请求已接受 vs 实际取消：措辞必须区分。
	env.backend.job.State = "cancel_requested"
	detail := env.get("/admin/backups/jobs/detail?job_id=" + backupTestJobID)
	if detail.Code != http.StatusOK ||
		!strings.Contains(detail.Body.String(), "取消请求已接受（任务尚未实际取消）") {
		t.Fatalf("取消请求状态措辞缺失: %d", detail.Code)
	}
	env.backend.job.State = "cancelled"
	cancelled := env.get("/admin/backups/jobs/detail?job_id=" + backupTestJobID)
	if !strings.Contains(cancelled.Body.String(), "已实际取消") {
		t.Fatal("实际取消状态应显示“已实际取消”")
	}
	// 下载超限（> 默认页面上限）映射为冲突拒绝，不读入内存或截断。
	env.backend.downloadErr = &login.UIBackupError{Code: "CONFLICT"}
	tooLarge := env.post("/admin/backups/download", url.Values{
		"backup_id": {backupTestID}})
	if tooLarge.Code != http.StatusConflict {
		t.Fatalf("下载超限状态=%d，期望 409", tooLarge.Code)
	}
	env.backend.downloadErr = nil
	// 会话过期：401 错误页，不渲染备份数据。
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session: expiredSessions{},
		Logger:  slog.New(slog.NewTextHandler(os.Stderr, nil)),
		PageBackups: &login.UIPageBackupOptions{
			Backend: env.backend,
			ValidateCSRF: func(context.Context, *http.Request, string) error {
				return errors.New("csrf")
			},
		}})
	if err != nil {
		t.Fatalf("构造过期会话页面失败: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://example.test/admin/backups", nil)
	recorder := httptest.NewRecorder()
	ui.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized || strings.Contains(recorder.Body.String(), backupTestID) {
		t.Fatalf("会话过期状态=%d 或泄露备份数据", recorder.Code)
	}
}
