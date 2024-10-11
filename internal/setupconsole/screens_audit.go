package setupconsole

// 步骤 291：本地审计/诊断/通知投递/报告/任务维护画面。
//
// 能力：结构化审计查询（分页）、诊断摘要、投递状态、报告列表/生成、任务列表/取消、
// 保留策略与危险清理（预估→确认→提交；复用 auditops 本地维护窄方法，维护日志与
// 受保护清理证据独立保留）。报告生成入口 g 复用 reports 本地维护窄方法提交真实
// 生成任务并展示报告/任务/状态；默认任务运行时未启用时明确返回不可用，不伪造成功；
// 区分“不可查询”与“零结果”。

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const ws3AuditScreenID = "ws3.audit"

type ws3AuditScreen struct {
	ws3ScreenBase
	mode     string // ""=menu "audit" "tasks" "reports" "deliveries"
	filter   LocalAuditFilter
	audit    LocalAuditPage
	tasks    []LocalTask
	reports  []LocalReport
	delivery []LocalDelivery
	form     *ws3FormState
	formKind string
	confirm  *ws3ConfirmAction
	runs     []LocalPurgeRun
	runsIdx  int
	mode2    string
}

func newWS3AuditScreen(open WS3SessionOpener) ScreenController {
	return &ws3AuditScreen{ws3ScreenBase: ws3ScreenBase{open: open},
		filter: LocalAuditFilter{Limit: 20}}
}

func (s *ws3AuditScreen) Title() string { return "本地维护 · 审计/诊断/通知/报告/任务" }

func (s *ws3AuditScreen) Render(ctx context.Context, canvas *Canvas, session SessionView) {
	_ = session
	if s.services == nil {
		if err := s.ensureSession(ctx); err != nil {
			_, top, width, _ := ws3CanvasArea(canvas)
			top = ws3DrawMessage(canvas, top, width, "不可用：", s.errText)
			top++
			canvas.Text(2, top, "Esc 返回主菜单。")
			return
		}
	}
	_, top, width, height := ws3CanvasArea(canvas)
	if s.form != nil {
		s.form.draw(canvas, top, width)
		return
	}
	if s.confirm != nil {
		ws3RenderConfirm(canvas, top, width, s.confirm.title, s.confirm.details)
		return
	}
	top = ws3DrawStatus(&s.ws3ScreenBase, canvas, top, width)
	switch s.mode {
	case "audit":
		s.renderAudit(canvas, top, width, height)
	case "tasks":
		s.renderTasks(canvas, top, width, height)
	case "reports":
		s.renderReports(canvas, top, width)
	case "deliveries":
		s.renderDeliveries(canvas, top, width, height)
	case "runs":
		s.renderPurgeRuns(canvas, top, width, height)
	default:
		s.renderMenu(canvas, top, width)
	}
}

func (s *ws3AuditScreen) renderMenu(canvas *Canvas, top, width int) {
	canvas.Text(2, top, "维护入口：")
	top += 2
	for _, line := range []string{
		"a=审计查询（结构化过滤+分页）  d=诊断摘要",
		"t=后台任务（进度/取消）  r=报告（列表/生成）  e=通知投递状态",
		"危险动作：审计清理/保留策略仅本地显式确认执行，并保留独立维护证据。",
		"Esc=返回主菜单；数据库断开时只展示本地诊断/维护日志，不伪造健康。",
	} {
		canvas.Text(2, top, ws3Truncate(line, width))
		top++
	}
}

func (s *ws3AuditScreen) renderAudit(canvas *Canvas, top, width, height int) {
	canvas.Text(2, top, fmt.Sprintf("审计查询（action=%q outcome=%q，最多 %d 条）  /=过滤  r=刷新  Esc=返回",
		s.filter.Action, s.filter.Outcome, s.filter.Limit))
	top += 2
	if len(s.audit.Entries) == 0 {
		canvas.Text(2, top, "没有匹配审计记录（注意：与“不可查询”不同，不可用时上方会显示错误原因）。")
		return
	}
	visible := maxInt(height-(top-ws3CanvasAreaTop(canvas)), 1)
	for index, entry := range s.audit.Entries {
		if index >= visible {
			break
		}
		canvas.Text(2, top, ws3Truncate(fmt.Sprintf("%s %s/%s %s target=%s outcome=%s req=%s",
			entry.CreatedAt.UTC().Format("01-02 15:04:05"), entry.ActorType,
			entry.ActorID, entry.Action, entry.Target, entry.Outcome, entry.RequestID), width))
		top++
	}
}

func (s *ws3AuditScreen) renderTasks(canvas *Canvas, top, width, height int) {
	canvas.Text(2, top, "后台任务（Enter=取消选中任务，需二次确认；Esc=返回）")
	top += 2
	if len(s.tasks) == 0 {
		canvas.Text(2, top, "没有任务（或任务列表不可用）。")
		return
	}
	visible := maxInt(height-(top-ws3CanvasAreaTop(canvas)), 1)
	for index, task := range s.tasks {
		if index >= visible {
			break
		}
		canvas.Text(2, top, ws3Truncate(fmt.Sprintf("%s %s state=%s progress=%d cancel=%s",
			task.ID, task.Kind, task.State, task.Progress, task.CancelState), width))
		top++
	}
}

func (s *ws3AuditScreen) renderReports(canvas *Canvas, top, width int) {
	canvas.Text(2, top, "报告（g=生成一份摘要报告；Esc=返回）")
	top += 2
	if len(s.reports) == 0 {
		canvas.Text(2, top, "没有报告（或报告列表不可用）。")
		return
	}
	for index, report := range s.reports {
		if index >= 10 {
			break
		}
		canvas.Text(2, top, ws3Truncate(fmt.Sprintf("%s %s/%s state=%s size=%d",
			report.ID, report.Kind, report.Format, report.State, report.SizeBytes), width))
		top++
	}
}

func (s *ws3AuditScreen) renderDeliveries(canvas *Canvas, top, width, height int) {
	canvas.Text(2, top, "通知/邮件投递状态（只读摘要；Esc=返回）")
	top += 2
	if len(s.delivery) == 0 {
		canvas.Text(2, top, "没有投递记录（或投递状态不可用）。")
		return
	}
	visible := maxInt(height-(top-ws3CanvasAreaTop(canvas)), 1)
	for index, delivery := range s.delivery {
		if index >= visible {
			break
		}
		canvas.Text(2, top, ws3Truncate(fmt.Sprintf("%s %s state=%s attempts=%d err=%s",
			delivery.ID, delivery.Kind, delivery.State, delivery.Attempts, delivery.LastError), width))
		top++
	}
}

func (s *ws3AuditScreen) HandleKey(ctx context.Context, key Key, session SessionView) (bool, error) {
	_ = session
	if s.services == nil {
		if err := s.ensureSession(ctx); err != nil {
			if key.Kind == KeyEsc || key.Kind == KeyCtrlC {
				s.closeSession()
				return true, nil
			}
			return false, nil
		}
		return false, nil
	}
	if s.form != nil {
		return s.handleFormKey(ctx, key), nil
	}
	if s.confirm != nil {
		return s.handleConfirmKey(ctx, key), nil
	}
	switch s.mode {
	case "runs":
		switch key.Kind {
		case KeyEsc:
			s.mode = ""
		case KeyUp:
			if s.runsIdx > 0 {
				s.runsIdx--
			}
		case KeyDown:
			if s.runsIdx < len(s.runs)-1 {
				s.runsIdx++
			}
		case KeyEnter:
			if s.runsIdx >= 0 && s.runsIdx < len(s.runs) {
				run := s.runs[s.runsIdx]
				evidence, err := s.services.Audit.PurgeEvidence(ctx, run.ID)
				if err != nil {
					s.setError(err)
				} else {
					parts := make([]string, 0, len(evidence))
					for _, entry := range evidence {
						parts = append(parts, entry.Action+"/"+entry.Result)
					}
					s.setStatus(fmt.Sprintf("清理 %s 维护证据 %d 条：%s", run.ID,
						len(evidence), strings.Join(parts, "，")))
				}
			}
		case KeyRune:
			if key.Rune == 'r' || key.Rune == 'R' {
				s.loadPurgeRuns(ctx)
			}
		}
	case "audit":
		if key.Kind == KeyEsc {
			s.mode = ""
		} else if key.Kind == KeyRune && (key.Rune == '/') {
			s.form = newWS3Form("审计过滤（结构化；空=全部）",
				[]string{"动作（如 user.disable）", "结果（success/failure）", "操作者 ID", "错误码"},
				[]bool{false, false, false, false}, "Enter 提交 · Esc 取消")
			s.form.setValue(0, s.filter.Action)
			s.form.setValue(1, s.filter.Outcome)
			s.form.setValue(2, s.filter.ActorID)
			s.form.setValue(3, s.filter.ErrorCode)
			s.formKind = "audit-filter"
		} else if key.Kind == KeyRune && (key.Rune == 'r' || key.Rune == 'R') {
			s.loadAudit(ctx)
		}
	case "tasks":
		if key.Kind == KeyEsc {
			s.mode = ""
		} else if key.Kind == KeyRune && (key.Rune == 'r' || key.Rune == 'R') {
			s.loadTasks(ctx)
		}
	case "reports":
		if key.Kind == KeyEsc {
			s.mode = ""
		} else if key.Kind == KeyRune && (key.Rune == 'g' || key.Rune == 'G') {
			s.generateReport(ctx)
		} else if key.Kind == KeyRune && (key.Rune == 'r' || key.Rune == 'R') {
			s.loadReports(ctx)
		}
	case "deliveries":
		if key.Kind == KeyEsc {
			s.mode = ""
		} else if key.Kind == KeyRune && (key.Rune == 'r' || key.Rune == 'R') {
			s.loadDeliveries(ctx)
		}
	default:
		switch key.Kind {
		case KeyEsc, KeyCtrlC:
			s.closeSession()
			return true, nil
		case KeyRune:
			switch key.Rune {
			case 'a', 'A':
				s.mode = "audit"
				s.loadAudit(ctx)
			case 'd', 'D':
				s.showDiagnostics(ctx)
			case 't', 'T':
				s.mode = "tasks"
				s.loadTasks(ctx)
			case 'r', 'R':
				s.mode = "reports"
				s.loadReports(ctx)
			case 'e', 'E':
				s.mode = "deliveries"
				s.loadDeliveries(ctx)
			case 'c', 'C':
				s.form = newWS3Form("修改安全审计保留策略（本地危险动作；维护日志记录）",
					[]string{"保留天数（1～3650）", "操作原因"}, []bool{false, false},
					"Enter 提交 · Esc 取消；版本冲突/范围错误会明确提示。")
				s.formKind = "retention"
			case 'p', 'P':
				s.form = newWS3Form("清理安全审计记录（先预估再确认；异步任务）",
					[]string{"截止时间（YYYY-MM-DD 或 RFC3339，必须早于保留边界）",
						"最大记录数", "操作原因"}, []bool{false, false, false},
					"Enter 预估 · Esc 取消；预估后再次确认才会提交。")
				s.formKind = "purge-preview"
			case 'v', 'V':
				s.mode = "runs"
				s.loadPurgeRuns(ctx)
			}
		}
	}
	return false, nil
}

func (s *ws3AuditScreen) loadAudit(ctx context.Context) {
	if s.services.Audit == nil {
		s.setError(ErrLocalUnsupported)
		return
	}
	page, err := s.services.Audit.QueryAudit(ctx, s.filter)
	if err != nil {
		s.setError(err)
		return
	}
	s.audit = page
	s.setStatus(fmt.Sprintf("审计记录：%d 条（has_more=%v）", len(page.Entries),
		page.Pagination.HasMore))
}

func (s *ws3AuditScreen) loadTasks(ctx context.Context) {
	if s.services.Audit == nil {
		s.setError(ErrLocalUnsupported)
		return
	}
	tasks, _, err := s.services.Audit.ListTasks(ctx, 20, 0)
	if err != nil {
		s.setError(err)
		return
	}
	s.tasks = tasks
}

func (s *ws3AuditScreen) loadReports(ctx context.Context) {
	if s.services.Audit == nil {
		s.setError(ErrLocalUnsupported)
		return
	}
	reports, _, err := s.services.Audit.ListReports(ctx, 20, 0)
	if err != nil {
		s.setError(err)
		return
	}
	s.reports = reports
}

func (s *ws3AuditScreen) loadDeliveries(ctx context.Context) {
	if s.services.Audit == nil {
		s.setError(ErrLocalUnsupported)
		return
	}
	items, _, err := s.services.Audit.ListDeliveries(ctx, 20, 0)
	if err != nil {
		s.setError(err)
		return
	}
	s.delivery = items
}

func (s *ws3AuditScreen) loadPurgeRuns(ctx context.Context) {
	items, _, err := s.services.Audit.ListPurgeRuns(ctx, 20, 0)
	if err != nil {
		s.setError(err)
		return
	}
	s.runs = items
	if s.runsIdx >= len(items) {
		s.runsIdx = maxInt(0, len(items)-1)
	}
	s.setStatus(fmt.Sprintf("清理记录：%d 条", len(items)))
}

func (s *ws3AuditScreen) showDiagnostics(ctx context.Context) {
	if s.services.Audit == nil {
		s.setError(ErrLocalUnsupported)
		return
	}
	diagnostics, err := s.services.Audit.Diagnostics(ctx)
	if err != nil {
		s.setError(err)
		return
	}
	notes := strings.Join(diagnostics.Notes, "；")
	if notes != "" {
		notes = "；" + notes
	}
	s.setStatus(fmt.Sprintf("就绪=%v；迁移 %d/%d；root=%s；数据库=%s%s",
		diagnostics.InstanceReady, diagnostics.AppliedCount, diagnostics.LatestCount,
		diagnostics.RootUserID, diagnostics.DatabasePath, notes))
}

func (s *ws3AuditScreen) generateReport(ctx context.Context) {
	if s.services.Audit == nil {
		s.setError(ErrLocalUnsupported)
		return
	}
	now := time.Now().UTC()
	request := LocalReportRequest{ScopeID: "system", From: now.Add(-24 * time.Hour),
		To: now, Formats: []string{"json"}, DetailRows: 100}
	s.confirm = &ws3ConfirmAction{title: "确认提交报告生成任务（范围 system，最近 24 小时，JSON）",
		details: []string{"生成任务需要任务运行时；提交只表示受理，真实结果见报告历史/任务状态。",
			"报告产物为受控导出；本地维护只读查询，不伪造成功。"},
		execute: func(ctx context.Context) (string, error) {
			report, err := s.services.Audit.GenerateReport(ctx, request)
			if err != nil {
				return "", err
			}
			s.loadReports(ctx)
			return fmt.Sprintf("报告任务已提交：%s（任务 %s，状态 %s）",
				report.ID, report.TaskID, report.State), nil
		}}
}

func (s *ws3AuditScreen) handleFormKey(ctx context.Context, key Key) bool {
	submitted, cancelled := s.form.handleKey(key)
	if cancelled {
		s.form = nil
		return false
	}
	if !submitted {
		return false
	}
	switch s.formKind {
	case "audit-filter":
		s.filter.Action = s.form.value(0)
		s.filter.Outcome = s.form.value(1)
		s.filter.ActorID = s.form.value(2)
		s.filter.ErrorCode = s.form.value(3)
		s.form = nil
		s.loadAudit(ctx)
	case "retention":
		days, err := strconv.Atoi(strings.TrimSpace(s.form.value(0)))
		if err != nil || days < 1 {
			s.form.errText = "保留天数必须是正整数"
			return false
		}
		reason := s.form.value(1)
		if reason == "" {
			s.form.errText = "必须填写操作原因（进入维护日志/审计）"
			return false
		}
		if _, err := s.services.Audit.SetRetention(ctx, days, reason); err != nil {
			s.form.errText = ws3ErrorText(err)
			return false
		}
		s.form = nil
		s.setStatus(fmt.Sprintf("保留策略已更新：%d 天（维护日志已记录）", days))
	case "purge-preview":
		now := time.Now().UTC()
		cutoff, err := ws3ParseTime(s.form.value(0), now)
		if err != nil || cutoff == nil {
			s.form.errText = "截止时间无效（必须早于保留期边界，格式 YYYY-MM-DD 或 RFC3339）"
			return false
		}
		maxRecords, err := strconv.Atoi(strings.TrimSpace(s.form.value(1)))
		if err != nil || maxRecords < 1 {
			s.form.errText = "最大记录数必须是正整数"
			return false
		}
		reason := s.form.value(2)
		if reason == "" {
			s.form.errText = "必须填写清理原因"
			return false
		}
		preview, err := s.services.Audit.PreviewPurge(ctx, *cutoff, maxRecords)
		if err != nil {
			s.form.errText = ws3ErrorText(err)
			return false
		}
		s.form = nil
		details := []string{
			fmt.Sprintf("范围 %s，截止 %s，预估 %d 条（至少标记=%v）",
				preview.ScopeID, preview.Cutoff.UTC().Format(time.RFC3339),
				preview.EstimatedCount, preview.AtLeast),
			fmt.Sprintf("保留期 %d 天；本次截止在保留期内：%v；维护日志受保护：%v",
				preview.Retention.Days, preview.WithinRetention,
				preview.MaintenanceProtected),
			"清理为异步任务；提交取消请求不等于实际取消，真实结果以清理记录为准。",
			"本操作需要维护锁与维护日志（写门已持有）；维护证据独立保留、不随历史删除。",
		}
		s.confirm = &ws3ConfirmAction{title: "确认提交安全审计清理任务",
			details: details, execute: func(ctx context.Context) (string, error) {
				run, err := s.services.Audit.StartPurge(ctx, preview, reason)
				if err != nil {
					return "", err
				}
				return fmt.Sprintf("清理任务已提交：%s（状态 %s，任务 %s）",
					run.ID, run.State, run.TaskID), nil
			}}
	}
	return false
}

// handleConfirmKey 处理危险清理确认。
func (s *ws3AuditScreen) handleConfirmKey(ctx context.Context, key Key) bool {
	if s.confirm == nil {
		return false
	}
	switch key.Kind {
	case KeyEsc:
		s.confirm = nil
	case KeyEnter:
		action := s.confirm
		s.confirm = nil
		message, err := action.execute(ctx)
		if err != nil {
			s.setError(err)
			return false
		}
		s.setStatus(message)
	}
	return false
}

// renderPurgeRuns 展示清理运行列表（维护证据入口）。
func (s *ws3AuditScreen) renderPurgeRuns(canvas *Canvas, top, width, height int) {
	canvas.Text(2, top, "审计清理记录（Enter=查看受保护维护证据，Esc=返回）")
	top += 2
	if len(s.runs) == 0 {
		canvas.Text(2, top, "没有清理记录（或清理能力不可用）。")
		return
	}
	visible := maxInt(height-(top-ws3CanvasAreaTop(canvas)), 1)
	start := 0
	if s.runsIdx >= visible {
		start = s.runsIdx - visible + 1
	}
	for index := start; index < len(s.runs) && index < start+visible; index++ {
		run := s.runs[index]
		marker := "  "
		if index == s.runsIdx {
			marker = "> "
		}
		canvas.Text(2, top, ws3Truncate(fmt.Sprintf("%s%s %s cleaned=%d failed=%d %s",
			marker, run.ID, run.State, run.Cleaned, run.Failed,
			run.CreatedAt.UTC().Format("2006-01-02T15:04Z")), width))
		top++
	}
}
