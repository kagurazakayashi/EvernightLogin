package ui_test

// 步骤 71 客服/人工恢复页面契约测试：受控 UISupportBackend 渲染、表单、错误映射、
// 秘密禁区、自批限制、幂等提示；真实 support/manualrecovery 服务集成见
// ui_pages_support_integration_test.go。

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
)

const (
	supportTestCaseID    = "sup_11111111111111111111111111111111"
	supportTestRequestID = "mrr_11111111111111111111111111111111"
	supportTestStaffID   = "usr_00000000000000000000000000000001"
)

// fakeSupportBackend 是受控页面后端替身（仅测试页面契约，不代表真实授权）。
type fakeSupportBackend struct {
	failCode      string
	failOn        string
	cases         []login.UISupportCaseView
	detail        login.UISupportCaseDetail
	policy        login.UISupportRecoveryPolicy
	recovery      login.UISupportRecoveryView
	caps          login.UISupportCapabilities
	created       login.UISupportCaseView
	approval      login.UISupportApprovalView
	execution     login.UISupportExecutionView
	executeErr    error
	lastReason    string
	lastStatus    string
	lastReference string
	releaseErr    error
}

func (f *fakeSupportBackend) fail(method string) error {
	if f.failCode != "" && (f.failOn == "" || f.failOn == method) {
		return &login.UISupportError{Code: f.failCode}
	}
	return nil
}

func (f *fakeSupportBackend) Capabilities(context.Context, string) (login.UISupportCapabilities, error) {
	if err := f.fail("capabilities"); err != nil {
		return login.UISupportCapabilities{}, err
	}
	return f.caps, nil
}

func (f *fakeSupportBackend) ListCases(_ context.Context, _ string,
	query login.UISupportCaseQuery) (login.UISupportCasePage, error) {
	if err := f.fail("list"); err != nil {
		return login.UISupportCasePage{}, err
	}
	return login.UISupportCasePage{Cases: f.cases, NextOffset: 20}, nil
}

func (f *fakeSupportBackend) GetCase(context.Context, string,
	string) (login.UISupportCaseDetail, error) {
	if err := f.fail("detail"); err != nil {
		return login.UISupportCaseDetail{}, err
	}
	return f.detail, nil
}

func (f *fakeSupportBackend) LookupTarget(context.Context, string, string,
	string) (login.UISupportTargetView, error) {
	if err := f.fail("lookup"); err != nil {
		return login.UISupportTargetView{}, err
	}
	return login.UISupportTargetView{UserID: supportTestStaffID, MaskedUsername: "al***",
		MaskedEmail: "a***@example.test", Status: "active", HasPassword: true,
		HasVerifiedEmail: true, CanRequestReset: true}, nil
}

func (f *fakeSupportBackend) CreateCase(_ context.Context, _, _, reason,
	_ string) (login.UISupportCaseView, error) {
	if err := f.fail("create"); err != nil {
		return login.UISupportCaseView{}, err
	}
	f.lastReason = reason
	return f.created, nil
}

func (f *fakeSupportBackend) ReassignCase(context.Context, string, string, string,
	string) (login.UISupportCaseView, error) {
	if err := f.fail("reassign"); err != nil {
		return login.UISupportCaseView{}, err
	}
	return f.created, nil
}

func (f *fakeSupportBackend) TransitionCase(_ context.Context, _, _, toStatus, _,
	_ string) (login.UISupportCaseView, error) {
	if err := f.fail("transition"); err != nil {
		return login.UISupportCaseView{}, err
	}
	f.lastStatus = toStatus
	return f.created, nil
}

func (f *fakeSupportBackend) SendReset(context.Context, string, string,
	string) (login.UISupportSendResult, error) {
	if err := f.fail("send"); err != nil {
		return login.UISupportSendResult{}, err
	}
	return login.UISupportSendResult{Sent: true, Status: "sent"}, nil
}

func (f *fakeSupportBackend) RecoveryPolicy(context.Context,
	string) (login.UISupportRecoveryPolicy, error) {
	if err := f.fail("policy"); err != nil {
		return login.UISupportRecoveryPolicy{}, err
	}
	return f.policy, nil
}

func (f *fakeSupportBackend) CreateRecoveryRequest(_ context.Context, _ string,
	create login.UISupportRecoveryCreate, _ string) (login.UISupportRecoveryView, error) {
	if err := f.fail("recovery_create"); err != nil {
		return login.UISupportRecoveryView{}, err
	}
	f.lastReference = create.VerificationReference
	return f.recovery, nil
}

func (f *fakeSupportBackend) GetRecoveryRequest(context.Context, string,
	string) (login.UISupportRecoveryView, error) {
	if err := f.fail("recovery"); err != nil {
		return login.UISupportRecoveryView{}, err
	}
	return f.recovery, nil
}

func (f *fakeSupportBackend) ApproveRecovery(context.Context, string, string, string,
	string) (login.UISupportApprovalView, error) {
	if err := f.fail("approve"); err != nil {
		return login.UISupportApprovalView{}, err
	}
	return f.approval, nil
}

func (f *fakeSupportBackend) RejectRecovery(context.Context, string, string, string, string) error {
	return f.fail("reject")
}

func (f *fakeSupportBackend) CancelRecovery(context.Context, string, string, string, string) error {
	return f.fail("cancel")
}

func (f *fakeSupportBackend) ExecuteRecovery(context.Context, string, string,
	string) (login.UISupportExecutionView, error) {
	if f.executeErr != nil {
		return login.UISupportExecutionView{}, f.executeErr
	}
	return f.execution, nil
}

// newSupportFakeBackend 构造默认测试数据（合成数据，无真实秘密）。
func newSupportFakeBackend() *fakeSupportBackend {
	now := time.Date(2026, 7, 10, 8, 0, 0, 0, time.UTC)
	caseView := login.UISupportCaseView{
		ID: supportTestCaseID, TargetUserID: "usr_00000000000000000000000000000011",
		TargetMaskedUsername: "al***", TargetMaskedEmail: "a***@example.test",
		Reason: "用户来电求助：忘记密码", Status: "pending_verification",
		AssigneeUserID: supportTestStaffID, CreatedByUserID: supportTestStaffID,
		CreatedAt: now, UpdatedAt: now, RowVersion: 1,
	}
	return &fakeSupportBackend{
		caps: login.UISupportCapabilities{ReadCases: true, CreateCase: true, UpdateCase: true,
			SendReset: true, RequestRecovery: true, ApprovePassword: true,
			ApproveMFA: true, ExecuteRecovery: true},
		cases: []login.UISupportCaseView{caseView},
		detail: login.UISupportCaseDetail{Case: caseView,
			Target: login.UISupportTargetView{UserID: caseView.TargetUserID,
				MaskedUsername: "al***", MaskedEmail: "a***@example.test",
				Status: "active", HasPassword: true, HasVerifiedEmail: true,
				CanRequestReset: true},
			History: login.UISupportHistoryPage{Events: []login.UISupportEventView{{
				Seq: 1, Action: "support.case.created", ActorType: "user",
				ActorID: supportTestStaffID, ToStatus: "pending_verification",
				Detail: "登记求助单", CreatedAt: now}}},
			Capabilities: login.UISupportCapabilities{ReadCases: true, CreateCase: true,
				UpdateCase: true, SendReset: true, RequestRecovery: true}},
		policy: login.UISupportRecoveryPolicy{Enabled: true, WaitPeriodSeconds: 3600,
			ApprovalTTLSeconds: 43200, RequestTTLSeconds: 86400,
			VerificationBases: []string{"in_person_identity_document"},
			DeliveryChannels:  []string{"verified_email"}, RequireIndependentApproval: true},
		recovery: login.UISupportRecoveryView{
			ID: supportTestRequestID, TargetUserID: "usr_00000000000000000000000000000011",
			InitiatorUserID: supportTestStaffID, Operation: "password_reset",
			Status: "pending_approval", VerificationBasis: "in_person_identity_document",
			VerificationReference: "verify-0001", EvidenceRegistered: true,
			Reason: "既有邮箱不可用", Delivery: "verified_email", DeliveryBound: "unknown",
			ContentConsistent: true, TargetSecurityVersion: 3, RowVersion: 1,
			ExpiresAt: now.Add(24 * time.Hour), CreatedAt: now, UpdatedAt: now,
			HistoryUnavailable: true,
		},
		created: caseView,
		approval: login.UISupportApprovalView{ID: "mra_11111111111111111111111111111111",
			ApproverUserID: "usr_00000000000000000000000000000002",
			Status:         "active", ApprovedAt: now, NotBefore: now.Add(time.Hour),
			ExpiresAt: now.Add(13 * time.Hour)},
		execution: login.UISupportExecutionView{ID: "mre_11111111111111111111111111111111",
			ExecutorUserID: "usr_00000000000000000000000000000003", Status: "succeeded",
			SessionsRevoked: 3, FactorsReset: true, Notification: "failed",
			StartedAt: now, FinishedAt: now},
	}
}

// newSupportTestUI 构造带客服页面的 WebUI。
func newSupportTestUI(t *testing.T, backend login.UISupportBackend,
	userID string) *login.WebUI {
	t.Helper()
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session:     appsTestSessions{userID: userID, management: true},
		PageSupport: &login.UIPageSupportOptions{Backend: backend}})
	if err != nil {
		t.Fatalf("页面框架: %v", err)
	}
	return ui
}

// serveSupportPage 执行页面请求并返回响应记录。
func serveSupportPage(ui http.Handler, method, target string, form url.Values) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "http://example.test"+target, bytes.NewReader(nil))
	if method == http.MethodPost {
		request = httptest.NewRequest(method, "http://example.test"+target,
			bytes.NewReader([]byte(form.Encode())))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	recorder := httptest.NewRecorder()
	ui.ServeHTTP(recorder, request)
	return recorder
}

// supportBody 返回响应正文。
func supportBody(recorder *httptest.ResponseRecorder) string {
	return recorder.Body.String()
}

// TestUIPageSupportRoutesContract 验证路由集合、依赖校验与全部模板可解析（渲染即解析）。
func TestUIPageSupportRoutesContract(t *testing.T) {
	ui := newSupportTestUI(t, newSupportFakeBackend(), supportTestStaffID)
	routes := map[string]bool{}
	for _, route := range ui.Routes() {
		routes[route.Name] = true
	}
	for _, name := range []string{"support.cases", "support.case_create",
		"support.case_create.submit", "support.case_detail",
		"support.case_reassign.submit", "support.case_transition.submit",
		"support.case_send.submit", "support.recovery_create.submit",
		"support.recovery_request", "support.recovery_cancel.submit",
		"support.recovery_inbox", "support.recovery_approval",
		"support.recovery_approve.submit", "support.recovery_reject.submit",
		"support.recovery_execute", "support.recovery_execute.submit"} {
		if !routes[name] {
			t.Fatalf("缺少步骤 71 路由 %s", name)
		}
	}
	if _, err := login.NewWebUI(login.WebUIOptions{
		PageSupport: &login.UIPageSupportOptions{}}); err == nil {
		t.Fatal("空客服后端应拒绝构造")
	}
}

// TestUIPageSupportCasesFlow 验证列表、空态、登记两步、详情历史与错误映射。
func TestUIPageSupportCasesFlow(t *testing.T) {
	backend := newSupportFakeBackend()
	ui := newSupportTestUI(t, backend, supportTestStaffID)
	list := serveSupportPage(ui, http.MethodGet, "/support/cases", nil)
	if list.Code != 200 || !strings.Contains(supportBody(list), "al***") ||
		!strings.Contains(supportBody(list), "电话仅是联系资料") {
		t.Fatalf("列表渲染 = %d", list.Code)
	}
	// 筛选无结果。
	backend.cases = nil
	empty := serveSupportPage(ui, http.MethodGet, "/support/cases?status=sent", nil)
	if empty.Code != 200 || !strings.Contains(supportBody(empty), "没有符合当前筛选条件的求助单") {
		t.Fatalf("筛选空态 = %d", empty.Code)
	}
	backend.cases = newSupportFakeBackend().cases
	// 登记：先读取目标摘要，再确认创建。
	lookup := serveSupportPage(ui, http.MethodPost, "/support/cases/create",
		url.Values{"csrf_token": {"token"}, "action": {"lookup"},
			"target_user_id": {backend.detail.Case.TargetUserID}})
	if lookup.Code != 200 || !strings.Contains(supportBody(lookup), "目标账户核对") {
		t.Fatalf("目标摘要读取 = %d", lookup.Code)
	}
	createDenied := serveSupportPage(ui, http.MethodPost, "/support/cases/create",
		url.Values{"csrf_token": {"token"}, "action": {"create"},
			"target_user_id": {backend.detail.Case.TargetUserID}, "reason": {"忘记密码"}})
	if createDenied.Code != http.StatusBadRequest ||
		!strings.Contains(supportBody(createDenied), "请先确认目标") ||
		strings.Contains(supportBody(createDenied), "page.support.case_create.confirm_required") {
		t.Fatalf("缺少确认的登记/中文提示缺失 = %d", createDenied.Code)
	}
	created := serveSupportPage(ui, http.MethodPost, "/support/cases/create",
		url.Values{"csrf_token": {"token"}, "action": {"create"},
			"target_user_id": {backend.detail.Case.TargetUserID}, "reason": {"忘记密码"},
			"confirm": {"yes"}})
	if created.Code != 200 || backend.lastReason != "忘记密码" ||
		!strings.Contains(supportBody(created), "尚未发送邮件或恢复账户") {
		t.Fatalf("登记成功 = %d", created.Code)
	}
	// 详情：历史可追溯操作者，无编辑/删除入口。
	detail := serveSupportPage(ui, http.MethodGet,
		"/support/cases/detail?case_id="+supportTestCaseID, nil)
	body := supportBody(detail)
	if detail.Code != 200 || !strings.Contains(body, "support.case.created") ||
		!strings.Contains(body, supportTestStaffID) ||
		strings.Contains(body, "删除记录") || strings.Contains(body, "编辑历史") {
		t.Fatalf("详情/历史渲染 = %d", detail.Code)
	}
	// 错误映射：无权限 → 统一安全文案。
	backend.failOn = "detail"
	backend.failCode = "ACCESS_DENIED"
	denied := serveSupportPage(ui, http.MethodGet,
		"/support/cases/detail?case_id="+supportTestCaseID, nil)
	if denied.Code != http.StatusForbidden ||
		!strings.Contains(supportBody(denied), "你没有查看或处理该对象的权限") {
		t.Fatalf("无权限映射 = %d", denied.Code)
	}
}

// TestUIPageSupportCaseActions 验证发送/状态/转派的确认与服务端错误映射。
func TestUIPageSupportCaseActions(t *testing.T) {
	backend := newSupportFakeBackend()
	ui := newSupportTestUI(t, backend, supportTestStaffID)
	sendDenied := serveSupportPage(ui, http.MethodPost, "/support/cases/send",
		url.Values{"csrf_token": {"token"}, "case_id": {supportTestCaseID}})
	if sendDenied.Code != http.StatusBadRequest {
		t.Fatalf("缺少确认的发送 = %d", sendDenied.Code)
	}
	send := serveSupportPage(ui, http.MethodPost, "/support/cases/send",
		url.Values{"csrf_token": {"token"}, "case_id": {supportTestCaseID},
			"confirm": {"yes"}})
	if send.Code != 200 || !strings.Contains(supportBody(send), "密码尚未因此改变") {
		t.Fatalf("发送成功提示 = %d", send.Code)
	}
	// 邮件失败不标成功。
	backend.failOn = "send"
	backend.failCode = "MAIL_DELIVERY_FAILED"
	failed := serveSupportPage(ui, http.MethodPost, "/support/cases/send",
		url.Values{"csrf_token": {"token"}, "case_id": {supportTestCaseID},
			"confirm": {"yes"}})
	if failed.Code != http.StatusBadGateway ||
		!strings.Contains(supportBody(failed), "未能确认投递") {
		t.Fatalf("邮件失败映射 = %d", failed.Code)
	}
	// 状态变更：拒绝手工写 sent。
	backend.failOn = ""
	backend.failCode = ""
	invalidStatus := serveSupportPage(ui, http.MethodPost, "/support/cases/transition",
		url.Values{"csrf_token": {"token"}, "case_id": {supportTestCaseID},
			"to_status": {"sent"}, "confirm": {"yes"}})
	if invalidStatus.Code != http.StatusBadRequest {
		t.Fatalf("手工 sent 状态应拒绝 = %d", invalidStatus.Code)
	}
	transitioned := serveSupportPage(ui, http.MethodPost, "/support/cases/transition",
		url.Values{"csrf_token": {"token"}, "case_id": {supportTestCaseID},
			"to_status": {"manual_review"}, "note": {"转人工核验"},
			"confirm": {"yes"}})
	if transitioned.Code != 200 || backend.lastStatus != "manual_review" ||
		!strings.Contains(supportBody(transitioned), "状态已更新") {
		t.Fatalf("状态变更成功 = %d", transitioned.Code)
	}
	// 转派：成功后显示真实负责人后果说明。
	reassigned := serveSupportPage(ui, http.MethodPost, "/support/cases/reassign",
		url.Values{"csrf_token": {"token"}, "case_id": {supportTestCaseID},
			"new_assignee_user_id": {"usr_00000000000000000000000000000009"},
			"confirm":              {"yes"}})
	if reassigned.Code != 200 ||
		!strings.Contains(supportBody(reassigned), "已转派给新的负责人") {
		t.Fatalf("转派成功 = %d", reassigned.Code)
	}
}

// TestUIPageSupportRecoveryDisabledAndDetail 验证人工恢复未启用、详情秘密禁区与内容变化提示。
func TestUIPageSupportRecoveryDisabledAndDetail(t *testing.T) {
	backend := newSupportFakeBackend()
	backend.policy.Enabled = false
	ui := newSupportTestUI(t, backend, supportTestStaffID)
	detail := serveSupportPage(ui, http.MethodGet,
		"/support/cases/detail?case_id="+supportTestCaseID, nil)
	body := supportBody(detail)
	if detail.Code != 200 ||
		!strings.Contains(body, "人工恢复流程尚未由 root/宿主启用") ||
		strings.Contains(body, `action="/support/recovery/request"`) {
		t.Fatalf("未启用时不应渲染可提交的恢复表单 = %d", detail.Code)
	}
	// 启用后详情包含核验/等待期/真实制度值。
	backend = newSupportFakeBackend()
	ui = newSupportTestUI(t, backend, supportTestStaffID)
	detail = serveSupportPage(ui, http.MethodGet,
		"/support/cases/detail?case_id="+supportTestCaseID, nil)
	body = supportBody(detail)
	if !strings.Contains(body, "1 小时") || !strings.Contains(body, "12 小时") ||
		!strings.Contains(body, "1 天") ||
		!strings.Contains(body, "证据摘要只提交一次") {
		t.Fatalf("恢复制度/证据提示缺失 = %d", detail.Code)
	}
	// N5：制度读取失败时显示“读取失败可重试”，不能误报“未启用”。
	backend.failOn = "policy"
	backend.failCode = "AUTHZ_UNAVAILABLE"
	policyFailedApproval := serveSupportPage(ui, http.MethodGet,
		"/support/recovery/approval?request_id="+supportTestRequestID, nil)
	failedBody := supportBody(policyFailedApproval)
	if !strings.Contains(failedBody, "制度摘要当前读取失败") ||
		strings.Contains(failedBody, "尚未由 root/宿主启用") {
		t.Fatalf("制度读取失败未区分未启用 = %d", policyFailedApproval.Code)
	}
	policyFailedCase := serveSupportPage(ui, http.MethodGet,
		"/support/cases/detail?case_id="+supportTestCaseID, nil)
	caseFailedBody := supportBody(policyFailedCase)
	if !strings.Contains(caseFailedBody, "制度摘要当前读取失败") ||
		strings.Contains(caseFailedBody, `action="/support/recovery/request"`) {
		t.Fatalf("工单详情制度读取失败未区分未启用 = %d", policyFailedCase.Code)
	}
	backend.failOn = ""
	backend.failCode = ""
	// 恢复详情：证据原文不回显、不出现完整邮箱或秘密。
	recovery := serveSupportPage(ui, http.MethodGet,
		"/support/recovery/request?request_id="+supportTestRequestID, nil)
	recoveryBody := supportBody(recovery)
	if recovery.Code != 200 ||
		!strings.Contains(recoveryBody, "原文不可回读") ||
		!strings.Contains(recoveryBody, "等待独立审批") {
		t.Fatalf("恢复详情 = %d", recovery.Code)
	}
	for _, forbidden := range []string{"alice@example.test", "verify-0001-raw-evidence",
		"重置链接", "验证码：", "以该用户登录"} {
		if strings.Contains(recoveryBody, forbidden) {
			t.Fatalf("恢复详情泄露/包含禁区内容 %q", forbidden)
		}
	}
	// 内容变化：显示旧批准失效提示。
	backend.recovery.ContentConsistent = false
	changed := serveSupportPage(ui, http.MethodGet,
		"/support/recovery/request?request_id="+supportTestRequestID, nil)
	if !strings.Contains(supportBody(changed), "原批准不再有效") {
		t.Fatalf("内容变化提示缺失 = %d", changed.Code)
	}
}

// TestUIPageSupportRecoveryCreateAndCancel 验证创建确认、证据只提交一次与取消限制。
func TestUIPageSupportRecoveryCreateAndCancel(t *testing.T) {
	backend := newSupportFakeBackend()
	ui := newSupportTestUI(t, backend, supportTestStaffID)
	form := url.Values{"csrf_token": {"token"},
		"target_user_id":         {backend.detail.Case.TargetUserID},
		"operation":              {"password_reset"},
		"verification_basis":     {"in_person_identity_document"},
		"verification_reference": {"verify-0001"},
		"evidence_summary":       {"线下核验证件原件"},
		"reason":                 {"既有邮箱不可用"},
		"delivery":               {"verified_email"},
		"support_case_id":        {supportTestCaseID}}
	denied := serveSupportPage(ui, http.MethodPost, "/support/recovery/request", form)
	if denied.Code != http.StatusBadRequest {
		t.Fatalf("缺少确认的恢复申请 = %d", denied.Code)
	}
	form.Set("confirm", "yes")
	created := serveSupportPage(ui, http.MethodPost, "/support/recovery/request", form)
	if created.Code != 200 || backend.lastReference != "verify-0001" ||
		!strings.Contains(supportBody(created), "尚未批准、尚未执行") {
		t.Fatalf("恢复申请创建 = %d", created.Code)
	}
	// N1：服务端返回未启用时错误横幅显示中文，不显示原始 i18n 键。
	backend.failOn = "recovery_create"
	backend.failCode = "DISABLED"
	disabledBody := supportBody(serveSupportPage(ui, http.MethodPost, "/support/recovery/request",
		url.Values{"csrf_token": {"token"}, "target_user_id": {backend.detail.Case.TargetUserID},
			"operation": {"password_reset"}, "verification_basis": {"in_person_identity_document"},
			"verification_reference": {"verify-0001"}, "evidence_summary": {"线下核验证件"},
			"reason": {"原因"}, "delivery": {"verified_email"}, "confirm": {"yes"}}))
	if !strings.Contains(disabledBody, "尚未由 root/宿主启用") ||
		strings.Contains(disabledBody, "page.support.recovery_request.not_enabled") {
		t.Fatalf("未启用错误横幅未翻译 = %q", disabledBody[:120])
	}
	backend.failOn = ""
	backend.failCode = ""
	// 非发起者取消：页面不显示取消表单。
	backend.recovery.InitiatorUserID = "usr_00000000000000000000000000000002"
	notInitiator := serveSupportPage(ui, http.MethodGet,
		"/support/recovery/request?request_id="+supportTestRequestID, nil)
	if strings.Contains(supportBody(notInitiator), `action="/support/recovery/cancel"`) {
		t.Fatalf("非发起者不应看到取消表单 = %d", notInitiator.Code)
	}
}

// TestUIPageSupportApprovalSelfAndCandidate 验证自批限制、候选审批人看到真实执行内容。
func TestUIPageSupportApprovalSelfAndCandidate(t *testing.T) {
	backend := newSupportFakeBackend()
	// 发起者打开审批页：显示自批限制，无批准控件。
	selfUI := newSupportTestUI(t, backend, supportTestStaffID)
	self := serveSupportPage(selfUI, http.MethodGet,
		"/support/recovery/approval?request_id="+supportTestRequestID, nil)
	selfBody := supportBody(self)
	if self.Code != 200 ||
		!strings.Contains(selfBody, "不能审批本人发起或本人账户的恢复申请") ||
		strings.Contains(selfBody, `action="/support/recovery/approval"`) {
		t.Fatalf("自批限制渲染 = %d", self.Code)
	}
	// 候选独立审批人：批准表单之前先显示实际目标/操作/后果/等待期。
	candidateUI := newSupportTestUI(t, backend, "usr_00000000000000000000000000000002")
	candidate := serveSupportPage(candidateUI, http.MethodGet,
		"/support/recovery/approval?request_id="+supportTestRequestID, nil)
	candidateBody := supportBody(candidate)
	approveFormIndex := strings.Index(candidateBody, `action="/support/recovery/approval"`)
	operationIndex := strings.Index(candidateBody, "批准后将允许执行以下内容")
	if candidate.Code != 200 || approveFormIndex < 0 || operationIndex < 0 ||
		operationIndex > approveFormIndex ||
		!strings.Contains(candidateBody, "密码恢复：作废旧密码") ||
		!strings.Contains(candidateBody, "确认不是授权") {
		t.Fatalf("候选审批详情渲染 = %d", candidate.Code)
	}
	// 批准成功显示真实时间窗口。
	approved := serveSupportPage(candidateUI, http.MethodPost, "/support/recovery/approval",
		url.Values{"csrf_token": {"token"}, "request_id": {supportTestRequestID},
			"note": {"已复核"}, "confirm": {"yes"}})
	if approved.Code != 200 || !strings.Contains(supportBody(approved), "已批准，但尚未执行") {
		t.Fatalf("批准成功 = %d", approved.Code)
	}
}

// TestUIPageSupportExecuteIdempotent 验证执行确认、冲突后重读与幂等提示。
func TestUIPageSupportExecuteIdempotent(t *testing.T) {
	backend := newSupportFakeBackend()
	backend.recovery.Status = "approved"
	backend.recovery.HasApproval = true
	backend.recovery.Approval = backend.approval
	ui := newSupportTestUI(t, backend, "usr_00000000000000000000000000000003")
	confirmPage := serveSupportPage(ui, http.MethodGet,
		"/support/recovery/execute?request_id="+supportTestRequestID, nil)
	body := supportBody(confirmPage)
	if confirmPage.Code != 200 || !strings.Contains(body, "确认不是授权") ||
		!strings.Contains(body, "一次性") {
		t.Fatalf("执行确认页 = %d", confirmPage.Code)
	}
	// 并发冲突：重新读取确认为已完成 → 幂等提示，不显示第二次成功。
	backend.executeErr = &login.UISupportError{Code: "CONFLICT"}
	backend.recovery.Status = "completed"
	backend.recovery.HasExecution = true
	backend.recovery.Execution = backend.execution
	conflicted := serveSupportPage(ui, http.MethodPost, "/support/recovery/execute",
		url.Values{"csrf_token": {"token"}, "request_id": {supportTestRequestID},
			"confirm": {"yes"}})
	conflictBody := supportBody(conflicted)
	if conflicted.Code != 200 ||
		!strings.Contains(conflictBody, "该申请已执行，本次未再次执行") ||
		!strings.Contains(conflictBody, "完成通知发送失败") {
		t.Fatalf("幂等提示/通知分离 = %d", conflicted.Code)
	}
}

// TestUIPageSupportInboxUnavailable 验证审批工作台不伪造列表能力。
func TestUIPageSupportInboxUnavailable(t *testing.T) {
	backend := newSupportFakeBackend()
	ui := newSupportTestUI(t, backend, "usr_00000000000000000000000000000002")
	inbox := serveSupportPage(ui, http.MethodGet, "/support/recovery", nil)
	body := supportBody(inbox)
	if inbox.Code != 200 || !strings.Contains(body, "审批列表能力尚未提供") ||
		strings.Contains(body, "mrr_11111111111111111111111111111111") {
		t.Fatalf("审批工作台不可用状态 = %d", inbox.Code)
	}
}

// TestUIPageSupportExecuteGatingAndFailedHint 覆盖步骤 153：执行入口按真实制度/
// 批准/内容绑定/能力位显示，不可执行时展示真实原因；failed 终态给出重试指引。
func TestUIPageSupportExecuteGatingAndFailedHint(t *testing.T) {
	newApproved := func() *fakeSupportBackend {
		backend := newSupportFakeBackend()
		backend.recovery.Status = "approved"
		backend.recovery.HasApproval = true
		backend.recovery.Approval = backend.approval
		backend.recovery.ContentConsistent = true
		return backend
	}
	// 可执行：详情显示执行入口。
	backend := newApproved()
	ui := newSupportTestUI(t, backend, supportTestStaffID)
	page := serveSupportPage(ui, http.MethodGet,
		"/support/recovery/request?request_id="+supportTestRequestID, nil)
	if page.Code != 200 || !strings.Contains(supportBody(page), "/support/recovery/execute?request_id=") {
		t.Fatalf("可执行时详情应显示执行入口 = %d", page.Code)
	}
	// 无执行能力：显示拒绝原因，不显示入口。
	backend = newApproved()
	backend.caps.ExecuteRecovery = false
	ui = newSupportTestUI(t, backend, supportTestStaffID)
	page = serveSupportPage(ui, http.MethodGet,
		"/support/recovery/request?request_id="+supportTestRequestID, nil)
	body := supportBody(page)
	if strings.Contains(body, "/support/recovery/execute?request_id=") ||
		!strings.Contains(body, "你没有执行该人工恢复") {
		t.Fatalf("无执行能力时不应显示入口 = %d", page.Code)
	}
	// 制度关闭：显示未启用原因，不显示入口。
	backend = newApproved()
	backend.policy.Enabled = false
	ui = newSupportTestUI(t, backend, supportTestStaffID)
	page = serveSupportPage(ui, http.MethodGet,
		"/support/recovery/request?request_id="+supportTestRequestID, nil)
	body = supportBody(page)
	if strings.Contains(body, "/support/recovery/execute?request_id=") ||
		!strings.Contains(body, "人工恢复流程尚未由 root/宿主启用") {
		t.Fatalf("制度关闭时不应显示执行入口 = %d", page.Code)
	}
	// 内容变化：原批准失效，不显示入口。
	backend = newApproved()
	backend.recovery.ContentConsistent = false
	ui = newSupportTestUI(t, backend, supportTestStaffID)
	page = serveSupportPage(ui, http.MethodGet,
		"/support/recovery/request?request_id="+supportTestRequestID, nil)
	body = supportBody(page)
	if strings.Contains(body, "/support/recovery/execute?request_id=") ||
		!strings.Contains(body, "原批准不再有效") {
		t.Fatalf("内容变化时不应显示执行入口 = %d", page.Code)
	}
	// failed 终态：显示失败重试指引，不伪造重试按钮。
	backend = newSupportFakeBackend()
	backend.recovery.Status = "failed"
	ui = newSupportTestUI(t, backend, supportTestStaffID)
	page = serveSupportPage(ui, http.MethodGet,
		"/support/recovery/request?request_id="+supportTestRequestID, nil)
	body = supportBody(page)
	if !strings.Contains(body, "执行失败") || strings.Contains(body, "action=\"/support/recovery/execute\"") {
		t.Fatalf("失败终态提示不符 = %d", page.Code)
	}
	// failed 执行记录显示稳定错误码（不显示底层消息/秘密）。
	backend.recovery.HasExecution = true
	backend.recovery.Execution = backend.execution
	backend.recovery.Execution.Status = "failed"
	backend.recovery.Execution.ErrorCode = "MAIL_DELIVERY_FAILED"
	page = serveSupportPage(ui, http.MethodGet,
		"/support/recovery/request?request_id="+supportTestRequestID, nil)
	body = supportBody(page)
	if !strings.Contains(body, "MAIL_DELIVERY_FAILED") || !strings.Contains(body, "执行失败错误码") {
		t.Fatalf("失败错误码展示缺失 = %d", page.Code)
	}
}

// TestSupportRecoveryNotificationQueuedShown 验证步骤 197 N2：队列已受理时页面显示
// “已受理（待投递）”，不得宣称“完成通知已发送”。
func TestSupportRecoveryNotificationQueuedShown(t *testing.T) {
	backend := newSupportFakeBackend()
	backend.recovery.HasExecution = true
	backend.recovery.Execution = backend.execution
	backend.recovery.Execution.Notification = "queued"
	ui := newSupportTestUI(t, backend, supportTestStaffID)
	page := serveSupportPage(ui, http.MethodGet,
		"/support/recovery/request?request_id="+supportTestRequestID, nil)
	body := supportBody(page)
	if !strings.Contains(body, "已受理（待投递）") {
		t.Fatalf("queued 通知未显示待投递提示：%s", body)
	}
	if strings.Contains(body, "完成通知已发送") {
		t.Fatalf("queued 通知不得显示为已发送：%s", body)
	}
}
