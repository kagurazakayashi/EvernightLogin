// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

// 客服求助单公开 Go 接口（步骤 229）。
//
// 安全边界（复用 internal/support 真实服务，不复制审批链）：
//   - 客服操作者必须是真实实名用户会话（AdminCaller 的 AdminSession 形式）；本机
//     受信操作者没有用户身份，不能成为客服工作人员，调用一律 ACCESS_DENIED。
//   - 功能权限与数据范围由真实 authz 判定；root/实际高权限目标拒绝普通客服处理
//     （SUPPORT_TARGET_PROTECTED），不能凭求助单接管账户。
//   - 登记/转派/状态变更/向原验证邮箱发起找回都属于敏感操作：必须完成真实再次认证
//     （support.case.create/update、support.reset.send，密码，必要时强因素），
//     且再次认证绑定目标/操作/参数摘要；不提供“已审批即执行恢复”的旁路。
//   - 客服只能看到脱敏视图（掩码用户名/邮箱、无密码/MFA/恢复 token/验证码/新密码/
//     TOTP 种子）；向原验证邮箱发送一次性找回入口不等于立即改密，也不解除 MFA。
//   - 状态迁移使用行版本条件更新，并发单赢家；审计失败关键变更整体回滚。
//
// 与人工核验恢复的分工：客服求助单负责受控查询与“向原验证邮箱发起找回”；既有
// 验证渠道不可用时，按 internal/manualrecovery 的独立申请/审批/执行链处理，客服
// 不能自批或直接执行恢复。对应公开门面见 app/manualrecovery_public.go。

import (
	"context"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/support"
)

// SupportAdminService 是客服求助单公开门面。
type SupportAdminService interface {
	CreateCase(ctx context.Context, req SupportCreateCaseRequest) (SupportCase, error)
	GetCase(ctx context.Context, req SupportCaseRequest) (SupportCase, error)
	ListCases(ctx context.Context, req SupportListCasesRequest) (SupportCasePage, error)
	ListEvents(ctx context.Context, req SupportCaseRequest) (SupportEventPage, error)
	LookupTarget(ctx context.Context, req SupportLookupTargetRequest) (SupportTarget, error)
	ReassignCase(ctx context.Context, req SupportReassignCaseRequest) (SupportCase, error)
	TransitionCase(ctx context.Context, req SupportTransitionCaseRequest) (SupportCase, error)
	SendReset(ctx context.Context, req SupportSendResetRequest) (SupportSendResult, error)
}

// SupportCase 是脱敏的客服求助单视图。
type SupportCase struct {
	ID                   string
	ApplicationID        string
	TargetUserID         string
	TargetMaskedUsername string
	TargetMaskedEmail    string
	Reason               string
	Status               string
	AssigneeUserID       string
	CreatedByUserID      string
	CreatedAt            string
	UpdatedAt            string
	RowVersion           int64
}

// SupportCaseEvent 是求助单处理历史的脱敏事件。
type SupportCaseEvent struct {
	ID         string
	CaseID     string
	Seq        int64
	Action     string
	ActorType  string
	ActorID    string
	FromStatus string
	ToStatus   string
	Note       string
	CreatedAt  string
}

// SupportCasePage 是求助单分页结果。
type SupportCasePage struct {
	Cases []SupportCase
	Page  AdminPageInfo
}

// SupportEventPage 是处理历史分页结果。
type SupportEventPage struct {
	Events []SupportCaseEvent
	Page   AdminPageInfo
}

// SupportTarget 是受控查询的脱敏目标资料。
type SupportTarget struct {
	UserID           string
	MaskedUsername   string
	MaskedEmail      string
	Status           string
	HasPassword      bool
	HasVerifiedEmail bool
	CanRequestReset  bool
}

// SupportSendResult 是向原验证邮箱发起找回的结果（不含链接/验证码/token）。
type SupportSendResult struct {
	Sent         bool
	ManualReview bool
	Status       string
}

// SupportCreateCaseRequest 登记求助单（敏感操作）。
type SupportCreateCaseRequest struct {
	Caller       AdminCaller
	TargetUserID string
	Reason       string
	Password     string
	TOTPCode     string
	RequestID    string
}

// SupportCaseRequest 读取单张求助单/其处理历史。
type SupportCaseRequest struct {
	Caller    AdminCaller
	CaseID    string
	RequestID string
}

// SupportListCasesRequest 分页列出分配给当前客服的求助单。
type SupportListCasesRequest struct {
	Caller    AdminCaller
	Statuses  []string
	Page      AdminPage
	RequestID string
}

// SupportLookupTargetRequest 在客服数据范围内脱敏定位目标用户。
type SupportLookupTargetRequest struct {
	Caller       AdminCaller
	TargetUserID string
	RequestID    string
}

// SupportReassignCaseRequest 将求助单转派给另一名客服（敏感操作）。
type SupportReassignCaseRequest struct {
	Caller            AdminCaller
	CaseID            string
	NewAssigneeUserID string
	Password          string
	TOTPCode          string
	RequestID         string
}

// SupportTransitionCaseRequest 变更求助单状态（敏感操作）。
type SupportTransitionCaseRequest struct {
	Caller    AdminCaller
	CaseID    string
	ToStatus  string
	Note      string
	Password  string
	TOTPCode  string
	RequestID string
}

// SupportSendResetRequest 向求助单目标原验证邮箱发起找回（敏感操作）。
type SupportSendResetRequest struct {
	Caller    AdminCaller
	CaseID    string
	Password  string
	TOTPCode  string
	RequestID string
}

// Support 返回客服求助单公开门面。
func (r *Runtime) Support() SupportAdminService {
	return &supportFacade{r: r}
}

type supportFacade struct {
	r *Runtime
}

func (f *supportFacade) admin() *adminFacade { return &adminFacade{r: f.r} }

// beginSupport 完成可信身份解析并要求真实用户会话，返回领域调用者。
func (f *supportFacade) beginSupport(ctx context.Context, caller AdminCaller,
	requestID string) (adminRequest, *support.Service, support.Caller, error) {
	call, err := f.admin().begin(ctx, caller, requestID)
	if err != nil {
		return adminRequest{}, nil, support.Caller{}, err
	}
	security := f.r.securityDomains()
	if security == nil || security.Support == nil {
		return call, nil, support.Caller{}, call.configError("客服服务未装配")
	}
	if call.identity.local || call.identity.userID == "" {
		return call, nil, support.Caller{}, mapDomainError(
			"客服操作必须由真实客服用户会话调用", "ACCESS_DENIED", call.requestID)
	}
	domainCaller, err := support.UserCaller(call.identity.userID)
	if err != nil {
		return call, nil, support.Caller{}, call.configError("客服调用者无效")
	}
	if domainCaller, err = domainCaller.WithRequestID(call.requestID); err != nil {
		return call, nil, support.Caller{}, call.configError("请求编号无效")
	}
	return call, security.Support, domainCaller, nil
}

// approveSupport 建立与领域服务一致的敏感操作再次认证上下文。
func (f *supportFacade) approveSupport(ctx context.Context, call adminRequest,
	operationID, targetType, targetID string, params map[string]string,
	password, totpCode string) (context.Context, error) {
	return f.admin().sensitiveContext(ctx, call.identity, operationID, targetType,
		targetID, params, password, totpCode, call.requestID)
}

// mapSupportError 映射客服领域错误；受保护目标使用根包专用错误码。
func mapSupportError(message, code, requestID string) error {
	if code == string(support.CodeSupportTargetProtected) {
		return login.NewAppError(login.CodeSupportTargetProtected, message,
			requestIDOption(requestID))
	}
	return mapDomainError(message, code, requestID)
}

// CreateCase 登记求助单（敏感操作，绑定目标/理由/请求编号）。
func (f *supportFacade) CreateCase(ctx context.Context,
	req SupportCreateCaseRequest) (SupportCase, error) {
	call, service, caller, err := f.beginSupport(ctx, req.Caller, req.RequestID)
	if err != nil {
		return SupportCase{}, err
	}
	reason := strings.TrimSpace(req.Reason)
	approved, err := f.approveSupport(ctx, call, support.OperationCaseCreate, "user",
		req.TargetUserID, support.ParamsCaseCreate(req.TargetUserID, reason, call.requestID),
		req.Password, req.TOTPCode)
	if err != nil {
		return SupportCase{}, err
	}
	view, err := service.CreateCase(approved, caller, support.CreateCaseRequest{
		TargetUserID: req.TargetUserID, Reason: reason, RequestID: call.requestID})
	if err != nil {
		return SupportCase{}, mapSupportError("登记求助单失败",
			string(support.CodeOf(err)), call.requestID)
	}
	return supportCaseOf(view), nil
}

// GetCase 读取单张求助单（脱敏）。
func (f *supportFacade) GetCase(ctx context.Context,
	req SupportCaseRequest) (SupportCase, error) {
	call, service, caller, err := f.beginSupport(ctx, req.Caller, req.RequestID)
	if err != nil {
		return SupportCase{}, err
	}
	view, err := service.GetCase(ctx, caller, req.CaseID)
	if err != nil {
		return SupportCase{}, mapSupportError("读取求助单失败",
			string(support.CodeOf(err)), call.requestID)
	}
	return supportCaseOf(view), nil
}

// ListCases 分页列出分配给当前客服的求助单。
func (f *supportFacade) ListCases(ctx context.Context,
	req SupportListCasesRequest) (SupportCasePage, error) {
	call, service, caller, err := f.beginSupport(ctx, req.Caller, req.RequestID)
	if err != nil {
		return SupportCasePage{}, err
	}
	page, err := call.page(req.Page)
	if err != nil {
		return SupportCasePage{}, err
	}
	statuses := make([]support.CaseStatus, 0, len(req.Statuses))
	for _, status := range req.Statuses {
		statuses = append(statuses, support.CaseStatus(strings.TrimSpace(status)))
	}
	result, err := service.ListCases(ctx, caller, statuses, page.Offset, page.Limit)
	if err != nil {
		return SupportCasePage{}, mapSupportError("列出求助单失败",
			string(support.CodeOf(err)), call.requestID)
	}
	cases := make([]SupportCase, 0, len(result.Cases))
	for _, item := range result.Cases {
		cases = append(cases, supportCaseOf(item))
	}
	return SupportCasePage{Cases: cases,
		Page: NewAdminPageInfo(page, len(cases), result.HasMore)}, nil
}

// ListEvents 分页读取求助单处理历史。
func (f *supportFacade) ListEvents(ctx context.Context,
	req SupportCaseRequest) (SupportEventPage, error) {
	call, service, caller, err := f.beginSupport(ctx, req.Caller, req.RequestID)
	if err != nil {
		return SupportEventPage{}, err
	}
	result, err := service.ListEvents(ctx, caller, req.CaseID, 0, 100)
	if err != nil {
		return SupportEventPage{}, mapSupportError("读取求助单历史失败",
			string(support.CodeOf(err)), call.requestID)
	}
	events := make([]SupportCaseEvent, 0, len(result.Events))
	for _, item := range result.Events {
		events = append(events, SupportCaseEvent{ID: item.ID, CaseID: item.CaseID,
			Seq: item.Seq, Action: item.Action, ActorType: string(item.ActorType),
			ActorID: item.ActorID, FromStatus: string(item.FromStatus),
			ToStatus: string(item.ToStatus), Note: item.Detail,
			CreatedAt: item.CreatedAt.UTC().Format(time.RFC3339)})
	}
	return SupportEventPage{Events: events,
		Page: NewAdminPageInfo(AdminPage{Limit: 100}, len(events), result.HasMore)}, nil
}

// LookupTarget 在数据范围内脱敏定位目标用户。
func (f *supportFacade) LookupTarget(ctx context.Context,
	req SupportLookupTargetRequest) (SupportTarget, error) {
	call, service, caller, err := f.beginSupport(ctx, req.Caller, req.RequestID)
	if err != nil {
		return SupportTarget{}, err
	}
	target, err := service.LookupTarget(ctx, caller, req.TargetUserID, call.requestID)
	if err != nil {
		return SupportTarget{}, mapSupportError("查询目标用户失败",
			string(support.CodeOf(err)), call.requestID)
	}
	return SupportTarget{UserID: target.UserID, MaskedUsername: target.MaskedUsername,
		MaskedEmail: target.MaskedEmail, Status: target.Status,
		HasPassword: target.HasPassword, HasVerifiedEmail: target.HasVerifiedEmail,
		CanRequestReset: target.CanRequestReset}, nil
}

// currentSupportCase 读取当前求助单并返回领域视图（用于敏感参数摘要）。
func (f *supportFacade) currentSupportCase(ctx context.Context, service *support.Service,
	caller support.Caller, caseID string) (support.CaseView, error) {
	return service.GetCase(ctx, caller, caseID)
}

// ReassignCase 转派求助单（敏感操作，参数摘要使用真实目标）。
func (f *supportFacade) ReassignCase(ctx context.Context,
	req SupportReassignCaseRequest) (SupportCase, error) {
	call, service, caller, err := f.beginSupport(ctx, req.Caller, req.RequestID)
	if err != nil {
		return SupportCase{}, err
	}
	current, err := f.currentSupportCase(ctx, service, caller, req.CaseID)
	if err != nil {
		return SupportCase{}, mapSupportError("读取求助单失败",
			string(support.CodeOf(err)), call.requestID)
	}
	approved, err := f.approveSupport(ctx, call, support.OperationCaseUpdate,
		"support_case", req.CaseID,
		support.ParamsCaseReassign(req.CaseID, current.TargetUserID,
			req.NewAssigneeUserID, call.requestID), req.Password, req.TOTPCode)
	if err != nil {
		return SupportCase{}, err
	}
	view, err := service.ReassignCase(approved, caller, support.ReassignRequest{
		CaseID: req.CaseID, NewAssigneeUserID: req.NewAssigneeUserID,
		RequestID: call.requestID})
	if err != nil {
		return SupportCase{}, mapSupportError("转派求助单失败",
			string(support.CodeOf(err)), call.requestID)
	}
	return supportCaseOf(view), nil
}

// TransitionCase 变更求助单状态（敏感操作，参数摘要使用真实目标）。
func (f *supportFacade) TransitionCase(ctx context.Context,
	req SupportTransitionCaseRequest) (SupportCase, error) {
	call, service, caller, err := f.beginSupport(ctx, req.Caller, req.RequestID)
	if err != nil {
		return SupportCase{}, err
	}
	current, err := f.currentSupportCase(ctx, service, caller, req.CaseID)
	if err != nil {
		return SupportCase{}, mapSupportError("读取求助单失败",
			string(support.CodeOf(err)), call.requestID)
	}
	approved, err := f.approveSupport(ctx, call, support.OperationCaseUpdate,
		"support_case", req.CaseID,
		support.ParamsCaseTransition(req.CaseID, current.TargetUserID, req.ToStatus,
			call.requestID), req.Password, req.TOTPCode)
	if err != nil {
		return SupportCase{}, err
	}
	view, err := service.TransitionCase(approved, caller, support.TransitionRequest{
		CaseID: req.CaseID, ToStatus: support.CaseStatus(req.ToStatus),
		Note: req.Note, RequestID: call.requestID})
	if err != nil {
		return SupportCase{}, mapSupportError("变更求助单状态失败",
			string(support.CodeOf(err)), call.requestID)
	}
	return supportCaseOf(view), nil
}

// SendReset 向目标原验证邮箱发起找回（敏感操作，不含链接/验证码）。
func (f *supportFacade) SendReset(ctx context.Context,
	req SupportSendResetRequest) (SupportSendResult, error) {
	call, service, caller, err := f.beginSupport(ctx, req.Caller, req.RequestID)
	if err != nil {
		return SupportSendResult{}, err
	}
	current, err := f.currentSupportCase(ctx, service, caller, req.CaseID)
	if err != nil {
		return SupportSendResult{}, mapSupportError("读取求助单失败",
			string(support.CodeOf(err)), call.requestID)
	}
	approved, err := f.approveSupport(ctx, call, support.OperationResetSend,
		"support_case", req.CaseID,
		support.ParamsResetSend(req.CaseID, current.TargetUserID, call.requestID),
		req.Password, req.TOTPCode)
	if err != nil {
		return SupportSendResult{}, err
	}
	result, err := service.SendReset(approved, caller, support.SendRequest{
		CaseID: req.CaseID, RequestID: call.requestID})
	if err != nil {
		return SupportSendResult{}, mapSupportError("发起找回失败",
			string(support.CodeOf(err)), call.requestID)
	}
	return SupportSendResult{Sent: result.Sent, ManualReview: result.ManualReview,
		Status: string(result.Status)}, nil
}

// supportCaseOf 转换脱敏求助单视图。
func supportCaseOf(view support.CaseView) SupportCase {
	return SupportCase{ID: view.ID, ApplicationID: view.ApplicationID,
		TargetUserID:         view.TargetUserID,
		TargetMaskedUsername: view.TargetMaskedUsername,
		TargetMaskedEmail:    view.TargetMaskedEmail, Reason: view.Reason,
		Status: string(view.Status), AssigneeUserID: view.AssigneeUserID,
		CreatedByUserID: view.CreatedByUserID,
		CreatedAt:       view.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:       view.UpdatedAt.UTC().Format(time.RFC3339),
		RowVersion:      view.RowVersion}
}
