// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

// 人工核验恢复公开 Go 接口（步骤 229）。
//
// 安全边界（复用 internal/manualrecovery 真实申请/独立审批/执行链）：
//   - 默认关闭；仅当宿主显式配置启用且真实邮件交付/执行器可用时，服务才可用；
//     未启用时所有阶段 fail-closed 拒绝，不提供占位成功。
//   - 操作者必须是真实实名工作人员用户会话（AdminSession）；本机受信操作者没有
//     用户身份，不能发起/审批/执行人工恢复，调用一律 ACCESS_DENIED。
//   - 申请绑定目标稳定 ID、操作类型、核验依据、外部核验记录、证据摘要（只存摘要）、
//     原因、交付渠道、目标安全版本与内容摘要；发起者/目标本人不得自批，执行人不得
//     是发起者或审批人（三权分离）。
//   - 审批与执行都要求真实近期强认证（support.recovery.approve/execute），并绑定
//     申请内容摘要/操作类型/批准；等待期、批准有效期、内容变化、审批人资格撤销、
//     目标变为 root/高权限都会使批准失效（fail-closed）。
//   - 客服/宿主视图不含证据明文、证件材料、密码、MFA 秘密、恢复代码或恢复 token；
//     恢复成功后用户必须重新认证，不能凭批准直接签发正常用户会话。
//   - 审计失败时关键变更整体回滚；状态迁移与执行使用条件更新（并发单赢家）。
//
// 与客服求助单的分工：客服求助单（app/support_public.go）只做受控查询与向原验证
// 邮箱发起找回；既有渠道不可用时，才进入本文件的人工核验恢复独立审批/执行链。

import (
	"context"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/manualrecovery"
)

// ManualRecoveryAdminService 是人工核验恢复公开门面。
type ManualRecoveryAdminService interface {
	// Policy 返回当前人工恢复制度（启用状态、允许核验依据/交付渠道与时间边界）。
	Policy(ctx context.Context) (ManualRecoveryPolicy, error)
	Create(ctx context.Context, req ManualRecoveryCreateRequest) (ManualRecoveryRequest, error)
	GetRequest(ctx context.Context, req ManualRecoveryRequestRef) (ManualRecoveryRequest, error)
	List(ctx context.Context, req ManualRecoveryListRequest) (ManualRecoveryListPage, error)
	Approve(ctx context.Context, req ManualRecoveryDecisionRequest) (ManualRecoveryApproval, error)
	Reject(ctx context.Context, req ManualRecoveryDecisionRequest) error
	Cancel(ctx context.Context, req ManualRecoveryCancelRequest) error
	Execute(ctx context.Context, req ManualRecoveryExecuteRequest) (ManualRecoveryExecutionResult, error)
	GetApproval(ctx context.Context, req ManualRecoveryRequestRef) (ManualRecoveryApproval, bool, error)
	GetExecution(ctx context.Context, req ManualRecoveryRequestRef) (ManualRecoveryExecutionRecord, bool, error)
}

// ManualRecoveryPolicy 是人工恢复制度视图。
type ManualRecoveryPolicy struct {
	Enabled                    bool
	VerificationBases          []string
	DeliveryChannels           []string
	WaitPeriod                 time.Duration
	ApprovalTTL                time.Duration
	RequestTTL                 time.Duration
	RequireIndependentApproval bool
}

// ManualRecoveryRequest 是申请/详情视图（不含证据明文与内容摘要）。
type ManualRecoveryRequest struct {
	ID                    string
	TargetUserID          string
	InitiatorUserID       string
	Operation             string
	Status                string
	VerificationBasis     string
	VerificationReference string
	Reason                string
	Delivery              string
	SupportCaseID         string
	ExpiresAt             string
	ClosedReason          string
	RowVersion            int64
	CreatedAt             string
	UpdatedAt             string
}

// ManualRecoveryApproval 是批准视图（不含内容摘要明文）。
type ManualRecoveryApproval struct {
	ID                string
	RequestID         string
	ApproverUserID    string
	Operation         string
	Status            string
	ApprovedAt        string
	NotBefore         string
	ExpiresAt         string
	FinishedAt        string
	InvalidatedReason string
	RowVersion        int64
}

// ManualRecoveryExecutionRecord 是执行记录视图。
type ManualRecoveryExecutionRecord struct {
	ID                    string
	RequestID             string
	ApprovalID            string
	ExecutorUserID        string
	Operation             string
	Status                string
	SessionsRevoked       int
	FactorsReset          bool
	ResetCredentialIssued bool
	NotificationState     string
	ErrorCode             string
	StartedAt             string
	FinishedAt            string
}

// ManualRecoveryExecutionResult 是一次执行的公开结果（通知队列不等于已送达）。
type ManualRecoveryExecutionResult struct {
	RequestID         string
	ExecutionID       string
	Status            string
	Operation         string
	SessionsRevoked   int
	FactorsReset      bool
	CredentialIssued  bool
	NotificationSent  bool
	NotificationState string
}

// ManualRecoveryListItem 是待办/历史列表的最小必要字段。
type ManualRecoveryListItem struct {
	RequestID     string
	SupportCaseID string
	Operation     string
	Status        string
	TargetMasked  string
	CreatedAt     string
	ExpiresAt     string
	MyRelation    string
}

// ManualRecoveryListPage 是列表分页结果。
type ManualRecoveryListPage struct {
	Items []ManualRecoveryListItem
	Page  AdminPageInfo
}

// ManualRecoveryCreateRequest 发起人工核验恢复申请（敏感操作）。
type ManualRecoveryCreateRequest struct {
	Caller                AdminCaller
	TargetUserID          string
	Operation             string
	VerificationBasis     string
	VerificationReference string
	EvidenceSummary       string
	Reason                string
	Delivery              string
	SupportCaseID         string
	Password              string
	TOTPCode              string
	RequestID             string
}

// ManualRecoveryRequestRef 读取申请/批准/执行记录。
type ManualRecoveryRequestRef struct {
	Caller AdminCaller
	// TargetRequestID 是人工恢复申请 ID（mrr_ 前缀）。
	TargetRequestID string
	TraceID         string
}

// ManualRecoveryListRequest 分页读取本人相关的待办/历史。
type ManualRecoveryListRequest struct {
	Caller    AdminCaller
	Mode      string
	Operation string
	Page      AdminPage
	RequestID string
}

// ManualRecoveryDecisionRequest 独立审批/拒绝申请（敏感操作）。
type ManualRecoveryDecisionRequest struct {
	Caller          AdminCaller
	TargetRequestID string
	Note            string
	Reason          string
	Password        string
	TOTPCode        string
	TraceID         string
}

// ManualRecoveryCancelRequest 发起者取消申请（非敏感，仅发起者本人）。
type ManualRecoveryCancelRequest struct {
	Caller          AdminCaller
	TargetRequestID string
	Reason          string
	TraceID         string
}

// ManualRecoveryExecuteRequest 执行已批准且等待期已满的恢复（敏感操作）。
type ManualRecoveryExecuteRequest struct {
	Caller          AdminCaller
	TargetRequestID string
	Password        string
	TOTPCode        string
	TraceID         string
}

// ManualRecovery 返回人工核验恢复公开门面。
func (r *Runtime) ManualRecovery() ManualRecoveryAdminService {
	return &manualRecoveryFacade{r: r}
}

type manualRecoveryFacade struct {
	r *Runtime
}

func (f *manualRecoveryFacade) admin() *adminFacade { return &adminFacade{r: f.r} }

// beginRecovery 完成可信身份解析并要求真实用户会话。
func (f *manualRecoveryFacade) beginRecovery(ctx context.Context, caller AdminCaller,
	requestID string) (adminRequest, *manualrecovery.Service, manualrecovery.Caller, error) {
	call, err := f.admin().begin(ctx, caller, requestID)
	if err != nil {
		return adminRequest{}, nil, manualrecovery.Caller{}, err
	}
	security := f.r.securityDomains()
	if security == nil || security.ManualRecovery == nil {
		return call, nil, manualrecovery.Caller{}, call.configError("人工恢复服务未装配")
	}
	if call.identity.local || call.identity.userID == "" {
		return call, nil, manualrecovery.Caller{}, mapDomainError(
			"人工恢复必须由真实工作人员用户会话调用", "ACCESS_DENIED", call.requestID)
	}
	domainCaller, err := manualrecovery.UserCaller(call.identity.userID)
	if err != nil {
		return call, nil, manualrecovery.Caller{}, call.configError("人工恢复调用者无效")
	}
	return call, security.ManualRecovery, domainCaller, nil
}

// approveRecovery 建立与领域服务一致的敏感操作再次认证上下文。
func (f *manualRecoveryFacade) approveRecovery(ctx context.Context, call adminRequest,
	operationID, targetID string, params map[string]string,
	password, totpCode string) (context.Context, error) {
	return f.admin().sensitiveContext(ctx, call.identity, operationID, "user",
		targetID, params, password, totpCode, call.requestID)
}

// mapRecoveryError 映射人工恢复领域错误；受保护目标使用根包专用错误码。
func mapRecoveryError(message, code, requestID string) error {
	if code == string(manualrecovery.CodeSupportTargetProtected) {
		return login.NewAppError(login.CodeSupportTargetProtected, message,
			requestIDOption(requestID))
	}
	return mapDomainError(message, code, requestID)
}

// Policy 返回当前制度视图。
func (f *manualRecoveryFacade) Policy(ctx context.Context) (ManualRecoveryPolicy, error) {
	security := f.r.securityDomains()
	if security == nil || security.ManualRecovery == nil {
		return ManualRecoveryPolicy{}, configError("人工恢复服务未装配")
	}
	policy := security.ManualRecovery.PolicySummary()
	bases := make([]string, 0, len(policy.VerificationBases))
	for _, basis := range policy.VerificationBases {
		bases = append(bases, string(basis))
	}
	channels := make([]string, 0, len(policy.DeliveryChannels))
	for _, channel := range policy.DeliveryChannels {
		channels = append(channels, string(channel))
	}
	return ManualRecoveryPolicy{Enabled: policy.Enabled, VerificationBases: bases,
		DeliveryChannels: channels, WaitPeriod: policy.WaitPeriod,
		ApprovalTTL: policy.ApprovalTTL, RequestTTL: policy.RequestTTL,
		RequireIndependentApproval: policy.RequireIndependentApproval}, nil
}

// Create 发起人工核验恢复申请（敏感操作，绑定目标/操作/核验依据/交付渠道）。
func (f *manualRecoveryFacade) Create(ctx context.Context,
	req ManualRecoveryCreateRequest) (ManualRecoveryRequest, error) {
	call, service, caller, err := f.beginRecovery(ctx, req.Caller, req.RequestID)
	if err != nil {
		return ManualRecoveryRequest{}, err
	}
	operation := manualrecovery.OperationType(strings.TrimSpace(req.Operation))
	basis := manualrecovery.VerificationBasis(strings.TrimSpace(req.VerificationBasis))
	delivery := manualrecovery.DeliveryChannel(strings.TrimSpace(req.Delivery))
	params := manualrecovery.ParamsRequest(req.TargetUserID, operation, basis,
		req.VerificationReference, req.EvidenceSummary, string(delivery),
		req.SupportCaseID)
	approved, err := f.approveRecovery(ctx, call, manualrecovery.OperationRequest,
		req.TargetUserID, params, req.Password, req.TOTPCode)
	if err != nil {
		return ManualRecoveryRequest{}, err
	}
	record, err := service.Create(approved, caller, manualrecovery.CreateRequest{
		TargetUserID: req.TargetUserID, Operation: operation,
		VerificationBasis: basis, VerificationReference: req.VerificationReference,
		EvidenceSummary: req.EvidenceSummary, Reason: req.Reason,
		Delivery: delivery, SupportCaseID: req.SupportCaseID, RequestID: call.requestID})
	if err != nil {
		return ManualRecoveryRequest{}, mapRecoveryError("发起人工恢复申请失败",
			string(manualrecovery.CodeOf(err)), call.requestID)
	}
	return manualRecoveryRequestOf(record), nil
}

// GetRequest 读取申请详情（申请参与者）。
func (f *manualRecoveryFacade) GetRequest(ctx context.Context,
	req ManualRecoveryRequestRef) (ManualRecoveryRequest, error) {
	call, service, caller, err := f.beginRecovery(ctx, req.Caller, req.TraceID)
	if err != nil {
		return ManualRecoveryRequest{}, err
	}
	record, err := service.GetRequest(ctx, caller, req.TargetRequestID)
	if err != nil {
		return ManualRecoveryRequest{}, mapRecoveryError("读取人工恢复申请失败",
			string(manualrecovery.CodeOf(err)), call.requestID)
	}
	return manualRecoveryRequestOf(record), nil
}

// List 分页读取本人相关待办/历史。
func (f *manualRecoveryFacade) List(ctx context.Context,
	req ManualRecoveryListRequest) (ManualRecoveryListPage, error) {
	call, service, caller, err := f.beginRecovery(ctx, req.Caller, req.RequestID)
	if err != nil {
		return ManualRecoveryListPage{}, err
	}
	page, err := call.page(req.Page)
	if err != nil {
		return ManualRecoveryListPage{}, err
	}
	result, err := service.ListForPage(ctx, caller, manualrecovery.ListRequest{
		Mode:      manualrecovery.ListMode(strings.TrimSpace(req.Mode)),
		Operation: manualrecovery.OperationType(strings.TrimSpace(req.Operation)),
		Offset:    page.Offset, Limit: page.Limit})
	if err != nil {
		return ManualRecoveryListPage{}, mapRecoveryError("读取人工恢复列表失败",
			string(manualrecovery.CodeOf(err)), call.requestID)
	}
	items := make([]ManualRecoveryListItem, 0, len(result.Items))
	for _, item := range result.Items {
		items = append(items, ManualRecoveryListItem{RequestID: item.RequestID,
			SupportCaseID: item.SupportCaseID, Operation: string(item.Operation),
			Status: string(item.Status), TargetMasked: item.TargetMasked,
			CreatedAt:  item.CreatedAt.UTC().Format(time.RFC3339),
			ExpiresAt:  item.ExpiresAt.UTC().Format(time.RFC3339),
			MyRelation: item.MyRelation})
	}
	return ManualRecoveryListPage{Items: items,
		Page: NewAdminPageInfo(page, len(items), result.HasMore)}, nil
}

// Approve 独立审批申请（敏感操作，绑定内容摘要/操作类型）。
func (f *manualRecoveryFacade) Approve(ctx context.Context,
	req ManualRecoveryDecisionRequest) (ManualRecoveryApproval, error) {
	call, service, caller, err := f.beginRecovery(ctx, req.Caller, req.TraceID)
	if err != nil {
		return ManualRecoveryApproval{}, err
	}
	record, err := service.GetRequestForApproval(ctx, caller, req.TargetRequestID)
	if err != nil {
		return ManualRecoveryApproval{}, mapRecoveryError("读取待审批申请失败",
			string(manualrecovery.CodeOf(err)), call.requestID)
	}
	approved, err := f.approveRecovery(ctx, call, manualrecovery.OperationApprove,
		record.TargetUserID, manualrecovery.ParamsApprove(record, "approve"),
		req.Password, req.TOTPCode)
	if err != nil {
		return ManualRecoveryApproval{}, err
	}
	approval, err := service.Approve(approved, caller, manualrecovery.ApproveRequest{
		RequestID: req.TargetRequestID, Note: req.Note, TraceID: call.requestID})
	if err != nil {
		return ManualRecoveryApproval{}, mapRecoveryError("审批人工恢复申请失败",
			string(manualrecovery.CodeOf(err)), call.requestID)
	}
	return manualRecoveryApprovalOf(approval), nil
}

// Reject 独立拒绝申请（敏感操作）。
func (f *manualRecoveryFacade) Reject(ctx context.Context,
	req ManualRecoveryDecisionRequest) error {
	call, service, caller, err := f.beginRecovery(ctx, req.Caller, req.TraceID)
	if err != nil {
		return err
	}
	record, err := service.GetRequestForApproval(ctx, caller, req.TargetRequestID)
	if err != nil {
		return mapRecoveryError("读取待审批申请失败",
			string(manualrecovery.CodeOf(err)), call.requestID)
	}
	approved, err := f.approveRecovery(ctx, call, manualrecovery.OperationApprove,
		record.TargetUserID, manualrecovery.ParamsApprove(record, "reject"),
		req.Password, req.TOTPCode)
	if err != nil {
		return err
	}
	if err := service.Reject(approved, caller, manualrecovery.RejectRequest{
		RequestID: req.TargetRequestID, Reason: req.Reason, TraceID: call.requestID}); err != nil {
		return mapRecoveryError("拒绝人工恢复申请失败",
			string(manualrecovery.CodeOf(err)), call.requestID)
	}
	return nil
}

// Cancel 发起者取消申请（非敏感，仅发起者本人）。
func (f *manualRecoveryFacade) Cancel(ctx context.Context,
	req ManualRecoveryCancelRequest) error {
	call, service, caller, err := f.beginRecovery(ctx, req.Caller, req.TraceID)
	if err != nil {
		return err
	}
	if err := service.Cancel(ctx, caller, req.TargetRequestID, call.requestID,
		req.Reason); err != nil {
		return mapRecoveryError("取消人工恢复申请失败",
			string(manualrecovery.CodeOf(err)), call.requestID)
	}
	return nil
}

// Execute 执行已批准且等待期已满的恢复（敏感操作，三权分离）。
func (f *manualRecoveryFacade) Execute(ctx context.Context,
	req ManualRecoveryExecuteRequest) (ManualRecoveryExecutionResult, error) {
	call, service, caller, err := f.beginRecovery(ctx, req.Caller, req.TraceID)
	if err != nil {
		return ManualRecoveryExecutionResult{}, err
	}
	record, err := service.GetRequestForPage(ctx, caller, req.TargetRequestID)
	if err != nil {
		return ManualRecoveryExecutionResult{}, mapRecoveryError("读取待执行申请失败",
			string(manualrecovery.CodeOf(err)), call.requestID)
	}
	approval, found, err := service.GetApproval(ctx, caller, req.TargetRequestID)
	if err != nil || !found {
		return ManualRecoveryExecutionResult{}, mapRecoveryError("读取有效批准失败",
			string(manualrecovery.CodeOf(err)), call.requestID)
	}
	approved, err := f.approveRecovery(ctx, call, manualrecovery.OperationExecute,
		record.TargetUserID, manualrecovery.ParamsExecute(record, approval),
		req.Password, req.TOTPCode)
	if err != nil {
		return ManualRecoveryExecutionResult{}, err
	}
	result, err := service.Execute(approved, caller, manualrecovery.ExecuteRequest{
		RequestID: req.TargetRequestID, TraceID: call.requestID})
	if err != nil {
		return ManualRecoveryExecutionResult{}, mapRecoveryError("执行人工恢复失败",
			string(manualrecovery.CodeOf(err)), call.requestID)
	}
	return ManualRecoveryExecutionResult{RequestID: result.RequestID,
		ExecutionID: result.ExecutionID, Status: string(result.Status),
		Operation: string(result.Operation), SessionsRevoked: result.SessionsRevoked,
		FactorsReset: result.FactorsReset, CredentialIssued: result.CredentialIssued,
		NotificationSent:  result.NotificationSent,
		NotificationState: result.NotificationState}, nil
}

// GetApproval 读取申请对应批准（参与者）。
func (f *manualRecoveryFacade) GetApproval(ctx context.Context,
	req ManualRecoveryRequestRef) (ManualRecoveryApproval, bool, error) {
	call, service, caller, err := f.beginRecovery(ctx, req.Caller, req.TraceID)
	if err != nil {
		return ManualRecoveryApproval{}, false, err
	}
	approval, found, err := service.GetApproval(ctx, caller, req.TargetRequestID)
	if err != nil {
		return ManualRecoveryApproval{}, false, mapRecoveryError("读取批准失败",
			string(manualrecovery.CodeOf(err)), call.requestID)
	}
	if !found {
		return ManualRecoveryApproval{}, false, nil
	}
	return manualRecoveryApprovalOf(approval), true, nil
}

// GetExecution 读取申请对应执行记录（参与者）。
func (f *manualRecoveryFacade) GetExecution(ctx context.Context,
	req ManualRecoveryRequestRef) (ManualRecoveryExecutionRecord, bool, error) {
	call, service, caller, err := f.beginRecovery(ctx, req.Caller, req.TraceID)
	if err != nil {
		return ManualRecoveryExecutionRecord{}, false, err
	}
	execution, found, err := service.GetExecution(ctx, caller, req.TargetRequestID)
	if err != nil {
		return ManualRecoveryExecutionRecord{}, false, mapRecoveryError("读取执行记录失败",
			string(manualrecovery.CodeOf(err)), call.requestID)
	}
	if !found {
		return ManualRecoveryExecutionRecord{}, false, nil
	}
	return manualRecoveryExecutionOf(execution), true, nil
}

// manualRecoveryRequestOf 转换申请视图（不含证据明文/内容摘要）。
func manualRecoveryRequestOf(record manualrecovery.RequestRecord) ManualRecoveryRequest {
	return ManualRecoveryRequest{ID: record.ID, TargetUserID: record.TargetUserID,
		InitiatorUserID: record.InitiatorUserID, Operation: string(record.Operation),
		Status: string(record.Status), VerificationBasis: string(record.VerificationBasis),
		VerificationReference: record.VerificationReference, Reason: record.Reason,
		Delivery: string(record.Delivery), SupportCaseID: record.SupportCaseID,
		ExpiresAt:    record.ExpiresAt.UTC().Format(time.RFC3339),
		ClosedReason: record.ClosedReason, RowVersion: record.RowVersion,
		CreatedAt: record.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt: record.UpdatedAt.UTC().Format(time.RFC3339)}
}

// manualRecoveryApprovalOf 转换批准视图。
func manualRecoveryApprovalOf(record manualrecovery.ApprovalRecord) ManualRecoveryApproval {
	return ManualRecoveryApproval{ID: record.ID, RequestID: record.RequestID,
		ApproverUserID: record.ApproverUserID, Operation: string(record.Operation),
		Status:            string(record.Status),
		ApprovedAt:        record.ApprovedAt.UTC().Format(time.RFC3339),
		NotBefore:         record.NotBefore.UTC().Format(time.RFC3339),
		ExpiresAt:         record.ExpiresAt.UTC().Format(time.RFC3339),
		FinishedAt:        formatOptionalTime(record.FinishedAt),
		InvalidatedReason: record.InvalidatedReason, RowVersion: record.RowVersion}
}

// manualRecoveryExecutionOf 转换执行记录视图。
func manualRecoveryExecutionOf(record manualrecovery.ExecutionRecord) ManualRecoveryExecutionRecord {
	return ManualRecoveryExecutionRecord{ID: record.ID, RequestID: record.RequestID,
		ApprovalID: record.ApprovalID, ExecutorUserID: record.ExecutorUserID,
		Operation: string(record.Operation), Status: record.Status,
		SessionsRevoked: record.SessionsRevoked, FactorsReset: record.FactorsReset,
		ResetCredentialIssued: record.ResetCredentialIssued,
		NotificationState:     record.NotificationState, ErrorCode: record.ErrorCode,
		StartedAt:  record.StartedAt.UTC().Format(time.RFC3339),
		FinishedAt: formatOptionalTime(record.FinishedAt)}
}
