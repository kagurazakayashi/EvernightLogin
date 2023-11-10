// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

// 邀请与注册审核管理公开 Go 接口（步骤 223）。
//
// 边界：
//   - 复用 internal/onboarding 的真实邀请/审核语义：目标邮箱或目标用户二选一、
//     邀请角色必须与作用范围一致、root/禁用/无邮箱目标不可邀请、创建事务内由生产
//     delegation Guard 复核可转授范围；审核需要真实管理授权（users.update）。
//   - LocalAdmin 走 onboarding.LocalAdminCaller（受信本地操作者，不是 is_root）；
//     AdminSession 走 onboarding.UserCaller，由生产 InviteAuthorizer（权限
//     onboarding.invite.create + 作用范围）与 ManagementAuthorizer（users.update）
//     判定；普通用户只能创建/查看自己的邀请（若其角色被允许）。
//   - 返回值脱敏：邀请/审核视图不含 token、邮件正文、密码或哈希；未发信时
//     TokenSent/Notified=false 并带稳定 ErrorCode，绝不伪造成已发送。
//   - 已授权但邀请/审核目标不存在时返回 NOT_FOUND（207 契约），未授权不泄露存在性。
//   - 访问器 Runtime.Invitations() 定义在本文件，不编辑 app/runtime.go。

import (
	"context"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/onboarding"
)

// InvitationAdminService 是邀请与注册审核管理门面。
type InvitationAdminService interface {
	// CreateInvitation 创建邀请（邮箱邀请或邀请已有用户）；创建成功但邮件未发送时
	// TokenSent=false + 稳定 ErrorCode，不伪造已发送。
	CreateInvitation(ctx context.Context,
		req AdminCreateInvitationRequest) (AdminInvitationCreateResult, error)
	// GetInvitation 读取邀请视图；用户身份只能读自己发起的邀请。
	GetInvitation(ctx context.Context, req AdminInvitationRequest) (AdminInvitation, error)
	// ListInvitations 分页列出邀请（用户只看自己发起的；受信管理通道看全部）。
	ListInvitations(ctx context.Context,
		req AdminListInvitationsRequest) (AdminInvitationList, error)
	// CancelInvitation 取消邀请（发起者或受信管理通道）；重复取消幂等。
	CancelInvitation(ctx context.Context,
		req AdminCancelInvitationRequest) (AdminInvitationCancelResult, error)
	// ListPendingRegistrations 分页列出待审核注册账户（需要真实管理强认证）。
	ListPendingRegistrations(ctx context.Context,
		req AdminListRegistrationsRequest) (AdminRegistrationList, error)
	// GetRegistration 读取待审核账户与审核状态。
	GetRegistration(ctx context.Context, req AdminRegistrationRequest) (AdminRegistration, error)
	// ApproveRegistration 通过注册审核（可分配显式作用范围的角色）。
	ApproveRegistration(ctx context.Context,
		req AdminRegistrationDecisionRequest) (AdminRegistrationDecisionResult, error)
	// RejectRegistration 拒绝注册审核（事务、幂等与审计语义由领域服务保证）。
	RejectRegistration(ctx context.Context,
		req AdminRegistrationDecisionRequest) (AdminRegistrationDecisionResult, error)
}

// AdminInvitationRole 是邀请/审核时显式给出的默认角色（角色 ID 与作用范围绑定）。
type AdminInvitationRole struct {
	RoleID  string
	ScopeID string
}

// AdminCreateInvitationRequest 是创建邀请请求；TargetEmail 与 TargetUserID 二选一。
type AdminCreateInvitationRequest struct {
	Caller       AdminCaller
	TargetEmail  string
	TargetUserID string
	// AppID 为空表示系统范围；非空时角色作用范围必须等于该应用。
	AppID     string
	Roles     []AdminInvitationRole
	MaxUses   int
	TTL       time.Duration
	RequestID string
}

// AdminInvitation 是脱敏的邀请视图（不含令牌/邮件正文）。
type AdminInvitation struct {
	ID            string
	InviterUserID string
	TargetKind    string
	TargetEmail   string
	TargetUserID  string
	AppID         string
	Status        string
	MaxUses       int
	UsedCount     int
	ExpiresAt     time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
	CancelledAt   time.Time
	CancelReason  string
	Roles         []AdminInvitationRole
	NotifyState   string
	NotifyError   string
	NotifiedAt    time.Time
}

// AdminInvitationCreateResult 是创建邀请结果；TokenSent=false 时 ErrorCode 说明
// 未发送类别（例如邮件未配置）。
type AdminInvitationCreateResult struct {
	Invitation AdminInvitation
	TokenSent  bool
	ErrorCode  string
}

// AdminInvitationRequest 是单个邀请读取请求。
type AdminInvitationRequest struct {
	Caller       AdminCaller
	InvitationID string
	RequestID    string
}

// AdminListInvitationsRequest 分页列出邀请；Status 空表示全部。
type AdminListInvitationsRequest struct {
	Caller    AdminCaller
	Status    string
	Page      AdminPage
	RequestID string
}

// AdminInvitationList 是邀请列表结果。
type AdminInvitationList struct {
	Invitations []AdminInvitation
	HasMore     bool
	Page        AdminPageInfo
}

// AdminCancelInvitationRequest 是取消邀请请求（Reason 写入审计，≤500 字符）。
type AdminCancelInvitationRequest struct {
	Caller       AdminCaller
	InvitationID string
	Reason       string
	RequestID    string
}

// AdminInvitationCancelResult 是取消邀请结果；Cancelled=false 表示幂等命中已取消。
type AdminInvitationCancelResult struct {
	Invitation AdminInvitation
	Cancelled  bool
}

// AdminRegistration 是待审核注册账户的脱敏视图。
type AdminRegistration struct {
	UserID        string
	Username      string
	Status        string
	ReviewStatus  string
	Reason        string
	DecidedByType string
	DecidedByID   string
	DecidedAt     time.Time
	CreatedAt     time.Time
	NotifyState   string
	NotifyError   string
	NotifiedAt    time.Time
}

// AdminListRegistrationsRequest 分页列出待审核注册账户。
type AdminListRegistrationsRequest struct {
	Caller    AdminCaller
	Page      AdminPage
	RequestID string
}

// AdminRegistrationList 是待审核列表结果。
type AdminRegistrationList struct {
	Registrations []AdminRegistration
	HasMore       bool
	Page          AdminPageInfo
}

// AdminRegistrationRequest 读取单个待审核账户。
type AdminRegistrationRequest struct {
	Caller    AdminCaller
	UserID    string
	RequestID string
}

// AdminRegistrationDecisionRequest 是注册审核决定请求；AppID/Roles 用于通过时
// 分配显式作用范围的默认角色（不能越过调用者可委派范围）。
type AdminRegistrationDecisionRequest struct {
	Caller    AdminCaller
	UserID    string
	Reason    string
	AppID     string
	Roles     []AdminInvitationRole
	RequestID string
}

// AdminRegistrationDecisionResult 是注册审核结果；Notified=false 时 ErrorCode
// 说明通知未发送类别。
type AdminRegistrationDecisionResult struct {
	Registration AdminRegistration
	Notified     bool
	ErrorCode    string
}

// Invitations 返回邀请与注册审核管理门面。
func (r *Runtime) Invitations() InvitationAdminService {
	return &invitationAdminFacade{r: r}
}

type invitationAdminFacade struct {
	r *Runtime
}

func (f *invitationAdminFacade) admin() *adminFacade {
	return &adminFacade{r: f.r}
}

// onboardingCaller 按管理身份构造入驻服务可信调用者。
func (f *invitationAdminFacade) onboardingCaller(id adminIdentity) (onboarding.Caller, error) {
	if id.local {
		return onboarding.LocalAdminCaller(id.actor.ID)
	}
	return onboarding.UserCaller(id.userID)
}

// beginOnboarding 完成身份解析、服务装配与调用者构造（统一前置，避免复制错误映射）。
func (f *invitationAdminFacade) beginOnboarding(ctx context.Context, caller AdminCaller,
	requestID string) (adminRequest, *onboarding.Service, onboarding.Caller, error) {
	call, err := f.admin().begin(ctx, caller, requestID)
	if err != nil {
		return adminRequest{}, nil, onboarding.Caller{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Onboarding == nil {
		return call, nil, onboarding.Caller{},
			call.configError("邀请服务未装配")
	}
	onboardingCaller, err := f.onboardingCaller(call.identity)
	if err != nil {
		return call, nil, onboarding.Caller{}, call.configError("邀请服务调用者无效")
	}
	if onboardingCaller, err = onboardingCaller.WithRequestID(call.requestID); err != nil {
		return call, nil, onboarding.Caller{}, call.configError("请求编号无效")
	}
	return call, managed.Onboarding, onboardingCaller, nil
}

// CreateInvitation 创建邀请。
//
// 边界：invitations.inviter_user_id 在数据库层外键引用真实用户，因此创建邀请必须
// 由真实用户（AdminSession + onboarding.invite.create 权限）发起；LocalAdmin 只有
// 进程操作者 ID、没有用户记录，不能作为邀请发起者（否则会得到误导性的存储错误）。
// LocalAdmin 仍可读取/取消失败或他人邀请（受信管理通道语义）。
func (f *invitationAdminFacade) CreateInvitation(ctx context.Context,
	req AdminCreateInvitationRequest) (AdminInvitationCreateResult, error) {
	call, service, caller, err := f.beginOnboarding(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminInvitationCreateResult{}, err
	}
	if call.identity.local {
		return AdminInvitationCreateResult{}, call.configError(
			"邀请必须由真实用户发起（LocalAdmin 没有用户身份，不能作为邀请发起者）")
	}
	roles := make([]onboarding.Role, 0, len(req.Roles))
	for _, role := range req.Roles {
		roles = append(roles, onboarding.Role{RoleID: strings.TrimSpace(role.RoleID),
			ScopeID: strings.TrimSpace(role.ScopeID)})
	}
	result, err := service.CreateInvitation(ctx, caller, onboarding.CreateRequest{
		TargetEmail:  strings.TrimSpace(req.TargetEmail),
		TargetUserID: strings.TrimSpace(req.TargetUserID),
		AppID:        strings.TrimSpace(req.AppID), Roles: roles, MaxUses: req.MaxUses,
		TTL: req.TTL, RequestID: call.requestID})
	if err != nil {
		return AdminInvitationCreateResult{}, call.domainError("创建邀请失败",
			string(onboarding.CodeOf(err)))
	}
	return AdminInvitationCreateResult{Invitation: adminInvitationOf(result.Invitation),
		TokenSent: result.TokenSent, ErrorCode: string(result.ErrorCode)}, nil
}

// GetInvitation 读取邀请视图。
func (f *invitationAdminFacade) GetInvitation(ctx context.Context,
	req AdminInvitationRequest) (AdminInvitation, error) {
	call, service, caller, err := f.beginOnboarding(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminInvitation{}, err
	}
	invitation, err := service.GetInvitation(ctx, caller, strings.TrimSpace(req.InvitationID))
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err,
			onboarding.ErrInvitationNotFound, "invitation"); ok {
			return AdminInvitation{}, replaced
		}
		return AdminInvitation{}, call.domainError("读取邀请失败",
			string(onboarding.CodeOf(err)))
	}
	return adminInvitationOf(invitation), nil
}

// ListInvitations 分页列出邀请。
func (f *invitationAdminFacade) ListInvitations(ctx context.Context,
	req AdminListInvitationsRequest) (AdminInvitationList, error) {
	call, service, caller, err := f.beginOnboarding(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminInvitationList{}, err
	}
	page, err := call.page(req.Page)
	if err != nil {
		return AdminInvitationList{}, err
	}
	result, err := service.ListInvitations(ctx, caller, onboarding.ListRequest{
		Status: onboarding.InvitationStatus(strings.TrimSpace(req.Status)),
		Limit:  page.Limit, Offset: page.Offset})
	if err != nil {
		return AdminInvitationList{}, call.domainError("列出邀请失败",
			string(onboarding.CodeOf(err)))
	}
	items := make([]AdminInvitation, 0, len(result.Invitations))
	for _, invitation := range result.Invitations {
		items = append(items, adminInvitationOf(invitation))
	}
	return AdminInvitationList{Invitations: items, HasMore: result.HasMore,
		Page: NewAdminPageInfo(page, len(items), result.HasMore)}, nil
}

// CancelInvitation 取消邀请。
func (f *invitationAdminFacade) CancelInvitation(ctx context.Context,
	req AdminCancelInvitationRequest) (AdminInvitationCancelResult, error) {
	call, service, caller, err := f.beginOnboarding(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminInvitationCancelResult{}, err
	}
	result, err := service.CancelInvitation(ctx, caller, onboarding.CancelRequest{
		InvitationID: strings.TrimSpace(req.InvitationID),
		Reason:       req.Reason, RequestID: call.requestID})
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err,
			onboarding.ErrInvitationNotFound, "invitation"); ok {
			return AdminInvitationCancelResult{}, replaced
		}
		return AdminInvitationCancelResult{}, call.domainError("取消邀请失败",
			string(onboarding.CodeOf(err)))
	}
	return AdminInvitationCancelResult{Invitation: adminInvitationOf(result.Invitation),
		Cancelled: result.Cancelled}, nil
}

// ListPendingRegistrations 分页列出待审核注册账户。
func (f *invitationAdminFacade) ListPendingRegistrations(ctx context.Context,
	req AdminListRegistrationsRequest) (AdminRegistrationList, error) {
	call, service, caller, err := f.beginOnboarding(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminRegistrationList{}, err
	}
	page, err := call.page(req.Page)
	if err != nil {
		return AdminRegistrationList{}, err
	}
	result, err := service.ListPendingReviews(ctx, caller,
		onboarding.ReviewQuery{Limit: page.Limit, Offset: page.Offset})
	if err != nil {
		return AdminRegistrationList{}, call.domainError("列出待审核注册失败",
			string(onboarding.CodeOf(err)))
	}
	items := make([]AdminRegistration, 0, len(result.Users))
	for _, user := range result.Users {
		items = append(items, adminRegistrationOf(user))
	}
	return AdminRegistrationList{Registrations: items, HasMore: result.HasMore,
		Page: NewAdminPageInfo(page, len(items), result.HasMore)}, nil
}

// GetRegistration 读取待审核账户。
func (f *invitationAdminFacade) GetRegistration(ctx context.Context,
	req AdminRegistrationRequest) (AdminRegistration, error) {
	call, service, caller, err := f.beginOnboarding(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminRegistration{}, err
	}
	user, err := service.GetReview(ctx, caller, strings.TrimSpace(req.UserID))
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err,
			onboarding.ErrReviewNotFound, "registration"); ok {
			return AdminRegistration{}, replaced
		}
		return AdminRegistration{}, call.domainError("读取待审核注册失败",
			string(onboarding.CodeOf(err)))
	}
	return adminRegistrationOf(user), nil
}

// ApproveRegistration 通过注册审核。
func (f *invitationAdminFacade) ApproveRegistration(ctx context.Context,
	req AdminRegistrationDecisionRequest) (AdminRegistrationDecisionResult, error) {
	return f.decideRegistration(ctx, req, true)
}

// RejectRegistration 拒绝注册审核。
func (f *invitationAdminFacade) RejectRegistration(ctx context.Context,
	req AdminRegistrationDecisionRequest) (AdminRegistrationDecisionResult, error) {
	return f.decideRegistration(ctx, req, false)
}

// decideRegistration 复用真实审核决定与事务/幂等/审计语义。
func (f *invitationAdminFacade) decideRegistration(ctx context.Context,
	req AdminRegistrationDecisionRequest,
	approve bool) (AdminRegistrationDecisionResult, error) {
	call, service, caller, err := f.beginOnboarding(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminRegistrationDecisionResult{}, err
	}
	roles := make([]onboarding.Role, 0, len(req.Roles))
	for _, role := range req.Roles {
		roles = append(roles, onboarding.Role{RoleID: strings.TrimSpace(role.RoleID),
			ScopeID: strings.TrimSpace(role.ScopeID)})
	}
	reviewRequest := onboarding.ReviewRequest{UserID: strings.TrimSpace(req.UserID),
		Reason: req.Reason, AppID: strings.TrimSpace(req.AppID), Roles: roles,
		RequestID: call.requestID}
	var result onboarding.ReviewResult
	if approve {
		result, err = service.ApproveRegistration(ctx, caller, reviewRequest)
	} else {
		result, err = service.RejectRegistration(ctx, caller, reviewRequest)
	}
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err,
			onboarding.ErrReviewNotFound, "registration"); ok {
			return AdminRegistrationDecisionResult{}, replaced
		}
		return AdminRegistrationDecisionResult{}, call.domainError("注册审核失败",
			string(onboarding.CodeOf(err)))
	}
	return AdminRegistrationDecisionResult{Registration: adminRegistrationOf(result.Review),
		Notified: result.Notified, ErrorCode: string(result.ErrorCode)}, nil
}

// adminInvitationOf 把入驻领域邀请快照转换为公开脱敏视图。
func adminInvitationOf(invitation onboarding.Invitation) AdminInvitation {
	roles := make([]AdminInvitationRole, 0, len(invitation.Roles))
	for _, role := range invitation.Roles {
		roles = append(roles, AdminInvitationRole{RoleID: role.RoleID,
			ScopeID: role.ScopeID})
	}
	return AdminInvitation{ID: invitation.ID, InviterUserID: invitation.InviterUserID,
		TargetKind: string(invitation.TargetKind), TargetEmail: invitation.TargetEmail,
		TargetUserID: invitation.TargetUserID, AppID: invitation.AppID,
		Status: string(invitation.Status), MaxUses: invitation.MaxUses,
		UsedCount: invitation.UsedCount, ExpiresAt: invitation.ExpiresAt,
		CreatedAt: invitation.CreatedAt, UpdatedAt: invitation.UpdatedAt,
		CancelledAt: invitation.CancelledAt, CancelReason: invitation.CancelReason,
		Roles: roles, NotifyState: string(invitation.NotifyState),
		NotifyError: invitation.NotifyError, NotifiedAt: invitation.NotifiedAt}
}

// adminRegistrationOf 把待审核账户快照转换为公开脱敏视图。
func adminRegistrationOf(user onboarding.ReviewUser) AdminRegistration {
	return AdminRegistration{UserID: user.UserID, Username: user.Username,
		Status: string(user.Status), ReviewStatus: string(user.ReviewStatus),
		Reason: user.Reason, DecidedByType: string(user.DecidedByType),
		DecidedByID: user.DecidedByID, DecidedAt: user.DecidedAt,
		CreatedAt: user.CreatedAt, NotifyState: string(user.NotifyState),
		NotifyError: user.NotifyError, NotifiedAt: user.NotifiedAt}
}
