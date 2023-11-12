// Copyright (c) Kagurazakayashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
)

// RBACDelegationService 是可转授资格管理服务。
//
// 委派资格只表示“可转授上限”，不授予系统资格、不替代有效权限；签发/撤回只接受
// 受信本地/系统通道（普通管理会话被领域服务拒绝），普通用户只能读取自己的资格与
// 可转授权限。所有实际赋权动作仍由 role/group/app 服务在事务内经同一 Guard 复核。
type RBACDelegationService interface {
	// Grant 为受信操作者签发委派资格（复用既有 AdminDelegationGrantRequest）。
	Grant(ctx context.Context, req AdminDelegationGrantRequest) (AdminDelegation, error)
	// Revoke 撤回委派资格（受信本地/系统通道；已撤回时幂等 Changed=false）。
	Revoke(ctx context.Context, req RBACDelegationRequest) (bool, error)
	// Get 读取一条委派资格；普通用户只能读取自己的资格。
	Get(ctx context.Context, req RBACDelegationRequest) (RBACDelegation, error)
	// List 分页读取委派资格（内部 Limit/Offset + limit+1 探测 HasMore）。
	List(ctx context.Context, req RBACDelegationListRequest) (RBACDelegationList, error)
	// DelegatablePermissions 读取调用者当前实际可转授的权限（仅普通用户自己的资格）。
	DelegatablePermissions(ctx context.Context,
		req RBACDelegatableRequest) ([]RBACDelegatablePermission, error)
}

// RBACDelegationRequest 是按资格 ID 的读取/撤回请求。
type RBACDelegationRequest struct {
	Caller    AdminCaller
	GrantID   string
	RequestID string
}

// RBACDelegation 是委派资格视图（含可转授上限与有效期状态）。
type RBACDelegation struct {
	ID              string
	DelegatorUserID string
	ScopeID         string
	PermissionID    string
	PermissionKey   string
	PermissionName  string
	MaxDataScope    string
	AllowSelf       bool
	ExpiresAt       *time.Time
	RevokedAt       *time.Time
	CreatedBy       string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// RBACDelegationListRequest 是委派资格分页列表请求。
type RBACDelegationListRequest struct {
	Caller          AdminCaller
	DelegatorUserID string
	IncludeRevoked  bool
	Page            AdminPage
	RequestID       string
}

// RBACDelegationList 是委派资格分页结果。
type RBACDelegationList struct {
	Grants  []RBACDelegation
	HasMore bool
	Page    AdminPageInfo
}

// RBACDelegatableRequest 是可转授权限查询请求。
type RBACDelegatableRequest struct {
	Caller    AdminCaller
	ScopeID   string
	RequestID string
}

// RBACDelegatablePermission 是当前实际可转授的权限摘要。
type RBACDelegatablePermission struct {
	PermissionID string
	Key          string
	Name         string
	MaxDataScope string
	AllowSelf    bool
	ExpiresAt    *time.Time
}

// Delegations 返回委派资格服务。
func (f *rbacFacade) Delegations() RBACDelegationService {
	return &rbacDelegationFacade{f: f}
}

type rbacDelegationFacade struct{ f *rbacFacade }

// delegationCaller 构造带请求编号的委派服务调用者。
func (s *rbacDelegationFacade) delegationCaller(call adminRequest) (delegation.Caller, error) {
	var (
		caller delegation.Caller
		err    error
	)
	if call.identity.local {
		caller, err = delegation.LocalBootstrapCaller(call.identity.actor.ID)
	} else {
		caller, err = delegation.UserCaller(call.identity.userID)
	}
	if err != nil {
		return delegation.Caller{}, call.configError("委派服务调用者无效")
	}
	return bindCaller(caller, call.requestID)
}

func (s *rbacDelegationFacade) service(call adminRequest) (*delegation.Service, error) {
	managed := s.f.r.managedServices()
	if managed == nil || managed.Delegation == nil {
		return nil, call.configError("委派服务未装配")
	}
	return managed.Delegation, nil
}

// rbacDelegation 把内部资格投影为公开视图。
func rbacDelegation(grant delegation.Grant) RBACDelegation {
	return RBACDelegation{ID: grant.ID, DelegatorUserID: grant.DelegatorUserID,
		ScopeID: grant.ScopeID, PermissionID: grant.PermissionID,
		PermissionKey: grant.PermissionKey, PermissionName: grant.PermissionName,
		MaxDataScope: grant.MaxDataScope, AllowSelf: grant.AllowSelf,
		ExpiresAt: grant.ExpiresAt, RevokedAt: grant.RevokedAt,
		CreatedBy: grant.CreatedBy.ID, CreatedAt: grant.CreatedAt, UpdatedAt: grant.UpdatedAt}
}

// Grant 复用 AdminService 的签发实现（内部强制受信通道）。
func (s *rbacDelegationFacade) Grant(ctx context.Context,
	req AdminDelegationGrantRequest) (AdminDelegation, error) {
	return s.f.admin.GrantDelegation(ctx, req)
}

// Revoke 撤回委派资格。
func (s *rbacDelegationFacade) Revoke(ctx context.Context, req RBACDelegationRequest) (bool, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return false, err
	}
	service, err := s.service(call)
	if err != nil {
		return false, err
	}
	caller, err := s.delegationCaller(call)
	if err != nil {
		return false, err
	}
	changed, err := service.Revoke(ctx, caller, req.GrantID)
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, delegation.ErrGrantNotFound, "delegation"); ok {
			return false, replaced
		}
		return false, call.domainError("撤回委派资格失败", string(delegation.CodeOf(err)))
	}
	return changed, nil
}

// Get 读取委派资格。
func (s *rbacDelegationFacade) Get(ctx context.Context, req RBACDelegationRequest) (RBACDelegation, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return RBACDelegation{}, err
	}
	service, err := s.service(call)
	if err != nil {
		return RBACDelegation{}, err
	}
	caller, err := s.delegationCaller(call)
	if err != nil {
		return RBACDelegation{}, err
	}
	grant, err := service.Get(ctx, caller, req.GrantID)
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, delegation.ErrGrantNotFound, "delegation"); ok {
			return RBACDelegation{}, replaced
		}
		return RBACDelegation{}, call.domainError("读取委派资格失败", string(delegation.CodeOf(err)))
	}
	return rbacDelegation(grant), nil
}

// List 分页读取委派资格。
func (s *rbacDelegationFacade) List(ctx context.Context,
	req RBACDelegationListRequest) (RBACDelegationList, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return RBACDelegationList{}, err
	}
	page, err := call.page(req.Page)
	if err != nil {
		return RBACDelegationList{}, err
	}
	service, err := s.service(call)
	if err != nil {
		return RBACDelegationList{}, err
	}
	caller, err := s.delegationCaller(call)
	if err != nil {
		return RBACDelegationList{}, err
	}
	// 内部列表没有 HasMore：多取一条在 App 层有界探测，不读全量。
	grants, err := service.List(ctx, caller, delegation.ListRequest{
		DelegatorUserID: req.DelegatorUserID, IncludeRevoked: req.IncludeRevoked,
		Limit: page.Limit + 1, Offset: page.Offset})
	if err != nil {
		return RBACDelegationList{}, call.domainError("读取委派资格列表失败",
			string(delegation.CodeOf(err)))
	}
	hasMore := len(grants) > page.Limit
	if hasMore {
		grants = grants[:page.Limit]
	}
	result := make([]RBACDelegation, 0, len(grants))
	for _, grant := range grants {
		result = append(result, rbacDelegation(grant))
	}
	return RBACDelegationList{Grants: result, HasMore: hasMore,
		Page: NewAdminPageInfo(page, len(result), hasMore)}, nil
}

// DelegatablePermissions 读取“当前实际可转授”的权限。
func (s *rbacDelegationFacade) DelegatablePermissions(ctx context.Context,
	req RBACDelegatableRequest) ([]RBACDelegatablePermission, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return nil, err
	}
	service, err := s.service(call)
	if err != nil {
		return nil, err
	}
	caller, err := s.delegationCaller(call)
	if err != nil {
		return nil, err
	}
	values, err := service.DelegatablePermissions(ctx, caller, req.ScopeID)
	if err != nil {
		return nil, call.domainError("读取可转授权限失败", string(delegation.CodeOf(err)))
	}
	result := make([]RBACDelegatablePermission, 0, len(values))
	for _, value := range values {
		result = append(result, RBACDelegatablePermission{PermissionID: value.PermissionID,
			Key: value.Key, Name: value.Name, MaxDataScope: value.MaxDataScope,
			AllowSelf: value.AllowSelf, ExpiresAt: value.ExpiresAt})
	}
	return result, nil
}
