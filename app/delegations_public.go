// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

// 委派资格公开 Go 接口（步骤 225 P0）。
//
// 边界：
//   - 复用 internal/delegation：签发/撤回只允许受信本地/系统通道；普通用户只能
//     读取自己的资格；签发的是“可转授上限”，实际转授仍由事务内 Guard 复核；
//   - 本门面只补“列表/详情/撤回/可转授权限”，签发继续保留既有
//     AdminService.GrantDelegation（单一签发入口，不复制）；
//   - Actor 模型限制（与 223 邀请 FK 同类）：LocalAdmin 只有进程操作者 ID、不是
//     用户也不是 is_root，不能成为委派对象；任何 DelegatorUserID 必须是真实用户。
//     把 LocalAdmin 操作者 ID 当作委派主体会得到稳定 REQ_INVALID/ACCESS_DENIED，
//     不会被静默接受；
//   - 撤回是安全清理，允许对已停用目标执行；重复撤回返回 Changed=false；
//   - 访问器 Runtime.Delegations() 定义在本文件，不编辑 runtime.go/admin.go/types.go。

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
)

// DelegationAdminService 是委派资格读取/撤回/可转授权限查询门面。
type DelegationAdminService interface {
	// ListDelegations 列出委派资格：普通用户只能看自己；受信管理通道可指定
	// DelegatorUserID 或读取全部。
	ListDelegations(ctx context.Context,
		req AdminListDelegationsRequest) (AdminDelegationList, error)
	// GetDelegation 读取单条委派资格（普通用户只能读自己的）。
	GetDelegation(ctx context.Context, req AdminDelegationRequest) (AdminDelegationDetail, error)
	// RevokeDelegation 撤回委派资格（只有受信本地/系统通道；重复撤回幂等）。
	RevokeDelegation(ctx context.Context,
		req AdminDelegationRequest) (AdminDelegationRevokeResult, error)
	// DelegatablePermissions 返回当前主体实际可转授的权限（与“可使用权限”区分）。
	DelegatablePermissions(ctx context.Context,
		req AdminDelegatablePermissionsRequest) ([]AdminDelegatablePermission, error)
}

// AdminDelegationDetail 是委派资格脱敏视图（不包含任何秘密）。
type AdminDelegationDetail struct {
	ID              string
	DelegatorUserID string
	ScopeID         string
	ScopeKind       string
	ApplicationID   string
	PermissionID    string
	PermissionKey   string
	PermissionName  string
	MaxDataScope    string
	AllowedUsers    []string
	AllowedGroups   []string
	AllowSelf       bool
	ExpiresAt       string
	RevokedAt       string
	CreatedByType   string
	CreatedByID     string
	CreatedAt       string
	UpdatedAt       string
}

// AdminListDelegationsRequest 分页列出委派资格；DelegatorUserID 仅受信通道有效。
type AdminListDelegationsRequest struct {
	Caller          AdminCaller
	DelegatorUserID string
	IncludeRevoked  bool
	Page            AdminPage
	RequestID       string
}

// AdminDelegationList 是委派资格列表结果。
type AdminDelegationList struct {
	Delegations []AdminDelegationDetail
	HasMore     bool
	Page        AdminPageInfo
}

// AdminDelegationRequest 读取/撤回单条委派资格。
type AdminDelegationRequest struct {
	Caller    AdminCaller
	GrantID   string
	RequestID string
}

// AdminDelegationRevokeResult 是撤回结果；Changed=false 表示幂等命中已撤回。
type AdminDelegationRevokeResult struct {
	GrantID string
	Changed bool
	Grant   AdminDelegationDetail
}

// AdminDelegatablePermissionsRequest 查询可转授权限。
type AdminDelegatablePermissionsRequest struct {
	Caller    AdminCaller
	ScopeID   string
	RequestID string
}

// AdminDelegatablePermission 是可转授权限摘要。
type AdminDelegatablePermission struct {
	PermissionID string
	Key          string
	Name         string
	MaxDataScope string
	AllowSelf    bool
	ExpiresAt    string
}

// Delegations 返回委派资格公开门面。
func (r *Runtime) Delegations() DelegationAdminService {
	return &delegationsFacade{r: r}
}

type delegationsFacade struct {
	r *Runtime
}

func (f *delegationsFacade) admin() *adminFacade {
	return &adminFacade{r: f.r}
}

// beginDelegation 完成身份解析并构造委派领域调用者。
func (f *delegationsFacade) beginDelegation(ctx context.Context, caller AdminCaller,
	requestID string) (adminRequest, *delegation.Service, delegation.Caller, error) {
	call, err := f.admin().begin(ctx, caller, requestID)
	if err != nil {
		return adminRequest{}, nil, delegation.Caller{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Delegation == nil {
		return call, nil, delegation.Caller{}, call.configError("委派服务未装配")
	}
	var delegationCaller delegation.Caller
	if call.identity.local {
		delegationCaller, err = delegation.LocalBootstrapCaller(call.identity.actor.ID)
	} else {
		delegationCaller, err = delegation.UserCaller(call.identity.userID)
	}
	if err != nil {
		return call, nil, delegation.Caller{}, call.configError("委派服务调用者无效")
	}
	if delegationCaller, err = delegationCaller.WithRequestID(call.requestID); err != nil {
		return call, nil, delegation.Caller{}, call.configError("请求编号无效")
	}
	return call, managed.Delegation, delegationCaller, nil
}

// ListDelegations 分页列出委派资格；为避免无界读取，按页最多取 limit+1 判定 HasMore。
func (f *delegationsFacade) ListDelegations(ctx context.Context,
	req AdminListDelegationsRequest) (AdminDelegationList, error) {
	call, service, caller, err := f.beginDelegation(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminDelegationList{}, err
	}
	page, err := call.page(req.Page)
	if err != nil {
		return AdminDelegationList{}, err
	}
	limit := page.Limit
	fetchLimit := limit
	if fetchLimit < delegationMaxListLimit {
		fetchLimit++
	}
	grants, err := service.List(ctx, caller, delegation.ListRequest{
		DelegatorUserID: req.DelegatorUserID, IncludeRevoked: req.IncludeRevoked,
		Limit: fetchLimit, Offset: page.Offset})
	if err != nil {
		return AdminDelegationList{}, call.domainError("列出委派资格失败",
			string(delegation.CodeOf(err)))
	}
	hasMore := len(grants) > limit
	if hasMore {
		grants = grants[:limit]
	}
	items := make([]AdminDelegationDetail, 0, len(grants))
	for _, grant := range grants {
		items = append(items, adminDelegationOf(grant))
	}
	return AdminDelegationList{Delegations: items, HasMore: hasMore,
		Page: NewAdminPageInfo(page, len(items), hasMore)}, nil
}

// delegationMaxListLimit 与 internal/delegation 单页上限保持一致。
const delegationMaxListLimit = 100

// GetDelegation 读取单条委派资格。
func (f *delegationsFacade) GetDelegation(ctx context.Context,
	req AdminDelegationRequest) (AdminDelegationDetail, error) {
	call, service, caller, err := f.beginDelegation(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminDelegationDetail{}, err
	}
	grant, err := service.Get(ctx, caller, req.GrantID)
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, delegation.ErrGrantNotFound,
			"delegation"); ok {
			return AdminDelegationDetail{}, replaced
		}
		return AdminDelegationDetail{}, call.domainError("读取委派资格失败",
			string(delegation.CodeOf(err)))
	}
	return adminDelegationOf(grant), nil
}

// RevokeDelegation 撤回委派资格（仅受信本地/系统通道）。
func (f *delegationsFacade) RevokeDelegation(ctx context.Context,
	req AdminDelegationRequest) (AdminDelegationRevokeResult, error) {
	call, service, caller, err := f.beginDelegation(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminDelegationRevokeResult{}, err
	}
	changed, err := service.Revoke(ctx, caller, req.GrantID)
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, delegation.ErrGrantNotFound,
			"delegation"); ok {
			return AdminDelegationRevokeResult{}, replaced
		}
		return AdminDelegationRevokeResult{}, call.domainError("撤回委派资格失败",
			string(delegation.CodeOf(err)))
	}
	result := AdminDelegationRevokeResult{GrantID: req.GrantID, Changed: changed}
	if grant, getErr := service.Get(ctx, caller, req.GrantID); getErr == nil {
		result.Grant = adminDelegationOf(grant)
	}
	return result, nil
}

// DelegatablePermissions 查询当前主体可转授权限。
func (f *delegationsFacade) DelegatablePermissions(ctx context.Context,
	req AdminDelegatablePermissionsRequest) ([]AdminDelegatablePermission, error) {
	call, service, caller, err := f.beginDelegation(ctx, req.Caller, req.RequestID)
	if err != nil {
		return nil, err
	}
	permissions, err := service.DelegatablePermissions(ctx, caller, req.ScopeID)
	if err != nil {
		return nil, call.domainError("查询可转授权限失败",
			string(delegation.CodeOf(err)))
	}
	items := make([]AdminDelegatablePermission, 0, len(permissions))
	for _, permission := range permissions {
		items = append(items, AdminDelegatablePermission{PermissionID: permission.PermissionID,
			Key: permission.Key, Name: permission.Name,
			MaxDataScope: permission.MaxDataScope, AllowSelf: permission.AllowSelf,
			ExpiresAt: formatDelegationTime(permission.ExpiresAt)})
	}
	return items, nil
}

// adminDelegationOf 转换委派资格视图。
func adminDelegationOf(grant delegation.Grant) AdminDelegationDetail {
	return AdminDelegationDetail{ID: grant.ID,
		DelegatorUserID: grant.DelegatorUserID, ScopeID: grant.ScopeID,
		ScopeKind: string(grant.ScopeKind), ApplicationID: grant.ApplicationID,
		PermissionID: grant.PermissionID, PermissionKey: grant.PermissionKey,
		PermissionName: grant.PermissionName, MaxDataScope: grant.MaxDataScope,
		AllowedUsers:  append([]string{}, grant.AllowedTargets.Users...),
		AllowedGroups: append([]string{}, grant.AllowedTargets.Groups...),
		AllowSelf:     grant.AllowSelf, ExpiresAt: formatDelegationPtr(grant.ExpiresAt),
		RevokedAt:     formatDelegationPtr(grant.RevokedAt),
		CreatedByType: string(grant.CreatedBy.Type), CreatedByID: grant.CreatedBy.ID,
		CreatedAt: grant.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt: grant.UpdatedAt.UTC().Format(time.RFC3339)}
}

// formatDelegationPtr 格式化可选时间；空指针返回空字符串。
func formatDelegationPtr(value *time.Time) string {
	if value == nil || value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

// formatDelegationTime 格式化可选时间值。
func formatDelegationTime(value *time.Time) string {
	return formatDelegationPtr(value)
}
