// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

import (
	"context"

	"github.com/kagurazakayashi/EvernightLogin/internal/group"
)

// RBACGroupService 是用户组与组成员批量变更服务。
//
// 组成员变更会通过“组角色”间接改变有效权限，因此领域服务对批量加入/移除执行
// 可转授范围检查与再次认证；root 不能作为组成员。批量操作原子：失败不返回部分成功。
type RBACGroupService interface {
	// Create 在系统或应用范围创建用户组（不自动分配角色）。
	Create(ctx context.Context, req RBACCreateGroupRequest) (RBACGroup, error)
	// Get 按稳定组 ID 读取；已授权但不存在返回 NOT_FOUND。
	Get(ctx context.Context, req RBACGroupRequest) (RBACGroup, error)
	// Update 更新名称/说明；scope/group_key 不可变。
	Update(ctx context.Context, req RBACUpdateGroupRequest) (RBACGroup, error)
	// Delete 删除用户组（仍被角色分配等引用时按领域语义拒绝）。
	Delete(ctx context.Context, req RBACGroupRequest) error
	// List 分页读取用户组（复用既有 AdminListGroupsRequest）。
	List(ctx context.Context, req AdminListGroupsRequest) (AdminGroupList, error)
	// ListMembers 分页读取组成员（复用既有 AdminListGroupMembersRequest）。
	ListMembers(ctx context.Context, req AdminListGroupMembersRequest) (AdminGroupMemberList, error)
	// AddMembers 批量加入成员（原子；敏感操作）。
	AddMembers(ctx context.Context, req RBACGroupMemberBatchRequest) (RBACGroupMemberBatchResult, error)
	// RemoveMembers 批量移除成员（原子；敏感操作）。
	RemoveMembers(ctx context.Context, req RBACGroupMemberBatchRequest) (RBACGroupMemberBatchResult, error)
}

// RBACCreateGroupRequest 是创建用户组请求。
type RBACCreateGroupRequest struct {
	Caller      AdminCaller
	ScopeID     string
	Key         string
	Name        string
	Description string
	RequestID   string
}

// RBACGroupRequest 是按组 ID 的只读/删除请求。
type RBACGroupRequest struct {
	Caller    AdminCaller
	GroupID   string
	RequestID string
}

// RBACUpdateGroupRequest 是用户组资料更新请求。
type RBACUpdateGroupRequest struct {
	Caller      AdminCaller
	GroupID     string
	Name        string
	Description string
	RequestID   string
}

// RBACGroupMemberBatchRequest 是组成员批量变更请求（原子）。
type RBACGroupMemberBatchRequest struct {
	Caller    AdminCaller
	GroupID   string
	UserIDs   []string
	Password  string
	TOTPCode  string
	RequestID string
}

// RBACGroupMemberBatchResult 是原子批量结果：失败时不返回部分成功。
type RBACGroupMemberBatchResult struct {
	Added   int
	Removed int
	Skipped int
}

// Groups 返回用户组服务。
func (f *rbacFacade) Groups() RBACGroupService { return &rbacGroupFacade{f: f} }

type rbacGroupFacade struct{ f *rbacFacade }

// Create 创建用户组。
func (s *rbacGroupFacade) Create(ctx context.Context, req RBACCreateGroupRequest) (RBACGroup, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return RBACGroup{}, err
	}
	managed := s.f.r.managedServices()
	if managed == nil || managed.Group == nil {
		return RBACGroup{}, call.configError("用户组服务未装配")
	}
	caller, err := s.f.groupCaller(call)
	if err != nil {
		return RBACGroup{}, err
	}
	value, err := managed.Group.CreateGroup(ctx, caller, group.CreateRequest{
		ScopeID: req.ScopeID, GroupKey: req.Key, Name: req.Name, Description: req.Description})
	if err != nil {
		return RBACGroup{}, call.domainError("创建用户组失败", string(group.CodeOf(err)))
	}
	return rbacGroup(value), nil
}

// Get 读取用户组。
func (s *rbacGroupFacade) Get(ctx context.Context, req RBACGroupRequest) (RBACGroup, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return RBACGroup{}, err
	}
	managed := s.f.r.managedServices()
	if managed == nil || managed.Group == nil {
		return RBACGroup{}, call.configError("用户组服务未装配")
	}
	caller, err := s.f.groupCaller(call)
	if err != nil {
		return RBACGroup{}, err
	}
	value, err := managed.Group.GetGroup(ctx, caller, req.GroupID)
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, group.ErrGroupNotFound, "group"); ok {
			return RBACGroup{}, replaced
		}
		return RBACGroup{}, call.domainError("读取用户组失败", string(group.CodeOf(err)))
	}
	return rbacGroup(value), nil
}

// Update 更新用户组资料。
func (s *rbacGroupFacade) Update(ctx context.Context, req RBACUpdateGroupRequest) (RBACGroup, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return RBACGroup{}, err
	}
	managed := s.f.r.managedServices()
	if managed == nil || managed.Group == nil {
		return RBACGroup{}, call.configError("用户组服务未装配")
	}
	caller, err := s.f.groupCaller(call)
	if err != nil {
		return RBACGroup{}, err
	}
	value, err := managed.Group.UpdateGroup(ctx, caller, req.GroupID,
		group.UpdateRequest{Name: req.Name, Description: req.Description})
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, group.ErrGroupNotFound, "group"); ok {
			return RBACGroup{}, replaced
		}
		return RBACGroup{}, call.domainError("更新用户组失败", string(group.CodeOf(err)))
	}
	return rbacGroup(value), nil
}

// Delete 删除用户组。
func (s *rbacGroupFacade) Delete(ctx context.Context, req RBACGroupRequest) error {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return err
	}
	managed := s.f.r.managedServices()
	if managed == nil || managed.Group == nil {
		return call.configError("用户组服务未装配")
	}
	caller, err := s.f.groupCaller(call)
	if err != nil {
		return err
	}
	if err := managed.Group.DeleteGroup(ctx, caller, req.GroupID); err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, group.ErrGroupNotFound, "group"); ok {
			return replaced
		}
		return call.domainError("删除用户组失败", string(group.CodeOf(err)))
	}
	return nil
}

// List 复用 AdminService 的分页实现（216/217 契约）。
func (s *rbacGroupFacade) List(ctx context.Context, req AdminListGroupsRequest) (AdminGroupList, error) {
	return s.f.admin.ListGroups(ctx, req)
}

// ListMembers 复用 AdminService 的分页实现。
func (s *rbacGroupFacade) ListMembers(ctx context.Context,
	req AdminListGroupMembersRequest) (AdminGroupMemberList, error) {
	return s.f.admin.ListGroupMembers(ctx, req)
}

// AddMembers 批量加入成员（敏感操作）。
func (s *rbacGroupFacade) AddMembers(ctx context.Context,
	req RBACGroupMemberBatchRequest) (RBACGroupMemberBatchResult, error) {
	return s.mutateMembers(ctx, req, true)
}

// RemoveMembers 批量移除成员（敏感操作）。
func (s *rbacGroupFacade) RemoveMembers(ctx context.Context,
	req RBACGroupMemberBatchRequest) (RBACGroupMemberBatchResult, error) {
	return s.mutateMembers(ctx, req, false)
}

func (s *rbacGroupFacade) mutateMembers(ctx context.Context,
	req RBACGroupMemberBatchRequest, add bool) (RBACGroupMemberBatchResult, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return RBACGroupMemberBatchResult{}, err
	}
	managed := s.f.r.managedServices()
	if managed == nil || managed.Group == nil {
		return RBACGroupMemberBatchResult{}, call.configError("用户组服务未装配")
	}
	caller, err := s.f.groupCaller(call)
	if err != nil {
		return RBACGroupMemberBatchResult{}, err
	}
	direction := "remove"
	if add {
		direction = "add"
	}
	approved, err := s.f.admin.sensitiveContext(ctx, call.identity, "group.member.change",
		"group", req.GroupID, map[string]string{"direction": direction}, req.Password,
		req.TOTPCode, call.requestID)
	if err != nil {
		return RBACGroupMemberBatchResult{}, err
	}
	batch := group.MemberBatchRequest{GroupID: req.GroupID, UserIDs: req.UserIDs}
	var result group.MemberBatchResult
	if add {
		result, err = managed.Group.AddMembers(approved, caller, batch)
	} else {
		result, err = managed.Group.RemoveMembers(approved, caller, batch)
	}
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, group.ErrGroupNotFound, "group"); ok {
			return RBACGroupMemberBatchResult{}, replaced
		}
		return RBACGroupMemberBatchResult{}, call.domainError("变更组成员失败", string(group.CodeOf(err)))
	}
	return RBACGroupMemberBatchResult{Added: result.Added, Removed: result.Removed,
		Skipped: result.Skipped}, nil
}
