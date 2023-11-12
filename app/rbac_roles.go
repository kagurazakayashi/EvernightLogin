// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

import (
	"context"

	"github.com/kagurazakayashi/EvernightLogin/internal/role"
)

// RBACRoleService 是角色生命周期、权限组合与分配服务。
//
// 敏感操作（权限组合增删、角色启停、用户/组角色分配）与既有 AdminService 使用同一
// 再次认证/委派 Guard：用户主体必须提供近期 Password（必要时 TOTPCode），本机受信
// 操作者按既有审计事实放行；领域服务在事务内复核“可转授范围”，不是只保护分配动作。
type RBACRoleService interface {
	// Create 在系统或应用范围登记角色（创建不授予权限，不自动分配）。
	Create(ctx context.Context, req AdminCreateRoleRequest) (AdminRole, error)
	// Get 按稳定角色 ID 读取完整视图；已授权但不存在返回 NOT_FOUND。
	Get(ctx context.Context, req RBACRoleRequest) (RBACRole, error)
	// Update 更新名称/说明/明确限制；scope/key/builtin 不可变，内置角色拒绝。
	Update(ctx context.Context, req RBACUpdateRoleRequest) (RBACRole, error)
	// Enable/Disable 改变角色启停；启用会重新复核可转授范围。
	Enable(ctx context.Context, req RBACRoleStateRequest) (RBACRole, error)
	Disable(ctx context.Context, req RBACRoleStateRequest) (RBACRole, error)
	// Delete 删除自定义角色；内置角色与仍被引用的角色拒绝。
	Delete(ctx context.Context, req RBACRoleRequest) error
	// AddPermission 向角色组合权限（敏感操作；root_only 权限禁止组合）。
	AddPermission(ctx context.Context, req AdminRolePermissionRequest) error
	// RemovePermission 从角色移除权限（敏感操作；实际撤权立即生效）。
	RemovePermission(ctx context.Context, req RBACRolePermissionRemoveRequest) error
	// ListPermissions 分页前的角色权限组合读取（既有 AdminService 同一实现）。
	ListPermissions(ctx context.Context, req AdminRoleRequest) ([]AdminPermission, error)
	// List 分页读取角色（216 契约；复用既有 AdminListRolesRequest）。
	List(ctx context.Context, req AdminListRolesRequest) (AdminRoleList, error)
	// ListAssignments 分页读取角色的用户/组分配（两类各自分页）。
	ListAssignments(ctx context.Context, req AdminListRoleAssignmentsRequest) (AdminRoleAssignmentList, error)
	// AssignUser/RevokeUser 分配/撤销用户角色；root 目标拒绝，应用角色要求 active 成员。
	AssignUser(ctx context.Context, req GrantRoleRequest) error
	RevokeUser(ctx context.Context, req RevokeRoleRequest) error
	// AssignGroup/RevokeGroup 分配/撤销用户组角色（组内 root 间接赋权被拒绝）。
	AssignGroup(ctx context.Context, req RBACRoleGroupRequest) error
	RevokeGroup(ctx context.Context, req RBACRoleGroupRequest) error
}

// RBACRoleRequest 是按角色 ID 的只读/删除请求。
type RBACRoleRequest struct {
	Caller    AdminCaller
	RoleID    string
	RequestID string
}

// RBACUpdateRoleRequest 是角色资料更新白名单请求。
type RBACUpdateRoleRequest struct {
	Caller      AdminCaller
	RoleID      string
	Name        string
	Description string
	Limits      string
	RequestID   string
}

// RBACRoleStateRequest 是角色启停请求。
type RBACRoleStateRequest struct {
	Caller    AdminCaller
	RoleID    string
	RequestID string
}

// RBACRolePermissionRemoveRequest 是移除角色权限的敏感请求。
type RBACRolePermissionRemoveRequest struct {
	Caller       AdminCaller
	RoleID       string
	PermissionID string
	// Password/TOTPCode 只用于用户主体的近期再次认证，不保存、不记录。
	Password  string
	TOTPCode  string
	RequestID string
}

// RBACRoleGroupRequest 是用户组角色分配/撤销请求。
type RBACRoleGroupRequest struct {
	Caller    AdminCaller
	RoleID    string
	GroupID   string
	Password  string
	TOTPCode  string
	RequestID string
}

// Roles 返回角色服务。
func (f *rbacFacade) Roles() RBACRoleService { return &rbacRoleFacade{f: f} }

type rbacRoleFacade struct{ f *rbacFacade }

// Create 复用 AdminService 的创建实现（同一领域服务/审计/委派检查）。
func (s *rbacRoleFacade) Create(ctx context.Context, req AdminCreateRoleRequest) (AdminRole, error) {
	return s.f.admin.CreateRole(ctx, req)
}

// Get 读取角色完整视图。
func (s *rbacRoleFacade) Get(ctx context.Context, req RBACRoleRequest) (RBACRole, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return RBACRole{}, err
	}
	managed := s.f.r.managedServices()
	if managed == nil || managed.Role == nil {
		return RBACRole{}, call.configError("角色服务未装配")
	}
	caller, err := s.f.roleCaller(call)
	if err != nil {
		return RBACRole{}, err
	}
	value, err := managed.Role.GetRole(ctx, caller, req.RoleID)
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, role.ErrRoleNotFound, "role"); ok {
			return RBACRole{}, replaced
		}
		return RBACRole{}, call.roleError("读取角色失败", err)
	}
	return rbacRole(value), nil
}

// Update 更新角色资料。
func (s *rbacRoleFacade) Update(ctx context.Context, req RBACUpdateRoleRequest) (RBACRole, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return RBACRole{}, err
	}
	managed := s.f.r.managedServices()
	if managed == nil || managed.Role == nil {
		return RBACRole{}, call.configError("角色服务未装配")
	}
	caller, err := s.f.roleCaller(call)
	if err != nil {
		return RBACRole{}, err
	}
	value, err := managed.Role.UpdateRole(ctx, caller, req.RoleID, role.UpdateRequest{
		Name: req.Name, Description: req.Description, Limits: req.Limits})
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, role.ErrRoleNotFound, "role"); ok {
			return RBACRole{}, replaced
		}
		return RBACRole{}, call.roleError("更新角色失败", err)
	}
	return rbacRole(value), nil
}

// Enable 启用角色（敏感操作）。
func (s *rbacRoleFacade) Enable(ctx context.Context, req RBACRoleStateRequest) (RBACRole, error) {
	return s.setState(ctx, req, true)
}

// Disable 停用角色（敏感操作）。
func (s *rbacRoleFacade) Disable(ctx context.Context, req RBACRoleStateRequest) (RBACRole, error) {
	return s.setState(ctx, req, false)
}

func (s *rbacRoleFacade) setState(ctx context.Context, req RBACRoleStateRequest, target bool) (RBACRole, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return RBACRole{}, err
	}
	managed := s.f.r.managedServices()
	if managed == nil || managed.Role == nil {
		return RBACRole{}, call.configError("角色服务未装配")
	}
	caller, err := s.f.roleCaller(call)
	if err != nil {
		return RBACRole{}, err
	}
	direction := "disable"
	if target {
		direction = "enable"
	}
	approved, err := s.f.admin.sensitiveContext(ctx, call.identity, "role.state.change", "role",
		req.RoleID, map[string]string{"target": direction}, "", "", call.requestID)
	if err != nil {
		return RBACRole{}, err
	}
	var value role.Role
	if target {
		value, _, err = managed.Role.EnableRole(approved, caller, req.RoleID)
	} else {
		value, _, err = managed.Role.DisableRole(approved, caller, req.RoleID)
	}
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, role.ErrRoleNotFound, "role"); ok {
			return RBACRole{}, replaced
		}
		return RBACRole{}, call.roleError("变更角色状态失败", err)
	}
	return rbacRole(value), nil
}

// Delete 删除自定义角色。
func (s *rbacRoleFacade) Delete(ctx context.Context, req RBACRoleRequest) error {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return err
	}
	managed := s.f.r.managedServices()
	if managed == nil || managed.Role == nil {
		return call.configError("角色服务未装配")
	}
	caller, err := s.f.roleCaller(call)
	if err != nil {
		return err
	}
	if err := managed.Role.DeleteRole(ctx, caller, req.RoleID); err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, role.ErrRoleNotFound, "role"); ok {
			return replaced
		}
		return call.roleError("删除角色失败", err)
	}
	return nil
}

// AddPermission 复用 AdminService 的敏感组合实现。
func (s *rbacRoleFacade) AddPermission(ctx context.Context, req AdminRolePermissionRequest) error {
	return s.f.admin.AddRolePermission(ctx, req)
}

// RemovePermission 从角色移除权限（敏感操作）。
func (s *rbacRoleFacade) RemovePermission(ctx context.Context, req RBACRolePermissionRemoveRequest) error {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return err
	}
	managed := s.f.r.managedServices()
	if managed == nil || managed.Role == nil {
		return call.configError("角色服务未装配")
	}
	caller, err := s.f.roleCaller(call)
	if err != nil {
		return err
	}
	approved, err := s.f.admin.sensitiveContext(ctx, call.identity, "role.permission.change",
		"role", req.RoleID, map[string]string{"direction": "remove", "permission_id": req.PermissionID},
		req.Password, req.TOTPCode, call.requestID)
	if err != nil {
		return err
	}
	if _, err := managed.Role.RemoveRolePermission(approved, caller, req.RoleID, req.PermissionID); err != nil {
		return call.roleError("移除角色权限失败", err)
	}
	return nil
}

// ListPermissions 复用 AdminService 的只读实现。
func (s *rbacRoleFacade) ListPermissions(ctx context.Context, req AdminRoleRequest) ([]AdminPermission, error) {
	return s.f.admin.ListRolePermissions(ctx, req)
}

// List 复用 AdminService 的分页实现（216 契约）。
func (s *rbacRoleFacade) List(ctx context.Context, req AdminListRolesRequest) (AdminRoleList, error) {
	return s.f.admin.ListRoles(ctx, req)
}

// ListAssignments 复用 AdminService 的分页实现。
func (s *rbacRoleFacade) ListAssignments(ctx context.Context,
	req AdminListRoleAssignmentsRequest) (AdminRoleAssignmentList, error) {
	return s.f.admin.ListRoleAssignments(ctx, req)
}

// AssignUser 复用 AdminService 的敏感分配实现。
func (s *rbacRoleFacade) AssignUser(ctx context.Context, req GrantRoleRequest) error {
	return s.f.admin.GrantApplicationRole(ctx, req)
}

// RevokeUser 复用 AdminService 的撤销实现。
func (s *rbacRoleFacade) RevokeUser(ctx context.Context, req RevokeRoleRequest) error {
	return s.f.admin.RevokeApplicationRole(ctx, req)
}

// AssignGroup 分配用户组角色（敏感操作）。
func (s *rbacRoleFacade) AssignGroup(ctx context.Context, req RBACRoleGroupRequest) error {
	return s.setGroupRole(ctx, req, true)
}

// RevokeGroup 撤销用户组角色（安全清理，不改变其他角色/权限）。
func (s *rbacRoleFacade) RevokeGroup(ctx context.Context, req RBACRoleGroupRequest) error {
	return s.setGroupRole(ctx, req, false)
}

func (s *rbacRoleFacade) setGroupRole(ctx context.Context, req RBACRoleGroupRequest, assign bool) error {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return err
	}
	managed := s.f.r.managedServices()
	if managed == nil || managed.Role == nil {
		return call.configError("角色服务未装配")
	}
	caller, err := s.f.roleCaller(call)
	if err != nil {
		return err
	}
	if assign {
		approved, err := s.f.admin.sensitiveContext(ctx, call.identity, "permission.role.assign",
			"group", req.GroupID, map[string]string{"direction": "assign", "role_id": req.RoleID},
			req.Password, req.TOTPCode, call.requestID)
		if err != nil {
			return err
		}
		if _, err := managed.Role.AssignGroupRole(approved, caller, req.RoleID, req.GroupID); err != nil {
			return call.roleError("分配用户组角色失败", err)
		}
		return nil
	}
	if _, err := managed.Role.RevokeGroupRole(ctx, caller, req.RoleID, req.GroupID); err != nil {
		return call.roleError("撤销用户组角色失败", err)
	}
	return nil
}
