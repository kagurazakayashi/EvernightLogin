package managedapi

// 步骤 148：应用范围组/角色/权限的受控写操作。所有操作在既有 group/role/permission
// 服务中执行；scope 固定为当前应用，builtin/root_only 由服务层与请求构造强制拒绝，
// 委派 Guard 由宿主注入的生产 Guard 判定（147/148 专用服务实例）。

import (
	"context"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
)

// CreateGroupRequest 创建应用用户组；scope 由服务端固定，group_key 不可跨应用。
type CreateGroupRequest struct {
	Meta
	GroupKey    string
	Name        string
	Description string
}

// UpdateGroupRequest 更新用户组名称/说明。
type UpdateGroupRequest struct {
	Meta
	GroupID     string
	Name        string
	Description string
}

// DeleteGroupRequest 删除用户组（不删除用户/审计）。
type DeleteGroupRequest struct {
	Meta
	GroupID string
}

// CreateRoleRequest 创建应用角色；IsBuiltin 由传输层强制 false。
type CreateRoleRequest struct {
	Meta
	Key         string
	Name        string
	Description string
	Limits      string
}

// UpdateRoleRequest 更新角色名称/说明/限制。
type UpdateRoleRequest struct {
	Meta
	RoleID      string
	Name        string
	Description string
	Limits      string
}

// DeleteRoleRequest 删除应用角色；内置角色由领域服务拒绝。
type DeleteRoleRequest struct {
	Meta
	RoleID string
}

// CreatePermissionRequest 创建应用自定义权限；root_only/is_builtin 强制 false。
type CreatePermissionRequest struct {
	Meta
	Key         string
	Name        string
	Description string
	Limits      string
}

// UpdatePermissionRequest 更新权限名称/说明/限制。
type UpdatePermissionRequest struct {
	Meta
	PermissionID string
	Name         string
	Description  string
	Limits       string
}

// PermissionActionRequest 启用/停用/删除应用权限。
type PermissionActionRequest struct {
	Meta
	PermissionID string
}

// CreateGroup 创建本应用用户组。
func (s *Service) CreateGroup(ctx context.Context, principal Principal,
	request CreateGroupRequest) (View, error) {
	ctx = normalizeContext(ctx)
	value, err := s.execute(ctx, principal, request.Meta, OpGroupsCreate, ObjectGroup, "",
		func(grantCtx context.Context, state resolved) (any, error) {
			if err := checkWriteFields(state, ObjectGroup, map[string]bool{
				"key": request.GroupKey != "", "name": request.Name != "",
				"description": request.Description != "",
			}); err != nil {
				return nil, err
			}
			caller, callerErr := s.groupCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			record, createErr := s.opts.Group.CreateGroup(grantCtx, caller, group.CreateRequest{
				ScopeID: state.appID, GroupKey: request.GroupKey, Name: request.Name,
				Description: request.Description})
			if createErr != nil {
				return nil, createErr
			}
			return ProjectGroup(state.policy, record), nil
		})
	if err != nil {
		return View{}, err
	}
	return value.(View), nil
}

// UpdateGroup 更新本应用用户组名称/说明。
func (s *Service) UpdateGroup(ctx context.Context, principal Principal,
	request UpdateGroupRequest) (View, error) {
	ctx = normalizeContext(ctx)
	value, err := s.execute(ctx, principal, request.Meta, OpGroupsUpdate, ObjectGroup,
		request.GroupID, func(grantCtx context.Context, state resolved) (any, error) {
			if err := s.requireObject(state, ObjectGroup, request.GroupID); err != nil {
				return nil, err
			}
			if err := checkWriteFields(state, ObjectGroup, map[string]bool{
				"name": request.Name != "", "description": request.Description != "",
			}); err != nil {
				return nil, err
			}
			caller, callerErr := s.groupCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			record, updateErr := s.opts.Group.UpdateGroup(grantCtx, caller, request.GroupID,
				group.UpdateRequest{Name: request.Name, Description: request.Description})
			if updateErr != nil {
				return nil, updateErr
			}
			return ProjectGroup(state.policy, record), nil
		})
	if err != nil {
		return View{}, err
	}
	return value.(View), nil
}

// DeleteGroup 删除本应用用户组。
func (s *Service) DeleteGroup(ctx context.Context, principal Principal,
	request DeleteGroupRequest) error {
	ctx = normalizeContext(ctx)
	_, err := s.execute(ctx, principal, request.Meta, OpGroupsDelete, ObjectGroup,
		request.GroupID, func(grantCtx context.Context, state resolved) (any, error) {
			if err := s.requireObject(state, ObjectGroup, request.GroupID); err != nil {
				return nil, err
			}
			caller, callerErr := s.groupCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			return nil, s.opts.Group.DeleteGroup(grantCtx, caller, request.GroupID)
		})
	return err
}

// CreateRole 创建本应用角色；创建请求里 IsBuiltin 固定 false。
func (s *Service) CreateRole(ctx context.Context, principal Principal,
	request CreateRoleRequest) (View, error) {
	ctx = normalizeContext(ctx)
	value, err := s.execute(ctx, principal, request.Meta, OpRolesCreate, ObjectRole, "",
		func(grantCtx context.Context, state resolved) (any, error) {
			if err := checkWriteFields(state, ObjectRole, map[string]bool{
				"key": request.Key != "", "name": request.Name != "",
				"description": request.Description != "", "limits": request.Limits != "",
			}); err != nil {
				return nil, err
			}
			caller, callerErr := s.roleCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			record, createErr := s.opts.Role.CreateRole(grantCtx, caller, role.CreateRequest{
				ScopeID: state.appID, Key: request.Key, Name: request.Name,
				Description: request.Description, Limits: request.Limits, IsBuiltin: false})
			if createErr != nil {
				return nil, createErr
			}
			return ProjectRole(state.policy, record), nil
		})
	if err != nil {
		return View{}, err
	}
	return value.(View), nil
}

// UpdateRole 更新本应用角色资料（不能改 scope/builtin/key）。
func (s *Service) UpdateRole(ctx context.Context, principal Principal,
	request UpdateRoleRequest) (View, error) {
	ctx = normalizeContext(ctx)
	value, err := s.execute(ctx, principal, request.Meta, OpRolesUpdate, ObjectRole,
		request.RoleID, func(grantCtx context.Context, state resolved) (any, error) {
			if err := s.requireObject(state, ObjectRole, request.RoleID); err != nil {
				return nil, err
			}
			if err := checkWriteFields(state, ObjectRole, map[string]bool{
				"name": request.Name != "", "description": request.Description != "",
				"limits": request.Limits != "",
			}); err != nil {
				return nil, err
			}
			caller, callerErr := s.roleCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			record, updateErr := s.opts.Role.UpdateRole(grantCtx, caller, request.RoleID,
				role.UpdateRequest{Name: request.Name, Description: request.Description,
					Limits: request.Limits})
			if updateErr != nil {
				return nil, updateErr
			}
			return ProjectRole(state.policy, record), nil
		})
	if err != nil {
		return View{}, err
	}
	return value.(View), nil
}

// DeleteRole 删除本应用角色；内置角色由领域服务拒绝。
func (s *Service) DeleteRole(ctx context.Context, principal Principal,
	request DeleteRoleRequest) error {
	ctx = normalizeContext(ctx)
	_, err := s.execute(ctx, principal, request.Meta, OpRolesDelete, ObjectRole,
		request.RoleID, func(grantCtx context.Context, state resolved) (any, error) {
			if err := s.requireObject(state, ObjectRole, request.RoleID); err != nil {
				return nil, err
			}
			caller, callerErr := s.roleCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			return nil, s.opts.Role.DeleteRole(grantCtx, caller, request.RoleID)
		})
	return err
}

// CreatePermission 创建本应用自定义权限；root_only/is_builtin 固定 false。
func (s *Service) CreatePermission(ctx context.Context, principal Principal,
	request CreatePermissionRequest) (View, error) {
	ctx = normalizeContext(ctx)
	value, err := s.execute(ctx, principal, request.Meta, OpPermissionsCreate,
		ObjectPermission, "", func(grantCtx context.Context, state resolved) (any, error) {
			if err := checkWriteFields(state, ObjectPermission, map[string]bool{
				"key": request.Key != "", "name": request.Name != "",
				"description": request.Description != "", "limits": request.Limits != "",
			}); err != nil {
				return nil, err
			}
			caller, callerErr := s.permissionCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			record, createErr := s.opts.Permission.CreatePermission(grantCtx, caller,
				permission.CreateRequest{ScopeID: state.appID, Key: request.Key,
					Name: request.Name, Description: request.Description,
					Limits: request.Limits, RootOnly: false, IsBuiltin: false})
			if createErr != nil {
				return nil, createErr
			}
			return ProjectPermission(state.policy, record), nil
		})
	if err != nil {
		return View{}, err
	}
	return value.(View), nil
}

// UpdatePermission 更新本应用权限资料（不能改 key/scope/builtin/root_only）。
func (s *Service) UpdatePermission(ctx context.Context, principal Principal,
	request UpdatePermissionRequest) (View, error) {
	ctx = normalizeContext(ctx)
	value, err := s.execute(ctx, principal, request.Meta, OpPermissionsUpdate,
		ObjectPermission, request.PermissionID,
		func(grantCtx context.Context, state resolved) (any, error) {
			if err := s.requireObject(state, ObjectPermission, request.PermissionID); err != nil {
				return nil, err
			}
			if err := checkWriteFields(state, ObjectPermission, map[string]bool{
				"name": request.Name != "", "description": request.Description != "",
				"limits": request.Limits != "",
			}); err != nil {
				return nil, err
			}
			caller, callerErr := s.permissionCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			record, updateErr := s.opts.Permission.UpdatePermission(grantCtx, caller,
				request.PermissionID, permission.UpdateRequest{Name: request.Name,
					Description: request.Description, Limits: request.Limits})
			if updateErr != nil {
				return nil, updateErr
			}
			return ProjectPermission(state.policy, record), nil
		})
	if err != nil {
		return View{}, err
	}
	return value.(View), nil
}

// SetPermissionEnabled 启用/停用本应用权限。
func (s *Service) SetPermissionEnabled(ctx context.Context, principal Principal,
	request PermissionActionRequest, enable bool) (View, error) {
	ctx = normalizeContext(ctx)
	opID := OpPermissionsDisable
	if enable {
		opID = OpPermissionsEnable
	}
	value, err := s.execute(ctx, principal, request.Meta, opID, ObjectPermission,
		request.PermissionID, func(grantCtx context.Context, state resolved) (any, error) {
			if err := s.requireObject(state, ObjectPermission, request.PermissionID); err != nil {
				return nil, err
			}
			caller, callerErr := s.permissionCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			var (
				record permission.Permission
				opErr  error
			)
			if enable {
				record, _, opErr = s.opts.Permission.EnablePermission(grantCtx, caller,
					request.PermissionID)
			} else {
				record, _, opErr = s.opts.Permission.DisablePermission(grantCtx, caller,
					request.PermissionID)
			}
			if opErr != nil {
				return nil, opErr
			}
			return ProjectPermission(state.policy, record), nil
		})
	if err != nil {
		return View{}, err
	}
	return value.(View), nil
}

// DeletePermission 删除本应用权限；内置/系统权限由领域服务拒绝。
func (s *Service) DeletePermission(ctx context.Context, principal Principal,
	request PermissionActionRequest) error {
	ctx = normalizeContext(ctx)
	_, err := s.execute(ctx, principal, request.Meta, OpPermissionsDelete,
		ObjectPermission, request.PermissionID,
		func(grantCtx context.Context, state resolved) (any, error) {
			if err := s.requireObject(state, ObjectPermission, request.PermissionID); err != nil {
				return nil, err
			}
			caller, callerErr := s.permissionCaller(state)
			if callerErr != nil {
				return nil, callerErr
			}
			return nil, s.opts.Permission.DeletePermission(grantCtx, caller,
				request.PermissionID)
		})
	return err
}
