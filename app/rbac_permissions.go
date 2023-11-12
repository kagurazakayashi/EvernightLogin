// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

import (
	"context"

	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
	"github.com/kagurazakayashi/EvernightLogin/internal/preset"
)

// RBACPermissionService 是权限目录生命周期与中文说明服务。
//
// 自定义权限只能写入明确 scope（system 或指定应用）：应用范围权限不能变成系统权限，
// 应用管理员不能创建 system/root_only 权限。内置权限不可删除、语义不可修改，只能按
// 规则停用；root_only 内置权限的停用/重启用仅受信本地初始化操作者可按领域规则执行。
type RBACPermissionService interface {
	// Create 登记自定义权限（复用既有 AdminCreatePermissionRequest 与领域校验）。
	Create(ctx context.Context, req AdminCreatePermissionRequest) (AdminPermission, error)
	// Get 按稳定权限 ID 读取完整视图。
	Get(ctx context.Context, req RBACPermissionRequest) (RBACPermission, error)
	// Update 更新名称/说明/明确限制；key/scope/builtin/root_only 不可变。
	Update(ctx context.Context, req RBACUpdatePermissionRequest) (RBACPermission, error)
	// Enable/Disable 启用/停用自定义或内置权限（内置保护与 root_only 规则由领域判定）。
	Enable(ctx context.Context, req RBACPermissionRequest) (RBACPermission, error)
	Disable(ctx context.Context, req RBACPermissionRequest) (RBACPermission, error)
	// Delete 删除自定义权限；内置权限与仍被角色引用的权限拒绝。
	Delete(ctx context.Context, req RBACPermissionRequest) error
	// List 分页读取权限目录（复用既有 AdminListPermissionsRequest）。
	List(ctx context.Context, req AdminListPermissionsRequest) (AdminPermissionList, error)
	// Catalog 返回版本化预设权限目录（中文“能做什么/生效范围/不能做什么”与
	// Implemented 真实标记）；不把目录里有键等同于已实现。
	Catalog(ctx context.Context, req RBACCatalogRequest) (RBACPresetCatalog, error)
}

// RBACPermissionRequest 是按权限 ID 的只读/启停/删除请求。
type RBACPermissionRequest struct {
	Caller       AdminCaller
	PermissionID string
	RequestID    string
}

// RBACUpdatePermissionRequest 是权限资料更新请求。
type RBACUpdatePermissionRequest struct {
	Caller       AdminCaller
	PermissionID string
	Name         string
	Description  string
	Limits       string
	RequestID    string
}

// RBACCatalogRequest 是只读预设目录请求（需要可信管理调用者）。
type RBACCatalogRequest struct {
	Caller    AdminCaller
	RequestID string
}

// RBACPresetPermission 是目录中的一条权限直白说明。
type RBACPresetPermission struct {
	Key            string
	Name           string
	Summary        string
	Scope          string
	Limits         string
	RequiresReauth bool
	RootOnly       bool
	DefaultRoles   []string
	// Implemented 表示对应业务操作是否已有真实执行路径；false 时不得声称已实现。
	Implemented bool
}

// RBACPresetCatalog 是预设目录的公开只读视图。
type RBACPresetCatalog struct {
	Version     string
	Permissions []RBACPresetPermission
}

// Permissions 返回权限服务。
func (f *rbacFacade) Permissions() RBACPermissionService { return &rbacPermissionFacade{f: f} }

type rbacPermissionFacade struct{ f *rbacFacade }

// Create 复用 AdminService 的权限登记实现。
func (s *rbacPermissionFacade) Create(ctx context.Context,
	req AdminCreatePermissionRequest) (AdminPermission, error) {
	return s.f.admin.CreatePermission(ctx, req)
}

// Get 读取权限完整视图。
func (s *rbacPermissionFacade) Get(ctx context.Context, req RBACPermissionRequest) (RBACPermission, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return RBACPermission{}, err
	}
	managed := s.f.r.managedServices()
	if managed == nil || managed.Permission == nil {
		return RBACPermission{}, call.configError("权限服务未装配")
	}
	caller, err := s.f.permissionCaller(call)
	if err != nil {
		return RBACPermission{}, err
	}
	value, err := managed.Permission.GetPermission(ctx, caller, req.PermissionID)
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, permission.ErrPermissionNotFound, "permission"); ok {
			return RBACPermission{}, replaced
		}
		return RBACPermission{}, call.domainError("读取权限失败", string(permission.CodeOf(err)))
	}
	return rbacPermission(value), nil
}

// Update 更新权限资料。
func (s *rbacPermissionFacade) Update(ctx context.Context,
	req RBACUpdatePermissionRequest) (RBACPermission, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return RBACPermission{}, err
	}
	managed := s.f.r.managedServices()
	if managed == nil || managed.Permission == nil {
		return RBACPermission{}, call.configError("权限服务未装配")
	}
	caller, err := s.f.permissionCaller(call)
	if err != nil {
		return RBACPermission{}, err
	}
	value, err := managed.Permission.UpdatePermission(ctx, caller, req.PermissionID,
		permission.UpdateRequest{Name: req.Name, Description: req.Description, Limits: req.Limits})
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, permission.ErrPermissionNotFound, "permission"); ok {
			return RBACPermission{}, replaced
		}
		return RBACPermission{}, call.domainError("更新权限失败", string(permission.CodeOf(err)))
	}
	return rbacPermission(value), nil
}

// Enable 启用权限。
func (s *rbacPermissionFacade) Enable(ctx context.Context, req RBACPermissionRequest) (RBACPermission, error) {
	return s.setState(ctx, req, true)
}

// Disable 停用权限。
func (s *rbacPermissionFacade) Disable(ctx context.Context, req RBACPermissionRequest) (RBACPermission, error) {
	return s.setState(ctx, req, false)
}

func (s *rbacPermissionFacade) setState(ctx context.Context,
	req RBACPermissionRequest, target bool) (RBACPermission, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return RBACPermission{}, err
	}
	managed := s.f.r.managedServices()
	if managed == nil || managed.Permission == nil {
		return RBACPermission{}, call.configError("权限服务未装配")
	}
	caller, err := s.f.permissionCaller(call)
	if err != nil {
		return RBACPermission{}, err
	}
	var value permission.Permission
	if target {
		value, _, err = managed.Permission.EnablePermission(ctx, caller, req.PermissionID)
	} else {
		value, _, err = managed.Permission.DisablePermission(ctx, caller, req.PermissionID)
	}
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, permission.ErrPermissionNotFound, "permission"); ok {
			return RBACPermission{}, replaced
		}
		return RBACPermission{}, call.domainError("变更权限状态失败", string(permission.CodeOf(err)))
	}
	return rbacPermission(value), nil
}

// Delete 删除自定义权限。
func (s *rbacPermissionFacade) Delete(ctx context.Context, req RBACPermissionRequest) error {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return err
	}
	managed := s.f.r.managedServices()
	if managed == nil || managed.Permission == nil {
		return call.configError("权限服务未装配")
	}
	caller, err := s.f.permissionCaller(call)
	if err != nil {
		return err
	}
	if err := managed.Permission.DeletePermission(ctx, caller, req.PermissionID); err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, permission.ErrPermissionNotFound, "permission"); ok {
			return replaced
		}
		return call.domainError("删除权限失败", string(permission.CodeOf(err)))
	}
	return nil
}

// List 复用 AdminService 的分页实现。
func (s *rbacPermissionFacade) List(ctx context.Context,
	req AdminListPermissionsRequest) (AdminPermissionList, error) {
	return s.f.admin.ListPermissions(ctx, req)
}

// Catalog 返回预设目录的公开只读视图（真实 Implemented 标记，不夸大实现状态）。
func (s *rbacPermissionFacade) Catalog(ctx context.Context, req RBACCatalogRequest) (RBACPresetCatalog, error) {
	if _, err := s.f.begin(ctx, req.Caller, req.RequestID); err != nil {
		return RBACPresetCatalog{}, err
	}
	catalog := preset.DefaultCatalog()
	if catalog == nil {
		return RBACPresetCatalog{}, configError("预设权限目录不可用")
	}
	entries := make([]RBACPresetPermission, 0, len(catalog.Permissions))
	for _, definition := range catalog.Permissions {
		entries = append(entries, RBACPresetPermission{
			Key: definition.Key, Name: definition.Name, Summary: definition.Summary,
			Scope: definition.Scope, Limits: definition.Limits,
			RequiresReauth: definition.RequiresReauth, RootOnly: definition.RootOnly,
			DefaultRoles: append([]string(nil), definition.DefaultRoles...),
			Implemented:  definition.Implemented,
		})
	}
	return RBACPresetCatalog{Version: catalog.Version, Permissions: entries}, nil
}
