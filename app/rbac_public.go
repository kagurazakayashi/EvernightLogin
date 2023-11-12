// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

// 角色 / 用户组 / 权限管理公开 Go 接口（步骤 224）。
//
// 设计边界：
//   - 只复用 internal/role、group、permission、authz、delegation、preset 的真实服务
//     （状态机、委派 Guard、再次认证、root 保护、内置保护、关键审计与事务回滚），
//     不复制第二套业务逻辑；既有 AdminService 保留兼容，本文件新增分组 RBAC 表面。
//   - 身份只来自 AdminCaller：LocalAdmin 是宿主进程可信操作者；AdminSession 是真实
//     完整用户会话（受限会话在解析阶段拒绝）。领域服务在事务内复核权限与可委派范围。
//   - 列表复用既有 AdminPage/AdminList*（216/217），有界遍历复用 IterateAdminPages（220）；
//     RBAC 不再另造分页/迭代契约。
//   - 本文件只新增文件，不编辑 runtime.go/admin.go/types.go；Runtime 方法在同包新文件
//     定义是 Go 允许的，避免并行步骤写冲突。

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
)

// RBACService 是分组清楚的 RBAC 公开服务入口。
type RBACService interface {
	// Roles 返回角色生命周期、权限组合与分配服务。
	Roles() RBACRoleService
	// Groups 返回用户组与组成员批量变更服务。
	Groups() RBACGroupService
	// Permissions 返回权限目录生命周期与中文说明服务。
	Permissions() RBACPermissionService
	// Authorization 返回有效权限/来源/资源级授权查询服务。
	Authorization() RBACAuthorizationService
	// Delegations 返回可转授资格管理（只给出“可转授上限”，不授予系统资格）。
	Delegations() RBACDelegationService
	// Presets 返回预设目录与恢复服务；恢复只接受 LocalAdmin（普通管理会话拒绝）。
	Presets() RBACPresetService
}

// RBAC 返回分组 RBAC 公开服务。方法定义在新文件而不是 runtime.go，避免并行写冲突。
func (r *Runtime) RBAC() RBACService {
	return &rbacFacade{r: r, admin: &adminFacade{r: r}}
}

// rbacFacade 是 RBAC 公开服务实现；复用 adminFacade 的身份解析、敏感操作与错误映射，
// 保持与既有管理入口完全相同的安全语义。
type rbacFacade struct {
	r     *Runtime
	admin *adminFacade
}

// begin 统一解析请求编号与可信调用者（与 AdminService 同一实现）。
func (f *rbacFacade) begin(ctx context.Context, caller AdminCaller,
	requestID string) (adminRequest, error) {
	return f.admin.begin(ctx, caller, requestID)
}

// roleCaller 构造带请求编号的角色服务调用者。
func (f *rbacFacade) roleCaller(call adminRequest) (role.Caller, error) {
	caller, err := f.admin.roleCaller(call.identity)
	if err != nil {
		return role.Caller{}, call.configError("角色服务调用者无效")
	}
	return bindCaller(caller, call.requestID)
}

// groupCaller 构造带请求编号的用户组服务调用者。
func (f *rbacFacade) groupCaller(call adminRequest) (group.Caller, error) {
	caller, err := f.admin.groupCaller(call.identity)
	if err != nil {
		return group.Caller{}, call.configError("用户组服务调用者无效")
	}
	return bindCaller(caller, call.requestID)
}

// permissionCaller 构造带请求编号的权限服务调用者。
func (f *rbacFacade) permissionCaller(call adminRequest) (permission.Caller, error) {
	caller, err := f.admin.permissionCaller(call.identity)
	if err != nil {
		return permission.Caller{}, call.configError("权限服务调用者无效")
	}
	return bindCaller(caller, call.requestID)
}

// RBACRole 是角色完整视图（含直白说明/明确限制/内置与启停状态）。
type RBACRole struct {
	ID            string
	ScopeID       string
	ApplicationID string
	Key           string
	Name          string
	Description   string
	Limits        string
	IsBuiltin     bool
	Enabled       bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// rbacRole 把内部角色记录投影为公开视图。
func rbacRole(value role.Role) RBACRole {
	return RBACRole{ID: value.ID, ScopeID: value.ScopeID, ApplicationID: value.ApplicationID,
		Key: value.Key, Name: value.Name, Description: value.Description,
		Limits: value.Limits, IsBuiltin: value.IsBuiltin, Enabled: value.Enabled,
		CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt}
}

// RBACGroup 是用户组完整视图。
type RBACGroup struct {
	ID            string
	ScopeID       string
	ApplicationID string
	Key           string
	Name          string
	Description   string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// rbacGroup 把内部用户组记录投影为公开视图。
func rbacGroup(value group.Group) RBACGroup {
	return RBACGroup{ID: value.ID, ScopeID: value.ScopeID, ApplicationID: value.ApplicationID,
		Key: value.GroupKey, Name: value.Name, Description: value.Description,
		CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt}
}

// RBACPermission 是权限完整视图（含中文说明/范围/内置与 root_only 标记）。
type RBACPermission struct {
	ID            string
	ScopeID       string
	ApplicationID string
	Key           string
	Name          string
	Description   string
	Limits        string
	IsBuiltin     bool
	RootOnly      bool
	Enabled       bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// rbacPermission 把内部权限记录投影为公开视图。
func rbacPermission(value permission.Permission) RBACPermission {
	return RBACPermission{ID: value.ID, ScopeID: value.ScopeID, ApplicationID: value.ApplicationID,
		Key: value.Key, Name: value.Name, Description: value.Description, Limits: value.Limits,
		IsBuiltin: value.IsBuiltin, RootOnly: value.RootOnly, Enabled: value.Enabled,
		CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt}
}
