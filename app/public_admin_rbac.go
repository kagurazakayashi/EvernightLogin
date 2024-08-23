package app

import (
	"time"
)

// AdminRole 是角色登记信息。
type AdminRole struct {
	ID            string
	ScopeID       string
	ApplicationID string
	Key           string
	Name          string
	Enabled       bool
}

// AdminPermission 是权限目录条目视图。
type AdminPermission struct {
	ID       string
	ScopeID  string
	Key      string
	Name     string
	Enabled  bool
	RootOnly bool
}

// AdminRoleRequest 读取角色权限组合。RequestID 用于关联调用、领域审计与返回
// 错误；空编号统一生成，非法编号拒绝。
type AdminRoleRequest struct {
	Caller    AdminCaller
	RoleID    string
	RequestID string
}

// AdminRolePermissionRequest 向角色添加权限（敏感操作：真实再次认证或本机受信
// 操作者确认；委派资格在服务事务内复核）。
type AdminRolePermissionRequest struct {
	Caller       AdminCaller
	RoleID       string
	PermissionID string
	// Password/TOTPCode 只用于用户主体的近期再次认证；不会被保存或记录。
	Password  string
	TOTPCode  string
	RequestID string
}

// GrantRoleRequest 把角色分配给用户（敏感操作；应用角色要求目标用户是该应用
// active 成员，且操作者当前持有被转授的全部权限）。
type GrantRoleRequest struct {
	Caller AdminCaller
	UserID string
	RoleID string
	// Password/TOTPCode 只用于用户主体的近期再次认证；不会被保存或记录。
	Password  string
	TOTPCode  string
	RequestID string
}

// RevokeRoleRequest 撤回用户的角色分配（安全清理，允许对已停用角色/账户执行）。
type RevokeRoleRequest struct {
	Caller    AdminCaller
	UserID    string
	RoleID    string
	RequestID string
}

// AdminPermissionQuery 查询某用户在指定范围（"system" 或应用 ID）的有效权限。
// RequestID 用于关联调用、领域审计与返回错误；空编号统一生成，非法编号拒绝。
type AdminPermissionQuery struct {
	Caller    AdminCaller
	UserID    string
	ScopeID   string
	Limit     int
	Offset    int
	RequestID string
}

// AdminEffectivePermissions 是有效权限查询结果；DeniedCode 非空表示查询被状态
// 或授权拒绝。
type AdminEffectivePermissions struct {
	UserID      string
	ScopeID     string
	Permissions []AdminPermission
	DeniedCode  string
}

// AdminPermissionCheck 对某用户执行一次联合权限检查（权限键 + 范围 + all/any）。
// RequestID 用于关联调用、领域审计与返回错误；空编号统一生成，非法编号拒绝。
type AdminPermissionCheck struct {
	Caller     AdminCaller
	UserID     string
	ScopeID    string
	Permission string
	Mode       string
	RequestID  string
}

// AdminPermissionDecision 是联合权限检查结果；拒绝时给出稳定码与原因。
type AdminPermissionDecision struct {
	Allowed bool
	Code    string
	Reason  string
}

// AdminDelegationGrantRequest 为本机受信操作者签发“可转授资格”：只有受信本地/
// 系统通道能签发；用户主体不能给自己或他人签发委派资格。签发只代表“可转授能力
// 上限”，实际转授仍要求操作者当前持有该权限并经委派引擎事务内复核。
type AdminDelegationGrantRequest struct {
	Caller          AdminCaller
	DelegatorUserID string
	ScopeID         string
	PermissionKey   string
	// MaxDataScope 是允许转授的数据范围上限（JSON，空表示 all）。
	MaxDataScope string
	RequestID    string
}

// AdminDelegation 是已签发的委派资格视图。
type AdminDelegation struct {
	ID              string
	DelegatorUserID string
	ScopeID         string
	PermissionKey   string
	GrantedBy       string
}

// AdminGroup 是用户组列表的管理视图（不含成员明细）。
type AdminGroup struct {
	ID            string
	ScopeID       string
	ApplicationID string
	Key           string
	Name          string
	Description   string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// AdminListGroupsRequest 分页查询用户组（作用范围筛选 + 白名单排序）。
// Sort 允许值："created_at"（默认）、"updated_at"、"name"、"key"；空字符串用默认值。
type AdminListGroupsRequest struct {
	Caller     AdminCaller
	ScopeID    string
	Sort       string
	Descending bool
	Page       AdminPage
	RequestID  string
}

// AdminGroupList 是用户组列表结果。
type AdminGroupList struct {
	Groups  []AdminGroup
	HasMore bool
	Page    AdminPageInfo
}

// AdminGroupMember 是用户组成员的管理视图：只包含稳定用户 ID、作用域与加入时间，
// 不携带邮箱、昵称等资料，避免成员列表成为跨域资料读取旁路。
type AdminGroupMember struct {
	GroupID  string
	UserID   string
	JoinedAt time.Time
}

// AdminListGroupMembersRequest 分页查询组成员。
// Sort 允许值："joined_at"（默认）、"user_id"。
type AdminListGroupMembersRequest struct {
	Caller     AdminCaller
	GroupID    string
	Sort       string
	Descending bool
	Page       AdminPage
	RequestID  string
}

// AdminGroupMemberList 是组成员列表结果。
type AdminGroupMemberList struct {
	Members []AdminGroupMember
	HasMore bool
	Page    AdminPageInfo
}

// AdminListRolesRequest 分页查询角色（作用范围/启停/内置筛选 + 白名单排序）。
// Sort 允许值："created_at"（默认）、"updated_at"、"name"、"key"。
type AdminListRolesRequest struct {
	Caller     AdminCaller
	ScopeID    string
	Enabled    *bool
	Builtin    *bool
	Sort       string
	Descending bool
	Page       AdminPage
	RequestID  string
}

// AdminRoleList 是角色列表结果。
type AdminRoleList struct {
	Roles   []AdminRole
	HasMore bool
	Page    AdminPageInfo
}

// AdminPermissionList 是权限目录列表结果。
type AdminPermissionList struct {
	Permissions []AdminPermission
	HasMore     bool
	Page        AdminPageInfo
}

// AdminRoleUserAssignment 是角色的用户分配（数据范围为受控字符串）。
type AdminRoleUserAssignment struct {
	UserID     string
	ScopeID    string
	DataScope  string
	AssignedBy string
	AssignedAt time.Time
}

// AdminRoleGroupAssignment 是角色的用户组分配。
type AdminRoleGroupAssignment struct {
	GroupID    string
	ScopeID    string
	DataScope  string
	AssignedAt time.Time
}

// AdminListRoleAssignmentsRequest 分页查询角色的用户/组分配；两类分配各自分页。
// Sort 允许值："created_at"（默认）、"target_id"。
type AdminListRoleAssignmentsRequest struct {
	Caller     AdminCaller
	RoleID     string
	UserPage   AdminPage
	GroupPage  AdminPage
	Sort       string
	Descending bool
	RequestID  string
}

// AdminRoleAssignmentList 是角色分配的分页结果。
type AdminRoleAssignmentList struct {
	Users         []AdminRoleUserAssignment
	UsersHasMore  bool
	UserPage      AdminPageInfo
	Groups        []AdminRoleGroupAssignment
	GroupsHasMore bool
	GroupPage     AdminPageInfo
}
