package app

import (
	"time"
)

// AdminApplication 是应用登记信息（不含客户端秘密）。
type AdminApplication struct {
	ID          string
	Name        string
	Description string
	OwnerUserID string
	Status      string
	RowVersion  int64
	CreatedAt   time.Time
}

// AdminCreateApplicationRequest 登记应用（应用范围容器）。本机受信操作者可引导
// 创建；用户主体需要系统范围 applications.create。ClientType 为空时使用
// confidential；创建后的应用默认停用，需要显式启用。
type AdminCreateApplicationRequest struct {
	Caller      AdminCaller
	Name        string
	Description string
	OwnerUserID string
	// ClientType 是 "public"（公开客户端，不保存密钥）或 "confidential"（服务端）。
	ClientType string
	RequestID  string
}

// AdminApplicationRequest 读取/操作单个应用。
type AdminApplicationRequest struct {
	Caller        AdminCaller
	ApplicationID string
	RequestID     string
}

// AdminSetApplicationEnabledRequest 启用或停用应用（启用会恢复其范围权限，由应用
// 服务按真实委派资格复核）。
type AdminSetApplicationEnabledRequest struct {
	Caller             AdminCaller
	ApplicationID      string
	Enabled            bool
	ExpectedRowVersion int64
	RequestID          string
}

// AdminListApplicationsRequest 分页查询应用列表（状态筛选 + 白名单排序，步骤 217）。
// Sort 允许值："created_at"（默认）、"updated_at"、"name"、"id"；IncludeDeleted 为
// true 时同时返回已逻辑删除应用（审计查看）。应用管理员只能看到被分配应用，范围由
// 领域服务先于分页判定，不能靠参数扩大。
type AdminListApplicationsRequest struct {
	Caller         AdminCaller
	Status         string
	IncludeDeleted bool
	Sort           string
	Descending     bool
	Page           AdminPage
	// Search 是可选的字面子串搜索（应用名称/描述；空不过滤）。
	Search       string
	SearchFields []string
	RequestID    string
}

// AdminApplicationList 是应用列表结果。
type AdminApplicationList struct {
	Applications []AdminApplication
	HasMore      bool
	Page         AdminPageInfo
}

// AdminApplicationMember 是应用成员的管理视图：只包含本应用成员关系字段，不含
// 令牌、客户端秘密或其他应用的成员/资料。
type AdminApplicationMember struct {
	ApplicationID string
	UserID        string
	Status        string
	RowVersion    int64
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// AdminListApplicationMembersRequest 分页查询应用成员（状态筛选 + 白名单排序）。
// Sort 允许值："created_at"（默认）、"updated_at"、"user_id"；Status 为空表示不过滤。
// 授权与应用范围由应用服务先于分页判定；一个用户属于两个应用时只返回目标应用的记录。
type AdminListApplicationMembersRequest struct {
	Caller        AdminCaller
	ApplicationID string
	Status        string
	Sort          string
	Descending    bool
	// Search 是可选的字面子串搜索（空表示不过滤）：只在目标应用成员范围内按成员的
	// 全局账户用户名/昵称匹配，不能跨应用枚举；应用内 profile 显示名不参与搜索。
	Search string
	// SearchFields 是可选的搜索字段白名单（"username"/"nickname"）；为空使用默认
	// 两个字段；邮箱/电话需要独立字段可见权限，当前未提供且会被拒绝。
	SearchFields []string
	Page         AdminPage
	RequestID    string
}

// AdminApplicationMemberList 是应用成员列表结果。
type AdminApplicationMemberList struct {
	Members []AdminApplicationMember
	HasMore bool
	Page    AdminPageInfo
}

// AdminListApplicationRolesRequest 分页查询某个应用范围的角色（步骤 217）。
// 作用范围固定为请求的 ApplicationID，调用方不能借此读取其他应用角色；
// Sort 允许值："created_at"（默认）、"updated_at"、"name"、"key"。
type AdminListApplicationRolesRequest struct {
	Caller        AdminCaller
	ApplicationID string
	Enabled       *bool
	Builtin       *bool
	Sort          string
	Descending    bool
	Page          AdminPage
	RequestID     string
}

// AdminListApplicationGroupsRequest 分页查询某个应用范围的用户组（步骤 217）。
// 作用范围固定为请求的 ApplicationID；Sort 允许值："created_at"（默认）、
// "updated_at"、"name"、"key"。
type AdminListApplicationGroupsRequest struct {
	Caller        AdminCaller
	ApplicationID string
	Sort          string
	Descending    bool
	Page          AdminPage
	RequestID     string
}

// AdminAddMemberRequest 把已有用户加入应用（应用成员关系，不授予角色权限）。
type AdminAddMemberRequest struct {
	Caller        AdminCaller
	ApplicationID string
	UserID        string
	RequestID     string
}
