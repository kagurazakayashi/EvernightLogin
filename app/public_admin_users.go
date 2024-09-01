package app

import (
	"context"
	"time"
)

// AdminCaller 是可信管理调用者，只能由 Runtime 构造：
//   - Runtime.LocalAdmin()：本机受信操作者（app.Options.OperatorID），代表宿主进程
//     自己——部署管理员；审计主体为本地管理员，用于初始化/受控引导；
//   - Runtime.AdminSession(secret)：真实管理用户会话；一切操作按当前有效权限与
//     委派资格判定，敏感操作还需要近期再次认证。
//
// 零值或无主 AdminCaller 一律拒绝。它不是 is_root：不能把任意用户/请求标记成
// root，也不能跳过权限与委派检查（本机受信通道除外，其审计主体仍为本地管理员）。
type AdminCaller struct {
	runtime       *Runtime
	sessionSecret []byte
	local         bool
}

// AdminUser 是管理视图的脱敏用户记录。
type AdminUser struct {
	ID        string
	Username  string
	Nickname  string
	Status    string
	CreatedAt time.Time
}

// AdminUserProfile 是允许管理员读写的用户资料视图（不含密码、密钥、安全版本）。
type AdminUserProfile struct {
	UserID     string
	Username   string
	Nickname   string
	Biography  string
	Language   string
	Timezone   string
	IsRoot     bool
	RowVersion int64
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// AdminListUsersRequest 分页查询用户（状态筛选/受控排序）。
type AdminListUsersRequest struct {
	Caller     AdminCaller
	Limit      int
	Offset     int
	Status     string
	Sort       string
	Descending bool
	// Search 是可选的字面子串搜索（空表示不过滤，保持原列表）。默认匹配用户名与
	// 昵称（NFKC + 大小写折叠口径）；模糊搜索不参与登录/唯一身份判定。
	Search string
	// SearchFields 是可选的搜索字段白名单（"username"/"nickname"）；为空使用默认
	// 两个字段。未知字段（含邮箱/电话，需独立字段可见权限，当前未提供）返回
	// REQ_INVALID，不静默忽略。
	SearchFields []string
	RequestID    string
}

// AdminUserList 是用户列表结果。
type AdminUserList struct {
	Users   []AdminUser
	HasMore bool
	// Page 是统一分页元数据（默认值/非法输入语义见 AdminPage）。
	Page AdminPageInfo
}

// AdminUserByUsernameRequest 按用户名读取脱敏用户记录。
type AdminUserByUsernameRequest struct {
	Caller    AdminCaller
	Username  string
	RequestID string
}

// AdminCreateUserRequest 由管理门面创建全局账户（与 registration.enabled 无关）。
// ApplicationIDs 非空时同时建立这些应用的成员关系（需要各应用的成员管理权限）。
type AdminCreateUserRequest struct {
	Caller         AdminCaller
	Username       string
	Nickname       string
	Biography      string
	ApplicationIDs []string
	RequestID      string
}

// AdminUserRequest 读取用户资料。RequestID 用于关联调用、领域审计与返回错误：
// 空编号由门面统一生成一次，非法编号在查询前拒绝（REQ_INVALID）。
type AdminUserRequest struct {
	Caller    AdminCaller
	UserID    string
	RequestID string
}

// AdminUpdateProfileRequest 修改允许管理员改写的资料字段；nil 表示不修改。
type AdminUpdateProfileRequest struct {
	Caller             AdminCaller
	UserID             string
	Nickname           *string
	Biography          *string
	Language           *string
	Timezone           *string
	ExpectedRowVersion int64
	RequestID          string
}

// AdminSessionView 是管理员会话列表的一条脱敏摘要：不含会话秘密、CSRF 令牌、
// 验证摘要或 Cookie；客户端字段只作展示参考，不是可信设备身份。
type AdminSessionView struct {
	ID                string
	AppID             string
	Kind              string
	Reason            string
	CreatedAt         time.Time
	LastSeenAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	RememberMe        bool
	Current           bool
	ClientUserAgent   string
	ClientAddress     string
}

// AdminListUserSessionsRequest 分页查询目标用户的活动会话（步骤 217）。
// 仅 AdminSession 调用者可用（必需真实管理会话做强认证/范围判定）；ScopeApplicationID
// 为空表示系统范围，非空只返回绑定该应用的会话；root 目标一律拒绝。
type AdminListUserSessionsRequest struct {
	Caller             AdminCaller
	TargetUserID       string
	ScopeApplicationID string
	Page               AdminPage
	RequestID          string
}

// AdminUserSessionList 是管理员会话列表结果。
type AdminUserSessionList struct {
	TargetUserID       string
	ScopeApplicationID string
	Sessions           []AdminSessionView
	Total              int64
	HasMore            bool
	Page               AdminPageInfo
}

// AdminRevokeSessionsRequest 是管理员强制下线请求：TargetUserID 与 TargetSessionID
// 必须且只能指定一个；ScopeApplicationID 为空表示系统范围。Reason 必填（仅审计/
// 排障，不参与授权）。Password/TOTPCode 只用于本次真实再次认证，不保存/不记录。
type AdminRevokeSessionsRequest struct {
	Caller             AdminCaller
	ScopeApplicationID string
	TargetUserID       string
	TargetSessionID    string
	Reason             string
	Password           string
	TOTPCode           string
	RequestID          string
}

// AdminRevokeSessionsResult 是管理员强制下线结果；Revoked 是实际撤销数量，
// 越界或目标已失效按幂等 0 返回。
type AdminRevokeSessionsResult struct {
	ScopeApplicationID string
	TargetUserID       string
	TargetSessionID    string
	Revoked            int64
}

// AdminListReportPlansRequest 分页查询报告计划（offset 契约，复用 AdminPage）。
type AdminListReportPlansRequest struct {
	Caller    AdminCaller
	Page      AdminPage
	RequestID string
}

// AdminListTasksRequest 分页查询后台任务；Cursor 绑定 State/Kind/RequestID/时间
// 区间与发起者范围。普通管理会话只能看到本人发起的任务，本机受信操作者/root 可看
// 全部（由领域列表授权判定，门面不信任客户端自报范围）。
type AdminListTasksRequest struct {
	Caller        AdminCaller
	State         string
	Kind          string
	TaskRequestID string
	From          time.Time
	To            time.Time
	Limit         int
	Cursor        string
	RequestID     string
}

// AdminCreateRoleRequest 在系统或应用范围登记角色（创建不授予任何权限）。
// Limits 为空时使用直白的默认边界说明（领域服务要求限制说明非空）。
type AdminCreateRoleRequest struct {
	Caller      AdminCaller
	ScopeID     string
	Key         string
	Name        string
	Description string
	Limits      string
	RequestID   string
}

// AdminCreatePermissionRequest 在系统或应用范围登记自定义权限。
// Limits 为空时使用直白的默认边界说明（领域服务要求限制说明非空）。
type AdminCreatePermissionRequest struct {
	Caller      AdminCaller
	ScopeID     string
	Key         string
	Name        string
	Description string
	Limits      string
	RequestID   string
}

// AdminListPermissionsRequest 分页查询权限目录（作用范围/启停筛选 + 白名单排序）。
// Sort 允许值："created_at"（默认）、"updated_at"、"name"、"key"。
type AdminListPermissionsRequest struct {
	Caller     AdminCaller
	ScopeID    string
	Enabled    *bool
	Sort       string
	Descending bool
	Page       AdminPage
	// Search 是可选的字面子串搜索（权限名称/机器标识；空不过滤）。
	Search       string
	SearchFields []string
	RequestID    string
}

// AdminService 是受信管理门面：用户/资料/应用/角色/权限的受控管理操作。
//
// 安全语义：
//   - 调用者必须由 Runtime.LocalAdmin() 或 Runtime.AdminSession() 建立，普通请求
//     参数无法自称管理员；
//   - 用户主体的一切操作按当前有效权限与委派资格判定，敏感操作需要近期再次认证；
//   - 管理员建用户与 registration.enabled 无关；全局账户资格与应用内角色分离；
//   - 应用作用域操作只影响目标应用，跨应用写入按缺失权限拒绝；
//   - 不接受 is_root、系统资格或已验证状态等特权字段；root 账户受既有服务保护。
//
// 请求关联与未找到契约（步骤 207）：
//   - 每个请求的 RequestID 会先统一解析一次：空编号生成一次，非法编号在查询前以
//     REQ_INVALID 拒绝；合法编号贯穿领域调用者/请求、领域审计与返回错误；
//   - 已通过身份与权限检查的查询若确认目标不存在，返回稳定的公开 *NotFoundError
//     （Code() == NotFoundCode，即 "NOT_FOUND"，HTTP 建议 404），外部模块用
//     errors.Is(err, app.ErrNotFound)、app.IsNotFound 或 app.AsNotFound 判断，
//     不需要导入 internal 包；
//   - 未授权调用者只会得到 ACCESS_DENIED 等拒绝码，不会通过“未找到/存在”差异
//     探测记录；参数格式错误仍返回 REQ_INVALID，与合法未找到区分。
type AdminService interface {
	CreateUser(ctx context.Context, req AdminCreateUserRequest) (AdminUser, error)
	ListUsers(ctx context.Context, req AdminListUsersRequest) (AdminUserList, error)
	// ListGroups/ListGroupMembers 分页读取用户组与组成员（授权与数据范围由领域
	// 服务先行判定；排序字段使用白名单，非法值返回 REQ_INVALID）。
	ListGroups(ctx context.Context, req AdminListGroupsRequest) (AdminGroupList, error)
	ListGroupMembers(ctx context.Context, req AdminListGroupMembersRequest) (AdminGroupMemberList, error)
	// ListRoles/ListPermissions 分页读取角色与权限目录。
	ListRoles(ctx context.Context, req AdminListRolesRequest) (AdminRoleList, error)
	ListPermissions(ctx context.Context, req AdminListPermissionsRequest) (AdminPermissionList, error)
	// ListRoleAssignments 在数据源处分页读取角色的用户/组分配（两类各自分页）。
	ListRoleAssignments(ctx context.Context, req AdminListRoleAssignmentsRequest) (AdminRoleAssignmentList, error)
	GetUserByUsername(ctx context.Context, req AdminUserByUsernameRequest) (AdminUser, error)
	GetUserProfile(ctx context.Context, req AdminUserRequest) (AdminUserProfile, error)
	UpdateUserProfile(ctx context.Context, req AdminUpdateProfileRequest) (AdminUserProfile, error)
	AddApplicationMember(ctx context.Context, req AdminAddMemberRequest) error
	CreateApplication(ctx context.Context, req AdminCreateApplicationRequest) (AdminApplication, error)
	SetApplicationEnabled(ctx context.Context, req AdminSetApplicationEnabledRequest) (AdminApplication, error)
	// ListApplications/ListApplicationMembers 分页读取应用与应用成员（授权与应用范围
	// 由领域服务先于分页判定；非法排序/分页返回 REQ_INVALID）。
	ListApplications(ctx context.Context, req AdminListApplicationsRequest) (AdminApplicationList, error)
	ListApplicationMembers(ctx context.Context, req AdminListApplicationMembersRequest) (AdminApplicationMemberList, error)
	// ListApplicationRoles/ListApplicationGroups 分页读取指定应用范围的角色与用户组；
	// 作用范围固定为请求的应用 ID，不能跨应用读取。
	ListApplicationRoles(ctx context.Context, req AdminListApplicationRolesRequest) (AdminRoleList, error)
	ListApplicationGroups(ctx context.Context, req AdminListApplicationGroupsRequest) (AdminGroupList, error)
	// ListUserSessions 管理员按作用范围分页读取目标用户活动会话（仅 AdminSession
	// 调用者；强认证、范围、root 保护与读审计由会话服务重新判定）。
	ListUserSessions(ctx context.Context, req AdminListUserSessionsRequest) (AdminUserSessionList, error)
	// RevokeUserSessions 管理员按作用范围强制下线目标用户或指定会话（仅真实
	// AdminSession + 强再次认证；LocalAdmin 没有管理会话，不能执行）。root 与
	// 受保护目标由会话服务拒绝；越界目标按幂等 0 处理，不泄露存在性。
	RevokeUserSessions(ctx context.Context, req AdminRevokeSessionsRequest) (AdminRevokeSessionsResult, error)
	// ListAuditEvents/ListReports/ListTasks 分页读取审计、历史报告与后台任务
	// （步骤 218：稳定游标分页，游标绑定 scope/筛选；不改 216 已有方法）。
	ListAuditEvents(ctx context.Context, req AdminListAuditEventsRequest) (AdminAuditEventList, error)
	ListReports(ctx context.Context, req AdminListReportsRequest) (AdminReportList, error)
	ListTasks(ctx context.Context, req AdminListTasksRequest) (AdminTaskList, error)
	// ListReportPlans/ListBackupJobs/ListBackupArtifacts/ListBackupSchedules/
	// ListBackupNotifications 分页读取报告计划与备份域可增长列表（offset 契约）。
	ListReportPlans(ctx context.Context, req AdminListReportPlansRequest) (AdminReportPlanList, error)
	ListBackupJobs(ctx context.Context, req AdminListBackupJobsRequest) (AdminBackupJobList, error)
	ListBackupArtifacts(ctx context.Context, req AdminListBackupArtifactsRequest) (AdminBackupArtifactList, error)
	ListBackupSchedules(ctx context.Context, req AdminListBackupSchedulesRequest) (AdminBackupScheduleList, error)
	ListBackupNotifications(ctx context.Context, req AdminListBackupNotificationsRequest) (AdminBackupNotificationList, error)
	CreateRole(ctx context.Context, req AdminCreateRoleRequest) (AdminRole, error)
	CreatePermission(ctx context.Context, req AdminCreatePermissionRequest) (AdminPermission, error)
	AddRolePermission(ctx context.Context, req AdminRolePermissionRequest) error
	GrantApplicationRole(ctx context.Context, req GrantRoleRequest) error
	RevokeApplicationRole(ctx context.Context, req RevokeRoleRequest) error
	GrantDelegation(ctx context.Context, req AdminDelegationGrantRequest) (AdminDelegation, error)
	ListRolePermissions(ctx context.Context, req AdminRoleRequest) ([]AdminPermission, error)
	EffectivePermissions(ctx context.Context, req AdminPermissionQuery) (AdminEffectivePermissions, error)
	CheckPermission(ctx context.Context, req AdminPermissionCheck) (AdminPermissionDecision, error)
}
