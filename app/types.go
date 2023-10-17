package app

import (
	"context"
	"io"
	"io/fs"
	"net"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// RootRequest 是首次 root 初始化请求。Password 只用于本次受限初始化，不保存、
// 不返回、不记录；调用方应尽快清空自己的副本。
type RootRequest struct {
	Username    string
	DisplayName string
	Password    string
	RequestID   string
}

// RootResult 是首次初始化结果（不含密码、密钥或会话）。
type RootResult struct {
	UserID             string
	State              string
	StrongAuthRequired bool
	SecurityVersion    int64
}

// CreateUserRequest 是宿主受信创建用户请求。
type CreateUserRequest struct {
	Username  string
	Password  string
	Email     string
	Nickname  string
	Language  string
	Timezone  string
	RequestID string
}

// User 是脱敏用户视图。
type User struct {
	ID        string
	Username  string
	Nickname  string
	Email     string
	Status    string
	CreatedAt time.Time
}

// LoginRequest 是一次密码登录请求（口令只用于本次验证）。
type LoginRequest struct {
	Username  string
	Password  string
	AppID     string
	ClientIP  string
	RequestID string
	// RememberMe 由宿主决定是否请求记住登录状态；是否生效由会话策略决定。
	RememberMe bool
	// UserAgent 是客户端自称的 UA 摘要（仅记录用途，不能作为身份）。
	UserAgent string
}

// LoginResult 是登录结果；SessionSecret/CSRFSecret 只在本结果出现一次。
//
// 当账户启用了第二因素或被策略要求强认证时，Login 返回受限会话与
// SecondFactor 挑战：Restricted=true，SessionSecret 是只能完成第二步的受限会话
// 秘密，宿主必须调用 AuthService.VerifySecondFactor 才能得到完整会话。
type LoginResult struct {
	UserID        string
	Username      string
	SessionID     string
	SessionSecret []byte
	CSRFSecret    []byte
	ExpiresAt     time.Time
	Restricted    bool
	RequiredSteps []string
	// SecondFactor 非 nil 表示必须完成第二步验证；挑战数据只返回一次。
	SecondFactor *SecondFactorChallenge
}

// SecondFactorChallenge 是第二步因素挑战（TOTP/Passkey/邮件或强认证初始化）。
// AttemptToken/PasskeyOptions 只在本结果出现一次，不得写入日志或普通存储。
type SecondFactorChallenge struct {
	ChallengeID       string
	AttemptToken      []byte
	FactorType        string
	MaskedEmail       string
	ExpiresAt         time.Time
	PasskeyCeremonyID string
	PasskeyOptions    []byte
	// SetupRequired 表示账户被要求强认证但尚未绑定强因素：当前只能完成受控
	// 强认证初始化（AllowedSetupMethods），完成后需要重新登录，不会签发完整会话。
	SetupRequired       bool
	AllowedSetupMethods []string
}

// VerifySecondFactorRequest 是完成第二步验证的请求。
type VerifySecondFactorRequest struct {
	// SessionSecret 是第一步签发的受限会话秘密。
	SessionSecret []byte
	ChallengeID   string
	AttemptToken  []byte
	// Code 是 TOTP/邮件验证码；Passkey 第二步使用 PasskeyCeremonyID/PasskeyResponse。
	Code              string
	PasskeyCeremonyID string
	PasskeyResponse   []byte
	RequestID         string
}

// VerifiedSession 是第二步通过后签发的完整会话；秘密只返回一次。
type VerifiedSession struct {
	UserID        string
	SessionID     string
	SessionSecret []byte
	CSRFSecret    []byte
	ExpiresAt     time.Time
	// Method/Strength 是本次第二步因素与达到的认证强度（"totp"/"passkey"/"email"）。
	Method   string
	Strength string
}

// BeginRecoveryRequest 使用恢复代码替代第二步，进入受限恢复会话。
type BeginRecoveryRequest struct {
	// SessionSecret 是第一步签发的受限会话秘密（待第二因素）。
	SessionSecret []byte
	ChallengeID   string
	AttemptToken  []byte
	RecoveryCode  string
	RequestID     string
}

// RecoverySession 是受限恢复会话：不能访问业务，只能检查状态并完成新因素绑定。
type RecoverySession struct {
	UserID           string
	SessionID        string
	SessionSecret    []byte
	ExpiresAt        time.Time
	CodesRemaining   int
	RequiredStrength string
	AllowedMethods   []string
}

// RecoveryStatusRequest 查询受限恢复会话状态。
type RecoveryStatusRequest struct {
	SessionSecret []byte
	RequestID     string
}

// RecoveryStatus 是受限恢复会话的只读状态（不含恢复代码或秘密）。
type RecoveryStatus struct {
	HasActiveGroup   bool
	CodesRemaining   int
	ExpiresAt        time.Time
	RequiredStrength string
	AllowedMethods   []string
}

// TOTPBindingBeginRequest 开始绑定 TOTP（敏感操作 mfa.add，需要近期密码验证）。
type TOTPBindingBeginRequest struct {
	SessionSecret []byte
	// Password 是本次敏感操作再次认证的密码；服务端不会保存它。
	Password  string
	RequestID string
}

// TOTPBindingStart 是 TOTP 绑定开始结果；Secret/OTPAuthURL 只返回一次。
type TOTPBindingStart struct {
	BindingID     string
	Secret        string
	OTPAuthURL    string
	ExpiresAt     time.Time
	PeriodSeconds int
	Digits        int
}

// TOTPBindingConfirmRequest 用一次性验证码确认 TOTP 绑定。
type TOTPBindingConfirmRequest struct {
	SessionSecret []byte
	BindingID     string
	Code          string
	RequestID     string
}

// TOTPBinding 是已激活 TOTP 绑定的脱敏元数据。
type TOTPBinding struct {
	BindingID   string
	Status      string
	CreatedAt   time.Time
	ActivatedAt time.Time
}

// RecoveryCodesRequest 生成新一组恢复代码（敏感操作 recovery.codes.rotate，
// 已绑定强因素的账户需要近期强认证：密码 + TOTP 动态码）。
type RecoveryCodesRequest struct {
	SessionSecret []byte
	Password      string
	TOTPCode      string
	RequestID     string
}

// RecoveryCodes 是新一组恢复代码的一次性结果；Codes 只返回一次。
type RecoveryCodes struct {
	Codes      []string
	Generation int64
	CreatedAt  time.Time
}

// SecurityStatusRequest 查询当前账户的认证/恢复能力概览。
type SecurityStatusRequest struct {
	SessionSecret []byte
	RequestID     string
}

// SecurityStatus 是认证/恢复能力概览（不含秘密或代码）。
type SecurityStatus struct {
	TOTPActive             bool
	EmailFactorActive      bool
	PasskeyEnabled         bool
	PasskeyCount           int
	RecoveryCodesRemaining int
	StrongFactorBound      bool
}

// AccessRequest 是联合权限检查请求（权限由业务服务端确定）。
type AccessRequest struct {
	UserID     string
	AppID      string
	Permission string
	Mode       string
	ResourceID string
	RequestID  string
}

// AccessDecision 是权限检查结果；Reason/Code 为稳定公开值。
type AccessDecision struct {
	Allowed     bool
	Code        string
	Reason      string
	RequestID   string
	Application string
}

// ===== 受信管理门面（步骤 182） =====

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
	RequestID  string
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
	RequestID      string
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
	Page          AdminPage
	RequestID     string
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

// SessionDeviceRequest 是本人设备列表请求；SessionSecret 必须是仍有效且可访问普通
// 业务的会话秘密。
type SessionDeviceRequest struct {
	SessionSecret []byte
	Page          AdminPage
}

// SessionDevice 是设备列表的一条脱敏会话摘要（不含秘密/CSRF/验证摘要）。
type SessionDevice struct {
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

// SessionDeviceList 是本人设备列表结果。
type SessionDeviceList struct {
	Devices []SessionDevice
	Total   int64
	HasMore bool
	Page    AdminPageInfo
}

// AdminRole 是角色登记信息。
type AdminRole struct {
	ID            string
	ScopeID       string
	ApplicationID string
	Key           string
	Name          string
	Enabled       bool
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

// AdminPermission 是权限目录条目视图。
type AdminPermission struct {
	ID       string
	ScopeID  string
	Key      string
	Name     string
	Enabled  bool
	RootOnly bool
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

// AdminAddMemberRequest 把已有用户加入应用（应用成员关系，不授予角色权限）。
type AdminAddMemberRequest struct {
	Caller        AdminCaller
	ApplicationID string
	UserID        string
	RequestID     string
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

// AdminListPermissionsRequest 分页查询权限目录（作用范围/启停筛选 + 白名单排序）。
// Sort 允许值："created_at"（默认）、"updated_at"、"name"、"key"。
type AdminListPermissionsRequest struct {
	Caller     AdminCaller
	ScopeID    string
	Enabled    *bool
	Sort       string
	Descending bool
	Page       AdminPage
	RequestID  string
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

// BootstrapService 是首次初始化门面。
type BootstrapService interface {
	EnsureRoot(ctx context.Context, req RootRequest) (RootResult, error)
}

// UserService 是宿主受信用户门面。
type UserService interface {
	Create(ctx context.Context, req CreateUserRequest) (User, error)
}

// AuthService 是认证门面：密码第一步 + 第二因素/受限恢复验证。
type AuthService interface {
	// Login 完成密码第一步。账户启用第二因素时返回受限会话与 SecondFactor 挑战；
	// 未启用时直接返回完整会话。
	Login(ctx context.Context, req LoginRequest) (LoginResult, error)
	// VerifySecondFactor 用受限会话 + 挑战数据完成第二步，返回完整会话。
	VerifySecondFactor(ctx context.Context, req VerifySecondFactorRequest) (VerifiedSession, error)
	// BeginRecovery 用恢复代码替代第二步，进入受限恢复会话。
	BeginRecovery(ctx context.Context, req BeginRecoveryRequest) (RecoverySession, error)
	// RecoveryStatus 查询受限恢复会话状态。
	RecoveryStatus(ctx context.Context, req RecoveryStatusRequest) (RecoveryStatus, error)
}

// SecurityService 是认证/安全设置门面：敏感操作经真实再次认证后执行。
type SecurityService interface {
	// Status 返回当前账户的认证/恢复能力概览。
	Status(ctx context.Context, req SecurityStatusRequest) (SecurityStatus, error)
	// BeginTOTPBinding 开始绑定 TOTP（敏感操作 mfa.add，需要近期密码验证）。
	BeginTOTPBinding(ctx context.Context, req TOTPBindingBeginRequest) (TOTPBindingStart, error)
	// ConfirmTOTPBinding 用一次性验证码确认 TOTP 绑定。
	ConfirmTOTPBinding(ctx context.Context, req TOTPBindingConfirmRequest) (TOTPBinding, error)
	// GenerateRecoveryCodes 生成新一组恢复代码（敏感操作，需要近期认证）。
	GenerateRecoveryCodes(ctx context.Context, req RecoveryCodesRequest) (RecoveryCodes, error)
}

// AccessService 是联合权限检查门面。
type AccessService interface {
	Check(ctx context.Context, req AccessRequest) (AccessDecision, error)
}

// SessionService 会话语义：校验当前会话、应用+权限联合检查、撤销当前会话。
//
// 安全边界（步骤 208）：
//   - Validate 只证明“会话此刻有效且是完整会话”，不证明会话属于当前业务应用，
//     也不证明用户具备当前操作需要的权限；业务/管理操作禁止只靠 Validate 放行。
//     需要应用绑定与权限联合判断时使用 Authorize（复用既有授权内核）。
//   - ValidateCSRF 只校验与会话绑定的 CSRF 令牌；CSRF 通过不会提升受限会话权限，
//     也不代替 Application/权限判断。来源（Origin/Referer）仍由宿主 HTTP 防护层
//     负责，不能只靠 CSRF 令牌。
//   - 三个方法都不会延长会话。
type SessionService interface {
	Validate(ctx context.Context, sessionSecret []byte) (SessionInfo, error)
	ValidateCSRF(ctx context.Context, sessionSecret []byte, token string) error
	// Authorize 对一个完整（非受限）会话执行“应用绑定 + 所需权限”联合检查，复用
	// 既有授权内核（令牌/当前权限/应用状态/成员状态/数据范围交集语义由权限引擎
	// 保证）。CSRFToken 非空时先校验 CSRF，但 CSRF 通过不会提高授权结果；受限会话
	// 一律拒绝。授权拒绝以决策返回（Allowed=false + 稳定 Code/Reason，error 为 nil），
	// 只有会话无效、输入非法或内部故障才返回 error。
	Authorize(ctx context.Context, req SessionAccessRequest) (SessionAccessDecision, error)
	Revoke(ctx context.Context, sessionSecret []byte) error
	// ListDevices 分页列出当前会话所属用户的本人活动会话（设备列表）；不包含会话
	// 秘密/CSRF/验证摘要，offset 在并发登录/退出下不保证快照一致。
	ListDevices(ctx context.Context, req SessionDeviceRequest) (SessionDeviceList, error)
}

// SessionAccessRequest 是“会话 + 应用绑定 + 所需权限”的联合检查请求。
//
// 安全语义：
//   - SessionSecret 必须来自可信边界（Cookie/Authorization 或宿主自己的安全存储），
//     不能来自 URL、查询参数或客户端自填字段；
//   - AppID 必填：会话没有当前应用边界时不能做业务授权判断；
//   - Permissions 必须是业务服务端确定的权限键，不能由客户端任意指定后当成“已授权”；
//     Mode 为空按 all 处理；
//   - CSRFToken 可选：适合写操作在同一个入口里同时校验 CSRF；它只参与校验，不会
//     提升会话或权限。
type SessionAccessRequest struct {
	SessionSecret []byte
	// AppID 是当前业务请求所属应用（"app_..." 稳定 ID）；必填。
	AppID string
	// Permissions 是当前操作需要的权限键（例如 "app.invoice.approve"）。
	Permissions []string
	// Mode 是 "all"（默认）或 "any"。
	Mode string
	// CSRFToken 是可选的会话绑定 CSRF 令牌；非空时先校验。
	CSRFToken string
	// RequestID 用于关联调用、领域审计与返回错误；空编号统一生成，非法编号拒绝。
	RequestID string
}

// SessionAccessDecision 是联合检查结果：Allowed=true 表示会话有效、属于当前应用
// 且具备所需权限；Allowed=false 时 Code/Reason 是稳定公开拒绝码与原因。
type SessionAccessDecision struct {
	UserID    string
	SessionID string
	AppID     string
	Allowed   bool
	Code      string
	Reason    string
	// RequestID 是与调用/审计/错误一致的请求编号。
	RequestID string
}

// SessionInfo 是校验通过后的会话快照；不含会话秘密和 CSRF 令牌。
type SessionInfo struct {
	UserID               string
	SessionID            string
	AppID                string
	ExpiresAt            time.Time
	IdleExpiresAt        time.Time
	CreatedAt            time.Time
	SecurityVersion      int64
	AuthMethods          []string
	StrongAuthVerifiedAt time.Time
}

var _ = net.IP{}

// ===== 嵌入式 HTTP 与页面挂载（步骤 183） =====

// HTTPOptions 是嵌入式 HTTP 与页面挂载选项；nil 表示不装配 HTTP（宿主只使用 Go API）。
// 装配沿用独立服务的完整安全链（限流/CSRF/安全头/会话/权限），不复制实现；
// 缺依赖时 Open 直接失败，不会退化为“只有健康页”的最小服务。
type HTTPOptions struct {
	// Prefix 覆盖站内路径前缀；空使用配置的 server.path_prefix。
	Prefix string
	// AccessLog 是宿主提供的 W3C 访问日志输出；nil 表示不写访问日志。
	AccessLog io.Writer
	// EnableProtocol 启用 OAuth2/OIDC 协议端点（需配置合法 protocol.issuer）。
	EnableProtocol bool
	// EnableAdminAPI 启用内置管理 JSON API（复用同一管理会话/CSRF 契约）。
	EnableAdminAPI bool
	AdminAPIPrefix string
	// EnableManagedAPI 启用业务应用托管管理 API。
	EnableManagedAPI bool
	ManagedAPIPrefix string
	// EnableAppSupport 启用应用受限客服 API（需要同时启用协议端点）。
	EnableAppSupport   bool
	AppSupportPrefix   string
	AppSupportAudience string
	// PageOverrides 是宿主页面/资源替换选项；替换不改变路由访问级别、会话/权限
	// 判定与 CSRF 校验。
	PageOverrides *PageOverrides
}

// PageOverrides 是宿主页面/资源替换选项；替换不改变路由访问级别、会话/权限判定与 CSRF 校验。
type PageOverrides struct {
	// HostTemplates 是宿主模板覆盖来源；HostRenderer 是最高优先级单页渲染器。
	HostTemplates *login.UIHostTemplates
	HostRenderer  login.UIPageRenderer
	// Brand 覆盖页面品牌；nil 使用内置品牌。
	Brand *login.UIBrand
	// AssetOverlays 按顺序覆盖内置静态资源（同逻辑路径后者优先）。
	AssetOverlays []fs.FS
	// Translations 追加/覆盖翻译目录；nil 使用内置 zh-CN。
	Translations login.UICatalogProvider
	// DisableBuiltinPages 关闭内置页面，仅由宿主模板/渲染器提供页面。
	DisableBuiltinPages bool
}
