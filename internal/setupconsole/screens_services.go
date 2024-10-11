package setupconsole

// WS3（步骤 286–291）本地维护画面使用的领域服务契约。
//
// 设计约束：
//   - 画面只依赖本文件的窄接口，不直接持有 internal 领域服务；生产适配器在
//     localruntime*.go 中用既有领域/存储 API + 本地维护身份实现，测试用替身实现；
//   - 本文件模型只含脱敏展示字段：不含密码/哈希/令牌/秘密；秘密只能通过输入
//     回调短暂存在，不进入模型、日志或渲染文本；
//   - 接口方法都显式返回错误，画面必须展示稳定错误并 fail-closed，不能伪造成功；
//   - 领域能力缺失时由适配器返回 ErrLocalUnsupported，画面显示“不可用”并阻止操作。

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/config"
)

// ErrLocalUnsupported 表示当前实例装配不支持该维护能力（依赖缺失）；画面必须
// 显示不可用并 fail-closed，绝不能把未实现能力表现为成功。
var ErrLocalUnsupported = errors.New("当前实例不支持该本地维护能力")

// ErrLocalRuntimeUnavailable 表示无法以本地维护身份打开实例（未配置/坏配置/
// 数据库不可达/待迁移等），画面只展示原因与退出路径。
var ErrLocalRuntimeUnavailable = errors.New("本地维护会话不可用")

// WS3Session 是一次本地维护会话（每个画面按需打开、退出画面关闭）。
type WS3Session interface {
	// Services 返回本地维护领域适配器。
	Services() *WS3Services
	// Config 返回已加载配置的只读副本。
	Config() config.Config
	// OperatorID 是稳定本地操作者标识（进入审计，不是 Evernight 账户）。
	OperatorID() string
	// Close 关闭本次会话自建资源；幂等。
	Close(ctx context.Context) error
}

// WS3SessionOpener 由 cmd/login-setup / 控制台装配注入。
type WS3SessionOpener func(ctx context.Context) (WS3Session, error)

// WS3Services 汇总各领域适配器；nil 子项表示该领域不可用。
type WS3Services struct {
	Users    UserAdmin
	Identity IdentityAdmin
	Security SecurityAdmin
	RBAC     RBACAdmin
	Apps     AppAdmin
	Audit    AuditAdmin
	// OperatorID 是调用时绑定的本地操作者标识（适配器内部用于审计 actor）。
	OperatorID string
}

// ---------- 通用分页 ----------

// LocalPageRequest 是本地维护列表的分页/搜索参数；Limit 有界。
type LocalPageRequest struct {
	Search string
	Limit  int
	Offset int
}

// LocalPagination 是分页结果元数据。
type LocalPagination struct {
	HasMore bool
	Offset  int
	Limit   int
}

// ---------- 286 用户生命周期 ----------

// LocalUser 是用户摘要/详情（脱敏）。
type LocalUser struct {
	ID              string
	Username        string
	Nickname        string
	Biography       string
	Language        string
	Timezone        string
	Status          string
	IsRoot          bool
	RowVersion      int64
	SecurityVersion int64
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// LocalUserPage 是用户列表页。
type LocalUserPage struct {
	Users      []LocalUser
	Pagination LocalPagination
}

// LocalUserQuery 是用户查询参数。PageRequest 是首选形态；Search/Limit/Offset
// 是兼容字段（WS2 账户方案等调用方直接构造），由适配器统一规范化。
type LocalUserQuery struct {
	PageRequest LocalPageRequest
	Status      string // ""=全部
	Search      string
	Limit       int
	Offset      int
}

// page 返回规范化后的分页参数。
func (q LocalUserQuery) page() LocalPageRequest {
	page := q.PageRequest
	if page.Limit <= 0 && q.Limit > 0 {
		page.Limit = q.Limit
	}
	if page.Offset <= 0 && q.Offset > 0 {
		page.Offset = q.Offset
	}
	if strings.TrimSpace(page.Search) == "" && strings.TrimSpace(q.Search) != "" {
		page.Search = q.Search
	}
	return page
}

// LocalUserCreate 是本地创建用户输入；密码经一次性输入传递后立即丢弃。
type LocalUserCreate struct {
	Username      string
	Nickname      string
	Biography     string
	Language      string
	Timezone      string
	Password      string
	RequireChange bool
}

// LocalProfileUpdate 是普通资料修改输入（不改用户名/状态/安全字段）。
type LocalProfileUpdate struct {
	Nickname           string
	Biography          string
	Language           string
	Timezone           string
	ExpectedRowVersion int64
}

// LocalValidity 是账户有效期快照（nil 表示该端永久有效）。
type LocalValidity struct {
	UserID     string
	ValidFrom  *time.Time
	ValidUntil *time.Time
	RowVersion int64
}

// LocalDeletionPreview 是不可逆删除前影响快照。
type LocalDeletionPreview struct {
	UserID             string
	Username           string
	Status             string
	IsRoot             bool
	RowVersion         int64
	SecurityVersion    int64
	AppMemberships     int
	UserRoles          int
	GroupMemberships   int
	OneTimeCredentials int
	OwnedApplications  int
}

// LocalPasswordResult 是设置密码结果（不含密码/哈希）。
type LocalPasswordResult struct {
	UserID            string
	SecurityVersion   int64
	PasswordChangedAt time.Time
	MustChange        bool
}

// LocalCredentialStatus 是账户凭证状态（只读，不可读回密码）。
type LocalCredentialStatus struct {
	UserID      string
	HasPassword bool
	IsRoot      bool
}

// UserAdmin 是 286 本地用户维护契约。
type UserAdmin interface {
	ListUsers(ctx context.Context, query LocalUserQuery) (LocalUserPage, error)
	GetUser(ctx context.Context, userID string) (LocalUser, error)
	CreateUser(ctx context.Context, input LocalUserCreate) (LocalUser, error)
	UpdateProfile(ctx context.Context, userID string, input LocalProfileUpdate) (LocalUser, error)
	// SetEnabled 启停账户；expectedRowVersion<=0 表示读取最新版本后自动重试一
	// 次（本地维护身份无交互确认竞争窗口），冲突仍返回错误。
	SetEnabled(ctx context.Context, userID string, enabled bool, expectedRowVersion int64) (LocalUser, error)
	GetValidity(ctx context.Context, userID string) (LocalValidity, error)
	SetValidity(ctx context.Context, userID string, validity LocalValidity) (LocalUser, error)
	PreviewDeletion(ctx context.Context, userID string) (LocalDeletionPreview, error)
	// RequestDeletion 将账户标记为待删除（不可逆删除的第一步）。
	RequestDeletion(ctx context.Context, userID string, expectedRowVersion int64) (LocalUser, error)
	// CompleteDeletion 完成删除（仅 pending_delete）；返回删除前影响快照。
	CompleteDeletion(ctx context.Context, userID string, expectedRowVersion int64) (LocalDeletionPreview, error)
	ListAssignableRoles(ctx context.Context) ([]LocalRole, error)
	AssignRole(ctx context.Context, userID, roleID string) error
}

// ---------- 287 身份维护 ----------

// IdentityAdmin 是 287 本地用户名/密码维护契约。
type IdentityAdmin interface {
	// Rename 直接修改用户显示用户名（含 root，本地维护身份；稳定 UserID 不变）。
	Rename(ctx context.Context, userID, newUsername, reason string, expectedRowVersion int64) (LocalUser, error)
	// SetPassword 直接设置/重置用户密码（含 root、无密码账户）；RequireChange
	// 要求目标下次登录先改密。密码只用于本次调用，不落模型/日志。
	SetPassword(ctx context.Context, userID, newPassword string, requireChange bool) (LocalPasswordResult, error)
	Credentials(ctx context.Context, userID string) (LocalCredentialStatus, error)
}

// ---------- 288 MFA 维护 ----------

// LocalFactorKind 是第二因素类别。
type LocalFactorKind string

const (
	LocalFactorTOTP     LocalFactorKind = "totp"
	LocalFactorEmail    LocalFactorKind = "email"
	LocalFactorPasskey  LocalFactorKind = "passkey"
	LocalFactorRecovery LocalFactorKind = "recovery_codes"
)

// LocalFactor 是一项可维护的认证因素/凭证（脱敏，不含种子/公钥细节）。
type LocalFactor struct {
	Kind       LocalFactorKind
	ID         string // TOTP 绑定/Passkey 凭证 ID；email/recovery 为空
	Label      string
	CreatedAt  time.Time
	LastUsedAt time.Time
	Primary    bool // 主登录 Passkey 标记（删除需显式选择）
	Revoked    bool
}

// LocalSession 是目标用户的一条会话摘要（脱敏）。
type LocalSession struct {
	ID         string
	Kind       string
	AppID      string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	IPSummary  string
	UserAgent  string
}

// SecurityAdmin 是 288 本地 MFA/会话维护契约。
type SecurityAdmin interface {
	ListFactors(ctx context.Context, userID string) ([]LocalFactor, error)
	// RemoveFactor 删除指定因素；passkey 需显式 primary 选择时由画面确认传入。
	RemoveFactor(ctx context.Context, userID string, factor LocalFactor, reason string) error
	// RevokeRecoveryCodes 撤销目标用户全部恢复代码。
	RevokeRecoveryCodes(ctx context.Context, userID, reason string) error
	// ClearSecondFactors 清除全部第二因素（TOTP/邮件/主登录 Passkey 分级由
	// includePrimaryPasskeys 显式控制；恢复代码同时撤销）。
	ClearSecondFactors(ctx context.Context, userID string, includePrimaryPasskeys bool, reason string) error
	ListSessions(ctx context.Context, userID string, limit, offset int) ([]LocalSession, bool, error)
	// RevokeSessions 强制目标用户下线（复用既有系统撤销路径）。
	RevokeSessions(ctx context.Context, userID, reason string) (int64, error)
}

// ---------- 289 角色/权限/用户组 ----------

// LocalRole 是角色摘要。
type LocalRole struct {
	ID      string
	Key     string
	Name    string
	ScopeID string
	Enabled bool
	Builtin bool
}

// LocalPermission 是权限目录摘要。
type LocalPermission struct {
	Key         string
	Name        string
	Implemented bool
	RootOnly    bool
}

// LocalGroup 是用户组摘要。
type LocalGroup struct {
	ID      string
	Key     string
	Name    string
	ScopeID string
	Enabled bool
}

// LocalPresetDiff 是预设恢复差异预览。PreviewToken 是服务端绑定状态摘要的一次性
// 确认令牌（只用于随后 Restore，不在画面显示/记录）。
type LocalPresetDiff struct {
	ScopeID       string
	RoleKey       string
	Add           []string
	Remove        []string
	Affected      int
	AffectedKnown bool
	CurrentComps  int
	PresetComps   int
	PreviewToken  string
}

// RBACAdmin 是 289 角色/权限/用户组维护契约。
type RBACAdmin interface {
	ListRoles(ctx context.Context, query LocalPageRequest, scopeID string) ([]LocalRole, bool, error)
	ListPermissions(ctx context.Context, query LocalPageRequest) ([]LocalPermission, bool, error)
	ListGroups(ctx context.Context, query LocalPageRequest, scopeID string) ([]LocalGroup, bool, error)
	// PreviewPresetRestore 返回指定范围/预设角色的差异，不改动任何数据。
	PreviewPresetRestore(ctx context.Context, scopeID, roleKey string) (LocalPresetDiff, error)
	// RestorePreset 应用恢复；要求显式 confirm=true，并在审计记录本地操作者。
	RestorePreset(ctx context.Context, diff LocalPresetDiff, confirm bool) error
	// SetRoleEnabled 启停自定义/预设角色（内置权限与 root 资格不受影响）。
	SetRoleEnabled(ctx context.Context, roleID string, enabled bool) error
	// AddGroupMember/RemoveGroupMember 维护组成员。
	AddGroupMember(ctx context.Context, groupID, userID string) error
	RemoveGroupMember(ctx context.Context, groupID, userID string) error
}

// ---------- 290 应用/成员/凭证/会话 ----------

// LocalApplication 是应用摘要（ID 创建后不变）。
type LocalApplication struct {
	ID          string
	Name        string
	Description string
	Homepage    string
	OwnerUserID string
	Status      string
	RowVersion  int64
}

// LocalAppMember 是应用成员摘要。
type LocalAppMember struct {
	UserID   string
	Username string
	Nickname string
	Status   string
}

// LocalAppClient 是 OAuth 客户端凭证摘要（秘密只在创建/轮换时一次展示）。
type LocalAppClient struct {
	ClientID     string
	Name         string
	Type         string
	RedirectURIs []string
	Status       string
	SecretShown  bool
}

// LocalAppClientCreated 是创建/轮换结果；Secret 只允许直接展示一次，不落存储。
type LocalAppClientCreated struct {
	Client LocalAppClient
	Secret string
}

// AppAdmin 是 290 应用维护契约。
type AppAdmin interface {
	ListApplications(ctx context.Context, query LocalPageRequest) ([]LocalApplication, bool, error)
	GetApplication(ctx context.Context, applicationID string) (LocalApplication, error)
	CreateApplication(ctx context.Context, name, description, homepage string) (LocalApplication, error)
	UpdateApplication(ctx context.Context, applicationID, name, description, homepage string, expectedRowVersion int64) (LocalApplication, error)
	SetApplicationEnabled(ctx context.Context, applicationID string, enabled bool) error
	ListMembers(ctx context.Context, applicationID string, query LocalPageRequest) ([]LocalAppMember, bool, error)
	AddMember(ctx context.Context, applicationID, userID string) error
	RemoveMember(ctx context.Context, applicationID, userID string) error
	ListClients(ctx context.Context, applicationID string) ([]LocalAppClient, error)
	CreateClient(ctx context.Context, applicationID, name string, redirectURIs []string) (LocalAppClientCreated, error)
	RotateClientSecret(ctx context.Context, applicationID, clientID string) (LocalAppClientCreated, error)
	RevokeClient(ctx context.Context, applicationID, clientID string) error
}

// ---------- 291 审计/诊断/通知/报告/任务 ----------

// LocalAuditEntry 是审计查询结果摘要。
type LocalAuditEntry struct {
	ID        int64
	CreatedAt time.Time
	ActorType string
	ActorID   string
	Action    string
	Target    string
	Outcome   string
	ErrorCode string
	RequestID string
}

// LocalAuditFilter 是审计查询过滤条件（结构化为主，可选有限文本）。
type LocalAuditFilter struct {
	Action    string
	Outcome   string
	ActorID   string
	ErrorCode string
	Limit     int
	Offset    int
}

// LocalAuditPage 是审计结果页。
type LocalAuditPage struct {
	Entries    []LocalAuditEntry
	Pagination LocalPagination
}

// LocalDiagnostics 是诊断摘要（脱敏）。
type LocalDiagnostics struct {
	InstanceReady bool
	DatabasePath  string
	AppliedCount  int
	LatestCount   int
	RootUserID    string
	Notes         []string
}

// LocalDelivery 是安全通知/邮件投递状态摘要。
type LocalDelivery struct {
	ID        string
	Kind      string
	State     string
	Attempts  int
	LastError string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// LocalReport 是报告摘要。
type LocalReport struct {
	ID        string
	Kind      string
	Format    string
	State     string
	TaskID    string
	CreatedAt time.Time
	SizeBytes int64
}

// LocalReportRequest 是本地维护报告生成参数（显式范围/窗口/格式）。
type LocalReportRequest struct {
	ScopeID    string
	From       time.Time
	To         time.Time
	Formats    []string
	DetailRows int
}

// LocalTask 是后台任务摘要。
type LocalTask struct {
	ID          string
	Kind        string
	State       string
	Progress    int
	LastError   string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	CancelState string
}

// LocalRetention 是审计保留策略摘要（运维信息）。
type LocalRetention struct {
	Days       int
	Configured bool
	Version    int64
	Cutoff     time.Time
	UpdatedAt  time.Time
}

// LocalPurgePreview 是审计清理预估（只读，不删除记录）。
type LocalPurgePreview struct {
	ScopeID              string
	Cutoff               time.Time
	BatchSize            int
	MaxRecords           int
	EstimatedCount       int64
	AtLeast              bool
	WithinRetention      bool
	MaintenanceProtected bool
	Digest               string
	Retention            LocalRetention
	GeneratedAt          time.Time
}

// LocalPurgeRun 是清理运行摘要（真实任务状态/计数）。
type LocalPurgeRun struct {
	ID            string
	Kind          string
	ScopeID       string
	State         string
	TaskID        string
	Cutoff        time.Time
	Scanned       int
	Cleaned       int
	Skipped       int
	Failed        int
	LimitReached  bool
	ErrorCode     string
	FailureReason string
	CreatedAt     time.Time
}

// LocalPurgeEvidence 是受保护清理维护证据条目。
type LocalPurgeEvidence struct {
	OperationID string
	Action      string
	Result      string
	ErrorCode   string
	StartedAt   time.Time
	FinishedAt  time.Time
	RequestID   string
}

// AuditAdmin 是 291 维护契约。
type AuditAdmin interface {
	QueryAudit(ctx context.Context, filter LocalAuditFilter) (LocalAuditPage, error)
	Diagnostics(ctx context.Context) (LocalDiagnostics, error)
	ListDeliveries(ctx context.Context, limit, offset int) ([]LocalDelivery, bool, error)
	ListReports(ctx context.Context, limit, offset int) ([]LocalReport, bool, error)
	GenerateReport(ctx context.Context, request LocalReportRequest) (LocalReport, error)
	ListTasks(ctx context.Context, limit, offset int) ([]LocalTask, bool, error)
	CancelTask(ctx context.Context, taskID, reason string) (LocalTask, error)
	// 审计保留策略/危险清理（本地维护显式动作；写门+独立维护证据）。
	Retention(ctx context.Context) (LocalRetention, error)
	SetRetention(ctx context.Context, retentionDays int, reason string) (LocalRetention, error)
	PreviewPurge(ctx context.Context, cutoff time.Time, maxRecords int) (LocalPurgePreview, error)
	StartPurge(ctx context.Context, preview LocalPurgePreview, reason string) (LocalPurgeRun, error)
	ListPurgeRuns(ctx context.Context, limit, offset int) ([]LocalPurgeRun, bool, error)
	PurgeEvidence(ctx context.Context, runID string) ([]LocalPurgeEvidence, error)
}
