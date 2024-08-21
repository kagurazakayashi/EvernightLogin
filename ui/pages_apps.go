package ui

// 步骤 70：指定应用的日常管理页面（资料/成员/安全与接入/凭证/资源许可/状态）。
//
// 安全不变量：
//   - 全部路由 UIAccessManagement：宿主 UISessionService 必须用真实
//     session.AuthorizeManagement 判定完整会话+强认证新鲜度；页面不凭前端状态放行。
//   - 每次读/写由 UIAppsBackend 适配器在服务端重新构造可信 Caller、复核管理授权、
//     应用作用范围与对象行版本；跨应用/越权/root 保护一律 fail-closed。
//   - 应用 ID、ScopeID、客户端类型只读；负责人变更不自动转移任何系统/应用权限。
//   - 成员管理只影响当前应用；页面不提供全局账户密码/Passkey/MFA/恢复代码入口。
//   - 客户端秘密只在登记/轮换成功响应的独立区域出现一次；页面不渲染秘密列表、
//     不回填明文、不写 localStorage/URL/隐藏字段；一次响应由框架 no-store。
//   - 回调/授权方式/Scope/audience/PKCE 使用明确控件；危险回调由真实 oauthclient
//     服务拒绝，页面按字段展示可纠正说明，不部分保存。
//   - 资源与接口/字段许可页（步骤 146）通过可选 UIAppsPolicyBackend 读取真实
//     managedapi 策略，并在受信写入通道 + 一次性强认证绑定时提供受控编辑；未注入
//     可选后端时保持只读，不渲染假开关/mock 成功。
//   - 服务器 TLS 私钥不属于本页面：页面只管理应用自身 OAuth 客户端凭证与公钥证书，
//     不接受私钥材料，未实现的设置显示“尚未启用”。
//   - 应用停用不等于删除；停用/启用显示服务端 Changed 语义，不伪造第二次变更。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// UIPageAppsOptions 是步骤 70 应用管理页配置。
type UIPageAppsOptions struct {
	Backend UIAppsBackend
	// PolicyBackend 是步骤 146 可选策略读写契约；未注入时应用许可页保持只读，
	// 既有 UIAppsBackend 实现无需新增方法（向后兼容）。
	PolicyBackend UIAppsPolicyBackend
	// PolicyReauth 是策略写前置的一次性强认证回调。它必须由宿主在真实管理会话/
	// 再次认证通过后调用，并把同一 app/version/policy-digest/request-id 绑定交给
	// 策略后端；页面表单本身不是授权。
	PolicyReauth func(ctx context.Context, userID string, binding UIAppPolicyActionBinding) error
	// DeleteReauth 是应用逻辑删除前置的再次认证回调（步骤 190）。它必须由宿主用
	// 真实 reauth/policy 链复核并把同一 app/row-version/request-id 绑定交给回调；
	// 未注入时删除入口 fail-closed 拒绝（不渲染可提交表单、不伪造成功）。
	DeleteReauth func(ctx context.Context, userID string, binding UIAppDeleteBinding) error
}

// UIAppDeleteBinding 是应用逻辑删除的再次认证参数绑定：目标应用、行版本与请求编号
// 必须与页面表单一致，确认不是授权，宿主仍要按真实敏感策略判定。
type UIAppDeleteBinding struct {
	ApplicationID      string
	ExpectedRowVersion int64
	RequestID          string
}

// UIApplicationDeleteImpact 是应用删除前影响预览的公开视图。
type UIApplicationDeleteImpact struct {
	Application UIApplicationView
	// CanDelete 表示当前是否可逻辑删除（必须已停用且未删除）；只是交互辅助，
	// 最终判定由领域服务按当前状态重新执行。
	CanDelete   bool
	BlockReason string
	// 以下计数是真实统计，用于展示“执行后失效/保留”的范围，不含秘密或令牌。
	MemberCount               int
	ActiveMemberCount         int
	RoleCount                 int
	PermissionCount           int
	GroupCount                int
	ActiveSessionCount        int
	OAuthClientCount          int
	RefreshTokenFamilyCount   int
	AuthorizationRequestCount int
	CredentialCount           int
	InvitationCount           int
	WebhookEndpointCount      int
	AuditEventCount           int
}

// UIAppsDeleteBackend 是应用删除预览/逻辑删除的可选扩展契约（步骤 190）。与
// UIAppsBackend 分开定义，避免要求既有实现同时新增方法；页面仅在实现该接口时
// 显示删除预览与删除表单，不渲染无法完成操作的静态按钮。
type UIAppsDeleteBackend interface {
	// GetApplicationDeleteImpact 返回删除前影响预览（真实统计 + 是否可删除）。
	GetApplicationDeleteImpact(ctx context.Context, adminID,
		applicationID string) (UIApplicationDeleteImpact, error)
	// DeleteApplication 对已停用应用执行逻辑删除（Changed=false 表示已删除）。
	DeleteApplication(ctx context.Context, adminID, applicationID string,
		expectedRowVersion int64, requestID string) (UIApplicationView, bool, error)
}

// UIAppsBackend 是应用管理页面调用真实 app/oauthclient 服务的最小契约；适配器负责
// 可信 Caller、管理授权、应用范围与行版本复核。页面层不实现授权。
type UIAppsBackend interface {
	ListApplications(ctx context.Context, adminID string, query UIAppQuery) (UIAppPage, error)
	GetApplication(ctx context.Context, adminID, appID string) (UIApplicationView, error)
	UpdateApplication(ctx context.Context, adminID, appID string, change UIApplicationChange,
		expectedRowVersion int64, requestID string) (UIApplicationView, error)
	SetApplicationState(ctx context.Context, adminID, appID string, enable bool,
		expectedRowVersion int64, requestID string) (UIApplicationView, bool, error)

	ListMembers(ctx context.Context, adminID, appID string,
		query UIAppMemberQuery) (UIAppMemberPage, error)
	AddMember(ctx context.Context, adminID, appID, userID string, profile UIAppMemberProfile,
		requestID string) (UIAppMemberView, error)
	UpdateMemberProfile(ctx context.Context, adminID, appID, userID string,
		profile UIAppMemberProfile, expectedRowVersion int64,
		requestID string) (UIAppMemberView, error)
	SetMemberState(ctx context.Context, adminID, appID, userID string, enable bool,
		expectedRowVersion int64, requestID string) (UIAppMemberView, bool, error)
	RemoveMember(ctx context.Context, adminID, appID, userID string, expectedRowVersion int64,
		requestID string) error

	GetOAuthSettings(ctx context.Context, adminID, appID string) (UIOAuthSettings, error)
	RegisterClient(ctx context.Context, adminID, appID string, register UIOAuthRegister,
		requestID string) (UIOAuthRegisterResult, error)
	UpdateClientSettings(ctx context.Context, adminID, appID string, change UIOAuthChange,
		expectedRowVersion int64, requestID string) (UIOAuthSettings, error)
	GetCredentials(ctx context.Context, adminID, appID string) (UIAppCredentials, error)
	RotateSecret(ctx context.Context, adminID, appID, requestID string) (UIAppRevealedSecret, error)
	RevokeSecret(ctx context.Context, adminID, appID, secretID, requestID string) error
	RegisterCertificate(ctx context.Context, adminID, appID, certificatePEM,
		requestID string) (UIAppCertificate, error)
	RevokeCertificate(ctx context.Context, adminID, appID, certificateID, requestID string) error

	// GetManagedPolicy 读取该应用真实的托管管理 API 委托策略（受信读取通道）。
	// 后端未装配/未获准必须返回明确状态与真实原因，不能伪装成“未启用”。
	GetManagedPolicy(ctx context.Context, adminID, appID string) (UIAppPolicyView, error)
}

// UIAppsCreateBackend 是应用管理页的可选新建能力。它单独成接口，避免要求所有
// 既有 UIAppsBackend 测试替身/宿主实现同时新增方法；页面只在后端实现该接口时
// 注册“新建应用”路由并显示入口，不渲染无法完成操作的静态按钮。
type UIAppsCreateBackend interface {
	// CanCreateApplication 返回当前管理员是否具备新建应用的页面能力，仅用于
	// 决定是否显示入口；实际创建仍由领域服务重新授权。依赖失败应返回错误，
	// 页面按“不可用”处理而不是显示按钮。
	CanCreateApplication(ctx context.Context, adminID string) (bool, error)
	// CreateApplication 以当前管理会话身份登记一个应用。应用 ID、作用范围、初始
	// 状态（停用）与行版本由领域服务生成；页面提交的字段只是创建白名单，授权、
	// 负责人资格、审计与失败原子性仍由真实 app.Service 判定。
	CreateApplication(ctx context.Context, adminID string, create UIApplicationCreate,
		requestID string) (UIApplicationView, error)
}

// UIApplicationCreate 是应用新建页提交白名单。应用 ID/状态/行版本/ScopeID 由
// 服务端生成；客户端类型在创建后不可修改。
type UIApplicationCreate struct {
	Name        string
	Description string
	IconRef     string
	Homepage    string
	OwnerUserID string
	ContactInfo string
	ClientType  string
}

// UIAppsError 是应用管理适配层返回的稳定公开错误。
type UIAppsError struct {
	Code              string
	RetryAfterSeconds int
}

// Error 实现 error。
func (e *UIAppsError) Error() string { return "应用管理页面操作失败: " + e.Code }

// UIApplicationCapabilities 是服务端为当前操作者判定的页面能力位（只是交互辅助；
// 每次写操作仍由领域服务重新授权）。
type UIApplicationCapabilities struct {
	// Write 表示可提交资料修改；ChangeOwner 表示可变更负责人（应用管理员恒为
	// false，负责人变化也不转移任何权限）。
	Write       bool
	ChangeOwner bool
	// ManageMembers/ManageSecurity/ManageCredentials 分别对应成员、安全设置、
	// 应用客户端凭证的写操作；读权限由页面是否成功读取体现。
	ManageMembers     bool
	ManageSecurity    bool
	ManageCredentials bool
}

// UIApplicationView 是应用记录公开视图。ID/ScopeID/ClientType 只读。
type UIApplicationView struct {
	ID          string
	ScopeID     string
	Name        string
	Description string
	IconRef     string
	Homepage    string
	OwnerUserID string
	ContactInfo string
	Status      string
	ClientType  string
	RowVersion  int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
	// DeletedAt 非零表示应用已逻辑删除（立即拒绝令牌/会话/客户端/权限判定）。
	DeletedAt time.Time
	// Capabilities 由适配器按当前操作者判定；页面只据此禁用交互，不替代服务端授权。
	Capabilities UIApplicationCapabilities
}

// Deleted 报告视图中的应用是否已逻辑删除。
func (v UIApplicationView) Deleted() bool { return !v.DeletedAt.IsZero() }

// UIAppQuery 是应用列表筛选/分页（排序字段白名单由适配器与服务端校验）。
type UIAppQuery struct {
	Status     string
	Sort       string
	Descending bool
	Limit      int
	Offset     int
}

// UIAppPage 是应用列表分页结果（只有 HasMore，不伪造总数）。
type UIAppPage struct {
	Applications []UIApplicationView
	HasMore      bool
	NextOffset   int
}

// UIApplicationChange 是应用资料更新白名单（不含 ID/客户端类型/状态）。
type UIApplicationChange struct {
	Name        string
	Description string
	IconRef     string
	Homepage    string
	OwnerUserID string
	ContactInfo string
}

// UIAppMemberProfile 是应用内成员资料白名单（不回写全局资料）。
type UIAppMemberProfile struct {
	DisplayName string
	Title       string
	Note        string
}

// UIAppMemberView 是应用成员公开视图：只有稳定用户 ID 与应用内资料/状态。
type UIAppMemberView struct {
	UserID      string
	DisplayName string
	Title       string
	Note        string
	Status      string
	RowVersion  int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// UIAppMemberQuery 是成员列表筛选/分页。
type UIAppMemberQuery struct {
	Status     string
	Sort       string
	Descending bool
	Limit      int
	Offset     int
}

// UIAppMemberPage 是成员列表分页结果。
type UIAppMemberPage struct {
	Members    []UIAppMemberView
	HasMore    bool
	NextOffset int
}

// UIOAuthSettings 是 OAuth 客户端安全设置脱敏视图（永不含秘密）。
type UIOAuthSettings struct {
	// Registered=false 表示该应用尚未登记 OAuth 客户端安全设置。
	Registered             bool
	ClientID               string
	ClientType             string
	GrantTypes             []string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	Scopes                 []string
	Audiences              []string
	AuthMethods            []string
	RequirePKCE            bool
	RowVersion             int64
	CreatedAt              time.Time
	UpdatedAt              time.Time
	// AudienceTrustUnverified 表示当前没有资源服务器信任映射目录可用，页面必须
	// 显示“信任映射未核验”，不能把 audience 写成已受信资源或 client_id。
	AudienceTrustUnverified bool
}

// UIOAuthRegister 是首次登记白名单。客户端类型由应用记录决定，页面不可另选。
type UIOAuthRegister struct {
	GrantTypes             []string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	Scopes                 []string
	Audiences              []string
	AuthMethods            []string
	RequirePKCE            bool
	CertificatePEM         string
}

// UIOAuthChange 是既有安全设置更新白名单（身份验证方式不可随本次修改）。
type UIOAuthChange struct {
	GrantTypes             []string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	Scopes                 []string
	Audiences              []string
	RequirePKCE            bool
}

// UIOAuthRegisterResult 是首次登记结果；Secret 只在本次响应出现一次。
type UIOAuthRegisterResult struct {
	Settings    UIOAuthSettings
	Secret      *UIAppRevealedSecret
	Certificate *UIAppCertificate
}

// UIAppSecretInfo 是客户端密钥非秘密元数据。
type UIAppSecretInfo struct {
	ID        string
	Prefix    string
	CreatedAt time.Time
	ExpiresAt time.Time
	RetireAt  time.Time
	RevokedAt time.Time
	// Status 是服务端按真实时间与元数据派生的展示状态：
	// active/retiring/retired/expired/revoked/unknown。
	Status string
}

// UIAppRevealedSecret 是只在登记/轮换成功响应出现一次的密钥明文。
type UIAppRevealedSecret struct {
	Info   UIAppSecretInfo
	Secret string
}

// UIAppCertificate 是应用客户端公钥证书身份元数据（证书本身是公开材料）。
type UIAppCertificate struct {
	ID                string
	FingerprintSHA256 string
	Subject           string
	NotBefore         time.Time
	NotAfter          time.Time
	CreatedAt         time.Time
	RevokedAt         time.Time
}

// UIAppCredentials 是凭证元数据快照。
type UIAppCredentials struct {
	ClientType string
	// Registered=false 表示该客户端尚未登记安全设置（区分“未登记”与“无密钥”）。
	Registered bool
	// AuthMethods 是真实已登记的客户端身份验证方式；页面据此决定是否展示
	// 轮换密钥/登记证书等真实可用操作（未配置的方式不提供假控件）。
	AuthMethods  []string
	Secrets      []UIAppSecretInfo
	Certificates []UIAppCertificate
}

// UIAppPolicyView 是应用真实托管管理 API 委托策略的只读视图。
//
// State 取值：
//   - "policy"：读到真实策略（操作/对象/字段/上限/版本/更新者）；
//   - "not_configured"：后端确认该应用尚未配置策略（真实未配置，不是“无许可”）；
//   - "unavailable"：页面受信读取通道未装配/未获准，Reason 给出真实原因。
//
// 写入必须由受信管理端完成（受信通道 + 再次认证 + 行版本 + 审计）；页面不提供
// 可提交的写控件。
type UIAppPolicyView struct {
	State          string
	Reason         string
	ApplicationID  string
	RowVersion     int64
	UpdatedBy      string
	Allowed        []UIAppPolicyOperation
	ServiceAllowed []UIAppPolicyOperation
	Objects        []UIAppPolicyObject
	Fields         []UIAppPolicyFields
	Limits         UIAppPolicyLimits
	// Catalog/FieldCatalog/CanWrite 仅用于步骤 146 可写页面；旧只读适配器留空。
	Catalog      []UIAppPolicyOperationCatalog
	FieldCatalog []UIAppPolicyFieldCatalog
	CanWrite     bool
}

// UIAppPolicyOperation 是策略里声明的操作及目录中文说明。
type UIAppPolicyOperation struct {
	ID          string
	Object      string
	Write       bool
	ServiceOK   bool
	Description string
}

// UIAppPolicyObject 是策略里声明的对象数据范围。
type UIAppPolicyObject struct {
	Object    string
	Mode      string
	Resources []string
}

// UIAppPolicyFields 是策略里声明的可读/可写字段白名单。
type UIAppPolicyFields struct {
	Object string
	Read   []string
	Write  []string
}

// UIAppPolicyLimits 是策略里的分页/批量上限。
type UIAppPolicyLimits struct {
	MaxLimit  int
	MaxOffset int
	MaxBatch  int
}

// UIAppsPolicyBackend 是步骤 146 的可选策略读写契约；与 UIAppsBackend 分开定义，
// 避免破坏既有宿主适配器。GetManagedPolicy 与 UIAppsBackend 的同名方法签名一致，
// adapter 同时实现两者即可注入。
type UIAppsPolicyBackend interface {
	GetManagedPolicy(ctx context.Context, adminID, appID string) (UIAppPolicyView, error)
	SetManagedPolicy(ctx context.Context, adminID, appID string, change UIAppPolicyChange,
		expectedRowVersion int64, requestID, policyDigest string) (UIAppPolicyView, error)
}

// UIAppPolicyOperationCatalog 是页面可选择的真实操作目录项（服务端生成，不接受
// 前端自定义操作 ID）。
type UIAppPolicyOperationCatalog struct {
	ID          string
	Object      string
	Description string
	Write       bool
	ServiceOK   bool
}

// UIAppPolicyFieldCatalog 是某对象类型在目录里的可读/可写字段全集（最终仍受
// managedapi 硬禁字段与策略校验约束）。
type UIAppPolicyFieldCatalog struct {
	Object string
	Read   []string
	Write  []string
}

// UIAppPolicyChange 是页面提交的策略变更；执行端会转换为受信策略结构并再次验证。
type UIAppPolicyChange struct {
	Allowed        []string
	ServiceAllowed []string
	Objects        []UIAppPolicyObject
	Fields         []UIAppPolicyFields
	Limits         UIAppPolicyLimits
}

// UIAppPolicyActionBinding 是一次策略写的一次性强认证绑定：应用、行版本与规范化
// 策略摘要 + request_id 必须与真正写入完全一致，旧确认不能复用到另一变更。
// UIAppPolicyForm 是可写许可页的文本域初始值（页面只是编辑辅助；服务端仍严格
// 解析并重新校验）。列表使用换行/逗号分隔，对象/字段规则各占一行。
type UIAppPolicyForm struct {
	Allowed        string
	ServiceAllowed string
	Objects        string
	Fields         string
	MaxLimit       int
	MaxOffset      int
	MaxBatch       int
}

type UIAppPolicyActionBinding struct {
	ApplicationID      string
	ExpectedRowVersion int64
	PolicyDigest       string
	RequestID          string
}

// Digest 返回策略变更的规范化 SHA-256 摘要（十六进制）。页面、适配器与
// managedapi 一次性批准使用同一摘要，避免确认后替换策略内容。
func (c UIAppPolicyChange) Digest() string {
	canonical := struct {
		Allowed        []string
		ServiceAllowed []string
		Objects        []UIAppPolicyObject
		Fields         []UIAppPolicyFields
		Limits         UIAppPolicyLimits
	}{
		Allowed:        append([]string{}, c.Allowed...),
		ServiceAllowed: append([]string{}, c.ServiceAllowed...),
		Objects:        append([]UIAppPolicyObject{}, c.Objects...),
		Fields:         append([]UIAppPolicyFields{}, c.Fields...),
		Limits:         c.Limits,
	}
	sort.Strings(canonical.Allowed)
	sort.Strings(canonical.ServiceAllowed)
	for index := range canonical.Objects {
		canonical.Objects[index].Resources = append([]string{},
			canonical.Objects[index].Resources...)
		sort.Strings(canonical.Objects[index].Resources)
	}
	sort.Slice(canonical.Objects, func(i, j int) bool {
		return canonical.Objects[i].Object < canonical.Objects[j].Object
	})
	for index := range canonical.Fields {
		canonical.Fields[index].Read = append([]string{}, canonical.Fields[index].Read...)
		canonical.Fields[index].Write = append([]string{}, canonical.Fields[index].Write...)
		sort.Strings(canonical.Fields[index].Read)
		sort.Strings(canonical.Fields[index].Write)
	}
	sort.Slice(canonical.Fields, func(i, j int) bool {
		return canonical.Fields[i].Object < canonical.Fields[j].Object
	})
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

// UIAppsFieldDiff 是资料/安全设置本次实际生效的差异行。
type UIAppsFieldDiff struct {
	Field  string
	Before string
	After  string
}

// newPageAppsPages 构造步骤 70 路由/处理器。
func newPageAppsPages(options UIPageAppsOptions) (*pageAppsPages, error) {
	if isNilUIValue(options.Backend) {
		return nil, fmt.Errorf("应用管理页面缺少后端适配器")
	}
	pages := &pageAppsPages{handlers: map[string]UIPageHandler{}, options: options}
	handler := &appsPageHandlers{pages: pages}
	routes := []UIRoute{
		{Name: "admin.applications", Method: http.MethodGet, Path: "/admin/applications",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/applications"},
		{Name: "admin.application_profile", Method: http.MethodGet,
			Path: "/admin/applications/profile", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/application_profile"},
		{Name: "admin.application_profile.submit", Method: http.MethodPost,
			Path: "/admin/applications/profile", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/application_profile"},
		{Name: "admin.application_members", Method: http.MethodGet,
			Path: "/admin/applications/members", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/application_members"},
		{Name: "admin.application_members.submit", Method: http.MethodPost,
			Path: "/admin/applications/members", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/application_members"},
		{Name: "admin.application_security", Method: http.MethodGet,
			Path: "/admin/applications/security", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/application_security"},
		{Name: "admin.application_security.submit", Method: http.MethodPost,
			Path: "/admin/applications/security", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/application_security"},
		{Name: "admin.application_credentials", Method: http.MethodGet,
			Path: "/admin/applications/credentials", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/application_credentials"},
		{Name: "admin.application_credentials.submit", Method: http.MethodPost,
			Path: "/admin/applications/credentials", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/application_credentials"},
		{Name: "admin.application_grants", Method: http.MethodGet,
			Path: "/admin/applications/grants", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/application_grants"},
		{Name: "admin.application_grants.submit", Method: http.MethodPost,
			Path: "/admin/applications/grants", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/application_grants"},
		{Name: "admin.application_status", Method: http.MethodGet,
			Path: "/admin/applications/status", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/application_status"},
		{Name: "admin.application_status.submit", Method: http.MethodPost,
			Path: "/admin/applications/status", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/application_status"},
	}
	// 新建应用是可选能力：只有真实后端实现 UIAppsCreateBackend 时才注册路由与
	// 入口，避免页面出现点了却无法执行的静态按钮。新建后应用默认停用，启用与
	// 客户端凭证仍需走各自的受控页面/服务。
	if _, ok := options.Backend.(UIAppsCreateBackend); ok {
		routes = append(routes,
			UIRoute{Name: "admin.application_create", Method: http.MethodGet,
				Path: "/admin/applications/create", Access: UIAccessManagement,
				Layout: "layout/base", Template: "page/admin/application_create"},
			UIRoute{Name: "admin.application_create.submit", Method: http.MethodPost,
				Path: "/admin/applications/create", Access: UIAccessManagement,
				Layout: "layout/base", Template: "page/admin/application_create"},
		)
	}
	// 应用逻辑删除是步骤 190 的可选能力：只有真实后端实现 UIAppsDeleteBackend
	// 时才注册删除路由（预览随状态页展示），避免静态按钮。
	if _, ok := options.Backend.(UIAppsDeleteBackend); ok {
		routes = append(routes,
			UIRoute{Name: "admin.application_delete", Method: http.MethodPost,
				Path: "/admin/applications/status/delete", Access: UIAccessManagement,
				Layout: "layout/base", Template: "page/admin/application_status"},
		)
	}
	for _, route := range routes {
		pages.routes = append(pages.routes, route)
		pages.handlers[route.Name] = handler
	}
	return pages, nil
}

// pageAppsPages 是应用管理页实现。
type pageAppsPages struct {
	routes   []UIRoute
	handlers map[string]UIPageHandler
	options  UIPageAppsOptions
}

// appsErrorOutcome 把适配器错误映射为稳定状态/已翻译文案。
func appsErrorOutcome(err error, data any, fallbackKey string) UIPageOutcome {
	outcome := UIPageOutcome{Data: data, StatusCode: http.StatusBadRequest,
		ErrorSummary: text(fallbackKey)}
	var publicErr *UIAppsError
	if errors.As(err, &publicErr) {
		outcome.ErrorCode = publicErr.Code
		switch publicErr.Code {
		case "ACCESS_DENIED":
			outcome.StatusCode = http.StatusForbidden
			outcome.ErrorSummary = text("page.admin.applications.common.forbidden")
		case "PERMISSION_REQUIRED", "RESOURCE_FORBIDDEN", "APP_MEMBERSHIP_REQUIRED",
			"APP_SCOPE_MISMATCH":
			outcome.StatusCode = http.StatusForbidden
			outcome.ErrorSummary = text("page.admin.applications.common.permission_required")
		case "REAUTH_REQUIRED", "MFA_REQUIRED":
			outcome.StatusCode = http.StatusForbidden
			outcome.ErrorSummary = text("page.admin.applications.common.reauth_required")
		case "CONFLICT":
			outcome.StatusCode = http.StatusConflict
			outcome.ErrorSummary = text("page.admin.applications.common.conflict")
		case "CLIENT_DISABLED":
			outcome.StatusCode = http.StatusConflict
			outcome.ErrorSummary = text("page.admin.applications.common.client_disabled")
		case "USER_DISABLED":
			outcome.StatusCode = http.StatusConflict
			outcome.ErrorSummary = text("page.admin.applications.common.user_disabled")
		case "RATE_LIMITED":
			outcome.StatusCode = http.StatusTooManyRequests
			outcome.ErrorSummary = text("common.state.rate_limited")
		case "AUTHZ_UNAVAILABLE", "DB_UNAVAILABLE", "AUDIT_WRITE_FAILED":
			outcome.StatusCode = http.StatusServiceUnavailable
			outcome.ErrorSummary = text("page.admin.applications.common.unavailable")
		case "REQ_INVALID":
			outcome.StatusCode = http.StatusBadRequest
			outcome.ErrorSummary = text(fallbackKey)
		default:
			outcome.StatusCode = http.StatusInternalServerError
			outcome.ErrorSummary = text("common.state.error")
		}
	}
	return outcome
}

// appsQueryAppID 读取并校验页面应用上下文 ID（只作为定位依据，不作为授权依据）。
func appsQueryAppID(request *http.Request) (string, bool) {
	value := strings.TrimSpace(request.URL.Query().Get("app_id"))
	if value == "" {
		return "", false
	}
	if len(value) > 128 || strings.ContainsAny(value, "\r\n\x00") {
		return "", false
	}
	return value, true
}

// appsParseOffset 解析非负分页偏移。
func appsParseOffset(raw string) (int, bool) {
	if raw == "" {
		return 0, true
	}
	offset, err := strconv.Atoi(raw)
	if err != nil || offset < 0 || offset > 1_000_000 {
		return 0, false
	}
	return offset, true
}

// appsParseRowVersion 解析行版本（必须为正整数）。
func appsParseRowVersion(raw string) (int64, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, false
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return 0, false
	}
	return parsed, true
}

// appsLines 把多行文本拆为去空行、去首尾空白的列表；超出上限返回错误。
func appsLines(raw string, maxItems, maxBytes int) ([]string, bool) {
	if len(raw) > maxBytes {
		return nil, false
	}
	var result []string
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		result = append(result, line)
		if len(result) > maxItems {
			return nil, false
		}
	}
	return result, true
}

// appsChecked 读取显式复选框（值为 1/yes 表示选中）。
func appsChecked(values url.Values, key string) bool {
	value := strings.TrimSpace(values.Get(key))
	return value == "1" || value == "yes" || value == "on"
}

// builtinAppsMessages 是应用管理页摘要使用的中文基线（模板静态文案仍走 i18n 键）。
var builtinAppsMessages = map[string]string{
	"page.admin.applications.common.forbidden":             "你没有管理该应用的权限，或管理强认证已过期；服务端已拒绝",
	"page.admin.applications.grants.invalid":               "策略表单格式不正确；请按帮助格式填写操作、对象范围与字段规则",
	"page.admin.applications.grants.save_failed":           "策略保存失败；未写入任何变更，请根据错误摘要修正后重试",
	"page.admin.applications.grants.write_unavailable":     "当前部署未装配受信策略写入或一次性强认证通道，页面不允许保存",
	"page.admin.applications.common.reauth_required":       "该操作需要重新完成强认证，请按提示重新验证；确认框本身不是授权",
	"page.admin.applications.common.conflict":              "数据或凭证状态已变化，请重新读取并比较后再试",
	"page.admin.applications.common.client_disabled":       "此应用已停用，当前操作不可用；停用不等于删除",
	"page.admin.applications.common.user_disabled":         "目标全局账户当前不可加入或启用为应用成员；不能绕过全局账户状态",
	"page.admin.applications.common.unavailable":           "服务暂时无法完成请求（授权/存储/审计不可用），操作按未完成处理",
	"page.admin.applications.common.permission_required":   "缺少该操作的委派资格或当前不持有对应权限；服务端已拒绝，成员关系与权限没有被改动",
	"page.admin.applications.list.load_failed":             "无法读取可管理的应用列表",
	"page.admin.applications.profile.load_failed":          "无法读取该应用资料",
	"page.admin.applications.profile.invalid":              "应用资料请求未通过校验，请按字段说明修改",
	"page.admin.applications.profile.save_failed":          "应用资料保存未完成；服务端已重新校验权限、字段白名单与行版本",
	"page.admin.applications.profile.no_changes":           "没有需要保存的更改",
	"page.admin.applications.profile.owner_denied":         "应用管理员不能变更负责人；变更负责人也不会自动转移任何权限",
	"page.admin.applications.members.load_failed":          "无法读取该应用成员列表",
	"page.admin.applications.members.invalid":              "成员请求未通过校验，请按字段说明修改",
	"page.admin.applications.members.add_failed":           "添加成员未完成；目标账户状态、应用状态、重复成员与可转授权限由服务端校验",
	"page.admin.applications.members.profile_failed":       "保存应用内成员资料未完成",
	"page.admin.applications.members.state_failed":         "成员启停未完成",
	"page.admin.applications.members.remove_failed":        "移除成员关系未完成",
	"page.admin.applications.members.confirm_required":     "请先确认成员启停/移除的实际目标与影响",
	"page.admin.applications.security.load_failed":         "无法读取该应用 OAuth 客户端安全设置",
	"page.admin.applications.security.invalid":             "安全设置请求未通过校验，请按字段说明修改",
	"page.admin.applications.security.register_failed":     "登记 OAuth 客户端安全设置未完成；危险回调与服务端校验由真实接口拒绝",
	"page.admin.applications.security.update_failed":       "保存安全设置未完成；身份验证方式不能随本次修改，行版本冲突需重新读取",
	"page.admin.applications.security.confirm_required":    "请先确认本次安全设置的实际目标、作用范围与完整差异",
	"page.admin.applications.credentials.load_failed":      "无法读取该应用客户端凭证元数据",
	"page.admin.applications.credentials.invalid":          "凭证请求未通过校验",
	"page.admin.applications.credentials.rotate_failed":    "轮换客户端秘密未完成；结果未知时请先重新读取凭证状态，不要重复轮换",
	"page.admin.applications.credentials.revoke_failed":    "撤销客户端凭证未完成；最后一个可用凭证由服务端拒绝",
	"page.admin.applications.credentials.confirm_required": "请先确认目标凭证、当前状态与撤销/轮换后果",
	"page.admin.applications.status.load_failed":           "无法读取该应用状态",
	"page.admin.applications.status.invalid":               "应用状态请求未通过校验",
	"page.admin.applications.status.change_failed":         "应用状态变更未完成；服务端会重新校验权限与可转授范围",
	"page.admin.applications.status.confirm_required":      "请先确认停用/启用的实际目标、作用范围与后果",
	"page.admin.applications.delete.invalid":               "应用删除请求未通过校验（缺少目标、行版本或确认）",
	"page.admin.applications.delete.confirm_required":      "请先确认目标应用、行版本与不可恢复的影响",
	"page.admin.applications.delete.reauth_required":       "应用删除需要重新完成强认证；确认框本身不是授权",
	"page.admin.applications.delete.forbidden":             "你没有删除该应用的权限，或管理强认证/再认证未通过；服务端已拒绝",
	"page.admin.applications.delete.unavailable":           "当前页面后端未提供应用删除能力；未注册删除入口，不会伪造成功",
	"page.admin.applications.delete.reauth_unavailable":    "当前部署未装配应用删除的再次认证通道，删除入口已关闭（fail-closed）",
	"page.admin.applications.delete.impact_unavailable":    "当前无法读取删除影响预览；实际删除仍由服务端按当前状态重新校验，不会伪造成功",
	"page.admin.applications.delete.failed":                "应用删除未完成；必须已停用、行版本未变化且再认证通过，服务端已重新校验",
	"page.admin.applications.grants.load_failed":           "无法读取该应用上下文，因此不能展示资源许可状态",
	"page.admin.applications.invalid_app":                  "应用 ID 缺失或格式无效；请从应用列表重新进入",
}

func init() {
	for key, message := range builtinAppsMessages {
		if _, exists := builtinAuthMessages[key]; !exists {
			builtinAuthMessages[key] = message
		}
	}
}
