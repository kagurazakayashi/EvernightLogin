// Package authz 实现有效权限计算、数据范围交集与权限来源查询。
//
// 本包是内部授权计算引擎，不提供 HTTP 端点。它只回答“当前主体在指定作用范围
// （系统或某个应用）现在实际拥有哪些权限、权限来自哪里、数据范围是什么”，不实现
// OAuth 令牌联合校验（后续协议步骤复用本包判断），也不实现角色/权限/组的管理
// 写入（分别由 internal/role、internal/permission、internal/group 负责）。
//
// 安全不变量：
//   - 禁用优先：账户非 active、应用非 active、应用成员缺失/非 active 时整体拒绝，
//     不因为角色或权限存在而放行；root 账户不通过普通权限引擎推导权限（root 走
//     后续受保护通道），直接按 ACCESS_DENIED 拒绝。
//   - 生效条件：角色必须 enabled、权限必须 enabled 且非 root_only、角色分配范围
//     必须与目标作用范围一致；直接用户角色与用户组成员角色合并，但数据范围取
//     交集（来源越多不会扩大数据范围）。
//   - 未知权限拒绝；all/any 默认 all，any 中出现未知/停用/root_only 权限仍拒绝。
//   - 每次计算在同一数据库事务快照中读取账户、应用、成员、角色、权限与分配，
//     不缓存权限结果，也不使用过期缓存；并发变更下结果要么是旧快照要么是新快照，
//     不会出现半更新组合。
//   - 查询别人的有效权限/来源必须通过 Authorizer：普通用户只能查自己；应用管理员
//     只能查自己获准应用内的成员；本地/系统操作者可查任意普通主体。未获准时返回
//     ACCESS_DENIED，不泄露目标是否存在。
//   - 业务资源归属不能从权限名推断：资源检查必须显式传入权限与资源标识，并只依据
//     本包计算出的数据范围交集判断；数据范围为 undefined（步骤 24 的历史 `{}`）
//     或 none 时资源检查默认拒绝。
//   - 单个权限的候选来源超过 MaxSourceRows 时无法证明数据范围交集完整：Check、
//     CheckResourceAccess 与 EffectivePermissions 一律 fail-closed（AUTHZ_UNAVAILABLE
//     并在结果中置 SourceLimitReached），不会用前 512 个来源的交集放行资源。
package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
)

const (
	// MaxRequirements 是单次权限检查的权限数量上限。
	MaxRequirements = 32
	// DefaultListLimit/MaxListLimit 是有效权限/来源查询分页边界。
	DefaultListLimit = 20
	MaxListLimit     = 100
	// MaxListOffset 限制深分页。
	MaxListOffset = 1_000_000
	// MaxSourceRows 是单次来源查询读取的候选来源行数上限。
	MaxSourceRows = 512
	// MaxDataScopeResources 是单个数据范围声明的最大资源数量。
	MaxDataScopeResources = 64
	// MaxResourceIDBytes 是资源标识长度上限。
	MaxResourceIDBytes = 256
)

// ScopeKind 是授权作用范围类型（系统或应用）。
type ScopeKind string

const (
	// ScopeKindSystem 表示系统范围。
	ScopeKindSystem ScopeKind = "system"
	// ScopeKindApplication 表示应用范围。
	ScopeKindApplication ScopeKind = "application"
)

// Scope 是已校验的授权作用范围。
type Scope struct {
	// ID 是 scope ID：系统固定 "system"，应用为应用 ID。
	ID string
	// Kind 是范围类型。
	Kind ScopeKind
	// ApplicationID 是应用范围对应的应用 ID；系统范围为空。
	ApplicationID string
}

// ParseScope 解析作用范围：只接受 "system" 或有效应用 ID。
func ParseScope(raw string) (Scope, error) {
	kind, applicationID, err := permission.ParseScope(strings.TrimSpace(raw))
	if err != nil {
		return Scope{}, fmt.Errorf("%w: 作用范围必须是 system 或有效应用 ID", ErrInvalidRequest)
	}
	if kind == permission.ScopeKindSystem {
		return Scope{ID: permission.ScopeSystem, Kind: ScopeKindSystem}, nil
	}
	return Scope{ID: applicationID, Kind: ScopeKindApplication, ApplicationID: applicationID}, nil
}

// IsSystem 报告作用范围是否为系统范围。
func (s Scope) IsSystem() bool {
	return s.Kind == ScopeKindSystem
}

// Mode 是 all/any 权限组合模式。
type Mode string

const (
	// ModeAll 要求全部权限都满足（默认）。
	ModeAll Mode = "all"
	// ModeAny 允许任一权限满足即可。
	ModeAny Mode = "any"
)

// Valid 报告模式是否已定义。
func (m Mode) Valid() bool {
	return m == ModeAll || m == ModeAny
}

// DataScopeMode 是数据范围模式。
//
// 数据范围与功能权限分开：功能权限说明“能不能做某类操作”，数据范围说明“能影响
// 哪些数据”。当前只定义第一版显式契约，分配写入接口尚不允许设置数据范围；步骤 24
// 及更早写入的 data_scope_json='{}' 按 historical(undefined) 解释：功能权限可用，
// 但资源级检查默认拒绝，避免把“未声明”当成“全部数据”。
type DataScopeMode string

const (
	// DataScopeUndefined 表示未声明数据范围（历史 `{}`/空值）；资源检查默认拒绝。
	DataScopeUndefined DataScopeMode = "undefined"
	// DataScopeAll 表示该权限不限制数据范围。
	DataScopeAll DataScopeMode = "all"
	// DataScopeNone 表示该权限不允许访问任何数据。
	DataScopeNone DataScopeMode = "none"
	// DataScopeResources 表示仅允许访问明确列出的资源集合。
	DataScopeResources DataScopeMode = "resources"
)

// DataScope 是数据范围契约。Resources 在 DataScopeResources 模式下是去重排序后的
// 资源标识；多个来源合并时取交集（越合并越窄）。
type DataScope struct {
	Mode      DataScopeMode
	Resources []string
	// LegacyUndefined 表示来自历史 `{}` 未声明数据；与 Undefined 同义，供诊断区分。
	LegacyUndefined bool
}

// Empty 报告数据范围是否未声明/为空。
func (d DataScope) Empty() bool {
	return d.Mode == "" || d.Mode == DataScopeUndefined
}

// IntersectDataScopes 合并多个来源的数据范围（供引擎与测试使用）：undefined 优先
// 保持 undefined；none 最严格；all 不限制；resources 取交集。
func IntersectDataScopes(scopes ...DataScope) DataScope {
	return intersectDataScopes(scopes)
}

// intersectDataScopes 合并多个来源的数据范围：undefined 优先保持 undefined；
// none 最严格；all 不限制；resources 取交集。来源越多不会扩大数据范围。
func intersectDataScopes(scopes []DataScope) DataScope {
	if len(scopes) == 0 {
		return DataScope{Mode: DataScopeUndefined, LegacyUndefined: true}
	}
	result := scopes[0]
	for _, next := range scopes[1:] {
		result = intersectPair(result, next)
	}
	return result
}

// intersectPair 计算两个数据范围的交集。
func intersectPair(left, right DataScope) DataScope {
	if left.Mode == DataScopeNone || right.Mode == DataScopeNone {
		// none 是最严格限制，即使另一个来源未声明数据范围也交集为 none。
		return DataScope{Mode: DataScopeNone}
	}
	if left.Empty() || right.Empty() {
		return DataScope{Mode: DataScopeUndefined, LegacyUndefined: left.LegacyUndefined || right.LegacyUndefined}
	}
	if left.Mode == DataScopeAll {
		return right
	}
	if right.Mode == DataScopeAll {
		return left
	}
	// 两者都是 resources：取交集。
	rightSet := make(map[string]struct{}, len(right.Resources))
	for _, resource := range right.Resources {
		rightSet[resource] = struct{}{}
	}
	common := make([]string, 0, len(left.Resources))
	for _, resource := range left.Resources {
		if _, ok := rightSet[resource]; ok {
			common = append(common, resource)
		}
	}
	if len(common) == 0 {
		return DataScope{Mode: DataScopeNone, Resources: []string{}}
	}
	return DataScope{Mode: DataScopeResources, Resources: common}
}

// AllowsResource 报告数据范围是否允许访问指定资源；undefined/none 默认拒绝。
func (d DataScope) AllowsResource(resourceID string) bool {
	switch d.Mode {
	case DataScopeAll:
		return true
	case DataScopeResources:
		for _, resource := range d.Resources {
			if resource == resourceID {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// dataScopeDocument 是 data_scope_json 的规范结构。
type dataScopeDocument struct {
	Version   int      `json:"v"`
	Mode      string   `json:"mode"`
	Resources []string `json:"resources,omitempty"`
}

// ParseDataScope 解析 data_scope_json。空值、"{}" 与 "null" 按历史未声明处理；
// 除此之外只接受当前版本的严格结构（禁止未知字段/重复资源/非法资源标识）。
func ParseDataScope(raw string) (DataScope, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "{}" || trimmed == "null" {
		return DataScope{Mode: DataScopeUndefined, LegacyUndefined: true}, nil
	}
	if len(trimmed) > 8192 {
		return DataScope{}, fmt.Errorf("%w: 数据范围声明过长", ErrInvalidRequest)
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(trimmed)))
	decoder.DisallowUnknownFields()
	var document dataScopeDocument
	if err := decoder.Decode(&document); err != nil {
		return DataScope{}, fmt.Errorf("%w: 数据范围不是合法 JSON", ErrInvalidRequest)
	}
	if err := ensureJSONDocumentEnd(decoder); err != nil {
		return DataScope{}, err
	}
	if document.Version != 1 {
		return DataScope{}, fmt.Errorf("%w: 数据范围版本不受支持", ErrInvalidRequest)
	}
	switch DataScopeMode(document.Mode) {
	case DataScopeAll, DataScopeNone:
		if len(document.Resources) != 0 {
			return DataScope{}, fmt.Errorf("%w: all/none 数据范围不能包含资源列表", ErrInvalidRequest)
		}
		return DataScope{Mode: DataScopeMode(document.Mode)}, nil
	case DataScopeResources:
		if len(document.Resources) == 0 || len(document.Resources) > MaxDataScopeResources {
			return DataScope{}, fmt.Errorf("%w: resources 数据范围资源数量必须是 1～%d", ErrInvalidRequest, MaxDataScopeResources)
		}
		seen := make(map[string]struct{}, len(document.Resources))
		resources := make([]string, 0, len(document.Resources))
		for _, resource := range document.Resources {
			if problem := validateResourceID(resource); problem != "" {
				return DataScope{}, fmt.Errorf("%w: %s", ErrInvalidRequest, problem)
			}
			if _, duplicated := seen[resource]; duplicated {
				return DataScope{}, fmt.Errorf("%w: 数据范围资源重复", ErrInvalidRequest)
			}
			seen[resource] = struct{}{}
			resources = append(resources, resource)
		}
		sortStrings(resources)
		return DataScope{Mode: DataScopeResources, Resources: resources}, nil
	default:
		return DataScope{}, fmt.Errorf("%w: 数据范围模式无效", ErrInvalidRequest)
	}
}

// ensureJSONDocumentEnd 确认 JSON 文档没有尾随内容。
func ensureJSONDocumentEnd(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return fmt.Errorf("%w: 数据范围包含多余内容", ErrInvalidRequest)
}

// validateResourceID 校验资源标识：非空、≤256 字节、无控制字符或首尾空白。
func validateResourceID(resource string) string {
	if resource == "" {
		return "资源标识不能为空"
	}
	if len(resource) > MaxResourceIDBytes {
		return fmt.Sprintf("资源标识不能超过 %d 字节", MaxResourceIDBytes)
	}
	if strings.TrimSpace(resource) != resource {
		return "资源标识不能包含首尾空白"
	}
	for _, character := range resource {
		if character < 0x20 || character == 0x7f {
			return "资源标识包含控制字符"
		}
	}
	return ""
}

// sortStrings 对字符串列表做稳定排序。
func sortStrings(values []string) {
	for index := 1; index < len(values); index++ {
		for position := index; position > 0 && values[position] < values[position-1]; position-- {
			values[position], values[position-1] = values[position-1], values[position]
		}
	}
}

// AccountInfo 是计算前读取的账户状态快照。
type AccountInfo struct {
	UserID string
	Status account.Status
	IsRoot bool
	// ValidFrom/ValidUntil 是全局账户有效期 UTC 半开区间；nil 表示该端不限制。
	// 授权引擎在每次判定时即时读取并拒绝到期/未开始账户，不依赖定时扫描。
	ValidFrom  *time.Time
	ValidUntil *time.Time
}

// ApplicationInfo 是应用状态快照。
type ApplicationInfo struct {
	ApplicationID string
	Status        app.Status
}

// MembershipInfo 是应用成员状态快照。
type MembershipInfo struct {
	ApplicationID string
	UserID        string
	Status        app.MembershipStatus
	Found         bool
}

// PermissionInfo 是目标范围内的权限目录快照。
type PermissionInfo struct {
	PermissionID string
	ScopeID      string
	Key          string
	Name         string
	Enabled      bool
	RootOnly     bool
}

// SourceKind 是权限来源类型。
type SourceKind string

const (
	// SourceKindUserRole 表示直接分配给用户的角色。
	SourceKindUserRole SourceKind = "user_role"
	// SourceKindGroupRole 表示通过用户组成员身份获得的角色。
	SourceKindGroupRole SourceKind = "group_role"
)

// GrantSource 是候选权限来源（可能被停用/排除）。
type GrantSource struct {
	PermissionID       string
	PermissionKey      string
	PermissionName     string
	PermissionEnabled  bool
	PermissionRootOnly bool
	RoleID             string
	RoleKey            string
	RoleName           string
	RoleEnabled        bool
	ScopeID            string
	Kind               SourceKind
	GroupID            string
	GroupKey           string
	GroupName          string
	DataScopeJSON      string
	AssignedBy         string
	CreatedAt          time.Time
}

// SourceSummary 是权限来源的脱敏说明。
type SourceSummary struct {
	Kind              SourceKind
	RoleID            string
	RoleKey           string
	RoleName          string
	RoleEnabled       bool
	GroupID           string
	GroupKey          string
	GroupName         string
	PermissionID      string
	PermissionKey     string
	PermissionName    string
	PermissionEnabled bool
	RootOnly          bool
	DataScope         DataScope
	Included          bool
	ExcludedReason    string
	AssignedBy        string
	CreatedAt         time.Time
}

// CheckRequest 是权限检查请求。SubjectUserID 是被检查主体；用户调用者只能检查
// 自己，本地/系统操作者可显式检查普通主体。
type CheckRequest struct {
	SubjectUserID string
	ScopeID       string
	Permissions   []string
	Mode          Mode
}

// PermissionDecision 是单个权限的判定结果与来源。
type PermissionDecision struct {
	Key       string
	Allowed   bool
	Code      ErrorCode
	Reason    string
	Sources   []SourceSummary
	DataScope DataScope
	// SourceLimitReached 表示候选来源达到 MaxSourceRows 上限、结果不完整；此时
	// Allowed 必定为 false（fail-closed），调用方不能把它当作已授予。
	SourceLimitReached bool
}

// CheckResult 是权限检查整体结果。Code 为空表示允许；依赖不可用时返回
// AUTHZ_UNAVAILABLE 并保持 Allowed=false（调用方必须默认拒绝）。
type CheckResult struct {
	SubjectUserID string
	Scope         Scope
	Mode          Mode
	Allowed       bool
	Code          ErrorCode
	Reason        string
	Permissions   []PermissionDecision
	// SourceLimitReached 表示任一被检查权限的候选来源被截断，结果不完整；此时
	// Allowed 必定为 false（fail-closed），资源检查同样拒绝。
	SourceLimitReached bool
}

// EffectivePermission 是有效权限目录中的一条权限及来源。
type EffectivePermission struct {
	Key       string
	Name      string
	ScopeID   string
	DataScope DataScope
	Sources   []SourceSummary
}

// EffectiveResult 是有效权限分页查询结果。状态字段说明被哪些账户/应用/成员状态
// 限制；DeniedCode 非空时 Permissions 为空。
type EffectiveResult struct {
	SubjectUserID     string
	Scope             Scope
	AccountStatus     account.Status
	ApplicationStatus app.Status
	MembershipStatus  app.MembershipStatus
	DeniedCode        ErrorCode
	DeniedReason      string
	Permissions       []EffectivePermission
	HasMore           bool
	// SourceLimitReached 表示单次来源读取达到 MaxSourceRows 上限；此时该页来源/
	// 数据范围交集可能不完整，调用方应减少目标权限数量或分页查询来源，不能把它
	// 当作完整授权结论。
	SourceLimitReached bool
}

// SourceResult 是权限来源查询结果，包含被停用/被状态限制的候选来源。
type SourceResult struct {
	SubjectUserID     string
	Scope             Scope
	AccountStatus     account.Status
	ApplicationStatus app.Status
	MembershipStatus  app.MembershipStatus
	PermissionKey     string
	PermissionName    string
	PermissionFound   bool
	Sources           []SourceSummary
	HasMore           bool
}

// ResourceDecision 是显式资源级判定结果。
type ResourceDecision struct {
	Allowed    bool
	Code       ErrorCode
	Reason     string
	Permission string
	ResourceID string
	DataScope  DataScope
}

// ListOptions 是有效权限/来源查询的分页参数。
type ListOptions struct {
	Limit  int
	Offset int
}

// ErrorCode 与根包错误码注册表一致的字面值；根包测试核对登记状态。
type ErrorCode string

const (
	CodeReqInvalid            ErrorCode = "REQ_INVALID"
	CodeAccessDenied          ErrorCode = "ACCESS_DENIED"
	CodeUserDisabled          ErrorCode = "USER_DISABLED"
	CodeClientDisabled        ErrorCode = "CLIENT_DISABLED"
	CodeAppMembershipRequired ErrorCode = "APP_MEMBERSHIP_REQUIRED"
	CodePermissionRequired    ErrorCode = "PERMISSION_REQUIRED"
	CodePermissionDisabled    ErrorCode = "PERMISSION_DISABLED"
	CodePermissionUnknown     ErrorCode = "PERMISSION_UNKNOWN"
	CodeAppScopeMismatch      ErrorCode = "APP_SCOPE_MISMATCH"
	CodeResourceForbidden     ErrorCode = "RESOURCE_FORBIDDEN"
	CodeAuthzUnavailable      ErrorCode = "AUTHZ_UNAVAILABLE"
	CodeDBUnavailable         ErrorCode = "DB_UNAVAILABLE"
	CodeInternalError         ErrorCode = "INTERNAL_ERROR"
)

// 领域错误哨兵。
var (
	ErrOptionsInvalid   = errors.New("授权引擎选项无效")
	ErrInvalidRequest   = errors.New("授权请求无效")
	ErrAccessDenied     = errors.New("未获准查询该主体的权限")
	ErrSubjectNotFound  = errors.New("被查询账户不存在")
	ErrRootProtected    = errors.New("root 账户不通过普通权限引擎推导权限")
	ErrStoreUnavailable = errors.New("权限存储暂时不可用")
)

// CodeOf 把授权引擎错误映射到已登记错误码。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrSubjectNotFound):
		return CodeReqInvalid
	case errors.Is(err, ErrAccessDenied), errors.Is(err, ErrRootProtected):
		return CodeAccessDenied
	case errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	default:
		return CodeInternalError
	}
}

// Caller 是可信调用者上下文；字段不导出，只能由构造器生成。
type Caller struct {
	actor     audit.Actor
	requestID string
}

// LocalBootstrapCaller 构造受限本地初始化操作者。
func LocalBootstrapCaller(operatorID string) (Caller, error) {
	return newCaller(audit.ActorLocalAdmin, operatorID)
}

// SystemCaller 构造系统组件操作者。
func SystemCaller(componentID string) (Caller, error) {
	return newCaller(audit.ActorSystem, componentID)
}

// UserCaller 构造已认证用户操作者。
func UserCaller(userID string) (Caller, error) {
	if !account.ValidUserID(userID) {
		return Caller{}, fmt.Errorf("%w: 用户 ID 格式无效", ErrInvalidRequest)
	}
	return newCaller(audit.ActorUser, userID)
}

// newCaller 校验并构造调用者。
func newCaller(kind audit.ActorKind, id string) (Caller, error) {
	actor := audit.Actor{Type: kind, ID: id}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 操作者标识无效", ErrInvalidRequest)
	}
	return Caller{actor: actor}, nil
}

// Actor 返回调用者的可信审计身份（只读副本）。
//
// 这是宿主授权适配层识别调用者所需的最小只读查询能力：授权器看不到不可见
// 字段，无法判断主体；该访问器不允许修改身份，也不暴露请求编号。
func (c Caller) Actor() audit.Actor { return c.actor }

// WithRequestID 返回带请求编号的调用者副本（验证与角色包一致）。
func (c Caller) WithRequestID(requestID string) (Caller, error) {
	if requestID != "" {
		if len(requestID) > 64 {
			return Caller{}, fmt.Errorf("%w: 请求编号过长", ErrInvalidRequest)
		}
		for index := 0; index < len(requestID); index++ {
			character := requestID[index]
			if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') || character == '.' ||
				character == '_' || character == '-' {
				continue
			}
			return Caller{}, fmt.Errorf("%w: 请求编号包含非法字符", ErrInvalidRequest)
		}
	}
	c.requestID = requestID
	return c, nil
}

// Authorizer 判定调用者能否查询指定主体的有效权限/来源。策略引擎未完成前只提供
// 显式 StaticAuthorizer；缺少 Authorizer 时引擎不可构造，不放行。
type Authorizer interface {
	AuthorizeQuery(ctx context.Context, caller Caller, subjectUserID string, scope Scope) error
}

// AuthorizerOptions 是 StaticAuthorizer 的显式配置。
type AuthorizerOptions struct {
	LocalAdminIDs     []string
	SystemIDs         []string
	ApplicationAdmins map[string][]string
}

// StaticAuthorizer 是权限查询的显式白名单授权器；普通用户只能查自己，应用管理员
// 还可以查询其获准应用范围的主体（是否成员由引擎在快照内再核对），本地/系统操作者
// 可查任意普通主体。它是临时装配，不是生产角色/委派模型。
type StaticAuthorizer struct {
	// mu 保护 maps：AssignApplicationAdmin 运行期写入，AuthorizeQuery 并发读取；
	// 与 internal/role 等包的 StaticAuthorizer 一致使用读写锁。
	mu          sync.RWMutex
	localAdmins map[string]struct{}
	systems     map[string]struct{}
	appAdmins   map[string]map[string]struct{}
}

// NewStaticAuthorizer 构造显式白名单授权器。
func NewStaticAuthorizer(options AuthorizerOptions) (*StaticAuthorizer, error) {
	if len(options.LocalAdminIDs) == 0 && len(options.SystemIDs) == 0 {
		return nil, fmt.Errorf("%w: 至少需要一个本地管理员或系统操作者", ErrOptionsInvalid)
	}
	authorizer := &StaticAuthorizer{
		localAdmins: make(map[string]struct{}, len(options.LocalAdminIDs)),
		systems:     make(map[string]struct{}, len(options.SystemIDs)),
		appAdmins:   make(map[string]map[string]struct{}, len(options.ApplicationAdmins)),
	}
	for _, id := range options.LocalAdminIDs {
		actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: id}
		if err := actor.Validate(); err != nil {
			return nil, fmt.Errorf("%w: 本地管理员标识无效", ErrOptionsInvalid)
		}
		authorizer.localAdmins[id] = struct{}{}
	}
	for _, id := range options.SystemIDs {
		actor := audit.Actor{Type: audit.ActorSystem, ID: id}
		if err := actor.Validate(); err != nil {
			return nil, fmt.Errorf("%w: 系统操作者标识无效", ErrOptionsInvalid)
		}
		authorizer.systems[id] = struct{}{}
	}
	for applicationID, userIDs := range options.ApplicationAdmins {
		parsed, err := ParseScope(applicationID)
		if err != nil || parsed.Kind != ScopeKindApplication {
			return nil, fmt.Errorf("%w: 应用管理员配置中的应用 ID 无效", ErrOptionsInvalid)
		}
		admins := make(map[string]struct{}, len(userIDs))
		for _, userID := range userIDs {
			if !account.ValidUserID(userID) {
				return nil, fmt.Errorf("%w: 应用管理员用户 ID 无效", ErrOptionsInvalid)
			}
			admins[userID] = struct{}{}
		}
		authorizer.appAdmins[applicationID] = admins
	}
	return authorizer, nil
}

// AssignApplicationAdmin 显式给应用分配权限查询管理员；由宿主/后续模块受控调用。
func (a *StaticAuthorizer) AssignApplicationAdmin(applicationID, userID string) error {
	if a == nil {
		return ErrOptionsInvalid
	}
	parsed, err := ParseScope(applicationID)
	if err != nil || parsed.Kind != ScopeKindApplication {
		return fmt.Errorf("%w: 应用 ID 无效", ErrInvalidRequest)
	}
	if !account.ValidUserID(userID) {
		return fmt.Errorf("%w: 用户 ID 无效", ErrInvalidRequest)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	admins, ok := a.appAdmins[applicationID]
	if !ok {
		admins = make(map[string]struct{})
		a.appAdmins[applicationID] = admins
	}
	admins[userID] = struct{}{}
	return nil
}

// AuthorizeQuery 实现 Authorizer。
func (a *StaticAuthorizer) AuthorizeQuery(_ context.Context, caller Caller, subjectUserID string, scope Scope) error {
	if a == nil {
		return ErrAccessDenied
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	switch caller.actor.Type {
	case audit.ActorLocalAdmin:
		if _, ok := a.localAdmins[caller.actor.ID]; ok {
			return nil
		}
	case audit.ActorSystem:
		if _, ok := a.systems[caller.actor.ID]; ok {
			return nil
		}
	case audit.ActorUser:
		if caller.actor.ID == subjectUserID {
			return nil
		}
		if scope.Kind == ScopeKindApplication {
			admins, ok := a.appAdmins[scope.ApplicationID]
			if ok {
				if _, allowed := admins[caller.actor.ID]; allowed {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("%w: 调用者不能查询该主体的权限", ErrAccessDenied)
}

// validatePermissionKeys 校验权限键并去重（保留首次出现顺序）。
func validatePermissionKeys(keys []string) ([]string, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: 至少需要一个权限", ErrInvalidRequest)
	}
	if len(keys) > MaxRequirements {
		return nil, fmt.Errorf("%w: 权限数量不能超过 %d", ErrInvalidRequest, MaxRequirements)
	}
	seen := make(map[string]struct{}, len(keys))
	normalized := make([]string, 0, len(keys))
	for _, key := range keys {
		value, err := permission.ValidateKey(key)
		if err != nil {
			return nil, fmt.Errorf("%w: 权限键无效", ErrInvalidRequest)
		}
		if _, duplicated := seen[value]; duplicated {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized, nil
}

// validateMode 返回规范化模式，默认 all。
func validateMode(mode Mode) (Mode, error) {
	if mode == "" {
		return ModeAll, nil
	}
	if !mode.Valid() {
		return "", fmt.Errorf("%w: 权限组合模式必须是 all 或 any", ErrInvalidRequest)
	}
	return mode, nil
}

// normalizeListOptions 校验并填充分页参数。
func normalizeListOptions(options ListOptions) (ListOptions, error) {
	limit := options.Limit
	if limit == 0 {
		limit = DefaultListLimit
	}
	if limit < 0 || limit > MaxListLimit {
		return ListOptions{}, fmt.Errorf("%w: 每页数量必须在 1～%d 之间", ErrInvalidRequest, MaxListLimit)
	}
	if options.Offset < 0 || options.Offset > MaxListOffset {
		return ListOptions{}, fmt.Errorf("%w: 分页偏移无效", ErrInvalidRequest)
	}
	return ListOptions{Limit: limit, Offset: options.Offset}, nil
}

// validateResourceID 已经定义；资源检查前再校验一次空值。
func requireResourceID(resourceID string) error {
	if problem := validateResourceID(resourceID); problem != "" {
		return fmt.Errorf("%w: %s", ErrInvalidRequest, problem)
	}
	return nil
}
