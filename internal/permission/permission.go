// Package permission 实现系统权限与应用独有权限的权限目录。
//
// 权限以所属作用范围（scope）与机器标识（permission_key）共同唯一定位：系统范围
// 固定 "system"，应用范围 scope ID 等于应用 ID。不同应用可以拥有相同机器标识，
// 但不能跨作用范围读取、修改、删除或串用。本包只管理目录，不实现角色分配、
// 授权判定或令牌；权限存在/启用不代表任何主体自动拥有它。
//
// 权限分类：
//   - 系统内置权限：scope=system 且 is_builtin=1；机器标识、名称、说明、限制与
//     root_only 语义不可修改、不可删除，只能按规则启用/停用（root_only 内置权限
//     只能由受限本地初始化操作者停用）。内置权限不是应用可自造的。
//   - 系统自定义权限：scope=system 且 is_builtin=0；显示名称、说明、限制可修改，
//     机器标识不可变（变更必须新增权限并显式迁移引用）。
//   - 应用独有权限：scope=应用 ID 且 is_builtin=0；只能由该应用管理员或本地/系统
//     操作者管理，不能创建系统权限或 root_only 权限。
//
// 停用是拒绝操作，不是跳过检查：依赖方必须把 enabled=false 当作拒绝；本包不提供
// 角色分配引擎，不能声称停用已级联撤销既有授权。删除自定义权限前必须在同一事务
// 条件删除中确认没有 role_permissions 引用，避免隐式级联破坏授权关系。
package permission

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
)

const (
	// MaxKeyBytes 是机器标识长度上限。
	MaxKeyBytes = 128
	// MaxNameRunes 是直白名称字符上限。
	MaxNameRunes = 64
	// MaxDescriptionRunes 是说明字符上限。
	MaxDescriptionRunes = 500
	// MaxLimitsRunes 是明确限制说明字符上限。
	MaxLimitsRunes = 1000
	// DefaultListLimit/MaxListLimit 是权限列表分页边界。
	DefaultListLimit = 20
	MaxListLimit     = 100
	// MaxListOffset 限制深分页。
	MaxListOffset = 1_000_000
	// ScopeSystem 是系统范围的固定 scope ID。
	ScopeSystem = "system"
	// permissionIDPrefix/permissionIDRandomBytes 定义稳定权限 ID：perm_ + 128 位随机数。
	permissionIDPrefix      = "perm_"
	permissionIDRandomBytes = 16
)

// ScopeKind 是权限作用范围类型。
type ScopeKind string

const (
	// ScopeKindSystem 表示系统权限。
	ScopeKindSystem ScopeKind = "system"
	// ScopeKindApplication 表示应用独有权限。
	ScopeKindApplication ScopeKind = "application"
)

// Permission 是权限目录快照。ID、ScopeID、Key、IsBuiltin、RootOnly 创建后不可变。
type Permission struct {
	ID            string
	ScopeID       string
	ScopeKind     ScopeKind
	ApplicationID string
	Key           string
	Group         string
	Name          string
	Description   string
	Limits        string
	IsBuiltin     bool
	RootOnly      bool
	Enabled       bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Definition 是权限的机器可读定义，供前端目录、审计与后续授权模块使用。
// 分组由机器标识首个点号前缀推导；默认值为启用（新建权限默认 enabled=true），
// Sensitive 等同 root_only；生效对象由 scope 明确。定义中的 Key/Scope/Builtin/
// Sensitive 均不可通过更新接口修改，避免已发布语义悄悄变化。
type Definition struct {
	Key            string    `json:"key"`
	Group          string    `json:"group"`
	ScopeID        string    `json:"scope_id"`
	ScopeKind      ScopeKind `json:"scope_kind"`
	ApplicationID  string    `json:"application_id,omitempty"`
	Target         string    `json:"target"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	Limits         string    `json:"limits"`
	DefaultEnabled bool      `json:"default_enabled"`
	Sensitive      bool      `json:"sensitive"`
	Builtin        bool      `json:"builtin"`
	Enabled        bool      `json:"enabled"`
}

// Definition 返回权限的机器可读定义。
func (p Permission) Definition() Definition {
	target := "system"
	if p.ScopeKind == ScopeKindApplication {
		target = "application:" + p.ApplicationID
	}
	return Definition{
		Key: p.Key, Group: p.Group, ScopeID: p.ScopeID, ScopeKind: p.ScopeKind,
		ApplicationID: p.ApplicationID, Target: target, Name: p.Name,
		Description: p.Description, Limits: p.Limits, DefaultEnabled: true,
		Sensitive: p.RootOnly, Builtin: p.IsBuiltin, Enabled: p.Enabled,
	}
}

// CreateRequest 是权限登记白名单。ID/scope 之外的 key/name/description/limits/
// root_only/is_builtin 由调用方显式给出，状态固定新建为 enabled。
type CreateRequest struct {
	ScopeID     string
	Key         string
	Name        string
	Description string
	Limits      string
	RootOnly    bool
	IsBuiltin   bool
}

// UpdateRequest 是自定义权限资料更新白名单：只允许名称、说明、限制；机器标识、
// scope、builtin/root_only 语义不可修改（变更须新增权限并显式迁移）。
type UpdateRequest struct {
	Name        string
	Description string
	Limits      string
}

// ListRequest 是权限目录列表请求；ScopeID 为空表示可管理范围内全部权限。
type ListRequest struct {
	ScopeID string
	Limit   int
	Offset  int
	Enabled *bool
}

// ListResult 是权限列表结果。
type ListResult struct {
	Permissions []Permission
	HasMore     bool
}

// 领域错误哨兵。
var (
	ErrOptionsInvalid      = errors.New("权限服务选项无效")
	ErrInvalidRequest      = errors.New("权限请求无效")
	ErrPermissionNotFound  = errors.New("权限不存在")
	ErrPermissionKeyTaken  = errors.New("同一范围内权限机器标识已存在")
	ErrScopeInvalid        = errors.New("权限作用范围无效")
	ErrAccessDenied        = errors.New("未获准执行该操作")
	ErrBuiltinProtected    = errors.New("内置权限不可修改或删除")
	ErrPermissionInUse     = errors.New("权限仍被角色引用，不能删除")
	ErrApplicationInactive = errors.New("应用当前不可用于权限登记")
	ErrStateConflict       = errors.New("权限状态已被其他操作修改")
	ErrStoreUnavailable    = errors.New("权限存储暂时不可用")
	ErrAuditUnavailable    = errors.New("关键操作未能可靠记录")
)

// ErrorCode 是与根包错误码注册表一致的字面值；根包测试核对登记状态。
type ErrorCode string

const (
	CodeReqInvalid       ErrorCode = "REQ_INVALID"
	CodeConflict         ErrorCode = "CONFLICT"
	CodeAccessDenied     ErrorCode = "ACCESS_DENIED"
	CodeClientDisabled   ErrorCode = "CLIENT_DISABLED"
	CodeDBUnavailable    ErrorCode = "DB_UNAVAILABLE"
	CodeAuditWriteFailed ErrorCode = "AUDIT_WRITE_FAILED"
	CodeInternalError    ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把权限目录领域错误映射到已登记错误码；委派检查错误优先映射为稳定错误码。
func CodeOf(err error) ErrorCode {
	if code := delegation.CodeOf(err); code != "" {
		return ErrorCode(code)
	}
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrPermissionNotFound),
		errors.Is(err, ErrScopeInvalid):
		return CodeReqInvalid
	case errors.Is(err, ErrPermissionKeyTaken), errors.Is(err, ErrPermissionInUse),
		errors.Is(err, ErrStateConflict):
		return CodeConflict
	case errors.Is(err, ErrAccessDenied), errors.Is(err, ErrBuiltinProtected):
		return CodeAccessDenied
	case errors.Is(err, ErrApplicationInactive):
		return CodeClientDisabled
	case errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	default:
		return CodeInternalError
	}
}

// NewPermissionID 生成 perm_ + 128 位随机数的稳定权限 ID。
func NewPermissionID(random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	buffer := make([]byte, permissionIDRandomBytes)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", fmt.Errorf("无法生成权限 ID: %w", err)
	}
	return permissionIDPrefix + hex.EncodeToString(buffer), nil
}

// ValidPermissionID 报告权限 ID 是否符合本包生成的固定格式。
func ValidPermissionID(id string) bool {
	if len(id) != len(permissionIDPrefix)+2*permissionIDRandomBytes ||
		!strings.HasPrefix(id, permissionIDPrefix) {
		return false
	}
	_, err := hex.DecodeString(id[len(permissionIDPrefix):])
	return err == nil
}

// ParseScope 解析作用范围：只接受 "system" 或有效应用 ID。
func ParseScope(scopeID string) (ScopeKind, string, error) {
	value := strings.TrimSpace(scopeID)
	if value == ScopeSystem {
		return ScopeKindSystem, "", nil
	}
	if !validApplicationID(value) {
		return "", "", fmt.Errorf("%w: 作用范围必须是 system 或有效应用 ID", ErrScopeInvalid)
	}
	return ScopeKindApplication, value, nil
}

// validApplicationID 复制应用 ID 格式校验，避免权限包依赖 app 包的类型细节；
// app_ 前缀 + 32 位十六进制。
func validApplicationID(id string) bool {
	if len(id) != 4+32 || !strings.HasPrefix(id, "app_") {
		return false
	}
	_, err := hex.DecodeString(id[4:])
	return err == nil
}

// ValidateKey 校验机器标识：3～128 字节，点号分段的 lower_snake 命名，至少两段
// （首段为分组），每段以字母开头，只允许小写字母、数字与下划线。
func ValidateKey(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if len(value) < 3 || len(value) > MaxKeyBytes {
		return "", fmt.Errorf("%w: 权限机器标识长度必须是 3～%d 字节", ErrInvalidRequest, MaxKeyBytes)
	}
	segments := strings.Split(value, ".")
	if len(segments) < 2 || len(segments) > 4 {
		return "", fmt.Errorf("%w: 权限机器标识必须由 2～4 个点号分段组成", ErrInvalidRequest)
	}
	for _, segment := range segments {
		if len(segment) == 0 || len(segment) > 32 {
			return "", fmt.Errorf("%w: 权限机器标识分段必须为 1～32 字节", ErrInvalidRequest)
		}
		if segment[0] < 'a' || segment[0] > 'z' {
			return "", fmt.Errorf("%w: 权限机器标识每段必须以小写字母开头", ErrInvalidRequest)
		}
		for index := 0; index < len(segment); index++ {
			character := segment[index]
			if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
				character == '_' {
				continue
			}
			return "", fmt.Errorf("%w: 权限机器标识只能包含小写字母、数字、下划线与点号", ErrInvalidRequest)
		}
	}
	return value, nil
}

// KeyGroup 返回机器标识首段分组；与权限语义无关，仅用于目录展示。
func KeyGroup(key string) string {
	if index := strings.IndexByte(key, '.'); index > 0 {
		return key[:index]
	}
	return key
}

// ValidateName 校验直白名称：NFKC、去空白、1～64 码点单行。
func ValidateName(raw string) (string, error) {
	return normalizeText(raw, MaxNameRunes, false, "权限名称")
}

// ValidateDescription 校验说明：NFKC、去空白、1～500 码点，允许换行/制表符。
func ValidateDescription(raw string) (string, error) {
	return normalizeText(raw, MaxDescriptionRunes, true, "权限说明")
}

// ValidateLimits 校验明确限制说明：NFKC、去空白、1～1000 码点，允许换行/制表符。
func ValidateLimits(raw string) (string, error) {
	return normalizeText(raw, MaxLimitsRunes, true, "权限限制说明")
}

// normalizeText 做 NFKC、去首尾空白、UTF-8/控制字符/长度校验。
func normalizeText(raw string, maxRunes int, allowNewlines bool, label string) (string, error) {
	value := strings.TrimSpace(norm.NFKC.String(strings.TrimSpace(raw)))
	if value == "" {
		return "", fmt.Errorf("%w: %s不能为空", ErrInvalidRequest, label)
	}
	if !utf8.ValidString(value) {
		return "", fmt.Errorf("%w: %s不是合法 UTF-8", ErrInvalidRequest, label)
	}
	count := 0
	for _, character := range value {
		count++
		if character == '\n' || character == '\t' {
			if !allowNewlines {
				return "", fmt.Errorf("%w: %s不能包含换行或制表符", ErrInvalidRequest, label)
			}
			continue
		}
		if unicode.IsControl(character) || unicode.Is(unicode.Cf, character) ||
			unicode.Is(unicode.Zl, character) || unicode.Is(unicode.Zp, character) {
			return "", fmt.Errorf("%w: %s包含不允许的控制或格式字符", ErrInvalidRequest, label)
		}
	}
	if count > maxRunes {
		return "", fmt.Errorf("%w: %s不能超过 %d 个字符", ErrInvalidRequest, label, maxRunes)
	}
	return value, nil
}

// Action 是权限目录操作动作。
type Action string

const (
	ActionCreatePermission  Action = "permission.create"
	ActionGetPermission     Action = "permission.get"
	ActionListPermissions   Action = "permission.list"
	ActionUpdatePermission  Action = "permission.update"
	ActionDeletePermission  Action = "permission.delete"
	ActionEnablePermission  Action = "permission.enable"
	ActionDisablePermission Action = "permission.disable"
)

// Valid 报告动作是否已定义。
func (a Action) Valid() bool {
	switch a {
	case ActionCreatePermission, ActionGetPermission, ActionListPermissions,
		ActionUpdatePermission, ActionDeletePermission,
		ActionEnablePermission, ActionDisablePermission:
		return true
	default:
		return false
	}
}

// Caller 是可信操作者上下文；字段不导出，只能由构造器生成。
type Caller struct {
	actor     audit.Actor
	requestID string
}

// LocalBootstrapCaller 构造受限本地初始化操作者（local_admin）。
func LocalBootstrapCaller(operatorID string) (Caller, error) {
	return newCaller(audit.ActorLocalAdmin, operatorID)
}

// SystemCaller 构造系统组件操作者（system）。
func SystemCaller(componentID string) (Caller, error) {
	return newCaller(audit.ActorSystem, componentID)
}

// UserCaller 构造已认证用户操作者（user）；权限仍由 Authorizer 判定。
func UserCaller(userID string) (Caller, error) {
	return newCaller(audit.ActorUser, userID)
}

func newCaller(kind audit.ActorKind, id string) (Caller, error) {
	actor := audit.Actor{Type: kind, ID: id}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 操作者标识无效", ErrInvalidRequest)
	}
	return Caller{actor: actor}, nil
}

// WithRequestID 返回带请求编号的调用者副本。
// Actor 返回调用者的可信审计身份（只读副本）。
//
// 这是宿主授权适配层识别调用者所需的最小只读查询能力：authorizer 无法从
// 不可见字段判断主体，因此补充该访问器；它不暴露请求编号，也不允许伪造身份。
func (c Caller) Actor() audit.Actor { return c.actor }

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

// Authorizer 判定调用者能否管理指定范围的权限目录。
type Authorizer interface {
	Authorize(ctx context.Context, caller Caller, action Action, scopeID string) error
	ManageableScopes(ctx context.Context, caller Caller) (all bool, scopeIDs []string, err error)
}

// AuthorizerOptions 是 StaticAuthorizer 的显式配置。
type AuthorizerOptions struct {
	LocalAdminIDs     []string
	SystemIDs         []string
	ApplicationAdmins map[string][]string
}

// StaticAuthorizer 是权限引擎未完成前的显式白名单授权器；无持久化、无继承。
type StaticAuthorizer struct {
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
		if !validApplicationID(applicationID) {
			return nil, fmt.Errorf("%w: 应用管理员配置中的应用 ID 无效", ErrOptionsInvalid)
		}
		admins := make(map[string]struct{}, len(userIDs))
		for _, userID := range userIDs {
			actor := audit.Actor{Type: audit.ActorUser, ID: userID}
			if err := actor.Validate(); err != nil {
				return nil, fmt.Errorf("%w: 应用管理员用户 ID 无效", ErrOptionsInvalid)
			}
			admins[userID] = struct{}{}
		}
		authorizer.appAdmins[applicationID] = admins
	}
	return authorizer, nil
}

// AssignApplicationAdmin 显式给应用分配权限目录管理员；由宿主/后续权限模块在
// 受控流程中调用，不由名称或负责人变化自动触发。
func (a *StaticAuthorizer) AssignApplicationAdmin(applicationID, userID string) error {
	if a == nil {
		return ErrOptionsInvalid
	}
	if !validApplicationID(applicationID) {
		return fmt.Errorf("%w: 应用 ID 无效", ErrInvalidRequest)
	}
	actor := audit.Actor{Type: audit.ActorUser, ID: userID}
	if err := actor.Validate(); err != nil {
		return fmt.Errorf("%w: 应用管理员用户 ID 无效", ErrInvalidRequest)
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

// Authorize 实现 Authorizer；列表动作范围由 ManageableScopes 决定。
func (a *StaticAuthorizer) Authorize(_ context.Context, caller Caller, action Action, scopeID string) error {
	if a == nil || !action.Valid() {
		return ErrAccessDenied
	}
	if action == ActionListPermissions {
		return nil
	}
	kind, applicationID, err := ParseScope(scopeID)
	if err != nil {
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
		if kind != ScopeKindApplication || applicationID == "" {
			return ErrAccessDenied
		}
		admins, ok := a.appAdmins[applicationID]
		if !ok {
			return ErrAccessDenied
		}
		if _, ok := admins[caller.actor.ID]; ok {
			return nil
		}
	}
	return ErrAccessDenied
}

// ManageableScopes 实现 Authorizer。
func (a *StaticAuthorizer) ManageableScopes(_ context.Context, caller Caller) (bool, []string, error) {
	if a == nil {
		return false, nil, ErrAccessDenied
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	switch caller.actor.Type {
	case audit.ActorLocalAdmin:
		if _, ok := a.localAdmins[caller.actor.ID]; ok {
			return true, nil, nil
		}
	case audit.ActorSystem:
		if _, ok := a.systems[caller.actor.ID]; ok {
			return true, nil, nil
		}
	case audit.ActorUser:
		scopes := make([]string, 0, len(a.appAdmins))
		for applicationID, admins := range a.appAdmins {
			if _, ok := admins[caller.actor.ID]; ok {
				scopes = append(scopes, applicationID)
			}
		}
		return false, scopes, nil
	}
	return false, nil, ErrAccessDenied
}
