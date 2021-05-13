// Package role 实现角色目录、角色权限组合，以及角色到用户/用户组的分配。
//
// 角色按作用范围（scope）隔离：系统范围固定 "system"，应用范围 scope ID 等于
// 应用 ID（沿用步骤 20/22/23 约定）。角色的机器标识（role_key）在创建后不可变，
// 同一范围内唯一；名称、说明与明确限制可修改。角色存在或启用不代表任何主体自动
// 获得权限：本包只管理存储关系，不实现有效权限推导（步骤 25）也不实现可转授权限
// 委派限制（步骤 26）。
//
// 安全不变量：
//   - 角色只能组合同一作用范围内、存在且启用的权限；root_only 敏感权限不能被
//     角色组合，避免通过普通角色分配产生 root 能力。root 账户不能作为普通角色
//     分配目标，角色机器标识也不能使用 root 语义。
//   - 应用角色只能分配给该应用的有效成员，或该应用范围内的用户组；系统角色只能
//     分配给可用全局账户或系统用户组，不能跨应用/跨系统串用。
//   - 角色资料、权限组合与分配/撤回全部经可信 Caller 与 Authorizer 判权，并在
//     审计事务中与成功审计一致提交；审计失败整体回滚。
//   - 分配与撤回只写 user_roles/group_roles；本包不修改用户状态、应用状态或权限
//     启停状态。角色/权限/组成员后续被停用或删除时，有效权限计算（步骤 25）必须
//     每次读取当前状态，不能依赖本包事件代替实时检查。
package role

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
	// MaxRoleKeyBytes 是角色机器标识长度上限。
	MaxRoleKeyBytes = 64
	// MaxNameRunes 是角色直白名称字符上限。
	MaxNameRunes = 64
	// MaxDescriptionRunes 是角色说明字符上限。
	MaxDescriptionRunes = 500
	// MaxLimitsRunes 是角色明确限制说明字符上限。
	MaxLimitsRunes = 1000
	// DefaultListLimit/MaxListLimit 是角色列表分页边界。
	DefaultListLimit = 20
	MaxListLimit     = 100
	// MaxListOffset 限制深分页。
	MaxListOffset = 1_000_000
	// ScopeSystem 是系统范围的固定 scope ID。
	ScopeSystem = "system"
	// roleIDPrefix/roleIDRandomBytes 定义稳定角色 ID：role_ + 128 位随机数。
	roleIDPrefix      = "role_"
	roleIDRandomBytes = 16
)

// ScopeKind 是角色作用范围类型。
type ScopeKind string

const (
	// ScopeKindSystem 表示系统角色。
	ScopeKindSystem ScopeKind = "system"
	// ScopeKindApplication 表示应用角色。
	ScopeKindApplication ScopeKind = "application"
)

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

// validApplicationID 复制应用 ID 格式校验（app_ + 32 位十六进制），避免角色包依赖
// app 包的类型细节。
func validApplicationID(id string) bool {
	if len(id) != 4+32 || !strings.HasPrefix(id, "app_") {
		return false
	}
	_, err := hex.DecodeString(id[4:])
	return err == nil
}

// Role 是角色快照。ID、ScopeID、ScopeKind、ApplicationID、Key、IsBuiltin 创建后
// 不可变；Enabled 通过独立命令变更。
type Role struct {
	ID            string
	ScopeID       string
	ScopeKind     ScopeKind
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

// PermissionSummary 是角色权限组合中的权限摘要，供展示与后续有效权限计算使用。
type PermissionSummary struct {
	PermissionID string
	Key          string
	Name         string
	ScopeID      string
	Enabled      bool
	RootOnly     bool
}

// UserRoleAssignment 是用户角色分配记录。
type UserRoleAssignment struct {
	UserID     string
	RoleID     string
	ScopeID    string
	DataScope  string
	AssignedBy string
	CreatedAt  time.Time
}

// GroupRoleAssignment 是用户组角色分配记录。group_roles 表没有 assigned_by 列，
// 操作者记录在安全审计事件中。
type GroupRoleAssignment struct {
	GroupID   string
	RoleID    string
	ScopeID   string
	DataScope string
	CreatedAt time.Time
}

// Assignments 是角色的用户/用户组分配快照。
type Assignments struct {
	Users  []UserRoleAssignment
	Groups []GroupRoleAssignment
}

// CreateRequest 是角色创建白名单。ID、scope 之外的机器标识、名称、说明、明确限制
// 与是否内置由调用方显式给出；新建角色默认 enabled=true，不包含任何权限或分配。
type CreateRequest struct {
	ScopeID     string
	Key         string
	Name        string
	Description string
	Limits      string
	IsBuiltin   bool
}

// UpdateRequest 是角色资料更新白名单：只允许名称、说明与明确限制；机器标识、
// scope 与 builtin 语义不可修改（变更需新增角色并显式迁移分配）。
type UpdateRequest struct {
	Name        string
	Description string
	Limits      string
}

// ListRequest 是角色列表请求；ScopeID 为空表示可管理范围内全部角色。
type ListRequest struct {
	ScopeID string
	Limit   int
	Offset  int
	Enabled *bool
	Builtin *bool
}

// ListResult 是角色列表结果。
type ListResult struct {
	Roles   []Role
	HasMore bool
}

// 领域错误哨兵。
var (
	ErrOptionsInvalid      = errors.New("角色服务选项无效")
	ErrInvalidRequest      = errors.New("角色请求无效")
	ErrRoleNotFound        = errors.New("角色不存在")
	ErrRoleKeyTaken        = errors.New("同一范围内角色机器标识已存在")
	ErrScopeInvalid        = errors.New("角色作用范围无效")
	ErrAccessDenied        = errors.New("未获准执行该操作")
	ErrBuiltinProtected    = errors.New("内置角色不可修改或删除")
	ErrRoleInUse           = errors.New("角色仍被引用或分配，不能删除")
	ErrRoleDisabled        = errors.New("角色当前已停用")
	ErrApplicationInactive = errors.New("应用当前不可用于角色管理")
	ErrStateConflict       = errors.New("角色数据已被其他操作修改")
	ErrStoreUnavailable    = errors.New("角色存储暂时不可用")
	ErrAuditUnavailable    = errors.New("关键操作未能可靠记录")
	ErrPermissionNotFound  = errors.New("要组合的权限不存在")
	ErrPermissionInactive  = errors.New("要组合的权限已停用")
	ErrPermissionScope     = errors.New("权限与角色不属于同一作用范围")
	ErrRootOnlyPermission  = errors.New("root_only 敏感权限不能被普通角色组合")
	ErrUserNotFound        = errors.New("目标用户不存在")
	ErrUserNotEligible     = errors.New("目标用户当前不可分配角色")
	ErrUserNotMember       = errors.New("目标用户不是该应用的有效成员")
	ErrRootProtected       = errors.New("root 账户不能作为普通角色分配目标")
	ErrGroupNotFound       = errors.New("目标用户组不存在")
	ErrGroupScope          = errors.New("用户组与角色不属于同一作用范围")
)

// ErrorCode 是与根包错误码注册表一致的字面值；根包测试核对登记状态。
type ErrorCode string

const (
	CodeReqInvalid            ErrorCode = "REQ_INVALID"
	CodeConflict              ErrorCode = "CONFLICT"
	CodeAccessDenied          ErrorCode = "ACCESS_DENIED"
	CodeAppScopeMismatch      ErrorCode = "APP_SCOPE_MISMATCH"
	CodeAppMembershipRequired ErrorCode = "APP_MEMBERSHIP_REQUIRED"
	CodeClientDisabled        ErrorCode = "CLIENT_DISABLED"
	CodeUserDisabled          ErrorCode = "USER_DISABLED"
	CodeDBUnavailable         ErrorCode = "DB_UNAVAILABLE"
	CodeAuditWriteFailed      ErrorCode = "AUDIT_WRITE_FAILED"
	CodeInternalError         ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把角色领域错误映射到已登记错误码。委派检查错误优先映射为可诊断的
// 稳定错误码（缺少转授资格为 PERMISSION_REQUIRED、自我/目标限制为 ACCESS_DENIED）。
func CodeOf(err error) ErrorCode {
	if code := delegation.CodeOf(err); code != "" {
		return ErrorCode(code)
	}
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrRoleNotFound),
		errors.Is(err, ErrScopeInvalid), errors.Is(err, ErrPermissionNotFound),
		errors.Is(err, ErrPermissionInactive), errors.Is(err, ErrUserNotFound),
		errors.Is(err, ErrGroupNotFound):
		return CodeReqInvalid
	case errors.Is(err, ErrRoleKeyTaken), errors.Is(err, ErrRoleInUse),
		errors.Is(err, ErrRoleDisabled), errors.Is(err, ErrStateConflict):
		return CodeConflict
	case errors.Is(err, ErrAccessDenied), errors.Is(err, ErrBuiltinProtected),
		errors.Is(err, ErrRootOnlyPermission), errors.Is(err, ErrRootProtected):
		return CodeAccessDenied
	case errors.Is(err, ErrPermissionScope), errors.Is(err, ErrGroupScope):
		return CodeAppScopeMismatch
	case errors.Is(err, ErrUserNotMember):
		return CodeAppMembershipRequired
	case errors.Is(err, ErrApplicationInactive):
		return CodeClientDisabled
	case errors.Is(err, ErrUserNotEligible):
		return CodeUserDisabled
	case errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	default:
		return CodeInternalError
	}
}

// NewRoleID 生成 role_ + 128 位随机数的稳定角色 ID。
func NewRoleID(random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	buffer := make([]byte, roleIDRandomBytes)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", fmt.Errorf("无法生成角色 ID: %w", err)
	}
	return roleIDPrefix + hex.EncodeToString(buffer), nil
}

// ValidRoleID 报告角色 ID 是否符合本包生成的固定格式。
func ValidRoleID(id string) bool {
	if len(id) != len(roleIDPrefix)+2*roleIDRandomBytes ||
		!strings.HasPrefix(id, roleIDPrefix) {
		return false
	}
	_, err := hex.DecodeString(id[len(roleIDPrefix):])
	return err == nil
}

// ValidateKey 校验角色机器标识：2～64 字节，ASCII 小写字母/数字与 . _ -，首尾必须
// 是字母或数字，且不能使用 root 语义分段（root、root.*、*_root 等），避免通过普通
// 角色产生 root 能力。
func ValidateKey(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if len(value) < 2 || len(value) > MaxRoleKeyBytes {
		return "", fmt.Errorf("%w: 角色机器标识长度必须是 2～%d 字节", ErrInvalidRequest, MaxRoleKeyBytes)
	}
	hasLetter := false
	for index := 0; index < len(value); index++ {
		character := value[index]
		switch {
		case character >= 'a' && character <= 'z':
			hasLetter = true
		case character >= '0' && character <= '9':
		case character == '.', character == '_', character == '-':
		default:
			return "", fmt.Errorf("%w: 角色机器标识只能包含小写字母、数字、点、下划线与连字符", ErrInvalidRequest)
		}
	}
	if !hasLetter {
		return "", fmt.Errorf("%w: 角色机器标识必须包含字母", ErrInvalidRequest)
	}
	isAlphaNumeric := func(character byte) bool {
		return (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9')
	}
	if !isAlphaNumeric(value[0]) || !isAlphaNumeric(value[len(value)-1]) {
		return "", fmt.Errorf("%w: 角色机器标识必须以字母或数字开头和结尾", ErrInvalidRequest)
	}
	for _, segment := range strings.FieldsFunc(value, func(r rune) bool {
		return r == '.' || r == '_' || r == '-'
	}) {
		if segment == "root" {
			return "", fmt.Errorf("%w: 角色机器标识不能使用 root 语义", ErrInvalidRequest)
		}
	}
	return value, nil
}

// ValidateName 校验角色直白名称：NFKC、去空白、1～64 码点单行。
func ValidateName(raw string) (string, error) {
	return normalizeText(raw, MaxNameRunes, false, "角色名称")
}

// ValidateDescription 校验角色说明：NFKC、去空白、1～500 码点，允许换行/制表符。
func ValidateDescription(raw string) (string, error) {
	return normalizeText(raw, MaxDescriptionRunes, true, "角色说明")
}

// ValidateLimits 校验角色明确限制说明：NFKC、去空白、1～1000 码点，允许换行。
func ValidateLimits(raw string) (string, error) {
	return normalizeText(raw, MaxLimitsRunes, true, "角色限制说明")
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

// Action 是角色操作动作。
type Action string

const (
	ActionCreateRole           Action = "role.create"
	ActionGetRole              Action = "role.get"
	ActionListRoles            Action = "role.list"
	ActionUpdateRole           Action = "role.update"
	ActionEnableRole           Action = "role.enable"
	ActionDisableRole          Action = "role.disable"
	ActionDeleteRole           Action = "role.delete"
	ActionAddRolePermission    Action = "role.permission.add"
	ActionRemoveRolePermission Action = "role.permission.remove"
	ActionListRolePermissions  Action = "role.permission.list"
	ActionAssignUserRole       Action = "role.assignment.user.assign"
	ActionRevokeUserRole       Action = "role.assignment.user.revoke"
	ActionAssignGroupRole      Action = "role.assignment.group.assign"
	ActionRevokeGroupRole      Action = "role.assignment.group.revoke"
	ActionListRoleAssignments  Action = "role.assignment.list"
)

// Valid 报告动作是否已定义。
func (a Action) Valid() bool {
	switch a {
	case ActionCreateRole, ActionGetRole, ActionListRoles, ActionUpdateRole,
		ActionEnableRole, ActionDisableRole, ActionDeleteRole,
		ActionAddRolePermission, ActionRemoveRolePermission, ActionListRolePermissions,
		ActionAssignUserRole, ActionRevokeUserRole, ActionAssignGroupRole,
		ActionRevokeGroupRole, ActionListRoleAssignments:
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

// Authorizer 判定调用者能否管理指定范围的角色。策略引擎/委派限制未完成前只提供
// StaticAuthorizer 显式白名单；缺少 Authorizer 时服务不可构造，不放行任何请求。
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

// StaticAuthorizer 是权限引擎/委派限制未完成前的显式白名单授权器；无持久化、
// 无继承，不是生产角色/权限模型。
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

// AssignApplicationAdmin 显式给应用分配角色管理员；由宿主/后续权限模块在受控流程
// 中调用，不由名称或负责人变化自动触发。
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
	if action == ActionListRoles {
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
		if len(scopes) == 0 {
			// 用户没有任何可管理应用时默认拒绝，不返回“空列表成功”，避免把无
			// 授权与“有授权但暂无角色”混淆。
			return false, nil, ErrAccessDenied
		}
		return false, scopes, nil
	}
	return false, nil, ErrAccessDenied
}

// formatBool 把布尔值转为审计差异文本。
func formatBool(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
