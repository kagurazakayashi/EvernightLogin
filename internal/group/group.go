// Package group 实现系统范围与应用范围的用户组与组成员管理。
//
// 本包是内部领域包，不直接暴露 HTTP 端点；调用者必须来自可信构造器并通过
// Authorizer 判权。用户组有稳定 ID、不可变作用范围与稳定机器键（group_key），
// 显示名称可修改但作用范围不能转移；组成员变更是未来权限的来源，全部写可靠
// 审计事件，角色/权限模块接入后必须消费这些事件并重新计算有效权限。
//
// 安全不变量：
//   - 系统组（scope "system"）只有具备系统资格的操作者可以管理；应用组只能由
//     本地/系统操作者或该应用的显式应用管理员管理，不能跨应用操作。
//   - 应用组成员只能加入其具有有效 app_memberships 成员关系且全局账户 active
//     的用户；应用停用时拒绝成员变更。系统组只要求全局账户 active。
//   - 组名称、说明不会推断任何权限，也不存在按名称识别的超级组；权限必须由后续
//     角色/权限模块显式分配。
//   - 批量成员操作有固定上限并采用全有或全无事务；失败不留部分成员，结果明确
//     返回新增/移除/跳过数量，不会整体成功却漏掉失败。
//   - 删除组只删除组、组成员关系与（未来的）组角色关联，不删除用户、不删除
//     审计历史；组成员变更与删除使用审计事务，失败时拒绝并回滚。
//
// 本步不实现角色分配、嵌套组、权限引擎持久化或 HTTP 管理端点；表中没有组状态列，
// 组在存在期间即为有效，删除即硬删除组记录（associations cascade）。
package group

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

	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
)

const (
	// MaxGroupKeyBytes 是稳定机器键长度上限；键只能是小写 ASCII 字母/数字与 . _ -。
	MaxGroupKeyBytes = 64
	// MaxNameRunes 是组显示名称字符上限。
	MaxNameRunes = 64
	// MaxDescriptionRunes 是组说明字符上限。
	MaxDescriptionRunes = 500
	// MaxBatchMembers 是单次批量成员操作的成员数上限。审计差异字段上限为 16，
	// 保留 added/skipped 等字段后最多可逐个记录 12 名成员。
	MaxBatchMembers = 12
	// DefaultMemberListLimit/MaxMemberListLimit 是成员列表分页边界。
	DefaultMemberListLimit = 20
	MaxMemberListLimit     = 100
	// MaxMemberOffset 限组成员列表深分页。
	MaxMemberOffset = 1_000_000
	// ScopeSystem 是系统范围的固定 scope ID。
	ScopeSystem = "system"
	// groupIDPrefix/groupIDRandomBytes 定义稳定组 ID：grp_ + 128 位随机数。
	groupIDPrefix      = "grp_"
	groupIDRandomBytes = 16
)

// ScopeKind 是组作用范围类型。
type ScopeKind string

const (
	// ScopeKindSystem 表示系统范围组。
	ScopeKindSystem ScopeKind = "system"
	// ScopeKindApplication 表示应用范围组。
	ScopeKindApplication ScopeKind = "application"
)

// Group 是用户组快照。ID、ScopeID、ScopeKind、GroupKey 创建后不可修改。
type Group struct {
	ID            string
	ScopeID       string
	ScopeKind     ScopeKind
	ApplicationID string
	GroupKey      string
	Name          string
	Description   string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// CreateRequest 是创建用户组请求；scope、group_key 创建后不可变。
type CreateRequest struct {
	ScopeID     string
	GroupKey    string
	Name        string
	Description string
}

// UpdateRequest 是组资料更新白名单：只能改名称与说明，不能改 scope/group_key/ID。
type UpdateRequest struct {
	Name        string
	Description string
}

// Member 是组成员关系快照。
type Member struct {
	GroupID   string
	UserID    string
	CreatedAt time.Time
}

// MemberBatchRequest 是批量加入/移除成员的请求。
type MemberBatchRequest struct {
	GroupID string
	UserIDs []string
}

// MemberBatchResult 是原子批量操作结果：Skipped 表示请求前已存在（加入）或不存在
// （移除）的成员，本次未产生变化；操作失败时不会返回部分成功。
type MemberBatchResult struct {
	Added   int
	Removed int
	Skipped int
}

// ListRequest 是组列表请求；ScopeID 为空表示可管理范围内全部组。
type ListRequest struct {
	ScopeID string
	Limit   int
	Offset  int
}

// ListResult 是组列表结果。
type ListResult struct {
	Groups  []Group
	HasMore bool
}

// MemberListRequest 是组成员分页请求。
type MemberListRequest struct {
	GroupID string
	Limit   int
	Offset  int
}

// MemberListResult 是组成员列表结果。
type MemberListResult struct {
	Members []Member
	HasMore bool
}

// 领域错误哨兵。
var (
	ErrOptionsInvalid      = errors.New("用户组服务选项无效")
	ErrInvalidRequest      = errors.New("用户组请求无效")
	ErrGroupNotFound       = errors.New("用户组不存在")
	ErrGroupKeyTaken       = errors.New("同一范围内用户组机器键已存在")
	ErrScopeInvalid        = errors.New("用户组作用范围无效")
	ErrAccessDenied        = errors.New("未获准执行该操作")
	ErrMemberNotEligible   = errors.New("目标用户不是该范围的有效成员")
	ErrApplicationInactive = errors.New("应用当前不可用于组成员变更")
	ErrStateConflict       = errors.New("成员关系已被其他操作修改")
	ErrStoreUnavailable    = errors.New("用户组存储暂时不可用")
	ErrAuditUnavailable    = errors.New("关键操作未能可靠记录")
)

// ErrorCode 是与根包错误码注册表一致的字面值；根包测试核对登记状态。
type ErrorCode string

const (
	CodeReqInvalid       ErrorCode = "REQ_INVALID"
	CodeConflict         ErrorCode = "CONFLICT"
	CodeAccessDenied     ErrorCode = "ACCESS_DENIED"
	CodeClientDisabled   ErrorCode = "CLIENT_DISABLED"
	CodeUserDisabled     ErrorCode = "USER_DISABLED"
	CodeDBUnavailable    ErrorCode = "DB_UNAVAILABLE"
	CodeAuditWriteFailed ErrorCode = "AUDIT_WRITE_FAILED"
	CodeInternalError    ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把用户组领域错误映射到已登记错误码；委派检查错误优先映射为稳定错误码。
func CodeOf(err error) ErrorCode {
	if code := delegation.CodeOf(err); code != "" {
		return ErrorCode(code)
	}
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrGroupNotFound),
		errors.Is(err, ErrScopeInvalid):
		return CodeReqInvalid
	case errors.Is(err, ErrGroupKeyTaken), errors.Is(err, ErrStateConflict):
		return CodeConflict
	case errors.Is(err, ErrAccessDenied):
		return CodeAccessDenied
	case errors.Is(err, ErrApplicationInactive):
		// 与 internal/app 的应用停用语义保持一致，供调用方按同族错误处理。
		return CodeClientDisabled
	case errors.Is(err, ErrMemberNotEligible):
		// 目标账户/应用成员资格不可用，与 app 包的用户不可用语义一致。
		return CodeUserDisabled
	case errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	default:
		return CodeInternalError
	}
}

// NewGroupID 生成 grp_ + 128 位随机数的稳定组 ID。
func NewGroupID(random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	buffer := make([]byte, groupIDRandomBytes)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", fmt.Errorf("无法生成用户组 ID: %w", err)
	}
	return groupIDPrefix + hex.EncodeToString(buffer), nil
}

// ValidGroupID 报告组 ID 是否符合本包生成的固定格式。
func ValidGroupID(id string) bool {
	if len(id) != len(groupIDPrefix)+2*groupIDRandomBytes || !strings.HasPrefix(id, groupIDPrefix) {
		return false
	}
	_, err := hex.DecodeString(id[len(groupIDPrefix):])
	return err == nil
}

// ParseScope 解析组作用范围：只接受 "system" 或应用 ID；应用范围类型由后续查询
// 数据库确认应用存在与状态。返回 ScopeKind 与应用 ID。
func ParseScope(scopeID string) (ScopeKind, string, error) {
	value := strings.TrimSpace(scopeID)
	if value == ScopeSystem {
		return ScopeKindSystem, "", nil
	}
	if !app.ValidApplicationID(value) {
		return "", "", fmt.Errorf("%w: 作用范围必须是 system 或有效应用 ID", ErrScopeInvalid)
	}
	return ScopeKindApplication, value, nil
}

// ValidateGroupKey 校验稳定机器键：2～64 字节小写 ASCII 字母/数字与 . _ -，首字符
// 必须是字母或数字。机器键不可从显示名称推断，也不允许通过改名转移权限语义。
func ValidateGroupKey(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if len(value) < 2 || len(value) > MaxGroupKeyBytes {
		return "", fmt.Errorf("%w: 用户组机器键长度必须是 2～%d 字节", ErrInvalidRequest, MaxGroupKeyBytes)
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		allowed := (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '-'
		if !allowed {
			return "", fmt.Errorf("%w: 用户组机器键只能包含小写字母、数字与 . _ -", ErrInvalidRequest)
		}
		if index == 0 && !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9')) {
			return "", fmt.Errorf("%w: 用户组机器键必须以字母或数字开头", ErrInvalidRequest)
		}
	}
	return value, nil
}

// ValidateGroupName 校验显示名称：NFKC、去首尾空白、1～64 码点单行，拒绝控制/
// 格式字符。名称不参与权限判定。
func ValidateGroupName(raw string) (string, error) {
	return normalizeDisplayText(raw, MaxNameRunes, false, "用户组名称")
}

// ValidateGroupDescription 校验说明：NFKC、去首尾空白、≤500 码点，允许换行/制表符。
func ValidateGroupDescription(raw string) (string, error) {
	return normalizeDisplayText(raw, MaxDescriptionRunes, true, "用户组说明")
}

// normalizeDisplayText 做 NFKC/去空白/UTF-8/控制字符/长度校验；allowEmpty 为 true
// 时允许空值（说明），名称不允许为空。
func normalizeDisplayText(raw string, maxRunes int, allowEmpty bool, label string) (string, error) {
	value := strings.TrimSpace(norm.NFKC.String(strings.TrimSpace(raw)))
	if value == "" {
		if allowEmpty {
			return "", nil
		}
		return "", fmt.Errorf("%w: %s不能为空", ErrInvalidRequest, label)
	}
	if !utf8.ValidString(value) {
		return "", fmt.Errorf("%w: %s不是合法 UTF-8", ErrInvalidRequest, label)
	}
	count := 0
	for _, character := range value {
		count++
		if character == '\n' || character == '\t' {
			if !allowEmpty {
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

// Action 是用户组操作动作。
type Action string

const (
	ActionCreateGroup   Action = "group.create"
	ActionGetGroup      Action = "group.get"
	ActionListGroups    Action = "group.list"
	ActionUpdateGroup   Action = "group.update"
	ActionDeleteGroup   Action = "group.delete"
	ActionAddMembers    Action = "group.member.add"
	ActionRemoveMembers Action = "group.member.remove"
	ActionListMembers   Action = "group.member.list"
)

// Valid 报告动作是否已定义。
func (a Action) Valid() bool {
	switch a {
	case ActionCreateGroup, ActionGetGroup, ActionListGroups, ActionUpdateGroup,
		ActionDeleteGroup, ActionAddMembers, ActionRemoveMembers, ActionListMembers:
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

// Authorizer 判定调用者能否管理指定 scope 的用户组。ScopeID 为系统范围或应用 ID。
type Authorizer interface {
	Authorize(ctx context.Context, caller Caller, action Action, scopeID string) error
	// ManageableScopes 返回调用者可管理的所有范围：all=true 表示全部；否则为
	// 应用 ID 列表（列表查询用）。
	ManageableScopes(ctx context.Context, caller Caller) (all bool, scopeIDs []string, err error)
}

// AuthorizerOptions 是 StaticAuthorizer 的显式配置。
type AuthorizerOptions struct {
	LocalAdminIDs []string
	SystemIDs     []string
	// ApplicationAdmins 按应用 ID 配置应用管理员用户 ID；应用管理员可管理该应用
	// 用户组，但不能管理系统组或其他应用组。
	ApplicationAdmins map[string][]string
}

// StaticAuthorizer 是权限引擎未完成前的显式白名单授权器。
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
	for appID, userIDs := range options.ApplicationAdmins {
		if !app.ValidApplicationID(appID) {
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
		authorizer.appAdmins[appID] = admins
	}
	return authorizer, nil
}

// AssignApplicationAdmin 显式给应用分配组管理员；由宿主/后续权限模块在受控流程
// 中调用，不由组名称或负责人变化自动触发。
func (a *StaticAuthorizer) AssignApplicationAdmin(applicationID, userID string) error {
	if a == nil {
		return ErrOptionsInvalid
	}
	if !app.ValidApplicationID(applicationID) {
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

// Authorize 实现 Authorizer。
func (a *StaticAuthorizer) Authorize(_ context.Context, caller Caller, action Action, scopeID string) error {
	if a == nil || !action.Valid() {
		return ErrAccessDenied
	}
	// 列表动作不针对单一 scope，实际可见范围由 ManageableScopes 决定；空 scope
	// 不能先被 ParseScope 拒绝，否则默认列表用法不可用。
	if action == ActionListGroups {
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
