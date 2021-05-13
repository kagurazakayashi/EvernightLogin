// Package delegation 实现“可使用权限”与“可转授权限”分离的委派模型。
//
// 背景：角色、权限与组成员关系只能说明主体“能不能使用某项能力”；能不能把这
// 项能力再交给别人，必须是另一份显式资格。仅拥有权限不自动获得转授资格，因此
// 本包把委派资格（Grant）单独持久化，并提供所有改变有效权限的写入路径共用的
// 统一检查（Guard）：
//
//   - 角色编辑（向角色组合权限）、启用角色；
//   - 把角色分配给用户或用户组；
//   - 向已有角色的用户组添加成员（“先配角色再拉人”的间接提权路径）；
//   - 应用成员加入/重新启用（会恢复该用户既有角色分配的有效权限）；
//   - 启用权限（会使已组合该权限的角色重新生效）。
//
// 检查与写入必须在同一数据库事务内完成：Guarded 方法都接收 audit.Tx，在调用方
// 的审计事务中读取委派资格、当前持有情况与目标限制，避免检查后状态被并发修改。
//
// 安全不变量：
//   - 只有受限本地初始化操作者（local_admin）与系统组件（system）能签发/撤回
//     委派资格；它们是受信通道，写入仍与安全审计同事务。普通用户不能自行
//     创建委派资格，也不能通过调用参数自称受信身份。
//   - 普通管理者只能转授“自己当前实际持有 + 有未过期未撤回委派资格”的权限；
//     持有但无委派资格、资格过期/撤回、本人权限已被收回，一律拒绝。
//   - 数据范围收缩：转授的数据范围必须是委派上限的子集；资源级上限不能转授
//     未声明（undefined）范围，避免用“未声明”扩大数据范围。
//   - 自我提权：默认不允许把权限转授给自己或自己所在的用户组；需要时由受信
//     操作者显式 allow_self。目标白名单可进一步限制可接收的用户/组。
//   - root 特殊通道不经过普通委派推导；受信通道的每次写入都记录操作者与前后值。
//
// 已知限制：无法识别同一自然人控制的“小号”，敏感权限应通过目标白名单限制接收
// 者；本包不实现审批引擎、再委派（受信操作者之外不能再签发委派资格）。
package delegation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

const (
	// ScopeSystem 是系统范围的固定 scope ID（沿用步骤 20/22/23/24/25 约定）。
	ScopeSystem = "system"
	// MaxScopeKeyBytes 是权限机器标识长度上限。
	MaxScopeKeyBytes = 128
	// MaxTargets 是目标白名单单类数量上限。
	MaxTargets = 64
	// MaxPermissionRefs 是单次转授检查的权限数量上限；超过时对普通管理者
	// fail-closed，避免无界循环，受信通道不受影响。
	MaxPermissionRefs = 512
	// MaxAffectedTargets 是单次检查的受影响目标数量上限；超过时对普通管理者
	// fail-closed，避免一次写入放大成无界的目标/成员查询。
	MaxAffectedTargets = 4096
	// DefaultListLimit/MaxListLimit 是委派列表分页边界。
	DefaultListLimit = 20
	MaxListLimit     = 100
	// MaxListOffset 限制深分页。
	MaxListOffset = 1_000_000

	grantIDPrefix      = "dlg_"
	grantIDRandomBytes = 16
)

// ScopeKind 是委派作用范围类型。
type ScopeKind string

const (
	// ScopeKindSystem 表示系统范围。
	ScopeKindSystem ScopeKind = "system"
	// ScopeKindApplication 表示应用范围。
	ScopeKindApplication ScopeKind = "application"
)

// ParseScope 解析委派作用范围：只接受 "system" 或有效应用 ID。
func ParseScope(scopeID string) (ScopeKind, string, error) {
	value := strings.TrimSpace(scopeID)
	if value == ScopeSystem {
		return ScopeKindSystem, "", nil
	}
	if !validApplicationID(value) {
		return "", "", fmt.Errorf("%w: 作用范围必须是 system 或有效应用 ID", ErrInvalidRequest)
	}
	return ScopeKindApplication, value, nil
}

// validApplicationID 复制应用 ID 校验（app_ + 32 位十六进制），避免依赖 app 包。
func validApplicationID(id string) bool {
	if len(id) != 4+32 || !strings.HasPrefix(id, "app_") {
		return false
	}
	_, err := hex.DecodeString(id[4:])
	return err == nil
}

// validGroupID 复制用户组 ID 校验（grp_ + 32 位十六进制）。
func validGroupID(id string) bool {
	if len(id) != 4+32 || !strings.HasPrefix(id, "grp_") {
		return false
	}
	_, err := hex.DecodeString(id[4:])
	return err == nil
}

// 领域错误哨兵。拒绝原因保持可诊断：调用方可据此返回稳定错误码与内部原因码。
var (
	ErrOptionsInvalid          = errors.New("委派服务选项无效")
	ErrInvalidRequest          = errors.New("委派请求无效")
	ErrStoreUnavailable        = errors.New("委派存储暂时不可用")
	ErrAuditUnavailable        = errors.New("关键操作未能可靠记录")
	ErrAccessDenied            = errors.New("未获准执行该操作")
	ErrGrantNotFound           = errors.New("委派资格不存在")
	ErrDelegatorInvalid        = errors.New("委派对象账户不可用")
	ErrPermissionNotFound      = errors.New("委派权限不存在")
	ErrPermissionUnavailable   = errors.New("该权限不可转授（已停用或 root_only）")
	ErrScopeMismatch           = errors.New("权限与委派作用范围不一致")
	ErrApplicationInactive     = errors.New("应用当前不可用于委派")
	ErrTransferNotGranted      = errors.New("缺少该权限的转授资格")
	ErrTransferExpired         = errors.New("委派资格已过期")
	ErrTransferRevoked         = errors.New("委派资格已撤回")
	ErrPermissionNotHeld       = errors.New("操作者当前不持有该权限")
	ErrSelfTransferDenied      = errors.New("不能向自身或自身所在用户组转授权限")
	ErrTargetNotAllowed        = errors.New("接收目标不在委派允许范围内")
	ErrDataScopeTooBroad       = errors.New("转授的数据范围超出委派上限")
	ErrDelegationNotSupported  = errors.New("该权限未配置转授资格检查")
	errDefaultDataScopeInvalid = errors.New("数据范围声明无效")
)

// ErrorCode 是与根包错误码注册表一致的字面值；根包测试核对登记状态。
type ErrorCode string

const (
	CodeReqInvalid         ErrorCode = "REQ_INVALID"
	CodePermissionRequired ErrorCode = "PERMISSION_REQUIRED"
	CodeAccessDenied       ErrorCode = "ACCESS_DENIED"
	CodeAppScopeMismatch   ErrorCode = "APP_SCOPE_MISMATCH"
	CodeClientDisabled     ErrorCode = "CLIENT_DISABLED"
	CodeUserDisabled       ErrorCode = "USER_DISABLED"
	CodeDBUnavailable      ErrorCode = "DB_UNAVAILABLE"
	CodeAuditWriteFailed   ErrorCode = "AUDIT_WRITE_FAILED"
	CodeInternalError      ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把委派领域错误映射到已登记错误码；非本包错误返回空字符串，便于调用方
// 在自身映射链中继续判断。受信通道无关的“不持有/无资格/过期/撤回”统一为
// PERMISSION_REQUIRED（缺少当前操作所需权限），自我/目标/数据范围限制为
// ACCESS_DENIED，范围串用为 APP_SCOPE_MISMATCH，应用停用为 CLIENT_DISABLED。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrGrantNotFound),
		errors.Is(err, ErrPermissionNotFound), errors.Is(err, errDefaultDataScopeInvalid):
		return CodeReqInvalid
	case errors.Is(err, ErrTransferNotGranted), errors.Is(err, ErrTransferExpired),
		errors.Is(err, ErrTransferRevoked), errors.Is(err, ErrPermissionNotHeld):
		return CodePermissionRequired
	case errors.Is(err, ErrSelfTransferDenied), errors.Is(err, ErrTargetNotAllowed),
		errors.Is(err, ErrDataScopeTooBroad), errors.Is(err, ErrAccessDenied),
		errors.Is(err, ErrPermissionUnavailable), errors.Is(err, ErrDelegationNotSupported):
		return CodeAccessDenied
	case errors.Is(err, ErrScopeMismatch):
		return CodeAppScopeMismatch
	case errors.Is(err, ErrApplicationInactive):
		return CodeClientDisabled
	case errors.Is(err, ErrDelegatorInvalid):
		return CodeUserDisabled
	case errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	case errors.Is(err, ErrOptionsInvalid):
		return CodeInternalError
	default:
		// 非本包错误：返回空字符串，让调用方的 CodeOf 继续映射。
		return ""
	}
}

// NewGrantID 生成 dlg_ + 128 位随机数的稳定委派资格 ID。
func NewGrantID(random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	buffer := make([]byte, grantIDRandomBytes)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", fmt.Errorf("无法生成委派资格 ID: %w", err)
	}
	return grantIDPrefix + hex.EncodeToString(buffer), nil
}

// ValidGrantID 报告委派资格 ID 是否符合本包生成的固定格式。
func ValidGrantID(id string) bool {
	value := strings.TrimSpace(id)
	if len(value) != len(grantIDPrefix)+2*grantIDRandomBytes || !strings.HasPrefix(value, grantIDPrefix) {
		return false
	}
	_, err := hex.DecodeString(value[len(grantIDPrefix):])
	return err == nil
}

// TargetKind 是转授接收目标类型。
type TargetKind string

const (
	// TargetUser 表示把权限转授给用户。
	TargetUser TargetKind = "user"
	// TargetGroup 表示把权限转授给用户组（组内当前与将来成员都会获得）。
	TargetGroup TargetKind = "group"
)

// Valid 报告目标类型是否已定义。
func (k TargetKind) Valid() bool {
	return k == TargetUser || k == TargetGroup
}

// Target 是转授接收目标；ID 必须是稳定用户 ID 或用户组 ID。
type Target struct {
	Kind TargetKind
	ID   string
}

// Valid 校验目标形状。
func (t Target) Valid() error {
	switch t.Kind {
	case TargetUser:
		if !account.ValidUserID(strings.TrimSpace(t.ID)) {
			return fmt.Errorf("%w: 目标用户 ID 格式无效", ErrInvalidRequest)
		}
	case TargetGroup:
		if !validGroupID(strings.TrimSpace(t.ID)) {
			return fmt.Errorf("%w: 目标用户组 ID 格式无效", ErrInvalidRequest)
		}
	default:
		return fmt.Errorf("%w: 目标类型无效", ErrInvalidRequest)
	}
	return nil
}

// AllowedTargets 是委派的目标白名单。两类均为空表示不限制具体目标（仍受
// AllowSelf 约束）；任一类非空时，对应类型的目标必须出现在该类列表中。
type AllowedTargets struct {
	Users  []string
	Groups []string
}

// Restricted 报告是否配置了目标白名单。
func (t AllowedTargets) Restricted() bool {
	return len(t.Users) > 0 || len(t.Groups) > 0
}

// allowedTargetsDocument 是 allowed_targets_json 的规范结构。
type allowedTargetsDocument struct {
	Version int      `json:"v"`
	Users   []string `json:"users,omitempty"`
	Groups  []string `json:"groups,omitempty"`
}

// ValidateTargets 校验目标白名单：数量有界、ID 格式正确、去重排序由 JSON 方法完成。
func ValidateTargets(targets AllowedTargets) error {
	if len(targets.Users) > MaxTargets || len(targets.Groups) > MaxTargets {
		return fmt.Errorf("%w: 目标白名单单类不能超过 %d 项", ErrInvalidRequest, MaxTargets)
	}
	for _, userID := range targets.Users {
		if !account.ValidUserID(strings.TrimSpace(userID)) {
			return fmt.Errorf("%w: 目标白名单中的用户 ID 无效", ErrInvalidRequest)
		}
	}
	for _, groupID := range targets.Groups {
		if !validGroupID(strings.TrimSpace(groupID)) {
			return fmt.Errorf("%w: 目标白名单中的用户组 ID 无效", ErrInvalidRequest)
		}
	}
	return nil
}

// JSON 把目标白名单编码为规范 JSON（去重、排序、版本 1）。
func (t AllowedTargets) JSON() (string, error) {
	if err := ValidateTargets(t); err != nil {
		return "", err
	}
	document := allowedTargetsDocument{Version: 1}
	document.Users = normalizeIDs(t.Users)
	document.Groups = normalizeIDs(t.Groups)
	encoded, err := json.Marshal(document)
	if err != nil {
		return "", fmt.Errorf("%w: 目标白名单不能编码", ErrInvalidRequest)
	}
	return string(encoded), nil
}

// ParseAllowedTargetsJSON 严格解析 allowed_targets_json：只接受版本 1、字段
// users/groups、禁止未知字段与重复项。空值等同于不限制。
func ParseAllowedTargetsJSON(raw string) (AllowedTargets, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return AllowedTargets{}, nil
	}
	decoder := json.NewDecoder(strings.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	var document allowedTargetsDocument
	if err := decoder.Decode(&document); err != nil {
		return AllowedTargets{}, fmt.Errorf("%w: 目标白名单不是合法 JSON", ErrInvalidRequest)
	}
	if decoder.More() {
		return AllowedTargets{}, fmt.Errorf("%w: 目标白名单包含多余内容", ErrInvalidRequest)
	}
	if document.Version != 1 {
		return AllowedTargets{}, fmt.Errorf("%w: 目标白名单版本不受支持", ErrInvalidRequest)
	}
	targets := AllowedTargets{Users: document.Users, Groups: document.Groups}
	if err := ValidateTargets(targets); err != nil {
		return AllowedTargets{}, err
	}
	seen := make(map[string]struct{}, len(targets.Users)+len(targets.Groups))
	for _, id := range append(append([]string{}, targets.Users...), targets.Groups...) {
		value := strings.TrimSpace(id)
		if _, exists := seen[value]; exists {
			return AllowedTargets{}, fmt.Errorf("%w: 目标白名单包含重复项", ErrInvalidRequest)
		}
		seen[value] = struct{}{}
	}
	return targets, nil
}

// PermissionRef 是转授检查中的一个权限引用。
//
// DataScopeJSON 是本次请求转授的数据范围：空字符串与 "{}" 表示未声明（undefined），
// 只有委派上限为 all 时才允许；显式 resources 必须是委派上限的子集。
type PermissionRef struct {
	PermissionID  string
	DataScopeJSON string
}

// Grant 是委派资格快照：某用户在某范围对某权限拥有“可转授”资格。
type Grant struct {
	ID              string
	DelegatorUserID string
	ScopeID         string
	ScopeKind       ScopeKind
	ApplicationID   string
	PermissionID    string
	PermissionKey   string
	PermissionName  string
	MaxDataScope    string
	AllowedTargets  AllowedTargets
	AllowSelf       bool
	ExpiresAt       *time.Time
	RevokedAt       *time.Time
	CreatedBy       audit.Actor
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// Active 报告资格在指定时刻是否可转授（未撤回且未过期）。
func (g Grant) Active(now time.Time) bool {
	if g.RevokedAt != nil {
		return false
	}
	if g.ExpiresAt != nil && !now.Before(*g.ExpiresAt) {
		return false
	}
	return true
}

// GrantRequest 是签发委派资格的白名单请求。受信操作者不能通过本请求变更
// 任何主体的有效权限，只登记“可转授”资格。
type GrantRequest struct {
	DelegatorUserID string
	ScopeID         string
	PermissionKey   string
	MaxDataScope    string
	AllowedTargets  AllowedTargets
	AllowSelf       bool
	ExpiresAt       *time.Time
}

// ListRequest 是委派资格列表请求：普通用户只能读取自己的资格；受信操作者可
// 指定 DelegatorUserID 或留空读取全部。
type ListRequest struct {
	DelegatorUserID string
	IncludeRevoked  bool
	Limit           int
	Offset          int
}

// DelegatablePermission 是“当前实际可转授”的权限摘要（区别于可使用权限）。
type DelegatablePermission struct {
	PermissionID string
	Key          string
	Name         string
	MaxDataScope string
	AllowSelf    bool
	ExpiresAt    *time.Time
}

// Caller 是可信操作者上下文；字段不导出，只能由构造器生成。委派资格签发/撤回
// 只接受本地初始化与系统操作者；普通用户只能读取自己的委派资格。
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

// UserCaller 构造已认证用户操作者（user）；委派资格签发/撤回会被拒绝。
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

// Actor 返回调用者的可信审计身份副本（只读），供宿主在构造 Guard 调用或
// 记录关联事件时使用；调用者身份仍只能由本包构造器产生。
func (c Caller) Actor() audit.Actor {
	return c.actor
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

// Guard 是所有改变有效权限的写入路径共用的转授检查接口，生产实现为 *Service。
//
// 方法必须在调用方的审计事务（audit.Tx）内执行，使其与写入处于同一一致性边界；
// 返回 nil 仅表示允许转授，不表示权限已授予。受信操作者（本地初始化/系统）直接
// 放行，由调用方的关键变更审计记录真实操作者。
//
// 所有方法都接收“受影响目标集合”或单个目标：间接提权（启用含权角色、启用权限、
// 组合权限进已分配角色、启用应用）会改变既有主体的有效权限，因此必须按真实目标
// 重新校验 AllowSelf 与目标白名单，而不是只校验委派资格本身。
type Guard interface {
	// CheckPermissionAccess 检查操作者能否把权限组合进角色：要求资格与当前实际持有，
	// 并按角色当前分配目标（用户与用户组）校验自我提权与目标白名单。
	CheckPermissionAccess(ctx context.Context, tx audit.Tx, actor audit.Actor, scopeID string, permissions []PermissionRef, targets []Target) error
	// CheckAssignment 检查操作者能否把权限转授给指定目标（资格、持有、自我提权与目标白名单）。
	CheckAssignment(ctx context.Context, tx audit.Tx, actor audit.Actor, scopeID string, permissions []PermissionRef, target Target) error
	// CheckPermissionActivation 检查操作者能否启用角色或启用权限：被启用的能力当前
	// 可能尚未生效（角色/权限已停用），因此只要求有效委派资格，不要求“当前持有”；
	// 但必须按启用后会重新获得权限的目标集合校验 AllowSelf 与目标白名单。
	CheckPermissionActivation(ctx context.Context, tx audit.Tx, actor audit.Actor, scopeID string, permissions []PermissionRef, targets []Target) error
	// CheckScopeRestoration 检查操作者能否启用应用：应用停用会整体拒绝其范围内权限，
	// 启用等于恢复这些权限。目标集合与权限集合由实现读取范围内将被恢复的权限及其
	// 持有目标；该路径允许应用处于停用状态（否则任何管理员都无法安全恢复）。
	CheckScopeRestoration(ctx context.Context, tx audit.Tx, actor audit.Actor, scopeID string) error
}

// GuardFuncs 是 Guard 的函数适配器，供宿主装配既有策略或测试替身使用。
// 生产装配应使用 New 构造的 *Service，不要用放宽的适配器替代真实检查。
type GuardFuncs struct {
	Access      func(ctx context.Context, tx audit.Tx, actor audit.Actor, scopeID string, permissions []PermissionRef, targets []Target) error
	Assignment  func(ctx context.Context, tx audit.Tx, actor audit.Actor, scopeID string, permissions []PermissionRef, target Target) error
	Activation  func(ctx context.Context, tx audit.Tx, actor audit.Actor, scopeID string, permissions []PermissionRef, targets []Target) error
	Restoration func(ctx context.Context, tx audit.Tx, actor audit.Actor, scopeID string) error
}

// CheckPermissionAccess 实现 Guard；未配置回调时 fail-closed。
func (g GuardFuncs) CheckPermissionAccess(ctx context.Context, tx audit.Tx, actor audit.Actor, scopeID string, permissions []PermissionRef, targets []Target) error {
	if g.Access == nil {
		return fmt.Errorf("%w: 未配置权限转授检查", ErrOptionsInvalid)
	}
	return g.Access(ctx, tx, actor, scopeID, permissions, targets)
}

// CheckAssignment 实现 Guard；未配置回调时 fail-closed。
func (g GuardFuncs) CheckAssignment(ctx context.Context, tx audit.Tx, actor audit.Actor, scopeID string, permissions []PermissionRef, target Target) error {
	if g.Assignment == nil {
		return fmt.Errorf("%w: 未配置目标转授检查", ErrOptionsInvalid)
	}
	return g.Assignment(ctx, tx, actor, scopeID, permissions, target)
}

// CheckPermissionActivation 实现 Guard；未配置回调时 fail-closed。
func (g GuardFuncs) CheckPermissionActivation(ctx context.Context, tx audit.Tx, actor audit.Actor, scopeID string, permissions []PermissionRef, targets []Target) error {
	if g.Activation == nil {
		return fmt.Errorf("%w: 未配置权限启用检查", ErrOptionsInvalid)
	}
	return g.Activation(ctx, tx, actor, scopeID, permissions, targets)
}

// CheckScopeRestoration 实现 Guard；未配置回调时 fail-closed（不放行应用启用）。
func (g GuardFuncs) CheckScopeRestoration(ctx context.Context, tx audit.Tx, actor audit.Actor, scopeID string) error {
	if g.Restoration == nil {
		return fmt.Errorf("%w: 未配置应用启用检查", ErrOptionsInvalid)
	}
	return g.Restoration(ctx, tx, actor, scopeID)
}

// NormalizeTargets 校验并规范化受影响目标集合：去除首尾空白、按 (类型, ID) 去重、
// 校验 ID 形状并限制数量。任何非法项都返回错误（调用方应 fail-closed），不静默丢弃，
// 避免损坏数据让校验范围被悄悄缩小。
func NormalizeTargets(targets []Target) ([]Target, error) {
	if len(targets) > MaxAffectedTargets {
		return nil, fmt.Errorf("%w: 受影响目标数量超过上限 %d", ErrInvalidRequest, MaxAffectedTargets)
	}
	result := make([]Target, 0, len(targets))
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		normalized := Target{Kind: target.Kind, ID: strings.TrimSpace(target.ID)}
		if err := normalized.Valid(); err != nil {
			return nil, err
		}
		key := string(normalized.Kind) + ":" + normalized.ID
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, normalized)
	}
	return result, nil
}

// normalizeIDs 去重并排序非空白 ID。
func normalizeIDs(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	result := make([]string, 0, len(ids))
	for _, id := range ids {
		value := strings.TrimSpace(id)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sortStrings(result)
	return result
}

// sortStrings 是简单插入排序，避免为小列表引入额外依赖。
func sortStrings(values []string) {
	for index := 1; index < len(values); index++ {
		for position := index; position > 0 && values[position] < values[position-1]; position-- {
			values[position], values[position-1] = values[position-1], values[position]
		}
	}
}

// dataScopeMode 与 internal/authz 的第一版数据范围契约保持一致（v1: all/none/
// resources，未声明为 undefined）。委派包不导入 authz，避免 authz → permission →
// delegation 的导入环；两处解析与校验规则必须同步调整，任何差异都不能放宽委派
// 上限。数据范围上限只接受显式 all/none/resources，不接受未声明。
type dataScopeMode string

const (
	dataScopeUndefined dataScopeMode = "undefined"
	dataScopeAll       dataScopeMode = "all"
	dataScopeNone      dataScopeMode = "none"
	dataScopeResources dataScopeMode = "resources"
)

const (
	// MaxDataScopeResources 是数据范围资源数量上限（与 authz 契约一致）。
	MaxDataScopeResources = 64
	// MaxResourceIDBytes 是单个资源标识字节上限（与 authz 契约一致）。
	MaxResourceIDBytes = 256
)

// dataScope 是委派检查使用的数据范围快照。
type dataScope struct {
	Mode      dataScopeMode
	Resources []string
}

// empty 报告数据范围是否未声明。
func (d dataScope) empty() bool {
	return d.Mode == "" || d.Mode == dataScopeUndefined
}

// dataScopeDocument 是 data_scope_json 的规范结构。
type dataScopeDocument struct {
	Version   int      `json:"v"`
	Mode      string   `json:"mode"`
	Resources []string `json:"resources,omitempty"`
}

// parseDataScope 严格解析数据范围 JSON：空值、"{}"、"null" 视为未声明；其余只
// 接受版本 1 的 all/none/resources，禁止未知字段、重复资源与非法资源标识。
func parseDataScope(raw string) (dataScope, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "{}" || trimmed == "null" {
		return dataScope{Mode: dataScopeUndefined}, nil
	}
	if len(trimmed) > 8192 {
		return dataScope{}, fmt.Errorf("%w: 数据范围声明过长", ErrInvalidRequest)
	}
	decoder := json.NewDecoder(strings.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	var document dataScopeDocument
	if err := decoder.Decode(&document); err != nil {
		return dataScope{}, fmt.Errorf("%w: 数据范围不是合法 JSON", ErrInvalidRequest)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return dataScope{}, fmt.Errorf("%w: 数据范围包含多余内容", ErrInvalidRequest)
	}
	if document.Version != 1 {
		return dataScope{}, fmt.Errorf("%w: 数据范围版本不受支持", ErrInvalidRequest)
	}
	switch dataScopeMode(document.Mode) {
	case dataScopeAll, dataScopeNone:
		if len(document.Resources) != 0 {
			return dataScope{}, fmt.Errorf("%w: all/none 数据范围不能包含资源列表", ErrInvalidRequest)
		}
		return dataScope{Mode: dataScopeMode(document.Mode)}, nil
	case dataScopeResources:
		if len(document.Resources) == 0 || len(document.Resources) > MaxDataScopeResources {
			return dataScope{}, fmt.Errorf("%w: resources 数据范围资源数量必须是 1～%d", ErrInvalidRequest, MaxDataScopeResources)
		}
		seen := make(map[string]struct{}, len(document.Resources))
		resources := make([]string, 0, len(document.Resources))
		for _, resource := range document.Resources {
			if problem := validateResourceID(resource); problem != "" {
				return dataScope{}, fmt.Errorf("%w: %s", ErrInvalidRequest, problem)
			}
			if _, duplicated := seen[resource]; duplicated {
				return dataScope{}, fmt.Errorf("%w: 数据范围资源重复", ErrInvalidRequest)
			}
			seen[resource] = struct{}{}
			resources = append(resources, resource)
		}
		sortStrings(resources)
		return dataScope{Mode: dataScopeResources, Resources: resources}, nil
	default:
		return dataScope{}, fmt.Errorf("%w: 数据范围模式无效", ErrInvalidRequest)
	}
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

// normalizeMaxDataScope 校验并规范化委派数据范围上限：空值默认 all；只接受
// 当前版本显式结构（all/none/resources），不接受历史未声明，避免把“未声明”
// 当上限。返回值是规范 JSON。
func normalizeMaxDataScope(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return `{"v":1,"mode":"all"}`, nil
	}
	scope, err := parseDataScope(trimmed)
	if err != nil {
		return "", fmt.Errorf("%w: 委派数据范围上限无效", ErrInvalidRequest)
	}
	switch scope.Mode {
	case dataScopeAll:
		return `{"v":1,"mode":"all"}`, nil
	case dataScopeNone:
		return `{"v":1,"mode":"none"}`, nil
	case dataScopeResources:
		if len(scope.Resources) == 0 {
			return "", fmt.Errorf("%w: 委派数据范围上限缺少资源", ErrInvalidRequest)
		}
		document := struct {
			Version   int      `json:"v"`
			Mode      string   `json:"mode"`
			Resources []string `json:"resources"`
		}{Version: 1, Mode: string(dataScopeResources), Resources: scope.Resources}
		encoded, err := json.Marshal(document)
		if err != nil {
			return "", fmt.Errorf("%w: 委派数据范围上限不能编码", ErrInvalidRequest)
		}
		return string(encoded), nil
	default:
		return "", fmt.Errorf("%w: 委派数据范围上限必须是 all、none 或 resources", ErrInvalidRequest)
	}
}

// parseRequestedDataScope 解析本次转授请求的数据范围；空值与 "{}" 视为未声明。
func parseRequestedDataScope(raw string) (dataScope, error) {
	scope, err := parseDataScope(raw)
	if err != nil {
		return dataScope{}, fmt.Errorf("%w: 转授数据范围声明无效", ErrInvalidRequest)
	}
	return scope, nil
}

// dataScopeSubset 报告请求转授的数据范围是否不超出委派上限。
//
// 规则：none 永远允许（不转授数据）；undefined/all 只有上限为 all 时才允许；
// resources 在上限为 all 或上限资源集合包含请求资源时允许。资源级上限不能
// 转授未声明范围，防止把“未声明”解释成更宽的数据范围。
func dataScopeSubset(requested, allowed dataScope) bool {
	if requested.Mode == dataScopeNone {
		return true
	}
	if allowed.Mode == dataScopeAll {
		return true
	}
	if requested.empty() || requested.Mode == dataScopeAll {
		return false
	}
	if allowed.Mode != dataScopeResources {
		return false
	}
	allowedSet := make(map[string]struct{}, len(allowed.Resources))
	for _, resource := range allowed.Resources {
		allowedSet[resource] = struct{}{}
	}
	for _, resource := range requested.Resources {
		if _, ok := allowedSet[resource]; !ok {
			return false
		}
	}
	return true
}

// trustedActor 报告操作者是否属于受信通道（受限本地初始化/系统组件）。受信
// 通道具有签发委派资格与执行受控 root 相关操作的能力，但每次写入仍必须与安全
// 审计同事务记录真实操作者。
func trustedActor(actor audit.Actor) bool {
	return actor.Type == audit.ActorLocalAdmin || actor.Type == audit.ActorSystem
}

// validatePermissionIDShape 校验权限 ID 形状（perm_ + 32 位十六进制）。
func validPermissionIDShape(id string) bool {
	value := strings.TrimSpace(id)
	if len(value) != 5+32 || !strings.HasPrefix(value, "perm_") {
		return false
	}
	_, err := hex.DecodeString(value[5:])
	return err == nil
}
