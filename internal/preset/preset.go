// Package preset 实现系统角色、用户组与权限预设目录的版本化初始化与恢复默认。
//
// 背景与安全边界（对应需求 11.1、11.3、11.5 与 AGENTS.md 第 10 节）：
//   - 预设目录是机器可读、版本化的数据（见 Catalog）：系统管理员、用户管理员、
//     客服、审计员、普通用户五个系统角色与默认用户组；应用管理员与应用普通用户
//     按应用创建模板生成，每个应用各自独立，不共用跨应用记录。
//   - 每条权限都有稳定机器标识、中文名称、能做什么、生效范围与不能做什么；同一格
//     列出的多个权限逐条登记为独立权限，不被捆成一个隐式开关。
//   - 预设不创建带固定密码的工作人员账户，也不创建任何账户；初始化只登记权限、
//     角色与空用户组，不进行角色分配，因此不会给任何用户赋权，也不存在普通 root
//     角色（root 不是可分配角色）。
//   - 初始化（Install）是幂等、可重复执行的：同一目录版本重复执行只补齐缺失项，
//     不覆盖用户已调整的角色权限组合；更高版本升级同样只补缺失项并把“已存在角色
//     缺少的新默认权限”列入待恢复提示，不静默改写既有组合。
//   - 恢复默认（Restore）必须满足三项：先经 Preview 读取并展示差异；使用服务端
//     签发、绑定操作者与目录状态摘要、短时有效且单次使用的确认令牌完成“再次授权”
//     （客户端布尔值不能冒充）；整次恢复在一个安全审计事务内完成。恢复只作用于
//     明确选择的目录/角色，保留自定义角色、自定义权限与自定义组成员。
//   - 恢复的写入路径（创建/调整角色权限、恢复权限启用状态）与步骤 26 的
//     delegation.Guard 在同一事务内检查：受信本地/系统通道按既有语义放行，未来
//     开放给非受信管理者时，Guard 会拒绝超出其持有与可转授范围的权限，恢复不能
//     扩大操作者的可转授范围。
//   - 功能尚未实现的权限在目录中登记并标记 Implemented=false；本包只登记定义与
//     说明，不实现对应业务操作，也不向业务调用返回虚假成功。业务方必须显式检查
//     该标记，未实现时返回明确的“未实现”错误。
//
// 已知限制：本包的初始化/恢复只接受受信本地初始化（local_admin）与系统（system）
// 操作者，非受信管理者的恢复入口需要后续会话层、再次认证与审批引擎接入；恢复的
// “差异展示 + 确认令牌”是服务层实现，不等同于密码/MFA 再次认证。预览令牌保存在
// 进程内，多实例部署需要共享存储的令牌表（后续步骤）。应用创建自动调用本包的
// 接线由宿主装配步骤完成，本包提供幂等的 InstallApplicationScope 供创建成功后调用。
package preset

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
)

const (
	// ScopeSystem 是系统范围的固定 scope ID（沿用步骤 20/22/23/24/25/26 约定）。
	ScopeSystem = "system"
	// MaxSelections 是单次预览/恢复的选择项上限（每个选择项是一个作用范围）。
	MaxSelections = 16
	// MaxRoleKeysPerScope 是单个作用范围单次可选择的角色数量上限。
	MaxRoleKeysPerScope = 32
	// MaxPreviewTokens 是进程内未使用预览令牌数量上限，避免无界内存增长。
	MaxPreviewTokens = 256
	// DefaultPreviewTTL 是预览确认令牌的默认有效期。
	DefaultPreviewTTL = 10 * time.Minute
	// MinPreviewTTL/MaxPreviewTTL 是调用方可配置的令牌有效期边界。
	MinPreviewTTL = 1 * time.Minute
	MaxPreviewTTL = 30 * time.Minute

	previewTokenBytes = 32
)

// ScopeKind 是预设作用范围类型。
type ScopeKind string

const (
	// ScopeKindSystem 表示系统范围。
	ScopeKindSystem ScopeKind = "system"
	// ScopeKindApplication 表示应用范围（scope ID 等于应用 ID）。
	ScopeKindApplication ScopeKind = "application"
)

// ParseScope 解析预设作用范围：只接受 "system" 或有效应用 ID。
func ParseScope(scopeID string) (ScopeKind, string, error) {
	value := strings.TrimSpace(scopeID)
	if value == ScopeSystem {
		return ScopeKindSystem, "", nil
	}
	if len(value) != 4+32 || !strings.HasPrefix(value, "app_") {
		return "", "", fmt.Errorf("%w: 作用范围必须是 system 或有效应用 ID", ErrInvalidRequest)
	}
	for index := 4; index < len(value); index++ {
		character := value[index]
		if (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') {
			continue
		}
		return "", "", fmt.Errorf("%w: 应用 ID 含非十六进制字符", ErrInvalidRequest)
	}
	return ScopeKindApplication, value, nil
}

// Caller 是可信调用者身份。身份只能由构造器生成，不能由请求参数自称。
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

func newCaller(kind audit.ActorKind, id string) (Caller, error) {
	actor := audit.Actor{Type: kind, ID: id}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 操作者标识无效", ErrInvalidRequest)
	}
	return Caller{actor: actor}, nil
}

// Actor 返回操作者审计身份。
func (c Caller) Actor() audit.Actor { return c.actor }

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

// trusted 报告调用者是否属于受信通道（受限本地初始化/系统组件）。预设初始化与
// 恢复只接受受信通道，其他调用者一律 ACCESS_DENIED（fail-closed）。
func (c Caller) trusted() bool {
	return c.actor.Type == audit.ActorLocalAdmin || c.actor.Type == audit.ActorSystem
}

// 领域错误哨兵。拒绝原因保持可诊断，调用方据此返回稳定错误码与内部原因码。
var (
	ErrOptionsInvalid      = errors.New("预设服务选项无效")
	ErrInvalidRequest      = errors.New("预设请求无效")
	ErrScopeInvalid        = errors.New("预设作用范围无效")
	ErrApplicationInactive = errors.New("应用当前不可用预设模板")
	ErrAccessDenied        = errors.New("未获准执行预设操作")
	ErrStateConflict       = errors.New("预设状态已被其他操作修改")
	ErrCatalogConflict     = errors.New("预设目录与现有定义冲突")
	ErrCatalogDowngrade    = errors.New("已安装的预设目录版本高于当前程序")
	ErrPreviewRequired     = errors.New("缺少有效的差异预览确认令牌")
	ErrPreviewStale        = errors.New("预览后状态已变化，需要重新预览")
	ErrStoreUnavailable    = errors.New("预设存储暂时不可用")
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

// CodeOf 把预设领域错误映射到已登记错误码；委派检查错误优先映射为稳定错误码。
func CodeOf(err error) ErrorCode {
	if code := delegation.CodeOf(err); code != "" {
		return ErrorCode(code)
	}
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrScopeInvalid),
		errors.Is(err, ErrPreviewRequired):
		return CodeReqInvalid
	case errors.Is(err, ErrStateConflict), errors.Is(err, ErrCatalogConflict),
		errors.Is(err, ErrCatalogDowngrade), errors.Is(err, ErrPreviewStale):
		return CodeConflict
	case errors.Is(err, ErrAccessDenied):
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

// ScopeInfo 是作用范围数据库快照。
type ScopeInfo struct {
	ScopeID           string
	Kind              ScopeKind
	ApplicationID     string
	ApplicationActive bool
}

// PermissionRecord 是预设读取/写入的权限目录快照。
type PermissionRecord struct {
	ID          string
	ScopeID     string
	Key         string
	Name        string
	Description string
	Limits      string
	IsBuiltin   bool
	RootOnly    bool
	Enabled     bool
}

// RoleRecord 是预设读取/写入的角色快照。
type RoleRecord struct {
	ID          string
	ScopeID     string
	Key         string
	Name        string
	Description string
	Limits      string
	IsBuiltin   bool
	Enabled     bool
}

// RolePermissionRecord 是角色当前组合的权限摘要。
type RolePermissionRecord struct {
	PermissionID string
	Key          string
	Enabled      bool
	RootOnly     bool
}

// GroupRecord 是预设读取/写入的用户组快照。
type GroupRecord struct {
	ID          string
	ScopeID     string
	GroupKey    string
	Name        string
	Description string
}

// InstallState 是某个作用范围已初始化的目录版本记录。
type InstallState struct {
	ScopeID        string
	CatalogVersion string
	AppliedAt      time.Time
	UpdatedAt      time.Time
}

// Store 是预设目录初始化与恢复所需的持久化契约，由 internal/preset/sqlite 提供
// 生产实现。所有写入方法都必须接收调用方审计事务，使“委派检查 + 写入 + 审计”处于
// 同一一致性边界；读取方法无事务参数，恢复前会重新计算差异并比对预览摘要。
type Store interface {
	GetScope(ctx context.Context, scopeID string) (ScopeInfo, error)
	ListPermissions(ctx context.Context, scopeID string) ([]PermissionRecord, error)
	ListRoles(ctx context.Context, scopeID string) ([]RoleRecord, error)
	ListRolePermissions(ctx context.Context, roleID string) ([]RolePermissionRecord, error)
	ListGroups(ctx context.Context, scopeID string) ([]GroupRecord, error)
	// PermissionHolderTargets 在调用方事务内读取“启用该权限后会重新获得它”的用户
	// 与用户组目标，供恢复启用状态前复核委派目标限制。
	PermissionHolderTargets(ctx context.Context, tx audit.Tx, permissionID string) ([]delegation.Target, error)
	// RoleAssignmentTargets 在调用方事务内读取角色当前分配的用户与用户组目标，供
	// 调整角色权限组合前复核委派目标限制。
	RoleAssignmentTargets(ctx context.Context, tx audit.Tx, roleID, scopeID string) ([]delegation.Target, error)
	GetInstallState(ctx context.Context, scopeID string) (InstallState, bool, error)
	ListInstallStates(ctx context.Context) ([]InstallState, error)
	// SnapshotFingerprint 返回一组作用范围目录状态的稳定摘要（范围与应用启用
	// 状态、初始化版本、权限、角色、角色权限组合、用户组），供预览记录“操作者
	// 确认时的状态”。
	SnapshotFingerprint(ctx context.Context, scopeIDs []string) (string, error)
	// SnapshotFingerprintTx 在调用方审计事务内重新计算同一摘要。恢复在写入前
	// 比对它，保证“预览内容=实际执行内容”：预览复核后到写入前的并发修改必须
	// 被拒绝，不能用旧计划覆盖新状态（TOCTOU）。
	SnapshotFingerprintTx(ctx context.Context, tx audit.Tx, scopeIDs []string) (string, error)

	CreatePermission(ctx context.Context, tx audit.Tx, record PermissionRecord) error
	UpdatePermissionText(ctx context.Context, tx audit.Tx, id, name, description, limits string, now time.Time) error
	SetPermissionEnabled(ctx context.Context, tx audit.Tx, id string, enabled bool, now time.Time) error
	CreateRole(ctx context.Context, tx audit.Tx, record RoleRecord) error
	CreateGroup(ctx context.Context, tx audit.Tx, record GroupRecord) error
	AddRolePermission(ctx context.Context, tx audit.Tx, roleID, permissionID, scopeID string) (bool, error)
	RemoveRolePermission(ctx context.Context, tx audit.Tx, roleID, permissionID string) (bool, error)
	SaveInstallState(ctx context.Context, tx audit.Tx, state InstallState) error
}

// AuditRecorder 是预设服务依赖的审计契约。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// Options 是预设服务依赖。Store/Audit/Transfers 必填；缺少任一项服务不可构造，
// 不放行任何初始化或恢复请求。Catalog 为空时使用 DefaultCatalog。
type Options struct {
	Store      Store
	Audit      AuditRecorder
	Transfers  delegation.Guard
	Catalog    *Catalog
	Now        func() time.Time
	Random     io.Reader
	Logger     *slog.Logger
	PreviewTTL time.Duration
}

// Service 是预设目录初始化与恢复服务；构造后不可变，可并发使用。
type Service struct {
	store      Store
	audit      AuditRecorder
	transfers  delegation.Guard
	catalog    *Catalog
	now        func() time.Time
	random     io.Reader
	logger     *slog.Logger
	previewTTL time.Duration

	// previewMu 保护进程内预览确认令牌；令牌短时有效、单次使用并绑定操作者与
	// 状态摘要，客户端无法用布尔值冒充“已展示差异并再次授权”。
	previewMu     sync.Mutex
	previewTokens map[string]previewToken
}

// previewToken 是一次未消费的差异预览确认令牌记录。
type previewToken struct {
	actorKey       string
	requestID      string
	catalogVersion string
	digest         string
	// fingerprint 是预览时各作用范围目录状态的稳定摘要。恢复会在写入事务内重算
	// 并比对它，确保“预览内容=实际执行内容”（防 TOCTOU：预览后到写入前的并发
	// 修改必须被拒绝，而不是用旧计划覆盖新状态）。
	fingerprint string
	selections  []RoleSelection
	skipped     []SkippedScope
	all         bool
	expiresAt   time.Time
}

// requireTrusted 拒绝非受信调用者，并把请求编号带入后续审计。
func requireTrusted(caller Caller) error {
	if err := caller.actor.Validate(); err != nil {
		return fmt.Errorf("%w: 操作者标识无效", ErrInvalidRequest)
	}
	if !caller.trusted() {
		return fmt.Errorf("%w: 只有受限本地初始化或系统操作者可以初始化或恢复预设", ErrAccessDenied)
	}
	return nil
}

// actorKey 返回审计身份的唯一字符串，用于绑定预览令牌。
func actorKey(actor audit.Actor) string {
	return string(actor.Type) + "|" + actor.ID
}

// normalizeContext 在上下文为空时使用 Background，避免下游 nil 上下文。
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// isNil 用接口的 nil 判断辅助依赖校验（typed nil 也视为缺失）。
func isNil(value any) bool {
	if value == nil {
		return true
	}
	switch typed := value.(type) {
	case Store:
		return typed == nil
	case AuditRecorder:
		return typed == nil
	case delegation.Guard:
		return typed == nil
	}
	return false
}

// constantTimeEqual 比较两个等长字符串，降低令牌比较的时序差异。
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// randHex 生成指定字节数的随机十六进制字符串。
func randHex(random io.Reader, size int) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	buffer := make([]byte, size)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", err
	}
	const alphabet = "0123456789abcdef"
	result := make([]byte, size*2)
	for index, value := range buffer {
		result[index*2] = alphabet[value>>4]
		result[index*2+1] = alphabet[value&0x0f]
	}
	return string(result), nil
}
