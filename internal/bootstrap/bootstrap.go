// Package bootstrap 实现本地受控的首次初始化：建立唯一 root 身份并让它处于
// 「受限待配置状态」，不开放匿名远程创建管理员的入口。
//
// 背景与边界（对应步骤 28）：
//   - 本包没有 HTTP/远程入口，调用方只能通过显式传入的可信 Caller 与 Authorizer
//     调用；生产实现只允许审计包定义的 local_admin（本地受控操作者），系统与普通
//     用户身份一律拒绝。
//   - 初始化不使用固定默认密码，也不保存任何密码或密码哈希：root 创建后只签发
//     一条一次性、本机、短期的配置凭证（internal/credential，数据库只保存摘要）。
//     正式密码与强认证由后续步骤的正式密码服务完成；在此之前本包绝不签发会话、
//     令牌或“完整管理员身份”，受限状态最多只允许必要的安全设置。
//   - 并发初始化由「进程内互斥 + 数据库条件插入」共同保证最多创建一个 root；
//     0001 的 ux_single_root 唯一索引与 0008 的单例约束是最后防线。初始化完成后
//     创建入口关闭：再次初始化返回 ErrAlreadyInitialized，不会重建默认账户。
//   - 状态持久化在 root_initializations 单例表，重启后只读取数据库，不会重新
//     生成默认账户；失败后可通过状态查询与重新签发凭证恢复，不实现完整应急重置。
//
// 安全不变量：
//   - root 用户名固定为保留值 root，普通账户创建规则永久禁止该名称，避免抢占。
//   - 一次性配置凭证用途固定为 PurposeRootSetup、目标绑定生成的 root 用户 ID，
//     有效期 1 分钟～1 小时（默认 15 分钟），过期、重放、错误绑定与错误操作者
//     全部拒绝。
//   - 初始化、凭证兑换、凭证重新签发与状态读取都写安全审计；初始化与兑换要求
//     成功审计与业务变更在同一事务提交，审计不可用时拒绝变更（fail-closed）。
//   - 凭证明文只出现在 Initialize/Reissue 的返回结果中一次，日志、审计与错误
//     文本只包含凭证 ID / 状态，不包含 Secret。
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
)

const (
	// RootUsername 是 root 账户的固定显示用户名。该名称在 account 保留名单内，
	// 普通创建请求无法占用，因此 root 身份不会被同名普通账户抢占。
	RootUsername = "root"
	// RootUsernameNormalized 是 RootUsername 经 NFKC + Unicode 大小写折叠后的
	// 唯一性判定值（"root"）。
	RootUsernameNormalized = "root"
	// DefaultRootNickname 是未指定昵称时 root 的默认昵称。
	DefaultRootNickname = "系统所有者"
	// PurposeRootSetup 是 root 受限配置一次性凭证的固定用途。后续正式密码服务
	// 必须复用同一用途常量，不能另造未绑定用途的入口。
	PurposeRootSetup = "root.setup"
	// DefaultSetupCredentialTTL 是未指定有效期时的默认配置凭证有效期。
	DefaultSetupCredentialTTL = 15 * time.Minute
	// MinSetupCredentialTTL 是配置凭证允许的最短有效期。
	MinSetupCredentialTTL = time.Minute
	// MaxSetupCredentialTTL 是配置凭证允许的最长有效期；首次配置必须是短期凭证，
	// 不允许长期或永久有效的本地旁路。
	MaxSetupCredentialTTL = time.Hour
	// maxCredentialIDBytes/maxCredentialSecretBytes 限制请求字段长度，避免把超大
	// 输入带进凭证查询或错误信息。
	maxCredentialIDBytes     = 64
	maxCredentialSecretBytes = 128
)

// State 是首次初始化的持久状态。它描述的是「初始化流程」而不是账户全局状态：
// root 的完整能力不通过普通角色推导，因此本状态不等同于用户角色或会话权限。
type State string

const (
	// StateUninitialized 表示还没有初始化记录，是全新实例的初始状态。
	StateUninitialized State = ""
	// StateExistingRoot 表示数据库里已存在 is_root=1 的账户，但没有对应的初始化
	// 记录（只可能来自旧版本数据或人工写入）。本包不会自动接管或重建它，只如实
	// 报告以便本地维护/后续应急流程处理。
	StateExistingRoot State = "existing_root"
	// StatePendingSetup 表示 root 已创建并处于受限待配置状态，等待一次性配置凭证
	// 兑换；凭证过期或丢失时可重新签发，但不会重新创建 root。
	StatePendingSetup State = "pending_setup"
	// StateSetupVerified 表示一次性配置凭证已兑换，只允许必要安全设置；仍不得
	// 签发完整管理员会话。正式密码/强认证由步骤 29 的正式服务完成。
	StateSetupVerified State = "setup_verified"
	// StateReady 表示正式密码与必需强认证已配置。本步保留该状态，转换由后续正式
	// 密码服务完成；本步不提供把它设为 ready 的公开方法。
	StateReady State = "ready"
)

// Valid 报告状态是否为已定义值（含非持久化的诊断状态）。
func (s State) Valid() bool {
	switch s {
	case StateUninitialized, StateExistingRoot, StatePendingSetup, StateSetupVerified, StateReady:
		return true
	default:
		return false
	}
}

// persisted 报告状态是否允许写入 root_initializations.state。
func (s State) persisted() bool {
	return s == StatePendingSetup || s == StateSetupVerified || s == StateReady
}

// Description 返回状态的中文直白说明，用于本地诊断输出，不含秘密。
func (s State) Description() string {
	switch s {
	case StateUninitialized:
		return "实例尚未初始化：还没有 root 账户与初始化记录。"
	case StateExistingRoot:
		return "数据库已存在 root 账户，但缺少初始化记录：可能来自旧版本或人工数据，需本地维护确认，本程序不会自动接管或重建。"
	case StatePendingSetup:
		return "root 已创建，处于受限待配置状态：仅持有一次性本机短期配置凭证，没有默认密码，也不会签发管理员会话。"
	case StateSetupVerified:
		return "一次性配置凭证已兑换，root 仍处于受限待配置状态：只允许必要的安全设置（如正式密码/强认证），凭证不能当会话使用。"
	case StateReady:
		return "正式密码与必需强认证已配置，初始化流程完成。"
	default:
		return "未知初始化状态。"
	}
}

// Action 是可审计的初始化操作动作。
type Action string

const (
	// ActionInitialize 创建唯一 root 并签发一次性受限配置凭证。
	ActionInitialize Action = "root.initialize"
	// ActionStatus 读取初始化状态（不含秘密）。
	ActionStatus Action = "root.status"
	// ActionRedeemSetupCredential 兑换一次性配置凭证，进入受限已校验状态。
	ActionRedeemSetupCredential Action = "root.setup.redeem"
	// ActionReissueSetupCredential 重新签发一次性配置凭证（本地可诊断恢复入口）。
	ActionReissueSetupCredential Action = "root.setup.reissue"
)

// Valid 报告动作是否已定义。
func (a Action) Valid() bool {
	switch a {
	case ActionInitialize, ActionStatus, ActionRedeemSetupCredential, ActionReissueSetupCredential:
		return true
	default:
		return false
	}
}

// 领域错误哨兵。调用方用 errors.Is 判断，并可用 CodeOf 映射到根包错误码。
var (
	// ErrOptionsInvalid 表示服务构造依赖不合法。
	ErrOptionsInvalid = errors.New("首次初始化服务选项无效")
	// ErrInvalidRequest 表示初始化请求字段、root 资料或凭证输入不合法。
	ErrInvalidRequest = errors.New("首次初始化请求无效")
	// ErrAlreadyInitialized 表示 root 或初始化记录已存在，创建入口已关闭。
	ErrAlreadyInitialized = errors.New("实例已完成 root 初始化")
	// ErrNotInitialized 表示尚未完成 root 创建，不能兑换或重签凭证。
	ErrNotInitialized = errors.New("实例尚未完成 root 初始化")
	// ErrSetupStateConflict 表示当前受限状态不允许该操作（例如凭证已兑换又重放、
	// 或凭证记录已被并发修改），调用方应重新读取状态。
	ErrSetupStateConflict = errors.New("当前初始化状态不允许该操作")
	// ErrSetupCredentialInvalid 表示一次性配置凭证无效：未知、绑定不符、过期、
	// 已消费、已撤销或内容错误。对外不区分具体原因，避免凭证探测。
	ErrSetupCredentialInvalid = errors.New("一次性配置凭证无效")
	// ErrRootUsernameTaken 表示保留的 root 用户名已被非 root 账户占用，必须由
	// 本地维护流程确认后再初始化，程序不会静默改名或覆盖。
	ErrRootUsernameTaken = errors.New("root 保留用户名已被占用")
	// ErrAccessDenied 表示可信调用身份未获准执行该操作。
	ErrAccessDenied = errors.New("未获准执行首次初始化操作")
	// ErrStoreUnavailable 表示初始化存储暂时不可用。
	ErrStoreUnavailable = errors.New("首次初始化存储暂时不可用")
	// ErrAuditUnavailable 表示安全审计未能可靠写入，操作被拒绝。
	ErrAuditUnavailable = errors.New("关键操作未能可靠记录")
)

// ErrorCode 是根包错误码注册表中的稳定字符串值。internal 包不能 import 根包，
// 因此这里只保存与注册表一致的字面值；根包测试会核对它们确实已登记。
type ErrorCode string

const (
	// CodeReqInvalid 对应已登记的 REQ_INVALID。
	CodeReqInvalid ErrorCode = "REQ_INVALID"
	// CodeConflict 对应已登记的 CONFLICT。
	CodeConflict ErrorCode = "CONFLICT"
	// CodeTokenInvalid 对应已登记的 TOKEN_INVALID（一次性配置凭证无效）。
	CodeTokenInvalid ErrorCode = "TOKEN_INVALID"
	// CodeAccessDenied 对应已登记的 ACCESS_DENIED。
	CodeAccessDenied ErrorCode = "ACCESS_DENIED"
	// CodeDBUnavailable 对应已登记的 DB_UNAVAILABLE。
	CodeDBUnavailable ErrorCode = "DB_UNAVAILABLE"
	// CodeAuditWriteFailed 对应已登记的 AUDIT_WRITE_FAILED。
	CodeAuditWriteFailed ErrorCode = "AUDIT_WRITE_FAILED"
	// CodeInternalError 对应已登记的 INTERNAL_ERROR。
	CodeInternalError ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把初始化领域错误映射到已登记错误码。审计失败优先判定，避免把“失败
// 证据未能可靠保存”伪装成普通状态冲突；未知错误一律视为内部错误。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrNotInitialized):
		return CodeReqInvalid
	case errors.Is(err, ErrAlreadyInitialized), errors.Is(err, ErrSetupStateConflict),
		errors.Is(err, ErrRootUsernameTaken):
		return CodeConflict
	case errors.Is(err, ErrSetupCredentialInvalid):
		return CodeTokenInvalid
	case errors.Is(err, ErrAccessDenied):
		return CodeAccessDenied
	case errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	default:
		return CodeInternalError
	}
}

// Caller 是通过可信边界建立的操作者上下文。字段不导出：调用方只能通过
// LocalBootstrapCaller 构造，不能从请求参数或客户端字段直接伪造。本包不提供
// 系统/普通用户 Caller：首次初始化只允许本地受控操作者。
type Caller struct {
	actor     audit.Actor
	requestID string
}

// LocalBootstrapCaller 构造受限本地初始化操作者（audit.ActorLocalAdmin）。
// operatorID 必须是宿主在可信环境提供的稳定本地操作者标识。
func LocalBootstrapCaller(operatorID string) (Caller, error) {
	actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: operatorID}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 本地操作者标识无效", ErrInvalidRequest)
	}
	return Caller{actor: actor}, nil
}

// WithRequestID 返回带请求编号的调用者副本，用于审计关联。非法编号返回
// ErrInvalidRequest，不会悄悄丢弃。
func (c Caller) WithRequestID(requestID string) (Caller, error) {
	if err := account.ValidateRequestID(requestID); err != nil {
		// 复用账户包同一请求编号规则，避免第二套格式。
		return Caller{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	c.requestID = requestID
	return c, nil
}

// Authorizer 判定可信调用者是否可执行首次初始化操作。生产实现只允许显式配置的
// 本地受控操作者；不提供“默认放行”实现，也不接受请求参数中的自称身份。
type Authorizer interface {
	Authorize(ctx context.Context, caller Caller, action Action) error
}

// LocalBootstrapAuthorizer 只允许显式配置的本地管理员执行首次初始化操作。
// 系统、普通用户与匿名身份一律拒绝；远程 HTTP 接入不得使用它。
type LocalBootstrapAuthorizer struct {
	operators map[string]struct{}
}

// NewLocalBootstrapAuthorizer 构造受限本地授权器。operatorIDs 不能为空，每个
// 标识必须是审计包允许的可见 ASCII 稳定 ID。
func NewLocalBootstrapAuthorizer(operatorIDs []string) (*LocalBootstrapAuthorizer, error) {
	if len(operatorIDs) == 0 {
		return nil, fmt.Errorf("%w: 本地初始化操作者列表不能为空", ErrOptionsInvalid)
	}
	operators := make(map[string]struct{}, len(operatorIDs))
	for _, operatorID := range operatorIDs {
		actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: operatorID}
		if err := actor.Validate(); err != nil {
			return nil, fmt.Errorf("%w: 本地初始化操作者标识无效", ErrOptionsInvalid)
		}
		if _, duplicated := operators[operatorID]; duplicated {
			return nil, fmt.Errorf("%w: 本地初始化操作者标识重复", ErrOptionsInvalid)
		}
		operators[operatorID] = struct{}{}
	}
	return &LocalBootstrapAuthorizer{operators: operators}, nil
}

// Authorize 实现 Authorizer。只有已配置的本地管理员且动作已定义时放行。
func (a *LocalBootstrapAuthorizer) Authorize(_ context.Context, caller Caller, action Action) error {
	if a == nil || !action.Valid() {
		return ErrAccessDenied
	}
	if caller.actor.Type != audit.ActorLocalAdmin {
		return ErrAccessDenied
	}
	if _, allowed := a.operators[caller.actor.ID]; !allowed {
		return ErrAccessDenied
	}
	return nil
}

// InitializeRequest 是首次初始化参数。root 用户名固定为 root，不接受调用方
// 指定，避免绕过保留名规则；这里只允许设置展示资料白名单与凭证有效期。
// 零值资料字段使用账户默认值；零值 TTL 使用 DefaultSetupCredentialTTL。
type InitializeRequest struct {
	// RootNickname 是 root 昵称；空值使用 DefaultRootNickname。
	RootNickname string
	// RootLanguage 是 root 语言标签；空值使用账户默认值 zh-CN。
	RootLanguage string
	// RootTimezone 是 root 时区；空值使用账户默认值 Asia/Shanghai。
	RootTimezone string
	// SetupCredentialTTL 是一次性配置凭证有效期，必须在 Min/Default/Max 范围内。
	SetupCredentialTTL time.Duration
}

// InitializeResult 是首次初始化结果。SetupCredential.Secret 只在本次返回出现
// 一次：调用方必须立即通过本地受控通道交给最终操作者，不得写入日志/审计/普通
// 存储。Root 是刚创建的 root 账户快照，不包含密码（本步不存密码）。
type InitializeResult struct {
	// Root 是新建的 root 账户快照（用户名固定 root，is_root=1 由存储写入）。
	Root account.User
	// State 是初始化后的受限状态（正常为 StatePendingSetup）。
	State State
	// SetupCredential 是一次性本机短期配置凭证。
	SetupCredential credential.IssuedCredential
}

// RedeemSetupCredentialRequest 是兑换一次性配置凭证的参数。Secret 是明文凭证，
// 只用于本次校验，服务不保存、不记录。
type RedeemSetupCredentialRequest struct {
	// CredentialID 是签发时返回的凭证 ID（otc_ 前缀）。
	CredentialID string
	// Secret 是签发时返回的明文令牌。
	Secret string
}

// SetupGrant 是一次性配置凭证兑换成功后的受限配置凭据。
//
// 它只是一次“本机一次性凭证校验通过”的服务端记录返回值，不是会话、不是令牌，
// 不能用于远程管理或调用未来 HTTP 接口；本步不提前签发完整管理员会话。正式
// 密码/强认证配置由后续正式密码服务完成。
type SetupGrant struct {
	// RootUserID 是已存在且处于受限待配置状态的 root 账户 ID。
	RootUserID string
	// RootUsername 固定为 RootUsername。
	RootUsername string
	// CredentialID 是本次消费的一次性配置凭证 ID（不含秘密）。
	CredentialID string
	// VerifiedAt 是凭证消费与服务端状态更新的时间。
	VerifiedAt time.Time
	// State 是兑换后的受限状态（正常为 StateSetupVerified）。
	State State
}

// ReissueSetupCredentialRequest 是重新签发一次性配置凭证的参数。它用于凭证过期、
// 丢失或兑换后尚未完成安全配置的本地可诊断恢复；不会重建 root、不会绕过后续
// 正式密码与强认证要求。
type ReissueSetupCredentialRequest struct {
	// SetupCredentialTTL 同 InitializeRequest.SetupCredentialTTL。
	SetupCredentialTTL time.Duration
}

// ReissueSetupCredentialResult 是重新签发结果；SetupCredential.Secret 同样只
// 返回一次。
type ReissueSetupCredentialResult struct {
	// RootUserID 是受限待配置状态的 root 账户 ID。
	RootUserID string
	// State 为 StatePendingSetup。
	State State
	// SetupCredential 是新的一次性本机短期配置凭证。
	SetupCredential credential.IssuedCredential
}

// Status 是初始化状态诊断快照，不含凭证秘密、摘要或任何密码材料。
type Status struct {
	// State 是当前初始化状态。
	State State
	// RootExists 表示数据库中已存在 root 账户（正常由初始化创建）。
	RootExists bool
	// RootUserID 是 root 稳定 ID；尚未初始化时为空。
	RootUserID string
	// RootUsername 是 root 显示用户名；尚未初始化时为空。
	RootUsername string
	// RootStatus 是 root 账户全局状态；尚未初始化时为空。
	RootStatus account.Status
	// RootSecurityVersion 是 root 会话语义的安全版本（root 保护的一部分）。
	RootSecurityVersion int64
	// StartedBy 是创建初始化记录的本地操作者标识。
	StartedBy string
	// CreatedAt/UpdatedAt 是初始化记录时间。
	CreatedAt time.Time
	UpdatedAt time.Time
	// SetupCredentialID 是最近一次签发的配置凭证 ID；空表示尚未签发。
	SetupCredentialID string
	// SetupCredentialUsable 表示该凭证当前仍可用于兑换（未过期/未消费/未撤销）。
	SetupCredentialUsable bool
	// SetupCredentialExpiresAt 是当前凭证过期时间。
	SetupCredentialExpiresAt time.Time
	// SetupCredentialConsumedAt/RevokedAt 非空表示凭证已消费/已撤销。
	SetupCredentialConsumedAt *time.Time
	SetupCredentialRevokedAt  *time.Time
	// SetupCredentialAttempts/MaxAttempts 是凭证失败尝试计数与上限（诊断用）。
	SetupCredentialAttempts    int
	SetupCredentialMaxAttempts int
	// VerifiedAt 非空表示一次性配置凭证已兑换。
	VerifiedAt *time.Time
	// ReadyAt 非空表示正式密码/强认证已配置（后续步骤）。
	ReadyAt *time.Time
}

// Initialized 报告是否已经创建过 root（包含缺少初始化记录的旧数据）。
func (s Status) Initialized() bool {
	return s.RootExists || s.State == StatePendingSetup ||
		s.State == StateSetupVerified || s.State == StateReady
}

// NeedsSetupCredential 报告当前是否应重新签发一次性配置凭证：仅在 root 已存在、
// 仍处于受限待配置状态且当前凭证不可用时为 true。正常等待兑换或已进入正式配置
// 时为 false。
func (s Status) NeedsSetupCredential() bool {
	if s.State != StatePendingSetup {
		return false
	}
	return s.SetupCredentialID == "" || !s.SetupCredentialUsable
}

// Explanation 返回状态、可选操作与安全边界的中文直白说明，用于本地诊断与恢复
// 入口展示；不包含任何秘密。
func (s Status) Explanation() string {
	switch s.State {
	case StateUninitialized:
		return "本实例尚未初始化。请在服务器本机以受控本地操作者身份执行首次初始化；" +
			"初始化只创建唯一 root 并签发一次性短期配置凭证，不设置默认密码，也不会提前开放管理员会话。"
	case StateExistingRoot:
		return "数据库已存在 root 账户但没有初始化记录（可能来自旧版本或人工数据）。" +
			"本程序不会自动接管、重建或降格该账户；请先由本地维护流程确认数据来源，再决定后续恢复步骤。"
	case StatePendingSetup:
		if s.SetupCredentialUsable {
			return "root 已创建，处于受限待配置状态；当前一次性配置凭证仍有效。" +
				"请通过本机受控通道使用该凭证完成必要安全设置。凭证过期或被消费后，可用本地恢复入口重新签发，不需要也无法重新创建 root。"
		}
		return "root 已创建，处于受限待配置状态；但当前一次性配置凭证已过期、被消费或被撤销。" +
			"请使用本地恢复入口重新签发一次性短期凭证后继续配置；root 身份与资料不受影响。"
	case StateSetupVerified:
		return "一次性配置凭证已兑换，root 仍处于受限待配置状态：只允许必要的安全设置，凭证本身不是会话。" +
			"正式密码与必需强认证由后续正式密码服务完成；若配置过程失败，可重新签发一次性凭证恢复，但不能据此跳过强认证。"
	case StateReady:
		return "正式密码与必需强认证已配置，初始化流程完成；后续管理操作必须走正式认证与授权路径。"
	default:
		return "未知初始化状态，请按服务诊断与运维手册处理。"
	}
}

// SetupCredentialStatus 是一次性配置凭证的安全诊断状态（不含摘要与明文）。它由
// 初始化存储直接查询 one_time_credentials 行得到，不参与凭证校验。
type SetupCredentialStatus struct {
	// Found 表示数据库中仍能找到该凭证行（过期清理后可能已不存在）。
	Found bool
	// ExpiresAt 是过期时间。
	ExpiresAt time.Time
	// ConsumedAt/RevokedAt 非空表示已消费/已撤销。
	ConsumedAt *time.Time
	RevokedAt  *time.Time
	// Attempts/MaxAttempts 是失败尝试计数与上限。
	Attempts    int
	MaxAttempts int
}

// Usable 报告凭证在给定时间是否仍可能被兑换。它只是诊断判断，最终是否可消费
// 仍由凭证服务的原子条件消费决定。
func (c SetupCredentialStatus) Usable(now time.Time) bool {
	if !c.Found || c.ConsumedAt != nil || c.RevokedAt != nil {
		return false
	}
	return c.ExpiresAt.After(now) && c.Attempts < c.MaxAttempts
}

// normalizeSetupCredentialTTL 填默认有效期并校验范围；首次配置必须是短期凭证。
func normalizeSetupCredentialTTL(ttl time.Duration) (time.Duration, error) {
	if ttl == 0 {
		return DefaultSetupCredentialTTL, nil
	}
	if ttl < MinSetupCredentialTTL || ttl > MaxSetupCredentialTTL {
		return 0, fmt.Errorf("%w: 配置凭证有效期必须在 %s 到 %s 之间",
			ErrInvalidRequest, MinSetupCredentialTTL, MaxSetupCredentialTTL)
	}
	return ttl, nil
}

// validateCredentialInput 校验兑换请求的凭证 ID 与明文长度，避免把畸形/超大输入
// 带进凭证查询。凭证内容是否正确由凭证服务统一判断（不在此产生可区分响应）。
func validateCredentialInput(request RedeemSetupCredentialRequest) error {
	id := request.CredentialID
	if len(id) != len(credential.CredentialIDPrefix)+32 || !strings.HasPrefix(id, credential.CredentialIDPrefix) {
		return fmt.Errorf("%w: 配置凭证 ID 格式无效", ErrInvalidRequest)
	}
	for index := len(credential.CredentialIDPrefix); index < len(id); index++ {
		character := id[index]
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return fmt.Errorf("%w: 配置凭证 ID 格式无效", ErrInvalidRequest)
		}
	}
	secret := request.Secret
	if secret == "" || len(secret) > maxCredentialSecretBytes {
		return fmt.Errorf("%w: 配置凭证内容长度无效", ErrInvalidRequest)
	}
	for index := 0; index < len(secret); index++ {
		character := secret[index]
		if character < 0x21 || character > 0x7e {
			return fmt.Errorf("%w: 配置凭证内容只能包含可见 ASCII 字符", ErrInvalidRequest)
		}
	}
	return nil
}
