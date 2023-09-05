// Package manualrecovery 实现默认关闭、由 root/宿主显式配置的人工账户恢复：申请、
// 独立审批与短期一次性的受控执行，只处理既有验证渠道不可用的普通账户。
//
// 安全不变量（对应步骤 47）：
//   - 默认关闭：Options.Policy.Enabled 为 false 时所有阶段一律拒绝（fail-closed），
//     不提供静默放行；启用时必须由宿主（root 配置）明确给出核验依据、等待期、
//     批准有效期与可信交付渠道。未配置/配置非法时拒绝构造，不采用安全问题、电话
//     口述等弱核验依据（这些值不在允许枚举内）。
//   - 申请绑定目标稳定 ID、操作类型（密码恢复/MFA 恢复分别申请）、核验依据与外部
//     核验记录编号、证据摘要（只存 SHA-256，不存证件/证据明文）、原因、交付渠道、
//     目标安全版本/高权限快照与服务端内容摘要；发起者不得自批。
//   - 审批必须是独立审批人（不得为发起者或目标本人），验证审批人**当前资格**
//     （功能权限由注入的 StaffAuthorizer 按内部 authz 判定；近期强认证由注入的
//     reauth.OperationRunner 判定），内容摘要/操作类型与批准不一致、等待期未到、
//     有效期过期、审批人权限被撤销或目标变为高权限/root 都不允许执行；这些变化
//     会使既有批准失效（fail-closed）。
//   - 执行短期一次性：条件更新把请求 approved→executing（双执行竞争只有一个成功）
//     并创建唯一执行记录；执行前再次校验审批人资格与目标状态。成功后在审计事务内
//     完成请求/批准/执行状态并写成功审计，随后尽力通知既有渠道；失败整体不宣称
//     成功（执行器故障回滚其自身副作用并记录失败审计）。
//   - root 与实际高权限账户不走普通流程（TargetGuard 按真实权限识别，拒绝处理；
//     root 恢复由步骤 48 的受控本地 CLI 负责）。
//   - 每个阶段（申请/批准/拒绝/执行/失败/拒绝）都以真实操作者写安全审计，事务前
//     拒绝也写失败审计；审计不可用时关键变更整体回滚。审计与视图不包含证据明文、
//     证件材料、密码、MFA 秘密、恢复代码或凭证/token。
package manualrecovery

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// 领域错误哨兵。错误文本不包含目标存在性细节、证据明文或凭证。
var (
	ErrOptionsInvalid      = errors.New("人工恢复服务选项无效")
	ErrDisabled            = errors.New("人工恢复流程未启用")
	ErrInvalidRequest      = errors.New("人工恢复请求无效")
	ErrAccessDenied        = errors.New("未获准执行该人工恢复操作")
	ErrTargetProtected     = errors.New("该账户不能走普通人工恢复流程")
	ErrTargetUnavailable   = errors.New("目标账户当前不可用")
	ErrSelfApproval        = errors.New("不得审批本人发起或本人账户的恢复申请")
	ErrRequestNotFound     = errors.New("人工恢复申请不存在")
	ErrRequestClosed       = errors.New("人工恢复申请已结束")
	ErrContentChanged      = errors.New("人工恢复申请内容已变化，既有批准失效")
	ErrApprovalNotYetValid = errors.New("人工恢复批准等待期未满")
	ErrApprovalExpired     = errors.New("人工恢复批准已过期")
	ErrApproverUnqualified = errors.New("审批人当前不具备审批资格")
	ErrExecutionConflict   = errors.New("人工恢复执行已被其他请求占用或已执行")
	ErrExecutionFailed     = errors.New("人工恢复执行失败")
	ErrReauthRequired      = errors.New("需要完成近期强认证")
	ErrMFARequired         = errors.New("需要完成两步验证")
	ErrAuthzUnavailable    = errors.New("暂时无法判定人工恢复权限")
	ErrStoreUnavailable    = errors.New("人工恢复存储暂时不可用")
	ErrAuditUnavailable    = errors.New("关键操作未能可靠记录")
	ErrNotificationFailed  = errors.New("恢复完成通知发送失败")
)

// ErrorCode 是人工恢复领域对根包错误码注册表的投影（只复用既有 46 码）。
type ErrorCode string

const (
	CodeReqInvalid             ErrorCode = "REQ_INVALID"
	CodeAccessDenied           ErrorCode = "ACCESS_DENIED"
	CodeReauthRequired         ErrorCode = "REAUTH_REQUIRED"
	CodeMFARequired            ErrorCode = "MFA_REQUIRED"
	CodeSupportTargetProtected ErrorCode = "SUPPORT_TARGET_PROTECTED"
	CodeUserDisabled           ErrorCode = "USER_DISABLED"
	CodeConflict               ErrorCode = "CONFLICT"
	CodeChallengeInvalid       ErrorCode = "CHALLENGE_INVALID"
	CodeAuthzUnavailable       ErrorCode = "AUTHZ_UNAVAILABLE"
	CodeDBUnavailable          ErrorCode = "DB_UNAVAILABLE"
	CodeAuditWriteFailed       ErrorCode = "AUDIT_WRITE_FAILED"
	CodeMailDeliveryFailed     ErrorCode = "MAIL_DELIVERY_FAILED"
	CodeInternalError          ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把人工恢复领域错误映射为已登记错误码；未知错误统一内部错误。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrDisabled), errors.Is(err, ErrInvalidRequest):
		return CodeReqInvalid
	case errors.Is(err, ErrTargetProtected):
		return CodeSupportTargetProtected
	case errors.Is(err, ErrTargetUnavailable):
		return CodeUserDisabled
	case errors.Is(err, ErrAccessDenied), errors.Is(err, ErrSelfApproval),
		errors.Is(err, ErrApproverUnqualified):
		return CodeAccessDenied
	case errors.Is(err, ErrReauthRequired):
		return CodeReauthRequired
	case errors.Is(err, ErrMFARequired):
		return CodeMFARequired
	case errors.Is(err, ErrContentChanged), errors.Is(err, ErrExecutionConflict),
		errors.Is(err, ErrApprovalNotYetValid):
		return CodeConflict
	case errors.Is(err, ErrRequestNotFound), errors.Is(err, ErrRequestClosed),
		errors.Is(err, ErrApprovalExpired):
		return CodeChallengeInvalid
	case errors.Is(err, ErrAuthzUnavailable):
		return CodeAuthzUnavailable
	case errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	case errors.Is(err, ErrNotificationFailed):
		return CodeMailDeliveryFailed
	default:
		return CodeInternalError
	}
}

// Caller 是可信调用身份；不能由请求参数自称。
type Caller struct {
	actor audit.Actor
}

// UserCaller 构造已认证普通用户调用者（人工恢复的操作者必须是实名工作人员账户）。
func UserCaller(userID string) (Caller, error) {
	actor := audit.Actor{Type: audit.ActorUser, ID: userID}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 用户标识无效", ErrInvalidRequest)
	}
	return Caller{actor: actor}, nil
}

// Actor 返回审计身份副本。
func (c Caller) Actor() audit.Actor { return c.actor }

// IsUser 报告是否为普通用户身份。
func (c Caller) IsUser() bool { return c.actor.Type == audit.ActorUser }

// OperationType 是被恢复的操作类型；密码恢复与 MFA 恢复分别申请、分别授权，不能
// 用一次批准完成任意重置。
type OperationType string

const (
	// OperationPasswordReset 是密码恢复（重置/重新建立唯一登录密码）。
	OperationPasswordReset OperationType = "password_reset"
	// OperationMFAReset 是两步验证恢复（撤销旧 MFA 因素并要求重新绑定）。
	OperationMFAReset OperationType = "mfa_reset"
)

// Valid 报告操作类型是否已定义。
func (o OperationType) Valid() bool {
	return o == OperationPasswordReset || o == OperationMFAReset
}

// VerificationBasis 是允许的人工核验依据。只允许可留痕、可复核的强依据；安全问题、
// 电话口述等弱依据不在枚举内，配置或请求中出现即拒绝。
type VerificationBasis string

const (
	// BasisInPersonIdentityDocument 是线下核验政府签发身份证件原件。
	BasisInPersonIdentityDocument VerificationBasis = "in_person_identity_document"
	// BasisNotarizedDeclaration 是经公证/书面声明等可复核的核验记录。
	BasisNotarizedDeclaration VerificationBasis = "notarized_declaration"
)

// Valid 报告核验依据是否被允许。
func (b VerificationBasis) Valid() bool {
	return b == BasisInPersonIdentityDocument || b == BasisNotarizedDeclaration
}

// DeliveryChannel 是可信交付方式。第一版只允许向目标既有已验证邮箱交付一次性
// 恢复入口；不提供短信/电话口述/客服代读等弱交付。
type DeliveryChannel string

// DeliveryVerifiedEmail 表示通过目标既有已验证邮箱交付。
const DeliveryVerifiedEmail DeliveryChannel = "verified_email"

// Valid 报告交付方式是否被支持。
func (d DeliveryChannel) Valid() bool { return d == DeliveryVerifiedEmail }

// Status 是申请状态。
type Status string

const (
	StatusPendingApproval Status = "pending_approval"
	StatusApproved        Status = "approved"
	StatusExecuting       Status = "executing"
	StatusCompleted       Status = "completed"
	StatusRejected        Status = "rejected"
	StatusCancelled       Status = "cancelled"
	StatusFailed          Status = "failed"
	StatusExpired         Status = "expired"
)

// Valid 报告状态是否已定义。
func (s Status) Valid() bool {
	switch s {
	case StatusPendingApproval, StatusApproved, StatusExecuting, StatusCompleted,
		StatusRejected, StatusCancelled, StatusFailed, StatusExpired:
		return true
	default:
		return false
	}
}

// Terminal 报告是否为终态。
func (s Status) Terminal() bool {
	switch s {
	case StatusCompleted, StatusRejected, StatusCancelled, StatusFailed, StatusExpired:
		return true
	default:
		return false
	}
}

// ApprovalStatus 是批准状态。
type ApprovalStatus string

const (
	ApprovalActive      ApprovalStatus = "active"
	ApprovalConsumed    ApprovalStatus = "consumed"
	ApprovalInvalidated ApprovalStatus = "invalidated"
	ApprovalExpired     ApprovalStatus = "expired"
)

// Policy 是 root/宿主显式配置的人工恢复制度。默认关闭。
type Policy struct {
	// Enabled 表示是否允许普通人工恢复流程；默认 false（所有阶段拒绝）。
	Enabled bool
	// VerificationBases 是允许的核验依据集合；启用时不能为空。
	VerificationBases []VerificationBasis
	// DeliveryChannels 是允许的可信交付方式集合；启用时不能为空。
	DeliveryChannels []DeliveryChannel
	// WaitPeriod 是批准后的强制等待期（执行不得早于批准 + 等待期）。
	WaitPeriod time.Duration
	// ApprovalTTL 是批准的有效期（批准 + ApprovalTTL 后失效）；必须大于等待期。
	ApprovalTTL time.Duration
	// RequestTTL 是申请自身的有效期（过期后不能审批/执行）。
	RequestTTL time.Duration
	// RequireIndependentApproval 表示必须由独立审批人批准（不得为发起者/目标本人）；
	// 启用人工恢复时必须显式设为 true，服务始终强制独立性，不提供关闭开关。
	RequireIndependentApproval bool
}

// 时间参数默认值与边界。
const (
	DefaultWaitPeriod  = 24 * time.Hour
	MinWaitPeriod      = time.Hour
	MaxWaitPeriod      = 7 * 24 * time.Hour
	DefaultApprovalTTL = 48 * time.Hour
	MinApprovalTTL     = time.Hour
	MaxApprovalTTL     = 7 * 24 * time.Hour
	DefaultRequestTTL  = 7 * 24 * time.Hour
	MinRequestTTL      = time.Hour
	MaxRequestTTL      = 30 * 24 * time.Hour
)

// DefaultPolicy 返回默认策略：关闭，不启用任何人工恢复路径。
func DefaultPolicy() Policy { return Policy{} }

// Validate 校验策略。关闭状态允许空配置；启用状态必须给出完整、有界且不与弱核验
// 依据混淆的制度参数。
func (p Policy) Validate() error {
	if !p.Enabled {
		return nil
	}
	if len(p.VerificationBases) == 0 {
		return fmt.Errorf("%w: 启用人工恢复必须显式配置核验依据", ErrOptionsInvalid)
	}
	seenBasis := make(map[VerificationBasis]struct{}, len(p.VerificationBases))
	for _, basis := range p.VerificationBases {
		if !basis.Valid() {
			return fmt.Errorf("%w: 不允许的核验依据 %q（安全问题/电话口述等弱依据不得使用）",
				ErrOptionsInvalid, basis)
		}
		if _, duplicate := seenBasis[basis]; duplicate {
			return fmt.Errorf("%w: 核验依据重复", ErrOptionsInvalid)
		}
		seenBasis[basis] = struct{}{}
	}
	if len(p.DeliveryChannels) == 0 {
		return fmt.Errorf("%w: 启用人工恢复必须显式配置可信交付方式", ErrOptionsInvalid)
	}
	for _, delivery := range p.DeliveryChannels {
		if !delivery.Valid() {
			return fmt.Errorf("%w: 不支持的可信交付方式 %q", ErrOptionsInvalid, delivery)
		}
	}
	if p.WaitPeriod < MinWaitPeriod || p.WaitPeriod > MaxWaitPeriod {
		return fmt.Errorf("%w: 等待期必须在 %s～%s 之间", ErrOptionsInvalid, MinWaitPeriod, MaxWaitPeriod)
	}
	if p.ApprovalTTL < MinApprovalTTL || p.ApprovalTTL > MaxApprovalTTL {
		return fmt.Errorf("%w: 批准有效期必须在 %s～%s 之间", ErrOptionsInvalid, MinApprovalTTL, MaxApprovalTTL)
	}
	if p.ApprovalTTL <= p.WaitPeriod {
		return fmt.Errorf("%w: 批准有效期必须大于等待期，否则执行窗口为空", ErrOptionsInvalid)
	}
	if p.RequestTTL < MinRequestTTL || p.RequestTTL > MaxRequestTTL {
		return fmt.Errorf("%w: 申请有效期必须在 %s～%s 之间", ErrOptionsInvalid, MinRequestTTL, MaxRequestTTL)
	}
	// 申请有效期必须覆盖“批准等待期 + 批准有效期”：否则策略可能允许批准在申请
	// 过期后仍然有效，执行路径必须以更早的申请过期时间为准（本服务仍双重校验）。
	if p.RequestTTL < p.WaitPeriod+p.ApprovalTTL {
		return fmt.Errorf("%w: 申请有效期必须不小于等待期+批准有效期，避免批准超出申请生命周期",
			ErrOptionsInvalid)
	}
	if !p.RequireIndependentApproval {
		return fmt.Errorf("%w: 启用人工恢复必须显式要求独立审批人", ErrOptionsInvalid)
	}
	return nil
}

// resolve 返回带默认值的策略副本。
func (p Policy) resolve() Policy {
	if p.Enabled {
		if p.WaitPeriod == 0 {
			p.WaitPeriod = DefaultWaitPeriod
		}
		if p.ApprovalTTL == 0 {
			p.ApprovalTTL = DefaultApprovalTTL
		}
		if p.RequestTTL == 0 {
			p.RequestTTL = DefaultRequestTTL
		}
	}
	return p
}

// basisAllowed / deliveryAllowed 校验请求是否落在 root 配置范围内。
func (p Policy) basisAllowed(basis VerificationBasis) bool {
	for _, allowed := range p.VerificationBases {
		if allowed == basis {
			return true
		}
	}
	return false
}

func (p Policy) deliveryAllowed(delivery DeliveryChannel) bool {
	for _, allowed := range p.DeliveryChannels {
		if allowed == delivery {
			return true
		}
	}
	return false
}

// 敏感操作目录操作标识；新增/变更时同步 internal/policy 目录。
const (
	OperationRequest = "support.recovery.request"
	OperationApprove = "support.recovery.approve"
	OperationExecute = "support.recovery.execute"
)

// strictReauthOperations 是允许强认证执行的操作集合（用于装配自检）。
var _ = []string{OperationRequest, OperationApprove, OperationExecute}

// scopeSystem 是敏感操作策略的系统作用域 ID。
const scopeSystem = "system"

// 功能权限键；与 internal/preset 权限目录保持一致。
const (
	PermissionRequest    = "recovery.request"
	PermissionApprove    = "recovery.approve"
	PermissionMFAApprove = "recovery.mfa.approve"
)

// ApprovalPermission 返回操作类型对应的审批功能权限键：密码恢复与 MFA 恢复分别授权。
func (o OperationType) ApprovalPermission() string {
	if o == OperationMFAReset {
		return PermissionMFAApprove
	}
	return PermissionApprove
}

// 领域内稳定 ID 前缀与长度。
const (
	requestIDPrefix   = "mrr_"
	approvalIDPrefix  = "mra_"
	executionIDPrefix = "mre_"
	idRandomBytes     = 16
	maxReferenceBytes = 128
	maxReasonBytes    = 500
	maxSummaryBytes   = 1024
	maxTraceIDBytes   = 64
)

// RequestRecord 是人工恢复申请的持久化快照（不含证据明文）。
type RequestRecord struct {
	ID                    string
	TargetUserID          string
	InitiatorUserID       string
	Operation             OperationType
	Status                Status
	VerificationBasis     VerificationBasis
	VerificationReference string
	EvidenceDigest        []byte
	Reason                string
	Delivery              DeliveryChannel
	DeliveryFingerprint   string
	TargetSecurityVersion int64
	TargetHighPrivilege   bool
	ContentDigest         []byte
	SupportCaseID         string
	ExpiresAt             time.Time
	ClosedReason          string
	RowVersion            int64
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// ApprovalRecord 是批准的持久化快照（绑定请求内容摘要与操作类型）。
type ApprovalRecord struct {
	ID                string
	RequestID         string
	ApproverUserID    string
	Operation         OperationType
	ContentDigest     []byte
	Status            ApprovalStatus
	ApprovedAt        time.Time
	NotBefore         time.Time
	ExpiresAt         time.Time
	FinishedAt        time.Time
	InvalidatedReason string
	RowVersion        int64
}

// ExecutionRecord 是一次执行的持久化快照（不含凭证/秘密）。
type ExecutionRecord struct {
	ID                    string
	RequestID             string
	ApprovalID            string
	ExecutorUserID        string
	Operation             OperationType
	Status                string
	SessionsRevoked       int
	FactorsReset          bool
	ResetCredentialIssued bool
	NotificationState     string
	ErrorCode             string
	StartedAt             time.Time
	FinishedAt            time.Time
}

// ExecutionCommand 是交给宿主执行器的受控执行命令；执行器必须由可信装配层实现，
// 只在独立审批通过且服务端完成状态预检后调用，不得由客户端直接触发。
type ExecutionCommand struct {
	RequestID      string
	ExecutionID    string
	TargetUserID   string
	Operation      OperationType
	Delivery       DeliveryChannel
	RequestTraceID string
}

// ExecutionOutcome 是执行器的成功结果摘要（不含密码/验证码/秘密）。
type ExecutionOutcome struct {
	Summary               string
	SessionsRevoked       int
	FactorsReset          bool
	ResetCredentialIssued bool
}

// Executor 是宿主提供的受控恢复执行器。
//
// 契约：Execute 必须完成该操作类型的实际恢复（密码恢复：作废旧密码并交付一次性
// 重置入口；MFA 恢复：撤销旧 MFA 因素/会话并要求重新绑定），幂等键为 ExecutionID，
// 仅在全部步骤成功后才返回成功；返回错误时必须自行补偿已产生的副作用（或保持
// 可重试且不留下部分成功状态）。Compensate 用于服务端在最终审计提交失败时尽力
// 撤销本次执行。执行器不得返回密码、验证码、秘密或 token。
type Executor interface {
	Execute(ctx context.Context, command ExecutionCommand) (ExecutionOutcome, error)
	Compensate(ctx context.Context, command ExecutionCommand) error
}

// NotificationKind 是人工恢复通知类别。
type NotificationKind string

const (
	// NotificationCompleted 表示人工恢复已执行完成。
	NotificationCompleted NotificationKind = "manual_recovery_completed"
	// NotificationFailed 表示执行失败（通知既有渠道以便用户求助）。
	NotificationFailed NotificationKind = "manual_recovery_failed"
)

// Notification 是发给既有渠道的安全通知（不含秘密）。
type Notification struct {
	Kind         NotificationKind
	RequestID    string
	TargetUserID string
	Operation    OperationType
	OccurredAt   time.Time
}

// Notifier 发送人工恢复结果通知（只发既有渠道，不得回退到不可信新地址）。
type Notifier interface {
	Notify(ctx context.Context, notification Notification) error
}

// StaffAuthorizer 按内部 authz 判定工作人员的功能权限与数据范围；实现必须是
// fail-closed 的（依赖故障/范围无法证明时返回错误或拒绝）。
type StaffAuthorizer interface {
	// AuthorizeRequest 校验发起者在目标范围内可否为该账户发起该操作类型的申请。
	AuthorizeRequest(ctx context.Context, staffUserID, targetUserID string, operation OperationType) error
	// AuthorizeApproval 校验审批人当前是否具备该操作类型的审批权限（密码恢复与
	// MFA 恢复使用不同权限键），并可用 targetUserID/scopeID 限制“只能审批自己
	// 数据范围内的目标”；实现必须 fail-closed。
	AuthorizeApproval(ctx context.Context, approverUserID, targetUserID, scopeID string, operation OperationType) error
	// AuthorizeExecution 校验执行人当前是否获准执行该操作类型的恢复。
	AuthorizeExecution(ctx context.Context, executorUserID, targetUserID string, operation OperationType) error
}

// TargetState 是目标账户的人工恢复相关状态；高权限标记必须由实现按**实际权限**
// （authz 有效权限）与 root 身份计算，不能只看角色名。
type TargetState struct {
	UserID          string
	Active          bool
	IsRoot          bool
	HighPrivilege   bool
	SecurityVersion int64
	// DeliveryFingerprint 是目标账户当前**可信交付地址**（第一版即此前已验证邮箱）的
	// 不可逆指纹/稳定引用：由实现用密钥或 SHA-256 计算，不能是邮箱明文。恢复申请
	// 与独立批准绑定该指纹，执行前重新读取并比对；地址变化（换绑邮箱）即批准失效。
	DeliveryFingerprint string
}

// TargetGuard 读取目标账户状态（含 root/高权限识别），用于申请/审批/执行各阶段的
// 重新校验；实现必须是只读、实时的可信数据来源。
type TargetGuard interface {
	LoadTarget(ctx context.Context, userID string) (TargetState, error)
}

// AuditRecorder 是安全审计契约；生产实现为 *audit.Recorder。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// 审计动作。
const (
	ActionRequested        = "manual_recovery.requested"
	ActionApproved         = "manual_recovery.approved"
	ActionRejected         = "manual_recovery.rejected"
	ActionCancelled        = "manual_recovery.cancelled"
	ActionExecutionStarted = "manual_recovery.execution_started"
	ActionExecution        = "manual_recovery.executed"
	ActionExecutionFail    = "manual_recovery.execution_failed"
	ActionDenied           = "manual_recovery.denied"
)

// ExecutionResult 是执行结果。
type ExecutionResult struct {
	RequestID        string
	ExecutionID      string
	Status           Status
	Operation        OperationType
	SessionsRevoked  int
	FactorsReset     bool
	CredentialIssued bool
	// NotificationSent 仅表示直接发送路径已确认送达；队列路径（queued）为 false。
	NotificationSent bool
	// NotificationState 是真实通知状态：sent/queued/failed/not_configured 等；
	// queued 表示已交给可靠投递队列，不代表已送达（步骤 197）。
	NotificationState string
}

// newDomainID 生成领域内稳定 ID（前缀 + 128 位安全随机十六进制）。
func newDomainID(random io.Reader, prefix string) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	buffer := make([]byte, idRandomBytes)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", fmt.Errorf("%w: 安全随机源不可用", ErrOptionsInvalid)
	}
	return prefix + hex.EncodeToString(buffer), nil
}

// validDomainID 校验领域内稳定 ID 格式。
func validDomainID(id, prefix string) bool {
	if len(id) != len(prefix)+2*idRandomBytes || !strings.HasPrefix(id, prefix) {
		return false
	}
	for _, r := range id[len(prefix):] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// validateRequestID 校验客户端请求编号（与既有 account.ValidateRequestID 同语义）。
func validateRequestID(requestID string) error {
	return account.ValidateRequestID(requestID)
}

// digestString 计算 SHA-256 十六进制摘要。
func digestString(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}

// digestHex 返回摘要十六进制表示。
func digestHex(digest []byte) string { return hex.EncodeToString(digest) }

// contentDigest 计算申请内容摘要：绑定目标、操作类型、核验依据/记录编号、证据摘要、
// 原因摘要、交付渠道、目标安全版本/高权限快照与支持工单关联。批准与执行都必须与
// 同一摘要一致；任何内容变化都会使既有批准失效。
func contentDigest(record RequestRecord) []byte {
	parts := []string{
		"manual-recovery-v1",
		record.TargetUserID,
		string(record.Operation),
		string(record.VerificationBasis),
		record.VerificationReference,
		digestHex(record.EvidenceDigest),
		digestHex(digestString(record.Reason)),
		string(record.Delivery),
		record.DeliveryFingerprint,
		fmt.Sprint(record.TargetSecurityVersion),
		fmt.Sprint(record.TargetHighPrivilege),
		record.SupportCaseID,
	}
	return digestString(strings.Join(parts, "\x00"))
}

// validText 校验不可信文本：合法 UTF-8、无控制字符、长度有界（字节）。
func validText(value string, maxBytes int, required bool) bool {
	if len(value) > maxBytes {
		return false
	}
	if required && strings.TrimSpace(value) == "" {
		return false
	}
	if !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
		if unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

// validReference 校验外部核验记录编号：可见 ASCII token（不保存证件材料本体）。
func validReference(value string) bool {
	if value == "" || len(value) > maxReferenceBytes {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' || r == ':' {
			continue
		}
		return false
	}
	return true
}
