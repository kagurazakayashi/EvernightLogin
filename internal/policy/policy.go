package policy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// 领域错误哨兵。错误文本不包含秘密或用户内容。
var (
	ErrOptionsInvalid          = errors.New("敏感策略服务选项无效")
	ErrInvalidRequest          = errors.New("敏感策略请求无效")
	ErrInvalidChange           = errors.New("敏感策略配置组合非法")
	ErrAccessDenied            = errors.New("未获准访问或修改敏感策略")
	ErrRootRequired            = errors.New("敏感策略只能由 root 修改")
	ErrReauthRequired          = errors.New("修改敏感策略需要再次验证")
	ErrConfirmationRequired    = errors.New("敏感操作需要显式确认")
	ErrVersionConflict         = errors.New("敏感策略已被其他操作修改")
	ErrOperationUnknown        = errors.New("敏感操作未登记")
	ErrScopeUnknown            = errors.New("敏感策略作用域不存在")
	ErrDefaultUnavailable      = errors.New("该操作没有可恢复的系统默认策略")
	ErrVerificationUnavailable = errors.New("要求的认证强度当前不可满足")
	ErrStoreUnavailable        = errors.New("敏感策略存储暂时不可用")
	ErrAuditUnavailable        = errors.New("关键操作未能可靠记录")
)

// ErrorCode 是敏感策略领域对根包错误码注册表的投影（只复用既有码）。
type ErrorCode string

const (
	CodeReqInvalid       ErrorCode = "REQ_INVALID"
	CodeAccessDenied     ErrorCode = "ACCESS_DENIED"
	CodeReauthRequired   ErrorCode = "REAUTH_REQUIRED"
	CodeMFARequired      ErrorCode = "MFA_REQUIRED"
	CodeConflict         ErrorCode = "CONFLICT"
	CodeDBUnavailable    ErrorCode = "DB_UNAVAILABLE"
	CodeAuditWriteFailed ErrorCode = "AUDIT_WRITE_FAILED"
	CodeInternalError    ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把敏感策略领域错误映射为根包已登记错误码（不新增错误码）。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrInvalidChange),
		errors.Is(err, ErrOperationUnknown), errors.Is(err, ErrScopeUnknown),
		errors.Is(err, ErrDefaultUnavailable):
		return CodeReqInvalid
	case errors.Is(err, ErrAccessDenied), errors.Is(err, ErrRootRequired):
		return CodeAccessDenied
	case errors.Is(err, ErrReauthRequired), errors.Is(err, ErrConfirmationRequired):
		return CodeReauthRequired
	case errors.Is(err, ErrVerificationUnavailable):
		return CodeMFARequired
	case errors.Is(err, ErrVersionConflict):
		return CodeConflict
	case errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	default:
		return CodeInternalError
	}
}

// Caller 是可信调用身份；不能由请求参数自称。
type Caller struct {
	actor     audit.Actor
	requestID string
}

// UserCaller 构造已认证普通用户调用者。
func UserCaller(userID string) (Caller, error) {
	actor := audit.Actor{Type: audit.ActorUser, ID: userID}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 用户标识无效", ErrInvalidRequest)
	}
	return Caller{actor: actor}, nil
}

// SystemCaller 构造系统组件调用者。
func SystemCaller(componentID string) (Caller, error) {
	actor := audit.Actor{Type: audit.ActorSystem, ID: componentID}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 系统组件标识无效", ErrInvalidRequest)
	}
	return Caller{actor: actor}, nil
}

// LocalAdminCaller 构造本地受信管理员调用者（只读诊断；策略修改仍要求真实 root）。
func LocalAdminCaller(operatorID string) (Caller, error) {
	actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: operatorID}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 本地操作者标识无效", ErrInvalidRequest)
	}
	return Caller{actor: actor}, nil
}

// Actor 返回审计身份副本。
func (c Caller) Actor() audit.Actor { return c.actor }

// IsUser 报告是否为普通用户身份。
func (c Caller) IsUser() bool { return c.actor.Type == audit.ActorUser }

// WithRequestID 返回带请求编号的副本。
func (c Caller) WithRequestID(requestID string) (Caller, error) {
	if err := account.ValidateRequestID(requestID); err != nil {
		return Caller{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	c.requestID = requestID
	return c, nil
}

// SourceKind 是有效策略的来源。
type SourceKind string

const (
	// SourceDefault 表示该操作没有覆盖，使用目录默认策略。
	SourceDefault SourceKind = "default"
	// SourceOverride 表示使用系统/应用覆盖行。
	SourceOverride SourceKind = "override"
	// SourceApplication 表示应用自身声明的敏感操作。
	SourceApplication SourceKind = "application"
)

// EffectiveOperation 是一条操作在指定作用域下的有效策略与不可覆盖约束。
type EffectiveOperation struct {
	OperationID string
	Domain      Domain
	Name        string
	Description string
	// Default 是系统目录默认策略；应用声明操作为零值且 HasDefault=false。
	Default Policy
	// HasDefault 报告该操作是否有系统目录默认值（应用声明操作为 false）。
	HasDefault bool
	// Override 是非默认来源的实际策略；nil 表示没有覆盖。
	Override *Policy
	// Effective 是默认与覆盖合并后的实际生效策略。
	Effective Policy
	// Source 是实际策略来源。
	Source SourceKind
	// 以下为不可被策略覆盖的安全约束。
	PermissionKey string
	RootOnly      bool
	AuditRequired bool
	Implemented   bool
}

// Snapshot 是某作用域的有效策略快照。
type Snapshot struct {
	ScopeID    string
	Version    int64
	Operations []EffectiveOperation
}

// Lookup 返回快照中指定操作的条目。
func (s Snapshot) Lookup(operationID string) (EffectiveOperation, bool) {
	for _, operation := range s.Operations {
		if operation.OperationID == operationID {
			return operation, true
		}
	}
	return EffectiveOperation{}, false
}

// FieldDiff 描述一个可配置字段的默认值与当前值差异。
type FieldDiff struct {
	Field   string
	Default string
	Current string
}

// OperationDiff 描述一条操作的差异或应用声明。
type OperationDiff struct {
	OperationID string
	Source      SourceKind
	// Changed 是相对默认值有差异的字段；应用声明操作为空（它本身不是默认值）。
	Changed []FieldDiff
}

// DiffResult 是某作用域相对系统默认策略的差异。
type DiffResult struct {
	ScopeID string
	Version int64
	// Changed 只包含 override 来源且确有差异的操作。
	Changed []OperationDiff
	// Declared 是应用声明的操作（仅应用作用域）。
	Declared []OperationDiff
}

// PolicyChange 是策略修改字段白名单；nil 表示该字段不变。
type PolicyChange struct {
	Sensitive            *bool
	ReauthRequired       *bool
	MaxAuthAgeSeconds    *int64
	RequiredStrength     *Strength
	ConfirmationRequired *bool
	NotificationRequired *bool
}

// HasChanges 报告是否至少修改了一个字段。
func (c PolicyChange) HasChanges() bool {
	return c.Sensitive != nil || c.ReauthRequired != nil || c.MaxAuthAgeSeconds != nil ||
		c.RequiredStrength != nil || c.ConfirmationRequired != nil || c.NotificationRequired != nil
}

// applyTo 把非 nil 字段合并到基础策略上。
func (c PolicyChange) applyTo(base Policy) Policy {
	next := base
	if c.Sensitive != nil {
		next.Sensitive = *c.Sensitive
	}
	if c.ReauthRequired != nil {
		next.ReauthRequired = *c.ReauthRequired
	}
	if c.MaxAuthAgeSeconds != nil {
		next.MaxAuthAgeSeconds = *c.MaxAuthAgeSeconds
	}
	if c.RequiredStrength != nil {
		next.Strength = *c.RequiredStrength
	}
	if c.ConfirmationRequired != nil {
		next.ConfirmationRequired = *c.ConfirmationRequired
	}
	if c.NotificationRequired != nil {
		next.NotificationRequired = *c.NotificationRequired
	}
	return next
}

// Verification 是执行器在判断操作能否继续时提供的近期验证事实。它只描述客观事实
// （验证时间、达到的强度、是否已确认），不包含用户声称的“已通过”标记。
type Verification struct {
	// VerifiedAt 是最近一次身份验证完成时间；零值表示没有可用验证。
	VerifiedAt time.Time
	// Strength 是那次验证实际达到的强度。
	Strength Strength
	// Confirmed 表示用户是否已针对本次操作内容完成确认步骤。
	Confirmed bool
}

// Decision 是策略评估结果。它只包含执行器需要的判定与不可覆盖约束，不返回策略
// 配置以外的秘密信息。
type Decision struct {
	OperationID          string
	Sensitive            bool
	ReauthRequired       bool
	ConfirmationRequired bool
	NotificationRequired bool
	// 不可覆盖约束：即使敏感标记被取消，基础权限/root 限制/审计仍必须执行。
	PermissionKey string
	RootOnly      bool
	AuditRequired bool
	// ReasonCode 是内部诊断原因码（不直接作为公开错误码）。
	ReasonCode string
}

// ReauthVerifier 是策略修改前的再次验证契约（由宿主实现密码/强认证复核）。未注入
// 时任何策略修改都 fail-closed 返回 REAUTH_REQUIRED。
type ReauthVerifier interface {
	VerifyReauth(ctx context.Context, caller Caller, operationID string) error
}

// ReauthVerifierFunc 是 ReauthVerifier 的函数适配器。
type ReauthVerifierFunc func(ctx context.Context, caller Caller, operationID string) error

// VerifyReauth 实现 ReauthVerifier。
func (f ReauthVerifierFunc) VerifyReauth(ctx context.Context, caller Caller, operationID string) error {
	if f == nil {
		return ErrReauthRequired
	}
	return f(ctx, caller, operationID)
}

// Authorizer 判定调用者能否读取/修改指定作用域策略；实现应默认拒绝。未注入时使用
// 默认口径：修改只允许真实 root；读取允许 root 与受信 system/local_admin。
type Authorizer interface {
	AuthorizePolicy(ctx context.Context, caller Caller, scopeID string, write bool) error
}

// AuthorizerFunc 是 Authorizer 的函数适配器。
type AuthorizerFunc func(ctx context.Context, caller Caller, scopeID string, write bool) error

// AuthorizePolicy 实现 Authorizer。
func (f AuthorizerFunc) AuthorizePolicy(ctx context.Context, caller Caller, scopeID string, write bool) error {
	if f == nil {
		return ErrAccessDenied
	}
	return f(ctx, caller, scopeID, write)
}
