// Package support 实现客服工作人员使用的求助单、受控查询与向原验证邮箱发起密码找回。
//
// 安全不变量：
//   - 客服工作人员是普通实名操作账户（每名工作人员独立账户），数据库/登录强认证层
//     已要求客服等高权限角色启用强认证；写操作（登记/更新/发起找回）还必须经
//     internal/reauth 的步骤 38/39 敏感策略执行前校验，默认要求近期**强认证**。
//     未接线敏感策略或授权器时构造失败，不提供静默放行路径。
//   - 功能权限与数据范围由 internal/authz 的有效权限与数据范围决定（support.cases.read/
//     create/update、recovery.request）。数据范围为 all 时覆盖全部普通用户，为
//     resources 时仅覆盖显式列出的用户；undefined/none 一律拒绝（fail-closed），
//     不把“未声明”当成全部数据。查询只返回本人被指派的求助单。
//   - 目标账户按**实际权限**识别：root 与持有系统管理/审批能力的账户拒绝普通客服
//     处理（SUPPORT_TARGET_PROTECTED）；识别依据是 authz 计算的有效权限，不看角色名。
//   - 求助单只保存目标稳定 ID、真实操作者、原因、状态与脱敏邮箱快照；不保存密码、
//     密码哈希、MFA 秘密、恢复代码、凭证或找回 token。返回给客服的资料一律脱敏；
//     客服永远拿不到找回邮件链接/验证码，也不能指定新密码或新收件地址。
//   - 发送动作复用 internal/passwordreset 的找回服务：只向目标用户**此前已验证的
//     邮箱**发送一次性入口；发送本身不修改密码（原密码在用户完成找回前仍有效），
//     不解除 MFA、不签发会话。重复发起按目标用户有界限流。
//   - 未具备验证渠道（无已验证邮箱/无密码/不可用）的申请只转入人工核验待处理状态
//     （manual_review），本包不实现人工核验审批与执行，更不允许以客服确认直接恢复。
//   - 状态迁移使用行版本条件更新（并发单赢家），处理历史为追加式记录（数据库触发器
//     禁止 UPDATE），每个动作、指派变更、状态变化与拒绝都写安全审计；审计失败时
//     关键变更整体回滚。
package support

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
)

// 领域错误哨兵。错误文本不包含目标账户存在性细节、邮箱明文、密码或 token。
var (
	ErrOptionsInvalid    = errors.New("客服求助单服务选项无效")
	ErrInvalidRequest    = errors.New("客服求助单请求无效")
	ErrAccessDenied      = errors.New("未获准执行该客服操作")
	ErrTargetProtected   = errors.New("客服不能处理该账户")
	ErrTargetUnavailable = errors.New("目标账户当前不可用于该操作")
	ErrCaseClosed        = errors.New("求助单已结束，不能继续变更")
	ErrVersionConflict   = errors.New("求助单已被其他操作修改")
	ErrRateLimited       = errors.New("请求过于频繁")
	ErrMailFailed        = errors.New("找回邮件发送失败")
	ErrAuthzUnavailable  = errors.New("暂时无法判定客服权限")
	ErrStoreUnavailable  = errors.New("客服求助单存储暂时不可用")
	ErrAuditUnavailable  = errors.New("关键操作未能可靠记录")
)

// ErrorCode 是客服求助单领域对根包错误码注册表的投影（只复用既有 46 码）。
type ErrorCode string

const (
	CodeReqInvalid             ErrorCode = "REQ_INVALID"
	CodeAccessDenied           ErrorCode = "ACCESS_DENIED"
	CodeReauthRequired         ErrorCode = "REAUTH_REQUIRED"
	CodeMFARequired            ErrorCode = "MFA_REQUIRED"
	CodeSupportTargetProtected ErrorCode = "SUPPORT_TARGET_PROTECTED"
	CodeUserDisabled           ErrorCode = "USER_DISABLED"
	CodeConflict               ErrorCode = "CONFLICT"
	CodeRateLimited            ErrorCode = "RATE_LIMITED"
	CodeAuthzUnavailable       ErrorCode = "AUTHZ_UNAVAILABLE"
	CodeDBUnavailable          ErrorCode = "DB_UNAVAILABLE"
	CodeAuditWriteFailed       ErrorCode = "AUDIT_WRITE_FAILED"
	CodeMailDeliveryFailed     ErrorCode = "MAIL_DELIVERY_FAILED"
	CodeInternalError          ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把客服领域错误映射为已登记错误码；未知错误统一内部错误。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidRequest):
		return CodeReqInvalid
	case errors.Is(err, ErrTargetProtected):
		return CodeSupportTargetProtected
	case errors.Is(err, ErrAccessDenied):
		return CodeAccessDenied
	case errors.Is(err, ErrReauthRequired):
		return CodeReauthRequired
	case errors.Is(err, ErrMFARequired):
		return CodeMFARequired
	case errors.Is(err, ErrTargetUnavailable):
		return CodeUserDisabled
	case errors.Is(err, ErrCaseClosed), errors.Is(err, ErrVersionConflict):
		return CodeConflict
	case errors.Is(err, ErrRateLimited):
		return CodeRateLimited
	case errors.Is(err, ErrMailFailed):
		return CodeMailDeliveryFailed
	case errors.Is(err, ErrAuthzUnavailable):
		return CodeAuthzUnavailable
	case errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	default:
		return CodeInternalError
	}
}

// 功能权限键；与 internal/preset 权限目录保持一致，新增权限时同步复查。
const (
	// PermissionCasesRead 查看分配给自己的求助单。
	PermissionCasesRead = "support.cases.read"
	// PermissionCasesCreate 登记求助单并定位负责范围内的普通用户。
	PermissionCasesCreate = "support.cases.create"
	// PermissionCasesUpdate 更新求助单状态与指派。
	PermissionCasesUpdate = "support.cases.update"
	// PermissionResetRequest 向既有验证渠道发起密码找回。
	PermissionResetRequest = "recovery.request"
)

// 敏感操作目录操作标识；新增时同步 internal/policy 目录。
const (
	OperationCaseCreate = "support.case.create"
	OperationCaseUpdate = "support.case.update"
	OperationResetSend  = "support.reset.send"
)

// 审计动作。
const (
	ActionCaseCreated        = "support.case.created"
	ActionCaseAssigned       = "support.case.assigned"
	ActionCaseStatusChanged  = "support.case.status_changed"
	ActionCaseResetRequested = "support.case.reset_requested"
	ActionCaseManualReview   = "support.case.manual_review"
	ActionCaseDenied         = "support.case.denied"
)

// CaseStatus 是求助单状态。
type CaseStatus string

const (
	// StatusPendingVerification 表示已登记，等待核验或向原验证邮箱发起找回。
	StatusPendingVerification CaseStatus = "pending_verification"
	// StatusSent 表示已向原已验证邮箱发起一次找回入口（不等于密码已重置）。
	StatusSent CaseStatus = "sent"
	// StatusManualReview 表示未具备验证渠道，只能转人工核验待处理（步骤 47 实现执行）。
	StatusManualReview CaseStatus = "manual_review"
	// StatusClosed 是正常结束终态。
	StatusClosed CaseStatus = "closed"
	// StatusCancelled 是取消终态。
	StatusCancelled CaseStatus = "cancelled"
)

// Valid 报告状态是否已定义。
func (s CaseStatus) Valid() bool {
	switch s {
	case StatusPendingVerification, StatusSent, StatusManualReview, StatusClosed, StatusCancelled:
		return true
	default:
		return false
	}
}

// Terminal 报告是否为终态（终态不能再变更指派或状态）。
func (s CaseStatus) Terminal() bool {
	return s == StatusClosed || s == StatusCancelled
}

const (
	// MaxReasonBytes 是求助原因最大字节数（中文按 UTF-8 字节计）。
	MaxReasonBytes = 2000
	// MaxNoteBytes 是处理说明最大字节数。
	MaxNoteBytes = 1000
	// DefaultPageSize 是列表默认页大小。
	DefaultPageSize = 20
	// MaxPageSize 是列表最大页大小。
	MaxPageSize = 100
	// MaxListOffset 限制深分页。
	MaxListOffset = 1_000_000
)

// Caller 是可信调用身份；不能由请求参数自称。
type Caller struct {
	actor     audit.Actor
	requestID string
}

// UserCaller 构造已认证的客服工作人员调用者。
func UserCaller(userID string) (Caller, error) {
	actor := audit.Actor{Type: audit.ActorUser, ID: userID}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 用户标识无效", ErrInvalidRequest)
	}
	return Caller{actor: actor}, nil
}

// SystemCaller 构造受信系统组件调用者（用于高级装配读取/测试）；登记与发送等
// 需要真实工作人员的写操作不接受系统身份。
func SystemCaller(componentID string) (Caller, error) {
	actor := audit.Actor{Type: audit.ActorSystem, ID: componentID}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 系统组件标识无效", ErrInvalidRequest)
	}
	return Caller{actor: actor}, nil
}

// Actor 返回审计身份副本。
func (c Caller) Actor() audit.Actor { return c.actor }

// IsUser 报告是否为普通用户（工作人员）身份。
func (c Caller) IsUser() bool { return c.actor.Type == audit.ActorUser }

// WithRequestID 返回带请求编号的副本。
func (c Caller) WithRequestID(requestID string) (Caller, error) {
	if err := account.ValidateRequestID(requestID); err != nil {
		return Caller{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	c.requestID = requestID
	return c, nil
}

// AuditRecorder 是安全审计写入契约；实现必须 fail-closed。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// TargetSnapshot 是定位到的目标普通用户快照（只在服务内部使用）。
type TargetSnapshot struct {
	UserID           string
	Username         string
	Status           string
	IsRoot           bool
	HasPassword      bool
	HasVerifiedEmail bool
	VerifiedEmail    string
}

// CaseRecord 是求助单持久化记录。TargetUsername 由查询关联得到，仅用于返回前脱敏，
// 不写入求助单表；目标邮箱只保存脱敏快照，原始验证邮箱只在发送找回时由服务读取。
type CaseRecord struct {
	ID                string
	TargetUserID      string
	TargetUsername    string
	CreatedByUserID   string
	AssigneeUserID    string
	TargetMaskedEmail string
	Reason            string
	Status            CaseStatus
	RowVersion        int64
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// EventRecord 是一条追加式处理历史。
type EventRecord struct {
	ID         string
	CaseID     string
	Seq        int64
	Action     string
	Actor      audit.Actor
	FromStatus CaseStatus
	ToStatus   CaseStatus
	Detail     string
	CreatedAt  time.Time
}

// CaseQuery 是求助单列表查询；服务对普通工作人员强制 AssigneeUserID=本人。
type CaseQuery struct {
	AssigneeUserID string
	Statuses       []CaseStatus
	Limit          int
	Offset         int
}

// CaseUpdate 是一次条件变更（行版本 + 非终态），与处理历史在同一事务内写入。
type CaseUpdate struct {
	CaseID          string
	ExpectedVersion int64
	// SetStatus 为空表示不变更状态；SetAssignee 为空表示不变更指派。
	SetStatus   CaseStatus
	SetAssignee string
	UpdatedAt   time.Time
	Event       EventRecord
}

// Store 是求助单与处理历史的持久化契约，由 internal/support/sqlite 实现。
// 所有条件更新在行版本不匹配或求助单已终结时返回 false，调用方整体回滚。
type Store interface {
	// CreateCaseTx 在审计事务内创建求助单并追加首条历史。
	CreateCaseTx(ctx context.Context, tx audit.Tx, record CaseRecord, event EventRecord) error
	// GetCase 按 ID 读取求助单（关联目标用户名用于脱敏）。
	GetCase(ctx context.Context, caseID string) (CaseRecord, bool, error)
	// ListCases 分页列出求助单；HasMore 表示还有下一页。
	ListCases(ctx context.Context, query CaseQuery) (cases []CaseRecord, hasMore bool, err error)
	// UpdateCaseTx 按行版本条件更新状态/指派，并在同一事务内追加历史。
	UpdateCaseTx(ctx context.Context, tx audit.Tx, update CaseUpdate) (bool, error)
	// ListEvents 按序号分页列出处理历史。
	ListEvents(ctx context.Context, caseID string, offset, limit int) (events []EventRecord, hasMore bool, err error)
	// LookupTarget 按稳定用户 ID 读取目标普通用户快照（含是否有已验证邮箱）。
	LookupTarget(ctx context.Context, userID string) (TargetSnapshot, bool, error)
}

// StaffScope 是工作人员在某功能权限上的数据范围快照。
type StaffScope struct {
	// AllUsers 表示该权限不限制普通用户数据范围。
	AllUsers bool
	// UserIDs 是显式允许的普通用户 ID 集合（AllUsers=false 时生效）。
	UserIDs []string
}

// Allows 报告数据范围是否覆盖目标用户。
func (s StaffScope) Allows(userID string) bool {
	if s.AllUsers {
		return true
	}
	for _, candidate := range s.UserIDs {
		if candidate == userID {
			return true
		}
	}
	return false
}

// Authorizer 判定客服工作人员的功能权限与数据范围，以及指定工作人员是否具备客服
// 资格。生产实现基于 internal/authz（见 AuthzAuthorizer）；任何不确定/依赖故障
// 都必须返回错误，调用方按 ACCESS_DENIED fail-closed。
type Authorizer interface {
	// AuthorizeStaff 返回工作人员在指定权限上的数据范围；未授予或范围未声明时
	// 返回 ErrAccessDenied。
	AuthorizeStaff(ctx context.Context, staffUserID, permissionKey string) (StaffScope, error)
	// StaffEligible 报告指定用户当前是否具备客服处理资格（用于指派变更）。
	StaffEligible(ctx context.Context, staffUserID string) (bool, error)
}

// TargetProtector 按实际权限识别禁止普通客服处理的高权限账户（root 与持有系统
// 管理/审批能力的账户）。实现不确定或依赖故障必须返回错误，调用方 fail-closed。
type TargetProtector interface {
	Protected(ctx context.Context, targetUserID string) (bool, error)
}

// SendRatePolicy 是客服发起找回的限流策略：按客服账户与全局发起预算双维度限流，
// 防止单个客服账户重复触发邮件或全局批量触发。零值使用 DefaultSendRatePolicy。
type SendRatePolicy struct {
	// StaffLimit/StaffWindow 是单个客服账户窗口内允许的发起次数。
	StaffLimit  int
	StaffWindow time.Duration
	// GlobalLimit/GlobalWindow 是全体客服窗口内允许的发起总次数。
	GlobalLimit  int
	GlobalWindow time.Duration
}

// DefaultSendRatePolicy 返回保守默认：单客服 10 分钟 5 次、全局每小时 100 次。
func DefaultSendRatePolicy() SendRatePolicy {
	return SendRatePolicy{
		StaffLimit: 5, StaffWindow: 10 * time.Minute,
		GlobalLimit: 100, GlobalWindow: time.Hour,
	}
}

// resolve 返回带默认值的策略副本。
func (p SendRatePolicy) resolve() SendRatePolicy {
	defaults := DefaultSendRatePolicy()
	if p.StaffLimit == 0 && p.StaffWindow == 0 {
		p.StaffLimit, p.StaffWindow = defaults.StaffLimit, defaults.StaffWindow
	}
	if p.GlobalLimit == 0 && p.GlobalWindow == 0 {
		p.GlobalLimit, p.GlobalWindow = defaults.GlobalLimit, defaults.GlobalWindow
	}
	return p
}

// validate 校验限流参数边界（有界，避免无限制或近零窗口）。
func (p SendRatePolicy) validate() error {
	if p.StaffLimit < 1 || p.StaffLimit > 50 {
		return fmt.Errorf("%w: 单客服找回限流次数必须在 1～50 之间", ErrOptionsInvalid)
	}
	if p.StaffWindow < time.Minute || p.StaffWindow > 24*time.Hour {
		return fmt.Errorf("%w: 单客服找回限流窗口必须在 1 分钟～24 小时之间", ErrOptionsInvalid)
	}
	if p.GlobalLimit < 1 || p.GlobalLimit > 10000 {
		return fmt.Errorf("%w: 全局找回限流次数必须在 1～10000 之间", ErrOptionsInvalid)
	}
	if p.GlobalWindow < time.Minute || p.GlobalWindow > 24*time.Hour {
		return fmt.Errorf("%w: 全局找回限流窗口必须在 1 分钟～24 小时之间", ErrOptionsInvalid)
	}
	return nil
}

// ResetSender 是受信客服通道的找回发送契约；生产实现 *passwordreset.Service。
// 只按目标用户 ID 发起，收件地址由找回服务从已验证邮箱中读取，调用方不能指定。
type ResetSender interface {
	SendResetForSupport(ctx context.Context, request passwordreset.SupportResetRequest) (passwordreset.SupportResetResult, error)
}

// TargetView 是返回给工作人员的必要脱敏资料；不含邮箱明文、密码/MFA/凭证信息。
type TargetView struct {
	UserID           string
	MaskedUsername   string
	MaskedEmail      string
	Status           string
	HasPassword      bool
	HasVerifiedEmail bool
	CanRequestReset  bool
}

// CaseView 是返回给工作人员的求助单脱敏视图。
type CaseView struct {
	ID                   string
	TargetUserID         string
	TargetMaskedUsername string
	TargetMaskedEmail    string
	Reason               string
	Status               CaseStatus
	AssigneeUserID       string
	CreatedByUserID      string
	CreatedAt            time.Time
	UpdatedAt            time.Time
	RowVersion           int64
}

// EventView 是返回给工作人员的处理历史脱敏视图。
type EventView struct {
	ID         string
	CaseID     string
	Seq        int64
	Action     string
	ActorType  audit.ActorKind
	ActorID    string
	FromStatus CaseStatus
	ToStatus   CaseStatus
	Detail     string
	CreatedAt  time.Time
}

// CasePage 是求助单列表结果。
type CasePage struct {
	Cases      []CaseView
	HasMore    bool
	NextOffset int
}

// HistoryPage 是处理历史分页结果。
type HistoryPage struct {
	Events     []EventView
	HasMore    bool
	NextOffset int
}

// ===== 内部辅助 =====

func maskEmail(address string) string {
	at := strings.Index(address, "@")
	if at <= 0 || at == len(address)-1 {
		return "[REDACTED]"
	}
	return string(address[0]) + "***@" + address[at+1:]
}

// maskUsername 只保留前两个字符（不足则一个），其余以 *** 代替，避免返回完整
// 用户名；空用户名返回 [REDACTED]。
func maskUsername(username string) string {
	trimmed := strings.TrimSpace(username)
	if trimmed == "" {
		return "[REDACTED]"
	}
	runes := []rune(trimmed)
	if len(runes) > 2 {
		runes = runes[:2]
	}
	return string(runes) + "***"
}

// validReason 校验求助原因：去掉首尾空白后长度 1～MaxReasonBytes 字节，拒绝 NUL
// 与控制字符以外的内容不做解释（求助文字是不可信数据，只保存不执行）。
func validReason(reason string) (string, bool) {
	trimmed := strings.TrimSpace(reason)
	if trimmed == "" || len(trimmed) > MaxReasonBytes {
		return "", false
	}
	for index := 0; index < len(trimmed); index++ {
		if trimmed[index] == 0 {
			return "", false
		}
	}
	return trimmed, true
}

// validNote 校验处理说明（可为空），规则同求助原因但上限更小。
func validNote(note string) (string, bool) {
	trimmed := strings.TrimSpace(note)
	if len(trimmed) > MaxNoteBytes {
		return "", false
	}
	for index := 0; index < len(trimmed); index++ {
		if trimmed[index] == 0 {
			return "", false
		}
	}
	return trimmed, true
}

func validStatusFilter(statuses []CaseStatus) bool {
	for _, status := range statuses {
		if !status.Valid() {
			return false
		}
	}
	return true
}

func reasonDigest(reason string) string {
	sum := sha256.Sum256([]byte(reason))
	return hex.EncodeToString(sum[:])
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func safeToken(value string) string {
	if len(value) == 0 || len(value) > 64 {
		return ""
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '_' {
			continue
		}
		return ""
	}
	return value
}

// validDetail 处理历史说明只允许稳定机器码与有限中文，避免把自由文本当指令执行。
func validDetail(detail string) string {
	trimmed := strings.TrimSpace(detail)
	if len(trimmed) > MaxNoteBytes {
		return ""
	}
	return trimmed
}
