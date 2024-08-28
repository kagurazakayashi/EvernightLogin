// Package passwordreset 实现主动改密与邮件找回的完整流程，复用密码策略、
// 一次性凭证、邮件模板、会话撤销与安全审计。
//
// 安全不变量：
//   - 主动改密必须由已认证用户本人发起，并复用 internal/authn.SetPassword 的当前
//     密码复核、密码策略/历史复用检查与步骤 39 敏感操作策略；改密成功后安全版本
//     递增（旧会话因版本不匹配失效）并撤销该账户全部会话，默认要求重新登录
//     （不保留当前会话），不返回新会话。
//   - 邮件找回只向**已验证邮箱**发送短期高熵一次性入口；公开响应不区分账户是否
//     存在（未找到/无密码/禁用/root/邮件发送失败都返回同一通用结果，差异只写内部
//     审计）。访问链接不会自动建立任何会话，链接只用于原子消费凭证并设置新密码。
//   - 找回不解除 MFA/Passkey，也不为无密码账户自动添加密码；root 密码只能走本地
//     受控初始化。凭证由 internal/credential 以受保护摘要保存并原子消费，过期/重放
//     与并发两次重置只有一方成功。
//   - 找回入口的页面预检查（ValidateResetToken）与最终提交（CompleteReset）共用
//     同一组请求状态、一次性凭证状态/绑定、期限与账户可找回性判断，但预检查不
//     消费、不改变状态，也不构成最终授权；过期、错误摘要、已消费/已撤销凭证、
//     存储故障与不可找回账户在两层都按默认拒绝处理。
//   - 找回完成（CompleteReset）采用“事务外昂贵准备 + 单事务提交”：密码策略、历史
//     复用与 Argon2 派生在消费凭证之前完成，失败不会烧掉仍有效入口；凭证条件消费、
//     请求终态、其他入口作废及其凭证撤销、密码/历史/安全版本写入、关键审计与
//     OAuth 撤销 outbox 在同一数据库事务提交，任一步失败整体回滚（令牌未消费、可
//     重试），不存在“先消费后改密”的双赢家或半提交，也不使用失败后恢复令牌的补丁。
//   - 找回入口在签发时绑定账户安全代际（users.security_version）、最近已验证邮箱
//     身份（bound_email_normalized）与已验证邮箱身份代际（bound_email_identity_version，
//     步骤 250），预检查与完成提交边界都核对：改密、管理员强制改密、人工/客服恢复、
//     MFA 因素变更、禁用（启用不递减）等安全变更使旧链接确定性失效；验证邮箱切换在
//     同一事务内替换已验证邮箱身份并递增代际，旧邮箱取得的有效期内链接立即失效；
//     邮箱 A→B→A 往返切换后文本虽复原，代际已前进，旧链接仍永久拒绝，不会复活。
//     迁移前未绑定旧行（含 0051 时代缺少代际的行）保守失效（不再保留不安全兼容），
//     不依赖异步清理保证安全。
//   - 找回改密只修改密码并递增安全版本：不解除 MFA/TOTP/Passkey/恢复代码，也不签发
//     会话；可重置密码不等于绕过 MFA 登录。
//   - 密码变更/找回后写入 OAuth 撤销 outbox 事件（后续 OAuth 步骤接入消费者），
//     不宣称当前已撤销所有外部应用/Token。
//   - 密码、找回 token、凭证明文与哈希绝不写入日志、审计、错误或通知；邮件与安全
//     告知只含用户可安全看到的信息。
package passwordreset

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
)

// 领域错误哨兵；错误文本不包含账户存在性细节、密码或 token。
var (
	ErrOptionsInvalid = errors.New("密码找回服务选项无效")
	ErrInvalidRequest = errors.New("密码找回请求无效")
	ErrAccessDenied   = errors.New("未获准执行该密码操作")
	ErrTokenInvalid   = errors.New("找回入口无效或已失效")
	ErrTokenExpired   = errors.New("找回入口已过期")
	// ErrConflict 表示找回提交与并发的账户/密码状态变化冲突；本次提交整体回滚，
	// 一次性凭证未被消费，调用方可用同一入口重试。
	ErrConflict         = errors.New("找回操作与并发变更冲突")
	ErrAccountDisabled  = errors.New("账户当前不可用")
	ErrNoPassword       = errors.New("账户未设置密码，不能通过找回流程添加")
	ErrMailFailed       = errors.New("找回邮件发送失败")
	ErrNoVerifiedEmail  = errors.New("账户没有可用于找回的已验证邮箱")
	ErrRateLimited      = errors.New("请求过于频繁")
	ErrSessionRevoke    = errors.New("会话撤销未完成")
	ErrStoreUnavailable = errors.New("密码找回存储暂时不可用")
	ErrAuditUnavailable = errors.New("关键操作未能可靠记录")
)

// ErrorCode 是密码找回领域对根包错误码注册表的投影（只复用既有 46 码）。
type ErrorCode string

const (
	CodeReqInvalid         ErrorCode = "REQ_INVALID"
	CodeAccessDenied       ErrorCode = "ACCESS_DENIED"
	CodeAuthFailed         ErrorCode = "AUTH_FAILED"
	CodeChallengeInvalid   ErrorCode = "CHALLENGE_INVALID"
	CodeUserDisabled       ErrorCode = "USER_DISABLED"
	CodeRateLimited        ErrorCode = "RATE_LIMITED"
	CodeConflict           ErrorCode = "CONFLICT"
	CodeAuthzUnavailable   ErrorCode = "AUTHZ_UNAVAILABLE"
	CodeDBUnavailable      ErrorCode = "DB_UNAVAILABLE"
	CodeAuditWriteFailed   ErrorCode = "AUDIT_WRITE_FAILED"
	CodeMailDeliveryFailed ErrorCode = "MAIL_DELIVERY_FAILED"
	CodeInternalError      ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把密码找回领域错误映射为已登记错误码；认证领域错误先委托 authn.CodeOf
// （弱密码/历史复用等映射到既有码），未知错误统一内部错误。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidRequest):
		return CodeReqInvalid
	case errors.Is(err, ErrAccessDenied), errors.Is(err, ErrNoPassword),
		errors.Is(err, ErrNoVerifiedEmail):
		return CodeAccessDenied
	case errors.Is(err, ErrTokenInvalid), errors.Is(err, ErrTokenExpired):
		return CodeChallengeInvalid
	case errors.Is(err, ErrConflict):
		return CodeConflict
	case errors.Is(err, ErrAccountDisabled):
		return CodeUserDisabled
	case errors.Is(err, ErrRateLimited):
		return CodeRateLimited
	case errors.Is(err, ErrMailFailed):
		return CodeMailDeliveryFailed
	case errors.Is(err, ErrSessionRevoke):
		return CodeDBUnavailable
	case errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	}
	switch mapped := authn.CodeOf(err); mapped {
	case "":
		return ""
	case authn.CodeInternalError:
		return CodeInternalError
	default:
		return ErrorCode(mapped)
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

// SystemCaller 构造受信系统组件调用者。
func SystemCaller(componentID string) (Caller, error) {
	actor := audit.Actor{Type: audit.ActorSystem, ID: componentID}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 系统组件标识无效", ErrInvalidRequest)
	}
	return Caller{actor: actor}, nil
}

// Actor 返回审计身份副本。
func (c Caller) Actor() audit.Actor { return c.actor }

// IsUser 报告是否为普通用户身份。
func (c Caller) IsUser() bool { return c.actor.Type == audit.ActorUser }

// PasswordService 是密码写入契约；生产实现为 *internal/authn.Service。
//
// 找回完成路径（CompleteReset）需要更严格的原子提交能力：生产实现还必须满足
// RecoveryCommitter（PrepareRecoveryReset + ApplyRecoveryResetTx）。只在非完成路径
// （ChangePassword）需要 SetPassword 的适配器可以只实现本接口，但 CompleteReset 对
// 不满足 RecoveryCommitter 的实现在运行期 fail-closed（ErrOptionsInvalid），不存在
// “先消费凭证、后改密”的非原子降级路径。
type PasswordService interface {
	SetPassword(ctx context.Context, caller authn.Caller, request authn.SetPasswordRequest) (authn.SetPasswordResult, error)
	ResetPasswordForRecovery(ctx context.Context, caller authn.Caller, request authn.RecoveryResetRequest) (authn.SetPasswordResult, error)
}

// RecoveryCommitter 是找回改密的原子提交扩展（步骤 205）：PrepareRecoveryReset 在
// 事务外完成账户/密码策略/历史复用校验与昂贵哈希派生（不消费凭证）；ApplyRecoveryResetTx
// 在调用方事务内重新核对账户/凭证版本并写入密码、历史与安全版本。生产实现为
// *internal/authn.Service。
type RecoveryCommitter interface {
	PrepareRecoveryReset(ctx context.Context, caller authn.Caller,
		request authn.RecoveryResetRequest) (authn.PreparedRecoveryReset, error)
	ApplyRecoveryResetTx(ctx context.Context, caller authn.Caller,
		prepared authn.PreparedRecoveryReset, tx audit.Tx) (authn.SetPasswordResult, error)
}

// SessionRevoker 是账户级会话撤销契约；生产实现为 *internal/session.Service。
type SessionRevoker interface {
	RevokeAllForUser(ctx context.Context, userID, reason string) (int64, error)
}

// AuditRecorder 是安全审计写入契约；实现必须 fail-closed。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// ChangeRequest 是本人主动改密请求。
type ChangeRequest struct {
	// CurrentPassword 是当前密码（再次验证）；不保存、不记录。
	CurrentPassword string
	// NewPassword 是新密码；不保存、不记录。
	NewPassword string
	// ClientIP 是可信边界解析的客户端地址，仅用于改密复核失败限流。
	ClientIP  string
	RequestID string
}

// ChangeResult 是改密结果；不包含密码或哈希。
type ChangeResult struct {
	UserID          string
	SecurityVersion int64
	// RequiresRelogin 恒为 true：默认安全策略是撤销全部会话并要求重新登录。
	RequiresRelogin bool
	SessionsRevoked int64
	OutboxEventID   string
	ChangedAt       time.Time
}

// BeginResult 是开始找回的公开结果。为避免账户存在性泄露，成功/未找到/无密码/
// 禁用/邮件失败/限流都返回同样的零值结构且 err 为 nil（差异只进内部审计）。
type BeginResult struct{}

// BeginResetRequest 是开始找回请求。Identifier 是邮箱；ClientIP 由可信边界解析，
// 用于来源维度限流（可用空表示未知来源，不能由普通请求参数自称）。
type BeginResetRequest struct {
	Identifier string
	ClientIP   string
	RequestID  string
}

// RatePolicy 是公开找回入口的有界限流/冷却策略。
type RatePolicy struct {
	// Limit/Window 是每邮箱与每来源在窗口内允许的开始找回次数。
	Limit  int
	Window time.Duration
}

// DefaultRatePolicy 返回保守默认：每邮箱/每来源每小时 5 次。
func DefaultRatePolicy() RatePolicy {
	return RatePolicy{Limit: 5, Window: time.Hour}
}

// ResetResult 是完成找回的结果；不签发会话。
type ResetResult struct {
	UserID          string
	SecurityVersion int64
	RequiresRelogin bool
	SessionsRevoked int64
	OutboxEventID   string
	ResetAt         time.Time
}

// CompleteRequest 是完成找回请求；Token 是从邮件链接取得的入口凭证。
type CompleteRequest struct {
	Token       string
	NewPassword string
	RequestID   string
}

// Options 是服务依赖。
type Options struct {
	Store       Store
	Audit       AuditRecorder
	Credentials *credential.Service
	// Passwords 是密码写入契约；找回完成路径要求实现同时满足 RecoveryCommitter
	// （生产 *internal/authn.Service 满足）。缺失时 CompleteReset fail-closed。
	Passwords PasswordService
	Sessions  SessionRevoker
	Mailer    mailer.Sender
	// Deliveries 是可靠投递入队服务（步骤 197）：非空时找回邮件/安全告知改走队列，
	// 失败由投递任务的有限重试承担；nil 时回退直接 Mailer（单测/嵌入式兼容）。
	Deliveries  mailer.DeliveryEnqueuer
	Templates   *mailer.TemplateSet
	FromAddress string
	AppName     string
	SupportURL  string
	// ResetURLBase 是邮件中找回入口的 URL 前缀（token 以 query 参数附加）；
	// 必须由宿主配置为受控的公开或本地页面地址。
	ResetURLBase string
	// TokenTTL 是找回入口有效期，默认 15 分钟，边界 5～30 分钟。
	TokenTTL time.Duration
	// RatePolicy 是公开找回入口每邮箱/每来源限流；零值使用 DefaultRatePolicy。
	RatePolicy RatePolicy
	// SupportRatePolicy 是受信客服通道按目标用户的限流；零值使用
	// DefaultSupportRatePolicy。它防止客服重复发起导致邮件轰炸。
	SupportRatePolicy SupportRatePolicy
	Now               func() time.Time
	Random            io.Reader
	Logger            *slog.Logger
}

// Service 是改密/找回流程服务。构造后不可变，不启动协程，不签发会话。
type Service struct {
	opts Options
	// 邮箱与来源两个维度各自滑动窗口计数；进程内单实例语义。
	emailLimiter *windowLimiter
	ipLimiter    *windowLimiter
	// supportLimiter 是受信客服通道按目标用户的限流。
	supportLimiter *supportLimiter
}

// windowLimiter 是有界进程内滑动窗口计数限流器；容量超限时清理最旧键。
type windowLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	entries map[string][]time.Time
}

func newWindowLimiter(limit int, window time.Duration) *windowLimiter {
	return &windowLimiter{limit: limit, window: window, entries: make(map[string][]time.Time)}
}

func (l *windowLimiter) allow(key string, now time.Time) bool {
	if l == nil || l.limit <= 0 || key == "" {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-l.window)
	kept := l.entries[key]
	retained := kept[:0]
	for _, timestamp := range kept {
		if timestamp.After(cutoff) {
			retained = append(retained, timestamp)
		}
	}
	if len(retained) >= l.limit {
		l.entries[key] = retained
		return false
	}
	l.entries[key] = append(retained, now)
	if len(l.entries) > 10000 {
		for candidate, timestamps := range l.entries {
			if len(timestamps) == 0 || !timestamps[len(timestamps)-1].After(cutoff) {
				delete(l.entries, candidate)
			}
		}
	}
	return true
}

// DefaultTokenTTL 是找回入口默认有效期。
const DefaultTokenTTL = 15 * time.Minute

// New 校验依赖并构造服务。
func New(options Options) (*Service, error) {
	if isNil(options.Store) {
		return nil, fmt.Errorf("%w: 存储为空", ErrOptionsInvalid)
	}
	if isNil(options.Audit) {
		return nil, fmt.Errorf("%w: 审计写入器为空", ErrOptionsInvalid)
	}
	if options.Credentials == nil {
		return nil, fmt.Errorf("%w: 一次性凭证服务为空", ErrOptionsInvalid)
	}
	if isNil(options.Passwords) {
		return nil, fmt.Errorf("%w: 密码服务为空", ErrOptionsInvalid)
	}
	if isNil(options.Sessions) {
		return nil, fmt.Errorf("%w: 会话撤销服务为空", ErrOptionsInvalid)
	}
	if isNil(options.Mailer) {
		return nil, fmt.Errorf("%w: 邮件发送接口为空", ErrOptionsInvalid)
	}
	if _, err := mailer.ParseAddress(options.FromAddress); err != nil {
		return nil, fmt.Errorf("%w: 发件地址无效", ErrOptionsInvalid)
	}
	if strings.TrimSpace(options.ResetURLBase) == "" {
		return nil, fmt.Errorf("%w: 找回入口 URL 前缀为空", ErrOptionsInvalid)
	}
	parsedURL, err := url.Parse(options.ResetURLBase)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") ||
		parsedURL.Host == "" || parsedURL.User != nil {
		return nil, fmt.Errorf("%w: 找回入口 URL 必须是无凭证的 http(s) 绝对地址", ErrOptionsInvalid)
	}
	if options.RatePolicy.Limit == 0 && options.RatePolicy.Window == 0 {
		options.RatePolicy = DefaultRatePolicy()
	}
	if options.RatePolicy.Limit < 1 || options.RatePolicy.Limit > 100 {
		return nil, fmt.Errorf("%w: 找回限流次数必须在 1～100 之间", ErrOptionsInvalid)
	}
	if options.RatePolicy.Window < time.Minute || options.RatePolicy.Window > 24*time.Hour {
		return nil, fmt.Errorf("%w: 找回限流窗口必须在 1 分钟～24 小时之间", ErrOptionsInvalid)
	}
	if options.SupportRatePolicy.Limit == 0 && options.SupportRatePolicy.Window == 0 {
		options.SupportRatePolicy = DefaultSupportRatePolicy()
	}
	if options.SupportRatePolicy.Limit < 1 || options.SupportRatePolicy.Limit > 100 {
		return nil, fmt.Errorf("%w: 客服找回限流次数必须在 1～100 之间", ErrOptionsInvalid)
	}
	if options.SupportRatePolicy.Window < time.Minute || options.SupportRatePolicy.Window > 24*time.Hour {
		return nil, fmt.Errorf("%w: 客服找回限流窗口必须在 1 分钟～24 小时之间", ErrOptionsInvalid)
	}
	if options.TokenTTL == 0 {
		options.TokenTTL = DefaultTokenTTL
	}
	if options.TokenTTL < 5*time.Minute || options.TokenTTL > 30*time.Minute {
		return nil, fmt.Errorf("%w: 找回入口有效期必须在 5～30 分钟之间", ErrOptionsInvalid)
	}
	if options.Templates == nil {
		templates, err := mailer.DefaultTemplateSet()
		if err != nil {
			return nil, fmt.Errorf("%w: 默认邮件模板不可用", ErrOptionsInvalid)
		}
		options.Templates = templates
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Service{
		opts:         options,
		emailLimiter: newWindowLimiter(options.RatePolicy.Limit, options.RatePolicy.Window),
		ipLimiter:    newWindowLimiter(options.RatePolicy.Limit, options.RatePolicy.Window),
		supportLimiter: &supportLimiter{
			policy:  options.SupportRatePolicy,
			entries: make(map[string][]time.Time),
		},
	}, nil
}

// ===== 内部辅助 =====

const (
	resetPurpose = "password.reset"
	// 用于 outbox 的原因类别。
	outboxReasonChanged = "password_changed"
	outboxReasonReset   = "password_reset"
)

func (s *Service) now() time.Time { return s.opts.Now().UTC().Truncate(time.Millisecond) }

func newID(random io.Reader, prefix string, size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", fmt.Errorf("%w: 安全随机源不可用", ErrStoreUnavailable)
	}
	return prefix + hex.EncodeToString(buffer), nil
}

func maskAddress(address string) string {
	at := strings.Index(address, "@")
	if at <= 0 || at == len(address)-1 {
		return "[REDACTED]"
	}
	return string(address[0]) + "***@" + address[at+1:]
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func validRequestID(value string) string {
	if account.ValidateRequestID(value) != nil {
		return ""
	}
	return value
}

func (s *Service) recordFailure(ctx context.Context, actor audit.Actor, action, reason, code, requestID string) {
	if err := actor.Validate(); err != nil {
		return
	}
	event := audit.Event{
		Actor: actor, Action: action, Target: audit.Target{Type: "password_reset"},
		Outcome: audit.OutcomeFailure, ErrorCode: code, ReasonCode: safeToken(reason),
		RequestID: validRequestID(requestID),
	}
	if err := s.opts.Audit.RecordFailure(ctx, event); err != nil {
		s.opts.Logger.Warn("密码找回失败审计写入失败", "error", err)
	}
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

func mapCriticalError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, audit.ErrAuditUnavailable):
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	case errors.Is(err, audit.ErrInvalidEvent):
		return fmt.Errorf("%w: 审计事件无效", ErrOptionsInvalid)
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrAccessDenied),
		errors.Is(err, ErrTokenInvalid), errors.Is(err, ErrTokenExpired),
		errors.Is(err, ErrConflict), errors.Is(err, ErrAccountDisabled),
		errors.Is(err, ErrNoPassword):
		return err
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, ErrStoreUnavailable):
		return err
	default:
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
}
