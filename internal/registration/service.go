package registration

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
)

// AuditRecorder 是注册服务依赖的安全审计写入契约；生产实现为 *audit.Recorder。
// 任何实现都必须 fail-closed：返回错误时调用方拒绝操作，不能静默丢弃审计。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// Options 是构造注册服务的显式依赖。
type Options struct {
	// Store 是注册持久化；必填。
	Store Store
	// Audit 是安全审计写入器；必填。
	Audit AuditRecorder
	// Credentials 是一次性凭证服务；必填。用于签发与消费邮箱验证入口。
	Credentials *credential.Service
	// Mailer 是验证邮件发送接口；nil 表示部署未启用邮件能力，此时提供邮箱的
	// 注册会被拒绝（RequireEmailVerification 时必须显式配置）。
	Mailer EmailSender
	// VerificationURLBase 是验证入口基础地址（例如
	// https://login.example.com/verify-email）。配置 Mailer 时必填；只允许
	// http/https，生产应使用 https。令牌只拼接到该地址的查询参数中，不写日志。
	VerificationURLBase string
	// Enabled 是自主注册总开关；false 时 Register 拒绝，管理员创建账户不受影响。
	Enabled bool
	// RequireReview 为 true 时新账户以 pending 状态创建，需人工审核后才能正常登录
	// （审核执行留给后续步骤；本包只记录待审核状态）。
	RequireReview bool
	// RequireEmailVerification 为 true 时注册必须提供邮箱；false（默认）时邮箱
	// 可选，无邮件能力的部署仍可完成密码注册。
	RequireEmailVerification bool
	// DefaultRoles 是可信默认角色策略；只写入系统/应用角色关联，不自动加入任何
	// 应用成员。空表示不分配默认角色。
	DefaultRoles []DefaultRole
	// PasswordPolicy 是密码策略；零值使用 authn.DefaultPasswordPolicy。
	PasswordPolicy authn.PasswordPolicy
	// HashParams 是 Argon2id 参数；零值使用 authn.DefaultParams。
	HashParams authn.Params
	// VerificationTTL 是验证入口有效期；零值使用 DefaultVerificationTTL。
	VerificationTTL time.Duration
	// ResendCooldown 是重新发送验证入口的最小间隔；零值使用 DefaultResendCooldown。
	ResendCooldown time.Duration
	// AppName 是邮件模板中显示的服务名称；空值使用 "EvernightLogin"。
	AppName string
	// Now 是可注入时钟；nil 使用 time.Now。时间统一 UTC。
	Now func() time.Time
	// Random 是安全随机源；nil 使用 crypto/rand.Reader。
	Random io.Reader
	// Logger 是运行日志器；nil 使用丢弃输出。日志不记录密码、令牌、验证链接、
	// 邮箱明文或哈希。
	Logger *slog.Logger
}

// Service 是注册与邮箱验证领域服务。构造后不可变，可被多个 goroutine 并发使用；
// 它不启动后台协程、不签发会话、不注册 HTTP 路由。
type Service struct {
	opts Options
}

// New 校验依赖并构造注册服务。缺少 Store/Audit/Credentials 或邮件能力配置不完整
// 时返回 ErrOptionsInvalid，不创建默认放行实现或替身依赖。
func New(options Options) (*Service, error) {
	if isNilInterface(options.Store) {
		return nil, fmt.Errorf("%w: 注册存储为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.Audit) {
		return nil, fmt.Errorf("%w: 安全审计写入器为空", ErrOptionsInvalid)
	}
	if options.Credentials == nil {
		return nil, fmt.Errorf("%w: 一次性凭证服务为空", ErrOptionsInvalid)
	}
	if options.Mailer != nil {
		if problem := verificationURLProblem(options.VerificationURLBase); problem != "" {
			return nil, fmt.Errorf("%w: %s", ErrOptionsInvalid, problem)
		}
	} else if options.RequireEmailVerification {
		return nil, fmt.Errorf("%w: 要求邮箱验证时必须配置邮件发送接口与验证入口地址", ErrOptionsInvalid)
	}
	if options.PasswordPolicy.MinRunes == 0 && options.PasswordPolicy.MaxRunes == 0 &&
		options.PasswordPolicy.HistoryLimit == 0 && len(options.PasswordPolicy.WeakExtraWords) == 0 {
		options.PasswordPolicy = authn.DefaultPasswordPolicy()
	}
	if err := options.PasswordPolicy.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOptionsInvalid, err)
	}
	if options.HashParams == (authn.Params{}) {
		options.HashParams = authn.DefaultParams()
	}
	if err := options.HashParams.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOptionsInvalid, err)
	}
	if options.VerificationTTL == 0 {
		options.VerificationTTL = DefaultVerificationTTL
	}
	if options.VerificationTTL < MinVerificationTTL || options.VerificationTTL > MaxVerificationTTL {
		return nil, fmt.Errorf("%w: 邮箱验证有效期必须在 %s～%s 之间", ErrOptionsInvalid,
			MinVerificationTTL, MaxVerificationTTL)
	}
	if options.ResendCooldown == 0 {
		options.ResendCooldown = DefaultResendCooldown
	}
	if options.ResendCooldown < MinResendCooldown || options.ResendCooldown > MaxResendCooldown {
		return nil, fmt.Errorf("%w: 重发冷却必须在 %s～%s 之间", ErrOptionsInvalid,
			MinResendCooldown, MaxResendCooldown)
	}
	if strings.TrimSpace(options.AppName) == "" {
		options.AppName = "EvernightLogin"
	}
	if len([]rune(options.AppName)) > 100 {
		return nil, fmt.Errorf("%w: 服务名称不能超过 100 个字符", ErrOptionsInvalid)
	}
	// 默认角色目前只支持 system 作用域的可信配置：应用角色赋权必须经过
	// internal/role/delegation 的范围与委派校验，注册流程不绕过该不变量。
	for _, role := range options.DefaultRoles {
		if strings.TrimSpace(role.RoleID) == "" || role.ScopeID != DefaultRoleScopeSystem {
			return nil, fmt.Errorf("%w: 默认角色只接受 system 作用域的非空角色 ID", ErrOptionsInvalid)
		}
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
	return &Service{opts: options}, nil
}

// Enabled 报告自主注册当前是否开放。
func (s *Service) Enabled() bool { return s.opts.Enabled }

// EmailCapabilityEnabled 报告是否配置了可用的邮箱验证发送能力。
func (s *Service) EmailCapabilityEnabled() bool {
	return s.opts.Mailer != nil && strings.TrimSpace(s.opts.VerificationURLBase) != ""
}

// Register 执行公开自主注册。
//
// 安全语义：
//   - 注册关闭时返回 ErrRegistrationClosed；管理员创建账户走 internal/account，
//     不受该开关影响。
//   - 字段只来自 RegisterRequest 白名单；用户名/昵称/语言/时区复用 account 的
//     统一规范化与保留名规则，密码复用 authn 策略与 Argon2id。
//   - 邮箱可选（除非 RequireEmailVerification）；提供邮箱时写入未验证行并尝试
//     发送一次性验证入口。验证成功前不会启用邮箱登录/找回能力，响应中的
//     VerificationSent 只表示邮件是否交给发送方，不代表邮箱已验证。
//   - 用户名或邮箱占用统一返回 ErrRegistrationConflict，避免枚举。
//   - 用户、密码凭证、未验证邮箱与默认角色在同一审计事务内创建，失败整体回滚。
//   - 不签发会话或 Token。
func (s *Service) Register(ctx context.Context, request RegisterRequest) (RegisterResult, error) {
	ctx = normalizeContext(ctx)
	if !s.opts.Enabled {
		return RegisterResult{}, ErrRegistrationClosed
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return RegisterResult{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return RegisterResult{}, err
	}
	username, usernameNormalized, err := account.NormalizeUsername(request.Username)
	if err != nil {
		return RegisterResult{}, err
	}
	nickname, err := account.NormalizeNickname(request.Nickname)
	if err != nil {
		return RegisterResult{}, err
	}
	language, err := account.NormalizeLanguage(request.Language)
	if err != nil {
		return RegisterResult{}, err
	}
	timezone, err := account.NormalizeTimezone(request.Timezone)
	if err != nil {
		return RegisterResult{}, err
	}

	var email, emailNormalized string
	if strings.TrimSpace(request.Email) != "" {
		if !s.EmailCapabilityEnabled() {
			return RegisterResult{}, fmt.Errorf("%w: 当前部署未启用邮箱验证，注册时不能提供邮箱", ErrInvalidRequest)
		}
		email, emailNormalized, err = authn.NormalizeEmail(request.Email)
		if err != nil {
			return RegisterResult{}, fmt.Errorf("%w: 邮箱格式无效", ErrInvalidRequest)
		}
	} else if s.opts.RequireEmailVerification {
		return RegisterResult{}, fmt.Errorf("%w: 当前配置要求提供邮箱", ErrInvalidRequest)
	}

	identifiers := []string{username, nickname}
	if email != "" {
		identifiers = append(identifiers, email)
	}
	if err := s.opts.PasswordPolicy.Check(request.Password, identifiers); err != nil {
		return RegisterResult{}, mapPasswordError(err)
	}
	passwordHash, err := authn.HashPassword(request.Password, s.opts.HashParams, s.opts.Random)
	if err != nil {
		return RegisterResult{}, fmt.Errorf("%w: 无法生成密码哈希", ErrStoreUnavailable)
	}
	userID, err := account.NewUserID(s.opts.Random)
	if err != nil {
		return RegisterResult{}, fmt.Errorf("%w: 无法生成用户标识", ErrStoreUnavailable)
	}
	now := s.now()
	status := account.StatusActive
	if s.opts.RequireReview {
		status = account.StatusPending
	}
	params := CreateUserParams{
		UserID:             userID,
		Username:           username,
		UsernameNormalized: usernameNormalized,
		Nickname:           nickname,
		Language:           language,
		Timezone:           timezone,
		Status:             status,
		PasswordHash:       passwordHash,
		Email:              email,
		EmailNormalized:    emailNormalized,
		DefaultRoles:       append([]DefaultRole(nil), s.opts.DefaultRoles...),
		Now:                now,
	}
	changes := []audit.FieldChange{
		{Field: "username", After: username},
		{Field: "status", After: string(status)},
	}
	if email != "" {
		changes = append(changes, audit.FieldChange{Field: "email", After: maskEmail(email)})
	}
	if len(params.DefaultRoles) > 0 {
		roles := make([]string, 0, len(params.DefaultRoles))
		for _, role := range params.DefaultRoles {
			roles = append(roles, role.ScopeID+"/"+role.RoleID)
		}
		changes = append(changes, audit.FieldChange{Field: "default_roles", After: strings.Join(roles, ",")})
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     audit.Actor{Type: audit.ActorAnonymous},
			Action:    "registration.create",
			Target:    audit.Target{Type: "user", ID: userID},
			RequestID: request.RequestID,
			Changes:   changes,
		},
		FailureReasonCode: "registration.create_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.opts.Store.CreateUser(txCtx, tx, params)
	})
	if err != nil {
		return RegisterResult{}, mapCriticalError(err)
	}
	result := RegisterResult{
		UserID:    userID,
		Username:  username,
		Email:     email,
		Status:    status,
		CreatedAt: now,
	}
	if email != "" {
		// 邮件发送失败不回滚已创建账户，也不宣称邮箱已验证；只记录发送状态，
		// 由调用方按冷却时间重新发送。
		sendResult, sendErr := s.sendVerification(ctx, systemCallerOrZero("registration"), userID, "", request.RequestID)
		if sendErr != nil {
			result.VerificationErrorCode = string(CodeOf(sendErr))
			s.opts.Logger.Warn("注册成功但邮箱验证入口未能签发",
				"user_id", userID, "error_code", result.VerificationErrorCode)
		} else {
			result.VerificationSent = sendResult.Sent
			result.VerificationExpiresAt = sendResult.ExpiresAt
			if !sendResult.Sent {
				result.VerificationErrorCode = sendResult.ErrorCode
			}
		}
	}
	s.opts.Logger.Info("自主注册已创建账户",
		"user_id", result.UserID, "status", string(result.Status),
		"email_verification_sent", result.VerificationSent)
	return result, nil
}

// SendEmailVerification 为账户签发新的邮箱验证入口并交给邮件发送方。
//
// 只允许用户本人（SelfCaller）或受信系统组件调用；Email 非空且与当前待验证
// 邮箱不同时，会在审计事务内替换尚未验证的邮箱并覆盖验证票据，使旧地址与旧
// 链接立即失效。已验证邮箱不允许通过本方法替换（返回 ErrEmailAlreadyVerified）。
// 重发受 ResendCooldown 限制；邮件发送失败返回 Sent=false 与稳定错误码，不返回
// “已验证”，也不回滚票据（可在冷却后重发）。
//
// 自主注册开关只影响新注册：注册关闭后既有待验证入口仍可重发与验证，否则关闭
// 注册会把正在进行中的验证流程一并废弃。
func (s *Service) SendEmailVerification(ctx context.Context, caller Caller, request SendVerificationRequest) (SendVerificationResult, error) {
	ctx = normalizeContext(ctx)
	if err := s.authorizeSend(caller, request.UserID); err != nil {
		return SendVerificationResult{}, err
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return SendVerificationResult{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	return s.sendVerification(ctx, caller, request.UserID, request.Email, request.RequestID)
}

// sendVerification 是内部重发实现。replaceEmail 非空时替换未验证邮箱。
func (s *Service) sendVerification(ctx context.Context, caller Caller, userID, replaceEmail, requestID string) (SendVerificationResult, error) {
	if err := ctx.Err(); err != nil {
		return SendVerificationResult{}, err
	}
	if !account.ValidUserID(userID) {
		return SendVerificationResult{}, fmt.Errorf("%w: 目标用户 ID 格式无效", ErrInvalidRequest)
	}
	snapshot, found, err := s.opts.Store.GetUserSnapshot(ctx, userID)
	if err != nil {
		return SendVerificationResult{}, ErrStoreUnavailable
	}
	if !found {
		return SendVerificationResult{}, ErrUserNotFound
	}
	if snapshot.Status != account.StatusActive && snapshot.Status != account.StatusPending {
		return SendVerificationResult{}, ErrAccessDenied
	}
	if !snapshot.HasEmail {
		return SendVerificationResult{}, ErrEmailNotAvailable
	}
	if snapshot.Email.Verified {
		return SendVerificationResult{}, ErrEmailAlreadyVerified
	}
	now := s.now()
	ticket, hasTicket, err := s.opts.Store.GetVerificationTicket(ctx, userID)
	if err != nil {
		return SendVerificationResult{}, ErrStoreUnavailable
	}
	if hasTicket {
		resendAllowedAt := ticket.CreatedAt.Add(s.opts.ResendCooldown)
		if now.Before(resendAllowedAt) {
			return SendVerificationResult{}, fmt.Errorf("%w: 请在 %s 后再试", ErrResendTooSoon,
				resendAllowedAt.UTC().Format(time.RFC3339))
		}
	}
	email := snapshot.Email.Email
	emailNormalized := snapshot.Email.EmailNormalized
	emailChanged := false
	if strings.TrimSpace(replaceEmail) != "" {
		newDisplay, newNormalized, err := authn.NormalizeEmail(replaceEmail)
		if err != nil {
			return SendVerificationResult{}, fmt.Errorf("%w: 邮箱格式无效", ErrInvalidRequest)
		}
		if newNormalized != emailNormalized {
			email, emailNormalized, emailChanged = newDisplay, newNormalized, true
		}
	}
	if !s.EmailCapabilityEnabled() {
		return SendVerificationResult{
			UserID:          userID,
			Email:           email,
			Sent:            false,
			ResendAllowedAt: now,
			ErrorCode:       string(CodeMailDeliveryFailed),
		}, nil
	}
	oldCredentialID := ""
	if hasTicket {
		oldCredentialID = ticket.CredentialID
	}
	// 先签发新凭证但不撤销旧凭证：票据事务可能因目标邮箱被占用等失败。只有新票据
	// 提交成功后旧入口才真正失效，失败时旧凭证与旧票据保持原样，旧有效链接不被误废。
	issued, err := s.opts.Credentials.Issue(ctx, credential.IssueRequest{
		Purpose: PurposeEmailVerify,
		Target:  userID,
		Kind:    credential.KindToken,
		TTL:     s.opts.VerificationTTL,
	})
	if err != nil {
		return SendVerificationResult{}, fmt.Errorf("%w: 无法签发验证入口", ErrStoreUnavailable)
	}
	verificationURL, err := s.buildVerificationURL(userID, issued.ID, issued.Secret.Reveal())
	if err != nil {
		s.cancelCredential(ctx, issued.ID, userID)
		return SendVerificationResult{}, fmt.Errorf("%w: 无法生成验证入口地址", ErrOptionsInvalid)
	}
	ticket = Ticket{
		UserID:          userID,
		CredentialID:    issued.ID,
		Email:           email,
		EmailNormalized: emailNormalized,
		CreatedAt:       now,
		ExpiresAt:       issued.ExpiresAt.UTC(),
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     caller.actor,
			Action:    "registration.email_verification_issued",
			Target:    audit.Target{Type: "user", ID: userID},
			RequestID: requestID,
			Changes: []audit.FieldChange{
				{Field: "email", After: maskEmail(email)},
				{Field: "email_replaced", After: fmt.Sprintf("%t", emailChanged)},
			},
		},
		FailureReasonCode: "registration.email_verification_issue_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.opts.Store.ReplaceTicket(txCtx, tx, ReplaceTicketParams{
			Ticket:         ticket,
			EmailChanged:   emailChanged,
			NewEmail:       email,
			NewEmailNorm:   emailNormalized,
			ReplacedAt:     now,
			EventRequestID: requestID,
		})
	})
	if err != nil {
		// 票据未落库时撤销刚签发的凭证，避免留下无法使用但仍活动的凭证记录；
		// 旧票据与旧凭证保持原样，旧有效链接继续可用。
		s.cancelCredential(ctx, issued.ID, userID)
		return SendVerificationResult{}, mapCriticalError(err)
	}
	// 新票据已提交，旧入口在票据层面已失效；再尽力撤销旧凭证做活动记录清理。
	// 撤销失败不影响安全性（验证时票据 credential_id 不匹配即拒绝）。
	if oldCredentialID != "" && oldCredentialID != issued.ID {
		s.revokeOldCredential(ctx, oldCredentialID, userID)
	}
	result := SendVerificationResult{
		UserID:          userID,
		Email:           email,
		ExpiresAt:       issued.ExpiresAt.UTC(),
		ResendAllowedAt: now.Add(s.opts.ResendCooldown),
	}
	displayName := snapshot.Nickname
	if strings.TrimSpace(displayName) == "" {
		displayName = snapshot.Username
	}
	sendErr := s.opts.Mailer.SendEmailVerification(ctx, EmailMessage{
		UserID:          userID,
		Recipient:       email,
		DisplayName:     displayName,
		VerificationURL: verificationURL,
		ExpiresAt:       issued.ExpiresAt.UTC(),
		ExpiresIn:       formatDuration(s.opts.VerificationTTL),
		AppName:         s.opts.AppName,
		CredentialID:    issued.ID,
		RequestID:       requestID,
	})
	if sendErr != nil {
		// 邮件失败不回滚票据与账户，也不宣称已验证；调用方可在冷却后重发。
		s.opts.Logger.Warn("验证邮件发送失败",
			"user_id", userID, "error_code", string(CodeMailDeliveryFailed))
		result.Sent = false
		result.ErrorCode = string(CodeMailDeliveryFailed)
		return result, nil
	}
	result.Sent = true
	s.opts.Logger.Info("邮箱验证入口已发送", "user_id", userID, "email_sent", true)
	return result, nil
}

// VerifyEmail 消费一次性验证入口并完成邮箱验证。
//
// 所有失败原因（不存在、过期、已消费、已替换、绑定不匹配）统一返回
// ErrVerificationInvalid，避免泄露凭证或账户状态。成功时在审计事务内条件更新
// 未验证邮箱行并删除验证票据；条件不满足时整体拒绝。
//
// 自主注册开关只影响新注册：注册关闭后既有待验证入口仍可完成验证。
func (s *Service) VerifyEmail(ctx context.Context, request VerifyEmailRequest) (VerifyEmailResult, error) {
	ctx = normalizeContext(ctx)
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return VerifyEmailResult{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if !account.ValidUserID(request.UserID) || strings.TrimSpace(request.CredentialID) == "" ||
		request.Token == "" {
		return VerifyEmailResult{}, ErrVerificationInvalid
	}
	ticket, found, err := s.opts.Store.GetVerificationTicket(ctx, request.UserID)
	if err != nil {
		return VerifyEmailResult{}, ErrStoreUnavailable
	}
	if !found || ticket.CredentialID != request.CredentialID {
		return VerifyEmailResult{}, ErrVerificationInvalid
	}
	// 复核账户仍可验证且当前待验证地址仍是票据绑定的地址：地址已被替换、删除或
	// 账户被禁用时旧入口一律失效，不因为票据仍存在而放行。
	snapshot, found, err := s.opts.Store.GetUserSnapshot(ctx, request.UserID)
	if err != nil {
		return VerifyEmailResult{}, ErrStoreUnavailable
	}
	if !found || (snapshot.Status != account.StatusActive && snapshot.Status != account.StatusPending) ||
		!snapshot.HasEmail || snapshot.Email.EmailNormalized != ticket.EmailNormalized ||
		snapshot.Email.Verified {
		return VerifyEmailResult{}, ErrVerificationInvalid
	}
	verified, err := s.opts.Credentials.VerifyAndConsume(ctx, credential.VerifyRequest{
		Kind:    credential.KindToken,
		ID:      request.CredentialID,
		Purpose: PurposeEmailVerify,
		Target:  request.UserID,
		Secret:  request.Token,
	})
	if err != nil {
		if errors.Is(err, credential.ErrStoreUnavailable) {
			return VerifyEmailResult{}, ErrStoreUnavailable
		}
		return VerifyEmailResult{}, ErrVerificationInvalid
	}
	verifiedAt := verified.ConsumedAt.UTC()
	applied := false
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     audit.Actor{Type: audit.ActorUser, ID: request.UserID},
			Action:    "registration.email_verified",
			Target:    audit.Target{Type: "user", ID: request.UserID},
			RequestID: request.RequestID,
			Changes:   []audit.FieldChange{{Field: "email", After: maskEmail(ticket.Email)}},
		},
		FailureReasonCode: "registration.email_verified_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, updateErr := s.opts.Store.CompleteEmailVerification(txCtx, tx, CompleteVerificationParams{
			UserID:          request.UserID,
			EmailNormalized: ticket.EmailNormalized,
			VerifiedAt:      verifiedAt,
		})
		if updateErr != nil {
			return updateErr
		}
		if !ok {
			return ErrVerificationInvalid
		}
		applied = true
		return nil
	})
	if err != nil {
		return VerifyEmailResult{}, mapCriticalError(err)
	}
	if !applied {
		return VerifyEmailResult{}, ErrVerificationInvalid
	}
	s.opts.Logger.Info("邮箱已验证", "user_id", request.UserID)
	return VerifyEmailResult{UserID: request.UserID, Email: ticket.Email, VerifiedAt: verifiedAt}, nil
}

// authorizeSend 校验重发验证入口的调用身份：只允许用户本人或受信系统组件。
func (s *Service) authorizeSend(caller Caller, userID string) error {
	if err := caller.actor.Validate(); err != nil {
		return ErrAccessDenied
	}
	switch caller.actor.Type {
	case audit.ActorUser:
		if caller.actor.ID != userID {
			return ErrAccessDenied
		}
		return nil
	case audit.ActorSystem:
		return nil
	default:
		return ErrAccessDenied
	}
}

// buildVerificationURL 把一次性凭证明文拼接到配置的验证入口地址。令牌只存在于
// 邮件链接中，不写入日志或数据库。
func (s *Service) buildVerificationURL(userID, credentialID, token string) (string, error) {
	base, err := url.Parse(s.opts.VerificationURLBase)
	if err != nil {
		return "", err
	}
	query := base.Query()
	query.Set("uid", userID)
	query.Set("cid", credentialID)
	query.Set("token", token)
	base.RawQuery = query.Encode()
	base.Fragment = ""
	return base.String(), nil
}

// cancelCredential 在票据未落库时尽力撤销刚签发的凭证；失败只写运行日志。
func (s *Service) cancelCredential(ctx context.Context, credentialID, userID string) {
	if credentialID == "" {
		return
	}
	if err := s.opts.Credentials.Cancel(context.WithoutCancel(ctx), credential.CancelRequest{
		ID:      credentialID,
		Purpose: PurposeEmailVerify,
		Target:  userID,
	}); err != nil {
		s.opts.Logger.Warn("撤销未使用的邮箱验证凭证失败", "user_id", userID,
			"error_category", "store_unavailable")
	}
}

// revokeOldCredential 在新票据提交成功后尽力撤销被替换的旧凭证。它只是活动记录
// 清理：验证路径以票据绑定的凭证 ID 为准，撤销失败不会让旧链接重新有效。
func (s *Service) revokeOldCredential(ctx context.Context, credentialID, userID string) {
	if err := s.opts.Credentials.Cancel(context.WithoutCancel(ctx), credential.CancelRequest{
		ID:      credentialID,
		Purpose: PurposeEmailVerify,
		Target:  userID,
	}); err != nil {
		s.opts.Logger.Warn("清理旧邮箱验证凭证失败", "user_id", userID,
			"error_category", "store_unavailable")
	}
}

// mapPasswordError 把 authn 密码策略错误映射为注册领域错误；只保留规则描述，
// 不回显密码内容。
func mapPasswordError(err error) error {
	if errors.Is(err, authn.ErrWeakPassword) {
		return fmt.Errorf("%w: 密码不符合强度要求", ErrWeakPassword)
	}
	if errors.Is(err, authn.ErrInvalidRequest) {
		return fmt.Errorf("%w: 密码格式无效", ErrInvalidRequest)
	}
	return fmt.Errorf("%w: 密码不符合要求", ErrWeakPassword)
}

// mapCriticalError 把审计事务或存储错误映射为稳定的注册领域错误。审计失败优先，
// 不能把“失败证据未可靠保存”伪装成普通冲突。
func mapCriticalError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, audit.ErrAuditUnavailable):
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	case errors.Is(err, ErrRegistrationConflict), errors.Is(err, ErrVerificationInvalid),
		errors.Is(err, ErrEmailAlreadyVerified), errors.Is(err, ErrResendTooSoon),
		errors.Is(err, ErrAccessDenied), errors.Is(err, ErrUserNotFound),
		errors.Is(err, ErrOptionsInvalid), errors.Is(err, ErrMailUnavailable):
		return err
	case errors.Is(err, audit.ErrInvalidEvent), errors.Is(err, audit.ErrDuplicateEvent):
		return fmt.Errorf("%w: 审计事件无效", ErrOptionsInvalid)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, ErrStoreUnavailable):
		return err
	default:
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
}

// maskEmail 把邮箱脱敏为可用于审计的单条诊断值（首字符 + 域名），不保存完整
// 本地部分。
func maskEmail(email string) string {
	at := strings.LastIndexByte(email, '@')
	if at <= 0 || at == len(email)-1 {
		return "[REDACTED]"
	}
	return email[:1] + "***" + email[at:]
}

// formatDuration 把时长格式化为邮件展示用的简短中文文本。
func formatDuration(d time.Duration) string {
	if d%time.Hour == 0 {
		return fmt.Sprintf("%d 小时", int(d/time.Hour))
	}
	if d%time.Minute == 0 {
		return fmt.Sprintf("%d 分钟", int(d/time.Minute))
	}
	return d.String()
}

// systemCallerOrZero 构造受信系统调用者；构造失败时返回零值（随后授权会被拒绝）。
func systemCallerOrZero(componentID string) Caller {
	caller, err := SystemCaller(componentID)
	if err != nil {
		return Caller{actor: audit.Actor{Type: audit.ActorSystem, ID: componentID}}
	}
	return caller
}

// now 返回 UTC 截断到毫秒的当前时间。
func (s *Service) now() time.Time {
	return s.opts.Now().UTC().Truncate(time.Millisecond)
}

// normalizeContext 把 nil ctx 当成 Background 处理。
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// isNilInterface 检测 nil 接口与 typed nil 指针，避免把 typed nil 当成可用依赖。
func isNilInterface(value any) bool {
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
