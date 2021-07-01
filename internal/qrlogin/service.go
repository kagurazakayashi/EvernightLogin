package qrlogin

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	"github.com/kagurazakayashi/EvernightLogin/internal/ratelimit"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// OAuthClientReader 读取客户端登记配置；生产实现为 *internal/oauthclient.Store。
type OAuthClientReader interface {
	GetClient(ctx context.Context, clientID string) (oauthclient.ClientRecord, bool, error)
}

// ApplicationReader 读取应用展示资料（确认页展示可信应用名）；生产实现为
// *internal/app/sqlite.Store 或 *app.Service 的只读存储。
type ApplicationReader interface {
	GetApplication(ctx context.Context, applicationID string) (app.Application, error)
}

// Sessions 是会话校验与确认端会话复核契约；生产实现为 *internal/session.Service。
type Sessions interface {
	Validate(ctx context.Context, secret string) (session.Session, error)
	VerifyActiveSession(ctx context.Context, userID, sessionID string) error
}

// SessionIssuer 是登录批准转换为目标应用会话的契约；生产实现为
// *internal/session.Service（IssueLoginGrantSession）。
type SessionIssuer interface {
	IssueLoginGrantSession(ctx context.Context, request session.LoginGrantRequest,
		gate session.LoginGrantGate) (session.IssuedSession, error)
}

// AuditRecorder 是安全审计写入契约；生产实现为 *internal/audit.Recorder。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// Options 是扫码登录服务的显式依赖。Store/Audit/Clients/Applications/Sessions/
// SessionIssuer/Keyring 任一缺失（含 typed-nil）都拒绝构造；Reauth 缺失时批准
// 一律拒绝（fail-closed）。Enabled=false 时所有写操作拒绝（默认关闭）。
type Options struct {
	Store         Store
	Audit         AuditRecorder
	Clients       OAuthClientReader
	Applications  ApplicationReader
	Sessions      Sessions
	SessionIssuer SessionIssuer
	// Reauth 是步骤 39 敏感操作收敛入口；缺失时"批准"一律拒绝。
	Reauth reauth.OperationRunner
	// Keyring 用于领取绑定 HMAC 摘要；必填。
	Keyring *secrets.Keyring
	// Enabled 是全局总开关；默认 false（关闭）。关闭时创建/批准/领取一律拒绝。
	Enabled bool
	// AllowedClientIDs 是应用级白名单；启用时为空表示任何应用都不允许。
	AllowedClientIDs []string
	// RequestTTL 是请求有效期；0 使用 DefaultRequestTTL。
	RequestTTL time.Duration
	// ClaimInterval 是领取/状态查询最小间隔；0 使用 DefaultClaimInterval。
	ClaimInterval time.Duration
	// CreatePerMinute 是每客户端每分钟创建请求上限；0 使用默认值。
	CreatePerMinute int
	// ConfirmPerWindow/ConfirmWindow 是每用户确认尝试上限与窗口；0 使用默认值。
	ConfirmPerWindow int
	ConfirmWindow    time.Duration
	Now              func() time.Time
	Random           io.Reader
	Logger           *slog.Logger
}

// Service 是扫码登录服务；构造后不可变、可并发使用，不启动后台协程、不渲染页面。
type Service struct {
	opts           Options
	allowedClients map[string]struct{}
	requestTTL     time.Duration
	claimInterval  time.Duration
	createLimiter  *ratelimit.Limiter
	confirmLimiter *ratelimit.Limiter
	now            func() time.Time
	random         io.Reader
	logger         *slog.Logger
}

// New 校验依赖与参数并构造服务。
func New(options Options) (*Service, error) {
	if isNilInterface(options.Store) {
		return nil, fmt.Errorf("%w: 扫码登录存储为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.Audit) {
		return nil, fmt.Errorf("%w: 审计写入器为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.Clients) {
		return nil, fmt.Errorf("%w: OAuth 客户端读取器为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.Applications) {
		return nil, fmt.Errorf("%w: 应用资料读取器为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.Sessions) {
		return nil, fmt.Errorf("%w: 会话校验器为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.SessionIssuer) {
		return nil, fmt.Errorf("%w: 登录批准会话签发器为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.Keyring) {
		return nil, fmt.Errorf("%w: 密钥环为空", ErrOptionsInvalid)
	}
	allowed, err := validateAllowedClients(options.AllowedClientIDs)
	if err != nil {
		return nil, err
	}
	requestTTL := options.RequestTTL
	if requestTTL == 0 {
		requestTTL = DefaultRequestTTL
	}
	if requestTTL < MinRequestTTL || requestTTL > MaxRequestTTL {
		return nil, fmt.Errorf("%w: 请求有效期必须在 %s～%s 之间",
			ErrOptionsInvalid, MinRequestTTL, MaxRequestTTL)
	}
	claimInterval := options.ClaimInterval
	if claimInterval == 0 {
		claimInterval = DefaultClaimInterval
	}
	if claimInterval < MinClaimInterval || claimInterval > MaxClaimInterval {
		return nil, fmt.Errorf("%w: 查询间隔必须在 %s～%s 之间",
			ErrOptionsInvalid, MinClaimInterval, MaxClaimInterval)
	}
	createPerMinute := options.CreatePerMinute
	if createPerMinute == 0 {
		createPerMinute = defaultCreatePerMinute
	}
	if createPerMinute < 1 || createPerMinute > 1000 {
		return nil, fmt.Errorf("%w: 创建限流上限必须在 1～1000 次/分钟之间", ErrOptionsInvalid)
	}
	confirmPerWindow := options.ConfirmPerWindow
	if confirmPerWindow == 0 {
		confirmPerWindow = defaultConfirmPerWindow
	}
	if confirmPerWindow < 1 || confirmPerWindow > 1000 {
		return nil, fmt.Errorf("%w: 确认限流上限必须在 1～1000 次之间", ErrOptionsInvalid)
	}
	confirmWindow := options.ConfirmWindow
	if confirmWindow == 0 {
		confirmWindow = defaultConfirmWindow
	}
	if confirmWindow < time.Minute || confirmWindow > time.Hour {
		return nil, fmt.Errorf("%w: 确认限流窗口必须在 1 分钟～1 小时之间", ErrOptionsInvalid)
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	random := options.Random
	if random == nil {
		random = randReader()
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	createLimiter, err := ratelimit.New(ratelimit.Options{
		Policy: ratelimit.Policy{Limit: createPerMinute, Window: time.Minute},
		Now:    now,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: 创建限流器构造失败", ErrOptionsInvalid)
	}
	confirmLimiter, err := ratelimit.New(ratelimit.Options{
		Policy: ratelimit.Policy{Limit: confirmPerWindow, Window: confirmWindow},
		Now:    now,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: 确认限流器构造失败", ErrOptionsInvalid)
	}
	return &Service{
		opts: options, allowedClients: allowedClientsMap(allowed),
		requestTTL: requestTTL, claimInterval: claimInterval,
		createLimiter: createLimiter, confirmLimiter: confirmLimiter,
		now: now, random: random, logger: logger,
	}, nil
}

// BeginRequest 是发起端创建扫码登录请求的输入。ClientID 是目标网页应用（由宿主
// 可信配置决定，不接受浏览器任意填写其它应用）；Scopes 只用于确认页展示，不是
// Token 授权；Requester 来自可信边界，仅展示与审计。
type BeginRequest struct {
	ClientID  string
	Scopes    []string
	RequestID string
	Requester RequesterInfo
}

// BeginResult 是创建结果。ClaimSecret 只在此返回一次，必须投递给原始发起端并且
// 绝不写入二维码；QRPayload 只含一次性请求标识。
type BeginResult struct {
	RequestID           string
	ClaimSecret         ClaimSecret
	QRPayload           string
	ExpiresAt           time.Time
	Version             int64
	PollIntervalSeconds int
}

// PromptRequest 是确认端（APP）读取请求的输入。SessionSecret 必须来自真实完整
// 普通会话；AuditRequestID 可选，用于审计关联。
type PromptRequest struct {
	SessionSecret  string
	RequestID      string
	AuditRequestID string
}

// Prompt 是确认页/APP 展示的上下文（不含任何秘密）。
type Prompt struct {
	RequestID       string
	ClientID        string
	ApplicationName string
	ClientType      string
	Status          string
	Scopes          []string
	Requester       RequesterInfo
	CreatedAt       time.Time
	ExpiresAt       time.Time
	Version         int64
	// Warning 是固定风险提醒：只确认本人正在进行的登录，避免社会工程。
	Warning string
}

// DecideRequest 是确认端批准/拒绝的输入。ExpectedVersion 必须与读取到的版本一致。
type DecideRequest struct {
	SessionSecret   string
	RequestID       string
	ExpectedVersion int64
	AuditRequestID  string
}

// ClaimedRequest 是发起端查询/领取/取消/重新生成的输入：必须同时持有请求标识与
// 领取绑定；ClaimSecret 绝不放进二维码或 URL。
type ClaimedRequest struct {
	ClaimSecret    ClaimSecret
	RequestID      string
	AuditRequestID string
}

// StatusResult 是发起端可观察的请求状态（含由有效期派生的 expired）。
type StatusResult struct {
	Status            string
	ExpiresAt         time.Time
	Version           int64
	RetryAfterSeconds int
}

// Begin 创建一次短时扫码登录请求。功能关闭/应用未列入白名单/应用停用/参数非法/
// 限流超限均拒绝；成功在审计事务内创建 pending 记录并返回一次性领取绑定。
func (s *Service) Begin(ctx context.Context, request BeginRequest) (BeginResult, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return BeginResult{}, err
	}
	if !app.ValidApplicationID(request.ClientID) {
		return BeginResult{}, fmt.Errorf("%w: 应用标识非法", ErrInvalidRequest)
	}
	if err := validateAuditRequestID(request.RequestID); err != nil {
		return BeginResult{}, err
	}
	if err := s.requireEnabled(request.ClientID); err != nil {
		s.failure(ctx, s.systemActor(), "app_qr_login.request_denied", request.ClientID,
			"disabled_or_client_not_allowed", string(CodeAccessDenied), request.RequestID)
		return BeginResult{}, err
	}
	client, err := s.loadEligibleClient(ctx, request.ClientID)
	if err != nil {
		s.failure(ctx, s.systemActor(), "app_qr_login.request_denied", request.ClientID,
			"client_unavailable", string(CodeOf(err)), request.RequestID)
		return BeginResult{}, err
	}
	scopes, err := normalizeScopes(request.Scopes, client.Scopes)
	if err != nil {
		return BeginResult{}, err
	}
	requester := sanitizeRequester(request.Requester)
	if decision := s.createLimiter.Allow("client:" + client.ClientID); !decision.Allowed {
		s.failure(ctx, s.systemActor(), "app_qr_login.request_denied", client.ClientID,
			"create_rate_limited", string(CodeRateLimited), request.RequestID)
		return BeginResult{}, ErrRateLimited
	}
	requestID, err := newRequestID(s.random)
	if err != nil {
		return BeginResult{}, err
	}
	claimSecret, err := newClaimSecret(s.random)
	if err != nil {
		return BeginResult{}, err
	}
	keyID := s.opts.Keyring.CurrentKeyID()
	digest, err := s.claimDigest(keyID, requestID, claimSecret.Reveal())
	if err != nil {
		return BeginResult{}, ErrStoreUnavailable
	}
	now := s.now()
	record := RequestRecord{
		ID: requestID, ClaimDigest: digest, ClaimKeyID: keyID,
		ClientID: client.ClientID, Scopes: scopes, RequestVersion: 1,
		Status: StatusPending, RequesterUserAgent: requester.UserAgent,
		RequesterAddress: requester.Address, RequestID: request.RequestID,
		IntervalSeconds: int(s.claimInterval / time.Second),
		CreatedAt:       now, ExpiresAt: now.Add(s.requestTTL),
	}
	if record.IntervalSeconds < 1 {
		record.IntervalSeconds = 1
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: s.systemActor(), Action: "app_qr_login.request_created",
			AppID:     client.ClientID,
			Target:    audit.Target{Type: "app_qr_login_request", ID: requestID},
			RequestID: request.RequestID,
			Changes: []audit.FieldChange{
				{Field: "client_id", After: client.ClientID},
				{Field: "scope", After: strings.Join(scopes, " ")},
				{Field: "expires_at", After: record.ExpiresAt.UTC().Format(time.RFC3339)},
			},
		},
		FailureReasonCode: "app_qr_login.request_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(s.mapCriticalError(err)))
		},
	}
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.opts.Store.CreateTx(txCtx, tx, record)
	}); err != nil {
		return BeginResult{}, s.mapCriticalError(err)
	}
	payload, err := EncodeQRPayload(requestID)
	if err != nil {
		return BeginResult{}, err
	}
	return BeginResult{
		RequestID: requestID, ClaimSecret: claimSecret, QRPayload: payload,
		ExpiresAt: record.ExpiresAt, Version: record.RequestVersion,
		PollIntervalSeconds: record.IntervalSeconds,
	}, nil
}

// Describe 用真实完整普通会话读取待确认请求，返回确认页所需的可信上下文。
// 不存在/已决定/过期统一 ErrRequestNotFound，避免任意登录用户探测他人的请求状态。
func (s *Service) Describe(ctx context.Context, request PromptRequest) (Prompt, error) {
	ctx = normalizeContext(ctx)
	userSession, err := s.validateConfirmSession(ctx, request.SessionSecret, request.AuditRequestID)
	if err != nil {
		return Prompt{}, err
	}
	record, err := s.loadRequest(ctx, request.RequestID)
	if err != nil {
		return Prompt{}, err
	}
	if err := s.requireEnabled(record.ClientID); err != nil {
		return Prompt{}, err
	}
	if record.Status != StatusPending || record.ExpiredAt(s.now()) {
		s.failure(ctx, sessionActor(userSession.UserID), "app_qr_login.describe_denied",
			record.ClientID, "not_pending", string(CodeChallengeInvalid), request.AuditRequestID)
		return Prompt{}, ErrRequestNotFound
	}
	if err := s.checkConfirmSessionScope(userSession, record.ClientID); err != nil {
		return Prompt{}, err
	}
	client, err := s.loadEligibleClient(ctx, record.ClientID)
	if err != nil {
		return Prompt{}, err
	}
	application, err := s.opts.Applications.GetApplication(ctx, record.ClientID)
	if err != nil {
		if errors.Is(err, app.ErrApplicationNotFound) {
			return Prompt{}, ErrClientUnavailable
		}
		return Prompt{}, ErrStoreUnavailable
	}
	prompt := s.promptOf(record, client, application.Name, userSession)
	event := audit.Event{
		Actor: sessionActor(userSession.UserID), Action: "app_qr_login.described",
		AppID: record.ClientID, Target: audit.Target{Type: "app_qr_login_request", ID: record.ID},
		RequestID: request.AuditRequestID, Outcome: audit.OutcomeSuccess,
	}
	if err := s.opts.Audit.Record(ctx, event); err != nil {
		s.logger.Warn("扫码登录查询成功审计写入失败", "error_category", "audit_unavailable")
	}
	return prompt, nil
}

// Approve 让用户在 APP 上显式批准一次扫码登录请求。必须真实完整会话 + 敏感策略
// 近期认证；批准在审计事务内条件更新并绑定用户/会话/安全版本/认证方法快照，
// 并发批准只有一方成功。
func (s *Service) Approve(ctx context.Context, request DecideRequest) (Prompt, error) {
	ctx = normalizeContext(ctx)
	userSession, err := s.validateConfirmSession(ctx, request.SessionSecret, request.AuditRequestID)
	if err != nil {
		return Prompt{}, err
	}
	record, err := s.loadRequest(ctx, request.RequestID)
	if err != nil {
		return Prompt{}, err
	}
	if err := s.requireEnabled(record.ClientID); err != nil {
		return Prompt{}, err
	}
	if record.VersionMismatch(request.ExpectedVersion) {
		s.failure(ctx, sessionActor(userSession.UserID), "app_qr_login.approve_denied",
			record.ClientID, "version_conflict", string(CodeConflict), request.AuditRequestID)
		return Prompt{}, ErrVersionConflict
	}
	if record.Status != StatusPending {
		s.failure(ctx, sessionActor(userSession.UserID), "app_qr_login.approve_denied",
			record.ClientID, "not_pending", string(CodeChallengeInvalid), request.AuditRequestID)
		return Prompt{}, ErrRequestNotFound
	}
	if record.ExpiredAt(s.now()) {
		s.failure(ctx, sessionActor(userSession.UserID), "app_qr_login.approve_denied",
			record.ClientID, "expired", string(CodeChallengeInvalid), request.AuditRequestID)
		return Prompt{}, ErrRequestExpired
	}
	if err := s.checkConfirmSessionScope(userSession, record.ClientID); err != nil {
		return Prompt{}, err
	}
	client, err := s.loadEligibleClient(ctx, record.ClientID)
	if err != nil {
		return Prompt{}, err
	}
	reauthResult, err := s.authorizeApproval(ctx, userSession, record, request.AuditRequestID)
	if err != nil {
		return Prompt{}, err
	}
	now := s.now()
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: sessionActor(userSession.UserID), Action: "app_qr_login.approved",
			AppID:     record.ClientID,
			Target:    audit.Target{Type: "app_qr_login_request", ID: record.ID},
			RequestID: request.AuditRequestID,
			Changes: []audit.FieldChange{
				{Field: "client_id", After: record.ClientID},
				{Field: "user_id", After: userSession.UserID},
				{Field: "request_version", After: fmt.Sprint(record.RequestVersion)},
			},
		},
		FailureReasonCode: "app_qr_login.approve_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(s.mapCriticalError(err)))
		},
	}
	updated := false
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, updateErr := s.opts.Store.ApproveTx(txCtx, tx, ApprovalDecision{
			ID: record.ID, ExpectedVersion: record.RequestVersion,
			UserID: userSession.UserID, SessionID: userSession.ID,
			SecurityVersion: userSession.SecurityVersion,
			AuthMethods:     userSession.AuthMethods, Now: now,
		})
		if updateErr != nil {
			return updateErr
		}
		updated = ok
		if !ok {
			return ErrVersionConflict
		}
		return nil
	}); err != nil {
		return Prompt{}, s.mapCriticalError(err)
	}
	if !updated {
		return Prompt{}, ErrVersionConflict
	}
	if reauthResult.OperationID != "" {
		if notifyErr := s.notifyReauth(ctx, reauthResult); notifyErr != nil {
			s.logger.Warn("扫码登录批准安全告知失败", "error_category", "notify_unavailable")
		}
	}
	record.Status = StatusApproved
	record.UserID = userSession.UserID
	record.SessionID = userSession.ID
	record.SecurityVersion = userSession.SecurityVersion
	return s.promptOf(record, client, "", userSession), nil
}

// Deny 让用户明确拒绝一次扫码登录请求（不需要再次认证，拒绝不改变其他安全状态）。
func (s *Service) Deny(ctx context.Context, request DecideRequest) (Prompt, error) {
	ctx = normalizeContext(ctx)
	userSession, err := s.validateConfirmSession(ctx, request.SessionSecret, request.AuditRequestID)
	if err != nil {
		return Prompt{}, err
	}
	record, err := s.loadRequest(ctx, request.RequestID)
	if err != nil {
		return Prompt{}, err
	}
	if err := s.requireEnabled(record.ClientID); err != nil {
		return Prompt{}, err
	}
	if record.VersionMismatch(request.ExpectedVersion) {
		return Prompt{}, ErrVersionConflict
	}
	if record.Status != StatusPending || record.ExpiredAt(s.now()) {
		return Prompt{}, ErrRequestNotFound
	}
	if err := s.checkConfirmSessionScope(userSession, record.ClientID); err != nil {
		return Prompt{}, err
	}
	client, err := s.loadEligibleClient(ctx, record.ClientID)
	if err != nil {
		return Prompt{}, err
	}
	now := s.now()
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: sessionActor(userSession.UserID), Action: "app_qr_login.denied",
			AppID:     record.ClientID,
			Target:    audit.Target{Type: "app_qr_login_request", ID: record.ID},
			RequestID: request.AuditRequestID,
			Changes:   []audit.FieldChange{{Field: "reason", After: "user_denied"}},
		},
		FailureReasonCode: "app_qr_login.deny_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(s.mapCriticalError(err)))
		},
	}
	updated := false
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, updateErr := s.opts.Store.DenyTx(txCtx, tx, record.ID, record.RequestVersion,
			userSession.UserID, now)
		if updateErr != nil {
			return updateErr
		}
		updated = ok
		if !ok {
			return ErrVersionConflict
		}
		return nil
	}); err != nil {
		return Prompt{}, s.mapCriticalError(err)
	}
	if !updated {
		return Prompt{}, ErrVersionConflict
	}
	record.Status = StatusDenied
	return s.promptOf(record, client, "", userSession), nil
}

// Status 用领取绑定查询请求状态（发起端轮询用）。服务端强制最小查询间隔；
// 不存在的凭据统一 ErrRequestNotFound，不泄露请求状态。
func (s *Service) Status(ctx context.Context, request ClaimedRequest) (StatusResult, error) {
	ctx = normalizeContext(ctx)
	record, err := s.lookupClaimed(ctx, request)
	if err != nil {
		return StatusResult{}, err
	}
	now := s.now()
	interval := time.Duration(record.IntervalSeconds) * time.Second
	if !record.LastPolledAt.IsZero() && now.Before(record.LastPolledAt.Add(interval)) {
		s.failure(ctx, s.systemActor(), "app_qr_login.status_denied", record.ClientID,
			"poll_interval", string(CodeRateLimited), request.AuditRequestID)
		return StatusResult{}, ErrRateLimited
	}
	// 记录查询时间（终态/过期记录不会被更新，但状态仍要如实返回）。
	if _, pollErr := s.opts.Store.TouchPoll(ctx, record.ID, now); pollErr != nil {
		return StatusResult{}, pollErr
	}
	status := record.Status
	if status == StatusPending || status == StatusApproved {
		if record.ExpiredAt(now) {
			status = QueryExpired
		}
	}
	return StatusResult{
		Status: status, ExpiresAt: record.ExpiresAt, Version: record.RequestVersion,
		RetryAfterSeconds: record.IntervalSeconds,
	}, nil
}

// Claim 领取登录结果：只有已批准、未过期、未被领取且持有正确领取绑定的发起端能
// 领取；领取时重新核对账户/成员/应用/客户端/确认端会话与请求状态。成功领取在
// 门控中原子消费批准（并发单赢家），再通过 internal/session 的受门控登录批准
// 签发**目标应用会话**（不签发任何 Token）。
func (s *Service) Claim(ctx context.Context, request ClaimedRequest) (session.IssuedSession, error) {
	ctx = normalizeContext(ctx)
	if err := s.requireEnabled(""); err != nil {
		return session.IssuedSession{}, err
	}
	record, err := s.lookupClaimed(ctx, request)
	if err != nil {
		return session.IssuedSession{}, err
	}
	now := s.now()
	switch record.Status {
	case StatusClaimed:
		return session.IssuedSession{}, ErrAlreadyClaimed
	case StatusDenied:
		return session.IssuedSession{}, ErrRequestDenied
	case StatusCancelled:
		return session.IssuedSession{}, ErrRequestCancelled
	case StatusPending:
		if record.ExpiredAt(now) {
			return session.IssuedSession{}, ErrRequestExpired
		}
		return session.IssuedSession{}, ErrRequestNotApproved
	case StatusApproved:
		if record.ExpiredAt(now) {
			return session.IssuedSession{}, ErrRequestExpired
		}
	default:
		return session.IssuedSession{}, ErrRequestNotFound
	}
	if err := s.requireEnabled(record.ClientID); err != nil {
		return session.IssuedSession{}, err
	}
	client, err := s.loadEligibleClient(ctx, record.ClientID)
	if err != nil {
		return session.IssuedSession{}, err
	}
	// 领取前复核确认端会话仍有效（撤销/过期/账户/应用/成员变化即拒绝）。
	if err := s.opts.Sessions.VerifyActiveSession(ctx, record.UserID, record.SessionID); err != nil {
		if errors.Is(err, session.ErrSessionInvalid) {
			s.failure(ctx, s.systemActor(), "app_qr_login.claim_denied", record.ClientID,
				"confirm_session_invalid", string(CodeAuthFailed), request.AuditRequestID)
			return session.IssuedSession{}, ErrSessionInvalid
		}
		return session.IssuedSession{}, ErrStoreUnavailable
	}
	methods, err := parseAuthMethods(record.AuthMethods)
	if err != nil {
		return session.IssuedSession{}, err
	}
	grant := session.LoginGrantRequest{
		GrantID: record.ID, UserID: record.UserID, SecurityVersion: record.SecurityVersion,
		AppID: record.ClientID, AuthMethods: methods, RequestID: request.AuditRequestID,
		Client: session.ClientInfo{
			UserAgent: record.RequesterUserAgent, Address: record.RequesterAddress,
		},
	}
	issued, err := s.opts.SessionIssuer.IssueLoginGrantSession(
		withClaimAuthorization(ctx, record.ID), grant, s)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return session.IssuedSession{}, ctxErr
		}
		mapped := mapSessionError(err)
		s.failure(ctx, s.systemActor(), "app_qr_login.claim_failed", record.ClientID,
			"session_issue_failed", string(CodeOf(mapped)), request.AuditRequestID)
		return session.IssuedSession{}, mapped
	}
	if ok, setErr := s.opts.Store.SetClaimedSession(ctx, record.ID, issued.Session.ID); setErr != nil || !ok {
		s.logger.Warn("领取成功后回写会话 ID 失败", "request_id", record.ID,
			"error_category", "store_unavailable")
	}
	s.logger.Info("扫码登录会话已签发", "request_id", record.ID,
		"client_id", client.ClientID, "user_id", record.UserID, "session_id", issued.Session.ID)
	return issued, nil
}

// Cancel 让发起端取消请求（需领取绑定）。pending/approved 可取消；已取消幂等
// 返回 cancelled；已领取/已拒绝/已过期按对应状态拒绝。
func (s *Service) Cancel(ctx context.Context, request ClaimedRequest) (StatusResult, error) {
	ctx = normalizeContext(ctx)
	record, err := s.lookupClaimed(ctx, request)
	if err != nil {
		return StatusResult{}, err
	}
	now := s.now()
	switch record.Status {
	case StatusCancelled:
		return StatusResult{Status: QueryCancelled, ExpiresAt: record.ExpiresAt,
			Version: record.RequestVersion}, nil
	case StatusClaimed:
		return StatusResult{}, ErrAlreadyClaimed
	case StatusDenied:
		return StatusResult{}, ErrRequestDenied
	}
	if record.ExpiredAt(now) {
		return StatusResult{}, ErrRequestExpired
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: s.systemActor(), Action: "app_qr_login.cancelled",
			AppID:     record.ClientID,
			Target:    audit.Target{Type: "app_qr_login_request", ID: record.ID},
			RequestID: request.AuditRequestID,
			Changes:   []audit.FieldChange{{Field: "reason", After: "initiator_cancelled"}},
		},
		FailureReasonCode: "app_qr_login.cancel_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(s.mapCriticalError(err)))
		},
	}
	updated := false
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, updateErr := s.opts.Store.CancelTx(txCtx, tx, record.ID, record.RequestVersion, now)
		if updateErr != nil {
			return updateErr
		}
		updated = ok
		if !ok {
			return ErrVersionConflict
		}
		return nil
	}); err != nil {
		return StatusResult{}, s.mapCriticalError(err)
	}
	if !updated {
		return StatusResult{}, ErrVersionConflict
	}
	return StatusResult{Status: QueryCancelled, ExpiresAt: record.ExpiresAt,
		Version: record.RequestVersion}, nil
}

// Regenerate 让发起端重新生成二维码：同一审计事务内取消旧请求并创建新请求
// （新请求标识 + 新领取绑定）；旧二维码/旧领取绑定随即失效。
func (s *Service) Regenerate(ctx context.Context, request ClaimedRequest) (BeginResult, error) {
	ctx = normalizeContext(ctx)
	record, err := s.lookupClaimed(ctx, request)
	if err != nil {
		return BeginResult{}, err
	}
	now := s.now()
	if record.Status == StatusClaimed {
		return BeginResult{}, ErrAlreadyClaimed
	}
	if record.Status == StatusDenied {
		return BeginResult{}, ErrRequestDenied
	}
	if record.ExpiredAt(now) {
		return BeginResult{}, ErrRequestExpired
	}
	if err := s.requireEnabled(record.ClientID); err != nil {
		return BeginResult{}, err
	}
	client, err := s.loadEligibleClient(ctx, record.ClientID)
	if err != nil {
		return BeginResult{}, err
	}
	if decision := s.createLimiter.Allow("client:" + client.ClientID); !decision.Allowed {
		return BeginResult{}, ErrRateLimited
	}
	newID, err := newRequestID(s.random)
	if err != nil {
		return BeginResult{}, err
	}
	claimSecret, err := newClaimSecret(s.random)
	if err != nil {
		return BeginResult{}, err
	}
	keyID := s.opts.Keyring.CurrentKeyID()
	digest, err := s.claimDigest(keyID, newID, claimSecret.Reveal())
	if err != nil {
		return BeginResult{}, ErrStoreUnavailable
	}
	newRecord := RequestRecord{
		ID: newID, ClaimDigest: digest, ClaimKeyID: keyID,
		ClientID: client.ClientID, Scopes: append([]string(nil), record.Scopes...),
		RequestVersion: 1, Status: StatusPending,
		RequesterUserAgent: record.RequesterUserAgent, RequesterAddress: record.RequesterAddress,
		RequestID:       request.AuditRequestID,
		IntervalSeconds: record.IntervalSeconds,
		CreatedAt:       now, ExpiresAt: now.Add(s.requestTTL),
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: s.systemActor(), Action: "app_qr_login.regenerated",
			AppID:     record.ClientID,
			Target:    audit.Target{Type: "app_qr_login_request", ID: record.ID},
			RequestID: request.AuditRequestID,
			Changes: []audit.FieldChange{
				{Field: "old_request", After: record.ID},
				{Field: "new_request", After: newID},
				{Field: "expires_at", After: newRecord.ExpiresAt.UTC().Format(time.RFC3339)},
			},
		},
		FailureReasonCode: "app_qr_login.regenerate_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(s.mapCriticalError(err)))
		},
	}
	updated := false
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, updateErr := s.opts.Store.RegenerateTx(txCtx, tx, record.ID, record.RequestVersion,
			now, newRecord)
		if updateErr != nil {
			return updateErr
		}
		updated = ok
		if !ok {
			return ErrVersionConflict
		}
		return nil
	}); err != nil {
		return BeginResult{}, s.mapCriticalError(err)
	}
	if !updated {
		return BeginResult{}, ErrVersionConflict
	}
	payload, err := EncodeQRPayload(newID)
	if err != nil {
		return BeginResult{}, err
	}
	return BeginResult{
		RequestID: newID, ClaimSecret: claimSecret, QRPayload: payload,
		ExpiresAt: newRecord.ExpiresAt, Version: newRecord.RequestVersion,
		PollIntervalSeconds: newRecord.IntervalSeconds,
	}, nil
}

// AuthorizeLoginGrant 实现 session.LoginGrantGate：领取阶段由 internal/session 在
// 签发会话前调用。它原子消费批准记录（approved→claimed），并重新核对批准事实、
// 客户端状态、确认端会话与调用链授权标记；失败返回错误（session 会拒绝签发）。
func (s *Service) AuthorizeLoginGrant(ctx context.Context, request session.LoginGrantRequest) error {
	ctx = normalizeContext(ctx)
	if !claimAuthorizedFromContext(ctx, request.GrantID) {
		s.logger.Warn("登录批准门控缺少领取调用链标记", "request_id", request.GrantID)
		return session.ErrLoginGrantDenied
	}
	record, err := s.loadRequest(ctx, request.GrantID)
	if err != nil {
		return session.ErrLoginGrantDenied
	}
	if record.Status != StatusApproved || record.ExpiredAt(s.now()) {
		return session.ErrLoginGrantDenied
	}
	if record.UserID != request.UserID || record.SecurityVersion != request.SecurityVersion ||
		record.ClientID != request.AppID || record.SessionID == "" {
		return session.ErrLoginGrantDenied
	}
	if !sameAuthMethods(record.AuthMethods, request.AuthMethods) {
		s.logger.Warn("登录批准认证方法快照不一致", "request_id", record.ID)
		return session.ErrLoginGrantDenied
	}
	if err := s.requireEnabled(record.ClientID); err != nil {
		return session.ErrLoginGrantDenied
	}
	if _, err := s.loadEligibleClient(ctx, record.ClientID); err != nil {
		return session.ErrLoginGrantDenied
	}
	if err := s.opts.Sessions.VerifyActiveSession(ctx, record.UserID, record.SessionID); err != nil {
		return session.ErrLoginGrantDenied
	}
	now := s.now()
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: sessionActor(record.UserID), Action: "app_qr_login.claimed",
			AppID:  record.ClientID,
			Target: audit.Target{Type: "app_qr_login_request", ID: record.ID},
			Changes: []audit.FieldChange{
				{Field: "client_id", After: record.ClientID},
				{Field: "user_id", After: record.UserID},
			},
		},
		FailureReasonCode: "app_qr_login.claim_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(s.mapCriticalError(err)))
		},
	}
	consumed := false
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, updateErr := s.opts.Store.ConsumeTx(txCtx, tx, record.ID, record.RequestVersion, now)
		if updateErr != nil {
			return updateErr
		}
		consumed = ok
		if !ok {
			return ErrAlreadyClaimed
		}
		return nil
	}); err != nil {
		return session.ErrLoginGrantDenied
	}
	if !consumed {
		return session.ErrLoginGrantDenied
	}
	return nil
}

// sameAuthMethods 比较持久化认证方法快照与领取请求携带的方法集合（顺序无关）。
func sameAuthMethods(stored []string, requested []authn.Method) bool {
	if len(stored) != len(requested) {
		return false
	}
	set := make(map[string]struct{}, len(stored))
	for _, method := range stored {
		set[method] = struct{}{}
	}
	for _, method := range requested {
		if _, ok := set[string(method)]; !ok {
			return false
		}
	}
	return true
}

// VersionMismatch 报告期望版本与记录版本是否不一致。
func (r RequestRecord) VersionMismatch(expected int64) bool {
	return expected != r.RequestVersion
}

// validateConfirmSession 校验确认端会话为真实完整普通会话，并执行确认限流。
func (s *Service) validateConfirmSession(ctx context.Context, secret, auditRequestID string) (session.Session, error) {
	if err := validateAuditRequestID(auditRequestID); err != nil {
		return session.Session{}, err
	}
	userSession, err := s.opts.Sessions.Validate(ctx, secret)
	if err != nil || !userSession.IsNormal() || userSession.UserID == "" {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "app_qr_login.confirm_denied",
			"", "session_invalid", string(CodeAuthFailed), auditRequestID)
		return session.Session{}, ErrSessionInvalid
	}
	if decision := s.confirmLimiter.Allow("user:" + userSession.UserID); !decision.Allowed {
		s.failure(ctx, sessionActor(userSession.UserID), "app_qr_login.confirm_denied",
			"", "confirm_rate_limited", string(CodeRateLimited), auditRequestID)
		return session.Session{}, ErrRateLimited
	}
	return userSession, nil
}

// checkConfirmSessionScope 校验应用作用域会话只能确认本应用请求。
func (s *Service) checkConfirmSessionScope(userSession session.Session, clientID string) error {
	if userSession.AppID != "" && userSession.AppID != clientID {
		return ErrAccessDenied
	}
	return nil
}

// authorizeApproval 按步骤 39 敏感策略要求近期认证；未接线 fail-closed。
// 参数绑定客户端、scope、请求版本与请求 ID，换目标/参数即失效。
func (s *Service) authorizeApproval(ctx context.Context, userSession session.Session,
	record RequestRecord, auditRequestID string) (reauth.Result, error) {
	if isNilInterface(s.opts.Reauth) {
		s.failure(ctx, sessionActor(userSession.UserID), "app_qr_login.approve_denied",
			record.ClientID, "reauth_not_configured", string(CodeAccessDenied), auditRequestID)
		return reauth.Result{}, ErrAccessDenied
	}
	caller, err := reauthUserCaller(userSession.UserID)
	if err != nil {
		return reauth.Result{}, ErrAccessDenied
	}
	params := map[string]string{
		"client_id": record.ClientID,
		"scope":     strings.Join(record.Scopes, " "),
		"request":   record.ID,
		"version":   fmt.Sprint(record.RequestVersion),
	}
	result, err := s.opts.Reauth.Authorize(ctx, caller, reauth.Request{
		ScopeID: "system", OperationID: operationApprove,
		TargetType: "application", TargetID: record.ClientID,
		Params: params, Description: "批准 APP 扫码登录网页请求", RequestID: auditRequestID,
	})
	if err != nil {
		s.failure(ctx, sessionActor(userSession.UserID), "app_qr_login.approve_denied",
			record.ClientID, "reauth_required", string(CodeAccessDenied), auditRequestID)
		return reauth.Result{}, ErrAccessDenied
	}
	return result, nil
}

// notifyReauth 在批准成功后发送安全告知（失败只记日志，不回滚已完成的批准）。
func (s *Service) notifyReauth(ctx context.Context, result reauth.Result) error {
	if isNilInterface(s.opts.Reauth) || result.OperationID == "" {
		return nil
	}
	return s.opts.Reauth.NotifyOutcome(ctx, result, reauth.OutcomeSuccess)
}

// loadRequest 校验请求标识并读取记录。
func (s *Service) loadRequest(ctx context.Context, requestID string) (RequestRecord, error) {
	if !validRequestID(requestID) {
		return RequestRecord{}, ErrRequestNotFound
	}
	record, found, err := s.opts.Store.GetRequest(ctx, requestID)
	if err != nil {
		return RequestRecord{}, err
	}
	if !found {
		return RequestRecord{}, ErrRequestNotFound
	}
	return record, nil
}

// lookupClaimed 校验领取绑定并读取记录：遍历密钥环中的 key_id 计算 HMAC 摘要
// 查询（支持密钥轮换后仍能核对历史记录）；找不到/格式非法统一 ErrRequestNotFound。
// 若携带的请求标识与摘要对应记录不一致，同样按不存在处理（不泄露信息）。
func (s *Service) lookupClaimed(ctx context.Context, request ClaimedRequest) (RequestRecord, error) {
	secret, err := normalizeClaimSecret(request.ClaimSecret)
	if err != nil {
		return RequestRecord{}, ErrRequestNotFound
	}
	if request.RequestID != "" && !validRequestID(request.RequestID) {
		return RequestRecord{}, ErrRequestNotFound
	}
	for _, keyID := range s.opts.Keyring.KeyIDs() {
		digest, digestErr := s.claimDigest(keyID, request.RequestID, secret)
		if digestErr != nil {
			continue
		}
		record, found, getErr := s.opts.Store.GetByClaimDigest(ctx, digest)
		if getErr != nil {
			return RequestRecord{}, getErr
		}
		if !found {
			continue
		}
		if request.RequestID != "" && subtle.ConstantTimeCompare(
			[]byte(record.ID), []byte(request.RequestID)) != 1 {
			return RequestRecord{}, ErrRequestNotFound
		}
		return record, nil
	}
	return RequestRecord{}, ErrRequestNotFound
}

// claimDigest 计算领取绑定 HMAC 摘要：消息绑定请求标识与秘密，避免同一秘密被
// 用于其它请求。
func (s *Service) claimDigest(keyID, requestID, secret string) ([32]byte, error) {
	var digest [32]byte
	message := []byte(requestID + "." + secret)
	sum, err := s.opts.Keyring.HMACDigest(keyID, claimDigestDomain, message)
	if err != nil || len(sum) != len(digest) {
		return digest, ErrStoreUnavailable
	}
	copy(digest[:], sum)
	return digest, nil
}

// requireEnabled 校验全局开关与应用白名单（clientID 为空只校验全局开关）。
func (s *Service) requireEnabled(clientID string) error {
	if !s.opts.Enabled {
		return ErrQRLoginDisabled
	}
	if clientID == "" {
		return nil
	}
	if _, allowed := s.allowedClients[clientID]; !allowed {
		return ErrQRLoginDisabled
	}
	return nil
}

// loadEligibleClient 读取客户端登记并确认所属应用启用（不存在/停用拒绝）。
func (s *Service) loadEligibleClient(ctx context.Context, clientID string) (oauthclient.ClientRecord, error) {
	if !app.ValidApplicationID(clientID) {
		return oauthclient.ClientRecord{}, ErrInvalidRequest
	}
	client, found, err := s.opts.Clients.GetClient(ctx, clientID)
	if err != nil {
		return oauthclient.ClientRecord{}, ErrStoreUnavailable
	}
	if !found {
		return oauthclient.ClientRecord{}, ErrClientUnavailable
	}
	if client.AppStatus != "active" {
		return oauthclient.ClientRecord{}, ErrClientUnavailable
	}
	return client, nil
}

// promptOf 构造确认页展示上下文。
func (s *Service) promptOf(record RequestRecord, client oauthclient.ClientRecord,
	applicationName string, userSession session.Session) Prompt {
	if applicationName == "" {
		applicationName = record.ClientID
	}
	return Prompt{
		RequestID: record.ID, ClientID: record.ClientID, ApplicationName: applicationName,
		ClientType: string(client.ClientType), Status: record.Status,
		Scopes: append([]string(nil), record.Scopes...),
		Requester: RequesterInfo{UserAgent: record.RequesterUserAgent,
			Address: record.RequesterAddress},
		CreatedAt: record.CreatedAt, ExpiresAt: record.ExpiresAt,
		Version: record.RequestVersion, Warning: confirmationWarning,
	}
}

// systemActor 返回系统审计主体。
func (s *Service) systemActor() audit.Actor {
	return audit.Actor{Type: audit.ActorSystem, ID: serviceComponentID}
}

// sessionActor 返回用户审计主体。
func sessionActor(userID string) audit.Actor {
	return audit.Actor{Type: audit.ActorUser, ID: userID}
}

// failure 写失败审计；审计失败只记运行日志，不改变拒绝结论。
func (s *Service) failure(ctx context.Context, actor audit.Actor, action, appID, reason,
	errorCode, requestID string) {
	event := audit.Event{
		Actor: actor, AppID: appID, Action: action,
		Target:  audit.Target{Type: "app_qr_login_request", ID: ""},
		Outcome: audit.OutcomeFailure, ErrorCode: errorCode, ReasonCode: reason,
		RequestID: requestID,
	}
	if err := s.opts.Audit.RecordFailure(ctx, event); err != nil {
		s.logger.Warn("扫码登录失败审计写入失败", "action", action,
			"error_category", "audit_unavailable")
	}
}

// mapCriticalError 把审计事务错误映射为稳定领域错误。
func (s *Service) mapCriticalError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrAuditUnavailable), errors.Is(err, audit.ErrAuditUnavailable):
		return ErrAuditUnavailable
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrVersionConflict),
		errors.Is(err, ErrAlreadyClaimed):
		return err
	default:
		return ErrStoreUnavailable
	}
}

// mapSessionError 把 internal/session 登录批准签发错误映射为本包稳定错误。
func mapSessionError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, session.ErrLoginGrantDenied):
		return ErrRequestNotApproved
	case errors.Is(err, session.ErrAccountNotEligible):
		return ErrAccessDenied
	case errors.Is(err, session.ErrInvalidRequest):
		return ErrInvalidRequest
	case errors.Is(err, session.ErrStoreUnavailable):
		return ErrStoreUnavailable
	case errors.Is(err, session.ErrAuditUnavailable):
		return ErrAuditUnavailable
	default:
		return ErrAccessDenied
	}
}

// allowedClientsMap 把白名单转换为集合。
func allowedClientsMap(clientIDs []string) map[string]struct{} {
	result := make(map[string]struct{}, len(clientIDs))
	for _, clientID := range clientIDs {
		result[clientID] = struct{}{}
	}
	return result
}

// claimAuthorizationKey 是领取调用链授权标记在 context 中的键。
type claimAuthorizationKey struct{}

// withClaimAuthorization 在调用 session 登录批准签发前写入本次领取的请求标识，
// 供门控确认“本次批准消费来自已通过领取绑定校验的调用链”。
func withClaimAuthorization(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, claimAuthorizationKey{}, requestID)
}

// claimAuthorizedFromContext 校验调用链授权标记与批准标识一致。
func claimAuthorizedFromContext(ctx context.Context, requestID string) bool {
	value, ok := ctx.Value(claimAuthorizationKey{}).(string)
	return ok && value != "" && value == requestID
}

// randReader 返回 crypto/rand.Reader（测试可注入 Options.Random）。
func randReader() io.Reader { return rand.Reader }

// reauthUserCaller 构造再次认证的用户调用者。
func reauthUserCaller(userID string) (reauth.Caller, error) {
	return reauth.UserCaller(userID)
}

// isNilInterface 检测 nil 接口与 typed-nil 指针。
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
