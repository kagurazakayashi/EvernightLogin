package oauthflow

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/token"
)

// 本文件实现步骤 57 的 OAuth 2.0 Device Authorization Grant（RFC 8628）：
// 设备申请设备码与人工短码 → 用户在另一台设备用真实完整会话核对短码并批准/拒绝
// → 原设备轮询 Token 端点领取令牌。
//
// 安全不变量：
//   - 高熵 device_code 只保存无密钥 SHA-256 摘要；低熵人工 user_code 按 AGENTS §10
//     只保存**带密钥 HMAC-SHA256 摘要**（宿主 secrets.Keyring 派生）并随行记录
//     user_code_key_id（支持密钥环轮换），绝不以无密钥摘要落库；密钥环缺失/不可用
//     时 fail-closed（拒绝构造或申请）。两类明文都只在申请响应出现一次；
//     二维码/验证链接只承载短码，永远不承载令牌或长期秘密。
//   - 用户查询/批准必须来自真实完整普通会话（internal/session 校验），不接受任何
//     客户端自报用户；批准按 internal/reauth 敏感策略要求近期认证，失败 fail-closed。
//   - 批准绑定 user+session+security_version+client+scope+audience 快照；领取前重新
//     核对用户、成员、客户端、会话与登记范围，任一变化都不签发令牌。
//   - 设备码与 client_id 绑定：换客户端提交按 invalid_grant 拒绝；保密客户端在申请
//     与轮询两端都必须完成客户端认证，公开客户端不要求也不可能“伪造保密凭证”。
//   - 轮询间隔由服务端持久化强制（slow_down），领取用条件更新保证并发单赢家。
//   - 过期/拒绝/取消/等待都是流程状态，不当成系统故障；安全相关拒绝写失败审计。

// 设备授权协议常量与默认值。
const (
	// DefaultDeviceAuthorizationTTL 是设备码默认有效期（用户确认窗口）。
	DefaultDeviceAuthorizationTTL = 10 * time.Minute
	// MinDeviceAuthorizationTTL/MaxDeviceAuthorizationTTL 是有效期边界。
	MinDeviceAuthorizationTTL = time.Minute
	MaxDeviceAuthorizationTTL = 30 * time.Minute
	// DefaultDevicePollInterval 是默认轮询间隔；RFC 8628 建议 5 秒起。
	DefaultDevicePollInterval = 5 * time.Second
	// MinDevicePollInterval/MaxDevicePollInterval 是轮询间隔边界。
	MinDevicePollInterval = 5 * time.Second
	MaxDevicePollInterval = 60 * time.Second
	// DefaultDeviceUserCodeAttempts/Window 是短码验证失败限流默认值：按用户维度
	// 固定窗口限流，防止在线猜解 20^8 空间。
	DefaultDeviceUserCodeAttempts = 10
	DefaultDeviceUserCodeWindow   = 10 * time.Minute
	// minDeviceUserCodeAttempts/maxDeviceUserCodeAttempts 与窗口边界。
	minDeviceUserCodeAttempts = 3
	maxDeviceUserCodeAttempts = 100
	minDeviceUserCodeWindow   = time.Minute
	maxDeviceUserCodeWindow   = time.Hour
	// 设备码/内部记录编号前缀与随机字节数。
	deviceCodePrefix            = "dc_"
	deviceAuthorizationIDPrefix = "odr_"
	deviceCodeRandomBytes       = 32
	// userCodeLength 是人工短码长度；userCodeAlphabet 是 RFC 8628 推荐的 base20
	// 字符集（去掉易混淆的元音 A/E/I/O/U 与 0/1）。20^8 ≈ 34.6 bit。
	userCodeLength   = 8
	userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"
	// userCodeAlphabetLimit 用于拒绝采样：<200 的随机字节对 20 无取模偏差。
	userCodeAlphabetLimit = 200
	// devicePollIntervalIncrementSeconds/maxDevicePollIntervalSeconds 是 slow_down
	// 时的间隔增量与上限（持久化到请求记录）。
	devicePollIntervalIncrementSeconds = 5
	maxDevicePollIntervalSeconds       = 300
	// maxDeviceCodeInputBytes 是客户端提交设备码的最大长度。
	maxDeviceCodeInputBytes = 512
	// maxUserCodeInputBytes 是用户提交短码的最大长度。
	maxUserCodeInputBytes = 64
	// userCodeDigestDomain 是短码 HMAC 摘要的用途域；与其它摘要用途隔离，避免
	// 低成本重用同一派生密钥。
	userCodeDigestDomain = "oauth.device.user-code-v1"
	// AccessTokenGrantDeviceCode 是 RFC 8628 的设备码授权类型 URN（Token 端点用）。
	AccessTokenGrantDeviceCode = string(oauthclient.GrantDeviceCode)
	// operationDeviceAuthorizationApprove 是步骤 38 敏感操作目录中的设备码批准操作。
	operationDeviceAuthorizationApprove = "oauth.device.authorization.approve"
)

// 设备授权领域错误（宿主据此写失败审计/诊断）。Token 端点协议错误另外使用
// *OAuthError 的标准 error 字段。
var (
	// ErrDeviceAuthorizationInvalid 表示设备授权请求参数无效。
	ErrDeviceAuthorizationInvalid = errors.New("设备授权请求无效")
	// ErrDeviceAuthorizationNotFound 表示设备码/短码不存在或已失效；对外统一，
	// 不区分“不存在”“已决定”“已过期”，避免泄露状态。
	ErrDeviceAuthorizationNotFound = errors.New("设备授权请求不存在或已失效")
	// ErrDeviceAuthorizationAccessDenied 表示当前会话/账户/成员状态不允许完成该
	// 设备授权确认。
	ErrDeviceAuthorizationAccessDenied = errors.New("当前身份不允许完成设备授权确认")
	// ErrDeviceAuthorizationReauthRequired 表示需要近期认证后重新确认。
	ErrDeviceAuthorizationReauthRequired = errors.New("需要重新验证身份后确认设备授权")
	// ErrDeviceAuthorizationRateLimited 表示短码验证尝试过于频繁。
	ErrDeviceAuthorizationRateLimited = errors.New("短码验证尝试过于频繁")
	// ErrDeviceAuthorizationConflict 表示请求已被其他操作决定/领取（并发冲突）。
	ErrDeviceAuthorizationConflict = errors.New("设备授权请求状态已变化")
	// ErrDeviceAuthorizationNotConfigured 表示宿主未配置验证地址，设备码能力不可用；
	// 不假装成功，也不写“已申请”的假记录。
	ErrDeviceAuthorizationNotConfigured = errors.New("设备码验证地址未配置")
	// ErrDeviceUserCodeKeyUnavailable 表示短码 HMAC 密钥环缺失或不可用。低熵短码
	// 不能退化为无密钥摘要，因此缺少密钥时 fail-closed（拒绝，不放行）。
	ErrDeviceUserCodeKeyUnavailable = errors.New("设备短码摘要密钥不可用")
)

// DeviceCode 是设备码明文。String/Format 全部脱敏，宿主返回给发起设备时必须显式
// Reveal()，且不得写入日志、审计或普通存储（数据库只保存摘要）。
type DeviceCode struct{ value string }

// Reveal 返回设备码原文（只用于返回给发起设备）。
func (c DeviceCode) Reveal() string { return c.value }

// IsSet 报告是否已生成设备码；不暴露内容。
func (c DeviceCode) IsSet() bool { return c.value != "" }

// String 实现 fmt.Stringer，固定脱敏。
func (c DeviceCode) String() string {
	if c.value == "" {
		return "[UNSET]"
	}
	return "[REDACTED]"
}

// GoString 实现 fmt.GoStringer。
func (c DeviceCode) GoString() string { return c.String() }

// Format 实现 fmt.Formatter，避免 %v/%s 泄露设备码。
func (c DeviceCode) Format(f fmt.State, _ rune) {
	if c.value == "" {
		_, _ = f.Write([]byte("[UNSET]"))
		return
	}
	_, _ = f.Write([]byte("[REDACTED]"))
}

// UserCode 是可人工输入/显示的短码（含 4-4 连字符显示形式）。它仍是短时凭证，
// String/Format 固定脱敏；宿主显示给用户时显式 Reveal()。
type UserCode struct{ value string }

// Reveal 返回短码显示形式（例如 ABCD-EFGH，只用于显示与二维码链接）。
func (c UserCode) Reveal() string { return c.value }

// IsSet 报告是否已生成短码。
func (c UserCode) IsSet() bool { return c.value != "" }

// String 实现 fmt.Stringer，固定脱敏。
func (c UserCode) String() string {
	if c.value == "" {
		return "[UNSET]"
	}
	return "[REDACTED]"
}

// GoString 实现 fmt.GoStringer。
func (c UserCode) GoString() string { return c.String() }

// Format 实现 fmt.Formatter，避免日志泄露短码。
func (c UserCode) Format(f fmt.State, _ rune) {
	if c.value == "" {
		_, _ = f.Write([]byte("[UNSET]"))
		return
	}
	_, _ = f.Write([]byte("[REDACTED]"))
}

// DeviceAuthorizationRequest 是发起设备授权申请（设备侧）的请求。保密客户端必须
// 提交 client_secret 或客户端证书完成认证；公开客户端不需要也不能靠秘密冒充保密。
type DeviceAuthorizationRequest struct {
	ClientID             string
	ClientSecret         string
	ClientCertificatePEM string
	Scope                []string
	Resource             []string
	// RequestID 是宿主请求编号，只用于审计关联。
	RequestID string
}

// DeviceAuthorizationResponse 是设备授权申请成功响应。DeviceCode/UserCode 均默认
// 脱敏；VerificationURIComplete 是可渲染为二维码的短时验证链接（只含短码，不含
// 令牌），打开它仍需用户登录并显式批准。
type DeviceAuthorizationResponse struct {
	DeviceCode              DeviceCode
	UserCode                UserCode
	VerificationURI         string
	VerificationURIComplete string
	ExpiresIn               int64
	Interval                int64
	RequestID               string
}

// DeviceConsentPrompt 是设备授权确认页所需的可信请求信息（不含任何秘密）。应用
// 展示名称由页面层按受控资料补充，与步骤 51 授权确认页一致。
type DeviceConsentPrompt struct {
	RequestID  string
	ClientID   string
	ClientType oauthclient.ClientType
	Scopes     []string
	Audiences  []string
	ExpiresAt  time.Time
}

// DeviceDecisionRequest 是用户对设备授权请求的决定。UserCode 是用户在页面上输入的
// 短码；服务端重新规范化并定位记录，再次证明持有短码。
type DeviceDecisionRequest struct {
	UserCode  string
	Approve   bool
	RequestID string
}

// DeviceDecisionResult 是确认结果；不包含任何令牌或设备码。
type DeviceDecisionResult struct {
	RequestID string
	ClientID  string
	UserID    string
	Approved  bool
}

// DeviceCancelRequest 是发起设备主动取消等待中的授权请求。必须提交申请时使用的
// 同一 client_id（保密客户端还需客户端认证），防止他人凭泄漏的设备码取消别人的
// 请求之外，也只影响该请求本身。
type DeviceCancelRequest struct {
	DeviceCode           string
	ClientID             string
	ClientSecret         string
	ClientCertificatePEM string
	RequestID            string
}

// ===== 设备码协议错误构造器（标准 OAuth error 字段） =====

// oauthDeviceAuthorizationPending 表示用户尚未完成确认（等待状态，不是故障）。
func oauthDeviceAuthorizationPending() *OAuthError {
	return newOAuthError("authorization_pending", "用户尚未完成设备授权确认", 400)
}

// oauthDeviceSlowDown 表示轮询过快；RetryAfter 供宿主设置 Retry-After 提示。
func oauthDeviceSlowDown(retryAfter time.Duration) *OAuthError {
	err := newOAuthError("slow_down", "轮询过快，请增大轮询间隔", 400)
	err.RetryAfter = retryAfter
	return err
}

// oauthDeviceAccessDenied 表示用户拒绝或发起设备取消。
func oauthDeviceAccessDenied() *OAuthError {
	return newOAuthError("access_denied", "用户拒绝或已取消设备授权", 400)
}

// oauthDeviceExpiredToken 表示设备码已过期。
func oauthDeviceExpiredToken() *OAuthError {
	return newOAuthError("expired_token", "设备码已过期", 400)
}

// ===== 申请 =====

// BeginDeviceAuthorization 校验申请并创建待用户确认的设备授权记录。
//
// 设备码与短码只以摘要落库；返回的明文只出现这一次。公开客户端只需要 client_id，
// 保密客户端必须完成客户端认证（缺失/失败一律 invalid_client）。未配置验证地址时
// fail-closed 返回 temporarily_unavailable，不创建无法确认的请求。
func (s *Service) BeginDeviceAuthorization(ctx context.Context,
	request DeviceAuthorizationRequest) (DeviceAuthorizationResponse, error) {
	ctx = normalizeContext(ctx)
	if err := validRequestID(request.RequestID); err != nil {
		return DeviceAuthorizationResponse{}, fmt.Errorf("%w: 请求编号无效",
			ErrDeviceAuthorizationInvalid)
	}
	if request.ClientID == "" || len(request.ClientID) > 128 {
		return DeviceAuthorizationResponse{}, fmt.Errorf("%w: client_id 无效",
			ErrDeviceAuthorizationInvalid)
	}
	client, found, err := s.opts.Clients.LoadClient(ctx, request.ClientID)
	if err != nil {
		return DeviceAuthorizationResponse{}, oauthTemporarilyUnavailable()
	}
	if !found {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.device.begin_denied",
			request.ClientID, "unknown_client", "CLIENT_AUTH_FAILED", request.RequestID)
		return DeviceAuthorizationResponse{}, oauthInvalidClient()
	}
	if !client.Active() {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.device.begin_denied",
			client.ClientID, "client_disabled", "CLIENT_DISABLED", request.RequestID)
		return DeviceAuthorizationResponse{}, newOAuthError("unauthorized_client",
			"客户端所属应用已停用", 403)
	}
	if !client.GrantsDeviceCode() {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.device.begin_denied",
			client.ClientID, "grant_not_allowed", "CLIENT_AUTH_FAILED", request.RequestID)
		return DeviceAuthorizationResponse{}, oauthUnauthorizedClient()
	}
	if client.ClientType == oauthclient.ClientTypeConfidential {
		if request.ClientSecret == "" && request.ClientCertificatePEM == "" {
			s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.device.begin_denied",
				client.ClientID, "missing_client_auth", "CLIENT_AUTH_FAILED", request.RequestID)
			return DeviceAuthorizationResponse{}, oauthInvalidClient()
		}
		if !s.verifyDeviceClientRequest(ctx, client.ClientID, request.ClientSecret,
			request.ClientCertificatePEM, "oauth.device.begin_denied", request.RequestID) {
			return DeviceAuthorizationResponse{}, oauthInvalidClient()
		}
	}
	scopes, scopeErr := normalizeScopes(request.Scope, client.Scopes)
	if scopeErr != nil {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.device.begin_denied",
			client.ClientID, "invalid_scope", "REQ_INVALID", request.RequestID)
		return DeviceAuthorizationResponse{}, scopeErr
	}
	// OIDC 设备码 ID Token 未在本步实现（OIDC Core 未定义标准设备流 ID Token 语义），
	// 明确拒绝 openid，不签发“看起来像 OIDC 登录”的令牌。
	if containsString(scopes, ScopeOpenID) {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.device.begin_denied",
			client.ClientID, "oidc_device_flow_not_supported", "REQ_INVALID", request.RequestID)
		return DeviceAuthorizationResponse{}, oauthInvalidScope()
	}
	audiences, audienceErr := normalizeAudiences(request.Resource, client.Audiences)
	if audienceErr != nil {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.device.begin_denied",
			client.ClientID, "invalid_audience", "REQ_INVALID", request.RequestID)
		return DeviceAuthorizationResponse{}, audienceErr
	}
	if len(audiences) == 0 {
		if len(client.Audiences) == 1 {
			audiences = []string{client.Audiences[0]}
		} else {
			s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.device.begin_denied",
				client.ClientID, "audience_required", "REQ_INVALID", request.RequestID)
			return DeviceAuthorizationResponse{}, oauthInvalidRequest("必须显式指定目标资源（resource）")
		}
	}
	verificationURI := strings.TrimSpace(s.opts.DeviceVerificationURI)
	if verificationURI == "" {
		// 未配置验证地址 = 能力未启用：fail-closed，不创建用户无法确认的请求。
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.device.begin_denied",
			client.ClientID, "device_flow_not_configured", "INTERNAL_ERROR", request.RequestID)
		return DeviceAuthorizationResponse{}, oauthTemporarilyUnavailable()
	}
	deviceCode, err := s.newDeviceCode()
	if err != nil {
		return DeviceAuthorizationResponse{}, oauthServerError()
	}
	userCode, err := s.newUserCode()
	if err != nil {
		return DeviceAuthorizationResponse{}, oauthServerError()
	}
	userCodeDigest, userCodeKeyID, err := s.userCodeDigest(userCode)
	if err != nil {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.device.begin_denied",
			client.ClientID, "user_code_key_unavailable", "INTERNAL_ERROR", request.RequestID)
		return DeviceAuthorizationResponse{}, oauthTemporarilyUnavailable()
	}
	recordID, err := s.newID(deviceAuthorizationIDPrefix)
	if err != nil {
		return DeviceAuthorizationResponse{}, oauthServerError()
	}
	now := s.now()
	record := DeviceAuthorizationRecord{
		ID: recordID, DeviceCodeSHA256: sha256.Sum256([]byte(deviceCode)),
		UserCodeDigest: userCodeDigest, UserCodeKeyID: userCodeKeyID,
		ClientID: client.ClientID,
		Scopes:   append([]string(nil), scopes...), Audiences: append([]string(nil), audiences...),
		Status: DeviceStatusPending, IntervalSeconds: int(s.devicePollInterval / time.Second),
		RequestID: request.RequestID, CreatedAt: now,
		ExpiresAt: now.Add(s.deviceTTL),
	}
	critical := s.criticalEvent("oauth.device.requested", serviceAuditActor(), client.ClientID,
		"oauth_device_authorization", recordID, request.RequestID, []audit.FieldChange{
			{Field: "client_id", After: client.ClientID},
			{Field: "scope", After: truncateAudit(joinScopes(scopes), 160)},
			{Field: "audience", After: truncateAudit(strings.Join(audiences, " "), 160)},
			{Field: "interval_seconds", After: fmt.Sprint(record.IntervalSeconds)},
			{Field: "expires_at", After: record.ExpiresAt.UTC().Format(time.RFC3339)},
		})
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context,
		tx audit.Tx) error {
		return s.opts.Store.CreateDeviceAuthorizationTx(txCtx, tx, record)
	}); err != nil {
		return DeviceAuthorizationResponse{}, mapCriticalProtocolError(err)
	}
	return DeviceAuthorizationResponse{
		DeviceCode:              DeviceCode{value: deviceCode},
		UserCode:                UserCode{value: displayUserCode(userCode)},
		VerificationURI:         verificationURI,
		VerificationURIComplete: buildVerificationURIComplete(verificationURI, displayUserCode(userCode)),
		ExpiresIn:               int64(s.deviceTTL / time.Second),
		Interval:                int64(s.devicePollInterval / time.Second),
		RequestID:               recordID,
	}, nil
}

// ===== 用户确认 =====

// DescribeDeviceAuthorization 用真实完整普通会话按短码读取待确认请求，返回确认页
// 所需信息。不存在/已决定/已过期/客户端已不可用都返回统一的
// ErrDeviceAuthorizationNotFound，避免向任意登录用户泄露请求状态。
func (s *Service) DescribeDeviceAuthorization(ctx context.Context, sessionSecret, userCode,
	requestID string) (DeviceConsentPrompt, error) {
	ctx = normalizeContext(ctx)
	if err := validRequestID(requestID); err != nil {
		return DeviceConsentPrompt{}, fmt.Errorf("%w: 请求编号无效",
			ErrDeviceAuthorizationInvalid)
	}
	userSession, err := s.opts.Sessions.Validate(ctx, sessionSecret)
	if err != nil || !userSession.IsNormal() || userSession.UserID == "" {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.device.describe_denied",
			"", "session_invalid", "AUTH_FAILED", requestID)
		return DeviceConsentPrompt{}, fmt.Errorf("%w: %w", ErrDeviceAuthorizationAccessDenied, err)
	}
	if err := s.allowUserCodeAttempt(userSession.UserID); err != nil {
		s.failure(ctx, sessionActor(userSession.UserID), "oauth.device.describe_denied",
			"", "user_code_rate_limited", "RATE_LIMITED", requestID)
		return DeviceConsentPrompt{}, err
	}
	normalized, ok := normalizeUserCode(userCode)
	if !ok {
		s.failure(ctx, sessionActor(userSession.UserID), "oauth.device.describe_denied",
			"", "user_code_invalid", "REQ_INVALID", requestID)
		return DeviceConsentPrompt{}, ErrDeviceAuthorizationNotFound
	}
	record, found, err := s.loadDeviceRequestByUserCode(ctx, normalized)
	if err != nil {
		return DeviceConsentPrompt{}, err
	}
	now := s.now()
	if !found || record.Status != DeviceStatusPending || record.ExpiredAt(now) {
		s.failure(ctx, sessionActor(userSession.UserID), "oauth.device.describe_denied",
			"", "user_code_not_pending", "REQ_INVALID", requestID)
		return DeviceConsentPrompt{}, ErrDeviceAuthorizationNotFound
	}
	client, found, err := s.opts.Clients.LoadClient(ctx, record.ClientID)
	if err != nil {
		return DeviceConsentPrompt{}, oauthTemporarilyUnavailable()
	}
	if !found || !client.Active() || !client.GrantsDeviceCode() {
		s.failure(ctx, sessionActor(userSession.UserID), "oauth.device.describe_denied",
			record.ClientID, "client_no_longer_eligible", "CLIENT_DISABLED", requestID)
		return DeviceConsentPrompt{}, ErrDeviceAuthorizationNotFound
	}
	userState, found, err := s.opts.Store.UserState(ctx, userSession.UserID)
	if err != nil {
		return DeviceConsentPrompt{}, oauthTemporarilyUnavailable()
	}
	if !found || !userState.Active() ||
		userState.SecurityVersion != userSession.SecurityVersion {
		s.failure(ctx, sessionActor(userSession.UserID), "oauth.device.describe_denied",
			record.ClientID, "user_state_changed", "AUTH_FAILED", requestID)
		return DeviceConsentPrompt{}, ErrDeviceAuthorizationAccessDenied
	}
	// 应用作用域会话只能确认自己应用范围内的请求（与授权码确认一致）。
	if userSession.AppID != "" && userSession.AppID != record.ClientID {
		s.failure(ctx, sessionActor(userSession.UserID), "oauth.device.describe_denied",
			record.ClientID, "session_app_mismatch", "APP_SCOPE_MISMATCH", requestID)
		return DeviceConsentPrompt{}, ErrDeviceAuthorizationAccessDenied
	}
	return DeviceConsentPrompt{
		RequestID: record.ID, ClientID: record.ClientID, ClientType: client.ClientType,
		Scopes:    append([]string(nil), record.Scopes...),
		Audiences: append([]string(nil), record.Audiences...), ExpiresAt: record.ExpiresAt,
	}, nil
}

// DecideDeviceAuthorization 执行用户对设备授权请求的决定。批准前要求真实完整会话
// 与敏感策略近期认证；批准绑定用户、会话与安全版本快照。拒绝不发任何令牌，也不
// 改变其他安全状态；并发决定只有一方成功。
func (s *Service) DecideDeviceAuthorization(ctx context.Context, sessionSecret string,
	request DeviceDecisionRequest) (DeviceDecisionResult, error) {
	ctx = normalizeContext(ctx)
	if err := validRequestID(request.RequestID); err != nil {
		return DeviceDecisionResult{}, fmt.Errorf("%w: 请求编号无效",
			ErrDeviceAuthorizationInvalid)
	}
	userSession, err := s.opts.Sessions.Validate(ctx, sessionSecret)
	if err != nil || !userSession.IsNormal() || userSession.UserID == "" {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.device.decide_denied",
			"", "session_invalid", "AUTH_FAILED", request.RequestID)
		return DeviceDecisionResult{}, ErrDeviceAuthorizationAccessDenied
	}
	if err := s.allowUserCodeAttempt(userSession.UserID); err != nil {
		s.failure(ctx, sessionActor(userSession.UserID), "oauth.device.decide_denied",
			"", "user_code_rate_limited", "RATE_LIMITED", request.RequestID)
		return DeviceDecisionResult{}, err
	}
	normalized, ok := normalizeUserCode(request.UserCode)
	if !ok {
		s.failure(ctx, sessionActor(userSession.UserID), "oauth.device.decide_denied",
			"", "user_code_invalid", "REQ_INVALID", request.RequestID)
		return DeviceDecisionResult{}, ErrDeviceAuthorizationNotFound
	}
	record, found, err := s.loadDeviceRequestByUserCode(ctx, normalized)
	if err != nil {
		return DeviceDecisionResult{}, err
	}
	now := s.now()
	if !found || record.Status != DeviceStatusPending || record.ExpiredAt(now) {
		s.failure(ctx, sessionActor(userSession.UserID), "oauth.device.decide_denied",
			"", "user_code_not_pending", "REQ_INVALID", request.RequestID)
		return DeviceDecisionResult{}, ErrDeviceAuthorizationNotFound
	}
	if userSession.AppID != "" && userSession.AppID != record.ClientID {
		s.failure(ctx, sessionActor(userSession.UserID), "oauth.device.decide_denied",
			record.ClientID, "session_app_mismatch", "APP_SCOPE_MISMATCH", request.RequestID)
		return DeviceDecisionResult{}, ErrDeviceAuthorizationAccessDenied
	}
	userState, found, err := s.opts.Store.UserState(ctx, userSession.UserID)
	if err != nil {
		return DeviceDecisionResult{}, oauthTemporarilyUnavailable()
	}
	if !found || !userState.Active() ||
		userState.SecurityVersion != userSession.SecurityVersion {
		s.failure(ctx, sessionActor(userSession.UserID), "oauth.device.decide_denied",
			record.ClientID, "user_state_changed", "AUTH_FAILED", request.RequestID)
		return DeviceDecisionResult{}, ErrDeviceAuthorizationAccessDenied
	}
	// 重新读取客户端登记：确认前应用可能已停用或移除设备码授权。
	currentClient, clientFound, clientErr := s.opts.Clients.LoadClient(ctx, record.ClientID)
	if clientErr != nil {
		return DeviceDecisionResult{}, oauthTemporarilyUnavailable()
	}
	if !clientFound || !currentClient.Active() || !currentClient.GrantsDeviceCode() {
		s.failure(ctx, sessionActor(userSession.UserID), "oauth.device.decide_denied",
			record.ClientID, "client_no_longer_eligible", "CLIENT_DISABLED", request.RequestID)
		return DeviceDecisionResult{}, ErrDeviceAuthorizationAccessDenied
	}
	member, err := s.opts.Store.MembershipActive(ctx, userSession.UserID, record.ClientID)
	if err != nil {
		return DeviceDecisionResult{}, oauthTemporarilyUnavailable()
	}
	if !member {
		s.failure(ctx, sessionActor(userSession.UserID), "oauth.device.decide_denied",
			record.ClientID, "not_app_member", "APP_MEMBERSHIP_REQUIRED", request.RequestID)
		return DeviceDecisionResult{}, ErrDeviceAuthorizationAccessDenied
	}
	if !request.Approve {
		critical := s.criticalEvent("oauth.device.denied", sessionActor(userSession.UserID),
			record.ClientID, "oauth_device_authorization", record.ID, request.RequestID,
			[]audit.FieldChange{{Field: "decision", After: "denied"}})
		if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context,
			tx audit.Tx) error {
			ok, decideErr := s.opts.Store.DecideDeviceAuthorizationTx(txCtx, tx, record.ID,
				DeviceStatusDenied, userSession.UserID, "", 0, now)
			if decideErr != nil {
				return decideErr
			}
			if !ok {
				return ErrConsentNotFound
			}
			return nil
		}); err != nil {
			return DeviceDecisionResult{}, mapDeviceCriticalError(err)
		}
		return DeviceDecisionResult{RequestID: record.ID, ClientID: record.ClientID,
			UserID: userSession.UserID, Approved: false}, nil
	}
	// 批准前的近期认证/敏感策略（fail-closed：未接线或拒绝则不批准）。
	authorization, reauthErr := s.authorizeDeviceApproval(ctx, userSession.UserID, record,
		request.RequestID)
	if reauthErr != nil {
		s.failure(ctx, sessionActor(userSession.UserID), "oauth.device.approve_denied",
			record.ClientID, "reauth_denied", string(reauthCode(reauthErr)), request.RequestID)
		return DeviceDecisionResult{}, fmt.Errorf("%w: %w", ErrDeviceAuthorizationReauthRequired,
			reauthErr)
	}
	critical := s.criticalEvent("oauth.device.approved", sessionActor(userSession.UserID),
		record.ClientID, "oauth_device_authorization", record.ID, request.RequestID,
		[]audit.FieldChange{
			{Field: "decision", After: "approved"},
			{Field: "session_id", After: userSession.ID},
			{Field: "scope", After: truncateAudit(joinScopes(record.Scopes), 160)},
			{Field: "audience", After: truncateAudit(strings.Join(record.Audiences, " "), 160)},
		})
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context,
		tx audit.Tx) error {
		ok, decideErr := s.opts.Store.DecideDeviceAuthorizationTx(txCtx, tx, record.ID,
			DeviceStatusApproved, userSession.UserID, userSession.ID,
			userSession.SecurityVersion, now)
		if decideErr != nil {
			return decideErr
		}
		if !ok {
			return ErrConsentNotFound
		}
		return nil
	}); err != nil {
		return DeviceDecisionResult{}, mapDeviceCriticalError(err)
	}
	s.notifyConsent(ctx, authorization)
	return DeviceDecisionResult{RequestID: record.ID, ClientID: record.ClientID,
		UserID: userSession.UserID, Approved: true}, nil
}

// CancelDeviceAuthorization 允许发起设备主动取消仍在等待的请求。必须绑定原 client_id
// （保密客户端还需客户端认证）；取消只影响该请求，不改变任何用户授权。
func (s *Service) CancelDeviceAuthorization(ctx context.Context,
	request DeviceCancelRequest) error {
	ctx = normalizeContext(ctx)
	if err := validRequestID(request.RequestID); err != nil {
		return fmt.Errorf("%w: 请求编号无效", ErrDeviceAuthorizationInvalid)
	}
	if request.ClientID == "" || len(request.ClientID) > 128 ||
		request.DeviceCode == "" || len(request.DeviceCode) > maxDeviceCodeInputBytes {
		return fmt.Errorf("%w: 取消请求参数无效", ErrDeviceAuthorizationInvalid)
	}
	client, found, err := s.opts.Clients.LoadClient(ctx, request.ClientID)
	if err != nil {
		return oauthTemporarilyUnavailable()
	}
	if !found {
		return ErrDeviceAuthorizationNotFound
	}
	if client.ClientType == oauthclient.ClientTypeConfidential {
		if request.ClientSecret == "" && request.ClientCertificatePEM == "" {
			s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.device.cancel_denied",
				client.ClientID, "missing_client_auth", "CLIENT_AUTH_FAILED", request.RequestID)
			return ErrDeviceAuthorizationAccessDenied
		}
		if !s.verifyDeviceClientRequest(ctx, client.ClientID, request.ClientSecret,
			request.ClientCertificatePEM, "oauth.device.cancel_denied", request.RequestID) {
			return ErrDeviceAuthorizationAccessDenied
		}
	}
	record, found, err := s.opts.Store.GetDeviceAuthorizationByDeviceCodeHash(ctx,
		sha256.Sum256([]byte(request.DeviceCode)))
	if err != nil {
		return ErrStoreUnavailable
	}
	if !found || record.ClientID != client.ClientID {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.device.cancel_denied",
			client.ClientID, "device_code_mismatch", "REQ_INVALID", request.RequestID)
		return ErrDeviceAuthorizationNotFound
	}
	now := s.now()
	if record.ExpiredAt(now) {
		return ErrDeviceAuthorizationNotFound
	}
	if record.Status != DeviceStatusPending {
		return ErrDeviceAuthorizationConflict
	}
	critical := s.criticalEvent("oauth.device.cancelled", audit.Actor{Type: audit.ActorSystem,
		ID: serviceComponentID}, record.ClientID, "oauth_device_authorization", record.ID,
		request.RequestID, []audit.FieldChange{{Field: "status", After: DeviceStatusCancelled}})
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context,
		tx audit.Tx) error {
		ok, cancelErr := s.opts.Store.CancelDeviceAuthorizationTx(txCtx, tx, record.ID, now)
		if cancelErr != nil {
			return cancelErr
		}
		if !ok {
			return ErrConsentNotFound
		}
		return nil
	}); err != nil {
		return mapDeviceCriticalError(err)
	}
	return nil
}

// ===== Token 端点轮询领取 =====

// exchangeDeviceCode 处理 grant_type=urn:ietf:params:oauth:grant-type:device_code。
// 标准流程状态用 *OAuthError 返回：authorization_pending/slow_down/access_denied/
// expired_token；设备码不存在、被替换的客户端、已领取或状态变化用 invalid_grant。
func (s *Service) exchangeDeviceCode(ctx context.Context,
	request ExchangeRequest) (TokenResponse, error) {
	if request.ClientID == "" || len(request.ClientID) > 128 ||
		request.DeviceCode == "" || len(request.DeviceCode) > maxDeviceCodeInputBytes {
		return TokenResponse{}, oauthInvalidRequest("设备码兑换请求参数无效")
	}
	if err := validRequestID(request.RequestID); err != nil {
		return TokenResponse{}, oauthInvalidRequest("请求编号无效")
	}
	client, found, err := s.opts.Clients.LoadClient(ctx, request.ClientID)
	if err != nil {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.device.poll_denied",
			request.ClientID, "client_source_unavailable", "DB_UNAVAILABLE", request.RequestID)
		return TokenResponse{}, oauthTemporarilyUnavailable()
	}
	if !found || !client.Active() || !client.GrantsDeviceCode() {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.device.poll_denied",
			request.ClientID, "invalid_client", "CLIENT_AUTH_FAILED", request.RequestID)
		return TokenResponse{}, oauthInvalidClient()
	}
	if client.ClientType == oauthclient.ClientTypeConfidential {
		if request.ClientSecret == "" && request.ClientCertificatePEM == "" {
			s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.device.poll_denied",
				client.ClientID, "missing_client_auth", "CLIENT_AUTH_FAILED", request.RequestID)
			return TokenResponse{}, oauthInvalidClient()
		}
		if !s.verifyDeviceClientRequest(ctx, client.ClientID, request.ClientSecret,
			request.ClientCertificatePEM, "oauth.device.poll_denied", request.RequestID) {
			return TokenResponse{}, oauthInvalidClient()
		}
	}
	digest := sha256.Sum256([]byte(request.DeviceCode))
	record, found, err := s.opts.Store.GetDeviceAuthorizationByDeviceCodeHash(ctx, digest)
	if err != nil {
		return TokenResponse{}, oauthTemporarilyUnavailable()
	}
	if !found {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.device.poll_denied",
			client.ClientID, "unknown_device_code", "AUTH_FAILED", request.RequestID)
		return TokenResponse{}, oauthInvalidGrant("设备码无效")
	}
	actor := audit.Actor{Type: audit.ActorAnonymous}
	if record.UserID != "" {
		actor = sessionActor(record.UserID)
	}
	if record.ClientID != request.ClientID {
		// 设备码被其他客户端提交：拒绝且不泄露所属客户端。
		s.failure(ctx, actor, "oauth.device.poll_denied", client.ClientID,
			"client_mismatch", "AUTH_FAILED", request.RequestID)
		return TokenResponse{}, oauthInvalidGrant("设备码绑定信息不匹配")
	}
	now := s.now()
	if record.ExpiredAt(now) {
		s.failure(ctx, actor, "oauth.device.poll_denied", client.ClientID,
			"device_code_expired", "CHALLENGE_INVALID", request.RequestID)
		return TokenResponse{}, oauthDeviceExpiredToken()
	}
	switch record.Status {
	case DeviceStatusDenied, DeviceStatusCancelled:
		s.failure(ctx, actor, "oauth.device.poll_denied", client.ClientID,
			"device_code_denied", "ACCESS_DENIED", request.RequestID)
		return TokenResponse{}, oauthDeviceAccessDenied()
	case DeviceStatusConsumed:
		s.failure(ctx, actor, "oauth.device.poll_denied", client.ClientID,
			"device_code_replayed", "AUTH_FAILED", request.RequestID)
		return TokenResponse{}, oauthInvalidGrant("设备码已被使用")
	case DeviceStatusPending, DeviceStatusApproved:
		// 继续下方轮询间隔与领取流程。
	default:
		s.failure(ctx, actor, "oauth.device.poll_denied", client.ClientID,
			"device_code_invalid_state", "AUTH_FAILED", request.RequestID)
		return TokenResponse{}, oauthInvalidGrant("设备码状态无效")
	}
	// 服务端强制轮询间隔：过快的轮询返回 slow_down 并增大间隔（不按故障统计）。
	if !record.PollAllowedAt(now) {
		newInterval, _ := s.opts.Store.IncreaseDevicePollInterval(ctx, record.ID, now)
		if newInterval <= 0 {
			newInterval = record.IntervalSeconds + devicePollIntervalIncrementSeconds
		}
		return TokenResponse{}, oauthDeviceSlowDown(time.Duration(newInterval) * time.Second)
	}
	claimed, claimErr := s.opts.Store.ClaimDevicePollSlot(ctx, record.ID, now)
	if claimErr != nil {
		return TokenResponse{}, oauthTemporarilyUnavailable()
	}
	if !claimed {
		// 条件更新失败 = 并发轮询赢得槽位：同样按 slow_down 收敛，不重复发令牌。
		newInterval, _ := s.opts.Store.IncreaseDevicePollInterval(ctx, record.ID, now)
		if newInterval <= 0 {
			newInterval = record.IntervalSeconds + devicePollIntervalIncrementSeconds
		}
		return TokenResponse{}, oauthDeviceSlowDown(time.Duration(newInterval) * time.Second)
	}
	if record.Status == DeviceStatusPending {
		return TokenResponse{}, oauthDeviceAuthorizationPending()
	}
	// approved：领取前重新读取状态（确认后可能被撤回/取消/并发领取）。
	record, found, err = s.opts.Store.GetDeviceAuthorizationByDeviceCodeHash(ctx, digest)
	if err != nil {
		return TokenResponse{}, oauthTemporarilyUnavailable()
	}
	if !found || record.ExpiredAt(now) {
		return TokenResponse{}, oauthDeviceExpiredToken()
	}
	switch record.Status {
	case DeviceStatusApproved:
		// 继续领取。
	case DeviceStatusDenied, DeviceStatusCancelled:
		s.failure(ctx, actor, "oauth.device.poll_denied", client.ClientID,
			"device_code_denied", "ACCESS_DENIED", request.RequestID)
		return TokenResponse{}, oauthDeviceAccessDenied()
	case DeviceStatusConsumed:
		s.failure(ctx, actor, "oauth.device.poll_denied", client.ClientID,
			"device_code_replayed", "AUTH_FAILED", request.RequestID)
		return TokenResponse{}, oauthInvalidGrant("设备码已被使用")
	default:
		return TokenResponse{}, oauthDeviceAuthorizationPending()
	}
	// 领取前重检：用户/安全版本/成员/客户端/会话/登记范围任一变化都 fail-closed。
	if err := s.verifyDeviceRecordStillValid(ctx, record, client, now); err != nil {
		if errors.Is(err, ErrStoreUnavailable) {
			return TokenResponse{}, oauthTemporarilyUnavailable()
		}
		s.failure(ctx, actor, "oauth.device.poll_denied", client.ClientID,
			"device_authorization_state_changed", "AUTH_FAILED", request.RequestID)
		return TokenResponse{}, oauthInvalidGrant("设备授权状态已变化")
	}
	scopes := append([]string(nil), record.Scopes...)
	critical := s.criticalEvent("oauth.device.consumed", actor, client.ClientID,
		"oauth_device_authorization", record.ID, request.RequestID, []audit.FieldChange{
			{Field: "scope", After: truncateAudit(joinScopes(scopes), 160)},
			{Field: "audience", After: truncateAudit(strings.Join(record.Audiences, " "), 160)},
		})
	consumeLost := false
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context,
		tx audit.Tx) error {
		consumed, consumeErr := s.opts.Store.ConsumeDeviceAuthorizationTx(txCtx, tx,
			record.ID, now)
		if consumeErr != nil {
			return consumeErr
		}
		if !consumed {
			consumeLost = true
			return ErrConsentNotFound
		}
		return nil
	}); err != nil {
		if consumeLost {
			s.failure(ctx, actor, "oauth.device.poll_denied", client.ClientID,
				"device_consume_conflict", "AUTH_FAILED", request.RequestID)
			return TokenResponse{}, oauthInvalidGrant("设备码已被使用")
		}
		return TokenResponse{}, mapCriticalProtocolError(err)
	}
	caller, err := token.UserCaller(record.UserID)
	if err != nil {
		s.failure(ctx, actor, "oauth.device.poll_denied", client.ClientID,
			"issuer_caller_invalid", "INTERNAL_ERROR", request.RequestID)
		return TokenResponse{}, oauthServerError()
	}
	issueRequestID, err := s.newID(tokenRequestPrefix)
	if err != nil {
		return TokenResponse{}, oauthServerError()
	}
	issued, issueErr := s.opts.Tokens.IssueAccessToken(ctx, caller, token.IssueAccessTokenRequest{
		ClientID: client.ClientID, SubjectUserID: record.UserID,
		GrantType: token.GrantDeviceCode, Scopes: scopes,
		Audiences: append([]string(nil), record.Audiences...), RequestID: issueRequestID,
	})
	if issueErr != nil {
		reason := "token_issuance_failed"
		switch {
		case errors.Is(issueErr, token.ErrGrantNotAllowed), errors.Is(issueErr, token.ErrScopeNotAllowed),
			errors.Is(issueErr, token.ErrAudienceNotAllowed):
			reason = "token_configuration_changed"
		case errors.Is(issueErr, token.ErrStoreUnavailable):
			reason = "token_store_unavailable"
		case errors.Is(issueErr, token.ErrAccessDenied):
			reason = "token_issuance_not_authorized"
		}
		s.failure(ctx, actor, "oauth.device.poll_denied", client.ClientID, reason,
			"INTERNAL_ERROR", request.RequestID)
		if reason == "token_store_unavailable" {
			return TokenResponse{}, oauthTemporarilyUnavailable()
		}
		return TokenResponse{}, oauthServerError()
	}
	// 刷新令牌：客户端登记 refresh_token 且授权含 offline_access 时签发（设备码
	// 流程与授权码流程共用同一刷新族语义）。
	refreshToken, refreshExpiresAt, refreshErr := s.issueRefreshTokenForDevice(ctx, record,
		client, scopes, actor, request.RequestID)
	if refreshErr != nil {
		s.failure(ctx, actor, "oauth.device.poll_denied", client.ClientID,
			"refresh_token_issue_failed", "INTERNAL_ERROR", request.RequestID)
		return TokenResponse{}, oauthServerError()
	}
	successEvent := audit.Event{
		Actor: actor, AppID: client.ClientID, Action: "oauth.device.token_issued",
		Target:    audit.Target{Type: "oauth_client", ID: client.ClientID},
		Outcome:   audit.OutcomeSuccess,
		RequestID: request.RequestID,
		Changes: []audit.FieldChange{
			{Field: "grant_type", After: AccessTokenGrantDeviceCode},
			{Field: "device_authorization_id", After: record.ID},
			{Field: "jti", After: issued.TokenID},
			{Field: "kid", After: issued.KeyID},
			{Field: "scope", After: truncateAudit(joinScopes(scopes), 160)},
			{Field: "audience", After: truncateAudit(strings.Join(record.Audiences, " "), 160)},
		},
	}
	if err := s.opts.Audit.Record(ctx, successEvent); err != nil {
		s.opts.Logger.Warn("设备码令牌签发成功审计写入失败", "reason", "audit_unavailable")
	}
	expiresIn := int64(issued.ExpiresAt.Sub(issued.IssuedAt).Seconds())
	if expiresIn <= 0 {
		expiresIn = 0
	}
	return TokenResponse{AccessToken: issued.Token, TokenType: "Bearer",
		ExpiresIn: expiresIn, RefreshToken: refreshToken,
		RefreshExpiresAt: refreshExpiresAt, Scope: joinScopes(scopes),
		RequestID: request.RequestID}, nil
}

// verifyDeviceRecordStillValid 在领取令牌前重检用户/安全版本/成员/会话/客户端登记
// 范围。任一变化都返回错误（fail-closed），不签发令牌。
func (s *Service) verifyDeviceRecordStillValid(ctx context.Context,
	record DeviceAuthorizationRecord, client ClientInfo, now time.Time) error {
	userState, found, err := s.opts.Store.UserState(ctx, record.UserID)
	if err != nil {
		return ErrStoreUnavailable
	}
	if !found || !userState.Active() || userState.SecurityVersion != record.SecurityVersion {
		return ErrDeviceAuthorizationAccessDenied
	}
	member, err := s.opts.Store.MembershipActive(ctx, record.UserID, record.ClientID)
	if err != nil {
		return ErrStoreUnavailable
	}
	if !member {
		return ErrDeviceAuthorizationAccessDenied
	}
	snapshot, found, err := s.opts.Store.SessionSnapshot(ctx, record.SessionID)
	if err != nil {
		return ErrStoreUnavailable
	}
	if !found || snapshot.UserID != record.UserID || !snapshot.ActiveAt(now) ||
		snapshot.SecurityVersion != record.SecurityVersion ||
		(snapshot.AppID != "" && snapshot.AppID != record.ClientID) {
		return ErrDeviceAuthorizationAccessDenied
	}
	if !scopesSubset(record.Scopes, client.Scopes) ||
		!containsAll(record.Audiences, client.Audiences) {
		return ErrDeviceAuthorizationAccessDenied
	}
	return nil
}

// authorizeDeviceApproval 复用步骤 39 敏感操作策略要求近期认证；未接线时
// fail-closed。操作 ID 与目标/参数绑定到本次设备授权请求，换目标即失效。
// userID 是当前真实会话用户（pending 记录的 UserID 为空，不能用它做调用者）。
func (s *Service) authorizeDeviceApproval(ctx context.Context, userID string,
	record DeviceAuthorizationRecord, requestID string) (reauth.Result, error) {
	if isNilInterface(s.opts.Reauth) {
		return reauth.Result{}, reauth.ErrAccessDenied
	}
	caller, err := reauthCaller(userID)
	if err != nil {
		return reauth.Result{}, reauth.ErrAccessDenied
	}
	params := map[string]string{
		"client_id": record.ClientID,
		"scope":     joinScopes(record.Scopes),
		"audience":  strings.Join(record.Audiences, " "),
		"request":   record.ID,
	}
	result, err := s.opts.Reauth.Authorize(ctx, caller, reauth.Request{
		ScopeID: "system", OperationID: operationDeviceAuthorizationApprove,
		TargetType: "oauth_client", TargetID: record.ClientID,
		Params: params, Description: "批准设备码授权请求", RequestID: requestID,
	})
	if err != nil {
		return reauth.Result{}, err
	}
	return result, nil
}

// verifyDeviceClientRequest 校验保密客户端的 secret/证书身份；失败写失败审计。
func (s *Service) verifyDeviceClientRequest(ctx context.Context, clientID, secret,
	certificatePEM, action, requestID string) bool {
	if secret != "" {
		identity, err := s.opts.ClientAuth.VerifyClientSecret(ctx, clientID, secret)
		if err != nil || identity.ClientID != clientID {
			s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, action, clientID,
				"client_auth_failed", "CLIENT_AUTH_FAILED", requestID)
			return false
		}
		return true
	}
	identity, err := s.opts.ClientAuth.VerifyClientCertificate(ctx, clientID, certificatePEM)
	if err != nil || identity.ClientID != clientID {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, action, clientID,
			"client_cert_auth_failed", "CLIENT_AUTH_FAILED", requestID)
		return false
	}
	return true
}

// allowUserCodeAttempt 按用户维度固定窗口限流短码验证尝试，抑制在线猜解。
func (s *Service) allowUserCodeAttempt(userID string) error {
	if s.userCodeLimiter == nil {
		return nil
	}
	if decision := s.userCodeLimiter.Allow("user:" + userID); !decision.Allowed {
		return ErrDeviceAuthorizationRateLimited
	}
	return nil
}

// ===== 内部辅助 =====

// newDeviceCode 生成高熵设备码明文（32 字节 base64url，带稳定前缀）。
func (s *Service) newDeviceCode() (string, error) {
	buffer := make([]byte, deviceCodeRandomBytes)
	random := s.opts.Random
	if random == nil {
		random = rand.Reader
	}
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", fmt.Errorf("%w: 安全随机源不可用", ErrOptionsInvalid)
	}
	return deviceCodePrefix + base64.RawURLEncoding.EncodeToString(buffer), nil
}

// newUserCode 生成 8 字符 base20 短码（拒绝采样避免取模偏差）。低熵短码的存储
// 摘要由 userCodeDigest 用宿主密钥环计算，绝不以无密钥摘要落库。
func (s *Service) newUserCode() (string, error) {
	random := s.opts.Random
	if random == nil {
		random = rand.Reader
	}
	buffer := make([]byte, 1)
	code := make([]byte, 0, userCodeLength)
	for len(code) < userCodeLength {
		if _, err := io.ReadFull(random, buffer); err != nil {
			return "", fmt.Errorf("%w: 安全随机源不可用", ErrOptionsInvalid)
		}
		if int(buffer[0]) >= userCodeAlphabetLimit {
			continue
		}
		code = append(code, userCodeAlphabet[int(buffer[0])%len(userCodeAlphabet)])
	}
	return string(code), nil
}

// userCodeDigest 计算短码的带密钥 HMAC-SHA256 摘要与所用密钥编号。
//
// 低熵短码（20^8 ≈ 34.6 bit）不能用无密钥摘要保护：数据库/备份泄露后可离线枚举。
// 这里使用宿主注入的 secrets.Keyring（HMAC-SHA256(HKDF(密钥), 规范化短码)）并在
// 记录上保存 key_id，使密钥轮换后旧记录仍可核对。密钥环缺失/当前写密钥不可用时
// fail-closed 返回 ErrDeviceUserCodeKeyUnavailable，绝不退化为无密钥摘要。
func (s *Service) userCodeDigest(normalized string) ([32]byte, string, error) {
	ring := s.opts.DeviceUserCodeKeyring
	if ring == nil {
		return [32]byte{}, "", ErrDeviceUserCodeKeyUnavailable
	}
	keyID := ring.CurrentKeyID()
	if keyID == "" || !ring.HasKey(keyID) {
		return [32]byte{}, "", ErrDeviceUserCodeKeyUnavailable
	}
	digest, err := ring.HMACDigest(keyID, userCodeDigestDomain, []byte(normalized))
	if err != nil || len(digest) != sha256.Size {
		return [32]byte{}, "", ErrDeviceUserCodeKeyUnavailable
	}
	var result [32]byte
	copy(result[:], digest)
	return result, keyID, nil
}

// loadDeviceRequestByUserCode 用密钥环中每个可用密钥分别计算候选短码摘要并查找。
//
// 查找前无法得知记录行保存的 key_id，因此按密钥环全部 key_id（有界，由密钥环
// 最大密钥数限制）计算候选摘要；命中后仍用常量时间比较复核摘要与行内 key_id，
// 防止“摘要命中即可信”的误解。密钥环缺失/不可用返回 ErrDeviceUserCodeKeyUnavailable
// （调用方 fail-closed）；旧密钥已从密钥环移除的旧记录按不存在处理（短码已失效）。
func (s *Service) loadDeviceRequestByUserCode(ctx context.Context,
	normalized string) (DeviceAuthorizationRecord, bool, error) {
	ring := s.opts.DeviceUserCodeKeyring
	if ring == nil {
		return DeviceAuthorizationRecord{}, false, ErrDeviceUserCodeKeyUnavailable
	}
	keyIDs := ring.KeyIDs()
	if len(keyIDs) == 0 {
		return DeviceAuthorizationRecord{}, false, ErrDeviceUserCodeKeyUnavailable
	}
	for _, keyID := range keyIDs {
		digest, err := ring.HMACDigest(keyID, userCodeDigestDomain, []byte(normalized))
		if err != nil {
			return DeviceAuthorizationRecord{}, false, ErrDeviceUserCodeKeyUnavailable
		}
		if len(digest) != sha256.Size {
			return DeviceAuthorizationRecord{}, false, ErrDeviceUserCodeKeyUnavailable
		}
		var expected [32]byte
		copy(expected[:], digest)
		record, found, lookupErr := s.opts.Store.GetDeviceAuthorizationByUserCodeDigest(ctx, expected)
		if lookupErr != nil {
			return DeviceAuthorizationRecord{}, false, ErrStoreUnavailable
		}
		if !found {
			continue
		}
		// 常量时间复核：行内 key_id 必须与本次候选一致，且摘要必须相同。
		if record.UserCodeKeyID != keyID ||
			subtle.ConstantTimeCompare(record.UserCodeDigest[:], expected[:]) != 1 {
			continue
		}
		return record, true, nil
	}
	return DeviceAuthorizationRecord{}, false, nil
}

// normalizeUserCode 规范化人工输入：去连字符/空白并转大写，只接受 base20 字符集。
func normalizeUserCode(raw string) (string, bool) {
	var builder strings.Builder
	for _, character := range strings.ToUpper(strings.TrimSpace(raw)) {
		switch character {
		case '-', ' ':
			continue
		}
		if !strings.ContainsRune(userCodeAlphabet, character) {
			return "", false
		}
		builder.WriteRune(character)
	}
	normalized := builder.String()
	if len(normalized) != userCodeLength {
		return "", false
	}
	return normalized, true
}

// displayUserCode 生成 4-4 连字符显示形式，便于用户输入与核对。
func displayUserCode(normalized string) string {
	if len(normalized) != userCodeLength {
		return normalized
	}
	return normalized[:4] + "-" + normalized[4:]
}

// buildVerificationURIComplete 在验证地址上附加短码查询参数（严格 URL 编码）。
func buildVerificationURIComplete(verificationURI, displayCode string) string {
	parsed, err := url.Parse(verificationURI)
	if err != nil {
		return verificationURI
	}
	values := parsed.Query()
	values.Set("user_code", displayCode)
	parsed.RawQuery = values.Encode()
	return parsed.String()
}

// validateDeviceVerificationURI 校验宿主配置的验证地址：必须 https，或 http 仅限
// 回环主机；拒绝 userinfo/片段并限制长度。
func validateDeviceVerificationURI(raw string) error {
	if raw == "" {
		return nil
	}
	if len(raw) > MaxRedirectURIBytes {
		return fmt.Errorf("%w: 验证地址过长", ErrOptionsInvalid)
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("%w: 验证地址格式无效", ErrOptionsInvalid)
	}
	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		host := parsed.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
		return fmt.Errorf("%w: http 验证地址只允许回环主机", ErrOptionsInvalid)
	default:
		return fmt.Errorf("%w: 验证地址必须使用 https（或回环 http）", ErrOptionsInvalid)
	}
}

// mapDeviceCriticalError 把设备授权审计事务错误映射为领域/协议错误。
func mapDeviceCriticalError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrConsentNotFound) {
		return ErrDeviceAuthorizationConflict
	}
	if errors.Is(err, audit.ErrAuditUnavailable) {
		return ErrAuditUnavailable
	}
	return ErrStoreUnavailable
}
