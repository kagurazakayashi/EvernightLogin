package tokenauthz

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	"github.com/kagurazakayashi/EvernightLogin/internal/token"
)

// Options 是联合授权判定服务的显式依赖。Verifier/Clients/Revocations/
// Permissions/Audit 缺失（含 typed-nil）时拒绝构造，绝不创建默认放行实现：
// 令牌验证、客户端登记、在线撤销、当前权限与失败审计都是安全必需项。
type Options struct {
	Verifier    TokenVerifier
	Clients     token.ClientSource
	Revocations RevocationChecker
	Permissions PermissionEngine
	// ServicePrincipals 判定服务身份（client_credentials）的业务权限；未注入时
	// 服务主体的权限要求一律拒绝（不能把持有服务令牌当成自动获得权限）。
	ServicePrincipals ServicePrincipalAuthorizer
	Audit             AuditRecorder
	Logger            *slog.Logger
	// Random 用于生成默认请求编号；nil 使用 crypto/rand。
	Random io.Reader
	// Now 仅用于运行日志时间，不参与安全判定；nil 使用 time.Now。
	Now func() time.Time
}

// Service 是联合授权判定服务；构造后不可变、可并发使用，不启动后台协程，不缓存
// 权限或令牌状态（每次判定读取当前状态，权限撤销后下一次判定立即生效）。
type Service struct {
	opts   Options
	random io.Reader
	logger *slog.Logger
}

// New 校验依赖并构造服务。缺少必需依赖或参数越界时返回 ErrOptionsInvalid。
func New(options Options) (*Service, error) {
	if isNilInterface(options.Verifier) {
		return nil, fmt.Errorf("%w: 令牌验证器为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.Clients) {
		return nil, fmt.Errorf("%w: 客户端登记来源为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.Revocations) {
		// 无状态 JWT 只能在线感知撤销；缺撤销检查时判定不可能安全完成。
		return nil, fmt.Errorf("%w: 令牌撤销检查为空（离线验签不能感知撤销）", ErrOptionsInvalid)
	}
	if isNilInterface(options.Permissions) {
		return nil, fmt.Errorf("%w: 当前权限计算引擎为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.Audit) {
		return nil, fmt.Errorf("%w: 失败审计写入器为空", ErrOptionsInvalid)
	}
	random := options.Random
	if random == nil {
		random = rand.Reader
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	return &Service{opts: options, random: random, logger: logger}, nil
}

// Decide 执行一次联合授权判定。返回 error 表示请求/调用者/依赖层面的失败：
// 业务必须默认拒绝（尤其是 ErrUnavailable 的 503 语义）。返回 error == nil 时
// Decision 是已处理完成的判定结果：Allow=false 是正常业务拒绝（HTTP 200 +
// allow=false + 稳定 code），Allow=true 表示访问凭证与当前权限同时满足。
func (s *Service) Decide(ctx context.Context, service ResourceService, request Request) (Decision, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	// 1. 可信调用者：身份只能来自可信边界构造的 ResourceService。
	if err := service.validate(); err != nil {
		s.recordCallerRejection(ctx, "invalid_resource_service")
		return Decision{}, ErrCallerUntrusted
	}
	// 2. 请求参数：需要业务服务端确定的权限（空要求不放行）。
	requestID, err := normalizeRequestID(request.RequestID, s.random)
	if err != nil {
		return Decision{}, err
	}
	keys, err := normalizePermissions(request.Permissions)
	if err != nil {
		return Decision{}, err
	}
	mode, err := normalizeMode(request.Mode)
	if err != nil {
		return Decision{}, err
	}
	if strings.TrimSpace(request.AccessToken) == "" {
		return Decision{}, fmt.Errorf("%w: 访问凭证为空", ErrInvalidRequest)
	}
	if request.ResourceID != "" {
		if err := validateResourceID(request.ResourceID); err != nil {
			return Decision{}, err
		}
	}
	requiredScopes, err := oauthclient.ParseScopes(request.RequiredScopes)
	if err != nil {
		return Decision{}, fmt.Errorf("%w: 所需 Scope 列表非法", ErrInvalidRequest)
	}
	// 3. 访问凭证：类型/签名/签发方/有效期/audience 由 internal/token 验证；
	// ID Token、Refresh Token、会话秘密都会因类型或格式不符被拒绝。
	claims, err := s.opts.Verifier.VerifyAccessToken(ctx, request.AccessToken, service.Audience())
	if err != nil {
		return s.handleTokenError(ctx, service, requestID, err)
	}
	// 4. 在线撤销状态：无状态 JWT 只能在线感知撤销，依赖故障按不可用拒绝。
	revoked, err := s.opts.Revocations.AccessTokenRevoked(ctx, claims)
	if err != nil {
		return Decision{}, s.unavailable(ctx, err)
	}
	if revoked {
		return s.deny(ctx, service, requestID, CodeTokenRevoked, reasonTokenRevoked, &claims), nil
	}
	// 5. 可信应用映射：令牌 client_id 必须映射到可信资源服务声明的同一应用，
	// 且客户端当前登记仍包含该资源 audience；跨应用/停用/注销一律拒绝。
	client, err := s.opts.Clients.LoadClient(ctx, claims.ClientID)
	if err != nil {
		switch {
		case errors.Is(err, token.ErrClientNotFound):
			return s.deny(ctx, service, requestID, CodeTokenInvalid, reasonClientUnavailable, &claims), nil
		case errors.Is(err, token.ErrClientInactive):
			return s.deny(ctx, service, requestID, CodeClientDisabled, reasonClientInactive, &claims), nil
		default:
			return Decision{}, s.unavailable(ctx, err)
		}
	}
	if client.ClientID != claims.ClientID {
		return s.deny(ctx, service, requestID, CodeTokenInvalid, reasonClientUnavailable, &claims), nil
	}
	if !client.AppActive {
		return s.deny(ctx, service, requestID, CodeClientDisabled, reasonClientInactive, &claims), nil
	}
	if client.ApplicationID != service.ApplicationID() {
		return s.deny(ctx, service, requestID, CodeAppScopeMismatch, reasonCrossApplication, &claims), nil
	}
	if !containsAudience(client.Audiences, service.Audience()) {
		return s.deny(ctx, service, requestID, CodeTokenAudienceMismatch, reasonAudienceRemoved, &claims), nil
	}
	// 令牌授权范围（scope）与业务额外要求取交集：缺少任一所需 scope 即拒绝。
	// scope 只表达令牌授权范围，不映射为角色权限（角色权限由下方主体模型判定）。
	if !scopesContainAll(claims.Scopes, requiredScopes) {
		return s.deny(ctx, service, requestID, CodeAccessDenied, reasonInsufficientScope, &claims), nil
	}
	// 6. 用户主体与服务主体采用各自模型。
	switch claims.SubjectType {
	case "", token.TokenSubjectTypeUser:
		if !validUserID(claims.Subject) {
			return s.deny(ctx, service, requestID, CodeTokenInvalid, reasonInvalidSubject, &claims), nil
		}
		return s.decideUser(ctx, service, requestID, claims, client, keys, mode, request.ResourceID)
	case token.TokenSubjectTypeService:
		return s.decideService(ctx, service, requestID, claims, client, keys, mode, request.ResourceID)
	default:
		// 验证器已拒绝未知 subject_type；此处防御性拒绝。
		return s.deny(ctx, service, requestID, CodeTokenInvalid, reasonInvalidSubject, &claims), nil
	}
}

// handleTokenError 把令牌验证失败映射为稳定业务拒绝或依赖不可用错误。
func (s *Service) handleTokenError(ctx context.Context, service ResourceService, requestID string, err error) (Decision, error) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return Decision{}, err
	}
	switch {
	case errors.Is(err, token.ErrStoreUnavailable):
		return Decision{}, s.unavailable(ctx, err)
	case errors.Is(err, token.ErrTokenExpired):
		return s.deny(ctx, service, requestID, CodeTokenExpired, reasonTokenExpired, nil), nil
	case errors.Is(err, token.ErrAudienceMismatch):
		return s.deny(ctx, service, requestID, CodeTokenAudienceMismatch, reasonAudienceMismatch, nil), nil
	case errors.Is(err, token.ErrKeyRevoked):
		return s.deny(ctx, service, requestID, CodeTokenRevoked, reasonTokenRevoked, nil), nil
	default:
		// 签名、算法、kid、issuer、typ/token_use（含 ID Token 混用）、格式、
		// 有效期上下界等一律视为访问凭证无效；不泄露具体内部原因给公开面。
		return s.deny(ctx, service, requestID, CodeTokenInvalid, reasonTokenInvalid, nil), nil
	}
}

// decideUser 用 internal/authz 实时计算用户当前有效权限并做 all/any 与数据范围
// 判定。调用者固定为被判定用户本人（authz 只允许检查自己），不借用系统身份。
func (s *Service) decideUser(ctx context.Context, service ResourceService, requestID string,
	claims token.AccessClaims, client token.ClientInfo, keys []string, mode authz.Mode,
	resourceID string) (Decision, error) {
	caller, err := authz.UserCaller(claims.Subject)
	if err != nil {
		return s.deny(ctx, service, requestID, CodeTokenInvalid, reasonInvalidSubject, &claims), nil
	}
	result, err := s.opts.Permissions.Check(ctx, caller, authz.CheckRequest{
		SubjectUserID: claims.Subject, ScopeID: service.ApplicationID(),
		Permissions: keys, Mode: mode,
	})
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Decision{}, ctxErr
		}
		return Decision{}, s.unavailable(ctx, err)
	}
	decision := s.baseDecision(service, requestID, claims, client)
	decision.Permissions = mapPermissionDecisions(result.Permissions)
	if !result.Allowed {
		code := ErrorCode(result.Code)
		if MessageOf(code) == "" {
			// 未登记码不得外泄；按权限缺失处理并保留原因为诊断线索。
			code = CodePermissionRequired
		}
		reason := result.Reason
		if reason == "" {
			reason = reasonPermissionDenied
		}
		decision.Code = code
		decision.Message = MessageOf(code)
		decision.Reason = reason
		s.recordDenial(ctx, service, decision, &claims)
		return decision, nil
	}
	// 权限满足后按可选资源标识做数据范围检查（与 internal/authz 的资源检查契约
	// 一致：undefined/none/不在集合内均拒绝）。
	if resourceID != "" {
		decision.ResourceID = resourceID
		if code, reason := evaluateResource(result.Permissions, mode, resourceID); code != "" {
			decision.Code = code
			decision.Message = MessageOf(code)
			decision.Reason = reason
			s.recordDenial(ctx, service, decision, &claims)
			return decision, nil
		}
		decision.ResourceAllowed = true
	}
	decision.Allow = true
	return decision, nil
}

// decideService 判定 client_credentials 服务主体的权限。服务主体没有用户角色
// 权限存储，必须由宿主注入的策略显式判定；未注入时拒绝（fail-closed）。
func (s *Service) decideService(ctx context.Context, service ResourceService, requestID string,
	claims token.AccessClaims, client token.ClientInfo, keys []string, mode authz.Mode,
	resourceID string) (Decision, error) {
	principal := ServicePrincipal{
		ClientID: claims.ClientID, ApplicationID: client.ApplicationID,
		Scopes:    append([]string(nil), claims.Scopes...),
		Audiences: append([]string(nil), claims.Audience...), TokenID: claims.TokenID,
	}
	decision := s.baseDecision(service, requestID, claims, client)
	decision.Permissions = allowedPermissionDecisions(keys)
	if isNilInterface(s.opts.ServicePrincipals) {
		decision.Code = CodePermissionRequired
		decision.Message = MessageOf(CodePermissionRequired)
		decision.Reason = reasonServicePolicyMiss
		s.recordDenial(ctx, service, decision, &claims)
		return decision, nil
	}
	policyDecision, err := s.opts.ServicePrincipals.AuthorizeServicePrincipal(ctx, service, principal,
		ServicePermissionRequest{Permissions: keys, Mode: mode, ResourceID: resourceID})
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Decision{}, ctxErr
		}
		return Decision{}, s.unavailable(ctx, err)
	}
	if !policyDecision.Allow {
		code := policyDecision.Code
		if MessageOf(code) == "" {
			code = CodePermissionRequired
		}
		reason := policyDecision.Reason
		if reason == "" {
			reason = reasonServiceDenied
		}
		decision.Code = code
		decision.Message = MessageOf(code)
		decision.Reason = reason
		s.recordDenial(ctx, service, decision, &claims)
		return decision, nil
	}
	decision.Allow = true
	if resourceID != "" {
		// 服务主体的资源判定由注入策略完成（本包不伪造用户数据范围语义）；
		// 策略允许即视为资源判定通过，返回值如实标注。
		decision.ResourceID = resourceID
		decision.ResourceAllowed = true
	}
	return decision, nil
}

// baseDecision 构造已通过令牌验证后的判定结果骨架（披露受信调用者可见信息）。
func (s *Service) baseDecision(service ResourceService, requestID string,
	claims token.AccessClaims, client token.ClientInfo) Decision {
	subjectType := claims.SubjectType
	if subjectType == "" {
		subjectType = token.TokenSubjectTypeUser
	}
	return Decision{
		RequestID: requestID, SubjectType: subjectType, Subject: claims.Subject,
		ClientID: client.ClientID, ApplicationID: service.ApplicationID(),
		Scopes: append([]string(nil), claims.Scopes...),
	}
}

// deny 构造已拒绝的判定结果并写失败审计（审计失败不改变拒绝结论）。
func (s *Service) deny(ctx context.Context, service ResourceService, requestID string,
	code ErrorCode, reason string, claims *token.AccessClaims) Decision {
	decision := Decision{
		Allow: false, Code: code, Message: MessageOf(code), Reason: reason,
		RequestID: requestID, ApplicationID: service.ApplicationID(),
	}
	if claims != nil {
		subjectType := claims.SubjectType
		if subjectType == "" {
			subjectType = token.TokenSubjectTypeUser
		}
		decision.SubjectType = subjectType
		decision.Subject = claims.Subject
		decision.ClientID = claims.ClientID
		decision.Scopes = append([]string(nil), claims.Scopes...)
	}
	s.recordDenial(ctx, service, decision, claims)
	return decision
}

// mapPermissionDecisions 转换 authz 的逐权限判定为对外结构（只保留稳定码与原因）。
func mapPermissionDecisions(decisions []authz.PermissionDecision) []PermissionDecision {
	if len(decisions) == 0 {
		return nil
	}
	mapped := make([]PermissionDecision, 0, len(decisions))
	for _, decision := range decisions {
		mapped = append(mapped, PermissionDecision{
			Key: decision.Key, Allowed: decision.Allowed,
			Code: ErrorCode(decision.Code), Reason: decision.Reason,
		})
	}
	return mapped
}

// allowedPermissionDecisions 构造服务主体策略通过后的逐权限结果。
func allowedPermissionDecisions(keys []string) []PermissionDecision {
	decisions := make([]PermissionDecision, 0, len(keys))
	for _, key := range keys {
		decisions = append(decisions, PermissionDecision{Key: key, Allowed: true})
	}
	return decisions
}

// evaluateResource 按 internal/authz.CheckResourceAccess 的既有契约判定数据范围：
// 未声明（undefined）或 none 一律拒绝，resources 必须显式包含资源标识。
func evaluateResource(decisions []authz.PermissionDecision, mode authz.Mode, resourceID string) (ErrorCode, string) {
	permit := func(decision authz.PermissionDecision) (ErrorCode, string) {
		if !decision.Allowed {
			code := ErrorCode(decision.Code)
			if MessageOf(code) == "" {
				code = CodePermissionRequired
			}
			return code, reasonPermissionDenied
		}
		if decision.DataScope.Empty() {
			return CodeResourceForbidden, "data_scope_undefined"
		}
		if decision.DataScope.Mode == authz.DataScopeNone {
			return CodeResourceForbidden, "data_scope_none"
		}
		if !decision.DataScope.AllowsResource(resourceID) {
			return CodeResourceForbidden, "resource_not_in_scope"
		}
		return "", ""
	}
	if mode == authz.ModeAny {
		var firstCode ErrorCode
		firstReason := ""
		for _, decision := range decisions {
			code, reason := permit(decision)
			if code == "" {
				return "", ""
			}
			if firstCode == "" {
				firstCode, firstReason = code, reason
			}
		}
		if firstCode == "" {
			return CodePermissionRequired, reasonPermissionDenied
		}
		return firstCode, firstReason
	}
	for _, decision := range decisions {
		if code, reason := permit(decision); code != "" {
			return code, reason
		}
	}
	return "", ""
}

// recordDenial 在独立事务写拒绝审计（含稳定错误码、精确原因与请求编号）；审计
// 写入失败只记录运行日志。目标只写稳定 ID，绝不写令牌原文或秘密。
func (s *Service) recordDenial(ctx context.Context, service ResourceService, decision Decision,
	claims *token.AccessClaims) {
	event := audit.Event{
		Actor: service.actor(), Action: "token.authz.denied",
		Target:  audit.Target{Type: "access_token", ID: ""},
		Outcome: audit.OutcomeFailure, ErrorCode: string(decision.Code),
		ReasonCode: decision.Reason, RequestID: decision.RequestID,
	}
	if claims != nil {
		if claims.SubjectType == token.TokenSubjectTypeService {
			event.Target = audit.Target{Type: "oauth_client", ID: claims.ClientID}
			event.AppID = claims.ClientID
		} else {
			event.Target = audit.Target{Type: "user", ID: claims.Subject}
		}
	}
	if err := s.opts.Audit.RecordFailure(ctx, event); err != nil {
		s.logger.Warn("联合授权拒绝审计写入失败", "reason", decision.Reason,
			"error_category", "audit_unavailable")
	}
}

// recordCallerRejection 为不可信调用者写匿名失败审计（无身份、无目标细节）。
func (s *Service) recordCallerRejection(ctx context.Context, reason string) {
	event := audit.Event{
		Actor: audit.Actor{Type: audit.ActorAnonymous}, Action: "token.authz.caller_rejected",
		Target:  audit.Target{Type: "resource_service", ID: ""},
		Outcome: audit.OutcomeFailure, ErrorCode: string(CodeAccessDenied), ReasonCode: reason,
	}
	if err := s.opts.Audit.RecordFailure(ctx, event); err != nil {
		s.logger.Warn("联合授权调用者拒绝审计写入失败", "error_category", "audit_unavailable")
	}
}

// unavailable 记录依赖不可用并返回统一错误（对外映射 503，业务必须拒绝访问）。
func (s *Service) unavailable(ctx context.Context, cause error) error {
	s.logger.Warn("联合授权判定依赖不可用", "error_category", "dependency_unavailable")
	_ = ctx
	return fmt.Errorf("%w: %w", ErrUnavailable, cause)
}

// normalizeContext 把 nil ctx 当成 Background。
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
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
