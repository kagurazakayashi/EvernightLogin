package oauthflow

import (
	"context"
	"fmt"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	"github.com/kagurazakayashi/EvernightLogin/internal/securityevent"
	"github.com/kagurazakayashi/EvernightLogin/internal/token"
)

// 步骤 55：授权撤回、令牌撤销与退出状态联动。
//
// 设计边界：
//   - 四种退出范围语义分离：退出当前会话、退出全部身份会话、撤回某次应用授权、
//     退出某应用（该用户在该应用的全部授权/凭证）。
//   - 撤回授权/退出应用会撤销未兑换授权码、刷新令牌族，并写（用户,客户端）在线撤销
//     标记；访问令牌是无状态 JWT，仅在在线校验/状态查询中按撤销标记判为无效，不能
//     宣称离线副本立即失效。
//   - 标准撤销端点按 RFC 7009：客户端认证后只撤销自己的令牌，未知/已撤销令牌也按
//     成功处理，避免存在性枚举；重复撤销幂等。
//   - 改密/恢复完成等既有可靠事件（oauth_revocation_events outbox）由消费者接入，
//     失败保留 pending 可重试；不以事件消费替代安全版本/会话撤销。

// 退出范围。
type LogoutScope string

const (
	// LogoutCurrentSession 只退出当前会话（不撤销其他会话/授权）。
	LogoutCurrentSession LogoutScope = "current_session"
	// LogoutAllSessions 退出该用户全部身份会话；不直接撤销应用授权/刷新令牌族
	// （需要撤销应用授权时使用 LogoutApplication）。
	LogoutAllSessions LogoutScope = "all_sessions"
	// LogoutApplication 退出用户在某应用上的全部授权与凭证（未兑换码、刷新族、
	// 应用会话，并写在线撤销标记）。
	LogoutApplication LogoutScope = "application"
)

// 撤销原因稳定码（审计/数据库使用，不含用户输入和秘密）。
const (
	reasonUserRevocation = "user_revocation"
	reasonAppLogout      = "app_logout"
	reasonSecurityEvent  = "security_event"
	reasonClientRevoke   = "client_revocation"
	reasonOAuthEvent     = "oauth_event"
)

// SessionRevoker 是退出服务需要的会话撤销能力；生产实现为 *internal/session.Service。
type SessionRevoker interface {
	Sessions
	RevokeSession(ctx context.Context, secret, targetSessionID string) (bool, error)
	RevokeAllOwnSessions(ctx context.Context, secret string, keepCurrent bool) (int64, error)
}

// RevokeResult 是一次授权/应用撤回的结果计数（不含任何令牌/秘密）。
type RevokeResult struct {
	RefreshFamilies    int64
	RefreshTokens      int64
	AuthorizationCodes int64
	AppSessions        int64
}

// RevokeAuthorizationRequest 是用户撤回某次应用授权（以授权确认请求 ID 标识）。
type RevokeAuthorizationRequest struct {
	SessionSecret   string
	AuthorizationID string
	RequestID       string
}

// LogoutRequest 是四种范围之一的一次退出/撤回请求。
type LogoutRequest struct {
	SessionSecret string
	Scope         LogoutScope
	// ClientID 在 LogoutApplication 范围必填。
	ClientID  string
	RequestID string
}

// RevokeTokenRequest 是标准撤销端点（RFC 7009）请求。PublicMetadata 客户端只凭
// client_id 撤销自己的令牌；保密客户端必须提供 secret 或客户端证书。
type RevokeTokenRequest struct {
	ClientID             string
	ClientSecret         string
	ClientCertificatePEM string
	Token                string
	TokenTypeHint        string
	RequestID            string
}

// SecurityEventKind 是由既有可靠事件（改密/恢复/禁用/成员移除）触发的安全事件。
type SecurityEventKind string

const (
	SecurityEventPasswordChanged   SecurityEventKind = "password_changed"
	SecurityEventRecoveryCompleted SecurityEventKind = "recovery_completed"
	SecurityEventAccountDisabled   SecurityEventKind = "account_disabled"
	SecurityEventMembershipRemoved SecurityEventKind = "membership_removed"
)

// SecurityEvent 是宿主在既有可靠事件提交后调用撤销服务的输入；不包含秘密。
type SecurityEvent struct {
	Kind      SecurityEventKind
	UserID    string
	ClientID  string
	RequestID string
}

// RevokeAuthorization 撤回一次应用授权：校验调用者会话且授权必须属于本人；在同一
// 审计事务内撤销该授权下的未兑换授权码与刷新令牌族，并写（用户,客户端）在线撤销
// 标记。已签发的无状态访问令牌只在在线校验时按标记判无效（失效延迟约定见 README）。
func (s *Service) RevokeAuthorization(ctx context.Context,
	request RevokeAuthorizationRequest) (RevokeResult, error) {
	ctx = normalizeContext(ctx)
	if err := validRequestID(request.RequestID); err != nil {
		return RevokeResult{}, oauthInvalidRequest("请求编号无效")
	}
	if strings.TrimSpace(request.AuthorizationID) == "" || len(request.AuthorizationID) > 64 {
		return RevokeResult{}, oauthInvalidRequest("授权标识无效")
	}
	userSession, err := s.opts.Sessions.Validate(ctx, request.SessionSecret)
	if err != nil || !userSession.IsNormal() {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.authorization.revoke_denied",
			"", "session_invalid", "AUTH_FAILED", request.RequestID)
		return RevokeResult{}, oauthAccessDeniedRedirect("需要登录后撤回授权", "", "")
	}
	record, found, err := s.opts.Store.GetAuthorizationRequest(ctx, request.AuthorizationID)
	if err != nil {
		return RevokeResult{}, oauthTemporarilyUnavailable()
	}
	if !found || record.UserID != userSession.UserID {
		// 不区分“不存在/属于他人”，避免已登录用户枚举他人授权 ID。
		s.failure(ctx, sessionActor(userSession.UserID), "oauth.authorization.revoke_denied",
			"", "authorization_not_owned", "ACCESS_DENIED", request.RequestID)
		return RevokeResult{}, oauthInvalidRequest("授权不存在或不属于当前用户")
	}
	result := RevokeResult{}
	critical := s.criticalEvent("oauth.authorization.revoked",
		sessionActor(userSession.UserID), record.ClientID, "oauth_authorization_request",
		record.ID, request.RequestID, []audit.FieldChange{
			{Field: "client_id", After: record.ClientID},
			{Field: "reason", After: reasonUserRevocation},
		})
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		families, listErr := s.opts.Store.ListRefreshFamilies(txCtx, record.UserID,
			record.ClientID, record.ID)
		if listErr != nil {
			return listErr
		}
		for _, family := range families {
			if !family.RevokedAt.IsZero() {
				continue
			}
			revoked, revokeErr := s.opts.Store.RevokeRefreshFamilyTx(txCtx, tx, family.ID,
				reasonUserRevocation, s.now())
			if revokeErr != nil {
				return revokeErr
			}
			result.RefreshFamilies++
			result.RefreshTokens += revoked
		}
		codes, codeErr := s.opts.Store.RevokeUnconsumedAuthorizationCodesTx(txCtx, tx,
			record.UserID, record.ClientID, record.ID, s.now())
		if codeErr != nil {
			return codeErr
		}
		result.AuthorizationCodes = codes
		return s.opts.Store.UpsertClientUserRevocationTx(txCtx, tx, record.UserID,
			record.ClientID, reasonUserRevocation, request.RequestID, s.now())
	}); err != nil {
		return RevokeResult{}, mapCriticalProtocolError(err)
	}
	s.emitSecurityEvent(ctx, securityevent.Event{
		Type: securityevent.TypeAuthorizationRevoked, ApplicationID: record.ClientID,
		UserID:         record.UserID,
		IdempotencyKey: "oauth.authorization.revoked:" + record.ID,
		RequestID:      request.RequestID,
		Data: map[string]string{
			"refresh_families":    fmt.Sprint(result.RefreshFamilies),
			"refresh_tokens":      fmt.Sprint(result.RefreshTokens),
			"authorization_codes": fmt.Sprint(result.AuthorizationCodes),
		},
	})
	return result, nil
}

// Logout 执行四种退出范围之一。退出当前/全部会话使用会话服务语义；退出应用在
// 单一审计事务内撤销该应用下未兑换授权码与刷新令牌族、写（用户,客户端）在线撤销
// 标记，并撤销该用户在该应用上的活动会话。删除浏览器 Cookie 不等于本服务调用。
func (s *Service) Logout(ctx context.Context, request LogoutRequest) (RevokeResult, error) {
	ctx = normalizeContext(ctx)
	if err := validRequestID(request.RequestID); err != nil {
		return RevokeResult{}, oauthInvalidRequest("请求编号无效")
	}
	if isNilInterface(s.opts.SessionRevoker) {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.logout.denied",
			request.ClientID, "logout_not_configured", "ACCESS_DENIED", request.RequestID)
		return RevokeResult{}, oauthTemporarilyUnavailable()
	}
	userSession, err := s.opts.Sessions.Validate(ctx, request.SessionSecret)
	if err != nil || !userSession.IsNormal() {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.logout.denied",
			request.ClientID, "session_invalid", "AUTH_FAILED", request.RequestID)
		return RevokeResult{}, oauthAccessDeniedRedirect("需要登录后退出", "", "")
	}
	switch request.Scope {
	case LogoutCurrentSession:
		revoked, revokeErr := s.opts.SessionRevoker.RevokeSession(ctx, request.SessionSecret,
			userSession.ID)
		if revokeErr != nil {
			return RevokeResult{}, oauthTemporarilyUnavailable()
		}
		s.recordLogout(ctx, userSession.UserID, "", "current_session",
			map[bool]int64{true: 1, false: 0}[revoked], request.RequestID)
		s.emitSecurityEvent(ctx, securityevent.Event{
			Type: securityevent.TypeSessionLoggedOut, UserID: userSession.UserID,
			IdempotencyKey: "oauth.logout.current:" + userSession.ID + ":" + request.RequestID,
			RequestID:      request.RequestID,
			Data:           map[string]string{"scope": "current_session"},
		})
		return RevokeResult{AppSessions: map[bool]int64{true: 1, false: 0}[revoked]}, nil
	case LogoutAllSessions:
		revoked, revokeErr := s.opts.SessionRevoker.RevokeAllOwnSessions(ctx,
			request.SessionSecret, false)
		if revokeErr != nil {
			return RevokeResult{}, oauthTemporarilyUnavailable()
		}
		s.recordLogout(ctx, userSession.UserID, "", "all_sessions", revoked, request.RequestID)
		s.emitSecurityEvent(ctx, securityevent.Event{
			Type: securityevent.TypeSessionAllRevoked, UserID: userSession.UserID,
			IdempotencyKey: "oauth.logout.all:" + userSession.UserID + ":" + request.RequestID,
			RequestID:      request.RequestID,
			Data: map[string]string{"revoked": fmt.Sprint(revoked),
				"reason_class": "all_sessions"},
		})
		return RevokeResult{AppSessions: revoked}, nil
	case LogoutApplication:
		if strings.TrimSpace(request.ClientID) == "" || len(request.ClientID) > 128 {
			return RevokeResult{}, oauthInvalidRequest("应用标识无效")
		}
		client, found, loadErr := s.opts.Clients.LoadClient(ctx, request.ClientID)
		if loadErr != nil {
			return RevokeResult{}, oauthTemporarilyUnavailable()
		}
		if !found {
			return RevokeResult{}, oauthInvalidRequest("应用不存在")
		}
		result := RevokeResult{}
		critical := s.criticalEvent("oauth.app.logged_out", sessionActor(userSession.UserID),
			client.ClientID, "oauth_client", client.ClientID, request.RequestID,
			[]audit.FieldChange{{Field: "reason", After: reasonAppLogout}})
		if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
			families, listErr := s.opts.Store.ListRefreshFamilies(txCtx, userSession.UserID,
				client.ClientID, "")
			if listErr != nil {
				return listErr
			}
			for _, family := range families {
				if !family.RevokedAt.IsZero() {
					continue
				}
				revoked, revokeErr := s.opts.Store.RevokeRefreshFamilyTx(txCtx, tx,
					family.ID, reasonAppLogout, s.now())
				if revokeErr != nil {
					return revokeErr
				}
				result.RefreshFamilies++
				result.RefreshTokens += revoked
			}
			codes, codeErr := s.opts.Store.RevokeUnconsumedAuthorizationCodesTx(txCtx, tx,
				userSession.UserID, client.ClientID, "", s.now())
			if codeErr != nil {
				return codeErr
			}
			result.AuthorizationCodes = codes
			return s.opts.Store.UpsertClientUserRevocationTx(txCtx, tx, userSession.UserID,
				client.ClientID, reasonAppLogout, request.RequestID, s.now())
		}); err != nil {
			return RevokeResult{}, mapCriticalProtocolError(err)
		}
		// 会话撤销：该用户在该应用上的活动会话（本人秘密可撤销自己的会话）。
		sessionIDs, listErr := s.opts.Store.ListActiveAppSessionIDs(ctx, userSession.UserID,
			client.ClientID, s.now())
		if listErr != nil {
			return RevokeResult{}, oauthTemporarilyUnavailable()
		}
		for _, sessionID := range sessionIDs {
			if _, revokeErr := s.opts.SessionRevoker.RevokeSession(ctx,
				request.SessionSecret, sessionID); revokeErr != nil {
				s.opts.Logger.Warn("退出应用时会话撤销失败", "reason", "session_revoke_failed")
				continue
			}
			result.AppSessions++
		}
		s.emitSecurityEvent(ctx, securityevent.Event{
			Type: securityevent.TypeAppLogout, ApplicationID: client.ClientID,
			UserID:         userSession.UserID,
			IdempotencyKey: "oauth.app.logged_out:" + userSession.UserID + ":" + client.ClientID + ":" + request.RequestID,
			RequestID:      request.RequestID,
			Data: map[string]string{
				"refresh_families":    fmt.Sprint(result.RefreshFamilies),
				"refresh_tokens":      fmt.Sprint(result.RefreshTokens),
				"authorization_codes": fmt.Sprint(result.AuthorizationCodes),
				"app_sessions":        fmt.Sprint(result.AppSessions),
			},
		})
		return result, nil
	default:
		return RevokeResult{}, oauthInvalidRequest("退出范围无效")
	}
}

// RevokeToken 实现 RFC 7009 标准撤销端点语义：客户端认证成功后只撤销自己的令牌；
// 未知/已撤销/属于其他客户端的令牌也按 200 成功处理（不枚举）；重复撤销幂等。
// 只支持 refresh_token 与 access_token，不支持撤销 ID Token/授权码。
func (s *Service) RevokeToken(ctx context.Context, request RevokeTokenRequest) error {
	ctx = normalizeContext(ctx)
	if request.ClientID == "" || len(request.ClientID) > 128 ||
		request.Token == "" || len(request.Token) > 8192 {
		return oauthInvalidRequest("撤销请求参数无效")
	}
	if err := validRequestID(request.RequestID); err != nil {
		return oauthInvalidRequest("请求编号无效")
	}
	client, found, err := s.opts.Clients.LoadClient(ctx, request.ClientID)
	if err != nil {
		return oauthTemporarilyUnavailable()
	}
	if !found || !client.Active() {
		return oauthInvalidClient()
	}
	if client.ClientType == oauthclient.ClientTypeConfidential {
		if request.ClientSecret == "" && request.ClientCertificatePEM == "" {
			return oauthInvalidClient()
		}
		var identity oauthclient.ClientIdentity
		var authErr error
		if request.ClientSecret != "" {
			identity, authErr = s.opts.ClientAuth.VerifyClientSecret(ctx, client.ClientID,
				request.ClientSecret)
		} else {
			identity, authErr = s.opts.ClientAuth.VerifyClientCertificate(ctx, client.ClientID,
				request.ClientCertificatePEM)
		}
		if authErr != nil || identity.ClientID != client.ClientID {
			s.failure(ctx, serviceAuditActor(), "oauth.token.revoke_denied", client.ClientID,
				"client_auth_failed", "CLIENT_AUTH_FAILED", request.RequestID)
			return oauthInvalidClient()
		}
	}
	// RFC 7009：token_type_hint 只是提示，错误 hint 必须被忽略并尝试另一类型。
	// 先按令牌形状选择首选类型；未被识别/归属不匹配时再尝试另一类型，避免因
	// 错误 hint 静默不撤销。
	tokenLooksLikeJWT := strings.Count(request.Token, ".") == 2
	handled := false
	if tokenLooksLikeJWT {
		handled, err = s.tryRevokeAccessToken(ctx, client, request)
	} else {
		handled, err = s.tryRevokeRefreshToken(ctx, client, request)
	}
	if err != nil {
		return err
	}
	if handled {
		return nil
	}
	// 回退尝试另一类型（错误 hint/异常形状）。
	if tokenLooksLikeJWT {
		_, err = s.tryRevokeRefreshToken(ctx, client, request)
	} else {
		_, err = s.tryRevokeAccessToken(ctx, client, request)
	}
	return err
}

// tryRevokeRefreshToken 尝试按刷新令牌撤销；handled=false 表示无法识别/不属于该
// 客户端（调用方静默成功即可，避免存在性枚举）。
func (s *Service) tryRevokeRefreshToken(ctx context.Context, client ClientInfo,
	request RevokeTokenRequest) (bool, error) {
	record, tokenFound, tokenErr := s.opts.Store.GetRefreshTokenByHash(ctx,
		hashRefreshToken(request.Token))
	if tokenErr != nil {
		return false, oauthTemporarilyUnavailable()
	}
	if !tokenFound {
		return false, nil
	}
	family, familyFound, familyErr := s.opts.Store.GetRefreshFamily(ctx, record.FamilyID)
	if familyErr != nil {
		return false, oauthTemporarilyUnavailable()
	}
	if !familyFound || family.ClientID != client.ClientID {
		return false, nil
	}
	// 刷新令牌撤销联动整个授权：除撤族外，还在同一事务写（用户,客户端）在线撤销
	// 标记，使该用户对该应用已签发的无状态 Access Token 在在线校验/状态查询中失效。
	// 这是保守的粗粒度边界（可能同时使同应用其他授权的 AT 在线失效），离线 JWT 副本
	// 仍不能即时感知；README 已说明。
	critical := s.criticalEvent("oauth.refresh_token.revoked", serviceAuditActor(),
		client.ClientID, "oauth_refresh_family", family.ID, request.RequestID,
		[]audit.FieldChange{{Field: "reason", After: reasonClientRevoke}})
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		if _, revokeErr := s.opts.Store.RevokeRefreshFamilyTx(txCtx, tx, family.ID,
			reasonClientRevoke, s.now()); revokeErr != nil {
			return revokeErr
		}
		return s.opts.Store.UpsertClientUserRevocationTx(txCtx, tx, family.SubjectUserID,
			client.ClientID, reasonClientRevoke, request.RequestID, s.now())
	}); err != nil {
		return false, mapCriticalProtocolError(err)
	}
	return true, nil
}

// tryRevokeAccessToken 尝试按访问令牌 jti 撤销；handled=false 表示无法验证/不属于
// 该客户端（调用方静默成功即可）。
func (s *Service) tryRevokeAccessToken(ctx context.Context, client ClientInfo,
	request RevokeTokenRequest) (bool, error) {
	if isNilInterface(s.opts.TokenVerifier) {
		return false, nil
	}
	for _, audience := range client.Audiences {
		claims, verifyErr := s.opts.TokenVerifier.VerifyAccessToken(ctx, request.Token, audience)
		if verifyErr != nil {
			continue
		}
		if claims.ClientID != client.ClientID {
			return false, nil
		}
		record := AccessTokenRevocationRecord{
			JTI: claims.TokenID, ClientID: claims.ClientID, UserID: "",
			SubjectType: claims.SubjectType, RevokedAt: s.now(),
			ExpiresAt: claims.ExpiresAt, Reason: reasonClientRevoke, RequestID: request.RequestID,
		}
		if claims.SubjectType == token.TokenSubjectTypeUser {
			record.UserID = claims.Subject
		}
		critical := s.criticalEvent("oauth.access_token.revoked", serviceAuditActor(),
			client.ClientID, "oauth_access_token", claims.TokenID, request.RequestID,
			[]audit.FieldChange{{Field: "reason", After: reasonClientRevoke},
				{Field: "subject_type", After: claims.SubjectType}})
		if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
			return s.opts.Store.InsertAccessTokenRevocationTx(txCtx, tx, record)
		}); err != nil {
			return false, mapCriticalProtocolError(err)
		}
		return true, nil
	}
	return false, nil
}

// ApplySecurityEvent 把既有可靠事件（改密/恢复完成/账户禁用/成员移除）接入撤销：
// 用户级事件撤销该用户全部刷新族与未兑换授权码并写用户级在线撤销标记；成员移除
// 事件按（用户,客户端）收敛。宿主应在原事件可靠提交后调用；失败可安全重试（幂等）。
func (s *Service) ApplySecurityEvent(ctx context.Context, event SecurityEvent) (RevokeResult, error) {
	ctx = normalizeContext(ctx)
	if strings.TrimSpace(event.UserID) == "" || len(event.UserID) > 64 {
		return RevokeResult{}, fmt.Errorf("%w: 安全事件用户无效", ErrInvalidRequest)
	}
	if err := validRequestID(event.RequestID); err != nil {
		return RevokeResult{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	userWide := true
	switch event.Kind {
	case SecurityEventPasswordChanged, SecurityEventRecoveryCompleted, SecurityEventAccountDisabled:
		userWide = true
	case SecurityEventMembershipRemoved:
		userWide = false
		if strings.TrimSpace(event.ClientID) == "" || len(event.ClientID) > 128 {
			return RevokeResult{}, fmt.Errorf("%w: 成员移除事件缺少应用标识", ErrInvalidRequest)
		}
	default:
		return RevokeResult{}, fmt.Errorf("%w: 未知安全事件类型", ErrInvalidRequest)
	}
	result := RevokeResult{}
	action := "oauth.security_event.user_revoked"
	clientID := ""
	if !userWide {
		action = "oauth.security_event.membership_revoked"
		clientID = event.ClientID
	}
	critical := s.criticalEvent(action, audit.Actor{Type: audit.ActorSystem, ID: serviceComponentID},
		clientID, "user", event.UserID, event.RequestID,
		[]audit.FieldChange{{Field: "event", After: string(event.Kind)},
			{Field: "reason", After: reasonSecurityEvent}})
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		families, listErr := s.opts.Store.ListRefreshFamilies(txCtx, event.UserID, clientID, "")
		if listErr != nil {
			return listErr
		}
		for _, family := range families {
			if !family.RevokedAt.IsZero() {
				continue
			}
			revoked, revokeErr := s.opts.Store.RevokeRefreshFamilyTx(txCtx, tx, family.ID,
				reasonSecurityEvent, s.now())
			if revokeErr != nil {
				return revokeErr
			}
			result.RefreshFamilies++
			result.RefreshTokens += revoked
		}
		codes, codeErr := s.opts.Store.RevokeUnconsumedAuthorizationCodesTx(txCtx, tx,
			event.UserID, clientID, "", s.now())
		if codeErr != nil {
			return codeErr
		}
		result.AuthorizationCodes = codes
		if userWide {
			return s.opts.Store.UpsertUserRevocationTx(txCtx, tx, event.UserID,
				reasonSecurityEvent, event.RequestID, s.now())
		}
		return s.opts.Store.UpsertClientUserRevocationTx(txCtx, tx, event.UserID, clientID,
			reasonSecurityEvent, event.RequestID, s.now())
	}); err != nil {
		return RevokeResult{}, mapCriticalProtocolError(err)
	}
	return result, nil
}

// ConsumeOAuthRevocationEvents 消费步骤 45 写入的 OAuth 撤销可靠事件（outbox）：
// 逐事件执行用户级撤销并标记 processed；单事件失败累计 attempt_count 且保留 pending，
// 下次可安全重试（撤销本身幂等）。返回成功处理数与首个错误。
func (s *Service) ConsumeOAuthRevocationEvents(ctx context.Context, limit int) (int, error) {
	ctx = normalizeContext(ctx)
	events, err := s.opts.Store.ListPendingOAuthRevocationEvents(ctx, limit)
	if err != nil {
		return 0, err
	}
	processed := 0
	var firstErr error
	for _, event := range events {
		result, applyErr := s.ApplySecurityEvent(ctx, SecurityEvent{
			Kind: SecurityEventPasswordChanged, UserID: event.UserID,
			RequestID: "ooer_" + event.ID,
		})
		_ = result
		if applyErr != nil {
			_ = s.opts.Store.MarkOAuthRevocationEventFailed(ctx, event.ID, s.now())
			if firstErr == nil {
				firstErr = applyErr
			}
			continue
		}
		if err := s.opts.Audit.ExecuteCritical(ctx, audit.CriticalRequest{
			Event: audit.Event{
				Actor:  audit.Actor{Type: audit.ActorSystem, ID: serviceComponentID},
				Action: "oauth.revocation_event.consumed", Target: audit.Target{Type: "oauth_revocation_event", ID: event.ID},
				Changes: []audit.FieldChange{{Field: "reason", After: event.Reason}},
			},
			FailureReasonCode: "oauth.revocation_event.consume_failed",
		}, func(txCtx context.Context, tx audit.Tx) error {
			return s.opts.Store.MarkOAuthRevocationEventProcessedTx(txCtx, tx, event.ID,
				reasonOAuthEvent, s.now())
		}); err != nil {
			_ = s.opts.Store.MarkOAuthRevocationEventFailed(ctx, event.ID, s.now())
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		processed++
	}
	return processed, firstErr
}

// accessTokenRevokedOnline 判断已验证访问令牌是否被在线撤销标记命中：jti 精确撤销；
// 用户令牌还要检查用户级/（用户,客户端）级撤销时间是否不早于令牌签发时间。服务身份
// 令牌没有用户主体，只受 jti 精确撤销约束。返回错误表示存储不可用（fail-closed）。
func (s *Service) accessTokenRevokedOnline(ctx context.Context,
	claims token.AccessClaims) (bool, error) {
	revoked, err := s.opts.Store.AccessTokenRevocation(ctx, claims.TokenID)
	if err != nil {
		return false, err
	}
	if revoked {
		return true, nil
	}
	if claims.SubjectType == token.TokenSubjectTypeService || claims.SubjectType == "" {
		return false, nil
	}
	userSince, clientSince, err := s.opts.Store.RevocationTimes(ctx, claims.Subject,
		claims.ClientID)
	if err != nil {
		return false, err
	}
	if !userSince.IsZero() && !claims.IssuedAt.After(userSince) {
		return true, nil
	}
	if !clientSince.IsZero() && !claims.IssuedAt.After(clientSince) {
		return true, nil
	}
	return false, nil
}

// AccessTokenRevoked 是供受信在线校验路径（如 OIDC UserInfo）复用的撤销检查：
// 返回 true 表示该已验证访问令牌被 jti 或用户/应用级在线撤销标记命中。离线验签
// 副本不会调用本方法，因此撤销仍有失效延迟（README 已声明）。
func (s *Service) AccessTokenRevoked(ctx context.Context,
	claims token.AccessClaims) (bool, error) {
	return s.accessTokenRevokedOnline(ctx, claims)
}

// recordLogout 写退出成功审计（不含会话秘密）；失败只记录日志。
func (s *Service) recordLogout(ctx context.Context, userID, clientID, scope string, count int64,
	requestID string) {
	event := audit.Event{
		Actor: sessionActor(userID), Action: "oauth.logout.succeeded",
		Target:  audit.Target{Type: "session", ID: userID},
		Outcome: audit.OutcomeSuccess, RequestID: requestID,
		Changes: []audit.FieldChange{{Field: "scope", After: scope},
			{Field: "revoked", After: fmt.Sprint(count)}},
	}
	if clientID != "" {
		event.AppID = clientID
	}
	if err := s.opts.Audit.Record(ctx, event); err != nil {
		s.opts.Logger.Warn("退出成功审计写入失败", "reason", "audit_unavailable")
	}
}

// emitSecurityEvent 把安全事件交给可选通知实现（步骤 59 Webhook）。调用发生在撤销/
// 退出审计事务提交之后：通知失败只记运行日志，不回滚已完成的撤销，也不影响令牌/会话
// 失效语义（端点失效不得回滚已完成撤销）。
func (s *Service) emitSecurityEvent(ctx context.Context, event securityevent.Event) {
	if isNilInterface(s.opts.Events) {
		return
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = s.now()
	}
	if err := s.opts.Events.Emit(context.WithoutCancel(ctx), event); err != nil {
		s.opts.Logger.Warn("安全事件通知失败", "reason", "webhook_emit_failed")
	}
}
