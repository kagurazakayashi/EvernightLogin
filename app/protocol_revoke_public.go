// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

// OAuth 令牌撤销公开 Go 接口（步骤 228）。
//
// 边界：
//   - 复用 HTTP RFC 7009 端点同一 `oauthflow.RevokeToken/RevokeAuthorization/Logout`
//     服务与同一审计/在线撤销/刷新族/会话失效语义，不复制第二套撤销事实；
//   - 宿主 Go 代码被视为可信客户端/用户会话边界：令牌撤销由客户端身份（机密客户端
//     secret 或已登记证书）验证归属；用户授权撤回/退出只接受真实用户会话秘密；
//   - 未知/已撤销/属于其他客户端的令牌按 RFC 7009 静默成功处理，避免存在性枚举；
//     跨客户端撤销不会生效；重复撤销幂等；
//   - 离线自包含 JWT 无法感知即时撤销；严格校验必须走在线状态查询/联合授权；
//     公开结果不返回令牌原文、客户端秘密或宿主路径。
//
// 访问器 Runtime.ProtocolRevocation() 定义在本文件；未编辑 app/runtime.go。

import (
	"context"
	"errors"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
)

// ProtocolRevocationService 是 OAuth 令牌/授权撤销的受控 Go 门面。
type ProtocolRevocationService interface {
	// RevokeToken 实现 RFC 7009 受控撤销：只撤销调用客户端自己的令牌；未知/已撤销/
	// 他人令牌按成功处理（不枚举），重复撤销幂等。机密客户端必须提供 secret 或已验证
	// 证书。返回值不区分令牌是否存在。
	RevokeToken(ctx context.Context, req ProtocolRevokeTokenRequest) (ProtocolRevokeResult, error)
	// RevokeAuthorization 由用户会话撤回一次应用授权：撤销未兑换授权码、该授权下的
	// 刷新令牌族并写（用户,客户端）在线撤销标记；不宣称离线 JWT 即时失效。
	RevokeAuthorization(ctx context.Context,
		req ProtocolRevokeAuthorizationRequest) (ProtocolRevokeResult, error)
	// Logout 执行退出当前会话/全部身份会话/退出某应用；退出应用会撤销该应用下的
	// 授权码、刷新族、应用内会话与在线撤销标记。
	Logout(ctx context.Context, req ProtocolLogoutRequest) (ProtocolRevokeResult, error)
}

// ProtocolRevokeTokenRequest 是 RFC 7009 受控撤销请求。
type ProtocolRevokeTokenRequest struct {
	ClientID string
	// 机密客户端必须提供 ClientSecret 或已验证的 ClientCertificatePEM；公开客户端
	// 只凭 ClientID（与标准端点一致）。宿主必须只从可信边界填入这些值。
	ClientSecret         string
	ClientCertificatePEM string
	Token                string
	// TokenTypeHint 只是提示；错误提示由领域回退尝试另一令牌类型。
	TokenTypeHint string
	RequestID     string
}

// ProtocolRevokeResult 是受控撤销结果。Token 撤销不返回是否存在/计数（防枚举）；
// 授权撤回/退出应用才会返回真实撤销计数。
type ProtocolRevokeResult struct {
	Accepted           bool
	RefreshFamilies    int64
	RefreshTokens      int64
	AuthorizationCodes int64
	AppSessions        int64
	Note               string
}

// ProtocolRevokeAuthorizationRequest 由用户会话撤回一次应用授权。
type ProtocolRevokeAuthorizationRequest struct {
	SessionSecret   []byte
	AuthorizationID string
	RequestID       string
}

// ProtocolLogoutRequest 是退出当前会话/全部会话/某应用请求。
type ProtocolLogoutRequest struct {
	SessionSecret []byte
	// Scope 只允许 current_session/all_sessions/application；application 时 ClientID
	// 必填。
	Scope     string
	ClientID  string
	RequestID string
}

// ProtocolRevocation 返回 OAuth 撤销门面。协议未启用时调用会返回 CONFIG_INVALID。
func (r *Runtime) ProtocolRevocation() ProtocolRevocationService {
	return &protocolRevocationFacade{r: r}
}

// protocolRevocationFacade 实现 ProtocolRevocationService。
type protocolRevocationFacade struct{ r *Runtime }

// RevokeToken 复用协议域 RFC 7009 实现；成功只表示端点按标准接受请求，不表示
// 令牌一定存在（防枚举）。
func (f *protocolRevocationFacade) RevokeToken(ctx context.Context,
	req ProtocolRevokeTokenRequest) (ProtocolRevokeResult, error) {
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return ProtocolRevokeResult{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := facadeContextError(ctx, requestID); err != nil {
		return ProtocolRevokeResult{}, err
	}
	if f.r == nil || f.r.base == nil || f.r.base.Protocol == nil ||
		f.r.base.Protocol.OAuthFlow == nil {
		return ProtocolRevokeResult{}, configError("OAuth 协议未启用，无法撤销令牌", requestID)
	}
	if strings.TrimSpace(req.ClientID) == "" || strings.TrimSpace(req.Token) == "" {
		return ProtocolRevokeResult{}, login.NewAppError(login.CodeReqInvalid,
			"客户端标识与令牌不能为空", login.WithRequestID(requestID))
	}
	err = f.r.base.Protocol.OAuthFlow.RevokeToken(ctx, oauthflow.RevokeTokenRequest{
		ClientID: strings.TrimSpace(req.ClientID), ClientSecret: req.ClientSecret,
		ClientCertificatePEM: req.ClientCertificatePEM,
		Token:                strings.TrimSpace(req.Token),
		TokenTypeHint:        strings.TrimSpace(req.TokenTypeHint), RequestID: requestID,
	})
	if err != nil {
		return ProtocolRevokeResult{}, protocolRevokeError(err, requestID)
	}
	return ProtocolRevokeResult{Accepted: true,
		Note: "RFC 7009 撤销成功不表示令牌一定存在或属于该客户端"}, nil
}

// RevokeAuthorization 复用协议域用户会话撤回授权（会话秘密只在本调用内使用）。
func (f *protocolRevocationFacade) RevokeAuthorization(ctx context.Context,
	req ProtocolRevokeAuthorizationRequest) (ProtocolRevokeResult, error) {
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return ProtocolRevokeResult{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := facadeContextError(ctx, requestID); err != nil {
		return ProtocolRevokeResult{}, err
	}
	if f.r == nil || f.r.base == nil || f.r.base.Protocol == nil ||
		f.r.base.Protocol.OAuthFlow == nil {
		return ProtocolRevokeResult{}, configError("OAuth 协议未启用，无法撤回授权", requestID)
	}
	if len(req.SessionSecret) == 0 {
		return ProtocolRevokeResult{}, login.NewAppError(login.CodeAccessDenied,
			"撤回授权需要有效用户会话", login.WithRequestID(requestID))
	}
	result, err := f.r.base.Protocol.OAuthFlow.RevokeAuthorization(ctx,
		oauthflow.RevokeAuthorizationRequest{SessionSecret: string(req.SessionSecret),
			AuthorizationID: strings.TrimSpace(req.AuthorizationID), RequestID: requestID})
	if err != nil {
		return ProtocolRevokeResult{}, protocolRevokeError(err, requestID)
	}
	return ProtocolRevokeResult{Accepted: true, RefreshFamilies: result.RefreshFamilies,
		RefreshTokens: result.RefreshTokens, AuthorizationCodes: result.AuthorizationCodes,
		AppSessions: result.AppSessions,
		Note:        "离线 JWT 访问令牌不会仅因本调用即时失效；严格校验走在线状态查询"}, nil
}

// Logout 复用协议域退出语义（范围校验、会话撤销与安全事件由领域完成）。
func (f *protocolRevocationFacade) Logout(ctx context.Context,
	req ProtocolLogoutRequest) (ProtocolRevokeResult, error) {
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return ProtocolRevokeResult{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := facadeContextError(ctx, requestID); err != nil {
		return ProtocolRevokeResult{}, err
	}
	if f.r == nil || f.r.base == nil || f.r.base.Protocol == nil ||
		f.r.base.Protocol.OAuthFlow == nil {
		return ProtocolRevokeResult{}, configError("OAuth 协议未启用，无法退出", requestID)
	}
	if len(req.SessionSecret) == 0 {
		return ProtocolRevokeResult{}, login.NewAppError(login.CodeAccessDenied,
			"退出需要有效用户会话", login.WithRequestID(requestID))
	}
	scope := oauthflow.LogoutScope(strings.TrimSpace(req.Scope))
	switch scope {
	case oauthflow.LogoutCurrentSession, oauthflow.LogoutAllSessions,
		oauthflow.LogoutApplication:
	default:
		return ProtocolRevokeResult{}, login.NewAppError(login.CodeReqInvalid,
			"退出范围无效", login.WithRequestID(requestID))
	}
	result, err := f.r.base.Protocol.OAuthFlow.Logout(ctx, oauthflow.LogoutRequest{
		SessionSecret: string(req.SessionSecret), Scope: scope,
		ClientID: strings.TrimSpace(req.ClientID), RequestID: requestID})
	if err != nil {
		return ProtocolRevokeResult{}, protocolRevokeError(err, requestID)
	}
	return ProtocolRevokeResult{Accepted: true, RefreshFamilies: result.RefreshFamilies,
		RefreshTokens: result.RefreshTokens, AuthorizationCodes: result.AuthorizationCodes,
		AppSessions: result.AppSessions,
		Note:        "退出/撤回不等于离线 JWT 即时失效；严格校验走在线状态查询"}, nil
}

// protocolRevokeError 把协议撤销错误映射为公开稳定错误，不泄露令牌/客户端存在性。
func protocolRevokeError(err error, requestID string) error {
	if err == nil {
		return nil
	}
	var oauthErr *oauthflow.OAuthError
	if errors.As(err, &oauthErr) {
		switch oauthErr.Code {
		case "invalid_request":
			return mapDomainError("撤销请求无效", "REQ_INVALID", requestID)
		case "invalid_client":
			return login.NewAppError(login.CodeClientAuthFailed, "客户端身份验证失败",
				login.WithRequestID(requestID))
		case "access_denied", "unauthorized_client":
			return mapDomainError("未获准执行该撤销", "ACCESS_DENIED", requestID)
		case "server_error":
			// 领域仅在关键审计不可用等不可安全提交的情况下返回 server_error；
			// 公开 Go 门面用更精确的 AUDIT_WRITE_FAILED 表示“未可靠记录即拒绝”。
			return mapDomainError("撤销未能可靠记录，已拒绝", "AUDIT_WRITE_FAILED", requestID)
		case "temporarily_unavailable":
			return mapDomainError("撤销暂时不可用", "DB_UNAVAILABLE", requestID)
		default:
			return mapDomainError("撤销失败", "INTERNAL_ERROR", requestID)
		}
	}
	switch {
	case errors.Is(err, oauthflow.ErrInvalidRequest):
		return mapDomainError("撤销请求无效", "REQ_INVALID", requestID)
	case errors.Is(err, oauthflow.ErrStoreUnavailable):
		return mapDomainError("撤销暂时不可用", "DB_UNAVAILABLE", requestID)
	case errors.Is(err, oauthflow.ErrAuditUnavailable):
		return mapDomainError("撤销未能可靠记录，已拒绝", "AUDIT_WRITE_FAILED", requestID)
	default:
		return mapDomainError("撤销失败", "INTERNAL_ERROR", requestID)
	}
}
