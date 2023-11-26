// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

// OAuth 令牌状态查询公开 Go 接口（步骤 227）。
//
// 边界：
//   - 复用 HTTP RFC 7662 端点同一 `oauthflow.InspectToken` 服务与同一在线撤销/
//     账户/应用状态复核，不复制第二套令牌状态判断；
//   - 宿主 Go 代码被视为可信资源服务边界：只接受启动配置 `protocol.resource_services`
//     中登记的 service_id，由 serverapp 映射到真实 client_id/audience，绝不接受请求
//     自称应用、audience 或客户端身份；
//   - 协议未启用或状态查询未显式启用时 fail-closed（CONFIG_INVALID），不返回
//     “空但成功”的假结果；
//   - Active 只表示令牌/令牌族当前有效，不等同于当前主体拥有任意业务权限；离线 JWT
//     验签无法感知即时撤销，严格验收必须走本在线查询；
//   - 不返回令牌原文、客户端秘密、宿主路径或内部错误细节。
//
// 撤销/退出属步骤 228，见 ProtocolRevocationService；本文件不包含其类型/方法。
// 访问器 Runtime.Protocol() 定义在本文件；未编辑 app/runtime.go。

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
	"github.com/kagurazakayashi/EvernightLogin/internal/serverapp"
)

// ProtocolService 是 OAuth 协议受控 Go 状态查询门面。撤销/退出属步骤 228，
// 见 ProtocolRevocationService，避免把撤销能力混入本步提交。
type ProtocolService interface {
	// IntrospectToken 查询访问令牌/刷新令牌当前状态。ServiceID 必须来自启动配置
	// `protocol.resource_services.service_id`；Audience 为空时使用该登记项声明的
	// 唯一目标资源，非空时必须与该登记项一致。
	IntrospectToken(ctx context.Context, req ProtocolIntrospectRequest) (ProtocolTokenInspection, error)
}

// ProtocolIntrospectRequest 是状态查询请求。TokenTypeHint 可为空、access_token 或
// refresh_token；未知 hint 按空处理（由令牌形状自动判断）。
type ProtocolIntrospectRequest struct {
	ServiceID     string
	Token         string
	TokenTypeHint string
	// Audience 可选；只允许该资源服务登记的目标资源，不能扩大查询范围。
	Audience  string
	RequestID string
}

// ProtocolTokenInspection 是受控 Go 查询结果（与 RFC 7662 响应同一来源）。
type ProtocolTokenInspection struct {
	Active      bool
	TokenType   string
	ClientID    string
	Scope       string
	Audience    []string
	Subject     string
	SubjectType string
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

// Protocol 返回 OAuth 协议受控查询门面。协议未启用时调用会返回 CONFIG_INVALID。
func (r *Runtime) Protocol() ProtocolService { return &protocolPublicFacade{r: r} }

// protocolPublicFacade 实现 ProtocolService。
type protocolPublicFacade struct{ r *Runtime }

// IntrospectToken 复用 serverapp 协议域与 oauthflow 状态查询实现。
func (f *protocolPublicFacade) IntrospectToken(ctx context.Context,
	req ProtocolIntrospectRequest) (ProtocolTokenInspection, error) {
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return ProtocolTokenInspection{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := facadeContextError(ctx, requestID); err != nil {
		return ProtocolTokenInspection{}, err
	}
	if f.r == nil || f.r.base == nil || f.r.base.Protocol == nil {
		return ProtocolTokenInspection{}, configError("OAuth 协议未启用，无法查询令牌状态",
			requestID)
	}
	if strings.TrimSpace(req.ServiceID) == "" || strings.TrimSpace(req.Token) == "" {
		return ProtocolTokenInspection{}, login.NewAppError(login.CodeReqInvalid,
			"资源服务标识与令牌不能为空", login.WithRequestID(requestID))
	}
	view, err := f.r.base.Protocol.InspectTokenForResourceService(ctx,
		strings.TrimSpace(req.ServiceID), strings.TrimSpace(req.Token),
		strings.TrimSpace(req.TokenTypeHint), strings.TrimSpace(req.Audience), requestID)
	if err != nil {
		return ProtocolTokenInspection{}, protocolInspectError(err, requestID)
	}
	return ProtocolTokenInspection{Active: view.Active, TokenType: view.TokenType,
		ClientID: view.ClientID, Scope: view.Scope,
		Audience: append([]string(nil), view.Audience...), Subject: view.Subject,
		SubjectType: view.SubjectType, IssuedAt: view.IssuedAt,
		ExpiresAt: view.ExpiresAt}, nil
}

// protocolInspectError 把协议域错误映射为公开稳定错误；不泄露资源服务/令牌存在性。
func protocolInspectError(err error, requestID string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, serverapp.ErrProtocolInspectDisabled) {
		return configError("OAuth 令牌状态查询未启用", requestID)
	}
	if errors.Is(err, serverapp.ErrResourceServiceUnknown) {
		return mapDomainError("资源服务标识或 audience 无效", "REQ_INVALID", requestID)
	}
	var oauthErr *oauthflow.OAuthError
	if errors.As(err, &oauthErr) {
		switch oauthErr.Code {
		case "invalid_request":
			return mapDomainError("令牌状态查询请求无效", "REQ_INVALID", requestID)
		case "invalid_client":
			return login.NewAppError(login.CodeClientAuthFailed, "客户端身份验证失败",
				login.WithRequestID(requestID))
		case "access_denied", "unauthorized_client":
			return mapDomainError("未获准查询该令牌状态", "ACCESS_DENIED", requestID)
		case "temporarily_unavailable":
			return mapDomainError("令牌状态查询暂时不可用", "DB_UNAVAILABLE", requestID)
		default:
			return mapDomainError("令牌状态查询失败", "INTERNAL_ERROR", requestID)
		}
	}
	switch {
	case errors.Is(err, oauthflow.ErrInvalidRequest):
		return mapDomainError("令牌状态查询请求无效", "REQ_INVALID", requestID)
	case errors.Is(err, oauthflow.ErrStoreUnavailable):
		return mapDomainError("令牌状态查询暂时不可用", "DB_UNAVAILABLE", requestID)
	default:
		return mapDomainError("令牌状态查询失败", "INTERNAL_ERROR", requestID)
	}
}
