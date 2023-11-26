package serverapp

// 令牌状态查询的受控 Go 入口（步骤 227）。
//
// HTTP RFC 7662 端点要求客户端认证；嵌入式宿主本身已持有进程控制权，公开 Go 入口
// 不接受请求自称 application_id/audience，只接受启动配置 `protocol.resource_services`
// 中已登记的受信 service_id，由服务端映射到真实 client_id 与 audience，再复用同一
// `oauthflow.Service.InspectToken` 与在线撤销/账户/应用状态检查。
//
// 安全不变量：
//   - 协议未启用、状态查询未显式启用、service_id 未登记一律拒绝（fail-closed）；
//   - audience 只允许该登记项声明的值，跨资源查询拒绝；
//   - 返回的 Active 只表示令牌/令牌族当前有效，不代表任意业务权限；
//   - 不返回令牌原文、宿主路径或内部错误细节。

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
)

// ErrProtocolInspectDisabled 表示协议域未装配或状态查询未显式启用。
var ErrProtocolInspectDisabled = errors.New("协议令牌状态查询未启用")

// ErrResourceServiceUnknown 表示 service_id 未在启动配置中登记，或请求的 audience
// 不属于该资源服务。
var ErrResourceServiceUnknown = errors.New("资源服务未登记或 audience 不匹配")

// TokenInspectionView 是受控 Go 查询的公开结果（与 HTTP RFC 7662 响应同一来源）。
type TokenInspectionView struct {
	Active    bool
	TokenType string
	ClientID  string
	Scope     string
	Audience  []string
	// Subject/SubjectType 默认不披露；只有资源服务登记显式允许时才返回。
	Subject     string
	SubjectType string
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

// InspectTokenForResourceService 以受信资源服务身份查询令牌状态。serviceID 必须来自
// 启动配置登记；audience 为空时使用该登记项声明的唯一目标资源。
func (d *ProtocolDomains) InspectTokenForResourceService(ctx context.Context,
	serviceID, token, tokenTypeHint, audience, requestID string) (TokenInspectionView, error) {
	if d == nil || d.OAuthFlow == nil || !d.InspectEnabled {
		return TokenInspectionView{}, ErrProtocolInspectDisabled
	}
	entry, err := d.registry.lookupByServiceID(serviceID)
	if err != nil {
		return TokenInspectionView{}, fmt.Errorf("%w: 资源服务标识无效", ErrResourceServiceUnknown)
	}
	audience = strings.TrimSpace(audience)
	if audience != "" && audience != entry.Audience {
		return TokenInspectionView{}, fmt.Errorf("%w: audience 不属于该资源服务",
			ErrResourceServiceUnknown)
	}
	inspection, err := d.OAuthFlow.InspectToken(ctx, oauthflow.TokenInspectRequest{
		Token: strings.TrimSpace(token), TokenTypeHint: strings.TrimSpace(tokenTypeHint),
		Audience: entry.Audience, ResourceServerClientID: entry.ClientID,
		RequestID: requestID})
	if err != nil {
		return TokenInspectionView{}, err
	}
	return TokenInspectionView{Active: inspection.Active,
		TokenType: inspection.TokenType, ClientID: inspection.ClientID,
		Scope: inspection.Scope, Audience: append([]string(nil), inspection.Audience...),
		Subject: inspection.Subject, SubjectType: inspection.SubjectType,
		IssuedAt: inspection.IssuedAt, ExpiresAt: inspection.ExpiresAt}, nil
}
