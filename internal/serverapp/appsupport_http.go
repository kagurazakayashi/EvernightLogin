package serverapp

// 步骤 154：应用受限客服 API 的生产装配。
//
// 认证只接受 OAuth 用户委托 Access Token（授权码+PKCE 由既有 oauthflow 签发），
// Token 的 client_id 决定应用、subject 决定客服用户、audience 必须是本资源；
// app_id 不接受路径/query/header 自报。联合判定包含：token 签名/aud/类型/期限、
// 在线撤销、客户端所属应用 active、用户应用成员关系与应用作用域权限；本 API 只
// 创建人工升级申请，不执行全局恢复。

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/appsupport"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	oauthclientsqlite "github.com/kagurazakayashi/EvernightLogin/internal/oauthclient/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	supportsqlite "github.com/kagurazakayashi/EvernightLogin/internal/support/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/token"
)

// appSupportTokenValidator 使用真实 token/oauthflow 验证委托 Access Token。
type appSupportTokenValidator struct {
	tokens      *token.Service
	revocations *oauthflow.Service
	store       *storagesqlite.Store
	clients     token.ClientSource
	audience    string
}

func (v appSupportTokenValidator) ValidateToken(ctx context.Context,
	raw string) (appsupport.Identity, error) {
	if v.tokens == nil || v.revocations == nil || v.store == nil {
		return appsupport.Identity{}, errors.New("token validator 未装配")
	}
	claims, err := v.tokens.VerifyAccessToken(ctx, raw, v.audience)
	if err != nil {
		return appsupport.Identity{}, err
	}
	if claims.SubjectType != "" && claims.SubjectType != token.TokenSubjectTypeUser {
		return appsupport.Identity{}, errors.New("应用客服只接受用户委托令牌")
	}
	if !app.ValidApplicationID(claims.ClientID) {
		return appsupport.Identity{}, errors.New("令牌 application 无效")
	}
	revoked, err := v.revocations.AccessTokenRevoked(ctx, claims)
	if err != nil || revoked {
		return appsupport.Identity{}, errors.New("令牌已撤销或撤销状态不可用")
	}
	client, err := v.clients.LoadClient(ctx, claims.ClientID)
	if err != nil || client.ClientID != claims.ClientID ||
		client.ApplicationID != claims.ClientID || !client.AppActive {
		return appsupport.Identity{}, errors.New("客户端/应用不可用")
	}
	if !audienceContains(client.Audiences, v.audience) {
		return appsupport.Identity{}, errors.New("客户端当前未登记客服 audience")
	}
	status, err := v.applicationStatus(ctx, claims.ClientID)
	if err != nil || status != "active" {
		return appsupport.Identity{}, errors.New("应用不可用")
	}
	return appsupport.Identity{ApplicationID: claims.ClientID,
		StaffUserID: claims.Subject}, nil
}

func (v appSupportTokenValidator) applicationStatus(ctx context.Context,
	applicationID string) (string, error) {
	rows, err := v.store.QueryContext(ctx, `SELECT status FROM applications WHERE id=?`, applicationID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	if !rows.Next() {
		return "", errors.New("应用不存在")
	}
	var status string
	if err := rows.Scan(&status); err != nil {
		return "", err
	}
	return status, nil
}

// appSupportMembership 查询真实 app_memberships（active）。
type appSupportMembership struct {
	store *storagesqlite.Store
}

func (m appSupportMembership) IsActiveMember(ctx context.Context, applicationID,
	userID string) (bool, error) {
	rows, err := m.store.QueryContext(ctx, `SELECT status FROM app_memberships
WHERE app_id=? AND user_id=?`, applicationID, userID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return false, nil
	}
	var status string
	if err := rows.Scan(&status); err != nil {
		return false, err
	}
	return status == "active", nil
}

// appSupportPermissions 使用真实 authz 计算当前应用范围权限。
type appSupportPermissions struct {
	authz *authz.Service
}

func (p appSupportPermissions) CheckApplicationPermission(ctx context.Context,
	applicationID, userID, permission string) error {
	if p.authz == nil {
		return errors.New("权限引擎未装配")
	}
	caller, err := authz.UserCaller(userID)
	if err != nil {
		return err
	}
	result, err := p.authz.Check(ctx, caller, authz.CheckRequest{
		SubjectUserID: userID, ScopeID: applicationID,
		Permissions: []string{permission}, Mode: authz.ModeAll,
	})
	if err != nil {
		return err
	}
	if !result.Allowed {
		return errors.New("权限不足")
	}
	return nil
}

// BuildAppSupportHandler 构造应用受限客服 API handler；默认关闭由宿主控制。
func BuildAppSupportHandler(deps Deps, managed *ManagedServices,
	protocolDomains *ProtocolDomains, audience, basePath string) (http.Handler, string, error) {
	if managed == nil || managed.Authz == nil || deps.Store == nil {
		return nil, "", fmt.Errorf("应用客服 API 缺少权限引擎/存储")
	}
	if protocolDomains == nil || protocolDomains.Tokens == nil ||
		protocolDomains.OAuthFlow == nil {
		return nil, "", fmt.Errorf("应用客服 API 需要启用 OAuth 协议端点（token/撤销服务）")
	}
	audience = strings.TrimSpace(audience)
	if audience == "" {
		audience = appsupport.DefaultAudience
	}
	supportStore, err := supportsqlite.New(deps.Store)
	if err != nil {
		return nil, "", fmt.Errorf("构造应用客服工单存储失败: %w", err)
	}
	clientStore, err := oauthclientsqlite.New(deps.Store)
	if err != nil {
		return nil, "", fmt.Errorf("构造应用客服客户端存储失败: %w", err)
	}
	tokenClients, err := token.NewOAuthClientSource(clientStore)
	if err != nil {
		return nil, "", fmt.Errorf("构造应用客服客户端来源失败: %w", err)
	}
	service, err := appsupport.New(appsupport.Options{
		Store: supportStore, Audit: deps.Audit,
		Tokens: appSupportTokenValidator{tokens: protocolDomains.Tokens,
			revocations: protocolDomains.OAuthFlow, store: deps.Store,
			clients: tokenClients, audience: audience},
		Membership:      appSupportMembership{store: deps.Store},
		Permissions:     appSupportPermissions{authz: managed.Authz},
		TargetProtector: supportTargetProtector{checker: managed.Checker, roots: managed.Roots},
		Now:             deps.Now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, "", fmt.Errorf("构造应用客服服务失败: %w", err)
	}
	handler, err := appsupport.NewHTTPHandler(appsupport.HTTPOptions{
		Service: service, BasePath: basePath, Logger: deps.Logger})
	if err != nil {
		return nil, "", fmt.Errorf("构造应用客服 HTTP 失败: %w", err)
	}
	return handler, handler.BasePath(), nil
}

func audienceContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
