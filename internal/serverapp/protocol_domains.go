package serverapp

// OAuth 2.0 / OpenID Connect 协议端点装配：真实 token / oidc / oauthflow 服务与
// internal/protocolapi 传输层接线。
//
// 边界与默认值：
//   - 默认关闭：只有配置 protocol.enabled 或 --enable-protocol 才构造并挂载；
//     关闭时协议路径不存在（404）。
//   - 固定 Issuer 来自配置（protocol.issuer），必须与 server.path_prefix 路径一致；
//     四个端点地址逐字节由 Issuer + protocolapi 路径常量生成。
//   - RFC 7662 状态查询需要受信资源服务登记，启用时校验登记并注入授权器；
//     未登记资源服务拒绝启动，不声明未实现能力。
//   - 设备码流程需要设备确认页与短码密钥环；当前仍在 143 范围，未启用时端点
//     不挂载、Discovery 不声明。
//   - 扫码登录服务在 app_qr_login.enabled 时构造，白名单应用必须存在且 active；
//     关闭时页面/协议 QR 端点返回受控错误，不伪造能力。
//   - 令牌签名私钥由 internal/token 用主密钥环加密保存并自动生成；签名材料不写入
//     配置或日志。

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	accountsqlite "github.com/kagurazakayashi/EvernightLogin/internal/account/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	appsqlite "github.com/kagurazakayashi/EvernightLogin/internal/app/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	oauthclientsqlite "github.com/kagurazakayashi/EvernightLogin/internal/oauthclient/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
	oauthflowsqlite "github.com/kagurazakayashi/EvernightLogin/internal/oauthflow/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/oidc"
	oidcsqlite "github.com/kagurazakayashi/EvernightLogin/internal/oidc/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/protocolapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/qrlogin"
	qrloginsqlite "github.com/kagurazakayashi/EvernightLogin/internal/qrlogin/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/token"
	tokensqlite "github.com/kagurazakayashi/EvernightLogin/internal/token/sqlite"
)

// ProtocolDomains 是 OAuth/OIDC 协议与页面共用的真实服务集合。
type ProtocolDomains struct {
	Tokens    *token.Service
	OIDC      *oidc.Service
	OAuthFlow *oauthflow.Service
	// QRLogin/QRClientID/QRApplicationNames 是扫码登录页面/协议共享装配；
	// QRLogin 为 nil 表示未启用（页面与协议端点都不提供）。
	QRLogin            *qrlogin.Service
	QRClientID         string
	QRApplicationNames map[string]string
	Protocol           *protocolapi.Server
	Mounts             []HandlerMount
	revocation         *revocationLinker
	// InspectEnabled 表示 RFC 7662 状态查询真实启用；false 时公开 Go 查询入口
	// 必须拒绝，不能因服务存在就宣称可查询。
	InspectEnabled bool
	// registry 是启动期受信资源服务登记；公开 Go 查询入口只按 service_id 映射到
	// 已登记的 client_id/audience，绝不接受请求自称应用或 audience。
	registry *resourceRegistry
}

// revocationLinker 解决 oidc（需要 oauthflow 做在线撤销检查）与 oauthflow（需要
// oidc 签发 ID Token）的构造循环：先注入链接器，二者构造完成后回填。
type revocationLinker struct {
	flow *oauthflow.Service
}

// AccessTokenRevoked 实现 oidc.RevocationChecker。
func (l *revocationLinker) AccessTokenRevoked(ctx context.Context,
	claims token.AccessClaims) (bool, error) {
	if l == nil || l.flow == nil {
		return false, errors.New("吊销检查尚未接线")
	}
	return l.flow.AccessTokenRevoked(ctx, claims)
}

// protocolIssuer 返回规范化后的协议签发方（由配置校验保证形状）。
func protocolIssuer(deps Deps) string {
	return strings.TrimSuffix(strings.TrimSpace(deps.Config.Protocol.Issuer), "/")
}

// protocolEnabled 报告本次启动是否启用协议端点（配置或显式选项）。
func protocolEnabled(deps Deps) bool {
	return deps.Config.Protocol.Enabled
}

// BuildProtocolDomains 构造 OAuth/OIDC 服务与协议端点挂载点。
//
// 未启用时返回 (nil, nil)。启用时缺少真实客户端/会话/审计依赖、Issuer 与路径前缀
// 不一致、或声明了未实现能力（状态查询）都返回错误，拒绝启动。
func BuildProtocolDomains(deps Deps, services *Services, managed *ManagedServices,
	gate *SecurityGate) (*ProtocolDomains, error) {
	if !protocolEnabled(deps) {
		return nil, nil
	}
	if services == nil || services.Sessions == nil || deps.Store == nil || deps.Audit == nil {
		return nil, fmt.Errorf("协议端点缺少会话或存储依赖")
	}
	if gate == nil || gate.Reauth == nil {
		return nil, fmt.Errorf("协议端点缺少敏感操作闸门")
	}
	issuer := protocolIssuer(deps)
	if issuer == "" {
		return nil, fmt.Errorf("启用协议端点时必须配置 protocol.issuer")
	}
	now := deps.Now
	if now == nil {
		now = time.Now
	}
	clientStore, err := oauthclientsqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造协议客户端存储失败: %w", err)
	}
	if managed == nil || managed.OAuthClient == nil {
		return nil, fmt.Errorf("协议端点缺少 OAuth 客户端服务")
	}

	sealer, err := secrets.NewSealer(deps.Keyring, deps.Logger)
	if err != nil {
		return nil, fmt.Errorf("构造令牌签名密钥加密器失败: %w", err)
	}
	tokenClients, err := token.NewOAuthClientSource(clientStore)
	if err != nil {
		return nil, fmt.Errorf("构造令牌客户端来源失败: %w", err)
	}
	tokenStore, err := tokensqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造令牌存储失败: %w", err)
	}
	issuanceAccounts, err := accountsqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造令牌签发账户有效期读取失败: %w", err)
	}
	tokenService, err := token.New(token.Options{
		Store: tokenStore, Audit: deps.Audit, Sealer: sealer,
		Issuer: issuer, Clients: tokenClients,
		Authorizer: protocolIssuanceAuthorizer{accounts: issuanceAccounts, now: now},
		Now:        now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造令牌服务失败: %w", err)
	}

	// 预引导 active 签名密钥：全新实例若等到首次令牌签发才懒创建密钥，JWKS 会为空
	// （协议端点看似可用但没有公钥）。幂等：已有 active 密钥时直接复用，kid 跨重启
	// 稳定；失败时协议装配失败（拒绝启动），绝不发布空 JWKS 假装可用。
	bootstrapCtx, bootstrapCancel := context.WithTimeout(context.Background(), 10*time.Second)
	keyInfo, keyErr := tokenService.EnsureSigningKey(bootstrapCtx)
	bootstrapCancel()
	if keyErr != nil {
		return nil, fmt.Errorf("启动阶段预引导令牌签名密钥失败（10s 上限，拒绝启动，避免空 JWKS）: %w", keyErr)
	}
	if deps.Logger != nil {
		deps.Logger.Info("已确保令牌签名密钥可用于 JWKS 发布", "kid", keyInfo.Kid)
	}
	oidcStore, err := oidcsqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造 OIDC 用户来源失败: %w", err)
	}
	subjectSecret, err := deriveSubjectSecret(deps)
	if err != nil {
		return nil, err
	}
	linker := &revocationLinker{}
	oidcService, err := oidc.New(oidc.Options{
		Issuer:                issuer,
		AuthorizationEndpoint: issuer + protocolapi.PathAuthorize,
		TokenEndpoint:         issuer + protocolapi.PathToken,
		UserInfoEndpoint:      issuer + protocolapi.PathUserInfo,
		JWKSURI:               issuer + protocolapi.PathJWKS,
		Tokens:                tokenService, Users: oidcStore,
		RevocationChecker: linker, SubjectSecret: subjectSecret,
		Now: now,
	})
	if err != nil {
		return nil, fmt.Errorf("构造 OIDC 服务失败: %w", err)
	}

	flowStore, err := oauthflowsqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造授权流程存储失败: %w", err)
	}
	flowClients, err := oauthflow.NewOAuthClientSource(clientStore)
	if err != nil {
		return nil, fmt.Errorf("构造授权流程客户端来源失败: %w", err)
	}
	loginPath := strings.TrimSpace(deps.Config.Protocol.LoginPath)
	deviceVerificationURI := ""
	if deps.Config.Protocol.DeviceCodeEnabled {
		publicBase := strings.TrimRight(strings.TrimSpace(deps.Config.Server.PublicBaseURL), "/")
		if publicBase == "" {
			return nil, fmt.Errorf("启用设备码时必须配置 server.public_base_url")
		}
		deviceVerificationURI = publicBase + "/oauth/device"
	}
	resourceRegistry, err := loadResourceRegistry(context.Background(), deps)
	if err != nil {
		return nil, fmt.Errorf("资源服务登记校验失败: %w", err)
	}
	inspectEnabled := deps.Config.Protocol.EnableIntrospection
	var inspectAuthorizer oauthflow.InspectAuthorizer
	var inspectClientAuthorizer oauthflow.InspectClientAuthorizer
	var tokenStateChecker oauthflow.TokenStateChecker
	if inspectEnabled {
		if len(resourceRegistry.byClient) == 0 {
			return nil, fmt.Errorf("启用状态查询前必须登记至少一个受信资源服务")
		}
		inspectAuthorizer = resourceInspectAuthorizer{registry: resourceRegistry}
		inspectClientAuthorizer = resourceInspectClientAuthorizer{registry: resourceRegistry}
		checker, checkerErr := newTokenStateChecker(deps)
		if checkerErr != nil {
			return nil, fmt.Errorf("构造令牌当前状态复核器失败: %w", checkerErr)
		}
		tokenStateChecker = checker
	}
	flow, err := oauthflow.New(oauthflow.Options{
		Store: flowStore, Audit: deps.Audit, Clients: flowClients,
		ClientAuth: managed.OAuthClient, Sessions: services.Sessions,
		SessionRevoker: services.Sessions, Tokens: tokenService,
		Reauth: gate.Reauth, OIDC: oidcService, TokenVerifier: tokenService,
		DeviceVerificationURI:   deviceVerificationURI,
		DeviceUserCodeKeyring:   deps.Keyring,
		InspectAuthorizer:       inspectAuthorizer,
		InspectClientAuthorizer: inspectClientAuthorizer,
		TokenStateChecker:       tokenStateChecker,
		Now:                     now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造授权流程服务失败: %w", err)
	}
	linker.flow = flow

	resourceAuthorize, err := buildResourceAuthorizeHandler(deps, resourceRegistry,
		managed.OAuthClient, tokenService, flow, tokenClients, managed.Authz)
	if err != nil {
		return nil, err
	}

	var qrLogin *qrlogin.Service
	var qrClientID string
	var qrApplicationNames map[string]string
	if deps.Config.AppQRLogin.Enabled {
		qrStore, qrErr := qrloginsqlite.New(deps.Store)
		if qrErr != nil {
			return nil, fmt.Errorf("构造扫码登录存储失败: %w", qrErr)
		}
		qrAppStore, qrErr := appsqlite.New(deps.Store)
		if qrErr != nil {
			return nil, fmt.Errorf("构造扫码应用读取器失败: %w", qrErr)
		}
		allowed := append([]string(nil), deps.Config.AppQRLogin.AllowedClientIDs...)
		if len(allowed) == 1 {
			qrClientID = allowed[0]
		}
		qrApplicationNames = make(map[string]string, len(allowed))
		for _, applicationID := range allowed {
			application, lookupErr := qrAppStore.GetApplication(context.Background(), applicationID)
			if lookupErr != nil {
				return nil, fmt.Errorf("扫码白名单应用 %q 不可读: %w", applicationID, lookupErr)
			}
			if application.Status != app.StatusActive {
				return nil, fmt.Errorf("扫码白名单应用 %q 不是 active 状态", applicationID)
			}
			qrApplicationNames[applicationID] = application.Name
		}
		qrLogin, err = qrlogin.New(qrlogin.Options{
			Store: qrStore, Audit: deps.Audit, Clients: clientStore, Applications: qrAppStore,
			Sessions: services.Sessions, SessionIssuer: services.Sessions, Reauth: gate.Reauth,
			Keyring: deps.Keyring, Enabled: true, AllowedClientIDs: allowed,
			RequestTTL:    time.Duration(deps.Config.AppQRLogin.RequestTTLSeconds) * time.Second,
			ClaimInterval: time.Duration(deps.Config.AppQRLogin.ClaimIntervalSeconds) * time.Second,
			Now:           now, Logger: deps.Logger,
		})
		if err != nil {
			return nil, fmt.Errorf("构造扫码登录服务失败: %w", err)
		}
	}
	server, err := protocolapi.New(protocolapi.Options{
		OAuth: flow, OIDC: oidcService, Tokens: tokenService,
		Sessions: services.Sessions, ClientAuth: managed.OAuthClient,
		TokenAuthorize:      resourceAuthorize,
		EnableIntrospection: inspectEnabled,
		EnableDeviceFlow:    deps.Config.Protocol.DeviceCodeEnabled,
		QRLogin:             qrLogin, QRClientID: qrClientID,
		BasePath:  deps.Config.Server.PathPrefix,
		LoginPath: loginPath,
		Logger:    deps.Logger, Now: now,
	})
	if err != nil {
		return nil, fmt.Errorf("构造协议端点失败: %w", err)
	}
	basePath := deps.Config.Server.PathPrefix
	namespaces := []struct {
		name string
		path string
	}{
		{name: "protocol-oauth", path: basePath + "/oauth"},
		{name: "protocol-well-known", path: basePath + "/.well-known"},
		{name: "protocol-jwks", path: basePath + "/jwks"},
	}
	mounts := make([]HandlerMount, 0, len(namespaces))
	for _, namespace := range namespaces {
		handler, handlerErr := server.PathPrefixHandler(namespace.path)
		if handlerErr != nil {
			return nil, fmt.Errorf("构造协议命名空间挂载失败: %w", handlerErr)
		}
		// 站内挂载前缀 = 完整协议前缀去掉部署路径前缀后的相对部分。
		relative := strings.TrimPrefix(namespace.path, basePath)
		if relative == "" {
			relative = "/"
		}
		mounts = append(mounts, HandlerMount{Name: namespace.name,
			Prefix: relative, Handler: handler})
	}
	return &ProtocolDomains{
		Tokens: tokenService, OIDC: oidcService, OAuthFlow: flow,
		QRLogin: qrLogin, QRClientID: qrClientID, QRApplicationNames: qrApplicationNames,
		Protocol: server, Mounts: mounts, revocation: linker,
		InspectEnabled: inspectEnabled, registry: resourceRegistry,
	}, nil
}

// protocolIssuanceAuthorizer 是令牌签发的宿主授权实现：只允许受信系统编排服务
// （授权码/设备码/客户端凭证流程）与用户本人（授权码/设备码）签发；未知授权类型
// 一律拒绝。客户端登记范围、audience 与 scope 由令牌服务按客户端配置再校验。
type protocolIssuanceAuthorizer struct {
	// accounts 读取账户有效期/状态；每次签发即时判定，不依赖定时扫描。
	accounts *accountsqlite.Store
	now      func() time.Time
}

// AuthorizeIssuance 实现 token.IssuanceAuthorizer。
func (a protocolIssuanceAuthorizer) AuthorizeIssuance(ctx context.Context, caller token.Caller,
	request token.IssuanceRequest) error {
	actor := caller.Actor()
	switch actor.Type {
	case audit.ActorSystem:
	case audit.ActorUser:
		switch request.GrantType {
		case token.GrantAuthorizationCode, token.GrantDeviceCode:
		default:
			return token.ErrAccessDenied
		}
	default:
		return token.ErrAccessDenied
	}
	// 用户主体令牌（授权码/设备码/刷新后签发）在签发时即时复核账户可用性：
	// 到期/未开始/手动禁用都拒绝；root 由 GetUserState 的 IsRoot 豁免普通期限。
	subject := strings.TrimSpace(request.SubjectUserID)
	if !account.ValidUserID(subject) {
		return nil
	}
	if a.accounts == nil {
		return token.ErrAccessDenied
	}
	state, err := a.accounts.GetUserState(ctx, subject)
	if err != nil {
		return token.ErrAccessDenied
	}
	if state.IsRoot {
		return nil
	}
	now := time.Now
	if a.now != nil {
		now = a.now
	}
	if available, _ := state.User.AvailabilityAt(now().UTC(), false); !available {
		return token.ErrAccessDenied
	}
	return nil
}

// deriveSubjectSecret 从主密钥环派生稳定的 OIDC subject 配对秘密（32 字节）。
// 轮换主密钥会改变 subject（既定限制，已在部署文档说明）。
func deriveSubjectSecret(deps Deps) ([]byte, error) {
	if deps.Keyring == nil {
		return nil, fmt.Errorf("协议端点缺少主密钥环")
	}
	document, err := deps.Keyring.Document()
	if err != nil {
		return nil, fmt.Errorf("读取主密钥环失败: %w", err)
	}
	secret, err := hkdf.Key(sha256.New, document, []byte("evernight-login/oidc-subject/v1"),
		"oidc-subject-pairing", 32)
	if err != nil {
		return nil, fmt.Errorf("派生 OIDC subject 秘密失败: %w", err)
	}
	if len(secret) < 32 {
		return nil, fmt.Errorf("OIDC subject 秘密长度不足")
	}
	return secret, nil
}

// protocolMounts 返回协议挂载点（未启用时为空）。
func (p *ProtocolDomains) protocolMounts() []HandlerMount {
	if p == nil {
		return nil
	}
	return append([]HandlerMount(nil), p.Mounts...)
}

// httpHandler 返回协议处理程序（诊断/测试用；默认通过挂载点组合）。
func (p *ProtocolDomains) httpHandler() http.Handler {
	if p == nil || p.Protocol == nil {
		return nil
	}
	return p.Protocol.Handler()
}
