// Package protocolapi 把既有的 OAuth 2.0 / OpenID Connect / 设备码 / 扫码登录
// 领域服务装配为可选挂载的 HTTP 协议端点（步骤 96 之后交付阻塞 B1 的协议端点部分）。
//
// 本包只做**协议传输层**：解析 HTTP 参数、把请求交给 internal/oauthflow、
// internal/oidc、internal/token、internal/qrlogin、internal/session 的真实服务，
// 再把结果按标准格式写回。它不重写协议语义、不做密码学、不保存令牌、不启动监听、
// 不注册全局路由；宿主通过 Handler 或 Mount 把它挂到自己的 mux 上（后续由 Lead
// 派集成任务接线 internal/serverapp，本包不改 serverapp）。
//
// 端点路径由本包的导出的 Path* 常量给出，不在根 mux 硬编码。固定挂载路径：
//
//	GET  /.well-known/openid-configuration   OIDC Discovery（只声明真实实现的能力）
//	GET  /jwks                               JWT 签名公钥集合（ES256）
//	GET  /oauth/authorize                    授权端点（真实会话 Cookie + 最小同意页）
//	POST /oauth/authorize                    同意/拒绝决定（会话 Cookie + CSRF 令牌）
//	POST /oauth/token                        令牌端点（authorization_code / refresh_token /
//	                                         client_credentials / 设备码 grant）
//	GET  /oauth/userinfo                     UserInfo（Bearer Access Token，按 scope 裁剪）
//	POST /oauth/userinfo                     UserInfo（同上，POST 兼容；令牌仍只从 Authorization 读取）
//	POST /oauth/revoke                       令牌撤销（RFC 7009）
//	POST /oauth/introspect                   令牌状态查询（需要 EnableIntrospection）
//	POST /oauth/token/authorize              Token+当前权限联合判定（可选注入扩展）
//	POST /oauth/device_authorization         设备授权申请（需要 EnableDeviceFlow）
//	POST /oauth/device/cancel                设备授权取消（本包扩展，需要 EnableDeviceFlow）
//	POST /oauth/qr/request                   扫码登录：创建请求（匿名）
//	POST /oauth/qr/status                    扫码登录：原发起端轮询状态
//	POST /oauth/qr/claim                     扫码登录：原发起端领取目标应用会话
//	POST /oauth/qr/cancel                    扫码登录：原发起端取消
//	POST /oauth/qr/regenerate                扫码登录：原发起端重新生成二维码
//	GET  /oauth/qr/prompt                    扫码登录：确认端读取待确认请求（会话）
//	POST /oauth/qr/decision                  扫码登录：确认端批准/拒绝（会话 + CSRF）
//
// 依赖的宿主中间件（本包不实现，文档化契约）：
//   - TLS 终止、HSTS、请求体超时/连接限流/按 IP 或账户限流、访问日志；
//   - 反向代理可信边界：RemoteAddr/客户端证书只能由可信边界建立，本包不读转发头；
//   - Cookie 会话的 CSRF Origin/Referer 允许列表由宿主的 internal/transport CSRF
//     中间件或等价实现负责；本包自身只额外校验会话绑定 CSRF 令牌与同源来源
//     （见 doc.go「宿主集成契约」）。
//
// 安全不变量（由本包 + 既有服务共同保证，逐条有测试）：
//   - 身份只能来自服务端会话/客户端认证，绝不接受请求参数自称的用户或应用。
//   - redirect_uri 精确匹配、授权码一次性且绑定 client/redirect/PKCE、PKCE 只允许
//     S256；错误回调只在已登记地址上重定向，无效 client/redirect 一律不重定向。
//   - 公开客户端不能靠 client_id 冒充保密客户端；保密客户端必须通过 secret 或
//     已完成验证的 TLS 客户端证书认证（本包只采信 VerifiedChains 非空的证书）。
//   - Discovery 只声明本包实际挂载并由真实服务实现的端点与能力；New 会校验
//     oidc.Service 配置的端点与 issuer 是否与本包挂载路径一致，不一致拒绝构造。
//   - 错误响应只包含稳定错误码与安全描述；令牌、授权码、设备码、短码、刷新令牌、
//     会话秘密、领取绑定不入日志、审计或 JSON 响应（一次性明文只在协议规定位置出现）。
package protocolapi

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
	"github.com/kagurazakayashi/EvernightLogin/internal/oidc"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/qrlogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	"github.com/kagurazakayashi/EvernightLogin/internal/transport"
)

// 端点路径常量。它们是本包的公开契约：宿主按这些路径挂载，OIDC 端点地址必须与
// issuer + 对应常量完全一致（New 会校验）。BasePath 非空时实际路径为 BasePath+常量。
const (
	// PathDiscovery 是 OIDC Discovery 文档路径（RFC 8414 / OIDC Discovery 1.0）。
	PathDiscovery = "/.well-known/openid-configuration"
	// PathJWKS 是 JWT 签名公钥集合路径。
	PathJWKS = "/jwks"
	// PathAuthorize 是 OAuth 2.0 授权端点（GET 展示同意页，POST 提交决定）。
	PathAuthorize = "/oauth/authorize"
	// PathToken 是 OAuth 2.0 令牌端点。
	PathToken = "/oauth/token"
	// PathUserInfo 是 OIDC UserInfo 端点。
	PathUserInfo = "/oauth/userinfo"
	// PathRevoke 是令牌撤销端点（RFC 7009）。
	PathRevoke = "/oauth/revoke"
	// PathIntrospect 是令牌状态查询端点（RFC 7662）。
	PathIntrospect = "/oauth/introspect"
	// PathTokenAuthorize 是宿主扩展的 Token+当前权限联合判定端点（非标准 OAuth，
	// 只有注入 TokenAuthorize 处理器时才挂载）。
	PathTokenAuthorize = "/oauth/token/authorize"
	// PathDeviceAuthorization 是设备授权申请端点（RFC 8628）。
	PathDeviceAuthorization = "/oauth/device_authorization"
	// PathDeviceCancel 是设备授权取消端点（本包扩展；非 RFC 8628 标准端点）。
	PathDeviceCancel = "/oauth/device/cancel"

	// PathQRRequest 创建一次扫码登录请求（匿名发起端）。
	PathQRRequest = "/oauth/qr/request"
	// PathQRStatus 查询扫码登录请求状态（原发起端，需领取绑定）。
	PathQRStatus = "/oauth/qr/status"
	// PathQRClaim 领取扫码登录结果并签发目标应用会话（原发起端，需领取绑定）。
	PathQRClaim = "/oauth/qr/claim"
	// PathQRCancel 取消扫码登录请求（原发起端，需领取绑定）。
	PathQRCancel = "/oauth/qr/cancel"
	// PathQRRegenerate 取消旧请求并生成新二维码（原发起端，需领取绑定）。
	PathQRRegenerate = "/oauth/qr/regenerate"
	// PathQRPrompt 确认端读取待确认请求（真实完整会话）。
	PathQRPrompt = "/oauth/qr/prompt"
	// PathQRDecision 确认端批准或拒绝（真实完整会话 + CSRF）。
	PathQRDecision = "/oauth/qr/decision"
)

// 协议常量。
const (
	// ScopeOfflineAccess 是请求刷新令牌所需的 OIDC 离线访问 scope；只有登记了
	// refresh_token 的客户端授权时才签发刷新令牌。
	ScopeOfflineAccess = "offline_access"
	// DeviceCodeGrantType 是 RFC 8628 设备码授权在令牌端点的 grant_type。
	DeviceCodeGrantType = oauthflow.AccessTokenGrantDeviceCode
	// TokenTypeBearer 是令牌响应的固定 token_type。
	TokenTypeBearer = "Bearer"
	// DefaultMaxBodyBytes 是协议端点请求体默认上限：令牌/表单参数远小于该值，
	// 同时限制设备码与同意表单的滥用体积。
	DefaultMaxBodyBytes int64 = 64 * 1024
	// MinMaxBodyBytes/MaxMaxBodyBytes 是请求体上限允许范围。
	MinMaxBodyBytes int64 = 4 * 1024
	MaxMaxBodyBytes int64 = 1024 * 1024
	// requestIDPrefix 是服务端生成的请求编号前缀（与既有请求编号约定一致）。
	requestIDPrefix = "req_"
	// requestIDRandomBytes 是生成请求编号的随机字节数。
	requestIDRandomBytes = 16
)

// 领域错误。协议响应仍使用标准 OAuth/OIDC 错误字段，这些错误只用于构造与挂载。
var (
	// ErrOptionsInvalid 表示构造参数缺失/不一致（缺依赖必须拒绝构造）。
	ErrOptionsInvalid = errors.New("协议端点选项无效")
	// ErrMountConflict 表示宿主 mux 已占用本包需要的路径或已有路由遮蔽它。
	ErrMountConflict = errors.New("协议端点挂载路径冲突")
)

// TokenPublisher 是 JWKS 发布契约；生产实现为 *internal/token.Service。
type TokenPublisher interface {
	PublishedJWKS(ctx context.Context) ([]byte, error)
}

// BrowserSessions 是浏览器会话/CSRF 契约；生产实现为 *internal/session.Service。
// 它只负责会话秘密获取、校验、Cookie 投递与页面 CSRF 令牌；身份判断全部由真实
// 会话服务完成，本包不解析 Cookie 内容。
type BrowserSessions interface {
	SessionSecretFromRequest(request *http.Request) (string, bool)
	Validate(ctx context.Context, secret string) (session.Session, error)
	NewCookie(issued session.IssuedSession) (*http.Cookie, error)
	IssuePageCSRFToken(ctx context.Context, secret string) (session.Secret, error)
	ValidateCSRFToken(ctx context.Context, request *http.Request, token string) error
}

// Options 是协议端点依赖与固定公开配置。所有依赖必须是已构造完成的真实服务；
// 本包不创建默认服务、不创建测试替身，缺依赖时拒绝构造（fail-closed）。
type Options struct {
	// OAuth 是授权确认/令牌兑换/撤销/设备码/状态查询服务；必填。
	OAuth *oauthflow.Service
	// OIDC 是 Discovery/UserInfo 服务；必填。其 Issuer 与四个端点地址必须与本包
	// BasePath + Path* 常量一致，否则 New 拒绝构造（避免发现文档声明未挂载端点）。
	OIDC *oidc.Service
	// Tokens 是签名公钥发布服务（/jwks）；必填。
	Tokens TokenPublisher
	// Sessions 是浏览器会话与 CSRF 服务；必填。
	Sessions BrowserSessions
	// ClientAuth 是资源服务/客户端身份验证契约（introspect 端点使用）；启用
	// EnableIntrospection 时必填。生产实现为 *internal/oauthclient.Service。
	ClientAuth oauthflow.ClientAuthenticator
	// QRLogin 是扫码登录服务；nil 表示不挂载 /oauth/qr/* 端点（不声明未提供能力）。
	// 服务自身的 Enabled/AllowedClientIDs 仍然是最终开关（默认关闭）。
	QRLogin *qrlogin.Service
	// QRClientID 是扫码登录固定的目标应用 ID；非空时请求只能为该应用创建请求，
	// 避免浏览器把扫码登录用作任意应用的会话通道。空表示由请求的 client_id 决定，
	// 服务端 qrlogin 白名单仍是最终边界。
	QRClientID string
	// QRScopes 是扫码登录确认页展示的 scope（不是令牌授权）；可空。
	QRScopes []string
	// BasePath 是挂载前缀（空表示根路径）。必须与 OIDC issuer 的路径部分一致。
	BasePath string
	// LoginPath 是可选的登录页路径（相对本服务 origin，例如 "/login"）。授权端点
	// 发现无有效会话时，若配置了该路径则 303 跳转到 LoginPath?return_to=<相对路径>；
	// 未配置则返回受控 JSON 错误。登录页必须校验 return_to 只允许本站 BasePath 下
	// 路径（宿主页面契约，本包只投递相对 request URI）。
	LoginPath string
	// EnableDeviceFlow 显式启用设备码端点与 Discovery 的 device_code 能力。只有
	// oauthflow 配置了 DeviceVerificationURI（设备确认页可用）时才允许置 true；
	// 否则发现文档会夸大能力。
	EnableDeviceFlow bool
	// EnableIntrospection 显式启用 RFC 7662 状态查询端点。只有 oauthflow 配置了
	// InspectAuthorizer（与可选的 InspectClientAuthorizer）时才允许置 true。
	EnableIntrospection bool
	// TokenAuthorize 是扩展的 Token+当前权限联合判定处理器；nil 表示不挂载。
	// 它必须自行完成调用方认证与授权，不得信任请求体自述身份。
	TokenAuthorize http.Handler
	// SessionCookieName 是浏览器会话 Cookie 名，用于判断请求是否使用 Cookie 会话
	// （Cookie 会话的写请求必须带 CSRF 令牌；Bearer 会话不受 CSRF 影响）。空使用
	// session.DefaultCookieName。
	SessionCookieName string
	// MaxBodyBytes 是协议端点请求体上限；0 使用 DefaultMaxBodyBytes。
	MaxBodyBytes int64
	// Logger 是结构化运行日志；nil 使用丢弃输出。日志只记录端点、结果类别与请求
	// 编号，绝不记录令牌/授权码/设备码/短码/秘密。
	Logger *slog.Logger
	// Now 是可注入时钟（仅用于日志与展示时间）；nil 使用 time.Now。
	Now func() time.Time
	// Random 是安全随机源（请求编号）；nil 使用 crypto/rand.Reader。
	Random io.Reader
}

// Server 是装配完成的协议端点集合；构造后不可变、可并发使用，不启动协程、不
// 监听端口、不打开数据库、不关闭宿主资源。
type Server struct {
	opts           Options
	basePath       string
	issuer         string
	issuerOrigin   string
	discovery      DiscoveryDocument
	handler        http.Handler
	routes         map[string]http.Handler
	paths          []string
	now            func() time.Time
	random         io.Reader
	logger         *slog.Logger
	cookieName     string
	consent        *consentRenderer
	enabledDevice  bool
	enabledInspect bool
}

// isNilDependency 识别 nil 与 typed-nil 依赖，避免“看起来注入但实际为 nil”的
// 依赖在运行时 panic 或被当成未配置而静默降级。
func isNilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Func, reflect.Slice, reflect.Chan:
		return reflected.IsNil()
	default:
		return false
	}
}

// New 校验依赖与配置并构造协议端点。任何缺失依赖、issuer/端点路径不一致、
// 非法 BasePath 或能力声明不完整都返回错误；不会创建默认服务或测试替身。
func New(options Options) (*Server, error) {
	if isNilDependency(options.OAuth) {
		return nil, fmt.Errorf("%w: 授权流程服务为空", ErrOptionsInvalid)
	}
	if isNilDependency(options.OIDC) {
		return nil, fmt.Errorf("%w: OIDC 服务为空", ErrOptionsInvalid)
	}
	if isNilDependency(options.Tokens) {
		return nil, fmt.Errorf("%w: 令牌发布服务为空", ErrOptionsInvalid)
	}
	if isNilDependency(options.Sessions) {
		return nil, fmt.Errorf("%w: 会话服务为空", ErrOptionsInvalid)
	}
	if options.EnableIntrospection && isNilDependency(options.ClientAuth) {
		return nil, fmt.Errorf("%w: 启用状态查询时必须注入客户端认证器", ErrOptionsInvalid)
	}
	basePath, err := transport.NormalizePrefix(options.BasePath)
	if err != nil {
		return nil, fmt.Errorf("%w: BasePath 无效: %v", ErrOptionsInvalid, err)
	}
	loginPath := ""
	if options.LoginPath != "" {
		loginPath, err = transport.NormalizePrefix(options.LoginPath)
		if err != nil {
			return nil, fmt.Errorf("%w: LoginPath 无效: %v", ErrOptionsInvalid, err)
		}
	}
	options.LoginPath = loginPath
	cookieName := strings.TrimSpace(options.SessionCookieName)
	if cookieName == "" {
		cookieName = session.DefaultCookieName
	}
	if !validCookieName(cookieName) {
		return nil, fmt.Errorf("%w: 会话 Cookie 名无效", ErrOptionsInvalid)
	}
	if options.MaxBodyBytes == 0 {
		options.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if options.MaxBodyBytes < MinMaxBodyBytes || options.MaxBodyBytes > MaxMaxBodyBytes {
		return nil, fmt.Errorf("%w: 请求体上限必须在 %d～%d 字节之间",
			ErrOptionsInvalid, MinMaxBodyBytes, MaxMaxBodyBytes)
	}
	if options.QRClientID != "" && !qrloginValidClientID(options.QRClientID) {
		return nil, fmt.Errorf("%w: QRClientID 不是合法的应用 ID", ErrOptionsInvalid)
	}
	if len(options.QRScopes) > qrlogin.MaxScopes {
		return nil, fmt.Errorf("%w: QRScopes 数量超过上限", ErrOptionsInvalid)
	}
	for _, scope := range options.QRScopes {
		if strings.TrimSpace(scope) == "" || len(scope) > qrlogin.MaxScopeTokenBytes {
			return nil, fmt.Errorf("%w: QRScopes 包含非法 scope", ErrOptionsInvalid)
		}
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	random := options.Random
	if random == nil {
		random = rand.Reader
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard,
			&slog.HandlerOptions{Level: slog.LevelError + 1}))
	}

	// 发现文档必须与实际挂载的端点一致：校验 oidc.Service 的固定 issuer 与端点
	// 地址，避免“发现文档声明了未挂载端点”或“挂载了未声明端点”两种夸大。
	issuer, issuerOrigin, err := validateIssuer(basePath, options.OIDC)
	if err != nil {
		return nil, err
	}
	server := &Server{
		opts: options, basePath: basePath, issuer: issuer, issuerOrigin: issuerOrigin,
		now: now, random: random, logger: logger, cookieName: cookieName,
		consent: newConsentRenderer(basePath), enabledDevice: options.EnableDeviceFlow,
		enabledInspect: options.EnableIntrospection,
	}
	server.discovery = server.buildDiscovery()
	server.routes = make(map[string]http.Handler)
	server.registerRoutes()
	server.paths = make([]string, 0, len(server.routes))
	for path := range server.routes {
		server.paths = append(server.paths, path)
	}
	sortStrings(server.paths)
	server.handler = server.router()
	return server, nil
}

// Handler 返回只服务本包端点的 http.Handler。宿主可以直接使用它，也可以调用
// Mount 把它按路径挂到自己的 mux；返回的 Handler 不注册全局路由、不监听端口。
func (s *Server) Handler() http.Handler {
	if s == nil {
		return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writeProblem(writer, nil, http.StatusServiceUnavailable, codeInternalError, "", "")
		})
	}
	return s.handler
}

// BasePath 返回构造时使用的挂载前缀（空表示根路径）。
func (s *Server) BasePath() string {
	if s == nil {
		return ""
	}
	return s.basePath
}

// PathPrefixHandler 返回可组合的命名空间处理器：宿主先按前缀路由并剥离前缀
// （例如 internal/serverapp.ComposeHandler 的语义），把剩余路径交给本处理器，
// 本处理器把 prefix 重新拼回 URL.Path 后交给协议路由。
//
// 它让宿主可以按协议命名空间分别挂载："/oauth"（全部 OAuth/设备码/扫码端点）、
// "/.well-known"（Discovery）、"/jwks"（公钥）。prefix 必须是实际存在的路由
// 前缀，且必须是本包路由的路径前缀（例如 BasePath+"/oauth"）；不匹配时返回错误，
// 避免把处理器挂到不会命中任何路由的位置。
func (s *Server) PathPrefixHandler(prefix string) (http.Handler, error) {
	if s == nil {
		return nil, fmt.Errorf("%w: 协议端点服务为空", ErrOptionsInvalid)
	}
	normalized, err := transport.NormalizePrefix(prefix)
	if err != nil {
		return nil, fmt.Errorf("%w: 命名空间前缀无效: %v", ErrOptionsInvalid, err)
	}
	if normalized == "" {
		return nil, fmt.Errorf("%w: 命名空间前缀不能为空（可直接使用 Handler）", ErrOptionsInvalid)
	}
	matched := false
	for _, path := range s.paths {
		if path == normalized || strings.HasPrefix(path, normalized+"/") {
			matched = true
			break
		}
	}
	if !matched {
		return nil, fmt.Errorf("%w: 前缀 %q 不是任何已挂载路由的前缀", ErrOptionsInvalid, normalized)
	}
	routeHandler := s.handler
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		cloned := request.Clone(request.Context())
		remainder := request.URL.Path
		if remainder == "" || remainder == "/" {
			remainder = ""
		}
		cloned.URL.Path = normalized + remainder
		cloned.URL.RawPath = ""
		routeHandler.ServeHTTP(writer, cloned)
	}), nil
}

// Paths 返回实际挂载的绝对路径（含 BasePath），按字典序排列。
func (s *Server) Paths() []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s.paths...)
}

// Issuer 返回固定公开签发方（与 OIDC/令牌 iss 一致）。
func (s *Server) Issuer() string {
	if s == nil {
		return ""
	}
	return s.issuer
}

// Discovery 返回本包实际声明能力的发现文档副本。
func (s *Server) Discovery() DiscoveryDocument {
	if s == nil {
		return DiscoveryDocument{}
	}
	return s.discovery.clone()
}

// Mount 把全部端点挂到宿主 mux。挂载前先做冲突探测：若宿主已在同一路径（或会用
// 更宽/方法限定模式遮蔽该路径）注册处理器，返回 ErrMountConflict 且不注册任何路由，
// 避免出现“发现文档声明的端点实际被其他处理器接管”的静默错误。
func (s *Server) Mount(mux *http.ServeMux) error {
	if s == nil {
		return fmt.Errorf("%w: 协议端点服务为空", ErrOptionsInvalid)
	}
	if mux == nil {
		return fmt.Errorf("%w: 宿主 mux 为空", ErrOptionsInvalid)
	}
	// 先整体探测，确认无冲突后再注册，避免失败时留下半挂载状态。
	for _, path := range s.paths {
		if conflict := mountConflict(mux, path); conflict != "" {
			return fmt.Errorf("%w: 路径 %s 已被 %q 占用", ErrMountConflict, path, conflict)
		}
	}
	for _, path := range s.paths {
		handler := s.routes[path]
		if err := registerRoute(mux, path, handler); err != nil {
			return fmt.Errorf("%w: 注册 %s 失败: %v", ErrMountConflict, path, err)
		}
	}
	return nil
}

// registerRoute 注册单条精确路径；防御性 recover 防止极端冲突导致 panic 逸出。
func registerRoute(mux *http.ServeMux, path string, handler http.Handler) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("mux 注册 panic: %v", recovered)
		}
	}()
	mux.Handle(path, handler)
	return nil
}

// mountConflict 探测宿主 mux 是否已占用指定路径。http.ServeMux 不提供注册表查询，
// 用 mux.Handler 的匹配结果判断：返回的模式不是空串且不是全局兜底 "/" 时说明该
// 路径已被更具体的处理器占用或遮蔽（方法限定模式也会遮蔽本包的非方法限定处理器）。
func mountConflict(mux *http.ServeMux, path string) string {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		request := &http.Request{Method: method, URL: &url.URL{Path: path}}
		_, pattern := mux.Handler(request)
		if pattern == "" || pattern == "/" {
			continue
		}
		return pattern
	}
	return ""
}

// recoveryWriter 记录响应是否已经开始写出。panic 恢复只允许在响应未写出时补写
// 统一 500；已经写出的响应无法撤回，不能追加第二个状态码。实现 Unwrap 以便外层
// 使用 http.ResponseController 时仍能找到底层 ResponseWriter（Flusher 等能力）。
type recoveryWriter struct {
	http.ResponseWriter
	wroteHeader bool
}

// WriteHeader 记录首次写状态。
func (w *recoveryWriter) WriteHeader(status int) {
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(status)
}

// Write 记录响应正文开始写出。
func (w *recoveryWriter) Write(body []byte) (int, error) {
	w.wroteHeader = true
	return w.ResponseWriter.Write(body)
}

// Unwrap 暴露底层 ResponseWriter（供 http.ResponseController 使用）。
func (w *recoveryWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// router 构造精确路径路由。它是全部协议端点的最外层传输边界：
//   - 未匹配路径返回 404 统一错误信封，并携带服务端生成/复用的 request_id；
//   - 任何处理器 panic 都在此恢复，未写出响应时返回统一 500（INTERNAL_ERROR +
//     request_id）；panic 值与栈不进入响应、不写日志，避免泄露内部细节；已写出
//     响应时只记录类别，不再写第二个响应。
func (s *Server) router() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		guard := &recoveryWriter{ResponseWriter: writer}
		defer func() {
			if recovered := recover(); recovered != nil {
				requestID := s.requestID(request)
				s.logFailure(request, requestID, "panic_recovered")
				if guard.wroteHeader {
					return
				}
				writeProblem(guard, request, http.StatusInternalServerError,
					codeInternalError, requestID, "")
			}
		}()
		handler, ok := s.routes[request.URL.Path]
		if !ok {
			requestID := s.requestID(request)
			writeProblem(guard, request, http.StatusNotFound, codeReqInvalid, requestID, "")
			return
		}
		handler.ServeHTTP(guard, request)
	})
}

// routePath 返回 BasePath + 固定路径。
func (s *Server) routePath(path string) string { return s.basePath + path }

// endpoint 返回 issuer + 固定路径（用于发现文档）。
func (s *Server) endpoint(path string) string { return s.issuer + path }

// issuerOrigin 返回 issuer 的 scheme://host（同源校验用）。
func validateIssuer(basePath string, service *oidc.Service) (string, string, error) {
	document := service.Discovery()
	issuer := strings.TrimSpace(document.Issuer)
	if issuer == "" {
		return "", "", fmt.Errorf("%w: OIDC issuer 为空", ErrOptionsInvalid)
	}
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" ||
		parsed.RawQuery != "" {
		return "", "", fmt.Errorf("%w: OIDC issuer 不是合法绝对地址", ErrOptionsInvalid)
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())) {
		return "", "", fmt.Errorf("%w: OIDC issuer 必须是 https（回环地址可用 http）", ErrOptionsInvalid)
	}
	issuerPath := strings.TrimSuffix(parsed.Path, "/")
	if issuerPath != basePath {
		return "", "", fmt.Errorf("%w: OIDC issuer 路径(%q)必须与 BasePath(%q) 一致",
			ErrOptionsInvalid, issuerPath, basePath)
	}
	expected := map[string]string{
		"authorization_endpoint": issuer + PathAuthorize,
		"token_endpoint":         issuer + PathToken,
		"userinfo_endpoint":      issuer + PathUserInfo,
		"jwks_uri":               issuer + PathJWKS,
	}
	actual := map[string]string{
		"authorization_endpoint": document.AuthorizationEndpoint,
		"token_endpoint":         document.TokenEndpoint,
		"userinfo_endpoint":      document.UserInfoEndpoint,
		"jwks_uri":               document.JWKSURI,
	}
	for name, want := range expected {
		if actual[name] != want {
			return "", "", fmt.Errorf(
				"%w: OIDC %s(%q)必须等于 %q（与 protocolapi 挂载路径一致）",
				ErrOptionsInvalid, name, actual[name], want)
		}
	}
	return issuer, parsed.Scheme + "://" + parsed.Host, nil
}

// isLoopbackHost 判断主机是否回环地址（含 localhost 与 IP 回环）。
func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	trimmed := strings.Trim(host, "[]")
	return trimmed == "127.0.0.1" || trimmed == "::1"
}

// validCookieName 校验 Cookie 名是合法 token（不接受空、控制字符、分隔符）。
func validCookieName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for index := 0; index < len(name); index++ {
		character := name[index]
		if character <= 0x20 || character >= 0x7f {
			return false
		}
		switch character {
		case '(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?',
			'=', '{', '}':
			return false
		}
	}
	return true
}

// qrloginValidClientID 做轻量的应用 ID 格式校验（与服务层同一约定：app_ + 32 hex）。
func qrloginValidClientID(clientID string) bool {
	if len(clientID) != len("app_")+32 || !strings.HasPrefix(clientID, "app_") {
		return false
	}
	for _, character := range clientID[len("app_"):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

// requestID 生成或复用合法请求编号。X-Request-ID 只用于关联排障，不参与授权；
// 非法值忽略并重新生成，绝不回显请求里的任意内容。
func (s *Server) requestID(request *http.Request) string {
	if request != nil {
		values := request.Header.Values("X-Request-ID")
		if len(values) == 1 {
			candidate := strings.TrimSpace(values[0])
			if candidate != "" && candidate == values[0] && len(candidate) <= 64 &&
				validRequestID(candidate) {
				return candidate
			}
		}
	}
	buffer := make([]byte, requestIDRandomBytes)
	if _, err := io.ReadFull(s.random, buffer); err != nil {
		return requestIDPrefix + "unavailable"
	}
	return requestIDPrefix + encodeHex(buffer)
}

// validRequestID 与既有请求编号约定一致：可见 ASCII 字母数字与 "._-"。
func validRequestID(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

// sortStrings 是小型稳定排序（避免为一处排序引入新依赖）。
func sortStrings(values []string) {
	for index := 1; index < len(values); index++ {
		for cursor := index; cursor > 0 && values[cursor] < values[cursor-1]; cursor-- {
			values[cursor], values[cursor-1] = values[cursor-1], values[cursor]
		}
	}
}

// encodeHex 把字节编码为小写十六进制。
func encodeHex(buffer []byte) string {
	const alphabet = "0123456789abcdef"
	output := make([]byte, len(buffer)*2)
	for index, value := range buffer {
		output[index*2] = alphabet[value>>4]
		output[index*2+1] = alphabet[value&0x0f]
	}
	return string(output)
}

// withSessionReauthSignals 把协议端点上已验证会话的近期强认证事实传给敏感操作
// 策略。协议端点没有页面层的附加 reauth 交互；会话本身已完成强认证且仍在
// 策略有效期内时，Bearer/会话 Cookie 的确认请求本身即用户确认。没有有效强认证
// 时保持原上下文，由 oauthflow/qrlogin fail-closed 拒绝。
func (s *Server) withSessionReauthSignals(ctx context.Context, secret string) context.Context {
	if s == nil || s.opts.Sessions == nil || strings.TrimSpace(secret) == "" {
		return ctx
	}
	record, err := s.opts.Sessions.Validate(ctx, secret)
	if err != nil || record.StrongAuthVerifiedAt.IsZero() {
		return ctx
	}
	return reauth.WithSignals(ctx, reauth.Signals{VerifiedAt: record.StrongAuthVerifiedAt,
		Strength: policy.StrengthStrong, Complete: true, Confirmed: true})
}
