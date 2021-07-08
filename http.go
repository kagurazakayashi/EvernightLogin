package login

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/transport"
)

const (
	// DefaultHTTPMaxBodyBytes 是 HTTP 请求体默认上限（1 MiB）。
	DefaultHTTPMaxBodyBytes int64 = transport.DefaultMaxBodyBytes
	// MinHTTPMaxBodyBytes/MaxHTTPMaxBodyBytes 是 HTTP 请求体上限允许范围。
	MinHTTPMaxBodyBytes int64 = transport.MinMaxBodyBytes
	MaxHTTPMaxBodyBytes int64 = transport.MaxMaxBodyBytes
	// MaxHTTPPrefixBytes 是固定路径前缀最大长度。
	MaxHTTPPrefixBytes = transport.MaxPrefixBytes
	// OAuthReservedPathPrefix 是保留给未来 OAuth/OIDC 标准协议响应的路径前缀；
	// 该前缀下的响应不使用统一业务错误 JSON。
	OAuthReservedPathPrefix = transport.OAuthReservedPrefix
)

// ErrIdentityInvalid 表示宿主提供的可信身份结构无效。它不是认证失败本身，而是
// 宿主身份建立契约被违反；HTTP 处理会把它映射为 AUTH_FAILED 并拒绝。
var ErrIdentityInvalid = errors.New("身份结构无效")

// IdentityKind 是可信身份的类型。身份只能由已经验证的会话、令牌或宿主可信
// 上下文建立，不能由请求参数或客户端自填字段声明。
type IdentityKind string

const (
	// IdentityKindUser 表示已认证用户。
	IdentityKindUser IdentityKind = "user"
	// IdentityKindApplication 表示应用服务身份（如 Client Credentials）；必须
	// 带 AppID，且不冒充某个用户。
	IdentityKindApplication IdentityKind = "application"
	// IdentityKindSystem 表示宿主系统组件身份；不得由普通 HTTP 客户端建立。
	IdentityKindSystem IdentityKind = "system"
)

// Valid 报告身份类型是否已定义。
func (k IdentityKind) Valid() bool {
	switch k {
	case IdentityKindUser, IdentityKindApplication, IdentityKindSystem:
		return true
	default:
		return false
	}
}

// Identity 是 HTTP 层建立并传递给服务层的可信身份。SubjectID 是稳定不透明 ID；
// AppID 是可选应用范围（应用身份必填）。显示名、邮箱等资料不放在这里。
type Identity struct {
	Kind      IdentityKind
	SubjectID string
	AppID     string
}

// Validate 校验身份结构：类型已定义、SubjectID 非空且是受限 ID 字符集、应用
// 身份必须带 AppID。它只做结构校验；权限判断必须由服务层完成。
func (i Identity) Validate() error {
	if !i.Kind.Valid() {
		return fmt.Errorf("%w: 身份类型未定义", ErrIdentityInvalid)
	}
	if i.SubjectID == "" {
		return fmt.Errorf("%w: 身份主体 ID 不能为空", ErrIdentityInvalid)
	}
	if err := validateCorrelationID("身份主体 ID", i.SubjectID); err != nil {
		return fmt.Errorf("%w: %v", ErrIdentityInvalid, err)
	}
	if i.Kind == IdentityKindApplication && i.AppID == "" {
		return fmt.Errorf("%w: 应用身份必须带应用范围", ErrIdentityInvalid)
	}
	if i.AppID != "" {
		if err := validateCorrelationID("应用范围 ID", i.AppID); err != nil {
			return fmt.Errorf("%w: %v", ErrIdentityInvalid, err)
		}
	}
	return nil
}

// IdentityResolver 从请求建立可信身份。实现必须基于已验证会话、OAuth 令牌或
// 宿主可信上下文；不得读取客户端自填的 user_id、actor_id、is_root 等字段。
//
// 返回错误表示身份建立失败；如果返回 *AppError 则保留其错误码与 HTTP 状态，
// 其他错误统一映射为 AUTH_FAILED（401）且不向调用者暴露细节。
type IdentityResolver interface {
	ResolveIdentity(ctx context.Context, request *http.Request) (Identity, error)
}

// IdentityResolverFunc 是 IdentityResolver 的函数适配器。
type IdentityResolverFunc func(ctx context.Context, request *http.Request) (Identity, error)

// ResolveIdentity 实现 IdentityResolver。
func (f IdentityResolverFunc) ResolveIdentity(ctx context.Context, request *http.Request) (Identity, error) {
	if f == nil {
		return Identity{}, fmt.Errorf("%w: 身份解析函数为空", ErrIdentityInvalid)
	}
	return f(ctx, request)
}

// HTTPOptions 是构造标准 net/http Handler 的显式依赖。
//
// Handler 只提供本步安全的最小能力：健康检查、OpenAPI 文档与默认启用的浏览器
// 请求防护（限流、超时/并发、CORS、安全响应头、Cookie 会话 CSRF 契约）。身份
// 解析函数用于未来受保护接口与宿主中间件；公开健康端点不依赖它。
type HTTPOptions struct {
	// Prefix 是固定路径前缀：空字符串或 /segment(/segment)*；不能以斜杠结尾。
	// 前缀不匹配的路径一律 404，不做清理重写。
	Prefix string
	// MaxBodyBytes 是请求体上限；0 使用 DefaultHTTPMaxBodyBytes。
	MaxBodyBytes int64
	// IdentityResolver 建立可信身份；nil 表示本 Handler 不建立身份，需要身份的
	// 路由会默认拒绝（fail-closed）。
	IdentityResolver IdentityResolver
	// Logger 是运行日志器；nil 时使用丢弃输出。Logger 与访问日志、审计分开。
	Logger *slog.Logger
	// AccessLogWriter 是 W3C Extended 访问日志输出；nil 表示不写访问日志。
	// 独立服务必须注入，并把输出交给受控的日志轮转/保留流程。
	AccessLogWriter io.Writer
	// OnAccessLogError 接收访问日志写入失败；nil 时通过 Logger.Error 告警。
	// 访问日志写入失败不改变 HTTP 响应，也不影响安全审计语义。
	OnAccessLogError func(error)
	// Now 是可注入时钟；nil 使用 time.Now。访问日志时间、限流窗口与测试使用该时钟。
	Now func() time.Time
	// Protection 是限流、资源预算、请求超时/并发、CORS、安全响应头、Cookie 与
	// CSRF 契约；nil 使用安全默认值。详见 HTTPProtectionOptions。
	Protection *HTTPProtectionOptions
	// UI 是可选的内置 HTML 页面处理器（例如 login.NewWebUI 的返回值）。挂载后
	// 非 API 路径交给页面处理器，并复用同一请求编号、访问日志、客户端 IP 限流与
	// CSRF 中间件；页面显式使用 PageContentSecurityPolicy（不再使用 API 的
	// default-src 'none'）。nil 表示本 Handler 只提供 API，不服务 HTML。
	UI *UIHTTPOptions
}

// UIHTTPOptions 是 HTML 页面挂载配置。Handler 由宿主提供（通常为
// login.NewWebUI 返回值），PageContentSecurityPolicy 必须包含页面安全基线，
// 可用 DefaultUIPageContentSecurityPolicy。
type UIHTTPOptions struct {
	Handler                   http.Handler
	PageContentSecurityPolicy string
}

// NewHTTPHandler 构造标准 net/http Handler。生产实例只注册固定预热用的健康
// 端点与 OpenAPI 文档；未鉴权的管理功能、调试路由和测试路由都不会注册。默认
// 启用安全响应头、多维限流、请求期限/并发上限与精确 CORS 配置入口；CSRF 默认
// 关闭，需宿主显式提供校验器并绑定 Cookie 会话契约。
//
// 选项非法时返回 CONFIG_INVALID 统一错误，不创建任何监听、协程或文件。
// NewHTTPHandler 不创建服务器、不监听端口、不启动后台 goroutine。
// uiConfigOf 把公开 UI 挂载配置转换为传输层内部配置。
func uiConfigOf(options *UIHTTPOptions) *transport.UIConfig {
	if options == nil {
		return nil
	}
	return &transport.UIConfig{Handler: options.Handler,
		PageContentSecurityPolicy: options.PageContentSecurityPolicy}
}

func NewHTTPHandler(options HTTPOptions) (http.Handler, error) {
	protection, err := normalizeHTTPProtection(options.Protection)
	if err != nil {
		return nil, NewAppError(CodeConfigInvalid, "HTTP 防护配置无效", WithCause(err))
	}
	handler, err := transport.New(transport.Options{
		Prefix:            options.Prefix,
		MaxBodyBytes:      options.MaxBodyBytes,
		ErrorCodes:        transportErrorCodes(),
		NewRequestID:      NewRequestID,
		ValidateRequestID: ValidateRequestID,
		ResolveIdentity:   resolveIdentityAdapter(options.IdentityResolver),
		Logger:            options.Logger,
		AccessLogWriter:   options.AccessLogWriter,
		OnAccessLogError:  options.OnAccessLogError,
		Now:               options.Now,
		Version:           CurrentBuildInfo().Version,
		Protection:        protection,
		UI:                uiConfigOf(options.UI),
	})
	if err != nil {
		return nil, NewAppError(CodeConfigInvalid, "HTTP 处理程序配置无效", WithCause(err))
	}
	return handler, nil
}

// OpenAPIDocument 生成指定路径前缀的机器可读 OpenAPI 文档。错误码 enum 与
// x-login-error-registry 直接来自错误码注册表，新增错误码时不会遗漏。
//
// prefix 的合法性规则与 HTTPOptions.Prefix 相同；非法前缀返回 CONFIG_INVALID。
func OpenAPIDocument(prefix string) ([]byte, error) {
	document, err := transport.OpenAPIDocument(prefix, transportErrorCodes(), CurrentBuildInfo().Version)
	if err != nil {
		return nil, NewAppError(CodeConfigInvalid, "OpenAPI 文档前缀无效", WithCause(err))
	}
	return document, nil
}

// IdentityFromContext 返回 HTTP Handler 或宿主中间件放入请求上下文的可信身份。
// 服务层只能使用这里的身份做授权判断；没有身份表示匿名访问，由具体接口决定
// 是否允许。
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	internalIdentity, ok := transport.IdentityFromContext(ctx)
	if !ok {
		return Identity{}, false
	}
	return Identity{
		Kind:      IdentityKind(internalIdentity.Kind),
		SubjectID: internalIdentity.SubjectID,
		AppID:     internalIdentity.AppID,
	}, true
}

// WithIdentity 把已由可信边界建立的身份放入上下文，供宿主或测试中间件使用。
// 身份必须通过 Validate；不要把客户端请求字段直接转成 Identity。
func WithIdentity(ctx context.Context, identity Identity) (context.Context, error) {
	if err := identity.Validate(); err != nil {
		return nil, err
	}
	return transport.WithIdentity(ctx, transport.Identity{
		Kind:      string(identity.Kind),
		SubjectID: identity.SubjectID,
		AppID:     identity.AppID,
	}), nil
}

// RequestIDFromContext 返回当前请求的查询编号；没有时返回空字符串。请求编号
// 不是凭证，不能用于授权判断。
func RequestIDFromContext(ctx context.Context) string {
	return transport.RequestIDFromContext(ctx)
}

// ClientServiceIdentityFromContext 返回独立 login.Server 的 mTLS 边界验证并显式
// 映射后的可信服务身份名称。未启用客户端证书认证、嵌入模式自行监听或匿名连接
// 时返回空字符串与 false。
//
// 该身份来自 TLS 客户端证书的显式“DNS 名称 -> 服务身份”映射，不是用户身份，
// 不会被当作 root 或自动获得任何业务权限；服务层必须独立授权。它也不能由请求
// 头、查询参数或请求体声明。
func ClientServiceIdentityFromContext(ctx context.Context) (string, bool) {
	return transport.ClientServiceIdentityFromContext(ctx)
}

// transportErrorCodes 把错误码注册表投影为内部传输层只读结构，避免内部包反向
// 依赖根包。
func transportErrorCodes() []transport.ErrorCodeInfo {
	infos := make([]transport.ErrorCodeInfo, 0, len(errorCodeDefinitions))
	for _, definition := range errorCodeDefinitions {
		infos = append(infos, transport.ErrorCodeInfo{
			Code:       string(definition.Code),
			Category:   string(definition.Category),
			Message:    definition.DefaultMessage,
			HTTPStatus: definition.HTTPStatus,
		})
	}
	return infos
}

// resolveIdentityAdapter 把公开的身份解析契约适配为内部函数，并保证失败时只
// 使用稳定的公开错误码与消息。
func resolveIdentityAdapter(resolver IdentityResolver) transport.ResolveIdentityFunc {
	if resolver == nil {
		return nil
	}
	return func(ctx context.Context, request *http.Request) (transport.Identity, error) {
		identity, err := resolver.ResolveIdentity(ctx, request)
		if err != nil {
			return transport.Identity{}, identityFailure(err)
		}
		if err := identity.Validate(); err != nil {
			return transport.Identity{}, identityFailure(err)
		}
		return transport.Identity{
			Kind:      string(identity.Kind),
			SubjectID: identity.SubjectID,
			AppID:     identity.AppID,
		}, nil
	}
}

// identityFailure 把身份建立失败映射为内部 IdentityError，保留已注册 AppError 的
// 公开码与状态；其他错误统一 AUTH_FAILED，绝不泄露内部原因。
func identityFailure(err error) *transport.IdentityError {
	if appError, ok := AsAppError(err); ok {
		status := appError.HTTPStatus()
		if status < 400 || status > 599 {
			status = http.StatusUnauthorized
		}
		return &transport.IdentityError{
			Code:    string(appError.Code()),
			Status:  status,
			Message: appError.Message(),
		}
	}
	return &transport.IdentityError{
		Code:    string(CodeAuthFailed),
		Status:  http.StatusUnauthorized,
		Message: "无法完成登录",
	}
}
