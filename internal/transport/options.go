// Package transport 实现 login 的标准 net/http Handler 装配、路由、统一错误
// 响应、可信身份传递、机器可读 OpenAPI 与 W3C Extended 访问日志。
//
// 本包只提供传输层基础能力，不实现具体业务接口：
//   - 生产路由只有最小健康端点和 OpenAPI 文档；测试路由只能由测试构造器注入，
//     不会出现在公开构造函数里。
//   - 路径按固定前缀严格匹配，不做“清理后仍然命中”的归一化：编码斜杠、重复
//     斜杠、点段、反斜杠和百分号编码在到达路由前被拒绝，避免绕过路由权限。
//   - 统一业务错误 JSON 只用于 login 自己的 API；/oauth2 前缀保留给未来 OAuth
//     标准协议响应，不被统一错误信封覆盖。
//   - 身份必须由注入的可信解析函数从请求建立，绝不读取客户端自填的操作者 ID；
//     公开健康端点不依赖身份解析，认证提供方故障时仍可探活。
//   - 访问日志省略查询参数、认证头、Cookie 与正文；字段经过 W3C Extended
//     转义，防止日志注入；写入失败只告警，不改变响应，也不进入安全审计。
//   - 浏览器请求防护由 Protection 选项控制：可信客户端地址、多维限流、昂贵
//     请求预算、请求期限/响应超时、并发上限、精确来源 CORS、安全响应头与
//     Cookie 会话 CSRF 契约；默认启用安全默认值。
package transport

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const (
	// DefaultMaxBodyBytes 是请求体默认上限（1 MiB）。
	DefaultMaxBodyBytes int64 = 1 << 20
	// MinMaxBodyBytes/MaxMaxBodyBytes 是请求体上限允许范围（1 KiB～16 MiB）。
	MinMaxBodyBytes int64 = 1 << 10
	MaxMaxBodyBytes int64 = 16 << 20
	// MaxPrefixBytes 是路径前缀最大长度。
	MaxPrefixBytes = 128
	// MaxQueryBytes 是原始查询串上限（8 KiB），超出返回 414，避免解析放大。
	MaxQueryBytes = 8 << 10
	// MaxPathBytes 是请求路径上限，超出返回 414。
	MaxPathBytes = 2 << 10
	// OAuthReservedPrefix 是保留给未来 OAuth/OIDC 标准响应空间的路径前缀。
	OAuthReservedPrefix = "/oauth2"
	// healthSuffix/openAPISuffix 是固定路由后缀，最终路径 = 前缀 + 后缀。
	healthSuffix  = "/healthz"
	openAPISuffix = "/openapi.json"
	// healthBody 是最小健康端点响应：不包含配置、数据库或密钥信息。
	healthBody = `{"status":"ok"}`
	// clientClosedStatus 是客户端在响应前取消请求时访问日志使用的状态码
	// （nginx 约定，非标准 HTTP 状态）；不向客户端承诺该状态。
	clientClosedStatus = 499
	// maxErrorMessageBytes 是传输层自行构造的公开错误说明上限。
	maxErrorMessageBytes = 200
)

// ErrorCodeInfo 是错误码注册表在传输层的只读投影；由公开包注入，避免内部包
// 反向依赖根包造成导入环。
type ErrorCodeInfo struct {
	Code       string
	Category   string
	Message    string
	HTTPStatus int
}

// Identity 是传输层内部的可信身份；只由注入的 ResolveIdentity 建立。
type Identity struct {
	Kind      string
	SubjectID string
	AppID     string
}

// ResolveIdentityFunc 从请求建立可信身份。实现必须基于已验证的会话、令牌或
// 宿主可信上下文，不得读取客户端自填的 user_id/actor_id 等字段。
type ResolveIdentityFunc func(ctx context.Context, r *http.Request) (Identity, error)

// IdentityError 让公开包把 AppError 映射为传输层身份错误（码、状态、公开说明），
// 内部包不需要依赖根包的 AppError 类型。
type IdentityError struct {
	Code    string
	Status  int
	Message string
}

// Error 返回公开说明；不包含内部原因。
func (e *IdentityError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

// Options 是构造传输层 Handler 的依赖；由公开包填充，其他包不应直接使用。
type Options struct {
	// Prefix 是固定路径前缀：空字符串或 /segment(/segment)*，不允许尾斜杠。
	Prefix string
	// MaxBodyBytes 是请求体上限；0 使用默认值。
	MaxBodyBytes int64
	// ErrorCodes 是错误码注册表投影；必须非空。
	ErrorCodes []ErrorCodeInfo
	// NewRequestID 生成请求编号；必填，由公开包提供。
	NewRequestID func() string
	// ValidateRequestID 校验外部请求编号；必填，由公开包提供。
	ValidateRequestID func(string) error
	// ResolveIdentity 建立可信身份；nil 表示本 Handler 不建立身份，受保护
	// 路由会默认拒绝。
	ResolveIdentity ResolveIdentityFunc
	// Logger 是运行日志器；nil 使用丢弃输出。
	Logger *slog.Logger
	// AccessLogWriter 是 W3C Extended 访问日志输出；nil 表示不写访问日志
	// （嵌入模式默认静默，独立服务必须注入）。
	AccessLogWriter io.Writer
	// OnAccessLogError 接收访问日志写入失败；nil 时使用 Logger.Error 告警。
	OnAccessLogError func(error)
	// Now 是可注入时钟；nil 使用 time.Now。
	Now func() time.Time
	// Version 是 OpenAPI info.version；空字符串使用 "devel"。
	Version string
	// Protection 是限流、超时、并发、CORS、CSRF 与安全响应头配置；nil 使用安全
	// 默认值。公开包负责把 HTTPProtectionOptions 转换成本类型。
	Protection *ProtectionOptions

	// extraRoutes 仅由同包测试构造器注入；生产 New 不设置。
	extraRoutes []route
}

// normalizeOptions 校验并填充传输层选项。
func normalizeOptions(options Options) (Options, error) {
	prefix, err := NormalizePrefix(options.Prefix)
	if err != nil {
		return Options{}, err
	}
	options.Prefix = prefix
	maxBody := options.MaxBodyBytes
	if maxBody == 0 {
		maxBody = DefaultMaxBodyBytes
	}
	if maxBody < MinMaxBodyBytes || maxBody > MaxMaxBodyBytes {
		return Options{}, fmt.Errorf("请求体上限必须在 %d～%d 字节之间", MinMaxBodyBytes, MaxMaxBodyBytes)
	}
	options.MaxBodyBytes = maxBody
	if len(options.ErrorCodes) == 0 {
		return Options{}, fmt.Errorf("错误码注册表投影不能为空")
	}
	codeIndex := make(map[string]struct{}, len(options.ErrorCodes))
	for _, code := range options.ErrorCodes {
		if strings.TrimSpace(code.Code) == "" {
			return Options{}, fmt.Errorf("错误码注册表投影包含空错误码")
		}
		if _, exists := codeIndex[code.Code]; exists {
			return Options{}, fmt.Errorf("错误码注册表投影包含重复错误码 %q", code.Code)
		}
		codeIndex[code.Code] = struct{}{}
	}
	if options.NewRequestID == nil {
		options.NewRequestID = fallbackRequestID
	}
	if options.ValidateRequestID == nil {
		options.ValidateRequestID = validateCorrelationFallback
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	options.Logger = logger
	now := options.Now
	if now == nil {
		now = time.Now
	}
	options.Now = now
	if options.Version == "" {
		options.Version = "devel"
	}
	return options, nil
}

// fallbackRequestID 只在 Options.NewRequestID 缺失时使用（仅内部测试路径）。
func fallbackRequestID() string {
	var random [16]byte
	if _, err := rand.Read(random[:]); err == nil {
		return "req_" + hex.EncodeToString(random[:])
	}
	return fmt.Sprintf("req_%016x", time.Now().UnixNano())
}

// validateCorrelationFallback 是 Options.ValidateRequestID 缺失时的保守校验。
func validateCorrelationFallback(id string) error {
	if id == "" || len(id) > 64 || !isASCIIAlnum(id[0]) {
		return fmt.Errorf("请求编号格式无效")
	}
	for index := 0; index < len(id); index++ {
		character := id[index]
		if !isASCIIAlnum(character) && character != '.' && character != '_' && character != '-' {
			return fmt.Errorf("请求编号格式无效")
		}
	}
	return nil
}

// isASCIIAlnum 报告字节是否为 ASCII 字母或数字。
func isASCIIAlnum(character byte) bool {
	return (character >= 'a' && character <= 'z') ||
		(character >= 'A' && character <= 'Z') ||
		(character >= '0' && character <= '9')
}
