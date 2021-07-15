// Package qrlogin 实现"已登录 APP 扫网页二维码并确认"的自定义登录流程（步骤 58）。
//
// 它与标准 OAuth Device Authorization Grant（internal/oauthflow，步骤 57）**完全
// 分别命名、分别存储、分别处理**，共用既有会话/客户端/审计/限流基础，但绝不混用
// 设备码、user_code 或 Token 端点语义。
//
// 角色与信任边界：
//   - 发起端（网页）：无登录态即可创建短时请求；创建响应一次性返回高熵领取绑定
//     （ClaimSecret）。二维码内容只包含一次性请求标识（QR 只放 request_id，不含
//     Token/密码/会话秘密/领取绑定），所以二维码被复制/截图不足以领取登录结果。
//   - 确认端（APP）：必须出示真实完整普通会话（internal/session 校验），服务端从
//     会话读取用户与安全版本，绝不接受请求参数自称的用户/应用。批准前按步骤 39
//     敏感策略要求近期认证（未接线 fail-closed），批准绑定用户+会话+安全版本+
//     认证方法快照+目标应用+请求版本；拒绝、取消是流程状态而非系统故障。
//   - 领取：只有持有领取绑定且请求已批准、未过期、未被领取的发起端能领取；领取时
//     重新核对账户/成员/应用/客户端/确认端会话/请求状态，任一变化都 fail-closed。
//     领取转换使用 internal/session 的受门控登录批准签发（只发目标应用会话，不发
//     任何 Token，不创造通用 Token 交换后门）。
//
// 安全不变量：
//   - 领取绑定高熵（32 字节随机），库中只保存 keyring HMAC-SHA256 摘要 + key_id；
//     明文只在创建响应出现一次，默认字符串化/格式化/JSON 全部脱敏。
//   - 状态机 pending→approved→claimed，pending/approved→denied/cancelled；过期由
//     服务层按 expires_at_ms 惰性判断。状态变更在审计事务中条件更新，保证并发
//     批准/领取单赢家；版本号防止旧页面替换请求。
//   - 缺少 Store/Audit/Clients/Applications/Sessions/SessionIssuer/Reauth/Keyring
//     任一项拒绝构造；全局开关与应用白名单默认关闭；功能关闭或应用未列入白名单
//     一律拒绝（默认拒绝）。
//   - 本包不渲染页面/二维码图片、不注册 HTTP 全局路由、不启动监听、不写日志中的
//     秘密；HTTP 装配与页面属后续步骤。
package qrlogin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
)

// 领域错误哨兵。错误文本不包含领取绑定、二维码内容或其他秘密。
var (
	// ErrOptionsInvalid 表示构造依赖或配置非法。
	ErrOptionsInvalid = errors.New("扫码登录选项无效")
	// ErrInvalidRequest 表示请求参数/二维码载荷非法。
	ErrInvalidRequest = errors.New("扫码登录请求无效")
	// ErrQRLoginDisabled 表示全局开关关闭或应用未列入白名单（拒绝，不泄露配置）。
	ErrQRLoginDisabled = errors.New("扫码登录未启用")
	// ErrClientUnavailable 表示目标客户端不存在或应用停用。
	ErrClientUnavailable = errors.New("目标应用不可用")
	// ErrAccessDenied 表示当前会话/账户/成员或确认端身份不允许完成该操作。
	ErrAccessDenied = errors.New("当前身份不允许完成扫码登录")
	// ErrRequestNotFound 表示请求不存在或已失效；对外统一，避免状态探测。
	ErrRequestNotFound = errors.New("扫码登录请求不存在或已失效")
	// ErrRequestExpired 表示请求已过期。
	ErrRequestExpired = errors.New("扫码登录请求已过期")
	// ErrRequestDenied 表示用户已明确拒绝。
	ErrRequestDenied = errors.New("用户已拒绝本次扫码登录")
	// ErrRequestCancelled 表示请求已被发起端取消或重新生成。
	ErrRequestCancelled = errors.New("扫码登录请求已取消")
	// ErrRequestNotApproved 表示请求尚未批准（等待用户确认）。
	ErrRequestNotApproved = errors.New("扫码登录请求尚未批准")
	// ErrAlreadyClaimed 表示登录结果已被领取（结果只能成功消费一次）。
	ErrAlreadyClaimed = errors.New("扫码登录结果已被领取")
	// ErrVersionConflict 表示请求版本已变化（旧页面/并发替换）。
	ErrVersionConflict = errors.New("扫码登录请求状态已变化")
	// ErrRateLimited 表示请求过于频繁。
	ErrRateLimited = errors.New("扫码登录请求过于频繁")
	// ErrSessionInvalid 表示确认端会话无效/已撤销/账户或成员状态变化。
	ErrSessionInvalid = errors.New("确认端会话无效或已失效")
	// ErrStoreUnavailable 表示存储暂时不可用（业务必须拒绝）。
	ErrStoreUnavailable = errors.New("扫码登录存储暂时不可用")
	// ErrAuditUnavailable 表示关键操作未能可靠记录。
	ErrAuditUnavailable = errors.New("关键操作未能可靠记录")
)

// ErrorCode 是根包错误码注册表的稳定字面值投影（只复用既有 46 码，不新增）。
type ErrorCode string

const (
	// CodeReqInvalid 请求内容不符合要求。
	CodeReqInvalid ErrorCode = "REQ_INVALID"
	// CodeAuthFailed 认证失败（确认端会话无效）。
	CodeAuthFailed ErrorCode = "AUTH_FAILED"
	// CodeAccessDenied 请求未获准（禁用/跨应用/不存在等对外统一）。
	CodeAccessDenied ErrorCode = "ACCESS_DENIED"
	// CodeChallengeInvalid 验证请求无效或已失效（过期/已消费/已取消）。
	CodeChallengeInvalid ErrorCode = "CHALLENGE_INVALID"
	// CodeConflict 状态冲突（并发/版本变化）。
	CodeConflict ErrorCode = "CONFLICT"
	// CodeRateLimited 请求过于频繁。
	CodeRateLimited ErrorCode = "RATE_LIMITED"
	// CodeClientDisabled 应用已停用。
	CodeClientDisabled ErrorCode = "CLIENT_DISABLED"
	// CodeDBUnavailable 数据库暂时不可用。
	CodeDBUnavailable ErrorCode = "DB_UNAVAILABLE"
	// CodeAuditWriteFailed 关键操作未能可靠记录。
	CodeAuditWriteFailed ErrorCode = "AUDIT_WRITE_FAILED"
	// CodeInternalError 服务发生未预期错误。
	CodeInternalError ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把扫码登录领域错误映射为已登记错误码。业务拒绝由方法返回的稳定
// 错误哨兵表达；协议/依赖错误同样返回对应的已登记码。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidRequest):
		return CodeReqInvalid
	case errors.Is(err, ErrQRLoginDisabled), errors.Is(err, ErrAccessDenied),
		errors.Is(err, ErrRequestDenied):
		return CodeAccessDenied
	case errors.Is(err, ErrClientUnavailable):
		return CodeClientDisabled
	case errors.Is(err, ErrSessionInvalid):
		return CodeAuthFailed
	case errors.Is(err, ErrRequestNotFound), errors.Is(err, ErrRequestExpired),
		errors.Is(err, ErrRequestCancelled), errors.Is(err, ErrRequestNotApproved),
		errors.Is(err, ErrAlreadyClaimed):
		return CodeChallengeInvalid
	case errors.Is(err, ErrVersionConflict):
		return CodeConflict
	case errors.Is(err, ErrRateLimited):
		return CodeRateLimited
	case errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	default:
		return CodeInternalError
	}
}

// 扫描登录请求状态（持久化状态；过期由 ExpiresAt 惰性派生，不落库）。
const (
	// StatusPending 表示等待用户在 APP 确认。
	StatusPending = "pending"
	// StatusApproved 表示已批准，等待发起端领取。
	StatusApproved = "approved"
	// StatusDenied 表示用户明确拒绝（终态）。
	StatusDenied = "denied"
	// StatusCancelled 表示发起端取消/重新生成（终态）。
	StatusCancelled = "cancelled"
	// StatusClaimed 表示登录结果已被领取（终态，只能成功一次）。
	StatusClaimed = "claimed"
)

// 查询结果的派生状态（含惰性过期）。
const (
	// QueryPending 等待确认。
	QueryPending = "pending"
	// QueryApproved 已批准待领取。
	QueryApproved = "approved"
	// QueryDenied 已拒绝。
	QueryDenied = "denied"
	// QueryCancelled 已取消。
	QueryCancelled = "cancelled"
	// QueryClaimed 已领取。
	QueryClaimed = "claimed"
	// QueryExpired 已过期（由 expires_at 派生）。
	QueryExpired = "expired"
)

// 协议常量与边界。
const (
	// QRPayloadScheme 是二维码载荷固定 scheme；APP 必须只从载荷取请求标识，
	// 绝不按载荷中的任意主机发请求（签发方地址由宿主配置固定）。
	QRPayloadScheme = "evernight-login"
	// QRPayloadHost 是二维码载荷固定 host 段。
	QRPayloadHost = "app-qr"
	// QRPayloadVersion 是二维码载荷版本。
	QRPayloadVersion = "1"
	// MaxQRPayloadBytes 是二维码载荷最大长度。
	MaxQRPayloadBytes = 256
	// requestIDPrefix 是请求标识前缀；requestIDRandomBytes 是随机字节数（128 位）。
	requestIDPrefix      = "qrl_"
	requestIDRandomBytes = 16
	// claimSecretRandomBytes 是领取绑定随机字节数（256 位）。
	claimSecretRandomBytes = 32
	// maxClaimSecretBytes 是客户端提交领取绑定的最大长度。
	maxClaimSecretBytes = 128
	// claimDigestDomain 是领取绑定摘要域（与其它秘密摘要域区分）。
	claimDigestDomain = "app-qr-login-v1"
	// DefaultRequestTTL 是请求默认有效期（短时）。
	DefaultRequestTTL = 2 * time.Minute
	// MinRequestTTL/MaxRequestTTL 是有效期边界。
	MinRequestTTL = 30 * time.Second
	MaxRequestTTL = 5 * time.Minute
	// DefaultClaimInterval 是领取状态查询默认最小间隔。
	DefaultClaimInterval = time.Second
	// MinClaimInterval/MaxClaimInterval 是最小间隔边界。
	MinClaimInterval = time.Second
	MaxClaimInterval = 5 * time.Second
	// MaxScopes 是请求展示 scope 数量上限。
	MaxScopes = 50
	// MaxScopeTokenBytes 是单项 scope 长度上限。
	MaxScopeTokenBytes = 128
	// MaxRequesterUserAgentBytes/MaxRequesterAddressBytes 是发起端展示信息上限。
	MaxRequesterUserAgentBytes = 256
	MaxRequesterAddressBytes   = 128
	// MaxAuditRequestIDBytes 是审计请求编号长度上限（与既有请求编号一致）。
	MaxAuditRequestIDBytes = 64
	// confirmationWarning 是 APP 确认时展示的固定风险提醒（中文直白）。
	confirmationWarning = "请确认该二维码确实出现在你本人正在登录的浏览器页面上；" +
		"不要确认他人发来的截图或二维码，确认后对方浏览器会登录为你的账户。"
	// operationApprove 是步骤 39 敏感操作目录中的扫码登录批准操作。
	operationApprove = "app.qr_login.approve"
	// serviceComponentID 是系统审计主体标识。
	serviceComponentID = "qrlogin"
	// maxAllowedClients 是应用白名单上限。
	maxAllowedClients = 200
	// defaultCreatePerMinute 是每客户端每分钟创建请求默认上限。
	defaultCreatePerMinute = 10
	// defaultConfirmPerWindow 是每用户确认尝试默认上限与窗口。
	defaultConfirmPerWindow = 20
	defaultConfirmWindow    = 10 * time.Minute
)

// RequesterInfo 是发起端可展示信息。UserAgent 由客户端自称、Address 来自可信
// 连接边界，两者都不是授权依据；服务端写入前截断并去控制字符。
type RequesterInfo struct {
	UserAgent string
	Address   string
}

// sanitizeRequester 去除控制字符并截断展示信息。
func sanitizeRequester(info RequesterInfo) RequesterInfo {
	return RequesterInfo{
		UserAgent: sanitizeText(info.UserAgent, MaxRequesterUserAgentBytes),
		Address:   sanitizeText(info.Address, MaxRequesterAddressBytes),
	}
}

// sanitizeText 去除控制字符/首尾空白并截断到 max 字节（按字节安全截断）。
func sanitizeText(value string, max int) string {
	value = strings.TrimSpace(value)
	var builder strings.Builder
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			continue
		}
		builder.WriteRune(character)
		if builder.Len() >= max {
			break
		}
	}
	result := builder.String()
	if len(result) > max {
		result = result[:max]
	}
	return result
}

// ClaimSecret 是领取绑定明文。默认字符串化/格式化/JSON 全部脱敏；宿主必须在创建
// 响应中显式 Reveal() 后交给发起端，禁止写入二维码、URL、日志、审计或普通存储。
type ClaimSecret struct{ value string }

// ClaimSecretFromString 从服务端受控存储/签名状态恢复领取绑定文本。它只做格式
// 校验，不证明秘密有效；调用方必须来自可信服务端状态（不得直接取自请求参数）。
func ClaimSecretFromString(value string) (ClaimSecret, error) {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) < 32 || len(trimmed) > 128 {
		return ClaimSecret{}, ErrInvalidRequest
	}
	for index := 0; index < len(trimmed); index++ {
		character := trimmed[index]
		if !(character >= 'A' && character <= 'Z') && !(character >= 'a' && character <= 'z') &&
			!(character >= '0' && character <= '9') && character != '-' && character != '_' {
			return ClaimSecret{}, ErrInvalidRequest
		}
	}
	return ClaimSecret{value: trimmed}, nil
}

// newClaimSecret 用安全随机源生成领取绑定（base64url 无填充，43 字符）。
func newClaimSecret(random io.Reader) (ClaimSecret, error) {
	if random == nil {
		random = rand.Reader
	}
	buffer := make([]byte, claimSecretRandomBytes)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return ClaimSecret{}, fmt.Errorf("%w: 安全随机源不可用", ErrInvalidRequest)
	}
	return ClaimSecret{value: base64RawURL(buffer)}, nil
}

// base64RawURL 把字节编码为无填充 base64url。
func base64RawURL(buffer []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var builder strings.Builder
	builder.Grow((len(buffer)*8 + 5) / 6)
	accumulator := uint(0)
	bits := uint(0)
	for _, value := range buffer {
		accumulator = accumulator<<8 | uint(value)
		bits += 8
		for bits >= 6 {
			bits -= 6
			builder.WriteByte(alphabet[(accumulator>>bits)&0x3f])
		}
	}
	if bits > 0 {
		builder.WriteByte(alphabet[(accumulator<<(6-bits))&0x3f])
	}
	return builder.String()
}

// Reveal 返回领取绑定原文（只用于投递给发起端一次）。
func (s ClaimSecret) Reveal() string { return s.value }

// IsSet 报告领取绑定是否非空；不暴露内容。
func (s ClaimSecret) IsSet() bool { return s.value != "" }

// String 实现 fmt.Stringer，固定脱敏。
func (s ClaimSecret) String() string {
	if s.value == "" {
		return "[UNSET]"
	}
	return "[REDACTED]"
}

// GoString 实现 fmt.GoStringer。
func (s ClaimSecret) GoString() string { return s.String() }

// Format 实现 fmt.Formatter，覆盖 %v/%s/%q/%x 等格式化动词。
func (s ClaimSecret) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(s.String()))
}

// MarshalJSON 实现 json.Marshaler，输出脱敏标记。
func (s ClaimSecret) MarshalJSON() ([]byte, error) { return []byte(`"` + s.String() + `"`), nil }

// QRPayload 是二维码载荷解析结果：只含一次性请求标识与版本。
type QRPayload struct {
	RequestID string
	Version   int
}

// EncodeQRPayload 生成二维码载荷：固定 scheme/host/version，只承载 request_id。
// 宿主可用任意二维码库把该文本渲染为图片；二维码不得包含 Token/密码/领取绑定。
func EncodeQRPayload(requestID string) (string, error) {
	if !validRequestID(requestID) {
		return "", fmt.Errorf("%w: 请求标识非法", ErrInvalidRequest)
	}
	return fmt.Sprintf("%s://%s?v=%s&r=%s", QRPayloadScheme, QRPayloadHost,
		QRPayloadVersion, requestID), nil
}

// ParseQRPayload 严格解析二维码载荷：只接受固定 scheme/host、唯一 v=1 与 r 参数，
// 拒绝 userinfo/fragment/重复参数/额外参数/非 ASCII/超长内容；不信任载荷中的任何
// 主机或回调地址（APP 永远调用宿主配置的固定签发方地址）。
func ParseQRPayload(raw string) (QRPayload, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > MaxQRPayloadBytes {
		return QRPayload{}, fmt.Errorf("%w: 二维码内容为空或过长", ErrInvalidRequest)
	}
	for index := 0; index < len(raw); index++ {
		if raw[index] < 0x21 || raw[index] > 0x7e {
			return QRPayload{}, fmt.Errorf("%w: 二维码内容包含非法字符", ErrInvalidRequest)
		}
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != QRPayloadScheme || parsed.Host != QRPayloadHost ||
		parsed.User != nil || parsed.Fragment != "" || parsed.Path != "" ||
		parsed.RawQuery == "" {
		return QRPayload{}, fmt.Errorf("%w: 二维码内容不是受支持的登录请求", ErrInvalidRequest)
	}
	values, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return QRPayload{}, fmt.Errorf("%w: 二维码参数非法", ErrInvalidRequest)
	}
	if len(values) != 2 || len(values["v"]) != 1 || len(values["r"]) != 1 {
		return QRPayload{}, fmt.Errorf("%w: 二维码参数不是受支持的结构", ErrInvalidRequest)
	}
	if values["v"][0] != QRPayloadVersion {
		return QRPayload{}, fmt.Errorf("%w: 二维码版本不受支持", ErrInvalidRequest)
	}
	requestID := values["r"][0]
	if !validRequestID(requestID) {
		return QRPayload{}, fmt.Errorf("%w: 二维码请求标识非法", ErrInvalidRequest)
	}
	return QRPayload{RequestID: requestID, Version: 1}, nil
}

// validRequestID 校验请求标识格式（qrl_ + 32 位小写十六进制）。
func validRequestID(requestID string) bool {
	if len(requestID) != len(requestIDPrefix)+2*requestIDRandomBytes ||
		!strings.HasPrefix(requestID, requestIDPrefix) {
		return false
	}
	for _, character := range requestID[len(requestIDPrefix):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

// newRequestID 生成一次性请求标识。
func newRequestID(random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	buffer := make([]byte, requestIDRandomBytes)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", fmt.Errorf("%w: 安全随机源不可用", ErrInvalidRequest)
	}
	return requestIDPrefix + hex.EncodeToString(buffer), nil
}

// normalizeClaimSecret 校验客户端提交的领取绑定格式。
func normalizeClaimSecret(secret ClaimSecret) (string, error) {
	value := strings.TrimSpace(secret.Reveal())
	if value == "" || len(value) > maxClaimSecretBytes {
		return "", fmt.Errorf("%w: 领取绑定无效", ErrRequestNotFound)
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' {
			continue
		}
		return "", fmt.Errorf("%w: 领取绑定无效", ErrRequestNotFound)
	}
	return value, nil
}

// validateAuditRequestID 校验可选审计请求编号；空值允许。
func validateAuditRequestID(requestID string) error {
	if strings.TrimSpace(requestID) != requestID {
		return fmt.Errorf("%w: 请求编号包含首尾空白", ErrInvalidRequest)
	}
	if requestID == "" {
		return nil
	}
	if len(requestID) > MaxAuditRequestIDBytes || account.ValidateRequestID(requestID) != nil {
		return fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	return nil
}

// normalizeScopes 校验并去重展示用 scope（必须属于客户端登记集合）。
func normalizeScopes(raw, registered []string) ([]string, error) {
	if len(raw) > MaxScopes {
		return nil, fmt.Errorf("%w: scope 数量超过上限", ErrInvalidRequest)
	}
	registeredSet := make(map[string]struct{}, len(registered))
	for _, scope := range registered {
		registeredSet[scope] = struct{}{}
	}
	seen := make(map[string]struct{}, len(raw))
	result := make([]string, 0, len(raw))
	for _, value := range raw {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > MaxScopeTokenBytes {
			return nil, fmt.Errorf("%w: scope 取值非法", ErrInvalidRequest)
		}
		for index := 0; index < len(value); index++ {
			character := value[index]
			if character < 0x21 || character > 0x7e {
				return nil, fmt.Errorf("%w: scope 取值非法", ErrInvalidRequest)
			}
		}
		if _, ok := registeredSet[value]; !ok {
			return nil, fmt.Errorf("%w: scope 未在客户端登记", ErrInvalidRequest)
		}
		if _, duplicated := seen[value]; duplicated {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

// validateAllowedClients 校验应用白名单（最多 maxAllowedClients 个合法应用 ID）。
func validateAllowedClients(clientIDs []string) ([]string, error) {
	if len(clientIDs) > maxAllowedClients {
		return nil, fmt.Errorf("%w: 应用白名单最多 %d 个", ErrOptionsInvalid, maxAllowedClients)
	}
	seen := make(map[string]struct{}, len(clientIDs))
	result := make([]string, 0, len(clientIDs))
	for _, clientID := range clientIDs {
		if !app.ValidApplicationID(clientID) {
			return nil, fmt.Errorf("%w: 应用白名单包含非法应用 ID", ErrOptionsInvalid)
		}
		if _, duplicated := seen[clientID]; duplicated {
			continue
		}
		seen[clientID] = struct{}{}
		result = append(result, clientID)
	}
	sort.Strings(result)
	return result, nil
}

// permissionScopeID 返回目标应用的作用范围 ID（应用范围即应用 ID）。这里使用
// internal/permission 的解析以保持与既有作用范围语义一致。
func permissionScopeID(clientID string) (string, error) {
	kind, applicationID, err := permission.ParseScope(clientID)
	if err != nil || kind != permission.ScopeKindApplication {
		return "", fmt.Errorf("%w: 目标应用作用范围无效", ErrInvalidRequest)
	}
	return applicationID, nil
}

// parseAuthMethods 解析批准记录中的认证方法快照（只接受已定义方法）。
func parseAuthMethods(raw []string) ([]authn.Method, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: 批准记录缺少认证方法", ErrInvalidRequest)
	}
	methods := make([]authn.Method, 0, len(raw))
	for _, value := range raw {
		method := authn.Method(value)
		if !method.Valid() {
			return nil, fmt.Errorf("%w: 批准记录包含未知认证方法", ErrInvalidRequest)
		}
		methods = append(methods, method)
	}
	return methods, nil
}

// timeUTC 返回 UTC 毫秒截断时间。
func timeUTC(now time.Time) time.Time { return now.UTC().Truncate(time.Millisecond) }

// normalizeContext 把 nil ctx 当成 Background。
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
