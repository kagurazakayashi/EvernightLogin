// Package webhook 实现应用安全事件的可信签名 Webhook 投递（步骤 59）：
// 端点与签名密钥管理、事件幂等落库、按应用扇出投递、签名请求、有界重试、
// 取消与失败查询。它只提供内部 Go API 与任务处理器，不建 HTTP 路由、不启动后台
// 协程、不真实外发（测试使用本地捕获端）。
//
// 安全不变量：
//   - 签名密钥只以 internal/secrets.Sealer 认证加密落库，明文只在创建/轮换响应出现
//     一次；轮换期最多两个可用密钥（active + retiring），签名头同时给出多个 v1，
//     退役/撤销后旧密钥不再参与签名。
//   - 签名覆盖“时间戳 + '.' + 实际传输字节”（HMAC-SHA256），重试重新生成时间戳但
//     事件 ID 不变；至少一次送达，消费方按事件 ID 去重，不承诺网络恰好一次。
//   - 投递目标经 internal/netguard 校验：仅 https（生产）/默认端口、无凭证、拒绝
//     环回/私有/链路本地/CGNAT/保留地址、每次连接前重新解析并固定 IP、默认不跟随
//     重定向。URL 在登记与每次投递前都重新校验，不信任登记时的解析结果。
//   - 事件 payload 是严格白名单的最小 JSON，不含密码、令牌、会话秘密、签名密钥或
//     自由文本；不把长期秘密放进事件/二维码/URL。
//   - 本包不实现 OIDC RP-Initiated/Back-Channel Logout 标准协议，也不得把本自定义
//     Webhook 冒称标准 OIDC 退出；标准 OIDC 退出属明确未实现范围（见 README）。
package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/securityevent"
)

// TaskKindWebhookDelivery 是投递任务的稳定类型标识；宿主把它与 Handler 一起注册到
// internal/task 执行器。
const TaskKindWebhookDelivery = "webhook.delivery"

// 协议与资源边界。
const (
	// DefaultMaxAttempts 是单条投递的默认尝试上限（含首次）。
	DefaultMaxAttempts = 5
	// MinMaxAttempts/MaxMaxAttempts 是尝试上限边界。
	MinMaxAttempts = 1
	MaxMaxAttempts = 10
	// DefaultDeliveryTimeoutSeconds 是单次投递任务超时。
	DefaultDeliveryTimeoutSeconds = 10
	// MinDeliveryTimeoutSeconds/MaxDeliveryTimeoutSeconds 是超时边界。
	MinDeliveryTimeoutSeconds = 5
	MaxDeliveryTimeoutSeconds = 60
	// DefaultSecretGracePeriod 是签名密钥轮换过渡期。
	DefaultSecretGracePeriod = 24 * time.Hour
	// MinSecretGracePeriod/MaxSecretGracePeriod 是过渡期边界。
	MinSecretGracePeriod = time.Minute
	MaxSecretGracePeriod = 30 * 24 * time.Hour
	// MaxEndpointsPerApp 是单应用可登记的 active/disabled 端点数上限。
	MaxEndpointsPerApp = 10
	// MaxUsableSecrets 是单 endpoint 同时可用（active+retiring）的签名密钥上限。
	MaxUsableSecrets = 2
	// MaxFanoutEndpoints 是单个事件扇出的 endpoint 数量上限。
	MaxFanoutEndpoints = 100
	// MaxListLimit 是投递查询单页上限。
	MaxListLimit = 100
	// MaxDescriptionBytes 是端点描述长度上限。
	MaxDescriptionBytes = 256
	// MaxEventPayloadBytes 是事件 data JSON 上限。
	MaxEventPayloadBytes = 16 * 1024
	// signingSecretBytes 是签名密钥随机字节数。
	signingSecretBytes = 32
	// secretPurpose 是 Sealer 用途绑定。
	secretPurpose = "webhook.signing"
	// eventVersion 是事件体版本。
	eventVersion = 1
	// 编号前缀。
	endpointIDPrefix = "whe_"
	secretIDPrefix   = "whs_"
	eventIDPrefix    = "whev_"
	deliveryIDPrefix = "whd_"
	// 审计/敏感操作 ID。
	operationEndpointChange = "application.webhook.endpoint.change"
	operationSecretRotate   = "application.webhook.secret.rotate"
)

// Action 是 Webhook 管理/查询动作。
type Action string

const (
	// ActionReadEndpoint 读取端点与密钥元数据。
	ActionReadEndpoint Action = "webhook.endpoint.read"
	// ActionManageEndpoint 登记/修改/启停端点。
	ActionManageEndpoint Action = "webhook.endpoint.manage"
	// ActionRotateSecret 创建/轮换/撤销签名密钥。
	ActionRotateSecret Action = "webhook.secret.rotate"
	// ActionQueryDelivery 查询投递记录。
	ActionQueryDelivery Action = "webhook.delivery.query"
	// ActionCancelDelivery 取消投递。
	ActionCancelDelivery Action = "webhook.delivery.cancel"
	// ActionRetryDelivery 对失败投递发起受控重试。
	ActionRetryDelivery Action = "webhook.delivery.retry"
)

// Valid 报告动作是否已定义。
func (a Action) Valid() bool {
	switch a {
	case ActionReadEndpoint, ActionManageEndpoint, ActionRotateSecret,
		ActionQueryDelivery, ActionCancelDelivery, ActionRetryDelivery:
		return true
	}
	return false
}

// 领域错误。协议/管理接口由宿主映射为稳定错误码（见 CodeOf）。
var (
	// ErrOptionsInvalid 表示构造配置无效。
	ErrOptionsInvalid = errors.New("Webhook 配置无效")
	// ErrAccessDenied 表示调用者未获准执行该动作。
	ErrAccessDenied = errors.New("未获准执行该 Webhook 操作")
	// ErrEndpointNotFound 表示端点不存在或不属于可访问范围。
	ErrEndpointNotFound = errors.New("Webhook 端点不存在")
	// ErrEndpointBlocked 表示端点 URL 被出站安全策略拒绝。
	ErrEndpointBlocked = errors.New("Webhook 地址不被允许")
	// ErrConflict 表示并发修改冲突或唯一约束冲突。
	ErrConflict = errors.New("Webhook 资源状态冲突")
	// ErrStoreUnavailable 表示持久化暂时不可用。
	ErrStoreUnavailable = errors.New("Webhook 存储暂时不可用")
	// ErrAuditUnavailable 表示关键操作审计写入失败。
	ErrAuditUnavailable = errors.New("关键操作未能可靠记录")
	// ErrInvalidRequest 表示参数不合法。
	ErrInvalidRequest = errors.New("Webhook 请求参数无效")
	// ErrSecretNotFound 表示签名密钥不存在。
	ErrSecretNotFound = errors.New("Webhook 签名密钥不存在")
	// ErrDeliveryNotFound 表示投递记录不存在。
	ErrDeliveryNotFound = errors.New("Webhook 投递不存在")
	// ErrDeliveryConflict 表示投递状态不允许该动作。
	ErrDeliveryConflict = errors.New("Webhook 投递状态冲突")
	// ErrEventInvalid 表示安全事件未通过类型/数据白名单校验。
	ErrEventInvalid = errors.New("安全事件无效")
)

// ErrorCode 是本领域对根包错误码注册表的投影。
type ErrorCode string

const (
	CodeReqInvalid             ErrorCode = "REQ_INVALID"
	CodeAccessDenied           ErrorCode = "ACCESS_DENIED"
	CodeConflict               ErrorCode = "CONFLICT"
	CodeDBUnavailable          ErrorCode = "DB_UNAVAILABLE"
	CodeAuditWriteFailed       ErrorCode = "AUDIT_WRITE_FAILED"
	CodeInternalError          ErrorCode = "INTERNAL_ERROR"
	CodeWebhookDeliveryFailed  ErrorCode = "WEBHOOK_DELIVERY_FAILED"
	CodeWebhookEndpointBlocked ErrorCode = "WEBHOOK_ENDPOINT_BLOCKED"
	CodeTaskCancelled          ErrorCode = "TASK_CANCELLED"
	CodeTaskCancelConflict     ErrorCode = "TASK_CANCEL_CONFLICT"
	// CodeTaskTimeout 是投递单次尝试超时的稳定原因码（复用已登记 TASK_TIMEOUT，
	// 表示“任务结果”而非系统故障；超时属于可重试失败，不是取消）。
	CodeTaskTimeout ErrorCode = "TASK_TIMEOUT"
)

// CodeOf 把本领域错误映射为根包已登记错误码。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrOptionsInvalid), errors.Is(err, ErrInvalidRequest),
		errors.Is(err, ErrEndpointNotFound), errors.Is(err, ErrSecretNotFound),
		errors.Is(err, ErrDeliveryNotFound), errors.Is(err, ErrEventInvalid):
		return CodeReqInvalid
	case errors.Is(err, ErrEndpointBlocked):
		return CodeWebhookEndpointBlocked
	case errors.Is(err, ErrAccessDenied):
		return CodeAccessDenied
	case errors.Is(err, ErrConflict), errors.Is(err, ErrDeliveryConflict):
		return CodeConflict
	case errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	default:
		return CodeInternalError
	}
}

// Caller 是可信边界建立的操作者上下文；字段不导出，只能通过构造函数建立。
type Caller struct {
	actor audit.Actor
}

// SystemCaller 构造系统组件操作者。
func SystemCaller(componentID string) (Caller, error) {
	return newCaller(audit.ActorSystem, componentID)
}

// LocalAdminCaller 构造本地管理员操作者。
func LocalAdminCaller(operatorID string) (Caller, error) {
	return newCaller(audit.ActorLocalAdmin, operatorID)
}

// UserCaller 构造普通用户操作者；读写他人应用必须由 Authorizer 放行。
func UserCaller(userID string) (Caller, error) { return newCaller(audit.ActorUser, userID) }

func newCaller(kind audit.ActorKind, id string) (Caller, error) {
	actor := audit.Actor{Type: kind, ID: id}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 操作者标识无效", ErrAccessDenied)
	}
	return Caller{actor: actor}, nil
}

// Actor 返回底层审计身份。
func (c Caller) Actor() audit.Actor { return c.actor }

// Authorizer 判定调用者能否对指定应用执行动作；实现必须 fail-closed，未配置时只有
// system/local_admin 主体可以通过。
type Authorizer interface {
	Authorize(ctx context.Context, caller Caller, action Action, applicationID string) error
}

// AuditRecorder 是安全审计契约；生产实现 *audit.Recorder。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// EndpointStatus 是端点状态。
type EndpointStatus string

const (
	// EndpointActive 表示端点会接收新事件。
	EndpointActive EndpointStatus = "active"
	// EndpointDisabled 表示端点保留历史但不再接收新事件。
	EndpointDisabled EndpointStatus = "disabled"
)

// Valid 报告端点状态是否已定义。
func (s EndpointStatus) Valid() bool { return s == EndpointActive || s == EndpointDisabled }

// DeliveryState 是投递状态。
type DeliveryState string

const (
	// DeliveryQueued 表示等待任务执行或等待重试。
	DeliveryQueued DeliveryState = "queued"
	// DeliverySending 表示正在尝试投递。
	DeliverySending DeliveryState = "sending"
	// DeliverySucceeded 表示对端返回 2xx。
	DeliverySucceeded DeliveryState = "succeeded"
	// DeliveryFailed 表示终态失败（永久错误或重试耗尽）。
	DeliveryFailed DeliveryState = "failed"
	// DeliveryCancelled 表示被取消。
	DeliveryCancelled DeliveryState = "cancelled"
)

// Valid 报告投递状态是否已定义。
func (s DeliveryState) Valid() bool {
	switch s {
	case DeliveryQueued, DeliverySending, DeliverySucceeded, DeliveryFailed, DeliveryCancelled:
		return true
	}
	return false
}

// Endpoint 是 Webhook 端点视图（不含密钥秘密）。
type Endpoint struct {
	ID            string
	ApplicationID string
	URL           string
	Description   string
	Status        EndpointStatus
	RowVersion    int64
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// SecretInfo 是签名密钥元数据（只含前缀与时间，不含秘密）。
type SecretInfo struct {
	ID        string
	Prefix    string
	CreatedAt time.Time
	RetireAt  time.Time
	RevokedAt time.Time
}

// RevealedSecret 是创建/轮换时返回一次的签名密钥明文；String 固定脱敏。
type RevealedSecret struct {
	Info   SecretInfo
	secret string
}

// Reveal 返回签名密钥原文（只用于展示给有权的应用管理员，不得写日志/审计）。
func (s RevealedSecret) Reveal() string { return s.secret }

// String 实现 fmt.Stringer，固定脱敏。
func (s RevealedSecret) String() string {
	if s.secret == "" {
		return "[UNSET]"
	}
	return "[REDACTED]"
}

// GoString 实现 fmt.GoStringer。
func (s RevealedSecret) GoString() string { return s.String() }

// Delivery 是投递记录视图（不含事件 payload 与任何秘密）。
type Delivery struct {
	ID                 string
	EventID            string
	EndpointID         string
	ApplicationID      string
	EventType          securityevent.Type
	State              DeliveryState
	Attempts           int
	MaxAttempts        int
	TaskID             string
	LastErrorCode      string
	LastErrorKind      string
	LastResponseStatus int
	RequestID          string
	CreatedAt          time.Time
	UpdatedAt          time.Time
	FinishedAt         time.Time
}

// ListDeliveriesQuery 是投递查询条件；零值表示不过滤。
type ListDeliveriesQuery struct {
	ApplicationID string
	EndpointID    string
	State         DeliveryState
	Limit         int
}

// EventEnvelope 是实际发送的事件体（字段顺序固定；data 为原始 JSON 字节）。
type EventEnvelope struct {
	ID            string             `json:"id"`
	Type          securityevent.Type `json:"type"`
	Version       int                `json:"version"`
	OccurredAt    string             `json:"occurred_at"`
	ApplicationID string             `json:"application_id"`
	Subject       EventSubject       `json:"subject"`
	Data          map[string]string  `json:"data,omitempty"`
}

// EventSubject 是事件主体（只含稳定用户 ID）。
type EventSubject struct {
	UserID string `json:"user_id,omitempty"`
}

// ===== 签名 =====

// Sign 计算签名头的单个 v1 值：HMAC-SHA256(secret, timestamp + "." + body)。
func Sign(secret []byte, timestamp int64, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	_, _ = mac.Write([]byte("."))
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// SignatureHeader 构造签名头：`t=<unix>,v1=<hex>[,v1=<hex>]`（轮换期多个可用密钥）。
func SignatureHeader(timestamp int64, signatures []string) string {
	var builder strings.Builder
	builder.WriteString("t=")
	builder.WriteString(strconv.FormatInt(timestamp, 10))
	for _, signature := range signatures {
		builder.WriteString(",v1=")
		builder.WriteString(signature)
	}
	return builder.String()
}

// VerifySignature 校验签名头（消费方验证算法参考实现）：解析时间戳与全部 v1，任一
// 密钥摘要恒定时间匹配且时间窗内即通过。tolerance<=0 使用默认 5 分钟。
//
// 注意：本函数只校验密码学与时间窗；消费方还必须按事件 ID（X-Evernight-Event-Id）
// 去重，避免重试造成的重复投递被重复处理。
func VerifySignature(secrets [][]byte, header string, body []byte, now time.Time,
	tolerance time.Duration) bool {
	timestamp, signatures, ok := parseSignatureHeader(header)
	if !ok {
		return false
	}
	if tolerance <= 0 {
		tolerance = 5 * time.Minute
	}
	delta := now.Unix() - timestamp
	if delta < 0 {
		delta = -delta
	}
	if time.Duration(delta)*time.Second > tolerance {
		return false
	}
	signedTimestamp := strconv.FormatInt(timestamp, 10)
	for _, secret := range secrets {
		if len(secret) == 0 {
			continue
		}
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write([]byte(signedTimestamp))
		_, _ = mac.Write([]byte("."))
		_, _ = mac.Write(body)
		expected := mac.Sum(nil)
		for _, signature := range signatures {
			decoded, err := hex.DecodeString(signature)
			if err != nil || len(decoded) != len(expected) {
				continue
			}
			if hmac.Equal(decoded, expected) {
				return true
			}
		}
	}
	return false
}

// parseSignatureHeader 解析 `t=...,v1=...`；时间戳与至少一个 v1 必须存在。
func parseSignatureHeader(header string) (int64, []string, bool) {
	var timestamp int64
	var signatures []string
	hasTimestamp := false
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		keyValue := strings.SplitN(part, "=", 2)
		if len(keyValue) != 2 {
			return 0, nil, false
		}
		switch keyValue[0] {
		case "t":
			value, err := strconv.ParseInt(strings.TrimSpace(keyValue[1]), 10, 64)
			if err != nil || value <= 0 {
				return 0, nil, false
			}
			timestamp = value
			hasTimestamp = true
		case "v1":
			value := strings.ToLower(strings.TrimSpace(keyValue[1]))
			if len(value) != 64 {
				return 0, nil, false
			}
			signatures = append(signatures, value)
		default:
			return 0, nil, false
		}
	}
	if !hasTimestamp || len(signatures) == 0 {
		return 0, nil, false
	}
	return timestamp, signatures, true
}

// ===== 事件数据白名单 =====

// validateEvent 校验安全事件类型与数据白名单，避免产生方把自由文本/秘密塞进通知。
func validateEvent(event securityevent.Event) error {
	if err := event.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrEventInvalid, err)
	}
	allowed := map[string]map[string]bool{
		string(securityevent.TypeUserDisabled): {
			"status": true, "previous_status": true, "security_version": true,
		},
		string(securityevent.TypeUserEnabled): {
			"status": true, "previous_status": true, "security_version": true,
		},
		string(securityevent.TypeSessionLoggedOut):  {"scope": true},
		string(securityevent.TypeSessionAllRevoked): {"revoked": true, "reason_class": true},
		string(securityevent.TypeAuthorizationRevoked): {
			"refresh_families": true, "refresh_tokens": true, "authorization_codes": true,
		},
		string(securityevent.TypeAppLogout): {
			"refresh_families": true, "refresh_tokens": true, "authorization_codes": true,
			"app_sessions": true,
		},
		string(securityevent.TypeAppMembershipChanged): {"status": true},
	}
	keys, ok := allowed[string(event.Type)]
	if !ok {
		return fmt.Errorf("%w: 未实现的事件类型", ErrEventInvalid)
	}
	for key := range event.Data {
		if !keys[key] {
			return fmt.Errorf("%w: 事件数据字段不在白名单", ErrEventInvalid)
		}
	}
	switch event.Type {
	case securityevent.TypeUserDisabled, securityevent.TypeUserEnabled,
		securityevent.TypeSessionAllRevoked:
		if event.ApplicationID != "" {
			return fmt.Errorf("%w: 用户级事件不能绑定单个应用", ErrEventInvalid)
		}
	case securityevent.TypeSessionLoggedOut:
		// 应用会话退出绑定应用；身份服务会话退出（应用为空）按成员关系扇出。
	case securityevent.TypeAuthorizationRevoked, securityevent.TypeAppLogout,
		securityevent.TypeAppMembershipChanged:
		if event.ApplicationID == "" {
			return fmt.Errorf("%w: 应用级事件必须绑定应用", ErrEventInvalid)
		}
	}
	if len(event.Data) > 0 {
		payload, err := marshalData(event.Data)
		if err != nil || len(payload) > MaxEventPayloadBytes {
			return fmt.Errorf("%w: 事件数据过大或不可编码", ErrEventInvalid)
		}
	}
	return nil
}

// marshalData 把白名单 map 编码为稳定 JSON（Go map 编码按键排序，重试字节一致）。
func marshalData(data map[string]string) ([]byte, error) {
	return json.Marshal(data)
}

// secretPrefix 返回密钥前缀（用于识别/列表，不泄露完整密钥）。
func secretPrefix(secret string) string {
	if len(secret) < 8 {
		return secret
	}
	return secret[:8]
}

// newSigningSecret 生成 32 字节高熵签名密钥（base64url）。
func newSigningSecret(random io.Reader) (string, error) {
	buffer := make([]byte, signingSecretBytes)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", fmt.Errorf("%w: 安全随机源不可用", ErrStoreUnavailable)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

// SensitiveRunner 是敏感操作执行前校验契约（生产 *reauth.Service）。
type SensitiveRunner = reauth.OperationRunner
