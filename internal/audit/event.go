package audit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// MaxActorIDBytes 是可信操作者稳定 ID 的最大字节数。
	MaxActorIDBytes = 128
	// MaxAppIDBytes 是事件记录的应用快照 ID 最大字节数。
	MaxAppIDBytes = 64
	// MaxActionBytes 是稳定动作标识的最大字节数。
	MaxActionBytes = 128
	// MaxTargetTypeBytes 是目标类型标识的最大字节数。
	MaxTargetTypeBytes = 64
	// MaxTargetIDBytes 是目标稳定 ID 的最大字节数。
	MaxTargetIDBytes = 128
	// MaxErrorCodeBytes 是对外错误码的最大字节数。
	MaxErrorCodeBytes = 64
	// MaxReasonCodeBytes 是受限内部原因码的最大字节数。
	MaxReasonCodeBytes = 64
	// MaxDedupeKeyBytes 是幂等键的最大字节数。
	MaxDedupeKeyBytes = 128
	// MaxDiffFields 是单条事件允许的变更差异字段数。
	MaxDiffFields = 16
	// MaxDiffFieldNameBytes 是差异字段名的最大字节数。
	MaxDiffFieldNameBytes = 64
	// MaxDiffValueBytes 是差异值（脱敏前后）的最大字节数。
	MaxDiffValueBytes = 256
	// MaxDetailBytes 是 detail_json 序列化后的最大字节数。
	MaxDetailBytes = 8 * 1024
	// MaxEventIDBytes 是事件 ID 的最大长度。
	MaxEventIDBytes = 40
	// MaxRequestIDBytes 与 MaxTaskIDBytes 与根包请求/任务编号约定一致。
	MaxRequestIDBytes = 64
	MaxTaskIDBytes    = 64
	// redactedValue 是敏感字段值的固定脱敏标记。
	redactedValue = "[REDACTED]"
	// eventIDPrefix 是审计事件 ID 的固定前缀。
	eventIDPrefix = "aud_"
	// eventIDRandomBytes 是事件 ID 的随机字节数（128 位）。
	eventIDRandomBytes = 16
)

// Outcome 是审计事件结果类别。
type Outcome string

const (
	// OutcomeSuccess 表示操作成功。
	OutcomeSuccess Outcome = "success"
	// OutcomeFailure 表示操作失败。
	OutcomeFailure Outcome = "failure"
	// OutcomeDenied 表示请求被拒绝（权限、策略或前置条件）。
	OutcomeDenied Outcome = "denied"
)

// Valid 报告结果类别是否已定义。
func (o Outcome) Valid() bool {
	return o == OutcomeSuccess || o == OutcomeFailure || o == OutcomeDenied
}

// ActorKind 是可信操作者类型。
type ActorKind string

const (
	// ActorUser 表示已认证的普通用户/操作者。
	ActorUser ActorKind = "user"
	// ActorSystem 表示系统任务/后台组件。
	ActorSystem ActorKind = "system"
	// ActorLocalAdmin 表示本地管理员/本地 CLI 应急操作者。
	ActorLocalAdmin ActorKind = "local_admin"
	// ActorAnonymous 表示匿名失败尝试，没有可信身份。
	ActorAnonymous ActorKind = "anonymous"
)

// Valid 报告操作者类型是否已定义。
func (a ActorKind) Valid() bool {
	return a == ActorUser || a == ActorSystem || a == ActorLocalAdmin || a == ActorAnonymous
}

// Actor 是由可信上下文提供的操作者身份。它不包含角色、显示名或请求参数中的
// 自称身份；调用方必须在认证/授权边界之后构造它。
type Actor struct {
	// Type 是操作者类型。
	Type ActorKind
	// ID 是稳定标识：用户 ID、系统组件标识或本地操作者标识。匿名事件必须为空。
	ID string
}

// Validate 校验操作者类型与身份规则。匿名事件不得携带 ID，避免匿名失败被伪造成
// 某个用户或 root 的审计记录。
func (a Actor) Validate() error {
	if !a.Type.Valid() {
		return fmt.Errorf("%w: 操作者类型未知", ErrInvalidEvent)
	}
	if a.Type == ActorAnonymous {
		if a.ID != "" {
			return fmt.Errorf("%w: 匿名事件不得携带操作者 ID", ErrInvalidEvent)
		}
		return nil
	}
	if err := validateVisibleASCII("操作者 ID", a.ID, MaxActorIDBytes, true); err != nil {
		return err
	}
	return nil
}

// Target 是审计事件的目标对象。
type Target struct {
	// Type 是目标类型稳定标识，例如 "user"、"application"、"credential"。
	Type string
	// ID 是目标稳定 ID；某些匿名失败可能没有可确认目标，因此允许为空。
	ID string
}

// FieldChange 是脱敏后的有限变更差异。它只保存字段名与前后值，不保存完整对象
// 正文；字段名应使用稳定机器名，而非用户输入的自由文本。
type FieldChange struct {
	Field  string `json:"field"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

// Event 是一条安全审计事件。
//
// OccurredAt 与 ID 由 Recorder 统一生成；调用 Store 时直接构造事件的测试/维护
// 代码必须提供它们。Changes 在写入前会被规范化：敏感字段值替换为 [REDACTED]，
// 超长值、控制字符与超量字段被拒绝。
type Event struct {
	ID         string
	OccurredAt time.Time
	Actor      Actor
	AppID      string
	Action     string
	Target     Target
	Outcome    Outcome
	ErrorCode  string
	ReasonCode string
	RequestID  string
	TaskID     string
	Changes    []FieldChange
	DedupeKey  string
}

// NewEventID 生成审计事件 ID：aud_ 加 128 位安全随机数的十六进制表示。
func NewEventID() (string, error) {
	return newEventID(rand.Reader)
}

// newEventID 允许测试注入随机源。
func newEventID(random io.Reader) (string, error) {
	buffer := make([]byte, eventIDRandomBytes)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", fmt.Errorf("%w: 无法生成审计事件 ID", ErrRandomSource)
	}
	return eventIDPrefix + hex.EncodeToString(buffer), nil
}

// NormalizeEvent 校验事件并返回规范化副本：敏感差异值被替换、差异 JSON 重新
// 序列化并检查大小。它不修改调用方传入的切片内容。
func NormalizeEvent(event Event) (Event, error) {
	if err := validateEventID(event.ID); err != nil {
		return Event{}, err
	}
	if event.OccurredAt.IsZero() {
		return Event{}, fmt.Errorf("%w: 发生时间不能为空", ErrInvalidEvent)
	}
	if err := event.Actor.Validate(); err != nil {
		return Event{}, err
	}
	if err := validateToken("应用快照 ID", event.AppID, MaxAppIDBytes, false); err != nil {
		return Event{}, err
	}
	if err := validateToken("动作", event.Action, MaxActionBytes, true); err != nil {
		return Event{}, err
	}
	if err := validateToken("目标类型", event.Target.Type, MaxTargetTypeBytes, true); err != nil {
		return Event{}, err
	}
	if err := validateVisibleASCII("目标 ID", event.Target.ID, MaxTargetIDBytes, false); err != nil {
		return Event{}, err
	}
	if !event.Outcome.Valid() {
		return Event{}, fmt.Errorf("%w: 结果类别未知", ErrInvalidEvent)
	}
	if err := validateErrorCode(event.ErrorCode); err != nil {
		return Event{}, err
	}
	if err := validateToken("内部原因码", event.ReasonCode, MaxReasonCodeBytes, false); err != nil {
		return Event{}, err
	}
	if err := validateRequestID(event.RequestID); err != nil {
		return Event{}, err
	}
	if err := validateTaskID(event.TaskID); err != nil {
		return Event{}, err
	}
	if err := validateVisibleASCII("幂等键", event.DedupeKey, MaxDedupeKeyBytes, false); err != nil {
		return Event{}, err
	}
	changes, err := RedactChanges(event.Changes)
	if err != nil {
		return Event{}, err
	}
	normalized := event
	normalized.Changes = changes
	if _, err := DetailJSON(changes); err != nil {
		return Event{}, err
	}
	return normalized, nil
}

// DetailJSON 把已规范化的变更差异序列化为 detail_json 文本。
func DetailJSON(changes []FieldChange) (string, error) {
	document := struct {
		Version int           `json:"v"`
		Changes []FieldChange `json:"changes,omitempty"`
	}{Version: 1, Changes: changes}
	encoded, err := json.Marshal(document)
	if err != nil {
		return "", fmt.Errorf("%w: 无法序列化差异", ErrInvalidEvent)
	}
	if len(encoded) > MaxDetailBytes {
		return "", fmt.Errorf("%w: 差异 JSON 超过 %d 字节", ErrInvalidEvent, MaxDetailBytes)
	}
	return string(encoded), nil
}

// RedactChanges 校验并脱敏差异字段。敏感字段名（密码、令牌、秘密、验证码、密钥、
// 凭证、Cookie、授权头、摘要、种子、恢复码等）的前后值固定替换为 [REDACTED]；
// 其它值必须是合法 UTF-8、不含控制字符且不超过 MaxDiffValueBytes。
func RedactChanges(changes []FieldChange) ([]FieldChange, error) {
	if len(changes) > MaxDiffFields {
		return nil, fmt.Errorf("%w: 差异字段超过 %d 个", ErrInvalidEvent, MaxDiffFields)
	}
	normalized := make([]FieldChange, 0, len(changes))
	seen := make(map[string]struct{}, len(changes))
	for _, change := range changes {
		if err := validateToken("差异字段名", change.Field, MaxDiffFieldNameBytes, true); err != nil {
			return nil, err
		}
		if _, exists := seen[change.Field]; exists {
			return nil, fmt.Errorf("%w: 差异字段名重复", ErrInvalidEvent)
		}
		seen[change.Field] = struct{}{}
		before, after := change.Before, change.After
		if sensitiveFieldName(change.Field) {
			before, after = redactedValue, redactedValue
		} else {
			if err := validateDiffValue(before); err != nil {
				return nil, err
			}
			if err := validateDiffValue(after); err != nil {
				return nil, err
			}
		}
		normalized = append(normalized, FieldChange{Field: change.Field, Before: before, After: after})
	}
	return normalized, nil
}

// sensitiveFieldName 判断字段名是否代表需要整体脱敏的敏感数据。采用保守的子串
// 匹配，宁可多脱敏也不泄露。
func sensitiveFieldName(name string) bool {
	lower := strings.ToLower(name)
	for _, token := range []string{
		"password", "passwd", "secret", "token", "code", "key", "credential",
		"cookie", "authorization", "hash", "seed", "totp", "recovery", "pin",
	} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

// validateDiffValue 校验非敏感差异值。
func validateDiffValue(value string) error {
	if len(value) > MaxDiffValueBytes {
		return fmt.Errorf("%w: 差异值超过 %d 字节", ErrInvalidEvent, MaxDiffValueBytes)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%w: 差异值不是合法 UTF-8", ErrInvalidEvent)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: 差异值不能包含控制字符", ErrInvalidEvent)
		}
	}
	return nil
}

// validateEventID 校验事件 ID 的固定格式。
func validateEventID(id string) error {
	if len(id) != len(eventIDPrefix)+2*eventIDRandomBytes || !strings.HasPrefix(id, eventIDPrefix) {
		return fmt.Errorf("%w: 事件 ID 格式无效", ErrInvalidEvent)
	}
	if _, err := hex.DecodeString(id[len(eventIDPrefix):]); err != nil {
		return fmt.Errorf("%w: 事件 ID 格式无效", ErrInvalidEvent)
	}
	return nil
}

// validateToken 校验稳定标识字段：可选/必填、长度受限、只含 ASCII 字母、数字与
// ". _ -"。
func validateToken(name, value string, max int, required bool) error {
	if value == "" {
		if required {
			return fmt.Errorf("%w: %s不能为空", ErrInvalidEvent, name)
		}
		return nil
	}
	if len(value) > max {
		return fmt.Errorf("%w: %s超过 %d 字节", ErrInvalidEvent, name, max)
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '.' && r != '_' && r != '-' {
			return fmt.Errorf("%w: %s只能包含 ASCII 字母、数字和 . _ -", ErrInvalidEvent, name)
		}
	}
	return nil
}

// validateVisibleASCII 校验稳定/可识别标识：可选/必填、长度受限、只含可见 ASCII。
func validateVisibleASCII(name, value string, max int, required bool) error {
	if value == "" {
		if required {
			return fmt.Errorf("%w: %s不能为空", ErrInvalidEvent, name)
		}
		return nil
	}
	if len(value) > max {
		return fmt.Errorf("%w: %s超过 %d 字节", ErrInvalidEvent, name, max)
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return fmt.Errorf("%w: %s只能包含可见 ASCII 字符", ErrInvalidEvent, name)
		}
	}
	return nil
}

// validateErrorCode 校验对外错误码：大写字母开头，字母/数字/下划线，最多 64 字节。
func validateErrorCode(code string) error {
	if code == "" {
		return nil
	}
	if len(code) > MaxErrorCodeBytes {
		return fmt.Errorf("%w: 错误码超过 %d 字节", ErrInvalidEvent, MaxErrorCodeBytes)
	}
	for i := 0; i < len(code); i++ {
		c := code[i]
		valid := c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
		if i == 0 && (c < 'A' || c > 'Z') {
			valid = false
		}
		if !valid {
			return fmt.Errorf("%w: 错误码只能包含大写字母、数字和下划线", ErrInvalidEvent)
		}
	}
	return nil
}

// validateRequestID 校验请求编号：与根包 login.ValidateRequestID 相同的字符集与
// 长度约定，避免审计记录出现不可关联的编号。
func validateRequestID(id string) error {
	if id == "" {
		return nil
	}
	if err := validateCorrelationID(id, MaxRequestIDBytes); err != nil {
		return fmt.Errorf("%w: 请求编号%s", ErrInvalidEvent, err)
	}
	return nil
}

// validateTaskID 校验任务编号。
func validateTaskID(id string) error {
	if id == "" {
		return nil
	}
	if err := validateCorrelationID(id, MaxTaskIDBytes); err != nil {
		return fmt.Errorf("%w: 任务编号%s", ErrInvalidEvent, err)
	}
	return nil
}

// validateCorrelationID 实现请求/任务编号的字符集、首字符与长度校验。
func validateCorrelationID(id string, max int) error {
	if len(id) == 0 || len(id) > max {
		return fmt.Errorf("长度无效")
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if i == 0 {
			if !alnum {
				return fmt.Errorf("首字符必须是 ASCII 字母或数字")
			}
			continue
		}
		if !alnum && c != '.' && c != '_' && c != '-' {
			return fmt.Errorf("只能包含 ASCII 字母、数字和 . _ -")
		}
	}
	return nil
}
