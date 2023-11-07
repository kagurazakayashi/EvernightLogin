package auditops

// 审计事件稳定游标（步骤 218）。大流水（审计事件持续追加）不能只用 offset：
// 并发追加会让 offset 页重复或跳过记录。游标用稳定排序键 (occurred_at_ms,id)
// 作为位置，并把“查询范围 + 筛选条件 + 排序”的摘要绑定进游标：
//   - 游标不携带授权结论；每次查询仍由服务层重新授权，SQL 的 scope 条件照常生效，
//     因此篡改位置不能扩大可见范围；
//   - 若调用方拿 A 范围/筛选生成的游标去查 B 范围/筛选，摘要不匹配直接
//     REQ_INVALID，避免“换筛选继续翻页”导致语义错乱；
//   - 位置本身不是秘密，但游标是不透明字符串，调用方不应解析或持久化依赖其格式。

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

const (
	// auditCursorVersion 是游标结构版本；变更语义时递增并拒绝旧版本。
	auditCursorVersion = 1
	// maxCursorBytes 限制调用方提交的游标长度，避免放大解析开销。
	maxCursorBytes = 4096
)

// CursorPosition 是稳定排序下的事件位置。OccurredAt 使用毫秒精度，
// 与服务端存储的 occurred_at_ms 一致；EventID 是并列时间的决胜键。
type CursorPosition struct {
	OccurredAt time.Time
	EventID    string
}

// cursorEnvelope 是游标 JSON 载荷；只有服务端生成/读取。
type cursorEnvelope struct {
	Version    int       `json:"v"`
	ScopeID    string    `json:"s"`
	ScopeKind  string    `json:"k"`
	FilterHash string    `json:"f"`
	Order      SortOrder `json:"o"`
	OccurredMS int64     `json:"t"`
	EventID    string    `json:"id"`
}

// filterFingerprint 计算筛选条件的稳定摘要（与 scope 分开）：只包含调用方可控的
// 筛选字段；授权后的数据范围约束不进入摘要（每次查询重新授权并写入 SQL）。
func filterFingerprint(filter Filter) string {
	normalized := struct {
		FromMS     int64  `json:"from_ms"`
		ToMS       int64  `json:"to_ms"`
		AppID      string `json:"app_id"`
		SystemOnly bool   `json:"system_only"`
		ActorType  string `json:"actor_type"`
		ActorID    string `json:"actor_id"`
		Action     string `json:"action"`
		Outcome    string `json:"outcome"`
		ErrorCode  string `json:"error_code"`
		RequestID  string `json:"request_id"`
		TaskID     string `json:"task_id"`
		TargetType string `json:"target_type"`
		TargetID   string `json:"target_id"`
	}{}
	if !filter.From.IsZero() {
		normalized.FromMS = filter.From.UTC().UnixMilli()
	}
	if !filter.To.IsZero() {
		normalized.ToMS = filter.To.UTC().UnixMilli()
	}
	normalized.AppID = filter.AppID
	normalized.SystemOnly = filter.SystemOnly
	normalized.ActorType = string(filter.ActorType)
	normalized.ActorID = filter.ActorID
	normalized.Action = filter.Action
	normalized.Outcome = string(filter.Outcome)
	normalized.ErrorCode = filter.ErrorCode
	normalized.RequestID = filter.RequestID
	normalized.TaskID = filter.TaskID
	normalized.TargetType = filter.TargetType
	normalized.TargetID = filter.TargetID
	encoded, err := json.Marshal(normalized)
	if err != nil {
		// 固定结构 JSON 序列化不应失败；返回保守摘要避免绕过校验。
		return "invalid"
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:16])
}

// encodeCursor 生成不透明游标。
func encodeCursor(scope ScopeInfo, filter Filter, order SortOrder,
	position CursorPosition) (string, error) {
	if position.EventID == "" {
		return "", fmt.Errorf("%w: 游标位置缺少事件编号", ErrInvalidRequest)
	}
	envelope := cursorEnvelope{Version: auditCursorVersion,
		ScopeID: scope.ID, ScopeKind: scope.Kind, FilterHash: filterFingerprint(filter),
		Order: order, OccurredMS: position.OccurredAt.UTC().UnixMilli(),
		EventID: position.EventID}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("%w: 游标编码失败", ErrInvalidRequest)
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

// decodeCursor 校验并解析游标；范围/筛选/排序不匹配、版本未知、格式错误一律
// 返回 ErrInvalidRequest，不静默退化为 offset 或第一页。
func decodeCursor(raw string, scope ScopeInfo, filter Filter,
	order SortOrder) (CursorPosition, error) {
	if raw == "" {
		return CursorPosition{}, nil
	}
	if len(raw) > maxCursorBytes {
		return CursorPosition{}, fmt.Errorf("%w: 游标过长", ErrInvalidRequest)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return CursorPosition{}, fmt.Errorf("%w: 游标格式无效", ErrInvalidRequest)
	}
	var envelope cursorEnvelope
	if err := json.Unmarshal(decoded, &envelope); err != nil {
		return CursorPosition{}, fmt.Errorf("%w: 游标格式无效", ErrInvalidRequest)
	}
	if envelope.Version != auditCursorVersion {
		return CursorPosition{}, fmt.Errorf("%w: 游标版本不受支持", ErrInvalidRequest)
	}
	if envelope.ScopeID != scope.ID || envelope.ScopeKind != scope.Kind {
		return CursorPosition{}, fmt.Errorf("%w: 游标与当前作用范围不匹配", ErrInvalidRequest)
	}
	if envelope.FilterHash != filterFingerprint(filter) {
		return CursorPosition{}, fmt.Errorf("%w: 游标与当前筛选条件不匹配", ErrInvalidRequest)
	}
	if envelope.Order != order {
		return CursorPosition{}, fmt.Errorf("%w: 游标与当前排序不匹配", ErrInvalidRequest)
	}
	if envelope.EventID == "" || envelope.OccurredMS <= 0 {
		return CursorPosition{}, fmt.Errorf("%w: 游标位置无效", ErrInvalidRequest)
	}
	return CursorPosition{
		OccurredAt: time.UnixMilli(envelope.OccurredMS).UTC(),
		EventID:    envelope.EventID,
	}, nil
}
