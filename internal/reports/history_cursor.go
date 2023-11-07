package reports

// 报告历史稳定游标（步骤 218）。历史列表排序为 created_at_ms DESC,id DESC；
// 游标位置用最后一条记录的时间与编号，并把 plan_id/state 筛选摘要绑定进游标：
// 换筛选继续翻页会被拒绝（REQ_INVALID），避免返回语义不一致的下一页。

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

const (
	historyCursorVersion = 1
	maxHistoryCursorSize = 4096
)

// historyCursorEnvelope 是游标 JSON 载荷（不透明字符串，调用方不应解析）。
type historyCursorEnvelope struct {
	Version   int    `json:"v"`
	Filter    string `json:"f"`
	CreatedMS int64  `json:"t"`
	ReportID  string `json:"id"`
}

// historyFilterFingerprint 计算历史列表筛选摘要；只包含调用方可控筛选。
func historyFilterFingerprint(planID, state string) string {
	normalized := struct {
		PlanID string `json:"plan_id"`
		State  string `json:"state"`
	}{PlanID: planID, State: state}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return "invalid"
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:16])
}

// encodeHistoryCursor 生成下一页游标；只在 HasMore 时调用。
func encodeHistoryCursor(planID, state string, record HistoryRecord) (string, error) {
	if record.ReportID == "" {
		return "", fmt.Errorf("%w: 游标位置缺少报告编号", ErrInvalidRequest)
	}
	envelope := historyCursorEnvelope{Version: historyCursorVersion,
		Filter:    historyFilterFingerprint(planID, state),
		CreatedMS: record.CreatedAt.UTC().UnixMilli(), ReportID: record.ReportID}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("%w: 游标编码失败", ErrInvalidRequest)
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

// decodeHistoryCursor 校验并解析游标；格式/版本/筛选不匹配一律 ErrInvalidRequest。
func decodeHistoryCursor(cursor, planID, state string) (time.Time, string, error) {
	if len(cursor) > maxHistoryCursorSize {
		return time.Time{}, "", fmt.Errorf("%w: 游标过长", ErrInvalidRequest)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("%w: 游标格式无效", ErrInvalidRequest)
	}
	var envelope historyCursorEnvelope
	if err := json.Unmarshal(decoded, &envelope); err != nil {
		return time.Time{}, "", fmt.Errorf("%w: 游标格式无效", ErrInvalidRequest)
	}
	if envelope.Version != historyCursorVersion {
		return time.Time{}, "", fmt.Errorf("%w: 游标版本不受支持", ErrInvalidRequest)
	}
	if envelope.Filter != historyFilterFingerprint(planID, state) {
		return time.Time{}, "", fmt.Errorf("%w: 游标与当前筛选条件不匹配", ErrInvalidRequest)
	}
	if envelope.ReportID == "" || envelope.CreatedMS <= 0 {
		return time.Time{}, "", fmt.Errorf("%w: 游标位置无效", ErrInvalidRequest)
	}
	return time.UnixMilli(envelope.CreatedMS).UTC(), envelope.ReportID, nil
}
