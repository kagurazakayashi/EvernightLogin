package mailer

// 步骤 266：投递记录只读有界分页（R10-23「邮件投递记录端点/权限」的领域层基础）。
//
// 目的：`List` 只支持一次性上限，无法支撑管理页/HTTP 的“继续读取”。本文件在保持
// 事实来源（mail_deliveries 文件记录）与既有授权/数据范围语义的前提下，补齐稳定
// keyset 游标分页：
//   - 排序固定 created_at DESC, id DESC（同时间以稳定 ID 并列），游标只记录位置；
//   - 游标绑定筛选条件（状态/收件人）与**实际数据范围**（普通用户只能本人），
//     条件或范围变化后旧游标返回 ErrDeliveryCursorMismatch，不从别的范围续读；
//   - 游标是不透明 base64url JSON；非法/篡改返回 ErrDeliveryCursorInvalid；
//   - 响应不含加密载荷（SealedPayload 恒为 nil），不新增权限键：跨用户/系统视图
//     由调用方已有权限（诊断/审计读）判定后再用系统/本地主体读取。

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// 投递列表分页默认/上限。单页最多 99 条：实现以 limit+1 探测 has_more，
// 而存储层 List 的上限是 MaxListLimit(100)。
const (
	DeliveryPageDefaultLimit = 20
	DeliveryPageMaxLimit     = MaxListLimit - 1
	deliveryCursorVersion    = 1
)

// 分页游标错误哨兵；协议层映射为统一分页参数错误。
var (
	// ErrDeliveryCursorInvalid 表示投递列表游标非法/被篡改。
	ErrDeliveryCursorInvalid = errors.New("投递列表游标无效，请从第一页重新开始")
	// ErrDeliveryCursorMismatch 表示游标与当前筛选条件或数据范围不一致。
	ErrDeliveryCursorMismatch = errors.New("投递列表游标与当前筛选/数据范围不一致，请从第一页重新开始")
)

// DeliveryPageQuery 是投递记录分页查询。State/Recipient 是可选筛选；
// Cursor 来自上一页 NextCursor（空表示第一页）。
type DeliveryPageQuery struct {
	State     DeliveryState
	Recipient string
	Limit     int
	Cursor    string
}

// DeliveryPage 是一页投递记录（不含加密载荷）。
type DeliveryPage struct {
	Records    []Record
	HasMore    bool
	Limit      int
	NextCursor string
}

// deliveryCursorEnvelope 是游标内部载荷（不透明字符串，调用方不解析）。
type deliveryCursorEnvelope struct {
	Version   int    `json:"v"`
	Filter    string `json:"f"`
	CreatedMS int64  `json:"t"`
	ID        string `json:"id"`
}

// deliveryFilterFingerprint 计算筛选+数据范围指纹；游标只在同一条件下有效。
func deliveryFilterFingerprint(state DeliveryState, recipient string,
	ownerType audit.ActorKind, ownerID string) string {
	payload := strings.Join([]string{string(state), strings.TrimSpace(recipient),
		string(ownerType), strings.TrimSpace(ownerID)}, "\x00")
	digest := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(digest[:16])
}

// encodeDeliveryCursor 生成下一页游标。
func encodeDeliveryCursor(filter string, last Record) (string, error) {
	if last.ID == "" || last.CreatedAt.IsZero() {
		return "", fmt.Errorf("%w: 游标位置缺少投递记录标识/时间", ErrInvalidMessage)
	}
	envelope := deliveryCursorEnvelope{Version: deliveryCursorVersion, Filter: filter,
		CreatedMS: last.CreatedAt.UTC().UnixMilli(), ID: last.ID}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("%w: 投递列表游标编码失败", ErrInvalidMessage)
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

// decodeDeliveryCursor 解码并校验游标与当前筛选/范围一致。
func decodeDeliveryCursor(cursor, filter string) (deliveryCursorEnvelope, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(cursor))
	if err != nil || len(raw) == 0 || len(raw) > 1024 {
		return deliveryCursorEnvelope{}, ErrDeliveryCursorInvalid
	}
	var envelope deliveryCursorEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return deliveryCursorEnvelope{}, ErrDeliveryCursorInvalid
	}
	if envelope.Version != deliveryCursorVersion || envelope.ID == "" || envelope.CreatedMS <= 0 {
		return deliveryCursorEnvelope{}, ErrDeliveryCursorInvalid
	}
	if envelope.Filter != filter {
		return deliveryCursorEnvelope{}, ErrDeliveryCursorMismatch
	}
	return envelope, nil
}

// ListPage 是投递记录的授权 + 有界分页查询（不返回加密载荷）。
//
// 授权与数据范围与 List 完全一致：先按动作复核 Authorizer；普通用户强制限定为本人
// 创建的投递；系统/本地管理员可读取全量。游标绑定实际生效的状态/收件人/归属范围。
func (s *DeliveryService) ListPage(ctx context.Context, caller Caller,
	query DeliveryPageQuery) (DeliveryPage, error) {
	if err := s.authorize(ctx, caller, ActionQueryDelivery, nil); err != nil {
		return DeliveryPage{}, err
	}
	if query.State != "" && !query.State.Valid() {
		return DeliveryPage{}, fmt.Errorf("%w: 非法状态 %q", ErrInvalidMessage, query.State)
	}
	limit := query.Limit
	if limit <= 0 {
		limit = DeliveryPageDefaultLimit
	}
	if limit > DeliveryPageMaxLimit {
		limit = DeliveryPageMaxLimit
	}
	listQuery := ListQuery{State: query.State,
		Recipient: strings.TrimSpace(query.Recipient), Limit: limit + 1}
	if caller.actor.Type == audit.ActorUser {
		listQuery.OwnerType = audit.ActorUser
		listQuery.OwnerID = caller.actor.ID
	}
	filter := deliveryFilterFingerprint(listQuery.State, listQuery.Recipient,
		listQuery.OwnerType, listQuery.OwnerID)
	if strings.TrimSpace(query.Cursor) != "" {
		position, err := decodeDeliveryCursor(query.Cursor, filter)
		if err != nil {
			return DeliveryPage{}, err
		}
		listQuery.AfterCreatedAt = time.UnixMilli(position.CreatedMS).UTC()
		listQuery.AfterID = position.ID
	}
	records, err := s.opts.Store.List(ctx, listQuery)
	if err != nil {
		return DeliveryPage{}, err
	}
	for i := range records {
		records[i].SealedPayload = nil
	}
	page := DeliveryPage{Limit: limit, Records: records}
	if len(records) > limit {
		page.Records = records[:limit]
		page.HasMore = true
		next, cursorErr := encodeDeliveryCursor(filter, page.Records[len(page.Records)-1])
		if cursorErr != nil {
			return DeliveryPage{}, cursorErr
		}
		page.NextCursor = next
	}
	return page, nil
}
