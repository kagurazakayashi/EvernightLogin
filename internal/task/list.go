package task

// 后台任务列表（步骤 218）。通用后台任务是可增长列表，需要与审计/报告同样的
// 有界分页：服务端按稳定排序 (created_at_ms,id) 读取一页，游标绑定筛选条件；
// 列表不返回任务载荷（Payload），避免把业务数据带出诊断入口。

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

const (
	// ListDefaultLimit/ListMaxLimit 是任务列表默认与最大单页条数。
	ListDefaultLimit = 20
	ListMaxLimit     = 100
	// listCursorVersion 是任务列表游标版本。
	listCursorVersion = 1
	maxListCursorSize = 4096
)

// ListJobsRequest 是任务列表查询。InitiatorType/InitiatorID 是列表授权层传入的
// 可见范围约束（普通用户只能看本人发起的任务）；空表示不按发起者过滤。
type ListJobsRequest struct {
	State         State
	Kind          string
	RequestID     string
	InitiatorType audit.ActorKind
	InitiatorID   string
	From          time.Time
	To            time.Time
	Limit         int
	Cursor        string
}

// JobListPage 是任务列表结果。HasMore 由多取一条判定；不返回总数。
type JobListPage struct {
	Jobs       []Job
	HasMore    bool
	Limit      int
	NextCursor string
}

// JobPageQuery 是存储层任务列表查询；AfterCreatedAt/AfterID 是服务层校验游标后
// 写入的 keyset 位置（空 ID 表示未使用游标）。
type JobPageQuery struct {
	State          State
	Kind           string
	RequestID      string
	InitiatorType  audit.ActorKind
	InitiatorID    string
	From           time.Time
	To             time.Time
	Limit          int
	AfterCreatedAt time.Time
	AfterID        string
}

// JobPage 是存储层一页任务结果。
type JobPage struct {
	Jobs    []Job
	HasMore bool
}

// jobCursorEnvelope 是任务列表游标 JSON 载荷（不透明字符串，调用方不应解析）。
type jobCursorEnvelope struct {
	Version int    `json:"v"`
	Filter  string `json:"f"`
	Created int64  `json:"t"`
	JobID   string `json:"id"`
}

// jobFilterFingerprint 计算列表筛选摘要；游标只在同一筛选条件下有效。
func jobFilterFingerprint(request ListJobsRequest) string {
	normalized := struct {
		State         string `json:"state"`
		Kind          string `json:"kind"`
		RequestID     string `json:"request_id"`
		InitiatorType string `json:"initiator_type"`
		InitiatorID   string `json:"initiator_id"`
		FromMS        int64  `json:"from_ms"`
		ToMS          int64  `json:"to_ms"`
	}{State: string(request.State), Kind: request.Kind, RequestID: request.RequestID,
		InitiatorType: string(request.InitiatorType), InitiatorID: request.InitiatorID}
	if !request.From.IsZero() {
		normalized.FromMS = request.From.UTC().UnixMilli()
	}
	if !request.To.IsZero() {
		normalized.ToMS = request.To.UTC().UnixMilli()
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return "invalid"
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:16])
}

// encodeJobCursor 生成下一页游标；只在 HasMore 时调用。
func encodeJobCursor(request ListJobsRequest, last Job) (string, error) {
	if last.ID == "" {
		return "", fmt.Errorf("%w: 游标位置缺少任务编号", ErrInvalidRequest)
	}
	envelope := jobCursorEnvelope{Version: listCursorVersion,
		Filter: jobFilterFingerprint(request), Created: last.CreatedAt.UTC().UnixMilli(),
		JobID: last.ID}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("%w: 游标编码失败", ErrInvalidRequest)
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

// decodeJobCursor 校验并解析游标；格式/版本/筛选不匹配一律 ErrInvalidRequest。
func decodeJobCursor(cursor string, request ListJobsRequest) (time.Time, string, error) {
	if cursor == "" {
		return time.Time{}, "", nil
	}
	if len(cursor) > maxListCursorSize {
		return time.Time{}, "", fmt.Errorf("%w: 游标过长", ErrInvalidRequest)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("%w: 游标格式无效", ErrInvalidRequest)
	}
	var envelope jobCursorEnvelope
	if err := json.Unmarshal(decoded, &envelope); err != nil {
		return time.Time{}, "", fmt.Errorf("%w: 游标格式无效", ErrInvalidRequest)
	}
	if envelope.Version != listCursorVersion {
		return time.Time{}, "", fmt.Errorf("%w: 游标版本不受支持", ErrInvalidRequest)
	}
	if envelope.Filter != jobFilterFingerprint(request) {
		return time.Time{}, "", fmt.Errorf("%w: 游标与当前筛选条件不匹配", ErrInvalidRequest)
	}
	if envelope.JobID == "" || envelope.Created <= 0 {
		return time.Time{}, "", fmt.Errorf("%w: 游标位置无效", ErrInvalidRequest)
	}
	return time.UnixMilli(envelope.Created).UTC(), envelope.JobID, nil
}

// normalizeJobListRequest 校验列表输入并填充默认值。
func normalizeJobListRequest(request ListJobsRequest) (ListJobsRequest, error) {
	request.Kind = strings.TrimSpace(request.Kind)
	if request.Kind != "" {
		if len(request.Kind) > MaxKindBytes {
			return ListJobsRequest{}, fmt.Errorf("%w: 任务类型过长", ErrInvalidRequest)
		}
	}
	request.RequestID = strings.TrimSpace(request.RequestID)
	if request.RequestID != "" {
		if err := account.ValidateRequestID(request.RequestID); err != nil {
			return ListJobsRequest{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
		}
	}
	if request.State != "" && !request.State.Valid() {
		return ListJobsRequest{}, fmt.Errorf("%w: 任务状态无效", ErrInvalidRequest)
	}
	if request.InitiatorType != "" {
		actor := audit.Actor{Type: request.InitiatorType, ID: request.InitiatorID}
		if err := actor.Validate(); err != nil {
			return ListJobsRequest{}, fmt.Errorf("%w: 发起者过滤无效", ErrInvalidRequest)
		}
	} else if request.InitiatorID != "" {
		return ListJobsRequest{}, fmt.Errorf("%w: 指定发起者 ID 时必须同时指定类型",
			ErrInvalidRequest)
	}
	if !request.From.IsZero() && !request.To.IsZero() && !request.From.Before(request.To) {
		return ListJobsRequest{}, fmt.Errorf("%w: 开始时间必须早于结束时间", ErrInvalidRequest)
	}
	limit := request.Limit
	if limit == 0 {
		limit = ListDefaultLimit
	}
	if limit < 1 || limit > ListMaxLimit {
		return ListJobsRequest{}, fmt.Errorf("%w: 每页条数必须在 1～%d 之间",
			ErrInvalidRequest, ListMaxLimit)
	}
	request.Limit = limit
	return request, nil
}

// DecodeJobListCursor 是受控只读入口（CLI 直读任务存储）使用的游标解析辅助：
// 校验请求输入与游标绑定并返回 keyset 位置。
func DecodeJobListCursor(request ListJobsRequest) (time.Time, string, error) {
	normalized, err := normalizeJobListRequest(request)
	if err != nil {
		return time.Time{}, "", err
	}
	return decodeJobCursor(normalized.Cursor, normalized)
}

// EncodeJobListCursor 是受控只读入口使用的游标生成辅助（只在 HasMore 时调用）。
func EncodeJobListCursor(request ListJobsRequest, last Job) (string, error) {
	normalized, err := normalizeJobListRequest(request)
	if err != nil {
		return "", err
	}
	return encodeJobCursor(normalized, last)
}

// ListJobs 返回任务列表一页。只能读取过滤/授权范围内的任务；列表视图不含 payload。
func (e *Executor) ListJobs(ctx context.Context, request ListJobsRequest) (JobListPage, error) {
	if e == nil {
		return JobListPage{}, ErrInvalidRequest
	}
	normalized, err := normalizeJobListRequest(request)
	if err != nil {
		return JobListPage{}, err
	}
	afterCreatedAt, afterID, err := decodeJobCursor(normalized.Cursor, normalized)
	if err != nil {
		return JobListPage{}, err
	}
	page, err := e.store.ListJobs(ctx, JobPageQuery{
		State: normalized.State, Kind: normalized.Kind, RequestID: normalized.RequestID,
		InitiatorType: normalized.InitiatorType, InitiatorID: normalized.InitiatorID,
		From: normalized.From, To: normalized.To, Limit: normalized.Limit,
		AfterCreatedAt: afterCreatedAt, AfterID: afterID,
	})
	if err != nil {
		return JobListPage{}, err
	}
	result := JobListPage{Jobs: page.Jobs, HasMore: page.HasMore, Limit: normalized.Limit}
	if page.HasMore && len(page.Jobs) > 0 {
		cursor, cursorErr := encodeJobCursor(normalized, page.Jobs[len(page.Jobs)-1])
		if cursorErr != nil {
			return JobListPage{}, cursorErr
		}
		result.NextCursor = cursor
	}
	for index := range result.Jobs {
		// 列表视图显式剔除任务载荷，避免诊断入口成为业务数据/秘密出口。
		result.Jobs[index].Payload = nil
	}
	return result, nil
}
