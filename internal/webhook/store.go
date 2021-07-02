package webhook

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// EndpointRecord 是 Webhook 端点的持久化记录。
type EndpointRecord struct {
	ID            string
	ApplicationID string
	URL           string
	Description   string
	Status        EndpointStatus
	RowVersion    int64
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// SecretRecord 是签名密钥持久化记录：只保存 Sealer 密文与前缀，不保存明文。
type SecretRecord struct {
	ID           string
	EndpointID   string
	Prefix       string
	SealedSecret []byte
	SealerKeyID  string
	CreatedAt    time.Time
	RetireAt     time.Time
	RevokedAt    time.Time
}

// UsableAt 报告密钥在 now 时刻是否仍参与签名：未撤销且（无退役时间或未到退役）。
func (r SecretRecord) UsableAt(now time.Time) bool {
	if !r.RevokedAt.IsZero() {
		return false
	}
	if !r.RetireAt.IsZero() && !now.Before(r.RetireAt) {
		return false
	}
	return true
}

// EventRecord 是一次安全事件的持久化记录；PayloadJSON 只含白名单最小数据。
type EventRecord struct {
	ID             string
	IdempotencyKey string
	Type           string
	ApplicationID  string
	SubjectUserID  string
	PayloadJSON    []byte
	Truncated      bool
	RequestID      string
	OccurredAt     time.Time
	CreatedAt      time.Time
}

// DeliveryRecord 是单条投递的持久化记录。
type DeliveryRecord struct {
	ID                 string
	EventID            string
	EndpointID         string
	ApplicationID      string
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

// Store 是 Webhook 持久化契约，由 internal/webhook/sqlite 提供 SQLite 实现。
// 变更类方法必须使用条件更新处理并发；事件+投递的创建必须在一个事务内完成。
type Store interface {
	// ApplicationActive 报告应用当前是否启用（读取 applications.status）。
	ApplicationActive(ctx context.Context, applicationID string) (bool, error)
	// CountEndpoints 返回应用下端点数（含 disabled，用于数量上限）。
	CountEndpoints(ctx context.Context, applicationID string) (int, error)
	// CreateEndpointTx 在审计事务内创建端点。
	CreateEndpointTx(ctx context.Context, tx audit.Tx, endpoint EndpointRecord) error
	// GetEndpoint 按 ID 读取端点；不存在返回 found=false。
	GetEndpoint(ctx context.Context, endpointID string) (EndpointRecord, bool, error)
	// ListEndpointsByApp 列出应用下全部端点（不含密钥）。
	ListEndpointsByApp(ctx context.Context, applicationID string) ([]EndpointRecord, error)
	// UpdateEndpointTx 按 row_version 条件更新端点（url/description/status）；
	// 返回是否赢家。
	UpdateEndpointTx(ctx context.Context, tx audit.Tx, endpoint EndpointRecord) (bool, error)
	// CreateSecretTx 在审计事务内插入签名密钥记录。
	CreateSecretTx(ctx context.Context, tx audit.Tx, secret SecretRecord) error
	// ListSecrets 列出端点全部密钥元数据（只含前缀/时间/密文，不返回明文）。
	ListSecrets(ctx context.Context, endpointID string) ([]SecretRecord, error)
	// RetireActiveSecretsTx 把当前可用密钥设为在 retireAt 退役（轮换过渡）。
	RetireActiveSecretsTx(ctx context.Context, tx audit.Tx, endpointID string,
		retireAt, now time.Time) error
	// RevokeSecretTx 条件撤销指定密钥；重复撤销幂等返回 false。
	RevokeSecretTx(ctx context.Context, tx audit.Tx, endpointID, secretID string,
		now time.Time) (bool, error)
	// UsableSecrets 返回 now 时刻仍可参与签名的密钥（最多 MaxUsableSecrets）。
	UsableSecrets(ctx context.Context, endpointID string, now time.Time) ([]SecretRecord, error)
	// CreateEventWithDeliveries 在一个事务内创建事件与全部投递；幂等键/事件投递
	// 唯一约束冲突时返回既有事件与 duplicate=true。
	CreateEventWithDeliveries(ctx context.Context, event EventRecord,
		deliveries []DeliveryRecord) (EventRecord, bool, error)
	// ListActiveEndpointsForApps 返回给定应用集合中 active 端点（扇出用）。
	ListActiveEndpointsForApps(ctx context.Context, applicationIDs []string) ([]EndpointRecord, error)
	// UserAppIDs 返回用户当前为 active 成员的应用 ID（用户级事件扇出用）。
	UserAppIDs(ctx context.Context, userID string) ([]string, error)
	// GetEvent 按 ID 读取事件。
	GetEvent(ctx context.Context, eventID string) (EventRecord, bool, error)
	// GetDelivery 按 ID 读取投递。
	GetDelivery(ctx context.Context, deliveryID string) (DeliveryRecord, bool, error)
	// SetDeliveryTask 关联任务 ID。
	SetDeliveryTask(ctx context.Context, deliveryID, taskID string, now time.Time) error
	// MarkDeliverySending 记录一次尝试开始（attempts 递增并置 sending）。
	MarkDeliverySending(ctx context.Context, deliveryID string, attempt int, now time.Time) error
	// FinishDelivery 条件写入终态（succeeded/failed/cancelled）。
	FinishDelivery(ctx context.Context, deliveryID string, state DeliveryState, errorCode,
		errorKind string, responseStatus int, now time.Time) error
	// RequeueDelivery 把 failed 条件迁移回 queued（受控重试）。
	RequeueDelivery(ctx context.Context, deliveryID string, now time.Time) error
	// ListDeliveries 分页查询投递记录。
	ListDeliveries(ctx context.Context, query ListDeliveriesQuery) ([]DeliveryRecord, error)
}
