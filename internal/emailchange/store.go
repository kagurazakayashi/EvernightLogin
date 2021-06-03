package emailchange

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// RequestRecord 是创建申请的事务内记录。
type RequestRecord struct {
	ID                 string
	UserID             string
	OldEmail           string
	OldEmailNormalized string
	NewEmail           string
	NewEmailNormalized string
	CredentialID       string
	CreatedAt          time.Time
	ExpiresAt          time.Time
	RequestID          string
}

// CompleteParams 是切换生效的事务内参数。
type CompleteParams struct {
	RequestID          string
	NewEmail           string
	NewEmailNormalized string
	Now                time.Time
}

// Store 是邮箱变更持久化契约，由 internal/emailchange/sqlite 实现。
//
// 事务方法必须使用调用方 audit.Tx 与成功审计一致提交；失败整体回滚。实现约定：
//   - 同一用户至多一条 pending 申请；BeginRequest 在同一事务内取消旧 pending 并
//     返回其 credential_id 列表供服务层撤销旧凭证。
//   - CompleteRequestTx 必须在事务内校验 pending/未过期/旧邮箱版本/新邮箱唯一性，
//     通过后删除旧已验证行、写入新已验证行并标记 completed；唯一冲突返回 ErrEmailInUse。
type Store interface {
	CurrentEmail(ctx context.Context, userID string) (EmailRecord, bool, error)
	EmailInUse(ctx context.Context, normalized string, excludeUserID string) (bool, error)
	BeginRequest(ctx context.Context, tx audit.Tx, record RequestRecord) error
	GetRequest(ctx context.Context, id string) (Request, bool, error)
	GetActiveRequest(ctx context.Context, userID string) (Request, bool, error)
	LoadRequestTx(ctx context.Context, tx audit.Tx, id string) (Request, bool, error)
	CancelRequestTx(ctx context.Context, tx audit.Tx, requestID, userID string, now time.Time) (bool, error)
	CompleteRequestTx(ctx context.Context, tx audit.Tx, params CompleteParams) (bool, error)
	MarkVerify(ctx context.Context, requestID string, state NotifyState, errorCode string, now time.Time) error
	MarkNotify(ctx context.Context, requestID string, state NotifyState, errorCode string, now time.Time) error
	// UpdateCredential updates the pending request credential ID after a compensating reissue.
	UpdateCredential(ctx context.Context, requestID string, credentialID string) error
}
