package qrlogin

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
)

// RequestRecord 是一次扫码登录请求的持久化记录。它不保存领取绑定明文、二维码
// 内容、会话秘密或任何 Token；ClaimDigest 是 keyring HMAC-SHA256 摘要。
type RequestRecord struct {
	ID          string
	ClaimDigest [32]byte
	ClaimKeyID  string
	ClientID    string
	Scopes      []string
	// RequestVersion 是请求版本（创建时为 1）；批准/拒绝/取消必须携带匹配版本，
	// 防止旧页面替换或被替换后的请求被继续确认。
	RequestVersion int64
	Status         string
	// UserID/SessionID/SecurityVersion/AuthMethods 是用户批准时的真实会话快照；
	// 领取前必须重新核对。
	UserID          string
	SessionID       string
	SecurityVersion int64
	AuthMethods     []string
	// 发起端展示信息：UserAgent 由客户端自称，Address 来自可信边界；都非授权依据。
	RequesterUserAgent string
	RequesterAddress   string
	// RequestID 是宿主层的请求编号（审计关联），不是领取凭据。
	RequestID       string
	IntervalSeconds int
	LastPolledAt    time.Time
	CreatedAt       time.Time
	ExpiresAt       time.Time
	DecidedAt       time.Time
	CancelledAt     time.Time
	ClaimedAt       time.Time
	// ClaimedSessionID 是领取成功后签发的会话 ID（尽力回写，用于审计追踪）。
	ClaimedSessionID string
}

// ExpiredAt 报告请求在 now 时刻是否已过期；过期判断不依赖落库状态。
func (r RequestRecord) ExpiredAt(now time.Time) bool {
	return !r.ExpiresAt.IsZero() && !now.Before(r.ExpiresAt)
}

// ApprovalDecision 是用户批准一次扫码登录请求时写入的绑定快照。
type ApprovalDecision struct {
	ID              string
	ExpectedVersion int64
	UserID          string
	SessionID       string
	SecurityVersion int64
	AuthMethods     []authn.Method
	Now             time.Time
}

// Store 是扫码登录请求的持久化契约，由 internal/qrlogin/sqlite 实现。所有条件
// 更新必须在同一审计事务内返回“是否真的更新了一行”，并发单赢家由数据库条件
// 更新保证；实现必须 fail-closed（错误不得当作成功）。
type Store interface {
	// CreateTx 在审计事务内创建 pending 请求。
	CreateTx(ctx context.Context, tx audit.Tx, record RequestRecord) error
	// GetRequest 按请求标识读取记录；不存在返回 found=false。
	GetRequest(ctx context.Context, id string) (RequestRecord, bool, error)
	// GetByClaimDigest 按领取绑定摘要读取记录；不存在返回 found=false。
	GetByClaimDigest(ctx context.Context, digest [32]byte) (RequestRecord, bool, error)
	// TouchPoll 条件更新最近查询时间（pending/approved 且未过期），供服务端强制
	// 最小查询间隔；返回是否真的更新。
	TouchPoll(ctx context.Context, id string, polledAt time.Time) (bool, error)
	// ApproveTx 条件把 pending 迁移为 approved，写入批准用户/会话/安全版本/方法
	// 快照；版本不匹配、已过期或状态变化时返回 false。
	ApproveTx(ctx context.Context, tx audit.Tx, approval ApprovalDecision) (bool, error)
	// DenyTx 条件把 pending 迁移为 denied。
	DenyTx(ctx context.Context, tx audit.Tx, id string, expectedVersion int64,
		userID string, now time.Time) (bool, error)
	// CancelTx 条件把 pending/approved 迁移为 cancelled（发起端取消/重新生成）。
	CancelTx(ctx context.Context, tx audit.Tx, id string, expectedVersion int64,
		now time.Time) (bool, error)
	// ConsumeTx 条件把 approved 迁移为 claimed（并发领取单赢家）。
	ConsumeTx(ctx context.Context, tx audit.Tx, id string, expectedVersion int64,
		now time.Time) (bool, error)
	// RegenerateTx 在同一审计事务内取消旧请求并创建新 pending 请求；旧请求必须仍
	// 可取消（pending/approved、未过期、版本匹配），否则整体返回 false。
	RegenerateTx(ctx context.Context, tx audit.Tx, oldID string, expectedVersion int64,
		now time.Time, record RequestRecord) (bool, error)
	// SetClaimedSession 尽力回写领取成功后的会话 ID（不影响已签发会话）。
	SetClaimedSession(ctx context.Context, id, sessionID string) (bool, error)
}
