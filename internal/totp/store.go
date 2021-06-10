package totp

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// Store 是 TOTP 持久化契约，由 internal/totp/sqlite 实现。明文种子永不进入
// Store；只保存 internal/secrets 产出的认证加密信封。所有状态迁移使用条件更新：
// 激活只允许 pending→active，时间步推进只允许严格更大值（并发单赢家）。
type Store interface {
	// CreatePendingTx 在审计事务内创建 pending 绑定（附带加密种子信封）。
	CreatePendingTx(ctx context.Context, tx audit.Tx, binding Binding) error
	// CountPending 统计用户**未过期**的 pending 绑定数（限制并发绑定尝试）。
	CountPending(ctx context.Context, userID string, now time.Time) (int, error)
	// DeleteExpiredPending 惰性清理用户已过期的 pending 绑定，返回删除行数。
	DeleteExpiredPending(ctx context.Context, userID string, now time.Time) (int64, error)
	// GetPending 读取用户指定 pending 绑定。
	GetPending(ctx context.Context, userID, bindingID string) (Binding, bool, error)
	// GetActive 读取用户当前 active 绑定。
	GetActive(ctx context.Context, userID string) (Binding, bool, error)
	// List 读取用户全部绑定元数据（含加密信封，由服务剥离后输出）。
	List(ctx context.Context, userID string) ([]Binding, error)
	// IncrementAttemptsTx 条件递增 pending 绑定确认尝试次数（事务内）。
	IncrementAttemptsTx(ctx context.Context, tx audit.Tx, userID, bindingID string, now time.Time) (int, bool, error)
	// IncrementAttempts 条件递增确认尝试次数（非事务，用于失败审计不伪造成功审计
	// 事务时的惰性计数；并发下仍由 SQL 条件保证不超上限）。
	IncrementAttempts(ctx context.Context, userID, bindingID string, now time.Time) (int, bool, error)
	// ActivateTx 条件把 pending 绑定激活（同时写入确认时使用的时间步，防止该码
	// 立即被当登录验证复用），并在同一事务内停用旧 active（重绑替换）。
	ActivateTx(ctx context.Context, tx audit.Tx, userID, bindingID string, step int64, now time.Time) (bool, error)
	// DisableActiveTx 条件停用用户当前 active 绑定。
	DisableActiveTx(ctx context.Context, tx audit.Tx, userID string, now time.Time) (bool, error)
	// AdvanceAcceptedStepTx 条件推进已接受时间步（只接受严格更大的 step）。
	AdvanceAcceptedStepTx(ctx context.Context, tx audit.Tx, userID, bindingID string, step int64, now time.Time) (bool, error)
	// HasActive 报告用户是否有 active TOTP 绑定。
	HasActive(ctx context.Context, userID string) (bool, error)
	// Username 返回用户显示用户名（用于导入 URI 标签）。
	Username(ctx context.Context, userID string) (string, bool, error)
}
