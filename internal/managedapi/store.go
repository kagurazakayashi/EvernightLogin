package managedapi

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// Store 是托管管理 API 策略的持久化契约，由 internal/managedapi/sqlite 实现。
// 所有条件更新必须在调用方审计事务内返回"是否真的更新"，并发单赢家由数据库
// 条件更新保证；实现必须 fail-closed。
type Store interface {
	// GetPolicy 读取应用策略；不存在返回 found=false。
	GetPolicy(ctx context.Context, applicationID string) (PolicyRecord, bool, error)
	// SetPolicyTx 在审计事务内写入策略：expectedRowVersion=0 表示新建（应用没有
	// 策略行）；否则按行版本条件更新。返回是否真的写入/更新。
	SetPolicyTx(ctx context.Context, tx audit.Tx, record PolicyRecord, expectedRowVersion int64) (bool, error)
	// ListPolicies 分页列出策略（仅受信配置通道使用）。
	ListPolicies(ctx context.Context, limit, offset int) ([]PolicyRecord, bool, error)
	// ApplicationStatus 读取应用状态（策略配置前确认应用存在）；不存在 found=false。
	ApplicationStatus(ctx context.Context, applicationID string) (string, bool, error)
}

// nowUTC 返回 UTC 毫秒时间。
func nowUTC(now time.Time) time.Time { return now.UTC().Truncate(time.Millisecond) }
