package serverapp

import (
	"context"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/bootstrap"
	bootstrapsqlite "github.com/kagurazakayashi/EvernightLogin/internal/bootstrap/sqlite"
)

// rootReadyMarker 在强认证完成事务内把 root 初始化状态推进到 ready。普通账户、
// 已 ready 或状态不匹配时幂等返回 nil；bootstrap 存储失败时返回错误并让整个
// 事务回滚，避免“强因素已绑定但 root 永远不可登录”的半提交。
type rootReadyMarker struct {
	store *bootstrapsqlite.Store
}

// MarkRootReady 实现 mfa.RootReadyMarker。
func (m rootReadyMarker) MarkRootReady(ctx context.Context, tx audit.Tx, userID string,
	now time.Time) error {
	if m.store == nil {
		return fmt.Errorf("root ready 标记缺少 bootstrap 存储")
	}
	root, found, err := m.store.GetRootAccount(ctx)
	if err != nil {
		return fmt.Errorf("读取 root 状态失败: %w", err)
	}
	if !found || root.UserID != userID {
		return nil
	}
	record, found, err := m.store.GetInitialization(ctx)
	if err != nil {
		return fmt.Errorf("读取初始化状态失败: %w", err)
	}
	if !found {
		return fmt.Errorf("初始化记录缺失，不能标记 root ready")
	}
	if record.State == bootstrap.StateReady {
		return nil
	}
	if record.State != bootstrap.StateSetupVerified {
		return fmt.Errorf("初始化状态 %s 不能推进为 ready", record.State)
	}
	if err := m.store.MarkReady(ctx, tx, bootstrap.RootReadyChange{
		RootUserID: userID, Now: now}); err != nil {
		return fmt.Errorf("标记 root ready 失败: %w", err)
	}
	return nil
}
