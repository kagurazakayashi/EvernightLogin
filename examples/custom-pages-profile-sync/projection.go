package main

// projection.go 是接**业务侧**的资料投影存储（示例自建，不属于 Login 核心）。
//
// 设计约束（步骤 241）：
//   - 业务记录只按稳定 UserID 关联账户；username 只是账户资料的只读同步展示值，
//     用户更名不换身份（同一 UserID 的记录保持不变）；
//   - 清楚区分三种时间：账户 CreatedAt（来自公开 ProfileView）、业务 LinkedAt
//     （业务首次关联账户的时间）、业务 BusinessUpdatedAt（业务侧最近一次同步时间）。
//     业务更新时间是业务自建字段，不冒充也不读取账户上不存在的业务字段；
//   - 未同步过的记录 BusinessUpdatedAt 保持零值，页面显示“未同步”，不虚构时间。
//
// 真实业务应把投影持久化到自己的数据库/队列；示例使用进程内内存存储，仅用于
// 展示同步语义，不写 Login 数据库，也不把客户/设备/项目表塞进 Login 核心。

import (
	"fmt"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/app"
)

// profileProjection 是业务侧资料投影。
type profileProjection struct {
	// UserID 是稳定关联键，来自公开会话/资料视图，绝不使用 username 做关联键。
	UserID string
	// Username 是账户 username 的只读同步展示值（用户更名后这里跟着变，但 UserID 不变）。
	Username string
	// Nickname 是账户昵称的同步展示值。
	Nickname string
	// LinkedAt 是业务首次关联该账户的时间（由业务在登录/首次同步时记录）。
	LinkedAt time.Time
	// AccountCreatedAt 是账户创建时间（从公开 ProfileView.CreatedAt 解析），只读存档。
	AccountCreatedAt time.Time
	// BusinessUpdatedAt 是业务侧资料投影最近一次同步时间；零值表示“尚未同步过”。
	// 它不是账户的 UpdatedAt，也不来自账户上不存在的业务字段。
	BusinessUpdatedAt time.Time
}

// projectionStore 是业务侧投影存储（示例用进程内实现）。
type projectionStore struct {
	mu     sync.Mutex
	byUser map[string]profileProjection
}

// newProjectionStore 返回空的投影存储。
func newProjectionStore() *projectionStore {
	return &projectionStore{byUser: make(map[string]profileProjection)}
}

// parseProfileTime 解析公开资料视图中的 RFC3339 时间（空串表示零值）。
func parseProfileTime(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("解析资料时间失败: %w", err)
	}
	return parsed.UTC(), nil
}

// Link 在业务侧首次关联账户：按稳定 UserID 建/取记录，记录业务 LinkedAt 与账户
// CreatedAt；已存在的记录不重置 LinkedAt（重复登录不改变业务关联时间）。
func (s *projectionStore) Link(view app.ProfileView, linkedAt time.Time) (profileProjection, error) {
	accountCreatedAt, err := parseProfileTime(view.CreatedAt)
	if err != nil {
		return profileProjection{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.byUser[view.UserID]; ok {
		// 关联键必须稳定：同一 UserID 重复关联只刷新只读展示值，不动 LinkedAt。
		existing.Username = view.Username
		existing.Nickname = view.Nickname
		s.byUser[view.UserID] = existing
		return existing, nil
	}
	record := profileProjection{
		UserID:            view.UserID,
		Username:          view.Username,
		Nickname:          view.Nickname,
		LinkedAt:          linkedAt.UTC(),
		AccountCreatedAt:  accountCreatedAt,
		BusinessUpdatedAt: time.Time{}, // 首次关联不等于资料同步，保持零值。
	}
	s.byUser[view.UserID] = record
	return record, nil
}

// SyncProfile 把账户资料变化同步到业务投影：按稳定 UserID 找到同一条记录，更新
// username/nickname 展示值并记录业务侧同步时间；LinkedAt 与关联键保持不变。
func (s *projectionStore) SyncProfile(view app.ProfileView,
	syncedAt time.Time) (profileProjection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.byUser[view.UserID]
	if !ok {
		return profileProjection{}, fmt.Errorf("业务投影未关联用户 %s（请先 Link）", view.UserID)
	}
	record.Username = view.Username
	record.Nickname = view.Nickname
	record.BusinessUpdatedAt = syncedAt.UTC()
	s.byUser[view.UserID] = record
	return record, nil
}

// Get 读取业务投影。
func (s *projectionStore) Get(userID string) (profileProjection, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.byUser[userID]
	return record, ok
}

// Count 返回业务投影记录数量（用于自检断言跨用户隔离）。
func (s *projectionStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byUser)
}
