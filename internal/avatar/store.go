package avatar

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// UserState 是头像操作需要的用户快照：是否存在、是否 root、当前行版本与当前
// 头像引用。它不包含邮箱、密码、角色等敏感字段。
type UserState struct {
	UserID     string
	Exists     bool
	IsRoot     bool
	RowVersion int64
	AvatarRef  string
}

// AvatarRecord 是持久化头像记录；StorageKey 只在包内与仓储/存储之间使用，
// 不通过 Avatar 暴露给调用者，也不写入审计。
type AvatarRecord struct {
	ID         string
	UserID     string
	StorageKey string
	MediaType  string
	ByteSize   int64
	Width      int
	Height     int
	SHA256     []byte
	SourceKind string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	RowVersion int64
}

// ReplaceRecord 是事务内替换头像参数：条件更新 users.avatar_ref 与 row_version，
// 删除旧头像行并插入新头像行；行版本不匹配时不得部分写入。
type ReplaceRecord struct {
	UserID             string
	New                AvatarRecord
	ExpectedRowVersion int64
	Now                time.Time
}

// Store 是头像记录持久化契约，由 internal/avatar/sqlite 实现。事务方法必须在
// 调用方审计事务内执行；条件更新影响 0 行表示版本冲突（由服务映射 CONFLICT）。
type Store interface {
	// GetUserState 读取用户是否存在、root 标记、行版本与当前头像引用。
	GetUserState(ctx context.Context, userID string) (UserState, error)
	// GetAvatar 按头像 ID 读取记录；不存在返回 found=false。
	GetAvatar(ctx context.Context, avatarID string) (AvatarRecord, bool, error)
	// Current 读取用户当前头像记录；不存在返回 found=false。
	Current(ctx context.Context, userID string) (AvatarRecord, bool, error)
	// ReplaceTx 在审计事务内条件替换头像并更新用户引用。
	ReplaceTx(ctx context.Context, tx audit.Tx, record ReplaceRecord) (AvatarRecord, bool, error)
	// RemoveTx 在审计事务内清除用户头像引用并删除头像行；返回被删除的记录。
	RemoveTx(ctx context.Context, tx audit.Tx, userID string, expectedRowVersion int64, now time.Time) (AvatarRecord, bool, error)
	// ListStorageKeys 返回数据库中仍被引用的全部存储键，供孤儿文件清理。
	ListStorageKeys(ctx context.Context) ([]string, error)
}
