package authn

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/bootstrap"
)

// UserRecord 是认证所需的账户最小快照。它只包含登录判断需要的字段，不包含
// 邮箱机密、密码材料或其他可开放资料。
type UserRecord struct {
	// UserID 是稳定用户 ID。
	UserID string
	// Username 是显示用户名；UsernameNormalized 是唯一性比较值。
	Username           string
	UsernameNormalized string
	// Nickname 用于弱密码“不能包含账户信息”检查。
	Nickname string
	// Status 是账户全局状态；只有 active 允许登录。
	Status account.Status
	// IsRoot 表示唯一 root 账户（受保护账户）。
	IsRoot bool
	// SecurityVersion 是会话/令牌失效版本；认证结果会携带它，供会话服务绑定。
	SecurityVersion int64
}

// CredentialRecord 是正式密码凭证快照。PasswordHash 是 Argon2id PHC 编码字符串，
// 只在服务内部用于校验与升级，绝不写入日志/审计/错误。
type CredentialRecord struct {
	// UserID 是凭证所属用户 ID。
	UserID string
	// PasswordHash 是 PHC 编码哈希（含参数、盐与摘要）。
	PasswordHash string
	// MustChange 表示下次成功登录后必须先修改密码。
	MustChange bool
	// CreatedAt/UpdatedAt/ChangedAt 是凭证时间。
	CreatedAt time.Time
	UpdatedAt time.Time
	ChangedAt time.Time
	// RowVersion 是凭证行版本，供条件升级与诊断。
	RowVersion int64
}

// PasswordChange 是一次密码写入（创建或替换）请求，必须在审计事务中执行。
type PasswordChange struct {
	// UserID 是目标用户稳定 ID。
	UserID string
	// PasswordHash 是新密码的 Argon2id PHC 编码字符串。
	PasswordHash string
	// MustChange 表示下次成功登录后必须先修改密码。
	MustChange bool
	// HistoryLimit 是保留的历史密码条数；0 表示不保留历史（仍始终拒绝与当前
	// 密码相同的输入，由服务层在写入前判断）。
	HistoryLimit int
	// Now 是写入时间。
	Now time.Time
}

// PasswordChangeResult 是密码写入结果。
type PasswordChangeResult struct {
	// SecurityVersion 是递增后的账户安全版本；会话服务据此使旧会话失效。
	SecurityVersion int64
	// RowVersion 是凭证行版本。
	RowVersion int64
	// ChangedAt 是凭证变更时间。
	ChangedAt time.Time
	// HistoryTrimmed 是写入后裁剪掉的超出上限的历史条数（诊断用）。
	HistoryTrimmed int
}

// HashUpgrade 是旧参数哈希的条件升级请求，必须在审计事务中执行。
type HashUpgrade struct {
	// UserID 是目标用户 ID。
	UserID string
	// OldHash 是读取到的旧哈希；条件更新要求它仍未被并发修改。
	OldHash string
	// NewHash 是使用当前参数重新派生的哈希。
	NewHash string
	// Now 是升级时间。
	Now time.Time
}

// RootInitializationStore 是 root 受限初始化状态的读写契约，生产实现为
// internal/bootstrap/sqlite 的 Store（bootstrap.Store 的超集）。本包只读取状态
// 与在正式密码落库的同一审计事务内条件推进 ready，不复制 0008 状态机。
type RootInitializationStore interface {
	// GetInitialization 读取 0008 单例记录。
	GetInitialization(ctx context.Context) (bootstrap.Record, bool, error)
	// MarkReady 在调用方审计事务中把 setup_verified 条件更新为 ready。
	MarkReady(ctx context.Context, tx audit.Tx, change bootstrap.RootReadyChange) error
}

// Store 是认证领域的持久化契约，由 internal/authn/sqlite 提供生产 SQLite
// 实现。实现约定：
//   - 所有方法传播 context；存储不可用时返回 ErrStoreUnavailable，错误文本不得
//     包含 SQL、路径、密码或哈希。
//   - 找不到用户/凭证时返回 (zero, false, nil)，不能把“不存在”当存储故障。
//   - 读取路径必须校验数据合法性（状态枚举、用户 ID 格式、哈希非空），异常数据
//     返回 ErrStoreUnavailable 让服务 fail-closed，不猜测放行。
//   - 写入方法只允许在调用方审计事务中执行；并发修改导致条件更新不生效时返回
//     ErrSetupStateConflict 等可识别错误，绝不能把失败当成功。
type Store interface {
	// FindUserByID 按稳定用户 ID 查找账户。
	FindUserByID(ctx context.Context, userID string) (UserRecord, bool, error)
	// FindUserByUsernameNormalized 按规范化用户名查找账户。
	FindUserByUsernameNormalized(ctx context.Context, normalized string) (UserRecord, bool, error)
	// FindUserByVerifiedEmail 按规范化验证邮箱查找账户；只匹配 verified_at_ms
	// 非空的邮箱行，未验证邮箱永远不参与登录。
	FindUserByVerifiedEmail(ctx context.Context, normalizedEmail string) (UserRecord, bool, error)
	// GetPasswordCredential 读取正式密码凭证；没有密码时返回 found=false。
	GetPasswordCredential(ctx context.Context, userID string) (CredentialRecord, bool, error)
	// ListPasswordHistoryHashes 按时间倒序返回最近的旧密码哈希（最多 limit 条）。
	ListPasswordHistoryHashes(ctx context.Context, userID string, limit int) ([]string, error)
	// StrongAuthRequired 报告账户是否必须完成强认证（MFA）后才能完整登录。
	// root 与高权限系统角色返回 true；MFA 尚未实现时这些账户的密码认证结果只能
	// 是受限状态。
	StrongAuthRequired(ctx context.Context, userID string) (bool, error)
	// SetPassword 在审计事务中创建/替换密码，递增账户安全版本，并按 HistoryLimit
	// 保存旧哈希与裁剪历史。
	SetPassword(ctx context.Context, tx audit.Tx, change PasswordChange) (PasswordChangeResult, error)
	// UpgradePasswordHash 在审计事务中条件升级旧参数哈希；旧哈希已变化时返回
	// ErrSetupStateConflict（并发修改，不能覆盖）。
	UpgradePasswordHash(ctx context.Context, tx audit.Tx, upgrade HashUpgrade) error
}
