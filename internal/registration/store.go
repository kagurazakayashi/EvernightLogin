package registration

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// DefaultRole 是宿主配置的可信默认角色策略项。RoleID 与 ScopeID 必须同时给出；
// 存储层只接受存在、已启用且作用域匹配的角色，绝不据此创建应用成员或应用角色。
type DefaultRole struct {
	// RoleID 是角色稳定 ID。
	RoleID string
	// ScopeID 是角色所属作用域 ID（系统角色为 "system"）。
	ScopeID string
}

// CreateUserParams 是已校验的注册创建参数。密码已是 Argon2id PHC 哈希；邮箱行
// 以未验证状态写入（VerifiedAt 为空），不保存任何验证秘密。
type CreateUserParams struct {
	UserID             string
	Username           string
	UsernameNormalized string
	Nickname           string
	Language           string
	Timezone           string
	Status             account.Status
	PasswordHash       string
	Email              string
	EmailNormalized    string
	DefaultRoles       []DefaultRole
	Now                time.Time
}

// EmailRecord 是账户当前用于注册/验证的邮箱行快照。
type EmailRecord struct {
	Email           string
	EmailNormalized string
	Verified        bool
	VerifiedAt      time.Time
	UpdatedAt       time.Time
}

// UserSnapshot 是重新发送验证入口所需的账户最小快照，不含密码或敏感管理字段。
type UserSnapshot struct {
	UserID   string
	Username string
	Nickname string
	Status   account.Status
	Email    EmailRecord
	// HasEmail 表示账户当前存在一条邮箱记录。
	HasEmail bool
}

// Ticket 是待验证邮箱与一次性凭证的绑定记录。
type Ticket struct {
	UserID          string
	CredentialID    string
	Email           string
	EmailNormalized string
	CreatedAt       time.Time
	ExpiresAt       time.Time
}

// ReplaceTicketParams 是一次待验证入口替换请求。EmailChanged 为 true 时在同一
// 审计事务内先把该用户所有未验证邮箱替换为 NewEmail，再覆盖验证票据；旧地址与
// 旧凭证随之失效。
type ReplaceTicketParams struct {
	Ticket         Ticket
	EmailChanged   bool
	NewEmail       string
	NewEmailNorm   string
	ReplacedAt     time.Time
	EventRequestID string
}

// CompleteVerificationParams 是完成邮箱验证的事务内条件更新参数。
type CompleteVerificationParams struct {
	UserID          string
	EmailNormalized string
	VerifiedAt      time.Time
}

// Store 是注册领域的持久化契约，由 internal/registration/sqlite 提供 SQLite
// 实现。实现约定：
//   - 事务方法必须使用调用方给出的 audit.Tx，与成功审计一致提交；失败时整体
//     回滚，不得留下部分创建或部分验证。
//   - 规范化用户名冲突或邮箱冲突统一返回 ErrRegistrationConflict，不区分具体
//     冲突字段（避免枚举）；其他存储失败返回 ErrStoreUnavailable，错误文本不得
//     包含 SQL、路径或用户输入。
//   - 找不到账户/邮箱/票据时返回 (zero, false, nil)，不把“不存在”当存储故障。
//   - 不得把邮箱验证令牌、邮件正文或验证链接写入任何表。
type Store interface {
	// CreateUser 在同一审计事务内创建用户、密码凭证、可选未验证邮箱与默认角色。
	// 用户名或邮箱唯一约束冲突返回 ErrRegistrationConflict；任一步失败整体回滚。
	CreateUser(ctx context.Context, tx audit.Tx, params CreateUserParams) error
	// GetUserSnapshot 读取账户与当前邮箱记录；账户不存在返回 found=false。
	GetUserSnapshot(ctx context.Context, userID string) (UserSnapshot, bool, error)
	// GetVerificationTicket 读取该用户当前待验证票据；没有返回 false。
	GetVerificationTicket(ctx context.Context, userID string) (Ticket, bool, error)
	// ReplaceTicket 在审计事务内可选替换未验证邮箱并覆盖验证票据。
	ReplaceTicket(ctx context.Context, tx audit.Tx, params ReplaceTicketParams) error
	// CompleteEmailVerification 在审计事务内条件把匹配的未验证邮箱置为已验证并删除
	// 验证票据。条件不满足（地址已替换/删除、已由其他入口验证）时返回 false，
	// 调用方必须整体拒绝，不得当作成功。
	CompleteEmailVerification(ctx context.Context, tx audit.Tx, params CompleteVerificationParams) (bool, error)
}
