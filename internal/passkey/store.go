package passkey

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// Store 是 Passkey 持久化契约，生产实现见 internal/passkey/sqlite。
//
// 表结构由 migrations/0022_passkey.sql 创建；实现必须保证：
//   - credential_id 全表唯一（跨用户也不能重复），重复创建映射 ErrCredentialConflict；
//   - 挑战消费是条件更新且只有一方成功（防重放/并发重复提交）；
//   - 成功变更类写入通过传入的审计事务执行，失败时整体回滚。
//
// 用户/用户名读取是只读的稳定表查询（users）。密码存在性用于删除最后一个登录
// 方式前的保护检查，读取 authn 的稳定表 password_credentials（迁移 0009）。
type Store interface {
	// EnsureUserHandle 返回用户稳定的 WebAuthn 用户句柄；不存在时用给定随机值
	// 创建。并发创建允许失败者重读，保证每用户一个句柄。
	EnsureUserHandle(ctx context.Context, userID string, handle []byte, now time.Time) ([]byte, error)

	// UserState 读取账户快照（含句柄可选）。
	UserState(ctx context.Context, userID string) (UserState, bool, error)
	// UserStateByHandle 按用户句柄读取账户（可发现凭证登录）。
	UserStateByHandle(ctx context.Context, handle []byte) (UserState, bool, error)
	// UserIDByNormalizedUsername 按规范化用户名查找用户 ID。
	UserIDByNormalizedUsername(ctx context.Context, normalized string) (string, bool, error)

	// ListActiveCredentials 返回用户未撤销的凭证（按创建时间升序）。
	ListActiveCredentials(ctx context.Context, userID string) ([]Credential, error)
	// CredentialByID 返回用户指定服务端凭证记录 ID 的有效记录。
	CredentialByID(ctx context.Context, userID, recordID string) (Credential, bool, error)
	// ActiveCredentialByRawID 返回指定认证器凭证 ID 的有效记录。
	ActiveCredentialByRawID(ctx context.Context, credentialID []byte) (Credential, bool, error)
	// CountActiveCredentialsTx 在审计事务中统计用户未撤销凭证数。
	CountActiveCredentialsTx(ctx context.Context, tx audit.Tx, userID string) (int, error)
	// HasPasswordCredentialTx 在审计事务中报告用户是否有正式密码登录方式。
	HasPasswordCredentialTx(ctx context.Context, tx audit.Tx, userID string) (bool, error)
	// CountActiveSecondFactorCredentialsTx 在审计事务中统计用户未撤销且用途允许
	// 第二步验证的凭证数量（删除最后强因素保护）。
	CountActiveSecondFactorCredentialsTx(ctx context.Context, tx audit.Tx, userID string) (int, error)
	// HasSecondFactorCredential 报告用户是否存在未撤销且用途允许第二步验证的
	// Passkey/安全密钥凭证（认证方式选择器使用，不返回凭证内容）。
	HasSecondFactorCredential(ctx context.Context, userID string) (bool, error)

	// CreateCredentialTx 在审计事务中创建凭证；凭证 ID 冲突返回 ErrCredentialConflict。
	CreateCredentialTx(ctx context.Context, tx audit.Tx, credential Credential) error
	// RenameCredentialTx 在审计事务中修改本人凭证显示名；不存在/已撤销返回 false。
	RenameCredentialTx(ctx context.Context, tx audit.Tx, userID, credentialID, name string, now time.Time) (bool, error)
	// RevokeCredentialTx 在审计事务中撤销本人凭证；不存在/已撤销返回 false。
	RevokeCredentialTx(ctx context.Context, tx audit.Tx, userID, credentialID, reason string, now time.Time) (bool, error)
	// IncrementUserSecurityVersionTx 在审计事务内递增用户 security_version，使既有
	// 会话失效（删除凭证等认证面变更后使用）。
	IncrementUserSecurityVersionTx(ctx context.Context, tx audit.Tx, userID string, now time.Time) error
	// UpdateCredentialUsageTx 在认证成功后原子更新计数器与备份状态等元数据。
	// 计数器只在更大时推进（同步凭证允许不递增）。
	UpdateCredentialUsageTx(ctx context.Context, tx audit.Tx, credential Credential, now time.Time) error

	// CreateCeremony 保存挑战记录（开始注册/认证时调用，不写成功审计）。
	CreateCeremony(ctx context.Context, ceremony Ceremony) error
	// ConsumeCeremony 一次性原子消费挑战：校验操作类型、绑定用户、上下文（如第二步
	// 绑定的 MFA 挑战 ID）、未消费且未过期。成功返回挑战记录；重复消费/操作类型或
	// 上下文不符返回 ErrCeremonyInvalid，过期返回 ErrCeremonyExpired。并发调用只有
	// 一方成功。userID/contextID 为空表示不限制该维度（可发现凭证登录）。
	ConsumeCeremony(ctx context.Context, id string, operation Operation, userID, contextID string, now time.Time) (Ceremony, error)
	// CleanupExpiredCeremonies 惰性清理过期且未消费的挑战；返回删除数量。
	CleanupExpiredCeremonies(ctx context.Context, before time.Time, limit int) (int64, error)
}
