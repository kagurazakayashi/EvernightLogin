package token

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// KeyRecord 是签名密钥的持久化记录。
//
// SealedPrivate 是经 internal/secrets.Sealer 认证加密的 PKCS#8 私钥（BLOB），只在
// 服务内部签名时解密；PublicJWK 是可公开的 JWK JSON（不含私有字段）；两者都不进入
// 日志、审计或对外列表。
type KeyRecord struct {
	Kid           string
	Algorithm     string
	Status        KeyStatus
	PublicJWK     []byte
	SealedPrivate []byte
	CreatedAt     time.Time
	ActivatedAt   time.Time
	RetiredAt     time.Time
	RetireAfter   time.Time
	RevokedAt     time.Time
	RevokedReason string
}

// Verifiable 报告该密钥在 now 时刻能否用于验证令牌：active 总是可用；retired 仅在
// 保留期（RetireAfter）内可用；next/revoked 一律不可用。
func (r KeyRecord) Verifiable(now time.Time) bool {
	switch r.Status {
	case KeyActive:
		return true
	case KeyRetired:
		return !r.RetireAfter.IsZero() && now.Before(r.RetireAfter)
	default:
		return false
	}
}

// Publishable 报告该公钥是否应出现在 JWKS：active、next（预发布）与保留期内的
// retired；revoked 与超过保留期的 retired 不再发布。
func (r KeyRecord) Publishable(now time.Time) bool {
	switch r.Status {
	case KeyActive, KeyNext:
		return true
	case KeyRetired:
		return !r.RetireAfter.IsZero() && now.Before(r.RetireAfter)
	default:
		return false
	}
}

// Store 是签名密钥持久化契约，由 internal/token/sqlite 提供 SQLite 实现。
//
// 实现约束：
//   - 所有 *Tx 方法必须与调用方的成功审计在同一事务提交，失败整体回滚。
//   - 状态迁移使用条件更新：同一时刻最多一个 active（数据库部分唯一索引兜底），
//     并发轮换只有一个成功。
//   - 不保存私钥明文；SealedPrivate 只保存 AEAD 密文。
type Store interface {
	// GetKey 按 kid 读取密钥记录。
	GetKey(ctx context.Context, kid string) (KeyRecord, bool, error)
	// GetActiveKey 返回当前 active 签名密钥。
	GetActiveKey(ctx context.Context) (KeyRecord, bool, error)
	// ListKeys 返回全部密钥记录（供 JWKS/验证集合在内存中筛选；不含私钥明文）。
	ListKeys(ctx context.Context) ([]KeyRecord, error)
	// InsertKeyTx 在审计事务内插入密钥记录（new/active/next）。
	InsertKeyTx(ctx context.Context, tx audit.Tx, record KeyRecord) error
	// ActivateKeyTx 条件把 next 密钥迁移为 active；返回是否成功。
	ActivateKeyTx(ctx context.Context, tx audit.Tx, kid string, now time.Time) (bool, error)
	// RetireKeyTx 条件把 active 密钥迁移为 retired 并写入保留期终点。
	RetireKeyTx(ctx context.Context, tx audit.Tx, kid string, now, retireAfter time.Time) (bool, error)
	// RevokeKeyTx 条件把 next/active/retired 密钥迁移为 revoked（紧急撤销）。
	RevokeKeyTx(ctx context.Context, tx audit.Tx, kid, reason string, now time.Time) (bool, error)
}
