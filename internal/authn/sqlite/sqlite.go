// Package sqlite 实现 internal/authn.Store 的 SQLite 生产持久化。
//
// 表结构来自 migrations/0001_identity_and_scope_core.sql（users 与角色分配）、
// 0009_password_credentials.sql（正式密码、可选历史、已验证邮箱）。本包不执行
// 迁移，调用方应在启动或测试中先应用全部迁移。本包不拥有数据库连接：
// *storage/sqlite.Store 的关闭由外层负责。构造后不可变，可被多个 goroutine 并发
// 使用；所有写入方法都要求调用方提供同一审计事务（audit.Tx），与成功审计一致
// 提交或整体回滚。
package sqlite

import (
	"context"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const (
	// selectUserColumns 是账户最小快照的公共选择列表。
	selectUserColumns = `u.id,u.username,u.username_normalized,u.nickname,u.status,u.is_root,u.security_version`

	selectUserByIDSQL = `SELECT ` + selectUserColumns + ` FROM users u WHERE u.id=?`

	selectUserByUsernameSQL = `SELECT ` + selectUserColumns + ` FROM users u WHERE u.username_normalized=?`

	// selectUserByVerifiedEmailSQL 只匹配已验证邮箱；未验证行永远不参与登录。
	selectUserByVerifiedEmailSQL = `SELECT ` + selectUserColumns + `
FROM user_emails e JOIN users u ON u.id=e.user_id
WHERE e.email_normalized=? AND e.verified_at_ms IS NOT NULL`

	selectCredentialSQL = `SELECT hash_scheme,hash_version,password_hash,must_change,created_at_ms,updated_at_ms,changed_at_ms,row_version
FROM password_credentials WHERE user_id=?`

	selectHistorySQL = `SELECT password_hash FROM password_history
WHERE user_id=? ORDER BY created_at_ms DESC,rowid DESC LIMIT ?`

	countHistorySQL = `SELECT COUNT(*) FROM password_history WHERE user_id=?`

	selectIsRootSQL = `SELECT is_root FROM users WHERE id=?`

	// sensitivePermissionKeys 是需要强认证（MFA）的高敏感系统权限键。除 root 之外，
	// 直接或经用户组持有这些权限（或任意 root_only 权限）的账户都要求强认证；
	// 自定义系统角色只要组合了这些权限同样命中，避免仅按固定角色键漏判。
	sensitivePermissionKeys = `'users.disable','users.delete','users.export','roles.assign','roles.manage',
'permissions.manage','permissions.state.update','applications.create',
'applications.credentials.manage','applications.members.manage','groups.manage','sessions.revoke',
'audit.read','audit.export','audit.purge','backups.create','backups.restore','backups.export',
'security.policy.manage','settings.manage','diagnostics.read','recovery.request','recovery.approve',
'recovery.mfa.approve','support.cases.read','support.cases.create','support.cases.update',
'authorization.check','reports.read','reports.generate','reports.export','reports.schedule.manage',
'reports.cleanup'`

	// selectSensitivePermissionSQL 判断账户是否（直接或经组角色）持有高敏感系统
	// 权限；root_only 权限一律视为高敏感。角色与权限都必须启用且属于系统范围。
	selectSensitivePermissionSQL = `SELECT 1 FROM user_roles ur
JOIN roles r ON r.id=ur.role_id AND r.enabled=1 AND r.scope_id='system'
JOIN role_permissions rp ON rp.role_id=r.id
JOIN permissions p ON p.id=rp.permission_id AND p.scope_id='system' AND p.enabled=1
WHERE ur.user_id=? AND (p.root_only=1 OR p.permission_key IN (` + sensitivePermissionKeys + `))
UNION ALL
SELECT 1 FROM group_members gm
JOIN group_roles gr ON gr.group_id=gm.group_id
JOIN roles r ON r.id=gr.role_id AND r.enabled=1 AND r.scope_id='system'
JOIN role_permissions rp ON rp.role_id=r.id
JOIN permissions p ON p.id=rp.permission_id AND p.scope_id='system' AND p.enabled=1
WHERE gm.user_id=? AND (p.root_only=1 OR p.permission_key IN (` + sensitivePermissionKeys + `))
LIMIT 1`

	// selectSecurityVersionTxSQL 在审计事务中读取递增后的安全版本。
	selectSecurityVersionTxSQL = `SELECT security_version FROM users WHERE id=?`

	// selectOldHashTxSQL 在审计事务中读取当前哈希，用于写入历史与复用检查。
	selectOldHashTxSQL = `SELECT password_hash FROM password_credentials WHERE user_id=?`

	insertHistorySQL = `INSERT OR IGNORE INTO password_history(user_id,password_hash,created_at_ms) VALUES(?,?,?)`

	// trimHistorySQL 只保留该用户按时间倒序的前 N 条历史；password_history 是
	// 普通 rowid 表，用 rowid 做稳定排序。
	trimHistorySQL = `DELETE FROM password_history WHERE user_id=? AND rowid NOT IN (
SELECT rowid FROM password_history WHERE user_id=? ORDER BY created_at_ms DESC,rowid DESC LIMIT ?)`

	clearHistorySQL = `DELETE FROM password_history WHERE user_id=?`

	// upsertCredentialSQL 创建或替换正式密码；原子更新行版本与变更时间。
	upsertCredentialSQL = `INSERT INTO password_credentials(
user_id,hash_scheme,hash_version,password_hash,must_change,row_version,created_at_ms,updated_at_ms,changed_at_ms
) VALUES(?,?,?,?,?,1,?,?,?)
ON CONFLICT(user_id) DO UPDATE SET
hash_scheme=excluded.hash_scheme,
hash_version=excluded.hash_version,
password_hash=excluded.password_hash,
must_change=excluded.must_change,
row_version=password_credentials.row_version+1,
updated_at_ms=excluded.updated_at_ms,
changed_at_ms=excluded.changed_at_ms`

	selectCredentialMetaTxSQL = `SELECT row_version,changed_at_ms FROM password_credentials WHERE user_id=?`

	// bumpSecurityVersionSQL 递增账户安全版本；后续会话/令牌模块据此拒绝旧会话。
	bumpSecurityVersionSQL = `UPDATE users SET security_version=security_version+1,updated_at_ms=? WHERE id=?`

	// upgradeHashSQL 条件升级旧参数哈希：只有旧哈希未被并发修改时才生效。
	upgradeHashSQL = `UPDATE password_credentials
SET password_hash=?,row_version=row_version+1,updated_at_ms=?
WHERE user_id=? AND password_hash=?`
)

// Store 是 authn.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装一个已打开并完成迁移的 SQLite 存储；store 为空返回
// authn.ErrOptionsInvalid，不会创建替代连接。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", authn.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

// 编译期确认实现 authn.Store。
var _ authn.Store = (*Store)(nil)

// FindUserByID 按稳定用户 ID 查找账户；不存在返回 (zero, false, nil)。
func (s *Store) FindUserByID(ctx context.Context, userID string) (authn.UserRecord, bool, error) {
	return s.findUser(ctx, selectUserByIDSQL, userID)
}

// FindUserByUsernameNormalized 按规范化用户名查找账户；不存在返回 false。
func (s *Store) FindUserByUsernameNormalized(ctx context.Context, normalized string) (authn.UserRecord, bool, error) {
	return s.findUser(ctx, selectUserByUsernameSQL, normalized)
}

// FindUserByVerifiedEmail 按规范化已验证邮箱查找账户；未验证邮箱不参与登录。
func (s *Store) FindUserByVerifiedEmail(ctx context.Context, normalizedEmail string) (authn.UserRecord, bool, error) {
	return s.findUser(ctx, selectUserByVerifiedEmailSQL, normalizedEmail)
}

// findUser 执行账户查询并校验数据合法性；异常数据按存储故障拒绝。
func (s *Store) findUser(ctx context.Context, query string, argument string) (authn.UserRecord, bool, error) {
	rows, err := s.store.QueryContext(ctx, query, argument)
	if err != nil {
		return authn.UserRecord{}, false, fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return authn.UserRecord{}, false, fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
		}
		return authn.UserRecord{}, false, nil
	}
	var (
		record authn.UserRecord
		status string
		isRoot int
	)
	if err := rows.Scan(&record.UserID, &record.Username, &record.UsernameNormalized,
		&record.Nickname, &status, &isRoot, &record.SecurityVersion); err != nil {
		return authn.UserRecord{}, false, fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
	}
	if err := rows.Err(); err != nil {
		return authn.UserRecord{}, false, fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
	}
	record.Status = account.Status(status)
	record.IsRoot = isRoot == 1
	if !account.ValidUserID(record.UserID) || !record.Status.Valid() ||
		record.UsernameNormalized == "" || (isRoot != 0 && isRoot != 1) {
		return authn.UserRecord{}, false, fmt.Errorf("%w: 账户数据无效", authn.ErrStoreUnavailable)
	}
	return record, true, nil
}

// GetPasswordCredential 读取正式密码凭证；没有密码时返回 found=false。
func (s *Store) GetPasswordCredential(ctx context.Context, userID string) (authn.CredentialRecord, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectCredentialSQL, userID)
	if err != nil {
		return authn.CredentialRecord{}, false, fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return authn.CredentialRecord{}, false, fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
		}
		return authn.CredentialRecord{}, false, nil
	}
	var (
		scheme     string
		version    int
		credential authn.CredentialRecord
		mustChange int
		createdAt  int64
		updatedAt  int64
		changedAt  int64
	)
	if err := rows.Scan(&scheme, &version, &credential.PasswordHash, &mustChange,
		&createdAt, &updatedAt, &changedAt, &credential.RowVersion); err != nil {
		return authn.CredentialRecord{}, false, fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
	}
	if err := rows.Err(); err != nil {
		return authn.CredentialRecord{}, false, fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
	}
	credential.UserID = userID
	credential.MustChange = mustChange == 1
	credential.CreatedAt = timeFromUnixMilli(createdAt)
	credential.UpdatedAt = timeFromUnixMilli(updatedAt)
	credential.ChangedAt = timeFromUnixMilli(changedAt)
	if scheme != authn.PasswordScheme || version != authn.PasswordSchemeVersion ||
		credential.PasswordHash == "" || (mustChange != 0 && mustChange != 1) {
		return authn.CredentialRecord{}, false, fmt.Errorf("%w: 密码凭证数据无效", authn.ErrStoreUnavailable)
	}
	return credential, true, nil
}

// ListPasswordHistoryHashes 按时间倒序返回最近的历史密码哈希。
func (s *Store) ListPasswordHistoryHashes(ctx context.Context, userID string, limit int) ([]string, error) {
	if limit <= 0 {
		return nil, nil
	}
	rows, err := s.store.QueryContext(ctx, selectHistorySQL, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	var hashes []string
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return nil, fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
		}
		hashes = append(hashes, hash)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
	}
	return hashes, nil
}

// StrongAuthRequired 报告账户是否要求强认证：root 恒为 true；直接或经用户组角色
// 持有已启用高敏感系统权限（含任意 root_only 权限）的账户也为 true。这样自定义
// 系统角色只要组合了高敏感权限同样命中，避免只按预设角色键漏判。
func (s *Store) StrongAuthRequired(ctx context.Context, userID string) (bool, error) {
	rows, err := s.store.QueryContext(ctx, selectIsRootSQL, userID)
	if err != nil {
		return false, fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
	}
	isRoot := -1
	if rows.Next() {
		if err := rows.Scan(&isRoot); err != nil {
			rows.Close()
			return false, fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return false, fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
	}
	rows.Close()
	if isRoot < 0 {
		return false, fmt.Errorf("%w: 判定强认证要求时账户不存在", authn.ErrStoreUnavailable)
	}
	if isRoot == 1 {
		return true, nil
	}
	rows, err = s.store.QueryContext(ctx, selectSensitivePermissionSQL, userID, userID)
	if err != nil {
		return false, fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if rows.Next() {
		return true, rows.Err()
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
	}
	return false, nil
}

// SetPassword 在审计事务中创建/替换密码、递增安全版本并维护有界历史。
//
// 行为：
//   - 已有密码时先把旧哈希写入 password_history（历史限制启用时），随后 upsert
//     新哈希；历史按 HistoryLimit 裁剪，0 表示清除历史并不再保留。
//   - users.security_version 必须恰好递增 1；账户行不存在说明并发删除，返回存储
//     错误由调用方整体回滚。
//   - 任一步失败返回错误，调用方审计事务回滚，不会留下“半更新”的凭证。
func (s *Store) SetPassword(ctx context.Context, tx audit.Tx, change authn.PasswordChange) (authn.PasswordChangeResult, error) {
	if tx == nil {
		return authn.PasswordChangeResult{}, fmt.Errorf("%w: 审计事务为空", authn.ErrOptionsInvalid)
	}
	nowMS := change.Now.UTC().UnixMilli()
	oldHash, hadOld, err := queryOptionalString(ctx, tx, selectOldHashTxSQL, change.UserID)
	if err != nil {
		return authn.PasswordChangeResult{}, fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
	}
	historyTrimmed := 0
	if hadOld && change.HistoryLimit > 0 {
		if _, err := tx.ExecContext(ctx, insertHistorySQL, change.UserID, oldHash, nowMS); err != nil {
			return authn.PasswordChangeResult{}, fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
		}
		if _, err := tx.ExecContext(ctx, trimHistorySQL, change.UserID, change.UserID, change.HistoryLimit); err != nil {
			return authn.PasswordChangeResult{}, fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
		}
		remaining, err := queryIntTx(ctx, tx, countHistorySQL, change.UserID)
		if err != nil {
			return authn.PasswordChangeResult{}, fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
		}
		if remaining > change.HistoryLimit {
			return authn.PasswordChangeResult{}, fmt.Errorf("%w: 密码历史裁剪未生效", authn.ErrStoreUnavailable)
		}
		historyTrimmed = remaining
	} else if !hadOld {
		// 首次设置没有历史可保存。
	} else {
		// 历史限制关闭：清除旧历史，避免保留不再使用的敏感材料。
		if _, err := tx.ExecContext(ctx, clearHistorySQL, change.UserID); err != nil {
			return authn.PasswordChangeResult{}, fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
		}
	}
	if _, err := tx.ExecContext(ctx, upsertCredentialSQL, change.UserID, authn.PasswordScheme,
		authn.PasswordSchemeVersion, change.PasswordHash, boolToInt(change.MustChange),
		nowMS, nowMS, nowMS); err != nil {
		return authn.PasswordChangeResult{}, fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
	}
	result := authn.PasswordChangeResult{ChangedAt: timeFromUnixMilli(nowMS), HistoryTrimmed: historyTrimmed}
	rows, err := tx.QueryContext(ctx, selectCredentialMetaTxSQL, change.UserID)
	if err != nil {
		return authn.PasswordChangeResult{}, fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
	}
	if rows.Next() {
		var changedAtMS int64
		if err := rows.Scan(&result.RowVersion, &changedAtMS); err != nil {
			rows.Close()
			return authn.PasswordChangeResult{}, fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
		}
		result.ChangedAt = timeFromUnixMilli(changedAtMS)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return authn.PasswordChangeResult{}, fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
	}
	rows.Close()
	update, err := tx.ExecContext(ctx, bumpSecurityVersionSQL, nowMS, change.UserID)
	if err != nil {
		return authn.PasswordChangeResult{}, fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
	}
	affected, err := update.RowsAffected()
	if err != nil {
		return authn.PasswordChangeResult{}, fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
	}
	if affected != 1 {
		return authn.PasswordChangeResult{}, fmt.Errorf("%w: 递增安全版本时账户不存在", authn.ErrStoreUnavailable)
	}
	securityVersion, err := queryInt64Tx(ctx, tx, selectSecurityVersionTxSQL, change.UserID)
	if err != nil {
		return authn.PasswordChangeResult{}, fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
	}
	result.SecurityVersion = securityVersion
	return result, nil
}

// UpgradePasswordHash 在审计事务中条件升级旧参数哈希；旧哈希已变化返回
// authn.ErrSetupStateConflict（并发修改，不能覆盖）。
func (s *Store) UpgradePasswordHash(ctx context.Context, tx audit.Tx, upgrade authn.HashUpgrade) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", authn.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, upgradeHashSQL, upgrade.NewHash,
		upgrade.Now.UTC().UnixMilli(), upgrade.UserID, upgrade.OldHash)
	if err != nil {
		return fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", authn.ErrStoreUnavailable, err)
	}
	switch affected {
	case 1:
		return nil
	case 0:
		return authn.ErrSetupStateConflict
	default:
		return fmt.Errorf("%w: 密码哈希升级影响行数异常", authn.ErrStoreUnavailable)
	}
}

// queryOptionalString 在事务中查询单个可空字符串；没有行返回 found=false。
func queryOptionalString(ctx context.Context, tx audit.Tx, query string, args ...any) (string, bool, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return "", false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return "", false, rows.Err()
	}
	var value string
	if err := rows.Scan(&value); err != nil {
		return "", false, err
	}
	return value, true, rows.Err()
}

// queryIntTx 在事务中查询单个整数。
func queryIntTx(ctx context.Context, tx audit.Tx, query string, args ...any) (int, error) {
	var value int
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	if !rows.Next() {
		return 0, rows.Err()
	}
	if err := rows.Scan(&value); err != nil {
		return 0, err
	}
	return value, rows.Err()
}

// queryInt64Tx 在事务中查询单个 int64。
func queryInt64Tx(ctx context.Context, tx audit.Tx, query string, args ...any) (int64, error) {
	var value int64
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	if !rows.Next() {
		return 0, rows.Err()
	}
	if err := rows.Scan(&value); err != nil {
		return 0, err
	}
	return value, rows.Err()
}

// boolToInt 把布尔值转成 SQLite 的 0/1。
func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

// timeFromUnixMilli 把数据库毫秒时间转成 UTC 时间。
func timeFromUnixMilli(value int64) time.Time {
	return time.UnixMilli(value).UTC()
}
