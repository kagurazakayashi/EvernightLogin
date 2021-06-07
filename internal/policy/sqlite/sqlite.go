// Package sqlite 实现 internal/policy.Store 的 SQLite 生产仓储。
//
// 表结构由 migrations/0018_sensitive_operation_policies.sql 创建；本包不执行迁移、
// 不拥有数据库连接。系统默认策略只存在于 internal/policy 的代码目录中，本包只
// 保存偏离默认值的覆盖行与应用声明行，以及每个作用域的策略版本。
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const scopeSQL = `SELECT id,kind FROM scopes WHERE id=?`

const versionSQL = `SELECT version FROM sensitive_policy_scopes WHERE scope_id=?`

const overridesSQL = `SELECT operation_id,is_sensitive,reauth_required,max_auth_age_seconds,
required_strength,confirmation_required,notification_required,source_kind,name,description,
row_version,created_at_ms,updated_at_ms
FROM sensitive_operation_policies WHERE scope_id=? ORDER BY operation_id`

const userRootSQL = `SELECT is_root FROM users WHERE id=?`

const ensureScopeRowSQL = `INSERT INTO sensitive_policy_scopes(scope_id,version,updated_at_ms)
VALUES(?,0,?) ON CONFLICT(scope_id) DO NOTHING`

const bumpVersionSQL = `UPDATE sensitive_policy_scopes SET version=version+1,updated_at_ms=?
WHERE scope_id=? AND version=?`

const overrideCountAllSQL = `SELECT COUNT(*) FROM sensitive_operation_policies
WHERE scope_id=? AND source_kind='override'`

const overrideCountOneSQL = `SELECT COUNT(*) FROM sensitive_operation_policies
WHERE scope_id=? AND source_kind='override' AND operation_id=?`

const upsertOverrideSQL = `INSERT INTO sensitive_operation_policies(
scope_id,operation_id,is_sensitive,reauth_required,max_auth_age_seconds,required_strength,
confirmation_required,notification_required,source_kind,name,description,row_version,
created_at_ms,updated_at_ms
) VALUES(?,?,?,?,?,?,?,?,?,?,?,1,?,?)
ON CONFLICT(scope_id,operation_id) DO UPDATE SET
is_sensitive=excluded.is_sensitive,
reauth_required=excluded.reauth_required,
max_auth_age_seconds=excluded.max_auth_age_seconds,
required_strength=excluded.required_strength,
confirmation_required=excluded.confirmation_required,
notification_required=excluded.notification_required,
source_kind=excluded.source_kind,
name=excluded.name,
description=excluded.description,
row_version=sensitive_operation_policies.row_version+1,
updated_at_ms=excluded.updated_at_ms`

const deleteAllOverridesSQL = `DELETE FROM sensitive_operation_policies
WHERE scope_id=? AND source_kind='override'`

// Store 是 policy.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装已迁移的 SQLite 存储。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", policy.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

var _ policy.Store = (*Store)(nil)

// GetScope 读取作用域是否存在及其类型。
func (s *Store) GetScope(ctx context.Context, scopeID string) (policy.ScopeInfo, bool, error) {
	rows, err := s.store.QueryContext(ctx, scopeSQL, scopeID)
	if err != nil {
		return policy.ScopeInfo{}, false, fmt.Errorf("%w: %w", policy.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return policy.ScopeInfo{}, false, nil
	}
	var scope policy.ScopeInfo
	var kind string
	if err := rows.Scan(&scope.ID, &kind); err != nil {
		return policy.ScopeInfo{}, false, fmt.Errorf("%w: %w", policy.ErrStoreUnavailable, err)
	}
	scope.Application = kind == "application"
	return scope, true, nil
}

// GetVersion 读取作用域策略版本；没有变更记录时返回 0。
func (s *Store) GetVersion(ctx context.Context, scopeID string) (int64, error) {
	rows, err := s.store.QueryContext(ctx, versionSQL, scopeID)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", policy.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return policy.DefaultPolicyVersion, nil
	}
	var version int64
	if err := rows.Scan(&version); err != nil {
		return 0, fmt.Errorf("%w: %w", policy.ErrStoreUnavailable, err)
	}
	return version, nil
}

// GetOverrides 读取作用域内全部覆盖与声明行。
func (s *Store) GetOverrides(ctx context.Context, scopeID string) ([]policy.OverrideRecord, error) {
	rows, err := s.store.QueryContext(ctx, overridesSQL, scopeID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", policy.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	records := make([]policy.OverrideRecord, 0, 8)
	for rows.Next() {
		var record policy.OverrideRecord
		var sensitive, reauth, confirmation, notification int
		var strength, sourceKind string
		var createdAt, updatedAt int64
		if err := rows.Scan(&record.OperationID, &sensitive, &reauth, &record.Policy.MaxAuthAgeSeconds,
			&strength, &confirmation, &notification, &sourceKind, &record.Name, &record.Description,
			&record.RowVersion, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("%w: %w", policy.ErrStoreUnavailable, err)
		}
		record.ScopeID = scopeID
		record.Policy.Sensitive = sensitive == 1
		record.Policy.ReauthRequired = reauth == 1
		record.Policy.Strength = policy.Strength(strength)
		record.Policy.ConfirmationRequired = confirmation == 1
		record.Policy.NotificationRequired = notification == 1
		record.SourceKind = policy.SourceKind(sourceKind)
		record.CreatedAt = time.UnixMilli(createdAt).UTC()
		record.UpdatedAt = time.UnixMilli(updatedAt).UTC()
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", policy.ErrStoreUnavailable, err)
	}
	return records, nil
}

// GetUserRoot 读取调用者是否为真实 root 账户。
func (s *Store) GetUserRoot(ctx context.Context, userID string) (bool, bool, error) {
	rows, err := s.store.QueryContext(ctx, userRootSQL, userID)
	if err != nil {
		return false, false, fmt.Errorf("%w: %w", policy.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return false, false, nil
	}
	var isRoot int
	if err := rows.Scan(&isRoot); err != nil {
		return false, false, fmt.Errorf("%w: %w", policy.ErrStoreUnavailable, err)
	}
	return true, isRoot == 1, nil
}

// SaveTx 在审计事务内条件递增作用域版本并保存覆盖/声明行。
func (s *Store) SaveTx(ctx context.Context, tx audit.Tx, scopeID string, record policy.OverrideRecord,
	expectedVersion int64, now time.Time) (int64, bool, error) {
	if tx == nil {
		return 0, false, fmt.Errorf("%w: 审计事务为空", policy.ErrOptionsInvalid)
	}
	nowMS := now.UTC().UnixMilli()
	if _, err := tx.ExecContext(ctx, ensureScopeRowSQL, scopeID, nowMS); err != nil {
		return 0, false, fmt.Errorf("%w: %w", policy.ErrStoreUnavailable, err)
	}
	result, err := tx.ExecContext(ctx, bumpVersionSQL, nowMS, scopeID, expectedVersion)
	if err != nil {
		return 0, false, fmt.Errorf("%w: %w", policy.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, false, fmt.Errorf("%w: %w", policy.ErrStoreUnavailable, err)
	}
	if affected == 0 {
		return 0, false, nil
	}
	if affected != 1 {
		return 0, false, fmt.Errorf("%w: 策略版本更新影响行数异常", policy.ErrStoreUnavailable)
	}
	if _, err := tx.ExecContext(ctx, upsertOverrideSQL, scopeID, record.OperationID,
		boolToInt(record.Policy.Sensitive), boolToInt(record.Policy.ReauthRequired),
		record.Policy.MaxAuthAgeSeconds, string(record.Policy.Strength),
		boolToInt(record.Policy.ConfirmationRequired), boolToInt(record.Policy.NotificationRequired),
		string(record.SourceKind), record.Name, record.Description, nowMS, nowMS); err != nil {
		return 0, false, fmt.Errorf("%w: %w", policy.ErrStoreUnavailable, err)
	}
	return expectedVersion + 1, true, nil
}

// DeleteTx 在审计事务内删除覆盖行并条件递增作用域版本；没有匹配行时不递增版本。
func (s *Store) DeleteTx(ctx context.Context, tx audit.Tx, scopeID string, operationIDs []string,
	allOverrides bool, expectedVersion int64, now time.Time) (int64, int, bool, error) {
	if tx == nil {
		return 0, 0, false, fmt.Errorf("%w: 审计事务为空", policy.ErrOptionsInvalid)
	}
	nowMS := now.UTC().UnixMilli()
	if _, err := tx.ExecContext(ctx, ensureScopeRowSQL, scopeID, nowMS); err != nil {
		return 0, 0, false, fmt.Errorf("%w: %w", policy.ErrStoreUnavailable, err)
	}
	removed, err := countOverridesTx(ctx, tx, scopeID, operationIDs, allOverrides)
	if err != nil {
		return 0, 0, false, err
	}
	if removed == 0 {
		version, err := currentVersionTx(ctx, tx, scopeID)
		if err != nil {
			return 0, 0, false, err
		}
		return version, 0, true, nil
	}
	result, err := tx.ExecContext(ctx, bumpVersionSQL, nowMS, scopeID, expectedVersion)
	if err != nil {
		return 0, 0, false, fmt.Errorf("%w: %w", policy.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, 0, false, fmt.Errorf("%w: %w", policy.ErrStoreUnavailable, err)
	}
	if affected == 0 {
		return 0, 0, false, nil
	}
	if affected != 1 {
		return 0, 0, false, fmt.Errorf("%w: 策略版本更新影响行数异常", policy.ErrStoreUnavailable)
	}
	if err := deleteOverridesTx(ctx, tx, scopeID, operationIDs, allOverrides); err != nil {
		return 0, 0, false, err
	}
	return expectedVersion + 1, removed, true, nil
}

// countOverridesTx 在事务内统计将受影响的 override 行数。
func countOverridesTx(ctx context.Context, tx audit.Tx, scopeID string, operationIDs []string,
	allOverrides bool) (int, error) {
	var rows *sql.Rows
	var err error
	if allOverrides {
		rows, err = tx.QueryContext(ctx, overrideCountAllSQL, scopeID)
	} else {
		if len(operationIDs) == 0 {
			return 0, nil
		}
		query, args := overrideCountInSQL(scopeID, operationIDs)
		rows, err = tx.QueryContext(ctx, query, args...)
	}
	if err != nil {
		return 0, fmt.Errorf("%w: %w", policy.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return 0, fmt.Errorf("%w: 无法统计覆盖行", policy.ErrStoreUnavailable)
	}
	var count int
	if err := rows.Scan(&count); err != nil {
		return 0, fmt.Errorf("%w: %w", policy.ErrStoreUnavailable, err)
	}
	return count, nil
}

// deleteOverridesTx 在事务内删除 override 行。
func deleteOverridesTx(ctx context.Context, tx audit.Tx, scopeID string, operationIDs []string,
	allOverrides bool) error {
	if allOverrides {
		if _, err := tx.ExecContext(ctx, deleteAllOverridesSQL, scopeID); err != nil {
			return fmt.Errorf("%w: %w", policy.ErrStoreUnavailable, err)
		}
		return nil
	}
	query, args := deleteOverrideInSQL(scopeID, operationIDs)
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("%w: %w", policy.ErrStoreUnavailable, err)
	}
	return nil
}

// currentVersionTx 在事务内读取作用域版本。
func currentVersionTx(ctx context.Context, tx audit.Tx, scopeID string) (int64, error) {
	rows, err := tx.QueryContext(ctx, versionSQL, scopeID)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", policy.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return policy.DefaultPolicyVersion, nil
	}
	var version int64
	if err := rows.Scan(&version); err != nil {
		return 0, fmt.Errorf("%w: %w", policy.ErrStoreUnavailable, err)
	}
	return version, nil
}

// overrideCountInSQL 构造按操作标识统计的参数化查询。
func overrideCountInSQL(scopeID string, operationIDs []string) (string, []any) {
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(operationIDs)), ",")
	query := `SELECT COUNT(*) FROM sensitive_operation_policies
WHERE scope_id=? AND source_kind='override' AND operation_id IN (` + placeholders + `)`
	args := make([]any, 0, len(operationIDs)+1)
	args = append(args, scopeID)
	for _, operationID := range operationIDs {
		args = append(args, operationID)
	}
	return query, args
}

// deleteOverrideInSQL 构造按操作标识删除的参数化查询。
func deleteOverrideInSQL(scopeID string, operationIDs []string) (string, []any) {
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(operationIDs)), ",")
	query := `DELETE FROM sensitive_operation_policies
WHERE scope_id=? AND source_kind='override' AND operation_id IN (` + placeholders + `)`
	args := make([]any, 0, len(operationIDs)+1)
	args = append(args, scopeID)
	for _, operationID := range operationIDs {
		args = append(args, operationID)
	}
	return query, args
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
