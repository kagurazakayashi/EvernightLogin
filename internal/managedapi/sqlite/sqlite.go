// Package sqlite 实现 internal/managedapi 的策略持久化（表由迁移 0038 创建）。
// 本包不执行迁移、不拥有数据库连接；策略 JSON 在写入前已由领域层严格校验。
package sqlite

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/managedapi"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const (
	getPolicySQL = `SELECT application_id,policy_json,row_version,updated_by,
created_at_ms,updated_at_ms FROM app_managed_api_policies WHERE application_id=?`

	listPoliciesSQL = `SELECT application_id,policy_json,row_version,updated_by,
created_at_ms,updated_at_ms FROM app_managed_api_policies
ORDER BY application_id LIMIT ? OFFSET ?`

	insertPolicySQL = `INSERT INTO app_managed_api_policies(
application_id,policy_json,row_version,updated_by,created_at_ms,updated_at_ms)
VALUES(?,?,1,?,?,?)`

	updatePolicySQL = `UPDATE app_managed_api_policies SET policy_json=?,updated_by=?,
row_version=row_version+1,updated_at_ms=? WHERE application_id=? AND row_version=?`

	applicationStatusSQL = `SELECT status FROM applications WHERE id=?`
)

// Store 是 managedapi.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 构造 SQLite 存储；底层存储为空时拒绝。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, managedapi.ErrOptionsInvalid
	}
	return &Store{store: store}, nil
}

var _ managedapi.Store = (*Store)(nil)

// GetPolicy 读取应用策略。
func (s *Store) GetPolicy(ctx context.Context, applicationID string) (managedapi.PolicyRecord, bool, error) {
	rows, err := s.store.QueryContext(ctx, getPolicySQL, applicationID)
	if err != nil {
		return managedapi.PolicyRecord{}, false, managedapi.ErrStoreUnavailable
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return managedapi.PolicyRecord{}, false, managedapi.ErrStoreUnavailable
		}
		return managedapi.PolicyRecord{}, false, nil
	}
	record, err := scanPolicy(rows)
	if err != nil {
		return managedapi.PolicyRecord{}, false, managedapi.ErrStoreUnavailable
	}
	return record, true, nil
}

// ListPolicies 分页列出策略。
func (s *Store) ListPolicies(ctx context.Context, limit, offset int) ([]managedapi.PolicyRecord, bool, error) {
	rows, err := s.store.QueryContext(ctx, listPoliciesSQL, limit+1, offset)
	if err != nil {
		return nil, false, managedapi.ErrStoreUnavailable
	}
	defer rows.Close()
	records := make([]managedapi.PolicyRecord, 0, limit)
	for rows.Next() {
		record, err := scanPolicy(rows)
		if err != nil {
			return nil, false, managedapi.ErrStoreUnavailable
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, false, managedapi.ErrStoreUnavailable
	}
	hasMore := len(records) > limit
	if hasMore {
		records = records[:limit]
	}
	return records, hasMore, nil
}

// SetPolicyTx 在审计事务内新建或按行版本条件更新策略。
func (s *Store) SetPolicyTx(ctx context.Context, tx audit.Tx, record managedapi.PolicyRecord,
	expectedRowVersion int64) (bool, error) {
	if tx == nil {
		return false, managedapi.ErrOptionsInvalid
	}
	encoded, err := managedapi.EncodePolicy(record.Policy)
	if err != nil {
		return false, managedapi.ErrInvalidRequest
	}
	now := record.UpdatedAt.UTC().UnixMilli()
	if expectedRowVersion == 0 {
		if _, err := tx.ExecContext(ctx, insertPolicySQL, record.ApplicationID, string(encoded),
			record.UpdatedBy, record.CreatedAt.UTC().UnixMilli(), now); err != nil {
			// 新建时已有策略行（主键冲突）按行版本冲突返回，由领域层转 CONFLICT；
			// 其它存储错误同样 fail-closed 不写入（事务回滚，不产生半完成状态）。
			return false, nil
		}
		return true, nil
	}
	result, err := tx.ExecContext(ctx, updatePolicySQL, string(encoded), record.UpdatedBy,
		now, record.ApplicationID, expectedRowVersion)
	if err != nil {
		return false, managedapi.ErrStoreUnavailable
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, managedapi.ErrStoreUnavailable
	}
	return affected == 1, nil
}

// ApplicationStatus 读取应用状态。
func (s *Store) ApplicationStatus(ctx context.Context, applicationID string) (string, bool, error) {
	rows, err := s.store.QueryContext(ctx, applicationStatusSQL, applicationID)
	if err != nil {
		return "", false, managedapi.ErrStoreUnavailable
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return "", false, managedapi.ErrStoreUnavailable
		}
		return "", false, nil
	}
	var status string
	if err := rows.Scan(&status); err != nil {
		return "", false, managedapi.ErrStoreUnavailable
	}
	return status, true, nil
}

// scanner 是最小扫描接口。
type scanner interface{ Scan(dest ...any) error }

// scanPolicy 把一行扫描为策略记录并解码策略 JSON。
func scanPolicy(row scanner) (managedapi.PolicyRecord, error) {
	var (
		record    managedapi.PolicyRecord
		policyRaw string
		createdMS int64
		updatedMS int64
	)
	if err := row.Scan(&record.ApplicationID, &policyRaw, &record.RowVersion,
		&record.UpdatedBy, &createdMS, &updatedMS); err != nil {
		return managedapi.PolicyRecord{}, err
	}
	policy, err := managedapi.DecodePolicy([]byte(policyRaw))
	if err != nil {
		return managedapi.PolicyRecord{}, err
	}
	record.Policy = policy
	record.CreatedAt = unixMilli(createdMS)
	record.UpdatedAt = unixMilli(updatedMS)
	return record, nil
}

// unixMilli 把毫秒时间戳转换为 UTC 时间。
func unixMilli(value int64) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.UnixMilli(value).UTC()
}
