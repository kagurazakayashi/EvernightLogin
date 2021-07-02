// Package sqlite 实现 internal/webhook.Store 的 SQLite 生产仓储。
//
// 表结构由 migrations/0037_webhook_delivery.sql 创建；本包不执行迁移、不拥有数据库
// 连接。签名密钥只保存 Sealer 密文与前缀；事件+投递在同一事务内创建；状态迁移使用
// 条件更新保证并发单赢家。
package sqlite

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/webhook"
)

// Store 是 webhook.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装已迁移的 SQLite 存储。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", webhook.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

var _ webhook.Store = (*Store)(nil)

const endpointColumns = `id,application_id,url,description,status,row_version,
created_at_ms,updated_at_ms`

const secretColumns = `id,endpoint_id,secret_prefix,sealed_secret,sealer_key_id,
created_at_ms,COALESCE(retire_at_ms,0),COALESCE(revoked_at_ms,0)`

const eventColumns = `id,idempotency_key,type,application_id,subject_user_id,
payload_json,truncated,request_id,occurred_at_ms,created_at_ms`

const deliveryColumns = `id,event_id,endpoint_id,application_id,state,attempts,
max_attempts,task_id,last_error_code,last_error_kind,last_response_status,request_id,
created_at_ms,updated_at_ms,COALESCE(finished_at_ms,0)`

const (
	applicationActiveSQL = `SELECT COUNT(*) FROM applications WHERE id=? AND status='active'`
	countEndpointsSQL    = `SELECT COUNT(*) FROM webhook_endpoints WHERE application_id=?`
	insertEndpointSQL    = `INSERT INTO webhook_endpoints(
id,application_id,url,description,status,row_version,created_at_ms,updated_at_ms
) VALUES(?,?,?,?,?,1,?,?)`
	selectEndpointSQL     = `SELECT ` + endpointColumns + ` FROM webhook_endpoints WHERE id=?`
	listEndpointsByAppSQL = `SELECT ` + endpointColumns + ` FROM webhook_endpoints
WHERE application_id=? ORDER BY created_at_ms,id`
	updateEndpointSQL = `UPDATE webhook_endpoints SET url=?,description=?,status=?,
row_version=row_version+1,updated_at_ms=? WHERE id=? AND row_version=?`
	insertSecretSQL = `INSERT INTO webhook_endpoint_secrets(
id,endpoint_id,secret_prefix,sealed_secret,sealer_key_id,created_at_ms,retire_at_ms,
revoked_at_ms) VALUES(?,?,?,?,?,?,?,NULL)`
	listSecretsSQL = `SELECT ` + secretColumns + ` FROM webhook_endpoint_secrets
WHERE endpoint_id=? ORDER BY created_at_ms,id`
	retireActiveSecretsSQL = `UPDATE webhook_endpoint_secrets SET retire_at_ms=?
WHERE endpoint_id=? AND revoked_at_ms IS NULL AND (retire_at_ms IS NULL OR retire_at_ms>?)`
	revokeSecretSQL = `UPDATE webhook_endpoint_secrets SET revoked_at_ms=?
WHERE id=? AND endpoint_id=? AND revoked_at_ms IS NULL`
	usableSecretsSQL = `SELECT ` + secretColumns + ` FROM webhook_endpoint_secrets
WHERE endpoint_id=? AND revoked_at_ms IS NULL AND (retire_at_ms IS NULL OR retire_at_ms>?)
ORDER BY created_at_ms,id LIMIT ?`
	insertEventSQL = `INSERT INTO webhook_events(
id,idempotency_key,type,application_id,subject_user_id,payload_json,truncated,
request_id,occurred_at_ms,created_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?)`
	selectEventByKeySQL = `SELECT ` + eventColumns + ` FROM webhook_events
WHERE idempotency_key=?`
	selectEventSQL    = `SELECT ` + eventColumns + ` FROM webhook_events WHERE id=?`
	insertDeliverySQL = `INSERT INTO webhook_deliveries(
id,event_id,endpoint_id,application_id,state,attempts,max_attempts,task_id,
last_error_code,last_error_kind,last_response_status,request_id,created_at_ms,
updated_at_ms,finished_at_ms) VALUES(?,?,?,?,'queued',0,?,'','','',0,?,?,?,NULL)`
	selectDeliverySQL  = `SELECT ` + deliveryColumns + ` FROM webhook_deliveries WHERE id=?`
	setDeliveryTaskSQL = `UPDATE webhook_deliveries SET task_id=?,updated_at_ms=?
WHERE id=?`
	markDeliverySendingSQL = `UPDATE webhook_deliveries SET state='sending',attempts=?,
updated_at_ms=?,finished_at_ms=NULL WHERE id=?
AND state IN('queued','sending')`
	finishDeliverySQL = `UPDATE webhook_deliveries SET state=?,last_error_code=?,
last_error_kind=?,last_response_status=?,updated_at_ms=?,finished_at_ms=?
WHERE id=? AND state IN('queued','sending')`
	requeueDeliverySQL = `UPDATE webhook_deliveries SET state='queued',updated_at_ms=?,
finished_at_ms=NULL WHERE id=? AND state='failed'`
	activeEndpointsForAppsSQL = `SELECT ` + endpointColumns + ` FROM webhook_endpoints
WHERE status='active' AND application_id IN (%s) ORDER BY application_id,created_at_ms,id`
	userAppIDsSQL = `SELECT app_id FROM app_memberships
WHERE user_id=? AND status='active' ORDER BY app_id`
	listDeliveriesBaseSQL = `SELECT ` + deliveryColumns + ` FROM webhook_deliveries`
)

// ApplicationActive 报告应用是否启用。
func (s *Store) ApplicationActive(ctx context.Context, applicationID string) (bool, error) {
	rows, err := s.store.QueryContext(ctx, applicationActiveSQL, applicationID)
	if err != nil {
		return false, webhook.ErrStoreUnavailable
	}
	defer rows.Close()
	if !rows.Next() {
		return false, rows.Err()
	}
	var count int
	if err := rows.Scan(&count); err != nil {
		return false, webhook.ErrStoreUnavailable
	}
	return count > 0, nil
}

// CountEndpoints 返回应用端点数量。
func (s *Store) CountEndpoints(ctx context.Context, applicationID string) (int, error) {
	rows, err := s.store.QueryContext(ctx, countEndpointsSQL, applicationID)
	if err != nil {
		return 0, webhook.ErrStoreUnavailable
	}
	defer rows.Close()
	if !rows.Next() {
		return 0, rows.Err()
	}
	var count int
	if err := rows.Scan(&count); err != nil {
		return 0, webhook.ErrStoreUnavailable
	}
	return count, nil
}

// CreateEndpointTx 在审计事务内创建端点。
func (s *Store) CreateEndpointTx(ctx context.Context, tx audit.Tx, endpoint webhook.EndpointRecord) error {
	if tx == nil {
		return webhook.ErrOptionsInvalid
	}
	if _, err := tx.ExecContext(ctx, insertEndpointSQL, endpoint.ID,
		endpoint.ApplicationID, endpoint.URL, endpoint.Description, string(endpoint.Status),
		endpoint.CreatedAt.UTC().UnixMilli(), endpoint.UpdatedAt.UTC().UnixMilli()); err != nil {
		return classifyWriteError(err)
	}
	return nil
}

// GetEndpoint 读取端点。
func (s *Store) GetEndpoint(ctx context.Context, endpointID string) (webhook.EndpointRecord, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectEndpointSQL, endpointID)
	if err != nil {
		return webhook.EndpointRecord{}, false, webhook.ErrStoreUnavailable
	}
	defer rows.Close()
	if !rows.Next() {
		return webhook.EndpointRecord{}, false, rows.Err()
	}
	record, err := scanEndpoint(rows)
	if err != nil {
		return webhook.EndpointRecord{}, false, webhook.ErrStoreUnavailable
	}
	return record, true, nil
}

// ListEndpointsByApp 列出应用端点。
func (s *Store) ListEndpointsByApp(ctx context.Context,
	applicationID string) ([]webhook.EndpointRecord, error) {
	rows, err := s.store.QueryContext(ctx, listEndpointsByAppSQL, applicationID)
	if err != nil {
		return nil, webhook.ErrStoreUnavailable
	}
	defer rows.Close()
	var records []webhook.EndpointRecord
	for rows.Next() {
		record, scanErr := scanEndpoint(rows)
		if scanErr != nil {
			return nil, webhook.ErrStoreUnavailable
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

// UpdateEndpointTx 条件更新端点。
func (s *Store) UpdateEndpointTx(ctx context.Context, tx audit.Tx,
	endpoint webhook.EndpointRecord) (bool, error) {
	if tx == nil {
		return false, webhook.ErrOptionsInvalid
	}
	result, err := tx.ExecContext(ctx, updateEndpointSQL, endpoint.URL, endpoint.Description,
		string(endpoint.Status), endpoint.UpdatedAt.UTC().UnixMilli(), endpoint.ID,
		endpoint.RowVersion-1)
	if err != nil {
		return false, classifyWriteError(err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, webhook.ErrStoreUnavailable
	}
	return affected == 1, nil
}

// CreateSecretTx 在审计事务内插入签名密钥。
func (s *Store) CreateSecretTx(ctx context.Context, tx audit.Tx, secret webhook.SecretRecord) error {
	if tx == nil {
		return webhook.ErrOptionsInvalid
	}
	var retireAt any
	if !secret.RetireAt.IsZero() {
		retireAt = secret.RetireAt.UTC().UnixMilli()
	}
	if _, err := tx.ExecContext(ctx, insertSecretSQL, secret.ID, secret.EndpointID,
		secret.Prefix, secret.SealedSecret, secret.SealerKeyID,
		secret.CreatedAt.UTC().UnixMilli(), retireAt); err != nil {
		return classifyWriteError(err)
	}
	return nil
}

// ListSecrets 列出端点密钥元数据。
func (s *Store) ListSecrets(ctx context.Context, endpointID string) ([]webhook.SecretRecord, error) {
	rows, err := s.store.QueryContext(ctx, listSecretsSQL, endpointID)
	if err != nil {
		return nil, webhook.ErrStoreUnavailable
	}
	defer rows.Close()
	var records []webhook.SecretRecord
	for rows.Next() {
		record, scanErr := scanSecret(rows)
		if scanErr != nil {
			return nil, webhook.ErrStoreUnavailable
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

// RetireActiveSecretsTx 把可用密钥设为在 retireAt 退役。
func (s *Store) RetireActiveSecretsTx(ctx context.Context, tx audit.Tx, endpointID string,
	retireAt, now time.Time) error {
	if tx == nil {
		return webhook.ErrOptionsInvalid
	}
	if _, err := tx.ExecContext(ctx, retireActiveSecretsSQL, retireAt.UTC().UnixMilli(),
		endpointID, now.UTC().UnixMilli()); err != nil {
		return webhook.ErrStoreUnavailable
	}
	return nil
}

// RevokeSecretTx 条件撤销密钥。
func (s *Store) RevokeSecretTx(ctx context.Context, tx audit.Tx, endpointID, secretID string,
	now time.Time) (bool, error) {
	if tx == nil {
		return false, webhook.ErrOptionsInvalid
	}
	result, err := tx.ExecContext(ctx, revokeSecretSQL, now.UTC().UnixMilli(), secretID,
		endpointID)
	if err != nil {
		return false, webhook.ErrStoreUnavailable
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, webhook.ErrStoreUnavailable
	}
	return affected == 1, nil
}

// UsableSecrets 返回 now 时刻可用密钥。
func (s *Store) UsableSecrets(ctx context.Context, endpointID string,
	now time.Time) ([]webhook.SecretRecord, error) {
	rows, err := s.store.QueryContext(ctx, usableSecretsSQL, endpointID,
		now.UTC().UnixMilli(), webhook.MaxUsableSecrets)
	if err != nil {
		return nil, webhook.ErrStoreUnavailable
	}
	defer rows.Close()
	var records []webhook.SecretRecord
	for rows.Next() {
		record, scanErr := scanSecret(rows)
		if scanErr != nil {
			return nil, webhook.ErrStoreUnavailable
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

// CreateEventWithDeliveries 在一个事务内创建事件与投递。
func (s *Store) CreateEventWithDeliveries(ctx context.Context, event webhook.EventRecord,
	deliveries []webhook.DeliveryRecord) (webhook.EventRecord, bool, error) {
	tx, err := s.store.DB().BeginTx(ctx, nil)
	if err != nil {
		return webhook.EventRecord{}, false, webhook.ErrStoreUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	if _, execErr := tx.ExecContext(ctx, insertEventSQL, event.ID, event.IdempotencyKey,
		event.Type, event.ApplicationID, event.SubjectUserID, string(event.PayloadJSON),
		boolToInt(event.Truncated), event.RequestID, event.OccurredAt.UTC().UnixMilli(),
		event.CreatedAt.UTC().UnixMilli()); execErr != nil {
		// 幂等命中：按幂等键回查既有事件（唯一约束错误类型由驱动包装方式决定，
		// 不依赖具体错误分类；键存在即意味着重复 Emit）。
		existing, found, lookupErr := s.getEventByIdempotencyKey(context.WithoutCancel(ctx),
			event.IdempotencyKey)
		if lookupErr != nil {
			return webhook.EventRecord{}, false, lookupErr
		}
		if found {
			return existing, true, nil
		}
		return webhook.EventRecord{}, false, classifyWriteError(execErr)
	}
	for _, delivery := range deliveries {
		if _, execErr := tx.ExecContext(ctx, insertDeliverySQL, delivery.ID,
			delivery.EventID, delivery.EndpointID, delivery.ApplicationID,
			delivery.MaxAttempts, delivery.RequestID, delivery.CreatedAt.UTC().UnixMilli(),
			delivery.UpdatedAt.UTC().UnixMilli()); execErr != nil {
			if isUniqueViolation(execErr) {
				return webhook.EventRecord{}, false, webhook.ErrConflict
			}
			return webhook.EventRecord{}, false, classifyWriteError(execErr)
		}
	}
	if err := tx.Commit(); err != nil {
		return webhook.EventRecord{}, false, webhook.ErrStoreUnavailable
	}
	return event, false, nil
}

func (s *Store) getEventByIdempotencyKey(ctx context.Context,
	key string) (webhook.EventRecord, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectEventByKeySQL, key)
	if err != nil {
		return webhook.EventRecord{}, false, webhook.ErrStoreUnavailable
	}
	defer rows.Close()
	if !rows.Next() {
		return webhook.EventRecord{}, false, rows.Err()
	}
	record, scanErr := scanEvent(rows)
	if scanErr != nil {
		return webhook.EventRecord{}, false, webhook.ErrStoreUnavailable
	}
	return record, true, nil
}

// ListActiveEndpointsForApps 返回应用集合的 active 端点。
func (s *Store) ListActiveEndpointsForApps(ctx context.Context,
	applicationIDs []string) ([]webhook.EndpointRecord, error) {
	if len(applicationIDs) == 0 {
		return nil, nil
	}
	placeholders := ""
	args := make([]any, 0, len(applicationIDs))
	for index, id := range applicationIDs {
		if index > 0 {
			placeholders += ","
		}
		placeholders += "?"
		args = append(args, id)
	}
	query := fmt.Sprintf(activeEndpointsForAppsSQL, placeholders)
	rows, err := s.store.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, webhook.ErrStoreUnavailable
	}
	defer rows.Close()
	var records []webhook.EndpointRecord
	for rows.Next() {
		record, scanErr := scanEndpoint(rows)
		if scanErr != nil {
			return nil, webhook.ErrStoreUnavailable
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

// UserAppIDs 返回用户 active 成员应用。
func (s *Store) UserAppIDs(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.store.QueryContext(ctx, userAppIDsSQL, userID)
	if err != nil {
		return nil, webhook.ErrStoreUnavailable
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, webhook.ErrStoreUnavailable
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// GetEvent 按 ID 读取事件。
func (s *Store) GetEvent(ctx context.Context, eventID string) (webhook.EventRecord, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectEventSQL, eventID)
	if err != nil {
		return webhook.EventRecord{}, false, webhook.ErrStoreUnavailable
	}
	defer rows.Close()
	if !rows.Next() {
		return webhook.EventRecord{}, false, rows.Err()
	}
	record, scanErr := scanEvent(rows)
	if scanErr != nil {
		return webhook.EventRecord{}, false, webhook.ErrStoreUnavailable
	}
	return record, true, nil
}

// GetDelivery 按 ID 读取投递。
func (s *Store) GetDelivery(ctx context.Context,
	deliveryID string) (webhook.DeliveryRecord, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectDeliverySQL, deliveryID)
	if err != nil {
		return webhook.DeliveryRecord{}, false, webhook.ErrStoreUnavailable
	}
	defer rows.Close()
	if !rows.Next() {
		return webhook.DeliveryRecord{}, false, rows.Err()
	}
	record, scanErr := scanDelivery(rows)
	if scanErr != nil {
		return webhook.DeliveryRecord{}, false, webhook.ErrStoreUnavailable
	}
	return record, true, nil
}

// SetDeliveryTask 关联任务 ID。
func (s *Store) SetDeliveryTask(ctx context.Context, deliveryID, taskID string,
	now time.Time) error {
	if _, err := s.store.ExecContext(ctx, setDeliveryTaskSQL, taskID,
		now.UTC().UnixMilli(), deliveryID); err != nil {
		return webhook.ErrStoreUnavailable
	}
	return nil
}

// MarkDeliverySending 记录一次尝试开始。
func (s *Store) MarkDeliverySending(ctx context.Context, deliveryID string, attempt int,
	now time.Time) error {
	if _, err := s.store.ExecContext(ctx, markDeliverySendingSQL, attempt,
		now.UTC().UnixMilli(), deliveryID); err != nil {
		return webhook.ErrStoreUnavailable
	}
	return nil
}

// FinishDelivery 条件写入终态。
func (s *Store) FinishDelivery(ctx context.Context, deliveryID string, state webhook.DeliveryState,
	errorCode, errorKind string, responseStatus int, now time.Time) error {
	finished := now.UTC().UnixMilli()
	if _, err := s.store.ExecContext(ctx, finishDeliverySQL, string(state), errorCode,
		errorKind, responseStatus, now.UTC().UnixMilli(), finished, deliveryID); err != nil {
		return webhook.ErrStoreUnavailable
	}
	return nil
}

// RequeueDelivery 把 failed 迁移回 queued。
func (s *Store) RequeueDelivery(ctx context.Context, deliveryID string, now time.Time) error {
	result, err := s.store.ExecContext(ctx, requeueDeliverySQL, now.UTC().UnixMilli(), deliveryID)
	if err != nil {
		return webhook.ErrStoreUnavailable
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return webhook.ErrStoreUnavailable
	}
	if affected != 1 {
		return webhook.ErrDeliveryConflict
	}
	return nil
}

// ListDeliveries 分页查询投递。
func (s *Store) ListDeliveries(ctx context.Context,
	query webhook.ListDeliveriesQuery) ([]webhook.DeliveryRecord, error) {
	statement := listDeliveriesBaseSQL
	args := make([]any, 0, 4)
	conditions := make([]string, 0, 3)
	if query.ApplicationID != "" {
		conditions = append(conditions, "application_id=?")
		args = append(args, query.ApplicationID)
	}
	if query.EndpointID != "" {
		conditions = append(conditions, "endpoint_id=?")
		args = append(args, query.EndpointID)
	}
	if query.State != "" {
		conditions = append(conditions, "state=?")
		args = append(args, string(query.State))
	}
	if len(conditions) > 0 {
		statement += " WHERE "
		for index, condition := range conditions {
			if index > 0 {
				statement += " AND "
			}
			statement += condition
		}
	}
	limit := query.Limit
	if limit <= 0 || limit > webhook.MaxListLimit {
		limit = webhook.MaxListLimit
	}
	statement += " ORDER BY created_at_ms DESC,id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := s.store.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, webhook.ErrStoreUnavailable
	}
	defer rows.Close()
	var records []webhook.DeliveryRecord
	for rows.Next() {
		record, scanErr := scanDelivery(rows)
		if scanErr != nil {
			return nil, webhook.ErrStoreUnavailable
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

// ===== 扫描辅助 =====

func scanEndpoint(rows rowScanner) (webhook.EndpointRecord, error) {
	var (
		record    webhook.EndpointRecord
		status    string
		createdMS int64
		updatedMS int64
	)
	if err := rows.Scan(&record.ID, &record.ApplicationID, &record.URL,
		&record.Description, &status, &record.RowVersion, &createdMS, &updatedMS); err != nil {
		return webhook.EndpointRecord{}, err
	}
	record.Status = webhook.EndpointStatus(status)
	record.CreatedAt = timeFromMillis(createdMS)
	record.UpdatedAt = timeFromMillis(updatedMS)
	return record, nil
}

func scanSecret(rows rowScanner) (webhook.SecretRecord, error) {
	var (
		record    webhook.SecretRecord
		createdMS int64
		retireMS  int64
		revokedMS int64
	)
	if err := rows.Scan(&record.ID, &record.EndpointID, &record.Prefix,
		&record.SealedSecret, &record.SealerKeyID, &createdMS, &retireMS,
		&revokedMS); err != nil {
		return webhook.SecretRecord{}, err
	}
	record.CreatedAt = timeFromMillis(createdMS)
	record.RetireAt = timeFromMillis(retireMS)
	record.RevokedAt = timeFromMillis(revokedMS)
	return record, nil
}

func scanEvent(rows rowScanner) (webhook.EventRecord, error) {
	var (
		record      webhook.EventRecord
		payload     []byte
		truncated   int
		occurredMS  int64
		createdAtMS int64
	)
	if err := rows.Scan(&record.ID, &record.IdempotencyKey, &record.Type,
		&record.ApplicationID, &record.SubjectUserID, &payload, &truncated,
		&record.RequestID, &occurredMS, &createdAtMS); err != nil {
		return webhook.EventRecord{}, err
	}
	record.PayloadJSON = payload
	record.Truncated = truncated != 0
	record.OccurredAt = timeFromMillis(occurredMS)
	record.CreatedAt = timeFromMillis(createdAtMS)
	return record, nil
}

func scanDelivery(rows rowScanner) (webhook.DeliveryRecord, error) {
	var (
		record     webhook.DeliveryRecord
		state      string
		createdMS  int64
		updatedMS  int64
		finishedMS int64
	)
	if err := rows.Scan(&record.ID, &record.EventID, &record.EndpointID,
		&record.ApplicationID, &state, &record.Attempts, &record.MaxAttempts,
		&record.TaskID, &record.LastErrorCode, &record.LastErrorKind,
		&record.LastResponseStatus, &record.RequestID, &createdMS, &updatedMS,
		&finishedMS); err != nil {
		return webhook.DeliveryRecord{}, err
	}
	record.State = webhook.DeliveryState(state)
	record.CreatedAt = timeFromMillis(createdMS)
	record.UpdatedAt = timeFromMillis(updatedMS)
	record.FinishedAt = timeFromMillis(finishedMS)
	return record, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func timeFromMillis(millis int64) time.Time {
	if millis == 0 {
		return time.Time{}
	}
	return time.UnixMilli(millis).UTC()
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

// classifyWriteError 把唯一约束映射为冲突，其余按存储不可用处理（不泄露 SQL 细节）。
func classifyWriteError(err error) error {
	if err == nil {
		return nil
	}
	if isUniqueViolation(err) {
		return webhook.ErrConflict
	}
	return webhook.ErrStoreUnavailable
}

func isUniqueViolation(err error) bool {
	return errors.Is(err, storage.ErrUniqueViolation)
}
