// Package sqlite 实现 internal/oauthclient.Store 的 SQLite 生产仓储。
//
// 表结构由 migrations/0029_oauth_clients.sql 创建；本包不执行迁移、不拥有数据库
// 连接。客户端密钥只保存前缀与 32 字节摘要，证书身份只保存公钥证书与指纹；安全
// 设置更新使用行版本条件更新，凭证撤销使用条件更新以保证并发单赢家。
package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const clientSelectColumns = `c.client_id,a.status,c.client_type,c.grant_types_json,
c.redirect_uris_json,c.post_logout_redirect_uris_json,c.scopes_json,c.audiences_json,
c.auth_methods_json,c.require_pkce,c.row_version,c.created_at_ms,c.updated_at_ms`

const getClientSQL = `SELECT ` + clientSelectColumns + `
FROM oauth_clients c JOIN applications a ON a.id=c.client_id WHERE c.client_id=?`

const lookupApplicationSQL = `SELECT client_type,status FROM applications WHERE id=?`

const insertClientSQL = `INSERT INTO oauth_clients(
client_id,client_type,grant_types_json,redirect_uris_json,post_logout_redirect_uris_json,
scopes_json,audiences_json,auth_methods_json,require_pkce,row_version,created_at_ms,updated_at_ms
) VALUES(?,?,?,?,?,?,?,?,?,1,?,?)`

const updateClientSQL = `UPDATE oauth_clients SET grant_types_json=?,redirect_uris_json=?,
post_logout_redirect_uris_json=?,scopes_json=?,audiences_json=?,require_pkce=?,
row_version=row_version+1,updated_at_ms=? WHERE client_id=? AND row_version=?`

const listSecretsSQL = `SELECT id,client_id,secret_prefix,secret_digest,created_at_ms,
expires_at_ms,COALESCE(retire_at_ms,0),COALESCE(revoked_at_ms,0)
FROM oauth_client_secrets WHERE client_id=? ORDER BY created_at_ms DESC,id`

const insertSecretSQL = `INSERT INTO oauth_client_secrets(
id,client_id,secret_prefix,secret_digest,created_at_ms,expires_at_ms,retire_at_ms,revoked_at_ms
) VALUES(?,?,?,?,?,?,?,NULL)`

const retireSecretsSQL = `UPDATE oauth_client_secrets SET retire_at_ms=?
WHERE client_id=? AND revoked_at_ms IS NULL AND retire_at_ms IS NULL AND expires_at_ms>?`

const revokeSecretSQL = `UPDATE oauth_client_secrets SET revoked_at_ms=?
WHERE id=? AND client_id=? AND revoked_at_ms IS NULL`

const listCertificatesSQL = `SELECT id,client_id,fingerprint_sha256,subject,not_before_ms,
not_after_ms,certificate_pem,created_at_ms,COALESCE(revoked_at_ms,0)
FROM oauth_client_certificates WHERE client_id=? ORDER BY created_at_ms DESC,id`

const insertCertificateSQL = `INSERT INTO oauth_client_certificates(
id,client_id,fingerprint_sha256,subject,not_before_ms,not_after_ms,certificate_pem,
created_at_ms,revoked_at_ms
) VALUES(?,?,?,?,?,?,?,?,NULL)`

const revokeCertificateSQL = `UPDATE oauth_client_certificates SET revoked_at_ms=?
WHERE id=? AND client_id=? AND revoked_at_ms IS NULL`

// Store 是 oauthclient.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装已迁移的 SQLite 存储。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", oauthclient.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

var _ oauthclient.Store = (*Store)(nil)

// LookupApplication 读取应用客户端类型与状态。
func (s *Store) LookupApplication(ctx context.Context, applicationID string) (oauthclient.AppSnapshot, bool, error) {
	rows, err := s.store.QueryContext(ctx, lookupApplicationSQL, applicationID)
	if err != nil {
		return oauthclient.AppSnapshot{}, false, fmt.Errorf("%w: %w", oauthclient.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return oauthclient.AppSnapshot{}, false, nil
	}
	var clientType, status string
	if err := rows.Scan(&clientType, &status); err != nil {
		return oauthclient.AppSnapshot{}, false, fmt.Errorf("%w: %w", oauthclient.ErrStoreUnavailable, err)
	}
	return oauthclient.AppSnapshot{ApplicationID: applicationID,
		ClientType: oauthclient.ClientType(clientType), Status: status}, true, nil
}

// GetClient 读取客户端配置。
func (s *Store) GetClient(ctx context.Context, clientID string) (oauthclient.ClientRecord, bool, error) {
	rows, err := s.store.QueryContext(ctx, getClientSQL, clientID)
	if err != nil {
		return oauthclient.ClientRecord{}, false, fmt.Errorf("%w: %w", oauthclient.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return oauthclient.ClientRecord{}, false, nil
	}
	var record oauthclient.ClientRecord
	var appStatus, clientType string
	var grants, redirects, logoutURIs, scopes, audiences, methods []byte
	var requirePKCE int
	var createdAt, updatedAt int64
	if err := rows.Scan(&record.ClientID, &appStatus, &clientType, &grants,
		&redirects, &logoutURIs, &scopes, &audiences, &methods, &requirePKCE,
		&record.RowVersion, &createdAt, &updatedAt); err != nil {
		return oauthclient.ClientRecord{}, false, fmt.Errorf("%w: %w", oauthclient.ErrStoreUnavailable, err)
	}
	record.AppStatus = appStatus
	record.ClientType = oauthclient.ClientType(clientType)
	record.RequirePKCE = requirePKCE == 1
	if err := decodeStringList(grants, &record.GrantTypes); err != nil {
		return oauthclient.ClientRecord{}, false, err
	}
	if err := decodeStringList(redirects, &record.RedirectURIs); err != nil {
		return oauthclient.ClientRecord{}, false, err
	}
	if err := decodeStringList(logoutURIs, &record.PostLogoutRedirectURIs); err != nil {
		return oauthclient.ClientRecord{}, false, err
	}
	if err := decodeStringList(scopes, &record.Scopes); err != nil {
		return oauthclient.ClientRecord{}, false, err
	}
	if err := decodeStringList(audiences, &record.Audiences); err != nil {
		return oauthclient.ClientRecord{}, false, err
	}
	if err := decodeStringList(methods, &record.AuthMethods); err != nil {
		return oauthclient.ClientRecord{}, false, err
	}
	record.CreatedAt = time.UnixMilli(createdAt).UTC()
	record.UpdatedAt = time.UnixMilli(updatedAt).UTC()
	return record, true, nil
}

// CreateClientTx 在审计事务内创建客户端配置与初始凭证。
func (s *Store) CreateClientTx(ctx context.Context, tx audit.Tx, record oauthclient.ClientRecord,
	secret *oauthclient.SecretRecord, certificate *oauthclient.CertificateRecord) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", oauthclient.ErrOptionsInvalid)
	}
	grants, err := encodeStringList(record.GrantTypes)
	if err != nil {
		return err
	}
	redirects, err := encodeStringList(record.RedirectURIs)
	if err != nil {
		return err
	}
	logoutURIs, err := encodeStringList(record.PostLogoutRedirectURIs)
	if err != nil {
		return err
	}
	scopes, err := encodeStringList(record.Scopes)
	if err != nil {
		return err
	}
	audiences, err := encodeStringList(record.Audiences)
	if err != nil {
		return err
	}
	methods, err := encodeStringList(record.AuthMethods)
	if err != nil {
		return err
	}
	requirePKCE := 0
	if record.RequirePKCE {
		requirePKCE = 1
	}
	if _, err := tx.ExecContext(ctx, insertClientSQL, record.ClientID, string(record.ClientType),
		grants, redirects, logoutURIs, scopes, audiences, methods, requirePKCE,
		record.CreatedAt.UTC().UnixMilli(), record.UpdatedAt.UTC().UnixMilli()); err != nil {
		return fmt.Errorf("%w: %w", oauthclient.ErrStoreUnavailable, err)
	}
	if secret != nil {
		if err := insertSecretTx(ctx, tx, *secret); err != nil {
			return err
		}
	}
	if certificate != nil {
		if _, err := tx.ExecContext(ctx, insertCertificateSQL, certificate.ID, certificate.ClientID,
			certificate.FingerprintSHA256[:], certificate.Subject,
			certificate.NotBefore.UTC().UnixMilli(), certificate.NotAfter.UTC().UnixMilli(),
			certificate.CertificatePEM, certificate.CreatedAt.UTC().UnixMilli()); err != nil {
			return fmt.Errorf("%w: %w", oauthclient.ErrStoreUnavailable, err)
		}
	}
	return nil
}

// UpdateClientTx 按行版本条件更新安全设置。
func (s *Store) UpdateClientTx(ctx context.Context, tx audit.Tx, update oauthclient.ClientUpdate) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", oauthclient.ErrOptionsInvalid)
	}
	grants, err := encodeStringList(update.GrantTypes)
	if err != nil {
		return false, err
	}
	redirects, err := encodeStringList(update.RedirectURIs)
	if err != nil {
		return false, err
	}
	logoutURIs, err := encodeStringList(update.PostLogoutRedirectURIs)
	if err != nil {
		return false, err
	}
	scopes, err := encodeStringList(update.Scopes)
	if err != nil {
		return false, err
	}
	audiences, err := encodeStringList(update.Audiences)
	if err != nil {
		return false, err
	}
	requirePKCE := 0
	if update.RequirePKCE {
		requirePKCE = 1
	}
	result, err := tx.ExecContext(ctx, updateClientSQL, grants, redirects, logoutURIs, scopes,
		audiences, requirePKCE, update.UpdatedAt.UTC().UnixMilli(), update.ClientID,
		update.ExpectedRowVersion)
	if err != nil {
		return false, fmt.Errorf("%w: %w", oauthclient.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%w: %w", oauthclient.ErrStoreUnavailable, err)
	}
	return affected == 1, nil
}

// ListSecrets 列出客户端密钥记录。
func (s *Store) ListSecrets(ctx context.Context, clientID string) ([]oauthclient.SecretRecord, error) {
	rows, err := s.store.QueryContext(ctx, listSecretsSQL, clientID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", oauthclient.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	records := make([]oauthclient.SecretRecord, 0, 2)
	for rows.Next() {
		var record oauthclient.SecretRecord
		var digest []byte
		var createdAt, expiresAt, retireAt, revokedAt int64
		if err := rows.Scan(&record.ID, &record.ClientID, &record.Prefix, &digest,
			&createdAt, &expiresAt, &retireAt, &revokedAt); err != nil {
			return nil, fmt.Errorf("%w: %w", oauthclient.ErrStoreUnavailable, err)
		}
		if len(digest) != 32 {
			return nil, fmt.Errorf("%w: 密钥摘要长度异常", oauthclient.ErrStoreUnavailable)
		}
		copy(record.Digest[:], digest)
		record.CreatedAt = time.UnixMilli(createdAt).UTC()
		record.ExpiresAt = time.UnixMilli(expiresAt).UTC()
		if retireAt > 0 {
			record.RetireAt = time.UnixMilli(retireAt).UTC()
		}
		if revokedAt > 0 {
			record.RevokedAt = time.UnixMilli(revokedAt).UTC()
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", oauthclient.ErrStoreUnavailable, err)
	}
	return records, nil
}

// InsertSecretTx 在审计事务内插入新密钥。
func (s *Store) InsertSecretTx(ctx context.Context, tx audit.Tx, record oauthclient.SecretRecord) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", oauthclient.ErrOptionsInvalid)
	}
	return insertSecretTx(ctx, tx, record)
}

func insertSecretTx(ctx context.Context, tx audit.Tx, record oauthclient.SecretRecord) error {
	var retireAt any
	if !record.RetireAt.IsZero() {
		retireAt = record.RetireAt.UTC().UnixMilli()
	}
	if _, err := tx.ExecContext(ctx, insertSecretSQL, record.ID, record.ClientID, record.Prefix,
		record.Digest[:], record.CreatedAt.UTC().UnixMilli(), record.ExpiresAt.UTC().UnixMilli(),
		retireAt); err != nil {
		return fmt.Errorf("%w: %w", oauthclient.ErrStoreUnavailable, err)
	}
	return nil
}

// RetireActiveSecretsTx 把客户端当前可用密钥标记为过渡期退休。
func (s *Store) RetireActiveSecretsTx(ctx context.Context, tx audit.Tx, clientID string,
	retireAt, now time.Time) (int64, error) {
	if tx == nil {
		return 0, fmt.Errorf("%w: 审计事务为空", oauthclient.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, retireSecretsSQL, retireAt.UTC().UnixMilli(),
		clientID, now.UTC().UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("%w: %w", oauthclient.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("%w: %w", oauthclient.ErrStoreUnavailable, err)
	}
	return affected, nil
}

// RevokeSecretTx 条件撤销指定密钥。
func (s *Store) RevokeSecretTx(ctx context.Context, tx audit.Tx, clientID, secretID string,
	now time.Time) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", oauthclient.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, revokeSecretSQL, now.UTC().UnixMilli(), secretID, clientID)
	if err != nil {
		return false, fmt.Errorf("%w: %w", oauthclient.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%w: %w", oauthclient.ErrStoreUnavailable, err)
	}
	return affected == 1, nil
}

// ListCertificates 列出客户端证书记录。
func (s *Store) ListCertificates(ctx context.Context, clientID string) ([]oauthclient.CertificateRecord, error) {
	rows, err := s.store.QueryContext(ctx, listCertificatesSQL, clientID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", oauthclient.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	records := make([]oauthclient.CertificateRecord, 0, 2)
	for rows.Next() {
		var record oauthclient.CertificateRecord
		var fingerprint []byte
		var notBefore, notAfter, createdAt, revokedAt int64
		if err := rows.Scan(&record.ID, &record.ClientID, &fingerprint, &record.Subject,
			&notBefore, &notAfter, &record.CertificatePEM, &createdAt, &revokedAt); err != nil {
			return nil, fmt.Errorf("%w: %w", oauthclient.ErrStoreUnavailable, err)
		}
		if len(fingerprint) != 32 {
			return nil, fmt.Errorf("%w: 证书指纹长度异常", oauthclient.ErrStoreUnavailable)
		}
		copy(record.FingerprintSHA256[:], fingerprint)
		record.NotBefore = time.UnixMilli(notBefore).UTC()
		record.NotAfter = time.UnixMilli(notAfter).UTC()
		record.CreatedAt = time.UnixMilli(createdAt).UTC()
		if revokedAt > 0 {
			record.RevokedAt = time.UnixMilli(revokedAt).UTC()
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", oauthclient.ErrStoreUnavailable, err)
	}
	return records, nil
}

// InsertCertificateTx 在审计事务内插入证书身份。
func (s *Store) InsertCertificateTx(ctx context.Context, tx audit.Tx, record oauthclient.CertificateRecord) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", oauthclient.ErrOptionsInvalid)
	}
	if _, err := tx.ExecContext(ctx, insertCertificateSQL, record.ID, record.ClientID,
		record.FingerprintSHA256[:], record.Subject,
		record.NotBefore.UTC().UnixMilli(), record.NotAfter.UTC().UnixMilli(),
		record.CertificatePEM, record.CreatedAt.UTC().UnixMilli()); err != nil {
		return fmt.Errorf("%w: %w", oauthclient.ErrStoreUnavailable, err)
	}
	return nil
}

// RevokeCertificateTx 条件撤销指定证书。
func (s *Store) RevokeCertificateTx(ctx context.Context, tx audit.Tx, clientID, certificateID string,
	now time.Time) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", oauthclient.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, revokeCertificateSQL, now.UTC().UnixMilli(), certificateID, clientID)
	if err != nil {
		return false, fmt.Errorf("%w: %w", oauthclient.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%w: %w", oauthclient.ErrStoreUnavailable, err)
	}
	return affected == 1, nil
}

// encodeStringList 把字符串序列编码为稳定 JSON 数组；空序列编码为空数组。
func encodeStringList[T ~string](values []T) ([]byte, error) {
	encoded := make([]string, 0, len(values))
	for _, value := range values {
		encoded = append(encoded, string(value))
	}
	if encoded == nil {
		encoded = []string{}
	}
	data, err := json.Marshal(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: 安全设置序列化失败", oauthclient.ErrStoreUnavailable)
	}
	return data, nil
}

// decodeStringList 把 JSON 字符串数组解码到目标切片；空数组得到 nil 切片。
func decodeStringList[T ~string](data []byte, target *[]T) error {
	var values []string
	if len(data) > 0 {
		if err := json.Unmarshal(data, &values); err != nil {
			return fmt.Errorf("%w: 安全设置反序列化失败", oauthclient.ErrStoreUnavailable)
		}
	}
	decoded := make([]T, 0, len(values))
	for _, value := range values {
		decoded = append(decoded, T(value))
	}
	if len(decoded) == 0 {
		*target = nil
		return nil
	}
	*target = decoded
	return nil
}
