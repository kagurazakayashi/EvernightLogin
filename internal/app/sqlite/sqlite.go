// Package sqlite 实现 internal/app.Store 的 SQLite 生产仓储。
//
// 表结构来自 migrations/0001_identity_and_scope_core.sql 的 applications、scopes
// 与 app_memberships 表；本包不执行迁移。创建应用必须在调用方事务中同时写入
// applications 与对应 scopes 行（id=app_id, kind='application'），保证应用与作用
// 范围一致；应用成员读写始终以 (app_id,user_id) 为范围，profile_json 只保存应用
// 专属资料，不写回 users 表。
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/search"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const (
	applicationColumns = `a.id,a.name,a.description,a.icon_ref,a.homepage,a.owner_user_id,a.contact_info,a.status,a.client_type,a.row_version,a.created_at_ms,a.updated_at_ms,a.deleted_at_ms,s.id`

	selectApplicationByIDSQL = `SELECT ` + applicationColumns + `
FROM applications a LEFT JOIN scopes s ON s.app_id=a.id AND s.kind='application' WHERE a.id=?`

	insertApplicationSQL = `INSERT INTO applications(
id,name,description,icon_ref,homepage,owner_user_id,contact_info,status,client_type,row_version,created_at_ms,updated_at_ms
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`

	insertApplicationScopeSQL = `INSERT INTO scopes(id,kind,app_id) VALUES(?,'application',?)`

	updateApplicationSQL = `UPDATE applications SET name=?,description=?,icon_ref=?,homepage=?,owner_user_id=?,contact_info=?,row_version=row_version+1,updated_at_ms=?
WHERE id=? AND row_version=?`

	applyApplicationStatusSQL = `UPDATE applications SET status=?,row_version=row_version+1,updated_at_ms=?
WHERE id=? AND status=? AND row_version=?`

	markApplicationDeletedSQL = `UPDATE applications SET deleted_at_ms=?,row_version=row_version+1,updated_at_ms=?
WHERE id=? AND row_version=? AND status='disabled' AND deleted_at_ms IS NULL`

	deleteApplicationPurgeSQL = `DELETE FROM applications WHERE id=? AND deleted_at_ms IS NOT NULL`

	purgeRefreshTokenFamiliesSQL = `DELETE FROM refresh_token_families WHERE client_id=?`

	deletionImpactSQL = `SELECT
 (SELECT COUNT(*) FROM app_memberships WHERE app_id=?),
 (SELECT COUNT(*) FROM app_memberships WHERE app_id=? AND status='active'),
 (SELECT COUNT(*) FROM roles r JOIN scopes s ON s.id=r.scope_id WHERE s.app_id=?),
 (SELECT COUNT(*) FROM permissions p JOIN scopes s ON s.id=p.scope_id WHERE s.app_id=?),
 (SELECT COUNT(*) FROM user_groups g JOIN scopes s ON s.id=g.scope_id WHERE s.app_id=?),
 (SELECT COUNT(*) FROM sessions WHERE app_id=? AND revoked_at_ms IS NULL),
 (SELECT COUNT(*) FROM oauth_clients WHERE client_id=?),
 (SELECT COUNT(*) FROM refresh_token_families WHERE client_id=?),
 (SELECT COUNT(*) FROM oauth_authorization_requests WHERE client_id=?),
 (SELECT COUNT(*) FROM one_time_credentials WHERE app_id=?),
 (SELECT COUNT(*) FROM invitations WHERE app_id=?),
 (SELECT COUNT(*) FROM webhook_endpoints WHERE application_id=?),
 (SELECT COUNT(*) FROM audit_events WHERE app_id_snapshot=?)`

	selectUserEligibleSQL = `SELECT 1 FROM users WHERE id=? AND status='active'`
)

// Store 是 app.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装一个已打开并完成迁移的 SQLite 存储。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", app.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

// 编译期确认实现 app.Store。
var _ app.Store = (*Store)(nil)

// CreateApplication 在审计事务中原子创建 applications 行与应用 scope。scope 写入
// 失败时应用行随事务回滚，不会出现不一致。
func (s *Store) CreateApplication(ctx context.Context, tx audit.Tx, application app.Application) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", app.ErrOptionsInvalid)
	}
	if _, err := tx.ExecContext(ctx, insertApplicationSQL,
		application.ID,
		application.Name,
		application.Description,
		nullable(application.IconRef),
		nullable(application.Homepage),
		nullable(application.OwnerUserID),
		nullable(application.ContactInfo),
		string(application.Status),
		string(application.ClientType),
		application.RowVersion,
		application.CreatedAt.UTC().UnixMilli(),
		application.UpdatedAt.UTC().UnixMilli(),
	); err != nil {
		return fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	if _, err := tx.ExecContext(ctx, insertApplicationScopeSQL, application.ScopeID, application.ID); err != nil {
		return fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	return nil
}

// GetApplication 读取应用与 scope ID；scope 缺失视为存储不一致而拒绝返回。
func (s *Store) GetApplication(ctx context.Context, id string) (app.Application, error) {
	rows, err := s.store.QueryContext(ctx, selectApplicationByIDSQL, id)
	if err != nil {
		return app.Application{}, fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return app.Application{}, fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
		}
		return app.Application{}, app.ErrApplicationNotFound
	}
	application, err := scanApplication(rows)
	if err != nil {
		return app.Application{}, err
	}
	if err := rows.Err(); err != nil {
		return app.Application{}, fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	return application, nil
}

// ListApplications 执行有限分页查询；应用管理员限制通过 ApplicationIDs 过滤，
// 排序只映射白名单固定列名，绝不拼接调用方原文。
func (s *Store) ListApplications(ctx context.Context, query app.ListQuery) ([]app.Application, bool, error) {
	column, ok := sortColumn(query.Sort)
	if !ok {
		return nil, false, fmt.Errorf("%w: 排序字段不在允许列表内", app.ErrInvalidRequest)
	}
	direction := "ASC"
	if query.Descending {
		direction = "DESC"
	}
	statement := `SELECT ` + applicationColumns + `
FROM applications a LEFT JOIN scopes s ON s.app_id=a.id AND s.kind='application'`
	conditions := make([]string, 0, 2)
	args := make([]any, 0, 8)
	if query.Status != "" {
		conditions = append(conditions, "a.status=?")
		args = append(args, string(query.Status))
	}
	if !query.IncludeDeleted {
		conditions = append(conditions, "a.deleted_at_ms IS NULL")
	}
	if !query.AllApplications {
		if len(query.ApplicationIDs) == 0 {
			return []app.Application{}, false, nil
		}
		placeholders := make([]string, len(query.ApplicationIDs))
		for index, id := range query.ApplicationIDs {
			placeholders[index] = "?"
			args = append(args, id)
		}
		conditions = append(conditions, "a.id IN ("+strings.Join(placeholders, ",")+")")
	}
	if query.Search != "" {
		pattern := search.ContainsPattern(query.Search)
		if pattern != "" {
			searchClauses := make([]string, 0, len(query.SearchFields))
			for _, field := range query.SearchFields {
				switch field {
				case app.ApplicationSearchName:
					searchClauses = append(searchClauses, `LOWER(a.name) LIKE ? ESCAPE '!'`)
					args = append(args, pattern)
				case app.ApplicationSearchDescription:
					searchClauses = append(searchClauses, `LOWER(a.description) LIKE ? ESCAPE '!'`)
					args = append(args, pattern)
				default:
					// 服务层已按白名单校验；仓储再次 fail-closed，不生成未知列。
					return nil, false, fmt.Errorf("%w: 搜索字段不在允许列表内",
						app.ErrInvalidRequest)
				}
			}
			if len(searchClauses) == 0 {
				return nil, false, fmt.Errorf("%w: 搜索字段为空", app.ErrInvalidRequest)
			}
			conditions = append(conditions, `(`+strings.Join(searchClauses, ` OR `)+`)`)
		}
	}
	if len(conditions) > 0 {
		statement += ` WHERE ` + strings.Join(conditions, " AND ")
	}
	statement += ` ORDER BY ` + column + ` ` + direction + `, a.id ` + direction + ` LIMIT ? OFFSET ?`
	args = append(args, query.Limit+1, query.Offset)
	rows, err := s.store.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	applications := make([]app.Application, 0, query.Limit+1)
	for rows.Next() {
		application, scanErr := scanApplication(rows)
		if scanErr != nil {
			return nil, false, scanErr
		}
		applications = append(applications, application)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	hasMore := false
	if len(applications) > query.Limit {
		hasMore = true
		applications = applications[:query.Limit]
	}
	return applications, hasMore, nil
}

// UpdateApplication 执行带行版本条件的资料更新；字段来自已校验白名单。
func (s *Store) UpdateApplication(ctx context.Context, tx audit.Tx, update app.UpdateRecord) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", app.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, updateApplicationSQL,
		update.Name,
		update.Description,
		nullable(update.IconRef),
		nullable(update.Homepage),
		nullable(update.OwnerUserID),
		nullable(update.ContactInfo),
		update.Now.UTC().UnixMilli(),
		update.ApplicationID,
		update.ExpectedRowVersion,
	)
	if err != nil {
		return fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	return checkAffected(result)
}

// ApplyStatus 执行带状态与行版本条件的启停更新。
func (s *Store) ApplyStatus(ctx context.Context, tx audit.Tx, change app.StatusChange) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", app.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, applyApplicationStatusSQL,
		string(change.NewStatus),
		change.Now.UTC().UnixMilli(),
		change.ApplicationID,
		string(change.ExpectedStatus),
		change.ExpectedRowVersion,
	)
	if err != nil {
		return fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	return checkAffected(result)
}

// UserEligibleAsOwner 报告用户是否存在且可用（active）；负责人指向不可用账户时
// 拒绝更新，避免把应用交给已禁用/待删除账户。
func (s *Store) UserEligibleAsOwner(ctx context.Context, userID string) (bool, error) {
	rows, err := s.store.QueryContext(ctx, selectUserEligibleSQL, userID)
	if err != nil {
		return false, fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return false, fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
		}
		return false, nil
	}
	return true, rows.Err()
}

// MarkApplicationDeleted 以行版本与“当前未删除且已停用”为条件标记逻辑删除；只写
// deleted_at_ms 与行版本，不物理删除任何关联数据（保留审计与追溯）。
func (s *Store) MarkApplicationDeleted(ctx context.Context, tx audit.Tx,
	change app.DeletionChange) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", app.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, markApplicationDeletedSQL,
		change.Now.UTC().UnixMilli(),
		change.Now.UTC().UnixMilli(),
		change.ApplicationID,
		change.ExpectedRowVersion,
	)
	if err != nil {
		return fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	return checkAffected(result)
}

// DeletionImpact 读取删除前影响预览；计数只用于展示与审计，不改变授权判定。
func (s *Store) DeletionImpact(ctx context.Context, applicationID string) (app.DeletionImpact, error) {
	rows, err := s.store.QueryContext(ctx, deletionImpactSQL,
		applicationID, applicationID, applicationID, applicationID, applicationID,
		applicationID, applicationID, applicationID, applicationID, applicationID,
		applicationID, applicationID, applicationID)
	if err != nil {
		return app.DeletionImpact{}, fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return app.DeletionImpact{}, fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
		}
		return app.DeletionImpact{}, app.ErrApplicationNotFound
	}
	var impact app.DeletionImpact
	if err := rows.Scan(&impact.MemberCount, &impact.ActiveMemberCount, &impact.RoleCount,
		&impact.PermissionCount, &impact.GroupCount, &impact.ActiveSessionCount,
		&impact.OAuthClientCount, &impact.RefreshTokenFamilyCount,
		&impact.AuthorizationRequestCount, &impact.CredentialCount,
		&impact.InvitationCount, &impact.WebhookEndpointCount,
		&impact.AuditEventCount); err != nil {
		return app.DeletionImpact{}, fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	if err := rows.Err(); err != nil {
		return app.DeletionImpact{}, fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	return impact, nil
}

// PurgeApplication 在调用方审计事务中物理清理已逻辑删除的应用：先显式删除没有外键
// 约束的刷新令牌族，再删除 applications 行（其外键以 ON DELETE CASCADE 清理作用范围/
// 成员/角色/权限/组/会话/客户端/授权/凭证/邀请/Webhook 配置/托管策略）。共享账户与
// audit_events（app_id_snapshot 无外键）保留。
func (s *Store) PurgeApplication(ctx context.Context, tx audit.Tx, applicationID string) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", app.ErrOptionsInvalid)
	}
	if _, err := tx.ExecContext(ctx, purgeRefreshTokenFamiliesSQL, applicationID); err != nil {
		return fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	result, err := tx.ExecContext(ctx, deleteApplicationPurgeSQL, applicationID)
	if err != nil {
		return fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	switch affected {
	case 1:
		return nil
	case 0:
		return app.ErrApplicationNotFound
	default:
		return fmt.Errorf("%w: 物理清理影响行数异常", app.ErrStoreUnavailable)
	}
}

// checkAffected 把条件更新结果转换为领域错误。
func checkAffected(result sql.Result) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	switch affected {
	case 1:
		return nil
	case 0:
		return app.ErrStateConflict
	default:
		return fmt.Errorf("%w: 条件更新影响行数异常", app.ErrStoreUnavailable)
	}
}

// scanApplication 读取一行应用快照并校验状态/客户端类型/scope 一致性。
func scanApplication(rows *sql.Rows) (app.Application, error) {
	var (
		application app.Application
		iconRef     sql.NullString
		homepage    sql.NullString
		ownerUserID sql.NullString
		contactInfo sql.NullString
		status      string
		clientType  string
		createdAtMS int64
		updatedAtMS int64
		deletedAtMS sql.NullInt64
		scopeID     sql.NullString
	)
	if err := rows.Scan(
		&application.ID,
		&application.Name,
		&application.Description,
		&iconRef,
		&homepage,
		&ownerUserID,
		&contactInfo,
		&status,
		&clientType,
		&application.RowVersion,
		&createdAtMS,
		&updatedAtMS,
		&deletedAtMS,
		&scopeID,
	); err != nil {
		return app.Application{}, fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	if deletedAtMS.Valid {
		application.DeletedAt = time.UnixMilli(deletedAtMS.Int64).UTC()
	}
	application.IconRef = iconRef.String
	application.Homepage = homepage.String
	application.OwnerUserID = ownerUserID.String
	application.ContactInfo = contactInfo.String
	application.Status = app.Status(status)
	application.ClientType = app.ClientType(clientType)
	if !application.Status.Valid() {
		return app.Application{}, fmt.Errorf("%w: 应用状态数据无效", app.ErrStoreUnavailable)
	}
	if !application.ClientType.Valid() {
		return app.Application{}, fmt.Errorf("%w: 应用客户端类型数据无效", app.ErrStoreUnavailable)
	}
	if !app.ValidApplicationID(application.ID) {
		return app.Application{}, fmt.Errorf("%w: 应用 ID 数据格式无效", app.ErrStoreUnavailable)
	}
	if !scopeID.Valid || scopeID.String != app.ScopeID(application.ID) {
		return app.Application{}, fmt.Errorf("%w: 应用作用范围缺失或不一致", app.ErrStoreUnavailable)
	}
	application.ScopeID = scopeID.String
	application.CreatedAt = time.UnixMilli(createdAtMS).UTC()
	application.UpdatedAt = time.UnixMilli(updatedAtMS).UTC()
	return application, nil
}

// sortColumn 把排序枚举映射为固定 SQL 列名。
func sortColumn(sort app.SortField) (string, bool) {
	switch sort {
	case app.SortID:
		return "a.id", true
	case app.SortName:
		return "a.name", true
	case app.SortCreatedAt:
		return "a.created_at_ms", true
	case app.SortUpdatedAt:
		return "a.updated_at_ms", true
	default:
		return "", false
	}
}

// nullable 把空字符串映射为 SQL NULL；展示字段允许为空。
func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}
