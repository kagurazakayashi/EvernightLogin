// Package sqlite 实现 internal/app.Store 的 SQLite 生产仓储。
//
// 表结构来自 migrations/0001_identity_and_scope_core.sql 的 applications 与
// scopes 表；本包不执行迁移。创建应用必须在调用方事务中同时写入 applications
// 与对应 scopes 行（id=app_id, kind='application'），保证应用与作用范围一致。
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const (
	applicationColumns = `a.id,a.name,a.description,a.icon_ref,a.homepage,a.owner_user_id,a.contact_info,a.status,a.client_type,a.row_version,a.created_at_ms,a.updated_at_ms,s.id`

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
		&scopeID,
	); err != nil {
		return app.Application{}, fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
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
