// Package sqlite 实现 internal/onboarding.Store 的 SQLite 生产仓储。
//
// 表由 migrations/0014_onboarding.sql 创建，并复用 0001 的 users/applications/
// app_memberships/user_roles 与 0009 的 user_emails/password_credentials。本包不执行
// 迁移、不拥有数据库连接；构造后不可变，可被并发使用。
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	"github.com/kagurazakayashi/EvernightLogin/internal/onboarding"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const insertInvitationSQL = `INSERT INTO invitations(
id,inviter_user_id,target_kind,target_email,target_user_id,app_id,status,max_uses,used_count,
expires_at_ms,created_at_ms,updated_at_ms,request_id,notify_state
) VALUES(?,?,?,?,?,?,'pending',?,0,?,?,?,?,'pending')`

const selectInvitationColumns = `id,inviter_user_id,target_kind,target_email,target_user_id,
app_id,status,max_uses,used_count,expires_at_ms,created_at_ms,updated_at_ms,
cancelled_at_ms,cancel_reason,notify_state,notify_error_code,notified_at_ms`

const selectInvitationSQL = `SELECT ` + selectInvitationColumns + ` FROM invitations WHERE id=?`

const selectRolesSQL = `SELECT role_id,scope_id FROM invitation_roles WHERE invitation_id=? ORDER BY role_id`

const cancelInvitationSQL = `UPDATE invitations SET status='cancelled',cancelled_at_ms=?,cancel_reason=?,
updated_at_ms=? WHERE id=? AND status='pending'`

const incrementInvitationSQL = `UPDATE invitations SET used_count=used_count+1,
status=CASE WHEN used_count+1>=max_uses THEN 'accepted' ELSE 'pending' END,
updated_at_ms=? WHERE id=? AND status='pending' AND used_count<max_uses AND expires_at_ms>?`

const insertAcceptanceSQL = `INSERT INTO invitation_acceptances(invitation_id,user_id,accepted_at_ms,request_id)
VALUES(?,?,?,?)`

const insertInvitedUserSQL = `INSERT INTO users(
id,username,username_normalized,nickname,biography,avatar_ref,language,timezone,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms
) VALUES(?,?,?,?,'',NULL,?,?,'active',0,1,1,?,?)`

const insertInvitedPasswordSQL = `INSERT INTO password_credentials(
user_id,hash_scheme,hash_version,password_hash,must_change,row_version,created_at_ms,updated_at_ms,changed_at_ms
) VALUES(?,'argon2id',19,?,0,1,?,?,?)`

const insertInvitedEmailSQL = `INSERT INTO user_emails(email_normalized,user_id,email,verified_at_ms,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?)`

const upsertMembershipSQL = `INSERT INTO app_memberships(
app_id,user_id,status,profile_json,row_version,created_at_ms,updated_at_ms
) VALUES(?,?,'active','{}',1,?,?)
ON CONFLICT(app_id,user_id) DO UPDATE SET status='active',row_version=row_version+1,updated_at_ms=excluded.updated_at_ms`

const insertUserRoleSQL = `INSERT INTO user_roles(user_id,role_id,scope_id,data_scope_json,assigned_by,created_at_ms)
SELECT ?,?,?,'{}',?,? FROM roles r WHERE r.id=? AND r.scope_id=? AND r.enabled=1
ON CONFLICT(user_id,role_id) DO NOTHING`

const markInvitationNotifySQL = `UPDATE invitations SET notify_state=?,notify_error_code=?,notified_at_ms=?
WHERE id=?`

const markReviewNotifySQL = `UPDATE registration_reviews SET notify_state=?,notify_error_code=?,notified_at_ms=?
WHERE user_id=?`

const selectReviewColumns = `u.id,u.username,u.status,COALESCE(r.status,'pending'),
COALESCE(r.reason,''),COALESCE(r.decided_by_type,''),COALESCE(r.decided_by_id,''),
r.decided_at_ms,u.created_at_ms,COALESCE(r.notify_state,'pending'),
COALESCE(r.notify_error_code,''),r.notified_at_ms`

const selectReviewByIDSQL = `SELECT ` + selectReviewColumns + ` FROM users u
LEFT JOIN registration_reviews r ON r.user_id=u.id WHERE u.id=?`

const listPendingReviewsSQL = `SELECT ` + selectReviewColumns + ` FROM users u
LEFT JOIN registration_reviews r ON r.user_id=u.id
WHERE u.status='pending' ORDER BY u.created_at_ms DESC,u.id LIMIT ? OFFSET ?`

const upsertReviewSQL = `INSERT INTO registration_reviews(
user_id,status,reason,decided_by_type,decided_by_id,decided_at_ms,created_at_ms,updated_at_ms,
request_id,notify_state,notify_error_code,notified_at_ms
) VALUES(?,?,?,?,?,?,?,?,?,'pending',NULL,NULL)
ON CONFLICT(user_id) DO UPDATE SET
status=excluded.status,reason=excluded.reason,decided_by_type=excluded.decided_by_type,
decided_by_id=excluded.decided_by_id,decided_at_ms=excluded.decided_at_ms,
updated_at_ms=excluded.updated_at_ms,request_id=excluded.request_id,
notify_state='pending',notify_error_code=NULL,notified_at_ms=NULL`

// Store 是 onboarding.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装已迁移的 SQLite 存储；store 为空时返回 ErrOptionsInvalid。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", onboarding.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

var _ onboarding.Store = (*Store)(nil)

// CreateInvitation 在审计事务内写邀请与允许角色。
func (s *Store) CreateInvitation(ctx context.Context, tx audit.Tx, record onboarding.InvitationRecord) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", onboarding.ErrOptionsInvalid)
	}
	if record.AppID != "" {
		rows, err := tx.QueryContext(ctx, `SELECT status FROM applications WHERE id=?`, record.AppID)
		if err != nil {
			return fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
		}
		found := rows.Next()
		_ = rows.Close()
		if !found {
			return fmt.Errorf("%w: 适用应用不存在", onboarding.ErrInvalidRequest)
		}
	}
	for _, role := range record.Roles {
		rows, err := tx.QueryContext(ctx,
			`SELECT 1 FROM roles WHERE id=? AND scope_id=? AND enabled=1`, role.RoleID, role.ScopeID)
		if err != nil {
			return fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
		}
		found := rows.Next()
		_ = rows.Close()
		if !found {
			return fmt.Errorf("%w: 角色不存在、已停用或作用域不匹配", onboarding.ErrInvalidRequest)
		}
	}
	now := record.Now.UTC().UnixMilli()
	var targetEmail, targetUserID any
	if record.TargetKind == onboarding.TargetEmail {
		targetEmail = record.TargetEmail
	} else {
		targetUserID = record.TargetUserID
	}
	if _, err := tx.ExecContext(ctx, insertInvitationSQL,
		record.ID, record.InviterUserID, string(record.TargetKind), targetEmail, targetUserID,
		nullableString(record.AppID), record.MaxUses, record.ExpiresAt.UTC().UnixMilli(),
		now, now, nullableString(record.RequestID)); err != nil {
		return fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	for _, role := range record.Roles {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO invitation_roles(invitation_id,role_id,scope_id) VALUES(?,?,?)`,
			record.ID, role.RoleID, role.ScopeID); err != nil {
			return fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
		}
	}
	return nil
}

// GetInvitation 读取邀请快照。
func (s *Store) GetInvitation(ctx context.Context, id string) (onboarding.Invitation, bool, error) {
	return s.loadInvitation(ctx, nil, id)
}

// LoadInvitationTx 在审计事务内读取邀请快照。
func (s *Store) LoadInvitationTx(ctx context.Context, tx audit.Tx, id string) (onboarding.Invitation, bool, error) {
	if tx == nil {
		return onboarding.Invitation{}, false, fmt.Errorf("%w: 审计事务为空", onboarding.ErrOptionsInvalid)
	}
	return s.loadInvitation(ctx, tx, id)
}

// loadInvitation 从 store 或 tx 读取邀请与角色。
func (s *Store) loadInvitation(ctx context.Context, tx audit.Tx, id string) (onboarding.Invitation, bool, error) {
	query := func(queryText string, args ...any) (*sql.Rows, error) {
		if tx != nil {
			return tx.QueryContext(ctx, queryText, args...)
		}
		return s.store.QueryContext(ctx, queryText, args...)
	}
	rows, err := query(selectInvitationSQL, id)
	if err != nil {
		return onboarding.Invitation{}, false, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	invitation, found, err := scanInvitation(rows)
	if err != nil || !found {
		return invitation, found, err
	}
	roleRows, err := query(selectRolesSQL, id)
	if err != nil {
		return onboarding.Invitation{}, false, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	defer roleRows.Close()
	for roleRows.Next() {
		var role onboarding.Role
		if err := roleRows.Scan(&role.RoleID, &role.ScopeID); err != nil {
			return onboarding.Invitation{}, false, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
		}
		invitation.Roles = append(invitation.Roles, role)
	}
	return invitation, true, nil
}

// scanInvitation 扫描单行邀请。
func scanInvitation(rows *sql.Rows) (onboarding.Invitation, bool, error) {
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return onboarding.Invitation{}, false, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
		}
		return onboarding.Invitation{}, false, nil
	}
	return scanInvitationCurrent(rows)
}

// scanInvitationCurrent 扫描当前已定位的邀请行（列表循环使用，不推进 rows）。
func scanInvitationCurrent(rows *sql.Rows) (onboarding.Invitation, bool, error) {
	var invitation onboarding.Invitation
	var targetEmail, targetUserID, appID, cancelledAt, cancelReason, notifyError, notifiedAt sql.NullString
	var cancelledAtMS, notifiedAtMS sql.NullInt64
	var expiresAt, createdAt, updatedAt int64
	if err := rows.Scan(&invitation.ID, &invitation.InviterUserID, &invitation.TargetKind,
		&targetEmail, &targetUserID, &appID, &invitation.Status, &invitation.MaxUses,
		&invitation.UsedCount, &expiresAt, &createdAt, &updatedAt, &cancelledAtMS,
		&cancelReason, &invitation.NotifyState, &notifyError, &notifiedAtMS); err != nil {
		return onboarding.Invitation{}, false, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	_ = cancelledAt
	invitation.TargetEmail = targetEmail.String
	invitation.TargetUserID = targetUserID.String
	invitation.AppID = appID.String
	invitation.CancelReason = cancelReason.String
	if notifyError.Valid {
		invitation.NotifyError = notifyError.String
	}
	if !invitation.Status.Valid() || !invitation.NotifyState.Valid() {
		return onboarding.Invitation{}, false, fmt.Errorf("%w: 邀请状态非法", onboarding.ErrStoreUnavailable)
	}
	_ = notifiedAt
	invitation.ExpiresAt = time.UnixMilli(expiresAt).UTC()
	invitation.CreatedAt = time.UnixMilli(createdAt).UTC()
	invitation.UpdatedAt = time.UnixMilli(updatedAt).UTC()
	if cancelledAtMS.Valid {
		invitation.CancelledAt = time.UnixMilli(cancelledAtMS.Int64).UTC()
	}
	if notifiedAtMS.Valid {
		invitation.NotifiedAt = time.UnixMilli(notifiedAtMS.Int64).UTC()
	}
	return invitation, true, nil
}

// ListInvitations 分页列出邀请。
func (s *Store) ListInvitations(ctx context.Context, inviterUserID string, request onboarding.ListRequest) (onboarding.ListResult, error) {
	query := `SELECT ` + selectInvitationColumns + ` FROM invitations WHERE 1=1`
	args := []any{}
	if inviterUserID != "" {
		query += ` AND inviter_user_id=?`
		args = append(args, inviterUserID)
	}
	if request.Status != "" {
		query += ` AND status=?`
		args = append(args, string(request.Status))
	}
	query += ` ORDER BY created_at_ms DESC,id LIMIT ? OFFSET ?`
	args = append(args, request.Limit+1, request.Offset)
	rows, err := s.store.QueryContext(ctx, query, args...)
	if err != nil {
		return onboarding.ListResult{}, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	var result onboarding.ListResult
	for rows.Next() {
		invitation, found, err := scanInvitationCurrent(rows)
		if err != nil {
			return onboarding.ListResult{}, err
		}
		if !found {
			break
		}
		if len(result.Invitations) == request.Limit {
			result.HasMore = true
			break
		}
		result.Invitations = append(result.Invitations, invitation)
	}
	_ = rows.Close()
	// 角色按邀请逐条读取（页大小受限，避免一次大 JOIN）。
	for index := range result.Invitations {
		invitation, _, err := s.loadInvitationRoles(ctx, result.Invitations[index])
		if err != nil {
			return onboarding.ListResult{}, err
		}
		result.Invitations[index] = invitation
	}
	return result, nil
}

// loadInvitationRoles 为列表项补角色。
func (s *Store) loadInvitationRoles(ctx context.Context, invitation onboarding.Invitation) (onboarding.Invitation, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectRolesSQL, invitation.ID)
	if err != nil {
		return onboarding.Invitation{}, false, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	invitation.Roles = nil
	for rows.Next() {
		var role onboarding.Role
		if err := rows.Scan(&role.RoleID, &role.ScopeID); err != nil {
			return onboarding.Invitation{}, false, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
		}
		invitation.Roles = append(invitation.Roles, role)
	}
	return invitation, true, nil
}

// CancelInvitation 条件取消 pending 邀请。
func (s *Store) CancelInvitation(ctx context.Context, tx audit.Tx, params onboarding.CancelParams) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", onboarding.ErrOptionsInvalid)
	}
	now := params.Now.UTC().UnixMilli()
	result, err := tx.ExecContext(ctx, cancelInvitationSQL, now, nullableString(params.Reason), now, params.InvitationID)
	if err != nil {
		return false, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	return affected == 1, nil
}

// UserStateTx 在审计事务内读取账户状态。
func (s *Store) UserStateTx(ctx context.Context, tx audit.Tx, userID string) (onboarding.UserState, bool, error) {
	if tx == nil {
		return onboarding.UserState{}, false, fmt.Errorf("%w: 审计事务为空", onboarding.ErrOptionsInvalid)
	}
	return s.queryUserState(ctx, tx, userID)
}

// UserState 读取账户状态。
func (s *Store) UserState(ctx context.Context, userID string) (onboarding.UserState, bool, error) {
	return s.queryUserState(ctx, nil, userID)
}

func (s *Store) queryUserState(ctx context.Context, tx audit.Tx, userID string) (onboarding.UserState, bool, error) {
	var rows *sql.Rows
	var err error
	if tx != nil {
		rows, err = tx.QueryContext(ctx, `SELECT id,status,is_root FROM users WHERE id=?`, userID)
	} else {
		rows, err = s.store.QueryContext(ctx, `SELECT id,status,is_root FROM users WHERE id=?`, userID)
	}
	if err != nil {
		return onboarding.UserState{}, false, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return onboarding.UserState{}, false, nil
	}
	var state onboarding.UserState
	var status string
	var isRoot int
	if err := rows.Scan(&state.UserID, &status, &isRoot); err != nil {
		return onboarding.UserState{}, false, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	state.Status = account.Status(status)
	if !state.Status.Valid() {
		return onboarding.UserState{}, false, fmt.Errorf("%w: 账户状态非法", onboarding.ErrStoreUnavailable)
	}
	state.IsRoot = isRoot == 1
	return state, true, nil
}

// NotificationEmail 返回账户通知邮箱，只接受已验证邮箱（未验证地址不能作为通知
// 目标，避免向无法证明控制权的地址发送审核/邀请信息）。
func (s *Store) NotificationEmail(ctx context.Context, userID string) (string, bool, error) {
	rows, err := s.store.QueryContext(ctx, `SELECT email FROM user_emails
WHERE user_id=? AND verified_at_ms IS NOT NULL ORDER BY created_at_ms DESC LIMIT 1`, userID)
	if err != nil {
		return "", false, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return "", false, nil
	}
	var email string
	if err := rows.Scan(&email); err != nil {
		return "", false, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	return email, true, nil
}

// VerifiedEmailTx 报告账户是否拥有该规范化已验证邮箱。
func (s *Store) VerifiedEmailTx(ctx context.Context, tx audit.Tx, userID, normalizedEmail string) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", onboarding.ErrOptionsInvalid)
	}
	rows, err := tx.QueryContext(ctx, `SELECT 1 FROM user_emails
WHERE user_id=? AND email_normalized=? AND verified_at_ms IS NOT NULL`, userID, normalizedEmail)
	if err != nil {
		return false, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	found := rows.Next()
	_ = rows.Close()
	return found, nil
}

// AppStatusTx 在审计事务内读取应用状态。
func (s *Store) AppStatusTx(ctx context.Context, tx audit.Tx, appID string) (string, bool, error) {
	if appID == "" {
		return "active", true, nil
	}
	if tx == nil {
		return "", false, fmt.Errorf("%w: 审计事务为空", onboarding.ErrOptionsInvalid)
	}
	rows, err := tx.QueryContext(ctx, `SELECT status FROM applications WHERE id=?`, appID)
	if err != nil {
		return "", false, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return "", false, nil
	}
	var status string
	if err := rows.Scan(&status); err != nil {
		return "", false, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	return status, true, nil
}

// RolePermissionsTx 读取角色当前启用的权限引用，用于委派复核。
func (s *Store) RolePermissionsTx(ctx context.Context, tx audit.Tx, roles []onboarding.Role) (map[string][]delegation.PermissionRef, error) {
	if tx == nil {
		return nil, fmt.Errorf("%w: 审计事务为空", onboarding.ErrOptionsInvalid)
	}
	result := make(map[string][]delegation.PermissionRef, len(roles))
	for _, role := range roles {
		rows, err := tx.QueryContext(ctx, `SELECT p.id FROM role_permissions rp
JOIN permissions p ON p.id=rp.permission_id AND p.scope_id=rp.scope_id
WHERE rp.role_id=? AND rp.scope_id=? AND p.enabled=1 ORDER BY p.id`, role.RoleID, role.ScopeID)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
		}
		seen := make(map[string]struct{})
		for rows.Next() {
			var permissionID string
			if err := rows.Scan(&permissionID); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
			}
			if _, exists := seen[permissionID]; exists {
				continue
			}
			seen[permissionID] = struct{}{}
			result[role.RoleID] = append(result[role.RoleID],
				delegation.PermissionRef{PermissionID: permissionID, DataScopeJSON: "{}"})
		}
		_ = rows.Close()
	}
	return result, nil
}

// AcceptInvitationTx 原子扣减次数并完成接受（可选创建账户/成员/角色）。
func (s *Store) AcceptInvitationTx(ctx context.Context, tx audit.Tx, params onboarding.AcceptParams) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", onboarding.ErrOptionsInvalid)
	}
	now := params.Now.UTC().UnixMilli()
	result, err := tx.ExecContext(ctx, incrementInvitationSQL, now, params.InvitationID, now)
	if err != nil {
		return fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	if affected != 1 {
		return onboarding.ErrInvitationConflict
	}
	// 读取邀请角色（事务内，确保与扣减同一快照）。
	roleRows, err := tx.QueryContext(ctx, selectRolesSQL, params.InvitationID)
	if err != nil {
		return fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	var roles []onboarding.Role
	for roleRows.Next() {
		var role onboarding.Role
		if err := roleRows.Scan(&role.RoleID, &role.ScopeID); err != nil {
			_ = roleRows.Close()
			return fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
		}
		roles = append(roles, role)
	}
	_ = roleRows.Close()
	var appID sql.NullString
	row := tx.QueryContext
	appRows, err := row(ctx, `SELECT app_id FROM invitations WHERE id=?`, params.InvitationID)
	if err != nil {
		return fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	if appRows.Next() {
		if err := appRows.Scan(&appID); err != nil {
			_ = appRows.Close()
			return fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
		}
	}
	_ = appRows.Close()
	if params.NewUser != nil {
		user := params.NewUser
		if _, err := tx.ExecContext(ctx, insertInvitedUserSQL,
			user.UserID, user.Username, user.UsernameNormalized, user.Nickname,
			user.Language, user.Timezone, now, now); err != nil {
			return fmt.Errorf("%w: %w", onboarding.ErrInvitationConflict, err)
		}
		if _, err := tx.ExecContext(ctx, insertInvitedPasswordSQL, user.UserID,
			user.PasswordHash, now, now, now); err != nil {
			return fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
		}
		verified := user.VerifiedAt
		if verified.IsZero() {
			verified = params.Now
		}
		if _, err := tx.ExecContext(ctx, insertInvitedEmailSQL, user.EmailNormalized,
			user.UserID, user.Email, verified.UTC().UnixMilli(), now, now); err != nil {
			return fmt.Errorf("%w: %w", onboarding.ErrInvitationConflict, err)
		}
	}
	if _, err := tx.ExecContext(ctx, insertAcceptanceSQL,
		params.InvitationID, params.UserID, now, nullableString(params.RequestID)); err != nil {
		return fmt.Errorf("%w: %w", onboarding.ErrInvitationConflict, err)
	}
	if appID.Valid && appID.String != "" {
		if _, err := tx.ExecContext(ctx, upsertMembershipSQL, appID.String, params.UserID, now, now); err != nil {
			return fmt.Errorf("%w: %w", onboarding.ErrInvitationNotAcceptable, err)
		}
	}
	assignedBy := "invitation:" + params.InvitationID
	for _, role := range roles {
		// 角色存在/启用/作用域已在服务层事务内校验；已持有同一角色时 INSERT OR IGNORE
		// 影响 0 行属于幂等成功（已有用户受邀不能因为已持有角色而失败）。
		if _, err := tx.ExecContext(ctx, insertUserRoleSQL,
			params.UserID, role.RoleID, role.ScopeID, assignedBy, now, role.RoleID, role.ScopeID); err != nil {
			return fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
		}
	}
	return nil
}

// MarkInvitationNotify 记录通知结果。
func (s *Store) MarkInvitationNotify(ctx context.Context, id string, state onboarding.NotifyState, errorCode string, now time.Time) error {
	result, err := s.store.ExecContext(ctx, markInvitationNotifySQL,
		string(state), nullableString(errorCode), now.UTC().UnixMilli(), id)
	if err != nil {
		return fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	if affected != 1 {
		return onboarding.ErrInvitationNotFound
	}
	return nil
}

// ListPendingReviews 分页列出待审核账户。
func (s *Store) ListPendingReviews(ctx context.Context, query onboarding.ReviewQuery) (onboarding.ReviewQueryResult, error) {
	rows, err := s.store.QueryContext(ctx, listPendingReviewsSQL, query.Limit+1, query.Offset)
	if err != nil {
		return onboarding.ReviewQueryResult{}, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	var result onboarding.ReviewQueryResult
	for rows.Next() {
		review, err := scanReview(rows)
		if err != nil {
			_ = rows.Close()
			return onboarding.ReviewQueryResult{}, err
		}
		if len(result.Users) == query.Limit {
			result.HasMore = true
			break
		}
		result.Users = append(result.Users, review)
	}
	_ = rows.Close()
	return result, nil
}

// GetReviewUser 读取单个账户审核状态。
func (s *Store) GetReviewUser(ctx context.Context, userID string) (onboarding.ReviewUser, bool, error) {
	return s.queryReviewUser(ctx, nil, userID)
}

// LoadReviewUserTx 在审计事务内读取账户审核状态。
func (s *Store) LoadReviewUserTx(ctx context.Context, tx audit.Tx, userID string) (onboarding.ReviewUser, bool, error) {
	if tx == nil {
		return onboarding.ReviewUser{}, false, fmt.Errorf("%w: 审计事务为空", onboarding.ErrOptionsInvalid)
	}
	return s.queryReviewUser(ctx, tx, userID)
}

func (s *Store) queryReviewUser(ctx context.Context, tx audit.Tx, userID string) (onboarding.ReviewUser, bool, error) {
	var rows *sql.Rows
	var err error
	if tx != nil {
		rows, err = tx.QueryContext(ctx, selectReviewByIDSQL, userID)
	} else {
		rows, err = s.store.QueryContext(ctx, selectReviewByIDSQL, userID)
	}
	if err != nil {
		return onboarding.ReviewUser{}, false, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return onboarding.ReviewUser{}, false, nil
	}
	review, err := scanReview(rows)
	if err != nil {
		return onboarding.ReviewUser{}, false, err
	}
	return review, true, nil
}

func scanReview(rows *sql.Rows) (onboarding.ReviewUser, error) {
	var review onboarding.ReviewUser
	var status, reviewStatus, decidedByType string
	var reason, decidedByID, notifyError string
	var decidedAt, notifiedAt sql.NullInt64
	var createdAt int64
	if err := rows.Scan(&review.UserID, &review.Username, &status, &reviewStatus, &reason,
		&decidedByType, &decidedByID, &decidedAt, &createdAt, &review.NotifyState,
		&notifyError, &notifiedAt); err != nil {
		return onboarding.ReviewUser{}, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	review.Status = account.Status(status)
	if !review.Status.Valid() {
		return onboarding.ReviewUser{}, fmt.Errorf("%w: 账户状态非法", onboarding.ErrStoreUnavailable)
	}
	review.ReviewStatus = onboarding.ReviewStatus(reviewStatus)
	review.Reason = reason
	review.DecidedByType = audit.ActorKind(decidedByType)
	review.DecidedByID = decidedByID
	review.NotifyError = notifyError
	review.CreatedAt = time.UnixMilli(createdAt).UTC()
	if decidedAt.Valid {
		review.DecidedAt = time.UnixMilli(decidedAt.Int64).UTC()
	}
	if notifiedAt.Valid {
		review.NotifiedAt = time.UnixMilli(notifiedAt.Int64).UTC()
	}
	if !review.NotifyState.Valid() {
		return onboarding.ReviewUser{}, fmt.Errorf("%w: 通知状态非法", onboarding.ErrStoreUnavailable)
	}
	return review, nil
}

// DecideReviewTx 条件更新账户状态并写审核决定与可选成员/角色。
func (s *Store) DecideReviewTx(ctx context.Context, tx audit.Tx, decision onboarding.ReviewDecision) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", onboarding.ErrOptionsInvalid)
	}
	now := decision.Now.UTC().UnixMilli()
	rows, err := tx.QueryContext(ctx, `SELECT status,is_root FROM users WHERE id=?`, decision.UserID)
	if err != nil {
		return false, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	found := false
	var status string
	var isRoot int
	if rows.Next() {
		found = true
		if err := rows.Scan(&status, &isRoot); err != nil {
			_ = rows.Close()
			return false, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
		}
	}
	_ = rows.Close()
	if !found {
		return false, onboarding.ErrReviewNotFound
	}
	if status != string(account.StatusPending) {
		return false, nil
	}
	if isRoot == 1 {
		return false, onboarding.ErrAccessDenied
	}
	var update string
	if decision.Approve {
		update = `UPDATE users SET status='active',row_version=row_version+1,updated_at_ms=?
WHERE id=? AND status='pending' AND is_root=0`
	} else {
		update = `UPDATE users SET status='disabled',security_version=security_version+1,
row_version=row_version+1,updated_at_ms=? WHERE id=? AND status='pending' AND is_root=0`
	}
	result, err := tx.ExecContext(ctx, update, now, decision.UserID)
	if err != nil {
		return false, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	if affected != 1 {
		return false, nil
	}
	if decision.Approve && decision.AppID != "" {
		if _, err := tx.ExecContext(ctx, upsertMembershipSQL, decision.AppID, decision.UserID, now, now); err != nil {
			return false, fmt.Errorf("%w: %w", onboarding.ErrInvitationNotAcceptable, err)
		}
	}
	statusText := "approved"
	if !decision.Approve {
		statusText = "rejected"
	}
	if _, err := tx.ExecContext(ctx, upsertReviewSQL,
		decision.UserID, statusText, nullableString(decision.Reason),
		string(decision.Actor.Type), decision.Actor.ID, now, now, now,
		nullableString(decision.RequestID)); err != nil {
		return false, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	if decision.Approve {
		assignedBy := strings.TrimSpace(string(decision.Actor.Type) + ":" + decision.Actor.ID)
		for _, role := range decision.Roles {
			// 角色可分配性由服务层在事务内用 RoleAssignableTx 校验；已持有同一角色
			// 时影响 0 行是幂等成功。
			if _, err := tx.ExecContext(ctx, insertUserRoleSQL,
				decision.UserID, role.RoleID, role.ScopeID, assignedBy, now, role.RoleID, role.ScopeID); err != nil {
				return false, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
			}
		}
	}
	return true, nil
}

// MarkReviewNotify 记录审核通知结果。
func (s *Store) MarkReviewNotify(ctx context.Context, userID string, state onboarding.NotifyState, errorCode string, now time.Time) error {
	result, err := s.store.ExecContext(ctx, markReviewNotifySQL,
		string(state), nullableString(errorCode), now.UTC().UnixMilli(), userID)
	if err != nil {
		return fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	if affected != 1 {
		return onboarding.ErrReviewNotFound
	}
	return nil
}

// nullableString 把空字符串转成 NULL，便于可空列查询。
func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// 编译期确认 account.Status 已在本包使用（避免误删导入）。
var _ = account.StatusActive

// VerifiedEmail 报告账户是否拥有该规范化已验证邮箱（接受前身份预检）。
func (s *Store) VerifiedEmail(ctx context.Context, userID, normalizedEmail string) (bool, error) {
	rows, err := s.store.QueryContext(ctx, `SELECT 1 FROM user_emails
WHERE user_id=? AND email_normalized=? AND verified_at_ms IS NOT NULL`, userID, normalizedEmail)
	if err != nil {
		return false, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	return rows.Next(), nil
}

// RoleAssignableTx 校验角色存在、启用且作用域匹配。
func (s *Store) RoleAssignableTx(ctx context.Context, tx audit.Tx, roles []onboarding.Role) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", onboarding.ErrOptionsInvalid)
	}
	for _, role := range roles {
		rows, err := tx.QueryContext(ctx,
			`SELECT 1 FROM roles WHERE id=? AND scope_id=? AND enabled=1`, role.RoleID, role.ScopeID)
		if err != nil {
			return fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
		}
		found := rows.Next()
		_ = rows.Close()
		if !found {
			return fmt.Errorf("%w: 角色不存在、已停用或作用域不匹配", onboarding.ErrInvalidRequest)
		}
	}
	return nil
}

// MemberEffectivePermissionRefsTx 返回目标用户在该范围当前有效权限引用；查询口径与
// internal/app 成员加入/重新启用的可转授检查一致。
func (s *Store) MemberEffectivePermissionRefsTx(ctx context.Context, tx audit.Tx, scopeID, userID string) ([]delegation.PermissionRef, error) {
	if tx == nil {
		return nil, fmt.Errorf("%w: 审计事务为空", onboarding.ErrOptionsInvalid)
	}
	resolved := scopeID
	if resolved == "" {
		resolved = "system"
	}
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT p.id FROM (
  SELECT ur.role_id,ur.scope_id FROM user_roles ur WHERE ur.user_id=? AND ur.scope_id=?
  UNION ALL
  SELECT gr.role_id,gr.scope_id FROM group_members gm
  JOIN group_roles gr ON gr.group_id=gm.group_id WHERE gm.user_id=? AND gr.scope_id=?
) chosen
JOIN roles r ON r.id=chosen.role_id AND r.scope_id=chosen.scope_id
JOIN role_permissions rp ON rp.role_id=r.id
JOIN permissions p ON p.id=rp.permission_id AND p.scope_id=chosen.scope_id
WHERE r.enabled=1 AND p.enabled=1 AND p.root_only=0 ORDER BY p.id`,
		userID, resolved, userID, resolved)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	var refs []delegation.PermissionRef
	for rows.Next() {
		var permissionID string
		if err := rows.Scan(&permissionID); err != nil {
			return nil, fmt.Errorf("%w: %w", onboarding.ErrStoreUnavailable, err)
		}
		refs = append(refs, delegation.PermissionRef{PermissionID: permissionID, DataScopeJSON: "{}"})
	}
	return refs, nil
}
