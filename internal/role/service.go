package role

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// ScopeInfo 是角色作用范围数据库快照。
type ScopeInfo struct {
	ScopeID           string
	Kind              ScopeKind
	ApplicationID     string
	ApplicationActive bool
}

// ListQuery 是已校验的角色列表查询。
type ListQuery struct {
	Limit       int
	Offset      int
	AllScopes   bool
	ScopeIDs    []string
	ScopeFilter string
	Enabled     *bool
	Builtin     *bool
}

// PermissionRecord 是组合角色前读取的权限状态；只接受同范围、启用、非 root_only。
type PermissionRecord struct {
	PermissionID string
	ScopeID      string
	Key          string
	Name         string
	Enabled      bool
	RootOnly     bool
}

// UserRecord 是角色分配目标账户的资格快照。
type UserRecord struct {
	UserID string
	Status account.Status
	IsRoot bool
}

// GroupRecord 是角色分配目标用户组的范围快照。
type GroupRecord struct {
	GroupID       string
	ScopeID       string
	Kind          ScopeKind
	ApplicationID string
}

// ReferenceCounts 是角色被引用/分配的计数，用于删除前预检与审计。
type ReferenceCounts struct {
	Permissions int
	Users       int
	Groups      int
}

// Total 返回所有引用总数。
func (c ReferenceCounts) Total() int {
	return c.Permissions + c.Users + c.Groups
}

// Store 是角色持久化契约，由 internal/role/sqlite 提供生产实现。
//
// 关联写入必须是条件/唯一约束语义：重复组合与重复分配不产生第二行；分配/撤回
// 不允许跨作用范围；删除角色前由服务预检引用并在同一事务条件删除。
type Store interface {
	GetScope(ctx context.Context, scopeID string) (ScopeInfo, error)
	CreateRole(ctx context.Context, tx audit.Tx, record Role) error
	GetRole(ctx context.Context, id string) (Role, error)
	// GetRoleScope 只读取角色 scope，供先鉴权后读取完整记录使用。
	GetRoleScope(ctx context.Context, id string) (string, error)
	ListRoles(ctx context.Context, query ListQuery) ([]Role, bool, error)
	UpdateRole(ctx context.Context, tx audit.Tx, id, name, description, limits string, now time.Time) error
	SetRoleEnabled(ctx context.Context, tx audit.Tx, id string, expectedEnabled, enabled bool, now time.Time) error
	CountDeleteReferences(ctx context.Context, id string) (ReferenceCounts, error)
	DeleteRole(ctx context.Context, tx audit.Tx, id string) error

	// 角色权限组合。
	GetPermissionForRole(ctx context.Context, permissionID string) (PermissionRecord, error)
	AddRolePermission(ctx context.Context, tx audit.Tx, roleID, permissionID, scopeID string) (bool, error)
	RemoveRolePermission(ctx context.Context, tx audit.Tx, roleID, permissionID string) (bool, error)
	ListRolePermissions(ctx context.Context, roleID string) ([]PermissionSummary, error)

	// 角色分配目标资格与关联。
	GetUserForRole(ctx context.Context, userID string) (UserRecord, error)
	GetApplicationMembership(ctx context.Context, applicationID, userID string) (app.MembershipStatus, bool, error)
	GetGroupForRole(ctx context.Context, groupID string) (GroupRecord, error)
	// GroupHasRootMember 报告用户组是否包含 root 账户；向含 root 的组分配角色
	// 等同于给 root 间接分配普通角色，必须拒绝。
	GroupHasRootMember(ctx context.Context, groupID string) (bool, error)
	AddUserRole(ctx context.Context, tx audit.Tx, assignment UserRoleAssignment) (bool, error)
	RemoveUserRole(ctx context.Context, tx audit.Tx, roleID, userID string) (bool, error)
	AddGroupRole(ctx context.Context, tx audit.Tx, assignment GroupRoleAssignment) (bool, error)
	RemoveGroupRole(ctx context.Context, tx audit.Tx, roleID, groupID string) (bool, error)
	ListRoleAssignments(ctx context.Context, roleID string) (Assignments, error)
}

// AuditRecorder 是角色服务依赖的审计契约。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// Options 是角色服务依赖。Authorizer 必填：缺少可信策略时服务不可构造，不放行。
type Options struct {
	Store      Store
	Audit      AuditRecorder
	Authorizer Authorizer
	Now        func() time.Time
	Random     io.Reader
	Logger     *slog.Logger
}

// Service 是角色领域服务；构造后不可变，可并发使用。
type Service struct {
	store      Store
	audit      AuditRecorder
	authorizer Authorizer
	now        func() time.Time
	random     io.Reader
	logger     *slog.Logger
}

// New 校验依赖并构造角色服务；任意必填依赖为空返回 ErrOptionsInvalid。
func New(options Options) (*Service, error) {
	if isNil(options.Store) {
		return nil, fmt.Errorf("%w: 角色存储为空", ErrOptionsInvalid)
	}
	if isNil(options.Audit) {
		return nil, fmt.Errorf("%w: 审计写入器为空", ErrOptionsInvalid)
	}
	if isNil(options.Authorizer) {
		return nil, fmt.Errorf("%w: 授权器为空", ErrOptionsInvalid)
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	random := options.Random
	if random == nil {
		random = rand.Reader
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	return &Service{store: options.Store, audit: options.Audit, authorizer: options.Authorizer,
		now: now, random: random, logger: logger}, nil
}

// CreateRole 在指定范围登记角色。系统范围可以创建系统自定义/内置角色（内置只能由
// 受限本地或系统操作者创建）；应用范围只允许该应用管理员或本地/系统操作者，不能
// 创建 builtin 角色。角色机器标识不能使用 root 语义，创建不授予任何权限。
func (s *Service) CreateRole(ctx context.Context, caller Caller, request CreateRequest) (Role, error) {
	// 先做 scope 文本形状校验（不访问数据库），再按作用范围授权；格式非法返回
	// REQ_INVALID，有效但无权返回 ACCESS_DENIED，不扩大存在性信息。
	kind, applicationID, err := ParseScope(request.ScopeID)
	if err != nil {
		return Role{}, err
	}
	if err := s.authorize(ctx, caller, ActionCreateRole, request.ScopeID); err != nil {
		return Role{}, err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return Role{}, err
	}
	scope, err := s.store.GetScope(ctx, strings.TrimSpace(request.ScopeID))
	if err != nil {
		return Role{}, err
	}
	if kind != scope.Kind || applicationID != scope.ApplicationID {
		return Role{}, ErrScopeInvalid
	}
	if kind == ScopeKindApplication {
		if request.IsBuiltin {
			return Role{}, fmt.Errorf("%w: 应用不能创建内置角色", ErrAccessDenied)
		}
		if !scope.ApplicationActive {
			return Role{}, fmt.Errorf("%w: 应用当前不可登记角色", ErrApplicationInactive)
		}
	}
	key, err := ValidateKey(request.Key)
	if err != nil {
		return Role{}, err
	}
	name, err := ValidateName(request.Name)
	if err != nil {
		return Role{}, err
	}
	description, err := ValidateDescription(request.Description)
	if err != nil {
		return Role{}, err
	}
	limits, err := ValidateLimits(request.Limits)
	if err != nil {
		return Role{}, err
	}
	id, err := NewRoleID(s.random)
	if err != nil {
		return Role{}, fmt.Errorf("%w: %v", ErrStoreUnavailable, err)
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	record := Role{
		ID: id, ScopeID: scope.ScopeID, ScopeKind: kind, ApplicationID: applicationID,
		Key: key, Name: name, Description: description, Limits: limits,
		IsBuiltin: request.IsBuiltin, Enabled: true, CreatedAt: now, UpdatedAt: now,
	}
	event := audit.Event{
		Actor:     caller.actor,
		AppID:     applicationID,
		Action:    string(ActionCreateRole),
		Target:    audit.Target{Type: "role", ID: id},
		RequestID: caller.requestID,
		Changes: []audit.FieldChange{
			{Field: "scope_id", After: scope.ScopeID},
			{Field: "role_key", After: key},
			{Field: "name", After: name},
			{Field: "builtin", After: formatBool(request.IsBuiltin)},
			{Field: "enabled", After: "true"},
		},
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "role.create_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.store.CreateRole(txCtx, tx, record)
	})
	if err != nil {
		return Role{}, mapCriticalError(err)
	}
	s.logger.Info("角色已创建", "role_id", id, "scope_id", scope.ScopeID, "builtin", request.IsBuiltin)
	return record, nil
}

// GetRole 按稳定 ID 读取角色并写审计读取事件。
func (s *Service) GetRole(ctx context.Context, caller Caller, id string) (Role, error) {
	record, err := s.getAuthorizedRole(ctx, caller, ActionGetRole, id)
	if err != nil {
		return Role{}, err
	}
	if err := s.recordRead(ctx, caller, ActionGetRole, record); err != nil {
		return Role{}, err
	}
	return record, nil
}

// ListRoles 在可管理范围内分页查询角色。空 ScopeID 是合法默认用法；应用管理员
// 只看到分配应用的角色，不会返回系统角色或其他应用角色。
func (s *Service) ListRoles(ctx context.Context, caller Caller, request ListRequest) (ListResult, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return ListResult{}, err
	}
	if err := caller.actor.Validate(); err != nil {
		return ListResult{}, ErrAccessDenied
	}
	all, scopes, err := s.authorizer.ManageableScopes(ctx, caller)
	if err != nil {
		return ListResult{}, ErrAccessDenied
	}
	limit := request.Limit
	if limit == 0 {
		limit = DefaultListLimit
	}
	if limit < 0 || limit > MaxListLimit {
		return ListResult{}, fmt.Errorf("%w: 每页数量必须在 1～%d 之间", ErrInvalidRequest, MaxListLimit)
	}
	if request.Offset < 0 || request.Offset > MaxListOffset {
		return ListResult{}, fmt.Errorf("%w: 分页偏移无效", ErrInvalidRequest)
	}
	query := ListQuery{Limit: limit, Offset: request.Offset, AllScopes: all,
		Enabled: request.Enabled, Builtin: request.Builtin}
	filter := strings.TrimSpace(request.ScopeID)
	if filter != "" {
		if _, _, err := ParseScope(filter); err != nil {
			return ListResult{}, err
		}
		if !all {
			allowed := false
			for _, scopeID := range scopes {
				if scopeID == filter {
					allowed = true
					break
				}
			}
			if !allowed {
				return ListResult{}, ErrAccessDenied
			}
		}
		query.ScopeFilter = filter
	}
	if !all {
		if len(scopes) == 0 {
			if err := s.recordListRead(ctx, caller, ""); err != nil {
				return ListResult{}, err
			}
			return ListResult{Roles: []Role{}}, nil
		}
		query.ScopeIDs = scopes
	}
	roles, hasMore, err := s.store.ListRoles(ctx, query)
	if err != nil {
		return ListResult{}, err
	}
	if err := s.recordListRead(ctx, caller, ""); err != nil {
		return ListResult{}, err
	}
	return ListResult{Roles: roles, HasMore: hasMore}, nil
}

// UpdateRole 修改角色直白名称、说明与明确限制。内置角色语义不可修改；机器标识、
// scope 与 builtin 不在更新请求中，因此不可变。
func (s *Service) UpdateRole(ctx context.Context, caller Caller, id string, request UpdateRequest) (Role, error) {
	current, err := s.getAuthorizedRole(ctx, caller, ActionUpdateRole, id)
	if err != nil {
		return Role{}, err
	}
	if current.IsBuiltin {
		return Role{}, ErrBuiltinProtected
	}
	name, err := ValidateName(request.Name)
	if err != nil {
		return Role{}, err
	}
	description, err := ValidateDescription(request.Description)
	if err != nil {
		return Role{}, err
	}
	limits, err := ValidateLimits(request.Limits)
	if err != nil {
		return Role{}, err
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	updated := current
	updated.Name = name
	updated.Description = description
	updated.Limits = limits
	updated.UpdatedAt = now
	changes := make([]audit.FieldChange, 0, 3)
	if current.Name != name {
		changes = append(changes, audit.FieldChange{Field: "name", Before: current.Name, After: name})
	}
	if current.Description != description {
		changes = append(changes, audit.FieldChange{Field: "description", Before: current.Description, After: description})
	}
	if current.Limits != limits {
		changes = append(changes, audit.FieldChange{Field: "limits", Before: current.Limits, After: limits})
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     caller.actor,
			AppID:     current.ApplicationID,
			Action:    string(ActionUpdateRole),
			Target:    audit.Target{Type: "role", ID: id},
			RequestID: caller.requestID,
			Changes:   changes,
		},
		FailureReasonCode: "role.update_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.store.UpdateRole(txCtx, tx, id, name, description, limits, now)
	})
	if err != nil {
		return Role{}, mapCriticalError(err)
	}
	return updated, nil
}

// EnableRole 启用角色。重复启用幂等成功；启用不代表角色分配立即获得权限，有效权限
// 计算仍必须读取当前角色/权限状态。
func (s *Service) EnableRole(ctx context.Context, caller Caller, id string) (Role, bool, error) {
	return s.setRoleEnabled(ctx, caller, id, true, ActionEnableRole)
}

// DisableRole 停用角色。停用是拒绝操作，不跳过检查；重复停用幂等成功。已分配的
// 用户/组关系保留，有效权限计算必须排除已停用角色。
func (s *Service) DisableRole(ctx context.Context, caller Caller, id string) (Role, bool, error) {
	return s.setRoleEnabled(ctx, caller, id, false, ActionDisableRole)
}

// setRoleEnabled 执行角色启停：先鉴权读取，幂等请求写成功审计，实际变更使用审计
// 事务；并发启停最终只有一个终态。
func (s *Service) setRoleEnabled(ctx context.Context, caller Caller, id string, target bool, action Action) (Role, bool, error) {
	current, err := s.getAuthorizedRole(ctx, caller, action, id)
	if err != nil {
		return Role{}, false, err
	}
	if current.Enabled == target {
		event := audit.Event{
			Actor:     caller.actor,
			AppID:     current.ApplicationID,
			Action:    string(action),
			Target:    audit.Target{Type: "role", ID: id},
			Outcome:   audit.OutcomeSuccess,
			RequestID: caller.requestID,
			Changes:   []audit.FieldChange{{Field: "result", After: "unchanged"}},
		}
		if err := s.audit.Record(ctx, event); err != nil {
			return Role{}, false, fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
		}
		return current, false, nil
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	updated := current
	updated.Enabled = target
	updated.UpdatedAt = now
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     caller.actor,
			AppID:     current.ApplicationID,
			Action:    string(action),
			Target:    audit.Target{Type: "role", ID: id},
			RequestID: caller.requestID,
			Changes: []audit.FieldChange{
				{Field: "enabled", Before: formatBool(current.Enabled), After: formatBool(target)},
			},
		},
		FailureReasonCode: "role.state_change_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.store.SetRoleEnabled(txCtx, tx, id, current.Enabled, target, now)
	})
	if err != nil {
		return Role{}, false, mapCriticalError(err)
	}
	s.logger.Info("角色状态已变更", "role_id", id, "enabled", target)
	return updated, true, nil
}

// DeleteRole 删除自定义角色。内置角色永远拒绝；仍被角色权限组合、用户分配或用户组
// 分配引用的角色拒绝删除（避免隐式级联破坏授权关系）；删除只移除角色记录，审计
// 历史保留。
func (s *Service) DeleteRole(ctx context.Context, caller Caller, id string) error {
	current, err := s.getAuthorizedRole(ctx, caller, ActionDeleteRole, id)
	if err != nil {
		return err
	}
	if current.IsBuiltin {
		return ErrBuiltinProtected
	}
	references, err := s.store.CountDeleteReferences(ctx, id)
	if err != nil {
		return err
	}
	if references.Total() > 0 {
		return fmt.Errorf("%w: 仍被 %d 个权限组合、%d 个用户和 %d 个用户组引用",
			ErrRoleInUse, references.Permissions, references.Users, references.Groups)
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     caller.actor,
			AppID:     current.ApplicationID,
			Action:    string(ActionDeleteRole),
			Target:    audit.Target{Type: "role", ID: id},
			RequestID: caller.requestID,
			Changes: []audit.FieldChange{
				{Field: "scope_id", Before: current.ScopeID},
				{Field: "role_key", Before: current.Key},
				{Field: "builtin", Before: formatBool(current.IsBuiltin)},
				{Field: "status", After: "deleted"},
			},
		},
		FailureReasonCode: "role.delete_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.store.DeleteRole(txCtx, tx, id)
	})
	if err != nil {
		return mapCriticalError(err)
	}
	s.logger.Info("角色已删除", "role_id", id)
	return nil
}

// AddRolePermission 把同一范围内、启用且非 root_only 的权限加入角色组合。不同
// 范围、已停用或不存在的权限拒绝；root_only 权限不能通过普通角色组合。
// 重复组合幂等成功（Changed=false），并发由唯一约束保证只有一行。
func (s *Service) AddRolePermission(ctx context.Context, caller Caller, roleID, permissionID string) (bool, error) {
	current, err := s.getAuthorizedRole(ctx, caller, ActionAddRolePermission, roleID)
	if err != nil {
		return false, err
	}
	permissionID = strings.TrimSpace(permissionID)
	if !validPermissionID(permissionID) {
		return false, fmt.Errorf("%w: 权限 ID 格式无效", ErrInvalidRequest)
	}
	permission, err := s.store.GetPermissionForRole(ctx, permissionID)
	if err != nil {
		return false, err
	}
	if permission.ScopeID != current.ScopeID {
		return false, fmt.Errorf("%w: 权限范围 %s 与角色范围 %s 不一致", ErrPermissionScope, permission.ScopeID, current.ScopeID)
	}
	if !permission.Enabled {
		return false, ErrPermissionInactive
	}
	if permission.RootOnly {
		return false, ErrRootOnlyPermission
	}
	changed := false
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     caller.actor,
			AppID:     current.ApplicationID,
			Action:    string(ActionAddRolePermission),
			Target:    audit.Target{Type: "role", ID: roleID},
			RequestID: caller.requestID,
			Changes: []audit.FieldChange{
				{Field: "permission_id", After: permission.PermissionID},
				{Field: "permission_key", After: permission.Key},
				{Field: "scope_id", After: current.ScopeID},
			},
		},
		FailureReasonCode: "role.permission_add_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		inserted, insertErr := s.store.AddRolePermission(txCtx, tx, roleID, permissionID, current.ScopeID)
		if insertErr != nil {
			return insertErr
		}
		changed = inserted
		return nil
	})
	if err != nil {
		return false, mapCriticalError(err)
	}
	if !changed {
		s.logger.Info("权限已在角色中，组合未变化", "role_id", roleID, "permission_id", permissionID)
	} else {
		s.logger.Info("权限已加入角色", "role_id", roleID, "permission_id", permissionID)
	}
	return changed, nil
}

// RemoveRolePermission 从角色组合移除权限。不存在的关系幂等成功（Changed=false）；
// 移除只改组合关系，不删除权限目录，也不改变任何主体已获得的权限缓存（未来模块
// 必须读取当前组合）。
func (s *Service) RemoveRolePermission(ctx context.Context, caller Caller, roleID, permissionID string) (bool, error) {
	current, err := s.getAuthorizedRole(ctx, caller, ActionRemoveRolePermission, roleID)
	if err != nil {
		return false, err
	}
	permissionID = strings.TrimSpace(permissionID)
	if !validPermissionID(permissionID) {
		return false, fmt.Errorf("%w: 权限 ID 格式无效", ErrInvalidRequest)
	}
	changed := false
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     caller.actor,
			AppID:     current.ApplicationID,
			Action:    string(ActionRemoveRolePermission),
			Target:    audit.Target{Type: "role", ID: roleID},
			RequestID: caller.requestID,
			Changes: []audit.FieldChange{
				{Field: "permission_id", Before: permissionID},
				{Field: "scope_id", Before: current.ScopeID},
			},
		},
		FailureReasonCode: "role.permission_remove_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		removed, removeErr := s.store.RemoveRolePermission(txCtx, tx, roleID, permissionID)
		if removeErr != nil {
			return removeErr
		}
		changed = removed
		return nil
	})
	if err != nil {
		return false, mapCriticalError(err)
	}
	return changed, nil
}

// ListRolePermissions 列出角色组合中的权限摘要，写审计读取事件；失败拒绝返回。
func (s *Service) ListRolePermissions(ctx context.Context, caller Caller, roleID string) ([]PermissionSummary, error) {
	current, err := s.getAuthorizedRole(ctx, caller, ActionListRolePermissions, roleID)
	if err != nil {
		return nil, err
	}
	permissions, err := s.store.ListRolePermissions(ctx, roleID)
	if err != nil {
		return nil, err
	}
	if err := s.recordRead(ctx, caller, ActionListRolePermissions, current); err != nil {
		return nil, err
	}
	return permissions, nil
}

// AssignUserRole 把角色分配给用户。角色必须启用；系统角色只能分配给 active 且
// 非 root 的账户；应用角色只能分配给该应用 active 成员（应用需启用、成员关系需
// active），因此应用角色不能授予其他应用的用户。重复分配幂等成功。
func (s *Service) AssignUserRole(ctx context.Context, caller Caller, roleID, userID string) (bool, error) {
	current, err := s.getAuthorizedRole(ctx, caller, ActionAssignUserRole, roleID)
	if err != nil {
		return false, err
	}
	if !current.Enabled {
		return false, ErrRoleDisabled
	}
	userID = strings.TrimSpace(userID)
	if !account.ValidUserID(userID) {
		return false, fmt.Errorf("%w: 用户 ID 格式无效", ErrInvalidRequest)
	}
	user, err := s.store.GetUserForRole(ctx, userID)
	if err != nil {
		return false, err
	}
	if user.IsRoot {
		return false, fmt.Errorf("%w: root 账户不能作为普通角色分配目标", ErrRootProtected)
	}
	if user.Status != account.StatusActive {
		return false, fmt.Errorf("%w: 账户当前状态为 %s", ErrUserNotEligible, user.Status)
	}
	if current.ScopeKind == ScopeKindApplication {
		scope, err := s.store.GetScope(ctx, current.ScopeID)
		if err != nil {
			return false, err
		}
		if !scope.ApplicationActive {
			return false, ErrApplicationInactive
		}
		membershipStatus, exists, err := s.store.GetApplicationMembership(ctx, current.ApplicationID, userID)
		if err != nil {
			return false, err
		}
		if !exists || membershipStatus != app.MembershipActive {
			return false, fmt.Errorf("%w: 目标用户不是应用 %s 的有效成员", ErrUserNotMember, current.ApplicationID)
		}
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	assignment := UserRoleAssignment{
		UserID: userID, RoleID: roleID, ScopeID: current.ScopeID,
		DataScope: "{}", AssignedBy: caller.actor.ID, CreatedAt: now,
	}
	changed := false
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     caller.actor,
			AppID:     current.ApplicationID,
			Action:    string(ActionAssignUserRole),
			Target:    audit.Target{Type: "role", ID: roleID},
			RequestID: caller.requestID,
			Changes: []audit.FieldChange{
				{Field: "user_id", After: userID},
				{Field: "role_id", After: roleID},
				{Field: "scope_id", After: current.ScopeID},
				{Field: "data_scope", After: "{}"},
			},
		},
		FailureReasonCode: "role.assignment_user_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		inserted, insertErr := s.store.AddUserRole(txCtx, tx, assignment)
		if insertErr != nil {
			return insertErr
		}
		changed = inserted
		return nil
	})
	if err != nil {
		return false, mapCriticalError(err)
	}
	if changed {
		s.logger.Info("角色已分配给用户", "role_id", roleID, "user_id", userID)
	}
	return changed, nil
}

// RevokeUserRole 撤回用户的角色分配。不存在的关系幂等成功（Changed=false）；
// 撤回用于安全清理，即使角色/应用/账户已停用也允许执行。
func (s *Service) RevokeUserRole(ctx context.Context, caller Caller, roleID, userID string) (bool, error) {
	current, err := s.getAuthorizedRole(ctx, caller, ActionRevokeUserRole, roleID)
	if err != nil {
		return false, err
	}
	userID = strings.TrimSpace(userID)
	if !account.ValidUserID(userID) {
		return false, fmt.Errorf("%w: 用户 ID 格式无效", ErrInvalidRequest)
	}
	changed := false
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     caller.actor,
			AppID:     current.ApplicationID,
			Action:    string(ActionRevokeUserRole),
			Target:    audit.Target{Type: "role", ID: roleID},
			RequestID: caller.requestID,
			Changes: []audit.FieldChange{
				{Field: "user_id", Before: userID},
				{Field: "role_id", Before: roleID},
				{Field: "scope_id", Before: current.ScopeID},
			},
		},
		FailureReasonCode: "role.revoke_user_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		removed, removeErr := s.store.RemoveUserRole(txCtx, tx, roleID, userID)
		if removeErr != nil {
			return removeErr
		}
		changed = removed
		return nil
	})
	if err != nil {
		return false, mapCriticalError(err)
	}
	return changed, nil
}

// AssignGroupRole 把角色分配给同一作用范围内的用户组。角色必须启用；系统角色只
// 能分配给系统组，应用角色只能分配给同一应用的应用组；应用停用时拒绝新分配。
// 重复分配幂等成功。
func (s *Service) AssignGroupRole(ctx context.Context, caller Caller, roleID, groupID string) (bool, error) {
	current, err := s.getAuthorizedRole(ctx, caller, ActionAssignGroupRole, roleID)
	if err != nil {
		return false, err
	}
	if !current.Enabled {
		return false, ErrRoleDisabled
	}
	groupID = strings.TrimSpace(groupID)
	if !validGroupID(groupID) {
		return false, fmt.Errorf("%w: 用户组 ID 格式无效", ErrInvalidRequest)
	}
	group, err := s.store.GetGroupForRole(ctx, groupID)
	if err != nil {
		return false, err
	}
	if group.ScopeID != current.ScopeID {
		return false, fmt.Errorf("%w: 用户组范围 %s 与角色范围 %s 不一致", ErrGroupScope, group.ScopeID, current.ScopeID)
	}
	if current.ScopeKind == ScopeKindApplication {
		scope, err := s.store.GetScope(ctx, current.ScopeID)
		if err != nil {
			return false, err
		}
		if !scope.ApplicationActive {
			return false, ErrApplicationInactive
		}
	}
	hasRoot, err := s.store.GroupHasRootMember(ctx, groupID)
	if err != nil {
		return false, err
	}
	if hasRoot {
		return false, fmt.Errorf("%w: 用户组包含 root 账户，不能分配普通角色", ErrRootProtected)
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	assignment := GroupRoleAssignment{
		GroupID: groupID, RoleID: roleID, ScopeID: current.ScopeID,
		DataScope: "{}", CreatedAt: now,
	}
	changed := false
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     caller.actor,
			AppID:     current.ApplicationID,
			Action:    string(ActionAssignGroupRole),
			Target:    audit.Target{Type: "role", ID: roleID},
			RequestID: caller.requestID,
			Changes: []audit.FieldChange{
				{Field: "group_id", After: groupID},
				{Field: "role_id", After: roleID},
				{Field: "scope_id", After: current.ScopeID},
				{Field: "data_scope", After: "{}"},
			},
		},
		FailureReasonCode: "role.assignment_group_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		inserted, insertErr := s.store.AddGroupRole(txCtx, tx, assignment)
		if insertErr != nil {
			return insertErr
		}
		changed = inserted
		return nil
	})
	if err != nil {
		return false, mapCriticalError(err)
	}
	if changed {
		s.logger.Info("角色已分配给用户组", "role_id", roleID, "group_id", groupID)
	}
	return changed, nil
}

// RevokeGroupRole 撤回用户组的角色分配。不存在的关系幂等成功；撤回用于安全清理，
// 即使角色/应用已停用也允许执行。
func (s *Service) RevokeGroupRole(ctx context.Context, caller Caller, roleID, groupID string) (bool, error) {
	current, err := s.getAuthorizedRole(ctx, caller, ActionRevokeGroupRole, roleID)
	if err != nil {
		return false, err
	}
	groupID = strings.TrimSpace(groupID)
	if !validGroupID(groupID) {
		return false, fmt.Errorf("%w: 用户组 ID 格式无效", ErrInvalidRequest)
	}
	changed := false
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     caller.actor,
			AppID:     current.ApplicationID,
			Action:    string(ActionRevokeGroupRole),
			Target:    audit.Target{Type: "role", ID: roleID},
			RequestID: caller.requestID,
			Changes: []audit.FieldChange{
				{Field: "group_id", Before: groupID},
				{Field: "role_id", Before: roleID},
				{Field: "scope_id", Before: current.ScopeID},
			},
		},
		FailureReasonCode: "role.revoke_group_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		removed, removeErr := s.store.RemoveGroupRole(txCtx, tx, roleID, groupID)
		if removeErr != nil {
			return removeErr
		}
		changed = removed
		return nil
	})
	if err != nil {
		return false, mapCriticalError(err)
	}
	return changed, nil
}

// ListRoleAssignments 列出角色的用户与用户组分配，写审计读取事件。
func (s *Service) ListRoleAssignments(ctx context.Context, caller Caller, roleID string) (Assignments, error) {
	current, err := s.getAuthorizedRole(ctx, caller, ActionListRoleAssignments, roleID)
	if err != nil {
		return Assignments{}, err
	}
	assignments, err := s.store.ListRoleAssignments(ctx, roleID)
	if err != nil {
		return Assignments{}, err
	}
	if err := s.recordRead(ctx, caller, ActionListRoleAssignments, current); err != nil {
		return Assignments{}, err
	}
	return assignments, nil
}

// authorize 校验可信调用者与授权器结果；缺失身份或授权器错误一律拒绝。
func (s *Service) authorize(ctx context.Context, caller Caller, action Action, scopeID string) error {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if !action.Valid() {
		return ErrAccessDenied
	}
	if err := caller.actor.Validate(); err != nil {
		return ErrAccessDenied
	}
	if err := s.authorizer.Authorize(ctx, caller, action, scopeID); err != nil {
		return fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	return nil
}

// getAuthorizedRole 先按可管理范围预鉴权，再读取角色；无管理范围不查库，范围外仅
// 读 scope 后拒绝，避免先读完整记录扩大存在性差异。
func (s *Service) getAuthorizedRole(ctx context.Context, caller Caller, action Action, id string) (Role, error) {
	if !ValidRoleID(id) {
		return Role{}, fmt.Errorf("%w: 角色 ID 格式无效", ErrInvalidRequest)
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return Role{}, err
	}
	if err := caller.actor.Validate(); err != nil {
		return Role{}, ErrAccessDenied
	}
	all, scopes, err := s.authorizer.ManageableScopes(ctx, caller)
	if err != nil {
		return Role{}, ErrAccessDenied
	}
	if all {
		record, err := s.store.GetRole(ctx, id)
		if err != nil {
			return Role{}, err
		}
		if err := s.authorize(ctx, caller, action, record.ScopeID); err != nil {
			return Role{}, err
		}
		return record, nil
	}
	if len(scopes) == 0 {
		return Role{}, ErrAccessDenied
	}
	scopeID, err := s.store.GetRoleScope(ctx, id)
	if err != nil {
		return Role{}, err
	}
	allowed := false
	for _, candidate := range scopes {
		if candidate == scopeID {
			allowed = true
			break
		}
	}
	if !allowed {
		return Role{}, ErrAccessDenied
	}
	record, err := s.store.GetRole(ctx, id)
	if err != nil {
		return Role{}, err
	}
	if err := s.authorize(ctx, caller, action, record.ScopeID); err != nil {
		return Role{}, err
	}
	return record, nil
}

// recordRead 写单条读取成功审计；失败时拒绝返回数据。
func (s *Service) recordRead(ctx context.Context, caller Caller, action Action, record Role) error {
	event := audit.Event{
		Actor:     caller.actor,
		AppID:     record.ApplicationID,
		Action:    string(action),
		Target:    audit.Target{Type: "role", ID: record.ID},
		Outcome:   audit.OutcomeSuccess,
		RequestID: caller.requestID,
	}
	if err := s.audit.Record(ctx, event); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	return nil
}

// recordListRead 写列表读取成功审计；失败时拒绝返回数据。
func (s *Service) recordListRead(ctx context.Context, caller Caller, appID string) error {
	event := audit.Event{
		Actor:     caller.actor,
		AppID:     appID,
		Action:    string(ActionListRoles),
		Target:    audit.Target{Type: "role"},
		Outcome:   audit.OutcomeSuccess,
		RequestID: caller.requestID,
	}
	if err := s.audit.Record(ctx, event); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	return nil
}

// mapCriticalError 把事务错误映射为角色领域错误；审计失败优先判定。
func mapCriticalError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, audit.ErrAuditUnavailable):
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrRoleNotFound),
		errors.Is(err, ErrScopeInvalid), errors.Is(err, ErrPermissionNotFound),
		errors.Is(err, ErrUserNotFound), errors.Is(err, ErrGroupNotFound):
		return err
	case errors.Is(err, ErrRoleKeyTaken), errors.Is(err, ErrRoleInUse),
		errors.Is(err, ErrRoleDisabled), errors.Is(err, ErrStateConflict):
		return err
	case errors.Is(err, ErrAccessDenied), errors.Is(err, ErrBuiltinProtected),
		errors.Is(err, ErrRootOnlyPermission), errors.Is(err, ErrRootProtected),
		errors.Is(err, ErrPermissionScope), errors.Is(err, ErrGroupScope),
		errors.Is(err, ErrUserNotMember), errors.Is(err, ErrUserNotEligible),
		errors.Is(err, ErrApplicationInactive):
		return err
	case errors.Is(err, ErrStoreUnavailable):
		return err
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, audit.ErrInvalidEvent):
		return fmt.Errorf("%w: 审计事件无效", ErrOptionsInvalid)
	default:
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
}

// normalizeContext 把 nil ctx 当成 Background。
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// isNil 检测 nil 接口与 typed nil 指针。
func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

// validPermissionID 复制权限 ID 格式校验（perm_ + 32 位十六进制），避免角色包
// 依赖权限包类型细节。
func validPermissionID(id string) bool {
	if len(id) != 5+32 || !strings.HasPrefix(id, "perm_") {
		return false
	}
	_, err := hex.DecodeString(id[5:])
	return err == nil
}

// validGroupID 复制用户组 ID 格式校验（grp_ + 32 位十六进制）。
func validGroupID(id string) bool {
	if len(id) != 4+32 || !strings.HasPrefix(id, "grp_") {
		return false
	}
	_, err := hex.DecodeString(id[4:])
	return err == nil
}
