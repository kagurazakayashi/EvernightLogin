package permission

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// ScopeInfo 是权限作用范围数据库快照。
type ScopeInfo struct {
	ScopeID           string
	Kind              ScopeKind
	ApplicationID     string
	ApplicationActive bool
}

// ListQuery 是已校验的权限目录查询。
type ListQuery struct {
	Limit       int
	Offset      int
	AllScopes   bool
	ScopeIDs    []string
	ScopeFilter string
	Enabled     *bool
}

// Store 是权限目录持久化契约，由 internal/permission/sqlite 提供生产实现。
type Store interface {
	GetScope(ctx context.Context, scopeID string) (ScopeInfo, error)
	CreatePermission(ctx context.Context, tx audit.Tx, record Permission) error
	GetPermission(ctx context.Context, id string) (Permission, error)
	// GetPermissionScope 只读取权限的 scope，供先鉴权后读取完整记录使用。
	GetPermissionScope(ctx context.Context, id string) (string, error)
	ListPermissions(ctx context.Context, query ListQuery) ([]Permission, bool, error)
	UpdatePermission(ctx context.Context, tx audit.Tx, id, name, description, limits string, now time.Time) error
	SetEnabled(ctx context.Context, tx audit.Tx, id string, enabled bool, now time.Time) error
	// CountReferences 返回 role_permissions 对该权限的引用数量；删除前预检。
	CountReferences(ctx context.Context, id string) (int, error)
	// DeletePermission 在同一事务条件删除，并确认没有 role_permissions 引用。
	DeletePermission(ctx context.Context, tx audit.Tx, id string) error
}

// AuditRecorder 是权限服务依赖的审计契约。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// Options 是权限服务依赖。
type Options struct {
	Store      Store
	Audit      AuditRecorder
	Authorizer Authorizer
	Now        func() time.Time
	Random     io.Reader
	Logger     *slog.Logger
}

// Service 是权限目录服务；构造后不可变，可并发使用。
type Service struct {
	store      Store
	audit      AuditRecorder
	authorizer Authorizer
	now        func() time.Time
	random     io.Reader
	logger     *slog.Logger
}

// New 校验依赖并构造服务。
func New(options Options) (*Service, error) {
	if isNil(options.Store) {
		return nil, fmt.Errorf("%w: 权限存储为空", ErrOptionsInvalid)
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

// CreatePermission 登记系统内置/系统自定义/应用独有权限。系统内置权限只能创建在
// 系统范围；应用范围不能创建 builtin 或 root_only 权限，应用管理员不能创建系统
// 权限或提升系统资格。新建权限默认 enabled=true，登记不代表创建者获得该权限。
func (s *Service) CreatePermission(ctx context.Context, caller Caller, request CreateRequest) (Permission, error) {
	if err := s.authorize(ctx, caller, ActionCreatePermission, request.ScopeID); err != nil {
		return Permission{}, err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return Permission{}, err
	}
	kind, applicationID, err := ParseScope(request.ScopeID)
	if err != nil {
		return Permission{}, err
	}
	scope, err := s.store.GetScope(ctx, strings.TrimSpace(request.ScopeID))
	if err != nil {
		return Permission{}, err
	}
	if kind != scope.Kind || applicationID != scope.ApplicationID {
		return Permission{}, ErrScopeInvalid
	}
	if kind == ScopeKindApplication {
		if request.IsBuiltin {
			return Permission{}, fmt.Errorf("%w: 应用不能创建系统内置权限", ErrAccessDenied)
		}
		if request.RootOnly {
			return Permission{}, fmt.Errorf("%w: root_only 只允许系统内置/系统自定义权限", ErrInvalidRequest)
		}
		if !scope.ApplicationActive {
			return Permission{}, fmt.Errorf("%w: 应用当前不可登记权限", ErrApplicationInactive)
		}
	}
	key, err := ValidateKey(request.Key)
	if err != nil {
		return Permission{}, err
	}
	name, err := ValidateName(request.Name)
	if err != nil {
		return Permission{}, err
	}
	description, err := ValidateDescription(request.Description)
	if err != nil {
		return Permission{}, err
	}
	limits, err := ValidateLimits(request.Limits)
	if err != nil {
		return Permission{}, err
	}
	id, err := NewPermissionID(s.random)
	if err != nil {
		return Permission{}, fmt.Errorf("%w: %v", ErrStoreUnavailable, err)
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	record := Permission{
		ID: id, ScopeID: scope.ScopeID, ScopeKind: kind, ApplicationID: applicationID,
		Key: key, Group: KeyGroup(key), Name: name, Description: description, Limits: limits,
		IsBuiltin: request.IsBuiltin, RootOnly: request.RootOnly, Enabled: true,
		CreatedAt: now, UpdatedAt: now,
	}
	event := audit.Event{
		Actor:     caller.actor,
		AppID:     applicationID,
		Action:    string(ActionCreatePermission),
		Target:    audit.Target{Type: "permission", ID: id},
		RequestID: caller.requestID,
		Changes: []audit.FieldChange{
			{Field: "scope_id", After: scope.ScopeID},
			{Field: "permission_key", After: key},
			{Field: "name", After: name},
			{Field: "builtin", After: strconv.FormatBool(request.IsBuiltin)},
			{Field: "root_only", After: strconv.FormatBool(request.RootOnly)},
			{Field: "enabled", After: "true"},
		},
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "permission.create_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.store.CreatePermission(txCtx, tx, record)
	})
	if err != nil {
		return Permission{}, mapCriticalError(err)
	}
	s.logger.Info("权限已登记", "permission_id", id, "scope_id", scope.ScopeID, "builtin", request.IsBuiltin)
	return record, nil
}

// GetPermission 按稳定 ID 读取权限，并写审计读取事件。
func (s *Service) GetPermission(ctx context.Context, caller Caller, id string) (Permission, error) {
	record, err := s.getAuthorizedPermission(ctx, caller, ActionGetPermission, id)
	if err != nil {
		return Permission{}, err
	}
	if err := s.recordRead(ctx, caller, ActionGetPermission, record); err != nil {
		return Permission{}, err
	}
	return record, nil
}

// ListPermissions 在可管理范围内分页查询权限目录。空 ScopeID 是合法默认用法；
// 应用管理员只看到分配应用的权限，不会返回系统权限或其他应用权限。
func (s *Service) ListPermissions(ctx context.Context, caller Caller, request ListRequest) (ListResult, error) {
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
	query := ListQuery{Limit: limit, Offset: request.Offset, AllScopes: all, Enabled: request.Enabled}
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
			if err := s.recordListRead(ctx, caller); err != nil {
				return ListResult{}, err
			}
			return ListResult{Permissions: []Permission{}}, nil
		}
		query.ScopeIDs = scopes
	}
	permissions, hasMore, err := s.store.ListPermissions(ctx, query)
	if err != nil {
		return ListResult{}, err
	}
	if err := s.recordListRead(ctx, caller); err != nil {
		return ListResult{}, err
	}
	return ListResult{Permissions: permissions, HasMore: hasMore}, nil
}

// UpdatePermission 修改自定义权限的直白名称、说明与明确限制。内置权限不能修改
// 含义；机器标识/scope/builtin/root_only 不在更新请求中，因此不可变。
func (s *Service) UpdatePermission(ctx context.Context, caller Caller, id string, request UpdateRequest) (Permission, error) {
	current, err := s.getAuthorizedPermission(ctx, caller, ActionUpdatePermission, id)
	if err != nil {
		return Permission{}, err
	}
	if current.IsBuiltin {
		return Permission{}, ErrBuiltinProtected
	}
	name, err := ValidateName(request.Name)
	if err != nil {
		return Permission{}, err
	}
	description, err := ValidateDescription(request.Description)
	if err != nil {
		return Permission{}, err
	}
	limits, err := ValidateLimits(request.Limits)
	if err != nil {
		return Permission{}, err
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
	event := audit.Event{
		Actor:     caller.actor,
		AppID:     current.ApplicationID,
		Action:    string(ActionUpdatePermission),
		Target:    audit.Target{Type: "permission", ID: id},
		RequestID: caller.requestID,
		Changes:   changes,
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "permission.update_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.store.UpdatePermission(txCtx, tx, id, name, description, limits, now)
	})
	if err != nil {
		return Permission{}, mapCriticalError(err)
	}
	return updated, nil
}

// EnablePermission 启用权限。重复启用幂等成功；启用不授予任何角色或主体权限。
func (s *Service) EnablePermission(ctx context.Context, caller Caller, id string) (Permission, bool, error) {
	return s.setPermissionEnabled(ctx, caller, id, true, ActionEnablePermission)
}

// DisablePermission 停用权限。停用是拒绝操作，不是跳过检查；重复停用幂等成功。
// root_only 内置权限属于安全底线，只能由受限本地初始化操作者停用。
func (s *Service) DisablePermission(ctx context.Context, caller Caller, id string) (Permission, bool, error) {
	return s.setPermissionEnabled(ctx, caller, id, false, ActionDisablePermission)
}

// setPermissionEnabled 执行启停：先鉴权与读取，root_only 内置权限要求本地操作者，
// 幂等请求写成功审计，实际变更使用审计事务。
func (s *Service) setPermissionEnabled(ctx context.Context, caller Caller, id string, target bool, action Action) (Permission, bool, error) {
	current, err := s.getAuthorizedPermission(ctx, caller, action, id)
	if err != nil {
		return Permission{}, false, err
	}
	if current.RootOnly && caller.actor.Type != audit.ActorLocalAdmin {
		return Permission{}, false, fmt.Errorf("%w: root_only 敏感权限只能由受限本地操作者启停", ErrAccessDenied)
	}
	if current.Enabled == target {
		event := audit.Event{
			Actor:     caller.actor,
			AppID:     current.ApplicationID,
			Action:    string(action),
			Target:    audit.Target{Type: "permission", ID: id},
			Outcome:   audit.OutcomeSuccess,
			RequestID: caller.requestID,
			Changes:   []audit.FieldChange{{Field: "result", After: "unchanged"}},
		}
		if err := s.audit.Record(ctx, event); err != nil {
			return Permission{}, false, fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
		}
		return current, false, nil
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	updated := current
	updated.Enabled = target
	updated.UpdatedAt = now
	event := audit.Event{
		Actor:     caller.actor,
		AppID:     current.ApplicationID,
		Action:    string(action),
		Target:    audit.Target{Type: "permission", ID: id},
		RequestID: caller.requestID,
		Changes: []audit.FieldChange{
			{Field: "enabled", Before: strconv.FormatBool(current.Enabled), After: strconv.FormatBool(target)},
			{Field: "root_only", After: strconv.FormatBool(current.RootOnly)},
		},
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "permission.state_change_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.store.SetEnabled(txCtx, tx, id, target, now)
	})
	if err != nil {
		return Permission{}, false, mapCriticalError(err)
	}
	s.logger.Info("权限状态已变更", "permission_id", id, "enabled", target)
	return updated, true, nil
}

// DeletePermission 删除自定义权限。内置权限永远拒绝；仍被 role_permissions 引用的
// 权限拒绝删除（避免隐式级联破坏授权关系）；删除只移除目录记录，审计历史保留。
func (s *Service) DeletePermission(ctx context.Context, caller Caller, id string) error {
	current, err := s.getAuthorizedPermission(ctx, caller, ActionDeletePermission, id)
	if err != nil {
		return err
	}
	if current.IsBuiltin {
		return ErrBuiltinProtected
	}
	references, err := s.store.CountReferences(ctx, id)
	if err != nil {
		return err
	}
	if references > 0 {
		return fmt.Errorf("%w: 仍被 %d 个角色引用", ErrPermissionInUse, references)
	}
	event := audit.Event{
		Actor:     caller.actor,
		AppID:     current.ApplicationID,
		Action:    string(ActionDeletePermission),
		Target:    audit.Target{Type: "permission", ID: id},
		RequestID: caller.requestID,
		Changes: []audit.FieldChange{
			{Field: "scope_id", Before: current.ScopeID},
			{Field: "permission_key", Before: current.Key},
			{Field: "builtin", Before: strconv.FormatBool(current.IsBuiltin)},
			{Field: "status", After: "deleted"},
		},
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "permission.delete_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.store.DeletePermission(txCtx, tx, id)
	})
	if err != nil {
		return mapCriticalError(err)
	}
	s.logger.Info("权限已删除", "permission_id", id)
	return nil
}

// getAuthorizedPermission 先按可管理范围预鉴权，再读取权限；无管理范围不查库，
// 范围外仅读 scope 后拒绝，避免先读完整记录扩大存在性差异。
func (s *Service) getAuthorizedPermission(ctx context.Context, caller Caller, action Action, id string) (Permission, error) {
	if !ValidPermissionID(id) {
		return Permission{}, fmt.Errorf("%w: 权限 ID 格式无效", ErrInvalidRequest)
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return Permission{}, err
	}
	if err := caller.actor.Validate(); err != nil {
		return Permission{}, ErrAccessDenied
	}
	all, scopes, err := s.authorizer.ManageableScopes(ctx, caller)
	if err != nil {
		return Permission{}, ErrAccessDenied
	}
	if all {
		record, err := s.store.GetPermission(ctx, id)
		if err != nil {
			return Permission{}, err
		}
		if err := s.authorize(ctx, caller, action, record.ScopeID); err != nil {
			return Permission{}, err
		}
		return record, nil
	}
	if len(scopes) == 0 {
		return Permission{}, ErrAccessDenied
	}
	scopeID, err := s.store.GetPermissionScope(ctx, id)
	if err != nil {
		return Permission{}, err
	}
	allowed := false
	for _, candidate := range scopes {
		if candidate == scopeID {
			allowed = true
			break
		}
	}
	if !allowed {
		return Permission{}, ErrAccessDenied
	}
	record, err := s.store.GetPermission(ctx, id)
	if err != nil {
		return Permission{}, err
	}
	if err := s.authorize(ctx, caller, action, record.ScopeID); err != nil {
		return Permission{}, err
	}
	return record, nil
}

// authorize 校验可信调用者与授权器结果。
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

// recordRead 写权限读取审计；审计失败拒绝返回数据。
func (s *Service) recordRead(ctx context.Context, caller Caller, action Action, record Permission) error {
	event := audit.Event{
		Actor:     caller.actor,
		AppID:     record.ApplicationID,
		Action:    string(action),
		Target:    audit.Target{Type: "permission", ID: record.ID},
		Outcome:   audit.OutcomeSuccess,
		RequestID: caller.requestID,
	}
	if err := s.audit.Record(ctx, event); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	return nil
}

// recordListRead 写权限列表读取审计。
func (s *Service) recordListRead(ctx context.Context, caller Caller) error {
	event := audit.Event{
		Actor:     caller.actor,
		Action:    string(ActionListPermissions),
		Target:    audit.Target{Type: "permission"},
		Outcome:   audit.OutcomeSuccess,
		RequestID: caller.requestID,
	}
	if err := s.audit.Record(ctx, event); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	return nil
}

// mapCriticalError 把事务错误映射为权限领域错误；审计失败优先。
func mapCriticalError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, audit.ErrAuditUnavailable):
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrPermissionNotFound),
		errors.Is(err, ErrScopeInvalid):
		return err
	case errors.Is(err, ErrPermissionKeyTaken), errors.Is(err, ErrPermissionInUse),
		errors.Is(err, ErrStateConflict):
		return err
	case errors.Is(err, ErrAccessDenied), errors.Is(err, ErrBuiltinProtected):
		return err
	case errors.Is(err, ErrApplicationInactive), errors.Is(err, ErrStoreUnavailable):
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
