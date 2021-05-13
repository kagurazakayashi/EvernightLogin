package delegation

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// AccountState 是委派检查使用的账户快照。
type AccountState struct {
	Status account.Status
	IsRoot bool
}

// PermissionState 是委派检查使用的权限定义快照。
type PermissionState struct {
	PermissionID string
	ScopeID      string
	Key          string
	Name         string
	Enabled      bool
	RootOnly     bool
}

// GrantQuery 是委派资格列表查询；DelegatorUserID 为空表示全部（仅受信操作者）。
type GrantQuery struct {
	DelegatorUserID string
	IncludeRevoked  bool
	Limit           int
	Offset          int
}

// Store 是委派资格持久化与事务内检查契约，由 internal/delegation/sqlite 提供
// 生产实现。带 audit.Tx 的方法必须在调用方审计事务内执行，用于保证“检查 + 写入”
// 同一一致性边界；仓储错误必须映射为 ErrStoreUnavailable。
type Store interface {
	// 事务内检查读取（Guard 使用）。
	AccountState(ctx context.Context, tx audit.Tx, userID string) (AccountState, bool, error)
	ApplicationState(ctx context.Context, tx audit.Tx, applicationID string) (active, found bool, err error)
	MembershipState(ctx context.Context, tx audit.Tx, applicationID, userID string) (exists, active bool, err error)
	PermissionDefinition(ctx context.Context, tx audit.Tx, permissionID string) (PermissionState, bool, error)
	HeldPermission(ctx context.Context, tx audit.Tx, userID, scopeID, permissionID string) (bool, error)
	GroupHasMember(ctx context.Context, tx audit.Tx, groupID, userID string) (bool, error)
	LoadGrants(ctx context.Context, tx audit.Tx, delegatorUserID, scopeID string) ([]Grant, error)
	// ScopeRestorationState 在调用方事务内读取“启用该范围应用时会被恢复”的权限
	// 与持有目标。权限只统计启用角色组合中的启用、非 root_only 权限，且角色当前
	// 有用户或用户组分配；目标是这些角色当前分配的用户与用户组（保守超集，包含
	// 之后可能失效的分配，绝不遗漏）。
	ScopeRestorationState(ctx context.Context, tx audit.Tx, scopeID string) (permissionIDs []string, targets []Target, err error)

	// 签发/撤回的事务内读取与写入。
	ResolvePermission(ctx context.Context, tx audit.Tx, scopeID, permissionKey string) (PermissionState, bool, error)
	GetGrantInTx(ctx context.Context, tx audit.Tx, id string) (Grant, error)
	// CreateOrReplaceGrant 以 (delegator,scope,permission) 唯一键写入或覆盖资格；
	// 覆盖时清除 revoked_at_ms 并返回覆盖前的快照供审计。
	CreateOrReplaceGrant(ctx context.Context, tx audit.Tx, grant Grant) (previous *Grant, err error)
	RevokeGrant(ctx context.Context, tx audit.Tx, id string, now time.Time) (bool, error)

	// 非事务读取（列表/可转授查询），只读且不修改状态。
	GetGrant(ctx context.Context, id string) (Grant, error)
	ListGrants(ctx context.Context, query GrantQuery) ([]Grant, error)
	// DelegatablePermissions 返回当前仍实际可转授的权限：资格未过期未撤回，且
	// 权限本身可用、操作者当前实际持有。
	DelegatablePermissions(ctx context.Context, delegatorUserID, scopeID string, now time.Time) ([]DelegatablePermission, error)
}

// AuditRecorder 是委派服务依赖的安全审计契约。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// Options 是委派服务依赖。Store 与 Audit 必填，缺失时不可构造。
type Options struct {
	Store  Store
	Audit  AuditRecorder
	Now    func() time.Time
	Random io.Reader
	Logger *slog.Logger
}

// Service 是委派资格服务，同时实现 Guard。构造后不可变，可并发使用。
type Service struct {
	store  Store
	audit  AuditRecorder
	now    func() time.Time
	random io.Reader
	logger *slog.Logger
}

// New 校验依赖并构造委派服务；缺少 Store/Audit 返回 ErrOptionsInvalid。
func New(options Options) (*Service, error) {
	if isNil(options.Store) {
		return nil, fmt.Errorf("%w: 委派存储为空", ErrOptionsInvalid)
	}
	if isNil(options.Audit) {
		return nil, fmt.Errorf("%w: 审计写入器为空", ErrOptionsInvalid)
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
	return &Service{store: options.Store, audit: options.Audit, now: now, random: random, logger: logger}, nil
}

// 编译期确认 Service 实现 Guard。
var _ Guard = (*Service)(nil)

// Grant 签发一条委派资格。只有受限本地/系统操作者可以签发；受信通道不改变任何
// 主体的有效权限，只登记“可转授”资格，并与成功审计同事务提交。
func (s *Service) Grant(ctx context.Context, caller Caller, request GrantRequest) (Grant, error) {
	if !trustedActor(caller.actor) {
		return Grant{}, fmt.Errorf("%w: 只有受限本地或系统操作者可以签发委派资格", ErrAccessDenied)
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return Grant{}, err
	}
	delegatorID := strings.TrimSpace(request.DelegatorUserID)
	if !account.ValidUserID(delegatorID) {
		return Grant{}, fmt.Errorf("%w: 委派对象用户 ID 格式无效", ErrInvalidRequest)
	}
	kind, applicationID, err := ParseScope(request.ScopeID)
	if err != nil {
		return Grant{}, err
	}
	scopeID := ScopeSystem
	if kind == ScopeKindApplication {
		scopeID = applicationID
	}
	permissionKey, err := validatePermissionKey(request.PermissionKey)
	if err != nil {
		return Grant{}, err
	}
	maxDataScope, err := normalizeMaxDataScope(request.MaxDataScope)
	if err != nil {
		return Grant{}, err
	}
	targetsJSON, err := request.AllowedTargets.JSON()
	if err != nil {
		return Grant{}, err
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	var expiresAt *time.Time
	if request.ExpiresAt != nil {
		expiry := request.ExpiresAt.UTC().Truncate(time.Millisecond)
		if !expiry.After(now) {
			return Grant{}, fmt.Errorf("%w: 委派有效期必须晚于当前时间", ErrInvalidRequest)
		}
		expiresAt = &expiry
	}
	id, err := NewGrantID(s.random)
	if err != nil {
		return Grant{}, fmt.Errorf("%w: %v", ErrStoreUnavailable, err)
	}
	grant := Grant{
		ID: id, DelegatorUserID: delegatorID, ScopeID: scopeID, ScopeKind: kind,
		ApplicationID: applicationID, PermissionKey: permissionKey,
		MaxDataScope: maxDataScope, AllowedTargets: request.AllowedTargets,
		AllowSelf: request.AllowSelf, ExpiresAt: expiresAt,
		CreatedBy: caller.actor, CreatedAt: now, UpdatedAt: now,
	}
	changes := []audit.FieldChange{
		{Field: "delegator_user_id", After: delegatorID},
		{Field: "scope_id", After: scopeID},
		{Field: "permission_key", After: permissionKey},
		{Field: "max_data_scope", After: maxDataScope},
		{Field: "allowed_targets", After: targetsJSON},
		{Field: "allow_self", After: formatBool(request.AllowSelf)},
		{Field: "expires_at", After: formatTime(expiresAt)},
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     caller.actor,
			AppID:     applicationID,
			Action:    "delegation.grant",
			Target:    audit.Target{Type: "delegation", ID: id},
			RequestID: caller.requestID,
			Changes:   changes,
		},
		FailureReasonCode: "delegation.grant_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		// 同一事务内重读账户/应用/权限状态，避免签发期间状态被并发修改。
		accountState, found, lookupErr := s.store.AccountState(txCtx, tx, delegatorID)
		if lookupErr != nil {
			return lookupErr
		}
		if !found || accountState.Status != account.StatusActive || accountState.IsRoot {
			return fmt.Errorf("%w: 目标账户不存在、非 active 或受保护", ErrDelegatorInvalid)
		}
		if kind == ScopeKindApplication {
			active, exists, scopeErr := s.store.ApplicationState(txCtx, tx, applicationID)
			if scopeErr != nil {
				return scopeErr
			}
			if !exists {
				return fmt.Errorf("%w: 应用不存在", ErrInvalidRequest)
			}
			if !active {
				return ErrApplicationInactive
			}
		}
		permission, found, resolveErr := s.store.ResolvePermission(txCtx, tx, scopeID, permissionKey)
		if resolveErr != nil {
			return resolveErr
		}
		if !found {
			return ErrPermissionNotFound
		}
		if !permission.Enabled || permission.RootOnly {
			return ErrPermissionUnavailable
		}
		grant.PermissionID = permission.PermissionID
		grant.PermissionName = permission.Name
		previous, storeErr := s.store.CreateOrReplaceGrant(txCtx, tx, grant)
		if storeErr != nil {
			return storeErr
		}
		if previous != nil {
			// 覆盖已有资格时在同一审计事务追加“被替换”事件，保留恢复所需的
			// 旧资格标识与旧有效期；不把旧值混进主事件的结构化差异。
			replacement, prepareErr := audit.PrepareEvent(audit.Event{
				Actor:     caller.actor,
				AppID:     applicationID,
				Action:    "delegation.grant.replaced",
				Target:    audit.Target{Type: "delegation", ID: previous.ID},
				Outcome:   audit.OutcomeSuccess,
				RequestID: caller.requestID,
				Changes: []audit.FieldChange{
					{Field: "replaced_by_grant_id", After: id},
					{Field: "previous_expires_at", Before: formatTime(previous.ExpiresAt)},
					{Field: "previous_revoked_at", Before: formatTime(previous.RevokedAt)},
				},
			}, now)
			if prepareErr != nil {
				return fmt.Errorf("%w: 替换审计事件无效", ErrInvalidRequest)
			}
			if appendErr := tx.AppendEvent(txCtx, replacement); appendErr != nil {
				return fmt.Errorf("%w: %w", ErrAuditUnavailable, appendErr)
			}
		}
		return nil
	})
	if err != nil {
		return Grant{}, mapCriticalError(err)
	}
	s.logger.Info("委派资格已签发",
		"grant_id", id, "delegator_user_id", delegatorID, "scope_id", scopeID, "permission_key", permissionKey)
	return grant, nil
}

// Revoke 撤回委派资格。只有受限本地/系统操作者可以撤回；重复撤回幂等。
func (s *Service) Revoke(ctx context.Context, caller Caller, grantID string) (bool, error) {
	if !trustedActor(caller.actor) {
		return false, fmt.Errorf("%w: 只有受限本地或系统操作者可以撤回委派资格", ErrAccessDenied)
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return false, err
	}
	grantID = strings.TrimSpace(grantID)
	if !ValidGrantID(grantID) {
		return false, fmt.Errorf("%w: 委派资格 ID 格式无效", ErrInvalidRequest)
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	changed := false
	var current Grant
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     caller.actor,
			Action:    "delegation.revoke",
			Target:    audit.Target{Type: "delegation", ID: grantID},
			RequestID: caller.requestID,
			Changes:   []audit.FieldChange{{Field: "revoked_at", After: formatTime(&now)}},
		},
		FailureReasonCode: "delegation.revoke_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err := s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		existing, getErr := s.store.GetGrantInTx(txCtx, tx, grantID)
		if getErr != nil {
			return getErr
		}
		current = existing
		revoked, revokeErr := s.store.RevokeGrant(txCtx, tx, grantID, now)
		if revokeErr != nil {
			return revokeErr
		}
		changed = revoked
		return nil
	})
	if err != nil {
		return false, mapCriticalError(err)
	}
	s.logger.Info("委派资格处理完成", "grant_id", grantID, "changed", changed,
		"delegator_user_id", current.DelegatorUserID, "scope_id", current.ScopeID)
	return changed, nil
}

// Get 读取一条委派资格并写审计读取事件；普通用户只能读取自己的资格。
func (s *Service) Get(ctx context.Context, caller Caller, grantID string) (Grant, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return Grant{}, err
	}
	grantID = strings.TrimSpace(grantID)
	if !ValidGrantID(grantID) {
		return Grant{}, fmt.Errorf("%w: 委派资格 ID 格式无效", ErrInvalidRequest)
	}
	grant, err := s.store.GetGrant(ctx, grantID)
	if err != nil {
		return Grant{}, err
	}
	if !trustedActor(caller.actor) && (caller.actor.Type != audit.ActorUser || caller.actor.ID != grant.DelegatorUserID) {
		return Grant{}, fmt.Errorf("%w: 只能读取自己的委派资格", ErrAccessDenied)
	}
	if err := s.recordRead(ctx, caller, "delegation.get", grant.DelegatorUserID, grant.ApplicationID); err != nil {
		return Grant{}, err
	}
	return grant, nil
}

// List 读取委派资格列表。普通用户只能读取自己的资格（忽略请求中的他人 ID）；
// 受信操作者可读取全部或指定委派对象。读取写审计，审计失败拒绝返回。
func (s *Service) List(ctx context.Context, caller Caller, request ListRequest) ([]Grant, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	delegator := strings.TrimSpace(request.DelegatorUserID)
	if !trustedActor(caller.actor) {
		if caller.actor.Type != audit.ActorUser {
			return nil, fmt.Errorf("%w: 未获准读取委派资格", ErrAccessDenied)
		}
		if delegator != "" && delegator != caller.actor.ID {
			return nil, fmt.Errorf("%w: 只能读取自己的委派资格", ErrAccessDenied)
		}
		delegator = caller.actor.ID
	} else if delegator != "" && !account.ValidUserID(delegator) {
		return nil, fmt.Errorf("%w: 委派对象用户 ID 格式无效", ErrInvalidRequest)
	}
	limit, offset, err := normalizeListBounds(request.Limit, request.Offset)
	if err != nil {
		return nil, err
	}
	grants, err := s.store.ListGrants(ctx, GrantQuery{
		DelegatorUserID: delegator, IncludeRevoked: request.IncludeRevoked,
		Limit: limit, Offset: offset,
	})
	if err != nil {
		return nil, err
	}
	target := delegator
	if target == "" {
		target = "*"
	}
	if err := s.recordRead(ctx, caller, "delegation.list", target, ""); err != nil {
		return nil, err
	}
	return grants, nil
}

// DelegatablePermissions 返回操作者自己当前实际可转授的权限（与“可使用权限”分开
// 查询）：要求资格未过期未撤回、权限可用且操作者当前实际持有。读取写审计，审计
// 失败拒绝返回。
func (s *Service) DelegatablePermissions(ctx context.Context, caller Caller, scopeID string) ([]DelegatablePermission, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if caller.actor.Type != audit.ActorUser {
		return nil, fmt.Errorf("%w: 只有普通用户可查询自己的可转授权限", ErrAccessDenied)
	}
	kind, applicationID, err := ParseScope(scopeID)
	if err != nil {
		return nil, err
	}
	resolvedScope := ScopeSystem
	appID := ""
	if kind == ScopeKindApplication {
		resolvedScope = applicationID
		appID = applicationID
	}
	permissions, err := s.store.DelegatablePermissions(ctx, caller.actor.ID, resolvedScope, s.now().UTC())
	if err != nil {
		return nil, err
	}
	if err := s.recordRead(ctx, caller, "delegation.delegatable.list", caller.actor.ID, appID); err != nil {
		return nil, err
	}
	return permissions, nil
}

// CheckPermissionAccess 实现 Guard：检查操作者能否把权限纳入角色。除了资格与
// “当前实际持有”，还按角色当前分配目标（用户与用户组）校验 allow_self 与目标
// 白名单，封堵“把权限组合进已分配给白名单外用户或自身所在组的角色”的间接提权。
func (s *Service) CheckPermissionAccess(ctx context.Context, tx audit.Tx, actor audit.Actor, scopeID string, permissions []PermissionRef, targets []Target) error {
	if trustedActor(actor) {
		return nil
	}
	return s.checkTransfer(ctx, tx, actor, scopeID, permissions, true, targets, transferOptions{})
}

// CheckAssignment 实现 Guard：检查操作者能否把权限转授给指定目标，额外校验
// 自我提权与目标白名单限制。
func (s *Service) CheckAssignment(ctx context.Context, tx audit.Tx, actor audit.Actor, scopeID string, permissions []PermissionRef, target Target) error {
	if trustedActor(actor) {
		return nil
	}
	return s.checkTransfer(ctx, tx, actor, scopeID, permissions, true, []Target{target}, transferOptions{})
}

// CheckPermissionActivation 实现 Guard：启用角色/启用权限只要求有效委派资格，
// 不要求操作者“当前持有”（被启用的能力此刻可能尚未生效）；但启用会让既有目标
// 重新获得权限，因此仍需按受影响目标集合校验 allow_self 与目标白名单。
func (s *Service) CheckPermissionActivation(ctx context.Context, tx audit.Tx, actor audit.Actor, scopeID string, permissions []PermissionRef, targets []Target) error {
	if trustedActor(actor) {
		return nil
	}
	return s.checkTransfer(ctx, tx, actor, scopeID, permissions, false, targets, transferOptions{})
}

// CheckScopeRestoration 实现 Guard：启用应用会恢复该范围内被整体拒绝的权限。
// 与写入同一事务内读取“将被恢复的权限集合”与“这些权限的持有目标”，按启用角色/
// 权限的同一语义校验；应用停用的状态不再作为拒绝理由，否则无人能安全恢复。
// 读取失败、数量超限或数据损坏一律 fail-closed。
func (s *Service) CheckScopeRestoration(ctx context.Context, tx audit.Tx, actor audit.Actor, scopeID string) error {
	if trustedActor(actor) {
		return nil
	}
	if tx == nil {
		return fmt.Errorf("%w: 应用启用检查缺少事务视图", ErrOptionsInvalid)
	}
	kind, applicationID, err := ParseScope(scopeID)
	if err != nil {
		return err
	}
	resolvedScope := ScopeSystem
	if kind == ScopeKindApplication {
		resolvedScope = applicationID
	}
	permissionIDs, targets, err := s.store.ScopeRestorationState(ctx, tx, resolvedScope)
	if err != nil {
		return err
	}
	refs := make([]PermissionRef, 0, len(permissionIDs))
	for _, id := range permissionIDs {
		refs = append(refs, PermissionRef{PermissionID: id})
	}
	return s.checkTransfer(ctx, tx, actor, scopeID, refs, false, targets,
		transferOptions{allowInactiveApplication: true})
}

// transferOptions 是转授检查的路径差异开关；默认（零值）为最严格语义。
type transferOptions struct {
	// allowInactiveApplication 允许应用处于停用状态仍然执行检查（仅启用应用路径
	// 使用：此刻应用必然停用，否则无需恢复）。
	allowInactiveApplication bool
}

// checkTransfer 是统一转授检查：在调用方事务内读取账户/应用/成员/权限/资格/
// 持有情况/目标限制，任一不满足 fail-closed。调用前已确认非受信操作者。
func (s *Service) checkTransfer(ctx context.Context, tx audit.Tx, actor audit.Actor, scopeID string, permissions []PermissionRef, requireHeld bool, targets []Target, options transferOptions) error {
	if tx == nil {
		return fmt.Errorf("%w: 转授检查缺少事务视图", ErrOptionsInvalid)
	}
	if actor.Type != audit.ActorUser || !account.ValidUserID(actor.ID) {
		return fmt.Errorf("%w: 转授检查只接受可识别用户操作者", ErrAccessDenied)
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	kind, applicationID, err := ParseScope(scopeID)
	if err != nil {
		return err
	}
	resolvedScope := ScopeSystem
	if kind == ScopeKindApplication {
		resolvedScope = applicationID
	}
	// 损坏或超限的目标集合直接拒绝，不静默缩小校验范围。
	normalizedTargets, err := NormalizeTargets(targets)
	if err != nil {
		return err
	}
	if len(permissions) > MaxPermissionRefs {
		// 无界检查会让一次写入放大成大量查询；普通管理者 fail-closed。
		return fmt.Errorf("%w: 单次转授检查的权限数量超过上限 %d", ErrInvalidRequest, MaxPermissionRefs)
	}
	accountState, found, err := s.store.AccountState(ctx, tx, actor.ID)
	if err != nil {
		return err
	}
	if !found || accountState.Status != account.StatusActive || accountState.IsRoot {
		return fmt.Errorf("%w: 操作者账户不存在、非 active 或为 root", ErrDelegatorInvalid)
	}
	if kind == ScopeKindApplication {
		active, exists, appErr := s.store.ApplicationState(ctx, tx, applicationID)
		if appErr != nil {
			return appErr
		}
		if !exists {
			return fmt.Errorf("%w: 应用不存在", ErrInvalidRequest)
		}
		if !active && !options.allowInactiveApplication {
			return ErrApplicationInactive
		}
		memberExists, memberActive, memberErr := s.store.MembershipState(ctx, tx, applicationID, actor.ID)
		if memberErr != nil {
			return memberErr
		}
		if !memberExists || !memberActive {
			return fmt.Errorf("%w: 操作者不是该应用的有效成员", ErrTransferNotGranted)
		}
	}
	grants, err := s.store.LoadGrants(ctx, tx, actor.ID, resolvedScope)
	if err != nil {
		return err
	}
	grantByPermission := make(map[string]Grant, len(grants))
	for _, grant := range grants {
		grantByPermission[grant.PermissionID] = grant
	}
	now := s.now().UTC()
	// 同一目标用户组的自我成员判断最多查询一次，避免按权限重复查询。
	groupSelf := make(map[string]bool)
	selfOfGroup := func(groupID string) (bool, error) {
		if member, cached := groupSelf[groupID]; cached {
			return member, nil
		}
		member, memberErr := s.store.GroupHasMember(ctx, tx, groupID, actor.ID)
		if memberErr != nil {
			return false, memberErr
		}
		groupSelf[groupID] = member
		return member, nil
	}
	for _, ref := range permissions {
		permissionID := strings.TrimSpace(ref.PermissionID)
		if !validPermissionIDShape(permissionID) {
			return fmt.Errorf("%w: 权限 ID 格式无效", ErrInvalidRequest)
		}
		permission, permissionFound, definitionErr := s.store.PermissionDefinition(ctx, tx, permissionID)
		if definitionErr != nil {
			return definitionErr
		}
		if !permissionFound {
			return ErrPermissionNotFound
		}
		if permission.ScopeID != resolvedScope {
			return ErrScopeMismatch
		}
		if permission.RootOnly {
			return ErrPermissionUnavailable
		}
		if requireHeld && !permission.Enabled {
			return ErrPermissionUnavailable
		}
		grant, granted := grantByPermission[permissionID]
		if !granted {
			return fmt.Errorf("%w: 权限 %s", ErrTransferNotGranted, permission.Key)
		}
		if grant.RevokedAt != nil {
			return fmt.Errorf("%w: 权限 %s", ErrTransferRevoked, permission.Key)
		}
		if !grant.Active(now) {
			return fmt.Errorf("%w: 权限 %s", ErrTransferExpired, permission.Key)
		}
		if requireHeld {
			held, heldErr := s.store.HeldPermission(ctx, tx, actor.ID, resolvedScope, permissionID)
			if heldErr != nil {
				return heldErr
			}
			if !held {
				return fmt.Errorf("%w: 权限 %s", ErrPermissionNotHeld, permission.Key)
			}
		}
		requested, scopeErr := parseRequestedDataScope(ref.DataScopeJSON)
		if scopeErr != nil {
			return scopeErr
		}
		maxScope, maxErr := parseMaxDataScope(grant.MaxDataScope)
		if maxErr != nil {
			// 委派上限数据损坏时 fail-closed，不按最宽范围解释。
			return fmt.Errorf("%w: 委派数据范围上限数据无效", ErrStoreUnavailable)
		}
		if !dataScopeSubset(requested, maxScope) {
			return fmt.Errorf("%w: 权限 %s", ErrDataScopeTooBroad, permission.Key)
		}
		for _, target := range normalizedTargets {
			if targetErr := s.checkTarget(ctx, tx, actor, grant, target, selfOfGroup); targetErr != nil {
				return targetErr
			}
		}
	}
	return nil
}

// checkTarget 校验转授目标：不能向自身/自身所在用户组转授（除非显式 allow_self），
// 配置了目标白名单时目标必须在白名单内。
func (s *Service) checkTarget(ctx context.Context, tx audit.Tx, actor audit.Actor, grant Grant, target Target, selfOfGroup func(groupID string) (bool, error)) error {
	switch target.Kind {
	case TargetUser:
		if target.ID == actor.ID && !grant.AllowSelf {
			return fmt.Errorf("%w: 目标用户是操作者本人", ErrSelfTransferDenied)
		}
	case TargetGroup:
		if !grant.AllowSelf {
			member, memberErr := selfOfGroup(target.ID)
			if memberErr != nil {
				return memberErr
			}
			if member {
				return fmt.Errorf("%w: 操作者是目标用户组成员", ErrSelfTransferDenied)
			}
		}
	default:
		return fmt.Errorf("%w: 目标类型无效", ErrInvalidRequest)
	}
	if grant.AllowedTargets.Restricted() {
		allowed := false
		switch target.Kind {
		case TargetUser:
			allowed = containsID(grant.AllowedTargets.Users, target.ID)
		case TargetGroup:
			allowed = containsID(grant.AllowedTargets.Groups, target.ID)
		}
		if !allowed {
			return ErrTargetNotAllowed
		}
	}
	return nil
}

// recordRead 写审计读取事件；失败时拒绝返回数据（fail-closed）。
func (s *Service) recordRead(ctx context.Context, caller Caller, action, delegatorUserID, applicationID string) error {
	event := audit.Event{
		Actor:     caller.actor,
		AppID:     applicationID,
		Action:    action,
		Target:    audit.Target{Type: "delegation", ID: delegatorUserID},
		Outcome:   audit.OutcomeSuccess,
		RequestID: caller.requestID,
	}
	if err := s.audit.Record(ctx, event); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	return nil
}

// mapCriticalError 把审计事务错误映射为委派领域错误；仓储错误已在仓储层包装。
func mapCriticalError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, audit.ErrAuditUnavailable) || errors.Is(err, audit.ErrDuplicateEvent) {
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	return err
}

// normalizeContext 保证上下文可用。
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// normalizeListBounds 校验列表分页边界。
func normalizeListBounds(limit, offset int) (int, int, error) {
	if limit <= 0 {
		limit = DefaultListLimit
	}
	if limit > MaxListLimit {
		return 0, 0, fmt.Errorf("%w: 列表数量超过上限 %d", ErrInvalidRequest, MaxListLimit)
	}
	if offset < 0 || offset > MaxListOffset {
		return 0, 0, fmt.Errorf("%w: 列表偏移超出范围", ErrInvalidRequest)
	}
	return limit, offset, nil
}

// validatePermissionKey 校验权限机器标识形状（2～128 字节，小写字母/数字与 ._-）。
func validatePermissionKey(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if len(value) < 2 || len(value) > MaxScopeKeyBytes {
		return "", fmt.Errorf("%w: 权限机器标识长度必须是 2～%d 字节", ErrInvalidRequest, MaxScopeKeyBytes)
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		switch {
		case character >= 'a' && character <= 'z':
		case character >= '0' && character <= '9':
		case character == '.', character == '_', character == '-':
		default:
			return "", fmt.Errorf("%w: 权限机器标识只能包含小写字母、数字、点、下划线与连字符", ErrInvalidRequest)
		}
	}
	return value, nil
}

// parseMaxDataScope 解析仓储中的委派数据范围上限；空值视为 all。
func parseMaxDataScope(raw string) (dataScope, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		trimmed = `{"v":1,"mode":"all"}`
	}
	return parseDataScope(trimmed)
}

// containsID 报告列表是否包含指定 ID。
func containsID(ids []string, value string) bool {
	for _, id := range ids {
		if strings.TrimSpace(id) == value {
			return true
		}
	}
	return false
}

// formatBool 把布尔值转为审计差异文本。
func formatBool(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

// formatTime 把可空时间转为审计差异文本。
func formatTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

// isNil 报告接口是否为 nil 或 typed nil。
func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Slice, reflect.Interface, reflect.Func, reflect.Chan:
		return reflected.IsNil()
	default:
		return false
	}
}
