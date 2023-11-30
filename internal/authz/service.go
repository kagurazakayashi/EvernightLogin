package authz

import (
	"context"
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
	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
)

// Reader 是同一事务快照内的只读查询契约，由 internal/authz/sqlite 实现。
type Reader interface {
	// Account 读取账户状态；not found 返回 found=false。
	Account(ctx context.Context, userID string) (AccountInfo, bool, error)
	// Application 读取应用状态；not found 返回 found=false。
	Application(ctx context.Context, applicationID string) (ApplicationInfo, bool, error)
	// Membership 读取应用成员状态。
	Membership(ctx context.Context, applicationID, userID string) (MembershipInfo, error)
	// Permission 读取指定 scope 内权限定义；not found 返回 found=false。
	Permission(ctx context.Context, scopeID, key string) (PermissionInfo, bool, error)
	// GrantedPermissions 返回已过滤角色/权限启停与 root_only 的有效权限目录页；
	// 结果按 permission_key 稳定排序。
	GrantedPermissions(ctx context.Context, scopeID, userID string, limit, offset int) ([]PermissionInfo, bool, error)
	// PermissionSources 返回指定权限集合的候选来源（含停用/被限制项），按固定次序
	// 排序；用于有效权限来源与诊断查询。
	PermissionSources(ctx context.Context, scopeID, userID string, permissionIDs []string, limit, offset int) ([]GrantSource, bool, error)
}

// Store 在单个数据库事务快照中执行一组读取，保证账户/应用/成员/角色/权限/分配
// 的一致性；查询失败时必须关闭快照并返回错误。第一版不缓存结果。
type Store interface {
	Snapshot(ctx context.Context, fn func(ctx context.Context, reader Reader) error) error
}

// Options 是授权引擎依赖。
type Options struct {
	Store      Store
	Authorizer Authorizer
	Logger     *slog.Logger
	// Now 是可注入时钟；nil 使用 time.Now。用于账户有效期即时判断。
	Now func() time.Time
}

// Service 是有效权限计算引擎；构造后不可变，可并发使用，不启动后台协程。
type Service struct {
	store      Store
	authorizer Authorizer
	logger     *slog.Logger
	now        func() time.Time
}

// New 校验依赖并构造引擎；缺少 Store/Authorizer 返回 ErrOptionsInvalid。
func New(options Options) (*Service, error) {
	if isNil(options.Store) {
		return nil, fmt.Errorf("%w: 授权存储为空", ErrOptionsInvalid)
	}
	if isNil(options.Authorizer) {
		return nil, fmt.Errorf("%w: 查询授权器为空", ErrOptionsInvalid)
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &Service{store: options.Store, authorizer: options.Authorizer, logger: logger,
		now: now}, nil
}

// subjectState 是同一快照内的主体状态。
type subjectState struct {
	account     AccountInfo
	application ApplicationInfo
	membership  MembershipInfo
	scope       Scope
}

// denial 描述整体拒绝码。
type denial struct {
	code   ErrorCode
	reason string
}

// Check 检查主体是否满足一组权限。caller 为普通用户时 SubjectUserID 必须是本人；
// 本地/系统操作者可显式检查普通主体。all/any 默认 all；未知、停用或 root_only
// 权限拒绝；依赖不可用时返回 AUTHZ_UNAVAILABLE 且 Allowed=false。
func (s *Service) Check(ctx context.Context, caller Caller, request CheckRequest) (CheckResult, error) {
	ctx = normalizeContext(ctx)
	result, err := s.prepareCheck(ctx, caller, request)
	if err != nil {
		return CheckResult{}, err
	}
	return result, nil
}

// prepareCheck 完成校验、授权与同一快照计算。
func (s *Service) prepareCheck(ctx context.Context, caller Caller, request CheckRequest) (CheckResult, error) {
	scope, err := ParseScope(request.ScopeID)
	if err != nil {
		return CheckResult{}, err
	}
	subject := stringsTrim(request.SubjectUserID)
	if !account.ValidUserID(subject) {
		return CheckResult{}, fmt.Errorf("%w: 被检查用户 ID 格式无效", ErrInvalidRequest)
	}
	keys, err := validatePermissionKeys(request.Permissions)
	if err != nil {
		return CheckResult{}, err
	}
	mode, err := validateMode(request.Mode)
	if err != nil {
		return CheckResult{}, err
	}
	if err := s.authorizeQuery(ctx, caller, subject, scope); err != nil {
		return CheckResult{}, err
	}
	if caller.actor.Type == audit.ActorUser && caller.actor.ID != subject {
		// 普通用户不能通过 Check 检查别人；管理员查询入口是 EffectivePermissions/
		// PermissionSources，避免把业务检查接口变成他人权限探测接口。
		return CheckResult{}, fmt.Errorf("%w: 普通用户只能检查自己的权限", ErrAccessDenied)
	}
	result := CheckResult{SubjectUserID: subject, Scope: scope, Mode: mode}
	snapshotErr := s.store.Snapshot(ctx, func(snapshotCtx context.Context, reader Reader) error {
		state, denied, loadErr := s.loadState(snapshotCtx, reader, subject, scope)
		if loadErr != nil {
			return loadErr
		}
		if denied != nil {
			result.Allowed = false
			result.Code = denied.code
			result.Reason = denied.reason
			return nil
		}
		if caller.actor.Type == audit.ActorUser && caller.actor.ID != subject {
			return ErrAccessDenied
		}
		decisions := make([]PermissionDecision, 0, len(keys))
		for _, key := range keys {
			decision, checkErr := s.evaluatePermission(snapshotCtx, reader, state, key)
			if checkErr != nil {
				return checkErr
			}
			decisions = append(decisions, decision)
		}
		result.Permissions = decisions
		applyOverallResult(&result, decisions, mode)
		return nil
	})
	if snapshotErr != nil {
		if errors.Is(snapshotErr, context.Canceled) || errors.Is(snapshotErr, context.DeadlineExceeded) {
			return CheckResult{}, snapshotErr
		}
		if errors.Is(snapshotErr, ErrAccessDenied) {
			return CheckResult{}, snapshotErr
		}
		// 依赖不可用：默认拒绝，返回稳定 AUTHZ_UNAVAILABLE；不把外部错误细节写入
		// 调用者可展示的 reason。
		s.logger.Warn("权限计算依赖不可用")
		result.Allowed = false
		result.Code = CodeAuthzUnavailable
		result.Reason = "authz_unavailable"
		result.Permissions = nil
		return result, nil
	}
	return result, nil
}

// applyOverallResult 根据 all/any 规则计算整体结果。未知/停用/root_only 权限在
// any 模式下也按硬拒绝优先，避免用“另一个允许的权限”掩盖不可用权限。
func applyOverallResult(result *CheckResult, decisions []PermissionDecision, mode Mode) {
	if len(decisions) == 0 {
		result.Allowed = false
		result.Code = CodePermissionRequired
		result.Reason = "no_permission_required"
		return
	}
	for _, decision := range decisions {
		if decision.SourceLimitReached {
			// 任一权限来源不完整时整体拒绝，不因 any 中其他权限满足而放行。
			result.Allowed = false
			result.Code = CodeAuthzUnavailable
			result.Reason = "source_limit_reached"
			result.SourceLimitReached = true
			return
		}
	}
	allowedCount := 0
	for _, decision := range decisions {
		if decision.Allowed {
			allowedCount++
			continue
		}
	}
	if mode == ModeAll {
		for _, decision := range decisions {
			if decision.Allowed {
				continue
			}
			result.Allowed = false
			result.Code = decision.Code
			result.Reason = decision.Reason
			return
		}
		result.Allowed = true
		return
	}
	// any：未知权限按硬拒绝（显式要求），其余未满足项不阻止其他权限生效。
	for _, decision := range decisions {
		if decision.Allowed {
			continue
		}
		if decision.Code == CodePermissionUnknown {
			result.Allowed = false
			result.Code = decision.Code
			result.Reason = decision.Reason
			return
		}
	}
	if allowedCount > 0 {
		result.Allowed = true
		return
	}
	for _, decision := range decisions {
		if !decision.Allowed {
			result.Allowed = false
			result.Code = decision.Code
			result.Reason = decision.Reason
			return
		}
	}
	result.Allowed = false
	result.Code = CodePermissionRequired
	result.Reason = "permission_not_granted"
}

// evaluatePermission 在快照内判定单个权限。
func (s *Service) evaluatePermission(ctx context.Context, reader Reader, state subjectState, key string) (PermissionDecision, error) {
	decision := PermissionDecision{Key: key, Allowed: false}
	info, found, err := reader.Permission(ctx, state.scope.ID, key)
	if err != nil {
		return PermissionDecision{}, err
	}
	if !found {
		decision.Code = CodePermissionUnknown
		decision.Reason = "permission_unknown"
		return decision, nil
	}
	if info.RootOnly {
		decision.Code = CodeAccessDenied
		decision.Reason = "root_only_permission"
		return decision, nil
	}
	if !info.Enabled {
		decision.Code = CodePermissionDisabled
		decision.Reason = "permission_disabled"
		return decision, nil
	}
	sources, sourcesTruncated, err := reader.PermissionSources(ctx, state.scope.ID, state.account.UserID, []string{info.PermissionID}, MaxSourceRows, 0)
	if err != nil {
		return PermissionDecision{}, err
	}
	if sourcesTruncated {
		// 候选来源超过单次上限：无法证明数据范围交集完整，整体 fail-closed。
		// 即使已读到的来源都允许某个资源，也不能据此放行。
		decision.SourceLimitReached = true
		decision.Code = CodeAuthzUnavailable
		decision.Reason = "source_limit_reached"
		return decision, nil
	}
	summaries, grantedScopes, allowed := s.evaluateSources(state, sources)
	decision.Sources = summaries
	decision.DataScope = intersectDataScopes(grantedScopes)
	if !allowed {
		decision.Code = CodePermissionRequired
		decision.Reason = "permission_not_granted"
		return decision, nil
	}
	decision.Allowed = true
	return decision, nil
}

// evaluateSources 对候选来源逐项判定并返回包含项的脱敏说明与数据范围。
func (s *Service) evaluateSources(state subjectState, sources []GrantSource) ([]SourceSummary, []DataScope, bool) {
	summaries := make([]SourceSummary, 0, len(sources))
	grantedScopes := make([]DataScope, 0, len(sources))
	allowed := false
	for _, source := range sources {
		summary, included := s.evaluateSource(state, source)
		summaries = append(summaries, summary)
		if !included {
			continue
		}
		allowed = true
		grantedScopes = append(grantedScopes, summary.DataScope)
	}
	return summaries, grantedScopes, allowed
}

// evaluateSource 判定单个来源是否生效，并给出排除原因与脱敏数据范围。
func (s *Service) evaluateSource(state subjectState, source GrantSource) (SourceSummary, bool) {
	summary := SourceSummary{
		Kind:   source.Kind,
		RoleID: source.RoleID, RoleKey: source.RoleKey, RoleName: source.RoleName,
		RoleEnabled: source.RoleEnabled,
		GroupID:     source.GroupID, GroupKey: source.GroupKey, GroupName: source.GroupName,
		PermissionID: source.PermissionID, PermissionKey: source.PermissionKey,
		PermissionName: source.PermissionName, PermissionEnabled: source.PermissionEnabled,
		RootOnly: source.PermissionRootOnly, AssignedBy: source.AssignedBy,
		CreatedAt: source.CreatedAt,
	}
	scope, scopeErr := ParseDataScope(source.DataScopeJSON)
	if scopeErr != nil {
		summary.DataScope = DataScope{Mode: DataScopeUndefined, LegacyUndefined: true}
		summary.Included = false
		summary.ExcludedReason = "data_scope_invalid"
		return summary, false
	}
	summary.DataScope = scope
	switch {
	case !source.RoleEnabled:
		summary.ExcludedReason = "role_disabled"
	case !source.PermissionEnabled:
		summary.ExcludedReason = "permission_disabled"
	case source.PermissionRootOnly:
		summary.ExcludedReason = "root_only_permission"
	case state.account.Status != account.StatusActive:
		summary.ExcludedReason = "account_disabled"
	case state.scope.Kind == ScopeKindApplication && state.application.Status != app.StatusActive:
		summary.ExcludedReason = "application_inactive"
	case state.scope.Kind == ScopeKindApplication &&
		(!state.membership.Found || state.membership.Status != app.MembershipActive):
		summary.ExcludedReason = "membership_required"
	}
	if summary.ExcludedReason != "" {
		summary.Included = false
		return summary, false
	}
	summary.Included = true
	return summary, true
}

// loadState 读取账户、应用、成员状态并给出优先级拒绝原因。禁用优先：账户 →
// 应用 → 成员。root 账户在普通引擎中直接拒绝。
func (s *Service) loadState(ctx context.Context, reader Reader, subject string, scope Scope) (subjectState, *denial, error) {
	info, found, err := reader.Account(ctx, subject)
	if err != nil {
		return subjectState{}, nil, err
	}
	if !found {
		return subjectState{}, nil, ErrSubjectNotFound
	}
	state := subjectState{account: info, scope: scope}
	if info.IsRoot {
		return state, &denial{code: CodeAccessDenied, reason: "root_protected"}, nil
	}
	if info.Status != account.StatusActive {
		return state, &denial{code: CodeUserDisabled, reason: "account_inactive"}, nil
	}
	// 账户有效期是计算出的不可用原因：每次授权即时判断，不依赖定时扫描。
	now := s.now().UTC()
	if info.ValidFrom != nil && now.Before(info.ValidFrom.UTC()) {
		return state, &denial{code: CodeUserDisabled, reason: "account_not_yet_valid"}, nil
	}
	if info.ValidUntil != nil && !now.Before(info.ValidUntil.UTC()) {
		return state, &denial{code: CodeUserDisabled, reason: "account_expired"}, nil
	}
	if scope.Kind == ScopeKindSystem {
		return state, nil, nil
	}
	application, appFound, err := reader.Application(ctx, scope.ApplicationID)
	if err != nil {
		return subjectState{}, nil, err
	}
	if !appFound {
		return state, &denial{code: CodeReqInvalid, reason: "application_unknown"}, nil
	}
	state.application = application
	if application.Status != app.StatusActive {
		return state, &denial{code: CodeClientDisabled, reason: "application_inactive"}, nil
	}
	membership, err := reader.Membership(ctx, scope.ApplicationID, subject)
	if err != nil {
		return subjectState{}, nil, err
	}
	state.membership = membership
	if !membership.Found || membership.Status != app.MembershipActive {
		return state, &denial{code: CodeAppMembershipRequired, reason: "membership_required"}, nil
	}
	return state, nil, nil
}

// EffectivePermissions 查询指定主体的有效权限分页，必须通过查询授权。结果包含
// 账户/应用/成员状态、数据范围交集与来源；root 账户不通过普通引擎返回权限。
func (s *Service) EffectivePermissions(ctx context.Context, caller Caller, subjectUserID, scopeID string, options ListOptions) (EffectiveResult, error) {
	ctx = normalizeContext(ctx)
	options, err := normalizeListOptions(options)
	if err != nil {
		return EffectiveResult{}, err
	}
	scope, err := ParseScope(scopeID)
	if err != nil {
		return EffectiveResult{}, err
	}
	subject := stringsTrim(subjectUserID)
	if !account.ValidUserID(subject) {
		return EffectiveResult{}, fmt.Errorf("%w: 被查询用户 ID 格式无效", ErrInvalidRequest)
	}
	if err := s.authorizeQuery(ctx, caller, subject, scope); err != nil {
		return EffectiveResult{}, err
	}
	result := EffectiveResult{SubjectUserID: subject, Scope: scope}
	snapshotErr := s.store.Snapshot(ctx, func(snapshotCtx context.Context, reader Reader) error {
		state, denied, loadErr := s.loadState(snapshotCtx, reader, subject, scope)
		if loadErr != nil {
			return loadErr
		}
		result.AccountStatus = state.account.Status
		result.ApplicationStatus = state.application.Status
		result.MembershipStatus = state.membership.Status
		if caller.actor.Type == audit.ActorUser && caller.actor.ID != subject && scope.Kind == ScopeKindApplication {
			if !state.membership.Found {
				return ErrAccessDenied
			}
		}
		if denied != nil {
			result.DeniedCode = denied.code
			result.DeniedReason = denied.reason
			result.Permissions = []EffectivePermission{}
			return nil
		}
		permissions, hasMore, listErr := reader.GrantedPermissions(snapshotCtx, scope.ID, subject, options.Limit, options.Offset)
		if listErr != nil {
			return listErr
		}
		result.HasMore = hasMore
		if len(permissions) == 0 {
			result.Permissions = []EffectivePermission{}
			return nil
		}
		ids := make([]string, 0, len(permissions))
		for _, permission := range permissions {
			ids = append(ids, permission.PermissionID)
		}
		sources, sourcesTruncated, sourcesErr := reader.PermissionSources(snapshotCtx, scope.ID, subject, ids, MaxSourceRows, 0)
		if sourcesErr != nil {
			return sourcesErr
		}
		if sourcesTruncated {
			// 有效权限列表同样不能基于不完整来源给出数据范围/授权结论。
			result.SourceLimitReached = true
			result.DeniedCode = CodeAuthzUnavailable
			result.DeniedReason = "source_limit_reached"
			result.Permissions = []EffectivePermission{}
			return nil
		}
		sourcesByPermission := make(map[string][]GrantSource, len(ids))
		for _, source := range sources {
			sourcesByPermission[source.PermissionID] = append(sourcesByPermission[source.PermissionID], source)
		}
		effective := make([]EffectivePermission, 0, len(permissions))
		for _, permission := range permissions {
			candidates := sourcesByPermission[permission.PermissionID]
			summaries, grantedScopes, allowed := s.evaluateSources(state, candidates)
			if !allowed {
				continue
			}
			included := make([]SourceSummary, 0, len(summaries))
			for _, summary := range summaries {
				if summary.Included {
					included = append(included, summary)
				}
			}
			effective = append(effective, EffectivePermission{
				Key: permission.Key, Name: permission.Name, ScopeID: permission.ScopeID,
				DataScope: intersectDataScopes(grantedScopes), Sources: included,
			})
		}
		result.Permissions = effective
		return nil
	})
	if snapshotErr != nil {
		if errors.Is(snapshotErr, ErrAccessDenied) || errors.Is(snapshotErr, ErrSubjectNotFound) || errors.Is(snapshotErr, ErrInvalidRequest) {
			return EffectiveResult{}, snapshotErr
		}
		if errors.Is(snapshotErr, context.Canceled) || errors.Is(snapshotErr, context.DeadlineExceeded) {
			return EffectiveResult{}, snapshotErr
		}
		s.logger.Warn("有效权限查询依赖不可用")
		return EffectiveResult{}, fmt.Errorf("%w: %w", ErrStoreUnavailable, snapshotErr)
	}
	return result, nil
}

// PermissionSources 查询指定权限的候选来源，包含被停用/被账户或应用/成员状态限制
// 的来源及排除原因。它不返回未获授权对象：调用者必须先通过查询授权，应用管理员只
// 能查询自己获准应用内成员。
func (s *Service) PermissionSources(ctx context.Context, caller Caller, subjectUserID, scopeID, permissionKey string, options ListOptions) (SourceResult, error) {
	ctx = normalizeContext(ctx)
	options, err := normalizeListOptions(options)
	if err != nil {
		return SourceResult{}, err
	}
	scope, err := ParseScope(scopeID)
	if err != nil {
		return SourceResult{}, err
	}
	subject := stringsTrim(subjectUserID)
	if !account.ValidUserID(subject) {
		return SourceResult{}, fmt.Errorf("%w: 被查询用户 ID 格式无效", ErrInvalidRequest)
	}
	key, err := permission.ValidateKey(permissionKey)
	if err != nil {
		return SourceResult{}, fmt.Errorf("%w: 权限键无效", ErrInvalidRequest)
	}
	if err := s.authorizeQuery(ctx, caller, subject, scope); err != nil {
		return SourceResult{}, err
	}
	result := SourceResult{SubjectUserID: subject, Scope: scope, PermissionKey: key, Sources: []SourceSummary{}}
	snapshotErr := s.store.Snapshot(ctx, func(snapshotCtx context.Context, reader Reader) error {
		state, denied, loadErr := s.loadState(snapshotCtx, reader, subject, scope)
		if loadErr != nil {
			return loadErr
		}
		result.AccountStatus = state.account.Status
		result.ApplicationStatus = state.application.Status
		result.MembershipStatus = state.membership.Status
		if denied != nil && denied.reason == "root_protected" {
			return ErrRootProtected
		}
		if caller.actor.Type == audit.ActorUser && caller.actor.ID != subject && scope.Kind == ScopeKindApplication && !state.membership.Found {
			return ErrAccessDenied
		}
		info, found, permissionErr := reader.Permission(snapshotCtx, scope.ID, key)
		if permissionErr != nil {
			return permissionErr
		}
		if !found {
			result.PermissionFound = false
			return nil
		}
		result.PermissionFound = true
		result.PermissionName = info.Name
		sources, hasMore, sourcesErr := reader.PermissionSources(snapshotCtx, scope.ID, subject,
			[]string{info.PermissionID}, options.Limit+1, options.Offset)
		if sourcesErr != nil {
			return sourcesErr
		}
		if len(sources) > options.Limit {
			hasMore = true
			sources = sources[:options.Limit]
		}
		result.HasMore = hasMore
		summaries := make([]SourceSummary, 0, len(sources))
		for _, source := range sources {
			summary, _ := s.evaluateSource(state, source)
			summaries = append(summaries, summary)
		}
		result.Sources = summaries
		return nil
	})
	if snapshotErr != nil {
		if errors.Is(snapshotErr, ErrAccessDenied) || errors.Is(snapshotErr, ErrRootProtected) ||
			errors.Is(snapshotErr, ErrSubjectNotFound) || errors.Is(snapshotErr, ErrInvalidRequest) {
			return SourceResult{}, snapshotErr
		}
		if errors.Is(snapshotErr, context.Canceled) || errors.Is(snapshotErr, context.DeadlineExceeded) {
			return SourceResult{}, snapshotErr
		}
		s.logger.Warn("权限来源查询依赖不可用")
		return SourceResult{}, fmt.Errorf("%w: %w", ErrStoreUnavailable, snapshotErr)
	}
	return result, nil
}

// CheckResourceAccess 是显式资源级检查接口：先做功能权限检查，再按数据范围交集
// 判断是否允许访问指定资源。业务资源归属不能由权限名推断，调用方必须传入资源标识；
// 数据范围 undefined/none 或资源不在集合内均拒绝。
func (s *Service) CheckResourceAccess(ctx context.Context, caller Caller, subjectUserID, scopeID, permissionKey, resourceID string) (ResourceDecision, error) {
	if err := requireResourceID(resourceID); err != nil {
		return ResourceDecision{}, err
	}
	check, err := s.Check(ctx, caller, CheckRequest{
		SubjectUserID: subjectUserID, ScopeID: scopeID,
		Permissions: []string{permissionKey}, Mode: ModeAll,
	})
	if err != nil {
		return ResourceDecision{}, err
	}
	decision := ResourceDecision{Permission: permissionKey, ResourceID: resourceID}
	if !check.Allowed {
		decision.Allowed = false
		decision.Code = check.Code
		decision.Reason = check.Reason
		return decision, nil
	}
	var dataScope DataScope
	for _, permission := range check.Permissions {
		if permission.Key == permissionKey {
			dataScope = permission.DataScope
			break
		}
	}
	decision.DataScope = dataScope
	switch {
	case dataScope.Empty():
		decision.Allowed = false
		decision.Code = CodeResourceForbidden
		decision.Reason = "data_scope_undefined"
	case dataScope.Mode == DataScopeNone:
		decision.Allowed = false
		decision.Code = CodeResourceForbidden
		decision.Reason = "data_scope_none"
	case !dataScope.AllowsResource(resourceID):
		decision.Allowed = false
		decision.Code = CodeResourceForbidden
		decision.Reason = "resource_not_in_scope"
	default:
		decision.Allowed = true
	}
	return decision, nil
}

// authorizeQuery 统一调用查询授权器；缺少授权时拒绝。
func (s *Service) authorizeQuery(ctx context.Context, caller Caller, subject string, scope Scope) error {
	if err := caller.actor.Validate(); err != nil {
		return fmt.Errorf("%w: 操作者标识无效", ErrAccessDenied)
	}
	if err := s.authorizer.AuthorizeQuery(ctx, caller, subject, scope); err != nil {
		return fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	return nil
}

// normalizeContext 把 nil ctx 当成 Background。
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// stringsTrim 去除首尾空白。
func stringsTrim(value string) string {
	return strings.TrimSpace(value)
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
