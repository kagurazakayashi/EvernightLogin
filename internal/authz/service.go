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
	// ScopePermissions 返回作用范围内的权限目录页（含 enabled=false 行，不要求
	// 主体获得角色），按 permission_key、权限 ID 稳定排序；供 root 的「全权限」
	// 有效权限列表合并分页使用。是否纳入由授权引擎按 enabled/实现状态判定。
	ScopePermissions(ctx context.Context, scopeID string, limit, offset int) ([]PermissionInfo, bool, error)
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
	// Catalog 是权限目录「是否已实现」的只读视图（步骤 252）。非 root 判定不需要它；
	// root 判定必须用它排除未实现权限，未装配时 root 判定 fail-closed。生产装配必须
	// 注入；nil 只用于不涉及 root 的测试/示例。
	Catalog PermissionCatalog
}

// Service 是有效权限计算引擎；构造后不可变，可并发使用，不启动后台协程。
type Service struct {
	store      Store
	authorizer Authorizer
	logger     *slog.Logger
	now        func() time.Time
	catalog    PermissionCatalog
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
		now: now, catalog: options.Catalog}, nil
}

// subjectState 是同一快照内的主体状态。
type subjectState struct {
	account     AccountInfo
	application ApplicationInfo
	membership  MembershipInfo
	scope       Scope
	// isRoot 表示主体是真实 root；root 不依赖角色分配，权限由内核按目录推导。
	isRoot bool
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
	result := CheckResult{SubjectUserID: subject, Scope: scope, Mode: mode}
	snapshotErr := s.store.Snapshot(ctx, func(snapshotCtx context.Context, reader Reader) error {
		state, denied, loadErr := s.loadState(snapshotCtx, reader, subject, scope)
		if loadErr != nil {
			return loadErr
		}
		// 普通用户只能检查自己；真实 root 作为可信管理主体可在快照内独立复核后
		// 检查他人（不信任可插拔 Authorizer 的单点结论）。
		if err := authorizeUserCrossQuery(snapshotCtx, reader, caller, subject); err != nil {
			return err
		}
		if denied != nil {
			result.Allowed = false
			result.Code = denied.code
			result.Reason = denied.reason
			return nil
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
		if state.isRoot {
			// root 全权限：数据库尚未登记的内置权限按只读目录的实现状态判定
			//（新库/未执行预设安装时 root 仍可管理；DB 有记录时以 DB 启停为准）。
			return s.evaluateRootCatalogPermission(key), nil
		}
		decision.Code = CodePermissionUnknown
		decision.Reason = "permission_unknown"
		return decision, nil
	}
	if state.isRoot {
		// root 全权限：目录登记 + 已启用 + 已实现才允许；root_only 属于 root 通道。
		return s.evaluateRootPermission(info), nil
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
// 应用 → 成员。root 账户不走普通角色/成员推导，但仍要求账户 active 与作用范围
// 真实有效（应用必须存在且 active），并忽略普通账户期限限制。
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
		state.isRoot = true
		if info.Status != account.StatusActive {
			return state, &denial{code: CodeUserDisabled, reason: "account_inactive"}, nil
		}
		// root 不受普通账户期限管理锁死（与 account.User.AvailabilityAt 的 root 语义
		// 一致）：有效期字段对 root 不参与拒绝判断。
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
		// root 不要求应用成员关系：root 管理所有有效范围。
		return state, nil, nil
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

// evaluateRootPermission 按 root「全权限受保护主体」语义判定单个数据库已登记权限：
//   - enabled=false：显式停用优先，拒绝（root 也不绕过功能关停）；
//   - 只读目录登记为未实现：拒绝（不把 root 全权限实现为一律放行）；
//   - 目录未登记（宿主自定义权限）：按已实现处理；
//   - root_only 权限属于 root 专属通道，允许；
//   - 未装配实现目录：fail-closed（AUTHZ_UNAVAILABLE），不猜测为已实现。
func (s *Service) evaluateRootPermission(info PermissionInfo) PermissionDecision {
	decision := PermissionDecision{Key: info.Key, Allowed: false,
		DataScope: DataScope{Mode: DataScopeAll}}
	source := rootSourceSummary(info)
	if !info.Enabled {
		decision.Code = CodePermissionDisabled
		decision.Reason = "permission_disabled"
		source.ExcludedReason = "permission_disabled"
		decision.Sources = []SourceSummary{source}
		return decision
	}
	if s == nil || s.catalog == nil {
		decision.Code = CodeAuthzUnavailable
		decision.Reason = "implementation_catalog_unavailable"
		source.ExcludedReason = "implementation_catalog_unavailable"
		decision.Sources = []SourceSummary{source}
		return decision
	}
	if implemented, known := s.catalog.IsImplemented(info.Key); known && !implemented {
		// 目录登记但业务执行路径尚未实现：不能把 root 全权限实现为一律放行。
		decision.Code = CodeAccessDenied
		decision.Reason = "permission_not_implemented"
		source.ExcludedReason = "permission_not_implemented"
		decision.Sources = []SourceSummary{source}
		return decision
	}
	decision.Allowed = true
	source.Included = true
	decision.Sources = []SourceSummary{source}
	return decision
}

// evaluateRootCatalogPermission 判定数据库尚未登记、但只读目录已登记实现的权限：
// 新库/尚未执行预设安装时 root 仍能立即管理（目录是内置权限的权威定义）；显式停用
// 只能通过数据库记录表达（存在记录时走 evaluateRootPermission）。未知权限与目录
// 未实现权限仍拒绝，未装配目录时 fail-closed。
func (s *Service) evaluateRootCatalogPermission(key string) PermissionDecision {
	decision := PermissionDecision{Key: key, Allowed: false,
		DataScope: DataScope{Mode: DataScopeAll}}
	if s == nil || s.catalog == nil {
		decision.Code = CodeAuthzUnavailable
		decision.Reason = "implementation_catalog_unavailable"
		return decision
	}
	if entry, ok := s.catalog.ImplementedPermission(key); ok {
		decision.Allowed = true
		decision.Sources = []SourceSummary{rootCatalogSourceSummary(entry)}
		return decision
	}
	if implemented, known := s.catalog.IsImplemented(key); known && !implemented {
		decision.Code = CodeAccessDenied
		decision.Reason = "permission_not_implemented"
		return decision
	}
	decision.Code = CodePermissionUnknown
	decision.Reason = "permission_unknown"
	return decision
}

// rootSourceSummary 构造数据库权限快照的 root 来源说明：它不是角色分配，也不能被
// 当成普通用户权限来源；DataScope 固定为 all（root 管理所有有效数据范围）。
func rootSourceSummary(info PermissionInfo) SourceSummary {
	return SourceSummary{Kind: SourceKindRoot, PermissionID: info.PermissionID,
		PermissionKey: info.Key, PermissionName: info.Name,
		PermissionEnabled: info.Enabled, RootOnly: info.RootOnly,
		DataScope: DataScope{Mode: DataScopeAll}}
}

// rootCatalogSourceSummary 构造只读目录权限定义的 root 来源说明（数据库未落地行）。
func rootCatalogSourceSummary(entry CatalogPermission) SourceSummary {
	return SourceSummary{Kind: SourceKindRoot, PermissionKey: entry.Key,
		PermissionName: entry.Name, RootOnly: entry.RootOnly,
		DataScope: DataScope{Mode: DataScopeAll}, Included: true}
}

// rootDBPermissionUsable 报告 root 在数据库已登记权限行上是否可用：显式停用优先，
// 目录登记未实现拒绝，目录未登记（自定义权限）按已实现。未装配目录时不可用。
func (s *Service) rootDBPermissionUsable(info PermissionInfo) bool {
	if !info.Enabled {
		return false
	}
	if s == nil || s.catalog == nil {
		return false
	}
	if implemented, known := s.catalog.IsImplemented(info.Key); known && !implemented {
		return false
	}
	return true
}

// callerIsRealRoot 在同一快照内核对用户调用者是否为真实 root（以账户 is_root 与
// active 状态为准，不接受调用方自报的身份字段）。系统/本地调用者返回 false。
func callerIsRealRoot(ctx context.Context, reader Reader, caller Caller) (bool, error) {
	if caller.actor.Type != audit.ActorUser {
		return false, nil
	}
	info, found, err := reader.Account(ctx, caller.actor.ID)
	if err != nil {
		return false, err
	}
	if !found || !info.IsRoot || info.Status != account.StatusActive {
		return false, nil
	}
	return true, nil
}

// authorizeUserCrossQuery 是 Check 的跨主体查询兜底：普通用户只能检查自己；真实
// root 作为可信管理主体可在快照内复核后检查他人。生产 Authorizer 已先行判定，
// 这里防止自定义/错误装配的 Authorizer 把普通用户放行成管理查询。
func authorizeUserCrossQuery(ctx context.Context, reader Reader, caller Caller, subject string) error {
	if caller.actor.Type != audit.ActorUser || caller.actor.ID == subject {
		return nil
	}
	root, err := callerIsRealRoot(ctx, reader, caller)
	if err != nil {
		return err
	}
	if !root {
		return fmt.Errorf("%w: 普通用户只能查询自己的权限", ErrAccessDenied)
	}
	return nil
}

// rootEffectivePermissions 返回 root 在作用范围内的有效权限页：合并「数据库已登记
// 且可用权限」与「只读目录已实现但数据库尚未登记的内置权限」，来源全部标记 root；
// 同一权限键以数据库启停/实现状态为准（显式停用不会被目录默认复活）。分页在合并
// 顺序上稳定（permission_key、权限 ID），数据库目录扫描超过 MaxPermissionDirectoryRows
// 时 fail-closed，不返回截断伪造的分页。未装配实现目录时 fail-closed。
func (s *Service) rootEffectivePermissions(ctx context.Context, reader Reader,
	state subjectState, options ListOptions, result *EffectiveResult) error {
	if s == nil || s.catalog == nil {
		result.DeniedCode = CodeAuthzUnavailable
		result.DeniedReason = "implementation_catalog_unavailable"
		result.Permissions = []EffectivePermission{}
		return nil
	}
	catalogPermissions := s.catalog.ImplementedPermissions()
	const dbPageSize = 64
	var dbRows []PermissionInfo
	dbOffset := 0
	dbDone := false
	dbScanned := 0
	catalogIndex := 0
	globalIndex := 0
	effective := make([]EffectivePermission, 0, options.Limit)
	hasMore := false
	for {
		if !dbDone && len(dbRows) == 0 {
			page, pageHasMore, err := reader.ScopePermissions(ctx, state.scope.ID,
				dbPageSize, dbOffset)
			if err != nil {
				return err
			}
			dbRows = page
			dbOffset += len(page)
			dbDone = !pageHasMore
		}
		haveDB := len(dbRows) > 0
		haveCatalog := catalogIndex < len(catalogPermissions)
		if !haveDB && !haveCatalog {
			break
		}
		var (
			item    EffectivePermission
			include bool
		)
		dbKey := ""
		if haveDB {
			dbKey = dbRows[0].Key
		}
		catalogKey := ""
		if haveCatalog {
			catalogKey = catalogPermissions[catalogIndex].Key
		}
		switch {
		case haveDB && haveCatalog && dbKey == catalogKey:
			// 数据库有记录：以数据库启停/实现状态为准，目录默认项被覆盖。
			row := dbRows[0]
			dbRows = dbRows[1:]
			dbScanned++
			catalogIndex++
			include = s.rootDBPermissionUsable(row)
			if include {
				item = rootEffectiveFromDB(row)
			}
		case haveDB && (!haveCatalog || dbKey < catalogKey):
			row := dbRows[0]
			dbRows = dbRows[1:]
			dbScanned++
			include = s.rootDBPermissionUsable(row)
			if include {
				item = rootEffectiveFromDB(row)
			}
		default:
			entry := catalogPermissions[catalogIndex]
			catalogIndex++
			include = true
			item = EffectivePermission{Key: entry.Key, Name: entry.Name,
				ScopeID: state.scope.ID, DataScope: DataScope{Mode: DataScopeAll},
				Sources: []SourceSummary{rootCatalogSourceSummary(entry)}}
		}
		if dbScanned > MaxPermissionDirectoryRows {
			result.DeniedCode = CodeAuthzUnavailable
			result.DeniedReason = "permission_directory_too_large"
			result.Permissions = []EffectivePermission{}
			result.HasMore = false
			return nil
		}
		if !include {
			continue
		}
		if globalIndex < options.Offset {
			globalIndex++
			continue
		}
		globalIndex++
		if len(effective) >= options.Limit {
			hasMore = true
			break
		}
		effective = append(effective, item)
	}
	result.HasMore = hasMore
	result.Permissions = effective
	return nil
}

// rootEffectiveFromDB 把数据库权限行转换为 root 有效权限条目。
func rootEffectiveFromDB(info PermissionInfo) EffectivePermission {
	source := rootSourceSummary(info)
	source.Included = true
	return EffectivePermission{Key: info.Key, Name: info.Name, ScopeID: info.ScopeID,
		DataScope: DataScope{Mode: DataScopeAll}, Sources: []SourceSummary{source}}
}

// EffectivePermissions 查询指定主体的有效权限分页，必须通过查询授权。结果包含
// 账户/应用/成员状态、数据范围交集与来源；root 账户返回目录中全部已启用且已实现
// 权限（来源 root），不依赖角色分配。
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
		// root 作为可信调用者可查询他人；普通用户的跨主体查询仍由 Authorizer 把关，
		// 应用范围下额外拒绝非成员目标，避免把查询接口变成成员存在性探测。
		rootCaller := false
		if caller.actor.Type == audit.ActorUser && caller.actor.ID != subject {
			rootCaller, err = callerIsRealRoot(snapshotCtx, reader, caller)
			if err != nil {
				return err
			}
		}
		if caller.actor.Type == audit.ActorUser && caller.actor.ID != subject && !rootCaller &&
			scope.Kind == ScopeKindApplication {
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
		if state.isRoot {
			return s.rootEffectivePermissions(snapshotCtx, reader, state, options, &result)
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

// rootPermissionSources 返回 root 主体指定权限的目录来源说明：真实 root 的权限
// 来源就是 root 本身（不是角色/组），并逐项给出停用、未实现或账户/应用状态导致
// 不可用的原因；调用方据此准确展示，不伪造普通角色来源。
func (s *Service) rootPermissionSources(ctx context.Context, reader Reader,
	state subjectState, key string, options ListOptions, denied *denial,
	result *SourceResult) error {
	info, found, err := reader.Permission(ctx, state.scope.ID, key)
	if err != nil {
		return err
	}
	if !found {
		// 数据库未登记时 root 仍可从只读目录说明内置权限来源（新库/未安装预设）。
		return s.rootCatalogPermissionSources(key, options, denied, result)
	}
	result.PermissionFound = true
	result.PermissionName = info.Name
	source := rootSourceSummary(info)
	switch {
	case denied != nil:
		source.ExcludedReason = denied.reason
	case !info.Enabled:
		source.ExcludedReason = "permission_disabled"
	case s == nil || s.catalog == nil:
		source.ExcludedReason = "implementation_catalog_unavailable"
	default:
		if implemented, known := s.catalog.IsImplemented(info.Key); known && !implemented {
			source.ExcludedReason = "permission_not_implemented"
		} else {
			source.Included = true
		}
	}
	result.Sources = []SourceSummary{source}
	if options.Limit <= 0 {
		options.Limit = DefaultListLimit
	}
	if len(result.Sources) > options.Limit {
		result.HasMore = true
		result.Sources = result.Sources[:options.Limit]
	}
	return nil
}

// rootCatalogPermissionSources 返回数据库未登记、但只读目录登记的内置权限的 root
// 来源说明；目录未登记（未知自定义键）时 PermissionFound=false。未装配目录时按
// 无法证明处理（PermissionFound=false），不伪造来源。
func (s *Service) rootCatalogPermissionSources(key string, options ListOptions,
	denied *denial, result *SourceResult) error {
	if s == nil || s.catalog == nil {
		result.PermissionFound = false
		return nil
	}
	limit := options.Limit
	if limit <= 0 {
		limit = DefaultListLimit
	}
	if entry, ok := s.catalog.ImplementedPermission(key); ok {
		result.PermissionFound = true
		result.PermissionName = entry.Name
		source := rootCatalogSourceSummary(entry)
		if denied != nil {
			source.Included = false
			source.ExcludedReason = denied.reason
		}
		result.Sources = []SourceSummary{source}
		if len(result.Sources) > limit {
			result.HasMore = true
			result.Sources = result.Sources[:limit]
		}
		return nil
	}
	if implemented, known := s.catalog.IsImplemented(key); known && !implemented {
		result.PermissionFound = true
		result.Sources = []SourceSummary{{Kind: SourceKindRoot, PermissionKey: key,
			DataScope:      DataScope{Mode: DataScopeAll},
			ExcludedReason: "permission_not_implemented"}}
		if len(result.Sources) > limit {
			result.HasMore = true
			result.Sources = result.Sources[:limit]
		}
		return nil
	}
	result.PermissionFound = false
	return nil
}

// PermissionSources 查询指定权限的候选来源，包含被停用/被账户或应用/成员状态限制
// 的来源及排除原因。它不返回未获授权对象：调用者必须先通过查询授权，应用管理员只
// 能查询自己获准应用内成员；root 主体返回 root 来源说明。
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
		rootCaller := false
		if caller.actor.Type == audit.ActorUser && caller.actor.ID != subject {
			var rootErr error
			rootCaller, rootErr = callerIsRealRoot(snapshotCtx, reader, caller)
			if rootErr != nil {
				return rootErr
			}
			if !rootCaller && scope.Kind == ScopeKindApplication && !state.membership.Found {
				return ErrAccessDenied
			}
		}
		if state.isRoot {
			return s.rootPermissionSources(snapshotCtx, reader, state, key, options,
				denied, &result)
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
		if errors.Is(snapshotErr, ErrAccessDenied) ||
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
