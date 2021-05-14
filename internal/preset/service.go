package preset

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
)

// 预设动作标识（写入安全审计）。
const (
	ActionInstall       = "preset.install"
	ActionPreview       = "preset.preview"
	ActionRestore       = "preset.restore"
	actionInstallFail   = "preset.install_failed"
	actionPreviewFail   = "preset.preview_failed"
	actionRestoreFail   = "preset.restore_failed"
	maxAuditDetailBytes = 4096
)

// InstallRequest 是初始化/升级请求：ScopeID 是 "system" 或应用 ID。空值默认系统
// 范围（首次初始化最常见用法）；应用模板必须显式传应用 ID。
type InstallRequest struct {
	ScopeID string
}

// InstallResult 是一次初始化/升级的真实结果。本包不虚构成功：创建数量来自实际
// 写入，待恢复提示来自逐项比对。
type InstallResult struct {
	ScopeID                    string
	ScopeKind                  ScopeKind
	CatalogVersion             string
	PreviousVersion            string
	Initialized                bool
	Upgraded                   bool
	UpToDate                   bool
	CreatedPermissions         []string
	CreatedRoles               []string
	CreatedGroups              []string
	DeferredRolePermissionAdds []string
	Changed                    bool
}

// RoleSelection 是恢复默认的明确选择：某个作用范围内要恢复的角色机器标识。
type RoleSelection struct {
	ScopeID  string
	RoleKeys []string
}

// PreviewRequest 是差异预览请求：要么显式选择角色（Selections），要么显式整体
// 恢复（All=true），二者不能同时为空或同时给出。
type PreviewRequest struct {
	Selections []RoleSelection
	All        bool
}

// PermissionChange 是差异中的权限条目（使用权限机器标识与中文名称）。
type PermissionChange struct {
	Key  string
	Name string
}

// RoleDiff 是角色维度的差异：缺失/需新增/需移除的权限组合与是否受核心保护。
type RoleDiff struct {
	ScopeID           string
	RoleKey           string
	Name              string
	RoleID            string
	Exists            bool
	Protected         bool
	Unchanged         bool
	AddPermissions    []PermissionChange
	RemovePermissions []PermissionChange
}

// GroupChange 是差异中的用户组条目。
type GroupChange struct {
	Key  string
	Name string
}

// ScopeDiff 是一个作用范围的差异摘要。
type ScopeDiff struct {
	ScopeID               string
	ScopeKind             ScopeKind
	CatalogVersion        string
	Installed             bool
	InstalledVersion      string
	MissingPermissions    []PermissionChange
	UpdatePermissionTexts []PermissionChange
	ReenablePermissions   []PermissionChange
	// SkippedRootOnlyReenables 列出因调用者不是系统通道而未重新启用的 root_only
	// 预设权限；它们保持停用，必须由 root 通过本地应急流程显式恢复，避免恢复
	// 默认逆转 root 有意的停用。
	SkippedRootOnlyReenables []PermissionChange
	MissingRoles             []PermissionChange
	MissingGroups            []GroupChange
	RoleDiffs                []RoleDiff
}

// DiffSummary 是差异汇总计数，供页面展示与审计。
type DiffSummary struct {
	CreatePermissions     int
	UpdatePermissionTexts int
	ReenablePermissions   int
	// SkippedRootOnlyReenables 是因通道限制被跳过的 root_only 重新启用数（不写入）。
	SkippedRootOnlyReenables int
	CreateRoles              int
	CreateGroups             int
	AddRolePermissions       int
	RemoveRolePermissions    int
	UnchangedRoles           int
	ProtectedRoles           int
}

// TotalChanges 返回会实际写入的条目总数（不含未变化项）。
func (s DiffSummary) TotalChanges() int {
	return s.CreatePermissions + s.UpdatePermissionTexts + s.ReenablePermissions +
		s.CreateRoles + s.CreateGroups + s.AddRolePermissions + s.RemoveRolePermissions
}

// SkippedScope 是整体恢复时被跳过的作用范围及其原因（当前只有应用已停用一种：
// 停用应用不得借恢复重新启用或改写其预设，避免把停用状态绕过）。
type SkippedScope struct {
	ScopeID string
	Reason  string
}

// Preview 是差异预览结果。Token 是服务端签发、绑定操作者与状态摘要、短时有效且
// 单次使用的确认令牌；Restore 只接受它，客户端布尔值不能冒充“已展示差异并再次
// 授权”。Selections 是实际将被恢复的具体选择（All 已在服务端展开）。
type Preview struct {
	Token          string
	CatalogVersion string
	GeneratedAt    time.Time
	ExpiresAt      time.Time
	Digest         string
	All            bool
	Selections     []RoleSelection
	SkippedScopes  []SkippedScope
	Scopes         []ScopeDiff
	Summary        DiffSummary
}

// RestoreRequest 是恢复默认请求：只接受 Preview 返回的确认令牌。
type RestoreRequest struct {
	Token string
}

// RestoreResult 是恢复默认的实际结果。
type RestoreResult struct {
	CatalogVersion string
	Digest         string
	All            bool
	Selections     []RoleSelection
	SkippedScopes  []SkippedScope
	Scopes         []ScopeDiff
	Summary        DiffSummary
}

// New 校验依赖并构造预设服务；缺少 Store/Audit/Transfers 返回 ErrOptionsInvalid，
// 不放行任何请求。目录默认使用 DefaultCatalog，可注入自定义目录用于升级测试。
func New(options Options) (*Service, error) {
	if isNil(options.Store) {
		return nil, fmt.Errorf("%w: 预设存储为空", ErrOptionsInvalid)
	}
	if isNil(options.Audit) {
		return nil, fmt.Errorf("%w: 审计写入器为空", ErrOptionsInvalid)
	}
	if isNil(options.Transfers) {
		return nil, fmt.Errorf("%w: 委派检查器为空（预设恢复必须接入同一 Guard）", ErrOptionsInvalid)
	}
	catalog := options.Catalog
	if catalog == nil {
		catalog = DefaultCatalog()
	}
	if err := catalog.Validate(); err != nil {
		return nil, err
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
	previewTTL := options.PreviewTTL
	if previewTTL == 0 {
		previewTTL = DefaultPreviewTTL
	}
	if previewTTL < MinPreviewTTL || previewTTL > MaxPreviewTTL {
		return nil, fmt.Errorf("%w: 预览令牌有效期必须在 %s～%s 之间", ErrOptionsInvalid, MinPreviewTTL, MaxPreviewTTL)
	}
	return &Service{
		store: options.Store, audit: options.Audit, transfers: options.Transfers,
		catalog: catalog, now: now, random: random, logger: logger,
		previewTTL: previewTTL, previewTokens: make(map[string]previewToken),
	}, nil
}

// Catalog 返回服务使用的预设目录副本（含版本与全部机器可读定义）。
func (s *Service) Catalog() *Catalog {
	if s == nil || s.catalog == nil {
		return nil
	}
	copyCatalog := *s.catalog
	copyCatalog.Permissions = append([]PermissionDefinition(nil), s.catalog.Permissions...)
	copyCatalog.Roles = append([]RoleTemplate(nil), s.catalog.Roles...)
	copyCatalog.Groups = append([]GroupTemplate(nil), s.catalog.Groups...)
	copyCatalog.ApplicationRoles = append([]RoleTemplate(nil), s.catalog.ApplicationRoles...)
	copyCatalog.ApplicationGroups = append([]GroupTemplate(nil), s.catalog.ApplicationGroups...)
	return &copyCatalog
}

// Install 幂等初始化/升级一个作用范围的预设目录。
//
// 系统范围登记全部预设权限、五个系统角色、默认用户组，并为“本次新建”的角色组合
// 默认权限；应用范围按应用创建模板生成该应用自己的角色与用户组（不共用跨应用
// 记录，也不创建任何权限）。规则：
//   - 已存在的目录项一律不改写；已有角色的权限组合保持不变（升级不覆盖用户调整），
//     缺失的默认权限只写入 DeferredRolePermissionAdds 提示，由显式恢复处理。
//   - 已存在的预设权限只同步中文名称/说明/范围/限制（需求允许随版本修正文案，不得
//     借修正扩大权限）；root_only/is_builtin 语义不一致时返回 ErrCatalogConflict。
//   - 已安装版本高于当前目录时返回 ErrCatalogDowngrade，拒绝旧程序覆盖新预设。
//   - 不创建账户、不做角色分配、不改变任何账户状态；初始化后可重复执行。
func (s *Service) Install(ctx context.Context, caller Caller, request InstallRequest) (InstallResult, error) {
	if err := requireTrusted(caller); err != nil {
		return InstallResult{}, err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return InstallResult{}, err
	}
	scopeID, err := normalizeScopeID(request.ScopeID)
	if err != nil {
		return InstallResult{}, err
	}
	plan, err := s.buildInstallPlan(ctx, scopeID)
	if err != nil {
		return InstallResult{}, err
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	result := InstallResult{
		ScopeID: plan.scope.ScopeID, ScopeKind: plan.scope.Kind,
		CatalogVersion: s.catalog.Version, PreviousVersion: plan.state.CatalogVersion,
		Initialized: !plan.installed, Upgraded: plan.installed && plan.state.CatalogVersion != s.catalog.Version,
	}
	for _, item := range plan.newPermissions {
		result.CreatedPermissions = append(result.CreatedPermissions, item.definition.Key)
	}
	for _, item := range plan.newRoles {
		result.CreatedRoles = append(result.CreatedRoles, item.template.Key)
	}
	for _, item := range plan.newGroups {
		result.CreatedGroups = append(result.CreatedGroups, item.template.Key)
	}
	for _, item := range plan.roleDiffs {
		for _, change := range item.add {
			result.DeferredRolePermissionAdds = append(result.DeferredRolePermissionAdds, item.template.Key+":"+change.definition.Key)
		}
	}
	result.UpToDate = plan.state.CatalogVersion == s.catalog.Version && !plan.changes()
	if !plan.changes() && !plan.installed {
		result.UpToDate = false
	}
	event := audit.Event{
		Actor: caller.actor, RequestID: caller.requestID, Action: ActionInstall,
		Target:  audit.Target{Type: "preset_scope", ID: plan.scope.ScopeID},
		AppID:   plan.scope.ApplicationID,
		Changes: installAuditChanges(plan, s.catalog.Version),
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: actionInstallFail,
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	changed := false
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		var changeErr error
		changed, changeErr = s.applyPlan(txCtx, tx, caller.actor, plan, now, installMode)
		return changeErr
	})
	if err != nil {
		return InstallResult{}, mapCriticalError(err)
	}
	result.Changed = changed
	s.logger.Info("预设目录已初始化", "scope_id", plan.scope.ScopeID,
		"catalog_version", s.catalog.Version, "changed", changed)
	return result, nil
}

// InstallApplicationScope 是按应用创建模板生成预设的便捷入口：只接受有效应用 ID
// 且要求应用处于 active 状态；等价于 Install{ScopeID: appID}。应用创建流程成功后
// 应调用它（可重复调用），本包不修改应用模块以避免跨领域事务。
func (s *Service) InstallApplicationScope(ctx context.Context, caller Caller, applicationID string) (InstallResult, error) {
	applicationID = strings.TrimSpace(applicationID)
	kind, _, err := ParseScope(applicationID)
	if err != nil {
		return InstallResult{}, err
	}
	if kind != ScopeKindApplication {
		return InstallResult{}, fmt.Errorf("%w: 应用模板必须指定应用 ID", ErrInvalidRequest)
	}
	return s.Install(ctx, caller, InstallRequest{ScopeID: applicationID})
}

// Preview 读取当前状态并计算差异，签发单次使用的确认令牌供 Restore 使用。预览
// 是恢复的强制前置：未预览或令牌过期/已用/不属于该操作者时 Restore 一律拒绝。
// 预览读取会写安全审计（读取失败则拒绝返回结果）。
func (s *Service) Preview(ctx context.Context, caller Caller, request PreviewRequest) (Preview, error) {
	if err := requireTrusted(caller); err != nil {
		return Preview{}, err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return Preview{}, err
	}
	selections, skipped, err := s.resolveSelections(ctx, request)
	if err != nil {
		return Preview{}, err
	}
	if len(selections) == 0 {
		return Preview{}, fmt.Errorf("%w: 已初始化的应用均处于停用状态，没有可恢复的作用范围", ErrInvalidRequest)
	}
	allowRootOnly := caller.actor.Type == audit.ActorLocalAdmin
	scopeIDs := make([]string, 0, len(selections))
	scopes := make([]ScopeDiff, 0, len(selections))
	for _, selection := range selections {
		plan, planErr := s.buildRestorePlan(ctx, selection.ScopeID, selection.RoleKeys, allowRootOnly)
		if planErr != nil {
			return Preview{}, planErr
		}
		scopeIDs = append(scopeIDs, selection.ScopeID)
		scopes = append(scopes, plan.diff())
	}
	// 记录预览时的目录状态摘要：恢复会在写入事务内重新计算并比对，保证预览后
	// 到写入前发生的并发修改不会用旧计划覆盖新状态。
	fingerprint, err := s.store.SnapshotFingerprint(ctx, scopeIDs)
	if err != nil {
		return Preview{}, fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	preview := Preview{
		CatalogVersion: s.catalog.Version, GeneratedAt: now, ExpiresAt: now.Add(s.previewTTL),
		All: request.All, Selections: selections, SkippedScopes: skipped,
		Scopes: scopes, Summary: summarize(scopes),
	}
	digest, err := previewDigest(preview)
	if err != nil {
		return Preview{}, err
	}
	preview.Digest = digest
	token, err := randHex(s.random, previewTokenBytes)
	if err != nil {
		return Preview{}, fmt.Errorf("%w: 生成预览确认令牌失败: %v", ErrStoreUnavailable, err)
	}
	preview.Token = token

	// 预览读取是敏感查询，写入读取审计；审计不可用时拒绝返回差异，避免出现
	// “看过差异但没有任何记录”的路径。
	event := audit.Event{
		Actor: caller.actor, RequestID: caller.requestID, Action: ActionPreview,
		Outcome: audit.OutcomeSuccess,
		Target:  audit.Target{Type: "preset_scope", ID: selectionsScopeLabel(selections)},
		Changes: []audit.FieldChange{
			{Field: "catalog_version", After: s.catalog.Version},
			{Field: "digest", After: digest},
			{Field: "selection", After: selectionsLabel(selections)},
		},
	}
	if err := s.audit.Record(ctx, event); err != nil {
		return Preview{}, fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	s.previewMu.Lock()
	s.prunePreviewTokensLocked(now)
	s.previewTokens[token] = previewToken{
		actorKey:       actorKey(caller.actor),
		requestID:      caller.requestID,
		catalogVersion: s.catalog.Version,
		digest:         digest,
		fingerprint:    fingerprint,
		selections:     selections,
		skipped:        skipped,
		all:            request.All,
		expiresAt:      preview.ExpiresAt,
	}
	s.previewMu.Unlock()
	return preview, nil
}

// Restore 按预览确认令牌恢复明确选择的目录/角色到预设默认值。整次恢复在一个安全
// 审计事务内完成：任何一步失败（含委派检查拒绝、审计不可用、状态已被并发修改）
// 都会回滚全部业务写入，只保留失败审计。恢复内容：
//   - 补齐缺失的预设权限、角色、默认用户组；
//   - 同步预设权限的中文说明（不改变 root_only/is_builtin 语义）；
//   - 重新启用被停用的预设内置权限（经 CheckPermissionActivation 复核目标）；按
//     internal/permission 的 root_only 规则，仅受限本地受控操作者可重新启用
//     root_only 权限，系统与其他通道一律跳过，避免撤销 root 有意的停用；
//   - 把所选角色的权限组合恢复为默认集合（核心角色跳过；新增权限经
//     CheckPermissionAccess 在同一事务内复核，不能借此扩大操作者可委派范围）；
//   - 自定义角色、自定义权限、自定义组成员一律保留。
//
// 令牌单次使用：无论成功、状态过期还是被拒绝，消费后都必须重新 Preview。事务前
// 的拒绝（令牌缺失/伪造/过期/不属于操作者/摘要过期）同样补写失败审计，不伪造成功
// 审计，保证“预览过期或拒绝”都有可追溯记录。
func (s *Service) Restore(ctx context.Context, caller Caller, request RestoreRequest) (RestoreResult, error) {
	if err := requireTrusted(caller); err != nil {
		return RestoreResult{}, err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return RestoreResult{}, err
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	token := strings.TrimSpace(request.Token)
	if token == "" {
		err := fmt.Errorf("%w: 缺少差异预览确认令牌，必须先预览差异", ErrPreviewRequired)
		s.recordRestoreRejection(ctx, caller, "", "preview_token_missing", err)
		return RestoreResult{}, err
	}
	s.previewMu.Lock()
	record, ok := s.previewTokens[token]
	delete(s.previewTokens, token)
	s.previewMu.Unlock()
	if !ok {
		err := fmt.Errorf("%w: 确认令牌不存在、已使用或已过期", ErrPreviewRequired)
		s.recordRestoreRejection(ctx, caller, "", "preview_token_unknown", err)
		return RestoreResult{}, err
	}
	target := selectionsScopeLabel(record.selections)
	if !now.Before(record.expiresAt) {
		err := fmt.Errorf("%w: 确认令牌已过期，请重新预览差异", ErrPreviewRequired)
		s.recordRestoreRejection(ctx, caller, target, "preview_token_expired", err)
		return RestoreResult{}, err
	}
	if !constantTimeEqual(record.actorKey, actorKey(caller.actor)) {
		err := fmt.Errorf("%w: 确认令牌不属于当前操作者", ErrPreviewRequired)
		s.recordRestoreRejection(ctx, caller, target, "preview_token_other_actor", err)
		return RestoreResult{}, err
	}
	if record.catalogVersion != s.catalog.Version {
		err := fmt.Errorf("%w: 预览时代码版本已变化", ErrPreviewStale)
		s.recordRestoreRejection(ctx, caller, target, "catalog_version_changed", err)
		return RestoreResult{}, err
	}

	// 重新计算差异并与预览摘要比对：状态在预览后被他人修改时拒绝，防止恢复实际
	// 执行的内容与操作者确认的内容不一致。
	allowRootOnly := caller.actor.Type == audit.ActorLocalAdmin
	scopes := make([]ScopeDiff, 0, len(record.selections))
	scopeIDs := make([]string, 0, len(record.selections))
	plans := make([]*scopePlan, 0, len(record.selections))
	for _, selection := range record.selections {
		plan, err := s.buildRestorePlan(ctx, selection.ScopeID, selection.RoleKeys, allowRootOnly)
		if err != nil {
			s.recordRestoreRejection(ctx, caller, target, "replan_failed", err)
			return RestoreResult{}, err
		}
		plans = append(plans, plan)
		scopeIDs = append(scopeIDs, selection.ScopeID)
		scopes = append(scopes, plan.diff())
	}
	current := Preview{CatalogVersion: s.catalog.Version, All: record.all, Selections: record.selections,
		SkippedScopes: record.skipped, Scopes: scopes, Summary: summarize(scopes)}
	digest, err := previewDigest(current)
	if err != nil {
		return RestoreResult{}, err
	}
	if !constantTimeEqual(digest, record.digest) {
		err := fmt.Errorf("%w: 预览后状态已变化，请重新预览差异后再恢复", ErrPreviewStale)
		s.recordRestoreRejection(ctx, caller, target, "preview_digest_stale", err)
		return RestoreResult{}, err
	}

	result := RestoreResult{
		CatalogVersion: s.catalog.Version, Digest: digest, All: record.all,
		Selections: record.selections, SkippedScopes: record.skipped,
		Scopes: scopes, Summary: summarize(scopes),
	}
	event := audit.Event{
		Actor: caller.actor, RequestID: caller.requestID, Action: ActionRestore,
		Target:  audit.Target{Type: "preset_scope", ID: selectionsScopeLabel(record.selections)},
		AppID:   selectionsApplicationID(record.selections),
		Changes: restoreAuditChanges(record, digest, result.Summary),
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: actionRestoreFail,
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		// 事务内条件校验：重算目录状态摘要并与预览时比对。计划读取发生在事务外，
		// 若复核与写入之间有并发修改，这里必须拒绝，绝不能用旧计划覆盖新状态。
		currentFingerprint, fingerprintErr := s.store.SnapshotFingerprintTx(txCtx, tx, scopeIDs)
		if fingerprintErr != nil {
			return fingerprintErr
		}
		if !constantTimeEqual(currentFingerprint, record.fingerprint) {
			return fmt.Errorf("%w: 预览后目录状态已变化，请重新预览差异后再恢复", ErrPreviewStale)
		}
		for _, plan := range plans {
			if _, applyErr := s.applyPlan(txCtx, tx, caller.actor, plan, now, restoreMode); applyErr != nil {
				return applyErr
			}
		}
		return nil
	})
	if err != nil {
		return RestoreResult{}, mapCriticalError(err)
	}
	for _, plan := range plans {
		for _, item := range plan.skippedRootOnly {
			s.logger.Warn("恢复默认未重新启用 root_only 权限",
				"scope_id", plan.scope.ScopeID, "permission", item.definition.Key,
				"reason", "仅受限本地操作者可重新启用 root_only 权限（与 internal/permission 规则一致）")
		}
	}
	s.logger.Info("预设目录已恢复默认", "catalog_version", s.catalog.Version,
		"selections", selectionsLabel(record.selections), "digest", digest,
		"skipped_scopes", len(record.skipped), "root_only_skipped", result.Summary.SkippedRootOnlyReenables)
	return result, nil
}

// recordRestoreRejection 为事务前被拒绝的恢复请求补写失败审计。此时没有任何业务
// 写入，拒绝结果不受审计写入成功与否影响；审计失败只记录运行日志告警，绝不把拒绝
// 伪装成成功。target 可为空（例如令牌不存在，尚不知道选择范围）。
func (s *Service) recordRestoreRejection(ctx context.Context, caller Caller, target, reason string, cause error) {
	event := audit.Event{
		Actor: caller.actor, RequestID: caller.requestID, Action: actionRestoreFail,
		Outcome:   audit.OutcomeFailure,
		Target:    audit.Target{Type: "preset_scope", ID: target},
		ErrorCode: string(CodeOf(cause)), ReasonCode: reason,
	}
	if err := s.audit.Record(ctx, event); err != nil {
		s.logger.Warn("恢复拒绝的失败审计写入失败", "reason", reason, "error", err)
	}
}

// installMode/restoreMode 区分初始化（只补缺失项）与恢复默认（重置所选角色组合）。
type planMode int

const (
	installMode planMode = iota
	restoreMode
)

// plannedPermission 是计划中的权限条目：definition 是目录定义，record 是已存在或
// 待创建权限（ID 已确定），用于委派检查与写入。
type plannedPermission struct {
	definition PermissionDefinition
	record     PermissionRecord
	existing   bool
	textDirty  bool
	reenable   bool
}

// rolePlan 是单个预设角色的计划。
type rolePlan struct {
	template  RoleTemplate
	record    RoleRecord
	existing  bool
	unchanged bool
	protected bool
	add       []plannedPermission
	remove    []RolePermissionRecord
}

// groupPlan 是待创建用户组的计划。
type groupPlan struct {
	template GroupTemplate
	record   GroupRecord
}

// scopePlan 是一个作用范围的初始化/恢复计划。
type scopePlan struct {
	scope            ScopeInfo
	state            InstallState
	installed        bool
	mode             planMode
	currentPerms     []PermissionRecord
	permissionsByKey map[string]plannedPermission
	newPermissions   []plannedPermission
	textUpdates      []plannedPermission
	reenables        []plannedPermission
	newRoles         []rolePlan
	roleDiffs        []rolePlan
	newGroups        []groupPlan
	// skippedRootOnly 是因通道限制未重新启用的 root_only 权限（不写入）。
	skippedRootOnly []plannedPermission
}

// changes 报告计划是否会写入业务数据（不含审计事件）。
func (p *scopePlan) changes() bool {
	return len(p.newPermissions) > 0 || len(p.textUpdates) > 0 || len(p.reenables) > 0 ||
		len(p.newRoles) > 0 || len(p.newGroups) > 0 || p.roleDiffChanges() > 0
}

// roleDiffChanges 报告角色组合是否有需新增/移除的权限。
func (p *scopePlan) roleDiffChanges() int {
	count := 0
	for _, diff := range p.roleDiffs {
		count += len(diff.add) + len(diff.remove)
	}
	for _, item := range p.newRoles {
		count += len(item.add)
	}
	return count
}

// diff 把计划转换为可展示、可摘要的差异。
func (p *scopePlan) diff() ScopeDiff {
	result := ScopeDiff{
		ScopeID: p.scope.ScopeID, ScopeKind: p.scope.Kind,
		CatalogVersion: p.state.CatalogVersion, Installed: p.installed,
		InstalledVersion: p.state.CatalogVersion,
	}
	for _, item := range p.newPermissions {
		result.MissingPermissions = append(result.MissingPermissions,
			PermissionChange{Key: item.definition.Key, Name: item.definition.Name})
	}
	for _, item := range p.textUpdates {
		result.UpdatePermissionTexts = append(result.UpdatePermissionTexts,
			PermissionChange{Key: item.definition.Key, Name: item.definition.Name})
	}
	for _, item := range p.reenables {
		result.ReenablePermissions = append(result.ReenablePermissions,
			PermissionChange{Key: item.definition.Key, Name: item.definition.Name})
	}
	for _, item := range p.skippedRootOnly {
		result.SkippedRootOnlyReenables = append(result.SkippedRootOnlyReenables,
			PermissionChange{Key: item.definition.Key, Name: item.definition.Name})
	}
	for _, item := range p.newRoles {
		result.MissingRoles = append(result.MissingRoles,
			PermissionChange{Key: item.template.Key, Name: item.template.Name})
	}
	for _, item := range p.newGroups {
		result.MissingGroups = append(result.MissingGroups,
			GroupChange{Key: item.template.Key, Name: item.template.Name})
	}
	for _, item := range p.roleDiffs {
		roleDiff := RoleDiff{
			ScopeID: p.scope.ScopeID, RoleKey: item.template.Key, Name: item.template.Name,
			RoleID: item.record.ID, Exists: item.existing, Protected: item.protected,
			Unchanged: item.unchanged,
		}
		for _, added := range item.add {
			roleDiff.AddPermissions = append(roleDiff.AddPermissions,
				PermissionChange{Key: added.definition.Key, Name: added.definition.Name})
		}
		for _, removed := range item.remove {
			roleDiff.RemovePermissions = append(roleDiff.RemovePermissions,
				PermissionChange{Key: removed.Key})
		}
		result.RoleDiffs = append(result.RoleDiffs, roleDiff)
	}
	return result
}

// summarize 汇总多个作用范围的差异计数。
func summarize(scopes []ScopeDiff) DiffSummary {
	var summary DiffSummary
	for _, scope := range scopes {
		summary.CreatePermissions += len(scope.MissingPermissions)
		summary.UpdatePermissionTexts += len(scope.UpdatePermissionTexts)
		summary.ReenablePermissions += len(scope.ReenablePermissions)
		summary.SkippedRootOnlyReenables += len(scope.SkippedRootOnlyReenables)
		summary.CreateRoles += len(scope.MissingRoles)
		summary.CreateGroups += len(scope.MissingGroups)
		for _, roleDiff := range scope.RoleDiffs {
			summary.AddRolePermissions += len(roleDiff.AddPermissions)
			summary.RemoveRolePermissions += len(roleDiff.RemovePermissions)
			if roleDiff.Protected {
				summary.ProtectedRoles++
			} else if roleDiff.Unchanged {
				summary.UnchangedRoles++
			}
		}
	}
	return summary
}

// normalizeScopeID 规范化初始化范围：空值默认系统范围。
func normalizeScopeID(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ScopeSystem, nil
	}
	if _, _, err := ParseScope(value); err != nil {
		return "", err
	}
	return value, nil
}

// loadScope 读取作用范围信息与当前目录项，并校验应用可用状态。
func (s *Service) loadScope(ctx context.Context, scopeID string) (ScopeInfo, bool, InstallState, []PermissionRecord, []RoleRecord, []GroupRecord, error) {
	scope, err := s.store.GetScope(ctx, scopeID)
	if err != nil {
		return ScopeInfo{}, false, InstallState{}, nil, nil, nil, err
	}
	if scope.Kind == ScopeKindApplication && !scope.ApplicationActive {
		// 错误文本只出现一次，并带出具体应用 ID，便于运维定位；调用方按
		// ErrApplicationInactive 映射 CLIENT_DISABLED。
		return ScopeInfo{}, false, InstallState{}, nil, nil, nil,
			fmt.Errorf("%w: 应用 %q 已停用，不能初始化或恢复其预设模板", ErrApplicationInactive, scopeID)
	}
	state, installed, err := s.store.GetInstallState(ctx, scopeID)
	if err != nil {
		return ScopeInfo{}, false, InstallState{}, nil, nil, nil, err
	}
	if !installed {
		state = InstallState{ScopeID: scopeID}
	}
	permissions, err := s.store.ListPermissions(ctx, scopeID)
	if err != nil {
		return ScopeInfo{}, false, InstallState{}, nil, nil, nil, err
	}
	roles, err := s.store.ListRoles(ctx, scopeID)
	if err != nil {
		return ScopeInfo{}, false, InstallState{}, nil, nil, nil, err
	}
	groups, err := s.store.ListGroups(ctx, scopeID)
	if err != nil {
		return ScopeInfo{}, false, InstallState{}, nil, nil, nil, err
	}
	return scope, installed, state, permissions, roles, groups, nil
}

// catalogForScope 返回该作用范围对应的预设权限、角色与用户组模板。
func (s *Service) catalogForScope(kind ScopeKind) ([]PermissionDefinition, []RoleTemplate, []GroupTemplate) {
	if kind == ScopeKindApplication {
		return nil, s.catalog.ApplicationRoles, s.catalog.ApplicationGroups
	}
	return s.catalog.Permissions, s.catalog.Roles, s.catalog.Groups
}

// buildInstallPlan 计算初始化/升级计划：只补缺失项，不覆盖既有角色组合。
func (s *Service) buildInstallPlan(ctx context.Context, scopeID string) (*scopePlan, error) {
	kind, _, err := ParseScope(scopeID)
	if err != nil {
		return nil, err
	}
	scope, installed, state, permissions, roles, groups, err := s.loadScope(ctx, scopeID)
	if err != nil {
		return nil, err
	}
	if installed {
		installedVersion, parseErr := parseCatalogVersion(state.CatalogVersion)
		if parseErr != nil {
			return nil, fmt.Errorf("%w: 已安装目录版本记录无效: %v", ErrCatalogDowngrade, parseErr)
		}
		currentVersion, _ := parseCatalogVersion(s.catalog.Version)
		if compareCatalogVersion(installedVersion, currentVersion) > 0 {
			return nil, fmt.Errorf("%w: 已安装版本 %s 高于程序内置版本 %s",
				ErrCatalogDowngrade, state.CatalogVersion, s.catalog.Version)
		}
	}
	definitions, roleTemplates, groupTemplates := s.catalogForScope(kind)
	plan := &scopePlan{scope: scope, state: state, installed: installed, mode: installMode,
		currentPerms: permissions, permissionsByKey: make(map[string]plannedPermission)}
	if kind == ScopeKindApplication {
		scope.ApplicationID = scopeID
	}
	// 现有权限索引与语义一致性检查。
	existingByKey := make(map[string]PermissionRecord, len(permissions))
	for _, record := range permissions {
		existingByKey[record.Key] = record
	}
	for _, definition := range definitions {
		record, exists := existingByKey[definition.Key]
		if exists {
			planned := plannedPermission{definition: definition, record: record, existing: true}
			if !record.IsBuiltin || record.RootOnly != definition.RootOnly {
				return nil, fmt.Errorf("%w: 预设权限 %q 与现有定义语义不一致（builtin=%t root_only=%t）",
					ErrCatalogConflict, definition.Key, record.IsBuiltin, record.RootOnly)
			}
			planned.textDirty = permissionTextDiffers(record, definition)
			if planned.textDirty {
				plan.textUpdates = append(plan.textUpdates, planned)
			}
			plan.permissionsByKey[definition.Key] = planned
			continue
		}
		id, idErr := permission.NewPermissionID(s.random)
		if idErr != nil {
			return nil, fmt.Errorf("%w: 生成权限 ID 失败: %v", ErrStoreUnavailable, idErr)
		}
		planned := plannedPermission{
			definition: definition,
			record: PermissionRecord{
				ID: id, ScopeID: scopeID, Key: definition.Key, Name: definition.Name,
				Description: permissionDescription(definition), Limits: definition.Limits,
				IsBuiltin: true, RootOnly: definition.RootOnly, Enabled: true,
			},
		}
		plan.newPermissions = append(plan.newPermissions, planned)
		plan.permissionsByKey[definition.Key] = planned
	}
	// 角色：缺失的创建；已存在的只记录“缺失的默认权限”提示，不改写组合。
	existingRoles := make(map[string]RoleRecord, len(roles))
	for _, record := range roles {
		existingRoles[record.Key] = record
	}
	for _, template := range roleTemplates {
		if record, exists := existingRoles[template.Key]; exists {
			diff, buildErr := s.existingRoleDiff(ctx, template, record, plan.permissionsByKey)
			if buildErr != nil {
				return nil, buildErr
			}
			plan.roleDiffs = append(plan.roleDiffs, diff)
			continue
		}
		id, idErr := role.NewRoleID(s.random)
		if idErr != nil {
			return nil, fmt.Errorf("%w: 生成角色 ID 失败: %v", ErrStoreUnavailable, idErr)
		}
		plan.newRoles = append(plan.newRoles, newRolePlan(template, RoleRecord{
			ID: id, ScopeID: scopeID, Key: template.Key, Name: template.Name,
			Description: template.Summary, Limits: template.Limits,
			IsBuiltin: kind == ScopeKindSystem, Enabled: true,
		}, plan.permissionsByKey))
	}
	existingGroups := make(map[string]struct{}, len(groups))
	for _, record := range groups {
		existingGroups[record.GroupKey] = struct{}{}
	}
	for _, template := range groupTemplates {
		if _, exists := existingGroups[template.Key]; exists {
			continue
		}
		id, idErr := group.NewGroupID(s.random)
		if idErr != nil {
			return nil, fmt.Errorf("%w: 生成用户组 ID 失败: %v", ErrStoreUnavailable, idErr)
		}
		plan.newGroups = append(plan.newGroups, groupPlan{template: template, record: GroupRecord{
			ID: id, ScopeID: scopeID, GroupKey: template.Key, Name: template.Name,
			Description: template.Description,
		}})
	}
	return plan, nil
}

// buildRestorePlan 计算恢复默认计划：仅限已初始化作用范围与明确选择的预设角色。
// allowRootOnlyReenables 仅对受限本地受控操作者（local_admin）为真，与
// internal/permission 的 root_only 启停规则一致；系统或其他通道不得借恢复默认
// 重新启用 root_only 权限（备份恢复、审计清理、敏感策略），否则可逆转 root 有意
// 的停用。被跳过的权限列入 skippedRootOnly 并在差异中明确展示。
func (s *Service) buildRestorePlan(ctx context.Context, scopeID string, roleKeys []string, allowRootOnlyReenables bool) (*scopePlan, error) {
	kind, _, err := ParseScope(scopeID)
	if err != nil {
		return nil, err
	}
	scope, installed, state, permissions, roles, groups, err := s.loadScope(ctx, scopeID)
	if err != nil {
		return nil, err
	}
	if !installed {
		return nil, fmt.Errorf("%w: 作用范围 %q 尚未初始化预设，请先执行初始化", ErrInvalidRequest, scopeID)
	}
	if installed && state.CatalogVersion != "" {
		if installedVersion, parseErr := parseCatalogVersion(state.CatalogVersion); parseErr != nil {
			return nil, fmt.Errorf("%w: 已安装目录版本记录无效", ErrCatalogDowngrade)
		} else if currentVersion, _ := parseCatalogVersion(s.catalog.Version); compareCatalogVersion(installedVersion, currentVersion) > 0 {
			return nil, fmt.Errorf("%w: 已安装版本 %s 高于程序内置版本 %s", ErrCatalogDowngrade, state.CatalogVersion, s.catalog.Version)
		}
	}
	definitions, roleTemplates, groupTemplates := s.catalogForScope(kind)
	selected, err := selectRoleTemplates(roleTemplates, roleKeys)
	if err != nil {
		return nil, err
	}
	plan := &scopePlan{scope: scope, state: state, installed: installed, mode: restoreMode,
		currentPerms: permissions, permissionsByKey: make(map[string]plannedPermission)}

	// 预设权限：缺失的补齐；说明随版本同步；被停用的内置权限恢复启用。
	existingByKey := make(map[string]PermissionRecord, len(permissions))
	for _, record := range permissions {
		existingByKey[record.Key] = record
	}
	for _, definition := range definitions {
		record, exists := existingByKey[definition.Key]
		if exists {
			planned := plannedPermission{definition: definition, record: record, existing: true}
			if !record.IsBuiltin || record.RootOnly != definition.RootOnly {
				return nil, fmt.Errorf("%w: 预设权限 %q 与现有定义语义不一致", ErrCatalogConflict, definition.Key)
			}
			planned.textDirty = permissionTextDiffers(record, definition)
			planned.reenable = !record.Enabled
			if planned.reenable && record.RootOnly && !allowRootOnlyReenables {
				// 非受限本地受控操作者跳过 root_only 重新启用：保持停用，并明确
				// 列入差异供操作者看到“这里不会恢复”，而不是静默忽略。
				planned.reenable = false
				plan.skippedRootOnly = append(plan.skippedRootOnly, planned)
			}
			if planned.textDirty {
				plan.textUpdates = append(plan.textUpdates, planned)
			}
			if planned.reenable {
				plan.reenables = append(plan.reenables, planned)
			}
			plan.permissionsByKey[definition.Key] = planned
			continue
		}
		id, idErr := permission.NewPermissionID(s.random)
		if idErr != nil {
			return nil, fmt.Errorf("%w: 生成权限 ID 失败: %v", ErrStoreUnavailable, idErr)
		}
		planned := plannedPermission{
			definition: definition,
			record: PermissionRecord{
				ID: id, ScopeID: scopeID, Key: definition.Key, Name: definition.Name,
				Description: permissionDescription(definition), Limits: definition.Limits,
				IsBuiltin: true, RootOnly: definition.RootOnly, Enabled: true,
			},
		}
		plan.newPermissions = append(plan.newPermissions, planned)
		plan.permissionsByKey[definition.Key] = planned
	}
	existingRoles := make(map[string]RoleRecord, len(roles))
	for _, record := range roles {
		existingRoles[record.Key] = record
	}
	for _, template := range selected {
		if record, exists := existingRoles[template.Key]; exists {
			if template.Core {
				plan.roleDiffs = append(plan.roleDiffs, rolePlan{
					template: template, record: record, existing: true, protected: true, unchanged: true,
				})
				continue
			}
			diff, buildErr := s.existingRoleDiff(ctx, template, record, plan.permissionsByKey)
			if buildErr != nil {
				return nil, buildErr
			}
			plan.roleDiffs = append(plan.roleDiffs, diff)
			continue
		}
		id, idErr := role.NewRoleID(s.random)
		if idErr != nil {
			return nil, fmt.Errorf("%w: 生成角色 ID 失败: %v", ErrStoreUnavailable, idErr)
		}
		plan.newRoles = append(plan.newRoles, newRolePlan(template, RoleRecord{
			ID: id, ScopeID: scopeID, Key: template.Key, Name: template.Name,
			Description: template.Summary, Limits: template.Limits,
			IsBuiltin: kind == ScopeKindSystem, Enabled: true,
		}, plan.permissionsByKey))
	}
	existingGroups := make(map[string]struct{}, len(groups))
	for _, record := range groups {
		existingGroups[record.GroupKey] = struct{}{}
	}
	for _, template := range groupTemplates {
		if _, exists := existingGroups[template.Key]; exists {
			continue
		}
		id, idErr := group.NewGroupID(s.random)
		if idErr != nil {
			return nil, fmt.Errorf("%w: 生成用户组 ID 失败: %v", ErrStoreUnavailable, idErr)
		}
		plan.newGroups = append(plan.newGroups, groupPlan{template: template, record: GroupRecord{
			ID: id, ScopeID: scopeID, GroupKey: template.Key, Name: template.Name,
			Description: template.Description,
		}})
	}
	return plan, nil
}

// existingRoleDiff 计算既有角色与目录默认权限的差异（仅用于恢复默认与提示）。
func (s *Service) existingRoleDiff(ctx context.Context, template RoleTemplate, record RoleRecord, permissionsByKey map[string]plannedPermission) (rolePlan, error) {
	result := rolePlan{template: template, record: record, existing: true}
	current, err := s.store.ListRolePermissions(ctx, record.ID)
	if err != nil {
		return rolePlan{}, err
	}
	currentByKey := make(map[string]RolePermissionRecord, len(current))
	for _, item := range current {
		currentByKey[item.Key] = item
	}
	if template.Core {
		result.protected = true
		result.unchanged = true
		return result, nil
	}
	seen := make(map[string]struct{}, len(template.DefaultPermissions))
	for _, key := range template.DefaultPermissions {
		seen[key] = struct{}{}
		planned, ok := permissionsByKey[key]
		if !ok {
			return rolePlan{}, fmt.Errorf("%w: 预设角色 %q 的默认权限 %q 不在目录中", ErrOptionsInvalid, template.Key, key)
		}
		if _, exists := currentByKey[key]; !exists {
			result.add = append(result.add, planned)
		}
	}
	for _, item := range current {
		if _, want := seen[item.Key]; !want {
			result.remove = append(result.remove, item)
		}
	}
	sort.Slice(result.add, func(i, j int) bool { return result.add[i].definition.Key < result.add[j].definition.Key })
	sort.Slice(result.remove, func(i, j int) bool { return result.remove[i].Key < result.remove[j].Key })
	result.unchanged = len(result.add) == 0 && len(result.remove) == 0
	return result, nil
}

// newRolePlan 构造新建角色的计划：把目录默认权限转换为待组合条目。
func newRolePlan(template RoleTemplate, record RoleRecord, permissionsByKey map[string]plannedPermission) rolePlan {
	result := rolePlan{template: template, record: record}
	for _, key := range template.DefaultPermissions {
		if planned, ok := permissionsByKey[key]; ok {
			result.add = append(result.add, planned)
		}
	}
	sort.Slice(result.add, func(i, j int) bool { return result.add[i].definition.Key < result.add[j].definition.Key })
	return result
}

// selectRoleTemplates 按明确选择过滤目录角色模板；未知角色键返回 REQ_INVALID。
func selectRoleTemplates(templates []RoleTemplate, roleKeys []string) ([]RoleTemplate, error) {
	if len(roleKeys) == 0 {
		return nil, fmt.Errorf("%w: 必须明确选择要恢复的角色", ErrInvalidRequest)
	}
	if len(roleKeys) > MaxRoleKeysPerScope {
		return nil, fmt.Errorf("%w: 单次恢复角色数量超过上限 %d", ErrInvalidRequest, MaxRoleKeysPerScope)
	}
	selected := make(map[string]struct{}, len(roleKeys))
	for _, key := range roleKeys {
		normalized := strings.TrimSpace(key)
		if normalized == "" {
			return nil, fmt.Errorf("%w: 角色机器标识不能为空", ErrInvalidRequest)
		}
		if _, exists := selected[normalized]; exists {
			return nil, fmt.Errorf("%w: 角色机器标识 %q 重复选择", ErrInvalidRequest, normalized)
		}
		selected[normalized] = struct{}{}
	}
	result := make([]RoleTemplate, 0, len(selected))
	for _, template := range templates {
		if _, ok := selected[template.Key]; ok {
			result = append(result, template)
			delete(selected, template.Key)
		}
	}
	if len(selected) > 0 {
		unknown := make([]string, 0, len(selected))
		for key := range selected {
			unknown = append(unknown, key)
		}
		sort.Strings(unknown)
		return nil, fmt.Errorf("%w: 选择的角色不在预设目录中: %s", ErrInvalidRequest, strings.Join(unknown, ","))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
	return result, nil
}

// resolveSelections 校验预览请求并展开为具体选择：显式选择或显式整体恢复。
// 整体恢复会跳过已停用的应用范围并返回跳过清单（停用应用不得借恢复被改写）。
func (s *Service) resolveSelections(ctx context.Context, request PreviewRequest) ([]RoleSelection, []SkippedScope, error) {
	if request.All && len(request.Selections) > 0 {
		return nil, nil, fmt.Errorf("%w: 整体恢复与显式选择不能同时使用", ErrInvalidRequest)
	}
	if !request.All && len(request.Selections) == 0 {
		return nil, nil, fmt.Errorf("%w: 必须明确选择作用范围与角色，或显式指定整体恢复", ErrInvalidRequest)
	}
	if request.All {
		states, err := s.store.ListInstallStates(ctx)
		if err != nil {
			return nil, nil, err
		}
		if len(states) == 0 {
			return nil, nil, fmt.Errorf("%w: 尚未初始化任何预设，无法整体恢复", ErrInvalidRequest)
		}
		sort.Slice(states, func(i, j int) bool {
			if states[i].ScopeID == ScopeSystem {
				return true
			}
			if states[j].ScopeID == ScopeSystem {
				return false
			}
			return states[i].ScopeID < states[j].ScopeID
		})
		if len(states) > MaxSelections {
			return nil, nil, fmt.Errorf("%w: 已初始化作用范围数量超过单次恢复上限 %d", ErrInvalidRequest, MaxSelections)
		}
		selections := make([]RoleSelection, 0, len(states))
		skipped := make([]SkippedScope, 0)
		for _, state := range states {
			kind, _, parseErr := ParseScope(state.ScopeID)
			if parseErr != nil {
				return nil, nil, parseErr
			}
			if kind == ScopeKindApplication {
				scope, scopeErr := s.store.GetScope(ctx, state.ScopeID)
				if scopeErr != nil {
					return nil, nil, scopeErr
				}
				if !scope.ApplicationActive {
					// 整体恢复跳过已停用应用，并在结果中明确报告；不能因为一个
					// 停用应用让整次恢复失败，也不能替它重新启用或改写预设。
					skipped = append(skipped, SkippedScope{
						ScopeID: state.ScopeID, Reason: "application_inactive",
					})
					continue
				}
			}
			_, templates, _ := s.catalogForScope(kind)
			keys := make([]string, 0, len(templates))
			for _, template := range templates {
				keys = append(keys, template.Key)
			}
			sort.Strings(keys)
			selections = append(selections, RoleSelection{ScopeID: state.ScopeID, RoleKeys: keys})
		}
		return selections, skipped, nil
	}
	if len(request.Selections) > MaxSelections {
		return nil, nil, fmt.Errorf("%w: 选择的作用范围数量超过上限 %d", ErrInvalidRequest, MaxSelections)
	}
	selections := make([]RoleSelection, 0, len(request.Selections))
	seenScopes := make(map[string]struct{}, len(request.Selections))
	for _, selection := range request.Selections {
		scopeID := strings.TrimSpace(selection.ScopeID)
		if _, _, err := ParseScope(scopeID); err != nil {
			return nil, nil, err
		}
		if _, exists := seenScopes[scopeID]; exists {
			return nil, nil, fmt.Errorf("%w: 作用范围 %q 重复选择", ErrInvalidRequest, scopeID)
		}
		seenScopes[scopeID] = struct{}{}
		keys := make([]string, 0, len(selection.RoleKeys))
		for _, key := range selection.RoleKeys {
			keys = append(keys, strings.TrimSpace(key))
		}
		sort.Strings(keys)
		selections = append(selections, RoleSelection{ScopeID: scopeID, RoleKeys: keys})
	}
	sort.Slice(selections, func(i, j int) bool {
		if selections[i].ScopeID == ScopeSystem {
			return true
		}
		if selections[j].ScopeID == ScopeSystem {
			return false
		}
		return selections[i].ScopeID < selections[j].ScopeID
	})
	return selections, nil, nil
}

// applyPlan 在调用方审计事务内执行计划，并在每条改变有效权限的写入前通过同一
// delegation.Guard 检查。changed 报告是否实际写入业务数据。
func (s *Service) applyPlan(ctx context.Context, tx audit.Tx, actor audit.Actor, plan *scopePlan, now time.Time, mode planMode) (bool, error) {
	changed := false
	scopeID := plan.scope.ScopeID
	for _, item := range plan.newPermissions {
		if err := s.store.CreatePermission(ctx, tx, item.record); err != nil {
			return false, err
		}
		changed = true
	}
	for _, item := range plan.textUpdates {
		// 文案同步必须写入目录定义的新值（item.definition），而不是已存在记录
		// 的旧快照；否则升级改文案时库内不更新，Changed 永不收敛、预览永远报
		// “说明更新”，违反幂等承诺。语义字段（root_only/is_builtin）已在计划阶段
		// 校验一致，这里不扩大权限。
		if err := s.store.UpdatePermissionText(ctx, tx, item.record.ID, item.definition.Name,
			permissionDescription(item.definition), item.definition.Limits, now); err != nil {
			return false, err
		}
		changed = true
	}
	for _, item := range plan.reenables {
		// 重新启用等于恢复该权限既有持有路径，必须按“启用后会重新获得它”的目标集合
		// 复核委派目标限制，与步骤 26 的启用权限路径保持一致。
		targets, err := s.store.PermissionHolderTargets(ctx, tx, item.record.ID)
		if err != nil {
			return false, err
		}
		refs := []delegation.PermissionRef{{PermissionID: item.record.ID}}
		if err := s.transfers.CheckPermissionActivation(ctx, tx, actor, scopeID, refs, targets); err != nil {
			return false, err
		}
		if err := s.store.SetPermissionEnabled(ctx, tx, item.record.ID, true, now); err != nil {
			return false, err
		}
		changed = true
	}
	for _, item := range plan.newRoles {
		if err := s.store.CreateRole(ctx, tx, item.record); err != nil {
			return false, err
		}
		changed = true
		if err := s.composeRolePermissions(ctx, tx, actor, scopeID, item.record.ID, item.add); err != nil {
			return false, err
		}
	}
	for _, item := range plan.newGroups {
		if err := s.store.CreateGroup(ctx, tx, item.record); err != nil {
			return false, err
		}
		changed = true
	}
	if mode == restoreMode {
		for _, diff := range plan.roleDiffs {
			if diff.protected {
				continue
			}
			if len(diff.add) > 0 {
				if err := s.composeRolePermissions(ctx, tx, actor, scopeID, diff.record.ID, diff.add); err != nil {
					return false, err
				}
				changed = true
			}
			for _, removed := range diff.remove {
				removedChanged, err := s.store.RemoveRolePermission(ctx, tx, diff.record.ID, removed.PermissionID)
				if err != nil {
					return false, err
				}
				if removedChanged {
					changed = true
				}
			}
		}
	}
	// 记录初始化版本：恢复默认同样把该作用范围标记为当前目录版本。
	state := InstallState{
		ScopeID: scopeID, CatalogVersion: s.catalog.Version, AppliedAt: now, UpdatedAt: now,
	}
	if plan.installed {
		state.AppliedAt = plan.state.AppliedAt
		if state.AppliedAt.IsZero() {
			state.AppliedAt = now
		}
	}
	if err := s.store.SaveInstallState(ctx, tx, state); err != nil {
		return false, err
	}
	if mode == installMode {
		changed = changed || len(plan.newPermissions) > 0 || len(plan.newRoles) > 0 || len(plan.newGroups) > 0
	}
	return changed, nil
}

// composeRolePermissions 在同一事务内先经 delegation.Guard 复核角色当前分配目标，
// 再逐条组合权限。恢复默认不能借新增权限扩大操作者可委派范围。
func (s *Service) composeRolePermissions(ctx context.Context, tx audit.Tx, actor audit.Actor, scopeID, roleID string, permissions []plannedPermission) error {
	if len(permissions) == 0 {
		return nil
	}
	targets, err := s.store.RoleAssignmentTargets(ctx, tx, roleID, scopeID)
	if err != nil {
		return err
	}
	refs := make([]delegation.PermissionRef, 0, len(permissions))
	for _, item := range permissions {
		refs = append(refs, delegation.PermissionRef{PermissionID: item.record.ID})
	}
	if err := s.transfers.CheckPermissionAccess(ctx, tx, actor, scopeID, refs, targets); err != nil {
		return err
	}
	for _, item := range permissions {
		if _, err := s.store.AddRolePermission(ctx, tx, roleID, item.record.ID, scopeID); err != nil {
			return err
		}
	}
	return nil
}

// permissionDescription 生成权限说明：能做什么｜范围：……；限制单独存放。
func permissionDescription(definition PermissionDefinition) string {
	return definition.Summary + "｜范围：" + definition.Scope
}

// permissionTextDiffers 报告现有预设权限的中文说明是否与目录定义不同。
func permissionTextDiffers(record PermissionRecord, definition PermissionDefinition) bool {
	return record.Name != definition.Name ||
		record.Description != permissionDescription(definition) ||
		record.Limits != definition.Limits
}

// previewDigest 计算与预览内容绑定的状态摘要；摘要不包含令牌与生成时间。
func previewDigest(preview Preview) (string, error) {
	payload := struct {
		CatalogVersion string
		All            bool
		Selections     []RoleSelection
		SkippedScopes  []SkippedScope
		Scopes         []ScopeDiff
		Summary        DiffSummary
	}{
		CatalogVersion: preview.CatalogVersion, All: preview.All,
		Selections: preview.Selections, SkippedScopes: preview.SkippedScopes,
		Scopes: preview.Scopes, Summary: preview.Summary,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("%w: 计算差异摘要失败: %v", ErrInvalidRequest, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// prunePreviewTokensLocked 清理过期令牌并在超过上限时淘汰最旧记录；调用方持锁。
func (s *Service) prunePreviewTokensLocked(now time.Time) {
	if len(s.previewTokens) < MaxPreviewTokens {
		return
	}
	for token, record := range s.previewTokens {
		if !now.Before(record.expiresAt) {
			delete(s.previewTokens, token)
		}
	}
	if len(s.previewTokens) < MaxPreviewTokens {
		return
	}
	var oldestToken string
	var oldest time.Time
	for token, record := range s.previewTokens {
		if oldestToken == "" || record.expiresAt.Before(oldest) {
			oldestToken, oldest = token, record.expiresAt
		}
	}
	delete(s.previewTokens, oldestToken)
}

// installAuditChanges 构造初始化审计差异字段。
func installAuditChanges(plan *scopePlan, version string) []audit.FieldChange {
	return []audit.FieldChange{
		{Field: "scope_id", After: plan.scope.ScopeID},
		{Field: "catalog_version", After: version},
		{Field: "permissions_created", After: fmt.Sprint(len(plan.newPermissions))},
		{Field: "roles_created", After: fmt.Sprint(len(plan.newRoles))},
		{Field: "groups_created", After: fmt.Sprint(len(plan.newGroups))},
		{Field: "role_permission_defaults_added", After: fmt.Sprint(plan.roleDiffChanges())},
	}
}

// restoreAuditChanges 构造恢复审计差异字段（含预览摘要、选择、跳过项，便于追溯）。
func restoreAuditChanges(record previewToken, digest string, summary DiffSummary) []audit.FieldChange {
	return []audit.FieldChange{
		{Field: "scope_selection", After: selectionsLabel(record.selections)},
		{Field: "catalog_version", After: record.catalogVersion},
		{Field: "preview_digest", After: digest},
		{Field: "create_permissions", After: fmt.Sprint(summary.CreatePermissions)},
		{Field: "create_roles", After: fmt.Sprint(summary.CreateRoles)},
		{Field: "add_role_permissions", After: fmt.Sprint(summary.AddRolePermissions)},
		{Field: "remove_role_permissions", After: fmt.Sprint(summary.RemoveRolePermissions)},
		{Field: "reenable_permissions", After: fmt.Sprint(summary.ReenablePermissions)},
		{Field: "root_only_reenable_skipped", After: fmt.Sprint(summary.SkippedRootOnlyReenables)},
		{Field: "skipped_scopes", After: fmt.Sprint(len(record.skipped))},
	}
}

// selectionsLabel 生成简洁、可审计的选择标签；过长时截断，避免审计字段超限。
func selectionsLabel(selections []RoleSelection) string {
	parts := make([]string, 0, len(selections))
	for _, selection := range selections {
		parts = append(parts, selection.ScopeID+":"+strings.Join(selection.RoleKeys, ","))
	}
	label := strings.Join(parts, ";")
	if len(label) > maxAuditDetailBytes {
		label = label[:maxAuditDetailBytes]
	}
	return label
}

// selectionsScopeLabel 生成审计目标标签（多个作用范围用逗号分隔）。
func selectionsScopeLabel(selections []RoleSelection) string {
	parts := make([]string, 0, len(selections))
	for _, selection := range selections {
		parts = append(parts, selection.ScopeID)
	}
	label := strings.Join(parts, ",")
	if len(label) > 128 {
		label = label[:128]
	}
	return label
}

// selectionsApplicationID 返回选择中唯一应用 ID（系统范围或混合范围返回空）。
func selectionsApplicationID(selections []RoleSelection) string {
	applicationID := ""
	for _, selection := range selections {
		if selection.ScopeID == ScopeSystem {
			continue
		}
		if applicationID != "" && applicationID != selection.ScopeID {
			return ""
		}
		applicationID = selection.ScopeID
	}
	return applicationID
}

// mapCriticalError 把事务/存储错误映射为预设领域错误；审计失败优先判定，委派检查
// 拒绝保留原错误由 CodeOf 映射，不能被误包装成存储不可用。
func mapCriticalError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, audit.ErrAuditUnavailable):
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrScopeInvalid),
		errors.Is(err, ErrPreviewRequired), errors.Is(err, ErrPreviewStale),
		errors.Is(err, ErrAccessDenied), errors.Is(err, ErrCatalogConflict),
		errors.Is(err, ErrCatalogDowngrade), errors.Is(err, ErrStateConflict),
		errors.Is(err, ErrApplicationInactive), errors.Is(err, ErrStoreUnavailable):
		return err
	case delegation.CodeOf(err) != "":
		return err
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, audit.ErrInvalidEvent):
		return fmt.Errorf("%w: 审计事件无效", ErrOptionsInvalid)
	default:
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
}
