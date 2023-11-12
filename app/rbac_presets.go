// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

import (
	"context"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/preset"
	presetsqlite "github.com/kagurazakayashi/EvernightLogin/internal/preset/sqlite"
)

// RBACPresetService 是预设目录与恢复服务。
//
// 安全边界：预览与恢复只接受 LocalAdmin（宿主进程受信操作者）；普通管理会话
// （AdminSession）与受限会话一律 ACCESS_DENIED，不能通过公开 Go 入口恢复高权限预设。
// 恢复只接受预览返回的短时单次确认令牌，客户端布尔值不能冒充“已展示差异并确认”；
// root_only 重新启用、停用应用跳过、预览后状态变化复核均由内部预设服务执行。
type RBACPresetService interface {
	// Catalog 返回版本化预设权限目录（中文说明与真实 Implemented 标记）。
	Catalog(ctx context.Context, req RBACCatalogRequest) (RBACPresetCatalog, error)
	// Preview 计算恢复预设的差异并签发确认令牌（仅 LocalAdmin）。
	Preview(ctx context.Context, req RBACPresetPreviewRequest) (RBACPresetPreview, error)
	// Restore 按确认令牌执行恢复（仅 LocalAdmin；令牌不存在/过期/已用过/状态变化拒绝）。
	Restore(ctx context.Context, req RBACPresetRestoreRequest) (RBACPresetRestoreResult, error)
}

// RBACPresetPreviewRequest 是预设差异预览请求。All=true 表示整体恢复；否则用
// ScopeID+RoleKeys 明确选择要恢复的角色（二者不能同时为空的规则由内部服务判定）。
type RBACPresetPreviewRequest struct {
	Caller    AdminCaller
	All       bool
	ScopeID   string
	RoleKeys  []string
	RequestID string
}

// RBACPresetSelection 是实际将被恢复的具体选择（All 已由服务端展开）。
type RBACPresetSelection struct {
	ScopeID  string
	RoleKeys []string
}

// RBACPresetSkippedScope 是被跳过的范围及原因（如应用已停用）。
type RBACPresetSkippedScope struct {
	ScopeID string
	Reason  string
}

// RBACPresetRoleDiff 是角色维度的预览差异。
type RBACPresetRoleDiff struct {
	ScopeID           string
	RoleKey           string
	Name              string
	RoleID            string
	Exists            bool
	Protected         bool
	Unchanged         bool
	AddPermissions    []string
	RemovePermissions []string
}

// RBACPresetScopeDiff 是一个作用范围的预览差异摘要。
type RBACPresetScopeDiff struct {
	ScopeID                  string
	ScopeKind                string
	CatalogVersion           string
	Installed                bool
	InstalledVersion         string
	MissingPermissions       []string
	UpdatePermissionTexts    []string
	ReenablePermissions      []string
	SkippedRootOnlyReenables []string
	MissingRoles             []string
	MissingGroups            []string
	RoleDiffs                []RBACPresetRoleDiff
}

// RBACPresetSummary 是差异汇总计数。
type RBACPresetSummary struct {
	CreatePermissions        int
	UpdatePermissionTexts    int
	ReenablePermissions      int
	SkippedRootOnlyReenables int
	CreateRoles              int
	CreateGroups             int
	AddRolePermissions       int
	RemoveRolePermissions    int
	UnchangedRoles           int
	ProtectedRoles           int
}

// RBACPresetPreview 是差异预览与确认令牌。
type RBACPresetPreview struct {
	Token          string
	CatalogVersion string
	GeneratedAt    time.Time
	ExpiresAt      time.Time
	Digest         string
	All            bool
	Selections     []RBACPresetSelection
	SkippedScopes  []RBACPresetSkippedScope
	Scopes         []RBACPresetScopeDiff
	Summary        RBACPresetSummary
}

// RBACPresetRestoreRequest 是恢复预设请求（只接受预览确认令牌）。
type RBACPresetRestoreRequest struct {
	Caller    AdminCaller
	Token     string
	RequestID string
}

// RBACPresetRestoreResult 是恢复预设的实际结果。
type RBACPresetRestoreResult struct {
	CatalogVersion string
	Digest         string
	All            bool
	Selections     []RBACPresetSelection
	SkippedScopes  []RBACPresetSkippedScope
	Scopes         []RBACPresetScopeDiff
	Summary        RBACPresetSummary
}

// Presets 返回预设目录与恢复服务。
func (f *rbacFacade) Presets() RBACPresetService { return &rbacPresetFacade{f: f} }

type rbacPresetFacade struct{ f *rbacFacade }

// rbacPresetHolder 按 Runtime 惰性缓存预设服务：预览令牌保存在服务实例内，
// Preview 与 Restore 必须命中同一实例；缓存不启动任何后台任务，Runtime 关闭后
// 对数据库的调用会失败关闭。限制：单进程实例内有效，多实例部署需共享令牌存储。
type rbacPresetHolder struct {
	mu      sync.Mutex
	service *preset.Service
}

var rbacPresetRegistry sync.Map // map[*Runtime]*rbacPresetHolder

// presetService 返回本 Runtime 的预设服务（惰性构造一次）。
func (s *rbacPresetFacade) presetService(call adminRequest) (*preset.Service, error) {
	if s.f.r == nil || s.f.r.base == nil || s.f.r.base.Store == nil ||
		s.f.r.base.Audit == nil {
		return nil, call.configError("预设服务依赖未装配")
	}
	managed := s.f.r.managedServices()
	if managed == nil || managed.Delegation == nil {
		return nil, call.configError("预设服务委派检查器未装配")
	}
	value, _ := rbacPresetRegistry.LoadOrStore(s.f.r, &rbacPresetHolder{})
	holder, ok := value.(*rbacPresetHolder)
	if !ok {
		return nil, call.configError("预设服务状态无效")
	}
	holder.mu.Lock()
	defer holder.mu.Unlock()
	if holder.service != nil {
		return holder.service, nil
	}
	store, err := presetsqlite.New(s.f.r.base.Store)
	if err != nil {
		return nil, call.configError("预设存储不可用")
	}
	service, err := preset.New(preset.Options{Store: store, Audit: s.f.r.base.Audit,
		Transfers: managed.Delegation, Now: s.f.r.runtimeNow, Logger: s.f.r.logger})
	if err != nil {
		return nil, call.configError("预设服务不可用")
	}
	holder.service = service
	return service, nil
}

// presetCaller 构造预设服务调用者：只接受 LocalAdmin；管理会话明确拒绝。
func (s *rbacPresetFacade) presetCaller(call adminRequest) (preset.Caller, error) {
	if !call.identity.local {
		return preset.Caller{}, mapDomainError("恢复预设只允许本机受信操作者",
			"ACCESS_DENIED", call.requestID)
	}
	caller, err := preset.LocalBootstrapCaller(call.identity.actor.ID)
	if err != nil {
		return preset.Caller{}, call.configError("预设服务调用者无效")
	}
	return bindCaller(caller, call.requestID)
}

// Catalog 返回预设目录的公开只读视图（完整管理会话可读）。
func (s *rbacPresetFacade) Catalog(ctx context.Context,
	req RBACCatalogRequest) (RBACPresetCatalog, error) {
	if _, err := s.f.begin(ctx, req.Caller, req.RequestID); err != nil {
		return RBACPresetCatalog{}, err
	}
	catalog := preset.DefaultCatalog()
	if catalog == nil {
		return RBACPresetCatalog{}, configError("预设权限目录不可用")
	}
	entries := make([]RBACPresetPermission, 0, len(catalog.Permissions))
	for _, definition := range catalog.Permissions {
		entries = append(entries, RBACPresetPermission{Key: definition.Key,
			Name: definition.Name, Summary: definition.Summary, Scope: definition.Scope,
			Limits: definition.Limits, RequiresReauth: definition.RequiresReauth,
			RootOnly:     definition.RootOnly,
			DefaultRoles: append([]string(nil), definition.DefaultRoles...),
			Implemented:  definition.Implemented})
	}
	return RBACPresetCatalog{Version: catalog.Version, Permissions: entries}, nil
}

// Preview 计算预设差异并签发确认令牌（仅 LocalAdmin）。
func (s *rbacPresetFacade) Preview(ctx context.Context,
	req RBACPresetPreviewRequest) (RBACPresetPreview, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return RBACPresetPreview{}, err
	}
	caller, err := s.presetCaller(call)
	if err != nil {
		return RBACPresetPreview{}, err
	}
	service, err := s.presetService(call)
	if err != nil {
		return RBACPresetPreview{}, err
	}
	previewRequest := preset.PreviewRequest{All: req.All}
	if !req.All && req.ScopeID != "" {
		previewRequest.Selections = []preset.RoleSelection{{
			ScopeID: req.ScopeID, RoleKeys: append([]string(nil), req.RoleKeys...)}}
	}
	value, err := service.Preview(ctx, caller, previewRequest)
	if err != nil {
		return RBACPresetPreview{}, call.domainError("预览预设恢复失败",
			string(preset.CodeOf(err)))
	}
	return rbacPresetPreview(value), nil
}

// Restore 执行预设恢复（仅 LocalAdmin；只接受预览确认令牌）。
func (s *rbacPresetFacade) Restore(ctx context.Context,
	req RBACPresetRestoreRequest) (RBACPresetRestoreResult, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return RBACPresetRestoreResult{}, err
	}
	caller, err := s.presetCaller(call)
	if err != nil {
		return RBACPresetRestoreResult{}, err
	}
	service, err := s.presetService(call)
	if err != nil {
		return RBACPresetRestoreResult{}, err
	}
	value, err := service.Restore(ctx, caller, preset.RestoreRequest{Token: req.Token})
	if err != nil {
		return RBACPresetRestoreResult{}, call.domainError("恢复预设失败",
			string(preset.CodeOf(err)))
	}
	return RBACPresetRestoreResult{CatalogVersion: value.CatalogVersion,
		Digest: value.Digest, All: value.All,
		Selections:    rbacPresetSelections(value.Selections),
		SkippedScopes: rbacPresetSkipped(value.SkippedScopes),
		Scopes:        rbacPresetScopes(value.Scopes),
		Summary:       rbacPresetSummary(value.Summary)}, nil
}

func rbacPresetPreview(value preset.Preview) RBACPresetPreview {
	return RBACPresetPreview{Token: value.Token, CatalogVersion: value.CatalogVersion,
		GeneratedAt: value.GeneratedAt, ExpiresAt: value.ExpiresAt, Digest: value.Digest,
		All: value.All, Selections: rbacPresetSelections(value.Selections),
		SkippedScopes: rbacPresetSkipped(value.SkippedScopes),
		Scopes:        rbacPresetScopes(value.Scopes),
		Summary:       rbacPresetSummary(value.Summary)}
}

func rbacPresetSelections(values []preset.RoleSelection) []RBACPresetSelection {
	result := make([]RBACPresetSelection, 0, len(values))
	for _, value := range values {
		result = append(result, RBACPresetSelection{ScopeID: value.ScopeID,
			RoleKeys: append([]string(nil), value.RoleKeys...)})
	}
	return result
}

func rbacPresetSkipped(values []preset.SkippedScope) []RBACPresetSkippedScope {
	result := make([]RBACPresetSkippedScope, 0, len(values))
	for _, value := range values {
		result = append(result, RBACPresetSkippedScope{ScopeID: value.ScopeID,
			Reason: value.Reason})
	}
	return result
}

func rbacPresetScopes(values []preset.ScopeDiff) []RBACPresetScopeDiff {
	result := make([]RBACPresetScopeDiff, 0, len(values))
	for _, value := range values {
		result = append(result, RBACPresetScopeDiff{ScopeID: value.ScopeID,
			ScopeKind: string(value.ScopeKind), CatalogVersion: value.CatalogVersion,
			Installed: value.Installed, InstalledVersion: value.InstalledVersion,
			MissingPermissions:       rbacPermissionChanges(value.MissingPermissions),
			UpdatePermissionTexts:    rbacPermissionChanges(value.UpdatePermissionTexts),
			ReenablePermissions:      rbacPermissionChanges(value.ReenablePermissions),
			SkippedRootOnlyReenables: rbacPermissionChanges(value.SkippedRootOnlyReenables),
			MissingRoles:             rbacPermissionChanges(value.MissingRoles),
			MissingGroups:            rbacGroupChanges(value.MissingGroups),
			RoleDiffs:                rbacRoleDiffs(value.RoleDiffs)})
	}
	return result
}

func rbacPermissionChanges(values []preset.PermissionChange) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.Key)
	}
	return result
}

func rbacGroupChanges(values []preset.GroupChange) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.Key)
	}
	return result
}

func rbacRoleDiffs(values []preset.RoleDiff) []RBACPresetRoleDiff {
	result := make([]RBACPresetRoleDiff, 0, len(values))
	for _, value := range values {
		result = append(result, RBACPresetRoleDiff{ScopeID: value.ScopeID,
			RoleKey: value.RoleKey, Name: value.Name, RoleID: value.RoleID,
			Exists: value.Exists, Protected: value.Protected, Unchanged: value.Unchanged,
			AddPermissions:    rbacPermissionChanges(value.AddPermissions),
			RemovePermissions: rbacPermissionChanges(value.RemovePermissions)})
	}
	return result
}

func rbacPresetSummary(value preset.DiffSummary) RBACPresetSummary {
	return RBACPresetSummary{CreatePermissions: value.CreatePermissions,
		UpdatePermissionTexts:    value.UpdatePermissionTexts,
		ReenablePermissions:      value.ReenablePermissions,
		SkippedRootOnlyReenables: value.SkippedRootOnlyReenables,
		CreateRoles:              value.CreateRoles, CreateGroups: value.CreateGroups,
		AddRolePermissions:    value.AddRolePermissions,
		RemoveRolePermissions: value.RemoveRolePermissions,
		UnchangedRoles:        value.UnchangedRoles, ProtectedRoles: value.ProtectedRoles}
}
