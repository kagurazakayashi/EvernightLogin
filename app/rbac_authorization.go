// Copyright (c) Kagurazakayashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

import (
	"context"

	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
)

// RBACAuthorizationService 是有效权限/来源/资源级授权查询服务。
//
// 所有查询先经领域查询授权（调用者只能查自己或获准范围）；跨应用同名权限按范围隔离，
// 拒绝不泄露其他应用存在性与数量；结果即时计算、不缓存旧授权。
//
// root 语义（步骤 252）：真实 root 主体的权限由授权内核按只读预设目录的「已实现且
// 已启用」权限（任意有效 scope）与数据库已启用的自定义/应用范围权限统一推导，
// 不依赖普通角色分配；有效权限来源 Kind 为 "root"。未知/停用/未实现权限与停用应用
// 仍拒绝，root 身份不会跳过这些判断。
type RBACAuthorizationService interface {
	// Check 检查主体是否满足一组权限（Mode 空按 all；未知/停用/root_only 拒绝）。
	Check(ctx context.Context, req RBACCheckRequest) (RBACCheckResult, error)
	// EffectivePermissions 分页读取主体在指定范围的有效权限及来源。
	EffectivePermissions(ctx context.Context,
		req RBACEffectiveRequest) (RBACEffectiveResult, error)
	// PermissionSources 查询指定权限的来源（含停用/受限原因）。
	PermissionSources(ctx context.Context,
		req RBACPermissionSourcesRequest) (RBACPermissionSourcesResult, error)
	// CheckResourceAccess 按权限+资源 ID 执行数据范围判定。
	CheckResourceAccess(ctx context.Context,
		req RBACResourceAccessRequest) (RBACResourceDecision, error)
}

// RBACCheckRequest 是权限检查请求。
type RBACCheckRequest struct {
	Caller        AdminCaller
	SubjectUserID string
	ScopeID       string
	Permissions   []string
	Mode          string // "all"（默认）或 "any"
	RequestID     string
}

// RBACGrantSource 是权限来源摘要。
type RBACGrantSource struct {
	Kind              string
	RoleID            string
	RoleKey           string
	RoleName          string
	RoleEnabled       bool
	GroupID           string
	GroupKey          string
	GroupName         string
	PermissionID      string
	PermissionKey     string
	PermissionName    string
	PermissionEnabled bool
	RootOnly          bool
	DataScopeMode     string
	DataScope         []string
	// Included 表示该来源是否计入当前权限；为 false 时 ExcludedReason 说明排除原因。
	// root 主体的来源 Kind 为 "root"（受保护全权限主体，不是角色/组分配）。
	Included       bool
	ExcludedReason string
}

// RBACPermissionDecision 是单个权限的判定。
type RBACPermissionDecision struct {
	Key                string
	Allowed            bool
	Code               string
	Reason             string
	Sources            []RBACGrantSource
	DataScopeMode      string
	DataScope          []string
	SourceLimitReached bool
}

// RBACCheckResult 是权限检查整体结果（Allowed=false 时 Code/Reason 说明原因）。
type RBACCheckResult struct {
	SubjectUserID      string
	ScopeID            string
	Mode               string
	Allowed            bool
	Code               string
	Reason             string
	Permissions        []RBACPermissionDecision
	SourceLimitReached bool
}

// RBACEffectiveRequest 是有效权限分页请求。
type RBACEffectiveRequest struct {
	Caller        AdminCaller
	SubjectUserID string
	ScopeID       string
	Page          AdminPage
	RequestID     string
}

// RBACEffectivePermission 是有效权限条目。
type RBACEffectivePermission struct {
	Key           string
	Name          string
	ScopeID       string
	DataScopeMode string
	DataScope     []string
	Sources       []RBACGrantSource
	// 说明：root 主体的有效权限来源为 Kind="root"（Included=true），表示受保护
	// 全权限主体按目录推导的权限，不是角色/组分配。
}

// RBACEffectiveResult 是有效权限分页结果。
type RBACEffectiveResult struct {
	SubjectUserID      string
	ScopeID            string
	AccountStatus      string
	ApplicationStatus  string
	MembershipStatus   string
	DeniedCode         string
	DeniedReason       string
	Permissions        []RBACEffectivePermission
	HasMore            bool
	Page               AdminPageInfo
	SourceLimitReached bool
}

// RBACPermissionSourcesRequest 是权限来源查询请求。
type RBACPermissionSourcesRequest struct {
	Caller        AdminCaller
	SubjectUserID string
	ScopeID       string
	PermissionKey string
	Page          AdminPage
	RequestID     string
}

// RBACPermissionSourcesResult 是权限来源查询结果。
type RBACPermissionSourcesResult struct {
	SubjectUserID     string
	ScopeID           string
	AccountStatus     string
	ApplicationStatus string
	MembershipStatus  string
	PermissionKey     string
	PermissionName    string
	PermissionFound   bool
	Sources           []RBACGrantSource
	HasMore           bool
	Page              AdminPageInfo
}

// RBACResourceAccessRequest 是资源级授权请求。
type RBACResourceAccessRequest struct {
	Caller        AdminCaller
	SubjectUserID string
	ScopeID       string
	PermissionKey string
	ResourceID    string
	RequestID     string
}

// RBACResourceDecision 是资源级授权结果。
type RBACResourceDecision struct {
	Allowed       bool
	Code          string
	Reason        string
	PermissionKey string
	ResourceID    string
	DataScopeMode string
	DataScope     []string
}

// Authorization 返回授权查询服务。
func (f *rbacFacade) Authorization() RBACAuthorizationService {
	return &rbacAuthorizationFacade{f: f}
}

type rbacAuthorizationFacade struct{ f *rbacFacade }

// authzCaller 构造带请求编号的授权引擎调用者。
func (s *rbacAuthorizationFacade) authzCaller(call adminRequest) (authz.Caller, error) {
	caller, err := s.f.admin.authzCaller(call.identity)
	if err != nil {
		return authz.Caller{}, call.configError("授权服务调用者无效")
	}
	return bindCaller(caller, call.requestID)
}

// authzService 读取授权引擎；未装配时 fail-closed。
func (s *rbacAuthorizationFacade) authzService(call adminRequest) (*authz.Service, error) {
	managed := s.f.r.managedServices()
	if managed == nil || managed.Authz == nil {
		return nil, call.configError("授权服务未装配")
	}
	return managed.Authz, nil
}

func rbacSources(values []authz.SourceSummary) []RBACGrantSource {
	result := make([]RBACGrantSource, 0, len(values))
	for _, value := range values {
		result = append(result, RBACGrantSource{
			Kind: string(value.Kind), RoleID: value.RoleID, RoleKey: value.RoleKey,
			RoleName: value.RoleName, RoleEnabled: value.RoleEnabled,
			GroupID: value.GroupID, GroupKey: value.GroupKey, GroupName: value.GroupName,
			PermissionID: value.PermissionID, PermissionKey: value.PermissionKey,
			PermissionName: value.PermissionName, PermissionEnabled: value.PermissionEnabled,
			RootOnly: value.RootOnly, DataScopeMode: string(value.DataScope.Mode),
			DataScope:      append([]string(nil), value.DataScope.Resources...),
			Included:       value.Included,
			ExcludedReason: value.ExcludedReason,
		})
	}
	return result
}

// Check 执行权限检查。
func (s *rbacAuthorizationFacade) Check(ctx context.Context, req RBACCheckRequest) (RBACCheckResult, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return RBACCheckResult{}, err
	}
	service, err := s.authzService(call)
	if err != nil {
		return RBACCheckResult{}, err
	}
	caller, err := s.authzCaller(call)
	if err != nil {
		return RBACCheckResult{}, err
	}
	mode := authz.Mode(req.Mode)
	if req.Mode == "" {
		mode = authz.ModeAll
	}
	result, err := service.Check(ctx, caller, authz.CheckRequest{
		SubjectUserID: req.SubjectUserID, ScopeID: req.ScopeID,
		Permissions: append([]string(nil), req.Permissions...), Mode: mode})
	if err != nil {
		return RBACCheckResult{}, call.domainError("权限检查失败", string(authz.CodeOf(err)))
	}
	decisions := make([]RBACPermissionDecision, 0, len(result.Permissions))
	for _, decision := range result.Permissions {
		decisions = append(decisions, RBACPermissionDecision{
			Key: decision.Key, Allowed: decision.Allowed, Code: string(decision.Code),
			Reason: decision.Reason, Sources: rbacSources(decision.Sources),
			DataScopeMode:      string(decision.DataScope.Mode),
			DataScope:          append([]string(nil), decision.DataScope.Resources...),
			SourceLimitReached: decision.SourceLimitReached,
		})
	}
	return RBACCheckResult{SubjectUserID: result.SubjectUserID, ScopeID: result.Scope.ID,
		Mode: string(result.Mode), Allowed: result.Allowed, Code: string(result.Code),
		Reason: result.Reason, Permissions: decisions,
		SourceLimitReached: result.SourceLimitReached}, nil
}

// EffectivePermissions 分页读取有效权限。
func (s *rbacAuthorizationFacade) EffectivePermissions(ctx context.Context,
	req RBACEffectiveRequest) (RBACEffectiveResult, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return RBACEffectiveResult{}, err
	}
	page, err := call.page(req.Page)
	if err != nil {
		return RBACEffectiveResult{}, err
	}
	service, err := s.authzService(call)
	if err != nil {
		return RBACEffectiveResult{}, err
	}
	caller, err := s.authzCaller(call)
	if err != nil {
		return RBACEffectiveResult{}, err
	}
	result, err := service.EffectivePermissions(ctx, caller, req.SubjectUserID, req.ScopeID,
		authz.ListOptions{Limit: page.Limit, Offset: page.Offset})
	if err != nil {
		return RBACEffectiveResult{}, call.domainError("读取有效权限失败", string(authz.CodeOf(err)))
	}
	permissions := make([]RBACEffectivePermission, 0, len(result.Permissions))
	for _, permission := range result.Permissions {
		permissions = append(permissions, RBACEffectivePermission{
			Key: permission.Key, Name: permission.Name, ScopeID: permission.ScopeID,
			DataScopeMode: string(permission.DataScope.Mode),
			DataScope:     append([]string(nil), permission.DataScope.Resources...),
			Sources:       rbacSources(permission.Sources),
		})
	}
	return RBACEffectiveResult{SubjectUserID: result.SubjectUserID, ScopeID: result.Scope.ID,
		AccountStatus: string(result.AccountStatus), ApplicationStatus: string(result.ApplicationStatus),
		MembershipStatus: string(result.MembershipStatus), DeniedCode: string(result.DeniedCode),
		DeniedReason: result.DeniedReason, Permissions: permissions, HasMore: result.HasMore,
		Page:               NewAdminPageInfo(page, len(permissions), result.HasMore),
		SourceLimitReached: result.SourceLimitReached}, nil
}

// PermissionSources 查询指定权限来源。
func (s *rbacAuthorizationFacade) PermissionSources(ctx context.Context,
	req RBACPermissionSourcesRequest) (RBACPermissionSourcesResult, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return RBACPermissionSourcesResult{}, err
	}
	page, err := call.page(req.Page)
	if err != nil {
		return RBACPermissionSourcesResult{}, err
	}
	service, err := s.authzService(call)
	if err != nil {
		return RBACPermissionSourcesResult{}, err
	}
	caller, err := s.authzCaller(call)
	if err != nil {
		return RBACPermissionSourcesResult{}, err
	}
	result, err := service.PermissionSources(ctx, caller, req.SubjectUserID, req.ScopeID,
		req.PermissionKey, authz.ListOptions{Limit: page.Limit, Offset: page.Offset})
	if err != nil {
		return RBACPermissionSourcesResult{}, call.domainError("读取权限来源失败",
			string(authz.CodeOf(err)))
	}
	sources := rbacSources(result.Sources)
	return RBACPermissionSourcesResult{SubjectUserID: result.SubjectUserID,
		ScopeID: result.Scope.ID, AccountStatus: string(result.AccountStatus),
		ApplicationStatus: string(result.ApplicationStatus),
		MembershipStatus:  string(result.MembershipStatus), PermissionKey: result.PermissionKey,
		PermissionName: result.PermissionName, PermissionFound: result.PermissionFound,
		Sources: sources, HasMore: result.HasMore,
		Page: NewAdminPageInfo(page, len(sources), result.HasMore)}, nil
}

// CheckResourceAccess 执行资源级数据范围判定。
func (s *rbacAuthorizationFacade) CheckResourceAccess(ctx context.Context,
	req RBACResourceAccessRequest) (RBACResourceDecision, error) {
	call, err := s.f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return RBACResourceDecision{}, err
	}
	service, err := s.authzService(call)
	if err != nil {
		return RBACResourceDecision{}, err
	}
	caller, err := s.authzCaller(call)
	if err != nil {
		return RBACResourceDecision{}, err
	}
	result, err := service.CheckResourceAccess(ctx, caller, req.SubjectUserID, req.ScopeID,
		req.PermissionKey, req.ResourceID)
	if err != nil {
		return RBACResourceDecision{}, call.domainError("资源授权检查失败",
			string(authz.CodeOf(err)))
	}
	return RBACResourceDecision{Allowed: result.Allowed, Code: string(result.Code),
		Reason: result.Reason, PermissionKey: result.Permission, ResourceID: result.ResourceID,
		DataScopeMode: string(result.DataScope.Mode),
		DataScope:     append([]string(nil), result.DataScope.Resources...)}, nil
}
