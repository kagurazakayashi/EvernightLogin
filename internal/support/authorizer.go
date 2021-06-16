package support

import (
	"context"
	"fmt"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	"github.com/kagurazakayashi/EvernightLogin/internal/preset"
)

// PermissionChecker 是 internal/authz.Service 中本包使用的最小只读接口，便于生产
// 装配与测试替身；它不是新的授权实现，也不缓存权限结果。
type PermissionChecker interface {
	Check(ctx context.Context, caller authz.Caller, request authz.CheckRequest) (authz.CheckResult, error)
	EffectivePermissions(ctx context.Context, caller authz.Caller, subjectUserID, scopeID string, options authz.ListOptions) (authz.EffectiveResult, error)
}

// baselineProtectedTargetPermissions 是人工维护的“受保护高权限能力”系统权限机器
// 标识基线；启动时与 internal/preset 权限目录交叉自检（见 buildProtectedTargetPermissions）：
// 基线中的每个权限必须存在于目录（防拼写/改名漂移），目录中新增的 RootOnly 或
// RequiresReauth 权限会自动并入保护集合（防目录新增高权限项漏判）。目标持有任一
// 此类权限即视为高权限账户，普通客服不得处理；该集合只追加保护（宁可拒绝），不是
// 授予依据。
var baselineProtectedTargetPermissions = map[string]struct{}{
	"users.create":                    {},
	"users.update":                    {},
	"users.disable":                   {},
	"users.delete":                    {},
	"users.export":                    {},
	"recovery.approve":                {},
	"recovery.mfa.approve":            {},
	"groups.manage":                   {},
	"roles.manage":                    {},
	"roles.assign":                    {},
	"permissions.manage":              {},
	"permissions.state.update":        {},
	"applications.create":             {},
	"applications.update":             {},
	"applications.credentials.manage": {},
	"applications.members.manage":     {},
	"sessions.revoke":                 {},
	"audit.read":                      {},
	"audit.export":                    {},
	"audit.purge":                     {},
	"reports.read":                    {},
	"reports.generate":                {},
	"reports.export":                  {},
	"reports.schedule.manage":         {},
	"backups.create":                  {},
	"backups.read":                    {},
	"backups.cancel":                  {},
	"backups.export":                  {},
	"backups.restore":                 {},
	"security.policy.manage":          {},
	"settings.manage":                 {},
	"diagnostics.read":                {},
}

// buildProtectedTargetPermissions 由人工基线与 internal/preset 权限目录元数据生成
// 最终保护集合，并做启动自检：基线权限缺失或目录声明 RootOnly/RequiresReauth 的
// 权限未进入保护集合都视为配置漂移错误（fail-closed，拒绝构造授权器）。
func buildProtectedTargetPermissions(definitions []preset.PermissionDefinition) (map[string]struct{}, error) {
	protected := make(map[string]struct{}, len(baselineProtectedTargetPermissions)+len(definitions))
	for key := range baselineProtectedTargetPermissions {
		protected[key] = struct{}{}
	}
	known := make(map[string]preset.PermissionDefinition, len(definitions))
	for _, definition := range definitions {
		known[definition.Key] = definition
	}
	for key := range baselineProtectedTargetPermissions {
		if _, exists := known[key]; !exists {
			return nil, fmt.Errorf("%w: 受保护权限清单中的 %q 不在权限目录中（目录漂移）",
				ErrOptionsInvalid, key)
		}
	}
	for _, definition := range definitions {
		if definition.RootOnly || definition.RequiresReauth {
			protected[definition.Key] = struct{}{}
		}
	}
	if len(protected) == 0 {
		return nil, fmt.Errorf("%w: 受保护权限集合为空", ErrOptionsInvalid)
	}
	return protected, nil
}

// AuthzAuthorizer 用既有 internal/authz 引擎实现 Authorizer：
//   - AuthorizeStaff 以工作人员本人身份在系统范围检查功能权限；普通用户只能检查
//     自己，符合 authz 查询授权语义；
//   - StaffEligible 用受限系统查询身份检查指定用户是否持有 support.cases.read；
//   - 数据范围为 all 表示覆盖全部普通用户；resources 表示仅显式列出的用户；
//     undefined/none 一律拒绝（不能把“未声明”当成全部数据）。
type AuthzAuthorizer struct {
	checker      PermissionChecker
	systemCaller authz.Caller
}

// NewAuthzAuthorizer 构造基于 authz 引擎的客服授权器；checker 为空（含 typed-nil）
// 时返回错误，不创建默认放行实现。
func NewAuthzAuthorizer(checker PermissionChecker) (*AuthzAuthorizer, error) {
	if isNilDependency(checker) {
		return nil, fmt.Errorf("%w: 权限检查器为空", ErrOptionsInvalid)
	}
	systemCaller, err := authz.SystemCaller("support-service")
	if err != nil {
		return nil, fmt.Errorf("%w: 无法构造受限系统查询身份", ErrOptionsInvalid)
	}
	return &AuthzAuthorizer{checker: checker, systemCaller: systemCaller}, nil
}

// AuthorizeStaff 实现 Authorizer。
func (a *AuthzAuthorizer) AuthorizeStaff(ctx context.Context, staffUserID, permissionKey string) (StaffScope, error) {
	ctx = normalizeContext(ctx)
	if !account.ValidUserID(staffUserID) || permissionKey == "" {
		return StaffScope{}, ErrAccessDenied
	}
	caller, err := authz.UserCaller(staffUserID)
	if err != nil {
		return StaffScope{}, ErrAccessDenied
	}
	result, err := a.checker.Check(ctx, caller, authz.CheckRequest{
		SubjectUserID: staffUserID,
		ScopeID:       "system",
		Permissions:   []string{permissionKey},
		Mode:          authz.ModeAll,
	})
	if err != nil {
		return StaffScope{}, fmt.Errorf("%w: %w", ErrAuthzUnavailable, err)
	}
	if !result.Allowed || result.SourceLimitReached {
		return StaffScope{}, ErrAccessDenied
	}
	scope := StaffScope{}
	found := false
	for _, decision := range result.Permissions {
		if decision.Key != permissionKey || !decision.Allowed || decision.SourceLimitReached {
			continue
		}
		found = true
		switch decision.DataScope.Mode {
		case authz.DataScopeAll:
			scope.AllUsers = true
		case authz.DataScopeResources:
			scope.UserIDs = append(scope.UserIDs, decision.DataScope.Resources...)
		default:
			// undefined/none：无法证明数据范围，fail-closed。
			return StaffScope{}, ErrAccessDenied
		}
	}
	if !found {
		return StaffScope{}, ErrAccessDenied
	}
	if !scope.AllUsers && len(scope.UserIDs) == 0 {
		return StaffScope{}, ErrAccessDenied
	}
	return scope, nil
}

// StaffEligible 实现 Authorizer；未授予客服读取能力或依赖故障按不具备资格处理。
func (a *AuthzAuthorizer) StaffEligible(ctx context.Context, staffUserID string) (bool, error) {
	ctx = normalizeContext(ctx)
	if !account.ValidUserID(staffUserID) {
		return false, nil
	}
	result, err := a.checker.Check(ctx, a.systemCaller, authz.CheckRequest{
		SubjectUserID: staffUserID,
		ScopeID:       "system",
		Permissions:   []string{PermissionCasesRead},
		Mode:          authz.ModeAll,
	})
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrAuthzUnavailable, err)
	}
	if !result.Allowed || result.SourceLimitReached {
		return false, nil
	}
	return true, nil
}

// AuthzTargetProtector 用 internal/authz 的有效权限查询识别高权限账户：目标在系统
// 范围持有任一受保护权限、为 root（普通权限引擎对 root 返回拒绝）或有效权限无法
// 完整证明时，一律视为受保护，普通客服不能处理。
type AuthzTargetProtector struct {
	checker      PermissionChecker
	systemCaller authz.Caller
	protected    map[string]struct{}
}

// NewAuthzTargetProtector 构造目标保护识别器；checker 为空（含 typed-nil）时返回错误。
func NewAuthzTargetProtector(checker PermissionChecker) (*AuthzTargetProtector, error) {
	if isNilDependency(checker) {
		return nil, fmt.Errorf("%w: 权限检查器为空", ErrOptionsInvalid)
	}
	systemCaller, err := authz.SystemCaller("support-target-check")
	if err != nil {
		return nil, fmt.Errorf("%w: 无法构造受限系统查询身份", ErrOptionsInvalid)
	}
	catalog := preset.DefaultCatalog()
	if catalog == nil {
		return nil, fmt.Errorf("%w: 权限目录不可用", ErrOptionsInvalid)
	}
	protected, err := buildProtectedTargetPermissions(catalog.Permissions)
	if err != nil {
		return nil, err
	}
	return &AuthzTargetProtector{checker: checker, systemCaller: systemCaller, protected: protected}, nil
}

// Protected 实现 TargetProtector。
func (p *AuthzTargetProtector) Protected(ctx context.Context, targetUserID string) (bool, error) {
	ctx = normalizeContext(ctx)
	if !account.ValidUserID(targetUserID) {
		return true, nil
	}
	target, err := p.checker.EffectivePermissions(ctx, p.systemCaller, targetUserID, "system",
		authz.ListOptions{Limit: authz.MaxListLimit})
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrAuthzUnavailable, err)
	}
	// 拒绝（root/停用等）或结果不完整：无法证明是普通账户，按受保护处理。
	if target.DeniedCode != "" || target.SubjectUserID != targetUserID {
		return true, nil
	}
	if target.HasMore || target.SourceLimitReached {
		return true, nil
	}
	for _, permission := range target.Permissions {
		if _, protected := p.protected[permission.Key]; protected {
			return true, nil
		}
	}
	return false, nil
}

// 编译期确认实现 Authorizer / TargetProtector。
var (
	_ Authorizer      = (*AuthzAuthorizer)(nil)
	_ TargetProtector = (*AuthzTargetProtector)(nil)
)
