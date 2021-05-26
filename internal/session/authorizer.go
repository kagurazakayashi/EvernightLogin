package session

import (
	"context"
	"fmt"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
)

// ScopeAuthorizer 判定管理员能否按范围强制下线。生产实现应基于既有授权语义
// （internal/authz 的有效权限与作用范围、角色/权限启停、应用成员与数据范围），
// 并且只接受可信边界建立的操作者身份，绝不采用客户端自称的角色或范围。
//
// 约定：
//   - scopeAppID 为空表示系统范围；非空表示仅该应用范围。实现必须在该范围内
//     校验 sessions.revoke 权限；系统范围使用系统权限，应用范围使用该应用的
//     应用独有权限。
//   - 应用范围实现还必须拒绝目标是受保护账户（root 及持有系统管理权限的账户）
//     的情形，防止应用管理员借强制下线影响系统管理员。
//   - 任何不确定/依赖故障都必须返回错误（调用方按 ACCESS_DENIED fail-closed）。
type ScopeAuthorizer interface {
	AuthorizeSessionRevoke(ctx context.Context, actor audit.Actor, scopeAppID, targetUserID string) error
}

// PermissionChecker 是 internal/authz.Service 中本包使用的最小只读接口，便于
// 生产装配与测试替身；它不是新的授权实现，也不缓存权限结果。
type PermissionChecker interface {
	Check(ctx context.Context, caller authz.Caller, request authz.CheckRequest) (authz.CheckResult, error)
	EffectivePermissions(ctx context.Context, caller authz.Caller, subjectUserID, scopeID string, options authz.ListOptions) (authz.EffectiveResult, error)
}

// protectedTargetPermissions 是“受保护管理能力”的权限机器标识集合，逐项对照
// internal/preset 的权限目录（系统权限键）维护。应用范围管理员不得强制下线持有
// 任一此类系统权限的账户，避免借应用会话撤销影响系统管理。该集合只用来追加保护
// （宁可拒绝），不是授予依据；新增目录权限时同步复查。
var protectedTargetPermissions = map[string]struct{}{
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

// AuthzAuthorizer 用既有 internal/authz 引擎实现 ScopeAuthorizer：
//  1. 以操作者本人身份在目标作用范围检查 sessions.revoke 权限（普通用户只能检查
//     自己，符合 authz 查询授权语义）；
//  2. 应用范围追加目标保护：用受限系统服务身份查询目标账户的系统范围有效权限，
//     若目标持有任一系统管理能力或查询被拒绝，则拒绝强制下线。
//
// 系统范围不额外按数据范围裁剪：authz 的数据范围收缩尚未完整落地，本步不伪造
// 数据范围授权；目标保护由会话服务另行拒绝 root，越界应用会话由服务端按 app 绑定
// 拒绝。宿主接入数据范围时应在 Authorizer 或后续策略层补充。
type AuthzAuthorizer struct {
	checker      PermissionChecker
	systemCaller authz.Caller
}

// NewAuthzAuthorizer 构造基于 authz 引擎的范围授权器；checker 为空时返回
// ErrOptionsInvalid，不会创建默认放行实现。
func NewAuthzAuthorizer(checker PermissionChecker) (*AuthzAuthorizer, error) {
	if isNilInterface(checker) {
		return nil, fmt.Errorf("%w: 权限检查器为空", ErrOptionsInvalid)
	}
	systemCaller, err := authz.SystemCaller("session-service")
	if err != nil {
		return nil, fmt.Errorf("%w: 无法构造受限系统查询身份", ErrOptionsInvalid)
	}
	return &AuthzAuthorizer{checker: checker, systemCaller: systemCaller}, nil
}

// AuthorizeSessionRevoke 实现 ScopeAuthorizer；所有失败统一返回 ErrAccessDenied，
// 不把 authz 内部错误码或目标状态细节暴露给调用方。
func (a *AuthzAuthorizer) AuthorizeSessionRevoke(ctx context.Context, actor audit.Actor, scopeAppID, targetUserID string) error {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if actor.Type != audit.ActorUser || !account.ValidUserID(actor.ID) {
		return ErrAccessDenied
	}
	caller, err := authz.UserCaller(actor.ID)
	if err != nil {
		return ErrAccessDenied
	}
	scopeID := "system"
	if scopeAppID != "" {
		if !validAppID(scopeAppID) {
			return ErrAccessDenied
		}
		scopeID = scopeAppID
	}
	result, err := a.checker.Check(ctx, caller, authz.CheckRequest{
		SubjectUserID: actor.ID,
		ScopeID:       scopeID,
		Permissions:   []string{PermissionSessionsRevoke},
		Mode:          authz.ModeAll,
	})
	if err != nil || !result.Allowed {
		return ErrAccessDenied
	}
	if scopeAppID == "" || targetUserID == "" {
		return nil
	}
	// 应用范围目标保护：目标持有系统管理能力时，应用管理员不得强制其下线。
	// 目标权限目录用最大页大小读取；出现 HasMore 或来源截断时无法证明保护集
	// 完整，按 fail-closed 拒绝（避免受保护权限位于后续页时漏判）。
	target, err := a.checker.EffectivePermissions(ctx, a.systemCaller, targetUserID, "system", authz.ListOptions{Limit: authz.MaxListLimit})
	if err != nil {
		return ErrAccessDenied
	}
	if target.DeniedCode != "" || target.SubjectUserID != targetUserID {
		return ErrAccessDenied
	}
	if target.HasMore || target.SourceLimitReached {
		return ErrAccessDenied
	}
	for _, permission := range target.Permissions {
		if _, protected := protectedTargetPermissions[permission.Key]; protected {
			return ErrAccessDenied
		}
	}
	return nil
}

// 编译期确认实现 ScopeAuthorizer。
var _ ScopeAuthorizer = (*AuthzAuthorizer)(nil)
