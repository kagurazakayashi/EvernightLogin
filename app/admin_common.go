package app

// 受信管理门面（步骤 182；步骤 207 补齐请求关联与未找到错误契约）。
//
// 设计边界：
//   - 调用者只能由 Runtime.LocalAdmin()（本机受信操作者 = 宿主进程/部署管理员，
//     审计主体为本地管理员）或 Runtime.AdminSession()（真实用户会话）建立；零值、
//     其他 Runtime 的调用者或普通请求参数都不能自称管理员。
//   - 用户主体的一切操作复用真实领域服务与既有授权/委派/审计：权限按当前有效授权
//     计算，角色分配等敏感操作还要经真实 reauth 挑战（密码 + 强因素动态码）。
//   - 本机受信操作者仅用于宿主自举（首次管理员/应用/角色/权限引导），不是 is_root，
//     不改变 root 账户保护；其敏感操作单独写审计事件后执行，不与用户强认证混用。
//   - 管理员建用户直接走账户服务，与 registration.enabled 无关；应用内授权与应用
//     成员关系按应用范围判定，与全局账户资格分离。
//   - 不提供传入 is_root / 系统资格 / 已验证状态的字段；root 账户由既有服务保护。
//   - 请求关联：每次调用先把请求编号统一解析一次（空编号生成、非法编号拒绝），
//     再把同一个编号附加到领域调用者/请求、领域审计与返回错误，不重复生成。
//   - 未找到语义：已通过身份与权限检查的查询若确认目标不存在，返回稳定的公开
//     NotFoundError（NotFoundCode = "NOT_FOUND"，见 errors.go），与“参数非法”
//     REQ_INVALID、“权限不足” ACCESS_DENIED 区分；未通过权限检查时只返回拒绝码，
//     不会用“未找到”泄露记录是否存在。匿名登录/找回入口仍使用防枚举响应。

import (
	"context"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
	"strings"
)

// 领域服务要求角色/权限的限制说明非空；门面未收到时使用保守的直白默认值。
const (
	defaultAdminRoleLimits       = "具体使用边界由管理员维护；不得用于跨应用或扩大系统资格。"
	defaultAdminPermissionLimits = "具体使用边界由管理员维护；不得用于跨应用或扩大系统资格。"
)

// LocalAdmin 返回本机受信管理调用者：代表宿主进程（部署管理员，Options.OperatorID）。
// 它不是 is_root，不能改变 root 账户保护；只用于宿主自举与受控管理。
func (r *Runtime) LocalAdmin() AdminCaller {
	if r == nil {
		return AdminCaller{}
	}
	return AdminCaller{runtime: r, local: true}
}

// AdminSession 返回基于真实用户会话的管理调用者；会话必须是完整（非受限）会话，
// 且调用时仍有效。权限按当前有效授权计算，不缓存。
func (r *Runtime) AdminSession(sessionSecret []byte) AdminCaller {
	if r == nil || len(sessionSecret) == 0 {
		return AdminCaller{}
	}
	secret := make([]byte, len(sessionSecret))
	copy(secret, sessionSecret)
	return AdminCaller{runtime: r, sessionSecret: secret}
}

// configError 返回带本次请求编号的 CONFIG_INVALID 公开错误。
func (a adminRequest) configError(message string) error {
	return configError(message, a.requestID)
}

// page 规范化公开分页输入，并把非法值映射为带本次请求编号的 REQ_INVALID 错误
// （请求编号贯穿调用、审计与返回错误）。
func (a adminRequest) page(page AdminPage) (AdminPage, error) {
	normalized, err := NormalizeAdminPage(page)
	if err != nil {
		return AdminPage{}, mapDomainError("分页参数无效", "REQ_INVALID", a.requestID)
	}
	return normalized, nil
}

// domainError 返回带本次请求编号的公开领域错误。
func (a adminRequest) domainError(message, code string) error {
	return mapDomainError(message, code, a.requestID)
}

// notFound 构造带本次请求编号的公开未找到错误。
func (a adminRequest) notFound(resource string) error {
	return newNotFoundError(resource, a.requestID)
}

// notFoundIfTargetMissing 把领域“目标不存在”错误转换为公开 NotFoundError；返回
// ok=false 表示不是未找到错误，调用方按领域码投影。
func (a adminRequest) notFoundIfTargetMissing(err, sentinel error,
	resource string) (error, bool) {
	return notFoundWhen(err, sentinel, resource, a.requestID)
}

// roleError 把角色/委派领域的稳定错误码映射为带本次请求编号的公开错误；委派拒绝
// （越权转授、自我提权、目标白名单等）优先按委派领域错误码投影，避免被折叠成
// INTERNAL_ERROR。
func (a adminRequest) roleError(message string, err error) error {
	if code := delegation.CodeOf(err); code != "" {
		return a.domainError(message, string(code))
	}
	return a.domainError(message, string(role.CodeOf(err)))
}

// resolveAdmin 校验管理调用者并返回可信身份；任何无效/伪造上下文一律拒绝。
// requestID 是本次调用的请求编号，会带入所有返回错误。
func (r *Runtime) resolveAdmin(ctx context.Context, caller AdminCaller,
	requestID string) (adminIdentity, error) {
	services := r.coreServices()
	if services == nil {
		return adminIdentity{}, configError("服务未装配", requestID)
	}
	if caller.runtime == nil || caller.runtime != r {
		return adminIdentity{}, mapDomainError("管理调用上下文无效", "ACCESS_DENIED", requestID)
	}
	if caller.local && len(caller.sessionSecret) > 0 {
		return adminIdentity{}, mapDomainError("管理调用上下文无效", "ACCESS_DENIED", requestID)
	}
	if caller.local {
		operatorID := strings.TrimSpace(r.opts.OperatorID)
		actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: operatorID}
		if err := actor.Validate(); err != nil {
			return adminIdentity{}, mapDomainError("本机受信操作者标识无效", "ACCESS_DENIED", requestID)
		}
		return adminIdentity{actor: actor, local: true}, nil
	}
	record, err := services.Sessions.Validate(ctx, string(caller.sessionSecret))
	if err != nil || !record.IsNormal() || record.UserID == "" {
		return adminIdentity{}, mapDomainError("管理会话无效或不是完整会话",
			"ACCESS_DENIED", requestID)
	}
	actor := audit.Actor{Type: audit.ActorUser, ID: record.UserID}
	if err := actor.Validate(); err != nil {
		return adminIdentity{}, mapDomainError("管理会话主体无效", "ACCESS_DENIED", requestID)
	}
	secretCopy := make([]byte, len(caller.sessionSecret))
	copy(secretCopy, caller.sessionSecret)
	return adminIdentity{actor: actor, userID: record.UserID, sessionSecret: secretCopy}, nil
}

var _ AdminService = (*adminFacade)(nil)
