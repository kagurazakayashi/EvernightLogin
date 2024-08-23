package app

import (
	"context"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/profile"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
	"strings"
)

// adminFacade 实现 AdminService。
type adminFacade struct{ r *Runtime }

// adminIdentity 是解析后的可信管理身份。
type adminIdentity struct {
	actor  audit.Actor
	local  bool
	userID string
	// sessionSecret 是普通管理会话调用者出示的会话秘密副本；仅用于会话领域内需要
	// “真实管理会话”参与判定的读取（如管理员按范围查询目标会话）。LocalAdmin 没有
	// 会话秘密，不能用于这类入口。秘密只在本次调用内使用，不写入日志/错误/结果。
	sessionSecret []byte
}

// adminRequest 是一次受信管理调用的可信上下文：可信身份与本次调用的请求编号。
// 请求编号只解析一次，之后领域调用者、领域审计与返回错误共用同一个值。
type adminRequest struct {
	identity  adminIdentity
	requestID string
}

// begin 统一完成一次受信管理调用的前置：
//  1. 解析请求编号：空编号按统一规则生成一次，非法编号返回 REQ_INVALID，且不执行
//     任何领域查询或写入；
//  2. 解析可信管理调用者：校验 Runtime 归属、LocalAdmin/AdminSession 形式与真实
//     会话状态；零值、伪造组合、其他 Runtime 的调用者一律 ACCESS_DENIED。
//
// 身份解析与领域权限检查都严格先于目标数据查询：各领域服务先判权再读取目标，因此
// 未授权调用者不能借“未找到/存在”差异探测记录。
func (f *adminFacade) begin(ctx context.Context, caller AdminCaller,
	requestID string) (adminRequest, error) {
	id, err := resolveRequestID(ctx, requestID)
	if err != nil {
		return adminRequest{}, err
	}
	identity, err := f.r.resolveAdmin(ctx, caller, id)
	if err != nil {
		return adminRequest{}, err
	}
	return adminRequest{identity: identity, requestID: id}, nil
}

// requestIDBinder 是所有领域服务调用者共有的“附加请求编号”能力。
type requestIDBinder[T any] interface {
	WithRequestID(string) (T, error)
}

// bindCaller 把本次已解析的请求编号附加到领域服务调用者，使领域审计与公开错误
// 关联同一个编号；编号已在 begin 中校验，这里失败说明领域实现口径不一致，按配置
// 错误 fail-closed。
func bindCaller[T requestIDBinder[T]](caller T, requestID string) (T, error) {
	bound, err := caller.WithRequestID(requestID)
	if err != nil {
		var zero T
		return zero, configError("领域服务请求编号无效", requestID)
	}
	return bound, nil
}

// accountCaller 按身份构造账户服务可信调用者。
func (f *adminFacade) accountCaller(id adminIdentity) (account.Caller, error) {
	if id.local {
		return account.LocalBootstrapCaller(id.actor.ID)
	}
	return account.UserCaller(id.userID)
}

// appCaller 构造应用服务可信调用者。
func (f *adminFacade) appCaller(id adminIdentity) (app.Caller, error) {
	if id.local {
		return app.LocalBootstrapCaller(id.actor.ID)
	}
	return app.UserCaller(id.userID)
}

// profileCaller 构造资料服务可信调用者。
func (f *adminFacade) profileCaller(id adminIdentity) (profile.Caller, error) {
	if id.local {
		return profile.LocalAdminCaller(id.actor.ID)
	}
	return profile.UserCaller(id.userID)
}

// roleCaller 构造角色服务可信调用者。
func (f *adminFacade) roleCaller(id adminIdentity) (role.Caller, error) {
	if id.local {
		return role.LocalBootstrapCaller(id.actor.ID)
	}
	return role.UserCaller(id.userID)
}

// permissionCaller 构造权限目录服务可信调用者。
func (f *adminFacade) permissionCaller(id adminIdentity) (permission.Caller, error) {
	if id.local {
		return permission.LocalBootstrapCaller(id.actor.ID)
	}
	return permission.UserCaller(id.userID)
}

// authzCaller 构造权限引擎可信调用者。
func (f *adminFacade) authzCaller(id adminIdentity) (authz.Caller, error) {
	if id.local {
		return authz.LocalBootstrapCaller(id.actor.ID)
	}
	return authz.UserCaller(id.userID)
}

// sensitiveContext 为敏感管理操作准备可信上下文：
//   - 用户主体：真实 reauth 挑战（密码 + 强认证要求的动态码），信号来自真实验证；
//   - 本机受信操作者：先写独立审计事件（操作/目标），再以本地管理员事实执行。
//
// 本机受信通道不是 is_root、不改变 root 保护，也不用于用户主体；用户主体永远
// 不会走该分支，避免用伪造强认证结果完成用户正向流程。requestID 是本次调用已解析
// 的编号，审计事件与返回错误共用它。
func (f *adminFacade) sensitiveContext(ctx context.Context, id adminIdentity,
	operationID, targetType, targetID string, params map[string]string,
	password, totpCode, requestID string) (context.Context, error) {
	if id.local {
		if f.r.base == nil || f.r.base.Audit == nil {
			return ctx, configError("审计服务未装配", requestID)
		}
		if err := f.r.base.Audit.Record(ctx, audit.Event{
			Actor: id.actor, Action: "admin.local_operator.sensitive_approved",
			Target:    audit.Target{Type: targetType, ID: targetID},
			RequestID: requestID,
			Outcome:   audit.OutcomeSuccess,
			Changes: []audit.FieldChange{
				{Field: "operation_id", After: operationID},
			},
		}); err != nil {
			return ctx, mapDomainError("本机受信操作审计不可用", "AUDIT_WRITE_FAILED", requestID)
		}
		return reauth.WithSignals(ctx, reauth.Signals{
			VerifiedAt: f.r.runtimeNow().UTC(), Strength: policy.StrengthStrong,
			Complete: true, Confirmed: true,
		}), nil
	}
	gate := f.r.securityGate()
	if gate == nil || gate.Reauth == nil {
		return ctx, configError("敏感操作闸门未装配", requestID)
	}
	caller, err := reauth.UserCaller(id.userID)
	if err != nil {
		return ctx, configError("管理会话主体无效", requestID)
	}
	challenge, err := gate.Reauth.BeginChallenge(ctx, caller, reauth.ChallengeRequest{
		ScopeID: "system", OperationID: operationID, TargetType: targetType,
		TargetID: targetID, Params: params, Description: "受信管理敏感操作",
		RequestID: requestID, MinimumStrength: policy.StrengthStrong,
	})
	if err != nil {
		return ctx, mapDomainError("敏感操作再次认证未通过",
			string(reauth.CodeOf(err)), requestID)
	}
	if !challenge.Required {
		return ctx, nil
	}
	if strings.TrimSpace(password) == "" {
		return ctx, mapDomainError("敏感操作需要近期密码验证", "REAUTH_REQUIRED", requestID)
	}
	grant, err := gate.Reauth.VerifyChallenge(ctx, caller, reauth.VerifyChallengeRequest{
		ChallengeID: challenge.ID, Password: password, TOTPCode: totpCode,
		RequestID: requestID,
	})
	if err != nil {
		return ctx, mapDomainError("敏感操作再次认证未通过",
			string(reauth.CodeOf(err)), requestID)
	}
	return reauth.WithSignals(ctx, reauth.Signals{
		VerifiedAt: f.r.runtimeNow().UTC(), Strength: grant.GrantedStrength,
		Complete: true, Confirmed: true, ApprovalToken: grant.Token,
	}), nil
}

// groupCaller 构造用户组服务可信调用者。
func (f *adminFacade) groupCaller(id adminIdentity) (group.Caller, error) {
	if id.local {
		return group.LocalBootstrapCaller(id.actor.ID)
	}
	return group.UserCaller(id.userID)
}
