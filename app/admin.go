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
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/profile"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
)

// adminFacade 实现 AdminService。
type adminFacade struct{ r *Runtime }

// 领域服务要求角色/权限的限制说明非空；门面未收到时使用保守的直白默认值。
const (
	defaultAdminRoleLimits       = "具体使用边界由管理员维护；不得用于跨应用或扩大系统资格。"
	defaultAdminPermissionLimits = "具体使用边界由管理员维护；不得用于跨应用或扩大系统资格。"
)

// adminIdentity 是解析后的可信管理身份。
type adminIdentity struct {
	actor  audit.Actor
	local  bool
	userID string
}

// adminRequest 是一次受信管理调用的可信上下文：可信身份与本次调用的请求编号。
// 请求编号只解析一次，之后领域调用者、领域审计与返回错误共用同一个值。
type adminRequest struct {
	identity  adminIdentity
	requestID string
}

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
	return adminIdentity{actor: actor, userID: record.UserID}, nil
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

// CreateUser 创建全局账户（与 registration.enabled 无关），可选建立应用成员关系。
func (f *adminFacade) CreateUser(ctx context.Context,
	req AdminCreateUserRequest) (AdminUser, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminUser{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Account == nil {
		return AdminUser{}, call.configError("账户服务未装配")
	}
	caller, err := f.accountCaller(call.identity)
	if err != nil {
		return AdminUser{}, call.configError("账户服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminUser{}, err
	}
	created, err := managed.Account.CreateUser(ctx, caller, account.CreateRequest{
		Username: req.Username, Nickname: req.Nickname, Biography: req.Biography,
	})
	if err != nil {
		return AdminUser{}, call.domainError("创建用户失败", string(account.CodeOf(err)))
	}
	if len(req.ApplicationIDs) > 0 {
		appCaller, callerErr := f.appCaller(call.identity)
		if callerErr != nil {
			return AdminUser{}, call.configError("应用服务调用者无效")
		}
		if appCaller, callerErr = bindCaller(appCaller, call.requestID); callerErr != nil {
			return AdminUser{}, callerErr
		}
		for _, applicationID := range req.ApplicationIDs {
			if _, memberErr := managed.App.AddApplicationMember(ctx, appCaller,
				app.AddMemberRequest{ApplicationID: applicationID, UserID: created.ID}); memberErr != nil {
				// 账户已创建但成员关系失败：不回滚全局账户（删除账户是更高风险操作），
				// 返回明确错误供宿主核对；不使用事务跨领域伪装整体成功。
				return AdminUser{}, call.domainError("创建用户后建立应用成员关系失败",
					string(app.CodeOf(memberErr)))
			}
		}
	}
	return AdminUser{ID: created.ID, Username: created.Username,
		Nickname: created.Nickname, Status: string(created.Status),
		CreatedAt: created.CreatedAt}, nil
}

// ListUsers 分页查询用户（本机受信通道，或系统范围 users.read 权限）。
//
// 注意区分“领域操作名”与“授权权限键”：领域内部审计动作是 user.list（由账户服务
// 写入），实际检查的权限键是 users.read（系统范围）；两者不是同一个字符串。
func (f *adminFacade) ListUsers(ctx context.Context,
	req AdminListUsersRequest) (AdminUserList, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminUserList{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Account == nil {
		return AdminUserList{}, call.configError("账户服务未装配")
	}
	caller, err := f.accountCaller(call.identity)
	if err != nil {
		return AdminUserList{}, call.configError("账户服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminUserList{}, err
	}
	page, err := call.page(AdminPage{Limit: req.Limit, Offset: req.Offset})
	if err != nil {
		return AdminUserList{}, err
	}
	result, err := managed.Account.ListUsers(ctx, caller, account.ListRequest{
		Limit: page.Limit, Offset: page.Offset, Status: account.Status(req.Status),
		Sort: account.SortField(req.Sort), Descending: req.Descending,
	})
	if err != nil {
		return AdminUserList{}, call.domainError("查询用户列表失败",
			string(account.CodeOf(err)))
	}
	users := make([]AdminUser, 0, len(result.Users))
	for _, user := range result.Users {
		users = append(users, adminUser(user))
	}
	return AdminUserList{Users: users, HasMore: result.HasMore,
		Page: NewAdminPageInfo(page, len(users), result.HasMore)}, nil
}

// groupCaller 构造用户组服务可信调用者。
func (f *adminFacade) groupCaller(id adminIdentity) (group.Caller, error) {
	if id.local {
		return group.LocalBootstrapCaller(id.actor.ID)
	}
	return group.UserCaller(id.userID)
}

// GetUserByUsername 按用户名读取脱敏用户记录（本机受信通道，或系统范围 users.read
// 权限）。用户名按与登录一致的 NFKC + 大小写折叠规范化后匹配。
//
// 已授权但用户不存在时返回稳定的公开 NotFoundError（NotFoundCode = "NOT_FOUND"），
// 与“用户名参数非法” REQ_INVALID 区分；未通过权限检查时只返回 ACCESS_DENIED，不
// 暴露用户是否存在。领域内部审计动作是 user.get，授权权限键是 users.read。
func (f *adminFacade) GetUserByUsername(ctx context.Context,
	req AdminUserByUsernameRequest) (AdminUser, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminUser{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Account == nil {
		return AdminUser{}, call.configError("账户服务未装配")
	}
	caller, err := f.accountCaller(call.identity)
	if err != nil {
		return AdminUser{}, call.configError("账户服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminUser{}, err
	}
	user, err := managed.Account.GetUserByUsername(ctx, caller, req.Username)
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, account.ErrUserNotFound, "user"); ok {
			return AdminUser{}, replaced
		}
		return AdminUser{}, call.domainError("按用户名查询用户失败",
			string(account.CodeOf(err)))
	}
	return adminUser(user), nil
}

// GetUserProfile 读取用户资料（本机受信通道，或系统范围 users.read 权限）。
// 已授权但目标用户不存在时返回 NotFoundError；权限先于资料读取判定。
func (f *adminFacade) GetUserProfile(ctx context.Context,
	req AdminUserRequest) (AdminUserProfile, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminUserProfile{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Profile == nil {
		return AdminUserProfile{}, call.configError("资料服务未装配")
	}
	caller, err := f.profileCaller(call.identity)
	if err != nil {
		return AdminUserProfile{}, call.configError("资料服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminUserProfile{}, err
	}
	value, err := managed.Profile.GetProfile(ctx, caller, req.UserID)
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, profile.ErrUserNotFound, "user"); ok {
			return AdminUserProfile{}, replaced
		}
		return AdminUserProfile{}, call.domainError("读取用户资料失败",
			string(profile.CodeOf(err)))
	}
	return adminUserProfile(value), nil
}

// UpdateUserProfile 修改允许管理员改写的资料字段（需要系统范围 users.update）。
// 已授权但目标用户不存在时同样返回 NotFoundError；其他失败按资料领域码投影。
func (f *adminFacade) UpdateUserProfile(ctx context.Context,
	req AdminUpdateProfileRequest) (AdminUserProfile, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminUserProfile{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Profile == nil {
		return AdminUserProfile{}, call.configError("资料服务未装配")
	}
	caller, err := f.profileCaller(call.identity)
	if err != nil {
		return AdminUserProfile{}, call.configError("资料服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminUserProfile{}, err
	}
	change := profile.ProfileChange{Nickname: req.Nickname, Biography: req.Biography,
		Language: req.Language, Timezone: req.Timezone}
	if !change.HasChanges() {
		return AdminUserProfile{}, call.configError("资料更新请求没有可修改字段")
	}
	value, err := managed.Profile.UpdateUser(ctx, caller, profile.UpdateRequest{
		TargetUserID: req.UserID, Change: change,
		ExpectedRowVersion: req.ExpectedRowVersion,
		RequestID:          call.requestID,
	})
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, profile.ErrUserNotFound, "user"); ok {
			return AdminUserProfile{}, replaced
		}
		return AdminUserProfile{}, call.domainError("更新用户资料失败",
			string(profile.CodeOf(err)))
	}
	return adminUserProfile(value), nil
}

// AddApplicationMember 把已有用户加入应用（需要该应用 applications.members.manage）。
func (f *adminFacade) AddApplicationMember(ctx context.Context, req AdminAddMemberRequest) error {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.App == nil {
		return call.configError("应用服务未装配")
	}
	caller, err := f.appCaller(call.identity)
	if err != nil {
		return call.configError("应用服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return err
	}
	if _, err := managed.App.AddApplicationMember(ctx, caller, app.AddMemberRequest{
		ApplicationID: req.ApplicationID, UserID: req.UserID,
	}); err != nil {
		return call.domainError("加入应用成员失败", string(app.CodeOf(err)))
	}
	return nil
}

// CreateApplication 登记应用（本机受信通道或系统范围 applications.create）。
func (f *adminFacade) CreateApplication(ctx context.Context,
	req AdminCreateApplicationRequest) (AdminApplication, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminApplication{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.App == nil {
		return AdminApplication{}, call.configError("应用服务未装配")
	}
	caller, err := f.appCaller(call.identity)
	if err != nil {
		return AdminApplication{}, call.configError("应用服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminApplication{}, err
	}
	owner := strings.TrimSpace(req.OwnerUserID)
	if owner == "" && !call.identity.local {
		owner = call.identity.userID
	}
	clientType := app.ClientType(strings.TrimSpace(req.ClientType))
	if clientType == "" {
		clientType = app.ClientTypeConfidential
	}
	created, err := managed.App.CreateApplication(ctx, caller, app.CreateRequest{
		Name: req.Name, Description: req.Description, OwnerUserID: owner,
		ClientType: clientType,
	})
	if err != nil {
		return AdminApplication{}, call.domainError("创建应用失败", string(app.CodeOf(err)))
	}
	return AdminApplication{ID: created.ID, Name: created.Name,
		Description: created.Description, OwnerUserID: created.OwnerUserID,
		Status: string(created.Status), RowVersion: created.RowVersion,
		CreatedAt: created.CreatedAt}, nil
}

// SetApplicationEnabled 启用或停用应用（应用启用会恢复其范围权限，由应用服务按
// 真实委派资格复核；停用不影响已有账户与角色记录）。
func (f *adminFacade) SetApplicationEnabled(ctx context.Context,
	req AdminSetApplicationEnabledRequest) (AdminApplication, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminApplication{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.App == nil {
		return AdminApplication{}, call.configError("应用服务未装配")
	}
	caller, err := f.appCaller(call.identity)
	if err != nil {
		return AdminApplication{}, call.configError("应用服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminApplication{}, err
	}
	statusRequest := app.StatusRequest{ApplicationID: req.ApplicationID,
		ExpectedRowVersion: req.ExpectedRowVersion}
	var result app.StatusResult
	if req.Enabled {
		result, err = managed.App.EnableApplication(ctx, caller, statusRequest)
	} else {
		result, err = managed.App.DisableApplication(ctx, caller, statusRequest)
	}
	if err != nil {
		return AdminApplication{}, call.domainError("应用启停失败", string(app.CodeOf(err)))
	}
	return AdminApplication{ID: result.Application.ID, Name: result.Application.Name,
		Description: result.Application.Description,
		OwnerUserID: result.Application.OwnerUserID,
		Status:      string(result.Application.Status),
		RowVersion:  result.Application.RowVersion,
		CreatedAt:   result.Application.CreatedAt}, nil
}

// CreateRole 在系统或应用范围登记角色（创建不授予任何权限）。
func (f *adminFacade) CreateRole(ctx context.Context,
	req AdminCreateRoleRequest) (AdminRole, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminRole{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Role == nil {
		return AdminRole{}, call.configError("角色服务未装配")
	}
	caller, err := f.roleCaller(call.identity)
	if err != nil {
		return AdminRole{}, call.configError("角色服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminRole{}, err
	}
	// 领域服务要求角色说明与限制说明非空；未提供时使用直白默认值（不含秘密）。
	description := strings.TrimSpace(req.Description)
	if description == "" {
		description = req.Name
	}
	limits := strings.TrimSpace(req.Limits)
	if limits == "" {
		limits = defaultAdminRoleLimits
	}
	created, err := managed.Role.CreateRole(ctx, caller, role.CreateRequest{
		ScopeID: req.ScopeID, Key: req.Key, Name: req.Name, Description: description,
		Limits: limits,
	})
	if err != nil {
		return AdminRole{}, call.domainError("创建角色失败", string(role.CodeOf(err)))
	}
	return AdminRole{ID: created.ID, ScopeID: created.ScopeID,
		ApplicationID: created.ApplicationID, Key: created.Key, Name: created.Name,
		Enabled: created.Enabled}, nil
}

// CreatePermission 在系统或应用范围登记自定义权限。
func (f *adminFacade) CreatePermission(ctx context.Context,
	req AdminCreatePermissionRequest) (AdminPermission, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminPermission{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Permission == nil {
		return AdminPermission{}, call.configError("权限服务未装配")
	}
	caller, err := f.permissionCaller(call.identity)
	if err != nil {
		return AdminPermission{}, call.configError("权限服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminPermission{}, err
	}
	// 领域服务要求权限说明与限制说明非空；未提供时使用直白默认值。
	description := strings.TrimSpace(req.Description)
	if description == "" {
		description = req.Name
	}
	limits := strings.TrimSpace(req.Limits)
	if limits == "" {
		limits = defaultAdminPermissionLimits
	}
	created, err := managed.Permission.CreatePermission(ctx, caller, permission.CreateRequest{
		ScopeID: req.ScopeID, Key: req.Key, Name: req.Name, Description: description,
		Limits: limits,
	})
	if err != nil {
		return AdminPermission{}, call.domainError("创建权限失败",
			string(permission.CodeOf(err)))
	}
	return AdminPermission{ID: created.ID, ScopeID: created.ScopeID, Key: created.Key,
		Name: created.Name, Enabled: created.Enabled, RootOnly: created.RootOnly}, nil
}

// AddRolePermission 向角色添加权限（敏感操作：用户主体需要真实近期再次认证；
// 委派资格在角色服务事务内复核，越权转授/自我提权由真实委派引擎拒绝）。
func (f *adminFacade) AddRolePermission(ctx context.Context,
	req AdminRolePermissionRequest) error {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Role == nil {
		return call.configError("角色服务未装配")
	}
	caller, err := f.roleCaller(call.identity)
	if err != nil {
		return call.configError("角色服务调用者无效")
	}
	// 角色服务把调用者的请求编号传给内部再次认证；必须先附加合法请求编号。
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return err
	}
	approved, err := f.sensitiveContext(ctx, call.identity, "role.permission.change", "role",
		req.RoleID, map[string]string{"direction": "add", "permission_id": req.PermissionID},
		req.Password, req.TOTPCode, call.requestID)
	if err != nil {
		return err
	}
	if _, err := managed.Role.AddRolePermission(approved, caller, req.RoleID,
		req.PermissionID); err != nil {
		return call.roleError("为角色添加权限失败", err)
	}
	return nil
}

// GrantApplicationRole 把角色分配给用户（敏感操作；应用角色要求目标用户是该应用
// active 成员；操作者必须当前持有被转授的全部权限，否则拒绝）。
func (f *adminFacade) GrantApplicationRole(ctx context.Context, req GrantRoleRequest) error {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Role == nil {
		return call.configError("角色服务未装配")
	}
	caller, err := f.roleCaller(call.identity)
	if err != nil {
		return call.configError("角色服务调用者无效")
	}
	// 角色服务把调用者的请求编号传给内部再次认证；必须先附加合法请求编号。
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return err
	}
	approved, err := f.sensitiveContext(ctx, call.identity, "permission.role.assign", "user",
		req.UserID, map[string]string{"direction": "assign", "role_id": req.RoleID},
		req.Password, req.TOTPCode, call.requestID)
	if err != nil {
		return err
	}
	if _, err := managed.Role.AssignUserRole(approved, caller, req.RoleID, req.UserID); err != nil {
		return call.roleError("分配角色失败", err)
	}
	return nil
}

// RevokeApplicationRole 撤回角色分配（安全清理；不改变其他角色/权限）。
func (f *adminFacade) RevokeApplicationRole(ctx context.Context, req RevokeRoleRequest) error {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Role == nil {
		return call.configError("角色服务未装配")
	}
	caller, err := f.roleCaller(call.identity)
	if err != nil {
		return call.configError("角色服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return err
	}
	if _, err := managed.Role.RevokeUserRole(ctx, caller, req.RoleID, req.UserID); err != nil {
		return call.roleError("撤回角色分配失败", err)
	}
	return nil
}

// GrantDelegation 为本机受信操作者签发可转授资格（用户主体不能签发委派资格，
// 由委派服务自身强制）。资格只确定“可转授上限”，实际转授仍要当前持有权限并经
// 事务内委派检查。
func (f *adminFacade) GrantDelegation(ctx context.Context,
	req AdminDelegationGrantRequest) (AdminDelegation, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminDelegation{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Delegation == nil {
		return AdminDelegation{}, call.configError("委派服务未装配")
	}
	var caller delegation.Caller
	if call.identity.local {
		caller, err = delegation.LocalBootstrapCaller(call.identity.actor.ID)
	} else {
		caller, err = delegation.UserCaller(call.identity.userID)
	}
	if err != nil {
		return AdminDelegation{}, call.configError("委派服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminDelegation{}, err
	}
	grant, err := managed.Delegation.Grant(ctx, caller, delegation.GrantRequest{
		DelegatorUserID: req.DelegatorUserID, ScopeID: req.ScopeID,
		PermissionKey: req.PermissionKey, MaxDataScope: req.MaxDataScope,
	})
	if err != nil {
		return AdminDelegation{}, call.domainError("签发委派资格失败",
			string(delegation.CodeOf(err)))
	}
	return AdminDelegation{ID: grant.ID, DelegatorUserID: grant.DelegatorUserID,
		ScopeID: grant.ScopeID, PermissionKey: grant.PermissionKey,
		GrantedBy: grant.CreatedBy.ID}, nil
}

// ListRolePermissions 读取角色当前权限组合。已授权但角色不存在时返回稳定的公开
// NotFoundError（NOT_FOUND），与角色 ID 参数非法 REQ_INVALID 区分。
func (f *adminFacade) ListRolePermissions(ctx context.Context,
	req AdminRoleRequest) ([]AdminPermission, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return nil, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Role == nil {
		return nil, call.configError("角色服务未装配")
	}
	caller, err := f.roleCaller(call.identity)
	if err != nil {
		return nil, call.configError("角色服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return nil, err
	}
	summaries, err := managed.Role.ListRolePermissions(ctx, caller, req.RoleID)
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, role.ErrRoleNotFound, "role"); ok {
			return nil, replaced
		}
		return nil, call.roleError("读取角色权限失败", err)
	}
	result := make([]AdminPermission, 0, len(summaries))
	for _, summary := range summaries {
		result = append(result, AdminPermission{ID: summary.PermissionID, Key: summary.Key,
			Name: summary.Name, ScopeID: summary.ScopeID, Enabled: summary.Enabled,
			RootOnly: summary.RootOnly})
	}
	return result, nil
}

// EffectivePermissions 查询用户在指定范围的有效权限（用户主体只能查询自己；
// 本机受信通道可查询任意主体）。已授权但目标账户不存在时返回 NotFoundError；
// 权限检查先于状态与权限数据读取。
func (f *adminFacade) EffectivePermissions(ctx context.Context,
	req AdminPermissionQuery) (AdminEffectivePermissions, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminEffectivePermissions{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Authz == nil {
		return AdminEffectivePermissions{}, call.configError("权限引擎未装配")
	}
	caller, err := f.authzCaller(call.identity)
	if err != nil {
		return AdminEffectivePermissions{}, call.configError("权限引擎调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminEffectivePermissions{}, err
	}
	result, err := managed.Authz.EffectivePermissions(ctx, caller, req.UserID, req.ScopeID,
		authz.ListOptions{Limit: req.Limit, Offset: req.Offset})
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, authz.ErrSubjectNotFound, "user"); ok {
			return AdminEffectivePermissions{}, replaced
		}
		return AdminEffectivePermissions{}, call.domainError("查询有效权限失败",
			string(authz.CodeOf(err)))
	}
	value := AdminEffectivePermissions{UserID: result.SubjectUserID,
		ScopeID: result.Scope.ID, DeniedCode: string(result.DeniedCode)}
	for _, item := range result.Permissions {
		value.Permissions = append(value.Permissions, AdminPermission{Key: item.Key,
			Name: item.Name, ScopeID: item.ScopeID, Enabled: true})
	}
	return value, nil
}

// CheckPermission 对用户执行一次联合权限检查（令牌/当前权限/范围交集语义由既有
// 权限引擎保证；用户主体只能检查自己，本机受信通道可检查任意主体）。
func (f *adminFacade) CheckPermission(ctx context.Context,
	req AdminPermissionCheck) (AdminPermissionDecision, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminPermissionDecision{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Authz == nil {
		return AdminPermissionDecision{}, call.configError("权限引擎未装配")
	}
	caller, err := f.authzCaller(call.identity)
	if err != nil {
		return AdminPermissionDecision{}, call.configError("权限引擎调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminPermissionDecision{}, err
	}
	mode := authz.Mode(req.Mode)
	if mode == "" {
		mode = authz.ModeAll
	}
	result, err := managed.Authz.Check(ctx, caller, authz.CheckRequest{
		SubjectUserID: req.UserID, ScopeID: req.ScopeID,
		Permissions: []string{req.Permission}, Mode: mode,
	})
	if err != nil {
		return AdminPermissionDecision{}, call.domainError("权限检查失败",
			string(authz.CodeOf(err)))
	}
	return AdminPermissionDecision{Allowed: result.Allowed, Code: string(result.Code),
		Reason: result.Reason}, nil
}

// adminUserProfile 把领域资料投影为公开脱敏视图。
func adminUser(value account.User) AdminUser {
	return AdminUser{ID: value.ID, Username: value.Username, Nickname: value.Nickname,
		Status: string(value.Status), CreatedAt: value.CreatedAt}
}

func adminUserProfile(value profile.UserProfile) AdminUserProfile {
	return AdminUserProfile{UserID: value.UserID, Username: value.Username,
		Nickname: value.Nickname, Biography: value.Biography, Language: value.Language,
		Timezone: value.Timezone, IsRoot: value.IsRoot, RowVersion: value.RowVersion,
		CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt}
}

var _ AdminService = (*adminFacade)(nil)

// ListGroups 分页查询用户组（作用范围筛选 + 白名单排序）。
//
// 授权与数据范围由用户组服务先行判定（只返回调用者可管理范围内的组），分页
// 在数据库查询阶段执行；非法排序字段/分页参数返回 REQ_INVALID，不静默纠正。
func (f *adminFacade) ListGroups(ctx context.Context,
	req AdminListGroupsRequest) (AdminGroupList, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminGroupList{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Group == nil {
		return AdminGroupList{}, call.configError("用户组服务未装配")
	}
	caller, err := f.groupCaller(call.identity)
	if err != nil {
		return AdminGroupList{}, call.configError("用户组服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminGroupList{}, err
	}
	page, err := call.page(req.Page)
	if err != nil {
		return AdminGroupList{}, err
	}
	result, err := managed.Group.ListGroups(ctx, caller, group.ListRequest{
		ScopeID: strings.TrimSpace(req.ScopeID), Limit: page.Limit, Offset: page.Offset,
		Sort: group.GroupSortField(strings.TrimSpace(req.Sort)), Descending: req.Descending})
	if err != nil {
		return AdminGroupList{}, call.domainError("查询用户组列表失败", string(group.CodeOf(err)))
	}
	groups := make([]AdminGroup, 0, len(result.Groups))
	for _, record := range result.Groups {
		groups = append(groups, AdminGroup{ID: record.ID, ScopeID: record.ScopeID,
			ApplicationID: record.ApplicationID, Key: record.GroupKey, Name: record.Name,
			Description: record.Description, CreatedAt: record.CreatedAt,
			UpdatedAt: record.UpdatedAt})
	}
	return AdminGroupList{Groups: groups, HasMore: result.HasMore,
		Page: NewAdminPageInfo(page, len(groups), result.HasMore)}, nil
}

// ListGroupMembers 分页查询组成员（只返回稳定用户 ID/加入时间，不携带跨域资料）。
func (f *adminFacade) ListGroupMembers(ctx context.Context,
	req AdminListGroupMembersRequest) (AdminGroupMemberList, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminGroupMemberList{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Group == nil {
		return AdminGroupMemberList{}, call.configError("用户组服务未装配")
	}
	caller, err := f.groupCaller(call.identity)
	if err != nil {
		return AdminGroupMemberList{}, call.configError("用户组服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminGroupMemberList{}, err
	}
	page, err := call.page(req.Page)
	if err != nil {
		return AdminGroupMemberList{}, err
	}
	result, err := managed.Group.ListMembers(ctx, caller, group.MemberListRequest{
		GroupID: strings.TrimSpace(req.GroupID), Limit: page.Limit, Offset: page.Offset,
		Sort: group.MemberSortField(strings.TrimSpace(req.Sort)), Descending: req.Descending})
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, group.ErrGroupNotFound, "group"); ok {
			return AdminGroupMemberList{}, replaced
		}
		return AdminGroupMemberList{}, call.domainError("查询组成员失败", string(group.CodeOf(err)))
	}
	members := make([]AdminGroupMember, 0, len(result.Members))
	for _, member := range result.Members {
		members = append(members, AdminGroupMember{GroupID: member.GroupID,
			UserID: member.UserID, JoinedAt: member.CreatedAt})
	}
	return AdminGroupMemberList{Members: members, HasMore: result.HasMore,
		Page: NewAdminPageInfo(page, len(members), result.HasMore)}, nil
}

// ListRoles 分页查询角色（作用范围/启停/内置筛选 + 白名单排序）。
func (f *adminFacade) ListRoles(ctx context.Context,
	req AdminListRolesRequest) (AdminRoleList, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminRoleList{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Role == nil {
		return AdminRoleList{}, call.configError("角色服务未装配")
	}
	caller, err := f.roleCaller(call.identity)
	if err != nil {
		return AdminRoleList{}, call.configError("角色服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminRoleList{}, err
	}
	page, err := call.page(req.Page)
	if err != nil {
		return AdminRoleList{}, err
	}
	result, err := managed.Role.ListRoles(ctx, caller, role.ListRequest{
		ScopeID: strings.TrimSpace(req.ScopeID), Limit: page.Limit, Offset: page.Offset,
		Enabled: req.Enabled, Builtin: req.Builtin,
		Sort: role.SortField(strings.TrimSpace(req.Sort)), Descending: req.Descending})
	if err != nil {
		return AdminRoleList{}, call.domainError("查询角色列表失败", string(role.CodeOf(err)))
	}
	roles := make([]AdminRole, 0, len(result.Roles))
	for _, record := range result.Roles {
		roles = append(roles, AdminRole{ID: record.ID, ScopeID: record.ScopeID,
			ApplicationID: record.ApplicationID, Key: record.Key, Name: record.Name,
			Enabled: record.Enabled})
	}
	return AdminRoleList{Roles: roles, HasMore: result.HasMore,
		Page: NewAdminPageInfo(page, len(roles), result.HasMore)}, nil
}

// ListPermissions 分页查询权限目录（作用范围/启停筛选 + 白名单排序）。
func (f *adminFacade) ListPermissions(ctx context.Context,
	req AdminListPermissionsRequest) (AdminPermissionList, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminPermissionList{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Permission == nil {
		return AdminPermissionList{}, call.configError("权限目录服务未装配")
	}
	caller, err := f.permissionCaller(call.identity)
	if err != nil {
		return AdminPermissionList{}, call.configError("权限目录服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminPermissionList{}, err
	}
	page, err := call.page(req.Page)
	if err != nil {
		return AdminPermissionList{}, err
	}
	result, err := managed.Permission.ListPermissions(ctx, caller, permission.ListRequest{
		ScopeID: strings.TrimSpace(req.ScopeID), Limit: page.Limit, Offset: page.Offset,
		Enabled: req.Enabled, Sort: permission.SortField(strings.TrimSpace(req.Sort)),
		Descending: req.Descending})
	if err != nil {
		return AdminPermissionList{}, call.domainError("查询权限目录失败",
			string(permission.CodeOf(err)))
	}
	permissions := make([]AdminPermission, 0, len(result.Permissions))
	for _, record := range result.Permissions {
		permissions = append(permissions, AdminPermission{ID: record.ID, ScopeID: record.ScopeID,
			Key: record.Key, Name: record.Name, Enabled: record.Enabled,
			RootOnly: record.RootOnly})
	}
	return AdminPermissionList{Permissions: permissions, HasMore: result.HasMore,
		Page: NewAdminPageInfo(page, len(permissions), result.HasMore)}, nil
}

// ListRoleAssignments 在数据源处分页读取角色的用户/组分配；两类分配各自分页，
// 避免一类增长把另一类挤出结果。权限检查与数据范围由角色服务先于分页判定。
func (f *adminFacade) ListRoleAssignments(ctx context.Context,
	req AdminListRoleAssignmentsRequest) (AdminRoleAssignmentList, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminRoleAssignmentList{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Role == nil {
		return AdminRoleAssignmentList{}, call.configError("角色服务未装配")
	}
	caller, err := f.roleCaller(call.identity)
	if err != nil {
		return AdminRoleAssignmentList{}, call.configError("角色服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminRoleAssignmentList{}, err
	}
	userPage, err := call.page(req.UserPage)
	if err != nil {
		return AdminRoleAssignmentList{}, err
	}
	groupPage, err := call.page(req.GroupPage)
	if err != nil {
		return AdminRoleAssignmentList{}, err
	}
	result, err := managed.Role.ListRoleAssignmentsPaged(ctx, caller, role.AssignmentListRequest{
		RoleID:    strings.TrimSpace(req.RoleID),
		UserLimit: userPage.Limit, UserOffset: userPage.Offset,
		GroupLimit: groupPage.Limit, GroupOffset: groupPage.Offset,
		Sort:       role.AssignmentSortField(strings.TrimSpace(req.Sort)),
		Descending: req.Descending})
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, role.ErrRoleNotFound, "role"); ok {
			return AdminRoleAssignmentList{}, replaced
		}
		return AdminRoleAssignmentList{}, call.roleError("查询角色分配失败", err)
	}
	users := make([]AdminRoleUserAssignment, 0, len(result.Users))
	for _, assignment := range result.Users {
		users = append(users, AdminRoleUserAssignment{UserID: assignment.UserID,
			ScopeID: assignment.ScopeID, DataScope: assignment.DataScope,
			AssignedBy: assignment.AssignedBy, AssignedAt: assignment.CreatedAt})
	}
	groups := make([]AdminRoleGroupAssignment, 0, len(result.Groups))
	for _, assignment := range result.Groups {
		groups = append(groups, AdminRoleGroupAssignment{GroupID: assignment.GroupID,
			ScopeID: assignment.ScopeID, DataScope: assignment.DataScope,
			AssignedAt: assignment.CreatedAt})
	}
	return AdminRoleAssignmentList{Users: users, UsersHasMore: result.UsersHasMore,
		UserPage: NewAdminPageInfo(userPage, len(users), result.UsersHasMore),
		Groups:   groups, GroupsHasMore: result.GroupsHasMore,
		GroupPage: NewAdminPageInfo(groupPage, len(groups), result.GroupsHasMore)}, nil
}
