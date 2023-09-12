package app

// 受信管理门面（步骤 182）。
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

import (
	"context"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
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

// resolveAdmin 校验管理调用者并返回可信身份；任何无效/伪造上下文一律拒绝。
func (r *Runtime) resolveAdmin(ctx context.Context, caller AdminCaller) (adminIdentity, error) {
	services := r.coreServices()
	if services == nil {
		return adminIdentity{}, configError("服务未装配")
	}
	if caller.runtime == nil || caller.runtime != r {
		return adminIdentity{}, mapDomainError("管理调用上下文无效", "ACCESS_DENIED")
	}
	if caller.local && len(caller.sessionSecret) > 0 {
		return adminIdentity{}, mapDomainError("管理调用上下文无效", "ACCESS_DENIED")
	}
	if caller.local {
		operatorID := strings.TrimSpace(r.opts.OperatorID)
		actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: operatorID}
		if err := actor.Validate(); err != nil {
			return adminIdentity{}, mapDomainError("本机受信操作者标识无效", "ACCESS_DENIED")
		}
		return adminIdentity{actor: actor, local: true}, nil
	}
	record, err := services.Sessions.Validate(ctx, string(caller.sessionSecret))
	if err != nil || !record.IsNormal() || record.UserID == "" {
		return adminIdentity{}, mapDomainError("管理会话无效或不是完整会话", "ACCESS_DENIED")
	}
	actor := audit.Actor{Type: audit.ActorUser, ID: record.UserID}
	if err := actor.Validate(); err != nil {
		return adminIdentity{}, mapDomainError("管理会话主体无效", "ACCESS_DENIED")
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

// adminRequestID 返回合法请求编号（缺省生成一次）。
func adminRequestID(requestID string) string {
	if strings.TrimSpace(requestID) == "" {
		return login.NewRequestID()
	}
	return requestID
}

// sensitiveContext 为敏感管理操作准备可信上下文：
//   - 用户主体：真实 reauth 挑战（密码 + 强认证要求的动态码），信号来自真实验证；
//   - 本机受信操作者：先写独立审计事件（操作/目标），再以本地管理员事实执行。
//
// 本机受信通道不是 is_root、不改变 root 保护，也不用于用户主体；用户主体永远
// 不会走该分支，避免用伪造强认证结果完成用户正向流程。
func (f *adminFacade) sensitiveContext(ctx context.Context, id adminIdentity,
	operationID, targetType, targetID string, params map[string]string,
	password, totpCode, requestID string) (context.Context, error) {
	if id.local {
		if f.r.base == nil || f.r.base.Audit == nil {
			return ctx, configError("审计服务未装配")
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
			return ctx, mapDomainError("本机受信操作审计不可用", "AUDIT_WRITE_FAILED")
		}
		return reauth.WithSignals(ctx, reauth.Signals{
			VerifiedAt: f.r.runtimeNow().UTC(), Strength: policy.StrengthStrong,
			Complete: true, Confirmed: true,
		}), nil
	}
	gate := f.r.securityGate()
	if gate == nil || gate.Reauth == nil {
		return ctx, configError("敏感操作闸门未装配")
	}
	caller, err := reauth.UserCaller(id.userID)
	if err != nil {
		return ctx, configError("管理会话主体无效")
	}
	challenge, err := gate.Reauth.BeginChallenge(ctx, caller, reauth.ChallengeRequest{
		ScopeID: "system", OperationID: operationID, TargetType: targetType,
		TargetID: targetID, Params: params, Description: "受信管理敏感操作",
		RequestID: requestID, MinimumStrength: policy.StrengthStrong,
	})
	if err != nil {
		return ctx, mapDomainError("敏感操作再次认证未通过", string(reauth.CodeOf(err)))
	}
	if !challenge.Required {
		return ctx, nil
	}
	if strings.TrimSpace(password) == "" {
		return ctx, mapDomainError("敏感操作需要近期密码验证", "REAUTH_REQUIRED")
	}
	grant, err := gate.Reauth.VerifyChallenge(ctx, caller, reauth.VerifyChallengeRequest{
		ChallengeID: challenge.ID, Password: password, TOTPCode: totpCode,
		RequestID: requestID,
	})
	if err != nil {
		return ctx, mapDomainError("敏感操作再次认证未通过", string(reauth.CodeOf(err)))
	}
	return reauth.WithSignals(ctx, reauth.Signals{
		VerifiedAt: f.r.runtimeNow().UTC(), Strength: grant.GrantedStrength,
		Complete: true, Confirmed: true, ApprovalToken: grant.Token,
	}), nil
}

// CreateUser 创建全局账户（与 registration.enabled 无关），可选建立应用成员关系。
func (f *adminFacade) CreateUser(ctx context.Context,
	req AdminCreateUserRequest) (AdminUser, error) {
	r := f.r
	managed := r.managedServices()
	if managed == nil || managed.Account == nil {
		return AdminUser{}, configError("账户服务未装配")
	}
	id, err := r.resolveAdmin(ctx, req.Caller)
	if err != nil {
		return AdminUser{}, err
	}
	requestID := adminRequestID(req.RequestID)
	caller, err := f.accountCaller(id)
	if err != nil {
		return AdminUser{}, configError("账户服务调用者无效")
	}
	if caller, err = caller.WithRequestID(requestID); err != nil {
		return AdminUser{}, configError("账户服务请求编号无效")
	}
	created, err := managed.Account.CreateUser(ctx, caller, account.CreateRequest{
		Username: req.Username, Nickname: req.Nickname, Biography: req.Biography,
	})
	if err != nil {
		return AdminUser{}, mapDomainError("创建用户失败", string(account.CodeOf(err)))
	}
	if len(req.ApplicationIDs) > 0 {
		appCaller, callerErr := f.appCaller(id)
		if callerErr != nil {
			return AdminUser{}, configError("应用服务调用者无效")
		}
		if appCaller, callerErr = appCaller.WithRequestID(requestID); callerErr != nil {
			return AdminUser{}, configError("应用服务请求编号无效")
		}
		for _, applicationID := range req.ApplicationIDs {
			if _, memberErr := managed.App.AddApplicationMember(ctx, appCaller,
				app.AddMemberRequest{ApplicationID: applicationID, UserID: created.ID}); memberErr != nil {
				// 账户已创建但成员关系失败：不回滚全局账户（删除账户是更高风险操作），
				// 返回明确错误供宿主核对；不使用事务跨领域伪装整体成功。
				return AdminUser{}, mapDomainError("创建用户后建立应用成员关系失败",
					string(app.CodeOf(memberErr)))
			}
		}
	}
	return AdminUser{ID: created.ID, Username: created.Username,
		Nickname: created.Nickname, Status: string(created.Status),
		CreatedAt: created.CreatedAt}, nil
}

// ListUsers 分页查询用户（需要系统范围 users.read 或本机受信通道）。
func (f *adminFacade) ListUsers(ctx context.Context,
	req AdminListUsersRequest) (AdminUserList, error) {
	managed := f.r.managedServices()
	if managed == nil || managed.Account == nil {
		return AdminUserList{}, configError("账户服务未装配")
	}
	id, err := f.r.resolveAdmin(ctx, req.Caller)
	if err != nil {
		return AdminUserList{}, err
	}
	caller, err := f.accountCaller(id)
	if err != nil {
		return AdminUserList{}, configError("账户服务调用者无效")
	}
	result, err := managed.Account.ListUsers(ctx, caller, account.ListRequest{
		Limit: req.Limit, Offset: req.Offset, Status: account.Status(req.Status),
		Sort: account.SortField(req.Sort), Descending: req.Descending,
	})
	if err != nil {
		return AdminUserList{}, mapDomainError("查询用户列表失败", string(account.CodeOf(err)))
	}
	users := make([]AdminUser, 0, len(result.Users))
	for _, user := range result.Users {
		users = append(users, adminUser(user))
	}
	return AdminUserList{Users: users, HasMore: result.HasMore}, nil
}

// GetUserByUsername 按用户名读取脱敏用户记录（需要 users.read 或本机受信通道）。
func (f *adminFacade) GetUserByUsername(ctx context.Context,
	req AdminUserByUsernameRequest) (AdminUser, error) {
	managed := f.r.managedServices()
	if managed == nil || managed.Account == nil {
		return AdminUser{}, configError("账户服务未装配")
	}
	id, err := f.r.resolveAdmin(ctx, req.Caller)
	if err != nil {
		return AdminUser{}, err
	}
	caller, err := f.accountCaller(id)
	if err != nil {
		return AdminUser{}, configError("账户服务调用者无效")
	}
	user, err := managed.Account.GetUserByUsername(ctx, caller, req.Username)
	if err != nil {
		return AdminUser{}, mapDomainError("按用户名查询用户失败", string(account.CodeOf(err)))
	}
	return adminUser(user), nil
}

// GetUserProfile 读取用户资料（需要系统范围 users.read 或本机受信通道）。
func (f *adminFacade) GetUserProfile(ctx context.Context,
	req AdminUserRequest) (AdminUserProfile, error) {
	managed := f.r.managedServices()
	if managed == nil || managed.Profile == nil {
		return AdminUserProfile{}, configError("资料服务未装配")
	}
	id, err := f.r.resolveAdmin(ctx, req.Caller)
	if err != nil {
		return AdminUserProfile{}, err
	}
	caller, err := f.profileCaller(id)
	if err != nil {
		return AdminUserProfile{}, configError("资料服务调用者无效")
	}
	value, err := managed.Profile.GetProfile(ctx, caller, req.UserID)
	if err != nil {
		return AdminUserProfile{}, mapDomainError("读取用户资料失败", string(profile.CodeOf(err)))
	}
	return adminUserProfile(value), nil
}

// UpdateUserProfile 修改允许管理员改写的资料字段（需要系统范围 users.update）。
func (f *adminFacade) UpdateUserProfile(ctx context.Context,
	req AdminUpdateProfileRequest) (AdminUserProfile, error) {
	managed := f.r.managedServices()
	if managed == nil || managed.Profile == nil {
		return AdminUserProfile{}, configError("资料服务未装配")
	}
	id, err := f.r.resolveAdmin(ctx, req.Caller)
	if err != nil {
		return AdminUserProfile{}, err
	}
	caller, err := f.profileCaller(id)
	if err != nil {
		return AdminUserProfile{}, configError("资料服务调用者无效")
	}
	change := profile.ProfileChange{Nickname: req.Nickname, Biography: req.Biography,
		Language: req.Language, Timezone: req.Timezone}
	if !change.HasChanges() {
		return AdminUserProfile{}, configError("资料更新请求没有可修改字段")
	}
	value, err := managed.Profile.UpdateUser(ctx, caller, profile.UpdateRequest{
		TargetUserID: req.UserID, Change: change,
		ExpectedRowVersion: req.ExpectedRowVersion,
		RequestID:          adminRequestID(req.RequestID),
	})
	if err != nil {
		return AdminUserProfile{}, mapDomainError("更新用户资料失败", string(profile.CodeOf(err)))
	}
	return adminUserProfile(value), nil
}

// AddApplicationMember 把已有用户加入应用（需要该应用 applications.members.manage）。
func (f *adminFacade) AddApplicationMember(ctx context.Context, req AdminAddMemberRequest) error {
	managed := f.r.managedServices()
	if managed == nil || managed.App == nil {
		return configError("应用服务未装配")
	}
	id, err := f.r.resolveAdmin(ctx, req.Caller)
	if err != nil {
		return err
	}
	caller, err := f.appCaller(id)
	if err != nil {
		return configError("应用服务调用者无效")
	}
	if _, err := managed.App.AddApplicationMember(ctx, caller, app.AddMemberRequest{
		ApplicationID: req.ApplicationID, UserID: req.UserID,
	}); err != nil {
		return mapDomainError("加入应用成员失败", string(app.CodeOf(err)))
	}
	return nil
}

// CreateApplication 登记应用（本机受信通道或系统范围 applications.create）。
func (f *adminFacade) CreateApplication(ctx context.Context,
	req AdminCreateApplicationRequest) (AdminApplication, error) {
	managed := f.r.managedServices()
	if managed == nil || managed.App == nil {
		return AdminApplication{}, configError("应用服务未装配")
	}
	id, err := f.r.resolveAdmin(ctx, req.Caller)
	if err != nil {
		return AdminApplication{}, err
	}
	caller, err := f.appCaller(id)
	if err != nil {
		return AdminApplication{}, configError("应用服务调用者无效")
	}
	owner := strings.TrimSpace(req.OwnerUserID)
	if owner == "" && !id.local {
		owner = id.userID
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
		return AdminApplication{}, mapDomainError("创建应用失败", string(app.CodeOf(err)))
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
	managed := f.r.managedServices()
	if managed == nil || managed.App == nil {
		return AdminApplication{}, configError("应用服务未装配")
	}
	id, err := f.r.resolveAdmin(ctx, req.Caller)
	if err != nil {
		return AdminApplication{}, err
	}
	caller, err := f.appCaller(id)
	if err != nil {
		return AdminApplication{}, configError("应用服务调用者无效")
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
		return AdminApplication{}, mapDomainError("应用启停失败", string(app.CodeOf(err)))
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
	managed := f.r.managedServices()
	if managed == nil || managed.Role == nil {
		return AdminRole{}, configError("角色服务未装配")
	}
	id, err := f.r.resolveAdmin(ctx, req.Caller)
	if err != nil {
		return AdminRole{}, err
	}
	caller, err := f.roleCaller(id)
	if err != nil {
		return AdminRole{}, configError("角色服务调用者无效")
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
		return AdminRole{}, mapDomainError("创建角色失败", string(role.CodeOf(err)))
	}
	return AdminRole{ID: created.ID, ScopeID: created.ScopeID,
		ApplicationID: created.ApplicationID, Key: created.Key, Name: created.Name,
		Enabled: created.Enabled}, nil
}

// CreatePermission 在系统或应用范围登记自定义权限。
func (f *adminFacade) CreatePermission(ctx context.Context,
	req AdminCreatePermissionRequest) (AdminPermission, error) {
	managed := f.r.managedServices()
	if managed == nil || managed.Permission == nil {
		return AdminPermission{}, configError("权限服务未装配")
	}
	id, err := f.r.resolveAdmin(ctx, req.Caller)
	if err != nil {
		return AdminPermission{}, err
	}
	caller, err := f.permissionCaller(id)
	if err != nil {
		return AdminPermission{}, configError("权限服务调用者无效")
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
		return AdminPermission{}, mapDomainError("创建权限失败",
			string(permission.CodeOf(err)))
	}
	return AdminPermission{ID: created.ID, ScopeID: created.ScopeID, Key: created.Key,
		Name: created.Name, Enabled: created.Enabled, RootOnly: created.RootOnly}, nil
}

// AddRolePermission 向角色添加权限（敏感操作：用户主体需要真实近期再次认证；
// 委派资格在角色服务事务内复核，越权转授/自我提权由真实委派引擎拒绝）。
func (f *adminFacade) AddRolePermission(ctx context.Context,
	req AdminRolePermissionRequest) error {
	managed := f.r.managedServices()
	if managed == nil || managed.Role == nil {
		return configError("角色服务未装配")
	}
	id, err := f.r.resolveAdmin(ctx, req.Caller)
	if err != nil {
		return err
	}
	caller, err := f.roleCaller(id)
	if err != nil {
		return configError("角色服务调用者无效")
	}
	requestID := adminRequestID(req.RequestID)
	// 角色服务把调用者的请求编号传给内部再次认证；必须先附加合法请求编号。
	caller, err = caller.WithRequestID(requestID)
	if err != nil {
		return configError("角色服务请求编号无效")
	}
	approved, err := f.sensitiveContext(ctx, id, "role.permission.change", "role",
		req.RoleID, map[string]string{"direction": "add", "permission_id": req.PermissionID},
		req.Password, req.TOTPCode, requestID)
	if err != nil {
		return err
	}
	if _, err := managed.Role.AddRolePermission(approved, caller, req.RoleID,
		req.PermissionID); err != nil {
		return roleAdminError("为角色添加权限失败", err)
	}
	return nil
}

// GrantApplicationRole 把角色分配给用户（敏感操作；应用角色要求目标用户是该应用
// active 成员；操作者必须当前持有被转授的全部权限，否则拒绝）。
func (f *adminFacade) GrantApplicationRole(ctx context.Context, req GrantRoleRequest) error {
	managed := f.r.managedServices()
	if managed == nil || managed.Role == nil {
		return configError("角色服务未装配")
	}
	id, err := f.r.resolveAdmin(ctx, req.Caller)
	if err != nil {
		return err
	}
	caller, err := f.roleCaller(id)
	if err != nil {
		return configError("角色服务调用者无效")
	}
	requestID := adminRequestID(req.RequestID)
	// 角色服务把调用者的请求编号传给内部再次认证；必须先附加合法请求编号。
	caller, err = caller.WithRequestID(requestID)
	if err != nil {
		return configError("角色服务请求编号无效")
	}
	approved, err := f.sensitiveContext(ctx, id, "permission.role.assign", "user",
		req.UserID, map[string]string{"direction": "assign", "role_id": req.RoleID},
		req.Password, req.TOTPCode, requestID)
	if err != nil {
		return err
	}
	if _, err := managed.Role.AssignUserRole(approved, caller, req.RoleID, req.UserID); err != nil {
		return roleAdminError("分配角色失败", err)
	}
	return nil
}

// RevokeApplicationRole 撤回角色分配（安全清理；不改变其他角色/权限）。
func (f *adminFacade) RevokeApplicationRole(ctx context.Context, req RevokeRoleRequest) error {
	managed := f.r.managedServices()
	if managed == nil || managed.Role == nil {
		return configError("角色服务未装配")
	}
	id, err := f.r.resolveAdmin(ctx, req.Caller)
	if err != nil {
		return err
	}
	caller, err := f.roleCaller(id)
	if err != nil {
		return configError("角色服务调用者无效")
	}
	if _, err := managed.Role.RevokeUserRole(ctx, caller, req.RoleID, req.UserID); err != nil {
		return roleAdminError("撤回角色分配失败", err)
	}
	return nil
}

// GrantDelegation 为本机受信操作者签发可转授资格（用户主体不能签发委派资格，
// 由委派服务自身强制）。资格只确定“可转授上限”，实际转授仍要当前持有权限并经
// 事务内委派检查。
func (f *adminFacade) GrantDelegation(ctx context.Context,
	req AdminDelegationGrantRequest) (AdminDelegation, error) {
	managed := f.r.managedServices()
	if managed == nil || managed.Delegation == nil {
		return AdminDelegation{}, configError("委派服务未装配")
	}
	id, err := f.r.resolveAdmin(ctx, req.Caller)
	if err != nil {
		return AdminDelegation{}, err
	}
	var caller delegation.Caller
	if id.local {
		caller, err = delegation.LocalBootstrapCaller(id.actor.ID)
	} else {
		caller, err = delegation.UserCaller(id.userID)
	}
	if err != nil {
		return AdminDelegation{}, configError("委派服务调用者无效")
	}
	grant, err := managed.Delegation.Grant(ctx, caller, delegation.GrantRequest{
		DelegatorUserID: req.DelegatorUserID, ScopeID: req.ScopeID,
		PermissionKey: req.PermissionKey, MaxDataScope: req.MaxDataScope,
	})
	if err != nil {
		return AdminDelegation{}, mapDomainError("签发委派资格失败",
			string(delegation.CodeOf(err)))
	}
	return AdminDelegation{ID: grant.ID, DelegatorUserID: grant.DelegatorUserID,
		ScopeID: grant.ScopeID, PermissionKey: grant.PermissionKey,
		GrantedBy: grant.CreatedBy.ID}, nil
}

// ListRolePermissions 读取角色当前权限组合。
func (f *adminFacade) ListRolePermissions(ctx context.Context,
	req AdminRoleRequest) ([]AdminPermission, error) {
	managed := f.r.managedServices()
	if managed == nil || managed.Role == nil {
		return nil, configError("角色服务未装配")
	}
	id, err := f.r.resolveAdmin(ctx, req.Caller)
	if err != nil {
		return nil, err
	}
	caller, err := f.roleCaller(id)
	if err != nil {
		return nil, configError("角色服务调用者无效")
	}
	summaries, err := managed.Role.ListRolePermissions(ctx, caller, req.RoleID)
	if err != nil {
		return nil, roleAdminError("读取角色权限失败", err)
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
// 本机受信通道可查询任意主体）。
func (f *adminFacade) EffectivePermissions(ctx context.Context,
	req AdminPermissionQuery) (AdminEffectivePermissions, error) {
	managed := f.r.managedServices()
	if managed == nil || managed.Authz == nil {
		return AdminEffectivePermissions{}, configError("权限引擎未装配")
	}
	id, err := f.r.resolveAdmin(ctx, req.Caller)
	if err != nil {
		return AdminEffectivePermissions{}, err
	}
	caller, err := f.authzCaller(id)
	if err != nil {
		return AdminEffectivePermissions{}, configError("权限引擎调用者无效")
	}
	result, err := managed.Authz.EffectivePermissions(ctx, caller, req.UserID, req.ScopeID,
		authz.ListOptions{Limit: req.Limit, Offset: req.Offset})
	if err != nil {
		return AdminEffectivePermissions{}, mapDomainError("查询有效权限失败",
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
	managed := f.r.managedServices()
	if managed == nil || managed.Authz == nil {
		return AdminPermissionDecision{}, configError("权限引擎未装配")
	}
	id, err := f.r.resolveAdmin(ctx, req.Caller)
	if err != nil {
		return AdminPermissionDecision{}, err
	}
	caller, err := f.authzCaller(id)
	if err != nil {
		return AdminPermissionDecision{}, configError("权限引擎调用者无效")
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
		return AdminPermissionDecision{}, mapDomainError("权限检查失败",
			string(authz.CodeOf(err)))
	}
	return AdminPermissionDecision{Allowed: result.Allowed, Code: string(result.Code),
		Reason: result.Reason}, nil
}

// roleAdminError 把角色/委派领域的稳定错误码映射为公开错误；委派拒绝（越权转授、
// 自我提权、目标白名单等）优先按委派领域错误码投影，避免被折叠成 INTERNAL_ERROR。
func roleAdminError(message string, err error) error {
	if code := delegation.CodeOf(err); code != "" {
		return mapDomainError(message, string(code))
	}
	return mapDomainError(message, string(role.CodeOf(err)))
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
