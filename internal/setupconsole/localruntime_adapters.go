package setupconsole

// WS3 本地维护领域适配器（步骤 286–291）。
//
// 授权模型（AGENTS §14）：本地维护身份的信任来自 OS 对实例配置/数据/密钥的访问，
// 领域调用使用各包既有的受限本地调用者构造函数（LocalBootstrapCaller /
// LocalAdminCaller），并为审计保留 actor_local_admin + 稳定操作者标识。普通 Web/
// HTTP/公开门面不经过本文件，也不存在 local=true 参数或可序列化维护令牌。
//
// 当前实现阶段（286→291 逐步接入）：
//   - 286 用户生命周期：已接入真实 account/profile/role 本地调用；
//   - 287 密码维护：已接入 authn.SetPassword/SetRootPassword；root 用户名更名依赖
//     profile 新增本地维护窄方法（单独提交），未接入前返回 ErrLocalUnsupported；
//   - 289 角色/权限/组：已接入真实 role/permission/group 本地调用；
//   - 290 应用：列表/详情/创建/资料/启停/成员增删与 OAuth 客户端凭证登记/轮换/
//     撤销均已接入（oauthclient 本地维护窄方法）；
//   - 288 MFA/会话：totp/mfa/passkey/recovery/session 本地窄方法已接入；
//   - 291 审计：auditops 查询/保留策略/清理预估与提交/受保护证据、任务列表/取消、
//     报告历史/投递状态已接入（报告生成与任务运行时相关限制见画面提示）。

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
	"github.com/kagurazakayashi/EvernightLogin/internal/preset"
	presetsqlite "github.com/kagurazakayashi/EvernightLogin/internal/preset/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/profile"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
	"github.com/kagurazakayashi/EvernightLogin/internal/serverapp"
	"sync"
)

// newWS3Services 用真实领域服务构造本地维护适配器；缺少依赖返回错误（fail-closed）。
func newWS3Services(base *serverapp.Base, operatorID string,
	guard localWriteGuard, maint *ws3MaintRecorder) (*WS3Services, error) {
	if base == nil || base.Managed == nil || base.Services == nil {
		return nil, fmt.Errorf("%w: 领域服务未装配（需要可用的实例数据库与配置）",
			ErrLocalRuntimeUnavailable)
	}
	if !validLocalOperatorID(operatorID) {
		return nil, fmt.Errorf("%w: 本地操作者标识无效", ErrLocalRuntimeUnavailable)
	}
	services := &WS3Services{OperatorID: operatorID}
	userAdmin, err := newLocalUserAdmin(base, operatorID)
	if err != nil {
		return nil, err
	}
	services.Users = userAdmin
	services.Identity = &localIdentityAdmin{base: base, operatorID: operatorID}
	rbacAdmin, err := newLocalRBACAdmin(base, operatorID)
	if err != nil {
		return nil, err
	}
	services.RBAC = rbacAdmin
	services.Apps = &localAppAdmin{base: base, operatorID: operatorID}
	securityAdmin, err := newLocalSecurityAdmin(base, operatorID)
	if err != nil {
		return nil, err
	}
	services.Security = securityAdmin
	auditAdmin, err := newLocalAuditAdmin(base, operatorID)
	if err != nil {
		return nil, err
	}
	services.Audit = auditAdmin
	// 只读方法不经装饰器（主服务运行时可浏览）；写方法统一经 281 写门。
	if guard != nil || maint != nil {
		services.Users = guardedUserAdmin{UserAdmin: services.Users, guard: guard, maint: maint}
		services.Identity = guardedIdentityAdmin{IdentityAdmin: services.Identity, guard: guard, maint: maint}
		services.Security = guardedSecurityAdmin{SecurityAdmin: services.Security, guard: guard, maint: maint}
		services.RBAC = guardedRBACAdmin{RBACAdmin: services.RBAC, guard: guard, maint: maint}
		services.Apps = guardedAppAdmin{AppAdmin: services.Apps, guard: guard, maint: maint}
		services.Audit = guardedAuditAdmin{AuditAdmin: services.Audit, guard: guard, maint: maint}
	}
	return services, nil
}

// ws3RequestID 生成本地维护操作请求编号（只用于审计关联，不含身份信息）。
func ws3RequestID(prefix string) string {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return prefix + "_" + time.Now().UTC().Format("20060102T150405.000000")
	}
	return prefix + "_" + hex.EncodeToString(raw[:])
}

// ---------- 286 用户 ----------

type localUserAdmin struct {
	base       *serverapp.Base
	operatorID string
}

func newLocalUserAdmin(base *serverapp.Base, operatorID string) (*localUserAdmin, error) {
	if _, err := account.LocalBootstrapCaller(operatorID); err != nil {
		return nil, fmt.Errorf("%w: 本地操作者标识无效", ErrLocalRuntimeUnavailable)
	}
	return &localUserAdmin{base: base, operatorID: operatorID}, nil
}

func (a *localUserAdmin) accountCaller() (account.Caller, error) {
	return account.LocalBootstrapCaller(a.operatorID)
}

func (a *localUserAdmin) roleCaller() (role.Caller, error) {
	return role.LocalBootstrapCaller(a.operatorID)
}

func (a *localUserAdmin) profileCaller() (profile.Caller, error) {
	return profile.LocalAdminCaller(a.operatorID)
}

func (a *localUserAdmin) authnCaller() (authn.Caller, error) {
	return authn.LocalAdminCaller(a.operatorID)
}

func (a *localUserAdmin) ListUsers(ctx context.Context,
	query LocalUserQuery) (LocalUserPage, error) {
	pageRequest := query.page()
	limit := pageRequest.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset := pageRequest.Offset
	if offset < 0 {
		offset = 0
	}
	caller, err := a.accountCaller()
	if err != nil {
		return LocalUserPage{}, err
	}
	request := account.ListRequest{Limit: limit, Offset: offset,
		Search: strings.TrimSpace(pageRequest.Search)}
	if status := strings.TrimSpace(query.Status); status != "" {
		request.Status = account.Status(status)
	}
	result, err := a.base.Managed.Account.ListUsers(ctx, caller, request)
	if err != nil {
		return LocalUserPage{}, localDomainError("列出用户", err)
	}
	page := LocalUserPage{Pagination: LocalPagination{HasMore: result.HasMore,
		Offset: offset, Limit: limit}}
	for _, user := range result.Users {
		page.Users = append(page.Users, localUserFromAccount(user))
	}
	return page, nil
}

func (a *localUserAdmin) GetUser(ctx context.Context, userID string) (LocalUser, error) {
	caller, err := a.accountCaller()
	if err != nil {
		return LocalUser{}, err
	}
	user, err := a.base.Managed.Account.GetUser(ctx, caller, strings.TrimSpace(userID))
	if err != nil {
		return LocalUser{}, localDomainError("读取用户", err)
	}
	return localUserFromAccount(user), nil
}

func (a *localUserAdmin) CreateUser(ctx context.Context,
	input LocalUserCreate) (LocalUser, error) {
	caller, err := a.accountCaller()
	if err != nil {
		return LocalUser{}, err
	}
	user, err := a.base.Managed.Account.CreateUser(ctx, caller, account.CreateRequest{
		Username:  strings.TrimSpace(input.Username),
		Nickname:  strings.TrimSpace(input.Nickname),
		Biography: strings.TrimSpace(input.Biography),
		Language:  strings.TrimSpace(input.Language),
		Timezone:  strings.TrimSpace(input.Timezone),
	})
	if err != nil {
		return LocalUser{}, localDomainError("创建用户", err)
	}
	if input.Password != "" {
		authnCaller, callerErr := a.authnCaller()
		if callerErr != nil {
			return LocalUser{}, callerErr
		}
		if _, setErr := a.base.Services.Authn.SetPassword(ctx, authnCaller,
			authn.SetPasswordRequest{TargetUserID: user.ID, NewPassword: input.Password,
				RequireChange: input.RequireChange, RequestID: ws3RequestID("req_local_setpwd")}); setErr != nil {
			// 账户已创建但密码设置失败：返回明确错误（不回滚已建账户，避免掩盖
			// 半成品状态；画面提示可对同一 UserID 重新设置密码）。
			return localUserFromAccount(user), fmt.Errorf("账户已创建但设置初始密码失败: %w",
				localDomainError("设置初始密码", setErr))
		}
		user, err = a.base.Managed.Account.GetUser(ctx, caller, user.ID)
		if err != nil {
			return localUserFromAccount(user), nil
		}
	}
	return localUserFromAccount(user), nil
}

func (a *localUserAdmin) UpdateProfile(ctx context.Context, userID string,
	input LocalProfileUpdate) (LocalUser, error) {
	caller, err := a.profileCaller()
	if err != nil {
		return LocalUser{}, err
	}
	change := profile.ProfileChange{}
	nickname := strings.TrimSpace(input.Nickname)
	biography := strings.TrimSpace(input.Biography)
	language := strings.TrimSpace(input.Language)
	timezone := strings.TrimSpace(input.Timezone)
	change.Nickname = &nickname
	change.Biography = &biography
	change.Language = &language
	change.Timezone = &timezone
	updated, err := a.base.Managed.Profile.UpdateUser(ctx, caller, profile.UpdateRequest{
		TargetUserID: strings.TrimSpace(userID), Change: change,
		ExpectedRowVersion: input.ExpectedRowVersion,
		RequestID:          ws3RequestID("req_local_profile"),
	})
	if err != nil {
		return LocalUser{}, localDomainError("更新资料", err)
	}
	return a.localUserFromProfile(ctx, updated)
}

func (a *localUserAdmin) SetEnabled(ctx context.Context, userID string, enabled bool,
	expectedRowVersion int64) (LocalUser, error) {
	caller, err := a.accountCaller()
	if err != nil {
		return LocalUser{}, err
	}
	if expectedRowVersion <= 0 {
		current, getErr := a.base.Managed.Account.GetUser(ctx, caller, strings.TrimSpace(userID))
		if getErr != nil {
			return LocalUser{}, localDomainError("读取用户版本", getErr)
		}
		expectedRowVersion = current.RowVersion
	}
	request := account.StateCommandRequest{UserID: strings.TrimSpace(userID),
		ExpectedRowVersion: expectedRowVersion}
	var result account.StateChangeResult
	if enabled {
		result, err = a.base.Managed.Account.EnableUser(ctx, caller, request)
	} else {
		result, err = a.base.Managed.Account.DisableUser(ctx, caller, request)
	}
	if err != nil {
		return LocalUser{}, localDomainError("变更用户状态", err)
	}
	return localUserFromAccount(result.User), nil
}

func (a *localUserAdmin) GetValidity(ctx context.Context, userID string) (LocalValidity, error) {
	caller, err := a.accountCaller()
	if err != nil {
		return LocalValidity{}, err
	}
	validity, err := a.base.Managed.Account.GetUserValidity(ctx, caller, strings.TrimSpace(userID))
	if err != nil {
		return LocalValidity{}, localDomainError("读取有效期", err)
	}
	return LocalValidity{UserID: validity.UserID, ValidFrom: validity.ValidFrom,
		ValidUntil: validity.ValidUntil, RowVersion: validity.RowVersion}, nil
}

func (a *localUserAdmin) SetValidity(ctx context.Context, userID string,
	validity LocalValidity) (LocalUser, error) {
	caller, err := a.accountCaller()
	if err != nil {
		return LocalUser{}, err
	}
	rowVersion := validity.RowVersion
	if rowVersion <= 0 {
		current, getErr := a.base.Managed.Account.GetUserValidity(ctx, caller,
			strings.TrimSpace(userID))
		if getErr != nil {
			return LocalUser{}, localDomainError("读取有效期版本", getErr)
		}
		rowVersion = current.RowVersion
	}
	if _, err := a.base.Managed.Account.SetValidity(ctx, caller, account.ValidityCommandRequest{
		UserID: strings.TrimSpace(userID), ValidFrom: validity.ValidFrom,
		ValidUntil: validity.ValidUntil, ExpectedRowVersion: rowVersion,
	}); err != nil {
		return LocalUser{}, localDomainError("设置有效期", err)
	}
	return a.GetUser(ctx, userID)
}

func (a *localUserAdmin) PreviewDeletion(ctx context.Context,
	userID string) (LocalDeletionPreview, error) {
	caller, err := a.accountCaller()
	if err != nil {
		return LocalDeletionPreview{}, err
	}
	preview, err := a.base.Managed.Account.PreviewDeletion(ctx, caller, strings.TrimSpace(userID))
	if err != nil {
		return LocalDeletionPreview{}, localDomainError("预览删除", err)
	}
	return localDeletionPreview(preview), nil
}

func (a *localUserAdmin) RequestDeletion(ctx context.Context, userID string,
	expectedRowVersion int64) (LocalUser, error) {
	caller, err := a.accountCaller()
	if err != nil {
		return LocalUser{}, err
	}
	if expectedRowVersion <= 0 {
		current, getErr := a.base.Managed.Account.GetUser(ctx, caller, strings.TrimSpace(userID))
		if getErr != nil {
			return LocalUser{}, localDomainError("读取用户版本", getErr)
		}
		expectedRowVersion = current.RowVersion
	}
	result, err := a.base.Managed.Account.RequestDeletion(ctx, caller,
		account.StateCommandRequest{UserID: strings.TrimSpace(userID),
			ExpectedRowVersion: expectedRowVersion})
	if err != nil {
		return LocalUser{}, localDomainError("标记待删除", err)
	}
	return localUserFromAccount(result.User), nil
}

func (a *localUserAdmin) CompleteDeletion(ctx context.Context, userID string,
	expectedRowVersion int64) (LocalDeletionPreview, error) {
	caller, err := a.accountCaller()
	if err != nil {
		return LocalDeletionPreview{}, err
	}
	if expectedRowVersion <= 0 {
		current, getErr := a.base.Managed.Account.GetUser(ctx, caller, strings.TrimSpace(userID))
		if getErr != nil {
			return LocalDeletionPreview{}, localDomainError("读取待删除用户版本", getErr)
		}
		expectedRowVersion = current.RowVersion
	}
	result, err := a.base.Managed.Account.CompleteDeletion(ctx, caller,
		account.StateCommandRequest{UserID: strings.TrimSpace(userID),
			ExpectedRowVersion: expectedRowVersion})
	if err != nil {
		return LocalDeletionPreview{}, localDomainError("完成删除", err)
	}
	return localDeletionPreview(result.Preview), nil
}

func (a *localUserAdmin) ListAssignableRoles(ctx context.Context) ([]LocalRole, error) {
	caller, err := a.roleCaller()
	if err != nil {
		return nil, err
	}
	result, err := a.base.Managed.Role.ListRoles(ctx, caller, role.ListRequest{
		ScopeID: "system", Limit: 100})
	if err != nil {
		return nil, localDomainError("列出角色", err)
	}
	roles := make([]LocalRole, 0, len(result.Roles))
	for _, item := range result.Roles {
		roles = append(roles, localRoleFromDomain(item))
	}
	return roles, nil
}

func (a *localUserAdmin) AssignRole(ctx context.Context, userID, roleID string) error {
	caller, err := a.roleCaller()
	if err != nil {
		return err
	}
	if _, err := a.base.Managed.Role.AssignUserRole(ctx, caller,
		strings.TrimSpace(roleID), strings.TrimSpace(userID)); err != nil {
		return localDomainError("分配角色", err)
	}
	return nil
}

func (a *localUserAdmin) localUserFromProfile(ctx context.Context,
	updated profile.UserProfile) (LocalUser, error) {
	caller, err := a.accountCaller()
	if err != nil {
		return LocalUser{}, err
	}
	user, err := a.base.Managed.Account.GetUser(ctx, caller, updated.UserID)
	if err != nil {
		return LocalUser{}, localDomainError("读取更新后用户", err)
	}
	return localUserFromAccount(user), nil
}

// ---------- 287 身份维护（密码；更名待 profile 本地窄方法） ----------

type localIdentityAdmin struct {
	base       *serverapp.Base
	operatorID string
}

func (a *localIdentityAdmin) Rename(ctx context.Context, userID, newUsername, reason string,
	expectedRowVersion int64) (LocalUser, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return LocalUser{}, fmt.Errorf("更换理由不能为空（进入审计）")
	}
	if len(reason) > profile.MaxManagementReasonBytes {
		return LocalUser{}, fmt.Errorf("更换理由过长（最多 %d 字节）",
			profile.MaxManagementReasonBytes)
	}
	userID = strings.TrimSpace(userID)
	profileCaller, err := profile.LocalAdminCaller(a.operatorID)
	if err != nil {
		return LocalUser{}, err
	}
	current, err := a.base.Managed.Profile.GetProfile(ctx, profileCaller, userID)
	if err != nil {
		return LocalUser{}, localDomainError("读取目标资料", err)
	}
	if expectedRowVersion <= 0 {
		expectedRowVersion = current.RowVersion
	}
	requestID := ws3RequestID("req_local_rename")
	localCaller, err := profile.NewLocalMaintenanceCaller(a.operatorID)
	if err != nil {
		return LocalUser{}, err
	}
	actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: a.operatorID}
	reasonField := audit.FieldChange{Field: "reason", After: reason}
	usernameChange := audit.FieldChange{Field: "username", Before: current.Username,
		After: newUsername}
	if current.IsRoot {
		plan, planErr := a.base.Managed.Profile.PrepareLocalMaintenanceRootRename(ctx,
			localCaller, profile.ManagementRenameRequest{TargetUserID: userID,
				NewUsername: newUsername, ExpectedRowVersion: expectedRowVersion,
				RequestID: requestID})
		if planErr != nil {
			return LocalUser{}, localDomainError("准备 root 更名", planErr)
		}
		var updated profile.UserProfile
		auditErr := a.base.Audit.ExecuteCritical(ctx, audit.CriticalRequest{
			Event: audit.Event{Actor: actor, Action: "user.username.change.local_root",
				Target:    audit.Target{Type: "user", ID: userID},
				Changes:   []audit.FieldChange{usernameChange, reasonField},
				RequestID: requestID},
			FailureReasonCode: "user.username.change.failed",
		}, func(txCtx context.Context, tx audit.Tx) error {
			value, applyErr := a.base.Managed.Profile.ApplyLocalMaintenanceRootRenameTx(
				txCtx, tx, localCaller, plan)
			if applyErr != nil {
				return applyErr
			}
			updated = value
			return nil
		})
		if auditErr != nil {
			return LocalUser{}, localDomainError("提交 root 更名", auditErr)
		}
		return a.updatedLocalUser(ctx, updated)
	}
	plan, planErr := a.base.Managed.Profile.PrepareManagementRename(ctx,
		profile.ManagementRenameRequest{TargetUserID: userID, NewUsername: newUsername,
			ExpectedRowVersion: expectedRowVersion, RequestID: requestID})
	if planErr != nil {
		return LocalUser{}, localDomainError("准备更名", planErr)
	}
	var updated profile.UserProfile
	auditErr := a.base.Audit.ExecuteCritical(ctx, audit.CriticalRequest{
		Event: audit.Event{Actor: actor, Action: "user.username.change.local_maintenance",
			Target:    audit.Target{Type: "user", ID: userID},
			Changes:   []audit.FieldChange{usernameChange, reasonField},
			RequestID: requestID},
		FailureReasonCode: "user.username.change.failed",
	}, func(txCtx context.Context, tx audit.Tx) error {
		value, applyErr := a.base.Managed.Profile.ApplyManagementRenameTx(txCtx, tx, plan)
		if applyErr != nil {
			return applyErr
		}
		updated = value
		return nil
	})
	if auditErr != nil {
		return LocalUser{}, localDomainError("提交更名", auditErr)
	}
	return a.updatedLocalUser(ctx, updated)
}

// updatedLocalUser 重新读取更名后的账户并补齐 root 标记。
func (a *localIdentityAdmin) updatedLocalUser(ctx context.Context,
	updated profile.UserProfile) (LocalUser, error) {
	caller, err := account.LocalBootstrapCaller(a.operatorID)
	if err != nil {
		return LocalUser{}, err
	}
	user, err := a.base.Managed.Account.GetUser(ctx, caller, updated.UserID)
	if err != nil {
		return LocalUser{}, localDomainError("读取更名后用户", err)
	}
	value := localUserFromAccount(user)
	value.IsRoot = updated.IsRoot
	return value, nil
}

func (a *localIdentityAdmin) SetPassword(ctx context.Context, userID, newPassword string,
	requireChange bool) (LocalPasswordResult, error) {
	if strings.TrimSpace(newPassword) == "" {
		return LocalPasswordResult{}, fmt.Errorf("新密码不能为空")
	}
	caller, err := authn.LocalAdminCaller(a.operatorID)
	if err != nil {
		return LocalPasswordResult{}, err
	}
	user, err := a.base.Managed.Account.GetUser(ctx, mustAccountCaller(a.operatorID), strings.TrimSpace(userID))
	if err != nil {
		return LocalPasswordResult{}, localDomainError("读取目标用户", err)
	}
	requestID := ws3RequestID("req_local_password")
	if user.ID == "" {
		return LocalPasswordResult{}, fmt.Errorf("目标用户不存在")
	}
	rootUserID := ""
	if a.base.Services != nil && a.base.Services.BootstrapStore != nil {
		if root, found, rootErr := a.base.Services.BootstrapStore.GetRootAccount(ctx); rootErr == nil && found {
			rootUserID = root.UserID
		}
	}
	if rootUserID != "" && user.ID == rootUserID {
		localCaller, localErr := authn.NewLocalMaintenanceCaller(a.operatorID)
		if localErr != nil {
			return LocalPasswordResult{}, localErr
		}
		result, err := a.base.Services.Authn.LocalMaintenanceSetRootPassword(ctx,
			localCaller, user.ID, newPassword, requestID)
		if err != nil {
			return LocalPasswordResult{}, localDomainError("设置 root 密码", err)
		}
		return LocalPasswordResult{UserID: result.RootUserID,
			SecurityVersion: result.SecurityVersion, PasswordChangedAt: result.PasswordChangedAt,
			MustChange: false}, nil
	}
	_ = caller
	localCaller, localErr := authn.NewLocalMaintenanceCaller(a.operatorID)
	if localErr != nil {
		return LocalPasswordResult{}, localErr
	}
	result, err := a.base.Services.Authn.LocalMaintenanceSetPassword(ctx, localCaller,
		user.ID, newPassword, requireChange, requestID)
	if err != nil {
		return LocalPasswordResult{}, localDomainError("设置密码", err)
	}
	return LocalPasswordResult{UserID: result.UserID,
		SecurityVersion: result.SecurityVersion, PasswordChangedAt: result.PasswordChangedAt,
		MustChange: requireChange}, nil
}

func (a *localIdentityAdmin) Credentials(ctx context.Context,
	userID string) (LocalCredentialStatus, error) {
	caller, err := authn.NewLocalMaintenanceCaller(a.operatorID)
	if err != nil {
		return LocalCredentialStatus{}, err
	}
	status, err := a.base.Services.Authn.LocalMaintenanceCredentialStatus(ctx,
		caller, strings.TrimSpace(userID))
	if err != nil {
		return LocalCredentialStatus{}, localDomainError("读取凭证状态", err)
	}
	return LocalCredentialStatus{UserID: status.UserID, HasPassword: status.HasPassword,
		IsRoot: status.IsRoot}, nil
}

// ---------- 289 角色/权限/用户组 ----------

type localRBACAdmin struct {
	base       *serverapp.Base
	operatorID string
	presetMu   sync.Mutex
	preset     *preset.Service
}

func newLocalRBACAdmin(base *serverapp.Base, operatorID string) (*localRBACAdmin, error) {
	if _, err := role.LocalBootstrapCaller(operatorID); err != nil {
		return nil, fmt.Errorf("%w: 本地操作者标识无效", ErrLocalRuntimeUnavailable)
	}
	return &localRBACAdmin{base: base, operatorID: operatorID}, nil
}

func (a *localRBACAdmin) roleCaller() (role.Caller, error) {
	return role.LocalBootstrapCaller(a.operatorID)
}
func (a *localRBACAdmin) groupCaller() (group.Caller, error) {
	return group.LocalBootstrapCaller(a.operatorID)
}
func (a *localRBACAdmin) permissionCaller() (permission.Caller, error) {
	return permission.LocalBootstrapCaller(a.operatorID)
}

func (a *localRBACAdmin) ListRoles(ctx context.Context, query LocalPageRequest,
	scopeID string) ([]LocalRole, bool, error) {
	caller, err := a.roleCaller()
	if err != nil {
		return nil, false, err
	}
	limit := query.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if strings.TrimSpace(scopeID) == "" {
		scopeID = "system"
	}
	result, err := a.base.Managed.Role.ListRoles(ctx, caller, role.ListRequest{
		ScopeID: strings.TrimSpace(scopeID), Limit: limit, Offset: maxInt(query.Offset, 0),
		Search: strings.TrimSpace(query.Search)})
	if err != nil {
		return nil, false, localDomainError("列出角色", err)
	}
	roles := make([]LocalRole, 0, len(result.Roles))
	for _, item := range result.Roles {
		roles = append(roles, localRoleFromDomain(item))
	}
	return roles, result.HasMore, nil
}

func (a *localRBACAdmin) ListPermissions(ctx context.Context,
	query LocalPageRequest) ([]LocalPermission, bool, error) {
	caller, err := a.permissionCaller()
	if err != nil {
		return nil, false, err
	}
	limit := query.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	result, err := a.base.Managed.Permission.ListPermissions(ctx, caller, permission.ListRequest{
		Limit: limit, Offset: maxInt(query.Offset, 0),
		Search: strings.TrimSpace(query.Search)})
	if err != nil {
		return nil, false, localDomainError("列出权限", err)
	}
	implemented := make(map[string]bool)
	if catalog := preset.DefaultCatalog(); catalog != nil {
		for _, definition := range catalog.Permissions {
			implemented[definition.Key] = definition.Implemented
		}
	}
	items := make([]LocalPermission, 0, len(result.Permissions))
	for _, item := range result.Permissions {
		items = append(items, LocalPermission{Key: item.Key, Name: item.Name,
			Implemented: implemented[item.Key], RootOnly: item.RootOnly})
	}
	return items, result.HasMore, nil
}

func (a *localRBACAdmin) ListGroups(ctx context.Context, query LocalPageRequest,
	scopeID string) ([]LocalGroup, bool, error) {
	caller, err := a.groupCaller()
	if err != nil {
		return nil, false, err
	}
	limit := query.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if strings.TrimSpace(scopeID) == "" {
		scopeID = "system"
	}
	result, err := a.base.Managed.Group.ListGroups(ctx, caller, group.ListRequest{
		ScopeID: strings.TrimSpace(scopeID), Limit: limit, Offset: maxInt(query.Offset, 0),
		Search: strings.TrimSpace(query.Search)})
	if err != nil {
		return nil, false, localDomainError("列出用户组", err)
	}
	items := make([]LocalGroup, 0, len(result.Groups))
	for _, item := range result.Groups {
		items = append(items, LocalGroup{ID: item.ID, Key: item.GroupKey, Name: item.Name,
			ScopeID: item.ScopeID, Enabled: true})
	}
	return items, result.HasMore, nil
}

func (a *localRBACAdmin) presetService() (*preset.Service, error) {
	a.presetMu.Lock()
	defer a.presetMu.Unlock()
	if a.preset != nil {
		return a.preset, nil
	}
	if a.base == nil || a.base.Store == nil || a.base.Audit == nil ||
		a.base.Managed == nil || a.base.Managed.Delegation == nil {
		return nil, fmt.Errorf("%w: 预设服务依赖未装配（存储/审计/委派）",
			ErrLocalUnsupported)
	}
	store, err := presetsqlite.New(a.base.Store)
	if err != nil {
		return nil, localDomainError("构造预设存储", err)
	}
	service, err := preset.New(preset.Options{Store: store, Audit: a.base.Audit,
		Transfers: a.base.Managed.Delegation, Now: a.base.Now,
		Logger: a.base.Logger})
	if err != nil {
		return nil, localDomainError("构造预设服务", err)
	}
	a.preset = service
	return service, nil
}

func (a *localRBACAdmin) presetCaller() (preset.Caller, error) {
	return preset.LocalBootstrapCaller(a.operatorID)
}

func (a *localRBACAdmin) PreviewPresetRestore(ctx context.Context, scopeID,
	roleKey string) (LocalPresetDiff, error) {
	service, err := a.presetService()
	if err != nil {
		return LocalPresetDiff{}, err
	}
	caller, err := a.presetCaller()
	if err != nil {
		return LocalPresetDiff{}, err
	}
	scopeID = strings.TrimSpace(scopeID)
	if scopeID == "" {
		scopeID = "system"
	}
	roleKey = strings.TrimSpace(roleKey)
	request := preset.PreviewRequest{}
	if roleKey == "" {
		request.All = true
	} else {
		request.Selections = []preset.RoleSelection{{ScopeID: scopeID,
			RoleKeys: []string{roleKey}}}
	}
	preview, err := service.Preview(ctx, caller, request)
	if err != nil {
		return LocalPresetDiff{}, localDomainError("预览预设恢复", err)
	}
	diff := LocalPresetDiff{ScopeID: scopeID, RoleKey: roleKey,
		PreviewToken: preview.Token, AffectedKnown: false,
		CurrentComps: preview.Summary.TotalChanges()}
	diff.Add = mapPresetPermissionKeys(preview, roleKey, true)
	diff.Remove = mapPresetPermissionKeys(preview, roleKey, false)
	diff.Affected = a.countPresetAffected(ctx, preview, roleKey)
	if diff.Affected >= 0 {
		diff.AffectedKnown = true
	}
	diff.PresetComps = preview.Summary.TotalChanges()
	return diff, nil
}

// mapPresetPermissionKeys 从预览差异提取角色新增/移除权限键（scope 级缺失权限
// 一并作为“新增”展示，便于操作者看到完整影响）。
func mapPresetPermissionKeys(preview preset.Preview, roleKey string, add bool) []string {
	keys := make([]string, 0, 8)
	seen := make(map[string]bool)
	appendKey := func(key string) {
		if key == "" || seen[key] {
			return
		}
		seen[key] = true
		keys = append(keys, key)
	}
	for _, scope := range preview.Scopes {
		if add {
			for _, permission := range scope.MissingPermissions {
				appendKey(permission.Key)
			}
		}
		for _, roleDiff := range scope.RoleDiffs {
			if roleKey != "" && roleDiff.RoleKey != roleKey {
				continue
			}
			if add {
				for _, permission := range roleDiff.AddPermissions {
					appendKey(permission.Key)
				}
			} else {
				for _, permission := range roleDiff.RemovePermissions {
					appendKey(permission.Key)
				}
			}
		}
	}
	return keys
}

// countPresetAffected 统计差异涉及角色的当前分配数（用户 + 用户组）；无法枚举时
// 返回 -1（画面显示“未知”，不伪造 0）。
func (a *localRBACAdmin) countPresetAffected(ctx context.Context, preview preset.Preview,
	roleKey string) int {
	if a.base.Managed.Role == nil {
		return -1
	}
	caller, err := a.roleCaller()
	if err != nil {
		return -1
	}
	total := 0
	known := true
	for _, scope := range preview.Scopes {
		for _, roleDiff := range scope.RoleDiffs {
			if roleKey != "" && roleDiff.RoleKey != roleKey {
				continue
			}
			if roleDiff.RoleID == "" {
				continue
			}
			page, listErr := a.base.Managed.Role.ListRoleAssignmentsPaged(ctx, caller,
				role.AssignmentListRequest{RoleID: roleDiff.RoleID, UserLimit: 100,
					GroupLimit: 100})
			if listErr != nil {
				known = false
				continue
			}
			total += len(page.Users) + len(page.Groups)
			if page.UsersHasMore || page.GroupsHasMore {
				known = false
			}
		}
	}
	if !known {
		return -1
	}
	return total
}

func (a *localRBACAdmin) RestorePreset(ctx context.Context, diff LocalPresetDiff,
	confirm bool) error {
	if !confirm {
		return fmt.Errorf("预设恢复需要显式确认（先预览差异）")
	}
	if strings.TrimSpace(diff.PreviewToken) == "" {
		return fmt.Errorf("缺少差异预览确认令牌，请重新预览")
	}
	service, err := a.presetService()
	if err != nil {
		return err
	}
	caller, err := a.presetCaller()
	if err != nil {
		return err
	}
	if _, err := service.Restore(ctx, caller,
		preset.RestoreRequest{Token: diff.PreviewToken}); err != nil {
		return localDomainError("应用预设恢复", err)
	}
	return nil
}

func (a *localRBACAdmin) SetRoleEnabled(ctx context.Context, roleID string,
	enabled bool) error {
	caller, err := a.roleCaller()
	if err != nil {
		return err
	}
	if enabled {
		_, _, err = a.base.Managed.Role.EnableRole(ctx, caller, strings.TrimSpace(roleID))
	} else {
		_, _, err = a.base.Managed.Role.DisableRole(ctx, caller, strings.TrimSpace(roleID))
	}
	if err != nil {
		return localDomainError("启停角色", err)
	}
	return nil
}

func (a *localRBACAdmin) AddGroupMember(ctx context.Context, groupID, userID string) error {
	caller, err := a.groupCaller()
	if err != nil {
		return err
	}
	if _, err := a.base.Managed.Group.AddMembers(ctx, caller, group.MemberBatchRequest{
		GroupID: strings.TrimSpace(groupID), UserIDs: []string{strings.TrimSpace(userID)}}); err != nil {
		return localDomainError("添加组成员", err)
	}
	return nil
}

func (a *localRBACAdmin) RemoveGroupMember(ctx context.Context, groupID, userID string) error {
	caller, err := a.groupCaller()
	if err != nil {
		return err
	}
	if _, err := a.base.Managed.Group.RemoveMembers(ctx, caller, group.MemberBatchRequest{
		GroupID: strings.TrimSpace(groupID), UserIDs: []string{strings.TrimSpace(userID)}}); err != nil {
		return localDomainError("移除组成员", err)
	}
	return nil
}

// ---------- 290 应用（只读部分） ----------

type localAppAdmin struct {
	base       *serverapp.Base
	operatorID string
}

func (a *localAppAdmin) caller() (app.Caller, error) {
	return app.LocalBootstrapCaller(a.operatorID)
}

func (a *localAppAdmin) ListApplications(ctx context.Context,
	query LocalPageRequest) ([]LocalApplication, bool, error) {
	caller, err := a.caller()
	if err != nil {
		return nil, false, err
	}
	limit := query.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	result, err := a.base.Managed.App.ListApplications(ctx, caller, app.ListRequest{
		Limit: limit, Offset: maxInt(query.Offset, 0), Search: strings.TrimSpace(query.Search)})
	if err != nil {
		return nil, false, localDomainError("列出应用", err)
	}
	items := make([]LocalApplication, 0, len(result.Applications))
	for _, item := range result.Applications {
		items = append(items, localApplicationFromDomain(item))
	}
	return items, result.HasMore, nil
}

func (a *localAppAdmin) GetApplication(ctx context.Context,
	applicationID string) (LocalApplication, error) {
	caller, err := a.caller()
	if err != nil {
		return LocalApplication{}, err
	}
	item, err := a.base.Managed.App.GetApplication(ctx, caller, strings.TrimSpace(applicationID))
	if err != nil {
		return LocalApplication{}, localDomainError("读取应用", err)
	}
	return localApplicationFromDomain(item), nil
}

func (a *localAppAdmin) CreateApplication(ctx context.Context, name, description,
	homepage string) (LocalApplication, error) {
	caller, err := a.caller()
	if err != nil {
		return LocalApplication{}, err
	}
	created, err := a.base.Managed.App.CreateApplication(ctx, caller, app.CreateRequest{
		Name: strings.TrimSpace(name), Description: strings.TrimSpace(description),
		Homepage: strings.TrimSpace(homepage), ClientType: app.ClientTypeConfidential})
	if err != nil {
		return LocalApplication{}, localDomainError("创建应用", err)
	}
	return localApplicationFromDomain(created), nil
}

func (a *localAppAdmin) UpdateApplication(ctx context.Context, applicationID, name,
	description, homepage string, expectedRowVersion int64) (LocalApplication, error) {
	caller, err := a.caller()
	if err != nil {
		return LocalApplication{}, err
	}
	current, err := a.base.Managed.App.GetApplication(ctx, caller, strings.TrimSpace(applicationID))
	if err != nil {
		return LocalApplication{}, localDomainError("读取应用", err)
	}
	if expectedRowVersion <= 0 {
		expectedRowVersion = current.RowVersion
	}
	updated, err := a.base.Managed.App.UpdateApplication(ctx, caller,
		strings.TrimSpace(applicationID), app.UpdateRequest{
			Name: strings.TrimSpace(name), Description: strings.TrimSpace(description),
			Homepage: strings.TrimSpace(homepage), OwnerUserID: current.OwnerUserID,
			ExpectedRowVersion: expectedRowVersion})
	if err != nil {
		return LocalApplication{}, localDomainError("更新应用", err)
	}
	return localApplicationFromDomain(updated), nil
}

func (a *localAppAdmin) SetApplicationEnabled(ctx context.Context, applicationID string,
	enabled bool) error {
	caller, err := a.caller()
	if err != nil {
		return err
	}
	current, err := a.base.Managed.App.GetApplication(ctx, caller, strings.TrimSpace(applicationID))
	if err != nil {
		return localDomainError("读取应用", err)
	}
	request := app.StatusRequest{ApplicationID: current.ID,
		ExpectedRowVersion: current.RowVersion}
	if enabled {
		_, err = a.base.Managed.App.EnableApplication(ctx, caller, request)
	} else {
		_, err = a.base.Managed.App.DisableApplication(ctx, caller, request)
	}
	if err != nil {
		return localDomainError("启停应用", err)
	}
	return nil
}

func (a *localAppAdmin) ListMembers(ctx context.Context, applicationID string,
	query LocalPageRequest) ([]LocalAppMember, bool, error) {
	caller, err := a.caller()
	if err != nil {
		return nil, false, err
	}
	limit := query.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	result, err := a.base.Managed.App.ListApplicationMembers(ctx, caller,
		app.MemberListRequest{ApplicationID: strings.TrimSpace(applicationID),
			Limit: limit, Offset: maxInt(query.Offset, 0),
			Search: strings.TrimSpace(query.Search)})
	if err != nil {
		return nil, false, localDomainError("列出应用成员", err)
	}
	accountCaller := mustAccountCaller(a.operatorID)
	members := make([]LocalAppMember, 0, len(result.Members))
	for _, member := range result.Members {
		item := LocalAppMember{UserID: member.UserID, Status: string(member.Status)}
		if a.base.Managed.Account != nil {
			if user, getErr := a.base.Managed.Account.GetUser(ctx, accountCaller,
				member.UserID); getErr == nil {
				item.Username = user.Username
				item.Nickname = user.Nickname
			}
		}
		members = append(members, item)
	}
	return members, result.HasMore, nil
}

func (a *localAppAdmin) AddMember(ctx context.Context, applicationID, userID string) error {
	caller, err := a.caller()
	if err != nil {
		return err
	}
	if _, err := a.base.Managed.App.AddApplicationMember(ctx, caller,
		app.AddMemberRequest{ApplicationID: strings.TrimSpace(applicationID),
			UserID: strings.TrimSpace(userID)}); err != nil {
		return localDomainError("添加应用成员", err)
	}
	return nil
}

func (a *localAppAdmin) RemoveMember(ctx context.Context, applicationID, userID string) error {
	caller, err := a.caller()
	if err != nil {
		return err
	}
	current, err := a.base.Managed.App.GetApplicationMember(ctx, caller,
		strings.TrimSpace(applicationID), strings.TrimSpace(userID))
	if err != nil {
		return localDomainError("读取应用成员", err)
	}
	if err := a.base.Managed.App.RemoveApplicationMember(ctx, caller,
		app.RemoveMemberRequest{ApplicationID: strings.TrimSpace(applicationID),
			UserID: strings.TrimSpace(userID), ExpectedRowVersion: current.RowVersion}); err != nil {
		return localDomainError("移除应用成员", err)
	}
	return nil
}

func (a *localAppAdmin) ListClients(ctx context.Context,
	applicationID string) ([]LocalAppClient, error) {
	caller, err := oauthclient.NewLocalMaintenanceCaller(a.operatorID)
	if err != nil {
		return nil, err
	}
	state, err := a.base.Managed.OAuthClient.LocalMaintenanceClientState(ctx, caller,
		strings.TrimSpace(applicationID))
	if err != nil {
		return nil, localDomainError("读取 OAuth 客户端", err)
	}
	if !state.Registered {
		return nil, nil
	}
	return []LocalAppClient{{ClientID: strings.TrimSpace(applicationID),
		Name: strings.TrimSpace(applicationID), Type: string(state.ClientType),
		RedirectURIs: state.RedirectURIs, Status: "registered"}}, nil
}

func (a *localAppAdmin) CreateClient(ctx context.Context, applicationID, name string,
	redirectURIs []string) (LocalAppClientCreated, error) {
	audience := ""
	if len(redirectURIs) > 0 {
		if parsed, parseErr := url.Parse(redirectURIs[0]); parseErr == nil &&
			parsed.Scheme != "" && parsed.Host != "" {
			audience = parsed.Scheme + "://" + parsed.Host
		}
	}
	if audience == "" {
		return LocalAppClientCreated{}, fmt.Errorf("至少一个重定向 URI 必须是绝对 http(s) URL")
	}
	request := oauthclient.RegisterRequest{ClientID: strings.TrimSpace(applicationID),
		ClientType:   oauthclient.ClientTypeConfidential,
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		RedirectURIs: redirectURIs, Audiences: []string{audience},
		AuthMethods: []string{"client_secret_basic"},
		RequestID:   ws3RequestID("req_local_oauth_register")}
	caller, err := oauthclient.NewLocalMaintenanceCaller(a.operatorID)
	if err != nil {
		return LocalAppClientCreated{}, err
	}
	result, err := a.base.Managed.OAuthClient.LocalMaintenanceRegisterClient(ctx, caller, request)
	if err != nil {
		return LocalAppClientCreated{}, localDomainError("登记 OAuth 客户端", err)
	}
	secret := ""
	if result.Secret != nil {
		secret = result.Secret.Secret
	}
	return LocalAppClientCreated{Client: LocalAppClient{
		ClientID: result.Client.ClientID, Name: strings.TrimSpace(name),
		Type: string(result.Client.ClientType), RedirectURIs: result.Client.RedirectURIs,
		Status: "registered", SecretShown: secret != ""}, Secret: secret}, nil
}

func (a *localAppAdmin) RotateClientSecret(ctx context.Context, applicationID,
	clientID string) (LocalAppClientCreated, error) {
	_ = applicationID
	caller, err := oauthclient.NewLocalMaintenanceCaller(a.operatorID)
	if err != nil {
		return LocalAppClientCreated{}, err
	}
	rotated, err := a.base.Managed.OAuthClient.LocalMaintenanceRotateClientSecret(ctx,
		caller, strings.TrimSpace(clientID), ws3RequestID("req_local_oauth_rotate"))
	if err != nil {
		return LocalAppClientCreated{}, localDomainError("轮换 OAuth 客户端密钥", err)
	}
	return LocalAppClientCreated{Client: LocalAppClient{ClientID: strings.TrimSpace(clientID),
		Name: strings.TrimSpace(clientID), Type: "confidential", Status: "registered",
		SecretShown: true}, Secret: rotated.Secret}, nil
}

func (a *localAppAdmin) RevokeClient(ctx context.Context, applicationID, clientID string) error {
	_ = applicationID
	caller, err := oauthclient.NewLocalMaintenanceCaller(a.operatorID)
	if err != nil {
		return err
	}
	state, err := a.base.Managed.OAuthClient.LocalMaintenanceClientState(ctx, caller,
		strings.TrimSpace(clientID))
	if err != nil {
		return localDomainError("读取 OAuth 客户端", err)
	}
	revoked := 0
	for _, secret := range state.Secrets {
		if secret.Revoked {
			continue
		}
		if err := a.base.Managed.OAuthClient.LocalMaintenanceRevokeClientSecret(ctx, caller,
			strings.TrimSpace(clientID), secret.ID,
			ws3RequestID("req_local_oauth_revoke")); err != nil {
			return localDomainError("撤销 OAuth 客户端密钥", err)
		}
		revoked++
	}
	if revoked == 0 {
		return fmt.Errorf("没有可撤销的客户端密钥")
	}
	return nil
}

// ---------- 288/291 未接入适配器（明确不可用，不伪造） ----------

type unsupportedSecurityAdmin struct{}

func (unsupportedSecurityAdmin) ListFactors(context.Context, string) ([]LocalFactor, error) {
	return nil, fmt.Errorf("%w: MFA 因素列举依赖 totp/mfa/passkey/recovery 本地窄方法",
		ErrLocalUnsupported)
}
func (unsupportedSecurityAdmin) RemoveFactor(context.Context, string, LocalFactor, string) error {
	return fmt.Errorf("%w: MFA 因素删除依赖本地窄方法", ErrLocalUnsupported)
}
func (unsupportedSecurityAdmin) RevokeRecoveryCodes(context.Context, string, string) error {
	return fmt.Errorf("%w: 恢复代码撤销依赖本地窄方法", ErrLocalUnsupported)
}
func (unsupportedSecurityAdmin) ClearSecondFactors(context.Context, string, bool, string) error {
	return fmt.Errorf("%w: 第二因素清除依赖本地窄方法", ErrLocalUnsupported)
}
func (unsupportedSecurityAdmin) ListSessions(context.Context, string, int, int) ([]LocalSession, bool, error) {
	return nil, false, fmt.Errorf("%w: 按用户会话列表依赖 session 本地窄方法", ErrLocalUnsupported)
}
func (unsupportedSecurityAdmin) RevokeSessions(context.Context, string, string) (int64, error) {
	return 0, fmt.Errorf("%w: 会话撤销依赖会话服务装配", ErrLocalUnsupported)
}

type unsupportedAuditAdmin struct{}

func (unsupportedAuditAdmin) QueryAudit(context.Context, LocalAuditFilter) (LocalAuditPage, error) {
	return LocalAuditPage{}, fmt.Errorf("%w: 审计查询依赖 auditops 本地维护授权适配",
		ErrLocalUnsupported)
}
func (unsupportedAuditAdmin) Diagnostics(context.Context) (LocalDiagnostics, error) {
	return LocalDiagnostics{}, fmt.Errorf("%w: 诊断摘要依赖实例检测", ErrLocalUnsupported)
}
func (unsupportedAuditAdmin) ListDeliveries(context.Context, int, int) ([]LocalDelivery, bool, error) {
	return nil, false, fmt.Errorf("%w: 投递状态依赖邮件/通知服务本地适配", ErrLocalUnsupported)
}
func (unsupportedAuditAdmin) ListReports(context.Context, int, int) ([]LocalReport, bool, error) {
	return nil, false, fmt.Errorf("%w: 报告列表依赖 reports 本地适配", ErrLocalUnsupported)
}
func (unsupportedAuditAdmin) GenerateReport(context.Context, string, string) (LocalReport, error) {
	return LocalReport{}, fmt.Errorf("%w: 报告生成依赖 reports 本地适配", ErrLocalUnsupported)
}
func (unsupportedAuditAdmin) ListTasks(context.Context, int, int) ([]LocalTask, bool, error) {
	return nil, false, fmt.Errorf("%w: 任务列表依赖 task 本地适配", ErrLocalUnsupported)
}
func (unsupportedAuditAdmin) CancelTask(context.Context, string, string) (LocalTask, error) {
	return LocalTask{}, fmt.Errorf("%w: 任务取消依赖 task 本地适配", ErrLocalUnsupported)
}

// ---------- 映射与错误辅助 ----------

func localUserFromAccount(user account.User) LocalUser {
	return LocalUser{ID: user.ID, Username: user.Username, Nickname: user.Nickname,
		Biography: user.Biography, Language: user.Language, Timezone: user.Timezone,
		Status: string(user.Status), RowVersion: user.RowVersion,
		SecurityVersion: user.SecurityVersion, CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt}
}

func localDeletionPreview(preview account.DeletionPreview) LocalDeletionPreview {
	return LocalDeletionPreview{UserID: preview.UserID, Username: preview.Username,
		Status: string(preview.Status), IsRoot: preview.IsRoot,
		RowVersion: preview.RowVersion, SecurityVersion: preview.SecurityVersion,
		AppMemberships: preview.AppMemberships, UserRoles: preview.UserRoles,
		GroupMemberships:   preview.GroupMemberships,
		OneTimeCredentials: preview.OneTimeCredentials,
		OwnedApplications:  preview.OwnedApplications}
}

func localRoleFromDomain(item role.Role) LocalRole {
	return LocalRole{ID: item.ID, Key: item.Key, Name: item.Name,
		ScopeID: item.ScopeID, Enabled: item.Enabled, Builtin: item.IsBuiltin}
}

func localApplicationFromDomain(item app.Application) LocalApplication {
	return LocalApplication{ID: item.ID, Name: item.Name, Description: item.Description,
		Homepage: item.Homepage, OwnerUserID: item.OwnerUserID,
		Status: string(item.Status), RowVersion: item.RowVersion}
}

func localDomainError(operation string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrLocalUnsupported) || errors.Is(err, ErrLocalRuntimeUnavailable) {
		return err
	}
	return fmt.Errorf("本地维护%s失败: %w", operation, err)
}

func mustAccountCaller(operatorID string) account.Caller {
	caller, err := account.LocalBootstrapCaller(operatorID)
	if err != nil {
		return account.Caller{}
	}
	return caller
}

func maxInt(value, minimum int) int {
	if value < minimum {
		return minimum
	}
	return value
}
