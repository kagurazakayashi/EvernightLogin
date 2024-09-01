package app

import (
	"context"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/profile"
)

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

				return AdminUser{}, call.domainError("创建用户后建立应用成员关系失败",
					string(app.CodeOf(memberErr)))
			}
		}
	}
	return AdminUser{ID: created.ID, Username: created.Username,
		Nickname: created.Nickname, Status: string(created.Status),
		CreatedAt: created.CreatedAt}, nil
}

// adminUserSearchFields 把公开门面的字符串搜索字段转换为账户领域白名单类型；
// 空/未知值不在门面层猜测，交给领域服务统一校验并返回 REQ_INVALID。
func adminUserSearchFields(fields []string) []account.UserSearchField {
	if len(fields) == 0 {
		return nil
	}
	converted := make([]account.UserSearchField, 0, len(fields))
	for _, field := range fields {
		converted = append(converted, account.UserSearchField(strings.TrimSpace(field)))
	}
	return converted
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
		Search: req.Search, SearchFields: adminUserSearchFields(req.SearchFields),
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
