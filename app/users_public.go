// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

// 用户生命周期管理公开 Go 接口（步骤 223）。
//
// 设计边界：
//   - 只复用 internal/account 的真实生命周期语义（状态机、root 保护、乐观并发、
//     关键审计与状态变更同事务），不复制第二套实现；
//   - 身份只来自 AdminCaller：LocalAdmin 是持有宿主进程控制权的可信本地代码
//     （审计主体为 local_admin，不是 is_root，不改变 root 保护）；AdminSession 是
//     真实用户完整会话，由账户服务按系统范围权限（users.read/users.update/
//     users.delete）与强认证判定，应用范围管理员无法通过系统范围检查；
//   - 所有写操作解析一次 RequestID（空生成、非法 REQ_INVALID）并贯穿领域审计与
//     返回错误；禁用/待删除递增 security_version，旧会话与令牌在下次校验时失效
//     （enable 不递减版本，不复活旧凭证）；
//   - 已授权但目标不存在时返回稳定的 NOT_FOUND（与步骤 207 契约一致），而不是
//     参数错误或 ACCESS_DENIED；
//   - 不提供 is_root/强制写入字段，不提供管理员强制改他人密码（本人改密见
//     PasswordChangeService）。
//
// 访问器 Runtime.UserLifecycle() 由本文件定义；未编辑 app/runtime.go 或
// app/admin.go/types.go（218 在途），避免并行写冲突。

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
)

// UserLifecycleService 是用户生命周期管理门面（按稳定 ID 读取、禁用/启用、
// 受控删除三步）。列表与创建仍由 AdminService 提供，避免重复接口。
type UserLifecycleService interface {
	// GetUser 按稳定用户 ID 读取生命周期视图（状态、row_version、
	// security_version）；需要 users.read。root 保护标记请用
	// AdminService.GetUserProfile（资料视图）读取，本视图不重复暴露。
	GetUser(ctx context.Context, req AdminUserRequest) (AdminUserState, error)
	// DisableUser 全局禁用账户：status -> disabled，row_version 与
	// security_version 各递增 1；已禁用时幂等成功（Changed=false，不改版本）；
	// root 返回 ACCESS_DENIED；并发版本不匹配返回 CONFLICT。
	DisableUser(ctx context.Context, req AdminUserStateRequest) (AdminUserStateChange, error)
	// EnableUser 启用已禁用账户：status -> active，row_version 递增 1；
	// security_version 不递减（重新启用不会恢复旧会话/旧令牌）。
	EnableUser(ctx context.Context, req AdminUserStateRequest) (AdminUserStateChange, error)
	// PreviewUserDeletion 读取完成删除的影响范围快照（只读、不执行删除）。
	PreviewUserDeletion(ctx context.Context, req AdminUserRequest) (AdminDeletionPreview, error)
	// RequestUserDeletion 把账户标记为 pending_delete（保留资料与应用数据，
	// 递增 security_version 使旧会话失效）；重复请求幂等成功。
	RequestUserDeletion(ctx context.Context, req AdminUserStateRequest) (AdminUserStateChange, error)
	// CompleteUserDeletion 完成不可逆删除；只允许 pending_delete 状态且
	// expected_row_version 必须匹配；root 拒绝；审计失败整体拒绝（业务回滚）。
	CompleteUserDeletion(ctx context.Context, req AdminUserStateRequest) (AdminDeletionResult, error)
}

// AdminUserState 是生命周期视图（脱敏；不含密码、哈希、秘密或邮箱）。
type AdminUserState struct {
	ID        string
	Username  string
	Nickname  string
	Biography string
	Language  string
	Timezone  string
	Status    string
	// RowVersion 是乐观并发版本；写操作必须回传读取到的值。
	RowVersion int64
	// SecurityVersion 是会话/令牌失效版本；disable 与 request_deletion 递增。
	SecurityVersion int64
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// AdminUserStateRequest 是生命周期写请求。
type AdminUserStateRequest struct {
	Caller             AdminCaller
	UserID             string
	ExpectedRowVersion int64
	RequestID          string
}

// AdminUserStateChange 是一次状态/删除请求的结果。Changed=false 表示幂等命中
// 目标状态（未改版本）；RequiresRelogin=true 表示本次变更递增了安全版本，旧
// 会话/令牌在下次校验失效。
type AdminUserStateChange struct {
	User            AdminUserState
	PreviousStatus  string
	Changed         bool
	RequiresRelogin bool
}

// AdminDeletionPreview 是完成删除前的影响范围快照（读取时快照，实际删除在事务
// 内重新执行；root 标记用于让调用方拒绝普通删除流程）。
type AdminDeletionPreview struct {
	UserID             string
	Username           string
	Status             string
	RowVersion         int64
	SecurityVersion    int64
	IsRoot             bool
	AppMemberships     int
	UserRoles          int
	GroupMemberships   int
	OneTimeCredentials int
	OwnedApplications  int
}

// AdminDeletionResult 是完成删除的结果与删除前影响快照。
type AdminDeletionResult struct {
	Preview   AdminDeletionPreview
	DeletedAt time.Time
}

// UserLifecycle 返回用户生命周期管理门面。
//
// 访问器定义在新增文件而不是 runtime.go：223 与 218/220 并行期间不制造写冲突，
// Go 允许在同一个包内为 Runtime 定义方法。
func (r *Runtime) UserLifecycle() UserLifecycleService {
	return &userLifecycleFacade{r: r}
}

type userLifecycleFacade struct {
	r *Runtime
}

// admin 返回复用的管理门面（提供 begin/accountCaller/错误映射等私有 helper）。
func (f *userLifecycleFacade) admin() *adminFacade {
	return &adminFacade{r: f.r}
}

// GetUser 按稳定用户 ID 读取生命周期视图（领域服务先判权再读取，未授权不会
// 暴露用户是否存在）。
func (f *userLifecycleFacade) GetUser(ctx context.Context,
	req AdminUserRequest) (AdminUserState, error) {
	call, err := f.admin().begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminUserState{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Account == nil {
		return AdminUserState{}, call.configError("账户服务未装配")
	}
	caller, err := f.admin().accountCaller(call.identity)
	if err != nil {
		return AdminUserState{}, call.configError("账户服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminUserState{}, err
	}
	record, err := managed.Account.GetUser(ctx, caller, req.UserID)
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, account.ErrUserNotFound, "user"); ok {
			return AdminUserState{}, replaced
		}
		return AdminUserState{}, call.domainError("读取用户失败", string(account.CodeOf(err)))
	}
	return adminUserStateOf(record), nil
}

// DisableUser 禁用账户。
func (f *userLifecycleFacade) DisableUser(ctx context.Context,
	req AdminUserStateRequest) (AdminUserStateChange, error) {
	return f.applyState(ctx, req, account.CommandDisable)
}

// EnableUser 启用账户。
func (f *userLifecycleFacade) EnableUser(ctx context.Context,
	req AdminUserStateRequest) (AdminUserStateChange, error) {
	return f.applyState(ctx, req, account.CommandEnable)
}

// RequestUserDeletion 标记待删除。
func (f *userLifecycleFacade) RequestUserDeletion(ctx context.Context,
	req AdminUserStateRequest) (AdminUserStateChange, error) {
	return f.applyState(ctx, req, account.CommandRequestDeletion)
}

// applyState 复用账户服务的状态机、幂等、root 保护与关键审计。
func (f *userLifecycleFacade) applyState(ctx context.Context, req AdminUserStateRequest,
	command account.UserCommand) (AdminUserStateChange, error) {
	call, err := f.admin().begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminUserStateChange{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Account == nil {
		return AdminUserStateChange{}, call.configError("账户服务未装配")
	}
	caller, err := f.admin().accountCaller(call.identity)
	if err != nil {
		return AdminUserStateChange{}, call.configError("账户服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminUserStateChange{}, err
	}
	stateCommand := account.StateCommandRequest{UserID: req.UserID,
		ExpectedRowVersion: req.ExpectedRowVersion}
	var result account.StateChangeResult
	switch command {
	case account.CommandDisable:
		result, err = managed.Account.DisableUser(ctx, caller, stateCommand)
	case account.CommandEnable:
		result, err = managed.Account.EnableUser(ctx, caller, stateCommand)
	case account.CommandRequestDeletion:
		result, err = managed.Account.RequestDeletion(ctx, caller, stateCommand)
	default:
		return AdminUserStateChange{}, call.configError("未知账户状态命令")
	}
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, account.ErrUserNotFound, "user"); ok {
			return AdminUserStateChange{}, replaced
		}
		return AdminUserStateChange{}, call.domainError("变更用户状态失败",
			string(account.CodeOf(err)))
	}
	requiresRelogin := result.Changed &&
		(command == account.CommandDisable || command == account.CommandRequestDeletion)
	return AdminUserStateChange{User: adminUserStateOf(result.User),
		PreviousStatus: string(result.PreviousStatus), Changed: result.Changed,
		RequiresRelogin: requiresRelogin}, nil
}

// PreviewUserDeletion 读取删除影响范围快照。
func (f *userLifecycleFacade) PreviewUserDeletion(ctx context.Context,
	req AdminUserRequest) (AdminDeletionPreview, error) {
	call, err := f.admin().begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminDeletionPreview{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Account == nil {
		return AdminDeletionPreview{}, call.configError("账户服务未装配")
	}
	caller, err := f.admin().accountCaller(call.identity)
	if err != nil {
		return AdminDeletionPreview{}, call.configError("账户服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminDeletionPreview{}, err
	}
	preview, err := managed.Account.PreviewDeletion(ctx, caller, req.UserID)
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, account.ErrUserNotFound, "user"); ok {
			return AdminDeletionPreview{}, replaced
		}
		return AdminDeletionPreview{}, call.domainError("读取删除影响失败",
			string(account.CodeOf(err)))
	}
	return adminDeletionPreviewOf(preview), nil
}

// CompleteUserDeletion 完成不可逆删除。
func (f *userLifecycleFacade) CompleteUserDeletion(ctx context.Context,
	req AdminUserStateRequest) (AdminDeletionResult, error) {
	call, err := f.admin().begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminDeletionResult{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Account == nil {
		return AdminDeletionResult{}, call.configError("账户服务未装配")
	}
	caller, err := f.admin().accountCaller(call.identity)
	if err != nil {
		return AdminDeletionResult{}, call.configError("账户服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminDeletionResult{}, err
	}
	result, err := managed.Account.CompleteDeletion(ctx, caller, account.StateCommandRequest{
		UserID: req.UserID, ExpectedRowVersion: req.ExpectedRowVersion})
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, account.ErrUserNotFound, "user"); ok {
			return AdminDeletionResult{}, replaced
		}
		return AdminDeletionResult{}, call.domainError("完成用户删除失败",
			string(account.CodeOf(err)))
	}
	return AdminDeletionResult{Preview: adminDeletionPreviewOf(result.Preview),
		DeletedAt: result.DeletedAt}, nil
}

// adminUserStateOf 把账户领域快照转换为公开脱敏生命周期视图。
func adminUserStateOf(record account.User) AdminUserState {
	return AdminUserState{ID: record.ID, Username: record.Username,
		Nickname: record.Nickname, Biography: record.Biography,
		Language: record.Language, Timezone: record.Timezone,
		Status: string(record.Status), RowVersion: record.RowVersion,
		SecurityVersion: record.SecurityVersion, CreatedAt: record.CreatedAt,
		UpdatedAt: record.UpdatedAt}
}

// adminDeletionPreviewOf 转换删除影响快照（字段与内部快照一一对应）。
func adminDeletionPreviewOf(preview account.DeletionPreview) AdminDeletionPreview {
	return AdminDeletionPreview{UserID: preview.UserID, Username: preview.Username,
		Status: string(preview.Status), RowVersion: preview.RowVersion,
		SecurityVersion: preview.SecurityVersion, IsRoot: preview.IsRoot,
		AppMemberships: preview.AppMemberships, UserRoles: preview.UserRoles,
		GroupMemberships:   preview.GroupMemberships,
		OneTimeCredentials: preview.OneTimeCredentials,
		OwnedApplications:  preview.OwnedApplications}
}
