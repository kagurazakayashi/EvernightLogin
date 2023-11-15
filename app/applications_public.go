// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

// 应用生命周期与成员管理公开 Go 接口（步骤 225 P0）。
//
// 边界：
//   - 复用 internal/app 真实实现：应用 ID 不可变；名称/说明/图标/主页/负责人/
//     联系信息按白名单与 expected_row_version 可改；client_type/status 不经资料
//     更新改变；逻辑删除保留审计，物理清理只允许受控本地/系统通道；
//   - 应用成员只管理本应用关系与资料：root 不能成为成员、跨应用越权由真实授权
//     与数据范围拒绝；移除成员不影响全局账户与其他应用；
//   - 身份来自 AdminCaller：LocalAdmin 为受信本地操作者（不是 is_root），
//     AdminSession 由应用范围权限（applications.*）与数据范围判定；
//   - 列表沿用 217 已公开的 ListApplications/ListApplicationMembers，不重复分页；
//   - 已授权但目标不存在返回稳定 NOT_FOUND（207 契约）；
//   - 访问器 Runtime.Applications() 定义在本文件，不编辑 runtime.go/admin.go/types.go。

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/app"
)

// ApplicationLifecycleService 是应用与成员管理公开门面。
type ApplicationLifecycleService interface {
	GetApplication(ctx context.Context, req AdminApplicationRequest) (AdminApplicationDetail, error)
	UpdateApplication(ctx context.Context,
		req AdminUpdateApplicationRequest) (AdminApplicationDetail, error)
	PreviewApplicationDeletion(ctx context.Context,
		req AdminApplicationRequest) (AdminApplicationDeletionPreview, error)
	DeleteApplication(ctx context.Context,
		req AdminApplicationDeleteRequest) (AdminApplicationDeletionResult, error)
	PurgeApplication(ctx context.Context,
		req AdminApplicationPurgeRequest) (AdminApplicationPurgeResult, error)
	GetApplicationMember(ctx context.Context,
		req AdminApplicationMemberRequest) (AdminApplicationMemberDetail, error)
	UpdateApplicationMemberProfile(ctx context.Context,
		req AdminUpdateApplicationMemberRequest) (AdminApplicationMemberDetail, error)
	EnableApplicationMember(ctx context.Context,
		req AdminApplicationMemberChangeRequest) (AdminApplicationMemberChange, error)
	DisableApplicationMember(ctx context.Context,
		req AdminApplicationMemberChangeRequest) (AdminApplicationMemberChange, error)
	RemoveApplicationMember(ctx context.Context, req AdminApplicationMemberChangeRequest) error
}

// AdminApplicationDetail 是应用详情的脱敏视图（不含任何客户端秘密）。
type AdminApplicationDetail struct {
	ID          string
	Name        string
	Description string
	IconRef     string
	Homepage    string
	OwnerUserID string
	ContactInfo string
	Status      string
	ClientType  string
	ScopeID     string
	RowVersion  int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
	// DeletedAt 非零表示已逻辑删除；停用不等于删除。
	DeletedAt time.Time
}

// AdminUpdateApplicationRequest 是应用资料完整更新请求（应用 ID 不可变）。
// ClientType/Status 不在资料白名单内；状态改用启停接口。
type AdminUpdateApplicationRequest struct {
	Caller             AdminCaller
	ApplicationID      string
	Name               string
	Description        string
	IconRef            string
	Homepage           string
	OwnerUserID        string
	ContactInfo        string
	ExpectedRowVersion int64
	RequestID          string
}

// AdminApplicationDeletionPreview 是删除前影响快照。
type AdminApplicationDeletionPreview struct {
	ApplicationID           string
	CanDelete               bool
	BlockReason             string
	MemberCount             int
	ActiveMemberCount       int
	RoleCount               int
	PermissionCount         int
	GroupCount              int
	ActiveSessionCount      int
	OAuthClientCount        int
	RefreshTokenFamilyCount int
	InvitationCount         int
	WebhookEndpointCount    int
}

// AdminApplicationDeleteRequest 是逻辑删除请求。
type AdminApplicationDeleteRequest struct {
	Caller             AdminCaller
	ApplicationID      string
	ExpectedRowVersion int64
	RequestID          string
}

// AdminApplicationDeletionResult 是逻辑删除结果；Changed=false 表示幂等命中。
type AdminApplicationDeletionResult struct {
	Application AdminApplicationDetail
	Changed     bool
}

// AdminApplicationPurgeRequest 是物理清理请求（仅受控本地/系统通道）。
type AdminApplicationPurgeRequest struct {
	Caller        AdminCaller
	ApplicationID string
	RequestID     string
}

// AdminApplicationPurgeResult 是物理清理结果；Changed=false 表示目标已不存在。
type AdminApplicationPurgeResult struct {
	ApplicationID string
	Changed       bool
}

// AdminApplicationMemberDetail 是应用成员详情（仅本应用资料）。
type AdminApplicationMemberDetail struct {
	ApplicationID string
	UserID        string
	Status        string
	DisplayName   string
	Title         string
	Note          string
	RowVersion    int64
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// AdminApplicationMemberRequest 读取成员详情。
type AdminApplicationMemberRequest struct {
	Caller        AdminCaller
	ApplicationID string
	UserID        string
	RequestID     string
}

// AdminUpdateApplicationMemberRequest 更新应用内成员资料（白名单）。
type AdminUpdateApplicationMemberRequest struct {
	Caller             AdminCaller
	ApplicationID      string
	UserID             string
	DisplayName        string
	Title              string
	Note               string
	ExpectedRowVersion int64
	RequestID          string
}

// AdminApplicationMemberChangeRequest 成员启停/移除请求。
type AdminApplicationMemberChangeRequest struct {
	Caller             AdminCaller
	ApplicationID      string
	UserID             string
	ExpectedRowVersion int64
	RequestID          string
}

// AdminApplicationMemberChange 是成员启停结果；Changed=false 表示幂等命中。
type AdminApplicationMemberChange struct {
	Member  AdminApplicationMemberDetail
	Changed bool
}

// Applications 返回应用与成员管理公开门面。
func (r *Runtime) Applications() ApplicationLifecycleService {
	return &applicationsFacade{r: r}
}

type applicationsFacade struct {
	r *Runtime
}

func (f *applicationsFacade) admin() *adminFacade {
	return &adminFacade{r: f.r}
}

// beginApp 完成身份、服务与调用者前置。
func (f *applicationsFacade) beginApp(ctx context.Context, caller AdminCaller,
	requestID string) (adminRequest, *app.Service, app.Caller, error) {
	call, err := f.admin().begin(ctx, caller, requestID)
	if err != nil {
		return adminRequest{}, nil, app.Caller{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.App == nil {
		return call, nil, app.Caller{}, call.configError("应用服务未装配")
	}
	appCaller, err := f.admin().appCaller(call.identity)
	if err != nil {
		return call, nil, app.Caller{}, call.configError("应用服务调用者无效")
	}
	if appCaller, err = bindCaller(appCaller, call.requestID); err != nil {
		return call, nil, app.Caller{}, err
	}
	return call, managed.App, appCaller, nil
}

// GetApplication 读取应用详情。
func (f *applicationsFacade) GetApplication(ctx context.Context,
	req AdminApplicationRequest) (AdminApplicationDetail, error) {
	call, service, caller, err := f.beginApp(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminApplicationDetail{}, err
	}
	record, err := service.GetApplication(ctx, caller, req.ApplicationID)
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, app.ErrApplicationNotFound,
			"application"); ok {
			return AdminApplicationDetail{}, replaced
		}
		return AdminApplicationDetail{}, call.domainError("读取应用失败",
			string(app.CodeOf(err)))
	}
	return adminApplicationDetailOf(record), nil
}

// UpdateApplication 更新应用资料白名单（完整替换语义，expected_row_version 必填）。
func (f *applicationsFacade) UpdateApplication(ctx context.Context,
	req AdminUpdateApplicationRequest) (AdminApplicationDetail, error) {
	call, service, caller, err := f.beginApp(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminApplicationDetail{}, err
	}
	record, err := service.UpdateApplication(ctx, caller, req.ApplicationID, app.UpdateRequest{
		Name: req.Name, Description: req.Description, IconRef: req.IconRef,
		Homepage: req.Homepage, OwnerUserID: req.OwnerUserID,
		ContactInfo: req.ContactInfo, ExpectedRowVersion: req.ExpectedRowVersion})
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, app.ErrApplicationNotFound,
			"application"); ok {
			return AdminApplicationDetail{}, replaced
		}
		return AdminApplicationDetail{}, call.domainError("更新应用资料失败",
			string(app.CodeOf(err)))
	}
	return adminApplicationDetailOf(record), nil
}

// PreviewApplicationDeletion 读取删除影响快照。
func (f *applicationsFacade) PreviewApplicationDeletion(ctx context.Context,
	req AdminApplicationRequest) (AdminApplicationDeletionPreview, error) {
	call, service, caller, err := f.beginApp(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminApplicationDeletionPreview{}, err
	}
	impact, err := service.PreviewDeletion(ctx, caller, req.ApplicationID)
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, app.ErrApplicationNotFound,
			"application"); ok {
			return AdminApplicationDeletionPreview{}, replaced
		}
		return AdminApplicationDeletionPreview{}, call.domainError("读取删除影响失败",
			string(app.CodeOf(err)))
	}
	return AdminApplicationDeletionPreview{ApplicationID: impact.Application.ID,
		CanDelete: impact.CanDelete, BlockReason: impact.BlockReason,
		MemberCount: impact.MemberCount, ActiveMemberCount: impact.ActiveMemberCount,
		RoleCount: impact.RoleCount, PermissionCount: impact.PermissionCount,
		GroupCount: impact.GroupCount, ActiveSessionCount: impact.ActiveSessionCount,
		OAuthClientCount:        impact.OAuthClientCount,
		RefreshTokenFamilyCount: impact.RefreshTokenFamilyCount,
		InvitationCount:         impact.InvitationCount,
		WebhookEndpointCount:    impact.WebhookEndpointCount}, nil
}

// DeleteApplication 逻辑删除应用。
func (f *applicationsFacade) DeleteApplication(ctx context.Context,
	req AdminApplicationDeleteRequest) (AdminApplicationDeletionResult, error) {
	call, service, caller, err := f.beginApp(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminApplicationDeletionResult{}, err
	}
	result, err := service.DeleteApplication(ctx, caller, app.DeletionRequest{
		ApplicationID: req.ApplicationID, ExpectedRowVersion: req.ExpectedRowVersion})
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, app.ErrApplicationNotFound,
			"application"); ok {
			return AdminApplicationDeletionResult{}, replaced
		}
		return AdminApplicationDeletionResult{}, call.domainError("删除应用失败",
			string(app.CodeOf(err)))
	}
	return AdminApplicationDeletionResult{Application: adminApplicationDetailOf(result.Application),
		Changed: result.Changed}, nil
}

// PurgeApplication 物理清理应用（仅受控本地/系统通道，内部二次判定）。
func (f *applicationsFacade) PurgeApplication(ctx context.Context,
	req AdminApplicationPurgeRequest) (AdminApplicationPurgeResult, error) {
	call, service, caller, err := f.beginApp(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminApplicationPurgeResult{}, err
	}
	result, err := service.PurgeApplication(ctx, caller, app.PurgeRequest{
		ApplicationID: req.ApplicationID})
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, app.ErrApplicationNotFound,
			"application"); ok {
			return AdminApplicationPurgeResult{}, replaced
		}
		return AdminApplicationPurgeResult{}, call.domainError("物理清理应用失败",
			string(app.CodeOf(err)))
	}
	return AdminApplicationPurgeResult{ApplicationID: result.ApplicationID,
		Changed: result.Changed}, nil
}

// GetApplicationMember 读取成员详情。
func (f *applicationsFacade) GetApplicationMember(ctx context.Context,
	req AdminApplicationMemberRequest) (AdminApplicationMemberDetail, error) {
	call, service, caller, err := f.beginApp(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminApplicationMemberDetail{}, err
	}
	member, err := service.GetApplicationMember(ctx, caller, req.ApplicationID, req.UserID)
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, app.ErrMemberNotFound,
			"application member"); ok {
			return AdminApplicationMemberDetail{}, replaced
		}
		return AdminApplicationMemberDetail{}, call.domainError("读取应用成员失败",
			string(app.CodeOf(err)))
	}
	return adminApplicationMemberOf(member), nil
}

// UpdateApplicationMemberProfile 更新应用内成员资料。
func (f *applicationsFacade) UpdateApplicationMemberProfile(ctx context.Context,
	req AdminUpdateApplicationMemberRequest) (AdminApplicationMemberDetail, error) {
	call, service, caller, err := f.beginApp(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminApplicationMemberDetail{}, err
	}
	member, err := service.UpdateApplicationMemberProfile(ctx, caller,
		app.MemberProfileRequest{ApplicationID: req.ApplicationID, UserID: req.UserID,
			Profile: app.MemberProfile{DisplayName: req.DisplayName, Title: req.Title,
				Note: req.Note},
			ExpectedRowVersion: req.ExpectedRowVersion})
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, app.ErrMemberNotFound,
			"application member"); ok {
			return AdminApplicationMemberDetail{}, replaced
		}
		return AdminApplicationMemberDetail{}, call.domainError("更新应用成员资料失败",
			string(app.CodeOf(err)))
	}
	return adminApplicationMemberOf(member), nil
}

// EnableApplicationMember 启用应用内成员。
func (f *applicationsFacade) EnableApplicationMember(ctx context.Context,
	req AdminApplicationMemberChangeRequest) (AdminApplicationMemberChange, error) {
	return f.applyMemberStatus(ctx, req, true)
}

// DisableApplicationMember 停用应用内成员。
func (f *applicationsFacade) DisableApplicationMember(ctx context.Context,
	req AdminApplicationMemberChangeRequest) (AdminApplicationMemberChange, error) {
	return f.applyMemberStatus(ctx, req, false)
}

func (f *applicationsFacade) applyMemberStatus(ctx context.Context,
	req AdminApplicationMemberChangeRequest, enable bool) (AdminApplicationMemberChange, error) {
	call, service, caller, err := f.beginApp(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminApplicationMemberChange{}, err
	}
	statusRequest := app.MemberStatusRequest{ApplicationID: req.ApplicationID,
		UserID: req.UserID, ExpectedRowVersion: req.ExpectedRowVersion}
	var result app.MemberStatusResult
	if enable {
		result, err = service.EnableApplicationMember(ctx, caller, statusRequest)
	} else {
		result, err = service.DisableApplicationMember(ctx, caller, statusRequest)
	}
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, app.ErrMemberNotFound,
			"application member"); ok {
			return AdminApplicationMemberChange{}, replaced
		}
		return AdminApplicationMemberChange{}, call.domainError("变更应用成员状态失败",
			string(app.CodeOf(err)))
	}
	return AdminApplicationMemberChange{Member: adminApplicationMemberOf(result.Membership),
		Changed: result.Changed}, nil
}

// RemoveApplicationMember 移除应用成员（不删除全局账户）。
func (f *applicationsFacade) RemoveApplicationMember(ctx context.Context,
	req AdminApplicationMemberChangeRequest) error {
	call, service, caller, err := f.beginApp(ctx, req.Caller, req.RequestID)
	if err != nil {
		return err
	}
	if err := service.RemoveApplicationMember(ctx, caller, app.RemoveMemberRequest{
		ApplicationID: req.ApplicationID, UserID: req.UserID,
		ExpectedRowVersion: req.ExpectedRowVersion}); err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, app.ErrMemberNotFound,
			"application member"); ok {
			return replaced
		}
		return call.domainError("移除应用成员失败", string(app.CodeOf(err)))
	}
	return nil
}

// adminApplicationDetailOf 转换应用详情。
func adminApplicationDetailOf(record app.Application) AdminApplicationDetail {
	return AdminApplicationDetail{ID: record.ID, Name: record.Name,
		Description: record.Description, IconRef: record.IconRef,
		Homepage: record.Homepage, OwnerUserID: record.OwnerUserID,
		ContactInfo: record.ContactInfo, Status: string(record.Status),
		ClientType: string(record.ClientType), ScopeID: record.ScopeID,
		RowVersion: record.RowVersion, CreatedAt: record.CreatedAt,
		UpdatedAt: record.UpdatedAt, DeletedAt: record.DeletedAt}
}

// adminApplicationMemberOf 转换应用成员视图。
func adminApplicationMemberOf(member app.Membership) AdminApplicationMemberDetail {
	return AdminApplicationMemberDetail{ApplicationID: member.ApplicationID,
		UserID: member.UserID, Status: string(member.Status),
		DisplayName: member.Profile.DisplayName, Title: member.Profile.Title,
		Note: member.Profile.Note, RowVersion: member.RowVersion,
		CreatedAt: member.CreatedAt, UpdatedAt: member.UpdatedAt}
}
