// Package uiadminadapter 把步骤 68 管理页公开契约接到真实 account/profile/
// onboarding/group 服务（模块内参考适配器；生产宿主按同一契约装配）。
//
// 安全边界：适配器只接受页面已通过 UIAccessManagement 验证后传入的管理员用户 ID，
// 每次都重新构造可信 Caller 并调用真实服务；管理授权/数据范围由宿主注入的服务
// Authorizer（account/group）与 ManagementAuth（onboarding 审核）判定；本包不实现
// 权限放行、不缓存授权、不读取前端自报角色。
package uiadminadapter

import (
	"context"
	"errors"
	"fmt"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/diag"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	"github.com/kagurazakayashi/EvernightLogin/internal/onboarding"
	"github.com/kagurazakayashi/EvernightLogin/internal/profile"
	"github.com/kagurazakayashi/EvernightLogin/internal/userbatch"
	ui "github.com/kagurazakayashi/EvernightLogin/ui"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Options 是管理页适配器依赖。Authorize 由宿主实现（authz + 管理强认证），
// 用于在调用真实服务前补充页面层明确的管理动作复核（可选；nil 时依赖服务自身
// Authorizer/ManagementAuth，仍 fail-closed）。
type Options struct {
	Account   *account.Service
	Profile   *profile.Service
	Reviews   *onboarding.Service
	Groups    *group.Service
	Batches   *userbatch.Service
	Authorize func(ctx context.Context, adminUserID, action string) error
	// Diagnostics 是可选的脱敏运行诊断收集器；nil 时诊断页面返回不可用（不伪造
	// 数据，也不越权读取）。
	Diagnostics *diag.Collector
	// Validity 复用同一账户服务（users.read/users.update）与审计；页面与 234
	// 管理 API 使用相同授权判定。
	Now    func() time.Time
	Audit  *audit.Recorder
	Logger *slog.Logger
}

// Adapter 实现 ui.UIAdminBackend。
type Adapter struct {
	opts Options
}

// New 校验依赖并构造适配器。
func New(options Options) (*Adapter, error) {
	if options.Account == nil || options.Profile == nil || options.Reviews == nil ||
		options.Groups == nil || options.Batches == nil {
		return nil, fmt.Errorf("管理页适配器缺少必需服务")
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Adapter{opts: options}, nil
}

// check 执行可选的页面层管理动作复核（失败即拒绝）。
func (a *Adapter) check(ctx context.Context, adminUserID, action string) error {
	if adminUserID == "" || !account.ValidUserID(adminUserID) {
		return adminErr("ACCESS_DENIED")
	}
	if a.opts.Authorize != nil {
		if err := a.opts.Authorize(ctx, adminUserID, action); err != nil {
			return adminErr("ACCESS_DENIED")
		}
	}
	return nil
}

// ListUsers 列出当前管理范围内用户（状态筛选/受控排序/分页）。
func (a *Adapter) ListUsers(ctx context.Context, adminUserID string,
	query ui.UIAdminUserQuery) (ui.UIAdminUserPage, error) {
	if err := a.check(ctx, adminUserID, "users.read"); err != nil {
		return ui.UIAdminUserPage{}, err
	}
	caller, err := account.UserCaller(adminUserID)
	if err != nil {
		return ui.UIAdminUserPage{}, adminErr("ACCESS_DENIED")
	}
	limit := query.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if query.Offset < 0 {
		return ui.UIAdminUserPage{}, adminErr("REQ_INVALID")
	}
	status := account.Status(strings.TrimSpace(query.Status))
	if status != "" && !status.Valid() {
		return ui.UIAdminUserPage{}, adminErr("REQ_INVALID")
	}
	sortField := account.SortField(strings.TrimSpace(query.Sort))
	if sortField == "" {
		sortField = account.SortCreatedAt
	}
	if !sortField.Valid() {
		return ui.UIAdminUserPage{}, adminErr("REQ_INVALID")
	}
	result, err := a.opts.Account.ListUsers(ctx, caller, account.ListRequest{
		Limit: limit, Offset: query.Offset, Status: status, Sort: sortField,
		Descending: query.Descending})
	if err != nil {
		return ui.UIAdminUserPage{}, mapAccountError(err)
	}
	page := ui.UIAdminUserPage{HasMore: result.HasMore,
		Users: make([]ui.UIAdminUserView, 0, len(result.Users))}
	for _, user := range result.Users {
		page.Users = append(page.Users, a.toAdminUser(user))
	}
	return page, nil
}

// CreateUser 创建账户资料（五字段白名单，不设密码/角色/成员）。
func (a *Adapter) CreateUser(ctx context.Context, adminUserID string,
	create ui.UIAdminCreateUser) (ui.UIAdminUserView, error) {
	if err := a.check(ctx, adminUserID, "users.create"); err != nil {
		return ui.UIAdminUserView{}, err
	}
	caller, err := account.UserCaller(adminUserID)
	if err != nil {
		return ui.UIAdminUserView{}, adminErr("ACCESS_DENIED")
	}
	user, err := a.opts.Account.CreateUser(ctx, caller, account.CreateRequest{
		Username: create.Username, Nickname: create.Nickname, Biography: create.Biography,
		Language: create.Language, Timezone: create.Timezone})
	if err != nil {
		return ui.UIAdminUserView{}, mapAccountError(err)
	}
	return a.toAdminUser(user), nil
}

// GetUser 读取目标用户（服务端数据范围判定）。
func (a *Adapter) GetUser(ctx context.Context, adminUserID string,
	userID string) (ui.UIAdminUserView, error) {
	if err := a.check(ctx, adminUserID, "users.read"); err != nil {
		return ui.UIAdminUserView{}, err
	}
	if !account.ValidUserID(userID) {
		return ui.UIAdminUserView{}, adminErr("REQ_INVALID")
	}
	caller, err := account.UserCaller(adminUserID)
	if err != nil {
		return ui.UIAdminUserView{}, adminErr("ACCESS_DENIED")
	}
	user, err := a.opts.Account.GetUser(ctx, caller, userID)
	if err != nil {
		return ui.UIAdminUserView{}, mapAccountError(err)
	}
	return a.toAdminUser(user), nil
}

// UpdateUser 修改白名单资料（行版本条件；不含认证/角色字段）。
func (a *Adapter) UpdateUser(ctx context.Context, adminUserID, userID string,
	change ui.UIProfileChange, expectedRowVersion int64,
	requestID string) (ui.UIAdminUserView, error) {
	if err := a.check(ctx, adminUserID, "users.update"); err != nil {
		return ui.UIAdminUserView{}, err
	}
	if !account.ValidUserID(userID) {
		return ui.UIAdminUserView{}, adminErr("REQ_INVALID")
	}
	caller, err := profile.UserCaller(adminUserID)
	if err != nil {
		return ui.UIAdminUserView{}, adminErr("ACCESS_DENIED")
	}
	updated, err := a.opts.Profile.UpdateUser(ctx, caller, profile.UpdateRequest{
		TargetUserID: userID,
		Change: profile.ProfileChange{Nickname: change.Nickname, Biography: change.Biography,
			Language: change.Language, Timezone: change.Timezone, Phone: change.Phone},
		ExpectedRowVersion: expectedRowVersion, RequestID: requestID})
	if err != nil {
		return ui.UIAdminUserView{}, mapProfileError(err)
	}
	return a.toAdminUser(profileToAccount(updated)), nil
}

// SetUserState 执行禁用/启用/请求删除。
func (a *Adapter) SetUserState(ctx context.Context, adminUserID, userID, action string,
	expectedRowVersion int64, requestID string) (ui.UIAdminUserView, bool, error) {
	if err := a.check(ctx, adminUserID, "users.update"); err != nil {
		return ui.UIAdminUserView{}, false, err
	}
	caller, err := account.UserCaller(adminUserID)
	if err != nil {
		return ui.UIAdminUserView{}, false, adminErr("ACCESS_DENIED")
	}
	request := account.StateCommandRequest{UserID: userID,
		ExpectedRowVersion: expectedRowVersion}
	var result account.StateChangeResult
	switch action {
	case "disable":
		result, err = a.opts.Account.DisableUser(ctx, caller, request)
	case "enable":
		result, err = a.opts.Account.EnableUser(ctx, caller, request)
	case "request_delete":
		result, err = a.opts.Account.RequestDeletion(ctx, caller, request)
	default:
		return ui.UIAdminUserView{}, false, adminErr("REQ_INVALID")
	}
	if err != nil {
		return ui.UIAdminUserView{}, false, mapAccountError(err)
	}
	return a.toAdminUser(result.User), result.Changed, nil
}

// PreviewDeletion 读取真实删除影响快照。
func (a *Adapter) PreviewDeletion(ctx context.Context, adminUserID,
	userID string) (ui.UIAdminDeletionPreview, error) {
	if err := a.check(ctx, adminUserID, "users.delete"); err != nil {
		return ui.UIAdminDeletionPreview{}, err
	}
	caller, err := account.UserCaller(adminUserID)
	if err != nil {
		return ui.UIAdminDeletionPreview{}, adminErr("ACCESS_DENIED")
	}
	preview, err := a.opts.Account.PreviewDeletion(ctx, caller, userID)
	if err != nil {
		return ui.UIAdminDeletionPreview{}, mapAccountError(err)
	}
	return toPreview(preview), nil
}

// CompleteDeletion 完成不可逆删除（服务端再次校验状态/版本/保护）。
func (a *Adapter) CompleteDeletion(ctx context.Context, adminUserID, userID string,
	expectedRowVersion int64, requestID string) (ui.UIAdminDeletionPreview, error) {
	if err := a.check(ctx, adminUserID, "users.delete"); err != nil {
		return ui.UIAdminDeletionPreview{}, err
	}
	caller, err := account.UserCaller(adminUserID)
	if err != nil {
		return ui.UIAdminDeletionPreview{}, adminErr("ACCESS_DENIED")
	}
	result, err := a.opts.Account.CompleteDeletion(ctx, caller, account.StateCommandRequest{
		UserID: userID, ExpectedRowVersion: expectedRowVersion})
	if err != nil {
		return ui.UIAdminDeletionPreview{}, mapAccountError(err)
	}
	preview := toPreview(result.Preview)
	preview.DeletedAt = result.DeletedAt
	return preview, nil
}

// ListReviews 列出待审核注册申请。
func (a *Adapter) ListReviews(ctx context.Context, adminUserID string,
	limit, offset int) (ui.UIAdminReviewPage, error) {
	if err := a.check(ctx, adminUserID, "users.review"); err != nil {
		return ui.UIAdminReviewPage{}, err
	}
	caller, err := onboarding.UserCaller(adminUserID)
	if err != nil {
		return ui.UIAdminReviewPage{}, adminErr("ACCESS_DENIED")
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	result, err := a.opts.Reviews.ListPendingReviews(ctx, caller,
		onboarding.ReviewQuery{Limit: limit, Offset: offset})
	if err != nil {
		return ui.UIAdminReviewPage{}, mapOnboardingError(err)
	}
	page := ui.UIAdminReviewPage{HasMore: result.HasMore,
		Reviews: make([]ui.UIAdminReview, 0, len(result.Users))}
	for _, review := range result.Users {
		page.Reviews = append(page.Reviews, toReview(review))
	}
	return page, nil
}

// GetReview 读取单个待审核申请。
func (a *Adapter) GetReview(ctx context.Context, adminUserID,
	userID string) (ui.UIAdminReview, error) {
	if err := a.check(ctx, adminUserID, "users.review"); err != nil {
		return ui.UIAdminReview{}, err
	}
	caller, err := onboarding.UserCaller(adminUserID)
	if err != nil {
		return ui.UIAdminReview{}, adminErr("ACCESS_DENIED")
	}
	review, err := a.opts.Reviews.GetReview(ctx, caller, userID)
	if err != nil {
		return ui.UIAdminReview{}, mapOnboardingError(err)
	}
	return toReview(review), nil
}

// DecideReview 批准/拒绝注册（理由必填由页面与服务共同校验）。
func (a *Adapter) DecideReview(ctx context.Context, adminUserID, userID string,
	approve bool, reason, appID string, roles []string,
	requestID string) (ui.UIAdminReviewDecision, error) {
	if err := a.check(ctx, adminUserID, "users.review"); err != nil {
		return ui.UIAdminReviewDecision{}, err
	}
	caller, err := onboarding.UserCaller(adminUserID)
	if err != nil {
		return ui.UIAdminReviewDecision{}, adminErr("ACCESS_DENIED")
	}
	roleRefs := make([]onboarding.Role, 0, len(roles))
	for _, role := range roles {
		roleRefs = append(roleRefs, onboarding.Role{RoleID: strings.TrimSpace(role)})
		if strings.TrimSpace(role) == "" {
			return ui.UIAdminReviewDecision{}, adminErr("REQ_INVALID")
		}
	}
	request := onboarding.ReviewRequest{UserID: userID, Reason: reason,
		AppID: strings.TrimSpace(appID), Roles: roleRefs, RequestID: requestID}
	var result onboarding.ReviewResult
	switch {
	case approve:
		result, err = a.opts.Reviews.ApproveRegistration(ctx, caller, request)
	default:
		if appID != "" || len(roleRefs) > 0 {
			return ui.UIAdminReviewDecision{}, adminErr("REQ_INVALID")
		}
		result, err = a.opts.Reviews.RejectRegistration(ctx, caller, request)
	}
	if err != nil {
		return ui.UIAdminReviewDecision{}, mapOnboardingError(err)
	}
	return ui.UIAdminReviewDecision{Review: toReview(result.Review),
		Notified: result.Notified, ErrorCode: result.ErrorCode}, nil
}

// ListGroups 列出当前范围用户组。
func (a *Adapter) ListGroups(ctx context.Context, adminUserID, scopeID string,
	limit, offset int) (ui.UIAdminGroupPage, error) {
	if err := a.check(ctx, adminUserID, "groups.read"); err != nil {
		return ui.UIAdminGroupPage{}, err
	}
	caller, err := group.UserCaller(adminUserID)
	if err != nil {
		return ui.UIAdminGroupPage{}, adminErr("ACCESS_DENIED")
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	result, err := a.opts.Groups.ListGroups(ctx, caller,
		group.ListRequest{ScopeID: strings.TrimSpace(scopeID), Limit: limit, Offset: offset})
	if err != nil {
		return ui.UIAdminGroupPage{}, mapGroupError(err)
	}
	page := ui.UIAdminGroupPage{HasMore: result.HasMore,
		Groups: make([]ui.UIAdminGroup, 0, len(result.Groups))}
	for _, record := range result.Groups {
		page.Groups = append(page.Groups, toGroup(record))
	}
	return page, nil
}

// CreateGroup 创建用户组（Scope/GroupKey 创建后不可变）。
func (a *Adapter) CreateGroup(ctx context.Context, adminUserID, scopeID, groupKey, name,
	description, requestID string) (ui.UIAdminGroup, error) {
	if err := a.check(ctx, adminUserID, "groups.update"); err != nil {
		return ui.UIAdminGroup{}, err
	}
	caller, err := group.UserCaller(adminUserID)
	if err != nil {
		return ui.UIAdminGroup{}, adminErr("ACCESS_DENIED")
	}
	created, err := a.opts.Groups.CreateGroup(ctx, caller, group.CreateRequest{
		ScopeID: strings.TrimSpace(scopeID), GroupKey: strings.TrimSpace(groupKey),
		Name: strings.TrimSpace(name), Description: description})
	if err != nil {
		return ui.UIAdminGroup{}, mapGroupError(err)
	}
	return toGroup(created), nil
}

// GetGroup 读取组详情。
func (a *Adapter) GetGroup(ctx context.Context, adminUserID,
	groupID string) (ui.UIAdminGroup, error) {
	if err := a.check(ctx, adminUserID, "groups.read"); err != nil {
		return ui.UIAdminGroup{}, err
	}
	caller, err := group.UserCaller(adminUserID)
	if err != nil {
		return ui.UIAdminGroup{}, adminErr("ACCESS_DENIED")
	}
	record, err := a.opts.Groups.GetGroup(ctx, caller, groupID)
	if err != nil {
		return ui.UIAdminGroup{}, mapGroupError(err)
	}
	return toGroup(record), nil
}

// UpdateGroup 只更新名称/说明。
func (a *Adapter) UpdateGroup(ctx context.Context, adminUserID, groupID, name, description,
	requestID string) (ui.UIAdminGroup, error) {
	if err := a.check(ctx, adminUserID, "groups.update"); err != nil {
		return ui.UIAdminGroup{}, err
	}
	caller, err := group.UserCaller(adminUserID)
	if err != nil {
		return ui.UIAdminGroup{}, adminErr("ACCESS_DENIED")
	}
	updated, err := a.opts.Groups.UpdateGroup(ctx, caller, groupID,
		group.UpdateRequest{Name: strings.TrimSpace(name), Description: description})
	if err != nil {
		return ui.UIAdminGroup{}, mapGroupError(err)
	}
	return toGroup(updated), nil
}

// DeleteGroup 删除组（硬删除；影响计数由确认页按未知展示）。
func (a *Adapter) DeleteGroup(ctx context.Context, adminUserID, groupID,
	requestID string) error {
	if err := a.check(ctx, adminUserID, "groups.update"); err != nil {
		return err
	}
	caller, err := group.UserCaller(adminUserID)
	if err != nil {
		return adminErr("ACCESS_DENIED")
	}
	if err := a.opts.Groups.DeleteGroup(ctx, caller, groupID); err != nil {
		return mapGroupError(err)
	}
	return nil
}

// ListMembers 分页读取组成员。
func (a *Adapter) ListMembers(ctx context.Context, adminUserID, groupID string,
	limit, offset int) (ui.UIAdminMemberPage, error) {
	if err := a.check(ctx, adminUserID, "groups.read"); err != nil {
		return ui.UIAdminMemberPage{}, err
	}
	caller, err := group.UserCaller(adminUserID)
	if err != nil {
		return ui.UIAdminMemberPage{}, adminErr("ACCESS_DENIED")
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	result, err := a.opts.Groups.ListMembers(ctx, caller,
		group.MemberListRequest{GroupID: groupID, Limit: limit, Offset: offset})
	if err != nil {
		return ui.UIAdminMemberPage{}, mapGroupError(err)
	}
	page := ui.UIAdminMemberPage{HasMore: result.HasMore,
		Members: make([]ui.UIAdminMember, 0, len(result.Members))}
	for _, member := range result.Members {
		page.Members = append(page.Members, ui.UIAdminMember{GroupID: member.GroupID,
			UserID: member.UserID, CreatedAt: member.CreatedAt})
	}
	return page, nil
}

// AddMembers 原子加入成员（≤12，稳定 UserID）。
func (a *Adapter) AddMembers(ctx context.Context, adminUserID, groupID string,
	userIDs []string, requestID string) (ui.UIAdminMemberResult, error) {
	return a.mutateMembers(ctx, adminUserID, groupID, userIDs, requestID, true)
}

// RemoveMembers 原子移除成员（≤12，稳定 UserID）。
func (a *Adapter) RemoveMembers(ctx context.Context, adminUserID, groupID string,
	userIDs []string, requestID string) (ui.UIAdminMemberResult, error) {
	return a.mutateMembers(ctx, adminUserID, groupID, userIDs, requestID, false)
}

// mutateMembers 校验并执行成员批量变更；服务端保证原子性。
func (a *Adapter) mutateMembers(ctx context.Context, adminUserID, groupID string,
	userIDs []string, requestID string, add bool) (ui.UIAdminMemberResult, error) {
	if err := a.check(ctx, adminUserID, "groups.update"); err != nil {
		return ui.UIAdminMemberResult{}, err
	}
	if len(userIDs) == 0 || len(userIDs) > 12 || groupID == "" {
		return ui.UIAdminMemberResult{}, adminErr("REQ_INVALID")
	}
	for _, userID := range userIDs {
		if !account.ValidUserID(userID) {
			return ui.UIAdminMemberResult{}, adminErr("REQ_INVALID")
		}
	}
	caller, err := group.UserCaller(adminUserID)
	if err != nil {
		return ui.UIAdminMemberResult{}, adminErr("ACCESS_DENIED")
	}
	request := group.MemberBatchRequest{GroupID: groupID, UserIDs: userIDs}
	var result group.MemberBatchResult
	if add {
		result, err = a.opts.Groups.AddMembers(ctx, caller, request)
	} else {
		result, err = a.opts.Groups.RemoveMembers(ctx, caller, request)
	}
	if err != nil {
		return ui.UIAdminMemberResult{}, mapGroupError(err)
	}
	return ui.UIAdminMemberResult{Added: result.Added, Removed: result.Removed,
		Skipped: result.Skipped}, nil
}

// ===== 映射 =====

func (a *Adapter) toAdminUser(user account.User) ui.UIAdminUserView {
	now := time.Now
	if a != nil && a.opts.Now != nil {
		now = a.opts.Now
	}
	_, reason := user.AvailabilityAt(now().UTC(), false)
	return ui.UIAdminUserView{UserID: user.ID, Username: user.Username,
		Nickname: user.Nickname, Biography: user.Biography, Language: user.Language,
		Timezone: user.Timezone, Status: string(user.Status), RowVersion: user.RowVersion,
		ValidFrom: user.ValidFrom, ValidUntil: user.ValidUntil,
		Availability: string(reason), CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt}
}

// profileToAccount 把资料快照转换为管理页用户视图使用的账户结构。
func profileToAccount(view profile.UserProfile) account.User {
	return account.User{ID: view.UserID, Username: view.Username, Nickname: view.Nickname,
		Biography: view.Biography, Language: view.Language, Timezone: view.Timezone,
		Status: account.StatusActive, RowVersion: view.RowVersion,
		CreatedAt: view.CreatedAt, UpdatedAt: view.UpdatedAt}
}

func toPreview(preview account.DeletionPreview) ui.UIAdminDeletionPreview {
	return ui.UIAdminDeletionPreview{UserID: preview.UserID, Username: preview.Username,
		Status: string(preview.Status), RowVersion: preview.RowVersion,
		SecurityVersion: preview.SecurityVersion, IsRoot: preview.IsRoot,
		AppMemberships: preview.AppMemberships, UserRoles: preview.UserRoles,
		GroupMemberships:   preview.GroupMemberships,
		OneTimeCredentials: preview.OneTimeCredentials,
		OwnedApplications:  preview.OwnedApplications}
}

func toReview(review onboarding.ReviewUser) ui.UIAdminReview {
	return ui.UIAdminReview{UserID: review.UserID, Username: review.Username,
		Status: string(review.Status), ReviewStatus: string(review.ReviewStatus),
		Reason: review.Reason, CreatedAt: review.CreatedAt,
		NotifyState: string(review.NotifyState), NotifyError: review.NotifyError}
}

func toGroup(record group.Group) ui.UIAdminGroup {
	return ui.UIAdminGroup{ID: record.ID, ScopeID: record.ScopeID,
		ScopeKind: string(record.ScopeKind), AppID: record.ApplicationID,
		GroupKey: record.GroupKey, Name: record.Name, Description: record.Description,
		CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt}
}

func adminErr(code string) error { return &ui.UIAdminError{Code: code} }

func mapAccountError(err error) error {
	switch {
	case errors.Is(err, account.ErrAccessDenied), errors.Is(err, account.ErrProtectedUser):
		return adminErr("ACCESS_DENIED")
	case errors.Is(err, account.ErrInvalidRequest), errors.Is(err, account.ErrInvalidTransition),
		errors.Is(err, account.ErrValidityInvalid):
		return adminErr("REQ_INVALID")
	case errors.Is(err, account.ErrStateConflict):
		return adminErr("CONFLICT")
	case errors.Is(err, account.ErrUsernameTaken):
		return adminErr("CONFLICT")
	case errors.Is(err, account.ErrUserNotFound):
		return adminErr("CHALLENGE_INVALID")
	case errors.Is(err, account.ErrStoreUnavailable), errors.Is(err, account.ErrAuditUnavailable):
		return adminErr("DB_UNAVAILABLE")
	default:
		return adminErr("INTERNAL_ERROR")
	}
}

func mapProfileError(err error) error {
	switch {
	case errors.Is(err, profile.ErrVersionConflict), errors.Is(err, profile.ErrUsernameTaken):
		return adminErr("CONFLICT")
	case errors.Is(err, profile.ErrAccessDenied):
		return adminErr("ACCESS_DENIED")
	case errors.Is(err, profile.ErrInvalidRequest), errors.Is(err, profile.ErrPhoneInvalid):
		return adminErr("REQ_INVALID")
	case errors.Is(err, profile.ErrStoreUnavailable), errors.Is(err, profile.ErrAuditUnavailable):
		return adminErr("DB_UNAVAILABLE")
	default:
		return adminErr("INTERNAL_ERROR")
	}
}

func mapOnboardingError(err error) error {
	switch {
	case errors.Is(err, onboarding.ErrAccessDenied), errors.Is(err, onboarding.ErrManagementAuthRequired):
		return adminErr("ACCESS_DENIED")
	case errors.Is(err, onboarding.ErrInvalidRequest), errors.Is(err, onboarding.ErrReviewStateConflict):
		return adminErr("CONFLICT")
	case errors.Is(err, onboarding.ErrStoreUnavailable), errors.Is(err, onboarding.ErrAuditUnavailable):
		return adminErr("DB_UNAVAILABLE")
	default:
		return adminErr("INTERNAL_ERROR")
	}
}

func mapGroupError(err error) error {
	switch {
	case errors.Is(err, group.ErrAccessDenied):
		return adminErr("ACCESS_DENIED")
	case errors.Is(err, group.ErrStateConflict), errors.Is(err, group.ErrGroupKeyTaken):
		return adminErr("CONFLICT")
	case errors.Is(err, group.ErrGroupNotFound):
		return adminErr("CHALLENGE_INVALID")
	case errors.Is(err, group.ErrInvalidRequest):
		return adminErr("REQ_INVALID")
	case errors.Is(err, group.ErrScopeInvalid), errors.Is(err, group.ErrMemberNotEligible),
		errors.Is(err, group.ErrApplicationInactive):
		return adminErr("ACCESS_DENIED")
	case errors.Is(err, group.ErrStoreUnavailable), errors.Is(err, group.ErrAuditUnavailable):
		return adminErr("DB_UNAVAILABLE")
	default:
		return adminErr("INTERNAL_ERROR")
	}
}

var _ = http.MethodGet
var _ = fmt.Sprint
var _ = context.Background

// PrecheckImport 只解析校验 CSV，不创建任务、不写库。
func (a *Adapter) PrecheckImport(ctx context.Context, adminUserID string,
	content []byte) (ui.UIAdminParseReport, error) {
	if err := a.check(ctx, adminUserID, "users.import"); err != nil {
		return ui.UIAdminParseReport{}, err
	}
	caller, err := account.UserCaller(adminUserID)
	if err != nil {
		return ui.UIAdminParseReport{}, adminErr("ACCESS_DENIED")
	}
	report, err := a.opts.Batches.PrecheckImport(ctx, caller, content)
	if err != nil {
		return ui.UIAdminParseReport{}, mapBatchError(err)
	}
	return toParseReport(report), nil
}

// StartImport 创建幂等导入任务（不执行批处理，执行由真实任务执行器负责）。
func (a *Adapter) StartImport(ctx context.Context, adminUserID string, content []byte,
	idempotencyKey, requestID string) (ui.UIAdminBatchStart, error) {
	if err := a.check(ctx, adminUserID, "users.import"); err != nil {
		return ui.UIAdminBatchStart{}, err
	}
	caller, err := account.UserCaller(adminUserID)
	if err != nil {
		return ui.UIAdminBatchStart{}, adminErr("ACCESS_DENIED")
	}
	result, err := a.opts.Batches.StartImport(ctx, userbatch.ImportRequest{
		Caller: caller, IdempotencyKey: idempotencyKey, Content: content, RequestID: requestID})
	if err != nil {
		return ui.UIAdminBatchStart{}, mapBatchError(err)
	}
	return toBatchStart(result), nil
}

// StartExport 创建导出任务（文件不出服务器；仅展示摘要/校验和）。
func (a *Adapter) StartExport(ctx context.Context, adminUserID string,
	options ui.UIAdminExportOptions, requestID string) (ui.UIAdminBatchStart, error) {
	if err := a.check(ctx, adminUserID, "users.export"); err != nil {
		return ui.UIAdminBatchStart{}, err
	}
	caller, err := account.UserCaller(adminUserID)
	if err != nil {
		return ui.UIAdminBatchStart{}, adminErr("ACCESS_DENIED")
	}
	result, err := a.opts.Batches.StartExport(ctx, userbatch.ExportRequest{
		Caller: caller, IdempotencyKey: options.IdempotencyKey, Fields: options.Fields,
		IncludeFreeText: options.IncludeFreeText, MaxRows: options.MaxRows,
		RequestID: requestID})
	if err != nil {
		return ui.UIAdminBatchStart{}, mapBatchError(err)
	}
	return toBatchStart(result), nil
}

// ListJobs 列出调用者可访问的批量任务。
func (a *Adapter) ListJobs(ctx context.Context, adminUserID, kind string, limit,
	offset int) (ui.UIAdminBatchPage, error) {
	if err := a.check(ctx, adminUserID, "users.read"); err != nil {
		return ui.UIAdminBatchPage{}, err
	}
	caller, err := account.UserCaller(adminUserID)
	if err != nil {
		return ui.UIAdminBatchPage{}, adminErr("ACCESS_DENIED")
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if offset < 0 || offset > 1_000_000 {
		offset = 0
	}
	query := userbatch.ListJobsQuery{Limit: limit, Offset: offset}
	switch userbatch.Kind(kind) {
	case userbatch.KindImport:
		query.Kind = userbatch.KindImport
	case userbatch.KindExport:
		query.Kind = userbatch.KindExport
	case "":
	default:
		return ui.UIAdminBatchPage{}, adminErr("REQ_INVALID")
	}
	jobs, hasMore, err := a.opts.Batches.ListJobs(ctx, caller, query)
	if err != nil {
		return ui.UIAdminBatchPage{}, mapBatchError(err)
	}
	page := ui.UIAdminBatchPage{Jobs: make([]ui.UIAdminBatchJob, 0, len(jobs)),
		HasMore: hasMore}
	for _, job := range jobs {
		page.Jobs = append(page.Jobs, toBatchJob(job))
	}
	return page, nil
}

// GetJob 读取任务真实状态。
func (a *Adapter) GetJob(ctx context.Context, adminUserID,
	jobID string) (ui.UIAdminBatchJob, error) {
	if err := a.check(ctx, adminUserID, "users.read"); err != nil {
		return ui.UIAdminBatchJob{}, err
	}
	caller, err := account.UserCaller(adminUserID)
	if err != nil {
		return ui.UIAdminBatchJob{}, adminErr("ACCESS_DENIED")
	}
	job, err := a.opts.Batches.GetJob(ctx, caller, jobID)
	if err != nil {
		return ui.UIAdminBatchJob{}, mapBatchError(err)
	}
	return toBatchJob(job), nil
}

// ListRows 读取逐行结果（不含原始行/秘密）。
func (a *Adapter) ListRows(ctx context.Context, adminUserID, jobID string, limit,
	offset int) ([]ui.UIAdminBatchRow, bool, error) {
	if err := a.check(ctx, adminUserID, "users.read"); err != nil {
		return nil, false, err
	}
	caller, err := account.UserCaller(adminUserID)
	if err != nil {
		return nil, false, adminErr("ACCESS_DENIED")
	}
	_ = offset // userbatch 逐行读取按上限返回；分页由后续受控接口扩展
	rows, truncated, err := a.opts.Batches.ListRows(ctx, caller, jobID, limit)
	if err != nil {
		return nil, false, mapBatchError(err)
	}
	result := make([]ui.UIAdminBatchRow, 0, len(rows))
	for _, row := range rows {
		result = append(result, ui.UIAdminBatchRow{RowNumber: row.RowNumber,
			Action: string(row.Action), ErrorCode: string(row.ErrorCode),
			ReasonCode: row.ReasonCode, UsernameNormalized: row.UsernameNormalized,
			UserID: row.UserID})
	}
	return result, truncated, nil
}

// ReportCSV 受控生成逐行报告（所有权/权限由后端再次判定）。
func (a *Adapter) ReportCSV(ctx context.Context, adminUserID, jobID string) ([]byte, bool, error) {
	if err := a.check(ctx, adminUserID, "users.read"); err != nil {
		return nil, false, err
	}
	caller, err := account.UserCaller(adminUserID)
	if err != nil {
		return nil, false, adminErr("ACCESS_DENIED")
	}
	return a.opts.Batches.ReportCSV(ctx, caller, jobID)
}

// CancelJob 提交取消请求；真实取消状态需后续 GetJob 确认。
func (a *Adapter) CancelJob(ctx context.Context, adminUserID, jobID, reason, requestID string) error {
	if err := a.check(ctx, adminUserID, "users.import"); err != nil {
		return err
	}
	caller, err := account.UserCaller(adminUserID)
	if err != nil {
		return adminErr("ACCESS_DENIED")
	}
	if err := a.opts.Batches.Cancel(ctx, caller, jobID, reason, requestID); err != nil {
		return mapBatchError(err)
	}
	return nil
}

// RetryJob 对可续跑失败任务重新入队。
func (a *Adapter) RetryJob(ctx context.Context, adminUserID, jobID,
	requestID string) (ui.UIAdminBatchJob, error) {
	if err := a.check(ctx, adminUserID, "users.import"); err != nil {
		return ui.UIAdminBatchJob{}, err
	}
	caller, err := account.UserCaller(adminUserID)
	if err != nil {
		return ui.UIAdminBatchJob{}, adminErr("ACCESS_DENIED")
	}
	job, err := a.opts.Batches.Retry(ctx, caller, jobID, requestID)
	if err != nil {
		return ui.UIAdminBatchJob{}, mapBatchError(err)
	}
	return toBatchJob(job), nil
}

func toParseReport(report userbatch.ParseReport) ui.UIAdminParseReport {
	view := ui.UIAdminParseReport{Headers: report.Headers, TotalRows: report.TotalRows,
		RejectedRows: report.RejectedRows, CanImport: report.CanImport,
		Truncated: report.Truncated}
	for _, parseErr := range report.Errors {
		view.Errors = append(view.Errors, ui.UIAdminParseError{Line: parseErr.Line,
			Column: parseErr.Column, Code: string(parseErr.Code), Reason: parseErr.Reason})
	}
	return view
}

func toBatchStart(result userbatch.StartResult) ui.UIAdminBatchStart {
	return ui.UIAdminBatchStart{JobID: result.Job.ID, Kind: string(result.Job.Kind),
		State: string(result.Job.State), TotalRows: result.Job.TotalRows,
		Duplicate: result.Duplicate, Report: toParseReport(result.Report)}
}

func toBatchJob(job userbatch.Job) ui.UIAdminBatchJob {
	return ui.UIAdminBatchJob{JobID: job.ID, Kind: string(job.Kind),
		State: string(job.State), TotalRows: job.TotalRows,
		CreatedCount: job.CreatedCount, SkippedCount: job.SkippedCount,
		ConflictCount: job.ConflictCount, FailedCount: job.FailedCount,
		DeniedCount: job.DeniedCount, Truncated: job.Truncated,
		ExportSHA256: job.ExportSHA256, ExportRows: job.ExportRows,
		ErrorCode: string(job.ErrorCode), TaskID: job.TaskID,
		InputAvailable: job.InputAvailable, CreatedAt: job.CreatedAt, UpdatedAt: job.UpdatedAt}
}

func mapBatchError(err error) error {
	switch {
	case errors.Is(err, userbatch.ErrAccessDenied):
		return adminErr("ACCESS_DENIED")
	case errors.Is(err, userbatch.ErrConflict):
		return adminErr("CONFLICT")
	case errors.Is(err, userbatch.ErrFileInvalid), errors.Is(err, userbatch.ErrInvalidRequest):
		return adminErr("REQ_INVALID")
	case errors.Is(err, userbatch.ErrJobState):
		return adminErr("CONFLICT")
	case errors.Is(err, userbatch.ErrExportPathUnsafe):
		return adminErr("REQ_INVALID")
	case errors.Is(err, userbatch.ErrStoreUnavailable), errors.Is(err, userbatch.ErrAuditUnavailable):
		return adminErr("DB_UNAVAILABLE")
	default:
		return adminErr("INTERNAL_ERROR")
	}
}
