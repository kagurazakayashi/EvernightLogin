// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

// 个人资料与受控用户名更名公开 Go 接口（步骤 221 P0）。
//
// 边界：
//   - 身份只从完整会话派生，不接受 userID 传参；本人只能读/改自己的资料；
//   - 资料更新走 internal/profile 的字段白名单（昵称/简介/语言/时区/电话），
//     不接受 is_root/邮箱已验证/角色/状态/安全版本等字段；
//   - 受控更名走真实敏感操作 `profile.username.change`：先建立真实再次认证上下文
//     （密码，必要时强因素动态码），再由 profile 服务复核冷却/保留名/root 保护；
//   - 访问器 Runtime.Profile() 定义在本文件，不编辑 runtime.go/admin.go/types.go。

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/profile"
)

// ProfileService 是个人资料公开门面。
type ProfileService interface {
	// GetProfile 读取当前会话本人的资料视图。
	GetProfile(ctx context.Context, req OwnProfileRequest) (ProfileView, error)
	// UpdateProfile 更新本人资料白名单字段（需要 expected_row_version）。
	UpdateProfile(ctx context.Context, req UpdateOwnProfileRequest) (ProfileView, error)
	// ChangeUsername 受控更名：需要完整会话 + 近期再次认证（密码，必要时动态码）
	// + expected_row_version；冷却/保留名/root 保护由领域服务判定。
	ChangeUsername(ctx context.Context, req ChangeOwnUsernameRequest) (ProfileView, error)
}

// OwnProfileRequest 读取本人资料。
type OwnProfileRequest struct {
	SessionSecret []byte
	RequestID     string
}

// UpdateOwnProfileRequest 更新本人资料：nil 表示该字段不变。
type UpdateOwnProfileRequest struct {
	SessionSecret      []byte
	Nickname           *string
	Biography          *string
	Language           *string
	Timezone           *string
	Phone              *string
	ExpectedRowVersion int64
	RequestID          string
}

// ChangeOwnUsernameRequest 受控更名请求。
type ChangeOwnUsernameRequest struct {
	SessionSecret []byte
	NewUsername   string
	// Password/TOTPCode 只用于本次真实再次认证，不保存/不记录。
	Password           string
	TOTPCode           string
	ExpectedRowVersion int64
	RequestID          string
}

// ProfileView 是本人资料视图（脱敏；电话未验证不作为登录依据）。
type ProfileView struct {
	UserID             string
	IsRoot             bool
	Username           string
	UsernameNormalized string
	Nickname           string
	Biography          string
	Language           string
	Timezone           string
	Phone              string
	PhoneVerified      bool
	RowVersion         int64
	UsernameChangedAt  string
	CreatedAt          string
	UpdatedAt          string
}

// Profile 返回个人资料公开门面。
func (r *Runtime) Profile() ProfileService {
	return &profileFacade{r: r}
}

type profileFacade struct {
	r *Runtime
}

// service 返回已装配的资料领域服务。
func (f *profileFacade) service() (*profile.Service, error) {
	managed := f.r.managedServices()
	if managed == nil || managed.Profile == nil {
		return nil, configError("资料服务未装配")
	}
	return managed.Profile, nil
}

// sessionUser 校验完整会话并返回本人用户 ID。
func (f *profileFacade) sessionUser(ctx context.Context, secret []byte,
	requestID string) (string, error) {
	record, err := f.r.requireSession(ctx, secret, true, requestID)
	if err != nil {
		return "", err
	}
	return record.UserID, nil
}

// GetProfile 读取本人资料。
func (f *profileFacade) GetProfile(ctx context.Context,
	req OwnProfileRequest) (ProfileView, error) {
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return ProfileView{}, err
	}
	userID, err := f.sessionUser(ctx, req.SessionSecret, requestID)
	if err != nil {
		return ProfileView{}, err
	}
	service, err := f.service()
	if err != nil {
		return ProfileView{}, err
	}
	caller, err := profile.UserCaller(userID)
	if err != nil {
		return ProfileView{}, mapDomainError("会话主体无效", "ACCESS_DENIED", requestID)
	}
	record, err := service.GetProfile(ctx, caller, userID)
	if err != nil {
		return ProfileView{}, mapDomainError("读取资料失败",
			string(profile.CodeOf(err)), requestID)
	}
	return profileViewOf(record), nil
}

// UpdateProfile 更新本人资料白名单字段。
func (f *profileFacade) UpdateProfile(ctx context.Context,
	req UpdateOwnProfileRequest) (ProfileView, error) {
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return ProfileView{}, err
	}
	userID, err := f.sessionUser(ctx, req.SessionSecret, requestID)
	if err != nil {
		return ProfileView{}, err
	}
	service, err := f.service()
	if err != nil {
		return ProfileView{}, err
	}
	caller, err := profile.UserCaller(userID)
	if err != nil {
		return ProfileView{}, mapDomainError("会话主体无效", "ACCESS_DENIED", requestID)
	}
	change := profile.ProfileChange{Nickname: req.Nickname, Biography: req.Biography,
		Language: req.Language, Timezone: req.Timezone, Phone: req.Phone}
	if !change.HasChanges() {
		return ProfileView{}, mapDomainError("资料更新至少需要一个白名单字段",
			"REQ_INVALID", requestID)
	}
	record, err := service.UpdateSelf(ctx, caller, change, req.ExpectedRowVersion, requestID)
	if err != nil {
		return ProfileView{}, mapDomainError("更新资料失败",
			string(profile.CodeOf(err)), requestID)
	}
	return profileViewOf(record), nil
}

// ChangeUsername 受控更名：真实再次认证 + 领域冷却/保留名/root 保护。
func (f *profileFacade) ChangeUsername(ctx context.Context,
	req ChangeOwnUsernameRequest) (ProfileView, error) {
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return ProfileView{}, err
	}
	userID, err := f.sessionUser(ctx, req.SessionSecret, requestID)
	if err != nil {
		return ProfileView{}, err
	}
	service, err := f.service()
	if err != nil {
		return ProfileView{}, err
	}
	caller, err := profile.UserCaller(userID)
	if err != nil {
		return ProfileView{}, mapDomainError("会话主体无效", "ACCESS_DENIED", requestID)
	}
	approved, err := f.r.approveSensitive(ctx, userID, "profile.username.change",
		"受控修改用户名", req.Password, req.TOTPCode, requestID, policy.StrengthPassword)
	if err != nil {
		return ProfileView{}, err
	}
	record, err := service.ChangeUsername(approved, caller, profile.ChangeUsernameRequest{
		TargetUserID: userID, NewUsername: req.NewUsername,
		ExpectedRowVersion: req.ExpectedRowVersion, RequestID: requestID})
	if err != nil {
		return ProfileView{}, mapDomainError("修改用户名失败",
			string(profile.CodeOf(err)), requestID)
	}
	return profileViewOf(record), nil
}

// profileViewOf 转换资料视图并统一时间格式。
func profileViewOf(record profile.UserProfile) ProfileView {
	return ProfileView{UserID: record.UserID, IsRoot: record.IsRoot,
		Username: record.Username, UsernameNormalized: record.UsernameNormalized,
		Nickname: record.Nickname, Biography: record.Biography,
		Language: record.Language, Timezone: record.Timezone, Phone: record.Phone,
		PhoneVerified: record.PhoneVerified, RowVersion: record.RowVersion,
		UsernameChangedAt: formatOptionalTime(record.UsernameChangedAt),
		CreatedAt:         record.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:         record.UpdatedAt.UTC().Format(time.RFC3339)}
}

// formatOptionalTime 返回 UTC RFC3339；零值返回空字符串（不把“从未”伪造成时间）。
func formatOptionalTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}
