// Package uiaccountadapter 把步骤 66 页面公开契约接到真实 profile/app/avatar/
// emailchange/passwordreset/reauth/session 服务（模块内适配器；生产宿主按同一契约
// 自行装配）。
//
// 安全边界：适配器只在服务端构造可信 Caller；敏感操作先经 reauth.BeginChallenge/
// VerifyChallenge 完成绑定操作与参数的一次性批准，再把批准信号放入上下文调用真实
// 服务；页面传入的当前密码只用于该挑战，不写入日志/存储。
package uiaccountadapter

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/avatar"
	"github.com/kagurazakayashi/EvernightLogin/internal/emailchange"
	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/profile"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	"github.com/kagurazakayashi/EvernightLogin/internal/transport"
	ui "github.com/kagurazakayashi/EvernightLogin/ui"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

// Options 是适配器依赖。
type Options struct {
	Profile     *profile.Service
	App         *app.Service
	Avatar      *avatar.Service
	EmailChange *emailchange.Service
	Passwords   *passwordreset.Service
	Reauth      ReauthChallenger
	Sessions    *session.Service
	// RequireReview 等展示策略由页面后端自行决定；本适配器只调用真实服务。
	Now    func() time.Time
	Logger *slog.Logger
}

// ReauthChallenger 是适配器需要的再次认证子集（生产实现 *reauth.Service）。
type ReauthChallenger interface {
	BeginChallenge(ctx context.Context, caller reauth.Caller,
		request reauth.ChallengeRequest) (reauth.Challenge, error)
	VerifyChallenge(ctx context.Context, caller reauth.Caller,
		request reauth.VerifyChallengeRequest) (reauth.ApprovalGrant, error)
	NotifyOutcome(ctx context.Context, result reauth.Result, outcome reauth.Outcome) error
}

// Adapter 实现 ui.UIAccountBackend。
type Adapter struct {
	opts Options
}

// New 校验依赖并构造适配器；缺少任一真实服务时拒绝构造（fail-closed）。
func New(options Options) (*Adapter, error) {
	if options.Profile == nil || options.App == nil || options.Avatar == nil ||
		options.EmailChange == nil || options.Passwords == nil || options.Reauth == nil ||
		options.Sessions == nil {
		return nil, fmt.Errorf("账户页面适配器缺少必需服务")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Adapter{opts: options}, nil
}

// ProfileSignalReauthVerifier 供宿主装配 profile 服务：只接受适配器在完成 reauth
// 挑战后放入上下文的近期完整认证信号；缺失时 fail-closed。
type ProfileSignalReauthVerifier struct {
	// Now 与适配器/服务使用同一注入时钟；nil 使用系统时间。
	Now func() time.Time
}

// VerifyReauth 实现 profile.ReauthVerifier。
func (v ProfileSignalReauthVerifier) VerifyReauth(ctx context.Context, _ profile.Caller,
	_ string) error {
	return checkSignals(ctx, nowOrSystem(v.Now))
}

// EmailSignalReauthVerifier 供宿主装配 emailchange 服务：同上，缺失时 fail-closed。
type EmailSignalReauthVerifier struct {
	// Now 与适配器/服务使用同一注入时钟；nil 使用系统时间。
	Now func() time.Time
}

// VerifyReauth 实现 emailchange.ReauthVerifier。
func (v EmailSignalReauthVerifier) VerifyReauth(ctx context.Context, _ emailchange.Caller,
	_ string) error {
	return checkSignals(ctx, nowOrSystem(v.Now))
}

// nowOrSystem 返回注入时钟或系统时间。
func nowOrSystem(now func() time.Time) time.Time {
	if now != nil {
		return now().UTC()
	}
	return time.Now().UTC()
}

// checkSignals 校验上下文中的近期完整认证信号（5 分钟新鲜度）。
func checkSignals(ctx context.Context, now time.Time) error {
	signals := reauth.SignalsFromContext(ctx)
	if signals.VerifiedAt.IsZero() || !signals.Complete ||
		now.Sub(signals.VerifiedAt.UTC()) > 5*time.Minute ||
		signals.VerifiedAt.UTC().After(now.Add(time.Minute)) {
		return fmt.Errorf("需要近期身份验证")
	}
	return nil
}

// GetProfile 读取本人全局资料。
func (a *Adapter) GetProfile(ctx context.Context, userID string) (ui.UIProfileView, error) {
	caller, err := profile.UserCaller(userID)
	if err != nil {
		return ui.UIProfileView{}, accountErr("ACCESS_DENIED")
	}
	view, err := a.opts.Profile.GetProfile(ctx, caller, userID)
	if err != nil {
		return ui.UIProfileView{}, mapProfileError(err)
	}
	return toProfileView(view), nil
}

// UpdateProfile 更新全局资料白名单字段（行版本条件）。
func (a *Adapter) UpdateProfile(ctx context.Context, userID string,
	change ui.UIProfileChange, expectedRowVersion int64,
	requestID string) (ui.UIProfileView, error) {
	caller, err := profile.UserCaller(userID)
	if err != nil {
		return ui.UIProfileView{}, accountErr("ACCESS_DENIED")
	}
	update := profile.ProfileChange{Nickname: change.Nickname, Biography: change.Biography,
		Language: change.Language, Timezone: change.Timezone, Phone: change.Phone}
	view, err := a.opts.Profile.UpdateSelf(ctx, caller, update, expectedRowVersion, requestID)
	if err != nil {
		return ui.UIProfileView{}, mapProfileError(err)
	}
	return toProfileView(view), nil
}

// ChangeUsername 执行受控更名：当前密码先完成绑定操作的 reauth 挑战。
func (a *Adapter) ChangeUsername(ctx context.Context, userID, newUsername string,
	expectedRowVersion int64, currentPassword, requestID string) (ui.UIProfileView, error) {
	normalized, _, err := account.NormalizeUsername(newUsername)
	if err != nil {
		return ui.UIProfileView{}, accountErr("REQ_INVALID")
	}
	params := map[string]string{"new_username": normalized,
		"expected_row_version": strconv.FormatInt(expectedRowVersion, 10)}
	ctx, sensitiveResult, err := a.approve(ctx, userID, "profile.username.change",
		params, currentPassword, requestID, "修改用户名")
	if err != nil {
		return ui.UIProfileView{}, err
	}
	caller, callerErr := profile.UserCaller(userID)
	if callerErr != nil {
		return ui.UIProfileView{}, accountErr("ACCESS_DENIED")
	}
	view, changeErr := a.opts.Profile.ChangeUsername(ctx, caller,
		profile.ChangeUsernameRequest{TargetUserID: userID, NewUsername: newUsername,
			ExpectedRowVersion: expectedRowVersion, RequestID: requestID})
	a.notify(sensitiveResult, changeErr)
	if changeErr != nil {
		return ui.UIProfileView{}, mapProfileError(changeErr)
	}
	return toProfileView(view), nil
}

// GetAppProfile 读取当前应用成员资料。
func (a *Adapter) GetAppProfile(ctx context.Context, userID,
	appID string) (ui.UIAppProfileView, error) {
	caller, err := app.UserCaller(userID)
	if err != nil {
		return ui.UIAppProfileView{}, accountErr("ACCESS_DENIED")
	}
	membership, err := a.opts.App.GetApplicationMember(ctx, caller, appID, userID)
	if err != nil {
		return ui.UIAppProfileView{}, mapAppError(err)
	}
	return toAppProfileView(membership), nil
}

// UpdateAppProfile 更新当前应用成员资料（只写本应用白名单字段）。
func (a *Adapter) UpdateAppProfile(ctx context.Context, userID, appID string,
	change ui.UIAppProfileChange, expectedRowVersion int64,
	requestID string) (ui.UIAppProfileView, error) {
	caller, err := app.UserCaller(userID)
	if err != nil {
		return ui.UIAppProfileView{}, accountErr("ACCESS_DENIED")
	}
	membership, err := a.opts.App.UpdateApplicationMemberProfile(ctx, caller,
		app.MemberProfileRequest{ApplicationID: appID, UserID: userID,
			Profile: app.MemberProfile{DisplayName: change.DisplayName,
				Title: change.Title, Note: change.Note},
			ExpectedRowVersion: expectedRowVersion})
	if err != nil {
		return ui.UIAppProfileView{}, mapAppError(err)
	}
	return toAppProfileView(membership), nil
}

// GetAvatar 读取当前头像摘要。
func (a *Adapter) GetAvatar(ctx context.Context, userID string) (ui.UIAvatarView, error) {
	caller, err := avatar.UserCaller(userID)
	if err != nil {
		return ui.UIAvatarView{}, accountErr("ACCESS_DENIED")
	}
	record, found, err := a.opts.Avatar.Current(ctx, caller, userID)
	if err != nil {
		return ui.UIAvatarView{}, mapAvatarError(err)
	}
	if !found {
		return ui.UIAvatarView{}, nil
	}
	return ui.UIAvatarView{Present: true, MediaType: record.MediaType,
		Width: record.Width, Height: record.Height, RowVersion: record.RowVersion}, nil
}

// UploadAvatar 上传并替换头像（真实字节校验/重编码由头像服务执行）。
func (a *Adapter) UploadAvatar(ctx context.Context, userID string, data []byte,
	declaredMediaType string, expectedRowVersion int64,
	requestID string) (ui.UIAvatarView, error) {
	caller, err := avatar.UserCaller(userID)
	if err != nil {
		return ui.UIAvatarView{}, accountErr("ACCESS_DENIED")
	}
	record, err := a.opts.Avatar.Upload(ctx, caller, avatar.UploadRequest{
		TargetUserID: userID, Data: data, DeclaredMediaType: declaredMediaType,
		ExpectedRowVersion: expectedRowVersion, RequestID: requestID})
	if err != nil {
		return ui.UIAvatarView{}, mapAvatarError(err)
	}
	return ui.UIAvatarView{Present: true, MediaType: record.MediaType,
		Width: record.Width, Height: record.Height, RowVersion: record.RowVersion}, nil
}

// RemoveAvatar 移除当前头像。
func (a *Adapter) RemoveAvatar(ctx context.Context, userID string,
	expectedRowVersion int64, requestID string) error {
	caller, err := avatar.UserCaller(userID)
	if err != nil {
		return accountErr("ACCESS_DENIED")
	}
	if err := a.opts.Avatar.Remove(ctx, caller, avatar.RemoveRequest{
		TargetUserID: userID, ExpectedRowVersion: expectedRowVersion, RequestID: requestID}); err != nil {
		return mapAvatarError(err)
	}
	return nil
}

// ReadAvatar 读取受控头像字节与安全响应头。
func (a *Adapter) ReadAvatar(ctx context.Context, userID string) (ui.UIAvatarContent, error) {
	caller, err := avatar.UserCaller(userID)
	if err != nil {
		return ui.UIAvatarContent{}, accountErr("ACCESS_DENIED")
	}
	content, err := a.opts.Avatar.Read(ctx, caller, userID)
	if err != nil {
		return ui.UIAvatarContent{}, mapAvatarError(err)
	}
	headers := http.Header{}
	content.SetResponseHeaders(headers)
	return ui.UIAvatarContent{MediaType: content.Avatar.MediaType,
		Headers: headers, Data: content.Data}, nil
}

// GetEmailChangeState 读取当前已验证邮箱与 pending 申请。
func (a *Adapter) GetEmailChangeState(ctx context.Context, userID string) (ui.UIEmailChangeState, error) {
	caller, err := emailchange.UserCaller(userID)
	if err != nil {
		return ui.UIEmailChangeState{}, accountErr("ACCESS_DENIED")
	}
	state := ui.UIEmailChangeState{}
	pending, found, err := a.opts.EmailChange.GetPending(ctx, caller)
	if err != nil {
		return ui.UIEmailChangeState{}, mapEmailChangeError(err)
	}
	if found {
		state.HasEmail = pending.OldEmail != ""
		state.OldEmail = pending.OldEmail
		state.Pending = true
		state.NewEmail = pending.NewEmail
		state.ExpiresAt = pending.ExpiresAt
		state.VerificationSent = pending.VerifyState == emailchange.NotifySent
		state.ErrorCode = pending.VerifyError
	}
	return state, nil
}

// RequestEmailChange 发起邮箱变更：当前密码完成绑定新邮箱摘要的 reauth 挑战。
func (a *Adapter) RequestEmailChange(ctx context.Context, userID, newEmail, currentPassword,
	requestID string) (ui.UIEmailChangeState, error) {
	normalized, _, err := authn.NormalizeEmail(newEmail)
	if err != nil {
		return ui.UIEmailChangeState{}, accountErr("REQ_INVALID")
	}
	ctx, sensitiveResult, err := a.approve(ctx, userID, "email.change.request",
		map[string]string{"new_email": normalized, "request_id": requestID},
		currentPassword, requestID, "变更邮箱")
	if err != nil {
		return ui.UIEmailChangeState{}, err
	}
	caller, callerErr := emailchange.UserCaller(userID)
	if callerErr != nil {
		return ui.UIEmailChangeState{}, accountErr("ACCESS_DENIED")
	}
	result, changeErr := a.opts.EmailChange.RequestChange(ctx, caller, newEmail, requestID)
	a.notify(sensitiveResult, changeErr)
	if changeErr != nil {
		return ui.UIEmailChangeState{}, mapEmailChangeError(changeErr)
	}
	return ui.UIEmailChangeState{HasEmail: result.Request.OldEmail != "",
		OldEmail: result.Request.OldEmail, Pending: true,
		NewEmail: result.Request.NewEmail, ExpiresAt: result.Request.ExpiresAt,
		VerificationSent: result.VerificationSent, ErrorCode: result.ErrorCode}, nil
}

// CancelEmailChange 取消 pending 邮箱变更。
func (a *Adapter) CancelEmailChange(ctx context.Context, userID, requestID string) error {
	caller, err := emailchange.UserCaller(userID)
	if err != nil {
		return accountErr("ACCESS_DENIED")
	}
	if err := a.opts.EmailChange.Cancel(ctx, caller, emailchange.CancelRequest{
		RequestIDLog: requestID}); err != nil {
		return mapEmailChangeError(err)
	}
	return nil
}

// VerifyEmailChange 消费一次性验证入口并切换邮箱（GET 不调用此方法）。
func (a *Adapter) VerifyEmailChange(ctx context.Context, requestID, credentialID, token,
	requestIDLog string) (ui.UIEmailChangeVerified, error) {
	result, err := a.opts.EmailChange.Verify(ctx, emailchange.VerifyRequest{
		RequestID: requestID, CredentialID: credentialID, Token: token,
		RequestIDLog: requestIDLog})
	if err != nil {
		return ui.UIEmailChangeVerified{}, mapEmailChangeError(err)
	}
	return ui.UIEmailChangeVerified{UserID: result.UserID, Email: result.Email,
		SwitchedAt: result.SwitchedAt, OldEmail: result.OldEmail,
		Notified: result.Notified, NotifyError: result.ErrorCode}, nil
}

// ChangePassword 修改密码：当前密码先完成绑定目标账户的 reauth 挑战，再调用真实
// passwordreset 服务（内部再复核当前密码并递增安全版本、撤销会话）。
func (a *Adapter) ChangePassword(ctx context.Context, userID, currentPassword, newPassword,
	requestID string) (ui.UIPasswordChangeResult, error) {
	ctx, sensitiveResult, err := a.approve(ctx, userID, "password.change",
		map[string]string{"target_user_id": userID}, currentPassword, requestID, "修改密码")
	if err != nil {
		return ui.UIPasswordChangeResult{}, err
	}
	clientIP, _ := transportClientIP(ctx)
	caller, callerErr := passwordreset.UserCaller(userID)
	if callerErr != nil {
		return ui.UIPasswordChangeResult{}, accountErr("ACCESS_DENIED")
	}
	result, changeErr := a.opts.Passwords.ChangePassword(ctx, caller,
		passwordreset.ChangeRequest{CurrentPassword: currentPassword,
			NewPassword: newPassword, ClientIP: clientIP, RequestID: requestID})
	a.notify(sensitiveResult, changeErr)
	if changeErr != nil {
		return ui.UIPasswordChangeResult{}, mapPasswordResetError(changeErr)
	}
	return ui.UIPasswordChangeResult{RequiresRelogin: result.RequiresRelogin,
		SessionsRevoked: result.SessionsRevoked, ChangedAt: result.ChangedAt}, nil
}

// LogoutCurrent 返回清理当前会话 Cookie（改密后会话已由服务端撤销；这里只清浏览器）。
func (a *Adapter) LogoutCurrent(ctx context.Context, request *http.Request) (*http.Cookie, error) {
	secret, ok := a.opts.Sessions.SessionSecretFromRequest(request)
	if !ok {
		return a.opts.Sessions.ClearCookie(), nil
	}
	_ = a.opts.Sessions.Logout(ctx, secret)
	return a.opts.Sessions.ClearCookie(), nil
}

// approve 执行绑定操作/参数的 reauth 挑战并把批准信号放入上下文。
func (a *Adapter) approve(ctx context.Context, userID, operationID string,
	params map[string]string, currentPassword, requestID,
	description string) (context.Context, reauth.Result, error) {
	caller, err := reauth.UserCaller(userID)
	if err != nil {
		return ctx, reauth.Result{}, accountErr("ACCESS_DENIED")
	}
	challenge, err := a.opts.Reauth.BeginChallenge(ctx, caller, reauth.ChallengeRequest{
		ScopeID: "system", OperationID: operationID, TargetType: "user", TargetID: userID,
		Params: params, Description: description, RequestID: requestID})
	if err != nil {
		return ctx, reauth.Result{}, mapReauthError(err)
	}
	result := reauth.Result{OperationID: operationID, TargetType: "user",
		TargetID: userID, UserID: userID}
	if !challenge.Required {
		// 策略未要求再认证：不得伪造 VerifiedAt/Strength/Complete/Confirmed 等可信
		// 信号；原样返回上下文，让下游服务按自身授权/策略判定（缺失信号即 fail-closed）。
		return ctx, result, nil
	}
	if currentPassword == "" {
		return ctx, reauth.Result{}, accountErr("REAUTH_REQUIRED")
	}
	grant, verifyErr := a.opts.Reauth.VerifyChallenge(ctx, caller,
		reauth.VerifyChallengeRequest{ChallengeID: challenge.ID,
			Password: currentPassword, RequestID: requestID})
	if verifyErr != nil {
		return ctx, reauth.Result{}, mapReauthError(verifyErr)
	}
	// 仅在真实 VerifyChallenge 成功后合成本次挑战对应的可信信号。
	signals := reauth.Signals{VerifiedAt: a.opts.Now().UTC(),
		Strength: policy.StrengthPassword, Complete: true, Confirmed: true,
		ApprovalToken: grant.Token}
	return reauth.WithSignals(ctx, signals), result, nil
}

// notify 记录敏感操作结果（通知失败不回滚业务结果）。
func (a *Adapter) notify(result reauth.Result, failure error) {
	outcome := reauth.OutcomeSuccess
	if failure != nil {
		outcome = reauth.OutcomeFailure
	}
	if err := a.opts.Reauth.NotifyOutcome(context.Background(), result, outcome); err != nil {
		a.opts.Logger.Warn("账户页面敏感操作告知未完成", "error_category", "notify_failed")
	}
}

// transportClientIP 从可信边界读取客户端地址（缺失时返回空，由服务限流 fail-safe）。
func transportClientIP(ctx context.Context) (string, bool) {
	return transport.ClientIPFromContext(ctx)
}

// ===== 映射 =====

func toProfileView(view profile.UserProfile) ui.UIProfileView {
	return ui.UIProfileView{UserID: view.UserID, IsRoot: view.IsRoot,
		Username: view.Username, Nickname: view.Nickname, Biography: view.Biography,
		Language: view.Language, Timezone: view.Timezone, Phone: view.Phone,
		PhoneVerified: view.PhoneVerified, RowVersion: view.RowVersion,
		UsernameChangedAt: view.UsernameChangedAt, UpdatedAt: view.UpdatedAt}
}

func toAppProfileView(membership app.Membership) ui.UIAppProfileView {
	return ui.UIAppProfileView{AppID: membership.ApplicationID, UserID: membership.UserID,
		Status: string(membership.Status), DisplayName: membership.Profile.DisplayName,
		Title: membership.Profile.Title, Note: membership.Profile.Note,
		RowVersion: membership.RowVersion}
}

func accountErr(code string) error { return &ui.UIAccountError{Code: code} }

func mapProfileError(err error) error {
	switch {
	case errors.Is(err, profile.ErrVersionConflict), errors.Is(err, profile.ErrUsernameTaken):
		return accountErr("CONFLICT")
	case errors.Is(err, profile.ErrRenameTooSoon):
		return &ui.UIAccountError{Code: "RATE_LIMITED", RetryAfterSeconds: 3600}
	case errors.Is(err, profile.ErrRenameReauthRequired):
		return accountErr("REAUTH_REQUIRED")
	case errors.Is(err, profile.ErrAccessDenied):
		return accountErr("ACCESS_DENIED")
	case errors.Is(err, profile.ErrInvalidRequest), errors.Is(err, profile.ErrPhoneInvalid):
		return accountErr("REQ_INVALID")
	case errors.Is(err, profile.ErrStoreUnavailable), errors.Is(err, profile.ErrAuditUnavailable):
		return accountErr("DB_UNAVAILABLE")
	default:
		return accountErr("INTERNAL_ERROR")
	}
}

func mapAppError(err error) error {
	switch {
	case errors.Is(err, app.ErrStateConflict):
		return accountErr("CONFLICT")
	case errors.Is(err, app.ErrAccessDenied), errors.Is(err, app.ErrApplicationInactive):
		return accountErr("ACCESS_DENIED")
	case errors.Is(err, app.ErrInvalidRequest):
		return accountErr("REQ_INVALID")
	default:
		return accountErr("INTERNAL_ERROR")
	}
}

func mapAvatarError(err error) error {
	switch {
	case errors.Is(err, avatar.ErrVersionConflict):
		return accountErr("CONFLICT")
	case errors.Is(err, avatar.ErrAccessDenied):
		return accountErr("ACCESS_DENIED")
	case errors.Is(err, avatar.ErrInvalidImage), errors.Is(err, avatar.ErrImageTooLarge),
		errors.Is(err, avatar.ErrUnsupportedMedia), errors.Is(err, avatar.ErrSVGNotAllowed),
		errors.Is(err, avatar.ErrContentTypeMismatch), errors.Is(err, avatar.ErrInvalidRequest):
		return accountErr("REQ_INVALID")
	case errors.Is(err, avatar.ErrStorageUnavailable), errors.Is(err, avatar.ErrStoreUnavailable),
		errors.Is(err, avatar.ErrAuditUnavailable):
		return accountErr("DB_UNAVAILABLE")
	default:
		return accountErr("INTERNAL_ERROR")
	}
}

func mapEmailChangeError(err error) error {
	switch {
	case errors.Is(err, emailchange.ErrReauthRequired):
		return accountErr("REAUTH_REQUIRED")
	case errors.Is(err, emailchange.ErrRequestNotFound), errors.Is(err, emailchange.ErrRequestExpired),
		errors.Is(err, emailchange.ErrRequestCancelled):
		return accountErr("CHALLENGE_INVALID")
	case errors.Is(err, emailchange.ErrInvalidRequest):
		return accountErr("REQ_INVALID")
	case errors.Is(err, emailchange.ErrAccessDenied):
		return accountErr("ACCESS_DENIED")
	case errors.Is(err, emailchange.ErrStoreUnavailable), errors.Is(err, emailchange.ErrAuditUnavailable):
		return accountErr("DB_UNAVAILABLE")
	case errors.Is(err, emailchange.ErrMailUnavailable):
		return accountErr("MAIL_DELIVERY_FAILED")
	default:
		return accountErr("INTERNAL_ERROR")
	}
}

func mapPasswordResetError(err error) error {
	switch {
	case errors.Is(err, passwordreset.ErrAccessDenied):
		return accountErr("ACCESS_DENIED")
	case errors.Is(err, passwordreset.ErrRateLimited):
		return &ui.UIAccountError{Code: "RATE_LIMITED", RetryAfterSeconds: 60}
	case errors.Is(err, authn.ErrWeakPassword), errors.Is(err, authn.ErrPasswordReused),
		errors.Is(err, passwordreset.ErrInvalidRequest):
		return accountErr("REQ_INVALID")
	case errors.Is(err, passwordreset.ErrStoreUnavailable),
		errors.Is(err, passwordreset.ErrAuditUnavailable):
		return accountErr("DB_UNAVAILABLE")
	default:
		return accountErr("INTERNAL_ERROR")
	}
}

func mapReauthError(err error) error {
	switch {
	case errors.Is(err, reauth.ErrReauthRequired), errors.Is(err, reauth.ErrConfirmationRequired),
		errors.Is(err, reauth.ErrChallengeInvalid):
		return accountErr("REAUTH_REQUIRED")
	case errors.Is(err, reauth.ErrMFARequired):
		return accountErr("MFA_REQUIRED")
	case errors.Is(err, reauth.ErrRateLimited), errors.Is(err, reauth.ErrAttemptsExceeded):
		return &ui.UIAccountError{Code: "RATE_LIMITED", RetryAfterSeconds: 60}
	case errors.Is(err, reauth.ErrAccessDenied):
		return accountErr("ACCESS_DENIED")
	case errors.Is(err, reauth.ErrStoreUnavailable), errors.Is(err, reauth.ErrAuditUnavailable):
		return accountErr("DB_UNAVAILABLE")
	default:
		return accountErr("REAUTH_REQUIRED")
	}
}

// 兼容未使用导入（surface 断言）。
var _ = subtle.ConstantTimeCompare
var _ = strconv.Itoa
var _ = context.Background
