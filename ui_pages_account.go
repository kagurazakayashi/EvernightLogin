package login

// 本文件实现步骤 66 个人资料/应用专属资料/头像/邮箱变更/密码修改页面（ui.v1 兼容
// 新增，不改变步骤 62～65 已冻结语义）。
//
// 安全不变量：
//   - 页面只消费 UISessionService 的公开摘要与宿主注入的 UIAccountBackend；不解析
//     Cookie、不缓存权限、不把前端确认当授权。
//   - 普通资料、更名、头像、邮箱、密码分别是独立表单/命名路由，不做“保存全部”；
//     写操作使用服务端行版本，冲突必须重新读取，不覆盖其他会话修改。
//   - 更名/邮箱/改密等敏感操作由适配器在服务端完成 reauth 挑战（绑定操作与参数）
//     后才调用真实服务；页面只收集当前密码用于该挑战，不保存、不回显。
//   - 头像只经受控后端校验/重编码与受控 Read 路由输出；不渲染 SVG/文件名/存储路径。
//   - 邮箱变更 GET 不消费；POST 才调用真实 Verify；旧地址在新地址验证前继续有效，
//     页面不把“验证邮件已交给发送方”写成已验证。
//   - 改密成功按后端真实结果处理会话失效并清 Cookie 跳登录，不自动用新密码重放。

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// uiAvatarMaxUploadBytes 是页面层接受的图片字节上限：取头像服务上限（2 MiB）与
// 传输层默认请求体上限（DefaultHTTPMaxBodyBytes，1 MiB）的较小值，避免默认装配下
// 大于传输上限的头像在传输层先被 413 拒绝。宿主同时提高 MaxBodyBytes 与头像服务
// 上限时可相应调整；页面只做有界读取，真实格式/尺寸/像素校验由头像服务执行。
const uiAvatarMaxUploadBytes = int64(DefaultHTTPMaxBodyBytes)

// UIPageAccountOptions 是步骤 66 页面配置。
type UIPageAccountOptions struct {
	Backend UIAccountBackend
}

// UIAccountBackend 是页面调用真实个人资料相关服务的最小契约；生产适配器内部构造
// 可信 Caller、执行 reauth 挑战并调用 profile/app/avatar/emailchange/passwordreset。
type UIAccountBackend interface {
	GetProfile(ctx context.Context, userID string) (UIProfileView, error)
	UpdateProfile(ctx context.Context, userID string, change UIProfileChange,
		expectedRowVersion int64, requestID string) (UIProfileView, error)
	ChangeUsername(ctx context.Context, userID, newUsername string, expectedRowVersion int64,
		currentPassword, requestID string) (UIProfileView, error)
	GetAppProfile(ctx context.Context, userID, appID string) (UIAppProfileView, error)
	UpdateAppProfile(ctx context.Context, userID, appID string, change UIAppProfileChange,
		expectedRowVersion int64, requestID string) (UIAppProfileView, error)
	GetAvatar(ctx context.Context, userID string) (UIAvatarView, error)
	UploadAvatar(ctx context.Context, userID string, data []byte, declaredMediaType string,
		expectedRowVersion int64, requestID string) (UIAvatarView, error)
	RemoveAvatar(ctx context.Context, userID string, expectedRowVersion int64, requestID string) error
	ReadAvatar(ctx context.Context, userID string) (UIAvatarContent, error)
	GetEmailChangeState(ctx context.Context, userID string) (UIEmailChangeState, error)
	RequestEmailChange(ctx context.Context, userID, newEmail, currentPassword,
		requestID string) (UIEmailChangeState, error)
	CancelEmailChange(ctx context.Context, userID, requestID string) error
	VerifyEmailChange(ctx context.Context, requestID, credentialID, token,
		requestIDLog string) (UIEmailChangeVerified, error)
	ChangePassword(ctx context.Context, userID, currentPassword, newPassword,
		requestID string) (UIPasswordChangeResult, error)
	LogoutCurrent(ctx context.Context, request *http.Request) (*http.Cookie, error)
}

// UIAccountError 是账户页面适配层返回的稳定公开错误。
type UIAccountError struct {
	Code              string
	RetryAfterSeconds int
}

// Error 实现 error。
func (e *UIAccountError) Error() string { return "页面账户操作失败: " + e.Code }

// UIProfileView 是全局资料公开视图（不含秘密/角色/邮箱验证状态）。
type UIProfileView struct {
	UserID            string
	IsRoot            bool
	Username          string
	Nickname          string
	Biography         string
	Language          string
	Timezone          string
	Phone             string
	PhoneVerified     bool
	RowVersion        int64
	UsernameChangedAt time.Time
	UpdatedAt         time.Time
}

// UIProfileChange 是资料更新白名单字段；nil 表示不修改，空字符串表示清除。
type UIProfileChange struct {
	Nickname  *string
	Biography *string
	Language  *string
	Timezone  *string
	Phone     *string
}

// UIAppProfileView 是当前应用成员资料视图。
type UIAppProfileView struct {
	AppID       string
	UserID      string
	Status      string
	DisplayName string
	Title       string
	Note        string
	RowVersion  int64
}

// UIAppProfileChange 是应用成员资料白名单字段。
type UIAppProfileChange struct {
	DisplayName string
	Title       string
	Note        string
}

// UIAvatarView 是头像公开摘要。
type UIAvatarView struct {
	Present    bool
	MediaType  string
	Width      int
	Height     int
	RowVersion int64
}

// UIAvatarContent 是受控头像字节与安全响应头。
type UIAvatarContent struct {
	MediaType string
	Headers   http.Header
	Data      []byte
}

// UIEmailChangeState 是邮箱变更申请/待验证状态。
type UIEmailChangeState struct {
	HasEmail         bool
	OldEmail         string
	Pending          bool
	NewEmail         string
	ExpiresAt        time.Time
	VerificationSent bool
	ErrorCode        string
}

// UIEmailChangeVerified 是邮箱切换成功结果。
type UIEmailChangeVerified struct {
	UserID      string
	Email       string
	SwitchedAt  time.Time
	OldEmail    string
	Notified    bool
	NotifyError string
}

// UIPasswordChangeResult 是改密结果。
type UIPasswordChangeResult struct {
	RequiresRelogin bool
	SessionsRevoked int64
	ChangedAt       time.Time
}

// pageAccountPages 是账户设置页路由与处理器。
type pageAccountPages struct {
	routes   []UIRoute
	handlers map[string]UIPageHandler
	options  UIPageAccountOptions
}

// newPageAccountPages 校验配置并构造路由/处理器。
func newPageAccountPages(options UIPageAccountOptions) (*pageAccountPages, error) {
	if isNilUIValue(options.Backend) {
		return nil, fmt.Errorf("账户设置页面缺少后端适配器")
	}
	pages := &pageAccountPages{handlers: map[string]UIPageHandler{}, options: options}
	handler := &accountPageHandlers{pages: pages}
	routes := []UIRoute{
		{Name: "account.profile", Method: http.MethodGet, Path: "/account/profile",
			Access: UIAccessUser, Layout: "layout/base", Template: "page/account/profile"},
		{Name: "account.profile.update", Method: http.MethodPost, Path: "/account/profile",
			Access: UIAccessUser, Layout: "layout/base", Template: "page/account/profile"},
		{Name: "account.profile_username", Method: http.MethodGet,
			Path: "/account/profile/username", Access: UIAccessUser, Layout: "layout/base",
			Template: "page/account/username"},
		{Name: "account.profile_username.submit", Method: http.MethodPost,
			Path: "/account/profile/username", Access: UIAccessUser, Layout: "layout/base",
			Template: "page/account/username"},
		{Name: "account.app_profile", Method: http.MethodGet, Path: "/account/app-profile",
			Access: UIAccessUser, Layout: "layout/base", Template: "page/account/app_profile"},
		{Name: "account.app_profile.submit", Method: http.MethodPost,
			Path: "/account/app-profile", Access: UIAccessUser, Layout: "layout/base",
			Template: "page/account/app_profile"},
		{Name: "account.profile_avatar", Method: http.MethodGet,
			Path: "/account/profile/avatar", Access: UIAccessUser, Layout: "layout/base",
			Template: "page/account/avatar"},
		{Name: "account.profile_avatar.submit", Method: http.MethodPost,
			Path: "/account/profile/avatar", Access: UIAccessUser, Layout: "layout/base",
			Template: "page/account/avatar"},
		{Name: "account.profile_avatar.remove", Method: http.MethodPost,
			Path: "/account/profile/avatar/remove", Access: UIAccessUser, Layout: "layout/base",
			Template: "page/account/avatar"},
		{Name: "account.profile_avatar_image", Method: http.MethodGet,
			Path: "/account/profile/avatar/image", Access: UIAccessUser, Layout: "layout/base",
			Template: "page/account/avatar"},
		{Name: "account.profile_email", Method: http.MethodGet, Path: "/account/profile/email",
			Access: UIAccessUser, Layout: "layout/base", Template: "page/account/email"},
		{Name: "account.profile_email.submit", Method: http.MethodPost,
			Path: "/account/profile/email", Access: UIAccessUser, Layout: "layout/base",
			Template: "page/account/email"},
		{Name: "account.profile_email.cancel", Method: http.MethodPost,
			Path: "/account/profile/email/cancel", Access: UIAccessUser, Layout: "layout/base",
			Template: "page/account/email"},
		{Name: "account.email_change_verify", Method: http.MethodGet,
			Path: "/email/change/verify", Access: UIAccessPublic, Layout: "layout/auth",
			Template: "page/account/email_verify"},
		{Name: "account.email_change_verify.submit", Method: http.MethodPost,
			Path: "/email/change/verify", Access: UIAccessPublic, Layout: "layout/auth",
			Template: "page/account/email_verify"},
		{Name: "account.password", Method: http.MethodGet, Path: "/account/password",
			Access: UIAccessUser, Layout: "layout/base", Template: "page/account/password"},
		{Name: "account.password.submit", Method: http.MethodPost, Path: "/account/password",
			Access: UIAccessUser, Layout: "layout/base", Template: "page/account/password"},
	}
	for _, route := range routes {
		pages.routes = append(pages.routes, route)
		pages.handlers[route.Name] = handler
	}
	return pages, nil
}

// UIPageAccountPublicFormPaths 返回步骤 66 公开表单路径与匿名 CSRF 用途（含前缀），
// 供宿主配置 transport 公开表单白名单与 pagecsrf 校验器。
func UIPageAccountPublicFormPaths(prefix string) map[string]string {
	return map[string]string{
		prefix + "/email/change/verify": "account.email_change_verify",
	}
}

// accountFormPurpose 把账户页公开路由映射为匿名 CSRF 用途。
func accountFormPurpose(routeName string) string {
	if routeName == "account.email_change_verify" ||
		routeName == "account.email_change_verify.submit" {
		return "account.email_change_verify"
	}
	return ""
}

// accountPageHandlers 实现账户设置页处理器。
type accountPageHandlers struct {
	pages *pageAccountPages
}

// HandlePage 按路由分派。
func (h *accountPageHandlers) HandlePage(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	switch page.RouteName {
	case "account.profile", "account.profile.update":
		return h.profile(ctx, request, page)
	case "account.profile_username", "account.profile_username.submit":
		return h.username(ctx, request, page)
	case "account.app_profile", "account.app_profile.submit":
		return h.appProfile(ctx, request, page)
	case "account.profile_avatar", "account.profile_avatar.submit", "account.profile_avatar.remove":
		return h.avatar(ctx, request, page)
	case "account.profile_avatar_image":
		return h.avatarImage(ctx, page)
	case "account.profile_email", "account.profile_email.submit", "account.profile_email.cancel":
		return h.email(ctx, request, page)
	case "account.email_change_verify", "account.email_change_verify.submit":
		return h.emailVerify(ctx, request, page)
	case "account.password", "account.password.submit":
		return h.password(ctx, request, page)
	default:
		return UIPageOutcome{}, nil
	}
}

// profile 读取/更新全局资料。
func (h *accountPageHandlers) profile(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	view, err := h.pages.options.Backend.GetProfile(ctx, page.Session.UserID)
	if err != nil {
		return accountErrorOutcome(err, nil, "page.account.profile.load_failed"), nil
	}
	data := map[string]any{"profile": view, "statusLoaded": true}
	if request.Method != http.MethodPost {
		if request.URL.Query().Get("status") == "updated" {
			data["updated"] = true
		}
		return UIPageOutcome{Data: data}, nil
	}
	form, formErr := readPageForm(request, page.CSRFField, []string{"nickname", "biography",
		"language", "timezone", "phone", "row_version"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			ErrorSummary: text("page.account.profile.invalid")}, nil
	}
	version, versionErr := parseRowVersion(form.Get("row_version"))
	if versionErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			ErrorSummary: text("page.account.profile.invalid")}, nil
	}
	change := UIProfileChange{}
	if values, ok := form["nickname"]; ok {
		change.Nickname = stringPointer(values[0])
	}
	if values, ok := form["biography"]; ok {
		change.Biography = stringPointer(values[0])
	}
	if values, ok := form["language"]; ok {
		change.Language = stringPointer(values[0])
	}
	if values, ok := form["timezone"]; ok {
		change.Timezone = stringPointer(values[0])
	}
	if values, ok := form["phone"]; ok {
		change.Phone = stringPointer(values[0])
	}
	updated, updateErr := h.pages.options.Backend.UpdateProfile(ctx, page.Session.UserID,
		change, version, page.RequestID)
	if updateErr != nil {
		return accountErrorOutcome(updateErr, data, "page.account.profile.save_failed"), nil
	}
	data["profile"] = updated
	return UIPageOutcome{Data: data, RedirectPath: "/account/profile",
		RedirectQuery: url.Values{"status": {"updated"}}}, nil
}

// username 展示/提交受控更名（当前密码用于绑定操作的 reauth 挑战）。
func (h *accountPageHandlers) username(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	view, err := h.pages.options.Backend.GetProfile(ctx, page.Session.UserID)
	if err != nil {
		return accountErrorOutcome(err, nil, "page.account.profile.load_failed"), nil
	}
	data := map[string]any{"profile": view}
	if request.Method != http.MethodPost {
		return UIPageOutcome{Data: data}, nil
	}
	form, formErr := readPageForm(request, page.CSRFField, []string{"new_username",
		"row_version", "current_password"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			ErrorSummary: text("page.account.username.invalid")}, nil
	}
	newUsername := form.Get("new_username")
	currentPassword := form.Get("current_password")
	version, versionErr := parseRowVersion(form.Get("row_version"))
	if newUsername == "" || currentPassword == "" || versionErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			ErrorSummary: text("page.account.username.invalid")}, nil
	}
	updated, changeErr := h.pages.options.Backend.ChangeUsername(ctx, page.Session.UserID,
		newUsername, version, currentPassword, page.RequestID)
	if changeErr != nil {
		return accountErrorOutcome(changeErr, data, "page.account.username.failed"), nil
	}
	data["profile"] = updated
	data["changed"] = true
	return UIPageOutcome{Data: data}, nil
}

// appProfile 读取/更新当前应用成员资料；应用来自可信会话 AppID。
func (h *accountPageHandlers) appProfile(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if page.Session.AppID == "" {
		return UIPageOutcome{Data: map[string]any{"appSelected": false}}, nil
	}
	view, err := h.pages.options.Backend.GetAppProfile(ctx, page.Session.UserID,
		page.Session.AppID)
	if err != nil {
		return accountErrorOutcome(err, nil, "page.account.app_profile.load_failed"), nil
	}
	data := map[string]any{"appSelected": true, "app": view}
	if request.Method != http.MethodPost {
		if request.URL.Query().Get("status") == "updated" {
			data["updated"] = true
		}
		return UIPageOutcome{Data: data}, nil
	}
	form, formErr := readPageForm(request, page.CSRFField, []string{"display_name", "title",
		"note", "row_version"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			ErrorSummary: text("page.account.app_profile.invalid")}, nil
	}
	version, versionErr := parseRowVersion(form.Get("row_version"))
	if versionErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			ErrorSummary: text("page.account.app_profile.invalid")}, nil
	}
	updated, updateErr := h.pages.options.Backend.UpdateAppProfile(ctx, page.Session.UserID,
		page.Session.AppID, UIAppProfileChange{DisplayName: form.Get("display_name"),
			Title: form.Get("title"), Note: form.Get("note")}, version, page.RequestID)
	if updateErr != nil {
		return accountErrorOutcome(updateErr, data, "page.account.app_profile.save_failed"), nil
	}
	data["app"] = updated
	return UIPageOutcome{Data: data, RedirectPath: "/account/app-profile",
		RedirectQuery: url.Values{"status": {"updated"}}}, nil
}

// avatar 读取头像页、处理 multipart 上传或移除。
func (h *accountPageHandlers) avatar(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	view, err := h.pages.options.Backend.GetAvatar(ctx, page.Session.UserID)
	if err != nil {
		return accountErrorOutcome(err, nil, "page.account.avatar.load_failed"), nil
	}
	data := map[string]any{"avatar": view}
	routeName := page.RouteName
	if routeName == "account.profile_avatar.remove" {
		if request.Method != http.MethodPost {
			return UIPageOutcome{StatusCode: http.StatusMethodNotAllowed,
				ErrorSummary: text("common.state.forbidden")}, nil
		}
		form, formErr := readPageForm(request, page.CSRFField, []string{"row_version"})
		if formErr != nil {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
				ErrorSummary: text("page.account.avatar.invalid")}, nil
		}
		version, versionErr := parseRowVersion(form.Get("row_version"))
		if versionErr != nil {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
				ErrorSummary: text("page.account.avatar.invalid")}, nil
		}
		if removeErr := h.pages.options.Backend.RemoveAvatar(ctx, page.Session.UserID,
			version, page.RequestID); removeErr != nil {
			return accountErrorOutcome(removeErr, data, "page.account.avatar.remove_failed"), nil
		}
		return UIPageOutcome{Data: data, RedirectPath: "/account/profile/avatar",
			RedirectQuery: url.Values{"status": {"removed"}}}, nil
	}
	if request.Method != http.MethodPost {
		if status := request.URL.Query().Get("status"); status != "" {
			data["status"] = status
		}
		return UIPageOutcome{Data: data}, nil
	}
	// multipart 上传：transport 已做 CSRF 校验并恢复请求体，这里只读取受控大小。
	if err := request.ParseMultipartForm(uiAvatarMaxUploadBytes); err != nil && request.MultipartForm == nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			ErrorSummary: text("page.account.avatar.upload_failed")}, nil
	}
	file, header, fileErr := request.FormFile("avatar")
	if fileErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			ErrorSummary: text("page.account.avatar.upload_failed")}, nil
	}
	defer file.Close()
	content, readErr := io.ReadAll(io.LimitReader(file, uiAvatarMaxUploadBytes+1))
	if readErr != nil || int64(len(content)) > uiAvatarMaxUploadBytes {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			ErrorSummary: text("page.account.avatar.too_large")}, nil
	}
	version, versionErr := parseRowVersion(request.FormValue("row_version"))
	if versionErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			ErrorSummary: text("page.account.avatar.invalid")}, nil
	}
	declared := ""
	if header != nil {
		declared = header.Header.Get("Content-Type")
	}
	updated, uploadErr := h.pages.options.Backend.UploadAvatar(ctx, page.Session.UserID,
		content, declared, version, page.RequestID)
	if uploadErr != nil {
		return accountErrorOutcome(uploadErr, data, "page.account.avatar.upload_failed"), nil
	}
	data["avatar"] = updated
	return UIPageOutcome{Data: data, RedirectPath: "/account/profile/avatar",
		RedirectQuery: url.Values{"status": {"uploaded"}}}, nil
}

// avatarImage 输出受控头像字节（服务端 Content-Type/ETag/缓存头）。
func (h *accountPageHandlers) avatarImage(ctx context.Context,
	page UIPageContext) (UIPageOutcome, error) {
	content, err := h.pages.options.Backend.ReadAvatar(ctx, page.Session.UserID)
	if err != nil {
		return accountErrorOutcome(err, nil, "page.account.avatar.load_failed"), nil
	}
	return UIPageOutcome{ContentType: content.MediaType, Body: content.Data,
		Headers: content.Headers}, nil
}

// email 读取邮箱变更状态、提交申请或取消。
func (h *accountPageHandlers) email(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	state, err := h.pages.options.Backend.GetEmailChangeState(ctx, page.Session.UserID)
	if err != nil {
		return accountErrorOutcome(err, nil, "page.account.email.load_failed"), nil
	}
	data := map[string]any{"email": state}
	switch page.RouteName {
	case "account.profile_email.cancel":
		if request.Method != http.MethodPost {
			return UIPageOutcome{StatusCode: http.StatusMethodNotAllowed, Data: data,
				ErrorSummary: text("common.state.forbidden")}, nil
		}
		if cancelErr := h.pages.options.Backend.CancelEmailChange(ctx,
			page.Session.UserID, page.RequestID); cancelErr != nil {
			return accountErrorOutcome(cancelErr, data, "page.account.email.cancel_failed"), nil
		}
		return UIPageOutcome{Data: data, RedirectPath: "/account/profile/email",
			RedirectQuery: url.Values{"status": {"cancelled"}}}, nil
	case "account.profile_email.submit":
		form, formErr := readPageForm(request, page.CSRFField, []string{"new_email",
			"current_password"})
		if formErr != nil {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
				ErrorSummary: text("page.account.email.invalid")}, nil
		}
		newEmail := strings.TrimSpace(form.Get("new_email"))
		currentPassword := form.Get("current_password")
		if newEmail == "" || currentPassword == "" ||
			!strings.Contains(newEmail, "@") {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
				ErrorSummary: text("page.account.email.invalid")}, nil
		}
		updated, requestErr := h.pages.options.Backend.RequestEmailChange(ctx,
			page.Session.UserID, newEmail, currentPassword, page.RequestID)
		if requestErr != nil {
			return accountErrorOutcome(requestErr, data, "page.account.email.request_failed"), nil
		}
		data["email"] = updated
		data["requested"] = true
		return UIPageOutcome{Data: data}, nil
	}
	if status := request.URL.Query().Get("status"); status != "" {
		data["status"] = status
	}
	return UIPageOutcome{Data: data}, nil
}

// emailVerify 渲染/消费新邮箱验证入口（GET 不消费，POST 才调用真实 Verify）。
func (h *accountPageHandlers) emailVerify(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	values := request.URL.Query()
	if request.Method == http.MethodPost {
		form, formErr := readPageForm(request, page.CSRFField, []string{"rid", "cid", "token"})
		if formErr != nil {
			return UIPageOutcome{StatusCode: http.StatusBadRequest,
				ErrorSummary: text("page.account.email_verify.invalid")}, nil
		}
		values = form
	}
	rid := values.Get("rid")
	cid := values.Get("cid")
	token := values.Get("token")
	data := map[string]any{"rid": rid, "cid": cid, "token": token}
	if !validAccountTokenPart(rid, 128) || !validAccountTokenPart(cid, 128) ||
		!validAccountTokenPart(token, 512) {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			ErrorCode:    "CHALLENGE_INVALID",
			ErrorSummary: text("page.account.email_verify.invalid")}, nil
	}
	if request.Method != http.MethodPost {
		return UIPageOutcome{Data: data}, nil
	}
	result, verifyErr := h.pages.options.Backend.VerifyEmailChange(ctx, rid, cid, token,
		page.RequestID)
	if verifyErr != nil {
		return accountErrorOutcome(verifyErr, map[string]any{}, "page.account.email_verify.invalid"), nil
	}
	return UIPageOutcome{Data: map[string]any{"verified": true, "email": result.Email,
		"oldEmail": result.OldEmail, "notified": result.Notified,
		"notifyError": result.NotifyError}}, nil
}

// password 渲染/提交改密（当前密码用于真实复核与绑定操作的 reauth 挑战）。
func (h *accountPageHandlers) password(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	data := map[string]any{}
	if request.Method != http.MethodPost {
		return UIPageOutcome{Data: data}, nil
	}
	form, formErr := readPageForm(request, page.CSRFField, []string{"current_password",
		"new_password", "password_confirm"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			ErrorSummary: text("page.account.password.invalid")}, nil
	}
	current := form.Get("current_password")
	newPassword := form.Get("new_password")
	confirm := form.Get("password_confirm")
	if current == "" || newPassword == "" || newPassword != confirm {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			ErrorSummary: text("page.account.password.mismatch")}, nil
	}
	result, changeErr := h.pages.options.Backend.ChangePassword(ctx, page.Session.UserID,
		current, newPassword, page.RequestID)
	if changeErr != nil {
		return accountErrorOutcome(changeErr, data, "page.account.password.failed"), nil
	}
	clearCookie, _ := h.pages.options.Backend.LogoutCurrent(ctx, request)
	outcome := UIPageOutcome{Data: map[string]any{"changed": true,
		"requiresRelogin": result.RequiresRelogin, "sessionsRevoked": result.SessionsRevoked},
		RedirectRoute: "auth.login"}
	if clearCookie != nil {
		outcome.SetCookies = append(outcome.SetCookies, clearCookie)
	}
	return outcome, nil
}

// ===== 辅助 =====

// accountErrorOutcome 把适配器错误映射为稳定公开状态/文案，不泄露内部细节。
func accountErrorOutcome(err error, data any, fallbackKey string) UIPageOutcome {
	outcome := UIPageOutcome{Data: data, StatusCode: http.StatusBadRequest,
		ErrorSummary: text(fallbackKey)}
	var publicErr *UIAccountError
	if errors.As(err, &publicErr) {
		switch publicErr.Code {
		case "REAUTH_REQUIRED":
			outcome.ErrorCode = "REAUTH_REQUIRED"
			outcome.ErrorSummary = text("page.account.reauth.required")
		case "MFA_REQUIRED":
			outcome.ErrorCode = "MFA_REQUIRED"
			outcome.ErrorSummary = text("page.account.reauth.mfa_required")
		case "CONFLICT":
			outcome.ErrorCode = "CONFLICT"
			outcome.ErrorSummary = text("page.account.common.conflict")
		case "RATE_LIMITED":
			outcome.StatusCode = http.StatusTooManyRequests
			outcome.ErrorCode = "RATE_LIMITED"
			outcome.ErrorSummary = text("common.state.rate_limited")
		case "ACCESS_DENIED":
			outcome.StatusCode = http.StatusForbidden
			outcome.ErrorCode = "ACCESS_DENIED"
			outcome.ErrorSummary = text("common.state.forbidden")
		case "REQ_INVALID":
			outcome.ErrorCode = "REQ_INVALID"
			outcome.ErrorSummary = text(fallbackKey)
		case "DB_UNAVAILABLE", "AUDIT_WRITE_FAILED", "MAIL_DELIVERY_FAILED", "RESOURCE_FORBIDDEN":
			// 依赖/通知/资源策略故障不能伪装成用户输入错误。
			outcome.StatusCode = http.StatusServiceUnavailable
			outcome.ErrorCode = publicErr.Code
			outcome.ErrorSummary = text("page.account.common.unavailable")
		case "INTERNAL_ERROR":
			outcome.StatusCode = http.StatusInternalServerError
			outcome.ErrorCode = "INTERNAL_ERROR"
			outcome.ErrorSummary = text("common.state.error")
		default:
			outcome.StatusCode = http.StatusInternalServerError
			outcome.ErrorCode = "INTERNAL_ERROR"
			outcome.ErrorSummary = text("common.state.error")
		}
	}
	return outcome
}

func parseRowVersion(value string) (int64, error) {
	parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("行版本无效")
	}
	return parsed, nil
}

func stringPointer(value string) *string { copied := value; return &copied }

// validAccountTokenPart 校验一次性链接参数形状（长度与非空；真实校验在服务端）。
func validAccountTokenPart(value string, maxBytes int) bool {
	return value != "" && len(value) <= maxBytes
}

// builtinAccountMessages 是账户设置页摘要使用的中文基线（模板静态文案仍走 i18n 键）。
var builtinAccountMessages = map[string]string{
	"page.account.profile.load_failed":     "无法读取资料，请稍后重试",
	"page.account.profile.invalid":         "资料输入无效，请检查后重试",
	"page.account.profile.save_failed":     "资料保存失败，请重新读取后再试",
	"page.account.username.invalid":        "更名输入无效，请检查后重试",
	"page.account.username.failed":         "更名未完成，请按提示处理",
	"page.account.app_profile.load_failed": "无法读取应用资料，请稍后重试",
	"page.account.app_profile.invalid":     "应用资料输入无效，请检查后重试",
	"page.account.app_profile.save_failed": "应用资料保存失败，请重新读取后再试",
	"page.account.avatar.load_failed":      "无法读取头像，请稍后重试",
	"page.account.avatar.invalid":          "头像请求无效，请检查后重试",
	"page.account.avatar.upload_failed":    "头像上传未完成，已保留原头像",
	"page.account.avatar.too_large":        "图片超过允许的大小",
	"page.account.avatar.remove_failed":    "移除头像未完成，请稍后重试",
	"page.account.email.load_failed":       "无法读取邮箱状态，请稍后重试",
	"page.account.email.invalid":           "邮箱输入无效，请检查后重试",
	"page.account.email.request_failed":    "邮箱变更申请未完成，请稍后重试",
	"page.account.email.cancel_failed":     "取消邮箱变更未完成，请稍后重试",
	"page.account.email_verify.invalid":    "该验证入口无法使用或已失效",
	"page.account.password.invalid":        "密码输入无效，请检查后重试",
	"page.account.password.mismatch":       "两次输入的新密码不一致",
	"page.account.password.failed":         "密码修改未完成，请检查当前密码与策略要求",
	"page.account.reauth.required":         "该操作需要先验证当前身份，请按提示完成验证",
	"page.account.reauth.mfa_required":     "当前操作需要更强制认证，暂不能降级完成",
	"page.account.common.conflict":         "数据已被其他操作修改，请重新读取后再试",
	"page.account.common.unavailable":      "服务暂时不可用，请稍后重试；未完成的操作不会被视为成功",
	"common.state.error":                   "操作未完成",
}

func accountMessage(key string) (string, bool) {
	message, ok := builtinAccountMessages[key]
	return message, ok
}

// 让 accountMessage 与既有 text 协同：text 查内置账户文案后再回退。
func init() {
	for key, message := range builtinAccountMessages {
		if _, exists := builtinAuthMessages[key]; !exists {
			builtinAuthMessages[key] = message
		}
	}
}
