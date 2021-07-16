package login_test

// 步骤 66 页面级测试：使用受控 UIAccountBackend 验证路由/表单/状态/错误映射与
// multipart 上传路径；真实 profile/avatar/emailchange/passwordreset 服务的集成
// 测试尚未在本轮完成（详见步骤 66 开发报告“未验证项”）。

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/pagecsrf"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

type fakeAccountBackend struct {
	profile     login.UIProfileView
	avatar      login.UIAvatarView
	emailState  login.UIEmailChangeState
	failVersion bool
	profileErr  error
	avatarErr   error
}

func (f *fakeAccountBackend) GetProfile(context.Context, string) (login.UIProfileView, error) {
	if f.profileErr != nil {
		return login.UIProfileView{}, f.profileErr
	}
	return f.profile, nil
}

func (f *fakeAccountBackend) UpdateProfile(_ context.Context, _ string,
	change login.UIProfileChange, version int64, _ string) (login.UIProfileView, error) {
	if f.profileErr != nil {
		return login.UIProfileView{}, f.profileErr
	}
	if version != f.profile.RowVersion {
		return login.UIProfileView{}, &login.UIAccountError{Code: "CONFLICT"}
	}
	if change.Nickname != nil {
		f.profile.Nickname = *change.Nickname
	}
	if change.Biography != nil {
		f.profile.Biography = *change.Biography
	}
	f.profile.RowVersion++
	return f.profile, nil
}

func (f *fakeAccountBackend) ChangeUsername(_ context.Context, _ string, newUsername string,
	_ int64, currentPassword, _ string) (login.UIProfileView, error) {
	if currentPassword != "correct-password" {
		return login.UIProfileView{}, &login.UIAccountError{Code: "REAUTH_REQUIRED"}
	}
	f.profile.Username = newUsername
	f.profile.RowVersion++
	return f.profile, nil
}

func (f *fakeAccountBackend) GetAppProfile(context.Context, string,
	string) (login.UIAppProfileView, error) {
	return login.UIAppProfileView{}, nil
}

func (f *fakeAccountBackend) UpdateAppProfile(context.Context, string, string,
	login.UIAppProfileChange, int64, string) (login.UIAppProfileView, error) {
	return login.UIAppProfileView{}, nil
}

func (f *fakeAccountBackend) GetAvatar(context.Context, string) (login.UIAvatarView, error) {
	return f.avatar, nil
}

func (f *fakeAccountBackend) UploadAvatar(_ context.Context, _ string, data []byte,
	_ string, _ int64, _ string) (login.UIAvatarView, error) {
	if f.avatarErr != nil {
		return login.UIAvatarView{}, f.avatarErr
	}
	if len(data) == 0 {
		return login.UIAvatarView{}, &login.UIAccountError{Code: "REQ_INVALID"}
	}
	f.avatar = login.UIAvatarView{Present: true, MediaType: "image/png",
		Width: 8, Height: 8, RowVersion: 2}
	return f.avatar, nil
}

func (f *fakeAccountBackend) RemoveAvatar(context.Context, string, int64, string) error {
	f.avatar = login.UIAvatarView{}
	return nil
}

func (f *fakeAccountBackend) ReadAvatar(context.Context, string) (login.UIAvatarContent, error) {
	headers := http.Header{}
	headers.Set("ETag", `"avatar-test"`)
	return login.UIAvatarContent{MediaType: "image/png", Headers: headers,
		Data: []byte("\x89PNG\r\n\x1a\n")}, nil
}

func (f *fakeAccountBackend) GetEmailChangeState(context.Context, string) (login.UIEmailChangeState, error) {
	return f.emailState, nil
}

func (f *fakeAccountBackend) RequestEmailChange(_ context.Context, _ string, newEmail,
	currentPassword, _ string) (login.UIEmailChangeState, error) {
	if currentPassword != "correct-password" {
		return login.UIEmailChangeState{}, &login.UIAccountError{Code: "REAUTH_REQUIRED"}
	}
	f.emailState.Pending = true
	f.emailState.NewEmail = newEmail
	f.emailState.ExpiresAt = time.Now().Add(time.Hour)
	f.emailState.VerificationSent = true
	return f.emailState, nil
}

func (f *fakeAccountBackend) CancelEmailChange(context.Context, string, string) error {
	f.emailState.Pending = false
	return nil
}

func (f *fakeAccountBackend) VerifyEmailChange(context.Context, string, string,
	string, string) (login.UIEmailChangeVerified, error) {
	return login.UIEmailChangeVerified{UserID: "usr_test", Email: "new@example.test",
		OldEmail: "old@example.test", Notified: true}, nil
}

func (f *fakeAccountBackend) ChangePassword(_ context.Context, _ string, currentPassword,
	_ string, _ string) (login.UIPasswordChangeResult, error) {
	if currentPassword != "correct-password" {
		return login.UIPasswordChangeResult{}, &login.UIAccountError{Code: "REAUTH_REQUIRED"}
	}
	return login.UIPasswordChangeResult{RequiresRelogin: true, SessionsRevoked: 2}, nil
}

func (f *fakeAccountBackend) LogoutCurrent(context.Context,
	*http.Request) (*http.Cookie, error) {
	return &http.Cookie{Name: "__Host-login_session", Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode}, nil
}

type fakePageSessions struct{}

func (fakePageSessions) ResolvePageSession(context.Context,
	*http.Request) (login.UISession, error) {
	return login.UISession{Authenticated: true, UserID: "usr_test", Kind: "normal"}, nil
}

func (fakePageSessions) IssueCSRFToken(context.Context, *http.Request) (string, error) {
	return "test-csrf-token", nil
}

type accountPageEnv struct {
	t       *testing.T
	handler http.Handler
	backend *fakeAccountBackend
}

func newAccountPageEnv(t *testing.T) *accountPageEnv {
	t.Helper()
	backend := &fakeAccountBackend{profile: login.UIProfileView{UserID: "usr_test",
		Username: "alice", Nickname: "Alice", Biography: "<script>alert(1)</script>",
		Language: "zh-CN", Timezone: "Asia/Shanghai", RowVersion: 3}}
	keyring, err := secrets.GenerateKeyring("k1", time.Now())
	if err != nil {
		t.Fatalf("密钥环: %v", err)
	}
	tokens, err := pagecsrf.New(pagecsrf.Options{Keyring: keyring})
	if err != nil {
		t.Fatalf("页面令牌: %v", err)
	}
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session: fakePageSessions{}, FormTokens: tokens,
		PageAccount: &login.UIPageAccountOptions{Backend: backend},
	})
	if err != nil {
		t.Fatalf("页面框架: %v", err)
	}
	return &accountPageEnv{t: t, handler: ui, backend: backend}
}

func (e *accountPageEnv) request(method, path string, body []byte,
	contentType string) *httptest.ResponseRecorder {
	e.t.Helper()
	reader := bytes.NewReader(body)
	if body == nil {
		reader = bytes.NewReader(nil)
	}
	request := httptest.NewRequest(method, "http://example.test"+path, reader)
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	recorder := httptest.NewRecorder()
	e.handler.ServeHTTP(recorder, request)
	return recorder
}

func (e *accountPageEnv) postForm(path string, values url.Values) *httptest.ResponseRecorder {
	return e.request(http.MethodPost, path, []byte(values.Encode()),
		"application/x-www-form-urlencoded")
}

func TestAccountProfileRendersAndUpdates(t *testing.T) {
	env := newAccountPageEnv(t)
	get := env.request(http.MethodGet, "/account/profile", nil, "")
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), "usr_test") ||
		!strings.Contains(get.Body.String(), "alice") {
		t.Fatalf("资料页渲染 = %d body=%.2000s", get.Code, get.Body.String())
	}
	if strings.Contains(get.Body.String(), "<script>alert(1)</script>") {
		t.Fatal("简介脚本字符未被转义")
	}
	if !strings.Contains(get.Body.String(), "&lt;script&gt;") {
		t.Fatal("简介应以文本形式安全展示")
	}
	update := env.postForm("/account/profile", url.Values{"csrf_token": {"test-csrf-token"},
		"row_version": {"3"}, "nickname": {"Alice2"}, "biography": {"hello"},
		"language": {"zh-CN"}, "timezone": {"Asia/Shanghai"}, "phone": {""}})
	if update.Code != http.StatusSeeOther || update.Header().Get("Location") != "/account/profile?status=updated" {
		t.Fatalf("资料保存 = %d %q", update.Code, update.Header().Get("Location"))
	}
	if env.backend.profile.Nickname != "Alice2" || env.backend.profile.RowVersion != 4 {
		t.Fatalf("资料未更新: %+v", env.backend.profile)
	}
	// 旧版本保存 → CONFLICT 重新读取提示。
	conflict := env.postForm("/account/profile", url.Values{"csrf_token": {"test-csrf-token"},
		"row_version": {"3"}, "nickname": {"Old"}})
	if conflict.Code != http.StatusBadRequest ||
		!strings.Contains(conflict.Body.String(), "重新读取") {
		t.Fatalf("版本冲突响应 = %d", conflict.Code)
	}
	// 未触碰字段不提交：只改昵称时其它字段保持。
	onlyNickname := env.postForm("/account/profile", url.Values{
		"csrf_token": {"test-csrf-token"}, "row_version": {"4"}, "nickname": {"Alice3"}})
	if onlyNickname.Code != http.StatusSeeOther || env.backend.profile.Language != "zh-CN" {
		t.Fatalf("单字段更新异常 = %d %+v", onlyNickname.Code, env.backend.profile)
	}
}

func TestAccountUsernameReauthAndConflict(t *testing.T) {
	env := newAccountPageEnv(t)
	page := env.request(http.MethodGet, "/account/profile/username", nil, "")
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "不会改变用户 ID") {
		t.Fatalf("更名页 = %d", page.Code)
	}
	missingReauth := env.postForm("/account/profile/username", url.Values{
		"csrf_token": {"test-csrf-token"}, "row_version": {"3"},
		"new_username": {"alice2"}, "current_password": {"wrong"}})
	if missingReauth.Code != http.StatusBadRequest ||
		!strings.Contains(missingReauth.Body.String(), "验证当前身份") {
		t.Fatalf("reauth 不足 = %d/%q", missingReauth.Code, missingReauth.Body.String())
	}
	changed := env.postForm("/account/profile/username", url.Values{
		"csrf_token": {"test-csrf-token"}, "row_version": {"3"},
		"new_username": {"alice2"}, "current_password": {"correct-password"}})
	if changed.Code != http.StatusOK || !strings.Contains(changed.Body.String(), "用户名已更新") {
		t.Fatalf("更名成功 = %d", changed.Code)
	}
}

func TestAccountAvatarMultipartAndImage(t *testing.T) {
	env := newAccountPageEnv(t)
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.WriteField("csrf_token", "test-csrf-token")
	_ = writer.WriteField("row_version", "3")
	part, err := writer.CreateFormFile("avatar", "avatar.png")
	if err != nil {
		t.Fatalf("构造 multipart: %v", err)
	}
	if _, err := part.Write([]byte("\x89PNG\r\n\x1a\nfakepng")); err != nil {
		t.Fatalf("写入文件: %v", err)
	}
	_ = writer.Close()
	upload := env.request(http.MethodPost, "/account/profile/avatar", body.Bytes(),
		writer.FormDataContentType())
	if upload.Code != http.StatusSeeOther || upload.Header().Get("Location") != "/account/profile/avatar?status=uploaded" {
		t.Fatalf("头像上传 = %d %q body=%.300s", upload.Code,
			upload.Header().Get("Location"), upload.Body.String())
	}
	if !env.backend.avatar.Present || env.backend.avatar.RowVersion != 2 {
		t.Fatalf("头像状态: %+v", env.backend.avatar)
	}
	image := env.request(http.MethodGet, "/account/profile/avatar/image", nil, "")
	if image.Code != http.StatusOK || image.Header().Get("Content-Type") != "image/png" ||
		image.Header().Get("ETag") != `"avatar-test"` ||
		!bytes.Equal(image.Body.Bytes(), []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatalf("头像字节 = %d %v", image.Code, image.Header())
	}
}

func TestAccountEmailVerifyPublicPage(t *testing.T) {
	env := newAccountPageEnv(t)
	get := env.request(http.MethodGet,
		"/email/change/verify?rid=req_1&cid=otc_1&token=secret-token", nil, "")
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), "验证新邮箱") {
		t.Fatalf("验证页 = %d", get.Code)
	}
	form := url.Values{"csrf_token": {extractPageToken(t, get.Body.String())},
		"rid": {"req_1"}, "cid": {"otc_1"}, "token": {"secret-token"}}
	post := env.postForm("/email/change/verify", form)
	if post.Code != http.StatusOK || !strings.Contains(post.Body.String(), "新邮箱已验证并生效") {
		t.Fatalf("验证消费 = %d", post.Code)
	}
}

func TestAccountPasswordChangeRequiresReauth(t *testing.T) {
	env := newAccountPageEnv(t)
	wrong := env.postForm("/account/password", url.Values{"csrf_token": {"test-csrf-token"},
		"current_password": {"wrong"}, "new_password": {"NewPassword1!"},
		"password_confirm": {"NewPassword1!"}})
	if wrong.Code != http.StatusBadRequest ||
		!strings.Contains(wrong.Body.String(), "验证当前身份") {
		t.Fatalf("改密 reauth = %d", wrong.Code)
	}
	ok := env.postForm("/account/password", url.Values{"csrf_token": {"test-csrf-token"},
		"current_password": {"correct-password"}, "new_password": {"NewPassword1!"},
		"password_confirm": {"NewPassword1!"}})
	if ok.Code != http.StatusSeeOther {
		t.Fatalf("改密成功 = %d body=%.300s", ok.Code, ok.Body.String())
	}
	if len(ok.Result().Cookies()) == 0 {
		t.Fatal("改密成功后应清理会话 Cookie")
	}
}

var pageTokenPattern = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

// extractPageToken 从渲染 HTML 中取 CSRF 隐藏字段值（页面级测试）。
func extractPageToken(t *testing.T, body string) string {
	t.Helper()
	match := pageTokenPattern.FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("未找到 CSRF 隐藏字段")
	}
	return match[1]
}

func TestAccountProfileAutocompleteAndTextarea(t *testing.T) {
	env := newAccountPageEnv(t)
	profile := env.request(http.MethodGet, "/account/profile", nil, "")
	if !strings.Contains(profile.Body.String(), "<textarea") {
		t.Fatal("简介应使用 textarea")
	}
	username := env.request(http.MethodGet, "/account/profile/username", nil, "")
	if !strings.Contains(username.Body.String(), `autocomplete="current-password"`) ||
		!strings.Contains(username.Body.String(), `autocomplete="username"`) {
		t.Fatal("更名/当前密码缺少 autocomplete 语义")
	}
	password := env.request(http.MethodGet, "/account/password", nil, "")
	body := password.Body.String()
	if !strings.Contains(body, `autocomplete="current-password"`) ||
		strings.Count(body, `autocomplete="new-password"`) != 2 {
		t.Fatal("改密字段缺少 current/new-password 自动填充语义")
	}
}

func TestAccountErrorsMapToServerFailures(t *testing.T) {
	env := newAccountPageEnv(t)
	env.backend.profileErr = &login.UIAccountError{Code: "DB_UNAVAILABLE"}
	page := env.request(http.MethodGet, "/account/profile", nil, "")
	if page.Code != http.StatusServiceUnavailable ||
		!strings.Contains(page.Body.String(), "服务暂时不可用") ||
		strings.Contains(page.Body.String(), "DB_UNAVAILABLE") {
		t.Fatalf("依赖故障页面 = %d/%q", page.Code, page.Body.String())
	}
	env.backend.profileErr = &login.UIAccountError{Code: "INTERNAL_ERROR"}
	page = env.request(http.MethodGet, "/account/profile", nil, "")
	if page.Code != http.StatusInternalServerError ||
		!strings.Contains(page.Body.String(), "操作未完成") {
		t.Fatalf("内部错误页面 = %d/%q", page.Code, page.Body.String())
	}
	env.backend.avatarErr = &login.UIAccountError{Code: "AUDIT_WRITE_FAILED"}
	uploadPage := env.request(http.MethodGet, "/account/profile/avatar", nil, "")
	if uploadPage.Code != http.StatusOK {
		t.Fatalf("头像页读取 = %d", uploadPage.Code)
	}
	// 头像上传审计失败 → 503，不伪装成输入错误。
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.WriteField("csrf_token", "test-csrf-token")
	_ = writer.WriteField("row_version", "0")
	part, _ := writer.CreateFormFile("avatar", "a.png")
	_, _ = part.Write([]byte("x"))
	_ = writer.Close()
	upload := env.request(http.MethodPost, "/account/profile/avatar", body.Bytes(),
		writer.FormDataContentType())
	if upload.Code != http.StatusServiceUnavailable ||
		!strings.Contains(upload.Body.String(), "服务暂时不可用") {
		t.Fatalf("头像审计失败 = %d", upload.Code)
	}
}

func TestAccountAvatarSizeBoundary(t *testing.T) {
	env := newAccountPageEnv(t)
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.WriteField("csrf_token", "test-csrf-token")
	_ = writer.WriteField("row_version", "3")
	part, _ := writer.CreateFormFile("avatar", "big.png")
	// 页面层上限取传输默认 1 MiB（与头像服务 2 MiB 的较小值）。
	_, _ = part.Write(bytes.Repeat([]byte{0x89}, uiAvatarPageLimitForTest+1))
	_ = writer.Close()
	response := env.request(http.MethodPost, "/account/profile/avatar", body.Bytes(),
		writer.FormDataContentType())
	if response.Code != http.StatusBadRequest ||
		!strings.Contains(response.Body.String(), "图片超过允许的大小") {
		t.Fatalf("超限头像 = %d/%q", response.Code, response.Body.String())
	}
	if env.backend.avatar.Present {
		t.Fatal("超限上传不应改变头像状态")
	}
}

// uiAvatarPageLimitForTest 与页面层上限（传输默认 1 MiB）保持一致。
const uiAvatarPageLimitForTest = 1 << 20
