package main

// host.go 是示例宿主的真实资源装配：临时数据目录、动态回环监听器、宿主自己的
// http.Server、本地邮件捕获器、宿主会话存储、业务资料投影存储与统一清理。
//
// 关键边界（步骤 241）：
//   - 宿主自定义页面挂在自己的路由上，并精确覆盖 Evernight 内置的登录/注册/
//     邮箱验证/找回/重置页面路径；这些页面只调用公开 Go 接口，不导入 internal；
//   - 宿主自定义页面不经过 Evernight HTTP 中间件，因此**自行**实现同源校验与
//     CSRF（匿名表单双提交 Cookie；已登录表单用公开 Sessions.ValidateCSRF），
//     未绕过认证/领域失败限制/审计；MFA 受限会话不建立宿主会话；
//   - 其余 Evernight 内置页面仍在同一 mux 的固定前缀下提供服务（并存挂载）；
//   - 宿主会话秘密只保存在宿主内存，不进浏览器 Cookie；浏览器只持有随机会话 ID。

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/app"
)

const (
	// httpPrefix 是 EvernightLogin 页面/HTTP 在宿主站点内的固定前缀。
	httpPrefix = "/idp"
	// hostSessionCookie 是宿主自己的会话 Cookie：值只是随机 ID，不是 Evernight
	// 会话秘密；真正的会话秘密保存在宿主内存中。
	hostSessionCookie = "host_session"
	// anonymousCSRFCookie 是匿名表单（登录/注册/找回/验证）双提交 Cookie。
	anonymousCSRFCookie = "host_csrf"
	// anonymousCSRFField 是匿名表单隐藏字段名。
	anonymousCSRFField = "host_csrf_token"
	// authenticatedCSRFField 是已登录业务表单隐藏字段名；令牌由登录结果一次性返回
	// 并保存在宿主内存会话中，提交时经公开 Sessions.ValidateCSRF 校验。
	authenticatedCSRFField = "csrf_token"
	// hostSessionTTL 是宿主会话的最长空闲保留时间（示例常量）。
	hostSessionTTL = 30 * time.Minute
)

// hostSession 是宿主自己的会话记录（Evernight 会话秘密只存在服务端内存）。
type hostSession struct {
	ID        string
	UserID    string
	Secret    []byte // Evernight 完整会话秘密；只在宿主内存中流转。
	CSRF      string // 登录结果一次性返回的 CSRF 令牌文本。
	CreatedAt time.Time
	ExpiresAt time.Time
}

// hostSessionStore 是宿主会话存储（内存示例实现）。
type hostSessionStore struct {
	mu      sync.Mutex
	byID    map[string]hostSession
	nowFunc func() time.Time
}

// newHostSessionStore 返回空的宿主会话存储。
func newHostSessionStore(now func() time.Time) *hostSessionStore {
	if now == nil {
		now = time.Now
	}
	return &hostSessionStore{byID: make(map[string]hostSession), nowFunc: now}
}

// Put 保存一次登录得到的会话秘密与 CSRF 令牌，返回浏览器持有的随机会话 ID。
func (s *hostSessionStore) Put(userID string, secret []byte, csrf string) (string, error) {
	id, err := randomToken()
	if err != nil {
		return "", err
	}
	now := s.nowFunc().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[id] = hostSession{ID: id, UserID: userID, Secret: append([]byte(nil), secret...),
		CSRF: csrf, CreatedAt: now, ExpiresAt: now.Add(hostSessionTTL)}
	return id, nil
}

// Get 读取未过期的宿主会话。
func (s *hostSessionStore) Get(id string) (hostSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.byID[id]
	if !ok {
		return hostSession{}, false
	}
	if s.nowFunc().UTC().After(record.ExpiresAt) {
		delete(s.byID, id)
		return hostSession{}, false
	}
	return record, true
}

// Delete 删除宿主会话（例如会话失效或退出登录）。
func (s *hostSessionStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, id)
}

// host 是示例宿主：运行时 + 宿主 HTTP 服务 + 本地邮件捕获器 + 业务存储。
type host struct {
	runtime     *app.Runtime
	listener    net.Listener
	server      *http.Server
	serveErr    chan error
	dataDir     string
	sink        *smtpSink
	sessions    *hostSessionStore
	projections *projectionStore
	// selfServiceRoleID 是示例受控本地初始化创建的自助权限角色 ID。
	selfServiceRoleID string
	demoMode          bool
	keepData          bool

	mu     sync.Mutex
	closed bool
}

// openHost 装配真实运行时与宿主页面，返回尚未 Start 的实例；失败时清理已建资源。
func openHost(ctx context.Context, demoMode, keepData bool) (h *host, err error) {
	h = &host{projections: newProjectionStore(), demoMode: demoMode, keepData: keepData}
	defer func() {
		if err != nil {
			_ = h.shutdown(context.Background())
		}
	}()
	if h.dataDir, err = os.MkdirTemp("", "evernightlogin-custom-pages-"); err != nil {
		return nil, fmt.Errorf("创建临时数据目录失败: %w", err)
	}
	if h.sink, err = newSMTPSink(); err != nil {
		return nil, err
	}
	if h.listener, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		return nil, fmt.Errorf("监听动态回环端口失败: %w", err)
	}
	origin := h.origin()
	cfg := login.Default()
	// 邮件链接基址与页面路由前缀必须一致（公开配置校验要求）。
	cfg.Server.PublicBaseURL = origin + httpPrefix
	cfg.Server.PathPrefix = httpPrefix
	cfg.Registration.Enabled = true
	cfg.Registration.RequireReview = false
	cfg.Registration.RequireEmailVerification = true
	// 本地明文回环 SMTP：仅允许 tls_mode=none + allow_plaintext_local + 回环地址。
	cfg.Mail.Enabled = true
	cfg.Mail.SMTP.Addr = h.sink.Addr()
	cfg.Mail.SMTP.Host = "localhost"
	cfg.Mail.SMTP.TLSMode = "none"
	cfg.Mail.SMTP.AllowPlaintextLocal = true
	cfg.Mail.SMTP.TimeoutSeconds = 10
	cfg.Mail.From.Address = "noreply@example.test"
	cfg.Mail.AppName = "CustomPagesExample"
	cfg.Mail.Delivery.MaxAttempts = 3
	cfg.Mail.Delivery.TimeoutSeconds = 60
	runtime, err := app.Open(ctx, app.Options{
		Config:          &cfg,
		DatabasePath:    filepath.Join(h.dataDir, "login.db"),
		MasterKeyFile:   filepath.Join(h.dataDir, "master.key"),
		CreateMasterKey: true,
		Migrate:         true,
		OperatorID:      "custom-pages-profile-sync-example",
		HTTP:            &app.HTTPOptions{Prefix: httpPrefix},
	})
	if err != nil {
		return nil, fmt.Errorf("打开嵌入式运行时失败: %w", err)
	}
	h.runtime = runtime
	h.sessions = newHostSessionStore(time.Now)
	// 受控本地初始化：用一个受信本地角色给示例用户授予自助资料权限。真实部署应
	// 通过管理页面/CLI 应用产品内置角色（本示例不安装预设目录，避免依赖产品种子）。
	if err := h.provisionSelfServiceRole(ctx); err != nil {
		return nil, fmt.Errorf("初始化示例自助权限角色失败: %w", err)
	}

	// 宿主页面：先注册精确路径覆盖内置 UI 的登录/注册/验证/找回/重置页面，再让
	// Evernight 的 HTTP/页面处理器挂到同一前缀的子树（更精确的宿主模式优先）。
	mux := http.NewServeMux()
	mux.HandleFunc("/", h.handleHome)
	mux.HandleFunc("/profile", h.handleProfilePage)
	mux.HandleFunc("/profile/update", h.handleProfileUpdate)
	mux.HandleFunc("/profile/rename", h.handleProfileRename)
	mux.HandleFunc("/logout", h.handleLogout)
	mux.HandleFunc(httpPrefix+"/login", h.handleLogin)
	mux.HandleFunc(httpPrefix+"/register", h.handleRegister)
	mux.HandleFunc(httpPrefix+"/email/verify", h.handleVerifyEmail)
	mux.HandleFunc(httpPrefix+"/login/forgot-password", h.handleForgotPassword)
	mux.HandleFunc(httpPrefix+"/login/reset-password", h.handleResetPassword)
	if h.demoMode {
		// 仅演示模式注册的本地开发信报页面；自检断言该路由在非演示模式为 404。
		mux.HandleFunc("/dev/mailbox", h.handleDevMailbox)
	}
	if err := runtime.Mount(mux); err != nil {
		return nil, fmt.Errorf("挂载 EvernightLogin HTTP 处理器失败: %w", err)
	}
	h.server = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	h.serveErr = make(chan error, 1)
	go func() { h.serveErr <- h.server.Serve(h.listener) }()
	return h, nil
}

// start 显式启动运行时后台任务（邮件投递任务需要）并检查就绪。
func (h *host) start(ctx context.Context) error {
	if err := h.runtime.Start(ctx); err != nil {
		return fmt.Errorf("显式启动运行时失败: %w", err)
	}
	if err := h.runtime.Ready(ctx); err != nil {
		return fmt.Errorf("就绪检查失败: %w", err)
	}
	return nil
}

// provisionSelfServiceRole 通过 LocalAdmin（仅宿主进程内可信代码）创建一个 system
// 范围角色，组合资料读写与凭据管理权限，供示例合成用户使用。
//
// 这是**示例的受控本地初始化**：它不来自任何 HTTP 请求参数，也不提供提权入口；
// 真实部署应使用产品内置角色/预设与真实管理流程，而不是在示例代码里手工建角色。
func (h *host) provisionSelfServiceRole(ctx context.Context) error {
	local := h.runtime.LocalAdmin()
	admin := h.runtime.Admin()
	role, err := admin.CreateRole(ctx, app.AdminCreateRoleRequest{
		Caller: local, ScopeID: "system", Key: "custom-pages-example-self-service",
		Name: "示例自助权限角色", RequestID: login.NewRequestID()})
	if err != nil {
		return fmt.Errorf("创建示例角色失败: %w", err)
	}
	for _, key := range []string{
		"self.profile.read", "self.profile.update", "self.credentials.manage",
	} {
		permission, permErr := admin.CreatePermission(ctx, app.AdminCreatePermissionRequest{
			Caller: local, ScopeID: "system", Key: key, Name: "示例自助权限 " + key,
			RequestID: login.NewRequestID()})
		if permErr != nil {
			return fmt.Errorf("创建示例权限 %s 失败: %w", key, permErr)
		}
		if permErr := admin.AddRolePermission(ctx, app.AdminRolePermissionRequest{
			Caller: local, RoleID: role.ID, PermissionID: permission.ID,
			RequestID: login.NewRequestID()}); permErr != nil {
			return fmt.Errorf("组合示例权限 %s 失败: %w", key, permErr)
		}
	}
	h.selfServiceRoleID = role.ID
	return nil
}

// assignSelfServiceRole 把示例自助权限角色分配给刚注册的合成用户（LocalAdmin）。
func (h *host) assignSelfServiceRole(ctx context.Context, userID string) error {
	if h.selfServiceRoleID == "" {
		return fmt.Errorf("示例自助权限角色未初始化")
	}
	return h.runtime.Admin().GrantApplicationRole(ctx, app.GrantRoleRequest{
		Caller: h.runtime.LocalAdmin(), UserID: userID, RoleID: h.selfServiceRoleID,
		RequestID: login.NewRequestID()})
}

// shutdown 有序关闭宿主资源并删除临时数据目录（幂等）。
func (h *host) shutdown(ctx context.Context) error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	h.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	var failures []error
	if h.server != nil {
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		if err := h.server.Shutdown(shutdownCtx); err != nil {
			failures = append(failures, fmt.Errorf("关闭 HTTP 服务失败: %w", err))
		}
		cancel()
		if h.serveErr != nil {
			select {
			case serveErr := <-h.serveErr:
				if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
					failures = append(failures, fmt.Errorf("HTTP 服务异常退出: %w", serveErr))
				}
			case <-time.After(3 * time.Second):
				failures = append(failures, errors.New("等待 HTTP 服务退出超时"))
			}
		}
	}
	if h.listener != nil {
		_ = h.listener.Close()
	}
	if h.runtime != nil {
		if err := h.runtime.Close(ctx); err != nil {
			failures = append(failures, fmt.Errorf("关闭运行时失败: %w", err))
		}
	}
	if h.sink != nil {
		if err := h.sink.Close(); err != nil {
			failures = append(failures, fmt.Errorf("关闭本地邮件捕获器失败: %w", err))
		}
	}
	if h.dataDir != "" && !h.keepData {
		if err := os.RemoveAll(h.dataDir); err != nil {
			failures = append(failures, fmt.Errorf("删除临时数据目录失败: %w", err))
		}
	}
	return errors.Join(failures...)
}

// origin 返回动态回环监听器的来源。
func (h *host) origin() string { return "http://" + h.listener.Addr().String() }

// url 返回宿主站点内的绝对 URL。
func (h *host) url(path string) string { return h.origin() + path }

// port 返回实际绑定的回环端口。
func (h *host) port() int {
	if address, ok := h.listener.Addr().(*net.TCPAddr); ok {
		return address.Port
	}
	return 0
}

// ===== 宿主侧 CSRF / 同源 / 会话辅助 =====

// randomToken 生成 base64url 随机令牌（Cookie/会话 ID）。
func randomToken() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("生成随机令牌失败: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

// verifySameOrigin 校验表单 POST 的 Origin（缺失时退回 Referer 来源）与站点同源。
// 宿主自定义页面不经过 Evernight HTTP 中间件，必须自行做同源防护。
func (h *host) verifySameOrigin(request *http.Request) error {
	raw := strings.TrimSpace(request.Header.Get("Origin"))
	if raw == "" {
		if referer := strings.TrimSpace(request.Header.Get("Referer")); referer != "" {
			if parsed, err := url.Parse(referer); err == nil {
				raw = parsed.Scheme + "://" + parsed.Host
			}
		}
	}
	if raw == "" {
		return errors.New("缺少 Origin/Referer，宿主表单拒绝跨站提交")
	}
	if raw != h.origin() {
		return errors.New("来源与宿主站点不一致")
	}
	return nil
}

// issueAnonymousCSRF 返回当前匿名表单 CSRF 令牌；没有 Cookie 时下发新令牌。
func (h *host) issueAnonymousCSRF(writer http.ResponseWriter,
	request *http.Request) (string, error) {
	if cookie, err := request.Cookie(anonymousCSRFCookie); err == nil && len(cookie.Value) >= 20 {
		return cookie.Value, nil
	}
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	http.SetCookie(writer, &http.Cookie{Name: anonymousCSRFCookie, Value: token,
		Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
	return token, nil
}

// verifyAnonymousCSRF 校验匿名表单：同源 + 双提交 Cookie 与隐藏字段一致。
func (h *host) verifyAnonymousCSRF(request *http.Request, formToken string) error {
	if err := h.verifySameOrigin(request); err != nil {
		return err
	}
	cookie, err := request.Cookie(anonymousCSRFCookie)
	if err != nil || len(cookie.Value) < 20 {
		return errors.New("缺少匿名表单 CSRF Cookie")
	}
	if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(formToken)) != 1 {
		return errors.New("匿名表单 CSRF 令牌不匹配")
	}
	return nil
}

// currentHostSession 读取浏览器 Cookie 对应的宿主会话（不校验 Evernight 会话状态）。
func (h *host) currentHostSession(request *http.Request) (hostSession, bool) {
	cookie, err := request.Cookie(hostSessionCookie)
	if err != nil || cookie.Value == "" {
		return hostSession{}, false
	}
	return h.sessions.Get(cookie.Value)
}

// authenticated 读取并**重新校验**宿主会话背后的 Evernight 完整会话；失效时删除
// 宿主会话并返回 ok=false，调用方负责跳转登录页。
func (h *host) authenticated(request *http.Request) (hostSession, app.SessionInfo, bool) {
	session, ok := h.currentHostSession(request)
	if !ok {
		return hostSession{}, app.SessionInfo{}, false
	}
	ctx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
	defer cancel()
	info, err := h.runtime.Sessions().Validate(ctx, session.Secret)
	if err != nil {
		h.sessions.Delete(session.ID)
		return hostSession{}, app.SessionInfo{}, false
	}
	return session, info, true
}

// setHostSessionCookie 下发宿主会话 Cookie（HttpOnly + SameSite=Lax；本地 http 演示
// 未加 Secure，生产 HTTPS 部署应加 Secure 并限制 Path）。
func (h *host) setHostSessionCookie(writer http.ResponseWriter, id string) {
	http.SetCookie(writer, &http.Cookie{Name: hostSessionCookie, Value: id,
		Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

// clearHostSessionCookie 清除宿主会话 Cookie。
func (h *host) clearHostSessionCookie(writer http.ResponseWriter) {
	http.SetCookie(writer, &http.Cookie{Name: hostSessionCookie, Value: "",
		Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}
