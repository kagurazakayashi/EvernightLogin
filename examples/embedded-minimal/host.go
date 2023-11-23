package main

// host.go 负责示例宿主侧的真实资源装配：临时数据目录、动态回环监听器、
// 宿主自己的 http.Server、受保护业务路由与统一清理。所有 EvernightLogin 调用都
// 只经过公开包（login 根包 + app 装配包），不导入 internal/。

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/app"
)

const (
	// httpPrefix 是 EvernightLogin 页面/HTTP 处理器在宿主站点内的固定前缀。
	httpPrefix = "/idp"
	// hostSessionCookie 是宿主自己业务路由使用的会话 Cookie 名。值取
	// Sessions.Validate 接受的会话秘密（base64url），只应在 HTTPS + HttpOnly +
	// SameSite 的宿主 Cookie 上使用；示例为兼容本地演示未设置这些属性。
	hostSessionCookie = "host_session"
	// credentialsFileName 是演示模式临时凭据文件名（随临时目录删除）。
	credentialsFileName = "demo-credentials.txt"
)

// host 是示例宿主：一个真实 http.Server + 一个已装配但可能尚未 Start 的运行时。
//
// 资源所有权：dataDir/listener/server 由本示例创建并负责清理；runtime 只会关闭它
// 自己打开的 SQLite、主密钥与后台任务，不关闭宿主资源（此处宿主没有额外注入）。
type host struct {
	runtime         *app.Runtime
	listener        net.Listener
	server          *http.Server
	serveErr        chan error
	dataDir         string
	credentialsPath string
	user            app.User
	userPassword    string
	rootUserID      string
	keepData        bool

	mu     sync.Mutex
	closed bool
}

// openHost 创建临时目录与动态回环监听器，装配真实运行时，受控初始化 root，
// 通过公开注册接口创建合成用户，并把 HTTP/UI 挂到宿主自己的 mux 与 http.Server。
//
// 它不调用 Runtime.Start（生命周期由调用方显式决定），也不监听固定端口。
// 返回 error 时已创建的资源会被清理，不遗留数据库句柄或监听端口。
func openHost(ctx context.Context, username string, writeCredentials bool) (h *host, err error) {
	h = &host{}
	defer func() {
		if err != nil {
			_ = h.shutdown(context.Background())
		}
	}()
	if h.dataDir, err = os.MkdirTemp("", "evernightlogin-embedded-minimal-"); err != nil {
		return nil, fmt.Errorf("创建临时数据目录失败: %w", err)
	}
	if h.listener, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		return nil, fmt.Errorf("监听动态回环端口失败: %w", err)
	}
	// 动态端口已知后才写入配置：公共基础地址与 CSRF/来源校验使用同一来源。
	publicBaseURL := h.origin()
	cfg := login.Default()
	cfg.Server.PublicBaseURL = publicBaseURL + httpPrefix
	cfg.Registration.Enabled = true
	cfg.Registration.RequireReview = false
	cfg.Registration.RequireEmailVerification = false
	runtime, err := app.Open(ctx, app.Options{
		Config:          &cfg,
		DatabasePath:    filepath.Join(h.dataDir, "login.db"),
		MasterKeyFile:   filepath.Join(h.dataDir, "master.key"),
		CreateMasterKey: true,
		Migrate:         true,
		OperatorID:      "embedded-minimal-example",
		HTTP:            &app.HTTPOptions{Prefix: httpPrefix},
	})
	if err != nil {
		return nil, fmt.Errorf("打开嵌入式运行时失败: %w", err)
	}
	h.runtime = runtime

	// 受控本地初始化：root 只由本进程的可信启动流程建立，绝不来自 HTTP 参数。
	rootPassword, err := randomPassword()
	if err != nil {
		return nil, err
	}
	root, err := runtime.Bootstrap().EnsureRoot(ctx, app.RootRequest{
		DisplayName: "Root", Password: rootPassword, RequestID: login.NewRequestID(),
	})
	if err != nil {
		return nil, fmt.Errorf("受控初始化 root 失败: %w", err)
	}
	h.rootUserID = root.UserID

	// 合成用户走公开注册流程（配置显式开启 registration.enabled）。
	password, err := randomPassword(username, "Minimal Embedding Example")
	if err != nil {
		return nil, err
	}
	user, err := runtime.Users().Create(ctx, app.CreateUserRequest{
		Username: username, Password: password, Nickname: "Minimal Embedding Example",
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		return nil, fmt.Errorf("公开注册合成用户失败: %w", err)
	}
	h.user = user
	h.userPassword = password

	// 演示模式的临时凭据文件：只写入本示例的临时目录，退出时随目录删除。
	if writeCredentials {
		h.credentialsPath = filepath.Join(h.dataDir, credentialsFileName)
		content := "username=" + username + "\npassword=" + password + "\n"
		if err := os.WriteFile(h.credentialsPath, []byte(content), 0o600); err != nil {
			return nil, fmt.Errorf("写入演示凭据文件失败: %w", err)
		}
	}

	// 宿主自己的路由与 EvernightLogin 页面/HTTP 共享同一个 mux：
	//   - /healthz、/api/whoami 是宿主业务路由，后者用公开 Sessions.Validate
	//     在宿主 HTTP 边界校验会话；
	//   - /idp/* 是 EvernightLogin 的页面与 HTTP 处理器（运行时装配）；
	//   - / 只在演示模式作为说明首页。
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", h.handleHealthz)
	mux.HandleFunc("/api/whoami", h.handleWhoAmI)
	mux.HandleFunc("/", h.handleHome)
	if err := runtime.Mount(mux); err != nil {
		return nil, fmt.Errorf("挂载 EvernightLogin HTTP 处理器失败: %w", err)
	}
	h.server = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	h.serveErr = make(chan error, 1)
	go func() { h.serveErr <- h.server.Serve(h.listener) }()
	return h, nil
}

// start 显式启动运行时的后台任务并检查就绪（Open 本身不启动任何后台任务）。
func (h *host) start(ctx context.Context) error {
	if err := h.runtime.Start(ctx); err != nil {
		return fmt.Errorf("显式启动运行时失败: %w", err)
	}
	if err := h.runtime.Ready(ctx); err != nil {
		return fmt.Errorf("就绪检查失败: %w", err)
	}
	return nil
}

// shutdown 有序关闭宿主资源并删除临时数据目录（幂等）。
// 关闭顺序：宿主 HTTP 服务 -> 运行时（自有 SQLite/后台任务）-> 监听器 -> 临时目录。
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
	if h.dataDir != "" && !h.keepData {
		if err := os.RemoveAll(h.dataDir); err != nil {
			failures = append(failures, fmt.Errorf("删除临时数据目录失败: %w", err))
		}
	}
	return errors.Join(failures...)
}

// url 返回宿主站点内的绝对 URL。
func (h *host) url(path string) string { return h.origin() + path }

// origin 返回动态回环监听器的 scheme://host:port 来源（配置与 CSRF 校验同源）。
func (h *host) origin() string { return "http://" + h.listener.Addr().String() }

// port 返回实际绑定的回环端口（0 表示不可用）。
func (h *host) port() int {
	if address, ok := h.listener.Addr().(*net.TCPAddr); ok {
		return address.Port
	}
	return 0
}

// handleHealthz 是宿主自己的存活检查，与 EvernightLogin 页面处理器并存。
func (h *host) handleHealthz(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(writer, "ok")
}

// handleWhoAmI 是“宿主受保护业务路由”的示范：会话秘密来自宿主自己的 Cookie，
// 由公开 Sessions.Validate 在请求边界校验；未认证或会话失效一律 401（fail-closed）。
// 它只负责校验，不代替业务权限判断；真实宿主还应对具体操作调用
// Sessions.Authorize（会话 + 应用绑定 + 所需权限）。
func (h *host) handleWhoAmI(writer http.ResponseWriter, request *http.Request) {
	ctx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
	defer cancel()
	cookie, err := request.Cookie(hostSessionCookie)
	if err != nil {
		writeUnauthorized(writer)
		return
	}
	secret, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		writeUnauthorized(writer)
		return
	}
	info, err := h.runtime.Sessions().Validate(ctx, secret)
	if err != nil {
		// 不把内部错误/账户状态细节返回给调用者。
		writeUnauthorized(writer)
		return
	}
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(writer).Encode(map[string]string{
		"user_id": info.UserID, "session_id": info.SessionID,
	})
}

// sessionCookie 把一次真实登录得到的会话秘密包装成宿主自己的 Cookie。
func (h *host) sessionCookie(secret []byte) *http.Cookie {
	return &http.Cookie{
		Name: hostSessionCookie, Value: base64.RawURLEncoding.EncodeToString(secret),
	}
}

// handleHome 只在演示模式作为本地说明页；其他未知宿主路径返回 404。
func (h *host) handleHome(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || request.URL.Path != "/" {
		http.NotFound(writer, request)
		return
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(writer, `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>EvernightLogin 最小嵌入示例</title></head><body>
<h1>EvernightLogin 最小嵌入示例（演示）</h1>
<p>本页面由宿主自己的 http.Server 提供；EvernightLogin 页面挂在固定前缀下。</p>
<ul>
<li><a href="%s">登录页</a></li>
<li><a href="%s">注册页</a></li>
<li><a href="/healthz">宿主健康检查</a></li>
<li><a href="/api/whoami">宿主受保护路由（未认证时应 401）</a></li>
</ul>
<p>临时 SQLite 与演示账户由本示例创建，退出时删除；本地管理员只由受控初始化流程建立。</p>
</body></html>`,
		h.url(httpPrefix+"/login"), h.url(httpPrefix+"/register"))
}

// writeUnauthorized 返回固定的未认证响应，不回显原因。
func writeUnauthorized(writer http.ResponseWriter) {
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.WriteHeader(http.StatusUnauthorized)
	_, _ = io.WriteString(writer, "unauthenticated")
}

// randomPassword 生成满足默认密码策略的高熵随机密码（仅用于临时合成账户）。
// 密码不含用户名/昵称等账户标识，也不写入普通日志或自检 JSON。
func randomPassword(identifiers ...string) (string, error) {
	for attempt := 0; attempt < 8; attempt++ {
		buffer := make([]byte, 24)
		if _, err := rand.Read(buffer); err != nil {
			return "", fmt.Errorf("生成随机密码失败: %w", err)
		}
		password := "Kq7-" + hex.EncodeToString(buffer)
		if !containsAnyIdentifier(password, identifiers) {
			return password, nil
		}
	}
	return "", errors.New("生成随机密码失败：连续命中账户标识")
}

// containsAnyIdentifier 报告密码是否包含长度 >= 3 的账户标识（与密码策略一致）。
func containsAnyIdentifier(password string, identifiers []string) bool {
	lower := strings.ToLower(password)
	for _, identifier := range identifiers {
		token := strings.ToLower(strings.TrimSpace(identifier))
		if len([]rune(token)) >= 3 && strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

// demoWaitContext 返回演示模式的结束信号：Ctrl+C/SIGTERM，或 duration 到期
// （duration<=0 表示只等 Ctrl+C）。返回值第二个函数释放信号订阅与定时器。
func demoWaitContext(duration time.Duration) (context.Context, context.CancelFunc) {
	signalCtx, stopSignal := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	if duration <= 0 {
		return signalCtx, stopSignal
	}
	timerCtx, cancelTimer := context.WithTimeout(signalCtx, duration)
	return timerCtx, func() {
		cancelTimer()
		stopSignal()
	}
}
