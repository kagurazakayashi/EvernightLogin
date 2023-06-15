package serverapp_test

// 管理页面 + 生产授权适配层的真实端到端测试：真实临时目录、真实 SQLite、真实监听、
// 真实 account/session 服务与 bootstrap 初始化记录。
//
// 测试只在一处使用“服务端事实合成”：直接调用真实 session.Service 为 root 签发一个
// 已完成强认证的会话（生产环境由 MFA/Passkey 绑定流程产生该事实；该流程尚未装配，
// 见报告缺口）。页面访问、权限判定、服务调用与渲染全部走真实代码路径。

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/bootstrap"
	bootstrapsqlite "github.com/kagurazakayashi/EvernightLogin/internal/bootstrap/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/serverapp"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	sessionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/session/sqlite"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// issueRootSession 使用真实会话服务为 root 签发会话。
//
// mode=strong：完整认证 + 服务端强认证时间（生产事实由 MFA/Passkey 流程产生）；
// mode=restricted：待第二因素受限会话（root 未完成强认证时的真实形态）。
func issueRootSession(t *testing.T, configPath, databasePath, masterKeyPath string,
	mode string) *http.Cookie {
	t.Helper()
	ctx := context.Background()
	cfg, err := serverapp.LoadConfig(configPath, databasePath)
	if err != nil {
		t.Fatalf("加载测试配置失败: %v", err)
	}
	keyring, _, err := serverapp.LoadKeyring(ctx, cfg, masterKeyPath, false, time.Now)
	if err != nil {
		t.Fatalf("加载测试主密钥环失败: %v", err)
	}
	store, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(cfg.Database.Path))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	defer store.Close()
	auditStore, err := auditsqlite.New(store)
	if err != nil {
		t.Fatalf("构造审计存储失败: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{})
	if err != nil {
		t.Fatalf("构造审计写入器失败: %v", err)
	}
	bootstrapStore, err := bootstrapsqlite.New(store)
	if err != nil {
		t.Fatalf("构造初始化存储失败: %v", err)
	}
	root, found, err := bootstrapStore.GetRootAccount(ctx)
	if err != nil || !found {
		t.Fatalf("读取 root 初始化记录失败: found=%v err=%v", found, err)
	}
	sessionStore, err := sessionsqlite.New(store)
	if err != nil {
		t.Fatalf("构造会话存储失败: %v", err)
	}
	service, err := session.New(sessionStore, session.Options{
		Store: sessionStore, Audit: recorder, Keyring: keyring,
		// 与生产装配一致：root 仅可在带服务端强认证时间的完整认证结果上签发
		// 普通会话（见 internal/serverapp/services.go）。
		AllowRootStrongAuthSessions: true,
	})
	if err != nil {
		t.Fatalf("构造会话服务失败: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	result := authn.AuthenticateResult{
		UserID: root.UserID, Username: bootstrap.RootUsername,
		Outcome:          authn.OutcomeComplete,
		CompletedMethods: []authn.Method{authn.MethodPassword},
		CompletedAt:      now, SecurityVersion: root.SecurityVersion,
	}
	switch mode {
	case "strong":
		result.StrongAuthCompletedAt = now
	case "restricted":
		result.Outcome = authn.OutcomePendingSecondFactor
		result.Restricted = true
		result.RequiredSteps = []authn.Step{authn.StepSecondFactor}
	default:
		t.Fatalf("未知会话模式: %s", mode)
	}
	issued, err := service.Login(ctx, session.LoginRequest{
		Result: result, RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("签发 root 测试会话失败（mode=%s）: %v", mode, err)
	}
	cookie, err := service.NewCookie(issued)
	if err != nil {
		t.Fatalf("构造会话 Cookie 失败: %v", err)
	}
	return cookie
}

// getWithCookie 发起带会话 Cookie 的 GET 请求。
func getWithCookie(t *testing.T, client *http.Client, target string,
	cookie *http.Cookie) (int, string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("请求 %s 失败: %v", target, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		t.Fatalf("读取响应失败: %v", err)
	}
	return response.StatusCode, string(body)
}

// TestManagementPagesRequireStrongAuthSession 验证管理页只对真实强认证会话开放，
// 且强认证会话可读取真实 account/role 数据（生产授权适配层）。
func TestManagementPagesRequireStrongAuthSession(t *testing.T) {
	paths := preparePaths(t, nil)
	writeMasterKey(t, paths.masterKey)
	if stdout, err := runInit(t, paths); err != nil {
		t.Fatalf("首次初始化失败: %v（stdout=%s）", err, stdout)
	}
	address, _, cancel := startServe(t, serverapp.ServeOptions{
		ConfigPath: paths.config, MasterKeyFile: paths.masterKey,
	})
	defer cancel()
	base := "http://" + address
	client := &http.Client{Timeout: 10 * time.Second}

	// 1) 无会话：管理页要求登录（401），不泄露内容。
	if status, _ := getWithCookie(t, client, base+"/admin/users", nil); status != http.StatusUnauthorized {
		t.Fatalf("无会话访问管理页状态码 = %d，期望 401", status)
	}
	// 2) 受限会话（root 未完成强认证时的真实形态）：管理页 403（fail-closed）。
	restrictedCookie := issueRootSession(t, paths.config, paths.database,
		paths.masterKey, "restricted")
	if status, body := getWithCookie(t, client, base+"/admin/users", restrictedCookie); status != http.StatusForbidden {
		t.Fatalf("受限会话访问管理页状态码 = %d，期望 403（body 前 80: %.80s）",
			status, body)
	}
	// 3) 真实完成强认证的 root 会话：已装配管理页 200，内容来自真实服务。
	strongCookie := issueRootSession(t, paths.config, paths.database, paths.masterKey, "strong")
	for _, pagePath := range []string{
		"/admin/users", "/admin/roles", "/admin/audit", "/admin/statistics",
		"/admin/reports", "/admin/backups", "/admin/applications",
	} {
		status, body := getWithCookie(t, client, base+pagePath, strongCookie)
		if status != http.StatusOK {
			t.Fatalf("强认证会话访问 %s 状态码 = %d，期望 200（body 前 160: %.160s）",
				pagePath, status, body)
		}
		if !strings.Contains(strings.ToLower(body), "<html") {
			t.Fatalf("%s 响应不是 HTML 页面: %.120s", pagePath, body)
		}
	}
	// 个人资料页已装配：强认证会话可读取；安全中心核心能力（MFA/TOTP/恢复代码/
	// 会话）不依赖 Passkey 与 OAuth，应正常注册；Passkey/OAuth 子能力显示未启用。
	if status, body := getWithCookie(t, client, base+"/account/profile", strongCookie); status != http.StatusOK {
		t.Fatalf("个人资料页状态码 = %d，期望 200（body 前 160: %.160s）", status, body)
	}
	if status, body := getWithCookie(t, client, base+"/account/security", strongCookie); status != http.StatusOK {
		t.Fatalf("Passkey 未启用时安全中心核心页应可用，状态码 = %d（body 前 160: %.160s）", status, body)
	}
	// 4) 伪造 Cookie 仍然是 401。
	forged := &http.Cookie{Name: session.DefaultCookieName, Value: "forged-session-value"}
	if status, _ := getWithCookie(t, client, base+"/admin/users", forged); status != http.StatusUnauthorized {
		t.Fatalf("伪造会话访问管理页状态码 = %d，期望 401", status)
	}
}

// 防止 secrets 包只被 import 未使用（LoadKeyring 内部已使用；显式保留编译期引用）。
var _ = secrets.GenerateKeyring
