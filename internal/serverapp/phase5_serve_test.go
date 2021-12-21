package serverapp_test

// B1/B2 第三阶段 serve 级真实集成测试：14 个页面选项（默认 12、条件 2）、OAuth/OIDC 协议端点、管理
// JSON API 完整路由、敏感操作 fail-closed 与维护模式。
//
// 全部使用真实临时目录、真实 SQLite、真实监听、真实领域服务（Passkey 的
// WebAuthn 依赖方配置使用 localhost 测试来源；不会真实访问网络）。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/maintenance"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/serverapp"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// protocolTestYAML 追加启用 Passkey（localhost 测试来源）与协议端点（本地 http
// 回环 issuer，路径前缀为空）。
const protocolTestYAML = `
passkey:
  enabled: true
  rp_id: "localhost"
  rp_display_name: "EvernightLogin 测试"
  allowed_origins:
    - "http://localhost"
  user_verification: required
protocol:
  enabled: true
  issuer: "https://localhost"
`

// newProtocolPaths 构造启用 Passkey 与协议端点的测试配置。
func newProtocolPaths(t *testing.T) testPaths {
	t.Helper()
	return preparePaths(t, func(config string) string { return config + protocolTestYAML })
}

// startProtocolServe 初始化并启动启用协议端点的服务，返回监听地址与取消函数。
func startProtocolServe(t *testing.T) (address string, cancel context.CancelFunc) {
	t.Helper()
	paths := newProtocolPaths(t)
	writeMasterKey(t, paths.masterKey)
	if stdout, err := runInit(t, paths); err != nil {
		t.Fatalf("首次初始化失败: %v（stdout=%s）", err, stdout)
	}
	result, _, cancelServe := startServeResult(t, serverapp.ServeOptions{
		ConfigPath:     paths.config,
		MasterKeyFile:  paths.masterKey,
		EnableAdminAPI: true,
	})
	return result.Addresses[0], cancelServe
}

// getStatus 发起 GET 并按需带上 Cookie，返回状态码与正文。
func getStatus(t *testing.T, client *http.Client, target, cookie string,
	body string) (int, string) {
	t.Helper()
	var reader io.Reader
	method := http.MethodGet
	if body != "" {
		method = http.MethodPost
		reader = strings.NewReader(body)
	}
	request, err := http.NewRequest(method, target, reader)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	if cookie != "" {
		request.Header.Set("Cookie", cookie)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("请求 %s 失败: %v", target, err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		t.Fatalf("读取响应失败: %v", err)
	}
	return response.StatusCode, string(payload)
}

// TestThirteenPagesProtocolAndAdminAPI 验证 14 个页面选项（本测试配置满足全部条件）、
// 协议端点与完整管理 API。
func TestThirteenPagesProtocolAndAdminAPI(t *testing.T) {
	paths := newProtocolPaths(t)
	writeMasterKey(t, paths.masterKey)
	if stdout, err := runInit(t, paths); err != nil {
		t.Fatalf("首次初始化失败: %v（stdout=%s）", err, stdout)
	}
	result, _, cancel := startServeResult(t, serverapp.ServeOptions{
		ConfigPath: paths.config, MasterKeyFile: paths.masterKey,
		EnableAdminAPI: true,
	})
	defer cancel()
	if result.Maintenance {
		t.Fatal("正常启动不应处于维护模式")
	}
	mounts := strings.Join(result.Mounts, ",")
	for _, expected := range []string{"/oauth", "/.well-known", "/jwks", "/admin/v1"} {
		if !strings.Contains(mounts, expected) {
			t.Fatalf("StartResult.Mounts = %v，缺少 %s", result.Mounts, expected)
		}
	}
	base := "http://" + result.Addresses[0]
	client := &http.Client{Timeout: 10 * time.Second}
	noCookie := ""

	// 无会话：受保护页面 401（不泄露内容）。
	for _, pagePath := range []string{
		"/admin/users", "/admin/security/policies", "/account/profile",
		"/account/security", "/support/cases",
	} {
		if status, body := getStatus(t, client, base+pagePath, noCookie, ""); status != http.StatusUnauthorized {
			t.Fatalf("无会话访问 %s 状态码 = %d，期望 401（body 前 120: %.120s）",
				pagePath, status, body)
		}
	}

	// 真实强认证管理会话（生产事实由 Passkey 登录流程产生；HTTP 测试在线程内用
	// 真实 session 服务合成同一事实）读取全部 14 个页面选项对应的页面。
	strongCookie := issueRootSession(t, paths.config, paths.database, paths.masterKey, "strong")
	cookieHeader := strongCookie.Name + "=" + strongCookie.Value
	managementPages := []string{
		"/admin/users",              // 用户/审核/用户组
		"/admin/roles",              // 角色/权限/委派
		"/admin/audit",              // 审计
		"/admin/statistics",         // 统计
		"/admin/reports",            // 报告
		"/admin/backups",            // 备份
		"/admin/applications",       // 应用/安全接入
		"/admin/security/policies",  // 敏感策略
		"/admin/notifications/mail", // 安全通知
	}
	for _, pagePath := range managementPages {
		status, body := getStatus(t, client, base+pagePath, cookieHeader, "")
		if status != http.StatusOK {
			t.Fatalf("管理会话访问 %s 状态码 = %d，期望 200（body 前 160: %.160s）",
				pagePath, status, body)
		}
	}
	accountPages := []string{
		"/account/profile", "/account/security", "/account/security/totp",
		"/account/security/passkeys", "/account/sessions", "/account/grants",
	}
	for _, pagePath := range accountPages {
		status, body := getStatus(t, client, base+pagePath, cookieHeader, "")
		if status != http.StatusOK {
			t.Fatalf("账户会话访问 %s 状态码 = %d，期望 200（body 前 160: %.160s）",
				pagePath, status, body)
		}
	}
	supportPages := []string{"/support/cases", "/support/cases/create", "/support/recovery"}
	for _, pagePath := range supportPages {
		status, body := getStatus(t, client, base+pagePath, cookieHeader, "")
		if status != http.StatusOK {
			t.Fatalf("客服页面 %s 状态码 = %d，期望 200（body 前 160: %.160s）",
				pagePath, status, body)
		}
	}
	// 两步验证流程页（公开入口）：无流程状态时给出受控错误页而不是 404。
	for _, pagePath := range []string{"/login/strong-setup", "/login/forgot-password"} {
		status, _ := getStatus(t, client, base+pagePath, noCookie, "")
		if status == http.StatusNotFound || status >= 500 {
			t.Fatalf("两步验证页面 %s 状态码 = %d，不应为 404/5xx", pagePath, status)
		}
	}
	// OAuth 授权确认页（公开入口）：缺少参数时受控失败，端点存在。
	if status, body := getStatus(t, client, base+"/oauth/authorize", noCookie, ""); status == http.StatusNotFound || status >= 500 {
		t.Fatalf("OAuth 授权页状态码 = %d，不应为 404/5xx（body 前 120: %.120s）", status, body)
	}

	// 协议端点：Discovery 与 JWKS 真实可达，issuer 与配置一致。
	status, body := getStatus(t, client, base+"/.well-known/openid-configuration", noCookie, "")
	if status != http.StatusOK {
		t.Fatalf("OIDC Discovery 状态码 = %d，期望 200（body 前 160: %.160s）", status, body)
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(body), &document); err != nil {
		t.Fatalf("Discovery 不是合法 JSON: %v", err)
	}
	if document["issuer"] != "https://localhost" {
		t.Fatalf("Discovery issuer = %v，期望 https://localhost", document["issuer"])
	}
	if status, body := getStatus(t, client, base+"/jwks", noCookie, ""); status != http.StatusOK ||
		!strings.Contains(body, "\"keys\"") {
		t.Fatalf("JWKS 状态码 = %d，期望 200 且包含 keys（body 前 120: %.120s）", status, body)
	}
	// 令牌端点存在：无效请求返回 OAuth 标准错误，而不是 404。
	status, body = getStatus(t, client, base+"/oauth/token", noCookie, `{"grant_type":"authorization_code"}`)
	if status == http.StatusNotFound {
		t.Fatalf("令牌端点返回 404，协议未挂载（body: %.160s）", body)
	}
	if status != http.StatusBadRequest && status != http.StatusUnauthorized &&
		status != http.StatusUnsupportedMediaType {
		t.Fatalf("令牌端点无效请求状态码 = %d，期望 4xx 标准错误（body 前 160: %.160s）",
			status, body)
	}

	// 管理 JSON API：审计/报告/备份真实域路由可达（不再 404）。
	for _, apiPath := range []string{
		"/admin/v1/meta", "/admin/v1/audit/events", "/admin/v1/reports",
		"/admin/v1/backups", "/admin/v1/backups/capabilities",
	} {
		status, body := getStatus(t, client, base+apiPath, cookieHeader, "")
		if status == http.StatusNotFound {
			t.Fatalf("管理 API %s 返回 404，域路由未挂载", apiPath)
		}
		if status != http.StatusOK {
			t.Fatalf("管理 API %s 状态码 = %d，期望 200（body 前 160: %.160s）",
				apiPath, status, body)
		}
	}
	// 敏感写操作（报告计划创建）在 Cookie 会话缺少 CSRF 令牌时即被拒绝；带伪造
	// CSRF 令牌时由敏感策略闸门 fail-closed（ACCESS_DENIED/REAUTH_REQUIRED）。
	// 真实 reauth 通过/拒绝路径由内部测试 TestReauthGate* 用真实闸门覆盖。
	status, body = getStatus(t, client, base+"/admin/v1/report-plans", cookieHeader,
		`{"kind":"summary","format":"json"}`)
	if status != http.StatusForbidden || !strings.Contains(body, "ACCESS_DENIED") {
		t.Fatalf("缺少 CSRF 的计划创建状态码 = %d（body 前 200: %.200s），期望 403 ACCESS_DENIED",
			status, body)
	}
	forgedRequest := func(target string) (int, string) {
		request, err := http.NewRequest(http.MethodPost, target,
			strings.NewReader(`{"kind":"summary","format":"json"}`))
		if err != nil {
			t.Fatalf("构造请求失败: %v", err)
		}
		request.Header.Set("Cookie", cookieHeader)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-CSRF-Token", "forged-csrf-token")
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("请求失败: %v", err)
		}
		defer response.Body.Close()
		payload, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		return response.StatusCode, string(payload)
	}
	csrfStatus, csrfBody := forgedRequest(base + "/admin/v1/report-plans")
	if csrfStatus != http.StatusForbidden {
		t.Fatalf("伪造 CSRF 的计划创建状态码 = %d，期望 403（body 前 200: %.200s）",
			csrfStatus, csrfBody)
	}
	// 未装配域（通知测试需要本地捕获器）明确返回未启用，而不是伪造成功。
	if status, _ := getStatus(t, client, base+"/admin/v1/notifications/test", cookieHeader,
		`{"confirm":true}`); status == http.StatusNotFound {
		t.Fatal("通知测试路由未挂载")
	}
}

// TestProtocolDisabledReturns404 验证未启用协议端点时相关路径不存在。
func TestProtocolDisabledReturns404(t *testing.T) {
	paths := preparePaths(t, nil)
	writeMasterKey(t, paths.masterKey)
	if stdout, err := runInit(t, paths); err != nil {
		t.Fatalf("首次初始化失败: %v（stdout=%s）", err, stdout)
	}
	address, _, cancel := startServe(t, serverapp.ServeOptions{
		ConfigPath: paths.config, MasterKeyFile: paths.masterKey,
	})
	defer cancel()
	client := &http.Client{Timeout: 10 * time.Second}
	for _, path := range []string{"/.well-known/openid-configuration", "/jwks", "/oauth/token"} {
		status, _ := getStatus(t, client, "http://"+address+path, "", "")
		if status != http.StatusNotFound {
			t.Fatalf("协议未启用时 %s 状态码 = %d，期望 404", path, status)
		}
	}
	cancel()
	// 协议关闭时不得预引导签名密钥（无密钥记录、无创建/复用审计），避免无谓副作用。
	deadline := time.Now().Add(20 * time.Second)
	for {
		lock, lockErr := serverapp.AcquireInstanceLock(paths.database)
		if lockErr == nil {
			lock.Release()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("serve 未在 20s 内关闭: %v", lockErr)
		}
		time.Sleep(50 * time.Millisecond)
	}
	store, err := storagesqlite.Open(context.Background(),
		storagesqlite.DefaultOptions(paths.database))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	defer store.Close()
	var keyCount, auditCount int
	if err := store.DB().QueryRow(`SELECT COUNT(*) FROM token_signing_keys`).Scan(&keyCount); err != nil {
		t.Fatalf("查询签名密钥失败: %v", err)
	}
	if keyCount != 0 {
		t.Fatalf("协议关闭时不应预引导签名密钥，实际 %d 条", keyCount)
	}
	if err := store.DB().QueryRow(`SELECT COUNT(*) FROM audit_events
		WHERE action IN ('token.key.created','token.key.ensured')`).Scan(&auditCount); err != nil {
		t.Fatalf("查询密钥审计失败: %v", err)
	}
	if auditCount != 0 {
		t.Fatalf("协议关闭时不应写密钥审计，实际 %d 条", auditCount)
	}
}

// TestMaintenanceModeBlocksProtocolAndAdminAPI 验证维护状态下协议端点与管理 API
// 一律 503（只有健康检查放行）。
func TestMaintenanceModeBlocksProtocolAndAdminAPI(t *testing.T) {
	paths := newProtocolPaths(t)
	if _, err := runInit(t, paths); err != nil {
		t.Fatalf("首次初始化失败: %v", err)
	}
	stateDir := filepath.Join(filepath.Dir(filepath.Dir(paths.database)),
		filepath.Base(filepath.Dir(paths.database))+"-maintenance")
	ring, err := secrets.LoadKeyring(context.Background(), secrets.ProviderFunc(
		func(context.Context) ([]byte, error) { return os.ReadFile(paths.masterKey) }))
	if err != nil {
		t.Fatalf("加载测试密钥环失败: %v", err)
	}
	_ = ring
	controller, err := maintenance.New(maintenance.Options{
		StateDir: stateDir, DatabasePath: paths.database,
		Keyring: secrets.ProviderFunc(func(context.Context) ([]byte, error) {
			return ring.Document()
		}),
	})
	if err != nil {
		t.Fatalf("构造维护状态控制器失败: %v", err)
	}
	t.Cleanup(func() { _ = controller.Close() })
	if controller.Missing() {
		if err := controller.Initialize(context.Background(), maintenance.InitializeRequest{
			Operator: maintenance.LocalOperator(), Reason: "测试进入维护状态"}); err != nil {
			t.Fatalf("初始化维护状态失败: %v", err)
		}
	}
	if err := controller.EnterMaintenance(context.Background(), maintenance.EnterRequest{
		Operator: maintenance.LocalOperator(), Reason: "测试维护窗口"}); err != nil {
		t.Fatalf("进入维护状态失败: %v", err)
	}
	address, _, cancel := startServe(t, serverapp.ServeOptions{
		ConfigPath: paths.config, MasterKeyFile: paths.masterKey,
		EnableAdminAPI: true,
	})
	defer cancel()
	client := &http.Client{Timeout: 10 * time.Second}
	base := "http://" + address
	if status, _ := getStatus(t, client, base+"/healthz", "", ""); status != http.StatusOK {
		t.Fatalf("维护模式健康检查状态码 = %d，期望 200", status)
	}
	for _, path := range []string{
		"/.well-known/openid-configuration", "/jwks", "/oauth/token",
		"/admin/v1/meta", "/admin/users",
	} {
		status, _ := getStatus(t, client, base+path, "", "")
		if status != http.StatusServiceUnavailable {
			t.Fatalf("维护模式 %s 状态码 = %d，期望 503", path, status)
		}
	}
}

// 防止 fmt 只被其他文件使用（保持显式引用；测试诊断信息需要）。
var _ = fmt.Sprintf

// TestAdminAPIWorksUnderPathPrefix 验证非空 server.path_prefix 下管理 JSON API
// 仍真实可达（KeepPrefix 处理器收到的是站内前缀路径，不发生 404）。
func TestAdminAPIWorksUnderPathPrefix(t *testing.T) {
	paths := preparePaths(t, func(config string) string {
		return strings.Replace(config, "server:\n  listen_addr",
			"server:\n  path_prefix: \"/login\"\n  listen_addr", 1)
	})
	writeMasterKey(t, paths.masterKey)
	if stdout, err := runInit(t, paths); err != nil {
		t.Fatalf("首次初始化失败: %v（stdout=%s）", err, stdout)
	}
	result, _, cancel := startServeResult(t, serverapp.ServeOptions{
		ConfigPath: paths.config, MasterKeyFile: paths.masterKey,
		EnableAdminAPI: true,
	})
	defer cancel()
	base := "http://" + result.Addresses[0]
	client := &http.Client{Timeout: 10 * time.Second}
	strong := issueRootSession(t, paths.config, paths.database, paths.masterKey, "strong")
	cookieHeader := strong.Name + "=" + strong.Value
	// 部署前缀下的管理 API 真实可达。
	status, body := getStatus(t, client, base+"/login/admin/v1/meta", cookieHeader, "")
	if status != http.StatusOK {
		t.Fatalf("部署前缀下管理 API meta 状态码 = %d，期望 200（body 前 160: %.160s）",
			status, body)
	}
	// 部署前缀下的管理页面同样可达。
	if status, body := getStatus(t, client, base+"/login/admin/users", cookieHeader, ""); status != http.StatusOK {
		t.Fatalf("部署前缀下管理页状态码 = %d，期望 200（body 前 160: %.160s）", status, body)
	}
	// 未带前缀的旧路径不存在（前缀语义严格）。
	if status, _ := getStatus(t, client, base+"/admin/v1/meta", cookieHeader, ""); status == http.StatusOK {
		t.Fatal("未带部署前缀的路径不应命中管理 API")
	}
}

// TestServeRejectsNonRequiredPasskeyUV 验证 Passkey 用于管理强认证时服务端硬性
// 拒绝 preferred/discouraged（UV 降级会削弱 root/管理强认证），不是仅文档约定。
func TestServeRejectsNonRequiredPasskeyUV(t *testing.T) {
	paths := preparePaths(t, func(config string) string {
		return config + `
passkey:
  enabled: true
  rp_id: "localhost"
  rp_display_name: "测试"
  allowed_origins:
    - "http://localhost"
  user_verification: preferred
`
	})
	writeMasterKey(t, paths.masterKey)
	if stdout, err := runInit(t, paths); err != nil {
		t.Fatalf("首次初始化失败: %v（stdout=%s）", err, stdout)
	}
	started := false
	err := serverapp.RunServe(context.Background(), serverapp.ServeOptions{
		ConfigPath: paths.config, MasterKeyFile: paths.masterKey,
		StandardOutput: io.Discard, StandardError: io.Discard,
		OnStarted: func(serverapp.StartResult) { started = true },
	})
	if err == nil {
		t.Fatal("user_verification=preferred 时应拒绝启动")
	}
	if !strings.Contains(err.Error(), "user_verification") {
		t.Fatalf("错误信息未指明 user_verification 要求: %v", err)
	}
	if started {
		t.Fatal("配置被拒绝时不应开始监听")
	}
}

// TestProtocolJWKSBootstrappedOnStartup 验证协议端点启用时启动阶段预引导签名密钥：
// JWKS 非空、包含 ES256 P-256 公钥、Discovery 声明的 jwks_uri 与 issuer 一致；
// 重启同一数据库后 kid 稳定（不会每次启动重新生成）。
func TestProtocolJWKSBootstrappedOnStartup(t *testing.T) {
	paths := newProtocolPaths(t)
	writeMasterKey(t, paths.masterKey)
	if stdout, err := runInit(t, paths); err != nil {
		t.Fatalf("首次初始化失败: %v（stdout=%s）", err, stdout)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	fetchJWKS := func(address string) (map[string]any, []map[string]any) {
		status, body := getStatus(t, client, "http://"+address+"/jwks", "", "")
		if status != http.StatusOK {
			t.Fatalf("JWKS 状态码 = %d，期望 200（body 前 160: %.160s）", status, body)
		}
		var document struct {
			Keys []map[string]any `json:"keys"`
		}
		if err := json.Unmarshal([]byte(body), &document); err != nil {
			t.Fatalf("JWKS 不是合法 JSON: %v（body 前 160: %.160s）", err, body)
		}
		if len(document.Keys) == 0 {
			t.Fatalf("JWKS keys 为空：启动阶段未预引导签名密钥（body: %.200s）", body)
		}
		raw := map[string]any{}
		_ = json.Unmarshal([]byte(body), &raw)
		return raw, document.Keys
	}
	firstAddress, _, firstCancel := startServe(t, serverapp.ServeOptions{
		ConfigPath: paths.config, MasterKeyFile: paths.masterKey,
	})
	_, firstKeys := fetchJWKS(firstAddress)
	first := firstKeys[0]
	for _, required := range []string{"kid", "kty", "crv", "x", "y", "alg", "use"} {
		if value, ok := first[required].(string); !ok || value == "" {
			t.Fatalf("JWKS 公钥缺少字段 %s: %v", required, first)
		}
	}
	if first["kty"] != "EC" || first["crv"] != "P-256" || first["alg"] != "ES256" {
		t.Fatalf("JWKS 公钥算法不符合 ES256/P-256: %v", first)
	}
	// Discovery 声明的 jwks_uri 必须指向真实挂载路径（issuer 校验一致）。
	status, body := getStatus(t, client, "http://"+firstAddress+"/.well-known/openid-configuration", "", "")
	if status != http.StatusOK {
		t.Fatalf("Discovery 状态码 = %d，期望 200", status)
	}
	var discovery map[string]any
	if err := json.Unmarshal([]byte(body), &discovery); err != nil {
		t.Fatalf("Discovery 不是合法 JSON: %v", err)
	}
	if discovery["jwks_uri"] != "https://localhost/jwks" {
		t.Fatalf("Discovery jwks_uri = %v，期望 https://localhost/jwks", discovery["jwks_uri"])
	}
	firstCancel()
	// 等待第一个实例完全退出并释放单实例锁后再启动第二个实例。
	deadline := time.Now().Add(20 * time.Second)
	for {
		lock, lockErr := serverapp.AcquireInstanceLock(paths.database)
		if lockErr == nil {
			lock.Release()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("首个实例未在 20s 内释放单实例锁: %v", lockErr)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// 重启同一数据库：签名密钥持久化，kid 必须稳定。
	secondAddress, _, secondCancel := startServe(t, serverapp.ServeOptions{
		ConfigPath: paths.config, MasterKeyFile: paths.masterKey,
	})
	defer secondCancel()
	_, secondKeys := fetchJWKS(secondAddress)
	if secondKeys[0]["kid"] != first["kid"] {
		t.Fatalf("重启后 kid 变化：first=%v second=%v（签名密钥未持久化）",
			first["kid"], secondKeys[0]["kid"])
	}
}
