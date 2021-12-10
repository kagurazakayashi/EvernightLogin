// 本文件实现在线管理命令（audit/reports/backups/notifications/tasks）的公共传输
// 层：全局参数、管理会话秘密文件读取、TLS、HTTP 客户端、adminapi envelope 解包、
// 原始字节流下载与错误/退出码映射。它是步骤 84 在线 CLI 域的唯一网络出口。
//
// 信任边界与安全约定：
//   - 管理会话秘密只从受保护文件读取（readProtectedSecret：绝对值、普通文件、
//     非符号链接、大小受限、secrets.CheckProtectedFile 平台权限检查），以
//     Authorization: Bearer 发送；它不进入命令行、环境变量明文、URL、日志、错误
//     或 --json 输出，进程内也不回显。
//   - 只调用运行中的 login-server 的管理 JSON API；未启动服务或未装配对应领域
//     服务时如实失败（连接失败/404/503），不本地伪造成功、不直连数据库。
//   - TLS 默认严格校验证书链与主机名；--ca-file 只追加可信 CA，绝不提供跳过
//     校验的开关。明文 http 只允许回环地址，远程管理必须经 https。
//   - 每个请求注入稳定的 X-Request-ID 与 User-Agent；请求编号只用于关联排障，
//     不参与授权。代理环境变量被显式忽略，避免把会话秘密交给环境代理。
//   - 下载端点（审计导出、报告/备份令牌兑换）返回原始字节流，不按 JSON 解析；
//     保存到 --out 指定路径：默认独占创建、不覆盖已有文件；--overwrite 先写同目录
//     临时文件，fsync 后原子 rename 覆盖（失败保留旧文件）；符号链接目标一律拒绝。
//   - 退出码映射见 exitForOnlineCode 与 online.go 顶部注释；REAUTH_REQUIRED 如实
//     提示需要重新完成强认证，绝不当作成功或降级为只读放行。
package managecli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"go.yaml.in/yaml/v3"
)

// 在线管理命令的默认值与硬上限。
const (
	// defaultOnlineAPIPath 是管理 JSON API 的默认挂载路径（adminapi.DefaultBasePath）。
	defaultOnlineAPIPath = "/admin/v1"
	// defaultOnlineServerPort 是未配置 server.listen_addr 时的默认端口。
	defaultOnlineServerPort = "8080"
	// defaultOnlineTimeout 是单个 JSON 请求的默认期限。
	defaultOnlineTimeout = 30 * time.Second
	// minOnlineTimeout/maxOnlineTimeout 是 --timeout 允许范围。
	minOnlineTimeout = time.Second
	maxOnlineTimeout = 5 * time.Minute
	// defaultOnlineDownloadTimeout 是原始字节流下载的整体上限（独立于 --timeout）。
	defaultOnlineDownloadTimeout = 10 * time.Minute
	// maxOnlineJSONBytes 是 JSON 响应体上限；maxOnlineErrorBytes 是错误响应上限。
	maxOnlineJSONBytes  = 8 << 20
	maxOnlineErrorBytes = 1 << 20
	// maxOnlineDownloadBytes 是单次下载落盘上限（防止误下超大文件占满磁盘）。
	maxOnlineDownloadBytes int64 = 2 << 30
	// maxOnlineCAFileBytes 是 --ca-file 文件大小上限。
	maxOnlineCAFileBytes = 4 << 20
)

// onlineFlagDefs 返回在线命令的公共参数定义（附加 extra 命令专属参数）。
func onlineFlagDefs(extra ...flagDef) []flagDef {
	defs := []flagDef{
		{name: "server", value: true}, {name: "api-path", value: true},
		{name: "config", value: true}, {name: "session-file", value: true},
		{name: "ca-file", value: true}, {name: "timeout", value: true},
		{name: "json"},
	}
	return append(defs, extra...)
}

// onlineTarget 是一次在线命令的已校验调用目标。它不输出秘密，也不被并发使用。
type onlineTarget struct {
	baseURL   string
	apiPath   string
	secret    string
	timeout   time.Duration
	client    *http.Client
	transport *http.Transport
	// stdout 用于 --out -（原始字节直接写标准输出）。
	stdout io.Writer
	// jsonOutput 表示 --json 模式：原始字节输出不能与 JSON 外壳混写。
	jsonOutput bool
}

// close 释放空闲连接；命令结束必须调用，避免测试或长脚本留下连接。
func (t *onlineTarget) close() {
	if t != nil && t.transport != nil {
		t.transport.CloseIdleConnections()
	}
}

// route 把相对路径拼成完整管理 API 地址。
func (t *onlineTarget) route(relative string) string {
	return strings.TrimRight(t.baseURL, "/") + t.apiPath + relative
}

// newRequestID 生成不可预测的请求编号（只用于关联排障，不是凭证）。
func (t *onlineTarget) newRequestID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("req_cli_%d", time.Now().UnixNano())
	}
	return "req_" + hex.EncodeToString(raw[:])
}

// apiEnvelope 是 adminapi 的统一响应外壳。
type apiEnvelope struct {
	OK        bool            `json:"ok"`
	RequestID string          `json:"request_id"`
	Data      json.RawMessage `json:"data"`
	Code      string          `json:"code"`
	Message   string          `json:"message"`
}

// onlineReply 是一次成功调用的结果：保留原始 data 字节（--json 原样转发）与解析后
// 的对象（人读输出与字段取值）。
type onlineReply struct {
	requestID string
	status    int
	raw       json.RawMessage
	data      map[string]any
}

// onlineError 是在线调用失败：稳定错误码、退出码与已脱敏的说明。
type onlineError struct {
	code      string
	exit      int
	message   string
	status    int
	requestID string
}

// Error 实现 error（只用于错误链与测试断言，不含秘密）。
func (e *onlineError) Error() string {
	if e == nil {
		return ""
	}
	return e.code + ": " + e.message
}

// exitForOnlineCode 把 adminapi/领域错误码映射为稳定退出码。
//
// 映射规则（与 README 步骤 84 章节一致）：
//   - AUTH_FAILED/TOKEN_*/CLIENT_AUTH_FAILED → 4 未认证；
//   - ACCESS_DENIED/PERMISSION_*/RESOURCE_FORBIDDEN/REPORT_ACCESS_DENIED/
//     BACKUP_CANCEL_FORBIDDEN/REAUTH_REQUIRED/MFA_REQUIRED/APP_*/USER_DISABLED → 5
//     无权限或受限会话（REAUTH_REQUIRED 另行附加“需重新认证”说明）；
//   - REQ_INVALID/PERMISSION_UNKNOWN/EXPORT_PATH_UNSAFE → 2 请求/用法错误；
//   - CONFLICT/TASK_CANCEL_CONFLICT/TASK_CANCELLED → 6 冲突，需要重新读取后重试；
//   - TASK_TIMEOUT → 7 等待超时（服务端任务可能仍在运行）；
//   - 其余（DB_UNAVAILABLE/AUTHZ_UNAVAILABLE/AUDIT_WRITE_FAILED/INTERNAL_ERROR/
//     BACKUP_INVALID/BACKUP_FAILED/REPORT_GENERATION_FAILED/MAIL_* 以及
//     NOTIFICATION_TEST_DISABLED/MAIL_DIAGNOSTICS_UNAVAILABLE）→ 1 执行失败，
//     保留服务端原始错误码，绝不伪成功。
func exitForOnlineCode(code string, status int) int {
	switch code {
	case "AUTH_FAILED", "TOKEN_INVALID", "TOKEN_EXPIRED", "TOKEN_REVOKED",
		"CLIENT_AUTH_FAILED", "REFRESH_REUSE_DETECTED":
		return ExitUnauthenticated
	case "ACCESS_DENIED", "PERMISSION_REQUIRED", "PERMISSION_DISABLED",
		"RESOURCE_FORBIDDEN", "REPORT_ACCESS_DENIED", "BACKUP_CANCEL_FORBIDDEN",
		"REAUTH_REQUIRED", "MFA_REQUIRED", "MFA_REBIND_REQUIRED",
		"APP_MEMBERSHIP_REQUIRED", "APP_SCOPE_MISMATCH", "USER_DISABLED":
		return ExitForbidden
	case "REQ_INVALID", "PERMISSION_UNKNOWN", "EXPORT_PATH_UNSAFE",
		"CHALLENGE_INVALID":
		return ExitUsage
	case "CONFLICT", "TASK_CANCEL_CONFLICT", "TASK_CANCELLED",
		"CLIENT_DISABLED", "BACKUP_VERSION_UNSUPPORTED":
		return ExitConflict
	case "TASK_TIMEOUT":
		return ExitTimeout
	case "AUTH_FAILED_EMPTY":
		// 仅占位，避免落入 default；实际不会出现该码。
		return ExitUnauthenticated
	default:
		// HTTP 状态兜底：未带 JSON 外壳时也要给出稳定类别。
		switch {
		case status == http.StatusUnauthorized:
			return ExitUnauthenticated
		case status == http.StatusForbidden:
			return ExitForbidden
		case status == http.StatusConflict:
			return ExitConflict
		case status == http.StatusGatewayTimeout:
			return ExitTimeout
		case status >= 400 && status < 500:
			return ExitUsage
		default:
			return ExitError
		}
	}
}

// withOnline 构造在线调用目标并在命令结束后释放连接；构造失败直接返回退出码。
func (r *runner) withOnline(values map[string]string,
	action func(*onlineTarget) int) int {
	target, exit := r.onlineTarget(values)
	if exit != ExitOK {
		return exit
	}
	defer target.close()
	return action(target)
}

// onlineTarget 校验并构造在线调用目标：会话秘密文件、服务地址、API 路径、CA 与
// 超时。任何一项不合法都在发请求前返回明确用法/认证错误。
func (r *runner) onlineTarget(values map[string]string) (*onlineTarget, int) {
	r.json = boolFlag(values, "json")
	sessionFile := stringFlag(values, "session-file")
	if sessionFile == "" {
		return nil, r.usage("在线管理命令必须提供 --session-file（管理会话秘密的受保护文件）")
	}
	secret, err := readProtectedSecret(sessionFile, "管理会话秘密文件")
	if err != nil {
		return nil, r.fail("SESSION_FILE_INVALID", ExitUnauthenticated,
			"管理会话秘密文件无效："+err.Error(), nil)
	}
	server := stringFlag(values, "server")
	if server == "" {
		defaultServer, exit := r.defaultOnlineServer(values)
		if exit != ExitOK {
			return nil, exit
		}
		server = defaultServer
	}
	baseURL, err := normalizeOnlineServer(server)
	if err != nil {
		return nil, r.usage("--server 无效：%v", err)
	}
	apiPath, err := normalizeOnlineAPIPath(stringFlag(values, "api-path"))
	if err != nil {
		return nil, r.usage("--api-path 无效：%v", err)
	}
	timeout, err := parseOnlineTimeout(stringFlag(values, "timeout"))
	if err != nil {
		return nil, r.usage("%v", err)
	}
	tlsConfig, err := onlineTLSConfig(stringFlag(values, "ca-file"))
	if err != nil {
		return nil, r.fail("CA_FILE_INVALID", ExitError, err.Error(), nil)
	}
	dialTimeout := timeout
	if dialTimeout > 10*time.Second {
		dialTimeout = 10 * time.Second
	}
	transport := &http.Transport{
		// 显式忽略环境代理：管理会话秘密不应交给 HTTP(S)_PROXY 指定的第三方。
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: time.Second,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
	}
	return &onlineTarget{
		baseURL: baseURL, apiPath: apiPath, secret: secret, timeout: timeout,
		// 客户端整体超时覆盖下载；JSON 请求另有更短的 context 期限。
		client:     &http.Client{Transport: transport, Timeout: defaultOnlineDownloadTimeout},
		transport:  transport,
		stdout:     r.stdout,
		jsonOutput: r.json,
	}, ExitOK
}

// defaultOnlineServer 生成默认服务地址：http://127.0.0.1:<配置端口或 8080>。
// 端口只从 --config 的 server.listen_addr 读取；该文件读取失败如实报错，不静默
// 回退到其它配置。
func (r *runner) defaultOnlineServer(values map[string]string) (string, int) {
	port := defaultOnlineServerPort
	if file := stringFlag(values, "config"); file != "" {
		listenAddr, err := readConfigListenAddr(file)
		if err != nil {
			return "", r.fail("CONFIG_FILE_INVALID", ExitError,
				"读取 --config 的 server.listen_addr 失败："+err.Error(), nil)
		}
		if parsed := portFromListenAddr(listenAddr); parsed != "" {
			port = parsed
		}
	}
	return "http://127.0.0.1:" + port, ExitOK
}

// readConfigListenAddr 只读取 YAML 配置里的 server.listen_addr，不做完整配置校验
// （完整校验由 config 命令负责；在线命令只关心连接端口）。
func readConfigListenAddr(file string) (string, error) {
	absolute, err := filepath.Abs(strings.TrimSpace(file))
	if err != nil {
		return "", fmt.Errorf("路径无效")
	}
	info, err := os.Stat(absolute)
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("文件不存在或不是普通文件")
	}
	if info.Size() > maxConfigFileBytes {
		return "", fmt.Errorf("文件超过 1 MiB 上限")
	}
	data, err := os.ReadFile(absolute)
	if err != nil {
		return "", fmt.Errorf("无法读取文件")
	}
	var document struct {
		Server struct {
			ListenAddr string `yaml:"listen_addr"`
		} `yaml:"server"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		return "", fmt.Errorf("不是合法 YAML")
	}
	return strings.TrimSpace(document.Server.ListenAddr), nil
}

// portFromListenAddr 从 host:port 中取端口；非法或缺失返回空串。
func portFromListenAddr(listenAddr string) string {
	listenAddr = strings.TrimSpace(listenAddr)
	if listenAddr == "" {
		return ""
	}
	_, port, err := net.SplitHostPort(listenAddr)
	if err != nil || port == "" {
		return ""
	}
	if _, err := net.LookupPort("tcp", port); err != nil {
		return ""
	}
	return port
}

// normalizeOnlineServer 校验并规范化服务基础地址：只允许 http/https、禁止
// 用户信息/查询/片段；明文 http 只允许回环主机（远程必须 https）。
func normalizeOnlineServer(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("不是合法 URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("只支持 http/https")
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("缺少主机名")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("不允许在地址中携带用户信息")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("不允许查询参数或片段")
	}
	host := parsed.Hostname()
	if parsed.Scheme == "http" {
		if !isLoopbackHost(host) {
			return "", fmt.Errorf("非回环地址的管理 API 必须使用 https（避免明文传输会话秘密）")
		}
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	if strings.Contains(parsed.Path, "..") || strings.Contains(parsed.Path, "\\") {
		return "", fmt.Errorf("路径包含非法片段")
	}
	return parsed.String(), nil
}

// isLoopbackHost 判断主机是否是本机回环地址。
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// normalizeOnlineAPIPath 校验管理 API 挂载路径（可与服务路径前缀组合）。
func normalizeOnlineAPIPath(raw string) (string, error) {
	path := strings.TrimSpace(raw)
	if path == "" {
		path = defaultOnlineAPIPath
	}
	if !strings.HasPrefix(path, "/") || path == "/" || strings.HasSuffix(path, "/") {
		return "", fmt.Errorf("必须是以单个斜杠开头的固定路径，且不能以斜杠结尾")
	}
	if strings.Contains(path, "//") || strings.ContainsAny(path, "\\%?#") {
		return "", fmt.Errorf("包含不允许的字符或空段")
	}
	for _, segment := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", fmt.Errorf("包含空段或点段")
		}
	}
	return path, nil
}

// parseOnlineTimeout 解析 --timeout（默认 30s，范围 1s～5m）。
func parseOnlineTimeout(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultOnlineTimeout, nil
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("--timeout 必须是时长（例如 30s）")
	}
	if parsed < minOnlineTimeout || parsed > maxOnlineTimeout {
		return 0, fmt.Errorf("--timeout 必须在 %s～%s 之间", minOnlineTimeout, maxOnlineTimeout)
	}
	return parsed, nil
}

// onlineTLSConfig 构造严格校验的 TLS 配置；--ca-file 只追加可信 CA。
func onlineTLSConfig(caFile string) (*tls.Config, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	caFile = strings.TrimSpace(caFile)
	if caFile == "" {
		return config, nil
	}
	absolute, err := filepath.Abs(caFile)
	if err != nil {
		return nil, fmt.Errorf("--ca-file 路径无效")
	}
	info, err := os.Stat(absolute)
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("--ca-file 不存在或不是普通文件")
	}
	if info.Size() <= 0 || info.Size() > maxOnlineCAFileBytes {
		return nil, fmt.Errorf("--ca-file 大小不合法（必须非空且不超过 %d 字节）", maxOnlineCAFileBytes)
	}
	data, err := os.ReadFile(absolute)
	if err != nil {
		return nil, fmt.Errorf("--ca-file 无法读取")
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("--ca-file 不含可解析的 PEM 证书")
	}
	config.RootCAs = pool
	return config, nil
}

// onlineUserAgent 返回带版本号的稳定 User-Agent（不包含主机名/秘密）。
func onlineUserAgent() string {
	version := strings.TrimSpace(login.CurrentBuildInfo().Version)
	if version == "" {
		version = "dev"
	}
	return "loginctl-managecli/" + version
}

// doJSON 调用管理 JSON API 并解包统一 envelope。返回的成功响应保留原始 data
// 字节；失败响应映射为 onlineError。它从不把原始错误文本、路径或秘密写入错误。
func (t *onlineTarget) doJSON(ctx context.Context, method, relative string,
	query url.Values, body any) (*onlineReply, *onlineError) {
	requestID := t.newRequestID()
	endpoint := t.route(relative)
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, &onlineError{code: "INTERNAL_ERROR", exit: ExitError,
				message: "请求体序列化失败"}
		}
		payload = bytes.NewReader(encoded)
	}
	callCtx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(callCtx, method, endpoint, payload)
	if err != nil {
		return nil, &onlineError{code: "REQ_INVALID", exit: ExitUsage,
			message: "无法构造管理 API 请求"}
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("User-Agent", onlineUserAgent())
	request.Header.Set("X-Request-ID", requestID)
	request.Header.Set("Authorization", "Bearer "+t.secret)
	if len(query) > 0 {
		request.URL.RawQuery = query.Encode()
	}
	response, err := t.client.Do(request)
	if err != nil {
		return nil, t.transportError(err)
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maxOnlineJSONBytes+1))
	if readErr != nil {
		return nil, &onlineError{code: "NETWORK_READ_FAILED", exit: ExitError,
			message: "读取管理 API 响应失败"}
	}
	if int64(len(raw)) > maxOnlineJSONBytes {
		return nil, &onlineError{code: "SERVER_RESPONSE_TOO_LARGE", exit: ExitError,
			message: "管理 API 响应超过 CLI 上限"}
	}
	var envelope apiEnvelope
	decodeErr := json.Unmarshal(raw, &envelope)
	if decodeErr != nil {
		return nil, &onlineError{code: "SERVER_RESPONSE_INVALID", exit: ExitError,
			message:   fmt.Sprintf("管理 API 响应不是合法 JSON（HTTP %d）", response.StatusCode),
			status:    response.StatusCode,
			requestID: firstNonEmptyHeader(response, "X-Request-ID", requestID)}
	}
	if !envelope.OK {
		code := strings.TrimSpace(envelope.Code)
		if code == "" {
			code = fallbackCodeForStatus(response.StatusCode)
		}
		message := strings.TrimSpace(envelope.Message)
		if message == "" {
			message = "管理 API 拒绝了请求（未提供说明）"
		}
		return nil, &onlineError{code: code,
			exit:      exitForOnlineCode(code, response.StatusCode),
			message:   message,
			status:    response.StatusCode,
			requestID: firstNonEmpty(envelope.RequestID, firstNonEmptyHeader(response, "X-Request-ID", requestID))}
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, &onlineError{code: "SERVER_RESPONSE_INVALID", exit: ExitError,
			message:   fmt.Sprintf("管理 API 返回 HTTP %d 但缺少成功标记", response.StatusCode),
			status:    response.StatusCode,
			requestID: firstNonEmpty(envelope.RequestID, requestID)}
	}
	reply := &onlineReply{requestID: firstNonEmpty(envelope.RequestID, requestID),
		status: response.StatusCode, raw: envelope.Data}
	if len(envelope.Data) > 0 {
		var data map[string]any
		if err := json.Unmarshal(envelope.Data, &data); err == nil {
			reply.data = data
		}
	}
	return reply, nil
}

// downloadInfo 是原始字节流下载结果（不含会话秘密）。
type downloadInfo struct {
	Path        string `json:"path,omitempty"`
	FileName    string `json:"file_name"`
	Bytes       int64  `json:"bytes"`
	SHA256      string `json:"sha256"`
	ContentType string `json:"content_type,omitempty"`
	RequestID   string `json:"request_id,omitempty"`
}

// download 调用原始字节流端点（审计导出、报告/备份令牌兑换），按 --out 保存。
// 非 200 响应按统一 envelope 解析为错误；成功响应不按 JSON 解析。
func (t *onlineTarget) download(ctx context.Context, method, relative string,
	query url.Values, body any, outPath string, overwrite bool) (*downloadInfo, *onlineError) {
	requestID := t.newRequestID()
	endpoint := t.route(relative)
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, &onlineError{code: "INTERNAL_ERROR", exit: ExitError,
				message: "请求体序列化失败"}
		}
		payload = bytes.NewReader(encoded)
	}
	callCtx, cancel := context.WithTimeout(ctx, defaultOnlineDownloadTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(callCtx, method, endpoint, payload)
	if err != nil {
		return nil, &onlineError{code: "REQ_INVALID", exit: ExitUsage,
			message: "无法构造管理 API 下载请求"}
	}
	request.Header.Set("Accept", "*/*")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("User-Agent", onlineUserAgent())
	request.Header.Set("X-Request-ID", requestID)
	request.Header.Set("Authorization", "Bearer "+t.secret)
	if len(query) > 0 {
		request.URL.RawQuery = query.Encode()
	}
	response, err := t.client.Do(request)
	if err != nil {
		return nil, t.transportError(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(response.Body, maxOnlineErrorBytes))
		var envelope apiEnvelope
		if json.Unmarshal(raw, &envelope) == nil && !envelope.OK &&
			strings.TrimSpace(envelope.Code) != "" {
			message := strings.TrimSpace(envelope.Message)
			if message == "" {
				message = "管理 API 拒绝了下载请求（未提供说明）"
			}
			return nil, &onlineError{code: envelope.Code,
				exit:      exitForOnlineCode(envelope.Code, response.StatusCode),
				message:   message,
				status:    response.StatusCode,
				requestID: firstNonEmpty(envelope.RequestID, requestID)}
		}
		return nil, &onlineError{code: "SERVER_HTTP_ERROR", exit: ExitError,
			message:   fmt.Sprintf("管理 API 下载返回 HTTP %d", response.StatusCode),
			status:    response.StatusCode,
			requestID: firstNonEmptyHeader(response, "X-Request-ID", requestID)}
	}
	fileName := safeDownloadName(dispositionFileName(response.Header.Get("Content-Disposition")),
		"download-"+shortRequestID(requestID)+".bin")
	info := &downloadInfo{FileName: fileName,
		ContentType: response.Header.Get("Content-Type"),
		RequestID:   firstNonEmptyHeader(response, "X-Request-ID", requestID)}
	if err := t.saveStream(response.Body, outPath, fileName, overwrite, info); err != nil {
		var failure *onlineError
		if errors.As(err, &failure) {
			return nil, failure
		}
		return nil, &onlineError{code: "OUTPUT_WRITE_FAILED", exit: ExitError,
			message: "保存下载内容失败：" + err.Error()}
	}
	return info, nil
}

// transportError 把网络/传输错误映射为稳定错误码与退出码，不泄露内部细节。
func (t *onlineTarget) transportError(err error) *onlineError {
	if errors.Is(err, context.Canceled) {
		return &onlineError{code: "INTERRUPTED", exit: ExitInterrupted,
			message: "命令被中断，操作结果未知"}
	}
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) ||
		(errors.As(err, &netErr) && netErr.Timeout()) ||
		errors.Is(err, os.ErrDeadlineExceeded) {
		return &onlineError{code: "NETWORK_TIMEOUT", exit: ExitTimeout,
			message: "连接管理 API 超时，未确认服务端是否已执行该操作"}
	}
	var certificateInvalid x509.CertificateInvalidError
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameError x509.HostnameError
	var recordHeader tls.RecordHeaderError
	if errors.As(err, &certificateInvalid) || errors.As(err, &unknownAuthority) ||
		errors.As(err, &hostnameError) || errors.As(err, &recordHeader) {
		return &onlineError{code: "TLS_VERIFY_FAILED", exit: ExitError,
			message: "管理 API TLS 证书校验失败（不会跳过证书校验；如为私有 CA 请用 --ca-file 提供）"}
	}
	return &onlineError{code: "NETWORK_UNREACHABLE", exit: ExitError,
		message: "无法连接管理 API（请确认 login-server 已启动且地址/端口正确）"}
}

// saveStream 把字节流保存到目标路径（--out）。空路径时使用安全文件名写入当前
// 目录；"-" 表示直接写 stdout（原始字节，不混入 JSON 外壳）。
//
// 写入安全语义：
//   - 默认不覆盖已有文件：O_CREATE|O_EXCL 独占创建；目标已存在（含符号链接）直接
//     失败，不会截断或跟随。
//   - --overwrite：先写同目录临时文件（0600），fsync 后原子 rename 覆盖目标；失败
//     时旧目标保持不变并被如实报告，不会出现半截内容或先截断再失败。
//   - 目标为符号链接、目录或无法 stat 的类型一律拒绝（不跟随符号链接，避免把受控
//     下载写到链接指向的其他位置）。
//   - 下载失败只删除本次创建的临时/独占文件，绝不删除调用前已存在的目标文件。
func (t *onlineTarget) saveStream(source io.Reader, outPath, fileName string,
	overwrite bool, info *downloadInfo) error {
	toStdout := strings.TrimSpace(outPath) == "-"
	if toStdout && t.jsonOutput {
		return &onlineError{code: "USAGE_INVALID", exit: ExitUsage,
			message: "--out -（原始字节写标准输出）不能与 --json 同时使用"}
	}
	var writer io.Writer
	var file *os.File
	// tempPath 是 --overwrite 的临时文件；exclusivePath 是默认模式的独占新文件；
	// 两者都不指向调用前已存在的目标，失败时只清理它们。
	var tempPath, exclusivePath, finalPath string
	if toStdout {
		writer = t.stdoutForDownload()
	} else {
		path := strings.TrimSpace(outPath)
		if path == "" {
			path = fileName
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			return &onlineError{code: "OUTPUT_FILE_INVALID", exit: ExitUsage,
				message: "--out 路径无效"}
		}
		existing, statErr := os.Lstat(absolute)
		if statErr == nil {
			if existing.Mode()&os.ModeSymlink != 0 {
				return &onlineError{code: "OUTPUT_FILE_INVALID", exit: ExitUsage,
					message: "--out 不能是符号链接（不会跟随链接写入其他位置）"}
			}
			if existing.IsDir() {
				return &onlineError{code: "OUTPUT_FILE_INVALID", exit: ExitUsage,
					message: "--out 指向目录，必须给出文件名"}
			}
			if !overwrite {
				return &onlineError{code: "OUTPUT_FILE_EXISTS", exit: ExitUsage,
					message: "输出文件已存在；如确需覆盖请显式加 --overwrite"}
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return &onlineError{code: "OUTPUT_FILE_INVALID", exit: ExitUsage,
				message: "--out 状态无法读取"}
		}
		finalPath = absolute
		if overwrite {
			temp, createErr := os.CreateTemp(filepath.Dir(absolute),
				".loginctl-download-*")
			if createErr != nil {
				return &onlineError{code: "OUTPUT_WRITE_FAILED", exit: ExitError,
					message: "无法创建输出临时文件（目录不存在或无写权限）"}
			}
			tempPath = temp.Name()
			if chmodErr := temp.Chmod(0o600); chmodErr != nil {
				_ = temp.Close()
				_ = os.Remove(tempPath)
				return &onlineError{code: "OUTPUT_WRITE_FAILED", exit: ExitError,
					message: "无法设置输出临时文件权限"}
			}
			file = temp
			writer = temp
		} else {
			handle, openErr := os.OpenFile(absolute,
				os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
			if openErr != nil {
				return &onlineError{code: "OUTPUT_WRITE_FAILED", exit: ExitError,
					message: "无法创建输出文件（目录不存在或无写权限）"}
			}
			exclusivePath = absolute
			file = handle
			writer = handle
		}
		info.Path = absolute
	}
	digest := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(writer, digest),
		io.LimitReader(source, maxOnlineDownloadBytes+1))
	if copyErr == nil && written > maxOnlineDownloadBytes {
		copyErr = &onlineError{code: "DOWNLOAD_TOO_LARGE", exit: ExitError,
			message: fmt.Sprintf("下载内容超过 CLI 上限 %d 字节", maxOnlineDownloadBytes)}
	}
	if file != nil {
		syncErr := file.Sync()
		closeErr := file.Close()
		if copyErr == nil {
			copyErr = syncErr
		}
		if copyErr == nil {
			copyErr = closeErr
		}
	}
	if copyErr != nil {
		// 失败清理：只删除本次创建的临时/独占文件；调用前已存在的目标保持不变。
		if tempPath != "" {
			_ = os.Remove(tempPath)
		}
		if exclusivePath != "" {
			_ = os.Remove(exclusivePath)
			info.Path = ""
		}
		var failure *onlineError
		if errors.As(copyErr, &failure) {
			return failure
		}
		return &onlineError{code: "DOWNLOAD_FAILED", exit: ExitError,
			message: "下载过程中断，已删除未完成内容（调用前已存在的目标文件保持不变）"}
	}
	if tempPath != "" {
		// 同目录原子替换：成功后旧文件才被替换；失败保留旧文件并删除临时文件。
		if renameErr := os.Rename(tempPath, finalPath); renameErr != nil {
			_ = os.Remove(tempPath)
			info.Path = ""
			return &onlineError{code: "OUTPUT_WRITE_FAILED", exit: ExitError,
				message: "无法原子替换输出文件（旧文件保持不变）"}
		}
	}
	info.Bytes = written
	info.SHA256 = hex.EncodeToString(digest.Sum(nil))
	return nil
}

// stdoutForDownload 返回下载输出；由 runner 注入（"--out -" 直接写原始字节）。
func (t *onlineTarget) stdoutForDownload() io.Writer {
	if t == nil || t.stdout == nil {
		return io.Discard
	}
	return t.stdout
}

// dispositionFileName 从 Content-Disposition 提取文件名（不含路径）。
func dispositionFileName(header string) string {
	if strings.TrimSpace(header) == "" {
		return ""
	}
	if _, params, err := mime.ParseMediaType(header); err == nil {
		return strings.TrimSpace(params["filename"])
	}
	return ""
}

// safeDownloadName 把服务端建议的文件名限制为安全 basename。
func safeDownloadName(raw, fallback string) string {
	base := filepath.Base(strings.ReplaceAll(strings.TrimSpace(raw), "\\", "/"))
	var builder strings.Builder
	for _, character := range base {
		switch {
		case character >= 'a' && character <= 'z',
			character >= 'A' && character <= 'Z',
			character >= '0' && character <= '9',
			character == '.', character == '-', character == '_':
			builder.WriteRune(character)
		}
		if builder.Len() >= 120 {
			break
		}
	}
	name := builder.String()
	if name == "" || name == "." || name == ".." {
		return fallback
	}
	return name
}

// shortRequestID 返回请求编号的短后缀，用于默认文件名。
func shortRequestID(requestID string) string {
	trimmed := strings.TrimPrefix(requestID, "req_")
	if len(trimmed) > 12 {
		trimmed = trimmed[:12]
	}
	if trimmed == "" {
		return "unknown"
	}
	return trimmed
}

// fallbackCodeForStatus 在响应缺少稳定错误码时按 HTTP 状态给出兜底码。
func fallbackCodeForStatus(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return "AUTH_FAILED"
	case http.StatusForbidden:
		return "ACCESS_DENIED"
	case http.StatusNotFound, http.StatusBadRequest, http.StatusMethodNotAllowed,
		http.StatusRequestEntityTooLarge:
		return "REQ_INVALID"
	case http.StatusConflict:
		return "CONFLICT"
	case http.StatusGatewayTimeout:
		return "TASK_TIMEOUT"
	default:
		return "INTERNAL_ERROR"
	}
}

// firstNonEmpty 返回第一个非空字符串。
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// firstNonEmptyHeader 返回响应头值或兜底值。
func firstNonEmptyHeader(response *http.Response, header, fallback string) string {
	if response != nil {
		if value := strings.TrimSpace(response.Header.Get(header)); value != "" {
			return value
		}
	}
	return fallback
}

// onlineFailure 输出在线调用失败并返回稳定退出码。REAUTH_REQUIRED 额外提示需要
// 重新完成强认证；绝不把受限会话当作成功或只读放行。
func (r *runner) onlineFailure(operation string, failure *onlineError) int {
	if failure == nil {
		failure = &onlineError{code: "INTERNAL_ERROR", exit: ExitError,
			message: "未知的管理 API 错误"}
	}
	message := operation + "失败：" + failure.message
	if failure.code == "REAUTH_REQUIRED" {
		message += "；管理 API 要求重新完成强认证（例如 Passkey/MFA）：请重新登录并生成新的" +
			"管理会话秘密文件后重试，本次操作未执行"
	}
	var details map[string]any
	if failure.status != 0 || failure.requestID != "" {
		details = map[string]any{}
		if failure.status != 0 {
			details["http_status"] = failure.status
		}
		if failure.requestID != "" {
			details["request_id"] = failure.requestID
		}
	}
	return r.fail(failure.code, failure.exit, message, details)
}

// succeedOnline 输出在线成功结果：--json 原样转发 adminapi 的 data 并附 request_id；
// 人读模式输出摘要（完整字段用 --json）。text 非空时使用命令自定义摘要。
func (r *runner) succeedOnline(reply *onlineReply, text func(io.Writer)) int {
	if reply == nil {
		return r.fail("INTERNAL_ERROR", ExitError, "管理 API 未返回结果", nil)
	}
	if r.json {
		r.writeEnvelope(jsonEnvelope{OK: true, Command: r.command,
			RequestID: reply.requestID, Data: reply.raw})
		return ExitOK
	}
	if text != nil {
		text(r.stdout)
		return ExitOK
	}
	if len(reply.data) == 0 {
		fmt.Fprintln(r.stdout, "操作成功（服务端未返回额外数据）。")
		return ExitOK
	}
	printOnlineData(r.stdout, reply.data)
	return ExitOK
}

// succeedDownload 输出原始字节流下载结果：--json 输出结构化元数据，人读模式输出
// 保存路径/大小/摘要；--out - 时字节已写入 stdout，提示只写 stderr 以免污染流。
func (r *runner) succeedDownload(info *downloadInfo, label string) int {
	if info == nil {
		return r.fail("INTERNAL_ERROR", ExitError, "下载未返回结果", nil)
	}
	if info.Path == "" {
		fmt.Fprintf(r.stderr, "%s已写入标准输出（%d 字节；sha256=%s）\n", label,
			info.Bytes, info.SHA256)
		return ExitOK
	}
	if r.json {
		encoded, err := json.Marshal(info)
		if err != nil {
			return r.fail("INTERNAL_ERROR", ExitError, "结果序列化失败", nil)
		}
		r.writeEnvelope(jsonEnvelope{OK: true, Command: r.command,
			RequestID: info.RequestID, Data: json.RawMessage(encoded)})
		return ExitOK
	}
	fmt.Fprintf(r.stdout, "%s已保存：%s\n", label, info.Path)
	fmt.Fprintf(r.stdout, "  大小：%d 字节；sha256：%s；服务端请求编号：%s\n",
		info.Bytes, info.SHA256, firstNonEmpty(info.RequestID, "-"))
	return ExitOK
}

// urlPathEscape 对路径参数做安全转义，避免把 /、? 等注入到路由路径。
func urlPathEscape(value string) string {
	return url.PathEscape(strings.TrimSpace(value))
}

// printOnlineData 输出人读摘要：顶层键按字典序；列表给出条数与每项关键字段。
func printOnlineData(out io.Writer, data map[string]any) {
	keys := make([]string, 0, len(data))
	for key := range data {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		switch value := data[key].(type) {
		case nil:
			fmt.Fprintf(out, "%s: -\n", key)
		case []any:
			fmt.Fprintf(out, "%s: %d 项\n", key, len(value))
			for _, item := range value {
				if object, ok := item.(map[string]any); ok {
					printOnlineItem(out, "  ", object)
					continue
				}
				fmt.Fprintf(out, "  - %v\n", item)
			}
		case map[string]any:
			fmt.Fprintf(out, "%s:\n", key)
			printOnlineItem(out, "  ", value)
		default:
			fmt.Fprintf(out, "%s: %v\n", key, value)
		}
	}
}

// printOnlineItem 输出单个对象摘要：优先展示稳定编号，再展示最多 8 个标量字段。
func printOnlineItem(out io.Writer, indent string, object map[string]any) {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, 8)
	for _, key := range keys {
		if len(parts) >= 8 {
			break
		}
		switch value := object[key].(type) {
		case string:
			if value == "" {
				continue
			}
			parts = append(parts, key+"="+value)
		case float64, bool, int64:
			parts = append(parts, fmt.Sprintf("%s=%v", key, value))
		}
	}
	if len(parts) == 0 {
		fmt.Fprintf(out, "%s（无可展示字段）\n", indent)
		return
	}
	fmt.Fprintf(out, "%s%s\n", indent, strings.Join(parts, "  "))
}

// onlineDataObject 读取 data 中的对象字段；缺失或类型不符返回 nil。
func onlineDataObject(reply *onlineReply, key string) map[string]any {
	if reply == nil || reply.data == nil {
		return nil
	}
	object, _ := reply.data[key].(map[string]any)
	return object
}

// onlineDataList 读取 data 中的数组字段。
func onlineDataList(reply *onlineReply, key string) []any {
	if reply == nil || reply.data == nil {
		return nil
	}
	list, _ := reply.data[key].([]any)
	return list
}

// onlineDataBool 读取 data 中的布尔字段。
func onlineDataBool(reply *onlineReply, key string) bool {
	if reply == nil || reply.data == nil {
		return false
	}
	value, _ := reply.data[key].(bool)
	return value
}

// objectList 读取对象里的数组字段。
func objectList(object map[string]any, key string) []any {
	if object == nil {
		return nil
	}
	list, _ := object[key].([]any)
	return list
}

// objectString 读取对象里的字符串字段。
func objectString(object map[string]any, key string) string {
	if object == nil {
		return ""
	}
	value, _ := object[key].(string)
	return value
}

// objectInt64 读取对象里的数值字段（JSON 数字统一为 float64）。
func objectInt64(object map[string]any, key string) int64 {
	if object == nil {
		return 0
	}
	switch value := object[key].(type) {
	case float64:
		return int64(value)
	case int64:
		return value
	case int:
		return int64(value)
	default:
		return 0
	}
}

// queryValues 构造查询参数：只加入非空值。
func queryValues() url.Values { return url.Values{} }

// setQuery 在字符串参数存在时写入查询。
func setQuery(values map[string]string, query url.Values, flag, key string) {
	if value := stringFlag(values, flag); value != "" {
		query.Set(key, value)
	}
}

// setQueryBool 在布尔参数存在时写入 true/false。
func setQueryBool(values map[string]string, query url.Values, flag, key string) {
	if boolFlag(values, flag) {
		query.Set(key, "true")
	}
}

// addPageQuery 写入受控分页参数（limit 1～100，offset ≥0）。
func addPageQuery(values map[string]string, query url.Values) error {
	limit, err := parseIntFlag(values, "limit", 20)
	if err != nil {
		return err
	}
	if limit < 1 || limit > 100 {
		return fmt.Errorf("--limit 必须在 1～100 之间")
	}
	offset, err := parseIntFlag(values, "offset", 0)
	if err != nil {
		return err
	}
	if offset < 0 || offset > 1_000_000 {
		return fmt.Errorf("--offset 必须在 0～1000000 之间")
	}
	query.Set("limit", fmt.Sprintf("%d", limit))
	query.Set("offset", fmt.Sprintf("%d", offset))
	return nil
}

// requiredFlag 读取必填字符串参数；缺失返回用法错误。
func (r *runner) requiredFlag(values map[string]string, name, label string) (string, int) {
	value := stringFlag(values, name)
	if value == "" {
		return "", r.usage("%s 必填（--%s）", label, name)
	}
	return value, ExitOK
}

// requireConfirmWord 校验显式确认词；确认不是授权，服务端仍重新判定权限与策略。
func (r *runner) requireConfirmWord(values map[string]string, want string) int {
	if stringFlag(values, "confirm") != want {
		return r.usage("该写操作必须显式确认：--confirm %s（确认不是授权，服务端仍会复核权限与强认证）", want)
	}
	return ExitOK
}

// onlineScopeID 返回作用范围标识（默认 system）。
func onlineScopeID(values map[string]string) string {
	if scope := stringFlag(values, "scope-id"); scope != "" {
		return scope
	}
	return "system"
}
