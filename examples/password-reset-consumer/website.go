// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package main

// 本文件把公开 app 包装配的嵌入式 HTTP 处理器挂到**宿主自己的** http.Server 上，
// 并用真实页面表单完成注册与邮箱验证（步骤 183 的嵌入挂载契约）：
//   - 只有公开包 `app.Runtime.Handler()`/`Mount`；不导入 internal；
//   - 页面表单带会话绑定的 CSRF 隐藏字段与同源 Origin，缺少/跨源都会被服务端拒绝；
//   - 只使用临时回环端口，不监听非回环地址，不访问外网。

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// hostWebsite 是宿主自己的 HTTP 站点（承载嵌入式页面处理器）。
type hostWebsite struct {
	prefix   string
	baseURL  string
	origin   string
	listener net.Listener
	server   *http.Server
	done     chan error
	client   *http.Client
}

// startHostWebsiteOn 在调用方已绑定的回环监听器上启动宿主站点；调用方需要先用
// 该监听器的真实端口生成 public_base_url（邮件链接），因此先绑定后启动。
//
// 站点使用临时自签名证书提供 **HTTPS**：嵌入式账户页的会话 Cookie 使用
// `__Host-` 前缀（Secure/Path=/ 且无 Domain），明文 HTTP 下浏览器不会回送，登录
// 后页面无法使用。外部回归不降低 Cookie 安全属性，而是用真实 TLS 承载本地站点。
func startHostWebsiteOn(handler http.Handler, prefix string, listener net.Listener) (*hostWebsite, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	certificate, rootPool, err := selfSignedCertificate()
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: rootPool, MinVersion: tls.VersionTLS12}}
	client := &http.Client{
		Jar: jar, Timeout: 15 * time.Second, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	host := listener.Addr().String()
	tlsListener := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	website := &hostWebsite{
		prefix: prefix, origin: "https://" + host,
		baseURL:  "https://" + host + prefix,
		listener: listener, done: make(chan error, 1), client: client,
		server: &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second},
	}
	go func() { website.done <- website.server.Serve(tlsListener) }()
	return website, nil
}

// selfSignedCertificate 生成仅用于本地回环测试的临时证书与信任池。
func selfSignedCertificate() (tls.Certificate, *x509.CertPool, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("生成临时 TLS 私钥失败: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true, BasicConstraintsValid: true,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:    []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("签发临时 TLS 证书失败: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("编码临时 TLS 私钥失败: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("装载临时 TLS 证书失败: %w", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("解析临时 TLS 证书失败: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return certificate, pool, nil
}

// close 有界关闭宿主站点并等待监听退出。
func (w *hostWebsite) close() error {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := w.server.Shutdown(shutdownCtx)
	select {
	case <-w.done:
	case <-time.After(5 * time.Second):
		if err == nil {
			err = fmt.Errorf("宿主 HTTP 站点未在关闭期限内退出")
		}
	}
	return err
}

// get 发起 GET 并返回状态码与响应体（最多 1 MiB）。
func (w *hostWebsite) get(target string) (int, string, error) {
	response, err := w.client.Get(target)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return 0, "", err
	}
	return response.StatusCode, string(body), nil
}

// sitePage 打开站内页面（target 为以 "/" 开头的站内路径）。
func (w *hostWebsite) sitePage(pagePath string) (int, string, error) {
	return w.get(w.baseURL + pagePath)
}

// csrfToken 打开站内页面并提取 CSRF 隐藏字段（Cookie 已保存在 client 中）。
func (w *hostWebsite) csrfToken(pagePath string) (string, error) {
	status, body, err := w.sitePage(pagePath)
	if err != nil {
		return "", fmt.Errorf("打开页面 %s 失败: %w", pagePath, err)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("页面 %s 状态码 = %d", pagePath, status)
	}
	match := csrfFieldPattern.FindStringSubmatch(body)
	if len(match) != 2 {
		return "", fmt.Errorf("页面 %s 未找到 CSRF 隐藏字段", pagePath)
	}
	return match[1], nil
}

// postSiteForm 以同源 Origin 提交站内表单（含 CSRF token）。
func (w *hostWebsite) postSiteForm(pagePath string, form url.Values) (int, string, error) {
	request, err := http.NewRequest(http.MethodPost, w.baseURL+pagePath,
		strings.NewReader(form.Encode()))
	if err != nil {
		return 0, "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Origin 只含 scheme+host（无路径）；与 public_base_url 的站点来源一致。
	request.Header.Set("Origin", w.origin)
	response, err := w.client.Do(request)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return 0, "", err
	}
	return response.StatusCode, string(body), nil
}

var (
	csrfFieldPattern    = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)
	hiddenInputPattern  = regexp.MustCompile(`<input[^>]*name="(uid|cid|token|csrf_token)"[^>]*value="([^"]*)"[^>]*>`)
	anyHiddenFieldRegex = regexp.MustCompile(`name="([^"]+)"\s+value="([^"]*)"`)
)

// hiddenFields 解析页面中的隐藏字段（name→value）。用于邮箱验证页的 uid/cid/token。
func hiddenFields(body string) map[string]string {
	fields := map[string]string{}
	for _, match := range hiddenInputPattern.FindAllStringSubmatch(body, -1) {
		fields[match[1]] = match[2]
	}
	// 兜底：某些模板属性顺序不同，按通配提取后再取白名单键。
	for _, match := range anyHiddenFieldRegex.FindAllStringSubmatch(body, -1) {
		if _, exists := fields[match[1]]; exists {
			continue
		}
		switch match[1] {
		case "uid", "cid", "token", "csrf_token":
			fields[match[1]] = match[2]
		}
	}
	return fields
}

// allHiddenFields 解析页面中的全部隐藏字段（name→value），用于第二因素挑战与
// 邮箱变更验证页的 challenge_id/attempt_token/rid/cid/token 等一次性状态。
func allHiddenFields(body string) map[string]string {
	fields := map[string]string{}
	for _, match := range anyHiddenFieldRegex.FindAllStringSubmatch(body, -1) {
		if _, exists := fields[match[1]]; exists {
			continue
		}
		fields[match[1]] = match[2]
	}
	return fields
}

// setSessionCookie 把公开 Go 门面签发的完整会话秘密注入站点 Cookie jar，供后续
// 真实账户页请求使用。会话仍由公开认证门面真实签发（密码 + TOTP 第二步），
// 这里不伪造会话、不绕过第二因素，只是让同一个合成浏览器持有该会话。
func (w *hostWebsite) setSessionCookie(sessionSecret []byte) error {
	if len(sessionSecret) == 0 {
		return fmt.Errorf("会话秘密为空，不能注入站点 Cookie")
	}
	base, err := url.Parse(w.baseURL)
	if err != nil {
		return fmt.Errorf("解析站点基址失败: %w", err)
	}
	w.client.Jar.SetCookies(base, []*http.Cookie{{
		Name: "__Host-login_session", Value: string(sessionSecret),
		Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	}})
	return nil
}

// loginViaPages 通过公开登录页完成“密码 + TOTP 第二步”登录，返回时 Cookie jar
// 中已有完整会话。只使用真实页面与表单，不伪造会话或跳过第二因素。
func (w *hostWebsite) loginViaPages(username, password, totpSecret string) error {
	csrf, err := w.csrfToken("/login")
	if err != nil {
		return err
	}
	status, body, err := w.postSiteForm("/login", url.Values{
		"csrf_token": {csrf}, "identifier": {username}, "password": {password}})
	if err != nil {
		return fmt.Errorf("提交登录页失败: %w", err)
	}
	if status != http.StatusSeeOther && status != http.StatusFound {
		return fmt.Errorf("登录页状态 = %d（期望跳转第二因素，body=%s）", status,
			truncateText(body, 300))
	}
	status, body, err = w.sitePage("/login/second-factor")
	if err != nil {
		return fmt.Errorf("打开第二因素页失败: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("第二因素页状态 = %d", status)
	}
	fields := allHiddenFields(body)
	if fields["challenge_id"] == "" || fields["attempt_token"] == "" ||
		fields["csrf_token"] == "" {
		return fmt.Errorf("第二因素页缺少 challenge_id/attempt_token/csrf_token")
	}
	code, err := totpCodeNextStep(totpSecret)
	if err != nil {
		return fmt.Errorf("计算 TOTP 失败: %w", err)
	}
	status, body, err = w.postSiteForm("/login/second-factor", url.Values{
		"csrf_token": {fields["csrf_token"]}, "challenge_id": {fields["challenge_id"]},
		"attempt_token": {fields["attempt_token"]}, "code": {code}})
	if err != nil {
		return fmt.Errorf("提交第二因素失败: %w", err)
	}
	if status >= http.StatusBadRequest {
		return fmt.Errorf("第二因素验证状态 = %d（body=%s）", status,
			truncateText(body, 300))
	}
	// 以受保护页面确认会话真实生效（不是仅凭重定向推断成功）。
	status, body, err = w.sitePage("/account/profile")
	if err != nil {
		return fmt.Errorf("打开账户页失败: %w", err)
	}
	if status != http.StatusOK {
		parsedOrigin, _ := url.Parse(w.origin)
		_ = parsedOrigin
		details := make([]string, 0, 4)
		for _, cookie := range w.client.Jar.Cookies(parsedOrigin) {
			details = append(details, fmt.Sprintf("%s(len=%d,secure=%t,path=%s)",
				cookie.Name, len(cookie.Value), cookie.Secure, cookie.Path))
		}
		return fmt.Errorf("账户页状态 = %d；cookies=%v；body=%s", status, details,
			truncateText(body, 800))
	}
	return nil
}

// changePasswordViaPages 通过账户改密页修改密码（当前密码用于真实复核）。
func (w *hostWebsite) changePasswordViaPages(currentPassword, newPassword string) error {
	csrf, err := w.csrfToken("/account/password")
	if err != nil {
		return err
	}
	status, body, err := w.postSiteForm("/account/password", url.Values{
		"csrf_token": {csrf}, "current_password": {currentPassword},
		"new_password": {newPassword}, "password_confirm": {newPassword}})
	if err != nil {
		return fmt.Errorf("提交改密页失败: %w", err)
	}
	if status >= http.StatusBadRequest {
		return fmt.Errorf("改密页状态 = %d（body=%s）", status, truncateText(body, 300))
	}
	return nil
}

// requestEmailChangeViaPages 通过账户邮箱页申请切换到新邮箱（需当前密码复核）。
func (w *hostWebsite) requestEmailChangeViaPages(currentPassword, newEmail string) error {
	csrf, err := w.csrfToken("/account/profile/email")
	if err != nil {
		return err
	}
	status, body, err := w.postSiteForm("/account/profile/email", url.Values{
		"csrf_token": {csrf}, "new_email": {newEmail},
		"current_password": {currentPassword}})
	if err != nil {
		return fmt.Errorf("提交邮箱变更页失败: %w", err)
	}
	if status >= http.StatusBadRequest {
		return fmt.Errorf("邮箱变更申请状态 = %d（body=%s）", status,
			truncateText(body, 300))
	}
	return nil
}

// confirmEmailChangeViaLink 打开新邮箱验证链接并提交确认（公开页，GET 不消费）。
func (w *hostWebsite) confirmEmailChangeViaLink(link string) error {
	status, body, err := w.get(link)
	if err != nil {
		return fmt.Errorf("打开新邮箱验证页失败: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("新邮箱验证页状态 = %d", status)
	}
	fields := allHiddenFields(body)
	if fields["rid"] == "" || fields["cid"] == "" || fields["token"] == "" ||
		fields["csrf_token"] == "" {
		return fmt.Errorf("新邮箱验证页缺少 rid/cid/token/csrf_token")
	}
	status, body, err = w.postSiteForm("/email/change/verify", url.Values{
		"csrf_token": {fields["csrf_token"]}, "rid": {fields["rid"]},
		"cid": {fields["cid"]}, "token": {fields["token"]}})
	if err != nil {
		return fmt.Errorf("提交新邮箱验证失败: %w", err)
	}
	if status != http.StatusOK || !strings.Contains(body, "新邮箱已验证") {
		return fmt.Errorf("新邮箱验证未成功: status=%d body=%s", status,
			truncateText(body, 400))
	}
	return nil
}

// cookieNames 返回当前站点 Cookie 名称（仅诊断用，不打印值）。
func (w *hostWebsite) cookieNames() []string {
	parsed, err := url.Parse(w.origin)
	if err != nil {
		return nil
	}
	cookies := w.client.Jar.Cookies(parsed)
	names := make([]string, 0, len(cookies))
	for _, cookie := range cookies {
		names = append(names, cookie.Name)
	}
	return names
}
