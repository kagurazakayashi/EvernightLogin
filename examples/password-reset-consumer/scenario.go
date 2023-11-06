// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package main

// 本文件实现步骤 211 的外部消费回归场景：只使用公开 app 包与真实本地 Mail，
// 覆盖注册/邮箱验证/登录/TOTP 绑定/找回申请/预检查/改密/重登/旧会话失效/MFA 保留，
// 以及防枚举、配置拒绝和审计诊断分离。

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/app"
)

const (
	// sitePrefix 是嵌入式 HTTP 的站内路径前缀；与 server.path_prefix 保持一致。
	sitePrefix = "/idp"
	// strongPassword 是满足默认密码策略的合成强密码。
	strongPassword = "K8$wR3!nB6@yF1#v"
	// weakPassword 是被密码策略拒绝的合成弱密码。
	weakPassword = "short"
	// mailWaitTimeout 是等待邮件投递的一封信件的有界期限。
	mailWaitTimeout = 45 * time.Second
)

// scenario 是一次外部消费回归的运行上下文。
type scenario struct {
	ctx      context.Context
	opts     scenarioOptions
	mail     *mailbox
	report   *scenarioReport
	runtimes []*testRuntime

	username        string
	email           string
	userID          string
	oldSession      []byte
	totpSecret      string
	currentPassword string
	newEmail        string
}

// testRuntime 是一个公开 app.Runtime + 宿主 HTTP 站点。
type testRuntime struct {
	runtime *app.Runtime
	website *hostWebsite
	dir     string
	dbPath  string
}

// runScenario 执行全部场景并返回结构化报告。
func runScenario(ctx context.Context, opts scenarioOptions) *scenarioReport {
	startedAt := time.Now()
	report := &scenarioReport{
		Schema:       "evernight.password-reset-consumer/v1",
		Status:       "FAIL",
		StartedAtUTC: startedAt.UTC().Format(time.RFC3339),
		GoVersion:    runtime.Version(),
		Platform:     runtime.GOOS + "/" + runtime.GOARCH,
		LogicalCPUs:  runtime.NumCPU(),
		Checks:       make([]checkResult, 0, 32),
	}
	run := &scenario{ctx: ctx, opts: opts, report: report,
		username: "externalreset", email: "externalreset@example.test"}
	defer run.cleanup()
	report.DurationMs = 0

	// 1) 真实 EvernightMail 子进程（本地收信，不访问公网）。
	if mailboxInstance, err := startMailbox(opts.MailBin, opts.WorkRoot); err != nil {
		run.fail("mail.start", fmt.Errorf("启动真实 EvernightMail 失败: %w", err))
		return run.finalize(startedAt)
	} else {
		run.mail = mailboxInstance
		run.pass("mail.start", "真实 EvernightMail 子进程已就绪（回环 SMTP/HTTP，临时数据目录）")
	}

	// 2) 主运行时：临时 SQLite + 真实邮件运行时 + 嵌入式 HTTP 页面。
	primary, err := run.openRuntime("primary", nil)
	if err != nil {
		run.fail("runtime.open_primary", fmt.Errorf("打开主测试运行时失败: %w", err))
		return run.finalize(startedAt)
	}
	run.runtimePass("runtime.open_primary", primary,
		"app.Open+Start 使用公开包完成临时 SQLite/邮件/页面装配")

	// 3) 公开页面注册 + 邮箱验证。
	run.checkRegistration(primary)
	// 4) 公开 Go 门面登录 + TOTP 绑定。
	run.checkSessionAndMFA(primary)
	// 5) 公开找回门面全链路（204/205/206 行为）。
	run.checkPasswordResetFlow(primary)
	// 6) 账户安全变更（206）：改密/邮箱切换后旧找回链接失效（真实页面流程）。
	run.checkAccountSecurityChanges(primary)
	// 7) 拒绝/配置/防枚举路径。
	run.checkNegativePaths(primary)
	// 8) 208：每来源限流与请求编号贯穿。
	run.checkRateLimitAndRequestID(primary)
	// 9) 管理诊断分离（只读审计行）。
	run.checkAuditDiagnostics(primary)

	return run.finalize(startedAt)
}

// baseConfig 构造外部宿主使用的公开配置（临时数据库 + 真实本地邮件 + 嵌入页面）。
func (s *scenario) baseConfig(dir, siteBaseURL string) login.Config {
	config := login.Default()
	config.Database.Path = filepath.Join(dir, "data", "login.db")
	config.Logging.Level = login.LogLevelError
	config.Logging.Format = login.LogFormatText
	config.Server.PublicBaseURL = siteBaseURL
	config.Server.PathPrefix = sitePrefix
	config.Registration.Enabled = true
	config.Registration.RequireReview = false
	config.Registration.RequireEmailVerification = true
	config.Mail = login.MailConfig{
		Enabled: true,
		// 本地回环明文投递：步骤 212 已修复“回环地址 + allow_plaintext_local”的
		// 配置校验；真实 EvernightMail 夹具因此可以走最简单、无证书变量的本地路径。
		SMTP: login.MailSMTPConfig{
			Addr:                s.mail.SMTPAddr,
			Host:                "mailtest.local",
			TLSMode:             "none",
			AllowPlaintextLocal: true,
			TimeoutSeconds:      10,
		},
		From:    login.MailFromConfig{Address: "no-reply@example.test", Name: "EvernightLogin 外部回归"},
		AppName: "EvernightLogin 外部回归",
		Delivery: login.MailDeliveryConfig{
			MaxAttempts:    2,
			TimeoutSeconds: 60,
		},
	}
	return config
}

// openRuntime 用公开 app.Options 打开并启动一个测试运行时；mutate 可修改配置变体。
func (s *scenario) openRuntime(name string, mutate func(*login.Config)) (*testRuntime, error) {
	dir := filepath.Join(s.opts.WorkRoot, name)
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o750); err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("监听宿主回环端口失败: %w", err)
	}
	siteBaseURL := "https://" + listener.Addr().String() + sitePrefix
	config := s.baseConfig(dir, siteBaseURL)
	if mutate != nil {
		mutate(&config)
	}
	if err := config.Validate(); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("测试配置未通过公开配置校验: %w", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	if s.opts.Verbose {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	runtimeInstance, err := app.Open(s.ctx, app.Options{
		Config:          &config,
		ConfigPath:      filepath.Join(dir, "login.yaml"),
		DatabasePath:    config.Database.Path,
		MasterKeyFile:   filepath.Join(dir, "master.key"),
		CreateMasterKey: true,
		Migrate:         true,
		OperatorID:      "password-reset-consumer",
		Logger:          logger,
		HTTP:            &app.HTTPOptions{Prefix: sitePrefix},
	})
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	if err := runtimeInstance.Start(s.ctx); err != nil {
		_ = runtimeInstance.Close(context.Background())
		_ = listener.Close()
		return nil, fmt.Errorf("启动测试运行时失败: %w", err)
	}
	website, err := startHostWebsiteOn(runtimeInstance.Handler(), sitePrefix, listener)
	if err != nil {
		_ = runtimeInstance.Close(context.Background())
		_ = listener.Close()
		return nil, err
	}
	instance := &testRuntime{runtime: runtimeInstance, website: website,
		dir: dir, dbPath: config.Database.Path}
	s.runtimes = append(s.runtimes, instance)
	return instance, nil
}

// cleanup 逆序关闭全部运行时与 Mail 子进程（不遗留端口/进程/临时数据）。
func (s *scenario) cleanup() {
	for index := len(s.runtimes) - 1; index >= 0; index-- {
		instance := s.runtimes[index]
		if instance.website != nil {
			_ = instance.website.close()
		}
		if instance.runtime != nil {
			closeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			_ = instance.runtime.Close(closeCtx)
			cancel()
		}
	}
	if s.mail != nil {
		_ = s.mail.Close()
	}
}

// ---- 检查注册 + 邮箱验证 ----

func (s *scenario) checkRegistration(instance *testRuntime) {
	if err := s.registerViaPages(instance); err != nil {
		s.fail("register.pages", err)
		return
	}
	s.pass("register.pages", "通过公开注册页面提交合成账户（CSRF+同源 Origin），收到验证邮件")
	if err := s.verifyEmailViaMail(instance); err != nil {
		s.fail("email.verify_via_mail", err)
		return
	}
	s.pass("email.verify_via_mail", "从真实 Mail 提取验证链接并提交验证页，账户邮箱已验证")
}

// registerViaPages 通过公开注册页表单创建合成账户。
func (s *scenario) registerViaPages(instance *testRuntime) error {
	token, err := instance.website.csrfToken("/register")
	if err != nil {
		return err
	}
	form := url.Values{
		"username":         {s.username},
		"password":         {strongPassword},
		"password_confirm": {strongPassword},
		"nickname":         {"外部消费用户"},
		"email":            {s.email},
		"csrf_token":       {token},
	}
	status, body, err := instance.website.postSiteForm("/register", form)
	if err != nil {
		return fmt.Errorf("提交注册表单失败: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("注册表单状态 = %d（body=%s）", status, truncateText(body, 400))
	}
	if !strings.Contains(body, "注册提交结果") && !strings.Contains(body, "验证邮件") {
		return fmt.Errorf("注册结果页缺少预期结果标识（body=%s）", truncateText(body, 400))
	}
	return nil
}

// verifyEmailViaMail 从 Mail 已提交邮件提取验证链接并完成公开验证页提交。
func (s *scenario) verifyEmailViaMail(instance *testRuntime) error {
	messages, err := s.mail.waitForMessages(s.ctx, mailWaitTimeout, func(message mailMessage) bool {
		if !containsAddressFold(message.To, s.email) {
			return false
		}
		_, found := findLink([]mailMessage{message}, "/email/verify")
		return found
	})
	if err != nil {
		return fmt.Errorf("等待验证邮件: %w", err)
	}
	link, found := findLink(messages, "/email/verify")
	if !found {
		return fmt.Errorf("验证邮件中未找到邮箱验证链接")
	}
	status, body, err := instance.website.get(link)
	if err != nil {
		return fmt.Errorf("打开邮箱验证页面失败: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("邮箱验证页状态 = %d（链接路径=%s，响应=%s）", status,
			parsedLinkPath(link), truncateText(body, 300))
	}
	fields := hiddenFields(body)
	if fields["uid"] == "" || fields["cid"] == "" || fields["token"] == "" {
		return fmt.Errorf("邮箱验证页缺少 uid/cid/token 隐藏字段")
	}
	// CSRF 必须取自带 uid/cid/token 的验证页本身；无查询串重新打开会 400。
	csrf := fields["csrf_token"]
	if csrf == "" {
		return fmt.Errorf("邮箱验证页缺少 CSRF 隐藏字段")
	}
	form := url.Values{
		"uid": {fields["uid"]}, "cid": {fields["cid"]},
		"token": {fields["token"]}, "csrf_token": {csrf},
	}
	status, body, err = instance.website.postSiteForm("/email/verify", form)
	if err != nil {
		return fmt.Errorf("提交邮箱验证表单失败: %w", err)
	}
	if status != http.StatusOK || !strings.Contains(body, "邮箱已验证") {
		return fmt.Errorf("邮箱验证未成功: status=%d body=%s", status, truncateText(body, 400))
	}
	return nil
}

// ---- 登录 + TOTP 绑定（MFA 保留的前置） ----

func (s *scenario) checkSessionAndMFA(instance *testRuntime) {
	loginResult, err := instance.runtime.Auth().Login(s.ctx, app.LoginRequest{
		Username: s.username, Password: strongPassword, ClientIP: "127.0.0.1",
		UserAgent: "password-reset-consumer", RequestID: login.NewRequestID(),
	})
	if err != nil || loginResult.Restricted || len(loginResult.SessionSecret) == 0 {
		s.fail("login.before_reset", fmt.Errorf("改密前密码登录失败: %v（restricted=%t）",
			err, loginResult.Restricted))
		return
	}
	s.oldSession = loginResult.SessionSecret
	s.userID = loginResult.UserID
	s.pass("login.before_reset", "改密前新密码登录得到完整会话（未绑定 MFA）")

	start, err := instance.runtime.Security().BeginTOTPBinding(s.ctx, app.TOTPBindingBeginRequest{
		SessionSecret: s.oldSession, Password: strongPassword, RequestID: login.NewRequestID(),
	})
	if err != nil {
		s.fail("mfa.bind_totp", fmt.Errorf("公开门面绑定 TOTP 失败: %w", err))
		return
	}
	code, err := totpCode(start.Secret, time.Now())
	if err != nil {
		s.fail("mfa.bind_totp", err)
		return
	}
	if _, err := instance.runtime.Security().ConfirmTOTPBinding(s.ctx, app.TOTPBindingConfirmRequest{
		SessionSecret: s.oldSession, BindingID: start.BindingID, Code: code,
		RequestID: login.NewRequestID(),
	}); err != nil {
		s.fail("mfa.bind_totp", fmt.Errorf("确认 TOTP 绑定失败: %w", err))
		return
	}
	s.totpSecret = start.Secret
	status, err := instance.runtime.Security().Status(s.ctx, app.SecurityStatusRequest{
		SessionSecret: s.oldSession, RequestID: login.NewRequestID(),
	})
	if err != nil || !status.TOTPActive {
		s.fail("mfa.bind_totp", fmt.Errorf("TOTP 绑定后状态异常: %+v err=%v", status, err))
		return
	}
	s.pass("mfa.bind_totp", "通过公开 Go 门面绑定并确认 TOTP，Security.Status 显示 TOTPActive")
}

// ---- 公开找回门面全链路 ----

func (s *scenario) checkPasswordResetFlow(instance *testRuntime) {
	// 申请找回：公开入口对可用账户返回 nil（不泄露处理细节）。
	if err := instance.runtime.PasswordReset().Request(s.ctx, app.RequestPasswordResetRequest{
		Identifier: s.email, ClientIP: "127.0.0.1", RequestID: login.NewRequestID(),
	}); err != nil {
		s.fail("reset.request", fmt.Errorf("公开门面发起找回失败: %w", err))
		return
	}
	s.pass("reset.request", "公开门面发起找回返回成功外形（邮件异步投递）")

	messages, err := s.mail.waitForMessages(s.ctx, mailWaitTimeout, func(message mailMessage) bool {
		if !containsAddressFold(message.To, s.email) {
			return false
		}
		_, found := findLink([]mailMessage{message}, "/login/reset-password")
		return found
	})
	if err != nil {
		s.fail("reset.mail_link", fmt.Errorf("等待找回邮件: %w", err))
		return
	}
	link, found := findLink(messages, "/login/reset-password")
	if !found {
		s.fail("reset.mail_link", fmt.Errorf("找回邮件中未找到重置链接"))
		return
	}
	parsed, err := url.Parse(link)
	if err != nil {
		s.fail("reset.mail_link", fmt.Errorf("解析找回链接失败: %w", err))
		return
	}
	token := parsed.Query().Get("token")
	if token == "" {
		s.fail("reset.mail_link", fmt.Errorf("找回链接缺少一次性 token"))
		return
	}
	s.pass("reset.mail_link", "从真实本地 Mail 提取一次性找回链接（链接基址=public_base_url+path_prefix）")

	// 预检查：连续两次成功且不消费（204/公开门面）。
	if err := instance.runtime.PasswordReset().ValidateTokenWithSource(s.ctx,
		app.ValidatePasswordResetTokenRequest{Token: token, ClientIP: "127.0.0.1",
			RequestID: login.NewRequestID()}); err != nil {
		s.fail("reset.precheck_no_consume", fmt.Errorf("第一次预检查失败: %w", err))
		return
	}
	if err := instance.runtime.PasswordReset().ValidateTokenWithSource(s.ctx,
		app.ValidatePasswordResetTokenRequest{Token: token, ClientIP: "127.0.0.1",
			RequestID: login.NewRequestID()}); err != nil {
		s.fail("reset.precheck_no_consume", fmt.Errorf("第二次预检查失败（预检查不得消费 token）: %w", err))
		return
	}
	s.pass("reset.precheck_no_consume", "公开预检查连续两次通过且未消费 token")

	// 205：弱密码失败不得烧掉仍有效的找回入口。
	if _, weakErr := instance.runtime.PasswordReset().Complete(s.ctx, app.CompletePasswordResetRequest{
		Token: token, NewPassword: weakPassword, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID(),
	}); weakErr == nil {
		s.fail("reset.weak_password_rejected", fmt.Errorf("弱密码被错误接受"))
		return
	}
	if err := instance.runtime.PasswordReset().ValidateTokenWithSource(s.ctx,
		app.ValidatePasswordResetTokenRequest{Token: token, ClientIP: "127.0.0.1",
			RequestID: login.NewRequestID()}); err != nil {
		s.fail("reset.weak_password_does_not_burn", fmt.Errorf("弱密码失败后 token 被烧掉: %w", err))
		return
	}
	s.pass("reset.weak_password_does_not_burn", "弱密码被拒绝且同一链接仍可用于预检查（不永久烧入口）")

	newPassword := "T4!wZ8@pL2#cN6$q"
	result, err := instance.runtime.PasswordReset().Complete(s.ctx, app.CompletePasswordResetRequest{
		Token: token, NewPassword: newPassword, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		s.fail("reset.complete", fmt.Errorf("强密码完成找回失败: %w", err))
		return
	}
	if result.UserID != s.userID || result.SessionsRevoked < 1 || !result.RequiresRelogin {
		s.fail("reset.complete", fmt.Errorf("完成结果异常: %+v（期望同用户、撤销旧会话、需重登）", result))
		return
	}
	s.currentPassword = newPassword
	s.pass("reset.complete", "强密码完成找回成功，旧会话被撤销且要求重新登录")

	// 一次性：旧 token 不得再次完成/预检查。
	if _, reuseErr := instance.runtime.PasswordReset().Complete(s.ctx, app.CompletePasswordResetRequest{
		Token: token, NewPassword: newPassword, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID(),
	}); reuseErr == nil {
		s.fail("reset.token_single_use", fmt.Errorf("已消费 token 仍可完成改密"))
		return
	}
	if err := instance.runtime.PasswordReset().ValidateTokenWithSource(s.ctx,
		app.ValidatePasswordResetTokenRequest{Token: token, ClientIP: "127.0.0.1",
			RequestID: login.NewRequestID()}); err == nil {
		s.fail("reset.token_single_use", fmt.Errorf("已消费 token 仍通过预检查"))
		return
	}
	s.pass("reset.token_single_use", "已消费 token 的完成与预检查均被拒绝（单次使用）")

	// 旧会话立即失效（不能复活）。
	if _, err := instance.runtime.Sessions().Validate(s.ctx, s.oldSession); err == nil {
		s.fail("reset.old_session_invalid", fmt.Errorf("改密后旧会话仍然有效"))
		return
	}
	s.pass("reset.old_session_invalid", "改密后旧会话校验被拒绝（旧凭据不复活）")

	// 旧密码不得再登录。
	if _, err := instance.runtime.Auth().Login(s.ctx, app.LoginRequest{
		Username: s.username, Password: strongPassword, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID(),
	}); err == nil {
		s.fail("reset.old_password_rejected", fmt.Errorf("改密后旧密码仍可登录"))
		return
	}
	s.pass("reset.old_password_rejected", "改密后旧密码登录被拒绝")

	// MFA 保留：新密码登录仍需 TOTP 第二步，完成后完整会话且 TOTPActive。
	restricted, err := instance.runtime.Auth().Login(s.ctx, app.LoginRequest{
		Username: s.username, Password: newPassword, ClientIP: "127.0.0.1",
		UserAgent: "password-reset-consumer", RequestID: login.NewRequestID(),
	})
	if err != nil || !restricted.Restricted || restricted.SecondFactor == nil ||
		restricted.SecondFactor.FactorType != "totp" {
		s.fail("reset.mfa_preserved", fmt.Errorf("改密后新密码登录未要求 TOTP: %+v err=%v",
			restricted, err))
		return
	}
	verifyCode, err := totpCodeNextStep(s.totpSecret)
	if err != nil {
		s.fail("reset.mfa_preserved", err)
		return
	}
	verified, err := instance.runtime.Auth().VerifySecondFactor(s.ctx, app.VerifySecondFactorRequest{
		SessionSecret: restricted.SessionSecret,
		ChallengeID:   restricted.SecondFactor.ChallengeID,
		AttemptToken:  restricted.SecondFactor.AttemptToken,
		Code:          verifyCode, RequestID: login.NewRequestID(),
	})
	if err != nil || len(verified.SessionSecret) == 0 {
		s.fail("reset.mfa_preserved", fmt.Errorf("TOTP 第二步失败: %v", err))
		return
	}
	status, err := instance.runtime.Security().Status(s.ctx, app.SecurityStatusRequest{
		SessionSecret: verified.SessionSecret, RequestID: login.NewRequestID(),
	})
	if err != nil || !status.TOTPActive {
		s.fail("reset.mfa_preserved", fmt.Errorf("改密后 TOTP 状态异常: %+v err=%v", status, err))
		return
	}
	s.pass("reset.mfa_preserved", "改密后新密码+原 TOTP 重新登录成功，MFA 未被清除")
}

// ---- 206：账户安全变更（改密/邮箱切换）后的旧找回链接失效 ----

// requestResetToken 申请一枚新的找回链接并等待其邮件，返回一次性 token。
func (s *scenario) requestResetToken(instance *testRuntime) (string, error) {
	before, _ := s.mail.messages()
	seen := map[string]bool{}
	for _, message := range before {
		seen[message.ID] = true
	}
	if err := instance.runtime.PasswordReset().Request(s.ctx,
		app.RequestPasswordResetRequest{Identifier: s.email, ClientIP: "127.0.0.1",
			RequestID: login.NewRequestID()}); err != nil {
		return "", fmt.Errorf("发起找回失败: %w", err)
	}
	messages, err := s.mail.waitForMessages(s.ctx, mailWaitTimeout, func(message mailMessage) bool {
		if seen[message.ID] || !containsAddressFold(message.To, s.email) {
			return false
		}
		_, found := findLink([]mailMessage{message}, "/login/reset-password")
		return found
	})
	if err != nil {
		return "", fmt.Errorf("等待新的找回邮件失败: %w", err)
	}
	for _, message := range messages {
		for _, link := range mailMessageLinks(message) {
			if !strings.Contains(link, "/login/reset-password") {
				continue
			}
			parsed, parseErr := url.Parse(link)
			if parseErr != nil {
				continue
			}
			if token := parsed.Query().Get("token"); token != "" {
				return token, nil
			}
		}
	}
	return "", fmt.Errorf("新的找回邮件缺少 token")
}

// loginFullSession 用公开 Go 门面完成“密码 + TOTP 第二步”登录并返回完整会话秘密。
func (s *scenario) loginFullSession(instance *testRuntime, password string) ([]byte, error) {
	loginResult, err := instance.runtime.Auth().Login(s.ctx, app.LoginRequest{
		Username: s.username, Password: password, ClientIP: "127.0.0.1",
		UserAgent: "password-reset-consumer", RequestID: login.NewRequestID(),
	})
	if err != nil || !loginResult.Restricted || loginResult.SecondFactor == nil {
		return nil, fmt.Errorf("公开门面登录未进入 TOTP 第二步: %v（restricted=%t）",
			err, loginResult.Restricted)
	}
	code, err := totpCodeNextStep(s.totpSecret)
	if err != nil {
		return nil, err
	}
	verified, err := instance.runtime.Auth().VerifySecondFactor(s.ctx,
		app.VerifySecondFactorRequest{SessionSecret: loginResult.SessionSecret,
			ChallengeID:  loginResult.SecondFactor.ChallengeID,
			AttemptToken: loginResult.SecondFactor.AttemptToken,
			Code:         code, RequestID: login.NewRequestID()})
	if err != nil || len(verified.SessionSecret) == 0 {
		return nil, fmt.Errorf("公开门面 TOTP 第二步失败: %v", err)
	}
	return verified.SessionSecret, nil
}

// checkAccountSecurityChanges 覆盖 206：已签发但未使用的找回链接必须随密码或邮箱
// 安全变更失效（真实账户页面流程：登录页 + TOTP 第二步 + 改密/邮箱切换页）。
func (s *scenario) checkAccountSecurityChanges(instance *testRuntime) {
	if s.totpSecret == "" || s.currentPassword == "" {
		s.notTested("reset.stale_token_invalidated",
			"MFA/改密前置未完成，无法验证安全变更后的旧链接失效")
		s.notTested("email.change_via_pages", "MFA/改密前置未完成")
		return
	}

	// 1) 密码变更：先持有未使用链接，再通过账户页改密，旧链接必须失效。
	staleToken, err := s.requestResetToken(instance)
	if err != nil {
		s.fail("reset.stale_token_invalidated", err)
		return
	}
	sessionSecret, err := s.loginFullSession(instance, s.currentPassword)
	if err != nil {
		s.fail("reset.stale_token_invalidated", fmt.Errorf("公开门面登录失败: %w", err))
		return
	}
	if err := instance.website.setSessionCookie(sessionSecret); err != nil {
		s.fail("reset.stale_token_invalidated", err)
		return
	}
	secondPassword := "S9!kR4#mW7@qB2$x"
	if err := instance.website.changePasswordViaPages(s.currentPassword, secondPassword); err != nil {
		s.fail("reset.stale_token_invalidated", fmt.Errorf("页面改密失败: %w", err))
		return
	}
	if err := instance.runtime.PasswordReset().ValidateTokenWithSource(s.ctx,
		app.ValidatePasswordResetTokenRequest{Token: staleToken, ClientIP: "127.0.0.1",
			RequestID: login.NewRequestID()}); err == nil {
		s.fail("reset.stale_token_invalidated", fmt.Errorf("改密后旧找回链接仍通过预检查"))
		return
	}
	s.pass("reset.stale_token_invalidated", "账户页改密后，先前未使用的找回链接失效（206）")
	s.currentPassword = secondPassword

	// 2) 邮箱切换：先持有未使用链接，再通过账户页切换并验证新邮箱，旧链接必须失效。
	staleToken2, err := s.requestResetToken(instance)
	if err != nil {
		s.fail("email.change_via_pages", err)
		return
	}
	sessionSecret, err = s.loginFullSession(instance, s.currentPassword)
	if err != nil {
		s.fail("email.change_via_pages", fmt.Errorf("公开门面登录失败: %w", err))
		return
	}
	if err := instance.website.setSessionCookie(sessionSecret); err != nil {
		s.fail("email.change_via_pages", err)
		return
	}
	const newEmail = "externalreset2@example.test"
	if err := instance.website.requestEmailChangeViaPages(s.currentPassword, newEmail); err != nil {
		s.fail("email.change_via_pages", err)
		return
	}
	changeMessages, err := s.mail.waitForMessages(s.ctx, mailWaitTimeout, func(message mailMessage) bool {
		if !containsAddressFold(message.To, newEmail) {
			return false
		}
		_, found := findLink([]mailMessage{message}, "/email/change/verify")
		return found
	})
	if err != nil {
		s.fail("email.change_via_pages", fmt.Errorf("等待新邮箱验证邮件失败: %w", err))
		return
	}
	changeLink, found := findLink(changeMessages, "/email/change/verify")
	if !found {
		s.fail("email.change_via_pages", fmt.Errorf("新邮箱验证邮件缺少链接"))
		return
	}
	if err := instance.website.confirmEmailChangeViaLink(changeLink); err != nil {
		s.fail("email.change_via_pages", err)
		return
	}
	s.newEmail = newEmail
	s.email = newEmail
	s.pass("email.change_via_pages", "通过账户页申请并验证新邮箱，公开验证入口完成切换")
	if err := instance.runtime.PasswordReset().ValidateTokenWithSource(s.ctx,
		app.ValidatePasswordResetTokenRequest{Token: staleToken2, ClientIP: "127.0.0.1",
			RequestID: login.NewRequestID()}); err == nil {
		s.fail("reset.stale_token_invalidated_by_email_change",
			fmt.Errorf("邮箱切换后旧找回链接仍通过预检查"))
		return
	}
	s.pass("reset.stale_token_invalidated_by_email_change",
		"邮箱切换后，先前未使用的找回链接失效（206）")
}

// ---- 拒绝/配置/防枚举路径 ----

func (s *scenario) checkNegativePaths(primary *testRuntime) {
	// 防枚举：未知账户的公开申请与可用账户返回相同外形（nil），且不向该目标发信。
	// 断言按收件人精确过滤并等待异步队列静默，避免前序场景邮件落入采样窗口。
	const unknownIdentifier = "unknown-user@example.test"
	err := primary.runtime.PasswordReset().Request(s.ctx, app.RequestPasswordResetRequest{
		Identifier: unknownIdentifier, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		s.fail("enumerate.unknown_identifier", fmt.Errorf("未知账户申请返回可区分错误: %w", err))
	} else if sent := s.mail.countMessagesForRecipient(s.ctx, unknownIdentifier,
		"/login/reset-password", 1500*time.Millisecond, 8*time.Second); sent != 0 {
		s.fail("enumerate.unknown_identifier", fmt.Errorf("未知账户申请产生了邮件（收件人精确匹配 %d 封）", sent))
	} else {
		s.pass("enumerate.unknown_identifier",
			"未知账户申请返回成功外形且不向该目标发送邮件（队列静默后按收件人精确校验）")
	}

	// root：公开入口不能为 root 绑定/验证邮箱，因此不能签发 root 找回入口。
	if _, err := primary.runtime.Bootstrap().EnsureRoot(s.ctx, app.RootRequest{
		Username: "root", DisplayName: "Root", Password: strongPassword,
		RequestID: login.NewRequestID(),
	}); err != nil {
		s.notTested("enumerate.root", "公开 Bootstrap.EnsureRoot 创建 root 失败，root 场景未执行: "+err.Error())
	} else {
		const rootIdentifier = "root@example.test"
		rootErr := primary.runtime.PasswordReset().Request(s.ctx, app.RequestPasswordResetRequest{
			Identifier: rootIdentifier, ClientIP: "127.0.0.1",
			RequestID: login.NewRequestID(),
		})
		rootSent := s.mail.countMessagesForRecipient(s.ctx, rootIdentifier,
			"/login/reset-password", 1500*time.Millisecond, 8*time.Second)
		if rootErr != nil || rootSent != 0 {
			s.fail("enumerate.root", fmt.Errorf("root 相关申请可区分或产生邮件: err=%v sent=%d",
				rootErr, rootSent))
		} else {
			s.pass("enumerate.root", "root 无已验证邮箱：公开申请返回成功外形且不发送邮件")
		}
	}

	// 待审核账户（公开注册页可创建）：公开申请返回统一外形且不发送邮件。
	pending, err := s.openRuntime("pending", func(config *login.Config) {
		config.Registration.RequireReview = true
		config.Registration.RequireEmailVerification = false
	})
	if err != nil {
		s.fail("enumerate.pending_account", fmt.Errorf("打开待审核场景运行时失败: %w", err))
	} else {
		pendingEmail := "pending-user@example.test"
		if err := s.registerPendingUser(pending, "pendinguser", pendingEmail); err != nil {
			s.fail("enumerate.pending_account", fmt.Errorf("通过公开页面创建待审核账户失败: %w", err))
		} else {
			pendingErr := pending.runtime.PasswordReset().Request(s.ctx,
				app.RequestPasswordResetRequest{Identifier: pendingEmail, ClientIP: "127.0.0.1",
					RequestID: login.NewRequestID()})
			pendingSent := s.mail.countMessagesForRecipient(s.ctx, pendingEmail,
				"/login/reset-password", 1500*time.Millisecond, 8*time.Second)
			if pendingErr != nil || pendingSent != 0 {
				s.fail("enumerate.pending_account",
					fmt.Errorf("待审核账户申请可区分或产生邮件: err=%v sent=%d",
						pendingErr, pendingSent))
			} else {
				s.pass("enumerate.pending_account",
					"待审核（不可正常登录）账户申请返回统一外形且不发送邮件")
			}
		}
	}

	// 真实 disabled / 无密码账户：当前公开 Go 门面没有创建/设置入口（管理写操作
	// 仍走内部/管理页面），无法仅用公开入口构造，如实登记未测。
	s.notTested("enumerate.disabled_passwordless",
		"公开 app 门面当前无禁用/无密码账户创建入口；该状态由内部测试覆盖，外部公开入口未测")

	// 邮件关闭：公开入口返回明确配置错误（不是伪造成功）。
	noMail, err := s.openRuntime("no-mail", func(config *login.Config) {
		config.Mail.Enabled = false
		config.Registration.RequireEmailVerification = false
	})
	if err != nil {
		s.fail("config.mail_disabled", fmt.Errorf("打开邮件关闭场景运行时失败: %w", err))
	} else {
		noMailErr := noMail.runtime.PasswordReset().Request(s.ctx, app.RequestPasswordResetRequest{
			Identifier: "anyone@example.test", ClientIP: "127.0.0.1",
			RequestID: login.NewRequestID(),
		})
		if !login.IsErrorCode(noMailErr, login.CodeConfigInvalid) {
			s.fail("config.mail_disabled",
				fmt.Errorf("邮件关闭时找回入口错误 = %v，期望 CONFIG_INVALID", noMailErr))
		} else {
			s.pass("config.mail_disabled", "邮件关闭时公开找回入口返回 CONFIG_INVALID（不伪造成功）")
		}
	}

	// 邮件投递失败：公开申请仍返回成功外形（防枚举），失败只进受控状态/审计。
	deadPort, portErr := freeLoopbackPort()
	if portErr != nil {
		s.fail("mail.delivery_failure", portErr)
	} else {
		mailDown, downErr := s.openRuntime("mail-down", func(config *login.Config) {
			config.Mail.SMTP.Addr = fmt.Sprintf("127.0.0.1:%d", deadPort)
			config.Mail.SMTP.TimeoutSeconds = 2
			config.Mail.Delivery.MaxAttempts = 1
		})
		if downErr != nil {
			s.fail("mail.delivery_failure", fmt.Errorf("打开邮件失败场景运行时失败: %w", downErr))
		} else {
			downEmail := "maildown-user@example.test"
			registerErr := s.registerUserViaAPI(mailDown, "maildownuser", downEmail)
			if registerErr != nil {
				s.fail("mail.delivery_failure",
					fmt.Errorf("邮件失败场景创建用户失败: %w", registerErr))
			} else {
				requestErr := mailDown.runtime.PasswordReset().Request(s.ctx,
					app.RequestPasswordResetRequest{Identifier: downEmail,
						ClientIP: "127.0.0.1", RequestID: login.NewRequestID()})
				if requestErr != nil {
					s.fail("mail.delivery_failure",
						fmt.Errorf("邮件失败时公开申请返回可区分错误: %w", requestErr))
				} else {
					s.pass("mail.delivery_failure",
						"SMTP 不可达时公开申请仍返回统一外形（失败只进受控状态/审计）")
				}
			}
		}
	}
}

// registerPendingUser 通过公开注册页创建待审核账户（不需要邮箱验证）。
func (s *scenario) registerPendingUser(instance *testRuntime, username, email string) error {
	token, err := instance.website.csrfToken("/register")
	if err != nil {
		return err
	}
	form := url.Values{
		"username": {username}, "password": {strongPassword},
		"password_confirm": {strongPassword}, "nickname": {"待审核用户"},
		"email": {email}, "csrf_token": {token},
	}
	status, body, err := instance.website.postSiteForm("/register", form)
	if err != nil || status != http.StatusOK {
		return fmt.Errorf("注册页提交失败: status=%d err=%v body=%s", status, err,
			truncateText(body, 300))
	}
	return nil
}

// registerUserViaAPI 通过公开 Users().Create 创建账户（仅用于邮件失败场景，不涉及
// 邮箱验证：该场景配置关闭了必须验证邮箱，随后申请找回仍会因邮箱未验证被统一拒绝）。
func (s *scenario) registerUserViaAPI(instance *testRuntime, username, email string) error {
	_, err := instance.runtime.Users().Create(s.ctx, app.CreateUserRequest{
		Username: username, Password: strongPassword, Email: email,
		Nickname: "邮件失败用户", RequestID: login.NewRequestID(),
	})
	return err
}

// ---- 审计诊断分离 ----

// checkRateLimitAndRequestID 覆盖 208：公开入口每来源限流与请求编号贯穿。
//   - 同一来源超过上限后仍返回统一成功外形（不可枚举），但不再产生邮件；
//   - 管理/审计诊断可看到 rate_limited 失败原因；
//   - 成功受理的请求编号出现在审计行中，可与调用关联。
func (s *scenario) checkRateLimitAndRequestID(primary *testRuntime) {
	// 使用独立可信来源地址，避免复用前序场景已消耗的配额，让限额边界可确定。
	const limiterClientIP = "198.51.100.7"
	const perSourceLimit = 10
	beforeMessages, _ := s.mail.messages()
	generatedIDs := make([]string, 0, perSourceLimit+2)
	// 限额内的前 N 次申请：统一成功外形并真实进入异步投递。
	for index := 0; index < perSourceLimit; index++ {
		requestID := login.NewRequestID()
		generatedIDs = append(generatedIDs, requestID)
		if err := primary.runtime.PasswordReset().Request(s.ctx,
			app.RequestPasswordResetRequest{Identifier: s.email, ClientIP: limiterClientIP,
				RequestID: requestID}); err != nil {
			s.fail("limit.request_uniform_failure",
				fmt.Errorf("限额内第 %d 次申请失败: %w", index+1, err))
			return
		}
	}
	s.pass("limit.request_uniform_failure",
		"同一来源限额内 10 次公开申请均返回统一成功外形")
	// 超限：返回稳定的 RATE_LIMITED（这是调用方配额事实，不是账户存在性差异）；
	// 对未知账户同样返回 RATE_LIMITED，不能借限流差异枚举账户。
	limitedRequestID := login.NewRequestID()
	generatedIDs = append(generatedIDs, limitedRequestID)
	limitedErr := primary.runtime.PasswordReset().Request(s.ctx,
		app.RequestPasswordResetRequest{Identifier: s.email, ClientIP: limiterClientIP,
			RequestID: limitedRequestID})
	if !login.IsErrorCode(limitedErr, login.CodeRateLimited) {
		s.fail("limit.per_source_quota",
			fmt.Errorf("超限申请错误 = %v，期望稳定 RATE_LIMITED", limitedErr))
	} else {
		s.pass("limit.per_source_quota", "同一来源超限返回稳定 RATE_LIMITED，不再受理")
	}
	unknownLimitedErr := primary.runtime.PasswordReset().Request(s.ctx,
		app.RequestPasswordResetRequest{Identifier: "unknown-limited@example.test",
			ClientIP: limiterClientIP, RequestID: login.NewRequestID()})
	if !login.IsErrorCode(unknownLimitedErr, login.CodeRateLimited) {
		s.fail("limit.unknown_identifier_same_limit",
			fmt.Errorf("未知账户超限错误 = %v，期望同样 RATE_LIMITED（不可枚举）",
				unknownLimitedErr))
	} else {
		s.pass("limit.unknown_identifier_same_limit",
			"未知账户与可用账户在同一受限来源上返回相同 RATE_LIMITED（不可枚举）")
	}
	// 邮件配额：邮箱级限流与来源级限流叠加，实际发出数可能少于 10（不低于上限、
	// 也不重复超发）。断言“上限内且超限后不再新增”，不虚构精确封数。
	deadline := time.Now().Add(8 * time.Second)
	var afterMessages []mailMessage
	for {
		afterMessages, _ = s.mail.messages()
		if len(afterMessages)-len(beforeMessages) > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	// 再观察一段时间，确认被拒绝的请求不会迟到投递。
	time.Sleep(2 * time.Second)
	afterMessages, _ = s.mail.messages()
	newMails := len(afterMessages) - len(beforeMessages)
	if newMails < 0 || newMails > perSourceLimit {
		s.fail("limit.mail_quota", fmt.Errorf("限额内产生 %d 封邮件，期望 0～%d",
			newMails, perSourceLimit))
	} else {
		s.pass("limit.mail_quota", fmt.Sprintf(
			"限额内实际发出 %d 封邮件（≤%d；邮箱级限流可与来源级叠加，超限后不再新增）",
			newMails, perSourceLimit))
	}
	evidence, err := readAuditDiagnostics(primary.dbPath)
	if err != nil {
		s.fail("limit.rate_limited_audited", fmt.Errorf("读取审计诊断失败: %w", err))
		return
	}
	if !auditHasReason(evidence, "rate_limited") {
		s.fail("limit.rate_limited_audited", fmt.Errorf("审计中未看到 rate_limited 失败原因"))
	} else {
		s.pass("limit.rate_limited_audited", "管理/审计诊断可辨别 rate_limited 拒绝原因")
	}
	correlated := false
	for _, requestID := range generatedIDs {
		if auditHasRequestID(evidence, requestID) {
			correlated = true
			break
		}
	}
	if !correlated {
		s.fail("limit.request_id_correlated", fmt.Errorf("审计行未包含任一调用生成的请求编号"))
	} else {
		s.pass("limit.request_id_correlated", "至少一条受理/拒绝审计行携带调用方生成的请求编号（208）")
	}
}

// checkAuditDiagnostics 校验公开响应防枚举的同时，管理/审计只读诊断能辨别真实
// 成功与拒绝原因（外部模块只读查询临时库，不写认证状态、不冒充管理接口）。
func (s *scenario) checkAuditDiagnostics(primary *testRuntime) {
	evidence, err := readAuditDiagnostics(primary.dbPath)
	if err != nil {
		s.fail("diagnostics.audit_separation", fmt.Errorf("只读审计诊断失败: %w", err))
		return
	}
	s.report.AuditSummary = append(s.report.AuditSummary, evidence...)
	hasSuccess := false
	hasFailureReason := false
	for _, item := range evidence {
		if item.Outcome == "success" {
			hasSuccess = true
		}
		if item.Outcome != "success" && item.ReasonCode != "" {
			hasFailureReason = true
		}
	}
	if !hasSuccess || !hasFailureReason {
		s.fail("diagnostics.audit_separation",
			fmt.Errorf("审计诊断无法区分成功与拒绝原因: success=%t failure_reason=%t",
				hasSuccess, hasFailureReason))
	} else {
		s.pass("diagnostics.audit_separation",
			"公开响应防枚举，同时审计行保留成功/拒绝原因（管理诊断可辨别）")
	}
	s.pass("diagnostics.audit_readonly",
		fmt.Sprintf("以只读模式读取 %d 条 password.reset_* 审计行（未写测试数据库认证状态）", len(evidence)))
}

// ---- 结果与检查记录 ----

func (s *scenario) pass(id, detail string) {
	s.report.Checks = append(s.report.Checks, checkResult{ID: id, Status: "PASS", Detail: detail})
	if s.opts.Verbose {
		fmt.Fprintf(os.Stderr, "[PASS] %s: %s\n", id, detail)
	}
}

func (s *scenario) fail(id string, err error) {
	detail := "失败"
	if err != nil {
		detail = err.Error()
	}
	s.report.Checks = append(s.report.Checks, checkResult{ID: id, Status: "FAIL", Detail: detail})
	fmt.Fprintf(os.Stderr, "[FAIL] %s: %s\n", id, detail)
}

func (s *scenario) notTested(id, detail string) {
	s.report.Checks = append(s.report.Checks, checkResult{ID: id, Status: "NOT_TESTED", Detail: detail})
	if s.opts.Verbose {
		fmt.Fprintf(os.Stderr, "[NOT_TESTED] %s: %s\n", id, detail)
	}
}

func (s *scenario) runtimePass(id string, instance *testRuntime, detail string) {
	s.pass(id, fmt.Sprintf("%s（HTTP 前缀=%s）", detail, instance.runtime.HTTPPrefix()))
}

// finalize 汇总状态与耗时；错误返回给调用方以非零退出。
func (s *scenario) finalize(startedAt time.Time) *scenarioReport {
	for _, item := range s.report.Checks {
		switch item.Status {
		case "PASS":
			s.report.Counts.Pass++
		case "FAIL":
			s.report.Counts.Fail++
		default:
			s.report.Counts.NotTested++
		}
	}
	s.report.DurationMs = time.Since(startedAt).Milliseconds()
	switch {
	case s.report.Counts.Fail > 0:
		s.report.Status = "FAIL"
	case s.report.Counts.NotTested > 0:
		s.report.Status = "PASS_WITH_NOTES"
	default:
		s.report.Status = "PASS"
	}
	return s.report
}

// containsAddressFold 判断地址列表中是否包含目标邮箱（不区分大小写）。
func containsAddressFold(addresses []string, target string) bool {
	lower := strings.ToLower(strings.TrimSpace(target))
	for _, address := range addresses {
		if strings.Contains(strings.ToLower(address), lower) {
			return true
		}
	}
	return false
}

// parsedLinkPath 返回链接的路径（不含查询串/token），仅用于错误诊断，不泄露秘密。
func parsedLinkPath(link string) string {
	parsed, err := url.Parse(link)
	if err != nil {
		return "<invalid>"
	}
	return parsed.Path
}
