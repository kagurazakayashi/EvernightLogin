package e2e

// 步骤 274 矩阵七：受控邮件链路上的恢复/通知真实行为。
//
//   - 250：邮箱 A→B→A 变更后，A 时期签发的旧找回链接永久拒绝（即使当前邮箱又等于 A），
//     且旧口令未受影响；受控本机 SMTP 捕获器取回邮件中的一次性链接，不经数据库读取令牌。
//   - 265/266：直接管理操作触发的安全告知邮件经真实可靠投递队列 + 本机 SMTP 发送后进入
//     succeeded 终态；HTTP 管理 API 只返回脱敏字段（不返回完整收件人/加密载荷），无权限
//     会话被拒绝；安全告知历史端点如实返回（不伪造未产生的通知）。
//
// 安全边界：邮件只在内存中捕获，令牌只用于本次断言且不输出；测试结束关闭监听。

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	loginapp "github.com/kagurazakayashi/EvernightLogin/app"
)

// waitCapturedURL 等待邮件中出现尚未消费过的指定路径一次性链接（多次发送时不复用旧链接）。
func waitCapturedURL(t *testing.T, capture *smtpCapture, pathFragment string,
	seen map[string]bool, timeout time.Duration) *url.URL {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, raw := range capturedURLList(capture.snapshot(), pathFragment) {
			if seen[raw] {
				continue
			}
			seen[raw] = true
			parsed, err := url.Parse(raw)
			if err != nil {
				t.Fatalf("解析邮件链接失败: %v", err)
			}
			return parsed
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("等待邮件链接超时：路径片段 %q（已捕获 %d 封）", pathFragment,
		capture.messageCount())
	return nil
}

// passwordResetToken 从找回邮件链接中读取 token 参数。
func passwordResetToken(t *testing.T, link *url.URL) string {
	t.Helper()
	token := link.Query().Get("token")
	if token == "" {
		t.Fatal("找回邮件链接缺少 token 参数")
	}
	return token
}

// TestMatrixEmailChangeResetLinkPermanentRejection 覆盖 250 A→B→A 旧链接永久拒绝。
func TestMatrixEmailChangeResetLinkPermanentRejection(t *testing.T) {
	ctx := context.Background()
	capture := startSMTPCapture(t)
	seenLinks := make(map[string]bool)
	env := openEnvMail(t, capture)
	const oldEmail = "old-address@example.test"
	const newEmail = "new-address@example.test"
	user, err := env.Runtime.Users().Create(ctx, loginapp.CreateUserRequest{
		Username: "mail-reset-user", Password: targetPassword, Email: oldEmail,
		Nickname: "mail-reset-user", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建带邮箱用户: %v", err)
	}
	seededVerifiedEmail(t, env.DBPath, user.ID, oldEmail)

	// 1) A 时期签发找回链接（真实邮件投递到本机 SMTP 捕获器）。
	session := loginFull(t, env.Runtime, "mail-reset-user", targetPassword).SessionSecret
	if err := env.Runtime.PasswordReset().Request(ctx, loginapp.RequestPasswordResetRequest{
		Identifier: oldEmail, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("发起找回: %v", err)
	}
	resetLink := waitCapturedURL(t, capture, "/login/reset-password",
		seenLinks, 15*time.Second)
	oldToken := passwordResetToken(t, resetLink)
	if err := env.Runtime.PasswordReset().ValidateToken(ctx, oldToken); err != nil {
		t.Fatalf("新签发找回链接应可用（前置）: %v", err)
	}

	// 2) A→B 邮箱变更（真实邮件验证链接），随后重新登录再 B→A。
	requestEmailChange := func(fromSession []byte, email string) {
		t.Helper()
		if _, err := env.Runtime.EmailChange().Request(ctx,
			loginapp.RequestEmailChangeRequest{SessionSecret: fromSession,
				NewEmail: email, Password: targetPassword,
				RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("发起邮箱变更到 %s: %v", email, err)
		}
		link := waitCapturedURL(t, capture, "/email/change/verify",
			seenLinks, 15*time.Second)
		query := link.Query()
		verified, verifyErr := env.Runtime.EmailChange().Verify(ctx,
			loginapp.VerifyEmailChangeRequest{ChangeRequestID: query.Get("rid"),
				CredentialID: query.Get("cid"), Token: query.Get("token"),
				RequestID: login.NewRequestID()})
		if verifyErr != nil {
			t.Fatalf("验证邮箱变更到 %s: %v", email, verifyErr)
		}
		if !strings.EqualFold(verified.Email, email) {
			t.Fatalf("邮箱变更结果 = %q，期望 %q", verified.Email, email)
		}
	}
	requestEmailChange(session, newEmail)
	// 邮箱变更使旧会话失效，重新登录后改回 A。
	session = loginFull(t, env.Runtime, "mail-reset-user", targetPassword).SessionSecret
	requestEmailChange(session, oldEmail)

	// 3) A→B→A 后，A 时期旧 token 必须永久拒绝（不能因当前邮箱又等于 A 而复活）。
	if err := env.Runtime.PasswordReset().ValidateToken(ctx, oldToken); err == nil {
		t.Fatal("A→B→A 后旧找回链接仍可用（250 回归失败）")
	} else if !login.IsErrorCode(err, login.CodeChallengeInvalid) &&
		!login.IsErrorCode(err, login.CodeTokenInvalid) &&
		!login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("旧找回链接错误码 = %v，期望稳定拒绝码", err)
	}
	if _, completeErr := env.Runtime.PasswordReset().Complete(ctx,
		loginapp.CompletePasswordResetRequest{Token: oldToken,
			NewPassword: directPasswordA, ClientIP: "127.0.0.1",
			RequestID: login.NewRequestID()}); completeErr == nil {
		t.Fatal("A→B→A 后旧找回链接仍能完成改密（250 回归失败）")
	}
	// 旧口令未受影响，仍可完整登录。
	if result, loginErr := env.Runtime.Auth().Login(ctx, loginapp.LoginRequest{
		Username: "mail-reset-user", Password: targetPassword, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()}); loginErr != nil || result.Restricted {
		t.Fatalf("旧口令应仍可完整登录: err=%v result=%+v", loginErr, result)
	}
}

// TestMatrixNotificationDeliveryTerminalState 覆盖 265/266 通知真实投递终态与 HTTP 脱敏读取。
func TestMatrixNotificationDeliveryTerminalState(t *testing.T) {
	ctx := context.Background()
	capture := startSMTPCapture(t)
	env := openEnvMail(t, capture)
	const targetEmail = "notice-target@example.test"
	operator, operatorTOTP := enrollTOTP(t, env.Runtime, env.Clock, "mail-notice-operator",
		operatorPassword)
	grantSystemPermissions(t, env.Runtime, operator.ID, "mail-notice-role",
		"users.username.change.other", "users.password.reset.other", "users.read",
		"diagnostics.read", "audit.read")
	strongSession := issueStrongManagementSession(t, env, operator.ID, "mail-notice-operator")

	target, err := env.Runtime.Users().Create(ctx, loginapp.CreateUserRequest{
		Username: "notice-target", Password: targetPassword, Email: targetEmail,
		Nickname: "notice-target", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建通知目标: %v", err)
	}
	seededVerifiedEmail(t, env.DBPath, target.ID, targetEmail)

	// 直接改名成功后会 best-effort 入队安全告知邮件；等待真实 SMTP 发送与终态。
	env.Clock.Advance(30 * time.Second)
	proof := env.Runtime.OperationProof()
	caller := env.Runtime.AdminSession(strongSession)
	challenge, err := proof.Begin(ctx, loginapp.OperationProofBeginRequest{
		Caller: caller, TargetUserID: target.ID,
		Operation: loginapp.OperationProofUsernameChange, NewUsername: "notice-target-renamed",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("发起改名证明: %v", err)
	}
	grant, err := proof.Confirm(ctx, loginapp.OperationProofConfirmRequest{
		Caller: caller, ChallengeID: challenge.ChallengeID, Password: operatorPassword,
		TOTPCode: totpCode(t, env.Clock, operatorTOTP), RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("完成改名两步验证: %v", err)
	}
	if _, err := env.Runtime.DirectUserManagement().ChangeUserUsername(ctx,
		loginapp.AdminChangeUserUsernameRequest{Caller: caller, TargetUserID: target.ID,
			NewUsername:        "notice-target-renamed",
			ExpectedRowVersion: userRowVersion(t, env.DBPath, target.ID),
			Reason:             "步骤274 通知终态", ProofToken: grant.ProofToken,
			RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("直接改名（触发通知）: %v", err)
	}
	// 等待邮件投递记录进入 succeeded 终态与真实 SMTP 捕获（证明不是“入队即成功”）。
	waitDeliveryState(t, env.DBPath, "admin-direct-username-change:", "succeeded",
		20*time.Second)
	if capture.messageCount() == 0 {
		t.Fatal("投递记录 succeeded 但本机 SMTP 未捕获到邮件（终态不可信）")
	}

	// HTTP 管理 API：投递记录只返回脱敏白名单字段；无权限会话拒绝。
	server := startHTTP(t, env.Runtime)
	bearer := string(strongSession)
	deliveries := httpCall(t, server, http.MethodGet, "/admin/v1/deliveries", bearer, nil)
	deliveryData := requireHTTPData(t, deliveries, "读取邮件投递记录")
	items, _ := deliveryData["deliveries"].([]any)
	if len(items) == 0 {
		t.Fatalf("投递记录列表为空（真实投递未投影）: %+v", deliveryData)
	}
	foundSucceeded := false
	var deliveryID string
	for _, raw := range items {
		item, _ := raw.(map[string]any)
		if item == nil {
			continue
		}
		if state, _ := item["state"].(string); state == "succeeded" {
			foundSucceeded = true
			deliveryID, _ = item["delivery_id"].(string)
		}
	}
	if !foundSucceeded || deliveryID == "" {
		t.Fatalf("投递记录缺少 succeeded 终态: %+v", items)
	}
	if strings.Contains(deliveries.Raw, targetEmail) {
		t.Fatal("投递记录 HTTP 响应泄露完整收件人地址")
	}
	if strings.Contains(strings.ToLower(deliveries.Raw), "sealed_payload") ||
		strings.Contains(strings.ToLower(deliveries.Raw), "sealed") {
		t.Fatal("投递记录 HTTP 响应泄露加密载荷字段")
	}
	// 安全告知历史 HTTP 端点：如实返回（不伪造未产生的记录）。直接管理告知目前只记录
	// 邮件投递，不写 reauth 安全告知历史表；因此这里只断言端点可读、结构真实、不报假成功。
	history := httpCall(t, server, http.MethodGet,
		"/admin/v1/notifications/history?user_id="+target.ID, bearer, nil)
	historyData := requireHTTPData(t, history, "读取安全告知历史")
	if _, present := historyData["notifications"]; !present {
		t.Fatalf("安全告知历史响应缺少 notifications 字段: %+v", historyData)
	}
	// 无管理强认证/无权限的普通会话不能读取投递记录。
	createUser(t, env.Runtime, "mail-notice-ordinary", targetPassword)
	ordinarySession := loginFull(t, env.Runtime, "mail-notice-ordinary", targetPassword).SessionSecret
	denied := httpCall(t, server, http.MethodGet, "/admin/v1/deliveries",
		string(ordinarySession), nil)
	requireHTTPFailure(t, denied, "无权限读取投递记录")
}
