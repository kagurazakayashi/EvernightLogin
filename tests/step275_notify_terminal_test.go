// 步骤 275 集成回归：直接管理安全告知的“真实终态可回查”。
//
// 目的：用公开 app 门面与真实本地 EvernightMail 夹具，验证直接改名触发的安全告知
// 不是“入队即成功”：
//   - 真实 delivery 记录先由通知路径创建（queued），随后由任务运行时真实投递；
//   - 本地 Mail 实际收到且仅收到 1 封（同一业务事件不重复投递）；
//   - 投递记录的终态为 succeeded（终态回查），模板为 security_notice；
//   - 直接操作成功返回与投递终态解耦：观测投递终态不改变已成功的业务结果。
//
// 该测试位于父仓库独立 tests 包（只读观测同一临时库 mail_deliveries 行，不导入
// 生产内部实现替代授权/会话/证明链路）。全部为临时 SQLite/回环 Mail，退出清理，
// 不输出秘密。

package tests

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailtest"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
)

const step275DirectPassword = "K8$wR3!nB6@yF1#v"

// step275Clock 是可推进的确定性时钟（TOTP 时间步）。
type step275Clock struct {
	mu  sync.Mutex
	now time.Time
}

// Now 实现 app.Options.Now。
func (c *step275Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance 推进时钟（TOTP 时间步 30 秒）。
func (c *step275Clock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

// step275TOTP 按 RFC 6238（SHA1/6 位/30 秒）计算验证码，等价用户的验证器 App。
func step275TOTP(encodedSecret string, at time.Time) (string, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(encodedSecret), " ", ""))
	normalized = strings.TrimRight(normalized, "=")
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(normalized)
	if err != nil {
		return "", fmt.Errorf("解码 TOTP 种子失败: %w", err)
	}
	step := uint64(at.Unix() / 30)
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], step)
	mac := hmac.New(sha1.New, secret)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	return fmt.Sprintf("%06d", value%1000000), nil
}

// step275ErrorChain 展开错误链用于诊断（不含配置秘密）。
func step275ErrorChain(err error) string {
	var parts []string
	for current := err; current != nil; current = errors.Unwrap(current) {
		parts = append(parts, current.Error())
	}
	return strings.Join(parts, " <- ")
}

// step275OpenRuntime 打开真实公开运行时（临时 SQLite + 真实本地 Mail + 可控时钟）。
func step275OpenRuntime(t *testing.T, mailAddr string, clock *step275Clock) (*app.Runtime, string) {
	t.Helper()
	dir := testutil.TempDir(t)
	cfg := login.Default()
	cfg.Registration.Enabled = true
	cfg.Registration.RequireReview = false
	cfg.Registration.RequireEmailVerification = false
	cfg.Logging.Level = login.LogLevelError
	cfg.Server.PublicBaseURL = "https://login.example.test"
	cfg.Mail = login.MailConfig{
		Enabled: true,
		SMTP: login.MailSMTPConfig{
			Addr: mailAddr, Host: "mailtest.local", TLSMode: "none",
			AllowPlaintextLocal: true, TimeoutSeconds: 10,
		},
		From:    login.MailFromConfig{Address: "no-reply@example.test", Name: "步骤275 回归"},
		AppName: "步骤275 回归",
		Delivery: login.MailDeliveryConfig{
			MaxAttempts: 2, TimeoutSeconds: 30,
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("测试配置校验失败: %v", err)
	}
	dbPath := filepath.Join(dir, "login.db")
	runtime, err := app.Open(context.Background(), app.Options{
		Config: &cfg, DatabasePath: dbPath,
		MasterKeyFile: filepath.Join(dir, "master.key"), CreateMasterKey: true,
		Migrate: true, OperatorID: "step275-tests", Now: clock.Now,
		Logger: slog.New(slog.NewTextHandler(os.Stderr,
			&slog.HandlerOptions{Level: slog.LevelError})),
	})
	if err != nil {
		t.Fatalf("打开测试运行时: %v（原因链: %s）", err, step275ErrorChain(err))
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	if err := runtime.Start(context.Background()); err != nil {
		t.Fatalf("启动测试运行时任务: %v", err)
	}
	return runtime, dbPath
}

// step275BindTOTP 登录新用户并完成真实 TOTP 绑定，返回会话与该用户种子。
func step275BindTOTP(t *testing.T, runtime *app.Runtime, clock *step275Clock,
	username, password string) ([]byte, string) {
	t.Helper()
	ctx := context.Background()
	loginResult, err := runtime.Auth().Login(ctx, app.LoginRequest{
		Username: username, Password: password, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil || loginResult.Restricted || len(loginResult.SessionSecret) == 0 {
		t.Fatalf("首次登录 %s 失败: %+v err=%v", username, loginResult, err)
	}
	start, err := runtime.Security().BeginTOTPBinding(ctx, app.TOTPBindingBeginRequest{
		SessionSecret: loginResult.SessionSecret, Password: password,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("开始绑定 TOTP: %v", err)
	}
	code, err := step275TOTP(start.Secret, clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Security().ConfirmTOTPBinding(ctx, app.TOTPBindingConfirmRequest{
		SessionSecret: loginResult.SessionSecret, BindingID: start.BindingID,
		Code: code, RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("确认 TOTP 绑定: %v", err)
	}
	return loginResult.SessionSecret, start.Secret
}

// step275VerifiedEmail 为合成用户写入已验证邮箱（测试夹具；直接管理告知只要求目标
// 最近已验证邮箱存在，不改变生产邮箱验证实现）。
func step275VerifiedEmail(t *testing.T, dbPath, userID, email string) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("打开观测数据库: %v", err)
	}
	defer func() { _ = db.Close() }()
	nowMS := time.Now().UTC().UnixMilli()
	const insertSQL = "INSERT INTO user_emails(user_id,email,email_normalized," +
		"verified_at_ms,created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?)"
	if _, err := db.Exec(insertSQL, userID, email, strings.ToLower(email),
		nowMS, nowMS, nowMS); err != nil {
		t.Fatalf("写入已验证邮箱夹具: %v", err)
	}
}

// step275DeliveryState 查询指定收件人的投递记录（只读观测）。
func step275DeliveryState(t *testing.T, dbPath, recipient string) ([]string, []string) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("打开观测数据库: %v", err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query("SELECT state,template_kind FROM mail_deliveries "+
		"WHERE recipient=? ORDER BY created_at_ms ASC,id ASC", recipient)
	if err != nil {
		t.Fatalf("查询投递记录: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var states, templates []string
	for rows.Next() {
		var state, template string
		if err := rows.Scan(&state, &template); err != nil {
			t.Fatalf("读取投递记录: %v", err)
		}
		states = append(states, state)
		templates = append(templates, template)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("遍历投递记录: %v", err)
	}
	return states, templates
}

// waitStep275DeliveryTerminal 有界等待投递记录离开 queued/sending 进入终态。
func waitStep275DeliveryTerminal(t *testing.T, dbPath, recipient string, timeout time.Duration) (string, string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		states, templates := step275DeliveryState(t, dbPath, recipient)
		if len(states) > 0 {
			switch states[len(states)-1] {
			case "succeeded", "failed", "cancelled":
				return states[len(states)-1], templates[len(templates)-1]
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	states, _ := step275DeliveryState(t, dbPath, recipient)
	t.Fatalf("投递记录未在 %s 内达到终态（当前=%v）", timeout, states)
	return "", ""
}

// TestStep275DirectManagementNoticeTerminalState 验证直接改名安全告知的真实投递终态。
func TestStep275DirectManagementNoticeTerminalState(t *testing.T) {
	ctx := context.Background()
	mail := mailtest.Start(t, mailtest.Options{Required: true, SMTPAuthNone: true})
	clock := &step275Clock{now: time.Date(2026, 11, 26, 6, 0, 0, 0, time.UTC)}
	runtime, dbPath := step275OpenRuntime(t, mail.Addr().String(), clock)
	local := runtime.LocalAdmin()

	target, err := runtime.Users().Create(ctx, app.CreateUserRequest{
		Username: "notify-target-275", Password: "T6#mX3!vB9@nK2$q",
		Nickname: "通知目标", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建目标用户: %v", err)
	}
	const targetEmail = "notify-target-275@example.test"
	step275VerifiedEmail(t, dbPath, target.ID, targetEmail)
	operator, err := runtime.Users().Create(ctx, app.CreateUserRequest{
		Username: "notify-operator-275", Password: step275DirectPassword,
		Nickname: "通知操作者", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建操作者: %v", err)
	}
	operatorSession, operatorTOTP := step275BindTOTP(t, runtime, clock,
		"notify-operator-275", step275DirectPassword)

	// 宿主自举：登记直接改名权限 + 只读权限并分配角色（会话在授权前建立）。
	permissionKeys := map[string]string{
		"users.read":                  "查看普通用户",
		"users.username.change.other": "直接修改他人用户名",
	}
	permissionIDs := make(map[string]string, len(permissionKeys))
	for key, name := range permissionKeys {
		created, createErr := runtime.Admin().CreatePermission(ctx, app.AdminCreatePermissionRequest{
			Caller: local, ScopeID: "system", Key: key, Name: name,
			Description: "步骤275 回归权限", Limits: "仅临时测试",
			RequestID: login.NewRequestID()})
		if createErr != nil {
			t.Fatalf("登记权限 %s: %v", key, createErr)
		}
		permissionIDs[key] = created.ID
	}
	role, err := runtime.Admin().CreateRole(ctx, app.AdminCreateRoleRequest{
		Caller: local, ScopeID: "system", Key: "notify-operator-275",
		Name: "通知操作者", Description: "步骤275 回归角色", Limits: "仅临时测试",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建操作者角色: %v", err)
	}
	for _, key := range []string{"users.read", "users.username.change.other"} {
		if err := runtime.Admin().AddRolePermission(ctx, app.AdminRolePermissionRequest{
			Caller: local, RoleID: role.ID, PermissionID: permissionIDs[key],
			RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("角色添加权限 %s: %v", key, err)
		}
	}
	if err := runtime.Admin().GrantApplicationRole(ctx, app.GrantRoleRequest{
		Caller: local, UserID: operator.ID, RoleID: role.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("分配操作者角色: %v", err)
	}
	adminCaller := runtime.AdminSession(operatorSession)
	profile, err := runtime.Admin().GetUserProfile(ctx, app.AdminUserRequest{
		Caller: adminCaller, UserID: target.ID, RequestID: login.NewRequestID()})
	if err != nil || profile.RowVersion < 1 {
		t.Fatalf("读取目标行版本: %+v err=%v", profile, err)
	}

	// 目标绑定一次性两步验证证明（密码 + 程序化 TOTP）。
	proof := runtime.OperationProof()
	challenge, err := proof.Begin(ctx, app.OperationProofBeginRequest{
		Caller: adminCaller, TargetUserID: target.ID,
		Operation: app.OperationProofUsernameChange, NewUsername: "notify-target-renamed-275",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("发起直接改名证明: %v", err)
	}
	clock.Advance(30 * time.Second)
	code, err := step275TOTP(operatorTOTP, clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	grant, err := proof.Confirm(ctx, app.OperationProofConfirmRequest{
		Caller: adminCaller, ChallengeID: challenge.ChallengeID,
		Password: step275DirectPassword, TOTPCode: code,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("确认直接改名证明: %v", err)
	}
	updated, err := runtime.DirectUserManagement().ChangeUserUsername(ctx,
		app.AdminChangeUserUsernameRequest{Caller: adminCaller, TargetUserID: target.ID,
			NewUsername: "notify-target-renamed-275", ExpectedRowVersion: profile.RowVersion,
			Reason: "步骤275 直接管理告知回归", ProofToken: grant.ProofToken,
			RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("直接改名: %v", err)
	}
	if updated.UserID != target.ID || updated.Username != "notify-target-renamed-275" {
		t.Fatalf("直接改名结果异常: %+v", updated)
	}

	// 真实 Mail 收到安全告知；投递记录终态为 succeeded（不是 queued）。
	waitCtx, waitCancel := context.WithTimeout(ctx, 20*time.Second)
	defer waitCancel()
	messages, err := mail.WaitMessage(waitCtx, mailtest.Query{To: targetEmail})
	if err != nil || len(messages) != 1 {
		t.Fatalf("本地 Mail 安全告知 = %d 封 err=%v（期望恰好 1 封）", len(messages), err)
	}
	state, template := waitStep275DeliveryTerminal(t, dbPath, targetEmail, 20*time.Second)
	if state != "succeeded" {
		t.Fatalf("投递终态 = %q，期望 succeeded（queued 不代表已送达）", state)
	}
	if template != "security_notice" {
		t.Fatalf("投递模板 = %q，期望 security_notice", template)
	}
	// 直接操作结果与投递终态解耦：通知终态不改变已成功的业务结果。
	profileAfter, err := runtime.Admin().GetUserProfile(ctx, app.AdminUserRequest{
		Caller: adminCaller, UserID: target.ID, RequestID: login.NewRequestID()})
	if err != nil || profileAfter.Username != "notify-target-renamed-275" {
		t.Fatalf("投递期间直接改名结果不稳定: %+v err=%v", profileAfter, err)
	}
}
