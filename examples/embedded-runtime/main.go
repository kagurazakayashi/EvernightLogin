// Command embedded-runtime 是步骤 138/A01、180、181 的真独立模块验收示例。
//
// 它使用自己的 go.mod（replace 指向仓库根），只导入公开包
// github.com/kagurazakayashi/EvernightLogin 与 .../app；Go 的 internal 规则禁止
// 模块外导入 internal，因此能编译运行即证明公开装配 API 未泄漏 internal 类型。
//
// 覆盖场景：
//   - Open 只构造运行时（StateNew），不启动后台任务；未 Start 时 Ready 报未运行；
//   - 真实临时 SQLite + 临时主密钥完成 root 初始化、创建用户、登录、权限检查、
//     撤销会话；
//   - 步骤 181：密码登录 -> TOTP 第二因素限制状态 -> 错误因素拒绝 -> 正确 TOTP
//     补充验证 -> 完整会话；敏感操作再次认证（错误密码拒绝）；恢复代码需近期强
//     认证，使用后只进入受限恢复会话（不能访问业务）；Passkey 关闭时 TOTP 仍可用；
//     关闭自助注册只影响注册入口，已有账户仍可登录；
//   - 显式 Start 启动允许的后台任务；重复 Start 返回 ErrAlreadyStarted；
//   - Close 幂等；宿主注入的数据库/通知器不被运行时关闭；
//   - 启动前取消 fail-closed（实例进入 closed），之后只能 Close；
//   - 迁移未完成时 Open fail-closed，且失败路径不遗留数据库句柄。
//
// TOTP 验证码由示例按 RFC 6238（SHA1/6 位/30 秒）用绑定返回的种子自行计算，等价
// 于用户手机上的验证器 App；示例不导入 internal、不使用伪造强认证结果。
// 邮件保持未配置（显式失败发送器，不访问网络）；真实本地 EvernightMail 邮件流程
// 由步骤 197 单独验收。
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/app"
)

// exampleClock 是可推进的确定性时钟；所有领域服务与示例的 TOTP 计算共用它。
type exampleClock struct {
	mu  sync.Mutex
	now time.Time
}

// Now 实现 func() time.Time。
func (c *exampleClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance 推进时钟（TOTP 时间步为 30 秒）。
func (c *exampleClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

// totpCode 按 RFC 6238（SHA1、6 位、30 秒步长）计算验证码；等价于验证器 App。
func totpCode(encodedSecret string, at time.Time) (string, error) {
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

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "embedded-runtime 验收失败:", err)
		os.Exit(1)
	}
	fmt.Println("embedded-runtime 验收通过：公开 app 包完成 TOTP 第二因素/敏感操作再次认证/受限恢复/显式启动/取消/重复关闭/宿主资源所有权/失败清理")
}

func run() error {
	dir, err := os.MkdirTemp("", "evernightlogin-embedded-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	cfg := login.Default()
	cfg.Registration.Enabled = true
	cfg.Registration.RequireReview = false
	cfg.Registration.RequireEmailVerification = false
	ctx := context.Background()
	clock := &exampleClock{now: time.Date(2026, 11, 23, 6, 0, 0, 0, time.UTC)}
	hostDatabase := &fakeDatabase{}
	notifier := &captureNotifier{}
	databasePath := filepath.Join(dir, "login.db")
	masterKeyPath := filepath.Join(dir, "master.key")
	runtime, err := app.Open(ctx, app.Options{
		Config: &cfg, DatabasePath: databasePath,
		MasterKeyFile: masterKeyPath, CreateMasterKey: true,
		Migrate: true, OperatorID: "embedded-example", Now: clock.Now,
		Database: hostDatabase, Notifier: notifier,
	})
	if err != nil {
		return fmt.Errorf("Open: %w", err)
	}
	defer func() { _ = runtime.Close(context.Background()) }()
	if runtime.State() != login.StateNew {
		return fmt.Errorf("Open 后状态必须为 new（未启动），实际 %q", runtime.State())
	}
	if err := runtime.Ready(ctx); !errors.Is(err, login.ErrNotRunning) {
		return fmt.Errorf("未 Start 时 Ready 应返回 ErrNotRunning，实际 %v", err)
	}
	if runtime.Instance() == nil || runtime.Instance().State() != login.StateNew {
		return fmt.Errorf("Open 后实例必须为 StateNew（未启动）")
	}
	root, err := runtime.Bootstrap().EnsureRoot(ctx, app.RootRequest{
		DisplayName: "Root", Password: "V7!qZ2#Lm9@Tp4$x", RequestID: login.NewRequestID(),
	})
	if err != nil {
		return fmt.Errorf("EnsureRoot: %w", err)
	}
	if root.UserID == "" {
		return fmt.Errorf("EnsureRoot 未返回 root 用户")
	}
	const alicePassword = "K8$wR3!nB6@yF1#v"
	user, err := runtime.Users().Create(ctx, app.CreateUserRequest{
		Username: "alice", Password: alicePassword, Nickname: "Alice",
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		return fmt.Errorf("Users.Create: %w", err)
	}
	loginResult, err := runtime.Auth().Login(ctx, app.LoginRequest{
		Username: "alice", Password: alicePassword, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		return fmt.Errorf("Auth.Login: %v", err)
	}
	if loginResult.Restricted || len(loginResult.SessionSecret) == 0 {
		return fmt.Errorf("未启用第二因素的账户应得到完整会话: %+v", loginResult)
	}
	decision, err := runtime.Access().Check(ctx, app.AccessRequest{
		UserID: user.ID, Permission: "authorization.check", Mode: "all",
	})
	if err != nil {
		return fmt.Errorf("Access.Check: %w", err)
	}
	if decision.Allowed || decision.Code == "" {
		return fmt.Errorf("未授权用户应被拒绝并有稳定码: %+v", decision)
	}

	// ===== 步骤 181：真实 TOTP 第二因素与敏感操作再次认证 =====
	if _, err := runtime.Security().BeginTOTPBinding(ctx, app.TOTPBindingBeginRequest{
		SessionSecret: loginResult.SessionSecret, Password: "wrong-password",
		RequestID: login.NewRequestID(),
	}); err == nil {
		return fmt.Errorf("错误密码不应通过敏感操作再次认证")
	}
	start, err := runtime.Security().BeginTOTPBinding(ctx, app.TOTPBindingBeginRequest{
		SessionSecret: loginResult.SessionSecret, Password: alicePassword,
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		return fmt.Errorf("BeginTOTPBinding: %w", err)
	}
	confirmCode, err := totpCode(start.Secret, clock.Now())
	if err != nil {
		return err
	}
	if _, err := runtime.Security().ConfirmTOTPBinding(ctx, app.TOTPBindingConfirmRequest{
		SessionSecret: loginResult.SessionSecret, BindingID: start.BindingID,
		Code: confirmCode, RequestID: login.NewRequestID(),
	}); err != nil {
		return fmt.Errorf("ConfirmTOTPBinding: %w", err)
	}
	// 下一个时间步登录：密码第一步后必须是受限会话 + TOTP 挑战。
	clock.Advance(30 * time.Second)
	restricted, err := runtime.Auth().Login(ctx, app.LoginRequest{
		Username: "alice", Password: alicePassword, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		return fmt.Errorf("启用 TOTP 后密码第一步失败: %w", err)
	}
	if !restricted.Restricted || restricted.SecondFactor == nil ||
		restricted.SecondFactor.FactorType != "totp" || len(restricted.SessionSecret) == 0 {
		return fmt.Errorf("TOTP 账户应返回受限会话与 TOTP 挑战: %+v", restricted)
	}
	verify := app.VerifySecondFactorRequest{
		SessionSecret: restricted.SessionSecret,
		ChallengeID:   restricted.SecondFactor.ChallengeID,
		AttemptToken:  restricted.SecondFactor.AttemptToken,
		RequestID:     login.NewRequestID(),
	}
	wrongVerify := verify
	wrongVerify.Code = "000000"
	if _, err := runtime.Auth().VerifySecondFactor(ctx, wrongVerify); err == nil {
		return fmt.Errorf("错误 TOTP 验证码不应通过")
	}
	correctCode, err := totpCode(start.Secret, clock.Now())
	if err != nil {
		return err
	}
	verify.Code = correctCode
	verified, err := runtime.Auth().VerifySecondFactor(ctx, verify)
	if err != nil {
		return fmt.Errorf("正确 TOTP 未通过第二步: %w", err)
	}
	if len(verified.SessionSecret) == 0 || verified.Method != "totp" {
		return fmt.Errorf("第二步结果异常: %+v", verified)
	}
	status, err := runtime.Security().Status(ctx, app.SecurityStatusRequest{
		SessionSecret: verified.SessionSecret})
	if err != nil {
		return fmt.Errorf("Security.Status: %w", err)
	}
	if !status.TOTPActive || !status.StrongFactorBound {
		return fmt.Errorf("TOTP/强因素状态异常: %+v", status)
	}
	if status.PasskeyEnabled {
		return fmt.Errorf("默认配置 Passkey 应关闭（关闭 Passkey 不影响 TOTP）: %+v", status)
	}
	// 恢复代码：只有密码时 fail-closed；密码 + TOTP 的近期强认证才允许生成。
	clock.Advance(30 * time.Second)
	if _, err := runtime.Security().GenerateRecoveryCodes(ctx, app.RecoveryCodesRequest{
		SessionSecret: verified.SessionSecret, Password: alicePassword,
		RequestID: login.NewRequestID(),
	}); err == nil {
		return fmt.Errorf("已绑定强因素的账户生成恢复代码必须要求近期强认证")
	}
	recoveryTOTP, err := totpCode(start.Secret, clock.Now())
	if err != nil {
		return err
	}
	codes, err := runtime.Security().GenerateRecoveryCodes(ctx, app.RecoveryCodesRequest{
		SessionSecret: verified.SessionSecret, Password: alicePassword,
		TOTPCode: recoveryTOTP, RequestID: login.NewRequestID(),
	})
	if err != nil {
		return fmt.Errorf("GenerateRecoveryCodes: %w", err)
	}
	if len(codes.Codes) == 0 {
		return fmt.Errorf("恢复代码为空")
	}
	// 恢复代码只替代第二步：进入受限恢复会话，不能访问业务。
	clock.Advance(30 * time.Second)
	restrictedForRecovery, err := runtime.Auth().Login(ctx, app.LoginRequest{
		Username: "alice", Password: alicePassword, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		return fmt.Errorf("恢复流程前密码第一步失败: %w", err)
	}
	if !restrictedForRecovery.Restricted || restrictedForRecovery.SecondFactor == nil {
		return fmt.Errorf("恢复流程前应为受限状态: %+v", restrictedForRecovery)
	}
	recoveryRequest := app.BeginRecoveryRequest{
		SessionSecret: restrictedForRecovery.SessionSecret,
		ChallengeID:   restrictedForRecovery.SecondFactor.ChallengeID,
		AttemptToken:  restrictedForRecovery.SecondFactor.AttemptToken,
		RecoveryCode:  "00000000-0000-0000-0000-000000000000",
		RequestID:     login.NewRequestID(),
	}
	if _, err := runtime.Auth().BeginRecovery(ctx, recoveryRequest); err == nil {
		return fmt.Errorf("错误恢复代码不应进入受限恢复会话")
	}
	recoveryRequest.RecoveryCode = codes.Codes[0]
	recoverySession, err := runtime.Auth().BeginRecovery(ctx, recoveryRequest)
	if err != nil {
		return fmt.Errorf("BeginRecovery: %w", err)
	}
	if len(recoverySession.SessionSecret) == 0 || recoverySession.RequiredStrength != "strong" {
		return fmt.Errorf("受限恢复会话异常: %+v", recoverySession)
	}
	if len(recoverySession.AllowedMethods) != 1 || recoverySession.AllowedMethods[0] != "passkey" {
		return fmt.Errorf("强认证恢复只允许 Passkey 重绑: %+v", recoverySession.AllowedMethods)
	}
	if _, err := runtime.Security().Status(ctx, app.SecurityStatusRequest{
		SessionSecret: recoverySession.SessionSecret}); err == nil {
		return fmt.Errorf("受限恢复会话不应访问完整会话操作")
	}
	recoveryStatus, err := runtime.Auth().RecoveryStatus(ctx, app.RecoveryStatusRequest{
		SessionSecret: recoverySession.SessionSecret})
	if err != nil {
		return fmt.Errorf("RecoveryStatus: %w", err)
	}
	if recoveryStatus.CodesRemaining != len(codes.Codes)-1 {
		return fmt.Errorf("恢复代码剩余异常: %d（期望 %d）",
			recoveryStatus.CodesRemaining, len(codes.Codes)-1)
	}
	// 原完整会话仍可用于撤销（绑定因素不提升/不伪造已有会话）。
	if err := runtime.Sessions().Revoke(ctx, loginResult.SessionSecret); err != nil {
		return fmt.Errorf("Sessions.Revoke: %w", err)
	}

	// 显式启动允许的后台任务；重复启动返回 ErrAlreadyStarted。
	if err := runtime.Start(ctx); err != nil {
		return fmt.Errorf("Start: %w", err)
	}
	if runtime.State() != login.StateRunning {
		return fmt.Errorf("Start 后状态应为 running，实际 %q", runtime.State())
	}
	if err := runtime.Start(ctx); !errors.Is(err, login.ErrAlreadyStarted) {
		return fmt.Errorf("重复 Start 应返回 ErrAlreadyStarted，实际 %v", err)
	}
	if err := runtime.Ready(ctx); err != nil {
		return fmt.Errorf("Ready: %w", err)
	}
	if err := runtime.Close(ctx); err != nil {
		return fmt.Errorf("Close: %v", err)
	}
	if err := runtime.Close(ctx); err != nil {
		return fmt.Errorf("重复 Close 应安全: %v", err)
	}
	// 宿主资源所有权：运行时绝不关闭宿主注入的数据库/通知器。
	if hostDatabase.isClosed() {
		return fmt.Errorf("运行时不关闭宿主数据库")
	}
	if events := notifier.snapshot(); len(events) != 2 ||
		events[0].Kind != login.LifecycleStarted || events[1].Kind != login.LifecycleClosed {
		return fmt.Errorf("生命周期通知异常: %+v", events)
	}

	// 关闭自助注册：公开创建入口 reject，已有账户仍可登录（进入 TOTP 受限状态）。
	closedRegistration := runtime.Config()
	closedRegistration.Registration.Enabled = false
	closedRuntime, err := app.Open(ctx, app.Options{
		Config: &closedRegistration, DatabasePath: databasePath,
		MasterKeyFile: masterKeyPath, CreateMasterKey: false,
		Migrate: true, OperatorID: "embedded-example", Now: clock.Now,
	})
	if err != nil {
		return fmt.Errorf("Open（关闭注册场景）: %w", err)
	}
	if _, err := closedRuntime.Users().Create(ctx, app.CreateUserRequest{
		Username: "dave", Password: "Q6#zX2!cV8@bN4%m",
		RequestID: login.NewRequestID(),
	}); !login.IsErrorCode(err, login.CodeConfigInvalid) {
		return fmt.Errorf("关闭注册后创建入口应返回 CONFIG_INVALID，实际 %v", err)
	}
	if _, err := closedRuntime.Auth().Login(ctx, app.LoginRequest{
		Username: "alice", Password: alicePassword, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID(),
	}); err != nil {
		return fmt.Errorf("关闭注册不应影响已有账户登录: %w", err)
	}
	if err := closedRuntime.Close(ctx); err != nil {
		return fmt.Errorf("关闭注册场景 Close: %v", err)
	}

	// 启动前取消：fail-closed 且不遗留资源；之后只能 Close。
	cancelled, err := app.Open(ctx, app.Options{
		Config: &cfg, DatabasePath: filepath.Join(dir, "cancelled.db"),
		MasterKeyFile: masterKeyPath, CreateMasterKey: false,
		Migrate: true, OperatorID: "embedded-example", Now: clock.Now,
	})
	if err != nil {
		return fmt.Errorf("Open（取消场景）: %w", err)
	}
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := cancelled.Start(cancelledCtx); err == nil {
		return fmt.Errorf("启动已取消时必须失败")
	}
	if cancelled.State() != login.StateClosed {
		return fmt.Errorf("启动取消后状态必须为 closed，实际 %q", cancelled.State())
	}
	if err := cancelled.Start(context.Background()); !errors.Is(err, login.ErrClosed) {
		return fmt.Errorf("启动失败后再次 Start 应返回 ErrClosed，实际 %v", err)
	}
	if err := cancelled.Close(context.Background()); err != nil {
		return fmt.Errorf("取消场景 Close: %v", err)
	}
	if err := cancelled.Close(context.Background()); err != nil {
		return fmt.Errorf("取消场景重复 Close 应安全: %v", err)
	}

	// 迁移未完成：fail-closed，且失败路径不遗留数据库句柄（临时目录可整体删除）。
	failDir, err := os.MkdirTemp("", "evernightlogin-embedded-fail-")
	if err != nil {
		return err
	}
	_, openErr := app.Open(ctx, app.Options{
		Config: &cfg, DatabasePath: filepath.Join(failDir, "login.db"),
		MasterKeyFile: filepath.Join(failDir, "master.key"), CreateMasterKey: true,
		Migrate: false, OperatorID: "embedded-example", Now: clock.Now,
	})
	if openErr == nil {
		return fmt.Errorf("迁移未完成时 Open 必须 fail-closed")
	}
	if removeErr := os.RemoveAll(failDir); removeErr != nil {
		return fmt.Errorf("失败路径不应遗留数据库句柄: %v", removeErr)
	}
	return nil
}

// fakeDatabase 模拟宿主拥有的数据库连接：运行时只 Ping，绝不关闭。
type fakeDatabase struct {
	mu     sync.Mutex
	pings  int
	closed bool
}

func (d *fakeDatabase) Ping(context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pings++
	return nil
}

func (d *fakeDatabase) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	return nil
}

func (d *fakeDatabase) isClosed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closed
}

// captureNotifier 记录生命周期事件；运行时不关闭它。
type captureNotifier struct {
	mu     sync.Mutex
	events []login.LifecycleEvent
}

func (n *captureNotifier) Notify(_ context.Context, event login.LifecycleEvent) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.events = append(n.events, event)
	return nil
}

func (n *captureNotifier) snapshot() []login.LifecycleEvent {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]login.LifecycleEvent, len(n.events))
	copy(out, n.events)
	return out
}
