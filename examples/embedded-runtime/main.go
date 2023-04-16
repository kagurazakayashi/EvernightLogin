// Command embedded-runtime 是步骤 138/A01 的真独立模块验收示例。
//
// 它使用自己的 go.mod（replace 指向仓库根），只导入公开包
// github.com/kagurazakayashi/EvernightLogin 与 .../app；Go 的 internal 规则禁止
// 模块外导入 internal，因此能编译运行即证明公开装配 API 未泄漏 internal 类型。
//
// 流程：临时 SQLite + 临时主密钥 → Open（不监听/不启动任务）→ EnsureRoot →
// 创建用户 → 登录 → 权限检查（未授权应拒绝）→ 撤销会话 → Close。全部使用真实
// 服务与真实数据库，不使用假数据库/假鉴权。
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/app"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "embedded-runtime 验收失败:", err)
		os.Exit(1)
	}
	fmt.Println("embedded-runtime 验收通过：公开 app 包完成 init/建用户/登录/权限检查/撤销/关闭")
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
	runtime, err := app.Open(ctx, app.Options{
		Config: &cfg, DatabasePath: filepath.Join(dir, "login.db"),
		MasterKeyFile: filepath.Join(dir, "master.key"), CreateMasterKey: true,
		Migrate: true, OperatorID: "embedded-example", Now: time.Now,
	})
	if err != nil {
		return fmt.Errorf("Open: %w", err)
	}
	defer runtime.Close(ctx)
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
	user, err := runtime.Users().Create(ctx, app.CreateUserRequest{
		Username: "alice", Password: "K8$wR3!nB6@yF1#v", Nickname: "Alice",
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		return fmt.Errorf("Users.Create: %w", err)
	}
	loginResult, err := runtime.Auth().Login(ctx, app.LoginRequest{
		Username: "alice", Password: "K8$wR3!nB6@yF1#v", ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		return fmt.Errorf("Auth.Login: %w", err)
	}
	if len(loginResult.SessionSecret) == 0 {
		return fmt.Errorf("Auth.Login 未返回会话秘密")
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
	if err := runtime.Sessions().Revoke(ctx, loginResult.SessionSecret); err != nil {
		return fmt.Errorf("Sessions.Revoke: %w", err)
	}
	if err := runtime.Close(ctx); err != nil {
		return fmt.Errorf("Close: %w", err)
	}
	return nil
}
