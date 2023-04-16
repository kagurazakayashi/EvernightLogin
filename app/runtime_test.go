package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

func testConfig() login.Config {
	cfg := login.Default()
	cfg.Registration.Enabled = true
	cfg.Registration.RequireReview = false
	cfg.Registration.RequireEmailVerification = false
	return cfg
}

func TestOpenEnsureRootUsersLoginAccessRevokeClose(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig()
	ctx := context.Background()
	runtime, err := Open(ctx, Options{
		Config: &cfg, DatabasePath: filepath.Join(dir, "login.db"),
		MasterKeyFile: filepath.Join(dir, "master.key"), CreateMasterKey: true,
		Migrate: true, OperatorID: "embedded-test", Now: time.Now,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	if runtime.Instance() == nil || runtime.Instance().State() != login.StateNew {
		t.Fatalf("Instance 必须是 StateNew")
	}
	root, err := runtime.Bootstrap().EnsureRoot(ctx, RootRequest{
		DisplayName: "Root", Password: "V7!qZ2#Lm9@Tp4$x", RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("EnsureRoot: %v", err)
	}
	if root.UserID == "" || root.State == "" {
		t.Fatalf("root 结果不完整: %+v", root)
	}
	if _, err := runtime.Bootstrap().EnsureRoot(ctx, RootRequest{Password: "H4%tY7^cN2&mQ9*p"}); err == nil {
		t.Fatal("重复初始化应被拒绝")
	}
	user, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "alice", Password: "K8$wR3!nB6@yF1#v", Nickname: "Alice",
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if user.ID == "" || user.Status != "active" {
		t.Fatalf("用户结果异常: %+v", user)
	}
	loginResult, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: "alice", Password: "K8$wR3!nB6@yF1#v", ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if len(loginResult.SessionSecret) == 0 || loginResult.SessionID == "" {
		t.Fatalf("登录未返回会话秘密")
	}
	decision, err := runtime.Access().Check(ctx, AccessRequest{
		UserID: user.ID, Permission: "authorization.check", Mode: "all",
	})
	if err != nil {
		t.Fatalf("权限检查错误: %v", err)
	}
	if decision.Allowed {
		t.Fatalf("未授权用户不应允许: %+v", decision)
	}
	if decision.Code == "" {
		t.Fatalf("拒绝必须有稳定码: %+v", decision)
	}
	if err := runtime.Sessions().Revoke(ctx, loginResult.SessionSecret); err != nil {
		t.Fatalf("撤销会话: %v", err)
	}
	if err := runtime.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := runtime.Close(ctx); err != nil {
		t.Fatalf("重复 Close 应安全: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "login.db")); err != nil {
		t.Fatalf("数据库文件应存在: %v", err)
	}
}

func TestOpenMigrateFalseFailsOnEmptyDatabase(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig()
	_, err := Open(context.Background(), Options{
		Config: &cfg, DatabasePath: filepath.Join(dir, "login.db"),
		MasterKeyFile: filepath.Join(dir, "master.key"), CreateMasterKey: true,
		Migrate: false, OperatorID: "embedded-test",
	})
	if err == nil {
		t.Fatal("未迁移库必须 fail-closed")
	}
}

func TestOpenMissingKeyWithoutCreateFails(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig()
	_, err := Open(context.Background(), Options{
		Config: &cfg, DatabasePath: filepath.Join(dir, "login.db"),
		MasterKeyFile: filepath.Join(dir, "master.key"), CreateMasterKey: false,
		Migrate: true, OperatorID: "embedded-test",
	})
	if err == nil {
		t.Fatal("缺主密钥且不允许创建时必须 fail-closed")
	}
}
