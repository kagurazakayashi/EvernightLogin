package authn_test

// 步骤 287 本地维护凭证状态窄方法定向测试。
//
// 覆盖：无密码/已有密码状态、root 标记、非法用户 ID、空本地身份、构造校验；
// 只读语义（不修改安全版本/凭证），不返回密码或哈希。

import (
	"context"
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
)

// TestLocalMaintenanceCredentialStatus 覆盖凭证状态查询与只读语义。
func TestLocalMaintenanceCredentialStatus(t *testing.T) {
	env := newTestEnv(t)
	caller, err := authn.NewLocalMaintenanceCaller("os:tester@local")
	if err != nil {
		t.Fatalf("本地维护身份: %v", err)
	}
	userID := env.insertUser("status-user", account.StatusActive, false)
	status, err := env.service.LocalMaintenanceCredentialStatus(context.Background(),
		caller, userID)
	if err != nil {
		t.Fatalf("无密码状态查询: %v", err)
	}
	if status.UserID != userID || status.HasPassword || status.IsRoot {
		t.Fatalf("无密码状态异常: %+v", status)
	}
	env.setPassword(userID, "StatusPass!Tr9x", false)
	status, err = env.service.LocalMaintenanceCredentialStatus(context.Background(),
		caller, userID)
	if err != nil {
		t.Fatalf("有密码状态查询: %v", err)
	}
	if !status.HasPassword || status.IsRoot {
		t.Fatalf("有密码状态异常: %+v", status)
	}
	// 本地维护设置密码：跳过近期再次认证，但复用密码策略/哈希/审计事务。
	localResult, err := env.service.LocalMaintenanceSetPassword(context.Background(),
		caller, userID, "LocalMaintenance!Pass9", true, "req-local-set-password")
	if err != nil {
		t.Fatalf("本地维护设置密码: %v", err)
	}
	if localResult.UserID != userID || localResult.SecurityVersion <= 0 {
		t.Fatalf("本地维护设置密码结果异常: %+v", localResult)
	}
	status, err = env.service.LocalMaintenanceCredentialStatus(context.Background(),
		caller, userID)
	if err != nil || !status.HasPassword {
		t.Fatalf("本地设密后凭证状态异常: %+v err=%v", status, err)
	}
	if _, err := env.service.LocalMaintenanceSetPassword(context.Background(),
		authn.LocalMaintenanceCaller{}, userID, "Another!Pass9", false,
		"req-local-set-password-empty"); !errors.Is(err, authn.ErrAccessDenied) {
		t.Fatalf("空本地身份设密错误 = %v，期望 ErrAccessDenied", err)
	}
	rootID := env.insertUser("root", account.StatusActive, true)
	rootStatus, err := env.service.LocalMaintenanceCredentialStatus(context.Background(),
		caller, rootID)
	if err != nil {
		t.Fatalf("root 状态查询: %v", err)
	}
	if !rootStatus.IsRoot || rootStatus.HasPassword {
		t.Fatalf("root 状态异常: %+v", rootStatus)
	}
	// 非法用户 ID / 不存在用户 / 空本地身份都必须明确失败。
	if _, err := env.service.LocalMaintenanceCredentialStatus(context.Background(),
		caller, "bad-id"); !errors.Is(err, authn.ErrInvalidRequest) {
		t.Fatalf("非法用户 ID 错误 = %v，期望 ErrInvalidRequest", err)
	}
	if _, err := env.service.LocalMaintenanceCredentialStatus(context.Background(),
		caller, "usr_0000000000000000000000000000ffff"); !errors.Is(
		err, authn.ErrUserNotFound) {
		t.Fatalf("不存在用户错误 = %v，期望 ErrUserNotFound", err)
	}
	if _, err := env.service.LocalMaintenanceCredentialStatus(context.Background(),
		authn.LocalMaintenanceCaller{}, userID); !errors.Is(err, authn.ErrAccessDenied) {
		t.Fatalf("空本地身份错误 = %v，期望 ErrAccessDenied", err)
	}
	if _, err := authn.NewLocalMaintenanceCaller(""); err == nil {
		t.Fatal("空操作者标识应构造失败")
	}
}

// TestLocalMaintenanceSetRootPasswordReady 覆盖 MEDIUM-1：Ready 实例本地救援
// 重设 root 密码；普通 SetRootPassword 仍按状态机拒绝；旧密码失效、新密码可登录。
func TestLocalMaintenanceSetRootPasswordReady(t *testing.T) {
	env := newTestEnv(t)
	rootID := env.insertUser("root", account.StatusActive, true)
	nowMS := env.clock.Now().UnixMilli()
	if _, err := env.raw.DB().ExecContext(context.Background(), `INSERT INTO root_initializations(
singleton,root_user_id,state,setup_credential_id,started_by,created_at_ms,updated_at_ms,
verified_at_ms,ready_at_ms) VALUES(1,?,'ready',NULL,'os:tester',?,?,?,?)`,
		rootID, nowMS, nowMS, nowMS, nowMS); err != nil {
		t.Fatalf("构造 Ready 初始化记录: %v", err)
	}
	// 普通本地初始化路径仍拒绝 Ready。
	if _, err := env.service.SetRootPassword(context.Background(), env.localCaller,
		authn.SetRootPasswordRequest{RootUserID: rootID, NewPassword: "OldPass!Tr9x",
			RequestID: "req-normal-root-ready"}); !errors.Is(err, authn.ErrSetupCompleted) {
		t.Fatalf("普通 SetRootPassword Ready 错误 = %v，期望 ErrSetupCompleted", err)
	}
	caller, err := authn.NewLocalMaintenanceCaller("os:tester@local")
	if err != nil {
		t.Fatalf("本地维护身份: %v", err)
	}
	first, err := env.service.LocalMaintenanceSetRootPassword(context.Background(), caller, rootID,
		"OldPass!Tr9x", "req-local-root-password-1")
	if err != nil {
		t.Fatalf("Ready 实例本地设置 root 密码（首次）: %v", err)
	}
	if first.RootUserID != rootID || first.SecurityVersion <= 0 {
		t.Fatalf("首次 root 设密结果异常: %+v", first)
	}
	second, err := env.service.LocalMaintenanceSetRootPassword(context.Background(), caller, rootID,
		"NewPass!Wm4z", "req-local-root-password-2")
	if err != nil {
		t.Fatalf("Ready 实例本地重设 root 密码: %v", err)
	}
	if second.SecurityVersion <= first.SecurityVersion {
		t.Fatalf("安全版本应递增: first=%d second=%d",
			first.SecurityVersion, second.SecurityVersion)
	}
	// 旧密码失效、新密码可认证（root 可能仍需强认证，但密码验证错误应为 nil）。
	if _, authErr := env.service.Authenticate(context.Background(), authn.AuthenticateRequest{
		Identifier: "root", Password: "OldPass!Tr9x", ClientIP: "127.0.0.1",
		RequestID: "req-auth-old"}); authErr == nil {
		t.Fatal("旧 root 密码不应再通过认证")
	}
	if _, authErr := env.service.Authenticate(context.Background(), authn.AuthenticateRequest{
		Identifier: "root", Password: "NewPass!Wm4z", ClientIP: "127.0.0.1",
		RequestID: "req-auth-new"}); authErr != nil {
		t.Fatalf("新 root 密码应通过密码认证: %v", authErr)
	}
	// 空本地身份拒绝。
	if _, err := env.service.LocalMaintenanceSetRootPassword(context.Background(),
		authn.LocalMaintenanceCaller{}, rootID, "Another!Pass3",
		"req-local-root-empty"); !errors.Is(err, authn.ErrAccessDenied) {
		t.Fatalf("空本地身份 root 设密错误 = %v，期望 ErrAccessDenied", err)
	}
}
