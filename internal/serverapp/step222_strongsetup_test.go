package serverapp

// 步骤 222 / R10-11（SEC209 N1）：强认证初始化类别来源必须对非 root 用户复算
// protectedRecoveryTarget。覆盖过渡态：人工恢复 MFA 重置时仍是普通用户、在重绑完成
// 前被授予高权限的用户，必须只允许抗钓鱼的 Passkey；Passkey 未启用时拒绝，不降级
// TOTP。同时保留 root 固定 Passkey、普通重绑用户按配置类别、无重绑需求拒绝。

import (
	"context"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/authfact"
)

const (
	step222RootUser    = "usr_00000000000000000000000000000221"
	step222HighUser    = "usr_00000000000000000000000000000222"
	step222NormalUser  = "usr_00000000000000000000000000000223"
	step222NoRebind    = "usr_00000000000000000000000000000224"
	step222RequestID   = "req_step222_strongsetup"
	step222RoleID      = "role_0000000000000000000000000000022a"
	step222RebindTable = "mfa_rebind_requirements"
)

// step222OpenBase 构造真实共享装配（含生产安全域），用于直接构造并验证
// rootStrongSetupAuthorizer 的生产行为。
func step222OpenBase(t *testing.T) *Base {
	t.Helper()
	cfg := baseTestConfig(t)
	cfg.Passkey.Enabled = true
	cfg.Passkey.RPID = "login.example.test"
	cfg.Passkey.RPDisplayName = "EvernightLogin Test"
	cfg.Passkey.AllowedOrigins = []string{"https://login.example.test"}
	cfg.Passkey.UserVerification = "required"
	ctx := context.Background()
	base, err := OpenBase(ctx, BaseOptions{
		Config: cfg, Keyring: newTestKeyring(t), Migrate: true,
		Logger: baseTestLogger(), Now: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("OpenBase: %v", err)
	}
	t.Cleanup(func() { _ = base.Close(context.Background()) })
	if base.Managed == nil || base.Managed.Checker == nil || base.Managed.Roots == nil ||
		base.Services == nil || base.Services.BootstrapStore == nil {
		t.Fatal("生产授权适配层未装配")
	}
	nowMS := testNow.UnixMilli()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, execErr := base.Store.DB().ExecContext(context.Background(), query, args...); execErr != nil {
			t.Fatalf("播种测试数据失败: %v\nSQL: %s", execErr, query)
		}
	}
	seedUser := func(userID, username string, isRoot int) {
		exec(`INSERT INTO users(id,username,username_normalized,nickname,biography,avatar_ref,
language,timezone,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,?, '',NULL,'zh-CN','Asia/Shanghai','active',?,1,1,?,?)`,
			userID, username, username, username, isRoot, nowMS, nowMS)
	}
	seedUser(step222RootUser, "step222-root", 1)
	seedUser(step222HighUser, "step222-high", 0)
	seedUser(step222NormalUser, "step222-normal", 0)
	seedUser(step222NoRebind, "step222-norebind", 0)
	// 预设管理角色（protectedRecoveryTarget 的预设角色判定路径）。
	exec(`INSERT INTO roles(id,scope_id,role_key,name,description,limits_text,
is_builtin,enabled,created_at_ms,updated_at_ms)
VALUES(?, 'system','system_admin','系统管理员','测试用预设管理角色','测试用',
0,1,?,?)`, step222RoleID, nowMS, nowMS)
	exec(`INSERT INTO user_roles(user_id,role_id,scope_id,data_scope_json,assigned_by,created_at_ms)
VALUES(?,?,'system','{}','step222-test',?)`, step222HighUser, step222RoleID, nowMS)
	// 高权限用户与普通用户都有未清除重绑需求；第四个用户没有需求。
	for _, userID := range []string{step222HighUser, step222NormalUser} {
		exec(`INSERT INTO `+step222RebindTable+`(user_id,required_at_ms,reason_code,
source_request_id,cleared_at_ms) VALUES(?,?,'manual_recovery_mfa_reset',?,NULL)`,
			userID, nowMS, step222RequestID)
	}
	return base
}

// step222Authorizer 直接构造被测生产授权器（字段均为生产装配真实依赖）。
func step222Authorizer(base *Base, passkeyEnabled bool) rootStrongSetupAuthorizer {
	return rootStrongSetupAuthorizer{
		store: base.Services.BootstrapStore, roots: base.Managed.Roots,
		rebind:         mfaRebindRequirementStore{store: base.Store},
		rebindMethods:  []authfact.Method{authfact.MethodTOTP},
		passkeyEnabled: passkeyEnabled, checker: base.Managed.Checker,
		protectedStore: base.Store,
	}
}

func TestStep222AllowedStrongSetupMethodsProtectedTransition(t *testing.T) {
	ctx := context.Background()
	base := step222OpenBase(t)
	authorizer := step222Authorizer(base, true)

	// root：固定只允许 Passkey。
	methods, err := authorizer.AllowedStrongSetupMethods(ctx, step222RootUser)
	if err != nil || len(methods) != 1 || methods[0] != authfact.MethodPasskey {
		t.Fatalf("root 允许类别 = %v err=%v，期望仅 Passkey", methods, err)
	}
	// root + Passkey 未启用：拒绝，不降级 TOTP。
	if _, err := step222Authorizer(base, false).AllowedStrongSetupMethods(ctx,
		step222RootUser); err == nil {
		t.Fatal("Passkey 未启用时 root 强认证初始化必须拒绝")
	}

	// 高权限过渡态：重置后、重绑完成前被授予预设管理角色 → 仅 Passkey。
	methods, err = authorizer.AllowedStrongSetupMethods(ctx, step222HighUser)
	if err != nil || len(methods) != 1 || methods[0] != authfact.MethodPasskey {
		t.Fatalf("高权限过渡态允许类别 = %v err=%v，期望仅 Passkey（不允许 TOTP）",
			methods, err)
	}
	// 高权限过渡态 + Passkey 未启用：拒绝。
	if _, err := step222Authorizer(base, false).AllowedStrongSetupMethods(ctx,
		step222HighUser); err == nil {
		t.Fatal("Passkey 未启用时高权限过渡态必须拒绝，不能降级 TOTP")
	}

	// 普通重绑用户：按配置允许类别（TOTP），不受高权限判定误伤。
	methods, err = authorizer.AllowedStrongSetupMethods(ctx, step222NormalUser)
	if err != nil || len(methods) != 1 || methods[0] != authfact.MethodTOTP {
		t.Fatalf("普通重绑用户允许类别 = %v err=%v，期望仅 TOTP", methods, err)
	}

	// 无重绑需求的普通用户：拒绝进入受限强初始化。
	if _, err := authorizer.AllowedStrongSetupMethods(ctx, step222NoRebind); err == nil {
		t.Fatal("无重绑需求用户不得进入受限强认证初始化")
	}
}
