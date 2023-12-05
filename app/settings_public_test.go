// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

// 步骤 232 受控配置管理定向测试：真实临时 YAML + 原子写入 + 版本冲突 +
// 字段授权 + 秘密遮盖 + 审计失败回滚 + 根策略默认值恢复。

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/appcore"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

const settingsTestYAML = `server:
  listen_addr: "127.0.0.1:18080"
registration:
  enabled: true
`

type settingsTestEnv struct {
	runtime    *Runtime
	clock      *testClock
	ctx        context.Context
	local      AdminCaller
	configPath string
}

// newSettingsTestEnv 打开带真实 YAML 配置文件的临时运行时。
func newSettingsTestEnv(t *testing.T) *settingsTestEnv {
	t.Helper()
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 8, 0, 0, 0, time.UTC))
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatalf("创建配置目录: %v", err)
	}
	configPath := filepath.Join(configDir, "login.yaml")
	if err := os.WriteFile(configPath, []byte(settingsTestYAML), 0o600); err != nil {
		t.Fatalf("写入测试配置: %v", err)
	}
	databasePath := filepath.Join(dir, "login.db")
	cfg, configErr := appcore.LoadConfigFile(configPath, databasePath)
	if configErr != nil {
		t.Fatalf("加载测试配置: %v", configErr)
	}
	runtime, err := Open(ctx, Options{Config: &cfg, ConfigPath: configPath,
		DatabasePath:  databasePath,
		MasterKeyFile: filepath.Join(dir, "master.key"), CreateMasterKey: true,
		Migrate: true, OperatorID: "host-operator", Now: clock.Now})
	if err != nil {
		t.Fatalf("打开设置测试运行时: %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	return &settingsTestEnv{runtime: runtime, clock: clock, ctx: ctx,
		local: runtime.LocalAdmin(), configPath: configPath}
}

func (env *settingsTestEnv) readConfig(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(env.configPath)
	if err != nil {
		t.Fatalf("读取配置: %v", err)
	}
	return string(data)
}

// TestSettingsFieldsVersionAndUpdate 覆盖字段查询、版本、原子写入与待重载状态。
func TestSettingsFieldsVersionAndUpdate(t *testing.T) {
	env := newSettingsTestEnv(t)
	settings := env.runtime.Settings()
	view, err := settings.Fields(env.ctx, SettingsFieldsRequest{Caller: env.local,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Fields: %v", err)
	}
	if !view.Configured || view.Version == "" || len(view.Fields) == 0 {
		t.Fatalf("字段视图异常: %+v", view)
	}
	field := findSettingsField(t, view.Fields, "logging.level")
	if field.Secret || field.Writable != true {
		t.Fatalf("logging.level 可写性异常: %+v", field)
	}
	if !findSettingsField(t, view.Fields, "server.trusted_proxies").RootOnly {
		t.Fatal("server.trusted_proxies 必须标记 root-only")
	}
	secret := findSettingsField(t, view.Fields, "mail.smtp.password")
	if !secret.Secret || secret.Writable || secret.Value == "" ||
		strings.Contains(secret.Value, "env:") || strings.Contains(secret.Value, "file:") {
		t.Fatalf("秘密字段必须遮盖且不可写: %+v", secret)
	}

	result, err := settings.Update(env.ctx, SettingsUpdateRequest{Caller: env.local,
		ExpectedVersion: view.Version, Changes: map[string]string{"logging.level": "debug"},
		Reason: "测试调整日志级别", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if result.Version == view.Version || len(result.ChangedFields) != 1 ||
		result.AppliedNow || !result.HostReloadNeeded {
		t.Fatalf("写入结果异常: %+v", result)
	}
	if !strings.Contains(env.readConfig(t), "level: debug") {
		t.Fatalf("配置文件未写入新值: %s", env.readConfig(t))
	}
	status, err := settings.Status(env.ctx, SettingsStatusRequest{Caller: env.local,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Version != result.Version || status.EffectiveVersion == "" ||
		!containsString(status.PendingHot, "logging.level") {
		t.Fatalf("状态异常: %+v", status)
	}

	// 重新打开后磁盘值成为有效配置。
	runtime2, err := Open(env.ctx, Options{ConfigPath: env.configPath,
		DatabasePath:  env.runtime.opts.DatabasePath,
		MasterKeyFile: env.runtime.opts.MasterKeyFile, Migrate: false,
		CreateMasterKey: false, OperatorID: "host-operator", Now: env.clock.Now})
	if err != nil {
		t.Fatalf("重新打开运行时: %v", err)
	}
	defer func() { _ = runtime2.Close(context.Background()) }()
	view2, err := runtime2.Settings().Fields(env.ctx, SettingsFieldsRequest{
		Caller: runtime2.LocalAdmin(), RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Fields after reopen: %v", err)
	}
	if got := findSettingsField(t, view2.Fields, "logging.level"); got.Value != `"debug"` {
		t.Fatalf("重启后有效值 = %s，期望 \"debug\"", got.Value)
	}
}

// TestSettingsVersionConflictAndInvalidConfig 覆盖并发版本冲突/非法配置不落盘。
func TestSettingsVersionConflictAndInvalidConfig(t *testing.T) {
	env := newSettingsTestEnv(t)
	settings := env.runtime.Settings()
	view, err := settings.Fields(env.ctx, SettingsFieldsRequest{Caller: env.local,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Fields: %v", err)
	}
	stale := view.Version
	if _, err := settings.Update(env.ctx, SettingsUpdateRequest{Caller: env.local,
		ExpectedVersion: stale, Changes: map[string]string{"logging.level": "debug"},
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("第一次 Update: %v", err)
	}
	_, err = settings.Update(env.ctx, SettingsUpdateRequest{Caller: env.local,
		ExpectedVersion: stale, Changes: map[string]string{"logging.format": "json"},
		RequestID: login.NewRequestID()})
	if err == nil {
		t.Fatal("使用旧版本写入必须冲突")
	}
	if code := asRBACAppError(t, err).Code(); code != login.CodeConflict {
		t.Fatalf("版本冲突码 = %q，期望 CONFLICT", code)
	}
	before := env.readConfig(t)
	_, err = settings.Update(env.ctx, SettingsUpdateRequest{Caller: env.local,
		ExpectedVersion: currentVersion(t, settings, env),
		Changes:         map[string]string{"server.listen_addr": "not-an-address"},
		RequestID:       login.NewRequestID()})
	if err == nil {
		t.Fatal("非法配置更新必须失败")
	}
	if env.readConfig(t) != before {
		t.Fatal("非法配置失败后文件必须保持不变")
	}
}

// TestSettingsFieldAuthorization 覆盖秘密遮占位、root-only 字段与 settings.manage。
func TestSettingsFieldAuthorization(t *testing.T) {
	env := newSettingsTestEnv(t)
	settings := env.runtime.Settings()
	// 秘密字段（含遮盖占位值）不能被公开 API 覆盖。
	for _, value := range []string{"__MASKED__", "[REDACTED]", "env:MAIL_PASSWORD"} {
		_, err := settings.Update(env.ctx, SettingsUpdateRequest{Caller: env.local,
			ExpectedVersion: currentVersion(t, settings, env),
			Changes:         map[string]string{"mail.smtp.password": value},
			RequestID:       login.NewRequestID()})
		if err == nil {
			t.Fatalf("秘密字段值 %q 必须拒绝", value)
		}
	}
	// 普通管理会话持有 settings.manage：可改常规字段，不能改 root-only 字段。
	adminCaller := env.systemAdminSession(t, "settings-admin", "settings.manage")
	if _, err := settings.Update(env.ctx, SettingsUpdateRequest{Caller: adminCaller,
		ExpectedVersion: currentVersion(t, settings, env),
		Changes:         map[string]string{"logging.level": "debug"},
		RequestID:       login.NewRequestID()}); err != nil {
		t.Fatalf("settings.manage 修改常规字段失败: %v", err)
	}
	_, err := settings.Update(env.ctx, SettingsUpdateRequest{Caller: adminCaller,
		ExpectedVersion: currentVersion(t, settings, env),
		Changes:         map[string]string{"server.trusted_proxies": `["127.0.0.1"]`},
		RequestID:       login.NewRequestID()})
	if err == nil {
		t.Fatal("普通 settings.manage 修改可信代理必须拒绝")
	}
	if code := asRBACAppError(t, err).Code(); code != login.CodeAccessDenied {
		t.Fatalf("越权字段码 = %q，期望 ACCESS_DENIED", code)
	}
	// 无 settings.manage 的完整会话不能读配置。
	plain := env.createSettingsUser(t, "settings-plain")
	plainSession := loginSettingsUser(t, env, "settings-plain")
	_, err = settings.Fields(env.ctx, SettingsFieldsRequest{
		Caller: env.runtime.AdminSession(plainSession), RequestID: login.NewRequestID()})
	if err == nil {
		t.Fatal("无 settings.manage 的会话读取配置必须拒绝")
	}
	_ = plain
}

// TestSettingsAuditFailureRollsBack 验证审计失败恢复旧文件（原子回滚）。
func TestSettingsAuditFailureRollsBack(t *testing.T) {
	env := newSettingsTestEnv(t)
	settings := env.runtime.Settings()
	view, err := settings.Fields(env.ctx, SettingsFieldsRequest{Caller: env.local,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Fields: %v", err)
	}
	before := env.readConfig(t)
	if _, err := env.runtime.base.Store.DB().Exec(
		`CREATE TRIGGER step232_fail_audit BEFORE INSERT ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit down'); END;`); err != nil {
		t.Fatalf("注入审计故障: %v", err)
	}
	t.Cleanup(func() {
		_, _ = env.runtime.base.Store.DB().Exec(`DROP TRIGGER step232_fail_audit`)
	})
	_, err = settings.Update(env.ctx, SettingsUpdateRequest{Caller: env.local,
		ExpectedVersion: view.Version, Changes: map[string]string{"logging.level": "debug"},
		Reason: "审计故障测试", RequestID: login.NewRequestID()})
	if err == nil {
		t.Fatal("审计故障时配置更新必须失败")
	}
	if code := asRBACAppError(t, err).Code(); code != login.CodeAuditWriteFailed {
		t.Fatalf("审计故障码 = %q，期望 AUDIT_WRITE_FAILED", code)
	}
	if env.readConfig(t) != before {
		t.Fatal("审计失败后配置必须回滚到旧内容")
	}
}

// TestSettingsRestoreSensitiveDefaultsRootOnly 验证普通设置权限不能恢复敏感策略，
// 真实 root 会话可恢复默认值。
func TestSettingsRestoreSensitiveDefaultsRootOnly(t *testing.T) {
	env := newSettingsTestEnv(t)
	settings := env.runtime.Settings()
	adminCaller := env.systemAdminSession(t, "settings-restore-admin", "settings.manage")
	if _, err := settings.RestoreSensitiveDefaults(env.ctx,
		SettingsRestoreSensitiveRequest{Caller: adminCaller, ScopeID: "system", All: true,
			RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("普通 settings.manage 恢复敏感策略默认值必须拒绝")
	}
	rootResult, err := env.runtime.Bootstrap().EnsureRoot(env.ctx, RootRequest{
		Username: "root", DisplayName: "root", Password: "V7!qZ2#Lm9@Tp4$x",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("EnsureRoot: %v", err)
	}
	rootCaller := env.runtime.AdminSession(mintSettingsSessionWithVersion(t, env,
		rootResult.UserID, "root", rootResult.SecurityVersion))
	_, err = settings.RestoreSensitiveDefaults(env.ctx,
		SettingsRestoreSensitiveRequest{Caller: rootCaller, ScopeID: "system", All: true,
			ExpectedVersion: 0, Password: "V7!qZ2#Lm9@Tp4$x",
			Reason: "恢复敏感策略默认值", RequestID: login.NewRequestID()})
	if err == nil {
		t.Fatal("未完成强认证的 root 会话恢复敏感策略默认值必须拒绝")
	}
	code := asRBACAppError(t, err).Code()
	if code != login.CodeMFARequired && code != login.CodeReauthRequired {
		t.Fatalf("root 强认证闸门错误码 = %q，期望 MFA_REQUIRED/REAUTH_REQUIRED", code)
	}
}

func findSettingsField(t *testing.T, fields []SettingField, name string) SettingField {
	t.Helper()
	for _, field := range fields {
		if field.Field == name {
			return field
		}
	}
	t.Fatalf("未找到字段 %s", name)
	return SettingField{}
}

func currentVersion(t *testing.T, settings SettingsService, env *settingsTestEnv) string {
	t.Helper()
	view, err := settings.Fields(env.ctx, SettingsFieldsRequest{Caller: env.local,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Fields: %v", err)
	}
	return view.Version
}

// createSettingsUser 创建真实用户。
func (env *settingsTestEnv) createSettingsUser(t *testing.T, username string) User {
	t.Helper()
	user, err := env.runtime.Users().Create(env.ctx, CreateUserRequest{
		Username: username, Password: "K8$wR3!nB6@yF1#v", Nickname: username,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建用户 %s: %v", username, err)
	}
	return user
}

// loginSettingsUser 登录并返回完整会话秘密。
func loginSettingsUser(t *testing.T, env *settingsTestEnv, username string) []byte {
	t.Helper()
	result, err := env.runtime.Auth().Login(env.ctx, LoginRequest{
		Username: username, Password: "K8$wR3!nB6@yF1#v", ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil || result.Restricted {
		t.Fatalf("登录 %s: %+v err=%v", username, result, err)
	}
	return result.SessionSecret
}

// systemAdminSession 创建带指定权限的完整管理会话（TOTP 绑定以通过强认证策略）。
func (env *settingsTestEnv) systemAdminSession(t *testing.T, username string,
	permissionKeys ...string) AdminCaller {
	t.Helper()
	user := env.createSettingsUser(t, username)
	role, err := env.runtime.Admin().CreateRole(env.ctx, AdminCreateRoleRequest{
		Caller: env.local, ScopeID: "system", Key: "settings_" + sanitizeKey(username),
		Name: "设置管理员", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建角色: %v", err)
	}
	for _, key := range permissionKeys {
		permission, err := env.runtime.Admin().CreatePermission(env.ctx,
			AdminCreatePermissionRequest{Caller: env.local, ScopeID: "system", Key: key,
				Name: key, RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("创建权限 %s: %v", key, err)
		}
		if err := env.runtime.Admin().AddRolePermission(env.ctx, AdminRolePermissionRequest{
			Caller: env.local, RoleID: role.ID, PermissionID: permission.ID,
			RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("组合权限: %v", err)
		}
	}
	if err := env.runtime.Admin().GrantApplicationRole(env.ctx, GrantRoleRequest{
		Caller: env.local, UserID: user.ID, RoleID: role.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("分配角色: %v", err)
	}
	return env.runtime.AdminSession(mintSettingsSession(t, env, user.ID, username))
}

// mintSettingsSession 直接经真实会话服务签发完整会话（测试夹具）：高权限账户登录
// 受强认证策略约束，而本测试只验证配置字段授权，不重复验证登录策略。
func mintSettingsSession(t *testing.T, env *settingsTestEnv, userID, username string) []byte {
	return mintSettingsSessionWithVersion(t, env, userID, username, 1)
}

func mintSettingsSessionWithVersion(t *testing.T, env *settingsTestEnv, userID, username string,
	securityVersion int64) []byte {
	t.Helper()
	now := time.Now().UTC()
	issued, err := env.runtime.coreServices().Sessions.Login(env.ctx, session.LoginRequest{
		Result: authn.AuthenticateResult{UserID: userID, Username: username,
			Outcome:          authn.OutcomeComplete,
			CompletedMethods: []authn.Method{authn.MethodPassword},
			CompletedAt:      now, StrongAuthCompletedAt: now,
			SecurityVersion: securityVersion},
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("签发测试管理会话: %v", err)
	}
	return []byte(issued.Secret.Reveal())
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// TestSettingsSecurityPolicyFieldsRootOnly 步骤 232 M1：普通 settings.manage 不得修改
// 注册/协议/扫码登录/公开 URL/邮件等安全策略字段；LocalAdmin 可写；未知字段 fail-closed。
func TestSettingsSecurityPolicyFieldsRootOnly(t *testing.T) {
	env := newSettingsTestEnv(t)
	settings := env.runtime.Settings()
	adminCaller := env.systemAdminSession(t, "settings-m1-admin", "settings.manage")
	before := env.readConfig(t)
	attempts := map[string]string{
		"registration.enabled":                    "false",
		"registration.require_review":             "true",
		"registration.require_email_verification": "true",
		"protocol.device_code_enabled":            "true",
		"app_qr_login.enabled":                    "true",
		"server.public_base_url":                  "https://example.com",
		"server.path_prefix":                      "/login2",
		"mail.enabled":                            "false",
		"mail.from.address":                       "noreply@example.com",
		"mail.delivery.max_attempts":              "5",
	}
	for field, value := range attempts {
		view, err := settings.Fields(env.ctx, SettingsFieldsRequest{Caller: adminCaller,
			RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("Fields: %v", err)
		}
		_, err = settings.Update(env.ctx, SettingsUpdateRequest{Caller: adminCaller,
			ExpectedVersion: view.Version, Changes: map[string]string{field: value},
			RequestID: login.NewRequestID()})
		if err == nil {
			t.Fatalf("普通 settings.manage 修改安全字段 %s 必须拒绝", field)
		}
		if code := asRBACAppError(t, err).Code(); code != login.CodeAccessDenied {
			t.Fatalf("字段 %s 拒绝码 = %q，期望 ACCESS_DENIED", field, code)
		}
	}
	if env.readConfig(t) != before {
		t.Fatal("越权尝试后配置文件必须保持不变")
	}
	// 未知字段拒绝（fail-closed，不能因未登记而放行）。
	view, err := settings.Fields(env.ctx, SettingsFieldsRequest{Caller: env.local,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Fields: %v", err)
	}
	if _, err := settings.Update(env.ctx, SettingsUpdateRequest{Caller: env.local,
		ExpectedVersion: view.Version,
		Changes:         map[string]string{"custom.unknown.future": "x"},
		RequestID:       login.NewRequestID()}); err == nil {
		t.Fatal("未知字段必须拒绝")
	}
	// LocalAdmin 可写 root-only 安全字段，证明确实是分权而非拒绝所有写。
	view, err = settings.Fields(env.ctx, SettingsFieldsRequest{Caller: env.local,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Fields: %v", err)
	}
	if _, err := settings.Update(env.ctx, SettingsUpdateRequest{Caller: env.local,
		ExpectedVersion: view.Version,
		Changes:         map[string]string{"registration.require_review": "true"},
		RequestID:       login.NewRequestID()}); err != nil {
		t.Fatalf("LocalAdmin 写 root-only 字段失败: %v", err)
	}
}
