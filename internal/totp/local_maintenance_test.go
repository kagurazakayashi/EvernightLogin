package totp_test

// 步骤 288 本地维护 TOTP 因素列举/删除定向测试。
//
// 覆盖：目标用户绑定元数据列举、本地维护删除（无用户验证码/再次认证）、删除后
// 绑定不可用于登录且 security_version 递增、重复删除返回 ErrBindingNotFound、
// 非法目标/空身份拒绝。

import (
	"errors"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/totp"
)

// TestLocalMaintenanceTOTPBindings 覆盖列举与本地删除语义。
func TestLocalMaintenanceTOTPBindings(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = env.now.UTC()
	userCaller := env.caller()
	start, err := env.service.BeginBinding(env.ctx, userCaller, "req-local-totp-bind")
	if err != nil {
		t.Fatalf("开始绑定: %v", err)
	}
	secret, err := totp.DecodeSecret(start.Secret)
	if err != nil {
		t.Fatalf("解码种子: %v", err)
	}
	if _, err := env.service.ConfirmBinding(env.ctx, userCaller, totp.BindConfirm{
		BindingID: start.BindingID, Code: mustCode(t, secret, env.now),
		RequestID: "req-local-totp-confirm"}); err != nil {
		t.Fatalf("确认绑定: %v", err)
	}
	localCaller, err := totp.NewLocalMaintenanceCaller("os:tester@local")
	if err != nil {
		t.Fatalf("本地维护身份: %v", err)
	}
	bindings, err := env.service.LocalMaintenanceListBindings(env.ctx, localCaller, userID)
	if err != nil {
		t.Fatalf("列举绑定: %v", err)
	}
	if len(bindings) != 1 || bindings[0].Status != "active" {
		t.Fatalf("绑定元数据异常: %+v", bindings)
	}
	var beforeVersion int64
	if err := env.raw.DB().QueryRowContext(env.ctx,
		`SELECT security_version FROM users WHERE id=?`, userID).Scan(&beforeVersion); err != nil {
		t.Fatalf("读取安全版本: %v", err)
	}
	if err := env.service.LocalMaintenanceRemoveBinding(env.ctx, localCaller, userID,
		"req-local-totp-remove"); err != nil {
		t.Fatalf("本地删除绑定: %v", err)
	}
	var afterVersion int64
	if err := env.raw.DB().QueryRowContext(env.ctx,
		`SELECT security_version FROM users WHERE id=?`, userID).Scan(&afterVersion); err != nil {
		t.Fatalf("读取安全版本: %v", err)
	}
	if afterVersion != beforeVersion+1 {
		t.Fatalf("安全版本应递增: before=%d after=%d", beforeVersion, afterVersion)
	}
	// 删除后旧码不能登录（绑定不存在/已停用）。
	if err := env.service.VerifyLoginCode(env.ctx, userID,
		mustCode(t, secret, env.now.Add(30*time.Second))); !errors.Is(
		err, totp.ErrBindingNotFound) {
		t.Fatalf("删除后登录验证错误 = %v，期望 ErrBindingNotFound", err)
	}
	// 重复删除：目标已无 active 绑定。
	if err := env.service.LocalMaintenanceRemoveBinding(env.ctx, localCaller, userID,
		"req-local-totp-remove-again"); !errors.Is(err, totp.ErrBindingNotFound) {
		t.Fatalf("重复删除错误 = %v，期望 ErrBindingNotFound", err)
	}
	// 非法目标/空本地身份。
	if _, err := env.service.LocalMaintenanceListBindings(env.ctx, localCaller, "bad-id"); !errors.Is(
		err, totp.ErrInvalidRequest) {
		t.Fatalf("非法目标错误 = %v，期望 ErrInvalidRequest", err)
	}
	if err := env.service.LocalMaintenanceRemoveBinding(env.ctx,
		totp.LocalMaintenanceCaller{}, userID, "req-x"); !errors.Is(err, totp.ErrAccessDenied) {
		t.Fatalf("空本地身份错误 = %v，期望 ErrAccessDenied", err)
	}
}
