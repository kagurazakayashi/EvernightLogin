package authz_test

// 步骤 234：授权引擎的账户有效期即时判定测试。
//
// 到期/未开始账户在每次 authz.Check 时被拒绝（CodeUserDisabled），续期当刻恢复；
// 不依赖定时扫描，也不改变账户 status。

import (
	"context"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
)

// setAuthzValidity 直接写库设置指定账户的有效期夹具。
func setAuthzValidity(t *testing.T, env *testEnv, userID string,
	validFrom, validUntil *time.Time) {
	t.Helper()
	var fromMS, untilMS any
	if validFrom != nil {
		fromMS = validFrom.UTC().UnixMilli()
	}
	if validUntil != nil {
		untilMS = validUntil.UTC().UnixMilli()
	}
	if _, err := env.raw.DB().ExecContext(context.Background(),
		`UPDATE users SET valid_from_ms=?, valid_until_ms=? WHERE id=?`,
		fromMS, untilMS, userID); err != nil {
		t.Fatalf("写入有效期夹具: %v", err)
	}
}

// TestAuthzValidityImmediate 验证授权检查在到期/未开始/续期时的即时结果。
func TestAuthzValidityImmediate(t *testing.T) {
	env := prepareEnv(t)
	env.insertRole("role_00000000000000000000000000000071", testAppOne,
		"validity.approver", true)
	env.addRolePermission("role_00000000000000000000000000000071",
		testPermissionApprove, testAppOne)
	env.assignUserRole(testActiveUser, "role_00000000000000000000000000000071",
		testAppOne, `{}`)
	result := env.check(testActiveUser, testAppOne, []string{"invoices.approve"}, authz.ModeAll)
	if !result.Allowed {
		t.Fatalf("基线授权应允许: %+v", result)
	}
	now := time.UnixMilli(1_700_000_000_000).UTC()
	// valid_until=now：右端半开，立即拒绝。
	setAuthzValidity(t, env, testActiveUser, nil, &now)
	result = env.check(testActiveUser, testAppOne, []string{"invoices.approve"}, authz.ModeAll)
	if result.Allowed || result.Code != authz.CodeUserDisabled {
		t.Fatalf("到期账户应拒绝: %+v", result)
	}
	// valid_from 未到：拒绝。
	from := now.Add(time.Hour)
	until := now.Add(2 * time.Hour)
	setAuthzValidity(t, env, testActiveUser, &from, &until)
	result = env.check(testActiveUser, testAppOne, []string{"invoices.approve"}, authz.ModeAll)
	if result.Allowed || result.Code != authz.CodeUserDisabled {
		t.Fatalf("未开始账户应拒绝: %+v", result)
	}
	// 续期窗口覆盖当前时刻：当刻恢复（引擎时钟为真实时间，使用过去起点/未来终点）。
	past := now.Add(-24 * time.Hour)
	setAuthzValidity(t, env, testActiveUser, &past, nil)
	result = env.check(testActiveUser, testAppOne, []string{"invoices.approve"}, authz.ModeAll)
	if !result.Allowed {
		t.Fatalf("无上限窗口应允许: %+v", result)
	}
	// 手动禁用仍优先拒绝。
	if _, err := env.raw.DB().ExecContext(context.Background(),
		`UPDATE users SET status='disabled' WHERE id=?`, testActiveUser); err != nil {
		t.Fatalf("禁用夹具: %v", err)
	}
	result = env.check(testActiveUser, testAppOne, []string{"invoices.approve"}, authz.ModeAll)
	if result.Allowed {
		t.Fatalf("手动禁用应拒绝: %+v", result)
	}
}
