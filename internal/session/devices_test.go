package session_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// newServiceWith 用同一测试环境依赖构造自定义选项的会话服务。
func (e *testEnv) newServiceWith(apply func(*session.Options)) *session.Service {
	e.t.Helper()
	options := session.Options{
		Store:           e.sessionStore,
		Audit:           e.audit,
		Keyring:         e.keyring,
		IdleTimeout:     10 * time.Minute,
		AbsoluteTimeout: 2 * time.Hour,
		Logger:          slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Now:             e.clock.Now,
	}
	if apply != nil {
		apply(&options)
	}
	service, err := session.New(options.Store, options)
	if err != nil {
		e.t.Fatalf("构造自定义会话服务失败: %v", err)
	}
	return service
}

// loginWith 使用完整认证结果签发普通会话，可指定应用、记住我与客户端描述。
func (e *testEnv) loginWith(service *session.Service, userID, appID string, rememberMe bool, client session.ClientInfo) session.IssuedSession {
	e.t.Helper()
	issued, err := service.Login(e.ctx, session.LoginRequest{
		Result:     completeResult(userID, 1),
		AppID:      appID,
		RememberMe: rememberMe,
		Client:     client,
	})
	if err != nil {
		e.t.Fatalf("签发会话失败: %v", err)
	}
	return issued
}

// auditCount 统计指定审计动作的事件数。
func (e *testEnv) auditCount(action session.Action) int {
	e.t.Helper()
	return e.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action=?`, string(action))
}

// activeSessionCount 统计数据库中某账户仍未被撤销的会话行数（仅测试断言用）。
func (e *testEnv) activeSessionCount(userID string) int {
	e.t.Helper()
	return e.queryInt(`SELECT COUNT(*) FROM sessions WHERE user_id=? AND revoked_at_ms IS NULL`, userID)
}

// markStrongAuth 直接在测试数据库中写入强认证完成时间，模拟管理强认证步骤接线后
// 的已认证状态；生产代码没有写入该字段的通道，本步管理操作默认 fail-closed。
func (e *testEnv) markStrongAuth(sessionID string) {
	e.t.Helper()
	e.exec(`UPDATE sessions SET strong_auth_verified_at_ms=? WHERE id=?`, e.clock.Now().UnixMilli(), sessionID)
}

// stubAuthorizer 是测试用范围授权器：按操作者 + 作用范围白名单放行，或统一拒绝。
type stubAuthorizer struct {
	allow map[string]bool
	deny  bool
}

// AuthorizeSessionRevoke 实现 session.ScopeAuthorizer。
func (a *stubAuthorizer) AuthorizeSessionRevoke(_ context.Context, actor audit.Actor, scopeAppID, _ string) error {
	if a.deny {
		return session.ErrAccessDenied
	}
	key := actor.ID + "|" + scopeAppID
	if a.allow[key] {
		return nil
	}
	return session.ErrAccessDenied
}

// TestListSessionsPaginationAndScope 验证设备列表分页、当前会话标记、本人范围与
// 不返回会话秘密：
//   - 同一用户 3 个活动会话，页大小 2 时第一页 2 条、第二页 1 条且 HasMore 正确；
//   - 当前出示的会话被标记 Current；客户端描述来自签发时的展示字段；
//   - 列表只含当前账户会话，其他用户会话不出现；
//   - 返回结构不含会话秘密/CSRF 令牌/验证摘要。
func TestListSessionsPaginationAndScope(t *testing.T) {
	env := newTestEnv(t)
	userA := "usr_00000000000000000000000000000021"
	userB := "usr_00000000000000000000000000000022"
	env.insertUser(userA, "alice", account.StatusActive, 1)
	env.insertUser(userB, "bob", account.StatusActive, 1)

	first := env.loginWith(env.session, userA, "", false, session.ClientInfo{
		UserAgent: "Mozilla/5.0 (Windows NT 10.0)  Browser/1.0",
		Address:   "203.0.113.7",
	})
	env.clock.Advance(time.Minute)
	second := env.loginWith(env.session, userA, "", true, session.ClientInfo{UserAgent: "cli/2.0", Address: "198.51.100.9"})
	env.clock.Advance(time.Minute)
	third := env.loginWith(env.session, userA, "", false, session.ClientInfo{})
	other := env.loginWith(env.session, userB, "", false, session.ClientInfo{UserAgent: "other-device"})

	page, err := env.session.ListSessions(env.ctx, second.Secret.Reveal(), session.ListOptions{Page: 1, PageSize: 2})
	if err != nil {
		t.Fatalf("读取设备列表失败: %v", err)
	}
	if page.Total != 3 || len(page.Sessions) != 2 || !page.HasMore {
		t.Fatalf("第一页结果 = total=%d len=%d hasMore=%v，期望 total=3 len=2 hasMore=true",
			page.Total, len(page.Sessions), page.HasMore)
	}
	seenIDs := map[string]session.SessionSummary{}
	for _, item := range page.Sessions {
		seenIDs[item.ID] = item
	}
	if _, found := seenIDs[other.Session.ID]; found {
		t.Error("设备列表出现其他用户的会话")
	}
	current, found := seenIDs[second.Session.ID]
	if !found {
		t.Fatal("第一页缺少当前会话")
	}
	if !current.Current {
		t.Error("当前会话未被标记 Current")
	}
	if current.Client.UserAgent != "cli/2.0" || current.Client.Address != "198.51.100.9" {
		t.Errorf("客户端描述 = %+v", current.Client)
	}
	if !current.RememberMe {
		t.Error("记住我会话未标记 RememberMe")
	}
	if _, found := seenIDs[first.Session.ID]; found && seenIDs[first.Session.ID].Current {
		t.Error("非当前会话被错误标记 Current")
	}
	// 返回结构序列化后不得包含任何会话秘密或 CSRF 令牌。
	rendered := fmt.Sprintf("%#v", page)
	for _, secret := range []session.IssuedSession{first, second, third, other} {
		if strings.Contains(rendered, secret.Secret.Reveal()) {
			t.Fatal("设备列表包含会话秘密明文")
		}
		if strings.Contains(rendered, secret.CSRFSecret.Reveal()) {
			t.Fatal("设备列表包含 CSRF 令牌明文")
		}
	}
	lastPage, err := env.session.ListSessions(env.ctx, second.Secret.Reveal(), session.ListOptions{Page: 2, PageSize: 2})
	if err != nil {
		t.Fatalf("读取第二页失败: %v", err)
	}
	if len(lastPage.Sessions) != 1 || lastPage.HasMore {
		t.Fatalf("第二页结果 = len=%d hasMore=%v，期望 len=1 hasMore=false", len(lastPage.Sessions), lastPage.HasMore)
	}
	if _, err := env.session.ListSessions(env.ctx, "", session.ListOptions{}); !errors.Is(err, session.ErrSessionInvalid) {
		t.Errorf("无会话列设备表错误 = %v，期望 ErrSessionInvalid", err)
	}
}

// TestUserRevokeOwnSessions 验证用户指定退出、退出全部、幂等重复退出与越权目标：
//   - 用户只能退出自己的会话，他人的会话 ID 按幂等无操作返回 false 且目标仍有效；
//   - 重复退出同一条会话返回 false 而不是错误；
//   - keepCurrent 保留当前会话，其余立即失效；
//   - 不保留的退出全部后所有会话（含当前）都无法再校验。
func TestUserRevokeOwnSessions(t *testing.T) {
	env := newTestEnv(t)
	userA := "usr_00000000000000000000000000000031"
	userB := "usr_00000000000000000000000000000032"
	env.insertUser(userA, "alice", account.StatusActive, 1)
	env.insertUser(userB, "bob", account.StatusActive, 1)

	device1 := env.loginWith(env.session, userA, "", false, session.ClientInfo{UserAgent: "device-1"})
	device2 := env.loginWith(env.session, userA, "", false, session.ClientInfo{UserAgent: "device-2"})
	device3 := env.loginWith(env.session, userA, "", false, session.ClientInfo{UserAgent: "device-3"})
	otherUser := env.loginWith(env.session, userB, "", false, session.ClientInfo{})

	// 越权目标：返回幂等无操作，不泄露存在性，也不撤销他人会话。
	revoked, err := env.session.RevokeSession(env.ctx, device1.Secret.Reveal(), otherUser.Session.ID)
	if err != nil || revoked {
		t.Fatalf("退出他人会话 = (%v, %v)，期望 (false, nil)", revoked, err)
	}
	if _, err := env.session.Validate(env.ctx, otherUser.Secret.Reveal()); err != nil {
		t.Fatalf("他人会话不应被撤销: %v", err)
	}

	revoked, err = env.session.RevokeSession(env.ctx, device1.Secret.Reveal(), device2.Session.ID)
	if err != nil || !revoked {
		t.Fatalf("退出本人指定会话 = (%v, %v)，期望 (true, nil)", revoked, err)
	}
	if _, err := env.session.Validate(env.ctx, device2.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("被撤销会话错误 = %v，期望 ErrSessionInvalid", err)
	}
	// 幂等重复退出：确定返回 false，不返回错误、不重复写审计。
	before := env.auditCount(session.ActionSessionRevokeOwn)
	revoked, err = env.session.RevokeSession(env.ctx, device1.Secret.Reveal(), device2.Session.ID)
	if err != nil || revoked {
		t.Fatalf("重复退出 = (%v, %v)，期望 (false, nil)", revoked, err)
	}
	if after := env.auditCount(session.ActionSessionRevokeOwn); after != before {
		t.Errorf("重复退出写入了额外审计：before=%d after=%d", before, after)
	}

	// 退出其他设备：保留当前会话。
	count, err := env.session.RevokeAllOwnSessions(env.ctx, device1.Secret.Reveal(), true)
	if err != nil {
		t.Fatalf("退出其他设备失败: %v", err)
	}
	if count != 1 {
		t.Errorf("退出其他设备数量 = %d，期望 1（device3）", count)
	}
	if _, err := env.session.Validate(env.ctx, device1.Secret.Reveal()); err != nil {
		t.Fatalf("当前会话不应被保留式退出撤销: %v", err)
	}
	if _, err := env.session.Validate(env.ctx, device3.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("其他设备错误 = %v，期望 ErrSessionInvalid", err)
	}

	// 退出全部（含当前）：所有会话不可再访问。
	count, err = env.session.RevokeAllOwnSessions(env.ctx, device1.Secret.Reveal(), false)
	if err != nil {
		t.Fatalf("退出全部失败: %v", err)
	}
	if count != 1 {
		t.Errorf("退出全部数量 = %d，期望 1（当前会话）", count)
	}
	if _, err := env.session.Validate(env.ctx, device1.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("退出全部后当前会话错误 = %v，期望 ErrSessionInvalid", err)
	}
	if env.activeSessionCount(userA) != 0 {
		t.Errorf("用户 A 仍有活动会话行: %d", env.activeSessionCount(userA))
	}
}

// TestAdminRevokeScopes 验证管理员按范围强制下线：
//   - 应用范围管理员只能撤销绑定该应用的会话，跨应用/全局会话按幂等无操作；
//   - 应用范围管理员按用户撤销时只撤销该应用会话，不影响该用户其他会话；
//   - 系统范围管理员可撤销目标账户全部会话；
//   - root 会话不可被任何管理员撤销；
//   - 无授权实现或授权拒绝时 fail-closed 返回 ACCESS_DENIED。
func TestAdminRevokeScopes(t *testing.T) {
	env := newTestEnv(t)
	adminID := "usr_00000000000000000000000000000041"
	appAdminID := "usr_00000000000000000000000000000042"
	targetID := "usr_00000000000000000000000000000043"
	rootID := "usr_00000000000000000000000000000044"
	appX := "app_00000000000000000000000000000041"
	appY := "app_00000000000000000000000000000042"
	env.insertUser(adminID, "sysadmin", account.StatusActive, 1)
	env.insertUser(appAdminID, "appadmin", account.StatusActive, 1)
	env.insertUser(targetID, "target", account.StatusActive, 1)
	env.insertUser(rootID, "root", account.StatusActive, 1)
	env.exec(`UPDATE users SET is_root=1 WHERE id=?`, rootID)
	env.insertApplication(appX, "active")
	env.insertApplication(appY, "active")
	env.insertMembership(appX, appAdminID, "active")
	env.insertMembership(appY, appAdminID, "active")
	env.insertMembership(appX, targetID, "active")
	env.insertMembership(appY, targetID, "active")

	authorizer := &stubAuthorizer{allow: map[string]bool{
		adminID + "|":           true, // 系统范围
		appAdminID + "|" + appX: true, // 仅应用 X
	}}
	service := env.newServiceWith(func(options *session.Options) {
		options.Authorizer = authorizer
	})

	adminSession := env.loginWith(service, adminID, "", false, session.ClientInfo{})
	appAdminSession := env.loginWith(service, appAdminID, "", false, session.ClientInfo{})
	// 管理强制下线要求强认证；MFA 未实现时没有写入通道，这里直接在测试数据库中
	// 注入“已完成强认证”的服务端时间，模拟后续管理强认证步骤接线后的已认证状态。
	env.markStrongAuth(adminSession.Session.ID)
	env.markStrongAuth(appAdminSession.Session.ID)
	appXTarget := env.loginWith(service, targetID, appX, false, session.ClientInfo{})
	appYTarget := env.loginWith(service, targetID, appY, false, session.ClientInfo{})
	globalTarget := env.loginWith(service, targetID, "", false, session.ClientInfo{})
	// root 只能持有受限会话（步骤 30 的强制语义），本用例验证其会话不可被管理员撤销。
	rootSession, err := service.Login(env.ctx, session.LoginRequest{
		Result: pendingSecondFactorResult(rootID, 1),
	})
	if err != nil {
		t.Fatalf("签发 root 受限会话失败: %v", err)
	}
	if !rootSession.Session.IsRestricted() {
		t.Fatal("root 会话应为受限会话")
	}

	// 应用范围管理员越界撤销全局会话：幂等无操作，全局会话仍有效。
	result, err := service.AdminRevoke(env.ctx, appAdminSession.Secret.Reveal(), session.AdminRevokeRequest{
		ScopeAppID:      appX,
		TargetSessionID: globalTarget.Session.ID,
	})
	if err != nil || result.Revoked != 0 {
		t.Fatalf("跨范围撤销 = (%+v, %v)，期望 Revoked=0 且无错误", result, err)
	}
	if _, err := service.Validate(env.ctx, globalTarget.Secret.Reveal()); err != nil {
		t.Fatalf("全局会话不应被应用管理员撤销: %v", err)
	}
	// 应用范围管理员撤销其他应用会话同样无操作。
	result, err = service.AdminRevoke(env.ctx, appAdminSession.Secret.Reveal(), session.AdminRevokeRequest{
		ScopeAppID:      appX,
		TargetSessionID: appYTarget.Session.ID,
	})
	if err != nil || result.Revoked != 0 {
		t.Fatalf("撤销其他应用会话 = (%+v, %v)，期望 Revoked=0 且无错误", result, err)
	}
	if _, err := service.Validate(env.ctx, appYTarget.Secret.Reveal()); err != nil {
		t.Fatalf("其他应用会话不应被撤销: %v", err)
	}
	// 应用范围管理员撤销本应用会话：成功且目标失效。
	result, err = service.AdminRevoke(env.ctx, appAdminSession.Secret.Reveal(), session.AdminRevokeRequest{
		ScopeAppID:      appX,
		TargetSessionID: appXTarget.Session.ID,
	})
	if err != nil || result.Revoked != 1 {
		t.Fatalf("应用范围撤销 = (%+v, %v)，期望 Revoked=1", result, err)
	}
	if _, err := service.Validate(env.ctx, appXTarget.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("被强制下线会话错误 = %v，期望 ErrSessionInvalid", err)
	}
	// 应用范围管理员按用户撤销：只撤销该应用会话（重建一个 appX 会话验证）。
	appXTarget2 := env.loginWith(service, targetID, appX, false, session.ClientInfo{})
	result, err = service.AdminRevoke(env.ctx, appAdminSession.Secret.Reveal(), session.AdminRevokeRequest{
		ScopeAppID:   appX,
		TargetUserID: targetID,
	})
	if err != nil || result.Revoked != 1 {
		t.Fatalf("应用范围按用户撤销 = (%+v, %v)，期望 Revoked=1", result, err)
	}
	if _, err := service.Validate(env.ctx, appXTarget2.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("应用范围按用户撤销后会话错误 = %v", err)
	}
	if _, err := service.Validate(env.ctx, globalTarget.Secret.Reveal()); err != nil {
		t.Errorf("应用范围按用户撤销不应影响全局会话: %v", err)
	}
	if _, err := service.Validate(env.ctx, appYTarget.Secret.Reveal()); err != nil {
		t.Errorf("应用范围按用户撤销不应影响其他应用会话: %v", err)
	}

	// 系统范围管理员撤销目标账户全部会话。
	result, err = service.AdminRevoke(env.ctx, adminSession.Secret.Reveal(), session.AdminRevokeRequest{
		TargetUserID: targetID,
		RequestID:    "req-admin-1",
	})
	if err != nil || result.Revoked != 2 {
		t.Fatalf("系统范围按用户撤销 = (%+v, %v)，期望 Revoked=2（全局 + appY）", result, err)
	}
	if env.activeSessionCount(targetID) != 0 {
		t.Errorf("目标账户仍有活动会话: %d", env.activeSessionCount(targetID))
	}

	// root 会话不可撤销：返回 ACCESS_DENIED 且会话仍有效。
	if _, err := service.AdminRevoke(env.ctx, adminSession.Secret.Reveal(), session.AdminRevokeRequest{
		TargetSessionID: rootSession.Session.ID,
	}); !errors.Is(err, session.ErrAccessDenied) {
		t.Fatalf("撤销 root 会话错误 = %v，期望 ErrAccessDenied", err)
	}
	if _, err := service.Validate(env.ctx, rootSession.Secret.Reveal()); err != nil {
		t.Errorf("root 受限会话不应被管理员撤销: %v", err)
	}

	// 未授权操作者（不在白名单）被拒绝。
	otherAdminID := "usr_00000000000000000000000000000045"
	env.insertUser(otherAdminID, "otheradmin", account.StatusActive, 1)
	otherAdminSession := env.loginWith(service, otherAdminID, "", false, session.ClientInfo{})
	if _, err := service.AdminRevoke(env.ctx, otherAdminSession.Secret.Reveal(), session.AdminRevokeRequest{
		TargetUserID: targetID,
	}); !errors.Is(err, session.ErrAccessDenied) {
		t.Fatalf("未授权管理员错误 = %v，期望 ErrAccessDenied", err)
	}
	// 没有授权实现的会话服务：管理强制下线一律拒绝。
	if _, err := env.session.AdminRevoke(env.ctx, adminSession.Secret.Reveal(), session.AdminRevokeRequest{
		TargetUserID: targetID,
	}); !errors.Is(err, session.ErrAccessDenied) {
		t.Fatalf("缺少授权实现错误 = %v，期望 ErrAccessDenied", err)
	}
	// 缺少强认证的会话不得执行管理强制下线（fail-closed，统一 ACCESS_DENIED）。
	if _, err := service.AdminRevoke(env.ctx, rootSession.Secret.Reveal(), session.AdminRevokeRequest{
		TargetUserID: targetID,
	}); !errors.Is(err, session.ErrAccessDenied) {
		t.Fatalf("缺少强认证的会话管理错误 = %v，期望 ErrAccessDenied", err)
	}
	if env.auditCount(session.ActionSessionAdminRevoke) < 3 {
		t.Errorf("管理强制下线审计数量 = %d，至少 3 条成功事件", env.auditCount(session.ActionSessionAdminRevoke))
	}
}

// TestAdminRevokeStrongAuthAndNoExistenceLeak 验证管理强制下线的强认证闸门与无差分
// 泄露：缺少强认证/缺少授权实现/授权拒绝时，对不存在、普通与 root 目标一律返回
// 同一个 ErrAccessDenied（先授权后读取目标）；只有强认证与目标级授权都通过后，
// 不存在目标才按幂等成功返回 0、root 目标返回 ACCESS_DENIED、普通目标真正撤销。
func TestAdminRevokeStrongAuthAndNoExistenceLeak(t *testing.T) {
	env := newTestEnv(t)
	adminID := "usr_00000000000000000000000000000046"
	targetID := "usr_00000000000000000000000000000047"
	rootID := "usr_00000000000000000000000000000048"
	env.insertUser(adminID, "admin", account.StatusActive, 1)
	env.insertUser(targetID, "target", account.StatusActive, 1)
	env.insertUser(rootID, "root", account.StatusActive, 1)
	env.exec(`UPDATE users SET is_root=1 WHERE id=?`, rootID)

	allow := &stubAuthorizer{allow: map[string]bool{adminID + "|": true}}
	service := env.newServiceWith(func(options *session.Options) { options.Authorizer = allow })
	adminSession := env.loginWith(service, adminID, "", false, session.ClientInfo{})
	targetSession := env.loginWith(service, targetID, "", false, session.ClientInfo{})
	rootSession, err := service.Login(env.ctx, session.LoginRequest{Result: pendingSecondFactorResult(rootID, 1)})
	if err != nil {
		t.Fatalf("签发 root 受限会话失败: %v", err)
	}
	missingID := "ses_0000000000000000000000000000dead"

	// 1) 缺少强认证：对不存在、普通、root 目标返回完全一致的 ACCESS_DENIED。
	for name, request := range map[string]session.AdminRevokeRequest{
		"不存在会话":  {TargetSessionID: missingID},
		"普通会话":   {TargetSessionID: targetSession.Session.ID},
		"root会话": {TargetSessionID: rootSession.Session.ID},
		"不存在用户":  {TargetUserID: "usr_00000000000000000000000000000099"},
		"普通用户":   {TargetUserID: targetID},
		"root用户": {TargetUserID: rootID},
	} {
		result, err := service.AdminRevoke(env.ctx, adminSession.Secret.Reveal(), request)
		if !errors.Is(err, session.ErrAccessDenied) || result.Revoked != 0 {
			t.Fatalf("%s 在缺少强认证时 = (%+v, %v)，期望 (0, ErrAccessDenied)", name, result, err)
		}
	}
	if _, err := service.Validate(env.ctx, targetSession.Secret.Reveal()); err != nil {
		t.Fatalf("缺少强认证时不得撤销任何目标会话: %v", err)
	}

	// 2) 已完成强认证但授权拒绝：对不存在/普通/root 目标仍返回一致的 ACCESS_DENIED。
	env.markStrongAuth(adminSession.Session.ID)
	denyService := env.newServiceWith(func(options *session.Options) {
		options.Authorizer = &stubAuthorizer{deny: true}
	})
	for name, request := range map[string]session.AdminRevokeRequest{
		"不存在会话":  {TargetSessionID: missingID},
		"普通会话":   {TargetSessionID: targetSession.Session.ID},
		"root会话": {TargetSessionID: rootSession.Session.ID},
	} {
		if _, err := denyService.AdminRevoke(env.ctx, adminSession.Secret.Reveal(), request); !errors.Is(err, session.ErrAccessDenied) {
			t.Fatalf("%s 在授权拒绝时 = %v，期望 ErrAccessDenied", name, err)
		}
	}

	// 3) 缺少授权实现（nil）：同样统一拒绝，不因目标不同产生差异。
	for name, request := range map[string]session.AdminRevokeRequest{
		"不存在会话":  {TargetSessionID: missingID},
		"普通会话":   {TargetSessionID: targetSession.Session.ID},
		"root会话": {TargetSessionID: rootSession.Session.ID},
	} {
		if _, err := env.session.AdminRevoke(env.ctx, adminSession.Secret.Reveal(), request); !errors.Is(err, session.ErrAccessDenied) {
			t.Fatalf("%s 在缺少授权实现时 = %v，期望 ErrAccessDenied", name, err)
		}
	}

	// 4) 强认证 + 授权通过：不存在目标按幂等成功返回 0；root 目标拒绝；普通目标撤销。
	result, err := service.AdminRevoke(env.ctx, adminSession.Secret.Reveal(), session.AdminRevokeRequest{
		TargetSessionID: missingID,
	})
	if err != nil || result.Revoked != 0 {
		t.Fatalf("已授权管理员撤销不存在会话 = (%+v, %v)，期望 (0, nil)", result, err)
	}
	if _, err := service.AdminRevoke(env.ctx, adminSession.Secret.Reveal(), session.AdminRevokeRequest{
		TargetSessionID: rootSession.Session.ID,
	}); !errors.Is(err, session.ErrAccessDenied) {
		t.Fatalf("已授权管理员撤销 root 会话错误 = %v，期望 ErrAccessDenied", err)
	}
	result, err = service.AdminRevoke(env.ctx, adminSession.Secret.Reveal(), session.AdminRevokeRequest{
		TargetSessionID: targetSession.Session.ID,
	})
	if err != nil || result.Revoked != 1 {
		t.Fatalf("已授权管理员撤销普通会话 = (%+v, %v)，期望 (1, nil)", result, err)
	}
	if _, err := service.Validate(env.ctx, targetSession.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("被强制下线会话错误 = %v，期望 ErrSessionInvalid", err)
	}
	// 真实操作者为管理员用户，强认证闸门拒绝也有可区分审计原因。
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action=? AND reason_code='strong_auth_required'`, string(session.ActionSessionAdminRevoke)); got == 0 {
		t.Error("缺少强认证的拒绝未写 strong_auth_required 审计原因")
	}
}

// TestConcurrentLoginLimitAtomic 验证并发登录下最大在线数由事务内原子条件更新维护：
// 8 个并发登录使用上限 3 的服务，最终活动会话行数不超过 3，且成功签发的会话要么
// 仍有效、要么已被后续登录按策略淘汰；自动淘汰写独立 session.eviction 审计。
func TestConcurrentLoginLimitAtomic(t *testing.T) {
	env := newTestEnv(t)
	userID := "usr_00000000000000000000000000000051"
	env.insertUser(userID, "concurrent", account.StatusActive, 1)
	service := env.newServiceWith(func(options *session.Options) {
		options.MaxActiveSessions = 3
	})

	const attempts = 8
	var (
		waitGroup sync.WaitGroup
		mu        sync.Mutex
		issued    []session.IssuedSession
		failures  []error
	)
	for index := 0; index < attempts; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			item, err := service.Login(env.ctx, session.LoginRequest{
				Result: completeResult(userID, 1),
			})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures = append(failures, err)
				return
			}
			issued = append(issued, item)
		}()
	}
	waitGroup.Wait()
	if len(issued) == 0 {
		t.Fatalf("并发登录全部失败: %v", failures)
	}
	if got := env.activeSessionCount(userID); got > 3 {
		t.Fatalf("并发登录后活动会话行数 = %d，超过上限 3", got)
	}
	for _, item := range issued {
		_, err := service.Validate(env.ctx, item.Secret.Reveal())
		if err == nil {
			continue
		}
		if !errors.Is(err, session.ErrSessionInvalid) {
			t.Fatalf("被淘汰会话错误 = %v，期望 nil 或 ErrSessionInvalid", err)
		}
	}
	if env.auditCount(session.ActionSessionEviction) == 0 {
		t.Error("并发登录自动淘汰未写 session.eviction 审计")
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action=? AND detail_json LIKE '%max_active_sessions%'`, string(session.ActionSessionEviction)); got == 0 {
		t.Error("自动淘汰审计未记录 max_active_sessions 策略")
	}
}

// TestSingleDeviceReplacement 验证单设备策略的明确替换规则：
// 第二次登录在同一事务内先撤销全部旧会话（原因 replaced_single_device）再签发，
// 旧会话立即失效、最终只有一个活动会话，并写独立自动淘汰审计。
func TestSingleDeviceReplacement(t *testing.T) {
	env := newTestEnv(t)
	userID := "usr_00000000000000000000000000000061"
	env.insertUser(userID, "single", account.StatusActive, 1)
	service := env.newServiceWith(func(options *session.Options) {
		options.DevicePolicy = session.DevicePolicySingle
	})
	first := env.loginWith(service, userID, "", false, session.ClientInfo{UserAgent: "old-device"})
	second := env.loginWith(service, userID, "", false, session.ClientInfo{UserAgent: "new-device"})

	if _, err := service.Validate(env.ctx, first.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("单设备替换后旧会话错误 = %v，期望 ErrSessionInvalid", err)
	}
	if _, err := service.Validate(env.ctx, second.Secret.Reveal()); err != nil {
		t.Fatalf("单设备替换后新会话应有效: %v", err)
	}
	if got := env.activeSessionCount(userID); got != 1 {
		t.Errorf("单设备策略活动会话行数 = %d，期望 1", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM sessions WHERE user_id=? AND revoked_reason=?`, userID, "replaced_single_device"); got != 1 {
		t.Errorf("替换撤销原因行数 = %d，期望 1", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action=? AND detail_json LIKE '%single%'`, string(session.ActionSessionEviction)); got == 0 {
		t.Error("单设备替换未写 session.eviction 审计")
	}
	// 单设备策略下“退出其他设备”保持当前会话不受影响。
	if count, err := service.RevokeAllOwnSessions(env.ctx, second.Secret.Reveal(), true); err != nil || count != 0 {
		t.Fatalf("单设备退出其他设备 = (%d, %v)，期望 (0, nil)", count, err)
	}
}

// TestRememberMeTimeout 验证记住我使用更长但受上限约束的绝对到期，且续期不越过
// 绝对到期；同时验证选项边界（记住我期限不得小于绝对期限或超过允许上限）。
func TestRememberMeTimeout(t *testing.T) {
	env := newTestEnv(t)
	userID := "usr_00000000000000000000000000000071"
	env.insertUser(userID, "remember", account.StatusActive, 1)
	service := env.newServiceWith(func(options *session.Options) {
		options.IdleTimeout = 2 * time.Hour
		options.AbsoluteTimeout = 2 * time.Hour
		options.RememberMeTimeout = 6 * time.Hour
	})
	normal := env.loginWith(service, userID, "", false, session.ClientInfo{})
	remembered := env.loginWith(service, userID, "", true, session.ClientInfo{})
	if got := normal.Session.AbsoluteExpiresAt.Sub(testStart); got != 2*time.Hour {
		t.Errorf("普通会话绝对期限 = %s，期望 2h", got)
	}
	if got := remembered.Session.AbsoluteExpiresAt.Sub(testStart); got != 6*time.Hour {
		t.Errorf("记住我会话绝对期限 = %s，期望 6h", got)
	}
	// 记住我会话在普通会话绝对到期之后仍然有效（空闲期限靠续期维持）。
	for index := 1; index <= 5; index++ {
		env.clock.Advance(time.Hour)
		if _, err := service.Renew(env.ctx, remembered.Secret.Reveal()); err != nil {
			t.Fatalf("第 %d 次续期记住我会话失败: %v", index, err)
		}
	}
	if _, err := service.Validate(env.ctx, normal.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("普通会话超过 2h 后错误 = %v，期望 ErrSessionInvalid", err)
	}
	// 续期不得越过记住我的绝对到期：最后一段空闲到期被 6h 绝对到期封顶。
	env.clock.Advance(30 * time.Minute)
	renewed, err := service.Renew(env.ctx, remembered.Secret.Reveal())
	if err != nil {
		t.Fatalf("记住我会话临界续期失败: %v", err)
	}
	if !renewed.IdleExpiresAt.Equal(remembered.Session.AbsoluteExpiresAt) {
		t.Errorf("续期后空闲到期 = %s，应被绝对到期 %s 封顶", renewed.IdleExpiresAt, remembered.Session.AbsoluteExpiresAt)
	}
	env.clock.Advance(time.Hour)
	if _, err := service.Validate(env.ctx, remembered.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("记住我会话超过绝对到期后错误 = %v，期望 ErrSessionInvalid", err)
	}
	// 选项边界：记住我与普通绝对期限相互独立，但都必须落在合理上下界内；
	// 普通绝对期限大于默认记住我期限时不应构造失败（宿主可配置更长的普通期限）。
	longAbsolute := env.newServiceWith(func(options *session.Options) {
		options.AbsoluteTimeout = 10 * 24 * time.Hour // 默认记住我 7 天更短，仍合法
	})
	longNormal := env.loginWith(longAbsolute, userID, "", false, session.ClientInfo{})
	longRemembered := env.loginWith(longAbsolute, userID, "", true, session.ClientInfo{})
	if got := longNormal.Session.AbsoluteExpiresAt.Sub(env.clock.Now()); got != 10*24*time.Hour {
		t.Errorf("长绝对期限普通会话 = %s，期望 10 天", got)
	}
	if got := longRemembered.Session.AbsoluteExpiresAt.Sub(env.clock.Now()); got != session.DefaultRememberMeTimeout {
		t.Errorf("默认记住我期限 = %s，期望 %s", got, session.DefaultRememberMeTimeout)
	}
	if _, err := session.New(env.sessionStore, session.Options{
		Store:             env.sessionStore,
		Audit:             env.audit,
		Keyring:           env.keyring,
		AbsoluteTimeout:   2 * time.Hour,
		RememberMeTimeout: time.Minute,
	}); !errors.Is(err, session.ErrOptionsInvalid) {
		t.Errorf("记住我期限过短构造错误 = %v，期望 ErrOptionsInvalid", err)
	}
	if _, err := session.New(env.sessionStore, session.Options{
		Store:             env.sessionStore,
		Audit:             env.audit,
		Keyring:           env.keyring,
		AbsoluteTimeout:   2 * time.Hour,
		RememberMeTimeout: session.MaxAbsoluteTimeout + time.Hour,
	}); !errors.Is(err, session.ErrOptionsInvalid) {
		t.Errorf("记住我期限超上限构造错误 = %v，期望 ErrOptionsInvalid", err)
	}
}

// TestAccountDisabledRevokeAndAuditActions 验证账户禁用触发退出使用独立审计动作，
// 撤销后所有会话不可访问，并与自动淘汰、管理员强制下线、用户指定退出的动作区分。
func TestAccountDisabledRevokeAndAuditActions(t *testing.T) {
	env := newTestEnv(t)
	userID := "usr_00000000000000000000000000000081"
	env.insertUser(userID, "disabled", account.StatusActive, 1)
	first := env.loginWith(env.session, userID, "", false, session.ClientInfo{})
	second := env.loginWith(env.session, userID, "", true, session.ClientInfo{})

	count, err := env.session.RevokeOnAccountDisabled(env.ctx, userID)
	if err != nil {
		t.Fatalf("账户禁用批量退出失败: %v", err)
	}
	if count != 2 {
		t.Errorf("账户禁用退出数量 = %d，期望 2", count)
	}
	for _, item := range []session.IssuedSession{first, second} {
		if _, err := env.session.Validate(env.ctx, item.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
			t.Fatalf("账户禁用退出后会话错误 = %v，期望 ErrSessionInvalid", err)
		}
	}
	// 重复执行幂等：0 条并仍写成功审计（确定结果）。
	count, err = env.session.RevokeOnAccountDisabled(env.ctx, userID)
	if err != nil || count != 0 {
		t.Fatalf("重复账户禁用退出 = (%d, %v)，期望 (0, nil)", count, err)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action=? AND actor_type='system' AND actor_id='session-service'`, string(session.ActionSessionAccountDisabledRevoke)); got != 2 {
		t.Errorf("账户禁用退出审计数量 = %d，期望 2（真实操作者为系统主体）", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action=?`, string(session.ActionSessionRevoke)); got != 0 {
		t.Errorf("账户禁用退出不应复用 session.revoke 动作，实际 %d", got)
	}
}

// fakePermissionChecker 是授权适配器测试用的最小 authz 检查器替身。
type fakePermissionChecker struct {
	checkAllowed       bool
	checkErr           error
	effective          authz.EffectiveResult
	effectiveErr       error
	lastCheckScope     string
	lastEffectiveLimit int
}

// Check 实现 session.PermissionChecker。
func (f *fakePermissionChecker) Check(_ context.Context, _ authz.Caller, request authz.CheckRequest) (authz.CheckResult, error) {
	f.lastCheckScope = request.ScopeID
	if f.checkErr != nil {
		return authz.CheckResult{}, f.checkErr
	}
	return authz.CheckResult{Allowed: f.checkAllowed, SubjectUserID: request.SubjectUserID, Scope: authz.Scope{ID: request.ScopeID}}, nil
}

// EffectivePermissions 实现 session.PermissionChecker。
func (f *fakePermissionChecker) EffectivePermissions(_ context.Context, _ authz.Caller, subjectUserID, _ string, options authz.ListOptions) (authz.EffectiveResult, error) {
	f.lastEffectiveLimit = options.Limit
	if f.effectiveErr != nil {
		return authz.EffectiveResult{}, f.effectiveErr
	}
	result := f.effective
	result.SubjectUserID = subjectUserID
	return result, nil
}

// TestAuthzAuthorizerScopeAndTargetProtection 验证授权适配器使用既有 authz 语义：
// 检查 sessions.revoke 权限（系统范围或应用范围），应用范围追加目标保护，拒绝
// 持有系统管理权限的目标账户，授权依赖故障时 fail-closed。
func TestAuthzAuthorizerScopeAndTargetProtection(t *testing.T) {
	actor := audit.Actor{Type: audit.ActorUser, ID: "usr_00000000000000000000000000000091"}
	target := "usr_00000000000000000000000000000092"

	allowed := &fakePermissionChecker{checkAllowed: true, effective: authz.EffectiveResult{Permissions: []authz.EffectivePermission{{Key: "self.profile.read"}}}}
	authorizer, err := session.NewAuthzAuthorizer(allowed)
	if err != nil {
		t.Fatalf("构造授权适配器失败: %v", err)
	}
	if err := authorizer.AuthorizeSessionRevoke(context.Background(), actor, "", target); err != nil {
		t.Fatalf("系统范围授权失败: %v", err)
	}
	if allowed.lastCheckScope != "system" {
		t.Errorf("系统范围检查 scope = %q，期望 system", allowed.lastCheckScope)
	}
	// 应用范围：普通目标放行，但检查 scope 使用应用 ID。
	if err := authorizer.AuthorizeSessionRevoke(context.Background(), actor, "app_00000000000000000000000000000091", target); err != nil {
		t.Fatalf("应用范围授权失败: %v", err)
	}
	if allowed.lastCheckScope != "app_00000000000000000000000000000091" {
		t.Errorf("应用范围检查 scope = %q", allowed.lastCheckScope)
	}
	// 应用范围目标保护：目标持有系统管理权限时拒绝。
	protected := &fakePermissionChecker{checkAllowed: true, effective: authz.EffectiveResult{
		Permissions: []authz.EffectivePermission{{Key: "users.disable"}},
	}}
	protectedAuthorizer, err := session.NewAuthzAuthorizer(protected)
	if err != nil {
		t.Fatalf("构造授权适配器失败: %v", err)
	}
	if err := protectedAuthorizer.AuthorizeSessionRevoke(context.Background(), actor, "app_00000000000000000000000000000091", target); !errors.Is(err, session.ErrAccessDenied) {
		t.Fatalf("受保护目标错误 = %v，期望 ErrAccessDenied", err)
	}
	// 目标有效权限超过 20 条时（受保护权限在后续页），适配器必须用最大页大小读取
	// 并拒绝，不能因默认分页大小漏判高权限目标。
	many := make([]authz.EffectivePermission, 0, 25)
	for index := 0; index < 24; index++ {
		many = append(many, authz.EffectivePermission{Key: fmt.Sprintf("custom.permission.%02d", index)})
	}
	many = append(many, authz.EffectivePermission{Key: "users.disable"})
	paged := &fakePermissionChecker{checkAllowed: true, effective: authz.EffectiveResult{Permissions: many}}
	pagedAuthorizer, err := session.NewAuthzAuthorizer(paged)
	if err != nil {
		t.Fatalf("构造授权适配器失败: %v", err)
	}
	if err := pagedAuthorizer.AuthorizeSessionRevoke(context.Background(), actor, "app_00000000000000000000000000000091", target); !errors.Is(err, session.ErrAccessDenied) {
		t.Fatalf(">20 权限目标保护错误 = %v，期望 ErrAccessDenied", err)
	}
	if paged.lastEffectiveLimit != authz.MaxListLimit {
		t.Errorf("目标权限读取页大小 = %d，期望最大页大小 %d", paged.lastEffectiveLimit, authz.MaxListLimit)
	}
	// HasMore 或来源截断表示保护集无法证明完整：fail-closed 拒绝。
	hasMore := &fakePermissionChecker{checkAllowed: true, effective: authz.EffectiveResult{
		Permissions: []authz.EffectivePermission{{Key: "self.profile.read"}},
		HasMore:     true,
	}}
	hasMoreAuthorizer, err := session.NewAuthzAuthorizer(hasMore)
	if err != nil {
		t.Fatalf("构造授权适配器失败: %v", err)
	}
	if err := hasMoreAuthorizer.AuthorizeSessionRevoke(context.Background(), actor, "app_00000000000000000000000000000091", target); !errors.Is(err, session.ErrAccessDenied) {
		t.Fatalf("HasMore 目标保护错误 = %v，期望 ErrAccessDenied", err)
	}
	truncated := &fakePermissionChecker{checkAllowed: true, effective: authz.EffectiveResult{
		Permissions:        []authz.EffectivePermission{{Key: "self.profile.read"}},
		SourceLimitReached: true,
	}}
	truncatedAuthorizer, err := session.NewAuthzAuthorizer(truncated)
	if err != nil {
		t.Fatalf("构造授权适配器失败: %v", err)
	}
	if err := truncatedAuthorizer.AuthorizeSessionRevoke(context.Background(), actor, "app_00000000000000000000000000000091", target); !errors.Is(err, session.ErrAccessDenied) {
		t.Fatalf("来源截断目标保护错误 = %v，期望 ErrAccessDenied", err)
	}
	// 权限检查拒绝或依赖故障：一律拒绝。
	denied := &fakePermissionChecker{checkAllowed: false}
	deniedAuthorizer, err := session.NewAuthzAuthorizer(denied)
	if err != nil {
		t.Fatalf("构造授权适配器失败: %v", err)
	}
	if err := deniedAuthorizer.AuthorizeSessionRevoke(context.Background(), actor, "", target); !errors.Is(err, session.ErrAccessDenied) {
		t.Fatalf("权限拒绝错误 = %v，期望 ErrAccessDenied", err)
	}
	broken := &fakePermissionChecker{checkErr: errors.New("authz unavailable")}
	brokenAuthorizer, err := session.NewAuthzAuthorizer(broken)
	if err != nil {
		t.Fatalf("构造授权适配器失败: %v", err)
	}
	if err := brokenAuthorizer.AuthorizeSessionRevoke(context.Background(), actor, "", target); !errors.Is(err, session.ErrAccessDenied) {
		t.Fatalf("授权依赖故障错误 = %v，期望 ErrAccessDenied", err)
	}
	// 非用户身份（系统/匿名）不能走管理强制下线授权。
	if err := allowedAuthorizer(t, allowed).AuthorizeSessionRevoke(context.Background(), audit.Actor{Type: audit.ActorSystem, ID: "svc"}, "", target); !errors.Is(err, session.ErrAccessDenied) {
		t.Fatalf("系统操作者授权错误 = %v，期望 ErrAccessDenied", err)
	}
	// 空检查器拒绝构造。
	if _, err := session.NewAuthzAuthorizer(nil); !errors.Is(err, session.ErrOptionsInvalid) {
		t.Errorf("空检查器构造错误 = %v，期望 ErrOptionsInvalid", err)
	}
}

// allowedAuthorizer 是测试辅助：复用同一适配器实例。
func allowedAuthorizer(t *testing.T, checker session.PermissionChecker) *session.AuthzAuthorizer {
	t.Helper()
	authorizer, err := session.NewAuthzAuthorizer(checker)
	if err != nil {
		t.Fatalf("构造授权适配器失败: %v", err)
	}
	return authorizer
}

// quotaBypassStore 是让活动会话计数返回超限值的存储装饰器，用于验证登录插入后
// 的数量约束复核会 fail-closed 返回 ErrConcurrentLimit（生产实现由原子淘汰保证不
// 会触发该路径，但复核点必须有真实测试覆盖）。
type quotaBypassStore struct {
	session.Store
	count int64
}

// CountActiveSessions 返回人为超限计数。
func (s *quotaBypassStore) CountActiveSessions(_ context.Context, _ audit.Tx, _ string, _ time.Time) (int64, error) {
	return s.count, nil
}

// TestLoginQuotaRecheckRejectsOverLimit 验证登录事务内数量复核：存储报告超限时
// 返回 ErrConcurrentLimit（AUTH_FAILED），整体回滚且不留下会话行。
func TestLoginQuotaRecheckRejectsOverLimit(t *testing.T) {
	env := newTestEnv(t)
	userID := "usr_00000000000000000000000000000052"
	env.insertUser(userID, "quotarecheck", account.StatusActive, 1)
	wrapped := &quotaBypassStore{Store: env.sessionStore, count: 99}
	service, err := session.New(wrapped, session.Options{
		Store:             wrapped,
		Audit:             env.audit,
		Keyring:           env.keyring,
		IdleTimeout:       10 * time.Minute,
		AbsoluteTimeout:   2 * time.Hour,
		MaxActiveSessions: 3,
		Logger:            slog.New(slog.NewTextHandler(env.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Now:               env.clock.Now,
	})
	if err != nil {
		t.Fatalf("构造服务失败: %v", err)
	}
	if _, err := service.Login(env.ctx, session.LoginRequest{Result: completeResult(userID, 1)}); !errors.Is(err, session.ErrConcurrentLimit) {
		t.Fatalf("超限复核错误 = %v，期望 ErrConcurrentLimit", err)
	}
	if got := env.activeSessionCount(userID); got != 0 {
		t.Errorf("超限复核失败后会话行数 = %d，期望 0（整体回滚）", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action=? AND outcome='failure' AND error_code='AUTH_FAILED'`, string(session.ActionSessionIssue)); got != 1 {
		t.Errorf("超限失败审计数量 = %d，期望 1", got)
	}
}

// TestRevokeUserCountsOnlyActiveSessions 验证批量撤销只统计实际撤销的未过期会话：
// 已过期会话不计入数量，也不会被标记为 revoked（清理由维护任务负责）。
func TestRevokeUserCountsOnlyActiveSessions(t *testing.T) {
	env := newTestEnv(t)
	userID := "usr_00000000000000000000000000000082"
	env.insertUser(userID, "expiredcount", account.StatusActive, 1)
	service := env.newServiceWith(func(options *session.Options) {
		options.IdleTimeout = 5 * time.Minute
		options.AbsoluteTimeout = 5 * time.Minute
	})
	expired := env.loginWith(service, userID, "", false, session.ClientInfo{})
	env.clock.Advance(6 * time.Minute) // 空闲与绝对到期都过期
	live := env.loginWith(service, userID, "", false, session.ClientInfo{})
	count, err := service.RevokeOnAccountDisabled(env.ctx, userID)
	if err != nil {
		t.Fatalf("账户禁用批量退出失败: %v", err)
	}
	if count != 1 {
		t.Errorf("批量撤销数量 = %d，期望 1（只统计未过期活动会话）", count)
	}
	if _, err := service.Validate(env.ctx, live.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("活动会话未被撤销: %v", err)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM sessions WHERE id=? AND revoked_at_ms IS NULL`, expired.Session.ID); got != 1 {
		t.Errorf("已过期会话不应被强制标记撤销（由清理负责），实际撤销标记 %d", 1-got)
	}
}
