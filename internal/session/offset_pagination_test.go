package session_test

// 步骤 217：会话/设备列表的 Limit/Offset 统一分页契约测试。
//   - ListSessionsPage：本人设备列表，存储层 LIMIT/OFFSET，返回统一分页元数据；
//   - AdminListSessionsPage：管理员按作用范围查询目标会话，授权/强认证/root 保护与
//     读审计不因分页形式改变；非法分页参数返回 ErrInvalidRequest；
//   - 公开结构不含会话秘密/CSRF/验证摘要。

import (
	"errors"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

func TestListSessionsOffsetPagination(t *testing.T) {
	env := newTestEnv(t)
	const userID = "usr_000000000000000000000000000000a1"
	env.insertUser(userID, "offset-alice", account.StatusActive, 1)
	env.loginWith(env.session, userID, "", false, session.ClientInfo{
		UserAgent: "Mozilla/5.0 offset-test", Address: "203.0.113.30"})
	env.clock.Advance(time.Minute)
	env.loginWith(env.session, userID, "", false, session.ClientInfo{UserAgent: "cli/offset"})
	env.clock.Advance(time.Minute)
	newest := env.loginWith(env.session, userID, "", false, session.ClientInfo{})

	page, err := env.session.ListSessionsPage(env.ctx, newest.Secret.Reveal(),
		session.ListPageOptions{Limit: 2, Offset: 0})
	if err != nil {
		t.Fatalf("设备第一页: %v", err)
	}
	if page.Limit != 2 || page.Offset != 0 || page.Returned != 2 || !page.HasMore ||
		page.NextOffset != 2 || page.Total != 3 {
		t.Fatalf("设备第一页元数据 = %+v", page)
	}
	currentMarked := false
	for _, item := range page.Sessions {
		if item.Current {
			currentMarked = true
		}
	}
	if !currentMarked {
		t.Error("当前会话未标记 Current")
	}
	second, err := env.session.ListSessionsPage(env.ctx, newest.Secret.Reveal(),
		session.ListPageOptions{Limit: 2, Offset: 2})
	if err != nil || second.Returned != 1 || second.HasMore || second.NextOffset != 3 {
		t.Fatalf("设备第二页 = %+v err=%v", second, err)
	}
	empty, err := env.session.ListSessionsPage(env.ctx, newest.Secret.Reveal(),
		session.ListPageOptions{Limit: 2, Offset: 10})
	if err != nil || empty.Returned != 0 || empty.HasMore {
		t.Fatalf("越界 offset = %+v err=%v", empty, err)
	}
	for _, options := range []session.ListPageOptions{
		{Limit: -1}, {Limit: session.MaxListPageSize + 1}, {Offset: -1}, {Offset: 1_000_001},
	} {
		if _, err := env.session.ListSessionsPage(env.ctx, newest.Secret.Reveal(),
			options); !errors.Is(err, session.ErrInvalidRequest) {
			t.Fatalf("非法分页参数 %+v 错误 = %v，期望 ErrInvalidRequest", options, err)
		}
	}
}

func TestAdminListSessionsOffsetPaginationAndScope(t *testing.T) {
	env := newTestEnv(t)
	const adminID = "usr_000000000000000000000000000000a2"
	const targetID = "usr_000000000000000000000000000000a3"
	const appA = "app_000000000000000000000000000000a4"
	const appB = "app_000000000000000000000000000000a5"
	env.insertUser(adminID, "offset-admin", account.StatusActive, 1)
	env.insertUser(targetID, "offset-target", account.StatusActive, 1)
	env.insertApplication(appA, "active")
	env.insertApplication(appB, "active")
	env.insertMembership(appA, targetID, "active")
	service := env.newServiceWith(func(options *session.Options) {
		options.Authorizer = &stubAuthorizer{allow: map[string]bool{
			adminID + "|":        true,
			adminID + "|" + appA: true,
		}}
	})
	adminSession := env.loginWith(service, adminID, "", false, session.ClientInfo{})
	env.markStrongAuth(adminSession.Session.ID)
	env.loginWith(service, targetID, "", false, session.ClientInfo{})
	env.loginWith(service, targetID, appA, false, session.ClientInfo{})

	first, err := service.AdminListSessionsPage(env.ctx, adminSession.Secret.Reveal(),
		session.AdminSessionListPageRequest{TargetUserID: targetID, Limit: 1, Offset: 0,
			RequestID: "req-offset-admin-1"})
	if err != nil {
		t.Fatalf("管理员 offset 第一页: %v", err)
	}
	if first.Total != 2 || first.Returned != 1 || !first.HasMore || first.NextOffset != 1 {
		t.Fatalf("管理员 offset 第一页元数据 = %+v", first)
	}
	second, err := service.AdminListSessionsPage(env.ctx, adminSession.Secret.Reveal(),
		session.AdminSessionListPageRequest{TargetUserID: targetID, Limit: 1, Offset: 1,
			RequestID: "req-offset-admin-2"})
	if err != nil || second.Returned != 1 || second.HasMore || second.Total != 2 {
		t.Fatalf("管理员 offset 第二页 = %+v err=%v", second, err)
	}
	appPage, err := service.AdminListSessionsPage(env.ctx, adminSession.Secret.Reveal(),
		session.AdminSessionListPageRequest{ScopeAppID: appA, TargetUserID: targetID,
			Limit: 20, Offset: 0})
	if err != nil || appPage.Total != 1 || appPage.Returned != 1 {
		t.Fatalf("应用范围 offset 分页 = %+v err=%v", appPage, err)
	}
	// 未授权应用范围仍拒绝（分页形式不改变授权）。
	if _, err := service.AdminListSessionsPage(env.ctx, adminSession.Secret.Reveal(),
		session.AdminSessionListPageRequest{ScopeAppID: appB, TargetUserID: targetID}); !errors.Is(err, session.ErrAccessDenied) {
		t.Fatalf("未授权应用范围错误 = %v，期望 ErrAccessDenied", err)
	}
	// 非法分页参数。
	for _, request := range []session.AdminSessionListPageRequest{
		{TargetUserID: targetID, Limit: -1},
		{TargetUserID: targetID, Limit: session.MaxListPageSize + 1},
		{TargetUserID: targetID, Offset: -1},
		{TargetUserID: targetID, Offset: 1_000_001},
	} {
		if _, err := service.AdminListSessionsPage(env.ctx, adminSession.Secret.Reveal(),
			request); !errors.Is(err, session.ErrInvalidRequest) {
			t.Fatalf("非法管理员分页 %+v 错误 = %v，期望 ErrInvalidRequest", request, err)
		}
	}
}
