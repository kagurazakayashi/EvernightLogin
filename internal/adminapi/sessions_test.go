package adminapi

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// revokerSession 在 stubSession 之上实现 SessionAdminRevoker。
type revokerSession struct {
	*stubSession
	result session.AdminRevokeResult
	err    error
	called bool
}

func (r *revokerSession) AdminRevoke(context.Context, string, session.AdminRevokeRequest) (session.AdminRevokeResult, error) {
	r.called = true
	return r.result, r.err
}

// TestSessionAdminRevokeRoute 覆盖步骤 151 管理 API：路由/确认/理由/成功返回，
// 以及强认证缺失映射和未实现 revoker 时不挂载路由。
func TestSessionAdminRevokeRoute(t *testing.T) {
	stub := &revokerSession{
		stubSession: &stubSession{secret: "s3cret", userID: "usr_00000000000000000000000000000001"},
		result:      session.AdminRevokeResult{Revoked: 2},
	}
	server, err := New(Options{Session: stub, ErrorCodes: testCodes()})
	if err != nil {
		t.Fatalf("构造管理 API 失败: %v", err)
	}
	body := `{"confirm":true,"target_user_id":"usr_00000000000000000000000000000002","reason":"security incident response"}`
	reply := callAPI(t, server, http.MethodPost, "/admin/v1/sessions/revoke", body, "Bearer s3cret", nil)
	if reply.status != http.StatusOK || !stub.called {
		t.Fatalf("管理员强制下线应成功: status=%d body=%s", reply.status, reply.body)
	}
	if !strings.Contains(string(reply.body), `"revoked":2`) {
		t.Fatalf("响应缺少撤销数量: %s", reply.body)
	}

	// 缺少确认/理由：400，不调用领域服务。
	for _, bad := range []string{
		`{"target_user_id":"usr_00000000000000000000000000000002","reason":"x"}`,
		`{"confirm":true,"target_user_id":"usr_00000000000000000000000000000002"}`,
	} {
		reply = callAPI(t, server, http.MethodPost, "/admin/v1/sessions/revoke", bad, "Bearer s3cret", nil)
		requireErrorCode(t, reply, http.StatusBadRequest, "REQ_INVALID")
	}

	// 强认证过期：映射 REAUTH_REQUIRED。
	stub.err = session.ErrStrongAuthRequired
	stub.result = session.AdminRevokeResult{}
	reply = callAPI(t, server, http.MethodPost, "/admin/v1/sessions/revoke", body, "Bearer s3cret", nil)
	requireErrorCode(t, reply, http.StatusForbidden, "REAUTH_REQUIRED")

	// 普通 stubSession 不实现可选接口：不挂载路由，返回 404 而不是放行。
	plain := &stubSession{secret: "s3cret", userID: "usr_00000000000000000000000000000001"}
	plainServer := newStubServer(t, plain)
	reply = callAPI(t, plainServer, http.MethodPost, "/admin/v1/sessions/revoke", body, "Bearer s3cret", nil)
	if reply.status != http.StatusNotFound {
		t.Fatalf("未装配 revoker 时路由应为 404，实际 %d", reply.status)
	}
}
