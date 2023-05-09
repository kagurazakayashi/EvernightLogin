package adminapi

import (
	"context"
	"net/http"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
)

// TestDomainRoutesContract 覆盖步骤 156 宿主领域路由扩展：统一认证/CSRF/envelope，
// 成功返回 data，DomainError 映射稳定错误码，未登记错误不泄露细节。
func TestDomainRoutesContract(t *testing.T) {
	stub := &stubSession{secret: "s3cret", userID: "usr_00000000000000000000000000000001"}
	server, err := New(Options{Session: stub, ErrorCodes: testCodes(),
		DomainRoutes: []DomainRoute{
			{Method: http.MethodGet, Pattern: "domain/ping", Handler: func(_ context.Context,
				caller account.Caller, _ *http.Request) (any, error) {
				return map[string]any{"user_id": caller.Actor().ID}, nil
			}},
			{Method: http.MethodGet, Pattern: "domain/denied", Handler: func(context.Context,
				account.Caller, *http.Request) (any, error) {
				return nil, &DomainError{Code: "ACCESS_DENIED", Message: "领域拒绝"}
			}},
			{Method: http.MethodPost, Pattern: "domain/write", Handler: func(context.Context,
				account.Caller, *http.Request) (any, error) {
				return map[string]any{"ok": true}, nil
			}},
		}})
	if err != nil {
		t.Fatalf("构造管理 API 失败: %v", err)
	}
	reply := callAPI(t, server, http.MethodGet, "/admin/v1/domain/ping", "", "Bearer s3cret", nil)
	requireSuccess(t, reply)
	reply = callAPI(t, server, http.MethodGet, "/admin/v1/domain/denied", "", "Bearer s3cret", nil)
	requireErrorCode(t, reply, http.StatusForbidden, "ACCESS_DENIED")
	// 写路由仍需认证；未认证不得到达领域处理器。
	reply = callAPI(t, server, http.MethodPost, "/admin/v1/domain/write", `{}`, "", nil)
	requireErrorCode(t, reply, http.StatusUnauthorized, "AUTH_FAILED")
	reply = callAPI(t, server, http.MethodPost, "/admin/v1/domain/write", `{}`, "Bearer s3cret", nil)
	requireSuccess(t, reply)
	// 未挂载的领域路由 404。
	reply = callAPI(t, server, http.MethodGet, "/admin/v1/domain/missing", "", "Bearer s3cret", nil)
	if reply.status != http.StatusNotFound {
		t.Fatalf("未挂载路由应为 404，实际 %d", reply.status)
	}
}
