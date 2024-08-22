package access_test

import (
	"context"
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/access"
	"github.com/kagurazakayashi/EvernightLogin/httpapi"
)

func TestPermissionAndAccessRequest(t *testing.T) {
	if err := access.Permission("users.read").Validate(); err != nil {
		t.Fatalf("合法权限被拒绝: %v", err)
	}
	if err := access.Permission("bad permission with space").Validate(); err == nil {
		t.Fatal("非法权限应拒绝")
	}
	identity := httpapi.Identity{Kind: httpapi.IdentityKindUser, SubjectID: "user-1"}
	request := access.AccessRequest{Identity: identity, Permission: "users.read",
		Scope: access.PermissionScopeSystem}
	if err := request.Validate(); err != nil {
		t.Fatalf("合法访问请求被拒绝: %v", err)
	}
	applicationScoped := request
	applicationScoped.Scope = access.PermissionScopeApplication
	if err := applicationScoped.Validate(); err == nil {
		t.Fatal("应用范围缺少 AppID 应拒绝")
	}
	controller := access.AccessControllerFunc(func(ctx context.Context,
		request access.AccessRequest) (access.AccessDecision, error) {
		return access.AccessDecision{}, errors.New("denied")
	})
	if _, err := controller.CheckAccess(context.Background(), request); err == nil {
		t.Fatal("控制器错误应传播")
	}
}
