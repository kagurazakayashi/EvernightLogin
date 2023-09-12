package app

import (
	"context"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin"
)

func TestAdminListUsersAndGetByUsername(t *testing.T) {
	ctx := context.Background()
	runtime := openTestRuntime(t, Options{})
	created, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "Alice", Password: "K8$wR3!nB6@yF1#v", Nickname: "Alice",
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "bob", Password: "K8$wR3!nB6@yF1#v", Nickname: "Bob",
		RequestID: login.NewRequestID(),
	}); err != nil {
		t.Fatalf("Create bob: %v", err)
	}
	admin := runtime.Admin()
	local := runtime.LocalAdmin()
	page, err := admin.ListUsers(ctx, AdminListUsersRequest{
		Caller: local, Limit: 10, Sort: "username",
	})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(page.Users) != 2 || page.HasMore {
		t.Fatalf("ListUsers 结果 = %+v", page)
	}
	got, err := admin.GetUserByUsername(ctx, AdminUserByUsernameRequest{
		Caller: local, Username: "ALICE",
	})
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if got.ID != created.ID || got.Username != "Alice" {
		t.Fatalf("GetUserByUsername = %+v, want ID=%s", got, created.ID)
	}
	if _, err := admin.GetUserByUsername(ctx, AdminUserByUsernameRequest{
		Caller: local, Username: "missing-user",
	}); err == nil {
		t.Fatal("不存在的用户名必须返回错误")
	}
}
