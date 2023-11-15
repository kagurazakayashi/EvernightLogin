package app

// 步骤 225 P0：委派资格公开接口测试。
//   - LocalAdmin 签发（既有 GrantDelegation）→列表/详情→撤回→幂等撤回；
//   - LocalAdmin 不能作为 Delegator（actor 模型限制，稳定拒绝而非数据约束错误）；
//   - 普通用户不能撤回（只有受信通道），只能读自己的资格。

import (
	"context"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// TestDelegationPublicFlow 覆盖委派资格列表/详情/撤回与 Actor 模型限制。
func TestDelegationPublicFlow(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 7, 20, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	local := runtime.LocalAdmin()
	delegations := runtime.Delegations()
	adminAPI := runtime.Admin()
	const password = "K8$wR3!nB6@yF1#v"
	delegator := createLifecycleUser(t, ctx, runtime, "delegator-user", password)

	// 先创建一个可委派的系统权限目录项。
	permission, err := adminAPI.CreatePermission(ctx, AdminCreatePermissionRequest{
		Caller: local, ScopeID: "system", Key: "delegation.test.perm",
		Name: "委派测试权限", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("CreatePermission: %v", err)
	}
	granted, err := adminAPI.GrantDelegation(ctx, AdminDelegationGrantRequest{
		Caller: local, DelegatorUserID: delegator.ID, ScopeID: "system",
		PermissionKey: "delegation.test.perm", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("GrantDelegation: %v", err)
	}
	if granted.ID == "" || granted.DelegatorUserID != delegator.ID {
		t.Fatalf("签发结果异常: %+v", granted)
	}
	// 列表（受信通道可读全部）。
	list, err := delegations.ListDelegations(ctx, AdminListDelegationsRequest{
		Caller: local, Page: AdminPage{Limit: 10}, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("ListDelegations: %v", err)
	}
	if len(list.Delegations) != 1 || list.Delegations[0].ID != granted.ID ||
		list.Delegations[0].PermissionKey != "delegation.test.perm" {
		t.Fatalf("委派列表异常: %+v", list)
	}
	detail, err := delegations.GetDelegation(ctx, AdminDelegationRequest{
		Caller: local, GrantID: granted.ID, RequestID: login.NewRequestID()})
	if err != nil || detail.ID != granted.ID || detail.PermissionID != permission.ID {
		t.Fatalf("GetDelegation: %+v, %v", detail, err)
	}
	// 可转授权限只能由普通用户查询自己的：LocalAdmin 拒绝，真实用户可用。
	if _, err := delegations.DelegatablePermissions(ctx,
		AdminDelegatablePermissionsRequest{Caller: local, ScopeID: "system",
			RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeAccessDenied) {
		t.Fatalf("LocalAdmin 查询可转授权限错误 = %v，期望 ACCESS_DENIED", err)
	}
	delegatorSession := loginLifecycleUser(t, ctx, runtime, "delegator-user", password)
	if _, err := delegations.DelegatablePermissions(ctx,
		AdminDelegatablePermissionsRequest{Caller: runtime.AdminSession(delegatorSession),
			ScopeID: "system", RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("用户查询可转授权限失败: %v", err)
	}
	// LocalAdmin 不能作为 Delegator：操作者 ID 不是真实用户。
	if _, err := adminAPI.GrantDelegation(ctx, AdminDelegationGrantRequest{
		Caller: local, DelegatorUserID: "host-operator", ScopeID: "system",
		PermissionKey: "delegation.test.perm",
		RequestID:     login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("LocalAdmin 作为 Delegator 错误 = %v，期望 REQ_INVALID", err)
	}
	// 撤回：Changed=true；重复撤回幂等 Changed=false。
	revoked, err := delegations.RevokeDelegation(ctx, AdminDelegationRequest{
		Caller: local, GrantID: granted.ID, RequestID: login.NewRequestID()})
	if err != nil || !revoked.Changed || revoked.Grant.RevokedAt == "" {
		t.Fatalf("撤回委派异常: %+v, %v", revoked, err)
	}
	again, err := delegations.RevokeDelegation(ctx, AdminDelegationRequest{
		Caller: local, GrantID: granted.ID, RequestID: login.NewRequestID()})
	if err != nil || again.Changed {
		t.Fatalf("重复撤回应幂等成功: %+v, %v", again, err)
	}
	// 普通用户不能撤回（即使读取自己的资格允许）。
	session := loginLifecycleUser(t, ctx, runtime, "delegator-user", password)
	if _, err := delegations.RevokeDelegation(ctx, AdminDelegationRequest{
		Caller: runtime.AdminSession(session), GrantID: granted.ID,
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeAccessDenied) {
		t.Fatalf("普通用户撤回委派错误 = %v，期望 ACCESS_DENIED", err)
	}
}
