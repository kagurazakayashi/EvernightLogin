package app_test

// 步骤 251 外部模块视角测试：只导入公开包（根包 login 与公开门面 app），验证
// AccessService 的资源范围判定契约：
//   - 功能权限判定与具体资源判定分离：不提供 ResourceID 时决策明确 ResourceChecked
//     为 false，不声称任何具体资源已校验；
//   - 提供 ResourceID 时走资源级判定，公开接口创建的分配未声明数据范围（undefined）
//     时按默认拒绝返回稳定 RESOURCE_FORBIDDEN，不能只返回功能权限结论；
//   - 空权限不是“无需权限”，返回 REQ_INVALID，客户端不能靠空权限自证授权。
//
// 文件刻意不导入任何 internal 包，证明宿主使用资源级授权既不需要、也不能依赖内部
// 类型。数据范围“允许”的定向证据（resources/all/none/跨应用）在 app 包内部测试
// 中用 SQL 夹具补写分配数据范围后验证（公开管理接口尚无写数据范围入口）。

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/app"
)

// TestPublicResourceScopeContractFromExternalModule 从外部模块视角验证资源级授权
// 契约的最小闭环（功能权限允许、资源级默认拒绝、空权限拒绝）。
func TestPublicResourceScopeContractFromExternalModule(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cfg := login.Default()
	cfg.Registration.Enabled = true
	runtime, err := app.Open(ctx, app.Options{
		Config: &cfg, DatabasePath: filepath.Join(dir, "login.db"),
		MasterKeyFile: filepath.Join(dir, "master.key"), CreateMasterKey: true,
		Migrate: true, OperatorID: "external-resource-scope-test", Now: time.Now,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })

	const password = "K8$wR3!nB6@yF1#v"
	member, err := runtime.Users().Create(ctx, app.CreateUserRequest{
		Username: "external-scope-member", Password: password,
		Nickname: "外部资源成员", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建成员用户失败: %v", err)
	}
	local := runtime.LocalAdmin()
	admin := runtime.Admin()
	createdApp, err := admin.CreateApplication(ctx, app.AdminCreateApplicationRequest{
		Caller: local, Name: "外部资源应用", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建应用失败: %v", err)
	}
	enabledApp, err := admin.SetApplicationEnabled(ctx, app.AdminSetApplicationEnabledRequest{
		Caller: local, ApplicationID: createdApp.ID, Enabled: true,
		ExpectedRowVersion: createdApp.RowVersion, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("启用应用失败: %v", err)
	}
	permission, err := admin.CreatePermission(ctx, app.AdminCreatePermissionRequest{
		Caller: local, ScopeID: enabledApp.ID, Key: "external.invoice.read",
		Name: "读取外部发票", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建权限失败: %v", err)
	}
	role, err := admin.CreateRole(ctx, app.AdminCreateRoleRequest{
		Caller: local, ScopeID: enabledApp.ID, Key: "external-invoice-reader",
		Name: "外部发票读取员", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建角色失败: %v", err)
	}
	if err := admin.AddRolePermission(ctx, app.AdminRolePermissionRequest{
		Caller: local, RoleID: role.ID, PermissionID: permission.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("角色组合权限失败: %v", err)
	}
	if err := admin.AddApplicationMember(ctx, app.AdminAddMemberRequest{
		Caller: local, ApplicationID: enabledApp.ID, UserID: member.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("加入应用成员失败: %v", err)
	}
	if err := admin.GrantApplicationRole(ctx, app.GrantRoleRequest{
		Caller: local, UserID: member.ID, RoleID: role.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("分配角色失败: %v", err)
	}

	access := runtime.Access()

	// 功能权限允许，且决策明确未校验具体资源。
	const functionalRequestID = "req_external_resource_functional"
	functional, err := access.Check(ctx, app.AccessRequest{
		UserID: member.ID, AppID: enabledApp.ID, Permission: "external.invoice.read",
		RequestID: functionalRequestID})
	if err != nil {
		t.Fatalf("功能权限检查失败: %v", err)
	}
	if !functional.Allowed || functional.ResourceChecked || functional.ResourceID != "" {
		t.Fatalf("功能权限决策异常（不得声称已校验资源）: %+v", functional)
	}
	if functional.RequestID != functionalRequestID ||
		functional.Application != enabledApp.ID {
		t.Fatalf("功能权限决策回显异常: %+v", functional)
	}

	// 提供 ResourceID：功能权限通过后仍须数据范围判定；公开接口创建的分配未声明
	// 数据范围（undefined），必须默认拒绝而不能沿用功能权限结论。
	const resourceRequestID = "req_external_resource_scoped"
	resource, err := access.Check(ctx, app.AccessRequest{
		UserID: member.ID, AppID: enabledApp.ID, Permission: "external.invoice.read",
		ResourceID: "invoice-1", RequestID: resourceRequestID})
	if err != nil {
		t.Fatalf("资源级检查失败: %v", err)
	}
	if resource.Allowed || !resource.ResourceChecked || resource.ResourceID != "invoice-1" {
		t.Fatalf("资源级决策异常: %+v", resource)
	}
	if resource.Code != string(login.CodeResourceForbidden) ||
		resource.Reason != "data_scope_undefined" || resource.RequestID != resourceRequestID {
		t.Fatalf("资源级默认拒绝语义异常: %+v", resource)
	}

	// 空权限不是“无需权限”：返回 REQ_INVALID，不能返回 Allowed=true。
	if decision, err := access.Check(ctx, app.AccessRequest{
		UserID: member.ID, AppID: enabledApp.ID, ResourceID: "invoice-1",
		RequestID: "req_external_empty_permission"}); err == nil {
		t.Fatalf("空权限必须拒绝，实际决策: %+v", decision)
	} else if !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("空权限应返回 REQ_INVALID，实际 %v", err)
	}
}
