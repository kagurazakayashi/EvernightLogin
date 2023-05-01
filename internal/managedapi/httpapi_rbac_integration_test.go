package managedapi_test

// 步骤 148 真实集成测试：真实 SQLite/域服务 + HTTP 传输创建应用组/角色/权限，
// 验证跨应用隔离、内置删除拒绝、角色自我/越权分配由既有委派 Guard 拒绝，以及
// 撤权后写立即失败。策略边界仍由 managedapi 统一判定。

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	. "github.com/kagurazakayashi/EvernightLogin/internal/managedapi"
)

func TestManagedAPIRBACRealServices(t *testing.T) {
	env := newTestEnv(t)
	policy := policyFor(testAppOne, []string{"status", "username", "display_name"},
		[]string{"display_name"})
	policy.Operations.Allowed = append(policy.Operations.Allowed,
		OpGroupsCreate, OpGroupsUpdate, OpGroupsDelete,
		OpRolesCreate, OpRolesUpdate, OpRolesDelete,
		OpPermissionsCreate, OpPermissionsUpdate, OpPermissionsDelete,
		OpPermissionsEnable, OpPermissionsDisable)
	for index := range policy.Fields {
		switch policy.Fields[index].Object {
		case ObjectGroup:
			policy.Fields[index].Read = []string{"id", "key", "name", "description"}
			policy.Fields[index].Write = []string{"key", "name", "description"}
		case ObjectRole:
			policy.Fields[index].Read = []string{"id", "key", "name", "description", "limits"}
			policy.Fields[index].Write = []string{"key", "name", "description", "limits"}
		case ObjectPermission:
			policy.Fields[index].Read = []string{"id", "key", "name", "description", "limits", "enabled"}
			policy.Fields[index].Write = []string{"key", "name", "description", "limits"}
		}
	}
	env.setPolicy(testAppOne, policy)
	server, session := newHTTPAPITestServer(t, env)
	base := server.URL + "/api/managed/v1/applications/" + testAppOne
	secret := session.Secret.Reveal()

	post := func(path, key, body string) (int, []byte) {
		status, payload, _ := apiRequest(t, http.MethodPost, base+path, secret,
			[]byte(body), key)
		return status, payload
	}
	status, payload := post("/groups", "idem-rbac-group",
		`{"key":"http-group","name":"HTTP 组"}`)
	if status != http.StatusOK || !bytes.Contains(payload, []byte("http-group")) {
		t.Fatalf("创建组 = %d %s", status, payload)
	}
	status, payload = post("/roles", "idem-rbac-role",
		`{"key":"http-role","name":"HTTP 角色","description":"HTTP 说明","limits":"none"}`)
	if status != http.StatusOK || !bytes.Contains(payload, []byte("http-role")) {
		t.Fatalf("创建角色 = %d %s", status, payload)
	}
	status, payload = post("/permissions", "idem-rbac-perm",
		`{"key":"http.test","name":"HTTP 权限","description":"HTTP 说明","limits":"none"}`)
	if status != http.StatusOK || !bytes.Contains(payload, []byte("http.test")) {
		t.Fatalf("创建权限 = %d %s", status, payload)
	}
	// 读取列表只能看到本应用对象（真实 service 过滤）。
	status, payload, _ = apiRequest(t, http.MethodGet, base+"/groups", secret, nil, "")
	if status != http.StatusOK || !bytes.Contains(payload, []byte("http-group")) {
		t.Fatalf("组列表 = %d %s", status, payload)
	}

	// 跨应用对象 ID 不能通过应用 A 的路径操作：应用 B 的组 ID 由领域服务
	// scope 归属检查拒绝，而不是仅看对象范围。
	status, payload, _ = apiRequest(t, http.MethodPatch,
		base+"/groups/"+testGroupAppTwo, secret,
		[]byte(`{"name":"跨应用改名"}`), "idem-rbac-cross-app")
	if status == http.StatusOK {
		t.Fatalf("跨应用组操作不应成功: %d %s", status, payload)
	}

	// 内置角色删除必须被领域服务拒绝（不能通过策略/API 绕过 builtin 保护）。
	status, payload, _ = apiRequest(t, http.MethodDelete,
		base+"/roles/"+testRoleOne, secret, nil, "idem-rbac-builtin")
	if status != http.StatusForbidden && status != http.StatusConflict {
		t.Fatalf("删除内置角色 = %d %s", status, payload)
	}
	// 把带权限的内置角色分配给其他用户：真实委派 Guard 拒绝非 root 的越权分配。
	status, payload = post("/roles/"+testRoleOne+"/assign", "idem-rbac-assign",
		`{"user_id":"`+testWorker+`"}`)
	if status != http.StatusForbidden && status != http.StatusConflict {
		t.Fatalf("越权角色分配 = %d %s", status, payload)
	}

	// 撤权后写立即拒绝：移除 roles.create 后同一主体不能继续建角色。
	revoked := policy
	revoked.Operations.Allowed = removeString(revoked.Operations.Allowed, OpRolesCreate)
	actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: "root-admin"}
	if _, err := env.service.SetPolicy(env.ctx, actor, SetPolicyRequest{
		ApplicationID: testAppOne, Policy: revoked, ExpectedRowVersion: 1,
		RequestID: "req_148_revoke"}); err != nil {
		t.Fatalf("撤权策略失败: %v", err)
	}
	status, payload = post("/roles", "idem-rbac-revoked",
		`{"key":"after-revoke","name":"撤权后"}`)
	if status != http.StatusForbidden {
		t.Fatalf("撤权后建角色 = %d %s", status, payload)
	}
}
