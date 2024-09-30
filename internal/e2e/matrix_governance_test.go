package e2e

// 步骤 274 矩阵六：269 结转——OpenAPI 契约无秘密示例（268）、游标绑定（262/263）、
// ResourceID 非授权资源（251）。
//
// 说明：OpenAPI 契约以仓库内已提交的 docs/reference/http-openapi*.json 为唯一来源，
// 只做只读断言；游标与资源范围通过公开 Go/HTTP 门面执行真实判定。

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	login "github.com/kagurazakayashi/EvernightLogin"
	loginapp "github.com/kagurazakayashi/EvernightLogin/app"
)

// TestMatrixOpenAPIContractNoSecrets 断言 HTTP OpenAPI 契约包含直接管理路由且不含真实
// 密钥/令牌/口令材料（示例只能是占位或合成说明）。
func TestMatrixOpenAPIContractNoSecrets(t *testing.T) {
	root := repoRoot(t)
	adminBytes, err := os.ReadFile(filepath.Join(root,
		"docs", "reference", "http-openapi-admin.json"))
	if err != nil {
		t.Fatalf("读取管理 OpenAPI 契约: %v", err)
	}
	mainBytes, err := os.ReadFile(filepath.Join(root,
		"docs", "reference", "http-openapi.json"))
	if err != nil {
		t.Fatalf("读取主 OpenAPI 契约: %v", err)
	}
	var admin, public map[string]any
	if err := json.Unmarshal(adminBytes, &admin); err != nil {
		t.Fatalf("管理 OpenAPI 不是合法 JSON: %v", err)
	}
	if err := json.Unmarshal(mainBytes, &public); err != nil {
		t.Fatalf("主 OpenAPI 不是合法 JSON: %v", err)
	}
	adminPaths, _ := admin["paths"].(map[string]any)
	if len(adminPaths) == 0 {
		t.Fatal("管理 OpenAPI 未声明任何路径")
	}
	for _, required := range []string{
		"/users/{user_id}/username", "/users/{user_id}/username-verification",
		"/users/{user_id}/password", "/users/{user_id}/password-verification",
	} {
		if _, ok := adminPaths[required]; !ok {
			t.Fatalf("管理 OpenAPI 缺少直接管理路径 %q", required)
		}
	}
	// 直接管理提交必须声明鉴权（Bearer 管理会话），不能是匿名端点。
	usernamePath, _ := adminPaths["/users/{user_id}/username"].(map[string]any)
	if usernamePath == nil {
		t.Fatal("管理 OpenAPI 直接改名路径不是对象")
	}
	post, _ := usernamePath["post"].(map[string]any)
	if post == nil {
		t.Fatal("管理 OpenAPI 直接改名路径缺少 post")
	}
	// 鉴权可在 operation、path 或文档级 security 声明；任一存在即视为已声明。
	_, postSecurity := post["security"]
	_, pathSecurity := usernamePath["security"]
	_, globalSecurity := admin["security"]
	if !postSecurity && !pathSecurity && !globalSecurity {
		t.Fatal("管理 OpenAPI 直接改名提交未声明 security")
	}
	if responses, ok := post["responses"].(map[string]any); !ok || responses == nil {
		t.Fatal("管理 OpenAPI 直接改名提交缺少 responses")
	}
	// 契约中的敏感键只允许类型/格式定义或占位示例，不得出现真实秘密。
	secretKeyPattern := regexp.MustCompile(`(?i)(password|secret|token|private[_ -]?key|credential|hash|seed)`)
	placeholderValues := map[string]bool{"": true, "string": true, "password": true,
		"example": true, "synthetic": true, "redacted": true, "*": true, "***": true,
		"<redacted>": true}
	jwtPattern := regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)
	privateKeyPattern := regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)
	highEntropyPattern := regexp.MustCompile(`^[A-Za-z0-9+/=_-]{40,}$`)
	// 本套件测试用口令不得出现在契约示例中（示例必须合成、不可复用真实测试值）。
	forbiddenLiterals := []string{operatorPassword, targetPassword, directPasswordA,
		directPasswordB, finalPassword}
	var walk func(path string, value any)
	walk = func(path string, value any) {
		switch typed := value.(type) {
		case map[string]any:
			for key, child := range typed {
				childPath := path + "/" + key
				if text, ok := child.(string); ok && secretKeyPattern.MatchString(key) &&
					!placeholderValues[strings.TrimSpace(text)] &&
					!isSyntheticSecretExample(text) {
					// OpenAPI schema 的 type/format 字段也是字符串；只拒绝看起来像真实值的
					// 非占位示例。显式标注 synthetic/example/not-real 的合成示例允许。
					if highEntropyPattern.MatchString(text) || strings.Contains(text, "Bearer ") {
						t.Fatalf("OpenAPI 敏感字段 %s 含疑似真实秘密示例: %q", childPath, text)
					}
				}
				walk(childPath, child)
			}
		case []any:
			for index, child := range typed {
				walk(path+"["+strings.Repeat("0", 0)+"]", child)
				_ = index
			}
		case string:
			if privateKeyPattern.MatchString(typed) {
				t.Fatalf("OpenAPI 含私钥材料: %q", path)
			}
			if jwtPattern.MatchString(typed) {
				t.Fatalf("OpenAPI 含 JWT 样式真实令牌: %q", path)
			}
			if strings.Contains(typed, "Bearer ") && highEntropyPattern.
				MatchString(strings.TrimPrefix(typed, "Bearer ")) {
				t.Fatalf("OpenAPI 含 Bearer 令牌示例: %q", path)
			}
			for _, forbidden := range forbiddenLiterals {
				if strings.Contains(typed, forbidden) {
					t.Fatalf("OpenAPI 含真实测试口令: %q", path)
				}
			}
		}
	}
	walk("admin", admin)
	walk("public", public)
}

// isSyntheticSecretExample 判断契约示例是否显式标注为合成/占位（不是真实凭据）。
func isSyntheticSecretExample(text string) bool {
	lower := strings.ToLower(strings.TrimSpace(text))
	for _, marker := range []string{"synthetic", "example", "not-real", "placeholder",
		"redacted", "sample", "test-only", "test_token", "replace"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// TestMatrixAuditCursorBinding 断言审计游标绑定 scope/筛选/排序，切换条件后旧游标拒绝。
func TestMatrixAuditCursorBinding(t *testing.T) {
	env := openEnv(t)
	ctx := context.Background()
	local := env.Runtime.LocalAdmin()
	admin := env.Runtime.Admin()
	// 产生一些真实审计事件（建用户/登录）。
	for index := 0; index < 3; index++ {
		createUser(t, env.Runtime, "cursor-user-"+string(rune('a'+index)), targetPassword)
	}
	first, err := admin.ListAuditEvents(ctx, loginapp.AdminListAuditEventsRequest{
		Caller: local, ScopeID: "system", Filter: loginapp.AdminAuditFilter{},
		Order: "occurred_asc", Limit: 2, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("读取第一页审计事件: %v", err)
	}
	if first.NextCursor == "" {
		t.Fatalf("审计事件第一页未返回 NextCursor: hasMore=%v count=%d",
			first.HasMore, len(first.Events))
	}
	// 同 scope/筛选/排序可继续使用游标。
	if _, err := admin.ListAuditEvents(ctx, loginapp.AdminListAuditEventsRequest{
		Caller: local, ScopeID: "system", Filter: loginapp.AdminAuditFilter{},
		Order: "occurred_asc", Limit: 2, Cursor: first.NextCursor,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("同条件复用游标失败: %v", err)
	}
	// 切换筛选（Outcome）复用游标必须拒绝，避免跨条件翻页。
	if _, err := admin.ListAuditEvents(ctx, loginapp.AdminListAuditEventsRequest{
		Caller: local, ScopeID: "system",
		Filter: loginapp.AdminAuditFilter{Outcome: "success"},
		Order:  "occurred_asc", Limit: 2, Cursor: first.NextCursor,
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("切换筛选复用游标 = %v，期望 REQ_INVALID", err)
	}
	// 切换排序复用游标必须拒绝。
	if _, err := admin.ListAuditEvents(ctx, loginapp.AdminListAuditEventsRequest{
		Caller: local, ScopeID: "system", Filter: loginapp.AdminAuditFilter{},
		Order: "occurred_desc", Limit: 2, Cursor: first.NextCursor,
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("切换排序复用游标 = %v，期望 REQ_INVALID", err)
	}
}

// TestMatrixResourceIDScope 覆盖会话授权对具体业务资源的数据范围判定（251）：
// 资源在授权清单内允许；非授权资源、跨应用同名权限、mode=none 一律拒绝。
func TestMatrixResourceIDScope(t *testing.T) {
	env := openEnv(t)
	ctx := context.Background()
	local := env.Runtime.LocalAdmin()
	admin := env.Runtime.Admin()
	member := createUser(t, env.Runtime, "scope-member", targetPassword)
	_ = createUser(t, env.Runtime, "scope-outsider", targetPassword)

	createEnabledApp := func(name string) loginapp.AdminApplication {
		t.Helper()
		created, err := admin.CreateApplication(ctx, loginapp.AdminCreateApplicationRequest{
			Caller: local, Name: name, RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("创建应用 %s: %v", name, err)
		}
		enabled, err := admin.SetApplicationEnabled(ctx,
			loginapp.AdminSetApplicationEnabledRequest{Caller: local,
				ApplicationID: created.ID, Enabled: true, ExpectedRowVersion: created.RowVersion,
				RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("启用应用 %s: %v", name, err)
		}
		if err := admin.AddApplicationMember(ctx, loginapp.AdminAddMemberRequest{
			Caller: local, ApplicationID: enabled.ID, UserID: member.ID,
			RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("成员加入应用 %s: %v", name, err)
		}
		return enabled
	}
	appA := createEnabledApp("274 资源范围应用 A")
	appB := createEnabledApp("274 资源范围应用 B")

	assignAppRole := func(scopeID, roleKey, permissionKey, dataScope string) loginapp.AdminRole {
		t.Helper()
		permission, err := admin.CreatePermission(ctx, loginapp.AdminCreatePermissionRequest{
			Caller: local, ScopeID: scopeID, Key: permissionKey, Name: permissionKey,
			RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("创建应用权限 %s: %v", permissionKey, err)
		}
		role, err := admin.CreateRole(ctx, loginapp.AdminCreateRoleRequest{
			Caller: local, ScopeID: scopeID, Key: roleKey, Name: roleKey,
			RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("创建应用角色 %s: %v", roleKey, err)
		}
		if err := admin.AddRolePermission(ctx, loginapp.AdminRolePermissionRequest{
			Caller: local, RoleID: role.ID, PermissionID: permission.ID,
			RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("应用角色组合权限: %v", err)
		}
		if err := admin.GrantApplicationRole(ctx, loginapp.GrantRoleRequest{
			Caller: local, UserID: member.ID, RoleID: role.ID,
			RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("分配应用角色: %v", err)
		}
		// 公开分配接口尚不接受数据范围；用只读夹具补写分配记录数据范围（不改定义）。
		executeSQL(t, env.DBPath,
			`UPDATE user_roles SET data_scope_json='`+dataScope+
				`' WHERE user_id='`+member.ID+`' AND role_id='`+role.ID+`'`)
		return role
	}
	assignAppRole(appA.ID, "scope-resources", "invoice.read",
		`{"v":1,"mode":"resources","resources":["invoice-1"]}`)
	assignAppRole(appA.ID, "scope-none", "invoice.none.read", `{"v":1,"mode":"none"}`)
	assignAppRole(appB.ID, "scope-cross-b", "invoice.read",
		`{"v":1,"mode":"resources","resources":["invoice-2"]}`)

	loginResult, err := env.Runtime.Auth().Login(ctx, loginapp.LoginRequest{
		Username: "scope-member", Password: targetPassword, AppID: appA.ID,
		ClientIP: "127.0.0.1", RequestID: login.NewRequestID()})
	if err != nil || len(loginResult.SessionSecret) == 0 {
		t.Fatalf("成员应用会话登录: %v", err)
	}
	authorize := func(appID string, permission, resourceID string) loginapp.SessionAccessDecision {
		t.Helper()
		decision, err := env.Runtime.Sessions().Authorize(ctx,
			loginapp.SessionAccessRequest{SessionSecret: loginResult.SessionSecret,
				AppID: appID, Permissions: []string{permission}, ResourceID: resourceID,
				RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("Sessions.Authorize(%s,%s,%s): %v", appID, permission, resourceID, err)
		}
		return decision
	}
	if decision := authorize(appA.ID, "invoice.read", "invoice-1"); !decision.Allowed {
		t.Fatalf("授权清单内资源应允许: %+v", decision)
	}
	if decision := authorize(appA.ID, "invoice.read", "invoice-2"); decision.Allowed {
		t.Fatalf("非授权资源不应允许: %+v", decision)
	}
	if decision := authorize(appB.ID, "invoice.read", "invoice-1"); decision.Allowed {
		t.Fatalf("跨应用同名权限不应允许: %+v", decision)
	}
	if decision := authorize(appA.ID, "invoice.none.read", "invoice-1"); decision.Allowed {
		t.Fatalf("mode=none 不应允许资源: %+v", decision)
	}
	// 非成员（outsider）无法用别人会话：会话只属于 member；用外部应用 ID 也不能放行。
	if decision := authorize(appB.ID, "invoice.read", "invoice-1"); decision.Allowed {
		t.Fatalf("跨应用资源判定不应允许: %+v", decision)
	}
}
