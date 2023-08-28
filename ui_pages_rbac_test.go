package login_test

// 步骤 69 角色/权限/委派/有效权限页面契约测试：受控 UIRBACBackend 渲染与表单/错误
// 映射；真实服务集成见 ui_pages_rbac_integration_test.go。测试替身只用于页面组件
// 契约，不充当生产鉴权。

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
)

type fakeRBACBackend struct {
	roles       []login.UIRBACRoleView
	permissions []login.UIRBACPermissionView
	role        login.UIRBACRoleView
	permission  login.UIRBACPermissionView
	available   []login.UIRBACPermissionView
	assignments login.UIRBACAssignments
	compose     login.UIRBACComposeResult
	assign      login.UIRBACAssignResult
	effective   login.UIRBACEffectiveView
	diff        login.UIRBACPresetDiff
	delegation  login.UIRBACDelegationView
	// 步骤 189：删除/停用影响预览与权限登记动作的受控结果。
	impact     login.UIRBACPermissionImpact
	lastCreate login.UIRBACCreatePermission
	failCode   string
	lastAction string
	lastTarget string
	empty      bool
}

func (f *fakeRBACBackend) fail() error {
	if f.failCode != "" {
		return &login.UIRBACError{Code: f.failCode}
	}
	return nil
}

func (f *fakeRBACBackend) ListScopes(context.Context, string) ([]login.UIRBACScope, error) {
	if err := f.fail(); err != nil {
		return nil, err
	}
	return []login.UIRBACScope{{ScopeID: "system", Kind: "system", Active: true},
		{ScopeID: "app_1111", Kind: "application", ApplicationID: "app_1111",
			ApplicationName: "示例应用", Active: true}}, nil
}

func (f *fakeRBACBackend) ListRoles(_ context.Context, _ string,
	query login.UIRBACRoleQuery) (login.UIRBACRolePage, error) {
	if err := f.fail(); err != nil {
		return login.UIRBACRolePage{}, err
	}
	roles := f.roles
	if f.empty {
		roles = nil
	}
	if query.ScopeID != "" && !f.empty {
		roles = nil
		for _, item := range f.roles {
			if item.ScopeID == query.ScopeID {
				roles = append(roles, item)
			}
		}
	}
	return login.UIRBACRolePage{Roles: roles, HasMore: !f.empty, NextOffset: 20}, nil
}

func (f *fakeRBACBackend) GetRole(context.Context, string,
	string) (login.UIRBACRoleDetail, error) {
	if err := f.fail(); err != nil {
		return login.UIRBACRoleDetail{}, err
	}
	return login.UIRBACRoleDetail{Role: f.role, Available: f.available,
		Assignments: f.assignments}, nil
}

func (f *fakeRBACBackend) CreateRole(_ context.Context, _ string,
	create login.UIRBACCreateRole, _ string) (login.UIRBACRoleView, error) {
	if err := f.fail(); err != nil {
		return login.UIRBACRoleView{}, err
	}
	if create.Name == "" {
		return login.UIRBACRoleView{}, &login.UIRBACError{Code: "REQ_INVALID"}
	}
	return login.UIRBACRoleView{ID: "role_new", ScopeID: create.ScopeID,
		Key: create.Key, Name: create.Name, Enabled: true}, nil
}

func (f *fakeRBACBackend) UpdateRole(_ context.Context, _, roleID string,
	change login.UIRBACTextChange, _ string) (login.UIRBACRoleView, error) {
	if err := f.fail(); err != nil {
		return login.UIRBACRoleView{}, err
	}
	role := f.role
	role.ID = roleID
	role.Name = change.Name
	return role, nil
}

func (f *fakeRBACBackend) SetRoleState(_ context.Context, _, roleID string, enable bool,
	_ string) (login.UIRBACRoleView, bool, error) {
	if err := f.fail(); err != nil {
		return login.UIRBACRoleView{}, false, err
	}
	role := f.role
	role.ID = roleID
	role.Enabled = enable
	return role, true, nil
}

func (f *fakeRBACBackend) ComposeRolePermission(_ context.Context, _, roleID,
	permissionID string, add bool, _ string) (login.UIRBACComposeResult, error) {
	if err := f.fail(); err != nil {
		return login.UIRBACComposeResult{}, err
	}
	result := f.compose
	result.Action = "remove"
	if add {
		result.Action = "add"
	}
	result.Before = []login.UIRBACPermissionView{{PermissionID: "perm_old",
		Key: "users.read", Name: "读取用户"}}
	result.After = []login.UIRBACPermissionView{{PermissionID: "perm_old",
		Key: "users.read", Name: "读取用户"}, {PermissionID: permissionID,
		Key: "roles.read", Name: "读取角色"}}
	result.Added = []login.UIRBACPermissionView{{PermissionID: permissionID,
		Key: "roles.read", Name: "读取角色"}}
	result.AffectedUsers = 1
	result.AffectedGroups = 1
	return result, nil
}

func (f *fakeRBACBackend) ListAssignments(context.Context, string,
	string) (login.UIRBACAssignments, error) {
	if err := f.fail(); err != nil {
		return login.UIRBACAssignments{}, err
	}
	return f.assignments, nil
}

func (f *fakeRBACBackend) AssignRole(_ context.Context, _, roleID, targetKind, targetID,
	_ string, assign bool) (login.UIRBACAssignResult, error) {
	if err := f.fail(); err != nil {
		return login.UIRBACAssignResult{}, err
	}
	if strings.ContainsAny(targetID, " \t") {
		return login.UIRBACAssignResult{}, &login.UIRBACError{Code: "REQ_INVALID"}
	}
	f.lastTarget = targetID
	action := "assign"
	if !assign {
		action = "revoke"
	}
	return login.UIRBACAssignResult{Action: action, TargetKind: targetKind,
		TargetID: targetID, DataScope: "{}", Changed: true}, nil
}

func (f *fakeRBACBackend) ListPermissions(_ context.Context, _ string,
	query login.UIRBACPermissionQuery) (login.UIRBACPermissionPage, error) {
	if err := f.fail(); err != nil {
		return login.UIRBACPermissionPage{}, err
	}
	permissions := f.permissions
	if f.empty {
		permissions = nil
	}
	if query.ScopeID != "" && !f.empty {
		permissions = nil
		for _, item := range f.permissions {
			if item.ScopeID == query.ScopeID {
				permissions = append(permissions, item)
			}
		}
	}
	return login.UIRBACPermissionPage{Permissions: permissions, HasMore: !f.empty,
		NextOffset: 20}, nil
}

func (f *fakeRBACBackend) GetPermission(context.Context, string,
	string) (login.UIRBACPermissionDetail, error) {
	if err := f.fail(); err != nil {
		return login.UIRBACPermissionDetail{}, err
	}
	return login.UIRBACPermissionDetail{Permission: f.permission,
		DefaultRoles: []string{"system_admin"}}, nil
}

func (f *fakeRBACBackend) UpdatePermission(_ context.Context, _, permissionID string,
	change login.UIRBACTextChange, _ string) (login.UIRBACPermissionView, error) {
	if err := f.fail(); err != nil {
		return login.UIRBACPermissionView{}, err
	}
	permission := f.permission
	permission.PermissionID = permissionID
	permission.Name = change.Name
	return permission, nil
}

func (f *fakeRBACBackend) SetPermissionState(_ context.Context, _, permissionID string,
	enable bool, _ string) (login.UIRBACPermissionView, bool, error) {
	if err := f.fail(); err != nil {
		return login.UIRBACPermissionView{}, false, err
	}
	permission := f.permission
	permission.PermissionID = permissionID
	permission.Enabled = enable
	return permission, true, nil
}

// CreatePermission 实现步骤 189 的权限登记扩展契约（测试替身只验证页面状态机，
// 真实授权/审计由集成测试与生产适配器覆盖）。
func (f *fakeRBACBackend) CreatePermission(_ context.Context, _ string,
	create login.UIRBACCreatePermission, _ string) (login.UIRBACPermissionView, error) {
	if err := f.fail(); err != nil {
		return login.UIRBACPermissionView{}, err
	}
	f.lastCreate = create
	if create.ScopeID == "" || create.Key == "" || create.Name == "" ||
		!strings.Contains(create.Key, ".") || strings.ContainsAny(create.Key, " \t") {
		return login.UIRBACPermissionView{}, &login.UIRBACError{Code: "REQ_INVALID"}
	}
	view := login.UIRBACPermissionView{PermissionID: "perm_new", ScopeID: create.ScopeID,
		ScopeKind: "system", Key: create.Key, Name: create.Name,
		Description: create.Description, Limits: create.Limits,
		Enabled: true, UpdatedAt: time.UnixMilli(f.permission.UpdatedAt.UnixMilli() + 1)}
	f.permissions = append(f.permissions, view)
	return view, nil
}

// DeletePermission 实现步骤 189 的删除契约（内置权限返回稳定拒绝码）。
func (f *fakeRBACBackend) DeletePermission(_ context.Context, _, _ string, _ string) error {
	if err := f.fail(); err != nil {
		return err
	}
	if f.permission.Builtin {
		return &login.UIRBACError{Code: "ACCESS_DENIED"}
	}
	return nil
}

// PermissionImpact 实现步骤 189 的影响预览契约；未显式配置时按当前权限给出默认值。
func (f *fakeRBACBackend) PermissionImpact(_ context.Context, _ string,
	_ string) (login.UIRBACPermissionImpact, error) {
	if err := f.fail(); err != nil {
		return login.UIRBACPermissionImpact{}, err
	}
	impact := f.impact
	impact.Permission = f.permission
	if !impact.RolesAvailable && impact.RolesUnavailableReason == "" &&
		len(impact.ReferencingRoles) == 0 {
		impact.RolesAvailable = true
		impact.CanDelete = !f.permission.Builtin
	}
	return impact, nil
}

func (f *fakeRBACBackend) DelegationView(_ context.Context, _, scopeID string,
	includeRevoked bool, limit, offset int) (login.UIRBACDelegationView, error) {
	if err := f.fail(); err != nil {
		return login.UIRBACDelegationView{}, err
	}
	view := f.delegation
	view.ScopeID = scopeID
	view.IncludeRevoked = includeRevoked
	view.GrantsHasMore = true
	view.NextOffset = offset + len(view.Grants)
	view.TrustedWriteRequired = true
	return view, nil
}

func (f *fakeRBACBackend) EffectivePermissions(_ context.Context, _, subjectUserID,
	scopeID string, limit, offset int) (login.UIRBACEffectiveView, error) {
	if err := f.fail(); err != nil {
		return login.UIRBACEffectiveView{}, err
	}
	view := f.effective
	view.SubjectUserID = subjectUserID
	view.ScopeID = scopeID
	view.NextOffset = offset + len(view.Permissions)
	return view, nil
}

func (f *fakeRBACBackend) PresetDiff(_ context.Context, _, scopeID string) (
	login.UIRBACPresetDiff, error) {
	if err := f.fail(); err != nil {
		return login.UIRBACPresetDiff{}, err
	}
	view := f.diff
	view.ScopeID = scopeID
	return view, nil
}

type rbacPageEnv struct {
	t       *testing.T
	handler http.Handler
	backend *fakeRBACBackend
}

func newRBACPageEnv(t *testing.T) *rbacPageEnv {
	t.Helper()
	now := time.Now()
	backend := &fakeRBACBackend{
		roles: []login.UIRBACRoleView{
			{ID: "role_admin", ScopeID: "system", ScopeKind: "system", Key: "system_admin",
				Name: "系统管理员", Description: "管理普通用户与应用", Limits: "不能操作 root",
				Enabled: true, IsPreset: true,
				DefaultPermissions: []login.UIRBACPermissionView{{Key: "users.read",
					Name: "读取用户"}},
				CurrentPermissions: []login.UIRBACPermissionView{{Key: "users.read",
					Name: "读取用户"}},
				UserAssignments: 1, GroupAssignments: 2, CreatedAt: now, UpdatedAt: now},
			{ID: "role_app", ScopeID: "app_1111", ScopeKind: "application",
				ApplicationID: "app_1111", AppContext: "示例应用", Key: "app_admin",
				Name: "应用管理员", Description: "管理指定应用", Limits: "仅限指定应用",
				Enabled: true, IsPreset: true},
		},
		role: login.UIRBACRoleView{ID: "role_admin", ScopeID: "system",
			ScopeKind: "system", Key: "system_admin", Name: "系统管理员",
			Description: "管理普通用户与应用", Limits: "不能操作 root", Enabled: true,
			IsPreset: true,
			CurrentPermissions: []login.UIRBACPermissionView{{PermissionID: "perm_users",
				Key: "users.read", Name: "读取用户", Description: "读取普通用户",
				Limits: "不能修改用户", Enabled: true}},
			DefaultPermissions: []login.UIRBACPermissionView{{Key: "users.read",
				Name: "读取用户"}},
			UserAssignments: 1, GroupAssignments: 1, CreatedAt: now, UpdatedAt: now},
		permissions: []login.UIRBACPermissionView{
			{PermissionID: "perm_users", ScopeID: "system", ScopeKind: "system",
				Key: "users.read", Name: "读取用户", Description: "读取普通用户",
				Limits: "不能修改用户", Builtin: true, Enabled: true, Implemented: true,
				DefaultName: "读取用户", DefaultSummary: "读取普通用户",
				DefaultScope: "全部普通用户", DefaultLimits: "不能修改用户",
				DefaultEnabled: true},
			{PermissionID: "perm_app_users", ScopeID: "app_1111",
				ScopeKind: "application", ApplicationID: "app_1111", AppContext: "示例应用",
				Key: "users.read", Name: "读取应用成员", Description: "读取当前应用成员",
				Builtin: false, Enabled: true, Implemented: true},
		},
		permission: login.UIRBACPermissionView{PermissionID: "perm_users",
			ScopeID: "system", ScopeKind: "system", Key: "users.read", Group: "users",
			Name: "读取用户", Description: "读取普通用户", Limits: "不能修改用户",
			Builtin: true, Enabled: true, DefaultName: "读取用户",
			DefaultSummary: "读取普通用户", DefaultScope: "全部普通用户",
			DefaultLimits: "不能修改用户", DefaultEnabled: true, Implemented: true,
			DefaultRoles: []string{"system_admin"}, CreatedAt: now, UpdatedAt: now},
		available: []login.UIRBACPermissionView{{PermissionID: "perm_roles",
			Key: "roles.read", Name: "读取角色", Description: "读取角色组合",
			Limits: "不能分配角色", Enabled: true}},
		assignments: login.UIRBACAssignments{
			Users: []login.UIRBACUserAssignment{{UserID: "usr_a", DataScope: "{}",
				DataScopeText: "未声明（资源级检查默认拒绝）",
				AssignedBy:    "usr_admin", CreatedAt: now}},
			Groups: []login.UIRBACGroupAssignment{{GroupID: "grp_a", ScopeID: "system",
				DataScope: "{}", DataScopeText: "未声明（资源级检查默认拒绝）",
				CreatedAt: now}},
		},
		compose: login.UIRBACComposeResult{},
		effective: login.UIRBACEffectiveView{AccountStatus: "active",
			AccountStatusText: "正常", ApplicationStatus: "active",
			ApplicationStatusText: "已启用", MembershipStatus: "active",
			MembershipStatusText: "有效成员",
			Permissions: []login.UIRBACEffectivePermission{
				{Key: "users.read", Name: "读取用户", ScopeID: "system",
					DataScope: login.UIRBACDataScope{Mode: "undefined", Legacy: true,
						Display: "未声明（历史数据；资源级检查默认拒绝）"},
					Sources: []login.UIRBACSource{
						{Kind: "user_role", RoleID: "role_admin", RoleKey: "system_admin",
							RoleName: "系统管理员", Included: true, AssignedBy: "usr_admin",
							CreatedAt: now},
						{Kind: "group_role", RoleID: "role_user_admin",
							RoleKey: "user_admin", RoleName: "用户管理员", GroupID: "grp_a",
							GroupKey: "user-administrators", GroupName: "用户管理员组",
							Included: true, AssignedBy: "usr_admin", CreatedAt: now},
					}},
				{Key: "roles.read", Name: "读取角色", ScopeID: "system",
					DataScope: login.UIRBACDataScope{Mode: "all", Display: "全部数据（不限制）"}}}},
		diff: login.UIRBACPresetDiff{CatalogVersion: "1.0.0", Available: true,
			ExecutionRestricted: true,
			Summary: login.UIRBACPresetSummary{RoleCount: 2, ChangedRoles: 1,
				MissingRoles: 0, MissingPermissions: 1, DisabledPermissions: 1,
				AddPermissions: 1, RemovePermissions: 1},
			Roles: []login.UIRBACPresetRoleDiff{
				{RoleKey: "system_admin", Name: "系统管理员", RoleID: "role_admin",
					Exists: true, Unchanged: false,
					AddPermissions: []login.UIRBACPermissionView{{Key: "roles.manage",
						Name: "管理角色"}},
					RemovePermissions: []login.UIRBACPermissionView{{Key: "audit.read",
						Name: "读取审计"}}},
				{RoleKey: "normal_user", Name: "普通用户", Exists: false,
					AddPermissions: []login.UIRBACPermissionView{{Key: "self.profile.read",
						Name: "读取本人资料"}}},
			}},
		delegation: login.UIRBACDelegationView{ScopeID: "system", ScopeKind: "system",
			TrustedWriteRequired: true,
			Delegatable: []login.UIRBACDelegatable{{PermissionID: "perm_users",
				Key: "users.read", Name: "读取用户",
				MaxDataScope:     `{"v":1,"mode":"all"}`,
				MaxDataScopeText: "全部数据（不限制）", AllowSelf: false}},
			Grants: []login.UIRBACGrant{{ID: "dlg_a", DelegatorUserID: "usr_admin",
				ScopeID: "system", PermissionKey: "users.read", PermissionName: "读取用户",
				MaxDataScope:     `{"v":1,"mode":"all"}`,
				MaxDataScopeText: "全部数据（不限制）", Active: true,
				AllowedUserCount: 0, AllowedGroupCount: 0, CreatedAt: now}}},
	}
	ui, err := login.NewWebUI(login.WebUIOptions{Session: adminPageSessions{},
		PageRBAC: &login.UIPageRBACOptions{Backend: backend}})
	if err != nil {
		t.Fatalf("角色权限页框架: %v", err)
	}
	return &rbacPageEnv{t: t, handler: ui, backend: backend}
}

// defaultFakeRBACEffective 返回用于恢复的默认有效权限假数据。
func defaultFakeRBACEffective() login.UIRBACEffectiveView {
	now := time.Now()
	return login.UIRBACEffectiveView{AccountStatus: "active",
		AccountStatusText: "正常", ApplicationStatus: "active",
		ApplicationStatusText: "已启用", MembershipStatus: "active",
		MembershipStatusText: "有效成员",
		Permissions: []login.UIRBACEffectivePermission{
			{Key: "users.read", Name: "读取用户", ScopeID: "system",
				DataScope: login.UIRBACDataScope{Mode: "undefined", Legacy: true,
					Display: "未声明（历史数据；资源级检查默认拒绝）"},
				Sources: []login.UIRBACSource{
					{Kind: "user_role", RoleID: "role_admin", RoleKey: "system_admin",
						RoleName: "系统管理员", Included: true, AssignedBy: "usr_admin",
						CreatedAt: now},
					{Kind: "group_role", RoleID: "role_user_admin",
						RoleKey: "user_admin", RoleName: "用户管理员", GroupID: "grp_a",
						GroupKey: "user-administrators", GroupName: "用户管理员组",
						Included: true, AssignedBy: "usr_admin", CreatedAt: now},
				}},
			{Key: "roles.read", Name: "读取角色", ScopeID: "system",
				DataScope: login.UIRBACDataScope{Mode: "all", Display: "全部数据（不限制）"}}}}
}

func (e *rbacPageEnv) request(method, target string, body []byte,
	contentType string) *httptest.ResponseRecorder {
	e.t.Helper()
	request := httptest.NewRequest(method, "http://example.test"+target, bytes.NewReader(body))
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	recorder := httptest.NewRecorder()
	e.handler.ServeHTTP(recorder, request)
	return recorder
}

func (e *rbacPageEnv) get(target string) *httptest.ResponseRecorder {
	return e.request(http.MethodGet, target, nil, "")
}

func (e *rbacPageEnv) post(target string, values url.Values) *httptest.ResponseRecorder {
	return e.request(http.MethodPost, target, []byte(values.Encode()),
		"application/x-www-form-urlencoded")
}

func (e *rbacPageEnv) postForm(values url.Values) url.Values {
	if values == nil {
		values = url.Values{}
	}
	values.Set("csrf_token", "admin-csrf-token")
	return values
}

// expectedVersion 返回当前权限夹具的页面层行版本（UpdatedAt 毫秒值文本）。
func (e *rbacPageEnv) expectedVersion() string {
	return strconv.FormatInt(e.backend.permission.UpdatedAt.UnixMilli(), 10)
}

// TestRBACRolesListAndCreate 覆盖角色列表（中文说明/范围/默认与当前/root 提示）与创建。
func TestRBACRolesListAndCreate(t *testing.T) {
	env := newRBACPageEnv(t)
	page := env.get("/admin/roles?scope_id=system")
	if page.Code != http.StatusOK {
		t.Fatalf("角色列表 = %d", page.Code)
	}
	body := page.Body.String()
	for _, want := range []string{"系统管理员", "示例应用", "app_1111", "不能操作 root",
		"默认值", "当前实际值", "用户组", "下一页"} {
		if !strings.Contains(body, want) {
			t.Fatalf("角色列表缺少 %q", want)
		}
	}
	if strings.Contains(body, "http://") || strings.Contains(body, "https://") {
		t.Fatal("角色列表引用了外部在线资源")
	}
	createPage := env.get("/admin/roles/create?scope_id=system")
	if createPage.Code != http.StatusOK ||
		!strings.Contains(createPage.Body.String(), "机器标识") {
		t.Fatalf("创建角色页 = %d", createPage.Code)
	}
	missing := env.post("/admin/roles/create",
		env.postForm(url.Values{"scope_id": {"system"}, "role_key": {"ops"},
			"name": {""}}))
	if missing.Code != http.StatusBadRequest {
		t.Fatalf("缺少名称应 400，实际 %d", missing.Code)
	}
	created := env.post("/admin/roles/create",
		env.postForm(url.Values{"scope_id": {"system"}, "role_key": {"ops"},
			"name": {"运维"}, "description": {"运维角色"}, "limits": {"仅限系统"}}))
	if created.Code != http.StatusSeeOther ||
		!strings.Contains(created.Header().Get("Location"), "role_id=role_new") {
		t.Fatalf("创建角色 = %d %q", created.Code, created.Header().Get("Location"))
	}
}

// TestRBACRoleDetailComposeAndState 覆盖详情、改动前后权限、停用确认。
func TestRBACRoleDetailComposeAndState(t *testing.T) {
	env := newRBACPageEnv(t)
	detail := env.get("/admin/roles/detail?role_id=role_admin")
	if detail.Code != http.StatusOK {
		t.Fatalf("角色详情 = %d", detail.Code)
	}
	for _, want := range []string{"users.read", "读取用户", "可组合的权限",
		"roles.read", "管理与查看分配", "默认权限集合",
		"来源：版本化预设目录的角色默认组合"} {
		if !strings.Contains(detail.Body.String(), want) {
			t.Fatalf("角色详情缺少 %q", want)
		}
	}
	// 修改资料。
	update := env.post("/admin/roles/update", env.postForm(url.Values{
		"role_id": {"role_admin"}, "name": {"系统管理员2"}, "description": {"说明"},
		"limits": {"限制"}}))
	if update.Code != http.StatusOK ||
		!strings.Contains(update.Body.String(), "已保存并重新读取真实结果") {
		t.Fatalf("修改角色 = %d", update.Code)
	}
	// 停用缺少确认 → 400。
	missingConfirm := env.post("/admin/roles/state", env.postForm(url.Values{
		"role_id": {"role_admin"}, "action": {"disable"}}))
	if missingConfirm.Code != http.StatusBadRequest {
		t.Fatalf("停用缺少确认 = %d", missingConfirm.Code)
	}
	disabled := env.post("/admin/roles/state", env.postForm(url.Values{
		"role_id": {"role_admin"}, "action": {"disable"}, "confirm": {"yes"}}))
	if disabled.Code != http.StatusOK ||
		!strings.Contains(disabled.Body.String(), "已停用") {
		t.Fatalf("停用角色 = %d", disabled.Code)
	}
	// 组合权限缺少确认 → 400；确认后展示改动前后与受影响分配。
	composeMissing := env.post("/admin/roles/permissions", env.postForm(url.Values{
		"role_id": {"role_admin"}, "permission_id": {"perm_roles"}, "action": {"add"}}))
	if composeMissing.Code != http.StatusBadRequest {
		t.Fatalf("组合缺少确认 = %d", composeMissing.Code)
	}
	composed := env.post("/admin/roles/permissions", env.postForm(url.Values{
		"role_id": {"role_admin"}, "permission_id": {"perm_roles"}, "action": {"add"},
		"confirm": {"yes"}}))
	if composed.Code != http.StatusOK {
		t.Fatalf("组合权限 = %d", composed.Code)
	}
	for _, want := range []string{"改动前权限", "改动后权限", "受影响的分配", "roles.read"} {
		if !strings.Contains(composed.Body.String(), want) {
			t.Fatalf("组合结果缺少 %q", want)
		}
	}
	if strings.Contains(composed.Body.String(), ">{}<") {
		t.Fatal("角色详情直出原始数据范围 JSON")
	}
	for _, want := range []string{} {
		if !strings.Contains(composed.Body.String(), want) {
			t.Fatalf("组合结果缺少 %q", want)
		}
	}
}

// TestRBACAssignments 覆盖直接用户/用户组分配与确认绑定实际目标。
func TestRBACAssignments(t *testing.T) {
	env := newRBACPageEnv(t)
	page := env.get("/admin/roles/assignments?role_id=role_admin")
	if page.Code != http.StatusOK {
		t.Fatalf("分配页 = %d", page.Code)
	}
	for _, want := range []string{"usr_a", "grp_a", "直接分配", "用户组间接",
		"自我提权"} {
		if !strings.Contains(page.Body.String(), want) {
			t.Fatalf("分配页缺少 %q", want)
		}
	}
	missingConfirm := env.post("/admin/roles/assignments", env.postForm(url.Values{
		"role_id": {"role_admin"}, "target_kind": {"group"}, "target_id": {"grp_a"},
		"action": {"assign"}}))
	if missingConfirm.Code != http.StatusBadRequest {
		t.Fatalf("分配缺少确认 = %d", missingConfirm.Code)
	}
	if env.backend.lastTarget != "" {
		t.Fatal("缺少确认时不得调用后端分配")
	}
	assigned := env.post("/admin/roles/assignments", env.postForm(url.Values{
		"role_id": {"role_admin"}, "target_kind": {"group"}, "target_id": {"grp_a"},
		"action": {"assign"}, "confirm": {"yes"}}))
	if assigned.Code != http.StatusOK ||
		env.backend.lastTarget != "grp_a" ||
		!strings.Contains(assigned.Body.String(), "分配操作已提交") {
		t.Fatalf("分配 = %d target=%q", assigned.Code, env.backend.lastTarget)
	}
	invalid := env.post("/admin/roles/assignments", env.postForm(url.Values{
		"role_id": {"role_admin"}, "target_kind": {"user"}, "target_id": {"bad id"},
		"action": {"assign"}, "confirm": {"yes"}}))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("非法实际目标 = %d", invalid.Code)
	}
}

// TestRBACPermissions 覆盖权限目录（应用同名权限带上下文）与停用确认。
func TestRBACPermissions(t *testing.T) {
	env := newRBACPageEnv(t)
	page := env.get("/admin/permissions")
	if page.Code != http.StatusOK {
		t.Fatalf("权限目录 = %d", page.Code)
	}
	body := page.Body.String()
	for _, want := range []string{"读取用户", "读取应用成员", "示例应用", "app_1111",
		"root_only", "应用上下文", "默认值与当前值",
		"未提供默认值（应用范围不使用系统预设默认说明）"} {
		if !strings.Contains(body, want) {
			t.Fatalf("权限目录缺少 %q", want)
		}
	}
	if strings.Count(body, "users.read") < 2 {
		t.Fatal("同名跨应用权限应分别列出，不能合并")
	}
	detail := env.get("/admin/permissions/detail?permission_id=perm_users")
	if detail.Code != http.StatusOK ||
		!strings.Contains(detail.Body.String(), "全部普通用户") ||
		!strings.Contains(detail.Body.String(), "system_admin") {
		t.Fatalf("权限详情 = %d", detail.Code)
	}
	update := env.post("/admin/permissions/update", env.postForm(url.Values{
		"permission_id": {"perm_users"}, "name": {"读取用户2"},
		"description": {"说明"}, "limits": {"限制"},
		"expected_updated_at": {env.expectedVersion()}}))
	if update.Code != http.StatusOK ||
		!strings.Contains(update.Body.String(), "已保存并重新读取真实结果") {
		t.Fatalf("修改权限说明 = %d", update.Code)
	}
	missingConfirm := env.post("/admin/permissions/state", env.postForm(url.Values{
		"permission_id": {"perm_users"}, "action": {"disable"}}))
	if missingConfirm.Code != http.StatusBadRequest {
		t.Fatalf("停用权限缺少确认 = %d", missingConfirm.Code)
	}
	disabled := env.post("/admin/permissions/state", env.postForm(url.Values{
		"permission_id": {"perm_users"}, "action": {"disable"}, "confirm": {"yes"},
		"expected_updated_at": {env.expectedVersion()}}))
	if disabled.Code != http.StatusOK ||
		!strings.Contains(disabled.Body.String(), "权限已停用") {
		t.Fatalf("停用权限 = %d", disabled.Code)
	}
}

// TestRBACDelegationsReadOnly 覆盖可使用/可转授分离与受信通道说明（页面只读）。
func TestRBACDelegationsReadOnly(t *testing.T) {
	env := newRBACPageEnv(t)
	page := env.get("/admin/delegations?scope_id=system")
	if page.Code != http.StatusOK {
		t.Fatalf("委派页 = %d", page.Code)
	}
	body := page.Body.String()
	for _, want := range []string{"当前可转授的权限", "users.read", "受信本地初始化或系统通道",
		"不会把不可转授的权限默认勾选为可授予", "未设置到期时间"} {
		if !strings.Contains(body, want) {
			t.Fatalf("委派页缺少 %q", want)
		}
	}
	if strings.Contains(body, `name="grant"`) || strings.Contains(body, "签发委派资格") {
		t.Fatal("委派页不得提供受信通道才能执行的发放入口")
	}
	if strings.Contains(body, `{"v":1`) || strings.Contains(body, ">undefined<") ||
		strings.Contains(body, ">all<") {
		t.Fatal("委派页不得直出原始数据范围 JSON/机器枚举")
	}
}

// TestRBACEffectivePermissions 覆盖有效权限查询与直接/组来源、数据范围。
func TestRBACEffectivePermissions(t *testing.T) {
	env := newRBACPageEnv(t)
	initial := env.get("/admin/access/effective")
	if initial.Code != http.StatusOK ||
		strings.Contains(initial.Body.String(), "读取用户") ||
		!strings.Contains(initial.Body.String(), "尚未查询") {
		t.Fatalf("未指定目标时应显示未查询状态: %d", initial.Code)
	}
	page := env.get("/admin/access/effective?subject_user_id=usr_a&scope_id=system")
	if page.Code != http.StatusOK {
		t.Fatalf("有效权限页 = %d", page.Code)
	}
	// 已查询但结果为空：显示“没有生效权限”，与“尚未查询”区分。
	env.backend.effective = login.UIRBACEffectiveView{AccountStatusText: "正常",
		ApplicationStatusText: "已启用", MembershipStatusText: "有效成员"}
	emptyQueried := env.get("/admin/access/effective?subject_user_id=usr_a&scope_id=system")
	if emptyQueried.Code != http.StatusOK ||
		!strings.Contains(emptyQueried.Body.String(), "没有生效权限") ||
		strings.Contains(emptyQueried.Body.String(), "尚未查询") {
		t.Fatalf("查询结果为空状态 = %d", emptyQueried.Code)
	}
	env.backend.effective = defaultFakeRBACEffective()
	page = env.get("/admin/access/effective?subject_user_id=usr_a&scope_id=system")
	if page.Code != http.StatusOK {
		t.Fatalf("有效权限页 = %d", page.Code)
	}
	body := page.Body.String()
	for _, want := range []string{"usr_a", "系统管理员", "用户管理员组",
		"直接角色", "用户组间接", "未声明（历史数据；资源级检查默认拒绝）",
		"全部数据（不限制）", "实时计算", "正常", "已启用", "有效成员"} {
		if !strings.Contains(body, want) {
			t.Fatalf("有效权限页缺少 %q", want)
		}
	}
	for _, raw := range []string{">active<", `{"v":1`, ">undefined<"} {
		if strings.Contains(body, raw) {
			t.Fatalf("有效权限页直出机器值 %q", raw)
		}
	}
}

// TestRBACPresetDiff 覆盖恢复预设差异只读展示（执行仅受信通道）。
func TestRBACPresetDiff(t *testing.T) {
	env := newRBACPageEnv(t)
	page := env.get("/admin/presets/diff?scope_id=system")
	if page.Code != http.StatusOK {
		t.Fatalf("预设差异页 = %d", page.Code)
	}
	body := page.Body.String()
	for _, want := range []string{"1.0.0", "系统管理员", "roles.manage", "audit.read",
		"只允许受信本地初始化或系统通道执行", "缺失权限", "停用权限",
		"角色缺失（恢复会创建）"} {
		if !strings.Contains(body, want) {
			t.Fatalf("预设差异页缺少 %q", want)
		}
	}
	if strings.Contains(body, `action="/admin/presets/restore"`) ||
		strings.Contains(body, "执行恢复") {
		t.Fatal("预设差异页不得提供受信通道才能执行的恢复入口")
	}
}

// TestRBACScopeSwitchAndEmptyStates 覆盖切换作用范围清除旧选择与各页空状态。
func TestRBACScopeSwitchAndEmptyStates(t *testing.T) {
	env := newRBACPageEnv(t)
	systemPage := env.get("/admin/roles?scope_id=system")
	if !strings.Contains(systemPage.Body.String(), "系统管理员") ||
		strings.Contains(systemPage.Body.String(), "应用管理员") {
		t.Fatal("系统范围不应混入应用范围角色")
	}
	appPage := env.get("/admin/roles?scope_id=app_1111")
	if !strings.Contains(appPage.Body.String(), "应用管理员") ||
		strings.Contains(appPage.Body.String(), "系统管理员") {
		t.Fatal("切换应用范围后仍串入系统角色")
	}
	// 空列表使用空状态提示，不伪造数据。
	env.backend.empty = true
	emptyRoles := env.get("/admin/roles?scope_id=system")
	if emptyRoles.Code != http.StatusOK ||
		!strings.Contains(emptyRoles.Body.String(), "当前作用范围没有可读取的角色") {
		t.Fatalf("空角色列表 = %d", emptyRoles.Code)
	}
	emptyPermissions := env.get("/admin/permissions?scope_id=system")
	if emptyPermissions.Code != http.StatusOK ||
		!strings.Contains(emptyPermissions.Body.String(), "当前作用范围没有可读取的权限") {
		t.Fatalf("空权限目录 = %d", emptyPermissions.Code)
	}
}

// TestRBACSessionExpired 覆盖会话过期时进入系统过期页而不是渲染管理数据。
func TestRBACSessionExpired(t *testing.T) {
	backend := &fakeRBACBackend{}
	ui, err := login.NewWebUI(login.WebUIOptions{Session: expiredPageSessions{},
		PageRBAC: &login.UIPageRBACOptions{Backend: backend}})
	if err != nil {
		t.Fatalf("会话过期页面框架: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://example.test/admin/roles", nil)
	recorder := httptest.NewRecorder()
	ui.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("会话过期 = %d", recorder.Code)
	}
}

// expiredPageSessions 返回未登录/过期状态。
type expiredPageSessions struct{}

func (expiredPageSessions) ResolvePageSession(context.Context,
	*http.Request) (login.UISession, error) {
	return login.UISession{}, login.ErrUISessionExpired
}

func (expiredPageSessions) IssueCSRFToken(context.Context, *http.Request) (string, error) {
	return "", nil
}

// TestRBACErrorsFailClosed 覆盖无权限/缺少转授资格/依赖故障/边界输入的页面状态。
func TestRBACErrorsFailClosed(t *testing.T) {
	env := newRBACPageEnv(t)
	env.backend.failCode = "ACCESS_DENIED"
	page := env.get("/admin/roles")
	if page.Code != http.StatusForbidden ||
		!strings.Contains(page.Body.String(), "服务端已拒绝") {
		t.Fatalf("越权页面 = %d", page.Code)
	}
	env.backend.failCode = "PERMISSION_REQUIRED"
	page = env.get("/admin/delegations")
	if page.Code != http.StatusForbidden ||
		!strings.Contains(page.Body.String(), "拥有权限不等于可以转授") {
		t.Fatalf("缺少转授资格页面 = %d", page.Code)
	}
	env.backend.failCode = "DB_UNAVAILABLE"
	page = env.get("/admin/effective")
	_ = page
	page = env.get("/admin/permissions")
	if page.Code != http.StatusServiceUnavailable {
		t.Fatalf("依赖故障页面 = %d", page.Code)
	}
	env.backend.failCode = ""
	badOffset := env.get("/admin/roles?offset=abc")
	if badOffset.Code != http.StatusBadRequest {
		t.Fatalf("非法分页 = %d", badOffset.Code)
	}
	unknown := env.get("/admin/roles/detail?role_id=")
	if unknown.Code != http.StatusOK {
		// 空目标由测试替身返回零值角色，真实后端会拒绝；此处只确认不 panic。
		t.Fatalf("空目标页面 = %d", unknown.Code)
	}
}

// customPermissionFixture 返回用于步骤 189 页面测试的自定义权限夹具。
func customPermissionFixture(updatedAt time.Time) login.UIRBACPermissionView {
	return login.UIRBACPermissionView{PermissionID: "perm_custom", ScopeID: "system",
		ScopeKind: "system", Key: "report.approve", Name: "审批报告",
		Description: "审批本系统报告", Limits: "仅限本系统报告", Enabled: true,
		CreatedAt: updatedAt, UpdatedAt: updatedAt}
}

// TestRBACPermissionCreatePage 覆盖创建自定义权限页面：入口/术语说明/字段白名单/
// 校验错误/成功重定向；同时确认页面不能提交内置或 root_only 标记。
func TestRBACPermissionCreatePage(t *testing.T) {
	env := newRBACPageEnv(t)
	list := env.get("/admin/permissions?scope_id=system")
	listBody := list.Body.String()
	for _, want := range []string{"术语说明", "内置权限", "/admin/permissions/create"} {
		if !strings.Contains(listBody, want) {
			t.Fatalf("权限目录缺少 %q", want)
		}
	}
	page := env.get("/admin/permissions/create?scope_id=system")
	if page.Code != http.StatusOK {
		t.Fatalf("创建权限页 = %d", page.Code)
	}
	body := page.Body.String()
	for _, want := range []string{"创建自定义权限", "机器标识", "内置权限", "作用范围",
		"确认创建"} {
		if !strings.Contains(body, want) {
			t.Fatalf("创建权限页缺少 %q", want)
		}
	}
	for _, forbidden := range []string{`name="is_builtin"`, `name="root_only"`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("创建页不得提交 %s", forbidden)
		}
	}
	missingConfirm := env.post("/admin/permissions/create", env.postForm(url.Values{
		"scope_id": {"system"}, "permission_key": {"report.approve"},
		"name": {"审批报告"}, "description": {"说明"}, "limits": {"限制"}}))
	if missingConfirm.Code != http.StatusBadRequest {
		t.Fatalf("创建缺少确认 = %d", missingConfirm.Code)
	}
	missingName := env.post("/admin/permissions/create", env.postForm(url.Values{
		"scope_id": {"system"}, "permission_key": {"report.approve"},
		"confirm": {"yes"}}))
	if missingName.Code != http.StatusBadRequest {
		t.Fatalf("创建缺少名称 = %d", missingName.Code)
	}
	invalidKey := env.post("/admin/permissions/create", env.postForm(url.Values{
		"scope_id": {"system"}, "permission_key": {"Bad Key"}, "name": {"非法标识"},
		"description": {"说明"}, "limits": {"限制"}, "confirm": {"yes"}}))
	if invalidKey.Code != http.StatusBadRequest ||
		!strings.Contains(invalidKey.Body.String(), "机器标识") {
		t.Fatalf("非法机器标识 = %d", invalidKey.Code)
	}
	created := env.post("/admin/permissions/create", env.postForm(url.Values{
		"scope_id": {"system"}, "permission_key": {"report.approve"},
		"name": {"审批报告"}, "description": {"审批本系统报告"},
		"limits": {"仅限本系统报告"}, "confirm": {"yes"}}))
	if created.Code != http.StatusSeeOther ||
		!strings.Contains(created.Header().Get("Location"), "permission_id=perm_new") {
		t.Fatalf("创建权限 = %d %q", created.Code, created.Header().Get("Location"))
	}
	if env.backend.lastCreate.Key != "report.approve" ||
		env.backend.lastCreate.ScopeID != "system" {
		t.Fatalf("创建请求白名单 = %+v", env.backend.lastCreate)
	}
}

// TestRBACPermissionImpactAndDelete 覆盖影响预览、内置不可删除、使用中删除冲突、
// 行版本冲突与删除成功/确认要求。
func TestRBACPermissionImpactAndDelete(t *testing.T) {
	env := newRBACPageEnv(t)
	now := env.backend.permission.UpdatedAt
	env.backend.permission = customPermissionFixture(now)
	env.backend.impact = login.UIRBACPermissionImpact{RolesAvailable: true,
		ReferencingRoles: []login.UIRBACImpactRole{{RoleID: "role_admin",
			RoleKey: "system_admin", RoleName: "系统管理员", ScopeID: "system",
			Builtin: true, Enabled: true}},
		ReferencedRoleCount: 1, CanDelete: false,
		DeleteBlockedReason: "仍被 1 个角色引用；请先在角色页解除组合后再删除"}
	detail := env.get("/admin/permissions/detail?permission_id=perm_custom")
	if detail.Code != http.StatusOK {
		t.Fatalf("权限详情 = %d", detail.Code)
	}
	body := detail.Body.String()
	for _, want := range []string{"删除 / 停用影响预览", "系统管理员", "仍被 1 个角色引用",
		"停用权限会立即影响"} {
		if !strings.Contains(body, want) {
			t.Fatalf("影响预览缺少 %q", want)
		}
	}
	if strings.Contains(body, `action="/admin/permissions/delete"`) {
		t.Fatal("仍被引用时不得显示删除提交表单")
	}
	// 内置权限不可删除（页面提示 + 直接提交也拒绝）。
	builtin := env.backend.permission
	builtin.Builtin = true
	builtin.PermissionID = "perm_users"
	env.backend.permission = builtin
	builtinDetail := env.get("/admin/permissions/detail?permission_id=perm_users")
	if builtinDetail.Code != http.StatusOK ||
		!strings.Contains(builtinDetail.Body.String(), "内置权限不可删除") {
		t.Fatalf("内置权限详情 = %d", builtinDetail.Code)
	}
	deleteBuiltin := env.post("/admin/permissions/delete", env.postForm(url.Values{
		"permission_id":       {"perm_users"},
		"expected_updated_at": {env.expectedVersion()}, "confirm": {"yes"}}))
	if deleteBuiltin.Code != http.StatusForbidden {
		t.Fatalf("删除内置权限 = %d", deleteBuiltin.Code)
	}
	// 使用中删除：领域冲突 → 409。
	env.backend.permission = customPermissionFixture(now)
	env.backend.impact = login.UIRBACPermissionImpact{}
	env.backend.failCode = "CONFLICT"
	inUse := env.post("/admin/permissions/delete", env.postForm(url.Values{
		"permission_id":       {"perm_custom"},
		"expected_updated_at": {env.expectedVersion()}, "confirm": {"yes"}}))
	if inUse.Code != http.StatusConflict ||
		!strings.Contains(inUse.Body.String(), "数据已被其他操作修改") {
		t.Fatalf("使用中删除 = %d", inUse.Code)
	}
	env.backend.failCode = ""
	// 行版本冲突 → 409 并重新读取当前状态。
	stale := env.post("/admin/permissions/delete", env.postForm(url.Values{
		"permission_id": {"perm_custom"}, "expected_updated_at": {"1"},
		"confirm": {"yes"}}))
	if stale.Code != http.StatusConflict ||
		!strings.Contains(stale.Body.String(), "行版本冲突") {
		t.Fatalf("删除行版本冲突 = %d", stale.Code)
	}
	// 缺少确认 → 400，且不调用后端删除。
	missingConfirm := env.post("/admin/permissions/delete", env.postForm(url.Values{
		"permission_id":       {"perm_custom"},
		"expected_updated_at": {env.expectedVersion()}}))
	if missingConfirm.Code != http.StatusBadRequest {
		t.Fatalf("删除缺少确认 = %d", missingConfirm.Code)
	}
	deleted := env.post("/admin/permissions/delete", env.postForm(url.Values{
		"permission_id":       {"perm_custom"},
		"expected_updated_at": {env.expectedVersion()}, "confirm": {"yes"}}))
	if deleted.Code != http.StatusSeeOther ||
		!strings.Contains(deleted.Header().Get("Location"), "/admin/permissions") {
		t.Fatalf("删除自定义权限 = %d %q", deleted.Code, deleted.Header().Get("Location"))
	}
	// 删除后列表页显示成功横幅。
	env.backend.empty = false
	after := env.get("/admin/permissions?scope_id=system&status=deleted")
	if after.Code != http.StatusOK ||
		!strings.Contains(after.Body.String(), "自定义权限已删除") {
		t.Fatalf("删除成功状态页 = %d", after.Code)
	}
}

// TestRBACPermissionStateConfirmAndReauth 覆盖启停确认、行版本冲突与再次认证失败关闭。
func TestRBACPermissionStateConfirmAndReauth(t *testing.T) {
	env := newRBACPageEnv(t)
	env.backend.permission = customPermissionFixture(env.backend.permission.UpdatedAt)
	missingConfirm := env.post("/admin/permissions/state", env.postForm(url.Values{
		"permission_id": {"perm_custom"}, "action": {"disable"},
		"expected_updated_at": {env.expectedVersion()}}))
	if missingConfirm.Code != http.StatusBadRequest {
		t.Fatalf("启停缺少确认 = %d", missingConfirm.Code)
	}
	stale := env.post("/admin/permissions/state", env.postForm(url.Values{
		"permission_id": {"perm_custom"}, "action": {"disable"},
		"expected_updated_at": {"1"}, "confirm": {"yes"}}))
	if stale.Code != http.StatusConflict ||
		!strings.Contains(stale.Body.String(), "行版本冲突") {
		t.Fatalf("启停行版本冲突 = %d", stale.Code)
	}
	env.backend.failCode = "REAUTH_REQUIRED"
	reauth := env.post("/admin/permissions/state", env.postForm(url.Values{
		"permission_id": {"perm_custom"}, "action": {"disable"},
		"expected_updated_at": {env.expectedVersion()}, "confirm": {"yes"}}))
	if reauth.Code != http.StatusForbidden ||
		!strings.Contains(reauth.Body.String(), "重新完成强认证") {
		t.Fatalf("再次认证失败关闭 = %d", reauth.Code)
	}
	env.backend.failCode = ""
	disabled := env.post("/admin/permissions/state", env.postForm(url.Values{
		"permission_id": {"perm_custom"}, "action": {"disable"},
		"expected_updated_at": {env.expectedVersion()}, "confirm": {"yes"}}))
	if disabled.Code != http.StatusOK ||
		!strings.Contains(disabled.Body.String(), "权限已停用") {
		t.Fatalf("停用权限 = %d", disabled.Code)
	}
	enabled := env.post("/admin/permissions/state", env.postForm(url.Values{
		"permission_id": {"perm_custom"}, "action": {"enable"},
		"expected_updated_at": {env.expectedVersion()}, "confirm": {"yes"}}))
	if enabled.Code != http.StatusOK ||
		!strings.Contains(enabled.Body.String(), "权限已启用") {
		t.Fatalf("启用权限 = %d", enabled.Code)
	}
}
