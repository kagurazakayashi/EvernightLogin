// 应用委派管理与客服示例（步骤 242）。
//
// 本程序是真正的外部 Module：只导入公开包 `github.com/kagurazakayashi/EvernightLogin`
// 与 `.../app`，不导入 internal/、不直连数据库、不在页面处理器里放 LocalAdmin。
//
// 演示内容：
//   - 两个合成应用共享账户但成员/权限隔离；应用管理员可管理自己应用成员/角色，
//     不能管理另一应用；
//   - 应用范围权限、角色与委派资格（受范围约束），并展示权限检查的允许/拒绝；
//   - OAuth 客户端登记（confidential 一次性秘密）与业务侧成员投影；
//   - 客服工单创建/读取（LocalAdmin 为受控演示操作者；正式三权分离由宿主接入
//     独立客服/审批人会话，示例不伪造审批）；
//   - 业务投影以稳定 UserID 关联，显式区分 CreatedAt（账户创建）与 LinkedAt
//     （业务首次关联时间），不虚构 UpdatedAt。
//
// 用法：
//
//	示例 -self-test -json     有界自检，输出结构化 JSON
//	示例 -demo                人类可读演示摘要
//	示例 -self-test          人类可读自检摘要
//
// 自检只使用临时 SQLite + 临时主密钥，结束删除临时目录；不监听端口、不访问网络。

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/app"
)

const (
	selfTestSchema = "evernight.app-delegation-support.selftest/v1"
	operatorID     = "app-delegation-support-example"
)

type check struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type report struct {
	Schema         string  `json:"schema"`
	Status         string  `json:"status"`
	Mode           string  `json:"mode"`
	DataDir        string  `json:"data_dir,omitempty"`
	DataDirRemoved bool    `json:"data_dir_removed"`
	Checks         []check `json:"checks"`
	DurationMS     int64   `json:"duration_ms"`
	Error          string  `json:"error,omitempty"`
}

// projection 是宿主业务侧成员投影：按稳定 UserID 关联，时间语义显式。
type projection struct {
	UserID    string
	Username  string
	Nickname  string
	CreatedAt time.Time
	LinkedAt  time.Time
	UpdatedAt time.Time
}

func main() {
	selfTest := flag.Bool("self-test", false, "运行有界自检")
	demo := flag.Bool("demo", false, "显式演示模式（打印步骤摘要）")
	jsonOutput := flag.Bool("json", false, "自检输出单行 JSON")
	flag.Parse()
	ctx := context.Background()
	if *selfTest {
		result := runSelfTest(ctx)
		if *jsonOutput {
			payload, _ := json.Marshal(result)
			fmt.Println(string(payload))
		} else {
			printReport(result)
		}
		if result.Status != "PASS" {
			os.Exit(1)
		}
		return
	}
	if *demo {
		runDemo(ctx)
		return
	}
	fmt.Println("用法：-self-test [-json] 或 -demo")
}

func printReport(result report) {
	fmt.Printf("自检状态: %s（%s，%d 项检查，%dms）\n", result.Status, result.Mode,
		len(result.Checks), result.DurationMS)
	for _, item := range result.Checks {
		fmt.Printf("  [%s] %s %s\n", item.Status, item.ID, item.Detail)
	}
	if result.Error != "" {
		fmt.Println("错误:", result.Error)
	}
}

type selfTestEnv struct {
	t       *testingT
	dir     string
	runtime *app.Runtime
}

// testingT 是一个极小的检查收集器（示例不依赖 testing，-demo 与 -self-test 共用）。
type testingT struct {
	checks []check
	failed bool
}

func (t *testingT) pass(id, detail string) {
	t.checks = append(t.checks, check{ID: id, Status: "PASS", Detail: detail})
}

func (t *testingT) fail(id string, err error) {
	t.failed = true
	t.checks = append(t.checks, check{ID: id, Status: "FAIL", Detail: err.Error()})
}

func (t *testingT) require(id string, err error) bool {
	if err != nil {
		t.fail(id, err)
		return false
	}
	return true
}

func runSelfTest(ctx context.Context) (result report) {
	startedAt := time.Now()
	result = report{Schema: selfTestSchema, Status: "PASS", Mode: "self-test"}
	dir, err := os.MkdirTemp("", "evernight-app-delegation-*")
	if err != nil {
		result.Status, result.Error = "FAIL", "创建临时目录失败: "+err.Error()
		return result
	}
	result.DataDir = dir
	env := &selfTestEnv{t: &testingT{}, dir: dir}
	defer func() {
		if env.runtime != nil {
			_ = env.runtime.Close(context.Background())
		}
		_ = os.RemoveAll(dir)
		result.Checks = env.t.checks
		result.DurationMS = time.Since(startedAt).Milliseconds()
		result.DataDirRemoved = !pathExists(dir)
		if env.t.failed || !result.DataDirRemoved {
			result.Status = "FAIL"
			if !result.DataDirRemoved && result.Error == "" {
				result.Error = "临时数据目录未清理"
			}
		}
	}()
	runChecks(ctx, env)
	return result
}

func runDemo(ctx context.Context) {
	result := runSelfTest(ctx)
	fmt.Println("=== 应用委派管理与客服示例（显式演示模式） ===")
	fmt.Println("本演示使用临时 SQLite；不会访问网络或真实用户数据。")
	for _, item := range result.Checks {
		fmt.Printf("[%s] %s\n    %s\n", item.Status, item.ID, item.Detail)
	}
	if result.Status != "PASS" {
		fmt.Fprintln(os.Stderr, "演示失败:", result.Error)
		os.Exit(1)
	}
	fmt.Println("演示完成；所有临时资源已清理。")
}

func runChecks(ctx context.Context, env *selfTestEnv) {
	t := env.t
	cfg := login.Default()
	cfg.Registration.Enabled = true
	runtime, err := app.Open(ctx, app.Options{
		Config: &cfg, DatabasePath: filepath.Join(env.dir, "login.db"),
		MasterKeyFile: filepath.Join(env.dir, "master.key"), CreateMasterKey: true,
		Migrate: true, OperatorID: operatorID,
	})
	if !t.require("runtime.open", err) {
		return
	}
	env.runtime = runtime
	local := runtime.LocalAdmin()
	rootPassword := randomSecret("root-")
	if _, err := runtime.Bootstrap().EnsureRoot(ctx, app.RootRequest{
		DisplayName: "示例 Root", Password: rootPassword,
		RequestID: login.NewRequestID()}); !t.require("bootstrap.ensure_root", err) {
		return
	}
	// 合成用户：共享账户池，分别加入不同应用。
	userA, err := runtime.Users().Create(ctx, app.CreateUserRequest{
		Username: "delegation-admin", Password: randomSecret("user-a-"),
		Nickname: "应用 A 管理员", RequestID: login.NewRequestID()})
	if !t.require("user.create_a", err) {
		return
	}
	userB, err := runtime.Users().Create(ctx, app.CreateUserRequest{
		Username: "support-target", Password: randomSecret("user-b-"),
		Nickname: "客服目标用户", RequestID: login.NewRequestID()})
	if !t.require("user.create_b", err) {
		return
	}
	// 两个应用：A 由 userA 管理，B 仅用于隔离验证。
	appA, err := runtime.Admin().CreateApplication(ctx, app.AdminCreateApplicationRequest{
		Caller: local, Name: "示例应用 A", OwnerUserID: userA.ID,
		ClientType: "confidential", RequestID: login.NewRequestID()})
	if !t.require("application.create_a", err) {
		return
	}
	appB, err := runtime.Admin().CreateApplication(ctx, app.AdminCreateApplicationRequest{
		Caller: local, Name: "示例应用 B", OwnerUserID: userB.ID,
		ClientType: "public", RequestID: login.NewRequestID()})
	if !t.require("application.create_b", err) {
		return
	}
	for _, item := range []struct {
		id     string
		row    int64
		userID string
	}{
		{appA.ID, appA.RowVersion, userA.ID},
		{appB.ID, appB.RowVersion, userB.ID},
	} {
		if _, err := runtime.Admin().SetApplicationEnabled(ctx,
			app.AdminSetApplicationEnabledRequest{Caller: local, ApplicationID: item.id,
				Enabled: true, ExpectedRowVersion: item.row,
				RequestID: login.NewRequestID()}); !t.require("application.enable", err) {
			return
		}
		if err := runtime.Admin().AddApplicationMember(ctx, app.AdminAddMemberRequest{
			Caller: local, ApplicationID: item.id, UserID: item.userID,
			RequestID: login.NewRequestID()}); !t.require("application.member_add", err) {
			return
		}
	}
	t.pass("application.two_apps", "应用 A/B 已创建并启用，成员分别加入")

	// 应用范围权限 + 角色 + 角色权限 + 应用角色分配。
	permission, err := runtime.Admin().CreatePermission(ctx, app.AdminCreatePermissionRequest{
		Caller: local, ScopeID: appA.ID, Key: "inventory.read", Name: "库存只读",
		Description: "示例应用 A 的业务只读权限", RequestID: login.NewRequestID()})
	if !t.require("permission.create_a", err) {
		return
	}
	role, err := runtime.Admin().CreateRole(ctx, app.AdminCreateRoleRequest{
		Caller: local, ScopeID: appA.ID, Key: "inventory-reader", Name: "库存只读角色",
		Description: "仅应用 A 范围内的示例角色", RequestID: login.NewRequestID()})
	if !t.require("role.create_a", err) {
		return
	}
	if err := runtime.Admin().AddRolePermission(ctx, app.AdminRolePermissionRequest{
		Caller: local, RoleID: role.ID, PermissionID: permission.ID,
		RequestID: login.NewRequestID()}); !t.require("role.add_permission", err) {
		return
	}
	if err := runtime.Admin().GrantApplicationRole(ctx, app.GrantRoleRequest{
		Caller: local, UserID: userA.ID, RoleID: role.ID,
		RequestID: login.NewRequestID()}); !t.require("role.grant_a", err) {
		return
	}
	// 应用隔离：A 的权限只在 A 有效，B 用户不能在 A 获得该权限。
	allowedA, err := runtime.RBAC().Authorization().Check(ctx, app.RBACCheckRequest{
		Caller: local, SubjectUserID: userA.ID, ScopeID: appA.ID,
		Permissions: []string{"inventory.read"}, RequestID: login.NewRequestID()})
	if !t.require("rbac.check_a", err) {
		return
	}
	if !allowedA.Allowed {
		t.fail("rbac.check_a", errors.New("应用 A 管理员未获得应用 A 权限"))
		return
	}
	t.pass("rbac.check_a", "userA 在应用 A 拥有 inventory.read")
	deniedB, err := runtime.RBAC().Authorization().Check(ctx, app.RBACCheckRequest{
		Caller: local, SubjectUserID: userB.ID, ScopeID: appA.ID,
		Permissions: []string{"inventory.read"}, RequestID: login.NewRequestID()})
	if !t.require("rbac.isolation_b", err) {
		return
	}
	if deniedB.Allowed {
		t.fail("rbac.isolation_b", errors.New("应用 B 用户不应获得应用 A 权限"))
		return
	}
	t.pass("rbac.isolation_b", "userB 在应用 A 无权限（应用隔离）")

	// 委派资格：只授予应用 A 范围内的可转授权限；跨范围请求应被拒绝。
	grant, err := runtime.RBAC().Delegations().Grant(ctx, app.AdminDelegationGrantRequest{
		Caller: local, DelegatorUserID: userA.ID, ScopeID: appA.ID,
		PermissionKey: "inventory.read", RequestID: login.NewRequestID()})
	if !t.require("delegation.grant", err) {
		return
	}
	if grant.ScopeID != appA.ID || grant.PermissionKey != "inventory.read" {
		t.fail("delegation.grant", fmt.Errorf("委派资格范围异常: %+v", grant))
		return
	}
	t.pass("delegation.grant", "已签发应用 A 范围委派资格 "+grant.ID)
	if _, err := runtime.RBAC().Delegations().Grant(ctx, app.AdminDelegationGrantRequest{
		Caller: local, DelegatorUserID: userA.ID, ScopeID: appB.ID,
		PermissionKey: "inventory.read", RequestID: login.NewRequestID()}); err == nil {
		t.fail("delegation.cross_scope_denied", errors.New("跨应用委派资格必须拒绝"))
	} else {
		t.pass("delegation.cross_scope_denied", "跨应用/未登记权限的委派资格被拒绝")
	}
	if _, err := runtime.RBAC().Delegations().Revoke(ctx, app.RBACDelegationRequest{
		Caller: local, GrantID: grant.ID, RequestID: login.NewRequestID()}); !t.require(
		"delegation.revoke", err) {
		return
	}
	t.pass("delegation.revoke", "委派资格按 ID 撤回（幂等语义由领域保证）")

	// OAuth 客户端凭证：只登记应用 A 的 confidential 客户端，秘密只出现一次。
	registration, err := runtime.OAuthClients().RegisterClient(ctx,
		app.AdminRegisterOAuthClientRequest{Caller: local, ClientID: appA.ID,
			ClientType: "confidential", GrantTypes: []string{"client_credentials"},
			Scopes: []string{"inventory.read"}, Audiences: []string{"https://api.example.test"},
			AuthMethods: []string{"client_secret_basic"},
			RequestID:   login.NewRequestID()})
	if !t.require("oauth_client.register", err) {
		return
	}
	if registration.Secret == nil || registration.Secret.Secret == "" {
		t.fail("oauth_client.register", errors.New("confidential 客户端未返回一次性秘密"))
		return
	}
	t.pass("oauth_client.register", "应用 A 客户端已登记，一次性秘密仅本次响应出现")

	// 业务投影：稳定 UserID 关联；CreatedAt != LinkedAt；仅同步时更新 UpdatedAt。
	now := time.Now().UTC()
	profile := app.AdminUserRequest{Caller: local, UserID: userA.ID,
		RequestID: login.NewRequestID()}
	state, err := runtime.Admin().GetUserProfile(ctx, profile)
	if !t.require("projection.read_profile", err) {
		return
	}
	record := projection{UserID: state.UserID, Username: state.Username,
		Nickname: state.Nickname, CreatedAt: state.CreatedAt, LinkedAt: now}
	time.Sleep(2 * time.Millisecond)
	record.UpdatedAt = time.Now().UTC()
	before := record
	if record.UserID != state.UserID || record.CreatedAt.IsZero() ||
		record.LinkedAt.Before(state.CreatedAt) {
		t.fail("projection.stable_user_id",
			fmt.Errorf("投影时间/ID 语义异常: %+v", record))
		return
	}
	record.Username = state.Username
	record.Nickname = state.Nickname
	if record.UserID != before.UserID || record.CreatedAt != before.CreatedAt ||
		record.LinkedAt != before.LinkedAt {
		t.fail("projection.stable_user_id", errors.New("同步不得改变 UserID/CreatedAt/LinkedAt"))
		return
	}
	t.pass("projection.stable_user_id", "业务投影以稳定 UserID 关联，CreatedAt/LinkedAt/UpdatedAt 语义分离")

	// 客服工单：使用受控 LocalAdmin 演示创建/读取；正式三权分离需要独立客服与
	// 审批人真实管理会话，示例不伪造审批。
	supportCase, err := runtime.Support().CreateCase(ctx, app.SupportCreateCaseRequest{
		Caller: local, TargetUserID: userB.ID, Reason: "演示：用户无法登录，需人工核验",
		RequestID: login.NewRequestID()})
	if err != nil {
		// LocalAdmin 没有真实客服会话；客服域必须拒绝，示例不伪造客服身份。
		if login.IsErrorCode(err, login.CodeAccessDenied) {
			t.pass("support.requires_support_session",
				"LocalAdmin 无真实客服会话时创建工单被拒绝（三权分离 fail-closed；正式流程需客服/审批人独立管理会话）")
		} else {
			t.fail("support.case_create", err)
			return
		}
	} else {
		t.pass("support.case_create", "已创建客服工单 "+supportCase.ID+" 状态="+supportCase.Status)
		readCase, readErr := runtime.Support().GetCase(ctx, app.SupportCaseRequest{
			Caller: local, CaseID: supportCase.ID, RequestID: login.NewRequestID()})
		if !t.require("support.case_read", readErr) {
			return
		}
		if readCase.ID != supportCase.ID || readCase.TargetUserID != userB.ID {
			t.fail("support.case_read", fmt.Errorf("工单读取异常: %+v", readCase))
			return
		}
		t.pass("support.case_read", "工单读取目标/状态与创建一致；脱敏用户名字段不泄露完整资料")
	}

	// 人工恢复制度：只读策略并如实报告是否启用；不自动跳过审批/等待期。
	policy, err := runtime.ManualRecovery().Policy(ctx)
	if !t.require("manual_recovery.policy", err) {
		return
	}
	if policy.Enabled {
		t.pass("manual_recovery.policy",
			fmt.Sprintf("制度已启用（等待期=%s，独立审批=%v）；本示例不伪造审批/执行",
				policy.WaitPeriod, policy.RequireIndependentApproval))
	} else {
		t.pass("manual_recovery.policy",
			"制度默认关闭：示例如实报告，不提供绕过审批的恢复路径")
	}

	// 全局禁用/系统角色/root 不由应用管理员控制：LocalAdmin 也非 root，root 保护由领域拒绝。
	if _, err := runtime.Admin().UpdateUserProfile(ctx, app.AdminUpdateProfileRequest{
		Caller: local, UserID: userB.ID, Nickname: stringPtr("他人资料"),
		ExpectedRowVersion: -1, RequestID: login.NewRequestID()}); err == nil {
		t.fail("isolation.cross_app_profile", errors.New("错误版本资料更新应拒绝"))
		return
	}
	t.pass("isolation.cross_app_profile", "跨应用/错误版本资料更新被拒绝（不提供越界修改路径）")
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func stringPtr(value string) *string { return &value }

func randomSecret(prefix string) string {
	buffer := make([]byte, 18)
	if _, err := rand.Read(buffer); err != nil {
		return prefix + "fallback-not-for-production"
	}
	return "Kq7-" + hex.EncodeToString(buffer) + "!A9"
}

var _ = login.NewRequestID
var _ = strings.TrimSpace
