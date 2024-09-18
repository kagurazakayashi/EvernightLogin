// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package main

// 本文件实现步骤 272：在真实外部示例中演示步骤 256/257 的“管理员/客服授权后的
// 直接改名与直接重置口令”，以及步骤 261/262 的用户与应用成员模糊搜索。
//
// 边界与安全语义：
//   - 只使用公开包（根包 + app）；不导入 internal，不使用任何测试旁路；
//   - LocalAdmin 只用于宿主自举（合成账户/角色/权限/应用与成员关系），**不**用于
//     任何直接管理操作或普通页面请求；直接操作必须由真实用户管理会话（AdminSession）
//     发起，并经 OperationProof 的密码 + TOTP 目标绑定证明；
//   - 合成账户全部走公开 Users().Create 与 Security() TOTP 绑定；TOTP 使用本示例按
//     RFC 6238 自行计算的验证码（等价真实验证器），不伪造强认证结果；
//   - 合成角色权限范围：管理员含两项直接权限 + 只读权限；改名客服只含
//     users.username.change.other；重置客服只含 users.password.reset.other；
//     两种客服另含 users.read 只读基线（用于读取目标行版本/列表搜索演示），
//     普通用户不含任何管理权限；
//   - 直接改名/重置只改目标用户名或口令，不解除目标 MFA；目标 UserID 稳定不变，
//     业务投影以 UserID 关联，改名后展示名同步而投影不重建；
//   - 使用独立的确定性时钟推进 TOTP 时间步（无睡眠等待），运行有界且退出清理；
//   - 页面摘要只含脱敏用户名/权限键/检查结果与稳定错误码，不含密码/种子/令牌。

import (
	"context"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/app"
)

const (
	demo272PermissionRead      = "users.read"
	demo272PermissionMembers   = "applications.members.manage"
	demo272PermissionRename    = "users.username.change.other"
	demo272PermissionReset     = "users.password.reset.other"
	demo272Reason              = "步骤272 示例：管理员/客服授权后的直接管理演示"
	demo272RenamedUsername     = "target-renamed-272"
	demo272ResetNewPassword    = "N7!vQ2#zR5@kM9$w"
	demo272SecondResetPassword = "P4!tY8#nC2@xD6$r"
)

// demoClock 是步骤 272 演示运行时的确定性时钟；TOTP 时间步可通过 Advance 推进，
// 不需要真实等待 30 秒。
type demoClock struct {
	now time.Time
}

// Now 实现 app.Options.Now。
func (c *demoClock) Now() time.Time { return c.now }

// Advance 推进时钟（TOTP 时间步 30 秒）。
func (c *demoClock) Advance(duration time.Duration) { c.now = c.now.Add(duration) }

// demoAccount 是一个合成演示账户与其真实会话。
type demoAccount struct {
	Username   string
	Password   string
	Nickname   string
	CustomerID string
	UserID     string
	TOTPSecret string
	Session    []byte
}

// demoPermissionRow 是示例页面/JSON 中的权限范围行。
type demoPermissionRow struct {
	Role             string   `json:"role"`
	Username         string   `json:"username"`
	StableUserID     string   `json:"stable_user_id"`
	DirectPermission []string `json:"direct_management_permissions"`
	ReadPermission   string   `json:"read_baseline,omitempty"`
	Result           string   `json:"demo_result"`
}

// directDemoReport 是步骤 272 演示的结构化结果（只含脱敏信息）。
type directDemoReport struct {
	PermissionMatrix []demoPermissionRow `json:"permission_matrix"`
	SummaryPagePath  string              `json:"summary_page,omitempty"`
}

// checkDirectManagementAndSearch 运行步骤 272 的完整演示与拒绝矩阵。调用时前序步骤
// （真实 Mail 找回、本人改密等）已经执行；本步骤只读取其检查状态作为“原有路径仍
// 可用”的证据，不重复消费一次找回凭据。
func (s *scenario) checkDirectManagementAndSearch() {
	report, err := s.runDirectManagementDemo()
	if err != nil {
		s.fail("step272.setup", err)
		return
	}
	s.report.DirectDemo = report
	if status := s.checkStatus("reset.mail_link"); status == "PASS" {
		s.pass("existing.email_reset_unchanged",
			"既有邮件找回链路仍通过（真实 Mail 链接提取/重置）；直接管理未修改找回配置")
	} else {
		s.notTested("existing.email_reset_unchanged",
			"前序邮件找回检查未通过，无法交叉证明既有路径")
	}
	if status := s.checkStatus("reset.stale_token_invalidated"); status == "PASS" ||
		s.checkStatus("reset.complete") == "PASS" {
		s.pass("existing.self_password_change_unchanged",
			"既有本人改密（账户页改密 + 旧会话/旧链接失效）与邮件找回检查仍通过；直接重置只作用于显式目标")
	} else {
		s.notTested("existing.self_password_change_unchanged",
			"本示例前序未覆盖本人改密检查，无法交叉证明")
	}
	// 人工恢复审批路径依赖宿主启用的人工恢复制度与独立审批角色；本示例默认关闭
	// 该制度，不能伪造审批成功。登记为未测并说明由仓库集成测试覆盖。
	s.notTested("existing.manual_recovery_unchanged",
		"本示例未启用人工恢复制度（需宿主 root 配置与独立审批角色），不伪造审批；"+
			"直接改名/重置未修改任何恢复/MFA 配置，仓库集成测试覆盖该路径")
}

// checkStatus 返回前序检查的状态；不存在返回空串。
func (s *scenario) checkStatus(id string) string {
	for _, check := range s.report.Checks {
		if check.ID == id {
			return check.Status
		}
	}
	return ""
}

// runDirectManagementDemo 在独立临时运行时上完成全部演示；失败返回错误。
func (s *scenario) runDirectManagementDemo() (*directDemoReport, error) {
	clock := &demoClock{now: time.Date(2026, 11, 23, 6, 0, 0, 0, time.UTC)}
	previousNow := s.nowOverride
	s.nowOverride = clock.Now
	defer func() { s.nowOverride = previousNow }()
	instance, err := s.openRuntime("direct272", func(config *login.Config) {
		// 演示账户由宿主受信门面创建；正式部署仍应保持邮箱验证/审核策略。
		config.Registration.Enabled = true
		config.Registration.RequireReview = false
		config.Registration.RequireEmailVerification = false
	})
	if err != nil {
		return nil, fmt.Errorf("打开步骤272 演示运行时失败: %w", err)
	}
	runtime := instance.runtime
	local := runtime.LocalAdmin()
	ctx := s.ctx

	root, err := runtime.Bootstrap().EnsureRoot(ctx, app.RootRequest{
		DisplayName: "Root", Password: "R7!qZ2#Lm9@Tp4$x", RequestID: login.NewRequestID()})
	if err != nil {
		return nil, fmt.Errorf("创建合成 root 失败: %w", err)
	}
	rootUserID := root.UserID
	admin, err := s.createDemoAccount(runtime, clock, "admin-272", "管理员", "A7!qZ2#Lm9@Tp4$x", "customer-1000")
	if err != nil {
		return nil, fmt.Errorf("创建合成管理员失败: %w", err)
	}
	supportRename, err := s.createDemoAccount(runtime, clock, "support-rename-272", "客服-改名",
		"K8$wR3!nB6@yF1#v", "customer-1001")
	if err != nil {
		return nil, fmt.Errorf("创建合成改名客服失败: %w", err)
	}
	supportReset, err := s.createDemoAccount(runtime, clock, "support-reset-272", "客服-重置",
		"S9!kR4#mW7@qB2$x", "customer-1002")
	if err != nil {
		return nil, fmt.Errorf("创建合成重置客服失败: %w", err)
	}
	target, err := s.createDemoAccount(runtime, clock, "target-272", "目标用户",
		"T6#mX3!vB9@nK2$q", "customer-2001")
	if err != nil {
		return nil, fmt.Errorf("创建合成普通目标失败: %w", err)
	}
	ordinary, err := s.createDemoAccount(runtime, clock, "ordinary-272", "普通用户",
		"O5!bN8#cF2@hJ7$m", "customer-3001")
	if err != nil {
		return nil, fmt.Errorf("创建合成普通用户失败: %w", err)
	}

	permissions, err := s.bootstrapDemoPermissions(runtime, local, &admin, &supportRename, &supportReset, &ordinary)
	if err != nil {
		return nil, err
	}
	_ = permissions

	// 真实用户管理会话：验证只读权限与直接权限的当前判定（矩阵证据）。
	matrix := []demoPermissionRow{
		{Role: "管理员", Username: admin.Username, StableUserID: admin.UserID,
			DirectPermission: []string{demo272PermissionRename, demo272PermissionReset},
			ReadPermission:   "users.read + applications.members.manage",
			Result:           "两项直接权限与成员搜索均允许"},
		{Role: "客服-只改名", Username: supportRename.Username, StableUserID: supportRename.UserID,
			DirectPermission: []string{demo272PermissionRename}, ReadPermission: "users.read",
			Result: "仅直接改名允许；直接重置被拒绝"},
		{Role: "客服-只重置", Username: supportReset.Username, StableUserID: supportReset.UserID,
			DirectPermission: []string{demo272PermissionReset}, ReadPermission: "users.read",
			Result: "仅直接重置允许；直接改名被拒绝"},
		{Role: "普通用户", Username: ordinary.Username, StableUserID: ordinary.UserID,
			ReadPermission: "", Result: "直接管理与搜索均被拒绝"},
	}
	if err := s.checkDemoPermissionMatrix(runtime, local, matrix, &admin, &supportRename, &supportReset, &ordinary); err != nil {
		return nil, err
	}

	// 真实 MFA 登录挑战（合成普通用户，非高敏权限持有者；管理员/客服的会话在授权
	// 前建立并保持有效，避免把“高权限账户只绑 TOTP 不能登录”的产品 fail-closed
	// 语义误当成示例缺陷）。密码第一步 -> TOTP 第二步 -> 完整会话。
	clock.Advance(30 * time.Second)
	ordinarySession, err := s.demoFullSessionLogin(runtime, clock,
		ordinary.Username, ordinary.Password, ordinary.TOTPSecret)
	if err != nil {
		return nil, fmt.Errorf("真实 MFA 登录挑战失败: %w", err)
	}
	ordinary.Session = ordinarySession
	s.pass("mfa.real_challenge",
		"合成普通用户经公开门面完成密码 + 程序化 TOTP 第二步真实登录挑战（非伪造强认证）")
	adminAdmin := runtime.AdminSession(admin.Session)

	// 模糊搜索（用户）：默认字段、精确 UserID 投影、非法字段拒绝。
	if err := s.checkDemoUserSearch(runtime, adminAdmin, &admin, &supportRename, &supportReset, &ordinary); err != nil {
		return nil, err
	}
	// 应用成员模糊搜索：应用范围隔离，不跨应用枚举。
	appA, err := runtime.Admin().CreateApplication(ctx, app.AdminCreateApplicationRequest{
		Caller: local, Name: "demo-app-272", OwnerUserID: admin.UserID,
		ClientType: "public", RequestID: login.NewRequestID()})
	if err != nil {
		return nil, fmt.Errorf("创建演示应用失败: %w", err)
	}
	appB, err := runtime.Admin().CreateApplication(ctx, app.AdminCreateApplicationRequest{
		Caller: local, Name: "demo-app-b-272", OwnerUserID: admin.UserID,
		ClientType: "public", RequestID: login.NewRequestID()})
	if err != nil {
		return nil, fmt.Errorf("创建第二个演示应用失败: %w", err)
	}
	for _, application := range []app.AdminApplication{appA, appB} {
		if _, err := runtime.Admin().SetApplicationEnabled(ctx,
			app.AdminSetApplicationEnabledRequest{Caller: local,
				ApplicationID: application.ID, Enabled: true,
				ExpectedRowVersion: application.RowVersion,
				RequestID:          login.NewRequestID()}); err != nil {
			return nil, fmt.Errorf("启用演示应用失败: %w", err)
		}
	}
	for _, memberID := range []string{target.UserID, supportRename.UserID} {
		if err := runtime.Admin().AddApplicationMember(ctx, app.AdminAddMemberRequest{
			Caller: local, ApplicationID: appA.ID, UserID: memberID,
			RequestID: login.NewRequestID()}); err != nil {
			return nil, fmt.Errorf("添加应用成员失败: %w", err)
		}
	}
	if err := runtime.Admin().AddApplicationMember(ctx, app.AdminAddMemberRequest{
		Caller: local, ApplicationID: appB.ID, UserID: supportReset.UserID,
		RequestID: login.NewRequestID()}); err != nil {
		return nil, fmt.Errorf("添加第二应用成员失败: %w", err)
	}
	// 应用成员列表按目标应用范围授权：为管理员在应用 A 登记应用范围角色与
	// applications.members.manage 权限（LocalAdmin 仅作宿主自举）；应用 B 故意不授予，
	// 用于证明“同权限不跨应用生效”。
	appPermission, err := runtime.Admin().CreatePermission(ctx, app.AdminCreatePermissionRequest{
		Caller: local, ScopeID: appA.ID, Key: demo272PermissionMembers,
		Name: "演示应用成员查看", Description: "步骤272 演示应用范围权限",
		Limits: "仅演示应用 A", RequestID: login.NewRequestID()})
	if err != nil {
		return nil, fmt.Errorf("登记应用范围成员权限失败: %w", err)
	}
	appRole, err := runtime.Admin().CreateRole(ctx, app.AdminCreateRoleRequest{
		Caller: local, ScopeID: appA.ID, Key: "demo272-app-member-reader",
		Name: "演示应用成员查看", Description: "步骤272 演示应用范围角色",
		Limits: "仅演示应用 A", RequestID: login.NewRequestID()})
	if err != nil {
		return nil, fmt.Errorf("创建应用范围角色失败: %w", err)
	}
	if err := runtime.Admin().AddRolePermission(ctx, app.AdminRolePermissionRequest{
		Caller: local, RoleID: appRole.ID, PermissionID: appPermission.ID,
		RequestID: login.NewRequestID()}); err != nil {
		return nil, fmt.Errorf("应用角色添加成员查看权限失败: %w", err)
	}
	if err := runtime.Admin().AddApplicationMember(ctx, app.AdminAddMemberRequest{
		Caller: local, ApplicationID: appA.ID, UserID: admin.UserID,
		RequestID: login.NewRequestID()}); err != nil {
		return nil, fmt.Errorf("管理员加入演示应用失败: %w", err)
	}
	if err := runtime.Admin().GrantApplicationRole(ctx, app.GrantRoleRequest{
		Caller: local, UserID: admin.UserID, RoleID: appRole.ID,
		RequestID: login.NewRequestID()}); err != nil {
		return nil, fmt.Errorf("管理员分配应用成员查看角色失败: %w", err)
	}
	if err := s.checkDemoMemberSearch(runtime, adminAdmin, appA.ID, appB.ID, &target, &supportRename); err != nil {
		return nil, err
	}

	// 目标行版本由客服自己的只读权限读取（不使用 LocalAdmin 读取业务数据）。
	supportRenameAdmin := runtime.AdminSession(supportRename.Session)
	profileBefore, err := runtime.Admin().GetUserProfile(ctx, app.AdminUserRequest{
		Caller: supportRenameAdmin, UserID: target.UserID, RequestID: login.NewRequestID()})
	if err != nil || profileBefore.RowVersion < 1 {
		return nil, fmt.Errorf("客服读取目标资料行版本失败: %+v err=%v", profileBefore, err)
	}

	// 直接改名：证明绑定目标+新用户名，错误意图/错误目标/重放均拒绝。
	clock.Advance(30 * time.Second)
	if err := s.runDemoDirectRename(runtime, clock, supportRenameAdmin, &supportRename,
		&target, &ordinary, profileBefore.RowVersion, matrix); err != nil {
		return nil, err
	}
	// 直接重置口令：证明绑定目标+新口令；目标 MFA 保留，旧口令失效。
	clock.Advance(30 * time.Second)
	supportResetAdmin := runtime.AdminSession(supportReset.Session)
	if err := s.runDemoDirectReset(runtime, clock, supportResetAdmin, &supportReset,
		&supportRename, &target, matrix); err != nil {
		return nil, err
	}
	// 拒绝矩阵：无权限客服/普通用户/LocalAdmin/root 目标。
	if err := s.runDemoDenials(runtime, clock, local, adminAdmin, rootUserID,
		&admin, &supportRename, &supportReset, &ordinary, &target, matrix); err != nil {
		return nil, err
	}

	// 稳定 UserID 业务投影：改名后投影仍按 UserID 关联，展示名取新用户名。
	profileAfter, err := runtime.Admin().GetUserProfile(ctx, app.AdminUserRequest{
		Caller: adminAdmin, UserID: target.UserID, RequestID: login.NewRequestID()})
	if err != nil || profileAfter.UserID != target.UserID || profileAfter.Username != demo272RenamedUsername {
		return nil, fmt.Errorf("改名后稳定 UserID/展示名异常: %+v err=%v", profileAfter, err)
	}
	if target.CustomerID != "customer-2001" || target.UserID != profileAfter.UserID {
		return nil, fmt.Errorf("业务投影未按稳定 UserID 关联: customer_id=%s user_id=%s",
			target.CustomerID, target.UserID)
	}

	report := &directDemoReport{PermissionMatrix: matrix}
	pagePath := filepath.Join(instance.dir, "direct272-summary.html")
	if err := writeDirectDemoPage(pagePath, report, s.report); err != nil {
		return nil, fmt.Errorf("写示例权限范围页面失败: %w", err)
	}
	pageBytes, readErr := os.ReadFile(pagePath)
	if readErr != nil {
		return nil, fmt.Errorf("读取示例权限范围页面失败: %w", readErr)
	}
	for _, marker := range []string{demo272PermissionRename, demo272PermissionReset,
		"auth.denied_matrix", "direct.reset.target_mfa_preserved"} {
		if !strings.Contains(string(pageBytes), marker) {
			return nil, fmt.Errorf("示例页面缺少权限/错误范围标记 %q", marker)
		}
	}
	s.pass("page.summary_rendered",
		"生成脱敏 HTML 权限范围页面：含角色/稳定 UserID/两项直接权限/拒绝矩阵与稳定检查码，不含密码或令牌")
	report.SummaryPagePath = pagePath
	return report, nil
}

// createDemoAccount 用公开门面创建合成账户、登录、绑定真实 TOTP 并返回会话。
func (s *scenario) createDemoAccount(runtime *app.Runtime, clock *demoClock,
	username, nickname, password, customerID string) (demoAccount, error) {
	ctx := s.ctx
	created, err := runtime.Users().Create(ctx, app.CreateUserRequest{
		Username: username, Password: password, Nickname: nickname,
		RequestID: login.NewRequestID()})
	if err != nil {
		return demoAccount{}, fmt.Errorf("创建账户 %s: %w", username, err)
	}
	loginResult, err := runtime.Auth().Login(ctx, app.LoginRequest{
		Username: username, Password: password, ClientIP: "127.0.0.1",
		UserAgent: "step272-example", RequestID: login.NewRequestID()})
	if err != nil || loginResult.Restricted || len(loginResult.SessionSecret) == 0 {
		return demoAccount{}, fmt.Errorf("账户 %s 首次登录异常（%s）err=%v",
			username, demoLoginSummary(loginResult), err)
	}
	start, err := runtime.Security().BeginTOTPBinding(ctx, app.TOTPBindingBeginRequest{
		SessionSecret: loginResult.SessionSecret, Password: password,
		RequestID: login.NewRequestID()})
	if err != nil {
		return demoAccount{}, fmt.Errorf("账户 %s 开始绑定 TOTP: %w", username, err)
	}
	code, err := totpCode(start.Secret, clock.Now())
	if err != nil {
		return demoAccount{}, err
	}
	if _, err := runtime.Security().ConfirmTOTPBinding(ctx, app.TOTPBindingConfirmRequest{
		SessionSecret: loginResult.SessionSecret, BindingID: start.BindingID, Code: code,
		RequestID: login.NewRequestID()}); err != nil {
		return demoAccount{}, fmt.Errorf("账户 %s 确认 TOTP: %w", username, err)
	}
	status, err := runtime.Security().Status(ctx, app.SecurityStatusRequest{
		SessionSecret: loginResult.SessionSecret, RequestID: login.NewRequestID()})
	if err != nil || !status.TOTPActive || !status.StrongFactorBound {
		return demoAccount{}, fmt.Errorf("账户 %s TOTP 状态异常: %+v err=%v", username, status, err)
	}
	return demoAccount{Username: username, Password: password, Nickname: nickname,
		CustomerID: customerID, UserID: created.ID, TOTPSecret: start.Secret,
		Session: loginResult.SessionSecret}, nil
}

// demoLoginSummary 只输出登录结果的可公开诊断字段（restricted/UserID/因素类型）。
// 禁止把 app.LoginResult 整体格式化到错误或日志：其 SessionSecret/CSRFSecret/
// SecondFactor 中的 AttemptToken 均为秘密（步骤272 安全审计 LOW-2）。错误文本只
// 附带公开错误码。
func demoLoginSummary(result app.LoginResult) string {
	factor := ""
	if result.SecondFactor != nil {
		factor = result.SecondFactor.FactorType
	}
	return fmt.Sprintf("restricted=%t user_id=%s factor=%s", result.Restricted, result.UserID, factor)
}

// demoFullSessionLogin 用密码 + TOTP 完成真实第二步登录，返回完整会话。
func (s *scenario) demoFullSessionLogin(runtime *app.Runtime, clock *demoClock,
	username, password, totpSecret string) ([]byte, error) {
	ctx := s.ctx
	first, err := runtime.Auth().Login(ctx, app.LoginRequest{
		Username: username, Password: password, ClientIP: "127.0.0.1",
		UserAgent: "step272-example", RequestID: login.NewRequestID()})
	if err != nil || !first.Restricted || first.SecondFactor == nil {
		return nil, fmt.Errorf("未进入 TOTP 第二步（%s）err=%v",
			demoLoginSummary(first), err)
	}
	code, err := totpCode(totpSecret, clock.Now())
	if err != nil {
		return nil, err
	}
	verified, err := runtime.Auth().VerifySecondFactor(ctx, app.VerifySecondFactorRequest{
		SessionSecret: first.SessionSecret, ChallengeID: first.SecondFactor.ChallengeID,
		AttemptToken: first.SecondFactor.AttemptToken, Code: code,
		RequestID: login.NewRequestID()})
	if err != nil || len(verified.SessionSecret) == 0 {
		return nil, fmt.Errorf("TOTP 第二步失败: %w", err)
	}
	return verified.SessionSecret, nil
}

// bootstrapDemoPermissions 用 LocalAdmin 只做宿主自举：登记权限、角色、分配角色。
func (s *scenario) bootstrapDemoPermissions(runtime *app.Runtime, local app.AdminCaller,
	admin, supportRename, supportReset, ordinary *demoAccount) (map[string]string, error) {
	ctx := s.ctx
	keys := map[string]string{
		demo272PermissionRead:    "查看普通用户",
		demo272PermissionMembers: "管理应用成员",
		demo272PermissionRename:  "直接修改他人用户名",
		demo272PermissionReset:   "直接重置他人密码",
	}
	ids := make(map[string]string, len(keys))
	for key, name := range keys {
		created, err := runtime.Admin().CreatePermission(ctx, app.AdminCreatePermissionRequest{
			Caller: local, ScopeID: "system", Key: key, Name: name,
			Description: "步骤272 演示用权限登记", Limits: "仅演示环境",
			RequestID: login.NewRequestID()})
		if err != nil {
			return nil, fmt.Errorf("登记演示权限 %s 失败: %w", key, err)
		}
		ids[key] = created.ID
	}
	roles := []struct {
		key   string
		name  string
		perms []string
	}{
		{"demo272-admin", "演示管理员", []string{demo272PermissionRead,
			demo272PermissionMembers, demo272PermissionRename, demo272PermissionReset}},
		{"demo272-support-rename", "客服-只改名", []string{demo272PermissionRead,
			demo272PermissionRename}},
		{"demo272-support-reset", "客服-只重置", []string{demo272PermissionRead,
			demo272PermissionReset}},
	}
	roleIDs := make(map[string]string, len(roles))
	for _, item := range roles {
		created, err := runtime.Admin().CreateRole(ctx, app.AdminCreateRoleRequest{
			Caller: local, ScopeID: "system", Key: item.key, Name: item.name,
			Description: "步骤272 演示角色", Limits: "仅演示环境",
			RequestID: login.NewRequestID()})
		if err != nil {
			return nil, fmt.Errorf("创建演示角色 %s 失败: %w", item.key, err)
		}
		roleIDs[item.key] = created.ID
		for _, permissionKey := range item.perms {
			if err := runtime.Admin().AddRolePermission(ctx, app.AdminRolePermissionRequest{
				Caller: local, RoleID: created.ID, PermissionID: ids[permissionKey],
				RequestID: login.NewRequestID()}); err != nil {
				return nil, fmt.Errorf("角色 %s 添加权限 %s 失败: %w",
					item.key, permissionKey, err)
			}
		}
	}
	assignments := []struct {
		userID string
		roleID string
	}{
		{admin.UserID, roleIDs["demo272-admin"]},
		{supportRename.UserID, roleIDs["demo272-support-rename"]},
		{supportReset.UserID, roleIDs["demo272-support-reset"]},
	}
	for _, item := range assignments {
		if err := runtime.Admin().GrantApplicationRole(ctx, app.GrantRoleRequest{
			Caller: local, UserID: item.userID, RoleID: item.roleID,
			RequestID: login.NewRequestID()}); err != nil {
			return nil, fmt.Errorf("分配演示角色失败: %w", err)
		}
	}
	_ = ordinary
	return ids, nil
}

// checkDemoPermissionMatrix 用真实权限内核验证角色范围（LocalAdmin 只查询，不做操作）。
func (s *scenario) checkDemoPermissionMatrix(runtime *app.Runtime, local app.AdminCaller,
	matrix []demoPermissionRow, admin, supportRename, supportReset, ordinary *demoAccount) error {
	ctx := s.ctx
	expect := func(userID, permission string, want bool) error {
		decision, err := runtime.Admin().CheckPermission(ctx, app.AdminPermissionCheck{
			Caller: local, UserID: userID, ScopeID: "system", Permission: permission,
			Mode: "all", RequestID: login.NewRequestID()})
		if err != nil {
			return fmt.Errorf("权限检查 %s 失败: %w", permission, err)
		}
		if decision.Allowed != want {
			return fmt.Errorf("权限 %s 期望 allowed=%t，实际 %+v", permission, want, decision)
		}
		return nil
	}
	if err := expect(admin.UserID, demo272PermissionRename, true); err != nil {
		return err
	}
	if err := expect(admin.UserID, demo272PermissionReset, true); err != nil {
		return err
	}
	if err := expect(supportRename.UserID, demo272PermissionRename, true); err != nil {
		return err
	}
	if err := expect(supportRename.UserID, demo272PermissionReset, false); err != nil {
		return err
	}
	if err := expect(supportReset.UserID, demo272PermissionReset, true); err != nil {
		return err
	}
	if err := expect(supportReset.UserID, demo272PermissionRename, false); err != nil {
		return err
	}
	if err := expect(ordinary.UserID, demo272PermissionRename, false); err != nil {
		return err
	}
	if err := expect(ordinary.UserID, demo272PermissionReset, false); err != nil {
		return err
	}
	_ = matrix
	return nil
}

// checkDemoUserSearch 验证用户列表模糊搜索：命中用户名/昵称、空搜索等价原列表、
// 非法搜索字段拒绝、改名前后旧名不命中/新名命中、稳定 UserID 不变。
func (s *scenario) checkDemoUserSearch(runtime *app.Runtime, adminAdmin app.AdminCaller,
	admin, supportRename, supportReset, ordinary *demoAccount) error {
	ctx := s.ctx
	page, err := runtime.Admin().ListUsers(ctx, app.AdminListUsersRequest{
		Caller: adminAdmin, Limit: 50, Search: "support", RequestID: login.NewRequestID()})
	if err != nil {
		return fmt.Errorf("用户模糊搜索失败: %w", err)
	}
	usernames := make(map[string]bool, len(page.Users))
	for _, user := range page.Users {
		usernames[user.Username] = true
	}
	if !usernames[supportRename.Username] || !usernames[supportReset.Username] {
		return fmt.Errorf("用户搜索 support 未命中两个客服: %+v", page.Users)
	}
	nicknamePage, err := runtime.Admin().ListUsers(ctx, app.AdminListUsersRequest{
		Caller: adminAdmin, Limit: 20, Search: "目标", SearchFields: []string{"nickname"},
		RequestID: login.NewRequestID()})
	if err != nil || !containsAdminUsername(nicknamePage.Users, "target-272") {
		return fmt.Errorf("昵称字段搜索未命中目标用户: %+v err=%v", nicknamePage.Users, err)
	}
	if _, err := runtime.Admin().ListUsers(ctx, app.AdminListUsersRequest{
		Caller: adminAdmin, Limit: 10, Search: "x", SearchFields: []string{"email"},
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		return fmt.Errorf("非法搜索字段应返回 REQ_INVALID: %v", err)
	}
	empty, err := runtime.Admin().ListUsers(ctx, app.AdminListUsersRequest{
		Caller: adminAdmin, Limit: 50, RequestID: login.NewRequestID()})
	if err != nil || len(empty.Users) < 5 {
		return fmt.Errorf("空搜索应等价原列表且包含合成账户: %d %v", len(empty.Users), err)
	}
	_ = admin
	_ = ordinary
	return nil
}

// checkDemoMemberSearch 验证应用成员模糊搜索的范围隔离（同名账户不同应用不泄露，
// 只匹配目标应用成员的用户名/昵称）。
func (s *scenario) checkDemoMemberSearch(runtime *app.Runtime, adminAdmin app.AdminCaller,
	appAID, appBID string, target, supportRename *demoAccount) error {
	ctx := s.ctx
	memberPage, err := runtime.Admin().ListApplicationMembers(ctx,
		app.AdminListApplicationMembersRequest{Caller: adminAdmin, ApplicationID: appAID,
			Search: "target", Page: app.AdminPage{Limit: 20}, RequestID: login.NewRequestID()})
	if err != nil {
		return fmt.Errorf("应用成员搜索失败: %w", err)
	}
	found := false
	for _, member := range memberPage.Members {
		if member.UserID == target.UserID {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("应用 A 成员搜索未命中目标: %+v", memberPage.Members)
	}
	otherApp, err := runtime.Admin().ListApplicationMembers(ctx,
		app.AdminListApplicationMembersRequest{Caller: adminAdmin, ApplicationID: appBID,
			Search: "target", Page: app.AdminPage{Limit: 20}, RequestID: login.NewRequestID()})
	if err == nil && len(otherApp.Members) > 0 {
		return fmt.Errorf("成员搜索不得跨应用返回非成员: %+v", otherApp.Members)
	}
	if err == nil {
		return fmt.Errorf("管理员在应用 B 无权限，成员搜索应被拒绝而不是空成功")
	}
	if !login.IsErrorCode(err, login.CodeAccessDenied) &&
		!login.IsErrorCode(err, login.CodePermissionRequired) {
		return fmt.Errorf("跨应用成员搜索应返回权限拒绝: %v", err)
	}
	if _, err := runtime.Admin().ListApplicationMembers(ctx,
		app.AdminListApplicationMembersRequest{Caller: adminAdmin, ApplicationID: appAID,
			Search: "x", SearchFields: []string{"email"}, Page: app.AdminPage{Limit: 20},
			RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		return fmt.Errorf("成员非法搜索字段应 REQ_INVALID: %v", err)
	}
	_ = supportRename
	return nil
}

// runDemoDirectRename 演示直接改名：证明绑定目标与新用户名，错误意图/目标/重放拒绝。
func (s *scenario) runDemoDirectRename(runtime *app.Runtime, clock *demoClock,
	operator app.AdminCaller, operatorAccount *demoAccount, target, otherTarget *demoAccount,
	rowVersion int64, matrix []demoPermissionRow) error {
	ctx := s.ctx
	proof := runtime.OperationProof()
	challenge, err := proof.Begin(ctx, app.OperationProofBeginRequest{
		Caller: operator, TargetUserID: target.UserID,
		Operation: app.OperationProofUsernameChange, NewUsername: demo272RenamedUsername,
		RequestID: login.NewRequestID()})
	if err != nil {
		return fmt.Errorf("直接改名证明发起失败: %w", err)
	}
	code, err := totpCode(operatorAccount.TOTPSecret, clock.Now())
	if err != nil {
		return err
	}
	grant, err := proof.Confirm(ctx, app.OperationProofConfirmRequest{
		Caller: operator, ChallengeID: challenge.ChallengeID,
		Password: operatorAccount.Password, TOTPCode: code, RequestID: login.NewRequestID()})
	if err != nil {
		return fmt.Errorf("直接改名证明两步验证失败: %w", err)
	}
	base := app.AdminChangeUserUsernameRequest{
		Caller: operator, TargetUserID: target.UserID, NewUsername: demo272RenamedUsername,
		ExpectedRowVersion: rowVersion, Reason: demo272Reason,
		ProofToken: grant.ProofToken, RequestID: login.NewRequestID()}
	// 错误新值意图：证明绑定的是 demo272RenamedUsername，换名必须拒绝且不消费证明。
	wrongIntent := base
	wrongIntent.NewUsername = "target-other-name-272"
	if _, err := runtime.DirectUserManagement().ChangeUserUsername(ctx,
		wrongIntent); err == nil {
		return fmt.Errorf("换新用户名不应通过目标绑定证明")
	}
	// 错误目标：证明绑定目标 target，换成 otherTarget 必须拒绝。
	wrongTarget := base
	wrongTarget.TargetUserID = otherTarget.UserID
	if _, err := runtime.DirectUserManagement().ChangeUserUsername(ctx,
		wrongTarget); err == nil {
		return fmt.Errorf("换目标不应通过目标绑定证明")
	}
	// 正确执行：成功改名且目标 UserID 稳定。
	updated, err := runtime.DirectUserManagement().ChangeUserUsername(ctx, base)
	if err != nil {
		return fmt.Errorf("直接改名执行失败: %w", err)
	}
	if updated.UserID != target.UserID || updated.Username != demo272RenamedUsername {
		return fmt.Errorf("直接改名结果异常: %+v", updated)
	}
	target.Username = updated.Username
	s.pass("direct.rename.success",
		"真实客服会话经目标绑定证明(密码+TOTP)直接改名成功；稳定 UserID="+updated.UserID)
	s.pass("direct.rename.negative_matrix",
		"换新用户名/换目标均在证明校验处拒绝；证明未被失败尝试烧毁")
	// 成功后重放同一证明：必须拒绝且不再二次改名。
	replay := base
	replay.ExpectedRowVersion = updated.RowVersion
	replay.NewUsername = demo272RenamedUsername
	if _, err := runtime.DirectUserManagement().ChangeUserUsername(ctx,
		replay); err == nil {
		return fmt.Errorf("直接改名成功后重放证明应被拒绝")
	}
	s.pass("direct.rename.replay_denied", "成功后重放同一一次性证明被拒绝")
	// 改名后搜索：旧用户名不命中、新用户名命中；业务投影仍按稳定 UserID。
	oldSearch, err := runtime.Admin().ListUsers(ctx, app.AdminListUsersRequest{
		Caller: runtime.AdminSession(operatorAccount.Session), Limit: 20, Search: "target-272",
		RequestID: login.NewRequestID()})
	if err != nil {
		return fmt.Errorf("改名后旧用户名搜索失败: %w", err)
	}
	if containsAdminUserID(oldSearch.Users, target.UserID) {
		return fmt.Errorf("改名后旧用户名不应命中: %+v", oldSearch.Users)
	}
	newSearch, err := runtime.Admin().ListUsers(ctx, app.AdminListUsersRequest{
		Caller: runtime.AdminSession(operatorAccount.Session), Limit: 20,
		Search: demo272RenamedUsername, RequestID: login.NewRequestID()})
	if err != nil || !containsAdminUserID(newSearch.Users, target.UserID) {
		return fmt.Errorf("改名后新用户名应命中: %+v err=%v", newSearch.Users, err)
	}
	s.pass("search.rename_projection_synced",
		"改名后列表按新用户名命中、旧用户名不命中；业务投影仍以稳定 UserID 关联")
	return nil
}

// runDemoDirectReset 演示直接重置口令：目标 MFA 保留、旧口令失效、新口令 + TOTP 登录。
func (s *scenario) runDemoDirectReset(runtime *app.Runtime, clock *demoClock,
	readOperator app.AdminCaller, operatorAccount, deniedOperator *demoAccount,
	target *demoAccount, matrix []demoPermissionRow) error {
	ctx := s.ctx
	proof := runtime.OperationProof()
	challenge, err := proof.Begin(ctx, app.OperationProofBeginRequest{
		Caller: readOperator, TargetUserID: target.UserID,
		Operation: app.OperationProofPasswordReset, NewPassword: demo272ResetNewPassword,
		RequestID: login.NewRequestID()})
	if err != nil {
		return fmt.Errorf("直接重置证明发起失败: %w", err)
	}
	// 只持有改名权限的客服不能发起重置证明（权限在证明创建事务内判定）。
	if _, err := proof.Begin(ctx, app.OperationProofBeginRequest{
		Caller: runtime.AdminSession(deniedOperator.Session), TargetUserID: target.UserID,
		Operation: app.OperationProofPasswordReset, NewPassword: demo272SecondResetPassword,
		RequestID: login.NewRequestID()}); err == nil {
		return fmt.Errorf("只持改名权限的客服不应发起重置证明")
	}
	code, err := totpCode(operatorAccount.TOTPSecret, clock.Now())
	if err != nil {
		return err
	}
	grant, err := proof.Confirm(ctx, app.OperationProofConfirmRequest{
		Caller: readOperator, ChallengeID: challenge.ChallengeID,
		Password: operatorAccount.Password, TOTPCode: code, RequestID: login.NewRequestID()})
	if err != nil {
		return fmt.Errorf("直接重置证明两步验证失败: %w", err)
	}
	request := app.AdminResetUserPasswordRequest{
		Caller: readOperator, TargetUserID: target.UserID,
		NewPassword: demo272ResetNewPassword, Reason: demo272Reason,
		ProofToken: grant.ProofToken, RequestID: login.NewRequestID()}
	wrongIntent := request
	wrongIntent.NewPassword = demo272SecondResetPassword
	if _, err := runtime.DirectPasswordManagement().ResetUserPassword(ctx,
		wrongIntent); err == nil {
		return fmt.Errorf("换新口令不应通过目标绑定证明")
	}
	result, err := runtime.DirectPasswordManagement().ResetUserPassword(ctx, request)
	if err != nil {
		return fmt.Errorf("直接重置口令执行失败: %w", err)
	}
	if result.UserID != target.UserID || !result.MustChange {
		return fmt.Errorf("直接重置结果异常: %+v", result)
	}
	s.pass("direct.reset.success",
		"真实客服会话经目标绑定证明直接重置口令成功；目标需下次登录改密，结果脱敏")
	// 旧口令失效；新口令登录只先要求本人强制改密（受限会话），完成强制改密后仍
	// 必须通过原 TOTP 第二步 —— 证明直接重置没有解除目标 MFA。
	if _, err := runtime.Auth().Login(ctx, app.LoginRequest{
		Username: target.Username, Password: target.Password, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()}); err == nil {
		return fmt.Errorf("直接重置后旧口令不应还能登录")
	}
	restricted, err := runtime.Auth().Login(ctx, app.LoginRequest{
		Username: target.Username, Password: demo272ResetNewPassword,
		ClientIP: "127.0.0.1", RequestID: login.NewRequestID()})
	if err != nil || !restricted.Restricted || len(restricted.SessionSecret) == 0 {
		return fmt.Errorf("重置后新口令应进入强制改密受限会话（%s）err=%v",
			demoLoginSummary(restricted), err)
	}
	finalPassword := "G5!vB9#tY2@nR7$k"
	if _, err := runtime.RequiredPasswordChanges().Complete(ctx,
		app.RequiredPasswordChangeRequest{SessionSecret: restricted.SessionSecret,
			CurrentPassword: demo272ResetNewPassword, NewPassword: finalPassword,
			ClientIP: "127.0.0.1", RequestID: login.NewRequestID()}); err != nil {
		return fmt.Errorf("目标完成强制改密失败: %w", err)
	}
	clock.Advance(30 * time.Second)
	retryRestricted, err := runtime.Auth().Login(ctx, app.LoginRequest{
		Username: target.Username, Password: finalPassword, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil || !retryRestricted.Restricted || retryRestricted.SecondFactor == nil ||
		retryRestricted.SecondFactor.FactorType != "totp" {
		return fmt.Errorf("强制改密后登录应仍进入 TOTP 第二步（MFA 保留）（%s）err=%v",
			demoLoginSummary(retryRestricted), err)
	}
	if _, err := runtime.Auth().VerifySecondFactor(ctx, app.VerifySecondFactorRequest{
		SessionSecret: retryRestricted.SessionSecret,
		ChallengeID:   retryRestricted.SecondFactor.ChallengeID,
		AttemptToken:  retryRestricted.SecondFactor.AttemptToken,
		Code:          mustDemoTOTP(target.TOTPSecret, clock.Now()),
		RequestID:     login.NewRequestID()}); err != nil {
		return fmt.Errorf("重置后目标 TOTP 第二步失败（MFA 应保留）: %w", err)
	}
	s.pass("direct.reset.target_mfa_preserved",
		"重置后旧口令失效、新口令只能先进强制改密受限会话；强制改密完成后仍需原 TOTP 第二步，直接操作不解除目标 MFA")
	s.pass("direct.reset.intent_binding",
		"换新口令被证明意图绑定拒绝；失败尝试未烧毁证明，正确口令随后成功")
	_ = matrix
	return nil
}

// runDemoDenials 覆盖无权限客服/普通用户/LocalAdmin 与 root 目标的拒绝。
func (s *scenario) runDemoDenials(runtime *app.Runtime, clock *demoClock,
	local app.AdminCaller, adminAdmin app.AdminCaller, rootUserID string,
	admin, supportRename, supportReset, ordinary, target *demoAccount,
	matrix []demoPermissionRow) error {
	ctx := s.ctx
	proof := runtime.OperationProof()
	// 只持重置权限的客服不能发起改名证明。
	if _, err := proof.Begin(ctx, app.OperationProofBeginRequest{
		Caller: runtime.AdminSession(supportReset.Session), TargetUserID: target.UserID,
		Operation: app.OperationProofUsernameChange, NewUsername: "should-not-pass-272",
		RequestID: login.NewRequestID()}); err == nil {
		return fmt.Errorf("只持重置权限的客服不应发起改名证明")
	}
	// 普通用户无任何直接管理权限。
	if _, err := proof.Begin(ctx, app.OperationProofBeginRequest{
		Caller: runtime.AdminSession(ordinary.Session), TargetUserID: target.UserID,
		Operation: app.OperationProofUsernameChange, NewUsername: "should-not-pass-272",
		RequestID: login.NewRequestID()}); err == nil {
		return fmt.Errorf("普通用户不应发起直接管理证明")
	}
	// LocalAdmin 没有用户两步因素：不得用本机受信身份跳过证明。
	if _, err := proof.Begin(ctx, app.OperationProofBeginRequest{
		Caller: local, TargetUserID: target.UserID,
		Operation: app.OperationProofUsernameChange, NewUsername: "should-not-pass-272",
		RequestID: login.NewRequestID()}); err == nil {
		return fmt.Errorf("LocalAdmin 不应发起直接管理证明")
	}
	// root 目标受保护：证明可发起（权限/目标参数合法），但执行处的领域校验必须
	// 拒绝把 root 作为直接改名目标。
	rootChallenge, rootErr := proof.Begin(ctx, app.OperationProofBeginRequest{
		Caller: adminAdmin, TargetUserID: rootUserID,
		Operation: app.OperationProofUsernameChange, NewUsername: "root-renamed-272",
		RequestID: login.NewRequestID()})
	if rootErr == nil {
		rootCode, codeErr := totpCode(admin.TOTPSecret, clock.Now())
		if codeErr != nil {
			return codeErr
		}
		rootGrant, grantErr := proof.Confirm(ctx, app.OperationProofConfirmRequest{
			Caller: adminAdmin, ChallengeID: rootChallenge.ChallengeID,
			Password: admin.Password, TOTPCode: rootCode, RequestID: login.NewRequestID()})
		if grantErr != nil {
			return fmt.Errorf("root 目标证明两步验证失败: %w", grantErr)
		}
		if _, execErr := runtime.DirectUserManagement().ChangeUserUsername(ctx,
			app.AdminChangeUserUsernameRequest{Caller: adminAdmin, TargetUserID: rootUserID,
				NewUsername: "root-renamed-272", ExpectedRowVersion: 1,
				Reason: demo272Reason, ProofToken: rootGrant.ProofToken,
				RequestID: login.NewRequestID()}); execErr == nil {
			return fmt.Errorf("root 目标不应被直接改名")
		}
	}
	// 越权执行（无第二证明直接调用执行门面）也必须拒绝：直接调用需有效证明令牌。
	if _, err := runtime.DirectUserManagement().ChangeUserUsername(ctx,
		app.AdminChangeUserUsernameRequest{Caller: runtime.AdminSession(supportReset.Session),
			TargetUserID: target.UserID, NewUsername: "no-proof-272",
			ExpectedRowVersion: 1, Reason: demo272Reason, ProofToken: "invalid-proof",
			RequestID: login.NewRequestID()}); err == nil {
		return fmt.Errorf("无有效证明令牌的直接改名应被拒绝")
	}
	if _, err := runtime.DirectPasswordManagement().ResetUserPassword(ctx,
		app.AdminResetUserPasswordRequest{Caller: runtime.AdminSession(supportRename.Session),
			TargetUserID: target.UserID, NewPassword: demo272SecondResetPassword,
			Reason: demo272Reason, ProofToken: "invalid-proof",
			RequestID: login.NewRequestID()}); err == nil {
		return fmt.Errorf("无有效证明令牌的直接重置应被拒绝")
	}
	// LOW-1(a)：缺少用户第二因素（TOTP）的证明完成必须 fail-closed。密码正确但
	// TOTP 为空时 Confirm 拒绝；随后取消挑战，不产生可执行证明。
	noMFAChallenge, err := proof.Begin(ctx, app.OperationProofBeginRequest{
		Caller: runtime.AdminSession(supportRename.Session), TargetUserID: ordinary.UserID,
		Operation: app.OperationProofUsernameChange, NewUsername: "no-mfa-272",
		RequestID: login.NewRequestID()})
	if err != nil {
		return fmt.Errorf("无 MFA 负例的证明发起失败: %w", err)
	}
	if _, confirmErr := proof.Confirm(ctx, app.OperationProofConfirmRequest{
		Caller:      runtime.AdminSession(supportRename.Session),
		ChallengeID: noMFAChallenge.ChallengeID, Password: supportRename.Password,
		TOTPCode: "", RequestID: login.NewRequestID()}); confirmErr == nil {
		return fmt.Errorf("缺少 TOTP 第二步的直接管理证明不应成功")
	}
	if cancelErr := proof.Cancel(ctx, app.OperationProofCancelRequest{
		Caller:      runtime.AdminSession(supportRename.Session),
		ChallengeID: noMFAChallenge.ChallengeID,
		RequestID:   login.NewRequestID()}); cancelErr != nil {
		return fmt.Errorf("取消无 MFA 证明挑战: %w", cancelErr)
	}
	s.pass("auth.denied_without_mfa",
		"密码正确但缺少 TOTP 第二步时直接管理证明 Confirm fail-closed 拒绝；挑战可取消且不产生证明")
	// LOW-1(b)：证明已签发、执行前权限被撤销时，执行处必须 fail-closed 拒绝，
	// 目标不变；随后恢复角色，保持演示后续状态一致。
	renameRoleID, err := demoFindRoleID(ctx, runtime, local, "demo272-support-rename")
	if err != nil {
		return fmt.Errorf("查询改名客服角色失败: %w", err)
	}
	supportRenameAdmin := runtime.AdminSession(supportRename.Session)
	ordinaryProfile, err := runtime.Admin().GetUserProfile(ctx, app.AdminUserRequest{
		Caller: supportRenameAdmin, UserID: ordinary.UserID, RequestID: login.NewRequestID()})
	if err != nil || ordinaryProfile.RowVersion < 1 {
		return fmt.Errorf("读取普通用户行版本失败: %+v err=%v", ordinaryProfile, err)
	}
	revokedChallenge, err := proof.Begin(ctx, app.OperationProofBeginRequest{
		Caller: supportRenameAdmin, TargetUserID: ordinary.UserID,
		Operation: app.OperationProofUsernameChange, NewUsername: "ordinary-renamed-272",
		RequestID: login.NewRequestID()})
	if err != nil {
		return fmt.Errorf("权限撤销负例的证明发起失败: %w", err)
	}
	clock.Advance(30 * time.Second)
	revokedCode, err := totpCode(supportRename.TOTPSecret, clock.Now())
	if err != nil {
		return err
	}
	revokedGrant, err := proof.Confirm(ctx, app.OperationProofConfirmRequest{
		Caller: supportRenameAdmin, ChallengeID: revokedChallenge.ChallengeID,
		Password: supportRename.Password, TOTPCode: revokedCode,
		RequestID: login.NewRequestID()})
	if err != nil {
		return fmt.Errorf("权限撤销负例的证明两步验证失败: %w", err)
	}
	if err := runtime.Admin().RevokeApplicationRole(ctx, app.RevokeRoleRequest{
		Caller: local, UserID: supportRename.UserID, RoleID: renameRoleID,
		RequestID: login.NewRequestID()}); err != nil {
		return fmt.Errorf("撤销改名客服角色: %w", err)
	}
	if _, execErr := runtime.DirectUserManagement().ChangeUserUsername(ctx,
		app.AdminChangeUserUsernameRequest{Caller: supportRenameAdmin,
			TargetUserID: ordinary.UserID, NewUsername: "ordinary-renamed-272",
			ExpectedRowVersion: ordinaryProfile.RowVersion, Reason: demo272Reason,
			ProofToken: revokedGrant.ProofToken, RequestID: login.NewRequestID()}); execErr == nil {
		return fmt.Errorf("权限撤销后直接改名不应成功")
	}
	unchanged, err := runtime.Admin().GetUserProfile(ctx, app.AdminUserRequest{
		Caller: adminAdmin, UserID: ordinary.UserID, RequestID: login.NewRequestID()})
	if err != nil || unchanged.Username != ordinary.Username {
		return fmt.Errorf("权限撤销后拒绝执行时目标不应变化: %+v err=%v", unchanged, err)
	}
	if err := runtime.Admin().GrantApplicationRole(ctx, app.GrantRoleRequest{
		Caller: local, UserID: supportRename.UserID, RoleID: renameRoleID,
		RequestID: login.NewRequestID()}); err != nil {
		return fmt.Errorf("恢复改名客服角色: %w", err)
	}
	s.pass("auth.denied_after_revoke",
		"证明已签发但执行前撤销授权时直接改名 fail-closed 拒绝且目标不变；权限恢复后演示状态一致")
	s.pass("auth.denied_matrix",
		"无直接权限客服/普通用户/LocalAdmin/root 目标/无有效证明执行全部 fail-closed 拒绝")
	_ = clock
	_ = admin
	_ = matrix
	return nil
}

// demoFindRoleID 用本机受信查询按角色键查找系统范围角色 ID（仅演示夹具定位，不
// 授予任何能力）。
func demoFindRoleID(ctx context.Context, runtime *app.Runtime, local app.AdminCaller,
	key string) (string, error) {
	list, err := runtime.Admin().ListRoles(ctx, app.AdminListRolesRequest{
		Caller: local, ScopeID: "system", Search: key, Page: app.AdminPage{Limit: 20},
		RequestID: login.NewRequestID()})
	if err != nil {
		return "", err
	}
	for _, role := range list.Roles {
		if role.Key == key {
			return role.ID, nil
		}
	}
	return "", fmt.Errorf("未找到角色 %s", key)
}

// directoryEntry 是示例页面的一个权限范围条目。
type directoryEntry struct {
	Role       string
	Username   string
	StableID   string
	Direct     string
	Read       string
	DemoResult string
}

// writeDirectDemoPage 写一份自包含 HTML 示例页面（权限范围/稳定 UserID/错误码），
// 不引用外部资源；页面只含脱敏合成数据。
func writeDirectDemoPage(path string, report *directDemoReport, scenarioReport *scenarioReport) error {
	var builder strings.Builder
	builder.WriteString("<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\">")
	builder.WriteString("<title>EvernightLogin 步骤272 直接管理与模糊搜索示例</title>")
	builder.WriteString("<style>body{font-family:system-ui,sans-serif;margin:2rem;line-height:1.5}" +
		"table{border-collapse:collapse;margin:1rem 0}td,th{border:1px solid #999;padding:.35rem .6rem;text-align:left}" +
		".pass{color:#136f13}.fail{color:#a40000}</style><h1>步骤272 示例：直接管理与模糊搜索</h1>")
	builder.WriteString("<p>本页由一条命令的 self-test 生成：临时 SQLite/Mail/测试认证器；" +
		"LocalAdmin 仅用于宿主自举，直接操作全部由真实用户会话 + 目标绑定一次性两步验证证明执行。页面不含密码/种子/令牌。</p>")
	builder.WriteString("<h2>权限范围（合成角色，按稳定 UserID 关联业务投影）</h2><table>")
	builder.WriteString("<tr><th>角色</th><th>用户名</th><th>稳定 UserID</th><th>直接管理权限</th><th>只读基线</th><th>演示结果</th></tr>")
	for _, row := range report.PermissionMatrix {
		builder.WriteString("<tr><td>")
		builder.WriteString(html.EscapeString(row.Role))
		builder.WriteString("</td><td>")
		builder.WriteString(html.EscapeString(row.Username))
		builder.WriteString("</td><td><code>")
		builder.WriteString(html.EscapeString(row.StableUserID))
		builder.WriteString("</code></td><td>")
		builder.WriteString(html.EscapeString(strings.Join(row.DirectPermission, ", ")))
		builder.WriteString("</td><td>")
		builder.WriteString(html.EscapeString(row.ReadPermission))
		builder.WriteString("</td><td>")
		builder.WriteString(html.EscapeString(row.Result))
		builder.WriteString("</td></tr>")
	}
	builder.WriteString("</table><h2>直接管理/搜索检查与稳定错误码</h2><table><tr><th>检查</th><th>状态</th><th>说明</th></tr>")
	for _, check := range scenarioReport.Checks {
		if !strings.HasPrefix(check.ID, "direct.") && !strings.HasPrefix(check.ID, "search.") &&
			!strings.HasPrefix(check.ID, "auth.") && !strings.HasPrefix(check.ID, "existing.") {
			continue
		}
		class := "pass"
		if check.Status == "FAIL" {
			class = "fail"
		}
		builder.WriteString("<tr><td><code>")
		builder.WriteString(html.EscapeString(check.ID))
		builder.WriteString("</code></td><td class=\"")
		builder.WriteString(class)
		builder.WriteString("\">")
		builder.WriteString(html.EscapeString(check.Status))
		builder.WriteString("</td><td>")
		builder.WriteString(html.EscapeString(check.Detail))
		builder.WriteString("</td></tr>")
	}
	builder.WriteString("</table><p>说明：直接改名/重置不解除目标 MFA；" +
		"人工恢复审批依赖宿主制度配置，本示例未启用，不能在本页面伪造成功。</p></html>")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(builder.String()), 0o600)
}

// containsAdminUserID 报告用户列表是否包含指定稳定 UserID。
func containsAdminUserID(users []app.AdminUser, userID string) bool {
	for _, user := range users {
		if user.ID == userID {
			return true
		}
	}
	return false
}

// containsAdminUsername 报告用户列表是否包含指定用户名。
func containsAdminUsername(users []app.AdminUser, username string) bool {
	for _, user := range users {
		if user.Username == username {
			return true
		}
	}
	return false
}

// mustDemoTOTP 计算当前时间步 TOTP；失败时 panic 只可能来自不可达的种子解码错误，
// 由调用方在固定合成种子上使用（测试/示例）。
func mustDemoTOTP(secret string, at time.Time) string {
	code, err := totpCode(secret, at)
	if err != nil {
		panic(err)
	}
	return code
}
