package login_test

// 步骤 91 验收测试环境：临时 SQLite（执行真实迁移）+ 真实领域服务
// （account/profile/credential/delegation/role/group/authz/session/registration/
// onboarding/emailchange/manualrecovery）。
//
// 边界说明（与步骤 91 的"不得用 mock 冒充真实服务"要求一致）：
//   - 账户、资料、会话、角色、用户组、权限判定、入驻/邀请、邮箱变更、人工恢复的
//     业务逻辑、存储与审计全部使用生产实现；
//   - 仅注入生产契约中本就由宿主提供的扩展点：领域 Authorizer（宿主权限引擎）、
//     邮件发送（本测试用内存捕获，禁止真实外发）、人工恢复的工作人员授权/目标读取/
//     受控执行器/敏感策略执行器，以及 session 签发所需的真实结构体入参。
//   - 本环境不打开 database/login.db、不监听端口、不访问网络、不真实外发邮件。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	accountsqlite "github.com/kagurazakayashi/EvernightLogin/internal/account/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	authzsqlite "github.com/kagurazakayashi/EvernightLogin/internal/authz/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	credentialsqlite "github.com/kagurazakayashi/EvernightLogin/internal/credential/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	delegationsqlite "github.com/kagurazakayashi/EvernightLogin/internal/delegation/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/emailchange"
	emailchangesqlite "github.com/kagurazakayashi/EvernightLogin/internal/emailchange/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	groupsqlite "github.com/kagurazakayashi/EvernightLogin/internal/group/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/manualrecovery"
	manualrecoverysqlite "github.com/kagurazakayashi/EvernightLogin/internal/manualrecovery/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/onboarding"
	onboardingsqlite "github.com/kagurazakayashi/EvernightLogin/internal/onboarding/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/profile"
	profilesqlite "github.com/kagurazakayashi/EvernightLogin/internal/profile/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/registration"
	registrationsqlite "github.com/kagurazakayashi/EvernightLogin/internal/registration/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
	rolesqlite "github.com/kagurazakayashi/EvernightLogin/internal/role/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	sessionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/session/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// step91AcceptanceTime 是固定的合成起点时间（不依赖真实时钟，避免测试随时间失效）。
var step91AcceptanceTime = time.Date(2026, 11, 20, 4, 0, 0, 0, time.UTC)

// step91LocalAdmin 是受信本地管理员标识（用于账户初始化/系统种子通道）。
const step91LocalAdmin = "step91-local-admin"

// step91UserID/step91AppID 生成符合生产格式的稳定 ID（usr_/app_ + 32 位十六进制）。
func step91UserID(n int) string { return fmt.Sprintf("usr_%032x", n) }
func step91AppID(n int) string  { return fmt.Sprintf("app_%032x", n) }

// step91Env 汇集本步验收使用的真实服务与合成数据。
type step91Env struct {
	t       *testing.T
	ctx     context.Context
	storage *storagesqlite.Store
	audit   *audit.Recorder
	now     time.Time

	accounts     *account.Service
	profiles     *profile.Service
	credentials  *credential.Service
	delegations  *delegation.Service
	roles        *role.Service
	groups       *group.Service
	access       *authz.Service
	sessions     *session.Service
	registration *registration.Service
	onboarding   *onboarding.Service
	emailchange  *emailchange.Service
	recovery     *manualrecovery.Service

	mail     *step91Mail
	staff    *step91Staff
	targets  *step91Targets
	executor *step91Executor
	reauth   *step91Reauth
	notifier *step91Notifier

	appA, appB string

	adminA, adminB                         string
	user1, user2, user3, userNoApp         string
	support, approver, executorUser        string
	target, highPriv, root, disabledTarget string

	roleAReader, roleAWriter, roleBReader, roleSystem string
	permARead, permAWrite, permBRead, permSysRead     string
	groupA                                            string
}

// nowFunc 返回读取当前可推进时钟的函数，供服务做时间线控制。
func (e *step91Env) nowFunc() func() time.Time { return func() time.Time { return e.now } }

// newStep91Env 构造隔离验收环境并写入合成数据。
func newStep91Env(t *testing.T) *step91Env {
	t.Helper()
	ctx := context.Background()
	storage, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(testutil.TempDir(t), "step91-acceptance.db")))
	if err != nil {
		t.Fatalf("打开临时数据库: %v", err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	migrationList, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := storage.Migrate(ctx, migrationList); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	env := &step91Env{
		t: t, ctx: ctx, storage: storage, now: step91AcceptanceTime,
		appA: step91AppID(1), appB: step91AppID(2),
		adminA: step91UserID(1), adminB: step91UserID(2),
		user1: step91UserID(3), user2: step91UserID(4),
		user3: step91UserID(5), userNoApp: step91UserID(6),
		support: step91UserID(7), approver: step91UserID(8),
		executorUser: step91UserID(9), target: step91UserID(10),
		highPriv: step91UserID(11), root: step91UserID(12),
		disabledTarget: step91UserID(13),
		roleAReader:    fmt.Sprintf("role_%032x", 21),
		roleAWriter:    fmt.Sprintf("role_%032x", 22),
		roleBReader:    fmt.Sprintf("role_%032x", 23),
		roleSystem:     fmt.Sprintf("role_%032x", 24),
		permARead:      fmt.Sprintf("perm_%032x", 11),
		permAWrite:     fmt.Sprintf("perm_%032x", 12),
		permBRead:      fmt.Sprintf("perm_%032x", 13),
		permSysRead:    fmt.Sprintf("perm_%032x", 14),
		groupA:         fmt.Sprintf("grp_%032x", 31),
		mail:           &step91Mail{},
		staff:          &step91Staff{},
		executor:       &step91Executor{},
		reauth:         &step91Reauth{},
		notifier:       &step91Notifier{},
	}
	nowFunc := env.nowFunc()

	auditStore, err := auditsqlite.New(storage)
	if err != nil {
		t.Fatalf("审计存储: %v", err)
	}
	env.audit, err = audit.New(auditStore, audit.Options{Now: nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("安全审计: %v", err)
	}

	accountStore, err := accountsqlite.New(storage)
	if err != nil {
		t.Fatalf("账户存储: %v", err)
	}
	bootstrapAuthorizer, err := account.NewLocalBootstrapAuthorizer([]string{step91LocalAdmin})
	if err != nil {
		t.Fatalf("账户本地授权器: %v", err)
	}
	env.accounts, err = account.New(account.Options{Store: accountStore, Audit: env.audit,
		Authorizer: bootstrapAuthorizer, Now: nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("账户服务: %v", err)
	}

	profileStore, err := profilesqlite.New(storage)
	if err != nil {
		t.Fatalf("资料存储: %v", err)
	}
	env.profiles, err = profile.New(profile.Options{Store: profileStore, Audit: env.audit,
		ReauthVerifier: profile.ReauthVerifierFunc(func(context.Context, profile.Caller, string) error {
			return nil
		}), AllowLegacyWithoutSensitive: true, Now: nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("资料服务: %v", err)
	}

	keyring, err := secrets.GenerateKeyring("k1", env.now)
	if err != nil {
		t.Fatalf("密钥环: %v", err)
	}
	credentialStore, err := credentialsqlite.New(storage)
	if err != nil {
		t.Fatalf("凭证存储: %v", err)
	}
	env.credentials, err = credential.New(credentialStore, credential.Options{
		Keyring: keyring, Now: nowFunc})
	if err != nil {
		t.Fatalf("凭证服务: %v", err)
	}

	delegationStore, err := delegationsqlite.New(storage)
	if err != nil {
		t.Fatalf("委派存储: %v", err)
	}
	env.delegations, err = delegation.New(delegation.Options{Store: delegationStore,
		Audit: env.audit, Now: nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("委派服务: %v", err)
	}

	roleStore, err := rolesqlite.New(storage)
	if err != nil {
		t.Fatalf("角色存储: %v", err)
	}
	roleAuthorizer, err := role.NewStaticAuthorizer(role.AuthorizerOptions{
		LocalAdminIDs: []string{step91LocalAdmin},
		ApplicationAdmins: map[string][]string{
			env.appA: {env.adminA}, env.appB: {env.adminB},
		}})
	if err != nil {
		t.Fatalf("角色授权器: %v", err)
	}
	env.roles, err = role.New(role.Options{Store: roleStore, Audit: env.audit,
		Authorizer: roleAuthorizer, Transfers: env.delegations,
		AllowLegacyWithoutSensitive: true, Now: nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("角色服务: %v", err)
	}

	groupStore, err := groupsqlite.New(storage)
	if err != nil {
		t.Fatalf("用户组存储: %v", err)
	}
	groupAuthorizer, err := group.NewStaticAuthorizer(group.AuthorizerOptions{
		LocalAdminIDs: []string{step91LocalAdmin},
		ApplicationAdmins: map[string][]string{
			env.appA: {env.adminA}, env.appB: {env.adminB},
		}})
	if err != nil {
		t.Fatalf("用户组授权器: %v", err)
	}
	env.groups, err = group.New(group.Options{Store: groupStore, Audit: env.audit,
		Authorizer: groupAuthorizer, Transfers: env.delegations,
		AllowLegacyWithoutSensitive: true, Now: nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("用户组服务: %v", err)
	}

	authzStore, err := authzsqlite.New(storage)
	if err != nil {
		t.Fatalf("授权存储: %v", err)
	}
	queryAuthorizer, err := authz.NewStaticAuthorizer(authz.AuthorizerOptions{
		LocalAdminIDs: []string{step91LocalAdmin},
		SystemIDs:     []string{"step91-target-guard"},
		ApplicationAdmins: map[string][]string{
			env.appA: {env.adminA}, env.appB: {env.adminB},
		}})
	if err != nil {
		t.Fatalf("授权查询器: %v", err)
	}
	env.access, err = authz.New(authz.Options{Store: authzStore, Authorizer: queryAuthorizer,
		Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("授权引擎: %v", err)
	}

	sessionStore, err := sessionsqlite.New(storage)
	if err != nil {
		t.Fatalf("会话存储: %v", err)
	}
	env.sessions, err = session.New(sessionStore, session.Options{Store: sessionStore,
		Audit: env.audit, Keyring: keyring, AllowLegacyWithoutSensitive: true,
		Now: nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("会话服务: %v", err)
	}

	registrationStore, err := registrationsqlite.New(storage)
	if err != nil {
		t.Fatalf("注册存储: %v", err)
	}
	env.registration, err = registration.New(registration.Options{Store: registrationStore,
		Audit: env.audit, Credentials: env.credentials, Enabled: true, RequireReview: true,
		Now: nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("注册服务: %v", err)
	}

	onboardingStore, err := onboardingsqlite.New(storage)
	if err != nil {
		t.Fatalf("入驻存储: %v", err)
	}
	env.onboarding, err = onboarding.New(onboarding.Options{Store: onboardingStore,
		Audit: env.audit, Guard: env.delegations, Credentials: env.credentials,
		Mailer: env.mail, AcceptanceURLBase: "https://login.example.test/accept",
		SupportURL: "https://login.example.test/support", AppName: "EvernightLogin",
		InvitationTTL: time.Hour,
		InviteAuthorizer: onboarding.InviteAuthorizerFunc(func(_ context.Context,
			caller onboarding.Caller, _ onboarding.CreateRequest) error {
			if caller.IsUser() && caller.Actor().ID == env.adminA {
				return nil
			}
			return onboarding.ErrAccessDenied
		}),
		ManagementAuth: onboarding.ManagementAuthorizerFunc(func(_ context.Context,
			caller onboarding.Caller) error {
			if caller.IsUser() && caller.Actor().ID == env.adminA {
				return nil
			}
			return onboarding.ErrManagementAuthRequired
		}),
		Now: nowFunc})
	if err != nil {
		t.Fatalf("入驻服务: %v", err)
	}

	emailchangeStore, err := emailchangesqlite.New(storage)
	if err != nil {
		t.Fatalf("邮箱变更存储: %v", err)
	}
	env.emailchange, err = emailchange.New(emailchange.Options{Store: emailchangeStore,
		Audit: env.audit, Credentials: env.credentials,
		ReauthVerifier: emailchange.ReauthVerifierFunc(func(context.Context,
			emailchange.Caller, string) error {
			return nil
		}),
		AllowLegacyWithoutSensitive: true, Mailer: env.mail,
		VerificationURLBase: "https://login.example.test/email-verify",
		SupportURL:          "https://login.example.test/support",
		AppName:             "EvernightLogin", TTL: time.Hour, Now: nowFunc})
	if err != nil {
		t.Fatalf("邮箱变更服务: %v", err)
	}

	if err := env.seedData(); err != nil {
		t.Fatalf("写入合成数据: %v", err)
	}
	env.targets = &step91Targets{env: env}
	env.staff.requestStaff = map[string]bool{env.support: true}
	env.staff.approvers = map[string]bool{env.approver: true}
	env.staff.executors = map[string]bool{env.executorUser: true}
	recoveryStore, err := manualrecoverysqlite.New(storage)
	if err != nil {
		t.Fatalf("人工恢复存储: %v", err)
	}
	env.recovery, err = manualrecovery.New(manualrecovery.Options{Store: recoveryStore,
		Audit: env.audit, Reauth: env.reauth, Staff: env.staff, Targets: env.targets,
		Executor: env.executor, Notifier: env.notifier,
		Policy: manualrecovery.Policy{
			Enabled:                    true,
			VerificationBases:          []manualrecovery.VerificationBasis{manualrecovery.BasisInPersonIdentityDocument},
			DeliveryChannels:           []manualrecovery.DeliveryChannel{manualrecovery.DeliveryVerifiedEmail},
			WaitPeriod:                 time.Hour,
			ApprovalTTL:                3 * time.Hour,
			RequestTTL:                 24 * time.Hour,
			RequireIndependentApproval: true,
		},
		Now: nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("人工恢复服务: %v", err)
	}
	return env
}

// seedData 写入多应用、多组角色、普通用户、客服、审批人、执行人、root 与成员状态的
// 合成数据（不含真实用户或秘密）。
func (e *step91Env) seedData() error {
	ctx := e.ctx
	nowMs := e.now.UnixMilli()
	db := e.storage.DB()
	for _, appID := range []string{e.appA, e.appB} {
		name := "验收应用A"
		if appID == e.appB {
			name = "验收应用B"
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO applications(
id,name,description,status,client_type,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,1,?,?)`, appID, name, "步骤91合成数据", "active", "public", nowMs, nowMs); err != nil {
			return fmt.Errorf("应用 %s: %w", appID, err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO scopes(id,kind,app_id)
VALUES(?,?,?)`, appID, "application", appID); err != nil {
			return fmt.Errorf("scope %s: %w", appID, err)
		}
	}
	// 账户：直接写入合成用户行（包含唯一 root）；真实账户服务的行为在生命周期用例中
	// 单独通过 CreateUser 创建并使用。
	users := []struct {
		id       string
		username string
		nickname string
	}{
		{e.adminA, "step91-admin-a", "应用A管理员"},
		{e.adminB, "step91-admin-b", "应用B管理员"},
		{e.user1, "step91-user1", "普通用户1"},
		{e.user2, "step91-user2", "普通用户2"},
		{e.user3, "step91-user3", "停用成员用户"},
		{e.userNoApp, "step91-user-noapp", "无应用成员用户"},
		{e.support, "step91-support-staff", "客服"},
		{e.approver, "step91-approver", "独立审批人"},
		{e.executorUser, "step91-executor", "恢复执行人"},
		{e.target, "step91-target", "恢复目标"},
		{e.highPriv, "step91-high-priv", "高权限目标"},
		{e.disabledTarget, "step91-disabled-target", "停用目标"},
	}
	for _, user := range users {
		if _, err := db.ExecContext(ctx, `INSERT INTO users(id,username,username_normalized,
nickname,biography,avatar_ref,language,timezone,status,is_root,security_version,row_version,
created_at_ms,updated_at_ms) VALUES(?,?,?,?,'',NULL,'zh-CN','Asia/Shanghai','active',0,1,1,?,?)`,
			user.id, user.username, user.username, user.nickname, nowMs, nowMs); err != nil {
			return fmt.Errorf("合成用户 %s: %w", user.username, err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO users(id,username,username_normalized,
nickname,biography,avatar_ref,language,timezone,status,is_root,security_version,row_version,
created_at_ms,updated_at_ms) VALUES(?,?,'step91-root','','',NULL,'zh-CN',
'Asia/Shanghai','active',1,1,1,?,?)`, e.root, "step91-root", nowMs, nowMs); err != nil {
		return fmt.Errorf("合成 root: %w", err)
	}
	// 邮箱：仅恢复目标与高权限目标有已验证邮箱（交付指纹来源）。
	for _, userID := range []string{e.target, e.highPriv} {
		if _, err := db.ExecContext(ctx, `INSERT INTO user_emails(email_normalized,user_id,
email,verified_at_ms,created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?)`,
			userID+"@example.test", userID, userID+"@example.test", nowMs, nowMs, nowMs); err != nil {
			return fmt.Errorf("邮箱 %s: %w", userID, err)
		}
	}
	// 权限：应用 A/B 同名权限分别定义（跨应用同名不关联），系统范围一个高权限判定键。
	permissions := []struct {
		id, scopeID, key string
		rootOnly         int
	}{
		{e.permARead, e.appA, "app.read", 0},
		{e.permAWrite, e.appA, "app.write", 0},
		{e.permBRead, e.appB, "app.read", 0},
		{e.permSysRead, "system", "users.read", 0},
	}
	for _, permission := range permissions {
		if _, err := db.ExecContext(ctx, `INSERT INTO permissions(id,scope_id,
permission_key,name,description,limits_text,is_builtin,root_only,enabled,created_at_ms,updated_at_ms)
VALUES(?,?,?,?, '', '', 0,?,1,?,?)`, permission.id, permission.scopeID, permission.key,
			permission.key, permission.rootOnly, nowMs, nowMs); err != nil {
			return fmt.Errorf("权限 %s: %w", permission.key, err)
		}
	}
	// 角色与角色权限。
	roles := []struct{ id, scopeID, key string }{
		{e.roleAReader, e.appA, "app_a_reader"},
		{e.roleAWriter, e.appA, "app_a_writer"},
		{e.roleBReader, e.appB, "app_b_reader"},
		{e.roleSystem, "system", "system_reader"},
	}
	for _, item := range roles {
		if _, err := db.ExecContext(ctx, `INSERT INTO roles(id,scope_id,role_key,name,
description,limits_text,is_builtin,enabled,created_at_ms,updated_at_ms)
VALUES(?,?,?,?, '', '', 0,1,?,?)`, item.id, item.scopeID, item.key, item.key,
			nowMs, nowMs); err != nil {
			return fmt.Errorf("角色 %s: %w", item.key, err)
		}
	}
	rolePermissions := [][3]string{
		{e.roleAReader, e.appA, e.permARead},
		{e.roleAWriter, e.appA, e.permARead},
		{e.roleAWriter, e.appA, e.permAWrite},
		{e.roleBReader, e.appB, e.permBRead},
		{e.roleSystem, "system", e.permSysRead},
	}
	for _, item := range rolePermissions {
		if _, err := db.ExecContext(ctx, `INSERT INTO role_permissions(role_id,permission_id,
scope_id) VALUES(?,?,?)`, item[0], item[2], item[1]); err != nil {
			return fmt.Errorf("角色权限 %s/%s: %w", item[0], item[2], err)
		}
	}
	// 应用成员：A 应用 adminA/user1/user2 有效、user3 停用；B 应用 adminB/user2 有效。
	memberships := []struct{ appID, userID, status string }{
		{e.appA, e.adminA, "active"},
		{e.appA, e.user1, "active"},
		{e.appA, e.user2, "active"},
		{e.appA, e.user3, "disabled"},
		{e.appB, e.adminB, "active"},
		{e.appB, e.user2, "active"},
	}
	for _, item := range memberships {
		if _, err := db.ExecContext(ctx, `INSERT INTO app_memberships(app_id,user_id,status,
profile_json,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'{}',1,?,?)`, item.appID, item.userID, item.status, nowMs, nowMs); err != nil {
			return fmt.Errorf("成员 %s/%s: %w", item.appID, item.userID, err)
		}
	}
	// 用户组（应用 A 作用域）与组成员、组角色（间接授权来源）。
	if _, err := db.ExecContext(ctx, `INSERT INTO user_groups(id,scope_id,group_key,name,
description,created_at_ms,updated_at_ms) VALUES(?,?,?,?, '',?,?)`,
		e.groupA, e.appA, "app_a_ops", "应用A运维组", nowMs, nowMs); err != nil {
		return fmt.Errorf("用户组: %w", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO group_members(group_id,user_id,created_at_ms)
VALUES(?,?,?)`, e.groupA, e.user1, nowMs); err != nil {
		return fmt.Errorf("组成员: %w", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO group_roles(group_id,role_id,scope_id,
data_scope_json,created_at_ms) VALUES(?,?,?,'{"v":1,"mode":"all"}',?)`,
		e.groupA, e.roleAReader, e.appA, nowMs); err != nil {
		return fmt.Errorf("组角色: %w", err)
	}
	// 直接授权：user2 应用 A 直接角色（受限数据范围），adminA 持有 app.read 以具备转授权限。
	direct := []struct{ userID, roleID, scopeID, dataScope string }{
		{e.user2, e.roleAWriter, e.appA, `{"v":1,"mode":"resources","resources":["res_step91_allowed"]}`},
		{e.adminA, e.roleAWriter, e.appA, `{"v":1,"mode":"all"}`},
		{e.user3, e.roleAReader, e.appA, `{"v":1,"mode":"all"}`},
		{e.highPriv, e.roleSystem, "system", `{"v":1,"mode":"all"}`},
	}
	for _, item := range direct {
		if _, err := db.ExecContext(ctx, `INSERT INTO user_roles(user_id,role_id,scope_id,
data_scope_json,assigned_by,created_at_ms) VALUES(?,?,?,?,?,?)`, item.userID, item.roleID,
			item.scopeID, item.dataScope, "step91-seed", nowMs); err != nil {
			return fmt.Errorf("用户角色 %s: %w", item.userID, err)
		}
	}
	// 受信通道签发委派资格：adminA 可把 app.read 转授给应用 A 内目标（不允许自我）。
	bootstrapCaller, err := delegation.LocalBootstrapCaller("step91-bootstrap")
	if err != nil {
		return fmt.Errorf("委派受信 Caller: %w", err)
	}
	if _, err := e.delegations.Grant(ctx, bootstrapCaller, delegation.GrantRequest{
		DelegatorUserID: e.adminA, ScopeID: e.appA, PermissionKey: "app.read",
		MaxDataScope: `{"v":1,"mode":"all"}`, AllowSelf: false}); err != nil {
		return fmt.Errorf("签发委派资格: %w", err)
	}
	return nil
}

// --- 邮件与人工恢复宿主扩展点的测试实现（不是生产鉴权替身） ---

// step91Mail 是本地捕获邮件发送器：不联网、不真实外发，仅保存可断言的通知内容。
type step91Mail struct {
	mu            sync.Mutex
	invitations   []onboarding.InvitationEmail
	reviews       []onboarding.ReviewEmail
	verifications []emailchange.VerificationEmail
	notices       []emailchange.SecurityNoticeEmail
}

func (m *step91Mail) SendInvitation(_ context.Context, message onboarding.InvitationEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invitations = append(m.invitations, message)
	return nil
}

func (m *step91Mail) SendReviewDecision(_ context.Context, message onboarding.ReviewEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reviews = append(m.reviews, message)
	return nil
}

func (m *step91Mail) SendVerification(_ context.Context, message emailchange.VerificationEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verifications = append(m.verifications, message)
	return nil
}

func (m *step91Mail) SendSecurityNotice(_ context.Context, message emailchange.SecurityNoticeEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.notices = append(m.notices, message)
	return nil
}

// lastInvitationURL 返回最后一条邀请的接受入口（解析失败即测试失败）。
func (m *step91Mail) lastInvitationURL(t *testing.T) *url.URL {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.invitations) == 0 {
		t.Fatal("未捕获邀请邮件")
	}
	parsed, err := url.Parse(m.invitations[len(m.invitations)-1].AcceptanceURL)
	if err != nil {
		t.Fatalf("邀请入口解析: %v", err)
	}
	return parsed
}

// lastVerificationURL 返回最后一条邮箱验证入口。
func (m *step91Mail) lastVerificationURL(t *testing.T) *url.URL {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.verifications) == 0 {
		t.Fatal("未捕获邮箱验证邮件")
	}
	parsed, err := url.Parse(m.verifications[len(m.verifications)-1].VerificationURL)
	if err != nil {
		t.Fatalf("验证入口解析: %v", err)
	}
	return parsed
}

// step91Reauth 是敏感策略执行器契约的测试实现：可注入拒绝，并记录请求参数绑定。
type step91Reauth struct {
	mu     sync.Mutex
	denied bool
	calls  int
}

func (r *step91Reauth) Authorize(_ context.Context, _ reauth.Caller, request reauth.Request) (reauth.Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.denied {
		return reauth.Result{}, reauth.ErrReauthRequired
	}
	return reauth.Result{OperationID: request.OperationID, TargetType: request.TargetType,
		TargetID: request.TargetID}, nil
}

func (r *step91Reauth) NotifyOutcome(context.Context, reauth.Result, reauth.Outcome) error {
	return nil
}

// step91Staff 按工作人员功能权限与数据范围判定人工恢复资格（宿主授权钩子实现）。
type step91Staff struct {
	requestStaff map[string]bool
	approvers    map[string]bool
	executors    map[string]bool
}

func (s *step91Staff) AuthorizeRequest(_ context.Context, staffUserID, _ string,
	_ manualrecovery.OperationType) error {
	if s.requestStaff[staffUserID] {
		return nil
	}
	return manualrecovery.ErrAccessDenied
}

func (s *step91Staff) AuthorizeApproval(_ context.Context, approverUserID, _, _ string,
	_ manualrecovery.OperationType) error {
	if s.approvers[approverUserID] {
		return nil
	}
	return manualrecovery.ErrAccessDenied
}

func (s *step91Staff) AuthorizeExecution(_ context.Context, executorUserID, _ string,
	_ manualrecovery.OperationType) error {
	if s.executors[executorUserID] {
		return nil
	}
	return manualrecovery.ErrAccessDenied
}

// step91Targets 从真实数据库与真实授权引擎读取目标状态（root/实际高权限/停用/交付指纹）。
type step91Targets struct{ env *step91Env }

func (g *step91Targets) LoadTarget(ctx context.Context, userID string) (manualrecovery.TargetState, error) {
	var status string
	var isRoot int
	var securityVersion int64
	row := g.env.storage.DB().QueryRowContext(ctx,
		`SELECT status, is_root, security_version FROM users WHERE id=?`, userID)
	if err := row.Scan(&status, &isRoot, &securityVersion); err != nil {
		return manualrecovery.TargetState{}, manualrecovery.ErrTargetUnavailable
	}
	var email string
	emailErr := g.env.storage.DB().QueryRowContext(ctx, `SELECT email FROM user_emails
WHERE user_id=? AND verified_at_ms IS NOT NULL LIMIT 1`, userID).Scan(&email)
	fingerprint := ""
	if emailErr == nil && email != "" {
		digest := sha256.Sum256([]byte(email))
		fingerprint = hex.EncodeToString(digest[:])
	}
	highPrivilege := false
	if !isRootNode(isRoot) {
		systemCaller, err := authz.SystemCaller("step91-target-guard")
		if err != nil {
			return manualrecovery.TargetState{}, manualrecovery.ErrTargetUnavailable
		}
		result, err := g.env.access.Check(ctx, systemCaller, authz.CheckRequest{
			SubjectUserID: userID, ScopeID: "system",
			Permissions: []string{"users.read"}, Mode: authz.ModeAll})
		if err != nil {
			return manualrecovery.TargetState{}, manualrecovery.ErrTargetUnavailable
		}
		highPrivilege = result.Allowed
	}
	return manualrecovery.TargetState{UserID: userID, Active: status == "active",
		IsRoot: isRoot == 1, HighPrivilege: highPrivilege, SecurityVersion: securityVersion,
		DeliveryFingerprint: fingerprint}, nil
}

func isRootNode(value int) bool { return value == 1 }

// step91Executor 是受控恢复执行器契约的测试实现：记录调用并返回不含量密的执行摘要。
type step91Executor struct {
	mu      sync.Mutex
	calls   int
	last    manualrecovery.ExecutionCommand
	outcome manualrecovery.ExecutionOutcome
	err     error
}

func (x *step91Executor) Execute(_ context.Context, command manualrecovery.ExecutionCommand) (manualrecovery.ExecutionOutcome, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.calls++
	x.last = command
	if x.err != nil {
		return manualrecovery.ExecutionOutcome{}, x.err
	}
	if x.outcome.Summary == "" {
		return manualrecovery.ExecutionOutcome{Summary: "验收执行完成", SessionsRevoked: 1,
			ResetCredentialIssued: true}, nil
	}
	return x.outcome, nil
}

func (x *step91Executor) Compensate(context.Context, manualrecovery.ExecutionCommand) error {
	return nil
}

// step91Notifier 记录恢复完成/失败通知。
type step91Notifier struct {
	mu            sync.Mutex
	notifications []manualrecovery.Notification
}

func (n *step91Notifier) Notify(_ context.Context, notification manualrecovery.Notification) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.notifications = append(n.notifications, notification)
	return nil
}

// countNotifications 返回已记录通知数量。
func (n *step91Notifier) countNotifications() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.notifications)
}

// auditCount 查询审计事件数量，用于断言成功/拒绝留痕。
func (e *step91Env) auditCount(t *testing.T, action, outcome string) int {
	t.Helper()
	var count int
	query := `SELECT COUNT(*) FROM audit_events WHERE action=?`
	args := []any{action}
	if outcome != "" {
		query += ` AND outcome=?`
		args = append(args, outcome)
	}
	if err := e.storage.DB().QueryRowContext(e.ctx, query, args...).Scan(&count); err != nil {
		t.Fatalf("查询审计事件 %s/%s: %v", action, outcome, err)
	}
	return count
}

// dbCount 执行单值计数查询（用于断言数据库真实状态）。
func (e *step91Env) dbCount(t *testing.T, query string, args ...any) int {
	t.Helper()
	var count int
	if err := e.storage.DB().QueryRowContext(e.ctx, query, args...).Scan(&count); err != nil {
		t.Fatalf("计数查询失败: %v", err)
	}
	return count
}

// assertAudit 断言指定动作与结果存在至少一条审计记录。
func (e *step91Env) assertAudit(t *testing.T, action, outcome string) {
	t.Helper()
	if got := e.auditCount(t, action, outcome); got < 1 {
		t.Fatalf("缺少审计事件 action=%s outcome=%s（实际 %d 条）", action, outcome, got)
	}
}

// mustStep91Err 断言错误匹配期望哨兵。
func mustStep91Err(t *testing.T, label string, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("%s: 期望错误 %v，实际 %v", label, target, err)
	}
}

// sessionResult 构造会话签发所需的认证结果结构（认证过程本身由步骤 29/30 的
// 真实测试覆盖；本步验证会话在账户状态/安全版本变化后的失效语义，会话服务本身
// 仍会在签发与校验时重读账户状态并交叉校验安全版本）。
func (e *step91Env) sessionResult(t *testing.T, userID string) authn.AuthenticateResult {
	t.Helper()
	user, err := e.accounts.GetUser(e.ctx, e.localAdmin(t), userID)
	if err != nil {
		t.Fatalf("读取账户: %v", err)
	}
	return authn.AuthenticateResult{
		UserID: user.ID, Username: user.Username,
		Outcome:          authn.OutcomeComplete,
		CompletedMethods: []authn.Method{authn.MethodPassword},
		CompletedAt:      e.now, SecurityVersion: user.SecurityVersion,
	}
}
