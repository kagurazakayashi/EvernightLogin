package login_test

// 步骤 68 真实服务集成测试：临时 SQLite + 真实 account/profile/onboarding/group/
// userbatch；管理会话为受控 kind=management；授权器使用测试白名单（生产由宿主真实
// authz 注入），不联网、不监听端口。

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	accountsqlite "github.com/kagurazakayashi/EvernightLogin/internal/account/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	credentialsqlite "github.com/kagurazakayashi/EvernightLogin/internal/credential/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	groupsqlite "github.com/kagurazakayashi/EvernightLogin/internal/group/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/onboarding"
	onboardingsqlite "github.com/kagurazakayashi/EvernightLogin/internal/onboarding/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/profile"
	profilesqlite "github.com/kagurazakayashi/EvernightLogin/internal/profile/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/registration"
	registrationsqlite "github.com/kagurazakayashi/EvernightLogin/internal/registration/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	"github.com/kagurazakayashi/EvernightLogin/internal/uiadminadapter"
	"github.com/kagurazakayashi/EvernightLogin/internal/userbatch"
	userbatchsqlite "github.com/kagurazakayashi/EvernightLogin/internal/userbatch/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// allowAllAdmin 是管理服务的测试授权器：允许所有可信 Caller（真实数据范围由宿主
// authz 实现；本测试不把该替身当作生产授权）。
type allowAllAdmin struct{}

func (allowAllAdmin) Authorize(context.Context, account.Caller, account.Action) error {
	return nil
}

func (allowAllAdmin) AuthorizeGroup(context.Context, group.Caller, group.Action, string) error {
	return nil
}

// batchSensitive 是 userbatch 敏感策略测试替身（真实用户批量服务已由步骤 61 测试）。
type batchSensitive struct{}

func (batchSensitive) Authorize(context.Context, reauth.Caller,
	reauth.Request) (reauth.Result, error) {
	return reauth.Result{}, nil
}

func (batchSensitive) NotifyOutcome(context.Context, reauth.Result, reauth.Outcome) error {
	return nil
}

type fakeBatchEnqueuer struct{ nextID int }

func (f *fakeBatchEnqueuer) Enqueue(_ context.Context,
	request task.EnqueueRequest) (task.Job, error) {
	f.nextID++
	return task.Job{ID: "job_" + string(rune('0'+f.nextID)), Kind: request.Kind,
		Payload: request.Payload}, nil
}

type fakeBatchCanceller struct{}

func (fakeBatchCanceller) RequestCancel(context.Context,
	task.CancelRequest) (task.CancelResult, error) {
	return task.CancelResult{Accepted: true, State: task.StateCancelled}, nil
}

type allowAllScope struct{}

func (allowAllScope) AuthorizeUser(context.Context, account.Caller, string,
	string) (bool, error) {
	return true, nil
}

type adminIntegrationEnv struct {
	t       *testing.T
	adapter *uiadminadapter.Adapter
	account *account.Service
	profile *profile.Service
	reviews *onboarding.Service
	groups  *group.Service
	batches *userbatch.Service
	storage *storagesqlite.Store
	adminID string
}

func newAdminIntegrationEnv(t *testing.T) *adminIntegrationEnv {
	t.Helper()
	ctx := context.Background()
	storage, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(t.TempDir(), "admin-pages.db")))
	if err != nil {
		t.Fatalf("打开数据库: %v", err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	list, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := storage.Migrate(ctx, list); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	now := time.Date(2026, 7, 8, 9, 10, 11, 0, time.UTC)
	nowFunc := func() time.Time { return now }
	auditStore, err := auditsqlite.New(storage)
	if err != nil {
		t.Fatalf("审计存储: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{Now: nowFunc,
		Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	accountStore, err := accountsqlite.New(storage)
	if err != nil {
		t.Fatalf("账户存储: %v", err)
	}
	accountService, err := account.New(account.Options{Store: accountStore, Audit: recorder,
		Authorizer: allowAllAdmin{}, Now: nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("账户服务: %v", err)
	}
	profileStore, err := profilesqlite.New(storage)
	if err != nil {
		t.Fatalf("资料存储: %v", err)
	}
	profileService, err := profile.New(profile.Options{Store: profileStore, Audit: recorder,
		Authorizer: profile.AuthorizerFunc(func(context.Context, profile.Caller,
			profile.UserProfile, bool) error {
			return nil
		}), Now: nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("资料服务: %v", err)
	}
	credentialStore, err := credentialsqlite.New(storage)
	if err != nil {
		t.Fatalf("凭证存储: %v", err)
	}
	keyring, err := secrets.GenerateKeyring("k1", now)
	if err != nil {
		t.Fatalf("密钥环: %v", err)
	}
	credentialService, err := credential.New(credentialStore, credential.Options{
		Keyring: keyring, Now: nowFunc})
	if err != nil {
		t.Fatalf("凭证服务: %v", err)
	}
	registrationStore, err := registrationsqlite.New(storage)
	if err != nil {
		t.Fatalf("注册存储: %v", err)
	}
	registrationService, err := registration.New(registration.Options{
		Store: registrationStore, Audit: recorder, Credentials: credentialService,
		Enabled: true, RequireReview: true, Now: nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("注册服务: %v", err)
	}
	onboardingStore, err := onboardingsqlite.New(storage)
	if err != nil {
		t.Fatalf("入域存储: %v", err)
	}
	onboardingService, err := onboarding.New(onboarding.Options{Store: onboardingStore,
		Audit: recorder, Guard: allowGuard{}, Credentials: credentialService,
		ManagementAuth: onboarding.ManagementAuthorizerFunc(func(context.Context,
			onboarding.Caller) error {
			return nil
		}),
		PasswordPolicy: authnDefaultPolicy(), HashParams: authnTestParams(),
		Now: nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("入域服务: %v", err)
	}
	groupStore, err := groupsqlite.New(storage)
	if err != nil {
		t.Fatalf("用户组存储: %v", err)
	}
	groupService, err := group.New(group.Options{Store: groupStore, Audit: recorder,
		Authorizer: allowGroupAuthorizer{}, Transfers: allowGuard{},
		AllowLegacyWithoutSensitive: true,
		Now:                         nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("用户组服务: %v", err)
	}
	batchStore, err := userbatchsqlite.New(storage)
	if err != nil {
		t.Fatalf("批量存储: %v", err)
	}
	outputDir := t.TempDir()
	batchService, err := userbatch.New(userbatch.Options{Store: batchStore, Audit: recorder,
		Authorizer: allowBatchAuthorizer{}, Sensitive: batchSensitive{},
		Accounts:  accountService,
		DataScope: allowAllScope{}, Enqueuer: &fakeBatchEnqueuer{},
		Canceller: fakeBatchCanceller{}, OutputDir: outputDir, BatchSize: 2,
		Now: nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("批量服务: %v", err)
	}
	adapter, err := uiadminadapter.New(uiadminadapter.Options{Account: accountService,
		Profile: profileService, Reviews: onboardingService, Groups: groupService,
		Batches: batchService, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("管理适配器: %v", err)
	}
	// 创建管理员与普通用户（active）。
	admin, err := accountService.CreateUser(ctx, systemAccountCaller(t),
		account.CreateRequest{Username: "admin1", Nickname: "Admin"})
	if err != nil {
		t.Fatalf("创建管理员: %v", err)
	}
	for _, name := range []string{"user1", "user2", "user3"} {
		if _, err := accountService.CreateUser(ctx, systemAccountCaller(t),
			account.CreateRequest{Username: name, Nickname: name}); err != nil {
			t.Fatalf("创建用户 %s: %v", name, err)
		}
	}
	// 通过真实注册服务创建 pending 用户（RequireReview）。
	if _, err := registrationService.Register(ctx, registration.RegisterRequest{
		Username: "pending1", Password: "V7#qZ!mR2@tL9$xP", RequestID: "req_pending"}); err != nil {
		t.Fatalf("创建待审核用户: %v", err)
	}
	// 种子 root（受保护对象）。
	nowMs := now.UTC().UnixMilli()
	if _, err := storage.DB().ExecContext(ctx, `INSERT INTO users(id,username,
username_normalized,nickname,biography,language,timezone,status,is_root,security_version,
row_version,created_at_ms,updated_at_ms) VALUES('usr_00000000000000000000000000000001',
'root','root','Root','','','','active',1,1,1,?,?)`, nowMs, nowMs); err != nil {
		t.Fatalf("种子 root: %v", err)
	}
	return &adminIntegrationEnv{t: t, adapter: adapter, account: accountService,
		profile: profileService, reviews: onboardingService, groups: groupService,
		batches: batchService,
		storage: storage, adminID: admin.ID}
}

// 便捷包装：账户/资料服务未在测试中直接使用，避免未用字段报错。
func authnDefaultPolicy() authn.PasswordPolicy { return authn.DefaultPasswordPolicy() }
func authnTestParams() authn.Params {
	return authn.Params{MemoryKiB: 8192, Iterations: 1, Parallelism: 1,
		SaltLength: 16, KeyLength: 32}
}

// systemAccountCaller 构造测试种子系统 Caller。
func systemAccountCaller(t *testing.T) account.Caller {
	t.Helper()
	caller, err := account.SystemCaller("test-seed")
	if err != nil {
		t.Fatalf("系统 Caller: %v", err)
	}
	return caller
}

// TestAdminIntegrationUsersAndRoot 覆盖真实账户分页/筛选与 root 保护。
func TestAdminIntegrationUsersAndRoot(t *testing.T) {
	env := newAdminIntegrationEnv(t)
	page, err := env.adapter.ListUsers(context.Background(), env.adminID,
		login.UIAdminUserQuery{Limit: 20})
	if err != nil {
		t.Fatalf("列出用户: %v", err)
	}
	if len(page.Users) < 4 || page.HasMore {
		t.Fatalf("用户分页异常: %d hasMore=%v", len(page.Users), page.HasMore)
	}
	activePage, err := env.adapter.ListUsers(context.Background(), env.adminID,
		login.UIAdminUserQuery{Status: "active", Limit: 2})
	if err != nil || len(activePage.Users) > 2 || !activePage.HasMore {
		t.Fatalf("状态筛选/分页上限异常: %+v err=%v", activePage, err)
	}
	// 分页与筛选一致：第二页不与第一页重复，且仍受状态筛选约束。
	secondPage, err := env.adapter.ListUsers(context.Background(), env.adminID,
		login.UIAdminUserQuery{Status: "active", Limit: 2, Offset: 2})
	if err != nil {
		t.Fatalf("第二页: %v", err)
	}
	seen := map[string]bool{}
	for _, user := range activePage.Users {
		seen[user.UserID] = true
	}
	for _, user := range secondPage.Users {
		if seen[user.UserID] {
			t.Fatalf("分页重复用户: %s", user.UserID)
		}
		if user.Status != "active" {
			t.Fatalf("分页筛选不一致: %s status=%s", user.UserID, user.Status)
		}
	}
	// root：预览可见受保护标记，完成删除必须被服务端拒绝。
	rootPreview, err := env.adapter.PreviewDeletion(context.Background(), env.adminID,
		"usr_00000000000000000000000000000001")
	if err != nil || !rootPreview.IsRoot {
		t.Fatalf("root 预览 = %+v err=%v", rootPreview, err)
	}
	if _, err := env.adapter.CompleteDeletion(context.Background(), env.adminID,
		"usr_00000000000000000000000000000001", rootPreview.RowVersion, "req_root"); err == nil {
		t.Fatal("root 完成删除应被服务端拒绝")
	}
}

// TestAdminIntegrationReviewsRepeat 覆盖真实审核状态机与重复审核拒绝。
func TestAdminIntegrationReviewsRepeat(t *testing.T) {
	env := newAdminIntegrationEnv(t)
	list, err := env.adapter.ListReviews(context.Background(), env.adminID, 20, 0)
	if err != nil || len(list.Reviews) == 0 {
		t.Fatalf("待审核列表: %+v err=%v", list, err)
	}
	userID := list.Reviews[0].UserID
	decision, err := env.adapter.DecideReview(context.Background(), env.adminID, userID,
		true, "资料核验通过", "", nil, "req_review")
	if err != nil {
		t.Fatalf("审核批准: %v", err)
	}
	if decision.Review.Status != "active" {
		t.Fatalf("批准后状态 = %q", decision.Review.Status)
	}
	if _, err := env.adapter.DecideReview(context.Background(), env.adminID, userID,
		true, "重复批准", "", nil, "req_review2"); err == nil {
		t.Fatal("重复审核应被拒绝")
	}
}

// TestAdminIntegrationGroupsAndMembers 覆盖真实用户组与原子成员变更。
func TestAdminIntegrationGroupsAndMembers(t *testing.T) {
	env := newAdminIntegrationEnv(t)
	groupRecord, err := env.adapter.CreateGroup(context.Background(), env.adminID, "system",
		"ops", "运维组", "desc", "req_group")
	if err != nil {
		t.Fatalf("创建用户组: %v", err)
	}
	users, err := env.adapter.ListUsers(context.Background(), env.adminID,
		login.UIAdminUserQuery{Limit: 20})
	if err != nil {
		t.Fatalf("用户列表: %v", err)
	}
	var ids []string
	for _, user := range users.Users {
		if len(ids) < 2 && user.Status == "active" &&
			user.UserID != "usr_00000000000000000000000000000001" && user.UserID != env.adminID {
			ids = append(ids, user.UserID)
		}
	}
	if len(ids) < 2 {
		t.Fatalf("可用用户不足: %v", ids)
	}
	result, err := env.adapter.AddMembers(context.Background(), env.adminID, groupRecord.ID,
		ids, "req_add")
	if err != nil || result.Added != 2 {
		t.Fatalf("加入成员 = %+v err=%v", result, err)
	}
	again, err := env.adapter.AddMembers(context.Background(), env.adminID, groupRecord.ID,
		ids, "req_add2")
	if err != nil || again.Skipped != 2 || again.Added != 0 {
		t.Fatalf("重复加入语义 = %+v err=%v", again, err)
	}
	members, err := env.adapter.ListMembers(context.Background(), env.adminID,
		groupRecord.ID, 20, 0)
	if err != nil || len(members.Members) != 2 {
		t.Fatalf("成员列表 = %+v err=%v", members, err)
	}
	removed, err := env.adapter.RemoveMembers(context.Background(), env.adminID,
		groupRecord.ID, ids[:1], "req_remove")
	if err != nil || removed.Removed != 1 {
		t.Fatalf("移除成员 = %+v err=%v", removed, err)
	}
	// 超过 12 名成员由适配器拒绝。
	tooMany := make([]string, 13)
	for index := range tooMany {
		tooMany[index] = ids[0]
	}
	if _, err := env.adapter.AddMembers(context.Background(), env.adminID, groupRecord.ID,
		tooMany, "req_many"); err == nil {
		t.Fatal("超过 12 名成员应被拒绝")
	}
}

// TestAdminIntegrationBatchPartialFailure 覆盖真实 userbatch 预检查/任务/部分失败/
// 逐项结果/报告下载与跨用户任务不可见。
func TestAdminIntegrationBatchPartialFailure(t *testing.T) {
	env := newAdminIntegrationEnv(t)
	content := []byte("username,nickname,biography,language,timezone\nbatchok,Nick,,zh-CN,Asia/Shanghai\nbad username!,Bad,,zh-CN,Asia/Shanghai\n")
	report, err := env.adapter.PrecheckImport(context.Background(), env.adminID, content)
	if err != nil || report.TotalRows != 2 {
		t.Fatalf("预检查 = %+v err=%v", report, err)
	}
	start, err := env.adapter.StartImport(context.Background(), env.adminID, content,
		"import-key-123", "req_batch")
	if err != nil || start.JobID == "" {
		t.Fatalf("创建导入任务 = %+v err=%v", start, err)
	}
	payload, _ := json.Marshal(map[string]string{"job_id": start.JobID})
	if err := env.batches.Handler(context.Background(), task.Job{Payload: payload}); err != nil {
		t.Fatalf("执行导入: %v", err)
	}
	job, err := env.adapter.GetJob(context.Background(), env.adminID, start.JobID)
	if err != nil || job.State != "partial" || job.CreatedCount != 1 || job.FailedCount != 1 {
		t.Fatalf("任务状态 = %+v err=%v", job, err)
	}
	rows, _, err := env.adapter.ListRows(context.Background(), env.adminID, start.JobID, 50, 0)
	if err != nil || len(rows) < 2 {
		t.Fatalf("逐行结果 = %+v err=%v", rows, err)
	}
	reportCSV, truncated, err := env.adapter.ReportCSV(context.Background(), env.adminID,
		start.JobID)
	if err != nil || truncated || !strings.Contains(string(reportCSV), "report_truncated") {
		t.Fatalf("报告 = %q truncated=%v err=%v", reportCSV, truncated, err)
	}
	// 其他普通用户不能读取他人任务。
	otherPage, err := env.adapter.ListUsers(context.Background(), env.adminID,
		login.UIAdminUserQuery{Limit: 20})
	if err != nil {
		t.Fatalf("用户列表: %v", err)
	}
	var otherUserID string
	for _, user := range otherPage.Users {
		if user.UserID != env.adminID {
			otherUserID = user.UserID
			break
		}
	}
	if _, err := env.adapter.GetJob(context.Background(), otherUserID, start.JobID); err == nil {
		t.Fatal("跨用户读取任务应被拒绝")
	}
}

// allowGroupAuthorizer 是用户组服务的测试授权器（生产由宿主 authz 注入）。
type allowGroupAuthorizer struct{}

func (allowGroupAuthorizer) Authorize(context.Context, group.Caller, group.Action,
	string) error {
	return nil
}

func (allowGroupAuthorizer) ManageableScopes(context.Context,
	group.Caller) (bool, []string, error) {
	return true, nil, nil
}

// allowBatchAuthorizer 是 userbatch 服务的测试授权器（生产由宿主 authz 注入）。
type allowBatchAuthorizer struct{}

func (allowBatchAuthorizer) Authorize(context.Context, account.Caller,
	userbatch.Action, string) error {
	return nil
}

// TestAdminIntegrationAuthorizationFailClosed 验证宿主授权器拒绝时适配器/页面
// fail-closed（数据范围/跨应用由宿主 authz 判定，本测试注入拒绝授权器）。
func TestAdminIntegrationAuthorizationFailClosed(t *testing.T) {
	env := newAdminIntegrationEnv(t)
	denied, err := uiadminadapter.New(uiadminadapter.Options{Account: env.account,
		Profile: env.profile, Reviews: env.reviews, Groups: env.groups,
		Batches: env.batches, Authorize: func(context.Context, string, string) error {
			return errors.New("denied-by-host-authz")
		}})
	if err != nil {
		t.Fatalf("拒绝适配器: %v", err)
	}
	_, listErr := denied.ListUsers(context.Background(), env.adminID,
		login.UIAdminUserQuery{Limit: 20})
	var publicErr *login.UIAdminError
	if !errors.As(listErr, &publicErr) || publicErr.Code != "ACCESS_DENIED" {
		t.Fatalf("授权拒绝应为 ACCESS_DENIED: %v", listErr)
	}
	// 跨应用（应用范围）尝试：不存在/不可管理的应用范围必须被服务端拒绝。
	if _, err := env.adapter.CreateGroup(context.Background(), env.adminID,
		"app_1234567890abcdef", "ops", "Ops", "", "req_cross"); err == nil {
		t.Fatal("跨应用创建用户组应被拒绝")
	}
}
