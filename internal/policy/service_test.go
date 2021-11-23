package policy_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	policysqlite "github.com/kagurazakayashi/EvernightLogin/internal/policy/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/preset"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// testRecordTime 是固定的历史时间，仅用于种子数据与审计事件时间，不参与策略
// 新鲜度判断（Evaluate 使用可注入的真实相对时钟）。
var testRecordTime = time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

const (
	rootUserID   = "usr_00000000000000000000000000000001"
	normalUserID = "usr_00000000000000000000000000000002"
)

type testEnv struct {
	t         *testing.T
	ctx       context.Context
	storage   *storagesqlite.Store
	service   *policy.Service
	store     policy.Store
	recorder  *audit.Recorder
	catalog   *policy.Catalog
	now       time.Time
	reauthErr error
}

func newTestEnv(t *testing.T, mutate func(*policy.Options)) *testEnv {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(testutil.TempDir(t), "policy-test.db")
	storage, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(path))
	if err != nil {
		t.Fatalf("打开数据库: %v", err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	migrationList, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := storage.Migrate(ctx, migrationList); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	auditStore, err := auditsqlite.New(storage)
	if err != nil {
		t.Fatalf("审计存储: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{Now: func() time.Time { return testRecordTime }})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	policyStore, err := policysqlite.New(storage)
	if err != nil {
		t.Fatalf("策略存储: %v", err)
	}
	env := &testEnv{t: t, ctx: ctx, storage: storage, store: policyStore, recorder: recorder,
		catalog: policy.DefaultCatalog(), now: time.Now().UTC()}
	options := policy.Options{
		Store: policyStore,
		Audit: recorder,
		ReauthVerifier: policy.ReauthVerifierFunc(func(ctx context.Context, caller policy.Caller, operationID string) error {
			return env.reauthErr
		}),
		Now:                func() time.Time { return env.now },
		Logger:             slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		AvailableStrengths: []policy.Strength{policy.StrengthNone, policy.StrengthPassword},
	}
	if mutate != nil {
		mutate(&options)
	}
	service, err := policy.New(options)
	if err != nil {
		t.Fatalf("敏感策略服务: %v", err)
	}
	env.service = service
	return env
}

// seedUser 插入合成用户。
func (e *testEnv) seedUser(id, username string, root bool) {
	e.t.Helper()
	now := testRecordTime.UnixMilli()
	isRoot := 0
	if root {
		isRoot = 1
	}
	if _, err := e.storage.DB().ExecContext(e.ctx, `INSERT INTO users(
id,username,username_normalized,nickname,biography,avatar_ref,language,timezone,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms
) VALUES(?,?,?,'','',NULL,'zh-CN','Asia/Shanghai','active',?,1,1,?,?)`,
		id, username, username, isRoot, now, now); err != nil {
		e.t.Fatalf("用户: %v", err)
	}
}

// seedApplication 插入应用与对应 scope，返回应用 ID。
func (e *testEnv) seedApplication(appID, name string) {
	e.t.Helper()
	now := testRecordTime.UnixMilli()
	if _, err := e.storage.DB().ExecContext(e.ctx, `INSERT INTO applications(
id,name,description,status,client_type,row_version,created_at_ms,updated_at_ms
) VALUES(?,?,'','active','confidential',1,?,?)`, appID, name, now, now); err != nil {
		e.t.Fatalf("应用: %v", err)
	}
	if _, err := e.storage.DB().ExecContext(e.ctx,
		`INSERT INTO scopes(id,kind,app_id) VALUES(?,'application',?)`, appID, appID); err != nil {
		e.t.Fatalf("应用 scope: %v", err)
	}
}

func (e *testEnv) rootCaller() policy.Caller {
	e.t.Helper()
	caller, err := policy.UserCaller(rootUserID)
	if err != nil {
		e.t.Fatalf("root 调用者: %v", err)
	}
	return caller
}

func (e *testEnv) normalCaller() policy.Caller {
	e.t.Helper()
	caller, err := policy.UserCaller(normalUserID)
	if err != nil {
		e.t.Fatalf("普通调用者: %v", err)
	}
	return caller
}

func (e *testEnv) systemCaller() policy.Caller {
	e.t.Helper()
	caller, err := policy.SystemCaller("svc-policy")
	if err != nil {
		e.t.Fatalf("系统调用者: %v", err)
	}
	return caller
}

func (e *testEnv) count(query string, args ...any) int {
	e.t.Helper()
	var value int
	if err := e.storage.DB().QueryRowContext(e.ctx, query, args...).Scan(&value); err != nil {
		e.t.Fatalf("计数: %v", err)
	}
	return value
}

func boolPtr(value bool) *bool                           { return &value }
func intPtr(value int64) *int64                          { return &value }
func strengthPtr(value policy.Strength) *policy.Strength { return &value }

// clearToNonSensitive 返回把策略完全改为非敏感的安全字段组合。
func clearToNonSensitive() policy.PolicyChange {
	return policy.PolicyChange{
		Sensitive:            boolPtr(false),
		ReauthRequired:       boolPtr(false),
		MaxAuthAgeSeconds:    intPtr(0),
		RequiredStrength:     strengthPtr(policy.StrengthNone),
		ConfirmationRequired: boolPtr(false),
	}
}

// TestDefaultsAndPartialOverride 验证默认目录、逐字段覆盖合并、版本递增、差异与审计。
func TestDefaultsAndPartialOverride(t *testing.T) {
	env := newTestEnv(t, nil)
	env.seedUser(rootUserID, "root", true)
	root := env.rootCaller()

	snapshot, err := env.service.Effective(env.ctx, root, "system")
	if err != nil {
		t.Fatalf("读取默认策略: %v", err)
	}
	if snapshot.ScopeID != "system" || snapshot.Version != 0 {
		t.Fatalf("默认快照 = %+v，期望 system/0", snapshot)
	}
	operation, found := snapshot.Lookup("password.change")
	if !found {
		t.Fatal("默认目录缺少 password.change")
	}
	wantDefault := policy.Policy{Sensitive: true, ReauthRequired: true, MaxAuthAgeSeconds: 600,
		Strength: policy.StrengthPassword, ConfirmationRequired: true, NotificationRequired: true}
	if !operation.Effective.Equal(wantDefault) {
		t.Fatalf("password.change 默认策略 = %+v，期望 %+v", operation.Effective, wantDefault)
	}
	if operation.Source != policy.SourceDefault || !operation.HasDefault || !operation.AuditRequired {
		t.Fatalf("默认来源/审计约束异常: %+v", operation)
	}
	policyChange, found := snapshot.Lookup(policy.OperationPolicyChange)
	if !found || !policyChange.RootOnly || policyChange.PermissionKey != "security.policy.manage" {
		t.Fatalf("策略变更操作定义异常: %+v", policyChange)
	}

	updated, err := env.service.Set(env.ctx, root, policy.SetRequest{
		ScopeID: "system", OperationID: "password.change",
		Change: policy.PolicyChange{
			NotificationRequired: boolPtr(false),
			MaxAuthAgeSeconds:    intPtr(900),
		},
		ExpectedVersion: 0, RequestID: "req-policy-set-1",
	})
	if err != nil {
		t.Fatalf("设置策略覆盖: %v", err)
	}
	if updated.Version != 1 {
		t.Fatalf("覆盖后版本 = %d，期望 1", updated.Version)
	}
	operation, found = updated.Lookup("password.change")
	if !found {
		t.Fatal("覆盖后缺少 password.change")
	}
	if operation.Source != policy.SourceOverride || operation.Override == nil {
		t.Fatalf("覆盖来源异常: %+v", operation)
	}
	// 逐字段合并：只改了告知与新鲜度，其他默认值保持。
	if operation.Effective.NotificationRequired || operation.Effective.MaxAuthAgeSeconds != 900 ||
		!operation.Effective.ReauthRequired || operation.Effective.Strength != policy.StrengthPassword {
		t.Fatalf("合并结果异常: %+v", operation.Effective)
	}
	if events := env.count(`SELECT COUNT(*) FROM audit_events WHERE action='policy.update' AND outcome='success'`); events != 1 {
		t.Errorf("策略修改成功审计数 = %d，期望 1", events)
	}
	diff, err := env.service.Diff(env.ctx, root, "system")
	if err != nil {
		t.Fatalf("读取差异: %v", err)
	}
	if diff.Version != 1 || len(diff.Changed) != 1 {
		t.Fatalf("差异 = %+v，期望 1 条", diff)
	}
	changed := diff.Changed[0]
	if changed.OperationID != "password.change" || len(changed.Changed) != 2 {
		t.Fatalf("差异字段异常: %+v", changed)
	}
	fields := []string{changed.Changed[0].Field, changed.Changed[1].Field}
	if strings.Join(fields, ",") != "max_auth_age_seconds,notification_required" {
		t.Errorf("差异字段顺序 = %v", fields)
	}
	if version, err := env.service.Version(env.ctx, root, "system"); err != nil || version != 1 {
		t.Errorf("Version = (%d, %v)，期望 1", version, err)
	}
	// 普通用户与注入授权器行为。
	if _, err := env.service.Effective(env.ctx, env.normalCaller(), "system"); !errors.Is(err, policy.ErrAccessDenied) {
		t.Errorf("普通用户读取错误 = %v，期望 ErrAccessDenied", err)
	}
	if _, err := env.service.Effective(env.ctx, env.systemCaller(), "system"); err != nil {
		t.Errorf("系统调用者读取: %v", err)
	}
	if _, _, err := env.store.GetUserRoot(env.ctx, rootUserID); err != nil {
		t.Errorf("root 查询: %v", err)
	}
}

// TestRejectInvalidChangesAndAuthorization 覆盖非法组合、非 root 拒绝、缺少再次验证与审计失败。
func TestRejectInvalidChangesAndAuthorization(t *testing.T) {
	env := newTestEnv(t, nil)
	env.seedUser(rootUserID, "root", true)
	env.seedUser(normalUserID, "user", false)
	root := env.rootCaller()

	invalid := []struct {
		name    string
		request policy.SetRequest
		want    error
	}{
		{name: "非敏感仍要求再次验证", request: policy.SetRequest{OperationID: "password.change",
			Change:          policy.PolicyChange{Sensitive: boolPtr(false), ConfirmationRequired: boolPtr(false)},
			ExpectedVersion: 0}, want: policy.ErrInvalidChange},
		{name: "再次验证无新鲜度", request: policy.SetRequest{OperationID: "password.change",
			Change:          policy.PolicyChange{ReauthRequired: boolPtr(true), MaxAuthAgeSeconds: intPtr(0)},
			ExpectedVersion: 0}, want: policy.ErrInvalidChange},
		{name: "新鲜度超上限", request: policy.SetRequest{OperationID: "password.change",
			Change:          policy.PolicyChange{MaxAuthAgeSeconds: intPtr(policy.MaxAuthAgeLimitSeconds + 1)},
			ExpectedVersion: 0}, want: policy.ErrInvalidChange},
		{name: "再次验证强度为 none", request: policy.SetRequest{OperationID: "password.change",
			Change:          policy.PolicyChange{ReauthRequired: boolPtr(true), RequiredStrength: strengthPtr(policy.StrengthNone)},
			ExpectedVersion: 0}, want: policy.ErrInvalidChange},
		{name: "高风险取消敏感", request: policy.SetRequest{OperationID: "mfa.remove",
			Change: clearToNonSensitive(), ExpectedVersion: 0}, want: policy.ErrInvalidChange},
		{name: "root恢复取消敏感", request: policy.SetRequest{OperationID: "backup.restore",
			Change: clearToNonSensitive(), ExpectedVersion: 0}, want: policy.ErrInvalidChange},
		{name: "未知操作", request: policy.SetRequest{OperationID: "does.not.exist",
			Change: policy.PolicyChange{Sensitive: boolPtr(false), ReauthRequired: boolPtr(false),
				MaxAuthAgeSeconds: intPtr(0), RequiredStrength: strengthPtr(policy.StrengthNone),
				ConfirmationRequired: boolPtr(false)}, ExpectedVersion: 0}, want: policy.ErrOperationUnknown},
		{name: "内置操作改名", request: policy.SetRequest{OperationID: "password.change",
			Name:            "随意改名",
			Change:          policy.PolicyChange{NotificationRequired: boolPtr(false)},
			ExpectedVersion: 0}, want: policy.ErrInvalidRequest},
		{name: "空字段修改", request: policy.SetRequest{OperationID: "password.change",
			ExpectedVersion: 0}, want: policy.ErrInvalidRequest},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			test.request.ScopeID = "system"
			test.request.RequestID = "req-invalid"
			if _, err := env.service.Set(env.ctx, root, test.request); !errors.Is(err, test.want) {
				t.Fatalf("Set 错误 = %v，期望 %v", err, test.want)
			}
		})
	}
	if rows := env.count(`SELECT COUNT(*) FROM sensitive_operation_policies`); rows != 0 {
		t.Errorf("非法请求后策略行数 = %d，期望 0", rows)
	}
	if version, _ := env.service.Version(env.ctx, root, "system"); version != 0 {
		t.Errorf("非法请求后版本 = %d，期望 0", version)
	}

	// 非 root / 系统通道不能修改；普通用户读取也被拒绝。
	if _, err := env.service.Set(env.ctx, env.normalCaller(), policy.SetRequest{
		ScopeID: "system", OperationID: "password.change",
		Change:          policy.PolicyChange{NotificationRequired: boolPtr(false)},
		ExpectedVersion: 0, RequestID: "req-nonroot"}); !errors.Is(err, policy.ErrRootRequired) {
		t.Errorf("非 root 修改错误 = %v，期望 ErrRootRequired", err)
	}
	if _, err := env.service.Set(env.ctx, env.systemCaller(), policy.SetRequest{
		ScopeID: "system", OperationID: "password.change",
		Change:          policy.PolicyChange{NotificationRequired: boolPtr(false)},
		ExpectedVersion: 0, RequestID: "req-system"}); !errors.Is(err, policy.ErrRootRequired) {
		t.Errorf("系统通道修改错误 = %v，期望 ErrRootRequired", err)
	}
	// 未注入再次验证实现时 fail-closed。
	noReauthEnv := newTestEnv(t, func(options *policy.Options) { options.ReauthVerifier = nil })
	noReauthEnv.seedUser(rootUserID, "root", true)
	if _, err := noReauthEnv.service.Set(noReauthEnv.ctx, noReauthEnv.rootCaller(), policy.SetRequest{
		ScopeID: "system", OperationID: "password.change",
		Change:          policy.PolicyChange{NotificationRequired: boolPtr(false)},
		ExpectedVersion: 0, RequestID: "req-no-reauth"}); !errors.Is(err, policy.ErrReauthRequired) {
		t.Errorf("缺少再次验证错误 = %v，期望 ErrReauthRequired", err)
	}
	// 再次验证失败同样拒绝。
	env.reauthErr = errors.New("reauth failed")
	if _, err := env.service.Set(env.ctx, root, policy.SetRequest{
		ScopeID: "system", OperationID: "password.change",
		Change:          policy.PolicyChange{NotificationRequired: boolPtr(false)},
		ExpectedVersion: 0, RequestID: "req-reauth-failed"}); !errors.Is(err, policy.ErrReauthRequired) {
		t.Errorf("再次验证失败错误 = %v，期望 ErrReauthRequired", err)
	}
	env.reauthErr = nil
	// 审计失败必须整体回滚。
	auditFailEnv := newTestEnv(t, func(options *policy.Options) {
		options.Audit = failingAudit{AuditRecorder: options.Audit}
	})
	auditFailEnv.seedUser(rootUserID, "root", true)
	if _, err := auditFailEnv.service.Set(auditFailEnv.ctx, auditFailEnv.rootCaller(), policy.SetRequest{
		ScopeID: "system", OperationID: "password.change",
		Change:          policy.PolicyChange{NotificationRequired: boolPtr(false)},
		ExpectedVersion: 0, RequestID: "req-audit-fail"}); !errors.Is(err, policy.ErrAuditUnavailable) {
		t.Errorf("审计失败错误 = %v，期望 ErrAuditUnavailable", err)
	}
	if rows := auditFailEnv.count(`SELECT COUNT(*) FROM sensitive_operation_policies`); rows != 0 {
		t.Errorf("审计失败后策略行数 = %d，期望 0（回滚）", rows)
	}
}

// failingAudit 让关键审计写入失败。
type failingAudit struct {
	policy.AuditRecorder
}

func (f failingAudit) ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error {
	return fmt.Errorf("%w: 测试注入", audit.ErrAuditUnavailable)
}

// TestVersionConflictAndConcurrentSet 覆盖版本冲突与两个服务实例的并发更新。
func TestVersionConflictAndConcurrentSet(t *testing.T) {
	env := newTestEnv(t, nil)
	env.seedUser(rootUserID, "root", true)
	root := env.rootCaller()
	if _, err := env.service.Set(env.ctx, root, policy.SetRequest{
		ScopeID: "system", OperationID: "password.change",
		Change:          policy.PolicyChange{NotificationRequired: boolPtr(false)},
		ExpectedVersion: 5, RequestID: "req-stale"}); !errors.Is(err, policy.ErrVersionConflict) {
		t.Fatalf("过期版本错误 = %v，期望 ErrVersionConflict", err)
	}
	if rows := env.count(`SELECT COUNT(*) FROM sensitive_operation_policies`); rows != 0 {
		t.Errorf("版本冲突后策略行数 = %d，期望 0", rows)
	}
	// 同一数据库上的第二个服务实例与第一个实例使用相同期望版本：只有一个成功。
	second, err := policy.New(policy.Options{
		Store:          env.store,
		Audit:          env.recorder,
		ReauthVerifier: policy.ReauthVerifierFunc(func(ctx context.Context, caller policy.Caller, operationID string) error { return nil }),
		Now:            func() time.Time { return env.now },
	})
	if err != nil {
		t.Fatalf("第二个服务: %v", err)
	}
	// 两个实例基于同一期望版本修改不同字段：有效策略必然不同，因此恰好一个成功、
	// 另一个因版本过期返回 CONFLICT（相同值的重复提交现在按幂等成功处理）。
	changes := []policy.PolicyChange{
		{NotificationRequired: boolPtr(false)},
		{ConfirmationRequired: boolPtr(false)},
	}
	results := make(chan error, 2)
	for index, service := range []*policy.Service{env.service, second} {
		go func(service *policy.Service, change policy.PolicyChange) {
			_, setErr := service.Set(env.ctx, root, policy.SetRequest{
				ScopeID: "system", OperationID: "password.change",
				Change: change, ExpectedVersion: 0, RequestID: "req-concurrent"})
			results <- setErr
		}(service, changes[index])
	}
	successes, conflicts := 0, 0
	for index := 0; index < 2; index++ {
		switch err := <-results; {
		case err == nil:
			successes++
		case errors.Is(err, policy.ErrVersionConflict):
			conflicts++
		default:
			t.Fatalf("并发 Set 未知错误: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Errorf("并发 Set 结果 = 成功 %d / 冲突 %d，期望 1/1", successes, conflicts)
	}
	if version, _ := env.service.Version(env.ctx, root, "system"); version != 1 {
		t.Errorf("并发后版本 = %d，期望 1", version)
	}
	if rows := env.count(`SELECT COUNT(*) FROM sensitive_operation_policies WHERE scope_id='system'`); rows != 1 {
		t.Errorf("并发后策略行数 = %d，期望 1", rows)
	}
}

// TestRestoreDefaults 覆盖逐项/整体恢复默认、幂等恢复与恢复审计。
func TestRestoreDefaults(t *testing.T) {
	env := newTestEnv(t, nil)
	env.seedUser(rootUserID, "root", true)
	root := env.rootCaller()
	setOverride := func(operationID string, expected int64) {
		if _, err := env.service.Set(env.ctx, root, policy.SetRequest{
			ScopeID: "system", OperationID: operationID,
			Change:          policy.PolicyChange{NotificationRequired: boolPtr(false)},
			ExpectedVersion: expected, RequestID: "req-restore-set"}); err != nil {
			t.Fatalf("设置 %s 覆盖: %v", operationID, err)
		}
	}
	setOverride("password.change", 0)
	setOverride("email.change.request", 1)
	restored, err := env.service.Restore(env.ctx, root, policy.RestoreRequest{
		ScopeID: "system", OperationID: "password.change", ExpectedVersion: 2, RequestID: "req-restore-1"})
	if err != nil {
		t.Fatalf("逐项恢复: %v", err)
	}
	if restored.Version != 3 {
		t.Errorf("逐项恢复后版本 = %d，期望 3", restored.Version)
	}
	operation, _ := restored.Lookup("password.change")
	if operation.Source != policy.SourceDefault {
		t.Errorf("恢复后来源 = %q，期望默认", operation.Source)
	}
	if events := env.count(`SELECT COUNT(*) FROM audit_events WHERE action='policy.restore' AND outcome='success'`); events != 1 {
		t.Errorf("恢复成功审计数 = %d，期望 1", events)
	}
	// 对已是默认值的操作再次恢复：幂等成功、不递增版本、不写新审计。
	again, err := env.service.Restore(env.ctx, root, policy.RestoreRequest{
		ScopeID: "system", OperationID: "password.change", ExpectedVersion: 3, RequestID: "req-restore-2"})
	if err != nil {
		t.Fatalf("幂等恢复: %v", err)
	}
	if again.Version != 3 {
		t.Errorf("幂等恢复后版本 = %d，期望 3（不递增）", again.Version)
	}
	if events := env.count(`SELECT COUNT(*) FROM audit_events WHERE action='policy.restore' AND outcome='success'`); events != 1 {
		t.Errorf("幂等恢复后审计数 = %d，期望仍为 1", events)
	}
	// 整体恢复删除全部 override（应用声明不在 system 作用域）。
	overall, err := env.service.Restore(env.ctx, root, policy.RestoreRequest{
		ScopeID: "system", All: true, ExpectedVersion: 3, RequestID: "req-restore-all"})
	if err != nil {
		t.Fatalf("整体恢复: %v", err)
	}
	if overall.Version != 4 {
		t.Errorf("整体恢复后版本 = %d，期望 4", overall.Version)
	}
	if rows := env.count(`SELECT COUNT(*) FROM sensitive_operation_policies WHERE scope_id='system' AND source_kind='override'`); rows != 0 {
		t.Errorf("整体恢复后覆盖行数 = %d，期望 0", rows)
	}
	// 整体恢复在无覆盖时幂等。
	idempotent, err := env.service.Restore(env.ctx, root, policy.RestoreRequest{
		ScopeID: "system", All: true, ExpectedVersion: 4, RequestID: "req-restore-all-2"})
	if err != nil || idempotent.Version != 4 {
		t.Errorf("整体幂等恢复 = (%d, %v)，期望版本 4", idempotent.Version, err)
	}
}

// TestApplicationScope 覆盖应用作用域声明、覆盖隔离、整体恢复保留声明与跨作用域保护。
func TestApplicationScope(t *testing.T) {
	env := newTestEnv(t, nil)
	env.seedUser(rootUserID, "root", true)
	env.seedUser(normalUserID, "user", false)
	const appID = "app_00000000000000000000000000000001"
	env.seedApplication(appID, "demo")
	root := env.rootCaller()

	declared, err := env.service.Set(env.ctx, root, policy.SetRequest{
		ScopeID: appID, OperationID: "app.order.export", Declare: true,
		Name: "导出订单数据", Description: "导出本应用订单数据；必须近期验证与确认，不能跨应用。",
		Change: policy.PolicyChange{
			Sensitive: boolPtr(true), ReauthRequired: boolPtr(true), MaxAuthAgeSeconds: intPtr(300),
			RequiredStrength: strengthPtr(policy.StrengthPassword), ConfirmationRequired: boolPtr(true),
		},
		ExpectedVersion: 0, RequestID: "req-app-declare"})
	if err != nil {
		t.Fatalf("应用声明操作: %v", err)
	}
	if declared.Version != 1 {
		t.Fatalf("应用作用域版本 = %d，期望 1", declared.Version)
	}
	operation, found := declared.Lookup("app.order.export")
	if !found {
		t.Fatal("应用声明操作未出现在有效策略中")
	}
	if operation.Source != policy.SourceApplication || operation.Name != "导出订单数据" ||
		operation.HasDefault || !operation.AuditRequired {
		t.Fatalf("应用声明条目异常: %+v", operation)
	}
	// 系统作用域看不到应用声明。
	systemSnapshot, err := env.service.Effective(env.ctx, root, "system")
	if err != nil {
		t.Fatalf("系统有效策略: %v", err)
	}
	if _, found := systemSnapshot.Lookup("app.order.export"); found {
		t.Error("应用声明泄漏到系统作用域")
	}
	// 应用作用域覆盖内置操作，不影响系统作用域。
	if _, err := env.service.Set(env.ctx, root, policy.SetRequest{
		ScopeID: appID, OperationID: "password.change",
		Change:          policy.PolicyChange{NotificationRequired: boolPtr(false)},
		ExpectedVersion: 1, RequestID: "req-app-override"}); err != nil {
		t.Fatalf("应用覆盖内置操作: %v", err)
	}
	appSnapshot, err := env.service.Effective(env.ctx, root, appID)
	if err != nil {
		t.Fatalf("应用有效策略: %v", err)
	}
	appPassword, _ := appSnapshot.Lookup("password.change")
	systemPassword, _ := systemSnapshot.Lookup("password.change")
	if appPassword.Source != policy.SourceOverride || systemPassword.Source != policy.SourceDefault {
		t.Errorf("作用域隔离异常: app=%q system=%q", appPassword.Source, systemPassword.Source)
	}
	// 整体恢复应用作用域：移除覆盖但保留应用声明。
	restored, err := env.service.Restore(env.ctx, root, policy.RestoreRequest{
		ScopeID: appID, All: true, ExpectedVersion: 2, RequestID: "req-app-restore"})
	if err != nil {
		t.Fatalf("应用整体恢复: %v", err)
	}
	if restored.Version != 3 {
		t.Errorf("应用恢复后版本 = %d，期望 3", restored.Version)
	}
	if _, found := restored.Lookup("app.order.export"); !found {
		t.Error("整体恢复误删应用声明操作")
	}
	if operation, _ := restored.Lookup("password.change"); operation.Source != policy.SourceDefault {
		t.Errorf("整体恢复后内置操作来源 = %q，期望默认", operation.Source)
	}
	// 应用声明操作没有系统默认值，不能逐项恢复。
	if _, err := env.service.Restore(env.ctx, root, policy.RestoreRequest{
		ScopeID: appID, OperationID: "app.order.export", ExpectedVersion: 3,
		RequestID: "req-app-restore-declared"}); !errors.Is(err, policy.ErrDefaultUnavailable) {
		t.Errorf("恢复应用声明操作错误 = %v，期望 ErrDefaultUnavailable", err)
	}
	// 系统作用域不能声明新操作；应用作用域必须存在；非 root 不能修改应用策略。
	if _, err := env.service.Set(env.ctx, root, policy.SetRequest{
		ScopeID: "system", OperationID: "app.new.operation", Declare: true,
		Name: "新操作", Description: "说明",
		Change:          policy.PolicyChange{Sensitive: boolPtr(true)},
		ExpectedVersion: 0, RequestID: "req-system-declare"}); !errors.Is(err, policy.ErrOperationUnknown) {
		t.Errorf("系统作用域声明错误 = %v，期望 ErrOperationUnknown", err)
	}
	if _, err := env.service.Set(env.ctx, root, policy.SetRequest{
		ScopeID: "app_missing", OperationID: "app.new.operation", Declare: true,
		Name: "新操作", Description: "说明", Change: policy.PolicyChange{Sensitive: boolPtr(true)},
		ExpectedVersion: 0, RequestID: "req-missing-scope"}); !errors.Is(err, policy.ErrScopeUnknown) {
		t.Errorf("不存在作用域错误 = %v，期望 ErrScopeUnknown", err)
	}
	if _, err := env.service.Set(env.ctx, env.normalCaller(), policy.SetRequest{
		ScopeID: appID, OperationID: "app.order.export",
		Change:          policy.PolicyChange{NotificationRequired: boolPtr(true)},
		ExpectedVersion: 3, RequestID: "req-app-nonroot"}); !errors.Is(err, policy.ErrRootRequired) {
		t.Errorf("非 root 修改应用策略错误 = %v，期望 ErrRootRequired", err)
	}
}

// TestEvaluateFailClosed 覆盖策略评估：默认、未实现强度 fail-closed、过期/未来时间戳、
// 强度不足、缺少确认、敏感标记取消后基础约束仍保留。
func TestEvaluateFailClosed(t *testing.T) {
	env := newTestEnv(t, nil)
	env.seedUser(rootUserID, "root", true)
	root := env.rootCaller()
	now := time.Now().UTC()
	env.now = now

	decision, err := env.service.Evaluate(env.ctx, root, policy.EvaluateRequest{
		ScopeID: "system", OperationID: "password.change",
		Verification: policy.Verification{VerifiedAt: now.Add(-time.Minute),
			Strength: policy.StrengthPassword, Confirmed: true},
	})
	if err != nil {
		t.Fatalf("默认密码级评估: %v", err)
	}
	if !decision.Sensitive || decision.PermissionKey != "self.credentials.manage" ||
		!decision.AuditRequired || decision.RootOnly {
		t.Fatalf("评估约束异常: %+v", decision)
	}
	// 过期验证。
	if _, err := env.service.Evaluate(env.ctx, root, policy.EvaluateRequest{
		ScopeID: "system", OperationID: "password.change",
		Verification: policy.Verification{VerifiedAt: now.Add(-20 * time.Minute),
			Strength: policy.StrengthPassword, Confirmed: true},
	}); !errors.Is(err, policy.ErrReauthRequired) {
		t.Errorf("过期验证错误 = %v，期望 ErrReauthRequired", err)
	}
	// 缺少验证。
	if _, err := env.service.Evaluate(env.ctx, root, policy.EvaluateRequest{
		ScopeID: "system", OperationID: "password.change",
		Verification: policy.Verification{Confirmed: true},
	}); !errors.Is(err, policy.ErrReauthRequired) {
		t.Errorf("缺少验证错误 = %v，期望 ErrReauthRequired", err)
	}
	// 未来时间戳视为异常事实，fail-closed。
	if _, err := env.service.Evaluate(env.ctx, root, policy.EvaluateRequest{
		ScopeID: "system", OperationID: "password.change",
		Verification: policy.Verification{VerifiedAt: now.Add(5 * time.Minute),
			Strength: policy.StrengthPassword, Confirmed: true},
	}); !errors.Is(err, policy.ErrReauthRequired) {
		t.Errorf("未来验证错误 = %v，期望 ErrReauthRequired", err)
	}
	// 强度不足。
	if _, err := env.service.Evaluate(env.ctx, root, policy.EvaluateRequest{
		ScopeID: "system", OperationID: "password.change",
		Verification: policy.Verification{VerifiedAt: now.Add(-time.Minute),
			Strength: policy.StrengthNone, Confirmed: true},
	}); !errors.Is(err, policy.ErrVerificationUnavailable) {
		t.Errorf("强度不足错误 = %v，期望 ErrVerificationUnavailable", err)
	}
	// 缺少确认。
	if _, err := env.service.Evaluate(env.ctx, root, policy.EvaluateRequest{
		ScopeID: "system", OperationID: "password.change",
		Verification: policy.Verification{VerifiedAt: now.Add(-time.Minute),
			Strength: policy.StrengthPassword},
	}); !errors.Is(err, policy.ErrConfirmationRequired) {
		t.Errorf("缺少确认错误 = %v，期望 ErrConfirmationRequired", err)
	}
	// 默认要求强认证但环境未实现：fail-closed 为 MFA_REQUIRED，不降级为密码。
	if _, err := env.service.Evaluate(env.ctx, root, policy.EvaluateRequest{
		ScopeID: "system", OperationID: "session.revoke.other",
		Verification: policy.Verification{VerifiedAt: now.Add(-time.Minute),
			Strength: policy.StrengthPassword, Confirmed: true},
	}); !errors.Is(err, policy.ErrVerificationUnavailable) {
		t.Errorf("未实现强认证错误 = %v，期望 ErrVerificationUnavailable", err)
	}
	// 注入“强认证已实现”的服务：强认证新鲜 + 确认后可以通过。
	strongEnv := newTestEnv(t, func(options *policy.Options) {
		options.AvailableStrengths = []policy.Strength{policy.StrengthNone, policy.StrengthPassword, policy.StrengthStrong}
	})
	strongEnv.seedUser(rootUserID, "root", true)
	strongEnv.now = now
	strongDecision, err := strongEnv.service.Evaluate(strongEnv.ctx, strongEnv.userCallerFor(rootUserID), policy.EvaluateRequest{
		ScopeID: "system", OperationID: "mfa.remove",
		Verification: policy.Verification{VerifiedAt: now.Add(-time.Minute),
			Strength: policy.StrengthStrong, Confirmed: true},
	})
	if err != nil {
		t.Fatalf("强认证可用时评估: %v", err)
	}
	if !strongDecision.Sensitive || !strongDecision.ReauthRequired {
		t.Errorf("强认证评估结果异常: %+v", strongDecision)
	}
	// 取消敏感标记后仍保留基础权限/root 限制/审计（不可通过策略取消）。
	if _, err := env.service.Set(env.ctx, root, policy.SetRequest{
		ScopeID: "system", OperationID: "password.change", Change: clearToNonSensitive(),
		ExpectedVersion: 0, RequestID: "req-eval-nonsensitive"}); err != nil {
		t.Fatalf("取消敏感标记: %v", err)
	}
	relaxed, err := env.service.Evaluate(env.ctx, root, policy.EvaluateRequest{
		ScopeID: "system", OperationID: "password.change"})
	if err != nil {
		t.Fatalf("非敏感评估: %v", err)
	}
	if relaxed.Sensitive || !relaxed.AuditRequired || relaxed.PermissionKey != "self.credentials.manage" {
		t.Errorf("取消敏感后基础约束异常: %+v", relaxed)
	}
	if _, err := env.service.Evaluate(env.ctx, root, policy.EvaluateRequest{
		ScopeID: "system", OperationID: "unknown.operation"}); !errors.Is(err, policy.ErrOperationUnknown) {
		t.Errorf("未知操作评估错误 = %v，期望 ErrOperationUnknown", err)
	}
}

// userCallerFor 是测试辅助：构造普通/root 用户调用者。
func (e *testEnv) userCallerFor(userID string) policy.Caller {
	e.t.Helper()
	caller, err := policy.UserCaller(userID)
	if err != nil {
		e.t.Fatalf("用户调用者: %v", err)
	}
	return caller
}

// TestCatalogValidation 校验内置目录完整性：标识唯一、默认策略合法、基础权限标识
// 都存在于既有预设权限目录。
func TestCatalogValidation(t *testing.T) {
	catalog := policy.DefaultCatalog()
	if err := catalog.Validate(); err != nil {
		t.Fatalf("默认目录校验: %v", err)
	}
	if len(catalog.Operations) < 20 {
		t.Errorf("默认目录操作数 = %d，期望至少 20", len(catalog.Operations))
	}
	permissions := make(map[string]bool)
	for _, definition := range preset.DefaultCatalog().Permissions {
		permissions[definition.Key] = true
	}
	seen := make(map[string]bool)
	for _, operation := range catalog.Operations {
		if seen[operation.ID] {
			t.Errorf("重复操作标识 %q", operation.ID)
		}
		seen[operation.ID] = true
		if operation.PermissionKey != "" && !permissions[operation.PermissionKey] {
			t.Errorf("操作 %q 的基础权限 %q 不在预设权限目录中", operation.ID, operation.PermissionKey)
		}
		if operation.Default.Sensitive != true {
			t.Errorf("操作 %q 默认应为敏感操作", operation.ID)
		}
		if operation.ImmutableSensitive && !operation.Default.Sensitive {
			t.Errorf("操作 %q 不可取消敏感但默认不敏感", operation.ID)
		}
	}
	// 非法目录必须被拒绝。
	invalid := []*policy.Catalog{
		{Version: "1.0", Operations: policy.DefaultCatalog().Operations},
		{Version: "1.0.0", Operations: nil},
	}
	duplicated := policy.DefaultCatalog()
	duplicated.Operations = append(duplicated.Operations, duplicated.Operations[0])
	invalid = append(invalid, duplicated)
	badPolicy := policy.DefaultCatalog()
	badPolicy.Operations = append([]policy.Operation(nil), badPolicy.Operations...)
	badPolicy.Operations[0].Default = policy.Policy{Sensitive: false, ReauthRequired: true}
	invalid = append(invalid, badPolicy)
	for index, catalog := range invalid {
		if err := catalog.Validate(); !errors.Is(err, policy.ErrOptionsInvalid) {
			t.Errorf("非法目录 %d 校验错误 = %v，期望 ErrOptionsInvalid", index, err)
		}
	}
	if _, err := policy.New(policy.Options{Store: nil}); !errors.Is(err, policy.ErrOptionsInvalid) {
		t.Errorf("缺少存储的构造错误 = %v，期望 ErrOptionsInvalid", err)
	}
}

// TestReadAuthorizerInjection 验证注入 Authorizer 可扩展读取，但不能放宽写必须 root。
func TestReadAuthorizerInjection(t *testing.T) {
	env := newTestEnv(t, func(options *policy.Options) {
		options.Authorizer = policy.AuthorizerFunc(func(ctx context.Context, caller policy.Caller, scopeID string, write bool) error {
			return nil
		})
	})
	env.seedUser(rootUserID, "root", true)
	env.seedUser(normalUserID, "user", false)
	if _, err := env.service.Effective(env.ctx, env.normalCaller(), "system"); err != nil {
		t.Errorf("注入授权器后普通用户读取: %v", err)
	}
	if _, err := env.service.Set(env.ctx, env.normalCaller(), policy.SetRequest{
		ScopeID: "system", OperationID: "password.change",
		Change:          policy.PolicyChange{NotificationRequired: boolPtr(false)},
		ExpectedVersion: 0, RequestID: "req-authorizer-write"}); !errors.Is(err, policy.ErrRootRequired) {
		t.Errorf("注入授权器后非 root 写入错误 = %v，期望 ErrRootRequired", err)
	}
}

// TestPartialUpdateKeepsHardenedFields 回归安全审计 PoC：第二次只改一个字段时，
// 必须保留既有覆盖里已经加严的其他字段，不能被目录默认值静默重置。
func TestPartialUpdateKeepsHardenedFields(t *testing.T) {
	env := newTestEnv(t, nil)
	env.seedUser(rootUserID, "root", true)
	root := env.rootCaller()
	if _, err := env.service.Set(env.ctx, root, policy.SetRequest{
		ScopeID: "system", OperationID: "password.change",
		Change:          policy.PolicyChange{MaxAuthAgeSeconds: intPtr(40)},
		ExpectedVersion: 0, RequestID: "req-hard-1"}); err != nil {
		t.Fatalf("首次加严: %v", err)
	}
	updated, err := env.service.Set(env.ctx, root, policy.SetRequest{
		ScopeID: "system", OperationID: "password.change",
		Change:          policy.PolicyChange{NotificationRequired: boolPtr(false)},
		ExpectedVersion: 1, RequestID: "req-hard-2"})
	if err != nil {
		t.Fatalf("二次部分更新: %v", err)
	}
	operation, _ := updated.Lookup("password.change")
	if operation.Effective.MaxAuthAgeSeconds != 40 {
		t.Errorf("二次更新后新鲜度 = %d，期望保留 40（不得回退默认 600）",
			operation.Effective.MaxAuthAgeSeconds)
	}
	if !operation.Effective.ReauthRequired || operation.Effective.Strength != policy.StrengthPassword ||
		!operation.Effective.ConfirmationRequired || operation.Effective.NotificationRequired {
		t.Errorf("二次更新后其他字段异常: %+v", operation.Effective)
	}
	if updated.Version != 2 {
		t.Errorf("版本 = %d，期望 2", updated.Version)
	}
}

// TestNoopSetDoesNotBumpVersion 验证相同有效策略重复提交/显式写回默认值不递增版本、
// 不写成功审计，与恢复默认的幂等语义一致。
func TestNoopSetDoesNotBumpVersion(t *testing.T) {
	env := newTestEnv(t, nil)
	env.seedUser(rootUserID, "root", true)
	root := env.rootCaller()
	change := policy.PolicyChange{NotificationRequired: boolPtr(false)}
	if _, err := env.service.Set(env.ctx, root, policy.SetRequest{
		ScopeID: "system", OperationID: "password.change", Change: change,
		ExpectedVersion: 0, RequestID: "req-noop-1"}); err != nil {
		t.Fatalf("首次设置: %v", err)
	}
	again, err := env.service.Set(env.ctx, root, policy.SetRequest{
		ScopeID: "system", OperationID: "password.change", Change: change,
		ExpectedVersion: 1, RequestID: "req-noop-2"})
	if err != nil {
		t.Fatalf("相同值重复设置: %v", err)
	}
	if again.Version != 1 {
		t.Errorf("相同值重复设置后版本 = %d，期望仍为 1", again.Version)
	}
	if events := env.count(`SELECT COUNT(*) FROM audit_events WHERE action='policy.update' AND outcome='success'`); events != 1 {
		t.Errorf("相同值重复设置后成功审计数 = %d，期望仍为 1", events)
	}
	// 对没有覆盖的操作显式写回默认值：不建行、不递增版本。
	unchanged, err := env.service.Set(env.ctx, root, policy.SetRequest{
		ScopeID: "system", OperationID: "email.change.request",
		Change:          policy.PolicyChange{NotificationRequired: boolPtr(true)},
		ExpectedVersion: 1, RequestID: "req-noop-3"})
	if err != nil {
		t.Fatalf("写回默认值: %v", err)
	}
	if unchanged.Version != 1 {
		t.Errorf("写回默认值后版本 = %d，期望仍为 1", unchanged.Version)
	}
	if rows := env.count(`SELECT COUNT(*) FROM sensitive_operation_policies WHERE operation_id='email.change.request'`); rows != 0 {
		t.Errorf("写回默认值不应创建覆盖行，实际 %d", rows)
	}
}

// TestRestoreIdempotentChecksVersion 验证“已经是默认值”的幂等恢复仍校验期望版本。
func TestRestoreIdempotentChecksVersion(t *testing.T) {
	env := newTestEnv(t, nil)
	env.seedUser(rootUserID, "root", true)
	root := env.rootCaller()
	restored, err := env.service.Restore(env.ctx, root, policy.RestoreRequest{
		ScopeID: "system", OperationID: "password.change", ExpectedVersion: 0,
		RequestID: "req-restore-version-1"})
	if err != nil || restored.Version != 0 {
		t.Fatalf("默认版本幂等恢复 = (%d, %v)，期望 (0, nil)", restored.Version, err)
	}
	if _, err := env.service.Restore(env.ctx, root, policy.RestoreRequest{
		ScopeID: "system", OperationID: "password.change", ExpectedVersion: 999,
		RequestID: "req-restore-version-2"}); !errors.Is(err, policy.ErrVersionConflict) {
		t.Errorf("过期版本幂等恢复错误 = %v，期望 ErrVersionConflict", err)
	}
}

// failingRecordAudit 让失败审计不可用，用于验证拒绝结果不被审计故障改变。
type failingRecordAudit struct {
	policy.AuditRecorder
}

func (f failingRecordAudit) RecordFailure(ctx context.Context, event audit.Event) error {
	return fmt.Errorf("%w: 测试注入", audit.ErrAuditUnavailable)
}

// TestRejectionFailureAudit 验证在审计事务之前的拒绝也写失败审计，且审计故障不会
// 把拒绝变成放行。
func TestRejectionFailureAudit(t *testing.T) {
	env := newTestEnv(t, nil)
	env.seedUser(rootUserID, "root", true)
	env.seedUser(normalUserID, "user", false)
	if _, err := env.service.Set(env.ctx, env.normalCaller(), policy.SetRequest{
		ScopeID: "system", OperationID: "password.change",
		Change:          policy.PolicyChange{NotificationRequired: boolPtr(false)},
		ExpectedVersion: 0, RequestID: "req-reject-nonroot"}); !errors.Is(err, policy.ErrRootRequired) {
		t.Fatalf("非 root 拒绝错误 = %v", err)
	}
	if events := env.count(`SELECT COUNT(*) FROM audit_events WHERE action='policy.update' AND outcome='denied'`); events != 1 {
		t.Errorf("非 root 拒绝失败审计数 = %d，期望 1", events)
	}
	if events := env.count(`SELECT COUNT(*) FROM audit_events WHERE action='policy.update' AND outcome='denied' AND error_code='ACCESS_DENIED'`); events != 1 {
		t.Errorf("ACCESS_DENIED 失败审计数 = %d，期望 1", events)
	}
	if _, err := env.service.Set(env.ctx, env.rootCaller(), policy.SetRequest{
		ScopeID: "system", OperationID: "password.change",
		Change:          policy.PolicyChange{NotificationRequired: boolPtr(false)},
		ExpectedVersion: 0, RequestID: "bad request id!"}); !errors.Is(err, policy.ErrInvalidRequest) {
		t.Fatalf("非法请求编号错误 = %v", err)
	}
	if events := env.count(`SELECT COUNT(*) FROM audit_events WHERE action='policy.update' AND outcome='failure'`); events < 1 {
		t.Errorf("非法请求编号后 failure 审计数 = %d，期望至少 1", events)
	}
	noReauthEnv := newTestEnv(t, func(options *policy.Options) { options.ReauthVerifier = nil })
	noReauthEnv.seedUser(rootUserID, "root", true)
	if _, err := noReauthEnv.service.Set(noReauthEnv.ctx, noReauthEnv.rootCaller(), policy.SetRequest{
		ScopeID: "system", OperationID: "password.change",
		Change:          policy.PolicyChange{NotificationRequired: boolPtr(false)},
		ExpectedVersion: 0, RequestID: "req-reject-reauth"}); !errors.Is(err, policy.ErrReauthRequired) {
		t.Fatalf("缺少再次验证错误 = %v", err)
	}
	if events := noReauthEnv.count(`SELECT COUNT(*) FROM audit_events WHERE action='policy.update' AND outcome='failure' AND error_code='REAUTH_REQUIRED'`); events != 1 {
		t.Errorf("再次验证失败审计数 = %d，期望 1", events)
	}
	auditFailingEnv := newTestEnv(t, func(options *policy.Options) {
		options.Audit = failingRecordAudit{AuditRecorder: options.Audit}
	})
	auditFailingEnv.seedUser(rootUserID, "root", true)
	auditFailingEnv.seedUser(normalUserID, "user", false)
	if _, err := auditFailingEnv.service.Set(auditFailingEnv.ctx, auditFailingEnv.normalCaller(), policy.SetRequest{
		ScopeID: "system", OperationID: "password.change",
		Change:          policy.PolicyChange{NotificationRequired: boolPtr(false)},
		ExpectedVersion: 0, RequestID: "req-reject-audit-fail"}); !errors.Is(err, policy.ErrRootRequired) {
		t.Errorf("失败审计不可用时错误 = %v，期望仍为 ErrRootRequired", err)
	}
}

// TestCatalogOnboardingAndAuthnOperations 验证 onboarding 与 authn 专门操作 ID 已登记
// 且基础权限由宿主授权器判定（目录不硬编码权限）。
func TestCatalogOnboardingAndAuthnOperations(t *testing.T) {
	catalog := policy.DefaultCatalog()
	for _, operationID := range []string{
		"onboarding.invite.create", "onboarding.registration.review",
		"authn.root_password.setup",
	} {
		operation, found := catalog.Lookup(operationID)
		if !found {
			t.Errorf("目录缺少操作 %q", operationID)
			continue
		}
		if operation.PermissionKey != "" {
			t.Errorf("操作 %q 的基础权限应由宿主授权器判定，实际 %q", operationID, operation.PermissionKey)
		}
		if !operation.Default.Sensitive {
			t.Errorf("操作 %q 默认应为敏感", operationID)
		}
	}
	rootSetup, _ := catalog.Lookup("authn.root_password.setup")
	if !rootSetup.RootOnly || !rootSetup.ImmutableSensitive || rootSetup.Default.ReauthRequired {
		t.Errorf("root 设置密码操作定义异常: %+v", rootSetup)
	}
	if len(catalog.Operations) < 24 {
		t.Errorf("目录操作数 = %d，期望至少 24", len(catalog.Operations))
	}
}
