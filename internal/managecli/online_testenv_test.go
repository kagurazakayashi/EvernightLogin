package managecli

// 本文件构造在线命令的真实测试环境：临时 SQLite（真实迁移）、真实 auditops/
// reports 领域服务、真实 session.Service 签发的管理会话秘密文件，以及真实
// internal/adminapi Handler + httptest.Server。
//
// 测试替身只替换各领域服务的授权/敏感/任务接缝（与 adminapi 自身集成测试一致），
// 业务逻辑、审计写入、会话认证、HTTP 传输与 envelope 全部是真实路径。backupadmin
// 装配成本高，备份命令使用线级契约替身（真实 adminapi 传输 + 假 BackupService），
// 在测试与报告中明确标注该边界。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/auditops"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/backupadmin"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/reports"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	sessionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/session/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// onlineTestNow 是在线测试的固定时钟（沿用 managecli 测试基准）。
var onlineTestNow = testNow

// onlineErrorCodes 把根包错误码注册表投影为 adminapi 需要的只读视图。
func onlineErrorCodes() []adminapi.ErrorCodeInfo {
	definitions := login.RegisteredErrorCodes()
	codes := make([]adminapi.ErrorCodeInfo, 0, len(definitions))
	for _, definition := range definitions {
		codes = append(codes, adminapi.ErrorCodeInfo{Code: string(definition.Code),
			Message: definition.DefaultMessage, HTTPStatus: definition.HTTPStatus})
	}
	return codes
}

// onlineFixture 是在线命令测试的共享环境。
type onlineFixture struct {
	t   *testing.T
	ctx context.Context

	raw        *storagesqlite.Store
	auditStore *auditsqlite.Store
	recorder   *audit.Recorder

	sessionService   *session.Service
	sessionFile      string
	plainSessionFile string
	strongSecret     string
	plainSecret      string
	userID           string

	server  *httptest.Server
	handler *adminapi.Server
}

// newOnlineFixture 构造临时数据库、真实审计写入、真实会话服务与两种管理会话
// （已完成强认证 / 仅普通认证）的受保护秘密文件。
func newOnlineFixture(t *testing.T) *onlineFixture {
	t.Helper()
	fixture := &onlineFixture{t: t, ctx: context.Background()}
	_, fixture.raw = newTestDatabase(t)
	fixture.userID = testUserID(40)
	seedUser(t, fixture.raw, fixture.userID, "online-admin", false)

	auditStore, err := auditsqlite.New(fixture.raw)
	if err != nil {
		t.Fatalf("构造审计存储: %v", err)
	}
	fixture.auditStore = auditStore
	recorder, err := audit.New(auditStore, audit.Options{Now: fixedOnlineNow})
	if err != nil {
		t.Fatalf("构造审计写入器: %v", err)
	}
	fixture.recorder = recorder

	sessionStore, err := sessionsqlite.New(fixture.raw)
	if err != nil {
		t.Fatalf("构造会话存储: %v", err)
	}
	ring, _ := newProtectedKeyringFile(t)
	sessionService, err := session.New(sessionStore, session.Options{
		Store: sessionStore, Audit: recorder, Keyring: ring, Now: fixedOnlineNow})
	if err != nil {
		t.Fatalf("构造会话服务: %v", err)
	}
	fixture.sessionService = sessionService

	strong, err := sessionService.Login(fixture.ctx, session.LoginRequest{
		Result: authn.AuthenticateResult{
			UserID: fixture.userID, Username: "online-admin",
			Outcome:               authn.OutcomeComplete,
			CompletedMethods:      []authn.Method{authn.MethodPassword, authn.MethodSecurityKey},
			CompletedAt:           onlineTestNow,
			StrongAuthCompletedAt: onlineTestNow,
			SecurityVersion:       1,
		}, RequestID: "req_online_fixture_strong"})
	if err != nil {
		t.Fatalf("签发强认证管理会话: %v", err)
	}
	fixture.strongSecret = strong.Secret.Reveal()
	fixture.sessionFile = writeProtectedSecretFile(t, "online-session.secret",
		fixture.strongSecret)

	plain, err := sessionService.Login(fixture.ctx, session.LoginRequest{
		Result: authn.AuthenticateResult{
			UserID: fixture.userID, Username: "online-admin",
			Outcome:          authn.OutcomeComplete,
			CompletedMethods: []authn.Method{authn.MethodPassword},
			CompletedAt:      onlineTestNow,
			SecurityVersion:  1,
		}, RequestID: "req_online_fixture_plain"})
	if err != nil {
		t.Fatalf("签发普通会话: %v", err)
	}
	fixture.plainSecret = plain.Secret.Reveal()
	fixture.plainSessionFile = writeProtectedSecretFile(t, "online-plain.secret",
		fixture.plainSecret)
	return fixture
}

// fixedOnlineNow 是测试注入的固定时钟。
func fixedOnlineNow() time.Time { return onlineTestNow }

// serve 用真实 adminapi Handler 启动 httptest 服务；configure 注入领域服务。
func (f *onlineFixture) serve(configure func(options *adminapi.Options)) {
	f.t.Helper()
	options := adminapi.Options{Session: f.sessionService,
		ErrorCodes: onlineErrorCodes(), Now: fixedOnlineNow}
	if configure != nil {
		configure(&options)
	}
	server, err := adminapi.New(options)
	if err != nil {
		f.t.Fatalf("构造管理 API: %v", err)
	}
	f.handler = server
	f.server = httptest.NewServer(server.Handler())
	f.t.Cleanup(f.server.Close)
}

// serveHandler 用自定义根处理器启动 httptest 服务（TLS/超时等传输测试使用）。
func (f *onlineFixture) serveHandler(handler http.Handler) {
	f.t.Helper()
	f.server = httptest.NewServer(handler)
	f.t.Cleanup(f.server.Close)
}

// serveTLS 用真实 adminapi Handler 启动 TLS httptest 服务（验证默认严格证书校验
// 与 --ca-file 追加可信 CA）。
func (f *onlineFixture) serveTLS(configure func(options *adminapi.Options)) {
	f.t.Helper()
	options := adminapi.Options{Session: f.sessionService,
		ErrorCodes: onlineErrorCodes(), Now: fixedOnlineNow}
	if configure != nil {
		configure(&options)
	}
	server, err := adminapi.New(options)
	if err != nil {
		f.t.Fatalf("构造管理 API: %v", err)
	}
	f.handler = server
	f.server = httptest.NewTLSServer(server.Handler())
	f.t.Cleanup(f.server.Close)
}

// run 以强认证管理会话调用 CLI，并追加公共在线参数。
func (f *onlineFixture) run(args ...string) (string, string, int) {
	f.t.Helper()
	return f.runWithSession(f.sessionFile, args...)
}

// runWithSession 指定会话文件调用 CLI。
func (f *onlineFixture) runWithSession(sessionFile string,
	args ...string) (string, string, int) {
	f.t.Helper()
	full := append([]string{}, args...)
	full = append(full, "--server", f.server.URL, "--session-file", sessionFile)
	stdout, stderr, exit := runCLI(f.t, full...)
	f.requireNoSecretLeak(stdout, stderr)
	return stdout, stderr, exit
}

// runCLIWithCommon 以额外公共参数（如 --timeout、--ca-file）调用 CLI。
func (f *onlineFixture) runCLIWithCommon(sessionFile string,
	extra []string, args ...string) (string, string, int) {
	f.t.Helper()
	full := append([]string{}, args...)
	full = append(full, "--server", f.server.URL, "--session-file", sessionFile)
	full = append(full, extra...)
	stdout, stderr, exit := runCLI(f.t, full...)
	f.requireNoSecretLeak(stdout, stderr)
	return stdout, stderr, exit
}

// requireNoSecretLeak 断言输出没有泄露管理会话秘密。
func (f *onlineFixture) requireNoSecretLeak(stdout, stderr string) {
	f.t.Helper()
	combined := stdout + stderr
	if f.strongSecret != "" && strings.Contains(combined, f.strongSecret) {
		f.t.Fatalf("输出泄露了强认证管理会话秘密")
	}
	if f.plainSecret != "" && strings.Contains(combined, f.plainSecret) {
		f.t.Fatalf("输出泄露了普通会话秘密")
	}
}

// seedAuditEvent 直接写入一条审计事件（真实 audit 规范化 + SQLite）。
func (f *onlineFixture) seedAuditEvent(action string, outcome audit.Outcome,
	actorID string, at time.Time) string {
	f.t.Helper()
	prepared, err := audit.PrepareEvent(audit.Event{
		Actor:  audit.Actor{Type: audit.ActorUser, ID: actorID},
		Action: action, Target: audit.Target{Type: "user", ID: "target_1"},
		Outcome: outcome}, at)
	if err != nil {
		f.t.Fatalf("准备审计事件: %v", err)
	}
	if err := f.auditStore.Append(f.ctx, prepared); err != nil {
		f.t.Fatalf("写入审计事件: %v", err)
	}
	return prepared.ID
}

// requireOnlineSuccess 断言 --json 成功外壳并返回 data 对象。
func requireOnlineSuccess(t *testing.T, stdout string) map[string]any {
	t.Helper()
	envelope := decodeEnvelope(t, stdout)
	if ok, _ := envelope["ok"].(bool); !ok {
		t.Fatalf("--json 输出不是成功外壳: %s", stdout)
	}
	if requestID, _ := envelope["request_id"].(string); requestID == "" {
		t.Fatalf("成功输出缺少 request_id: %s", stdout)
	}
	data, _ := envelope["data"].(map[string]any)
	if data == nil {
		t.Fatalf("成功输出缺少 data 对象: %s", stdout)
	}
	return data
}

// requireOnlineFailure 断言 --json 失败外壳的退出码与稳定错误码。
func requireOnlineFailure(t *testing.T, stdout string, exit, wantExit int, wantCode string) {
	t.Helper()
	if exit != wantExit {
		t.Fatalf("退出码 = %d，期望 %d，输出=%s", exit, wantExit, stdout)
	}
	envelope := decodeEnvelope(t, stdout)
	if ok, _ := envelope["ok"].(bool); ok {
		t.Fatalf("失败输出 ok 应为 false: %s", stdout)
	}
	if code := envelopeErrorCode(t, envelope); code != wantCode {
		t.Fatalf("错误码 = %q，期望 %q，输出=%s", code, wantCode, stdout)
	}
}

// writeProtectedSecretFile 写入受保护秘密文件（平台权限检查可接受）。
func writeProtectedSecretFile(t *testing.T, name, secret string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
		t.Fatalf("写入秘密文件: %v", err)
	}
	if err := secrets.ProtectFile(path); err != nil {
		t.Fatalf("收紧秘密文件权限: %v", err)
	}
	return path
}

// grantOnline 是测试授权替身的公共写法：调用者 + 权限 + 范围。
func grantKey(callerID, permission, scopeID string) string {
	return callerID + "|" + permission + "|" + scopeID
}

// ===== auditops 接缝替身（业务逻辑与审计写入仍是真实的）=====

type onlineAuditAuthorizer struct {
	mu     sync.Mutex
	grants map[string]auditops.ScopeGrant
}

func newOnlineAuditAuthorizer() *onlineAuditAuthorizer {
	return &onlineAuditAuthorizer{grants: map[string]auditops.ScopeGrant{}}
}

func (f *onlineAuditAuthorizer) grant(callerID, permission, scopeID string,
	grant auditops.ScopeGrant) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.grants[grantKey(callerID, permission, scopeID)] = grant
}

func (f *onlineAuditAuthorizer) AuthorizeScope(_ context.Context,
	caller account.Caller, permissionKey, scopeID string) (auditops.ScopeGrant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.grants[grantKey(caller.Actor().ID, permissionKey, scopeID)], nil
}

// onlineRootFake 判定 root 身份。
type onlineRootFake struct {
	mu    sync.Mutex
	roots map[string]bool
}

func newOnlineRootFake() *onlineRootFake {
	return &onlineRootFake{roots: map[string]bool{}}
}

func (f *onlineRootFake) setRoot(callerID string, isRoot bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.roots[callerID] = isRoot
}

func (f *onlineRootFake) IsRoot(_ context.Context, caller account.Caller) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.roots[caller.Actor().ID], nil
}

// onlineSensitiveFake 是敏感策略（强认证）替身：deny 中的操作返回
// reauth.ErrReauthRequired，其余通过。
type onlineSensitiveFake struct {
	mu     sync.Mutex
	denied map[string]bool
}

func newOnlineSensitiveFake() *onlineSensitiveFake {
	return &onlineSensitiveFake{denied: map[string]bool{}}
}

func (f *onlineSensitiveFake) deny(operationID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.denied[operationID] = true
}

func (f *onlineSensitiveFake) allow(operationID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.denied, operationID)
}

func (f *onlineSensitiveFake) Authorize(_ context.Context, caller reauth.Caller,
	request reauth.Request) (reauth.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.denied[request.OperationID] {
		return reauth.Result{}, fmt.Errorf("%w: 需要再次认证", reauth.ErrReauthRequired)
	}
	return reauth.Result{OperationID: request.OperationID,
		TargetType: request.TargetType, TargetID: request.TargetID,
		UserID: caller.Actor().ID, RequestID: request.RequestID}, nil
}

func (f *onlineSensitiveFake) NotifyOutcome(_ context.Context, _ reauth.Result,
	_ reauth.Outcome) error {
	return nil
}

// onlineEnqueuerFake 记录最近一次入队请求并返回 queued 任务。
type onlineEnqueuerFake struct {
	mu   sync.Mutex
	last task.EnqueueRequest
}

func (f *onlineEnqueuerFake) Enqueue(_ context.Context,
	request task.EnqueueRequest) (task.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.last = request
	return task.Job{ID: "job_00000000000000000000000000000001",
		Kind: request.Kind, State: task.StateQueued, Initiator: request.Actor,
		Payload: request.Payload, TimeoutSeconds: request.TimeoutSeconds,
		MaxAttempts: request.MaxAttempts, RequestID: request.RequestID,
		CreatedAt: onlineTestNow}, nil
}

// onlineCancellerFake 接受取消请求（接受不等于已取消）。
type onlineCancellerFake struct{}

func (f *onlineCancellerFake) RequestCancel(_ context.Context,
	request task.CancelRequest) (task.CancelResult, error) {
	return task.CancelResult{Accepted: true,
		State: task.StateCancelRequested}, nil
}

// onlineAuditTaskReader 提供 auditops 任务摘要读取。
type onlineAuditTaskReader struct {
	mu   sync.Mutex
	jobs map[string]task.Job
}

func newOnlineAuditTaskReader() *onlineAuditTaskReader {
	return &onlineAuditTaskReader{jobs: map[string]task.Job{}}
}

func (f *onlineAuditTaskReader) Get(_ context.Context,
	id string) (task.Job, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	job, found := f.jobs[id]
	return job, found, nil
}

// ===== reports 接缝替身（历史存储与业务逻辑是真实的）=====

type onlineStatsAuthorizer struct {
	mu     sync.Mutex
	grants map[string]stats.ScopeGrant
}

func newOnlineStatsAuthorizer() *onlineStatsAuthorizer {
	return &onlineStatsAuthorizer{grants: map[string]stats.ScopeGrant{}}
}

func (f *onlineStatsAuthorizer) grant(callerID, permission, scopeID string,
	grant stats.ScopeGrant) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.grants[grantKey(callerID, permission, scopeID)] = grant
}

func (f *onlineStatsAuthorizer) revoke(callerID, permission, scopeID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.grants, grantKey(callerID, permission, scopeID))
}

func (f *onlineStatsAuthorizer) AuthorizeScope(_ context.Context,
	caller account.Caller, permissionKey, scopeID string) (stats.ScopeGrant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.grants[grantKey(caller.Actor().ID, permissionKey, scopeID)], nil
}

// onlineReportsAudit 是报告/管理 API 共用审计写入替身（不访问真实数据库的目的
// 仅是减少装配；报告业务逻辑仍为真实服务）。
type onlineReportsAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (f *onlineReportsAudit) Record(_ context.Context, event audit.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, event)
	return nil
}

func (f *onlineReportsAudit) RecordFailure(_ context.Context, event audit.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, event)
	return nil
}

func (f *onlineReportsAudit) ExecuteCritical(_ context.Context,
	_ audit.CriticalRequest, _ audit.Change) error {
	return nil
}

// onlineStatsSource 是报告统计数据源替身（本测试只覆盖历史读路径与令牌下载，
// 不触发真实生成）。
type onlineStatsSource struct{}

func (f *onlineStatsSource) Activity(_ context.Context,
	_ stats.ActivityRequest) (stats.ActivityResult, error) {
	return stats.ActivityResult{}, nil
}

func (f *onlineStatsSource) Errors(_ context.Context,
	_ stats.ErrorRequest) (stats.ErrorResult, error) {
	return stats.ErrorResult{}, nil
}

func (f *onlineStatsSource) ErrorTrend(_ context.Context,
	_ stats.ErrorTrendRequest) (stats.ErrorTrendResult, error) {
	return stats.ErrorTrendResult{}, nil
}

// ===== adminapi 任务/通知/备份接缝替身 =====

// onlineTaskReader 是 adminapi.TaskReader 替身。
type onlineTaskReader struct {
	mu   sync.Mutex
	jobs map[string]task.Job
}

func newOnlineTaskReader() *onlineTaskReader {
	return &onlineTaskReader{jobs: map[string]task.Job{}}
}

func (f *onlineTaskReader) add(job task.Job) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jobs[job.ID] = job
}

func (f *onlineTaskReader) Get(_ context.Context, id string) (task.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	job, found := f.jobs[id]
	if !found {
		return task.Job{}, task.ErrTaskNotFound
	}
	return job, nil
}

func (f *onlineTaskReader) Attempts(_ context.Context, id string) ([]task.Attempt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, found := f.jobs[id]; !found {
		return nil, task.ErrTaskNotFound
	}
	return []task.Attempt{{Attempt: 1, StartedAt: onlineTestNow,
		Outcome: "success"}}, nil
}

// onlineTaskAuthorizer 是 adminapi.TaskAuthorizer 替身：deny 时统一拒绝。
type onlineTaskAuthorizer struct {
	deny bool
}

func (f *onlineTaskAuthorizer) AuthorizeTaskRead(_ context.Context,
	_ account.Caller, _ task.Job) error {
	if f.deny {
		return fmt.Errorf("测试拒绝任务读取")
	}
	return nil
}

// onlineNotificationsFake 是 adminapi.NotificationService 替身。
type onlineNotificationsFake struct {
	localCapture bool
	failStatus   error
}

func (f *onlineNotificationsFake) NotificationStatus(_ context.Context,
	_ account.Caller) (adminapi.NotificationStatus, error) {
	if f.failStatus != nil {
		return adminapi.NotificationStatus{}, f.failStatus
	}
	status := adminapi.NotificationStatus{Enabled: true,
		LocalCapture: f.localCapture, Channels: []string{"mail"},
		DeliveryMode: "local_capture", Note: "测试本地捕获器"}
	if !f.localCapture {
		status.DeliveryMode = "smtp"
	}
	return status, nil
}

func (f *onlineNotificationsFake) TestNotification(_ context.Context,
	_ account.Caller, _ string) (adminapi.NotificationTestResult, error) {
	return adminapi.NotificationTestResult{CaptureID: "cap_1", Channel: "mail",
		RecipientMasked: "t***@example.test", CapturedAt: onlineTestNow,
		Note: "本地捕获"}, nil
}

// onlineBackupFake 是 adminapi.BackupService 的线级契约替身：真实 adminapi 传输
// 与 CLI 不变，仅领域实现被替换（backupadmin 真实装配成本高，见报告边界说明）。
type onlineBackupFake struct {
	mu sync.Mutex

	deny bool
	// conflictRetention 让 SaveRetention 返回版本冲突。
	conflictRetention bool
	// lastSchedule 记录最近一次创建/编辑请求。
	lastSchedule backupadmin.ScheduleRequest
	// downloadData 是下载令牌兑换返回的字节。
	downloadData []byte
}

func newOnlineBackupFake() *onlineBackupFake {
	return &onlineBackupFake{downloadData: []byte("backup-archive-bytes")}
}

func (f *onlineBackupFake) accessDenied() error {
	if f.deny {
		return fmt.Errorf("%w: 测试拒绝", backupadmin.ErrAccessDenied)
	}
	return nil
}

func (f *onlineBackupFake) CheckReadAccess(_ context.Context, _ account.Caller) error {
	return f.accessDenied()
}

func (f *onlineBackupFake) Capabilities(_ context.Context,
	_ account.Caller) (backupadmin.Capabilities, error) {
	if err := f.accessDenied(); err != nil {
		return backupadmin.Capabilities{}, err
	}
	return backupadmin.Capabilities{Read: true, Create: true, Cancel: true,
		Download: true, Retention: true, Cleanup: true,
		DownloadTTL: 5 * time.Minute}, nil
}

// backupArtifact 返回固定的备份产物视图。
func (f *onlineBackupFake) backupArtifact() backupadmin.ArtifactView {
	return backupadmin.ArtifactView{BackupID: "bak_00000000000000000000000000000001",
		JobID: "job_00000000000000000000000000000002", Origin: "manual",
		SizeBytes: 1234, FileSHA256: strings.Repeat("a", 64),
		FormatVersion: 1, ContentDatabase: true, EntryCount: 3,
		Verification: "verified", RetentionVersion: 1, Cleanup: "none",
		CreatedAt: onlineTestNow, PublishedAt: onlineTestNow, FileExists: true,
		IsLastUsable: true, Downloadable: true}
}

func (f *onlineBackupFake) backupSchedule() backupadmin.ScheduleView {
	return backupadmin.ScheduleView{ID: "sch_00000000000000000000000000000001",
		Name: "每日备份", Enabled: true, ScheduleType: "daily",
		Expression: "02:00", TimeZone: "UTC", MissedPolicy: "skip",
		MaxCatchUp: 3, TimeoutSeconds: 600, MaxAttempts: 2,
		Owner:          audit.Actor{Type: audit.ActorUser, ID: testUserID(40)},
		ExecutionActor: audit.Actor{Type: audit.ActorUser, ID: testUserID(40)},
		ScopeID:        "system", RetentionVersion: 1,
		CreatedAt: onlineTestNow, UpdatedAt: onlineTestNow}
}

func (f *onlineBackupFake) ListArtifacts(_ context.Context, _ account.Caller,
	_ backupadmin.ArtifactFilter) ([]backupadmin.ArtifactView, bool, error) {
	if err := f.accessDenied(); err != nil {
		return nil, false, err
	}
	return []backupadmin.ArtifactView{f.backupArtifact()}, false, nil
}

func (f *onlineBackupFake) GetArtifact(_ context.Context, _ account.Caller,
	backupID string) (backupadmin.ArtifactView, error) {
	if err := f.accessDenied(); err != nil {
		return backupadmin.ArtifactView{}, err
	}
	artifact := f.backupArtifact()
	artifact.BackupID = backupID
	return artifact, nil
}

func (f *onlineBackupFake) ListJobs(_ context.Context, _ account.Caller,
	_ backupadmin.JobFilter) ([]backupadmin.JobView, bool, error) {
	if err := f.accessDenied(); err != nil {
		return nil, false, err
	}
	return []backupadmin.JobView{}, false, nil
}

func (f *onlineBackupFake) GetJob(_ context.Context, _ account.Caller,
	_ string) (backupadmin.JobView, error) {
	if err := f.accessDenied(); err != nil {
		return backupadmin.JobView{}, err
	}
	return backupadmin.JobView{ID: "job_1", Kind: "backup.create", State: "queued",
		Initiator: audit.Actor{Type: audit.ActorUser, ID: testUserID(40)},
		CreatedAt: onlineTestNow}, nil
}

func (f *onlineBackupFake) EnqueueBackup(_ context.Context, _ account.Caller,
	_ string) (backupadmin.JobRef, error) {
	if err := f.accessDenied(); err != nil {
		return backupadmin.JobRef{}, err
	}
	return backupadmin.JobRef{JobID: "job_1", State: "queued"}, nil
}

func (f *onlineBackupFake) CancelJob(_ context.Context, _ account.Caller,
	jobID, _, _ string) (backupadmin.CancelView, error) {
	if err := f.accessDenied(); err != nil {
		return backupadmin.CancelView{}, err
	}
	return backupadmin.CancelView{JobID: jobID, Accepted: true,
		State: "cancel_requested"}, nil
}

func (f *onlineBackupFake) IssueDownloadTicket(_ context.Context, _ account.Caller,
	backupID, _ string) (backupadmin.DownloadTicket, error) {
	if err := f.accessDenied(); err != nil {
		return backupadmin.DownloadTicket{}, err
	}
	return backupadmin.DownloadTicket{BackupID: backupID,
		Token:     strings.Repeat("a", 64),
		ExpiresAt: onlineTestNow.Add(5 * time.Minute)}, nil
}

func (f *onlineBackupFake) RedeemDownloadTicket(_ context.Context, _ account.Caller,
	_ string, _ string) (backupadmin.DownloadFile, error) {
	if err := f.accessDenied(); err != nil {
		return backupadmin.DownloadFile{}, err
	}
	digest := sha256.Sum256(f.downloadData)
	return backupadmin.DownloadFile{BackupID: "bak_1", FileName: "backup-bak_1.bin",
		ContentType: "application/octet-stream",
		SHA256:      hex.EncodeToString(digest[:]), Size: int64(len(f.downloadData)),
		Data: f.downloadData}, nil
}

func (f *onlineBackupFake) Retention(_ context.Context,
	_ account.Caller) (backupadmin.RetentionView, error) {
	if err := f.accessDenied(); err != nil {
		return backupadmin.RetentionView{}, err
	}
	return backupadmin.RetentionView{IsDefault: false,
		Policy: backupadmin.RetentionPolicy{Version: 3, MaxCount: 10, MaxAgeDays: 30,
			MaxTotalBytes: 1 << 30, UpdatedAt: onlineTestNow,
			UpdatedBy: audit.Actor{Type: audit.ActorUser, ID: testUserID(40)}}}, nil
}

func (f *onlineBackupFake) SaveRetention(_ context.Context,
	change backupadmin.RetentionChange) (backupadmin.RetentionView, error) {
	if err := f.accessDenied(); err != nil {
		return backupadmin.RetentionView{}, err
	}
	if f.conflictRetention {
		return backupadmin.RetentionView{}, backupadmin.ErrConflict
	}
	return backupadmin.RetentionView{Policy: backupadmin.RetentionPolicy{
		Version: change.ExpectedVersion + 1, MaxCount: change.MaxCount,
		MaxAgeDays: change.MaxAgeDays, MaxTotalBytes: change.MaxTotalBytes,
		UpdatedAt: onlineTestNow, Reason: change.Reason}}, nil
}

func (f *onlineBackupFake) CleanupPreview(_ context.Context,
	_ account.Caller) (backupadmin.CleanupPreview, error) {
	if err := f.accessDenied(); err != nil {
		return backupadmin.CleanupPreview{}, err
	}
	return backupadmin.CleanupPreview{TotalRetained: 1, TotalBytes: 1234,
		PreviewedAt: onlineTestNow, Note: "测试预览"}, nil
}

func (f *onlineBackupFake) EnqueueCleanup(_ context.Context, _ account.Caller,
	_ string) (backupadmin.JobRef, error) {
	if err := f.accessDenied(); err != nil {
		return backupadmin.JobRef{}, err
	}
	return backupadmin.JobRef{JobID: "job_cleanup_1", State: "queued"}, nil
}

func (f *onlineBackupFake) ListSchedules(_ context.Context,
	_ account.Caller) ([]backupadmin.ScheduleView, error) {
	if err := f.accessDenied(); err != nil {
		return nil, err
	}
	return []backupadmin.ScheduleView{f.backupSchedule()}, nil
}

// ListSchedulesPage 是步骤 218 的分页契约替身：从 ListSchedules 结果切页。
func (f *onlineBackupFake) ListSchedulesPage(ctx context.Context, caller account.Caller,
	limit, offset int) ([]backupadmin.ScheduleView, bool, error) {
	views, err := f.ListSchedules(ctx, caller)
	if err != nil {
		return nil, false, err
	}
	if limit <= 0 {
		limit = 20
	}
	if offset < 0 || offset >= len(views) {
		return []backupadmin.ScheduleView{}, false, nil
	}
	end := offset + limit
	if end > len(views) {
		end = len(views)
	}
	return views[offset:end], end < len(views), nil
}

func (f *onlineBackupFake) GetSchedule(_ context.Context, _ account.Caller,
	scheduleID string) (backupadmin.ScheduleView, error) {
	if err := f.accessDenied(); err != nil {
		return backupadmin.ScheduleView{}, err
	}
	schedule := f.backupSchedule()
	schedule.ID = scheduleID
	return schedule, nil
}

func (f *onlineBackupFake) CreateSchedule(_ context.Context,
	request backupadmin.ScheduleRequest) (backupadmin.ScheduleView, error) {
	if err := f.accessDenied(); err != nil {
		return backupadmin.ScheduleView{}, err
	}
	f.mu.Lock()
	f.lastSchedule = request
	f.mu.Unlock()
	schedule := f.backupSchedule()
	schedule.Name = request.Name
	schedule.ScheduleType = string(request.ScheduleType)
	schedule.Expression = request.Expression
	return schedule, nil
}

func (f *onlineBackupFake) UpdateSchedule(_ context.Context, scheduleID string,
	request backupadmin.ScheduleRequest) (backupadmin.ScheduleView, error) {
	if err := f.accessDenied(); err != nil {
		return backupadmin.ScheduleView{}, err
	}
	f.mu.Lock()
	f.lastSchedule = request
	f.mu.Unlock()
	schedule := f.backupSchedule()
	schedule.ID = scheduleID
	schedule.Name = request.Name
	schedule.Expression = request.Expression
	schedule.Enabled = request.Enabled
	return schedule, nil
}

func (f *onlineBackupFake) SetScheduleEnabled(_ context.Context, _ account.Caller,
	scheduleID string, enabled bool, _, _ string) (backupadmin.ScheduleView, error) {
	if err := f.accessDenied(); err != nil {
		return backupadmin.ScheduleView{}, err
	}
	schedule := f.backupSchedule()
	schedule.ID = scheduleID
	schedule.Enabled = enabled
	return schedule, nil
}

func (f *onlineBackupFake) DeleteSchedule(_ context.Context, _ account.Caller,
	_ string, _, _ string) error {
	return f.accessDenied()
}

// ===== 编译期确认替身满足领域接缝 =====

var (
	_ auditops.Authorizer      = (*onlineAuditAuthorizer)(nil)
	_ auditops.RootChecker     = (*onlineRootFake)(nil)
	_ auditops.SensitiveRunner = (*onlineSensitiveFake)(nil)
	_ auditops.Enqueuer        = (*onlineEnqueuerFake)(nil)
	_ auditops.Canceller       = (*onlineCancellerFake)(nil)
	_ auditops.TaskReader      = (*onlineAuditTaskReader)(nil)

	_ reports.Authorizer      = (*onlineStatsAuthorizer)(nil)
	_ reports.RootChecker     = (*onlineRootFake)(nil)
	_ reports.SensitiveRunner = (*onlineSensitiveFake)(nil)
	_ reports.AuditRecorder   = (*onlineReportsAudit)(nil)
	_ reports.Enqueuer        = (*onlineEnqueuerFake)(nil)
	_ reports.Canceller       = (*onlineCancellerFake)(nil)
	_ reports.Source          = (*onlineStatsSource)(nil)

	_ adminapi.BackupService       = (*onlineBackupFake)(nil)
	_ adminapi.NotificationService = (*onlineNotificationsFake)(nil)
	_ adminapi.TaskReader          = (*onlineTaskReader)(nil)
	_ adminapi.TaskAuthorizer      = (*onlineTaskAuthorizer)(nil)
	_ adminapi.AuditRecorder       = (*onlineReportsAudit)(nil)
	_ reauth.OperationRunner       = (*onlineSensitiveFake)(nil)
)
