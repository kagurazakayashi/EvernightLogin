package restore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/avatar"
	"github.com/kagurazakayashi/EvernightLogin/internal/backup"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	appmigrations "github.com/kagurazakayashi/EvernightLogin/migrations"
)

// 测试固定时钟：清单与恢复记录时间可断言；随机源使用真实 crypto/rand。
var restoreTestClock = time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

// testEnv 是使用真实临时 SQLite、真实备份服务、真实审计与真实恢复服务的测试环境。
type testEnv struct {
	t             *testing.T
	root          string
	dbDir         string
	dbPath        string
	stateDir      string
	backupDir     string
	avatarsDir    string
	configPath    string
	ring          *secrets.Keyring
	migrations    []migrate.Migration
	clock         func() time.Time
	withAttach    bool
	withConfig    bool
	backupService *backup.Service
}

// newTestEnv 构造隔离测试环境：数据库目录、库外状态目录、回退备份目录与附件目录
// 全部位于 t.TempDir() 下，互不重叠。
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	root := t.TempDir()
	env := &testEnv{
		t:          t,
		root:       root,
		dbDir:      filepath.Join(root, "data"),
		stateDir:   filepath.Join(root, "restore-state"),
		backupDir:  filepath.Join(root, "backups"),
		avatarsDir: filepath.Join(root, "avatars"),
		configPath: filepath.Join(root, "login.yaml"),
		clock:      func() time.Time { return restoreTestClock },
	}
	env.dbPath = filepath.Join(env.dbDir, "login.db")
	for _, directory := range []string{env.dbDir, env.backupDir, env.avatarsDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatalf("创建测试目录失败：%v", err)
		}
	}
	if err := os.WriteFile(env.configPath,
		[]byte("server:\n  listen_addr: 127.0.0.1:8080\n"), 0o600); err != nil {
		t.Fatalf("写入测试配置失败：%v", err)
	}
	migrations, err := migrate.LoadMigrations(appmigrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移失败：%v", err)
	}
	env.migrations = migrations
	ring, err := secrets.GenerateKeyring("k1", restoreTestClock)
	if err != nil {
		t.Fatalf("生成测试密钥环失败：%v", err)
	}
	env.ring = ring
	return env
}

// openStore 打开测试数据库（调用方负责关闭）。
func (e *testEnv) openStore(t *testing.T, wal bool) *storagesqlite.Store {
	t.Helper()
	options := storagesqlite.DefaultOptions(e.dbPath)
	options.WAL = wal
	store, err := storagesqlite.Open(context.Background(), options)
	if err != nil {
		t.Fatalf("打开测试数据库失败：%v", err)
	}
	return store
}

// mustMigrate 对测试数据库执行全部迁移。
func (e *testEnv) mustMigrate(t *testing.T, store *storagesqlite.Store) {
	t.Helper()
	if _, err := store.Migrate(context.Background(), e.migrations); err != nil {
		t.Fatalf("执行迁移失败：%v", err)
	}
}

// provider 返回测试主密钥环提供者。
func (e *testEnv) provider() secrets.Provider {
	return secrets.ProviderFunc(func(ctx context.Context) ([]byte, error) {
		return e.ring.Document()
	})
}

// keyring 返回认证解密用测试密钥环。
func (e *testEnv) keyring() *secrets.Keyring { return e.ring }

// caller 返回本地应急管理员调用者。
func (e *testEnv) caller(t *testing.T) account.Caller {
	t.Helper()
	caller, err := account.LocalBootstrapCaller("os:tester@test-host")
	if err != nil {
		t.Fatalf("构造本地管理员调用者失败：%v", err)
	}
	return caller
}

// allowAuthorizer 是测试授权器：只对本地管理员放行，用于验证真实服务授权调用语义。
type allowAuthorizer struct{}

// AuthorizeScope 实现 stats.Authorizer。
func (allowAuthorizer) AuthorizeScope(_ context.Context, caller account.Caller,
	permissionKey, scopeID string) (stats.ScopeGrant, error) {
	if caller.Actor().Type != audit.ActorLocalAdmin || scopeID != ScopeSystem {
		return stats.ScopeGrant{}, nil
	}
	switch permissionKey {
	case PermissionRestore, backup.PermissionCreate, backup.PermissionCancel:
		return stats.ScopeGrant{Allowed: true, AllData: true}, nil
	default:
		return stats.ScopeGrant{}, nil
	}
}

// newAuditRecorder 在指定数据库上构造真实审计写入器。
func (e *testEnv) newAuditRecorder(t *testing.T, store *storagesqlite.Store) *audit.Recorder {
	t.Helper()
	auditStore, err := auditsqlite.New(store)
	if err != nil {
		t.Fatalf("构造审计存储失败：%v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{Now: e.clock})
	if err != nil {
		t.Fatalf("构造审计写入器失败：%v", err)
	}
	return recorder
}

// newBackupService 用给定已打开数据库构造真实备份服务（SQLite 在线快照 + 认证加密）。
func (e *testEnv) newBackupService(t *testing.T,
	store *storagesqlite.Store) *backup.Service {
	t.Helper()
	snapshotter, err := backup.NewSQLiteSnapshotter(store)
	if err != nil {
		t.Fatalf("构造 SQLite 快照器失败：%v", err)
	}
	options := backup.Options{
		Snapshotter: snapshotter,
		Keyring:     e.provider(),
		Authorizer:  allowAuthorizer{},
		Audit:       e.newAuditRecorder(t, store),
		OutputDir:   e.backupDir,
		Hostname:    "test-host",
		AppVersion:  loginVersionForTest(),
		Now:         e.clock,
	}
	if e.withAttach {
		storage, err := avatar.NewLocalStorage(e.avatarsDir)
		if err != nil {
			t.Fatalf("构造附件存储失败：%v", err)
		}
		source, err := backup.NewAvatarAttachmentSource(storage)
		if err != nil {
			t.Fatalf("构造附件源失败：%v", err)
		}
		options.Attachments = source
	}
	if e.withConfig {
		source, err := backup.NewFileConfigSource(e.configPath, 0)
		if err != nil {
			t.Fatalf("构造配置源失败：%v", err)
		}
		options.Config = source
	}
	service, err := backup.New(options)
	if err != nil {
		t.Fatalf("构造备份服务失败：%v", err)
	}
	return service
}

// loginVersionForTest 返回备份清单中的测试应用版本标识。
func loginVersionForTest() string { return "test-version" }

// createBackup 用当前数据库内容创建一份真实加密备份并返回结果。
func (e *testEnv) createBackup(t *testing.T) backup.Result {
	t.Helper()
	store := e.openStore(t, true)
	defer func() { _ = store.Close() }()
	service := e.newBackupService(t, store)
	result, err := service.Create(context.Background(), backup.CreateRequest{
		Caller: e.caller(t), RequestID: "req_restore_seed_backup"})
	if err != nil {
		t.Fatalf("创建种子备份失败：%v", err)
	}
	return result
}

// rollbackBackupHook 构造真实回退备份实现：打开数据库、构造备份服务并创建新备份。
func (e *testEnv) rollbackBackupHook() RollbackBackupFunc {
	return func(ctx context.Context, caller account.Caller,
		requestID string) (backup.Result, error) {
		store, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(e.dbPath))
		if err != nil {
			return backup.Result{}, err
		}
		defer func() { _ = store.Close() }()
		service := e.newBackupService(e.t, store)
		return service.Create(ctx, backup.CreateRequest{Caller: caller, RequestID: requestID})
	}
}

// restoreOptions 返回真实恢复服务构造参数；configure 可注入故障/替代密钥环等。
func (e *testEnv) restoreOptions(t *testing.T, configure func(*Options)) Options {
	t.Helper()
	options := Options{
		DatabasePath:    e.dbPath,
		StateDir:        e.stateDir,
		Migrations:      e.migrations,
		Keyring:         e.provider(),
		RollbackBackup:  e.rollbackBackupHook(),
		BackupOutputDir: e.backupDir,
		AttachmentsDir:  e.avatarsDir,
		Authorizer:      allowAuthorizer{},
		Now:             e.clock,
		FreeBytes: func(string) (uint64, error) {
			return 1 << 40, nil
		},
	}
	if configure != nil {
		configure(&options)
	}
	return options
}

// newRestoreService 构造真实恢复服务；configure 可注入故障/替代密钥环等测试选项。
func (e *testEnv) newRestoreService(t *testing.T,
	configure func(*Options)) *Service {
	t.Helper()
	options := e.restoreOptions(t, configure)
	service, err := New(options)
	if err != nil {
		t.Fatalf("构造恢复服务失败：%v", err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if service.StateMissing() {
		if err := service.InitState(context.Background(), InitStateRequest{
			Caller: e.caller(t), Reason: "测试初始化库外恢复状态",
			RequestID: "req_test_init_state"}); err != nil {
			t.Fatalf("初始化库外恢复状态失败：%v", err)
		}
	}
	return service
}

// seededIDs 是种子数据的关键标识，供测试断言引用。
type seededIDs struct {
	rootUserID string
	userID     string
	appID      string
	sessionID  string
}

// seedDatabase 写入恢复测试所需的账户、应用、会话、刷新令牌、授权码、恢复代码、
// 验证链接、找回链接、扫码请求、调度计划、Webhook、任务与邮件投递等数据。
func (e *testEnv) seedDatabase(t *testing.T, store *storagesqlite.Store) seededIDs {
	t.Helper()
	ctx := context.Background()
	nowMS := e.clock().UnixMilli()
	expires := nowMS + 3600_000
	ids := seededIDs{
		rootUserID: "usr_root_" + strings.Repeat("0", 8),
		userID:     "usr_user_" + strings.Repeat("1", 8),
		appID:      "app_seed_" + strings.Repeat("2", 8),
		sessionID:  "ses_" + strings.Repeat("3", 32),
	}
	mustExec := func(query string, args ...any) {
		t.Helper()
		if _, err := store.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("种子 SQL 失败（%s）：%v", firstLine(query), err)
		}
	}
	mustExec(`INSERT INTO users(id,username,username_normalized,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?,?,?)`, ids.rootUserID, "root", "root", "active", 1, 3, 1, nowMS, nowMS)
	mustExec(`INSERT INTO users(id,username,username_normalized,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?,?,?)`, ids.userID, "alice", "alice", "active", 0, 2, 1, nowMS, nowMS)
	mustExec(`INSERT INTO applications(id,name,status,client_type,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?)`, ids.appID, "测试应用", "active", "confidential", nowMS, nowMS)

	// 会话（正常种类；security_version 与用户一致）。
	mustExec(`INSERT INTO sessions(id,user_id,app_id,kind,restricted_reason,
required_steps_json,security_version,secret_digest,csrf_digest,key_id,
created_at_ms,last_seen_at_ms,idle_expires_at_ms,absolute_expires_at_ms)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, ids.sessionID, ids.userID, nil, "normal", "",
		"[]", 2, bytesOf(32, 1), bytesOf(32, 2), "k1", nowMS, nowMS, expires, expires+3600_000)

	// 刷新令牌族与令牌。
	mustExec(`INSERT INTO refresh_token_families(id,client_id,subject_user_id,
authorization_id,scope,audiences_json,security_version,created_at_ms,
absolute_expires_at_ms,idle_timeout_ms)
VALUES(?,?,?,?,?,?,?,?,?,?)`, "fam_"+strings.Repeat("4", 20), ids.appID, ids.userID,
		"auth_1", "openid", `["system"]`, 2, nowMS, expires+3600_000, 3600_000)
	mustExec(`INSERT INTO refresh_tokens(id,family_id,token_sha256,status,
issued_at_ms,idle_expires_at_ms,expires_at_ms)
VALUES(?,?,?,?,?,?,?)`, "rt_"+strings.Repeat("5", 20), "fam_"+strings.Repeat("4", 20),
		bytesOf(32, 3), "active", nowMS, expires, expires+3600_000)

	// 授权请求与授权码。
	mustExec(`INSERT INTO oauth_authorization_requests(id,user_id,client_id,
redirect_uri,response_type,scope,audience_json,state,nonce,code_challenge,
code_challenge_method,session_id,security_version,status,created_at_ms,expires_at_ms)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, "oar_"+strings.Repeat("6", 20),
		ids.userID, ids.appID, "https://app.example/cb", "code", "openid", `["system"]`,
		"state", "", strings.Repeat("A", 43), "S256", ids.sessionID, 2, "pending",
		nowMS, nowMS+60000)
	mustExec(`INSERT INTO oauth_authorization_codes(id,code_sha256,
authorization_request_id,user_id,client_id,redirect_uri,scope,audience_json,
nonce,code_challenge,code_challenge_method,session_id,security_version,
issued_at_ms,expires_at_ms)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, "oac_"+strings.Repeat("7", 20),
		bytesOf(32, 4), "oar_"+strings.Repeat("6", 20), ids.userID, ids.appID,
		"https://app.example/cb", "openid", `["system"]`, "", strings.Repeat("B", 43),
		"S256", ids.sessionID, 2, nowMS, nowMS+60000)

	// 恢复代码组与恢复代码。
	mustExec(`INSERT INTO recovery_code_groups(id,user_id,generation,status,
code_count,created_at_ms) VALUES(?,?,?,?,?,?)`, "rcg_"+strings.Repeat("8", 16),
		ids.userID, 1, "active", 8, nowMS)
	mustExec(`INSERT INTO recovery_codes(id,group_id,user_id,digest,key_id,
created_at_ms) VALUES(?,?,?,?,?,?)`, "rcd_"+strings.Repeat("9", 16),
		"rcg_"+strings.Repeat("8", 16), ids.userID, bytesOf(32, 5), "k1", nowMS)

	// 邮箱验证链接与找回密码链接。
	mustExec(`INSERT INTO email_verification_tickets(user_id,credential_id,email,
email_normalized,created_at_ms,expires_at_ms) VALUES(?,?,?,?,?,?)`,
		ids.userID, "cred_"+strings.Repeat("a", 16), "alice@example.com",
		"alice@example.com", nowMS, expires)
	mustExec(`INSERT INTO password_reset_requests(id,user_id,masked_email,
credential_id,token_sha256,state,created_at_ms,expires_at_ms)
VALUES(?,?,?,?,?,?,?,?)`, "psr_"+strings.Repeat("b", 16), ids.userID, "a***@example.com",
		"cred_"+strings.Repeat("a", 16), bytesOf(32, 6), "pending", nowMS, expires)

	// 扫码登录请求与设备码授权。
	mustExec(`INSERT INTO app_qr_login_requests(id,claim_digest,claim_key_id,
client_id,scopes_json,request_version,status,interval_seconds,created_at_ms,
expires_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?)`, "qrl_"+strings.Repeat("c", 20),
		bytesOf(32, 7), "k1", ids.appID, `["openid"]`, 1, "pending", 5, nowMS, expires)
	mustExec(`INSERT INTO oauth_device_authorizations(id,device_code_sha256,
user_code_digest,user_code_key_id,client_id,scope,audience_json,status,
created_at_ms,expires_at_ms,interval_seconds)
VALUES(?,?,?,?,?,?,?,?,?,?,?)`, "dev_"+strings.Repeat("d", 20), bytesOf(32, 8),
		bytesOf(32, 9), "k1", ids.appID, "openid", `["system"]`, "pending", nowMS,
		expires, 5)

	// 调度计划、Webhook 端点、在途任务与待发邮件。
	mustExec(`INSERT INTO schedules(id,kind,schedule_type,expression,timezone,
owner_type,owner_id,execution_type,execution_id,scope_id,enabled,
permission_required,missed_policy,max_catch_up,config_json,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, "sch_"+strings.Repeat("e", 16),
		"report.generate", "daily", "0 2 * * *", "Asia/Shanghai", "system", "test-owner",
		"system", "test-executor", "system", 1, 1, "skip", 24, "{}", nowMS, nowMS)
	mustExec(`INSERT INTO webhook_endpoints(id,application_id,url,description,
status,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?,?)`, "whk_"+strings.Repeat("f", 16), ids.appID,
		"https://example.com/hook", "测试端点", "active", 1, nowMS, nowMS)
	mustExec(`INSERT INTO jobs(id,kind,state,initiated_by_type,initiated_by_id,
timeout_seconds,payload_json,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?,?,?)`, "job_"+strings.Repeat("1", 16), "mail.deliver", "queued",
		"system", "test-system", 60, "{}", nowMS, nowMS)
	mustExec(`INSERT INTO mail_deliveries(id,idempotency_key,template_kind,recipient,
owner_type,owner_id,state,attempts,max_attempts,sealed_payload,created_at_ms,
updated_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, "mail_"+strings.Repeat("2", 16),
		"idem-restore-test", "verification", "alice@example.com", "system", "test-system",
		"queued", 0, 1, []byte("sealed-payload"), nowMS, nowMS)

	// 旧 Webhook 事件/投递（queued）与旧人工恢复批准、注册审核批准：恢复后都不得
	// 保留可重放/可重发状态。
	mustExec(`INSERT INTO webhook_events(id,idempotency_key,type,application_id,
subject_user_id,payload_json,truncated,request_id,occurred_at_ms,created_at_ms)
VALUES(?,?,?,?,?,?,?,?,?,?)`, "whe_"+strings.Repeat("3", 20), "idem-webhook-restore",
		"account.disabled", ids.appID, ids.userID, `{"v":1}`, 0, "", nowMS, nowMS)
	mustExec(`INSERT INTO webhook_deliveries(id,event_id,endpoint_id,application_id,
state,attempts,max_attempts,task_id,last_error_code,last_error_kind,
last_response_status,request_id,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, "whd_"+strings.Repeat("4", 20),
		"whe_"+strings.Repeat("3", 20), "whk_"+strings.Repeat("f", 16), ids.appID,
		"queued", 0, 3, "", "", "", 0, "", nowMS, nowMS)
	mustExec(`INSERT INTO manual_recovery_requests(id,target_user_id,initiator_user_id,
operation_type,status,verification_basis,verification_reference,evidence_digest,
reason,delivery_channel,delivery_fingerprint,target_security_version,
target_high_privilege,content_digest,expires_at_ms,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, "mrr_"+strings.Repeat("5", 20),
		ids.userID, ids.rootUserID, "password_reset", "approved",
		"in_person_identity_document", "ref-001", bytesOf(32, 13), "测试旧批准",
		"verified_email", "fingerprint-001", 2, 0, bytesOf(32, 14),
		expires, nowMS, nowMS)
	mustExec(`INSERT INTO registration_reviews(user_id,status,reason,
decided_by_type,decided_by_id,decided_at_ms,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?,?)`, ids.userID, "approved", "测试旧审核批准",
		"local_admin", "os:tester@test-host", nowMS, nowMS, nowMS)
	// 令牌签名密钥（恢复后必须删除，使旧离线 JWT 在签名校验处失效）。
	mustExec(`INSERT INTO token_signing_keys(kid,algorithm,status,public_jwk,
sealed_private,created_at_ms,activated_at_ms)
VALUES(?,?,?,?,?,?,?)`, "kid_restore_test", "ES256", "active", []byte(`{"kty":"EC"}`),
		bytesOf(64, 10), nowMS, nowMS)

	// 备份时的既有审计事件：恢复后应仍在（来自备份内容）。其中包含一条带真实取消
	// 执行者的备份取消审计，用于证明恢复不会丢失“取消身份”。
	recorder := e.newAuditRecorder(t, store)
	for _, event := range []audit.Event{
		{
			Actor:   audit.Actor{Type: audit.ActorSystem, ID: "test-system"},
			Action:  "test.pre_restore_audit",
			Target:  audit.Target{Type: "test", ID: "seed"},
			Outcome: audit.OutcomeSuccess,
		},
		{
			Actor:   audit.Actor{Type: audit.ActorLocalAdmin, ID: "os:tester@test-host"},
			Action:  "backup.cancelled",
			Target:  audit.Target{Type: "backup", ID: "bkp_historical_cancel"},
			Outcome: audit.OutcomeSuccess,
		},
	} {
		if err := recorder.Record(ctx, event); err != nil {
			t.Fatalf("写入备份前审计事件失败：%v", err)
		}
	}
	return ids
}

// bytesOf 生成指定长度的确定性字节序列（测试摘要/密文占位，不是真实密钥）。
func bytesOf(length int, seed byte) []byte {
	buffer := make([]byte, length)
	for index := range buffer {
		buffer[index] = seed
	}
	return buffer
}

// firstLine 返回 SQL 首行，便于失败定位。
func firstLine(query string) string {
	line := query
	if index := strings.IndexByte(line, '\n'); index >= 0 {
		line = line[:index]
	}
	if len(line) > 120 {
		line = line[:120]
	}
	return line
}

// mutateAfterBackup 在备份之后修改数据库：新增备份中不存在的用户与凭证，并改变
// 备份中存在对象的可观察状态，用于证明恢复确实回到备份时间点。
func (e *testEnv) mutateAfterBackup(t *testing.T, store *storagesqlite.Store) {
	t.Helper()
	ctx := context.Background()
	nowMS := e.clock().UnixMilli() + 1000
	queries := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO users(id,username,username_normalized,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?,?,?)`, []any{"usr_post_backup", "postbackup", "postbackup",
			"active", 0, 1, 1, nowMS, nowMS}},
		{`INSERT INTO sessions(id,user_id,app_id,kind,restricted_reason,
required_steps_json,security_version,secret_digest,csrf_digest,key_id,
created_at_ms,last_seen_at_ms,idle_expires_at_ms,absolute_expires_at_ms)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, []any{"ses_" + strings.Repeat("9", 32),
			"usr_post_backup", nil, "normal", "", "[]", 1, bytesOf(32, 11),
			bytesOf(32, 12), "k1", nowMS, nowMS, nowMS + 3600_000,
			nowMS + 7200_000}},
		{`UPDATE users SET nickname='修改于备份之后', updated_at_ms=? WHERE username='alice'`,
			[]any{nowMS}},
	}
	for _, item := range queries {
		if _, err := store.ExecContext(ctx, item.query, item.args...); err != nil {
			t.Fatalf("备份后修改失败（%s）：%v", firstLine(item.query), err)
		}
	}
}

// closeStore 关闭数据库并断言成功。
func closeStore(t *testing.T, store *storagesqlite.Store) {
	t.Helper()
	if err := store.Close(); err != nil {
		t.Fatalf("关闭数据库失败：%v", err)
	}
}

// tableCount 返回表行数。
func tableCount(t *testing.T, store *storagesqlite.Store, table string) int64 {
	t.Helper()
	var count int64
	if err := store.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM `+table).Scan(&count); err != nil {
		t.Fatalf("统计表 %s 行数失败：%v", table, err)
	}
	return count
}

// queryInt64 执行单值查询。
func queryInt64(t *testing.T, store *storagesqlite.Store, query string, args ...any) int64 {
	t.Helper()
	var value int64
	if err := store.DB().QueryRowContext(context.Background(), query, args...).
		Scan(&value); err != nil {
		t.Fatalf("查询失败（%s）：%v", firstLine(query), err)
	}
	return value
}

// queryString 执行单字符串查询。
func queryString(t *testing.T, store *storagesqlite.Store, query string, args ...any) string {
	t.Helper()
	var value string
	if err := store.DB().QueryRowContext(context.Background(), query, args...).
		Scan(&value); err != nil {
		t.Fatalf("查询失败（%s）：%v", firstLine(query), err)
	}
	return value
}

// fileSHA256 返回文件 SHA-256 十六进制。
func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取文件失败（%s）：%v", filepath.Base(path), err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// openLive 打开恢复后的数据库（调用方负责关闭）。
func (e *testEnv) openLive(t *testing.T) *storagesqlite.Store {
	t.Helper()
	return e.openStore(t, true)
}

// waitCondition 在墙钟上限内轮询条件（避免固定 sleep）。
func waitCondition(t *testing.T, timeout time.Duration, condition func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return condition()
}

// errIs 报告错误链是否包含目标哨兵。
func errIs(err error, target error) bool { return errors.Is(err, target) }

// formatError 返回错误的短文本（测试失败信息用）。
func formatError(err error) string {
	if err == nil {
		return "<nil>"
	}
	text := err.Error()
	if len(text) > 300 {
		text = text[:300]
	}
	return text
}

// assertNoError 断言错误为空。
func assertNoError(t *testing.T, err error, contextText string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s：%v", contextText, formatError(err))
	}
}

// 编译期确认测试引用 fmt 与 errors（辅助函数使用）。
var _ = fmt.Sprintf
var _ = errIs
