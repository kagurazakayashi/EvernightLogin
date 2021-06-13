package session_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	sessionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/session/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// recoveryGateStub 是 session.RecoverySessionGate 的测试替身：只记录请求并返回预设
// 结论，用于验证 session 服务自身的签发约束（真实 gate 由 internal/recovery 提供）。
type recoveryGateStub struct {
	mu       sync.Mutex
	requests []session.RecoverySessionRequest
	err      error
}

// AuthorizeRecoverySession 实现 session.RecoverySessionGate。
func (g *recoveryGateStub) AuthorizeRecoverySession(_ context.Context, request session.RecoverySessionRequest) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.requests = append(g.requests, request)
	return g.err
}

// sessionRecoveryEnv 是受限恢复会话签发的测试环境。
type sessionRecoveryEnv struct {
	t     *testing.T
	ctx   context.Context
	store *storagesqlite.Store
	svc   *session.Service
	audit *audit.Recorder
	gate  *recoveryGateStub
	now   time.Time
}

// newSessionRecoveryEnv 构造测试环境；allowRoot 控制是否允许 root 恢复会话。
func newSessionRecoveryEnv(t *testing.T, gate *recoveryGateStub, allowRoot bool) *sessionRecoveryEnv {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "session-recovery-test.db")
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
	env := &sessionRecoveryEnv{t: t, ctx: ctx, store: storage, gate: gate,
		now: time.Now().UTC().Truncate(time.Millisecond)}
	auditStore, err := auditsqlite.New(storage)
	if err != nil {
		t.Fatalf("审计存储: %v", err)
	}
	env.audit, err = audit.New(auditStore, audit.Options{Now: func() time.Time { return env.now }})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	keyring, err := secrets.GenerateKeyring("k1", env.now)
	if err != nil {
		t.Fatalf("密钥环: %v", err)
	}
	sessionStore, err := sessionsqlite.New(storage)
	if err != nil {
		t.Fatalf("会话存储: %v", err)
	}
	env.svc, err = session.New(sessionStore, session.Options{
		Audit: env.audit, Keyring: keyring, Now: func() time.Time { return env.now },
		RecoveryGate:              gate,
		AllowRootRecoverySessions: allowRoot,
	})
	if err != nil {
		t.Fatalf("会话服务: %v", err)
	}
	return env
}

// seedUser 插入合成用户并返回安全版本。
func (env *sessionRecoveryEnv) seedUser(userID string, isRoot bool) int64 {
	env.t.Helper()
	nowMS := env.now.UnixMilli()
	username := "user-" + userID[len(userID)-2:]
	isRootValue := 0
	if isRoot {
		isRootValue = 1
	}
	if _, err := env.store.ExecContext(env.ctx,
		`INSERT INTO users(id,username,username_normalized,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		userID, username, username, "active", isRootValue, 1, 1, nowMS, nowMS); err != nil {
		env.t.Fatalf("插入用户: %v", err)
	}
	return 1
}

// recoveryRequest 构造签发请求。
func recoveryRequest(userID string, securityVersion int64) session.RecoverySessionRequest {
	return session.RecoverySessionRequest{
		UserID:          userID,
		SecurityVersion: securityVersion,
		AttemptID:       "rca_0123456789abcdef0123456789abcdef",
		RequestID:       "req-rec-1",
	}
}

const recoveryUser = "usr_00000000000000000000000000000001"

// TestIssueRecoverySessionRequiresGate 验证未装配 gate 或 gate 拒绝时 fail-closed。
func TestIssueRecoverySessionRequiresGate(t *testing.T) {
	env := newSessionRecoveryEnv(t, nil, false)
	env.seedUser(recoveryUser, false)
	if _, err := env.svc.IssueRecoverySession(env.ctx, recoveryRequest(recoveryUser, 1)); !errors.Is(err, session.ErrRecoveryNotAllowed) {
		t.Fatalf("没有 gate 应拒绝，得到 %v", err)
	}
	gate := &recoveryGateStub{err: errors.New("attempt invalid")}
	env = newSessionRecoveryEnv(t, gate, false)
	env.seedUser(recoveryUser, false)
	if _, err := env.svc.IssueRecoverySession(env.ctx, recoveryRequest(recoveryUser, 1)); !errors.Is(err, session.ErrRecoveryNotAllowed) {
		t.Fatalf("gate 拒绝应拒绝，得到 %v", err)
	}
}

// TestIssueRecoverySessionCreatesShortLivedRestrictedSession 验证恢复会话：受限原因、
// 短时到期、不能访问业务/管理接口、凭据只返回一次且库中只有摘要。
func TestIssueRecoverySessionCreatesShortLivedRestrictedSession(t *testing.T) {
	gate := &recoveryGateStub{}
	env := newSessionRecoveryEnv(t, gate, false)
	env.seedUser(recoveryUser, false)
	issued, err := env.svc.IssueRecoverySession(env.ctx, recoveryRequest(recoveryUser, 1))
	if err != nil {
		t.Fatalf("签发受限恢复会话: %v", err)
	}
	if issued.Session.Kind != session.KindRestricted || issued.Session.Reason != session.ReasonRecovery {
		t.Fatalf("会话类别错误: %+v", issued.Session)
	}
	ttl := issued.Session.AbsoluteExpiresAt.Sub(env.now)
	if ttl != session.DefaultRecoverySessionTTL {
		t.Fatalf("恢复会话绝对期限 = %s，期望 %s", ttl, session.DefaultRecoverySessionTTL)
	}
	if issued.Session.CanAccessBusiness() || issued.Session.CanAccessManagement() {
		t.Fatalf("恢复会话不应允许业务/管理访问")
	}
	if _, err := env.svc.AuthorizeBusiness(env.ctx, issued.Secret.Reveal()); !errors.Is(err, session.ErrRestrictedSession) {
		t.Fatalf("恢复会话访问业务应拒绝，得到 %v", err)
	}
	if _, err := env.svc.AuthorizeManagement(env.ctx, issued.Secret.Reveal()); !errors.Is(err, session.ErrRestrictedSession) {
		t.Fatalf("恢复会话访问管理应拒绝，得到 %v", err)
	}
	// 越权必须留痕：恢复会话访问业务/管理接口各写一条失败审计。
	var deniedAudits int
	rows, err := env.store.QueryContext(env.ctx, `SELECT COUNT(*) FROM audit_events
		WHERE action=? AND outcome='failure' AND error_code='ACCESS_DENIED'`,
		string(session.ActionSessionRestrictedDenied))
	if err != nil {
		t.Fatalf("读取越权审计: %v", err)
	}
	if rows.Next() {
		if err := rows.Scan(&deniedAudits); err != nil {
			rows.Close()
			t.Fatalf("扫描越权审计: %v", err)
		}
	}
	rows.Close()
	if deniedAudits < 2 {
		t.Fatalf("恢复会话越权审计数量 = %d，期望至少 2", deniedAudits)
	}
	validated, err := env.svc.Validate(env.ctx, issued.Secret.Reveal())
	if err != nil {
		t.Fatalf("校验恢复会话: %v", err)
	}
	if validated.Reason != session.ReasonRecovery || !validated.IsRestricted() {
		t.Fatalf("校验结果错误: %+v", validated)
	}
	if len(gate.requests) != 1 || gate.requests[0].AttemptID != recoveryRequest(recoveryUser, 1).AttemptID {
		t.Fatalf("gate 请求异常: %+v", gate.requests)
	}
	// 数据库不保存会话秘密原文。
	rows, err = env.store.QueryContext(env.ctx, `SELECT secret_digest FROM sessions`)
	if err != nil {
		t.Fatalf("读取会话摘要: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatalf("缺少会话行")
	}
	var digest []byte
	if err := rows.Scan(&digest); err != nil {
		t.Fatalf("扫描会话摘要: %v", err)
	}
	if len(digest) != 32 {
		t.Fatalf("会话摘要长度 = %d", len(digest))
	}
	// 审计事件带受限原因与短时标记，且不含会话秘密（恢复尝试 ID 作为
	// 敏感差异字段被审计层整体脱敏，这是预期行为）。
	rows, err = env.store.QueryContext(env.ctx, `SELECT action,COALESCE(detail_json,'') FROM audit_events`)
	if err != nil {
		t.Fatalf("读取审计: %v", err)
	}
	defer rows.Close()
	var builder strings.Builder
	foundIssue := false
	for rows.Next() {
		var action, detail string
		if err := rows.Scan(&action, &detail); err != nil {
			t.Fatalf("扫描审计: %v", err)
		}
		if action == string(session.ActionSessionIssue) {
			foundIssue = true
		}
		builder.WriteString(detail)
	}
	if !foundIssue {
		t.Fatalf("缺少会话签发审计")
	}
	if !strings.Contains(builder.String(), "restricted_reason") || !strings.Contains(builder.String(), "short_lived") {
		t.Fatalf("审计缺少受限恢复会话标记")
	}
	if strings.Contains(builder.String(), issued.Secret.Reveal()) ||
		strings.Contains(builder.String(), issued.CSRFSecret.Reveal()) {
		t.Fatalf("审计泄露会话秘密或 CSRF 令牌")
	}
}

// TestIssueRecoverySessionRejectsRootAndStaleVersion 验证 root 默认拒绝、安全版本不
// 一致拒绝、非法尝试 ID 拒绝。
func TestIssueRecoverySessionRejectsRootAndStaleVersion(t *testing.T) {
	gate := &recoveryGateStub{}
	env := newSessionRecoveryEnv(t, gate, false)
	env.seedUser(recoveryUser, false)
	env.seedUser("usr_00000000000000000000000000000009", true)
	if _, err := env.svc.IssueRecoverySession(env.ctx, recoveryRequest("usr_00000000000000000000000000000009", 1)); !errors.Is(err, session.ErrRecoveryNotAllowed) {
		t.Fatalf("root 应拒绝，得到 %v", err)
	}
	if _, err := env.svc.IssueRecoverySession(env.ctx, recoveryRequest(recoveryUser, 2)); !errors.Is(err, session.ErrAccountNotEligible) {
		t.Fatalf("安全版本不一致应拒绝，得到 %v", err)
	}
	bad := recoveryRequest(recoveryUser, 1)
	bad.AttemptID = "not-a-recovery-attempt"
	if _, err := env.svc.IssueRecoverySession(env.ctx, bad); !errors.Is(err, session.ErrInvalidRequest) {
		t.Fatalf("非法尝试 ID 应拒绝，得到 %v", err)
	}
	// 显式允许 root 时（受控本地通道装配前提）可以签发受限恢复会话，但仍只能是
	// 受限会话，不能访问业务。
	rootEnv := newSessionRecoveryEnv(t, gate, true)
	rootEnv.seedUser("usr_00000000000000000000000000000009", true)
	issued, err := rootEnv.svc.IssueRecoverySession(rootEnv.ctx, recoveryRequest("usr_00000000000000000000000000000009", 1))
	if err != nil {
		t.Fatalf("受控 root 恢复会话签发: %v", err)
	}
	if !issued.Session.IsRestricted() || issued.Session.Reason != session.ReasonRecovery {
		t.Fatalf("root 恢复会话必须是受限会话")
	}
}

// TestIssueRecoverySessionRotatesExistingSession 验证携带旧受限会话时会话固定轮换。
func TestIssueRecoverySessionRotatesExistingSession(t *testing.T) {
	gate := &recoveryGateStub{}
	env := newSessionRecoveryEnv(t, gate, false)
	env.seedUser(recoveryUser, false)
	first, err := env.svc.IssueRecoverySession(env.ctx, recoveryRequest(recoveryUser, 1))
	if err != nil {
		t.Fatalf("首次签发: %v", err)
	}
	request := recoveryRequest(recoveryUser, 1)
	request.ExistingSession = first.Secret.Reveal()
	second, err := env.svc.IssueRecoverySession(env.ctx, request)
	if err != nil {
		t.Fatalf("轮换签发: %v", err)
	}
	if second.RotatedSessionID != first.Session.ID {
		t.Fatalf("轮换会话 ID = %q，期望 %q", second.RotatedSessionID, first.Session.ID)
	}
	if _, err := env.svc.Validate(env.ctx, first.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("旧恢复会话应失效，得到 %v", err)
	}
}

// TestRenewRejectsRecoverySession 验证受限恢复会话不允许续期（保持短时边界）。
func TestRenewRejectsRecoverySession(t *testing.T) {
	gate := &recoveryGateStub{}
	env := newSessionRecoveryEnv(t, gate, false)
	env.seedUser(recoveryUser, false)
	issued, err := env.svc.IssueRecoverySession(env.ctx, recoveryRequest(recoveryUser, 1))
	if err != nil {
		t.Fatalf("签发受限恢复会话: %v", err)
	}
	if _, err := env.svc.Renew(env.ctx, issued.Secret.Reveal()); !errors.Is(err, session.ErrRestrictedSession) {
		t.Fatalf("恢复会话续期应被拒绝，得到 %v", err)
	}
	// 拒绝续期不改变会话可用性（仍可在短时窗口内核对/绑定/退出）。
	if _, err := env.svc.Validate(env.ctx, issued.Secret.Reveal()); err != nil {
		t.Fatalf("拒绝续期后恢复会话应仍有效: %v", err)
	}
}

// TestRecoverySessionTTLOptions 验证恢复会话期限边界校验。
func TestRecoverySessionTTLOptions(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "session-recovery-ttl.db")
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
	recorder, err := audit.New(auditStore, audit.Options{Now: time.Now})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	keyring, err := secrets.GenerateKeyring("k1", time.Now())
	if err != nil {
		t.Fatalf("密钥环: %v", err)
	}
	sessionStore, err := sessionsqlite.New(storage)
	if err != nil {
		t.Fatalf("会话存储: %v", err)
	}
	for _, ttl := range []time.Duration{time.Minute, 31 * time.Minute} {
		if _, err := session.New(sessionStore, session.Options{
			Audit: recorder, Keyring: keyring, RecoverySessionTTL: ttl,
		}); !errors.Is(err, session.ErrOptionsInvalid) {
			t.Fatalf("期限 %s 应被拒绝，得到 %v", ttl, err)
		}
	}
}
