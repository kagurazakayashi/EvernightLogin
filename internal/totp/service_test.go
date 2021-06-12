package totp_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	policysqlite "github.com/kagurazakayashi/EvernightLogin/internal/policy/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	reauthsqlite "github.com/kagurazakayashi/EvernightLogin/internal/reauth/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/totp"
	totpsqlite "github.com/kagurazakayashi/EvernightLogin/internal/totp/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

var seedTime = time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

const userID = "usr_00000000000000000000000000000001"

type fakeSessionInvalidator struct{ calls int }

func (f *fakeSessionInvalidator) RevokeAllForUser(ctx context.Context, userID, reason string) (int64, error) {
	f.calls++
	return 1, nil
}

type allowRunner struct{ calls int }

func (r *allowRunner) Authorize(ctx context.Context, caller reauth.Caller, request reauth.Request) (reauth.Result, error) {
	r.calls++
	return reauth.Result{OperationID: request.OperationID, TargetID: request.TargetID}, nil
}

func (r *allowRunner) NotifyOutcome(ctx context.Context, result reauth.Result, outcome reauth.Outcome) error {
	return nil
}

type testEnv struct {
	t        *testing.T
	ctx      context.Context
	raw      *storagesqlite.Store
	service  *totp.Service
	store    totp.Store
	sealer   *secrets.Sealer
	recorder *audit.Recorder
	now      time.Time
	runner   *allowRunner
}

func newTestEnv(t *testing.T, mutate func(*totp.Options)) *testEnv {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(filepath.Join(t.TempDir(), "totp.db")))
	if err != nil {
		t.Fatalf("打开数据库: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	list, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := raw.Migrate(ctx, list); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		t.Fatalf("审计存储: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{Now: func() time.Time { return seedTime }})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	keyring, err := secrets.GenerateKeyring("k1", seedTime)
	if err != nil {
		t.Fatalf("密钥环: %v", err)
	}
	sealer, err := secrets.NewSealer(keyring, nil)
	if err != nil {
		t.Fatalf("加密器: %v", err)
	}
	store, err := totpsqlite.New(raw)
	if err != nil {
		t.Fatalf("TOTP 存储: %v", err)
	}
	env := &testEnv{t: t, ctx: ctx, raw: raw, now: time.Now().UTC(), runner: &allowRunner{},
		sealer: sealer, recorder: recorder, store: store}
	options := totp.Options{Store: store, Audit: recorder, Sealer: sealer, Reauth: env.runner,
		IssuerName: "登录服务", Now: func() time.Time { return env.now },
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))}
	if mutate != nil {
		mutate(&options)
	}
	service, err := totp.New(options)
	if err != nil {
		t.Fatalf("TOTP 服务: %v", err)
	}
	env.service = service
	now := seedTime.UnixMilli()
	if _, err := raw.DB().ExecContext(ctx, `INSERT INTO users(
id,username,username_normalized,nickname,biography,avatar_ref,language,timezone,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms
) VALUES(?,?,'','','',NULL,'zh-CN','Asia/Shanghai','active',0,1,1,?,?)`,
		userID, "alice", now, now); err != nil {
		t.Fatalf("用户: %v", err)
	}
	return env
}

func (e *testEnv) caller() totp.Caller {
	caller, err := totp.UserCaller(userID)
	if err != nil {
		e.t.Fatalf("调用者: %v", err)
	}
	return caller
}

func (e *testEnv) count(query string, args ...any) int {
	e.t.Helper()
	var value int
	if err := e.raw.DB().QueryRowContext(e.ctx, query, args...).Scan(&value); err != nil {
		e.t.Fatalf("计数: %v", err)
	}
	return value
}

// TestRFC6238KnownVectors 覆盖 RFC 6238 SHA1 已知测试向量（8 位与 6 位）。
func TestRFC6238KnownVectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	vectors := []struct {
		unix  int64
		want8 string
		want6 string
	}{
		{59, "94287082", "287082"},
		{1111111109, "07081804", "081804"},
		{1111111111, "14050471", "050471"},
		{1234567890, "89005924", "005924"},
		{2000000000, "69279037", "279037"},
		{20000000000, "65353130", "353130"},
	}
	for _, vector := range vectors {
		at := time.Unix(vector.unix, 0).UTC()
		code8, _, err := totp.GenerateCode(secret, at, 30, 8)
		if err != nil || code8 != vector.want8 {
			t.Errorf("T=%d 8位 = %q (err=%v)，期望 %q", vector.unix, code8, err, vector.want8)
		}
		code6, _, err := totp.GenerateCode(secret, at, 30, 6)
		if err != nil || code6 != vector.want6 {
			t.Errorf("T=%d 6位 = %q (err=%v)，期望 %q", vector.unix, code6, err, vector.want6)
		}
	}
}

// TestClockWindowBoundaries 验证前后窗口内接受、窗口外拒绝与位数不足拒绝。
func TestClockWindowBoundaries(t *testing.T) {
	secret := []byte("12345678901234567890")
	at := time.Unix(1111111111, 0).UTC()
	code, step, err := totp.GenerateCode(secret, at, 30, 6)
	if err != nil {
		t.Fatalf("生成验证码: %v", err)
	}
	// 同一时间步、前一步、后一步在窗口 1 内接受。
	for offset := int64(-1); offset <= 1; offset++ {
		checkAt := at.Add(time.Duration(offset*30) * time.Second)
		matched, ok := totp.VerifyCode(secret, code, checkAt, 30, 6, 1)
		if !ok || matched != step {
			t.Errorf("窗口偏移 %d 应接受，matched=%d ok=%v", offset, matched, ok)
		}
	}
	// 窗口外（两步前）拒绝。
	if _, ok := totp.VerifyCode(secret, code, at.Add(-2*30*time.Second), 30, 6, 1); ok {
		t.Error("窗口外验证码应拒绝")
	}
	// 窗口为 0 时只接受当前步。
	if _, ok := totp.VerifyCode(secret, code, at.Add(30*time.Second), 30, 6, 0); ok {
		t.Error("窗口 0 时相邻步应拒绝")
	}
	// 位数不符拒绝。
	if _, ok := totp.VerifyCode(secret, code[:5], at, 30, 6, 1); ok {
		t.Error("位数不足应拒绝")
	}
}

// TestBindConfirmLoginRebindAndRemovalProtection 覆盖绑定中/已激活、重绑先验证再替换、
// 登录验证防重放与强制策略解除保护。
func TestBindConfirmLoginRebindAndRemovalProtection(t *testing.T) {
	forced := newTestEnv(t, func(options *totp.Options) {
		options.Policy = totp.PolicyFunc(func(ctx context.Context, userID string) (bool, error) { return true, nil })
	})
	forced.now = time.Now().UTC()
	caller := forced.caller()
	start, err := forced.service.BeginBinding(forced.ctx, caller, "req-bind-1")
	if err != nil {
		t.Fatalf("开始绑定: %v", err)
	}
	if !strings.HasPrefix(start.URI, "otpauth://totp/") || start.Secret == "" {
		t.Fatalf("导入 URI/种子异常: %+v", start)
	}
	secret, err := totp.DecodeSecret(start.Secret)
	if err != nil {
		t.Fatalf("解码种子: %v", err)
	}
	// 绑定中尚未激活：登录验证应拒绝。
	if err := forced.service.VerifyLoginCode(forced.ctx, userID, mustCode(t, secret, forced.now)); !errors.Is(err, totp.ErrBindingNotFound) {
		t.Fatalf("pending 绑定不应可用于登录: %v", err)
	}
	code := mustCode(t, secret, forced.now)
	if _, err := forced.service.ConfirmBinding(forced.ctx, caller, totp.BindConfirm{
		BindingID: start.BindingID, Code: "000000", RequestID: "req-confirm-bad"}); !errors.Is(err, totp.ErrCodeInvalid) {
		t.Fatalf("错误验证码确认错误 = %v，期望 ErrCodeInvalid", err)
	}
	confirmed, err := forced.service.ConfirmBinding(forced.ctx, caller, totp.BindConfirm{
		BindingID: start.BindingID, Code: code, RequestID: "req-confirm"})
	if err != nil || confirmed.Status != "active" {
		t.Fatalf("确认绑定 = %+v err=%v", confirmed, err)
	}
	// 确认绑定使用的时间步已写入 last_accepted_step：该码不能立即用于登录。
	if err := forced.service.VerifyLoginCode(forced.ctx, userID, code); !errors.Is(err, totp.ErrReplay) {
		t.Fatalf("确认步立即登录错误 = %v，期望 ErrReplay", err)
	}
	// 下一时间步可正常登录。
	forced.now = forced.now.Add(30 * time.Second)
	loginCode := mustCode(t, secret, forced.now)
	if err := forced.service.VerifyLoginCode(forced.ctx, userID, loginCode); err != nil {
		t.Fatalf("首次登录验证: %v", err)
	}
	// 同一时间步重放拒绝。
	if err := forced.service.VerifyLoginCode(forced.ctx, userID, loginCode); !errors.Is(err, totp.ErrReplay) {
		t.Fatalf("同一步重放错误 = %v，期望 ErrReplay", err)
	}
	// 并发同一步验证：只有一个成功。
	forced.now = forced.now.Add(30 * time.Second)
	newCode := mustCode(t, secret, forced.now)
	startChannel := make(chan struct{})
	results := make(chan error, 2)
	var waitGroup sync.WaitGroup
	for index := 0; index < 2; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-startChannel
			results <- forced.service.VerifyLoginCode(forced.ctx, userID, newCode)
		}()
	}
	close(startChannel)
	waitGroup.Wait()
	close(results)
	successes, replays := 0, 0
	for verifyErr := range results {
		switch {
		case verifyErr == nil:
			successes++
		case errors.Is(verifyErr, totp.ErrReplay):
			replays++
		default:
			t.Fatalf("并发验证未知错误: %v", verifyErr)
		}
	}
	if successes != 1 || replays != 1 {
		t.Errorf("并发验证 = 成功 %d / 重放 %d，期望 1/1", successes, replays)
	}
	// 重绑：新绑定先验证，再替换旧 active；旧种子验证码随后不可用。
	rebind, err := forced.service.BeginBinding(forced.ctx, caller, "req-bind-2")
	if err != nil {
		t.Fatalf("重绑开始: %v", err)
	}
	newSecret, err := totp.DecodeSecret(rebind.Secret)
	if err != nil {
		t.Fatalf("解码新种子: %v", err)
	}
	if _, err := forced.service.ConfirmBinding(forced.ctx, caller, totp.BindConfirm{
		BindingID: rebind.BindingID, Code: mustCode(t, newSecret, forced.now), RequestID: "req-rebind"}); err != nil {
		t.Fatalf("重绑确认: %v", err)
	}
	active := forced.count(`SELECT COUNT(*) FROM totp_bindings WHERE user_id=? AND status='active'`, userID)
	if active != 1 {
		t.Errorf("重绑后 active 绑定数 = %d，期望 1", active)
	}
	// 重绑后旧种子验证码失效（旧 active 已停用）。
	forced.now = forced.now.Add(30 * time.Second)
	if err := forced.service.VerifyLoginCode(forced.ctx, userID, mustCode(t, secret, forced.now)); err == nil {
		t.Fatal("重绑后旧种子验证码不应通过")
	}
	// 强制 MFA 且无其他强因素：解除被拒绝（先通过当前 TOTP 验证码证明持有）。
	forced.now = forced.now.Add(2 * time.Minute)
	if err := forced.service.RemoveBinding(forced.ctx, caller, totp.RemoveRequest{
		Code: mustCode(t, newSecret, forced.now), RequestID: "req-remove"}); !errors.Is(err, totp.ErrFactorRequired) {
		t.Fatalf("强制策略解除错误 = %v，期望 ErrFactorRequired", err)
	}
}

func mustCode(t *testing.T, secret []byte, at time.Time) string {
	t.Helper()
	code, _, err := totp.GenerateCode(secret, at, 30, 6)
	if err != nil {
		t.Fatalf("生成验证码: %v", err)
	}
	return code
}

// TestSecretNotLeakedToAuditOrQuery 验证明文种子不出现在审计与普通查询结果中。
func TestSecretNotLeakedToAuditOrQuery(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	caller := env.caller()
	start, err := env.service.BeginBinding(env.ctx, caller, "req-leak")
	if err != nil {
		t.Fatalf("开始绑定: %v", err)
	}
	secret, _ := totp.DecodeSecret(start.Secret)
	if _, err := env.service.ConfirmBinding(env.ctx, caller, totp.BindConfirm{
		BindingID: start.BindingID, Code: mustCode(t, secret, env.now), RequestID: "req-leak-confirm"}); err != nil {
		t.Fatalf("确认绑定: %v", err)
	}
	rows, err := env.raw.DB().QueryContext(env.ctx,
		`SELECT action,COALESCE(reason_code,''),COALESCE(error_code,''),detail_json FROM audit_events`)
	if err != nil {
		t.Fatalf("读取审计: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var action, reason, codeValue, detail string
		if err := rows.Scan(&action, &reason, &codeValue, &detail); err != nil {
			t.Fatalf("扫描审计: %v", err)
		}
		if strings.Contains(action+reason+codeValue+detail, start.Secret) {
			t.Errorf("审计泄露 TOTP 种子")
		}
	}
	bindings, err := env.service.Bindings(env.ctx, caller)
	if err != nil || len(bindings) == 0 {
		t.Fatalf("绑定查询 = %+v err=%v", bindings, err)
	}
	// 普通查询结果不包含种子/密文（结构体中只有元数据）。
	if strings.Contains(strings.Join([]string{bindings[0].ID, bindings[0].Status}, " "), start.Secret) {
		t.Error("绑定查询泄露种子")
	}
}

// TestPendingExpiryCleanupAndLimit 覆盖过期 pending 惰性清理与名额释放。
func TestPendingExpiryCleanupAndLimit(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	caller := env.caller()
	if _, err := env.service.BeginBinding(env.ctx, caller, "req-old-pending"); err != nil {
		t.Fatalf("首个 pending: %v", err)
	}
	// 超过绑定有效期后新绑定仍可创建（过期记录不占用名额并被清理）。
	env.now = env.now.Add(totp.DefaultBindingTTL + time.Minute)
	if _, err := env.service.BeginBinding(env.ctx, caller, "req-new-pending"); err != nil {
		t.Fatalf("过期后新建 pending: %v", err)
	}
	if count := env.count(`SELECT COUNT(*) FROM totp_bindings WHERE user_id=? AND status='pending'`, userID); count != 1 {
		t.Errorf("pending 数 = %d，期望 1（过期已清理）", count)
	}
}

// TestReauthMissingFailClosed 验证未注入近期认证时绑定 fail-closed 且写失败审计。
func TestReauthMissingFailClosed(t *testing.T) {
	env := newTestEnv(t, func(options *totp.Options) {
		options.Reauth = nil
	})
	env.now = time.Now().UTC()
	if _, err := env.service.BeginBinding(env.ctx, env.caller(), "req-no-reauth"); !errors.Is(err, totp.ErrReauthRequired) {
		t.Fatalf("未注入 reauth 错误 = %v，期望 ErrReauthRequired", err)
	}
	if count := env.count(`SELECT COUNT(*) FROM totp_bindings`); count != 0 {
		t.Errorf("拒绝后不应创建绑定，实际 %d", count)
	}
}

// TestBindFailureAuditNotSuccess 验证确认失败只写 failure 审计、成功激活写 success。
func TestBindFailureAuditNotSuccess(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	caller := env.caller()
	start, err := env.service.BeginBinding(env.ctx, caller, "req-audit")
	if err != nil {
		t.Fatalf("开始绑定: %v", err)
	}
	secret, _ := totp.DecodeSecret(start.Secret)
	if _, err := env.service.ConfirmBinding(env.ctx, caller, totp.BindConfirm{
		BindingID: start.BindingID, Code: "000000", RequestID: "req-audit-bad"}); !errors.Is(err, totp.ErrCodeInvalid) {
		t.Fatalf("错误验证码确认: %v", err)
	}
	var failureOutcomes int
	if err := env.raw.DB().QueryRowContext(env.ctx,
		`SELECT COUNT(*) FROM audit_events WHERE action='mfa.totp_bind_confirm_failed' AND outcome='failure'`).Scan(&failureOutcomes); err != nil {
		t.Fatalf("查询失败审计: %v", err)
	}
	if failureOutcomes < 1 {
		t.Error("确认失败缺少 failure 审计")
	}
	var fakeSuccess int
	if err := env.raw.DB().QueryRowContext(env.ctx,
		`SELECT COUNT(*) FROM audit_events WHERE action='mfa.totp_bind_confirm_failed' AND outcome='success'`).Scan(&fakeSuccess); err != nil {
		t.Fatalf("查询成功审计: %v", err)
	}
	if fakeSuccess != 0 {
		t.Errorf("确认失败被记为 success 审计 %d 条", fakeSuccess)
	}
	if _, err := env.service.ConfirmBinding(env.ctx, caller, totp.BindConfirm{
		BindingID: start.BindingID, Code: mustCode(t, secret, env.now), RequestID: "req-audit-ok"}); err != nil {
		t.Fatalf("正确确认: %v", err)
	}
	var successOutcomes int
	if err := env.raw.DB().QueryRowContext(env.ctx,
		`SELECT COUNT(*) FROM audit_events WHERE action='mfa.totp_bind_activated' AND outcome='success'`).Scan(&successOutcomes); err != nil {
		t.Fatalf("查询激活审计: %v", err)
	}
	if successOutcomes < 1 {
		t.Error("成功激活缺少 success 审计")
	}
}

// TestBeginBindingInvalidRequestAudited 验证非法请求失败审计（不泄密）。
func TestBeginBindingInvalidRequestAudited(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	if _, err := env.service.BeginBinding(env.ctx, env.caller(), "bad request id!"); !errors.Is(err, totp.ErrInvalidRequest) {
		t.Fatalf("非法请求错误 = %v，期望 ErrInvalidRequest", err)
	}
	var failures int
	if err := env.raw.DB().QueryRowContext(env.ctx,
		`SELECT COUNT(*) FROM audit_events WHERE action='mfa.totp_bind_begin_denied' AND outcome='failure'`).Scan(&failures); err != nil {
		t.Fatalf("查询审计: %v", err)
	}
	if failures < 1 {
		t.Error("非法请求缺少失败审计")
	}
}

// TestBeginBindingWithRealReauthPolicy 使用真实 policy.Service+reauth.Service 验证
// mfa.add 默认策略（password+近期）可用：无近期认证事实时 fail-closed，近期密码
// 认证（reauth.Signals）可通过，且绑定可确认；用于覆盖“先有鸡还是先有蛋”。
func TestBeginBindingWithRealReauthPolicy(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	policyStore, err := policysqlite.New(env.raw)
	if err != nil {
		t.Fatalf("策略存储: %v", err)
	}
	policyService, err := policy.New(policy.Options{
		Store: policyStore, Audit: env.recorder, Now: func() time.Time { return env.now },
	})
	if err != nil {
		t.Fatalf("策略服务: %v", err)
	}
	reauthStore, err := reauthsqlite.New(env.raw)
	if err != nil {
		t.Fatalf("再次认证存储: %v", err)
	}
	reauthService, err := reauth.New(reauth.Options{
		Store: reauthStore, Audit: env.recorder, Policy: policyService,
		Now: func() time.Time { return env.now },
	})
	if err != nil {
		t.Fatalf("再次认证服务: %v", err)
	}
	service, err := totp.New(totp.Options{
		Store: env.store, Audit: env.recorder, Sealer: env.sealer, Reauth: reauthService,
		IssuerName: "登录服务", Now: func() time.Time { return env.now },
	})
	if err != nil {
		t.Fatalf("TOTP 服务（真实 reauth）: %v", err)
	}
	// 无近期认证事实：不允许绑定。
	if _, err := service.BeginBinding(env.ctx, env.caller(), "req-real-noauth"); err == nil {
		t.Fatal("无近期认证不应允许绑定")
	}
	// 近期密码认证（步骤 39 Signals）应满足 mfa.add 默认策略。
	signed := reauth.WithSignals(env.ctx, reauth.Signals{
		VerifiedAt: env.now.Add(-time.Minute), Strength: policy.StrengthPassword, Complete: true,
	})
	start, err := service.BeginBinding(signed, env.caller(), "req-real")
	if err != nil {
		t.Fatalf("真实 reauth 密码策略绑定: %v", err)
	}
	secret, _ := totp.DecodeSecret(start.Secret)
	if _, err := service.ConfirmBinding(env.ctx, env.caller(), totp.BindConfirm{
		BindingID: start.BindingID, Code: mustCode(t, secret, env.now), RequestID: "req-real-confirm"}); err != nil {
		t.Fatalf("真实 reauth 路径确认: %v", err)
	}
}

// TestRemoveBindingInvalidatesExistingSessions 验证解除 TOTP（强因素）后：
// 同一审计事务递增 security_version，并触发注入的会话撤销器；旧强认证会话失效。
func TestRemoveBindingInvalidatesExistingSessions(t *testing.T) {
	invalidator := &fakeSessionInvalidator{}
	env := newTestEnv(t, func(options *totp.Options) {
		options.SessionInvalidator = invalidator
	})
	env.now = time.Now().UTC()
	caller := env.caller()
	start, err := env.service.BeginBinding(env.ctx, caller, "req-remove-invalidate")
	if err != nil {
		t.Fatalf("开始绑定: %v", err)
	}
	secret, err := totp.DecodeSecret(start.Secret)
	if err != nil {
		t.Fatalf("解码种子: %v", err)
	}
	if _, err := env.service.ConfirmBinding(env.ctx, caller, totp.BindConfirm{
		BindingID: start.BindingID, Code: mustCode(t, secret, env.now),
		RequestID: "req-remove-invalidate-confirm"}); err != nil {
		t.Fatalf("确认绑定: %v", err)
	}
	env.now = env.now.Add(30 * time.Second)
	if err := env.service.RemoveBinding(env.ctx, caller, totp.RemoveRequest{
		Code: mustCode(t, secret, env.now), RequestID: "req-remove-invalidate-remove"}); err != nil {
		t.Fatalf("解除绑定: %v", err)
	}
	if invalidator.calls != 1 {
		t.Fatalf("解除强因素后应触发会话撤销: %d", invalidator.calls)
	}
	version := env.count(`SELECT security_version FROM users WHERE id=?`, userID)
	if version < 2 {
		t.Fatalf("解除强因素后 security_version 应递增: %d", version)
	}
}
