package token_test

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	. "github.com/kagurazakayashi/EvernightLogin/internal/token"
)

// TestAuditFailureFailsIssuance 验证步骤 50 遗留 (c)：成功审计失败时签发
// fail-closed 返回错误，不返回令牌，避免“有令牌无审计”。
type failingSuccessAudit struct {
	inner AuditRecorder
}

func (f failingSuccessAudit) Record(context.Context, audit.Event) error {
	return audit.ErrAuditUnavailable
}

func (f failingSuccessAudit) RecordFailure(ctx context.Context, event audit.Event) error {
	return f.inner.RecordFailure(ctx, event)
}

func (f failingSuccessAudit) ExecuteCritical(ctx context.Context, request audit.CriticalRequest,
	change audit.Change) error {
	return f.inner.ExecuteCritical(ctx, request, change)
}

func TestAuditFailureFailsIssuance(t *testing.T) {
	env := newTestEnv(t, func(options *Options) {
		options.Audit = failingSuccessAudit{inner: options.Audit}
	})
	issued, err := env.service.IssueAccessToken(env.ctx, env.caller(testUserA), accessRequest())
	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("审计失败应拒绝签发，得到 err=%v issued=%v", err, issued)
	}
	if issued.Token.IsSet() {
		t.Fatal("审计失败时不得返回令牌")
	}
}

// TestStrictJWSHeaderRejectsDuplicateFields 验证步骤 50 遗留 (d)：JWS 头出现重复
// 顶层字段时在签名校验前按畸形令牌拒绝，避免 enc/json 覆盖语义造成歧义。
func TestStrictJWSHeaderRejectsDuplicateFields(t *testing.T) {
	env := newTestEnv(t, nil)
	issued := env.issueAccess()
	parts := strings.Split(issued.Token.Reveal(), ".")
	if len(parts) != 3 {
		t.Fatalf("令牌分段数 = %d", len(parts))
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("解码头部: %v", err)
	}
	// 在头部对象内追加重复的 kid 字段，保留原签名（签名必然失效，但应在签名校验
	// 前因重复字段返回畸形令牌）。
	tampered := strings.TrimSuffix(string(header), "}") + `,"kid":"tampered"}`
	parts[0] = base64.RawURLEncoding.EncodeToString([]byte(tampered))
	malformed := strings.Join(parts, ".")
	if _, err := env.service.VerifyAccessToken(env.ctx, malformed, testAudience); !errors.Is(err, ErrMalformedToken) {
		t.Fatalf("重复头部字段应返回 ErrMalformedToken，得到 %v", err)
	}
}

// TestIDTokenRequiresAuthorizationCodeGrant 验证步骤 50 遗留：ID Token 只能由
// 授权码/设备码流程的客户端签发，client_credentials 客户端必须拒绝。
func TestIDTokenRequiresAuthorizationCodeGrant(t *testing.T) {
	env := newTestEnv(t, nil)
	_, err := env.service.IssueIDToken(env.ctx, env.caller(testUserA), IssueIDTokenRequest{
		ClientID: testClientB, SubjectUserID: testUserA, Nonce: "nonce", RequestID: "req-id-token",
	})
	if !errors.Is(err, ErrGrantNotAllowed) {
		t.Fatalf("client_credentials 客户端签发 ID Token 应拒绝，得到 %v", err)
	}
	// 授权码客户端仍可签发。
	issued, err := env.service.IssueIDToken(env.ctx, env.caller(testUserA), IssueIDTokenRequest{
		ClientID: testClient, SubjectUserID: testUserA, Nonce: "nonce", RequestID: "req-id-token-2",
	})
	if err != nil {
		t.Fatalf("授权码客户端签发 ID Token: %v", err)
	}
	if !issued.Token.IsSet() {
		t.Fatal("缺少 ID Token")
	}
}

// TestClientCredentialsServicePrincipal 验证服务身份签发：普通用户调用者不能替客户端
// 铸造服务令牌；受信系统通道签发的令牌主体固定为 client_id 且 subject_type=service，
// 与用户 Access Token（user）清晰区分。
func TestClientCredentialsServicePrincipal(t *testing.T) {
	env := newTestEnv(t, nil)
	serviceRequest := IssueAccessTokenRequest{
		ClientID: testClientB, GrantType: GrantClientCredentials,
		Scopes: []string{"service.read"}, Audiences: []string{testAudience},
		RequestID: "req-service-token",
	}
	if _, err := env.service.IssueAccessToken(env.ctx, env.caller(testUserA),
		serviceRequest); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("普通用户调用者签发服务令牌应拒绝，得到 %v", err)
	}
	issued, err := env.service.IssueAccessToken(env.ctx, env.systemCaller(), serviceRequest)
	if err != nil {
		t.Fatalf("系统通道签发服务令牌: %v", err)
	}
	claims, err := env.service.VerifyAccessToken(env.ctx, issued.Token.Reveal(), testAudience)
	if err != nil {
		t.Fatalf("验证服务令牌: %v", err)
	}
	if claims.Subject != testClientB || claims.ClientID != testClientB {
		t.Fatalf("服务主体必须为 client_id: sub=%q client=%q", claims.Subject, claims.ClientID)
	}
	if claims.SubjectType != TokenSubjectTypeService {
		t.Fatalf("subject_type = %q，期望 service", claims.SubjectType)
	}
	// 用户 Access Token 必须是 user 类型。
	userIssued := env.issueAccess()
	userClaims, err := env.service.VerifyAccessToken(env.ctx, userIssued.Token.Reveal(), testAudience)
	if err != nil {
		t.Fatalf("验证用户令牌: %v", err)
	}
	if userClaims.SubjectType != TokenSubjectTypeUser {
		t.Fatalf("用户令牌 subject_type = %q，期望 user", userClaims.SubjectType)
	}
	// 服务身份请求不得携带用户主体。
	badRequest := serviceRequest
	badRequest.SubjectUserID = testUserA
	badRequest.RequestID = "req-service-token-bad-subject"
	if _, err := env.service.IssueAccessToken(env.ctx, env.systemCaller(),
		badRequest); !errors.Is(err, ErrSubjectNotAllowed) {
		t.Fatalf("服务身份携带用户主体应拒绝，得到 %v", err)
	}
}

// barrierKeyStore 让两个并发轮换都基于同一旧 active 快照进入事务，从而确定性地
// 验证“并发轮换只有一个成功”。
type barrierKeyStore struct {
	Store
	armed   bool
	arrived chan struct{}
	gate    chan struct{}
}

func (b *barrierKeyStore) GetActiveKey(ctx context.Context) (KeyRecord, bool, error) {
	if !b.armed {
		return b.Store.GetActiveKey(ctx)
	}
	record, found, err := b.Store.GetActiveKey(ctx)
	if err != nil {
		return KeyRecord{}, false, err
	}
	b.arrived <- struct{}{}
	<-b.gate
	return record, found, nil
}

// TestConcurrentKeyRotationSingleWinner 验证步骤 50 遗留 (e)：两个基于同一旧 active
// 快照的并发轮换只有一个提交成功，另一个回滚且不会产生第二个 active。
func TestConcurrentKeyRotationSingleWinner(t *testing.T) {
	var barrier *barrierKeyStore
	env := newTestEnv(t, func(options *Options) {
		barrier = &barrierKeyStore{Store: options.Store, arrived: make(chan struct{}, 2),
			gate: make(chan struct{})}
		options.Store = barrier
	})
	env.issueAccess() // 先确保存在 active 密钥
	barrier.armed = true
	type result struct {
		err   error
		keyID string
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for index := 0; index < 2; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			key, err := env.service.RotateSigningKey(env.ctx, env.systemCaller(),
				"req-rotate-concurrent-"+string(rune('a'+index)))
			results <- result{err: err, keyID: key.Kid}
		}(index)
	}
	// 等待两个轮换都读取旧 active 快照后放行事务。
	for index := 0; index < 2; index++ {
		select {
		case <-barrier.arrived:
		case <-time.After(10 * time.Second):
			t.Fatal("等待并发轮换进入事务超时")
		}
	}
	close(barrier.gate)
	wg.Wait()
	close(results)
	success := 0
	failure := 0
	for item := range results {
		if item.err == nil {
			success++
			if item.keyID == "" {
				t.Fatal("轮换成功缺少 key id")
			}
			continue
		}
		if errors.Is(item.err, ErrKeyUnavailable) || errors.Is(item.err, ErrStoreUnavailable) {
			failure++
			continue
		}
		t.Fatalf("并发轮换非预期错误: %v", item.err)
	}
	if success != 1 || failure != 1 {
		t.Fatalf("并发轮换结果 success=%d failure=%d，期望各 1", success, failure)
	}
	if keys := env.countActiveKeys(t); keys != 1 {
		t.Fatalf("active 密钥数量 = %d，期望 1", keys)
	}
}

// countActiveKeys 统计数据库中 active 密钥数量。
func (env *testEnv) countActiveKeys(t *testing.T) int64 {
	t.Helper()
	var count int64
	query := `SELECT COUNT(*) FROM token_signing_keys WHERE status='active'`
	rows, err := env.raw.QueryContext(env.ctx, query)
	if err != nil {
		t.Fatalf("查询 active 密钥: %v", err)
	}
	defer rows.Close()
	if rows.Next() {
		if err := rows.Scan(&count); err != nil {
			t.Fatalf("扫描 active 密钥: %v", err)
		}
	}
	return count
}
