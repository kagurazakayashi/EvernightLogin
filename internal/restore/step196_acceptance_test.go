// step196_acceptance_test.go — 步骤196 验收探针：真实临时 SQLite + 真实备份/恢复
// 服务，验证恢复旧备份后备份内的旧凭据不复活、离线 JWT 因签名密钥删除而失效、
// 恢复代际/库外审计锚点不在被回滚库内。
//
// 边界说明（不把替身当生产功能）：
//   - 真实部分：internal/backup（SQLite 在线快照 + 认证加密）、internal/restore
//     （维护模式、回退备份、恢复、同事务凭证失效）、internal/token/session/
//     credential 服务、真实临时 SQLite（全部迁移）、库外恢复状态目录与日志。
//   - 刷新令牌/授权码：使用恢复服务真实删除逻辑与产品服务使用的「SHA-256 摘要
//     查询」路径（oauthflow/sqlite Store）验证恢复后查不到；其明文回放需完整
//     oauthflow 授权流程装配，本步未装配（见验收文档“未测/限制”）。
//   - 恢复代码/重置链接/邮件验证等：明文摘要为密钥派生或由对应流程发行，本步
//     以真实 restore 事务删除计数与逐表为空断言覆盖，不做明文回放。
package restore

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	credentialsqlite "github.com/kagurazakayashi/EvernightLogin/internal/credential/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
	oauthflowsqlite "github.com/kagurazakayashi/EvernightLogin/internal/oauthflow/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	sessionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/session/sqlite"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/token"
	tokensqlite "github.com/kagurazakayashi/EvernightLogin/internal/token/sqlite"
)

// step196TokenClients 是令牌签发依赖的受控客户端来源（仅测试装配）。
type step196TokenClients struct {
	clientID    string
	application string
	audience    string
}

// LoadClient 返回受控的授权码客户端配置。
func (c step196TokenClients) LoadClient(_ context.Context, clientID string) (token.ClientInfo, error) {
	if clientID != c.clientID {
		return token.ClientInfo{}, errors.New("unknown client")
	}
	return token.ClientInfo{
		ClientID: c.clientID, ApplicationID: c.application,
		ClientType: "confidential", AppActive: true,
		GrantTypes: []string{"client_credentials"},
		Scopes:     []string{"service.read"},
		Audiences:  []string{c.audience},
	}, nil
}

// step196AllowIssuance 是受控签发授权器：允许系统/本地管理员签发测试令牌。
func step196AllowIssuance(_ context.Context, _ token.Caller, _ token.IssuanceRequest) error {
	return nil
}

// step196Audience 是令牌校验使用的目标资源（受控测试资源标识，须为合法 https URI）。
const step196Audience = "https://api.step196.test"

// step196ClientID 是令牌服务要求的合法应用客户端标识（app_ + 32 位小写十六进制）。
const step196ClientID = "app_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// step196IssueAccessToken 用真实 token 服务为已存在用户签发一枚 Access Token。
func step196IssueAccessToken(t *testing.T, store *storagesqlite.Store,
	env *testEnv, userID, appID string) (raw, kid string) {
	t.Helper()
	tokenStore, err := tokensqlite.New(store)
	if err != nil {
		t.Fatalf("构造令牌存储失败：%v", err)
	}
	sealer, err := secrets.NewSealer(env.ring, nil)
	if err != nil {
		t.Fatalf("构造私钥加密器失败：%v", err)
	}
	clientID := step196ClientID
	service, err := token.New(token.Options{
		Store: tokenStore, Audit: env.newAuditRecorder(t, store), Sealer: sealer,
		Issuer:     "https://issuer.step196.test",
		Clients:    step196TokenClients{clientID: clientID, application: appID, audience: step196Audience},
		Authorizer: token.IssuanceAuthorizerFunc(step196AllowIssuance),
		AccessTTL:  15 * time.Minute, IDTokenTTL: 10 * time.Minute,
		KeyRetention: 24 * time.Hour, ClockSkew: time.Minute,
		Now: env.clock,
	})
	if err != nil {
		t.Fatalf("构造令牌服务失败：%v", err)
	}
	caller, err := token.SystemCaller("svc-step196-token")
	if err != nil {
		t.Fatalf("构造令牌调用者失败：%v", err)
	}
	issued, err := service.IssueAccessToken(context.Background(), caller,
		token.IssueAccessTokenRequest{
			ClientID: clientID, SubjectUserID: "",
			GrantType: token.GrantClientCredentials,
			Scopes:    []string{"service.read"}, Audiences: []string{step196Audience},
			RequestID: "req_step196_token",
		})
	if err != nil {
		t.Fatalf("签发 Access Token 失败：%v", err)
	}
	if _, err := service.VerifyAccessToken(context.Background(),
		issued.Token.Reveal(), step196Audience); err != nil {
		t.Fatalf("备份前 Access Token 验证失败：%v", err)
	}
	return issued.Token.Reveal(), issued.KeyID
}

// step196IssueSession 用真实会话服务为已存在用户签发一个会话并返回秘密明文。
func step196IssueSession(t *testing.T, store *storagesqlite.Store,
	env *testEnv, userID, username, appID string) (secret string) {
	t.Helper()
	sessionStore, err := sessionsqlite.New(store)
	if err != nil {
		t.Fatalf("构造会话存储失败：%v", err)
	}
	service, err := session.New(sessionStore, session.Options{
		Store: sessionStore, Audit: env.newAuditRecorder(t, store), Keyring: env.ring,
	})
	if err != nil {
		t.Fatalf("构造会话服务失败：%v", err)
	}
	issued, err := service.Login(context.Background(), session.LoginRequest{
		Result: authn.AuthenticateResult{
			UserID: userID, Username: username, Outcome: authn.OutcomeComplete,
			CompletedMethods: []authn.Method{authn.MethodPassword},
			CompletedAt:      env.clock(), SecurityVersion: 2,
		},
		AppID: appID, RequestID: "req_step196_session",
	})
	if err != nil {
		t.Fatalf("签发会话失败：%v", err)
	}
	secret = issued.Secret.Reveal()
	if _, err := service.Validate(context.Background(), secret); err != nil {
		t.Fatalf("备份前会话校验失败：%v", err)
	}
	return secret
}

// step196IssueCredential 用真实一次性凭证服务签发邮件验证令牌并返回明文。
func step196IssueCredential(t *testing.T, store *storagesqlite.Store,
	env *testEnv, userID string) (credentialID, secret string) {
	t.Helper()
	credentialStore, err := credentialsqlite.New(store)
	if err != nil {
		t.Fatalf("构造一次性凭证存储失败：%v", err)
	}
	service, err := credential.New(credentialStore,
		credential.Options{Keyring: env.ring, Now: env.clock})
	if err != nil {
		t.Fatalf("构造一次性凭证服务失败：%v", err)
	}
	issued, err := service.Issue(context.Background(), credential.IssueRequest{
		Purpose: "email.verify", Target: userID, Kind: credential.KindToken,
		TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("签发一次性凭证失败：%v", err)
	}
	secret = issued.Secret.Reveal()
	if _, err := service.Peek(context.Background(), credential.VerifyRequest{
		Kind: credential.KindToken, ID: issued.ID, Purpose: "email.verify",
		Target: userID, Secret: secret,
	}); err != nil {
		t.Fatalf("备份前一次性凭证校验失败：%v", err)
	}
	return issued.ID, secret
}

// TestRestoreDoesNotRevivePreBackupCredentials 是本步核心验收：备份前创建真实
// 会话/刷新令牌/授权码/一次性凭证并签发 Access Token，备份后撤销/消费，再恢复
// 旧备份；逐类真实尝试必须拒绝，且签名密钥删除使旧 JWT 失效。
func TestRestoreDoesNotRevivePreBackupCredentials(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	env.withConfig = true
	store := env.openStore(t, true)
	env.mustMigrate(t, store)
	ids := env.seedDatabase(t, store)
	// 会话/一次性凭证服务会校验稳定 ID 格式（usr_ + 32 位十六进制）；种子的 ID
	// 是简化值，这里另建一个格式合法的测试账户用于真实签发与恢复后拒绝验证。
	validUserID := "usr_" + strings.Repeat("1", 32)
	nowMS := env.clock().UnixMilli()
	if _, err := store.ExecContext(ctx, `INSERT INTO users(id,username,
username_normalized,status,is_root,security_version,row_version,created_at_ms,
updated_at_ms) VALUES(?,?,?,?,?,?,?,?,?)`, validUserID, "alice196", "alice196",
		"active", 0, 2, 1, nowMS, nowMS); err != nil {
		t.Fatalf("插入格式合法的测试账户失败：%v", err)
	} // 种子的签名密钥是不可解密的占位行；删除后由真实 token 服务生成真实密钥，
	// 才能做「备份前可验签、恢复后签名密钥删除即失效」的能力验证。
	if _, err := store.ExecContext(ctx, `DELETE FROM token_signing_keys`); err != nil {
		t.Fatalf("清理占位签名密钥失败：%v", err)
	}
	// ===== 备份前：真实签发各类凭据 =====
	jwtRaw, jwtKID := step196IssueAccessToken(t, store, env, ids.userID, ids.appID)
	sessionSecret := step196IssueSession(t, store, env, validUserID, "alice196", "")
	credentialID, credentialSecret := step196IssueCredential(t, store, env, validUserID)

	// 把种子里已有的刷新令牌/授权码摘要改成已知明文的 SHA-256，便于恢复后用产品
	// 同一条摘要查询路径做真实尝试（明文只在测试进程内，不落盘）。
	refreshSecret := "refresh-step196-" + strings.Repeat("a", 32)
	refreshDigest := sha256.Sum256([]byte(refreshSecret))
	if _, err := store.ExecContext(ctx,
		`UPDATE refresh_tokens SET token_sha256=? WHERE id=?`,
		refreshDigest[:], "rt_"+strings.Repeat("5", 20)); err != nil {
		t.Fatalf("改写刷新令牌摘要失败：%v", err)
	}
	authCodeSecret := "code-step196-" + strings.Repeat("b", 32)
	authCodeDigest := sha256.Sum256([]byte(authCodeSecret))
	if _, err := store.ExecContext(ctx,
		`UPDATE oauth_authorization_codes SET code_sha256=? WHERE id=?`,
		authCodeDigest[:], "oac_"+strings.Repeat("7", 20)); err != nil {
		t.Fatalf("改写授权码摘要失败：%v", err)
	}
	// 恢复代码/重置链接/邮件验证等种子行由 seedDatabase 真实写入；此处记录其数量，
	// 恢复后逐表断言清空（这些明文摘要由密钥派生或对应流程发行，不做明文回放）。
	preCounts := map[string]int64{
		"sessions":                   tableCount(t, store, "sessions"),
		"refresh_tokens":             tableCount(t, store, "refresh_tokens"),
		"oauth_authorization_codes":  tableCount(t, store, "oauth_authorization_codes"),
		"recovery_codes":             tableCount(t, store, "recovery_codes"),
		"password_reset_requests":    tableCount(t, store, "password_reset_requests"),
		"email_verification_tickets": tableCount(t, store, "email_verification_tickets"),
		"one_time_credentials":       tableCount(t, store, "one_time_credentials"),
		"token_signing_keys":         tableCount(t, store, "token_signing_keys"),
	}
	for name, count := range preCounts {
		if count <= 0 {
			t.Fatalf("备份前 %s 无种子数据，无法验证恢复失效", name)
		}
	}

	// 产品同一条摘要查询路径：备份前必须能查到刷新令牌/授权码。
	oauthStore, err := oauthflowsqlite.New(store)
	if err != nil {
		t.Fatalf("构造授权流程存储失败：%v", err)
	}
	if _, found, err := oauthStore.GetRefreshTokenByHash(ctx, refreshDigest); err != nil || !found {
		t.Fatalf("备份前刷新令牌摘要查询失败：found=%v err=%v", found, err)
	}
	if _, found, err := oauthStore.GetAuthorizationCodeByHash(ctx, authCodeDigest); err != nil || !found {
		t.Fatalf("备份前授权码摘要查询失败：found=%v err=%v", found, err)
	}

	// ===== 创建真实加密备份 =====
	backupResult := env.createBackup(t)

	// ===== 备份后：撤销/消费这些凭据（若恢复让旧备份覆盖当前库，它们可能复活）=====
	sessionStore, err := sessionsqlite.New(store)
	if err != nil {
		t.Fatalf("构造会话存储失败：%v", err)
	}
	sessionService, err := session.New(sessionStore, session.Options{
		Store: sessionStore, Audit: env.newAuditRecorder(t, store), Keyring: env.ring,
	})
	if err != nil {
		t.Fatalf("构造会话服务失败：%v", err)
	}
	if err := sessionService.Logout(ctx, sessionSecret); err != nil {
		t.Fatalf("备份后撤销会话失败：%v", err)
	}
	credentialStore, err := credentialsqlite.New(store)
	if err != nil {
		t.Fatalf("构造凭证存储失败：%v", err)
	}
	credentialService, err := credential.New(credentialStore,
		credential.Options{Keyring: env.ring, Now: env.clock})
	if err != nil {
		t.Fatalf("构造凭证服务失败：%v", err)
	}
	if _, err := credentialService.VerifyAndConsume(ctx, credential.VerifyRequest{
		Kind: credential.KindToken, ID: credentialID, Purpose: "email.verify",
		Target: validUserID, Secret: credentialSecret,
	}); err != nil {
		t.Fatalf("备份后消费一次性凭证失败：%v", err)
	}
	if _, err := store.ExecContext(ctx,
		`UPDATE refresh_tokens SET status='revoked' WHERE id=?`,
		"rt_"+strings.Repeat("5", 20)); err != nil {
		t.Fatalf("备份后撤销刷新令牌失败：%v", err)
	}
	closeStore(t, store)

	// ===== 恢复旧备份：恢复服务必须删除备份中可能复活的全部一次性凭据与签名密钥 =====
	service := env.newRestoreService(t, nil)
	result, err := service.Execute(ctx, Request{Caller: env.caller(t),
		BackupPath: backupResult.Path, Reason: "步骤196旧凭据失效验收",
		RequestID: "req_step196_restore"})
	assertNoError(t, err, "恢复旧备份失败")
	if !result.MaintenanceExited {
		t.Fatal("恢复成功后未退出维护状态")
	}
	if result.Generation != 1 {
		t.Fatalf("恢复代际 = %d，期望 1", result.Generation)
	}
	if result.Revoked.SigningKeys < 1 {
		t.Fatalf("恢复未删除签名密钥：%+v", result.Revoked)
	}

	// ===== 恢复后：逐类真实尝试必须被拒绝 =====
	live := env.openLive(t)
	defer closeStore(t, live)

	// 1) 会话：真实 Validate 必须拒绝。
	liveSessionStore, err := sessionsqlite.New(live)
	if err != nil {
		t.Fatalf("构造恢复后会话存储失败：%v", err)
	}
	liveSessionService, err := session.New(liveSessionStore, session.Options{
		Store: liveSessionStore, Audit: env.newAuditRecorder(t, live), Keyring: env.ring,
	})
	if err != nil {
		t.Fatalf("构造恢复后会话服务失败：%v", err)
	}
	if _, err := liveSessionService.Validate(ctx, sessionSecret); err == nil {
		t.Fatal("恢复后旧会话仍可校验通过（旧会话复活）")
	}

	// 2) 刷新令牌：产品使用的摘要查询路径必须查不到。
	liveOAuthStore, err := oauthflowsqlite.New(live)
	if err != nil {
		t.Fatalf("构造恢复后授权流程存储失败：%v", err)
	}
	if _, found, err := liveOAuthStore.GetRefreshTokenByHash(ctx, refreshDigest); err != nil || found {
		t.Fatalf("恢复后刷新令牌仍可查到：found=%v err=%v", found, err)
	}
	// 3) 授权码：同样必须查不到（不能再次兑换）。
	if _, found, err := liveOAuthStore.GetAuthorizationCodeByHash(ctx, authCodeDigest); err != nil || found {
		t.Fatalf("恢复后授权码仍可查到：found=%v err=%v", found, err)
	}

	// 4) 一次性凭证：真实 VerifyAndConsume 必须拒绝。
	liveCredentialStore, err := credentialsqlite.New(live)
	if err != nil {
		t.Fatalf("构造恢复后一次性凭证存储失败：%v", err)
	}
	liveCredentialService, err := credential.New(liveCredentialStore,
		credential.Options{Keyring: env.ring, Now: env.clock})
	if err != nil {
		t.Fatalf("构造恢复后凭证服务失败：%v", err)
	}
	if _, err := liveCredentialService.VerifyAndConsume(ctx, credential.VerifyRequest{
		Kind: credential.KindToken, ID: credentialID, Purpose: "email.verify",
		Target: validUserID, Secret: credentialSecret,
	}); err == nil {
		t.Fatal("恢复后旧一次性凭证仍可消费（旧链接复活）")
	}

	// 5) 离线 JWT：恢复删除签名密钥后，旧 Access Token 必须验证失败；客户端缓存的
	// 旧 JWKS 仍含旧公钥，但服务端已无对应私钥/密钥记录，无法再验签通过。
	liveTokenStore, err := tokensqlite.New(live)
	if err != nil {
		t.Fatalf("构造恢复后令牌存储失败：%v", err)
	}
	liveSealer, err := secrets.NewSealer(env.ring, nil)
	if err != nil {
		t.Fatalf("构造恢复后私钥加密器失败：%v", err)
	}
	liveTokenService, err := token.New(token.Options{
		Store: liveTokenStore, Audit: env.newAuditRecorder(t, live), Sealer: liveSealer,
		Issuer: "https://issuer.step196.test",
		Clients: step196TokenClients{clientID: step196ClientID,
			application: ids.appID, audience: step196Audience},
		Authorizer: token.IssuanceAuthorizerFunc(step196AllowIssuance),
		AccessTTL:  15 * time.Minute, IDTokenTTL: 10 * time.Minute,
		KeyRetention: 24 * time.Hour, ClockSkew: time.Minute,
		Now: env.clock,
	})
	if err != nil {
		t.Fatalf("构造恢复后令牌服务失败：%v", err)
	}
	if _, err := liveTokenService.VerifyAccessToken(ctx, jwtRaw, step196Audience); err == nil {
		t.Fatal("恢复后旧 Access Token 仍验证通过（离线 JWT 未失效）")
	}
	// 恢复后不应再发布备份中的旧签名密钥。
	keyInfos, err := liveTokenService.KeyInfos(ctx)
	if err != nil {
		t.Fatalf("读取恢复后密钥列表失败：%v", err)
	}
	for _, info := range keyInfos {
		if info.Kid == jwtKID {
			t.Fatalf("恢复后仍发布备份中的旧签名密钥 %s", jwtKID)
		}
	}

	// 6) 逐表为空：会话/刷新/授权码/恢复代码/重置链接/邮件验证/一次性凭证/签名密钥。
	for name := range preCounts {
		if count := tableCount(t, live, name); count != 0 {
			t.Fatalf("恢复后 %s 仍有 %d 行（旧凭据可能复活）", name, count)
		}
	}

	// 7) 恢复代际/库外锚点：代际写入恢复后数据库，库外状态目录与恢复日志独立存在，
	// 回退备份不能把它们一起回滚。
	stateEntries, err := os.ReadDir(env.stateDir)
	if err != nil {
		t.Fatalf("读取库外恢复状态目录失败：%v", err)
	}
	if len(stateEntries) == 0 {
		t.Fatal("库外恢复状态目录为空（代际/排他锚点不应只存在于被回滚库内）")
	}
	journal, err := service.JournalEntries()
	assertNoError(t, err, "读取库外恢复审计日志失败")
	if len(journal) == 0 {
		t.Fatal("库外恢复审计日志为空")
	}
	for index, entry := range journal {
		if entry.Seq != int64(index+1) {
			t.Fatalf("库外恢复日志序号不连续：第 %d 条为 %d", index+1, entry.Seq)
		}
	}
	if got := queryInt64(t, live, `SELECT generation FROM restore_generation WHERE id=1`); got != 1 {
		t.Fatalf("恢复后库内代际 = %d，期望 1", got)
	}
}

// 引用库外状态目录路径，避免测试重构后目录字段被误删。
var _ = filepath.Join
var _ = storagesqlite.Store{}
var _ = oauthflow.TokenResponse{}
