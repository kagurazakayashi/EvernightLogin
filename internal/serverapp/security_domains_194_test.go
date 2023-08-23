package serverapp

// 步骤 194 审计 F1 的生产装配行为回归：BuildSecurityDomains 必须把真实 TOTP 查询
// 能力接到 Passkey 服务的 OtherStrongFactors。修复前值类型装箱导致 Passkey 永远看
// 不到 TOTP：强制 MFA 账户仍有活动 TOTP 时，删除最后一个 Passkey 被误拒。

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/passkey"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
)

const (
	passkeyWiringRootUser  = "usr_000000000000000000000000000000a1"
	passkeyWiringRootName  = "root-a1"
	passkeyWiringCredA     = "pkc_000000000000000000000000000000a1"
	passkeyWiringCredB     = "pkc_000000000000000000000000000000b2"
	passkeyWiringTOTPBind  = "totp_000000000000000000000000000000a1"
	passkeyWiringRequestID = "req_serverapp_passkey_wiring"
)

// passkeyWiringEnv 打开真实共享装配（OpenBase 会走 BuildSecurityDomains）并播种
// 一个 root 账户（强制 MFA）、一个主密码、一个 Passkey 第二步凭证与一个活动 TOTP。
func passkeyWiringEnv(t *testing.T) *Base {
	t.Helper()
	cfg := baseTestConfig(t)
	cfg.Passkey.Enabled = true
	cfg.Passkey.RPID = "login.example.test"
	cfg.Passkey.RPDisplayName = "EvernightLogin Test"
	cfg.Passkey.AllowedOrigins = []string{"https://login.example.test"}
	cfg.Passkey.UserVerification = "required"
	ctx := context.Background()
	base, err := OpenBase(ctx, BaseOptions{
		Config: cfg, Keyring: newTestKeyring(t), Migrate: true,
		Logger: baseTestLogger(), Now: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("OpenBase: %v", err)
	}
	t.Cleanup(func() { _ = base.Close(context.Background()) })
	if base.Security == nil || base.Security.Passkey == nil || base.Security.TOTP == nil {
		t.Fatalf("安全域未装配: %+v", base.Security)
	}
	nowMS := testNow.UnixMilli()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, execErr := base.Store.DB().ExecContext(context.Background(), query, args...); execErr != nil {
			t.Fatalf("播种测试数据失败: %v\nSQL: %s", execErr, query)
		}
	}
	exec(`INSERT INTO users(id,username,username_normalized,nickname,biography,avatar_ref,
language,timezone,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'root-a1','Root','',NULL,'zh-CN','Asia/Shanghai','active',1,1,1,?,?)`,
		passkeyWiringRootUser, passkeyWiringRootName, nowMS, nowMS)
	exec(`INSERT INTO password_credentials(user_id,hash_scheme,hash_version,password_hash,
must_change,row_version,created_at_ms,updated_at_ms,changed_at_ms)
VALUES(?,?,?,?,0,1,?,?,?)`, passkeyWiringRootUser, "argon2id", 19,
		strings.Repeat("a", 43), nowMS, nowMS, nowMS)
	// 一个 Passkey 第二步凭证（删除时会走“最后一个强因素”保护分支）。
	exec(`INSERT INTO webauthn_credentials(id,user_id,credential_id,public_key,aaguid,rp_id,
name,sign_count,transports,backup_eligible,backed_up,user_present,user_verified,attachment,
usage,version,last_used_at_ms,revoked_at_ms,revoked_reason,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?,0,'[]',0,0,1,1,'platform','second_factor',1,NULL,NULL,'',?,?)`,
		passkeyWiringCredA, passkeyWiringRootUser, []byte("0123456789abcdef"), []byte{2}, []byte{3},
		cfg.Passkey.RPID, "测试安全密钥", nowMS, nowMS)
	// 活动 TOTP 绑定（HasActive 只按 status='active' 判定；种子不参与验证码）。
	exec(`INSERT INTO totp_bindings(id,user_id,status,sealed_secret,algorithm,digits,
period_seconds,window_steps,last_accepted_step,attempts,max_attempts,expires_at_ms,
created_at_ms,updated_at_ms,activated_at_ms)
VALUES(?,?,'active',?,'SHA1',6,30,1,-1,0,5,0,?,?,?)`,
		passkeyWiringTOTPBind, passkeyWiringRootUser, []byte{4, 5, 6}, nowMS, nowMS, nowMS)
	return base
}

// recentAuthContext 注入近期主密码认证信号（真实 reauth 服务仍按策略判定）。
func recentAuthContext() context.Context {
	return reauth.WithSignals(context.Background(), reauth.Signals{
		VerifiedAt: testNow, Strength: policy.StrengthPassword, Complete: true, Confirmed: true})
}

// TestSecurityDomainsPasskeySeesTOTPOtherStrongFactor 验证 F1 修复：
//   - 强制 MFA（root）+ 活动 TOTP + 单个 Passkey：删除 Passkey 必须成功（未被误拒）；
//   - 随后移除 TOTP：同样强制 MFA 且无其他强因素时，删除 Passkey 必须被
//     ErrLastStrongFactor 拒绝（反向保护仍生效）。
func TestSecurityDomainsPasskeySeesTOTPOtherStrongFactor(t *testing.T) {
	base := passkeyWiringEnv(t)
	hasTOTP, err := base.Security.TOTP.HasActive(context.Background(), passkeyWiringRootUser)
	if err != nil || !hasTOTP {
		t.Fatalf("种子 TOTP 未生效: %v, %v", hasTOTP, err)
	}
	caller, err := passkey.UserCaller(passkeyWiringRootUser)
	if err != nil {
		t.Fatalf("构造 Passkey 调用者失败: %v", err)
	}
	// 正向：仍有活动 TOTP（其他强因素）→ 删除最后一个 Passkey 必须成功。
	if err := base.Security.Passkey.Revoke(recentAuthContext(), caller,
		passkey.RevokeRequest{CredentialID: passkeyWiringCredA,
			RequestID: passkeyWiringRequestID}); err != nil {
		t.Fatalf("审计 F1：存在活动 TOTP 时删除 Passkey 不应被拒绝: %v", err)
	}
	// 反向：补一把 Passkey、移除 TOTP 后，强制 MFA 且无其他强因素 → 拒绝。
	nowMS := testNow.UnixMilli()
	if _, execErr := base.Store.DB().ExecContext(context.Background(),
		`INSERT INTO webauthn_credentials(id,user_id,credential_id,public_key,aaguid,rp_id,
name,sign_count,transports,backup_eligible,backed_up,user_present,user_verified,attachment,
usage,version,last_used_at_ms,revoked_at_ms,revoked_reason,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?,0,'[]',0,0,1,1,'platform','second_factor',1,NULL,NULL,'',?,?)`,
		passkeyWiringCredB, passkeyWiringRootUser, []byte("fedcba9876543210"), []byte{8}, []byte{9},
		"login.example.test", "第二把安全密钥", nowMS, nowMS); execErr != nil {
		t.Fatalf("播种第二把 Passkey 失败: %v", execErr)
	}
	if _, execErr := base.Store.DB().ExecContext(context.Background(),
		`DELETE FROM totp_bindings WHERE user_id=?`, passkeyWiringRootUser); execErr != nil {
		t.Fatalf("移除 TOTP 种子失败: %v", execErr)
	}
	err = base.Security.Passkey.Revoke(recentAuthContext(), caller,
		passkey.RevokeRequest{CredentialID: passkeyWiringCredB,
			RequestID: passkeyWiringRequestID + "_reverse"})
	if !errors.Is(err, passkey.ErrLastStrongFactor) {
		t.Fatalf("强制 MFA 且无其他强因素时删除最后一个 Passkey 应被拒绝，实际: %v", err)
	}
}
