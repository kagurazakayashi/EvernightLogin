package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
)

func TestPasswordResetRequiresMailAndRejectsInvalidToken(t *testing.T) {
	ctx := context.Background()
	runtime := openTestRuntime(t, Options{})

	if err := runtime.PasswordReset().Request(ctx, RequestPasswordResetRequest{
		Identifier: "alice@example.test", ClientIP: "127.0.0.1",
	}); err == nil {
		t.Fatal("未启用邮件时 Request 必须返回配置错误")
	}
	if err := runtime.PasswordReset().ValidateToken(ctx, "not-a-real-token"); err == nil {
		t.Fatal("无效 token 必须拒绝")
	}
	if _, err := runtime.PasswordReset().Complete(ctx, CompletePasswordResetRequest{
		Token: "not-a-real-token", NewPassword: "K8$wR3!nB6@yF1#v",
	}); err == nil {
		t.Fatal("无效 token 必须拒绝")
	}
}

// TestPasswordResetValidateTokenMatchesServiceJudgment 验证新 Go 门面的
// ValidateToken 与内置找回页面共用同一领域判断（请求状态/凭证状态/账户可找回状态），
// 并且所有预检查失败在公开层统一为 CHALLENGE_INVALID，不泄露账户存在性或状态。
//
// 测试直接使用真实运行时装配的一次性凭证服务与 SQLite 存储构造“邮件已投递”的
// pending 找回请求，避免依赖 SMTP；每次失败场景都使用独立 token，避免预检查限流
// 影响判断路径。
func TestPasswordResetValidateTokenMatchesServiceJudgment(t *testing.T) {
	ctx := context.Background()
	runtime := openTestRuntime(t, Options{})
	facade := runtime.PasswordReset()

	user, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "resetuser", Password: "K8$wR3!nB6@yF1#v",
		Nickname: "Reset User", RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("创建用户: %v", err)
	}
	seedVerifiedEmail(t, runtime, user.ID, "resetuser@example.test")

	// 正常 link：可预检查且不消费。
	resetID, credentialID, token := insertPendingReset(t, runtime, user.ID)
	if err := facade.ValidateToken(ctx, token); err != nil {
		t.Fatalf("有效找回 token 预检查失败: %v", err)
	}
	assertResetRequestPending(t, runtime, resetID)
	assertOneTimeCredentialActive(t, runtime, credentialID)

	// 公开错误统一性：各拒绝场景必须返回同一错误码与同一公开消息。
	type rejection struct {
		name string
		err  error
	}
	rejections := make([]rejection, 0, 8)

	// 错误摘要。
	_, _, wrongDigest := insertPendingReset(t, runtime, user.ID)
	parts := strings.SplitN(wrongDigest, ".", 2)
	rejections = append(rejections, rejection{"错误摘要", facade.ValidateToken(ctx, tamperSecret(parts[0], parts[1]))})

	// 过期（请求与凭证均在期限外；数据库 CHECK 要求 expires > created）。
	expiredID, expiredCredentialID, expiredToken := insertPendingReset(t, runtime, user.ID)
	if _, err := runtime.base.Store.DB().ExecContext(ctx,
		`UPDATE password_reset_requests SET created_at_ms=?,expires_at_ms=? WHERE id=?`,
		time.Now().Add(-2*time.Hour).UnixMilli(), time.Now().Add(-time.Hour).UnixMilli(),
		expiredID); err != nil {
		t.Fatalf("构造过期请求: %v", err)
	}
	_ = expiredCredentialID
	rejections = append(rejections, rejection{"过期", facade.ValidateToken(ctx, expiredToken)})

	// 成功使用后（请求状态 consumed）。
	usedID, _, usedToken := insertPendingReset(t, runtime, user.ID)
	if _, err := runtime.base.Store.DB().ExecContext(ctx,
		`UPDATE password_reset_requests SET state='consumed',consumed_at_ms=? WHERE id=?`,
		time.Now().UnixMilli(), usedID); err != nil {
		t.Fatalf("构造已使用请求: %v", err)
	}
	rejections = append(rejections, rejection{"已使用", facade.ValidateToken(ctx, usedToken)})

	// 被新申请替代 / 显式取消（请求状态 cancelled）。
	cancelledID, _, cancelledToken := insertPendingReset(t, runtime, user.ID)
	if _, err := runtime.base.Store.DB().ExecContext(ctx,
		`UPDATE password_reset_requests SET state='cancelled' WHERE id=?`, cancelledID); err != nil {
		t.Fatalf("构造已取消请求: %v", err)
	}
	rejections = append(rejections, rejection{"已取消", facade.ValidateToken(ctx, cancelledToken)})

	// 凭证被撤销（请求仍 pending，必须依据凭证状态拒绝）。
	revokedID, revokedCredentialID, revokedToken := insertPendingReset(t, runtime, user.ID)
	if err := runtime.base.Services.Credential.Cancel(ctx, credential.CancelRequest{
		ID: revokedCredentialID, Purpose: "password.reset", Target: user.ID}); err != nil {
		t.Fatalf("撤销找回凭证: %v", err)
	}
	assertResetRequestPending(t, runtime, revokedID)
	rejections = append(rejections, rejection{"凭证已撤销", facade.ValidateToken(ctx, revokedToken)})

	// 账户改为 root。
	rootID, _, rootToken := insertPendingReset(t, runtime, user.ID)
	if _, err := runtime.base.Store.DB().ExecContext(ctx,
		`UPDATE users SET is_root=1 WHERE id=?`, user.ID); err != nil {
		t.Fatalf("改为 root: %v", err)
	}
	rejections = append(rejections, rejection{"root 账户", facade.ValidateToken(ctx, rootToken)})
	_ = rootID
	if _, err := runtime.base.Store.DB().ExecContext(ctx,
		`UPDATE users SET is_root=0 WHERE id=?`, user.ID); err != nil {
		t.Fatalf("恢复非 root: %v", err)
	}

	// 账户被禁用。
	disabledID, _, disabledToken := insertPendingReset(t, runtime, user.ID)
	if _, err := runtime.base.Store.DB().ExecContext(ctx,
		`UPDATE users SET status='disabled' WHERE id=?`, user.ID); err != nil {
		t.Fatalf("禁用账户: %v", err)
	}
	rejections = append(rejections, rejection{"账户禁用", facade.ValidateToken(ctx, disabledToken)})
	_ = disabledID
	if _, err := runtime.base.Store.DB().ExecContext(ctx,
		`UPDATE users SET status='active' WHERE id=?`, user.ID); err != nil {
		t.Fatalf("恢复账户: %v", err)
	}

	// 账户没有密码（找回不得为无密码账户添加密码）。
	_, _, noPasswordToken := insertPendingReset(t, runtime, user.ID)
	if _, err := runtime.base.Store.DB().ExecContext(ctx,
		`DELETE FROM password_credentials WHERE user_id=?`, user.ID); err != nil {
		t.Fatalf("移除密码: %v", err)
	}
	rejections = append(rejections, rejection{"无密码账户", facade.ValidateToken(ctx, noPasswordToken)})

	appErr, ok := login.AsAppError(rejections[0].err)
	if !ok {
		t.Fatalf("%s 未返回统一 AppError: %v", rejections[0].name, rejections[0].err)
	}
	for _, item := range rejections {
		if item.err == nil {
			t.Fatalf("%s 必须被拒绝", item.name)
		}
		current, ok := login.AsAppError(item.err)
		if !ok {
			t.Fatalf("%s 未返回统一 AppError: %v", item.name, item.err)
		}
		if current.Code() != login.CodeChallengeInvalid {
			t.Errorf("%s 错误码 = %s，期望 CHALLENGE_INVALID", item.name, current.Code())
		}
		if current.Message() != appErr.Message() {
			t.Errorf("%s 公开消息 = %q，与基线 %q 不一致（存在枚举风险）",
				item.name, current.Message(), appErr.Message())
		}
	}
}

// seedVerifiedEmail 为真实运行时用户写入一条已验证邮箱（模拟注册/验证后的状态）。
func seedVerifiedEmail(t *testing.T, runtime *Runtime, userID, address string) {
	t.Helper()
	now := time.Now().UTC().UnixMilli()
	if _, err := runtime.base.Store.DB().ExecContext(context.Background(),
		`INSERT INTO user_emails(email_normalized,user_id,email,verified_at_ms,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?)`, strings.ToLower(address), userID, address, now, now, now); err != nil {
		t.Fatalf("写入已验证邮箱: %v", err)
	}
}

// insertPendingReset 通过真实凭证服务签发一次性凭证，并写入一条 pending 找回请求，
// 返回可直接展示给用户的 token（等价于邮件已投递的结果）。不修改生产代码路径。
func insertPendingReset(t *testing.T, runtime *Runtime, userID string) (resetID, credentialID, token string) {
	t.Helper()
	ctx := context.Background()
	issued, err := runtime.base.Services.Credential.Issue(ctx, credential.IssueRequest{
		Purpose: "password.reset", Target: userID, Kind: credential.KindToken,
		TTL: 15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("签发找回凭证: %v", err)
	}
	secret := issued.Secret.Reveal()
	digest := sha256.Sum256([]byte(secret))
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		t.Fatalf("生成找回请求 ID: %v", err)
	}
	resetID = "prq_" + hex.EncodeToString(randomBytes)
	// 步骤 206：找回请求带安全代际与最近已验证邮箱身份绑定；测试夹具按当前真实状态
	// 写入两列，避免把“未绑定旧行”误当成生产签发的有效入口。
	var securityVersion int64
	if err := runtime.base.Store.DB().QueryRowContext(ctx,
		`SELECT security_version FROM users WHERE id=?`, userID).Scan(&securityVersion); err != nil {
		t.Fatalf("读取账户安全版本: %v", err)
	}
	var boundEmailNormalized string
	if err := runtime.base.Store.DB().QueryRowContext(ctx,
		`SELECT email_normalized FROM user_emails WHERE user_id=? AND verified_at_ms IS NOT NULL
ORDER BY verified_at_ms DESC LIMIT 1`, userID).Scan(&boundEmailNormalized); err != nil {
		t.Fatalf("读取最近已验证邮箱: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	if _, err := runtime.base.Store.DB().ExecContext(ctx, `INSERT INTO password_reset_requests(
id,user_id,masked_email,credential_id,token_sha256,state,created_at_ms,expires_at_ms,consumed_at_ms,
security_version,bound_email_normalized
) VALUES(?,?,?,?,?,'pending',?,?,NULL,?,?)`,
		resetID, userID, "r***@example.test", issued.ID, digest[:],
		now.UnixMilli(), now.Add(15*time.Minute).UnixMilli(),
		securityVersion, boundEmailNormalized); err != nil {
		t.Fatalf("写入找回请求: %v", err)
	}
	return resetID, issued.ID, resetID + "." + secret
}

// assertResetRequestPending 断言找回请求仍是 pending 且未消费。
func assertResetRequestPending(t *testing.T, runtime *Runtime, resetID string) {
	t.Helper()
	var state string
	var consumed *int64
	if err := runtime.base.Store.DB().QueryRowContext(context.Background(),
		`SELECT state,consumed_at_ms FROM password_reset_requests WHERE id=?`, resetID).
		Scan(&state, &consumed); err != nil {
		t.Fatalf("读取找回请求: %v", err)
	}
	if state != "pending" || consumed != nil {
		t.Fatalf("预检查改变了找回请求状态: state=%s consumed=%v", state, consumed)
	}
}

// assertOneTimeCredentialActive 断言一次性凭证未消费、未撤销。
func assertOneTimeCredentialActive(t *testing.T, runtime *Runtime, credentialID string) {
	t.Helper()
	var consumed, revoked *int64
	if err := runtime.base.Store.DB().QueryRowContext(context.Background(),
		`SELECT consumed_at_ms,revoked_at_ms FROM one_time_credentials WHERE id=?`, credentialID).
		Scan(&consumed, &revoked); err != nil {
		t.Fatalf("读取一次性凭证: %v", err)
	}
	if consumed != nil || revoked != nil {
		t.Fatalf("预检查改变了凭证状态: consumed=%v revoked=%v", consumed, revoked)
	}
}

// tamperSecret 构造“resetID 正确但 secret 摘要错误”的 token。
func tamperSecret(resetID, secret string) string {
	buffer := []byte(secret)
	if buffer[0] == 'A' {
		buffer[0] = 'B'
	} else {
		buffer[0] = 'A'
	}
	return resetID + "." + string(buffer)
}
