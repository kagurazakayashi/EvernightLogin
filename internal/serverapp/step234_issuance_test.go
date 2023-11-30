package serverapp

// 步骤 234：令牌签发入口账户有效期即时校验测试。
//
// 覆盖授权码/设备码/刷新等所有“既有授权记录后的用户令牌签发”共用入口：
// 账户到期/未开始时签发拒绝；续期后当刻恢复；服务主体令牌不受用户期限影响。

import (
	"context"
	"testing"
	"time"

	accountsqlite "github.com/kagurazakayashi/EvernightLogin/internal/account/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/token"
)

// TestProtocolIssuanceAuthorizerAccountValidity 验证签发授权器即时复核账户可用性。
func TestProtocolIssuanceAuthorizerAccountValidity(t *testing.T) {
	ctx := context.Background()
	base, err := OpenBase(ctx, BaseOptions{
		Config: baseTestConfig(t), Keyring: newTestKeyring(t), Migrate: true,
		Logger: baseTestLogger(), Now: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("OpenBase: %v", err)
	}
	t.Cleanup(func() { _ = base.Close(context.Background()) })
	accounts, err := accountsqlite.New(base.Store)
	if err != nil {
		t.Fatalf("账户存储: %v", err)
	}
	userID := "usr_000000000000000000000000000000c1"
	nowMS := testNow.UTC().UnixMilli()
	if _, err := base.Store.DB().ExecContext(ctx, `INSERT INTO users(id,username,
username_normalized,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'active',0,1,1,?,?)`, userID, "issuance-validity", "issuance-validity",
		nowMS, nowMS); err != nil {
		t.Fatalf("写入用户: %v", err)
	}
	authorizer := protocolIssuanceAuthorizer{accounts: accounts,
		now: func() time.Time { return testNow }}
	system, err := token.SystemCaller("test-system")
	if err != nil {
		t.Fatalf("系统调用者: %v", err)
	}
	request := token.IssuanceRequest{ClientID: "test-client",
		SubjectUserID: userID, GrantType: token.GrantAuthorizationCode,
		TokenKind: "access", Scopes: []string{"openid"}}
	if err := authorizer.AuthorizeIssuance(ctx, system, request); err != nil {
		t.Fatalf("无期限账户签发应允许: %v", err)
	}
	// valid_until = 当前时刻：右端半开，拒绝。
	if _, err := base.Store.DB().ExecContext(ctx,
		`UPDATE users SET valid_until_ms=? WHERE id=?`, nowMS, userID); err != nil {
		t.Fatalf("设置到期: %v", err)
	}
	if err := authorizer.AuthorizeIssuance(ctx, system, request); err == nil {
		t.Fatal("到期账户签发应拒绝")
	}
	// valid_from 未到：拒绝。
	future := nowMS + int64(time.Hour/time.Millisecond)
	if _, err := base.Store.DB().ExecContext(ctx,
		`UPDATE users SET valid_from_ms=?, valid_until_ms=NULL WHERE id=?`, future, userID); err != nil {
		t.Fatalf("设置未来起点: %v", err)
	}
	if err := authorizer.AuthorizeIssuance(ctx, system, request); err == nil {
		t.Fatal("未开始账户签发应拒绝")
	}
	// 续期覆盖当前：恢复。
	past := nowMS - int64(time.Hour/time.Millisecond)
	if _, err := base.Store.DB().ExecContext(ctx,
		`UPDATE users SET valid_from_ms=?, valid_until_ms=? WHERE id=?`,
		past, future, userID); err != nil {
		t.Fatalf("续期: %v", err)
	}
	if err := authorizer.AuthorizeIssuance(ctx, system, request); err != nil {
		t.Fatalf("续期后签发应恢复: %v", err)
	}
	// 服务主体令牌（subject 为 client_id）不受用户期限影响。
	serviceRequest := request
	serviceRequest.SubjectUserID = "client-service-1"
	if err := authorizer.AuthorizeIssuance(ctx, system, serviceRequest); err != nil {
		t.Fatalf("服务主体签发不应受用户期限影响: %v", err)
	}
}
