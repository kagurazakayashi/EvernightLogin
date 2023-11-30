package app

// 步骤 234：账户有效期公开 Go 门面测试（LocalAdmin 受信边界）。
//
// 验证 Set/GetUserValidity 真实落库、到期/续期、手动禁用不解除、root 拒绝与读取
// 忽略期限；审计/授权由领域服务完成，本测试不绕过公开入口。

import (
	"context"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
)

// TestUserValidityPublicFacade 验证公开门面读写与边界。
func TestUserValidityPublicFacade(t *testing.T) {
	ctx := context.Background()
	runtime := openTestRuntime(t, Options{})
	caller := runtime.LocalAdmin()
	created, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "validity-public", Password: "K8$wR3!nB6@yF1#v",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建用户: %v", err)
	}
	validity, err := runtime.UserLifecycle().GetUserValidity(ctx, AdminUserRequest{
		Caller: caller, UserID: created.ID, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("默认有效期: %v", err)
	}
	if !validity.Available || validity.ValidFrom != nil || validity.ValidUntil != nil {
		t.Fatalf("默认应永久有效: %+v", validity)
	}
	now := time.Now().UTC()
	until := now.Add(time.Hour)
	change, err := runtime.UserLifecycle().SetUserValidity(ctx, AdminUserValidityRequest{
		Caller: caller, UserID: created.ID, ExpectedRowVersion: validity.RowVersion,
		ValidUntil: &until, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("设置有效期: %v", err)
	}
	if !change.Changed || change.Validity.RowVersion != validity.RowVersion+1 ||
		!change.Validity.Available {
		t.Fatalf("设置结果异常: %+v", change)
	}
	// 缩短到过去：立即不可用（到期是计算原因）。
	past := now.Add(-time.Hour)
	shortened, err := runtime.UserLifecycle().SetUserValidity(ctx,
		AdminUserValidityRequest{Caller: caller, UserID: created.ID,
			ExpectedRowVersion: change.Validity.RowVersion, ValidUntil: &past,
			RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("缩短有效期: %v", err)
	}
	if shortened.Validity.Available ||
		shortened.Validity.Reason != string(account.AvailabilityExpired) {
		t.Fatalf("缩短后应到期不可用: %+v", shortened.Validity)
	}
	// 手动禁用后延长：状态仍 disabled、不可用；续期不解除禁用。
	disabled, err := runtime.UserLifecycle().DisableUser(ctx, AdminUserStateRequest{
		Caller: caller, UserID: created.ID,
		ExpectedRowVersion: shortened.Validity.RowVersion,
		RequestID:          login.NewRequestID()})
	if err != nil {
		t.Fatalf("禁用: %v", err)
	}
	renewedUntil := now.Add(2 * time.Hour)
	renewed, err := runtime.UserLifecycle().SetUserValidity(ctx,
		AdminUserValidityRequest{Caller: caller, UserID: created.ID,
			ExpectedRowVersion: disabled.User.RowVersion, ValidUntil: &renewedUntil,
			RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("禁用后续期: %v", err)
	}
	if renewed.Validity.Status != string(account.StatusDisabled) ||
		renewed.Validity.Available {
		t.Fatalf("续期不得解除手动禁用: %+v", renewed.Validity)
	}
	// 非法区间：REQ_INVALID。
	invalidFrom := now.Add(2 * time.Hour)
	invalidUntil := now.Add(time.Hour)
	_, err = runtime.UserLifecycle().SetUserValidity(ctx, AdminUserValidityRequest{
		Caller: caller, UserID: created.ID,
		ExpectedRowVersion: renewed.Validity.RowVersion, ValidFrom: &invalidFrom,
		ValidUntil: &invalidUntil, RequestID: login.NewRequestID()})
	if err == nil || !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("空区间应返回 REQ_INVALID: %v", err)
	}
	// 旧版本并发：CONFLICT。
	_, err = runtime.UserLifecycle().SetUserValidity(ctx, AdminUserValidityRequest{
		Caller: caller, UserID: created.ID,
		ExpectedRowVersion: validity.RowVersion, ValidUntil: &renewedUntil,
		RequestID: login.NewRequestID()})
	if err == nil || !login.IsErrorCode(err, login.CodeConflict) {
		t.Fatalf("旧版本应返回 CONFLICT: %v", err)
	}
}

// TestUserValidityRootProtectedPublic 验证 root 拒绝设置、读取忽略期限。
func TestUserValidityRootProtectedPublic(t *testing.T) {
	ctx := context.Background()
	runtime := openTestRuntime(t, Options{})
	rootID := "usr_000000000000000000000000000000b1"
	nowMS := time.Now().UTC().UnixMilli()
	if _, err := runtime.base.Store.DB().ExecContext(ctx, `INSERT INTO users(id,
username,username_normalized,status,is_root,security_version,row_version,
created_at_ms,updated_at_ms,valid_from_ms,valid_until_ms)
VALUES(?,?,?,'active',1,1,1,?,?,?,?)`, rootID, "validity-root", "validity-root",
		nowMS, nowMS, nowMS-int64(24*time.Hour/time.Millisecond),
		nowMS-int64(time.Hour/time.Millisecond)); err != nil {
		t.Fatalf("写入 root: %v", err)
	}
	validity, err := runtime.UserLifecycle().GetUserValidity(ctx, AdminUserRequest{
		Caller: runtime.LocalAdmin(), UserID: rootID, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("读取 root 有效期: %v", err)
	}
	if !validity.IsRoot || !validity.Available {
		t.Fatalf("root 应忽略普通期限: %+v", validity)
	}
	until := time.Now().UTC().Add(time.Hour)
	_, err = runtime.UserLifecycle().SetUserValidity(ctx, AdminUserValidityRequest{
		Caller: runtime.LocalAdmin(), UserID: rootID,
		ExpectedRowVersion: validity.RowVersion, ValidUntil: &until,
		RequestID: login.NewRequestID()})
	if err == nil || !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("root 设置应 ACCESS_DENIED: %v", err)
	}
}
