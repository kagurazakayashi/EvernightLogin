package serverapp

// 步骤 259：直接重置密码管理路由的协议/桥接契约测试（真实授权/证明/事务由根包
// 257 门面测试覆盖；本文件只验证 HTTP 层不伪造身份、不绕过桥接、结果脱敏）。

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
)

// fakeDirectPasswordResetBridge 记录桥接调用并返回受控结果。
type fakeDirectPasswordResetBridge struct {
	beginChallenge DirectProofChallenge
	confirmGrant   DirectProofGrant
	resetResult    DirectPasswordResetResult
	resetErr       error
	lastBegin      struct{ operator, target, newPassword string }
	lastConfirm    struct{ operator, challenge, password, totp string }
	lastReset      DirectPasswordResetRequest
}

func (f *fakeDirectPasswordResetBridge) BeginPasswordResetVerification(_ context.Context,
	operatorID, targetID, newPassword, _ string) (DirectProofChallenge, error) {
	f.lastBegin.operator, f.lastBegin.target, f.lastBegin.newPassword =
		operatorID, targetID, newPassword
	return f.beginChallenge, nil
}

func (f *fakeDirectPasswordResetBridge) ConfirmPasswordResetVerification(_ context.Context,
	operatorID, challengeID, password, totp, _ string) (DirectProofGrant, error) {
	f.lastConfirm.operator, f.lastConfirm.challenge = operatorID, challengeID
	f.lastConfirm.password, f.lastConfirm.totp = password, totp
	return f.confirmGrant, nil
}

func (f *fakeDirectPasswordResetBridge) BeginPasswordResetWebAuthnVerification(context.Context,
	string, string, string) (DirectWebAuthnStart, error) {
	return DirectWebAuthnStart{}, nil
}

func (f *fakeDirectPasswordResetBridge) ConfirmPasswordResetWebAuthnVerification(context.Context,
	string, string, string, []byte, string) (DirectProofGrant, error) {
	return f.confirmGrant, nil
}

func (f *fakeDirectPasswordResetBridge) CancelPasswordResetVerification(context.Context,
	string, string, string) error {
	return nil
}

func (f *fakeDirectPasswordResetBridge) ResetPassword(_ context.Context,
	request DirectPasswordResetRequest) (DirectPasswordResetResult, error) {
	f.lastReset = request
	return f.resetResult, f.resetErr
}

const directPasswordTargetID = "usr_00000000000000000000000000000002"

// TestDirectPasswordResetRoutesUseTrustedCallerAndProof 覆盖：
//   - 操作者只来自可信 caller（body 伪造操作者字段被拒绝）；
//   - begin 接收目标与新口令（绑定意图）；confirm 接收密码+TOTP；
//   - 提交把证明令牌原样交给桥接一次，响应只含脱敏事实（无密码/哈希/证明）。
func TestDirectPasswordResetRoutesUseTrustedCallerAndProof(t *testing.T) {
	bridge := &fakeDirectPasswordResetBridge{
		beginChallenge: DirectProofChallenge{ChallengeID: "chl_pw_1",
			TargetUserID: directPasswordTargetID, RequiredStrength: "strong",
			ExpiresAt: time.Now().Add(time.Minute), MaxAttempts: 5},
		confirmGrant: DirectProofGrant{ProofToken: "proof-pw-once",
			TargetUserID: directPasswordTargetID, GrantedStrength: "strong"},
		resetResult: DirectPasswordResetResult{UserID: directPasswordTargetID,
			SecurityVersion: 9, MustChange: true, SessionsRevoked: 3,
			OldResetRequestsCancelled: 2, OldResetCredentialsRevoked: 2,
			OutboxEventID: "outbox_pw_1", PasswordChangedAt: time.Now()},
	}
	routes := buildAdminDirectPasswordResetRoutes(bridge,
		func(*http.Request) (string, bool) { return "session-secret", true })
	if len(routes) != 6 {
		t.Fatalf("路由数 = %d，期望 6", len(routes))
	}
	caller, err := account.UserCaller("usr_00000000000000000000000000000009")
	if err != nil {
		t.Fatalf("构造可信 caller: %v", err)
	}
	ctx := context.Background()

	forge := directRouteByPattern(t, routes, http.MethodPost,
		"users/{user_id}/password-verification")
	_, err = forge(ctx, caller, httptest.NewRequest(http.MethodPost,
		"/admin/v1/users/"+directPasswordTargetID+"/password-verification",
		bytes.NewBufferString(`{"new_password":"N3w!Passw0rd#259","operator_id":"usr_forged","confirm":true}`)))
	if domainErr, ok := err.(*adminapi.DomainError); !ok || domainErr.Code != "REQ_INVALID" {
		t.Fatalf("伪造调用者错误 = %#v，期望 REQ_INVALID", err)
	}
	reply, err := forge(ctx, caller, httptest.NewRequest(http.MethodPost,
		"/admin/v1/users/"+directPasswordTargetID+"/password-verification",
		bytes.NewBufferString(`{"new_password":"N3w!Passw0rd#259","confirm":true}`)))
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if bridge.lastBegin.operator != "usr_00000000000000000000000000000009" ||
		bridge.lastBegin.target != directPasswordTargetID ||
		bridge.lastBegin.newPassword != "N3w!Passw0rd#259" {
		t.Fatalf("begin 桥接参数 = %+v", bridge.lastBegin)
	}
	challengeJSON, _ := json.Marshal(reply)
	if !strings.Contains(string(challengeJSON), `"challenge_id":"chl_pw_1"`) {
		t.Fatalf("begin 响应 = %s", challengeJSON)
	}

	confirm := directRouteByPattern(t, routes, http.MethodPost,
		"users/{user_id}/password-verification/confirm")
	if _, err := confirm(ctx, caller, httptest.NewRequest(http.MethodPost,
		"/admin/v1/users/"+directPasswordTargetID+"/password-verification/confirm",
		bytes.NewBufferString(`{"challenge_id":"chl_pw_1","password":"AdminP@ss1","totp_code":"123456","confirm":true}`))); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if bridge.lastConfirm.password != "AdminP@ss1" || bridge.lastConfirm.totp != "123456" {
		t.Fatalf("confirm 桥接参数 = %+v", bridge.lastConfirm)
	}

	reset := directRouteByPattern(t, routes, http.MethodPost, "users/{user_id}/password")
	resetReply, err := reset(ctx, caller, httptest.NewRequest(http.MethodPost,
		"/admin/v1/users/"+directPasswordTargetID+"/password",
		bytes.NewBufferString(`{"new_password":"N3w!Passw0rd#259","reason":"用户申请","proof_token":"proof-pw-once","confirm":true}`)))
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	if bridge.lastReset.OperatorUserID != "usr_00000000000000000000000000000009" ||
		bridge.lastReset.TargetUserID != directPasswordTargetID ||
		bridge.lastReset.NewPassword != "N3w!Passw0rd#259" ||
		bridge.lastReset.Reason != "用户申请" ||
		bridge.lastReset.ProofToken != "proof-pw-once" {
		t.Fatalf("reset 桥接参数 = %+v", bridge.lastReset)
	}
	resultJSON, _ := json.Marshal(resetReply)
	for _, want := range []string{`"must_change":true`, `"security_version":9`,
		`"sessions_revoked":3`, `"old_reset_requests_cancelled":2`} {
		if !strings.Contains(string(resultJSON), want) {
			t.Fatalf("reset 响应缺少 %s: %s", want, resultJSON)
		}
	}
	for _, forbidden := range []string{"N3w!Passw0rd#259", "proof-pw-once", "AdminP@ss1"} {
		if strings.Contains(string(resultJSON), forbidden) {
			t.Fatalf("reset 响应泄露秘密 %q: %s", forbidden, resultJSON)
		}
	}
}

// TestDirectPasswordResetRoutesFailClosed 覆盖：无桥接不挂载；无管理会话秘密拒绝；
// 桥接稳定错误码原样投影且不泄露原因。
func TestDirectPasswordResetRoutesFailClosed(t *testing.T) {
	if routes := buildAdminDirectPasswordResetRoutes(nil,
		func(*http.Request) (string, bool) { return "s", true }); routes != nil {
		t.Fatalf("无桥接不应挂载路由: %d", len(routes))
	}
	bridge := &fakeDirectPasswordResetBridge{resetErr: NewDirectManagementError(
		"ACCESS_DENIED", errString("权限不足"))}
	routes := buildAdminDirectPasswordResetRoutes(bridge,
		func(*http.Request) (string, bool) { return "", false })
	caller, _ := account.UserCaller(directPasswordTargetID)
	begin := directRouteByPattern(t, routes, http.MethodPost,
		"users/{user_id}/password-verification")
	if _, err := begin(context.Background(), caller, httptest.NewRequest(http.MethodPost,
		"/admin/v1/users/"+directPasswordTargetID+"/password-verification",
		bytes.NewBufferString(`{"new_password":"x","confirm":true}`))); err != nil {
		if domainErr, ok := err.(*adminapi.DomainError); !ok || domainErr.Code != "ACCESS_DENIED" {
			t.Fatalf("缺少管理会话错误 = %#v", err)
		}
	} else {
		t.Fatal("缺少管理会话秘密应拒绝")
	}
	routes = buildAdminDirectPasswordResetRoutes(bridge,
		func(*http.Request) (string, bool) { return "session-secret", true })
	reset := directRouteByPattern(t, routes, http.MethodPost, "users/{user_id}/password")
	_, err := reset(context.Background(), caller, httptest.NewRequest(http.MethodPost,
		"/admin/v1/users/"+directPasswordTargetID+"/password",
		bytes.NewBufferString(`{"new_password":"x","reason":"r","proof_token":"p","confirm":true}`)))
	domainErr, ok := err.(*adminapi.DomainError)
	if !ok || domainErr.Code != "ACCESS_DENIED" {
		t.Fatalf("桥接错误投影 = %#v", err)
	}
	if strings.Contains(domainErr.Error(), "权限不足") {
		t.Fatal("错误投影泄露内部原因")
	}
}

// errString 是测试用简单 error（避免额外依赖）。
type errString string

// Error 实现 error。
func (e errString) Error() string { return string(e) }
