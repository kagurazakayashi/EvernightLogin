package serverapp

// 步骤 258：直接改名管理路由的协议/桥接契约测试（内部测试；真实授权/证明/事务
// 由根包门面测试覆盖，本文件只验证 HTTP 层不伪造身份、不绕过桥接、错误码投影）。

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
)

// fakeDirectUsernameBridge 记录桥接调用并返回受控结果。
type fakeDirectUsernameBridge struct {
	beginChallenge DirectProofChallenge
	beginErr       error
	confirmGrant   DirectProofGrant
	confirmErr     error
	changeResult   DirectUsernameChangeResult
	changeErr      error
	lastBegin      struct{ operator, target, newUsername, requestID string }
	lastConfirm    struct{ operator, challenge, password, totp string }
	lastChange     DirectUsernameChangeRequest
}

func (f *fakeDirectUsernameBridge) BeginUsernameVerification(_ context.Context,
	operatorID, targetID, newUsername, requestID string) (DirectProofChallenge, error) {
	f.lastBegin.operator, f.lastBegin.target = operatorID, targetID
	f.lastBegin.newUsername, f.lastBegin.requestID = newUsername, requestID
	return f.beginChallenge, f.beginErr
}

func (f *fakeDirectUsernameBridge) ConfirmUsernameVerification(_ context.Context,
	operatorID, challengeID, password, totp, _ string) (DirectProofGrant, error) {
	f.lastConfirm.operator, f.lastConfirm.challenge = operatorID, challengeID
	f.lastConfirm.password, f.lastConfirm.totp = password, totp
	return f.confirmGrant, f.confirmErr
}

func (f *fakeDirectUsernameBridge) BeginUsernameWebAuthnVerification(context.Context,
	string, string, string) (DirectWebAuthnStart, error) {
	return DirectWebAuthnStart{}, errors.New("not used")
}

func (f *fakeDirectUsernameBridge) ConfirmUsernameWebAuthnVerification(context.Context,
	string, string, string, []byte, string) (DirectProofGrant, error) {
	return DirectProofGrant{}, errors.New("not used")
}

func (f *fakeDirectUsernameBridge) CancelUsernameVerification(context.Context,
	string, string, string) error {
	return nil
}

func (f *fakeDirectUsernameBridge) ChangeUsername(_ context.Context,
	request DirectUsernameChangeRequest) (DirectUsernameChangeResult, error) {
	f.lastChange = request
	return f.changeResult, f.changeErr
}

// routeByPattern 返回指定方法/模式的路由处理器。
func directRouteByPattern(t *testing.T, routes []adminapi.DomainRoute, method, pattern string) adminapi.DomainHandler {
	t.Helper()
	for _, route := range routes {
		if route.Method == method && route.Pattern == pattern {
			return route.Handler
		}
	}
	t.Fatalf("未找到路由 %s %s", method, pattern)
	return nil
}

const directTestUserID = "usr_00000000000000000000000000000001"

// TestDirectUsernameRoutesUseTrustedCallerAndProof 覆盖：
//   - 操作者只来自可信 caller（请求体 operator_id 被 JSON 白名单拒绝）；
//   - begin 绑定目标/新用户名；confirm 接收密码+TOTP 并返回一次性证明；
//   - 提交改名把证明令牌原样交给桥接（HTTP 层不重复验证），返回值脱敏。
func TestDirectUsernameRoutesUseTrustedCallerAndProof(t *testing.T) {
	bridge := &fakeDirectUsernameBridge{
		beginChallenge: DirectProofChallenge{ChallengeID: "chl_1", Operation: "user.username.change.other",
			TargetUserID: directTestUserID, RequiredStrength: "strong",
			ExpiresAt: time.Now().Add(time.Minute), MaxAttempts: 5},
		confirmGrant: DirectProofGrant{ProofToken: "proof-once", ExpiresAt: time.Now().Add(time.Minute),
			Operation: "user.username.change.other", TargetUserID: directTestUserID,
			GrantedStrength: "strong"},
		changeResult: DirectUsernameChangeResult{UserID: directTestUserID, Username: "new-name",
			RowVersion: 8, UpdatedAt: time.Now()},
	}
	routes := buildAdminDirectUsernameRoutes(bridge,
		func(*http.Request) (string, bool) { return "session-secret", true })
	if len(routes) != 6 {
		t.Fatalf("路由数 = %d，期望 6", len(routes))
	}
	caller, err := account.UserCaller("usr_00000000000000000000000000000009")
	if err != nil {
		t.Fatalf("构造可信 caller: %v", err)
	}
	ctx := context.Background()

	// begin：请求体带 operator_id 必须被 JSON 白名单拒绝（不能从 body 伪造调用者）。
	begin := directRouteByPattern(t, routes, http.MethodPost, "users/{user_id}/username-verification")
	forgeBody := `{"new_username":"target-name","operator_id":"usr_forged","confirm":true}`
	forged, err := begin(ctx, caller, httptest.NewRequest(http.MethodPost,
		"/admin/v1/users/"+directTestUserID+"/username-verification",
		bytes.NewBufferString(forgeBody)))
	if err == nil {
		t.Fatalf("伪造调用者字段应被拒绝，返回 %+v", forged)
	}
	if domainErr, ok := err.(*adminapi.DomainError); !ok || domainErr.Code != "REQ_INVALID" {
		t.Fatalf("伪造调用者错误 = %#v，期望 REQ_INVALID", err)
	}
	reply, err := begin(ctx, caller, httptest.NewRequest(http.MethodPost,
		"/admin/v1/users/"+directTestUserID+"/username-verification",
		bytes.NewBufferString(`{"new_username":"target-name","confirm":true}`)))
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if bridge.lastBegin.operator != "usr_00000000000000000000000000000009" ||
		bridge.lastBegin.target != directTestUserID ||
		bridge.lastBegin.newUsername != "target-name" {
		t.Fatalf("begin 桥接参数 = %+v", bridge.lastBegin)
	}
	challengeJSON, _ := json.Marshal(reply)
	if !strings.Contains(string(challengeJSON), `"challenge_id":"chl_1"`) {
		t.Fatalf("begin 响应 = %s", challengeJSON)
	}

	// confirm：密码/TOTP 交给桥接；证明令牌只出现在受控响应中。
	confirm := directRouteByPattern(t, routes, http.MethodPost,
		"users/{user_id}/username-verification/confirm")
	confirmReply, err := confirm(ctx, caller, httptest.NewRequest(http.MethodPost,
		"/admin/v1/users/"+directTestUserID+"/username-verification/confirm",
		bytes.NewBufferString(`{"challenge_id":"chl_1","password":"P@ssw0rd-258","totp_code":"123456","confirm":true}`)))
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if bridge.lastConfirm.password != "P@ssw0rd-258" || bridge.lastConfirm.totp != "123456" ||
		bridge.lastConfirm.operator != "usr_00000000000000000000000000000009" {
		t.Fatalf("confirm 桥接参数 = %+v", bridge.lastConfirm)
	}
	grantJSON, _ := json.Marshal(confirmReply)
	if !strings.Contains(string(grantJSON), `"proof_token":"proof-once"`) {
		t.Fatalf("confirm 响应 = %s", grantJSON)
	}

	// 提交：证明令牌原样交给桥接一次（HTTP 层不重复两步验证）。
	change := directRouteByPattern(t, routes, http.MethodPost, "users/{user_id}/username")
	changeReply, err := change(ctx, caller, httptest.NewRequest(http.MethodPost,
		"/admin/v1/users/"+directTestUserID+"/username",
		bytes.NewBufferString(`{"new_username":"new-name","expected_row_version":7,"reason":"用户申请","proof_token":"proof-once","confirm":true}`)))
	if err != nil {
		t.Fatalf("change: %v", err)
	}
	if bridge.lastChange.OperatorUserID != "usr_00000000000000000000000000000009" ||
		bridge.lastChange.TargetUserID != directTestUserID ||
		bridge.lastChange.ProofToken != "proof-once" ||
		bridge.lastChange.ExpectedRowVersion != 7 || bridge.lastChange.Reason != "用户申请" {
		t.Fatalf("change 桥接参数 = %+v", bridge.lastChange)
	}
	resultJSON, _ := json.Marshal(changeReply)
	if !strings.Contains(string(resultJSON), `"username":"new-name"`) ||
		!strings.Contains(string(resultJSON), `"row_version":8`) {
		t.Fatalf("change 响应 = %s", resultJSON)
	}
}

// TestDirectUsernameRoutesFailClosed 覆盖：无桥接不挂载；无管理会话秘密拒绝；
// 桥接稳定错误码原样投影且不泄露原因。
func TestDirectUsernameRoutesFailClosed(t *testing.T) {
	if routes := buildAdminDirectUsernameRoutes(nil,
		func(*http.Request) (string, bool) { return "s", true }); routes != nil {
		t.Fatalf("无桥接不应挂载路由: %d", len(routes))
	}
	bridge := &fakeDirectUsernameBridge{changeErr: NewDirectManagementError("ACCESS_DENIED",
		errors.New("权限不足"))}
	routes := buildAdminDirectUsernameRoutes(bridge,
		func(*http.Request) (string, bool) { return "", false })
	caller, _ := account.UserCaller(directTestUserID)
	begin := directRouteByPattern(t, routes, http.MethodPost, "users/{user_id}/username-verification")
	_, err := begin(context.Background(), caller, httptest.NewRequest(http.MethodPost,
		"/admin/v1/users/"+directTestUserID+"/username-verification",
		bytes.NewBufferString(`{"new_username":"x","confirm":true}`)))
	if domainErr, ok := err.(*adminapi.DomainError); !ok || domainErr.Code != "ACCESS_DENIED" {
		t.Fatalf("缺少管理会话错误 = %#v，期望 ACCESS_DENIED", err)
	}
	routes = buildAdminDirectUsernameRoutes(bridge,
		func(*http.Request) (string, bool) { return "session-secret", true })
	change := directRouteByPattern(t, routes, http.MethodPost, "users/{user_id}/username")
	_, err = change(context.Background(), caller, httptest.NewRequest(http.MethodPost,
		"/admin/v1/users/"+directTestUserID+"/username",
		bytes.NewBufferString(`{"new_username":"x","reason":"r","proof_token":"p","expected_row_version":1,"confirm":true}`)))
	domainErr, ok := err.(*adminapi.DomainError)
	if !ok || domainErr.Code != "ACCESS_DENIED" {
		t.Fatalf("桥接错误投影 = %#v", err)
	}
	if strings.Contains(domainErr.Error(), "权限不足") {
		t.Fatal("错误投影泄露内部原因")
	}
}
