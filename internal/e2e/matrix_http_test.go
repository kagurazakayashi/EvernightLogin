package e2e

// 步骤 274 矩阵四：直接管理 HTTP 管理 API（258 改名 / 259 重置口令）。
//
// 使用真实嵌入式 HTTP 装配（app.Open + HTTPOptions{EnableAdminAPI,EnableProtocol}）
// 与 httptest 服务，通过 Authorization: Bearer <真实管理会话> 调用真实管理 JSON API：
//   - 258 改名：发起挑战→密码+TOTP 确认→一次性证明→提交；响应/数据库真实结果、ID 稳定；
//   - 259 重置口令：挑战绑定新口令→确认→提交；must_change=true、旧会话失效；
//   - 负向：匿名、无权限会话、请求体冒充操作者（operator/user_id 覆盖）、证明换口令、
//     证明重放均拒绝；页面入口未认证不返回管理内容；
//   - 响应与 CLI 输出均不得包含管理密码、TOTP 验证码、一次性证明或新口令（除绑定提交外
//     的一次性证明由设计只返回一次，不在本次断言排除范围：其只出现在 confirm 响应）。

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	loginapp "github.com/kagurazakayashi/EvernightLogin/app"
)

// httpDirectOperator 准备 HTTP 矩阵的操作者会话（两项直接管理权限 + TOTP）。
func httpDirectOperator(t *testing.T, env *harnessEnv) (session []byte, totpSecret string) {
	t.Helper()
	operator, secret := enrollTOTP(t, env.Runtime, env.Clock, "http-matrix-operator",
		operatorPassword)
	grantSystemPermissions(t, env.Runtime, operator.ID, "http-matrix-role",
		"users.username.change.other", "users.password.reset.other", "users.read")
	session = issueStrongManagementSession(t, env, operator.ID, "http-matrix-operator")
	return session, secret
}

// TestMatrixHTTPDirectManagement 覆盖 HTTP 管理 API 的改名/重置口令闭环与拒绝边界。
func TestMatrixHTTPDirectManagement(t *testing.T) {
	env := openEnvHTTP(t)
	server := startHTTP(t, env.Runtime)
	operatorSession, operatorTOTP := httpDirectOperator(t, env)
	bearer := string(operatorSession)

	// 1) 258 改名成功链。
	renameTarget := createUser(t, env.Runtime, "http-rename-target", targetPassword)
	env.Clock.Advance(30 * time.Second)
	begin := httpCall(t, server, http.MethodPost,
		"/admin/v1/users/"+renameTarget.ID+"/username-verification", bearer,
		map[string]any{"new_username": "http-renamed", "confirm": true})
	beginData := requireHTTPData(t, begin, "258 发起改名验证")
	challengeID, _ := beginData["challenge_id"].(string)
	if challengeID == "" {
		t.Fatalf("258 挑战缺少 challenge_id: %+v", beginData)
	}
	confirm := httpCall(t, server, http.MethodPost,
		"/admin/v1/users/"+renameTarget.ID+"/username-verification/confirm", bearer,
		map[string]any{"challenge_id": challengeID, "password": operatorPassword,
			"totp_code": totpCode(t, env.Clock, operatorTOTP), "confirm": true})
	confirmData := requireHTTPData(t, confirm, "258 完成改名验证")
	proofToken, _ := confirmData["proof_token"].(string)
	if proofToken == "" {
		t.Fatalf("258 验证未返回一次性证明: %+v", confirmData)
	}
	submit := httpCall(t, server, http.MethodPost,
		"/admin/v1/users/"+renameTarget.ID+"/username", bearer,
		map[string]any{"new_username": "http-renamed", "reason": "步骤274 HTTP 矩阵",
			"expected_row_version": userRowVersion(t, env.DBPath, renameTarget.ID),
			"proof_token":          proofToken, "confirm": true})
	submitData := requireHTTPData(t, submit, "258 提交改名")
	userPayload, _ := submitData["user"].(map[string]any)
	if userPayload == nil || userPayload["id"] != renameTarget.ID ||
		userPayload["username"] != "http-renamed" {
		t.Fatalf("258 改名响应异常: %+v", submitData)
	}
	resolved, err := env.Runtime.Admin().GetUserByUsername(context.Background(),
		loginapp.AdminUserByUsernameRequest{Caller: env.Runtime.LocalAdmin(),
			Username: "http-renamed", RequestID: login.NewRequestID()})
	if err != nil || resolved.ID != renameTarget.ID {
		t.Fatalf("258 改名后数据库未落到目标 ID: %+v err=%v", resolved, err)
	}
	// 证明重放：同名校验或证明已消费，都必须非 2xx 且不改名。
	replay := httpCall(t, server, http.MethodPost,
		"/admin/v1/users/"+renameTarget.ID+"/username", bearer,
		map[string]any{"new_username": "http-renamed", "reason": "重放",
			"expected_row_version": userRowVersion(t, env.DBPath, renameTarget.ID),
			"proof_token":          proofToken, "confirm": true})
	if code := requireHTTPFailure(t, replay, "258 证明重放"); code != "TOKEN_INVALID" &&
		code != "REQ_INVALID" && code != "CONFLICT" {
		t.Fatalf("258 重放错误码 = %q", code)
	}

	// 2) 259 重置口令成功链：证明绑定新口令，提交后 must_change 且旧会话失效。
	resetTarget := createUser(t, env.Runtime, "http-reset-target", targetPassword)
	oldSession := loginFull(t, env.Runtime, "http-reset-target", targetPassword).SessionSecret
	env.Clock.Advance(30 * time.Second)
	resetBegin := httpCall(t, server, http.MethodPost,
		"/admin/v1/users/"+resetTarget.ID+"/password-verification", bearer,
		map[string]any{"new_password": directPasswordA, "confirm": true})
	resetBeginData := requireHTTPData(t, resetBegin, "259 发起重置验证")
	resetChallenge, _ := resetBeginData["challenge_id"].(string)
	resetConfirm := httpCall(t, server, http.MethodPost,
		"/admin/v1/users/"+resetTarget.ID+"/password-verification/confirm", bearer,
		map[string]any{"challenge_id": resetChallenge, "password": operatorPassword,
			"totp_code": totpCode(t, env.Clock, operatorTOTP), "confirm": true})
	resetConfirmData := requireHTTPData(t, resetConfirm, "259 完成重置验证")
	resetProof, _ := resetConfirmData["proof_token"].(string)
	if resetProof == "" {
		t.Fatalf("259 验证未返回证明: %+v", resetConfirmData)
	}
	resetSubmit := httpCall(t, server, http.MethodPost,
		"/admin/v1/users/"+resetTarget.ID+"/password", bearer,
		map[string]any{"new_password": directPasswordA, "reason": "步骤274 HTTP 矩阵",
			"proof_token": resetProof, "confirm": true})
	resetData := requireHTTPData(t, resetSubmit, "259 提交重置")
	if mustChange, _ := resetData["must_change"].(bool); !mustChange {
		t.Fatalf("259 重置结果缺少 must_change: %+v", resetData)
	}
	if _, err := env.Runtime.Sessions().Validate(context.Background(), oldSession); err == nil {
		t.Fatal("259 重置后目标旧会话仍有效")
	}
	restrictedLogin, loginErr := env.Runtime.Auth().Login(context.Background(),
		loginapp.LoginRequest{Username: "http-reset-target", Password: directPasswordA,
			ClientIP: "127.0.0.1", RequestID: login.NewRequestID()})
	if loginErr != nil || !restrictedLogin.Restricted {
		t.Fatalf("259 重置后新口令登录应为受限改密: err=%v result=%+v",
			loginErr, restrictedLogin)
	}

	// 3) 负向：匿名请求、无权限会话、请求体冒充操作者、证明绑定换口令。
	anonymous := httpCall(t, server, http.MethodPost,
		"/admin/v1/users/"+renameTarget.ID+"/username-verification", "",
		map[string]any{"new_username": "http-anonymous", "confirm": true})
	requireHTTPFailure(t, anonymous, "HTTP 匿名直接管理")
	createUser(t, env.Runtime, "http-ordinary", targetPassword)
	ordinarySession := loginFull(t, env.Runtime, "http-ordinary", targetPassword).SessionSecret
	noPermission := httpCall(t, server, http.MethodPost,
		"/admin/v1/users/"+renameTarget.ID+"/username-verification",
		string(ordinarySession), map[string]any{"new_username": "http-denied", "confirm": true})
	if code := requireHTTPFailure(t, noPermission, "HTTP 无权限直接管理"); code != "ACCESS_DENIED" &&
		code != "REAUTH_REQUIRED" {
		t.Fatalf("HTTP 无权限错误码 = %q", code)
	}
	override := httpCall(t, server, http.MethodPost,
		"/admin/v1/users/"+renameTarget.ID+"/username-verification", bearer,
		map[string]any{"new_username": "http-override", "user_id": renameTarget.ID, "confirm": true})
	if code := requireHTTPFailure(t, override, "HTTP 冒充操作者字段"); code != "REQ_INVALID" {
		t.Fatalf("HTTP 冒充操作者错误码 = %q", code)
	}
	// 证明绑定新口令：用绑定 A 的证明提交 B 必须拒绝且目标旧口令仍可用。
	crossTarget := createUser(t, env.Runtime, "http-cross-target", targetPassword)
	env.Clock.Advance(30 * time.Second)
	crossBegin := httpCall(t, server, http.MethodPost,
		"/admin/v1/users/"+crossTarget.ID+"/password-verification", bearer,
		map[string]any{"new_password": directPasswordA, "confirm": true})
	crossChallenge := requireHTTPData(t, crossBegin, "跨口令发起")["challenge_id"].(string)
	crossConfirm := httpCall(t, server, http.MethodPost,
		"/admin/v1/users/"+crossTarget.ID+"/password-verification/confirm", bearer,
		map[string]any{"challenge_id": crossChallenge, "password": operatorPassword,
			"totp_code": totpCode(t, env.Clock, operatorTOTP), "confirm": true})
	crossProof := requireHTTPData(t, crossConfirm, "跨口令确认")["proof_token"].(string)
	crossSubmit := httpCall(t, server, http.MethodPost,
		"/admin/v1/users/"+crossTarget.ID+"/password", bearer,
		map[string]any{"new_password": directPasswordB, "reason": "换口令",
			"proof_token": crossProof, "confirm": true})
	if code := requireHTTPFailure(t, crossSubmit, "证明换新口令"); code != "TOKEN_INVALID" &&
		code != "REQ_INVALID" {
		t.Fatalf("证明换新口令错误码 = %q", code)
	}
	// 页面入口未认证不得返回管理内容（直接改名页面为受保护页面）。
	pageRequest, err := http.NewRequest(http.MethodGet,
		server.URL+"/admin/users/"+renameTarget.ID+"/rename", nil)
	if err != nil {
		t.Fatalf("构造页面请求: %v", err)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	pageResponse, err := client.Do(pageRequest)
	if err != nil {
		t.Fatalf("页面请求: %v", err)
	}
	defer pageResponse.Body.Close()
	pageBody, _ := io.ReadAll(io.LimitReader(pageResponse.Body, 1<<18))
	if pageResponse.StatusCode == http.StatusOK &&
		bytes.Contains(pageBody, []byte("http-renamed")) {
		t.Fatal("未认证请求直接管理页面返回了管理内容")
	}
	// 253 结转的“强认证完成窗口”集成断言：管理强认证超过窗口后，即使会话本身仍有效，
	// 直接管理 API 也必须拒绝并要求重新完成强认证（不能凭旧强认证时间窗口继续敏感操作）。
	// 推进超过 15 分钟管理强认证窗口，但小于会话空闲期（30 分钟）。
	env.Clock.Advance(16 * time.Minute)
	staleWindow := httpCall(t, server, http.MethodPost,
		"/admin/v1/users/"+renameTarget.ID+"/username-verification", bearer,
		map[string]any{"new_username": "http-stale-window", "confirm": true})
	if code := requireHTTPFailure(t, staleWindow, "强认证窗口过期"); code != "REAUTH_REQUIRED" &&
		code != "ACCESS_DENIED" && code != "AUTH_FAILED" {
		t.Fatalf("强认证窗口过期错误码 = %q，期望 REAUTH_REQUIRED/ACCESS_DENIED", code)
	}
}
