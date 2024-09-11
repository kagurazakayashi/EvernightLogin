package serverapp

// 步骤 258：直接修改他人用户名的管理 JSON API 路由。
//
// 路由（均要求真实管理会话 + 管理强认证；Cookie 会话写请求由 adminapi 外壳强制
// CSRF，本层不另开旁路）：
//
//	POST users/{user_id}/username-verification                 发起两步验证挑战
//	POST users/{user_id}/username-verification/confirm         密码 + TOTP 完成验证，返回一次性证明
//	POST users/{user_id}/username-verification/webauthn/begin  Passkey/安全密钥第二步开始
//	POST users/{user_id}/username-verification/webauthn/confirm Passkey/安全密钥第二步完成
//	POST users/{user_id}/username-verification/cancel          取消未完成挑战
//	POST users/{user_id}/username                              用一次性证明提交改名
//
// 操作者身份只来自 adminapi 验证后的可信 caller；请求体中的任何操作者字段都不被
// 读取。授权/证明绑定/事务提交由宿主桥接实现（见 DirectUsernameBridge）。

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
)

// buildAdminDirectUsernameRoutes 构造直接改名的管理域路由；缺少桥接或会话秘密
// 提取能力时不挂载（fail-closed 404）。
func buildAdminDirectUsernameRoutes(bridge DirectUsernameBridge,
	sessionSecret func(*http.Request) (string, bool)) []adminapi.DomainRoute {
	if bridge == nil || sessionSecret == nil {
		return nil
	}
	routes := make([]adminapi.DomainRoute, 0, 6)
	add := func(method, pattern string,
		handler func(ctx context.Context, caller account.Caller,
			request *http.Request) (any, error)) {
		routes = append(routes, adminapi.DomainRoute{Method: method, Pattern: pattern,
			Handler: func(ctx context.Context, caller account.Caller,
				request *http.Request) (any, error) {
				secret, ok := sessionSecret(request)
				if !ok || strings.TrimSpace(secret) == "" {
					return nil, &adminapi.DomainError{Code: "ACCESS_DENIED",
						Message: "管理会话无效"}
				}
				ctx = WithManagementSessionSecret(ctx, secret)
				return handler(ctx, caller, request)
			}})
	}
	add(http.MethodPost, "users/{user_id}/username-verification",
		func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
			body, err := adminWriteBody(request)
			if err != nil {
				return nil, err
			}
			if err := rejectOperatorOverride(body); err != nil {
				return nil, err
			}
			target := adminPathPartFromEnd(request, 2)
			challenge, err := bridge.BeginUsernameVerification(ctx, caller.Actor().ID,
				target, adminString(body, "new_username"), adminRequestID(body, request))
			if err != nil {
				return nil, directUsernameDomainError(err)
			}
			return directChallengeJSON(challenge), nil
		})
	add(http.MethodPost, "users/{user_id}/username-verification/confirm",
		func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
			body, err := adminWriteBody(request)
			if err != nil {
				return nil, err
			}
			if err := rejectOperatorOverride(body); err != nil {
				return nil, err
			}
			grant, err := bridge.ConfirmUsernameVerification(ctx, caller.Actor().ID,
				adminString(body, "challenge_id"), adminString(body, "password"),
				adminString(body, "totp_code"), adminRequestID(body, request))
			if err != nil {
				return nil, directUsernameDomainError(err)
			}
			return directGrantJSON(grant), nil
		})
	add(http.MethodPost, "users/{user_id}/username-verification/webauthn/begin",
		func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
			body, err := adminWriteBody(request)
			if err != nil {
				return nil, err
			}
			if err := rejectOperatorOverride(body); err != nil {
				return nil, err
			}
			start, err := bridge.BeginUsernameWebAuthnVerification(ctx,
				caller.Actor().ID, adminString(body, "challenge_id"),
				adminRequestID(body, request))
			if err != nil {
				return nil, directUsernameDomainError(err)
			}
			return map[string]any{"challenge_id": start.ChallengeID,
				"ceremony_id": start.CeremonyID, "public_key": start.PublicKey,
				"rp_id": start.RPID, "expires_at": start.ExpiresAt}, nil
		})
	add(http.MethodPost, "users/{user_id}/username-verification/webauthn/confirm",
		func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
			body, err := adminWriteBody(request)
			if err != nil {
				return nil, err
			}
			if err := rejectOperatorOverride(body); err != nil {
				return nil, err
			}
			response, decodeErr := base64.StdEncoding.DecodeString(adminString(body, "response_b64"))
			if decodeErr != nil {
				return nil, &adminapi.DomainError{Code: "REQ_INVALID",
					Message: "WebAuthn 响应必须是 base64"}
			}
			grant, err := bridge.ConfirmUsernameWebAuthnVerification(ctx,
				caller.Actor().ID, adminString(body, "challenge_id"),
				adminString(body, "ceremony_id"), response, adminRequestID(body, request))
			if err != nil {
				return nil, directUsernameDomainError(err)
			}
			return directGrantJSON(grant), nil
		})
	add(http.MethodPost, "users/{user_id}/username-verification/cancel",
		func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
			body, err := adminWriteBody(request)
			if err != nil {
				return nil, err
			}
			if err := rejectOperatorOverride(body); err != nil {
				return nil, err
			}
			if err := bridge.CancelUsernameVerification(ctx, caller.Actor().ID,
				adminString(body, "challenge_id"), adminRequestID(body, request)); err != nil {
				return nil, directUsernameDomainError(err)
			}
			return map[string]any{"cancelled": true}, nil
		})
	add(http.MethodPost, "users/{user_id}/username",
		func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
			body, err := adminWriteBody(request)
			if err != nil {
				return nil, err
			}
			if err := rejectOperatorOverride(body); err != nil {
				return nil, err
			}
			target := adminPathPartFromEnd(request, 2)
			result, err := bridge.ChangeUsername(ctx, DirectUsernameChangeRequest{
				OperatorUserID: caller.Actor().ID, TargetUserID: target,
				NewUsername:        adminString(body, "new_username"),
				ExpectedRowVersion: adminInt64(body, "expected_row_version"),
				Reason:             adminString(body, "reason"),
				ProofToken:         adminString(body, "proof_token"),
				RequestID:          adminRequestID(body, request)})
			if err != nil {
				return nil, directUsernameDomainError(err)
			}
			return map[string]any{"user": map[string]any{
				"id": result.UserID, "username": result.Username,
				"row_version": result.RowVersion, "updated_at": result.UpdatedAt}}, nil
		})
	return routes
}

// adminPathPartFromEnd 读取路径中倒数第 offset 段（offset=1 为最后一段）；
// 直接改名路由的 user_id 后面固定跟随 1～4 段协议后缀。
func adminPathPartFromEnd(request *http.Request, offset int) string {
	if request == nil || offset < 1 {
		return ""
	}
	parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	index := len(parts) - offset
	if index < 0 {
		return ""
	}
	return strings.TrimSpace(parts[index])
}

// rejectOperatorOverride 拒绝在请求体中携带操作者字段的请求：操作者身份只能来自
// 已校验的管理会话 caller，任何 body 操作者/用户身份字段都不能冒充或覆盖可信身份。
func rejectOperatorOverride(fields map[string]json.RawMessage) error {
	for _, key := range []string{"operator_id", "operator_user_id", "user_id", "operator"} {
		if _, exists := fields[key]; exists {
			return &adminapi.DomainError{Code: "REQ_INVALID",
				Message: "请求体不能包含操作者身份字段"}
		}
	}
	return nil
}

// directChallengeJSON 投影挑战（不含密封意图）。
func directChallengeJSON(challenge DirectProofChallenge) map[string]any {
	return map[string]any{"challenge_id": challenge.ChallengeID,
		"operation": challenge.Operation, "target_user_id": challenge.TargetUserID,
		"required_strength": challenge.RequiredStrength,
		"expires_at":        challenge.ExpiresAt, "max_attempts": challenge.MaxAttempts,
		"webauthn_available": challenge.WebAuthnAvailable}
}

// directGrantJSON 投影一次性证明；调用方必须立即使用或写入受保护文件。
func directGrantJSON(grant DirectProofGrant) map[string]any {
	return map[string]any{"proof_token": grant.ProofToken,
		"expires_at": grant.ExpiresAt, "operation": grant.Operation,
		"target_user_id": grant.TargetUserID, "granted_strength": grant.GrantedStrength}
}

// directUsernameDomainError 把桥接错误投影为管理 API 稳定错误；未识别错误一律
// INTERNAL_ERROR，不泄露内部细节。
func directUsernameDomainError(err error) error {
	if err == nil {
		return nil
	}
	typed, ok := err.(*DirectManagementError)
	if !ok {
		return &adminapi.DomainError{Code: "INTERNAL_ERROR", Cause: err}
	}
	code := strings.TrimSpace(typed.Code)
	if code == "" {
		code = "INTERNAL_ERROR"
	}
	return &adminapi.DomainError{Code: code, Cause: err}
}
