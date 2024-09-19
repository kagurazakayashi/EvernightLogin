package serverapp

// 步骤 259：直接重置他人密码的管理 JSON API 路由。
//
// 路由（均要求真实管理会话 + 管理强认证；Cookie 会话写请求由 adminapi 外壳强制
// CSRF；证明绑定操作/目标/新口令，提交即消费，不再重复弹两步验证）：
//
//	POST users/{user_id}/password-verification                  发起两步验证挑战（body 含 new_password，仅用于密封意图）
//	POST users/{user_id}/password-verification/confirm          密码 + TOTP 完成验证，返回一次性证明
//	POST users/{user_id}/password-verification/webauthn/begin   Passkey/安全密钥第二步开始
//	POST users/{user_id}/password-verification/webauthn/confirm Passkey/安全密钥第二步完成
//	POST users/{user_id}/password-verification/cancel           取消未完成挑战
//	POST users/{user_id}/password                               用一次性证明提交重置（body: new_password/reason/proof_token）
//
// 操作者身份只来自 adminapi 验证后的可信 caller；请求体中的操作者字段被显式拒绝。
// 密码、证明不进入响应/日志；提交结果只返回脱敏事实（must_change/会话撤销/旧找回失效）。

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
)

// buildAdminDirectPasswordResetRoutes 构造直接重置密码管理域路由；缺少桥接或会话
// 秘密提取能力时不挂载（fail-closed 404）。
func buildAdminDirectPasswordResetRoutes(bridge DirectPasswordResetBridge,
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
	add(http.MethodPost, "users/{user_id}/password-verification",
		func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
			body, err := adminWriteBody(request)
			if err != nil {
				return nil, err
			}
			if err := rejectOperatorOverride(body); err != nil {
				return nil, err
			}
			target := adminPathPartFromEnd(request, 2)
			challenge, err := bridge.BeginPasswordResetVerification(ctx, caller.Actor().ID,
				target, adminString(body, "new_password"), adminRequestID(body, request))
			if err != nil {
				return nil, directUsernameDomainError(err)
			}
			return directChallengeJSON(challenge), nil
		})
	add(http.MethodPost, "users/{user_id}/password-verification/confirm",
		func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
			body, err := adminWriteBody(request)
			if err != nil {
				return nil, err
			}
			if err := rejectOperatorOverride(body); err != nil {
				return nil, err
			}
			grant, err := bridge.ConfirmPasswordResetVerification(ctx, caller.Actor().ID,
				adminString(body, "challenge_id"), adminString(body, "password"),
				adminString(body, "totp_code"), adminRequestID(body, request))
			if err != nil {
				return nil, directUsernameDomainError(err)
			}
			return directGrantJSON(grant), nil
		})
	add(http.MethodPost, "users/{user_id}/password-verification/webauthn/begin",
		func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
			body, err := adminWriteBody(request)
			if err != nil {
				return nil, err
			}
			if err := rejectOperatorOverride(body); err != nil {
				return nil, err
			}
			start, err := bridge.BeginPasswordResetWebAuthnVerification(ctx,
				caller.Actor().ID, adminString(body, "challenge_id"),
				adminRequestID(body, request))
			if err != nil {
				return nil, directUsernameDomainError(err)
			}
			return map[string]any{"challenge_id": start.ChallengeID,
				"ceremony_id": start.CeremonyID, "public_key": start.PublicKey,
				"rp_id": start.RPID, "expires_at": start.ExpiresAt}, nil
		})
	add(http.MethodPost, "users/{user_id}/password-verification/webauthn/confirm",
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
			grant, err := bridge.ConfirmPasswordResetWebAuthnVerification(ctx,
				caller.Actor().ID, adminString(body, "challenge_id"),
				adminString(body, "ceremony_id"), response, adminRequestID(body, request))
			if err != nil {
				return nil, directUsernameDomainError(err)
			}
			return directGrantJSON(grant), nil
		})
	add(http.MethodPost, "users/{user_id}/password-verification/cancel",
		func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
			body, err := adminWriteBody(request)
			if err != nil {
				return nil, err
			}
			if err := rejectOperatorOverride(body); err != nil {
				return nil, err
			}
			if err := bridge.CancelPasswordResetVerification(ctx, caller.Actor().ID,
				adminString(body, "challenge_id"), adminRequestID(body, request)); err != nil {
				return nil, directUsernameDomainError(err)
			}
			return map[string]any{"cancelled": true}, nil
		})
	add(http.MethodPost, "users/{user_id}/password",
		func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
			body, err := adminWriteBody(request)
			if err != nil {
				return nil, err
			}
			if err := rejectOperatorOverride(body); err != nil {
				return nil, err
			}
			target := adminPathPartFromEnd(request, 2)
			result, err := bridge.ResetPassword(ctx, DirectPasswordResetRequest{
				OperatorUserID: caller.Actor().ID, TargetUserID: target,
				NewPassword: adminString(body, "new_password"),
				Reason:      adminString(body, "reason"),
				ProofToken:  adminString(body, "proof_token"),
				RequestID:   adminRequestID(body, request)})
			if err != nil {
				return nil, directUsernameDomainError(err)
			}
			return directPasswordResetResultJSON(result), nil
		})
	return routes
}

// directPasswordResetResultJSON 投影重置结果；不含密码/哈希/种子/证明。
func directPasswordResetResultJSON(result DirectPasswordResetResult) map[string]any {
	return map[string]any{"user_id": result.UserID,
		"security_version":    result.SecurityVersion,
		"password_changed_at": result.PasswordChangedAt, "must_change": result.MustChange,
		"sessions_revoked":              result.SessionsRevoked,
		"old_reset_requests_cancelled":  result.OldResetRequestsCancelled,
		"old_reset_credentials_revoked": result.OldResetCredentialsRevoked,
		"outbox_event_id":               result.OutboxEventID}
}
