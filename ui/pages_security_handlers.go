package ui

import (
	"context"
	"errors"
	"net/http"
	"strconv"
)

// sectionData 构造页面分区数据（错误时保留其他区域）。
func (h *securityPageHandlers) pagePageSize(request *http.Request) (int, int, bool) {
	page := 1
	pageSize := 20
	if raw := request.URL.Query().Get("page"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 1000000 {
			return 0, 0, false
		}
		page = value
	}
	if raw := request.URL.Query().Get("page_size"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 50 {
			return 0, 0, false
		}
		pageSize = value
	}
	return page, pageSize, true
}

// mfa 处理邮件因素页。
func (h *securityPageHandlers) mfa(ctx context.Context, request *http.Request,
	page UIPageContext, backend UIPageSecurityBackend, userID string) (UIPageOutcome, error) {
	switch page.RouteName {
	case "account.security_mfa.add_start":
		if request.Method != http.MethodPost {
			return UIPageOutcome{StatusCode: http.StatusMethodNotAllowed}, nil
		}
		enrollment, err := backend.BeginMFAEnrollment(ctx, userID, page.RequestID)
		if err != nil {
			return accountErrorOutcome(err, map[string]any{}, ""), nil
		}
		return UIPageOutcome{Data: map[string]any{"Enrollment": enrollment}}, nil
	case "account.security_mfa.add_confirm":
		if request.Method != http.MethodPost {
			return UIPageOutcome{StatusCode: http.StatusMethodNotAllowed}, nil
		}
		form, ok := pageForm(request, page, "challenge_id", "attempt_token", "code")
		if !ok {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: securityText("error.business.REQ_INVALID")}, nil
		}
		challengeID, _ := singleValue(form, "challenge_id", 128)
		attemptToken, _ := singleValue(form, "attempt_token", 128)
		code, _ := singleValue(form, "code", 64)
		if err := backend.ConfirmMFAEnrollment(ctx, userID, UISecurityConfirm{
			ChallengeID: challengeID, AttemptToken: attemptToken, Code: code}); err != nil {
			return accountErrorOutcome(err, map[string]any{}, ""), nil
		}
		return UIPageOutcome{Data: map[string]any{"Done": "mfa_added"}}, nil
	case "account.security_mfa.remove":
		if request.Method != http.MethodPost {
			return UIPageOutcome{StatusCode: http.StatusMethodNotAllowed}, nil
		}
		form, ok := pageForm(request, page, "current_password")
		if !ok {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: securityText("error.business.REQ_INVALID")}, nil
		}
		password, _ := singleValue(form, "current_password", 1024)
		if err := backend.RemoveMFA(ctx, userID, password, page.RequestID); err != nil {
			return accountErrorOutcome(err, map[string]any{}, ""), nil
		}
		return UIPageOutcome{Data: map[string]any{"Done": "mfa_removed"}}, nil
	}
	factors, err := backend.ListMFA(ctx, userID)
	if err != nil {
		return accountErrorOutcome(err, map[string]any{}, ""), nil
	}
	return UIPageOutcome{Data: map[string]any{"Factors": factors}}, nil
}

// totp 处理 TOTP 绑定/解除页。
func (h *securityPageHandlers) totp(ctx context.Context, request *http.Request,
	page UIPageContext, backend UIPageSecurityBackend, userID string) (UIPageOutcome, error) {
	switch page.RouteName {
	case "account.security_totp.bind_start":
		if request.Method != http.MethodPost {
			return UIPageOutcome{StatusCode: http.StatusMethodNotAllowed}, nil
		}
		form, formOK := pageForm(request, page, "current_password")
		if !formOK {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: securityText("error.business.REQ_INVALID")}, nil
		}
		password, _ := singleValue(form, "current_password", 1024)
		var binding UITOTPBinding
		var err error
		if reauthBackend, ok := backend.(UIPageSecurityReauthBackend); ok {
			binding, err = reauthBackend.BeginTOTPWithPassword(ctx, userID, password, page.RequestID)
		} else {
			binding, err = backend.BeginTOTP(ctx, userID, page.RequestID)
		}
		if err != nil {
			return accountErrorOutcome(err, map[string]any{}, ""), nil
		}
		return UIPageOutcome{Data: map[string]any{"Binding": binding}}, nil
	case "account.security_totp.bind_confirm":
		if request.Method != http.MethodPost {
			return UIPageOutcome{StatusCode: http.StatusMethodNotAllowed}, nil
		}
		form, ok := pageForm(request, page, "binding_id", "code")
		if !ok {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: securityText("error.business.REQ_INVALID")}, nil
		}
		bindingID, _ := singleValue(form, "binding_id", 128)
		code, _ := singleValue(form, "code", 16)
		if err := backend.ConfirmTOTP(ctx, userID, UISecurityConfirm{
			ChallengeID: bindingID, Code: code}); err != nil {
			return accountErrorOutcome(err, map[string]any{}, ""), nil
		}
		return UIPageOutcome{Data: map[string]any{"Done": "totp_enabled"}}, nil
	case "account.security_totp.remove":
		if request.Method != http.MethodPost {
			return UIPageOutcome{StatusCode: http.StatusMethodNotAllowed}, nil
		}
		form, ok := pageForm(request, page, "code", "current_password")
		if !ok {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: securityText("error.business.REQ_INVALID")}, nil
		}
		code, _ := singleValue(form, "code", 16)
		password, _ := singleValue(form, "current_password", 1024)
		if err := backend.RemoveTOTP(ctx, userID, password, code, page.RequestID); err != nil {
			return accountErrorOutcome(err, map[string]any{}, ""), nil
		}
		return UIPageOutcome{Data: map[string]any{"Done": "totp_removed"}}, nil
	}
	state, err := backend.GetTOTP(ctx, userID)
	if err != nil {
		return accountErrorOutcome(err, map[string]any{}, ""), nil
	}
	return UIPageOutcome{Data: map[string]any{"TOTP": state}}, nil
}

// passkeys 处理 Passkey 列表/注册/重命名/撤销。
func (h *securityPageHandlers) passkeys(ctx context.Context, request *http.Request,
	page UIPageContext, backend UIPageSecurityBackend, userID string) (UIPageOutcome, error) {
	switch page.RouteName {
	case "account.security_passkeys.register_start":
		if request.Method != http.MethodPost {
			return UIPageOutcome{StatusCode: http.StatusMethodNotAllowed}, nil
		}
		start, err := backend.BeginPasskeyRegistration(ctx, userID, page.RequestID)
		if err != nil {
			return accountErrorOutcome(err, map[string]any{}, ""), nil
		}
		return UIPageOutcome{Data: map[string]any{"Registration": start}}, nil
	case "account.security_passkeys.register_finish":
		if request.Method != http.MethodPost {
			return UIPageOutcome{StatusCode: http.StatusMethodNotAllowed}, nil
		}
		form, ok := pageForm(request, page, "ceremony_id", "passkey_response", "name", "current_password")
		if !ok {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: securityText("error.business.REQ_INVALID")}, nil
		}
		ceremonyID, _ := singleValue(form, "ceremony_id", 128)
		response, _ := singleValue(form, "passkey_response", 24*1024)
		name, _ := singleValue(form, "name", 64)
		password, _ := singleValue(form, "current_password", 1024)
		finish := UIPasskeyFinish{CeremonyID: ceremonyID, Response: []byte(response), Name: name,
			CurrentPassword: password}
		var finishErr error
		if reauthBackend, ok := backend.(UIPageSecurityReauthBackend); ok {
			finishErr = reauthBackend.FinishPasskeyRegistrationWithPassword(ctx, userID, finish)
		} else {
			finishErr = backend.FinishPasskeyRegistration(ctx, userID, finish)
		}
		if finishErr != nil {
			return accountErrorOutcome(finishErr, map[string]any{}, ""), nil
		}
		return UIPageOutcome{Data: map[string]any{"Done": "passkey_added"}}, nil
	case "account.security_passkeys.rename":
		if request.Method != http.MethodPost {
			return UIPageOutcome{StatusCode: http.StatusMethodNotAllowed}, nil
		}
		form, ok := pageForm(request, page, "credential_id", "name")
		if !ok {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: securityText("error.business.REQ_INVALID")}, nil
		}
		credentialID, _ := singleValue(form, "credential_id", 128)
		name, _ := singleValue(form, "name", 64)
		if err := backend.RenamePasskey(ctx, userID, credentialID, name, page.RequestID); err != nil {
			return accountErrorOutcome(err, map[string]any{}, ""), nil
		}
		return UIPageOutcome{Data: map[string]any{"Done": "passkey_renamed"}}, nil
	case "account.security_passkeys.revoke":
		if request.Method != http.MethodPost {
			return UIPageOutcome{StatusCode: http.StatusMethodNotAllowed}, nil
		}
		form, ok := pageForm(request, page, "credential_id", "current_password")
		if !ok {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: securityText("error.business.REQ_INVALID")}, nil
		}
		credentialID, _ := singleValue(form, "credential_id", 128)
		password, _ := singleValue(form, "current_password", 1024)
		if err := backend.RemovePasskey(ctx, userID, credentialID, password, page.RequestID); err != nil {
			return accountErrorOutcome(err, map[string]any{}, ""), nil
		}
		return UIPageOutcome{Data: map[string]any{"Done": "passkey_removed"}}, nil
	}
	passkeys, err := backend.ListPasskeys(ctx, userID)
	if err != nil {
		return accountErrorOutcome(err, map[string]any{}, ""), nil
	}
	return UIPageOutcome{Data: map[string]any{"Passkeys": passkeys}}, nil
}

// recovery 处理恢复代码 Inventory/生成。
func (h *securityPageHandlers) recovery(ctx context.Context, request *http.Request,
	page UIPageContext, backend UIPageSecurityBackend, userID string) (UIPageOutcome, error) {
	if page.RouteName == "account.security_recovery_codes.generate" {
		if request.Method != http.MethodPost {
			return UIPageOutcome{StatusCode: http.StatusMethodNotAllowed}, nil
		}
		form, ok := pageForm(request, page, "current_password", "totp_code", "confirm")
		if !ok {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: securityText("error.business.REQ_INVALID")}, nil
		}
		if confirm, _ := singleValue(form, "confirm", 16); confirm != "true" {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: securityText("page.account.recovery_codes.regenerate_warning")}, nil
		}
		password, _ := singleValue(form, "current_password", 1024)
		totpCode, _ := singleValue(form, "totp_code", 16)
		codes, err := backend.GenerateRecoveryCodes(ctx, userID, password, totpCode, page.RequestID)
		if err != nil {
			return accountErrorOutcome(err, map[string]any{}, ""), nil
		}
		return UIPageOutcome{Data: map[string]any{"Codes": codes}}, nil
	}
	inventory, err := backend.GetRecoveryCodes(ctx, userID)
	if err != nil {
		return accountErrorOutcome(err, map[string]any{}, ""), nil
	}
	return UIPageOutcome{Data: map[string]any{"Recovery": inventory}}, nil
}

// sessions 处理会话列表/退出。
func (h *securityPageHandlers) sessions(ctx context.Context, request *http.Request,
	page UIPageContext, backend UIPageSecurityBackend, userID string) (UIPageOutcome, error) {
	switch page.RouteName {
	case "account.sessions.revoke":
		form, ok := pageForm(request, page, "target_session_id", "current_password")
		if !ok {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: securityText("error.business.REQ_INVALID")}, nil
		}
		target, _ := singleValue(form, "target_session_id", 128)
		password, _ := singleValue(form, "current_password", 1024)
		if err := backend.RevokeSession(ctx, request, target, password, page.RequestID); err != nil {
			return accountErrorOutcome(err, map[string]any{}, ""), nil
		}
		return UIPageOutcome{Data: map[string]any{"Done": "session_revoked"}}, nil
	case "account.sessions.revoke_others":
		form, ok := pageForm(request, page, "current_password")
		if !ok {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: securityText("error.business.REQ_INVALID")}, nil
		}
		password, _ := singleValue(form, "current_password", 1024)
		count, err := backend.RevokeOtherSessions(ctx, request, password, page.RequestID)
		if err != nil {
			return accountErrorOutcome(err, map[string]any{}, ""), nil
		}
		return UIPageOutcome{Data: map[string]any{"RevokedCount": count}}, nil
	case "account.sessions.revoke_all":
		form, ok := pageForm(request, page, "current_password")
		if !ok {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: securityText("error.business.REQ_INVALID")}, nil
		}
		password, _ := singleValue(form, "current_password", 1024)
		cookie, count, err := backend.RevokeAllSessions(ctx, request, password, page.RequestID)
		if err != nil {
			return accountErrorOutcome(err, map[string]any{}, ""), nil
		}
		outcome := UIPageOutcome{RedirectPath: "/login"}
		outcome.SetCookies = append(outcome.SetCookies, cookie)
		_ = count
		return outcome, nil
	}
	pageNo, pageSize, ok := h.pagePageSize(request)
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
			ErrorSummary: securityText("error.business.REQ_INVALID")}, nil
	}
	sessions, err := backend.ListSessions(ctx, request, pageNo, pageSize)
	if err != nil {
		return accountErrorOutcome(err, map[string]any{}, ""), nil
	}
	return UIPageOutcome{Data: map[string]any{"Sessions": sessions}}, nil
}

// grants 处理已授权应用列表/撤回。
func (h *securityPageHandlers) grants(ctx context.Context, request *http.Request,
	page UIPageContext, backend UIPageSecurityBackend, userID string) (UIPageOutcome, error) {
	if page.RouteName == "account.grants.revoke" {
		form, ok := pageForm(request, page, "authorization_id", "current_password")
		if !ok {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: securityText("error.business.REQ_INVALID")}, nil
		}
		authorizationID, _ := singleValue(form, "authorization_id", 128)
		password, _ := singleValue(form, "current_password", 1024)
		result, err := backend.RevokeGrant(ctx, request, authorizationID, password, page.RequestID)
		if err != nil {
			return accountErrorOutcome(err, map[string]any{}, ""), nil
		}
		return UIPageOutcome{Data: map[string]any{"RevokeResult": result}}, nil
	}
	pageNo, pageSize, ok := h.pagePageSize(request)
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
			ErrorSummary: securityText("error.business.REQ_INVALID")}, nil
	}
	grants, err := backend.ListGrants(ctx, request, pageNo, pageSize)
	if err != nil {
		var publicErr *UIAccountError
		if errors.As(err, &publicErr) && publicErr.Code == "AUTHZ_UNAVAILABLE" {
			return UIPageOutcome{StatusCode: http.StatusServiceUnavailable,
				ErrorCode: "AUTHZ_UNAVAILABLE", ErrorSummary: securityText(
					"page.account.grants.query_unavailable")}, nil
		}
		return accountErrorOutcome(err, map[string]any{}, ""), nil
	}
	return UIPageOutcome{Data: map[string]any{"Grants": grants}}, nil
}
