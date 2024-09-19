package ui

// 步骤 259：管理页直接重置他人密码的处理器。
//
// 流程：GET 展示目标稳定 ID/旧用户名与影响说明（旧会话/找回链接失效、MFA 保留、
// 下次登录改密），按钮按权限显示；POST 在同一请求内 begin（绑定目标+新口令密封
// 意图）→ confirm（密码+TOTP）→ 用一次性证明立即提交，MFA_REQUIRED 时仅回显
// challenge_id 要求补动态码。新口令/管理密码/证明都不进入渲染数据或日志。

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// directPasswordResetBackend 返回可用的直接重置页面后端；未装配时 ok=false。
func (h *adminPageHandlers) directPasswordResetBackend() (UIDirectPasswordResetBackend, bool) {
	if h == nil || h.pages == nil || h.pages.options.ManagementSession == nil ||
		h.pages.options.DirectPasswordReset == nil {
		return nil, false
	}
	return h.pages.options.DirectPasswordReset, true
}

// passwordResetFormData 构造重置表单渲染数据；绝不含新口令/管理密码/证明。
func passwordResetFormData(user UIAdminUserView, canReset bool, challengeID,
	errorSummary string, result *UIDirectPasswordResetResult) map[string]any {
	data := map[string]any{"user": user, "canReset": canReset,
		"challengeID": challengeID, "resetError": errorSummary, "result": nil}
	if result != nil {
		data["result"] = result
	}
	return data
}

// userPasswordReset 渲染直接重置密码表单（GET）。
func (h *adminPageHandlers) userPasswordReset(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	backend, ok := h.directPasswordResetBackend()
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusNotFound,
			ErrorSummary: text("page.admin.common.forbidden")}, nil
	}
	userID := strings.TrimSpace(request.URL.Query().Get("user_id"))
	if userID == "" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.users.invalid")}, nil
	}
	user, err := h.pages.options.Backend.GetUser(ctx, page.Session.UserID, userID)
	if err != nil {
		return adminErrorOutcome(err, nil, "page.admin.users.load_failed"), nil
	}
	canReset, canErr := backend.CanResetPassword(ctx, page.Session.UserID)
	if canErr != nil {
		canReset = false
	}
	return UIPageOutcome{Data: passwordResetFormData(user, canReset, "",
		request.URL.Query().Get("error"), nil)}, nil
}

// userPasswordResetSubmit 执行“一次两步验证 + 立即提交重置”。
func (h *adminPageHandlers) userPasswordResetSubmit(ctx context.Context,
	request *http.Request, page UIPageContext) (UIPageOutcome, error) {
	backend, ok := h.directPasswordResetBackend()
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusNotFound,
			ErrorSummary: text("page.admin.common.forbidden")}, nil
	}
	secret, ok := h.pages.options.ManagementSession(request)
	if !ok || strings.TrimSpace(secret) == "" {
		return UIPageOutcome{StatusCode: http.StatusForbidden,
			ErrorSummary: text("page.admin.common.forbidden")}, nil
	}
	form, formErr := readPageForm(request, page.CSRFField, []string{"user_id",
		"new_password", "new_password_confirm", "reason", "password", "totp_code",
		"challenge_id"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.users.invalid")}, nil
	}
	userID := strings.TrimSpace(form.Get("user_id"))
	newPassword := form.Get("new_password")
	confirmPassword := form.Get("new_password_confirm")
	reason := strings.TrimSpace(form.Get("reason"))
	switch {
	case userID == "" || newPassword == "" || reason == "":
		return h.renderPasswordResetError(ctx, page, userID, "",
			text("page.admin.users.invalid"), http.StatusBadRequest), nil
	case newPassword != confirmPassword:
		return h.renderPasswordResetError(ctx, page, userID, "",
			text("page.admin.users.password_reset_mismatch"), http.StatusBadRequest), nil
	}
	challengeID := strings.TrimSpace(form.Get("challenge_id"))
	if challengeID == "" {
		challenge, beginErr := backend.BeginDirectPasswordReset(ctx, page.Session.UserID,
			secret, userID, newPassword, page.RequestID)
		if beginErr != nil {
			return h.passwordResetBackendFailure(ctx, page, userID, beginErr), nil
		}
		challengeID = challenge.ChallengeID
	}
	grant, confirmErr := backend.ConfirmDirectPasswordReset(ctx, page.Session.UserID,
		secret, challengeID, form.Get("password"), form.Get("totp_code"), page.RequestID)
	if confirmErr != nil {
		if resetPageErrorCode(confirmErr) == "MFA_REQUIRED" {
			return h.renderPasswordResetError(ctx, page, userID, challengeID,
				text("page.admin.users.password_reset_need_mfa"), http.StatusForbidden), nil
		}
		return h.passwordResetBackendFailure(ctx, page, userID, confirmErr), nil
	}
	result, applyErr := backend.ApplyDirectPasswordReset(ctx, page.Session.UserID,
		secret, userID, newPassword, reason, grant.ProofToken, page.RequestID)
	if applyErr != nil {
		return h.passwordResetBackendFailure(ctx, page, userID, applyErr), nil
	}
	return h.renderPasswordResetResult(ctx, page, userID, result), nil
}

// renderPasswordResetResult 渲染成功结果（脱敏事实：must_change/会话撤销/旧找回失效）。
func (h *adminPageHandlers) renderPasswordResetResult(ctx context.Context,
	page UIPageContext, userID string, result UIDirectPasswordResetResult) UIPageOutcome {
	user, err := h.pages.options.Backend.GetUser(ctx, page.Session.UserID, userID)
	if err != nil {
		return adminErrorOutcome(err, nil, "page.admin.users.load_failed")
	}
	backend, _ := h.directPasswordResetBackend()
	canReset := false
	if backend != nil {
		if allowed, canErr := backend.CanResetPassword(ctx, page.Session.UserID); canErr == nil {
			canReset = allowed
		}
	}
	return UIPageOutcome{Data: passwordResetFormData(user, canReset, "", "", &result)}
}

// renderPasswordResetError 重新渲染表单并显示稳定错误；口令/证明不进入渲染数据。
func (h *adminPageHandlers) renderPasswordResetError(ctx context.Context,
	page UIPageContext, userID, challengeID, summary string, status int) UIPageOutcome {
	user, err := h.pages.options.Backend.GetUser(ctx, page.Session.UserID, userID)
	if err != nil {
		return adminErrorOutcome(err, nil, "page.admin.users.load_failed")
	}
	backend, _ := h.directPasswordResetBackend()
	canReset := false
	if backend != nil {
		if allowed, canErr := backend.CanResetPassword(ctx, page.Session.UserID); canErr == nil {
			canReset = allowed
		}
	}
	return UIPageOutcome{StatusCode: status, ErrorSummary: summary,
		Data: passwordResetFormData(user, canReset, challengeID, summary, nil)}
}

// passwordResetBackendFailure 把后端错误映射为页面结果。
func (h *adminPageHandlers) passwordResetBackendFailure(ctx context.Context,
	page UIPageContext, userID string, err error) UIPageOutcome {
	if userID != "" {
		return h.renderPasswordResetError(ctx, page, userID, "",
			text("page.admin.users.password_reset_failed"), http.StatusBadRequest)
	}
	return adminErrorOutcome(err, nil, "page.admin.users.password_reset_failed")
}

// resetPageErrorCode 读取页面统一错误码（用于 MFA_REQUIRED 二次提示）。
func resetPageErrorCode(err error) string {
	var publicErr *UIAdminError
	if errors.As(err, &publicErr) {
		return publicErr.Code
	}
	return ""
}
