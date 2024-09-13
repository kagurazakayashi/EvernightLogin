package ui

// 步骤 258：管理员直接修改他人用户名的管理页（目标稳定 ID/旧新用户名展示、
// 一次两步验证后直接提交）。
//
// 安全边界：
//   - 页面会话摘要 UISession 不含真实会话秘密；秘密由宿主注入的
//     UIPageAdminOptions.ManagementSession 回调在**处理器代码内**取得，只作为参数
//     传给后端方法，不进入模板上下文/渲染数据/响应/日志。
//   - 回调未注入时页面路由 fail-closed（404/403），不静默降级。
//   - 授权/证明绑定与消费/目标与行版本校验/事务提交仍由后端门面执行；按钮显示只是
//     体验，服务端每次提交独立检查。
//   - 证明令牌只在处理器内存中，立即用于同一请求的提交，绝不写入页面。

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// UIDirectRenameChallenge 是页面侧两步验证挑战投影。
type UIDirectRenameChallenge struct {
	ChallengeID       string
	TargetUserID      string
	RequiredStrength  string
	ExpiresAt         time.Time
	MaxAttempts       int
	WebAuthnAvailable bool
}

// UIDirectRenameGrant 是一次性证明（只在处理器内存）。
type UIDirectRenameGrant struct {
	ProofToken string
	ExpiresAt  time.Time
}

// UIDirectRenameBackend 是管理页直接改名的可选后端契约（由宿主适配器实现）。
type UIDirectRenameBackend interface {
	CanChangeUsername(ctx context.Context, adminUserID string) (bool, error)
	BeginDirectUsernameChange(ctx context.Context, adminUserID, sessionSecret,
		targetUserID, newUsername, requestID string) (UIDirectRenameChallenge, error)
	ConfirmDirectUsernameChange(ctx context.Context, adminUserID, sessionSecret,
		challengeID, password, totpCode, requestID string) (UIDirectRenameGrant, error)
	ApplyDirectUsernameChange(ctx context.Context, adminUserID, sessionSecret,
		targetUserID, newUsername string, expectedRowVersion int64, reason, proofToken,
		requestID string) (UIAdminUserView, error)
}

// directRenameBackend 返回可用的直接改名页面后端；未装配时 ok=false（fail-closed）。
func (h *adminPageHandlers) directRenameBackend() (UIDirectRenameBackend, bool) {
	if h == nil || h.pages == nil || h.pages.options.ManagementSession == nil {
		return nil, false
	}
	backend, ok := h.pages.options.Backend.(UIDirectRenameBackend)
	return backend, ok
}

// renameFormData 构造改名表单渲染数据；不包含会话秘密、密码、证明。
func renameFormData(user UIAdminUserView, canRename bool, challengeID,
	newUsername, reason, errorSummary string) map[string]any {
	return map[string]any{"user": user, "canRename": canRename,
		"challengeID": challengeID, "newUsername": newUsername, "reason": reason,
		"expectedVersion": user.RowVersion, "renameError": errorSummary}
}

// userRename 渲染直接改名表单（GET）。
func (h *adminPageHandlers) userRename(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	backend, ok := h.directRenameBackend()
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
	canRename, canErr := backend.CanChangeUsername(ctx, page.Session.UserID)
	if canErr != nil {
		canRename = false
	}
	return UIPageOutcome{Data: renameFormData(user, canRename, "", "", "",
		request.URL.Query().Get("error"))}, nil
}

// userRenameSubmit 执行“先 begin/confirm 取得一次性证明，再立即提交改名”的同一
// 请求流程；MFA_REQUIRED 时返回带 challenge_id 的表单要求补动态码（密码不落页面）。
func (h *adminPageHandlers) userRenameSubmit(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	backend, ok := h.directRenameBackend()
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
		"new_username", "reason", "expected_row_version", "password", "totp_code",
		"challenge_id"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.users.invalid")}, nil
	}
	userID := strings.TrimSpace(form.Get("user_id"))
	newUsername := strings.TrimSpace(form.Get("new_username"))
	reason := strings.TrimSpace(form.Get("reason"))
	version, versionErr := strconv.ParseInt(strings.TrimSpace(form.Get("expected_row_version")), 10, 64)
	if userID == "" || newUsername == "" || reason == "" || versionErr != nil || version < 1 {
		return h.renderRenameError(ctx, page, userID, "", newUsername, reason,
			text("page.admin.users.invalid"), http.StatusBadRequest), nil
	}
	challengeID := strings.TrimSpace(form.Get("challenge_id"))
	if challengeID == "" {
		challenge, beginErr := backend.BeginDirectUsernameChange(ctx, page.Session.UserID,
			secret, userID, newUsername, page.RequestID)
		if beginErr != nil {
			return h.renameBackendFailure(ctx, page, beginErr, userID, "", newUsername, reason), nil
		}
		challengeID = challenge.ChallengeID
	}
	grant, confirmErr := backend.ConfirmDirectUsernameChange(ctx, page.Session.UserID,
		secret, challengeID, form.Get("password"), form.Get("totp_code"), page.RequestID)
	if confirmErr != nil {
		if renameErrorCode(confirmErr) == "MFA_REQUIRED" {
			return h.renderRenameError(ctx, page, userID, challengeID, newUsername, reason,
				text("page.admin.users.rename_need_mfa"), http.StatusForbidden), nil
		}
		return h.renameBackendFailure(ctx, page, confirmErr, userID, challengeID,
			newUsername, reason), nil
	}
	updated, applyErr := backend.ApplyDirectUsernameChange(ctx, page.Session.UserID,
		secret, userID, newUsername, version, reason, grant.ProofToken, page.RequestID)
	if applyErr != nil {
		return h.renameBackendFailure(ctx, page, applyErr, userID, "", newUsername, reason), nil
	}
	return UIPageOutcome{Data: map[string]any{"user": updated},
		RedirectPath:  "/admin/users/detail",
		RedirectQuery: url.Values{"user_id": {userID}, "status": {"username_renamed"}}}, nil
}

// renameBackendFailure 把后端错误映射为页面结果并尽量保留表单输入（不含秘密）。
func (h *adminPageHandlers) renameBackendFailure(ctx context.Context, page UIPageContext,
	err error, userID, challengeID, newUsername, reason string) UIPageOutcome {
	if userID != "" {
		return h.renderRenameError(ctx, page, userID, challengeID, newUsername, reason,
			text("page.admin.users.rename_failed"), http.StatusBadRequest)
	}
	return adminErrorOutcome(err, nil, "page.admin.users.rename_failed")
}

// renderRenameError 重新渲染表单并显示稳定错误；密码/证明不进入渲染数据。
func (h *adminPageHandlers) renderRenameError(ctx context.Context, page UIPageContext,
	userID, challengeID, newUsername, reason, summary string, status int) UIPageOutcome {
	user, err := h.pages.options.Backend.GetUser(ctx, page.Session.UserID, userID)
	if err != nil {
		return adminErrorOutcome(err, nil, "page.admin.users.load_failed")
	}
	backend, _ := h.directRenameBackend()
	canRename := false
	if backend != nil {
		if allowed, canErr := backend.CanChangeUsername(ctx, page.Session.UserID); canErr == nil {
			canRename = allowed
		}
	}
	return UIPageOutcome{StatusCode: status, ErrorSummary: summary,
		Data: renameFormData(user, canRename, challengeID, newUsername, reason, summary)}
}

// renameErrorCode 读取页面统一错误码（用于 MFA_REQUIRED 二次提示）。
func renameErrorCode(err error) string {
	var publicErr *UIAdminError
	if errors.As(err, &publicErr) {
		return publicErr.Code
	}
	return ""
}
