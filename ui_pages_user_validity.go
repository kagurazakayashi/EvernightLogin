package login

// 步骤 235：管理页账户全局有效期展示与设置。
//
// 边界：
//   - 页面只调用 UIAdminUserValidityBackend；真实适配器使用与 234 管理 API 相同的
//     users.read/users.update 授权与账户领域服务，不新增旁路；
//   - root 账户不接受普通期限管理：详情页不渲染设置表单，后端仍会拒绝伪造提交；
//   - 表单时间为 UTC；结束必须晚于开始；两端留空表示清除（永久有效）；
//   - 每次变更要求变更理由与显式确认，后端审计记录真实操作者、理由与请求编号；
//   - 到期是计算出的可用性，不改变手动状态；续期不会解除手动禁用。

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// UIAdminUserValidityBackend 是管理页读取/设置账户全局有效期的最小契约。
// 实现必须重新判定 users.read/users.update 权限；root 由账户领域服务拒绝。
type UIAdminUserValidityBackend interface {
	// GetUserValidity 返回脱敏有效期视图与当前可用性。
	GetUserValidity(ctx context.Context, adminID, userID string) (UIAdminUserValidityView, error)
	// SetUserValidity 设置/续期/清除全局有效期；reason 为必填审计理由。
	SetUserValidity(ctx context.Context, adminID, userID string,
		change UIAdminUserValidityChange) (UIAdminUserValidityView, error)
}

// UIAdminUserValidityView 是管理页有效期视图（不含秘密/个人资料）。
type UIAdminUserValidityView struct {
	UserID     string
	Status     string
	IsRoot     bool
	ValidFrom  *time.Time
	ValidUntil *time.Time
	RowVersion int64
	// Available/Reason 是请求当刻计算出的可用性与原因（available/not_yet_valid/
	// expired/pending/disabled/pending_delete）。
	Available bool
	Reason    string
	CheckedAt time.Time
}

// UIAdminUserValidityChange 是页面设置有效期请求（UTC 半开区间）。
type UIAdminUserValidityChange struct {
	ValidFrom          *time.Time
	ValidUntil         *time.Time
	ExpectedRowVersion int64
	RequestID          string
	Reason             string
}

// userValidity 处理 POST /admin/users/validity：校验确认/理由/UTC 时间后调用
// 与 API 同一授权的后端；成功后重定向详情并带状态。
func (h *adminPageHandlers) userValidity(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if h.pages.options.Validity == nil || isNilUIValue(h.pages.options.Validity) {
		return UIPageOutcome{StatusCode: http.StatusNotFound,
			ErrorSummary: text("page.admin.users.validity_unavailable")}, nil
	}
	form, formErr := readPageForm(request, page.CSRFField, []string{"user_id",
		"valid_from", "valid_until", "expected_row_version", "reason", "confirm"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.users.invalid")}, nil
	}
	// 页面框架/传输层已做 CSRF 校验；本高风险入口再做一次服务端令牌绑定校验，
	// 防止绕过中间件或伪造字段时直接提交有效期变更。
	if page.CSRF == "" || form.Get(page.CSRFField) != page.CSRF {
		return UIPageOutcome{StatusCode: http.StatusForbidden,
			ErrorCode:    "ACCESS_DENIED",
			ErrorSummary: text("page.admin.common.forbidden")}, nil
	}
	userID := strings.TrimSpace(form.Get("user_id"))
	version, versionErr := parseRowVersion(form.Get("expected_row_version"))
	reason := strings.TrimSpace(form.Get("reason"))
	if userID == "" || versionErr != nil || len(reason) == 0 || len(reason) > 200 ||
		form.Get("confirm") != "yes" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.users.validity_confirm_required")}, nil
	}
	validFrom, fromErr := parseValidityFormTime(form.Get("valid_from"))
	validUntil, untilErr := parseValidityFormTime(form.Get("valid_until"))
	if fromErr != nil || untilErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.users.validity_invalid")}, nil
	}
	if validFrom != nil && validUntil != nil && !validUntil.After(*validFrom) {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.users.validity_invalid")}, nil
	}
	requestID := strings.TrimSpace(page.RequestID)
	if requestID == "" {
		// 页面框架未提供请求编号时生成一个，保证变更审计可关联到本次提交。
		requestID = NewRequestID()
	}
	view, err := h.pages.options.Validity.SetUserValidity(ctx, page.Session.UserID,
		userID, UIAdminUserValidityChange{ValidFrom: validFrom, ValidUntil: validUntil,
			ExpectedRowVersion: version, RequestID: requestID, Reason: reason})
	if err != nil {
		return adminErrorOutcome(err, nil, "page.admin.users.validity_failed"), nil
	}
	status := "validity_saved"
	if view.ValidFrom == nil && view.ValidUntil == nil {
		status = "validity_cleared"
	}
	return UIPageOutcome{Data: map[string]any{"validity": view},
		RedirectPath:  "/admin/users/detail",
		RedirectQuery: url.Values{"user_id": {userID}, "status": {status}}}, nil
}

// parseValidityFormTime 解析表单 UTC 时间；空串表示该端不限制。
//
// 支持 RFC3339（带 Z/偏移，统一转 UTC）与浏览器 datetime-local 的无时区格式
// （2006-01-02T15:04[:05]），后者按 UTC 解释；不做模糊本地时区推断。
func parseValidityFormTime(raw string) (*time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var (
		parsed time.Time
		err    error
	)
	if strings.HasSuffix(raw, "Z") || strings.ContainsAny(raw, "+-") {
		parsed, err = time.Parse(time.RFC3339, raw)
	}
	if err != nil || parsed.IsZero() {
		for _, layout := range []string{"2006-01-02T15:04", "2006-01-02T15:04:05",
			"2006-01-02 15:04", "2006-01-02 15:04:05"} {
			parsed, err = time.ParseInLocation(layout, raw, time.UTC)
			if err == nil {
				break
			}
		}
	}
	if err != nil {
		return nil, err
	}
	utc := parsed.UTC().Truncate(time.Millisecond)
	if utc.Year() < 1970 || utc.Year() > 9999 {
		return nil, fmt.Errorf("UTC 时间超出允许范围")
	}
	return &utc, nil
}
