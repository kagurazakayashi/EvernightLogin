package login

import (
	"context"
	"errors"
	"net/http"
	"net/url"
)

// oauthErrorOutcome 把适配器公开错误映射为页面状态与稳定码；内部故障 500。
func oauthErrorOutcome(err error) UIPageOutcome {
	var publicErr *UIPageAuthError
	if !errors.As(err, &publicErr) || publicErr.Code == "" {
		return UIPageOutcome{StatusCode: http.StatusInternalServerError,
			ErrorCode: "INTERNAL_ERROR", ErrorSummary: oauthText("error.business.INTERNAL_ERROR")}
	}
	status := http.StatusBadRequest
	switch publicErr.Code {
	case "ACCESS_DENIED", "AUTH_FAILED", "MFA_REQUIRED", "REAUTH_REQUIRED", "USER_DISABLED":
		status = http.StatusForbidden
	case "CONFLICT":
		status = http.StatusConflict
	case "RATE_LIMITED":
		status = http.StatusTooManyRequests
	case "AUTHZ_UNAVAILABLE", "DB_UNAVAILABLE", "AUDIT_WRITE_FAILED":
		status = http.StatusServiceUnavailable
	case "INTERNAL_ERROR":
		status = http.StatusInternalServerError
	}
	return UIPageOutcome{StatusCode: status, ErrorCode: publicErr.Code,
		ErrorSummary: oauthText("error.business." + publicErr.Code)}
}

// oauthPageHandlers 实现步骤 65 页面处理器。
type oauthPageHandlers struct{ pages *pageOAuthPages }

// HandlePage 按路由分派。
func (h *oauthPageHandlers) HandlePage(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	backend := h.pages.options.Backend
	switch page.RouteName {
	case "oauth.consent", "oauth.consent.decide":
		return h.consent(ctx, request, page, backend)
	case "oauth.device_verify", "oauth.device_verify.describe",
		"oauth.device_confirm", "oauth.device_confirm.decide":
		return h.device(ctx, request, page, backend)
	case "auth.qr_login", "auth.qr_login.poll", "auth.qr_login.claim",
		"auth.qr_login.regenerate", "auth.qr_login.cancel":
		return h.qrLogin(ctx, request, page, backend)
	case "app.scan_confirm", "app.scan_confirm.decide":
		return h.scanConfirm(ctx, request, page, backend)
	default:
		return UIPageOutcome{}, nil
	}
}

// consent 渲染/提交 OAuth 授权确认。
func (h *oauthPageHandlers) consent(ctx context.Context, request *http.Request,
	page UIPageContext, backend UIPageOAuthBackend) (UIPageOutcome, error) {
	if request.Method == http.MethodGet {
		prompt, err := backend.BeginConsent(ctx, request, request.URL.Query())
		if err != nil {
			return oauthErrorOutcome(err), nil
		}
		return UIPageOutcome{Data: map[string]any{"Consent": prompt}}, nil
	}
	form, ok := pageForm(request, page, "request_id", "approve")
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
			ErrorSummary: oauthText("error.business.REQ_INVALID")}, nil
	}
	requestID, _ := singleValue(form, "request_id", 128)
	decision, _ := singleValue(form, "approve", 16)
	if requestID == "" || (decision != "true" && decision != "false") {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
			ErrorSummary: oauthText("error.business.REQ_INVALID")}, nil
	}
	result, err := backend.DecideConsent(ctx, request, UIPageConsentDecision{
		RequestID: requestID, Approve: decision == "true"})
	if err != nil {
		return oauthErrorOutcome(err), nil
	}
	if result.RedirectURL == "" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
			ErrorSummary: oauthText("page.oauth.consent.redirect_missing")}, nil
	}
	return UIPageOutcome{ExternalRedirectURL: result.RedirectURL}, nil
}

// device 渲染/描述/提交设备码确认。
func (h *oauthPageHandlers) device(ctx context.Context, request *http.Request,
	page UIPageContext, backend UIPageOAuthBackend) (UIPageOutcome, error) {
	if page.RouteName == "oauth.device_confirm.decide" {
		form, ok := pageForm(request, page, "user_code", "approve")
		if !ok {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: oauthText("error.business.REQ_INVALID")}, nil
		}
		userCode, _ := singleValue(form, "user_code", 64)
		decision, _ := singleValue(form, "approve", 16)
		if userCode == "" || (decision != "true" && decision != "false") {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: oauthText("error.business.REQ_INVALID")}, nil
		}
		result, err := backend.DeviceDecide(ctx, request, UIPageDeviceDecision{
			UserCode: userCode, Approve: decision == "true"})
		if err != nil {
			return oauthErrorOutcome(err), nil
		}
		return UIPageOutcome{Data: map[string]any{"DeviceDone": result}}, nil
	}
	if page.RouteName == "oauth.device_verify.describe" {
		form, ok := pageForm(request, page, "user_code")
		if !ok {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: oauthText("error.business.REQ_INVALID")}, nil
		}
		userCode, _ := singleValue(form, "user_code", 64)
		if userCode == "" {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: oauthText("page.oauth.device.invalid_code")}, nil
		}
		prompt, err := backend.DeviceDescribe(ctx, request, userCode)
		if err != nil {
			return oauthErrorOutcome(err), nil
		}
		return UIPageOutcome{Data: map[string]any{"Device": prompt}}, nil
	}
	return UIPageOutcome{Data: map[string]any{}}, nil
}

// qrLogin 渲染/轮询/领取/刷新/取消匿名扫码发起页。
func (h *oauthPageHandlers) qrLogin(ctx context.Context, request *http.Request,
	page UIPageContext, backend UIPageOAuthBackend) (UIPageOutcome, error) {
	switch page.RouteName {
	case "auth.qr_login.claim":
		if request.Method != http.MethodPost {
			return UIPageOutcome{StatusCode: http.StatusMethodNotAllowed}, nil
		}
		result, err := backend.ClaimQR(ctx, request)
		if err != nil {
			return oauthErrorOutcome(err), nil
		}
		return UIPageOutcome{RedirectPath: h.pages.options.PostLoginPath,
			SetCookies: []*http.Cookie{result.SessionCookie, result.StateCookie}}, nil
	case "auth.qr_login.regenerate":
		if request.Method != http.MethodPost {
			return UIPageOutcome{StatusCode: http.StatusMethodNotAllowed}, nil
		}
		begin, err := backend.RegenerateQR(ctx, request)
		if err != nil {
			return oauthErrorOutcome(err), nil
		}
		outcome := UIPageOutcome{Data: map[string]any{"QR": begin}}
		outcome.SetCookies = append(outcome.SetCookies, begin.StateCookie)
		return outcome, nil
	case "auth.qr_login.cancel":
		if request.Method != http.MethodPost {
			return UIPageOutcome{StatusCode: http.StatusMethodNotAllowed}, nil
		}
		status, err := backend.CancelQR(ctx, request)
		if err != nil {
			return oauthErrorOutcome(err), nil
		}
		outcome := UIPageOutcome{Data: map[string]any{"QRStatus": status}}
		outcome.SetCookies = append(outcome.SetCookies, status.StateCookie)
		return outcome, nil
	case "auth.qr_login.poll":
		if request.Method != http.MethodPost {
			return UIPageOutcome{StatusCode: http.StatusMethodNotAllowed}, nil
		}
		status, err := backend.QueryQR(ctx, request)
		if err != nil {
			return oauthErrorOutcome(err), nil
		}
		outcome := UIPageOutcome{Data: map[string]any{"QRStatus": status}}
		outcome.SetCookies = append(outcome.SetCookies, status.StateCookie)
		return outcome, nil
	}
	begin, err := backend.BeginQR(ctx, request)
	if err != nil {
		return oauthErrorOutcome(err), nil
	}
	outcome := UIPageOutcome{Data: map[string]any{"QR": begin}}
	outcome.SetCookies = append(outcome.SetCookies, begin.StateCookie)
	return outcome, nil
}

// scanConfirm 渲染/提交 APP 扫码确认页。
func (h *oauthPageHandlers) scanConfirm(ctx context.Context, request *http.Request,
	page UIPageContext, backend UIPageOAuthBackend) (UIPageOutcome, error) {
	requestID := request.URL.Query().Get("request_id")
	if page.RouteName == "app.scan_confirm.decide" {
		form, ok := pageForm(request, page, "request_id", "expected_version", "approve")
		if !ok {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: oauthText("error.business.REQ_INVALID")}, nil
		}
		requestID, _ = singleValue(form, "request_id", 128)
		approveRaw, _ := singleValue(form, "approve", 16)
		versionRaw, _ := singleValue(form, "expected_version", 32)
		expectedVersion, versionErr := parseInt64(versionRaw)
		if requestID == "" || versionErr != nil || (approveRaw != "true" && approveRaw != "false") {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: oauthText("error.business.REQ_INVALID")}, nil
		}
		prompt, err := backend.DecideQR(ctx, request, UIPageQRDecision{
			RequestID: requestID, ExpectedVersion: expectedVersion, Approve: approveRaw == "true"})
		if err != nil {
			return oauthErrorOutcome(err), nil
		}
		return UIPageOutcome{Data: map[string]any{"Scan": prompt, "Decided": true}}, nil
	}
	if requestID == "" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
			ErrorSummary: oauthText("page.app.scan.missing_request")}, nil
	}
	prompt, err := backend.DescribeQR(ctx, request, requestID)
	if err != nil {
		return oauthErrorOutcome(err), nil
	}
	return UIPageOutcome{Data: map[string]any{"Scan": prompt}}, nil
}

// parseInt64 解析十进制整数（仅用于版本号）。
func parseInt64(value string) (int64, error) {
	var result int64
	if value == "" || len(value) > 19 {
		return 0, errors.New("版本号无效")
	}
	for index := 0; index < len(value); index++ {
		digit := value[index]
		if digit < '0' || digit > '9' {
			return 0, errors.New("版本号无效")
		}
		result = result*10 + int64(digit-'0')
	}
	return result, nil
}

// unusedURL 保留 url 导入用于未来查询参数类型化（当前处理器直接读取 Query）。
var _ = url.Values{}
