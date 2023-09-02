package uiadminadapter

// 步骤 187：管理员强制下线页面适配器。
//
// 边界：
//   - 管理会话秘密只从请求 Cookie/Authorization 由真实 session.Service 提取；页面
//     处理器不接触秘密，适配器不缓存秘密。
//   - 查询与撤销都调用真实 session.Service（AdminListSessions/AdminRevoke）；权限、
//     作用范围、root/受保护目标、强认证、敏感策略与审计全部由领域服务重新判定。
//   - 页面再次认证证据由宿主回调返回；适配器只把服务端事实转换为 reauth 信号并
//     拒绝不完整/非强认证证据，不信任前端自报时间。
//   - 错误映射为稳定公开码，不回传底层消息或秘密。

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// AdminSessionsOptions 是管理员强制下线页适配器依赖。
type AdminSessionsOptions struct {
	// Sessions 是真实会话服务；必填。
	Sessions *session.Service
	// Authorize 判定页面能力位（交互辅助）；为 nil 时能力位全部为 false，写操作
	// 仍由领域服务授权并 fail-closed。
	Authorize func(ctx context.Context, adminUserID, action string) error
	Logger    *slog.Logger
}

// AdminSessionsAdapter 实现 login.UIAdminSessionsBackend。
type AdminSessionsAdapter struct {
	opts AdminSessionsOptions
}

// NewAdminSessions 校验依赖并构造管理员会话页适配器。
func NewAdminSessions(options AdminSessionsOptions) (*AdminSessionsAdapter, error) {
	if options.Sessions == nil {
		return nil, fmt.Errorf("管理员会话页适配器缺少会话服务")
	}
	if options.Logger == nil {
		options.Logger = slog.Default()
	}
	return &AdminSessionsAdapter{opts: options}, nil
}

var _ login.UIAdminSessionsBackend = (*AdminSessionsAdapter)(nil)

// adminSessionsErr 构造稳定公开错误。
func adminSessionsErr(code string) error { return &login.UIAdminSessionsError{Code: code} }

// adminSessionsMapError 把会话/领域错误映射为页面稳定错误码。
func adminSessionsMapError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, session.ErrStrongAuthRequired), errors.Is(err, session.ErrRestrictedSession),
		errors.Is(err, session.ErrSessionInvalid):
		return adminSessionsErr("SESSION_EXPIRED")
	case errors.Is(err, session.ErrAccessDenied):
		return adminSessionsErr("ACCESS_DENIED")
	case errors.Is(err, session.ErrStoreUnavailable):
		return adminSessionsErr("DB_UNAVAILABLE")
	case errors.Is(err, session.ErrAuditUnavailable):
		return adminSessionsErr("AUDIT_WRITE_FAILED")
	case errors.Is(err, session.ErrInvalidRequest):
		return adminSessionsErr("REQ_INVALID")
	case errors.Is(err, reauth.ErrReauthRequired), errors.Is(err, reauth.ErrMFARequired):
		return adminSessionsErr("REAUTH_REQUIRED")
	case errors.Is(err, reauth.ErrAccessDenied):
		return adminSessionsErr("ACCESS_DENIED")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return adminSessionsErr("UNAVAILABLE")
	default:
		return adminSessionsErr("INTERNAL_ERROR")
	}
}

// Capabilities 返回页面能力位；授权依赖不可用时按无能力处理。
func (a *AdminSessionsAdapter) Capabilities(ctx context.Context, request *http.Request,
	userID string) (login.UIAdminSessionsCapabilities, error) {
	if a.opts.Authorize == nil || userID == "" {
		return login.UIAdminSessionsCapabilities{}, nil
	}
	allowed := a.opts.Authorize(ctx, userID, "sessions.revoke") == nil
	return login.UIAdminSessionsCapabilities{List: allowed, Revoke: allowed}, nil
}

// ListSessions 调用真实会话服务查询目标用户活动会话；不含秘密。
func (a *AdminSessionsAdapter) ListSessions(ctx context.Context, request *http.Request,
	userID string, query login.UIAdminSessionQuery) (login.UIAdminSessionPage, error) {
	if request == nil || userID == "" {
		return login.UIAdminSessionPage{}, adminSessionsErr("ACCESS_DENIED")
	}
	secret, ok := a.opts.Sessions.SessionSecretFromRequest(request)
	if !ok || secret == "" {
		return login.UIAdminSessionPage{}, adminSessionsErr("SESSION_EXPIRED")
	}
	result, err := a.opts.Sessions.AdminListSessions(ctx, secret, session.AdminSessionListRequest{
		ScopeAppID:   query.ScopeAppID,
		TargetUserID: query.TargetUserID,
		Page:         query.Page,
		PageSize:     query.PageSize,
		RequestID:    loginRequestID(request),
	})
	if err != nil {
		return login.UIAdminSessionPage{}, adminSessionsMapError(err)
	}
	page := login.UIAdminSessionPage{
		TargetUserID: result.TargetUserID, ScopeAppID: result.ScopeAppID,
		Page: result.Page, PageSize: result.PageSize,
		Total: result.Total, HasMore: result.HasMore,
	}
	for _, item := range result.Sessions {
		page.Sessions = append(page.Sessions, login.UIAdminSessionView{
			ID: item.ID, AppID: item.AppID, Kind: string(item.Kind), Reason: string(item.Reason),
			CreatedAt: item.CreatedAt, LastSeenAt: item.LastSeenAt,
			IdleExpiresAt: item.IdleExpiresAt, AbsoluteExpiresAt: item.AbsoluteExpiresAt,
			RememberMe: item.RememberMe, Current: item.Current,
			ClientUserAgent: item.Client.UserAgent, ClientAddress: item.Client.Address,
		})
	}
	return page, nil
}

// RevokeSessions 把已校验的页面再次认证证据转换为 reauth 信号后调用真实撤销。
// 证据不完整/非强认证时拒绝；领域服务仍会重新判定敏感策略、权限、范围与保护。
func (a *AdminSessionsAdapter) RevokeSessions(ctx context.Context, request *http.Request,
	userID string, action login.UIAdminSessionRevokeAction,
	evidence login.UIAdminSessionEvidence) (login.UIAdminSessionRevokeResult, error) {
	if request == nil || userID == "" {
		return login.UIAdminSessionRevokeResult{}, adminSessionsErr("ACCESS_DENIED")
	}
	if !action.Confirm {
		return login.UIAdminSessionRevokeResult{}, adminSessionsErr("REQ_INVALID")
	}
	if evidence.Strength != "strong" || !evidence.Complete || !evidence.Confirmed ||
		evidence.VerifiedAt.IsZero() {
		return login.UIAdminSessionRevokeResult{}, adminSessionsErr("REAUTH_REQUIRED")
	}
	secret, ok := a.opts.Sessions.SessionSecretFromRequest(request)
	if !ok || secret == "" {
		return login.UIAdminSessionRevokeResult{}, adminSessionsErr("SESSION_EXPIRED")
	}
	signals := reauth.Signals{
		VerifiedAt: evidence.VerifiedAt,
		Strength:   policy.StrengthStrong,
		Complete:   true,
		Confirmed:  true,
	}
	result, err := a.opts.Sessions.AdminRevoke(reauth.WithSignals(ctx, signals), secret,
		session.AdminRevokeRequest{
			ScopeAppID:      action.ScopeAppID,
			TargetUserID:    action.TargetUserID,
			TargetSessionID: action.TargetSessionID,
			RequestID:       loginRequestID(request),
			Reason:          action.Reason,
		})
	if err != nil {
		a.opts.Logger.Info("管理员会话页强制下线失败", "error_category", adminSessionsErrorCategory(err))
		return login.UIAdminSessionRevokeResult{}, adminSessionsMapError(err)
	}
	return login.UIAdminSessionRevokeResult{
		Revoked: result.Revoked, ScopeAppID: action.ScopeAppID,
	}, nil
}

// adminSessionsErrorCategory 返回不含敏感信息的日志分类。
func adminSessionsErrorCategory(err error) string {
	switch {
	case errors.Is(err, session.ErrAccessDenied), errors.Is(err, reauth.ErrAccessDenied):
		return "access_denied"
	case errors.Is(err, session.ErrStrongAuthRequired), errors.Is(err, reauth.ErrReauthRequired),
		errors.Is(err, reauth.ErrMFARequired):
		return "reauth_required"
	case errors.Is(err, session.ErrStoreUnavailable):
		return "store_unavailable"
	case errors.Is(err, session.ErrAuditUnavailable):
		return "audit_unavailable"
	default:
		return "internal_error"
	}
}

// loginRequestID 从请求头读取已校验格式的请求编号；缺失/非法时返回空字符串。
func loginRequestID(request *http.Request) string {
	if request == nil {
		return ""
	}
	value := request.Header.Get("X-Request-ID")
	if value == "" || len(value) > 128 {
		return ""
	}
	return value
}
