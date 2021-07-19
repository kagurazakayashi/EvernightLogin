// 本文件实现步骤 67 账户安全中心页面：登录方式/安全设置/会话/已授权应用自助管理
// （ui.v1 兼容新增，不改变步骤 62～66 已冻结语义）。
//
// 安全边界：
//   - 页面只消费真实会话公开摘要与宿主注入的 UIPageSecurityBackend；每次读写都由
//     服务端重新校验会话/权限，前端不缓存授权。
//   - 敏感动作（删除因素、退出全部会话、撤回授权、生成恢复代码）必须由适配器完成
//     绑定操作/目标/参数的再次认证后才调用真实服务；强认证不足 fail-closed 不降级。
//   - 秘密（TOTP 种子/URI、恢复代码、验证码、Token）只在必要页面一次性显示；不进入
//     URL/localStorage/日志/审计；页面切换/完成/过期清理。
//   - 用户身份只来自 UISessionService 真实会话摘要；不信任客户端 userID/角色字段。
package login

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// UIPageSecurityOptions 是步骤 67 页面配置。
type UIPageSecurityOptions struct {
	Backend UIPageSecurityBackend
}

// UIPageSecurityBackend 是页面调用真实凭证/会话/授权服务的最小契约；生产适配器
// 内部构造可信 Caller、执行 reauth 挑战并调用真实 mfa/totp/passkey/recovery/
// session/oauthflow 服务。
type UIPageSecurityBackend interface {
	GetOverview(ctx context.Context, userID string) (UISecurityOverview, error)

	ListMFA(ctx context.Context, userID string) ([]UIMFAFactor, error)
	BeginMFAEnrollment(ctx context.Context, userID, requestID string) (UIMFAEnrollment, error)
	ConfirmMFAEnrollment(ctx context.Context, userID string, confirm UISecurityConfirm) error
	RemoveMFA(ctx context.Context, userID, currentPassword, requestID string) error

	GetTOTP(ctx context.Context, userID string) (UITOTPState, error)
	BeginTOTP(ctx context.Context, userID, requestID string) (UITOTPBinding, error)
	ConfirmTOTP(ctx context.Context, userID string, confirm UISecurityConfirm) error
	RemoveTOTP(ctx context.Context, userID, currentPassword, code, requestID string) error

	ListPasskeys(ctx context.Context, userID string) ([]UIPasskey, error)
	BeginPasskeyRegistration(ctx context.Context, userID, requestID string) (UIPasskeyRegistration, error)
	FinishPasskeyRegistration(ctx context.Context, userID string, finish UIPasskeyFinish) error
	RenamePasskey(ctx context.Context, userID, credentialID, name, requestID string) error
	RemovePasskey(ctx context.Context, userID, credentialID, currentPassword, requestID string) error

	GetRecoveryCodes(ctx context.Context, userID string) (UIRecoveryInventory, error)
	GenerateRecoveryCodes(ctx context.Context, userID, currentPassword, requestID string) ([]string, error)

	ListSessions(ctx context.Context, request *http.Request, page, pageSize int) (UISessionPage, error)
	RevokeSession(ctx context.Context, request *http.Request, targetSessionID,
		currentPassword, requestID string) error
	RevokeOtherSessions(ctx context.Context, request *http.Request, currentPassword,
		requestID string) (int64, error)
	RevokeAllSessions(ctx context.Context, request *http.Request, currentPassword,
		requestID string) (*http.Cookie, int64, error)

	ListGrants(ctx context.Context, request *http.Request, page, pageSize int) (UIGrantPage, error)
	RevokeGrant(ctx context.Context, request *http.Request, authorizationID,
		currentPassword, requestID string) (UIGrantRevokeResult, error)
}

// UISecurityOverview 是安全中心只读事实摘要（不输出“安全/不安全”结论）。
type UISecurityOverview struct {
	EmailMFAEnabled   bool
	TOTPEnabled       bool
	PasskeyCount      int
	RecoveryAvailable bool
	RecoveryRemaining int
	ActiveSessions    int64
}

// UIMFAFactor 是邮件因素公开视图。
type UIMFAFactor struct {
	Type      string
	State     string
	CreatedAt time.Time
}

// UIMFAEnrollment 是邮件因素添加开始结果（AttemptToken 只用于当前流程）。
type UIMFAEnrollment struct {
	ChallengeID  string
	AttemptToken string
	MaskedEmail  string
	ExpiresAt    time.Time
}

// UISecurityConfirm 是验证码/挑战确认字段。
type UISecurityConfirm struct {
	ChallengeID  string
	AttemptToken string
	Code         string
}

// UITOTPState 是 TOTP 状态与元数据（不含种子）。
type UITOTPState struct {
	Enabled       bool
	Status        string
	Algorithm     string
	Digits        int
	PeriodSeconds int
	ActivatedAt   time.Time
}

// UITOTPBinding 是 TOTP 绑定开始结果：Secret/URI 仅本次显示。
type UITOTPBinding struct {
	BindingID string
	Secret    string
	URI       string
	ExpiresAt time.Time
}

// UIPasskey 是 Passkey 公开元数据（不含公钥/原始凭证/计数器）。
type UIPasskey struct {
	ID             string
	Name           string
	BackupEligible bool
	BackedUp       bool
	Transports     []string
	CreatedAt      time.Time
	LastUsedAt     time.Time
}

// UIPasskeyRegistration 是注册 ceremony 公开选项。
type UIPasskeyRegistration struct {
	CeremonyID string
	PublicKey  []byte
	ExpiresAt  time.Time
}

// UIPasskeyFinish 是注册完成字段（断言只在当前请求）。
type UIPasskeyFinish struct {
	CeremonyID string
	Response   []byte
	Name       string
}

// UIRecoveryInventory 是恢复代码组只读概览。
type UIRecoveryInventory struct {
	HasActiveGroup bool
	Generation     int64
	CodesRemaining int
	CreatedAt      time.Time
}

// UISessionSummary 是会话公开摘要（UA/来源仅作展示参考）。
type UISessionSummary struct {
	ID                string
	Current           bool
	AppID             string
	Kind              string
	Reason            string
	CreatedAt         time.Time
	LastSeenAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	RememberMe        bool
	ClientHint        string
	AddressHint       string
}

// UISessionPage 是会话分页结果。
type UISessionPage struct {
	Sessions []UISessionSummary
	Page     int
	PageSize int
	Total    int64
	HasMore  bool
}

// UIGrant 是已授权应用公开摘要（不含 Token/授权码）。
type UIGrant struct {
	AuthorizationID       string
	ApplicationName       string
	ClientID              string
	Scopes                []UIPageScopeInfo
	Audiences             []UIPageAudienceInfo
	ApprovedAt            time.Time
	ExpiresAt             time.Time
	ActiveRefreshFamilies int
}

// UIGrantPage 是已授权应用分页结果。
type UIGrantPage struct {
	Grants   []UIGrant
	Page     int
	PageSize int
	Total    int64
	HasMore  bool
}

// UIGrantRevokeResult 是撤回结果（区分刷新族/未兑换码/离线 Token 限制）。
type UIGrantRevokeResult struct {
	RefreshFamilies    int64
	RefreshTokens      int64
	AuthorizationCodes int64
}

// PageSecurityRouteNames 返回步骤 67 命名路由。
func PageSecurityRouteNames() []string {
	return []string{
		"account.security", "account.security_mfa", "account.security_mfa.add_start",
		"account.security_mfa.add_confirm", "account.security_mfa.remove",
		"account.security_totp", "account.security_totp.bind_start",
		"account.security_totp.bind_confirm", "account.security_totp.remove",
		"account.security_passkeys", "account.security_passkeys.register_start",
		"account.security_passkeys.register_finish", "account.security_passkeys.rename",
		"account.security_passkeys.revoke", "account.security_recovery_codes",
		"account.security_recovery_codes.generate", "account.sessions",
		"account.sessions.revoke", "account.sessions.revoke_others",
		"account.sessions.revoke_all", "account.grants", "account.grants.revoke",
	}
}

// pageSecurityPages 是步骤 67 路由与处理器。
type pageSecurityPages struct {
	routes   []UIRoute
	handlers map[string]UIPageHandler
	options  UIPageSecurityOptions
}

// newPageSecurityPages 校验配置并构造页面。
func newPageSecurityPages(options UIPageSecurityOptions) (*pageSecurityPages, error) {
	if isNilUIValue(options.Backend) {
		return nil, fmt.Errorf("安全中心页面后端适配器不能为空")
	}
	pages := &pageSecurityPages{handlers: map[string]UIPageHandler{}, options: options}
	handler := &securityPageHandlers{pages: pages}
	routes := []UIRoute{
		{Name: "account.security", Method: http.MethodGet, Path: "/account/security",
			Access: UIAccessUser, Layout: "layout/base", Template: "page/account/security"},
		{Name: "account.security_mfa", Method: http.MethodGet, Path: "/account/security/mfa",
			Access: UIAccessUser, Layout: "layout/base", Template: "page/account/security_mfa"},
		{Name: "account.security_mfa.add_start", Method: http.MethodPost,
			Path: "/account/security/mfa", Access: UIAccessUser, Layout: "layout/base",
			Template: "page/account/security_mfa"},
		{Name: "account.security_mfa.add_confirm", Method: http.MethodPost,
			Path: "/account/security/mfa/confirm", Access: UIAccessUser, Layout: "layout/base",
			Template: "page/account/security_mfa"},
		{Name: "account.security_mfa.remove", Method: http.MethodPost,
			Path: "/account/security/mfa/remove", Access: UIAccessUser, Layout: "layout/base",
			Template: "page/account/security_mfa"},
		{Name: "account.security_totp", Method: http.MethodGet, Path: "/account/security/totp",
			Access: UIAccessUser, Layout: "layout/base", Template: "page/account/security_totp"},
		{Name: "account.security_totp.bind_start", Method: http.MethodPost,
			Path: "/account/security/totp/bind", Access: UIAccessUser, Layout: "layout/base",
			Template: "page/account/security_totp"},
		{Name: "account.security_totp.bind_confirm", Method: http.MethodPost,
			Path: "/account/security/totp/confirm", Access: UIAccessUser, Layout: "layout/base",
			Template: "page/account/security_totp"},
		{Name: "account.security_totp.remove", Method: http.MethodPost,
			Path: "/account/security/totp/remove", Access: UIAccessUser, Layout: "layout/base",
			Template: "page/account/security_totp"},
		{Name: "account.security_passkeys", Method: http.MethodGet,
			Path: "/account/security/passkeys", Access: UIAccessUser, Layout: "layout/base",
			Template: "page/account/security_passkeys"},
		{Name: "account.security_passkeys.register_start", Method: http.MethodPost,
			Path: "/account/security/passkeys/register", Access: UIAccessUser,
			Layout: "layout/base", Template: "page/account/security_passkeys"},
		{Name: "account.security_passkeys.register_finish", Method: http.MethodPost,
			Path: "/account/security/passkeys/register/finish", Access: UIAccessUser,
			Layout: "layout/base", Template: "page/account/security_passkeys"},
		{Name: "account.security_passkeys.rename", Method: http.MethodPost,
			Path: "/account/security/passkeys/rename", Access: UIAccessUser,
			Layout: "layout/base", Template: "page/account/security_passkeys"},
		{Name: "account.security_passkeys.revoke", Method: http.MethodPost,
			Path: "/account/security/passkeys/revoke", Access: UIAccessUser,
			Layout: "layout/base", Template: "page/account/security_passkeys"},
		{Name: "account.security_recovery_codes", Method: http.MethodGet,
			Path: "/account/security/recovery-codes", Access: UIAccessUser,
			Layout: "layout/base", Template: "page/account/security_recovery_codes"},
		{Name: "account.security_recovery_codes.generate", Method: http.MethodPost,
			Path: "/account/security/recovery-codes", Access: UIAccessUser,
			Layout: "layout/base", Template: "page/account/security_recovery_codes"},
		{Name: "account.sessions", Method: http.MethodGet, Path: "/account/sessions",
			Access: UIAccessUser, Layout: "layout/base", Template: "page/account/sessions"},
		{Name: "account.sessions.revoke", Method: http.MethodPost, Path: "/account/sessions/revoke",
			Access: UIAccessUser, Layout: "layout/base", Template: "page/account/sessions"},
		{Name: "account.sessions.revoke_others", Method: http.MethodPost,
			Path: "/account/sessions/revoke-others", Access: UIAccessUser,
			Layout: "layout/base", Template: "page/account/sessions"},
		{Name: "account.sessions.revoke_all", Method: http.MethodPost,
			Path: "/account/sessions/revoke-all", Access: UIAccessUser,
			Layout: "layout/base", Template: "page/account/sessions"},
		{Name: "account.grants", Method: http.MethodGet, Path: "/account/grants",
			Access: UIAccessUser, Layout: "layout/base", Template: "page/account/grants"},
		{Name: "account.grants.revoke", Method: http.MethodPost,
			Path: "/account/grants/revoke", Access: UIAccessUser,
			Layout: "layout/base", Template: "page/account/grants"},
	}
	for _, route := range routes {
		pages.routes = append(pages.routes, route)
		pages.handlers[route.Name] = handler
	}
	return pages, nil
}

// securityText 返回中文基线文案。
func securityText(key string) string { return textMFA(key) }

// securityPageHandlers 实现步骤 67 页面处理器。
type securityPageHandlers struct{ pages *pageSecurityPages }

// HandlePage 按路由分派。
func (h *securityPageHandlers) HandlePage(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	backend := h.pages.options.Backend
	userID := page.Session.UserID
	if userID == "" || page.Session.Kind != "normal" {
		return UIPageOutcome{StatusCode: http.StatusForbidden, ErrorCode: "ACCESS_DENIED",
			ErrorSummary: securityText("error.business.ACCESS_DENIED")}, nil
	}
	switch page.RouteName {
	case "account.security":
		overview, err := backend.GetOverview(ctx, userID)
		if err != nil {
			return accountErrorOutcome(err, nil, ""), nil
		}
		return UIPageOutcome{Data: map[string]any{"Overview": overview}}, nil
	case "account.security_mfa", "account.security_mfa.add_start",
		"account.security_mfa.add_confirm", "account.security_mfa.remove":
		return h.mfa(ctx, request, page, backend, userID)
	case "account.security_totp", "account.security_totp.bind_start",
		"account.security_totp.bind_confirm", "account.security_totp.remove":
		return h.totp(ctx, request, page, backend, userID)
	case "account.security_passkeys", "account.security_passkeys.register_start",
		"account.security_passkeys.register_finish", "account.security_passkeys.rename",
		"account.security_passkeys.revoke":
		return h.passkeys(ctx, request, page, backend, userID)
	case "account.security_recovery_codes", "account.security_recovery_codes.generate":
		return h.recovery(ctx, request, page, backend, userID)
	case "account.sessions", "account.sessions.revoke", "account.sessions.revoke_others",
		"account.sessions.revoke_all":
		return h.sessions(ctx, request, page, backend, userID)
	case "account.grants", "account.grants.revoke":
		return h.grants(ctx, request, page, backend, userID)
	default:
		return UIPageOutcome{}, nil
	}
}
