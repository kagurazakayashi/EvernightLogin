package app

// 会话校验公开门面（嵌入宿主用）。
//
// 目标：让宿主能在自己的业务 API 上验证 Evernight 会话，而不需要导入 internal/
// 或伪造 HTTP 请求。Validate 只接受完整会话；ValidateCSRF 校验与会话绑定的 CSRF
// 令牌；Authorize 提供“会话有效 + 属于当前应用 + 具备所需权限”的联合检查，复用
// 既有授权内核，避免业务方把单一 Validate 当成授权结论。
//
// 差异核查（步骤 208）：
//   - 会话有效不等于会话属于当前应用：Authorize 同时检查会话的应用绑定与目标应用
//     的成员/状态/权限；绑定不一致返回 APP_SCOPE_MISMATCH。
//   - CSRF 通过不等于有权限：ValidateCSRF 通过不会提升受限会话或改变授权结果；
//     Authorize 对受限会话一律拒绝。
//   - 来源（Origin/Referer）与传输层限流仍由宿主 HTTP 防护层负责，本门面不解析
//     转发头；会话秘密必须来自可信边界（Cookie/Authorization 或宿主安全存储）。

import (
	"context"
	"errors"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// Validate 校验会话秘密并返回脱敏快照。空闲/绝对过期、撤销、账户禁用、安全版本
// 变化、应用成员失效都会失败；不会延长会话。
//
// 它只证明“会话此刻有效且完整”，不证明会话属于当前业务应用、也不证明用户具备
// 当前操作权限；业务/管理操作必须再走 Authorize 或领域服务的真实授权判定。
func (f *sessionFacade) Validate(ctx context.Context, sessionSecret []byte) (SessionInfo, error) {
	requestID, err := resolveRequestID(ctx, "")
	if err != nil {
		return SessionInfo{}, err
	}
	record, err := f.r.requireSession(ctx, sessionSecret, true, requestID)
	if err != nil {
		return SessionInfo{}, err
	}
	info := SessionInfo{
		UserID:               record.UserID,
		SessionID:            record.ID,
		AppID:                record.AppID,
		ExpiresAt:            record.AbsoluteExpiresAt,
		IdleExpiresAt:        record.IdleExpiresAt,
		CreatedAt:            record.CreatedAt,
		SecurityVersion:      record.SecurityVersion,
		StrongAuthVerifiedAt: record.StrongAuthVerifiedAt,
	}
	for _, method := range record.AuthMethods {
		info.AuthMethods = append(info.AuthMethods, string(method))
	}
	return info, nil
}

// ValidateCSRF 校验与会话绑定的 CSRF 令牌。会话秘密必须由可信边界取得；不要把
// 会话秘密或 CSRF 令牌写入 URL、日志或 localStorage。
//
// CSRF 校验成功只表示该请求不是跨站伪造，它不提升受限会话权限、不授予任何业务
// 权限，也不代替 Authorize 的应用/权限判断。
func (f *sessionFacade) ValidateCSRF(ctx context.Context, sessionSecret []byte, token string) error {
	requestID, err := resolveRequestID(ctx, "")
	if err != nil {
		return err
	}
	return f.validateCSRF(ctx, sessionSecret, token, requestID)
}

// validateCSRF 是带显式请求编号的 CSRF 校验实现，供 Authorize 与 ValidateCSRF 共用。
func (f *sessionFacade) validateCSRF(ctx context.Context, sessionSecret []byte,
	token, requestID string) error {
	services := f.r.coreServices()
	if services == nil {
		return configError("服务未装配", requestID)
	}
	if len(sessionSecret) == 0 {
		return login.NewAppError(login.CodeAuthFailed, "会话无效或已失效",
			login.WithRequestID(requestID))
	}
	if strings.TrimSpace(token) == "" {
		return login.NewAppError(login.CodeReqInvalid, "CSRF 令牌为空",
			login.WithRequestID(requestID))
	}
	if err := services.Sessions.ValidateCSRFTokenForSecret(ctx, string(sessionSecret), token); err != nil {
		return mapDomainError("会话 CSRF 校验未通过", string(session.CodeOf(err)), requestID)
	}
	return nil
}

// Authorize 执行“会话 + 应用绑定 + 所需权限（+ 可选资源）”的联合检查。
//
// 判定顺序（默认拒绝）：
//  1. 输入校验：应用范围与至少一个权限键必填，请求编号空则生成、非法则拒绝；
//     提供 ResourceID 时要求恰好一个权限键，拒绝“多权限资源判定”的含糊请求；
//  2. 可选 CSRF 校验：只在请求带 CSRFToken 时执行，通过不改变后续授权结论；
//  3. 会话有效性：无效/过期/撤销/账户状态变化 → 返回 AUTH_FAILED 等稳定错误；
//  4. 完整会话：受限会话（待第二因素/受限恢复）直接拒绝，CSRF 不能提升权限；
//  5. 应用绑定：会话自身绑定到其他应用 → APP_SCOPE_MISMATCH；
//  6. 权限内核：复用 authz.Check 判定账户/应用/成员状态与当前权限（含数据范围
//     交集）；提供 ResourceID 时再复用 authz.CheckResourceAccess 判定该资源的
//     数据范围。拒绝以决策返回（Allowed=false + 稳定 Code），不向调用者泄露内部
//     细节；未提供 ResourceID 的结论不证明任何具体业务资源已通过归属检查。
func (f *sessionFacade) Authorize(ctx context.Context,
	req SessionAccessRequest) (SessionAccessDecision, error) {
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return SessionAccessDecision{}, err
	}
	if err := facadeContextError(ctx, requestID); err != nil {
		return SessionAccessDecision{}, err
	}
	services := f.r.coreServices()
	if services == nil {
		return SessionAccessDecision{}, configError("服务未装配", requestID)
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Authz == nil {
		return SessionAccessDecision{}, configError("权限服务未装配", requestID)
	}
	appID := strings.TrimSpace(req.AppID)
	if appID == "" {
		return SessionAccessDecision{}, login.NewAppError(login.CodeReqInvalid,
			"会话授权需要明确的应用范围", login.WithRequestID(requestID))
	}
	permissions := normalizeSessionPermissions(req.Permissions)
	if len(permissions) == 0 {
		return SessionAccessDecision{}, login.NewAppError(login.CodeReqInvalid,
			"会话授权需要至少一个权限键", login.WithRequestID(requestID))
	}
	mode := authz.Mode(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = authz.ModeAll
	}
	if !mode.Valid() {
		return SessionAccessDecision{}, login.NewAppError(login.CodeReqInvalid,
			"权限组合模式必须是 all 或 any", login.WithRequestID(requestID))
	}
	resourceID := req.ResourceID
	if resourceID != "" && len(permissions) != 1 {
		return SessionAccessDecision{}, login.NewAppError(login.CodeReqInvalid,
			"资源级会话授权需要恰好一个权限键", login.WithRequestID(requestID))
	}
	if len(req.SessionSecret) == 0 {
		return SessionAccessDecision{}, login.NewAppError(login.CodeAuthFailed,
			"会话无效或已失效", login.WithRequestID(requestID))
	}
	if token := strings.TrimSpace(req.CSRFToken); token != "" {
		if err := f.validateCSRF(ctx, req.SessionSecret, token, requestID); err != nil {
			return SessionAccessDecision{}, err
		}
	}
	record, err := services.Sessions.Validate(ctx, string(req.SessionSecret))
	if err != nil {
		return SessionAccessDecision{}, mapDomainError("会话无效或已失效",
			string(session.CodeOf(err)), requestID)
	}
	decision := SessionAccessDecision{UserID: record.UserID, SessionID: record.ID,
		AppID: appID, RequestID: requestID, ResourceID: resourceID}
	if !record.IsNormal() {
		// 受限会话（待第二因素或受限恢复）不能访问业务；CSRF 通过也不改变这一点。
		decision.Code = string(login.CodeAccessDenied)
		decision.Reason = "restricted_session"
		return decision, nil
	}
	if record.AppID != "" && record.AppID != appID {
		decision.Code = string(login.CodeAppScopeMismatch)
		decision.Reason = "session_app_mismatch"
		return decision, nil
	}
	caller, err := authz.UserCaller(record.UserID)
	if err != nil {
		return SessionAccessDecision{}, configError("会话主体无效", requestID)
	}
	if caller, err = bindCaller(caller, requestID); err != nil {
		return SessionAccessDecision{}, err
	}
	if resourceID != "" {
		// 资源级判定：功能权限 + 该资源的数据范围，复用领域内核，不能只看功能权限。
		result, err := managed.Authz.CheckResourceAccess(ctx, caller, record.UserID,
			appID, permissions[0], resourceID)
		if err != nil {
			if errors.Is(err, authz.ErrAccessDenied) {
				// 权限内核拒绝查询该主体（例如非本人且非受信主体）：按无权限拒绝，
				// 不把内部授权原因以错误文本暴露。
				decision.Code = string(login.CodeAccessDenied)
				decision.Reason = "authorization_unavailable"
				return decision, nil
			}
			return SessionAccessDecision{}, mapDomainError("会话资源授权检查失败",
				string(authz.CodeOf(err)), requestID)
		}
		decision.Allowed = result.Allowed
		decision.Code = string(result.Code)
		decision.Reason = result.Reason
		decision.ResourceChecked = true
		decision.ResourceID = result.ResourceID
		return decision, nil
	}
	result, err := managed.Authz.Check(ctx, caller, authz.CheckRequest{
		SubjectUserID: record.UserID, ScopeID: appID,
		Permissions: permissions, Mode: mode,
	})
	if err != nil {
		if errors.Is(err, authz.ErrAccessDenied) {
			// 权限内核拒绝查询该主体（例如非本人且非受信主体）：按无权限拒绝，
			// 不把内部授权原因以错误文本暴露。
			decision.Code = string(login.CodeAccessDenied)
			decision.Reason = "authorization_unavailable"
			return decision, nil
		}
		return SessionAccessDecision{}, mapDomainError("会话权限检查失败",
			string(authz.CodeOf(err)), requestID)
	}
	decision.Allowed = result.Allowed
	decision.Code = string(result.Code)
	decision.Reason = result.Reason
	return decision, nil
}

// normalizeSessionPermissions 去空白、丢弃空键并保序去重，避免同一权限键重复计数
// 或空字符串进入权限内核。
func normalizeSessionPermissions(permissions []string) []string {
	seen := make(map[string]struct{}, len(permissions))
	normalized := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		trimmed := strings.TrimSpace(permission)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	return normalized
}

// ListDevices 分页列出当前会话所属用户的本人活动会话（设备列表），供嵌入宿主在
// 自己的安全中心页面展示；只返回展示所需字段，不包含会话秘密/CSRF 令牌/验证摘要。
// offset 在并发登录/退出下不保证快照一致；需要稳定导出应使用稳定游标或快照。
func (f *sessionFacade) ListDevices(ctx context.Context, req SessionDeviceRequest) (SessionDeviceList, error) {
	r := f.r
	services := r.coreServices()
	if services == nil || services.Sessions == nil {
		return SessionDeviceList{}, configError("会话服务未装配")
	}
	if len(req.SessionSecret) == 0 {
		return SessionDeviceList{}, login.NewAppError(login.CodeAccessDenied, "缺少会话秘密")
	}
	page, err := NormalizeAdminPage(req.Page)
	if err != nil {
		return SessionDeviceList{}, err
	}
	result, err := services.Sessions.ListSessionsPage(ctx, string(req.SessionSecret),
		session.ListPageOptions{Limit: page.Limit, Offset: page.Offset})
	if err != nil {
		return SessionDeviceList{}, mapDomainError("读取设备列表失败",
			string(session.CodeOf(err)))
	}
	devices := make([]SessionDevice, 0, len(result.Sessions))
	for _, record := range result.Sessions {
		devices = append(devices, SessionDevice{ID: record.ID, AppID: record.AppID,
			Kind: string(record.Kind), Reason: string(record.Reason),
			CreatedAt: record.CreatedAt, LastSeenAt: record.LastSeenAt,
			IdleExpiresAt:     record.IdleExpiresAt,
			AbsoluteExpiresAt: record.AbsoluteExpiresAt,
			RememberMe:        record.RememberMe, Current: record.Current,
			ClientUserAgent: record.Client.UserAgent, ClientAddress: record.Client.Address})
	}
	return SessionDeviceList{Devices: devices, Total: result.Total,
		HasMore: result.HasMore,
		Page:    NewAdminPageInfo(page, len(devices), result.HasMore)}, nil
}
