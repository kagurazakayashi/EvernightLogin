package adminapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	"github.com/kagurazakayashi/EvernightLogin/internal/transport"
)

// routeSegment 是路由模式的一段：字面量或 {参数}。
type routeSegment struct {
	literal string
	param   string
}

// route 是一条固定管理 API 路由；顺序即匹配优先级，字面量段多的模式必须先
// 注册，避免被同段数的 {参数} 模式吞掉。
type route struct {
	method   string
	pattern  string
	segments []routeSegment
	handler  func(*callContext) error
}

// buildRoutes 按已装配的领域服务生成路由表。未装配的服务不注册任何路由，
// 对应请求得到 404（fail-closed），而不是“暂未实现也放行”。
func (s *Server) buildRoutes() []route {
	var routes []route
	add := func(method, pattern string, handler func(*callContext) error) {
		routes = append(routes, route{method: method, pattern: pattern,
			segments: parseRoutePattern(pattern), handler: handler})
	}

	// 基础只读端点：不依赖具体领域服务。
	add(http.MethodGet, "meta", s.handleMeta)
	add(http.MethodGet, "error-codes", s.handleErrorCodes)

	if s.sessionRevoker != nil {
		// 步骤 151：管理员强制下线。权限/作用范围/强认证/root 保护/审计全部由
		// 会话服务重新判定；本层只做参数与错误映射。
		add(http.MethodPost, "sessions/revoke", s.handleSessionAdminRevoke)
	}
	if s.audit != nil {
		add(http.MethodGet, "audit/events", s.handleAuditEventList)
		add(http.MethodGet, "audit/events/{event_id}", s.handleAuditEventGet)
		add(http.MethodGet, "audit/retention", s.handleAuditRetentionGet)
		add(http.MethodGet, "audit/exports", s.handleAuditExportList)
		add(http.MethodGet, "audit/exports/{export_id}", s.handleAuditExportGet)
		add(http.MethodGet, "audit/exports/{export_id}/download", s.handleAuditExportDownload)
		add(http.MethodPost, "audit/exports", s.handleAuditExportStart)
		add(http.MethodPost, "audit/exports/{export_id}/cancel", s.handleAuditExportCancel)
		add(http.MethodGet, "audit/purge-runs", s.handleAuditPurgeList)
		add(http.MethodGet, "audit/purge-runs/{run_id}", s.handleAuditPurgeGet)
		add(http.MethodPost, "audit/purge/preview", s.handleAuditPurgePreview)
		add(http.MethodPost, "audit/purge", s.handleAuditPurgeStart)
		add(http.MethodPost, "audit/purge/{run_id}/cancel", s.handleAuditPurgeCancel)
		add(http.MethodPut, "audit/retention", s.handleAuditRetentionSet)
	}
	if s.reports != nil {
		add(http.MethodGet, "reports", s.handleReportHistoryList)
		add(http.MethodGet, "reports/cleanup-preview", s.handleReportCleanupPreview)
		add(http.MethodPost, "reports/cleanup", s.handleReportCleanupExecute)
		add(http.MethodGet, "reports/{report_id}", s.handleReportGet)
		add(http.MethodGet, "reports/{report_id}/snapshot", s.handleReportSnapshot)
		add(http.MethodPost, "reports/download-tickets/redeem", s.handleReportDownloadRedeem)
		add(http.MethodPost, "reports/{report_id}/download-tickets", s.handleReportDownloadTicket)
		add(http.MethodPost, "reports/{report_id}/cancel", s.handleReportCancel)
		add(http.MethodPost, "reports/{report_id}/retry", s.handleReportRetry)
	}
	if s.plans != nil {
		add(http.MethodGet, "report-plans", s.handlePlanList)
		add(http.MethodPost, "report-plans", s.handlePlanCreate)
		add(http.MethodGet, "report-plans/{plan_id}", s.handlePlanGet)
		add(http.MethodPut, "report-plans/{plan_id}", s.handlePlanUpdate)
		add(http.MethodDelete, "report-plans/{plan_id}", s.handlePlanDelete)
		add(http.MethodGet, "report-plans/{plan_id}/delete-preview", s.handlePlanDeletePreview)
		add(http.MethodPost, "report-plans/{plan_id}/enabled", s.handlePlanSetEnabled)
	}
	if s.backups != nil {
		add(http.MethodGet, "backups", s.handleBackupArtifactList)
		add(http.MethodGet, "backups/capabilities", s.handleBackupCapabilities)
		add(http.MethodGet, "backups/retention", s.handleBackupRetentionGet)
		add(http.MethodGet, "backups/cleanup-preview", s.handleBackupCleanupPreview)
		add(http.MethodGet, "backups/jobs", s.handleBackupJobList)
		add(http.MethodGet, "backups/schedules", s.handleBackupScheduleList)
		add(http.MethodPost, "backups/schedules", s.handleBackupScheduleCreate)
		add(http.MethodGet, "backups/schedules/{schedule_id}", s.handleBackupScheduleGet)
		add(http.MethodPut, "backups/schedules/{schedule_id}", s.handleBackupScheduleUpdate)
		add(http.MethodDelete, "backups/schedules/{schedule_id}", s.handleBackupScheduleDelete)
		add(http.MethodPost, "backups/schedules/{schedule_id}/enabled", s.handleBackupScheduleSetEnabled)
		add(http.MethodGet, "backups/jobs/{job_id}", s.handleBackupJobGet)
		add(http.MethodGet, "backups/{backup_id}", s.handleBackupArtifactGet)
		add(http.MethodPost, "backups", s.handleBackupCreate)
		add(http.MethodPost, "backups/cleanup", s.handleBackupCleanupEnqueue)
		add(http.MethodPost, "backups/download-tickets/redeem", s.handleBackupDownloadRedeem)
		add(http.MethodPost, "backups/jobs/{job_id}/cancel", s.handleBackupJobCancel)
		add(http.MethodPost, "backups/{backup_id}/download-tickets", s.handleBackupDownloadTicket)
		add(http.MethodPut, "backups/retention", s.handleBackupRetentionSet)
	}
	// 任务详情必须同时装配查询与权限/数据范围判定；任一缺失都不挂载路由，
	// 避免“可管理会话即可读任意任务元数据”的 IDOR。
	if s.tasks != nil && s.taskAuthorizer != nil {
		add(http.MethodGet, "tasks/{task_id}", s.handleTaskGet)
	}
	for _, domainRoute := range s.domainRoutes {
		domainRoute := domainRoute
		add(domainRoute.Method, domainRoute.Pattern, func(c *callContext) error {
			data, err := domainRoute.Handler(c.request.Context(), c.caller, c.request)
			if err != nil {
				return s.domainProblem(err)
			}
			s.writeSuccess(c.writer, c.requestID, data)
			return nil
		})
	}
	// 通知端点始终挂载：未装配本地捕获/配置时返回稳定的能力错误码，便于 CLI
	// 明确区分“不可用”与“路径不存在”（绝不伪成功、绝不真实外发）。
	add(http.MethodGet, "notifications", s.handleNotificationStatus)
	add(http.MethodPost, "notifications/test", s.handleNotificationTest)
	return routes
}

// parseRoutePattern 把 "a/{param}/b" 解析为段列表。
func parseRoutePattern(pattern string) []routeSegment {
	rawSegments := strings.Split(pattern, "/")
	segments := make([]routeSegment, 0, len(rawSegments))
	for _, raw := range rawSegments {
		if strings.HasPrefix(raw, "{") && strings.HasSuffix(raw, "}") {
			segments = append(segments, routeSegment{param: strings.TrimSuffix(strings.TrimPrefix(raw, "{"), "}")})
			continue
		}
		segments = append(segments, routeSegment{literal: raw})
	}
	return segments
}

// match 把相对路径匹配到路由并返回路径参数。
func matchRoute(routes []route, method, relativePath string) (*route, map[string]string, bool, []string) {
	segments := strings.Split(relativePath, "/")
	var allowed []string
	for index := range routes {
		candidate := &routes[index]
		if len(candidate.segments) != len(segments) {
			continue
		}
		params := make(map[string]string, 2)
		matched := true
		for position, pattern := range candidate.segments {
			value := segments[position]
			if pattern.param != "" {
				if value == "" {
					matched = false
					break
				}
				params[pattern.param] = value
				continue
			}
			if pattern.literal != value {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		allowed = append(allowed, candidate.method)
		if candidate.method == method {
			return candidate, params, true, allowed
		}
	}
	return nil, nil, false, allowed
}

// Handler 返回可直接挂载的 http.Handler。宿主应把它挂在 Options.BasePath 前缀下
// （Mount 已完成；也可直接作为子路由处理器使用）。
func (s *Server) Handler() http.Handler { return s }

// Mount 把管理 API 注册到给定 ServeMux，返回实际注册的模式（供文档与测试核对）。
// 不会覆盖已注册的模式：同一 ServeMux 重复注册会 panic，宿主应先检查。
func (s *Server) Mount(mux *http.ServeMux) ([]string, error) {
	if mux == nil {
		return nil, fmt.Errorf("%w: ServeMux 为空", ErrOptionsInvalid)
	}
	pattern := s.basePath + "/"
	mux.Handle(pattern, s)
	return []string{pattern}, nil
}

// ServeHTTP 是管理 API 入口：建立请求编号与处理期限、恢复 panic、重新认证管理
// 会话、执行 CSRF 契约、路由并写统一 JSON 响应与访问日志。
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := transport.RequestIDFromContext(r.Context())
	if requestID == "" {
		requestID = s.newRequestID()
	}
	w.Header().Set("X-Request-ID", requestID)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	defer func() {
		if recovered := recover(); recovered != nil {
			s.logger.Error("管理 API 处理发生 panic", "request_id", requestID)
			s.writeProblem(w, requestID, s.codeProblem(string(codeInternalError), nil))
		}
	}()

	if r.URL.Path == s.basePath || !strings.HasPrefix(r.URL.Path, s.basePath+"/") {
		// 挂载前缀之外或只有前缀本身：语义上是“资源不存在”，不泄露内部路由。
		s.writeProblem(w, requestID, s.notFoundProblem())
		return
	}
	relativePath, ok := s.relativePath(r.URL.Path, r.URL.RawPath)
	if !ok {
		s.writeProblem(w, requestID, s.codeProblem(string(codeReqInvalid), nil))
		return
	}
	matched, params, methodMatched, allowed := matchRoute(s.routes, r.Method, relativePath)
	if matched == nil {
		if !methodMatched && len(allowed) > 0 {
			w.Header().Set("Allow", strings.Join(allowed, ", "))
			p := s.codeProblem(string(codeReqInvalid), nil)
			p.status = http.StatusMethodNotAllowed
			p.message = "请求方法不受支持"
			s.writeProblem(w, requestID, p)
			return
		}
		s.writeProblem(w, requestID, s.notFoundProblem())
		return
	}
	if r.ContentLength > s.maxBodyBytes {
		p := s.codeProblem(string(codeReqInvalid), nil)
		p.status = http.StatusRequestEntityTooLarge
		p.message = "请求体超过允许的大小"
		s.writeProblem(w, requestID, p)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.maxBodyBytes)

	ctx, cancel := context.WithTimeout(r.Context(), s.requestTimeout)
	defer cancel()
	r = r.WithContext(ctx)

	if problem := s.authenticate(ctx, r, requestID); problem != nil {
		s.writeProblem(w, requestID, problem)
		return
	}
	secret, _ := s.session.SessionSecretFromRequest(r)
	sessionRecord, err := s.session.AuthorizeManagement(ctx, secret)
	if err != nil {
		s.writeProblem(w, requestID, s.sessionProblem(err))
		return
	}
	if !sessionRecord.CanAccessManagement() {
		s.writeProblem(w, requestID, s.codeProblem(string(codeAccessDenied), nil))
		return
	}
	caller, callerErr := account.UserCaller(sessionRecord.UserID)
	if callerErr != nil {
		s.writeProblem(w, requestID, s.codeProblem(string(codeAccessDenied), callerErr))
		return
	}
	caller, callerErr = caller.WithRequestID(requestID)
	if callerErr != nil {
		s.writeProblem(w, requestID, s.codeProblem(string(codeReqInvalid), callerErr))
		return
	}
	if problem := s.validateCSRF(ctx, r); problem != nil {
		s.writeProblem(w, requestID, problem)
		return
	}
	call := &callContext{server: s, writer: w, request: r,
		requestID: requestID, caller: caller, params: params}
	if handlerErr := matched.handler(call); handlerErr != nil {
		s.writeProblem(w, requestID, s.problemFor(ctx, handlerErr))
	}
}

// authenticate 先做一次“会话秘密存在性”检查，避免把未认证请求送进后续逻辑；
// 真正的状态校验仍由 AuthorizeManagement 完成（每次请求重新鉴权）。
func (s *Server) authenticate(_ context.Context, r *http.Request, _ string) *problem {
	if _, ok := s.session.SessionSecretFromRequest(r); !ok {
		return s.codeProblem(string(codeAuthFailed), nil)
	}
	return nil
}

// notFoundProblem 构造“资源不存在”的统一 404（不区分未挂载与未知路径，避免
// 暴露内部能力装配情况）。
func (s *Server) notFoundProblem() *problem {
	p := s.codeProblem(string(codeReqInvalid), nil)
	p.status = http.StatusNotFound
	p.message = "请求的资源不存在"
	return p
}

// validateCSRF 实现管理 API 的 CSRF 契约：
//   - Authorization: Bearer 会话秘密（CLI/宿主进程内调用）不依赖浏览器 Cookie，
//     不受 CSRF 影响，但仍是管理会话，需通过同一 AuthorizeManagement；
//   - Cookie 会话（浏览器同站）的所有非安全方法必须携带与会话绑定的
//     X-CSRF-Token，并由既有会话服务校验；缺失或无效一律拒绝。
//
// Origin/Referer 允许列表由宿主 HTTP 防护中间件负责，本包不重复实现，但文档
// 明确要求宿主必须挂载在该中间件之后。
func (s *Server) validateCSRF(ctx context.Context, r *http.Request) *problem {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return nil
	}
	if requestUsesBearer(r) {
		return nil
	}
	token := strings.TrimSpace(r.Header.Get(CSRFHeaderName))
	if token == "" {
		return s.codeProblem(string(codeAccessDenied), nil)
	}
	if err := s.session.ValidateCSRFToken(ctx, r, token); err != nil {
		return s.codeProblem(string(codeAccessDenied), err)
	}
	return nil
}

// requestUsesBearer 判断本请求是否属于“无 Cookie、仅用 Authorization: Bearer”
// 的调用。CSRF 判定必须与实际凭据一致：
//   - 只要请求携带任何 Cookie（会话服务会优先用 Cookie 鉴权，浏览器也可能自动
//     附带 Cookie），一律不认定为 Bearer 免 CSRF，必须校验 X-CSRF-Token；
//   - 仅当完全没有 Cookie 且恰好一个 Authorization: Bearer 头（scheme 大小写
//     不敏感，其后必须有一个空白与非空令牌）时才免 CSRF。
//
// 解析规则与 internal/session 的 SessionSecretFromRequest 对齐，但更严格：
// 未知/自定义 Cookie 名同样触发 CSRF 要求，避免按默认 Cookie 名判断造成漏检。
func requestUsesBearer(r *http.Request) bool {
	if len(r.Cookies()) > 0 || strings.TrimSpace(r.Header.Get("Cookie")) != "" {
		return false
	}
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return false
	}
	scheme, token, found := strings.Cut(strings.TrimSpace(values[0]), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return false
	}
	return strings.TrimSpace(token) != ""
}

// sessionProblem 把会话服务错误映射为统一 problem（复用根包既有错误码）。
// 强认证缺失/过期单独映射为 REAUTH_REQUIRED，便于 CLI/宿主提示重新认证；
// 其余错误沿用会话服务 CodeOf 的既有映射。
func (s *Server) sessionProblem(err error) *problem {
	if errors.Is(err, session.ErrStrongAuthRequired) {
		return s.codeProblem(string(codeReauthRequired), err)
	}
	code := string(session.CodeOf(err))
	if code == "" {
		code = string(codeAuthFailed)
	}
	return s.codeProblem(code, err)
}

// relativePath 校验请求路径并返回相对挂载前缀的部分。路径归一化一律拒绝而非
// “清理后仍然命中”：编码斜杠、反斜杠、点段、重复斜杠、尾斜杠都不被接受。
// rawPath 是客户端未解码的原始路径；只要出现编码斜杠/反斜杠就拒绝，防止
// URL.Path 解码后与本包路由校验之间出现口径差异。
func (s *Server) relativePath(path, rawPath string) (string, bool) {
	if !strings.HasPrefix(path, s.basePath+"/") {
		return "", false
	}
	lowerRaw := strings.ToLower(rawPath)
	if strings.Contains(lowerRaw, "%2f") || strings.Contains(lowerRaw, "%5c") ||
		strings.Contains(lowerRaw, "%2e") {
		return "", false
	}
	if escaped := strings.ToLower(path); strings.Contains(escaped, "%2f") ||
		strings.Contains(escaped, "%5c") {
		return "", false
	}
	relative := strings.TrimPrefix(path, s.basePath+"/")
	if relative == "" {
		return "", false
	}
	for _, segment := range strings.Split(relative, "/") {
		if segment == "" || segment == "." || segment == ".." || strings.ContainsAny(segment, "\\") {
			return "", false
		}
	}
	return relative, true
}

// domainProblem 把宿主领域路由错误映射为统一 problem。DomainError 的 Code 必须
// 已登记；未识别错误一律 500，不输出内部细节。
func (s *Server) domainProblem(err error) *problem {
	var domainErr *DomainError
	if errors.As(err, &domainErr) && domainErr != nil {
		code := domainErr.Code
		if _, ok := s.codes[code]; !ok {
			code = string(codeInternalError)
		}
		problem := s.codeProblem(code, domainErr.Cause)
		if domainErr.Message != "" {
			problem.message = domainErr.Message
		}
		return problem
	}
	return s.codeProblem(string(codeInternalError), err)
}
