package serverapp

// 步骤 186：CLI 敏感操作的一次性再次认证/确认通道。
//
// 目标：让 loginctl 在真实管理会话之上完成“操作绑定”的再认证，并把真实的认证
// 事实注入到**紧接着的那一次管理 API 写请求**，由领域服务既有的
// reauth/policy/audit 链完成最终授权与消费。本文件不绕过任何领域授权：
//
//   - 只有真实管理会话（AuthorizeManagement）才能开始/完成/取消确认；
//   - 确认绑定：主体（用户 + 管理会话 ID）、操作 ID/作用域、目标、参数摘要、
//     以及即将执行的管理 API 写请求（method + 相对路径 + 请求体摘要）、有效期；
//   - 密码/TOTP 路径以真实 internal/reauth 的 Challenge/Approval 为授权事实，
//     一次性批准令牌只保存在服务端内存，下发给 CLI 的是另一次性的确认证明；
//   - WebAuthn 路径受控跳转到服务端自带的最小浏览器页完成真实断言，不降低认证
//     要求；完成状态由 CLI 轮询取得，证明同样只取一次；
//   - 证明只允许使用一次，且在 middleware 中重新校验会话/主体/请求摘要/有效期；
//     校验失败一律 401/403 且不向下游注入任何信号（领域服务仍会 REAUTH_REQUIRED）；
//   - 证明与批准令牌都不进入服务端日志、错误响应或 CLI 的 --json 输出（CLI 将
//     证明写入受保护文件，见 internal/managecli）。

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/kagurazakayashi/EvernightLogin/errs"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/passkey"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// 确认证明的传输与有效期常量。
const (
	// cliConfirmationHeader 是 CLI 把一次性确认证明传给管理 API 写请求的头。
	cliConfirmationHeader = "X-Login-Confirmation"
	// cliConfirmationTTL 是 CLI 确认记录的最长有效期（同时受 reauth 挑战有效期约束）。
	cliConfirmationTTL = 5 * time.Minute
	// cliMaxBodyBytes 是被绑定/被重放的请求体上限（与在线 CLI JSON 上限一致）。
	cliMaxBodyBytes = 8 << 20
)

// cliConfirmationState 是确认记录状态；只有 pending 可验证、只有 verified 可使用。
type cliConfirmationState string

const (
	cliConfirmationPending   cliConfirmationState = "pending"
	cliConfirmationVerified  cliConfirmationState = "verified"
	cliConfirmationCancelled cliConfirmationState = "cancelled"
	cliConfirmationConsumed  cliConfirmationState = "consumed"
)

// cliConfirmation 是一次 CLI 再认证确认记录。敏感字段（批准令牌、证明摘要）只
// 存在于服务端内存/不可导出字段，不写入响应之外的任何输出。
type cliConfirmation struct {
	id           string
	userID       string
	sessionID    string
	scopeID      string
	operationID  string
	targetType   string
	targetID     string
	paramsDigest [32]byte
	method       string
	path         string
	bodyDigest   [32]byte
	required     policy.Strength

	challengeID   string
	approvalToken string
	strength      policy.Strength
	verifiedAt    time.Time
	authMethod    string

	// 证明与浏览器一次性码只保存 SHA-256 摘要；明文只在生成时用于交付/URL，
	// 不写入确认记录、不落盘、不写日志。
	proofDigest    [32]byte
	proofDelivered bool
	webCodeDigest  [32]byte

	state     cliConfirmationState
	expiresAt time.Time
	createdAt time.Time
}

// cliReauthHandler 把确认端点与“证明→reauth 信号”中间件包在管理 API 处理器外。
type cliReauthHandler struct {
	adminPrefix string
	service     *cliReauthService
	next        http.Handler
}

// newCLIReauthHandler 构造 CLI 确认通道；依赖不完整时启动失败（fail-closed）。
func newCLIReauthHandler(deps Deps, services *Services, gate *SecurityGate,
	security *SecurityDomains, adminPrefix string) (*cliReauthHandler, error) {
	if services == nil || services.Sessions == nil {
		return nil, fmt.Errorf("CLI 确认通道缺少真实会话服务")
	}
	if gate == nil || gate.Reauth == nil {
		return nil, fmt.Errorf("CLI 确认通道缺少再次认证服务")
	}
	now := deps.Now
	if now == nil {
		now = time.Now
	}
	var passkeys *passkey.Service
	if security != nil {
		passkeys = security.Passkey
	}
	return &cliReauthHandler{adminPrefix: adminPrefix,
		service: &cliReauthService{adminPrefix: adminPrefix, sessions: services.Sessions, reauth: gate.Reauth,
			passkeys: passkeys, now: now, confirmations: map[string]*cliConfirmation{}}}, nil
}

// wrap 返回包住管理 API 的处理器：先处理确认端点，再为携带证明的写请求注入
// 已校验的 reauth 信号；证明无效时直接拒绝，绝不把未验证信号传给下游。
func (h *cliReauthHandler) wrap(next http.Handler) http.Handler {
	h.next = next
	return h
}

// ServeHTTP 实现 http.Handler。
func (h *cliReauthHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if h.service == nil || h.next == nil {
		writeCLIError(writer, request, http.StatusServiceUnavailable,
			string(reauth.CodeAccessDenied), "CLI 确认通道未装配")
		return
	}
	relative, ok := h.relativePath(request.URL.Path)
	if ok && (relative == "/reauth/begin" || relative == "/reauth/verify" ||
		relative == "/reauth/status" || relative == "/reauth/cancel" ||
		strings.HasPrefix(relative, "/reauth/browser/")) {
		h.service.serve(writer, request, relative)
		return
	}
	if token := strings.TrimSpace(request.Header.Get(cliConfirmationHeader)); token != "" {
		ctx, failure := h.service.authorizeConfirmation(request, token)
		if failure != nil {
			writeCLIError(writer, request, failure.status, string(failure.code), failure.message)
			return
		}
		// 防御纵深：证明已被消费，转发前移除该头，避免下游/日志再次看到证明。
		request.Header.Del(cliConfirmationHeader)
		request = request.WithContext(ctx)
	}
	h.next.ServeHTTP(writer, request)
}

// relativePath 去掉管理 API 前缀，返回站内相对路径；不在前缀下时 ok=false。
func (h *cliReauthHandler) relativePath(path string) (string, bool) {
	if !strings.HasPrefix(path, h.adminPrefix+"/") {
		return "", false
	}
	relative := strings.TrimPrefix(path, h.adminPrefix)
	if relative == "" {
		relative = "/"
	}
	return relative, true
}

// cliReauthService 持有确认记录；不启动协程，过期记录在访问时惰性清理。
type cliReauthService struct {
	adminPrefix string
	sessions    *session.Service
	reauth      *reauth.Service
	passkeys    *passkey.Service
	now         func() time.Time

	mu            sync.Mutex
	confirmations map[string]*cliConfirmation
}

// cliReauthFailure 是确认通道的稳定失败结果。
type cliReauthFailure struct {
	status  int
	code    reauth.ErrorCode
	message string
}

// serve 分派确认端点。
func (s *cliReauthService) serve(writer http.ResponseWriter, request *http.Request, relative string) {
	now := s.now().UTC()
	switch {
	case relative == "/reauth/begin" && request.Method == http.MethodPost:
		s.handleBegin(writer, request, now)
	case relative == "/reauth/verify" && request.Method == http.MethodPost:
		s.handleVerify(writer, request, now)
	case relative == "/reauth/status" && request.Method == http.MethodGet:
		s.handleStatus(writer, request, now)
	case relative == "/reauth/cancel" && request.Method == http.MethodPost:
		s.handleCancel(writer, request, now)
	case strings.HasPrefix(relative, "/reauth/browser/"):
		s.handleBrowser(writer, request, relative, now)
	default:
		writeCLIError(writer, request, http.StatusNotFound, "REQ_INVALID", "未知的 CLI 确认端点")
	}
}

// beginRequest 是 CLI 开始确认的请求：声明即将执行的管理写请求，以便服务端把
// 证明绑定到该请求（method/路径/请求体摘要）。
type beginRequest struct {
	ScopeID     string            `json:"scope_id"`
	OperationID string            `json:"operation_id"`
	TargetType  string            `json:"target_type"`
	TargetID    string            `json:"target_id"`
	Params      map[string]string `json:"params"`
	Description string            `json:"description"`
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	Body        string            `json:"body"`
}

// beginResponse 不含任何证明/令牌；只在 there is a browser path 时给出受控 URL。
type beginResponse struct {
	ConfirmationID   string   `json:"confirmation_id"`
	ChallengeID      string   `json:"challenge_id"`
	Required         bool     `json:"required"`
	RequiredStrength string   `json:"required_strength"`
	Methods          []string `json:"methods"`
	ExpiresAt        string   `json:"expires_at"`
	BrowserPath      string   `json:"browser_path,omitempty"`
}

// handleBegin 校验管理会话并创建绑定挑战。普通会话在这里就被拒绝（不能冒充管理）。
func (s *cliReauthService) handleBegin(writer http.ResponseWriter, request *http.Request, now time.Time) {
	record, failure := s.managementSession(request)
	if failure != nil {
		writeCLIError(writer, request, failure.status, string(failure.code), failure.message)
		return
	}
	var input beginRequest
	if err := decodeCLIJSON(request, &input); err != nil {
		writeCLIError(writer, request, http.StatusBadRequest, "REQ_INVALID", "请求体无效")
		return
	}
	method := strings.ToUpper(strings.TrimSpace(input.Method))
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		writeCLIError(writer, request, http.StatusBadRequest, "REQ_INVALID",
			"确认只支持管理写请求（POST/PUT/PATCH/DELETE）")
		return
	}
	path := strings.TrimSpace(input.Path)
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "..") || len(path) > 512 {
		writeCLIError(writer, request, http.StatusBadRequest, "REQ_INVALID", "绑定路径无效")
		return
	}
	if len(input.Body) > cliMaxBodyBytes {
		writeCLIError(writer, request, http.StatusBadRequest, "REQ_INVALID", "绑定请求体过大")
		return
	}
	caller, err := reauth.UserCaller(record.UserID)
	if err != nil {
		writeCLIError(writer, request, http.StatusForbidden, "ACCESS_DENIED", "调用者无效")
		return
	}
	requestID := cliRequestID(request)
	caller, err = caller.WithRequestID(requestID)
	if err != nil {
		writeCLIError(writer, request, http.StatusBadRequest, "REQ_INVALID", "请求编号无效")
		return
	}
	challenge, err := s.reauth.BeginChallenge(request.Context(), caller, reauth.ChallengeRequest{
		ScopeID: strings.TrimSpace(input.ScopeID), OperationID: strings.TrimSpace(input.OperationID),
		TargetType: strings.TrimSpace(input.TargetType), TargetID: strings.TrimSpace(input.TargetID),
		Params: input.Params, Description: input.Description, RequestID: requestID,
	})
	if err != nil {
		code, status := cliReauthError(err)
		writeCLIError(writer, request, status, string(code), "创建再次认证挑战失败")
		return
	}
	if !challenge.Required {
		writeCLIJSON(writer, request, map[string]any{"confirmation_id": "",
			"challenge_id": challenge.ID, "required": false,
			"required_strength": string(challenge.RequiredStrength),
			"methods":           []string{}, "expires_at": challenge.ExpiresAt.UTC().Format(time.RFC3339)})
		return
	}
	confirmation, webCode, err := s.newConfirmation(record, input, challenge, now)
	if err != nil {
		writeCLIError(writer, request, http.StatusInternalServerError, "INTERNAL_ERROR",
			"无法创建确认记录")
		return
	}
	methods := []string{"password"}
	if challenge.RequiredStrength == policy.StrengthStrong {
		methods = append(methods, "totp")
	}
	response := beginResponse{ConfirmationID: confirmation.id, ChallengeID: challenge.ID,
		Required: true, RequiredStrength: string(challenge.RequiredStrength),
		Methods: methods, ExpiresAt: confirmation.expiresAt.Format(time.RFC3339)}
	if s.passkeys != nil {
		hasSecondFactor, hasErr := s.passkeys.HasSecondFactor(request.Context(), record.UserID)
		if hasErr == nil && hasSecondFactor {
			response.Methods = append(response.Methods, "webauthn")
			response.BrowserPath = fmt.Sprintf("/reauth/browser/%s?code=%s",
				confirmation.id, webCode)
		}
	}
	writeCLIJSON(writer, request, response)
}

// newConfirmation 生成绑定记录；浏览器一次性码只保存 SHA-256 摘要（明文仅用于
// 本函数返回的受控 URL）。确认证明在 verify/status 交付时生成，服务端也只保存摘要。
func (s *cliReauthService) newConfirmation(record session.Session, input beginRequest,
	challenge reauth.Challenge, now time.Time) (*cliConfirmation, string, error) {
	webCode, webDigest, err := newCLIProof()
	if err != nil {
		return nil, "", err
	}
	expiresAt := challenge.ExpiresAt.UTC()
	if limit := now.Add(cliConfirmationTTL); limit.Before(expiresAt) {
		expiresAt = limit
	}
	id, err := newCLIID("cfm_")
	if err != nil {
		return nil, "", err
	}
	confirmation := &cliConfirmation{
		id: id, userID: record.UserID, sessionID: record.ID,
		scopeID: strings.TrimSpace(input.ScopeID), operationID: strings.TrimSpace(input.OperationID),
		targetType: strings.TrimSpace(input.TargetType), targetID: strings.TrimSpace(input.TargetID),
		paramsDigest: reauth.ParamsDigest(input.Params),
		method:       strings.ToUpper(strings.TrimSpace(input.Method)),
		path:         strings.TrimSpace(input.Path),
		bodyDigest:   canonicalJSONDigest(input.Body),
		required:     challenge.RequiredStrength, challengeID: challenge.ID,
		webCodeDigest: webDigest,
		state:         cliConfirmationPending, expiresAt: expiresAt, createdAt: now,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	s.confirmations[id] = confirmation
	return confirmation, webCode, nil
}

// verifyRequest 是 CLI 提交密码/动态码的请求；秘密只走请求体，不进 URL/参数。
type verifyRequest struct {
	ConfirmationID string `json:"confirmation_id"`
	Password       string `json:"password"`
	TOTPCode       string `json:"totp_code"`
}

// handleVerify 用真实 reauth.VerifyChallenge 校验密码/TOTP，成功后把一次性批准
// 令牌保存在服务端，并只向 CLI 返回一次性确认证明。
func (s *cliReauthService) handleVerify(writer http.ResponseWriter, request *http.Request,
	now time.Time) {
	record, failure := s.managementSession(request)
	if failure != nil {
		writeCLIError(writer, request, failure.status, string(failure.code), failure.message)
		return
	}
	var input verifyRequest
	if err := decodeCLIJSON(request, &input); err != nil {
		writeCLIError(writer, request, http.StatusBadRequest, "REQ_INVALID", "请求体无效")
		return
	}
	confirmation, failure := s.lookupOwned(request, record, input.ConfirmationID, now)
	if failure != nil {
		writeCLIError(writer, request, failure.status, string(failure.code), failure.message)
		return
	}
	if confirmation.state != cliConfirmationPending {
		writeCLIError(writer, request, http.StatusConflict, "CHALLENGE_INVALID",
			"确认记录当前状态不可验证")
		return
	}
	caller, err := reauth.UserCaller(record.UserID)
	if err != nil {
		writeCLIError(writer, request, http.StatusForbidden, "ACCESS_DENIED", "调用者无效")
		return
	}
	requestID := cliRequestID(request)
	caller, err = caller.WithRequestID(requestID)
	if err != nil {
		writeCLIError(writer, request, http.StatusBadRequest, "REQ_INVALID", "请求编号无效")
		return
	}
	grant, err := s.reauth.VerifyChallenge(request.Context(), caller, reauth.VerifyChallengeRequest{
		ChallengeID: confirmation.challengeID, Password: input.Password,
		TOTPCode: input.TOTPCode, RequestID: requestID,
	})
	if err != nil {
		code, status := cliReauthError(err)
		writeCLIError(writer, request, status, string(code), "再次认证未通过")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if confirmation.state != cliConfirmationPending {
		writeCLIError(writer, request, http.StatusConflict, "TOKEN_INVALID", "确认记录已被使用")
		return
	}
	confirmation.approvalToken = grant.Token
	confirmation.strength = grant.GrantedStrength
	confirmation.verifiedAt = now
	confirmation.authMethod = "password"
	if input.TOTPCode != "" {
		confirmation.authMethod = "password+totp"
	}
	confirmation.state = cliConfirmationVerified
	proof, proofDigest, proofErr := newCLIProof()
	if proofErr != nil {
		writeCLIError(writer, request, http.StatusInternalServerError, "INTERNAL_ERROR",
			"无法生成确认证明")
		return
	}
	confirmation.proofDigest = proofDigest
	confirmation.proofDelivered = true
	writeCLIJSON(writer, request, map[string]any{
		"confirmation_id":    confirmation.id,
		"confirmation_token": proof,
		"expires_at":         confirmation.expiresAt.Format(time.RFC3339),
		"method":             confirmation.authMethod,
	})
}

// status 返回确认状态；WebAuthn 完成后首次查询时返回一次性证明。
func (s *cliReauthService) handleStatus(writer http.ResponseWriter, request *http.Request,
	now time.Time) {
	record, failure := s.managementSession(request)
	if failure != nil {
		writeCLIError(writer, request, failure.status, string(failure.code), failure.message)
		return
	}
	confirmationID := strings.TrimSpace(request.URL.Query().Get("confirmation_id"))
	confirmation, failure := s.lookupOwned(request, record, confirmationID, now)
	if failure != nil {
		writeCLIError(writer, request, failure.status, string(failure.code), failure.message)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	payload := map[string]any{"confirmation_id": confirmation.id,
		"state":      string(confirmation.state),
		"expires_at": confirmation.expiresAt.Format(time.RFC3339)}
	if confirmation.state == cliConfirmationVerified && !confirmation.proofDelivered {
		proof, proofDigest, proofErr := newCLIProof()
		if proofErr != nil {
			delete(payload, "state")
			writeCLIError(writer, request, http.StatusInternalServerError, "INTERNAL_ERROR",
				"无法生成确认证明")
			return
		}
		confirmation.proofDigest = proofDigest
		confirmation.proofDelivered = true
		payload["confirmation_token"] = proof
		payload["method"] = confirmation.authMethod
	}
	writeCLIJSON(writer, request, payload)
}

// handleCancel 取消 pending 确认与底层 reauth 挑战；已确认/已使用/已过期的确认
// 不可取消（返回冲突），确保“取消后不执行”且不能借取消回滚已成立的事实。
func (s *cliReauthService) handleCancel(writer http.ResponseWriter, request *http.Request,
	now time.Time) {
	record, failure := s.managementSession(request)
	if failure != nil {
		writeCLIError(writer, request, failure.status, string(failure.code), failure.message)
		return
	}
	var input struct {
		ConfirmationID string `json:"confirmation_id"`
	}
	if err := decodeCLIJSON(request, &input); err != nil {
		writeCLIError(writer, request, http.StatusBadRequest, "REQ_INVALID", "请求体无效")
		return
	}
	confirmation, failure := s.lookupOwned(request, record, input.ConfirmationID, now)
	if failure != nil {
		writeCLIError(writer, request, failure.status, string(failure.code), failure.message)
		return
	}
	s.mu.Lock()
	if confirmation.state != cliConfirmationPending {
		s.mu.Unlock()
		writeCLIError(writer, request, http.StatusConflict, "TOKEN_INVALID", "确认记录当前状态不可取消")
		return
	}
	confirmation.state = cliConfirmationCancelled
	s.mu.Unlock()
	caller, err := reauth.UserCaller(record.UserID)
	if err == nil {
		caller, err = caller.WithRequestID(cliRequestID(request))
	}
	if err == nil {
		// 底层挑战可能已过期/已确认；取消失败不改变“本确认已取消”的事实。
		_ = s.reauth.CancelChallenge(request.Context(), caller, confirmation.challengeID)
	}
	writeCLIJSON(writer, request, map[string]any{"confirmation_id": confirmation.id,
		"cancelled": true, "state": string(confirmation.state)})
}

// handleBrowser 提供最小 WebAuthn 受控跳转页与断言接口（不降低认证要求）。
func (s *cliReauthService) handleBrowser(writer http.ResponseWriter, request *http.Request,
	relative string, now time.Time) {
	rest := strings.TrimPrefix(relative, "/reauth/browser/")
	segments := strings.Split(strings.Trim(rest, "/"), "/")
	if len(segments) == 0 || segments[0] == "" {
		writeCLIError(writer, request, http.StatusNotFound, "REQ_INVALID", "未知的确认浏览器端点")
		return
	}
	id := segments[0]
	action := ""
	if len(segments) > 1 {
		action = segments[1]
	}
	s.mu.Lock()
	confirmation := s.confirmations[id]
	s.mu.Unlock()
	if confirmation == nil || now.After(confirmation.expiresAt) {
		writeCLIError(writer, request, http.StatusNotFound, "CHALLENGE_INVALID", "确认记录不存在或已过期")
		return
	}
	code := strings.TrimSpace(request.URL.Query().Get("code"))
	switch action {
	case "":
		if hashCLIProof(code) != confirmation.webCodeDigest {
			writeCLIError(writer, request, http.StatusForbidden, "ACCESS_DENIED", "浏览器确认码无效")
			return
		}
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		_, _ = io.WriteString(writer, cliBrowserPage)
	case "options":
		s.handleBrowserOptions(writer, request, confirmation, code)
	case "finish":
		s.handleBrowserFinish(writer, request, confirmation, code, now)
	default:
		writeCLIError(writer, request, http.StatusNotFound, "REQ_INVALID", "未知的确认浏览器端点")
	}
}

// handleBrowserOptions 为真实 Passkey 第二步认证生成 WebAuthn 选项。
func (s *cliReauthService) handleBrowserOptions(writer http.ResponseWriter,
	request *http.Request, confirmation *cliConfirmation, code string) {
	if s.passkeys == nil {
		writeCLIError(writer, request, http.StatusNotFound, "MFA_REQUIRED", "Passkey 未启用")
		return
	}
	if hashCLIProof(code) != confirmation.webCodeDigest {
		writeCLIError(writer, request, http.StatusForbidden, "ACCESS_DENIED", "浏览器确认码无效")
		return
	}
	start, err := s.passkeys.BeginSecondFactor(request.Context(), confirmation.userID,
		confirmation.id, cliRequestID(request))
	if err != nil {
		writeCLIError(writer, request, http.StatusForbidden, "MFA_REQUIRED", "无法开始 Passkey 认证")
		return
	}
	writeCLIJSON(writer, request, map[string]any{"ceremony_id": start.CeremonyID,
		"public_key": json.RawMessage(start.PublicKey),
		"expires_at": start.ExpiresAt.Format(time.RFC3339)})
}

// handleBrowserFinish 校验真实 WebAuthn 断言并标记确认已验证（强认证事实）。
func (s *cliReauthService) handleBrowserFinish(writer http.ResponseWriter,
	request *http.Request, confirmation *cliConfirmation, code string, now time.Time) {
	if s.passkeys == nil {
		writeCLIError(writer, request, http.StatusNotFound, "MFA_REQUIRED", "Passkey 未启用")
		return
	}
	if hashCLIProof(code) != confirmation.webCodeDigest {
		writeCLIError(writer, request, http.StatusForbidden, "ACCESS_DENIED", "浏览器确认码无效")
		return
	}
	var input struct {
		CeremonyID string          `json:"ceremony_id"`
		Response   json.RawMessage `json:"response"`
	}
	if err := decodeCLIJSON(request, &input); err != nil {
		writeCLIError(writer, request, http.StatusBadRequest, "REQ_INVALID", "请求体无效")
		return
	}
	result, err := s.passkeys.FinishSecondFactor(request.Context(), passkey.SecondFactorFinishRequest{
		CeremonyID: input.CeremonyID, ContextID: confirmation.id,
		Response: input.Response, RequestID: cliRequestID(request),
	})
	if err != nil {
		writeCLIError(writer, request, http.StatusForbidden, "AUTH_FAILED", "Passkey 认证失败")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if confirmation.state != cliConfirmationPending || now.After(confirmation.expiresAt) {
		writeCLIError(writer, request, http.StatusConflict, "CHALLENGE_INVALID", "确认记录当前状态不可完成")
		return
	}
	confirmation.state = cliConfirmationVerified
	confirmation.authMethod = "webauthn"
	confirmation.strength = policy.StrengthStrong
	confirmation.verifiedAt = result.VerifiedAt
	if confirmation.verifiedAt.IsZero() {
		confirmation.verifiedAt = now
	}
	writeCLIJSON(writer, request, map[string]any{"confirmed": true,
		"method": confirmation.authMethod})
}

// authorizeConfirmation 在管理 API 写请求上校验/消费证明，并把真实 reauth 信号
// 注入请求上下文；任何不匹配都拒绝且不注入信号。
func (s *cliReauthService) authorizeConfirmation(request *http.Request,
	token string) (context.Context, *cliReauthFailure) {
	now := s.now().UTC()
	record, failure := s.managementSession(request)
	if failure != nil {
		return request.Context(), failure
	}
	body, err := readAndRestoreBody(request)
	if err != nil {
		return request.Context(), &cliReauthFailure{status: http.StatusBadRequest,
			code: reauth.CodeReqInvalid, message: "无法读取请求体"}
	}
	relative := request.URL.Path
	// 本处理器与管理 API 包装在同一层：请求路径已由宿主剥离部署前缀，含管理 API
	// 前缀；去掉后与 CLI 绑定的相对路径比较。
	relative = strings.TrimPrefix(relative, s.adminPrefix)
	if relative == "" {
		relative = "/"
	}
	bodyDigest := canonicalJSONDigest(string(body))
	proofDigest := hashCLIProof(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	var matched *cliConfirmation
	for _, confirmation := range s.confirmations {
		if confirmation.proofDigest == proofDigest {
			matched = confirmation
			break
		}
	}
	if matched == nil || matched.state != cliConfirmationVerified ||
		now.After(matched.expiresAt) {
		return request.Context(), &cliReauthFailure{status: http.StatusForbidden,
			code: reauth.CodeTokenInvalid, message: "确认证明无效或已过期"}
	}
	if matched.userID != record.UserID || matched.sessionID != record.ID {
		return request.Context(), &cliReauthFailure{status: http.StatusForbidden,
			code: reauth.CodeTokenInvalid, message: "确认证明与当前会话不匹配"}
	}
	if matched.method != request.Method || matched.path != relative ||
		matched.bodyDigest != bodyDigest {
		return request.Context(), &cliReauthFailure{status: http.StatusForbidden,
			code: reauth.CodeTokenInvalid, message: "确认证明与当前请求不匹配"}
	}
	// 一次性：先消费证明，再注入信号；下游失败也不会留下可重复使用的证明。
	matched.state = cliConfirmationConsumed
	delete(s.confirmations, matched.id)
	if matched.approvalToken != "" {
		// 只传一次性批准令牌：目标/参数/主体/操作绑定由 reauth.consumeApproval
		// 重新核对并原子消费；不额外塞入“直接验证事实”，否则过宽的信号可能让
		// 策略跳过批准绑定校验。
		signals := reauth.Signals{ApprovalToken: matched.approvalToken, Confirmed: true}
		return reauth.WithSignals(request.Context(), signals), nil
	}
	if matched.strength == policy.StrengthStrong {
		signals := reauth.Signals{VerifiedAt: matched.verifiedAt,
			Strength: policy.StrengthStrong, Complete: true, Confirmed: true}
		return reauth.WithSignals(request.Context(), signals), nil
	}
	return request.Context(), &cliReauthFailure{status: http.StatusForbidden,
		code: reauth.CodeTokenInvalid, message: "确认证明缺少可用的认证事实"}
}

// managementSession 校验 Bearer 管理会话；普通会话/受限会话一律拒绝。
func (s *cliReauthService) managementSession(request *http.Request) (session.Session,
	*cliReauthFailure) {
	secret := cliBearerSecret(request)
	if secret == "" {
		return session.Session{}, &cliReauthFailure{status: http.StatusUnauthorized,
			code: reauth.CodeAuthFailed, message: "缺少管理会话"}
	}
	record, err := s.sessions.AuthorizeManagement(request.Context(), secret)
	if err != nil || record.ID == "" {
		if err == nil {
			err = fmt.Errorf("会话无效")
		}
		return session.Session{}, &cliReauthFailure{status: http.StatusForbidden,
			code: reauth.CodeReauthRequired, message: "需要真实管理会话与近期强认证"}
	}
	return record, nil
}

// lookupOwned 读取确认记录并核对管理会话/主体归属。
func (s *cliReauthService) lookupOwned(request *http.Request, record session.Session,
	id string, now time.Time) (*cliConfirmation, *cliReauthFailure) {
	id = strings.TrimSpace(id)
	if !strings.HasPrefix(id, "cfm_") || len(id) != len("cfm_")+32 {
		return nil, &cliReauthFailure{status: http.StatusBadRequest,
			code: reauth.CodeReqInvalid, message: "确认编号格式无效"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	confirmation := s.confirmations[id]
	if confirmation == nil || confirmation.userID != record.UserID ||
		confirmation.sessionID != record.ID {
		return nil, &cliReauthFailure{status: http.StatusNotFound,
			code: reauth.CodeChallengeInvalid, message: "确认记录不存在"}
	}
	if now.After(confirmation.expiresAt) {
		delete(s.confirmations, id)
		return nil, &cliReauthFailure{status: http.StatusGone,
			code: reauth.CodeChallengeInvalid, message: "确认记录已过期"}
	}
	return confirmation, nil
}

// pruneLocked 清理过期记录（调用方必须持有锁）。
func (s *cliReauthService) pruneLocked(now time.Time) {
	for id, confirmation := range s.confirmations {
		if now.After(confirmation.expiresAt) ||
			confirmation.state == cliConfirmationConsumed {
			delete(s.confirmations, id)
		}
	}
}

// ===== 小工具 =====

// cliBrowserPage 是受控跳转的最小页面：调用真实 WebAuthn 断言，完成后提示回到终端。
const cliBrowserPage = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>CLI 敏感操作确认</title>
<meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body>
<h1>CLI 敏感操作确认</h1>
<p>请在下方使用 Passkey 完成本次操作的强认证；完成后可回到终端继续。</p>
<p id="status">等待开始…</p>
<button id="start" type="button">使用 Passkey 确认</button>
<pre id="detail"></pre>
<script>
(function () {
  var confirmationID = %q;
  var code = new URLSearchParams(location.search).get("code") || "";
  function post(path, body) {
    return fetch(path + "?code=" + encodeURIComponent(code), {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify(body), credentials: "same-origin"
    }).then(function (response) { return response.json(); });
  }
  document.getElementById("start").addEventListener("click", function () {
    var status = document.getElementById("status");
    status.textContent = "正在准备 Passkey 认证…";
    post("/reauth/browser/" + confirmationID + "/options", {}).then(function (result) {
      if (!result.ok) { throw new Error((result.error && result.error.message) || "无法开始"); }
      var data = result.data;
      var publicKey = data.public_key;
      publicKey.challenge = Uint8Array.from(atob(publicKey.challenge), function (c) { return c.charCodeAt(0); });
      (publicKey.allowCredentials || []).forEach(function (item) {
        item.id = Uint8Array.from(atob(item.id), function (c) { return c.charCodeAt(0); });
      });
      return navigator.credentials.get({publicKey: publicKey}).then(function (credential) {
        var response = credential.response;
        var payload = {
          id: credential.id, rawId: btoa(String.fromCharCode.apply(null, new Uint8Array(credential.rawId))),
          type: credential.type,
          response: {
            clientDataJSON: btoa(String.fromCharCode.apply(null, new Uint8Array(response.clientDataJSON))),
            authenticatorData: btoa(String.fromCharCode.apply(null, new Uint8Array(response.authenticatorData))),
            signature: btoa(String.fromCharCode.apply(null, new Uint8Array(response.signature))),
            userHandle: response.userHandle ? btoa(String.fromCharCode.apply(null, new Uint8Array(response.userHandle))) : null
          }
        };
        return post("/reauth/browser/" + confirmationID + "/finish",
          {ceremony_id: data.ceremony_id, response: payload});
      });
    }).then(function (result) {
      if (!result.ok) { throw new Error((result.error && result.error.message) || "认证未通过"); }
      document.getElementById("status").textContent = "确认完成，可以回到终端继续。";
      document.getElementById("start").disabled = true;
    }).catch(function (error) {
      document.getElementById("status").textContent = "认证未完成：" + error.message;
    });
  });
})();
</script></body></html>`

// decodeCLIJSON 解析上限受控的 JSON 请求体。
func decodeCLIJSON(request *http.Request, target any) error {
	limited := io.LimitReader(request.Body, cliMaxBodyBytes+1)
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return nil
}

// readAndRestoreBody 读取请求体并恢复，供中间件绑定校验后下游继续读取。
func readAndRestoreBody(request *http.Request) ([]byte, error) {
	if request.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, cliMaxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > cliMaxBodyBytes {
		return nil, fmt.Errorf("请求体过大")
	}
	request.Body = io.NopCloser(strings.NewReader(string(body)))
	return body, nil
}

// cliBearerSecret 从 Authorization: Bearer 读取会话秘密。
func cliBearerSecret(request *http.Request) string {
	header := strings.TrimSpace(request.Header.Get("Authorization"))
	if len(header) < 7 || !strings.EqualFold(header[:7], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(header[7:])
}

// cliRequestID 返回合法请求编号：优先使用客户端 X-Request-ID，否则生成。
func cliRequestID(request *http.Request) string {
	candidate := strings.TrimSpace(request.Header.Get("X-Request-ID"))
	if account.ValidateRequestID(candidate) == nil {
		return candidate
	}
	id, err := newCLIID("req_cli_")
	if err != nil {
		return "req_cli_0123456789abcdef0123456789abcdef"
	}
	return id
}

// cliReauthError 把 reauth 领域错误映射为稳定 HTTP 状态与错误码。
func cliReauthError(err error) (reauth.ErrorCode, int) {
	code := reauth.CodeOf(err)
	switch code {
	case reauth.CodeReqInvalid:
		return code, http.StatusBadRequest
	case reauth.CodeAuthFailed, reauth.CodeChallengeInvalid:
		return code, http.StatusForbidden
	case reauth.CodeReauthRequired, reauth.CodeMFARequired:
		return code, http.StatusForbidden
	case reauth.CodeRateLimited:
		return code, http.StatusTooManyRequests
	case reauth.CodeAccessDenied:
		return code, http.StatusForbidden
	case reauth.CodeDBUnavailable:
		return code, http.StatusServiceUnavailable
	default:
		return reauth.CodeInternalError, http.StatusInternalServerError
	}
}

// writeCLIJSON 输出 {ok:true,data:...} 外壳（与 adminapi 契约一致），不写秘密。
func writeCLIJSON(writer http.ResponseWriter, request *http.Request, data any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(writer).Encode(map[string]any{"ok": true,
		"request_id": cliRequestID(request), "data": data})
}

// writeCLIError 输出统一失败外壳；message 不含证明/令牌/内部路径。
func writeCLIError(writer http.ResponseWriter, request *http.Request, status int,
	code, message string) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{"ok": false,
		"request_id": cliRequestID(request), "code": code, "message": message})
}

// canonicalJSONDigest 计算 JSON 请求体的规范化摘要：空体为全零；否则解析后按 Go
// encoding/json 的稳定键顺序重新编码再 SHA-256，使等价 JSON（空白/键顺序不同）得到
// 同一摘要，避免 CLI 传参与实际发送字节的格式化差异被误判为不同操作。
func canonicalJSONDigest(raw string) [32]byte {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return [32]byte{}
	}
	var value any
	if err := json.Unmarshal([]byte(trimmed), &value); err != nil {
		return sha256.Sum256([]byte(trimmed))
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return sha256.Sum256([]byte(trimmed))
	}
	return sha256.Sum256(encoded)
}

// newCLIID 生成带前缀的 128 位随机 ID。
func newCLIID(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(raw[:]), nil
}

// newCLIProof 生成一次性证明与其 SHA-256 摘要。
func newCLIProof() (string, [32]byte, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", [32]byte{}, err
	}
	text := hex.EncodeToString(raw[:])
	return text, hashCLIProof(text), nil
}

// hashCLIProof 计算证明摘要（只保存/比较摘要）。
func hashCLIProof(value string) [32]byte {
	return sha256.Sum256([]byte(strings.TrimSpace(value)))
}

// bodyDigestOf 返回 body 摘要（供绑定比较）。
func bodyDigestOf(digest [32]byte) [32]byte { return digest }

// cliAdminPrefixFromPath 从完整路径中识别管理 API 前缀（以 /admin/ 或配置前缀开头）。
func cliAdminPrefixFromPath(path string) string {
	index := strings.Index(path, "/reauth/")
	if index > 0 {
		return path[:index]
	}
	if strings.HasPrefix(path, "/admin/") {
		trimmed := strings.TrimPrefix(path, "/admin")
		if idx := strings.Index(trimmed, "/v1"); idx == 0 {
			return "/admin/v1"
		}
	}
	return ""
}

// login 包引用用于错误码登记测试（保持依赖显式）。
var _ = errs.CodeReauthRequired
