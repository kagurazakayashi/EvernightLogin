package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/managedapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// Options 构造业务托管管理 HTTP Handler。
type Options struct {
	Service      Service
	Sessions     SessionService
	Idempotency  IdempotencyStore
	BasePath     string
	MaxBodyBytes int64
	Now          func() time.Time
	Logger       *slog.Logger
	Random       io.Reader
	// IdempotencyTTL 是完成响应可重放窗口；默认 24 小时。
	IdempotencyTTL time.Duration
}

// Handler 是业务托管管理 API handler；并发安全，不启动后台任务。
type Handler struct {
	basePath       string
	service        Service
	sessions       SessionService
	idempotency    IdempotencyStore
	maxBodyBytes   int64
	now            func() time.Time
	logger         *slog.Logger
	random         io.Reader
	idempotencyTTL time.Duration
}

// New 校验依赖并构造 Handler；错误时不返回半可用 handler。
func New(options Options) (*Handler, error) {
	if options.Service == nil || options.Sessions == nil || options.Idempotency == nil {
		return nil, errors.New("managed API handler 缺少 service/session/idempotency 依赖")
	}
	basePath := strings.TrimSpace(options.BasePath)
	if basePath == "" {
		basePath = DefaultBasePath
	}
	if !validBasePath(basePath) {
		return nil, errors.New("managed API base path 非法")
	}
	if options.MaxBodyBytes <= 0 {
		options.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if options.MaxBodyBytes > 16<<20 {
		return nil, errors.New("managed API body 上限过大")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.IdempotencyTTL <= 0 {
		options.IdempotencyTTL = 24 * time.Hour
	}
	return &Handler{basePath: basePath, service: options.Service, sessions: options.Sessions,
		idempotency: options.Idempotency, maxBodyBytes: options.MaxBodyBytes,
		now: options.Now, logger: options.Logger, random: options.Random,
		idempotencyTTL: options.IdempotencyTTL}, nil
}

// BasePath 返回 handler 实际挂载前缀。
func (h *Handler) BasePath() string { return h.basePath }

// ServeHTTP 完成认证、版本/request_id、幂等与路由分发。
func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	requestID := h.requestID(request)
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	if requestID == "" {
		h.writeError(writer, "", http.StatusBadRequest, invalidRequest("请求编号非法"))
		return
	}
	if strings.TrimSpace(request.Header.Get("X-Evernight-API-Version")) != APIVersion {
		h.writeError(writer, requestID, http.StatusBadRequest, invalidRequest("缺少或不支持的 API 版本"))
		return
	}
	path, appID, route, ok := h.parsePath(request.URL.Path)
	if !ok {
		h.writeError(writer, requestID, http.StatusNotFound, APIError{HTTPStatus: http.StatusNotFound,
			Code: "REQ_INVALID", Message: "不存在的托管 API 路由"})
		return
	}
	if values := request.URL.Query(); len(values) > 0 {
		for key := range values {
			switch strings.ToLower(key) {
			case "app_id", "application_id":
				h.writeError(writer, requestID, http.StatusBadRequest,
					invalidRequest("应用标识不能来自查询参数"))
				return
			}
		}
	}
	principal, identity, authErr := h.authenticate(request, appID)
	if authErr.HTTPStatus != 0 {
		h.writeError(writer, requestID, authErr.HTTPStatus, authErr)
		return
	}
	meta := managedapi.Meta{APIVersion: managedapi.APIVersion, RequestID: requestID}
	write := request.Method != http.MethodGet
	var body []byte
	if write {
		// DELETE 允许空 body；POST/PATCH 必须 JSON。
		if request.Method != http.MethodDelete {
			if request.Header.Get("Content-Type") == "" ||
				!strings.HasPrefix(strings.ToLower(request.Header.Get("Content-Type")), "application/json") {
				h.writeError(writer, requestID, http.StatusBadRequest, invalidRequest("写请求必须使用 application/json"))
				return
			}
			var readErr APIError
			body, readErr = h.readBody(request)
			if readErr.HTTPStatus != 0 {
				h.writeError(writer, requestID, readErr.HTTPStatus, readErr)
				return
			}
		} else if request.ContentLength > 0 {
			var readErr APIError
			body, readErr = h.readBody(request)
			if readErr.HTTPStatus != 0 {
				h.writeError(writer, requestID, readErr.HTTPStatus, readErr)
				return
			}
		}
	}
	// 写请求要求幂等键；幂等作用域绑定应用/主体/键，绝不跨应用复用。
	var idemScope IdempotencyScope
	requestHash := ""
	if write {
		key := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
		if !validIdempotencyKey(key) {
			h.writeError(writer, requestID, http.StatusBadRequest, invalidRequest("写请求必须提供合法 Idempotency-Key"))
			return
		}
		idemScope = IdempotencyScope{ApplicationID: appID, PrincipalKind: identity.kind,
			PrincipalID: identity.id, Key: key}
		hash := sha256.Sum256([]byte(request.Method + "\n" + path + "\n" + string(body)))
		requestHash = hex.EncodeToString(hash[:])
		stored, conflictFound, idemErr := h.idempotency.Begin(request.Context(), idemScope,
			request.Method+" "+path, requestHash, h.now(), h.now().Add(h.idempotencyTTL))
		if idemErr != nil {
			h.writeError(writer, requestID, http.StatusServiceUnavailable, unavailable("幂等记录不可用"))
			return
		}
		if conflictFound {
			h.writeError(writer, requestID, http.StatusConflict, conflict("相同幂等键的请求正在进行或请求内容不同"))
			return
		}
		if stored != nil {
			writer.Header().Set("Idempotent-Replayed", "true")
			writer.WriteHeader(stored.Status)
			_, _ = writer.Write(stored.Body)
			return
		}
	}
	status, responseData, err := h.execute(request.Context(), principal, meta, route,
		request.Method, request.URL.Query(), body)
	if err != nil {
		if write {
			_ = h.idempotency.Abort(request.Context(), idemScope)
		}
		apiErr := asAPIError(err)
		h.writeError(writer, requestID, apiErr.HTTPStatus, apiErr)
		return
	}
	payload := marshalResponse(Envelope{RequestID: requestID, APIVersion: APIVersion, Data: responseData})
	if write {
		if completeErr := h.idempotency.Complete(request.Context(), idemScope, status, payload); completeErr != nil {
			// 领域操作已成功但幂等状态无法记录：返回 503 让调用方按未确认处理，
			// 不伪造“可安全重试”的成功语义；记录冲突由 apply 层/运维核对。
			h.logger.Error("托管 API 幂等完成记录失败", "error_category", "idempotency_complete_failed")
			h.writeError(writer, requestID, http.StatusServiceUnavailable, unavailable("操作状态无法持久记录"))
			return
		}
	}
	writer.WriteHeader(status)
	_, _ = writer.Write(payload)
}

// identity 是认证后的幂等主体标识；不包含会话秘密。
type identity struct {
	kind string
	id   string
}

// authenticate 只接受 Authorization: Bearer 用户会话或 Basic/证书服务身份。
func (h *Handler) authenticate(request *http.Request, appID string) (managedapi.Principal,
	identity, APIError) {
	authorization := strings.TrimSpace(request.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(authorization), "bearer ") {
		secret := strings.TrimSpace(authorization[len("bearer "):])
		if secret == "" || len(secret) > 512 {
			return managedapi.Principal{}, identity{}, unauthorized("用户会话缺失或无效")
		}
		record, err := h.sessions.Validate(request.Context(), secret)
		if err != nil {
			return managedapi.Principal{}, identity{}, unauthorized("用户会话无效或已过期")
		}
		if record.Kind != session.KindNormal || !record.IsNormal() {
			return managedapi.Principal{}, identity{}, accessDenied("需要完整认证会话")
		}
		if record.AppID != "" && record.AppID != appID {
			return managedapi.Principal{}, identity{}, APIError{HTTPStatus: http.StatusForbidden,
				Code: string(managedapi.CodeAppScopeMismatch), Message: "会话所属应用与请求应用不一致"}
		}
		return managedapi.UserPrincipal(secret, appID), identity{kind: "user", id: record.UserID}, APIError{}
	}
	if username, password, ok := request.BasicAuth(); ok {
		clientID := strings.TrimSpace(username)
		if clientID == "" || clientID != appID || !app.ValidApplicationID(clientID) {
			return managedapi.Principal{}, identity{}, APIError{HTTPStatus: http.StatusForbidden,
				Code: string(managedapi.CodeAppScopeMismatch), Message: "客户端身份与请求应用不一致"}
		}
		if strings.TrimSpace(password) == "" {
			return managedapi.Principal{}, identity{}, unauthorized("客户端密钥缺失")
		}
		return managedapi.ServicePrincipal(clientID, password, ""), identity{kind: "service", id: clientID}, APIError{}
	}
	// mTLS：只使用 TLS 层已验证的对端叶子证书；不接受请求头自报证书。
	if request.TLS != nil && len(request.TLS.PeerCertificates) > 0 {
		certificatePEM := encodeCertificate(request.TLS.PeerCertificates[0].Raw)
		if !app.ValidApplicationID(appID) {
			return managedapi.Principal{}, identity{}, unauthorized("应用标识无效")
		}
		return managedapi.ServicePrincipal(appID, "", certificatePEM),
			identity{kind: "service", id: appID}, APIError{}
	}
	return managedapi.Principal{}, identity{}, unauthorized("缺少用户会话或应用客户端认证")
}

// encodeCertificate 把 DER 叶子证书编码为 PEM；只使用 TLS 已验证证书，不解析用户输入。
func encodeCertificate(der []byte) string {
	if len(der) == 0 {
		return ""
	}
	return "-----BEGIN CERTIFICATE-----\n" + base64.StdEncoding.EncodeToString(der) +
		"\n-----END CERTIFICATE-----\n"
}

// route 标识解析后的操作。
type route struct {
	operation string
	userID    string
	action    string
}

// parsePath 解析 /v1 之后的路径并校验 app_id 只来自路径。
func (h *Handler) parsePath(rawPath string) (string, string, route, bool) {
	if !strings.HasPrefix(rawPath, h.basePath+"/") || strings.Contains(rawPath, "//") ||
		strings.HasSuffix(rawPath, "/") {
		return "", "", route{}, false
	}
	relative := strings.TrimPrefix(rawPath, h.basePath+"/")
	parts := strings.Split(relative, "/")
	if len(parts) < 2 || parts[0] != "applications" {
		return "", "", route{}, false
	}
	appID := parts[1]
	if !app.ValidApplicationID(appID) {
		return "", "", route{}, false
	}
	if len(parts) == 2 {
		return rawPath, appID, route{operation: "application.get"}, true
	}
	resource := parts[2]
	if len(parts) == 3 {
		switch resource {
		case "members":
			return rawPath, appID, route{operation: "members.list"}, true
		case "users":
			return rawPath, appID, route{operation: "users.create_with_membership"}, true
		case "groups":
			return rawPath, appID, route{operation: "groups.list"}, true
		case "roles":
			return rawPath, appID, route{operation: "roles.list"}, true
		case "permissions":
			return rawPath, appID, route{operation: "permissions.list"}, true
		}
		return "", "", route{}, false
	}
	id := parts[3]
	switch resource {
	case "members":
		if !account.ValidUserID(id) {
			return "", "", route{}, false
		}
		if len(parts) == 4 {
			return rawPath, appID, route{operation: "members.item", userID: id}, true
		}
		if len(parts) == 5 {
			switch parts[4] {
			case "enable", "disable", "remove":
				return rawPath, appID, route{operation: "members." + parts[4], userID: id}, true
			}
		}
	case "groups":
		if len(parts) == 4 {
			return rawPath, appID, route{operation: "groups.item", userID: id}, true
		}
		if len(parts) == 5 && parts[4] == "members" {
			return rawPath, appID, route{operation: "groups.members", userID: id}, true
		}
	case "roles":
		if len(parts) == 4 {
			return rawPath, appID, route{operation: "roles.item", userID: id}, true
		}
		if len(parts) == 5 {
			switch parts[4] {
			case "permissions":
				return rawPath, appID, route{operation: "roles.permissions", userID: id}, true
			case "assignments":
				return rawPath, appID, route{operation: "roles.assignments", userID: id}, true
			case "assign", "revoke":
				return rawPath, appID, route{operation: "roles." + parts[4], userID: id}, true
			}
		}
	case "permissions":
		if len(parts) == 4 {
			return rawPath, appID, route{operation: "permissions.item", userID: id}, true
		}
		if len(parts) == 5 {
			switch parts[4] {
			case "enable", "disable":
				return rawPath, appID, route{operation: "permissions." + parts[4], userID: id}, true
			}
		}
	}
	return "", "", route{}, false
}

// execute 校验 HTTP 方法并调用 managedapi；只做 DTO 映射。
func (h *Handler) execute(ctx context.Context, principal managedapi.Principal,
	meta managedapi.Meta, target route, method string, query url.Values,
	body []byte) (int, any, error) {
	switch target.operation {
	case "application.get":
		if method != http.MethodGet {
			return 0, nil, invalidRequest("方法不允许")
		}
		view, err := h.service.GetApplication(ctx, principal, managedapi.GetApplicationRequest{Meta: meta})
		return http.StatusOK, view, err
	case "members.list":
		if method != http.MethodGet {
			return 0, nil, invalidRequest("方法不允许")
		}
		limit, err := parsePositive(query.Get("limit"), 0)
		if err != nil {
			return 0, nil, invalidRequest("limit 非法")
		}
		offset, err := parsePositive(query.Get("offset"), 0)
		if err != nil {
			return 0, nil, invalidRequest("offset 非法")
		}
		result, listErr := h.service.ListMembers(ctx, principal, managedapi.ListMembersRequest{
			ListMeta:   managedapi.ListMeta{Meta: meta, Limit: limit, Offset: offset},
			Status:     strings.TrimSpace(query.Get("status")),
			Sort:       strings.TrimSpace(query.Get("sort")),
			Descending: query.Get("desc") == "1" || strings.EqualFold(query.Get("desc"), "true"),
		})
		return http.StatusOK, result, listErr
	case "members.item":
		switch method {
		case http.MethodGet:
			view, err := h.service.GetMember(ctx, principal, managedapi.GetMemberRequest{
				Meta: meta, UserID: target.userID})
			return http.StatusOK, view, err
		case http.MethodPatch:
			var payload updateProfilePayload
			if err := decodeStrict(body, &payload); err != nil {
				return 0, nil, invalidRequest("请求体字段或 JSON 非法")
			}
			view, err := h.service.UpdateMemberProfile(ctx, principal,
				managedapi.UpdateMemberProfileRequest{Meta: meta, UserID: target.userID,
					ExpectedRowVersion: payload.ExpectedRowVersion, DisplayName: payload.DisplayName,
					Title: payload.Title, Note: payload.Note})
			return http.StatusOK, view, err
		default:
			return 0, nil, invalidRequest("方法不允许")
		}
	case "members.enable", "members.disable":
		if method != http.MethodPost {
			return 0, nil, invalidRequest("方法不允许")
		}
		var payload memberActionPayload
		if err := decodeStrict(body, &payload); err != nil {
			return 0, nil, invalidRequest("请求体字段或 JSON 非法")
		}
		view, err := h.service.UpdateMemberStatus(ctx, principal,
			managedapi.MemberActionRequest{Meta: meta, UserID: target.userID,
				ExpectedRowVersion: payload.ExpectedRowVersion},
			target.operation == "members.enable")
		return http.StatusOK, view, err
	case "members.remove":
		if method != http.MethodPost {
			return 0, nil, invalidRequest("方法不允许")
		}
		var payload memberActionPayload
		if err := decodeStrict(body, &payload); err != nil {
			return 0, nil, invalidRequest("请求体字段或 JSON 非法")
		}
		err := h.service.RemoveMember(ctx, principal, managedapi.MemberActionRequest{
			Meta: meta, UserID: target.userID, ExpectedRowVersion: payload.ExpectedRowVersion})
		return http.StatusNoContent, nil, err
	case "users.create_with_membership":
		if method != http.MethodPost {
			return 0, nil, invalidRequest("方法不允许")
		}
		var payload createUserPayload
		if err := decodeStrict(body, &payload); err != nil {
			return 0, nil, invalidRequest("请求体字段或 JSON 非法")
		}
		view, err := h.service.CreateUserWithMembership(ctx, principal,
			managedapi.CreateUserRequest{Meta: meta, Username: payload.Username,
				Nickname: payload.Nickname, Biography: payload.Biography})
		return http.StatusOK, view, err
	case "groups.list":
		switch method {
		case http.MethodGet:
			limit, offset, queryErr := listPaging(query, 10, 0)
			if queryErr.HTTPStatus != 0 {
				return 0, nil, queryErr
			}
			result, err := h.service.ListGroups(ctx, principal,
				managedapi.ListGroupsRequest{ListMeta: managedapi.ListMeta{Meta: meta,
					Limit: limit, Offset: offset}})
			return http.StatusOK, result, err
		case http.MethodPost:
			var payload groupCreatePayload
			if err := decodeStrict(body, &payload); err != nil {
				return 0, nil, invalidRequest("请求体字段或 JSON 非法")
			}
			view, err := h.service.CreateGroup(ctx, principal,
				managedapi.CreateGroupRequest{Meta: meta, GroupKey: payload.Key,
					Name: payload.Name, Description: payload.Description})
			return http.StatusOK, view, err
		default:
			return 0, nil, invalidRequest("方法不允许")
		}
	case "groups.item":
		switch method {
		case http.MethodGet:
			view, err := h.service.GetGroup(ctx, principal,
				managedapi.GetGroupRequest{Meta: meta, GroupID: target.userID})
			return http.StatusOK, view, err
		case http.MethodPatch:
			var payload groupUpdatePayload
			if err := decodeStrict(body, &payload); err != nil {
				return 0, nil, invalidRequest("请求体字段或 JSON 非法")
			}
			view, err := h.service.UpdateGroup(ctx, principal,
				managedapi.UpdateGroupRequest{Meta: meta, GroupID: target.userID,
					Name: payload.Name, Description: payload.Description})
			return http.StatusOK, view, err
		case http.MethodDelete:
			err := h.service.DeleteGroup(ctx, principal,
				managedapi.DeleteGroupRequest{Meta: meta, GroupID: target.userID})
			return http.StatusNoContent, nil, err
		default:
			return 0, nil, invalidRequest("方法不允许")
		}
	case "groups.members":
		switch method {
		case http.MethodGet:
			limit, offset, queryErr := listPaging(query, 10, 0)
			if queryErr.HTTPStatus != 0 {
				return 0, nil, queryErr
			}
			result, err := h.service.ListGroupMembers(ctx, principal,
				managedapi.ListGroupMembersRequest{ListMeta: managedapi.ListMeta{Meta: meta,
					Limit: limit, Offset: offset}, GroupID: target.userID})
			return http.StatusOK, result, err
		case http.MethodPost, http.MethodDelete:
			var payload groupMembersPayload
			if err := decodeStrict(body, &payload); err != nil {
				return 0, nil, invalidRequest("请求体字段或 JSON 非法")
			}
			err := h.service.UpdateGroupMembers(ctx, principal,
				managedapi.GroupMembersRequest{Meta: meta, GroupID: target.userID,
					UserIDs: payload.UserIDs}, method == http.MethodPost)
			return http.StatusOK, map[string]any{"changed": true}, err
		default:
			return 0, nil, invalidRequest("方法不允许")
		}
	case "roles.list":
		switch method {
		case http.MethodGet:
			limit, offset, queryErr := listPaging(query, 10, 0)
			if queryErr.HTTPStatus != 0 {
				return 0, nil, queryErr
			}
			result, err := h.service.ListRoles(ctx, principal,
				managedapi.ListRolesRequest{ListMeta: managedapi.ListMeta{Meta: meta,
					Limit: limit, Offset: offset}})
			return http.StatusOK, result, err
		case http.MethodPost:
			var payload roleCreatePayload
			if err := decodeStrict(body, &payload); err != nil {
				return 0, nil, invalidRequest("请求体字段或 JSON 非法")
			}
			view, err := h.service.CreateRole(ctx, principal,
				managedapi.CreateRoleRequest{Meta: meta, Key: payload.Key,
					Name: payload.Name, Description: payload.Description, Limits: payload.Limits})
			return http.StatusOK, view, err
		default:
			return 0, nil, invalidRequest("方法不允许")
		}
	case "roles.item":
		switch method {
		case http.MethodGet:
			view, err := h.service.GetRole(ctx, principal,
				managedapi.GetRoleRequest{Meta: meta, RoleID: target.userID})
			return http.StatusOK, view, err
		case http.MethodPatch:
			var payload roleUpdatePayload
			if err := decodeStrict(body, &payload); err != nil {
				return 0, nil, invalidRequest("请求体字段或 JSON 非法")
			}
			view, err := h.service.UpdateRole(ctx, principal,
				managedapi.UpdateRoleRequest{Meta: meta, RoleID: target.userID,
					Name: payload.Name, Description: payload.Description, Limits: payload.Limits})
			return http.StatusOK, view, err
		case http.MethodDelete:
			err := h.service.DeleteRole(ctx, principal,
				managedapi.DeleteRoleRequest{Meta: meta, RoleID: target.userID})
			return http.StatusNoContent, nil, err
		default:
			return 0, nil, invalidRequest("方法不允许")
		}
	case "roles.permissions":
		if method != http.MethodGet {
			return 0, nil, invalidRequest("方法不允许")
		}
		items, err := h.service.ListRolePermissions(ctx, principal,
			managedapi.ListRoleSubresourceRequest{Meta: meta, RoleID: target.userID})
		return http.StatusOK, items, err
	case "roles.assignments":
		if method != http.MethodGet {
			return 0, nil, invalidRequest("方法不允许")
		}
		items, err := h.service.ListRoleAssignments(ctx, principal,
			managedapi.ListRoleSubresourceRequest{Meta: meta, RoleID: target.userID})
		return http.StatusOK, items, err
	case "roles.assign", "roles.revoke":
		if method != http.MethodPost {
			return 0, nil, invalidRequest("方法不允许")
		}
		var payload roleAssignPayload
		if err := decodeStrict(body, &payload); err != nil {
			return 0, nil, invalidRequest("请求体字段或 JSON 非法")
		}
		if (payload.UserID == "") == (payload.GroupID == "") {
			return 0, nil, invalidRequest("必须且只能指定 user_id 或 group_id 之一")
		}
		if payload.UserID != "" {
			err := h.service.AssignUserRole(ctx, principal,
				managedapi.RoleTargetRequest{Meta: meta, RoleID: target.userID,
					UserID: payload.UserID}, target.operation == "roles.assign")
			return http.StatusOK, map[string]any{"changed": true}, err
		}
		err := h.service.AssignGroupRole(ctx, principal,
			managedapi.RoleGroupTargetRequest{Meta: meta, RoleID: target.userID,
				GroupID: payload.GroupID}, target.operation == "roles.assign")
		return http.StatusOK, map[string]any{"changed": true}, err
	case "permissions.list":
		switch method {
		case http.MethodGet:
			limit, offset, queryErr := listPaging(query, 10, 0)
			if queryErr.HTTPStatus != 0 {
				return 0, nil, queryErr
			}
			result, err := h.service.ListPermissions(ctx, principal,
				managedapi.ListPermissionsRequest{ListMeta: managedapi.ListMeta{Meta: meta,
					Limit: limit, Offset: offset}})
			return http.StatusOK, result, err
		case http.MethodPost:
			var payload permissionCreatePayload
			if err := decodeStrict(body, &payload); err != nil {
				return 0, nil, invalidRequest("请求体字段或 JSON 非法")
			}
			view, err := h.service.CreatePermission(ctx, principal,
				managedapi.CreatePermissionRequest{Meta: meta, Key: payload.Key,
					Name: payload.Name, Description: payload.Description, Limits: payload.Limits})
			return http.StatusOK, view, err
		default:
			return 0, nil, invalidRequest("方法不允许")
		}
	case "permissions.item":
		switch method {
		case http.MethodGet:
			view, err := h.service.GetPermission(ctx, principal,
				managedapi.GetPermissionRequest{Meta: meta, PermissionID: target.userID})
			return http.StatusOK, view, err
		case http.MethodPatch:
			var payload permissionUpdatePayload
			if err := decodeStrict(body, &payload); err != nil {
				return 0, nil, invalidRequest("请求体字段或 JSON 非法")
			}
			view, err := h.service.UpdatePermission(ctx, principal,
				managedapi.UpdatePermissionRequest{Meta: meta, PermissionID: target.userID,
					Name: payload.Name, Description: payload.Description, Limits: payload.Limits})
			return http.StatusOK, view, err
		case http.MethodDelete:
			err := h.service.DeletePermission(ctx, principal,
				managedapi.PermissionActionRequest{Meta: meta, PermissionID: target.userID})
			return http.StatusNoContent, nil, err
		default:
			return 0, nil, invalidRequest("方法不允许")
		}
	case "permissions.enable", "permissions.disable":
		if method != http.MethodPost {
			return 0, nil, invalidRequest("方法不允许")
		}
		view, err := h.service.SetPermissionEnabled(ctx, principal,
			managedapi.PermissionActionRequest{Meta: meta, PermissionID: target.userID},
			target.operation == "permissions.enable")
		return http.StatusOK, view, err
	default:
		return 0, nil, invalidRequest("未知操作")
	}
}

func (h *Handler) readBody(request *http.Request) ([]byte, APIError) {
	if request.Body == nil {
		return nil, invalidRequest("缺少请求体")
	}
	limited := io.LimitReader(request.Body, h.maxBodyBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, invalidRequest("读取请求体失败")
	}
	if int64(len(body)) > h.maxBodyBytes {
		return nil, APIError{HTTPStatus: http.StatusRequestEntityTooLarge,
			Code: string(managedapi.CodeReqInvalid), Message: "请求体过大"}
	}
	if len(bytesTrimSpace(body)) == 0 {
		return nil, invalidRequest("缺少请求体")
	}
	return body, APIError{}
}

func bytesTrimSpace(value []byte) []byte {
	return []byte(strings.TrimSpace(string(value)))
}

func (h *Handler) writeError(writer http.ResponseWriter, requestID string, status int, apiErr APIError) {
	if status <= 0 {
		status = http.StatusInternalServerError
	}
	writer.WriteHeader(status)
	payload := marshalResponse(ErrorEnvelope{RequestID: requestID, APIVersion: APIVersion,
		Error: ErrorPayload{Code: apiErr.Code, Message: apiErr.Message, Retryable: apiErr.Retryable}})
	_, _ = writer.Write(payload)
}

func (h *Handler) requestID(request *http.Request) string {
	value := strings.TrimSpace(request.Header.Get("X-Request-Id"))
	if value == "" {
		buffer := make([]byte, 16)
		if _, err := io.ReadFull(h.random, buffer); err != nil {
			return ""
		}
		value = "req_" + hex.EncodeToString(buffer)
	}
	if account.ValidateRequestID(value) != nil {
		return ""
	}
	return value
}

func validIdempotencyKey(value string) bool {
	if value == "" || len(value) > MaxIdempotencyKeyBytes {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] == 0x7f {
			return false
		}
	}
	return true
}

func validBasePath(value string) bool {
	if !strings.HasPrefix(value, "/") || value == "/" || strings.HasSuffix(value, "/") ||
		strings.Contains(value, "//") {
		return false
	}
	if !strings.HasSuffix(value, "/"+APIVersion) {
		return false
	}
	return true
}

func parsePositive(value string, fallback int) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback, nil
	}
	number, err := strconv.Atoi(value)
	if err != nil || number < 0 {
		return 0, errors.New("invalid")
	}
	return number, nil
}

type updateProfilePayload struct {
	ExpectedRowVersion int64   `json:"expected_row_version"`
	DisplayName        *string `json:"display_name"`
	Title              *string `json:"title"`
	Note               *string `json:"note"`
}

type memberActionPayload struct {
	ExpectedRowVersion int64 `json:"expected_row_version"`
}

type createUserPayload struct {
	Username  string  `json:"username"`
	Nickname  *string `json:"nickname"`
	Biography *string `json:"biography"`
}

func decodeStrict(body []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(bytesTrimSpace(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return errors.New("多余 JSON 内容")
	} else if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

type groupCreatePayload struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type roleCreatePayload struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Limits      string `json:"limits"`
}

type permissionCreatePayload struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Limits      string `json:"limits"`
}

type groupUpdatePayload struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type groupMembersPayload struct {
	UserIDs []string `json:"user_ids"`
}

type roleAssignPayload struct {
	UserID  string `json:"user_id"`
	GroupID string `json:"group_id"`
}

type roleUpdatePayload struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Limits      string `json:"limits"`
}

type permissionUpdatePayload struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Limits      string `json:"limits"`
}

func listPaging(query url.Values, defaultLimit, defaultOffset int) (int, int, APIError) {
	limit, err := parsePositive(query.Get("limit"), defaultLimit)
	if err != nil {
		return 0, 0, invalidRequest("limit 非法")
	}
	offset, err := parsePositive(query.Get("offset"), defaultOffset)
	if err != nil {
		return 0, 0, invalidRequest("offset 非法")
	}
	return limit, offset, APIError{}
}
