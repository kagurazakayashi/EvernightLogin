package httpapi

// 传输层契约测试：认证边界、API 版本/request_id、严格 JSON、路由、错误 envelope
// 与幂等 replay/conflict。真实 SQLite 幂等存储与真实 managedapi 服务分别由
// idempotency_test.go 和 internal/managedapi 真实测试覆盖。

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/managedapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

const (
	testAppA  = "app_11111111111111111111111111111111"
	testAppB  = "app_22222222222222222222222222222222"
	testUser  = "usr_11111111111111111111111111111111"
	testUser2 = "usr_22222222222222222222222222222222"
)

type fakeSessionService struct {
	session session.Session
	err     error
}

func (f fakeSessionService) SessionSecretFromRequest(*http.Request) (string, bool) {
	return "session-secret", true
}
func (f fakeSessionService) Validate(context.Context, string) (session.Session, error) {
	return f.session, f.err
}

type fakeService struct {
	getErr        error
	updateErr     error
	createErr     error
	lastPrincipal managedapi.Principal
	lastRequest   any
}

func (f *fakeService) GetApplication(context.Context, managedapi.Principal,
	managedapi.GetApplicationRequest) (managedapi.View, error) {
	return managedapi.View{ID: testAppA, Fields: map[string]any{"name": "app A"}}, f.getErr
}
func (f *fakeService) ListMembers(context.Context, managedapi.Principal,
	managedapi.ListMembersRequest) (managedapi.MemberListResult, error) {
	return managedapi.MemberListResult{Members: []managedapi.MemberView{{UserID: testUser,
		Fields: map[string]any{"display_name": "alice"}}}}, f.getErr
}
func (f *fakeService) GetMember(_ context.Context, principal managedapi.Principal,
	request managedapi.GetMemberRequest) (managedapi.MemberView, error) {
	f.lastPrincipal, f.lastRequest = principal, request
	return managedapi.MemberView{UserID: request.UserID}, f.getErr
}
func (f *fakeService) UpdateMemberProfile(_ context.Context, _ managedapi.Principal,
	request managedapi.UpdateMemberProfileRequest) (managedapi.MemberView, error) {
	f.lastRequest = request
	return managedapi.MemberView{UserID: request.UserID}, f.updateErr
}
func (f *fakeService) UpdateMemberStatus(_ context.Context, _ managedapi.Principal,
	request managedapi.MemberActionRequest, _ bool) (managedapi.MemberView, error) {
	f.lastRequest = request
	return managedapi.MemberView{UserID: request.UserID}, f.updateErr
}
func (f *fakeService) RemoveMember(context.Context, managedapi.Principal,
	managedapi.MemberActionRequest) error {
	return f.updateErr
}
func (f *fakeService) CreateUserWithMembership(_ context.Context, _ managedapi.Principal,
	request managedapi.CreateUserRequest) (managedapi.MemberView, error) {
	f.lastRequest = request
	return managedapi.MemberView{UserID: testUser2}, f.createErr
}

type memoryIdempotency struct {
	records map[string]*StoredResponse
	hash    map[string]string
	fail    bool
}

func newMemoryIdempotency() *memoryIdempotency {
	return &memoryIdempotency{records: map[string]*StoredResponse{}, hash: map[string]string{}}
}
func (m *memoryIdempotency) key(scope IdempotencyScope) string {
	return scope.ApplicationID + "|" + scope.PrincipalKind + "|" + scope.PrincipalID + "|" + scope.Key
}
func (m *memoryIdempotency) Begin(_ context.Context, scope IdempotencyScope, _ string,
	requestHash string, _, _ time.Time) (*StoredResponse, bool, error) {
	if m.fail {
		return nil, false, errors.New("store down")
	}
	key := m.key(scope)
	if hash, ok := m.hash[key]; ok {
		if hash != requestHash {
			return nil, true, nil
		}
		if stored, found := m.records[key]; found {
			return stored, false, nil
		}
		return nil, true, nil // in progress
	}
	m.hash[key] = requestHash
	return nil, false, nil
}
func (m *memoryIdempotency) Complete(_ context.Context, scope IdempotencyScope, status int,
	body []byte) error {
	m.records[m.key(scope)] = &StoredResponse{Status: status, Body: append([]byte{}, body...)}
	return nil
}
func (m *memoryIdempotency) Abort(_ context.Context, scope IdempotencyScope) error {
	delete(m.hash, m.key(scope))
	return nil
}

func newTestHandler(t *testing.T, service Service, sessions SessionService,
	idempotency IdempotencyStore) *Handler {
	t.Helper()
	handler, err := New(Options{Service: service, Sessions: sessions,
		Idempotency: idempotency, Now: func() time.Time {
			return time.Date(2026, 11, 21, 20, 0, 0, 0, time.UTC)
		}})
	if err != nil {
		t.Fatalf("构造 handler: %v", err)
	}
	return handler
}

func serveAPI(handler *Handler, method, target string, body []byte,
	headers map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "http://example.test"+target, bytes.NewReader(body))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func authHeaders() map[string]string {
	return map[string]string{"Authorization": "Bearer session-secret",
		"X-Evernight-API-Version": "v1", "X-Request-Id": "req_147_test"}
}

func TestHandlerAuthVersionAndEnvelope(t *testing.T) {
	service := &fakeService{}
	sessions := fakeSessionService{session: session.Session{UserID: testUser, Kind: session.KindNormal}}
	handler := newTestHandler(t, service, sessions, newMemoryIdempotency())
	ok := serveAPI(handler, http.MethodGet, "/api/managed/v1/applications/"+testAppA,
		nil, authHeaders())
	if ok.Code != http.StatusOK || ok.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("读取状态 = %d %s", ok.Code, ok.Body.String())
	}
	var envelope Envelope
	if err := json.Unmarshal(ok.Body.Bytes(), &envelope); err != nil ||
		envelope.RequestID != "req_147_test" || envelope.APIVersion != "v1" {
		t.Fatalf("成功 envelope = %s err=%v", ok.Body.String(), err)
	}
	missingVersion := serveAPI(handler, http.MethodGet,
		"/api/managed/v1/applications/"+testAppA, nil,
		map[string]string{"Authorization": "Bearer session-secret"})
	if missingVersion.Code != http.StatusBadRequest {
		t.Fatalf("缺版本 = %d", missingVersion.Code)
	}
	missingAuth := serveAPI(handler, http.MethodGet,
		"/api/managed/v1/applications/"+testAppA, nil,
		map[string]string{"X-Evernight-API-Version": "v1"})
	if missingAuth.Code != http.StatusUnauthorized {
		t.Fatalf("缺认证 = %d", missingAuth.Code)
	}
	// app_id 不能来自查询参数
	queryScope := serveAPI(handler, http.MethodGet,
		"/api/managed/v1/applications/"+testAppA+"?app_id="+testAppB, nil, authHeaders())
	if queryScope.Code != http.StatusBadRequest {
		t.Fatalf("query app_id 状态 = %d", queryScope.Code)
	}
}

func TestHandlerSessionAppScope(t *testing.T) {
	service := &fakeService{}
	sessions := fakeSessionService{session: session.Session{UserID: testUser,
		Kind: session.KindNormal, AppID: testAppB}}
	handler := newTestHandler(t, service, sessions, newMemoryIdempotency())
	response := serveAPI(handler, http.MethodGet,
		"/api/managed/v1/applications/"+testAppA, nil, authHeaders())
	if response.Code != http.StatusForbidden ||
		!bytes.Contains(response.Body.Bytes(), []byte("APP_SCOPE_MISMATCH")) {
		t.Fatalf("跨应用会话 = %d %s", response.Code, response.Body.String())
	}
}

func TestHandlerMembersAndStrictJSON(t *testing.T) {
	service := &fakeService{}
	sessions := fakeSessionService{session: session.Session{UserID: testUser, Kind: session.KindNormal}}
	handler := newTestHandler(t, service, sessions, newMemoryIdempotency())
	member := serveAPI(handler, http.MethodGet,
		"/api/managed/v1/applications/"+testAppA+"/members/"+testUser2, nil, authHeaders())
	if member.Code != http.StatusOK || !bytes.Contains(member.Body.Bytes(), []byte(testUser2)) {
		t.Fatalf("成员读取 = %d %s", member.Code, member.Body.String())
	}
	// 未知字段（含危险系统字段 is_root）严格拒绝，不进入服务。
	body := []byte(`{"expected_row_version":2,"display_name":"x","is_root":true}`)
	headers := authHeaders()
	headers["Idempotency-Key"] = "idem-1"
	rejected := serveAPI(handler, http.MethodPatch,
		"/api/managed/v1/applications/"+testAppA+"/members/"+testUser2, body, headers)
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("未知字段状态 = %d %s", rejected.Code, rejected.Body.String())
	}
}

func TestHandlerIdempotencyReplayAndConflict(t *testing.T) {
	service := &fakeService{}
	sessions := fakeSessionService{session: session.Session{UserID: testUser, Kind: session.KindNormal}}
	handler := newTestHandler(t, service, sessions, newMemoryIdempotency())
	body := []byte(`{"username":"alice-new","nickname":"Alice"}`)
	headers := authHeaders()
	headers["Idempotency-Key"] = "idem-create-1"
	first := serveAPI(handler, http.MethodPost,
		"/api/managed/v1/applications/"+testAppA+"/users", body, headers)
	if first.Code != http.StatusOK {
		t.Fatalf("创建 = %d %s", first.Code, first.Body.String())
	}
	// 同 key/同请求：重放同一成功响应，不再次调用服务（fake 无计数，响应头可证）。
	replay := serveAPI(handler, http.MethodPost,
		"/api/managed/v1/applications/"+testAppA+"/users", body, headers)
	if replay.Code != http.StatusOK || replay.Header().Get("Idempotent-Replayed") != "true" ||
		!bytes.Equal(first.Body.Bytes(), replay.Body.Bytes()) {
		t.Fatalf("重放 = %d header=%q body=%s", replay.Code,
			replay.Header().Get("Idempotent-Replayed"), replay.Body.String())
	}
	different := []byte(`{"username":"bob-new"}`)
	conflictResponse := serveAPI(handler, http.MethodPost,
		"/api/managed/v1/applications/"+testAppA+"/users", different, headers)
	if conflictResponse.Code != http.StatusConflict {
		t.Fatalf("幂等冲突 = %d %s", conflictResponse.Code, conflictResponse.Body.String())
	}
	noKey := serveAPI(handler, http.MethodPost,
		"/api/managed/v1/applications/"+testAppA+"/users", body,
		map[string]string{"Authorization": "Bearer session-secret", "X-Evernight-API-Version": "v1"})
	if noKey.Code != http.StatusBadRequest {
		t.Fatalf("缺幂等键 = %d", noKey.Code)
	}
}

func TestHandlerErrorMappingAndAuditFailClosed(t *testing.T) {
	service := &fakeService{updateErr: managedapi.ErrVersionConflict}
	sessions := fakeSessionService{session: session.Session{UserID: testUser, Kind: session.KindNormal}}
	handler := newTestHandler(t, service, sessions, newMemoryIdempotency())
	headers := authHeaders()
	headers["Idempotency-Key"] = "idem-version"
	body := []byte(`{"expected_row_version":1}`)
	conflictResponse := serveAPI(handler, http.MethodPost,
		"/api/managed/v1/applications/"+testAppA+"/members/"+testUser2+"/disable", body, headers)
	if conflictResponse.Code != http.StatusConflict ||
		!bytes.Contains(conflictResponse.Body.Bytes(), []byte("CONFLICT")) {
		t.Fatalf("冲突映射 = %d %s", conflictResponse.Code, conflictResponse.Body.String())
	}
	// 审计失败必须导致写路径拒绝（managedapi 返回 AUDIT_WRITE_FAILED）。
	service.updateErr = managedapi.ErrAuditUnavailable
	headers["Idempotency-Key"] = "idem-audit"
	auditResponse := serveAPI(handler, http.MethodPost,
		"/api/managed/v1/applications/"+testAppA+"/members/"+testUser2+"/disable", body, headers)
	if auditResponse.Code != http.StatusServiceUnavailable ||
		!bytes.Contains(auditResponse.Body.Bytes(), []byte("AUDIT_WRITE_FAILED")) {
		t.Fatalf("审计失败映射 = %d %s", auditResponse.Code, auditResponse.Body.String())
	}
}

func TestHandlerRejectsMalformedPath(t *testing.T) {
	handler := newTestHandler(t, &fakeService{},
		fakeSessionService{session: session.Session{UserID: testUser, Kind: session.KindNormal}},
		newMemoryIdempotency())
	for _, target := range []string{
		"/api/managed/v1/applications",
		"/api/managed/v1/applications/not-an-app",
		"/api/managed/v1/other/" + testAppA,
		"/api/managed/v1/applications/" + testAppA + "/members/not-a-user",
	} {
		response := serveAPI(handler, http.MethodGet, target, nil, authHeaders())
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s 状态 = %d", target, response.Code)
		}
	}
}

func (f *fakeService) ListGroups(context.Context, managedapi.Principal,
	managedapi.ListGroupsRequest) (managedapi.ListResult, error) {
	return managedapi.ListResult{}, f.getErr
}
func (f *fakeService) GetGroup(context.Context, managedapi.Principal,
	managedapi.GetGroupRequest) (managedapi.View, error) {
	return managedapi.View{}, f.getErr
}
func (f *fakeService) CreateGroup(_ context.Context, _ managedapi.Principal,
	request managedapi.CreateGroupRequest) (managedapi.View, error) {
	f.lastRequest = request
	return managedapi.View{ID: "grp_11111111111111111111111111111111",
		Fields: map[string]any{"name": request.Name}}, f.createErr
}
func (f *fakeService) UpdateGroup(context.Context, managedapi.Principal,
	managedapi.UpdateGroupRequest) (managedapi.View, error) {
	return managedapi.View{}, f.updateErr
}
func (f *fakeService) DeleteGroup(context.Context, managedapi.Principal,
	managedapi.DeleteGroupRequest) error {
	return f.updateErr
}
func (f *fakeService) ListGroupMembers(context.Context, managedapi.Principal,
	managedapi.ListGroupMembersRequest) (managedapi.ListResult, error) {
	return managedapi.ListResult{}, f.getErr
}
func (f *fakeService) UpdateGroupMembers(context.Context, managedapi.Principal,
	managedapi.GroupMembersRequest, bool) error {
	return f.updateErr
}
func (f *fakeService) ListRoles(context.Context, managedapi.Principal,
	managedapi.ListRolesRequest) (managedapi.ListResult, error) {
	return managedapi.ListResult{}, f.getErr
}
func (f *fakeService) GetRole(context.Context, managedapi.Principal,
	managedapi.GetRoleRequest) (managedapi.View, error) {
	return managedapi.View{}, f.getErr
}
func (f *fakeService) CreateRole(context.Context, managedapi.Principal,
	managedapi.CreateRoleRequest) (managedapi.View, error) {
	return managedapi.View{}, f.createErr
}
func (f *fakeService) UpdateRole(context.Context, managedapi.Principal,
	managedapi.UpdateRoleRequest) (managedapi.View, error) {
	return managedapi.View{}, f.updateErr
}
func (f *fakeService) DeleteRole(context.Context, managedapi.Principal,
	managedapi.DeleteRoleRequest) error {
	return f.updateErr
}
func (f *fakeService) ListRolePermissions(context.Context, managedapi.Principal,
	managedapi.ListRoleSubresourceRequest) ([]managedapi.View, error) {
	return nil, f.getErr
}
func (f *fakeService) ListRoleAssignments(context.Context, managedapi.Principal,
	managedapi.ListRoleSubresourceRequest) (map[string]any, error) {
	return nil, f.getErr
}
func (f *fakeService) AssignUserRole(context.Context, managedapi.Principal,
	managedapi.RoleTargetRequest, bool) error {
	return f.updateErr
}
func (f *fakeService) AssignGroupRole(context.Context, managedapi.Principal,
	managedapi.RoleGroupTargetRequest, bool) error {
	return f.updateErr
}
func (f *fakeService) ListPermissions(context.Context, managedapi.Principal,
	managedapi.ListPermissionsRequest) (managedapi.ListResult, error) {
	return managedapi.ListResult{}, f.getErr
}
func (f *fakeService) GetPermission(context.Context, managedapi.Principal,
	managedapi.GetPermissionRequest) (managedapi.View, error) {
	return managedapi.View{}, f.getErr
}
func (f *fakeService) CreatePermission(context.Context, managedapi.Principal,
	managedapi.CreatePermissionRequest) (managedapi.View, error) {
	return managedapi.View{}, f.createErr
}
func (f *fakeService) UpdatePermission(context.Context, managedapi.Principal,
	managedapi.UpdatePermissionRequest) (managedapi.View, error) {
	return managedapi.View{}, f.updateErr
}
func (f *fakeService) DeletePermission(context.Context, managedapi.Principal,
	managedapi.PermissionActionRequest) error {
	return f.updateErr
}
func (f *fakeService) SetPermissionEnabled(context.Context, managedapi.Principal,
	managedapi.PermissionActionRequest, bool) (managedapi.View, error) {
	return managedapi.View{}, f.updateErr
}
