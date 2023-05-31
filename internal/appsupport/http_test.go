package appsupport_test

// 步骤 154 真实 SQLite + HTTP 契约测试：应用客服只创建升级申请、应用归属隔离、
// 跨应用读取/审批拒绝、字段白名单拒绝密码/MFA/恢复材料、缺权限拒绝与审计落库。
// TokenValidator 使用严格测试替身（不伪造 header 身份）；真实 OAuth Token 验证由
// internal/tokenauthz 集成测试与 serverapp 生产装配覆盖。

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/appsupport"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	supportsqlite "github.com/kagurazakayashi/EvernightLogin/internal/support/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	testAppA      = "app_11111111111111111111111111111111"
	testAppB      = "app_22222222222222222222222222222222"
	staffA        = "usr_11111111111111111111111111111111"
	staffB        = "usr_22222222222222222222222222222222"
	targetA       = "usr_33333333333333333333333333333333"
	targetB       = "usr_44444444444444444444444444444444"
	tokenA        = "token-app-a"
	tokenB        = "token-app-b"
	tokenReadOnly = "token-read-only"
	staffNoPerm   = "usr_55555555555555555555555555555555"
)

type fakeTokens struct{}

func (fakeTokens) ValidateToken(_ context.Context, raw string) (appsupport.Identity, error) {
	switch raw {
	case tokenA:
		return appsupport.Identity{ApplicationID: testAppA, StaffUserID: staffA}, nil
	case tokenB:
		return appsupport.Identity{ApplicationID: testAppB, StaffUserID: staffB}, nil
	case tokenReadOnly:
		return appsupport.Identity{ApplicationID: testAppA, StaffUserID: staffNoPerm}, nil
	default:
		return appsupport.Identity{}, appsupport.ErrIdentityUnavailable
	}
}

type fakeMembership struct{}

func (fakeMembership) IsActiveMember(context.Context, string, string) (bool, error) {
	return true, nil
}

type fakePermissions struct{}

func (fakePermissions) CheckApplicationPermission(_ context.Context, appID, staffID,
	permission string) error {
	if staffID == staffA && appID == testAppA {
		return nil
	}
	if staffID == staffB && appID == testAppB {
		return nil
	}
	return appsupport.ErrAccessDenied
}

type fakeProtector struct{}

func (fakeProtector) Protected(context.Context, string) (bool, error) { return false, nil }

type testEnv struct {
	t       *testing.T
	handler http.Handler
	store   *storagesqlite.Store
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()
	store, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(testutil.TempDir(t), "app-support.db")))
	if err != nil {
		t.Fatalf("打开临时数据库: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	set, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := store.Migrate(ctx, set); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	auditStore, err := auditsqlite.New(store)
	if err != nil {
		t.Fatalf("审计存储: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{Now: func() time.Time {
		return time.Date(2026, 11, 21, 20, 0, 0, 0, time.UTC)
	}})
	if err != nil {
		t.Fatalf("审计服务: %v", err)
	}
	now := time.Date(2026, 11, 21, 19, 0, 0, 0, time.UTC).UnixMilli()
	for _, userID := range []string{staffA, staffB, targetA, targetB} {
		if _, err := store.ExecContext(ctx, `INSERT INTO users(id,username,username_normalized,
status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'active',0,1,1,?,?)`, userID, userID, userID, now, now); err != nil {
			t.Fatalf("插入用户 %s: %v", userID, err)
		}
	}
	supportStore, err := supportsqlite.New(store)
	if err != nil {
		t.Fatalf("工单存储: %v", err)
	}
	service, err := appsupport.New(appsupport.Options{
		Store: supportStore, Audit: recorder, Tokens: fakeTokens{},
		Membership: fakeMembership{}, Permissions: fakePermissions{},
		TargetProtector: fakeProtector{},
		Now:             func() time.Time { return time.Date(2026, 11, 21, 20, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("构造服务: %v", err)
	}
	handler, err := appsupport.NewHTTPHandler(appsupport.HTTPOptions{Service: service})
	if err != nil {
		t.Fatalf("构造 HTTP: %v", err)
	}
	return &testEnv{t: t, handler: handler, store: store}
}

func (e *testEnv) request(method, target, token string, body []byte) (int, []byte) {
	e.t.Helper()
	request := httptest.NewRequest(method, "http://example.test"+target, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Evernight-API-Version", "v1")
	request.Header.Set("X-Request-Id", "req_154_test")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	e.handler.ServeHTTP(response, request)
	return response.Code, response.Body.Bytes()
}

func (e *testEnv) createCase(token, target, reason string) map[string]any {
	e.t.Helper()
	body, _ := json.Marshal(map[string]string{"target_user_id": target, "reason": reason})
	status, payload := e.request(http.MethodPost, "/api/app/v1/support/cases", token, body)
	if status != http.StatusOK {
		e.t.Fatalf("创建应用工单 = %d %s", status, payload)
	}
	var envelope struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		e.t.Fatalf("解析创建响应: %v", err)
	}
	return envelope.Data
}

func TestAppSupportCreateAndIsolation(t *testing.T) {
	env := newTestEnv(t)
	caseA := env.createCase(tokenA, targetA, "应用 A 客服升级申请")
	if caseA["application_id"] != testAppA || caseA["status"] != "manual_review" ||
		caseA["id"] == nil {
		t.Fatalf("应用 A 工单 = %+v", caseA)
	}
	caseB := env.createCase(tokenB, targetB, "应用 B 客服升级申请")
	if caseB["application_id"] != testAppB {
		t.Fatalf("应用 B 工单 = %+v", caseB)
	}
	// 应用 B 读取应用 A 工单必须拒绝，不泄露存在性。
	status, payload := env.request(http.MethodGet,
		"/api/app/v1/support/cases/"+caseA["id"].(string), tokenB, nil)
	if status != http.StatusForbidden {
		t.Fatalf("跨应用读取 = %d %s", status, payload)
	}
	// 列表按应用归属过滤。
	status, payload = env.request(http.MethodGet, "/api/app/v1/support/cases", tokenA, nil)
	if status != http.StatusOK || bytes.Contains(payload, []byte(testAppB)) {
		t.Fatalf("应用 A 列表 = %d %s", status, payload)
	}
	// 应用管理员不能自批全局恢复。
	status, payload = env.request(http.MethodPost,
		"/api/app/v1/support/cases/"+caseA["id"].(string)+"/approve", tokenA,
		[]byte(`{"approve":true}`))
	if status != http.StatusForbidden || !bytes.Contains(payload, []byte("recovery.approve")) {
		t.Fatalf("应用自批 = %d %s", status, payload)
	}
}

func TestAppSupportFieldWhitelistAndAudit(t *testing.T) {
	env := newTestEnv(t)
	dangerous := []byte(`{"target_user_id":"` + targetA +
		`","reason":"x","new_password":"P@ssw0rd","mfa":"123456"}`)
	status, payload := env.request(http.MethodPost, "/api/app/v1/support/cases", tokenA, dangerous)
	if status != http.StatusBadRequest {
		t.Fatalf("密码/MFA 字段必须拒绝 = %d %s", status, payload)
	}
	caseA := env.createCase(tokenA, targetA, "合法升级")
	if caseA["target_masked_email"] != "[REDACTED]" {
		t.Fatalf("脱敏邮箱 = %v", caseA["target_masked_email"])
	}
	rows, err := env.store.QueryContext(context.Background(),
		`SELECT COUNT(*) FROM audit_events WHERE action='support.app.case.created' AND app_id_snapshot=?`,
		testAppA)
	if err != nil {
		t.Fatalf("查询审计: %v", err)
	}
	defer rows.Close()
	var count int
	if rows.Next() {
		if err := rows.Scan(&count); err != nil {
			t.Fatalf("扫描审计: %v", err)
		}
	}
	if count != 1 {
		t.Fatalf("应用工单创建审计行数 = %d", count)
	}
	// 无客服权限的令牌被服务层拒绝（真实权限适配器在 serverapp 装配）。
	status, payload = env.request(http.MethodPost, "/api/app/v1/support/cases", tokenReadOnly,
		[]byte(`{"target_user_id":"`+targetA+`","reason":"x"}`))
	if status != http.StatusForbidden {
		t.Fatalf("无权限 = %d %s", status, payload)
	}
}
