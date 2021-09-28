// Command service-identity 演示服务身份（client credentials / 服务主体）与权限联合
// 校验接入契约（步骤 89）。
//
// 本示例使用真实 SQLite（临时库，退出自动删除）、真实令牌服务、真实权限引擎与真实
// 联合判定服务，演示：
//
//  1. 用保密客户端申请服务身份令牌（client_credentials，subject_type=service）；
//  2. 服务主体权限必须由宿主显式策略判定（持有服务令牌不等于自动获得权限）；
//  3. 用户 Access Token 与应用当前权限的联合判定（scope ∩ 当前权限、应用隔离）；
//  4. 权限撤销后下一次判定立即拒绝（无缓存失效窗口）；
//  5. ID Token 不能冒充业务 Access Token；
//  6. 依赖不可用时返回不可用错误，业务必须默认拒绝；
//  7. 错误码与拒绝原因只向受信资源服务披露。
//
// 运行方式（仓库根目录）：
//
//	go run ./examples/service-identity
//
// 边界说明：本示例内部 import internal/ 包，只用于演示服务端语义；外部宿主不能导入
// internal/，必须等待独立服务 HTTP 端点装配后用标准 HTTP 对接（见
// docs/deployment/integration.md）。示例中的客户端登记、在线撤销检查与服务主体策略
// 是宿主边界适配器，生产必须接入真实实现（internal/oauthclient、internal/oauthflow
// 与宿主服务身份策略）；示例不监听端口、不联网、不写文件。
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	authzsqlite "github.com/kagurazakayashi/EvernightLogin/internal/authz/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/token"
	tokensqlite "github.com/kagurazakayashi/EvernightLogin/internal/token/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/tokenauthz"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	testAudience  = "https://api.example.test"
	testUserID    = "usr_00000000000000000000000000000001"
	appOneID      = "app_00000000000000000000000000000001"
	appTwoID      = "app_00000000000000000000000000000002"
	serviceAppID  = "app_00000000000000000000000000000003"
	roleAppOneID  = "rol_00000000000000000000000000000001"
	roleAppTwoID  = "rol_00000000000000000000000000000002"
	permAppOneID  = "perm_00000000000000000000000000000001"
	permAppTwoID  = "perm_00000000000000000000000000000002"
	servicePermID = "perm_00000000000000000000000000000003"
	permissionKey = "invoices.approve"
	serviceKey    = "reports.read"
	serviceClient = serviceAppID
	requestID     = "req_example_service_identity"
)

// demoClients 是令牌服务与联合判定共用的客户端登记替身（宿主边界）。生产使用
// internal/oauthclient 的真实持久化登记与客户端认证。
type demoClients map[string]token.ClientInfo

func (c demoClients) LoadClient(_ context.Context, id string) (token.ClientInfo, error) {
	info, found := c[id]
	if !found {
		return token.ClientInfo{}, token.ErrClientNotFound
	}
	return info, nil
}

// demoRevocations 是在线撤销检查替身（宿主边界）。生产实现为
// internal/oauthflow.Service 的在线撤销检查；无状态 JWT 不能离线感知撤销。
type demoRevocations struct{}

func (*demoRevocations) AccessTokenRevoked(context.Context, token.AccessClaims) (bool, error) {
	return false, nil
}

// demoServicePolicy 是服务主体权限策略替身（宿主边界）。生产必须由宿主按服务主体
// 规划显式实现（不能把 OAuth scope 当角色权限，也不能把持有服务令牌当成自动放行）。
// 这里只允许示例服务客户端在自身应用范围内使用 reports.read。
type demoServicePolicy struct{}

func (demoServicePolicy) AuthorizeServicePrincipal(_ context.Context, service tokenauthz.ResourceService,
	principal tokenauthz.ServicePrincipal, request tokenauthz.ServicePermissionRequest,
) (tokenauthz.ServicePrincipalDecision, error) {
	if principal.ClientID != serviceClient || service.ApplicationID() != serviceAppID {
		return tokenauthz.ServicePrincipalDecision{
			Allow: false, Code: tokenauthz.CodeAccessDenied, Reason: "service_principal_not_allowed",
		}, nil
	}
	for _, key := range request.Permissions {
		if key != serviceKey {
			return tokenauthz.ServicePrincipalDecision{
				Allow: false, Code: tokenauthz.CodePermissionRequired, Reason: "service_permission_not_granted",
			}, nil
		}
	}
	return tokenauthz.ServicePrincipalDecision{Allow: true}, nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "示例失败:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()
	tempDir, err := os.MkdirTemp("", "login-service-identity-")
	if err != nil {
		return fmt.Errorf("创建临时目录失败: %w", err)
	}
	defer os.RemoveAll(tempDir)

	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(filepath.Join(tempDir, "identity.db")))
	if err != nil {
		return fmt.Errorf("打开临时数据库失败: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = raw.Close()
		}
	}()

	list, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		return fmt.Errorf("加载迁移失败: %w", err)
	}
	if _, err := raw.Migrate(ctx, list); err != nil {
		return fmt.Errorf("执行迁移失败: %w", err)
	}
	if err := insertFixtures(ctx, raw); err != nil {
		return err
	}

	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		return fmt.Errorf("审计存储失败: %w", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{Now: time.Now})
	if err != nil {
		return fmt.Errorf("审计服务失败: %w", err)
	}
	keyring, err := secrets.GenerateKeyring("k1", now)
	if err != nil {
		return fmt.Errorf("生成临时密钥环失败: %w", err)
	}
	sealer, err := secrets.NewSealer(keyring, nil)
	if err != nil {
		return fmt.Errorf("构造密文封装器失败: %w", err)
	}
	tokenStore, err := tokensqlite.New(raw)
	if err != nil {
		return fmt.Errorf("令牌存储失败: %w", err)
	}
	clients := demoClients{
		appOneID: {ClientID: appOneID, ApplicationID: appOneID, ClientType: "confidential",
			AppActive: true, GrantTypes: []string{string(token.GrantAuthorizationCode)},
			Audiences: []string{testAudience}},
		appTwoID: {ClientID: appTwoID, ApplicationID: appTwoID, ClientType: "confidential",
			AppActive: true, GrantTypes: []string{string(token.GrantAuthorizationCode)},
			Audiences: []string{testAudience}},
		serviceClient: {ClientID: serviceClient, ApplicationID: serviceAppID, ClientType: "confidential",
			AppActive: true, GrantTypes: []string{string(token.GrantClientCredentials)},
			Scopes:    []string{serviceKey},
			Audiences: []string{testAudience}},
	}
	tokens, err := token.New(token.Options{
		Store: tokenStore, Audit: recorder, Sealer: sealer, Issuer: "https://issuer.example.test",
		Clients: clients,
		Logger:  discardLogger(),
		Now:     func() time.Time { return now },
		Authorizer: token.IssuanceAuthorizerFunc(func(_ context.Context, _ token.Caller,
			request token.IssuanceRequest) error {
			switch request.GrantType {
			case token.GrantAuthorizationCode, token.GrantClientCredentials:
				return nil
			default:
				return token.ErrAccessDenied
			}
		}),
	})
	if err != nil {
		return fmt.Errorf("令牌服务失败: %w", err)
	}

	authzStore, err := authzsqlite.New(raw)
	if err != nil {
		return fmt.Errorf("权限存储失败: %w", err)
	}
	queryAuthorizer, err := authz.NewStaticAuthorizer(authz.AuthorizerOptions{
		LocalAdminIDs: []string{"example-admin"},
	})
	if err != nil {
		return fmt.Errorf("权限查询授权器失败: %w", err)
	}
	engine, err := authz.New(authz.Options{Store: authzStore, Authorizer: queryAuthorizer,
		Logger: discardLogger()})
	if err != nil {
		return fmt.Errorf("权限引擎失败: %w", err)
	}
	combined, err := tokenauthz.New(tokenauthz.Options{
		Verifier: tokens, Clients: clients, Revocations: &demoRevocations{},
		Permissions: engine, ServicePrincipals: demoServicePolicy{},
		Audit: recorder, Logger: discardLogger(),
	})
	if err != nil {
		return fmt.Errorf("联合判定服务失败: %w", err)
	}

	appOneResource, err := tokenauthz.NewResourceService("billing-api", appOneID, testAudience)
	if err != nil {
		return fmt.Errorf("资源服务身份失败: %w", err)
	}
	appTwoResource, err := tokenauthz.NewResourceService("billing-api", appTwoID, testAudience)
	if err != nil {
		return fmt.Errorf("资源服务身份失败: %w", err)
	}
	serviceResource, err := tokenauthz.NewResourceService("reports-api", serviceAppID, testAudience)
	if err != nil {
		return fmt.Errorf("资源服务身份失败: %w", err)
	}

	fmt.Println("== 1. 签发用户 Access Token（授权码流程完成后，代表真实用户）")
	appOneToken, err := issueUserToken(ctx, tokens, appOneID)
	if err != nil {
		return err
	}
	appTwoToken, err := issueUserToken(ctx, tokens, appTwoID)
	if err != nil {
		return err
	}
	fmt.Println("  [OK] 已签发应用一/应用二用户令牌（示例只在内存持有，不写文件、不打印）。")

	fmt.Println("\n== 2. 用户令牌 + 当前权限联合判定：应用一允许")
	decision, err := combined.Decide(ctx, appOneResource, tokenauthz.Request{
		AccessToken: appOneToken, Permissions: []string{permissionKey}, RequestID: requestID,
	})
	if err != nil {
		return fmt.Errorf("应用一联合判定失败: %w", err)
	}
	if !decision.Allow || decision.SubjectType != "user" || decision.Subject != testUserID {
		return fmt.Errorf("应用一应允许（用户有该应用审批权限），实际 %+v", decision)
	}
	fmt.Printf("  [OK] allow=%v subject=%s app=%s permissions=%+v\n",
		decision.Allow, decision.Subject, decision.ApplicationID, decision.Permissions)

	fmt.Println("\n== 3. 同名权限的应用隔离：应用二令牌不能借用应用一授权")
	decision, err = combined.Decide(ctx, appTwoResource, tokenauthz.Request{
		AccessToken: appTwoToken, Permissions: []string{permissionKey}, RequestID: requestID,
	})
	if err != nil {
		return fmt.Errorf("应用二联合判定失败: %w", err)
	}
	if decision.Allow || decision.Code != tokenauthz.CodePermissionRequired {
		return fmt.Errorf("应用二同名权限不应借用应用一授权，实际 %+v", decision)
	}
	fmt.Printf("  [OK] 拒绝 code=%s reason=%s\n", decision.Code, decision.Reason)

	fmt.Println("\n== 4. 跨应用令牌：应用一的令牌用于应用二资源被拒绝")
	decision, err = combined.Decide(ctx, appTwoResource, tokenauthz.Request{
		AccessToken: appOneToken, Permissions: []string{permissionKey}, RequestID: requestID,
	})
	if err != nil {
		return fmt.Errorf("跨应用判定失败: %w", err)
	}
	if decision.Allow || decision.Code != tokenauthz.CodeAppScopeMismatch {
		return fmt.Errorf("跨应用令牌应返回 APP_SCOPE_MISMATCH，实际 %+v", decision)
	}
	fmt.Printf("  [OK] code=%s（可信应用映射来自资源服务边界，不由请求参数自称）\n", decision.Code)

	fmt.Println("\n== 5. 权限撤销后下一次判定立即拒绝（无缓存失效窗口）")
	if _, err := raw.ExecContext(ctx, `DELETE FROM role_permissions WHERE role_id=? AND permission_id=?`,
		roleAppOneID, permAppOneID); err != nil {
		return fmt.Errorf("撤销权限失败: %w", err)
	}
	decision, err = combined.Decide(ctx, appOneResource, tokenauthz.Request{
		AccessToken: appOneToken, Permissions: []string{permissionKey}, RequestID: requestID,
	})
	if err != nil {
		return fmt.Errorf("撤销后判定失败: %w", err)
	}
	if decision.Allow || decision.Code != tokenauthz.CodePermissionRequired {
		return fmt.Errorf("权限撤销后应立即拒绝，实际 %+v", decision)
	}
	fmt.Println("  [OK] 下一次判定立即拒绝，不需要等待令牌过期。")

	fmt.Println("\n== 6. 服务身份（client_credentials）：令牌 + 宿主服务主体策略")
	serviceToken, err := issueServiceToken(ctx, tokens)
	if err != nil {
		return err
	}
	decision, err = combined.Decide(ctx, serviceResource, tokenauthz.Request{
		AccessToken: serviceToken, Permissions: []string{serviceKey}, RequestID: requestID,
	})
	if err != nil {
		return fmt.Errorf("服务身份判定失败: %w", err)
	}
	if !decision.Allow || decision.SubjectType != "service" || decision.Subject != serviceClient {
		return fmt.Errorf("服务主体在显式策略允许时应通过，实际 %+v", decision)
	}
	fmt.Printf("  [OK] subject_type=service subject=%s（服务身份不代表任何用户）\n", decision.Subject)
	decision, err = combined.Decide(ctx, serviceResource, tokenauthz.Request{
		AccessToken: serviceToken, Permissions: []string{"users.manage"}, RequestID: requestID,
	})
	if err != nil {
		return fmt.Errorf("服务主体越权判定失败: %w", err)
	}
	if decision.Allow {
		return errors.New("服务主体未被授予的权限不应放行")
	}
	fmt.Printf("  [OK] 未授予的服务权限被拒绝 code=%s\n", decision.Code)

	fmt.Println("\n== 7. ID Token 不能冒充业务 Access Token")
	caller, err := token.SystemCaller("example-service-identity")
	if err != nil {
		return fmt.Errorf("构造签发调用者失败: %w", err)
	}
	idToken, err := tokens.IssueIDToken(ctx, caller, token.IssueIDTokenRequest{
		ClientID: appOneID, SubjectUserID: testUserID, RequestID: requestID,
	})
	if err != nil {
		return fmt.Errorf("签发 ID Token 失败: %w", err)
	}
	decision, err = combined.Decide(ctx, appOneResource, tokenauthz.Request{
		AccessToken: idToken.Token.Reveal(), Permissions: []string{permissionKey}, RequestID: requestID,
	})
	if err != nil {
		return fmt.Errorf("ID Token 混用判定失败: %w", err)
	}
	if decision.Allow || decision.Code != tokenauthz.CodeTokenInvalid {
		return fmt.Errorf("ID Token 冒充 Access Token 应返回 TOKEN_INVALID，实际 %+v", decision)
	}
	fmt.Println("  [OK] ID Token/会话秘密不能作为业务 Access Token。")

	fmt.Println("\n== 8. 依赖不可用：返回不可用错误，业务必须默认拒绝")
	closed = true
	if err := raw.Close(); err != nil {
		return fmt.Errorf("关闭数据库失败: %w", err)
	}
	if _, err := combined.Decide(ctx, appOneResource, tokenauthz.Request{
		AccessToken: appOneToken, Permissions: []string{permissionKey}, RequestID: requestID,
	}); !errors.Is(err, tokenauthz.ErrUnavailable) {
		return fmt.Errorf("断库时应返回 ErrUnavailable（业务视为拒绝），实际 %v", err)
	}
	fmt.Println("  [OK] AUTHZ_UNAVAILABLE：不允许因为依赖故障而降级放行。")

	fmt.Println("\n服务身份与权限联合校验示例完成。")
	return nil
}

// insertFixtures 写入合成账户/应用/成员/权限/角色数据（示例数据，不是真实用户）。
func insertFixtures(ctx context.Context, raw *storagesqlite.Store) error {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC).UnixMilli()
	exec := func(query string, args ...any) error {
		if _, err := raw.ExecContext(ctx, query, args...); err != nil {
			return fmt.Errorf("插入示例数据失败: %w", err)
		}
		return nil
	}
	if err := exec(`INSERT INTO users(id,username,username_normalized,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms) VALUES(?,?,?,'active',0,1,1,?,?)`,
		testUserID, "alice", "alice", now, now); err != nil {
		return err
	}
	insertApplication := func(applicationID, name, clientType string) error {
		if err := exec(`INSERT INTO applications(id,name,description,status,client_type,row_version,
created_at_ms,updated_at_ms) VALUES(?,?,'','active',?,1,?,?)`,
			applicationID, name, clientType, now, now); err != nil {
			return err
		}
		return exec(`INSERT INTO scopes(id,kind,app_id) VALUES(?,'application',?)`, applicationID, applicationID)
	}
	for _, application := range []struct{ id, name string }{
		{appOneID, "应用一（账单）"},
		{appTwoID, "应用二（账单）"},
		{serviceAppID, "报表服务"},
	} {
		if err := insertApplication(application.id, application.name, "confidential"); err != nil {
			return err
		}
	}
	for _, applicationID := range []string{appOneID, appTwoID} {
		if err := exec(`INSERT INTO app_memberships(app_id,user_id,status,profile_json,row_version,
created_at_ms,updated_at_ms) VALUES(?,?,'active','{"v":1}',1,?,?)`,
			applicationID, testUserID, now, now); err != nil {
			return err
		}
	}
	for _, item := range []struct{ permissionID, scopeID, key string }{
		{permAppOneID, appOneID, permissionKey},
		{permAppTwoID, appTwoID, permissionKey},
		{servicePermID, serviceAppID, serviceKey},
	} {
		if err := exec(`INSERT INTO permissions(id,scope_id,permission_key,name,description,limits_text,
is_builtin,root_only,enabled,created_at_ms,updated_at_ms) VALUES(?,?,?,?,'','',0,0,1,?,?)`,
			item.permissionID, item.scopeID, item.key, item.key, now, now); err != nil {
			return err
		}
	}
	for _, item := range []struct{ roleID, scopeID, roleKey string }{
		{roleAppOneID, appOneID, "invoices.approver"},
		{roleAppTwoID, appTwoID, "invoices.approver"},
	} {
		if err := exec(`INSERT INTO roles(id,scope_id,role_key,name,description,limits_text,
is_builtin,enabled,created_at_ms,updated_at_ms) VALUES(?,?,?,?,'','',0,1,?,?)`,
			item.roleID, item.scopeID, item.roleKey, item.roleKey, now, now); err != nil {
			return err
		}
	}
	if err := exec(`INSERT INTO role_permissions(role_id,permission_id,scope_id) VALUES(?,?,?)`,
		roleAppOneID, permAppOneID, appOneID); err != nil {
		return err
	}
	return exec(`INSERT INTO user_roles(user_id,role_id,scope_id,data_scope_json,assigned_by,
created_at_ms) VALUES(?,?,?,'{}','example-admin',?)`, testUserID, roleAppOneID, appOneID, now)
}

// issueUserToken 用真实令牌服务签发代表示例用户的 Access Token。
func issueUserToken(ctx context.Context, tokens *token.Service, clientID string) (string, error) {
	caller, err := token.SystemCaller("example-service-identity")
	if err != nil {
		return "", fmt.Errorf("构造签发调用者失败: %w", err)
	}
	issued, err := tokens.IssueAccessToken(ctx, caller, token.IssueAccessTokenRequest{
		ClientID: clientID, SubjectUserID: testUserID, GrantType: token.GrantAuthorizationCode,
		Audiences: []string{testAudience}, RequestID: requestID,
	})
	if err != nil {
		return "", fmt.Errorf("签发用户 Access Token 失败: %w", err)
	}
	return issued.Token.Reveal(), nil
}

// issueServiceToken 用真实令牌服务签发服务身份 Access Token（client_credentials）。
// 服务令牌只能由受信编排层签发，普通用户调用者会被拒绝；主体是客户端自身。
func issueServiceToken(ctx context.Context, tokens *token.Service) (string, error) {
	caller, err := token.SystemCaller("example-service-identity")
	if err != nil {
		return "", fmt.Errorf("构造签发调用者失败: %w", err)
	}
	issued, err := tokens.IssueAccessToken(ctx, caller, token.IssueAccessTokenRequest{
		ClientID: serviceClient, GrantType: token.GrantClientCredentials,
		Scopes: []string{serviceKey}, Audiences: []string{testAudience}, RequestID: requestID,
	})
	if err != nil {
		return "", fmt.Errorf("签发服务身份 Access Token 失败: %w", err)
	}
	return issued.Token.Reveal(), nil
}

// discardLogger 丢弃运行日志输出（示例不打印内部日志）。
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}
