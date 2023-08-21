// Command app-qr-login 演示"已登录 APP 扫网页二维码确认登录"的完整本地闭环
// （步骤 58）。示例使用临时 SQLite 数据库、确定性时钟与真实服务，不监听端口、
// 不联网、不写入仓库；退出时自动删除临时数据库。
//
// 运行方式：go run ./examples/app-qr-login
//
// 角色边界：
//   - 发起端（网页）创建请求，二维码只承载一次性请求标识；领取绑定只在创建响应
//     出现一次，绝不放进二维码。
//   - 确认端（APP）使用真实完整普通会话读取请求并批准；批准按步骤 39 敏感策略
//     要求近期认证。示例在宿主边界注入一次"近期密码验证事实"（等价于生产环境
//     由会话中间件调用 reauth.WithSignals；这不是生产鉴权实现）。
//   - 领取转换使用 internal/session 的受门控登录批准签发目标应用会话，不签发
//     任何 OAuth Token。
//
// 与真实部署的关系（步骤 193）：本示例演示领域服务闭环。真实部署的 HTTP 端点、
// 内置确认网页（/login/qr、/app/scan）与合法协议直连方式（Bearer 会话 + 同源
// Origin；Cookie 会话另需 CSRF，不关闭校验）见 docs/deployment/integration.md
// 第 6 节；对应的真实网页双会话验收记录见 docs/acceptance/step193-qr-login.md。
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

	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	appsqlite "github.com/kagurazakayashi/EvernightLogin/internal/app/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	oauthclientsqlite "github.com/kagurazakayashi/EvernightLogin/internal/oauthclient/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	policysqlite "github.com/kagurazakayashi/EvernightLogin/internal/policy/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/qrlogin"
	qrloginsqlite "github.com/kagurazakayashi/EvernightLogin/internal/qrlogin/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	reauthsqlite "github.com/kagurazakayashi/EvernightLogin/internal/reauth/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	sessionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/session/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	userID   = "usr_00000000000000000000000000000001"
	clientID = "app_00000000000000000000000000000001"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "示例失败:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "login-app-qr-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(filepath.Join(dir, "demo.db")))
	if err != nil {
		return err
	}
	defer raw.Close()
	migrationSet, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		return err
	}
	if _, err := raw.Migrate(ctx, migrationSet); err != nil {
		return err
	}
	now := time.Now().UTC()
	clock := func() time.Time { return now }
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		return err
	}
	auditRecorder, err := audit.New(auditStore, audit.Options{Logger: logger, Now: clock})
	if err != nil {
		return err
	}
	keyring, err := secrets.GenerateKeyring("k1", now)
	if err != nil {
		return err
	}
	sessionStore, err := sessionsqlite.New(raw)
	if err != nil {
		return err
	}
	sessionService, err := session.New(sessionStore, session.Options{
		Store: sessionStore, Audit: auditRecorder, Keyring: keyring,
		AllowLegacyWithoutSensitive: true, Logger: logger, Now: clock,
	})
	if err != nil {
		return err
	}
	appStore, err := appsqlite.New(raw)
	if err != nil {
		return err
	}
	clientStore, err := oauthclientsqlite.New(raw)
	if err != nil {
		return err
	}
	policyService, err := policy.New(policy.Options{
		Store: mustPolicyStore(raw), Audit: auditRecorder, Logger: logger, Now: clock,
	})
	if err != nil {
		return err
	}
	reauthService, err := reauth.New(reauth.Options{
		Store: mustReauthStore(raw), Audit: auditRecorder, Policy: policyService,
		AvailableStrengths: []policy.Strength{policy.StrengthNone, policy.StrengthPassword},
		Logger:             logger, Now: clock,
	})
	if err != nil {
		return err
	}
	qrStore, err := qrloginsqlite.New(raw)
	if err != nil {
		return err
	}
	qrService, err := qrlogin.New(qrlogin.Options{
		Store: qrStore, Audit: auditRecorder, Clients: clientStore, Applications: appStore,
		Sessions: sessionService, SessionIssuer: sessionService, Reauth: reauthService,
		Keyring: keyring, Enabled: true, AllowedClientIDs: []string{clientID},
		Now: clock, Logger: logger,
	})
	if err != nil {
		return err
	}
	if err := seedDemoData(ctx, raw, now); err != nil {
		return err
	}

	// 1. 发起端（网页）创建扫码登录请求；领取绑定只在创建响应出现一次。
	begin, err := qrService.Begin(ctx, qrlogin.BeginRequest{
		ClientID: clientID, Scopes: []string{"openid", "profile"},
		RequestID: "req_example_begin",
		Requester: qrlogin.RequesterInfo{UserAgent: "DemoBrowser/1.0", Address: "127.0.0.1"},
	})
	if err != nil {
		return fmt.Errorf("创建扫码请求失败: %w", err)
	}
	fmt.Println("== 发起端创建请求 ==")
	fmt.Printf("request_id=%s version=%d expires_in=%s\n", begin.RequestID, begin.Version,
		begin.ExpiresAt.Sub(now))
	fmt.Printf("QR 内容（只含一次性请求标识）: %s\n", begin.QRPayload)
	fmt.Printf("领取绑定（只在创建响应出现，绝不放进二维码）: %s\n", begin.ClaimSecret.String())

	parsed, err := qrlogin.ParseQRPayload(begin.QRPayload)
	if err != nil || parsed.RequestID != begin.RequestID {
		return fmt.Errorf("解析二维码失败: %w", err)
	}

	// 2. APP 已有真实完整普通会话（示例直接以服务端认证结果签发；生产由登录流程签发）。
	appSession, err := sessionService.Login(ctx, session.LoginRequest{
		Result: authn.AuthenticateResult{
			UserID: userID, Username: "qruser", Outcome: authn.OutcomeComplete,
			CompletedMethods: []authn.Method{authn.MethodPassword},
			CompletedAt:      now, SecurityVersion: 1,
		},
		AppID: clientID, RequestID: "req_example_app_login",
	})
	if err != nil {
		return fmt.Errorf("签发 APP 会话失败: %w", err)
	}
	prompt, err := qrService.Describe(ctx, qrlogin.PromptRequest{
		SessionSecret: appSession.Secret.Reveal(), RequestID: parsed.RequestID,
		AuditRequestID: "req_example_describe",
	})
	if err != nil {
		return fmt.Errorf("APP 读取请求失败: %w", err)
	}
	fmt.Println("\n== APP 确认页上下文 ==")
	fmt.Printf("应用: %s (%s) 状态: %s\n", prompt.ApplicationName, prompt.ClientID, prompt.Status)
	fmt.Printf("发起端: UA=%q 地址=%q 创建时间=%s\n", prompt.Requester.UserAgent,
		prompt.Requester.Address, prompt.CreatedAt.Format(time.RFC3339))
	fmt.Printf("提醒: %s\n", prompt.Warning)

	// 3. 用户在 APP 显式批准；批准经步骤 39 敏感策略要求近期认证。生产环境的
	// 会话中间件负责注入真实认证事实；示例在这里模拟该"宿主边界"调用。
	approveCtx := reauth.WithSignals(ctx, reauth.Signals{
		VerifiedAt: now, Strength: policy.StrengthPassword, Complete: true, Confirmed: true,
	})
	if _, err := qrService.Approve(approveCtx, qrlogin.DecideRequest{
		SessionSecret: appSession.Secret.Reveal(), RequestID: parsed.RequestID,
		ExpectedVersion: prompt.Version, AuditRequestID: "req_example_approve",
	}); err != nil {
		return fmt.Errorf("APP 批准失败: %w", err)
	}
	fmt.Println("\n== APP 已批准 ==")

	// 4. 发起端用领取绑定领取登录结果；得到目标应用会话，不签发 Token。
	issued, err := qrService.Claim(ctx, qrlogin.ClaimedRequest{
		ClaimSecret: begin.ClaimSecret, RequestID: begin.RequestID,
		AuditRequestID: "req_example_claim",
	})
	if err != nil {
		return fmt.Errorf("领取登录结果失败: %w", err)
	}
	fmt.Println("\n== 网页领取登录结果 ==")
	fmt.Printf("会话 id=%s user=%s app=%s kind=%s\n", issued.Session.ID,
		issued.Session.UserID, issued.Session.AppID, issued.Session.Kind)
	fmt.Printf("会话凭据（投递到目标网页 Cookie）: %s\n", issued.Secret.String())

	// 5. 重复领取必须失败（结果只能成功消费一次）。
	if _, err := qrService.Claim(ctx, qrlogin.ClaimedRequest{
		ClaimSecret: begin.ClaimSecret, RequestID: begin.RequestID,
		AuditRequestID: "req_example_claim_again",
	}); !errors.Is(err, qrlogin.ErrAlreadyClaimed) {
		return fmt.Errorf("重复领取应失败，实际 %v", err)
	}
	fmt.Println("\n== 重复领取被拒绝（已消费）==")
	return nil
}

// seedDemoData 插入示例用合成账户/应用/成员/客户端登记（仅示例，不是生产数据）。
func seedDemoData(ctx context.Context, raw *storagesqlite.Store, now time.Time) error {
	nowMS := now.UnixMilli()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO users(id,username,username_normalized,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'active',0,1,1,?,?)`, []any{userID, "qruser", "qruser", nowMS, nowMS}},
		{`INSERT INTO applications(id,name,description,status,client_type,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'','active','public',1,?,?)`, []any{clientID, "扫码演示应用", nowMS, nowMS}},
		{`INSERT INTO scopes(id,kind,app_id) VALUES(?,'application',?)`, []any{clientID, clientID}},
		{`INSERT INTO app_memberships(app_id,user_id,status,profile_json,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'active','{"v":1}',1,?,?)`, []any{clientID, userID, nowMS, nowMS}},
		{`INSERT INTO oauth_clients(client_id,client_type,grant_types_json,redirect_uris_json,
post_logout_redirect_uris_json,scopes_json,audiences_json,auth_methods_json,require_pkce,
row_version,created_at_ms,updated_at_ms)
VALUES(?,'public','["authorization_code"]','[]','[]','["openid","profile"]','[]','[]',1,1,?,?)`,
			[]any{clientID, nowMS, nowMS}},
	}
	for _, statement := range statements {
		if _, err := raw.ExecContext(ctx, statement.query, statement.args...); err != nil {
			return fmt.Errorf("插入示例数据失败: %w", err)
		}
	}
	return nil
}

// mustPolicyStore 构造示例用敏感策略存储。
func mustPolicyStore(raw *storagesqlite.Store) *policysqlite.Store {
	store, err := policysqlite.New(raw)
	if err != nil {
		panic(err)
	}
	return store
}

// mustReauthStore 构造示例用再次认证存储。
func mustReauthStore(raw *storagesqlite.Store) *reauthsqlite.Store {
	store, err := reauthsqlite.New(raw)
	if err != nil {
		panic(err)
	}
	return store
}

// 编译期断言：示例使用的生产适配器满足扫码登录接口。
var (
	_ qrlogin.OAuthClientReader = (*oauthclientsqlite.Store)(nil)
	_ qrlogin.ApplicationReader = (*appsqlite.Store)(nil)
	_                           = app.StatusActive
	_ oauthclient.ClientType    = oauthclient.ClientTypePublic
)
