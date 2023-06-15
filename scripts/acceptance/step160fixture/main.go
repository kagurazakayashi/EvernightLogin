package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	appcore "github.com/kagurazakayashi/EvernightLogin/internal/appcore"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/bootstrap"
	"github.com/kagurazakayashi/EvernightLogin/internal/registration"
	"github.com/kagurazakayashi/EvernightLogin/internal/serverapp"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

type result struct {
	AppID              string `json:"app_id"`
	Session            string `json:"session"`
	ConfigPath         string `json:"config_path"`
	MasterKey          string `json:"master_key"`
	BaseURL            string `json:"base_url"`
	ResourceClientID   string `json:"resource_client_id"`
	ResourceSecretFile string `json:"resource_secret_file"`
}

func main() {
	dir := os.Args[1]
	port := os.Args[2]
	baseURL := "http://127.0.0.1:" + port
	dbPath := filepath.Join(dir, "login.db")
	keyPath := filepath.Join(dir, "master.key")
	cfg := login.Default()
	cfg.Database.Path = dbPath
	cfg.Server.ListenAddr = "127.0.0.1:" + port
	cfg.Server.PublicBaseURL = baseURL
	cfg.Protocol.Enabled = true
	cfg.Protocol.Issuer = baseURL
	cfg.Protocol.DeviceCodeEnabled = true
	cfg.Registration.Enabled = true
	cfg.Registration.RequireReview = false
	cfg.Registration.RequireEmailVerification = false
	ctx := context.Background()
	keyring, _, err := appcore.LoadKeyring(ctx, cfg, keyPath, true, time.Now)
	if err != nil {
		panic(err)
	}
	store, err := appcore.OpenStore(ctx, cfg, nil)
	if err != nil {
		panic(err)
	}
	defer store.Close()
	if _, err := appcore.ApplyMigrations(ctx, store); err != nil {
		panic(err)
	}
	auditRecorder, err := appcore.NewAuditRecorder(ctx, store, slog.Default(), time.Now)
	if err != nil {
		panic(err)
	}
	deps := serverapp.Deps{Config: cfg, Store: store, Keyring: keyring, Audit: auditRecorder,
		Logger: slog.Default(), Now: time.Now}
	services, err := serverapp.BuildServices(deps)
	if err != nil {
		panic(err)
	}
	gate, err := serverapp.BuildSecurityGate(deps, services.BootstrapStore, services.Authn, false)
	if err != nil {
		panic(err)
	}
	tasks, err := serverapp.NewTaskRuntime(deps, gate)
	if err != nil {
		panic(err)
	}
	defer tasks.Close(context.Background())
	managed, err := serverapp.BuildManagedServices(deps, services, tasks, gate)
	if err != nil {
		panic(err)
	}
	bootService, bootCaller, err := serverapp.BuildBootstrapService(deps, "fixture-operator")
	if err != nil {
		panic(err)
	}
	initialized, err := bootService.Initialize(ctx, bootCaller, bootstrap.InitializeRequest{})
	if err != nil {
		panic(err)
	}
	grant, err := bootService.RedeemSetupCredential(ctx, bootCaller, bootstrap.RedeemSetupCredentialRequest{
		CredentialID: initialized.SetupCredential.ID, Secret: initialized.SetupCredential.Secret.Reveal()})
	if err != nil {
		panic(err)
	}
	rootCaller, _ := authn.LocalAdminCaller("fixture-operator")
	if _, err := services.Authn.SetRootPassword(ctx, rootCaller, authn.SetRootPasswordRequest{
		RootUserID: grant.RootUserID, NewPassword: "V7!qZ2#Lm9@Tp4$x", RequestID: login.NewRequestID()}); err != nil {
		panic(err)
	}
	registered, err := services.Registration.Register(ctx, registration.RegisterRequest{
		Username: "alice", Password: "K8$wR3!nB6@yF1#v", Nickname: "Alice",
		RequestID: login.NewRequestID()})
	if err != nil {
		panic(err)
	}
	accountCaller, _ := account.LocalBootstrapCaller("fixture-operator")
	user, err := managed.Account.GetUser(ctx, accountCaller, registered.UserID)
	if err != nil {
		panic(err)
	}
	appCaller, _ := app.LocalBootstrapCaller("fixture-operator")
	application, err := managed.App.CreateApplication(ctx, appCaller, app.CreateRequest{
		Name: "device-app", OwnerUserID: user.ID, ClientType: app.ClientTypePublic})
	if err != nil {
		panic(err)
	}
	if _, err := managed.App.EnableApplication(ctx, appCaller, app.StatusRequest{
		ApplicationID: application.ID, ExpectedRowVersion: application.RowVersion}); err != nil {
		panic(err)
	}
	if _, err := managed.App.AddApplicationMember(ctx, appCaller, app.AddMemberRequest{
		ApplicationID: application.ID, UserID: user.ID}); err != nil {
		panic(err)
	}
	resourceApp, err := managed.App.CreateApplication(ctx, appCaller, app.CreateRequest{
		Name: "resource-api", OwnerUserID: user.ID, ClientType: app.ClientTypeConfidential})
	if err != nil {
		panic(err)
	}
	if _, err := managed.App.EnableApplication(ctx, appCaller, app.StatusRequest{
		ApplicationID: resourceApp.ID, ExpectedRowVersion: resourceApp.RowVersion}); err != nil {
		panic(err)
	}
	resourceSecret := "resource-secret-step160-9f3a7c1b"
	nowMS := time.Now().UnixMilli()
	insertPublicClient(store.DB(), application.ID, nowMS)
	insertConfidentialClient(store.DB(), resourceApp.ID, resourceSecret, nowMS)
	resourceSecretPath := filepath.Join(dir, "resource-secret.txt")
	if err := os.WriteFile(resourceSecretPath, []byte(resourceSecret), 0o600); err != nil {
		panic(err)
	}
	authResult := authn.AuthenticateResult{UserID: user.ID, Username: user.Username,
		Outcome: authn.OutcomeComplete, CompletedMethods: []authn.Method{authn.MethodPassword},
		CompletedAt: time.Now(), StrongAuthCompletedAt: time.Now(), SecurityVersion: user.SecurityVersion}
	issued, err := services.Sessions.Login(ctx, session.LoginRequest{Result: authResult,
		AppID: application.ID, RequestID: login.NewRequestID()})
	if err != nil {
		panic(err)
	}
	config := fmt.Sprintf(`server:
  listen_addr: "127.0.0.1:%s"
  public_base_url: "%s"
database:
  path: "%s"
protocol:
  enabled: true
  issuer: "%s"
  device_code_enabled: true
  enable_introspection: true
  resource_services:
    - service_id: "step160-resource"
      client_id: "%s"
      audience: "https://resource.example.test/api"
app_qr_login:
  enabled: true
  allowed_client_ids:
    - "%s"
  request_ttl_seconds: 120
  claim_interval_seconds: 1
`, port, baseURL, filepath.ToSlash(dbPath), baseURL, resourceApp.ID, application.ID)
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		panic(err)
	}
	sessionPath := filepath.Join(dir, "session.txt")
	if err := os.WriteFile(sessionPath, []byte(issued.Secret.Reveal()), 0o600); err != nil {
		panic(err)
	}
	_ = json.NewEncoder(os.Stdout).Encode(result{AppID: application.ID,
		Session: sessionPath, ConfigPath: configPath, MasterKey: keyPath, BaseURL: baseURL,
		ResourceClientID: resourceApp.ID, ResourceSecretFile: resourceSecretPath})
}

func insertPublicClient(db *sql.DB, clientID string, nowMS int64) {
	grants, _ := json.Marshal([]string{"authorization_code", "refresh_token",
		"urn:ietf:params:oauth:grant-type:device_code"})
	redirects, _ := json.Marshal([]string{"http://127.0.0.1:9999/callback"})
	scopes, _ := json.Marshal([]string{"openid", "profile", "offline_access"})
	audiences, _ := json.Marshal([]string{"https://resource.example.test/api"})
	methods, _ := json.Marshal([]string{})
	if _, err := db.Exec(`INSERT INTO oauth_clients(client_id,client_type,grant_types_json,redirect_uris_json,
post_logout_redirect_uris_json,scopes_json,audiences_json,auth_methods_json,require_pkce,row_version,
created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?,?,?,?,1,?,?)`, clientID, "public", grants, redirects,
		"[]", scopes, audiences, methods, 1, nowMS, nowMS); err != nil {
		panic(err)
	}
}

func insertConfidentialClient(db *sql.DB, clientID, secret string, nowMS int64) {
	grants, _ := json.Marshal([]string{"client_credentials"})
	redirects, _ := json.Marshal([]string{})
	scopes, _ := json.Marshal([]string{"resource.read"})
	audiences, _ := json.Marshal([]string{"https://resource.example.test/api"})
	methods, _ := json.Marshal([]string{"client_secret_basic", "client_secret_post"})
	if _, err := db.Exec(`INSERT INTO oauth_clients(client_id,client_type,grant_types_json,redirect_uris_json,
post_logout_redirect_uris_json,scopes_json,audiences_json,auth_methods_json,require_pkce,row_version,
created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?,?,?,0,1,?,?)`, clientID, "confidential", grants,
		redirects, "[]", scopes, audiences, methods, nowMS, nowMS); err != nil {
		panic(err)
	}
	digest := sha256.Sum256([]byte(secret))
	if _, err := db.Exec(`INSERT INTO oauth_client_secrets(id,client_id,secret_prefix,secret_digest,
created_at_ms,expires_at_ms,retire_at_ms,revoked_at_ms) VALUES(?,?,?,?,?,?,NULL,NULL)`,
		"sec_step160_resource", clientID, "resource", digest[:], nowMS,
		nowMS+int64((24*time.Hour).Milliseconds())); err != nil {
		panic(err)
	}
}
