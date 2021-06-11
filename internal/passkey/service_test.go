package passkey_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/passkey"
	passkeysqlite "github.com/kagurazakayashi/EvernightLogin/internal/passkey/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	sessionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/session/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	testRPID   = "login.example.com"
	testOrigin = "https://login.example.com"
	aliceID    = "usr_00000000000000000000000000000001"
	bobID      = "usr_00000000000000000000000000000002"
	appID      = "app_00000000000000000000000000000001"
)

var seedTime = time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

// fakeRunner 是可编程的再次认证替身（只用于测试；生产必须注入真实 reauth）。
type fakeRunner struct {
	err    error
	calls  []string
	params []map[string]string
	notify int
}

func (r *fakeRunner) Authorize(ctx context.Context, caller reauth.Caller, request reauth.Request) (reauth.Result, error) {
	r.calls = append(r.calls, request.OperationID)
	r.params = append(r.params, request.Params)
	if r.err != nil {
		return reauth.Result{}, r.err
	}
	return reauth.Result{OperationID: request.OperationID, TargetID: request.TargetID,
		Method: "direct", RequestID: request.RequestID}, nil
}

func (r *fakeRunner) NotifyOutcome(ctx context.Context, result reauth.Result, outcome reauth.Outcome) error {
	r.notify++
	return nil
}

type testEnv struct {
	t        *testing.T
	ctx      context.Context
	raw      *storagesqlite.Store
	service  *passkey.Service
	session  *session.Service
	store    passkey.Store
	runner   *fakeRunner
	now      time.Time
	recorder *audit.Recorder
}

func newTestEnv(t *testing.T, mutate func(*passkey.Options)) *testEnv {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(filepath.Join(t.TempDir(), "passkey.db")))
	if err != nil {
		t.Fatalf("打开数据库: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	list, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := raw.Migrate(ctx, list); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		t.Fatalf("审计存储: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{Now: func() time.Time { return seedTime }})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	keyring, err := secrets.GenerateKeyring("k1", seedTime)
	if err != nil {
		t.Fatalf("密钥环: %v", err)
	}
	sessionStore, err := sessionsqlite.New(raw)
	if err != nil {
		t.Fatalf("会话存储: %v", err)
	}
	env := &testEnv{t: t, ctx: ctx, raw: raw, now: time.Now().UTC(), runner: &fakeRunner{},
		recorder: recorder}
	sessionService, err := session.New(sessionStore, session.Options{
		Audit: recorder, Keyring: keyring, Now: func() time.Time { return env.now },
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	})
	if err != nil {
		t.Fatalf("会话服务: %v", err)
	}
	env.session = sessionService
	store, err := passkeysqlite.New(raw)
	if err != nil {
		t.Fatalf("Passkey 存储: %v", err)
	}
	options := passkey.Options{
		Store: store, Audit: recorder, Sessions: sessionService, Reauth: env.runner,
		Config: passkey.Config{RPID: testRPID, Origins: []string{testOrigin}},
		Now:    func() time.Time { return env.now },
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	if mutate != nil {
		mutate(&options)
	}
	service, err := passkey.New(options)
	if err != nil {
		t.Fatalf("Passkey 服务: %v", err)
	}
	env.service = service
	env.store = store
	now := seedTime.UnixMilli()
	for _, user := range []struct{ id, username string }{
		{aliceID, "alice"}, {bobID, "bob"},
	} {
		if _, err := raw.DB().ExecContext(ctx, `INSERT INTO users(
id,username,username_normalized,nickname,biography,avatar_ref,language,timezone,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms
) VALUES(?,?,?,'','',NULL,'zh-CN','Asia/Shanghai','active',0,1,1,?,?)`,
			user.id, user.username, user.username, now, now); err != nil {
			t.Fatalf("用户 %s: %v", user.username, err)
		}
	}
	return env
}

func (e *testEnv) caller(userID string) passkey.Caller {
	caller, err := passkey.UserCaller(userID)
	if err != nil {
		e.t.Fatalf("调用者: %v", err)
	}
	return caller
}

func (e *testEnv) addPassword(userID string) {
	e.t.Helper()
	now := seedTime.UnixMilli()
	if _, err := e.raw.DB().ExecContext(e.ctx, `INSERT INTO password_credentials(
user_id,hash_scheme,hash_version,password_hash,must_change,row_version,created_at_ms,
updated_at_ms,changed_at_ms) VALUES(?,'argon2id',19,?,0,1,?,?,?)`,
		userID, "argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaA",
		now, now, now); err != nil {
		e.t.Fatalf("密码凭证: %v", err)
	}
}

func (e *testEnv) addAppMembership(userID string) {
	e.t.Helper()
	now := seedTime.UnixMilli()
	if _, err := e.raw.DB().ExecContext(e.ctx, `INSERT INTO applications(
id,name,description,status,client_type,row_version,created_at_ms,updated_at_ms
) VALUES(?,?,'','active','confidential',1,?,?)`, appID, "app", now, now); err != nil {
		e.t.Fatalf("应用: %v", err)
	}
	if _, err := e.raw.DB().ExecContext(e.ctx, `INSERT INTO app_memberships(
app_id,user_id,status,profile_json,row_version,created_at_ms,updated_at_ms
) VALUES(?,?,'active','{}',1,?,?)`, appID, userID, now, now); err != nil {
		e.t.Fatalf("应用成员: %v", err)
	}
}

// registerCredential 使用模拟认证器完成一次注册，返回凭证元数据与模拟器。
func (e *testEnv) registerCredential(userID, name string, simulator *authenticator) passkey.CredentialMetadata {
	e.t.Helper()
	start, err := e.service.BeginRegistration(e.ctx, e.caller(userID), "req-register-1")
	if err != nil {
		e.t.Fatalf("开始注册: %v", err)
	}
	response := simulator.registrationResponse(e.t, start.PublicKey, testOrigin, "")
	meta, err := e.service.FinishRegistration(e.ctx, e.caller(userID),
		passkey.RegistrationFinishRequest{CeremonyID: start.CeremonyID,
			Response: response, Name: name, RequestID: "req-register-2"})
	if err != nil {
		e.t.Fatalf("完成注册: %v", err)
	}
	return meta
}

// ===== 模拟认证器（测试专用，不是真机/浏览器实测） =====

type authenticator struct {
	t              *testing.T
	key            *ecdsa.PrivateKey
	credentialID   []byte
	handle         []byte
	signCount      uint32
	userVerified   bool
	backupEligible bool
	backedUp       bool
	origin         string
	rpID           string
}

func newAuthenticator(t *testing.T) *authenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成认证器密钥: %v", err)
	}
	credentialID := make([]byte, 32)
	if _, err := rand.Read(credentialID); err != nil {
		t.Fatalf("凭证 ID: %v", err)
	}
	return &authenticator{t: t, key: key, credentialID: credentialID, userVerified: true,
		origin: testOrigin, rpID: testRPID}
}

type creationOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		AuthenticatorSelection struct {
			UserVerification string `json:"userVerification"`
		} `json:"authenticatorSelection"`
	} `json:"publicKey"`
}

type requestOptions struct {
	PublicKey struct {
		Challenge        string `json:"challenge"`
		RPID             string `json:"rpId"`
		UserVerification string `json:"userVerification"`
		AllowCredentials []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
	} `json:"publicKey"`
}

func (a *authenticator) registrationResponse(t *testing.T, optionsJSON []byte, origin, rpIDOverride string) []byte {
	t.Helper()
	var options creationOptions
	if err := json.Unmarshal(optionsJSON, &options); err != nil {
		t.Fatalf("解析注册选项: %v", err)
	}
	rpID := options.PublicKey.RP.ID
	if rpIDOverride != "" {
		rpID = rpIDOverride
	}
	clientData := a.clientData("webauthn.create", options.PublicKey.Challenge, origin)
	flags := byte(0x01 | 0x40) // UP + AT
	if a.userVerified {
		flags |= 0x04 // UV
	}
	if a.backupEligible {
		flags |= 0x08
	}
	if a.backedUp {
		flags |= 0x10
	}
	auth := buildAuthData(rpID, flags, a.signCount, a.credentialID, coseES256(&a.key.PublicKey))
	attestation := attestationObject(auth)
	response := map[string]any{
		"id":                     base64.RawURLEncoding.EncodeToString(a.credentialID),
		"rawId":                  base64.RawURLEncoding.EncodeToString(a.credentialID),
		"type":                   "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
			"attestationObject": base64.RawURLEncoding.EncodeToString(attestation),
			"transports":        []string{"internal"},
		},
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("序列化注册响应: %v", err)
	}
	return encoded
}

func (a *authenticator) assertionResponse(t *testing.T, optionsJSON []byte, origin, rpIDOverride string,
	counter uint32, userHandle []byte) []byte {
	t.Helper()
	var options requestOptions
	if err := json.Unmarshal(optionsJSON, &options); err != nil {
		t.Fatalf("解析登录选项: %v", err)
	}
	rpID := options.PublicKey.RPID
	if rpIDOverride != "" {
		rpID = rpIDOverride
	}
	clientData := a.clientData("webauthn.get", options.PublicKey.Challenge, origin)
	flags := byte(0x01)
	if a.userVerified {
		flags |= 0x04
	}
	if a.backupEligible {
		flags |= 0x08
	}
	if a.backedUp {
		flags |= 0x10
	}
	auth := buildAuthData(rpID, flags, counter, nil, nil)
	clientDataHash := sha256.Sum256(clientData)
	signed := append(append([]byte(nil), auth...), clientDataHash[:]...)
	digest := sha256.Sum256(signed)
	signature, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatalf("签名: %v", err)
	}
	response := map[string]any{
		"id":                     base64.RawURLEncoding.EncodeToString(a.credentialID),
		"rawId":                  base64.RawURLEncoding.EncodeToString(a.credentialID),
		"type":                   "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
			"authenticatorData": base64.RawURLEncoding.EncodeToString(auth),
			"signature":         base64.RawURLEncoding.EncodeToString(signature),
		},
	}
	if len(userHandle) > 0 {
		response["response"].(map[string]any)["userHandle"] =
			base64.RawURLEncoding.EncodeToString(userHandle)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("序列化登录响应: %v", err)
	}
	return encoded
}

func (a *authenticator) clientData(ceremonyType, challenge, origin string) []byte {
	collected := map[string]any{
		"type": ceremonyType, "challenge": challenge, "origin": origin, "crossOrigin": false,
	}
	encoded, err := json.Marshal(collected)
	if err != nil {
		a.t.Fatalf("序列化 clientData: %v", err)
	}
	return encoded
}

func buildAuthData(rpID string, flags byte, counter uint32, credentialID, coseKey []byte) []byte {
	hash := sha256.Sum256([]byte(rpID))
	auth := append([]byte(nil), hash[:]...)
	auth = append(auth, flags)
	var counterBytes [4]byte
	binary.BigEndian.PutUint32(counterBytes[:], counter)
	auth = append(auth, counterBytes[:]...)
	if flags&0x40 != 0 {
		auth = append(auth, make([]byte, 16)...) // AAGUID
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(credentialID)))
		auth = append(auth, length[:]...)
		auth = append(auth, credentialID...)
		auth = append(auth, coseKey...)
	}
	return auth
}

// coseES256 构造最小合法的 ES256 COSE 公钥（CBOR 由测试手工编码）。
func coseES256(publicKey *ecdsa.PublicKey) []byte {
	x := publicKey.X.FillBytes(make([]byte, 32))
	y := publicKey.Y.FillBytes(make([]byte, 32))
	result := []byte{0xa5} // map(5)
	result = append(result, 0x01, 0x02)
	result = append(result, 0x03, 0x26) // alg: -7 (ES256)
	result = append(result, 0x20, 0x01) // crv: 1 (P-256)
	result = append(result, 0x21)
	result = append(result, cborBytes(x)...)
	result = append(result, 0x22)
	result = append(result, cborBytes(y)...)
	return result
}

func attestationObject(authData []byte) []byte {
	result := []byte{0xa3} // map(3)
	result = append(result, cborText("fmt")...)
	result = append(result, cborText("none")...)
	result = append(result, cborText("attStmt")...)
	result = append(result, 0xa0) // map(0)
	result = append(result, cborText("authData")...)
	result = append(result, cborBytes(authData)...)
	return result
}

func cborText(value string) []byte {
	header := cborHead(3, uint64(len(value)))
	return append(header, value...)
}

func cborBytes(value []byte) []byte {
	header := cborHead(2, uint64(len(value)))
	return append(header, value...)
}

func cborHead(major byte, length uint64) []byte {
	switch {
	case length < 24:
		return []byte{major<<5 | byte(length)}
	case length < 256:
		return []byte{major<<5 | 24, byte(length)}
	case length < 65536:
		return []byte{major<<5 | 25, byte(length >> 8), byte(length)}
	default:
		return []byte{major<<5 | 26, byte(length >> 24), byte(length >> 16),
			byte(length >> 8), byte(length)}
	}
}

// ===== 测试用例 =====

func TestRegisterListRenameAndReauth(t *testing.T) {
	env := newTestEnv(t, nil)
	simulator := newAuthenticator(t)
	meta := env.registerCredential(aliceID, "我的手机", simulator)
	if meta.ID == "" || meta.Name != "我的手机" || !strings.HasPrefix(meta.ID, "cred_") {
		t.Fatalf("凭证元数据异常: %+v", meta)
	}
	if len(env.runner.calls) != 1 || env.runner.calls[0] != "passkey.register" {
		t.Fatalf("注册应经过 passkey.register 敏感策略: %v", env.runner.calls)
	}
	if env.runner.notify != 1 {
		t.Fatalf("注册成功应发送安全告知: %d", env.runner.notify)
	}
	list, err := env.service.List(env.ctx, env.caller(aliceID))
	if err != nil || len(list) != 1 || list[0].ID != meta.ID {
		t.Fatalf("凭证列表: %+v err=%v", list, err)
	}
	renamed, err := env.service.Rename(env.ctx, env.caller(aliceID), passkey.RenameRequest{
		CredentialID: meta.ID, Name: "  笔记本  ", RequestID: "req-rename-1"})
	if err != nil || renamed.Name != "笔记本" {
		t.Fatalf("重命名: %+v err=%v", renamed, err)
	}
	// 句柄是随机值（与用户 ID 无关）、长度固定，且再次开始注册时保持不变。
	state, found, err := passkeysqliteHandle(env, aliceID)
	if err != nil || !found || len(state) != passkey.HandleBytes {
		t.Fatalf("用户句柄: len=%d err=%v", len(state), err)
	}
	if strings.Contains(string(state), aliceID) {
		t.Fatal("用户句柄不应包含用户 ID")
	}
	second, err := env.service.BeginRegistration(env.ctx, env.caller(aliceID), "req-register-3")
	if err != nil {
		t.Fatalf("再次开始注册: %v", err)
	}
	var options creationOptions
	if err := json.Unmarshal(second.PublicKey, &options); err != nil {
		t.Fatalf("解析注册选项: %v", err)
	}
	decodedHandle, decodeErr := base64.RawURLEncoding.DecodeString(options.PublicKey.User.ID)
	if decodeErr != nil {
		decodedHandle, decodeErr = base64.URLEncoding.DecodeString(options.PublicKey.User.ID)
	}
	if decodeErr != nil || string(decodedHandle) != string(state) {
		t.Fatalf("注册选项中的用户句柄应与存储句柄一致: %q err=%v", options.PublicKey.User.ID, decodeErr)
	}
}

// passkeysqliteHandle 直接读取用户句柄（测试观测用）。
func passkeysqliteHandle(env *testEnv, userID string) ([]byte, bool, error) {
	var handle []byte
	err := env.raw.DB().QueryRowContext(env.ctx,
		`SELECT handle FROM webauthn_user_handles WHERE user_id=?`, userID).Scan(&handle)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return nil, false, nil
		}
		return nil, false, err
	}
	return handle, true, nil
}

func TestRegistrationReplayAndOperationConfusion(t *testing.T) {
	env := newTestEnv(t, nil)
	simulator := newAuthenticator(t)
	start, err := env.service.BeginRegistration(env.ctx, env.caller(aliceID), "req-1")
	if err != nil {
		t.Fatalf("开始注册: %v", err)
	}
	response := simulator.registrationResponse(t, start.PublicKey, testOrigin, "")
	if _, err := env.service.FinishRegistration(env.ctx, env.caller(aliceID),
		passkey.RegistrationFinishRequest{CeremonyID: start.CeremonyID, Response: response,
			RequestID: "req-2"}); err != nil {
		t.Fatalf("首次注册: %v", err)
	}
	// 同一挑战/同一响应重放必须拒绝（挑战已一次性消费）。
	_, err = env.service.FinishRegistration(env.ctx, env.caller(aliceID),
		passkey.RegistrationFinishRequest{CeremonyID: start.CeremonyID, Response: response,
			RequestID: "req-3"})
	if !errors.Is(err, passkey.ErrCeremonyInvalid) {
		t.Fatalf("注册重放应被拒绝: %v", err)
	}
	// 注册挑战不能用于登录。
	loginStart, err := env.service.BeginLogin(env.ctx, passkey.LoginStartRequest{
		Username: "alice", RequestID: "req-4"})
	if err != nil {
		t.Fatalf("开始登录: %v", err)
	}
	loginResponse := simulator.assertionResponse(t, loginStart.PublicKey, testOrigin, "", 1, nil)
	_, err = env.service.FinishRegistration(env.ctx, env.caller(aliceID),
		passkey.RegistrationFinishRequest{CeremonyID: loginStart.CeremonyID,
			Response: loginResponse, RequestID: "req-5"})
	if !errors.Is(err, passkey.ErrCeremonyInvalid) {
		t.Fatalf("登录挑战不能用于注册: %v", err)
	}
}

func TestRegistrationRejectsWrongOriginAndRPIDAndUV(t *testing.T) {
	env := newTestEnv(t, nil)
	simulator := newAuthenticator(t)
	start, err := env.service.BeginRegistration(env.ctx, env.caller(aliceID), "req-1")
	if err != nil {
		t.Fatalf("开始注册: %v", err)
	}
	// 错误来源（恶意站点）：必须拒绝。
	response := simulator.registrationResponse(t, start.PublicKey, "https://evil.example.net", "")
	if _, err := env.service.FinishRegistration(env.ctx, env.caller(aliceID),
		passkey.RegistrationFinishRequest{CeremonyID: start.CeremonyID, Response: response,
			RequestID: "req-2"}); !errors.Is(err, passkey.ErrCeremonyInvalid) {
		t.Fatalf("错误来源应被拒绝: %v", err)
	}
	// 错误 RP ID（认证器数据 rpIdHash 不匹配）：必须拒绝。
	start, err = env.service.BeginRegistration(env.ctx, env.caller(aliceID), "req-3")
	if err != nil {
		t.Fatalf("开始注册: %v", err)
	}
	response = simulator.registrationResponse(t, start.PublicKey, testOrigin, "evil.example.net")
	if _, err := env.service.FinishRegistration(env.ctx, env.caller(aliceID),
		passkey.RegistrationFinishRequest{CeremonyID: start.CeremonyID, Response: response,
			RequestID: "req-4"}); !errors.Is(err, passkey.ErrCeremonyInvalid) {
		t.Fatalf("错误 RP ID 应被拒绝: %v", err)
	}
	// UV 策略 required 时缺少 UV 标志：必须拒绝。
	start, err = env.service.BeginRegistration(env.ctx, env.caller(aliceID), "req-5")
	if err != nil {
		t.Fatalf("开始注册: %v", err)
	}
	noUV := newAuthenticator(t)
	noUV.userVerified = false
	response = noUV.registrationResponse(t, start.PublicKey, testOrigin, "")
	if _, err := env.service.FinishRegistration(env.ctx, env.caller(aliceID),
		passkey.RegistrationFinishRequest{CeremonyID: start.CeremonyID, Response: response,
			RequestID: "req-6"}); !errors.Is(err, passkey.ErrCeremonyInvalid) {
		t.Fatalf("缺少 UV 应被拒绝: %v", err)
	}
}

func TestCredentialConflictCannotClaimAnotherUsersCredential(t *testing.T) {
	env := newTestEnv(t, nil)
	attacker := newAuthenticator(t)
	env.registerCredential(bobID, "bob 的凭证", attacker)
	// alice 尝试用 bob 的凭证 ID 注册到自己名下：凭证 ID 全局唯一必须拒绝。
	simulator := newAuthenticator(t)
	simulator.credentialID = append([]byte(nil), attacker.credentialID...)
	start, err := env.service.BeginRegistration(env.ctx, env.caller(aliceID), "req-1")
	if err != nil {
		t.Fatalf("开始注册: %v", err)
	}
	response := simulator.registrationResponse(t, start.PublicKey, testOrigin, "")
	_, err = env.service.FinishRegistration(env.ctx, env.caller(aliceID),
		passkey.RegistrationFinishRequest{CeremonyID: start.CeremonyID, Response: response,
			RequestID: "req-2"})
	if !errors.Is(err, passkey.ErrCredentialConflict) {
		t.Fatalf("重复凭证 ID 应冲突拒绝: %v", err)
	}
	list, err := env.service.List(env.ctx, env.caller(aliceID))
	if err != nil || len(list) != 0 {
		t.Fatalf("冲突后不应创建凭证: %+v err=%v", list, err)
	}
}

func TestUsernameLoginIssuesCompleteSession(t *testing.T) {
	env := newTestEnv(t, nil)
	simulator := newAuthenticator(t)
	env.registerCredential(aliceID, "手机", simulator)
	simulator.signCount = 1
	start, err := env.service.BeginLogin(env.ctx, passkey.LoginStartRequest{
		Username: "Alice", RequestID: "req-login-1"})
	if err != nil {
		t.Fatalf("开始登录: %v", err)
	}
	response := simulator.assertionResponse(t, start.PublicKey, testOrigin, "", 1, nil)
	result, err := env.service.FinishLogin(env.ctx, passkey.LoginFinishRequest{
		CeremonyID: start.CeremonyID, Response: response, RequestID: "req-login-2"})
	if err != nil {
		t.Fatalf("完成登录: %v", err)
	}
	if !result.Authenticated.IsComplete() || result.Session.Session.IsRestricted() {
		t.Fatalf("登录结果不是完整会话: %+v", result.Authenticated)
	}
	if len(result.Authenticated.CompletedMethods) != 1 ||
		result.Authenticated.CompletedMethods[0] != "passkey" {
		t.Fatalf("认证方法应只有 passkey（不追加同源因素）: %v", result.Authenticated.CompletedMethods)
	}
	if !result.UserVerified {
		t.Fatal("应记录本次用户验证")
	}
	validated, err := env.session.Validate(env.ctx, result.Session.Secret.Reveal())
	if err != nil || validated.UserID != aliceID || validated.AppID != "" {
		t.Fatalf("会话校验: %+v err=%v", validated, err)
	}
	// 同一挑战/响应重放：挑战已消费且单赢家。
	if _, err := env.service.FinishLogin(env.ctx, passkey.LoginFinishRequest{
		CeremonyID: start.CeremonyID, Response: response, RequestID: "req-login-3"}); !errors.Is(err, passkey.ErrCeremonyInvalid) {
		t.Fatalf("登录重放应被拒绝: %v", err)
	}
}

func TestDiscoverableLoginAndWrongUserHandle(t *testing.T) {
	env := newTestEnv(t, nil)
	aliceAuth := newAuthenticator(t)
	env.registerCredential(aliceID, "alice", aliceAuth)
	bobAuth := newAuthenticator(t)
	env.registerCredential(bobID, "bob", bobAuth)
	aliceHandle, _, err := passkeysqliteHandle(env, aliceID)
	if err != nil {
		t.Fatalf("alice 句柄: %v", err)
	}
	// 可发现凭证登录：不提供用户名，由认证器返回用户句柄。
	start, err := env.service.BeginLogin(env.ctx, passkey.LoginStartRequest{RequestID: "req-1"})
	if err != nil {
		t.Fatalf("开始可发现凭证登录: %v", err)
	}
	response := aliceAuth.assertionResponse(t, start.PublicKey, testOrigin, "", 1, aliceHandle)
	result, err := env.service.FinishLogin(env.ctx, passkey.LoginFinishRequest{
		CeremonyID: start.CeremonyID, Response: response, RequestID: "req-2"})
	if err != nil || result.Session.Session.UserID != aliceID {
		t.Fatalf("可发现凭证登录: user=%v err=%v", result.Session.Session.UserID, err)
	}
	// 把 alice 的凭证连同 bob 的用户句柄提交：必须失败（不能登记/登录成他人）。
	start, err = env.service.BeginLogin(env.ctx, passkey.LoginStartRequest{RequestID: "req-3"})
	if err != nil {
		t.Fatalf("开始可发现凭证登录: %v", err)
	}
	bobHandle, _, err := passkeysqliteHandle(env, bobID)
	if err != nil {
		t.Fatalf("bob 句柄: %v", err)
	}
	forged := aliceAuth.assertionResponse(t, start.PublicKey, testOrigin, "", 2, bobHandle)
	if _, err := env.service.FinishLogin(env.ctx, passkey.LoginFinishRequest{
		CeremonyID: start.CeremonyID, Response: forged, RequestID: "req-4"}); !errors.Is(err, passkey.ErrAuthenticationFailed) {
		t.Fatalf("他人凭证+他人句柄应拒绝: %v", err)
	}
}

func TestWrongOriginLoginRejected(t *testing.T) {
	env := newTestEnv(t, nil)
	simulator := newAuthenticator(t)
	env.registerCredential(aliceID, "手机", simulator)
	start, err := env.service.BeginLogin(env.ctx, passkey.LoginStartRequest{
		Username: "alice", RequestID: "req-1"})
	if err != nil {
		t.Fatalf("开始登录: %v", err)
	}
	response := simulator.assertionResponse(t, start.PublicKey, "https://evil.example.net", "", 1, nil)
	if _, err := env.service.FinishLogin(env.ctx, passkey.LoginFinishRequest{
		CeremonyID: start.CeremonyID, Response: response, RequestID: "req-2"}); !errors.Is(err, passkey.ErrAuthenticationFailed) {
		t.Fatalf("错误来源登录应拒绝: %v", err)
	}
}

func TestSyncedCredentialCounterMayNotIncrement(t *testing.T) {
	env := newTestEnv(t, nil)
	synced := newAuthenticator(t)
	synced.backupEligible = true
	synced.backedUp = true
	synced.signCount = 0
	env.registerCredential(aliceID, "同步 Passkey", synced)
	// 同步凭证计数器保持 0：允许登录并保持计数为 0。
	synced.signCount = 0
	start, err := env.service.BeginLogin(env.ctx, passkey.LoginStartRequest{
		Username: "alice", RequestID: "req-1"})
	if err != nil {
		t.Fatalf("开始登录: %v", err)
	}
	response := synced.assertionResponse(t, start.PublicKey, testOrigin, "", 0, nil)
	if _, err := env.service.FinishLogin(env.ctx, passkey.LoginFinishRequest{
		CeremonyID: start.CeremonyID, Response: response, RequestID: "req-2"}); err != nil {
		t.Fatalf("同步凭证计数器不递增应允许登录: %v", err)
	}
	// 非同步凭证计数器不递增：按可能的凭证复制拒绝。
	hardware := newAuthenticator(t)
	hardware.signCount = 5
	env.registerCredential(bobID, "硬件密钥", hardware)
	start, err = env.service.BeginLogin(env.ctx, passkey.LoginStartRequest{
		Username: "bob", RequestID: "req-3"})
	if err != nil {
		t.Fatalf("开始登录: %v", err)
	}
	response = hardware.assertionResponse(t, start.PublicKey, testOrigin, "", 5, nil)
	if _, err := env.service.FinishLogin(env.ctx, passkey.LoginFinishRequest{
		CeremonyID: start.CeremonyID, Response: response, RequestID: "req-4"}); !errors.Is(err, passkey.ErrCloneDetected) {
		t.Fatalf("非同步凭证计数器不递增应拒绝: %v", err)
	}
	// 正常递增的硬件密钥登录成功，并推进计数。
	start, err = env.service.BeginLogin(env.ctx, passkey.LoginStartRequest{
		Username: "bob", RequestID: "req-5"})
	if err != nil {
		t.Fatalf("开始登录: %v", err)
	}
	response = hardware.assertionResponse(t, start.PublicKey, testOrigin, "", 6, nil)
	if _, err := env.service.FinishLogin(env.ctx, passkey.LoginFinishRequest{
		CeremonyID: start.CeremonyID, Response: response, RequestID: "req-6"}); err != nil {
		t.Fatalf("计数器递增登录应成功: %v", err)
	}
}

func TestAppScopedLoginDoesNotUpgradeToGlobalSession(t *testing.T) {
	env := newTestEnv(t, nil)
	env.addAppMembership(aliceID)
	simulator := newAuthenticator(t)
	env.registerCredential(aliceID, "手机", simulator)
	start, err := env.service.BeginLogin(env.ctx, passkey.LoginStartRequest{
		Username: "alice", AppID: appID, RememberMe: true, RequestID: "req-1"})
	if err != nil {
		t.Fatalf("开始应用登录: %v", err)
	}
	response := simulator.assertionResponse(t, start.PublicKey, testOrigin, "", 1, nil)
	result, err := env.service.FinishLogin(env.ctx, passkey.LoginFinishRequest{
		CeremonyID: start.CeremonyID, Response: response, RequestID: "req-2"})
	if err != nil {
		t.Fatalf("完成应用登录: %v", err)
	}
	if result.Session.Session.AppID != appID || result.Session.Session.IsRestricted() {
		t.Fatalf("应用作用域会话被升级或错误: %+v", result.Session.Session)
	}
	validated, err := env.session.Validate(env.ctx, result.Session.Secret.Reveal())
	if err != nil || validated.AppID != appID {
		t.Fatalf("应用会话校验: %+v err=%v", validated, err)
	}
}

func TestRevokeProtectsLastLoginMethod(t *testing.T) {
	env := newTestEnv(t, nil)
	simulator := newAuthenticator(t)
	meta := env.registerCredential(aliceID, "唯一凭证", simulator)
	// 账户没有主密码：不能撤销最后一个登录方式。
	if err := env.service.Revoke(env.ctx, env.caller(aliceID), passkey.RevokeRequest{
		CredentialID: meta.ID, RequestID: "req-1"}); !errors.Is(err, passkey.ErrLastLoginMethod) {
		t.Fatalf("最后登录方式应被保护: %v", err)
	}
	if len(env.runner.calls) != 2 || env.runner.calls[1] != "passkey.remove" {
		t.Fatalf("撤销应经过 passkey.remove 敏感策略: %v", env.runner.calls)
	}
	// 有可用主密码后允许撤销；重复撤销返回不存在。
	env.addPassword(aliceID)
	if err := env.service.Revoke(env.ctx, env.caller(aliceID), passkey.RevokeRequest{
		CredentialID: meta.ID, RequestID: "req-2"}); err != nil {
		t.Fatalf("有密码时撤销: %v", err)
	}
	list, err := env.service.List(env.ctx, env.caller(aliceID))
	if err != nil || len(list) != 0 {
		t.Fatalf("撤销后列表应为空: %+v err=%v", list, err)
	}
	if err := env.service.Revoke(env.ctx, env.caller(aliceID), passkey.RevokeRequest{
		CredentialID: meta.ID, RequestID: "req-3"}); !errors.Is(err, passkey.ErrCredentialNotFound) {
		t.Fatalf("重复撤销: %v", err)
	}
	// 另一个用户的凭证不能被撤销。
	env2 := newTestEnv(t, nil)
	bobMeta := env2.registerCredential(bobID, "bob", newAuthenticator(t))
	if err := env2.service.Revoke(env2.ctx, env2.caller(aliceID), passkey.RevokeRequest{
		CredentialID: bobMeta.ID, RequestID: "req-4"}); !errors.Is(err, passkey.ErrCredentialNotFound) {
		t.Fatalf("跨用户撤销应拒绝: %v", err)
	}
}

func TestReauthFailClosed(t *testing.T) {
	env := newTestEnv(t, func(options *passkey.Options) { options.Reauth = nil })
	simulator := newAuthenticator(t)
	start, err := env.service.BeginRegistration(env.ctx, env.caller(aliceID), "req-1")
	if err != nil {
		t.Fatalf("开始注册: %v", err)
	}
	response := simulator.registrationResponse(t, start.PublicKey, testOrigin, "")
	_, err = env.service.FinishRegistration(env.ctx, env.caller(aliceID),
		passkey.RegistrationFinishRequest{CeremonyID: start.CeremonyID, Response: response,
			RequestID: "req-2"})
	if !errors.Is(err, passkey.ErrReauthRequired) {
		t.Fatalf("缺少再次认证应 fail-closed: %v", err)
	}
	if _, err := env.service.List(env.ctx, env.caller(aliceID)); err != nil {
		t.Fatalf("列表: %v", err)
	}
	// 再次认证返回强认证不足时映射 MFA_REQUIRED，且不创建凭证。
	env2 := newTestEnv(t, func(options *passkey.Options) {
		options.Reauth = &fakeRunner{err: reauth.ErrMFARequired}
	})
	start, err = env2.service.BeginRegistration(env2.ctx, env2.caller(aliceID), "req-3")
	if err != nil {
		t.Fatalf("开始注册: %v", err)
	}
	response = simulator.registrationResponse(t, start.PublicKey, testOrigin, "")
	_, err = env2.service.FinishRegistration(env2.ctx, env2.caller(aliceID),
		passkey.RegistrationFinishRequest{CeremonyID: start.CeremonyID, Response: response,
			RequestID: "req-4"})
	if !errors.Is(err, passkey.ErrMFARequired) {
		t.Fatalf("强认证不足应拒绝: %v", err)
	}
}

func TestUnknownUserAndDisabledAccountUniformFailure(t *testing.T) {
	env := newTestEnv(t, nil)
	if _, err := env.service.BeginLogin(env.ctx, passkey.LoginStartRequest{
		Username: "nobody", RequestID: "req-1"}); !errors.Is(err, passkey.ErrAuthenticationFailed) {
		t.Fatalf("未知用户应统一失败: %v", err)
	}
	if _, err := env.raw.DB().ExecContext(env.ctx,
		`UPDATE users SET status='disabled' WHERE id=?`, aliceID); err != nil {
		t.Fatalf("禁用账户: %v", err)
	}
	// 禁用账户与未知用户返回同一错误，不泄露账户状态。
	if _, err := env.service.BeginLogin(env.ctx, passkey.LoginStartRequest{
		Username: "alice", RequestID: "req-2"}); !errors.Is(err, passkey.ErrAuthenticationFailed) {
		t.Fatalf("禁用账户应统一失败: %v", err)
	}
}

func TestCeremonyExpiry(t *testing.T) {
	env := newTestEnv(t, nil)
	simulator := newAuthenticator(t)
	start, err := env.service.BeginRegistration(env.ctx, env.caller(aliceID), "req-1")
	if err != nil {
		t.Fatalf("开始注册: %v", err)
	}
	env.now = env.now.Add(passkey.DefaultCeremonyTTL + time.Minute)
	response := simulator.registrationResponse(t, start.PublicKey, testOrigin, "")
	if _, err := env.service.FinishRegistration(env.ctx, env.caller(aliceID),
		passkey.RegistrationFinishRequest{CeremonyID: start.CeremonyID, Response: response,
			RequestID: "req-2"}); !errors.Is(err, passkey.ErrCeremonyExpired) {
		t.Fatalf("过期挑战应拒绝: %v", err)
	}
}

func TestConfigValidationFailsClosed(t *testing.T) {
	storeNeeded := newTestEnv(t, nil)
	cases := []passkey.Config{
		{RPID: "", Origins: []string{testOrigin}},
		{RPID: "https://login.example.com", Origins: []string{testOrigin}},
		{RPID: "127.0.0.1", Origins: []string{"http://127.0.0.1"}},
		{RPID: testRPID, Origins: nil},
		{RPID: testRPID, Origins: []string{"http://login.example.com"}},
		{RPID: testRPID, Origins: []string{"https://evil.example.net"}},
		{RPID: testRPID, Origins: []string{"https://login.example.com/path"}},
		{RPID: testRPID, Origins: []string{testOrigin}, UserVerification: "unknown"},
	}
	for index, config := range cases {
		if _, err := passkey.New(passkey.Options{
			Store: storeNeeded.store, Audit: storeNeeded.recorder,
			Sessions: storeNeeded.session, Reauth: storeNeeded.runner, Config: config,
		}); err == nil {
			t.Errorf("配置 %d 应被拒绝: %+v", index, config)
		}
	}
	if err := passkey.ValidateRPConfig("localhost", []string{"http://localhost:8080"}); err != nil {
		t.Errorf("localhost 本地开发来源应允许: %v", err)
	}
	if err := passkey.ValidateRPConfig(testRPID, []string{"http://localhost:8080"}); err == nil {
		t.Error("RP ID 与来源主机不匹配时应拒绝")
	}
}
