package app

// 步骤 222：通过公开 MFA 门面完成真实软件 WebAuthn 注册与免密码登录 ceremony。
// 认证器由测试用 P-256 私钥与手工编码的 CBOR/authenticatorData 构造（仅测试，不
// 代表真实硬件/浏览器已测）；验证的是公开入口 -> internal/passkey 的完整挑战、
// 来源/RP ID/签名/counter/UV 校验链。

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

const (
	mfa222RPID   = "login.example.test"
	mfa222Origin = "https://login.example.test"
)

// mfa222Authenticator 是测试专用软件认证器。
type mfa222Authenticator struct {
	t              *testing.T
	key            *ecdsa.PrivateKey
	credentialID   []byte
	signCount      uint32
	userVerified   bool
	backupEligible bool
	backedUp       bool
	origin         string
	rpID           string
}

func newMFA222Authenticator(t *testing.T) *mfa222Authenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成认证器密钥: %v", err)
	}
	credentialID := make([]byte, 32)
	if _, err := rand.Read(credentialID); err != nil {
		t.Fatalf("凭证 ID: %v", err)
	}
	return &mfa222Authenticator{t: t, key: key, credentialID: credentialID,
		userVerified: true, origin: mfa222Origin, rpID: mfa222RPID}
}

type mfa222CreationOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	} `json:"publicKey"`
}

type mfa222RequestOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RPID      string `json:"rpId"`
	} `json:"publicKey"`
}

func (a *mfa222Authenticator) registrationResponse(optionsJSON []byte,
	origin, rpIDOverride string) []byte {
	a.t.Helper()
	var options mfa222CreationOptions
	if err := json.Unmarshal(optionsJSON, &options); err != nil {
		a.t.Fatalf("解析注册选项: %v", err)
	}
	rpID := options.PublicKey.RP.ID
	if rpIDOverride != "" {
		rpID = rpIDOverride
	}
	clientData := a.clientData("webauthn.create", options.PublicKey.Challenge, origin)
	flags := byte(0x01 | 0x40) // UP + AT
	if a.userVerified {
		flags |= 0x04
	}
	if a.backupEligible {
		flags |= 0x08
	}
	if a.backedUp {
		flags |= 0x10
	}
	authData := mfa222BuildAuthData(rpID, flags, a.signCount, a.credentialID,
		mfa222COSEES256(&a.key.PublicKey))
	attestation := mfa222AttestationObject(authData)
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
		a.t.Fatalf("序列化注册响应: %v", err)
	}
	return encoded
}

func (a *mfa222Authenticator) assertionResponse(optionsJSON []byte,
	origin, rpIDOverride string, counter uint32) []byte {
	a.t.Helper()
	var options mfa222RequestOptions
	if err := json.Unmarshal(optionsJSON, &options); err != nil {
		a.t.Fatalf("解析登录选项: %v", err)
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
	authData := mfa222BuildAuthData(rpID, flags, counter, nil, nil)
	clientDataHash := sha256.Sum256(clientData)
	signed := append(append([]byte(nil), authData...), clientDataHash[:]...)
	digest := sha256.Sum256(signed)
	signature, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		a.t.Fatalf("签名: %v", err)
	}
	response := map[string]any{
		"id":                     base64.RawURLEncoding.EncodeToString(a.credentialID),
		"rawId":                  base64.RawURLEncoding.EncodeToString(a.credentialID),
		"type":                   "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
			"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
			"signature":         base64.RawURLEncoding.EncodeToString(signature),
		},
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		a.t.Fatalf("序列化登录响应: %v", err)
	}
	return encoded
}

func (a *mfa222Authenticator) clientData(ceremonyType, challenge, origin string) []byte {
	collected := map[string]any{
		"type": ceremonyType, "challenge": challenge, "origin": origin, "crossOrigin": false,
	}
	encoded, err := json.Marshal(collected)
	if err != nil {
		a.t.Fatalf("序列化 clientData: %v", err)
	}
	return encoded
}

func mfa222BuildAuthData(rpID string, flags byte, counter uint32,
	credentialID, coseKey []byte) []byte {
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

// mfa222COSEES256 构造最小合法 ES256 COSE 公钥（CBOR 手工编码）。
func mfa222COSEES256(publicKey *ecdsa.PublicKey) []byte {
	x := publicKey.X.FillBytes(make([]byte, 32))
	y := publicKey.Y.FillBytes(make([]byte, 32))
	result := []byte{0xa5} // map(5)
	result = append(result, 0x01, 0x02)
	result = append(result, 0x03, 0x26) // alg: -7 (ES256)
	result = append(result, 0x20, 0x01) // crv: 1 (P-256)
	result = append(result, 0x21)
	result = append(result, mfa222CBORBytes(x)...)
	result = append(result, 0x22)
	result = append(result, mfa222CBORBytes(y)...)
	return result
}

func mfa222AttestationObject(authData []byte) []byte {
	result := []byte{0xa3} // map(3)
	result = append(result, mfa222CBORText("fmt")...)
	result = append(result, mfa222CBORText("none")...)
	result = append(result, mfa222CBORText("attStmt")...)
	result = append(result, 0xa0)
	result = append(result, mfa222CBORText("authData")...)
	result = append(result, mfa222CBORBytes(authData)...)
	return result
}

func mfa222CBORText(value string) []byte {
	header := mfa222CBORHead(3, uint64(len(value)))
	return append(header, value...)
}

func mfa222CBORBytes(value []byte) []byte {
	header := mfa222CBORHead(2, uint64(len(value)))
	return append(header, value...)
}

func mfa222CBORHead(major byte, length uint64) []byte {
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

// TestMFAPublicWebAuthnRegistrationAndPasswordlessLogin 覆盖公开入口的完整
// WebAuthn 注册与免密码登录 ceremony（错误来源拒绝、一次性 ceremony 重放拒绝）。
func TestMFAPublicWebAuthnRegistrationAndPasswordlessLogin(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 7, 0, 0, 0, time.UTC))
	cfg := testConfig()
	cfg.Passkey.Enabled = true
	cfg.Passkey.RPID = mfa222RPID
	cfg.Passkey.RPDisplayName = "EvernightLogin Test"
	cfg.Passkey.AllowedOrigins = []string{mfa222Origin}
	cfg.Passkey.UserVerification = "required"
	runtime := openTestRuntime(t, Options{Config: &cfg, Now: clock.Now})

	const username = "mfa-webauthn-user"
	const password = "W9$hK4!pR7@tY2#n"
	user, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: username, Password: password, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建用户: %v", err)
	}
	session, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: username, Password: password, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil || session.Restricted {
		t.Fatalf("初始登录: %+v err=%v", session, err)
	}

	authenticator := newMFA222Authenticator(t)
	// 错误来源的注册响应：WebAuthn 校验拒绝，不产生凭证。
	badStart, err := runtime.MFA().BeginPasskeyRegistration(ctx,
		MFAPasskeyRegisterBeginRequest{SessionSecret: session.SessionSecret,
			Purpose: "login", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("开始注册（错误来源用例）: %v", err)
	}
	badResponse := authenticator.registrationResponse(badStart.PublicKey,
		"https://evil.example.test", "")
	if _, err := runtime.MFA().FinishPasskeyRegistration(ctx,
		MFAPasskeyRegisterFinishRequest{SessionSecret: session.SessionSecret,
			CeremonyID: badStart.CeremonyID, Response: badResponse,
			Name: "错误来源", Password: password,
			RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("错误来源的 Passkey 注册响应必须被拒绝")
	}

	// 真实来源的完整注册 ceremony。
	start, err := runtime.MFA().BeginPasskeyRegistration(ctx,
		MFAPasskeyRegisterBeginRequest{SessionSecret: session.SessionSecret,
			Purpose: "login", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("开始注册: %v", err)
	}
	response := authenticator.registrationResponse(start.PublicKey, mfa222Origin, "")
	credential, err := runtime.MFA().FinishPasskeyRegistration(ctx,
		MFAPasskeyRegisterFinishRequest{SessionSecret: session.SessionSecret,
			CeremonyID: start.CeremonyID, Response: response,
			Name: "软件认证器", Password: password, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("完成注册: %v", err)
	}
	if credential.ID == "" || credential.Name != "软件认证器" {
		t.Fatalf("注册凭证元数据 = %+v", credential)
	}
	// 同一 ceremony 不能重放注册。
	if _, err := runtime.MFA().FinishPasskeyRegistration(ctx,
		MFAPasskeyRegisterFinishRequest{SessionSecret: session.SessionSecret,
			CeremonyID: start.CeremonyID, Response: response,
			Name: "重放", Password: password,
			RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("重放注册 ceremony 必须被拒绝")
	}
	list, err := runtime.MFA().ListPasskeys(ctx, MFAPasskeyListRequest{
		SessionSecret: session.SessionSecret, RequestID: login.NewRequestID()})
	if err != nil || len(list) != 1 || list[0].ID != credential.ID {
		t.Fatalf("注册后 Passkey 列表 = %+v err=%v", list, err)
	}

	// 免密码登录 ceremony（用户名路径）。
	loginStart, err := runtime.MFA().BeginPasskeyLogin(ctx, MFAPasskeyLoginBeginRequest{
		Username: username, AppID: "", ClientIP: "127.0.0.1",
		UserAgent: "mfa222-test", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("开始免密码登录: %v", err)
	}
	assertion := authenticator.assertionResponse(loginStart.PublicKey,
		mfa222Origin, "", 1)
	loggedIn, err := runtime.MFA().FinishPasskeyLogin(ctx,
		MFAPasskeyLoginFinishRequest{CeremonyID: loginStart.CeremonyID,
			Response: assertion, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("完成免密码登录: %v", err)
	}
	if loggedIn.UserID != user.ID || len(loggedIn.SessionSecret) == 0 ||
		loggedIn.Method != "passkey" {
		t.Fatalf("免密码登录结果 = %+v", loggedIn)
	}
	// 签发的完整会话可通过公开会话门面验证。
	info, err := runtime.Sessions().Validate(ctx, loggedIn.SessionSecret)
	if err != nil || info.UserID != user.ID {
		t.Fatalf("Passkey 登录会话验证 = %+v err=%v", info, err)
	}
	// 已消费的登录 ceremony 重放拒绝。
	if _, err := runtime.MFA().FinishPasskeyLogin(ctx,
		MFAPasskeyLoginFinishRequest{CeremonyID: loginStart.CeremonyID,
			Response: assertion, RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("重放 Passkey 登录 ceremony 必须被拒绝")
	}

	// 撤销 Passkey：错误密码再认证拒绝；正确密码成功后凭证消失且会话失效。
	if err := runtime.MFA().RemovePasskey(ctx, MFAPasskeyRemoveRequest{
		SessionSecret: loggedIn.SessionSecret, CredentialID: credential.ID,
		Password: "Wrong!Passw0rd", RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("错误密码不应通过撤销 Passkey 的再次认证")
	}
	if err := runtime.MFA().RemovePasskey(ctx, MFAPasskeyRemoveRequest{
		SessionSecret: loggedIn.SessionSecret, CredentialID: credential.ID,
		Password: password, RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("撤销 Passkey: %v", err)
	}
	// 撤销凭证递增安全版本并撤销既有会话：旧会话失效。
	if _, err := runtime.MFA().ListPasskeys(ctx, MFAPasskeyListRequest{
		SessionSecret: loggedIn.SessionSecret,
		RequestID:     login.NewRequestID()}); err == nil {
		t.Fatal("撤销 Passkey 后旧会话必须失效")
	}
	relogin, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: username, Password: password, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil || relogin.Restricted {
		t.Fatalf("撤销 Passkey 后密码登录: %+v err=%v", relogin, err)
	}
	remaining, err := runtime.MFA().ListPasskeys(ctx, MFAPasskeyListRequest{
		SessionSecret: relogin.SessionSecret, RequestID: login.NewRequestID()})
	if err != nil || len(remaining) != 0 {
		t.Fatalf("撤销后 Passkey 列表 = %+v err=%v", remaining, err)
	}
}
