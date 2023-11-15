// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

// OAuth 客户端凭证与安全设置公开 Go 接口（步骤 225 P0）。
//
// 边界：
//   - 复用 internal/oauthclient：客户端类型（public/confidential）、身份验证方式、
//     重定向/scope/audience/PKCE 设置、密钥轮换/撤销/列表、mTLS 证书身份；
//   - 客户端密钥明文只在登记/轮换响应出现一次，服务端只存摘要；本门面不提供任何
//     后续读取明文的接口，结果/错误/日志不包含秘密；
//   - 轮换有真实过渡窗口（旧密钥在领域配置的 grace period 内仍可用，之后失效），
//     撤销按密钥 ID，最后一个可用密钥不能被撤销导致自锁（内部判定）；
//   - 敏感操作走真实再次认证（LocalAdmin 本地审批审计；AdminSession 密码+强因素），
//     复用既有 policy 操作 ID，不新增策略键；
//   - 访问器 Runtime.OAuthClients() 定义在本文件，不编辑 runtime.go/admin.go/types.go。

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
)

// OAuthClientAdminService 是 OAuth 客户端凭证/安全设置公开门面。
type OAuthClientAdminService interface {
	RegisterClient(ctx context.Context,
		req AdminRegisterOAuthClientRequest) (AdminOAuthClientRegistration, error)
	GetClient(ctx context.Context, req AdminOAuthClientRequest) (AdminOAuthClient, error)
	UpdateClientSettings(ctx context.Context,
		req AdminUpdateOAuthClientSettingsRequest) (AdminOAuthClient, error)
	RotateClientSecret(ctx context.Context,
		req AdminOAuthClientSecretRotateRequest) (AdminRevealedClientSecret, error)
	RevokeClientSecret(ctx context.Context, req AdminOAuthClientSecretRevokeRequest) error
	ListClientSecrets(ctx context.Context,
		req AdminOAuthClientRequest) ([]AdminClientSecretInfo, error)
	RegisterClientCertificate(ctx context.Context,
		req AdminOAuthClientCertificateRequest) (AdminClientCertificateInfo, error)
	RevokeClientCertificate(ctx context.Context,
		req AdminOAuthClientCertificateRequest) error
	ListClientCertificates(ctx context.Context,
		req AdminOAuthClientRequest) ([]AdminClientCertificateInfo, error)
}

// AdminOAuthClient 是客户端安全设置的脱敏视图（不含凭证材料）。
type AdminOAuthClient struct {
	ClientID               string
	ClientType             string
	GrantTypes             []string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	Scopes                 []string
	Audiences              []string
	AuthMethods            []string
	RequirePKCE            bool
	RowVersion             int64
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

// AdminRegisterOAuthClientRequest 登记客户端安全设置与初始凭证。
type AdminRegisterOAuthClientRequest struct {
	Caller                 AdminCaller
	ClientID               string
	ClientType             string
	GrantTypes             []string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	Scopes                 []string
	Audiences              []string
	AuthMethods            []string
	RequirePKCE            *bool
	CertificatePEM         string
	// Password/TOTPCode 只用于本次真实再次认证，不保存/不记录。
	Password  string
	TOTPCode  string
	RequestID string
}

// AdminOAuthClientRegistration 是登记结果；Secret 明文只在本响应出现一次。
type AdminOAuthClientRegistration struct {
	Client      AdminOAuthClient
	Secret      *AdminRevealedClientSecret
	Certificate *AdminClientCertificateInfo
}

// AdminOAuthClientRequest 读取单个客户端/凭证列表。
type AdminOAuthClientRequest struct {
	Caller    AdminCaller
	ClientID  string
	RequestID string
}

// AdminUpdateOAuthClientSettingsRequest 更新客户端安全设置。
type AdminUpdateOAuthClientSettingsRequest struct {
	Caller                 AdminCaller
	ClientID               string
	GrantTypes             []string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	Scopes                 []string
	Audiences              []string
	RequirePKCE            *bool
	ExpectedRowVersion     int64
	Password               string
	TOTPCode               string
	RequestID              string
}

// AdminClientSecretInfo 是客户端密钥展示信息（不含明文/摘要）。
type AdminClientSecretInfo struct {
	ID        string
	Prefix    string
	CreatedAt time.Time
	ExpiresAt time.Time
	RetireAt  time.Time
	RevokedAt time.Time
}

// AdminRevealedClientSecret 是只在登记/轮换响应出现一次的明文密钥。
type AdminRevealedClientSecret struct {
	ClientID string
	Info     AdminClientSecretInfo
	// Secret 是明文客户端密钥；调用方必须立即安全保存，服务端不再返回。
	Secret string
}

// AdminClientCertificateInfo 是客户端证书身份展示信息（证书本身为公开材料）。
type AdminClientCertificateInfo struct {
	ID                string
	ClientID          string
	FingerprintSHA256 string
	Subject           string
	NotBefore         time.Time
	NotAfter          time.Time
	CreatedAt         time.Time
	RevokedAt         time.Time
}

// AdminOAuthClientSecretRotateRequest 轮换客户端密钥。
type AdminOAuthClientSecretRotateRequest struct {
	Caller    AdminCaller
	ClientID  string
	Password  string
	TOTPCode  string
	RequestID string
}

// AdminOAuthClientSecretRevokeRequest 撤销指定密钥。
type AdminOAuthClientSecretRevokeRequest struct {
	Caller    AdminCaller
	ClientID  string
	SecretID  string
	Password  string
	TOTPCode  string
	RequestID string
}

// AdminOAuthClientCertificateRequest 登记/撤销客户端证书身份。
type AdminOAuthClientCertificateRequest struct {
	Caller         AdminCaller
	ClientID       string
	CertificateID  string
	CertificatePEM string
	Password       string
	TOTPCode       string
	RequestID      string
}

// OAuthClients 返回 OAuth 客户端公开门面。
func (r *Runtime) OAuthClients() OAuthClientAdminService {
	return &oauthClientsFacade{r: r}
}

type oauthClientsFacade struct {
	r *Runtime
}

func (f *oauthClientsFacade) admin() *adminFacade {
	return &adminFacade{r: f.r}
}

// beginClient 完成身份、服务与调用者前置。
func (f *oauthClientsFacade) beginClient(ctx context.Context, caller AdminCaller,
	requestID string) (adminRequest, *oauthclient.Service, oauthclient.Caller, error) {
	call, err := f.admin().begin(ctx, caller, requestID)
	if err != nil {
		return adminRequest{}, nil, oauthclient.Caller{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.OAuthClient == nil {
		return call, nil, oauthclient.Caller{}, call.configError("OAuth 客户端服务未装配")
	}
	var clientCaller oauthclient.Caller
	if call.identity.local {
		clientCaller, err = oauthclient.LocalAdminCaller(call.identity.actor.ID)
	} else {
		clientCaller, err = oauthclient.UserCaller(call.identity.userID)
	}
	if err != nil {
		return call, nil, oauthclient.Caller{}, call.configError("OAuth 客户端调用者无效")
	}
	if clientCaller, err = clientCaller.WithRequestID(call.requestID); err != nil {
		return call, nil, oauthclient.Caller{}, call.configError("请求编号无效")
	}
	return call, managed.OAuthClient, clientCaller, nil
}

// RegisterClient 登记客户端并返回一次性明文密钥（如有）。
func (f *oauthClientsFacade) RegisterClient(ctx context.Context,
	req AdminRegisterOAuthClientRequest) (AdminOAuthClientRegistration, error) {
	call, service, caller, err := f.beginClient(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminOAuthClientRegistration{}, err
	}
	approved, err := f.admin().sensitiveContext(ctx, call.identity,
		oauthclient.OperationClientRegister, "application", req.ClientID,
		map[string]string{"client_id": req.ClientID, "client_type": req.ClientType,
			"request_id": call.requestID},
		req.Password, req.TOTPCode, call.requestID)
	if err != nil {
		return AdminOAuthClientRegistration{}, err
	}
	result, err := service.RegisterClient(approved, caller, oauthclient.RegisterRequest{
		ClientID: req.ClientID, ClientType: oauthclient.ClientType(req.ClientType),
		GrantTypes: req.GrantTypes, RedirectURIs: req.RedirectURIs,
		PostLogoutRedirectURIs: req.PostLogoutRedirectURIs, Scopes: req.Scopes,
		Audiences: req.Audiences, AuthMethods: req.AuthMethods,
		RequirePKCE: req.RequirePKCE, CertificatePEM: req.CertificatePEM,
		RequestID: call.requestID})
	if err != nil {
		return AdminOAuthClientRegistration{}, call.domainError("登记 OAuth 客户端失败",
			string(oauthclient.CodeOf(err)))
	}
	registration := AdminOAuthClientRegistration{Client: adminOAuthClientOf(result.Client)}
	if result.Secret != nil {
		secret := adminRevealedSecretOf(*result.Secret, req.ClientID)
		registration.Secret = &secret
	}
	if result.Certificate != nil {
		certificate := adminClientCertificateOf(*result.Certificate)
		registration.Certificate = &certificate
	}
	return registration, nil
}

// GetClient 读取客户端设置（不含凭证）。
func (f *oauthClientsFacade) GetClient(ctx context.Context,
	req AdminOAuthClientRequest) (AdminOAuthClient, error) {
	call, service, caller, err := f.beginClient(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminOAuthClient{}, err
	}
	client, err := service.GetClient(ctx, caller, req.ClientID)
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, oauthclient.ErrClientNotFound,
			"oauth client"); ok {
			return AdminOAuthClient{}, replaced
		}
		return AdminOAuthClient{}, call.domainError("读取 OAuth 客户端失败",
			string(oauthclient.CodeOf(err)))
	}
	return adminOAuthClientOf(client), nil
}

// UpdateClientSettings 更新客户端安全设置（敏感操作）。
func (f *oauthClientsFacade) UpdateClientSettings(ctx context.Context,
	req AdminUpdateOAuthClientSettingsRequest) (AdminOAuthClient, error) {
	call, service, caller, err := f.beginClient(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminOAuthClient{}, err
	}
	approved, err := f.admin().sensitiveContext(ctx, call.identity,
		oauthclient.OperationClientSettingsChange, "application", req.ClientID,
		map[string]string{"client_id": req.ClientID, "request_id": call.requestID},
		req.Password, req.TOTPCode, call.requestID)
	if err != nil {
		return AdminOAuthClient{}, err
	}
	client, err := service.UpdateClientSettings(approved, caller,
		oauthclient.UpdateSettingsRequest{ClientID: req.ClientID,
			GrantTypes: req.GrantTypes, RedirectURIs: req.RedirectURIs,
			PostLogoutRedirectURIs: req.PostLogoutRedirectURIs, Scopes: req.Scopes,
			Audiences: req.Audiences, RequirePKCE: req.RequirePKCE,
			ExpectedRowVersion: req.ExpectedRowVersion, RequestID: call.requestID})
	if err != nil {
		return AdminOAuthClient{}, call.domainError("更新 OAuth 客户端设置失败",
			string(oauthclient.CodeOf(err)))
	}
	return adminOAuthClientOf(client), nil
}

// RotateClientSecret 轮换客户端密钥；明文只在本响应出现一次。
func (f *oauthClientsFacade) RotateClientSecret(ctx context.Context,
	req AdminOAuthClientSecretRotateRequest) (AdminRevealedClientSecret, error) {
	call, service, caller, err := f.beginClient(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminRevealedClientSecret{}, err
	}
	approved, err := f.admin().sensitiveContext(ctx, call.identity,
		oauthclient.OperationCredentialRotate, "application", req.ClientID,
		map[string]string{"client_id": req.ClientID, "action": "rotate_secret",
			"request_id": call.requestID},
		req.Password, req.TOTPCode, call.requestID)
	if err != nil {
		return AdminRevealedClientSecret{}, err
	}
	revealed, err := service.RotateClientSecret(approved, caller,
		oauthclient.RotateSecretRequest{ClientID: req.ClientID, RequestID: call.requestID})
	if err != nil {
		return AdminRevealedClientSecret{}, call.domainError("轮换客户端密钥失败",
			string(oauthclient.CodeOf(err)))
	}
	return adminRevealedSecretOf(revealed, req.ClientID), nil
}

// RevokeClientSecret 撤销指定客户端密钥。
func (f *oauthClientsFacade) RevokeClientSecret(ctx context.Context,
	req AdminOAuthClientSecretRevokeRequest) error {
	call, service, caller, err := f.beginClient(ctx, req.Caller, req.RequestID)
	if err != nil {
		return err
	}
	approved, err := f.admin().sensitiveContext(ctx, call.identity,
		oauthclient.OperationCredentialRotate, "application", req.ClientID,
		map[string]string{"client_id": req.ClientID, "action": "revoke_secret",
			"secret_id": req.SecretID, "request_id": call.requestID},
		req.Password, req.TOTPCode, call.requestID)
	if err != nil {
		return err
	}
	if err := service.RevokeClientSecret(approved, caller, oauthclient.RevokeSecretRequest{
		ClientID: req.ClientID, SecretID: req.SecretID, RequestID: call.requestID}); err != nil {
		return call.domainError("撤销客户端密钥失败", string(oauthclient.CodeOf(err)))
	}
	return nil
}

// ListClientSecrets 列出客户端密钥展示信息（不含明文）。
func (f *oauthClientsFacade) ListClientSecrets(ctx context.Context,
	req AdminOAuthClientRequest) ([]AdminClientSecretInfo, error) {
	call, service, caller, err := f.beginClient(ctx, req.Caller, req.RequestID)
	if err != nil {
		return nil, err
	}
	secrets, err := service.ListClientSecrets(ctx, caller, req.ClientID)
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, oauthclient.ErrClientNotFound,
			"oauth client"); ok {
			return nil, replaced
		}
		return nil, call.domainError("列出客户端密钥失败", string(oauthclient.CodeOf(err)))
	}
	items := make([]AdminClientSecretInfo, 0, len(secrets))
	for _, secret := range secrets {
		items = append(items, adminClientSecretInfoOf(secret))
	}
	return items, nil
}

// RegisterClientCertificate 登记客户端证书身份（敏感操作）。
func (f *oauthClientsFacade) RegisterClientCertificate(ctx context.Context,
	req AdminOAuthClientCertificateRequest) (AdminClientCertificateInfo, error) {
	call, service, caller, err := f.beginClient(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminClientCertificateInfo{}, err
	}
	approved, err := f.admin().sensitiveContext(ctx, call.identity,
		oauthclient.OperationCredentialRotate, "application", req.ClientID,
		map[string]string{"client_id": req.ClientID, "action": "register_certificate",
			"request_id": call.requestID},
		req.Password, req.TOTPCode, call.requestID)
	if err != nil {
		return AdminClientCertificateInfo{}, err
	}
	certificate, err := service.RegisterClientCertificate(approved, caller,
		oauthclient.CertificateRequest{ClientID: req.ClientID,
			CertificatePEM: req.CertificatePEM, RequestID: call.requestID})
	if err != nil {
		return AdminClientCertificateInfo{}, call.domainError("登记客户端证书失败",
			string(oauthclient.CodeOf(err)))
	}
	return adminClientCertificateOf(certificate), nil
}

// RevokeClientCertificate 撤销客户端证书身份（敏感操作）。
func (f *oauthClientsFacade) RevokeClientCertificate(ctx context.Context,
	req AdminOAuthClientCertificateRequest) error {
	call, service, caller, err := f.beginClient(ctx, req.Caller, req.RequestID)
	if err != nil {
		return err
	}
	approved, err := f.admin().sensitiveContext(ctx, call.identity,
		oauthclient.OperationCredentialRotate, "application", req.ClientID,
		map[string]string{"client_id": req.ClientID, "action": "revoke_certificate",
			"certificate_id": req.CertificateID, "request_id": call.requestID},
		req.Password, req.TOTPCode, call.requestID)
	if err != nil {
		return err
	}
	if err := service.RevokeClientCertificate(approved, caller, oauthclient.CertificateRequest{
		ClientID: req.ClientID, CertificateID: req.CertificateID,
		RequestID: call.requestID}); err != nil {
		return call.domainError("撤销客户端证书失败", string(oauthclient.CodeOf(err)))
	}
	return nil
}

// ListClientCertificates 列出客户端证书身份。
func (f *oauthClientsFacade) ListClientCertificates(ctx context.Context,
	req AdminOAuthClientRequest) ([]AdminClientCertificateInfo, error) {
	call, service, caller, err := f.beginClient(ctx, req.Caller, req.RequestID)
	if err != nil {
		return nil, err
	}
	certificates, err := service.ListClientCertificates(ctx, caller, req.ClientID)
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, oauthclient.ErrClientNotFound,
			"oauth client"); ok {
			return nil, replaced
		}
		return nil, call.domainError("列出客户端证书失败", string(oauthclient.CodeOf(err)))
	}
	items := make([]AdminClientCertificateInfo, 0, len(certificates))
	for _, certificate := range certificates {
		items = append(items, adminClientCertificateOf(certificate))
	}
	return items, nil
}

// adminOAuthClientOf 转换客户端设置视图。
func adminOAuthClientOf(client oauthclient.Client) AdminOAuthClient {
	grantTypes := make([]string, 0, len(client.GrantTypes))
	for _, item := range client.GrantTypes {
		grantTypes = append(grantTypes, string(item))
	}
	authMethods := make([]string, 0, len(client.AuthMethods))
	for _, item := range client.AuthMethods {
		authMethods = append(authMethods, string(item))
	}
	return AdminOAuthClient{ClientID: client.ClientID, ClientType: string(client.ClientType),
		GrantTypes: grantTypes, RedirectURIs: append([]string{}, client.RedirectURIs...),
		PostLogoutRedirectURIs: append([]string{}, client.PostLogoutRedirectURIs...),
		Scopes:                 append([]string{}, client.Scopes...),
		Audiences:              append([]string{}, client.Audiences...),
		AuthMethods:            authMethods, RequirePKCE: client.RequirePKCE,
		RowVersion: client.RowVersion, CreatedAt: client.CreatedAt,
		UpdatedAt: client.UpdatedAt}
}

// adminRevealedSecretOf 转换一次性明文密钥结果（secret 只出现一次）。
func adminRevealedSecretOf(revealed oauthclient.RevealedClientSecret,
	clientID string) AdminRevealedClientSecret {
	return AdminRevealedClientSecret{ClientID: clientID,
		Info: adminClientSecretInfoOf(revealed.Info), Secret: revealed.Secret}
}

// adminClientSecretInfoOf 转换密钥展示信息。
func adminClientSecretInfoOf(secret oauthclient.ClientSecretInfo) AdminClientSecretInfo {
	return AdminClientSecretInfo{ID: secret.ID, Prefix: secret.Prefix,
		CreatedAt: secret.CreatedAt, ExpiresAt: secret.ExpiresAt,
		RetireAt: secret.RetireAt, RevokedAt: secret.RevokedAt}
}

// adminClientCertificateOf 转换证书身份展示信息。
func adminClientCertificateOf(certificate oauthclient.ClientCertificateInfo) AdminClientCertificateInfo {
	return AdminClientCertificateInfo{ID: certificate.ID,
		FingerprintSHA256: certificate.FingerprintSHA256, Subject: certificate.Subject,
		NotBefore: certificate.NotBefore, NotAfter: certificate.NotAfter,
		CreatedAt: certificate.CreatedAt, RevokedAt: certificate.RevokedAt}
}
