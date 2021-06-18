package oauthclient

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"encoding/pem"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
)

// Options 是 OAuth 客户端服务依赖；所有依赖缺失都视为构造失败（fail-closed）。
type Options struct {
	Store      Store
	Audit      AuditRecorder
	Authorizer Authorizer
	// Sensitive 是步骤 38/39 敏感策略执行前校验契约（生产 *reauth.Service）；
	// 登记/修改安全设置与凭证操作必须经它判定近期强认证与操作绑定，缺失拒绝构造。
	Sensitive reauth.OperationRunner
	// SecretTTL 是客户端密钥有效期，默认 180 天，边界 24 小时～5 年。
	SecretTTL time.Duration
	// RotationGracePeriod 是轮换后旧密钥仍可用的过渡期，默认 24 小时，
	// 边界 1 分钟～30 天。
	RotationGracePeriod time.Duration
	Now                 func() time.Time
	Random              io.Reader
	Logger              *slog.Logger
}

// Service 是 OAuth 客户端安全设置与身份验证服务。构造后不可变，不启动协程、
// 不签发令牌、不实现授权端点。
type Service struct {
	opts Options
}

// New 校验依赖并构造服务；任何依赖为空（含 typed-nil）都返回错误。
func New(options Options) (*Service, error) {
	if isNilDependency(options.Store) {
		return nil, fmt.Errorf("%w: OAuth 客户端存储为空", ErrOptionsInvalid)
	}
	if isNilDependency(options.Audit) {
		return nil, fmt.Errorf("%w: 安全审计写入器为空", ErrOptionsInvalid)
	}
	if isNilDependency(options.Authorizer) {
		return nil, fmt.Errorf("%w: 客户端管理授权器为空", ErrOptionsInvalid)
	}
	if isNilDependency(options.Sensitive) {
		return nil, fmt.Errorf("%w: 敏感策略执行器为空（客户端安全设置必须满足再次验证）", ErrOptionsInvalid)
	}
	if options.SecretTTL == 0 {
		options.SecretTTL = DefaultSecretTTL
	}
	if options.SecretTTL < MinSecretTTL || options.SecretTTL > MaxSecretTTL {
		return nil, fmt.Errorf("%w: 客户端密钥有效期必须在 24 小时～5 年之间", ErrOptionsInvalid)
	}
	if options.RotationGracePeriod == 0 {
		options.RotationGracePeriod = DefaultRotationGracePeriod
	}
	if options.RotationGracePeriod < MinRotationGracePeriod || options.RotationGracePeriod > MaxRotationGracePeriod {
		return nil, fmt.Errorf("%w: 密钥轮换过渡期必须在 1 分钟～30 天之间", ErrOptionsInvalid)
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Service{opts: options}, nil
}

// RegisterRequest 是登记客户端安全设置的请求。回调/Scope/audience 都是必填
// 安全设置；客户端类型必须与应用登记一致，凭证在服务端生成并只展示一次。
type RegisterRequest struct {
	ClientID               string
	ClientType             ClientType
	GrantTypes             []string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	Scopes                 []string
	Audiences              []string
	AuthMethods            []string
	// RequirePKCE 为 nil 时默认 true；公开客户端始终强制 true。
	RequirePKCE *bool
	// CertificatePEM 是 tls_client_auth 的初始客户端证书（公钥证书，不含私钥）。
	CertificatePEM string
	RequestID      string
}

// RegisterResult 是登记结果；Secret 只在登记响应出现一次。
type RegisterResult struct {
	Client      Client
	Secret      *RevealedClientSecret
	Certificate *ClientCertificateInfo
}

// UpdateSettingsRequest 是修改客户端安全设置请求；客户端类型与身份验证方式不可
// 通过本请求改变（后者属于凭证管理动作）。
type UpdateSettingsRequest struct {
	ClientID               string
	GrantTypes             []string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	Scopes                 []string
	Audiences              []string
	RequirePKCE            *bool
	ExpectedRowVersion     int64
	RequestID              string
}

// RotateSecretRequest 是轮换客户端密钥请求。
type RotateSecretRequest struct {
	ClientID  string
	RequestID string
}

// RevokeSecretRequest 是撤销客户端密钥请求。
type RevokeSecretRequest struct {
	ClientID  string
	SecretID  string
	RequestID string
}

// CertificateRequest 是登记/撤销客户端证书身份请求。
type CertificateRequest struct {
	ClientID       string
	CertificateID  string
	CertificatePEM string
	RequestID      string
}

// RegisterClient 登记客户端安全设置并生成初始凭证（密钥和/或证书）。客户端类型
// 必须与应用登记的 client_type 一致；公开客户端禁止 secret/证书与 client_credentials，
// 保密客户端必须配置至少一种身份验证方式并具备对应凭证。
func (s *Service) RegisterClient(ctx context.Context, caller Caller, request RegisterRequest) (RegisterResult, error) {
	ctx = normalizeContext(ctx)
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		s.recordFailure(ctx, caller.actor, ActionClientDenied, "application", request.ClientID, "invalid_request_id", string(CodeReqInvalid), "")
		return RegisterResult{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if !app.ValidApplicationID(request.ClientID) || !request.ClientType.Valid() {
		s.recordFailure(ctx, caller.actor, ActionClientDenied, "application", request.ClientID, "invalid_client", string(CodeReqInvalid), request.RequestID)
		return RegisterResult{}, fmt.Errorf("%w: 客户端 ID 或类型无效", ErrInvalidRequest)
	}
	if err := s.authorize(ctx, caller, request.ClientID, ActionUpdateSettings); err != nil {
		s.recordFailure(ctx, caller.actor, ActionClientDenied, "application", request.ClientID, "not_authorized", string(CodeOf(err)), request.RequestID)
		return RegisterResult{}, err
	}
	grants, redirects, logoutURIs, scopes, audiences, methods, requirePKCE, err :=
		validateClientSettings(request.ClientType, request.GrantTypes, request.RedirectURIs,
			request.PostLogoutRedirectURIs, request.Scopes, request.Audiences,
			request.AuthMethods, request.RequirePKCE)
	if err != nil {
		s.recordFailure(ctx, caller.actor, ActionClientDenied, "application", request.ClientID, "invalid_settings", string(CodeOf(err)), request.RequestID)
		return RegisterResult{}, err
	}
	// 秘密/证书材料与身份验证方式必须一致：公开客户端不接受任何凭证材料。
	if request.ClientType == ClientTypePublic && (request.CertificatePEM != "") {
		s.recordFailure(ctx, caller.actor, ActionClientDenied, "application", request.ClientID, "public_with_certificate", string(CodeReqInvalid), request.RequestID)
		return RegisterResult{}, fmt.Errorf("%w: 公开客户端不能配置证书身份", ErrInvalidConfiguration)
	}
	snapshot, found, err := s.opts.Store.LookupApplication(ctx, request.ClientID)
	if err != nil {
		return RegisterResult{}, mapStoreError(err)
	}
	if !found {
		return RegisterResult{}, ErrClientNotFound
	}
	if snapshot.ClientType != request.ClientType {
		s.recordFailure(ctx, caller.actor, ActionClientDenied, "application", request.ClientID, "client_type_mismatch", string(CodeReqInvalid), request.RequestID)
		return RegisterResult{}, ErrClientTypeMismatch
	}
	if _, exists, err := s.opts.Store.GetClient(ctx, request.ClientID); err != nil {
		return RegisterResult{}, mapStoreError(err)
	} else if exists {
		return RegisterResult{}, ErrCredentialConflict
	}
	now := s.now()
	record := ClientRecord{
		Client: Client{
			ClientID: request.ClientID, ClientType: request.ClientType,
			GrantTypes: grants, RedirectURIs: redirects, PostLogoutRedirectURIs: logoutURIs,
			Scopes: scopes, Audiences: audiences, AuthMethods: methods,
			RequirePKCE: requirePKCE, RowVersion: 1, CreatedAt: now, UpdatedAt: now,
		},
	}
	var secretRecord *SecretRecord
	var revealed *RevealedClientSecret
	if hasSecretMethod(methods) {
		secret, prefix, err := s.newClientSecret()
		if err != nil {
			return RegisterResult{}, err
		}
		secretRecord = &SecretRecord{
			ID: mustNewID(s.opts.Random, "ocs_"), ClientID: request.ClientID,
			Prefix: prefix, Digest: digestSecret(secret), CreatedAt: now,
			ExpiresAt: now.Add(s.opts.SecretTTL),
		}
		revealed = &RevealedClientSecret{Info: secretInfo(*secretRecord), Secret: secret}
	}
	var certificateRecord *CertificateRecord
	var certificateInfo *ClientCertificateInfo
	if hasTLSMethod(methods) {
		if strings.TrimSpace(request.CertificatePEM) == "" {
			return RegisterResult{}, fmt.Errorf("%w: tls_client_auth 必须同时登记客户端证书", ErrInvalidConfiguration)
		}
		parsed, err := parseClientCertificate(request.CertificatePEM, now)
		if err != nil {
			s.recordFailure(ctx, caller.actor, ActionClientDenied, "application", request.ClientID, "invalid_certificate", string(CodeReqInvalid), request.RequestID)
			return RegisterResult{}, err
		}
		parsed.ID = mustNewID(s.opts.Random, "occ_")
		parsed.ClientID = request.ClientID
		certificateRecord = &parsed
		info := certificateInfoOf(*certificateRecord)
		certificateInfo = &info
	}
	guard, err := s.authorizeSensitive(ctx, caller, OperationClientRegister, "application", request.ClientID,
		map[string]string{"client_id": request.ClientID, "client_type": string(request.ClientType),
			"config_sha256": settingsDigest(record.Client), "request_id": request.RequestID},
		"登记 OAuth 客户端安全设置", request.RequestID)
	if err != nil {
		s.recordFailure(ctx, caller.actor, ActionClientDenied, "application", request.ClientID, "reauth_rejected", string(CodeOf(err)), request.RequestID)
		return RegisterResult{}, err
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.actor, Action: ActionClientRegistered,
			Target:    audit.Target{Type: "oauth_client", ID: request.ClientID},
			RequestID: validRequestID(request.RequestID),
			Changes: []audit.FieldChange{
				{Field: "client_type", After: string(request.ClientType)},
				{Field: "grant_types", After: strings.Join(joinGrants(grants), ",")},
				{Field: "redirect_count", After: fmt.Sprint(len(redirects))},
				{Field: "pkce_required", After: fmt.Sprint(requirePKCE)},
				{Field: "auth_methods", After: strings.Join(joinMethods(methods), ",")},
			},
		},
		FailureReasonCode:   "oauth.client.register_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.opts.Store.CreateClientTx(txCtx, tx, record, secretRecord, certificateRecord)
	}); err != nil {
		return RegisterResult{}, mapCriticalError(err)
	}
	s.notifySensitive(ctx, guard)
	return RegisterResult{Client: clientView(record), Secret: revealed, Certificate: certificateInfo}, nil
}

// GetClient 读取客户端安全设置（不含任何凭证材料）。
func (s *Service) GetClient(ctx context.Context, caller Caller, clientID string) (Client, error) {
	ctx = normalizeContext(ctx)
	if !app.ValidApplicationID(clientID) {
		return Client{}, fmt.Errorf("%w: 客户端 ID 无效", ErrInvalidRequest)
	}
	if err := s.authorize(ctx, caller, clientID, ActionRead); err != nil {
		return Client{}, err
	}
	record, found, err := s.opts.Store.GetClient(ctx, clientID)
	if err != nil {
		return Client{}, mapStoreError(err)
	}
	if !found {
		return Client{}, ErrClientNotFound
	}
	return clientView(record), nil
}

// UpdateClientSettings 修改回调/授权类型/Scope/audience/PKCE 等安全设置；客户端
// 类型与身份验证方式不可在此改变。变更要求当前管理权限、步骤 38/39 再次验证与
// 行版本条件更新（并发只有一方成功），并写审计。
func (s *Service) UpdateClientSettings(ctx context.Context, caller Caller, request UpdateSettingsRequest) (Client, error) {
	ctx = normalizeContext(ctx)
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		s.recordFailure(ctx, caller.actor, ActionClientDenied, "application", request.ClientID, "invalid_request_id", string(CodeReqInvalid), "")
		return Client{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if !app.ValidApplicationID(request.ClientID) || request.ExpectedRowVersion <= 0 {
		return Client{}, fmt.Errorf("%w: 客户端 ID 或期望版本无效", ErrInvalidRequest)
	}
	if err := s.authorize(ctx, caller, request.ClientID, ActionUpdateSettings); err != nil {
		s.recordFailure(ctx, caller.actor, ActionClientDenied, "application", request.ClientID, "not_authorized", string(CodeOf(err)), request.RequestID)
		return Client{}, err
	}
	record, found, err := s.opts.Store.GetClient(ctx, request.ClientID)
	if err != nil {
		return Client{}, mapStoreError(err)
	}
	if !found {
		return Client{}, ErrClientNotFound
	}
	grants, redirects, logoutURIs, scopes, audiences, _, requirePKCE, err :=
		validateClientSettings(record.ClientType, request.GrantTypes, request.RedirectURIs,
			request.PostLogoutRedirectURIs, request.Scopes, request.Audiences,
			joinMethods(record.AuthMethods), request.RequirePKCE)
	if err != nil {
		s.recordFailure(ctx, caller.actor, ActionClientDenied, "application", request.ClientID, "invalid_settings", string(CodeOf(err)), request.RequestID)
		return Client{}, err
	}
	updated := record.Client
	updated.GrantTypes, updated.RedirectURIs, updated.PostLogoutRedirectURIs =
		grants, redirects, logoutURIs
	updated.Scopes, updated.Audiences, updated.RequirePKCE = scopes, audiences, requirePKCE
	guard, err := s.authorizeSensitive(ctx, caller, OperationClientSettingsChange, "application", request.ClientID,
		map[string]string{"client_id": request.ClientID, "config_sha256": settingsDigest(updated),
			"expected_row_version": fmt.Sprint(request.ExpectedRowVersion), "request_id": request.RequestID},
		"修改 OAuth 客户端安全设置", request.RequestID)
	if err != nil {
		s.recordFailure(ctx, caller.actor, ActionClientDenied, "application", request.ClientID, "reauth_rejected", string(CodeOf(err)), request.RequestID)
		return Client{}, err
	}
	now := s.now()
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.actor, Action: ActionClientSettingsChanged,
			Target:    audit.Target{Type: "oauth_client", ID: request.ClientID},
			RequestID: validRequestID(request.RequestID),
			Changes: []audit.FieldChange{
				{Field: "grant_types", Before: strings.Join(joinGrants(record.GrantTypes), ","), After: strings.Join(joinGrants(grants), ",")},
				{Field: "redirect_count", Before: fmt.Sprint(len(record.RedirectURIs)), After: fmt.Sprint(len(redirects))},
				{Field: "pkce_required", Before: fmt.Sprint(record.RequirePKCE), After: fmt.Sprint(requirePKCE)},
				{Field: "row_version", Before: fmt.Sprint(request.ExpectedRowVersion)},
			},
		},
		FailureReasonCode:   "oauth.client.settings_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	ok := false
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		var updateErr error
		ok, updateErr = s.opts.Store.UpdateClientTx(txCtx, tx, ClientUpdate{
			ClientID: request.ClientID, GrantTypes: grants, RedirectURIs: redirects,
			PostLogoutRedirectURIs: logoutURIs, Scopes: scopes, Audiences: audiences,
			RequirePKCE: requirePKCE, UpdatedAt: now, ExpectedRowVersion: request.ExpectedRowVersion,
		})
		return updateErr
	}); err != nil {
		return Client{}, mapCriticalError(err)
	}
	if !ok {
		return Client{}, ErrVersionConflict
	}
	updated.RowVersion = request.ExpectedRowVersion + 1
	updated.UpdatedAt = now
	s.notifySensitive(ctx, guard)
	return clientViewOf(updated), nil
}

// RotateClientSecret 生成新客户端密钥并把现有可用密钥标记为过渡期退休：新密钥
// 立即生效，旧密钥在过渡期（默认 24 小时，且不超过其原有效期）内仍可用，超出即
// 拒绝。明文只在本响应出现一次。仅适用于配置了密钥身份验证方式的保密客户端。
func (s *Service) RotateClientSecret(ctx context.Context, caller Caller, request RotateSecretRequest) (RevealedClientSecret, error) {
	ctx = normalizeContext(ctx)
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return RevealedClientSecret{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if !app.ValidApplicationID(request.ClientID) {
		return RevealedClientSecret{}, fmt.Errorf("%w: 客户端 ID 无效", ErrInvalidRequest)
	}
	if err := s.authorize(ctx, caller, request.ClientID, ActionManageCredentials); err != nil {
		s.recordFailure(ctx, caller.actor, ActionClientDenied, "application", request.ClientID, "not_authorized", string(CodeOf(err)), request.RequestID)
		return RevealedClientSecret{}, err
	}
	record, found, err := s.opts.Store.GetClient(ctx, request.ClientID)
	if err != nil {
		return RevealedClientSecret{}, mapStoreError(err)
	}
	if !found {
		return RevealedClientSecret{}, ErrClientNotFound
	}
	if record.ClientType != ClientTypeConfidential || !hasSecretMethod(record.AuthMethods) {
		s.recordFailure(ctx, caller.actor, ActionClientDenied, "application", request.ClientID, "no_secret_method", string(CodeClientAuthFailed), request.RequestID)
		return RevealedClientSecret{}, ErrUnsupportedAuthMethod
	}
	secrets, err := s.opts.Store.ListSecrets(ctx, request.ClientID)
	if err != nil {
		return RevealedClientSecret{}, mapStoreError(err)
	}
	now := s.now()
	usable := 0
	for _, existing := range secrets {
		if secretUsable(existing, now) {
			usable++
		}
	}
	if usable >= MaxActiveClientSecrets {
		return RevealedClientSecret{}, ErrCredentialConflict
	}
	guard, err := s.authorizeSensitive(ctx, caller, OperationCredentialRotate, "application", request.ClientID,
		map[string]string{"client_id": request.ClientID, "action": "rotate_secret", "request_id": request.RequestID},
		"轮换 OAuth 客户端密钥", request.RequestID)
	if err != nil {
		s.recordFailure(ctx, caller.actor, ActionClientDenied, "application", request.ClientID, "reauth_rejected", string(CodeOf(err)), request.RequestID)
		return RevealedClientSecret{}, err
	}
	secret, prefix, err := s.newClientSecret()
	if err != nil {
		return RevealedClientSecret{}, err
	}
	secretRecord := SecretRecord{
		ID: mustNewID(s.opts.Random, "ocs_"), ClientID: request.ClientID,
		Prefix: prefix, Digest: digestSecret(secret), CreatedAt: now,
		ExpiresAt: now.Add(s.opts.SecretTTL),
	}
	retireAt := now.Add(s.opts.RotationGracePeriod)
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.actor, Action: ActionSecretRotated,
			Target:    audit.Target{Type: "oauth_client", ID: request.ClientID},
			RequestID: validRequestID(request.RequestID),
			Changes: []audit.FieldChange{
				{Field: "secret_prefix", After: prefix},
				{Field: "retire_at_ms", After: fmt.Sprint(retireAt.UnixMilli())},
			},
		},
		FailureReasonCode:   "oauth.client.secret_rotate_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		if _, retireErr := s.opts.Store.RetireActiveSecretsTx(txCtx, tx, request.ClientID, retireAt, now); retireErr != nil {
			return retireErr
		}
		return s.opts.Store.InsertSecretTx(txCtx, tx, secretRecord)
	}); err != nil {
		return RevealedClientSecret{}, mapCriticalError(err)
	}
	s.notifySensitive(ctx, guard)
	return RevealedClientSecret{Info: secretInfo(secretRecord), Secret: secret}, nil
}

// RevokeClientSecret 立即撤销指定客户端密钥；已撤销的重复请求幂等成功。若客户端
// 仅用密钥方式认证且这是最后一个可用密钥，拒绝撤销（先轮换新密钥，避免自锁）。
func (s *Service) RevokeClientSecret(ctx context.Context, caller Caller, request RevokeSecretRequest) error {
	ctx = normalizeContext(ctx)
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if !app.ValidApplicationID(request.ClientID) || !validCredentialID(request.SecretID, "ocs_") {
		return fmt.Errorf("%w: 客户端或密钥 ID 无效", ErrInvalidRequest)
	}
	if err := s.authorize(ctx, caller, request.ClientID, ActionManageCredentials); err != nil {
		s.recordFailure(ctx, caller.actor, ActionClientDenied, "application", request.ClientID, "not_authorized", string(CodeOf(err)), request.RequestID)
		return err
	}
	record, found, err := s.opts.Store.GetClient(ctx, request.ClientID)
	if err != nil {
		return mapStoreError(err)
	}
	if !found {
		return ErrClientNotFound
	}
	secrets, err := s.opts.Store.ListSecrets(ctx, request.ClientID)
	if err != nil {
		return mapStoreError(err)
	}
	now := s.now()
	var target *SecretRecord
	usable := 0
	for index := range secrets {
		candidate := secrets[index]
		if secretUsable(candidate, now) {
			usable++
		}
		if candidate.ID == request.SecretID {
			target = &secrets[index]
		}
	}
	if target == nil {
		return ErrClientNotFound
	}
	if !target.RevokedAt.IsZero() {
		return nil
	}
	if usable <= 1 && hasSecretMethod(record.AuthMethods) && !hasTLSMethod(record.AuthMethods) {
		s.recordFailure(ctx, caller.actor, ActionClientDenied, "application", request.ClientID, "last_credential", string(CodeConflict), request.RequestID)
		return ErrLastCredential
	}
	guard, err := s.authorizeSensitive(ctx, caller, OperationCredentialRotate, "application", request.ClientID,
		map[string]string{"client_id": request.ClientID, "action": "revoke_secret",
			"secret_id": request.SecretID, "request_id": request.RequestID},
		"撤销 OAuth 客户端密钥", request.RequestID)
	if err != nil {
		s.recordFailure(ctx, caller.actor, ActionClientDenied, "application", request.ClientID, "reauth_rejected", string(CodeOf(err)), request.RequestID)
		return err
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.actor, Action: ActionSecretRevoked,
			Target:    audit.Target{Type: "oauth_client", ID: request.ClientID},
			RequestID: validRequestID(request.RequestID),
			Changes:   []audit.FieldChange{{Field: "secret_prefix", Before: target.Prefix}},
		},
		FailureReasonCode:   "oauth.client.secret_revoke_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	ok := false
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		var revokeErr error
		ok, revokeErr = s.opts.Store.RevokeSecretTx(txCtx, tx, request.ClientID, request.SecretID, now)
		return revokeErr
	}); err != nil {
		return mapCriticalError(err)
	}
	if !ok {
		return ErrCredentialConflict
	}
	s.notifySensitive(ctx, guard)
	return nil
}

// ListClientSecrets 列出客户端密钥展示信息（ID/前缀/时间），不含明文或摘要。
func (s *Service) ListClientSecrets(ctx context.Context, caller Caller, clientID string) ([]ClientSecretInfo, error) {
	ctx = normalizeContext(ctx)
	if !app.ValidApplicationID(clientID) {
		return nil, fmt.Errorf("%w: 客户端 ID 无效", ErrInvalidRequest)
	}
	if err := s.authorize(ctx, caller, clientID, ActionRead); err != nil {
		return nil, err
	}
	if _, found, err := s.opts.Store.GetClient(ctx, clientID); err != nil {
		return nil, mapStoreError(err)
	} else if !found {
		return nil, ErrClientNotFound
	}
	records, err := s.opts.Store.ListSecrets(ctx, clientID)
	if err != nil {
		return nil, mapStoreError(err)
	}
	infos := make([]ClientSecretInfo, 0, len(records))
	for _, record := range records {
		infos = append(infos, secretInfo(record))
	}
	return infos, nil
}

// RegisterClientCertificate 登记 TLS 客户端证书身份（公钥证书，不含私钥）；仅适用
// 于已配置 tls_client_auth 的保密客户端。支持多张有效证书并存以便轮换，旧证书
// 需显式撤销。
func (s *Service) RegisterClientCertificate(ctx context.Context, caller Caller, request CertificateRequest) (ClientCertificateInfo, error) {
	ctx = normalizeContext(ctx)
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return ClientCertificateInfo{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if !app.ValidApplicationID(request.ClientID) || request.CertificateID != "" {
		return ClientCertificateInfo{}, fmt.Errorf("%w: 客户端 ID 无效", ErrInvalidRequest)
	}
	if err := s.authorize(ctx, caller, request.ClientID, ActionManageCredentials); err != nil {
		s.recordFailure(ctx, caller.actor, ActionClientDenied, "application", request.ClientID, "not_authorized", string(CodeOf(err)), request.RequestID)
		return ClientCertificateInfo{}, err
	}
	record, found, err := s.opts.Store.GetClient(ctx, request.ClientID)
	if err != nil {
		return ClientCertificateInfo{}, mapStoreError(err)
	}
	if !found {
		return ClientCertificateInfo{}, ErrClientNotFound
	}
	if record.ClientType != ClientTypeConfidential || !hasTLSMethod(record.AuthMethods) {
		return ClientCertificateInfo{}, ErrUnsupportedAuthMethod
	}
	now := s.now()
	if strings.TrimSpace(request.CertificatePEM) == "" {
		return ClientCertificateInfo{}, fmt.Errorf("%w: 证书内容为空", ErrInvalidRequest)
	}
	parsed, err := parseClientCertificate(request.CertificatePEM, now)
	if err != nil {
		s.recordFailure(ctx, caller.actor, ActionClientDenied, "application", request.ClientID, "invalid_certificate", string(CodeOf(err)), request.RequestID)
		return ClientCertificateInfo{}, err
	}
	certificates, err := s.opts.Store.ListCertificates(ctx, request.ClientID)
	if err != nil {
		return ClientCertificateInfo{}, mapStoreError(err)
	}
	active := 0
	for _, existing := range certificates {
		if existing.RevokedAt.IsZero() && now.Before(existing.NotAfter) {
			active++
		}
		if existing.FingerprintSHA256 == parsed.FingerprintSHA256 && existing.RevokedAt.IsZero() {
			return ClientCertificateInfo{}, ErrCredentialConflict
		}
	}
	if active >= MaxActiveClientCertificates {
		return ClientCertificateInfo{}, ErrCredentialConflict
	}
	guard, err := s.authorizeSensitive(ctx, caller, OperationCredentialRotate, "application", request.ClientID,
		map[string]string{"client_id": request.ClientID, "action": "register_certificate",
			"fingerprint": hexFingerprint(parsed.FingerprintSHA256), "request_id": request.RequestID},
		"登记 OAuth 客户端证书身份", request.RequestID)
	if err != nil {
		s.recordFailure(ctx, caller.actor, ActionClientDenied, "application", request.ClientID, "reauth_rejected", string(CodeOf(err)), request.RequestID)
		return ClientCertificateInfo{}, err
	}
	parsed.ID = mustNewID(s.opts.Random, "occ_")
	parsed.ClientID = request.ClientID
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.actor, Action: ActionCertificateRegistered,
			Target:    audit.Target{Type: "oauth_client", ID: request.ClientID},
			RequestID: validRequestID(request.RequestID),
			Changes: []audit.FieldChange{
				{Field: "certificate_fingerprint", After: hexFingerprint(parsed.FingerprintSHA256)},
				{Field: "certificate_subject", After: parsed.Subject},
				{Field: "not_after", After: parsed.NotAfter.UTC().Format(time.RFC3339)},
			},
		},
		FailureReasonCode:   "oauth.client.certificate_register_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.opts.Store.InsertCertificateTx(txCtx, tx, parsed)
	}); err != nil {
		return ClientCertificateInfo{}, mapCriticalError(err)
	}
	s.notifySensitive(ctx, guard)
	return certificateInfoOf(parsed), nil
}

// RevokeClientCertificate 撤销客户端证书身份；已撤销的重复请求幂等成功。若这是
// 客户端唯一的可用身份验证凭证（tls 单独方式且无其他有效证书），拒绝撤销。
func (s *Service) RevokeClientCertificate(ctx context.Context, caller Caller, request CertificateRequest) error {
	ctx = normalizeContext(ctx)
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if !app.ValidApplicationID(request.ClientID) || !validCredentialID(request.CertificateID, "occ_") {
		return fmt.Errorf("%w: 客户端或证书 ID 无效", ErrInvalidRequest)
	}
	if err := s.authorize(ctx, caller, request.ClientID, ActionManageCredentials); err != nil {
		s.recordFailure(ctx, caller.actor, ActionClientDenied, "application", request.ClientID, "not_authorized", string(CodeOf(err)), request.RequestID)
		return err
	}
	record, found, err := s.opts.Store.GetClient(ctx, request.ClientID)
	if err != nil {
		return mapStoreError(err)
	}
	if !found {
		return ErrClientNotFound
	}
	certificates, err := s.opts.Store.ListCertificates(ctx, request.ClientID)
	if err != nil {
		return mapStoreError(err)
	}
	now := s.now()
	var target *CertificateRecord
	active := 0
	for index := range certificates {
		candidate := certificates[index]
		if candidate.RevokedAt.IsZero() && now.Before(candidate.NotAfter) {
			active++
		}
		if candidate.ID == request.CertificateID {
			target = &certificates[index]
		}
	}
	if target == nil {
		return ErrClientNotFound
	}
	if !target.RevokedAt.IsZero() {
		return nil
	}
	if active <= 1 && !hasSecretMethod(record.AuthMethods) {
		s.recordFailure(ctx, caller.actor, ActionClientDenied, "application", request.ClientID, "last_credential", string(CodeConflict), request.RequestID)
		return ErrLastCredential
	}
	guard, err := s.authorizeSensitive(ctx, caller, OperationCredentialRotate, "application", request.ClientID,
		map[string]string{"client_id": request.ClientID, "action": "revoke_certificate",
			"certificate_id": request.CertificateID, "request_id": request.RequestID},
		"撤销 OAuth 客户端证书身份", request.RequestID)
	if err != nil {
		s.recordFailure(ctx, caller.actor, ActionClientDenied, "application", request.ClientID, "reauth_rejected", string(CodeOf(err)), request.RequestID)
		return err
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.actor, Action: ActionCertificateRevoked,
			Target:    audit.Target{Type: "oauth_client", ID: request.ClientID},
			RequestID: validRequestID(request.RequestID),
			Changes:   []audit.FieldChange{{Field: "certificate_fingerprint", Before: hexFingerprint(target.FingerprintSHA256)}},
		},
		FailureReasonCode:   "oauth.client.certificate_revoke_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	ok := false
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		var revokeErr error
		ok, revokeErr = s.opts.Store.RevokeCertificateTx(txCtx, tx, request.ClientID, request.CertificateID, now)
		return revokeErr
	}); err != nil {
		return mapCriticalError(err)
	}
	if !ok {
		return ErrCredentialConflict
	}
	s.notifySensitive(ctx, guard)
	return nil
}

// ListClientCertificates 列出客户端证书身份展示信息（指纹/主题/有效期）。
func (s *Service) ListClientCertificates(ctx context.Context, caller Caller, clientID string) ([]ClientCertificateInfo, error) {
	ctx = normalizeContext(ctx)
	if !app.ValidApplicationID(clientID) {
		return nil, fmt.Errorf("%w: 客户端 ID 无效", ErrInvalidRequest)
	}
	if err := s.authorize(ctx, caller, clientID, ActionRead); err != nil {
		return nil, err
	}
	if _, found, err := s.opts.Store.GetClient(ctx, clientID); err != nil {
		return nil, mapStoreError(err)
	} else if !found {
		return nil, ErrClientNotFound
	}
	records, err := s.opts.Store.ListCertificates(ctx, clientID)
	if err != nil {
		return nil, mapStoreError(err)
	}
	infos := make([]ClientCertificateInfo, 0, len(records))
	for _, record := range records {
		infos = append(infos, certificateInfoOf(record))
	}
	return infos, nil
}

// VerifyClientSecret 在客户端令牌端点验证保密客户端密钥：应用停用返回
// CLIENT_DISABLED，其余失败统一 CLIENT_AUTH_FAILED（不区分未登记/类型不符/过期/
// 撤销/错误，避免探测）。成功返回客户端身份，但不代表该客户端的用户已认证。
func (s *Service) VerifyClientSecret(ctx context.Context, clientID, secret string) (ClientIdentity, error) {
	ctx = normalizeContext(ctx)
	if !app.ValidApplicationID(clientID) || secret == "" || len(secret) > 256 {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "oauthclient"},
			ActionClientDenied, "oauth_client", clientID, "invalid_secret_request", string(CodeClientAuthFailed), "")
		return ClientIdentity{}, ErrClientAuthFailed
	}
	record, found, err := s.opts.Store.GetClient(ctx, clientID)
	if err != nil {
		return ClientIdentity{}, mapStoreError(err)
	}
	if !found {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "oauthclient"},
			ActionClientDenied, "oauth_client", clientID, "unknown_client", string(CodeClientAuthFailed), "")
		return ClientIdentity{}, ErrClientAuthFailed
	}
	if record.AppStatus != "active" {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "oauthclient"},
			ActionClientDenied, "oauth_client", clientID, "client_disabled", string(CodeClientDisabled), "")
		return ClientIdentity{}, ErrClientDisabled
	}
	if record.ClientType != ClientTypeConfidential || !hasSecretMethod(record.AuthMethods) {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "oauthclient"},
			ActionClientDenied, "oauth_client", clientID, "method_not_allowed", string(CodeClientAuthFailed), "")
		return ClientIdentity{}, ErrClientAuthFailed
	}
	secrets, err := s.opts.Store.ListSecrets(ctx, clientID)
	if err != nil {
		return ClientIdentity{}, mapStoreError(err)
	}
	now := s.now()
	computed := digestSecret(secret)
	matched := false
	for _, candidate := range secrets {
		if !secretUsable(candidate, now) {
			continue
		}
		// 逐个做恒定时间比较，避免在候选中提前返回泄露命中位置的信息。
		if constantTimeEqual(candidate.Digest, computed) {
			matched = true
		}
	}
	if !matched {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "oauthclient"},
			ActionClientDenied, "oauth_client", clientID, "invalid_secret", string(CodeClientAuthFailed), "")
		return ClientIdentity{}, ErrClientAuthFailed
	}
	method := AuthMethodSecretBasic
	for _, candidate := range record.AuthMethods {
		if candidate.IsSecretMethod() {
			method = candidate
			break
		}
	}
	if err := s.opts.Audit.Record(ctx, audit.Event{
		Actor:  audit.Actor{Type: audit.ActorSystem, ID: "oauthclient"},
		Action: ActionClientAuthenticated, Target: audit.Target{Type: "oauth_client", ID: clientID},
		Outcome: audit.OutcomeSuccess, Changes: []audit.FieldChange{{Field: "auth_method", After: string(method)}},
	}); err != nil {
		s.opts.Logger.Warn("客户端身份验证成功审计写入失败", "error", err)
	}
	return ClientIdentity{ClientID: clientID, ClientType: record.ClientType, AuthMethod: method}, nil
}

// VerifyClientCertificate 验证呈现的客户端证书（leaf PEM）是否为该客户端登记的
// 未撤销身份：证书必须当前有效且 SHA-256 指纹与某个登记证书精确一致。证书链信任
// 由 TLS 层完成，本方法只做身份匹配。
func (s *Service) VerifyClientCertificate(ctx context.Context, clientID, certificatePEM string) (ClientIdentity, error) {
	ctx = normalizeContext(ctx)
	if !app.ValidApplicationID(clientID) {
		return ClientIdentity{}, ErrClientAuthFailed
	}
	record, found, err := s.opts.Store.GetClient(ctx, clientID)
	if err != nil {
		return ClientIdentity{}, mapStoreError(err)
	}
	if !found {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "oauthclient"},
			ActionClientDenied, "oauth_client", clientID, "unknown_client", string(CodeClientAuthFailed), "")
		return ClientIdentity{}, ErrClientAuthFailed
	}
	if record.AppStatus != "active" {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "oauthclient"},
			ActionClientDenied, "oauth_client", clientID, "client_disabled", string(CodeClientDisabled), "")
		return ClientIdentity{}, ErrClientDisabled
	}
	if record.ClientType != ClientTypeConfidential || !hasTLSMethod(record.AuthMethods) {
		return ClientIdentity{}, ErrClientAuthFailed
	}
	now := s.now()
	leaf, err := parseLeafCertificate(certificatePEM, now)
	if err != nil {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "oauthclient"},
			ActionClientDenied, "oauth_client", clientID, "invalid_certificate", string(CodeClientAuthFailed), "")
		return ClientIdentity{}, ErrClientAuthFailed
	}
	certificates, err := s.opts.Store.ListCertificates(ctx, clientID)
	if err != nil {
		return ClientIdentity{}, mapStoreError(err)
	}
	matched := false
	for _, candidate := range certificates {
		if !candidate.RevokedAt.IsZero() || !now.Before(candidate.NotAfter) || now.Before(candidate.NotBefore) {
			continue
		}
		if subtleCompare(candidate.FingerprintSHA256, leaf) {
			matched = true
		}
	}
	if !matched {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "oauthclient"},
			ActionClientDenied, "oauth_client", clientID, "certificate_mismatch", string(CodeClientAuthFailed), "")
		return ClientIdentity{}, ErrClientAuthFailed
	}
	if err := s.opts.Audit.Record(ctx, audit.Event{
		Actor:  audit.Actor{Type: audit.ActorSystem, ID: "oauthclient"},
		Action: ActionClientAuthenticated, Target: audit.Target{Type: "oauth_client", ID: clientID},
		Outcome: audit.OutcomeSuccess, Changes: []audit.FieldChange{{Field: "auth_method", After: string(AuthMethodTLSClientAuth)}},
	}); err != nil {
		s.opts.Logger.Warn("客户端证书身份验证成功审计写入失败", "error", err)
	}
	return ClientIdentity{ClientID: clientID, ClientType: record.ClientType, AuthMethod: AuthMethodTLSClientAuth}, nil
}

// ===== 内部辅助 =====

// validateClientSettings 校验并规范化一整套安全设置；返回最终使用的身份验证方式
// 用于登记，更新安全设置时忽略该返回值（方式不可通过本路径改变）。
func validateClientSettings(clientType ClientType, grantRaw, redirectRaw, logoutRaw, scopeRaw, audienceRaw, authRaw []string,
	requirePKCE *bool) ([]GrantType, []string, []string, []string, []string, []AuthMethod, bool, error) {
	if !clientType.Valid() {
		return nil, nil, nil, nil, nil, nil, false, fmt.Errorf("%w: 客户端类型无效", ErrInvalidRequest)
	}
	grants, err := ParseGrantTypes(grantRaw)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, false, err
	}
	redirects, err := normalizeStrings(redirectRaw, MaxRedirectURIs, func(value string) bool { return true })
	if err != nil || len(redirects) == 0 {
		return nil, nil, nil, nil, nil, nil, false, fmt.Errorf("%w: 至少登记一个回调地址", ErrInvalidRequest)
	}
	for _, redirect := range redirects {
		if err := ValidateRedirectURI(redirect, clientType); err != nil {
			return nil, nil, nil, nil, nil, nil, false, err
		}
	}
	logoutURIs, err := normalizeStrings(logoutRaw, MaxPostLogoutRedirectURIs, func(value string) bool { return true })
	if err != nil {
		return nil, nil, nil, nil, nil, nil, false, err
	}
	for _, logout := range logoutURIs {
		if err := ValidateRedirectURI(logout, clientType); err != nil {
			return nil, nil, nil, nil, nil, nil, false, err
		}
	}
	scopes, err := ParseScopes(scopeRaw)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, false, err
	}
	audiences, err := ParseAudiences(audienceRaw)
	if err != nil || len(audiences) == 0 {
		return nil, nil, nil, nil, nil, nil, false, fmt.Errorf("%w: 至少登记一个允许的目标资源", ErrInvalidRequest)
	}
	methods, err := ParseAuthMethods(authRaw)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, false, err
	}
	pkce := true
	if requirePKCE != nil {
		pkce = *requirePKCE
	}
	switch clientType {
	case ClientTypePublic:
		if len(methods) != 0 {
			return nil, nil, nil, nil, nil, nil, false, fmt.Errorf("%w: 公开客户端不能配置身份验证方式或密钥", ErrInvalidConfiguration)
		}
		for _, grant := range grants {
			if grant == GrantClientCredentials {
				return nil, nil, nil, nil, nil, nil, false, fmt.Errorf("%w: 公开客户端不能使用 client_credentials", ErrInvalidConfiguration)
			}
		}
		if !pkce {
			return nil, nil, nil, nil, nil, nil, false, fmt.Errorf("%w: 公开客户端必须要求 PKCE", ErrInvalidConfiguration)
		}
		pkce = true
	case ClientTypeConfidential:
		if len(methods) == 0 {
			return nil, nil, nil, nil, nil, nil, false, fmt.Errorf("%w: 保密客户端必须配置至少一种身份验证方式", ErrInvalidConfiguration)
		}
	}
	return grants, redirects, logoutURIs, scopes, audiences, methods, pkce, nil
}

// settingsDigest 计算安全设置的稳定摘要（用于敏感操作绑定），不含凭证。
func settingsDigest(client Client) string {
	type configDocument struct {
		ClientType             ClientType   `json:"client_type"`
		GrantTypes             []GrantType  `json:"grant_types"`
		RedirectURIs           []string     `json:"redirect_uris"`
		PostLogoutRedirectURIs []string     `json:"post_logout_redirect_uris"`
		Scopes                 []string     `json:"scopes"`
		Audiences              []string     `json:"audiences"`
		AuthMethods            []AuthMethod `json:"auth_methods"`
		RequirePKCE            bool         `json:"require_pkce"`
	}
	document := configDocument{
		ClientType: client.ClientType, GrantTypes: client.GrantTypes,
		RedirectURIs: client.RedirectURIs, PostLogoutRedirectURIs: client.PostLogoutRedirectURIs,
		Scopes: client.Scopes, Audiences: client.Audiences,
		AuthMethods: client.AuthMethods, RequirePKCE: client.RequirePKCE,
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func clientView(record ClientRecord) Client {
	return clientViewOf(record.Client)
}

func clientViewOf(client Client) Client {
	client.GrantTypes = append([]GrantType(nil), client.GrantTypes...)
	client.RedirectURIs = append([]string(nil), client.RedirectURIs...)
	client.PostLogoutRedirectURIs = append([]string(nil), client.PostLogoutRedirectURIs...)
	client.Scopes = append([]string(nil), client.Scopes...)
	client.Audiences = append([]string(nil), client.Audiences...)
	client.AuthMethods = append([]AuthMethod(nil), client.AuthMethods...)
	return client
}

func secretInfo(record SecretRecord) ClientSecretInfo {
	return ClientSecretInfo{ID: record.ID, Prefix: record.Prefix, CreatedAt: record.CreatedAt,
		ExpiresAt: record.ExpiresAt, RetireAt: record.RetireAt, RevokedAt: record.RevokedAt}
}

func certificateInfoOf(record CertificateRecord) ClientCertificateInfo {
	return ClientCertificateInfo{ID: record.ID, FingerprintSHA256: hexFingerprint(record.FingerprintSHA256),
		Subject: record.Subject, NotBefore: record.NotBefore, NotAfter: record.NotAfter,
		CreatedAt: record.CreatedAt, RevokedAt: record.RevokedAt}
}

// secretUsable 报告密钥当前是否可用于客户端身份验证（未撤销、未过期、未退休）。
func secretUsable(record SecretRecord, now time.Time) bool {
	if !record.RevokedAt.IsZero() {
		return false
	}
	if !now.Before(record.ExpiresAt) {
		return false
	}
	if !record.RetireAt.IsZero() && !now.Before(record.RetireAt) {
		return false
	}
	return true
}

// newClientSecret 生成高熵客户端密钥与展示前缀；明文只由调用方返回一次。
func (s *Service) newClientSecret() (secret, prefix string, err error) {
	buffer := make([]byte, 32)
	if _, err := io.ReadFull(s.opts.Random, buffer); err != nil {
		return "", "", fmt.Errorf("%w: 安全随机源不可用", ErrStoreUnavailable)
	}
	secret = base64.RawURLEncoding.EncodeToString(buffer)
	if len(secret) < 8 {
		return "", "", fmt.Errorf("%w: 生成的密钥长度不足", ErrStoreUnavailable)
	}
	return secret, secret[:8], nil
}

// parseClientCertificate 解析并校验客户端公钥证书：只接受单个 CERTIFICATE 块，
// 拒绝私钥、CA 证书、过期/未生效证书；ID/ClientID 由调用方补齐。
func parseClientCertificate(pemText string, now time.Time) (CertificateRecord, error) {
	trimmed := strings.TrimSpace(pemText)
	if trimmed == "" || len(trimmed) > MaxCertificatePEMBytes {
		return CertificateRecord{}, fmt.Errorf("%w: 证书内容长度无效", ErrInvalidRequest)
	}
	if strings.Contains(strings.ToUpper(trimmed), "PRIVATE KEY") {
		return CertificateRecord{}, fmt.Errorf("%w: 只能登记公钥证书，不能包含私钥", ErrInvalidRequest)
	}
	rest := []byte(trimmed)
	var certificateBlock *pem.Block
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type == "CERTIFICATE" {
			if certificateBlock != nil {
				return CertificateRecord{}, fmt.Errorf("%w: 只允许登记一张叶证书", ErrInvalidRequest)
			}
			certificateBlock = block
			continue
		}
		if block.Type == "PRIVATE KEY" || strings.Contains(block.Type, "PRIVATE") {
			return CertificateRecord{}, fmt.Errorf("%w: 不能登记私钥", ErrInvalidRequest)
		}
	}
	if certificateBlock == nil {
		return CertificateRecord{}, fmt.Errorf("%w: 未找到证书 PEM 块", ErrInvalidRequest)
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		return CertificateRecord{}, fmt.Errorf("%w: 证书 PEM 之后存在多余内容", ErrInvalidRequest)
	}
	parsed, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		return CertificateRecord{}, fmt.Errorf("%w: 证书无法解析", ErrInvalidRequest)
	}
	if parsed.IsCA {
		return CertificateRecord{}, fmt.Errorf("%w: 不能登记 CA 证书作为客户端身份", ErrInvalidRequest)
	}
	if now.Before(parsed.NotBefore) || !now.Before(parsed.NotAfter) {
		return CertificateRecord{}, fmt.Errorf("%w: 证书当前不在有效期内", ErrInvalidRequest)
	}
	fingerprint := sha256.Sum256(parsed.Raw)
	return CertificateRecord{
		FingerprintSHA256: fingerprint, Subject: parsed.Subject.String(),
		NotBefore: parsed.NotBefore.UTC(), NotAfter: parsed.NotAfter.UTC(),
		CertificatePEM: trimmed, CreatedAt: now,
	}, nil
}

// parseLeafCertificate 解析证书并返回 SHA-256 指纹；有效期按给定时间校验。
func parseLeafCertificate(pemText string, now time.Time) ([32]byte, error) {
	record, err := parseClientCertificate(pemText, now)
	if err != nil {
		return [32]byte{}, err
	}
	return record.FingerprintSHA256, nil
}

func validCredentialID(value, prefix string) bool {
	if len(value) != len(prefix)+32 || !strings.HasPrefix(value, prefix) {
		return false
	}
	for index := len(prefix); index < len(value); index++ {
		character := value[index]
		if (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') {
			continue
		}
		return false
	}
	return true
}

// mustNewID 生成带前缀的 128 位随机 ID；随机源不可用时返回空串由存储层拒绝。
func mustNewID(random io.Reader, prefix string) string {
	buffer := make([]byte, 16)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return ""
	}
	return prefix + hex.EncodeToString(buffer)
}

func joinGrants(grants []GrantType) []string {
	values := make([]string, 0, len(grants))
	for _, grant := range grants {
		values = append(values, string(grant))
	}
	return values
}

func joinMethods(methods []AuthMethod) []string {
	values := make([]string, 0, len(methods))
	for _, method := range methods {
		values = append(values, string(method))
	}
	return values
}

func subtleCompare(left, right [32]byte) bool {
	return constantTimeEqual(left, right)
}

func (s *Service) now() time.Time { return s.opts.Now().UTC().Truncate(time.Millisecond) }

func validRequestID(value string) string {
	if account.ValidateRequestID(value) != nil {
		return ""
	}
	return value
}

// authorize 判定当前管理权限；未接线/拒绝统一 fail-closed。
func (s *Service) authorize(ctx context.Context, caller Caller, clientID string, action Action) error {
	if err := caller.actor.Validate(); err != nil {
		return ErrAccessDenied
	}
	if err := s.opts.Authorizer.AuthorizeClient(ctx, caller, clientID, action); err != nil {
		if errors.Is(err, ErrAccessDenied) {
			return ErrAccessDenied
		}
		return fmt.Errorf("%w: %w", ErrAuthzUnavailable, err)
	}
	return nil
}

// authorizeSensitive 执行步骤 38/39 敏感策略判定并绑定操作/目标/配置摘要。
func (s *Service) authorizeSensitive(ctx context.Context, caller Caller, operationID, targetType,
	targetID string, params map[string]string, description, requestID string) (reauth.Result, error) {
	guardCaller, err := reauth.CallerFromActor(caller.actor)
	if err != nil {
		return reauth.Result{}, ErrAccessDenied
	}
	result, err := s.opts.Sensitive.Authorize(ctx, guardCaller, reauth.Request{
		ScopeID: "system", OperationID: operationID, TargetType: targetType, TargetID: targetID,
		Params: params, Description: description, RequestID: requestID,
	})
	if err != nil {
		return reauth.Result{}, mapReauthError(err)
	}
	return result, nil
}

// notifySensitive 发送/记录执行后安全告知；失败只记日志，不回滚已成功变更。
func (s *Service) notifySensitive(ctx context.Context, result reauth.Result) {
	if result.OperationID == "" {
		return
	}
	if err := s.opts.Sensitive.NotifyOutcome(ctx, result, reauth.OutcomeSuccess); err != nil {
		s.opts.Logger.Warn("客户端安全设置告知未完成", "error", err)
	}
}

// recordFailure 写拒绝/失败审计（独立事务）；审计失败不改变拒绝结果。
func (s *Service) recordFailure(ctx context.Context, actor audit.Actor, action, targetType, targetID,
	reason, code, requestID string) {
	if err := actor.Validate(); err != nil {
		return
	}
	event := audit.Event{
		Actor: actor, Action: action, Outcome: audit.OutcomeDenied,
		Target:    audit.Target{Type: targetType, ID: targetID},
		ErrorCode: code, ReasonCode: safeToken(reason), RequestID: validRequestID(requestID),
	}
	if err := s.opts.Audit.RecordFailure(ctx, event); err != nil {
		s.opts.Logger.Warn("OAuth 客户端失败审计写入失败", "error", err)
	}
}

func safeToken(value string) string {
	if len(value) == 0 || len(value) > 64 {
		return ""
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '_' {
			continue
		}
		return ""
	}
	return value
}

func mapReauthError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, reauth.ErrAccessDenied):
		return ErrAccessDenied
	case errors.Is(err, reauth.ErrMFARequired):
		return fmt.Errorf("%w: %w", ErrMFARequired, err)
	case errors.Is(err, reauth.ErrReauthRequired), errors.Is(err, reauth.ErrConfirmationRequired),
		errors.Is(err, reauth.ErrAuthenticationFailed), errors.Is(err, reauth.ErrChallengeInvalid),
		errors.Is(err, reauth.ErrChallengeExpired), errors.Is(err, reauth.ErrAttemptsExceeded),
		errors.Is(err, reauth.ErrApprovalInvalid), errors.Is(err, reauth.ErrApprovalExpired),
		errors.Is(err, reauth.ErrApprovalConsumed), errors.Is(err, reauth.ErrRateLimited):
		return fmt.Errorf("%w: %w", ErrReauthRequired, err)
	default:
		return fmt.Errorf("%w: %w", ErrAuthzUnavailable, err)
	}
}

func mapStoreError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrStoreUnavailable) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
}

func mapCriticalError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, audit.ErrAuditUnavailable):
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	case errors.Is(err, audit.ErrInvalidEvent):
		return fmt.Errorf("%w: 审计事件无效", ErrOptionsInvalid)
	case errors.Is(err, ErrStoreUnavailable):
		return err
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
}
