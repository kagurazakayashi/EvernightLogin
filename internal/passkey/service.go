package passkey

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// 敏感策略目录中的稳定操作 ID（步骤 38 目录体系）。
const (
	operationRegister = "passkey.register"
	operationRemove   = "passkey.remove"
)

// Options 是 Passkey 服务依赖。Store/Audit/Sessions 缺失时构造失败（fail-closed）；
// Reauth 缺失时新增/删除凭证一律拒绝。
type Options struct {
	Store    Store
	Audit    AuditRecorder
	Sessions SessionIssuer
	// Reauth 是步骤 39 的近期认证与敏感策略收敛入口；nil 时新增/删除凭证拒绝。
	Reauth reauth.OperationRunner
	// OtherStrongFactors 报告其他强因素（如 TOTP）；nil 视为没有。删除最后一个第二
	// 步凭证且账户被强制 MFA 时，没有其他强因素会拒绝删除（避免失去强认证）。
	OtherStrongFactors OtherStrongFactors
	// MFAPolicy 报告账户是否被强制 MFA；nil 视为没有外部强制策略。
	MFAPolicy MFAPolicy
	// SessionInvalidator 在删除凭证（强因素变更）后撤销该用户既有会话；nil 时
	// 仍会在同事务递增 security_version 使会话失效，本接口提供更即时的撤销。
	SessionInvalidator SessionInvalidator
	Config             Config
	Now                func() time.Time
	Random             io.Reader
	Logger             *slog.Logger
}

// Service 是 Passkey 注册、登录与凭证管理服务。构造后不可变，不启动协程、不暴露
// HTTP 路由；宿主必须先从可信会话建立 Caller，再调用本服务。
type Service struct {
	opts     Options
	webauthn *webauthn.WebAuthn
}

// New 校验依赖与配置并构造服务。配置非法（RP ID/允许来源/UV/上限）一律拒绝。
func New(options Options) (*Service, error) {
	if isNil(options.Store) {
		return nil, fmt.Errorf("%w: Passkey 存储为空", ErrOptionsInvalid)
	}
	if isNil(options.Audit) {
		return nil, fmt.Errorf("%w: 审计写入器为空", ErrOptionsInvalid)
	}
	if isNil(options.Sessions) {
		return nil, fmt.Errorf("%w: 会话签发器为空", ErrOptionsInvalid)
	}
	config, err := options.Config.validated()
	if err != nil {
		return nil, err
	}
	options.Config = config
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	requireResidentKey := true
	webAuthn, err := webauthn.New(&webauthn.Config{
		RPID:          config.RPID,
		RPDisplayName: config.RPDisplayName,
		RPOrigins:     append([]string(nil), config.Origins...),
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: &requireResidentKey,
			UserVerification:   protocolValue(config.UserVerification),
		},
		AttestationPreference: protocol.PreferNoAttestation,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: WebAuthn 依赖方配置无效: %v", ErrOptionsInvalid, err)
	}
	return &Service{opts: options, webauthn: webAuthn}, nil
}

// RPID 返回当前配置的 RP ID（诊断/页面使用，不是认证依据）。
func (s *Service) RPID() string { return s.opts.Config.RPID }

// ===== 注册 =====

// RegistrationStart 是开始注册的结果。PublicKey 是浏览器
// navigator.credentials.create() 的 publicKey 选项 JSON；不含秘密。
type RegistrationStart struct {
	CeremonyID       string
	PublicKey        json.RawMessage
	ExpiresAt        time.Time
	RPID             string
	UserVerification UserVerification
	// Purpose 是本次注册的目标凭证用途；完成注册时只能使用挑战中保存的用途，
	// 客户端不能改写。
	Purpose Purpose
}

// BeginRegistration 为当前已认证用户在服务端创建主登录用途的注册挑战
// （等价于 BeginRegistrationWithPurpose(..., PurposeLogin)）。
//
// 装配约束：Caller 必须来自完整（非受限）已认证会话；本服务不判断会话是否受限，
// 宿主必须拒绝把待第二因素/待改密等受限会话接到注册入口。强认证初始化受限流程
// 绑定强因素时，宿主必须限定为 PurposeBoth（同时允许主登录与第二步）或
// PurposeSecondFactor，并在初始化完成后撤销受限会话。真正的近期认证检查在
// FinishRegistration 的成功写入前执行（passkey.register 策略）。
func (s *Service) BeginRegistration(ctx context.Context, caller Caller, requestID string) (RegistrationStart, error) {
	return s.BeginRegistrationWithPurpose(ctx, caller, requestID, PurposeLogin)
}

// BeginRegistrationWithPurpose 创建指定用途的注册挑战。purpose 由服务端入口决定
// （主登录注册 / 安全密钥第二步注册 / 强认证初始化），完成后写入凭证且不可由客户端
// 修改；第二步注册不要求可发现凭证（resident key discouraged），主登录/两者要求
// 可发现凭证（resident key required）。
func (s *Service) BeginRegistrationWithPurpose(ctx context.Context, caller Caller,
	requestID string, purpose Purpose) (RegistrationStart, error) {
	ctx = normalizeContext(ctx)
	if !purpose.Valid() {
		return RegistrationStart{}, fmt.Errorf("%w: 凭证用途未知", ErrInvalidRequest)
	}
	if err := s.requireUserCaller(caller); err != nil {
		return RegistrationStart{}, err
	}
	if err := account.ValidateRequestID(requestID); err != nil {
		s.recordFailure(ctx, caller.Actor(), "passkey.register_begin_denied", "invalid_request",
			string(CodeReqInvalid), "")
		return RegistrationStart{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	s.cleanupCeremonies(ctx)
	state, found, err := s.opts.Store.UserState(ctx, caller.Actor().ID)
	if err != nil {
		return RegistrationStart{}, ErrStoreUnavailable
	}
	if !found || !state.Active() {
		s.recordFailure(ctx, caller.Actor(), "passkey.register_begin_denied", "account_not_eligible",
			string(CodeAccessDenied), requestID)
		return RegistrationStart{}, ErrAccessDenied
	}
	credentials, err := s.opts.Store.ListActiveCredentials(ctx, caller.Actor().ID)
	if err != nil {
		return RegistrationStart{}, ErrStoreUnavailable
	}
	if len(credentials) >= s.opts.Config.MaxCredentialsPerUser {
		s.recordFailure(ctx, caller.Actor(), "passkey.register_begin_denied", "credential_limit",
			string(CodeConflict), requestID)
		return RegistrationStart{}, ErrCredentialLimit
	}
	handle, err := s.ensureHandle(ctx, state)
	if err != nil {
		return RegistrationStart{}, err
	}
	user := newWebAuthnUser(state, handle, credentials)
	registrationOptions := []webauthn.RegistrationOption{
		webauthn.WithExclusions(credentialDescriptors(credentials)),
	}
	if !purpose.AllowsLogin() {
		// 第二步用途通常由外置安全密钥承担，不要求可发现凭证；仍由配置要求 UV。
		registrationOptions = append(registrationOptions,
			webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementDiscouraged))
	}
	creation, sessionData, err := s.webauthn.BeginRegistration(user, registrationOptions...)
	if err != nil {
		s.opts.Logger.Warn("Passkey 注册挑战生成失败", "error", err)
		return RegistrationStart{}, fmt.Errorf("%w: 无法生成注册挑战", ErrInternal)
	}
	payload, err := json.Marshal(creation)
	if err != nil {
		return RegistrationStart{}, fmt.Errorf("%w: 无法序列化注册选项", ErrInternal)
	}
	sessionBytes, err := sessionData.MarshalMsg(nil)
	if err != nil {
		return RegistrationStart{}, fmt.Errorf("%w: 无法保存挑战状态", ErrInternal)
	}
	now := s.now()
	ceremonyID, idErr := s.newID("pkc_")
	if idErr != nil {
		return RegistrationStart{}, idErr
	}
	ceremony := Ceremony{
		ID: ceremonyID, UserID: caller.Actor().ID,
		Operation: OperationRegistration, Purpose: purpose, Challenge: sessionData.Challenge,
		RPID: s.opts.Config.RPID, SessionData: sessionBytes,
		RequestID: validRequestID(requestID), CreatedAt: now,
		ExpiresAt: now.Add(s.opts.Config.CeremonyTTL),
	}
	if err := s.opts.Store.CreateCeremony(ctx, ceremony); err != nil {
		return RegistrationStart{}, ErrStoreUnavailable
	}
	return RegistrationStart{
		CeremonyID: ceremony.ID, PublicKey: payload, ExpiresAt: ceremony.ExpiresAt,
		RPID: s.opts.Config.RPID, UserVerification: s.opts.Config.UserVerification,
		Purpose: purpose,
	}, nil
}

// RegistrationFinishRequest 是完成注册的请求。
type RegistrationFinishRequest struct {
	CeremonyID string
	// Response 是浏览器 PublicKeyCredential（navigator.credentials.create 结果）的 JSON。
	Response json.RawMessage
	// Name 是凭证显示名；空时使用“Passkey”。
	Name      string
	RequestID string
}

// FinishRegistration 校验认证器注册响应并创建凭证。
//
// 处理顺序：一次性消费挑战 → 校验认证器响应（库校验 challenge/类型/来源/RP ID/
// 签名/UP/UV）→ 近期认证与敏感策略（passkey.register）→ 审计事务内创建凭证。
// 凭证绑定的是服务端挑战中的用户，客户端无法把认证器凭证登记到别的账户；凭证 ID
// 全表唯一，重复或跨用户登记被拒绝。
func (s *Service) FinishRegistration(ctx context.Context, caller Caller, request RegistrationFinishRequest) (CredentialMetadata, error) {
	return s.finishRegistration(ctx, caller, request, false)
}

// FinishRegistrationTrusted 由受控恢复流程使用：恢复代码已验证并处于受限恢复会话，
// 新强因素绑定由恢复服务授权；不跳过 WebAuthn 校验，只跳过额外的 passkey.register
// 再次认证（恢复代码本身已是替代第二因素的强认证事实）。不得暴露给普通页面入口。
func (s *Service) FinishRegistrationTrusted(ctx context.Context, caller Caller,
	request RegistrationFinishRequest) (CredentialMetadata, error) {
	return s.finishRegistration(ctx, caller, request, true)
}

func (s *Service) finishRegistration(ctx context.Context, caller Caller,
	request RegistrationFinishRequest, trustedRecovery bool) (CredentialMetadata, error) {
	ctx = normalizeContext(ctx)
	if err := s.requireUserCaller(caller); err != nil {
		return CredentialMetadata{}, err
	}
	if !validRecordID(request.CeremonyID) || len(request.Response) == 0 || len(request.Response) > MaxResponseBytes {
		s.recordFailure(ctx, caller.Actor(), "passkey.register_finish_denied", "invalid_params",
			string(CodeReqInvalid), request.RequestID)
		return CredentialMetadata{}, ErrInvalidRequest
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		s.recordFailure(ctx, caller.Actor(), "passkey.register_finish_denied", "invalid_request",
			string(CodeReqInvalid), "")
		return CredentialMetadata{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	name, nameErr := normalizeCredentialName(request.Name)
	if nameErr != nil {
		s.recordFailure(ctx, caller.Actor(), "passkey.register_finish_denied", "invalid_name",
			string(CodeReqInvalid), request.RequestID)
		return CredentialMetadata{}, nameErr
	}
	now := s.now()
	ceremony, err := s.opts.Store.ConsumeCeremony(ctx, request.CeremonyID,
		OperationRegistration, caller.Actor().ID, "", now)
	if err != nil {
		s.recordFailure(ctx, caller.Actor(), "passkey.register_finish_denied", "ceremony_invalid",
			string(CodeOf(err)), request.RequestID)
		return CredentialMetadata{}, err
	}
	if ceremony.RPID != s.opts.Config.RPID {
		s.recordFailure(ctx, caller.Actor(), "passkey.register_finish_denied", "rp_mismatch",
			string(CodeChallengeInvalid), request.RequestID)
		return CredentialMetadata{}, ErrCeremonyInvalid
	}
	if !ceremony.Purpose.Valid() {
		s.recordFailure(ctx, caller.Actor(), "passkey.register_finish_denied", "purpose_invalid",
			string(CodeChallengeInvalid), request.RequestID)
		return CredentialMetadata{}, ErrCeremonyInvalid
	}
	sessionData, err := decodeSessionData(ceremony.SessionData)
	if err != nil {
		s.recordFailure(ctx, caller.Actor(), "passkey.register_finish_denied", "session_data_invalid",
			string(CodeChallengeInvalid), request.RequestID)
		return CredentialMetadata{}, ErrCeremonyInvalid
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(request.Response)
	if err != nil {
		s.recordFailure(ctx, caller.Actor(), "passkey.register_finish_denied", "response_parse",
			string(CodeChallengeInvalid), request.RequestID)
		return CredentialMetadata{}, fmt.Errorf("%w: 注册响应格式无效", ErrCeremonyInvalid)
	}
	state, found, err := s.opts.Store.UserState(ctx, caller.Actor().ID)
	if err != nil {
		return CredentialMetadata{}, ErrStoreUnavailable
	}
	if !found || !state.Active() || len(state.Handle) == 0 {
		s.recordFailure(ctx, caller.Actor(), "passkey.register_finish_denied", "account_not_eligible",
			string(CodeAccessDenied), request.RequestID)
		return CredentialMetadata{}, ErrAccessDenied
	}
	credentials, err := s.opts.Store.ListActiveCredentials(ctx, caller.Actor().ID)
	if err != nil {
		return CredentialMetadata{}, ErrStoreUnavailable
	}
	user := newWebAuthnUser(state, state.Handle, credentials)
	credential, err := s.webauthn.CreateCredential(user, *sessionData, parsed)
	if err != nil {
		s.opts.Logger.Debug("Passkey 注册响应校验失败", "error", err)
		s.recordFailure(ctx, caller.Actor(), "passkey.register_finish_denied", "webauthn_rejected",
			string(CodeChallengeInvalid), request.RequestID)
		return CredentialMetadata{}, fmt.Errorf("%w: 认证器注册响应未通过校验", ErrCeremonyInvalid)
	}
	// 近期认证必须在真实写入前执行；策略不满足时 fail-closed，不创建凭证。
	// 受控恢复流程已完成恢复代码验证（恢复代码替代第二因素的强认证事实），由恢复
	// 服务决定是否允许绑定新强因素；这里只跳过重复的 passkey.register 敏感审批，
	// WebAuthn 注册响应仍必须通过上面的真实校验。
	var authorization reauth.Result
	if !trustedRecovery {
		var authErr error
		authorization, authErr = s.authorize(ctx, caller, operationRegister, request.RequestID,
			map[string]string{"operation": "register", "usage": ceremony.Purpose.usage(), "name": name},
			"注册 Passkey 凭证")
		if authErr != nil {
			s.recordFailure(ctx, caller.Actor(), "passkey.register_finish_denied", reauthReason(authErr),
				string(CodeOf(authErr)), request.RequestID)
			return CredentialMetadata{}, authErr
		}
	}
	recordID, idErr := s.newID("cred_")
	if idErr != nil {
		return CredentialMetadata{}, idErr
	}
	record := Credential{
		ID: recordID, UserID: caller.Actor().ID,
		CredentialID: credential.ID, PublicKey: credential.PublicKey,
		AAGUID: credential.Authenticator.AAGUID, RPID: s.opts.Config.RPID,
		Name: name, SignCount: credential.Authenticator.SignCount,
		Transports:     transportStrings(credential.Transport),
		BackupEligible: credential.Flags.BackupEligible, BackedUp: credential.Flags.BackupState,
		UserPresent: credential.Flags.UserPresent, UserVerified: credential.Flags.UserVerified,
		Attachment: string(credential.Authenticator.Attachment), Usage: ceremony.Purpose.usage(),
		Version: 1, CreatedAt: now, UpdatedAt: now,
	}
	critical := s.critical("passkey.registered", caller.Actor(), record.ID, request.RequestID,
		[]audit.FieldChange{
			{Field: "credential_id", After: hex.EncodeToString(record.CredentialID)},
			{Field: "name", After: record.Name},
			{Field: "usage", After: record.Usage},
			{Field: "backup_eligible", After: fmt.Sprint(record.BackupEligible)},
			{Field: "backed_up", After: fmt.Sprint(record.BackedUp)},
		})
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.opts.Store.CreateCredentialTx(txCtx, tx, record)
	}); err != nil {
		return CredentialMetadata{}, mapCriticalError(err)
	}
	s.notifyOutcome(ctx, authorization, reauth.OutcomeSuccess, request.RequestID)
	return metadata(record), nil
}

// ===== 登录 =====

// LoginStartRequest 是开始登录的请求。Username 为空表示可发现凭证（usernameless）
// 登录；非空时按用户名检索该账户的凭证。
type LoginStartRequest struct {
	Username   string
	AppID      string
	RememberMe bool
	Client     session.ClientInfo
	RequestID  string
}

// LoginStart 是开始登录的结果。PublicKey 是
// navigator.credentials.get() 的 publicKey 选项 JSON。
type LoginStart struct {
	CeremonyID string
	PublicKey  json.RawMessage
	ExpiresAt  time.Time
	RPID       string
}

// BeginLogin 创建认证挑战。用户名不存在、账户不可用、无凭证等情况统一返回
// ErrAuthenticationFailed（不区分原因，避免账户/凭证存在性探测）；可发现凭证
// 登录不查询用户。
//
// 应用作用域：AppID 在开始阶段绑定到服务端挑战，完成阶段只能以同一 AppID 签发
// 会话（不会升级为全局会话）。
func (s *Service) BeginLogin(ctx context.Context, request LoginStartRequest) (LoginStart, error) {
	ctx = normalizeContext(ctx)
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return LoginStart{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if len(request.AppID) > 128 || len(request.Client.UserAgent) > 512 || len(request.Client.Address) > 256 {
		return LoginStart{}, ErrInvalidRequest
	}
	s.cleanupCeremonies(ctx)
	now := s.now()
	appID := strings.TrimSpace(request.AppID)
	ceremonyID, idErr := s.newID("pkc_")
	if idErr != nil {
		return LoginStart{}, idErr
	}
	ceremony := Ceremony{
		ID: ceremonyID, Operation: OperationAuthentication, Purpose: PurposeLogin,
		AppID: appID, RememberMe: request.RememberMe,
		UserAgent: sanitizeText(request.Client.UserAgent, 256),
		Address:   sanitizeText(request.Client.Address, 128),
		RequestID: validRequestID(request.RequestID), CreatedAt: now,
		ExpiresAt: now.Add(s.opts.Config.CeremonyTTL), RPID: s.opts.Config.RPID,
	}
	var user webauthn.User
	if strings.TrimSpace(request.Username) == "" {
		assertion, sessionData, err := s.webauthn.BeginDiscoverableLogin()
		if err != nil {
			return LoginStart{}, fmt.Errorf("%w: 无法生成登录挑战", ErrInternal)
		}
		ceremony.Challenge = sessionData.Challenge
		if ceremony.SessionData, err = sessionData.MarshalMsg(nil); err != nil {
			return LoginStart{}, fmt.Errorf("%w: 无法保存挑战状态", ErrInternal)
		}
		return s.finishLoginStart(ctx, ceremony, assertion)
	}
	display, normalized, err := account.NormalizeUsername(request.Username)
	if err != nil || normalized == "" {
		s.recordAnonymousFailure(ctx, "passkey.login_begin_denied", "invalid_username", request.RequestID)
		return LoginStart{}, ErrAuthenticationFailed
	}
	_ = display
	userID, found, err := s.opts.Store.UserIDByNormalizedUsername(ctx, normalized)
	if err != nil {
		return LoginStart{}, ErrStoreUnavailable
	}
	if !found {
		s.recordAnonymousFailure(ctx, "passkey.login_begin_denied", "unknown_user", request.RequestID)
		return LoginStart{}, ErrAuthenticationFailed
	}
	state, found, err := s.opts.Store.UserState(ctx, userID)
	if err != nil {
		return LoginStart{}, ErrStoreUnavailable
	}
	if !found || !state.Active() || state.IsRoot || len(state.Handle) == 0 {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: userID},
			"passkey.login_begin_denied", "account_not_eligible", string(CodeAuthFailed), request.RequestID)
		return LoginStart{}, ErrAuthenticationFailed
	}
	credentials, err := s.opts.Store.ListActiveCredentials(ctx, userID)
	if err != nil {
		return LoginStart{}, ErrStoreUnavailable
	}
	// 主登录只能使用用途为 login/both 的凭证；第二步凭证不能冒充主登录。
	credentials = filterCredentials(credentials, func(credential Credential) bool {
		return credentialPurposeAllowsLogin(credential)
	})
	if len(credentials) == 0 {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: userID},
			"passkey.login_begin_denied", "no_credentials", string(CodeAuthFailed), request.RequestID)
		return LoginStart{}, ErrAuthenticationFailed
	}
	user = newWebAuthnUser(state, state.Handle, credentials)
	assertion, sessionData, err := s.webauthn.BeginLogin(user)
	if err != nil {
		return LoginStart{}, fmt.Errorf("%w: 无法生成登录挑战", ErrInternal)
	}
	ceremony.UserID = userID
	ceremony.Challenge = sessionData.Challenge
	if ceremony.SessionData, err = sessionData.MarshalMsg(nil); err != nil {
		return LoginStart{}, fmt.Errorf("%w: 无法保存挑战状态", ErrInternal)
	}
	return s.finishLoginStart(ctx, ceremony, assertion)
}

// finishLoginStart 持久化挑战并返回浏览器选项。
func (s *Service) finishLoginStart(ctx context.Context, ceremony Ceremony,
	assertion *protocol.CredentialAssertion) (LoginStart, error) {
	payload, err := json.Marshal(assertion)
	if err != nil {
		return LoginStart{}, fmt.Errorf("%w: 无法序列化登录选项", ErrInternal)
	}
	if err := s.opts.Store.CreateCeremony(ctx, ceremony); err != nil {
		return LoginStart{}, ErrStoreUnavailable
	}
	return LoginStart{CeremonyID: ceremony.ID, PublicKey: payload, ExpiresAt: ceremony.ExpiresAt,
		RPID: s.opts.Config.RPID}, nil
}

// LoginFinishRequest 是完成登录的请求。
type LoginFinishRequest struct {
	CeremonyID string
	// Response 是浏览器 PublicKeyCredential（navigator.credentials.get 结果）的 JSON。
	Response json.RawMessage
	// ExistingSession 是客户端本次出示的旧会话秘密，用于登录轮换；可为空。
	ExistingSession string
	RequestID       string
}

// LoginResult 是一次成功 Passkey 登录的结果。Authenticated 是真实完成的认证结果
// （Passkey 方法、完整、携带安全版本），会话由 internal/session 签发。
type LoginResult struct {
	Session       session.IssuedSession
	Authenticated authn.AuthenticateResult
	Credential    CredentialMetadata
	UserVerified  bool
}

// FinishLogin 校验认证器断言并签发会话。
//
// 成功条件：挑战未消费且未过期（一次性原子消费）、操作类型为认证、挑战 RP ID 与
// 当前配置一致、认证器响应通过库校验（challenge/来源/RP ID/签名/UP/按策略 UV）、
// 凭证属于已解析用户且未撤销、账户仍为 active。同步凭证计数器不递增被接受，
// 非同步凭证计数器回退按可能的凭证复制拒绝。成功后直接完成登录（不追加同源
// 第二因素），应用作用域登录以挑战绑定的 AppID 签发并防御性复验。
func (s *Service) FinishLogin(ctx context.Context, request LoginFinishRequest) (LoginResult, error) {
	ctx = normalizeContext(ctx)
	if !validRecordID(request.CeremonyID) || len(request.Response) == 0 || len(request.Response) > MaxResponseBytes {
		s.recordAnonymousFailure(ctx, "passkey.login_finish_denied", "invalid_params", request.RequestID)
		return LoginResult{}, ErrInvalidRequest
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		s.recordAnonymousFailure(ctx, "passkey.login_finish_denied", "invalid_request", request.RequestID)
		return LoginResult{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	now := s.now()
	ceremony, err := s.opts.Store.ConsumeCeremony(ctx, request.CeremonyID,
		OperationAuthentication, "", "", now)
	if err != nil {
		s.recordAnonymousFailure(ctx, "passkey.login_finish_denied", "ceremony_invalid", request.RequestID)
		return LoginResult{}, err
	}
	if ceremony.RPID != s.opts.Config.RPID {
		s.recordAnonymousFailure(ctx, "passkey.login_finish_denied", "rp_mismatch", request.RequestID)
		return LoginResult{}, ErrCeremonyInvalid
	}
	sessionData, err := decodeSessionData(ceremony.SessionData)
	if err != nil {
		s.recordAnonymousFailure(ctx, "passkey.login_finish_denied", "session_data_invalid", request.RequestID)
		return LoginResult{}, ErrCeremonyInvalid
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(request.Response)
	if err != nil {
		s.recordAnonymousFailure(ctx, "passkey.login_finish_denied", "response_parse", request.RequestID)
		return LoginResult{}, fmt.Errorf("%w: 认证响应格式无效", ErrAuthenticationFailed)
	}
	var (
		state    UserState
		isState  bool
		verified bool
	)
	validatedCredential, err := s.validateAssertion(ctx, ceremony, sessionData, parsed, &state, &isState)
	if err != nil {
		actor := audit.Actor{Type: audit.ActorAnonymous}
		if isState {
			actor = audit.Actor{Type: audit.ActorUser, ID: state.UserID}
		}
		s.recordFailure(ctx, actor, "passkey.login_finish_denied", "assertion_rejected",
			string(CodeAuthFailed), request.RequestID)
		return LoginResult{}, err
	}
	verified = parsed.Response.AuthenticatorData.Flags.HasUserVerified()
	if s.opts.Config.UserVerification == UserVerificationRequired && !verified {
		// 库在 session.UserVerification=required 时已经拒绝；这是防御性复核。
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: state.UserID},
			"passkey.login_finish_denied", "user_verification_missing", string(CodeAuthFailed), request.RequestID)
		return LoginResult{}, ErrAuthenticationFailed
	}
	stored, found, err := s.opts.Store.ActiveCredentialByRawID(ctx, validatedCredential.ID)
	if err != nil {
		return LoginResult{}, ErrStoreUnavailable
	}
	if !found || stored.UserID != state.UserID {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: state.UserID},
			"passkey.login_finish_denied", "credential_not_owned", string(CodeAuthFailed), request.RequestID)
		return LoginResult{}, ErrAuthenticationFailed
	}
	if !credentialPurposeAllowsLogin(stored) {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: state.UserID},
			"passkey.login_finish_denied", "purpose_not_allowed", string(CodeAccessDenied), request.RequestID)
		return LoginResult{}, ErrPurposeNotAllowed
	}
	// 同步凭证（backup eligible）允许计数器不递增；非同步凭证计数器回退或不变
	// 都按可能的凭证复制处理。库已经在认证器数据里更新了计数器/克隆标记。
	cloneWarning := validatedCredential.Authenticator.CloneWarning
	if cloneWarning && !stored.BackupEligible {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: state.UserID},
			"passkey.login_finish_denied", "clone_warning", string(CodeAuthFailed), request.RequestID)
		return LoginResult{}, ErrCloneDetected
	}
	updated := stored
	updated.SignCount = validatedCredential.Authenticator.SignCount
	updated.BackedUp = validatedCredential.Flags.BackupState
	updated.UserPresent = validatedCredential.Flags.UserPresent
	updated.UserVerified = validatedCredential.Flags.UserVerified
	updated.LastUsedAt = now
	updated.UpdatedAt = now
	updated.Version = stored.Version + 1
	critical := s.critical("passkey.login_verified", audit.Actor{Type: audit.ActorUser, ID: state.UserID},
		stored.ID, request.RequestID, []audit.FieldChange{
			{Field: "sign_count", Before: fmt.Sprint(stored.SignCount), After: fmt.Sprint(updated.SignCount)},
			{Field: "backed_up", Before: fmt.Sprint(stored.BackedUp), After: fmt.Sprint(updated.BackedUp)},
			{Field: "clone_warning", After: fmt.Sprint(cloneWarning)},
			{Field: "user_verified", After: fmt.Sprint(verified)},
		})
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.opts.Store.UpdateCredentialUsageTx(txCtx, tx, updated, now)
	}); err != nil {
		return LoginResult{}, mapCriticalError(err)
	}
	authenticated := completedAuthentication(state, now)
	if verified {
		// Passkey 完成 UV 时为强认证：记录时间供会话管理访问闸门使用（与步骤 39
		// 敏感操作的再认证语义衔接；仍需操作策略要求再次确认时另行 reauth）。
		authenticated.StrongAuthCompletedAt = now
	}
	issued, err := s.opts.Sessions.Login(ctx, session.LoginRequest{
		Result: authenticated, AppID: ceremony.AppID, ExistingSession: request.ExistingSession,
		RequestID: request.RequestID, RememberMe: ceremony.RememberMe,
		Client: session.ClientInfo{UserAgent: ceremony.UserAgent, Address: ceremony.Address},
	})
	if err != nil {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: state.UserID},
			"passkey.login_finish_denied", "session_not_issued", string(CodeAuthFailed), request.RequestID)
		return LoginResult{}, fmt.Errorf("%w: 会话签发失败", ErrAuthenticationFailed)
	}
	// 防御性复验：完整会话不得是受限会话，也不得改变应用作用域（步骤 40 语义）。
	if issued.Session.IsRestricted() || issued.Session.AppID != ceremony.AppID {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: state.UserID},
			"passkey.login_finish_denied", "session_scope_mismatch", string(CodeAuthFailed), request.RequestID)
		return LoginResult{}, fmt.Errorf("%w: 会话作用域不符", ErrAuthenticationFailed)
	}
	return LoginResult{Session: issued, Authenticated: authenticated,
		Credential: metadata(updated), UserVerified: verified}, nil
}

// validateAssertion 执行库校验并解析出用户状态；state 只有在校验成功时有效。
func (s *Service) validateAssertion(ctx context.Context, ceremony Ceremony, sessionData *webauthn.SessionData,
	parsed *protocol.ParsedCredentialAssertionData, state *UserState, isState *bool) (*webauthn.Credential, error) {
	if ceremony.UserID != "" {
		userState, found, err := s.opts.Store.UserState(ctx, ceremony.UserID)
		if err != nil {
			return nil, ErrStoreUnavailable
		}
		if !found || !userState.Active() || len(userState.Handle) == 0 {
			return nil, ErrAuthenticationFailed
		}
		credentials, err := s.opts.Store.ListActiveCredentials(ctx, ceremony.UserID)
		if err != nil {
			return nil, ErrStoreUnavailable
		}
		credentials = filterCredentials(credentials, func(credential Credential) bool {
			return credentialPurposeAllowsLogin(credential)
		})
		if len(credentials) == 0 {
			return nil, ErrAuthenticationFailed
		}
		user := newWebAuthnUser(userState, userState.Handle, credentials)
		credential, err := s.webauthn.ValidateLogin(user, *sessionData, parsed)
		if err != nil {
			s.opts.Logger.Debug("Passkey 认证响应校验失败", "error", err)
			return nil, ErrAuthenticationFailed
		}
		*state = userState
		*isState = true
		return credential, nil
	}
	// 可发现凭证登录：用户句柄来自认证器响应，必须能在服务端解析到 active 账户。
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		if len(userHandle) == 0 || len(userHandle) > 64 {
			return nil, ErrAuthenticationFailed
		}
		userState, found, err := s.opts.Store.UserStateByHandle(ctx, userHandle)
		if err != nil {
			return nil, ErrStoreUnavailable
		}
		if !found || !userState.Active() || userState.IsRoot {
			return nil, ErrAuthenticationFailed
		}
		credentials, err := s.opts.Store.ListActiveCredentials(ctx, userState.UserID)
		if err != nil {
			return nil, ErrStoreUnavailable
		}
		credentials = filterCredentials(credentials, func(credential Credential) bool {
			return credentialPurposeAllowsLogin(credential)
		})
		if len(credentials) == 0 {
			return nil, ErrAuthenticationFailed
		}
		*state = userState
		*isState = true
		return newWebAuthnUser(userState, userState.Handle, credentials), nil
	}
	credential, err := s.webauthn.ValidateDiscoverableLogin(handler, *sessionData, parsed)
	if err != nil {
		s.opts.Logger.Debug("Passkey 可发现凭证认证校验失败", "error", err)
		if errors.Is(err, ErrStoreUnavailable) {
			return nil, ErrStoreUnavailable
		}
		return nil, ErrAuthenticationFailed
	}
	if !*isState {
		return nil, ErrAuthenticationFailed
	}
	return credential, nil
}

// ===== 第二步验证（FIDO2 / 安全密钥） =====

// SecondFactorStart 是开始第二步 WebAuthn 认证的结果。PublicKey 是浏览器
// navigator.credentials.get() 的 publicKey 选项 JSON（allowCredentials 只包含
// 用途允许第二步的凭证）。
type SecondFactorStart struct {
	CeremonyID string
	PublicKey  json.RawMessage
	ExpiresAt  time.Time
	RPID       string
}

// BeginSecondFactor 为 MFA 挑战已确认的账户创建第二步认证挑战。
//
// 安全边界：userID 与 contextID（MFA 挑战 ID）必须由 internal/mfa 从服务端挑战中
// 取得并传入，不能来自客户端自述；本方法不签发会话，只完成 WebAuthn 断言校验。
// 只有用途允许第二步的凭证会进入 allowCredentials，主登录凭证不能冒充第二因素。
func (s *Service) BeginSecondFactor(ctx context.Context, userID, contextID, requestID string) (SecondFactorStart, error) {
	ctx = normalizeContext(ctx)
	if !account.ValidUserID(userID) || contextID == "" || len(contextID) > 128 {
		return SecondFactorStart{}, ErrInvalidRequest
	}
	if err := account.ValidateRequestID(requestID); err != nil {
		return SecondFactorStart{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	s.cleanupCeremonies(ctx)
	state, found, err := s.opts.Store.UserState(ctx, userID)
	if err != nil {
		return SecondFactorStart{}, ErrStoreUnavailable
	}
	// root 的第二因素必须允许 Passkey：root 始终要求强认证，且不能用密码替代；
	// 密码less 主登录仍单独拒绝 root（见 BeginLogin），避免 root 绕过主密码。
	if !found || !state.Active() {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: userID},
			"passkey.second_factor_begin_denied", "account_not_eligible",
			string(CodeAccessDenied), requestID)
		return SecondFactorStart{}, ErrAccessDenied
	}
	credentials, err := s.opts.Store.ListActiveCredentials(ctx, userID)
	if err != nil {
		return SecondFactorStart{}, ErrStoreUnavailable
	}
	credentials = filterCredentials(credentials, credentialPurposeAllowsSecondFactor)
	if len(credentials) == 0 {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: userID},
			"passkey.second_factor_begin_denied", "no_second_factor_credential",
			string(CodeReqInvalid), requestID)
		return SecondFactorStart{}, ErrNoSecondFactor
	}
	if len(state.Handle) == 0 {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: userID},
			"passkey.second_factor_begin_denied", "user_handle_missing",
			string(CodeAccessDenied), requestID)
		return SecondFactorStart{}, ErrAccessDenied
	}
	user := newWebAuthnUser(state, state.Handle, credentials)
	assertion, sessionData, err := s.webauthn.BeginLogin(user)
	if err != nil {
		return SecondFactorStart{}, fmt.Errorf("%w: 无法生成第二步认证挑战", ErrInternal)
	}
	payload, err := json.Marshal(assertion)
	if err != nil {
		return SecondFactorStart{}, fmt.Errorf("%w: 无法序列化第二步选项", ErrInternal)
	}
	sessionBytes, err := sessionData.MarshalMsg(nil)
	if err != nil {
		return SecondFactorStart{}, fmt.Errorf("%w: 无法保存挑战状态", ErrInternal)
	}
	now := s.now()
	ceremonyID, idErr := s.newID("pkc_")
	if idErr != nil {
		return SecondFactorStart{}, idErr
	}
	ceremony := Ceremony{
		ID: ceremonyID, UserID: userID, Operation: OperationSecondFactor,
		Purpose: PurposeSecondFactor, ContextID: contextID,
		Challenge: sessionData.Challenge, RPID: s.opts.Config.RPID,
		SessionData: sessionBytes, RequestID: validRequestID(requestID),
		CreatedAt: now, ExpiresAt: now.Add(s.opts.Config.CeremonyTTL),
	}
	if err := s.opts.Store.CreateCeremony(ctx, ceremony); err != nil {
		return SecondFactorStart{}, ErrStoreUnavailable
	}
	return SecondFactorStart{CeremonyID: ceremony.ID, PublicKey: payload,
		ExpiresAt: ceremony.ExpiresAt, RPID: s.opts.Config.RPID}, nil
}

// SecondFactorFinishRequest 是完成第二步认证的请求。ContextID 必须与开始时的 MFA
// 挑战 ID 一致（服务端再次核对），防止跨登录尝试挪用挑战。
type SecondFactorFinishRequest struct {
	CeremonyID string
	ContextID  string
	Response   json.RawMessage
	RequestID  string
}

// SecondFactorResult 是一次成功 FIDO2 第二步验证的结果；不包含会话秘密，会话由
// internal/mfa 在挑战状态机内签发。
type SecondFactorResult struct {
	UserID          string
	Credential      CredentialMetadata
	AuthenticatorID string
	UserVerified    bool
	VerifiedAt      time.Time
}

// FinishSecondFactor 校验第二步 WebAuthn 断言并原子消费挑战。
// 用途不符/上下文不符/重放/过期都拒绝；非同步凭证计数器回退按可能的复制拒绝；
// 配置要求 UV 时缺少 UV 拒绝。成功写入计数与审计，不签发会话。
func (s *Service) FinishSecondFactor(ctx context.Context, request SecondFactorFinishRequest) (SecondFactorResult, error) {
	ctx = normalizeContext(ctx)
	if !validRecordID(request.CeremonyID) || request.ContextID == "" ||
		len(request.Response) == 0 || len(request.Response) > MaxResponseBytes {
		return SecondFactorResult{}, ErrInvalidRequest
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return SecondFactorResult{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	now := s.now()
	ceremony, err := s.opts.Store.ConsumeCeremony(ctx, request.CeremonyID,
		OperationSecondFactor, "", request.ContextID, now)
	if err != nil {
		return SecondFactorResult{}, err
	}
	if ceremony.RPID != s.opts.Config.RPID || ceremony.Purpose != PurposeSecondFactor ||
		ceremony.UserID == "" {
		return SecondFactorResult{}, ErrCeremonyInvalid
	}
	userID := ceremony.UserID
	sessionData, err := decodeSessionData(ceremony.SessionData)
	if err != nil {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: userID},
			"passkey.second_factor_denied", "session_data_invalid", string(CodeChallengeInvalid), request.RequestID)
		return SecondFactorResult{}, ErrCeremonyInvalid
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(request.Response)
	if err != nil {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: userID},
			"passkey.second_factor_denied", "response_parse", string(CodeChallengeInvalid), request.RequestID)
		return SecondFactorResult{}, fmt.Errorf("%w: 第二步响应格式无效", ErrAuthenticationFailed)
	}
	state, found, err := s.opts.Store.UserState(ctx, userID)
	if err != nil {
		return SecondFactorResult{}, ErrStoreUnavailable
	}
	if !found || !state.Active() || len(state.Handle) == 0 {
		return SecondFactorResult{}, ErrAuthenticationFailed
	}
	credentials, err := s.opts.Store.ListActiveCredentials(ctx, userID)
	if err != nil {
		return SecondFactorResult{}, ErrStoreUnavailable
	}
	credentials = filterCredentials(credentials, credentialPurposeAllowsSecondFactor)
	if len(credentials) == 0 {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: userID},
			"passkey.second_factor_denied", "no_second_factor_credential",
			string(CodeReqInvalid), request.RequestID)
		return SecondFactorResult{}, ErrNoSecondFactor
	}
	user := newWebAuthnUser(state, state.Handle, credentials)
	validated, err := s.webauthn.ValidateLogin(user, *sessionData, parsed)
	if err != nil {
		s.opts.Logger.Debug("FIDO2 第二步断言校验失败", "error", err)
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: userID},
			"passkey.second_factor_denied", "assertion_rejected", string(CodeAuthFailed), request.RequestID)
		return SecondFactorResult{}, ErrAuthenticationFailed
	}
	verified := parsed.Response.AuthenticatorData.Flags.HasUserVerified()
	if s.opts.Config.UserVerification == UserVerificationRequired && !verified {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: userID},
			"passkey.second_factor_denied", "user_verification_missing", string(CodeAuthFailed), request.RequestID)
		return SecondFactorResult{}, ErrAuthenticationFailed
	}
	stored, found, err := s.opts.Store.ActiveCredentialByRawID(ctx, validated.ID)
	if err != nil {
		return SecondFactorResult{}, ErrStoreUnavailable
	}
	if !found || stored.UserID != userID || !credentialPurposeAllowsSecondFactor(stored) {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: userID},
			"passkey.second_factor_denied", "credential_purpose_mismatch",
			string(CodeAccessDenied), request.RequestID)
		return SecondFactorResult{}, ErrPurposeNotAllowed
	}
	cloneWarning := validated.Authenticator.CloneWarning
	if cloneWarning && !stored.BackupEligible {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: userID},
			"passkey.second_factor_denied", "clone_warning", string(CodeAuthFailed), request.RequestID)
		return SecondFactorResult{}, ErrCloneDetected
	}
	updated := stored
	updated.SignCount = validated.Authenticator.SignCount
	updated.BackedUp = validated.Flags.BackupState
	updated.UserPresent = validated.Flags.UserPresent
	updated.UserVerified = validated.Flags.UserVerified
	updated.LastUsedAt = now
	updated.UpdatedAt = now
	updated.Version = stored.Version + 1
	critical := s.critical("passkey.second_factor_verified",
		audit.Actor{Type: audit.ActorUser, ID: userID}, stored.ID, request.RequestID,
		[]audit.FieldChange{
			{Field: "sign_count", Before: fmt.Sprint(stored.SignCount), After: fmt.Sprint(updated.SignCount)},
			{Field: "clone_warning", After: fmt.Sprint(cloneWarning)},
			{Field: "user_verified", After: fmt.Sprint(verified)},
		})
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.opts.Store.UpdateCredentialUsageTx(txCtx, tx, updated, now)
	}); err != nil {
		return SecondFactorResult{}, mapCriticalError(err)
	}
	return SecondFactorResult{UserID: userID, Credential: metadata(updated),
		AuthenticatorID: stored.ID, UserVerified: verified, VerifiedAt: now}, nil
}

// HasSecondFactor 报告用户是否存在可用于第二步验证的 Passkey/安全密钥凭证。
// 供认证方式选择器判断“安全密钥”因素是否实际启用；不返回凭证内容。
func (s *Service) HasSecondFactor(ctx context.Context, userID string) (bool, error) {
	ctx = normalizeContext(ctx)
	if !account.ValidUserID(userID) {
		return false, ErrInvalidRequest
	}
	available, err := s.opts.Store.HasSecondFactorCredential(ctx, userID)
	if err != nil {
		return false, ErrStoreUnavailable
	}
	return available, nil
}

// ===== 凭证管理 =====

// List 返回调用者自己的 Passkey 元数据（不含公钥/凭证 ID 原始字节）。
func (s *Service) List(ctx context.Context, caller Caller) ([]CredentialMetadata, error) {
	ctx = normalizeContext(ctx)
	if err := s.requireUserCaller(caller); err != nil {
		return nil, err
	}
	credentials, err := s.opts.Store.ListActiveCredentials(ctx, caller.Actor().ID)
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	result := make([]CredentialMetadata, 0, len(credentials))
	for _, credential := range credentials {
		result = append(result, metadata(credential))
	}
	return result, nil
}

// RenameRequest 是修改凭证显示名请求。
type RenameRequest struct {
	CredentialID string
	Name         string
	RequestID    string
}

// Rename 修改本人凭证的显示名。显示名只用于界面展示，不参与认证或授权；仍写
// 审计且只能修改本人未撤销的凭证，不要求再次认证（不改变安全状态）。
func (s *Service) Rename(ctx context.Context, caller Caller, request RenameRequest) (CredentialMetadata, error) {
	ctx = normalizeContext(ctx)
	if err := s.requireUserCaller(caller); err != nil {
		return CredentialMetadata{}, err
	}
	name, err := normalizeCredentialName(request.Name)
	if err != nil {
		s.recordFailure(ctx, caller.Actor(), "passkey.rename_denied", "invalid_name",
			string(CodeReqInvalid), request.RequestID)
		return CredentialMetadata{}, err
	}
	if !validRecordID(request.CredentialID) {
		s.recordFailure(ctx, caller.Actor(), "passkey.rename_denied", "invalid_params",
			string(CodeReqInvalid), request.RequestID)
		return CredentialMetadata{}, ErrInvalidRequest
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		s.recordFailure(ctx, caller.Actor(), "passkey.rename_denied", "invalid_request",
			string(CodeReqInvalid), "")
		return CredentialMetadata{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	stored, found, err := s.opts.Store.CredentialByID(ctx, caller.Actor().ID, request.CredentialID)
	if err != nil {
		return CredentialMetadata{}, ErrStoreUnavailable
	}
	if !found {
		s.recordFailure(ctx, caller.Actor(), "passkey.rename_denied", "not_found",
			string(CodeReqInvalid), request.RequestID)
		return CredentialMetadata{}, ErrCredentialNotFound
	}
	now := s.now()
	critical := s.critical("passkey.renamed", caller.Actor(), stored.ID, request.RequestID,
		[]audit.FieldChange{{Field: "name", Before: stored.Name, After: name}})
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, renameErr := s.opts.Store.RenameCredentialTx(txCtx, tx, caller.Actor().ID,
			stored.ID, name, now)
		if renameErr != nil {
			return renameErr
		}
		if !ok {
			return ErrCredentialNotFound
		}
		return nil
	}); err != nil {
		return CredentialMetadata{}, mapCriticalError(err)
	}
	stored.Name = name
	stored.UpdatedAt = now
	return metadata(stored), nil
}

// RevokeRequest 是撤销凭证请求。
type RevokeRequest struct {
	CredentialID string
	RequestID    string
}

// Revoke 在近期认证（passkey.remove 策略）后撤销本人凭证。撤销前在同一审计事务
// 内检查是否还有其他可用登录方式（其他有效 Passkey 或主密码）；不允许撤销最后
// 一个登录方式。撤销是软删除，保留记录与审计关联。
func (s *Service) Revoke(ctx context.Context, caller Caller, request RevokeRequest) error {
	ctx = normalizeContext(ctx)
	if err := s.requireUserCaller(caller); err != nil {
		return err
	}
	if !validRecordID(request.CredentialID) {
		s.recordFailure(ctx, caller.Actor(), "passkey.revoke_denied", "invalid_params",
			string(CodeReqInvalid), request.RequestID)
		return ErrInvalidRequest
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		s.recordFailure(ctx, caller.Actor(), "passkey.revoke_denied", "invalid_request",
			string(CodeReqInvalid), "")
		return fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	stored, found, err := s.opts.Store.CredentialByID(ctx, caller.Actor().ID, request.CredentialID)
	if err != nil {
		return ErrStoreUnavailable
	}
	if !found {
		s.recordFailure(ctx, caller.Actor(), "passkey.revoke_denied", "not_found",
			string(CodeReqInvalid), request.RequestID)
		return ErrCredentialNotFound
	}
	authorization, err := s.authorize(ctx, caller, operationRemove, request.RequestID,
		map[string]string{"operation": "revoke", "credential": stored.ID}, "撤销 Passkey 凭证")
	if err != nil {
		s.recordFailure(ctx, caller.Actor(), "passkey.revoke_denied", reauthReason(err),
			string(CodeOf(err)), request.RequestID)
		return err
	}
	now := s.now()
	critical := s.critical("passkey.revoked", caller.Actor(), stored.ID, request.RequestID,
		[]audit.FieldChange{{Field: "revoked", Before: "false", After: "true"}})
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		active, countErr := s.opts.Store.CountActiveCredentialsTx(txCtx, tx, caller.Actor().ID)
		if countErr != nil {
			return countErr
		}
		hasPassword, passwordErr := s.opts.Store.HasPasswordCredentialTx(txCtx, tx, caller.Actor().ID)
		if passwordErr != nil {
			return passwordErr
		}
		if !hasPassword && active-1 <= 0 {
			return ErrLastLoginMethod
		}
		// 删除第二步凭证时，若这是最后一个强因素且账户被强制 MFA，必须拒绝：
		// 否则用户虽有密码登录方式，却会失去满足强制策略的强认证能力。
		if credentialPurposeAllowsSecondFactor(stored) {
			secondFactors, countErr := s.opts.Store.CountActiveSecondFactorCredentialsTx(
				txCtx, tx, caller.Actor().ID)
			if countErr != nil {
				return countErr
			}
			if secondFactors-1 <= 0 {
				hasOther := false
				if !isNil(s.opts.OtherStrongFactors) {
					hasOther, countErr = s.opts.OtherStrongFactors.HasOtherStrongFactor(txCtx, caller.Actor().ID)
					if countErr != nil {
						return countErr
					}
				}
				forced := false
				if !isNil(s.opts.MFAPolicy) {
					forced, countErr = s.opts.MFAPolicy.MFARequired(txCtx, caller.Actor().ID)
					if countErr != nil {
						return countErr
					}
				}
				if !hasOther && forced {
					return ErrLastStrongFactor
				}
			}
		}
		revoked, revokeErr := s.opts.Store.RevokeCredentialTx(txCtx, tx, caller.Actor().ID,
			stored.ID, "user_revoked", now)
		if revokeErr != nil {
			return revokeErr
		}
		if !revoked {
			return ErrCredentialNotFound
		}
		// 凭证（可能是主登录 Passkey 或第二步安全密钥）变更会改变认证面：在同一
		// 审计事务内递增 security_version，让删除前建立的所有会话（含记住我）在
		// 下次校验时立即失效，不能继续凭旧强认证访问管理接口。
		return s.opts.Store.IncrementUserSecurityVersionTx(txCtx, tx, caller.Actor().ID, now)
	}); err != nil {
		mapped := mapCriticalError(err)
		switch {
		case errors.Is(mapped, ErrLastLoginMethod):
			s.recordFailure(ctx, caller.Actor(), "passkey.revoke_denied", "last_login_method",
				string(CodeConflict), request.RequestID)
		case errors.Is(mapped, ErrLastStrongFactor):
			s.recordFailure(ctx, caller.Actor(), "passkey.revoke_denied", "last_strong_factor",
				string(CodeConflict), request.RequestID)
		}
		return mapped
	}
	// 审计事务提交后再做即时会话撤销（可靠事件）：失败只记录日志，security_version
	// 已递增，会话在下次校验时仍会失效。
	if !isNil(s.opts.SessionInvalidator) {
		if _, err := s.opts.SessionInvalidator.RevokeAllForUser(ctx, caller.Actor().ID,
			"passkey_removed"); err != nil {
			s.opts.Logger.Warn("Passkey 删除后撤销会话失败", "error", err)
		}
	}
	s.notifyOutcome(ctx, authorization, reauth.OutcomeSuccess, request.RequestID)
	return nil
}

var _ SessionInvalidator = (*session.Service)(nil)

// ===== 内部辅助 =====

// credentialPurposeAllowsLogin 报告凭证用途是否允许主登录；未知用途 fail-closed。
func credentialPurposeAllowsLogin(credential Credential) bool {
	purpose, ok := purposeFromUsage(credential.Usage)
	return ok && purpose.AllowsLogin()
}

// credentialPurposeAllowsSecondFactor 报告凭证用途是否允许第二步验证。
func credentialPurposeAllowsSecondFactor(credential Credential) bool {
	purpose, ok := purposeFromUsage(credential.Usage)
	return ok && purpose.AllowsSecondFactor()
}

// filterCredentials 按谓词过滤凭证副本。
func filterCredentials(credentials []Credential, keep func(Credential) bool) []Credential {
	result := make([]Credential, 0, len(credentials))
	for _, credential := range credentials {
		if keep(credential) {
			result = append(result, credential)
		}
	}
	return result
}

func (s *Service) requireUserCaller(caller Caller) error {
	if err := caller.Actor().Validate(); err != nil || !caller.IsUser() {
		return ErrAccessDenied
	}
	return nil
}

// ensureHandle 返回用户句柄；首次注册时用安全随机值创建，之后保持不变。
func (s *Service) ensureHandle(ctx context.Context, state UserState) ([]byte, error) {
	if len(state.Handle) > 0 {
		return state.Handle, nil
	}
	handle := make([]byte, HandleBytes)
	if _, err := io.ReadFull(s.opts.Random, handle); err != nil {
		return nil, fmt.Errorf("%w: 安全随机源不可用", ErrStoreUnavailable)
	}
	result, err := s.opts.Store.EnsureUserHandle(ctx, state.UserID, handle, s.now())
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	if len(result) == 0 {
		return nil, ErrStoreUnavailable
	}
	return result, nil
}

// authorize 复用步骤 39 的敏感操作收敛入口；未接线时 fail-closed。
func (s *Service) authorize(ctx context.Context, caller Caller, operationID, requestID string,
	params map[string]string, description string) (reauth.Result, error) {
	if isNil(s.opts.Reauth) {
		return reauth.Result{}, ErrReauthRequired
	}
	reauthCaller, err := reauth.CallerFromActor(caller.Actor())
	if err != nil {
		return reauth.Result{}, ErrAccessDenied
	}
	result, err := s.opts.Reauth.Authorize(ctx, reauthCaller, reauth.Request{
		ScopeID: "system", OperationID: operationID, TargetType: "user",
		TargetID: caller.Actor().ID, Params: params, Description: description,
		RequestID: requestID,
	})
	if err != nil {
		switch {
		case errors.Is(err, reauth.ErrAccessDenied):
			return reauth.Result{}, ErrAccessDenied
		case errors.Is(err, reauth.ErrMFARequired):
			return reauth.Result{}, ErrMFARequired
		default:
			return reauth.Result{}, ErrReauthRequired
		}
	}
	return result, nil
}

// notifyOutcome 发送成功安全告知；失败不回滚已完成的凭证变更、也不当作认证。
func (s *Service) notifyOutcome(ctx context.Context, result reauth.Result, outcome reauth.Outcome, requestID string) {
	if isNil(s.opts.Reauth) || result.OperationID == "" {
		return
	}
	if err := s.opts.Reauth.NotifyOutcome(ctx, result, outcome); err != nil {
		s.opts.Logger.Warn("Passkey 安全告知发送失败", "operation", result.OperationID,
			"request_id", validRequestID(requestID))
	}
}

// cleanupCeremonies 惰性清理过期挑战；失败只记录日志（不影响开始新挑战）。
func (s *Service) cleanupCeremonies(ctx context.Context) {
	if _, err := s.opts.Store.CleanupExpiredCeremonies(ctx, s.now(), 100); err != nil {
		s.opts.Logger.Warn("Passkey 过期挑战清理失败", "error", err)
	}
}

func (s *Service) now() time.Time { return s.opts.Now().UTC().Truncate(time.Millisecond) }

// webauthnUser 是本包账户快照到库 User 接口的适配。
type webauthnUser struct {
	id          []byte
	username    string
	displayName string
	credentials []webauthn.Credential
}

func newWebAuthnUser(state UserState, handle []byte, credentials []Credential) *webauthnUser {
	converted := make([]webauthn.Credential, 0, len(credentials))
	for _, credential := range credentials {
		converted = append(converted, toWebAuthnCredential(credential))
	}
	return &webauthnUser{id: append([]byte(nil), handle...), username: state.Username,
		displayName: state.Username, credentials: converted}
}

func (u *webauthnUser) WebAuthnID() []byte                         { return u.id }
func (u *webauthnUser) WebAuthnName() string                       { return u.username }
func (u *webauthnUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// toWebAuthnCredential 把存储记录还原为库的凭证结构。Attestation 原始数据未持久化
// （未接入 MDS/attestation 证书链校验），但签名验证只需要公钥与计数器。
func toWebAuthnCredential(credential Credential) webauthn.Credential {
	transports := make([]protocol.AuthenticatorTransport, 0, len(credential.Transports))
	for _, transport := range credential.Transports {
		transports = append(transports, protocol.AuthenticatorTransport(transport))
	}
	var flags protocol.AuthenticatorFlags
	if credential.UserPresent {
		flags |= protocol.FlagUserPresent
	}
	if credential.UserVerified {
		flags |= protocol.FlagUserVerified
	}
	if credential.BackupEligible {
		flags |= protocol.FlagBackupEligible
	}
	if credential.BackedUp {
		flags |= protocol.FlagBackupState
	}
	return webauthn.Credential{
		ID:        append([]byte(nil), credential.CredentialID...),
		PublicKey: append([]byte(nil), credential.PublicKey...),
		Transport: transports,
		Flags:     webauthn.NewCredentialFlags(flags),
		Authenticator: webauthn.Authenticator{
			AAGUID:     append([]byte(nil), credential.AAGUID...),
			SignCount:  credential.SignCount,
			Attachment: protocol.AuthenticatorAttachment(credential.Attachment),
		},
	}
}

// credentialDescriptors 生成注册排除列表，避免同一认证器重复注册同一账户凭证。
func credentialDescriptors(credentials []Credential) []protocol.CredentialDescriptor {
	descriptors := make([]protocol.CredentialDescriptor, 0, len(credentials))
	for _, credential := range credentials {
		transports := make([]protocol.AuthenticatorTransport, 0, len(credential.Transports))
		for _, transport := range credential.Transports {
			transports = append(transports, protocol.AuthenticatorTransport(transport))
		}
		descriptors = append(descriptors, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: append([]byte(nil), credential.CredentialID...),
			Transport:    transports,
		})
	}
	return descriptors
}

func transportStrings(transports []protocol.AuthenticatorTransport) []string {
	result := make([]string, 0, len(transports))
	for _, transport := range transports {
		value := strings.TrimSpace(string(transport))
		if value == "" || len(value) > 32 {
			continue
		}
		result = append(result, value)
	}
	return result
}

func metadata(credential Credential) CredentialMetadata {
	return CredentialMetadata{
		ID: credential.ID, Name: credential.Name,
		BackupEligible: credential.BackupEligible, BackedUp: credential.BackedUp,
		Transports: append([]string(nil), credential.Transports...),
		CreatedAt:  credential.CreatedAt, LastUsedAt: credential.LastUsedAt,
	}
}

// normalizeCredentialName 校验并规范化凭证显示名：去除首尾空白、禁止控制字符、
// 1～64 个字符；空名使用默认“Passkey”。
func normalizeCredentialName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "Passkey", nil
	}
	if !utf8.ValidString(name) {
		return "", fmt.Errorf("%w: 凭证名不是合法 UTF-8", ErrInvalidRequest)
	}
	count := 0
	for _, character := range name {
		if unicode.IsControl(character) {
			return "", fmt.Errorf("%w: 凭证名不能包含控制字符", ErrInvalidRequest)
		}
		count++
	}
	if count > MaxCredentialNameRunes {
		return "", fmt.Errorf("%w: 凭证名最多 %d 个字符", ErrInvalidRequest, MaxCredentialNameRunes)
	}
	return name, nil
}

func decodeSessionData(raw []byte) (*webauthn.SessionData, error) {
	if len(raw) == 0 {
		return nil, ErrCeremonyInvalid
	}
	var sessionData webauthn.SessionData
	if _, err := sessionData.UnmarshalMsg(raw); err != nil {
		return nil, ErrCeremonyInvalid
	}
	return &sessionData, nil
}

// newID 生成带稳定前缀的随机标识；安全随机源不可用时 fail-closed。
func (s *Service) newID(prefix string) (string, error) {
	buffer := make([]byte, 16)
	if _, err := io.ReadFull(s.opts.Random, buffer); err != nil {
		return "", fmt.Errorf("%w: 安全随机源不可用", ErrInternal)
	}
	return prefix + hex.EncodeToString(buffer), nil
}

func validRecordID(value string) bool {
	for _, prefix := range []string{"pkc_", "cred_"} {
		if !strings.HasPrefix(value, prefix) {
			continue
		}
		remainder := value[len(prefix):]
		if len(remainder) != 32 {
			return false
		}
		_, err := hex.DecodeString(remainder)
		return err == nil
	}
	return false
}

func sanitizeText(value string, limit int) string {
	value = strings.TrimSpace(value)
	var builder strings.Builder
	for _, character := range value {
		if unicode.IsControl(character) {
			continue
		}
		if builder.Len()+utf8.RuneLen(character) > limit {
			break
		}
		builder.WriteRune(character)
	}
	return builder.String()
}

func validRequestID(value string) string {
	if account.ValidateRequestID(value) != nil {
		return ""
	}
	return value
}

func (s *Service) critical(action string, actor audit.Actor, credentialID, requestID string,
	changes []audit.FieldChange) audit.CriticalRequest {
	return audit.CriticalRequest{
		Event: audit.Event{
			Actor: actor, Action: action,
			Target:    audit.Target{Type: "passkey_credential", ID: safeValue(credentialID)},
			RequestID: validRequestID(requestID), Changes: changes,
		},
		FailureReasonCode:   action + "_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
}

func (s *Service) recordFailure(ctx context.Context, actor audit.Actor, action, reason, code, requestID string) {
	if err := actor.Validate(); err != nil {
		return
	}
	event := audit.Event{Actor: actor, Action: action,
		Target:  audit.Target{Type: "passkey_credential"},
		Outcome: audit.OutcomeFailure, ErrorCode: code, ReasonCode: safeReason(reason),
		RequestID: validRequestID(requestID)}
	if err := s.opts.Audit.RecordFailure(ctx, event); err != nil {
		s.opts.Logger.Warn("Passkey 失败审计写入失败", "error", err)
	}
}

func (s *Service) recordAnonymousFailure(ctx context.Context, action, reason, requestID string) {
	s.recordFailure(ctx, audit.Actor{Type: audit.ActorAnonymous}, action, reason,
		string(CodeAuthFailed), requestID)
}

func mapCriticalError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, audit.ErrAuditUnavailable):
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	case errors.Is(err, audit.ErrInvalidEvent):
		return fmt.Errorf("%w: 审计事件无效", ErrOptionsInvalid)
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrCeremonyInvalid),
		errors.Is(err, ErrCeremonyExpired), errors.Is(err, ErrCredentialNotFound),
		errors.Is(err, ErrCredentialConflict), errors.Is(err, ErrAccessDenied),
		errors.Is(err, ErrLastLoginMethod), errors.Is(err, ErrLastStrongFactor),
		errors.Is(err, ErrCredentialLimit),
		errors.Is(err, ErrMFARequired), errors.Is(err, ErrReauthRequired),
		errors.Is(err, ErrStoreUnavailable):
		return err
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
}

func reauthReason(err error) string {
	switch {
	case errors.Is(err, ErrAccessDenied):
		return "reauth_denied"
	case errors.Is(err, ErrMFARequired):
		return "strong_auth_required"
	default:
		return "reauth_required"
	}
}

func safeValue(value string) string {
	if len(value) == 0 || len(value) > 128 {
		return ""
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' ||
			character == '-' {
			continue
		}
		return ""
	}
	return value
}

func safeReason(value string) string {
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

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
