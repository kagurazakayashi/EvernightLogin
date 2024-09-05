package app

// 步骤 255：直接管理操作的公开“目标绑定一次性两步验证证明”门面。
//
// 用途：步骤 256（直接修改他人用户名）与步骤 257（直接重置他人口令）在执行各自
// 领域写入前，先由本门面获得一次性证明，再在同一个审计事务内调用
// reauth.ConsumeProofTx 消费证明并写入业务变更（步骤 256/257 实现）。
//
// 安全语义（由 reauth 层保证，本门面只做可信身份解析与公开契约投影）：
//   - 证明绑定操作者（当前真实管理会话的用户）、会话 ID、作用域、操作、目标用户
//     ID、服务端参数摘要与“本次新值意图”；
//   - 两步验证验证的是**操作者本人**的密码 + TOTP 或 Passkey/WebAuthn 断言（无密码
//     Passkey 账户不必添加密码）；本机受信操作者（LocalAdmin）没有用户因素，不能
//     用于直接管理证明；
//   - 换目标/换新用户名/换新口令/权限被撤销/会话失效/证明过期或重放一律拒绝；
//   - 新值意图只在服务端密封保存（不落明文、不做无密钥摘要），证明单次消费并与业务
//     写入同事务提交，提交失败可重试、成功后重放不二次执行；
//   - 不签发会话、不解除 MFA、不读取目标旧秘密、不返回密码或哈希。
//
// 本门面返回的 ProofToken 是短时一次性凭据：只在本次逻辑操作中使用，不写日志、不
// 放入页面 HTML；HTTP/CLI/页面层后续步骤复用同一门面，不重复要求两步验证。

import (
	"context"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
)

// OperationProofOperation 是直接管理操作的公开稳定标识（与内部策略操作 ID 一致）。
type OperationProofOperation string

const (
	// OperationProofUsernameChange 是直接修改他人用户名操作。
	OperationProofUsernameChange OperationProofOperation = "user.username.change.other"
	// OperationProofPasswordReset 是直接重置他人密码操作。
	OperationProofPasswordReset OperationProofOperation = "user.password.reset.other"
)

// policyOperationID 把公开操作标识映射为内部策略操作 ID 与意图类别；未知值拒绝。
func (o OperationProofOperation) policyOperationID() (string, reauth.IntentKind, bool) {
	switch o {
	case OperationProofUsernameChange:
		return policy.OperationDirectUsernameChange, reauth.IntentUsername, true
	case OperationProofPasswordReset:
		return policy.OperationDirectPasswordReset, reauth.IntentPassword, true
	default:
		return "", "", false
	}
}

// publicOperationFromPolicyID 把内部操作 ID 投影回公开标识（用于结果回显）。
func publicOperationFromPolicyID(operationID string) OperationProofOperation {
	switch operationID {
	case policy.OperationDirectUsernameChange:
		return OperationProofUsernameChange
	case policy.OperationDirectPasswordReset:
		return OperationProofPasswordReset
	default:
		return OperationProofOperation(operationID)
	}
}

// OperationProofBeginRequest 是发起一次直接管理操作证明的请求。Caller 必须是当前
// 真实管理会话（AdminSession）；Operation 决定并校验新值字段：
//   - OperationProofUsernameChange 使用 NewUsername（服务端按既有用户名规范化后绑定）；
//   - OperationProofPasswordReset 使用 NewPassword（服务端只保存密封密文）。
type OperationProofBeginRequest struct {
	Caller       AdminCaller
	TargetUserID string
	Operation    OperationProofOperation
	NewUsername  string
	NewPassword  string
	RequestID    string
}

// OperationProofChallenge 是已创建的证明挑战。RequiredStrength 恒为 strong（直接
// 管理操作的安全下限）。WebAuthnAvailable 表示当前部署是否启用了 Passkey/安全密钥
// 第二步路径（TOTP 路径由 reauth 按操作者实际绑定情况判定）。
type OperationProofChallenge struct {
	ChallengeID       string
	Operation         OperationProofOperation
	TargetUserID      string
	RequiredStrength  string
	ExpiresAt         time.Time
	MaxAttempts       int
	WebAuthnAvailable bool
}

// OperationProofConfirmRequest 用操作者密码 + TOTP 动态码完成两步验证。
type OperationProofConfirmRequest struct {
	Caller      AdminCaller
	ChallengeID string
	Password    string
	TOTPCode    string
	RequestID   string
}

// OperationProofGrant 是一次性操作证明（明文令牌只在本次返回一次）。调用方只应把
// ProofToken 交给紧随其后的同一逻辑操作，不持久化、不写日志、不展示给其他主体。
type OperationProofGrant struct {
	ProofToken      string
	ExpiresAt       time.Time
	Operation       OperationProofOperation
	TargetUserID    string
	GrantedStrength string
}

// OperationProofWebAuthnBeginRequest 为证明挑战开始 Passkey/安全密钥第二步断言。
type OperationProofWebAuthnBeginRequest struct {
	Caller      AdminCaller
	ChallengeID string
	RequestID   string
}

// OperationProofWebAuthnStart 是浏览器 WebAuthn get() 所需的公开参数；不含秘密。
type OperationProofWebAuthnStart struct {
	ChallengeID string
	CeremonyID  string
	PublicKey   []byte
	RPID        string
	ExpiresAt   time.Time
}

// OperationProofWebAuthnConfirmRequest 用 WebAuthn 断言完成第二步验证。
type OperationProofWebAuthnConfirmRequest struct {
	Caller      AdminCaller
	ChallengeID string
	CeremonyID  string
	Response    []byte
	RequestID   string
}

// OperationProofCancelRequest 取消尚未完成的证明挑战（不产生任何可执行能力）。
type OperationProofCancelRequest struct {
	Caller      AdminCaller
	ChallengeID string
	RequestID   string
}

// OperationProofService 是目标绑定一次性两步验证证明的公开 Go 门面。
type OperationProofService interface {
	Begin(ctx context.Context, request OperationProofBeginRequest) (OperationProofChallenge, error)
	Confirm(ctx context.Context, request OperationProofConfirmRequest) (OperationProofGrant, error)
	BeginWebAuthn(ctx context.Context, request OperationProofWebAuthnBeginRequest) (OperationProofWebAuthnStart, error)
	ConfirmWebAuthn(ctx context.Context, request OperationProofWebAuthnConfirmRequest) (OperationProofGrant, error)
	Cancel(ctx context.Context, request OperationProofCancelRequest) error
}

// OperationProof 返回目标绑定操作证明门面；Runtime 未装配敏感闸门时调用会返回
// 明确配置错误（fail-closed），不会静默跳过两步验证。
func (r *Runtime) OperationProof() OperationProofService {
	return &operationProofFacade{r: r}
}

type operationProofFacade struct{ r *Runtime }

// proofIdentity 解析可信管理身份与会话 ID：只接受真实用户管理会话（AdminSession）。
// 本机受信操作者（LocalAdmin）没有用户两步因素，不能用于直接管理证明。
func (f *operationProofFacade) proofIdentity(ctx context.Context, caller AdminCaller,
	requestID string) (userID, sessionID string, err error) {
	r := f.r
	services := r.coreServices()
	if services == nil || services.Sessions == nil {
		return "", "", configError("服务未装配", requestID)
	}
	if caller.local {
		return "", "", mapDomainError("直接管理操作证明必须由真实用户管理会话发起",
			"ACCESS_DENIED", requestID)
	}
	identity, err := r.resolveAdmin(ctx, caller, requestID)
	if err != nil {
		return "", "", err
	}
	if identity.userID == "" || len(identity.sessionSecret) == 0 {
		return "", "", mapDomainError("管理会话无效", "ACCESS_DENIED", requestID)
	}
	record, err := services.Sessions.Validate(ctx, string(identity.sessionSecret))
	if err != nil || !record.IsNormal() || record.UserID != identity.userID {
		return "", "", mapDomainError("管理会话无效或不是完整会话", "ACCESS_DENIED", requestID)
	}
	return record.UserID, record.ID, nil
}

// proofReauth 返回真实再次认证服务；未装配时配置错误 fail-closed。
func (f *operationProofFacade) proofReauth(requestID string) (*reauth.Service, error) {
	gate := f.r.securityGate()
	if gate == nil || gate.Reauth == nil {
		return nil, configError("敏感操作闸门未装配", requestID)
	}
	return gate.Reauth, nil
}

// buildProofIntent 校验并构造本次新值意图；用户名复用既有规范化（只接受能通过
// NormalizeUsername 的输入），口令仅在服务端密封保存。
//
// 用户名意图绑定的契约（步骤 256 复用，必须遵守）：证明绑定的是**操作者本次提交的
// display 用户名输入串**（已通过 NormalizeUsername 校验），不是其规范化身份键。执行
// 直接改名的步骤 256 必须用同一 display 串在提交处重新调用 NormalizeUsername，
// 写入该 display 串（唯一性/保留名仍用规范化键判定），并在 ConsumePreparedProofTx
// 的 Intent 中提交同一 display 串；不得替换为“等价规范化形式”，否则大小写/全角等
// display 差异不会被证明覆盖。口令意图绑定的是原样口令字节（不 trim、不规范化）。
func buildProofIntent(request OperationProofBeginRequest, kind reauth.IntentKind) (reauth.Intent, error) {
	switch kind {
	case reauth.IntentUsername:
		if strings.TrimSpace(request.NewPassword) != "" {
			return reauth.Intent{}, errProofInvalidRequest
		}
		if strings.TrimSpace(request.NewUsername) == "" {
			return reauth.Intent{}, errProofInvalidRequest
		}
		display, normalized, err := account.NormalizeUsername(request.NewUsername)
		if err != nil || normalized == "" || display == "" {
			return reauth.Intent{}, errProofInvalidRequest
		}
		return reauth.Intent{Kind: reauth.IntentUsername, Username: display}, nil
	case reauth.IntentPassword:
		if strings.TrimSpace(request.NewUsername) != "" {
			return reauth.Intent{}, errProofInvalidRequest
		}
		if request.NewPassword == "" || len(request.NewPassword) > 1024 {
			return reauth.Intent{}, errProofInvalidRequest
		}
		return reauth.Intent{Kind: reauth.IntentPassword, Password: request.NewPassword}, nil
	default:
		return reauth.Intent{}, errProofInvalidRequest
	}
}

// errProofInvalidRequest 是门面内部请求校验哨兵（对外映射 REQ_INVALID）。
var errProofInvalidRequest = &proofRequestError{}

type proofRequestError struct{}

func (*proofRequestError) Error() string { return "直接管理操作证明请求无效" }

// Begin 创建目标绑定证明挑战：先复核操作者真实管理会话与目标合法性，再以 intent
// 密封并创建挑战；权限复核在挑战创建事务内完成（权限不足不会要求用户先做两步验证）。
func (f *operationProofFacade) Begin(ctx context.Context,
	request OperationProofBeginRequest) (OperationProofChallenge, error) {
	r := f.r
	requestID, err := resolveRequestID(ctx, request.RequestID)
	if err != nil {
		return OperationProofChallenge{}, err
	}
	userID, sessionID, err := f.proofIdentity(ctx, request.Caller, requestID)
	if err != nil {
		return OperationProofChallenge{}, err
	}
	if !account.ValidUserID(request.TargetUserID) {
		return OperationProofChallenge{}, mapDomainError("目标用户标识无效",
			"REQ_INVALID", requestID)
	}
	if request.TargetUserID == userID {
		return OperationProofChallenge{}, mapDomainError("本人操作请使用本人资料/密码流程，不能使用直接管理证明",
			"REQ_INVALID", requestID)
	}
	policyOperationID, kind, ok := request.Operation.policyOperationID()
	if !ok {
		return OperationProofChallenge{}, mapDomainError("直接管理操作类别无效",
			"REQ_INVALID", requestID)
	}
	intent, err := buildProofIntent(request, kind)
	if err != nil {
		return OperationProofChallenge{}, mapDomainError("本次新值无效",
			"REQ_INVALID", requestID)
	}
	reauthService, err := f.proofReauth(requestID)
	if err != nil {
		return OperationProofChallenge{}, err
	}
	caller, callerErr := reauth.UserCaller(userID)
	if callerErr != nil {
		return OperationProofChallenge{}, configError("管理会话主体无效", requestID)
	}
	challenge, err := reauthService.BeginChallenge(ctx, caller, reauth.ChallengeRequest{
		ScopeID: "system", OperationID: policyOperationID, TargetType: "user",
		TargetID: request.TargetUserID, Description: "直接管理操作两步验证",
		RequestID: requestID, MinimumStrength: policy.StrengthStrong,
		SessionID: sessionID, Intent: &intent,
	})
	if err != nil {
		return OperationProofChallenge{}, mapDomainError("直接管理操作证明发起失败",
			string(reauth.CodeOf(err)), requestID)
	}
	webAuthnAvailable := false
	if security := r.securityDomains(); security != nil && security.Passkey != nil {
		webAuthnAvailable = true
	}
	return OperationProofChallenge{
		ChallengeID: challenge.ID, Operation: request.Operation,
		TargetUserID: request.TargetUserID, RequiredStrength: string(challenge.RequiredStrength),
		ExpiresAt: challenge.ExpiresAt, MaxAttempts: challenge.MaxAttempts,
		WebAuthnAvailable: webAuthnAvailable,
	}, nil
}

// Confirm 用操作者密码 + TOTP 完成两步验证并返回一次性证明。
func (f *operationProofFacade) Confirm(ctx context.Context,
	request OperationProofConfirmRequest) (OperationProofGrant, error) {
	requestID, err := resolveRequestID(ctx, request.RequestID)
	if err != nil {
		return OperationProofGrant{}, err
	}
	userID, sessionID, err := f.proofIdentity(ctx, request.Caller, requestID)
	if err != nil {
		return OperationProofGrant{}, err
	}
	reauthService, err := f.proofReauth(requestID)
	if err != nil {
		return OperationProofGrant{}, err
	}
	caller, callerErr := reauth.UserCaller(userID)
	if callerErr != nil {
		return OperationProofGrant{}, configError("管理会话主体无效", requestID)
	}
	grant, err := reauthService.VerifyChallenge(ctx, caller, reauth.VerifyChallengeRequest{
		ChallengeID: request.ChallengeID, Password: request.Password,
		TOTPCode: request.TOTPCode, SessionID: sessionID, RequestID: requestID,
	})
	if err != nil {
		return OperationProofGrant{}, mapDomainError("直接管理操作两步验证未通过",
			string(reauth.CodeOf(err)), requestID)
	}
	return OperationProofGrant{ProofToken: grant.Token, ExpiresAt: grant.ExpiresAt,
		Operation:       publicOperationFromPolicyID(grant.OperationID),
		TargetUserID:    grant.TargetID,
		GrantedStrength: string(grant.GrantedStrength)}, nil
}

// BeginWebAuthn 为证明挑战开始 Passkey/安全密钥第二步断言（无密码 Passkey 账户使用）。
func (f *operationProofFacade) BeginWebAuthn(ctx context.Context,
	request OperationProofWebAuthnBeginRequest) (OperationProofWebAuthnStart, error) {
	requestID, err := resolveRequestID(ctx, request.RequestID)
	if err != nil {
		return OperationProofWebAuthnStart{}, err
	}
	userID, sessionID, err := f.proofIdentity(ctx, request.Caller, requestID)
	if err != nil {
		return OperationProofWebAuthnStart{}, err
	}
	reauthService, err := f.proofReauth(requestID)
	if err != nil {
		return OperationProofWebAuthnStart{}, err
	}
	caller, callerErr := reauth.UserCaller(userID)
	if callerErr != nil {
		return OperationProofWebAuthnStart{}, configError("管理会话主体无效", requestID)
	}
	start, err := reauthService.BeginWebAuthnChallenge(ctx, caller,
		reauth.BeginWebAuthnChallengeRequest{ChallengeID: request.ChallengeID,
			SessionID: sessionID, RequestID: requestID})
	if err != nil {
		return OperationProofWebAuthnStart{}, mapDomainError("WebAuthn 第二步无法开始",
			string(reauth.CodeOf(err)), requestID)
	}
	return OperationProofWebAuthnStart{ChallengeID: request.ChallengeID,
		CeremonyID: start.CeremonyID, PublicKey: start.PublicKey, RPID: start.RPID,
		ExpiresAt: start.ExpiresAt}, nil
}

// ConfirmWebAuthn 校验 WebAuthn 第二步断言并返回一次性证明。
func (f *operationProofFacade) ConfirmWebAuthn(ctx context.Context,
	request OperationProofWebAuthnConfirmRequest) (OperationProofGrant, error) {
	requestID, err := resolveRequestID(ctx, request.RequestID)
	if err != nil {
		return OperationProofGrant{}, err
	}
	userID, sessionID, err := f.proofIdentity(ctx, request.Caller, requestID)
	if err != nil {
		return OperationProofGrant{}, err
	}
	reauthService, err := f.proofReauth(requestID)
	if err != nil {
		return OperationProofGrant{}, err
	}
	caller, callerErr := reauth.UserCaller(userID)
	if callerErr != nil {
		return OperationProofGrant{}, configError("管理会话主体无效", requestID)
	}
	grant, err := reauthService.FinishWebAuthnChallenge(ctx, caller,
		reauth.FinishWebAuthnChallengeRequest{ChallengeID: request.ChallengeID,
			SessionID: sessionID, CeremonyID: request.CeremonyID,
			Response: request.Response, RequestID: requestID})
	if err != nil {
		return OperationProofGrant{}, mapDomainError("WebAuthn 第二步验证未通过",
			string(reauth.CodeOf(err)), requestID)
	}
	return OperationProofGrant{ProofToken: grant.Token, ExpiresAt: grant.ExpiresAt,
		Operation:       publicOperationFromPolicyID(grant.OperationID),
		TargetUserID:    grant.TargetID,
		GrantedStrength: string(grant.GrantedStrength)}, nil
}

// Cancel 取消尚未完成的证明挑战（只能由同一操作者会话发起；不产生可执行能力）。
func (f *operationProofFacade) Cancel(ctx context.Context,
	request OperationProofCancelRequest) error {
	requestID, err := resolveRequestID(ctx, request.RequestID)
	if err != nil {
		return err
	}
	userID, _, err := f.proofIdentity(ctx, request.Caller, requestID)
	if err != nil {
		return err
	}
	reauthService, err := f.proofReauth(requestID)
	if err != nil {
		return err
	}
	caller, callerErr := reauth.UserCaller(userID)
	if callerErr != nil {
		return configError("管理会话主体无效", requestID)
	}
	if err := reauthService.CancelChallenge(ctx, caller, request.ChallengeID); err != nil {
		return mapDomainError("取消直接管理操作证明失败",
			string(reauth.CodeOf(err)), requestID)
	}
	return nil
}

var _ OperationProofService = (*operationProofFacade)(nil)
