package reauth

// 步骤 255：目标绑定的一次性两步验证操作证明（direct management proof）。
//
// 背景：0019 的再次认证批准面向“操作者即目标”的敏感操作，批准只绑定
// 用户/作用域/操作/目标/参数摘要，且消费发生在独立审计事务中。直接修改他人用户名
// 或直接重置他人密码需要更强的闭环：
//   - 操作者（管理员）与目标（被管理用户）不是同一人，验证的必须是**操作者本人**
//     的两步因素；
//   - 证明绑定操作者、会话 ID、作用域、操作、目标用户、服务端参数摘要与“本次新值
//     意图”（新用户名/新口令）；换目标、换会话、换新值一律拒绝；
//   - 新值意图只在服务端以既有 internal/secrets AES-256-GCM 密封保存（不落明文、
//     不做无密钥摘要），消费时清空密文，过期密文由有界清理擦除；
//   - 证明单次消费且与业务写入处于**同一个审计事务**：提交失败整体回滚（证明仍
//     可用、可重试），提交成功后重放返回“已使用”，不会二次执行；
//   - 支持现有合格的两步验证路径：密码 + TOTP（复用 0019 挑战/批准）或
//     Passkey/WebAuthn 第二步断言（经注入的 StrongWebAuthnVerifier 适配真实
//     passkey 服务，密码less 账户不被强制要求密码）；
//   - 消费前重新核对操作者当前权限与会话仍然有效（由注入的 PermissionChecker /
//     SessionVerifier 完成；未接线时对直接管理操作 fail-closed）。
//
// 两阶段消费与窗口收敛（步骤 255 安全审计 HIGH 修复）：
//  1) PrepareProof（事务外）：完成会话有效性、操作者权限、策略、绑定与意图一致性
//     的完整复核，返回带 PreparedAt 的 PreparedProof（无副作用）；
//  2) ConsumePreparedProofTx（调用方审计事务内）：
//     - 强制“准备→提交”最大间隔 Options.ProofMaxAge（默认 5 秒，允许 500ms～5s，
//       **不允许**放宽到分钟级），超时 ErrProofExpired，必须重新 Prepare；
//     - 用**同一 tx 连接**只读重读 sessions（归属/种类/撤销/空闲与绝对到期）与
//       users（status/有效期/security_version），安全版本必须与会话签发快照一致；
//     - 用同一 tx 连接重读操作者当前权限（PermissionChecker.CheckOperationPermissionTx，
//       只读 SQL，不另开连接/事务，避免 SQLite 写事务互锁）；
//     - 重新读取同一批准行，核对绑定一致、未消费/未过期、密文存在后条件消费并写入
//       证明消费审计；业务写入与证明消费同事务提交/回滚。
// 因此“准备后被撤销权限/会话失效/账户禁用或到期/安全版本变化”与“准备到提交超时”
// 都会在最终事务内确定性拒绝且不烧证明。残余边界：准备阶段与事务内终检之间仍有一
// 个不超过 ProofMaxAge（且通常为毫秒级）的间隔，终检覆盖该间隔内已提交的状态变化；
// 消费方（256/257）仍必须在同一审计事务内调用本方法并完成业务写入，不得把证明当
// 作权限/会话校验的替代，也不得在事务外先消费。
//
// 本文件不实现用户名修改/密码重置本身（步骤 256/257 在同一审计事务内调用
// ConsumePreparedProofTx），也不签发会话、不解除 MFA、不读取 target 的旧秘密。

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

// 步骤 255 领域错误哨兵；错误文本不包含密码、意图值、令牌或本机路径。
var (
	// ErrIntentInvalid 表示本次新值意图缺失、过长或形状非法。
	ErrIntentInvalid = errors.New("操作意图无效")
	// ErrSessionMismatch 表示证明绑定的会话与本次调用/当前会话不一致或已失效。
	ErrSessionMismatch = errors.New("操作证明绑定的会话无效")
	// ErrProofBindingMismatch 表示会话/目标/操作/参数/新值意图与签发时不一致。
	ErrProofBindingMismatch = errors.New("操作证明绑定不一致")
	// ErrProofUnavailable 表示证明所需依赖（意图加密、会话校验、权限复核）未装配，
	// 直接管理操作 fail-closed。
	ErrProofUnavailable = errors.New("操作证明所需依赖未装配")
	// ErrProofExpired 表示证明准备到最终提交的间隔超过允许上限（默认 5 秒），
	// 必须重新准备（重新复核会话/账户/权限）后才能消费；不是可重用的并发冲突。
	ErrProofExpired = errors.New("操作证明准备已过期")
)

// IntentKind 是目标绑定操作意图的类别。
type IntentKind string

const (
	// IntentUsername 表示本次操作将设置的新用户名。
	IntentUsername IntentKind = "username"
	// IntentPassword 表示本次操作将设置的新口令。
	IntentPassword IntentKind = "password"
)

// Valid 报告意图类别是否已定义。
func (k IntentKind) Valid() bool {
	return k == IntentUsername || k == IntentPassword
}

// 直接管理操作的稳定权限键。操作 ID 来自 internal/policy（步骤 254 的敏感操作
// 目录）；权限键来自内部预设目录。两者不是同一命名空间的拼写错误：授权判定用
// 权限键，再次验证/策略用操作 ID（见 internal/policy/service.go 注释）。
const (
	directUsernamePermissionKey = "users.username.change.other"
	directPasswordPermissionKey = "users.password.reset.other"
	// operationIntentPurpose 是密封意图的加密绑定用途；不同用途派生不同子密钥。
	operationIntentPurpose = "reauth.operation_intent"
	// maxIntentUsernameBytes/maxIntentPasswordBytes 限制意图长度（与用户名/口令上限
	// 对齐，避免把本服务当成通用加密接口）。
	maxIntentUsernameBytes = 256
	maxIntentPasswordBytes = 1024
)

// Intent 是本次操作将被应用的新值意图。它只存在于服务端内存与被密封的数据库列中，
// 不出现在批准令牌、审计、日志或错误信息里。
type Intent struct {
	Kind     IntentKind
	Username string
	Password string
}

// Value 返回意图对应的值（用户名或口令）；Kind 非法时返回空串。
func (i Intent) Value() string {
	switch i.Kind {
	case IntentUsername:
		return i.Username
	case IntentPassword:
		return i.Password
	default:
		return ""
	}
}

// Validate 校验意图形状：类别必须已知，且只有对应字段非空、长度受限、不含控制字符。
func (i Intent) Validate() error {
	switch i.Kind {
	case IntentUsername:
		if i.Password != "" || len(i.Username) == 0 || len(i.Username) > maxIntentUsernameBytes {
			return ErrIntentInvalid
		}
		return validateIntentText(i.Username)
	case IntentPassword:
		if i.Username != "" || len(i.Password) == 0 || len(i.Password) > maxIntentPasswordBytes {
			return ErrIntentInvalid
		}
		return validateIntentText(i.Password)
	default:
		return ErrIntentInvalid
	}
}

// validateIntentText 拒绝控制字符（意图值会进入密封载荷与内存比较，不应包含 NUL 等）。
func validateIntentText(value string) error {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character == 0 || character == '\r' || character == '\n' || character == '\t' {
			return ErrIntentInvalid
		}
	}
	return nil
}

// intentEnvelope 是被密封 JSON 的稳定结构；字段名固定，便于跨版本读取。
type intentEnvelope struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// IntentSealer 是意图加密契约；生产实现为 *secrets.Sealer。Seal/Open 必须绑定
// Binding（用途/对象/范围）作为 AEAD 关联数据，使密文不能跨记录/跨用途复用。
type IntentSealer interface {
	Seal(binding secrets.Binding, plaintext []byte) ([]byte, error)
	Open(binding secrets.Binding, sealed []byte) ([]byte, error)
}

// SessionVerifier 是会话仍有效且属于该用户的校验契约；生产实现为
// *session.Service（VerifyActiveSession）。未接线时直接管理证明 fail-closed。
type SessionVerifier interface {
	VerifyActiveSession(ctx context.Context, userID, sessionID string) error
}

// PermissionChecker 是操作者当前权限的复核契约；生产实现由宿主接 internal/authz
// （root 语义由该内核统一决定）。它有两级复核：
//   - CheckOperationPermission：事务外（准备/发起阶段）使用独立只读连接做完整判定；
//   - CheckOperationPermissionTx：最终提交事务内使用**同一 tx 连接**再次判定（避免独立
//     连接与 SQLite 写事务互锁），权限在准备后被撤销时消费失败。
//
// 读不到/错误一律拒绝。事务内实现必须是只读 SQL，不写任何表。
type PermissionChecker interface {
	CheckOperationPermission(ctx context.Context, userID, permissionKey string) error
	CheckOperationPermissionTx(ctx context.Context, tx audit.Tx, userID, permissionKey string) error
}

// StrongWebAuthnStart 是一次 WebAuthn 第二步（强因素）挑战的公开参数；PublicKey
// 是给浏览器 WebAuthn API 的 options JSON，不含任何服务端秘密。
type StrongWebAuthnStart struct {
	CeremonyID string
	PublicKey  []byte
	RPID       string
	ExpiresAt  time.Time
}

// StrongWebAuthnVerifier 是 Passkey/安全密钥第二步断言的校验契约；生产实现适配
// internal/passkey 的 BeginSecondFactor/FinishSecondFactor（contextID = reauth 挑战
// ID，绑定到本次挑战，不能被其它登录/挑战挪用）。未接线时 WebAuthn 路径 fail-closed。
type StrongWebAuthnVerifier interface {
	BeginStrongWebAuthn(ctx context.Context, userID, contextID, requestID string) (StrongWebAuthnStart, error)
	FinishStrongWebAuthn(ctx context.Context, userID, contextID, ceremonyID string,
		response []byte, requestID string) (StrongFactorVerifyResult, error)
}

// SetSessionVerifier 晚接线会话校验实现（由宿主装配层在会话服务可用后调用）。
func (s *Service) SetSessionVerifier(verifier SessionVerifier) {
	if s == nil {
		return
	}
	s.proofMu.Lock()
	defer s.proofMu.Unlock()
	s.sessionVerifier = verifier
}

// SetPermissionChecker 晚接线权限复核实现（由宿主装配层在权限引擎可用后调用）。
func (s *Service) SetPermissionChecker(checker PermissionChecker) {
	if s == nil {
		return
	}
	s.proofMu.Lock()
	defer s.proofMu.Unlock()
	s.permissionChecker = checker
}

// SetStrongWebAuthn 晚接线 WebAuthn 第二步验证器（Passkey 服务构造完成后调用）。
func (s *Service) SetStrongWebAuthn(verifier StrongWebAuthnVerifier) {
	if s == nil {
		return
	}
	s.proofMu.Lock()
	defer s.proofMu.Unlock()
	s.strongWebAuthn = verifier
}

func (s *Service) currentSessionVerifier() SessionVerifier {
	if s == nil {
		return nil
	}
	s.proofMu.RLock()
	defer s.proofMu.RUnlock()
	return s.sessionVerifier
}

func (s *Service) currentPermissionChecker() PermissionChecker {
	if s == nil {
		return nil
	}
	s.proofMu.RLock()
	defer s.proofMu.RUnlock()
	return s.permissionChecker
}

func (s *Service) currentStrongWebAuthn() StrongWebAuthnVerifier {
	if s == nil {
		return nil
	}
	s.proofMu.RLock()
	defer s.proofMu.RUnlock()
	return s.strongWebAuthn
}

// isDirectManagementOperation 报告操作是否为“操作者与目标不同”的直接管理操作。
func isDirectManagementOperation(operationID string) bool {
	return operationID == policy.OperationDirectUsernameChange ||
		operationID == policy.OperationDirectPasswordReset
}

// directPermissionKey 返回直接管理操作对应的权限键；非直接管理操作返回 false。
func directPermissionKey(operationID string) (string, bool) {
	switch operationID {
	case policy.OperationDirectUsernameChange:
		return directUsernamePermissionKey, true
	case policy.OperationDirectPasswordReset:
		return directPasswordPermissionKey, true
	default:
		return "", false
	}
}

// requiredIntentKind 返回直接管理操作要求的意图类别。
func requiredIntentKind(operationID string) (IntentKind, bool) {
	switch operationID {
	case policy.OperationDirectUsernameChange:
		return IntentUsername, true
	case policy.OperationDirectPasswordReset:
		return IntentPassword, true
	default:
		return "", false
	}
}

// validSessionBinding 校验会话 ID 绑定的保守格式（真实有效性由 SessionVerifier
// 在准备阶段确认；这里只拒绝空值/超长/控制字符，避免把任意字符串写入绑定列）。
func validSessionBinding(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' ||
			character == '-' || character == ':' {
			continue
		}
		return false
	}
	return true
}

// sealIntent 把意图序列化并用注入的 Sealer 密封；未接线时返回 ErrProofUnavailable。
func (s *Service) sealIntent(challengeID, scopeID string, intent Intent) ([]byte, error) {
	if err := intent.Validate(); err != nil {
		return nil, err
	}
	s.proofMu.RLock()
	sealer := s.intentSealer
	s.proofMu.RUnlock()
	if isNil(sealer) {
		return nil, fmt.Errorf("%w: 操作意图加密器未装配", ErrProofUnavailable)
	}
	payload, err := json.Marshal(intentEnvelope{Kind: string(intent.Kind), Value: intent.Value()})
	if err != nil {
		return nil, fmt.Errorf("%w: 无法编码操作意图", ErrIntentInvalid)
	}
	sealed, err := sealer.Seal(secrets.Binding{
		Purpose: operationIntentPurpose, ObjectID: challengeID, ScopeID: scopeID,
	}, payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	return sealed, nil
}

// openIntent 解开批准上的密封意图；绑定不匹配/密文损坏一律按绑定不一致拒绝。
func (s *Service) openIntent(approval ApprovalRecord) (Intent, error) {
	s.proofMu.RLock()
	sealer := s.intentSealer
	s.proofMu.RUnlock()
	if isNil(sealer) {
		return Intent{}, fmt.Errorf("%w: 操作意图加密器未装配", ErrProofUnavailable)
	}
	if len(approval.IntentSealed) == 0 {
		return Intent{}, ErrApprovalInvalid
	}
	payload, err := sealer.Open(secrets.Binding{
		Purpose: operationIntentPurpose, ObjectID: approval.ChallengeID, ScopeID: approval.ScopeID,
	}, approval.IntentSealed)
	if err != nil {
		return Intent{}, ErrProofBindingMismatch
	}
	var envelope intentEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return Intent{}, ErrProofBindingMismatch
	}
	intent := Intent{Kind: IntentKind(envelope.Kind)}
	switch intent.Kind {
	case IntentUsername:
		intent.Username = envelope.Value
	case IntentPassword:
		intent.Password = envelope.Value
	default:
		return Intent{}, ErrProofBindingMismatch
	}
	if err := intent.Validate(); err != nil {
		return Intent{}, ErrProofBindingMismatch
	}
	return intent, nil
}

// sameIntentValue 以常量时间比较两个意图值（对低熵口令避免长度外的时间侧信道）。
func sameIntentValue(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

// checkDirectProofPermission 在事务外复核操作者当前权限；未接线时 fail-closed。
func (s *Service) checkDirectProofPermission(ctx context.Context, userID, permissionKey string) error {
	checker := s.currentPermissionChecker()
	if isNil(checker) {
		return fmt.Errorf("%w: 权限复核未装配", ErrProofUnavailable)
	}
	if err := checker.CheckOperationPermission(ctx, userID, permissionKey); err != nil {
		if errors.Is(err, ErrStoreUnavailable) || errors.Is(err, ErrProofUnavailable) {
			return err
		}
		return ErrAccessDenied
	}
	return nil
}

// ConsumeProofRequest 是准备消费目标绑定操作证明的请求。字段必须与签发时的绑定
// 完全一致；Intent 是本次执行准备应用的新值（与密封意图做常量时间一致性核对）。
type ConsumeProofRequest struct {
	ProofToken  string
	ScopeID     string
	OperationID string
	TargetType  string
	TargetID    string
	Params      map[string]string
	SessionID   string
	Intent      *Intent
	RequestID   string
}

// PreparedProof 是事务外完成全部复核后的证明快照，只存在于内存；调用方应立即把它
// 交给紧随其后的同一业务审计事务消费，不得持久化或跨请求复用。
//
// PreparedAt 是准备完成时间；ConsumePreparedProofTx 强制“准备→提交”最大间隔
// （Options.ProofMaxAge，默认 5 秒且不允许放宽到分钟级），超时返回 ErrProofExpired。
// 这是收敛两阶段窗口的硬边界：权限/会话复核只在准备阶段做完整判定，事务内再做
// 同一 tx 上的会话/账户/权限终检。
type PreparedProof struct {
	ApprovalID      string
	OperatorUserID  string
	ScopeID         string
	OperationID     string
	TargetType      string
	TargetID        string
	SessionID       string
	PermissionKey   string
	GrantedStrength policy.Strength
	Intent          Intent
	VerifiedAt      time.Time
	ExpiresAt       time.Time
	RequestID       string
	PreparedAt      time.Time
	// tokenDigest/paramsDigest 用于在最终事务内重新定位批准行并核对绑定一致。
	tokenDigest  []byte
	paramsDigest [32]byte
}

// ProofResult 是证明消费成功后的结果；Intent 是服务端密封保存并已核对一致的新值，
// 调用方应在同一事务内据此执行，不得写入日志/审计/响应。
type ProofResult struct {
	ApprovalID string
	// UserID 是完成两步验证的操作者。
	UserID          string
	ScopeID         string
	OperationID     string
	TargetType      string
	TargetID        string
	SessionID       string
	GrantedStrength policy.Strength
	Intent          Intent
	VerifiedAt      time.Time
	RequestID       string
}

// PrepareProof 在**事务外**完成目标绑定证明的全部复核：
//   - 操作令牌/操作者/作用域/操作/目标/参数绑定；
//   - 会话仍有效且属于操作者（SessionVerifier）；
//   - 操作者当前仍持有专门权限（PermissionChecker；权限撤销后拒绝）；
//   - 批准未消费/未过期、授予强度为 strong；
//   - 意图密文可解且与本次提交的新值完全一致。
//
// 本方法无副作用；返回 PreparedProof 后调用方应立即在业务审计事务内调用
// ConsumePreparedProofTx。失败一律拒绝且不改变批准状态。
func (s *Service) PrepareProof(ctx context.Context, caller Caller,
	request ConsumeProofRequest) (PreparedProof, error) {
	if err := caller.actor.Validate(); err != nil {
		return PreparedProof{}, ErrAccessDenied
	}
	if !caller.IsUser() {
		// 目标绑定证明必须由真实用户（管理员）会话完成两步验证，系统/本机身份不能
		// 代替操作者本人的强认证。
		return PreparedProof{}, ErrAccessDenied
	}
	if !isDirectManagementOperation(request.OperationID) {
		return PreparedProof{}, fmt.Errorf("%w: 非直接管理操作不能消费目标绑定证明", ErrInvalidRequest)
	}
	permissionKey, _ := directPermissionKey(request.OperationID)
	requiredKind, _ := requiredIntentKind(request.OperationID)
	policyRequest := Request{
		ScopeID: request.ScopeID, OperationID: request.OperationID,
		TargetType: request.TargetType, TargetID: request.TargetID, Params: request.Params,
		RequestID: request.RequestID,
	}
	if err := s.validateRequest(policyRequest); err != nil {
		return PreparedProof{}, err
	}
	if request.ScopeID != "system" {
		return PreparedProof{}, fmt.Errorf("%w: 直接管理操作只允许系统范围", ErrInvalidRequest)
	}
	if request.TargetType != "user" || !account.ValidUserID(request.TargetID) {
		return PreparedProof{}, fmt.Errorf("%w: 目标用户标识无效", ErrInvalidRequest)
	}
	if !validSessionBinding(request.SessionID) {
		return PreparedProof{}, ErrSessionMismatch
	}
	if request.Intent == nil || request.Intent.Kind != requiredKind {
		return PreparedProof{}, ErrIntentInvalid
	}
	if err := request.Intent.Validate(); err != nil {
		return PreparedProof{}, err
	}
	rawToken, decodeErr := hexToken(request.ProofToken)
	if decodeErr != nil {
		return PreparedProof{}, ErrApprovalInvalid
	}
	digest := secretDigest(rawToken)
	approval, found, err := s.opts.Store.GetApprovalByTokenDigest(ctx, digest)
	if err != nil {
		return PreparedProof{}, ErrStoreUnavailable
	}
	if !found {
		return PreparedProof{}, ErrApprovalInvalid
	}
	if approval.UserID != caller.actor.ID {
		return PreparedProof{}, ErrApprovalInvalid
	}
	if approval.ScopeID != request.ScopeID || approval.OperationID != request.OperationID ||
		approval.TargetType != request.TargetType || approval.TargetID != request.TargetID {
		return PreparedProof{}, ErrProofBindingMismatch
	}
	paramsDigest := ParamsDigest(request.Params)
	if !equalBytes(approval.ParamsSHA256, paramsDigest[:]) {
		return PreparedProof{}, ErrProofBindingMismatch
	}
	if approval.SessionID == "" || approval.SessionID != request.SessionID {
		return PreparedProof{}, ErrSessionMismatch
	}
	if approval.GrantedStrength != policy.StrengthStrong {
		// 直接管理操作固定要求两步验证（strong）；单因素批准不得消费。
		return PreparedProof{}, ErrMFARequired
	}
	now := s.now()
	if !approval.ConsumedAt.IsZero() {
		return PreparedProof{}, ErrApprovalConsumed
	}
	if !now.Before(approval.ExpiresAt) {
		return PreparedProof{}, ErrApprovalExpired
	}
	// 会话仍有效且属于操作者：撤销/过期会话上的证明拒绝（事务外读取）。
	sessionVerifier := s.currentSessionVerifier()
	if isNil(sessionVerifier) {
		return PreparedProof{}, fmt.Errorf("%w: 会话校验未装配", ErrProofUnavailable)
	}
	if verifyErr := sessionVerifier.VerifyActiveSession(ctx, caller.actor.ID, approval.SessionID); verifyErr != nil {
		return PreparedProof{}, ErrSessionMismatch
	}
	// 操作者当前权限复核：权限被撤销后证明拒绝（root 语义由权限内核统一决定）。
	if err := s.checkDirectProofPermission(ctx, caller.actor.ID, permissionKey); err != nil {
		return PreparedProof{}, err
	}
	// 意图一致性：服务端密封保存的新值必须与本次提交完全一致（换新值拒绝）。
	storedIntent, intentErr := s.openIntent(approval)
	if intentErr != nil {
		return PreparedProof{}, intentErr
	}
	if storedIntent.Kind != request.Intent.Kind || !sameIntentValue(storedIntent.Value(), request.Intent.Value()) {
		return PreparedProof{}, ErrProofBindingMismatch
	}
	// 用批准授予的真实认证事实复核策略（策略版本/目录变化时 fail-closed）。
	policyCaller, policyErr := toPolicyCaller(caller.actor)
	if policyErr != nil {
		return PreparedProof{}, ErrAccessDenied
	}
	decision, evaluateErr := s.opts.Policy.Evaluate(ctx, policyCaller, policy.EvaluateRequest{
		ScopeID: approval.ScopeID, OperationID: approval.OperationID,
		Verification: policy.Verification{VerifiedAt: approval.GrantedAt,
			Strength: approval.GrantedStrength, Confirmed: true},
	})
	if evaluateErr != nil {
		return PreparedProof{}, s.mapEvaluateError(evaluateErr, decision)
	}
	if err := s.checkComplete(decision, approval.Complete); err != nil {
		return PreparedProof{}, err
	}
	return PreparedProof{
		ApprovalID: approval.ID, OperatorUserID: approval.UserID, ScopeID: approval.ScopeID,
		OperationID: approval.OperationID, TargetType: approval.TargetType,
		TargetID: approval.TargetID, SessionID: approval.SessionID,
		PermissionKey: permissionKey, GrantedStrength: approval.GrantedStrength,
		Intent: storedIntent, VerifiedAt: approval.GrantedAt, ExpiresAt: approval.ExpiresAt,
		RequestID: request.RequestID, PreparedAt: s.now(),
		tokenDigest: digest, paramsDigest: paramsDigest,
	}, nil
}

// ConsumePreparedProofTx 在调用方审计事务内消费已准备好的证明：
//   - 强制“准备→提交”最大间隔（Options.ProofMaxAge，默认 5 秒、硬上限 5 秒），
//     超时返回 ErrProofExpired，调用方须重新 Prepare（重新复核会话/账户/权限）；
//   - 用**同一事务连接**重读会话状态与账户状态：sessions 必须仍存在、属于操作者、
//     kind=normal、未撤销、未空闲/绝对过期，且会话 security_version 与 users 当前
//     security_version 一致；users.status 必须 active 且在账户有效期内。任一不满足
//     整体拒绝，证明不被消费、业务不落库；
//   - 用同一事务连接重读操作者当前权限（CheckOperationPermissionTx，tx 内只读 SQL），
//     准备后被撤销的权限在此拒绝；
//   - 重新读取同一批准行，核对绑定快照一致、未消费/未过期、密文仍存在；条件消费
//     （并发只有一个赢家）；
//   - 在同一事务内写入“证明已消费”审计事件并返回服务端意图。
//
// 业务写入失败时调用方回滚，证明不被消费、可再次 Prepare 后重试。本方法不调用
// 任何会另开连接/另开事务的依赖（避免 SQLite 写事务互锁产生 AUTHZ_UNAVAILABLE）。
func (s *Service) ConsumePreparedProofTx(ctx context.Context, tx audit.Tx, caller Caller,
	prepared PreparedProof) (ProofResult, error) {
	if tx == nil {
		return ProofResult{}, fmt.Errorf("%w: 审计事务为空", ErrOptionsInvalid)
	}
	if err := caller.actor.Validate(); err != nil {
		return ProofResult{}, ErrAccessDenied
	}
	if !caller.IsUser() || prepared.OperatorUserID != caller.actor.ID ||
		prepared.ApprovalID == "" || len(prepared.tokenDigest) != 32 ||
		!isDirectManagementOperation(prepared.OperationID) ||
		prepared.SessionID == "" || prepared.PermissionKey == "" {
		return ProofResult{}, ErrApprovalInvalid
	}
	now := s.now()
	// 硬窗口：准备到提交的最大间隔，防止权限/会话复核结果被无限期复用。
	if prepared.PreparedAt.IsZero() || now.Before(prepared.PreparedAt) {
		return ProofResult{}, ErrProofExpired
	}
	if now.Sub(prepared.PreparedAt) > s.proofMaxAgeLimit() {
		return ProofResult{}, ErrProofExpired
	}
	approval, found, err := s.opts.Store.GetApprovalByTokenDigestTx(ctx, tx, prepared.tokenDigest)
	if err != nil {
		return ProofResult{}, ErrStoreUnavailable
	}
	if !found || approval.ID != prepared.ApprovalID {
		return ProofResult{}, ErrApprovalInvalid
	}
	if approval.UserID != prepared.OperatorUserID ||
		approval.ScopeID != prepared.ScopeID ||
		approval.OperationID != prepared.OperationID ||
		approval.TargetType != prepared.TargetType ||
		approval.TargetID != prepared.TargetID ||
		approval.SessionID != prepared.SessionID ||
		approval.GrantedStrength != prepared.GrantedStrength ||
		!equalBytes(approval.ParamsSHA256, prepared.paramsDigest[:]) {
		return ProofResult{}, ErrProofBindingMismatch
	}
	if !approval.ConsumedAt.IsZero() {
		return ProofResult{}, ErrApprovalConsumed
	}
	if !now.Before(approval.ExpiresAt) {
		return ProofResult{}, ErrApprovalExpired
	}
	if len(approval.IntentSealed) == 0 {
		// 密文已被清空（消费/清理）或旧行：证明不再可用。
		return ProofResult{}, ErrApprovalInvalid
	}
	// (1) 事务内重读会话状态：未撤销、未过期、正常会话、属于操作者。
	sessionState, sessionFound, stateErr := s.opts.Store.GetSessionStateTx(ctx, tx, approval.SessionID)
	if stateErr != nil {
		return ProofResult{}, ErrStoreUnavailable
	}
	if !sessionFound || sessionState.UserID != caller.actor.ID ||
		sessionState.Kind != "normal" || sessionState.Revoked ||
		!sessionState.IdleExpiresAt.After(now) || !sessionState.AbsoluteExpiresAt.After(now) {
		return ProofResult{}, ErrSessionMismatch
	}
	// (2) 事务内重读账户状态：active、有效期内、安全版本与会话签发快照一致。
	userState, userFound, userErr := s.opts.Store.GetUserAuthStateTx(ctx, tx, caller.actor.ID)
	if userErr != nil {
		return ProofResult{}, ErrStoreUnavailable
	}
	if !userFound || userState.Status != "active" {
		return ProofResult{}, ErrAccessDenied
	}
	if userState.ValidFrom != nil && now.Before(*userState.ValidFrom) {
		return ProofResult{}, ErrAccessDenied
	}
	if userState.ValidUntil != nil && !now.Before(*userState.ValidUntil) {
		return ProofResult{}, ErrAccessDenied
	}
	if sessionState.SecurityVersion != userState.SecurityVersion {
		// 会话签发后账户安全版本已变化（改密/禁用/状态变更）：现会话已失效，
		// 依赖该会话完成的证明随之拒绝。
		return ProofResult{}, ErrSessionMismatch
	}
	// (3) 事务内复核操作者当前权限（同 tx 只读 SQL；不使用独立连接）。
	permissionChecker := s.currentPermissionChecker()
	if isNil(permissionChecker) {
		return ProofResult{}, fmt.Errorf("%w: 权限复核未装配", ErrProofUnavailable)
	}
	if checkErr := permissionChecker.CheckOperationPermissionTx(ctx, tx, caller.actor.ID,
		prepared.PermissionKey); checkErr != nil {
		if errors.Is(checkErr, ErrStoreUnavailable) || errors.Is(checkErr, ErrProofUnavailable) {
			return ProofResult{}, checkErr
		}
		return ProofResult{}, ErrAccessDenied
	}
	consumed, consumeErr := s.opts.Store.ConsumeApprovalTx(ctx, tx, approval.ID, now)
	if consumeErr != nil {
		return ProofResult{}, mapCriticalError(consumeErr)
	}
	if !consumed {
		return ProofResult{}, ErrApprovalConsumed
	}
	// 证明消费事件与业务写入/关键审计同事务：任一失败由调用方回滚（证明不被烧毁）。
	eventID, idErr := audit.NewEventID()
	if idErr != nil {
		return ProofResult{}, fmt.Errorf("%w: 无法生成审计事件编号", ErrStoreUnavailable)
	}
	if eventErr := tx.AppendEvent(ctx, audit.Event{
		ID: eventID, OccurredAt: now, Actor: caller.actor,
		Action:  "reauth.operation_proof_consumed",
		Target:  audit.Target{Type: "reauth_approval", ID: approval.ID},
		Outcome: audit.OutcomeSuccess, RequestID: validRequestID(prepared.RequestID),
		Changes: []audit.FieldChange{
			{Field: "operation_id", After: approval.OperationID},
			{Field: "target_type", After: approval.TargetType},
			{Field: "target_id", After: safeValue(approval.TargetID)},
			{Field: "session_bound", After: "true"},
			{Field: "granted_strength", After: string(approval.GrantedStrength)},
		},
	}); eventErr != nil {
		return ProofResult{}, mapCriticalError(fmt.Errorf("%w: %w", audit.ErrAuditUnavailable, eventErr))
	}
	return ProofResult{
		ApprovalID: approval.ID, UserID: approval.UserID, ScopeID: approval.ScopeID,
		OperationID: approval.OperationID, TargetType: approval.TargetType,
		TargetID: approval.TargetID, SessionID: approval.SessionID,
		GrantedStrength: approval.GrantedStrength, Intent: prepared.Intent,
		VerifiedAt: prepared.VerifiedAt, RequestID: prepared.RequestID,
	}, nil
}

// purgeExpiredIntents 有界擦除过期/已消费批准上的密文，避免密封意图长期滞留。
// 清理解密文不改变批准状态；失败只记录日志（不影响签发结果，实际安全由消费时校验
// 与过期判断保证）。
func (s *Service) purgeExpiredIntents(ctx context.Context) {
	if err := s.opts.Store.ClearExpiredIntents(context.WithoutCancel(ctx), s.now()); err != nil {
		s.opts.Logger.Warn("清理过期操作意图密文失败", "error", err)
	}
}

// errDirectOperationRequiresProof 是旧批准信号路径对直接管理操作的统一拒绝原因。
var errDirectOperationRequiresProof = fmt.Errorf(
	"%w: 直接管理操作必须使用目标绑定操作证明", ErrReauthRequired)
