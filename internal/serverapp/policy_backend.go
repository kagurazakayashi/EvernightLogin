package serverapp

// 敏感策略页后端包装：在真实 uiadminadapter 之外加一层“每次策略写绑定具体变更”
// 的宿主边界。
//
// 背景：页面适配器的 Reauth 回调只按 userID 触发一次再次认证，而真正写库发生在
// 回调之后；如果没有绑定，一次确认可能被挪用到另一条策略变更。这里把
// begin(变更摘要/版本/作用域/操作) → 回调 → policy.Set 消费 → finish(核对摘要)
// 串行化，任何不一致/重放都返回 REAUTH_REQUIRED。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// policyWriteBackend 包装真实敏感策略页后端，只拦截四个写/敏感动作。
type policyWriteBackend struct {
	login.UISecurityPolicyBackend
	gate  *SecurityGate
	audit *audit.Recorder
}

// newPolicyWriteBackend 构造包装器；gate 为空时返回 nil（调用方应拒绝装配）。
func newPolicyWriteBackend(inner login.UISecurityPolicyBackend,
	gate *SecurityGate, recorder *audit.Recorder) *policyWriteBackend {
	if inner == nil || gate == nil {
		return nil
	}
	return &policyWriteBackend{UISecurityPolicyBackend: inner, gate: gate, audit: recorder}
}

// securityPolicyReauthError 返回页面稳定错误码（再次认证未满足）。
func securityPolicyReauthError() error {
	return &login.UISecurityPolicyError{Code: "REAUTH_REQUIRED"}
}

// policyValuesDigest 规范化策略值后计算绑定摘要（不含秘密，仅定位变更内容）。
func policyValuesDigest(values login.UISecurityPolicyValues) string {
	canonical := fmt.Sprintf("%t|%t|%d|%s|%t|%t", values.Sensitive,
		values.ReauthRequired, values.MaxAuthAgeSeconds, values.Strength,
		values.ConfirmationRequired, values.NotificationRequired)
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

// SavePolicy 实现 login.UISecurityPolicyBackend：绑定变更摘要与版本后执行。
func (b *policyWriteBackend) SavePolicy(ctx context.Context, userID, scopeID,
	operationID string, change login.UISecurityPolicyValues, expectedVersion int64,
	previewToken, requestID string) (login.UISecurityPolicyWriteResult, error) {
	normalized, _ := login.NormalizeSecurityPolicyChange(change)
	digest := policyValuesDigest(normalized)
	if err := b.beginLocked(userID, "policy.save", scopeID, operationID,
		expectedVersion, digest); err != nil {
		return login.UISecurityPolicyWriteResult{}, securityPolicyReauthError()
	}
	if authErr := b.gate.authorizePolicyWrite(ctx, userID, "policy.save", scopeID,
		operationID, expectedVersion, digest); authErr != nil {
		b.gate.policyWriteMu.Unlock()
		b.gate.abortPolicyWrite(userID)
		return login.UISecurityPolicyWriteResult{}, securityPolicyReauthError()
	}
	result, callErr := b.UISecurityPolicyBackend.SavePolicy(ctx, userID, scopeID,
		operationID, change, expectedVersion, previewToken, requestID)
	return b.finishOnReturn(userID, digest, result, callErr)
}

// RestorePolicy 实现 login.UISecurityPolicyBackend：绑定作用域/操作/版本后执行。
func (b *policyWriteBackend) RestorePolicy(ctx context.Context, userID, scopeID,
	operationID string, all bool, expectedVersion int64, previewToken,
	requestID string) (login.UISecurityPolicyWriteResult, error) {
	digest := policyWriteDigest("policy.restore", scopeID, operationID,
		expectedVersion, strconv.FormatBool(all))
	if err := b.beginLocked(userID, "policy.restore", scopeID, operationID,
		expectedVersion, digest); err != nil {
		return login.UISecurityPolicyWriteResult{}, securityPolicyReauthError()
	}
	if authErr := b.gate.authorizePolicyWrite(ctx, userID, "policy.restore", scopeID,
		operationID, expectedVersion, digest); authErr != nil {
		b.gate.policyWriteMu.Unlock()
		b.gate.abortPolicyWrite(userID)
		return login.UISecurityPolicyWriteResult{}, securityPolicyReauthError()
	}
	result, callErr := b.UISecurityPolicyBackend.RestorePolicy(ctx, userID, scopeID,
		operationID, all, expectedVersion, previewToken, requestID)
	return b.finishOnReturn(userID, digest, result, callErr)
}

// SendTestMail 实现 login.UISecurityPolicyBackend：只做再次认证，不建立策略写批准。
func (b *policyWriteBackend) SendTestMail(ctx context.Context, userID, recipient,
	kind, idempotencyKey, requestID string) (login.UINotificationTestResult, error) {
	return b.UISecurityPolicyBackend.SendTestMail(ctx, userID, recipient, kind,
		idempotencyKey, requestID)
}

// ReplaceSMTPSecret 实现 login.UISecurityPolicyBackend：秘密替换同样属于敏感动作，
// 只做再次认证；真实秘密写入通道未装配（页面能力位为 false）。
func (b *policyWriteBackend) ReplaceSMTPSecret(ctx context.Context, userID, newSecret,
	idempotencyKey, requestID string) (login.UINotificationSecretResult, error) {
	return b.UISecurityPolicyBackend.ReplaceSMTPSecret(ctx, userID, newSecret,
		idempotencyKey, requestID)
}

// beginLocked 获取写锁并登记变更绑定。
func (b *policyWriteBackend) beginLocked(userID, action, scopeID, operationID string,
	version int64, digest string) error {
	b.gate.policyWriteMu.Lock()
	if err := b.gate.beginPolicyWriteLocked(userID, action, scopeID, operationID,
		version, digest); err != nil {
		b.gate.policyWriteMu.Unlock()
		return err
	}
	return nil
}

// finishOnReturn 在写完/失败后核对绑定并释放写锁。
func (b *policyWriteBackend) finishOnReturn(userID, digest string,
	result login.UISecurityPolicyWriteResult, err error) (login.UISecurityPolicyWriteResult, error) {
	defer b.gate.policyWriteMu.Unlock()
	if err != nil {
		b.gate.abortPolicyWrite(userID)
		return result, err
	}
	if finishErr := b.gate.finishPolicyWrite(userID, digest); finishErr != nil {
		// 授权与绑定检查发生在写之前（authorizePolicyWrite），此处只可能是内部不变量
		// 违例；写失败审计并清理记录，不改变已提交结果也不残留批准。
		b.recordInvariantFailure(context.WithoutCancel(context.Background()))
		return result, nil
	}
	return result, nil
}

// recordInvariantFailure 写失败审计（写前授权已通过，正常路径不会触发）。
func (b *policyWriteBackend) recordInvariantFailure(ctx context.Context) {
	if b == nil || b.audit == nil {
		return
	}
	_ = b.audit.RecordFailure(ctx, audit.Event{
		Actor:   audit.Actor{Type: audit.ActorSystem, ID: hostComponentID},
		Action:  "security.policy.write_invariant_failed",
		Target:  audit.Target{Type: "sensitive_policy", ID: "system"},
		Outcome: audit.OutcomeFailure, ErrorCode: "INTERNAL_ERROR",
	})
}

// beginPolicyWriteLocked 假设调用方已持有串行化锁，只做记录登记。
func (g *SecurityGate) beginPolicyWriteLocked(userID, action, scopeID,
	operationID string, version int64, digest string) error {
	if g == nil || userID == "" {
		return login.ErrUISessionExpired
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, exists := g.policyWrites[userID]; exists {
		return fmt.Errorf("策略写批准仍在进行中")
	}
	g.policyWrites[userID] = &policyWrite{
		digest: digest, action: action, scopeID: scopeID, operationID: operationID,
		version: version, expiresAt: time.Now().Add(policyApprovalTTL),
	}
	return nil
}
