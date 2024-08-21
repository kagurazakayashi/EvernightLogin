// Package uiadminadapter 的步骤 72 补充：把敏感操作策略目录/覆盖/恢复默认与安全
// 通知设置页面公开契约接到真实 policy/reauth/audit/mailer 能力。
//
// 安全边界：适配器只接受页面已通过 UIAccessManagement 验证后传入的管理员用户 ID，
// 每次都重新构造可信 Caller 并调用真实服务；root 判定、再次认证、版本冲突、字段
// 白名单与审计由 policy.Service 强制执行。本包不实现放行、不缓存授权、不读取前端
// 自报角色。
//
// 本文件新增的三层绑定（步骤 72 安全修复轮）：
//   - 预览令牌：预览由适配器签发一次性随机令牌，绑定操作者/动作/作用域/目标/版本/
//     完整拟提交值摘要或恢复清单摘要；保存/恢复必须带回，服务端重算比较并消费，
//     目标或参数变化、重复使用均拒绝（CHALLENGE_INVALID）。
//   - 再次认证：保存、恢复、SMTP 秘密替换与测试邮件在动作前调用宿主 Reauth 回调，
//     回调收到同一 UISecurityPolicyActionBinding 作为参数摘要；未装配即 fail-closed
//     REAUTH_REQUIRED。
//   - 审计：秘密替换与测试邮件成功/失败均写安全审计（不含秘密/完整目标）；审计不可
//     用时动作按未完成处理（AUDIT_WRITE_FAILED）。
//
// 另外：页面能力位使用真实权限键 security.policy.manage，并结合真实 root 资格；
// 秘密替换与测试邮件带幂等键，重复提交返回同一结果且不重复调用宿主/发送。
package uiadminadapter

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	ui "github.com/kagurazakayashi/EvernightLogin/ui"
)

// SecurityPolicyPermissionKey 是敏感策略页面使用的真实既有权限键（预设目录
// `security.policy.manage`：「查看、修改与恢复敏感操作安全策略」）。写操作仍由
// policy.Service 强制真实 root；本键只用于页面能力位与宿主授权映射。
const SecurityPolicyPermissionKey = "security.policy.manage"

// 页面动作名（均由 SecurityPolicyPermissionKey 派生；通知区域当前无独立真实权限
// 键，复用同一键并额外要求真实 root，待后续步骤冻结专用键）。
const (
	SecurityPolicyActionRead      = SecurityPolicyPermissionKey
	SecurityPolicyActionWrite     = SecurityPolicyPermissionKey
	NotificationActionRead        = SecurityPolicyPermissionKey
	NotificationActionTest        = SecurityPolicyPermissionKey
	NotificationActionSecretWrite = SecurityPolicyPermissionKey
)

// previewTokenTTL 是一次性预览令牌/幂等记录的有效期。
const previewTokenTTL = 10 * time.Minute

// NotificationMailOptions 是安全通知设置页的真实依赖；nil 表示宿主未接入该能力，
// 页面显示真实“未配置/状态未读取”，不伪造可提交表单。
type NotificationMailOptions struct {
	Sender                 mailer.Sender
	Templates              *mailer.TemplateSet
	TemplateSource         string
	FromAddress            string
	SMTPAddr               string
	SMTPHost               string
	TLSMode                string
	SMTPTimeoutSeconds     int
	MaxAttempts            int
	DeliveryTimeoutSeconds int
	AllowPlaintextLocal    bool
	TrustedRootsConfigured bool
	SecretConfigured       bool
	SecretStatusKnown      bool
	ReplaceSecret          func(ctx context.Context, operatorUserID, newSecret, requestID string) error
	Notifications          *reauth.Service
}

// SecurityPolicyAuditor 是安全审计写入契约（秘密替换/测试邮件的成功与失败留痕）。
type SecurityPolicyAuditor interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
}

// SecurityPolicyOptions 是敏感策略/安全通知页面适配器依赖。
type SecurityPolicyOptions struct {
	Policy *policy.Service
	// Authorize 由宿主实现（authz + 管理强认证），用于页面能力位与读取许可；
	// 为 nil 时能力位全部为 false（页面只呈现无权限状态；真实服务仍会拒绝写）。
	Authorize func(ctx context.Context, userID, action string) error
	// Reauth 是页面动作前的再次认证（参数摘要由 binding 携带）；nil 时写/替换/
	// 测试动作 fail-closed 为 REAUTH_REQUIRED。
	Reauth func(ctx context.Context, userID string, binding ui.UISecurityPolicyActionBinding) error
	// Audit 是秘密替换/测试邮件的安全审计；nil 时对应能力位为 false（不 fail-open）。
	Audit SecurityPolicyAuditor
	Mail  *NotificationMailOptions
}

// SecurityPolicyAdapter 实现 ui.UISecurityPolicyBackend。
type SecurityPolicyAdapter struct {
	opts   SecurityPolicyOptions
	now    func() time.Time
	mu     sync.Mutex
	secret bool
	// previews 是服务端一次性预览绑定；tokens 用后即删。
	previews map[string]previewEntry
	// idempotent 保存幂等结果（秘密替换/测试邮件），键为 userID|idempotencyKey。
	idempotent map[string]idempotentEntry
	testSends  map[string][]time.Time
}

type previewEntry struct {
	binding ui.UISecurityPolicyActionBinding
	expires time.Time
}

type idempotentEntry struct {
	expires time.Time
	result  any
}

// NewSecurityPolicy 校验依赖并构造敏感策略页面适配器。
func NewSecurityPolicy(options SecurityPolicyOptions) (*SecurityPolicyAdapter, error) {
	if options.Policy == nil {
		return nil, fmt.Errorf("敏感策略页面适配器缺少策略服务")
	}
	adapter := &SecurityPolicyAdapter{
		opts: options, now: time.Now,
		previews:   map[string]previewEntry{},
		idempotent: map[string]idempotentEntry{},
		testSends:  map[string][]time.Time{},
	}
	if options.Mail != nil {
		adapter.secret = options.Mail.SecretConfigured
	}
	return adapter, nil
}

var _ ui.UISecurityPolicyBackend = (*SecurityPolicyAdapter)(nil)

// securityPolicyErr 构造稳定公开错误。
func securityPolicyErr(code string) error {
	return &ui.UISecurityPolicyError{Code: code}
}

// policyErr 把 policy 领域错误映射为页面稳定错误码（只复用既有公开错误码）。
func policyErr(err error) error {
	if err == nil {
		return nil
	}
	code := string(policy.CodeOf(err))
	if code == "" {
		code = "INTERNAL_ERROR"
	}
	return &ui.UISecurityPolicyError{Code: code}
}

// securityPolicyCheck 判定页面能力位（失败按无能力处理）。
func (a *SecurityPolicyAdapter) securityPolicyCheck(ctx context.Context, userID,
	action string) bool {
	if a.opts.Authorize == nil || !account.ValidUserID(userID) {
		return false
	}
	return a.opts.Authorize(ctx, userID, action) == nil
}

// policyCaller 构造可信用户调用者；写操作绑定请求编号。宿主直接挂载页面（未经
// transport 中间件）时请求编号可能为空：适配器生成符合校验规则的随机编号。
func policyCaller(userID, requestID string) (policy.Caller, error) {
	caller, err := policy.UserCaller(userID)
	if err != nil {
		return policy.Caller{}, err
	}
	trimmed := strings.TrimSpace(requestID)
	if trimmed == "" {
		trimmed = newSecurityPolicyRequestID()
	}
	caller, err = caller.WithRequestID(trimmed)
	if err != nil {
		return policy.Caller{}, err
	}
	return caller, nil
}

// newSecurityPolicyRequestID 生成页面写操作使用的随机请求编号。
func newSecurityPolicyRequestID() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return ""
	}
	return "req_" + hex.EncodeToString(buffer)
}

// newPreviewToken 生成一次性预览令牌。
func newPreviewToken() string {
	buffer := make([]byte, 24)
	if _, err := rand.Read(buffer); err != nil {
		return ""
	}
	return "prev_" + hex.EncodeToString(buffer)
}

// digestStrings 对规范化字符串序列计算 SHA-256 十六进制摘要。
func digestStrings(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		hash.Write([]byte(part))
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// capabilityRoot 报告当前用户是否为真实 root（只读；失败按非 root）。
func (a *SecurityPolicyAdapter) capabilityRoot(ctx context.Context, userID string) bool {
	caller, err := policy.UserCaller(userID)
	if err != nil {
		return false
	}
	isRoot, err := a.opts.Policy.UserIsRoot(ctx, caller)
	return err == nil && isRoot
}

// Capabilities 返回当前管理员的页面能力位（只影响呈现）。
func (a *SecurityPolicyAdapter) Capabilities(ctx context.Context,
	userID string) (ui.UISecurityPolicyCapabilities, error) {
	if a.opts.Authorize == nil || !account.ValidUserID(userID) {
		return ui.UISecurityPolicyCapabilities{}, securityPolicyErr("ACCESS_DENIED")
	}
	read := a.securityPolicyCheck(ctx, userID, SecurityPolicyActionRead)
	root := a.capabilityRoot(ctx, userID)
	write := root && a.securityPolicyCheck(ctx, userID, SecurityPolicyActionWrite)
	mailReady := a.opts.Mail != nil && a.opts.Reauth != nil && a.opts.Audit != nil
	testMail := root && mailReady && a.opts.Mail.Sender != nil &&
		a.opts.Mail.Templates != nil && a.securityPolicyCheck(ctx, userID, NotificationActionTest)
	replaceSecret := root && mailReady && a.opts.Mail.ReplaceSecret != nil &&
		a.securityPolicyCheck(ctx, userID, NotificationActionSecretWrite)
	return ui.UISecurityPolicyCapabilities{
		ReadPolicies:      read,
		WritePolicies:     write,
		ReadNotifications: read && a.securityPolicyCheck(ctx, userID, NotificationActionRead),
		TestMail:          testMail,
		ReplaceSecret:     replaceSecret,
	}, nil
}

// policyValues 把领域策略转为页面机器值。
func policyValues(value policy.Policy) ui.UISecurityPolicyValues {
	return ui.UISecurityPolicyValues{
		Sensitive:            value.Sensitive,
		ReauthRequired:       value.ReauthRequired,
		MaxAuthAgeSeconds:    value.MaxAuthAgeSeconds,
		Strength:             string(value.Strength),
		ConfirmationRequired: value.ConfirmationRequired,
		NotificationRequired: value.NotificationRequired,
	}
}

// policyFromValues 把页面机器值转为领域策略（字段白名单由页面契约固定）。
func policyFromValues(value ui.UISecurityPolicyValues) policy.Policy {
	return policy.Policy{
		Sensitive:            value.Sensitive,
		ReauthRequired:       value.ReauthRequired,
		MaxAuthAgeSeconds:    value.MaxAuthAgeSeconds,
		Strength:             policy.Strength(value.Strength),
		ConfirmationRequired: value.ConfirmationRequired,
		NotificationRequired: value.NotificationRequired,
	}
}

// valuesDigest 计算六字段与目标/版本绑定的参数摘要。
func valuesDigest(scopeID, operationID string, version int64,
	values ui.UISecurityPolicyValues) string {
	return digestStrings("policy.save", scopeID, operationID,
		fmt.Sprintf("%d", version), fmt.Sprintf("%t", values.Sensitive),
		fmt.Sprintf("%t", values.ReauthRequired),
		fmt.Sprintf("%d", values.MaxAuthAgeSeconds), values.Strength,
		fmt.Sprintf("%t", values.ConfirmationRequired),
		fmt.Sprintf("%t", values.NotificationRequired))
}

// operationView 把有效操作转为页面视图。
func (a *SecurityPolicyAdapter) operationView(operation policy.EffectiveOperation,
	available map[policy.Strength]bool) ui.UISecurityPolicyOperation {
	view := ui.UISecurityPolicyOperation{
		OperationID: operation.OperationID, Domain: string(operation.Domain),
		Name: operation.Name, Description: operation.Description,
		Default: policyValues(operation.Default), HasDefault: operation.HasDefault,
		Effective: policyValues(operation.Effective), Source: string(operation.Source),
		PermissionKey: operation.PermissionKey, RootOnly: operation.RootOnly,
		AuditRequired: operation.AuditRequired, Implemented: operation.Implemented,
		ChangedFields: login.SecurityPolicyChangedFields(policyValues(operation.Default),
			policyValues(operation.Effective)),
		StrengthAvailable: available[operation.Effective.Strength] ||
			operation.Effective.Strength == policy.StrengthNone,
	}
	if operation.Override != nil {
		override := policyValues(*operation.Override)
		view.Override = &override
	}
	if definition, ok := a.opts.Policy.Operation(operation.OperationID); ok {
		view.ImmutableSensitive = definition.ImmutableSensitive
	}
	return view
}

// snapshotView 把领域快照转为页面视图。
func (a *SecurityPolicyAdapter) snapshotView(snapshot policy.Snapshot) ui.UISecurityPolicySnapshot {
	available := map[policy.Strength]bool{}
	strengths := []string{}
	for _, strength := range a.opts.Policy.AvailableStrengths() {
		available[strength] = true
		strengths = append(strengths, string(strength))
	}
	view := ui.UISecurityPolicySnapshot{
		ScopeID: snapshot.ScopeID, ScopeName: snapshot.ScopeID,
		Version: snapshot.Version, CatalogVersion: a.opts.Policy.CatalogVersion(),
		AvailableStrengths: strengths,
		Operations:         make([]ui.UISecurityPolicyOperation, 0, len(snapshot.Operations)),
	}
	for _, operation := range snapshot.Operations {
		item := a.operationView(operation, available)
		if operation.Source == policy.SourceApplication {
			view.Declared = append(view.Declared, item)
			continue
		}
		view.Operations = append(view.Operations, item)
	}
	return view
}

// readSnapshot 读取系统作用域快照（读取许可由 policy.Service 复核）。
func (a *SecurityPolicyAdapter) readSnapshot(ctx context.Context,
	userID, scopeID string) (policy.Snapshot, ui.UISecurityPolicySnapshot, error) {
	caller, err := policyCaller(userID, "")
	if err != nil {
		return policy.Snapshot{}, ui.UISecurityPolicySnapshot{}, securityPolicyErr("ACCESS_DENIED")
	}
	if scopeID == "" {
		scopeID = ui.UISecurityPolicySystemScope
	}
	snapshot, err := a.opts.Policy.Effective(ctx, caller, scopeID)
	if err != nil {
		return policy.Snapshot{}, ui.UISecurityPolicySnapshot{}, policyErr(err)
	}
	return snapshot, a.snapshotView(snapshot), nil
}

// Snapshot 读取系统作用域有效策略快照。
func (a *SecurityPolicyAdapter) Snapshot(ctx context.Context, userID,
	scopeID string) (ui.UISecurityPolicySnapshot, error) {
	_, view, err := a.readSnapshot(ctx, userID, scopeID)
	return view, err
}

// findOperation 在领域快照中查找操作。
func findOperation(snapshot policy.Snapshot,
	operationID string) (policy.EffectiveOperation, bool) {
	return snapshot.Lookup(operationID)
}

// availableStrengthSet 返回当前环境可满足的强度集合。
func availableStrengthSet(service *policy.Service) map[policy.Strength]bool {
	available := map[policy.Strength]bool{}
	for _, strength := range service.AvailableStrengths() {
		available[strength] = true
	}
	return available
}

// issuePreview 保存一次性预览绑定并返回令牌。
func (a *SecurityPolicyAdapter) issuePreview(binding ui.UISecurityPolicyActionBinding) string {
	token := newPreviewToken()
	if token == "" {
		return ""
	}
	now := a.now().UTC()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cleanupLocked(now)
	a.previews[token] = previewEntry{binding: binding, expires: now.Add(previewTokenTTL)}
	return token
}

// consumePreview 校验并一次性消费预览令牌：目标/参数/版本任一变化或重复使用都拒绝。
func (a *SecurityPolicyAdapter) consumePreview(token, userID string,
	actual ui.UISecurityPolicyActionBinding) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return securityPolicyErr("REQ_INVALID")
	}
	now := a.now().UTC()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cleanupLocked(now)
	entry, ok := a.previews[token]
	if !ok || !entry.expires.After(now) {
		return securityPolicyErr("CHALLENGE_INVALID")
	}
	if entry.binding.UserID != userID || entry.binding.Action != actual.Action ||
		entry.binding.ScopeID != actual.ScopeID ||
		entry.binding.OperationID != actual.OperationID ||
		entry.binding.Version != actual.Version ||
		entry.binding.ChangeDigest != actual.ChangeDigest ||
		entry.binding.All != actual.All ||
		entry.binding.AffectedCount != actual.AffectedCount ||
		entry.binding.SelfProtection != actual.SelfProtection ||
		strings.Join(entry.binding.AffectedOperations, ",") !=
			strings.Join(actual.AffectedOperations, ",") {
		return securityPolicyErr("CHALLENGE_INVALID")
	}
	delete(a.previews, token)
	return nil
}

// cleanupLocked 清理过期的预览与幂等记录（调用方持有锁）。
func (a *SecurityPolicyAdapter) cleanupLocked(now time.Time) {
	for token, entry := range a.previews {
		if !entry.expires.After(now) {
			delete(a.previews, token)
		}
	}
	for key, entry := range a.idempotent {
		if !entry.expires.After(now) {
			delete(a.idempotent, key)
		}
	}
}

// verifyReauth 调用宿主再次认证并绑定参数摘要；未装配即 fail-closed。
func (a *SecurityPolicyAdapter) verifyReauth(ctx context.Context, userID string,
	binding ui.UISecurityPolicyActionBinding) error {
	if a.opts.Reauth == nil {
		return securityPolicyErr("REAUTH_REQUIRED")
	}
	if err := a.opts.Reauth(ctx, userID, binding); err != nil {
		return securityPolicyErr("REAUTH_REQUIRED")
	}
	return nil
}

// recordAudit 记录一次安全动作审计（不含秘密与完整目标）。
func (a *SecurityPolicyAdapter) recordAudit(ctx context.Context, userID, action,
	outcome, errorCode, requestID string) error {
	if a.opts.Audit == nil {
		return securityPolicyErr("AUDIT_WRITE_FAILED")
	}
	event := audit.Event{
		Actor:     audit.Actor{Type: audit.ActorUser, ID: userID},
		Action:    action,
		Target:    audit.Target{Type: "notification_mail", ID: "settings"},
		Outcome:   audit.Outcome(outcome),
		ErrorCode: errorCode,
		RequestID: requestID,
	}
	var err error
	if outcome == string(audit.OutcomeSuccess) {
		err = a.opts.Audit.Record(ctx, event)
	} else {
		err = a.opts.Audit.RecordFailure(ctx, event)
	}
	if err != nil {
		return securityPolicyErr("AUDIT_WRITE_FAILED")
	}
	return nil
}

// idempotencyKey 规范化幂等键（空时回退请求编号，再空则随机生成）；动作前缀保证
// 秘密替换与测试邮件不会因页面复用同一隐藏键而互相命中。
func idempotencyKey(action, userID, key, requestID string) string {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		trimmed = strings.TrimSpace(requestID)
	}
	if trimmed == "" {
		trimmed = newPreviewToken()
	}
	return action + "|" + userID + "|" + trimmed
}

// lookupIdempotent 读取未过期的幂等结果。
func (a *SecurityPolicyAdapter) lookupIdempotent(key string) (any, bool) {
	now := a.now().UTC()
	a.mu.Lock()
	defer a.mu.Unlock()
	entry, ok := a.idempotent[key]
	if !ok || !entry.expires.After(now) {
		return nil, false
	}
	return entry.result, true
}

// storeIdempotent 保存幂等结果。
func (a *SecurityPolicyAdapter) storeIdempotent(key string, result any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.idempotent[key] = idempotentEntry{expires: a.now().UTC().Add(previewTokenTTL), result: result}
}

// PreviewPolicy 校验并计算提交前预览，同时签发一次性绑定令牌（不写入）。
func (a *SecurityPolicyAdapter) PreviewPolicy(ctx context.Context, userID, scopeID,
	operationID string, change ui.UISecurityPolicyValues) (ui.UISecurityPolicyPreview, error) {
	caller, err := policyCaller(userID, "")
	if err != nil {
		return ui.UISecurityPolicyPreview{}, securityPolicyErr("ACCESS_DENIED")
	}
	if scopeID == "" {
		scopeID = ui.UISecurityPolicySystemScope
	}
	snapshot, err := a.opts.Policy.Effective(ctx, caller, scopeID)
	if err != nil {
		return ui.UISecurityPolicyPreview{}, policyErr(err)
	}
	operation, found := findOperation(snapshot, operationID)
	if !found {
		return ui.UISecurityPolicyPreview{}, securityPolicyErr("REQ_INVALID")
	}
	normalized, derived := login.NormalizeSecurityPolicyChange(change)
	next := policyFromValues(normalized)
	if definition, ok := a.opts.Policy.Operation(operation.OperationID); ok &&
		definition.ImmutableSensitive && !next.Sensitive {
		return ui.UISecurityPolicyPreview{}, securityPolicyErr("REQ_INVALID")
	}
	if validateErr := policy.ValidatePolicy(next); validateErr != nil {
		return ui.UISecurityPolicyPreview{}, securityPolicyErr("REQ_INVALID")
	}
	available := availableStrengthSet(a.opts.Policy)
	strengthWarning := next.Sensitive && next.ReauthRequired && !available[next.Strength]
	preview := ui.UISecurityPolicyPreview{
		OperationID: operation.OperationID, HasDefault: operation.HasDefault,
		Default: policyValues(operation.Default), Current: policyValues(operation.Effective),
		Proposed: normalized, DerivedFields: derived,
		ChangedFields:   login.SecurityPolicyChangedFields(policyValues(operation.Effective), normalized),
		SelfProtection:  operation.OperationID == policy.OperationPolicyChange,
		StrengthWarning: strengthWarning,
	}
	preview.NoChanges = len(preview.ChangedFields) == 0
	preview.Token = a.issuePreview(ui.UISecurityPolicyActionBinding{
		Action: "policy.save", UserID: userID, ScopeID: scopeID,
		OperationID: operation.OperationID, Version: snapshot.Version,
		ChangeDigest:   valuesDigest(scopeID, operation.OperationID, snapshot.Version, normalized),
		SelfProtection: preview.SelfProtection,
	})
	if preview.Token == "" {
		return ui.UISecurityPolicyPreview{}, securityPolicyErr("INTERNAL_ERROR")
	}
	return preview, nil
}

// fullChange 把页面机器值转为完整六字段修改（不依赖默认值/覆盖作为 base）。
func fullChange(value ui.UISecurityPolicyValues) policy.PolicyChange {
	sensitive := value.Sensitive
	reauth := value.ReauthRequired
	age := value.MaxAuthAgeSeconds
	strength := policy.Strength(value.Strength)
	confirmation := value.ConfirmationRequired
	notification := value.NotificationRequired
	return policy.PolicyChange{
		Sensitive: &sensitive, ReauthRequired: &reauth, MaxAuthAgeSeconds: &age,
		RequiredStrength: &strength, ConfirmationRequired: &confirmation,
		NotificationRequired: &notification,
	}
}

// SavePolicy 校验预览绑定与再次认证后执行真实策略写入。
func (a *SecurityPolicyAdapter) SavePolicy(ctx context.Context, userID, scopeID,
	operationID string, change ui.UISecurityPolicyValues, expectedVersion int64,
	previewToken, requestID string) (ui.UISecurityPolicyWriteResult, error) {
	caller, err := policyCaller(userID, requestID)
	if err != nil {
		return ui.UISecurityPolicyWriteResult{}, securityPolicyErr("ACCESS_DENIED")
	}
	if scopeID == "" {
		scopeID = ui.UISecurityPolicySystemScope
	}
	before, err := a.opts.Policy.Effective(ctx, caller, scopeID)
	if err != nil {
		return ui.UISecurityPolicyWriteResult{}, policyErr(err)
	}
	normalized, _ := login.NormalizeSecurityPolicyChange(change)
	binding := ui.UISecurityPolicyActionBinding{
		Action: "policy.save", UserID: userID, ScopeID: scopeID,
		OperationID: operationID, Version: expectedVersion,
		ChangeDigest:   valuesDigest(scopeID, operationID, expectedVersion, normalized),
		SelfProtection: operationID == policy.OperationPolicyChange,
	}
	if err := a.consumePreview(previewToken, userID, binding); err != nil {
		return ui.UISecurityPolicyWriteResult{}, err
	}
	if err := a.verifyReauth(ctx, userID, binding); err != nil {
		return ui.UISecurityPolicyWriteResult{}, err
	}
	after, err := a.opts.Policy.Set(ctx, caller, policy.SetRequest{
		ScopeID: scopeID, OperationID: operationID, Change: fullChange(normalized),
		ExpectedVersion: expectedVersion, RequestID: requestID,
	})
	if err != nil {
		return ui.UISecurityPolicyWriteResult{}, policyErr(err)
	}
	return ui.UISecurityPolicyWriteResult{
		Snapshot: a.snapshotView(after), Changed: after.Version != before.Version,
		NotificationStatus: "unknown",
	}, nil
}

// restoreBinding 由当前真实覆盖快照计算恢复绑定（含清单摘要）。
func (a *SecurityPolicyAdapter) restoreBinding(userID, scopeID, operationID string,
	all bool, snapshot policy.Snapshot) ui.UISecurityPolicyActionBinding {
	operations := []string{}
	selfProtection := false
	for _, operation := range snapshot.Operations {
		if operation.Source != policy.SourceOverride {
			continue
		}
		if !all && operation.OperationID != operationID {
			continue
		}
		operations = append(operations, operation.OperationID)
		if operation.OperationID == policy.OperationPolicyChange {
			selfProtection = true
		}
	}
	sortStrings(operations)
	return ui.UISecurityPolicyActionBinding{
		Action: "policy.restore", UserID: userID, ScopeID: scopeID,
		OperationID: operationID, Version: snapshot.Version, All: all,
		AffectedOperations: operations, AffectedCount: len(operations),
		SelfProtection: selfProtection,
		ChangeDigest: digestStrings(append([]string{"policy.restore", scopeID,
			fmt.Sprintf("%d", snapshot.Version), fmt.Sprintf("%t", all)}, operations...)...),
	}
}

// sortStrings 对字符串切片排序（不引入额外依赖）。
func sortStrings(values []string) {
	for index := 1; index < len(values); index++ {
		for back := index; back > 0 && values[back] < values[back-1]; back-- {
			values[back], values[back-1] = values[back-1], values[back]
		}
	}
}

// PreviewRestore 计算逐项/整体恢复默认的提交前预览并签发一次性令牌。
func (a *SecurityPolicyAdapter) PreviewRestore(ctx context.Context, userID, scopeID,
	operationID string, all bool) (ui.UISecurityPolicyRestorePreview, error) {
	caller, err := policyCaller(userID, "")
	if err != nil {
		return ui.UISecurityPolicyRestorePreview{}, securityPolicyErr("ACCESS_DENIED")
	}
	if scopeID == "" {
		scopeID = ui.UISecurityPolicySystemScope
	}
	snapshot, err := a.opts.Policy.Effective(ctx, caller, scopeID)
	if err != nil {
		return ui.UISecurityPolicyRestorePreview{}, policyErr(err)
	}
	view := a.snapshotView(snapshot)
	preview := ui.UISecurityPolicyRestorePreview{
		ScopeID: view.ScopeID, ScopeName: view.ScopeName, Version: view.Version,
		All: all, OperationID: operationID, Declared: view.Declared,
	}
	if !all {
		operation, found := findOperation(snapshot, operationID)
		if !found {
			return ui.UISecurityPolicyRestorePreview{}, securityPolicyErr("REQ_INVALID")
		}
		if !operation.HasDefault {
			return ui.UISecurityPolicyRestorePreview{}, securityPolicyErr("REQ_INVALID")
		}
	}
	binding := a.restoreBinding(userID, scopeID, operationID, all, snapshot)
	for _, operation := range view.Operations {
		if operation.Source != string(policy.SourceOverride) {
			continue
		}
		if !all && operation.OperationID != operationID {
			continue
		}
		preview.Operations = append(preview.Operations, operation)
	}
	preview.SelfProtection = binding.SelfProtection
	preview.NoChanges = len(preview.Operations) == 0
	preview.Token = a.issuePreview(binding)
	if preview.Token == "" {
		return ui.UISecurityPolicyRestorePreview{}, securityPolicyErr("INTERNAL_ERROR")
	}
	return preview, nil
}

// RestorePolicy 校验预览绑定与再次认证后执行真实恢复默认。
func (a *SecurityPolicyAdapter) RestorePolicy(ctx context.Context, userID, scopeID,
	operationID string, all bool, expectedVersion int64, previewToken,
	requestID string) (ui.UISecurityPolicyWriteResult, error) {
	caller, err := policyCaller(userID, requestID)
	if err != nil {
		return ui.UISecurityPolicyWriteResult{}, securityPolicyErr("ACCESS_DENIED")
	}
	if scopeID == "" {
		scopeID = ui.UISecurityPolicySystemScope
	}
	before, err := a.opts.Policy.Effective(ctx, caller, scopeID)
	if err != nil {
		return ui.UISecurityPolicyWriteResult{}, policyErr(err)
	}
	binding := a.restoreBinding(userID, scopeID, operationID, all, before)
	binding.Version = expectedVersion
	binding.ChangeDigest = digestStrings(append([]string{"policy.restore", scopeID,
		fmt.Sprintf("%d", expectedVersion), fmt.Sprintf("%t", all)},
		binding.AffectedOperations...)...)
	if err := a.consumePreview(previewToken, userID, binding); err != nil {
		return ui.UISecurityPolicyWriteResult{}, err
	}
	if err := a.verifyReauth(ctx, userID, binding); err != nil {
		return ui.UISecurityPolicyWriteResult{}, err
	}
	after, err := a.opts.Policy.Restore(ctx, caller, policy.RestoreRequest{
		ScopeID: scopeID, OperationID: operationID, All: all,
		ExpectedVersion: expectedVersion, RequestID: requestID,
	})
	if err != nil {
		return ui.UISecurityPolicyWriteResult{}, policyErr(err)
	}
	return ui.UISecurityPolicyWriteResult{
		Snapshot: a.snapshotView(after), Changed: after.Version != before.Version,
		NotificationStatus: "unknown",
	}, nil
}

// ===== 安全通知设置 =====

// NotificationSettings 返回安全通知设置页的真实只读事实。
func (a *SecurityPolicyAdapter) NotificationSettings(ctx context.Context,
	userID string) (ui.UINotificationSettings, error) {
	caps, err := a.Capabilities(ctx, userID)
	if err != nil {
		return ui.UINotificationSettings{}, err
	}
	if !caps.ReadNotifications {
		return ui.UINotificationSettings{}, securityPolicyErr("ACCESS_DENIED")
	}
	settings := ui.UINotificationSettings{
		Capabilities: ui.UINotificationCapabilities{
			Read: true, TestMail: caps.TestMail, ReplaceSecret: caps.ReplaceSecret,
		},
	}
	if notificationsRequired, countErr := a.notificationRequiredOperations(ctx, userID); countErr == nil {
		settings.NotificationRequiredOperations = notificationsRequired
		settings.NotificationRequiredKnown = true
	}
	if a.opts.Mail == nil {
		settings.SettingsUnavailableReason = "runtime_mail_not_wired"
		return settings, nil
	}
	mail := a.opts.Mail
	settings.From = maskNotificationAddress(mail.FromAddress)
	settings.SMTPAddr = mail.SMTPAddr
	settings.SMTPHost = mail.SMTPHost
	settings.TLSMode = mail.TLSMode
	settings.SMTPTimeoutSeconds = mail.SMTPTimeoutSeconds
	settings.MaxAttempts = mail.MaxAttempts
	settings.DeliveryTimeoutSeconds = mail.DeliveryTimeoutSeconds
	settings.AllowPlaintextLocal = mail.AllowPlaintextLocal
	settings.TrustedRootsConfigured = mail.TrustedRootsConfigured
	settings.SenderConfigured = mail.Sender != nil
	settings.SecretStatusKnown = mail.SecretStatusKnown
	a.mu.Lock()
	settings.SecretConfigured = a.secret
	a.mu.Unlock()
	if mail.Templates != nil {
		settings.TemplatesConfigured = true
		settings.TemplateSource = strings.TrimSpace(mail.TemplateSource)
		if settings.TemplateSource == "" {
			settings.TemplateSource = "builtin"
		}
		templates := mail.Templates.Templates()
		for _, kind := range []mailer.Kind{mailer.KindVerification,
			mailer.KindPasswordReset, mailer.KindSecurityNotice} {
			tmpl, ok := templates[kind]
			if !ok {
				continue
			}
			settings.Templates = append(settings.Templates, ui.UINotificationTemplate{
				Kind: string(kind), Subject: tmpl.Subject, Body: tmpl.Body,
				Source: settings.TemplateSource, Editable: false,
			})
		}
	}
	settings.TemplateEditingAvailable = false
	settings.SettingsEditingAvailable = false
	if mail.Notifications != nil {
		a.loadNotices(ctx, userID, &settings)
	}
	return settings, nil
}

// notificationRequiredOperations 统计当前成功后要求告知的敏感操作数（只读事实）。
func (a *SecurityPolicyAdapter) notificationRequiredOperations(ctx context.Context,
	userID string) (int, error) {
	caller, err := policyCaller(userID, "")
	if err != nil {
		return 0, err
	}
	snapshot, err := a.opts.Policy.Effective(ctx, caller, ui.UISecurityPolicySystemScope)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, operation := range snapshot.Operations {
		if operation.Effective.Sensitive && operation.Effective.NotificationRequired {
			count++
		}
	}
	return count, nil
}

// loadNotices 读取当前操作者本人最近的安全告知记录。
func (a *SecurityPolicyAdapter) loadNotices(ctx context.Context, userID string,
	settings *ui.UINotificationSettings) {
	caller, err := reauth.UserCaller(userID)
	if err != nil {
		return
	}
	records, err := a.opts.Mail.Notifications.Notifications(ctx, caller, userID, 10)
	if err != nil {
		settings.NoticesAvailable = false
		return
	}
	settings.NoticesAvailable = true
	for _, record := range records {
		settings.Notices = append(settings.Notices, ui.UINotificationNotice{
			OperationID: record.OperationID, Outcome: string(record.Outcome),
			State: notificationNoticeState(record), ErrorCode: notificationNoticeErrorCode(record),
			RecipientMasked: record.RecipientMasked, CreatedAt: record.CreatedAt,
		})
	}
}

// notificationNoticeState 把告知主记录 + 关联投递记录的当前状态映射为页面状态：
// 排队/投递中/发送后端已接受/失败/取消。页面模板按页面状态拼 i18n 键，因此这里只
// 返回稳定枚举值。
//
// 口径（安全边界）：
//   - mailer.DeliverySucceeded 只表示“发送后端已接受邮件”，映射为 smtp_accepted，
//     绝不映射为 sent/已读/已送达；最终邮箱送达与用户已读无法由本服务保证。
//   - 主记录 state=queued 但当前关联不到投递记录（历史数据、关联回写尚未完成、
//     投递记录缺失）时映射为 unknown，不能把不确定状态显示为成功。
//   - 未走可靠队列的直接发送回退路径没有投递状态，沿用主记录 sent/failed 等状态。
func notificationNoticeState(record reauth.NotificationRecord) string {
	switch record.DeliveryState {
	case mailer.DeliveryQueued:
		return "queued"
	case mailer.DeliverySending:
		return "sending"
	case mailer.DeliverySucceeded:
		return "smtp_accepted"
	case mailer.DeliveryFailed:
		return "failed"
	case mailer.DeliveryCancelled:
		return "cancelled"
	}
	if record.State == reauth.NotificationQueued {
		return "unknown"
	}
	return string(record.State)
}

// notificationNoticeErrorCode 优先展示投递记录的失败错误码（如 SMTP 拒绝/重试耗尽），
// 其次是告知主记录的原因码；都不存在时为空。
func notificationNoticeErrorCode(record reauth.NotificationRecord) string {
	if record.DeliveryState == mailer.DeliveryFailed && record.DeliveryErrorCode != "" {
		return record.DeliveryErrorCode
	}
	return record.ErrorCode
}

// PreviewTemplate 使用合成数据渲染模板（不保存、不发送）。
func (a *SecurityPolicyAdapter) PreviewTemplate(ctx context.Context, userID,
	kind string) (ui.UINotificationTemplatePreview, error) {
	caps, err := a.Capabilities(ctx, userID)
	if err != nil {
		return ui.UINotificationTemplatePreview{}, err
	}
	if !caps.ReadNotifications {
		return ui.UINotificationTemplatePreview{}, securityPolicyErr("ACCESS_DENIED")
	}
	templateKind := mailer.Kind(kind)
	if !templateKind.Valid() {
		return ui.UINotificationTemplatePreview{}, securityPolicyErr("REQ_INVALID")
	}
	preview := ui.UINotificationTemplatePreview{Kind: kind}
	if a.opts.Mail == nil || a.opts.Mail.Templates == nil {
		preview.ErrorCode = "MAIL_NOT_CONFIGURED"
		return preview, nil
	}
	content, err := a.opts.Mail.Templates.Render(syntheticRenderRequest(templateKind))
	if err != nil {
		preview.ErrorCode = mailer.CodeOf(err)
		if preview.ErrorCode == "" {
			preview.ErrorCode = "MAIL_INVALID_MESSAGE"
		}
		return preview, nil
	}
	preview.Valid = true
	preview.Subject = content.Subject
	preview.TextBody = content.TextBody
	return preview, nil
}

// syntheticRenderRequest 构造明确标注合成的模板数据。
func syntheticRenderRequest(kind mailer.Kind) mailer.RenderRequest {
	request := mailer.RenderRequest{Kind: kind}
	switch kind {
	case mailer.KindVerification:
		request.Verification = &mailer.VerificationData{
			DisplayName: "测试收件人", Code: "000000", ExpiresIn: "10 分钟",
			AppName: "EvernightLogin 测试",
		}
	case mailer.KindPasswordReset:
		request.PasswordReset = &mailer.PasswordResetData{
			DisplayName: "测试收件人",
			ResetURL:    "https://example.invalid/reset#test-only",
			ExpiresIn:   "10 分钟", AppName: "EvernightLogin 测试",
		}
	case mailer.KindSecurityNotice:
		request.Notice = &mailer.SecurityNoticeData{
			DisplayName: "测试收件人", Event: "测试安全告知（合成数据）",
			OccurredAt: "2026-01-01 00:00:00 UTC", ClientInfo: "本地收件器测试",
			AppName: "EvernightLogin 测试", SupportURL: "https://example.invalid/support",
		}
	}
	return request
}

// testMailWindow/testMailLimit 是单实例测试发送频率窗口（多实例未实现）。
const (
	testMailWindow = time.Minute
	testMailLimit  = 3
)

// allowTestSend 记录并判定单实例测试发送频率。
func (a *SecurityPolicyAdapter) allowTestSend(userID string, now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	cutoff := now.Add(-testMailWindow)
	kept := make([]time.Time, 0, len(a.testSends[userID]))
	for _, sentAt := range a.testSends[userID] {
		if sentAt.After(cutoff) {
			kept = append(kept, sentAt)
		}
	}
	if len(kept) >= testMailLimit {
		a.testSends[userID] = kept
		return false
	}
	a.testSends[userID] = append(kept, now)
	return true
}

// SendTestMail 向用户明确指定的目标发送一封合成测试邮件。
func (a *SecurityPolicyAdapter) SendTestMail(ctx context.Context, userID, recipient, kind,
	idempotencyKeyValue, requestID string) (ui.UINotificationTestResult, error) {
	caps, err := a.Capabilities(ctx, userID)
	if err != nil {
		return ui.UINotificationTestResult{}, err
	}
	if !caps.TestMail {
		return ui.UINotificationTestResult{}, securityPolicyErr("ACCESS_DENIED")
	}
	templateKind := mailer.Kind(kind)
	if !templateKind.Valid() {
		return ui.UINotificationTestResult{}, securityPolicyErr("REQ_INVALID")
	}
	target, err := mailer.ParseAddress(recipient)
	if err != nil {
		return ui.UINotificationTestResult{}, securityPolicyErr("MAIL_ADDRESS_REJECTED")
	}
	key := idempotencyKey("mail.test", userID, idempotencyKeyValue, requestID)
	if stored, ok := a.lookupIdempotent(key); ok {
		result, _ := stored.(ui.UINotificationTestResult)
		result.Duplicate = true
		return result, nil
	}
	binding := ui.UISecurityPolicyActionBinding{
		Action: "mail.test", UserID: userID, Kind: kind,
		RecipientDigest: digestStrings("recipient", strings.ToLower(target.Spec)),
	}
	if err := a.verifyReauth(ctx, userID, binding); err != nil {
		_ = a.recordAudit(ctx, userID, "notification.mail.test", string(audit.OutcomeDenied),
			"REAUTH_REQUIRED", requestID)
		return ui.UINotificationTestResult{}, err
	}
	result := ui.UINotificationTestResult{
		Status: "failed", Kind: kind, RecipientMasked: maskNotificationAddress(target.Spec),
		AttemptedAt: a.now().UTC(),
	}
	mail := a.opts.Mail
	if mail == nil || mail.Sender == nil || mail.Templates == nil {
		result.Status = "not_configured"
		if auditErr := a.recordAudit(ctx, userID, "notification.mail.test",
			string(audit.OutcomeFailure), "MAIL_NOT_CONFIGURED", requestID); auditErr != nil {
			return ui.UINotificationTestResult{}, auditErr
		}
		a.storeIdempotent(key, result)
		return result, nil
	}
	from, fromErr := mailer.ParseAddress(mail.FromAddress)
	if fromErr != nil {
		result.Status = "not_configured"
		if auditErr := a.recordAudit(ctx, userID, "notification.mail.test",
			string(audit.OutcomeFailure), "MAIL_NOT_CONFIGURED", requestID); auditErr != nil {
			return ui.UINotificationTestResult{}, auditErr
		}
		a.storeIdempotent(key, result)
		return result, nil
	}
	if !a.allowTestSend(userID, a.now()) {
		_ = a.recordAudit(ctx, userID, "notification.mail.test", string(audit.OutcomeDenied),
			"RATE_LIMITED", requestID)
		return ui.UINotificationTestResult{}, &ui.UISecurityPolicyError{
			Code: "RATE_LIMITED", RetryAfterSeconds: int(testMailWindow / time.Second),
		}
	}
	content, renderErr := mail.Templates.Render(syntheticRenderRequest(templateKind))
	if renderErr != nil {
		result.ErrorCode = mailer.CodeOf(renderErr)
		if result.ErrorCode == "" {
			result.ErrorCode = "MAIL_INVALID_MESSAGE"
		}
		if auditErr := a.recordAudit(ctx, userID, "notification.mail.test",
			string(audit.OutcomeFailure), result.ErrorCode, requestID); auditErr != nil {
			return ui.UINotificationTestResult{}, auditErr
		}
		a.storeIdempotent(key, result)
		return result, nil
	}
	message := mailer.Message{From: from, To: []mailer.Address{target},
		Subject: content.Subject, TextBody: content.TextBody,
		Headers: []mailer.Header{{Name: "X-Request-ID", Value: requestID}}}
	sendCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if sendErr := mail.Sender.Send(sendCtx, message); sendErr != nil {
		result.ErrorCode = mailer.CodeOf(sendErr)
		if result.ErrorCode == "" {
			result.ErrorCode = "MAIL_SEND_UNAVAILABLE"
		}
		if auditErr := a.recordAudit(ctx, userID, "notification.mail.test",
			string(audit.OutcomeFailure), result.ErrorCode, requestID); auditErr != nil {
			return ui.UINotificationTestResult{}, auditErr
		}
		a.storeIdempotent(key, result)
		return result, nil
	}
	result.Status = "accepted"
	if auditErr := a.recordAudit(ctx, userID, "notification.mail.test",
		string(audit.OutcomeSuccess), "", requestID); auditErr != nil {
		return ui.UINotificationTestResult{}, auditErr
	}
	a.storeIdempotent(key, result)
	return result, nil
}

// ReplaceSMTPSecret 校验绑定/再次认证/审计后调用宿主真实替换契约；不回显秘密。
func (a *SecurityPolicyAdapter) ReplaceSMTPSecret(ctx context.Context, userID, newSecret,
	idempotencyKeyValue, requestID string) (ui.UINotificationSecretResult, error) {
	caps, err := a.Capabilities(ctx, userID)
	if err != nil {
		return ui.UINotificationSecretResult{}, err
	}
	if !caps.ReplaceSecret {
		return ui.UINotificationSecretResult{}, securityPolicyErr("ACCESS_DENIED")
	}
	if strings.TrimSpace(newSecret) == "" {
		return ui.UINotificationSecretResult{}, securityPolicyErr("REQ_INVALID")
	}
	key := idempotencyKey("mail.secret.replace", userID, idempotencyKeyValue, requestID)
	if stored, ok := a.lookupIdempotent(key); ok {
		result, _ := stored.(ui.UINotificationSecretResult)
		result.Duplicate = true
		return result, nil
	}
	binding := ui.UISecurityPolicyActionBinding{
		Action: "mail.secret.replace", UserID: userID,
		ChangeDigest: digestStrings("secret.replace", newSecret),
	}
	if err := a.verifyReauth(ctx, userID, binding); err != nil {
		_ = a.recordAudit(ctx, userID, "notification.mail.secret.replace",
			string(audit.OutcomeDenied), "REAUTH_REQUIRED", requestID)
		return ui.UINotificationSecretResult{}, err
	}
	if err := a.opts.Mail.ReplaceSecret(ctx, userID, newSecret, requestID); err != nil {
		var publicErr *ui.UISecurityPolicyError
		if errors.As(err, &publicErr) {
			_ = a.recordAudit(ctx, userID, "notification.mail.secret.replace",
				string(audit.OutcomeFailure), publicErr.Code, requestID)
			return ui.UINotificationSecretResult{}, publicErr
		}
		_ = a.recordAudit(ctx, userID, "notification.mail.secret.replace",
			string(audit.OutcomeFailure), "INTERNAL_ERROR", requestID)
		return ui.UINotificationSecretResult{}, securityPolicyErr("INTERNAL_ERROR")
	}
	if auditErr := a.recordAudit(ctx, userID, "notification.mail.secret.replace",
		string(audit.OutcomeSuccess), "", requestID); auditErr != nil {
		return ui.UINotificationSecretResult{}, auditErr
	}
	a.mu.Lock()
	a.secret = true
	a.mu.Unlock()
	result := ui.UINotificationSecretResult{Replaced: true, SecretConfigured: true}
	a.storeIdempotent(key, result)
	return result, nil
}

// maskNotificationAddress 脱敏邮件地址：只保留首字符与域名。
func maskNotificationAddress(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	at := strings.LastIndexByte(trimmed, '@')
	if at <= 1 || at == len(trimmed)-1 {
		return "***"
	}
	return string(trimmed[0]) + "***" + trimmed[at:]
}
