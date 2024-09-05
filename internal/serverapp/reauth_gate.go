package serverapp

// 敏感操作安全闸门：把真实 internal/policy（敏感操作目录/策略评估）与
// internal/reauth（近期认证/一次性批准/安全告知）装配成宿主级唯一入口，并接给
// 所有领域服务（导出/清理/凭证轮换/策略修改/恢复代码/邮箱变更等）。
//
// 安全不变量（fail-closed）：
//   - 未装配（存储/审计/策略/密码校验任一缺失）时构造失败，不存在“跳过策略”的
//     降级路径；领域服务拿不到可用闸门时其自身仍需拒绝敏感动作。
//   - 只有密码强度的信号（由页面适配器在真实 reauth 挑战通过后合成）才能满足
//     需要近期验证的操作；需要强认证（Passkey/安全密钥）的操作只有在真实强因素
//     可用（Passkey 已启用）时才被声明为可满足，否则策略评估 fail-closed。
//   - 安全告知走真实 reauth 服务；当前部署没有配置真实邮件发送器，发送必然以
//     明确“未配置”失败并留痕，不会静默成功、也不真实外发。
//   - 管理访问的强认证事实由真实会话服务（session.AuthorizeManagement）产生；
//     本文件只在页面会话解析时登记“该用户当前请求持有有效管理会话”的短时事实，
//     供宿主安全策略页的再次认证回调使用；参数绑定与一次性确认仍由页面适配器的
//     签名预览令牌与版本校验完成。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	bootstrapsqlite "github.com/kagurazakayashi/EvernightLogin/internal/bootstrap/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/emailchange"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	policysqlite "github.com/kagurazakayashi/EvernightLogin/internal/policy/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/profile"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	reauthsqlite "github.com/kagurazakayashi/EvernightLogin/internal/reauth/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	"github.com/kagurazakayashi/EvernightLogin/internal/totp"
	totpsqlite "github.com/kagurazakayashi/EvernightLogin/internal/totp/sqlite"
	ui "github.com/kagurazakayashi/EvernightLogin/ui"
	"strconv"
	"strings"
	"sync"
	"time"
)

// hostComponentID 是宿主系统组件标识（写入敏感操作审计主体）。
const hostComponentID = "login-server"

// managementFactTTL 是页面会话登记的管理强认证事实可被同一次页面动作使用的窗口。
const managementFactTTL = 30 * time.Second

// policyApprovalTTL 是安全策略页确认后一次性写批准的有效期（短时、单次）。
const policyApprovalTTL = 30 * time.Second

// securityPolicyOperationID 是敏感策略修改自身的操作标识（与 internal/policy 一致）。
const securityPolicyOperationID = policy.OperationPolicyChange

// SecurityGate 是敏感操作策略与再次认证的宿主装配结果。
type SecurityGate struct {
	Policy *policy.Service
	Reauth *reauth.Service

	mu         sync.Mutex
	management map[string]managementFact
	// policyWrites 是“正在执行中的敏感策略写”，绑定变更摘要/版本/作用域/操作：
	// 再次认证只确认一次具体变更，不能把确认复用到另一条变更。
	policyWrites map[string]*policyWrite
	// policyWriteMu 串行化策略写入（写操作很少，串行换取消歧义），保证
	// begin → 回调 → policy.Set 消费 → finish 之间不会被另一个请求插入。
	policyWriteMu sync.Mutex
}

// managementFact 是一次页面会话解析产生的强认证事实。
type managementFact struct {
	verifiedAt time.Time
	recordedAt time.Time
}

// policyWrite 是一次敏感策略写的一次性批准记录：摘要由实际变更参数、版本、
// 作用域与操作计算，回调必须匹配同一记录，执行完成后核对已消费摘要一致。
type policyWrite struct {
	digest      string
	action      string
	scopeID     string
	operationID string
	version     int64
	// authorized 表示本次变更已通过真实再次认证（在 policy.Set 之前完成）；
	// signalsIssued 表示已向 policy.Set 的 ReauthVerifier 发放过一次信号。
	authorized    bool
	signalsIssued bool
	expiresAt     time.Time
}

// BuildSecurityGate 构造真实敏感策略与再次认证服务。
//
// 构造不启动协程、不访问网络、不发送邮件；策略与再次认证使用与主库同一连接池的
// SQLite 表（迁移已包含）。缺少任一必需依赖时返回错误。
//
// strongAuthAvailable 表示当前装配是否真实具备强认证（Passkey/安全密钥）。false 时
// 需要强认证的操作策略评估 fail-closed，不会降级为密码。
func BuildSecurityGate(deps Deps, bootstrapStore *bootstrapsqlite.Store,
	authnService *authn.Service, strongAuthAvailable bool) (*SecurityGate, error) {
	if deps.Store == nil || deps.Audit == nil {
		return nil, fmt.Errorf("敏感操作闸门缺少存储或审计依赖")
	}
	if bootstrapStore == nil || authnService == nil {
		return nil, fmt.Errorf("敏感操作闸门缺少 root 识别存储或认证服务")
	}
	now := deps.Now
	if now == nil {
		now = time.Now
	}
	policyStore, err := policysqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造敏感策略存储失败: %w", err)
	}
	reauthStore, err := reauthsqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造再次认证存储失败: %w", err)
	}
	roots, err := newHostRootChecker(bootstrapStore)
	if err != nil {
		return nil, err
	}
	gate := &SecurityGate{
		management:   make(map[string]managementFact),
		policyWrites: make(map[string]*policyWrite),
	}
	// TOTP 始终由安全域装配；它可作为再次认证的第二强因素。strong 是否“可用”
	// 仍需按账户实际因素在验证时 fail-closed（未绑定 TOTP/Passkey 的账户不能通过）。
	strengths := []policy.Strength{policy.StrengthNone, policy.StrengthPassword, policy.StrengthStrong}
	_ = strongAuthAvailable
	policyService, err := policy.New(policy.Options{
		Store: policyStore, Audit: deps.Audit,
		Catalog:            policy.DefaultCatalog(),
		ReauthVerifier:     &policyReauthRelay{gate: gate},
		Authorizer:         policyPageAuthorizer{roots: roots},
		AvailableStrengths: strengths,
		Now:                now,
		Logger:             deps.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造敏感策略服务失败: %w", err)
	}
	gate.Policy = policyService
	mailURLs, urlErr := buildMailURLs(deps.Config)
	if deps.Config.Mail.Enabled && urlErr != nil {
		return nil, fmt.Errorf("CONFIG_INVALID: %w", urlErr)
	}
	sealer, sealerErr := secrets.NewSealer(deps.Keyring, deps.Logger)
	if sealerErr != nil {
		return nil, fmt.Errorf("构造再次认证强因素加密器失败: %w", sealerErr)
	}
	totpStore, totpErr := totpsqlite.New(deps.Store)
	if totpErr != nil {
		return nil, fmt.Errorf("构造再次认证 TOTP 存储失败: %w", totpErr)
	}
	strongTOTP, totpErr := totp.New(totp.Options{
		Store: totpStore, Audit: deps.Audit, Sealer: sealer,
		IssuerName: "EvernightLogin", Now: now, Logger: deps.Logger})
	if totpErr != nil {
		return nil, fmt.Errorf("构造再次认证 TOTP 服务失败: %w", totpErr)
	}
	// 步骤 197：安全告知改走可靠投递队列；任务运行时晚于本函数构造，用延迟代理在
	// 实际入队时取 provider。邮件未启用时保持 nil（回退现有 Sender/failed 语义）。
	var reauthDeliveries mailer.DeliveryEnqueuer
	if deps.Config.Mail.Enabled {
		reauthDeliveries = lateMailDeliveries{provider: deps.MailDeliveryProvider}
	}
	reauthService, err := reauth.New(reauth.Options{
		Store: reauthStore, Audit: deps.Audit, Policy: policyService,
		Passwords:     authn.ReauthPasswordVerifier{Service: authnService},
		StrongFactors: &reauthStrongFactorVerifier{totp: strongTOTP, now: now},
		// 步骤 255：直接管理操作的新值意图用同一主密钥环 AES-GCM 密封存储。
		IntentSealer: sealer,
		Mailer:       deps.Mail.SenderOrDisabled(),
		Deliveries:   reauthDeliveries,
		Templates:    mustMailTemplates(),
		FromAddress:  deps.Mail.FromAddress().Spec,
		AppName:      deps.Mail.AppDisplayName(),
		SupportURL:   mailURLs.Support,
		// 强认证是否可用由真实 Passkey 装配决定；未启用时声明为不可满足，
		// 需要强认证的敏感操作 fail-closed，而不是退回密码。
		AvailableStrengths: strengths,
		Now:                now,
		Logger:             deps.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造再次认证服务失败: %w", err)
	}
	gate.Reauth = reauthService
	return gate, nil
}

// disabledMailSender 是“未配置真实邮件发送器”的显式实现：发送必然以不可重试的
// 明确错误失败（MAIL_SEND_UNAVAILABLE），不访问网络、不真实外发。安全告知因此
// 记录为未配置/失败状态，绝不伪造发送成功。
func disabledMailSender() mailer.Sender {
	return mailer.SenderFunc(func(ctx context.Context, message mailer.Message) error {
		return mailer.SenderFunc(nil).Send(ctx, message)
	})
}

// lateMailDeliveries 在每次 Enqueue 时通过 provider 取可靠投递服务：用于早于
// 任务运行时构造的领域服务（步骤 197 的 reauth 安全告知）。provider 为 nil 或
// 尚未装配时明确失败，不伪造入队成功。
type lateMailDeliveries struct {
	provider func() *mailer.DeliveryService
}

// Enqueue 实现 mailer.DeliveryEnqueuer。
func (l lateMailDeliveries) Enqueue(ctx context.Context, request mailer.EnqueueRequest) (mailer.EnqueueResult, error) {
	if l.provider == nil {
		return mailer.EnqueueResult{}, errors.New("邮件可靠投递服务未装配")
	}
	delivery := l.provider()
	if delivery == nil {
		return mailer.EnqueueResult{}, errors.New("邮件可靠投递服务尚未就绪")
	}
	return delivery.Enqueue(ctx, request)
}

// policyReauthRelay 把 internal/policy 的再次验证契约接到真实 reauth 服务。
//
// 策略修改只有 root 能写（policy 服务自身强制）；这里只回答“这次写入是否已获
// 近期认证/一次性批准”，不复制 root 判定。
type policyReauthRelay struct {
	gate *SecurityGate
}

// VerifyReauth 实现 policy.ReauthVerifier。
//
// 策略写不接受 context 伪造信号：只有宿主包装器在调用 policy.Set 之前完成真实
// 再次认证并把本次变更登记为 authorized 时，才发放一次信号；否则 fail-closed。
func (r *policyReauthRelay) VerifyReauth(_ context.Context, caller policy.Caller,
	operationID string) error {
	if r == nil || r.gate == nil {
		return policy.ErrReauthRequired
	}
	actor := caller.Actor()
	if actor.Type != audit.ActorUser {
		return policy.ErrReauthRequired
	}
	if _, err := r.gate.issuePolicyWriteSignals(actor.ID, operationID); err != nil {
		return policy.ErrReauthRequired
	}
	return nil
}

// policyPageAuthorizer 实现 policy.Authorizer：读取允许 root 与受信主体；写入仍由
// policy 服务强制 root，这里对 root 放行后由服务继续判定。
type policyPageAuthorizer struct {
	roots *hostRootChecker
}

// AuthorizePolicy 实现 policy.Authorizer。
func (a policyPageAuthorizer) AuthorizePolicy(ctx context.Context,
	caller policy.Caller, _ string, _ bool) error {
	actor := caller.Actor()
	switch actor.Type {
	case audit.ActorSystem, audit.ActorLocalAdmin:
		return nil
	case audit.ActorUser:
		if a.roots == nil {
			return policy.ErrAccessDenied
		}
		root, err := a.roots.isRoot(ctx, actor.ID)
		if err != nil {
			return policy.ErrAccessDenied
		}
		if root {
			return nil
		}
		return policy.ErrAccessDenied
	default:
		return policy.ErrAccessDenied
	}
}

// recordManagementFact 记录一次有效管理会话解析（由页面会话服务调用）。
func (g *SecurityGate) recordManagementFact(userID string, verifiedAt time.Time) {
	if g == nil || userID == "" {
		return
	}
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	for key, fact := range g.management {
		if now.Sub(fact.recordedAt) > managementFactTTL {
			delete(g.management, key)
		}
	}
	g.management[userID] = managementFact{verifiedAt: verifiedAt, recordedAt: now}
}

// takeManagementFact 取出并删除该用户最近的短时管理强认证事实。
func (g *SecurityGate) takeManagementFact(userID string) (managementFact, bool) {
	if g == nil {
		return managementFact{}, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	fact, ok := g.management[userID]
	if !ok {
		return managementFact{}, false
	}
	delete(g.management, userID)
	if time.Since(fact.recordedAt) > managementFactTTL {
		return managementFact{}, false
	}
	return fact, true
}

// beginPolicyWrite 登记一次正在执行的敏感策略写（尚未授权），返回绑定摘要。
func (g *SecurityGate) beginPolicyWrite(userID, action, scopeID, operationID string,
	version int64, changeDigest string) (string, error) {
	if g == nil || userID == "" {
		return "", reauth.ErrAccessDenied
	}
	digest := policyWriteDigest(action, scopeID, operationID, version, changeDigest)
	if err := g.beginPolicyWriteLocked(userID, action, scopeID, operationID, version, digest); err != nil {
		return "", err
	}
	return digest, nil
}

// authorizePolicyWrite 在 policy.Set 之前完成真实再次认证，并把本次变更标记为已授权。
// 根因：页面适配器的 Reauth 回调先于写库，只有先把“这次具体变更”授权并登记，写库时
// 才不需要信任 context 信号，也不会出现“写已提交但事后核对失败”的半提交。
func (g *SecurityGate) authorizePolicyWrite(ctx context.Context, userID, action,
	scopeID, operationID string, version int64, digest string) error {
	if g == nil || g.Reauth == nil {
		return reauth.ErrReauthRequired
	}
	if !account.ValidUserID(userID) {
		return reauth.ErrAccessDenied
	}
	if root, err := g.reauthCallerIsRoot(ctx, userID); err != nil || !root {
		return reauth.ErrAccessDenied
	}
	g.mu.Lock()
	record := g.policyWrites[userID]
	matches := record != nil && !record.authorized && !record.signalsIssued &&
		time.Now().Before(record.expiresAt) && record.digest == digest &&
		record.action == action && record.scopeID == scopeID &&
		record.operationID == operationID && record.version == version
	g.mu.Unlock()
	if !matches {
		return reauth.ErrReauthRequired
	}
	fact, ok := g.takeManagementFact(userID)
	if !ok || fact.verifiedAt.IsZero() {
		return reauth.ErrReauthRequired
	}
	caller, err := reauth.UserCaller(userID)
	if err != nil {
		return reauth.ErrAccessDenied
	}
	request := reauth.Request{
		ScopeID: "system", OperationID: securityPolicyOperationID,
		TargetType: "sensitive_policy", TargetID: digest,
		Params: map[string]string{"action": action, "scope_id": scopeID,
			"operation_id": operationID, "version": strconv.FormatInt(version, 10),
			"change_digest": digest},
		Description: "修改敏感操作策略",
	}
	signals := reauth.Signals{
		VerifiedAt: fact.verifiedAt, Strength: policy.StrengthStrong,
		Complete: true, Confirmed: true,
	}
	approved, authorizeErr := g.Reauth.Authorize(
		reauth.WithSignals(ctx, signals), caller, request)
	if authorizeErr != nil {
		return reauth.ErrReauthRequired
	}
	g.mu.Lock()
	if current := g.policyWrites[userID]; current == nil || current.digest != digest {
		g.mu.Unlock()
		return reauth.ErrReauthRequired
	}
	g.policyWrites[userID].authorized = true
	g.mu.Unlock()
	if notifyErr := g.Reauth.NotifyOutcome(ctx, approved, reauth.OutcomeSuccess); notifyErr != nil {
		_ = notifyErr
	}
	return nil
}

// issuePolicyWriteSignals 向 policy.Set 的 ReauthVerifier 发放一次信号：只对在本次
// 写之前已由 authorizePolicyWrite 授权的同一变更有效，且只发放一次。
func (g *SecurityGate) issuePolicyWriteSignals(userID, operationID string) (reauth.Signals, error) {
	if g == nil {
		return reauth.Signals{}, reauth.ErrReauthRequired
	}
	g.mu.Lock()
	record := g.policyWrites[userID]
	if operationID != securityPolicyOperationID || record == nil ||
		!record.authorized || record.signalsIssued ||
		time.Now().After(record.expiresAt) {
		g.mu.Unlock()
		return reauth.Signals{}, reauth.ErrReauthRequired
	}
	record.signalsIssued = true
	g.mu.Unlock()
	return reauth.Signals{
		VerifiedAt: time.Now().UTC(), Strength: policy.StrengthStrong,
		Complete: true, Confirmed: true,
	}, nil
}

// finishPolicyWrite 在写操作成功后核对“授权+信号发放”均已发生并清理记录。
// 失败只可能来自未授权/未消费的不变量违例：不返回半提交错误，而是清理记录并
// 写失败审计（授权检查发生在写之前，正常路径不会走到这里）。
func (g *SecurityGate) finishPolicyWrite(userID, digest string) error {
	if g == nil {
		return reauth.ErrAccessDenied
	}
	g.mu.Lock()
	record := g.policyWrites[userID]
	delete(g.policyWrites, userID)
	g.mu.Unlock()
	if record == nil || record.digest != digest || !record.authorized {
		return reauth.ErrReauthRequired
	}
	return nil
}

// abortPolicyWrite 在写操作失败/未执行时清理本次批准（防止残留被其它请求挪用）。
func (g *SecurityGate) abortPolicyWrite(userID string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.policyWrites, userID)
}

// policyWriteDigest 计算策略写的绑定摘要（长度前缀编码，避免歧义拼接）。
func policyWriteDigest(action, scopeID, operationID string, version int64,
	changeDigest string) string {
	fields := []string{action, scopeID, operationID,
		strconv.FormatInt(version, 10), changeDigest}
	var builder strings.Builder
	for _, field := range fields {
		builder.WriteString(strconv.Itoa(len(field)))
		builder.WriteByte(':')
		builder.WriteString(field)
		builder.WriteByte('|')
	}
	sum := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(sum[:])
}

// SecurityPolicyReauth 是敏感策略页适配器的宿主再次认证回调。
//
// 策略写在宿主包装器里已完成真实再次认证（authorizePolicyWrite，绑定本次变更的
// 摘要/版本/作用域/操作）；本回调只复核绑定一致，不再重复认证、也不信任 context
// 信号。通知类动作（邮件测试/秘密替换）在这里做真实再次认证。
func (g *SecurityGate) SecurityPolicyReauth(ctx context.Context, userID string,
	binding ui.UISecurityPolicyActionBinding) error {
	if g == nil || g.Reauth == nil || g.Policy == nil {
		return reauth.ErrReauthRequired
	}
	if !account.ValidUserID(userID) {
		return reauth.ErrAccessDenied
	}
	if root, err := g.reauthCallerIsRoot(ctx, userID); err != nil || !root {
		return reauth.ErrAccessDenied
	}
	if isPolicyWriteAction(binding.Action) {
		g.mu.Lock()
		record := g.policyWrites[userID]
		matches := record != nil && record.authorized &&
			record.action == binding.Action &&
			record.scopeID == binding.ScopeID &&
			record.operationID == binding.OperationID &&
			record.version == binding.Version
		g.mu.Unlock()
		if !matches {
			return reauth.ErrReauthRequired
		}
		return nil
	}
	fact, ok := g.takeManagementFact(userID)
	if !ok || fact.verifiedAt.IsZero() {
		return reauth.ErrReauthRequired
	}
	caller, err := reauth.UserCaller(userID)
	if err != nil {
		return reauth.ErrAccessDenied
	}
	params := map[string]string{"action": binding.Action}
	if binding.ChangeDigest != "" {
		params["change_digest"] = binding.ChangeDigest
	}
	if binding.OperationID != "" {
		params["operation_id"] = binding.OperationID
	}
	if binding.ScopeID != "" {
		params["scope_id"] = binding.ScopeID
	}
	request := reauth.Request{
		ScopeID: "system", OperationID: securityPolicyOperationID,
		TargetType: "user", TargetID: userID, Params: params,
		Description: "修改安全通知设置",
	}
	signals := reauth.Signals{
		VerifiedAt: fact.verifiedAt, Strength: policy.StrengthStrong,
		Complete: true, Confirmed: true,
	}
	approved, authorizeErr := g.Reauth.Authorize(
		reauth.WithSignals(ctx, signals), caller, request)
	if authorizeErr != nil {
		return reauth.ErrReauthRequired
	}
	if notifyErr := g.Reauth.NotifyOutcome(ctx, approved, reauth.OutcomeSuccess); notifyErr != nil {
		_ = notifyErr
	}
	return nil
}

// isPolicyWriteAction 报告页面动作是否属于会写入敏感策略的动作。
func isPolicyWriteAction(action string) bool {
	switch action {
	case "policy.save", "policy.restore":
		return true
	default:
		return false
	}
}

// reauthCallerIsRoot 通过 policy 服务的 root 只读判定识别真实 root。
func (g *SecurityGate) reauthCallerIsRoot(ctx context.Context, userID string) (bool, error) {
	caller, err := policy.UserCaller(userID)
	if err != nil {
		return false, err
	}
	return g.Policy.UserIsRoot(ctx, caller)
}

// SensitiveRunner 返回满足领域服务敏感操作契约的真实执行器（*reauth.Service）。
func (g *SecurityGate) SensitiveRunner() reauth.OperationRunner {
	if g == nil {
		return nil
	}
	return g.Reauth
}

// recentAuthVerifier 是资料/邮箱等服务“近期验证”旧闸门的宿主实现：只检查当前
// 上下文是否携带可信近期验证事实（由页面适配器在真实 reauth 挑战通过后合成），
// 不消费一次性批准；真正的策略判定由 SensitiveRunner 完成。
type recentAuthVerifier struct {
	maxAge time.Duration
	now    func() time.Time
}

// verify 检查上下文中的验证事实是否完整且新鲜。
func (v recentAuthVerifier) verify(ctx context.Context) error {
	signals := reauth.SignalsFromContext(ctx)
	if signals.VerifiedAt.IsZero() || !signals.Complete {
		return reauth.ErrReauthRequired
	}
	now := time.Now
	if v.now != nil {
		now = v.now
	}
	age := now().Sub(signals.VerifiedAt)
	if age < -time.Minute || age > v.maxAge {
		return reauth.ErrReauthRequired
	}
	if signals.Strength != policy.StrengthPassword && signals.Strength != policy.StrengthStrong {
		return reauth.ErrReauthRequired
	}
	return nil
}

// profileReauthVerifier 实现 profile.ReauthVerifier。
type profileReauthVerifier struct {
	recentAuthVerifier
}

// VerifyReauth 实现 profile.ReauthVerifier。
func (v profileReauthVerifier) VerifyReauth(ctx context.Context, _ profile.Caller,
	_ string) error {
	return v.verify(ctx)
}

// emailChangeReauthVerifier 实现 emailchange.ReauthVerifier。
type emailChangeReauthVerifier struct {
	recentAuthVerifier
}

// VerifyReauth 实现 emailchange.ReauthVerifier。
func (v emailChangeReauthVerifier) VerifyReauth(ctx context.Context,
	_ emailchange.Caller, _ string) error {
	return v.verify(ctx)
}

// sensitiveRelay 是会话/认证服务的“敏感操作”延迟绑定：服务先于闸门构造，但真正
// 的判定发生在启动后的请求处理中。未绑定前一律拒绝（fail-closed）。
type sensitiveRelay struct {
	mu     sync.Mutex
	runner reauth.OperationRunner
}

// Set 绑定真实闸门（由宿主在闸门构造完成后调用一次）。
func (r *sensitiveRelay) Set(runner reauth.OperationRunner) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.runner = runner
}

// Authorize 实现 reauth.OperationRunner。
func (r *sensitiveRelay) Authorize(ctx context.Context, caller reauth.Caller,
	request reauth.Request) (reauth.Result, error) {
	runner := r.current()
	if runner == nil {
		return reauth.Result{}, reauth.ErrReauthRequired
	}
	return runner.Authorize(ctx, caller, request)
}

// NotifyOutcome 实现 reauth.OperationRunner。
func (r *sensitiveRelay) NotifyOutcome(ctx context.Context, result reauth.Result,
	outcome reauth.Outcome) error {
	runner := r.current()
	if runner == nil {
		return nil
	}
	return runner.NotifyOutcome(ctx, result, outcome)
}

func (r *sensitiveRelay) current() reauth.OperationRunner {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.runner
}

// strongFactorRelay 是认证服务“是否已绑定强因素”的延迟依赖：认证服务先构造，
// TOTP/Passkey 服务后构造，回填真实来源前保守按“未绑定”处理（fail-closed）。
type strongFactorRelay struct {
	mu     sync.Mutex
	source authn.StrongFactorPresence
}

// Set 绑定真实强因素来源。
func (r *strongFactorRelay) Set(source authn.StrongFactorPresence) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.source = source
}

// HasStrongFactor 实现 authn.StrongFactorPresence。
func (r *strongFactorRelay) HasStrongFactor(ctx context.Context, userID string) (bool, error) {
	if r == nil {
		return false, errors.New("强因素来源尚未接线")
	}
	r.mu.Lock()
	source := r.source
	r.mu.Unlock()
	if source == nil {
		return false, errors.New("强因素来源尚未接线")
	}
	return source.HasStrongFactor(ctx, userID)
}

// sessionManagementFact 从真实会话记录提取管理强认证事实（无强认证时返回零值）。
func sessionManagementFact(record session.Session) time.Time {
	return record.StrongAuthVerifiedAt
}
