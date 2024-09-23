package app

// 找回密码公开门面（嵌入宿主用）。
//
// 第 11 轮（260）口径：账户口令相关入口分为三条用户路径——①已登录本人改密
// （Profile.ChangePassword / account.password 页）、②自助邮件找回（本文件，
// /login/forgot-password + /login/reset-password 内置页）、③ManualRecovery 人工核验
// 恢复（申请/独立审批/执行三权分离，保持可信渠道），三者共用同一密码/会话/找回核心，
// 不新增重复密码存储。另有**独立管理操作**：根包 DirectUserManagement（直接改名）与
// DirectPasswordManagement（直接重置他人密码），要求操作者独立权限 + 本人一次两步
// 验证，不经目标确认或另一管理员审批，**不是第四种匿名找回**，也不替换或删除人工恢复。
//
// 目标：让宿主在自己的“忘记密码”页面发起 Evernight 的邮件找回流程，并用邮件
// 中的一次性 token 完成密码重置；不暴露 internal/ 类型，也不返回重置 token。
//
// 安全与限流边界（步骤 208）：
//   - 防账户枚举：Request 对“账户不存在/已禁用/无密码/邮件发送失败”保持与成功相同
//     的外部结果；只有邮件能力未配置时才返回明确配置错误。ValidateToken 的所有
//     失败统一为 CHALLENGE_INVALID，不区分 token 不存在/过期/已使用/账户状态。
//   - 请求编号：三个入口都统一解析一次请求编号（空编号生成、非法编号拒绝），并把它
//     带入领域调用/审计与返回错误。
//   - 来源限流：Request/ValidateToken/Complete 在门面层各自有有界进程内固定窗口限流，
//     键是宿主从可信边界解析的“单一来源 IP”（不是转发头原文，也不是每次可更换的
//     token secret）。空来源按共享的“无来源”桶处理；伪造的转发头链/任意字符串在
//     入口直接按 REQ_INVALID 拒绝，不会生成新的限流键。限流只阻止同一来源的滥用，
//     不代表 token 强度或账户状态；令牌本身仍是高熵一次性凭证。
//   - 取消：context 已取消/超时的调用不消耗限流配额，返回 INTERNAL_ERROR（原因链
//     保留 context 错误供 errors.Is 判断），也不会执行领域读写。
//   - 审计：Request 的领域审计失败按既有映射返回（不伪装成功）；ValidateToken 是
//     只读预检查不写审计；Complete 的关键审计失败由领域映射为 AUDIT_WRITE_FAILED。
//     门面限流拒绝不写审计（与传输层限流一致），日志不记录 token、密码或找回链接。

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
	"github.com/kagurazakayashi/EvernightLogin/internal/ratelimit"
)

// 找回入口来源限流策略：保守阈值 + 有界键容量，够挡住单来源滥用又不会误伤正常
// 用户；窗口与阈值是进程内单实例语义，不提供跨实例共享计数。
const (
	passwordResetRequestSourceLimit   = 10
	passwordResetRequestSourceWindow  = 15 * time.Minute
	passwordResetValidateSourceLimit  = 30
	passwordResetValidateSourceWindow = 10 * time.Minute
	passwordResetCompleteSourceLimit  = 10
	passwordResetCompleteSourceWindow = 15 * time.Minute
	passwordResetLimiterMaxEntries    = 4096
	// passwordResetSourcelessBucket 是没有可信来源时使用的共享限流桶键；不同调用者
	// 共用该预算，避免“没有来源”变成无限流入口，也不让客户端自填值生成新键。
	passwordResetSourcelessBucket = "sourceless"
)

// passwordResetLimiters 是找回三个入口各自独立的来源限流器（有界容量、并发安全）。
type passwordResetLimiters struct {
	request  *ratelimit.Limiter
	validate *ratelimit.Limiter
	complete *ratelimit.Limiter
}

// newPasswordResetLimiters 构造三个来源限流器；时钟与运行时共用以便测试可控。
func newPasswordResetLimiters(now func() time.Time) (*passwordResetLimiters, error) {
	if now == nil {
		now = time.Now
	}
	build := func(policy ratelimit.Policy) (*ratelimit.Limiter, error) {
		return ratelimit.New(ratelimit.Options{
			Policy: policy, MaxEntries: passwordResetLimiterMaxEntries,
			CleanupInterval: policy.Window, Now: now,
		})
	}
	request, err := build(ratelimit.Policy{Limit: passwordResetRequestSourceLimit,
		Window: passwordResetRequestSourceWindow})
	if err != nil {
		return nil, err
	}
	validate, err := build(ratelimit.Policy{Limit: passwordResetValidateSourceLimit,
		Window: passwordResetValidateSourceWindow})
	if err != nil {
		return nil, err
	}
	complete, err := build(ratelimit.Policy{Limit: passwordResetCompleteSourceLimit,
		Window: passwordResetCompleteSourceWindow})
	if err != nil {
		return nil, err
	}
	return &passwordResetLimiters{request: request, validate: validate, complete: complete}, nil
}

// RequestPasswordResetRequest 是发起找回密码的请求。
type RequestPasswordResetRequest struct {
	// Identifier 是邮箱地址（Evernight 通过邮箱匹配账户）。
	Identifier string
	// ClientIP 是宿主从可信边界解析的单一客户端 IP（不是原始转发头值），用于来源
	// 维度限流；必须是从连接/受信代理解析出的 IP 字面量。
	ClientIP  string
	RequestID string
}

// ValidatePasswordResetTokenRequest 是 token 预检查请求（带可信来源上下文）。
type ValidatePasswordResetTokenRequest struct {
	// Token 是邮件中的一次性找回令牌；不会写入日志或返回。
	Token string
	// ClientIP 是宿主从可信边界解析的单一客户端 IP，用于来源维度限流；空表示没有
	// 可信来源（使用共享的无来源限流桶）。
	ClientIP  string
	RequestID string
}

// CompletePasswordResetRequest 是用邮件 token 设置新密码的请求。
type CompletePasswordResetRequest struct {
	Token       string
	NewPassword string
	// ClientIP 是宿主从可信边界解析的单一客户端 IP，用于来源维度限流。
	ClientIP  string
	RequestID string
}

// PasswordResetResult 是完成找回的结果；不签发业务会话。
type PasswordResetResult struct {
	UserID          string
	SecurityVersion int64
	RequiresRelogin bool
	SessionsRevoked int64
	ResetAt         time.Time
}

// PasswordResetService 是找回密码公开门面。
type PasswordResetService interface {
	// Request 发起找回；成功/未找到/禁用等统一返回 nil，避免账号枚举。来源限流
	// 超限时返回 RATE_LIMITED（不涉及账户状态，因此不泄露账户是否存在）。
	Request(ctx context.Context, req RequestPasswordResetRequest) error
	// ValidateToken 检查邮件 token 当前是否仍可用：核对请求状态、一次性凭证状态/
	// 绑定与账户可找回状态，但不消费、不改状态；所有失败统一返回 CHALLENGE_INVALID。
	// 该兼容入口没有显式来源参数，使用共享的无来源限流桶；能提供可信来源时请用
	// ValidateTokenWithSource。
	ValidateToken(ctx context.Context, token string) error
	// ValidateTokenWithSource 与 ValidateToken 判断相同，但带显式可信来源与请求编号，
	// 来源用于有界限流（不是授权依据）。
	ValidateTokenWithSource(ctx context.Context, req ValidatePasswordResetTokenRequest) error
	// Complete 用 token 设置新强密码并撤销旧会话。密码策略/历史复用失败时令牌不消费，
	// 可用同一入口重试；并发状态冲突返回 CONFLICT（同样未消费）。
	Complete(ctx context.Context, req CompletePasswordResetRequest) (PasswordResetResult, error)
}

type passwordResetFacade struct{ r *Runtime }

// resetLimiters 返回运行时来源限流器；未装配时 ok=false，由调用方按配置错误
// fail-closed（不放行无限流的公开入口）。
func (f *passwordResetFacade) resetLimiters() (*passwordResetLimiters, bool) {
	if f.r == nil || f.r.resetLimiters == nil {
		return nil, false
	}
	return f.r.resetLimiters, true
}

// trustedSourceKey 把宿主传入的来源规范化为限流键：
//   - 空白 → 共享的“无来源”桶（有界，不与任意客户端字符串绑定）；
//   - 合法 IP 字面量 → 规范化的 IP 文本（同一地址不同写法合并计数）；
//   - 其他值（例如未解析的 X-Forwarded-For 链、"unknown"、任意伪造字符串）→ 拒绝。
//
// 只接受可解析的单一 IP，避免客户端通过轮换伪造字符串生成无限多个限流键绕过预算。
func trustedSourceKey(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return passwordResetSourcelessBucket, true
	}
	ip := net.ParseIP(trimmed)
	if ip == nil {
		return "", false
	}
	return ip.String(), true
}

// allowSource 对指定入口的限流器消耗一次来源预算；返回是否允许与建议等待时间。
func allowSource(limiter *ratelimit.Limiter, sourceKey string) (bool, time.Duration) {
	decision := limiter.Allow(sourceKey)
	if decision.Allowed {
		return true, 0
	}
	return false, decision.RetryAfter
}

// resolveSource 解析来源并在非法时返回带请求编号的 REQ_INVALID。
func resolveSource(raw, requestID string) (string, error) {
	key, ok := trustedSourceKey(raw)
	if !ok {
		return "", login.NewAppError(login.CodeReqInvalid,
			"来源地址必须是从可信边界解析的单一 IP", login.WithRequestID(requestID))
	}
	return key, nil
}

// rateLimitedError 构造带编号与等待建议的 RATE_LIMITED 公开错误（不记录 token）。
func rateLimitedError(message, requestID string) error {
	return login.NewAppError(login.CodeRateLimited, message,
		login.WithRequestID(requestID))
}

// checkFacadeContext 在消耗任何限流预算或执行领域读写前检查 context；已取消/超时
// 的调用不计数、不改状态，返回带编号且保留 context 原因链的公开错误。
func checkFacadeContext(ctx context.Context, requestID string) error {
	return facadeContextError(ctx, requestID)
}

func (f *passwordResetFacade) Request(ctx context.Context, req RequestPasswordResetRequest) error {
	r := f.r
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return err
	}
	if r == nil || r.base == nil {
		return configError("找回密码服务未装配", requestID)
	}
	if !r.base.Config.Mail.Enabled {
		return configError("找回密码邮件未配置", requestID)
	}
	security := r.securityDomains()
	if security == nil || security.PasswordReset == nil {
		return configError("找回密码服务未装配", requestID)
	}
	limiters, ok := f.resetLimiters()
	if !ok {
		return configError("找回密码限流器未装配", requestID)
	}
	if err := checkFacadeContext(ctx, requestID); err != nil {
		return err
	}
	sourceKey, err := resolveSource(req.ClientIP, requestID)
	if err != nil {
		return err
	}
	if allowed, _ := allowSource(limiters.request, sourceKey); !allowed {
		// 来源级限流不涉及账户是否存在，因此可安全返回 RATE_LIMITED。
		return rateLimitedError("找回请求过于频繁", requestID)
	}
	sourceIP := canonicalSourceIP(sourceKey)
	// BeginReset 对账户不存在/禁用/邮件失败统一返回 nil，差异只进审计。
	if _, err := security.PasswordReset.BeginReset(ctx, passwordreset.BeginResetRequest{
		Identifier: req.Identifier, ClientIP: sourceIP, RequestID: requestID,
	}); err != nil {
		return mapDomainError("发起找回密码失败", string(passwordreset.CodeOf(err)), requestID)
	}
	return nil
}

// canonicalSourceIP 把限流键还原为传给领域的来源文本；无来源桶传空字符串，让领域
// 仍按“没有来源”处理（领域自身不会因空来源放行其他安全判断）。
func canonicalSourceIP(sourceKey string) string {
	if sourceKey == passwordResetSourcelessBucket {
		return ""
	}
	return sourceKey
}

// ValidateToken 是兼容入口：没有显式来源，使用共享的无来源限流桶；请求编号从
// context 取或统一生成，保证返回错误可关联。
func (f *passwordResetFacade) ValidateToken(ctx context.Context, token string) error {
	requestID, err := resolveRequestID(ctx, "")
	if err != nil {
		return err
	}
	return f.validateToken(ctx, token, "", requestID)
}

// ValidateTokenWithSource 是带显式可信来源与请求编号的预检查入口。
func (f *passwordResetFacade) ValidateTokenWithSource(ctx context.Context,
	req ValidatePasswordResetTokenRequest) error {
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return err
	}
	return f.validateToken(ctx, req.Token, req.ClientIP, requestID)
}

// validateToken 实现预检查：可疑来源/超限在调用领域前拒绝；领域失败统一为
// CHALLENGE_INVALID（防枚举），但底层存储故障仍按领域默认拒绝处理。
func (f *passwordResetFacade) validateToken(ctx context.Context, token,
	rawSource, requestID string) error {
	security := f.r.securityDomains()
	if security == nil || security.PasswordReset == nil {
		return configError("找回密码服务未装配", requestID)
	}
	limiters, ok := f.resetLimiters()
	if !ok {
		return configError("找回密码限流器未装配", requestID)
	}
	if err := checkFacadeContext(ctx, requestID); err != nil {
		return err
	}
	sourceKey, err := resolveSource(rawSource, requestID)
	if err != nil {
		return err
	}
	if allowed, _ := allowSource(limiters.validate, sourceKey); !allowed {
		return rateLimitedError("找回 token 校验请求过于频繁", requestID)
	}
	// 预检查与内置找回页面走同一个领域判断（ValidateResetToken 会核对请求状态、
	// 一次性凭证状态/绑定与账户可找回状态），但公开错误统一为 CHALLENGE_INVALID：
	// 不区分 token 不存在/过期/已使用/已撤销/账户禁用/无密码，避免公开入口泄露
	// 账户状态。服务层对底层存储故障仍按默认拒绝处理，不会当作有效 token。
	if err := security.PasswordReset.ValidateResetToken(ctx, token); err != nil {
		return login.NewAppError(login.CodeChallengeInvalid, "找回 token 无效或已失效",
			login.WithRequestID(requestID))
	}
	return nil
}

func (f *passwordResetFacade) Complete(ctx context.Context,
	req CompletePasswordResetRequest) (PasswordResetResult, error) {
	security := f.r.securityDomains()
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return PasswordResetResult{}, err
	}
	if security == nil || security.PasswordReset == nil {
		return PasswordResetResult{}, configError("找回密码服务未装配", requestID)
	}
	limiters, ok := f.resetLimiters()
	if !ok {
		return PasswordResetResult{}, configError("找回密码限流器未装配", requestID)
	}
	if err := checkFacadeContext(ctx, requestID); err != nil {
		return PasswordResetResult{}, err
	}
	sourceKey, err := resolveSource(req.ClientIP, requestID)
	if err != nil {
		return PasswordResetResult{}, err
	}
	if allowed, _ := allowSource(limiters.complete, sourceKey); !allowed {
		return PasswordResetResult{}, rateLimitedError("重置密码请求过于频繁", requestID)
	}
	result, err := security.PasswordReset.CompleteReset(ctx, passwordreset.CompleteRequest{
		Token: req.Token, NewPassword: req.NewPassword, RequestID: requestID,
	})
	if err != nil {
		return PasswordResetResult{}, mapDomainError("重置密码失败",
			string(passwordreset.CodeOf(err)), requestID)
	}
	return PasswordResetResult{
		UserID: result.UserID, SecurityVersion: result.SecurityVersion,
		RequiresRelogin: result.RequiresRelogin, SessionsRevoked: result.SessionsRevoked,
		ResetAt: result.ResetAt,
	}, nil
}

var _ PasswordResetService = (*passwordResetFacade)(nil)
