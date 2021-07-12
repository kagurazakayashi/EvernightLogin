package credential

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

// Options 是构造 Service 的依赖。
type Options struct {
	// Keyring 提供低熵验证码受密钥保护摘要所需的密钥材料；必填，且必须包含
	// 当前写密钥（用于签发新验证码）。
	Keyring *secrets.Keyring
	// Logger 是结构化运行日志；nil 使用丢弃输出。日志只记录凭证 ID、用途、
	// 应用绑定、形态与失败原因，绝不记录令牌、验证码、摘要或目标内容。
	Logger *slog.Logger
	// Now 是可注入时钟；nil 使用 time.Now。服务内部统一截断到 UTC 毫秒，
	// 与数据库毫秒时间约定一致，便于有效期边界测试。
	Now func() time.Time
	// Random 是安全随机源；nil 使用 crypto/rand.Reader。生产不得替换为弱随机源。
	Random io.Reader
}

// Service 是一次性凭证服务。构造后不可变，可被多个 goroutine 并发使用。
//
// 生命周期：Service 不拥有数据库连接、不启动后台协程、不自动清理过期记录；
// 过期清理由调用方按策略调用 Cleanup。签发结果中的 Secret 只返回一次，服务端
// 只保存摘要。
type Service struct {
	store  Store
	ring   *secrets.Keyring
	logger *slog.Logger
	now    func() time.Time
	random io.Reader
}

// New 创建一次性凭证服务。store 为空、密钥环为空或缺少当前写密钥时返回
// ErrOptionsInvalid；不会创建任何默认密钥或替身存储。
func New(store Store, options Options) (*Service, error) {
	if isNilStore(store) {
		return nil, fmt.Errorf("%w: 凭证存储为空", ErrOptionsInvalid)
	}
	if options.Keyring == nil {
		return nil, fmt.Errorf("%w: 主密钥环为空", ErrOptionsInvalid)
	}
	currentKeyID := options.Keyring.CurrentKeyID()
	if currentKeyID == "" || !options.Keyring.HasKey(currentKeyID) {
		return nil, fmt.Errorf("%w: 密钥环缺少当前写密钥", ErrOptionsInvalid)
	}
	logger := options.Logger
	if logger == nil {
		logger = discardLogger()
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	random := options.Random
	if random == nil {
		random = defaultRandomReader()
	}
	return &Service{store: store, ring: options.Keyring, logger: logger, now: now, random: random}, nil
}

// isNilStore 检测 nil 接口以及 typed nil 指针，避免把 typed nil 当成可用存储
// 调用而 panic。
func isNilStore(store Store) bool {
	if store == nil {
		return true
	}
	value := reflect.ValueOf(store)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// discardLogger 返回写入丢弃输出的日志器，用于未注入日志器的内部调用。
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

// normalizeContext 把 nil ctx 当成 Background，避免调用方漏传时 panic。
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// clockNow 返回统一截断到 UTC 毫秒的当前时间，确保服务判断与数据库毫秒列
// 表示一致，避免边界测试出现亚毫秒歧义。
func (s *Service) clockNow() time.Time {
	return s.now().UTC().Truncate(time.Millisecond)
}

// Issue 签发一条一次性凭证。低熵验证码的摘要由密钥环当前写密钥派生；高熵令牌
// 只保存 SHA-256 摘要。ReplaceActive 为 true 时在同一事务内撤销同作用域旧凭证。
func (s *Service) Issue(ctx context.Context, request IssueRequest) (IssuedCredential, error) {
	return s.issue(ctx, request)
}

// Replace 签发一条新凭证并原子替换同用途、同目标、同应用的活动凭证。
func (s *Service) Replace(ctx context.Context, request IssueRequest) (IssuedCredential, error) {
	request.ReplaceActive = true
	return s.issue(ctx, request)
}

// issue 实现 Issue 与 Replace 的共同逻辑。
func (s *Service) issue(ctx context.Context, request IssueRequest) (IssuedCredential, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return IssuedCredential{}, err
	}
	normalized, err := normalizeIssueRequest(request)
	if err != nil {
		return IssuedCredential{}, err
	}
	currentTime := s.clockNow()

	id, err := newCredentialID(s.random)
	if err != nil {
		return IssuedCredential{}, err
	}
	var secret string
	var verifier []byte
	var keyID string
	switch normalized.Kind {
	case KindToken:
		secret, err = newTokenSecret(s.random)
		if err != nil {
			return IssuedCredential{}, err
		}
		verifier = tokenVerifierHash(id, normalized.Purpose, normalized.Target, normalized.AppID, secret)
	case KindCode:
		secret, err = newCodeSecret(s.random)
		if err != nil {
			return IssuedCredential{}, err
		}
		keyID = s.ring.CurrentKeyID()
		verifier, err = s.ring.HMACDigest(keyID, hmacDomain,
			codeDigestMessage(id, normalized.Purpose, normalized.Target, normalized.AppID, secret))
		if err != nil {
			return IssuedCredential{}, fmt.Errorf("%w: 无法生成受密钥保护的验证码摘要", ErrKeyUnavailable)
		}
	}
	expiresAt := time.UnixMilli(currentTime.Add(normalized.TTL).UnixMilli()).UTC()
	record := Record{
		ID:           id,
		Purpose:      normalized.Purpose,
		Target:       normalized.Target,
		AppID:        normalized.AppID,
		VerifierHash: verifier,
		KeyID:        keyID,
		ContextJSON:  contextJSON(normalized.Kind),
		MaxAttempts:  normalized.MaxAttempts,
		CreatedAt:    currentTime,
		ExpiresAt:    expiresAt,
	}
	var storeErr error
	if normalized.ReplaceActive {
		storeErr = s.store.ReplaceActiveAndInsert(ctx, record, currentTime)
	} else {
		storeErr = s.store.Insert(ctx, record)
	}
	if storeErr != nil {
		return IssuedCredential{}, s.storeFailure(ctx, "写入凭证", storeErr)
	}
	s.logger.Info("一次性凭证已签发",
		"credential_id", id,
		"kind", string(normalized.Kind),
		"purpose", normalized.Purpose,
		"app_id", normalized.AppID,
		"expires_at", expiresAt,
	)
	return IssuedCredential{
		ID:        id,
		Kind:      normalized.Kind,
		Purpose:   normalized.Purpose,
		Target:    normalized.Target,
		AppID:     normalized.AppID,
		ExpiresAt: expiresAt,
		Secret:    newSecret(secret),
	}, nil
}

// VerifyAndConsume 验证并原子消费一条凭证。
//
// 外部安全语义：未知凭证、用途/目标/应用不匹配、过期、已消费、已撤销、尝试
// 次数用尽与内容不匹配都返回同一个 ErrInvalidCredential，且没有可区分消息。
// 只有条件消费更新成功才返回成功；并发验证时最多一个调用能成功。存储错误返回
// ErrStoreUnavailable，绝不返回成功。
//
// 失败尝试：低熵验证码内容不匹配时原子增加尝试次数，达到 max_attempts 后失效；
// 高熵令牌内容不匹配不消耗尝试次数（256 位随机值无法穷举，避免持有公开 ID 的
// 攻击者耗尽他人凭证）。
func (s *Service) VerifyAndConsume(ctx context.Context, request VerifyRequest) (VerifiedCredential, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return VerifiedCredential{}, err
	}
	if err := request.validate(); err != nil {
		return VerifiedCredential{}, err
	}
	currentTime := s.clockNow()

	record, found, err := s.store.LoadByID(ctx, request.ID)
	if err != nil {
		return VerifiedCredential{}, s.storeFailure(ctx, "读取凭证", err)
	}
	if !found {
		return VerifiedCredential{}, s.invalid(ReasonNotFound, request.ID, request.Purpose, request.AppID)
	}
	recordKind := KindToken
	if record.KeyID != "" {
		recordKind = KindCode
	}
	if record.Purpose != request.Purpose || record.Target != request.Target ||
		record.AppID != request.AppID || recordKind != request.Kind {
		return VerifiedCredential{}, s.invalid(ReasonBindingMismatch, request.ID, request.Purpose, request.AppID)
	}
	if record.ConsumedAt != nil {
		return VerifiedCredential{}, s.invalid(ReasonConsumed, record.ID, record.Purpose, record.AppID)
	}
	if record.RevokedAt != nil {
		return VerifiedCredential{}, s.invalid(ReasonRevoked, record.ID, record.Purpose, record.AppID)
	}
	if !record.ExpiresAt.After(currentTime) {
		return VerifiedCredential{}, s.invalid(ReasonExpired, record.ID, record.Purpose, record.AppID)
	}
	if record.Attempts >= record.MaxAttempts {
		return VerifiedCredential{}, s.invalid(ReasonAttemptsExhausted, record.ID, record.Purpose, record.AppID)
	}

	var computed []byte
	if recordKind == KindToken {
		computed = tokenVerifierHash(record.ID, record.Purpose, record.Target, record.AppID, request.Secret)
	} else {
		computed, err = s.ring.HMACDigest(record.KeyID, hmacDomain,
			codeDigestMessage(record.ID, record.Purpose, record.Target, record.AppID, request.Secret))
		if err != nil {
			// 密钥缺失是服务内部故障，但对请求方仍必须表现为普通“凭证无效”，
			// 否则会暴露该作用域存在活动凭证。
			s.logger.Error("一次性凭证验证密钥不可用",
				"credential_id", record.ID,
				"key_id", record.KeyID,
			)
			return VerifiedCredential{}, s.invalid(ReasonKeyUnavailable, record.ID, record.Purpose, record.AppID)
		}
	}
	if subtle.ConstantTimeCompare(computed, record.VerifierHash) != 1 {
		if recordKind == KindToken {
			return VerifiedCredential{}, s.invalid(ReasonSecretMismatch, record.ID, record.Purpose, record.AppID)
		}
		attempt, err := s.store.RecordFailedAttempt(ctx, record.ID, currentTime)
		if err != nil {
			return VerifiedCredential{}, s.storeFailure(ctx, "记录失败尝试", err)
		}
		reason := ReasonSecretMismatch
		switch {
		case attempt.Remaining <= 0:
			reason = ReasonAttemptsExhausted
		case !attempt.Active:
			// 记录在失败尝试期间被并发消费、撤销或过期。
			reason = ReasonNotActive
		}
		return VerifiedCredential{}, s.invalid(reason, record.ID, record.Purpose, record.AppID)
	}

	consumed, err := s.store.Consume(ctx, ConsumeCondition{
		ID:      record.ID,
		Purpose: record.Purpose,
		Target:  record.Target,
		AppID:   record.AppID,
		Now:     currentTime,
	})
	if err != nil {
		return VerifiedCredential{}, s.storeFailure(ctx, "消费凭证", err)
	}
	if !consumed {
		// 验证通过后条件消费失败：并发消费、恰好过期或被撤销。绝不能返回成功。
		return VerifiedCredential{}, s.invalid(ReasonConsumeConflict, record.ID, record.Purpose, record.AppID)
	}
	s.logger.Info("一次性凭证已消费",
		"credential_id", record.ID,
		"kind", string(recordKind),
		"purpose", record.Purpose,
		"app_id", record.AppID,
	)
	return VerifiedCredential{
		ID:         record.ID,
		Purpose:    record.Purpose,
		Target:     record.Target,
		AppID:      record.AppID,
		ConsumedAt: currentTime,
	}, nil
}

// Peek 只校验一次性凭证的绑定、状态、有效期与秘密是否匹配，**不消费、不记录
// 失败尝试、不改变任何状态**。它用于“持有链接凭证但尚未消费”的受控前置校验
// （例如步骤 63 邮箱验证页的受控重发），不能替代 VerifyAndConsume 作为一次性
// 消费/授权证明；调用方对失败必须返回统一通用响应，不得据此暴露凭证/账户状态。
func (s *Service) Peek(ctx context.Context, request VerifyRequest) (VerifiedCredential, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return VerifiedCredential{}, err
	}
	if err := request.validate(); err != nil {
		return VerifiedCredential{}, err
	}
	currentTime := s.clockNow()
	record, found, err := s.store.LoadByID(ctx, request.ID)
	if err != nil {
		return VerifiedCredential{}, s.storeFailure(ctx, "读取凭证", err)
	}
	if !found {
		return VerifiedCredential{}, s.invalid(ReasonNotFound, request.ID, request.Purpose, request.AppID)
	}
	recordKind := KindToken
	if record.KeyID != "" {
		recordKind = KindCode
	}
	if record.Purpose != request.Purpose || record.Target != request.Target ||
		record.AppID != request.AppID || recordKind != request.Kind {
		return VerifiedCredential{}, s.invalid(ReasonBindingMismatch, request.ID, request.Purpose, request.AppID)
	}
	if record.ConsumedAt != nil {
		return VerifiedCredential{}, s.invalid(ReasonConsumed, record.ID, record.Purpose, record.AppID)
	}
	if record.RevokedAt != nil {
		return VerifiedCredential{}, s.invalid(ReasonRevoked, record.ID, record.Purpose, record.AppID)
	}
	if !record.ExpiresAt.After(currentTime) {
		return VerifiedCredential{}, s.invalid(ReasonExpired, record.ID, record.Purpose, record.AppID)
	}
	var computed []byte
	if recordKind == KindToken {
		computed = tokenVerifierHash(record.ID, record.Purpose, record.Target, record.AppID, request.Secret)
	} else {
		computed, err = s.ring.HMACDigest(record.KeyID, hmacDomain,
			codeDigestMessage(record.ID, record.Purpose, record.Target, record.AppID, request.Secret))
		if err != nil {
			return VerifiedCredential{}, s.invalid(ReasonKeyUnavailable, record.ID, request.Purpose, request.AppID)
		}
	}
	if subtle.ConstantTimeCompare(computed, record.VerifierHash) != 1 {
		return VerifiedCredential{}, s.invalid(ReasonSecretMismatch, record.ID, request.Purpose, request.AppID)
	}
	return VerifiedCredential{ID: record.ID, Purpose: record.Purpose,
		Target: record.Target, AppID: record.AppID, ConsumedAt: time.Time{}}, nil
}

// Cancel 按 ID 与绑定信息撤销仍活动的一次性凭证。已消费、已撤销、过期或绑定
// 不匹配时返回 ErrInvalidCredential；存储错误返回 ErrStoreUnavailable。
func (s *Service) Cancel(ctx context.Context, request CancelRequest) error {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := request.validate(); err != nil {
		return err
	}
	currentTime := s.clockNow()
	revoked, err := s.store.Revoke(ctx, RevokeCondition{
		ID:      request.ID,
		Purpose: request.Purpose,
		Target:  request.Target,
		AppID:   request.AppID,
		Now:     currentTime,
	})
	if err != nil {
		return s.storeFailure(ctx, "撤销凭证", err)
	}
	if !revoked {
		return s.invalid(ReasonNotActive, request.ID, request.Purpose, request.AppID)
	}
	s.logger.Info("一次性凭证已撤销",
		"credential_id", request.ID,
		"purpose", request.Purpose,
		"app_id", request.AppID,
	)
	return nil
}

// Cleanup 删除过期已超过 retention 的凭证记录，返回删除数量。只应在维护任务或
// 受控管理操作中调用；retention 为 0 表示过期即删除。Service 不自动调度清理。
func (s *Service) Cleanup(ctx context.Context, retention time.Duration) (CleanupReport, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return CleanupReport{}, err
	}
	if retention < 0 || retention > MaxCleanupRetention {
		return CleanupReport{}, requestInvalid("清理保留时长必须在 0 到 %s 之间", MaxCleanupRetention)
	}
	currentTime := s.clockNow()
	cutoff := time.UnixMilli(currentTime.Add(-retention).UnixMilli()).UTC()
	deleted, err := s.store.DeleteExpired(ctx, cutoff)
	if err != nil {
		return CleanupReport{}, s.storeFailure(ctx, "清理过期凭证", err)
	}
	s.logger.Info("一次性凭证过期清理完成",
		"deleted", deleted,
		"cutoff", cutoff,
	)
	return CleanupReport{Deleted: deleted, Cutoff: cutoff}, nil
}

// invalid 返回统一的凭证无效错误，并按内部原因记录结构化日志。日志不含令牌、
// 验证码、摘要与目标内容。
func (s *Service) invalid(reason Reason, credentialID, purpose, appID string) error {
	s.logger.Info("一次性凭证验证未通过",
		"reason", string(reason),
		"credential_id", credentialID,
		"purpose", purpose,
		"app_id", appID,
	)
	return newInvalid(reason)
}

// storeFailure 把存储错误映射为对外安全的 ErrStoreUnavailable，同时保留 context
// 取消/超时语义；原始错误只写入结构化日志供内部诊断。它绝不把失败包装成成功。
func (s *Service) storeFailure(ctx context.Context, operation string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	s.logger.Warn("一次性凭证存储操作失败",
		"operation", operation,
		"error", err,
	)
	return fmt.Errorf("%w: %s", ErrStoreUnavailable, operation)
}
