package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

// AuditRecorder 是安全审计契约；生产实现为 *audit.Recorder。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// Options 是令牌服务的显式依赖；核心依赖缺失时拒绝构造（fail-closed）。
type Options struct {
	Store Store
	Audit AuditRecorder
	// Sealer 加密保存签名私钥（用途 oauth.signing/对象=kid/范围 system）；必填。
	Sealer *secrets.Sealer
	// Issuer 是固定签发方标识（https 绝对地址，回环测试可 http）；必填。
	Issuer string
	// Clients 读取 oauthclient 已登记的客户端 Scope/audience/grant 配置；必填。
	Clients ClientSource
	// Authorizer 判定签发上下文是否获准；必填（nil 时拒绝构造，不允许任意签发）。
	Authorizer IssuanceAuthorizer
	// AccessTTL/IDTokenTTL 是令牌有效期；0 使用默认值，越界拒绝构造。
	AccessTTL  time.Duration
	IDTokenTTL time.Duration
	// KeyRetention 是签名密钥退役后公钥继续验签/发布的保留期；必须覆盖令牌最长
	// 有效期与时钟容差（否则无法验证退役前已签发的令牌）。
	KeyRetention time.Duration
	// ClockSkew 是验证时允许的时钟容差；0 使用 DefaultClockSkew。
	ClockSkew time.Duration
	Now       func() time.Time
	Random    io.Reader
	Logger    *slog.Logger
}

// Service 是令牌签发/验证与签名密钥管理服务。构造后不可变、可并发使用；不启动
// 协程、不暴露 HTTP 路由、不签发刷新令牌。
type Service struct {
	opts         Options
	accessTTL    time.Duration
	idTokenTTL   time.Duration
	keyRetention time.Duration
	clockSkew    time.Duration
	now          func() time.Time
	random       io.Reader
	logger       *slog.Logger
}

// New 校验依赖与参数并构造令牌服务。缺少 Store/Audit/Sealer/Issuer/Clients/
// Authorizer 或参数越界时返回错误；不会创建默认密钥、默认授权器或测试替身。
func New(options Options) (*Service, error) {
	if isNilInterface(options.Store) {
		return nil, fmt.Errorf("%w: 令牌存储为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.Audit) {
		return nil, fmt.Errorf("%w: 安全审计写入器为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.Sealer) {
		return nil, fmt.Errorf("%w: 私钥加密器为空", ErrOptionsInvalid)
	}
	if err := validateIssuer(options.Issuer); err != nil {
		return nil, err
	}
	if isNilInterface(options.Clients) {
		return nil, fmt.Errorf("%w: OAuth 客户端来源为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.Authorizer) {
		return nil, fmt.Errorf("%w: 签发授权器为空（不允许任意签发）", ErrOptionsInvalid)
	}
	accessTTL := options.AccessTTL
	if accessTTL == 0 {
		accessTTL = DefaultAccessTTL
	}
	if accessTTL < MinAccessTTL || accessTTL > MaxAccessTTL {
		return nil, fmt.Errorf("%w: Access Token 有效期必须在 %s～%s 之间",
			ErrOptionsInvalid, MinAccessTTL, MaxAccessTTL)
	}
	idTokenTTL := options.IDTokenTTL
	if idTokenTTL == 0 {
		idTokenTTL = DefaultIDTokenTTL
	}
	if idTokenTTL < MinIDTokenTTL || idTokenTTL > MaxIDTokenTTL {
		return nil, fmt.Errorf("%w: ID Token 有效期必须在 %s～%s 之间",
			ErrOptionsInvalid, MinIDTokenTTL, MaxIDTokenTTL)
	}
	keyRetention := options.KeyRetention
	if keyRetention == 0 {
		keyRetention = DefaultKeyRetention
	}
	if keyRetention < MinKeyRetention || keyRetention > MaxKeyRetention {
		return nil, fmt.Errorf("%w: 密钥保留期必须在 %s～%s 之间",
			ErrOptionsInvalid, MinKeyRetention, MaxKeyRetention)
	}
	clockSkew := options.ClockSkew
	if clockSkew == 0 {
		clockSkew = DefaultClockSkew
	}
	if clockSkew < 0 || clockSkew > MaxClockSkew {
		return nil, fmt.Errorf("%w: 时钟容差必须在 0～%s 之间", ErrOptionsInvalid, MaxClockSkew)
	}
	maxTTL := accessTTL
	if idTokenTTL > maxTTL {
		maxTTL = idTokenTTL
	}
	// 保留期必须覆盖已签令牌最长有效期 + 时钟容差，否则退役会提前让旧令牌不可验证。
	if keyRetention < maxTTL+clockSkew {
		return nil, fmt.Errorf("%w: 密钥保留期必须不小于最长令牌有效期+时钟容差（至少 %s）",
			ErrOptionsInvalid, maxTTL+clockSkew)
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	random := options.Random
	if random == nil {
		random = rand.Reader
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Service{
		opts: options, accessTTL: accessTTL, idTokenTTL: idTokenTTL,
		keyRetention: keyRetention, clockSkew: clockSkew,
		now: now, random: random, logger: logger,
	}, nil
}

// isNilInterface 检测 nil 接口与 typed nil 指针。
func isNilInterface(value any) bool {
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

// clockNow 返回统一截断到 UTC 毫秒的当前时间。
func (s *Service) clockNow() time.Time { return s.now().UTC().Truncate(time.Millisecond) }

// AccessTTL 返回 Access Token 有效期（供宿主配置/文档使用）。
func (s *Service) AccessTTL() time.Duration { return s.accessTTL }

// IDTokenTTL 返回 ID Token 有效期。
func (s *Service) IDTokenTTL() time.Duration { return s.idTokenTTL }

// Issuer 返回固定签发方。
func (s *Service) Issuer() string { return s.opts.Issuer }

// SealBinding 返回签名私钥加密绑定。
func sealBinding(kid string) secrets.Binding {
	return secrets.Binding{Purpose: "oauth.signing", ObjectID: kid, ScopeID: secrets.ScopeSystem}
}

// ensureActiveKey 返回当前 active 签名密钥；没有时创建并激活一把（系统主体审计）。
// 引导建钥只发生在没有任何 active 密钥时；已有密钥永不自动替换。
//
// 紧急撤销 active 后的语义（步骤 51 收口）：下一次签发会引导创建**全新** active
// 密钥（不会复用被撤销密钥），这是显式的自动恢复，不是把 revoked 降级复用；如果
// 运维需要暂停签发，应在服务装配层停止调用签发入口/下线令牌端点，而不是依赖本
// 方法失败。该语义与本文件 RevokeSigningKey 的说明保持一致。
func (s *Service) ensureActiveKey(ctx context.Context) (KeyRecord, error) {
	return s.ensureActiveKeyWithStatus(ctx, nil)
}

// ensureActiveKeyWithStatus 与 ensureActiveKey 相同，额外通过 onReuse 回调标识
// “本次未创建、复用了既有 active 密钥”的路径（供 EnsureSigningKey 写复用审计）。
func (s *Service) ensureActiveKeyWithStatus(ctx context.Context,
	onReuse func(KeyRecord) error) (KeyRecord, error) {
	active, found, err := s.opts.Store.GetActiveKey(ctx)
	if err != nil {
		return KeyRecord{}, ErrStoreUnavailable
	}
	if found {
		if onReuse != nil {
			if err := onReuse(active); err != nil {
				return KeyRecord{}, err
			}
		}
		return active, nil
	}
	kid, publicJWK, sealed, err := s.generateKeyMaterial()
	if err != nil {
		return KeyRecord{}, err
	}
	now := s.clockNow()
	record := KeyRecord{
		Kid: kid, Algorithm: AlgorithmES256, Status: KeyActive,
		PublicJWK: publicJWK, SealedPrivate: sealed,
		CreatedAt: now, ActivatedAt: now,
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:  audit.Actor{Type: audit.ActorSystem, ID: "token-service"},
			Action: "token.key.created",
			Target: audit.Target{Type: "oauth_signing_key", ID: kid},
			Changes: []audit.FieldChange{
				{Field: "algorithm", After: AlgorithmES256},
				{Field: "status", After: string(KeyActive)},
				{Field: "bootstrapped", After: "true"},
			},
		},
		FailureReasonCode:   "token.key.create_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapKeyError(err))) },
	}
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.opts.Store.InsertKeyTx(txCtx, tx, record)
	}); err != nil {
		// 并发引导可能被另一请求抢先创建 active 密钥：重读并复用，避免把并发首签
		// 变成失败；仍无 active 时才返回错误（fail-closed）。
		if existing, found, readErr := s.opts.Store.GetActiveKey(ctx); readErr == nil && found {
			if onReuse != nil {
				if err := onReuse(existing); err != nil {
					return KeyRecord{}, err
				}
			}
			return existing, nil
		}
		return KeyRecord{}, mapKeyError(err)
	}
	s.logger.Info("令牌签名密钥已引导创建", "kid", kid, "algorithm", AlgorithmES256)
	return record, nil
}

// generateKeyMaterial 生成 ECDSA P-256 私钥、公开 JWK 与密封私钥。
func (s *Service) generateKeyMaterial() (string, []byte, []byte, error) {
	kid, err := generateKeyID(s.random)
	if err != nil {
		return "", nil, nil, err
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), s.random)
	if err != nil {
		return "", nil, nil, fmt.Errorf("%w: 无法生成签名密钥", ErrOptionsInvalid)
	}
	publicKey := privateKey.PublicKey
	publicJWK, err := json.Marshal(jose.JSONWebKey{
		Key: &publicKey, KeyID: kid, Algorithm: AlgorithmES256, Use: KeyUseSignature,
	})
	if err != nil {
		return "", nil, nil, fmt.Errorf("%w: 无法编码公开 JWK", ErrOptionsInvalid)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", nil, nil, fmt.Errorf("%w: 无法编码私钥", ErrOptionsInvalid)
	}
	sealed, err := s.opts.Sealer.Seal(sealBinding(kid), der)
	if err != nil {
		return "", nil, nil, fmt.Errorf("%w: 无法加密保存签名私钥", ErrKeyUnavailable)
	}
	return kid, publicJWK, sealed, nil
}

// openPrivateKey 解密并解析签名私钥；任何失败都 fail-closed（绝不返回部分材料）。
func (s *Service) openPrivateKey(record KeyRecord) (*ecdsa.PrivateKey, error) {
	der, err := s.opts.Sealer.Open(sealBinding(record.Kid), record.SealedPrivate)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法解密签名私钥", ErrKeyUnavailable)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: 签名私钥格式无效", ErrKeyUnavailable)
	}
	privateKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || privateKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: 签名私钥类型不是 P-256 ECDSA", ErrKeyUnavailable)
	}
	return privateKey, nil
}

// signClaims 用指定密钥对声明签名，并写入 kid/typ 头。payload 是已序列化的 JSON 声明。
func (s *Service) signClaims(record KeyRecord, payload []byte, typ string) (string, error) {
	privateKey, err := s.openPrivateKey(record)
	if err != nil {
		return "", err
	}
	signerOptions := (&jose.SignerOptions{}).WithType(jose.ContentType(typ))
	signerOptions.WithHeader(jose.HeaderKey("kid"), record.Kid)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: privateKey}, signerOptions)
	if err != nil {
		return "", fmt.Errorf("%w: 无法构造签名器", ErrSigningFailed)
	}
	object, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("%w: 无法签名令牌", ErrSigningFailed)
	}
	compact, err := object.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("%w: 无法序列化令牌", ErrSigningFailed)
	}
	return compact, nil
}

// EnsureSigningKey 在装配/启动阶段幂等确保存在 active 签名密钥（系统主体审计），
// 供宿主在发布 JWKS 前预引导：全新实例若等到首次令牌签发才懒创建密钥，JWKS 会
// 发布空集合，调用方会误判为“协议不可用/无密钥”。已有 active 密钥时不生成新密钥，
// kid 跨重启稳定；创建走与签发相同的 ensureActiveKey 审计路径（密钥材料经既有
// secrets 封装保存），失败时返回错误由宿主拒绝启动。
func (s *Service) EnsureSigningKey(ctx context.Context) (KeyInfo, error) {
	ctx = normalizeContext(ctx)
	record, err := s.ensureActiveKeyWithStatus(ctx, func(existing KeyRecord) error {
		// 复用既有 active 密钥同样写审计（不静默）：system 主体、kid/algorithm，
		// 不含任何私钥材料；审计不可用时 fail-closed。
		event := audit.Event{
			Actor:   audit.Actor{Type: audit.ActorSystem, ID: "token-service"},
			Action:  "token.key.ensured",
			Target:  audit.Target{Type: "oauth_signing_key", ID: existing.Kid},
			Outcome: audit.OutcomeSuccess,
			Changes: []audit.FieldChange{
				{Field: "algorithm", After: existing.Algorithm},
				{Field: "status", After: string(existing.Status)},
				{Field: "reused", After: "true"},
			},
		}
		if recordErr := s.opts.Audit.Record(ctx, event); recordErr != nil {
			return ErrAuditUnavailable
		}
		return nil
	})
	if err != nil {
		return KeyInfo{}, mapKeyError(err)
	}
	return keyInfoOf(record), nil
}

// PublishedJWKS 返回 JWKS 公钥集合（active + next + 保留期内 retired），不含任何
// 私有字段；revoked 与超过保留期的 retired 不再发布。当前 RotateSigningKey 在单一
// 事务内插入 next 并立即激活，因此提交后不会长期存在 next 密钥；发布集合保留 next
// 是为将来“先预发布下一把公钥、再切换 active”的显式过渡预留，不代表当前实现已经
// 提前预发布（README/MEMORY 已记录该一致性说明）。JWKS 只是纯数据，HTTP 路由由
// 后续步骤装配。
func (s *Service) PublishedJWKS(ctx context.Context) ([]byte, error) {
	records, err := s.opts.Store.ListKeys(ctx)
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	now := s.clockNow()
	keys := make([]jose.JSONWebKey, 0, len(records))
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		if record.Status == KeyRevoked || !record.Publishable(now) {
			continue
		}
		if _, duplicate := seen[record.Kid]; duplicate {
			continue
		}
		var key jose.JSONWebKey
		if err := json.Unmarshal(record.PublicJWK, &key); err != nil {
			// 损坏的公钥不发布，但也不能因此返回私有材料。
			s.logger.Warn("签名公钥 JWK 解析失败，已跳过发布", "kid", record.Kid)
			continue
		}
		if key.IsPublic() == false {
			// 防御：公开集合只允许公钥，绝不发布含私有字段的 JWK。
			s.logger.Warn("签名公钥 JWK 含私有材料，已跳过发布", "kid", record.Kid)
			continue
		}
		seen[record.Kid] = struct{}{}
		keys = append(keys, key)
	}
	document, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
	if err != nil {
		return nil, fmt.Errorf("%w: 无法编码 JWKS", ErrInternal)
	}
	return document, nil
}

// ErrInternal 是内部编码故障哨兵（映射 INTERNAL_ERROR）。
var ErrInternal = errors.New("令牌服务内部错误")

// mapKeyError 把密钥存储/审计错误映射为稳定领域错误。
func mapKeyError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrAuditUnavailable), errors.Is(err, audit.ErrAuditUnavailable):
		return ErrAuditUnavailable
	case errors.Is(err, ErrKeyUnavailable), errors.Is(err, ErrSigningFailed):
		return err
	default:
		return ErrStoreUnavailable
	}
}

// RecordFailure 写入失败审计（独立事务）；审计不可用只写日志，不改变拒绝结论。
func (s *Service) recordFailure(ctx context.Context, actor audit.Actor, action, targetType, targetID, reason, errorCode string) {
	event := audit.Event{
		Actor: actor, Action: action,
		Target:  audit.Target{Type: targetType, ID: targetID},
		Outcome: audit.OutcomeFailure, ErrorCode: errorCode, ReasonCode: reason,
	}
	if err := s.opts.Audit.RecordFailure(ctx, event); err != nil {
		s.logger.Warn("令牌操作失败审计写入失败", "action", action, "reason", reason,
			"error_category", "audit_unavailable")
	}
}

// KeyInfo 是签名密钥的公开元数据（不含私钥或密文）。
type KeyInfo struct {
	Kid         string
	Algorithm   string
	Status      KeyStatus
	CreatedAt   time.Time
	ActivatedAt time.Time
	RetiredAt   time.Time
	RetireAfter time.Time
}

// keyInfoOf 构造公开密钥元数据。
func keyInfoOf(record KeyRecord) KeyInfo {
	return KeyInfo{
		Kid: record.Kid, Algorithm: record.Algorithm, Status: record.Status,
		CreatedAt: record.CreatedAt, ActivatedAt: record.ActivatedAt,
		RetiredAt: record.RetiredAt, RetireAfter: record.RetireAfter,
	}
}

// RotateSigningKey 生成并启用新签名密钥，同时把旧 active 密钥置为 retired：
// 旧密钥在 KeyRetention 内仍可验证旧令牌并继续出现在 JWKS，保留期后验证拒绝且
// 不再发布。仅允许系统/本地管理员可信调用者；普通用户调用拒绝并写失败审计。
func (s *Service) RotateSigningKey(ctx context.Context, caller Caller, requestID string) (KeyInfo, error) {
	ctx = normalizeContext(ctx)
	if err := caller.actor.Validate(); err != nil || !caller.IsTrusted() {
		s.recordFailure(ctx, caller.actor, "token.key.rotate_denied", "oauth_signing_key", "unknown",
			"caller_not_trusted", string(CodeAccessDenied))
		return KeyInfo{}, ErrAccessDenied
	}
	if err := account.ValidateRequestID(requestID); err != nil {
		return KeyInfo{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	kid, publicJWK, sealed, err := s.generateKeyMaterial()
	if err != nil {
		return KeyInfo{}, err
	}
	now := s.clockNow()
	next := KeyRecord{
		Kid: kid, Algorithm: AlgorithmES256, Status: KeyNext,
		PublicJWK: publicJWK, SealedPrivate: sealed, CreatedAt: now,
	}
	// 先读旧 active（事务外只读快照）；同事务内依次：插入 next → 退役旧 active →
	// 激活 next（避免 active 部分唯一索引冲突）。数据库条件更新保证并发轮换只有
	// 一个成功，旧快照失效时整体回滚。
	oldActive, hasOldActive, err := s.opts.Store.GetActiveKey(ctx)
	if err != nil {
		return KeyInfo{}, ErrStoreUnavailable
	}
	rotated := KeyInfo{}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.actor, Action: "token.key.rotated",
			Target:    audit.Target{Type: "oauth_signing_key", ID: kid},
			RequestID: requestID,
			Changes: []audit.FieldChange{
				{Field: "algorithm", After: AlgorithmES256},
				{Field: "status", Before: string(KeyNext), After: string(KeyActive)},
				{Field: "key_retention", After: s.keyRetention.String()},
			},
		},
		FailureReasonCode:   "token.key.rotate_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapKeyError(err))) },
	}
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		if err := s.opts.Store.InsertKeyTx(txCtx, tx, next); err != nil {
			return err
		}
		if hasOldActive {
			retired, err := s.opts.Store.RetireKeyTx(txCtx, tx, oldActive.Kid, now, now.Add(s.keyRetention))
			if err != nil {
				return err
			}
			if !retired {
				return ErrKeyUnavailable
			}
		}
		activated, err := s.opts.Store.ActivateKeyTx(txCtx, tx, kid, now)
		if err != nil {
			return err
		}
		if !activated {
			return ErrKeyUnavailable
		}
		rotated = KeyInfo{Kid: kid, Algorithm: AlgorithmES256, Status: KeyActive,
			CreatedAt: now, ActivatedAt: now}
		return nil
	}); err != nil {
		return KeyInfo{}, mapKeyError(err)
	}
	s.logger.Info("令牌签名密钥已轮换", "new_kid", kid, "retention", s.keyRetention.String())
	return rotated, nil
}

// RevokeSigningKey 紧急撤销一把签名密钥（next/active/retired）：立即让该密钥签发的
// 令牌验证失败并停止发布其公钥；仅允许系统/本地管理员可信调用者。
//
// 撤销 active 后不会降级复用 revoked 密钥：下一次签发由 ensureActiveKey 引导创建
// 全新 active（新的 kid/私钥），旧令牌仍因 revoked 拒绝。若需要暂停签发，应由宿主
// 装配层下线签发入口；本方法本身不设置“暂停签发”持久闸门。
func (s *Service) RevokeSigningKey(ctx context.Context, caller Caller, requestID, kid, reason string) error {
	ctx = normalizeContext(ctx)
	if err := caller.actor.Validate(); err != nil || !caller.IsTrusted() {
		s.recordFailure(ctx, caller.actor, "token.key.revoke_denied", "oauth_signing_key", kid,
			"caller_not_trusted", string(CodeAccessDenied))
		return ErrAccessDenied
	}
	if err := account.ValidateRequestID(requestID); err != nil {
		return fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if !validKeyID(kid) || reason == "" || len(reason) > 200 {
		return fmt.Errorf("%w: 密钥标识或撤销原因无效", ErrInvalidRequest)
	}
	now := s.clockNow()
	revoked := false
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.actor, Action: "token.key.revoked",
			Target:    audit.Target{Type: "oauth_signing_key", ID: kid},
			RequestID: requestID,
			Changes:   []audit.FieldChange{{Field: "status", After: string(KeyRevoked)}},
		},
		FailureReasonCode:   "token.key.revoke_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapKeyError(err))) },
	}
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, err := s.opts.Store.RevokeKeyTx(txCtx, tx, kid, reason, now)
		if err != nil {
			return err
		}
		revoked = ok
		if !ok {
			return ErrKeyUnavailable
		}
		return nil
	}); err != nil {
		return mapKeyError(err)
	}
	_ = revoked
	s.logger.Info("令牌签名密钥已撤销", "kid", kid)
	return nil
}

// KeyInfos 返回全部签名密钥的公开元数据（不含私钥/密文），供受控管理查询与排障。
func (s *Service) KeyInfos(ctx context.Context) ([]KeyInfo, error) {
	records, err := s.opts.Store.ListKeys(ctx)
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	infos := make([]KeyInfo, 0, len(records))
	for _, record := range records {
		infos = append(infos, keyInfoOf(record))
	}
	return infos, nil
}

// normalizeContext 把 nil ctx 当成 Background。
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
