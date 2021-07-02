package webhook

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/netguard"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// Enqueuer 是投递任务入队最小契约；生产实现 *task.Executor。
type Enqueuer interface {
	Enqueue(ctx context.Context, request task.EnqueueRequest) (task.Job, error)
}

// Canceller 是任务取消最小契约；生产实现 *task.Executor。
type Canceller interface {
	RequestCancel(ctx context.Context, request task.CancelRequest) (task.CancelResult, error)
}

// Options 是 Webhook 服务依赖；Store/Audit/Authorizer/Sensitive/Sealer/Enqueuer
// 缺失时拒绝构造（fail-closed）。Canceller 缺失时取消投递不可用（不影响投递）。
type Options struct {
	Store      Store
	Audit      AuditRecorder
	Authorizer Authorizer
	// Sensitive 是步骤 38/39 敏感操作执行前校验（生产 *reauth.Service）；端点安全
	// 设置与签名密钥变更必须经它判定近期认证，缺失拒绝构造。
	Sensitive reauth.OperationRunner
	// Sealer 加密签名密钥（purpose webhook.signing，scope system）；必填。
	Sealer *secrets.Sealer
	// Enqueuer 是投递任务入队器；必填。
	Enqueuer Enqueuer
	// Canceller 是任务取消能力；nil 时 CancelDelivery fail-closed 拒绝。
	Canceller Canceller
	// Resolver 是出站 DNS 解析契约；nil 使用 net.DefaultResolver。测试可注入假解析器。
	Resolver netguard.IPResolver
	// NetworkPolicy 是出站目标策略；零值使用安全默认（https/443/默认不重定向）。
	NetworkPolicy netguard.Policy
	// MaxAttempts 是默认投递尝试上限；0 使用 DefaultMaxAttempts。
	MaxAttempts int
	// TimeoutSeconds 是单次投递任务墙钟超时；0 使用 DefaultDeliveryTimeoutSeconds。
	// 单次 HTTP 请求超时由服务自动推导为严格小于墙钟预算（约 60%，且至少比墙钟
	// 少 2 秒、不少于 netguard 下限），使网络超时先于任务期限发生并进入可重试
	// 失败，而不是被误判为“取消”。
	TimeoutSeconds int
	// SecretGracePeriod 是签名密钥轮换过渡期；0 使用 DefaultSecretGracePeriod。
	SecretGracePeriod time.Duration
	Now               func() time.Time
	Random            io.Reader
	Logger            *slog.Logger
}

// Service 是 Webhook 端点、签名密钥与投递服务。构造后不可变、可并发使用；不启动
// 协程、不提供 HTTP 路由；投递由宿主把 Handler 注册到 internal/task 执行器。
type Service struct {
	opts           Options
	validator      *netguard.Validator
	maxAttempts    int
	timeout        int
	requestTimeout time.Duration
	grace          time.Duration
}

// New 校验依赖并构造服务。
func New(options Options) (*Service, error) {
	if isNil(options.Store) {
		return nil, fmt.Errorf("%w: 存储为空", ErrOptionsInvalid)
	}
	if isNil(options.Audit) {
		return nil, fmt.Errorf("%w: 审计写入器为空", ErrOptionsInvalid)
	}
	if isNil(options.Authorizer) {
		return nil, fmt.Errorf("%w: 授权器为空", ErrOptionsInvalid)
	}
	if isNil(options.Sensitive) {
		return nil, fmt.Errorf("%w: 敏感策略执行器为空（Webhook 安全设置必须再次验证）",
			ErrOptionsInvalid)
	}
	if isNil(options.Sealer) {
		return nil, fmt.Errorf("%w: 签名密钥加密器为空", ErrOptionsInvalid)
	}
	if isNil(options.Enqueuer) {
		return nil, fmt.Errorf("%w: 任务入队器为空", ErrOptionsInvalid)
	}
	maxAttempts := options.MaxAttempts
	if maxAttempts == 0 {
		maxAttempts = DefaultMaxAttempts
	}
	if maxAttempts < MinMaxAttempts || maxAttempts > MaxMaxAttempts {
		return nil, fmt.Errorf("%w: 尝试上限必须在 %d～%d 之间", ErrOptionsInvalid,
			MinMaxAttempts, MaxMaxAttempts)
	}
	timeout := options.TimeoutSeconds
	if timeout == 0 {
		timeout = DefaultDeliveryTimeoutSeconds
	}
	if timeout < MinDeliveryTimeoutSeconds || timeout > MaxDeliveryTimeoutSeconds {
		return nil, fmt.Errorf("%w: 投递超时必须在 %d～%d 秒之间", ErrOptionsInvalid,
			MinDeliveryTimeoutSeconds, MaxDeliveryTimeoutSeconds)
	}
	grace := options.SecretGracePeriod
	if grace == 0 {
		grace = DefaultSecretGracePeriod
	}
	if grace < MinSecretGracePeriod || grace > MaxSecretGracePeriod {
		return nil, fmt.Errorf("%w: 签名密钥过渡期必须在 %s～%s 之间", ErrOptionsInvalid,
			MinSecretGracePeriod, MaxSecretGracePeriod)
	}
	// 单次 HTTP 请求超时必须严格小于任务墙钟预算：网络/端点超时先触发并走可重试
	// 失败（failed/queued + TASK_TIMEOUT），只有真正取消才写 cancelled。
	requestTimeout := time.Duration(timeout) * time.Second * 3 / 5
	if maxRequest := time.Duration(timeout)*time.Second - 2*time.Second; requestTimeout > maxRequest {
		requestTimeout = maxRequest
	}
	if requestTimeout < netguard.MinTimeout {
		requestTimeout = netguard.MinTimeout
	}
	if requestTimeout >= time.Duration(timeout)*time.Second {
		return nil, fmt.Errorf("%w: 无法推导严格小于任务超时的请求超时", ErrOptionsInvalid)
	}
	networkPolicy := options.NetworkPolicy
	// 出站客户端超时统一由服务推导，宿主策略只控制地址/重定向/字节/主机限制。
	networkPolicy.Timeout = requestTimeout
	validator, err := netguard.NewValidator(networkPolicy, options.Resolver)
	if err != nil {
		return nil, fmt.Errorf("%w: 出站网络策略无效: %v", ErrOptionsInvalid, err)
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
	return &Service{opts: options, validator: validator, maxAttempts: maxAttempts,
		timeout: timeout, requestTimeout: requestTimeout, grace: grace}, nil
}

// RegisterEndpointRequest 是登记端点请求；服务端生成初始签名密钥并只返回一次明文。
type RegisterEndpointRequest struct {
	ApplicationID string
	URL           string
	Description   string
	RequestID     string
}

// RegisterEndpointResult 是登记结果。
type RegisterEndpointResult struct {
	Endpoint Endpoint
	Secret   RevealedSecret
}

// UpdateEndpointRequest 是修改端点请求；ExpectedRowVersion 用于并发单赢家。
type UpdateEndpointRequest struct {
	EndpointID         string
	URL                string
	Description        string
	Status             EndpointStatus
	ExpectedRowVersion int64
	RequestID          string
}

// RegisterEndpoint 登记应用级 Webhook 端点并生成首个签名密钥。
func (s *Service) RegisterEndpoint(ctx context.Context, caller Caller,
	request RegisterEndpointRequest) (RegisterEndpointResult, error) {
	ctx = normalizeContext(ctx)
	requestID, err := s.validateManagementRequest(caller, request.RequestID)
	if err != nil {
		return RegisterEndpointResult{}, err
	}
	applicationID := strings.TrimSpace(request.ApplicationID)
	if len(applicationID) != 36 || len(request.URL) == 0 {
		return RegisterEndpointResult{}, fmt.Errorf("%w: 应用或 URL 无效", ErrInvalidRequest)
	}
	active, err := s.opts.Store.ApplicationActive(ctx, applicationID)
	if err != nil {
		return RegisterEndpointResult{}, ErrStoreUnavailable
	}
	if !active {
		return RegisterEndpointResult{}, fmt.Errorf("%w: 应用未启用", ErrAccessDenied)
	}
	count, err := s.opts.Store.CountEndpoints(ctx, applicationID)
	if err != nil {
		return RegisterEndpointResult{}, ErrStoreUnavailable
	}
	if count >= MaxEndpointsPerApp {
		return RegisterEndpointResult{}, fmt.Errorf("%w: 端点数量已达上限", ErrConflict)
	}
	target, err := s.validator.ValidateURL(request.URL)
	if err != nil {
		s.recordFailure(ctx, caller.actor, "webhook.endpoint.register_denied",
			applicationID, "endpoint_blocked", CodeWebhookEndpointBlocked, requestID)
		return RegisterEndpointResult{}, fmt.Errorf("%w: %v", ErrEndpointBlocked, err)
	}
	description, err := normalizeDescription(request.Description)
	if err != nil {
		return RegisterEndpointResult{}, err
	}
	now := s.now()
	endpoint := EndpointRecord{
		ID:            mustNewID(s.opts.Random, endpointIDPrefix),
		ApplicationID: applicationID, URL: target.String(), Description: description,
		Status: EndpointActive, RowVersion: 1, CreatedAt: now, UpdatedAt: now,
	}
	secret, secretRecord, err := s.newSecretRecord(endpoint.ID, now)
	if err != nil {
		return RegisterEndpointResult{}, err
	}
	guard, err := s.authorizeSensitive(ctx, caller, operationEndpointChange, applicationID,
		endpoint.ID, map[string]string{
			"application_id": applicationID, "endpoint_id": endpoint.ID,
			"url": target.String(), "action": "register", "request_id": requestID,
		}, "登记应用安全事件 Webhook 端点", requestID)
	if err != nil {
		s.recordFailure(ctx, caller.actor, "webhook.endpoint.register_denied",
			applicationID, "reauth_rejected", CodeOf(err), requestID)
		return RegisterEndpointResult{}, err
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.actor, AppID: applicationID, Action: "webhook.endpoint.registered",
			Target:    audit.Target{Type: "webhook_endpoint", ID: endpoint.ID},
			RequestID: requestID,
			Changes: []audit.FieldChange{
				{Field: "url", After: truncate(target.String(), 200)},
				{Field: "secret_prefix", After: secretRecord.Prefix},
			},
		},
		FailureReasonCode: "webhook.endpoint.register_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context,
		tx audit.Tx) error {
		if err := s.opts.Store.CreateEndpointTx(txCtx, tx, endpoint); err != nil {
			return err
		}
		return s.opts.Store.CreateSecretTx(txCtx, tx, secretRecord)
	}); err != nil {
		return RegisterEndpointResult{}, mapCriticalError(err)
	}
	s.notifySensitive(ctx, guard)
	return RegisterEndpointResult{Endpoint: endpointView(endpoint), Secret: secret}, nil
}

// UpdateEndpoint 修改端点 URL/描述/状态（row_version 并发单赢家）。
func (s *Service) UpdateEndpoint(ctx context.Context, caller Caller,
	request UpdateEndpointRequest) (Endpoint, error) {
	ctx = normalizeContext(ctx)
	requestID, err := s.validateManagementRequest(caller, request.RequestID)
	if err != nil {
		return Endpoint{}, err
	}
	if !validEndpointID(request.EndpointID) || request.ExpectedRowVersion <= 0 {
		return Endpoint{}, fmt.Errorf("%w: 端点或版本无效", ErrInvalidRequest)
	}
	if !request.Status.Valid() {
		return Endpoint{}, fmt.Errorf("%w: 端点状态无效", ErrInvalidRequest)
	}
	current, found, err := s.opts.Store.GetEndpoint(ctx, request.EndpointID)
	if err != nil {
		return Endpoint{}, ErrStoreUnavailable
	}
	if !found {
		return Endpoint{}, ErrEndpointNotFound
	}
	if request.ExpectedRowVersion != current.RowVersion {
		return Endpoint{}, ErrConflict
	}
	target, err := s.validator.ValidateURL(request.URL)
	if err != nil {
		s.recordFailure(ctx, caller.actor, "webhook.endpoint.update_denied",
			current.ApplicationID, "endpoint_blocked", CodeWebhookEndpointBlocked, requestID)
		return Endpoint{}, fmt.Errorf("%w: %v", ErrEndpointBlocked, err)
	}
	description, err := normalizeDescription(request.Description)
	if err != nil {
		return Endpoint{}, err
	}
	guard, err := s.authorizeSensitive(ctx, caller, operationEndpointChange,
		current.ApplicationID, current.ID, map[string]string{
			"application_id": current.ApplicationID, "endpoint_id": current.ID,
			"url": target.String(), "status": string(request.Status), "action": "update",
			"request_id": requestID,
		}, "修改应用安全事件 Webhook 端点", requestID)
	if err != nil {
		s.recordFailure(ctx, caller.actor, "webhook.endpoint.update_denied",
			current.ApplicationID, "reauth_rejected", CodeOf(err), requestID)
		return Endpoint{}, err
	}
	updated := current
	updated.URL = target.String()
	updated.Description = description
	updated.Status = request.Status
	updated.RowVersion = current.RowVersion + 1
	updated.UpdatedAt = s.now()
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.actor, AppID: current.ApplicationID, Action: "webhook.endpoint.updated",
			Target:    audit.Target{Type: "webhook_endpoint", ID: current.ID},
			RequestID: requestID,
			Changes: []audit.FieldChange{
				{Field: "url", Before: truncate(current.URL, 200), After: truncate(updated.URL, 200)},
				{Field: "status", Before: string(current.Status), After: string(updated.Status)},
				{Field: "row_version", Before: strconv.FormatInt(current.RowVersion, 10),
					After: strconv.FormatInt(updated.RowVersion, 10)},
			},
		},
		FailureReasonCode: "webhook.endpoint.update_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context,
		tx audit.Tx) error {
		ok, updateErr := s.opts.Store.UpdateEndpointTx(txCtx, tx, updated)
		if updateErr != nil {
			return updateErr
		}
		if !ok {
			return ErrConflict
		}
		return nil
	}); err != nil {
		return Endpoint{}, mapCriticalError(err)
	}
	s.notifySensitive(ctx, guard)
	return endpointView(updated), nil
}

// ListEndpoints 列出应用端点（Authorizer 按应用范围判定）。
func (s *Service) ListEndpoints(ctx context.Context, caller Caller,
	applicationID string) ([]Endpoint, error) {
	ctx = normalizeContext(ctx)
	if err := s.authorize(ctx, caller, ActionReadEndpoint, applicationID); err != nil {
		return nil, err
	}
	records, err := s.opts.Store.ListEndpointsByApp(ctx, applicationID)
	if err != nil {
		return nil, err
	}
	views := make([]Endpoint, 0, len(records))
	for _, record := range records {
		views = append(views, endpointView(record))
	}
	return views, nil
}

// ListSecrets 列出端点签名密钥元数据（不含明文）。
func (s *Service) ListSecrets(ctx context.Context, caller Caller,
	endpointID string) ([]SecretInfo, error) {
	ctx = normalizeContext(ctx)
	record, found, err := s.opts.Store.GetEndpoint(ctx, endpointID)
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	if !found {
		return nil, ErrEndpointNotFound
	}
	if err := s.authorize(ctx, caller, ActionReadEndpoint, record.ApplicationID); err != nil {
		return nil, err
	}
	records, err := s.opts.Store.ListSecrets(ctx, endpointID)
	if err != nil {
		return nil, err
	}
	infos := make([]SecretInfo, 0, len(records))
	for _, secret := range records {
		infos = append(infos, secretInfo(secret))
	}
	return infos, nil
}

// RotateSecret 生成新签名密钥并把当前可用密钥置为过渡期退役（旧密钥在过渡期内仍
// 参与多签，保证消费方平滑轮换）；可用密钥数超上限时拒绝。
func (s *Service) RotateSecret(ctx context.Context, caller Caller, endpointID,
	requestID string) (RevealedSecret, error) {
	ctx = normalizeContext(ctx)
	requestID, err := s.validateManagementRequest(caller, requestID)
	if err != nil {
		return RevealedSecret{}, err
	}
	record, found, err := s.opts.Store.GetEndpoint(ctx, endpointID)
	if err != nil {
		return RevealedSecret{}, ErrStoreUnavailable
	}
	if !found {
		return RevealedSecret{}, ErrEndpointNotFound
	}
	now := s.now()
	usable, err := s.opts.Store.UsableSecrets(ctx, endpointID, now)
	if err != nil {
		return RevealedSecret{}, err
	}
	if len(usable) >= MaxUsableSecrets {
		return RevealedSecret{}, fmt.Errorf("%w: 可用签名密钥已达上限", ErrConflict)
	}
	secret, secretRecord, err := s.newSecretRecord(endpointID, now)
	if err != nil {
		return RevealedSecret{}, err
	}
	retireAt := now.Add(s.grace)
	guard, err := s.authorizeSensitive(ctx, caller, operationSecretRotate,
		record.ApplicationID, endpointID, map[string]string{
			"application_id": record.ApplicationID, "endpoint_id": endpointID,
			"action": "rotate", "request_id": requestID,
		}, "轮换应用 Webhook 签名密钥", requestID)
	if err != nil {
		s.recordFailure(ctx, caller.actor, "webhook.secret.rotate_denied",
			record.ApplicationID, "reauth_rejected", CodeOf(err), requestID)
		return RevealedSecret{}, err
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.actor, AppID: record.ApplicationID, Action: "webhook.secret.rotated",
			Target:    audit.Target{Type: "webhook_endpoint", ID: endpointID},
			RequestID: requestID,
			Changes: []audit.FieldChange{
				{Field: "secret_prefix", After: secretRecord.Prefix},
				{Field: "retire_at", After: retireAt.UTC().Format(time.RFC3339)},
			},
		},
		FailureReasonCode: "webhook.secret.rotate_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context,
		tx audit.Tx) error {
		if err := s.opts.Store.RetireActiveSecretsTx(txCtx, tx, endpointID, retireAt, now); err != nil {
			return err
		}
		return s.opts.Store.CreateSecretTx(txCtx, tx, secretRecord)
	}); err != nil {
		return RevealedSecret{}, mapCriticalError(err)
	}
	s.notifySensitive(ctx, guard)
	return secret, nil
}

// RevokeSecret 立即撤销指定签名密钥（幂等；重复撤销按成功处理）。
func (s *Service) RevokeSecret(ctx context.Context, caller Caller, endpointID, secretID,
	requestID string) error {
	ctx = normalizeContext(ctx)
	requestID, err := s.validateManagementRequest(caller, requestID)
	if err != nil {
		return err
	}
	if !validEndpointID(endpointID) || len(secretID) == 0 || len(secretID) > 64 {
		return fmt.Errorf("%w: 端点或密钥 ID 无效", ErrInvalidRequest)
	}
	record, found, err := s.opts.Store.GetEndpoint(ctx, endpointID)
	if err != nil {
		return ErrStoreUnavailable
	}
	if !found {
		return ErrEndpointNotFound
	}
	guard, err := s.authorizeSensitive(ctx, caller, operationSecretRotate,
		record.ApplicationID, endpointID, map[string]string{
			"application_id": record.ApplicationID, "endpoint_id": endpointID,
			"secret_id": secretID, "action": "revoke", "request_id": requestID,
		}, "撤销应用 Webhook 签名密钥", requestID)
	if err != nil {
		s.recordFailure(ctx, caller.actor, "webhook.secret.revoke_denied",
			record.ApplicationID, "reauth_rejected", CodeOf(err), requestID)
		return err
	}
	now := s.now()
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.actor, AppID: record.ApplicationID, Action: "webhook.secret.revoked",
			Target:    audit.Target{Type: "webhook_secret", ID: secretID},
			RequestID: requestID,
		},
		FailureReasonCode: "webhook.secret.revoke_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context,
		tx audit.Tx) error {
		_, revokeErr := s.opts.Store.RevokeSecretTx(txCtx, tx, endpointID, secretID, now)
		return revokeErr
	}); err != nil {
		return mapCriticalError(err)
	}
	s.notifySensitive(ctx, guard)
	return nil
}

// ===== 内部辅助 =====

func (s *Service) validateManagementRequest(caller Caller, requestID string) (string, error) {
	if err := caller.actor.Validate(); err != nil {
		return "", fmt.Errorf("%w: 操作者无效", ErrAccessDenied)
	}
	if len(requestID) > 128 {
		return "", fmt.Errorf("%w: 请求编号过长", ErrInvalidRequest)
	}
	if requestID == "" {
		return "", fmt.Errorf("%w: 请求编号必填", ErrInvalidRequest)
	}
	return requestID, nil
}

// authorize 执行 Authorizer；未配置时只有 system/local_admin 主体可用（fail-closed）。
func (s *Service) authorize(ctx context.Context, caller Caller, action Action,
	applicationID string) error {
	if !action.Valid() {
		return fmt.Errorf("%w: 未定义动作", ErrAccessDenied)
	}
	if err := caller.actor.Validate(); err != nil {
		return fmt.Errorf("%w: 操作者无效", ErrAccessDenied)
	}
	if isNil(s.opts.Authorizer) {
		return ErrAccessDenied
	}
	if err := s.opts.Authorizer.Authorize(ctx, caller, action, applicationID); err != nil {
		return fmt.Errorf("%w: %v", ErrAccessDenied, err)
	}
	return nil
}

// authorizeSensitive 在 Authorizer 之外经 internal/reauth 做近期认证/操作绑定校验。
func (s *Service) authorizeSensitive(ctx context.Context, caller Caller, operationID,
	applicationID, endpointID string, params map[string]string,
	description, requestID string) (reauth.Result, error) {
	if err := s.authorize(ctx, caller, ActionManageEndpoint, applicationID); err != nil {
		return reauth.Result{}, err
	}
	reauthCaller, err := reauth.CallerFromActor(caller.actor)
	if err != nil {
		return reauth.Result{}, ErrAccessDenied
	}
	result, err := s.opts.Sensitive.Authorize(ctx, reauthCaller, reauth.Request{
		ScopeID: "system", OperationID: operationID, TargetType: "webhook_endpoint",
		TargetID: endpointID, Params: params, Description: description, RequestID: requestID,
	})
	if err != nil {
		return reauth.Result{}, ErrAccessDenied
	}
	return result, nil
}

func (s *Service) notifySensitive(ctx context.Context, result reauth.Result) {
	if result.OperationID == "" {
		return
	}
	if err := s.opts.Sensitive.NotifyOutcome(ctx, result, reauth.OutcomeSuccess); err != nil {
		s.opts.Logger.Warn("Webhook 敏感操作告知失败", "reason", "notify_unavailable")
	}
}

// newSecretRecord 生成签名密钥明文并加密落库记录。
func (s *Service) newSecretRecord(endpointID string,
	now time.Time) (RevealedSecret, SecretRecord, error) {
	secretValue, err := newSigningSecret(s.opts.Random)
	if err != nil {
		return RevealedSecret{}, SecretRecord{}, err
	}
	secretID := mustNewID(s.opts.Random, secretIDPrefix)
	sealed, err := s.opts.Sealer.Seal(secrets.Binding{
		Purpose: secretPurpose, ObjectID: secretID, ScopeID: secrets.ScopeSystem,
	}, []byte(secretValue))
	if err != nil {
		return RevealedSecret{}, SecretRecord{}, fmt.Errorf("%w: 加密签名密钥", ErrStoreUnavailable)
	}
	keyID, err := secrets.KeyIDOf(sealed)
	if err != nil {
		return RevealedSecret{}, SecretRecord{}, fmt.Errorf("%w: 密钥信封无效", ErrStoreUnavailable)
	}
	record := SecretRecord{
		ID: secretID, EndpointID: endpointID, Prefix: secretPrefix(secretValue),
		SealedSecret: sealed, SealerKeyID: keyID, CreatedAt: now,
	}
	return RevealedSecret{Info: secretInfo(record), secret: secretValue}, record, nil
}

// openSecret 解密签名密钥（只在投递时使用，禁止写日志）。
func (s *Service) openSecret(record SecretRecord) ([]byte, error) {
	plaintext, err := s.opts.Sealer.Open(secrets.Binding{
		Purpose: secretPurpose, ObjectID: record.ID, ScopeID: secrets.ScopeSystem,
	}, record.SealedSecret)
	if err != nil {
		return nil, fmt.Errorf("%w: 解密签名密钥失败", ErrStoreUnavailable)
	}
	return plaintext, nil
}

func (s *Service) now() time.Time { return s.opts.Now().UTC().Truncate(time.Millisecond) }

// recordFailure 写失败审计（best-effort，不改变拒绝结果）。
func (s *Service) recordFailure(ctx context.Context, actor audit.Actor, action, appID,
	reason string, code ErrorCode, requestID string) {
	if actor.Validate() != nil {
		return
	}
	event := audit.Event{
		Actor: actor, AppID: appID, Action: action,
		Target:  audit.Target{Type: "webhook_endpoint", ID: appID},
		Outcome: audit.OutcomeFailure, ErrorCode: string(code),
		ReasonCode: stableReason(reason), RequestID: requestID,
	}
	if err := s.opts.Audit.RecordFailure(ctx, event); err != nil {
		s.opts.Logger.Warn("Webhook 失败审计写入失败", "reason", "audit_unavailable")
	}
}

func mapCriticalError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrConflict) {
		return ErrConflict
	}
	if errors.Is(err, audit.ErrAuditUnavailable) {
		return ErrAuditUnavailable
	}
	return ErrStoreUnavailable
}

func endpointView(record EndpointRecord) Endpoint {
	return Endpoint{
		ID: record.ID, ApplicationID: record.ApplicationID, URL: record.URL,
		Description: record.Description, Status: record.Status, RowVersion: record.RowVersion,
		CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt,
	}
}

func secretInfo(record SecretRecord) SecretInfo {
	return SecretInfo{ID: record.ID, Prefix: record.Prefix, CreatedAt: record.CreatedAt,
		RetireAt: record.RetireAt, RevokedAt: record.RevokedAt}
}

func normalizeDescription(value string) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) > MaxDescriptionBytes {
		return "", fmt.Errorf("%w: 描述过长", ErrInvalidRequest)
	}
	if strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", fmt.Errorf("%w: 描述包含控制字符", ErrInvalidRequest)
	}
	return value, nil
}

func validEndpointID(value string) bool {
	return len(value) == len(endpointIDPrefix)+32 && strings.HasPrefix(value, endpointIDPrefix)
}

// validDeliveryID 报告投递编号格式是否有效。
func validDeliveryID(value string) bool {
	return len(value) == len(deliveryIDPrefix)+32 && strings.HasPrefix(value, deliveryIDPrefix)
}

func truncate(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit]
}

func stableReason(value string) string {
	if len(value) == 0 || len(value) > 64 {
		return "invalid_reason"
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !(character >= 'a' && character <= 'z') && character != '_' &&
			!(character >= '0' && character <= '9') {
			return "invalid_reason"
		}
	}
	return value
}

func mustNewID(random io.Reader, prefix string) string {
	buffer := make([]byte, 16)
	if _, err := io.ReadFull(random, buffer); err != nil {
		panic("webhook: 生成安全随机编号失败")
	}
	return prefix + hex.EncodeToString(buffer)
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
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
