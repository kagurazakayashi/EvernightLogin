package bootstrap

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
)

// AuditRecorder 是首次初始化依赖的安全审计写入契约；生产实现为 *audit.Recorder。
// 使用接口便于测试注入故障，但任何实现都必须提供 fail-closed 语义：返回错误时
// 调用方拒绝操作，不能静默丢弃审计。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// CredentialService 是首次初始化需要的一次性凭证能力子集，生产实现为
// *credential.Service。它保证签发结果只在返回中出现一次，服务端只保存摘要。
type CredentialService interface {
	Issue(ctx context.Context, request credential.IssueRequest) (credential.IssuedCredential, error)
	Replace(ctx context.Context, request credential.IssueRequest) (credential.IssuedCredential, error)
	VerifyAndConsume(ctx context.Context, request credential.VerifyRequest) (credential.VerifiedCredential, error)
	Cancel(ctx context.Context, request credential.CancelRequest) error
}

// Options 是构造首次初始化服务的显式依赖。
type Options struct {
	// Store 是初始化状态持久化；必填。
	Store Store
	// Audit 是安全审计写入器；必填，初始化/兑换要求审计与业务一致提交。
	Audit AuditRecorder
	// Authorizer 判定可信调用者权限；必填，没有默认放行实现。
	Authorizer Authorizer
	// Credentials 是一次性凭证服务；必填。
	Credentials CredentialService
	// Now 是可注入时钟；nil 使用 time.Now。所有时间统一 UTC 毫秒。
	Now func() time.Time
	// Random 是安全随机源；nil 使用 crypto/rand.Reader。用于生成 root 用户 ID。
	Random io.Reader
	// Logger 是运行日志器；nil 使用丢弃输出。日志不记录凭证明文或摘要。
	Logger *slog.Logger
}

// Service 是本地受控首次初始化领域服务。构造后不可变，可被多个 goroutine 并发
// 使用；它不启动后台协程、不提供 HTTP 端点、不缓存 root 或凭证数据。
//
// 进程内使用互斥串行化初始化/兑换/重签，使同一 Service 上的并发初始化只有一次
// 成功；跨进程仍由数据库唯一约束与条件插入保证至多一个 root（第一版不承诺多实例
// 部署，并发写冲突按可重试的存储不可用处理）。
type Service struct {
	store       Store
	audit       AuditRecorder
	authorizer  Authorizer
	credentials CredentialService
	now         func() time.Time
	random      io.Reader
	logger      *slog.Logger
	mu          sync.Mutex
}

// New 校验依赖并构造首次初始化服务。缺少 Store/Audit/Authorizer/Credentials 时
// 返回 ErrOptionsInvalid，不会创建替代实现、默认放行权限或默认密码。
func New(options Options) (*Service, error) {
	if isNilInterface(options.Store) {
		return nil, fmt.Errorf("%w: 初始化存储为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.Audit) {
		return nil, fmt.Errorf("%w: 安全审计写入器为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.Authorizer) {
		return nil, fmt.Errorf("%w: 授权器为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.Credentials) {
		return nil, fmt.Errorf("%w: 一次性凭证服务为空", ErrOptionsInvalid)
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
		logger = discardLogger()
	}
	return &Service{
		store:       options.Store,
		audit:       options.Audit,
		authorizer:  options.Authorizer,
		credentials: options.Credentials,
		now:         now,
		random:      random,
		logger:      logger,
	}, nil
}

// Initialize 创建唯一 root 并签发一次性、本机、短期配置凭证。
//
// 行为与安全不变量：
//   - 只允许可信本地管理员调用；root 用户名固定为 root，资料字段走账户白名单，
//     请求不能提交 is_root、status、security_version 或密码字段。
//   - 不保存任何密码或密码哈希，不签发会话/令牌；返回的是一次性配置凭证明文本
//     身（只出现一次）。root 创建后处于 StatePendingSetup 受限待配置状态。
//   - 若 root 或初始化记录已存在，创建入口关闭，返回 ErrAlreadyInitialized 并写
//     失败审计；已有 root 但缺初始化记录时同样拒绝自动接管。
//   - root 行与初始化记录在同一审计事务中条件插入：任一失败整体回滚，不会留下
//     半个 root 或“有 root 无记录”的中间态；审计不可用时拒绝创建。
//   - 创建失败会尽力撤销本次签发的一次性凭证；即使撤销失败，该凭证的目标是
//     本次生成的、未落库的 root 用户 ID，无法用于后续兑换。
//
// 并发：同一 Service 内互斥串行化；数据库条件插入与 ux_single_root 唯一索引是
// 跨进程的最后防线，最多创建一个 root。
func (s *Service) Initialize(ctx context.Context, caller Caller, request InitializeRequest) (InitializeResult, error) {
	if err := s.authorize(ctx, caller, ActionInitialize); err != nil {
		return InitializeResult{}, err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return InitializeResult{}, err
	}
	ttl, err := normalizeSetupCredentialTTL(request.SetupCredentialTTL)
	if err != nil {
		return InitializeResult{}, err
	}
	nickname, err := account.NormalizeNickname(request.RootNickname)
	if err != nil {
		return InitializeResult{}, fmt.Errorf("%w: root 昵称不符合账户资料白名单", ErrInvalidRequest)
	}
	if nickname == "" {
		nickname = DefaultRootNickname
	}
	language, err := account.NormalizeLanguage(request.RootLanguage)
	if err != nil {
		return InitializeResult{}, fmt.Errorf("%w: root 语言标签无效", ErrInvalidRequest)
	}
	timezone, err := account.NormalizeTimezone(request.RootTimezone)
	if err != nil {
		return InitializeResult{}, fmt.Errorf("%w: root 时区无效", ErrInvalidRequest)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// 预检查给出针对性错误码与失败审计；事务内的条件插入仍是最终保证。
	current, found, err := s.store.GetInitialization(ctx)
	if err != nil {
		return InitializeResult{}, s.storeFailure(ctx, "读取初始化状态", err)
	}
	if found {
		return InitializeResult{}, s.rejected(ctx, caller, ActionInitialize, current.RootUserID,
			"already_initialized", CodeConflict, ErrAlreadyInitialized)
	}
	existingRoot, rootFound, err := s.store.GetRootAccount(ctx)
	if err != nil {
		return InitializeResult{}, s.storeFailure(ctx, "读取 root 账户", err)
	}
	if rootFound {
		return InitializeResult{}, s.rejected(ctx, caller, ActionInitialize, existingRoot.UserID,
			"existing_root_without_initialization", CodeConflict, ErrAlreadyInitialized)
	}

	rootID, err := account.NewUserID(s.random)
	if err != nil {
		return InitializeResult{}, fmt.Errorf("%w: 无法生成 root 用户 ID", ErrStoreUnavailable)
	}
	now := s.clockNow()
	root := account.User{
		ID:                 rootID,
		Username:           RootUsername,
		UsernameNormalized: RootUsernameNormalized,
		Nickname:           nickname,
		Language:           language,
		Timezone:           timezone,
		Status:             account.StatusActive,
		RowVersion:         1,
		SecurityVersion:    1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	issued, err := s.credentials.Issue(ctx, credential.IssueRequest{
		Kind:        credential.KindToken,
		Purpose:     PurposeRootSetup,
		Target:      rootID,
		TTL:         ttl,
		MaxAttempts: 1,
	})
	if err != nil {
		return InitializeResult{}, s.credentialFailure(ctx, "签发一次性配置凭证", err)
	}
	record := Record{
		RootUserID:        rootID,
		State:             StatePendingSetup,
		SetupCredentialID: issued.ID,
		StartedBy:         caller.actor.ID,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	event := audit.Event{
		Actor:     caller.actor,
		Action:    string(ActionInitialize),
		Target:    audit.Target{Type: "root", ID: rootID},
		RequestID: caller.requestID,
		Changes: []audit.FieldChange{
			{Field: "root_user_id", After: rootID},
			{Field: "root_username", After: RootUsername},
			{Field: "state", After: string(StatePendingSetup)},
			{Field: "setup_credential_id", After: issued.ID},
			{Field: "setup_credential_expires_at", After: issued.ExpiresAt.Format(time.RFC3339)},
		},
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "root.initialize_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.store.Create(txCtx, tx, root, record)
	})
	if err != nil {
		// 创建失败：尽力撤销本次签发的一次性凭证，避免遗留看似可用的活动凭证。
		s.cancelIssuedCredential(ctx, issued)
		return InitializeResult{}, mapCriticalError(err)
	}
	s.logger.Info("root 首次初始化已创建（受限待配置状态）",
		"root_user_id", rootID,
		"credential_id", issued.ID,
		"expires_at", issued.ExpiresAt,
	)
	return InitializeResult{Root: root, State: StatePendingSetup, SetupCredential: issued}, nil
}

// Status 读取初始化状态与一次性配置凭证的安全诊断信息，并写读取审计；审计失败
// 时拒绝返回数据（fail-closed）。它不返回凭证摘要、秘密或密码材料。
func (s *Service) Status(ctx context.Context, caller Caller) (Status, error) {
	if err := s.authorize(ctx, caller, ActionStatus); err != nil {
		return Status{}, err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return Status{}, err
	}
	// 与 Initialize/Redeem/Reissue 共用同一互斥：状态读取需要“先读初始化记录、
	// 再读 root、最后读凭证”三段查询，若与初始化提交窗口交错，可能短暂看到
	// “root 已存在但无初始化记录”而误报 existing_root。进程内串行化消除该窗口；
	// 跨进程提交窗口另由下方“root 存在但记录缺失时重读一次记录”兜底。
	s.mu.Lock()
	defer s.mu.Unlock()

	record, found, err := s.store.GetInitialization(ctx)
	if err != nil {
		return Status{}, s.storeFailure(ctx, "读取初始化状态", err)
	}
	root, rootFound, err := s.store.GetRootAccount(ctx)
	if err != nil {
		return Status{}, s.storeFailure(ctx, "读取 root 账户", err)
	}
	if !found && rootFound {
		// root 行与初始化记录在同一个数据库事务中提交；若另一进程/连接刚提交，
		// 本次读取可能先看到 root 后看到记录。重读一次记录，避免把提交窗口误报为
		// existing_root（重读仍缺失时才视为真实的旧数据/人工数据）。
		retried, retryFound, retryErr := s.store.GetInitialization(ctx)
		if retryErr != nil {
			return Status{}, s.storeFailure(ctx, "重读初始化状态", retryErr)
		}
		if retryFound {
			record, found = retried, true
		}
	}
	currentTime := s.clockNow()
	status := Status{State: StateUninitialized}
	if rootFound {
		status.RootExists = true
		status.RootUserID = root.UserID
		status.RootUsername = root.Username
		status.RootStatus = root.Status
		status.RootSecurityVersion = root.SecurityVersion
	}
	if !found {
		if rootFound {
			status.State = StateExistingRoot
		}
		return status, s.recordRead(ctx, caller, status.RootUserID)
	}
	if !record.State.persisted() {
		return Status{}, fmt.Errorf("%w: 初始化状态数据无效", ErrStoreUnavailable)
	}
	if !rootFound {
		// 0008 的 root_user_id 外键与 ON DELETE RESTRICT 保证记录存在时 root 必在；
		// 这里按存储数据损坏处理，不返回推测状态。
		return Status{}, fmt.Errorf("%w: 初始化记录缺少 root 账户", ErrStoreUnavailable)
	}
	status.State = record.State
	status.StartedBy = record.StartedBy
	status.CreatedAt = record.CreatedAt
	status.UpdatedAt = record.UpdatedAt
	status.VerifiedAt = record.VerifiedAt
	status.ReadyAt = record.ReadyAt
	if record.SetupCredentialID != "" {
		credentialStatus, err := s.store.GetSetupCredentialStatus(ctx, record.SetupCredentialID)
		if err != nil {
			return Status{}, s.storeFailure(ctx, "读取配置凭证状态", err)
		}
		status.SetupCredentialID = record.SetupCredentialID
		status.SetupCredentialUsable = credentialStatus.Usable(currentTime)
		if credentialStatus.Found {
			status.SetupCredentialExpiresAt = credentialStatus.ExpiresAt
			status.SetupCredentialConsumedAt = credentialStatus.ConsumedAt
			status.SetupCredentialRevokedAt = credentialStatus.RevokedAt
			status.SetupCredentialAttempts = credentialStatus.Attempts
			status.SetupCredentialMaxAttempts = credentialStatus.MaxAttempts
		}
	}
	if err := s.recordRead(ctx, caller, status.RootUserID); err != nil {
		return Status{}, err
	}
	return status, nil
}

// RedeemSetupCredential 兑换一次性配置凭证，把受限状态推进到 StateSetupVerified。
//
// 安全语义：
//   - 只允许本地管理员调用；凭证必须仍活动、未过期、未消费、未撤销，用途固定为
//     PurposeRootSetup 且绑定到当前 root 用户 ID；否则统一返回 ErrSetupCredentialInvalid
//     （不区分具体原因，避免凭证探测）。
//   - 凭证消费由凭证服务的原子条件更新完成，并发兑换最多一个成功。
//   - 消费成功后在同一审计事务内条件把状态改为 setup_verified；状态更新失败时
//     凭证已消费但状态保持 pending_setup，可通过重新签发凭证恢复，不会重放成功。
//   - 返回的 SetupGrant 不是会话或令牌，不能用于远程管理；本步不签发完整管理员
//     会话，正式密码/强认证仍由后续步骤完成。
func (s *Service) RedeemSetupCredential(ctx context.Context, caller Caller, request RedeemSetupCredentialRequest) (SetupGrant, error) {
	if err := s.authorize(ctx, caller, ActionRedeemSetupCredential); err != nil {
		return SetupGrant{}, err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return SetupGrant{}, err
	}
	if err := validateCredentialInput(request); err != nil {
		return SetupGrant{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record, found, err := s.store.GetInitialization(ctx)
	if err != nil {
		return SetupGrant{}, s.storeFailure(ctx, "读取初始化状态", err)
	}
	if !found {
		return SetupGrant{}, s.rejected(ctx, caller, ActionRedeemSetupCredential, "",
			"not_initialized", CodeReqInvalid, ErrNotInitialized)
	}
	switch record.State {
	case StatePendingSetup:
		// 正常路径。
	case StateSetupVerified, StateReady:
		return SetupGrant{}, s.rejected(ctx, caller, ActionRedeemSetupCredential, record.RootUserID,
			"credential_already_redeemed", CodeConflict, ErrSetupStateConflict)
	default:
		return SetupGrant{}, s.rejected(ctx, caller, ActionRedeemSetupCredential, record.RootUserID,
			"setup_state_invalid", CodeConflict, ErrSetupStateConflict)
	}
	if record.SetupCredentialID == "" || request.CredentialID != record.SetupCredentialID {
		return SetupGrant{}, s.rejected(ctx, caller, ActionRedeemSetupCredential, record.RootUserID,
			"credential_replaced_or_missing", CodeTokenInvalid, ErrSetupCredentialInvalid)
	}
	verified, err := s.credentials.VerifyAndConsume(ctx, credential.VerifyRequest{
		Kind:    credential.KindToken,
		ID:      request.CredentialID,
		Purpose: PurposeRootSetup,
		Target:  record.RootUserID,
		Secret:  request.Secret,
	})
	if err != nil {
		if errors.Is(err, credential.ErrInvalidCredential) {
			return SetupGrant{}, s.rejected(ctx, caller, ActionRedeemSetupCredential, record.RootUserID,
				"setup_credential_invalid", CodeTokenInvalid, ErrSetupCredentialInvalid)
		}
		return SetupGrant{}, s.credentialFailure(ctx, "验证配置凭证", err)
	}
	now := s.clockNow()
	event := audit.Event{
		Actor:     caller.actor,
		Action:    string(ActionRedeemSetupCredential),
		Target:    audit.Target{Type: "root", ID: record.RootUserID},
		RequestID: caller.requestID,
		Changes: []audit.FieldChange{
			{Field: "state", Before: string(StatePendingSetup), After: string(StateSetupVerified)},
			{Field: "setup_credential_id", After: request.CredentialID},
			{Field: "verified_at", After: now.Format(time.RFC3339)},
		},
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "root.setup_redeem_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.store.MarkSetupVerified(txCtx, tx, SetupVerifiedChange{
			RootUserID:   record.RootUserID,
			CredentialID: request.CredentialID,
			Now:          now,
		})
	})
	if err != nil {
		return SetupGrant{}, mapCriticalError(err)
	}
	s.logger.Info("root 一次性配置凭证已兑换（受限配置状态）",
		"root_user_id", record.RootUserID,
		"credential_id", request.CredentialID,
	)
	return SetupGrant{
		RootUserID:   record.RootUserID,
		RootUsername: RootUsername,
		CredentialID: request.CredentialID,
		VerifiedAt:   verified.ConsumedAt,
		State:        StateSetupVerified,
	}, nil
}

// ReissueSetupCredential 为已创建的 root 重新签发一次性本机短期配置凭证。
//
// 用途与边界：
//   - 这是失败初始化的本地可诊断恢复入口：凭证过期、丢失、或因并发/故障在兑换
//     后未完成安全设置时，本地受控操作者可重签凭证继续必要的安全设置。
//   - 不会重建 root、不会改变 root 保护规则、不会签发会话，也不允许在 StateReady
//     之后重开配置入口（返回 ErrAlreadyInitialized）。
//   - 新凭证签发采用 ReplaceActive，同用途/目标的活动旧凭证在同一事务内被撤销，
//     保证任一时刻最多一条可用配置凭证；随后条件更新初始化记录，并发重签最多
//     一次生效。
//
// 失败窗口（已声明）：ReplaceActive 先撤销旧活动凭证并签发新凭证，之后才在审计
// 事务中条件更新初始化记录。若第二步因审计不可用、状态被并发修改或存储故障失败，
// 新凭证会被尽力撤销，因此可能短暂没有任何可用配置凭证（fail-closed：不会留下
// 未记录的状态变化，也不会伪造成功审计）。调用方重新调用本方法即可再次签发，
// 不需要重建 root；本步不实现完整 root 应急重置。
func (s *Service) ReissueSetupCredential(ctx context.Context, caller Caller, request ReissueSetupCredentialRequest) (ReissueSetupCredentialResult, error) {
	if err := s.authorize(ctx, caller, ActionReissueSetupCredential); err != nil {
		return ReissueSetupCredentialResult{}, err
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return ReissueSetupCredentialResult{}, err
	}
	ttl, err := normalizeSetupCredentialTTL(request.SetupCredentialTTL)
	if err != nil {
		return ReissueSetupCredentialResult{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record, found, err := s.store.GetInitialization(ctx)
	if err != nil {
		return ReissueSetupCredentialResult{}, s.storeFailure(ctx, "读取初始化状态", err)
	}
	if !found {
		return ReissueSetupCredentialResult{}, s.rejected(ctx, caller, ActionReissueSetupCredential, "",
			"not_initialized", CodeReqInvalid, ErrNotInitialized)
	}
	switch record.State {
	case StatePendingSetup, StateSetupVerified:
		// 受限待配置阶段允许本地恢复；ready 之后配置入口关闭。
	case StateReady:
		return ReissueSetupCredentialResult{}, s.rejected(ctx, caller, ActionReissueSetupCredential, record.RootUserID,
			"initialization_completed", CodeConflict, ErrAlreadyInitialized)
	default:
		return ReissueSetupCredentialResult{}, s.rejected(ctx, caller, ActionReissueSetupCredential, record.RootUserID,
			"setup_state_invalid", CodeConflict, ErrSetupStateConflict)
	}
	issued, err := s.credentials.Replace(ctx, credential.IssueRequest{
		Kind:          credential.KindToken,
		Purpose:       PurposeRootSetup,
		Target:        record.RootUserID,
		TTL:           ttl,
		MaxAttempts:   1,
		ReplaceActive: true,
	})
	if err != nil {
		return ReissueSetupCredentialResult{}, s.credentialFailure(ctx, "重新签发一次性配置凭证", err)
	}
	now := s.clockNow()
	event := audit.Event{
		Actor:     caller.actor,
		Action:    string(ActionReissueSetupCredential),
		Target:    audit.Target{Type: "root", ID: record.RootUserID},
		RequestID: caller.requestID,
		Changes: []audit.FieldChange{
			{Field: "setup_credential_id", Before: record.SetupCredentialID, After: issued.ID},
			{Field: "state", Before: string(record.State), After: string(StatePendingSetup)},
			{Field: "setup_credential_expires_at", After: issued.ExpiresAt.Format(time.RFC3339)},
		},
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "root.setup_reissue_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.store.UpdateSetupCredential(txCtx, tx, CredentialReissueChange{
			RootUserID:           record.RootUserID,
			PreviousCredentialID: record.SetupCredentialID,
			NewCredentialID:      issued.ID,
			Now:                  now,
		})
	})
	if err != nil {
		// 状态更新失败：撤销刚落库的新凭证并返回冲突；旧状态不被覆盖。
		s.cancelIssuedCredential(ctx, issued)
		return ReissueSetupCredentialResult{}, mapCriticalError(err)
	}
	s.logger.Info("root 一次性配置凭证已重新签发",
		"root_user_id", record.RootUserID,
		"credential_id", issued.ID,
		"expires_at", issued.ExpiresAt,
	)
	return ReissueSetupCredentialResult{
		RootUserID:      record.RootUserID,
		State:           StatePendingSetup,
		SetupCredential: issued,
	}, nil
}

// authorize 校验可信调用身份与授权结果。任何缺失或未获准的身份一律
// ErrAccessDenied；不读取请求参数中的自称身份，也不接受匿名调用。
func (s *Service) authorize(ctx context.Context, caller Caller, action Action) error {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if !action.Valid() {
		return ErrAccessDenied
	}
	if err := caller.actor.Validate(); err != nil {
		return ErrAccessDenied
	}
	if err := s.authorizer.Authorize(ctx, caller, action); err != nil {
		return fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	return nil
}

// recordRead 写成功读取审计；审计失败返回 ErrAuditUnavailable，调用方不返回数据。
func (s *Service) recordRead(ctx context.Context, caller Caller, rootUserID string) error {
	event := audit.Event{
		Actor:     caller.actor,
		Action:    string(ActionStatus),
		Target:    audit.Target{Type: "root", ID: rootUserID},
		Outcome:   audit.OutcomeSuccess,
		RequestID: caller.requestID,
	}
	if err := s.audit.Record(ctx, event); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	return nil
}

// rejected 写入一条拒绝/失败审计，并把审计失败与原拒绝错误合并返回。审计失败
// 不会被静默忽略（fail-closed 证据优先），但不改变对外错误码判定顺序。
func (s *Service) rejected(ctx context.Context, caller Caller, action Action, rootUserID, reason string, code ErrorCode, cause error) error {
	event := audit.Event{
		Actor:      caller.actor,
		Action:     string(action),
		Target:     audit.Target{Type: "root", ID: rootUserID},
		Outcome:    audit.OutcomeFailure,
		ErrorCode:  string(code),
		ReasonCode: reason,
		RequestID:  caller.requestID,
	}
	if err := s.audit.RecordFailure(ctx, event); err != nil {
		return errors.Join(cause, fmt.Errorf("%w: %w", ErrAuditUnavailable, err))
	}
	return cause
}

// cancelIssuedCredential 尽力撤销已签发但未能与 root 创建一起提交的配置凭证。
// 使用独立于取消的上下文；失败只记录告警，不影响返回真实初始化错误。
func (s *Service) cancelIssuedCredential(ctx context.Context, issued credential.IssuedCredential) {
	cancelCtx := context.WithoutCancel(normalizeContext(ctx))
	if err := s.credentials.Cancel(cancelCtx, credential.CancelRequest{
		ID:      issued.ID,
		Purpose: issued.Purpose,
		Target:  issued.Target,
		AppID:   issued.AppID,
	}); err != nil {
		s.logger.Warn("撤销未提交的初始化配置凭证失败（凭证将自然过期且目标 root 未落库）",
			"credential_id", issued.ID,
			"error", err,
		)
	}
}

// storeFailure 把存储错误映射为对外安全的 ErrStoreUnavailable；保留 context
// 取消/超时语义，原始错误只写运行日志。
func (s *Service) storeFailure(ctx context.Context, operation string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, ErrStoreUnavailable) {
		return err
	}
	s.logger.Warn("首次初始化存储操作失败", "operation", operation, "error", err)
	return fmt.Errorf("%w: %s", ErrStoreUnavailable, operation)
}

// credentialFailure 把凭证服务错误映射为对外安全错误；凭证无效由调用方单独
// 处理，这里处理存储/配置故障。保留 context 语义，不把原始错误文本透出。
func (s *Service) credentialFailure(ctx context.Context, operation string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	s.logger.Warn("首次初始化一次性凭证操作失败", "operation", operation, "error", err)
	return fmt.Errorf("%w: %s", ErrStoreUnavailable, operation)
}

// clockNow 返回统一截断到 UTC 毫秒的当前时间，与数据库毫秒列一致。
func (s *Service) clockNow() time.Time {
	return s.now().UTC().Truncate(time.Millisecond)
}

// mapCriticalError 把审计事务错误映射为初始化领域错误。审计失败优先判定，避免
// 把“失败证据未能可靠保存”伪装成普通业务冲突。
func mapCriticalError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, audit.ErrAuditUnavailable):
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	case errors.Is(err, ErrAlreadyInitialized),
		errors.Is(err, ErrRootUsernameTaken),
		errors.Is(err, ErrSetupStateConflict),
		errors.Is(err, ErrInvalidRequest):
		return err
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, audit.ErrInvalidEvent):
		return fmt.Errorf("%w: 审计事件无效", ErrOptionsInvalid)
	case errors.Is(err, ErrStoreUnavailable):
		return err
	default:
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
}

// normalizeContext 把 nil ctx 当成 Background，避免调用方漏传导致 panic。
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// discardLogger 返回写入丢弃输出的日志器，用于未注入日志器的内部调用。
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

// isNilInterface 检测 nil 接口与 typed nil 指针，避免服务调用时 panic。
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
