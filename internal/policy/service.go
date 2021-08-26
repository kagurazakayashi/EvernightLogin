package policy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"sort"
	"strconv"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// DefaultPolicyVersion 是没有变更记录时的作用域策略版本。
const DefaultPolicyVersion int64 = 0

// maxVerificationClockSkew 是验证时间允许的未来时钟偏差；超过则视为异常事实。
const maxVerificationClockSkew = time.Minute

// OperationPolicyChange 是“修改敏感策略”这一操作自身的稳定标识；策略修改必须
// 通过宿主再次验证，即使 root 取消其他操作的敏感标记也不能跳过该保护。
const OperationPolicyChange = "security.policy.change"

// AuditRecorder 是安全审计写入契约；实现必须 fail-closed。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// Options 是敏感策略服务依赖。
type Options struct {
	Store Store
	Audit AuditRecorder
	// Catalog 是敏感操作目录；nil 使用 DefaultCatalog。
	Catalog *Catalog
	// ReauthVerifier 是策略修改前的再次验证契约；nil 时策略修改 fail-closed。
	ReauthVerifier ReauthVerifier
	// Authorizer 是附加授权判定；nil 时读默认允许 root/受信 system/local_admin，
	// 写只允许真实 root。注入实现可以进一步限制，但不能放宽“写必须 root”。
	Authorizer Authorizer
	// AvailableStrengths 是当前环境已实现的认证强度；nil 时只认为 none/password
	// 可用（MFA/Passkey 未实现），要求 strong 的策略评估会 fail-closed。
	AvailableStrengths []Strength
	Now                func() time.Time
	Logger             *slog.Logger
}

// Service 是敏感操作策略配置服务。构造后不可变，不启动协程、不签发会话、不执行
// 敏感操作本身（执行器在后续步骤接入）。
type Service struct {
	opts      Options
	catalog   *Catalog
	available map[Strength]bool
}

// New 校验依赖并构造服务。目录或可用强度非法时拒绝构造。
func New(options Options) (*Service, error) {
	if isNil(options.Store) {
		return nil, fmt.Errorf("%w: 策略存储为空", ErrOptionsInvalid)
	}
	if isNil(options.Audit) {
		return nil, fmt.Errorf("%w: 审计写入器为空", ErrOptionsInvalid)
	}
	catalog := options.Catalog
	if catalog == nil {
		catalog = DefaultCatalog()
	}
	if err := catalog.Validate(); err != nil {
		return nil, err
	}
	available := make(map[Strength]bool)
	if len(options.AvailableStrengths) == 0 {
		available[StrengthNone] = true
		available[StrengthPassword] = true
	} else {
		for _, strength := range options.AvailableStrengths {
			if !strength.Known() {
				return nil, fmt.Errorf("%w: 可用认证强度 %q 未知", ErrOptionsInvalid, strength)
			}
			available[strength] = true
		}
		available[StrengthNone] = true
	}
	if !available[StrengthPassword] {
		return nil, fmt.Errorf("%w: 可用认证强度必须包含 password（否则普通敏感操作无法完成）", ErrOptionsInvalid)
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Service{opts: options, catalog: catalog, available: available}, nil
}

// CatalogVersion 返回当前目录版本。
func (s *Service) CatalogVersion() string { return s.catalog.Version }

// Operation 返回目录中某敏感操作的只读定义副本（含不可覆盖约束）。页面与适配器
// 只能读取；策略修改仍必须走 Set/Restore 的 root、再次认证与审计链。
func (s *Service) Operation(operationID string) (Operation, bool) {
	operation, ok := s.catalog.Lookup(operationID)
	return operation, ok
}

// UserIsRoot 报告可信用户调用者当前是否为真实 root。它只读取用户资格，不授予
// 任何写权限；管理页面用它决定是否呈现写控件（真正写入仍由 Set/Restore 强制）。
func (s *Service) UserIsRoot(ctx context.Context, caller Caller) (bool, error) {
	ctx = normalizeContext(ctx)
	if err := caller.actor.Validate(); err != nil {
		return false, ErrAccessDenied
	}
	if !caller.IsUser() {
		return false, nil
	}
	exists, isRoot, err := s.opts.Store.GetUserRoot(ctx, caller.actor.ID)
	if err != nil {
		return false, ErrStoreUnavailable
	}
	return exists && isRoot, nil
}

// AvailableStrengths 返回当前环境已实现并可满足的认证强度（升序，固定包含 none
// 与 password）。页面用它区分“当前环境尚未支持”与“业务执行器未实现”，不得把
// 未实现强度显示为可满足。
func (s *Service) AvailableStrengths() []Strength {
	result := make([]Strength, 0, len(s.available))
	for _, strength := range []Strength{StrengthNone, StrengthPassword, StrengthStrong} {
		if s.available[strength] {
			result = append(result, strength)
		}
	}
	return result
}

// Version 返回作用域当前策略版本；未发生变更时为 0。
func (s *Service) Version(ctx context.Context, caller Caller, scopeID string) (int64, error) {
	ctx = normalizeContext(ctx)
	scope, err := s.resolveScope(ctx, scopeID)
	if err != nil {
		return 0, err
	}
	if err := s.authorizeRead(ctx, caller, scope); err != nil {
		return 0, err
	}
	version, err := s.opts.Store.GetVersion(ctx, scope.ID)
	if err != nil {
		return 0, ErrStoreUnavailable
	}
	return version, nil
}

// Effective 返回作用域的有效策略快照：系统目录默认值合并覆盖行，并追加应用声明
// 操作（仅应用作用域）。
func (s *Service) Effective(ctx context.Context, caller Caller, scopeID string) (Snapshot, error) {
	ctx = normalizeContext(ctx)
	scope, err := s.resolveScope(ctx, scopeID)
	if err != nil {
		return Snapshot{}, err
	}
	if err := s.authorizeRead(ctx, caller, scope); err != nil {
		return Snapshot{}, err
	}
	return s.buildSnapshot(ctx, scope)
}

// Diff 返回作用域相对系统默认策略的差异与应用声明列表。
func (s *Service) Diff(ctx context.Context, caller Caller, scopeID string) (DiffResult, error) {
	ctx = normalizeContext(ctx)
	scope, err := s.resolveScope(ctx, scopeID)
	if err != nil {
		return DiffResult{}, err
	}
	if err := s.authorizeRead(ctx, caller, scope); err != nil {
		return DiffResult{}, err
	}
	snapshot, err := s.buildSnapshot(ctx, scope)
	if err != nil {
		return DiffResult{}, err
	}
	result := DiffResult{ScopeID: scope.ID, Version: snapshot.Version}
	for _, operation := range snapshot.Operations {
		switch operation.Source {
		case SourceOverride:
			changed := policyFieldDiffs(operation.Default, operation.Effective)
			if len(changed) > 0 {
				result.Changed = append(result.Changed, OperationDiff{
					OperationID: operation.OperationID, Source: SourceOverride, Changed: changed})
			}
		case SourceApplication:
			result.Declared = append(result.Declared, OperationDiff{
				OperationID: operation.OperationID, Source: SourceApplication})
		}
	}
	return result, nil
}

// SetRequest 是策略修改请求。Declare=true 时在应用作用域声明一个新的敏感操作，
// 必须提供 Name；系统作用域不能声明新操作（只能覆盖内置目录）。
type SetRequest struct {
	ScopeID         string
	OperationID     string
	Change          PolicyChange
	Declare         bool
	Name            string
	Description     string
	ExpectedVersion int64
	RequestID       string
}

// Set 修改或声明策略，返回变更后的有效快照。只有真实 root 能修改，且必须通过
// ReauthVerifier；成功/失败都在安全审计中记录，版本不匹配返回 CONFLICT。
func (s *Service) Set(ctx context.Context, caller Caller, request SetRequest) (snapshot Snapshot, returnErr error) {
	ctx = normalizeContext(ctx)
	criticalStarted := false
	defer func() {
		if returnErr == nil || criticalStarted {
			return
		}
		// 在审计事务开始前的拒绝也要留失败审计，不能出现“篡改尝试没有任何记录”。
		returnErr = s.recordRejection(ctx, caller, "policy.update", request.ScopeID,
			request.RequestID, returnErr)
	}()
	requestID, err := s.prepareWrite(ctx, caller, request.ScopeID, request.ExpectedVersion, request.RequestID)
	if err != nil {
		return Snapshot{}, err
	}
	scope, err := s.resolveScope(ctx, request.ScopeID)
	if err != nil {
		return Snapshot{}, err
	}
	if !validOperationID(request.OperationID) {
		return Snapshot{}, fmt.Errorf("%w: 操作标识格式非法", ErrInvalidRequest)
	}
	if !request.Change.HasChanges() {
		return Snapshot{}, fmt.Errorf("%w: 没有需要修改的策略字段", ErrInvalidRequest)
	}
	builtin, hasBuiltin := s.catalog.Lookup(request.OperationID)
	existing, hasExisting, err := s.lookupOverride(ctx, scope.ID, request.OperationID)
	if err != nil {
		return Snapshot{}, err
	}
	var base Policy
	immutableSensitive := false
	sourceKind := SourceOverride
	name, description := "", ""
	var previous *Policy
	switch {
	case hasBuiltin && hasExisting && existing.SourceKind == SourceApplication:
		// 内置操作不允许以应用声明行存在（防御历史/外部写入造成的歧义）。
		return Snapshot{}, fmt.Errorf("%w: 内置操作存在非法应用声明行", ErrStoreUnavailable)
	case hasBuiltin:
		// 存在既有覆盖时必须以其当前策略为 base：部分更新只改请求字段，未提交字段
		// 保持此前（可能已加严的）值，不能被默认值静默重置。
		base = builtin.Default
		if hasExisting {
			base = existing.Policy
		}
		immutableSensitive = builtin.ImmutableSensitive
		if request.Declare || request.Name != "" || request.Description != "" {
			return Snapshot{}, fmt.Errorf("%w: 内置目录操作的名称/说明不能通过策略修改", ErrInvalidRequest)
		}
		sourceKind = SourceOverride
	case scope.Application && (request.Declare || hasExisting):
		// 应用自身敏感操作：必须由 root 显式声明并给出直白名称/说明。
		if hasExisting {
			if existing.SourceKind != SourceApplication {
				return Snapshot{}, fmt.Errorf("%w: 应用声明操作与覆盖行冲突", ErrStoreUnavailable)
			}
			base = existing.Policy
			name, description = existing.Name, existing.Description
		}
		if request.Declare {
			if err := validateText("操作中文名称", request.Name, MaxNameRunes, false); err != nil {
				return Snapshot{}, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
			}
			if err := validateText("操作说明", request.Description, MaxDescriptionRunes, true); err != nil {
				return Snapshot{}, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
			}
			name = trimText(request.Name)
			description = trimText(request.Description)
		} else if name == "" {
			return Snapshot{}, fmt.Errorf("%w: 应用声明操作必须提供中文名称", ErrInvalidRequest)
		}
		sourceKind = SourceApplication
	default:
		return Snapshot{}, fmt.Errorf("%w: 操作 %q 未登记；应用作用域需显式声明", ErrOperationUnknown, request.OperationID)
	}
	next := request.Change.applyTo(base)
	if immutableSensitive && !next.Sensitive {
		return Snapshot{}, fmt.Errorf("%w: 高风险操作不能取消敏感标记", ErrInvalidChange)
	}
	if err := validatePolicy(next, immutableSensitive); err != nil {
		return Snapshot{}, err
	}
	// 有效策略没有真正变化时不递增版本、不写成功审计（与恢复默认的幂等语义一致）：
	// 相同策略重复提交或“显式写回默认值”都不应制造虚假的版本历史。
	if hasExisting {
		unchanged := existing.Policy.Equal(next) && existing.SourceKind == sourceKind
		if sourceKind == SourceApplication {
			unchanged = unchanged && existing.Name == name && existing.Description == description
		}
		if unchanged {
			return s.buildSnapshot(ctx, scope)
		}
	} else if hasBuiltin && sourceKind == SourceOverride && next.Equal(builtin.Default) {
		return s.buildSnapshot(ctx, scope)
	}
	if hasExisting {
		previousPolicy := existing.Policy
		previous = &previousPolicy
	}
	changes := policyChangeFields(previous, next, request.OperationID, sourceKind, name)
	action := "policy.update"
	if sourceKind == SourceApplication {
		action = "policy.declare"
	}
	now := s.now()
	record := OverrideRecord{
		ScopeID: scope.ID, OperationID: request.OperationID, Policy: next,
		SourceKind: sourceKind, Name: name, Description: description,
		CreatedAt: now, UpdatedAt: now,
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     caller.actor,
			Action:    action,
			Target:    audit.Target{Type: "sensitive_policy", ID: scope.ID},
			RequestID: requestID,
			Changes:   changes,
		},
		FailureReasonCode: "policy.update_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	criticalStarted = true
	err = s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		_, ok, saveErr := s.opts.Store.SaveTx(txCtx, tx, scope.ID, record, request.ExpectedVersion, now)
		if saveErr != nil {
			return saveErr
		}
		if !ok {
			return ErrVersionConflict
		}
		return nil
	})
	if err != nil {
		return Snapshot{}, mapCriticalError(err)
	}
	return s.buildSnapshot(ctx, scope)
}

// RestoreRequest 是恢复默认请求。All=true 时恢复该作用域全部覆盖行（保留应用声明
// 操作，它们不是默认值的偏离）；否则必须指定 OperationID。
type RestoreRequest struct {
	ScopeID         string
	OperationID     string
	All             bool
	ExpectedVersion int64
	RequestID       string
}

// Restore 逐项或整体恢复系统默认策略。只有真实 root 能执行且必须再次验证；恢复
// 只删除覆盖行，不删除应用声明操作，也不恢复目录以外的“历史默认值”。
func (s *Service) Restore(ctx context.Context, caller Caller, request RestoreRequest) (snapshot Snapshot, returnErr error) {
	ctx = normalizeContext(ctx)
	criticalStarted := false
	defer func() {
		if returnErr == nil || criticalStarted {
			return
		}
		returnErr = s.recordRejection(ctx, caller, "policy.restore", request.ScopeID,
			request.RequestID, returnErr)
	}()
	requestID, err := s.prepareWrite(ctx, caller, request.ScopeID, request.ExpectedVersion, request.RequestID)
	if err != nil {
		return Snapshot{}, err
	}
	scope, err := s.resolveScope(ctx, request.ScopeID)
	if err != nil {
		return Snapshot{}, err
	}
	var operationIDs []string
	if !request.All {
		if !validOperationID(request.OperationID) {
			return Snapshot{}, fmt.Errorf("%w: 操作标识格式非法", ErrInvalidRequest)
		}
		if _, hasDefault := s.catalog.Lookup(request.OperationID); !hasDefault {
			return Snapshot{}, fmt.Errorf("%w: 操作 %q 没有系统默认策略", ErrDefaultUnavailable, request.OperationID)
		}
		operationIDs = []string{request.OperationID}
	}
	overrides, err := s.opts.Store.GetOverrides(ctx, scope.ID)
	if err != nil {
		return Snapshot{}, ErrStoreUnavailable
	}
	matched := 0
	for _, record := range overrides {
		if record.SourceKind != SourceOverride {
			continue
		}
		if request.All {
			matched++
			continue
		}
		if record.OperationID == request.OperationID {
			matched++
		}
	}
	if matched == 0 {
		// 已经是默认值：幂等成功，不递增版本、不写成功审计；但仍校验期望版本，
		// 过期的期望版本必须返回 CONFLICT，不能让调用者误以为读到了最新状态。
		version, versionErr := s.opts.Store.GetVersion(ctx, scope.ID)
		if versionErr != nil {
			return Snapshot{}, ErrStoreUnavailable
		}
		if version != request.ExpectedVersion {
			return Snapshot{}, ErrVersionConflict
		}
		return s.buildSnapshot(ctx, scope)
	}
	changes := []audit.FieldChange{}
	if request.All {
		changes = append(changes, audit.FieldChange{Field: "restore_scope", After: "all_overrides"})
	} else {
		if existing, ok := snapshotOperation(overrides, request.OperationID); ok {
			changes = append(changes, audit.FieldChange{
				Field: "operation", After: request.OperationID,
			})
			operation, _ := s.catalog.Lookup(request.OperationID)
			for _, diff := range policyFieldDiffs(existing.Policy, operation.Default) {
				changes = append(changes, audit.FieldChange{Field: diff.Field, Before: diff.Current, After: diff.Default})
			}
		}
	}
	now := s.now()
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     caller.actor,
			Action:    "policy.restore",
			Target:    audit.Target{Type: "sensitive_policy", ID: scope.ID},
			RequestID: requestID,
			Changes:   changes,
		},
		FailureReasonCode: "policy.restore_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	criticalStarted = true
	err = s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		_, removed, ok, deleteErr := s.opts.Store.DeleteTx(txCtx, tx, scope.ID, operationIDs,
			request.All, request.ExpectedVersion, now)
		if deleteErr != nil {
			return deleteErr
		}
		if !ok {
			return ErrVersionConflict
		}
		if removed == 0 {
			// 版本匹配但没有任何覆盖行：数据不一致，回滚并要求重试。
			return fmt.Errorf("%w: 恢复默认未匹配到覆盖行", ErrStoreUnavailable)
		}
		return nil
	})
	if err != nil {
		return Snapshot{}, mapCriticalError(err)
	}
	return s.buildSnapshot(ctx, scope)
}

// EvaluateRequest 是策略评估请求。Verification 是执行器提供的近期验证事实。
type EvaluateRequest struct {
	ScopeID      string
	OperationID  string
	Verification Verification
}

// Evaluate 判断某操作在当前环境是否满足策略要求。它不执行操作、不检查基础权限，
// 只表达策略层的额外要求；基础权限与审计由执行器另行强制执行。
//
// 失败语义：要求强认证但环境未实现时返回 MFA_REQUIRED（不降级为密码）；缺少/
// 过期/未来时间戳的验证返回 REAUTH_REQUIRED；缺少确认返回 REAUTH_REQUIRED。
func (s *Service) Evaluate(ctx context.Context, caller Caller, request EvaluateRequest) (Decision, error) {
	ctx = normalizeContext(ctx)
	if err := caller.actor.Validate(); err != nil {
		return Decision{}, ErrAccessDenied
	}
	scope, err := s.resolveScope(ctx, request.ScopeID)
	if err != nil {
		return Decision{}, err
	}
	snapshot, err := s.buildSnapshot(ctx, scope)
	if err != nil {
		return Decision{}, err
	}
	operation, found := snapshot.Lookup(request.OperationID)
	if !found {
		return Decision{}, fmt.Errorf("%w: 操作 %q 未登记", ErrOperationUnknown, request.OperationID)
	}
	decision := Decision{
		OperationID:          operation.OperationID,
		Sensitive:            operation.Effective.Sensitive,
		ReauthRequired:       operation.Effective.ReauthRequired,
		ConfirmationRequired: operation.Effective.ConfirmationRequired,
		NotificationRequired: operation.Effective.NotificationRequired,
		PermissionKey:        operation.PermissionKey,
		RootOnly:             operation.RootOnly,
		AuditRequired:        true,
		RequiredStrength:     operation.Effective.Strength,
		MaxAuthAgeSeconds:    operation.Effective.MaxAuthAgeSeconds,
	}
	if !operation.Effective.Sensitive {
		// 取消敏感标记不取消基础权限/root 限制/审计；这里只表示没有额外策略要求。
		return decision, nil
	}
	required := operation.Effective.Strength
	if !s.available[required] {
		decision.ReasonCode = "strength_not_implemented"
		return decision, fmt.Errorf("%w: 需要 %q 强度认证", ErrVerificationUnavailable, required)
	}
	now := s.now()
	if operation.Effective.ReauthRequired {
		if request.Verification.VerifiedAt.IsZero() {
			decision.ReasonCode = "reauth_missing"
			return decision, ErrReauthRequired
		}
		age := now.Sub(request.Verification.VerifiedAt)
		if age < -maxVerificationClockSkew {
			// 明显未来时间戳视为时钟异常/伪造事实，fail-closed 不当作新鲜验证。
			decision.ReasonCode = "reauth_in_future"
			return decision, ErrReauthRequired
		}
		if age < 0 {
			// 毫秒截断/时钟抖动造成的极小负值按“刚刚验证”处理，避免正常路径误报。
			age = 0
		}
		if operation.Effective.MaxAuthAgeSeconds > 0 &&
			age > time.Duration(operation.Effective.MaxAuthAgeSeconds)*time.Second {
			decision.ReasonCode = "reauth_stale"
			return decision, ErrReauthRequired
		}
		if !request.Verification.Strength.Known() ||
			request.Verification.Strength.rank() < required.rank() {
			decision.ReasonCode = "strength_insufficient"
			return decision, fmt.Errorf("%w: 当前验证强度不足", ErrVerificationUnavailable)
		}
	}
	if operation.Effective.ConfirmationRequired && !request.Verification.Confirmed {
		decision.ReasonCode = "confirmation_missing"
		return decision, ErrConfirmationRequired
	}
	return decision, nil
}

// recordRejection 为在审计事务开始前就被拒绝的写请求补写独立失败审计（参考步骤 28
// root 拒绝失败审计的做法）。审计不可用时拒绝结果保持不变，只把审计不可用附加到
// 错误文本，绝不因此放行或伪装成功。
func (s *Service) recordRejection(ctx context.Context, caller Caller, action, scopeID, requestID string,
	cause error) error {
	if cause == nil {
		return nil
	}
	if errors.Is(cause, ErrAuditUnavailable) || errors.Is(cause, audit.ErrAuditUnavailable) {
		// 审计本身不可用：没有可靠的审计通道，不再递归尝试。
		return cause
	}
	if err := caller.actor.Validate(); err != nil {
		return cause
	}
	outcome := audit.OutcomeFailure
	code := CodeOf(mapCriticalError(cause))
	if code == CodeAccessDenied {
		outcome = audit.OutcomeDenied
	}
	event := audit.Event{
		Actor:      caller.actor,
		Action:     action,
		Target:     audit.Target{Type: "sensitive_policy", ID: safeAuditTarget(scopeID)},
		Outcome:    outcome,
		ErrorCode:  string(code),
		ReasonCode: "policy.write_rejected",
	}
	if account.ValidateRequestID(requestID) == nil {
		event.RequestID = requestID
	}
	if auditErr := s.opts.Audit.RecordFailure(ctx, event); auditErr != nil {
		return fmt.Errorf("%w: 失败审计不可用（%v）", cause, auditErr)
	}
	return cause
}

// safeAuditTarget 只把符合审计标识规则的字符串当作作用域 ID，避免调用者提供的
// 非法内容使失败审计事件本身被拒绝（从而静默丢失拒绝记录）。
func safeAuditTarget(value string) string {
	if len(value) == 0 || len(value) > 64 {
		return ""
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' ||
			character == '-' {
			continue
		}
		return ""
	}
	return value
}

// prepareWrite 在读取/写入前完成请求编号、作用域、root 判定与再次验证。
func (s *Service) prepareWrite(ctx context.Context, caller Caller, scopeID string, expectedVersion int64,
	requestID string) (string, error) {
	if err := account.ValidateRequestID(requestID); err != nil {
		return "", fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if caller.requestID != "" && requestID == "" {
		requestID = caller.requestID
	}
	if expectedVersion < 0 {
		return "", fmt.Errorf("%w: 期望版本非法", ErrInvalidRequest)
	}
	if err := caller.actor.Validate(); err != nil {
		return "", ErrAccessDenied
	}
	scope, err := s.resolveScope(ctx, scopeID)
	if err != nil {
		return "", err
	}
	if err := s.authorizeWrite(ctx, caller, scope); err != nil {
		return "", err
	}
	if s.opts.ReauthVerifier == nil {
		return "", ErrReauthRequired
	}
	if err := s.opts.ReauthVerifier.VerifyReauth(ctx, caller, OperationPolicyChange); err != nil {
		return "", ErrReauthRequired
	}
	return requestID, nil
}

// resolveScope 校验作用域存在并返回其类型。
func (s *Service) resolveScope(ctx context.Context, scopeID string) (ScopeInfo, error) {
	if scopeID == "" {
		return ScopeInfo{}, fmt.Errorf("%w: 作用域为空", ErrInvalidRequest)
	}
	scope, found, err := s.opts.Store.GetScope(ctx, scopeID)
	if err != nil {
		return ScopeInfo{}, ErrStoreUnavailable
	}
	if !found {
		return ScopeInfo{}, fmt.Errorf("%w: %q", ErrScopeUnknown, scopeID)
	}
	return scope, nil
}

// authorizeRead 使用默认口径或注入 Authorizer 判定读取权限。
func (s *Service) authorizeRead(ctx context.Context, caller Caller, scope ScopeInfo) error {
	if err := caller.actor.Validate(); err != nil {
		return ErrAccessDenied
	}
	if s.opts.Authorizer != nil {
		if err := s.opts.Authorizer.AuthorizePolicy(ctx, caller, scope.ID, false); err != nil {
			return ErrAccessDenied
		}
		return nil
	}
	switch caller.actor.Type {
	case audit.ActorSystem, audit.ActorLocalAdmin:
		return nil
	case audit.ActorUser:
		_, isRoot, err := s.opts.Store.GetUserRoot(ctx, caller.actor.ID)
		if err != nil {
			return ErrStoreUnavailable
		}
		if isRoot {
			return nil
		}
		return ErrAccessDenied
	default:
		return ErrAccessDenied
	}
}

// authorizeWrite 要求真实 root 身份；受信 system/local_admin 也不能自称 root。
func (s *Service) authorizeWrite(ctx context.Context, caller Caller, scope ScopeInfo) error {
	if !caller.IsUser() {
		return ErrRootRequired
	}
	exists, isRoot, err := s.opts.Store.GetUserRoot(ctx, caller.actor.ID)
	if err != nil {
		return ErrStoreUnavailable
	}
	if !exists || !isRoot {
		return ErrRootRequired
	}
	if s.opts.Authorizer != nil {
		if err := s.opts.Authorizer.AuthorizePolicy(ctx, caller, scope.ID, true); err != nil {
			return ErrAccessDenied
		}
	}
	return nil
}

// lookupOverride 读取指定操作的现有覆盖/声明行。
func (s *Service) lookupOverride(ctx context.Context, scopeID, operationID string) (OverrideRecord, bool, error) {
	records, err := s.opts.Store.GetOverrides(ctx, scopeID)
	if err != nil {
		return OverrideRecord{}, false, ErrStoreUnavailable
	}
	for _, record := range records {
		if record.OperationID == operationID {
			return record, true, nil
		}
	}
	return OverrideRecord{}, false, nil
}

// buildSnapshot 组装作用域有效策略：目录默认值 + 覆盖 + 应用声明。
func (s *Service) buildSnapshot(ctx context.Context, scope ScopeInfo) (Snapshot, error) {
	version, err := s.opts.Store.GetVersion(ctx, scope.ID)
	if err != nil {
		return Snapshot{}, ErrStoreUnavailable
	}
	records, err := s.opts.Store.GetOverrides(ctx, scope.ID)
	if err != nil {
		return Snapshot{}, ErrStoreUnavailable
	}
	byOperation := make(map[string]OverrideRecord, len(records))
	for _, record := range records {
		byOperation[record.OperationID] = record
	}
	snapshot := Snapshot{ScopeID: scope.ID, Version: version,
		Operations: make([]EffectiveOperation, 0, len(s.catalog.Operations)+len(records))}
	for _, operation := range s.catalog.Operations {
		effective := EffectiveOperation{
			OperationID: operation.ID, Domain: operation.Domain, Name: operation.Name,
			Description: operation.Description, Default: operation.Default, HasDefault: true,
			Effective: operation.Default, Source: SourceDefault,
			PermissionKey: operation.PermissionKey, RootOnly: operation.RootOnly,
			AuditRequired: true, Implemented: operation.Implemented,
		}
		if record, ok := byOperation[operation.ID]; ok {
			override := record.Policy
			effective.Override = &override
			effective.Effective = record.Policy
			effective.Source = SourceOverride
		}
		snapshot.Operations = append(snapshot.Operations, effective)
	}
	declared := make([]OverrideRecord, 0, 4)
	for _, record := range records {
		if _, ok := s.catalog.Lookup(record.OperationID); ok {
			continue
		}
		if record.SourceKind != SourceApplication {
			continue
		}
		declared = append(declared, record)
	}
	sort.Slice(declared, func(left, right int) bool {
		return declared[left].OperationID < declared[right].OperationID
	})
	for _, record := range declared {
		override := record.Policy
		snapshot.Operations = append(snapshot.Operations, EffectiveOperation{
			OperationID: record.OperationID, Name: record.Name, Description: record.Description,
			HasDefault: false, Override: &override, Effective: record.Policy,
			Source: SourceApplication, AuditRequired: true,
		})
	}
	return snapshot, nil
}

// policyFieldDiffs 比较两条策略的可配置字段，按稳定顺序返回差异。
func policyFieldDiffs(before, after Policy) []FieldDiff {
	diffs := make([]FieldDiff, 0, 6)
	if before.Sensitive != after.Sensitive {
		diffs = append(diffs, FieldDiff{Field: "is_sensitive",
			Default: strconv.FormatBool(before.Sensitive), Current: strconv.FormatBool(after.Sensitive)})
	}
	if before.ReauthRequired != after.ReauthRequired {
		diffs = append(diffs, FieldDiff{Field: "reauth_required",
			Default: strconv.FormatBool(before.ReauthRequired), Current: strconv.FormatBool(after.ReauthRequired)})
	}
	if before.MaxAuthAgeSeconds != after.MaxAuthAgeSeconds {
		diffs = append(diffs, FieldDiff{Field: "max_auth_age_seconds",
			Default: strconv.FormatInt(before.MaxAuthAgeSeconds, 10),
			Current: strconv.FormatInt(after.MaxAuthAgeSeconds, 10)})
	}
	if before.Strength != after.Strength {
		diffs = append(diffs, FieldDiff{Field: "required_strength",
			Default: string(before.Strength), Current: string(after.Strength)})
	}
	if before.ConfirmationRequired != after.ConfirmationRequired {
		diffs = append(diffs, FieldDiff{Field: "confirmation_required",
			Default: strconv.FormatBool(before.ConfirmationRequired), Current: strconv.FormatBool(after.ConfirmationRequired)})
	}
	if before.NotificationRequired != after.NotificationRequired {
		diffs = append(diffs, FieldDiff{Field: "notification_required",
			Default: strconv.FormatBool(before.NotificationRequired), Current: strconv.FormatBool(after.NotificationRequired)})
	}
	return diffs
}

// policyChangeFields 生成审计差异：只记录稳定字段名与布尔/枚举/秒值，不记录秘密。
func policyChangeFields(previous *Policy, next Policy, operationID string, sourceKind SourceKind,
	name string) []audit.FieldChange {
	changes := []audit.FieldChange{
		{Field: "operation_id", After: operationID},
		{Field: "source_kind", After: string(sourceKind)},
	}
	if name != "" {
		changes = append(changes, audit.FieldChange{Field: "name", After: name})
	}
	var before Policy
	if previous != nil {
		before = *previous
	}
	for _, diff := range policyFieldDiffs(before, next) {
		changes = append(changes, audit.FieldChange{Field: diff.Field, Before: diff.Default, After: diff.Current})
	}
	return changes
}

// snapshotOperation 从覆盖行中取指定操作的记录。
func snapshotOperation(records []OverrideRecord, operationID string) (OverrideRecord, bool) {
	for _, record := range records {
		if record.OperationID == operationID {
			return record, true
		}
	}
	return OverrideRecord{}, false
}

// trimText 去除首尾空白，保持策略文本与审计记录稳定。
func trimText(value string) string {
	for len(value) > 0 && (value[0] == ' ' || value[0] == '\t' || value[0] == '\n' || value[0] == '\r') {
		value = value[1:]
	}
	for len(value) > 0 {
		last := value[len(value)-1]
		if last != ' ' && last != '\t' && last != '\n' && last != '\r' {
			break
		}
		value = value[:len(value)-1]
	}
	return value
}

func (s *Service) now() time.Time { return s.opts.Now().UTC().Truncate(time.Millisecond) }

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// mapCriticalError 把审计事务错误映射为领域错误，不把内部错误伪装成成功。
func mapCriticalError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, audit.ErrAuditUnavailable):
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	case errors.Is(err, audit.ErrInvalidEvent):
		return fmt.Errorf("%w: 审计事件无效", ErrOptionsInvalid)
	case errors.Is(err, ErrVersionConflict), errors.Is(err, ErrInvalidRequest),
		errors.Is(err, ErrInvalidChange), errors.Is(err, ErrAccessDenied),
		errors.Is(err, ErrRootRequired), errors.Is(err, ErrOperationUnknown),
		errors.Is(err, ErrScopeUnknown), errors.Is(err, ErrDefaultUnavailable),
		errors.Is(err, ErrOptionsInvalid):
		return err
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, ErrStoreUnavailable), errors.Is(err, ErrVerificationUnavailable):
		return err
	default:
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
}

func isNil(value any) bool {
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
