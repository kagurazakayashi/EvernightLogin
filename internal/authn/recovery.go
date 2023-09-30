package authn

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// ActionPasswordRecoveryReset 是“经一次性找回凭证验证后重置密码”的审计动作。
const ActionPasswordRecoveryReset Action = "password.recovery_reset"

// RecoveryResetRequest 是邮件找回流程在原子消费一次性凭证后调用密码重置的请求。
//
// 安全边界：本方法不经过 SensitiveRunner（凭证消费本身就是授权证明），因此只能由
// 受信内部服务在完成凭证验证后调用；调用者必须是 system 角色。它仍执行密码策略、
// 历史复用检查、安全版本递增与审计，且不修改 MFA/Passkey 等其他认证因素。
type RecoveryResetRequest struct {
	// UserID 是目标普通账户稳定 ID；root 拒绝。
	UserID string
	// NewPassword 是新明文密码；只用于本次处理，不保存、不记录。
	NewPassword string
	// RequestID 可选，写入审计用于关联。
	RequestID string
	// Reason 是受限原因类别（例如 password_reset），写入审计变更字段。
	Reason string
}

// PreparedRecoveryReset 是找回改密在事务外完成的预计算结果：账户/密码策略/历史复用
// 校验已通过、Argon2 新哈希已派生，并记录了准备时刻的安全版本与密码凭证行版本快照。
//
// 它不写库、不消费任何凭证、不记录密码材料，只在内存中短暂存在；必须交给同一进程的
// ApplyRecoveryResetTx 在调用方事务内复核并提交。本接口只暴露不含密码材料的只读视图，
// 具体实现是 internal/authn 的私有类型；任何外部伪造/替身实现都会在
// ApplyRecoveryResetTx 被拒绝（fail-closed）。
type PreparedRecoveryReset interface {
	// UserID 返回目标用户稳定 ID（不含密码材料）。
	UserID() string
	// AuditChanges 返回可合并进关键审计的安全差异字段副本（不含密码/哈希）。
	AuditChanges() []audit.FieldChange
}

// preparedRecoveryReset 是 PreparedRecoveryReset 的唯一生产实现。字段不导出，避免
// 密码哈希被无意记录或跨边界序列化；String/GoString 固定脱敏。
type preparedRecoveryReset struct {
	userID                       string
	passwordHash                 string
	historyLimit                 int
	changedAt                    time.Time
	expectedSecurityVersion      int64
	expectedCredentialRowVersion int64
	auditChanges                 []audit.FieldChange
}

// UserID 返回目标用户稳定 ID（不含密码材料）。
func (p *preparedRecoveryReset) UserID() string { return p.userID }

// AuditChanges 返回可合并进关键审计的安全差异字段副本（不含密码/哈希）。
func (p *preparedRecoveryReset) AuditChanges() []audit.FieldChange {
	return append([]audit.FieldChange(nil), p.auditChanges...)
}

// String 实现 fmt.Stringer，固定输出脱敏标记，避免 %v/%+v 泄露密码哈希。
func (p *preparedRecoveryReset) String() string { return "[REDACTED prepared recovery reset]" }

// GoString 实现 fmt.GoStringer，覆盖 %#v 输出。
func (p *preparedRecoveryReset) GoString() string { return p.String() }

var _ PreparedRecoveryReset = (*preparedRecoveryReset)(nil)

// PrepareRecoveryReset 在事务外完成找回改密的可失败准备工作：
//   - 只允许 system 调用者；账户必须存在、active、非 root 且已有密码凭证；
//   - 执行密码策略与历史复用检查，并派生 Argon2 新哈希（有界并发槽位）；
//   - 记录当前 security_version 与密码凭证 row_version 作为提交前并发快照。
//
// 本方法不写库、不消费任何凭证：弱密码/历史复用/哈希资源忙等失败都发生在消费之前，
// 因此仍有效的找回入口不会被永久烧掉。它返回的准备结果必须交给
// ApplyRecoveryResetTx 在调用方事务内复核并写入。
func (s *Service) PrepareRecoveryReset(ctx context.Context, caller Caller,
	request RecoveryResetRequest) (PreparedRecoveryReset, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return nil, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if !account.ValidUserID(request.UserID) {
		return nil, fmt.Errorf("%w: 目标用户 ID 格式无效", ErrInvalidRequest)
	}
	if len(request.NewPassword) == 0 || len(request.NewPassword) > MaxPasswordBytes {
		return nil, fmt.Errorf("%w: 新密码长度无效", ErrInvalidRequest)
	}
	if err := caller.actor.Validate(); err != nil {
		return nil, ErrAccessDenied
	}
	if caller.actorKind() != audit.ActorSystem {
		return nil, fmt.Errorf("%w: 找回重置只允许受信系统组件", ErrAccessDenied)
	}
	user, found, err := s.store.FindUserByID(ctx, request.UserID)
	if err != nil {
		return nil, s.storeFailure(ctx, "查询找回目标账户", err)
	}
	if !found {
		return nil, ErrUserNotFound
	}
	if user.IsRoot {
		return nil, fmt.Errorf("%w: root 密码只能通过本地受控初始化流程重置", ErrAccessDenied)
	}
	if user.Status != account.StatusActive {
		return nil, fmt.Errorf("%w: 账户当前不可用", ErrAccessDenied)
	}
	credential, credentialFound, err := s.store.GetPasswordCredential(ctx, user.UserID)
	if err != nil {
		return nil, s.storeFailure(ctx, "读取找回目标密码凭证", err)
	}
	if !credentialFound {
		// 无密码账户不得被找回流程自动添加密码；需要额外的受控授权流程。
		return nil, fmt.Errorf("%w: 账户未设置密码，找回流程不能自动添加密码", ErrAccessDenied)
	}
	if err := s.checkPasswordPolicy(request.NewPassword, user); err != nil {
		return nil, s.rejectedPasswordChange(ctx, caller, ActionPasswordRecoveryReset,
			user.UserID, reasonWeakPassword, CodeOf(err), err)
	}
	if err := s.checkPasswordReuse(ctx, user.UserID, credential, request.NewPassword); err != nil {
		if contextFailure(err) {
			return nil, err
		}
		if errors.Is(err, errPasswordWorkBusy) {
			return nil, s.passwordWorkFailure(ctx, caller,
				ActionPasswordRecoveryReset, user.UserID, err)
		}
		return nil, s.rejectedPasswordChange(ctx, caller, ActionPasswordRecoveryReset,
			user.UserID, reasonPasswordReused, CodeOf(err), err)
	}
	newHash, err := s.hashPassword(ctx, request.NewPassword)
	if err != nil {
		if contextFailure(err) {
			return nil, err
		}
		if errors.Is(err, errPasswordWorkBusy) {
			return nil, s.passwordWorkFailure(ctx, caller,
				ActionPasswordRecoveryReset, user.UserID, err)
		}
		return nil, fmt.Errorf("%w: %w", ErrOptionsInvalid, err)
	}
	return &preparedRecoveryReset{
		userID:                       user.UserID,
		passwordHash:                 newHash,
		historyLimit:                 s.policy.HistoryLimit,
		changedAt:                    s.clockNow(),
		expectedSecurityVersion:      user.SecurityVersion,
		expectedCredentialRowVersion: credential.RowVersion,
		auditChanges: []audit.FieldChange{
			{Field: "security_version_change", After: "password_recovery_reset"},
			{Field: "reason", After: safeRecoveryReason(request.Reason)},
			{Field: "argon2_params", After: s.params.String()},
			{Field: "history_limit", After: strconv.Itoa(s.policy.HistoryLimit)},
		},
	}, nil
}

// ApplyRecoveryResetTx 在调用方提供的审计事务内复核并提交找回改密：
//   - 事务内重新读取账户与密码凭证，拒绝已删除/禁用/改为 root/无密码的状态；
//   - 要求 security_version 与密码凭证 row_version 与 Prepare 快照一致，检测准备到
//     提交之间的并发修改（返回 ErrRecoveryStateConflict，调用方回滚后令牌未消费、
//     可重试）；
//   - 通过后在**同一事务**内写入新密码、维护有限历史并递增安全版本。
//
// 本方法不写成功审计（由调用方的关键审计在同一事务内提交）；不发送通知；不消费
// 任何一次性凭证（由调用方在同一事务内完成）。存储必须实现 TransactionStore，
// 缺失时 fail-closed 返回 ErrOptionsInvalid，不会退化为事务外读取或部分提交。
func (s *Service) ApplyRecoveryResetTx(ctx context.Context, caller Caller,
	prepared PreparedRecoveryReset, tx audit.Tx) (SetPasswordResult, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return SetPasswordResult{}, err
	}
	if tx == nil {
		return SetPasswordResult{}, fmt.Errorf("%w: 审计事务为空", ErrOptionsInvalid)
	}
	if err := caller.actor.Validate(); err != nil {
		return SetPasswordResult{}, ErrAccessDenied
	}
	if caller.actorKind() != audit.ActorSystem {
		return SetPasswordResult{}, fmt.Errorf("%w: 找回重置只允许受信系统组件", ErrAccessDenied)
	}
	concrete, ok := prepared.(*preparedRecoveryReset)
	if !ok || concrete == nil {
		return SetPasswordResult{}, fmt.Errorf("%w: 找回改密准备结果无效", ErrInvalidRequest)
	}
	if !account.ValidUserID(concrete.userID) || concrete.passwordHash == "" {
		return SetPasswordResult{}, fmt.Errorf("%w: 找回改密准备结果无效", ErrInvalidRequest)
	}
	txStore, ok := s.store.(TransactionStore)
	if !ok {
		return SetPasswordResult{}, fmt.Errorf("%w: 认证存储不支持事务内复核", ErrOptionsInvalid)
	}
	user, found, err := txStore.FindUserByIDTx(ctx, tx, concrete.userID)
	if err != nil {
		return SetPasswordResult{}, s.storeFailure(ctx, "事务内查询找回目标账户", err)
	}
	if !found {
		return SetPasswordResult{}, ErrUserNotFound
	}
	if user.IsRoot {
		return SetPasswordResult{}, fmt.Errorf("%w: root 密码只能通过本地受控初始化流程重置", ErrAccessDenied)
	}
	if user.Status != account.StatusActive {
		return SetPasswordResult{}, fmt.Errorf("%w: 账户当前不可用", ErrAccessDenied)
	}
	credential, credentialFound, err := txStore.GetPasswordCredentialTx(ctx, tx, concrete.userID)
	if err != nil {
		return SetPasswordResult{}, s.storeFailure(ctx, "事务内读取找回目标密码凭证", err)
	}
	if !credentialFound {
		return SetPasswordResult{}, fmt.Errorf("%w: 账户未设置密码，找回流程不能自动添加密码", ErrAccessDenied)
	}
	if user.SecurityVersion != concrete.expectedSecurityVersion ||
		credential.RowVersion != concrete.expectedCredentialRowVersion {
		return SetPasswordResult{}, fmt.Errorf("%w: 安全版本或密码凭证已变化", ErrRecoveryStateConflict)
	}
	changeResult, err := s.store.SetPassword(ctx, tx, PasswordChange{
		UserID:       user.UserID,
		PasswordHash: concrete.passwordHash,
		MustChange:   false,
		HistoryLimit: concrete.historyLimit,
		Now:          concrete.changedAt,
	})
	if err != nil {
		return SetPasswordResult{}, err
	}
	return SetPasswordResult{
		UserID:            user.UserID,
		SecurityVersion:   changeResult.SecurityVersion,
		PasswordChangedAt: changeResult.ChangedAt,
		HistoryLimit:      concrete.historyLimit,
	}, nil
}

// ResetPasswordForRecovery 在找回凭证已验证并原子消费后重置密码：
//   - 只允许 system 调用者；普通用户/管理员走 SetPassword 的完整敏感策略路径。
//   - 账户必须存在、active、非 root 且已有密码凭证；无密码账户拒绝，不允许找回
//     流程自动添加密码。
//   - 仍使用密码策略与历史复用检查；安全版本在存储事务内递增，旧会话因版本不匹配
//     失效；MFA 等其他因素不被清除。
//   - 不发送安全告知（由找回服务在事务外发送，且不含密码/凭证）。
//
// 本方法是 PrepareRecoveryReset + 自身关键审计事务 + ApplyRecoveryResetTx 的兼容
// 包装：策略/哈希失败发生在写事务之前，提交时事务内复核。找回服务（步骤 205）改用
// 与凭证消费同一事务的两阶段调用；保留本方法避免破坏既有调用方与测试。
func (s *Service) ResetPasswordForRecovery(ctx context.Context, caller Caller,
	request RecoveryResetRequest) (SetPasswordResult, error) {
	prepared, err := s.PrepareRecoveryReset(ctx, caller, request)
	if err != nil {
		return SetPasswordResult{}, err
	}
	event := audit.Event{
		Actor: caller.actor, Action: string(ActionPasswordRecoveryReset),
		Target: audit.Target{Type: "user", ID: prepared.UserID()}, Outcome: audit.OutcomeSuccess,
		RequestID: caller.requestID,
		Changes:   prepared.AuditChanges(),
	}
	critical := audit.CriticalRequest{
		Event: event, FailureReasonCode: "password_recovery_reset_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	var result SetPasswordResult
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		applied, applyErr := s.ApplyRecoveryResetTx(txCtx, caller, prepared, tx)
		if applyErr != nil {
			return applyErr
		}
		result = applied
		return nil
	})
	if err != nil {
		return SetPasswordResult{}, mapCriticalError(err)
	}
	s.logger.Info("密码已通过找回流程重置", "user_id", result.UserID,
		"security_version", result.SecurityVersion)
	return result, nil
}

// safeRecoveryReason 把原因类别限制为短的安全 ASCII 标识，避免审计注入。
func safeRecoveryReason(value string) string {
	if len(value) == 0 || len(value) > 64 {
		return "password_reset"
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			character == '_' || character == '-' {
			continue
		}
		return "password_reset"
	}
	return value
}
