package authn

// 步骤 257：管理员直接重置他人密码的领域准备/提交原语。
//
// 定位：由持有独立权限 users.password.reset.other 与本次操作绑定两步验证证明的直接管理
// 门面（app.DirectPasswordManagement）调用；**不是**找回流程的 system-caller 捷径：
//   - 本文件提供独立的 PrepareAdminReset / ApplyAdminResetTx，不接受“system 调用者即
//     免授权”的语义，也不暴露 RecoveryResetRequest 那套只允许 system 组件的入口给管理员；
//   - 授权（专门权限 + 目标绑定两步验证证明）与证明消费由调用方在同一审计事务内完成；
//     本原语只负责密码策略/历史复用/哈希准备与事务内条件写入。
//
// 安全边界：
//   - 目标必须存在、active、非 root、且**已有密码凭证**（无密码账户拒绝，不能把重置
//     权限扩成任意添加密码）；
//   - 复用密码策略与历史复用检查；Argon2 哈希在事务外派生（有界并发槽位）；
//   - 事务内重新读取账户/凭证并核对 security_version 与凭证行版本快照，检测准备到提交
//     之间的并发变化（ErrRecoveryStateConflict，调用方回滚后可重试）；
//   - 默认设置 must_change=true：目标下次登录进入受限改密流程；不修改 MFA/Passkey；
//   - 不写成功审计（由调用方关键审计同事务提交）、不发通知、不消费展示凭证；
//   - 不保存/不记录明文密码或哈希；准备结果 String 固定脱敏。

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// AdminResetRequest 是直接管理重置他人密码的准备请求。
type AdminResetRequest struct {
	// TargetUserID 是目标普通用户稳定 ID；root/无密码/非 active 目标拒绝。
	TargetUserID string
	// NewPassword 是新明文密码；只用于本次处理，不保存、不记录。
	NewPassword string
	// RequestID 写入审计用于关联。
	RequestID string
	// Reason 是本次直接管理理由（审计可读自由文本；调用方已脱敏限长）。
	Reason string
}

// PreparedAdminReset 是事务外完成的直接管理重置预计算结果：策略/历史/哈希已完成，
// 并记录准备时刻的 security_version 与密码凭证 row_version 快照。只暴露不含密码材料
// 的只读视图；唯一实现是本包私有类型，外部伪造实现会在 ApplyAdminResetTx 被拒绝。
type PreparedAdminReset interface {
	// UserID 返回目标用户稳定 ID（不含密码材料）。
	UserID() string
	// AuditChanges 返回可合并进关键审计的安全差异字段副本（不含密码/哈希）。
	AuditChanges() []audit.FieldChange
}

type preparedAdminReset struct {
	userID                       string
	passwordHash                 string
	historyLimit                 int
	changedAt                    time.Time
	expectedSecurityVersion      int64
	expectedCredentialRowVersion int64
	auditChanges                 []audit.FieldChange
}

// UserID 返回目标用户稳定 ID。
func (p *preparedAdminReset) UserID() string { return p.userID }

// AuditChanges 返回安全审计差异字段副本。
func (p *preparedAdminReset) AuditChanges() []audit.FieldChange {
	return append([]audit.FieldChange(nil), p.auditChanges...)
}

// String 实现 fmt.Stringer，固定脱敏，避免日志泄露哈希。
func (p *preparedAdminReset) String() string { return "[REDACTED prepared admin password reset]" }

// GoString 实现 fmt.GoStringer。
func (p *preparedAdminReset) GoString() string { return p.String() }

var _ PreparedAdminReset = (*preparedAdminReset)(nil)

// AdminResetResult 是事务内提交成功后的结果（不含密码/哈希）。
type AdminResetResult struct {
	UserID            string
	SecurityVersion   int64
	PasswordChangedAt time.Time
	// MustChange 恒为 true：目标下次登录必须完成本人改密。
	MustChange   bool
	HistoryLimit int
}

// PrepareAdminReset 在事务外完成直接管理重置的可失败准备：账户/root/状态/无密码检查、
// 密码策略与历史复用检查、Argon2 新哈希派生，并记录并发快照。失败时不写库、不消费任何
// 证明；调用方必须在随后的事务内调用 ApplyAdminResetTx。
func (s *Service) PrepareAdminReset(ctx context.Context, request AdminResetRequest) (PreparedAdminReset, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return nil, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if !account.ValidUserID(request.TargetUserID) {
		return nil, fmt.Errorf("%w: 目标用户 ID 格式无效", ErrInvalidRequest)
	}
	if len(request.NewPassword) == 0 || len(request.NewPassword) > MaxPasswordBytes {
		return nil, fmt.Errorf("%w: 新密码长度无效", ErrInvalidRequest)
	}
	user, found, err := s.store.FindUserByID(ctx, request.TargetUserID)
	if err != nil {
		return nil, s.storeFailure(ctx, "查询直接重置目标账户", err)
	}
	if !found {
		return nil, ErrUserNotFound
	}
	if user.IsRoot {
		return nil, fmt.Errorf("%w: root 密码只能通过本人流程或本地受控初始化流程重置", ErrAccessDenied)
	}
	if user.Status != account.StatusActive {
		return nil, fmt.Errorf("%w: 目标账户当前不可用", ErrAccessDenied)
	}
	credential, credentialFound, err := s.store.GetPasswordCredential(ctx, user.UserID)
	if err != nil {
		return nil, s.storeFailure(ctx, "读取直接重置目标密码凭证", err)
	}
	if !credentialFound {
		// 无密码账户不得被重置权限顺手添加密码；需要独立的受控凭证添加流程。
		return nil, fmt.Errorf("%w: 目标账户未设置密码，不能被重置流程添加密码", ErrAccessDenied)
	}
	if err := s.checkPasswordPolicy(request.NewPassword, user); err != nil {
		return nil, ErrWeakPassword
	}
	if err := s.checkPasswordReuse(ctx, user.UserID, credential, request.NewPassword); err != nil {
		if contextFailure(err) {
			return nil, err
		}
		if errors.Is(err, errPasswordWorkBusy) {
			return nil, ErrStoreUnavailable
		}
		return nil, ErrPasswordReused
	}
	newHash, err := s.hashPassword(ctx, request.NewPassword)
	if err != nil {
		if contextFailure(err) {
			return nil, err
		}
		return nil, ErrStoreUnavailable
	}
	return &preparedAdminReset{
		userID:                       user.UserID,
		passwordHash:                 newHash,
		historyLimit:                 s.policy.HistoryLimit,
		changedAt:                    s.clockNow(),
		expectedSecurityVersion:      user.SecurityVersion,
		expectedCredentialRowVersion: credential.RowVersion,
		auditChanges: []audit.FieldChange{
			{Field: "security_version_change", After: "password_direct_admin_reset"},
			{Field: "must_change", After: "true"},
			{Field: "reason", After: safeRecoveryReason(request.Reason)},
			{Field: "argon2_params", After: s.params.String()},
			{Field: "history_limit", After: strconv.Itoa(s.policy.HistoryLimit)},
		},
	}, nil
}

// ApplyAdminResetTx 在调用方审计事务内复核并提交直接管理重置：
//   - 事务内重新读取账户/凭证：拒绝已删除/禁用/改为 root/无密码；
//   - security_version 与凭证 row_version 必须与准备快照一致，否则 ErrRecoveryStateConflict
//     （调用方回滚，证明不被消费、可重新准备后重试）；
//   - 写入新密码与历史、must_change=true 并在同一事务内递增安全版本（旧会话/旧刷新
//     凭证在各自校验处因版本不匹配失效）；
//   - 不写成功审计、不发通知、不撤销 pending 找回入口（调用方在同一事务内完成）。
func (s *Service) ApplyAdminResetTx(ctx context.Context, tx audit.Tx,
	prepared PreparedAdminReset) (AdminResetResult, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return AdminResetResult{}, err
	}
	if tx == nil {
		return AdminResetResult{}, fmt.Errorf("%w: 审计事务为空", ErrOptionsInvalid)
	}
	concrete, ok := prepared.(*preparedAdminReset)
	if !ok || concrete == nil {
		return AdminResetResult{}, fmt.Errorf("%w: 直接重置准备结果无效", ErrInvalidRequest)
	}
	if !account.ValidUserID(concrete.userID) || concrete.passwordHash == "" {
		return AdminResetResult{}, fmt.Errorf("%w: 直接重置准备结果无效", ErrInvalidRequest)
	}
	txStore, ok := s.store.(TransactionStore)
	if !ok {
		return AdminResetResult{}, fmt.Errorf("%w: 认证存储不支持事务内复核", ErrOptionsInvalid)
	}
	user, found, err := txStore.FindUserByIDTx(ctx, tx, concrete.userID)
	if err != nil {
		return AdminResetResult{}, s.storeFailure(ctx, "事务内查询直接重置目标账户", err)
	}
	if !found {
		return AdminResetResult{}, ErrUserNotFound
	}
	if user.IsRoot {
		return AdminResetResult{}, fmt.Errorf("%w: root 密码只能通过本人流程或本地受控初始化流程重置", ErrAccessDenied)
	}
	if user.Status != account.StatusActive {
		return AdminResetResult{}, fmt.Errorf("%w: 目标账户当前不可用", ErrAccessDenied)
	}
	credential, credentialFound, err := txStore.GetPasswordCredentialTx(ctx, tx, concrete.userID)
	if err != nil {
		return AdminResetResult{}, s.storeFailure(ctx, "事务内读取直接重置目标密码凭证", err)
	}
	if !credentialFound {
		return AdminResetResult{}, fmt.Errorf("%w: 目标账户未设置密码，不能被重置流程添加密码", ErrAccessDenied)
	}
	if user.SecurityVersion != concrete.expectedSecurityVersion ||
		credential.RowVersion != concrete.expectedCredentialRowVersion {
		return AdminResetResult{}, ErrRecoveryStateConflict
	}
	changeResult, err := s.store.SetPassword(ctx, tx, PasswordChange{
		UserID:       user.UserID,
		PasswordHash: concrete.passwordHash,
		MustChange:   true,
		HistoryLimit: concrete.historyLimit,
		Now:          concrete.changedAt,
	})
	if err != nil {
		return AdminResetResult{}, err
	}
	return AdminResetResult{UserID: user.UserID,
		SecurityVersion:   changeResult.SecurityVersion,
		PasswordChangedAt: changeResult.ChangedAt,
		MustChange:        true, HistoryLimit: concrete.historyLimit}, nil
}
