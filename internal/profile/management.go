package profile

// 步骤 256：直接管理他人用户名的领域能力（操作者与目标不同）。
//
// 背景：本包既有 ChangeUsername 是“本人受控更名”（自带近期再次验证、冷却与
// Sensitive 策略）。管理员直接改名是另一条明确能力：
//   - 授权由上层门面用独立权限 users.username.change.other 与本次两步验证证明完成
//     （internal/reauth 的目标绑定操作证明），不在本方法里复用“本人再次验证”；
//   - 复用同一套用户名规范化（NFKC/大小写折叠/保留名）与唯一性、行版本并发保护；
//   - 具备专门权限的直接操作豁免本人改名冷却（本方法不检查冷却），但仍更新
//     username_changed_at，使目标后续走本人流程时照常受冷却约束；
//   - root 目标一律拒绝（root 用户名只走本人受控流程/本地应急，不开远程直接改）；
//   - 只允许 active/disabled 的稳定账户；pending/pending_delete 拒绝，避免把
//     注册/删除过渡态改名成难以追踪的状态。
//
// 两阶段设计（与步骤 255 证明消费的事务边界一致）：
//   - PrepareManagementRename（事务外）：校验请求、读取当前资料、按保留名规范化、
//     检查 root/状态/行版本/同名，返回内部计划；
//   - ApplyManagementRenameTx（调用方审计事务内）：重新读取目标并再次核对 root/
//     状态/行版本/改名前用户名，然后条件更新（唯一冲突→ErrUsernameTaken，
//     版本不符→ErrVersionConflict）；证明消费由调用方在同一事务内先完成。

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// MaxManagementReasonBytes 是直接管理操作理由的最大长度（理由是审计可读的自由文本，
// 必须脱敏、不含口令/token；空理由拒绝）。
const MaxManagementReasonBytes = 256

var (
	// ErrTargetNotManageable 表示目标账户（root / 过渡态 / 状态非法）不能走直接
	// 管理更名；对外映射 ACCESS_DENIED，不泄露账户内部细节。
	ErrTargetNotManageable = errors.New("目标账户不可被直接管理")
)

// ManagementRenameRequest 是直接管理更名的请求（领域层只做目标/新值/版本校验，
// 授权与两步验证证明由上层门面完成）。
type ManagementRenameRequest struct {
	// OperatorUserID 是执行直接管理的操作者稳定 ID（仅用于审计关联与计划绑定）。
	OperatorUserID string
	TargetUserID   string
	NewUsername    string
	// ExpectedRowVersion 是操作者确认的目标资料行版本（乐观并发）。
	ExpectedRowVersion int64
	RequestID          string
}

// ManagementRenamePlan 是事务外校验通过的更名计划；只能由
// PrepareManagementRename 产生，ApplyManagementRenameTx 会再次校验其规范形态与
// 目标当前状态，避免调用方伪造/复用过期计划。
type ManagementRenamePlan struct {
	OperatorUserID     string
	TargetUserID       string
	BeforeUsername     string
	BeforeNormalized   string
	BeforeStatus       account.Status
	DisplayUsername    string
	NormalizedUsername string
	ExpectedRowVersion int64
	RequestID          string
	PreparedAt         time.Time
}

// AllowsManagementRenameStatus 报告账户状态是否允许直接管理更名：只允许稳定账户
// （active/disabled）；pending 属于注册/验证过渡态，pending_delete 属于删除过渡态。
func AllowsManagementRenameStatus(status account.Status) bool {
	return status == account.StatusActive || status == account.StatusDisabled
}

// PrepareManagementRename 在事务外完成直接管理更名的全部领域校验：
//   - 目标稳定 ID / 新用户名 / 期望行版本 / 请求编号合法；
//   - 规范化（含保留名）与“与当前用户名等价”检查；
//   - 目标存在、非 root、状态允许、行版本与操作者看到的一致。
//
// 本方法无副作用；返回的计划应立即交给同一逻辑操作的 ApplyManagementRenameTx。
func (s *Service) PrepareManagementRename(ctx context.Context,
	request ManagementRenameRequest) (ManagementRenamePlan, error) {
	ctx = normalizeContext(ctx)
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return ManagementRenamePlan{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if !account.ValidUserID(request.TargetUserID) {
		return ManagementRenamePlan{}, fmt.Errorf("%w: 目标用户 ID 格式无效", ErrInvalidRequest)
	}
	if request.OperatorUserID != "" && !account.ValidUserID(request.OperatorUserID) {
		return ManagementRenamePlan{}, fmt.Errorf("%w: 操作者标识无效", ErrInvalidRequest)
	}
	if request.ExpectedRowVersion < 1 {
		return ManagementRenamePlan{}, fmt.Errorf("%w: 资料版本无效", ErrInvalidRequest)
	}
	display, normalized, err := account.NormalizeUsernameWithReserved(
		request.NewUsername, s.policy.reserved)
	if err != nil {
		return ManagementRenamePlan{}, err
	}
	current, found, err := s.opts.Store.GetProfile(ctx, request.TargetUserID)
	if err != nil {
		return ManagementRenamePlan{}, ErrStoreUnavailable
	}
	if !found {
		return ManagementRenamePlan{}, ErrUserNotFound
	}
	if current.IsRoot {
		return ManagementRenamePlan{}, ErrTargetNotManageable
	}
	if !AllowsManagementRenameStatus(current.Status) {
		return ManagementRenamePlan{}, fmt.Errorf("%w: 目标账户处于过渡状态", ErrTargetNotManageable)
	}
	if current.RowVersion != request.ExpectedRowVersion {
		return ManagementRenamePlan{}, ErrVersionConflict
	}
	if normalized == current.UsernameNormalized && display == current.Username {
		return ManagementRenamePlan{}, fmt.Errorf("%w: 新用户名与当前用户名相同", ErrInvalidRequest)
	}
	return ManagementRenamePlan{
		OperatorUserID: request.OperatorUserID, TargetUserID: request.TargetUserID,
		BeforeUsername: current.Username, BeforeNormalized: current.UsernameNormalized,
		BeforeStatus: current.Status, DisplayUsername: display,
		NormalizedUsername: normalized, ExpectedRowVersion: request.ExpectedRowVersion,
		RequestID: request.RequestID, PreparedAt: s.now(),
	}, nil
}

// ApplyManagementRenameTx 在调用方审计事务内执行直接管理更名。
//
// 事务内重新读取目标并复核：存在、非 root、状态允许、行版本与改名前用户名与计划
// 一致（防止计划被挪用/目标在准备后变化）；通过后条件更新用户名并返回更新后的
// 资料快照。唯一冲突返回 ErrUsernameTaken，版本不符返回 ErrVersionConflict。
// 证明消费、本方法写入与关键审计由调用方放在同一事务：任一步失败整体回滚。
func (s *Service) ApplyManagementRenameTx(ctx context.Context, tx audit.Tx,
	plan ManagementRenamePlan) (UserProfile, error) {
	if tx == nil {
		return UserProfile{}, fmt.Errorf("%w: 审计事务为空", ErrOptionsInvalid)
	}
	// 计划形态复核：只接受本包 PrepareManagementRename 产生的规范计划（防止调用方
	// 自行拼造 display/normalized 不一致的值写入用户名）。
	if !account.ValidUserID(plan.TargetUserID) || plan.RequestID == "" ||
		plan.ExpectedRowVersion < 1 || plan.DisplayUsername == "" || plan.NormalizedUsername == "" ||
		plan.PreparedAt.IsZero() {
		return UserProfile{}, fmt.Errorf("%w: 更名计划无效", ErrInvalidRequest)
	}
	if plan.OperatorUserID != "" && !account.ValidUserID(plan.OperatorUserID) {
		return UserProfile{}, fmt.Errorf("%w: 更名计划操作者无效", ErrInvalidRequest)
	}
	display, normalized, err := account.NormalizeUsernameWithReserved(
		plan.DisplayUsername, s.policy.reserved)
	if err != nil || display != plan.DisplayUsername || normalized != plan.NormalizedUsername {
		return UserProfile{}, fmt.Errorf("%w: 更名计划用户名非规范形态", ErrInvalidRequest)
	}
	if !s.now().Before(plan.PreparedAt.Add(managementPlanTTL)) {
		return UserProfile{}, ErrVersionConflict
	}
	current, found, err := s.opts.Store.GetProfileTx(ctx, tx, plan.TargetUserID)
	if err != nil {
		return UserProfile{}, ErrStoreUnavailable
	}
	if !found {
		return UserProfile{}, ErrUserNotFound
	}
	if current.IsRoot {
		return UserProfile{}, ErrTargetNotManageable
	}
	if !AllowsManagementRenameStatus(current.Status) {
		return UserProfile{}, fmt.Errorf("%w: 目标账户处于过渡状态", ErrTargetNotManageable)
	}
	if current.RowVersion != plan.ExpectedRowVersion ||
		current.Username != plan.BeforeUsername ||
		current.UsernameNormalized != plan.BeforeNormalized {
		return UserProfile{}, ErrVersionConflict
	}
	now := s.now()
	changed, err := s.opts.Store.UpdateUsername(ctx, tx, UsernameUpdate{
		UserID: plan.TargetUserID, Username: plan.DisplayUsername,
		UsernameNormalized: plan.NormalizedUsername,
		ExpectedRowVersion: plan.ExpectedRowVersion, Now: now,
	})
	if err != nil {
		return UserProfile{}, err
	}
	if !changed {
		return UserProfile{}, ErrVersionConflict
	}
	updated, found, err := s.opts.Store.GetProfileTx(ctx, tx, plan.TargetUserID)
	if err != nil {
		return UserProfile{}, ErrStoreUnavailable
	}
	if !found {
		return UserProfile{}, ErrStoreUnavailable
	}
	return updated, nil
}

// managementPlanTTL 是更名计划从准备到事务提交的最长允许间隔；超过视为陈旧计划
// 拒绝（要求重新准备，重新核对权限/会话/证明与目标状态）。
const managementPlanTTL = 2 * time.Minute
