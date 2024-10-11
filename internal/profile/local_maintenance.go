package profile

// 步骤 287（本地维护控制台）：root 用户名直接更名能力。
//
// 背景：普通管理路径（步骤 256 PrepareManagementRename/ApplyManagementRenameTx）
// 明确拒绝 root，root 用户名此前只能通过本人受控流程/本地应急维护。用户批准的
// 本地维护控制台需要能在丢失 root 应用凭证时救援 root，包括修改 root 显示用户名。
//
// 安全边界（AGENTS §14 / Lead 裁决）：
//   - 只接受显式 LocalMaintenanceCaller；该类型字段不可由 JSON 反序列化，构造函数
//     只应被本机 login-setup 装配调用；它不代表任何 Evernight 账户/HTTP 身份；
//   - 仍然校验 root 目标（is_root=1）、稳定账户状态、保留名/唯一性/Unicode 规范化、
//     行版本乐观并发，并更新 username_changed_at（root 稳定 UserID 不变）；
//   - 普通 PrepareManagementRename/ApplyManagementRenameTx 行为不变（root 继续拒绝）；
//   - 计划由本文件独立类型表达，不能把普通管理计划用于 root，也不能把本地计划用于
//     非 root（防止调用方混淆授权路径）；
//   - 审计由调用方（login-setup）在 Apply 的同一审计事务内写入本地操作者与理由。

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// LocalMaintenanceCaller 是仅供本机维护控制台使用的显式本地身份。
//
// 它不是 Evernight 账户、不能从 HTTP/请求参数/JSON 构造，也没有可序列化令牌；
// 授权来自 login-setup 进程对实例配置/数据/密钥的 OS 访问权限。构造失败返回错误。
type LocalMaintenanceCaller struct {
	operatorID string
}

// NewLocalMaintenanceCaller 构造本地维护调用者；只应由 cmd/login-setup 本地入口
// （经 internal/setupconsole）调用。operatorID 是稳定本地操作者标识（审计字段）。
func NewLocalMaintenanceCaller(operatorID string) (LocalMaintenanceCaller, error) {
	actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: operatorID}
	if err := actor.Validate(); err != nil {
		return LocalMaintenanceCaller{}, fmt.Errorf("%w: 本地维护操作者标识无效", ErrInvalidRequest)
	}
	return LocalMaintenanceCaller{operatorID: operatorID}, nil
}

// OperatorID 返回审计用本地操作者标识。
func (c LocalMaintenanceCaller) OperatorID() string { return c.operatorID }

// LocalRootRenamePlan 是本地维护 root 更名计划；只能由
// PrepareLocalMaintenanceRootRename 产生并由同一本地身份应用。
type LocalRootRenamePlan struct {
	OperatorID         string
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

// PrepareLocalMaintenanceRootRename 在事务外校验本地维护 root 更名：
// 目标必须是 root（is_root=1）、状态允许、行版本一致，用户名按保留名规则规范化，
// 且与当前用户名不是等价无变化。普通用户目标返回 ErrTargetNotManageable，调用方
// 应使用普通直接管理路径。
func (s *Service) PrepareLocalMaintenanceRootRename(ctx context.Context,
	caller LocalMaintenanceCaller, request ManagementRenameRequest) (LocalRootRenamePlan, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return LocalRootRenamePlan{}, err
	}
	if caller.operatorID == "" {
		return LocalRootRenamePlan{}, fmt.Errorf("%w: 缺少本地维护身份", ErrAccessDenied)
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return LocalRootRenamePlan{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if !account.ValidUserID(request.TargetUserID) {
		return LocalRootRenamePlan{}, fmt.Errorf("%w: 目标用户 ID 格式无效", ErrInvalidRequest)
	}
	if request.ExpectedRowVersion < 1 {
		return LocalRootRenamePlan{}, fmt.Errorf("%w: 资料版本无效", ErrInvalidRequest)
	}
	display, normalized, err := account.NormalizeUsernameWithReserved(
		request.NewUsername, s.policy.reserved)
	if err != nil {
		return LocalRootRenamePlan{}, err
	}
	current, found, err := s.opts.Store.GetProfile(ctx, request.TargetUserID)
	if err != nil {
		return LocalRootRenamePlan{}, ErrStoreUnavailable
	}
	if !found {
		return LocalRootRenamePlan{}, ErrUserNotFound
	}
	if !current.IsRoot {
		return LocalRootRenamePlan{}, fmt.Errorf("%w: 本地 root 更名只接受 root 目标",
			ErrTargetNotManageable)
	}
	if !AllowsManagementRenameStatus(current.Status) {
		return LocalRootRenamePlan{}, fmt.Errorf("%w: root 账户处于过渡状态",
			ErrTargetNotManageable)
	}
	if current.RowVersion != request.ExpectedRowVersion {
		return LocalRootRenamePlan{}, ErrVersionConflict
	}
	if normalized == current.UsernameNormalized && display == current.Username {
		return LocalRootRenamePlan{}, fmt.Errorf("%w: 新用户名与当前用户名相同", ErrInvalidRequest)
	}
	return LocalRootRenamePlan{
		OperatorID: caller.operatorID, TargetUserID: request.TargetUserID,
		BeforeUsername: current.Username, BeforeNormalized: current.UsernameNormalized,
		BeforeStatus: current.Status, DisplayUsername: display,
		NormalizedUsername: normalized, ExpectedRowVersion: request.ExpectedRowVersion,
		RequestID: request.RequestID, PreparedAt: s.now(),
	}, nil
}

// ApplyLocalMaintenanceRootRenameTx 在调用方审计事务内应用 root 更名计划。
// 事务内复核目标仍是 root、状态稳定、行版本与改名前用户名一致；root 稳定
// UserID 不变。唯一冲突返回 ErrUsernameTaken，版本冲突返回 ErrVersionConflict。
func (s *Service) ApplyLocalMaintenanceRootRenameTx(ctx context.Context, tx audit.Tx,
	caller LocalMaintenanceCaller, plan LocalRootRenamePlan) (UserProfile, error) {
	if tx == nil {
		return UserProfile{}, fmt.Errorf("%w: 审计事务为空", ErrOptionsInvalid)
	}
	if caller.operatorID == "" || plan.OperatorID != caller.operatorID {
		return UserProfile{}, fmt.Errorf("%w: 本地维护身份与计划不匹配", ErrAccessDenied)
	}
	if !account.ValidUserID(plan.TargetUserID) || plan.RequestID == "" ||
		plan.ExpectedRowVersion < 1 || plan.DisplayUsername == "" ||
		plan.NormalizedUsername == "" || plan.PreparedAt.IsZero() {
		return UserProfile{}, fmt.Errorf("%w: root 更名计划无效", ErrInvalidRequest)
	}
	display, normalized, err := account.NormalizeUsernameWithReserved(
		plan.DisplayUsername, s.policy.reserved)
	if err != nil || display != plan.DisplayUsername || normalized != plan.NormalizedUsername {
		return UserProfile{}, fmt.Errorf("%w: root 更名计划用户名非规范形态", ErrInvalidRequest)
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
	if !current.IsRoot {
		return UserProfile{}, fmt.Errorf("%w: root 更名计划目标已不是 root",
			ErrTargetNotManageable)
	}
	if !AllowsManagementRenameStatus(current.Status) {
		return UserProfile{}, fmt.Errorf("%w: root 账户处于过渡状态", ErrTargetNotManageable)
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

// 编译期确保错误类型可被调用方用 errors.Is 识别（保留在文件内便于审计检查）。
var _ = errors.Is
