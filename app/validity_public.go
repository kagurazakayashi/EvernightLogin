package app

// 步骤 234：账户全局有效期公开 Go 门面。
//
// 语义与安全边界：
//   - 有效期是 UTC 半开区间 [ValidFrom, ValidUntil)，nil 表示该端不限制；默认
//     两段都为空（永久有效）。
//   - 到期/未开始是计算出的不可用原因，不改写手动 status；续期不会启用被手动
//     禁用的账户；root 不接受普通期限管理。
//   - 读写都需要真实 AdminCaller 与账户领域授权（users.read/users.update）；本
//     门面只做参数转换与错误映射，审计、root 保护、乐观并发由领域服务完成。
//   - 不使用 security_version 强制下线：每次身份生效与请求校验即时读取有效期；
//     离线纯 JWT 验签无法感知即时到期，严格集成必须走在线授权。

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
)

// AdminUserValidity 是账户有效期与当前可用性视图（脱敏）。
type AdminUserValidity struct {
	UserID string
	Status string
	// IsRoot 表示受保护 root；root 忽略普通期限约束，不能通过本门面设置期限。
	IsRoot    bool
	ValidFrom *time.Time
	// ValidUntil 是半开区间右端：到达该时刻起不可用。
	ValidUntil *time.Time
	RowVersion int64
	// Available 是当前时刻计算出的可用性；Reason 为 available/not_yet_valid/
	// expired/pending/disabled/pending_delete 之一。
	Available bool
	Reason    string
	CheckedAt time.Time
}

// AdminUserValidityRequest 是设置账户有效期的管理请求。
type AdminUserValidityRequest struct {
	Caller AdminCaller
	UserID string
	// ExpectedRowVersion 必须回传读取到的行版本；并发修改返回 CONFLICT。
	ExpectedRowVersion int64
	// ValidFrom/ValidUntil 为 nil 表示清除该端；两段都设置时 until 必须晚于
	// from（UTC 毫秒精度在领域层规范化）。
	ValidFrom  *time.Time
	ValidUntil *time.Time
	RequestID  string
}

// AdminUserValidityChange 是一次有效期变更结果。
type AdminUserValidityChange struct {
	Validity           AdminUserValidity
	PreviousValidFrom  *time.Time
	PreviousValidUntil *time.Time
	// Changed=false 表示幂等命中相同区间（未改行版本）。
	Changed bool
}

// GetUserValidity 读取账户有效期与当前可用性。
func (f *userLifecycleFacade) GetUserValidity(ctx context.Context,
	req AdminUserRequest) (AdminUserValidity, error) {
	call, err := f.admin().begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminUserValidity{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Account == nil {
		return AdminUserValidity{}, call.configError("账户服务未装配")
	}
	caller, err := f.admin().accountCaller(call.identity)
	if err != nil {
		return AdminUserValidity{}, call.configError("账户服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminUserValidity{}, err
	}
	validity, err := managed.Account.GetUserValidity(ctx, caller, req.UserID)
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, account.ErrUserNotFound, "user"); ok {
			return AdminUserValidity{}, replaced
		}
		return AdminUserValidity{}, call.domainError("读取账户有效期失败",
			string(account.CodeOf(err)))
	}
	return adminUserValidityOf(validity), nil
}

// SetUserValidity 设置账户全局有效期（root 拒绝、审计失败整体拒绝）。
func (f *userLifecycleFacade) SetUserValidity(ctx context.Context,
	req AdminUserValidityRequest) (AdminUserValidityChange, error) {
	call, err := f.admin().begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminUserValidityChange{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Account == nil {
		return AdminUserValidityChange{}, call.configError("账户服务未装配")
	}
	caller, err := f.admin().accountCaller(call.identity)
	if err != nil {
		return AdminUserValidityChange{}, call.configError("账户服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminUserValidityChange{}, err
	}
	result, err := managed.Account.SetValidity(ctx, caller, account.ValidityCommandRequest{
		UserID: req.UserID, ExpectedRowVersion: req.ExpectedRowVersion,
		ValidFrom: req.ValidFrom, ValidUntil: req.ValidUntil})
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, account.ErrUserNotFound, "user"); ok {
			return AdminUserValidityChange{}, replaced
		}
		return AdminUserValidityChange{}, call.domainError("设置账户有效期失败",
			string(account.CodeOf(err)))
	}
	return AdminUserValidityChange{
		Validity: adminUserValidityOf(account.UserValidity{UserID: result.User.ID,
			Status: result.User.Status, ValidFrom: result.User.ValidFrom,
			ValidUntil: result.User.ValidUntil, RowVersion: result.User.RowVersion,
			Available: availableNow(result.User, f.r.runtimeNow()),
			Reason:    availabilityReasonNow(result.User, f.r.runtimeNow()),
			CheckedAt: f.r.runtimeNow()}),
		PreviousValidFrom:  cloneAdminTime(result.PreviousValidFrom),
		PreviousValidUntil: cloneAdminTime(result.PreviousValidUntil),
		Changed:            result.Changed}, nil
}

// adminUserValidityOf 把账户领域有效期快照映射为公开视图。
func adminUserValidityOf(validity account.UserValidity) AdminUserValidity {
	return AdminUserValidity{UserID: validity.UserID, Status: string(validity.Status),
		IsRoot: validity.IsRoot, ValidFrom: cloneAdminTime(validity.ValidFrom),
		ValidUntil: cloneAdminTime(validity.ValidUntil), RowVersion: validity.RowVersion,
		Available: validity.Available, Reason: string(validity.Reason),
		CheckedAt: validity.CheckedAt}
}

// cloneAdminTime 复制可选 UTC 时间，避免调用方改写内部快照。
func cloneAdminTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	converted := value.UTC()
	return &converted
}

// availableNow/availabilityReasonNow 是变更结果中“当前可用性”的轻量计算。
func availableNow(user account.User, now time.Time) bool {
	available, _ := user.AvailabilityAt(now, false)
	return available
}

// availabilityReasonNow 返回当前可用性原因。
func availabilityReasonNow(user account.User, now time.Time) account.AvailabilityReason {
	_, reason := user.AvailabilityAt(now, false)
	return reason
}
