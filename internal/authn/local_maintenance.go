package authn

// 步骤 287（本地维护控制台）：凭证状态只读窄方法。
//
// 本地维护身份需要展示“是否已有密码/是否 root”，用于救援时判断设置新密码是否
// 为“添加凭证”，但**永远不能读取旧密码或哈希**。普通远程入口不经过本方法。
//
// 安全边界：显式 LocalMaintenanceCaller（字段不可 JSON 反序列化，仅本机
// login-setup 装配）；只读查询，不改变任何状态，不返回凭证材料/哈希/失败细节。

import (
	"context"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// LocalMaintenanceCaller 是仅供本机维护控制台使用的显式本地身份。
type LocalMaintenanceCaller struct {
	operatorID string
}

// NewLocalMaintenanceCaller 构造本地维护身份；只应由 cmd/login-setup（经
// internal/setupconsole）调用，不代表任何 Evernight 账户或 HTTP 身份。
func NewLocalMaintenanceCaller(operatorID string) (LocalMaintenanceCaller, error) {
	actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: operatorID}
	if err := actor.Validate(); err != nil {
		return LocalMaintenanceCaller{}, fmt.Errorf("%w: 本地维护操作者标识无效", ErrInvalidRequest)
	}
	return LocalMaintenanceCaller{operatorID: operatorID}, nil
}

// OperatorID 返回审计用本地操作者标识。
func (c LocalMaintenanceCaller) OperatorID() string { return c.operatorID }

// LocalMaintenancePasswordResult 是本地维护设置密码结果（不含密码/哈希）。
type LocalMaintenancePasswordResult struct {
	UserID            string
	SecurityVersion   int64
	PasswordChangedAt time.Time
	MustChange        bool
}

// LocalMaintenanceSetPassword 由本地维护身份设置/重置普通账户密码：不要求目标
// 当前密码、应用 MFA 或近期再次认证（本地绝对权限），但复用完全相同的密码策略、
// 历史复用检查、哈希、会话失效/审计事务；root 仍拒绝（root 走 SetRootPassword
// 本地受控流程）。新密码只用于本次调用，不记录、不回显。
func (s *Service) LocalMaintenanceSetPassword(ctx context.Context,
	caller LocalMaintenanceCaller, targetUserID, newPassword string,
	requireChange bool, requestID string) (LocalMaintenancePasswordResult, error) {
	if caller.operatorID == "" {
		return LocalMaintenancePasswordResult{}, ErrAccessDenied
	}
	if !account.ValidUserID(targetUserID) || account.ValidateRequestID(requestID) != nil {
		return LocalMaintenancePasswordResult{}, fmt.Errorf("%w: 参数无效", ErrInvalidRequest)
	}
	internalCaller, err := LocalAdminCaller(caller.operatorID)
	if err != nil {
		return LocalMaintenancePasswordResult{}, err
	}
	result, err := s.setPasswordInternal(ctx, internalCaller, SetPasswordRequest{
		TargetUserID: targetUserID, NewPassword: newPassword,
		RequireChange: requireChange, RequestID: requestID}, true)
	if err != nil {
		return LocalMaintenancePasswordResult{}, err
	}
	return LocalMaintenancePasswordResult{UserID: result.UserID,
		SecurityVersion:   result.SecurityVersion,
		PasswordChangedAt: result.PasswordChangedAt}, nil
}

// LocalMaintenanceSetRootPassword 由本地维护身份在任意初始化状态（含 ready）为
// 唯一 root 重设正式密码：复用完整密码策略/历史/哈希/安全版本递增/关键审计，
// 允许正常运行实例救援；普通 SetRootPassword 的状态机行为不变（ready 仍拒绝）。
// root 旧密码/旧会话通过安全版本递增失效；本方法不签发会话、不改变 MFA 状态。
func (s *Service) LocalMaintenanceSetRootPassword(ctx context.Context,
	caller LocalMaintenanceCaller, rootUserID, newPassword, requestID string) (
	RootPasswordResult, error) {
	if caller.operatorID == "" {
		return RootPasswordResult{}, ErrAccessDenied
	}
	internalCaller, err := LocalAdminCaller(caller.operatorID)
	if err != nil {
		return RootPasswordResult{}, err
	}
	return s.setRootPasswordInternal(ctx, internalCaller, SetRootPasswordRequest{
		RootUserID: rootUserID, NewPassword: newPassword, RequestID: requestID}, true)
}

// LocalMaintenanceCredentialStatus 是凭证只读状态；不含密码/哈希/历史。
type LocalMaintenanceCredentialStatus struct {
	UserID      string
	HasPassword bool
	IsRoot      bool
}

// LocalMaintenanceCredentialStatus 只读报告目标账户凭证状态。
func (s *Service) LocalMaintenanceCredentialStatus(ctx context.Context,
	caller LocalMaintenanceCaller, userID string) (LocalMaintenanceCredentialStatus, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return LocalMaintenanceCredentialStatus{}, err
	}
	if caller.operatorID == "" {
		return LocalMaintenanceCredentialStatus{}, ErrAccessDenied
	}
	if !account.ValidUserID(userID) {
		return LocalMaintenanceCredentialStatus{}, fmt.Errorf("%w: 用户 ID 格式无效", ErrInvalidRequest)
	}
	user, found, err := s.store.FindUserByID(ctx, userID)
	if err != nil {
		return LocalMaintenanceCredentialStatus{}, s.storeFailure(ctx, "查询目标账户", err)
	}
	if !found {
		return LocalMaintenanceCredentialStatus{}, ErrUserNotFound
	}
	_, credentialFound, err := s.store.GetPasswordCredential(ctx, userID)
	if err != nil {
		return LocalMaintenanceCredentialStatus{}, s.storeFailure(ctx, "读取密码凭证状态", err)
	}
	return LocalMaintenanceCredentialStatus{UserID: user.UserID,
		HasPassword: credentialFound, IsRoot: user.IsRoot}, nil
}
