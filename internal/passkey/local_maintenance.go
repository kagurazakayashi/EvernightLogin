package passkey

// 步骤 288（本地维护控制台）：Passkey 凭证本地列举/撤销（含主登录 Passkey）。
//
// 普通 List/Revoke 是本人 + 再次认证语义；本地维护在丢失因素场景以 OS 访问权限
// 直接清除。本窄方法复用同一 Store 事务与审计，跳过本人/再次认证与“最后登录方式”
// 保护（救援必须允许删到零，画面会给出重绑/设密路径），但仍在同一审计事务内：
//   - RevokeCredentialTx 软撤销指定/全部凭证；
//   - IncrementUserSecurityVersionTx 使旧会话立即失效；
//   - 审计事务提交后按既有系统路径撤销会话（失败只告警）。
//
// 边界：主登录 Passkey 与第二步凭证可能重叠，调用方画面逐项显示用途并显式选择；
// 不删除其他用户凭证、不读取公钥/认证器数据。

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
// internal/setupconsole）调用，不代表 Evernight 账户/HTTP 身份。
func NewLocalMaintenanceCaller(operatorID string) (LocalMaintenanceCaller, error) {
	actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: operatorID}
	if err := actor.Validate(); err != nil {
		return LocalMaintenanceCaller{}, fmt.Errorf("%w: 本地维护操作者标识无效", ErrInvalidRequest)
	}
	return LocalMaintenanceCaller{operatorID: operatorID}, nil
}

// OperatorID 返回审计用本地操作者标识。
func (c LocalMaintenanceCaller) OperatorID() string { return c.operatorID }

// LocalMaintenanceCredential 是 Passkey 凭证脱敏摘要。
type LocalMaintenanceCredential struct {
	ID         string
	Name       string
	Usage      string
	CreatedAt  time.Time
	LastUsedAt time.Time
}

// LocalMaintenanceListCredentials 列出目标用户未撤销的 Passkey 凭证。
func (s *Service) LocalMaintenanceListCredentials(ctx context.Context,
	caller LocalMaintenanceCaller, targetUserID string) ([]LocalMaintenanceCredential, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if caller.operatorID == "" {
		return nil, ErrAccessDenied
	}
	if !account.ValidUserID(targetUserID) {
		return nil, fmt.Errorf("%w: 目标用户 ID 格式无效", ErrInvalidRequest)
	}
	credentials, err := s.opts.Store.ListActiveCredentials(ctx, targetUserID)
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	result := make([]LocalMaintenanceCredential, 0, len(credentials))
	for _, credential := range credentials {
		result = append(result, LocalMaintenanceCredential{ID: credential.ID,
			Name: credential.Name, Usage: credential.Usage,
			CreatedAt: credential.CreatedAt, LastUsedAt: credential.LastUsedAt})
	}
	return result, nil
}

// LocalMaintenanceRevokeCredential 撤销目标用户指定 Passkey 凭证（无本人/再次
// 认证；本地救援专用）。凭证不存在/已撤销返回 ErrCredentialNotFound。
func (s *Service) LocalMaintenanceRevokeCredential(ctx context.Context,
	caller LocalMaintenanceCaller, targetUserID, credentialID, requestID string) error {
	credentials, err := s.localMaintenanceTargetCredentials(ctx, caller,
		targetUserID, requestID)
	_ = credentials
	if err != nil {
		return err
	}
	return s.localMaintenanceRevoke(ctx, caller, targetUserID, requestID,
		[]string{credentialID})
}

// LocalMaintenanceRevokeAllCredentials 撤销目标用户全部 Passkey 凭证（主登录与
// 第二步一起，救援场景显式动作）。
func (s *Service) LocalMaintenanceRevokeAllCredentials(ctx context.Context,
	caller LocalMaintenanceCaller, targetUserID, requestID string) error {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if caller.operatorID == "" {
		return ErrAccessDenied
	}
	if !account.ValidUserID(targetUserID) || account.ValidateRequestID(requestID) != nil {
		return fmt.Errorf("%w: 参数无效", ErrInvalidRequest)
	}
	credentials, err := s.opts.Store.ListActiveCredentials(ctx, targetUserID)
	if err != nil {
		return ErrStoreUnavailable
	}
	ids := make([]string, 0, len(credentials))
	for _, credential := range credentials {
		ids = append(ids, credential.ID)
	}
	if len(ids) == 0 {
		return ErrCredentialNotFound
	}
	return s.localMaintenanceRevoke(ctx, caller, targetUserID, requestID, ids)
}

func (s *Service) localMaintenanceTargetCredentials(ctx context.Context,
	caller LocalMaintenanceCaller, targetUserID, requestID string) ([]Credential, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if caller.operatorID == "" {
		return nil, ErrAccessDenied
	}
	if !account.ValidUserID(targetUserID) || account.ValidateRequestID(requestID) != nil {
		return nil, fmt.Errorf("%w: 参数无效", ErrInvalidRequest)
	}
	credentials, err := s.opts.Store.ListActiveCredentials(ctx, targetUserID)
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	return credentials, nil
}

func (s *Service) localMaintenanceRevoke(ctx context.Context,
	caller LocalMaintenanceCaller, targetUserID, requestID string, credentialIDs []string) error {
	actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: caller.operatorID}
	changes := make([]audit.FieldChange, 0, len(credentialIDs)+1)
	for _, credentialID := range credentialIDs {
		changes = append(changes, audit.FieldChange{Field: "passkey_revoked",
			Before: credentialID, After: "revoked"})
	}
	changes = append(changes, audit.FieldChange{Field: "maintenance",
		After: "local_console"})
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: actor, Action: "passkey.local_maintenance_revoked",
			Target:    audit.Target{Type: "user", ID: targetUserID},
			RequestID: requestID, Changes: changes,
		},
		FailureReasonCode:   "passkey.local_maintenance_revoke_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	now := s.now()
	revoked := int64(0)
	err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		for _, credentialID := range credentialIDs {
			ok, revokeErr := s.opts.Store.RevokeCredentialTx(txCtx, tx, targetUserID,
				credentialID, "local_maintenance", now)
			if revokeErr != nil {
				return revokeErr
			}
			if !ok {
				return ErrCredentialNotFound
			}
			revoked++
		}
		return s.opts.Store.IncrementUserSecurityVersionTx(txCtx, tx, targetUserID, now)
	})
	if err != nil {
		return mapCriticalError(err)
	}
	if !isNil(s.opts.SessionInvalidator) {
		if _, revokeErr := s.opts.SessionInvalidator.RevokeAllForUser(ctx,
			targetUserID, "passkey_local_maintenance_removed"); revokeErr != nil {
			s.opts.Logger.Warn("本地维护撤销 Passkey 后撤销会话失败", "error", revokeErr)
		}
	}
	return nil
}
