package setupconsole

// WS3 288/290 安全域适配器：把本机维护身份接到已报备的领域窄方法
// （totp/mfa/passkey/recovery/session 的 *LocalMaintenance 方法）。
//
// 原则：
//   - 不绕过领域事务：每个删除操作仍走领域审计事务与安全版本/会话失效；
//   - 不读取种子/公钥/验证码/恢复代码；列表只返回脱敏元数据；
//   - 领域服务未装配（配置关闭）时明确返回 ErrLocalUnsupported，画面 fail-closed；
//   - 主登录 Passkey 与第二步 Passkey 按 Usage 区分，逐项显示并显式选择。

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/mfa"
	"github.com/kagurazakayashi/EvernightLogin/internal/passkey"
	"github.com/kagurazakayashi/EvernightLogin/internal/recovery"
	"github.com/kagurazakayashi/EvernightLogin/internal/serverapp"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	"github.com/kagurazakayashi/EvernightLogin/internal/totp"
)

type localSecurityAdmin struct {
	base       *serverapp.Base
	operatorID string
}

func newLocalSecurityAdmin(base *serverapp.Base, operatorID string) (*localSecurityAdmin, error) {
	if base == nil || base.Services == nil {
		return nil, fmt.Errorf("%w: 安全域服务未装配", ErrLocalRuntimeUnavailable)
	}
	return &localSecurityAdmin{base: base, operatorID: operatorID}, nil
}

func (a *localSecurityAdmin) targetUserExists(ctx context.Context, userID string) error {
	if a.base.Managed == nil || a.base.Managed.Account == nil {
		return fmt.Errorf("%w: 账户服务未装配", ErrLocalUnsupported)
	}
	caller, err := mustAccountCaller(a.operatorID), error(nil)
	if err != nil {
		return err
	}
	if _, err := a.base.Managed.Account.GetUser(ctx, caller, strings.TrimSpace(userID)); err != nil {
		return localDomainError("读取目标用户", err)
	}
	return nil
}

func (a *localSecurityAdmin) totpCaller() (totp.LocalMaintenanceCaller, error) {
	return totp.NewLocalMaintenanceCaller(a.operatorID)
}

func (a *localSecurityAdmin) mfaCaller() (mfa.LocalMaintenanceCaller, error) {
	return mfa.NewLocalMaintenanceCaller(a.operatorID)
}

func (a *localSecurityAdmin) passkeyCaller() (passkey.LocalMaintenanceCaller, error) {
	return passkey.NewLocalMaintenanceCaller(a.operatorID)
}

func (a *localSecurityAdmin) recoveryCaller() (recovery.LocalMaintenanceCaller, error) {
	return recovery.NewLocalMaintenanceCaller(a.operatorID)
}

func (a *localSecurityAdmin) sessionCaller() (session.LocalMaintenanceCaller, error) {
	return session.NewLocalMaintenanceCaller(a.operatorID)
}

func (a *localSecurityAdmin) ListFactors(ctx context.Context,
	userID string) ([]LocalFactor, error) {
	userID = strings.TrimSpace(userID)
	if err := a.targetUserExists(ctx, userID); err != nil {
		return nil, err
	}
	if a.base.Security == nil {
		return nil, fmt.Errorf("%w: 安全域未装配", ErrLocalUnsupported)
	}
	factors := make([]LocalFactor, 0, 8)
	if a.base.Security.TOTP != nil {
		caller, err := a.totpCaller()
		if err != nil {
			return nil, err
		}
		bindings, err := a.base.Security.TOTP.LocalMaintenanceListBindings(ctx, caller, userID)
		if err != nil {
			return nil, localDomainError("列举 TOTP 因素", err)
		}
		for _, binding := range bindings {
			state := "已绑定"
			if binding.Status != "active" {
				state = binding.Status
			}
			factors = append(factors, LocalFactor{Kind: LocalFactorTOTP, ID: binding.ID,
				Label: "TOTP 验证器（" + state + "）", CreatedAt: binding.CreatedAt})
		}
	}
	if a.base.Security.MFA != nil {
		caller, err := a.mfaCaller()
		if err != nil {
			return nil, err
		}
		items, err := a.base.Security.MFA.LocalMaintenanceFactors(ctx, caller, userID)
		if err != nil {
			return nil, localDomainError("列举 MFA 因素", err)
		}
		for _, item := range items {
			kind := LocalFactorEmail
			switch item.Type {
			case mfa.FactorEmail:
				kind = LocalFactorEmail
			case mfa.FactorTOTP:
				// TOTP 已由 totp 绑定列表展示，跳过避免重复。
				continue
			case mfa.FactorPasskey:
				kind = LocalFactorPasskey
			default:
				continue
			}
			factors = append(factors, LocalFactor{Kind: kind, ID: item.ID,
				Label: "MFA 因素：" + string(item.Type), CreatedAt: item.CreatedAt})
		}
	}
	if a.base.Security.Passkey != nil {
		caller, err := a.passkeyCaller()
		if err != nil {
			return nil, err
		}
		credentials, err := a.base.Security.Passkey.LocalMaintenanceListCredentials(ctx, caller, userID)
		if err != nil {
			return nil, localDomainError("列举 Passkey", err)
		}
		for _, credential := range credentials {
			primary := strings.TrimSpace(credential.Usage) != "second_factor"
			label := "Passkey：" + credential.Name
			if primary {
				label += "（可用于主登录）"
			} else {
				label += "（仅第二步）"
			}
			factors = append(factors, LocalFactor{Kind: LocalFactorPasskey,
				ID: credential.ID, Label: label, CreatedAt: credential.CreatedAt,
				LastUsedAt: credential.LastUsedAt, Primary: primary})
		}
	}
	if a.base.Security.Recovery != nil {
		caller, err := a.recoveryCaller()
		if err != nil {
			return nil, err
		}
		status, err := a.base.Security.Recovery.LocalMaintenanceRecoveryStatus(ctx, caller, userID)
		if err != nil {
			return nil, localDomainError("读取恢复代码状态", err)
		}
		if status.HasActiveGroup {
			factors = append(factors, LocalFactor{Kind: LocalFactorRecovery,
				Label: fmt.Sprintf("恢复代码（剩余 %d 条，组 %s）", status.RemainingCodes,
					status.GroupID), CreatedAt: status.CreatedAt})
		}
	}
	return factors, nil
}

func (a *localSecurityAdmin) RemoveFactor(ctx context.Context, userID string,
	factor LocalFactor, reason string) error {
	userID = strings.TrimSpace(userID)
	_ = reason
	if a.base.Security == nil {
		return fmt.Errorf("%w: 安全域未装配", ErrLocalUnsupported)
	}
	requestID := ws3RequestID("req_local_factor_remove")
	switch factor.Kind {
	case LocalFactorTOTP:
		if a.base.Security.TOTP == nil {
			return fmt.Errorf("%w: TOTP 未启用", ErrLocalUnsupported)
		}
		caller, err := a.totpCaller()
		if err != nil {
			return err
		}
		return localDomainError("删除 TOTP 因素",
			a.base.Security.TOTP.LocalMaintenanceRemoveBinding(ctx, caller, userID, requestID))
	case LocalFactorEmail:
		if a.base.Security.MFA == nil {
			return fmt.Errorf("%w: MFA 未启用", ErrLocalUnsupported)
		}
		caller, err := a.mfaCaller()
		if err != nil {
			return err
		}
		return localDomainError("删除邮件因素",
			a.base.Security.MFA.LocalMaintenanceRemoveEmailFactor(ctx, caller, userID, requestID))
	case LocalFactorPasskey:
		if a.base.Security.Passkey == nil {
			return fmt.Errorf("%w: Passkey 未启用", ErrLocalUnsupported)
		}
		if strings.TrimSpace(factor.ID) == "" {
			return fmt.Errorf("Passkey 凭证 ID 不能为空")
		}
		caller, err := a.passkeyCaller()
		if err != nil {
			return err
		}
		return localDomainError("撤销 Passkey",
			a.base.Security.Passkey.LocalMaintenanceRevokeCredential(ctx, caller, userID,
				factor.ID, requestID))
	case LocalFactorRecovery:
		return a.RevokeRecoveryCodes(ctx, userID, reason)
	default:
		return fmt.Errorf("未知因素类型：%s", factor.Kind)
	}
}

func (a *localSecurityAdmin) RevokeRecoveryCodes(ctx context.Context, userID,
	reason string) error {
	_ = reason
	if a.base.Security == nil || a.base.Security.Recovery == nil {
		return fmt.Errorf("%w: 恢复代码服务未启用", ErrLocalUnsupported)
	}
	caller, err := a.recoveryCaller()
	if err != nil {
		return err
	}
	return localDomainError("撤销恢复代码",
		a.base.Security.Recovery.LocalMaintenanceRevokeRecoveryCodes(ctx, caller,
			strings.TrimSpace(userID), ws3RequestID("req_local_recovery_revoke")))
}

// ClearSecondFactors 是本地显式“清除第二因素”动作：按因素逐项调用既有删除窄方法，
// 不是跨因素单一事务（DEFERRED-M2A-1：部分失败会把已完成项保留并返回错误，画面
// 明确提示；不会声称整体成功）。主登录 Passkey 默认保留，删除需显式选择。
func (a *localSecurityAdmin) ClearSecondFactors(ctx context.Context, userID string,
	includePrimaryPasskeys bool, reason string) error {
	userID = strings.TrimSpace(userID)
	if a.targetUserExists(ctx, userID) != nil {
		return localDomainError("读取目标用户", fmt.Errorf("目标用户不存在"))
	}
	factors, err := a.ListFactors(ctx, userID)
	if err != nil {
		return err
	}
	removed := 0
	for _, factor := range factors {
		if factor.Kind == LocalFactorPasskey {
			if factor.Primary && !includePrimaryPasskeys {
				continue
			}
			if !factor.Primary && !includePrimaryPasskeys {
				// 第二步 Passkey 属于第二因素，显式删除；主登录 Passkey 默认保留。
			}
		}
		if factor.Kind == LocalFactorRecovery {
			if err := a.RevokeRecoveryCodes(ctx, userID, reason); err != nil {
				return err
			}
			removed++
			continue
		}
		if err := a.RemoveFactor(ctx, userID, factor, reason); err != nil {
			if errors.Is(err, mfa.ErrFactorNotFound) || errors.Is(err, totp.ErrBindingNotFound) {
				continue
			}
			return err
		}
		removed++
	}
	if removed == 0 {
		return fmt.Errorf("%w: 没有可清除的第二因素", ErrLocalUnsupported)
	}
	return nil
}

func (a *localSecurityAdmin) ListSessions(ctx context.Context, userID string,
	limit, offset int) ([]LocalSession, bool, error) {
	if a.base.Services == nil || a.base.Services.Sessions == nil {
		return nil, false, fmt.Errorf("%w: 会话服务未装配", ErrLocalUnsupported)
	}
	caller, err := a.sessionCaller()
	if err != nil {
		return nil, false, err
	}
	items, hasMore, err := a.base.Services.Sessions.LocalMaintenanceListUserSessions(
		ctx, caller, strings.TrimSpace(userID), limit, offset)
	if err != nil {
		return nil, false, localDomainError("列举会话", err)
	}
	result := make([]LocalSession, 0, len(items))
	for _, item := range items {
		result = append(result, LocalSession{ID: item.ID, Kind: string(item.Kind),
			AppID: item.AppID, CreatedAt: item.CreatedAt, LastSeenAt: item.LastSeenAt,
			ExpiresAt: item.AbsoluteExpiresAt, IPSummary: item.Address,
			UserAgent: item.UserAgent})
	}
	return result, hasMore, nil
}

func (a *localSecurityAdmin) RevokeSessions(ctx context.Context, userID,
	reason string) (int64, error) {
	if a.base.Services == nil || a.base.Services.Sessions == nil {
		return 0, fmt.Errorf("%w: 会话服务未装配", ErrLocalUnsupported)
	}
	if strings.TrimSpace(reason) == "" {
		reason = "local_maintenance_revoke"
	}
	caller, err := a.sessionCaller()
	if err != nil {
		return 0, err
	}
	count, err := a.base.Services.Sessions.LocalMaintenanceRevokeAllSessions(ctx, caller,
		strings.TrimSpace(userID), sanitizeSessionReason(reason),
		ws3RequestID("req_local_session_revoke"))
	if err != nil {
		return 0, localDomainError("强制下线", err)
	}
	return count, nil
}

// sanitizeSessionReason 把本地画面理由转为会话服务允许的可见 ASCII 原因码。
func sanitizeSessionReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return "local_maintenance_revoke"
	}
	build := make([]byte, 0, len(reason))
	for index := 0; index < len(reason) && len(build) < 64; index++ {
		char := reason[index]
		if char < 0x21 || char > 0x7e {
			continue
		}
		build = append(build, char)
	}
	if len(build) == 0 {
		return "local_maintenance_revoke"
	}
	return string(build)
}

var _ = time.Now
