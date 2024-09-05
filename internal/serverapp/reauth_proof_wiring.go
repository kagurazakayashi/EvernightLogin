package serverapp

// 步骤 255：把目标绑定一次性两步验证操作证明所需的晚接线依赖接到真实服务。
//
// 直接管理操作（users.username.change.other / users.password.reset.other）的证明需要：
//   - 会话仍有效：*session.Service.VerifyActiveSession（真实门面，不只是字符串比较）；
//   - 操作者当前权限：managed.Checker 的真实权限内核（root 语义由内核统一决定，
//     本适配层不特殊放行）；
//   - WebAuthn 第二步：internal/passkey 的第二步 ceremony（contextID 使用本次
//     reauth 挑战 ID，挑战绑定不会被挪用到其它登录/操作），使无密码 Passkey 账户
//     不必先添加密码。
//
// 这些依赖在 base.go 的装配顺序里晚于 reauth 服务构造，因此使用 reauth 提供的
// Set* 晚接线入口；任一真实实现缺失时相关路径在 reauth 层 fail-closed，不会降级
// 为单因素或跳过会话/权限复核。

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	"github.com/kagurazakayashi/EvernightLogin/internal/passkey"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
)

// reauthPermissionChecker 把宿主真实权限判定适配为 reauth.PermissionChecker。
//
// 两级判定（步骤 255 修复）：
//   - CheckOperationPermission：事务外使用真实 authz 内核做完整判定（含 root 全权限
//     语义、账户/范围状态、来源与数据范围）；
//   - CheckOperationPermissionTx：最终提交事务内使用**同一 tx 连接**只读复核系统范围
//     的功能权限（账户 active/有效期、会话安全版本由 reauth 另行核对；权限行启用、
//     非 root_only、存在已启用的用户角色/组成员角色来源；root 按预设实现目录 +
//     DB 启停状态判定）。它不包含应用范围/数据范围判定（直接管理只跑系统范围功能
//     权限），也不修改任何表；权威判定仍是 authz 内核，这里只收敛“准备→提交”
//     窗口内的撤销，避免另开连接造成 SQLite 写事务互锁。
type reauthPermissionChecker struct {
	managed *ManagedServices
	catalog *presetPermissionCatalog
	// now 是注入时钟（步骤 255 修复二轮 N-255-7）：事务内账户有效期判定必须使用
	// 宿主注入时钟，不能用真实墙钟，保证可控时钟下行为确定。
	now func() time.Time
}

// currentNow 返回注入时钟；未注入时退回 time.Now（仅防御性兜底，生产装配总注入）。
func (c reauthPermissionChecker) currentNow() time.Time {
	if c.now != nil {
		return c.now().UTC()
	}
	return time.Now().UTC()
}

// CheckOperationPermission 复核操作者在系统范围内仍持有直接管理权限。
//
// 权限内核使用独立只读连接，本方法由 reauth 在**审计事务外**（证明准备阶段与挑战
// 发起阶段）调用；证明消费事务内改用 CheckOperationPermissionTx。
func (c reauthPermissionChecker) CheckOperationPermission(ctx context.Context,
	userID, permissionKey string) error {
	if c.managed == nil || c.managed.Checker == nil {
		return fmt.Errorf("%w: 权限内核未装配", reauth.ErrProofUnavailable)
	}
	if err := c.managed.Checker.check(ctx, userID, permissionKey, "system"); err != nil {
		// 权限存储不可用时向上传递可诊断错误；明确拒绝统一映射为权限不足。
		if errors.Is(err, authz.ErrStoreUnavailable) {
			return fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
		}
		return err
	}
	return nil
}

// CheckOperationPermissionTx 在调用方审计事务内用同一连接只读复核系统范围功能权限。
func (c reauthPermissionChecker) CheckOperationPermissionTx(ctx context.Context, tx audit.Tx,
	userID, permissionKey string) error {
	if tx == nil || c.catalog == nil {
		return fmt.Errorf("%w: 事务内权限复核依赖未装配", reauth.ErrProofUnavailable)
	}
	var (
		status          string
		securityVersion int64
		isRoot          int
		validFrom       sql.NullInt64
		validUntil      sql.NullInt64
	)
	rows, err := tx.QueryContext(ctx,
		`SELECT status,security_version,is_root,valid_from_ms,valid_until_ms FROM users WHERE id=?`,
		userID)
	if err != nil {
		return fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	found := rows.Next()
	if found {
		if err := rows.Scan(&status, &securityVersion, &isRoot, &validFrom, &validUntil); err != nil {
			_ = rows.Close()
			return fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
		}
	}
	_ = rows.Close()
	if !found {
		return fmt.Errorf("操作者账户不存在")
	}
	_ = securityVersion
	if status != "active" {
		return fmt.Errorf("操作者账户不可用")
	}
	now := c.currentNow()
	if validFrom.Valid && now.Before(time.UnixMilli(validFrom.Int64)) {
		return fmt.Errorf("操作者账户尚未生效")
	}
	if validUntil.Valid && !now.Before(time.UnixMilli(validUntil.Int64)) {
		return fmt.Errorf("操作者账户已过期")
	}
	// 权限行状态（系统范围）：存在、启用；root_only 由下方按主体判定。
	var permissionID string
	var permissionEnabled, rootOnly sql.NullBool
	permRows, err := tx.QueryContext(ctx,
		`SELECT id,enabled,root_only FROM permissions WHERE scope_id='system' AND permission_key=?`,
		permissionKey)
	if err != nil {
		return fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	permissionFound := permRows.Next()
	if permissionFound {
		if err := permRows.Scan(&permissionID, &permissionEnabled, &rootOnly); err != nil {
			_ = permRows.Close()
			return fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
		}
	}
	_ = permRows.Close()
	if isRoot == 1 {
		// root 全权限：DB 有记录时以启停为准；目录登记未实现 → 拒绝；未知权限 → 拒绝。
		if permissionFound {
			if !permissionEnabled.Valid || !permissionEnabled.Bool {
				return fmt.Errorf("权限已停用")
			}
			if implemented, known := c.catalog.IsImplemented(permissionKey); known && !implemented {
				return fmt.Errorf("权限能力尚未实现")
			}
			return nil
		}
		if _, implemented := c.catalog.ImplementedPermission(permissionKey); implemented {
			return nil
		}
		return fmt.Errorf("root 权限未登记或未实现")
	}
	if !permissionFound || !permissionEnabled.Valid || !permissionEnabled.Bool {
		return fmt.Errorf("权限不存在或已停用")
	}
	if rootOnly.Valid && rootOnly.Bool {
		return fmt.Errorf("权限为 root 专属")
	}
	// 至少一个“仍实际授权该权限”的已启用系统范围角色来源（用户直授或用户组继承）。
	// 步骤 255 修复二轮 F1：必须 JOIN role_permissions——角色仍启用但从角色移除了该
	// 权限时，终检必须拒绝（否则 ≤5s 窗口内旧 prepared 仍可消费）。
	sourceRows, err := tx.QueryContext(ctx, `SELECT 1 FROM (
	SELECT ur.role_id AS role_id FROM user_roles ur WHERE ur.user_id=? AND ur.scope_id='system'
	UNION
	SELECT gr.role_id AS role_id FROM group_members gm
	JOIN group_roles gr ON gr.group_id=gm.group_id AND gr.scope_id='system'
	WHERE gm.user_id=?
) src JOIN roles r ON r.id=src.role_id AND r.scope_id='system'
JOIN role_permissions rp ON rp.role_id=r.id AND rp.permission_id=?
	AND rp.scope_id='system'
WHERE r.enabled=1 LIMIT 1`, userID, userID, permissionID)
	if err != nil {
		return fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	granted := sourceRows.Next()
	_ = sourceRows.Close()
	if !granted {
		return fmt.Errorf("缺少有效权限来源（角色未授权该权限或已停用）")
	}
	return nil
}

// reauthPasskeyVerifier 把 internal/passkey 的第二步 ceremony 适配为
// reauth.StrongWebAuthnVerifier。
type reauthPasskeyVerifier struct {
	service *passkey.Service
}

// BeginStrongWebAuthn 开始 Passkey/安全密钥第二步断言；contextID=reauth 挑战 ID。
func (v reauthPasskeyVerifier) BeginStrongWebAuthn(ctx context.Context, userID, contextID,
	requestID string) (reauth.StrongWebAuthnStart, error) {
	if v.service == nil {
		return reauth.StrongWebAuthnStart{}, fmt.Errorf("passkey 服务未装配")
	}
	start, err := v.service.BeginSecondFactor(ctx, userID, contextID, requestID)
	if err != nil {
		return reauth.StrongWebAuthnStart{}, err
	}
	return reauth.StrongWebAuthnStart{CeremonyID: start.CeremonyID,
		PublicKey: []byte(start.PublicKey), RPID: start.RPID,
		ExpiresAt: start.ExpiresAt}, nil
}

// FinishStrongWebAuthn 校验第二步断言并返回真实强因素事实；不签发会话。
func (v reauthPasskeyVerifier) FinishStrongWebAuthn(ctx context.Context, userID, contextID,
	ceremonyID string, response []byte, requestID string) (reauth.StrongFactorVerifyResult, error) {
	if v.service == nil {
		return reauth.StrongFactorVerifyResult{}, fmt.Errorf("passkey 服务未装配")
	}
	result, err := v.service.FinishSecondFactor(ctx, passkey.SecondFactorFinishRequest{
		CeremonyID: ceremonyID, ContextID: contextID,
		Response: json.RawMessage(response), RequestID: requestID,
	})
	if err != nil {
		return reauth.StrongFactorVerifyResult{}, err
	}
	return reauth.StrongFactorVerifyResult{UserID: result.UserID,
		CompletedAt: result.VerifiedAt, Method: "passkey",
		UserVerified: result.UserVerified}, nil
}

// wireReauthOperationProof 在安全闸门、会话、权限内核与 Passkey 服务构造完成后接线
// 目标绑定操作证明依赖。会话缺失（完整装配中不可能）返回错误拒绝启动，避免静默
// 关闭直接管理证明的安全校验。
func wireReauthOperationProof(gate *SecurityGate, services *Services,
	managed *ManagedServices, security *SecurityDomains,
	now func() time.Time) error {
	if gate == nil || gate.Reauth == nil {
		return fmt.Errorf("目标绑定操作证明接线缺少再次认证服务")
	}
	if services == nil || services.Sessions == nil {
		return fmt.Errorf("目标绑定操作证明接线缺少会话服务")
	}
	gate.Reauth.SetSessionVerifier(services.Sessions)
	if managed != nil && managed.Checker != nil {
		catalog, catalogErr := newPresetPermissionCatalog()
		if catalogErr != nil {
			return fmt.Errorf("目标绑定操作证明接线缺少权限实现目录: %w", catalogErr)
		}
		gate.Reauth.SetPermissionChecker(reauthPermissionChecker{
			managed: managed, catalog: catalog, now: now})
	}
	if security != nil && security.Passkey != nil {
		gate.Reauth.SetStrongWebAuthn(reauthPasskeyVerifier{service: security.Passkey})
	}
	return nil
}
