package serverapp

// 步骤 188：人工恢复 MFA 重置后的“强制重新绑定强因素”状态存储与审计。
//
// 语义：
//   - MFA 恢复执行器成功重置因素后，在同一 MFA 审计事务内写入未清除需求；
//   - 登录时 authn 读取该需求，只签发受限初始化会话（绑定 Passkey 后才能完整登录）；
//   - 强认证初始化完成后清除需求并记录真实操作者/请求编号；
//   - 表只存事实（时间/原因/来源申请），不含秘密/凭证/令牌。

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// mfaRebindReasonManualRecovery 是人工恢复 MFA 重置写入的重绑原因码。
const mfaRebindReasonManualRecovery = "manual_recovery_mfa_reset"

// mfaRebindRequirementStore 是 authn/mfa 共享的强制重绑状态读写实现。
type mfaRebindRequirementStore struct {
	store  *storagesqlite.Store
	audit  *audit.Recorder
	logger *slog.Logger
}

// MFARebindRequired 实现 authn 的可选只读判定：存在未清除需求即为 true。
func (r mfaRebindRequirementStore) MFARebindRequired(ctx context.Context, userID string) (bool, error) {
	if r.store == nil {
		return false, errors.New("强制重绑存储未装配")
	}
	var cleared sql.NullInt64
	err := r.store.DB().QueryRowContext(ctx,
		`SELECT cleared_at_ms FROM mfa_rebind_requirements WHERE user_id=?`, userID).Scan(&cleared)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("读取强制重绑需求失败: %w", err)
	}
	return !cleared.Valid, nil
}

// MarkRebindRequiredTx 在 MFA 管理员重置事务内登记强制重绑需求（幂等 upsert）。
func (r mfaRebindRequirementStore) MarkRebindRequiredTx(ctx context.Context, tx audit.Tx,
	userID, sourceRequestID string, now time.Time) error {
	if tx == nil {
		return errors.New("强制重绑写入缺少审计事务")
	}
	if userID == "" || sourceRequestID == "" {
		return errors.New("强制重绑写入参数无效")
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO mfa_rebind_requirements(
user_id,required_at_ms,reason_code,source_request_id,cleared_at_ms)
VALUES(?,?,?,?,NULL)
ON CONFLICT(user_id) DO UPDATE SET required_at_ms=excluded.required_at_ms,
reason_code=excluded.reason_code,source_request_id=excluded.source_request_id,cleared_at_ms=NULL`,
		userID, now.UTC().UnixMilli(), mfaRebindReasonManualRecovery, sourceRequestID)
	if err != nil {
		return fmt.Errorf("登记强制重绑需求失败: %w", err)
	}
	return nil
}

// ClearRebindRequirement 在强认证初始化完成后清除需求并写真实审计；清除失败返回错误，
// 登录仍保持强制重绑（fail-closed）。
func (r mfaRebindRequirementStore) ClearRebindRequirement(ctx context.Context,
	userID, requestID string) error {
	if r.store == nil {
		return errors.New("强制重绑存储未装配")
	}
	result, err := r.store.DB().ExecContext(ctx, `UPDATE mfa_rebind_requirements
SET cleared_at_ms=? WHERE user_id=? AND cleared_at_ms IS NULL`,
		time.Now().UTC().UnixMilli(), userID)
	if err != nil {
		return fmt.Errorf("清除强制重绑需求失败: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		// 没有未清除需求（正常初始化流程）：保持幂等成功，不写误导性审计。
		return nil
	}
	if r.audit != nil {
		if recordErr := r.audit.Record(ctx, audit.Event{
			Actor:     audit.Actor{Type: audit.ActorUser, ID: userID},
			Action:    "mfa.rebind_requirement_cleared",
			Target:    audit.Target{Type: "user", ID: userID},
			Outcome:   audit.OutcomeSuccess,
			RequestID: requestID,
			Changes:   []audit.FieldChange{{Field: "rebind_requirement", Before: "pending", After: "cleared"}},
		}); recordErr != nil {
			if r.logger != nil {
				r.logger.Warn("清除强制重绑需求的审计写入失败", "error_category", "audit_unavailable")
			}
		}
	}
	return nil
}
