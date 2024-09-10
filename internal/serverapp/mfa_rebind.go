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
	"github.com/kagurazakayashi/EvernightLogin/internal/mfa"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// mfaRebindReasonManualRecovery 是人工恢复 MFA 重置写入的重绑原因码。
const mfaRebindReasonManualRecovery = "manual_recovery_mfa_reset"

// errRebindRequirementConflict 表示强认证初始化完成期间，重绑需求代际已被新的
// 恢复申请替换或已被清除（旧完成请求不得清掉更新的恢复要求）。
var errRebindRequirementConflict = errors.New("强制重绑需求在完成期间已变化")

// errRebindSecurityStateChanged 表示完成期间账户状态/安全版本已变化（例如又发生
// 一次 MFA 重置），本次完成不能再视为有效。
var errRebindSecurityStateChanged = errors.New("账户安全状态在完成期间已变化")

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

// RebindRequirementSnapshot 实现 mfa.StrongSetupFinalizer：读取当前未清除的重绑
// 需求代际快照（事务外只读，仅用于审计字段与条件清除期望值）。
func (r mfaRebindRequirementStore) RebindRequirementSnapshot(ctx context.Context,
	userID string) (mfa.RebindRequirementSnapshot, error) {
	if r.store == nil {
		return mfa.RebindRequirementSnapshot{}, errors.New("强制重绑存储未装配")
	}
	var (
		requiredAtMS int64
		sourceID     string
		cleared      sql.NullInt64
	)
	err := r.store.DB().QueryRowContext(ctx, `SELECT required_at_ms,source_request_id,cleared_at_ms
FROM mfa_rebind_requirements WHERE user_id=?`, userID).Scan(&requiredAtMS, &sourceID, &cleared)
	if errors.Is(err, sql.ErrNoRows) {
		return mfa.RebindRequirementSnapshot{}, nil
	}
	if err != nil {
		return mfa.RebindRequirementSnapshot{}, fmt.Errorf("读取强制重绑需求失败: %w", err)
	}
	if cleared.Valid {
		return mfa.RebindRequirementSnapshot{}, nil
	}
	return mfa.RebindRequirementSnapshot{Present: true, RequiredAtMS: requiredAtMS,
		SourceRequestID: sourceID}, nil
}

// FinalizeStrongSetupTx 实现 mfa.StrongSetupFinalizer：在强初始化完成的同一审计
// 事务内复核账户仍 active、security_version 与挑战一致，并按快照代际条件清除重绑
// 需求。任何不匹配都返回错误使整个完成事务回滚（fail-closed，可重新登录重试）。
func (r mfaRebindRequirementStore) FinalizeStrongSetupTx(ctx context.Context, tx audit.Tx,
	userID string, expected mfa.RebindRequirementSnapshot, challengeSecurityVersion int64) error {
	if tx == nil {
		return errors.New("强制重绑最终复核缺少审计事务")
	}
	if r.store == nil {
		return errors.New("强制重绑存储未装配")
	}
	var (
		status          string
		securityVersion int64
	)
	rows, err := tx.QueryContext(ctx, `SELECT status,security_version FROM users WHERE id=?`, userID)
	if err != nil {
		return fmt.Errorf("复核账户状态失败: %w", err)
	}
	if !rows.Next() {
		_ = rows.Close()
		return errRebindSecurityStateChanged
	}
	if scanErr := rows.Scan(&status, &securityVersion); scanErr != nil {
		_ = rows.Close()
		return fmt.Errorf("复核账户状态失败: %w", scanErr)
	}
	_ = rows.Close()
	if status != "active" {
		return errRebindSecurityStateChanged
	}
	// 挑战创建时的安全版本必须仍然一致：账户期间被重置/安全状态变化时，
	// 本次“新绑定”不再代表当前安全代际。
	if challengeSecurityVersion > 0 && securityVersion != challengeSecurityVersion {
		return errRebindSecurityStateChanged
	}
	var (
		requiredAtMS int64
		sourceID     string
		cleared      sql.NullInt64
	)
	requirementRows, err := tx.QueryContext(ctx, `SELECT required_at_ms,source_request_id,cleared_at_ms
FROM mfa_rebind_requirements WHERE user_id=?`, userID)
	if err != nil {
		return fmt.Errorf("复核强制重绑需求失败: %w", err)
	}
	found := requirementRows.Next()
	if found {
		if scanErr := requirementRows.Scan(&requiredAtMS, &sourceID, &cleared); scanErr != nil {
			_ = requirementRows.Close()
			return fmt.Errorf("复核强制重绑需求失败: %w", scanErr)
		}
	}
	_ = requirementRows.Close()
	present := found && !cleared.Valid
	if !expected.Present {
		// 快照时没有需求：完成期间出现新的未清除需求说明发生了新的恢复申请，
		// 不能把本次完成当作已满足新要求。
		if present {
			return errRebindRequirementConflict
		}
		return nil
	}
	if !present || requiredAtMS != expected.RequiredAtMS ||
		sourceID != expected.SourceRequestID {
		// 需求已被清除（并发完成）或替换（新恢复申请）：旧完成请求不得清除新需求。
		return errRebindRequirementConflict
	}
	result, err := tx.ExecContext(ctx, `UPDATE mfa_rebind_requirements
SET cleared_at_ms=? WHERE user_id=? AND cleared_at_ms IS NULL
AND required_at_ms=? AND source_request_id=?`,
		time.Now().UTC().UnixMilli(), userID, expected.RequiredAtMS, expected.SourceRequestID)
	if err != nil {
		return fmt.Errorf("条件清除强制重绑需求失败: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return errRebindRequirementConflict
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
