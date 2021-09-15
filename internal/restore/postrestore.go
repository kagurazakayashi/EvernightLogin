// 本文件实现恢复后处理：在恢复后数据库的**同一个事务**内删除全部一次性凭证与
// 会话材料、默认暂停旧调度/Webhook/任务/通知、写入恢复运行记录与暂停清单，并
// 校验恢复代际。提交成功后才允许退出维护；任何失败都回退数据库并保持维护。
package restore

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/maintenance"
)

// maxPausedItems 是单次恢复记录到暂停清单的逐项上限；超过时仍以集合语句暂停全部
// 对象，但只记录前若干项，聚合数量写入恢复运行记录（不静默截断事实）。
const maxPausedItems = 10000

// postProcessOutcome 是恢复后处理的真实结果。
type postProcessOutcome struct {
	Revoked RevocationCounts
	Paused  PausedCounts
}

// pausedItem 是一条记录到 restore_paused_items 的暂停对象。
type pausedItem struct {
	Kind          string
	TargetID      string
	PreviousState string
}

// postProcessRestoredDatabase 在恢复后数据库上执行凭证失效与默认暂停事务，并写
// 恢复运行记录/代际。事务提交后数据库即为“恢复完成且旧凭证已失效”的一致性状态。
func (s *Service) postProcessRestoredDatabase(ctx context.Context, token maintenance.Token,
	operator audit.Actor, request Request, summary BackupSummary, startedAt time.Time,
	rollbackFile string) (postProcessOutcome, error) {
	ctx = normalizeContext(ctx)
	var outcome postProcessOutcome
	store, err := s.openLiveStore(ctx)
	if err != nil {
		return outcome, fmt.Errorf("%w: %w", ErrPostProcessFailed, err)
	}
	defer func() { _ = store.Close() }()
	if err := s.fault("after_switch_before_postprocess"); err != nil {
		return outcome, err
	}
	now := s.nowUTC()
	transactionErr := store.Transaction(ctx, func(ctx context.Context, tx *sql.Tx) error {
		revoked, err := revokeCredentialMaterial(ctx, tx)
		if err != nil {
			return err
		}
		outcome.Revoked = revoked
		paused, items, err := pauseRestoreDisposition(ctx, tx, now)
		if err != nil {
			return err
		}
		outcome.Paused = paused
		if err := s.fault("postprocess_before_state_rows"); err != nil {
			return err
		}
		if err := writeRestoreStateRows(ctx, tx, token, operator, request, summary,
			startedAt, now, rollbackFile, outcome, items); err != nil {
			return err
		}
		// 提交前再次核对：所有代表的凭证表必须为空，否则按 fail-closed 回滚事务。
		if err := verifyNoLiveCredentials(ctx, tx); err != nil {
			return err
		}
		return nil
	})
	if transactionErr != nil {
		return postProcessOutcome{}, fmt.Errorf("%w: %w", ErrPostProcessFailed, transactionErr)
	}
	if err := s.fault("after_postprocess_before_complete"); err != nil {
		return outcome, err
	}
	return outcome, nil
}

// credentialTables 是恢复后必须清空的一次性凭证/会话材料表（按删除依赖顺序）。
// 密码哈希、MFA 因素、Passkey、OAuth 客户端密钥属于被恢复的账户/应用安全状态，
// 不在此列（删除它们会使被恢复账户无法登录，且不属于“一次性凭证复活”风险）。
var credentialTables = []struct {
	table string
	field *int64
}{
	{"refresh_tokens", nil},
	{"refresh_token_families", nil},
	{"oauth_authorization_codes", nil},
	{"oauth_authorization_requests", nil},
	{"recovery_attempts", nil},
	{"recovery_codes", nil},
	{"recovery_code_groups", nil},
	{"email_verification_tickets", nil},
	{"password_reset_requests", nil},
	{"email_change_requests", nil},
	{"app_qr_login_requests", nil},
	{"oauth_device_authorizations", nil},
	{"mfa_challenges", nil},
	{"webauthn_ceremonies", nil},
	{"reauth_approvals", nil},
	{"reauth_challenges", nil},
	{"invitation_acceptances", nil},
	{"invitations", nil},
	{"manual_recovery_executions", nil},
	{"manual_recovery_approvals", nil},
	{"manual_recovery_requests", nil},
	{"registration_reviews", nil},
	{"sessions", nil},
	{"one_time_credentials", nil},
	{"token_signing_keys", nil},
}

// revokeCredentialMaterial 在事务内删除全部会话/刷新族/授权码/恢复代码/验证链接/
// 扫码请求/一次性凭证/重认证挑战/邀请/刷新签名密钥，并返回真实删除行数。
func revokeCredentialMaterial(ctx context.Context, tx *sql.Tx) (RevocationCounts, error) {
	var counts RevocationCounts
	assign := func(table string, value int64) {
		switch table {
		case "refresh_tokens":
			counts.RefreshTokens = value
		case "refresh_token_families":
			counts.RefreshFamilies = value
		case "oauth_authorization_codes":
			counts.AuthorizationCodes = value
		case "oauth_authorization_requests":
			counts.AuthorizationRequests = value
		case "recovery_attempts":
			counts.RecoveryAttempts = value
		case "recovery_codes":
			counts.RecoveryCodes = value
		case "recovery_code_groups":
			counts.RecoveryGroups = value
		case "email_verification_tickets":
			counts.VerificationTickets = value
		case "password_reset_requests":
			counts.PasswordResets = value
		case "email_change_requests":
			counts.EmailChanges = value
		case "app_qr_login_requests":
			counts.QRLoginRequests = value
		case "oauth_device_authorizations":
			counts.DeviceAuthorizations = value
		case "mfa_challenges":
			counts.MFAChallenges += value
		case "webauthn_ceremonies":
			counts.WebAuthnCeremonies += value
		case "reauth_approvals", "reauth_challenges":
			counts.ReauthItems += value
		case "invitations", "invitation_acceptances":
			counts.Invitations += value
		case "manual_recovery_executions", "manual_recovery_approvals",
			"manual_recovery_requests", "registration_reviews":
			counts.RecoveryApprovals += value
		case "sessions":
			counts.Sessions = value
		case "one_time_credentials":
			counts.OneTimeCredentials = value
		case "token_signing_keys":
			counts.SigningKeys = value
		}
	}
	for _, target := range credentialTables {
		result, err := tx.ExecContext(ctx, `DELETE FROM `+target.table)
		if err != nil {
			return RevocationCounts{}, fmt.Errorf("删除凭证表 %s 失败: %w", target.table, err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return RevocationCounts{}, fmt.Errorf("统计凭证表 %s 删除行数失败: %w",
				target.table, err)
		}
		assign(target.table, affected)
		counts.TotalDeleted += affected
	}
	return counts, nil
}

// verifyNoLiveCredentials 在提交前核对代表凭证表为空（防御性复核，防止删除语句
// 因表结构变化被静默忽略）。
func verifyNoLiveCredentials(ctx context.Context, tx *sql.Tx) error {
	for _, target := range credentialTables {
		var count int64
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM `+target.table).Scan(&count); err != nil {
			return fmt.Errorf("复核凭证表 %s 失败: %w", target.table, err)
		}
		if count != 0 {
			return fmt.Errorf("凭证表 %s 清理后仍剩 %d 行", target.table, count)
		}
	}
	return nil
}

// pauseRestoreDisposition 在事务内默认暂停/取消旧调度计划、Webhook 端点、在途任务、
// 待发邮件与待补发通知，返回真实影响数量与逐项清单（有上限）。
func pauseRestoreDisposition(ctx context.Context, tx *sql.Tx, now time.Time) (
	PausedCounts, []pausedItem, error) {
	var counts PausedCounts
	items := make([]pausedItem, 0, 16)
	nowMS := now.UnixMilli()
	recordItems := func(kind, previousState string, query string) (int64, error) {
		rows, err := tx.QueryContext(ctx, query)
		if err != nil {
			return 0, fmt.Errorf("读取待暂停 %s 失败: %w", kind, err)
		}
		defer rows.Close()
		var total int64
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return 0, fmt.Errorf("读取待暂停 %s 标识失败: %w", kind, err)
			}
			total++
			if len(items) < maxPausedItems {
				items = append(items, pausedItem{Kind: kind, TargetID: id,
					PreviousState: previousState})
			}
		}
		if err := rows.Err(); err != nil {
			return 0, fmt.Errorf("遍历待暂停 %s 失败: %w", kind, err)
		}
		return total, nil
	}

	schedules, err := recordItems("schedule", "enabled",
		`SELECT id FROM schedules WHERE enabled=1 ORDER BY id`)
	if err != nil {
		return PausedCounts{}, nil, err
	}
	if schedules > 0 {
		if _, err := tx.ExecContext(ctx,
			`UPDATE schedules SET enabled=0, updated_at_ms=? WHERE enabled=1`, nowMS); err != nil {
			return PausedCounts{}, nil, fmt.Errorf("暂停调度计划失败: %w", err)
		}
	}
	counts.Schedules = schedules

	webhooks, err := recordItems("webhook", "active",
		`SELECT id FROM webhook_endpoints WHERE status='active' ORDER BY id`)
	if err != nil {
		return PausedCounts{}, nil, err
	}
	if webhooks > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE webhook_endpoints
SET status='disabled', row_version=row_version+1, updated_at_ms=? WHERE status='active'`,
			nowMS); err != nil {
			return PausedCounts{}, nil, fmt.Errorf("暂停 Webhook 端点失败: %w", err)
		}
	}
	counts.Webhooks = webhooks
	webhookDeliveries, err := recordItems("notification", "pending",
		`SELECT id FROM webhook_deliveries WHERE state IN('queued','sending') ORDER BY id`)
	if err != nil {
		return PausedCounts{}, nil, err
	}
	if webhookDeliveries > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE webhook_deliveries
SET state='cancelled', updated_at_ms=?, finished_at_ms=?
WHERE state IN('queued','sending')`, nowMS, nowMS); err != nil {
			return PausedCounts{}, nil, fmt.Errorf("取消旧 Webhook 投递失败: %w", err)
		}
	}
	counts.WebhookDeliveries = webhookDeliveries

	jobs, err := recordItems("job", "pending",
		`SELECT id FROM jobs WHERE state IN('queued','running','cancel_requested') ORDER BY id`)
	if err != nil {
		return PausedCounts{}, nil, err
	}
	if jobs > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE jobs
SET state='cancelled', cancelled_by_type='system', cancelled_by_id='restore',
    cancellation_reason='restore_review', finished_at_ms=?, updated_at_ms=?
WHERE state IN('queued','running','cancel_requested')`, nowMS, nowMS); err != nil {
			return PausedCounts{}, nil, fmt.Errorf("取消在途任务失败: %w", err)
		}
	}
	counts.Jobs = jobs

	mails, err := recordItems("mail", "pending",
		`SELECT id FROM mail_deliveries WHERE state IN('queued','sending') ORDER BY id`)
	if err != nil {
		return PausedCounts{}, nil, err
	}
	if mails > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE mail_deliveries
SET state='cancelled', updated_at_ms=?, last_error_code='RESTORE_REVIEW'
WHERE state IN('queued','sending')`, nowMS); err != nil {
			return PausedCounts{}, nil, fmt.Errorf("取消待发邮件失败: %w", err)
		}
	}
	counts.MailDeliveries = mails

	backupNotifications, err := recordItems("notification", "pending",
		`SELECT id FROM backup_notifications WHERE state='pending' ORDER BY id`)
	if err != nil {
		return PausedCounts{}, nil, err
	}
	if backupNotifications > 0 {
		if _, err := tx.ExecContext(ctx,
			`UPDATE backup_notifications SET state='unknown', updated_at_ms=?
WHERE state='pending'`, nowMS); err != nil {
			return PausedCounts{}, nil, fmt.Errorf("暂停备份通知失败: %w", err)
		}
	}
	rootNotifications, err := recordItems("notification", "pending",
		`SELECT id FROM root_recovery_events WHERE notification_state='pending' ORDER BY id`)
	if err != nil {
		return PausedCounts{}, nil, err
	}
	if rootNotifications > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE root_recovery_events
SET notification_state='failed', last_error_code='RESTORE_REVIEW',
    notification_attempts=notification_attempts+1
WHERE notification_state='pending'`); err != nil {
			return PausedCounts{}, nil, fmt.Errorf("暂停 root 恢复通知失败: %w", err)
		}
	}
	counts.Notifications = backupNotifications + rootNotifications
	return counts, items, nil
}

// writeRestoreStateRows 在恢复后数据库写入恢复代际、恢复运行记录与暂停清单。
func writeRestoreStateRows(ctx context.Context, tx *sql.Tx, token maintenance.Token,
	operator audit.Actor, request Request, summary BackupSummary, startedAt time.Time,
	now time.Time, rollbackFile string, outcome postProcessOutcome,
	items []pausedItem) error {
	if token.NextGeneration != token.Generation+1 {
		return fmt.Errorf("恢复代际不连续：%d → %d", token.Generation, token.NextGeneration)
	}
	nowMS := now.UnixMilli()
	if _, err := tx.ExecContext(ctx,
		`UPDATE restore_generation SET generation=?, updated_at_ms=? WHERE id=1`,
		int64(token.NextGeneration), nowMS); err != nil {
		return fmt.Errorf("写入库内恢复代际失败: %w", err)
	}
	var generation int64
	if err := tx.QueryRowContext(ctx,
		`SELECT generation FROM restore_generation WHERE id=1`).Scan(&generation); err != nil {
		return fmt.Errorf("复核库内恢复代际失败: %w", err)
	}
	if uint64(generation) != token.NextGeneration {
		return fmt.Errorf("库内恢复代际写入不一致：%d/%d", generation, token.NextGeneration)
	}
	resultJSON := fmt.Sprintf(
		`{"revoked_total":%d,"sessions":%d,"refresh_families":%d,"authorization_codes":%d,`+
			`"recovery_codes":%d,"verification_tickets":%d,"qr_requests":%d,`+
			`"schedules_paused":%d,"webhooks_paused":%d,"webhook_deliveries_cancelled":%d,`+
			`"jobs_cancelled":%d,"mails_cancelled":%d,"notifications_paused":%d}`,
		outcome.Revoked.TotalDeleted, outcome.Revoked.Sessions,
		outcome.Revoked.RefreshFamilies, outcome.Revoked.AuthorizationCodes,
		outcome.Revoked.RecoveryCodes,
		outcome.Revoked.VerificationTickets+outcome.Revoked.PasswordResets+
			outcome.Revoked.EmailChanges,
		outcome.Revoked.QRLoginRequests, outcome.Paused.Schedules,
		outcome.Paused.Webhooks, outcome.Paused.WebhookDeliveries, outcome.Paused.Jobs,
		outcome.Paused.MailDeliveries, outcome.Paused.Notifications)
	if _, err := tx.ExecContext(ctx, `INSERT INTO restore_runs(
restore_id,generation,backup_id,backup_sha256,backup_schema_version,
operator_type,operator_id,status,started_at_ms,completed_at_ms,reason,
rollback_backup_file,result_json
) VALUES(?,?,?,?,?,?,?,'completed',?,?,?,?,?)`,
		token.RestoreID, int64(token.NextGeneration), summary.BackupID,
		summary.FileSHA256, summary.SchemaVersion, string(operator.Type), operator.ID,
		startedAt.UnixMilli(), nowMS, request.Reason, rollbackFile, resultJSON); err != nil {
		return fmt.Errorf("写入恢复运行记录失败: %w", err)
	}
	for _, item := range items {
		if _, err := tx.ExecContext(ctx, `INSERT INTO restore_paused_items(
restore_id,kind,target_id,previous_state,paused_at_ms) VALUES(?,?,?,?,?)`,
			token.RestoreID, item.Kind, item.TargetID, item.PreviousState, nowMS); err != nil {
			return fmt.Errorf("写入恢复暂停清单失败: %w", err)
		}
	}
	return nil
}
