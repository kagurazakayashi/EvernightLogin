// Package sqlite 实现步骤 81 备份生命周期（产物、保留策略、计划附加配置、任务阶段
// 与通知投递）的 SQLite 生产持久化。
//
// 表由 migrations/0043_backup_lifecycle.sql 创建，本包不执行迁移；调用方应在启动
// 或测试中先通过 internal/storage/migrate 应用全部迁移。本包不拥有数据库连接，
// 关闭由外层负责；构造后不可变、可并发使用。
//
// 安全不变量：
//   - 只保存受控元数据：不保存备份正文、明文数据库内容、主密钥材料、宿主绝对路径、
//     通知收件地址原文或审计原文。
//   - 策略保存使用行版本乐观并发控制；版本冲突返回 backupadmin.ErrConflict，不静默
//     覆盖其他会话的修改。
//   - 任务状态不复制 internal/task 状态机：本包只保存阶段、进度与结果摘要。
//   - 时间统一使用 UTC 毫秒整数，展示时区由页面层换算。
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/backupadmin"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// Store 是备份生命周期的 SQLite 仓储。
type Store struct {
	store *storagesqlite.Store
}

// New 包装一个已打开并完成迁移的 SQLite 存储；store 为空时拒绝构造。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", backupadmin.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

// timeToMS 把时间转换为 UTC 毫秒；零值保持 0。
func timeToMS(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.UTC().UnixMilli()
}

// msToTime 把毫秒转换为 UTC 时间；0 返回零值。
func msToTime(value int64) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.UnixMilli(value).UTC()
}

// actorColumns 拆分审计身份。
func actorColumns(actor audit.Actor) (string, string, error) {
	if err := actor.Validate(); err != nil || actor.Type == audit.ActorAnonymous || actor.ID == "" {
		return "", "", backupadmin.ErrInvalidRequest
	}
	return string(actor.Type), actor.ID, nil
}

// actorFromColumns 还原审计身份。
func actorFromColumns(actorType, actorID string) (audit.Actor, error) {
	actor := audit.Actor{Type: audit.ActorKind(actorType), ID: actorID}
	if err := actor.Validate(); err != nil {
		return audit.Actor{}, backupadmin.ErrStoreUnavailable
	}
	return actor, nil
}

// InsertArtifact 插入一条产物元数据；主键冲突返回 ErrConflict。
func (s *Store) InsertArtifact(ctx context.Context, artifact backupadmin.Artifact) error {
	if artifact.Origin == "" {
		artifact.Origin = backupadmin.OriginManual
	}
	cleanupActorType, cleanupActorID := "", ""
	if artifact.CleanedBy != nil {
		actorType, actorID, err := actorColumns(*artifact.CleanedBy)
		if err != nil {
			return err
		}
		cleanupActorType, cleanupActorID = actorType, actorID
	}
	_, err := s.store.ExecContext(ctx, `INSERT INTO backup_artifacts (
backup_id, job_id, schedule_id, origin, file_name, size_bytes, payload_bytes,
file_sha256, manifest_sha256, format_version, schema_version, content_database,
content_attachments, content_config, entry_count, hostname, app_version,
verification_state, verified_at_ms, retention_version, cleanup_state, cleaned_at_ms,
cleanup_actor_type, cleanup_actor_id, created_at_ms, published_at_ms, request_id)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		artifact.BackupID, artifact.JobID, artifact.ScheduleID, string(artifact.Origin),
		artifact.FileName, artifact.SizeBytes, artifact.PayloadBytes,
		strings.ToLower(artifact.FileSHA256), strings.ToLower(artifact.ManifestSHA256),
		artifact.FormatVersion, artifact.SchemaVersion, boolInt(artifact.ContentDatabase),
		string(artifact.ContentAttach), string(artifact.ContentConfig), artifact.EntryCount,
		artifact.Hostname, artifact.AppVersion, string(artifact.Verification),
		timeToMS(artifact.VerifiedAt), artifact.RetentionVersion, string(artifact.Cleanup),
		timeToMS(artifact.CleanedAt), cleanupActorType, cleanupActorID,
		timeToMS(artifact.CreatedAt), timeToMS(artifact.PublishedAt), artifact.RequestID)
	if err != nil {
		if isConstraintError(err) {
			return fmt.Errorf("%w: 备份产物已登记", backupadmin.ErrConflict)
		}
		return fmt.Errorf("%w: 备份产物写入失败: %v", backupadmin.ErrStoreUnavailable, err)
	}
	return nil
}

// GetArtifact 读取单个产物。
func (s *Store) GetArtifact(ctx context.Context, backupID string) (backupadmin.Artifact, bool, error) {
	row := s.store.DB().QueryRowContext(ctx, artifactColumns+
		` FROM backup_artifacts WHERE backup_id = ?`, backupID)
	artifact, err := scanArtifact(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return backupadmin.Artifact{}, false, nil
		}
		return backupadmin.Artifact{}, false, fmt.Errorf("%w: 备份产物读取失败", backupadmin.ErrStoreUnavailable)
	}
	return artifact, true, nil
}

// artifactColumns 是产物查询列清单。
const artifactColumns = `SELECT backup_id, job_id, schedule_id, origin, file_name,
size_bytes, payload_bytes, file_sha256, manifest_sha256, format_version, schema_version,
content_database, content_attachments, content_config, entry_count, hostname, app_version,
verification_state, verified_at_ms, retention_version, cleanup_state, cleaned_at_ms,
cleanup_actor_type, cleanup_actor_id, created_at_ms, published_at_ms, request_id`

// rowScanner 是 *sql.Row/*sql.Rows 的最小扫描契约。
type rowScanner interface {
	Scan(dest ...any) error
}

// scanArtifact 扫描一行产物。
func scanArtifact(row rowScanner) (backupadmin.Artifact, error) {
	artifact := backupadmin.Artifact{}
	var origin, contentAttach, contentConfig, verification, cleanup string
	var database int
	var verifiedAt, cleanedAt, createdAt, publishedAt int64
	var cleanupActorType, cleanupActorID string
	err := row.Scan(&artifact.BackupID, &artifact.JobID, &artifact.ScheduleID, &origin,
		&artifact.FileName, &artifact.SizeBytes, &artifact.PayloadBytes,
		&artifact.FileSHA256, &artifact.ManifestSHA256, &artifact.FormatVersion,
		&artifact.SchemaVersion, &database, &contentAttach, &contentConfig,
		&artifact.EntryCount, &artifact.Hostname, &artifact.AppVersion, &verification,
		&verifiedAt, &artifact.RetentionVersion, &cleanup, &cleanedAt,
		&cleanupActorType, &cleanupActorID, &createdAt, &publishedAt, &artifact.RequestID)
	if err != nil {
		return backupadmin.Artifact{}, err
	}
	artifact.Origin = backupadmin.Origin(origin)
	artifact.Verification = backupadmin.VerificationState(verification)
	artifact.Cleanup = backupadmin.CleanupState(cleanup)
	artifact.ContentDatabase = database == 1
	artifact.ContentAttach = backupadmin.ContentStatus(contentAttach)
	artifact.ContentConfig = backupadmin.ContentStatus(contentConfig)
	artifact.VerifiedAt = msToTime(verifiedAt)
	artifact.CleanedAt = msToTime(cleanedAt)
	artifact.CreatedAt = msToTime(createdAt)
	artifact.PublishedAt = msToTime(publishedAt)
	if cleanupActorType != "" {
		actor, err := actorFromColumns(cleanupActorType, cleanupActorID)
		if err != nil {
			return backupadmin.Artifact{}, err
		}
		artifact.CleanedBy = &actor
	}
	return artifact, nil
}

// ListArtifacts 按白名单条件列出产物（发布倒序、编号倒序稳定排序）。
func (s *Store) ListArtifacts(ctx context.Context,
	filter backupadmin.ArtifactFilter) ([]backupadmin.Artifact, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 1000 {
		limit = 1000
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	query := artifactColumns + ` FROM backup_artifacts WHERE 1 = 1`
	args := make([]any, 0, 8)
	if filter.Origin != "" {
		query += ` AND origin = ?`
		args = append(args, string(filter.Origin))
	}
	if filter.Verification != "" {
		query += ` AND verification_state = ?`
		args = append(args, string(filter.Verification))
	}
	if filter.Cleanup != "" {
		query += ` AND cleanup_state = ?`
		args = append(args, string(filter.Cleanup))
	}
	if filter.ScheduleID != "" {
		query += ` AND schedule_id = ?`
		args = append(args, filter.ScheduleID)
	}
	if filter.JobID != "" {
		query += ` AND job_id = ?`
		args = append(args, filter.JobID)
	}
	query += ` ORDER BY published_at_ms DESC, backup_id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, filter.Offset)
	rows, err := s.store.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("%w: 备份产物查询失败", backupadmin.ErrStoreUnavailable)
	}
	defer rows.Close()
	artifacts := make([]backupadmin.Artifact, 0, limit)
	for rows.Next() {
		artifact, err := scanArtifact(rows)
		if err != nil {
			return nil, fmt.Errorf("%w: 备份产物读取失败", backupadmin.ErrStoreUnavailable)
		}
		artifacts = append(artifacts, artifact)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: 备份产物读取失败", backupadmin.ErrStoreUnavailable)
	}
	return artifacts, nil
}

// UpdateArtifactVerification 更新校验状态；状态未知时不覆盖已验证结果。
func (s *Store) UpdateArtifactVerification(ctx context.Context, backupID string,
	state backupadmin.VerificationState, verifiedAt time.Time) error {
	if !state.Valid() {
		return backupadmin.ErrInvalidRequest
	}
	_, err := s.store.ExecContext(ctx, `UPDATE backup_artifacts
SET verification_state = ?, verified_at_ms = ? WHERE backup_id = ?`,
		string(state), timeToMS(verifiedAt), backupID)
	if err != nil {
		return fmt.Errorf("%w: 备份校验状态更新失败", backupadmin.ErrStoreUnavailable)
	}
	return nil
}

// MarkArtifactCleaned 标记产物已清理；只有未清理的记录可迁移。
func (s *Store) MarkArtifactCleaned(ctx context.Context, backupID string,
	actor audit.Actor, now time.Time) error {
	actorType, actorID, err := actorColumns(actor)
	if err != nil {
		return err
	}
	result, err := s.store.ExecContext(ctx, `UPDATE backup_artifacts
SET cleanup_state = 'cleaned', cleaned_at_ms = ?, cleanup_actor_type = ?, cleanup_actor_id = ?
WHERE backup_id = ? AND cleanup_state = 'retained'`,
		timeToMS(now), actorType, actorID, backupID)
	if err != nil {
		return fmt.Errorf("%w: 备份清理状态更新失败", backupadmin.ErrStoreUnavailable)
	}
	if affected, err := result.RowsAffected(); err == nil && affected == 0 {
		return backupadmin.ErrConflict
	}
	return nil
}

// RetentionPolicy 读取当前生效策略。
func (s *Store) RetentionPolicy(ctx context.Context) (backupadmin.RetentionPolicy, bool, error) {
	row := s.store.DB().QueryRowContext(ctx, `SELECT version, max_count, max_age_days,
max_total_bytes, updated_at_ms, updated_by_type, updated_by_id, reason, request_id
FROM backup_retention_policy WHERE id = 1`)
	policy := backupadmin.RetentionPolicy{}
	var updatedAt int64
	var actorType, actorID string
	err := row.Scan(&policy.Version, &policy.MaxCount, &policy.MaxAgeDays,
		&policy.MaxTotalBytes, &updatedAt, &actorType, &actorID, &policy.Reason,
		&policy.RequestID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return backupadmin.RetentionPolicy{}, false, nil
		}
		return backupadmin.RetentionPolicy{}, false,
			fmt.Errorf("%w: 保留策略读取失败", backupadmin.ErrStoreUnavailable)
	}
	policy.UpdatedAt = msToTime(updatedAt)
	policy.UpdatedBy, err = actorFromColumns(actorType, actorID)
	if err != nil {
		return backupadmin.RetentionPolicy{}, false, err
	}
	return policy, true, nil
}

// SaveRetentionPolicy 保存策略；expectedVersion 为 0 表示要求首次写入。
func (s *Store) SaveRetentionPolicy(ctx context.Context,
	policy backupadmin.RetentionPolicy, expectedVersion int64) error {
	actorType, actorID, err := actorColumns(policy.UpdatedBy)
	if err != nil {
		return err
	}
	err = s.store.Transaction(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var current int64
		scanErr := tx.QueryRowContext(ctx,
			`SELECT version FROM backup_retention_policy WHERE id = 1`).Scan(&current)
		switch {
		case errors.Is(scanErr, sql.ErrNoRows):
			if expectedVersion != 0 && expectedVersion != 1 {
				return backupadmin.ErrConflict
			}
			_, insertErr := tx.ExecContext(ctx, `INSERT INTO backup_retention_policy
(id, version, max_count, max_age_days, max_total_bytes, updated_at_ms,
updated_by_type, updated_by_id, reason, request_id) VALUES (1,?,?,?,?,?,?,?,?,?)`,
				policy.Version, policy.MaxCount, policy.MaxAgeDays, policy.MaxTotalBytes,
				timeToMS(policy.UpdatedAt), actorType, actorID, policy.Reason,
				policy.RequestID)
			return insertErr
		case scanErr != nil:
			return scanErr
		case current != expectedVersion:
			return backupadmin.ErrConflict
		default:
			_, updateErr := tx.ExecContext(ctx, `UPDATE backup_retention_policy
SET version = ?, max_count = ?, max_age_days = ?, max_total_bytes = ?,
updated_at_ms = ?, updated_by_type = ?, updated_by_id = ?, reason = ?, request_id = ?
WHERE id = 1`, policy.Version, policy.MaxCount, policy.MaxAgeDays,
				policy.MaxTotalBytes, timeToMS(policy.UpdatedAt), actorType, actorID,
				policy.Reason, policy.RequestID)
			return updateErr
		}
	})
	if err != nil {
		if errors.Is(err, backupadmin.ErrConflict) {
			return err
		}
		return fmt.Errorf("%w: 保留策略保存失败", backupadmin.ErrStoreUnavailable)
	}
	return nil
}

// ScheduleMeta 读取计划附加配置。
func (s *Store) ScheduleMeta(ctx context.Context, scheduleID string) (backupadmin.ScheduleMeta, bool, error) {
	row := s.store.DB().QueryRowContext(ctx, `SELECT schedule_id, name, retention_version,
notify_failures, notify_success, notify_target, created_by_type, created_by_id,
created_at_ms, updated_at_ms FROM backup_schedules WHERE schedule_id = ?`, scheduleID)
	meta := backupadmin.ScheduleMeta{}
	var notifyFailures, notifySuccess int
	var createdByType, createdByID string
	var createdAt, updatedAt int64
	err := row.Scan(&meta.ScheduleID, &meta.Name, &meta.RetentionVersion, &notifyFailures,
		&notifySuccess, &meta.NotifyTarget, &createdByType, &createdByID, &createdAt, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return backupadmin.ScheduleMeta{}, false, nil
		}
		return backupadmin.ScheduleMeta{}, false,
			fmt.Errorf("%w: 计划配置读取失败", backupadmin.ErrStoreUnavailable)
	}
	meta.NotifyFailures = notifyFailures == 1
	meta.NotifySuccess = notifySuccess == 1
	meta.CreatedAt = msToTime(createdAt)
	meta.UpdatedAt = msToTime(updatedAt)
	meta.CreatedBy, err = actorFromColumns(createdByType, createdByID)
	if err != nil {
		return backupadmin.ScheduleMeta{}, false, err
	}
	return meta, true, nil
}

// ListScheduleMeta 列出全部计划附加配置。
func (s *Store) ListScheduleMeta(ctx context.Context) ([]backupadmin.ScheduleMeta, error) {
	rows, err := s.store.QueryContext(ctx, `SELECT schedule_id, name, retention_version,
notify_failures, notify_success, notify_target, created_by_type, created_by_id,
created_at_ms, updated_at_ms FROM backup_schedules`)
	if err != nil {
		return nil, fmt.Errorf("%w: 计划配置查询失败", backupadmin.ErrStoreUnavailable)
	}
	defer rows.Close()
	metas := make([]backupadmin.ScheduleMeta, 0, 8)
	for rows.Next() {
		meta := backupadmin.ScheduleMeta{}
		var notifyFailures, notifySuccess int
		var createdByType, createdByID string
		var createdAt, updatedAt int64
		if err := rows.Scan(&meta.ScheduleID, &meta.Name, &meta.RetentionVersion,
			&notifyFailures, &notifySuccess, &meta.NotifyTarget, &createdByType,
			&createdByID, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("%w: 计划配置读取失败", backupadmin.ErrStoreUnavailable)
		}
		meta.NotifyFailures = notifyFailures == 1
		meta.NotifySuccess = notifySuccess == 1
		meta.CreatedAt = msToTime(createdAt)
		meta.UpdatedAt = msToTime(updatedAt)
		if meta.CreatedBy, err = actorFromColumns(createdByType, createdByID); err != nil {
			return nil, err
		}
		metas = append(metas, meta)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: 计划配置读取失败", backupadmin.ErrStoreUnavailable)
	}
	return metas, nil
}

// SaveScheduleMeta 写入/覆盖计划附加配置。
func (s *Store) SaveScheduleMeta(ctx context.Context, meta backupadmin.ScheduleMeta) error {
	actorType, actorID, err := actorColumns(meta.CreatedBy)
	if err != nil {
		return err
	}
	_, err = s.store.ExecContext(ctx, `INSERT INTO backup_schedules
(schedule_id, name, retention_version, notify_failures, notify_success, notify_target,
created_by_type, created_by_id, created_at_ms, updated_at_ms)
VALUES (?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(schedule_id) DO UPDATE SET name = excluded.name,
retention_version = excluded.retention_version,
notify_failures = excluded.notify_failures, notify_success = excluded.notify_success,
notify_target = excluded.notify_target, updated_at_ms = excluded.updated_at_ms`,
		meta.ScheduleID, meta.Name, meta.RetentionVersion, boolInt(meta.NotifyFailures),
		boolInt(meta.NotifySuccess), meta.NotifyTarget, actorType, actorID,
		timeToMS(meta.CreatedAt), timeToMS(meta.UpdatedAt))
	if err != nil {
		return fmt.Errorf("%w: 计划配置保存失败", backupadmin.ErrStoreUnavailable)
	}
	return nil
}

// DeleteScheduleMeta 删除计划附加配置。
func (s *Store) DeleteScheduleMeta(ctx context.Context, scheduleID string) error {
	_, err := s.store.ExecContext(ctx,
		`DELETE FROM backup_schedules WHERE schedule_id = ?`, scheduleID)
	if err != nil {
		return fmt.Errorf("%w: 计划配置删除失败", backupadmin.ErrStoreUnavailable)
	}
	return nil
}

// InsertJob 写入任务索引；重复插入按已有记录处理。
func (s *Store) InsertJob(ctx context.Context, entry backupadmin.JobIndexEntry) error {
	actorType, actorID, err := actorColumns(entry.Initiator)
	if err != nil {
		return err
	}
	origin := entry.Origin
	if origin == "" {
		origin = backupadmin.OriginManual
	}
	_, err = s.store.ExecContext(ctx, `INSERT OR IGNORE INTO backup_jobs
(job_id, kind, origin, schedule_id, initiator_type, initiator_id, created_at_ms)
VALUES (?,?,?,?,?,?,?)`, entry.JobID, entry.Kind, string(origin),
		entry.ScheduleID, actorType, actorID, timeToMS(entry.CreatedAt))
	if err != nil {
		return fmt.Errorf("%w: 任务索引写入失败", backupadmin.ErrStoreUnavailable)
	}
	return nil
}

// GetJob 读取任务索引。
func (s *Store) GetJob(ctx context.Context, jobID string) (backupadmin.JobIndexEntry, bool, error) {
	row := s.store.DB().QueryRowContext(ctx, `SELECT job_id, kind, origin, schedule_id,
initiator_type, initiator_id, created_at_ms FROM backup_jobs WHERE job_id = ?`, jobID)
	entry := backupadmin.JobIndexEntry{}
	var origin, actorType, actorID string
	var createdAt int64
	err := row.Scan(&entry.JobID, &entry.Kind, &origin, &entry.ScheduleID,
		&actorType, &actorID, &createdAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return backupadmin.JobIndexEntry{}, false, nil
		}
		return backupadmin.JobIndexEntry{}, false,
			fmt.Errorf("%w: 任务索引读取失败", backupadmin.ErrStoreUnavailable)
	}
	entry.Origin = backupadmin.Origin(origin)
	entry.CreatedAt = msToTime(createdAt)
	entry.Initiator, err = actorFromColumns(actorType, actorID)
	if err != nil {
		return backupadmin.JobIndexEntry{}, false, err
	}
	return entry, true, nil
}

// ListJobs 按条件列出任务索引（创建倒序）。
func (s *Store) ListJobs(ctx context.Context, filter backupadmin.JobFilter) ([]backupadmin.JobIndexEntry, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 1000 {
		limit = 1000
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	query := `SELECT job_id, kind, origin, schedule_id, initiator_type, initiator_id,
created_at_ms FROM backup_jobs WHERE 1 = 1`
	args := make([]any, 0, 4)
	if filter.Kind != "" {
		query += ` AND kind = ?`
		args = append(args, filter.Kind)
	}
	if filter.ScheduleID != "" {
		query += ` AND schedule_id = ?`
		args = append(args, filter.ScheduleID)
	}
	query += ` ORDER BY created_at_ms DESC, job_id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, filter.Offset)
	rows, err := s.store.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("%w: 任务索引查询失败", backupadmin.ErrStoreUnavailable)
	}
	defer rows.Close()
	entries := make([]backupadmin.JobIndexEntry, 0, limit)
	for rows.Next() {
		entry := backupadmin.JobIndexEntry{}
		var origin, actorType, actorID string
		var createdAt int64
		if err := rows.Scan(&entry.JobID, &entry.Kind, &origin, &entry.ScheduleID,
			&actorType, &actorID, &createdAt); err != nil {
			return nil, fmt.Errorf("%w: 任务索引读取失败", backupadmin.ErrStoreUnavailable)
		}
		entry.Origin = backupadmin.Origin(origin)
		entry.CreatedAt = msToTime(createdAt)
		if entry.Initiator, err = actorFromColumns(actorType, actorID); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: 任务索引读取失败", backupadmin.ErrStoreUnavailable)
	}
	return entries, nil
}

// JobState 读取任务的阶段/进度/结果摘要。
func (s *Store) JobState(ctx context.Context, jobID string) (backupadmin.JobProgressState, bool, error) {
	row := s.store.DB().QueryRowContext(ctx, `SELECT job_id, backup_id, stage_code,
progress_done, progress_total, progress_unit, notification_state,
notification_error_code, result_summary, updated_at_ms
FROM backup_job_state WHERE job_id = ?`, jobID)
	state := backupadmin.JobProgressState{}
	var done, total sql.NullInt64
	var updatedAt int64
	err := row.Scan(&state.JobID, &state.BackupID, &state.StageCode, &done, &total,
		&state.ProgressUnit, &state.NotificationStat, &state.NotificationCode,
		&state.ResultSummary, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return backupadmin.JobProgressState{}, false, nil
		}
		return backupadmin.JobProgressState{}, false,
			fmt.Errorf("%w: 任务状态读取失败", backupadmin.ErrStoreUnavailable)
	}
	if done.Valid {
		value := done.Int64
		state.ProgressDone = &value
	}
	if total.Valid {
		value := total.Int64
		state.ProgressTotal = &value
	}
	state.UpdatedAt = msToTime(updatedAt)
	return state, true, nil
}

// SaveJobState 写入/覆盖任务阶段状态。
func (s *Store) SaveJobState(ctx context.Context, state backupadmin.JobProgressState) error {
	var done, total any
	if state.ProgressDone != nil {
		done = *state.ProgressDone
	}
	if state.ProgressTotal != nil {
		total = *state.ProgressTotal
	}
	_, err := s.store.ExecContext(ctx, `INSERT INTO backup_job_state
(job_id, backup_id, stage_code, progress_done, progress_total, progress_unit,
notification_state, notification_error_code, result_summary, updated_at_ms)
VALUES (?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(job_id) DO UPDATE SET backup_id = excluded.backup_id,
stage_code = excluded.stage_code, progress_done = excluded.progress_done,
progress_total = excluded.progress_total, progress_unit = excluded.progress_unit,
notification_state = excluded.notification_state,
notification_error_code = excluded.notification_error_code,
result_summary = excluded.result_summary, updated_at_ms = excluded.updated_at_ms`,
		state.JobID, state.BackupID, state.StageCode, done, total, state.ProgressUnit,
		state.NotificationStat, state.NotificationCode, state.ResultSummary,
		timeToMS(state.UpdatedAt))
	if err != nil {
		return fmt.Errorf("%w: 任务状态保存失败", backupadmin.ErrStoreUnavailable)
	}
	return nil
}

// InsertNotification 写入通知投递记录。
func (s *Store) InsertNotification(ctx context.Context, notification backupadmin.Notification) error {
	_, err := s.store.ExecContext(ctx, `INSERT INTO backup_notifications
(id, job_id, backup_id, kind, state, channel, recipient_masked, error_code, attempts,
created_at_ms, updated_at_ms) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		notification.ID, notification.JobID, notification.BackupID, notification.Kind,
		notification.State, notification.Channel, notification.RecipientMasked,
		notification.ErrorCode, notification.Attempts, timeToMS(notification.CreatedAt),
		timeToMS(notification.UpdatedAt))
	if err != nil {
		return fmt.Errorf("%w: 通知记录写入失败", backupadmin.ErrStoreUnavailable)
	}
	return nil
}

// UpdateNotification 更新投递状态。
func (s *Store) UpdateNotification(ctx context.Context, id, state, errorCode string,
	attempts int, now time.Time) error {
	_, err := s.store.ExecContext(ctx, `UPDATE backup_notifications
SET state = ?, error_code = ?, attempts = ?, updated_at_ms = ? WHERE id = ?`,
		state, errorCode, attempts, timeToMS(now), id)
	if err != nil {
		return fmt.Errorf("%w: 通知状态更新失败", backupadmin.ErrStoreUnavailable)
	}
	return nil
}

// ListNotifications 按任务或产物列出通知记录（最新在前）。
func (s *Store) ListNotifications(ctx context.Context, jobID, backupID string) ([]backupadmin.Notification, error) {
	query := `SELECT id, job_id, backup_id, kind, state, channel, recipient_masked,
error_code, attempts, created_at_ms, updated_at_ms FROM backup_notifications WHERE 1 = 1`
	args := make([]any, 0, 2)
	if jobID != "" {
		query += ` AND job_id = ?`
		args = append(args, jobID)
	}
	if backupID != "" {
		query += ` AND backup_id = ?`
		args = append(args, backupID)
	}
	query += ` ORDER BY created_at_ms DESC, id DESC LIMIT 50`
	rows, err := s.store.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("%w: 通知记录查询失败", backupadmin.ErrStoreUnavailable)
	}
	defer rows.Close()
	records := make([]backupadmin.Notification, 0, 8)
	for rows.Next() {
		record := backupadmin.Notification{}
		var createdAt, updatedAt int64
		if err := rows.Scan(&record.ID, &record.JobID, &record.BackupID, &record.Kind,
			&record.State, &record.Channel, &record.RecipientMasked, &record.ErrorCode,
			&record.Attempts, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("%w: 通知记录读取失败", backupadmin.ErrStoreUnavailable)
		}
		record.CreatedAt = msToTime(createdAt)
		record.UpdatedAt = msToTime(updatedAt)
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: 通知记录读取失败", backupadmin.ErrStoreUnavailable)
	}
	return records, nil
}

// boolInt 把布尔转换为 0/1。
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

// isConstraintError 判断是否为约束/主键冲突错误；只用于把重复登记映射为冲突。
func isConstraintError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "constraint") || strings.Contains(message, "unique")
}
