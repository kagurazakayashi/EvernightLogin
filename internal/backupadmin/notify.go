package backupadmin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"io"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// 通知类别稳定值（与迁移中的 kind 约束一致）。
const (
	NotificationSucceeded        = "backup_succeeded"
	NotificationBackupFailed     = "backup_failed"
	NotificationBackupTimeout    = "backup_timeout"
	NotificationPermissionDenied = "permission_denied"
	NotificationCleanupFailed    = "cleanup_failed"
)

// 通知投递状态稳定值。
const (
	NotificationStateNotConfigured = "not_configured"
	NotificationStatePending       = "pending"
	NotificationStateAccepted      = "accepted"
	NotificationStateFailed        = "failed"
	NotificationStateUnknown       = "unknown"
)

// BackupNotification 是发送给宿主的备份结果通知（只含受控字段，不含文件、秘密、
// 宿主路径、短期下载令牌或公开链接）。接收者由宿主按通知渠道键解析并自行做权限/
// 隐私检查。
type BackupNotification struct {
	Kind       string
	JobID      string
	BackupID   string
	ScheduleID string
	State      string
	ErrorCode  string
	Channel    string
	// EntryRoute 是需登录且每次重新授权的管理页面路由名；通知正文不能包含永久链接。
	EntryRoute string
	// Actor 是任务发起/执行身份（宿主据此解析受控接收者）。
	Actor      audit.Actor
	Note       string
	CreatedAt  time.Time
	FinishedAt time.Time
}

// notifySettings 是一次通知的生效配置。
type notifySettings struct {
	enabled bool
	channel string
}

// settingsFor 解析任务/计划的通知配置；计划附加配置缺失时使用宿主默认值。
func (s *Service) settingsFor(ctx context.Context, job task.Job, payload jobPayload,
	success bool) notifySettings {
	channel := s.opts.DefaultNotifyTarget
	enabled := s.opts.DefaultNotifyFailures
	if success {
		enabled = s.opts.DefaultNotifySuccess
	}
	if payload.ScheduleID != "" {
		if meta, found, err := s.opts.Store.ScheduleMeta(ctx, payload.ScheduleID); err == nil && found {
			channel = meta.NotifyTarget
			if channel == "" {
				channel = s.opts.DefaultNotifyTarget
			}
			if success {
				enabled = meta.NotifySuccess
			} else {
				enabled = meta.NotifyFailures
			}
		}
	}
	if channel == "" {
		enabled = false
	}
	return notifySettings{enabled: enabled, channel: channel}
}

// notifyFailure 在备份最终失败/超时/权限拒绝时发送失败通知；通知失败不改变备份
// 产物事实，也不删除任何记录。
func (s *Service) notifyFailure(ctx context.Context, job task.Job, payload jobPayload,
	kind, errorCode string) {
	settings := s.settingsFor(ctx, job, payload, false)
	if !settings.enabled {
		return
	}
	s.sendNotification(ctx, job, payload, kind, errorCode, settings.channel, false)
}

// notifySuccess 在备份成功且产物登记后发送成功通知。
func (s *Service) notifySuccess(ctx context.Context, job task.Job, payload jobPayload,
	artifact Artifact) {
	settings := s.settingsFor(ctx, job, payload, true)
	if !settings.enabled {
		return
	}
	s.sendNotification(ctx, job, payload, NotificationSucceeded, "", settings.channel, true)
}

// sendNotification 先持久化投递记录，再发送并更新真实结果；发送失败只影响通知状态。
func (s *Service) sendNotification(ctx context.Context, job task.Job, payload jobPayload,
	kind, errorCode, channel string, success bool) {
	notificationID, err := s.newNotificationID()
	if err != nil {
		s.logger.Warn("通知编号生成失败", "job_id", job.ID)
		return
	}
	matchedChannel := channel
	if err := s.opts.Store.InsertNotification(ctx, Notification{
		ID: notificationID, JobID: job.ID, BackupID: "", Kind: kind,
		State: NotificationStatePending, Channel: "local",
		RecipientMasked: saturatingText(matchedChannel, 64),
		ErrorCode:       safeToken(errorCode), Attempts: 1,
		CreatedAt: s.now(), UpdatedAt: s.now(),
	}); err != nil {
		s.logger.Warn("通知记录写入失败", "job_id", job.ID)
	}
	if s.opts.Notifier == nil {
		s.updateNotificationState(ctx, job.ID, notificationID, NotificationStateFailed, "NOT_CONFIGURED")
		return
	}
	note := "备份任务失败，未产生可下载备份；请登录管理页面查看任务详情。"
	if success {
		note = "备份已完成并登记为可用恢复点；下载仍需独立权限与再次认证。"
	}
	notification := BackupNotification{
		Kind: kind, JobID: job.ID, ScheduleID: payload.ScheduleID,
		State: string(job.State), ErrorCode: safeToken(errorCode), Channel: matchedChannel,
		EntryRoute: "admin.backups", Actor: job.Initiator, Note: note,
		CreatedAt: job.CreatedAt, FinishedAt: s.now(),
	}
	sendCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := s.opts.Notifier.NotifyBackup(sendCtx, notification); err != nil {
		s.updateNotificationState(ctx, job.ID, notificationID, NotificationStateFailed, "DELIVERY_FAILED")
	} else {
		s.updateNotificationState(ctx, job.ID, notificationID, NotificationStateAccepted, "")
	}
}

// updateNotificationState 更新通知记录与任务侧通知摘要。
func (s *Service) updateNotificationState(ctx context.Context, jobID, notificationID,
	state, errorCode string) {
	if err := s.opts.Store.UpdateNotification(ctx, notificationID, state, errorCode,
		1, s.now()); err != nil {
		s.logger.Warn("通知状态更新失败", "job_id", jobID)
	}
	s.updateJobState(ctx, JobProgressState{JobID: jobID, NotificationStat: state,
		NotificationCode: safeToken(errorCode), UpdatedAt: s.now()})
	s.recordBestEffort(ctx, audit.Event{
		Actor:   audit.Actor{Type: audit.ActorSystem, ID: "backup_notifier"},
		Action:  ActionNotification,
		Target:  audit.Target{Type: "backup_job", ID: jobID},
		Outcome: audit.OutcomeSuccess,
		Changes: []audit.FieldChange{
			{Field: "state", After: state},
			{Field: "error_code", After: safeToken(errorCode)},
		},
	})
}

// newNotificationID 生成通知编号。
func (s *Service) newNotificationID() (string, error) {
	reader := s.random
	if reader == nil {
		reader = rand.Reader
	}
	buffer := make([]byte, 16)
	if _, err := io.ReadFull(reader, buffer); err != nil {
		return "", fmt.Errorf("%w: 安全随机源不可用", ErrStoreUnavailable)
	}
	return "ntf_" + hex.EncodeToString(buffer), nil
}

// ListNotifications 返回任务/产物的通知投递记录（要求 backups.read；全量兼容入口，
// 页面/HTTP 应优先使用分页的 ListNotificationsPage）。
func (s *Service) ListNotifications(ctx context.Context, caller account.Caller,
	jobID, backupID string) ([]Notification, error) {
	if err := s.authorize(ctx, caller, PermissionRead); err != nil {
		return nil, err
	}
	records, err := s.opts.Store.ListNotifications(ctx, jobID, backupID)
	if err != nil {
		return nil, err
	}
	for index := range records {
		records[index].RecipientMasked = saturatingText(records[index].RecipientMasked, 64)
	}
	return records, nil
}

// ListNotificationsPage 分页返回任务/产物的通知投递记录（步骤 218）；旧
// ListNotifications 保留全量兼容。记录按存储层最新在前返回，服务层再按 offset 切页。
func (s *Service) ListNotificationsPage(ctx context.Context, caller account.Caller,
	jobID, backupID string, limit, offset int) ([]Notification, bool, error) {
	if err := s.authorize(ctx, caller, PermissionRead); err != nil {
		return nil, false, err
	}
	if limit == 0 {
		limit = defaultListLimit
	}
	if limit < 1 || limit > maxListLimit {
		return nil, false, fmt.Errorf("%w: 每页条数必须在 1～100 之间", ErrInvalidRequest)
	}
	if offset < 0 || offset > 1_000_000 {
		return nil, false, fmt.Errorf("%w: 分页偏移超出范围", ErrInvalidRequest)
	}
	records, err := s.opts.Store.ListNotifications(ctx, jobID, backupID)
	if err != nil {
		return nil, false, err
	}
	for index := range records {
		records[index].RecipientMasked = saturatingText(records[index].RecipientMasked, 64)
	}
	if offset >= len(records) {
		return []Notification{}, false, nil
	}
	end := offset + limit
	hasMore := false
	if end < len(records) {
		hasMore = true
	} else {
		end = len(records)
	}
	return records[offset:end], hasMore, nil
}
