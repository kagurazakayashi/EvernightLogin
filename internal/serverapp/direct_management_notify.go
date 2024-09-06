package serverapp

// 步骤 256/257：管理员“直接修改他人用户名 / 直接重置他人口令”的敏感操作安全告知。
//
// 背景：这两类操作由管理员凭专门权限 + 本次两步验证证明直接执行，目标用户并未参与。
// AGENTS 要求按现有配置发送敏感操作告知，且告知只含用户可安全看到的信息、不包含新
// 用户名以外的秘密（本实现连新用户名也不写入，只告知“发生了直接管理操作”）。
//
// 可靠投递（步骤 265 机制复用）：
//   - 走真实 mailer 可靠投递队列（enqueueSecurityNotice），入队成功只代表已受理/排队，
//     不代表最终送达；失败不回滚已完成的业务，由调用方记录可诊断状态；
//   - 使用稳定业务去重键（证明批准 ID 派生），重复调用不会重复发信，投递记录可按去重键
//     回看实际投递状态；
//   - 目标没有已验证邮箱、投递队列未装配、入队失败都返回明确的失败回执与错误，绝不
//     伪造“已通知/已送达”；
//   - 不保存/不输出新的口令、哈希、证明令牌、验证码或恢复秘密；收件地址只用于本次
//     入队，不写入本包日志。
//
// 本文件只新增能力，不修改 265 的人工恢复通知实现。

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/manualrecovery"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// 直接管理告知状态（与 265 语义对齐：queued 只表示已入可靠投递队列）。
const (
	DirectNoticeQueued           = "queued"
	DirectNoticeFailed           = "failed"
	DirectNoticeNoVerifiedEmail  = "no_verified_email"
	DirectNoticeNotConfigured    = "not_configured"
	DirectNoticeInvalidRecipient = "invalid_recipient"
)

// DirectManagementNotice 是一次直接管理操作告知请求。
type DirectManagementNotice struct {
	// TargetUserID 是被管理的目标用户稳定 ID（必填）。
	TargetUserID string
	// OperationLabel 是展示用操作标签（如“直接修改用户名”），不含秘密。
	OperationLabel string
	// OccurredAt 是业务完成时间（UTC）。
	OccurredAt time.Time
	// DedupKey 是稳定业务去重键（由证明批准 ID 派生，调用方保证同一逻辑操作稳定）。
	DedupKey string
	// RequestID 是本次管理请求编号。
	RequestID string
}

// DirectManagementNoticeReceipt 是告知结果回执；State=queued 只表示已入队。
type DirectManagementNoticeReceipt struct {
	State      string
	DedupKey   string
	DeliveryID string
	Duplicate  bool
}

// DirectManagementNotifier 发送直接管理操作的敏感操作告知。
type DirectManagementNotifier struct {
	deliveries mailer.DeliveryEnqueuer
	store      *storagesqlite.Store
	appName    string
	supportURL string
}

// NewDirectManagementNotifier 用共享装配依赖构造通知器；缺少存储或投递队列时返回错误
// （调用方应把通知视为不可用并记录，而不是伪造成功）。
func NewDirectManagementNotifier(deps Deps) (*DirectManagementNotifier, error) {
	if deps.Store == nil {
		return nil, errors.New("直接管理告知缺少数据库存储")
	}
	deliveries := deps.MailDeliveryProvider != nil
	var enqueuer mailer.DeliveryEnqueuer
	if deliveries {
		enqueuer = deps.MailDeliveryProvider()
	}
	appName := "EvernightLogin"
	supportURL := ""
	if deps.Mail != nil {
		appName = deps.Mail.AppDisplayName()
		urls, urlErr := buildMailURLs(deps.Config)
		if urlErr == nil {
			supportURL = urls.Support
		}
	}
	return newDirectManagementNotifier(enqueuer, deps.Store, appName, supportURL), nil
}

// newDirectManagementNotifier 用显式依赖构造通知器（测试可注入受控入队器；生产经
// NewDirectManagementNotifier 从共享装配取得同一投递队列）。
func newDirectManagementNotifier(deliveries mailer.DeliveryEnqueuer,
	store *storagesqlite.Store, appName, supportURL string) *DirectManagementNotifier {
	return &DirectManagementNotifier{deliveries: deliveries, store: store,
		appName: appName, supportURL: supportURL}
}

// Notify 向目标用户最近已验证邮箱发送“直接管理操作已发生”的告知。
//
// 返回失败回执与错误时调用方必须保留已完成业务、记录可诊断状态，不得回滚或宣称已通知。
func (n *DirectManagementNotifier) Notify(ctx context.Context,
	notice DirectManagementNotice) (DirectManagementNoticeReceipt, error) {
	receipt := DirectManagementNoticeReceipt{State: DirectNoticeFailed,
		DedupKey: notice.DedupKey}
	if n == nil || n.store == nil {
		return receipt, errors.New("直接管理告知未装配")
	}
	if !account.ValidUserID(notice.TargetUserID) {
		receipt.State = DirectNoticeInvalidRecipient
		return receipt, errors.New("目标用户标识无效")
	}
	label := strings.TrimSpace(notice.OperationLabel)
	if label == "" || len(label) > 64 {
		label = "直接管理操作"
	}
	if !manualrecovery.ValidNotificationDedupKey(notice.DedupKey) {
		return receipt, errors.New("告知去重键无效")
	}
	occurred := notice.OccurredAt
	if occurred.IsZero() {
		occurred = time.Now().UTC()
	}
	if n.deliveries == nil {
		receipt.State = DirectNoticeNotConfigured
		return receipt, errors.New("安全告知投递队列未装配")
	}
	// 收件地址只取目标最近已验证邮箱；查询失败不猜测地址。
	var email string
	err := n.store.DB().QueryRowContext(ctx, `SELECT email FROM user_emails
WHERE user_id=? AND verified_at_ms IS NOT NULL ORDER BY verified_at_ms DESC LIMIT 1`,
		notice.TargetUserID).Scan(&email)
	if err != nil || strings.TrimSpace(email) == "" {
		receipt.State = DirectNoticeNoVerifiedEmail
		return receipt, fmt.Errorf("目标没有可用于安全告知的已验证邮箱")
	}
	caller, callerErr := mailer.SystemCaller("direct-user-management")
	if callerErr != nil {
		return receipt, errors.New("构造告知投递身份失败")
	}
	securityNotice := &mailer.SecurityNoticeData{
		Event:      label,
		OccurredAt: occurred.UTC().Format(time.RFC3339),
		ClientInfo: "管理员直接管理",
		AppName:    n.appName,
		SupportURL: n.supportURL,
	}
	enqueued, err := n.deliveries.Enqueue(ctx, mailer.EnqueueRequest{
		Caller: caller, IdempotencyKey: notice.DedupKey, Kind: mailer.KindSecurityNotice,
		Recipient: email,
		Data: mailer.RenderRequest{Kind: mailer.KindSecurityNotice,
			Notice: securityNotice},
		RequestID: notice.RequestID,
	})
	if err != nil {
		receipt.State = DirectNoticeNotConfigured
		return receipt, errors.New("安全告知入队失败")
	}
	receipt.State = DirectNoticeQueued
	receipt.DeliveryID = enqueued.Record.ID
	receipt.Duplicate = enqueued.Duplicate
	return receipt, nil
}
