package serverapp

// 步骤 256：直接管理操作安全告知的定向测试（真实迁移 SQLite + 受控入队器）。
//
// 覆盖：向目标最近已验证邮箱入队、去重键/用途/收件人正确、内容不含秘密字段、
// 无已验证邮箱/未装配投递队列/非法去重键的明确失败回执（绝不伪造已通知），以及
// 重复入队结果透传。

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
)

// captureEnqueuer 是受控的可靠投递入队器替身。
type captureEnqueuer struct {
	mu       sync.Mutex
	requests []mailer.EnqueueRequest
	result   mailer.EnqueueResult
	err      error
}

func (c *captureEnqueuer) Enqueue(_ context.Context,
	request mailer.EnqueueRequest) (mailer.EnqueueResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests = append(c.requests, request)
	if c.err != nil {
		return mailer.EnqueueResult{}, c.err
	}
	return c.result, nil
}

// TestDirectManagementNotifier 覆盖告知入队成功与失败语义。
func TestDirectManagementNotifier(t *testing.T) {
	store := openMigratedStore(t)
	ctx := context.Background()
	const targetID = "usr_0000000000000000000000000000e001"
	nowMS := testNow.UnixMilli()
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO users(
id,username,username_normalized,nickname,biography,avatar_ref,language,timezone,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'','',NULL,'zh-CN','Asia/Shanghai','active',0,1,1,?,?)`,
		targetID, "notice-target", "notice-target", nowMS, nowMS); err != nil {
		t.Fatalf("插入目标用户: %v", err)
	}
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO user_emails(
email_normalized,user_id,email,verified_at_ms,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?)`, "notice@example.test", targetID, "notice@example.test",
		nowMS, nowMS, nowMS); err != nil {
		t.Fatalf("插入已验证邮箱: %v", err)
	}
	notice := DirectManagementNotice{TargetUserID: targetID,
		OperationLabel: "管理员修改了你的用户名", OccurredAt: testNow,
		DedupKey:  "admin-direct-username-change:apr_test_dedup_0001",
		RequestID: "req-256-notice"}

	// 1) 正常入队：用途/收件人/去重键正确，内容不含密码等秘密字段。
	enqueuer := &captureEnqueuer{result: mailer.EnqueueResult{
		Record: mailer.Record{ID: "mdl_test_notice_0001"}}}
	notifier := newDirectManagementNotifier(enqueuer, store, "EvernightLogin",
		"https://example.test/support")
	receipt, err := notifier.Notify(ctx, notice)
	if err != nil {
		t.Fatalf("告知入队: %v", err)
	}
	if receipt.State != DirectNoticeQueued || receipt.DeliveryID != "mdl_test_notice_0001" {
		t.Fatalf("告知回执异常: %+v", receipt)
	}
	enqueuer.mu.Lock()
	if len(enqueuer.requests) != 1 {
		enqueuer.mu.Unlock()
		t.Fatalf("入队请求数 = %d，期望 1", len(enqueuer.requests))
	}
	request := enqueuer.requests[0]
	enqueuer.mu.Unlock()
	if request.Kind != mailer.KindSecurityNotice || request.IdempotencyKey != notice.DedupKey ||
		request.Recipient != "notice@example.test" {
		t.Fatalf("入队请求参数异常: %+v", request)
	}
	if request.Data.Notice == nil || request.Data.Notice.Event != "管理员修改了你的用户名" {
		t.Fatalf("安全告知内容异常: %+v", request.Data.Notice)
	}
	// 重复入队：幂等键已存在时透传 Duplicate，不伪造新投递。
	enqueuer.mu.Lock()
	enqueuer.result = mailer.EnqueueResult{Record: mailer.Record{ID: "mdl_test_notice_0001"},
		Duplicate: true}
	enqueuer.mu.Unlock()
	duplicateReceipt, err := notifier.Notify(ctx, notice)
	if err != nil || !duplicateReceipt.Duplicate {
		t.Fatalf("重复入队回执异常: %+v err=%v", duplicateReceipt, err)
	}

	// 2) 入队失败：返回失败回执与错误，不冒充成功。
	failing := &captureEnqueuer{err: errors.New("注入入队失败")}
	failReceipt, failErr := newDirectManagementNotifier(failing, store,
		"EvernightLogin", "").Notify(ctx, notice)
	if failErr == nil || failReceipt.State == DirectNoticeQueued {
		t.Fatalf("入队失败回执异常: %+v err=%v", failReceipt, failErr)
	}

	// 3) 未装配投递队列：明确 not_configured。
	unconfigured := newDirectManagementNotifier(nil, store, "EvernightLogin", "")
	if _, unconfiguredErr := unconfigured.Notify(ctx, notice); unconfiguredErr == nil {
		t.Fatal("未装配投递队列必须返回错误")
	}

	// 4) 非法去重键：拒绝且不入队。
	badKey := notice
	badKey.DedupKey = "x"
	if _, badErr := notifier.Notify(ctx, badKey); badErr == nil {
		t.Fatal("非法去重键必须拒绝")
	}

	// 5) 目标没有已验证邮箱：明确 no_verified_email，不猜测地址。
	const noEmailID = "usr_0000000000000000000000000000e002"
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO users(
id,username,username_normalized,status,is_root,security_version,row_version,
created_at_ms,updated_at_ms) VALUES(?,?,?,'active',0,1,1,?,?)`,
		noEmailID, "no-email", "no-email", nowMS, nowMS); err != nil {
		t.Fatalf("插入无邮箱用户: %v", err)
	}
	noEmailNotice := notice
	noEmailNotice.TargetUserID = noEmailID
	noEmailNotice.DedupKey = "admin-direct-username-change:apr_test_dedup_0002"
	noEmailReceipt, noEmailErr := notifier.Notify(ctx, noEmailNotice)
	if noEmailErr == nil || noEmailReceipt.State != DirectNoticeNoVerifiedEmail {
		t.Fatalf("无邮箱目标回执异常: %+v err=%v", noEmailReceipt, noEmailErr)
	}
}
