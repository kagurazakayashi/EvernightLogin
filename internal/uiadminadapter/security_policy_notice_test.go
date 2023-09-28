// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package uiadminadapter

import (
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
)

// TestNotificationNoticeStateMapping 校验通知页状态映射：可靠投递记录的实时状态
// 优先于主记录状态；succeeded 只映射为 smtp_accepted（SMTP 接受），绝不冒充 sent/
// 已读/已送达；主记录 queued 但关联不到投递时映射 unknown，不显示成功。
func TestNotificationNoticeStateMapping(t *testing.T) {
	cases := []struct {
		name   string
		record reauth.NotificationRecord
		want   string
	}{
		{"queued delivery", reauth.NotificationRecord{State: reauth.NotificationQueued,
			DeliveryState: mailer.DeliveryQueued}, "queued"},
		{"sending delivery", reauth.NotificationRecord{State: reauth.NotificationQueued,
			DeliveryState: mailer.DeliverySending}, "sending"},
		{"smtp accepted", reauth.NotificationRecord{State: reauth.NotificationQueued,
			DeliveryState: mailer.DeliverySucceeded}, "smtp_accepted"},
		{"delivery failed", reauth.NotificationRecord{State: reauth.NotificationQueued,
			DeliveryState: mailer.DeliveryFailed, DeliveryErrorCode: "SMTP_AUTH_FAILED"}, "failed"},
		{"delivery cancelled", reauth.NotificationRecord{State: reauth.NotificationQueued,
			DeliveryState: mailer.DeliveryCancelled}, "cancelled"},
		{"queued without delivery", reauth.NotificationRecord{State: reauth.NotificationQueued},
			"unknown"},
		{"direct sent", reauth.NotificationRecord{State: reauth.NotificationSent}, "sent"},
		{"no verified email", reauth.NotificationRecord{State: reauth.NotificationNoVerifiedEmail},
			"no_verified_email"},
		{"rate limited", reauth.NotificationRecord{State: reauth.NotificationRateLimited},
			"rate_limited"},
		{"not configured", reauth.NotificationRecord{State: reauth.NotificationNotConfigured},
			"not_configured"},
		{"suppressed", reauth.NotificationRecord{State: reauth.NotificationSuppressed},
			"suppressed"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := notificationNoticeState(testCase.record); got != testCase.want {
				t.Fatalf("状态映射 = %q，期望 %q", got, testCase.want)
			}
		})
	}
}

// TestNotificationNoticeErrorCodeMapping 校验失败错误码优先展示投递记录的稳定错误码，
// 其次才是告知主记录原因码；成功/取消不额外显示失败码。
func TestNotificationNoticeErrorCodeMapping(t *testing.T) {
	failed := reauth.NotificationRecord{
		State: reauth.NotificationQueued, ErrorCode: "delivery_enqueue_failed",
		DeliveryState: mailer.DeliveryFailed, DeliveryErrorCode: "SMTP_AUTH_FAILED",
	}
	if got := notificationNoticeErrorCode(failed); got != "SMTP_AUTH_FAILED" {
		t.Errorf("失败错误码 = %q，期望投递记录错误码", got)
	}
	queued := reauth.NotificationRecord{State: reauth.NotificationQueued}
	if got := notificationNoticeErrorCode(queued); got != "" {
		t.Errorf("排队状态不应显示错误码: %q", got)
	}
	succeeded := reauth.NotificationRecord{DeliveryState: mailer.DeliverySucceeded,
		DeliveryErrorCode: "忽略", ErrorCode: "ignored"}
	if got := notificationNoticeErrorCode(succeeded); got != "ignored" {
		t.Errorf("成功投递应回退主记录错误码: %q", got)
	}
}
