package sqlite_test

// 步骤 218：备份计划与通知记录分页测试（服务层切片 + 授权保持）。
//   - 计划列表按创建时间倒序分页，HasMore 多取一条判定；
//   - 越界 offset 返回空页；非法 limit/offset 返回 ErrInvalidRequest；
//   - 通知记录分页读取不改变脱敏字段。

import (
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/backupadmin"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

func TestBackupSchedulesAndNotificationsPagination(t *testing.T) {
	e := newEnv(t)
	for index := 0; index < 3; index++ {
		if _, err := e.admin.CreateSchedule(e.ctx, backupadmin.ScheduleRequest{
			Caller: e.caller, Name: "分页计划", ScheduleType: task.ScheduleTypeDaily,
			Expression: "02:30", TimeZone: "Asia/Shanghai", MissedPolicy: task.MissedSkip,
			MaxCatchUp: 1, TimeoutSeconds: 3600, MaxAttempts: 1,
			RetentionVersion: 1, Enabled: true,
			RequestID: "req-page-schedule-" + string(rune('a'+index)),
		}); err != nil {
			t.Fatalf("创建备份计划 %d: %v", index, err)
		}
	}
	first, hasMore, err := e.admin.ListSchedulesPage(e.ctx, e.caller, 2, 0)
	if err != nil || len(first) != 2 || !hasMore {
		t.Fatalf("备份计划第一页 = %d hasMore=%v err=%v", len(first), hasMore, err)
	}
	second, hasMore, err := e.admin.ListSchedulesPage(e.ctx, e.caller, 2, 2)
	if err != nil || len(second) != 1 || hasMore {
		t.Fatalf("备份计划第二页 = %d hasMore=%v err=%v", len(second), hasMore, err)
	}
	seen := map[string]bool{}
	for _, view := range append(first, second...) {
		if seen[view.ID] {
			t.Fatalf("计划分页重复 %s", view.ID)
		}
		seen[view.ID] = true
	}
	if len(seen) != 3 {
		t.Fatalf("计划两页数量 = %d，期望 3", len(seen))
	}
	if empty, hasMore, err := e.admin.ListSchedulesPage(e.ctx, e.caller, 2, 100); err != nil ||
		len(empty) != 0 || hasMore {
		t.Fatalf("计划越界 offset = %d hasMore=%v err=%v", len(empty), hasMore, err)
	}
	for _, limit := range []int{-1, 101} {
		if _, _, err := e.admin.ListSchedulesPage(e.ctx, e.caller, limit, 0); !errors.Is(err,
			backupadmin.ErrInvalidRequest) {
			t.Fatalf("非法计划分页 limit=%d 错误 = %v，期望 ErrInvalidRequest", limit, err)
		}
	}
	if _, _, err := e.admin.ListSchedulesPage(e.ctx, e.caller, 2, -1); !errors.Is(err,
		backupadmin.ErrInvalidRequest) {
		t.Fatalf("非法计划分页 offset 错误 = %v，期望 ErrInvalidRequest", err)
	}

	// 通知记录分页：直接写入受控通知记录（不执行真实备份）。
	now := e.now.UTC()
	for index := 0; index < 3; index++ {
		if _, err := e.raw.DB().ExecContext(e.ctx, `INSERT INTO backup_notifications(
id,job_id,backup_id,kind,state,channel,recipient_masked,error_code,attempts,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
			"ntf_"+string(rune('a'+index)), "job_page", "", "backup_failed", "accepted",
			"mail", "u***@example.test", "", 1, now.UnixMilli(), now.UnixMilli()); err != nil {
			t.Fatalf("写入通知记录 %d: %v", index, err)
		}
	}
	notifications, hasMore, err := e.admin.ListNotificationsPage(e.ctx, e.caller,
		"job_page", "", 2, 0)
	if err != nil || len(notifications) != 2 || !hasMore {
		t.Fatalf("通知第一页 = %d hasMore=%v err=%v", len(notifications), hasMore, err)
	}
	secondNotifications, hasMore, err := e.admin.ListNotificationsPage(e.ctx, e.caller,
		"job_page", "", 2, 2)
	if err != nil || len(secondNotifications) != 1 || hasMore {
		t.Fatalf("通知第二页 = %d hasMore=%v err=%v", len(secondNotifications), hasMore, err)
	}
	if notifications[0].RecipientMasked != "u***@example.test" {
		t.Fatalf("通知脱敏字段 = %q", notifications[0].RecipientMasked)
	}
	if _, _, err := e.admin.ListNotificationsPage(e.ctx, e.caller,
		"job_page", "", 0, 0); err != nil {
		t.Fatalf("通知默认页大小失败: %v", err)
	}
}
