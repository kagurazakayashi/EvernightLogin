package reauth_test

// 步骤 266：安全告知 keyset 有界分页测试。
// 覆盖：同一创建时间稳定排序、继续读取不重不漏、游标绑定目标用户（换用户拒绝）、
// 非法/篡改游标拒绝、非本人读取拒绝、既有索引可支撑查询（EXPLAIN QUERY PLAN）。

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
)

// TestNotificationsPageStableKeyset 验证同一时间下的稳定分页与游标绑定用户。
func TestNotificationsPageStableKeyset(t *testing.T) {
	env := newTestEnv(t, nil)
	ctx := context.Background()
	base := time.Date(2026, 11, 26, 3, 0, 0, 0, time.UTC)
	env.now = base
	// 同一 created_at_ms 的 5 条告知（以稳定告知 ID 作并列键）。
	for index := 1; index <= 5; index++ {
		if _, err := env.storage.DB().ExecContext(ctx, `INSERT INTO security_notifications(
id,user_id,operation_id,target_type,target_id,outcome,state,error_code,reason_code,
recipient_masked,created_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
			fmt.Sprintf("ntf_page_%04d", index), normalUserID, "password.change", "user",
			normalUserID, "success", "queued", "", "", "a***@example.com",
			base.UnixMilli()); err != nil {
			t.Fatalf("插入告知 %d: %v", index, err)
		}
	}
	alice := env.userCaller(t, normalUserID)
	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		page, err := env.service.NotificationsPage(ctx, alice, normalUserID, cursor, 2)
		if err != nil {
			t.Fatalf("分页读取: %v", err)
		}
		if len(page.Records) > 2 {
			t.Fatalf("单页超过 limit: %d", len(page.Records))
		}
		for _, record := range page.Records {
			if record.ID == "" || seen[record.ID] {
				t.Fatalf("分页重复/缺 ID: %q", record.ID)
			}
			if record.RecipientMasked != "a***@example.com" {
				t.Fatalf("脱敏收件人异常: %q", record.RecipientMasked)
			}
			seen[record.ID] = true
		}
		pages++
		if !page.HasMore {
			if page.NextCursor != "" {
				t.Fatal("无下一页时不应返回游标")
			}
			break
		}
		if page.NextCursor == "" {
			t.Fatal("HasMore=true 时必须返回游标")
		}
		cursor = page.NextCursor
		if pages > 10 {
			t.Fatal("分页未收敛")
		}
	}
	if len(seen) != 5 || pages != 3 {
		t.Fatalf("分页覆盖异常: seen=%d pages=%d", len(seen), pages)
	}

	// 游标绑定目标用户：用 alice 的游标读另一个用户必须拒绝（系统调用者可用）。
	system, err := reauth.SystemCaller("reauth-test")
	if err != nil {
		t.Fatalf("系统调用者: %v", err)
	}
	first, err := env.service.NotificationsPage(ctx, system, normalUserID, "", 1)
	if err != nil || !first.HasMore || first.NextCursor == "" {
		t.Fatalf("系统读取第一页应产生游标: %+v err=%v", first, err)
	}
	otherUser := "usr_00000000000000000000000000000003"
	if _, err := env.service.NotificationsPage(ctx, system, otherUser,
		first.NextCursor, 1); !errors.Is(err, reauth.ErrNotificationCursorMismatch) {
		t.Fatalf("换用户继续旧游标应拒绝，得到 %v", err)
	}
	// 非法/篡改游标拒绝。
	for _, bad := range []string{"not-base64!!", "e30"} {
		if _, err := env.service.NotificationsPage(ctx, alice, normalUserID,
			bad, 1); !errors.Is(err, reauth.ErrNotificationCursorInvalid) {
			t.Fatalf("非法游标 %q 应拒绝，得到 %v", bad, err)
		}
	}
	// 非本人（普通用户）读取拒绝；非法用户 ID 拒绝。
	bob := env.userCaller(t, "usr_00000000000000000000000000000003")
	if _, err := env.service.NotificationsPage(ctx, bob, normalUserID, "",
		1); !errors.Is(err, reauth.ErrAccessDenied) {
		t.Fatalf("非本人读取应拒绝，得到 %v", err)
	}
	if _, err := env.service.NotificationsPage(ctx, alice, "bad-user-id", "",
		1); !errors.Is(err, reauth.ErrInvalidRequest) {
		t.Fatalf("非法用户 ID 应拒绝，得到 %v", err)
	}
	// 空列表：新用户无告知时返回空页且无游标。
	empty := "usr_00000000000000000000000000000004"
	emptyPage, err := env.service.NotificationsPage(ctx, system, empty, "", 5)
	if err != nil || len(emptyPage.Records) != 0 || emptyPage.HasMore || emptyPage.NextCursor != "" {
		t.Fatalf("空列表异常: %+v err=%v", emptyPage, err)
	}
}

// TestNotificationsPageQueryPlanUsesIndex 记录 keyset 查询计划：既有
// ix_security_notifications_user_created(user_id, created_at_ms) 应被使用（无需新迁移）。
func TestNotificationsPageQueryPlanUsesIndex(t *testing.T) {
	env := newTestEnv(t, nil)
	rows, err := env.storage.DB().QueryContext(context.Background(),
		`EXPLAIN QUERY PLAN SELECT id FROM security_notifications
WHERE user_id=? AND (created_at_ms<? OR (created_at_ms=? AND id<?))
ORDER BY created_at_ms DESC, id DESC LIMIT ?`,
		normalUserID, 1, 1, "x", 21)
	if err != nil {
		t.Fatalf("EXPLAIN QUERY PLAN: %v", err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatalf("读取查询计划: %v", err)
		}
		plan.WriteString(detail + "; ")
	}
	if !strings.Contains(plan.String(), "ix_security_notifications_user_created") {
		t.Fatalf("keyset 查询未使用既有索引，需评估复合索引（记录计划: %s）", plan.String())
	}
}
