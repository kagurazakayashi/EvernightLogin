package mailer_test

// 步骤 266：投递记录 keyset 有界分页测试（R10-23 邮件投递记录端点/权限的领域层）。
// 覆盖：同创建时间稳定排序、继续读取不重不漏、筛选/数据范围变化旧游标拒绝、
// 非法/篡改游标拒绝、普通用户数据范围、响应不含加密载荷。

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
)

// TestDeliveryListPageStableKeyset 验证同一创建时间下的稳定 keyset 分页。
func TestDeliveryListPageStableKeyset(t *testing.T) {
	env := newDeliveryEnv(t)
	ctx := context.Background()
	// 同一 Now 入队 5 封（created_at 相同），以稳定 ID 作并列键。
	for index := 0; index < 5; index++ {
		if _, err := env.service.Enqueue(ctx, verificationRequest(
			fmt.Sprintf("verify:page:user-%d", index))); err != nil {
			t.Fatalf("入队 %d: %v", index, err)
		}
	}
	system := mustSystemCaller(t)
	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		page, err := env.service.ListPage(ctx, system, mailer.DeliveryPageQuery{
			Limit: 2, Cursor: cursor})
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
			if record.SealedPayload != nil {
				t.Fatalf("分页响应不得包含加密载荷")
			}
			seen[record.ID] = true
		}
		pages++
		if !page.HasMore {
			if page.NextCursor != "" {
				t.Fatalf("无下一页时不应返回游标")
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
}

// TestDeliveryListPageCursorBindsFilterAndScope 验证游标绑定筛选条件与数据范围。
func TestDeliveryListPageCursorBindsFilterAndScope(t *testing.T) {
	env := newDeliveryEnv(t)
	ctx := context.Background()
	for index := 0; index < 3; index++ {
		if _, err := env.service.Enqueue(ctx, verificationRequest(
			fmt.Sprintf("verify:bind:user-%d", index))); err != nil {
			t.Fatalf("入队 %d: %v", index, err)
		}
	}
	system := mustSystemCaller(t)
	first, err := env.service.ListPage(ctx, system, mailer.DeliveryPageQuery{Limit: 1})
	if err != nil || !first.HasMore || first.NextCursor == "" {
		t.Fatalf("第一页应产生游标: %+v err=%v", first, err)
	}
	// 同条件继续读取。
	if _, err := env.service.ListPage(ctx, system, mailer.DeliveryPageQuery{
		Limit: 1, Cursor: first.NextCursor}); err != nil {
		t.Fatalf("同条件继续分页应成功: %v", err)
	}
	// 切换状态筛选：拒绝（不能跨筛选续读）。
	if _, err := env.service.ListPage(ctx, system, mailer.DeliveryPageQuery{
		Limit: 1, State: mailer.DeliveryFailed, Cursor: first.NextCursor}); !errors.Is(err, mailer.ErrDeliveryCursorMismatch) {
		t.Fatalf("切换筛选后旧游标应拒绝，得到 %v", err)
	}
	// 切换数据范围（普通用户只看本人；系统用户建立的记录对普通用户不可见）：拒绝。
	user := mustUserCaller(t, "usr_00000000000000000000000000000001")
	if _, err := env.service.ListPage(ctx, user, mailer.DeliveryPageQuery{
		Limit: 1, Cursor: first.NextCursor}); !errors.Is(err, mailer.ErrDeliveryCursorMismatch) {
		t.Fatalf("跨数据范围使用旧游标应拒绝，得到 %v", err)
	}
	// 普通用户的独立第一页为空（数据范围隔离），不因游标拒绝而泄露。
	page, err := env.service.ListPage(ctx, user, mailer.DeliveryPageQuery{Limit: 1})
	if err != nil || len(page.Records) != 0 || page.HasMore {
		t.Fatalf("普通用户不应看到系统投递记录: %+v err=%v", page, err)
	}
	// 非法/篡改游标拒绝。
	for _, bad := range []string{"not-base64!!", "e30"} {
		if _, err := env.service.ListPage(ctx, system, mailer.DeliveryPageQuery{
			Limit: 1, Cursor: bad}); !errors.Is(err, mailer.ErrDeliveryCursorInvalid) {
			t.Fatalf("非法游标 %q 应拒绝，得到 %v", bad, err)
		}
	}
	// 非法状态明确拒绝。
	if _, err := env.service.ListPage(ctx, system, mailer.DeliveryPageQuery{
		Limit: 1, State: mailer.DeliveryState("bogus")}); !errors.Is(err, mailer.ErrInvalidMessage) {
		t.Fatalf("非法状态应拒绝，得到 %v", err)
	}
}
