package group_test

// 步骤 216：用户组列表与成员列表的白名单排序、稳定同值次序、分页与非法输入。
//   - 默认排序 created_at ASC；同值按稳定 ID 次序，保证分页不重复/不跳行；
//   - 排序字段来自白名单，非法值返回 ErrInvalidRequest（不静默用默认值）；
//   - 分页在存储层执行（LIMIT/OFFSET），HasMore 表示后续仍有记录；
//   - offset 不提供并发快照语义，这里只验证顺序稳定性。

import (
	"context"
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/group"
)

// createNamedGroup 用显式名称创建系统组（便于排序断言）。
func (e *testEnv) createNamedGroup(scopeID, key, name string) group.Group {
	e.t.Helper()
	record, err := e.service.CreateGroup(context.Background(), e.system, group.CreateRequest{
		ScopeID: scopeID, GroupKey: key, Name: name, Description: "排序测试",
	})
	if err != nil {
		e.t.Fatalf("创建用户组 %s 失败: %v", key, err)
	}
	return record
}

func TestGroupListSortWhitelistAndStableOrder(t *testing.T) {
	env := prepareEnv(t)
	ctx := context.Background()
	env.createNamedGroup(group.ScopeSystem, "sort-alpha", "Alpha组")
	env.createNamedGroup(group.ScopeSystem, "sort-zeta", "Zeta组")
	// 同名组用于验证“同值时按稳定 ID 次序”。
	firstSame := env.createNamedGroup(group.ScopeSystem, "sort-same-1", "同名组")
	secondSame := env.createNamedGroup(group.ScopeSystem, "sort-same-2", "同名组")

	page, err := env.service.ListGroups(ctx, env.system, group.ListRequest{
		Limit: 10, Sort: group.GroupSortName})
	if err != nil {
		t.Fatalf("按名称排序失败: %v", err)
	}
	if len(page.Groups) != 4 {
		t.Fatalf("组数 = %d，期望 4", len(page.Groups))
	}
	names := []string{page.Groups[0].Name, page.Groups[1].Name, page.Groups[2].Name,
		page.Groups[3].Name}
	// SQLite 默认二进制排序：ASCII 前缀在中文之前，同名组按 UTF-8 字节排在 Zeta 之后。
	if names[0] != "Alpha组" || names[1] != "Zeta组" ||
		names[2] != "同名组" || names[3] != "同名组" {
		t.Fatalf("名称升序 = %v", names)
	}
	// 同名两条必须按 ID 升序稳定出现。
	if page.Groups[2].ID >= page.Groups[3].ID {
		t.Fatalf("同值未按稳定 ID 升序: %s >= %s", page.Groups[2].ID, page.Groups[3].ID)
	}
	if page.Groups[2].ID != firstSame.ID && page.Groups[2].ID != secondSame.ID ||
		page.Groups[3].ID != firstSame.ID && page.Groups[3].ID != secondSame.ID {
		t.Fatalf("同名组顺序异常: %+v", page.Groups[2:4])
	}

	// 降序：方向反转但同值仍按稳定 ID 降序。
	desc, err := env.service.ListGroups(ctx, env.system, group.ListRequest{
		Limit: 10, Sort: group.GroupSortName, Descending: true})
	if err != nil {
		t.Fatalf("降序排序失败: %v", err)
	}
	if desc.Groups[0].Name != "同名组" || desc.Groups[3].Name != "Alpha组" {
		t.Fatalf("降序名称 = %v", []string{desc.Groups[0].Name, desc.Groups[1].Name,
			desc.Groups[2].Name, desc.Groups[3].Name})
	}
	if desc.Groups[0].Name == desc.Groups[1].Name && desc.Groups[0].ID <= desc.Groups[1].ID {
		t.Fatalf("降序同值未按稳定 ID 降序: %s <= %s", desc.Groups[0].ID, desc.Groups[1].ID)
	}

	// 分页：limit=1 逐页拼接应等于完整顺序，且末页 HasMore=false。
	full := make([]string, 0, 4)
	for offset := 0; offset < 4; offset++ {
		current, pageErr := env.service.ListGroups(ctx, env.system, group.ListRequest{
			Limit: 1, Offset: offset, Sort: group.GroupSortName})
		if pageErr != nil {
			t.Fatalf("分页 offset=%d 失败: %v", offset, pageErr)
		}
		if len(current.Groups) != 1 {
			t.Fatalf("offset=%d 条数 = %d", offset, len(current.Groups))
		}
		wantMore := offset < 3
		if current.HasMore != wantMore {
			t.Fatalf("offset=%d HasMore = %v，期望 %v", offset, current.HasMore, wantMore)
		}
		full = append(full, current.Groups[0].ID)
	}
	for index, record := range page.Groups {
		if full[index] != record.ID {
			t.Fatalf("分页拼接与整页顺序不一致: index=%d %s != %s", index,
				full[index], record.ID)
		}
	}

	// 非法排序字段 fail-closed。
	if _, err := env.service.ListGroups(ctx, env.system, group.ListRequest{
		Limit: 10, Sort: group.GroupSortField("bogus")}); !errors.Is(err, group.ErrInvalidRequest) {
		t.Fatalf("非法排序字段错误 = %v，期望 ErrInvalidRequest", err)
	}
	// 非法分页参数同样拒绝。
	if _, err := env.service.ListGroups(ctx, env.system, group.ListRequest{
		Limit: 101}); !errors.Is(err, group.ErrInvalidRequest) {
		t.Fatalf("limit 越界错误 = %v，期望 ErrInvalidRequest", err)
	}
	if _, err := env.service.ListGroups(ctx, env.system, group.ListRequest{
		Limit: 10, Offset: -1}); !errors.Is(err, group.ErrInvalidRequest) {
		t.Fatalf("负 offset 错误 = %v，期望 ErrInvalidRequest", err)
	}
}

func TestGroupMemberListSortAndPagination(t *testing.T) {
	env := prepareEnv(t)
	ctx := context.Background()
	record := env.createGroup(group.ScopeSystem, "member-sort")
	for _, userID := range []string{userOne, userTwo, userThree} {
		if _, err := env.service.AddMembers(ctx, env.system, group.MemberBatchRequest{
			GroupID: record.ID, UserIDs: []string{userID}}); err != nil {
			t.Fatalf("加入成员 %s 失败: %v", userID, err)
		}
	}

	// user_id 降序：userThree > userTwo > userOne（稳定 ID 字典序）。
	page, err := env.service.ListMembers(ctx, env.system, group.MemberListRequest{
		GroupID: record.ID, Limit: 2, Sort: group.MemberSortUserID, Descending: true})
	if err != nil {
		t.Fatalf("成员排序失败: %v", err)
	}
	if len(page.Members) != 2 || !page.HasMore {
		t.Fatalf("成员第一页 = %d, hasMore=%v", len(page.Members), page.HasMore)
	}
	if page.Members[0].UserID != userThree || page.Members[1].UserID != userTwo {
		t.Fatalf("成员降序顺序 = %+v", page.Members)
	}
	second, err := env.service.ListMembers(ctx, env.system, group.MemberListRequest{
		GroupID: record.ID, Limit: 2, Offset: 2, Sort: group.MemberSortUserID,
		Descending: true})
	if err != nil || len(second.Members) != 1 || second.HasMore {
		t.Fatalf("成员第二页 = %+v, err=%v", second, err)
	}
	if second.Members[0].UserID != userOne {
		t.Fatalf("成员第二页用户 = %s，期望 %s", second.Members[0].UserID, userOne)
	}
	// 默认 joined_at 升序：时间相同按 user_id 升序稳定。
	joined, err := env.service.ListMembers(ctx, env.system, group.MemberListRequest{
		GroupID: record.ID, Limit: 3})
	if err != nil || len(joined.Members) != 3 {
		t.Fatalf("默认成员排序 = %+v, %v", joined, err)
	}
	for index := 1; index < len(joined.Members); index++ {
		if joined.Members[index-1].UserID >= joined.Members[index].UserID {
			t.Fatalf("默认成员次序不稳定: %+v", joined.Members)
		}
	}
	if _, err := env.service.ListMembers(ctx, env.system, group.MemberListRequest{
		GroupID: record.ID, Limit: 10, Sort: group.MemberSortField("bogus")}); !errors.Is(err,
		group.ErrInvalidRequest) {
		t.Fatalf("非法成员排序字段错误 = %v，期望 ErrInvalidRequest", err)
	}
}
