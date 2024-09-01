package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
)

// insertSearchUser 插入带昵称的合成账户（不经过账户服务，只用于成员搜索夹具）。
func (e *testEnv) insertSearchUser(userID, username, nickname string) {
	e.t.Helper()
	now := e.clock.Now().UnixMilli()
	if _, err := e.raw.ExecContext(context.Background(),
		`INSERT INTO users(id,username,username_normalized,nickname,biography,language,timezone,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,'','zh-CN','Asia/Shanghai','active',0,1,1,?,?)`,
		userID, username, username, nickname, now, now); err != nil {
		e.t.Fatalf("插入搜索用户 %q 失败: %v", username, err)
	}
}

// memberIDs 把成员列表投影为用户 ID 序列。
func memberIDs(members []app.Membership) []string {
	ids := make([]string, 0, len(members))
	for _, member := range members {
		ids = append(ids, member.UserID)
	}
	return ids
}

// TestApplicationMemberSearch 验收应用成员列表有界字面搜索：只在目标应用的成员
// 范围内按全局用户名/昵称匹配（JOIN users 参数化 LIKE），中文/大小写/全角/通配符
// 字面/单引号/方括号/反斜杠、跨应用隔离、状态与排序分页组合、以及非法搜索字段
// 的拒绝。真实 SQLite 执行路径。
func TestApplicationMemberSearch(t *testing.T) {
	env := prepareEnv(t)
	ctx := context.Background()
	appA := env.newActiveApp()
	appB := env.newActiveApp()

	const (
		userAlice = "usr_00000000000000000000000000000101"
		userBob   = "usr_00000000000000000000000000000102"
		userCarol = "usr_00000000000000000000000000000103"
		userDave  = "usr_00000000000000000000000000000104"
		userErin  = "usr_00000000000000000000000000000105"
		// 非成员：即使用户名/昵称匹配也不能被应用成员搜索返回。
		userOutsider = "usr_00000000000000000000000000000106"
	)
	env.insertSearchUser(userAlice, "Alice", "张三")
	env.insertSearchUser(userBob, "bob", "Alice小号")
	env.insertSearchUser(userCarol, "carol", "100%_real")
	env.insertSearchUser(userDave, "dave", "o'brien [admin]")
	env.insertSearchUser(userErin, "erin", `path\seg`)
	env.insertSearchUser(userOutsider, "outsider", "张三")
	for _, userID := range []string{userAlice, userBob, userCarol, userDave, userErin} {
		env.addMember(appA.ID, userID, app.MemberProfile{})
	}
	// bob 同时属于应用 B；应用 A 的搜索不能读取或泄露应用 B 之外的成员关系。
	env.addMember(appB.ID, userBob, app.MemberProfile{})

	searchMembers := func(applicationID string, request app.MemberListRequest) []string {
		t.Helper()
		request.ApplicationID = applicationID
		result, err := env.service.ListApplicationMembers(ctx, env.system, request)
		if err != nil {
			t.Fatalf("搜索应用成员失败: %v", err)
		}
		return memberIDs(result.Members)
	}
	assertExactly := func(label string, got []string, want ...string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s: 结果 = %v，期望 %v", label, got, want)
		}
		for index := range want {
			if got[index] != want[index] {
				t.Fatalf("%s: 结果 = %v，期望 %v", label, got, want)
			}
		}
	}

	// 默认字段=用户名+昵称：大小写折叠/全角折半角同时命中 Alice 与 bob 的昵称。
	assertExactly("大小写", searchMembers(appA.ID, app.MemberListRequest{Limit: 20, Search: "ALICE"}),
		userAlice, userBob)
	assertExactly("全角", searchMembers(appA.ID, app.MemberListRequest{Limit: 20, Search: "ＡＬＩＣＥ"}),
		userAlice, userBob)
	// 中文按字面子串；outsider 虽同昵称但不是本应用成员，不能被返回。
	assertExactly("中文", searchMembers(appA.ID, app.MemberListRequest{Limit: 20, Search: "张三"}),
		userAlice)
	// 通配符按字面。
	assertExactly("百分号字面", searchMembers(appA.ID, app.MemberListRequest{Limit: 20, Search: "%"}),
		userCarol)
	assertExactly("下划线字面", searchMembers(appA.ID, app.MemberListRequest{Limit: 20, Search: "_"}),
		userCarol)
	// 单引号/方括号/反斜杠字面输入不破坏 SQL。
	assertExactly("单引号", searchMembers(appA.ID, app.MemberListRequest{Limit: 20, Search: "'"}),
		userDave)
	assertExactly("方括号", searchMembers(appA.ID, app.MemberListRequest{Limit: 20, Search: "["}),
		userDave)
	assertExactly("反斜杠", searchMembers(appA.ID, app.MemberListRequest{Limit: 20, Search: `\`}),
		userErin)
	// 字段白名单：只搜用户名/只搜昵称。
	assertExactly("只搜昵称", searchMembers(appA.ID, app.MemberListRequest{Limit: 20, Search: "alice",
		SearchFields: []account.UserSearchField{account.UserSearchNickname}}), userBob)
	assertExactly("只搜用户名", searchMembers(appA.ID, app.MemberListRequest{Limit: 20, Search: "alice",
		SearchFields: []account.UserSearchField{account.UserSearchUsername}}), userAlice)
	// 空搜索保持本应用原成员列表（5 人，不含 outsider，不含应用 B 的其他成员）。
	if got := searchMembers(appA.ID, app.MemberListRequest{Limit: 20}); len(got) != 5 {
		t.Fatalf("空搜索成员数 = %d，期望应用 A 的 5 名成员", len(got))
	}
	// 跨应用隔离：应用 B 只有 bob；搜索 Alice 命中 bob（其昵称），不会返回应用 A
	// 的成员。
	assertExactly("应用B隔离", searchMembers(appB.ID, app.MemberListRequest{Limit: 20, Search: "alice"}),
		userBob)
	// 无匹配。
	if got := searchMembers(appA.ID, app.MemberListRequest{Limit: 20, Search: "不存在"}); len(got) != 0 {
		t.Fatalf("无匹配结果 = %v", got)
	}
	// 非法字段/超长搜索被拒绝（不静默改用默认字段）。
	if _, err := env.service.ListApplicationMembers(ctx, env.system, app.MemberListRequest{
		ApplicationID: appA.ID, Limit: 20, Search: "x",
		SearchFields: []account.UserSearchField{account.UserSearchField("email")},
	}); !errors.Is(err, app.ErrInvalidRequest) {
		t.Fatalf("邮箱字段错误 = %v，期望 ErrInvalidRequest", err)
	}
	if _, err := env.service.ListApplicationMembers(ctx, env.system, app.MemberListRequest{
		ApplicationID: appA.ID, Limit: 20, Search: "不存在的人",
	}); err != nil {
		t.Fatalf("普通无匹配搜索不应报错: %v", err)
	}

	// 搜索与状态过滤组合：把 carol 的成员关系改为 disabled 后按状态筛选。
	if _, err := env.raw.ExecContext(ctx,
		`UPDATE app_memberships SET status='disabled' WHERE app_id=? AND user_id=?`,
		appA.ID, userCarol); err != nil {
		t.Fatalf("停用成员失败: %v", err)
	}
	disabled := searchMembers(appA.ID, app.MemberListRequest{Limit: 20, Search: "carol",
		Status: app.MembershipDisabled})
	assertExactly("搜索+成员状态", disabled, userCarol)
	if got := searchMembers(appA.ID, app.MemberListRequest{Limit: 20, Search: "carol",
		Status: app.MembershipActive}); len(got) != 0 {
		t.Fatalf("搜索+成员状态不应命中 active: %v", got)
	}

	// 排序与分页组合：按 user_id 升序，两页拼接不重复且各一条。
	first, err := env.service.ListApplicationMembers(ctx, env.system, app.MemberListRequest{
		ApplicationID: appA.ID, Limit: 1, Search: "a", Sort: app.MemberSortUserID})
	if err != nil {
		t.Fatalf("搜索分页第一页失败: %v", err)
	}
	second, err := env.service.ListApplicationMembers(ctx, env.system, app.MemberListRequest{
		ApplicationID: appA.ID, Limit: 1, Offset: 1, Search: "a", Sort: app.MemberSortUserID})
	if err != nil {
		t.Fatalf("搜索分页第二页失败: %v", err)
	}
	if len(first.Members) != 1 || len(second.Members) != 1 || !first.HasMore {
		t.Fatalf("搜索分页 = %v(h=%v) / %v(h=%v)", memberIDs(first.Members), first.HasMore,
			memberIDs(second.Members), second.HasMore)
	}
	if first.Members[0].UserID == second.Members[0].UserID {
		t.Fatal("搜索分页出现重复成员")
	}
}
