package account_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/search"
)

// createUserWithNickname 创建带昵称的合成用户；失败时终止测试。
func (e *testEnv) createUserWithNickname(username, nickname string) account.User {
	e.t.Helper()
	user, err := e.service.CreateUser(context.Background(), e.caller, account.CreateRequest{
		Username: username, Nickname: nickname,
	})
	if err != nil {
		e.t.Fatalf("创建用户 %q（昵称 %q）失败: %v", username, nickname, err)
	}
	return user
}

// usernamesOf 把列表结果投影为用户名切片，便于断言。
func usernamesOf(users []account.User) []string {
	names := make([]string, 0, len(users))
	for _, user := range users {
		names = append(names, user.Username)
	}
	return names
}

// searchUsers 经服务 + 真实 SQLite 执行一次搜索并返回用户名列表。
func (e *testEnv) searchUsers(request account.ListRequest) []string {
	e.t.Helper()
	result, err := e.service.ListUsers(context.Background(), e.caller, request)
	if err != nil {
		e.t.Fatalf("搜索用户失败: %v", err)
	}
	return usernamesOf(result.Users)
}

// assertExactly 断言搜索结果的用户名恰好等于期望序列（顺序敏感）。
func assertExactly(t *testing.T, label string, got []string, want ...string) {
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

// TestListUsersSearch 验收用户列表有界字面模糊搜索：中文、大小写、全角、通配符
// 字面、单引号/方括号/反斜杠、重复昵称稳定排序、状态/排序/分页组合与空搜索。
// 全部经真实 SQLite 的执行路径（服务 + 仓储），不是纯函数替身。
func TestListUsersSearch(t *testing.T) {
	env := prepareEnv(t)
	ctx := context.Background()
	env.createUserWithNickname("Alice", "张三")
	env.createUserWithNickname("bob", "Alice小号")
	env.createUserWithNickname("carol", "100%_real")
	env.createUserWithNickname("dave", "o'brien [admin]")
	env.createUserWithNickname("erin", `path\seg`)
	env.createUserWithNickname("frank", "同名")
	env.createUserWithNickname("grace", "同名")

	// 大小写折叠：同时命中用户名 alice 与昵称“Alice小号”（默认字段=用户名+昵称）。
	got := env.searchUsers(account.ListRequest{Limit: 20, Search: "ALICE", Sort: account.SortUsername})
	assertExactly(t, "大小写", got, "Alice", "bob")
	// 全角输入按 NFKC 折到同一字面。
	got = env.searchUsers(account.ListRequest{Limit: 20, Search: "ＡＬＩＣＥ", Sort: account.SortUsername})
	assertExactly(t, "全角", got, "Alice", "bob")
	// 中文子串。
	assertExactly(t, "中文", env.searchUsers(account.ListRequest{Limit: 20, Search: "张三"}), "Alice")
	// 通配符按字面：`%` 只命中真的含 % 的昵称，不会命中全部用户。
	assertExactly(t, "百分号字面", env.searchUsers(account.ListRequest{Limit: 20, Search: "%"}), "carol")
	assertExactly(t, "下划线字面", env.searchUsers(account.ListRequest{Limit: 20, Search: "_"}), "carol")
	// 单引号、方括号、反斜杠都按字面输入，不破坏 SQL、不被当作模式。
	assertExactly(t, "单引号", env.searchUsers(account.ListRequest{Limit: 20, Search: "'"}), "dave")
	assertExactly(t, "方括号", env.searchUsers(account.ListRequest{Limit: 20, Search: "["}), "dave")
	assertExactly(t, "反斜杠", env.searchUsers(account.ListRequest{Limit: 20, Search: `\`}), "erin")
	// 显式字段白名单：只搜昵称不搜用户名，反之亦然。
	assertExactly(t, "只搜昵称", env.searchUsers(account.ListRequest{
		Limit: 20, Search: "alice", SearchFields: []account.UserSearchField{account.UserSearchNickname},
	}), "bob")
	assertExactly(t, "只搜用户名", env.searchUsers(account.ListRequest{
		Limit: 20, Search: "alice", SearchFields: []account.UserSearchField{account.UserSearchUsername},
	}), "Alice")
	// 空搜索保持原列表（字段白名单合法时也不启用过滤）。
	result, err := env.service.ListUsers(ctx, env.caller, account.ListRequest{
		Limit: 100, Search: "  ", SearchFields: account.DefaultUserSearchFields(),
	})
	if err != nil {
		t.Fatalf("空搜索失败: %v", err)
	}
	if len(result.Users) != 7 {
		t.Fatalf("空搜索结果数 = %d，期望全部 7 个", len(result.Users))
	}
	// 无匹配。
	if got := env.searchUsers(account.ListRequest{Limit: 20, Search: "不存在的人"}); len(got) != 0 {
		t.Fatalf("无匹配结果 = %v", got)
	}
	// 长度上限。
	if _, err := env.service.ListUsers(ctx, env.caller, account.ListRequest{
		Limit: 20, Search: strings.Repeat("a", search.MaxQueryRunes+1),
	}); !errors.Is(err, account.ErrInvalidRequest) {
		t.Fatalf("超长搜索错误 = %v，期望 ErrInvalidRequest", err)
	}
	// 邮箱/电话不在默认字段白名单，也不能显式请求（需要独立字段可见权限）。
	if _, err := env.service.ListUsers(ctx, env.caller, account.ListRequest{
		Limit: 20, Search: "a@example.com",
		SearchFields: []account.UserSearchField{account.UserSearchField("email")},
	}); !errors.Is(err, account.ErrInvalidRequest) {
		t.Fatalf("邮箱搜索字段错误 = %v，期望 ErrInvalidRequest", err)
	}
	if _, err := env.service.ListUsers(ctx, env.caller, account.ListRequest{
		Limit: 20, Search: "13800000000",
		SearchFields: []account.UserSearchField{account.UserSearchField("phone")},
	}); !errors.Is(err, account.ErrInvalidRequest) {
		t.Fatalf("电话搜索字段错误 = %v，期望 ErrInvalidRequest", err)
	}

	// 同名昵称稳定排序 + offset 分页不重复：按用户名排序，两页拼起来恰为两人。
	first, err := env.service.ListUsers(ctx, env.caller, account.ListRequest{
		Limit: 1, Search: "同名", Sort: account.SortUsername})
	if err != nil {
		t.Fatalf("同名搜索第一页失败: %v", err)
	}
	second, err := env.service.ListUsers(ctx, env.caller, account.ListRequest{
		Limit: 1, Offset: 1, Search: "同名", Sort: account.SortUsername})
	if err != nil {
		t.Fatalf("同名搜索第二页失败: %v", err)
	}
	if len(first.Users) != 1 || len(second.Users) != 1 || !first.HasMore || second.HasMore {
		t.Fatalf("同名分页 = %v(h=%v) / %v(h=%v)", usernamesOf(first.Users), first.HasMore,
			usernamesOf(second.Users), second.HasMore)
	}
	if first.Users[0].ID == second.Users[0].ID {
		t.Fatal("同名分页出现重复记录")
	}
	combined := append(append([]account.User{}, first.Users...), second.Users...)
	assertExactly(t, "同名排序", usernamesOf(combined), "frank", "grace")

	// 搜索与状态过滤组合：禁用 carol 后 status=disabled 才命中。
	carol, err := env.service.GetUserByUsername(ctx, env.caller, "carol")
	if err != nil {
		t.Fatalf("读取 carol 失败: %v", err)
	}
	if _, err := env.service.DisableUser(ctx, env.caller, account.StateCommandRequest{
		UserID: carol.ID, ExpectedRowVersion: carol.RowVersion,
	}); err != nil {
		t.Fatalf("禁用 carol 失败: %v", err)
	}
	assertExactly(t, "搜索+状态", env.searchUsers(account.ListRequest{
		Limit: 20, Search: "carol", Status: account.StatusDisabled,
	}), "carol")
	if active := env.searchUsers(account.ListRequest{
		Limit: 20, Search: "carol", Status: account.StatusActive,
	}); len(active) != 0 {
		t.Fatalf("搜索+状态不应命中 active: %v", active)
	}

	// 精确查询语义不变：模糊匹配不参与登录/唯一身份判定。
	if _, err := env.service.GetUserByUsername(ctx, env.caller, "ali"); !errors.Is(err, account.ErrUserNotFound) {
		t.Fatalf("GetUserByUsername(ali) 错误 = %v，期望 ErrUserNotFound（必须保持精确）", err)
	}
	if _, err := env.service.GetUserByUsername(ctx, env.caller, "ALICE"); err != nil {
		t.Fatalf("GetUserByUsername 精确匹配大小写折叠失败: %v", err)
	}
}

// TestListUsersSearchInvalidFields 验收字段白名单与类型校验：未知字段与非法搜索
// 文本都返回 REQ_INVALID，不静默回退到默认字段。
func TestListUsersSearchInvalidFields(t *testing.T) {
	env := prepareEnv(t)
	ctx := context.Background()
	env.createUserWithNickname("alice", "张三")

	cases := []struct {
		name    string
		request account.ListRequest
	}{
		{name: "未知字段", request: account.ListRequest{Limit: 20, Search: "x",
			SearchFields: []account.UserSearchField{"password_hash"}}},
		{name: "邮箱字段", request: account.ListRequest{Limit: 20, Search: "x",
			SearchFields: []account.UserSearchField{account.UserSearchField("email")}}},
		{name: "控制字符", request: account.ListRequest{Limit: 20, Search: "a\x00b"}},
		{name: "换行", request: account.ListRequest{Limit: 20, Search: "a\nb"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := env.service.ListUsers(ctx, env.caller, testCase.request)
			if !errors.Is(err, account.ErrInvalidRequest) {
				t.Fatalf("错误 = %v，期望 ErrInvalidRequest", err)
			}
			if code := account.CodeOf(err); code != account.CodeReqInvalid {
				t.Fatalf("错误码 = %v，期望 REQ_INVALID", code)
			}
		})
	}
	// 重复字段去重后正常执行，不产生重复 LIKE 或错误。
	result, err := env.service.ListUsers(ctx, env.caller, account.ListRequest{
		Limit: 20, Search: "alice",
		SearchFields: []account.UserSearchField{account.UserSearchUsername,
			account.UserSearchUsername, account.UserSearchNickname},
	})
	if err != nil {
		t.Fatalf("重复字段应去重而非报错: %v", err)
	}
	if len(result.Users) != 1 || result.Users[0].Username != "alice" {
		t.Fatalf("重复字段搜索结果 = %v", usernamesOf(result.Users))
	}
}
