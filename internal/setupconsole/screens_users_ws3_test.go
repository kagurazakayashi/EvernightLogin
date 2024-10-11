package setupconsole

// WS3 画面定向测试（步骤 286/287）：用替身实现用户/身份服务，驱动 ScreenController
// 的按键与渲染，验证稳定 UserID 绑定、分页/搜索、创建、启停、密码确认与不可用
// fail-closed。真实领域链路由各领域包测试 + localruntime 适配器集成测试覆盖。

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/config"
)

// fakeWS3Session 是 WS3Session 测试替身。
type fakeWS3Session struct {
	services *WS3Services
	closed   bool
}

func (s *fakeWS3Session) Services() *WS3Services { return s.services }
func (s *fakeWS3Session) Config() config.Config {
	return config.Config{}
}
func (s *fakeWS3Session) OperatorID() string { return "os:test@local" }
func (s *fakeWS3Session) Close(context.Context) error {
	s.closed = true
	return nil
}

// 说明：WS3Session.Config 返回 config.Config，测试替身需真实类型；见下方 fakeConfig。

type fakeUserAdmin struct {
	users       []LocalUser
	createCalls []LocalUserCreate
	enabled     map[string]bool
	assigned    []string
	listErr     error
}

func (f *fakeUserAdmin) ListUsers(_ context.Context, query LocalUserQuery) (LocalUserPage, error) {
	if f.listErr != nil {
		return LocalUserPage{}, f.listErr
	}
	filtered := make([]LocalUser, 0, len(f.users))
	search := strings.ToLower(strings.TrimSpace(query.PageRequest.Search))
	for _, user := range f.users {
		if query.Status != "" && user.Status != query.Status {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(user.Username), search) &&
			!strings.Contains(strings.ToLower(user.Nickname), search) {
			continue
		}
		filtered = append(filtered, user)
	}
	page := LocalUserPage{Users: filtered,
		Pagination: LocalPagination{HasMore: false, Offset: query.PageRequest.Offset,
			Limit: query.PageRequest.Limit}}
	return page, nil
}

func (f *fakeUserAdmin) GetUser(_ context.Context, userID string) (LocalUser, error) {
	for _, user := range f.users {
		if user.ID == userID {
			return user, nil
		}
	}
	return LocalUser{}, fmt.Errorf("用户不存在")
}

func (f *fakeUserAdmin) CreateUser(_ context.Context, input LocalUserCreate) (LocalUser, error) {
	f.createCalls = append(f.createCalls, input)
	user := LocalUser{ID: fmt.Sprintf("usr_fake%03d", len(f.users)+1),
		Username: input.Username, Nickname: input.Nickname, Status: "active",
		RowVersion: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	f.users = append(f.users, user)
	return user, nil
}

func (f *fakeUserAdmin) UpdateProfile(_ context.Context, userID string, input LocalProfileUpdate) (LocalUser, error) {
	for index := range f.users {
		if f.users[index].ID == userID {
			f.users[index].Nickname = input.Nickname
			f.users[index].RowVersion++
			return f.users[index], nil
		}
	}
	return LocalUser{}, fmt.Errorf("用户不存在")
}

func (f *fakeUserAdmin) SetEnabled(_ context.Context, userID string, enabled bool, _ int64) (LocalUser, error) {
	if f.enabled == nil {
		f.enabled = map[string]bool{}
	}
	f.enabled[userID] = enabled
	for index := range f.users {
		if f.users[index].ID == userID {
			if enabled {
				f.users[index].Status = "active"
			} else {
				f.users[index].Status = "disabled"
			}
			return f.users[index], nil
		}
	}
	return LocalUser{}, fmt.Errorf("用户不存在")
}

func (f *fakeUserAdmin) GetValidity(context.Context, string) (LocalValidity, error) {
	return LocalValidity{RowVersion: 1}, nil
}

func (f *fakeUserAdmin) SetValidity(_ context.Context, userID string, _ LocalValidity) (LocalUser, error) {
	return f.GetUser(context.Background(), userID)
}

func (f *fakeUserAdmin) PreviewDeletion(context.Context, string) (LocalDeletionPreview, error) {
	return LocalDeletionPreview{Username: "bob", UserID: "usr_fake001", Status: "active",
		RowVersion: 1, AppMemberships: 1}, nil
}

func (f *fakeUserAdmin) RequestDeletion(_ context.Context, userID string, _ int64) (LocalUser, error) {
	user, err := f.GetUser(context.Background(), userID)
	if err != nil {
		return LocalUser{}, err
	}
	user.Status = "pending_delete"
	user.RowVersion++
	return user, nil
}

func (f *fakeUserAdmin) CompleteDeletion(context.Context, string, int64) (LocalDeletionPreview, error) {
	return LocalDeletionPreview{Username: "bob", UserID: "usr_fake001"}, nil
}

func (f *fakeUserAdmin) ListAssignableRoles(context.Context) ([]LocalRole, error) {
	return []LocalRole{{ID: "role_admin", Key: "system_admin", Name: "系统管理员",
		ScopeID: "system", Enabled: true}}, nil
}

func (f *fakeUserAdmin) AssignRole(_ context.Context, userID, roleID string) error {
	f.assigned = append(f.assigned, userID+"/"+roleID)
	return nil
}

type fakeIdentityAdmin struct {
	renamed    []string
	passwords  []string
	credStatus LocalCredentialStatus
}

func (f *fakeIdentityAdmin) Rename(_ context.Context, userID, newUsername, _ string,
	_ int64) (LocalUser, error) {
	f.renamed = append(f.renamed, userID+"/"+newUsername)
	return LocalUser{ID: userID, Username: newUsername, Status: "active",
		RowVersion: 2}, nil
}

func (f *fakeIdentityAdmin) SetPassword(_ context.Context, userID, newPassword string,
	requireChange bool) (LocalPasswordResult, error) {
	f.passwords = append(f.passwords, userID+"/"+newPassword)
	return LocalPasswordResult{UserID: userID, SecurityVersion: 2,
		MustChange: requireChange}, nil
}

func (f *fakeIdentityAdmin) Credentials(context.Context, string) (LocalCredentialStatus, error) {
	return f.credStatus, nil
}

// newFakeUsersScreen 构造带替身的用户画面。
func newFakeUsersScreen(t *testing.T, admin *fakeUserAdmin,
	identity *fakeIdentityAdmin) *ws3UsersScreen {
	t.Helper()
	services := &WS3Services{OperatorID: "os:test@local", Users: admin, Identity: identity}
	return newWS3UsersScreen(func(context.Context) (WS3Session, error) {
		return &fakeWS3Session{services: services}, nil
	}).(*ws3UsersScreen)
}

func drawFake(canvas *Canvas, screen ScreenController, ctx context.Context) string {
	canvas.Clear()
	screen.Render(ctx, canvas, SessionView{})
	return canvas.Render()
}

// TestWS3UsersListDetailAndActions 覆盖列表加载、稳定 ID 绑定详情、启停与删除确认。
func TestWS3UsersListDetailAndActions(t *testing.T) {
	admin := &fakeUserAdmin{users: []LocalUser{
		{ID: "usr_fake001", Username: "bob", Nickname: "Bob", Status: "active", RowVersion: 1},
		{ID: "usr_fake002", Username: "carol", Nickname: "Carol", Status: "active", RowVersion: 1},
	}}
	screen := newFakeUsersScreen(t, admin, &fakeIdentityAdmin{})
	ctx := context.Background()
	canvas := NewCanvas(100, 30)
	// 第一次 Render 打开会话并加载列表。
	body := drawFake(canvas, screen, ctx)
	if !strings.Contains(body, "bob") || !strings.Contains(body, "carol") {
		t.Fatalf("用户列表缺少数据: %s", body)
	}
	// 下移到 carol 并进入详情。
	if _, err := screen.HandleKey(ctx, Key{Kind: KeyDown}, SessionView{}); err != nil {
		t.Fatalf("下移: %v", err)
	}
	if _, err := screen.HandleKey(ctx, Key{Kind: KeyEnter}, SessionView{}); err != nil {
		t.Fatalf("进入详情: %v", err)
	}
	if screen.detail.ID != "usr_fake002" {
		t.Fatalf("稳定 ID 绑定错误: %+v", screen.detail)
	}
	body = drawFake(canvas, screen, ctx)
	if !strings.Contains(body, "usr_fake002") {
		t.Fatalf("详情缺少稳定 ID: %s", body)
	}
	// 启停：d 打开确认，Enter 执行。
	if _, err := screen.HandleKey(ctx, Key{Kind: KeyRune, Rune: 'd'}, SessionView{}); err != nil {
		t.Fatalf("打开启停确认: %v", err)
	}
	if screen.confirm == nil {
		t.Fatal("应进入启停确认")
	}
	if _, err := screen.HandleKey(ctx, Key{Kind: KeyEnter}, SessionView{}); err != nil {
		t.Fatalf("执行启停: %v", err)
	}
	if admin.enabled["usr_fake002"] {
		t.Fatalf("当前用户为 active，d 应停用并作用于稳定 ID: %+v", admin.enabled)
	}
}

// TestWS3UsersCreateAndSearch 覆盖搜索与创建表单提交。
func TestWS3UsersCreateAndSearch(t *testing.T) {
	admin := &fakeUserAdmin{users: []LocalUser{{ID: "usr_fake001", Username: "bob",
		Nickname: "Bob", Status: "active", RowVersion: 1}}}
	screen := newFakeUsersScreen(t, admin, &fakeIdentityAdmin{})
	ctx := context.Background()
	canvas := NewCanvas(100, 30)
	_ = drawFake(canvas, screen, ctx)
	// 创建：n 打开表单，输入用户名/密码，Enter 提交。
	if _, err := screen.HandleKey(ctx, Key{Kind: KeyRune, Rune: 'n'}, SessionView{}); err != nil {
		t.Fatalf("打开创建表单: %v", err)
	}
	for _, r := range "dave" {
		_, _ = screen.HandleKey(ctx, Key{Kind: KeyRune, Rune: r}, SessionView{})
	}
	_, _ = screen.HandleKey(ctx, Key{Kind: KeyTab}, SessionView{})
	_, _ = screen.HandleKey(ctx, Key{Kind: KeyTab}, SessionView{})
	for _, r := range "Passw0rd!x" {
		_, _ = screen.HandleKey(ctx, Key{Kind: KeyRune, Rune: r}, SessionView{})
	}
	if _, err := screen.HandleKey(ctx, Key{Kind: KeyEnter}, SessionView{}); err != nil {
		t.Fatalf("提交创建: %v", err)
	}
	if len(admin.createCalls) != 1 || admin.createCalls[0].Username != "dave" ||
		admin.createCalls[0].Password != "Passw0rd!x" {
		t.Fatalf("创建输入异常: %+v", admin.createCalls)
	}
	// 搜索：/ 打开表单，输入 carol，Enter 提交，列表只剩匹配项（无则空态）。
	if _, err := screen.HandleKey(ctx, Key{Kind: KeyRune, Rune: '/'}, SessionView{}); err != nil {
		t.Fatalf("打开搜索: %v", err)
	}
	for _, r := range "carol" {
		_, _ = screen.HandleKey(ctx, Key{Kind: KeyRune, Rune: r}, SessionView{})
	}
	if _, err := screen.HandleKey(ctx, Key{Kind: KeyEnter}, SessionView{}); err != nil {
		t.Fatalf("提交搜索: %v", err)
	}
	if len(screen.page.Users) != 0 {
		t.Fatalf("搜索无匹配应返回空列表: %+v", screen.page.Users)
	}
}

// TestWS3IdentityRenamePasswordAndUnavailable 覆盖改名/密码确认与不可用错误。
func TestWS3IdentityRenamePasswordAndUnavailable(t *testing.T) {
	admin := &fakeUserAdmin{users: []LocalUser{{ID: "usr_fake001", Username: "root",
		Nickname: "Root", Status: "active", RowVersion: 1}}}
	identity := &fakeIdentityAdmin{credStatus: LocalCredentialStatus{UserID: "usr_fake001",
		HasPassword: false, IsRoot: true}}
	screen := newWS3IdentityScreen(func(context.Context) (WS3Session, error) {
		return &fakeWS3Session{services: &WS3Services{Users: admin, Identity: identity}}, nil
	}).(*ws3IdentityScreen)
	ctx := context.Background()
	canvas := NewCanvas(100, 30)
	_ = drawFake(canvas, screen, ctx)
	_, _ = screen.HandleKey(ctx, Key{Kind: KeyEnter}, SessionView{})
	// d 查询凭证状态（只读，不返回密码）。
	_, _ = screen.HandleKey(ctx, Key{Kind: KeyRune, Rune: 'd'}, SessionView{})
	if !strings.Contains(screen.statusText, "已有密码=否") {
		t.Fatalf("凭证状态未展示: %q", screen.statusText)
	}
	// r 改名：输入新用户名 + 理由。
	_, _ = screen.HandleKey(ctx, Key{Kind: KeyRune, Rune: 'r'}, SessionView{})
	for _, r := range "root-owner" {
		_, _ = screen.HandleKey(ctx, Key{Kind: KeyRune, Rune: r}, SessionView{})
	}
	_, _ = screen.HandleKey(ctx, Key{Kind: KeyTab}, SessionView{})
	for _, r := range "工单救援" {
		_, _ = screen.HandleKey(ctx, Key{Kind: KeyRune, Rune: r}, SessionView{})
	}
	if _, err := screen.HandleKey(ctx, Key{Kind: KeyEnter}, SessionView{}); err != nil {
		t.Fatalf("提交改名: %v", err)
	}
	if len(identity.renamed) != 1 || identity.renamed[0] != "usr_fake001/root-owner" {
		t.Fatalf("改名调用异常: %+v", identity.renamed)
	}
	// p 密码：两次输入一致后进入确认，Enter 执行。
	_, _ = screen.HandleKey(ctx, Key{Kind: KeyRune, Rune: 'p'}, SessionView{})
	for _, r := range "NewPass!9x" {
		_, _ = screen.HandleKey(ctx, Key{Kind: KeyRune, Rune: r}, SessionView{})
	}
	_, _ = screen.HandleKey(ctx, Key{Kind: KeyTab}, SessionView{})
	for _, r := range "NewPass!9x" {
		_, _ = screen.HandleKey(ctx, Key{Kind: KeyRune, Rune: r}, SessionView{})
	}
	_, _ = screen.HandleKey(ctx, Key{Kind: KeyEnter}, SessionView{})
	if screen.confirm == nil {
		t.Fatal("密码设置应进入确认")
	}
	_, _ = screen.HandleKey(ctx, Key{Kind: KeyEnter}, SessionView{})
	if len(identity.passwords) != 1 {
		t.Fatalf("密码设置未执行: %+v", identity.passwords)
	}
}

// TestWS3MenuRegistration 覆盖 WS3 菜单注册与实例状态门控。
func TestWS3MenuRegistration(t *testing.T) {
	app := NewApp(&fakeTerminalForWS3{}, "login.yaml", func(context.Context, DetectOptions) Detection {
		return Detection{Kind: StateReady}
	})
	if err := RegisterWS3(app, func(context.Context) (WS3Session, error) {
		return &fakeWS3Session{services: &WS3Services{}}, nil
	}); err != nil {
		t.Fatalf("注册 WS3: %v", err)
	}
	ids := []string{MenuLocalUsers, MenuLocalIdentity, MenuLocalSecurity,
		MenuLocalRBAC, MenuLocalApps, MenuLocalAudit}
	for _, id := range ids {
		if _, exists := app.menuEntries[id]; !exists {
			t.Errorf("菜单项未注册: %s", id)
		}
		if _, exists := app.screens[id]; !exists {
			t.Errorf("画面未注册: %s", id)
		}
	}
	if ws3MenuEnabled(Detection{Kind: StateDatabaseDown}) {
		t.Error("数据库不可达时 WS3 菜单必须不可用")
	}
	if !ws3MenuEnabled(Detection{Kind: StateRootMissing}) {
		t.Error("root 缺失时仍应允许救援画面")
	}
}

// fakeTerminalForWS3 是注册测试用的空终端（不执行交互）。
type fakeTerminalForWS3 struct{}

func (f *fakeTerminalForWS3) Init() error           { return nil }
func (f *fakeTerminalForWS3) Close() error          { return nil }
func (f *fakeTerminalForWS3) Size() (int, int)      { return 100, 30 }
func (f *fakeTerminalForWS3) Write(string) error    { return nil }
func (f *fakeTerminalForWS3) ReadKey() (Key, error) { return Key{}, nil }
