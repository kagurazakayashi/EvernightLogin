package setupconsole

// 步骤 290：本地应用/成员/凭证/会话维护画面。
//
// 复用既有应用领域服务；应用 ID 创建后不变；客户端秘密只在创建/轮换时一次展示，
// 不写入本地状态。应用 CRUD/启停/成员增删与 OAuth 客户端登记/轮换/撤销均已接入
// 显式 LocalMaintenance 窄方法；维护锁与维护日志由 WS3 写门装饰器统一保证。

import (
	"context"
	"fmt"
	"strings"
)

const ws3AppsScreenID = "ws3.apps"

type ws3AppsScreen struct {
	ws3ScreenBase
	page     []LocalApplication
	hasMore  bool
	query    LocalPageRequest
	cursor   int
	detail   LocalApplication
	mode     string // ""=list "detail" "members" "clients" "form"
	members  []LocalAppMember
	clients  []LocalAppClient
	form     *ws3FormState
	formKind string
	confirm  *ws3ConfirmAction
	loaded   bool
}

func newWS3AppsScreen(open WS3SessionOpener) ScreenController {
	return &ws3AppsScreen{ws3ScreenBase: ws3ScreenBase{open: open},
		query: LocalPageRequest{Limit: 10}}
}

func (s *ws3AppsScreen) Title() string { return "本地维护 · 应用/成员/凭证/会话" }

func (s *ws3AppsScreen) Render(ctx context.Context, canvas *Canvas, session SessionView) {
	_ = session
	if s.services == nil {
		if err := s.ensureSession(ctx); err != nil {
			_, top, width, _ := ws3CanvasArea(canvas)
			top = ws3DrawMessage(canvas, top, width, "不可用：", s.errText)
			top++
			canvas.Text(2, top, "Esc 返回主菜单。")
			return
		}
		if len(s.page) == 0 {
			s.loadApps(ctx)
		}
	}
	_, top, width, height := ws3CanvasArea(canvas)
	if s.form != nil {
		s.form.draw(canvas, top, width)
		return
	}
	if s.confirm != nil {
		ws3RenderConfirm(canvas, top, width, s.confirm.title, s.confirm.details)
		return
	}
	top = ws3DrawStatus(&s.ws3ScreenBase, canvas, top, width)
	switch s.mode {
	case "detail":
		s.renderDetail(canvas, top, width)
	case "members":
		s.renderMembers(canvas, top, width, height)
	case "clients":
		s.renderClients(canvas, top, width, height)
	default:
		s.renderList(canvas, top, width, height)
	}
}

func (s *ws3AppsScreen) renderList(canvas *Canvas, top, width, height int) {
	canvas.Text(2, top, "应用列表（Enter=详情  n=新建  r=刷新  Esc=返回）")
	top += 2
	if len(s.page) == 0 {
		canvas.Text(2, top, "没有应用（r 刷新）。")
		return
	}
	visible := maxInt(height-(top-ws3CanvasAreaTop(canvas)), 1)
	start := 0
	if s.cursor >= visible {
		start = s.cursor - visible + 1
	}
	for index := start; index < len(s.page) && index < start+visible; index++ {
		app := s.page[index]
		marker := "  "
		if index == s.cursor {
			marker = "> "
		}
		canvas.Text(2, top, ws3Truncate(fmt.Sprintf("%s%s（%s，状态 %s）", marker,
			app.Name, app.ID, app.Status), width))
		top++
	}
}

func (s *ws3AppsScreen) renderDetail(canvas *Canvas, top, width int) {
	app := s.detail
	canvas.Text(2, top, "应用详情（Esc 返回列表）")
	top += 2
	for _, row := range [][2]string{
		{"应用 ID（不变）", app.ID}, {"名称", app.Name}, {"描述", app.Description},
		{"主页", app.Homepage}, {"负责人 UserID", app.OwnerUserID},
		{"状态", app.Status}, {"行版本", fmt.Sprint(app.RowVersion)},
	} {
		canvas.Text(2, top, ws3Truncate(row[0]+"："+row[1], width))
		top++
	}
	top++
	canvas.Text(2, top, "m=成员  c=OAuth 客户端凭证  e=改资料  d=启停  Esc=返回")
}

func (s *ws3AppsScreen) renderMembers(canvas *Canvas, top, width, height int) {
	canvas.Text(2, top, "应用成员（a 添加 / x 移除 / r 刷新 / Esc 返回）")
	top += 2
	if len(s.members) == 0 {
		canvas.Text(2, top, "没有成员（或该能力当前不可用）。")
		return
	}
	visible := maxInt(height-(top-ws3CanvasAreaTop(canvas)), 1)
	for index, member := range s.members {
		if index >= visible {
			break
		}
		canvas.Text(2, top, ws3Truncate(fmt.Sprintf("%s（%s，%s）", member.Username,
			member.UserID, member.Status), width))
		top++
	}
}

func (s *ws3AppsScreen) renderClients(canvas *Canvas, top, width, height int) {
	canvas.Text(2, top, "OAuth 客户端凭证（秘密只在创建/轮换时一次展示；Esc 返回）")
	top += 2
	if len(s.clients) == 0 {
		canvas.Text(2, top, "没有客户端（或该能力当前不可用）。")
		return
	}
	visible := maxInt(height-(top-ws3CanvasAreaTop(canvas)), 1)
	for index, client := range s.clients {
		if index >= visible {
			break
		}
		canvas.Text(2, top, ws3Truncate(fmt.Sprintf("%s（%s，%s）", client.Name,
			client.ClientID, client.Status), width))
		top++
	}
}

func (s *ws3AppsScreen) HandleKey(ctx context.Context, key Key, session SessionView) (bool, error) {
	_ = session
	if s.services == nil {
		if err := s.ensureSession(ctx); err != nil {
			if key.Kind == KeyEsc || key.Kind == KeyCtrlC {
				s.closeSession()
				return true, nil
			}
			return false, nil
		}
		if len(s.page) == 0 {
			s.loadApps(ctx)
		}
		return false, nil
	}
	if s.form != nil {
		return s.handleFormKey(ctx, key)
	}
	if s.confirm != nil {
		return s.handleConfirmKey(ctx, key)
	}
	switch s.mode {
	case "detail":
		return s.handleDetailKey(ctx, key)
	case "members":
		return s.handleMembersKey(ctx, key)
	case "clients":
		return s.handleClientsKey(ctx, key)
	default:
		return s.handleListKey(ctx, key)
	}
}

func (s *ws3AppsScreen) loadApps(ctx context.Context) {
	if s.services == nil || s.services.Apps == nil {
		s.setError(ErrLocalUnsupported)
		return
	}
	apps, hasMore, err := s.services.Apps.ListApplications(ctx, s.query)
	if err != nil {
		s.setError(err)
		return
	}
	s.page = apps
	s.hasMore = hasMore
	s.loaded = true
	if s.cursor >= len(apps) {
		s.cursor = maxInt(0, len(apps)-1)
	}
}

func (s *ws3AppsScreen) handleListKey(ctx context.Context, key Key) (bool, error) {
	switch key.Kind {
	case KeyEsc, KeyCtrlC:
		s.closeSession()
		return true, nil
	case KeyUp:
		if s.cursor > 0 {
			s.cursor--
		}
	case KeyDown:
		if s.cursor < len(s.page)-1 {
			s.cursor++
		}
	case KeyEnter:
		if s.cursor >= 0 && s.cursor < len(s.page) {
			s.selectedApplication(ctx, s.page[s.cursor].ID)
		}
	case KeyRune:
		switch key.Rune {
		case 'r', 'R':
			s.loadApps(ctx)
		case 'n', 'N':
			s.form = newWS3Form("新建应用（名称/描述/主页）",
				[]string{"名称", "描述", "主页"}, []bool{false, false, false},
				"Enter 提交 · Esc 取消；应用创建后 ID 不变。")
			s.formKind = "create-app"
		}
	}
	return false, nil
}

func (s *ws3AppsScreen) selectedApplication(ctx context.Context, applicationID string) {
	if s.services.Apps == nil {
		s.setError(ErrLocalUnsupported)
		return
	}
	app, err := s.services.Apps.GetApplication(ctx, applicationID)
	if err != nil {
		s.setError(err)
		return
	}
	s.detail = app
	s.mode = "detail"
	s.setStatus("当前作用范围：应用 " + app.ID + "（" + app.Name + "）")
}

func (s *ws3AppsScreen) handleDetailKey(ctx context.Context, key Key) (bool, error) {
	switch key.Kind {
	case KeyEsc:
		s.mode = ""
	case KeyCtrlC:
		s.closeSession()
		return true, nil
	case KeyRune:
		switch key.Rune {
		case 'm', 'M':
			s.loadMembers(ctx)
			s.mode = "members"
		case 'c', 'C':
			s.loadClients(ctx)
			s.mode = "clients"
		case 'e', 'E':
			s.form = newWS3Form("修改应用资料（名称/描述/主页）",
				[]string{"名称", "描述", "主页"}, []bool{false, false, false},
				"Enter 提交 · Esc 取消；应用 ID 不变。")
			s.form.setValue(0, s.detail.Name)
			s.form.setValue(1, s.detail.Description)
			s.form.setValue(2, s.detail.Homepage)
			s.formKind = "update-app"
		case 'd', 'D':
			s.setError(s.services.Apps.SetApplicationEnabled(ctx, s.detail.ID,
				s.detail.Status != "active"))
		}
	}
	return false, nil
}

func (s *ws3AppsScreen) handleMembersKey(ctx context.Context, key Key) (bool, error) {
	switch key.Kind {
	case KeyEsc:
		s.mode = "detail"
	case KeyCtrlC:
		s.closeSession()
		return true, nil
	case KeyRune:
		switch key.Rune {
		case 'a', 'A':
			s.form = newWS3Form("添加应用成员（目标用户稳定 ID / 应用内角色 ID）",
				[]string{"用户 ID", "应用内角色 ID（可空）"}, []bool{false, false},
				"Enter 提交 · Esc 取消")
			s.formKind = "add-member"
		case 'x', 'X':
			s.form = newWS3Form("移除应用成员（目标用户稳定 ID）",
				[]string{"用户 ID"}, []bool{false}, "Enter 提交 · Esc 取消")
			s.formKind = "remove-member"
		case 'r', 'R':
			s.loadMembers(ctx)
		}
	}
	return false, nil
}

// handleClientsKey 维护 OAuth 客户端凭证：n 登记、t 轮换、x 撤销、r 刷新。
func (s *ws3AppsScreen) handleClientsKey(ctx context.Context, key Key) (bool, error) {
	switch key.Kind {
	case KeyEsc:
		s.mode = "detail"
	case KeyCtrlC:
		s.closeSession()
		return true, nil
	case KeyRune:
		switch key.Rune {
		case 'n', 'N':
			s.form = newWS3Form("登记 OAuth 客户端（保密客户端；秘密只显示一次）",
				[]string{"重定向 URI（绝对 http(s) URL）"}, []bool{false},
				"Enter 提交 · Esc 取消；观众自动取重定向 URI 的来源。")
			s.formKind = "create-client"
		case 'r', 'R':
			s.loadClients(ctx)
		case 't', 'T':
			if len(s.clients) > 0 {
				client := s.clients[0]
				s.confirm = &ws3ConfirmAction{title: "轮换客户端密钥（旧密钥进入过渡期）",
					details: []string{"客户端：" + client.ClientID,
						"新密钥只在完成后显示一次；旧密钥在过渡期内仍可用。"},
					execute: func(ctx context.Context) (string, error) {
						created, err := s.services.Apps.RotateClientSecret(ctx,
							s.detail.ID, client.ClientID)
						if err != nil {
							return "", err
						}
						s.loadClients(ctx)
						return "客户端密钥（只显示一次）：" + created.Secret, nil
					}}
				s.mode = "confirm"
			}
		case 'x', 'X':
			if len(s.clients) > 0 {
				client := s.clients[0]
				s.confirm = &ws3ConfirmAction{title: "撤销客户端全部可用密钥",
					details: []string{"客户端：" + client.ClientID,
						"撤销后该客户端无法再用密钥认证；如仍需要请重新轮换。"},
					execute: func(ctx context.Context) (string, error) {
						if err := s.services.Apps.RevokeClient(ctx, s.detail.ID,
							client.ClientID); err != nil {
							return "", err
						}
						s.loadClients(ctx)
						return "客户端密钥已撤销", nil
					}}
				s.mode = "confirm"
			}
		}
	}
	return false, nil
}

// handleConfirmKey 处理客户端凭证危险操作确认。
func (s *ws3AppsScreen) handleConfirmKey(ctx context.Context, key Key) (bool, error) {
	if s.confirm == nil {
		s.mode = "detail"
		return false, nil
	}
	switch key.Kind {
	case KeyEsc:
		s.confirm = nil
		s.mode = "detail"
	case KeyCtrlC:
		s.closeSession()
		return true, nil
	case KeyEnter:
		action := s.confirm
		s.confirm = nil
		message, err := action.execute(ctx)
		s.mode = "detail"
		if err != nil {
			s.setError(err)
			return false, nil
		}
		s.setStatus(message)
	}
	return false, nil
}

func (s *ws3AppsScreen) loadMembers(ctx context.Context) {
	if s.services.Apps == nil {
		return
	}
	members, hasMore, err := s.services.Apps.ListMembers(ctx, s.detail.ID,
		LocalPageRequest{Limit: 20})
	if err != nil {
		s.setError(err)
		return
	}
	s.members = members
	if hasMore {
		s.setStatus("成员还有更多（当前仅展示前 20 条）")
	}
}

func (s *ws3AppsScreen) loadClients(ctx context.Context) {
	if s.services.Apps == nil {
		return
	}
	clients, err := s.services.Apps.ListClients(ctx, s.detail.ID)
	if err != nil {
		s.setError(err)
		return
	}
	s.clients = clients
}

func (s *ws3AppsScreen) handleFormKey(ctx context.Context, key Key) (bool, error) {
	submitted, cancelled := s.form.handleKey(key)
	if cancelled {
		s.form = nil
		return false, nil
	}
	if !submitted {
		return false, nil
	}
	switch s.formKind {
	case "create-app":
		app, err := s.services.Apps.CreateApplication(ctx, s.form.value(0),
			s.form.value(1), s.form.value(2))
		if err != nil {
			s.form.errText = ws3ErrorText(err)
			return false, nil
		}
		s.form = nil
		s.loadApps(ctx)
		s.setStatus("应用已创建：" + app.ID)
	case "update-app":
		app, err := s.services.Apps.UpdateApplication(ctx, s.detail.ID, s.form.value(0),
			s.form.value(1), s.form.value(2), s.detail.RowVersion)
		if err != nil {
			s.form.errText = ws3ErrorText(err)
			return false, nil
		}
		s.detail = app
		s.form = nil
		s.loadApps(ctx)
		s.setStatus("应用资料已更新")
	case "create-client":
		redirectURI := strings.TrimSpace(s.form.value(0))
		if redirectURI == "" {
			s.form.errText = "重定向 URI 不能为空"
			return false, nil
		}
		created, err := s.services.Apps.CreateClient(ctx, s.detail.ID,
			s.detail.Name+" OAuth 客户端", []string{redirectURI})
		if err != nil {
			s.form.errText = ws3ErrorText(err)
			return false, nil
		}
		s.form = nil
		s.formKind = ""
		s.loadClients(ctx)
		s.mode = "clients"
		s.setStatus("客户端密钥（只显示一次）：" + created.Secret)
		return false, nil
	case "add-member", "remove-member":
		var err error
		if s.formKind == "add-member" {
			err = s.services.Apps.AddMember(ctx, s.detail.ID, s.form.value(0))
		} else {
			err = s.services.Apps.RemoveMember(ctx, s.detail.ID, s.form.value(0))
		}
		if err != nil {
			s.form.errText = ws3ErrorText(err)
			return false, nil
		}
		s.form = nil
		s.loadMembers(ctx)
		s.setStatus("成员关系已更新")
	default:
		s.form.errText = "未知表单动作"
	}
	return false, nil
}
