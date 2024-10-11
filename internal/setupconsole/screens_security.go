package setupconsole

// 步骤 288：本地 MFA 清除与受限重绑恢复画面。
//
// 依赖领域本地窄方法（totp/mfa/passkey/recovery/session）：未接入前服务适配器返回
// ErrLocalUnsupported，画面明确显示不可用并 fail-closed；不会假装清除成功。
// UI 流程：用户列表（稳定 UserID）→ 目标操作页 → 因素列表/会话列表/危险清除确认。

import (
	"context"
	"fmt"
)

const ws3SecurityScreenID = "ws3.security"

type ws3SecurityScreen struct {
	ws3ScreenBase
	page     LocalUserPage
	query    LocalUserQuery
	cursor   int
	selected LocalUser
	mode     string // ""=list, "actions", "factors", "sessions", "confirm"
	factors  []LocalFactor
	sessions []LocalSession
	confirm  *ws3ConfirmAction
	loaded   bool
}

func newWS3SecurityScreen(open WS3SessionOpener) ScreenController {
	screen := &ws3SecurityScreen{ws3ScreenBase: ws3ScreenBase{open: open}}
	screen.query = LocalUserQuery{PageRequest: LocalPageRequest{Limit: 10}}
	return screen
}

func (s *ws3SecurityScreen) Title() string {
	return "本地维护 · MFA 清除与受限重绑（root 救援）"
}

func (s *ws3SecurityScreen) Render(ctx context.Context, canvas *Canvas, session SessionView) {
	_ = session
	if s.services == nil {
		if err := s.ensureSession(ctx); err != nil {
			_, top, width, _ := ws3CanvasArea(canvas)
			top = ws3DrawMessage(canvas, top, width, "不可用：", s.errText)
			top++
			canvas.Text(2, top, "Esc 返回主菜单。")
			return
		}
	}
	if !s.loaded && s.mode == "" {
		s.loadUsers(ctx)
	}
	_, top, width, height := ws3CanvasArea(canvas)
	switch s.mode {
	case "confirm":
		if s.confirm != nil {
			ws3RenderConfirm(canvas, top, width, s.confirm.title, s.confirm.details)
		}
	case "factors":
		s.renderFactors(canvas, top, width, height)
	case "sessions":
		s.renderSessions(canvas, top, width, height)
	case "actions":
		s.renderActions(canvas, top, width)
	default:
		s.renderList(canvas, top, width, height)
	}
}

func (s *ws3SecurityScreen) renderList(canvas *Canvas, top, width, height int) {
	top = ws3DrawStatus(&s.ws3ScreenBase, canvas, top, width)
	canvas.Text(2, top, "选择用户（Enter 进入 MFA/会话维护）")
	top += 2
	if len(s.page.Users) == 0 {
		canvas.Text(2, top, "没有可维护用户（r=刷新）。")
		return
	}
	visible := maxInt(height-(top-ws3CanvasAreaTop(canvas)), 1)
	start := 0
	if s.cursor >= visible {
		start = s.cursor - visible + 1
	}
	for index := start; index < len(s.page.Users) && index < start+visible; index++ {
		user := s.page.Users[index]
		marker := "  "
		if index == s.cursor {
			marker = "> "
		}
		canvas.Text(2, top, ws3Truncate(fmt.Sprintf("%s%s（%s）", marker,
			user.Username, user.ID), width))
		top++
	}
}

func (s *ws3SecurityScreen) renderActions(canvas *Canvas, top, width int) {
	top = ws3DrawStatus(&s.ws3ScreenBase, canvas, top, width)
	canvas.Text(2, top, "目标："+s.selected.Username+"（稳定 ID "+s.selected.ID+"）")
	top += 2
	if s.selected.IsRoot {
		canvas.Text(2, top, "root 救援：可清除因素/撤销会话后按安全策略受限重绑。")
		top++
	}
	canvas.Text(2, top, "f=因素列表  s=会话列表  x=撤销恢复代码  c=清除全部第二因素  v=强制下线  Esc=返回")
}

func (s *ws3SecurityScreen) renderFactors(canvas *Canvas, top, width, height int) {
	top = ws3DrawStatus(&s.ws3ScreenBase, canvas, top, width)
	canvas.Text(2, top, "因素列表（f 刷新，Esc 返回；当前不支持删除时显示原因）")
	top += 2
	if len(s.factors) == 0 {
		canvas.Text(2, top, "没有列出因素（或该能力当前不可用）。")
		return
	}
	visible := maxInt(height-(top-ws3CanvasAreaTop(canvas)), 1)
	for index, factor := range s.factors {
		if index >= visible {
			break
		}
		primary := ""
		if factor.Primary {
			primary = " [主登录]"
		}
		canvas.Text(2, top, ws3Truncate(fmt.Sprintf("%d%s%s  ID=%s", index+1,
			factor.Kind, primary, factor.ID), width))
		top++
	}
}

func (s *ws3SecurityScreen) renderSessions(canvas *Canvas, top, width, height int) {
	top = ws3DrawStatus(&s.ws3ScreenBase, canvas, top, width)
	canvas.Text(2, top, "会话列表（只读摘要；Esc 返回）")
	top += 2
	if len(s.sessions) == 0 {
		canvas.Text(2, top, "没有列出会话（或该能力当前不可用）。")
		return
	}
	visible := maxInt(height-(top-ws3CanvasAreaTop(canvas)), 1)
	for index, item := range s.sessions {
		if index >= visible {
			break
		}
		canvas.Text(2, top, ws3Truncate(fmt.Sprintf("%d %s %s %s", index+1,
			item.Kind, item.CreatedAt.UTC().Format("2006-01-02T15:04Z"), item.ID), width))
		top++
	}
}

func (s *ws3SecurityScreen) HandleKey(ctx context.Context, key Key,
	session SessionView) (bool, error) {
	_ = session
	if s.services == nil {
		if err := s.ensureSession(ctx); err != nil {
			if key.Kind == KeyEsc || key.Kind == KeyCtrlC {
				s.closeSession()
				return true, nil
			}
			return false, nil
		}
		if s.mode == "" && len(s.page.Users) == 0 {
			s.loadUsers(ctx)
		}
		return false, nil
	}
	switch s.mode {
	case "confirm":
		return s.handleConfirmKey(ctx, key)
	case "factors":
		if key.Kind == KeyEsc {
			s.mode = "actions"
		} else if key.Kind == KeyRune && (key.Rune == 'f' || key.Rune == 'F') {
			s.loadFactors(ctx)
		}
	case "sessions":
		if key.Kind == KeyEsc {
			s.mode = "actions"
		} else if key.Kind == KeyRune && (key.Rune == 's' || key.Rune == 'S') {
			s.loadSessions(ctx)
		}
	case "actions":
		return s.handleActionsKey(ctx, key)
	default:
		return s.handleListKey(ctx, key)
	}
	return false, nil
}

func (s *ws3SecurityScreen) loadUsers(ctx context.Context) {
	if s.services == nil || s.services.Users == nil {
		s.setError(ErrLocalUnsupported)
		return
	}
	page, err := s.services.Users.ListUsers(ctx, s.query)
	if err != nil {
		s.setError(err)
		return
	}
	s.page = page
	s.loaded = true
	if s.cursor >= len(page.Users) {
		s.cursor = maxInt(0, len(page.Users)-1)
	}
}

func (s *ws3SecurityScreen) handleListKey(ctx context.Context, key Key) (bool, error) {
	switch key.Kind {
	case KeyEsc, KeyCtrlC:
		s.closeSession()
		return true, nil
	case KeyUp:
		if s.cursor > 0 {
			s.cursor--
		}
	case KeyDown:
		if s.cursor < len(s.page.Users)-1 {
			s.cursor++
		}
	case KeyPageDown:
		if s.page.Pagination.HasMore {
			s.query.PageRequest.Offset += s.query.PageRequest.Limit
			s.cursor = 0
			s.loadUsers(ctx)
		}
	case KeyPageUp:
		if s.query.PageRequest.Offset > 0 {
			s.query.PageRequest.Offset = maxInt(0,
				s.query.PageRequest.Offset-s.query.PageRequest.Limit)
			s.cursor = 0
			s.loadUsers(ctx)
		}
	case KeyEnter:
		if s.cursor >= 0 && s.cursor < len(s.page.Users) {
			s.selected = s.page.Users[s.cursor]
			s.mode = "actions"
			s.setStatus("按稳定 UserID 绑定：" + s.selected.ID)
		}
	case KeyRune:
		if key.Rune == 'r' || key.Rune == 'R' {
			s.loadUsers(ctx)
		}
	}
	return false, nil
}

func (s *ws3SecurityScreen) handleActionsKey(ctx context.Context, key Key) (bool, error) {
	switch key.Kind {
	case KeyEsc:
		s.mode = ""
	case KeyCtrlC:
		s.closeSession()
		return true, nil
	case KeyRune:
		switch key.Rune {
		case 'f', 'F':
			s.loadFactors(ctx)
			s.mode = "factors"
		case 's', 'S':
			s.loadSessions(ctx)
			s.mode = "sessions"
		case 'x', 'X':
			s.confirm = &ws3ConfirmAction{title: "撤销目标用户全部恢复代码",
				details: []string{"目标：" + s.selected.Username + "（" + s.selected.ID + "）", "恢复代码撤销后需重新生成；不会解除密码或 TOTP。"},
				execute: func(ctx context.Context) (string, error) {
					return "", s.securityAction(func() error {
						return s.services.Security.RevokeRecoveryCodes(ctx, s.selected.ID, "本地维护撤销恢复代码")
					}, "恢复代码已撤销")
				}}
			s.mode = "confirm"
		case 'c', 'C':
			target := s.selected
			s.confirm = &ws3ConfirmAction{title: "清除全部第二因素（不含主登录 Passkey，除非另行显式选择）",
				details: []string{"目标：" + target.Username + "（" + target.ID + "）",
					"清除后旧挑战/会话/恢复授权按领域可靠边界失效；root 救援后下一次远程登录按安全策略受限重绑。",
					"主登录 Passkey 默认保留；需要删除时逐项选择。"},
				execute: func(ctx context.Context) (string, error) {
					return "", s.securityAction(func() error {
						return s.services.Security.ClearSecondFactors(ctx, target.ID, false, "本地维护清除第二因素")
					}, "第二因素已清除（主登录 Passkey 保留）")
				}}
			s.mode = "confirm"
		case 'v', 'V':
			target := s.selected
			s.confirm = &ws3ConfirmAction{title: "强制目标用户下线",
				details: []string{"目标：" + target.Username + "（" + target.ID + "）",
					"复用既有系统撤销路径；会话失效不等于清除 MFA。"},
				execute: func(ctx context.Context) (string, error) {
					if s.services.Security == nil {
						return "", ErrLocalUnsupported
					}
					count, err := s.services.Security.RevokeSessions(ctx, target.ID, "本地维护强制下线")
					if err != nil {
						return "", err
					}
					return fmt.Sprintf("已撤销会话数量：%d", count), nil
				}}
			s.mode = "confirm"
		}
	}
	return false, nil
}

func (s *ws3SecurityScreen) securityAction(action func() error, success string) error {
	if s.services.Security == nil {
		return ErrLocalUnsupported
	}
	if err := action(); err != nil {
		return err
	}
	s.setStatus(success)
	return nil
}

func (s *ws3SecurityScreen) loadFactors(ctx context.Context) {
	if s.services.Security == nil {
		s.setError(ErrLocalUnsupported)
		return
	}
	factors, err := s.services.Security.ListFactors(ctx, s.selected.ID)
	if err != nil {
		s.setError(err)
		return
	}
	s.factors = factors
	s.setStatus(fmt.Sprintf("因素数量：%d", len(factors)))
}

func (s *ws3SecurityScreen) loadSessions(ctx context.Context) {
	if s.services.Security == nil {
		s.setError(ErrLocalUnsupported)
		return
	}
	sessions, hasMore, err := s.services.Security.ListSessions(ctx, s.selected.ID, 20, 0)
	if err != nil {
		s.setError(err)
		return
	}
	s.sessions = sessions
	if hasMore {
		s.setStatus(fmt.Sprintf("会话数量：%d+（还有更多）", len(sessions)))
	} else {
		s.setStatus(fmt.Sprintf("会话数量：%d", len(sessions)))
	}
}

func (s *ws3SecurityScreen) handleConfirmKey(ctx context.Context, key Key) (bool, error) {
	if s.confirm == nil {
		s.mode = "actions"
		return false, nil
	}
	switch key.Kind {
	case KeyEsc:
		s.confirm = nil
		s.mode = "actions"
	case KeyCtrlC:
		s.closeSession()
		return true, nil
	case KeyEnter:
		action := s.confirm
		s.confirm = nil
		message, err := action.execute(ctx)
		s.mode = "actions"
		if err != nil {
			s.setError(err)
			return false, nil
		}
		if message != "" {
			s.setStatus(message)
		}
	}
	return false, nil
}
