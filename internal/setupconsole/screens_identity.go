package setupconsole

// 步骤 287：本地用户名与密码维护画面。
//
// 能力：
//   - 用户列表选择（稳定 UserID 绑定，翻页/搜索后动作仍作用于选中 ID）；
//   - 直接改名（含 root；root 走本地维护窄方法，普通用户走 256 直接管理路径）；
//     需要输入更换理由（进入审计），行版本冲突明确提示；
//   - 设置/重置密码（含 root、无密码账户）：新密码只经掩码输入，不回显、不记录；
//     默认要求目标下次登录改密（must_change）；确认框展示目标与影响。
//
// 本地维护身份无需目标旧密码/应用 MFA/审批；但仍执行领域密码策略、唯一性、行版本、
// 审计与会话失效语义。

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const ws3IdentityScreenID = "ws3.identity"

type ws3IdentityMode int

const (
	ws3IdentityList ws3IdentityMode = iota
	ws3IdentityActions
	ws3IdentityForm
	ws3IdentityConfirm
)

type ws3IdentityScreen struct {
	ws3ScreenBase
	mode     ws3IdentityMode
	page     LocalUserPage
	query    LocalUserQuery
	cursor   int
	selected LocalUser
	detail   LocalUser
	form     *ws3FormState
	formKind string
	confirm  *ws3ConfirmAction
	loaded   bool
}

func newWS3IdentityScreen(open WS3SessionOpener) ScreenController {
	screen := &ws3IdentityScreen{ws3ScreenBase: ws3ScreenBase{open: open}}
	screen.query = LocalUserQuery{PageRequest: LocalPageRequest{Limit: 10}}
	return screen
}

func (s *ws3IdentityScreen) Title() string { return "本地维护 · 用户名与密码（含 root）" }

func (s *ws3IdentityScreen) Render(ctx context.Context, canvas *Canvas, sessionView SessionView) {
	_ = sessionView
	if s.services == nil {
		if err := s.ensureSession(ctx); err != nil {
			_, top, width, _ := ws3CanvasArea(canvas)
			top = ws3DrawMessage(canvas, top, width, "不可用：", s.errText)
			top++
			canvas.Text(2, top, "Esc 返回主菜单。")
			return
		}
	}
	if !s.loaded && s.mode == ws3IdentityList {
		s.loadUsers(ctx)
	}
	_, top, width, height := ws3CanvasArea(canvas)
	switch s.mode {
	case ws3IdentityActions:
		s.renderActions(canvas, top, width, height)
	case ws3IdentityForm:
		s.form.draw(canvas, top, width)
	case ws3IdentityConfirm:
		if s.confirm != nil {
			ws3RenderConfirm(canvas, top, width, s.confirm.title, s.confirm.details)
		}
	default:
		s.renderList(canvas, top, width, height)
	}
}

func (s *ws3IdentityScreen) renderList(canvas *Canvas, top, width, height int) {
	top = ws3DrawStatus(&s.ws3ScreenBase, canvas, top, width)
	canvas.Text(2, top, "选择用户（Enter 进入维护；r=刷新  /=搜索  PgUp/PgDn=翻页）")
	top += 2
	if len(s.page.Users) == 0 {
		canvas.Text(2, top, "没有可维护用户。")
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
		rootMark := ""
		if user.IsRoot {
			rootMark = " [root]"
		}
		canvas.Text(2, top, ws3Truncate(fmt.Sprintf("%s%s%s（%s，状态 %s）",
			marker, user.Username, rootMark, user.ID, user.Status), width))
		top++
	}
}

func (s *ws3IdentityScreen) renderActions(canvas *Canvas, top, width, height int) {
	_ = height
	top = ws3DrawStatus(&s.ws3ScreenBase, canvas, top, width)
	user := s.detail
	canvas.Text(2, top, "维护目标："+user.Username+"（稳定 ID "+user.ID+"）")
	top++
	if user.IsRoot {
		canvas.Text(2, top, "目标为 root：本地维护可改名/设密，但稳定 root 身份不变。")
		top++
	}
	canvas.Text(2, top, "资料行版本："+fmt.Sprint(user.RowVersion)+
		"  安全版本："+fmt.Sprint(user.SecurityVersion))
	top += 2
	canvas.Text(2, top, "操作：r=直接改名  p=设置/重置密码  d=查看凭证状态  Esc=返回")
	_ = width
}

func (s *ws3IdentityScreen) HandleKey(ctx context.Context, key Key,
	sessionView SessionView) (bool, error) {
	_ = sessionView
	if s.services == nil {
		if err := s.ensureSession(ctx); err != nil {
			if key.Kind == KeyEsc || key.Kind == KeyCtrlC {
				s.closeSession()
				return true, nil
			}
			return false, nil
		}
		if s.mode == ws3IdentityList && len(s.page.Users) == 0 {
			s.loadUsers(ctx)
		}
		return false, nil
	}
	switch s.mode {
	case ws3IdentityForm:
		return s.handleFormKey(ctx, key)
	case ws3IdentityConfirm:
		return s.handleConfirmKey(ctx, key)
	case ws3IdentityActions:
		return s.handleActionsKey(ctx, key)
	default:
		return s.handleListKey(ctx, key)
	}
}

func (s *ws3IdentityScreen) loadUsers(ctx context.Context) {
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

func (s *ws3IdentityScreen) handleListKey(ctx context.Context, key Key) (bool, error) {
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
			s.detail = s.selected
			s.mode = ws3IdentityActions
			s.setStatus("按稳定 UserID 绑定当前操作目标：" + s.selected.ID)
		}
	case KeyRune:
		if key.Rune == 'r' || key.Rune == 'R' {
			s.query.PageRequest.Search = ""
			s.query.PageRequest.Offset = 0
			s.cursor = 0
			s.loadUsers(ctx)
		}
	}
	return false, nil
}

func (s *ws3IdentityScreen) handleActionsKey(ctx context.Context, key Key) (bool, error) {
	switch key.Kind {
	case KeyEsc:
		s.mode = ws3IdentityList
	case KeyCtrlC:
		s.closeSession()
		return true, nil
	case KeyRune:
		switch key.Rune {
		case 'r', 'R':
			s.openRenameForm()
		case 'p', 'P':
			s.openPasswordForm()
		case 'd', 'D':
			s.showCredentialStatus(ctx)
		}
	}
	return false, nil
}

func (s *ws3IdentityScreen) openRenameForm() {
	form := newWS3Form("直接改名（root 与普通用户均可；本地维护不需目标确认）",
		[]string{"新用户名", "更换理由（进入审计，必填）"}, []bool{false, false},
		"Enter 提交 · Esc 取消；仍校验保留名/唯一性/行版本。")
	s.form = form
	s.formKind = "rename"
	s.mode = ws3IdentityForm
	s.setStatus("")
}

func (s *ws3IdentityScreen) openPasswordForm() {
	form := newWS3Form("设置/重置密码（本地维护，无需旧密码/应用 MFA）",
		[]string{"新密码", "确认新密码", "要求下次登录改密（y/n）"}, []bool{true, true, false},
		"Enter 提交 · Esc 取消；密码只用于本次输入，不显示、不写日志。")
	form.setValue(2, "y")
	s.form = form
	s.formKind = "password"
	s.mode = ws3IdentityForm
	s.setStatus("")
}

func (s *ws3IdentityScreen) showCredentialStatus(ctx context.Context) {
	if s.services.Identity == nil {
		s.setError(ErrLocalUnsupported)
		return
	}
	status, err := s.services.Identity.Credentials(ctx, s.detail.ID)
	if err != nil {
		s.setError(err)
		return
	}
	hasPassword := "否"
	if status.HasPassword {
		hasPassword = "是（不可读回）"
	}
	s.setStatus(fmt.Sprintf("凭证状态：已有密码=%s；root=%v", hasPassword, status.IsRoot))
}

func (s *ws3IdentityScreen) handleFormKey(ctx context.Context, key Key) (bool, error) {
	if s.form == nil {
		s.mode = ws3IdentityActions
		return false, nil
	}
	submitted, cancelled := s.form.handleKey(key)
	if cancelled {
		s.form = nil
		s.formKind = ""
		s.mode = ws3IdentityActions
		return false, nil
	}
	if !submitted {
		return false, nil
	}
	if err := s.submitForm(ctx); err != nil {
		s.form.errText = ws3ErrorText(err)
	}
	return false, nil
}

func (s *ws3IdentityScreen) submitForm(ctx context.Context) error {
	if s.services.Identity == nil {
		return ErrLocalUnsupported
	}
	switch s.formKind {
	case "rename":
		newUsername := s.form.value(0)
		reason := s.form.value(1)
		if newUsername == "" {
			return fmt.Errorf("新用户名不能为空")
		}
		if reason == "" {
			return fmt.Errorf("更换理由不能为空（进入审计）")
		}
		user, err := s.services.Identity.Rename(ctx, s.detail.ID, newUsername,
			reason, s.detail.RowVersion)
		if err != nil {
			return err
		}
		s.detail = user
		s.selected = user
		s.refreshListUser(user)
		s.form = nil
		s.formKind = ""
		s.mode = ws3IdentityActions
		s.setStatus("已改名：" + user.Username + "（稳定 ID " + user.ID + "）")
		return nil
	case "password":
		password := s.form.value(0)
		if password == "" {
			return fmt.Errorf("新密码不能为空")
		}
		if password != s.form.value(1) {
			return fmt.Errorf("两次输入的新密码不一致")
		}
		requireChange := strings.EqualFold(s.form.value(2), "y") ||
			strings.EqualFold(s.form.value(2), "yes")
		target := s.detail
		s.confirm = &ws3ConfirmAction{
			title: "确认设置/重置密码",
			details: []string{
				"目标：" + target.Username + "（稳定 ID " + target.ID + "）",
				"root 目标：" + fmt.Sprint(target.IsRoot),
				"下次登录要求改密：" + fmt.Sprint(requireChange),
				"成功后旧会话/旧找回入口按领域语义失效；密码不回显、不记录。",
			},
			execute: func(ctx context.Context) (string, error) {
				result, err := s.services.Identity.SetPassword(ctx, target.ID, password, requireChange)
				if err != nil {
					return "", err
				}
				s.detail.SecurityVersion = result.SecurityVersion
				return fmt.Sprintf("密码已设置；安全版本 %d；要求下次登录改密=%v",
					result.SecurityVersion, result.MustChange), nil
			},
		}
		s.form = nil
		s.formKind = ""
		s.mode = ws3IdentityConfirm
		return nil
	default:
		return fmt.Errorf("未知表单动作")
	}
}

func (s *ws3IdentityScreen) handleConfirmKey(ctx context.Context, key Key) (bool, error) {
	if s.confirm == nil {
		s.mode = ws3IdentityActions
		return false, nil
	}
	switch key.Kind {
	case KeyEsc:
		s.confirm = nil
		s.mode = ws3IdentityActions
	case KeyCtrlC:
		s.closeSession()
		return true, nil
	case KeyEnter:
		action := s.confirm
		s.confirm = nil
		message, err := action.execute(ctx)
		s.mode = ws3IdentityActions
		if err != nil {
			s.setError(err)
			return false, nil
		}
		s.setStatus(message)
	}
	return false, nil
}

func (s *ws3IdentityScreen) refreshListUser(user LocalUser) {
	for index := range s.page.Users {
		if s.page.Users[index].ID == user.ID {
			s.page.Users[index] = user
			return
		}
	}
}

var _ = time.Now
