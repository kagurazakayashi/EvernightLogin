package setupconsole

// 步骤 289：本地角色/权限/用户组快捷维护画面。
//
// 能力：系统范围角色/权限/用户组列表（分页+字面搜索）、角色启停、组成员增删、
// 预设恢复差异预览 + 显式确认恢复（本地操作者审计）。普通客服与“直接改名/改密
// 客服”区别通过权限键说明展示；root 资格不通过角色勾选产生/移除；内置权限不可
// 删除（领域服务 fail-closed）。预设恢复依赖 preset 本地适配，未接入前明确显示不可用。

import (
	"context"
	"fmt"
	"strings"
)

const ws3RBACScreenID = "ws3.rbac"

type ws3RBACScreen struct {
	ws3ScreenBase
	tab      int // 0=roles 1=permissions 2=groups
	query    LocalPageRequest
	cursor   int
	roles    []LocalRole
	perms    []LocalPermission
	groups   []LocalGroup
	hasMore  bool
	form     *ws3FormState
	formKind string
	confirm  *ws3ConfirmAction
}

func newWS3RBACScreen(open WS3SessionOpener) ScreenController {
	return &ws3RBACScreen{ws3ScreenBase: ws3ScreenBase{open: open},
		query: LocalPageRequest{Limit: 10}}
}

func (s *ws3RBACScreen) Title() string { return "本地维护 · 角色/权限/用户组" }

func (s *ws3RBACScreen) Render(ctx context.Context, canvas *Canvas, session SessionView) {
	_ = session
	if s.services == nil {
		if err := s.ensureSession(ctx); err != nil {
			_, top, width, _ := ws3CanvasArea(canvas)
			top = ws3DrawMessage(canvas, top, width, "不可用：", s.errText)
			top++
			canvas.Text(2, top, "Esc 返回主菜单。")
			return
		}
		if s.empty() {
			s.loadCurrent(ctx)
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
	tabs := []string{"1 角色", "2 权限", "3 用户组"}
	canvas.Text(2, top, fmt.Sprintf("%s | 当前：%s | r=刷新 /=搜索  p=预设恢复",
		strings.Join(tabs, "  "), tabs[maxInt(minInt(s.tab, 2), 0)]))
	top += 2
	visible := maxInt(height-(top-ws3CanvasAreaTop(canvas)), 1)
	switch s.tab {
	case 1:
		s.renderPermissions(canvas, top, width, visible)
	case 2:
		s.renderGroups(canvas, top, width, visible)
	default:
		s.renderRoles(canvas, top, width, visible)
	}
}

func (s *ws3RBACScreen) empty() bool {
	return len(s.roles) == 0 && len(s.perms) == 0 && len(s.groups) == 0
}

func (s *ws3RBACScreen) renderRoles(canvas *Canvas, top, width, visible int) {
	if len(s.roles) == 0 {
		canvas.Text(2, top, "没有角色（r 刷新）。")
		return
	}
	start := 0
	if s.cursor >= visible {
		start = s.cursor - visible + 1
	}
	for index := start; index < len(s.roles) && index < start+visible; index++ {
		role := s.roles[index]
		marker := "  "
		if index == s.cursor {
			marker = "> "
		}
		canvas.Text(2, top, ws3Truncate(fmt.Sprintf("%s%s（%s）%s%s", marker,
			role.Name, role.Key, ws3BoolLabel(role.Enabled), map[bool]string{true: " [内置]", false: ""}[role.Builtin]), width))
		top++
	}
	canvas.Text(2, top+1, "Enter=启停角色（危险操作需确认）；内置角色由领域服务保护")
}

func (s *ws3RBACScreen) renderPermissions(canvas *Canvas, top, width, visible int) {
	if len(s.perms) == 0 {
		canvas.Text(2, top, "没有权限（r 刷新）。")
		return
	}
	for index, permission := range s.perms {
		if index >= visible {
			break
		}
		state := "已实现"
		if !permission.Implemented {
			state = "目录登记未实现"
		}
		if permission.RootOnly {
			state += "/root_only"
		}
		canvas.Text(2, top, ws3Truncate(fmt.Sprintf("%s  %s（%s）", permission.Key,
			permission.Name, state), width))
		top++
	}
}

func (s *ws3RBACScreen) renderGroups(canvas *Canvas, top, width, visible int) {
	if len(s.groups) == 0 {
		canvas.Text(2, top, "没有用户组（r 刷新）。")
		return
	}
	start := 0
	if s.cursor >= visible {
		start = s.cursor - visible + 1
	}
	for index := start; index < len(s.groups) && index < start+visible; index++ {
		group := s.groups[index]
		marker := "  "
		if index == s.cursor {
			marker = "> "
		}
		canvas.Text(2, top, ws3Truncate(fmt.Sprintf("%s%s（%s）范围 %s", marker,
			group.Name, group.Key, group.ScopeID), width))
		top++
	}
	canvas.Text(2, top+1, "Enter=组成员维护（a 添加成员 / x 移除成员）")
}

func (s *ws3RBACScreen) HandleKey(ctx context.Context, key Key, session SessionView) (bool, error) {
	_ = session
	if s.services == nil {
		if err := s.ensureSession(ctx); err != nil {
			if key.Kind == KeyEsc || key.Kind == KeyCtrlC {
				s.closeSession()
				return true, nil
			}
			return false, nil
		}
		if s.empty() {
			s.loadCurrent(ctx)
		}
		return false, nil
	}
	if s.form != nil {
		return s.handleFormKey(ctx, key)
	}
	if s.confirm != nil {
		return s.handleConfirmKey(ctx, key)
	}
	switch key.Kind {
	case KeyEsc, KeyCtrlC:
		s.closeSession()
		return true, nil
	case KeyUp:
		if s.cursor > 0 {
			s.cursor--
		}
	case KeyDown:
		limit := s.currentLength()
		if s.cursor < limit-1 {
			s.cursor++
		}
	case KeyEnter:
		return false, s.activateCurrent(ctx)
	case KeyRune:
		switch key.Rune {
		case '1':
			s.tab, s.cursor = 0, 0
			s.loadCurrent(ctx)
		case '2':
			s.tab, s.cursor = 1, 0
			s.loadCurrent(ctx)
		case '3':
			s.tab, s.cursor = 2, 0
			s.loadCurrent(ctx)
		case 'r', 'R':
			s.query.Offset = 0
			s.cursor = 0
			s.loadCurrent(ctx)
		case '/':
			s.openSearchForm()
		case 'p', 'P':
			s.openPresetForm()
		case 'a', 'A':
			if s.tab == 2 {
				s.openGroupMemberForm(true)
			}
		case 'x', 'X':
			if s.tab == 2 {
				s.openGroupMemberForm(false)
			}
		case 'n', 'N':
			// 下一页（PgDn 等价）。
			if s.hasMore {
				s.query.Offset += s.query.Limit
				s.cursor = 0
				s.loadCurrent(ctx)
			}
		}
	}
	return false, nil
}

func (s *ws3RBACScreen) currentLength() int {
	switch s.tab {
	case 1:
		return len(s.perms)
	case 2:
		return len(s.groups)
	default:
		return len(s.roles)
	}
}

func (s *ws3RBACScreen) loadCurrent(ctx context.Context) {
	if s.services == nil || s.services.RBAC == nil {
		s.setError(ErrLocalUnsupported)
		return
	}
	var err error
	s.hasMore = false
	switch s.tab {
	case 1:
		s.perms, s.hasMore, err = s.services.RBAC.ListPermissions(ctx, s.query)
	case 2:
		s.groups, s.hasMore, err = s.services.RBAC.ListGroups(ctx, s.query, "system")
	default:
		s.roles, s.hasMore, err = s.services.RBAC.ListRoles(ctx, s.query, "system")
	}
	if err != nil {
		s.setError(err)
	}
}

func (s *ws3RBACScreen) activateCurrent(ctx context.Context) error {
	if s.services == nil || s.services.RBAC == nil {
		return ErrLocalUnsupported
	}
	switch s.tab {
	case 0:
		if s.cursor < 0 || s.cursor >= len(s.roles) {
			return nil
		}
		role := s.roles[s.cursor]
		enable := !role.Enabled
		s.confirm = &ws3ConfirmAction{title: "启停角色：" + role.Name,
			details: []string{"目标角色：" + role.Name + "（" + role.Key + "）",
				"新状态：" + ws3BoolLabel(enable) + "；内置角色由领域服务保护，root 资格不受角色影响。"},
			execute: func(ctx context.Context) (string, error) {
				if err := s.services.RBAC.SetRoleEnabled(ctx, role.ID, enable); err != nil {
					return "", err
				}
				s.loadCurrent(ctx)
				return "角色状态已更新：" + ws3BoolLabel(enable), nil
			}}
	case 2:
		if s.cursor < 0 || s.cursor >= len(s.groups) {
			return nil
		}
		group := s.groups[s.cursor]
		s.openMemberFormForGroup(group, true)
	default:
		s.setStatus("权限为目录只读；如需调整请使用角色组合或预设恢复。")
	}
	return nil
}

func (s *ws3RBACScreen) openSearchForm() {
	form := newWS3Form("搜索当前列表（名称/机器键字面子串；空=清除）",
		[]string{"搜索词"}, []bool{false}, "Enter 提交 · Esc 取消")
	form.setValue(0, s.query.Search)
	s.form = form
	s.formKind = "search"
}

func (s *ws3RBACScreen) openPresetForm() {
	form := newWS3Form("预设恢复（先预览差异，再显式确认；不静默覆盖自定义角色）",
		[]string{"作用范围（system 或 app:<应用ID>）", "角色机器键（如 system_admin，空=全部预设角色）"},
		[]bool{false, false}, "Enter 预览 · Esc 取消；恢复前列出增删权限与影响账户。")
	form.setValue(0, "system")
	s.form = form
	s.formKind = "preset"
}

func (s *ws3RBACScreen) openGroupMemberForm(add bool) {
	if s.cursor < 0 || s.cursor >= len(s.groups) {
		s.setError(fmt.Errorf("请先选择用户组"))
		return
	}
	s.openMemberFormForGroup(s.groups[s.cursor], add)
}

func (s *ws3RBACScreen) openMemberFormForGroup(group LocalGroup, add bool) {
	s.openGroupMemberFormForGroup(group, add)
}

func (s *ws3RBACScreen) openGroupMemberFormForGroup(group LocalGroup, add bool) {
	action := "添加"
	if !add {
		action = "移除"
	}
	form := newWS3Form(fmt.Sprintf("%s组成员：%s（%s）", action, group.Name, group.Key),
		[]string{"目标用户稳定 ID（usr_…）"}, []bool{false}, "Enter 提交 · Esc 取消")
	s.form = form
	s.formKind = "group-member-add"
	if !add {
		s.formKind = "group-member-remove"
	}
	s.form.labels = append(s.form.labels, "用户组 ID（自动绑定，不可改）")
	s.form.values = append(s.form.values, group.ID)
	s.form.secret = append(s.form.secret, false)
}

func (s *ws3RBACScreen) handleFormKey(ctx context.Context, key Key) (bool, error) {
	submitted, cancelled := s.form.handleKey(key)
	if cancelled {
		s.form = nil
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

func (s *ws3RBACScreen) submitForm(ctx context.Context) error {
	switch s.formKind {
	case "search":
		s.query.Search = s.form.value(0)
		s.query.Offset = 0
		s.cursor = 0
		s.form = nil
		s.loadCurrent(ctx)
		return nil
	case "preset":
		scopeID := s.form.value(0)
		roleKey := s.form.value(1)
		diff, err := s.services.RBAC.PreviewPresetRestore(ctx, scopeID, roleKey)
		if err != nil {
			return err
		}
		details := []string{
			fmt.Sprintf("范围 %s / 角色 %s：新增权限 %d，移除权限 %d，影响账户 %d",
				diff.ScopeID, diff.RoleKey, len(diff.Add), len(diff.Remove), diff.Affected),
			"新增：" + strings.Join(diff.Add, ", "),
			"移除：" + strings.Join(diff.Remove, ", "),
			"恢复不会静默提升既有客服的全局改密权；自定义角色保留。",
		}
		s.form = nil
		s.confirm = &ws3ConfirmAction{title: "确认应用预设恢复", details: details,
			execute: func(ctx context.Context) (string, error) {
				if err := s.services.RBAC.RestorePreset(ctx, diff, true); err != nil {
					return "", err
				}
				s.loadCurrent(ctx)
				return "预设恢复已应用（本地操作者已记审计）", nil
			}}
		return nil
	case "group-member-add", "group-member-remove":
		userID := s.form.value(0)
		groupID := ""
		if len(s.form.values) > 1 {
			groupID = strings.TrimSpace(s.form.values[1])
		}
		if groupID == "" {
			return fmt.Errorf("缺少用户组 ID")
		}
		var err error
		if s.formKind == "group-member-add" {
			err = s.services.RBAC.AddGroupMember(ctx, groupID, userID)
		} else {
			err = s.services.RBAC.RemoveGroupMember(ctx, groupID, userID)
		}
		if err != nil {
			return err
		}
		s.form = nil
		s.setStatus("组成员关系已更新")
		return nil
	default:
		return fmt.Errorf("未知表单动作")
	}
}

func (s *ws3RBACScreen) handleConfirmKey(ctx context.Context, key Key) (bool, error) {
	switch key.Kind {
	case KeyEsc:
		s.confirm = nil
	case KeyCtrlC:
		s.closeSession()
		return true, nil
	case KeyEnter:
		action := s.confirm
		s.confirm = nil
		message, err := action.execute(ctx)
		if err != nil {
			s.setError(err)
			return false, nil
		}
		s.setStatus(message)
	}
	return false, nil
}
