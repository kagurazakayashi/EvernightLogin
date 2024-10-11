package setupconsole

// 步骤 286：本地用户查询与账户生命周期维护画面。
//
// 能力（全部经本地维护身份调用既有领域服务，不新增账户存储）：
//   - 用户列表：分页、字面搜索（用户名/昵称）、状态过滤；
//   - 详情：稳定 UserID 绑定选择，翻页/搜索后动作仍按当前选中 ID；
//   - 创建用户（预设角色快捷分配在详情“分配角色”）、修改普通资料；
//   - 启停账户、设置/清除全局有效期；
//   - 删除预览（真实关联影响）→ 标记待删除 → 确认完成删除；
//   - root 账户保护：领域服务拒绝普通删除/禁用/有效期；画面只显示不可用原因。
//
// 安全：无应用会话/审批要求，但保留唯一性、状态机、行版本、审计；数据库不可用
// 时画面显示错误并 fail-closed。

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const ws3UsersScreenID = "ws3.users"

type ws3UsersMode int

const (
	ws3UsersList ws3UsersMode = iota
	ws3UsersDetail
	ws3UsersForm
	ws3UsersConfirm
	ws3UsersRoles
)

type ws3UsersScreen struct {
	ws3ScreenBase
	mode     ws3UsersMode
	page     LocalUserPage
	query    LocalUserQuery
	cursor   int
	selected LocalUser
	detail   LocalUser
	detailOK bool

	form      *ws3FormState
	formKind  string
	confirm   *ws3ConfirmAction
	roles     []LocalRole
	rolesOK   bool
	rolesIdx  int
	loading   bool
	loaded    bool
	lastError error
}

func newWS3UsersScreen(open WS3SessionOpener) ScreenController {
	screen := &ws3UsersScreen{ws3ScreenBase: ws3ScreenBase{open: open}}
	screen.query = LocalUserQuery{PageRequest: LocalPageRequest{Limit: 10}}
	return screen
}

func (s *ws3UsersScreen) Title() string { return "本地维护 · 用户与账户生命周期" }

func (s *ws3UsersScreen) Render(ctx context.Context, canvas *Canvas, session SessionView) {
	_ = session
	if s.services == nil {
		if err := s.ensureSession(ctx); err != nil {
			s.drawUnavailable(canvas)
			return
		}
	}
	if !s.loaded && s.mode == ws3UsersList {
		s.loadUsers(ctx)
	}
	left, top, width, height := ws3CanvasArea(canvas)
	_ = left
	switch s.mode {
	case ws3UsersDetail:
		s.renderDetail(canvas, top, width, height)
	case ws3UsersForm:
		s.drawForm(canvas, top, width)
	case ws3UsersConfirm:
		if s.confirm != nil {
			ws3RenderConfirm(canvas, top, width, s.confirm.title, s.confirm.details)
		}
	case ws3UsersRoles:
		s.renderRoles(canvas, top, width, height)
	default:
		s.renderList(canvas, top, width, height)
	}
}

func (s *ws3UsersScreen) drawUnavailable(canvas *Canvas) {
	_, top, width, _ := ws3CanvasArea(canvas)
	top = ws3DrawMessage(canvas, top, width, "不可用：", s.errText)
	top++
	canvas.Text(2, top, "Esc 返回主菜单；请先修复实例配置/数据库/迁移。")
}

func (s *ws3UsersScreen) renderList(canvas *Canvas, top, width, height int) {
	top = ws3DrawStatus(&s.ws3ScreenBase, canvas, top, width)
	if s.loading {
		canvas.Text(2, top, "正在读取用户列表…")
		return
	}
	canvas.Text(2, top, fmt.Sprintf("用户列表（共本页 %d 条，偏移 %d）  n=新建  /=搜索  r=刷新  Enter=详情",
		len(s.page.Users), s.query.PageRequest.Offset))
	top += 2
	if len(s.page.Users) == 0 {
		canvas.Text(2, top, "当前筛选没有用户。")
	} else {
		header := "  #  用户名            昵称              状态        行版本  用户 ID"
		canvas.Text(2, top, ws3Truncate(header, width))
		top++
		visible := height - (top - ws3CanvasAreaTop(canvas))
		if visible < 1 {
			visible = 1
		}
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
			line := fmt.Sprintf("%s%-3d %-17s %-17s %-10s %-6d %s", marker, index+1,
				ws3Truncate(user.Username, 17), ws3Truncate(user.Nickname, 17),
				ws3Truncate(user.Status, 10), user.RowVersion, user.ID)
			canvas.Text(2, top, ws3Truncate(line, width))
			top++
		}
	}
	top++
	pageText := fmt.Sprintf("第 %d+ 条；PgUp/PgDn=翻页  Home/End=首尾  状态: %d=%s",
		s.query.PageRequest.Offset, len(s.page.Users), s.statusLabel())
	canvas.Text(2, top, ws3Truncate(pageText, width))
}

func ws3CanvasAreaTop(canvas *Canvas) int {
	_, top, _, _ := ws3CanvasArea(canvas)
	return top
}

func (s *ws3UsersScreen) statusLabel() string {
	if s.query.Status == "" {
		return "全部"
	}
	return s.query.Status
}

func (s *ws3UsersScreen) loadUsers(ctx context.Context) {
	if s.services == nil || s.services.Users == nil {
		s.setError(ErrLocalUnsupported)
		return
	}
	s.loading = true
	page, err := s.services.Users.ListUsers(ctx, s.query)
	s.loading = false
	if err != nil {
		s.setError(err)
		return
	}
	s.page = page
	s.loaded = true
	if s.cursor >= len(page.Users) {
		if len(page.Users) > 0 {
			s.cursor = len(page.Users) - 1
		} else {
			s.cursor = 0
		}
	}
}

func (s *ws3UsersScreen) renderDetail(canvas *Canvas, top, width, height int) {
	_ = height
	top = ws3DrawStatus(&s.ws3ScreenBase, canvas, top, width)
	user := s.detail
	canvas.Text(2, top, "用户详情（Esc 返回列表）")
	top += 2
	rows := [][2]string{
		{"稳定用户 ID", user.ID},
		{"用户名", user.Username},
		{"昵称", user.Nickname},
		{"简介", user.Biography},
		{"语言/时区", user.Language + " / " + user.Timezone},
		{"状态", user.Status},
		{"root 账户", ws3BoolLabel(user.IsRoot)},
		{"资料行版本", strconv.FormatInt(user.RowVersion, 10)},
		{"安全版本", strconv.FormatInt(user.SecurityVersion, 10)},
		{"创建时间", ws3FormatTime(user.CreatedAt)},
		{"更新时间", ws3FormatTime(user.UpdatedAt)},
	}
	for _, row := range rows {
		canvas.Text(2, top, ws3Truncate(row[0]+"："+row[1], width))
		top++
	}
	top++
	canvas.Text(2, top, "操作：e=改资料  p=设置/重置密码  v=有效期  d=启停  x=删除  a=分配角色  r=刷新")
}

func (s *ws3UsersScreen) renderRoles(canvas *Canvas, top, width, height int) {
	top = ws3DrawStatus(&s.ws3ScreenBase, canvas, top, width)
	canvas.Text(2, top, "选择要授予该用户的角色（↑/↓ 移动，Enter 确认，Esc 返回）")
	top += 2
	if len(s.roles) == 0 {
		canvas.Text(2, top, "没有可分配的角色。")
		return
	}
	visible := height - (top - ws3CanvasAreaTop(canvas))
	if visible < 1 {
		visible = 1
	}
	start := 0
	if s.rolesIdx >= visible {
		start = s.rolesIdx - visible + 1
	}
	for index := start; index < len(s.roles) && index < start+visible; index++ {
		role := s.roles[index]
		marker := "  "
		if index == s.rolesIdx {
			marker = "> "
		}
		canvas.Text(2, top, ws3Truncate(fmt.Sprintf("%s%s（%s，范围 %s）", marker,
			role.Name, role.Key, role.ScopeID), width))
		top++
	}
}

func (s *ws3UsersScreen) drawForm(canvas *Canvas, top, width int) {
	if s.form == nil {
		return
	}
	s.form.draw(canvas, top, width)
}

// HandleKey 实现 ScreenController。
func (s *ws3UsersScreen) HandleKey(ctx context.Context, key Key,
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
		if s.mode == ws3UsersList && len(s.page.Users) == 0 {
			s.loadUsers(ctx)
		}
		return false, nil
	}
	switch s.mode {
	case ws3UsersForm:
		return s.handleFormKey(ctx, key)
	case ws3UsersConfirm:
		return s.handleConfirmKey(ctx, key)
	case ws3UsersRoles:
		return s.handleRolesKey(ctx, key)
	case ws3UsersDetail:
		return s.handleDetailKey(ctx, key)
	default:
		return s.handleListKey(ctx, key)
	}
}

func (s *ws3UsersScreen) handleListKey(ctx context.Context, key Key) (bool, error) {
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
	case KeyHome:
		if len(s.page.Users) > 0 {
			s.cursor = 0
		}
	case KeyEnd:
		if len(s.page.Users) > 0 {
			s.cursor = len(s.page.Users) - 1
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
			s.detailOK = true
			s.mode = ws3UsersDetail
			s.setStatus("按稳定 UserID 绑定当前操作目标：" + s.selected.ID)
		}
	case KeyRune:
		switch key.Rune {
		case 'r', 'R':
			s.loadUsers(ctx)
		case 'n', 'N':
			s.openCreateForm()
		case '/':
			s.openSearchForm()
		}
	}
	return false, nil
}

func (s *ws3UsersScreen) handleDetailKey(ctx context.Context, key Key) (bool, error) {
	switch key.Kind {
	case KeyEsc:
		s.mode = ws3UsersList
		s.setStatus("")
	case KeyCtrlC:
		s.closeSession()
		return true, nil
	case KeyRune:
		switch key.Rune {
		case 'e', 'E':
			s.openEditForm()
		case 'p', 'P':
			s.openPasswordForm()
		case 'v', 'V':
			s.openValidityForm(ctx)
		case 'd', 'D':
			s.openToggleConfirm()
		case 'x', 'X':
			s.openDeletionPreview(ctx)
		case 'a', 'A':
			s.openRolePicker(ctx)
		case 'r', 'R':
			s.refreshDetail(ctx)
		}
	}
	return false, nil
}

func (s *ws3UsersScreen) refreshDetail(ctx context.Context) {
	if s.services == nil || s.services.Users == nil {
		return
	}
	user, err := s.services.Users.GetUser(ctx, s.selected.ID)
	if err != nil {
		s.setError(err)
		return
	}
	s.detail = user
	s.selected = user
}

func (s *ws3UsersScreen) openSearchForm() {
	form := newWS3Form("搜索用户（用户名/昵称字面子串；留空清除搜索）",
		[]string{"搜索词", "状态（active/disabled/pending/空=全部）"}, []bool{false, false},
		"Enter 提交 · Esc 取消")
	form.setValue(0, s.query.PageRequest.Search)
	form.setValue(1, s.query.Status)
	s.form = form
	s.formKind = "search"
	s.mode = ws3UsersForm
	s.setStatus("")
}

func (s *ws3UsersScreen) openCreateForm() {
	form := newWS3Form("创建用户（密码只用于本次输入，不显示、不记录）",
		[]string{"用户名", "昵称", "密码（可空=稍后设置）", "首次登录强制改密（y/n）"},
		[]bool{false, false, true, false}, "Enter 提交 · Esc 取消")
	form.setValue(3, "y")
	s.form = form
	s.formKind = "create"
	s.mode = ws3UsersForm
	s.setStatus("")
}

func (s *ws3UsersScreen) openEditForm() {
	form := newWS3Form("修改普通资料（用户名/状态/密码不在此处）",
		[]string{"昵称", "简介", "语言", "时区"}, []bool{false, false, false, false},
		"Enter 提交 · Esc 取消")
	form.setValue(0, s.detail.Nickname)
	form.setValue(1, s.detail.Biography)
	form.setValue(2, s.detail.Language)
	form.setValue(3, s.detail.Timezone)
	s.form = form
	s.formKind = "edit"
	s.mode = ws3UsersForm
	s.setStatus("")
}

func (s *ws3UsersScreen) openPasswordForm() {
	form := newWS3Form("设置/重置密码（本地维护身份，无需目标旧密码；root 亦可）",
		[]string{"新密码", "确认新密码"}, []bool{true, true},
		"提交成功后旧会话/旧找回入口按领域语义失效；密码不回显、不记录。")
	s.form = form
	s.formKind = "password"
	s.mode = ws3UsersForm
	s.setStatus("")
}

func (s *ws3UsersScreen) openValidityForm(ctx context.Context) {
	form := newWS3Form("账户有效期（UTC；空=永久有效该端；格式 YYYY-MM-DD、RFC3339 或 now）",
		[]string{"开始（valid_from）", "结束（valid_until）"}, []bool{false, false},
		"Enter 提交 · Esc 取消；root 不允许设置有效期")
	if s.services != nil && s.services.Users != nil {
		if validity, err := s.services.Users.GetValidity(ctx, s.detail.ID); err == nil {
			form.setValue(0, ws3FormatOptionalTime(validity.ValidFrom))
			form.setValue(1, ws3FormatOptionalTime(validity.ValidUntil))
			form.setValue(2, strconv.FormatInt(validity.RowVersion, 10))
			form.labels = append(form.labels, "行版本（自动，可留空取最新）")
			form.values = append(form.values, strconv.FormatInt(validity.RowVersion, 10))
			form.secret = append(form.secret, false)
		}
	}
	s.form = form
	s.formKind = "validity"
	s.mode = ws3UsersForm
	s.setStatus("")
}

func ws3FormatOptionalTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format("2006-01-02 15:04:05Z")
}

// ws3NowUTC 返回本地控制台当前 UTC 时间（有效期输入 "now" 使用）。
func ws3NowUTC() time.Time { return time.Now().UTC() }

func (s *ws3UsersScreen) openToggleConfirm() {
	enable := s.detail.Status != "active"
	title := "停用账户（可再启用）"
	if enable {
		title = "启用账户"
	}
	details := []string{
		"目标：" + s.detail.Username + "（稳定 ID " + s.detail.ID + "）",
		"当前状态：" + s.detail.Status,
		"root 账户不允许普通启停；领域服务会再次校验并写审计。",
	}
	userID := s.detail.ID
	s.confirm = &ws3ConfirmAction{title: title, details: details,
		execute: func(ctx context.Context) (string, error) {
			user, err := s.services.Users.SetEnabled(ctx, userID, enable, 0)
			if err != nil {
				return "", err
			}
			s.detail = user
			s.selected = user
			s.refreshListUser(user)
			return "状态已变更为 " + user.Status, nil
		}}
	s.mode = ws3UsersConfirm
	s.setStatus("")
}

func (s *ws3UsersScreen) openDeletionPreview(ctx context.Context) {
	if s.services == nil || s.services.Users == nil {
		s.setError(ErrLocalUnsupported)
		return
	}
	preview, err := s.services.Users.PreviewDeletion(ctx, s.detail.ID)
	if err != nil {
		s.setError(err)
		return
	}
	details := []string{
		fmt.Sprintf("目标：%s（%s，状态 %s）", preview.Username, preview.UserID, preview.Status),
		fmt.Sprintf("应用成员关系：%d；用户角色：%d；用户组：%d；一次性凭证：%d；名下应用：%d",
			preview.AppMemberships, preview.UserRoles, preview.GroupMemberships,
			preview.OneTimeCredentials, preview.OwnedApplications),
		"删除为两阶段：先标记待删除，再确认完成；root 永远拒绝。",
	}
	if preview.IsRoot {
		details = append(details, "目标为 root：领域服务将拒绝删除，不能完成。")
	}
	userID := preview.UserID
	s.confirm = &ws3ConfirmAction{title: "删除用户（不可逆，先标记待删除再完成）",
		details: details, execute: func(ctx context.Context) (string, error) {
			user, err := s.services.Users.RequestDeletion(ctx, userID, 0)
			if err != nil {
				return "", err
			}
			impact, err := s.services.Users.CompleteDeletion(ctx, userID, user.RowVersion)
			if err != nil {
				return "", fmt.Errorf("已标记待删除但完成删除失败（可稍后重试）: %w", err)
			}
			s.mode = ws3UsersList
			s.detail = LocalUser{}
			s.detailOK = false
			s.query.PageRequest.Offset = 0
			s.cursor = 0
			s.loadUsers(ctx)
			return fmt.Sprintf("已删除用户 %s；影响快照：成员 %d、角色 %d、组 %d",
				impact.Username, impact.AppMemberships, impact.UserRoles,
				impact.GroupMemberships), nil
		}}
	s.mode = ws3UsersConfirm
	s.setStatus("")
}

func (s *ws3UsersScreen) openRolePicker(ctx context.Context) {
	if s.services == nil || s.services.Users == nil {
		s.setError(ErrLocalUnsupported)
		return
	}
	if !s.rolesOK {
		roles, err := s.services.Users.ListAssignableRoles(ctx)
		if err != nil {
			s.setError(err)
			return
		}
		s.roles = roles
		s.rolesOK = true
	}
	s.rolesIdx = 0
	s.mode = ws3UsersRoles
	s.setStatus("")
}

func (s *ws3UsersScreen) handleRolesKey(ctx context.Context, key Key) (bool, error) {
	switch key.Kind {
	case KeyEsc:
		s.mode = ws3UsersDetail
	case KeyUp:
		if s.rolesIdx > 0 {
			s.rolesIdx--
		}
	case KeyDown:
		if s.rolesIdx < len(s.roles)-1 {
			s.rolesIdx++
		}
	case KeyEnter:
		if s.rolesIdx >= 0 && s.rolesIdx < len(s.roles) {
			role := s.roles[s.rolesIdx]
			if err := s.services.Users.AssignRole(ctx, s.detail.ID, role.ID); err != nil {
				s.setError(err)
			} else {
				s.setStatus("已授予角色 " + role.Name + "（" + role.Key + "）")
				s.mode = ws3UsersDetail
			}
		}
	}
	return false, nil
}

func (s *ws3UsersScreen) handleFormKey(ctx context.Context, key Key) (bool, error) {
	if s.form == nil {
		s.mode = ws3UsersList
		return false, nil
	}
	submitted, cancelled := s.form.handleKey(key)
	if cancelled {
		s.form = nil
		switch s.formKind {
		case "search":
			s.mode = ws3UsersList
		default:
			if s.detailOK {
				s.mode = ws3UsersDetail
			} else {
				s.mode = ws3UsersList
			}
		}
		s.formKind = ""
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

func (s *ws3UsersScreen) submitForm(ctx context.Context) error {
	switch s.formKind {
	case "search":
		s.query.PageRequest.Search = s.form.value(0)
		s.query.Status = strings.TrimSpace(s.form.value(1))
		s.query.PageRequest.Offset = 0
		s.cursor = 0
		s.form = nil
		s.formKind = ""
		s.mode = ws3UsersList
		s.loadUsers(ctx)
		return nil
	case "create":
		username := s.form.value(0)
		if username == "" {
			return fmt.Errorf("用户名不能为空")
		}
		requireChange := strings.EqualFold(s.form.value(3), "y") ||
			strings.EqualFold(s.form.value(3), "yes")
		password := s.form.value(2)
		input := LocalUserCreate{Username: username, Nickname: s.form.value(1),
			Password: password, RequireChange: requireChange}
		user, err := s.services.Users.CreateUser(ctx, input)
		if err != nil {
			return err
		}
		s.form = nil
		s.formKind = ""
		s.mode = ws3UsersList
		s.query.PageRequest.Offset = 0
		s.cursor = 0
		s.loadUsers(ctx)
		s.setStatus("已创建用户 " + user.Username + "（" + user.ID + "）")
		return nil
	case "edit":
		user, err := s.services.Users.UpdateProfile(ctx, s.detail.ID, LocalProfileUpdate{
			Nickname: s.form.value(0), Biography: s.form.value(1),
			Language: s.form.value(2), Timezone: s.form.value(3),
			ExpectedRowVersion: s.detail.RowVersion,
		})
		if err != nil {
			return err
		}
		s.detail = user
		s.selected = user
		s.refreshListUser(user)
		s.form = nil
		s.formKind = ""
		s.mode = ws3UsersDetail
		s.setStatus("资料已更新（行版本 " + strconv.FormatInt(user.RowVersion, 10) + "）")
		return nil
	case "password":
		if s.services.Identity == nil {
			return ErrLocalUnsupported
		}
		password := s.form.value(0)
		if password == "" {
			return fmt.Errorf("新密码不能为空")
		}
		if password != s.form.value(1) {
			return fmt.Errorf("两次输入的新密码不一致")
		}
		result, err := s.services.Identity.SetPassword(ctx, s.detail.ID, password, true)
		if err != nil {
			return err
		}
		s.detail.SecurityVersion = result.SecurityVersion
		s.form = nil
		s.formKind = ""
		s.mode = ws3UsersDetail
		s.setStatus("密码已设置；安全版本 " + strconv.FormatInt(result.SecurityVersion, 10) +
			"；目标下次登录需改密")
		return nil
	case "validity":
		if s.services.Users == nil {
			return ErrLocalUnsupported
		}
		now := ws3NowUTC()
		from, err := ws3ParseTime(s.form.value(0), now)
		if err != nil {
			return err
		}
		until, err := ws3ParseTime(s.form.value(1), now)
		if err != nil {
			return err
		}
		user, err := s.services.Users.SetValidity(ctx, s.detail.ID, LocalValidity{
			UserID: s.detail.ID, ValidFrom: from, ValidUntil: until})
		if err != nil {
			return err
		}
		s.detail = user
		s.selected = user
		s.form = nil
		s.formKind = ""
		s.mode = ws3UsersDetail
		s.setStatus("有效期已更新")
		return nil
	default:
		return fmt.Errorf("未知表单动作")
	}
}

func (s *ws3UsersScreen) handleConfirmKey(ctx context.Context, key Key) (bool, error) {
	if s.confirm == nil {
		s.mode = ws3UsersList
		return false, nil
	}
	switch key.Kind {
	case KeyEsc:
		s.confirm = nil
		if s.detailOK {
			s.mode = ws3UsersDetail
		} else {
			s.mode = ws3UsersList
		}
	case KeyCtrlC:
		s.closeSession()
		return true, nil
	case KeyEnter:
		action := s.confirm
		s.confirm = nil
		message, err := action.execute(ctx)
		if err != nil {
			s.setError(err)
			if s.detailOK {
				s.mode = ws3UsersDetail
			} else {
				s.mode = ws3UsersList
			}
			return false, nil
		}
		s.setStatus(message)
		if s.mode == ws3UsersConfirm {
			s.mode = ws3UsersList
		}
	}
	return false, nil
}

func (s *ws3UsersScreen) refreshListUser(user LocalUser) {
	for index := range s.page.Users {
		if s.page.Users[index].ID == user.ID {
			s.page.Users[index] = user
			return
		}
	}
}
