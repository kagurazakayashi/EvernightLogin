package setupconsole

// WS2（步骤 282–285）本地初始化画面注册与最小可用画面。
//
// 画面只调用本文件/同工作流文件中的真实计划与领域函数；没有结果就不显示成功。
// 复杂字段表单在本轮 M2 审计前继续补齐；当前提供可实际操作的核心路径：
//   - 282：测试连接、保存数据库配置、排他锁下初始化/补迁移；
//   - 283：创建 root/继续未完成初始化/本地重设密码（密码一次展示）；
//   - 284：安装系统预设、按方案创建账户（临时密码首登改密）；
//   - 285：选择并应用三套推荐配置（待配置项明确、可继续迁移）。

import (
	"context"
	"fmt"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/config"
)

// WS2Option 是 RegisterWS2 的可选装配参数。
type WS2Option func(*ws2Registration)

type ws2Registration struct {
	operatorID string
}

// WithWS2OperatorID 注入稳定本地操作者标识；默认从实例目录推导。
func WithWS2OperatorID(operatorID string) WS2Option {
	return func(registration *ws2Registration) {
		registration.operatorID = strings.TrimSpace(operatorID)
	}
}

// RegisterWS2 注册 282–285 的菜单与画面；重复注册返回错误。
func RegisterWS2(app *App, options ...WS2Option) error {
	if app == nil {
		return fmt.Errorf("控制台未初始化")
	}
	registration := ws2Registration{}
	for _, option := range options {
		if option != nil {
			option(&registration)
		}
	}
	menus := []MenuEntry{
		{ID: "ws2-database", Label: "数据库设置与初始化（282）", Order: 100},
		{ID: "ws2-root", Label: "创建/恢复 root（283）", Order: 110},
		{ID: "ws2-accounts", Label: "常用账户方案（284）", Order: 120},
		{ID: "ws2-recommend", Label: "推荐配置一键应用（285）", Order: 130},
	}
	for _, menu := range menus {
		if err := app.RegisterMenu(menu); err != nil {
			return err
		}
	}
	screens := map[string]func() ScreenController{
		"ws2-database": func() ScreenController { return newWS2DatabaseScreen(registration.operatorID) },
		"ws2-root":     func() ScreenController { return newWS2RootScreen(registration.operatorID) },
		"ws2-accounts": func() ScreenController { return newWS2AccountsScreen(registration.operatorID) },
		"ws2-recommend": func() ScreenController {
			return newWS2RecommendScreen(registration.operatorID)
		},
	}
	for id, factory := range screens {
		if err := app.RegisterScreen(id, factory); err != nil {
			return err
		}
	}
	return nil
}

// ---------- 公共画面基座 ----------

type ws2ScreenBase struct {
	title      string
	operatorID string
	lines      []string
	status     string
	errText    string
	inputMode  bool
	inputLabel string
	inputValue string
	inputApply func(string) error
}

func (b *ws2ScreenBase) Title() string { return b.title }

func (b *ws2ScreenBase) setLines(lines ...string) { b.lines = lines }

func (b *ws2ScreenBase) setStatus(text string) { b.status = text; b.errText = "" }

func (b *ws2ScreenBase) setError(err error) {
	if err == nil {
		b.errText = ""
		return
	}
	b.errText = ws2PublicError(err)
	b.status = ""
}

func (b *ws2ScreenBase) beginInput(label, initial string, apply func(string) error) {
	b.inputMode = true
	b.inputLabel = label
	b.inputValue = initial
	b.inputApply = apply
}

func (b *ws2ScreenBase) render(ctx context.Context, canvas *Canvas) {
	width := canvas.Width() - 4
	if width < 20 {
		width = 20
	}
	top := 3
	draw := func(text string) {
		if top >= canvas.Height()-2 {
			return
		}
		canvas.Text(2, top, ws2Clip(text, width))
		top++
	}
	for _, line := range b.lines {
		draw(line)
	}
	if b.status != "" {
		draw("")
		draw("成功：" + b.status)
	}
	if b.errText != "" {
		draw("")
		draw("失败：" + b.errText)
	}
	if b.inputMode {
		draw("")
		draw(b.inputLabel + "：" + b.inputValue + "_")
		draw("Enter 确认，Esc 取消输入")
	}
	draw("")
	draw("Esc 返回")
}

// handleInput 处理输入模式；返回 handled=true 表示已消费按键。
func (b *ws2ScreenBase) handleInput(key Key) (handled bool, closeScreen bool) {
	if !b.inputMode {
		return false, false
	}
	switch key.Kind {
	case KeyEsc:
		b.inputMode = false
		b.inputValue = ""
		b.inputApply = nil
		b.setStatus("已取消输入")
	case KeyEnter:
		apply := b.inputApply
		value := strings.TrimSpace(b.inputValue)
		b.inputMode = false
		b.inputValue = ""
		b.inputApply = nil
		if apply != nil {
			if err := apply(value); err != nil {
				b.setError(err)
			} else {
				b.setStatus("已应用输入")
			}
		}
	case KeyRune:
		b.inputValue += string(key.Rune)
	case KeyBackspace:
		runes := []rune(b.inputValue)
		if len(runes) > 0 {
			b.inputValue = string(runes[:len(runes)-1])
		}
	default:
		// 其他导航键在输入模式忽略，避免误触。
	}
	return true, false
}

func (b *ws2ScreenBase) operator(ctx context.Context, session SessionView) string {
	if strings.TrimSpace(b.operatorID) != "" {
		return b.operatorID
	}
	instanceDir := ws2InstanceDir(session.ConfigPath)
	if instanceDir == "" {
		return ""
	}
	identity, err := LocalMaintenanceIdentity(instanceDir)
	if err != nil {
		b.setError(err)
		return ""
	}
	b.operatorID = strings.TrimSpace(identity.OSUser)
	return b.operatorID
}

func ws2InstanceDir(configPath string) string {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return ""
	}
	absolute := configPath
	if index := strings.LastIndexAny(absolute, "\\/"); index > 0 {
		return absolute[:index]
	}
	return ""
}

func ws2PublicError(err error) string {
	if err == nil {
		return ""
	}
	text := strings.TrimSpace(err.Error())
	text = strings.ReplaceAll(text, "\r", " ")
	text = strings.ReplaceAll(text, "\n", "；")
	if len([]rune(text)) > 360 {
		text = string([]rune(text)[:359]) + "…"
	}
	return text
}

func ws2Clip(text string, maxRunes int) string {
	text = strings.ReplaceAll(text, "\t", " ")
	if maxRunes <= 1 {
		return text
	}
	runes := []rune(text)
	if len(runes) <= maxRunes {
		return text
	}
	return string(runes[:maxRunes-1]) + "…"
}

// ---------- 282 数据库设置 ----------

type ws2DatabaseScreen struct {
	ws2ScreenBase
	plan   DBSetupPlan
	loaded bool
}

func newWS2DatabaseScreen(operatorID string) *ws2DatabaseScreen {
	return &ws2DatabaseScreen{ws2ScreenBase: ws2ScreenBase{title: "数据库设置与初始化（282）",
		operatorID: operatorID}}
}

func (s *ws2DatabaseScreen) Render(ctx context.Context, canvas *Canvas, session SessionView) {
	if !s.loaded {
		s.reload(session)
		s.loaded = true
	}
	s.ws2ScreenBase.render(ctx, canvas)
}

func (s *ws2DatabaseScreen) reload(session SessionView) {
	base := session.Detection.Config
	if !session.Detection.ConfigLoaded {
		base = config.Default()
	}
	input := dbSetupInputFromConfig(base)
	if strings.TrimSpace(input.SQLitePath) == "" {
		input.SQLitePath = "database/login.db"
	}
	plan, err := BuildDBSetupPlan(session.ConfigPath, base, input)
	s.plan = plan
	if err != nil {
		s.setError(err)
	} else {
		s.setStatus("已按当前配置生成数据库计划，可测试连接或初始化。")
	}
	s.refreshLines(session)
}

func (s *ws2DatabaseScreen) refreshLines(session SessionView) {
	database := s.plan.Config.Database
	runtime := "运行未接入（仅配置/适配代码）"
	if database.Driver.RuntimeSupported() {
		runtime = "SQLite 运行时已接入"
	}
	lines := []string{
		"当前状态：" + session.Detection.Kind.Label(),
		fmt.Sprintf("驱动：%s（%s）", database.Driver, runtime),
		"数据库：" + ws2ValueOr(session.ConfigPath, "（未选择配置路径）"),
	}
	if database.Driver == config.DatabaseDriverSQLite {
		lines = append(lines, "SQLite 路径："+ws2ValueOr(database.Path, "（空）"),
			fmt.Sprintf("WAL=%t，忙等待=%dms", database.WAL, database.BusyTimeoutMS))
	} else {
		lines = append(lines, fmt.Sprintf("主机：%s:%d  用户名：%s  库名：%s  模式：%s",
			database.Host, database.Port, database.Username, database.Database, database.TLSMode),
			"密码：受保护来源（不显示）")
	}
	lines = append(lines, s.plan.Notes...)
	lines = append(lines, "按键：t 测试连接  i 初始化/补迁移  s 保存数据库配置  d 切换驱动（配置演练）  e 修改 SQLite 路径")
	s.lines = lines
}

func ws2ValueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func (s *ws2DatabaseScreen) HandleKey(ctx context.Context, key Key,
	session SessionView) (bool, error) {
	if closeScreen, _ := s.ws2ScreenBase.handleInput(key); closeScreen {
		return true, nil
	}
	if s.inputMode {
		return false, nil
	}
	if key.Kind == KeyEsc {
		return true, nil
	}
	if key.Kind != KeyRune {
		return false, nil
	}
	switch key.Rune {
	case 't':
		status, err := TestDatabaseConnection(ctx, s.plan)
		if err != nil {
			s.setError(err)
		} else {
			s.setStatus(status.Message)
		}
		s.refreshLines(session)
	case 'i':
		operatorID := s.operator(ctx, session)
		if operatorID == "" {
			return false, nil
		}
		instanceDir := ws2InstanceDir(session.ConfigPath)
		input := dbSetupInputFromConfig(s.plan.Config)
		plan, err := BuildDBSetupPlan(session.ConfigPath, s.plan.Config, input)
		if err != nil {
			s.setError(err)
			return false, nil
		}
		result, err := InitializeDatabase(ctx, plan, DBInitOptions{InstanceDir: instanceDir,
			CreateMasterKey: true, OperatorID: operatorID, Purpose: "初始化数据库结构"})
		if err != nil {
			s.setError(err)
		} else {
			summary := fmt.Sprintf("数据库就绪：已应用 %d 项迁移（已是/已到最新），路径 %s",
				result.AppliedCount, result.DatabasePath)
			if result.AlreadyMigrated {
				summary = "数据库结构已是最新，无需重复迁移。"
			}
			s.setStatus(summary)
		}
		session.App.RefreshDetection(ctx)
		session = session.App.Session()
		s.loaded = false
		s.reload(session)
	case 's':
		draft, err := NewConfigDraft(session.ConfigPath, LoadConfigReport(session.ConfigPath).Raw)
		if err != nil {
			s.setError(err)
			return false, nil
		}
		if err := ApplyDBSetupToDraft(draft, s.plan); err != nil {
			s.setError(err)
			return false, nil
		}
		result, err := SaveConfigDraft(ctx, SaveRequest{Draft: draft,
			ConflictPolicy: ConflictFail, CreateBackup: true, Mode: 0o600})
		if err != nil {
			s.setError(err)
			return false, nil
		}
		s.setStatus(fmt.Sprintf("数据库配置已保存（%s）", result.ReloadResult))
		s.loaded = false
		session.App.RefreshDetection(ctx)
		session = session.App.Session()
		s.reload(session)
	case 'd':
		drivers := []config.DatabaseDriver{config.DatabaseDriverSQLite,
			config.DatabaseDriverMySQL, config.DatabaseDriverPostgreSQL,
			config.DatabaseDriverSQLServer}
		index := 0
		for i, driver := range drivers {
			if driver == s.plan.Config.Database.Driver {
				index = i
				break
			}
		}
		next := drivers[(index+1)%len(drivers)]
		input := dbSetupInputFromConfig(s.plan.Config)
		input.Driver = next
		if next != config.DatabaseDriverSQLite {
			input.SQLitePath = ""
			input.Host = "127.0.0.1"
			input.Port = 0
			input.Username = "evernightlogin"
			input.DatabaseName = "evernightlogin"
			input.TLSMode = next.DefaultTLSMode()
			input.Password = config.SecretSource{}
		}
		plan, err := BuildDBSetupPlan(session.ConfigPath, s.plan.Config, input)
		s.plan = plan
		if err != nil {
			s.setError(err)
		} else {
			s.setStatus("已切换驱动为配置演练；运行入口会 fail-closed，不会假装已连接。")
		}
		s.refreshLines(session)
	case 'e':
		s.beginInput("SQLite 数据库路径", s.plan.Config.Database.Path, func(value string) error {
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("路径不能为空")
			}
			input := dbSetupInputFromConfig(s.plan.Config)
			input.Driver = config.DatabaseDriverSQLite
			input.SQLitePath = value
			plan, err := BuildDBSetupPlan(session.ConfigPath, s.plan.Config, input)
			if err != nil {
				return err
			}
			s.plan = plan
			s.refreshLines(session)
			return nil
		})
	}
	return false, nil
}

// ---------- 283 root ----------

type ws2RootScreen struct {
	ws2ScreenBase
	loaded            bool
	generatedPassword string
}

func newWS2RootScreen(operatorID string) *ws2RootScreen {
	return &ws2RootScreen{ws2ScreenBase: ws2ScreenBase{title: "创建/恢复 root（283）",
		operatorID: operatorID}}
}

func (s *ws2RootScreen) Render(ctx context.Context, canvas *Canvas, session SessionView) {
	if !s.loaded {
		s.refresh(ctx, session)
		s.loaded = true
	}
	if strings.TrimSpace(s.generatedPassword) != "" {
		s.lines = append(s.lines, "", "一次性临时密码（仅本次显示）："+s.generatedPassword,
			"请立即记录后按任意键清除；关闭/重启后无法再读取。")
	}
	s.ws2ScreenBase.render(ctx, canvas)
}

func (s *ws2RootScreen) refresh(ctx context.Context, session SessionView) {
	status, err := InspectRootInitialization(ctx, session.Detection.Config, RootInitOptions{
		ConfigPath: session.ConfigPath, InstanceDir: ws2InstanceDir(session.ConfigPath)})
	lines := []string{"当前状态：" + session.Detection.Kind.Label()}
	if err != nil {
		lines = append(lines, "读取 root 状态失败："+ws2PublicError(err))
	} else {
		lines = append(lines,
			"初始化状态："+status.StateDescription,
			fmt.Sprintf("root 存在：%t，稳定 ID：%s，用户名：%s", status.RootExists,
				ws2ValueOr(status.RootUserID, "（无）"), ws2ValueOr(status.RootUsername, "（无）")))
	}
	lines = append(lines,
		"root 用户名固定保留名 root；创建后可在本地维护画面改名，稳定 ID 不变。",
		"按键：i 创建 root（自动生成强密码）  r 明确重设既有 root 密码（仅 setup_verified）")
	s.lines = lines
}

func (s *ws2RootScreen) HandleKey(ctx context.Context, key Key,
	session SessionView) (bool, error) {
	if closeScreen, _ := s.ws2ScreenBase.handleInput(key); closeScreen {
		return true, nil
	}
	if s.inputMode {
		return false, nil
	}
	if key.Kind == KeyEsc {
		return true, nil
	}
	if key.Kind != KeyRune {
		return false, nil
	}
	s.generatedPassword = ""
	operatorID := s.operator(ctx, session)
	if operatorID == "" {
		return false, nil
	}
	instanceDir := ws2InstanceDir(session.ConfigPath)
	options := RootInitOptions{ConfigPath: session.ConfigPath, InstanceDir: instanceDir,
		OperatorID: operatorID, Purpose: "创建或恢复唯一 root"}
	request := RootInitRequest{GeneratePassword: true, ResetExistingPassword: false}
	switch key.Rune {
	case 'i':
	case 'r':
		request.ResetExistingPassword = true
	default:
		return false, nil
	}
	result, err := InitializeRoot(ctx, session.Detection.Config, request, options)
	if err != nil {
		s.setError(err)
	} else {
		s.generatedPassword = result.GeneratedPassword
		s.setStatus(fmt.Sprintf("root 状态：%s；强认证待完成：%t；%s",
			result.StateDescription, result.PendingStrongAuth, result.Note))
	}
	s.loaded = false
	session.App.RefreshDetection(ctx)
	session = session.App.Session()
	s.refresh(ctx, session)
	s.loaded = true
	return false, nil
}

// ---------- 284 账户方案 ----------

type ws2AccountsScreen struct {
	ws2ScreenBase
	selected      int
	username      string
	loaded        bool
	generatedPass string
}

func newWS2AccountsScreen(operatorID string) *ws2AccountsScreen {
	return &ws2AccountsScreen{ws2ScreenBase: ws2ScreenBase{title: "常用账户方案（284）",
		operatorID: operatorID}, selected: 1}
}

func (s *ws2AccountsScreen) Render(ctx context.Context, canvas *Canvas, session SessionView) {
	if !s.loaded {
		s.refresh(ctx, session)
		s.loaded = true
	}
	if strings.TrimSpace(s.generatedPass) != "" {
		s.lines = append(s.lines, "", "一次性临时密码（仅本次显示）："+s.generatedPass,
			"首次登录必须改密；请记录后按任意键清除。")
	}
	s.ws2ScreenBase.render(ctx, canvas)
}

func (s *ws2AccountsScreen) refresh(ctx context.Context, session SessionView) {
	schemes := AccountSchemes()
	lines := []string{"当前状态：" + session.Detection.Kind.Label(),
		"账户类型（↑/↓ 选择，c 创建，u 改用户名，p 先安装系统预设）："}
	for index, scheme := range schemes {
		marker := "  "
		if index == s.selected {
			marker = "> "
		}
		state := "可用"
		if scheme.RootQualification {
			state = "特殊资格（不可批量创建）"
		} else if !scheme.Available {
			state = "不可用"
		}
		lines = append(lines, fmt.Sprintf("%s%s %s：%s", marker, scheme.Label,
			strings.Join(scheme.RoleKeys, ","), state))
		if index == s.selected && strings.TrimSpace(scheme.UnavailableReason) != "" {
			lines = append(lines, "    原因："+scheme.UnavailableReason)
		}
	}
	username := strings.TrimSpace(s.username)
	if username == "" {
		username = "（未设置）"
	}
	lines = append(lines, "待创建用户名："+username,
		"临时密码：自动生成，RequireChange=true（首次登录改密）")
	s.lines = lines
}

func (s *ws2AccountsScreen) move(delta int) {
	count := len(AccountSchemes())
	if count == 0 {
		return
	}
	s.selected = (s.selected + delta + count) % count
}

func (s *ws2AccountsScreen) HandleKey(ctx context.Context, key Key,
	session SessionView) (bool, error) {
	if closeScreen, _ := s.ws2ScreenBase.handleInput(key); closeScreen {
		return true, nil
	}
	if s.inputMode {
		return false, nil
	}
	switch key.Kind {
	case KeyEsc:
		return true, nil
	case KeyUp:
		s.move(-1)
		s.refresh(ctx, session)
		return false, nil
	case KeyDown:
		s.move(1)
		s.refresh(ctx, session)
		return false, nil
	case KeyRune:
	default:
		return false, nil
	}
	s.generatedPass = ""
	scheme := AccountSchemes()[s.selected]
	operatorID := s.operator(ctx, session)
	if operatorID == "" {
		return false, nil
	}
	switch key.Rune {
	case 'u':
		s.beginInput("账户用户名", s.username, func(value string) error {
			if len(value) < 3 {
				return fmt.Errorf("用户名至少 3 个字符")
			}
			s.username = value
			s.refresh(ctx, session)
			return nil
		})
	case 'p':
		instanceDir := ws2InstanceDir(session.ConfigPath)
		result, err := EnsureSystemPresets(ctx, session.Detection.Config, PresetInstallOptions{
			ConfigPath: session.ConfigPath, InstanceDir: instanceDir, OperatorID: operatorID,
			Purpose: "安装系统预设角色与权限"})
		if err != nil {
			s.setError(err)
		} else {
			s.setStatus(fmt.Sprintf("系统预设已安装/更新：创建角色 %d、权限 %d、组 %d",
				len(result.CreatedRoles), len(result.CreatedPermissions), len(result.CreatedGroups)))
		}
	case 'c':
		if !scheme.Available {
			s.setError(fmt.Errorf("%w: %s", ErrAccountSchemeUnavailable, scheme.UnavailableReason))
			return false, nil
		}
		username := strings.TrimSpace(s.username)
		if username == "" {
			s.setError(fmt.Errorf("请先按 u 设置用户名"))
			return false, nil
		}
		result, err := ApplyAccountScheme(ctx, session.Detection,
			[]AccountDraft{{Username: username, SchemeKey: scheme.Key, GeneratePassword: true}},
			AccountApplyOptions{ConfigPath: session.ConfigPath,
				InstanceDir: ws2InstanceDir(session.ConfigPath), OperatorID: operatorID,
				Purpose: "按账户方案创建账户"})
		if err != nil {
			s.setError(err)
		} else if len(result.Accounts) > 0 {
			item := result.Accounts[0]
			s.generatedPass = item.GeneratedPassword
			if item.SkippedExisting {
				s.setStatus(fmt.Sprintf("用户 %s 已存在；未改动既有口令/角色。", item.Username))
			} else {
				s.setStatus(fmt.Sprintf("已创建用户 %s（角色 %s），临时密码一次性展示。",
					item.Username, strings.Join(item.RoleKeys, ",")))
			}
		}
	}
	s.loaded = false
	s.refresh(ctx, session)
	s.loaded = true
	return false, nil
}

// ---------- 285 推荐配置 ----------

type ws2RecommendScreen struct {
	ws2ScreenBase
	selected int
	plan     *RecommendationPlan
	loaded   bool
}

func newWS2RecommendScreen(operatorID string) *ws2RecommendScreen {
	return &ws2RecommendScreen{ws2ScreenBase: ws2ScreenBase{title: "推荐配置一键应用（285）",
		operatorID: operatorID}}
}

func (s *ws2RecommendScreen) Render(ctx context.Context, canvas *Canvas, session SessionView) {
	if !s.loaded {
		s.preview(session)
		s.loaded = true
	}
	s.ws2ScreenBase.render(ctx, canvas)
}

func (s *ws2RecommendScreen) preview(session SessionView) {
	profiles := RecommendationProfiles()
	if s.selected >= len(profiles) {
		s.selected = 0
	}
	lines := []string{"当前状态：" + session.Detection.Kind.Label(),
		"推荐方案（↑/↓ 选择，p 预览，a 应用配置+可选补迁移）："}
	for index, profile := range profiles {
		marker := "  "
		if index == s.selected {
			marker = "> "
		}
		lines = append(lines, marker+profile.Label+"："+profile.Description)
	}
	plan, err := PlanRecommendation(session.ConfigPath, profiles[s.selected].Key)
	if err != nil {
		lines = append(lines, "预览失败："+ws2PublicError(err))
	} else {
		s.plan = &plan
		lines = append(lines, "待配置项：")
		if len(plan.Pending) == 0 {
			lines = append(lines, "  （无；外部能力仍按默认关闭）")
		}
		for _, item := range plan.Pending {
			lines = append(lines, "  - "+item)
		}
		lines = append(lines, "操作计划：")
		for _, step := range plan.Steps {
			lines = append(lines, "  - "+step)
		}
	}
	s.lines = lines
}

func (s *ws2RecommendScreen) HandleKey(ctx context.Context, key Key,
	session SessionView) (bool, error) {
	if closeScreen, _ := s.ws2ScreenBase.handleInput(key); closeScreen {
		return true, nil
	}
	if s.inputMode {
		return false, nil
	}
	switch key.Kind {
	case KeyEsc:
		return true, nil
	case KeyUp:
		s.selected = (s.selected - 1 + len(RecommendationProfiles())) % len(RecommendationProfiles())
		s.loaded = false
		s.preview(session)
		s.loaded = true
		return false, nil
	case KeyDown:
		s.selected = (s.selected + 1) % len(RecommendationProfiles())
		s.loaded = false
		s.preview(session)
		s.loaded = true
		return false, nil
	case KeyRune:
	default:
		return false, nil
	}
	if key.Rune == 'p' {
		s.loaded = false
		s.preview(session)
		s.loaded = true
		return false, nil
	}
	if key.Rune != 'a' || s.plan == nil {
		return false, nil
	}
	operatorID := s.operator(ctx, session)
	if operatorID == "" {
		return false, nil
	}
	result, err := ApplyRecommendation(ctx, *s.plan, RecommendationApplyOptions{
		ConflictPolicy: ConflictFail, CreateBackup: true, InitializeDatabase: true,
		DBInit: DBInitOptions{InstanceDir: ws2InstanceDir(session.ConfigPath),
			CreateMasterKey: true, OperatorID: operatorID, Purpose: "应用推荐配置并补迁移"}})
	if err != nil {
		s.setError(err)
	} else {
		s.setStatus(fmt.Sprintf("配置已保存；数据库迁移：%t", result.DatabaseInited))
	}
	s.loaded = false
	session.App.RefreshDetection(ctx)
	session = session.App.Session()
	s.preview(session)
	s.loaded = true
	return false, nil
}
