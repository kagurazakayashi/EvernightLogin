package setupconsole

// 步骤 295 的完整实例重新初始化画面与执行器（WS4，危险操作）。
//
// 流程严格受控：
//   1) 预览：精确路径/清除与保留清单/确认串（来自 295 模型）；
//   2) 执行：取得 281 维护排他锁（主服务运行中直接拒绝）→ 写可恢复执行日志 →
//      按 allow-list 清除（不跟随符号链接，不删除链接外目标）→ 复用 WS2 推荐
//      配置/数据库初始化/唯一 root 重建 → 检测并提示下一步；
//   3) 新 root 临时密码只在本次画面显示一次，不写日志/审计/文件。
//
// 不删除代码仓库、其他实例、保留路径；不假装备份成功（备份需先在 292 画面完成）。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/config"
)

// ReinitScreen 是完整重新初始化画面。
type ReinitScreen struct {
	keepMasterKey     bool
	oldCredentialsAck bool
	backupConfirmed   bool
	keptMasterKey     bool
	confirmText       string
	editing           bool
	buffer            string
	plan              *ReinitPlan
	pending           bool
	generatedPassword string
	message           string
	errText           string
}

// NewReinitScreen 创建重新初始化画面。
func NewReinitScreen() *ReinitScreen { return &ReinitScreen{} }

// Title 实现 ScreenController。
func (s *ReinitScreen) Title() string { return "完整实例重新初始化（步骤 295，危险）" }

// Render 实现 ScreenController。
func (s *ReinitScreen) Render(ctx context.Context, canvas *Canvas, session SessionView) {
	width := canvas.Width()
	if width < 40 {
		width = 40
	}
	y := 0
	line := func(text string) {
		if y < canvas.Height() {
			canvas.Text(0, y, ws4ClipText(text, width))
			y++
		}
	}
	canvas.Clear()
	configPath := session.Detection.ConfigPath
	line("实例配置：" + ws4ValueOr(configPath, "（未选择）"))
	line("数据库：" + ws4ValueOr(session.Detection.DatabasePath, "（未检测到）"))
	line(fmt.Sprintf("保留主密钥=%t（按 k 切换）；旧凭证失效确认=%t（按 c 切换）；已备份确认=%t（按 b 切换）",
		s.keepMasterKey, s.oldCredentialsAck, s.backupConfirmed))
	line(strings.Repeat("-", ws4MinInt(width, 60)))
	if s.plan != nil {
		line("清除清单：")
		for _, item := range s.plan.ClearItems {
			line("  - " + item.Label + "：" + item.Path)
		}
		line("保留清单：")
		for _, item := range s.plan.RetainItems {
			line("  + " + item.Label + "：" + item.Path)
		}
		line("确认串：" + s.plan.RequiredConfirm)
		for _, blocking := range s.plan.Blocking {
			line("阻塞：" + blocking)
		}
		line(s.plan.BackupNote)
	}
	if s.editing {
		line("输入确认串（Enter 确认，Esc 取消）：> " + ws4ClipText(s.buffer, width-2))
	}
	if s.errText != "" {
		line("错误：" + s.errText)
	}
	if s.message != "" {
		line(s.message)
	}
	if s.pending {
		line("再次按 x 确认执行完整重新初始化（其他键取消）")
	}
	if s.generatedPassword != "" {
		line("新 root 临时密码（只显示一次，请立即记录到受控位置）：" + s.generatedPassword)
	}
	line("p 预览计划；t 输入确认串；x 执行；Esc 返回")
}

// HandleKey 实现 ScreenController。
func (s *ReinitScreen) HandleKey(ctx context.Context, key Key, session SessionView) (bool, error) {
	if s.editing {
		s.handleEditKey(key)
		return false, nil
	}
	if key.Kind == KeyEsc {
		return true, nil
	}
	if key.Kind != KeyRune {
		s.pending = false
		return false, nil
	}
	switch key.Rune {
	case 'k', 'K':
		s.pending = false
		s.keepMasterKey = !s.keepMasterKey
		s.plan = nil
		s.message = "主密钥保留选项已切换，按 p 重新预览"
	case 'c', 'C':
		s.pending = false
		s.oldCredentialsAck = !s.oldCredentialsAck
		s.plan = nil
		s.message = "旧凭证失效确认已切换，按 p 重新预览"
	case 'b', 'B':
		s.pending = false
		s.backupConfirmed = !s.backupConfirmed
		s.plan = nil
		s.message = "备份确认已切换，按 p 重新预览"
	case 'p', 'P':
		s.pending = false
		s.preview(ctx, session)
	case 't', 'T':
		s.pending = false
		if s.plan == nil {
			s.errText = "请先按 p 预览"
			return false, nil
		}
		s.editing = true
		s.buffer = ""
	case 'x', 'X':
		if s.pending {
			s.pending = false
			s.execute(ctx, session)
			return false, nil
		}
		s.prepareExecute()
	}
	return false, nil
}

func (s *ReinitScreen) handleEditKey(key Key) {
	switch key.Kind {
	case KeyEsc:
		s.editing = false
		s.buffer = ""
	case KeyEnter:
		s.confirmText = strings.TrimSpace(s.buffer)
		s.editing = false
		s.buffer = ""
		if s.plan != nil && s.confirmText == s.plan.RequiredConfirm {
			s.message = "确认串匹配；按 x 准备执行"
		} else {
			s.errText = "确认串不匹配"
		}
	case KeyBackspace:
		runes := []rune(s.buffer)
		if len(runes) > 0 {
			s.buffer = string(runes[:len(runes)-1])
		}
	case KeyRune:
		s.buffer += string(key.Rune)
	}
}

// ws4ReinitPaths 从检测结果推导精确路径；不猜测配置里不存在的附件目录。
func ws4ReinitPaths(session SessionView) (ReinitPaths, error) {
	configPath := strings.TrimSpace(session.Detection.ConfigPath)
	if configPath == "" || !filepath.IsAbs(configPath) {
		return ReinitPaths{}, fmt.Errorf("未选择绝对配置路径，无法生成重新初始化计划")
	}
	instanceDir := filepath.Dir(configPath)
	databasePath := strings.TrimSpace(session.Detection.DatabasePath)
	if databasePath == "" {
		return ReinitPaths{}, fmt.Errorf("未检测到数据库路径，无法生成重新初始化计划")
	}
	if !filepath.IsAbs(databasePath) {
		databasePath = filepath.Join(instanceDir, databasePath)
	}
	databasePath = filepath.Clean(databasePath)
	dataDir := filepath.Dir(databasePath)
	stateDir := filepath.Join(filepath.Dir(dataDir), filepath.Base(dataDir)+"-maintenance")
	paths := ReinitPaths{
		InstanceDir: instanceDir, ConfigPath: filepath.Clean(configPath),
		DatabasePath: databasePath, StateDir: stateDir,
	}
	masterKey := filepath.Join(instanceDir, "master.key")
	if info, err := os.Lstat(masterKey); err == nil && info.Mode().IsRegular() {
		paths.MasterKeyFile = masterKey
	}
	return paths, nil
}

// ws4InstanceID 从实例目录派生稳定实例标识（本地维护身份同源指纹风格）。
func ws4InstanceID(instanceDir string) string {
	absolute, err := filepath.Abs(instanceDir)
	if err != nil {
		absolute = instanceDir
	}
	return "instance-" + ws4StableDigest(absolute)[:16]
}

func (s *ReinitScreen) preview(ctx context.Context, session SessionView) {
	s.errText = ""
	s.plan = nil
	s.generatedPassword = ""
	paths, err := ws4ReinitPaths(session)
	if err != nil {
		s.errText = err.Error()
		return
	}
	request := ReinitRequest{
		Paths: paths, InstanceID: ws4InstanceID(paths.InstanceDir),
		KeepMasterKey:             s.keepMasterKey,
		AcknowledgeOldCredentials: s.oldCredentialsAck,
		BackupAvailable:           s.backupConfirmed,
		ReservedPaths:             []string{},
	}
	plan, err := PlanFullReinit(request)
	if err != nil {
		s.errText = ws4SafeErrorText(err)
		return
	}
	// 预览阶段不要求确认串；执行前由用户逐字输入。
	plan.Blocking = removeBlockingPrefix(plan.Blocking, "确认串")
	plan.CanExecute = len(plan.Blocking) == 0
	s.plan = &plan
	s.message = "计划已生成；请按 t 逐字输入确认串后按 x 执行"
	_ = ctx
}

func (s *ReinitScreen) prepareExecute() {
	s.errText = ""
	if s.plan == nil {
		s.errText = "请先按 p 预览计划"
		return
	}
	if !s.plan.CanExecute {
		s.errText = "计划存在阻塞项，不能执行"
		return
	}
	if strings.TrimSpace(s.confirmText) != s.plan.RequiredConfirm {
		s.errText = "确认串不匹配：请按 t 逐字输入 " + s.plan.RequiredConfirm
		return
	}
	s.pending = true
	s.message = "执行将清空实例数据并重建数据库与唯一 root；需再次按 x 确认"
}

// ws4ReinitExecutor 使用 WS1 维护锁 + WS2 初始化能力执行计划。
type ws4ReinitExecutor struct{}

func (s *ReinitScreen) execute(ctx context.Context, session SessionView) {
	s.errText = ""
	if s.plan == nil {
		s.errText = "请先预览"
		return
	}
	result, err := (&ws4ReinitExecutor{}).ExecuteFullReinit(ctx, *s.plan, session)
	if err != nil {
		s.errText = ws4SafeErrorText(err)
		return
	}
	if result.GeneratedRootPassword != "" {
		s.generatedPassword = result.GeneratedRootPassword
	}
	s.message = "完整重新初始化完成：已重建数据库与唯一 root；请完成推荐配置/账户方案并按需启动服务"
	s.plan = nil
	s.confirmText = ""
}

// ExecuteFullReinit 执行计划（维护证据 + 锁、清除、WS2 重建、执行日志）。
func (e *ws4ReinitExecutor) ExecuteFullReinit(ctx context.Context, plan ReinitPlan,
	session SessionView) (ReinitResult, error) {
	instanceDir := plan.Paths.InstanceDir
	maint, err := openWS4Maint(instanceDir)
	if err != nil {
		return ReinitResult{}, err
	}
	if recordErr := maint.record(ctx, "instance.reinitialize", plan.InstanceID, "started", ""); recordErr != nil {
		return ReinitResult{}, fmt.Errorf("写入维护日志失败，已阻止重新初始化：%w", recordErr)
	}
	result, runErr := e.executeLocked(ctx, plan, session)
	if runErr != nil {
		_ = maint.record(ctx, "instance.reinitialize", plan.InstanceID, "failed", "E_REINIT")
		return result, runErr
	}
	if recordErr := maint.record(ctx, "instance.reinitialize", plan.InstanceID, "success", ""); recordErr != nil {
		return result, fmt.Errorf("重新初始化已完成但维护日志记录失败：%w", recordErr)
	}
	return result, nil
}

// executeLocked 在维护锁与执行日志下执行实际清除/重建（由 ExecuteFullReinit 包装）。
func (e *ws4ReinitExecutor) executeLocked(ctx context.Context, plan ReinitPlan,
	session SessionView) (ReinitResult, error) {
	instanceDir := plan.Paths.InstanceDir
	identity, err := LocalMaintenanceIdentity(instanceDir)
	if err != nil {
		return ReinitResult{}, err
	}
	operatorID := ws4OperatorID(identity)
	lock, err := AcquireMaintenanceLock(ctx, LockRequest{
		InstanceDir: instanceDir, DatabasePath: plan.Paths.DatabasePath,
		Purpose: "full instance reinitialize", Operator: identity,
	})
	if err != nil {
		return ReinitResult{}, err
	}
	defer func() { _ = lock.Release() }()
	journal, err := OpenReinitJournal(instanceDir)
	if err != nil {
		return ReinitResult{}, err
	}
	step := func(name string) error {
		if err := journal.Record(name, "started", ""); err != nil {
			return err
		}
		return nil
	}
	if err := step("clear-instance"); err != nil {
		return ReinitResult{}, err
	}
	cleared := 0
	for _, item := range plan.ClearItems {
		if err := reinitRemovePath(plan.Paths.InstanceDir, item.Path); err != nil {
			_ = journal.Record("clear-instance", "failed", "E_CLEAR")
			return ReinitResult{}, fmt.Errorf("清除 %s 失败：%w", item.Label, err)
		}
		cleared++
	}
	if err := journal.Record("clear-instance", "success", ""); err != nil {
		return ReinitResult{}, err
	}

	// 复用 WS2：重新写入推荐运行配置。
	if err := step("write-recommended-config"); err != nil {
		return ReinitResult{}, err
	}
	recommendation, err := PlanRecommendation(plan.Paths.ConfigPath, "local")
	if err != nil {
		_ = journal.Record("write-recommended-config", "failed", "E_CONFIG")
		return ReinitResult{}, fmt.Errorf("生成推荐配置失败：%w", err)
	}
	if _, err := ApplyRecommendation(ctx, recommendation, RecommendationApplyOptions{
		ConflictPolicy: ConflictUseDraft, CreateBackup: false, InitializeDatabase: false,
	}); err != nil {
		_ = journal.Record("write-recommended-config", "failed", "E_CONFIG")
		return ReinitResult{}, fmt.Errorf("写入推荐配置失败：%w", err)
	}
	if err := journal.Record("write-recommended-config", "success", ""); err != nil {
		return ReinitResult{}, err
	}

	cfg, err := config.Load(config.LoadOptions{YAMLFile: plan.Paths.ConfigPath})
	if err != nil {
		return ReinitResult{}, fmt.Errorf("重新加载配置失败：%w", err)
	}
	// 数据库初始化（幂等迁移 + 新主密钥）。
	if err := step("init-database"); err != nil {
		return ReinitResult{}, err
	}
	dbInput := DBSetupInput{
		Driver: cfg.Database.Driver, SQLitePath: cfg.Database.Path,
		WAL: cfg.Database.WAL, BusyTimeoutMS: cfg.Database.BusyTimeoutMS,
		Host: cfg.Database.Host, Port: cfg.Database.Port, Username: cfg.Database.Username,
		Password: cfg.Database.Password, DatabaseName: cfg.Database.Database,
		TLSMode: cfg.Database.TLSMode,
	}
	dbPlan, err := BuildDBSetupPlan(plan.Paths.ConfigPath, cfg, dbInput)
	if err != nil {
		_ = journal.Record("init-database", "failed", "E_DB")
		return ReinitResult{}, fmt.Errorf("数据库设置计划失败：%w", err)
	}
	if len(dbPlan.ConfigIssues) > 0 {
		return ReinitResult{}, fmt.Errorf("数据库设置未通过校验：%s", strings.Join(dbPlan.ConfigIssues, "；"))
	}
	dbResult, err := InitializeDatabase(ctx, dbPlan, DBInitOptions{
		InstanceDir: instanceDir, MasterKeyFile: plan.Paths.MasterKeyFile,
		CreateMasterKey: !plan.KeepMasterKey, OperatorID: operatorID,
		Purpose: "full instance reinitialize", Lock: lock,
	})
	if err != nil {
		_ = journal.Record("init-database", "failed", "E_DB")
		return ReinitResult{}, fmt.Errorf("数据库初始化失败：%w", err)
	}
	if err := journal.Record("init-database", "success", ""); err != nil {
		return ReinitResult{}, err
	}

	// 唯一 root 重建（临时密码只在内存返回一次）。
	if err := step("create-root"); err != nil {
		return ReinitResult{}, err
	}
	rootResult, err := InitializeRoot(ctx, cfg, RootInitRequest{GeneratePassword: true},
		RootInitOptions{
			ConfigPath: plan.Paths.ConfigPath, InstanceDir: instanceDir,
			OperatorID: operatorID, Purpose: "full instance reinitialize",
			MasterKeyFile: dbResult.MasterKeyFile, Lock: lock,
		})
	if err != nil {
		_ = journal.Record("create-root", "failed", "E_ROOT")
		return ReinitResult{}, fmt.Errorf("重建唯一 root 失败：%w", err)
	}
	if err := journal.Record("create-root", "success", ""); err != nil {
		return ReinitResult{}, err
	}
	return ReinitResult{
		Completed: true, InstanceID: plan.InstanceID, ClearedItems: cleared,
		KeptMasterKey: plan.KeepMasterKey, NewRootUserID: rootResult.RootUserID,
		GeneratedRootPassword: rootResult.GeneratedPassword,
		NextSteps: []string{
			"确认新 root 临时密码已保存到受控位置（本画面只显示一次）",
			"按需完成推荐配置/账户方案（WS2 画面）",
			"检查并启动服务（WS4 服务状态画面），确认 /healthz 就绪",
		},
	}, nil
}

// ws4StableDigest 返回稳定十六进制摘要（仅用于本地实例标识，不涉秘密）。
func ws4StableDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func reinitRemovePath(instanceDir, path string) error {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return nil
	}
	cleanPath := filepath.Clean(trimmed)
	info, err := os.Lstat(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	// 删除前再次确认：只允许实例目录内，或计划显式列出的外部数据库。
	inside := samePathOrInside(cleanPath, instanceDir)
	if !inside {
		// 外部数据库路径允许（计划已显式确认），但绝不能删除实例目录之外的非数据库对象。
		// 调用方只会在 AcknowledgeExternalPaths 时生成外部项。
		return fmt.Errorf("目标 %s 位于实例目录之外，拒绝删除", cleanPath)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return os.Remove(cleanPath) // 只删除链接本身，绝不跟随
	}
	if info.IsDir() {
		return os.RemoveAll(cleanPath)
	}
	return os.Remove(cleanPath)
}

func removeBlockingPrefix(blocking []string, fragment string) []string {
	filtered := make([]string, 0, len(blocking))
	for _, item := range blocking {
		if strings.Contains(item, fragment) {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}

// RegisterWS4ReinitScreen 注册 295 画面（由 RegisterWS4 调用）。
func RegisterWS4ReinitScreen(app *App) error {
	if app == nil {
		return errors.New("RegisterWS4ReinitScreen: app 不能为空")
	}
	if err := app.RegisterMenu(MenuEntry{
		ID: "ws4-reinit", Label: "完整实例重新初始化（危险）", Order: 550,
	}); err != nil {
		return err
	}
	return app.RegisterScreen("ws4-reinit", func() ScreenController {
		return NewReinitScreen()
	})
}
