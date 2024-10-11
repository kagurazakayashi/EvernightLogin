package setupconsole

// 步骤 293 的配置导入导出画面（WS4）：复用 292/293 模型与 WS1 280 保存接口。
//
// 画面只处理本地文件路径输入与确认；正式校验、秘密占位保护、原子保存、最后有效
// 副本与重载结果全部由 WS1 280 的 SaveConfigDraft 完成（ws4ConfigSaver 适配）。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ConfigIOScreen 是配置导入导出画面。
type ConfigIOScreen struct {
	configPath    string
	masterKeyFile string
	outputDir     string
	editing       string
	buffer        string
	exportPath    string
	importPath    string
	preview       *ConfigImportPreview
	confirmText   string
	pendingApply  bool
	message       string
	errText       string
}

// NewConfigIOScreen 创建配置导入导出画面。
func NewConfigIOScreen() *ConfigIOScreen { return &ConfigIOScreen{} }

// Title 实现 ScreenController。
func (s *ConfigIOScreen) Title() string { return "配置导入导出（步骤 293）" }

// Render 实现 ScreenController。
func (s *ConfigIOScreen) Render(ctx context.Context, canvas *Canvas, session SessionView) {
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
	configPath := s.configPath
	if configPath == "" {
		configPath = session.Detection.ConfigPath
	}
	outputDir := s.outputDir
	if outputDir == "" && configPath != "" {
		outputDir = filepath.Dir(configPath)
	}
	line("当前配置：" + ws4ValueOr(configPath, "（未选择配置）"))
	line("导出目录：" + ws4ValueOr(outputDir, "（未设置，按 o 编辑）"))
	line("主密钥：" + ws4ValueOr(s.masterKeyFile, "（默认实例目录 master.key；按 m 编辑）"))
	line("导入路径：" + ws4ValueOr(s.importPath, "（按 i 输入）"))
	line(strings.Repeat("-", ws4MinInt(width, 60)))
	if s.exportPath != "" {
		line("最近导出：" + s.exportPath)
	}
	if s.preview != nil {
		line(fmt.Sprintf("导入预览：来源=%s 可应用=%t 变更字段=%d",
			s.preview.SourceKind, s.preview.CanApply, len(s.preview.ChangedPaths)))
		if s.preview.DatabasePathChange != "" {
			line("数据库变化：" + s.preview.DatabasePathChange)
		}
		if len(s.preview.Blocking) > 0 {
			line("阻塞：" + strings.Join(s.preview.Blocking, "；"))
		}
		for _, warning := range s.preview.Warnings {
			line("提示：" + warning)
		}
		line("确认串：" + s.preview.RequiredConfirm)
	}
	if s.errText != "" {
		line("错误：" + s.errText)
	}
	if s.message != "" {
		line(s.message)
	}
	if s.pendingApply {
		line("再次按 a 确认应用导入（其他键取消）")
	}
	if s.editing != "" {
		line("输入中：> " + ws4ClipText(s.buffer, width-2))
	}
	line("e 导出脱敏 YAML；x 导出加密敏感包；i 输入导入路径；p 预览；a 应用；o 导出目录；m 主密钥；Esc 返回")
}

// HandleKey 实现 ScreenController。
func (s *ConfigIOScreen) HandleKey(ctx context.Context, key Key, session SessionView) (bool, error) {
	if s.editing != "" {
		s.handleEditKey(key)
		return false, nil
	}
	if key.Kind == KeyEsc {
		return true, nil
	}
	if key.Kind != KeyRune {
		s.pendingApply = false
		return false, nil
	}
	switch key.Rune {
	case 'e', 'E':
		s.pendingApply = false
		s.exportMasked(session)
	case 'x', 'X':
		s.pendingApply = false
		s.exportEncrypted(ctx, session)
	case 'i', 'I':
		s.pendingApply = false
		s.editing = "import"
		s.buffer = s.importPath
	case 'p', 'P':
		s.pendingApply = false
		s.previewImport(ctx, session)
	case 'a', 'A':
		if s.pendingApply {
			s.pendingApply = false
			s.applyImport(ctx, session)
			return false, nil
		}
		s.prepareApply()
	case 'o', 'O':
		s.pendingApply = false
		s.editing = "output"
		s.buffer = s.outputDir
	case 'm', 'M':
		s.pendingApply = false
		s.editing = "master"
		s.buffer = s.masterKeyFile
	}
	return false, nil
}

func (s *ConfigIOScreen) handleEditKey(key Key) {
	switch key.Kind {
	case KeyEsc:
		s.editing = ""
		s.buffer = ""
	case KeyEnter:
		value := strings.TrimSpace(s.buffer)
		switch s.editing {
		case "import":
			s.importPath = value
			s.preview = nil
			s.message = "导入路径已更新，按 p 预览"
		case "output":
			s.outputDir = value
			s.message = "导出目录已更新"
		case "master":
			s.masterKeyFile = value
			s.message = "主密钥路径已更新"
		}
		s.editing = ""
		s.buffer = ""
	case KeyBackspace:
		runes := []rune(s.buffer)
		if len(runes) > 0 {
			s.buffer = string(runes[:len(runes)-1])
		}
	case KeyRune:
		s.buffer += string(key.Rune)
	}
}

func (s *ConfigIOScreen) resolvePaths(session SessionView) (configPath, outputDir string) {
	configPath = s.configPath
	if configPath == "" {
		configPath = session.Detection.ConfigPath
	}
	outputDir = s.outputDir
	if outputDir == "" && configPath != "" {
		outputDir = filepath.Dir(configPath)
	}
	if s.masterKeyFile == "" && configPath != "" {
		candidate := filepath.Join(filepath.Dir(configPath), "master.key")
		if info, err := os.Lstat(candidate); err == nil && info.Mode().IsRegular() {
			s.masterKeyFile = candidate
		}
	}
	return configPath, outputDir
}

func (s *ConfigIOScreen) nextExportPath(outputDir, suffix string) string {
	name := "masked-config-" + time.Now().Format("20060102-150405") + suffix
	return filepath.Join(outputDir, name)
}

func (s *ConfigIOScreen) exportMasked(session SessionView) {
	s.errText = ""
	configPath, outputDir := s.resolvePaths(session)
	if configPath == "" || outputDir == "" {
		s.errText = "未选择配置或导出目录"
		return
	}
	result, err := ExportMaskedConfig(ConfigExportOptions{
		ConfigPath: configPath, OutputPath: s.nextExportPath(outputDir, ".yaml"),
	})
	if err != nil {
		s.errText = ws4SafeErrorText(err)
		return
	}
	s.exportPath = result.OutputPath
	s.message = fmt.Sprintf("已导出脱敏 YAML（%d 字节，脱敏字段 %d 个）", result.SizeBytes, len(result.Masked))
}

func (s *ConfigIOScreen) exportEncrypted(ctx context.Context, session SessionView) {
	s.errText = ""
	configPath, outputDir := s.resolvePaths(session)
	if configPath == "" || outputDir == "" {
		s.errText = "未选择配置或导出目录"
		return
	}
	if s.masterKeyFile == "" {
		s.errText = "加密敏感包需要主密钥文件：按 m 设置"
		return
	}
	summary, err := ExportEncryptedConfigPackage(ctx, ConfigExportOptions{
		ConfigPath: configPath, OutputPath: s.nextExportPath(outputDir, ".lncfg"),
		MasterKeyFile: s.masterKeyFile, Operator: "login-setup",
	})
	if err != nil {
		s.errText = ws4SafeErrorText(err)
		return
	}
	s.exportPath = summary.Path
	s.message = fmt.Sprintf("已导出加密敏感配置包（%d 字节，sha256=%s…）",
		summary.PackageSize, firstChars(summary.PackageSHA256, 12))
}

func (s *ConfigIOScreen) previewImport(ctx context.Context, session SessionView) {
	s.errText = ""
	s.preview = nil
	configPath, _ := s.resolvePaths(session)
	if configPath == "" || s.importPath == "" {
		s.errText = "需先选择当前配置并输入导入路径"
		return
	}
	preview, err := PreviewConfigImport(ctx, ConfigImportRequest{
		ImportPath: s.importPath, CurrentConfigPath: configPath,
		MasterKeyFile: s.masterKeyFile,
	})
	if err != nil {
		s.errText = ws4SafeErrorText(err)
		return
	}
	s.preview = &preview
	s.message = "预览完成；确认串为 " + preview.RequiredConfirm
}

func (s *ConfigIOScreen) prepareApply() {
	if s.preview == nil {
		s.errText = "请先按 p 预览导入"
		return
	}
	if !s.preview.CanApply {
		s.errText = "预览存在阻塞项，不能应用"
		return
	}
	s.pendingApply = true
	s.message = "应用将原子保存配置并保留最后有效副本；需再次按 a 确认"
}

func (s *ConfigIOScreen) applyImport(ctx context.Context, session SessionView) {
	s.errText = ""
	if s.preview == nil {
		s.errText = "请先预览导入"
		return
	}
	configPath, _ := s.resolvePaths(session)
	instanceDir, err := ws4InstanceDirForConfig(configPath)
	if err != nil {
		s.errText = ws4SafeErrorText(err)
		return
	}
	maint, err := openWS4Maint(instanceDir)
	if err != nil {
		s.errText = ws4SafeErrorText(err)
		return
	}
	var outcome ConfigImportApplyResult
	_, err = maint.runDestructive(ctx, session.Detection.DatabasePath, "config.import",
		func() (string, error) {
			applied, applyErr := ApplyConfigImport(ctx, ws4ConfigSaver{}, ConfigImportRequest{
				ImportPath: s.importPath, CurrentConfigPath: configPath,
				MasterKeyFile: s.masterKeyFile, ConfirmText: s.preview.RequiredConfirm,
				ConflictPolicy: string(ConflictFail),
			})
			if applyErr != nil {
				return "config", applyErr
			}
			outcome = applied
			return "config", nil
		})
	if err != nil {
		s.errText = ws4SafeErrorText(err)
		return
	}
	s.message = "配置已保存；服务重载结果：" + ws4ValueOr(outcome.Outcome.ReloadResult, "not-requested") +
		"（文件保存成功不等于已生效；维护日志已记录）"
	s.preview = nil
}

// ws4ConfigSaver 把 WS4 的 ConfigSaver 接口适配到 WS1 280 SaveConfigDraft。
//
// 用新原文构造草稿并显式设置 BaseDigest，使外部修改冲突检测仍由 280 完成；
// 不用占位/空值覆盖真实秘密（该保护在 SaveConfigDraft 内）。
type ws4ConfigSaver struct{}

// SaveConfig 实现 ConfigSaver。
func (ws4ConfigSaver) SaveConfig(ctx context.Context, request ConfigSaveRequest) (ConfigSaveOutcome, error) {
	draft, err := NewConfigDraft(request.Path, request.NewRaw)
	if err != nil {
		return ConfigSaveOutcome{}, err
	}
	sum := sha256.Sum256(request.BaseRaw)
	draft.BaseDigest = hex.EncodeToString(sum[:])
	policy := ConflictPolicy(strings.TrimSpace(request.ConflictPolicy))
	if policy == "" {
		policy = ConflictFail
	}
	result, err := SaveConfigDraft(ctx, SaveRequest{
		Draft: draft, ConflictPolicy: policy, CreateBackup: request.CreateBackup, Mode: 0o600,
	})
	outcome := ConfigSaveOutcome{
		Saved: result.Saved, BackupPath: result.BackupPath, FileDigest: result.FileDigest,
		ConfigValid: result.ConfigValid, ReloadResult: result.ReloadResult, Conflict: result.Conflict,
	}
	if err != nil {
		return outcome, err
	}
	return outcome, nil
}

// firstChars 返回字符串前 n 个字符（用于显示摘要前缀）。
func firstChars(text string, n int) string {
	runes := []rune(text)
	if len(runes) <= n {
		return text
	}
	return string(runes[:n])
}

// RegisterWS4ConfigIOScreen 注册 293 画面（由 RegisterWS4 调用）。
func RegisterWS4ConfigIOScreen(app *App) error {
	if app == nil {
		return errors.New("RegisterWS4ConfigIOScreen: app 不能为空")
	}
	if err := app.RegisterMenu(MenuEntry{
		ID: "ws4-configio", Label: "配置导入导出（脱敏/加密包）", Order: 530,
	}); err != nil {
		return err
	}
	return app.RegisterScreen("ws4-configio", func() ScreenController {
		return NewConfigIOScreen()
	})
}
