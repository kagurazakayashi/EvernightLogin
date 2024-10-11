package setupconsole

// 步骤 294 的两类恢复画面（WS4）。
//
//   - 运行时配置恢复：用 WS2 的推荐配置方案生成推荐原文，再用 294 模型做“保留
//     数据库/秘密/访问地址”的差异预览，最后经 WS1 280 原子保存；
//   - 预设角色权限恢复：通过 WS3 本地维护会话（OpenLocalRuntime）使用 289 的
//     预览/恢复窄方法，恢复预设角色组合；默认不碰自定义角色/账户口令/业务数据。

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"
)

// WS4Option 是 RegisterWS4 的可选装配项。
type WS4Option func(*ws4Options) error

type ws4Options struct {
	openSession WS3SessionOpener
}

// WithWS4SessionOpener 注入 WS3 本地维护会话 opener（cmd/login-setup 装配）。
//
// 未注入时 RegisterWS4 使用与入口一致的内置装配（OS 维护身份 + 写门闸 +
// OpenLocalRuntime）；不来自 HTTP 请求或可序列化令牌。
func WithWS4SessionOpener(open WS3SessionOpener) WS4Option {
	return func(options *ws4Options) error {
		options.openSession = open
		return nil
	}
}

// ws4DefaultSessionOpener 构造与 cmd/login-setup 语义一致的本地维护会话 opener。
func ws4DefaultSessionOpener(app *App) WS3SessionOpener {
	return func(ctx context.Context) (WS3Session, error) {
		if app == nil {
			return nil, errors.New("控制台未初始化")
		}
		detection := app.RefreshDetection(ctx)
		configPath := strings.TrimSpace(detection.ConfigPath)
		if configPath == "" {
			return nil, errors.New("未选择实例配置路径，无法打开本地维护会话")
		}
		instanceDir := filepath.Dir(configPath)
		identity, err := LocalMaintenanceIdentity(instanceDir)
		if err != nil {
			return nil, err
		}
		databasePath := strings.TrimSpace(detection.DatabasePath)
		if databasePath != "" && !filepath.IsAbs(databasePath) {
			databasePath = filepath.Join(instanceDir, databasePath)
		}
		guard := func(guardCtx context.Context) (func(), error) {
			lock, err := AcquireMaintenanceLock(guardCtx, LockRequest{
				InstanceDir: instanceDir, DatabasePath: databasePath,
				Purpose: "local maintenance write transaction", Operator: identity,
			})
			if err != nil {
				return nil, err
			}
			return func() { _ = lock.Release() }, nil
		}
		return OpenLocalRuntime(ctx, detection, LocalRuntimeOptions{
			ConfigPath: configPath, OperatorID: ws4OperatorID(identity), WriteGuard: guard,
		})
	}
}

// ws4OperatorID 把 OS 维护身份转成稳定 ASCII 审计标识（<=128，无控制字符）。
func ws4OperatorID(identity MaintenanceIdentity) string {
	sanitize := func(value string) string {
		var builder strings.Builder
		for _, character := range strings.TrimSpace(value) {
			if character >= 0x20 && character <= 0x7e {
				builder.WriteRune(character)
			} else {
				builder.WriteRune('_')
			}
		}
		trimmed := strings.Trim(builder.String(), "_")
		if trimmed == "" {
			return "unknown"
		}
		return trimmed
	}
	operator := "local-os:" + sanitize(identity.OSUser) + "@" + sanitize(identity.Machine)
	if len(operator) > 128 {
		operator = operator[:128]
	}
	return operator
}

// RecoverScreen 是 294 两类恢复画面。
type RecoverScreen struct {
	openSession WS3SessionOpener
	profiles    []RecommendationProfile
	profile     int
	runtimePlan *RuntimeConfigRecoveryPlan
	presetPlan  *PresetRoleRecoveryPlan
	presetDiff  []LocalPresetDiff
	pending     string
	message     string
	errText     string
}

// NewRecoverScreen 创建恢复画面。
func NewRecoverScreen(open WS3SessionOpener) *RecoverScreen {
	return &RecoverScreen{openSession: open, profiles: RecommendationProfiles()}
}

// Title 实现 ScreenController。
func (s *RecoverScreen) Title() string { return "保留数据的恢复（步骤 294）" }

// Render 实现 ScreenController。
func (s *RecoverScreen) Render(ctx context.Context, canvas *Canvas, session SessionView) {
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
	line("配置：" + ws4ValueOr(session.Detection.ConfigPath, "（未选择）"))
	if len(s.profiles) > 0 {
		profile := s.profiles[s.profile%len(s.profiles)]
		line("推荐方案：" + profile.Key + " - " + profile.Label + "（按 p 切换）")
	}
	line(strings.Repeat("-", ws4MinInt(width, 60)))
	if s.runtimePlan != nil {
		line("运行配置恢复预览：保留段=" + strings.Join(s.runtimePlan.RetainedSections, ",") +
			"；重置段=" + strings.Join(s.runtimePlan.ResetSections, ","))
		line(fmt.Sprintf("幂等=%t 可应用=%t 变更字段=%d",
			s.runtimePlan.Idempotent, s.runtimePlan.CanApply, len(s.runtimePlan.ChangedPaths)))
		for _, blocking := range s.runtimePlan.Blocking {
			line("阻塞：" + blocking)
		}
		line("确认串：" + s.runtimePlan.RequiredConfirm)
	}
	if s.presetPlan != nil {
		preview := s.presetPlan.Preview
		line(fmt.Sprintf("预设角色预览：预设=%s 幂等=%t 可应用=%t 角色=%d 自定义未动=%d",
			preview.PresetVersion, preview.Idempotent, s.presetPlan.CanApply,
			len(preview.Roles), len(preview.CustomRoles)))
		for _, role := range preview.Roles {
			line(fmt.Sprintf("  %s %s +%d -%d", role.Role, role.Action, len(role.Added), len(role.Removed)))
		}
		for _, blocking := range preview.Blocking {
			line("阻塞：" + blocking)
		}
		line("确认串：" + s.presetPlan.RequiredConfirm)
	}
	if s.errText != "" {
		line("错误：" + s.errText)
	}
	if s.message != "" {
		line(s.message)
	}
	if s.pending != "" {
		line("再次按 " + s.pending + " 确认执行（其他键取消）")
	}
	line("1 预览运行配置恢复；2 应用；3 预览预设角色恢复；4 应用；p 切换推荐方案；Esc 返回")
}

// HandleKey 实现 ScreenController。
func (s *RecoverScreen) HandleKey(ctx context.Context, key Key, session SessionView) (bool, error) {
	if key.Kind == KeyEsc {
		return true, nil
	}
	if key.Kind != KeyRune {
		s.pending = ""
		return false, nil
	}
	switch key.Rune {
	case 'p', 'P':
		s.pending = ""
		if len(s.profiles) > 0 {
			s.profile = (s.profile + 1) % len(s.profiles)
			s.runtimePlan = nil
			s.message = "推荐方案已切换，按 1 重新预览"
		}
	case '1':
		s.pending = ""
		s.previewRuntime(session)
	case '2':
		if s.pending == "2" {
			s.pending = ""
			s.applyRuntime(ctx, session)
			return false, nil
		}
		s.requestApply("2", s.runtimePlan != nil && s.runtimePlan.CanApply,
			"运行配置恢复")
	case '3':
		s.pending = ""
		s.previewPreset(ctx, session)
	case '4':
		if s.pending == "4" {
			s.pending = ""
			s.applyPreset(ctx, session)
			return false, nil
		}
		s.requestApply("4", s.presetPlan != nil && s.presetPlan.CanApply,
			"预设角色恢复")
	}
	return false, nil
}

func (s *RecoverScreen) requestApply(key string, canApply bool, label string) {
	s.errText = ""
	if !canApply {
		s.errText = label + "需要先预览且无阻塞项"
		return
	}
	s.pending = key
	s.message = label + "将写入真实配置/数据库；请再次确认"
}

func (s *RecoverScreen) previewRuntime(session SessionView) {
	s.errText = ""
	s.runtimePlan = nil
	configPath := session.Detection.ConfigPath
	if configPath == "" {
		s.errText = "未选择配置"
		return
	}
	_ = configPath
	if len(s.profiles) == 0 {
		s.errText = "没有可用推荐配置方案"
		return
	}
	profile := s.profiles[s.profile%len(s.profiles)]
	currentRaw, _, err := readConfigSource(configPath)
	if err != nil {
		s.errText = ws4SafeErrorText(err)
		return
	}
	recommendation, err := PlanRecommendation(configPath, profile.Key)
	if err != nil {
		s.errText = ws4SafeErrorText(err)
		return
	}
	plan, err := BuildRuntimeConfigRecoveryPlan(configPath, currentRaw, recommendation.Raw)
	if err != nil {
		s.errText = ws4SafeErrorText(err)
		return
	}
	s.runtimePlan = &plan
	s.message = "运行配置恢复预览完成"
}

func (s *RecoverScreen) applyRuntime(ctx context.Context, session SessionView) {
	s.errText = ""
	if s.runtimePlan == nil {
		s.errText = "请先预览"
		return
	}
	configPath := session.Detection.ConfigPath
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
	var outcome ConfigSaveOutcome
	_, err = maint.runDestructive(ctx, session.Detection.DatabasePath, "config.restore-recommended",
		func() (string, error) {
			saved, saveErr := ApplyRuntimeConfigRecovery(ctx, ws4ConfigSaver{}, *s.runtimePlan,
				s.runtimePlan.RequiredConfirm)
			if saveErr != nil {
				return "config", saveErr
			}
			outcome = saved
			return "config", nil
		})
	if err != nil {
		s.errText = ws4SafeErrorText(err)
		return
	}
	s.message = "运行配置已保存；重载结果：" + ws4ValueOr(outcome.ReloadResult, "not-requested") +
		"（数据库/主密钥/访问地址已保留；维护日志已记录）"
	s.runtimePlan = nil
}

func (s *RecoverScreen) previewPreset(ctx context.Context, session SessionView) {
	s.errText = ""
	s.presetPlan = nil
	s.presetDiff = nil
	if s.openSession == nil {
		s.errText = "本地维护会话未装配，无法预览预设角色恢复"
		return
	}
	maintenance, err := s.openSession(ctx)
	if err != nil {
		s.errText = "打开本地维护会话失败：" + ws4SafeErrorText(err)
		return
	}
	defer func() { _ = maintenance.Close(ctx) }()
	if maintenance.Services() == nil || maintenance.Services().RBAC == nil {
		s.errText = "本地维护会话未提供角色维护能力"
		return
	}
	rbac := maintenance.Services().RBAC
	roles, _, err := rbac.ListRoles(ctx, LocalPageRequest{Limit: 100}, "system")
	if err != nil {
		s.errText = ws4SafeErrorText(err)
		return
	}
	preview := PresetRoleRecoveryPreview{PresetVersion: "system-presets"}
	diffs := make([]LocalPresetDiff, 0, len(roles))
	for _, role := range roles {
		if !role.Builtin {
			preview.CustomRoles = append(preview.CustomRoles, role.Key)
			continue
		}
		diff, err := rbac.PreviewPresetRestore(ctx, "system", role.Key)
		if err != nil {
			preview.Blocking = append(preview.Blocking,
				"预览预设角色 "+role.Key+" 失败："+ws4SafeErrorText(err))
			continue
		}
		diffs = append(diffs, diff)
		if len(diff.Add) == 0 && len(diff.Remove) == 0 {
			preview.Roles = append(preview.Roles, PresetRoleChange{
				Role: role.Key, Action: "unchanged",
				Detail: fmt.Sprintf("当前 %d/%d 个权限组合", diff.CurrentComps, diff.PresetComps),
			})
			continue
		}
		preview.Roles = append(preview.Roles, PresetRoleChange{
			Role: role.Key, Action: "update", Added: append([]string(nil), diff.Add...),
			Removed: append([]string(nil), diff.Remove...),
			Detail:  fmt.Sprintf("影响 %d 项，当前 %d → 预设 %d", diff.Affected, diff.CurrentComps, diff.PresetComps),
		})
	}
	preview.Idempotent = true
	for _, role := range preview.Roles {
		if role.Action != "unchanged" {
			preview.Idempotent = false
		}
	}
	if len(preview.CustomRoles) > 0 {
		preview.Warnings = append(preview.Warnings,
			"自定义角色保持不变："+strings.Join(preview.CustomRoles, ", "))
	}
	plan := PresetRoleRecoveryPlan{
		Preview: preview, RequiredConfirm: presetRoleRecoveryConfirm,
		CanApply: len(preview.Blocking) == 0 && !preview.Idempotent,
	}
	s.presetPlan = &plan
	s.presetDiff = diffs
	s.message = "预设角色预览完成（未修改任何数据）"
}

func (s *RecoverScreen) applyPreset(ctx context.Context, session SessionView) {
	s.errText = ""
	if s.presetPlan == nil || s.openSession == nil {
		s.errText = "请先预览预设角色恢复"
		return
	}
	maintenance, err := s.openSession(ctx)
	if err != nil {
		s.errText = "打开本地维护会话失败：" + ws4SafeErrorText(err)
		return
	}
	defer func() { _ = maintenance.Close(ctx) }()
	if maintenance.Services() == nil || maintenance.Services().RBAC == nil {
		s.errText = "本地维护会话未提供角色维护能力"
		return
	}
	rbac := maintenance.Services().RBAC
	instanceDir, err := ws4InstanceDirForConfig(session.Detection.ConfigPath)
	if err != nil {
		s.errText = ws4SafeErrorText(err)
		return
	}
	maint, err := openWS4Maint(instanceDir)
	if err != nil {
		s.errText = ws4SafeErrorText(err)
		return
	}
	var restored int
	_, err = maint.runWithEvidence(ctx, "roles.restore-presets", func() (string, error) {
		for _, diff := range s.presetDiff {
			if len(diff.Add) == 0 && len(diff.Remove) == 0 {
				continue
			}
			if err := rbac.RestorePreset(ctx, diff, true); err != nil {
				return fmt.Sprintf("restored=%d", restored),
					fmt.Errorf("恢复预设角色失败（可重试，已恢复 %d 项）：%w", restored, err)
			}
			restored++
		}
		return fmt.Sprintf("restored=%d", restored), nil
	})
	if err != nil {
		s.errText = ws4SafeErrorText(err)
		return
	}
	s.message = fmt.Sprintf("预设角色恢复完成：恢复 %d 个预设角色；自定义角色未改动；维护日志已记录", restored)
	s.presetPlan = nil
	s.presetDiff = nil
}

// RegisterWS4RecoverScreen 注册 294 画面（由 RegisterWS4 调用）。
func RegisterWS4RecoverScreen(app *App, open WS3SessionOpener) error {
	if app == nil {
		return errors.New("RegisterWS4RecoverScreen: app 不能为空")
	}
	if err := app.RegisterMenu(MenuEntry{
		ID: "ws4-recover", Label: "保留数据的恢复（配置/预设）", Order: 540,
	}); err != nil {
		return err
	}
	return app.RegisterScreen("ws4-recover", func() ScreenController {
		return NewRecoverScreen(open)
	})
}

// 保留 unicode 导入用于中文内容长度检查（防止未来改动误删）。
var _ = unicode.IsPrint
