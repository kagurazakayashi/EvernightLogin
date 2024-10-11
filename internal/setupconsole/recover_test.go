package setupconsole

// 步骤 294 的定向测试：保留数据的两类恢复计划、确认与幂等（不写盘、不改库）。

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ws4RecoveryConfigs(t *testing.T) (currentRaw, recommendedRaw []byte) {
	t.Helper()
	currentDB := filepath.ToSlash(filepath.Join(t.TempDir(), "data", "login.db"))
	current := ws4ConfigWithSecrets(t, currentDB)
	current = strings.Replace(current, "level: info", "level: warn", 1)
	recommended := strings.ReplaceAll(current, currentDB, "P:/go/tmp/ws4/default/login.db")
	recommended = strings.Replace(recommended, "level: warn", "level: info", 1)
	return []byte(current), []byte(recommended)
}

func TestBuildRuntimeConfigRecoveryPlanRetainsDataAndSecrets(t *testing.T) {
	current, recommended := ws4RecoveryConfigs(t)
	plan, err := BuildRuntimeConfigRecoveryPlan("P:/go/tmp/ws4/login.yaml", current, recommended)
	if err != nil {
		t.Fatalf("生成运行配置恢复计划失败：%v", err)
	}
	if !plan.CanApply {
		t.Fatalf("合法计划应可应用，阻塞：%v（%+v）", plan.Blocking, plan.ProposedReport.Issues)
	}
	if plan.RequiredConfirm != runtimeConfigRecoveryConfirm {
		t.Fatalf("确认串错误：%s", plan.RequiredConfirm)
	}
	text := string(plan.Proposed)
	if !strings.Contains(text, "currentDB") && !strings.Contains(text, "login.db") {
		t.Fatal("database 段必须保留当前数据库定位")
	}
	if !strings.Contains(text, "WS4_TEST_MASTER_KEY") {
		t.Fatal("secrets 段必须保留当前主密钥来源")
	}
	if !strings.Contains(text, "level: info") {
		t.Fatal("logging 段应按推荐配置重置")
	}
	if len(plan.ResetSections) == 0 {
		t.Fatal("应列出被重置的段")
	}
	if !hasBlockingContaining(plan.RetainedSections, "database") {
		t.Fatalf("应声明 database 为保留段：%v", plan.RetainedSections)
	}
}

func TestBuildRuntimeConfigRecoveryPlanIdempotentAndBlocking(t *testing.T) {
	_, recommended := ws4RecoveryConfigs(t)
	plan, err := BuildRuntimeConfigRecoveryPlan("P:/go/tmp/ws4/login.yaml", recommended, recommended)
	if err != nil {
		t.Fatalf("生成计划失败：%v", err)
	}
	if !plan.Idempotent {
		t.Fatalf("相同配置应判定幂等，变化：%v", plan.ChangedPaths)
	}
	if plan.CanApply {
		t.Fatal("幂等计划不应再执行应用")
	}

	missingDatabase := "server:\n  listen_addr: \"127.0.0.1:8080\"\n"
	blocked, err := BuildRuntimeConfigRecoveryPlan("P:/go/tmp/ws4/login.yaml",
		[]byte(missingDatabase), recommended)
	if err != nil {
		t.Fatalf("生成计划失败：%v", err)
	}
	if blocked.CanApply {
		t.Fatal("缺少 database 段必须阻塞恢复")
	}
	if !hasBlockingContaining(blocked.Blocking, "database") {
		t.Fatalf("阻塞原因需说明 database 缺失：%v", blocked.Blocking)
	}
}

func TestApplyRuntimeConfigRecoveryRequiresSaverAndConfirm(t *testing.T) {
	if _, err := ApplyRuntimeConfigRecovery(context.Background(), nil, RuntimeConfigRecoveryPlan{}, ""); err == nil {
		t.Fatal("未注入保存接口必须拒绝")
	}
	fake := &fakeConfigSaver{}
	_, recommended := ws4RecoveryConfigs(t)
	plan := RuntimeConfigRecoveryPlan{
		CurrentPath: "P:/go/tmp/ws4/login.yaml", RequiredConfirm: runtimeConfigRecoveryConfirm,
		CanApply: true, Proposed: recommended,
	}
	if _, err := ApplyRuntimeConfigRecovery(context.Background(), fake, plan, "wrong"); err == nil {
		t.Fatal("确认串错误必须拒绝")
	}
	if fake.calls != 0 {
		t.Fatal("确认失败时不得调用保存接口")
	}
}

type fakeConfigSaver struct{ calls int }

func (f *fakeConfigSaver) SaveConfig(ctx context.Context, request ConfigSaveRequest) (ConfigSaveOutcome, error) {
	f.calls++
	return ConfigSaveOutcome{Saved: true, ConfigValid: true, ReloadResult: "restart-required"}, nil
}

type fakePresetProvider struct {
	preview PresetRoleRecoveryPreview
	applied int
}

func (f *fakePresetProvider) PreviewPresetRoleRecovery(context.Context) (PresetRoleRecoveryPreview, error) {
	return f.preview, nil
}

func (f *fakePresetProvider) ApplyPresetRoleRecovery(context.Context, string) (PresetRoleRecoveryResult, error) {
	f.applied++
	return PresetRoleRecoveryResult{Applied: true, RolesUpdated: 2}, nil
}

func TestPresetRoleRecoveryPlanAndApply(t *testing.T) {
	provider := &fakePresetProvider{preview: PresetRoleRecoveryPreview{
		PresetVersion: "round12-v1",
		Roles: []PresetRoleChange{
			{Role: "auditor", Action: "update", Added: []string{"audit.read"}},
			{Role: "custom-role", Action: "skip-custom"},
		},
		CustomRoles: []string{"custom-role"},
	}}
	plan, err := PlanPresetRoleRecovery(context.Background(), provider)
	if err != nil {
		t.Fatalf("生成预设恢复计划失败：%v", err)
	}
	if !plan.CanApply || plan.RequiredConfirm != presetRoleRecoveryConfirm {
		t.Fatalf("计划不正确：%+v", plan)
	}
	if _, err := ApplyPresetRoleRecovery(context.Background(), provider, plan, "wrong"); err == nil {
		t.Fatal("错误确认串必须拒绝")
	}
	result, err := ApplyPresetRoleRecovery(context.Background(), provider, plan, presetRoleRecoveryConfirm)
	if err != nil {
		t.Fatalf("应用预设恢复失败：%v", err)
	}
	if !result.Applied || provider.applied != 1 {
		t.Fatal("应调用一次领域恢复")
	}

	idempotent := &fakePresetProvider{preview: PresetRoleRecoveryPreview{Idempotent: true}}
	plan2, err := PlanPresetRoleRecovery(context.Background(), idempotent)
	if err != nil {
		t.Fatalf("幂等计划失败：%v", err)
	}
	if plan2.CanApply {
		t.Fatal("幂等预览不应再应用")
	}
	if _, err := ApplyPresetRoleRecovery(context.Background(), idempotent, plan2, presetRoleRecoveryConfirm); err == nil {
		t.Fatal("幂等时应用应返回无需恢复")
	}
}

func TestRecoverScreenRuntimePreviewAndApplyGuard(t *testing.T) {
	dir := t.TempDir()
	configText := ws4ConfigWithSecrets(t, filepath.ToSlash(filepath.Join(dir, "data", "login.db")))
	configPath := filepath.Join(dir, "login.yaml")
	writeConfigioFile(t, configPath, configText)
	screen := NewRecoverScreen(nil)
	canvas := NewCanvas(90, 30)
	session := SessionView{Detection: Detection{ConfigPath: configPath}}
	screen.Render(context.Background(), canvas, session)
	screen.previewRuntime(session)
	if screen.errText != "" {
		t.Fatalf("运行配置恢复预览失败：%s", screen.errText)
	}
	if screen.runtimePlan == nil {
		t.Fatal("预览应生成恢复计划")
	}
	// 未预览预设且 opener 为空时应用必须拒绝，不得改动数据库。
	screen.presetPlan = nil
	screen.requestApply("4", false, "预设角色恢复")
	if screen.errText == "" {
		t.Fatal("无预览时必须拒绝应用")
	}
	if screen.pending != "" {
		t.Fatal("拒绝时不得进入确认状态")
	}
}

func TestRecoverScreenApplyWritesMaintenanceEvidence(t *testing.T) {
	dir := t.TempDir()
	configText := ws4ConfigWithSecrets(t, filepath.ToSlash(filepath.Join(dir, "data", "login.db")))
	configPath := filepath.Join(dir, "login.yaml")
	writeConfigioFile(t, configPath, configText)
	screen := NewRecoverScreen(nil)
	session := SessionView{Detection: Detection{ConfigPath: configPath}}
	screen.previewRuntime(session)
	if screen.runtimePlan == nil || !screen.runtimePlan.CanApply {
		t.Fatalf("预览应可应用：%+v", screen.runtimePlan)
	}
	screen.applyRuntime(context.Background(), session)
	if screen.errText != "" {
		t.Fatalf("应用运行配置恢复失败：%s", screen.errText)
	}
	raw, err := os.ReadFile(filepath.Join(dir, ".login-setup-maintenance.jsonl"))
	if err != nil {
		t.Fatalf("维护日志不存在：%v", err)
	}
	text := string(raw)
	if !strings.Contains(text, "config.restore-recommended") || !strings.Contains(text, "success") {
		t.Fatalf("维护日志未记录恢复动作：%s", text)
	}
}
