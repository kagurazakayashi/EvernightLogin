package setupconsole

// 步骤 294：保留数据的“恢复推荐运行配置”与“恢复预设角色权限”（WS4）。
//
// 两类恢复严格分开：
//   - 运行配置恢复：只重置配置文件的非保留字段为推荐默认；数据库定位、主密钥/
//     秘密来源与必要访问地址（server 段）保留当前值。不删除数据目录、不改账户
//     密码、不重建 root。
//   - 预设角色权限恢复：只恢复系统预设角色/权限组合；默认不碰自定义角色、账户
//     口令与业务数据。实际数据库事务由注入的 PresetRoleRecoveryProvider 完成，
//     本文件只做预览/确认/幂等判定，避免第二套权限实现。
//
// 本文件不直接写配置文件：应用通过 WS1 280 ConfigSaver 注入；不在本文件实现事务。

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	// runtimeConfigRecoveryConfirm 是应用运行配置恢复的确认串。
	runtimeConfigRecoveryConfirm = "RESET-RUNTIME-CONFIG"
	// presetRoleRecoveryConfirm 是应用预设角色恢复的确认串。
	presetRoleRecoveryConfirm = "RESTORE-PRESET-ROLES"
)

// runtimeConfigRetainedSections 是运行配置恢复中保留当前值的顶层段。
//
// database：数据库定位（恢复不得切换数据库，避免连接到另一个实例的数据）；
// secrets：主密钥/秘密来源引用（不得因恢复配置换钥导致旧数据无法解密）；
// server：必要访问地址、Host/代理与 TLS 配置（换地址可能使现有入口不可用）。
// 其余段（logging/registration/passkey/app_qr_login/protocol/mail/manual_recovery
// 等）按推荐运行配置重置。
var runtimeConfigRetainedSections = []string{"database", "secrets", "server"}

// RuntimeConfigRecoveryPlan 是“恢复推荐运行配置”的差异预览。
type RuntimeConfigRecoveryPlan struct {
	CurrentPath string `json:"current_path"`
	// RetainedSections 是保留当前值的顶层段。
	RetainedSections []string `json:"retained_sections"`
	// ResetSections 是按推荐配置重置的顶层段。
	ResetSections []string `json:"reset_sections"`
	// ChangedPaths 是变化字段路径（尽力而为，脱敏）。
	ChangedPaths []string `json:"changed_paths"`
	// Idempotent 表示按保留规则应用后与当前配置无差异。
	Idempotent bool `json:"idempotent"`
	// RequiredConfirm 是应用前必须逐字输入的确认串。
	RequiredConfirm string `json:"required_confirm"`
	// Proposed 是应用后的配置原文（仅内存；不写盘）。
	Proposed []byte `json:"-"`
	// ProposedReport 是 Proposed 的校验结果。
	ProposedReport ConfigReport `json:"-"`
	Blocking       []string     `json:"blocking,omitempty"`
	Warnings       []string     `json:"warnings,omitempty"`
	CanApply       bool         `json:"can_apply"`
}

// BuildRuntimeConfigRecoveryPlan 基于当前配置与推荐运行配置生成恢复计划。
//
// 保留 database/secrets/server 三段当前值，其余段取推荐配置；不读取/不写数据库，
// 不删除数据目录，不修改账户口令。
func BuildRuntimeConfigRecoveryPlan(currentPath string, currentRaw, recommendedRaw []byte) (RuntimeConfigRecoveryPlan, error) {
	plan := RuntimeConfigRecoveryPlan{
		CurrentPath: filepath.Clean(currentPath), RequiredConfirm: runtimeConfigRecoveryConfirm,
		RetainedSections: append([]string(nil), runtimeConfigRetainedSections...),
	}
	if len(currentRaw) > configExportMaxPlaintextBytes || len(recommendedRaw) > configExportMaxPlaintextBytes {
		return RuntimeConfigRecoveryPlan{}, errors.New("配置超过恢复计划大小上限")
	}
	var currentDoc, recommendedDoc yaml.Node
	if err := yaml.Unmarshal(currentRaw, &currentDoc); err != nil {
		return RuntimeConfigRecoveryPlan{}, fmt.Errorf("当前配置解析失败：%w", err)
	}
	if err := yaml.Unmarshal(recommendedRaw, &recommendedDoc); err != nil {
		return RuntimeConfigRecoveryPlan{}, fmt.Errorf("推荐配置解析失败：%w", err)
	}
	if len(currentDoc.Content) == 0 || len(recommendedDoc.Content) == 0 {
		return RuntimeConfigRecoveryPlan{}, errors.New("当前配置或推荐配置为空")
	}
	currentRoot := currentDoc.Content[0]
	recommendedRoot := recommendedDoc.Content[0]
	if currentRoot.Kind != yaml.MappingNode || recommendedRoot.Kind != yaml.MappingNode {
		return RuntimeConfigRecoveryPlan{}, errors.New("配置根节点必须是映射")
	}
	retained := map[string]bool{}
	for _, section := range runtimeConfigRetainedSections {
		retained[section] = true
	}
	currentSections := mappingKeys(currentRoot)
	recommendedSections := mappingKeys(recommendedRoot)
	plan.ResetSections = make([]string, 0, len(recommendedSections))
	for section := range recommendedSections {
		if retained[section] {
			continue
		}
		plan.ResetSections = append(plan.ResetSections, section)
		if currentSections[section] {
			delete(currentSections, section)
		}
	}
	// 当前有、推荐没有且不在保留段中的段会被删除；必须显式说明。
	for section := range currentSections {
		if retained[section] {
			continue
		}
		plan.Warnings = append(plan.Warnings,
			"段 "+section+" 在推荐配置中不存在，应用恢复会移除该段（如为自定义扩展请先备份）")
	}

	proposed := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	// 以推荐配置为骨架，保留段用当前值覆盖。
	for index := 0; index+1 < len(recommendedRoot.Content); index += 2 {
		key := recommendedRoot.Content[index]
		value := recommendedRoot.Content[index+1]
		if retained[key.Value] {
			if currentValue, ok := mappingValue(currentRoot, key.Value); ok {
				proposed.Content = append(proposed.Content, key, currentValue)
				continue
			}
			plan.Blocking = append(plan.Blocking,
				"当前配置缺少保留段 "+key.Value+"：初始化状态异常，不能按推荐配置恢复")
			proposed.Content = append(proposed.Content, key, value)
			continue
		}
		proposed.Content = append(proposed.Content, key, value)
	}
	// 保留段里当前有但推荐没有的段，仍保留当前值（不得因推荐模板缺失而丢数据）。
	for _, section := range runtimeConfigRetainedSections {
		if _, exists := mappingValue(proposed, section); exists {
			continue
		}
		if currentValue, ok := mappingValue(currentRoot, section); ok {
			proposed.Content = append(proposed.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: section}, currentValue)
		}
	}
	encoded, err := yaml.Marshal(proposed)
	if err != nil {
		return RuntimeConfigRecoveryPlan{}, fmt.Errorf("编码恢复后的配置失败：%w", err)
	}
	plan.Proposed = encoded
	plan.ProposedReport = ValidateConfigText(encoded)
	plan.ChangedPaths = changedConfigPaths(currentRaw, encoded)
	plan.Idempotent = len(plan.ChangedPaths) == 0
	if !plan.ProposedReport.Valid {
		plan.Blocking = append(plan.Blocking,
			"恢复后的配置未通过校验："+plan.ProposedReport.Summary)
	}
	if currentValue, ok := mappingValue(currentRoot, "database"); ok {
		if currentPathValue := mappingScalar(currentValue, "path"); currentPathValue == "" {
			plan.Warnings = append(plan.Warnings, "当前数据库路径为空：恢复不会猜测或迁移数据库")
		}
	} else {
		plan.Blocking = append(plan.Blocking, "当前配置缺少 database 段：不能按“保留数据”语义恢复")
	}
	plan.CanApply = len(plan.Blocking) == 0 && !plan.Idempotent
	return plan, nil
}

// ApplyRuntimeConfigRecovery 通过 WS1 280 ConfigSaver 应用推荐运行配置恢复。
//
// 必须逐字确认；幂等时直接返回“无变化”，不写盘；保存创建最后有效副本。
func ApplyRuntimeConfigRecovery(ctx context.Context, saver ConfigSaver, plan RuntimeConfigRecoveryPlan, confirm string) (ConfigSaveOutcome, error) {
	if saver == nil {
		return ConfigSaveOutcome{}, errors.New("未注入配置保存接口（WS1 280）")
	}
	if plan.Idempotent {
		return ConfigSaveOutcome{Saved: false, ConfigValid: true, ReloadResult: "not-requested"},
			errors.New("当前配置已符合推荐运行配置（含保留段），无需恢复")
	}
	if !plan.CanApply {
		return ConfigSaveOutcome{}, fmt.Errorf("恢复计划存在阻塞项：%s", strings.Join(plan.Blocking, "；"))
	}
	if strings.TrimSpace(confirm) != plan.RequiredConfirm {
		return ConfigSaveOutcome{}, fmt.Errorf("确认串不匹配：必须逐字输入 %q", plan.RequiredConfirm)
	}
	currentRaw, _, err := readConfigSource(plan.CurrentPath)
	if err != nil {
		return ConfigSaveOutcome{}, err
	}
	return saver.SaveConfig(ctx, ConfigSaveRequest{
		Path: plan.CurrentPath, BaseRaw: currentRaw, NewRaw: plan.Proposed,
		ConflictPolicy: "fail", CreateBackup: true, Operator: "login-setup",
	})
}

// PresetRoleChange 是一条预设角色变化。
type PresetRoleChange struct {
	Role    string   `json:"role"`
	Action  string   `json:"action"` // "create"|"update"|"unchanged"|"skip-custom"
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
	Detail  string   `json:"detail,omitempty"`
}

// PresetRoleRecoveryPreview 是预设角色权限恢复的影响预览（由领域实现提供）。
type PresetRoleRecoveryPreview struct {
	PresetVersion string             `json:"preset_version"`
	Roles         []PresetRoleChange `json:"roles"`
	CustomRoles   []string           `json:"custom_roles_untouched,omitempty"`
	// Idempotent 表示当前数据库已与预设一致。
	Idempotent bool     `json:"idempotent"`
	Blocking   []string `json:"blocking,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
}

// PresetRoleRecoveryProvider 是预设角色恢复的领域能力注入点。
//
// 实现必须复用既有角色/权限服务与数据库事务：只恢复系统预设角色/权限组合，
// 不修改自定义角色、账户口令、会话或业务数据；重复恢复幂等。
type PresetRoleRecoveryProvider interface {
	PreviewPresetRoleRecovery(ctx context.Context) (PresetRoleRecoveryPreview, error)
	ApplyPresetRoleRecovery(ctx context.Context, confirm string) (PresetRoleRecoveryResult, error)
}

// PresetRoleRecoveryResult 是预设恢复的脱敏结果。
type PresetRoleRecoveryResult struct {
	Applied       bool     `json:"applied"`
	PresetVersion string   `json:"preset_version"`
	RolesCreated  int      `json:"roles_created"`
	RolesUpdated  int      `json:"roles_updated"`
	RolesSkipped  int      `json:"roles_skipped"`
	Notes         []string `json:"notes,omitempty"`
}

// PresetRoleRecoveryPlan 是带确认要求的预设角色恢复计划。
type PresetRoleRecoveryPlan struct {
	Preview         PresetRoleRecoveryPreview `json:"preview"`
	RequiredConfirm string                    `json:"required_confirm"`
	CanApply        bool                      `json:"can_apply"`
}

// PlanPresetRoleRecovery 读取领域预览并生成确认要求；不修改数据库。
func PlanPresetRoleRecovery(ctx context.Context, provider PresetRoleRecoveryProvider) (PresetRoleRecoveryPlan, error) {
	if provider == nil {
		return PresetRoleRecoveryPlan{}, errors.New("未注入预设角色恢复实现")
	}
	preview, err := provider.PreviewPresetRoleRecovery(ctx)
	if err != nil {
		return PresetRoleRecoveryPlan{}, fmt.Errorf("读取预设角色差异失败：%w", err)
	}
	plan := PresetRoleRecoveryPlan{
		Preview: preview, RequiredConfirm: presetRoleRecoveryConfirm,
		CanApply: len(preview.Blocking) == 0 && !preview.Idempotent,
	}
	return plan, nil
}

// ApplyPresetRoleRecovery 确认后调用领域恢复；幂等时返回无变化。
func ApplyPresetRoleRecovery(ctx context.Context, provider PresetRoleRecoveryProvider, plan PresetRoleRecoveryPlan, confirm string) (PresetRoleRecoveryResult, error) {
	if provider == nil {
		return PresetRoleRecoveryResult{}, errors.New("未注入预设角色恢复实现")
	}
	if plan.Preview.Idempotent {
		return PresetRoleRecoveryResult{Applied: false, PresetVersion: plan.Preview.PresetVersion},
			errors.New("当前角色权限已与预设一致，无需恢复")
	}
	if !plan.CanApply {
		return PresetRoleRecoveryResult{}, fmt.Errorf("预设恢复存在阻塞项：%s", strings.Join(plan.Preview.Blocking, "；"))
	}
	if strings.TrimSpace(confirm) != plan.RequiredConfirm {
		return PresetRoleRecoveryResult{}, fmt.Errorf("确认串不匹配：必须逐字输入 %q", plan.RequiredConfirm)
	}
	return provider.ApplyPresetRoleRecovery(ctx, confirm)
}

// ---- YAML 辅助 ----

func mappingKeys(node *yaml.Node) map[string]bool {
	keys := map[string]bool{}
	if node == nil || node.Kind != yaml.MappingNode {
		return keys
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		keys[node.Content[index].Value] = true
	}
	return keys
}

func mappingValue(node *yaml.Node, key string) (*yaml.Node, bool) {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil, false
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		if node.Content[index].Value == key {
			return node.Content[index+1], true
		}
	}
	return nil, false
}

func mappingScalar(node *yaml.Node, key string) string {
	value, ok := mappingValue(node, key)
	if !ok || value.Kind != yaml.ScalarNode {
		return ""
	}
	return value.Value
}
