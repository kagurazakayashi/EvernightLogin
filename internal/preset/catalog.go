package preset

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
)

// Catalog 是 versioned、机器可读的预设目录：系统权限、系统角色、默认用户组以及
// 应用创建模板（应用角色与应用用户组）。目录是只读数据，不携带任何账户、密码、
// 委派资格或角色分配，因此初始化预设不会创建带固定密码的工作人员账户，也不会
// 直接给任何用户赋权。
//
// 目录版本用于可重复执行的初始化与升级比较：同一版本重复执行只补齐缺失项，不
// 覆盖用户已调整的角色权限组合；恢复默认必须显式选择角色并经过差异预览与再次
// 授权（见 Service.Preview / Service.Restore）。
type Catalog struct {
	// Version 是目录版本，格式为 主.次.修订（均为非负整数），供升级比较。
	Version string `json:"version"`
	// Permissions 是系统内置权限目录；每项都必须有中文名称、能做什么、生效范围
	// 与不能做什么的直白说明。
	Permissions []PermissionDefinition `json:"permissions"`
	// Roles 是系统范围预设角色；DefaultPermissions 使用目录内的权限机器标识。
	Roles []RoleTemplate `json:"roles"`
	// Groups 是系统范围默认用户组；只建立空组，不自动加入成员。
	Groups []GroupTemplate `json:"groups"`
	// ApplicationRoles 是每个应用创建时按模板生成的该应用范围内角色，不同应用
	// 各自独立、不共用跨应用记录。
	ApplicationRoles []RoleTemplate `json:"application_roles"`
	// ApplicationGroups 是每个应用创建时按模板生成的该应用范围内用户组。
	ApplicationGroups []GroupTemplate `json:"application_groups"`
}

// PermissionDefinition 是一条预设权限的直白说明。同一格列出的多个权限是独立
// 权限，必须逐条登记，不能用一个开关捆绑授权。
type PermissionDefinition struct {
	// Key 是稳定机器标识（lower_snake，2～4 段），创建后不可修改。
	Key string `json:"key"`
	// Name 是中文名称。
	Name string `json:"name"`
	// Summary 说明该权限能做什么（“可以做什么”）。
	Summary string `json:"summary"`
	// Scope 说明该权限可以影响的人/应用/数据范围。
	Scope string `json:"scope"`
	// Limits 明确说明不能做什么，防止把功能权限理解为无限制能力。
	Limits string `json:"limits"`
	// RequiresReauth 表示执行该操作需要再次确认身份或操作内容。
	RequiresReauth bool `json:"requires_reauth"`
	// RootOnly 表示该权限只能由 root 特殊通道使用，普通角色不能组合。
	RootOnly bool `json:"root_only"`
	// DefaultRoles 是默认授予的预设角色机器标识；为空表示默认不授予。
	DefaultRoles []string `json:"default_roles,omitempty"`
	// Implemented 表示该权限对应的业务操作是否已经实现。未实现的权限只登记目录
	// 定义与说明，不得让对应操作伪装成功；业务调用必须显式检查该标记。
	Implemented bool `json:"implemented"`
}

// RoleTemplate 是一条预设角色模板。
type RoleTemplate struct {
	// Key 是稳定角色机器标识，任何分段都不能是 root。
	Key string `json:"key"`
	// Name 是中文名称。
	Name string `json:"name"`
	// Summary 说明该角色可以做什么。
	Summary string `json:"summary"`
	// Limits 明确说明该角色的生效范围与不能做什么。
	Limits string `json:"limits"`
	// Builtin 表示作为内置角色登记（内置角色资料与删除受既有步骤 24 保护）。
	Builtin bool `json:"builtin"`
	// Core 表示核心预设角色：初始化只补缺失项，恢复默认不得改写其权限组合。
	// 第一版目录没有核心角色（root 不是可分配角色），保留该语义供后续扩展。
	Core bool `json:"core"`
	// DefaultPermissions 是恢复默认时的权限集合（权限机器标识）。
	DefaultPermissions []string `json:"default_permissions"`
	// DefaultGroupKey 是与之配套的默认用户组机器标识（只建空组）。
	DefaultGroupKey string `json:"default_group_key,omitempty"`
}

// GroupTemplate 是一条预设用户组模板。
type GroupTemplate struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// DefaultCatalog 返回第一版内置预设目录（副本，调用方修改不影响内置数据）。
//
// 目录依据 docs/requirements/login_功能列表_v1.1.md 第 11.1、11.3、11.5 节：
//   - 系统管理员、用户管理员、客服、审计员、普通用户五个系统角色与其默认组；
//   - 应用管理员、应用普通用户按应用创建模板生成（应用范围，不共用记录）；
//   - 每条权限都有中文名称、能做什么、范围与不能做什么；同一格多个权限各自独立；
//   - 高风险与默认不授予的权限（恢复审批、备份导出/恢复、审计清理、敏感策略、
//     权限启停）不进入任何预设角色，root_only 权限不能被普通角色组合。
//
// 目录不包含 root 角色、root 权限集合或任何账户；root 能力不能通过普通角色分配
// 产生（沿用步骤 24/25/26 语义）。
func DefaultCatalog() *Catalog {
	source := catalogV1()
	catalog := *source
	catalog.Permissions = append([]PermissionDefinition(nil), source.Permissions...)
	catalog.Roles = append([]RoleTemplate(nil), source.Roles...)
	catalog.Groups = append([]GroupTemplate(nil), source.Groups...)
	catalog.ApplicationRoles = append([]RoleTemplate(nil), source.ApplicationRoles...)
	catalog.ApplicationGroups = append([]GroupTemplate(nil), source.ApplicationGroups...)
	return &catalog
}

// JSON 返回目录的机器可读 JSON（稳定字段顺序由结构体定义决定，供导出与比对）。
func (c *Catalog) JSON() ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: 预设目录为空", ErrOptionsInvalid)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("%w: 序列化预设目录失败: %v", ErrOptionsInvalid, err)
	}
	return data, nil
}

// Validate 校验目录自洽性：版本格式、机器标识合法性、中文说明完整性、同一格
// 多个权限不被捆绑（逐条登记）、默认角色引用存在、root_only 权限不进入普通角色、
// 预设角色不含 root 语义、应用模板只在应用范围使用。任何不合格都返回错误，拒绝
// 以不完整目录初始化（避免“发布没有说明的权限”）。
func (c *Catalog) Validate() error {
	if c == nil {
		return fmt.Errorf("%w: 预设目录为空", ErrOptionsInvalid)
	}
	if _, err := parseCatalogVersion(c.Version); err != nil {
		return err
	}
	if len(c.Permissions) == 0 {
		return fmt.Errorf("%w: 预设目录没有任何权限", ErrOptionsInvalid)
	}
	permissionsByKey := make(map[string]*PermissionDefinition, len(c.Permissions))
	for index := range c.Permissions {
		definition := &c.Permissions[index]
		key, err := permission.ValidateKey(definition.Key)
		if err != nil {
			return fmt.Errorf("%w: 预设权限 %q 机器标识无效: %v", ErrOptionsInvalid, definition.Key, err)
		}
		definition.Key = key
		if _, exists := permissionsByKey[key]; exists {
			return fmt.Errorf("%w: 预设权限 %q 重复登记", ErrOptionsInvalid, key)
		}
		if err := validatePermissionDefinitionText(*definition); err != nil {
			return err
		}
		permissionsByKey[key] = definition
	}
	// 先校验用户组，再校验角色：角色的 DefaultGroupKey 必须指向同一作用范围的
	// 默认用户组，避免“声明了配套默认组但初始化不会建组”的不一致。
	systemGroupKeys, err := validateGroups(c.Groups, "系统")
	if err != nil {
		return err
	}
	applicationGroupKeys, err := validateGroups(c.ApplicationGroups, "应用")
	if err != nil {
		return err
	}
	roleKeys := make(map[string]struct{}, len(c.Roles)+len(c.ApplicationRoles))
	if err := validateRoles(c.Roles, roleKeys, permissionsByKey, false, systemGroupKeys); err != nil {
		return err
	}
	if err := validateRoles(c.ApplicationRoles, roleKeys, permissionsByKey, true, applicationGroupKeys); err != nil {
		return err
	}
	// 反向核对默认角色映射：权限声明默认授予的角色必须存在且其默认权限集合包含
	// 该权限，避免“说明写了但初始化不会授予”的不一致。
	for index := range c.Permissions {
		definition := &c.Permissions[index]
		for _, roleKey := range definition.DefaultRoles {
			template, ok := lookupRoleTemplate(c.Roles, roleKey)
			if !ok {
				return fmt.Errorf("%w: 权限 %q 的默认角色 %q 不在系统预设角色中", ErrOptionsInvalid, definition.Key, roleKey)
			}
			if !containsString(template.DefaultPermissions, definition.Key) {
				return fmt.Errorf("%w: 权限 %q 声明默认授予 %q，但该角色默认权限不含它", ErrOptionsInvalid, definition.Key, roleKey)
			}
		}
	}
	return nil
}

// validateRoles 校验角色模板集合：键合法且不含 root 语义、说明完整、默认权限引用
// 目录内权限且不含 root_only 权限、DefaultGroupKey 指向同一作用范围的默认用户组；
// 应用模板不得自带系统权限（应用范围默认没有预置权限，避免把系统能力放进应用范围）。
func validateRoles(templates []RoleTemplate, roleKeys map[string]struct{}, permissionsByKey map[string]*PermissionDefinition, applicationScope bool, groupKeys map[string]struct{}) error {
	for index := range templates {
		template := &templates[index]
		key, err := role.ValidateKey(template.Key)
		if err != nil {
			return fmt.Errorf("%w: 预设角色 %q 机器标识无效: %v", ErrOptionsInvalid, template.Key, err)
		}
		template.Key = key
		if hasRootSegment(key) {
			return fmt.Errorf("%w: 预设角色 %q 不得含 root 语义", ErrOptionsInvalid, key)
		}
		if _, exists := roleKeys[key]; exists {
			return fmt.Errorf("%w: 预设角色 %q 重复登记", ErrOptionsInvalid, key)
		}
		roleKeys[key] = struct{}{}
		if _, err := role.ValidateName(template.Name); err != nil {
			return fmt.Errorf("%w: 预设角色 %q 名称无效: %v", ErrOptionsInvalid, key, err)
		}
		if _, err := role.ValidateDescription(template.Summary); err != nil {
			return fmt.Errorf("%w: 预设角色 %q 能做什么说明无效: %v", ErrOptionsInvalid, key, err)
		}
		if _, err := role.ValidateLimits(template.Limits); err != nil {
			return fmt.Errorf("%w: 预设角色 %q 限制说明无效: %v", ErrOptionsInvalid, key, err)
		}
		if template.DefaultGroupKey != "" {
			if _, ok := groupKeys[template.DefaultGroupKey]; !ok {
				return fmt.Errorf("%w: 预设角色 %q 的默认用户组 %q 不在对应默认用户组目录中",
					ErrOptionsInvalid, key, template.DefaultGroupKey)
			}
		}
		seen := make(map[string]struct{}, len(template.DefaultPermissions))
		for _, permissionKey := range template.DefaultPermissions {
			normalized := strings.TrimSpace(permissionKey)
			if _, exists := seen[normalized]; exists {
				return fmt.Errorf("%w: 预设角色 %q 重复组合权限 %q", ErrOptionsInvalid, key, normalized)
			}
			seen[normalized] = struct{}{}
			definition, ok := permissionsByKey[normalized]
			if !ok {
				return fmt.Errorf("%w: 预设角色 %q 引用了目录外权限 %q", ErrOptionsInvalid, key, normalized)
			}
			if applicationScope {
				return fmt.Errorf("%w: 应用预设角色 %q 不能组合系统权限 %q（应用默认没有预置权限）", ErrOptionsInvalid, key, normalized)
			}
			if definition.RootOnly {
				return fmt.Errorf("%w: 预设角色 %q 不能组合 root_only 权限 %q", ErrOptionsInvalid, key, normalized)
			}
		}
	}
	return nil
}

// validateGroups 校验用户组模板：键/名称/说明合法且唯一；返回机器标识集合供角色
// 的 DefaultGroupKey 存在性校验使用。
func validateGroups(templates []GroupTemplate, kind string) (map[string]struct{}, error) {
	seen := make(map[string]struct{}, len(templates))
	for _, template := range templates {
		key, err := group.ValidateGroupKey(template.Key)
		if err != nil {
			return nil, fmt.Errorf("%w: %s默认用户组 %q 机器标识无效: %v", ErrOptionsInvalid, kind, template.Key, err)
		}
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("%w: %s默认用户组 %q 重复登记", ErrOptionsInvalid, kind, key)
		}
		seen[key] = struct{}{}
		if _, err := group.ValidateGroupName(template.Name); err != nil {
			return nil, fmt.Errorf("%w: %s默认用户组 %q 名称无效: %v", ErrOptionsInvalid, kind, key, err)
		}
		if _, err := group.ValidateGroupDescription(template.Description); err != nil {
			return nil, fmt.Errorf("%w: %s默认用户组 %q 说明无效: %v", ErrOptionsInvalid, kind, key, err)
		}
	}
	return seen, nil
}

// validatePermissionDefinitionText 校验每条权限的直白说明完整性：中文名称、能做
// 什么、生效范围、不能做什么都不能为空，且长度受既有权限目录字段上限约束。
func validatePermissionDefinitionText(definition PermissionDefinition) error {
	if _, err := permission.ValidateName(definition.Name); err != nil {
		return fmt.Errorf("%w: 预设权限 %q 名称无效: %v", ErrOptionsInvalid, definition.Key, err)
	}
	if strings.TrimSpace(definition.Summary) == "" {
		return fmt.Errorf("%w: 预设权限 %q 缺少“能做什么”说明", ErrOptionsInvalid, definition.Key)
	}
	if strings.TrimSpace(definition.Scope) == "" {
		return fmt.Errorf("%w: 预设权限 %q 缺少生效范围说明", ErrOptionsInvalid, definition.Key)
	}
	if strings.TrimSpace(definition.Limits) == "" {
		return fmt.Errorf("%w: 预设权限 %q 缺少“不能做什么”说明", ErrOptionsInvalid, definition.Key)
	}
	// 说明字段复用权限目录的限制长度；拼接“范围 + 限制”以保证两者的长度合法。
	if _, err := permission.ValidateDescription(definition.Summary + "｜范围：" + definition.Scope); err != nil {
		return fmt.Errorf("%w: 预设权限 %q 说明无效: %v", ErrOptionsInvalid, definition.Key, err)
	}
	if _, err := permission.ValidateLimits(definition.Limits); err != nil {
		return fmt.Errorf("%w: 预设权限 %q 限制说明无效: %v", ErrOptionsInvalid, definition.Key, err)
	}
	for _, roleKey := range definition.DefaultRoles {
		if strings.TrimSpace(roleKey) == "" {
			return fmt.Errorf("%w: 预设权限 %q 的默认角色为空", ErrOptionsInvalid, definition.Key)
		}
	}
	return nil
}

// parseCatalogVersion 解析“主.次.修订”三段非负整数版本。
func parseCatalogVersion(version string) ([3]int, error) {
	var result [3]int
	trimmed := strings.TrimSpace(version)
	parts := strings.Split(trimmed, ".")
	if len(parts) != 3 {
		return result, fmt.Errorf("%w: 预设目录版本 %q 必须是 主.次.修订", ErrOptionsInvalid, version)
	}
	for index, part := range parts {
		if part == "" {
			return result, fmt.Errorf("%w: 预设目录版本 %q 含空段", ErrOptionsInvalid, version)
		}
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 {
			return result, fmt.Errorf("%w: 预设目录版本 %q 含非法段", ErrOptionsInvalid, version)
		}
		result[index] = value
	}
	return result, nil
}

// compareCatalogVersion 比较两个已校验版本：负数表示 a 更低，0 相等，正数更高。
func compareCatalogVersion(a, b [3]int) int {
	for index := 0; index < len(a); index++ {
		if a[index] != b[index] {
			return a[index] - b[index]
		}
	}
	return 0
}

// lookupRoleTemplate 在角色模板集合中查找机器标识。
func lookupRoleTemplate(templates []RoleTemplate, key string) (RoleTemplate, bool) {
	for _, template := range templates {
		if template.Key == key {
			return template, true
		}
	}
	return RoleTemplate{}, false
}

// containsString 报告字符串切片是否包含指定值。
func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// hasRootSegment 报告机器标识是否含 root 语义分段（root、system_root 等）。
func hasRootSegment(key string) bool {
	for _, segment := range strings.Split(strings.ToLower(key), ".") {
		if strings.Contains(segment, "root") {
			return true
		}
	}
	return false
}

// catalogV1 返回第一版预设目录数据。每次调用返回独立数据，避免调用方修改内置
// 目录；目录版本升级必须同时更新 Version 与内容，并通过 Validate 校验。
func catalogV1() *Catalog {
	return &Catalog{
		Version:           "1.0.0",
		Permissions:       catalogPermissionsV1(),
		Roles:             catalogRolesV1(),
		Groups:            catalogGroupsV1(),
		ApplicationRoles:  catalogApplicationRolesV1(),
		ApplicationGroups: catalogApplicationGroupsV1(),
	}
}

// catalogPermissionsV1 是需求 11.5 的第一版权限目录基线，逐条独立登记。
func catalogPermissionsV1() []PermissionDefinition {
	return []PermissionDefinition{
		// 本人权限：所有正常用户的基础角色。
		{
			Key: "self.profile.read", Name: "查看自己的资料", Summary: "查看自己的显示名称、联系资料与账户状态。",
			Scope: "仅本人；不包含其他人的资料。", Limits: "不能查看他人的资料、管理资格或安全设置。",
			Implemented: false, DefaultRoles: []string{"system_admin", "user_admin", "support", "auditor", "normal_user"},
		},
		{
			Key: "self.profile.update", Name: "修改自己的资料", Summary: "修改自己的显示资料。",
			Scope: "仅本人；用户名与邮箱修改遵守单独验证流程。", Limits: "不能修改管理资格、安全版本、已验证状态或他人资料。",
			Implemented: false, DefaultRoles: []string{"system_admin", "user_admin", "support", "auditor", "normal_user"},
		},
		{
			Key: "self.credentials.manage", Name: "管理自己的登录凭证", Summary: "管理自己的密码、Passkey 与两步验证。",
			Scope: "仅本人；敏感修改仍需再次确认身份。", Limits: "不能免除再次验证要求，不能为他人重置凭证或解除两步验证。",
			RequiresReauth: true, Implemented: false, DefaultRoles: []string{"system_admin", "user_admin", "support", "auditor", "normal_user"},
		},
		{
			Key: "self.sessions.manage", Name: "退出自己的设备", Summary: "查看并退出自己的登录会话与设备。",
			Scope: "仅本人。", Limits: "不能退出或查看其他人的设备与会话。",
			Implemented: false, DefaultRoles: []string{"system_admin", "user_admin", "support", "auditor", "normal_user"},
		},
		{
			Key: "self.grants.manage", Name: "撤回自己给应用的授权", Summary: "查看并撤回自己授权给应用的访问。",
			Scope: "仅本人。", Limits: "不能撤回其他人的授权或应用自身的凭证。",
			Implemented: false, DefaultRoles: []string{"system_admin", "user_admin", "support", "auditor", "normal_user"},
		},
		// 用户管理。
		{
			Key: "users.read", Name: "查看普通用户", Summary: "按获准范围查看普通用户的必要资料。",
			Scope: "仅获准管理的普通用户范围。", Limits: "不能查看 root 或超出管理范围的高权限管理账户资料。",
			Implemented: false, DefaultRoles: []string{"system_admin", "user_admin"},
		},
		{
			Key: "users.create", Name: "创建普通用户", Summary: "创建普通用户并登记基本资料。",
			Scope: "仅获准管理的普通用户范围。", Limits: "不能创建 root 或带管理资格的账户，不能设置固定密码。",
			Implemented: false, DefaultRoles: []string{"system_admin", "user_admin"},
		},
		{
			Key: "users.update", Name: "修改普通用户", Summary: "修改普通用户的显示资料。",
			Scope: "仅获准管理的普通用户范围。", Limits: "不能修改密码、邮箱验证状态、安全版本或管理资格。",
			Implemented: false, DefaultRoles: []string{"system_admin", "user_admin"},
		},
		{
			Key: "users.disable", Name: "禁用普通用户", Summary: "禁用获准范围内的普通用户。",
			Scope: "仅获准管理的普通用户范围。", Limits: "不能禁用 root 或其他高权限管理账户。",
			Implemented: false, DefaultRoles: []string{"system_admin", "user_admin"},
		},
		{
			Key: "users.delete", Name: "删除普通用户", Summary: "删除获准范围内的普通用户。",
			Scope: "仅获准普通用户，需确认；删除不清除审计。", Limits: "默认不授予，需另行分配；不能删除 root 或高权限账户。",
			RequiresReauth: true, Implemented: false,
		},
		{
			Key: "users.export", Name: "导出用户资料", Summary: "按字段许可批量导出普通用户资料。",
			Scope: "仅获准普通用户范围，导出仍按字段许可。", Limits: "默认不授予；不能导出密码、MFA 秘密、恢复码或私钥。",
			RequiresReauth: true, Implemented: false,
		},
		// 账户恢复与客服。
		{
			Key: "recovery.request", Name: "发起密码找回", Summary: "向用户此前已验证的渠道发送一次性密码找回入口。",
			Scope: "仅获准的普通用户范围；不能选择新地址。", Limits: "不能查看找回入口或验证码，不能解除两步验证，不能为 root 或高权限账户发起。",
			Implemented: false, DefaultRoles: []string{"system_admin", "user_admin", "support"},
		},
		{
			Key: "support.cases.read", Name: "查看求助单", Summary: "查看分配给自己的求助单与必要脱敏信息。",
			Scope: "仅分配给自己的求助单。", Limits: "不能查看未分配求助单或未脱敏的敏感资料。",
			Implemented: false, DefaultRoles: []string{"support"},
		},
		{
			Key: "support.cases.create", Name: "登记求助单", Summary: "登记用户求助事项与必要核验结果。",
			Scope: "仅自己经手且获准的普通用户。", Limits: "不能伪造核验结果，不能记录无关证件材料。",
			Implemented: false, DefaultRoles: []string{"support"},
		},
		{
			Key: "support.cases.update", Name: "更新求助单", Summary: "更新分配给自己且未结束的求助单状态。",
			Scope: "仅分配给自己的求助单。", Limits: "不能改写历史处理记录，不能替用户设置新密码。",
			Implemented: false, DefaultRoles: []string{"support"},
		},
		{
			Key: "recovery.approve", Name: "审批人工核验恢复", Summary: "审批通过人工核验的普通账户恢复申请。",
			Scope: "仅获准的普通账户恢复申请；需独立审批。", Limits: "默认不授予；不能审批本人发起的申请，不能审批 root 或高权限账户。",
			RequiresReauth: true, Implemented: false,
		},
		{
			Key: "recovery.mfa.approve", Name: "审批两步验证恢复", Summary: "审批普通用户的两步验证恢复申请。",
			Scope: "仅获准的普通账户，独立核验与审批。", Limits: "默认不授予；不能与密码恢复合并，完成后必须强制重新绑定。",
			RequiresReauth: true, Implemented: false,
		},
		// 用户组与角色。
		{
			Key: "groups.read", Name: "查看用户组", Summary: "查看获准范围内的用户组与成员。",
			Scope: "仅获准系统或应用范围。", Limits: "不能查看范围外用户组，查看不代表可修改成员。",
			Implemented: false, DefaultRoles: []string{"system_admin"},
		},
		{
			Key: "groups.manage", Name: "管理用户组", Summary: "创建、修改用户组并管理组成员。",
			Scope: "仅获准系统或应用范围。", Limits: "涉及赋权仍需角色分配权限；不能借组管理改变全局账户状态。",
			Implemented: false, DefaultRoles: []string{"system_admin"},
		},
		{
			Key: "roles.read", Name: "查看角色", Summary: "查看获准范围内的普通角色及其权限组合。",
			Scope: "仅获准系统或应用范围。", Limits: "不能查看 root 能力，查看不代表可修改。",
			Implemented: false, DefaultRoles: []string{"system_admin"},
		},
		{
			Key: "roles.manage", Name: "管理普通角色", Summary: "创建、修改普通角色及其权限组合。",
			Scope: "仅获准范围且只能组合可委派权限。", Limits: "不能制造 root 角色，不能组合超出自己委派范围的权限。",
			Implemented: false, DefaultRoles: []string{"system_admin"},
		},
		{
			Key: "roles.assign", Name: "分配角色", Summary: "把允许转授的角色交给指定用户或用户组。",
			Scope: "仅获准范围；不能授予超出自己委派范围的权限。", Limits: "不能自行提权，不能把角色分配给 root 或范围外主体。",
			Implemented: false, DefaultRoles: []string{"system_admin"},
		},
		// 权限目录。
		{
			Key: "permissions.read", Name: "查看权限目录", Summary: "查看系统与获准应用范围的权限定义与说明。",
			Scope: "仅获准系统或应用范围。", Limits: "不能查看范围外应用权限，不能修改内置权限含义。",
			Implemented: false, DefaultRoles: []string{"system_admin"},
		},
		{
			Key: "permissions.manage", Name: "管理自定义权限", Summary: "登记、修改与删除自定义权限。",
			Scope: "仅获准系统或应用范围。", Limits: "不能修改或删除内置系统权限，不能跨应用修改权限。",
			Implemented: false, DefaultRoles: []string{"system_admin"},
		},
		{
			Key: "permissions.state.update", Name: "启停权限", Summary: "启用或停用获准范围内的权限。",
			Scope: "仅获准权限，停用即拒绝对应操作。", Limits: "默认仅 root，可明确委派非核心范围；不能取消安全底线。",
			RequiresReauth: true, Implemented: false,
		},
		// 应用管理。
		{
			Key: "applications.read", Name: "查看应用", Summary: "查看获准范围内应用的资料与状态。",
			Scope: "系统管理员限管理范围；应用管理员仅已分配应用。", Limits: "不能查看未分配应用的资料或凭证。",
			Implemented: false, DefaultRoles: []string{"system_admin"},
		},
		{
			Key: "applications.create", Name: "创建应用", Summary: "创建新的应用登记。",
			Scope: "仅系统管理员的管理范围。", Limits: "应用管理员不默认拥有；不能创建后自动获得系统管理资格。",
			Implemented: false, DefaultRoles: []string{"system_admin"},
		},
		{
			Key: "applications.update", Name: "修改应用资料", Summary: "修改获准应用的显示资料。",
			Scope: "系统管理员限管理范围；应用管理员仅已分配应用。", Limits: "不能修改应用 ID、client_type 或作用范围，不能借此扩大权限。",
			Implemented: false, DefaultRoles: []string{"system_admin"},
		},
		{
			Key: "applications.credentials.manage", Name: "管理应用凭证", Summary: "轮换应用密钥或公钥凭证。",
			Scope: "仅指定应用；需再次确认身份。", Limits: "不包含服务器 HTTPS 私钥；默认不授予应用管理员，需明确授予。",
			RequiresReauth: true, Implemented: false, DefaultRoles: []string{"system_admin"},
		},
		{
			Key: "applications.members.manage", Name: "管理应用成员", Summary: "管理应用成员及应用内状态。",
			Scope: "仅指定应用。", Limits: "不能因此禁用或删除全局账户，不能修改全局管理资格。",
			Implemented: false, DefaultRoles: []string{"system_admin"},
		},
		{
			Key: "authorization.check", Name: "联合校验授权", Summary: "校验访问令牌与所需应用权限。",
			Scope: "仅获准调用的应用与目标资源。", Limits: "不能查询其他应用的身份详情，不能改变权限或签发令牌。",
			Implemented: false,
		},
		{
			Key: "sessions.revoke", Name: "强制会话退出", Summary: "强制获准范围内的普通用户退出相关会话。",
			Scope: "仅获准用户或应用会话。", Limits: "不包含 root；不能用于绕过登录验证或冒充用户。",
			Implemented: false, DefaultRoles: []string{"system_admin", "user_admin"},
		},
		// 审计与报告。
		{
			Key: "audit.read", Name: "查看安全记录", Summary: "查看获准范围内的安全审计记录。",
			Scope: "仅获准范围，内容按权限脱敏。", Limits: "不能修改或删除原始记录，不能查看范围外记录。",
			Implemented: false, DefaultRoles: []string{"system_admin", "auditor"},
		},
		{
			Key: "audit.export", Name: "导出安全记录", Summary: "按许可导出获准范围内的安全记录。",
			Scope: "仅获准范围，导出仍脱敏。", Limits: "不能删除记录，不能导出未脱敏的秘密或范围外数据。",
			Implemented: false, DefaultRoles: []string{"system_admin", "auditor"},
		},
		{
			Key: "reports.read", Name: "查看统计报告", Summary: "查看获准数据范围内的统计报告。",
			Scope: "仅获准数据范围。", Limits: "不能查看范围外数据，缺失数据必须标记而不是记为零。",
			Implemented: false, DefaultRoles: []string{"system_admin", "auditor"},
		},
		{
			Key: "reports.generate", Name: "生成统计报告", Summary: "生成获准数据范围的统计报告。",
			Scope: "仅获准数据范围。", Limits: "不能生成超出权限范围的报告，不能伪造数据来源。",
			Implemented: false, DefaultRoles: []string{"system_admin", "auditor"},
		},
		{
			Key: "reports.export", Name: "导出统计报告", Summary: "导出获准范围的报告文件。",
			Scope: "仅获准数据范围，按格式安全转义。", Limits: "不能导出未获准的数据，不能绕过脱敏与注入防护。",
			Implemented: false, DefaultRoles: []string{"system_admin", "auditor"},
		},
		{
			Key: "reports.schedule.manage", Name: "管理定期报告", Summary: "安排与暂停定期报告任务。",
			Scope: "仅获准数据范围；任务不能超出所有者当前权限。", Limits: "不能创建超出权限范围的任务，不能修改他人报告。",
			Implemented: false, DefaultRoles: []string{"system_admin", "auditor"},
		},
		{
			Key: "reports.cleanup", Name: "清理过期报告文件", Summary: "按保留策略清理已到期的报告产物文件。",
			Scope: "仅获准数据范围；必须强认证并记录实际目标与结果。", Limits: "不能删除原始审计记录，不能清理未到期或范围外文件。",
			Implemented: false, DefaultRoles: []string{"system_admin"},
		},
		// 备份。
		{
			Key: "backups.create", Name: "创建备份", Summary: "创建备份任务。",
			Scope: "获准任务范围。", Limits: "不能下载数据库文件，不能覆盖既有备份。",
			Implemented: false, DefaultRoles: []string{"system_admin"},
		},
		{
			Key: "backups.read", Name: "查看备份任务", Summary: "查看备份任务及清单。",
			Scope: "获准任务范围。", Limits: "查看清单不代表可下载数据库文件。",
			Implemented: false, DefaultRoles: []string{"system_admin"},
		},
		{
			Key: "backups.cancel", Name: "取消备份任务", Summary: "取消获准范围内的备份任务。",
			Scope: "获准任务范围；取消请求不等于实际取消。", Limits: "不能删除既有备份，不能取消范围外任务。",
			Implemented: false, DefaultRoles: []string{"system_admin"},
		},
		{
			Key: "backups.export", Name: "导出备份", Summary: "下载备份或导出备份内容。",
			Scope: "可能覆盖全系统数据，需明确授予。", Limits: "默认仅 root，可审慎委派；不自动交给应用管理员或客服。",
			RequiresReauth: true, Implemented: false,
		},
		{
			Key: "backups.restore", Name: "恢复备份", Summary: "用备份恢复系统数据。",
			Scope: "全系统高风险操作。", Limits: "仅 root；不能通过普通角色分配下放。",
			RootOnly: true, RequiresReauth: true, Implemented: false,
		},
		{
			Key: "audit.purge", Name: "清理安全记录", Summary: "按保留策略清理安全审计记录。",
			Scope: "全系统高风险操作。", Limits: "仅 root；不能通过普通角色分配下放。",
			RootOnly: true, RequiresReauth: true, Implemented: false,
		},
		{
			Key: "security.policy.manage", Name: "修改敏感操作规则", Summary: "查看、修改与恢复敏感操作安全策略。",
			Scope: "全系统高风险操作。", Limits: "仅 root；不能通过普通角色分配下放，不能取消安全底线。",
			RootOnly: true, RequiresReauth: true, Implemented: false,
		},
		// 常规设置与诊断。
		{
			Key: "settings.manage", Name: "修改常规设置", Summary: "修改常规运行设置。",
			Scope: "仅常规设置，不包含敏感策略。", Limits: "不能修改敏感操作规则、主密钥或未脱敏秘密。",
			Implemented: false, DefaultRoles: []string{"system_admin"},
		},
		{
			Key: "diagnostics.read", Name: "查看运行诊断", Summary: "查看脱敏的运行诊断信息。",
			Scope: "仅脱敏诊断信息。", Limits: "不能查看未脱敏秘密、主密钥或敏感策略内容。",
			Implemented: false, DefaultRoles: []string{"system_admin"},
		},
	}
}

// catalogRolesV1 是五个系统预设角色及其默认权限与默认用户组。
func catalogRolesV1() []RoleTemplate {
	return []RoleTemplate{
		{
			Key: "system_admin", Name: "系统管理员",
			Summary: "管理普通用户、应用、用户组和普通角色，维护常规设置、备份与报告。",
			Limits:  "仅限 root 已交给他的管理范围；默认不能修改敏感操作规则、恢复备份、清理审计、操作 root 或自行扩大授权范围。",
			Builtin: true, DefaultGroupKey: "system-administrators",
			DefaultPermissions: []string{
				"self.profile.read", "self.profile.update", "self.credentials.manage",
				"self.sessions.manage", "self.grants.manage",
				"users.read", "users.create", "users.update", "users.disable",
				"recovery.request", "groups.read", "groups.manage", "roles.read",
				"roles.manage", "roles.assign", "permissions.read", "permissions.manage",
				"applications.read", "applications.create", "applications.update",
				"applications.credentials.manage", "applications.members.manage",
				"sessions.revoke", "audit.read", "audit.export", "reports.read",
				"reports.generate", "reports.export", "reports.schedule.manage",
				"reports.cleanup",
				"backups.create", "backups.read", "backups.cancel", "settings.manage",
				"diagnostics.read",
			},
		},
		{
			Key: "user_admin", Name: "用户管理员",
			Summary: "创建、查询、修改和禁用普通用户，发起密码找回。",
			Limits:  "仅限获准管理的用户；默认不能操作 root、其他高权限管理账户或修改权限分配。",
			Builtin: true, DefaultGroupKey: "user-administrators",
			DefaultPermissions: []string{
				"self.profile.read", "self.profile.update", "self.credentials.manage",
				"self.sessions.manage", "self.grants.manage",
				"users.read", "users.create", "users.update", "users.disable",
				"recovery.request", "sessions.revoke",
			},
		},
		{
			Key: "support", Name: "客服",
			Summary: "查询必要的脱敏资料，登记求助事项，向用户原已验证邮箱发送密码重置入口，查询本人负责的处理进度。",
			Limits:  "仅限分配给客服的普通用户；不能查看或指定密码、修改邮箱后再重置、清除两步验证、冒充用户登录或操作高权限账户。",
			Builtin: true, DefaultGroupKey: "support-team",
			DefaultPermissions: []string{
				"self.profile.read", "self.profile.update", "self.credentials.manage",
				"self.sessions.manage", "self.grants.manage",
				"recovery.request", "support.cases.read", "support.cases.create", "support.cases.update",
			},
		},
		{
			Key: "auditor", Name: "审计员",
			Summary: "查看安全记录，查看和生成统计报告，按许可导出记录。",
			Limits:  "仅限获准查看的应用和用户；不能修改用户、改变权限或删除原始记录。",
			Builtin: true, DefaultGroupKey: "auditors",
			DefaultPermissions: []string{
				"self.profile.read", "self.profile.update", "self.credentials.manage",
				"self.sessions.manage", "self.grants.manage",
				"audit.read", "audit.export", "reports.read", "reports.generate",
				"reports.export", "reports.schedule.manage",
			},
		},
		{
			Key: "normal_user", Name: "普通用户",
			Summary: "修改自己的资料，管理自己的密码、登录方式、会话和应用授权。",
			Limits:  "仅限自己；敏感修改仍需再次确认身份，不能查看或改变他人资料。",
			Builtin: true, DefaultGroupKey: "normal-users",
			DefaultPermissions: []string{
				"self.profile.read", "self.profile.update", "self.credentials.manage",
				"self.sessions.manage", "self.grants.manage",
			},
		},
	}
}

// catalogGroupsV1 是五个默认用户组（只建空组，不自动加人）。
func catalogGroupsV1() []GroupTemplate {
	return []GroupTemplate{
		{Key: "system-administrators", Name: "系统管理员组", Description: "系统管理员角色的默认成员组，初始化不自动加入成员。"},
		{Key: "user-administrators", Name: "用户管理员组", Description: "用户管理员角色的默认成员组，初始化不自动加入成员。"},
		{Key: "support-team", Name: "客服组", Description: "客服角色的默认成员组，初始化不自动加入成员。"},
		{Key: "auditors", Name: "审计员组", Description: "审计员角色的默认成员组，初始化不自动加入成员。"},
		{Key: "normal-users", Name: "普通用户组", Description: "普通用户角色的默认成员组，初始化不自动加入成员。"},
	}
}

// catalogApplicationRolesV1 是每个应用创建时按模板生成的该应用范围角色。应用范围
// 默认没有预置权限（应用独有权限由应用管理员按需登记），因此模板角色初始为空；
// 不同应用生成各自独立的角色记录，不共用跨应用记录。
func catalogApplicationRolesV1() []RoleTemplate {
	return []RoleTemplate{
		{
			Key: "app_admin", Name: "应用管理员",
			Summary:         "管理指定应用资料、成员、应用内角色和应用独有权限。",
			Limits:          "仅限指定应用；不能修改共享密码、其他应用权限或系统管理资格；转授权限需另有许可。",
			DefaultGroupKey: "app-administrators",
		},
		{
			Key: "app_user", Name: "应用普通用户",
			Summary:         "登录已加入的应用，使用明确分配的业务功能。",
			Limits:          "仅限自己已加入的应用和已获准功能；加入应用不代表自动拥有全部功能。",
			DefaultGroupKey: "app-users",
		},
	}
}

// catalogApplicationGroupsV1 是每个应用创建时按模板生成的该应用范围用户组。
func catalogApplicationGroupsV1() []GroupTemplate {
	return []GroupTemplate{
		{Key: "app-administrators", Name: "应用管理员组", Description: "应用管理员角色的默认成员组，初始化不自动加入成员。"},
		{Key: "app-users", Name: "应用用户组", Description: "应用普通用户角色的默认成员组，初始化不自动加入成员。"},
	}
}
