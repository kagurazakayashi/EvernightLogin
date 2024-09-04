package serverapp

// 本文件把版本化只读预设权限目录适配为 internal/authz.PermissionCatalog（步骤 252）。
//
// 只读边界：
//   - 只读取 internal/preset.DefaultCatalog() 的权限登记与 Implemented 标记，不写
//     预设目录、不改目录版本、不创建/修改任何权限记录；
//   - 目录是编译期静态数据，读取后不再变化；root 全权限集合因此随目录升级自动包含
//     新实现的权限，无需缓存或重启重建；
//   - 目录中未实现的权限只用于拒绝 root 使用/从有效权限列表排除，不会被当成可授予
//     权限，也不影响普通用户的角色/委派判定。
import (
	"fmt"
	"sort"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	"github.com/kagurazakayashi/EvernightLogin/internal/preset"
)

// presetPermissionCatalog 是预设目录的只读实现状态视图。
type presetPermissionCatalog struct {
	// implemented 的 key 是规范权限键；value 表示对应业务能力是否已有真实执行路径。
	implemented map[string]bool
	// implementedPermissions 是按 Key 稳定排序的已实现权限定义（供 root 有效权限
	// 列表合并分页与来源说明使用）。
	implementedPermissions []authz.CatalogPermission
}

// 编译期确认实现 authz.PermissionCatalog。
var _ authz.PermissionCatalog = (*presetPermissionCatalog)(nil)

// newPresetPermissionCatalog 读取并校验版本化预设目录，构造只读实现状态视图。
// 目录自洽性校验失败时整体失败（fail-closed），不退化为“全部已实现”。
func newPresetPermissionCatalog() (*presetPermissionCatalog, error) {
	catalog := preset.DefaultCatalog()
	if catalog == nil {
		return nil, fmt.Errorf("预设权限目录为空")
	}
	if err := catalog.Validate(); err != nil {
		return nil, fmt.Errorf("预设权限目录未通过校验: %w", err)
	}
	implemented := make(map[string]bool, len(catalog.Permissions))
	entries := make([]authz.CatalogPermission, 0, len(catalog.Permissions))
	for _, definition := range catalog.Permissions {
		key := strings.TrimSpace(definition.Key)
		if key == "" {
			return nil, fmt.Errorf("预设权限目录包含空权限键")
		}
		implemented[key] = definition.Implemented
		if definition.Implemented {
			entries = append(entries, authz.CatalogPermission{Key: key,
				Name: definition.Name, RootOnly: definition.RootOnly})
		}
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Key < entries[right].Key })
	return &presetPermissionCatalog{implemented: implemented,
		implementedPermissions: entries}, nil
}

// IsImplemented 实现 authz.PermissionCatalog：目录未登记的键（宿主自定义权限）返回
// known=false，内核按已实现处理；目录登记的键返回其 Implemented 标记。
func (c *presetPermissionCatalog) IsImplemented(key string) (bool, bool) {
	if c == nil {
		return false, false
	}
	implemented, known := c.implemented[strings.TrimSpace(key)]
	return implemented, known
}

// ImplementedPermissions 实现 authz.PermissionCatalog：返回副本，调用方不能修改内部状态。
func (c *presetPermissionCatalog) ImplementedPermissions() []authz.CatalogPermission {
	if c == nil {
		return nil
	}
	return append([]authz.CatalogPermission(nil), c.implementedPermissions...)
}

// ImplementedPermission 实现 authz.PermissionCatalog：返回单个已实现权限定义。
func (c *presetPermissionCatalog) ImplementedPermission(key string) (authz.CatalogPermission, bool) {
	if c == nil {
		return authz.CatalogPermission{}, false
	}
	normalized := strings.TrimSpace(key)
	if !c.implemented[normalized] {
		return authz.CatalogPermission{}, false
	}
	for _, entry := range c.implementedPermissions {
		if entry.Key == normalized {
			return entry, true
		}
	}
	return authz.CatalogPermission{}, false
}
