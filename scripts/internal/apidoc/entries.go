package apidoc

import (
	"fmt"

	"github.com/kagurazakayashi/EvernightLogin/config"
	"github.com/kagurazakayashi/EvernightLogin/errs"
	"github.com/kagurazakayashi/EvernightLogin/internal/preset"
)

// 本文件从产品代码暴露的注册表读取错误码、权限目录与配置字段元数据，确保参考
// 文档与代码使用同一事实来源；不解析手写表格、不复制第二份常量清单。

// loadErrors 读取公开错误码注册表与公开说明补充（顺序与手册一致）。
func loadErrors() ([]ErrorEntry, error) {
	definitions := errs.RegisteredErrorCodes()
	if len(definitions) == 0 {
		return nil, fmt.Errorf("错误码注册表为空")
	}
	entries := make([]ErrorEntry, 0, len(definitions))
	for _, definition := range definitions {
		code := string(definition.Code)
		entry := ErrorEntry{
			Code:           code,
			Category:       string(definition.Category),
			HTTPStatus:     definition.HTTPStatus,
			DefaultMessage: definition.DefaultMessage,
		}
		if guidance, ok := errs.LookupErrorCodeGuidance(definition.Code); ok {
			entry.Cause = guidance.Cause
			entry.Advice = guidance.Advice
			entry.Retry = guidance.Retry
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// permissionCatalog 是预设目录的参考视图。
type permissionCatalog struct {
	Version           string
	Permissions       []PermissionEntry
	SystemRoles       []RoleEntry
	ApplicationRoles  []RoleEntry
	SystemGroups      []GroupEntry
	ApplicationGroups []GroupEntry
}

// loadPermissionCatalog 读取 internal/preset 的默认目录（版本化机器目录）。
func loadPermissionCatalog() (permissionCatalog, error) {
	catalog := preset.DefaultCatalog()
	if catalog == nil {
		return permissionCatalog{}, fmt.Errorf("预设目录为空")
	}
	result := permissionCatalog{Version: catalog.Version}
	for _, definition := range catalog.Permissions {
		result.Permissions = append(result.Permissions, PermissionEntry{
			Key: definition.Key, Name: definition.Name, Summary: definition.Summary,
			Scope: definition.Scope, Limits: definition.Limits,
			RequiresReauth: definition.RequiresReauth, RootOnly: definition.RootOnly,
			DefaultRoles: append([]string(nil), definition.DefaultRoles...),
			Implemented:  definition.Implemented,
		})
	}
	result.SystemRoles = roleEntries(catalog.Roles, false)
	result.ApplicationRoles = roleEntries(catalog.ApplicationRoles, true)
	for _, group := range catalog.Groups {
		result.SystemGroups = append(result.SystemGroups, GroupEntry{
			Key: group.Key, Name: group.Name, Description: group.Description,
		})
	}
	for _, group := range catalog.ApplicationGroups {
		result.ApplicationGroups = append(result.ApplicationGroups, GroupEntry{
			Key: group.Key, Name: group.Name, Description: group.Description,
			ApplicationScope: true,
		})
	}
	return result, nil
}

// roleEntries 把角色模板转换为参考条目。
func roleEntries(templates []preset.RoleTemplate, applicationScope bool) []RoleEntry {
	entries := make([]RoleEntry, 0, len(templates))
	for _, template := range templates {
		entries = append(entries, RoleEntry{
			Key: template.Key, Name: template.Name, Summary: template.Summary,
			Limits: template.Limits, Builtin: template.Builtin, Core: template.Core,
			DefaultPermissions: append([]string(nil), template.DefaultPermissions...),
			DefaultGroupKey:    template.DefaultGroupKey,
			ApplicationScope:   applicationScope,
		})
	}
	return entries
}

// loadConfigFields 读取配置字段元数据（字段、环境变量、生效分类、秘密标记）。
func loadConfigFields() []ConfigFieldEntry {
	fields := config.Fields()
	entries := make([]ConfigFieldEntry, 0, len(fields))
	for _, field := range fields {
		entries = append(entries, ConfigFieldEntry{
			Field: field.Field, Env: field.Env, Class: string(field.Class), Secret: field.Secret,
		})
	}
	return entries
}
