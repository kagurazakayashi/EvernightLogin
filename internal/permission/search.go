package permission

// 权限目录列表有界字面搜索：复用 internal/search 的规范化与 LIKE 转义约定。
//
// 搜索只作用于调用方可见的权限行（系统或应用范围先由授权与 SQL 范围条件限定），
// 因此应用管理员不会因搜索读取其他应用的权限或系统隐藏权限；内置权限的存在性、
// 可启停性与 root_only 保护不受搜索影响。固定状态继续用既有 Enabled 精确过滤。

import (
	"fmt"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/search"
)

// PermissionSearchField 是权限目录模糊搜索允许的字段白名单。
type PermissionSearchField string

const (
	// PermissionSearchName 匹配权限显示名称（字面子串，按方言大小写规则折叠）。
	PermissionSearchName PermissionSearchField = "name"
	// PermissionSearchKey 匹配权限机器标识（字面子串）。
	PermissionSearchKey PermissionSearchField = "key"
)

// Valid 报告搜索字段是否在白名单内。
func (f PermissionSearchField) Valid() bool {
	switch f {
	case PermissionSearchName, PermissionSearchKey:
		return true
	default:
		return false
	}
}

// DefaultPermissionSearchFields 返回不指定字段时的默认搜索字段（名称、机器标识）。
func DefaultPermissionSearchFields() []PermissionSearchField {
	return []PermissionSearchField{PermissionSearchName, PermissionSearchKey}
}

// normalizePermissionSearch 规范化搜索文本与字段白名单；空搜索返回空文本。
func normalizePermissionSearch(raw string, fields []PermissionSearchField) (string, []PermissionSearchField, error) {
	text, err := search.NormalizeQuery(raw)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	if text == "" {
		return "", nil, nil
	}
	if len(fields) == 0 {
		return text, DefaultPermissionSearchFields(), nil
	}
	seen := make(map[PermissionSearchField]struct{}, len(fields))
	normalized := make([]PermissionSearchField, 0, len(fields))
	for _, field := range fields {
		value := PermissionSearchField(strings.TrimSpace(string(field)))
		if !value.Valid() {
			return "", nil, fmt.Errorf("%w: 搜索字段 %q 不在允许列表内（仅支持 name/key）",
				ErrInvalidRequest, field)
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return text, normalized, nil
}
