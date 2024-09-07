package role

// 角色列表有界字面搜索：复用 internal/search 的输入规范化与 LIKE 转义约定
// （NFKC + Unicode 大小写折叠 + NFC；ESCAPE '!'；参数化绑定）。
//
// 搜索范围只作用于角色自身可见行，且始终在调用方可管理的系统/应用范围之后执行：
// 应用管理员搜索不会返回其他应用的跨范围同名角色。邮箱/电话等与角色无关的字段
// 不接受；固定枚举（内置/启用状态）继续用既有精确过滤，不做模糊搜索。

import (
	"fmt"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/search"
)

// RoleSearchField 是角色列表模糊搜索允许的字段白名单。
type RoleSearchField string

const (
	// RoleSearchName 匹配角色显示名称（字面子串，按方言大小写规则折叠）。
	RoleSearchName RoleSearchField = "name"
	// RoleSearchKey 匹配角色机器标识（lower_snake，字面子串）。
	RoleSearchKey RoleSearchField = "key"
)

// Valid 报告搜索字段是否在白名单内。
func (f RoleSearchField) Valid() bool {
	switch f {
	case RoleSearchName, RoleSearchKey:
		return true
	default:
		return false
	}
}

// DefaultRoleSearchFields 返回不指定字段时的默认搜索字段（名称、机器标识）。
func DefaultRoleSearchFields() []RoleSearchField {
	return []RoleSearchField{RoleSearchName, RoleSearchKey}
}

// normalizeRoleSearch 规范化搜索文本与字段白名单。空搜索返回空文本（不过滤）；
// 未知字段返回 ErrInvalidRequest（不静默回退到默认字段）。
func normalizeRoleSearch(raw string, fields []RoleSearchField) (string, []RoleSearchField, error) {
	text, err := search.NormalizeQuery(raw)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	if text == "" {
		return "", nil, nil
	}
	if len(fields) == 0 {
		return text, DefaultRoleSearchFields(), nil
	}
	seen := make(map[RoleSearchField]struct{}, len(fields))
	normalized := make([]RoleSearchField, 0, len(fields))
	for _, field := range fields {
		value := RoleSearchField(strings.TrimSpace(string(field)))
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
