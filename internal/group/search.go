package group

// 用户组列表有界字面搜索：复用 internal/search 的规范化与 LIKE 转义约定。
//
// 搜索只作用于调用方可管理的系统/应用范围（范围条件先于搜索进入 SQL），应用管理员
// 不会因搜索读取其他应用的用户组；固定状态/排序/分页契约不变。

import (
	"fmt"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/search"
)

// GroupSearchField 是用户组列表模糊搜索允许的字段白名单。
type GroupSearchField string

const (
	// GroupSearchName 匹配用户组显示名称（字面子串，按方言大小写规则折叠）。
	GroupSearchName GroupSearchField = "name"
	// GroupSearchKey 匹配用户组机器标识（字面子串）。
	GroupSearchKey GroupSearchField = "key"
)

// Valid 报告搜索字段是否在白名单内。
func (f GroupSearchField) Valid() bool {
	switch f {
	case GroupSearchName, GroupSearchKey:
		return true
	default:
		return false
	}
}

// DefaultGroupSearchFields 返回不指定字段时的默认搜索字段（名称、机器标识）。
func DefaultGroupSearchFields() []GroupSearchField {
	return []GroupSearchField{GroupSearchName, GroupSearchKey}
}

// normalizeGroupSearch 规范化搜索文本与字段白名单；空搜索返回空文本。
func normalizeGroupSearch(raw string, fields []GroupSearchField) (string, []GroupSearchField, error) {
	text, err := search.NormalizeQuery(raw)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	if text == "" {
		return "", nil, nil
	}
	if len(fields) == 0 {
		return text, DefaultGroupSearchFields(), nil
	}
	seen := make(map[GroupSearchField]struct{}, len(fields))
	normalized := make([]GroupSearchField, 0, len(fields))
	for _, field := range fields {
		value := GroupSearchField(strings.TrimSpace(string(field)))
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
