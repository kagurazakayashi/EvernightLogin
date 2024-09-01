package app

// 应用列表有界字面搜索：复用 internal/search 的规范化与 LIKE 转义约定。
//
// 搜索只作用于调用方可管理的应用范围（系统管理员全部 / 应用管理员仅已分配应用，
// 由 ApplicationScope 与 SQL 范围条件先行限定），不会因搜索枚举未分配应用；已逻辑
// 删除应用默认仍被排除，IncludeDeleted 与状态过滤语义不变。

import (
	"fmt"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/search"
)

// ApplicationSearchField 是应用列表模糊搜索允许的字段白名单。
type ApplicationSearchField string

const (
	// ApplicationSearchName 匹配应用名称（字面子串，按方言大小写规则折叠）。
	ApplicationSearchName ApplicationSearchField = "name"
	// ApplicationSearchDescription 匹配应用描述（字面子串，按方言大小写规则折叠）。
	ApplicationSearchDescription ApplicationSearchField = "description"
)

// Valid 报告搜索字段是否在白名单内。
func (f ApplicationSearchField) Valid() bool {
	switch f {
	case ApplicationSearchName, ApplicationSearchDescription:
		return true
	default:
		return false
	}
}

// DefaultApplicationSearchFields 返回不指定字段时的默认搜索字段（名称、描述）。
func DefaultApplicationSearchFields() []ApplicationSearchField {
	return []ApplicationSearchField{ApplicationSearchName, ApplicationSearchDescription}
}

// normalizeApplicationSearch 规范化搜索文本与字段白名单；空搜索返回空文本。
func normalizeApplicationSearch(raw string, fields []ApplicationSearchField) (string, []ApplicationSearchField, error) {
	text, err := search.NormalizeQuery(raw)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	if text == "" {
		return "", nil, nil
	}
	if len(fields) == 0 {
		return text, DefaultApplicationSearchFields(), nil
	}
	seen := make(map[ApplicationSearchField]struct{}, len(fields))
	normalized := make([]ApplicationSearchField, 0, len(fields))
	for _, field := range fields {
		value := ApplicationSearchField(strings.TrimSpace(string(field)))
		if !value.Valid() {
			return "", nil, fmt.Errorf("%w: 搜索字段 %q 不在允许列表内（仅支持 name/description）",
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
