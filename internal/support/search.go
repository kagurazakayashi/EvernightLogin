package support

// 客服工单列表有界字面搜索：复用 internal/search 的输入规范化与 LIKE 转义约定。
//
// 只允许搜索工单编号与原因（标题等价文本）；**不搜索**脱敏邮箱、真实用户名等
// 隐藏字段，避免向无权调用者泄露“隐藏字段是否匹配”的存在性信息。搜索始终在
// staffScope/Assignee 授权范围之后执行。

import (
	"fmt"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/search"
)

// normalizeCaseSearch 规范化搜索文本与字段白名单；空搜索返回空文本。
// 未知字段/超长/控制字符返回 ErrInvalidRequest（不静默回退默认字段）。
func normalizeCaseSearch(raw string, fields []CaseSearchField) (string, []CaseSearchField, error) {
	text, err := search.NormalizeQuery(raw)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	if text == "" {
		return "", nil, nil
	}
	if len(fields) == 0 {
		return text, DefaultCaseSearchFields(), nil
	}
	seen := make(map[CaseSearchField]struct{}, len(fields))
	normalized := make([]CaseSearchField, 0, len(fields))
	for _, field := range fields {
		value := CaseSearchField(strings.TrimSpace(string(field)))
		if !value.Valid() {
			return "", nil, fmt.Errorf("%w: 搜索字段 %q 不在允许列表内（仅支持 id/reason；"+
				"不搜索脱敏邮箱/用户名等隐藏字段）", ErrInvalidRequest, field)
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return text, normalized, nil
}
