// Package search 提供跨列表共享的有界字面模糊搜索输入规范化与 LIKE 转义约定。
//
// 定位与边界：
//   - 搜索是**字面子串匹配**（默认 contains），不把用户输入解释为正则、拼音、
//     近似拼写或 SQL 模式；不做模糊排序与相关度评分。
//   - 查询文本按既有用户名口径做 NFKC + Unicode 大小写折叠 + NFC（与
//     internal/account 的用户名唯一性规范化同源），使全角/大小写变体按同一字面
//     匹配；空文本表示不使用搜索过滤，保持原列表。
//   - 转义用固定的 ESCAPE '!'，而不是反斜杠：MySQL 默认把反斜杠当作字符串转义符，
//     反斜杠作 ESCAPE 会产生方言差异；'!' 在 SQLite/MySQL/PostgreSQL/SQL Server
//     中都是普通字符。`%`、`_`、`[`、`]` 与 ESCAPE 字符自身会被转义，使它们在所有
//     方言中按字面匹配（SQL Server 的方括号字符类也会被中和）；反斜杠在声明了
//     ESCAPE '!' 的方言中没有特殊含义，因此保持原样、不额外转义（与实现一致）。
//   - LIKE 模式必须作为独立参数绑定（参数化查询），不做字符串拼接；单引号由
//     参数绑定处理，不在这里做字符串转义。
//   - 查询长度有界（MaxQueryRunes），调用方不得把一次搜索放大成无界扫描。
package search

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

const (
	// MaxQueryRunes 是单次搜索文本的字符数上限（NFKC 规范化后按码点计）。与
	// 用户名/昵称等可搜索字段的量级匹配，避免超长模式放大查询与日志开销。
	MaxQueryRunes = 64
	// EscapeChar 是 LIKE 的 ESCAPE 字符；调用方必须在 SQL 中声明
	// `ESCAPE '!'`，并把 ContainsPattern 的结果作为绑定参数。
	EscapeChar = '!'
)

// ErrInvalidQuery 表示搜索文本不合法（超长、控制字符或非法 UTF-8）。
var ErrInvalidQuery = errors.New("搜索条件无效")

// NormalizeQuery 规范化搜索文本：去首尾空白、NFKC、Unicode 大小写折叠、NFC。
// 空文本返回 ""，表示不使用搜索过滤（保持原列表）。任何超出允许范围的输入都
// 返回 ErrInvalidQuery，调用方应映射为 REQ_INVALID 并拒绝请求，不能静默截断。
func NormalizeQuery(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	if !utf8.ValidString(trimmed) {
		return "", fmt.Errorf("%w: 搜索文本不是合法 UTF-8", ErrInvalidQuery)
	}
	canonical := norm.NFC.String(cases.Fold().String(norm.NFKC.String(trimmed)))
	if canonical == "" {
		return "", nil
	}
	count := 0
	for _, character := range canonical {
		count++
		if character == '\n' || character == '\t' {
			// 搜索是单行输入；空白字符在字面包含匹配中没有意义，统一拒绝。
			return "", fmt.Errorf("%w: 搜索文本不能包含换行或制表符", ErrInvalidQuery)
		}
		if unicode.IsControl(character) || unicode.Is(unicode.Cf, character) ||
			unicode.Is(unicode.Zl, character) || unicode.Is(unicode.Zp, character) {
			return "", fmt.Errorf("%w: 搜索文本包含不允许的控制或格式字符", ErrInvalidQuery)
		}
	}
	if count > MaxQueryRunes {
		return "", fmt.Errorf("%w: 搜索文本不能超过 %d 个字符", ErrInvalidQuery, MaxQueryRunes)
	}
	return canonical, nil
}

// ContainsPattern 返回字面子串匹配的 LIKE 模式（首尾加 %）。返回值必须作为独立
// 绑定参数使用，且 SQL 必须声明 `ESCAPE '!'`；空输入返回空串（调用方应视为
// 无搜索，不要生成 LIKE）。
func ContainsPattern(normalized string) string {
	if normalized == "" {
		return ""
	}
	return "%" + EscapeLike(normalized) + "%"
}

// PrefixPattern 返回字面前缀匹配的 LIKE 模式（尾部加 %），供需要前缀语义的
// 列表使用；同样必须参数化并声明 `ESCAPE '!'`。
func PrefixPattern(normalized string) string {
	if normalized == "" {
		return ""
	}
	return EscapeLike(normalized) + "%"
}

// EscapeLike 转义 LIKE 中具有特殊含义的字符：ESCAPE 字符自身、`%`、`_`、`[`、`]`。
// 反斜杠在任何声明了 ESCAPE '!' 的方言中都是普通字符，因此保持原样；单引号由
// 参数化绑定处理，绝不需要（也不应该）在这里做字符串拼接式转义。
func EscapeLike(value string) string {
	if !strings.ContainsAny(value, `!%_[]`) {
		return value
	}
	var builder strings.Builder
	builder.Grow(len(value) + 8)
	for _, character := range value {
		switch character {
		case EscapeChar, '%', '_', '[', ']':
			builder.WriteRune(EscapeChar)
		}
		builder.WriteRune(character)
	}
	return builder.String()
}
