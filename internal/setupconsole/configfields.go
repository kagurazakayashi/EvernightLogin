package setupconsole

// 全配置字段编辑模型（步骤279）。
//
// 唯一语义来源是主配置包的字段注册表 config.Fields() 与校验器 config.Load：
//   - 字段清单/环境变量名/重载分类/秘密标记全部来自注册表，新增字段自动出现；
//   - 默认值/有效值用 config.Default()/Config.FieldValues() 的脱敏取值，与控制台
//     自身环境无关；环境变量覆盖只提示“已设置”，不回显值；
//   - 编辑对象是 YAML 树草稿（内存），支持标量/布尔/数字/列表/映射与嵌套路径；
//     草稿不写盘，保存/差异确认在步骤280接入；
//   - 秘密字段只显示状态（[REDACTED]/[UNSET]/来源），不在本画面回显或编辑；
//   - 未知字段/未在注册表中的 YAML 键保留在草稿树中。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/kagurazakayashi/EvernightLogin/config"
)

// ConfigDraft 是内存配置草稿（文件原始文本 + 可编辑 YAML 树）。
type ConfigDraft struct {
	// Path 是目标配置文件路径（保存时使用；本模型不写盘）。
	Path string
	// BaseDigest 是草稿开始时的文件摘要（外部修改冲突检测，280 使用）。
	BaseDigest string
	// baseRaw 是草稿开始时的原始文本；baseTree 是同样的已解析树，用于修改标记。
	baseRaw  []byte
	baseTree map[string]any
	tree     map[string]any
}

// NewConfigDraft 从配置文件原始文本构造草稿；空文件视为空映射。
func NewConfigDraft(path string, raw []byte) (*ConfigDraft, error) {
	tree := map[string]any{}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed != "" {
		root := map[string]any{}
		if err := yaml.Unmarshal(raw, &root); err != nil {
			return nil, fmt.Errorf("配置 YAML 解析失败: %w", err)
		}
		if root == nil {
			root = map[string]any{}
		}
		tree = root
	}
	baseCopy := deepCopyTree(tree)
	digest := sha256.Sum256(raw)
	return &ConfigDraft{Path: strings.TrimSpace(path),
		BaseDigest: hex.EncodeToString(digest[:]), baseRaw: append([]byte(nil), raw...),
		baseTree: baseCopy, tree: deepCopyTree(tree)}, nil
}

// Digest 返回当前草稿序列化内容的摘要。
func (d *ConfigDraft) Digest() string {
	if d == nil {
		return ""
	}
	sum := sha256.Sum256(d.Raw())
	return hex.EncodeToString(sum[:])
}

// Raw 返回当前草稿的 YAML 序列化文本（稳定缩进；注释不保留，未知字段保留）。
func (d *ConfigDraft) Raw() []byte {
	if d == nil {
		return nil
	}
	if len(d.tree) == 0 {
		return []byte{}
	}
	encoded, err := yaml.Marshal(d.tree)
	if err != nil {
		return nil
	}
	return encoded
}

// BaseRaw 返回草稿开始时的原始文本。
func (d *ConfigDraft) BaseRaw() []byte {
	if d == nil {
		return nil
	}
	return append([]byte(nil), d.baseRaw...)
}

// Validate 用正式加载器校验草稿内容。
func (d *ConfigDraft) Validate() ConfigReport {
	if d == nil {
		return ConfigReport{Summary: "草稿为空"}
	}
	return ValidateConfigText(d.Raw())
}

// GetValue 按点分路径读取草稿中的文件值；不存在时 found=false。
func (d *ConfigDraft) GetValue(path string) (any, bool) {
	if d == nil {
		return nil, false
	}
	segments := splitFieldPath(path)
	current := any(d.tree)
	for _, segment := range segments {
		mapping, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		value, exists := mapping[segment]
		if !exists {
			return nil, false
		}
		current = value
	}
	return current, true
}

// SetValue 按点分路径写入草稿值（自动创建/补全嵌套映射）。
func (d *ConfigDraft) SetValue(path string, value any) error {
	if d == nil {
		return errors.New("草稿为空")
	}
	segments := splitFieldPath(path)
	if len(segments) == 0 {
		return errors.New("字段路径为空")
	}
	current := d.tree
	for depth, segment := range segments[:len(segments)-1] {
		child, exists := current[segment]
		if !exists {
			child = map[string]any{}
			current[segment] = child
		}
		mapping, ok := child.(map[string]any)
		if !ok {
			// 中间层是标量/列表：用新的映射替代（草稿明确覆盖，不静默忽略）。
			mapping = map[string]any{}
			current[segment] = mapping
		}
		_ = depth
		current = mapping
	}
	current[segments[len(segments)-1]] = value
	return nil
}

// Unset 删除路径上的文件值（回退默认值），并清理空映射。
func (d *ConfigDraft) Unset(path string) {
	if d == nil {
		return
	}
	segments := splitFieldPath(path)
	if len(segments) == 0 {
		return
	}
	d.unset(d.tree, segments)
}

func (d *ConfigDraft) unset(mapping map[string]any, segments []string) bool {
	if len(segments) == 1 {
		delete(mapping, segments[0])
		return len(mapping) == 0
	}
	child, exists := mapping[segments[0]]
	if !exists {
		return false
	}
	childMap, ok := child.(map[string]any)
	if !ok {
		return false
	}
	if d.unset(childMap, segments[1:]) {
		delete(mapping, segments[0])
	}
	return len(mapping) == 0
}

// IsModified 判断字段相对草稿开始时是否修改（新增/修改/删除均算修改）。
func (d *ConfigDraft) IsModified(path string) bool {
	if d == nil {
		return false
	}
	current, currentFound := d.GetValue(path)
	previous, previousFound := getTreeValue(d.baseTree, splitFieldPath(path))
	if !currentFound && !previousFound {
		return false
	}
	if currentFound != previousFound {
		return true
	}
	return !deepEqualValue(current, previous)
}

// FieldTypeHint 返回字段的编辑类型提示（来自默认/有效值的脱敏文本形态）。
func FieldTypeHint(field string) string {
	for _, value := range config.Default().FieldValues() {
		if value.Field != field {
			continue
		}
		if value.Secret {
			return "秘密字段（只显示状态）"
		}
		text := strings.TrimSpace(value.Value)
		switch {
		case text == "true" || text == "false":
			return "布尔：true/false"
		case strings.HasPrefix(text, "["):
			return "列表：YAML 列表，例如 [\"a\", \"b\"]"
		case strings.HasPrefix(text, "{"):
			return "映射：YAML 映射，例如 {dns_name: \"x\", service: \"y\"}"
		case strings.HasPrefix(text, "\""):
			return "字符串：直接输入；输入 \"\" 表示空字符串，<unset> 表示回退默认"
		default:
			return "数字：整数；<unset> 表示回退默认"
		}
	}
	return "按字段注册表编辑"
}

// ParseFieldInput 把用户输入解析成 YAML 值；<unset>/<empty> 特殊标记由调用方处理。
func ParseFieldInput(input string) (any, error) {
	text := strings.TrimSpace(input)
	if text == "" {
		return nil, errors.New("输入为空；清空文件值请输入 <unset>，表示空字符串请输入 <empty>")
	}
	var decoded map[string]any
	if err := yaml.Unmarshal([]byte("value: "+text), &decoded); err != nil {
		// 解析失败按普通字符串处理（用户输入可能含 YAML 特殊字符）。
		return input, nil
	}
	value, exists := decoded["value"]
	if !exists {
		return input, nil
	}
	return value, nil
}

// FieldView 是一条配置字段的可展示信息。
type FieldView struct {
	Path       string
	Group      string
	GroupLabel string
	Default    string
	File       string
	Effective  string
	Override   string
	Class      string
	ClassLabel string
	Secret     bool
	Modified   bool
	HasFile    bool
	Error      string
}

// GroupLabel 返回配置分组中文标签。
func GroupLabel(group string) string {
	labels := map[string]string{
		"server":          "服务与网络",
		"logging":         "日志",
		"database":        "数据库",
		"registration":    "注册策略",
		"passkey":         "Passkey/WebAuthn",
		"protocol":        "OAuth2/OIDC 协议",
		"app_qr_login":    "已登录应用扫码登录",
		"secrets":         "主密钥/秘密来源",
		"mail":            "邮件发送",
		"manual_recovery": "人工恢复制度",
		"security":        "安全/会话策略",
		"audit":           "审计与保留",
		"reports":         "报告",
		"backups":         "备份",
		"tasks":           "后台任务",
		"ui":              "页面与品牌",
	}
	if label, exists := labels[group]; exists {
		return label
	}
	return group
}

// ClassLabel 返回重载分类中文标签。
func ClassLabel(class string) string {
	switch class {
	case string(config.ReloadHotReloadable):
		return "热重载（重新加载后生效）"
	case string(config.ReloadRestartRequired):
		return "重启进程后生效"
	default:
		return "生效方式未知"
	}
}

// BuildFieldViews 根据草稿构建全部字段视图（默认值/文件值/有效值/覆盖提示）。
func BuildFieldViews(draft *ConfigDraft) []FieldView {
	if draft == nil {
		return nil
	}
	report := draft.Validate()
	defaultValues := make(map[string]string)
	for _, value := range config.Default().FieldValues() {
		defaultValues[value.Field] = value.Value
	}
	effectiveValues := make(map[string]string)
	if report.Valid {
		for _, value := range report.Config.FieldValues() {
			effectiveValues[value.Field] = value.Value
		}
	}
	views := make([]FieldView, 0, len(config.Fields()))
	for _, info := range config.Fields() {
		group := info.Field
		if index := strings.IndexByte(info.Field, '.'); index > 0 {
			group = info.Field[:index]
		}
		view := FieldView{Path: info.Field, Group: group, GroupLabel: GroupLabel(group),
			Default: defaultValues[info.Field], Class: string(info.Class),
			ClassLabel: ClassLabel(string(info.Class)), Secret: info.Secret}
		if fileValue, found := draft.GetValue(info.Field); found {
			view.HasFile = true
			view.File = FormatFieldValue(fileValue)
		} else {
			view.File = "（默认）"
		}
		if info.Secret {
			view.Effective = secretEffectiveText(draft, info.Field, effectiveValues)
			view.File = secretFileText(draft, info.Field)
		} else if report.Valid {
			view.Effective = effectiveValues[info.Field]
		} else {
			view.Effective = "（未知：草稿校验失败）"
		}
		if _, present := os.LookupEnv(info.Env); present {
			view.Override = "环境变量 " + info.Env + " 已设置（覆盖文件值）"
		}
		view.Modified = draft.IsModified(info.Field)
		view.Error = issueForField(report.Issues, info.Field)
		views = append(views, view)
	}
	return views
}

// secretEffectiveText 秘密字段只显示设置状态（来自脱敏 FieldValues）。
func secretEffectiveText(draft *ConfigDraft, field string, effective map[string]string) string {
	if config.Default().FieldValues() == nil {
		return "（未知）"
	}
	for _, value := range config.Default().FieldValues() {
		if value.Field == field && value.Secret {
			if raw, found := draft.GetValue(field); found {
				_ = raw
				return "已配置（来源引用已写入文件；值不回显）"
			}
			return "[UNSET]（未配置）"
		}
	}
	_ = effective
	return "（未知）"
}

// secretFileText 秘密字段文件值只显示是否写了来源引用。
func secretFileText(draft *ConfigDraft, field string) string {
	if _, found := draft.GetValue(field); found {
		return "（秘密来源引用已设置）"
	}
	return "（未设置）"
}

// issueForField 找到字段相关诊断的简短说明。
func issueForField(issues []ConfigIssue, field string) string {
	for _, issue := range issues {
		if issue.Field == field {
			return issue.Kind + "：" + issue.Detail
		}
	}
	return ""
}

// FormatFieldValue 把 YAML 值格式化到单行展示（列表/映射用 YAML 流式表示）。
func FormatFieldValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return "null"
	case string:
		return fmt.Sprintf("%q", typed)
	case bool:
		return fmt.Sprintf("%t", typed)
	case int, int64, uint64, float64:
		return fmt.Sprintf("%v", typed)
	default:
		encoded, err := yaml.Marshal(typed)
		if err != nil {
			return fmt.Sprintf("%v", typed)
		}
		return strings.TrimSpace(strings.ReplaceAll(string(encoded), "\n", " "))
	}
}

// splitFieldPath 拆分点分路径。
func splitFieldPath(path string) []string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, ".")
}

// getTreeValue 按路径读取树值。
func getTreeValue(tree map[string]any, segments []string) (any, bool) {
	var current any = tree
	for _, segment := range segments {
		mapping, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		value, exists := mapping[segment]
		if !exists {
			return nil, false
		}
		current = value
	}
	return current, true
}

// deepCopyTree 深拷贝 YAML 树（只含 YAML 支持的标量/映射/序列）。
func deepCopyTree(tree map[string]any) map[string]any {
	if tree == nil {
		return map[string]any{}
	}
	copied := make(map[string]any, len(tree))
	for key, value := range tree {
		copied[key] = deepCopyValue(value)
	}
	return copied
}

func deepCopyValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return deepCopyTree(typed)
	case []any:
		copied := make([]any, len(typed))
		for index, item := range typed {
			copied[index] = deepCopyValue(item)
		}
		return copied
	default:
		return typed
	}
}

func deepEqualValue(left, right any) bool {
	switch leftTyped := left.(type) {
	case map[string]any:
		rightMap, ok := right.(map[string]any)
		if !ok || len(leftTyped) != len(rightMap) {
			return false
		}
		for key, value := range leftTyped {
			other, exists := rightMap[key]
			if !exists || !deepEqualValue(value, other) {
				return false
			}
		}
		return true
	case []any:
		rightList, ok := right.([]any)
		if !ok || len(leftTyped) != len(rightList) {
			return false
		}
		for index := range leftTyped {
			if !deepEqualValue(leftTyped[index], rightList[index]) {
				return false
			}
		}
		return true
	default:
		return fmt.Sprintf("%v", left) == fmt.Sprintf("%v", right)
	}
}

// DiffLine 是行级差异的一行。
type DiffLine struct {
	Kind string // same/add/remove
	Line int
	Text string
}

// Diff 返回草稿相对初始文本的行级差异（简单 LCS，行数有界）。
func (d *ConfigDraft) Diff() []DiffLine {
	if d == nil {
		return nil
	}
	return diffLines(splitRawLines(d.baseRaw), splitRawLines(d.Raw()))
}

func splitRawLines(raw []byte) []string {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	if text == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(text, "\n"), "\n")
}

// diffLines 使用 LCS 生成行级差异；超过 4000 行时退化为整段替换，避免无界开销。
func diffLines(before, after []string) []DiffLine {
	if len(before) > 4000 || len(after) > 4000 {
		lines := make([]DiffLine, 0, len(before)+len(after))
		for index, line := range before {
			lines = append(lines, DiffLine{Kind: "remove", Line: index + 1, Text: line})
		}
		for index, line := range after {
			lines = append(lines, DiffLine{Kind: "add", Line: index + 1, Text: line})
		}
		return lines
	}
	width := len(after) + 1
	table := make([]int, (len(before)+1)*width)
	index := func(row, column int) int { return row*width + column }
	for row := len(before) - 1; row >= 0; row-- {
		for column := len(after) - 1; column >= 0; column-- {
			if before[row] == after[column] {
				table[index(row, column)] = table[index(row+1, column+1)] + 1
			} else if table[index(row+1, column)] >= table[index(row, column+1)] {
				table[index(row, column)] = table[index(row+1, column)]
			} else {
				table[index(row, column)] = table[index(row, column+1)]
			}
		}
	}
	var lines []DiffLine
	row, column := 0, 0
	for row < len(before) && column < len(after) {
		if before[row] == after[column] {
			lines = append(lines, DiffLine{Kind: "same", Line: row + 1, Text: before[row]})
			row++
			column++
			continue
		}
		if table[index(row+1, column)] >= table[index(row, column+1)] {
			lines = append(lines, DiffLine{Kind: "remove", Line: row + 1, Text: before[row]})
			row++
		} else {
			lines = append(lines, DiffLine{Kind: "add", Line: column + 1, Text: after[column]})
			column++
		}
	}
	for ; row < len(before); row++ {
		lines = append(lines, DiffLine{Kind: "remove", Line: row + 1, Text: before[row]})
	}
	for ; column < len(after); column++ {
		lines = append(lines, DiffLine{Kind: "add", Line: column + 1, Text: after[column]})
	}
	return lines
}

// SortedGroupPairs 返回按注册表首次出现顺序的分组列表。
func SortedGroupPairs(views []FieldView) []struct{ Group, Label string } {
	seen := make(map[string]bool)
	var pairs []struct{ Group, Label string }
	for _, view := range views {
		if seen[view.Group] {
			continue
		}
		seen[view.Group] = true
		pairs = append(pairs, struct{ Group, Label string }{view.Group, view.GroupLabel})
	}
	sort.SliceStable(pairs, func(left, right int) bool {
		return false // 保持注册表顺序
	})
	return pairs
}

var _ = context.Background
