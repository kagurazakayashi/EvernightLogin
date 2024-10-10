package setupconsole

// 坏配置诊断与可恢复修复模型（步骤278）。
//
// 与检测器共用同一诊断模型（ConfigIssue），表单与非交互命令都只消费本文件的结果：
//   - LoadConfigReport 只读加载配置并收集：文件缺失/不可读/过大、YAML 语法/重复键/
//     未知字段/类型/范围、结构过深；
//   - 原始配置文本按行保留（修复时不做规范化重写，未知字段因此天然保留）；
//   - 保存使用 SafeWriteFile（同目录临时文件 + Sync + 原子替换 + 权限保持），
//     失败不破坏原文件；278 的“另存为”与 280 的正式应用共用该写入原语；
//   - 展示文本不含秘密值：配置错误详情由 config 包保证不含值，界面只显示原文行。

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/kagurazakayashi/EvernightLogin/config"
)

// 配置诊断常量。
const (
	// MaxConfigBytes 与主配置加载器一致：1 MiB。
	MaxConfigBytes = 1 << 20
	// MaxYAMLDepth 是控制台可展示/可编辑的 YAML 嵌套深度上限；更深的文件拒绝编辑。
	MaxYAMLDepth = 32
)

// ConfigReport 是一次配置诊断结果。
type ConfigReport struct {
	// Path 是配置文件路径。
	Path string
	// Exists/Readable 表示文件存在且可读。
	Exists   bool
	Readable bool
	// Raw 是原始文本（仅可读时非 nil）；修复界面按行编辑。
	Raw []byte
	// Valid 表示配置可被正式加载器接受。
	Valid bool
	// Config 是加载成功后的配置。
	Config config.Config
	// Issues 是可展示诊断（不含秘密值）。
	Issues []ConfigIssue
	// Summary 是一行摘要。
	Summary string
	// Size 是文件字节数（存在时）。
	Size int64
}

// LoadConfigReport 只读加载并诊断一个配置文件；不创建/修改任何文件。
func LoadConfigReport(path string) ConfigReport {
	report := ConfigReport{Path: strings.TrimSpace(path)}
	if report.Path == "" {
		report.Summary = "未指定配置文件路径"
		report.Issues = []ConfigIssue{{Kind: "options", Detail: "配置文件路径为空",
			Suggestion: "先用“选择实例配置路径”指定 login.yaml。"}}
		return report
	}
	info, err := os.Stat(report.Path)
	if err != nil {
		report.Summary = "配置文件不存在或不可访问"
		report.Issues = []ConfigIssue{{Kind: "file", Detail: publicFileError(err),
			Suggestion: "确认路径正确；全新实例可走初始化流程创建配置。"}}
		return report
	}
	report.Exists = true
	report.Size = info.Size()
	if info.IsDir() {
		report.Summary = "配置路径是目录"
		report.Issues = []ConfigIssue{{Kind: "file", Detail: "路径是目录而不是文件",
			Suggestion: "请选择 login.yaml 文件。"}}
		return report
	}
	if info.Size() > MaxConfigBytes {
		report.Summary = "配置文件超过大小上限"
		report.Issues = []ConfigIssue{{Kind: "invalid-options", Source: "loader",
			Detail:     fmt.Sprintf("配置文件 %d 字节，超过 %d 字节上限", info.Size(), MaxConfigBytes),
			Suggestion: "确认是否选错文件；不要编辑超大文件。"}}
		return report
	}
	raw, readErr := os.ReadFile(report.Path)
	if readErr != nil {
		report.Summary = "配置文件不可读"
		report.Issues = []ConfigIssue{{Kind: "file", Detail: publicFileError(readErr),
			Suggestion: "检查文件权限/占用；坏文件不会被自动覆盖。"}}
		return report
	}
	report.Readable = true
	report.Raw = raw
	// 结构深度是编辑器的安全边界：过深文件允许诊断但不进入行编辑器。
	if depth, depthErr := yamlDepth(raw); depthErr != nil {
		report.Issues = append(report.Issues, ConfigIssue{Kind: "yaml-syntax",
			Source: "yaml", Detail: "YAML 解析失败：" + publicFileError(depthErr),
			Suggestion: suggestionFor(config.ConfigErrorYAMLSyntax)})
	} else if depth > MaxYAMLDepth {
		report.Issues = append(report.Issues, ConfigIssue{Kind: "structure-too-deep",
			Source: "yaml", Detail: fmt.Sprintf("YAML 嵌套深度 %d 超过上限 %d",
				depth, MaxYAMLDepth),
			Suggestion: "缩进层级过多；请简化结构或人工修复，控制台不对此文件提供逐行编辑。"})
	}
	if _, loadErr := config.Load(config.LoadOptions{YAMLFile: report.Path}); loadErr != nil {
		if len(report.Issues) == 0 {
			report.Issues = configIssues(loadErr)
		}
		if report.Summary == "" {
			report.Summary = "配置校验失败（存在错误）"
		}
		return report
	}
	// 正式加载成功但深度超限：仍按拒绝处理（不允许编辑过深文件）。
	for _, issue := range report.Issues {
		if issue.Kind == "structure-too-deep" || issue.Kind == "yaml-syntax" {
			report.Summary = "配置可解析但结构超出控制台编辑边界"
			return report
		}
	}
	cfg, _ := config.Load(config.LoadOptions{YAMLFile: report.Path})
	report.Valid = true
	report.Config = cfg
	report.Summary = "配置有效"
	return report
}

// yamlDepth 返回 YAML 文档最大嵌套深度（映射/序列）；解析失败返回错误。
func yamlDepth(raw []byte) (int, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return 0, err
	}
	maxDepth := 0
	var walk func(node *yaml.Node, depth int)
	walk = func(node *yaml.Node, depth int) {
		if node == nil {
			return
		}
		if depth > maxDepth {
			maxDepth = depth
		}
		if depth > MaxYAMLDepth+8 {
			return // 防御性剪枝：远超上限时不再深入。
		}
		for _, child := range node.Content {
			walk(child, depth+1)
		}
	}
	if len(root.Content) > 0 {
		walk(root.Content[0], 1)
	}
	return maxDepth, nil
}

// ReloadAllowed 表示当前诊断是否允许进入行编辑（过深/超限文件只读诊断）。
func (report ConfigReport) ReloadAllowed() bool {
	if !report.Readable {
		return false
	}
	for _, issue := range report.Issues {
		if issue.Kind == "structure-too-deep" || issue.Kind == "invalid-options" {
			return false
		}
	}
	return true
}

// SafeWriteFile 以同目录临时文件 + Sync + 原子替换写入文件；失败不破坏原文件。
//
// 边界：只写调用方指定的目标文件与同目录临时文件；不删除其他文件；原文件权限位
// 被保留（目标已存在时）；不跟随符号链接（目标为符号链接时拒绝）。
func SafeWriteFile(path string, data []byte, mode os.FileMode) error {
	target := strings.TrimSpace(path)
	if target == "" {
		return errors.New("目标路径为空")
	}
	if info, err := os.Lstat(target); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("拒绝写入符号链接目标")
		}
		mode = info.Mode().Perm()
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("检查目标文件失败: %w", err)
	}
	dir := filepath.Dir(target)
	if dir == "" {
		dir = "."
	}
	temp, err := os.CreateTemp(dir, ".login-setup-save-*")
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	tempName := temp.Name()
	cleanup := func() {
		_ = temp.Close()
		_ = os.Remove(tempName)
	}
	if _, err := temp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("写入临时文件失败: %w", err)
	}
	if err := temp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("同步临时文件失败: %w", err)
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(tempName)
		return fmt.Errorf("关闭临时文件失败: %w", err)
	}
	if err := os.Chmod(tempName, mode); err != nil {
		_ = os.Remove(tempName)
		return fmt.Errorf("设置文件权限失败: %w", err)
	}
	if err := os.Rename(tempName, target); err != nil {
		_ = os.Remove(tempName)
		return fmt.Errorf("原子替换目标文件失败: %w", err)
	}
	return nil
}

// LastValidStore 是会话内“上次有效配置文本”的只读缓存（278 修复界面使用）。
//
// 只在内存中保留最近一次成功加载的原始文本；不写盘、不包含解析后的秘密值。
type LastValidStore struct {
	path string
	raw  []byte
}

// Remember 在配置有效时记录原文。
func (s *LastValidStore) Remember(report ConfigReport) {
	if s == nil || !report.Valid || report.Path == "" {
		return
	}
	s.path = report.Path
	s.raw = append([]byte(nil), report.Raw...)
}

// Load 返回当前路径的上次有效原文；没有记录时 found=false。
func (s *LastValidStore) Load(path string) ([]byte, bool) {
	if s == nil || s.path == "" || s.raw == nil {
		return nil, false
	}
	if filepath.Clean(strings.TrimSpace(path)) != filepath.Clean(s.path) {
		return nil, false
	}
	return append([]byte(nil), s.raw...), true
}

// ValidateConfigText 对编辑后的文本做与写盘前一致的正式校验（不落盘）。
func ValidateConfigText(raw []byte) ConfigReport {
	report := ConfigReport{Path: "(未保存草稿)", Readable: true, Raw: raw}
	if len(raw) > MaxConfigBytes {
		report.Summary = "配置文本超过大小上限"
		report.Issues = []ConfigIssue{{Kind: "invalid-options", Detail: "文本超过 1 MiB",
			Suggestion: "缩减配置或拆分维护。"}}
		return report
	}
	if depth, err := yamlDepth(raw); err != nil {
		report.Issues = append(report.Issues, ConfigIssue{Kind: "yaml-syntax",
			Source: "yaml", Detail: publicFileError(err),
			Suggestion: suggestionFor(config.ConfigErrorYAMLSyntax)})
		report.Summary = "草稿 YAML 解析失败"
		return report
	} else if depth > MaxYAMLDepth {
		report.Issues = append(report.Issues, ConfigIssue{Kind: "structure-too-deep",
			Detail: fmt.Sprintf("嵌套深度 %d 超过上限 %d", depth, MaxYAMLDepth)})
		report.Summary = "草稿结构过深"
		return report
	}
	// 写临时文件校验与正式文件同源；临时文件只用于本函数读取后立即删除。
	dir, err := os.MkdirTemp("", "login-setup-validate-*")
	if err != nil {
		report.Summary = "无法执行配置校验"
		report.Issues = []ConfigIssue{{Kind: "options", Detail: publicFileError(err)}}
		return report
	}
	defer os.RemoveAll(dir)
	tempPath := filepath.Join(dir, "login.yaml")
	if err := os.WriteFile(tempPath, raw, 0o600); err != nil {
		report.Summary = "无法写入校验副本"
		report.Issues = []ConfigIssue{{Kind: "options", Detail: publicFileError(err)}}
		return report
	}
	loaded, loadErr := config.Load(config.LoadOptions{YAMLFile: tempPath})
	if loadErr != nil {
		report.Issues = configIssues(loadErr)
		report.Summary = "草稿配置校验失败"
		return report
	}
	report.Valid = true
	report.Config = loaded
	report.Summary = "草稿配置有效"
	return report
}

// ContextAwait 是给非交互命令使用的空上下文兼容入口。
var _ = context.Background
