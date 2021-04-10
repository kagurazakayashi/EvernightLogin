package login

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// MaxSecretBytes 是配置加载器接受的最大秘密长度。超过上限的来源会被拒绝，
// 避免把日志、证书等大文件误当成秘密整体读入内存。
const MaxSecretBytes = 64 * 1024

// Secret 保存一个配置秘密，例如主密钥材料。
//
// Secret 的零值表示“未设置”。任何字符串化、格式化以及 JSON/YAML 序列化都
// 只输出脱敏标记，不会输出内容；只有显式调用 Value 才能取得副本。调用方
// 不得把 Value 的结果写入日志、错误、报告或任何可被他人读取的位置。
//
// 本步只负责秘密的保存与脱敏，不代表已经实现主密钥加载、加密或轮换
// （见步骤 08）。
type Secret struct {
	value []byte
	set   bool
}

// NewSecret 从字节切片构造秘密，并复制内容，调用方可以安全重用原切片。
// 空值也会被标记为“已设置”，由配置校验决定是否允许。
func NewSecret(value []byte) Secret {
	copied := make([]byte, len(value))
	copy(copied, value)
	return Secret{value: copied, set: true}
}

// NewSecretString 从字符串构造秘密，行为与 NewSecret 相同。
func NewSecretString(value string) Secret {
	return NewSecret([]byte(value))
}

// IsSet 报告秘密是否已配置。它不会暴露秘密内容。
func (s Secret) IsSet() bool {
	return s.set
}

// Len 返回秘密的字节长度；未设置时返回 0。长度本身可用于校验，但不是秘密内容。
func (s Secret) Len() int {
	if !s.set {
		return 0
	}
	return len(s.value)
}

// Value 返回秘密内容的副本；未设置时返回 nil。调用方必须自行限制副本的
// 生命周期，不得记录或持久化到非受保护位置。
func (s Secret) Value() []byte {
	if !s.set {
		return nil
	}
	copied := make([]byte, len(s.value))
	copy(copied, s.value)
	return copied
}

// String 实现 fmt.Stringer。已设置的秘密固定显示为 [REDACTED]，未设置显示为
// [UNSET]，两者都不包含内容。
func (s Secret) String() string {
	if s.set {
		return "[REDACTED]"
	}
	return "[UNSET]"
}

// GoString 实现 fmt.GoStringer，覆盖 %#v 输出，避免调试打印泄露秘密。
func (s Secret) GoString() string {
	return s.String()
}

// Format 实现 fmt.Formatter，覆盖 %v、%s、%q、%x 等格式化动词。
func (s Secret) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(s.String()))
}

// MarshalText 实现 encoding.TextMarshaler，输出脱敏标记。
func (s Secret) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// MarshalJSON 实现 json.Marshaler，输出脱敏标记。
func (s Secret) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// MarshalYAML 实现 yaml.Marshaler，输出脱敏标记；不得据此序列化后回读为秘密。
func (s Secret) MarshalYAML() (any, error) {
	return s.String(), nil
}

// SecretSourceKind 是受保护秘密来源的类型。
type SecretSourceKind string

const (
	// SecretSourceEnv 表示秘密值来自环境变量。环境变量在进程环境中可被同用户
	// 的进程读取，只适合无法使用文件的部署方式。
	SecretSourceEnv SecretSourceKind = "env"
	// SecretSourceFile 表示秘密值来自受保护文件；非 Windows 平台会检查文件
	// 权限不向其他用户开放。
	SecretSourceFile SecretSourceKind = "file"
)

// SecretSource 指向一个受保护的秘密来源，本身不包含秘密值。它可以在 YAML 中
// 出现，因此可以安全地存入版本库和诊断输出。
type SecretSource struct {
	Kind SecretSourceKind
	// Name 是环境变量名或秘密文件的绝对路径。
	Name string
}

// ParseSecretSource 解析 "env:NAME" 或 "file:绝对路径" 形式的秘密来源描述。
// 秘密值本身不能写在配置里，只能通过这些受保护来源提供。
func ParseSecretSource(spec string) (SecretSource, error) {
	kind, name, ok := strings.Cut(spec, ":")
	if !ok || name == "" {
		return SecretSource{}, fmt.Errorf("秘密来源必须写成 env:环境变量名 或 file:绝对路径")
	}
	switch SecretSourceKind(kind) {
	case SecretSourceEnv:
		if !validEnvName(name) {
			return SecretSource{}, fmt.Errorf("秘密来源的环境变量名不合法")
		}
	case SecretSourceFile:
		if !filepath.IsAbs(name) {
			return SecretSource{}, fmt.Errorf("秘密文件必须使用绝对路径")
		}
	default:
		return SecretSource{}, fmt.Errorf("不支持的秘密来源类型（只支持 env 或 file）")
	}
	return SecretSource{Kind: SecretSourceKind(kind), Name: name}, nil
}

// validEnvName 只接受由 ASCII 字母、数字和下划线组成且不以数字开头的名称，与
// Go 的 os.LookupEnv 名称约定一致，避免跨平台环境变量名差异。
func validEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		if i == 0 {
			if !(r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')) {
				return false
			}
			continue
		}
		if !(r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// Load 从受保护来源读取秘密值。错误只描述来源（变量名或文件路径），不会包含
// 秘密内容。
func (s SecretSource) Load() (Secret, error) {
	return s.load(nil)
}

// load 与 Load 相同，但允许注入环境变量读取函数，便于测试和宿主定制。
// lookup 为 nil 时使用 os.LookupEnv。
func (s SecretSource) load(lookup func(string) (string, bool)) (Secret, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	switch s.Kind {
	case SecretSourceEnv:
		value, ok := lookup(s.Name)
		if !ok {
			return Secret{}, fmt.Errorf("秘密环境变量未设置")
		}
		if value == "" {
			return Secret{}, fmt.Errorf("秘密环境变量为空")
		}
		if len(value) > MaxSecretBytes {
			return Secret{}, fmt.Errorf("秘密环境变量内容超过 %d 字节上限", MaxSecretBytes)
		}
		return NewSecretString(value), nil
	case SecretSourceFile:
		return loadSecretFile(s.Name)
	default:
		return Secret{}, fmt.Errorf("不支持的秘密来源类型")
	}
}

// loadSecretFile 读取秘密文件并做基本安全检查：必须是绝对路径、普通文件、
// 大小受限、非空；非 Windows 平台还要求不向组或其他用户开放权限。
func loadSecretFile(path string) (Secret, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Secret{}, fmt.Errorf("无法读取秘密文件：%v", err)
	}
	if !info.Mode().IsRegular() {
		return Secret{}, fmt.Errorf("秘密来源必须是普通文件")
	}
	if info.Size() > MaxSecretBytes {
		return Secret{}, fmt.Errorf("秘密文件超过 %d 字节上限", MaxSecretBytes)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return Secret{}, fmt.Errorf("秘密文件权限过宽，必须仅所有者可读写")
	}

	file, err := os.Open(path)
	if err != nil {
		return Secret{}, fmt.Errorf("无法读取秘密文件：%v", err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, MaxSecretBytes+1))
	if err != nil {
		return Secret{}, fmt.Errorf("读取秘密文件失败：%v", err)
	}
	if len(data) > MaxSecretBytes {
		return Secret{}, fmt.Errorf("秘密文件超过 %d 字节上限", MaxSecretBytes)
	}
	// 密钥文件常以换行结尾；只去掉行尾的 CR/LF，不修改内容中间的空格。
	data = bytes.TrimRight(data, "\r\n")
	if len(data) == 0 {
		return Secret{}, fmt.Errorf("秘密文件为空")
	}
	return NewSecret(data), nil
}

// secretsEqual 比较两个秘密是否都由设置且内容相同，仅用于配置差异判断。
func secretsEqual(a, b Secret) bool {
	if a.set != b.set {
		return false
	}
	return bytes.Equal(a.value, b.value)
}
