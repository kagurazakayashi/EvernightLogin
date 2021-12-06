package loginte2e

import (
	"fmt"
	"os"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

// 受保护秘密文件的读取与解析。
//
// 安全约定：
//   - 读取前必须通过 secrets.CheckProtectedFile（Windows 检查 DACL，类 Unix 检查
//     权限位）。检查失败直接拒绝，不“先读再警告”。
//   - 文件内容只保留在内存中的 Config 字段里；任何错误信息都不包含文件内容。
//   - 支持三种常见格式：纯会话秘密一行、HTTP Cookie 头（`a=b; c=d`）、
//     Netscape cookies.txt（浏览器导出）。工具无法知道服务端 Cookie 名时可用
//     SessionCookieName 选择；只有一项时直接采用。

// LoadSessionSecretFile 读取并解析浏览器会话 Cookie/会话秘密文件。返回的字符串
// 是会话秘密原文（调用方不得打印）。
func LoadSessionSecretFile(path, cookieName string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("%w: 未提供会话 Cookie 文件", ErrConfigInvalid)
	}
	if cookieName == "" {
		cookieName = DefaultSessionCookieName
	}
	content, err := readProtectedSecretFile(path)
	if err != nil {
		return "", err
	}
	return parseSecretContent(content, cookieName)
}

// LoadAdminSessionSecretFile 读取管理会话秘密文件。管理 API 会话秘密通常以
// Authorization: Bearer 方式使用，也接受 Cookie 头格式（取 Cookie 值）。
func LoadAdminSessionSecretFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("%w: 未提供管理会话文件", ErrConfigInvalid)
	}
	content, err := readProtectedSecretFile(path)
	if err != nil {
		return "", err
	}
	return parseSecretContent(content, DefaultSessionCookieName)
}

// LoadClientSecretFile 读取保密客户端密钥文件（纯值一行）。
func LoadClientSecretFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("%w: 未提供客户端密钥文件", ErrConfigInvalid)
	}
	content, err := readProtectedSecretFile(path)
	if err != nil {
		return "", err
	}
	return parseSecretContent(content, "")
}

// readProtectedSecretFile 校验受保护文件并读取内容（大小有上限）。
func readProtectedSecretFile(path string) (string, error) {
	if err := secrets.CheckProtectedFile(path); err != nil {
		return "", fmt.Errorf("%w: 秘密文件未满足受保护文件要求（非 Windows 需 0600，Windows 需受限 DACL）",
			ErrConfigInvalid)
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("%w: 无法读取秘密文件状态", ErrConfigInvalid)
	}
	if info.Size() > maxSecretFileBytes {
		return "", fmt.Errorf("%w: 秘密文件超过 %d 字节", ErrConfigInvalid, maxSecretFileBytes)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("%w: 读取秘密文件失败", ErrConfigInvalid)
	}
	if len(payload) == 0 {
		return "", fmt.Errorf("%w: 秘密文件为空", ErrConfigInvalid)
	}
	if len(payload) > maxSecretFileBytes {
		return "", fmt.Errorf("%w: 秘密文件超过 %d 字节", ErrConfigInvalid, maxSecretFileBytes)
	}
	return string(payload), nil
}

// isCookieFile 判断内容是否像 Cookie 文件（Netscape 或 Cookie 头）而不是纯秘密。
func isCookieFile(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(strings.ToLower(trimmed), "cookie:") {
			return true
		}
		if strings.Count(trimmed, "\t") >= 6 {
			return true
		}
		if strings.Contains(trimmed, "=") && strings.Contains(trimmed, ";") {
			return true
		}
		// 单行 `name=value`：会话秘密本身不含 "="，因此按 Cookie 对解析更安全。
		if !strings.ContainsAny(trimmed, " \t") && strings.Count(trimmed, "=") == 1 {
			return true
		}
	}
	return false
}

// parseSecretContent 按内容形态解析秘密：Netscape cookies.txt、Cookie 头或纯值。
func parseSecretContent(content, cookieName string) (string, error) {
	trimmedBOM := strings.TrimPrefix(content, "\ufeff")
	if strings.TrimSpace(trimmedBOM) == "" {
		return "", fmt.Errorf("%w: 秘密文件内容为空", ErrConfigInvalid)
	}
	if !isCookieFile(trimmedBOM) {
		secret := strings.TrimSpace(trimmedBOM)
		if err := validateSecretValue(secret); err != nil {
			return "", err
		}
		return secret, nil
	}
	cookies, err := parseCookieFile(trimmedBOM)
	if err != nil {
		return "", err
	}
	if len(cookies) == 0 {
		return "", fmt.Errorf("%w: Cookie 文件不含任何 Cookie", ErrConfigInvalid)
	}
	if cookieName != "" {
		for index := range cookies {
			if cookies[index].name == cookieName {
				return cookies[index].value, nil
			}
		}
	}
	if len(cookies) == 1 {
		return cookies[0].value, nil
	}
	names := make([]string, 0, len(cookies))
	for index := range cookies {
		names = append(names, cookies[index].name)
	}
	return "", fmt.Errorf("%w: Cookie 文件含多个 Cookie（%s），请用 Cookie 名选择目标会话",
		ErrConfigInvalid, strings.Join(names, ", "))
}

// cookieEntry 是从 Cookie 文件解析出的一项。
type cookieEntry struct{ name, value string }

// parseCookieFile 解析 Netscape cookies.txt 或 Cookie 头；只保留名字与值。
func parseCookieFile(content string) ([]cookieEntry, error) {
	var result []cookieEntry
	for _, rawLine := range strings.Split(content, "\n") {
		line := strings.TrimRight(rawLine, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(strings.ToLower(trimmed), "cookie:") {
			header := strings.TrimSpace(trimmed[len("Cookie:"):])
			result = append(result, parseCookieHeader(header)...)
			continue
		}
		if strings.Count(line, "\t") >= 6 {
			fields := strings.Split(line, "\t")
			if len(fields) < 7 {
				continue
			}
			name := strings.TrimSpace(fields[5])
			value := strings.TrimSpace(fields[6])
			if name != "" && value != "" {
				result = append(result, cookieEntry{name: name, value: value})
			}
			continue
		}
		if strings.Contains(trimmed, "=") {
			result = append(result, parseCookieHeader(trimmed)...)
			continue
		}
		return nil, fmt.Errorf("%w: Cookie 文件包含无法识别的行", ErrConfigInvalid)
	}
	return result, nil
}

// parseCookieHeader 解析 `name=value; name2=value2` 形式的 Cookie 头。
func parseCookieHeader(header string) []cookieEntry {
	var result []cookieEntry
	for _, part := range strings.Split(header, ";") {
		pair := strings.TrimSpace(part)
		if pair == "" {
			continue
		}
		name, value, found := strings.Cut(pair, "=")
		if !found {
			continue
		}
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if name == "" || value == "" {
			continue
		}
		result = append(result, cookieEntry{name: name, value: value})
	}
	return result
}

// validateSecretValue 校验纯秘密值的基本形态：可见 ASCII、无空白、长度合理。
func validateSecretValue(value string) error {
	if value == "" {
		return fmt.Errorf("%w: 秘密值为空", ErrConfigInvalid)
	}
	if len(value) > 4096 {
		return fmt.Errorf("%w: 秘密值过长", ErrConfigInvalid)
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character <= 0x20 || character >= 0x7f || character == '"' || character == '\\' {
			return fmt.Errorf("%w: 秘密值含非法字符（只允许单行可见 ASCII）", ErrConfigInvalid)
		}
	}
	return nil
}
