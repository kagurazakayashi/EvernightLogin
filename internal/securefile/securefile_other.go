//go:build !windows

package securefile

// 非 Windows：秘密文件保护依赖 POSIX 模式位 0600（仅所有者读写）。

import (
	"fmt"
	"os"
)

// protect 收紧新文件模式位并自检。
func protect(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("%w: 设置 0600 失败: %v", ErrProtectFailed, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%w: 读取权限失败: %v", ErrProtectFailed, err)
	}
	return verify(path, info)
}

// verify 校验已有文件模式位不得授予组/其他用户任何访问。
func verify(path string, info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: 权限 %04o 过宽（期望 0600 或更严格）", ErrInsecurePerm,
			info.Mode().Perm())
	}
	return nil
}
