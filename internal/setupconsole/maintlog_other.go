//go:build !windows

package setupconsole

// 非 Windows 维护日志保护自检：模式位必须为 0600（仅所有者读写）。
// Windows 的 NTFS ACL 处理见 maintlog_windows.go。

import (
	"fmt"
	"os"
)

// prepareMaintenanceLogFile 校验非 Windows 文件模式位，不满足则 fail-closed。
func prepareMaintenanceLogFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrLogUnavailable, err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf("%w: 维护日志权限 %04o 过宽，期望 0600", ErrLogUnavailable, mode)
	}
	return nil
}
