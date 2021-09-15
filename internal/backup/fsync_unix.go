//go:build !windows

package backup

import (
	"fmt"
	"os"
)

// syncDir 在非 Windows 平台同步目录项，确保原子改名在崩溃后可见。Windows 上
// 目录句柄的 fsync 语义与 Unix 不同，见 fsync_windows.go；文件内容始终会被 fsync。
func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("无法打开备份目录同步: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("无法同步备份目录: %w", err)
	}
	return nil
}

// isWindowsPlatform 报告当前平台是否为 Windows（用于平台化权限差异）。
func isWindowsPlatform() bool { return false }
