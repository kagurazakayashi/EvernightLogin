//go:build !windows

package rootrecovery

import (
	"fmt"
	"os"
	"syscall"
)

// fileIdentity 返回数据库文件的稳定身份（设备号 + inode），用于让同一底层文件的
// 不同路径（含硬链接）共享同一把互斥锁。
func fileIdentity(resolvedPath string) (string, error) {
	info, err := os.Stat(resolvedPath)
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("无法读取文件 inode 信息")
	}
	return fmt.Sprintf("unix:%d:%d", stat.Dev, stat.Ino), nil
}
