//go:build windows

package rootrecovery

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// fileIdentity 返回数据库文件的稳定身份（卷序列号 + 文件索引），用于让同一底层
// 文件的不同路径（含硬链接）共享同一把互斥锁。
func fileIdentity(resolvedPath string) (string, error) {
	file, err := os.OpenFile(resolvedPath, os.O_RDONLY, 0)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil {
		return "", err
	}
	return fmt.Sprintf("win:%08x:%08x:%08x",
		info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow), nil
}
