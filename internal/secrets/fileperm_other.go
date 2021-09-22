//go:build !windows

package secrets

import (
	"fmt"
	"os"
	"path/filepath"
)

// 本文件实现非 Windows 平台的密钥文件保护：要求文件是普通文件，且权限位
// 只允许所有者读写（通常为 0600）。Windows 的 ACL 检查在 fileperm_windows.go
// 中单独实现，不能把这里的 chmod 判断当成 Windows 上的充分保护。

// checkFileProtection 检查文件权限位不向组和其他用户开放。
func checkFileProtection(_ *os.File, info os.FileInfo) error {
	return validateUnixFileModePerm(info.Mode().Perm())
}

// protectExistingFile 把已存在文件的权限位设为 0600（覆盖继承的宽松权限）。
func protectExistingFile(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("%w: 无法收紧文件权限", ErrInsecurePermissions)
	}
	return nil
}

// writeProtectedFile 原子地写入受保护文件：在目标目录创建 0600 临时文件，
// 写入并同步后重命名覆盖目标，最后重新检查权限。
func writeProtectedFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".evernight-secret-*.tmp")
	if err != nil {
		return fmt.Errorf("%w: 无法在目标目录创建临时文件", ErrFileInvalid)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	// os.CreateTemp 默认使用 0600；显式 Chmod 让意图可见，并覆盖 umask 差异。
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("%w: 无法设置临时密钥文件权限", ErrInsecurePermissions)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("%w: 写入临时密钥文件失败", ErrFileInvalid)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("%w: 同步临时密钥文件失败", ErrFileInvalid)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("%w: 关闭临时密钥文件失败", ErrFileInvalid)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("%w: 无法替换目标密钥文件", ErrFileInvalid)
	}
	return CheckProtectedFile(path)
}
