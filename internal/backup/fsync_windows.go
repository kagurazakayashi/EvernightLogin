//go:build windows

package backup

// syncDir 在 Windows 上不做目录 fsync：Go 对目录句柄的 Sync 语义与 Unix 不同，
// 原子改名（MoveFileEx）后的目录项持久化由文件系统日志保证。备份文件本身在发布
// 前已执行 File.Sync，因此本函数只作为跨平台占位，不声称提供 POSIX 目录同步。
func syncDir(string) error {
	return nil
}
