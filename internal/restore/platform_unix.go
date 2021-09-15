//go:build !windows

package restore

// platformIsWindows 报告当前平台是否为 Windows，用于平台化权限差异。
const platformIsWindows = false
