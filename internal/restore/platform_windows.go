//go:build windows

package restore

// platformIsWindows 报告当前平台是否为 Windows：文件权限语义（0600/0700 不构成
// 访问控制）与数据库文件改名/打开语义不同，README 已声明该边界。
const platformIsWindows = true
