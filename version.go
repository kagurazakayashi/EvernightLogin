package login

import "runtime"

// ModulePath 是本模块的导入路径。宿主在 go.mod 中引用该路径；首次发布后
// 不应变更，否则会破坏已有 import 和接入示例。
const ModulePath = "github.com/kagurazakayashi/EvernightLogin"

// 以下变量可由构建流程通过 -ldflags 注入。源码直接构建时保留明确的
// 占位值，不把本地构建伪装成正式发布版本。
var (
	version   = "devel"
	commit    = "unknown"
	buildTime = "unknown"
)

// BuildInfo 描述当前二进制的版本信息，不包含秘密或用户数据。
type BuildInfo struct {
	// Version 是语义化版本；源码直接构建时为 "devel"。
	Version string
	// Commit 是构建所用提交的标识；未知时为 "unknown"。
	Commit string
	// BuildTime 是构建时间；未知时为 "unknown"。
	BuildTime string
	// GoVersion 是编译该二进制所用的 Go 工具链版本。
	GoVersion string
}

// String 返回单行、可安全打印的版本信息。
func (b BuildInfo) String() string {
	return valueOr(b.Version, "devel") +
		" (commit " + valueOr(b.Commit, "unknown") +
		", built " + valueOr(b.BuildTime, "unknown") +
		", " + valueOr(b.GoVersion, "unknown") + ")"
}

// CurrentBuildInfo 返回当前运行二进制的版本信息。Version、Commit 和
// BuildTime 可通过 -ldflags "-X <模块路径>.<变量名>=..." 注入。
func CurrentBuildInfo() BuildInfo {
	return BuildInfo{
		Version:   version,
		Commit:    commit,
		BuildTime: buildTime,
		GoVersion: runtime.Version(),
	}
}

// valueOr 为空字符串提供稳定的占位文本，避免版本输出出现空洞。
func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
