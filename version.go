package login

import buildversion "github.com/kagurazakayashi/EvernightLogin/version"

// ModulePath 是本模块的导入路径。宿主在 go.mod 中引用该路径；首次发布后
// 不应变更，否则会破坏已有 import 和接入示例。
const ModulePath = "github.com/kagurazakayashi/EvernightLogin"

// 以下变量可由构建流程通过 -ldflags 注入。变量名/路径保持既有构建脚本兼容；
// 公开 BuildInfo 类型由公共 version/ 提供，root 只保留兼容别名与当前值。
var (
	version   = "devel"
	commit    = "unknown"
	buildTime = "unknown"
)

// CurrentBuildInfo 返回当前运行二进制的版本信息。Version、Commit 和
// BuildTime 可通过 -ldflags "-X <模块路径>.<变量名>=..." 注入。
func CurrentBuildInfo() buildversion.BuildInfo {
	return buildversion.BuildInfo{
		Version:   version,
		Commit:    commit,
		BuildTime: buildTime,
		GoVersion: buildversion.CurrentGoVersion(),
	}
}

// valueOr 为空字符串提供稳定的占位文本，避免版本输出出现空洞。
func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
