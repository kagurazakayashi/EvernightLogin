// Package version 定义公开构建信息类型；实际版本变量仍由根包通过 ldflags
// 注入，根包 CurrentBuildInfo 返回本包类型，internal/CLI 通过注入接收该值，
// 不反向 import 根包。
package version

import "runtime"

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

// CurrentGoVersion 返回编译工具链版本；供需要构造 BuildInfo 的进程入口使用。
func CurrentGoVersion() string { return runtime.Version() }

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
