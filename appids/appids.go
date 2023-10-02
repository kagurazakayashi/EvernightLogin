// Package appids 定义稳定应用 ID 的公共格式与校验规则。
//
// 应用 ID 一经创建不再改变，格式为 "app_" 加 128 位随机数的十六进制表示；业务
// 应用不得用名称作为永久外键。本包是纯格式校验（不查库、不依赖 internal），供
// 公开的 config 包与内部应用/权限服务共用同一口径。
package appids

import (
	"encoding/hex"
	"strings"
)

const (
	// Prefix 是应用 ID 的固定前缀。
	Prefix = "app_"
	// RandomBytes 是应用 ID 随机部分的字节数（128 位）。
	RandomBytes = 16
)

// ValidApplicationID 报告应用 ID 是否符合本包生成的固定格式。查询前用它拒绝任意
// 字符串，避免把畸形输入带进 SQL 或错误信息。
func ValidApplicationID(id string) bool {
	if len(id) != len(Prefix)+2*RandomBytes || !strings.HasPrefix(id, Prefix) {
		return false
	}
	_, err := hex.DecodeString(id[len(Prefix):])
	return err == nil
}
