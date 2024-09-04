package uiadminadapter

// 步骤 252 页面适配层 root 来源与未实现/目录不可用原因的中文展示定向测试。

import (
	"strings"
	"testing"
)

// TestRootSourceAndNotImplementedReasonText 验证页面适配层把新增加的 root 语义
// 原因码转成可披露中文，不直出内部机器码。
func TestRootSourceAndNotImplementedReasonText(t *testing.T) {
	for reason, want := range map[string]string{
		"permission_not_implemented":         "尚未实现",
		"implementation_catalog_unavailable": "权限实现目录不可用",
		"permission_directory_too_large":     "权限目录过大",
	} {
		if got := deniedReasonText(reason); !strings.Contains(got, want) {
			t.Fatalf("deniedReasonText(%q) = %q，期望包含 %q", reason, got, want)
		}
	}
	for reason, want := range map[string]string{
		"permission_not_implemented":         "尚未实现",
		"implementation_catalog_unavailable": "目录不可用",
		"permission_disabled":                "已停用",
	} {
		if got := excludedReasonText(reason); !strings.Contains(got, want) {
			t.Fatalf("excludedReasonText(%q) = %q，期望包含 %q", reason, got, want)
		}
	}
}
