package login

import (
	"strings"
	"testing"
)

func TestBuildInfoString(t *testing.T) {
	tests := []struct {
		name  string
		info  BuildInfo
		wants []string
	}{
		{
			name: "完整信息",
			info: BuildInfo{
				Version:   "1.2.3",
				Commit:    "abc1234",
				BuildTime: "2026-11-14T12:00:00Z",
				GoVersion: "go1.26.0",
			},
			wants: []string{"1.2.3", "abc1234", "2026-11-14T12:00:00Z", "go1.26.0"},
		},
		{
			name:  "空值使用明确占位",
			info:  BuildInfo{},
			wants: []string{"devel", "unknown"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := test.info.String()
			for _, want := range test.wants {
				if !strings.Contains(got, want) {
					t.Errorf("BuildInfo.String() = %q，缺少 %q", got, want)
				}
			}
		})
	}
}

func TestCurrentBuildInfo(t *testing.T) {
	info := CurrentBuildInfo()
	if info.Version == "" {
		t.Error("Version 不应为空")
	}
	if info.GoVersion == "" {
		t.Error("GoVersion 不应为空")
	}
	if ModulePath != "github.com/kagurazakayashi/EvernightLogin" {
		t.Errorf("ModulePath = %q，与 go.mod 不一致", ModulePath)
	}
}
