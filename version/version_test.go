package version_test

import (
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/version"
)

func TestBuildInfoString(t *testing.T) {
	empty := version.BuildInfo{}
	if empty.String() != "devel (commit unknown, built unknown, unknown)" {
		t.Fatalf("空 BuildInfo 文案异常: %q", empty.String())
	}
	filled := version.BuildInfo{Version: "1.2.3", Commit: "abc", BuildTime: "t", GoVersion: "go1.27"}
	if filled.String() != "1.2.3 (commit abc, built t, go1.27)" {
		t.Fatalf("BuildInfo 文案异常: %q", filled.String())
	}
}
