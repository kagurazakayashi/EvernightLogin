package cli

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin"
)

func testBuildInfo() login.BuildInfo {
	return login.BuildInfo{
		Version:   "1.2.3-test",
		Commit:    "abc1234",
		BuildTime: "2026-11-14T12:00:00Z",
		GoVersion: "go1.26.0",
	}
}

func TestExecuteExitCodes(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{
			name:       "版本成功",
			args:       []string{"--version"},
			wantCode:   0,
			wantStdout: "login-server 1.2.3-test",
		},
		{
			name:       "帮助成功",
			args:       []string{"--help"},
			wantCode:   0,
			wantStdout: "配置加载器已提供但尚未接入服务启动",
		},
		{
			name:       "无参数明确失败",
			args:       nil,
			wantCode:   1,
			wantStderr: "尚未实现",
		},
		{
			name:       "未知参数失败",
			args:       []string{"--definitely-unknown"},
			wantCode:   1,
			wantStderr: "unknown flag",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Execute(test.args, &stdout, &stderr, testBuildInfo())
			if code != test.wantCode {
				t.Fatalf("退出码 = %d，期望 %d；stdout=%q stderr=%q",
					code, test.wantCode, stdout.String(), stderr.String())
			}
			if test.wantStdout != "" && !strings.Contains(stdout.String(), test.wantStdout) {
				t.Errorf("stdout = %q，缺少 %q", stdout.String(), test.wantStdout)
			}
			if test.wantStderr != "" && !strings.Contains(stderr.String(), test.wantStderr) {
				t.Errorf("stderr = %q，缺少 %q", stderr.String(), test.wantStderr)
			}
			if test.wantCode == 0 && stderr.Len() != 0 {
				t.Errorf("成功命令不应写 stderr，实际为 %q", stderr.String())
			}
		})
	}
}

func TestNewReturnsNotImplemented(t *testing.T) {
	cmd := New(testBuildInfo())
	cmd.SetArgs(nil)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	err := cmd.Execute()
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v，期望包装 ErrNotImplemented", err)
	}
}
