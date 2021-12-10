package managecli

// 本文件覆盖命令框架本身：帮助、未知命令、JSON 外壳、稳定退出码与参数解析。

import (
	"bytes"
	"strings"
	"testing"
)

// TestExitCodesStable 锁定稳定退出码数值（脚本依赖）。
func TestExitCodesStable(t *testing.T) {
	values := map[string]int{
		"ok": ExitOK, "error": ExitError, "usage": ExitUsage,
		"cancelled": ExitCancelled, "unauthenticated": ExitUnauthenticated,
		"forbidden": ExitForbidden, "conflict": ExitConflict, "timeout": ExitTimeout,
		"task_failed": ExitTaskFailed, "interrupted": ExitInterrupted,
	}
	expected := map[string]int{"ok": 0, "error": 1, "usage": 2, "cancelled": 3,
		"unauthenticated": 4, "forbidden": 5, "conflict": 6, "timeout": 7,
		"task_failed": 8, "interrupted": 130}
	for name, value := range values {
		if value != expected[name] {
			t.Fatalf("退出码 %s = %d，期望 %d", name, value, expected[name])
		}
	}
}

// TestHelpAndUnknownCommand 验证帮助成功、未知命令为用法错误。
func TestHelpAndUnknownCommand(t *testing.T) {
	stdout, _, exit := runCLI(t, "help")
	if exit != ExitOK {
		t.Fatalf("help 退出码 = %d", exit)
	}
	for _, keyword := range []string{"config", "diag", "migrate", "task", "session",
		"user", "退出码"} {
		if !strings.Contains(stdout, keyword) {
			t.Fatalf("帮助缺少 %q", keyword)
		}
	}
	_, stderr, exit := runCLI(t, "not-a-command")
	if exit != ExitUsage {
		t.Fatalf("未知命令退出码 = %d，期望 %d", exit, ExitUsage)
	}
	if !strings.Contains(stderr, "未知的管理命令") {
		t.Fatalf("未知命令错误不是中文提示: %s", stderr)
	}
	// 组级帮助也成功。
	if _, _, exit := runCLI(t, "config", "--help"); exit != ExitOK {
		t.Fatalf("config --help 退出码 = %d", exit)
	}
}

// TestJSONFailureEnvelope 验证失败时输出可解析的 JSON 外壳且 stderr 有中文错误。
func TestJSONFailureEnvelope(t *testing.T) {
	stdout, stderr, exit := runCLI(t, "config", "get", "no.such.field", "--json")
	if exit != ExitUsage {
		t.Fatalf("退出码 = %d", exit)
	}
	envelope := decodeEnvelope(t, stdout)
	if envelope["ok"] != false {
		t.Fatalf("失败外壳 = %v", envelope)
	}
	if envelope["command"] != "config get" {
		t.Fatalf("命令标识 = %v", envelope["command"])
	}
	if !strings.Contains(stderr, "错误：[CONFIG_FIELD_UNKNOWN]") {
		t.Fatalf("stderr = %s", stderr)
	}
}

// TestParseFlagsAnywhereAndErrors 验证参数可位于位置参数前后与错误检测。
func TestParseFlagsAnywhereAndErrors(t *testing.T) {
	values, positional, err := parseFlags([]string{"field", "--config", "a.yaml",
		"--json", "value", "--limit=5"}, []flagDef{
		{name: "config", value: true}, {name: "json"}, {name: "limit", value: true}})
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if values["config"] != "a.yaml" || values["json"] != "1" || values["limit"] != "5" {
		t.Fatalf("解析结果 = %v", values)
	}
	if len(positional) != 2 || positional[0] != "field" || positional[1] != "value" {
		t.Fatalf("位置参数 = %v", positional)
	}
	for _, args := range [][]string{
		{"--unknown"},
		{"--config"},
		{"--json=1"},
		{"--config", "a", "--config", "b"},
	} {
		if _, _, err := parseFlags(args, []flagDef{{name: "config", value: true},
			{name: "json"}}); err == nil {
			t.Fatalf("参数 %v 应被拒绝", args)
		}
	}
	if _, _, err := parseFlags([]string{"--help"}, nil); err != errHelp {
		t.Fatalf("--help 应返回 errHelp: %v", err)
	}
}

// TestNilStreamsUsage 验证输入/输出缺失时返回用法错误。
func TestNilStreamsUsage(t *testing.T) {
	if RunWithOptions([]string{"help"}, nil, &bytes.Buffer{}, &bytes.Buffer{},
		Options{}) != ExitUsage {
		t.Fatal("缺少 stdin 应返回用法错误")
	}
}
