package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestNewLevelFiltering(t *testing.T) {
	cases := []struct {
		level     string
		wantDebug bool
		wantInfo  bool
		wantWarn  bool
		wantError bool
	}{
		{"debug", true, true, true, true},
		{"info", false, true, true, true},
		{"warn", false, false, true, true},
		{"error", false, false, false, true},
	}
	for _, test := range cases {
		t.Run(test.level, func(t *testing.T) {
			var buffer bytes.Buffer
			logger, err := New(test.level, "text", &buffer)
			if err != nil {
				t.Fatalf("New() 失败：%v", err)
			}
			logger.Debug("debug-message")
			logger.Info("info-message")
			logger.Warn("warn-message")
			logger.Error("error-message")
			output := buffer.String()
			check := func(message string, expected bool) {
				if got := strings.Contains(output, message); got != expected {
					t.Errorf("级别 %s：包含 %q = %v，期望 %v；输出：%s",
						test.level, message, got, expected, output)
				}
			}
			check("debug-message", test.wantDebug)
			check("info-message", test.wantInfo)
			check("warn-message", test.wantWarn)
			check("error-message", test.wantError)
		})
	}
}

func TestNewJSONFormat(t *testing.T) {
	var buffer bytes.Buffer
	logger, err := New("info", "json", &buffer)
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	logger.Info("structured", "component", "config", "count", 2)

	lines := strings.Split(strings.TrimSpace(buffer.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("JSON 日志行数 = %d：%s", len(lines), buffer.String())
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &payload); err != nil {
		t.Fatalf("输出不是合法 JSON：%v；%s", err, lines[0])
	}
	if payload["msg"] != "structured" || payload["component"] != "config" {
		t.Errorf("JSON 字段不正确：%v", payload)
	}
	if payload["level"] != "INFO" {
		t.Errorf("level = %v", payload["level"])
	}
}

func TestNewTextFormat(t *testing.T) {
	var buffer bytes.Buffer
	logger, err := New("info", "text", &buffer)
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	logger.Info("text-message", "key", "value")
	output := buffer.String()
	if !strings.Contains(output, "msg=text-message") || !strings.Contains(output, "key=value") {
		t.Errorf("文本日志格式不正确：%s", output)
	}
}

func TestNewInvalidConfiguration(t *testing.T) {
	if _, err := New("verbose", "text", &bytes.Buffer{}); err == nil {
		t.Error("非法日志级别应返回错误")
	}
	if _, err := New("info", "xml", &bytes.Buffer{}); err == nil {
		t.Error("非法日志格式应返回错误")
	}
}

func TestNewNilOutputDiscards(t *testing.T) {
	logger, err := New("debug", "text", nil)
	if err != nil {
		t.Fatalf("New(nil) 失败：%v", err)
	}
	if logger == nil {
		t.Fatal("New(nil) 应返回可用日志器")
	}
	logger.Debug("不会输出")
}

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug": slog.LevelDebug,
		"info":  slog.LevelInfo,
		"warn":  slog.LevelWarn,
		"error": slog.LevelError,
	}
	for level, want := range cases {
		got, err := ParseLevel(level)
		if err != nil {
			t.Errorf("ParseLevel(%q) 失败：%v", level, err)
		}
		if got != want {
			t.Errorf("ParseLevel(%q) = %v，期望 %v", level, got, want)
		}
	}
	if _, err := ParseLevel("trace"); err == nil {
		t.Error("未知级别应返回错误")
	}
}
