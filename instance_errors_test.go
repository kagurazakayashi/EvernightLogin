package login

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestInstanceConfigErrorIsAppError(t *testing.T) {
	config := Default()
	config.Logging.Level = LogLevel("verbose")
	_, err := New(Options{Config: &config})
	if err == nil {
		t.Fatal("非法配置应导致 New 失败")
	}
	if !IsErrorCode(err, CodeConfigInvalid) {
		t.Fatalf("错误未映射为 CONFIG_INVALID：%v", err)
	}
	appError, ok := AsAppError(err)
	if !ok {
		t.Fatalf("错误不是 AppError：%v", err)
	}
	if err := ValidateRequestID(appError.RequestID()); err != nil {
		t.Errorf("配置错误缺少合法 request_id：%v", err)
	}
	var configErrors ConfigErrors
	if !errors.As(err, &configErrors) {
		t.Error("CONFIG_INVALID 应保留 ConfigErrors 原因链")
	}
	if strings.Contains(appError.Error(), "verbose") {
		t.Errorf("公开错误不应回显配置值：%q", appError.Error())
	}
}

func TestInstanceLifecycleErrorsAreAppErrors(t *testing.T) {
	var logBuffer bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))
	componentCause := errors.New("模拟数据库启动失败 password=hunter2")
	component := &fakeComponent{name: "db", startErr: componentCause}
	instance, err := New(Options{
		Components: []BackgroundComponent{component},
		Logger:     logger,
	})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}

	startErr := instance.Start(context.Background())
	if startErr == nil {
		t.Fatal("组件启动失败应导致 Start 失败")
	}
	if !IsErrorCode(startErr, CodeInternalError) {
		t.Fatalf("未分类组件错误应回退 INTERNAL_ERROR：%v", startErr)
	}
	appError, ok := AsAppError(startErr)
	if !ok {
		t.Fatalf("生命周期错误不是 AppError：%T", startErr)
	}
	if err := ValidateRequestID(appError.RequestID()); err != nil {
		t.Errorf("生命周期错误缺少合法 request_id：%v", err)
	}
	if !errors.Is(startErr, componentCause) {
		t.Error("生命周期错误应保留组件原因链")
	}
	if strings.Contains(appError.Error(), "hunter2") {
		t.Errorf("公开错误泄露组件原因：%q", appError.Error())
	}
	logOutput := logBuffer.String()
	if strings.Contains(logOutput, "hunter2") {
		t.Fatalf("结构化日志泄露组件原因：%s", logOutput)
	}
	if !strings.Contains(logOutput, "INTERNAL_ERROR") {
		t.Errorf("结构化日志缺少错误码：%s", logOutput)
	}
	if !strings.Contains(logOutput, appError.RequestID()) {
		t.Errorf("结构化日志缺少 request_id：%s", logOutput)
	}
	if got := instance.State(); got != StateClosed {
		t.Errorf("启动失败后状态 = %q", got)
	}
}

func TestInstanceCloseErrorsAreAppErrors(t *testing.T) {
	var logBuffer bytes.Buffer
	config := debugConfig()
	componentCause := errors.New("模拟关闭失败 secret=abc123")
	component := &fakeComponent{name: "server", closeErr: componentCause}
	instance, err := New(Options{
		Components: []BackgroundComponent{component},
		LogOutput:  &logBuffer,
		Config:     &config,
	})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	if err := instance.Start(context.Background()); err != nil {
		t.Fatalf("Start() 失败：%v", err)
	}

	closeErr := instance.Close(context.Background())
	if closeErr == nil {
		t.Fatal("组件关闭失败应返回错误")
	}
	if !IsErrorCode(closeErr, CodeInternalError) {
		t.Errorf("关闭错误未回退 INTERNAL_ERROR：%v", closeErr)
	}
	appError, ok := AsAppError(closeErr)
	if !ok || ValidateRequestID(appError.RequestID()) != nil {
		t.Errorf("关闭错误缺少合法 request_id：%v", closeErr)
	}
	if !errors.Is(closeErr, componentCause) {
		t.Error("关闭错误应保留组件原因链")
	}
	if strings.Contains(appError.Error(), "abc123") {
		t.Errorf("公开关闭错误泄露原因：%q", appError.Error())
	}
	logOutput := logBuffer.String()
	if strings.Contains(logOutput, "abc123") {
		t.Fatalf("关闭日志泄露组件原因：%s", logOutput)
	}
	if !strings.Contains(logOutput, "INTERNAL_ERROR") || !strings.Contains(logOutput, appError.RequestID()) {
		t.Errorf("关闭日志缺少错误码或请求编号：%s", logOutput)
	}
	if got := instance.State(); got != StateClosed {
		t.Errorf("关闭后状态 = %q", got)
	}
}

func TestComponentAppErrorCodeIsPreserved(t *testing.T) {
	componentError := NewAppError(CodeDBUnavailable, "")
	component := &fakeComponent{name: "db", startErr: componentError}
	instance, err := New(Options{Components: []BackgroundComponent{component}})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	startErr := instance.Start(context.Background())
	if !IsErrorCode(startErr, CodeDBUnavailable) {
		t.Fatalf("组件返回的具体错误码应保留：%v", startErr)
	}
	appError, ok := AsAppError(startErr)
	if !ok {
		t.Fatalf("错误不是 AppError：%T", startErr)
	}
	if err := ValidateRequestID(appError.RequestID()); err != nil {
		t.Errorf("实例应补充合法 request_id：%v", err)
	}
}

func TestInstanceInjectedLogger(t *testing.T) {
	var buffer bytes.Buffer
	injected := slog.New(slog.NewTextHandler(&buffer, &slog.HandlerOptions{Level: slog.LevelDebug}))
	config := Default()
	config.Logging.Level = LogLevelError // 默认日志器不会输出 debug，注入日志器应优先
	component := &fakeComponent{name: "a"}
	instance, err := New(Options{
		Config:     &config,
		Components: []BackgroundComponent{component},
		Logger:     injected,
	})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	if instance.Logger() != injected {
		t.Error("Logger() 应返回宿主注入的日志器")
	}
	if err := instance.Start(context.Background()); err != nil {
		t.Fatalf("Start() 失败：%v", err)
	}
	if err := instance.Close(context.Background()); err != nil {
		t.Fatalf("Close() 失败：%v", err)
	}
	output := buffer.String()
	if !strings.Contains(output, "实例开始启动") {
		t.Errorf("宿主日志器未收到 debug 日志：%s", output)
	}
	if !strings.Contains(output, "实例启动完成") || !strings.Contains(output, "实例已关闭") {
		t.Errorf("宿主日志器缺少生命周期日志：%s", output)
	}
}

func TestInstanceDefaultLoggerFromConfig(t *testing.T) {
	config := debugConfig()
	config.Logging.Format = LogFormatJSON
	var buffer bytes.Buffer
	instance, err := New(Options{Config: &config, LogOutput: &buffer})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	if instance.Logger() == nil {
		t.Fatal("未注入日志器时应按配置创建默认日志器")
	}
	if err := instance.Start(context.Background()); err != nil {
		t.Fatalf("Start() 失败：%v", err)
	}
	if err := instance.Close(context.Background()); err != nil {
		t.Fatalf("Close() 失败：%v", err)
	}

	lines := strings.Split(strings.TrimSpace(buffer.String()), "\n")
	if len(lines) == 0 {
		t.Fatal("默认日志器没有输出")
	}
	foundCompletion := false
	for _, line := range lines {
		var payload map[string]any
		if err := json.Unmarshal([]byte(line), &payload); err != nil {
			t.Fatalf("默认 JSON 日志不合法：%v；%s", err, line)
		}
		if payload["msg"] == "实例启动完成" {
			foundCompletion = true
		}
	}
	if !foundCompletion {
		t.Errorf("默认日志器缺少启动完成日志：%s", buffer.String())
	}
}

func TestInstanceDefaultLoggerDiscardsWithoutOutput(t *testing.T) {
	instance, err := New(Options{})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	if instance.Logger() == nil {
		t.Fatal("默认日志器不应为 nil")
	}
	if err := instance.Start(context.Background()); err != nil {
		t.Fatalf("Start() 失败：%v", err)
	}
	if err := instance.Close(context.Background()); err != nil {
		t.Fatalf("Close() 失败：%v", err)
	}
}

// debugConfig 返回启用 debug 级别、text 格式的配置副本，便于测试默认日志器。
func debugConfig() Config {
	config := Default()
	config.Logging.Level = LogLevelDebug
	return config
}
