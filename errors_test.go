package login

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestAppErrorClassification(t *testing.T) {
	cases := []struct {
		code     ErrorCode
		category ErrorCategory
		http     int
		message  string
	}{
		{CodePermissionRequired, CategoryPermission, 403, "缺少当前操作所需权限"},
		{CodeRateLimited, CategoryRateLimit, 429, "请求过于频繁"},
		{CodeTaskCancelled, CategoryTaskResult, 0, "任务已取消"},
		{CodeConfigInvalid, CategoryConfiguration, 0, "配置未通过检查"},
		{CodeInternalError, CategoryInternal, 500, "服务发生未预期错误"},
	}
	for _, test := range cases {
		t.Run(string(test.code), func(t *testing.T) {
			appError := NewAppError(test.code, "")
			if appError.Code() != test.code {
				t.Errorf("Code() = %q", appError.Code())
			}
			if appError.Category() != test.category {
				t.Errorf("Category() = %q，期望 %q", appError.Category(), test.category)
			}
			if appError.HTTPStatus() != test.http {
				t.Errorf("HTTPStatus() = %d，期望 %d", appError.HTTPStatus(), test.http)
			}
			if appError.Message() != test.message {
				t.Errorf("Message() = %q，期望 %q", appError.Message(), test.message)
			}
		})
	}
}

func TestNewAppErrorUnknownCodeFallback(t *testing.T) {
	appError := NewAppError(ErrorCode("NOT_REGISTERED"), "")
	if appError.Code() != CodeInternalError {
		t.Fatalf("未注册错误码应回退 INTERNAL_ERROR，实际 %q", appError.Code())
	}
	if appError.Message() != "服务发生未预期错误" {
		t.Errorf("回退消息 = %q", appError.Message())
	}
	if appError.InternalReasonCode() != "unregistered_error_code" {
		t.Errorf("受限原因码 = %q", appError.InternalReasonCode())
	}
	if strings.Contains(appError.Error(), "NOT_REGISTERED") {
		t.Errorf("公开错误不应包含未注册码：%q", appError.Error())
	}
}

func TestAppErrorMessageSanitization(t *testing.T) {
	t.Run("控制字符与换行", func(t *testing.T) {
		appError := NewAppError(CodeReqInvalid, "第一行\n第二行\r\t第三行\x00")
		message := appError.Message()
		if strings.ContainsAny(message, "\r\n\t\x00") {
			t.Fatalf("公开消息仍含控制字符：%q", message)
		}
		if message != "第一行 第二行 第三行" {
			t.Errorf("公开消息 = %q", message)
		}
		if strings.ContainsAny(appError.Error(), "\r\n\t\x00") {
			t.Errorf("Error() 仍含控制字符：%q", appError.Error())
		}
	})

	t.Run("超长消息截断", func(t *testing.T) {
		long := strings.Repeat("长", MaxPublicMessageLength+50)
		appError := NewAppError(CodeReqInvalid, long)
		if runes := []rune(appError.Message()); len(runes) > MaxPublicMessageLength {
			t.Errorf("消息长度 = %d，超过上限 %d", len(runes), MaxPublicMessageLength)
		}
		if !strings.HasSuffix(appError.Message(), "...") {
			t.Errorf("超长消息应截断并加省略号：%q", appError.Message())
		}
	})

	t.Run("空消息使用默认说明", func(t *testing.T) {
		appError := NewAppError(CodeAuthFailed, "   \n\t ")
		if appError.Message() != "无法完成登录" {
			t.Errorf("空消息应回退默认说明，实际 %q", appError.Message())
		}
	})
}

func TestRequestIDGenerationAndValidation(t *testing.T) {
	generated := NewRequestID()
	if err := ValidateRequestID(generated); err != nil {
		t.Fatalf("生成请求编号不合法：%v", err)
	}
	if !strings.HasPrefix(generated, requestIDPrefix) {
		t.Errorf("请求编号缺少固定前缀：%q", generated)
	}
	if len(generated) != len(requestIDPrefix)+32 {
		t.Errorf("请求编号长度 = %d，期望 %d", len(generated), len(requestIDPrefix)+32)
	}

	seen := make(map[string]bool)
	for index := 0; index < 200; index++ {
		id := NewRequestID()
		if seen[id] {
			t.Fatalf("请求编号重复：%q", id)
		}
		seen[id] = true
	}

	valid := []string{
		"abc",
		"req_abc-123.X_Y",
		strings.Repeat("a", MaxCorrelationIDLength),
	}
	for _, id := range valid {
		if err := ValidateRequestID(id); err != nil {
			t.Errorf("有效请求编号 %q 被拒绝：%v", id, err)
		}
	}

	invalid := []string{
		"",
		strings.Repeat("a", MaxCorrelationIDLength+1),
		"req 123",
		"req\n123",
		"req\r123",
		"-abc",
		".abc",
		"汉字编号",
		"req\x00123",
	}
	for _, id := range invalid {
		if err := ValidateRequestID(id); err == nil {
			t.Errorf("非法请求编号 %q 未被拒绝", id)
		}
	}

	t.Run("WithRequestID 只接受合法编号", func(t *testing.T) {
		validError := NewAppError(CodeReqInvalid, "", WithRequestID("req_valid"))
		if validError.RequestID() != "req_valid" {
			t.Errorf("合法请求编号未保存：%q", validError.RequestID())
		}
		invalidError := NewAppError(CodeReqInvalid, "", WithRequestID("bad\nid"))
		if invalidError.RequestID() != "" {
			t.Errorf("非法请求编号不应保存：%q", invalidError.RequestID())
		}
		if strings.Contains(invalidError.Error(), "bad") {
			t.Errorf("Error() 泄露非法请求编号：%q", invalidError.Error())
		}
	})

	t.Run("任务编号使用同一限制", func(t *testing.T) {
		if err := ValidateTaskID("task_abc123"); err != nil {
			t.Errorf("有效任务编号被拒绝：%v", err)
		}
		if err := ValidateTaskID("bad task"); err == nil {
			t.Error("非法任务编号未被拒绝")
		}
		appError := NewAppError(CodeTaskTimeout, "", WithTaskID("task_abc123"))
		if appError.TaskID() != "task_abc123" {
			t.Errorf("任务编号未保存：%q", appError.TaskID())
		}
	})
}

func TestAppErrorCauseSeparation(t *testing.T) {
	cause := errors.New("cause-secret-value\nsecond line")
	appError := NewAppError(CodeInternalError, "",
		WithCause(cause), WithRequestID("req_correlation"))

	outputs := []string{
		appError.Error(),
		fmt.Sprintf("%v", appError),
		fmt.Sprintf("%+v", appError),
		fmt.Sprintf("%#v", appError),
		fmt.Sprintf("%q", appError),
	}
	jsonBytes, err := json.Marshal(appError)
	if err != nil {
		t.Fatalf("JSON 序列化失败：%v", err)
	}
	outputs = append(outputs, string(jsonBytes))

	for _, output := range outputs {
		if strings.Contains(output, "cause-secret-value") {
			t.Fatalf("公开输出泄露内部原因：%q", output)
		}
		if strings.Contains(output, "second line") {
			t.Fatalf("公开输出泄露内部原因：%q", output)
		}
		if strings.ContainsAny(output, "\r\n") {
			t.Fatalf("公开输出包含换行：%q", output)
		}
	}

	if !errors.Is(appError, cause) {
		t.Error("errors.Is 应能沿内部原因链匹配")
	}
	if appError.Unwrap() != cause {
		t.Errorf("Unwrap() = %v", appError.Unwrap())
	}
	if !strings.Contains(appError.Error(), "INTERNAL_ERROR") {
		t.Errorf("Error() 缺少错误码：%q", appError.Error())
	}
	if !strings.Contains(appError.Error(), "request_id=req_correlation") {
		t.Errorf("Error() 缺少请求编号：%q", appError.Error())
	}
}

func TestAppErrorWrappingChain(t *testing.T) {
	base := errors.New("底层连接失败")
	middle := fmt.Errorf("仓储层：%w", base)
	appError := NewAppError(CodeDBUnavailable, "", WithCause(middle))

	if !errors.Is(appError, base) {
		t.Error("错误链未保留底层原因")
	}
	found, ok := AsAppError(appError)
	if !ok || found != appError {
		t.Errorf("AsAppError() = %v, %v", found, ok)
	}
	if !IsErrorCode(appError, CodeDBUnavailable) {
		t.Error("IsErrorCode 未识别错误码")
	}
	if code, ok := ErrorCodeOf(appError); !ok || code != CodeDBUnavailable {
		t.Errorf("ErrorCodeOf() = %q, %v", code, ok)
	}
	if _, ok := ErrorCodeOf(errors.New("普通错误")); ok {
		t.Error("普通错误不应有错误码")
	}
	if IsErrorCode(errors.New("普通错误"), CodeInternalError) {
		t.Error("普通错误不应匹配任何错误码")
	}
}

func TestFromError(t *testing.T) {
	if FromError(nil) != nil {
		t.Error("FromError(nil) 应为 nil")
	}

	cause := errors.New("database gone")
	appError := FromError(cause)
	if appError.Code() != CodeInternalError {
		t.Errorf("未知异常回退错误码 = %q", appError.Code())
	}
	if appError.RequestID() == "" {
		t.Error("未知异常兜底应生成请求编号")
	}
	if err := ValidateRequestID(appError.RequestID()); err != nil {
		t.Errorf("兜底请求编号不合法：%v", err)
	}
	if !errors.Is(appError, cause) {
		t.Error("未知异常兜底应保留原因链")
	}
	if strings.Contains(appError.Error(), "database gone") {
		t.Errorf("未知异常兜底不应公开原因文本：%q", appError.Error())
	}

	existing := NewAppError(CodeTokenExpired, "")
	if FromError(existing) != existing {
		t.Error("FromError 应返回已有 AppError 而非重复包装")
	}
}

func TestAppErrorJSONFields(t *testing.T) {
	appError := NewAppError(CodePermissionRequired, "",
		WithRequestID("req_json"), WithTaskID("task_json"),
		WithInternalReasonCode("permission.missing"))
	jsonBytes, err := json.Marshal(appError)
	if err != nil {
		t.Fatalf("JSON 序列化失败：%v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(jsonBytes, &payload); err != nil {
		t.Fatalf("JSON 反序列化失败：%v", err)
	}
	if payload["code"] != "PERMISSION_REQUIRED" ||
		payload["message"] != "缺少当前操作所需权限" ||
		payload["request_id"] != "req_json" ||
		payload["task_id"] != "task_json" {
		t.Errorf("公开 JSON 字段不正确：%v", payload)
	}
	for _, forbidden := range []string{"cause", "reason_code", "category", "stack"} {
		if _, exists := payload[forbidden]; exists {
			t.Errorf("公开 JSON 不应包含 %q：%v", forbidden, payload)
		}
	}
	if strings.Contains(string(jsonBytes), "permission.missing") {
		t.Errorf("公开 JSON 泄露内部原因码：%s", jsonBytes)
	}

	empty := NewAppError(CodeReqInvalid, "")
	emptyJSON, err := json.Marshal(empty)
	if err != nil {
		t.Fatalf("JSON 序列化失败：%v", err)
	}
	if strings.Contains(string(emptyJSON), "request_id") || strings.Contains(string(emptyJSON), "task_id") {
		t.Errorf("空编号不应序列化：%s", emptyJSON)
	}
}

func TestAppErrorSlogRedaction(t *testing.T) {
	var buffer bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buffer, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cause := errors.New("cause-secret-value")
	appError := NewAppError(CodeInternalError, "",
		WithCause(cause), WithRequestID("req_log"),
		WithInternalReasonCode("internal.reason.secret"))
	logger.Error("请求失败", "error", appError)

	output := buffer.String()
	if strings.Contains(output, "cause-secret-value") {
		t.Fatalf("结构化日志泄露内部原因：%s", output)
	}
	if strings.Contains(output, "internal.reason.secret") {
		t.Fatalf("结构化日志泄露内部原因码：%s", output)
	}
	if !strings.Contains(output, "INTERNAL_ERROR") || !strings.Contains(output, "req_log") {
		t.Errorf("结构化日志缺少错误码或请求编号：%s", output)
	}

	buffer.Reset()
	logger.Info("秘密字段", "master_key", NewSecretString("super-secret-value"))
	output = buffer.String()
	if strings.Contains(output, "super-secret-value") {
		t.Fatalf("结构化日志泄露 Secret：%s", output)
	}
	if !strings.Contains(output, "[REDACTED]") {
		t.Errorf("结构化日志未显示脱敏标记：%s", output)
	}
}

func TestWithInternalReasonCodeRestricted(t *testing.T) {
	appError := NewAppError(CodeAccessDenied, "",
		WithInternalReasonCode("policy.deny.specific"))
	if appError.InternalReasonCode() != "policy.deny.specific" {
		t.Errorf("内部原因码 = %q", appError.InternalReasonCode())
	}
	if strings.Contains(appError.Error(), "policy.deny.specific") {
		t.Error("Error() 不应包含内部原因码")
	}

	invalid := NewAppError(CodeAccessDenied, "", WithInternalReasonCode("bad\ncode"))
	if invalid.InternalReasonCode() != "" {
		t.Errorf("非法内部原因码不应保存：%q", invalid.InternalReasonCode())
	}
}

func TestNewlineInjectionDoesNotBreakLogLines(t *testing.T) {
	var buffer bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buffer, &slog.HandlerOptions{Level: slog.LevelDebug}))
	logger.Info("事件", "detail", "line1\nline2\rline3")
	if lines := strings.Count(buffer.String(), "\n"); lines != 1 {
		t.Fatalf("日志行数 = %d，期望 1：%q", lines, buffer.String())
	}

	appError := NewAppError(CodeReqInvalid, "line1\nline2")
	if strings.ContainsAny(appError.Error(), "\r\n") {
		t.Errorf("错误文本包含换行：%q", appError.Error())
	}
}
