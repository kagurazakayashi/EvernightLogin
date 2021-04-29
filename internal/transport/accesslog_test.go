package transport

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// failingWriter 是总是失败的访问日志输出，用于验证写入失败告警。
type failingWriter struct {
	writes atomic.Int64
	err    error
}

// Write 实现 io.Writer，始终返回错误。
func (w *failingWriter) Write([]byte) (int, error) {
	w.writes.Add(1)
	return 0, w.err
}

// TestAccessLogFormatAndRedaction 验证 W3C Extended 字段、脱敏与注入防护。
func TestAccessLogFormatAndRedaction(t *testing.T) {
	logBuffer := &syncBuffer{}
	options := testOptions(logBuffer)
	options.extraRoutes = []route{jsonBodyRoute()}
	handler := buildHandler(t, options)

	request := httptest.NewRequest(http.MethodPost,
		"/test/body?token=QUERY_SECRET&code=123456", strings.NewReader(`{"name":"BODY_SECRET"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer AUTH_SECRET")
	request.Header.Set("Cookie", "session=COOKIE_SECRET")
	request.Header.Set("User-Agent", "agent\r\nINJECTED")
	request.Header.Set("Referer", "https://example.test/page?code=REFERER_SECRET")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("请求状态 = %d（%s）", recorder.Code, recorder.Body.String())
	}

	output := logBuffer.String()
	if !strings.HasPrefix(output, accessLogHeaderVersion+"\n#Fields: "+accessLogFields+"\n") {
		t.Fatalf("访问日志缺少 W3C 头: %q", output)
	}
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 3 {
		t.Fatalf("日志行数 = %d，期望 头部 2 行 + 记录 1 行（注入应当被转义）: %q", len(lines), output)
	}
	fields := strings.Fields(lines[2])
	wantFields := len(strings.Fields(accessLogFields))
	if len(fields) != wantFields {
		t.Fatalf("记录字段数 = %d，期望 %d: %q", len(fields), wantFields, lines[2])
	}
	for _, secret := range []string{"QUERY_SECRET", "AUTH_SECRET", "COOKIE_SECRET", "BODY_SECRET", "REFERER_SECRET", "123456"} {
		if strings.Contains(output, secret) {
			t.Fatalf("访问日志泄露敏感值 %q: %q", secret, output)
		}
	}
	if strings.Contains(lines[2], "?") {
		t.Fatalf("访问日志不应记录查询串: %q", lines[2])
	}
	if !strings.Contains(lines[2], "agent%0D%0AINJECTED") {
		t.Fatalf("User-Agent 注入未按 W3C 转义: %q", lines[2])
	}
	if fields[0] != "2026-11-14" || fields[1] != "12:00:00" {
		t.Fatalf("日志日期/时间 = %q %q，期望使用注入时钟", fields[0], fields[1])
	}
	if fields[2] != "192.0.2.1" {
		t.Fatalf("c-ip = %q，期望去除端口", fields[2])
	}
	if fields[3] != http.MethodPost || fields[5] != "200" {
		t.Fatalf("方法/状态字段异常: %q", lines[2])
	}
	if fields[5] != "200" {
		t.Fatalf("日志状态与响应不一致: %q", lines[2])
	}
	if fields[len(fields)-2] != recorder.Header().Get("X-Request-ID") {
		t.Fatalf("日志 request id 与响应头不一致: %q vs %q", fields[len(fields)-2], recorder.Header().Get("X-Request-ID"))
	}
	if fields[len(fields)-1] != "-" {
		t.Fatalf("成功请求 x-error-code = %q，期望 -", fields[len(fields)-1])
	}
}

// TestAccessLogRecordsErrorCode 验证失败响应的稳定错误码写入访问日志。
func TestAccessLogRecordsErrorCode(t *testing.T) {
	logBuffer := &syncBuffer{}
	handler := buildHandler(t, testOptions(logBuffer))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/missing", nil))
	lines := strings.Split(strings.TrimSpace(logBuffer.String()), "\n")
	fields := strings.Fields(lines[len(lines)-1])
	if fields[len(fields)-1] != "REQ_INVALID" || fields[5] != "404" {
		t.Fatalf("错误访问日志字段异常: %q", lines[len(lines)-1])
	}
}

// TestAccessLogWriteFailureAlerts 验证写入失败会告警且不改变响应。
func TestAccessLogWriteFailureAlerts(t *testing.T) {
	writer := &failingWriter{err: errors.New("disk full")}
	var alerts atomic.Int64
	options := testOptions(writer)
	options.OnAccessLogError = func(err error) {
		if err == nil {
			t.Fatalf("告警错误为空")
		}
		alerts.Add(1)
	}
	handler := buildHandler(t, options)
	for index := 0; index < 2; index++ {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("访问日志失败不应改变响应状态，实际 %d", recorder.Code)
		}
		if recorder.Body.String() != healthBody {
			t.Fatalf("访问日志失败不应改变响应正文: %q", recorder.Body.String())
		}
	}
	if got := alerts.Load(); got != 2 {
		t.Fatalf("告警次数 = %d，期望 2", got)
	}
	if writer.writes.Load() != 2 {
		t.Fatalf("写入尝试次数 = %d，期望 2", writer.writes.Load())
	}
}

// TestAccessLogAlertPanicIsolated 验证宿主告警回调 panic 不会破坏响应。
func TestAccessLogAlertPanicIsolated(t *testing.T) {
	options := testOptions(&failingWriter{err: errors.New("broken pipe")})
	options.OnAccessLogError = func(error) { panic("alert callback panic") }
	handler := buildHandler(t, options)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if recorder.Code != http.StatusOK || recorder.Body.String() != healthBody {
		t.Fatalf("告警回调 panic 破坏了响应: %d %q", recorder.Code, recorder.Body.String())
	}
}

// TestAccessLogDisabledWithoutWriter 验证未注入输出时不产生访问日志。
func TestAccessLogDisabledWithoutWriter(t *testing.T) {
	handler := buildHandler(t, testOptions(nil))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("状态 = %d", recorder.Code)
	}
}

// TestW3CTokenEscaping 验证日志字段转义规则。
func TestW3CTokenEscaping(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"plain-ASCII_1.2", "plain-ASCII_1.2"},
		{"with space", "with%20space"},
		{"line\nbreak", "line%0Abreak"},
		{"carriage\rreturn", "carriage%0Dreturn"},
		{"quote\"and\\slash", "quote%22and%5Cslash"},
		{"中文", "%E4%B8%AD%E6%96%87"},
		{"", "-"},
	}
	for _, testCase := range cases {
		if got := w3cToken(testCase.input, maxAccessLogValueBytes); got != testCase.want {
			t.Errorf("w3cToken(%q) = %q，期望 %q", testCase.input, got, testCase.want)
		}
	}
	if got := w3cQuoted("", maxAccessLogValueBytes); got != "-" {
		t.Errorf("空引用值 = %q，期望 -", got)
	}
	if got := w3cQuoted("a b", maxAccessLogValueBytes); got != `"a%20b"` {
		t.Errorf("引用值 = %q", got)
	}
	long := w3cToken(strings.Repeat("a", maxAccessLogValueBytes+10), maxAccessLogValueBytes)
	if len(long) > maxAccessLogValueBytes+3 || !strings.HasSuffix(long, "...") {
		t.Errorf("超长字段未被截断: %d", len(long))
	}
}
