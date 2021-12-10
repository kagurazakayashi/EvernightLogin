package managecli

// 本文件覆盖在线命令的传输层失败映射：服务不可达、超时、TLS 证书严格校验与
// --ca-file 追加可信 CA、非回环明文 http 拒绝、CA 文件非法。全部使用真实
// httptest 服务（TLS 与超时场景用真实 TLS 监听/延迟处理器）。

import (
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// TestOnlineTransportUnreachableAndTimeout 覆盖服务不可达与请求超时的稳定映射。
func TestOnlineTransportUnreachableAndTimeout(t *testing.T) {
	fixture := newOnlineFixture(t)

	// 找一个已关闭的本地端口：连接失败 → NETWORK_UNREACHABLE，退出码 1。
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听临时端口: %v", err)
	}
	closedURL := "http://" + listener.Addr().String()
	_ = listener.Close()
	stdout, stderr, exit := runCLI(t, "audit", "events", "list", "--json",
		"--server", closedURL, "--session-file", fixture.sessionFile)
	requireOnlineFailure(t, stdout, exit, ExitError, "NETWORK_UNREACHABLE")
	if strings.Contains(stdout+stderr, fixture.strongSecret) {
		t.Fatalf("传输失败输出泄露了会话秘密")
	}

	// 延迟响应超过 --timeout：NETWORK_TIMEOUT，退出码 7（操作结果未知）。
	delayed := newOnlineFixture(t)
	delayed.serveHandler(http.HandlerFunc(func(writer http.ResponseWriter,
		_ *http.Request) {
		time.Sleep(1500 * time.Millisecond)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"ok":true,"request_id":"req_delayed","data":{"events":[]}}`))
	}))
	stdout, stderr, exit = delayed.runCLIWithCommon(delayed.sessionFile,
		[]string{"--timeout", "1s"}, "audit", "events", "list", "--json")
	requireOnlineFailure(t, stdout, exit, ExitTimeout, "NETWORK_TIMEOUT")
	if !strings.Contains(stdout+stderr, "未确认服务端是否已执行") {
		t.Fatalf("超时映射未说明操作结果未知: %s%s", stdout, stderr)
	}
}

// TestOnlineTLSCertificateStrictAndCAFile 覆盖默认严格证书校验与 --ca-file。
func TestOnlineTLSCertificateStrictAndCAFile(t *testing.T) {
	fixture := newOnlineFixture(t)
	tasks := newOnlineTaskReader()
	tasks.add(task.Job{ID: "job_tls", Kind: "backup.create", State: task.StateQueued,
		Initiator: audit.Actor{Type: audit.ActorUser, ID: fixture.userID},
		CreatedAt: onlineTestNow})
	fixture.serveTLS(func(options *adminapi.Options) {
		options.Tasks = tasks
		options.TaskAuthorizer = &onlineTaskAuthorizer{}
	})

	// 默认严格校验：自签测试证书不被系统信任 → TLS_VERIFY_FAILED，且不跳过校验。
	stdout, stderr, exit := fixture.runCLIWithCommon(fixture.sessionFile, nil,
		"tasks", "get", "job_tls", "--json")
	requireOnlineFailure(t, stdout, exit, ExitError, "TLS_VERIFY_FAILED")
	if !strings.Contains(stdout+stderr, "不会跳过证书校验") {
		t.Fatalf("TLS 失败未说明不会跳过校验: %s%s", stdout, stderr)
	}

	// --ca-file 追加可信 CA 后同一请求成功。
	certificate := fixture.server.Certificate()
	caPath := filepath.Join(t.TempDir(), "test-ca.pem")
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE",
		Bytes: certificate.Raw})
	if err := os.WriteFile(caPath, pemData, 0o600); err != nil {
		t.Fatalf("写入测试 CA: %v", err)
	}
	data := requireOnlineSuccess(t, func() string {
		stdout, stderr, exit := fixture.runCLIWithCommon(fixture.sessionFile,
			[]string{"--ca-file", caPath}, "tasks", "get", "job_tls", "--json")
		if exit != ExitOK {
			t.Fatalf("--ca-file 后请求失败: exit=%d stdout=%s stderr=%s",
				exit, stdout, stderr)
		}
		return stdout
	}())
	if job, _ := data["task"].(map[string]any); job["id"] != "job_tls" {
		t.Fatalf("TLS 请求返回结果不符: %v", data)
	}

	// CA 文件不合法：稳定错误码 CA_FILE_INVALID。
	stdout, _, exit = fixture.runCLIWithCommon(fixture.sessionFile,
		[]string{"--ca-file", filepath.Join(t.TempDir(), "missing-ca.pem")},
		"tasks", "get", "job_tls", "--json")
	requireOnlineFailure(t, stdout, exit, ExitError, "CA_FILE_INVALID")
}

// TestOnlineServerURLValidation 覆盖服务地址安全校验：非回环明文 http 被拒绝、
// 非法 scheme 与用户信息被拒绝。这些错误在发请求前返回用法错误。
func TestOnlineServerURLValidation(t *testing.T) {
	fixture := newOnlineFixture(t)
	cases := []string{
		"http://192.0.2.1:8080",
		"ftp://127.0.0.1:8080",
		"http://user:pass@127.0.0.1:8080",
		"://bad-url",
	}
	for _, server := range cases {
		stdout, stderr, exit := runCLI(t, "tasks", "get", "job_x", "--json",
			"--server", server, "--session-file", fixture.sessionFile)
		if exit != ExitUsage {
			t.Fatalf("服务地址 %q 退出码 = %d，期望 %d（stderr=%s）",
				server, exit, ExitUsage, stderr)
		}
		envelope := decodeEnvelope(t, stdout)
		if code := envelopeErrorCode(t, envelope); code != "USAGE_INVALID" {
			t.Fatalf("服务地址 %q 错误码 = %s，期望 USAGE_INVALID", server, code)
		}
	}
}
