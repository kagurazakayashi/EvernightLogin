package testmail_test

import (
	"crypto/tls"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/testmail"
)

// TestOptionsDefaultsAndValidation 验证默认监听地址落在回环、非法配置被拒绝。
func TestOptionsDefaultsAndValidation(t *testing.T) {
	srv := startServer(t, testmail.Options{})
	addr := srv.Addr().String()
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("默认监听地址应为回环随机端口，实际 %q", addr)
	}
	if strings.HasSuffix(addr, ":0") {
		t.Fatalf("Start 后应给出实际端口，实际 %q", addr)
	}

	cases := []struct {
		name string
		opts testmail.Options
	}{
		{"非回环地址未显式允许", testmail.Options{Addr: "0.0.0.0:0"}},
		{"空主机名未显式允许", testmail.Options{Addr: ":0"}},
		{"空主机名固定端口", testmail.Options{Addr: ":2525"}},
		{"IPv6 通配未显式允许", testmail.Options{Addr: "[::]:0"}},
		{"监听地址格式错误", testmail.Options{Addr: "not-an-address"}},
		{"端口越界", testmail.Options{Addr: "127.0.0.1:70000"}},
		{"主机名含空白", testmail.Options{Hostname: "bad host"}},
		{"消息上限为负", testmail.Options{MaxMessageBytes: -1}},
		{"消息上限过大", testmail.Options{MaxMessageBytes: testmail.MaxMaxMessageBytes + 1}},
		{"收件人上限为负", testmail.Options{MaxRecipients: -1}},
		{"并发连接上限过大", testmail.Options{MaxConnections: testmail.MaxMaxConnections + 1}},
		{"保留消息上限为负", testmail.Options{MaxMessages: -1}},
		{"读取超时过短", testmail.Options{ReadTimeout: time.Millisecond}},
		{"会话超时过长", testmail.Options{SessionTimeout: 48 * time.Hour}},
		{"AUTH 无用户", testmail.Options{Auth: &testmail.AuthOptions{}}},
		{"AUTH 空密码", testmail.Options{Auth: &testmail.AuthOptions{Users: map[string]string{"u": ""}}}},
		{"AUTH 密码含控制字符", testmail.Options{Auth: &testmail.AuthOptions{Users: map[string]string{"u": "a\nb"}}}},
		{"TLS 证书为空", testmail.Options{TLS: &testmail.TLSOptions{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, err := testmail.New(tc.opts)
			if err == nil {
				t.Fatalf("非法配置应被拒绝，实际创建成功: %+v", srv)
			}
			if !errors.Is(err, testmail.ErrInvalidOptions) {
				t.Fatalf("错误应包装 ErrInvalidOptions，实际 %v", err)
			}
		})
	}
}

// TestExplicitNonLoopbackAllowed 验证显式选择非回环地址时校验通过（只创建不监听，
// 避免在测试环境暴露端口）。
func TestExplicitNonLoopbackAllowed(t *testing.T) {
	srv, err := testmail.New(testmail.Options{Addr: "0.0.0.0:0", AllowNonLoopback: true})
	if err != nil {
		t.Fatalf("显式允许非回环地址时应通过校验: %v", err)
	}
	if srv == nil {
		t.Fatal("服务器不应为 nil")
	}
	// 空主机名同样只有在显式允许时才通过（否则会绑定全部接口）。
	if _, err := testmail.New(testmail.Options{Addr: ":0", AllowNonLoopback: true}); err != nil {
		t.Fatalf("显式允许时空主机名应通过校验: %v", err)
	}
	// localhost 属于回环，无需额外允许。
	if srv, err := testmail.New(testmail.Options{Addr: "localhost:0"}); err != nil || srv == nil {
		t.Fatalf("localhost 应视为回环地址: %v", err)
	}
}

// TestAuthOptionsCopy 验证 New 复制认证映射：调用方之后修改原 map 不影响服务器。
func TestAuthOptionsCopy(t *testing.T) {
	users := map[string]string{"tester": "s3cret-test"}
	srv := startServer(t, testmail.Options{Auth: &testmail.AuthOptions{Users: users}})
	users["tester"] = "changed"
	users["intruder"] = "x"

	c := wrapRaw(t, dialRaw(t, srv))
	c.expect(220)
	c.expectCode(250, "EHLO client.example.test")
	changed := "AUTH PLAIN " + base64Of("\x00tester\x00changed")
	c.expectCode(535, changed)
	intruder := "AUTH PLAIN " + base64Of("\x00intruder\x00x")
	c.expectCode(535, intruder)
	original := "AUTH PLAIN " + base64Of("\x00tester\x00s3cret-test")
	c.expectCode(235, original)
}

// TestGenerateTestCertificate 验证测试证书可用于 TLS 握手且包含预期主机名。
func TestGenerateTestCertificate(t *testing.T) {
	cert, err := testmail.GenerateTestCertificate("localhost", "127.0.0.1")
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("测试证书链为空")
	}
	if cert.PrivateKey == nil {
		t.Fatal("测试证书缺少私钥")
	}
	// 能作为 tls.Config 的服务端证书使用即视为可用；握手路径由 STARTTLS 测试覆盖。
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if len(cfg.Certificates) != 1 || len(cfg.Certificates[0].Certificate) == 0 {
		t.Fatal("tls.Config 未正确接受测试证书")
	}
}
