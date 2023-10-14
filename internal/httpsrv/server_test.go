package httpsrv

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/config"
	"github.com/kagurazakayashi/EvernightLogin/errs"
	"github.com/kagurazakayashi/EvernightLogin/httpapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/tlscert"
)

func testHandler() http.Handler {
	return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
}

// configInvalidMessage 断言 err 是 CONFIG_INVALID AppError 并返回公开消息。
func configInvalidMessage(t *testing.T, err error) string {
	t.Helper()
	appError, ok := errs.AsAppError(err)
	if !ok {
		t.Fatalf("期望 *errs.AppError，实际 %T: %v", err, err)
	}
	if appError.Code() != errs.CodeConfigInvalid {
		t.Fatalf("错误码 = %q，期望 CONFIG_INVALID", appError.Code())
	}
	return appError.Message()
}

func testServerConfig(t *testing.T, mutate func(*config.Config)) config.Config {
	t.Helper()
	cfg := config.Default()
	if mutate != nil {
		mutate(&cfg)
	}
	return cfg
}

// TestNewValidationMessages 验证构造期错误码与公开消息与迁移前一致，且不绑定
// 端口、不创建协程。
func TestNewValidationMessages(t *testing.T) {
	cases := []struct {
		name    string
		options Options
		want    string
	}{
		{"缺少处理程序", Options{Config: testServerConfig(t, nil)}, "缺少 HTTP 处理程序"},
		{"配置无效", Options{Config: config.Config{}, Handler: testHandler()}, "配置无效"},
		{"非法前缀", Options{Config: testServerConfig(t, nil), Handler: testHandler(),
			Prefix: "api"}, "路径前缀无效"},
		{"前缀不一致", Options{Config: testServerConfig(t, func(c *config.Config) {
			c.Server.PathPrefix = "/api"
		}), Handler: testHandler()}, "必须与 server.path_prefix 一致"},
		{"公开地址路径不一致", Options{Config: testServerConfig(t, func(c *config.Config) {
			c.Server.PublicBaseURL = "https://example.test/other"
		}), Handler: testHandler()}, "公开基础地址的路径"},
		// 空监听地址与非回环明文组合会先被公共配置校验拒绝；此处确认仍返回
		// CONFIG_INVALID 而不是崩溃或监听。
		{"无监听地址", Options{Config: testServerConfig(t, func(c *config.Config) {
			c.Server.ListenAddr = ""
		}), Handler: testHandler()}, "配置无效"},
		{"非回环明文无代理模式", Options{Config: testServerConfig(t, func(c *config.Config) {
			c.Server.ListenAddr = "0.0.0.0:8080"
		}), Handler: testHandler()}, "非回环明文监听"},
		{"非回环明文无可信代理", Options{Config: testServerConfig(t, func(c *config.Config) {
			c.Server.ListenAddr = "0.0.0.0:8080"
			c.Server.TLSProxyMode = true
			c.Server.PublicBaseURL = "https://example.test"
			c.Server.AllowedHosts = []string{"example.test"}
		}), Handler: testHandler()}, "配置无效"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			server, err := New(test.options)
			if err == nil {
				if server != nil {
					_ = server.Close(context.Background())
				}
				t.Fatal("期望构造失败")
			}
			if message := configInvalidMessage(t, err); !strings.Contains(message, test.want) {
				t.Fatalf("公开消息 = %q，期望包含 %q", message, test.want)
			}
		})
	}
}

// TestNewValidAndReloadWithoutTLS 验证合法回环配置可构造（不监听），未启用 TLS 时
// ReloadTLS 返回与迁移前一致的 CONFIG_INVALID 错误。
func TestNewValidAndReloadWithoutTLS(t *testing.T) {
	server, err := New(Options{Config: testServerConfig(t, nil), Handler: testHandler()})
	if err != nil {
		t.Fatalf("合法回环配置构造失败: %v", err)
	}
	if server.Addrs() != nil {
		t.Fatalf("未启动时 Addrs 必须为空: %v", server.Addrs())
	}
	if server.TLSEnabled() {
		t.Fatal("未配置证书时 TLSEnabled 必须为 false")
	}
	if _, ok := server.TLSStatus(); ok {
		t.Fatal("未配置证书时 TLSStatus 必须返回 false")
	}
	if message := configInvalidMessage(t, server.ReloadTLS(context.Background())); !strings.Contains(message, "未启用本地 TLS 证书") {
		t.Fatalf("ReloadTLS 错误消息 = %q", message)
	}
	if err := server.Close(context.Background()); err != nil {
		t.Fatalf("未启动 Close 应成功: %v", err)
	}
}

// TestPublicTLSStatusProjection 验证内部 TLS 状态被完整脱敏投影为公开类型。
func TestPublicTLSStatusProjection(t *testing.T) {
	now := time.Now().UTC()
	status := tlscert.Status{
		LoadedAt:         now,
		EarliestNotAfter: now.Add(24 * time.Hour),
		ExpiringSoon:     true,
		ReloadFailures:   2,
		LastReloadAt:     now,
		LastReloadFailed: true,
		Certificates: []tlscert.CertificateInfo{{
			Domains: []string{"example.test"}, NotBefore: now,
			NotAfter: now.Add(48 * time.Hour), FingerprintSHA256: "abc",
			SerialNumber: "01", SelfSigned: true,
		}},
		ClientAuth: tlscert.ClientAuthStatus{
			Mode: tlscert.ClientAuthOptional,
			TrustAnchors: []tlscert.ClientTrustAnchor{{
				Subject: "CN=Test CA", FingerprintSHA256: "def",
				NotBefore: now, NotAfter: now.Add(72 * time.Hour), SelfSigned: true,
			}},
			Identities: []tlscert.ClientIdentity{{DNSName: "svc.example.test", Service: "svc"}},
		},
	}
	public := publicTLSStatus(status)
	if public.LoadedAt != now || len(public.Certificates) != 1 ||
		public.Certificates[0].Domains[0] != "example.test" ||
		public.Certificates[0].FingerprintSHA256 != "abc" ||
		!public.Certificates[0].SelfSigned {
		t.Fatalf("证书状态投影异常: %+v", public)
	}
	if public.ClientAuth.Mode != config.TLSClientAuthOptional ||
		len(public.ClientAuth.TrustAnchors) != 1 ||
		public.ClientAuth.TrustAnchors[0].Subject != "CN=Test CA" ||
		len(public.ClientAuth.Identities) != 1 ||
		public.ClientAuth.Identities[0].Service != "svc" {
		t.Fatalf("客户端认证状态投影异常: %+v", public.ClientAuth)
	}
	if !public.ExpiringSoon || !public.LastReloadFailed || public.ReloadFailures != 2 {
		t.Fatalf("重载/到期状态投影异常: %+v", public)
	}
	// 空状态 Mode 归一为 disabled（公开契约稳定值）。
	empty := publicTLSStatus(tlscert.Status{})
	if empty.ClientAuth.Mode != config.TLSClientAuthDisabled {
		t.Fatalf("空客户端认证模式 = %q，期望 disabled", empty.ClientAuth.Mode)
	}
	_ = httpapi.TLSStatus{}
}
