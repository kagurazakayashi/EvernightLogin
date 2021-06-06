package avatar_test

import (
	"bytes"
	"compress/gzip"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/avatar"
)

// fetchHandler 构造覆盖远程边界用例的本地 HTTP 服务；测试不访问真实外网。
func fetchHandler(t *testing.T) http.Handler {
	t.Helper()
	pngData := makePNG(t, 32, 32)
	jpegData := makeJPEG(t, 40, 40)
	bigData := makePNG(t, 600, 600)
	if len(bigData) <= 4096 {
		t.Fatalf("大图尺寸异常: %d 字节", len(bigData))
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(make([]byte, 8<<20)); err != nil {
		t.Fatalf("压缩测试数据: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("关闭压缩: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ok.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(pngData)
	})
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ok.png", http.StatusFound)
	})
	mux.HandleFunc("/redirect-file", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "file:///etc/passwd")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	})
	mux.HandleFunc("/html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>not an image</html>"))
	})
	mux.HandleFunc("/missing", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		// 追加远大于策略上限的填充字节，确保按 Content-Length 或读取上限提前拒绝。
		payload := append(append([]byte(nil), bigData...), bytes.Repeat([]byte{0}, 200<<10)...)
		_, _ = w.Write(payload)
	})
	mux.HandleFunc("/mismatch", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/jpeg")
		_, _ = w.Write(pngData)
	})
	mux.HandleFunc("/gzip-bomb", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(compressed.Bytes())
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1200 * time.Millisecond)
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(pngData)
	})
	_ = jpegData
	return mux
}

// TestNetworkFetchBoundaries 覆盖受控抓取的正常路径、重定向、大小/时限/类型与
// 非允许目标拒绝；使用本地 httptest 服务，不访问真实外网。
func TestNetworkFetchBoundaries(t *testing.T) {
	server := httptest.NewServer(fetchHandler(t))
	defer server.Close()
	env := newTestEnv(t, func(options *avatar.Options) {
		options.Network = avatar.NetworkPolicy{
			TestOnlyAllowLocalAddresses: true,
			MaxBytes:                    128 << 10,
			Timeout:                     time.Second,
			MaxRedirects:                2,
		}
	})
	const userID = "usr_00000000000000000000000000000010"
	env.seedUser(userID, "frank")
	caller := env.userCaller(userID)

	// 正常抓取并落库；URL 不写入数据库，审计只记录主机名。
	fetched, err := env.service.FetchFromURL(env.ctx, caller, avatar.FetchRequest{
		URL: server.URL + "/ok.png", ExpectedRowVersion: 1, RequestID: "req-net-1",
	})
	if err != nil {
		t.Fatalf("抓取网络头像: %v", err)
	}
	if fetched.SourceKind != avatar.SourceNetwork || fetched.MediaType != avatar.MediaTypePNG {
		t.Fatalf("网络头像元数据异常: %+v", fetched)
	}
	if events := env.successEvents("avatar.fetch"); events != 1 {
		t.Errorf("网络头像成功审计数 = %d，期望 1", events)
	}
	detail := env.auditDetail("avatar.fetch")
	if strings.Contains(detail, "/ok.png") || strings.Contains(detail, server.URL) {
		t.Errorf("审计不应记录完整网络地址: %q", detail)
	}
	if strings.Contains(detail, env.dir) {
		t.Errorf("审计泄露本机路径: %q", detail)
	}
	// 重定向到允许目标可以成功。
	if _, err := env.service.FetchFromURL(env.ctx, caller, avatar.FetchRequest{
		URL: server.URL + "/redirect", ExpectedRowVersion: 2, RequestID: "req-net-2",
	}); err != nil {
		t.Errorf("允许重定向抓取: %v", err)
	}

	boundaries := []struct {
		name string
		url  string
		want error
	}{
		{name: "重定向到file协议", url: server.URL + "/redirect-file", want: avatar.ErrRemoteBlocked},
		{name: "重定向次数超限", url: server.URL + "/loop", want: avatar.ErrRemoteBlocked},
		{name: "file协议", url: "file:///etc/passwd", want: avatar.ErrRemoteBlocked},
		{name: "地址含凭证", url: "http://user:pass@127.0.0.1/ok.png", want: avatar.ErrRemoteBlocked},
		{name: "远端404", url: server.URL + "/missing", want: avatar.ErrRemoteUnavailable},
		{name: "远端HTML", url: server.URL + "/html", want: avatar.ErrUnsupportedMedia},
		{name: "远端过大", url: server.URL + "/big", want: avatar.ErrImageTooLarge},
		{name: "远端超时", url: server.URL + "/slow", want: avatar.ErrRemoteUnavailable},
		{name: "声明与真实不一致", url: server.URL + "/mismatch", want: avatar.ErrContentTypeMismatch},
		{name: "压缩炸弹不解压", url: server.URL + "/gzip-bomb", want: avatar.ErrUnsupportedMedia},
		{name: "非法URL", url: "://bad", want: avatar.ErrInvalidRequest},
	}
	for _, boundary := range boundaries {
		t.Run(boundary.name, func(t *testing.T) {
			if _, err := env.service.FetchFromURL(env.ctx, caller, avatar.FetchRequest{
				URL: boundary.url, ExpectedRowVersion: 3, RequestID: "req-net-boundary",
			}); !errors.Is(err, boundary.want) {
				t.Fatalf("抓取错误 = %v，期望 %v", err, boundary.want)
			}
		})
	}
	if files := env.storedFiles(); len(files) != 1 {
		t.Errorf("边界用例后头像文件数 = %d，期望 1（只保留成功抓取的结果）", len(files))
	}
	if rows := env.count(`SELECT COUNT(*) FROM avatars`); rows != 1 {
		t.Errorf("边界用例后头像行数 = %d，期望 1", rows)
	}
}

// TestNetworkProductionPolicyBlocksLocalTargets 验证默认生产策略拒绝回环/明文目标，
// 且被拒绝请求不触发任何存储或数据库写入；主机白名单外目标同样拒绝。
func TestNetworkProductionPolicyBlocksLocalTargets(t *testing.T) {
	server := httptest.NewServer(fetchHandler(t))
	defer server.Close()
	env := newTestEnv(t, func(options *avatar.Options) {
		options.Network = avatar.NetworkPolicy{}
	})
	const userID = "usr_00000000000000000000000000000011"
	env.seedUser(userID, "grace")
	caller := env.userCaller(userID)
	if _, err := env.service.FetchFromURL(env.ctx, caller, avatar.FetchRequest{
		URL: server.URL + "/ok.png", ExpectedRowVersion: 1, RequestID: "req-net-prod",
	}); !errors.Is(err, avatar.ErrRemoteBlocked) {
		t.Fatalf("生产策略抓取回环地址错误 = %v，期望 ErrRemoteBlocked", err)
	}
	if ref := env.scalar(`SELECT COALESCE(avatar_ref,'') FROM users WHERE id=?`, userID); ref != "" {
		t.Errorf("被拒绝抓取后 avatar_ref = %q，期望空", ref)
	}
	if rows := env.count(`SELECT COUNT(*) FROM avatars`); rows != 0 {
		t.Errorf("被拒绝抓取后头像行数 = %d，期望 0", rows)
	}

	allowlistEnv := newTestEnv(t, func(options *avatar.Options) {
		options.Network = avatar.NetworkPolicy{AllowedHosts: []string{"cdn.example.com"}}
	})
	allowlistEnv.seedUser(userID, "grace")
	if _, err := allowlistEnv.service.FetchFromURL(allowlistEnv.ctx, allowlistEnv.userCaller(userID), avatar.FetchRequest{
		URL: "https://other.example.com/avatar.png", ExpectedRowVersion: 1, RequestID: "req-net-allow",
	}); !errors.Is(err, avatar.ErrRemoteBlocked) {
		t.Fatalf("白名单外主机错误 = %v，期望 ErrRemoteBlocked", err)
	}
}

// TestNetworkPolicyValidation 校验网络策略边界值拒绝非法配置。
func TestNetworkPolicyValidation(t *testing.T) {
	cases := []struct {
		name   string
		policy avatar.NetworkPolicy
	}{
		{name: "字节上限过小", policy: avatar.NetworkPolicy{MaxBytes: 10}},
		{name: "字节上限过大", policy: avatar.NetworkPolicy{MaxBytes: avatar.MaxStoredBytes + 1}},
		{name: "超时过小", policy: avatar.NetworkPolicy{Timeout: 100 * time.Millisecond}},
		{name: "超时过大", policy: avatar.NetworkPolicy{Timeout: time.Minute}},
		{name: "重定向过多", policy: avatar.NetworkPolicy{MaxRedirects: 9}},
		{name: "主机名非法", policy: avatar.NetworkPolicy{AllowedHosts: []string{"bad host/path"}}},
	}
	env := newTestEnv(t, nil)
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			options := env.options
			options.Network = test.policy
			if _, err := avatar.New(options); !errors.Is(err, avatar.ErrOptionsInvalid) {
				t.Fatalf("非法网络策略错误 = %v，期望 ErrOptionsInvalid", err)
			}
		})
	}
}

// TestAuthorizationBeforeResourceWork 验证无权限调用者既不能驱使服务器抓取网络
// 地址，也不能让服务器先做图片解码；授权/版本判定发生在资源消耗之前。
func TestAuthorizationBeforeResourceWork(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(makePNG(t, 32, 32))
	}))
	defer server.Close()
	env := newTestEnv(t, func(options *avatar.Options) {
		options.Network = avatar.NetworkPolicy{TestOnlyAllowLocalAddresses: true, Timeout: time.Second}
	})
	const aliceID = "usr_00000000000000000000000000000012"
	const bobID = "usr_00000000000000000000000000000013"
	env.seedUser(aliceID, "alice4")
	env.seedUser(bobID, "bob4")
	bob := env.userCaller(bobID)
	if _, err := env.service.FetchFromURL(env.ctx, bob, avatar.FetchRequest{
		TargetUserID: aliceID, URL: server.URL + "/ok.png",
		ExpectedRowVersion: 1, RequestID: "req-order-1",
	}); !errors.Is(err, avatar.ErrAccessDenied) {
		t.Fatalf("越权抓取错误 = %v，期望 ErrAccessDenied", err)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("越权抓取仍向远端发出 %d 次请求，期望 0", got)
	}
	if _, err := env.service.Upload(env.ctx, bob, avatar.UploadRequest{
		TargetUserID: aliceID, Data: []byte("not an image"),
		ExpectedRowVersion: 1, RequestID: "req-order-2",
	}); !errors.Is(err, avatar.ErrAccessDenied) {
		t.Fatalf("越权上传错误 = %v，期望 ErrAccessDenied（先判权再解码）", err)
	}
}
