package testmail_test

import (
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/testmail"
)

// repoRoot 返回仓库根目录（本测试文件位于 <root>/internal/testmail/）。
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("无法定位测试文件路径")
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(file)))
}

// TestExternalRecipientCapturedLocally 验证收件人域名为外部域名时消息也只保存在
// 本地内存中（不尝试外部投递）。
func TestExternalRecipientCapturedLocally(t *testing.T) {
	srv := startServer(t, testmail.Options{})
	c := dialServer(t, srv)
	c.expectCode(250, "EHLO client.example.test")
	c.sendMail("sender@example.test", []string{"nobody@unreachable.invalid"}, "Subject: no egress\n\nbody")

	msgs := srv.Messages(testmail.Query{To: "nobody@unreachable.invalid"})
	if len(msgs) != 1 {
		t.Fatalf("外部域名收件人应被本地捕获，实际 %d 封", len(msgs))
	}
	if msgs[0].Subject != "no egress" {
		t.Errorf("捕获内容异常: %+v", msgs[0])
	}
}

// TestPackageHasNoOutboundNetworkCode 是对"绝不外发"的源码级守护：本包非测试
// 代码中不允许出现主动拨号/发送邮件的调用，防止将来误加中继能力。
func TestPackageHasNoOutboundNetworkCode(t *testing.T) {
	root := repoRoot(t)
	pkgDir := filepath.Join(root, "internal", "testmail")
	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		t.Fatalf("读取包目录失败: %v", err)
	}
	forbidden := []string{"net.Dial", "smtp.Dial", "smtp.SendMail", "http.Get(", "http.Post("}
	checked := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		checked++
		content, err := os.ReadFile(filepath.Join(pkgDir, name))
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", name, err)
		}
		for _, pattern := range forbidden {
			if strings.Contains(string(content), pattern) {
				t.Errorf("%s 出现禁止的外发调用 %q；testmail 只能本地捕获", name, pattern)
			}
		}
	}
	if checked == 0 {
		t.Fatal("没有检查到任何非测试源文件，检查逻辑可能失效")
	}
}

// TestNotImportedByProductionEntrypoints 验证内部测试服务器没有被生产入口或根包
// 导入：cmd/ 与仓库根包的 Go 文件都不允许引用 internal/testmail。防止测试基础设施
// 被悄悄装配进生产启动路径。
func TestNotImportedByProductionEntrypoints(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()

	checkFile := func(path string) {
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("解析 %s 失败: %v", path, err)
		}
		for _, imp := range file.Imports {
			value, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("解析导入路径失败: %v", err)
			}
			if strings.Contains(value, "internal/testmail") {
				t.Errorf("%s 不应导入 internal/testmail（测试基础设施不得进入生产路径）", path)
			}
		}
	}

	dirs := []string{
		filepath.Join(root, "cmd"),
		root,
	}
	checked := 0
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("读取目录 %s 失败: %v", dir, err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			checked++
			checkFile(filepath.Join(dir, entry.Name()))
		}
	}
	for _, sub := range []string{"login-server", "loginctl", "login-backup"} {
		dir := filepath.Join(root, "cmd", sub)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue // 尚未创建的命令目录跳过。
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			checked++
			checkFile(filepath.Join(dir, entry.Name()))
		}
	}
	if checked == 0 {
		t.Fatal("没有检查到任何生产入口文件，检查逻辑可能失效")
	}
}

// TestNetProtoListenersAreLoopbackOnly 是新监听器（IMAP/POP3）的隔离守护：
//   - 启动后三个监听器的实际绑定地址都必须回环；
//   - IMAP/POP3 必须配置模拟账户才能启用（不允许匿名读取收件箱）；
//   - 明文 IMAP/POP3 即使显式 AllowNonLoopback 也拒绝非回环地址；
//   - 非回环监听必须同时启用隐式 TLS 并显式 AllowNonLoopback。
//
// 测试只做 New 阶段的配置校验，不真实绑定非回环地址，避免在测试机上开放对外端口。
func TestNetProtoListenersAreLoopbackOnly(t *testing.T) {
	auth := &testmail.AuthOptions{Users: map[string]string{"tester": "test-pass"}}
	cert, err := testmail.GenerateTestCertificate()
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	srv := startServer(t, testmail.Options{
		Auth: auth,
		IMAP: &testmail.IMAPOptions{},
		POP3: &testmail.POP3Options{},
	})
	listeners := map[string]net.Addr{
		"SMTP": srv.Addr(),
		"IMAP": srv.IMAPAddr(),
		"POP3": srv.POP3Addr(),
	}
	for name, addr := range listeners {
		if addr == nil {
			t.Fatalf("%s 监听地址为空（监听器未启动）", name)
		}
		tcpAddr, ok := addr.(*net.TCPAddr)
		if !ok || tcpAddr.IP == nil || !tcpAddr.IP.IsLoopback() {
			t.Errorf("%s 实际绑定地址 %s 不是回环地址；测试邮件服务器不得对网络暴露", name, addr)
		}
	}

	// IMAP/POP3 没有模拟账户时必须在 New 阶段拒绝（默认拒绝，不允许匿名收件箱）。
	if _, err := testmail.New(testmail.Options{IMAP: &testmail.IMAPOptions{}}); err == nil {
		t.Error("未配置 Auth 的 IMAP 应在 New 阶段被拒绝")
	}
	if _, err := testmail.New(testmail.Options{POP3: &testmail.POP3Options{}}); err == nil {
		t.Error("未配置 Auth 的 POP3 应在 New 阶段被拒绝")
	}

	// 明文非回环：即使 AllowNonLoopback=true 也必须拒绝（明文只允许回环）。
	if _, err := testmail.New(testmail.Options{
		Auth:             auth,
		AllowNonLoopback: true,
		IMAP:             &testmail.IMAPOptions{Addr: "0.0.0.0:0"},
	}); err == nil {
		t.Error("明文 IMAP 监听 0.0.0.0:0 应被拒绝")
	}
	if _, err := testmail.New(testmail.Options{
		Auth:             auth,
		AllowNonLoopback: true,
		POP3:             &testmail.POP3Options{Addr: ":0"},
	}); err == nil {
		t.Error("明文 POP3 空主机名监听应被拒绝")
	}

	// 非回环 + TLS 但未显式 AllowNonLoopback：仍然拒绝（两道开关缺一不可）。
	if _, err := testmail.New(testmail.Options{
		Auth: auth,
		IMAP: &testmail.IMAPOptions{Addr: "0.0.0.0:0", TLS: &testmail.TLSOptions{Certificate: cert}},
	}); err == nil {
		t.Error("TLS IMAP 未显式 AllowNonLoopback 时监听 0.0.0.0:0 应被拒绝")
	}

	// 非回环 + TLS + 显式 AllowNonLoopback：配置校验通过（这里不真正监听）。
	if _, err := testmail.New(testmail.Options{
		Auth:             auth,
		AllowNonLoopback: true,
		IMAP:             &testmail.IMAPOptions{Addr: "0.0.0.0:0", TLS: &testmail.TLSOptions{Certificate: cert}},
		POP3:             &testmail.POP3Options{Addr: "0.0.0.0:0", TLS: &testmail.TLSOptions{Certificate: cert}},
	}); err != nil {
		t.Errorf("TLS + AllowNonLoopback 的非回环配置不应被拒绝: %v", err)
	}
}
