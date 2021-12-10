package managecli

// 本文件覆盖下载写入安全语义（步骤 84 审计低项 L1/L2）：
//   - `--overwrite` 采用同目录临时文件 + fsync + 原子 rename，成功后旧文件才被替换；
//   - 下载失败时调用前已存在的目标文件保持不变（不会被截断/删除）；
//   - 目标为符号链接时拒绝写入（不跟随链接写到其他位置）；
//   - 成功/失败都不在目标目录遗留临时文件。
//
// 传输层使用真实 httptest 服务；管理会话秘密来自真实 session.Service（fixture），
// 下载命令的真实路由、envelope 与 --out 处理均走生产代码。

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// downloadPayloadHandler 返回固定字节流并声明安全文件名。
func downloadPayloadHandler(payload []byte) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/csv; charset=utf-8")
		writer.Header().Set("Content-Disposition",
			`attachment; filename="audit-export-fixed.csv"`)
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(payload)
	})
}

// requireNoDownloadTempFiles 断言下载目录没有遗留临时文件。
func requireNoDownloadTempFiles(t *testing.T, dir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, ".loginctl-download-*"))
	if err != nil {
		t.Fatalf("检查下载临时文件失败: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("下载遗留临时文件: %v", matches)
	}
}

// TestOnlineDownloadOverwriteAtomic 验证 --overwrite 原子覆盖与无临时残留。
func TestOnlineDownloadOverwriteAtomic(t *testing.T) {
	fixture := newOnlineFixture(t)
	fixture.serveHandler(downloadPayloadHandler([]byte("new-content")))
	dir := t.TempDir()
	target := filepath.Join(dir, "audit-export.csv")
	if err := os.WriteFile(target, []byte("old-content"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, exit := fixture.run("audit", "exports", "download", "aex_1",
		"--out", target, "--overwrite", "--json")
	if exit != ExitOK {
		t.Fatalf("覆盖下载退出码 = %d，stdout=%s stderr=%s", exit, stdout, stderr)
	}
	content, err := os.ReadFile(target)
	if err != nil || string(content) != "new-content" {
		t.Fatalf("覆盖后内容不符: %q err=%v", string(content), err)
	}
	requireNoDownloadTempFiles(t, dir)
}

// TestOnlineDownloadFailurePreservesExistingFile 验证下载中途失败时旧目标文件
// 保持完整（不会被截断或删除），且不遗留临时文件。
func TestOnlineDownloadFailurePreservesExistingFile(t *testing.T) {
	fixture := newOnlineFixture(t)
	// 声明 1 KiB 但只写 5 字节并提前返回：客户端读取得到 unexpected EOF。
	fixture.serveHandler(http.HandlerFunc(func(writer http.ResponseWriter,
		_ *http.Request) {
		writer.Header().Set("Content-Length", "1024")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("short"))
	}))
	dir := t.TempDir()
	target := filepath.Join(dir, "audit-export.csv")
	if err := os.WriteFile(target, []byte("old-content-must-stay"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, exit := fixture.run("audit", "exports", "download", "aex_1",
		"--out", target, "--overwrite", "--json")
	if exit != ExitError {
		t.Fatalf("失败下载退出码 = %d，期望 %d，stdout=%s stderr=%s",
			exit, ExitError, stdout, stderr)
	}
	content, err := os.ReadFile(target)
	if err != nil || string(content) != "old-content-must-stay" {
		t.Fatalf("失败下载破坏了旧文件: %q err=%v", string(content), err)
	}
	requireNoDownloadTempFiles(t, dir)
}

// TestOnlineDownloadRejectsSymlinkTarget 验证目标为符号链接时拒绝写入，且不跟随
// 链接改动被指向的文件（平台不支持创建符号链接时跳过）。
func TestOnlineDownloadRejectsSymlinkTarget(t *testing.T) {
	fixture := newOnlineFixture(t)
	fixture.serveHandler(downloadPayloadHandler([]byte("new-content")))
	dir := t.TempDir()
	realTarget := filepath.Join(dir, "real-target.bin")
	if err := os.WriteFile(realTarget, []byte("real-old-content"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(dir, "link.bin")
	if err := os.Symlink(realTarget, linkPath); err != nil {
		t.Skipf("当前环境无法创建符号链接（跳过）: %v", err)
	}
	stdout, _, exit := fixture.run("audit", "exports", "download", "aex_1",
		"--out", linkPath, "--overwrite", "--json")
	requireOnlineFailure(t, stdout, exit, ExitUsage, "OUTPUT_FILE_INVALID")
	content, err := os.ReadFile(realTarget)
	if err != nil || string(content) != "real-old-content" {
		t.Fatalf("符号链接目标被跟随写入: %q err=%v", string(content), err)
	}
	if info, err := os.Lstat(linkPath); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("符号链接被替换/删除: %v err=%v", info, err)
	}
	requireNoDownloadTempFiles(t, dir)
}
