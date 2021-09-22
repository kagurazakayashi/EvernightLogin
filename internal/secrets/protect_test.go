package secrets

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestProtectFileTightensExistingFile 验证 ProtectFile 能收紧已存在普通文件的权限，
// 并在收紧后通过 CheckProtectedFile 复核。
func TestProtectFileTightensExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sensitive-export.csv")
	if err := os.WriteFile(path, []byte("id,value\n1,demo\n"), 0o644); err != nil {
		t.Fatalf("写入测试文件失败：%v", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatalf("设置宽松权限失败：%v", err)
		}
	}
	if err := ProtectFile(path); err != nil {
		t.Fatalf("ProtectFile 失败：%v", err)
	}
	if err := CheckProtectedFile(path); err != nil {
		t.Fatalf("收紧后 CheckProtectedFile 仍失败：%v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("读取文件状态失败：%v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("Unix 权限 = %o，期望 0600", info.Mode().Perm())
	}
	// 内容不得被 ProtectFile 改写。
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "demo") {
		t.Fatalf("文件内容异常：%q err=%v", data, err)
	}
}

// TestProtectFileRejectsUnsafeTargets 验证 ProtectFile 拒绝相对路径、目录、缺失文件
// 与符号链接（默认拒绝，不做静默降级）。
func TestProtectFileRejectsUnsafeTargets(t *testing.T) {
	if err := ProtectFile("relative.txt"); !errors.Is(err, ErrFileInvalid) {
		t.Fatalf("相对路径未按 ErrFileInvalid 拒绝：%v", err)
	}
	dir := t.TempDir()
	if err := ProtectFile(filepath.Join(dir, "missing.txt")); !errors.Is(err, ErrFileInvalid) {
		t.Fatalf("缺失文件未按 ErrFileInvalid 拒绝：%v", err)
	}
	if err := ProtectFile(dir); !errors.Is(err, ErrFileInvalid) {
		t.Fatalf("目录未按 ErrFileInvalid 拒绝：%v", err)
	}
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatalf("写入目标失败：%v", err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("当前环境不支持符号链接：%v", err)
	}
	if err := ProtectFile(link); !errors.Is(err, ErrFileInvalid) {
		t.Fatalf("符号链接未按 ErrFileInvalid 拒绝：%v", err)
	}
}
