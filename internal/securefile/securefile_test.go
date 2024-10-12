package securefile

// 秘密文件读写定向测试：新建/拒绝覆盖/读取/大小上限/符号链接/宽权限拒绝。
// Windows DACL 专项见 securefile_windows_test.go；本文件在 Windows 上也会运行
// 通用部分（符号链接在无权限创建时跳过）。

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWriteReadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	if err := Write(path, []byte("S3cret-Value\n")); err != nil {
		t.Fatalf("写入秘密文件: %v", err)
	}
	raw, err := Read(path, DefaultMaxBytes)
	if err != nil {
		t.Fatalf("读取秘密文件: %v", err)
	}
	if string(raw) != "S3cret-Value\n" {
		t.Fatalf("读取内容 = %q", raw)
	}
}

func TestWriteRefusesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("new")); !errors.Is(err, ErrExists) {
		t.Fatalf("已存在文件应返回 ErrExists，得到 %v", err)
	}
	if raw, _ := os.ReadFile(path); string(raw) != "old" {
		t.Fatalf("已存在文件被改写: %q", raw)
	}
}

func TestReadRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	if err := Write(target, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("当前环境不允许创建符号链接（%v），跳过符号链接拒绝用例", err)
	}
	if _, err := Read(link, DefaultMaxBytes); !errors.Is(err, ErrSymlink) {
		t.Fatalf("符号链接应被拒绝，得到 %v", err)
	}
}

func TestReadRejectsNonRegular(t *testing.T) {
	dir := t.TempDir()
	if _, err := Read(dir, DefaultMaxBytes); err == nil {
		t.Fatal("目录不应被当作秘密文件读取")
	}
}

func TestReadRejectsTooLarge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.txt")
	if err := Write(path, []byte(strings.Repeat("x", 128))); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, 64); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("超限文件应返回 ErrTooLarge，得到 %v", err)
	}
}

func TestReadRejectsWorldReadable(t *testing.T) {
	// POSIX 模式位检查；Windows 由 DACL 测试覆盖。
	dir := t.TempDir()
	path := filepath.Join(dir, "wide.txt")
	if err := os.WriteFile(path, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Read(path, DefaultMaxBytes)
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatal(statErr)
	}
	if !errors.Is(err, ErrInsecurePerm) {
		if runtime.GOOS == "windows" {
			t.Logf("Windows 上模式位不适用，由 DACL 校验决定：%v", err)
		} else {
			t.Fatalf("组/其他可读文件应被拒绝，得到 %v", err)
		}
	}
}
