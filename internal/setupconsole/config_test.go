package setupconsole

// 步骤278：坏配置诊断/原文编辑/另存为/原子写入的定向测试。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLineEditorEditsAndRoundTrip 覆盖行编辑器基本操作与换行保留。
func TestLineEditorEditsAndRoundTrip(t *testing.T) {
	editor := newLineEditor([]byte("server:\n  listen_addr: 127.0.0.1:8080\n"))
	if editor.LineCount() != 3 { // 末尾换行产生空尾行
		t.Fatalf("行数 = %d，期望 3", editor.LineCount())
	}
	editor.SetCursor(1, len([]rune("  listen_addr: 127.0.0.1:8080")))
	editor.InsertRune('!')
	if !strings.Contains(string(editor.Bytes()), "8080!") {
		t.Fatalf("插入字符失败: %q", string(editor.Bytes()))
	}
	editor.Backspace()
	editor.SetCursor(0, 0)
	editor.InsertText("# 注释\n")
	text := string(editor.Bytes())
	if !strings.HasPrefix(text, "# 注释\nserver:") {
		t.Fatalf("拆行插入失败: %q", text)
	}
	// 合并：# 注释 行末 Backspace 与上一行合并。
	editor.SetCursor(1, 0)
	editor.Backspace()
	if strings.Count(string(editor.Bytes()), "\n") != 2 {
		t.Fatalf("行合并后换行数异常: %q", string(editor.Bytes()))
	}
	// 删除行只影响草稿。
	editor.SetCursor(0, 0)
	editor.DeleteLine()
	if editor.LineCount() != 2 {
		t.Fatalf("删除行后行数 = %d，期望 2", editor.LineCount())
	}
}

// TestValidateConfigTextAndDiagnostics 覆盖草稿校验与诊断模型（行列/建议）。
func TestValidateConfigTextAndDiagnostics(t *testing.T) {
	bad := ValidateConfigText([]byte("server: [\n"))
	if bad.Valid || len(bad.Issues) == 0 {
		t.Fatalf("坏草稿应返回诊断: %+v", bad)
	}
	if bad.Issues[0].Suggestion == "" {
		t.Fatal("坏草稿诊断缺少修复建议")
	}
	good := ValidateConfigText([]byte("logging:\n  level: debug\n"))
	if !good.Valid {
		t.Fatalf("好草稿应有效: %+v", good)
	}
	deep := strings.Repeat("a:\n", 40) + "value: 1\n"
	tooDeep := ValidateConfigText([]byte(deep))
	if tooDeep.Valid {
		t.Fatal("过深草稿不应通过编辑边界")
	}
	oversize := ValidateConfigText(make([]byte, MaxConfigBytes+1))
	if oversize.Valid {
		t.Fatal("超大草稿不应通过")
	}
}

// TestSafeWriteFileAtomicAndSymlink 覆盖原子写入、权限保持与符号链接拒绝。
func TestSafeWriteFileAtomicAndSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "login.yaml")
	if err := os.WriteFile(target, []byte("old\n"), 0o640); err != nil {
		t.Fatalf("写入初始文件: %v", err)
	}
	initialInfo, err := os.Stat(target)
	if err != nil {
		t.Fatalf("读取初始权限: %v", err)
	}
	initialMode := initialInfo.Mode().Perm()
	if err := SafeWriteFile(target, []byte("new\n"), 0o600); err != nil {
		t.Fatalf("原子写入: %v", err)
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "new\n" {
		t.Fatalf("原子写入结果异常: %q err=%v", string(data), err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("读取权限: %v", err)
	}
	if info.Mode().Perm() != initialMode {
		t.Fatalf("已有文件权限 = %o，期望保持 %o", info.Mode().Perm(), initialMode)
	}
	// 目标目录不存在：失败且不留下临时文件。
	missing := filepath.Join(dir, "missing-dir", "login.yaml")
	if err := SafeWriteFile(missing, []byte("x"), 0o600); err == nil {
		t.Fatal("不存在的目录应写入失败")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读取目录: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".login-setup-save-") {
			t.Fatalf("失败写入留下临时文件: %s", entry.Name())
		}
	}
	// 符号链接目标拒绝写入。
	linkPath := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(target, linkPath); err == nil {
		if err := SafeWriteFile(linkPath, []byte("x"), 0o600); err == nil {
			t.Fatal("符号链接目标应拒绝写入")
		}
	}
}

// TestLastValidStorePerPath 覆盖上次有效副本按路径隔离。
func TestLastValidStorePerPath(t *testing.T) {
	store := LastValidStore{}
	store.Remember(ConfigReport{Path: "/a/login.yaml", Valid: true, Raw: []byte("a")})
	if raw, ok := store.Load("/a/login.yaml"); !ok || string(raw) != "a" {
		t.Fatalf("上次有效副本读取失败: %q %v", string(raw), ok)
	}
	if _, ok := store.Load("/b/login.yaml"); ok {
		t.Fatal("不同路径不应复用上次有效副本")
	}
	store.Remember(ConfigReport{Path: "/a/login.yaml", Valid: false, Raw: []byte("bad")})
	if raw, _ := store.Load("/a/login.yaml"); string(raw) != "a" {
		t.Fatal("无效配置不应覆盖上次有效副本")
	}
}
