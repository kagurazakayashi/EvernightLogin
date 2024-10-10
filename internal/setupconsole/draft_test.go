package setupconsole

// 步骤280：草稿校验/差异/原子保存/冲突/备份/秘密占位定向测试。

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newDraftFromFile 写入初始配置并为其构造草稿。
func newDraftFromFile(t *testing.T, dir, content string) (*ConfigDraft, string) {
	t.Helper()
	path := filepath.Join(dir, "login.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("写入配置: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取配置: %v", err)
	}
	draft, err := NewConfigDraft(path, raw)
	if err != nil {
		t.Fatalf("构造草稿: %v", err)
	}
	return draft, path
}

// TestSaveConfigDraftSuccessAndBackup 覆盖成功保存、最后有效备份与热重载分类。
func TestSaveConfigDraftSuccessAndBackup(t *testing.T) {
	dir := t.TempDir()
	original := "logging:\n  level: info\n"
	draft, path := newDraftFromFile(t, dir, original)
	if err := draft.SetValue("logging.level", "debug"); err != nil {
		t.Fatalf("编辑草稿: %v", err)
	}
	result, err := SaveConfigDraft(context.Background(), SaveRequest{Draft: draft,
		ConflictPolicy: ConflictFail, CreateBackup: true})
	if err != nil {
		t.Fatalf("保存草稿: %v", err)
	}
	if !result.Saved || result.FileDigest == "" {
		t.Fatalf("保存结果异常: %+v", result)
	}
	saved, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(saved), "debug") {
		t.Fatalf("保存内容异常: %q err=%v", string(saved), err)
	}
	if result.BackupPath == "" {
		t.Fatal("缺少最后有效备份记录")
	}
	backup, err := os.ReadFile(result.BackupPath)
	if err != nil || !strings.Contains(string(backup), "info") {
		t.Fatalf("最后有效备份内容异常: %q err=%v", string(backup), err)
	}
	if result.ReloadResult != "hot-reload-required" {
		t.Fatalf("logging.level 应为热重载分类，实际 %q", result.ReloadResult)
	}
	for _, field := range result.HotFields {
		if field == "logging.level" {
			return
		}
	}
	t.Fatalf("热重载字段缺少 logging.level：%+v", result.HotFields)
}

// TestSaveConfigDraftExternalConflict 覆盖外部修改冲突默认拒绝并且不覆盖文件。
func TestSaveConfigDraftExternalConflict(t *testing.T) {
	dir := t.TempDir()
	draft, path := newDraftFromFile(t, dir, "logging:\n  level: info\n")
	if err := draft.SetValue("logging.level", "debug"); err != nil {
		t.Fatalf("编辑草稿: %v", err)
	}
	external := "logging:\n  level: warn\n"
	if err := os.WriteFile(path, []byte(external), 0o600); err != nil {
		t.Fatalf("模拟外部修改: %v", err)
	}
	if _, err := SaveConfigDraft(context.Background(),
		SaveRequest{Draft: draft, ConflictPolicy: ConflictFail}); !errors.Is(err, ErrSaveConflict) {
		t.Fatalf("外部修改应拒绝保存: %v", err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != external {
		t.Fatalf("冲突时覆盖了外部修改: %q", string(data))
	}
}

// TestSaveConfigDraftRejectsInvalidAndPlaceholder 覆盖非法草稿/秘密占位拒绝。
func TestSaveConfigDraftRejectsInvalidAndPlaceholder(t *testing.T) {
	dir := t.TempDir()
	draft, path := newDraftFromFile(t, dir, "logging:\n  level: info\n")
	if err := draft.SetValue("logging.level", "not-a-level"); err != nil {
		t.Fatalf("编辑草稿: %v", err)
	}
	if _, err := SaveConfigDraft(context.Background(),
		SaveRequest{Draft: draft}); !errors.Is(err, ErrDraftInvalid) {
		t.Fatalf("非法草稿应拒绝: %v", err)
	}
	before, _ := os.ReadFile(path)
	if !strings.Contains(string(before), "info") {
		t.Fatal("非法草稿保存写入了文件")
	}
	// 秘密占位拒绝：secrets.master_key 写 "***"。
	placeholderDraft, _ := newDraftFromFile(t, t.TempDir(), "logging:\n  level: info\n")
	if err := placeholderDraft.SetValue("secrets.master_key", "***"); err != nil {
		t.Fatalf("设置占位: %v", err)
	}
	if _, err := SaveConfigDraft(context.Background(),
		SaveRequest{Draft: placeholderDraft}); !errors.Is(err, ErrSecretPlaceholder) {
		t.Fatalf("秘密占位应拒绝: %v", err)
	}
}

// TestSaveConfigDraftWriteFailureKeepsOriginal 覆盖注入写盘失败时原文件完整。
func TestSaveConfigDraftWriteFailureKeepsOriginal(t *testing.T) {
	dir := t.TempDir()
	original := "logging:\n  level: info\n"
	draft, path := newDraftFromFile(t, dir, original)
	if err := draft.SetValue("logging.level", "debug"); err != nil {
		t.Fatalf("编辑草稿: %v", err)
	}
	previousWriter := writeFileAtomic
	writeFileAtomic = func(string, []byte, os.FileMode) error {
		return errors.New("注入写盘失败")
	}
	defer func() { writeFileAtomic = previousWriter }()
	if _, err := SaveConfigDraft(context.Background(),
		SaveRequest{Draft: draft, CreateBackup: true}); err == nil {
		t.Fatal("注入写盘失败应返回错误")
	}
	data, _ := os.ReadFile(path)
	if string(data) != original {
		t.Fatalf("写盘失败破坏原文件: %q", string(data))
	}
}

// TestDetectStaleTempFiles 覆盖崩溃残留识别（不删除）。
func TestDetectStaleTempFiles(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, ".login-setup-save-123456")
	if err := os.WriteFile(stale, []byte("partial"), 0o600); err != nil {
		t.Fatalf("写入残留: %v", err)
	}
	found, err := DetectStaleTempFiles(dir)
	if err != nil {
		t.Fatalf("识别残留: %v", err)
	}
	if len(found) != 1 || found[0] != stale {
		t.Fatalf("残留识别结果异常: %+v", found)
	}
	if _, err := os.Stat(stale); err != nil {
		t.Fatal("识别残留不应删除文件")
	}
}

// TestFieldsScreenSaveViaPreview 覆盖全屏“W→预览→Enter 保存”闭环。
func TestFieldsScreenSaveViaPreview(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "login.yaml")
	if err := os.WriteFile(configPath, []byte("logging:\n  level: info\n"), 0o600); err != nil {
		t.Fatalf("写入配置: %v", err)
	}
	terminal := newFakeTerminal(
		downKey(), downKey(), enterKey(), // 全配置字段编辑
		runeKey('/'), runeKey('l'), runeKey('o'), runeKey('g'), runeKey('g'),
		runeKey('i'), runeKey('n'), runeKey('g'), runeKey('.'), runeKey('l'),
		runeKey('e'), runeKey('v'), runeKey('e'), runeKey('l'),
		enterKey(), // 精确搜索 logging.level
		enterKey(), // 编辑（预填当前值 info）
		Key{Kind: KeyBackspace}, Key{Kind: KeyBackspace}, Key{Kind: KeyBackspace},
		Key{Kind: KeyBackspace},                                                          // 清空预填值
		runeKey('d'), runeKey('e'), runeKey('b'), runeKey('u'), runeKey('g'), enterKey(), // 输入 debug
		runeKey('w'),                                                      // 预览
		enterKey(),                                                        // 保存
		escKey(),                                                          // 返回配置画面
		escKey(),                                                          // 返回主菜单
		downKey(), downKey(), downKey(), downKey(), downKey(), enterKey(), // 退出
	)
	app := NewApp(terminal, configPath, func(ctx context.Context,
		options DetectOptions) Detection {
		return Detection{Kind: StateReady, ConfigPath: options.ConfigPath, Summary: "就绪"}
	})
	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("运行控制台: %v", err)
	}
	saved, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("读取保存结果: %v", err)
	}
	if !strings.Contains(string(saved), "debug") {
		t.Fatalf("全屏保存未生效: %q", string(saved))
	}
}
