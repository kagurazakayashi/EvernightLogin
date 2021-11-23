package backup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
)

// TestExtractRejectsPresetSymlinkDestination 验证步骤 82 审计 L5 的加固：解包父
// 目录里的预置符号链接/普通文件不会被跟随，条目文件 O_EXCL 不覆盖已有文件。
func TestExtractRejectsPresetSymlinkDestination(t *testing.T) {
	env, backupPath, avatarContent := newViewerTestEnv(t, nil)
	ctx := context.Background()
	report, err := VerifyFile(ctx, backupPath, env.ring)
	if err != nil {
		t.Fatalf("认证校验失败：%v", err)
	}
	var attachmentEntry *EntryReport
	for index := range report.Entries {
		if report.Entries[index].Kind == EntryKindAttachment {
			attachmentEntry = &report.Entries[index]
			break
		}
	}
	if attachmentEntry == nil {
		t.Fatalf("测试备份缺少附件条目")
	}

	// 情形一：目标暂存目录内预置 attachments 符号链接指向外部目录。
	outsideDir := testutil.TempDir(t)
	destination := testutil.TempDir(t)
	if err := os.Symlink(outsideDir, filepath.Join(destination, "attachments")); err != nil {
		t.Skipf("当前环境不支持创建符号链接，跳过符号链接用例：%v", err)
	}
	_, err = Extract(ctx, ExtractOptions{Path: backupPath, Keyring: env.ring,
		Destination: destination})
	if !errors.Is(err, ErrOutputDirUnsafe) {
		t.Fatalf("预置符号链接父目录未按 ErrOutputDirUnsafe 拒绝：%v", err)
	}
	if entries, readErr := os.ReadDir(outsideDir); readErr != nil || len(entries) != 0 {
		t.Fatalf("解包越出暂存目录：%v %v", entries, readErr)
	}

	// 情形二：目标暂存目录内预置同名普通文件（不是目录）阻止落盘。
	destination2 := testutil.TempDir(t)
	blocker := filepath.Join(destination2, "attachments")
	if err := os.WriteFile(blocker, []byte("preserve"), 0o600); err != nil {
		t.Fatalf("写入预置文件失败：%v", err)
	}
	if _, err := Extract(ctx, ExtractOptions{Path: backupPath, Keyring: env.ring,
		Destination: destination2}); err == nil {
		t.Fatal("预置普通文件父路径未被拒绝")
	}
	if data, readErr := os.ReadFile(blocker); readErr != nil || string(data) != "preserve" {
		t.Fatalf("预置文件被修改：%q err=%v", data, readErr)
	}

	// 情形三：预置完整目标路径文件；O_EXCL 必须失败且不覆盖原内容。
	destination3 := testutil.TempDir(t)
	targetPath := filepath.Join(destination3,
		filepath.FromSlash(attachmentEntry.Name))
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
		t.Fatalf("创建预置目录失败：%v", err)
	}
	if err := os.WriteFile(targetPath, []byte("preserve"), 0o600); err != nil {
		t.Fatalf("写入预置目标文件失败：%v", err)
	}
	if _, err := Extract(ctx, ExtractOptions{Path: backupPath, Keyring: env.ring,
		Destination: destination3}); !errors.Is(err, ErrBackupIO) {
		t.Fatalf("预置目标文件未按创建冲突拒绝：%v", err)
	}
	if data, readErr := os.ReadFile(targetPath); readErr != nil || string(data) != "preserve" {
		t.Fatalf("预置目标文件被覆盖：%q err=%v", data, readErr)
	}

	// 情形四：正常解包附件内容正确。
	destination4 := testutil.TempDir(t)
	result, err := Extract(ctx, ExtractOptions{Path: backupPath, Keyring: env.ring,
		Destination: destination4})
	if err != nil {
		t.Fatalf("正常解包失败：%v", err)
	}
	if len(result.Attachments) != 1 {
		t.Fatalf("附件解包数量 = %d", len(result.Attachments))
	}
	extracted, err := os.ReadFile(result.Attachments[0].Path)
	if err != nil || string(extracted) != string(avatarContent) {
		t.Fatalf("附件内容异常：%q err=%v", extracted, err)
	}
	if !strings.HasSuffix(result.Attachments[0].Name, ".png") &&
		!strings.HasPrefix(result.Attachments[0].Name, attachmentEntryPrefix) {
		t.Fatalf("附件条目名异常：%s", result.Attachments[0].Name)
	}
}

// TestExtractRejectsUnsafeDestination 验证解包目标本身的安全检查（相对路径/符号
// 链接/文件）。
func TestExtractRejectsUnsafeDestination(t *testing.T) {
	env, backupPath, _ := newViewerTestEnv(t, nil)
	ctx := context.Background()
	if _, err := Extract(ctx, ExtractOptions{Path: backupPath, Keyring: env.ring,
		Destination: "relative-dir"}); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("相对解包目录未按 ErrOptionsInvalid 拒绝：%v", err)
	}
	filePath := filepath.Join(testutil.TempDir(t), "not-a-dir")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("写入文件失败：%v", err)
	}
	if _, err := Extract(ctx, ExtractOptions{Path: backupPath, Keyring: env.ring,
		Destination: filePath}); !errors.Is(err, ErrOutputDirUnsafe) {
		t.Fatalf("文件作为解包目录未按 ErrOutputDirUnsafe 拒绝：%v", err)
	}
}
