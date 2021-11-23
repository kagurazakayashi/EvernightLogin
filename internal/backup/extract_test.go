package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
)

// newExtractEnv 构造带附件与配置的真实备份环境，返回环境与备份结果。
func newExtractEnv(t *testing.T) (*testEnv, Result) {
	t.Helper()
	env := newTestEnv(t)
	env.service = env.newService(t, func(options *Options) {
		options.Attachments = mustAvatarSource(t, env.avatars)
		options.Config = env.writeConfig(t)
	})
	userID := "usr_" + strings.Repeat("22", 16)
	env.insertUser(t, userID)
	env.insertAvatar(t, userID, []byte("avatar-bytes-for-extract-test"))
	result, err := env.service.Create(context.Background(), CreateRequest{
		Caller: testCaller(t), RequestID: "req_extract_001"})
	if err != nil {
		t.Fatalf("创建测试备份失败：%v", err)
	}
	return env, result
}

// stagingDir 创建一个 0700 的受控暂存目录。
func stagingDir(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(testutil.TempDir(t), "staging")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("创建暂存目录失败：%v", err)
	}
	return directory
}

// TestExtractAuthenticatedBackupContent 校验认证解包：数据库/附件/配置条目真实落盘，
// 数据库文件摘要与清单一致，附件与配置字节与来源一致。
func TestExtractAuthenticatedBackupContent(t *testing.T) {
	env, backupResult := newExtractEnv(t)
	destination := stagingDir(t)
	extracted, err := Extract(context.Background(), ExtractOptions{
		Path: backupResult.Path, Keyring: env.ring, Destination: destination,
	})
	if err != nil {
		t.Fatalf("认证解包失败：%v", err)
	}
	if !extracted.Report.Authenticated || !extracted.Report.StructuralValid {
		t.Fatalf("解包报告未标记认证通过：%+v", extracted.Report)
	}
	if extracted.DatabasePath == "" {
		t.Fatal("解包结果缺少数据库条目路径")
	}
	databaseData, err := os.ReadFile(extracted.DatabasePath)
	if err != nil {
		t.Fatalf("读取解包数据库失败：%v", err)
	}
	digest := sha256.Sum256(databaseData)
	if int64(len(databaseData)) != extracted.Report.Database.SizeBytes ||
		hex.EncodeToString(digest[:]) != extracted.Report.Database.SHA256 {
		t.Fatal("解包数据库大小/摘要与清单不一致")
	}
	if len(extracted.Attachments) != 1 || len(extracted.Report.Entries) != 3 {
		t.Fatalf("解包条目数 = %d 附件 %d，期望 3/1",
			len(extracted.Report.Entries), len(extracted.Attachments))
	}
	attachmentData, err := os.ReadFile(extracted.Attachments[0].Path)
	if err != nil {
		t.Fatalf("读取解包附件失败：%v", err)
	}
	if string(attachmentData) != "avatar-bytes-for-extract-test" {
		t.Fatalf("解包附件内容不一致：%q", attachmentData)
	}
	if extracted.ConfigPath == "" {
		t.Fatal("解包结果缺少配置条目路径")
	}
	configData, err := os.ReadFile(extracted.ConfigPath)
	if err != nil {
		t.Fatalf("读取解包配置失败：%v", err)
	}
	if !bytes.Contains(configData, []byte("listen_addr")) {
		t.Fatalf("解包配置内容不一致：%q", configData)
	}
	// 解包文件权限必须收紧（非 Windows 由权限位约束；Windows 由目录 ACL 约束）。
	if !isWindowsPlatform() {
		info, err := os.Stat(extracted.DatabasePath)
		if err != nil {
			t.Fatalf("读取解包数据库状态失败：%v", err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("解包数据库权限过宽：%v", info.Mode().Perm())
		}
	}
}

// TestExtractOnlyEntriesFilter 校验条目过滤只落盘指定条目，其余条目仍被校验。
func TestExtractOnlyEntriesFilter(t *testing.T) {
	env, backupResult := newExtractEnv(t)
	destination := stagingDir(t)
	extracted, err := Extract(context.Background(), ExtractOptions{
		Path: backupResult.Path, Keyring: env.ring, Destination: destination,
		OnlyEntries: func(entry ManifestEntry) bool { return entry.Kind == EntryKindDatabase },
	})
	if err != nil {
		t.Fatalf("过滤解包失败：%v", err)
	}
	if len(extracted.Entries) != 1 || len(extracted.Attachments) != 0 ||
		extracted.ConfigPath != "" {
		t.Fatalf("过滤解包不应落盘附件/配置：%+v", extracted.Entries)
	}
	if _, err := os.Stat(filepath.Join(destination, "attachments")); !os.IsNotExist(err) {
		t.Fatalf("过滤解包不应创建附件目录：%v", err)
	}
}

// TestExtractWrongKeyAndUnsafeDestination 校验错误密钥与不安全暂存目录被拒绝。
func TestExtractWrongKeyAndUnsafeDestination(t *testing.T) {
	env, backupResult := newExtractEnv(t)
	wrong, err := secrets.GenerateKeyring("k2", backupTestTime)
	if err != nil {
		t.Fatalf("构造错误密钥环失败：%v", err)
	}
	if _, err := Extract(context.Background(), ExtractOptions{
		Path: backupResult.Path, Keyring: wrong, Destination: stagingDir(t),
	}); err == nil {
		t.Fatal("错误密钥必须导致解包失败")
	}
	if _, err := Extract(context.Background(), ExtractOptions{
		Path: backupResult.Path, Keyring: env.ring,
		Destination: filepath.Join(testutil.TempDir(t), "missing"),
	}); err == nil {
		t.Fatal("不存在的暂存目录必须拒绝")
	}
	if _, err := Extract(context.Background(), ExtractOptions{
		Path: backupResult.Path, Keyring: env.ring, Destination: "relative-dir",
	}); err == nil {
		t.Fatal("相对路径暂存目录必须拒绝")
	}
	// 符号链接目录必须拒绝。
	target := stagingDir(t)
	link := filepath.Join(testutil.TempDir(t), "link")
	if err := os.Symlink(target, link); err == nil {
		if _, err := Extract(context.Background(), ExtractOptions{
			Path: backupResult.Path, Keyring: env.ring, Destination: link,
		}); err == nil {
			t.Fatal("符号链接暂存目录必须拒绝")
		}
	}
}
