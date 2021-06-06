package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestAvatarMigration 校验 0017 的头像元数据结构：服务端 ID、每用户一个、受控
// 存储相对键、重编码后的静态媒体类型、尺寸/字节数/摘要、来源类别，且不保存原始
// 内容、原始文件名、绝对路径或网络地址明文，也不提前创建通用文件管理表。
func TestAvatarMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0017_avatar.sql")
	if err != nil {
		t.Fatalf("读取头像迁移: %v", err)
	}
	sqlText := string(data)
	if count := strings.Count(sqlText, "CREATE TABLE "); count != 1 {
		t.Fatalf("0017 CREATE TABLE 数量 = %d，期望只新建 1 张表", count)
	}
	for _, want := range []string{
		"id TEXT PRIMARY KEY NOT NULL",
		"user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE",
		"storage_key TEXT NOT NULL UNIQUE",
		"media_type TEXT NOT NULL",
		"CHECK(media_type IN('image/png','image/jpeg'))",
		"byte_size INTEGER NOT NULL CHECK(byte_size > 0)",
		"width INTEGER NOT NULL CHECK(width BETWEEN 8 AND 1024)",
		"height INTEGER NOT NULL CHECK(height BETWEEN 8 AND 1024)",
		"content_sha256 BLOB NOT NULL CHECK(length(content_sha256) = 32)",
		"source_kind TEXT NOT NULL CHECK(source_kind IN('upload','network'))",
		"created_at_ms INTEGER NOT NULL",
		"updated_at_ms INTEGER NOT NULL",
	} {
		if !strings.Contains(sqlText, want) {
			t.Errorf("0017 缺少定义 %q", want)
		}
	}
	for _, index := range []string{
		"CREATE INDEX ix_avatars_created_at_ms ON avatars(created_at_ms);",
	} {
		if !strings.Contains(sqlText, index) {
			t.Errorf("0017 缺少索引 %q", index)
		}
	}
	// 原始内容、原始文件名、绝对路径、URL 明文与主动内容类型都不得落库。
	for _, forbidden := range []string{
		" original_name", " filename ", " absolute_path", " local_path",
		" data BLOB", " content BLOB", " url TEXT", " svg",
	} {
		if strings.Contains(strings.ToLower(sqlText), forbidden) {
			t.Errorf("0017 不应引入敏感/无关列 %q", forbidden)
		}
	}
	for _, future := range []string{
		"CREATE TABLE files", "CREATE TABLE uploads", "CREATE TABLE attachments",
		"CREATE TABLE documents", "CREATE TABLE storage_objects",
	} {
		if strings.Contains(sqlText, future) {
			t.Errorf("0017 提前创建了通用文件管理表 %q", future)
		}
	}
	if strings.Contains(sqlText, "TIMESTAMP") || strings.Contains(sqlText, "BOOLEAN") {
		t.Error("迁移不应使用 TIMESTAMP/BOOLEAN 类型")
	}
}
