package mysql

import (
	"errors"
	"strings"
	"testing"

	gomysql "github.com/go-sql-driver/mysql"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage"
)

// TestTranslateRepositorySQL 覆盖仓储实际使用的 SQLite 方言与拒绝路径。
func TestTranslateRepositorySQL(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name: "DO NOTHING 转幂等 UPDATE",
			input: "INSERT INTO users(id,username,username_normalized) VALUES(?,?,?)" +
				"ON CONFLICT(username_normalized) DO NOTHING",
			want: "INSERT INTO users(id,username,username_normalized) VALUES(?,?,?)" +
				"ON DUPLICATE KEY UPDATE `id`=`id`",
		},
		{
			name: "DO UPDATE 转 VALUES()",
			input: "INSERT INTO password_credentials(user_id,password_hash,row_version)" +
				" VALUES(?,?,1) ON CONFLICT(user_id) DO UPDATE SET password_hash=excluded.password_hash," +
				"row_version=password_credentials.row_version+1",
			want: "INSERT INTO password_credentials(user_id,password_hash,row_version)" +
				" VALUES(?,?,1) ON DUPLICATE KEY UPDATE `password_hash`=VALUES(`password_hash`), " +
				"`row_version`=row_version+1",
		},
		{
			name:  "INSERT OR IGNORE",
			input: "INSERT OR IGNORE INTO password_history(user_id,password_hash) VALUES(?,?)",
			want:  "INSERT IGNORE INTO password_history(user_id,password_hash) VALUES(?,?)",
		},
		{
			name:  "裸 rowid 替换",
			input: "DELETE FROM password_history WHERE user_id=? AND rowid NOT IN (SELECT rowid FROM password_history WHERE user_id=? ORDER BY created_at_ms DESC,rowid DESC LIMIT ?)",
			want:  "DELETE FROM password_history WHERE user_id=? AND _rowid NOT IN (SELECT * FROM (SELECT _rowid FROM password_history WHERE user_id=? ORDER BY created_at_ms DESC,_rowid DESC LIMIT ?) AS _subq1)",
		},
		{
			name:  "普通 SQL 原样返回",
			input: "SELECT id FROM users WHERE id=? LIMIT ? OFFSET ?",
			want:  "SELECT id FROM users WHERE id=? LIMIT ? OFFSET ?",
		},
		{
			name:    "INSERT OR REPLACE 明确拒绝",
			input:   "INSERT OR REPLACE INTO users(id) VALUES(?)",
			wantErr: true,
		},
		{
			name:    "未知 SQLite 方言拒绝",
			input:   "SELECT strftime('%s','now')",
			wantErr: true,
		},
		{
			name:    "RETURNING 拒绝",
			input:   "DELETE FROM users WHERE id=? RETURNING id",
			wantErr: true,
		},
		{
			name:    "json_extract 拒绝",
			input:   "SELECT json_extract(detail_json,'$.a') FROM audit_events",
			wantErr: true,
		},
		{
			name:    "GLOB 拒绝",
			input:   "SELECT id FROM users WHERE username GLOB 'a*'",
			wantErr: true,
		},
		{
			name:    "PRAGMA 拒绝",
			input:   "PRAGMA foreign_keys",
			wantErr: true,
		},
		{
			name:    "拼接运算符拒绝",
			input:   "SELECT id || '-suffix' FROM users",
			wantErr: true,
		},
		{
			name:  "字符串内容含禁用词不拒绝",
			input: "SELECT id FROM users WHERE username='a||b RETURNING'",
			want:  "SELECT id FROM users WHERE username='a||b RETURNING'",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := TranslateRepositorySQL(testCase.input)
			if testCase.wantErr {
				if err == nil {
					t.Fatalf("期望翻译失败，实际得到 %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("翻译失败: %v", err)
			}
			if got != testCase.want {
				t.Fatalf("翻译结果:\n got  %q\n want %q", got, testCase.want)
			}
		})
	}
}

// TestMapError 覆盖 MySQL 错误码分类；这是静态映射，未对真实服务器逐码实测。
func TestMapError(t *testing.T) {
	cases := []struct {
		number int
		want   error
	}{
		{1062, storage.ErrUniqueViolation},
		{1213, storage.ErrBusy},
		{1205, storage.ErrBusy},
		{1452, storage.ErrConstraint},
		{1451, storage.ErrConstraint},
		{3819, storage.ErrConstraint},
		{1644, storage.ErrConstraint},
		{1044, storage.ErrPermission},
		{1045, storage.ErrPermission},
		{1040, storage.ErrUnavailable},
		{1146, storage.ErrUnavailable},
		{9999, storage.ErrUnavailable},
	}
	for _, testCase := range cases {
		mapped := mapError(&gomysql.MySQLError{Number: uint16(testCase.number), Message: "secret raw detail"})
		if !errors.Is(mapped, testCase.want) {
			t.Fatalf("错误码 %d 映射 = %v，期望 %v", testCase.number, mapped, testCase.want)
		}
		if strings.Contains(mapped.Error(), "secret") {
			t.Fatalf("错误码 %d 的公开文本泄漏了驱动原文", testCase.number)
		}
	}
}

// TestBackupCapabilityUnsupported 确认 MySQL 在线备份明确不支持且不生成假备份。
func TestBackupCapabilityUnsupported(t *testing.T) {
	store := &Store{}
	capability := store.BackupCapability()
	if capability.Supported {
		t.Fatal("未实现 MySQL 在线备份，Supported 不得为 true")
	}
	if capability.Limitation == "" || capability.Mechanism == "" {
		t.Fatal("备份能力声明必须说明机制与限制")
	}
	if err := store.CreateOnlineBackup(t.Context(), "C:\\tmp\\x"); !errors.Is(err, ErrOnlineBackupUnsupported) {
		t.Fatalf("CreateOnlineBackup 错误 = %v，期望 ErrOnlineBackupUnsupported", err)
	}
	if err := store.RestoreOnlineBackup(t.Context(), "C:\\tmp\\x"); !errors.Is(err, ErrOnlineBackupUnsupported) {
		t.Fatalf("RestoreOnlineBackup 错误 = %v，期望 ErrOnlineBackupUnsupported", err)
	}
}

// TestOptionsValidate 覆盖配置边界：拒绝空主机/端口越界/连接池越界/非法 TLS。
func TestOptionsValidate(t *testing.T) {
	valid := DefaultOptions("127.0.0.1", "login", "evernight")
	if _, err := valid.validate(); err != nil {
		t.Fatalf("默认配置应合法: %v", err)
	}
	bad := []Options{
		{Host: "", User: "u", Database: "d"},
		{Host: "127.0.0.1", User: "", Database: "d"},
		{Host: "127.0.0.1", User: "u", Database: ""},
		{Host: "127.0.0.1", Port: 70000, User: "u", Database: "d"},
		{Host: "127.0.0.1", User: "u", Database: "d", MaxOpenConns: MaxAllowedOpenConns + 1},
		{Host: "127.0.0.1", User: "u", Database: "d", TLS: "bad tls"},
		{Host: "127.0.0.1", User: "u", Database: "d", TLS: ""},
		{Host: "127.0.0.1", User: "u", Database: "d", TLS: "skip-verify"},
		{Host: "127.0.0.1", User: "u", Database: "d", TLS: "preferred"},
	}
	for index, options := range bad {
		if _, err := options.validate(); err == nil {
			t.Fatalf("第 %d 个非法配置未被拒绝: %+v", index, options)
		}
	}
	// 本地明文/跳过校验必须显式 AllowInsecure，且文档标明仅本地测试。
	for _, tls := range []string{"", "skip-verify", "preferred"} {
		options := DefaultOptions("127.0.0.1", "u", "d")
		options.TLS = tls
		options.AllowInsecure = true
		if _, err := options.validate(); err != nil {
			t.Fatalf("AllowInsecure=true 时 TLS=%q 应可用: %v", tls, err)
		}
	}
	// 默认必须要求 TLS。
	if !strings.EqualFold(DefaultOptions("127.0.0.1", "u", "d").TLS, "true") {
		t.Fatal("默认配置必须要求 TLS")
	}
}
