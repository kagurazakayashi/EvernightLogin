package postgres

import (
	"context"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/lib/pq/pqerror"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage"
)

// Test TranslateRepositorySQL 的确定性翻译：占位符、幂等插入、rowid 代理列、LIKE。
func TestTranslateRepositorySQL(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    string
		wantErr string
	}{
		{
			name:  "占位符顺序转换",
			input: "SELECT id,name FROM users WHERE id=? AND status=? LIMIT ? OFFSET ?",
			want:  "SELECT id,name FROM users WHERE id=$1 AND status=$2 LIMIT $3 OFFSET $4",
		},
		{
			name:  "单引号内的问号不转换",
			input: "SELECT '?' AS q, id FROM users WHERE name=?",
			want:  "SELECT '?' AS q, id FROM users WHERE name=$1",
		},
		{
			name:  "双引号标识符不转换",
			input: `SELECT "we?ird" FROM users WHERE id=?`,
			want:  `SELECT "we?ird" FROM users WHERE id=$1`,
		},
		{
			name:  "行注释跳过",
			input: "SELECT id FROM users -- ? 不是占位符\nWHERE id=?",
			want:  "SELECT id FROM users -- ? 不是占位符\nWHERE id=$1",
		},
		{
			name:  "INSERT OR IGNORE 转 ON CONFLICT DO NOTHING",
			input: "INSERT OR IGNORE INTO password_history(user_id,password_hash,created_at_ms) VALUES(?,?,?)",
			want:  "INSERT INTO password_history(user_id,password_hash,created_at_ms) VALUES($1,$2,$3) ON CONFLICT DO NOTHING",
		},
		{
			name:  "裸 rowid 与限定 rowid 转为 _rowid",
			input: "SELECT rowid FROM password_history WHERE user_id=? ORDER BY e.rowid DESC",
			want:  "SELECT _rowid FROM password_history WHERE user_id=$1 ORDER BY e._rowid DESC",
		},
		{
			name:  "LIKE 转 ILIKE 保持 ASCII 大小写不敏感语义",
			input: `SELECT id FROM audit_events WHERE detail_json LIKE '%"field":"x"%' AND id=?`,
			want:  `SELECT id FROM audit_events WHERE detail_json ILIKE '%"field":"x"%' AND id=$1`,
		},
		{
			name:  "ON CONFLICT 目标与 excluded 保留",
			input: "INSERT INTO users(id,row_version) VALUES(?,1) ON CONFLICT(id) DO UPDATE SET row_version=excluded.row_version",
			want:  "INSERT INTO users(id,row_version) VALUES($1,1) ON CONFLICT(id) DO UPDATE SET row_version=excluded.row_version",
		},
		{
			name:    "拒绝 INSERT OR REPLACE",
			input:   "INSERT OR REPLACE INTO users(id) VALUES(?)",
			wantErr: "INSERT OR REPLACE",
		},
		{
			name:    "拒绝 json_valid",
			input:   "SELECT id FROM t WHERE json_valid(detail_json)",
			wantErr: "JSON_VALID(",
		},
		{
			name:  "RETURNING 透传（INSERT 参数编号）",
			input: "INSERT INTO one_time_credentials(id,verifier_hash) VALUES(?,?) RETURNING id",
			want:  "INSERT INTO one_time_credentials(id,verifier_hash) VALUES($1,$2) RETURNING id",
		},
		{
			name:  "RETURNING 透传（原子消费条件 UPDATE，参数编号正确）",
			input: "UPDATE one_time_credentials SET consumed_at_ms=? WHERE id=? AND consumed_at_ms IS NULL AND attempts < max_attempts RETURNING id",
			want:  "UPDATE one_time_credentials SET consumed_at_ms=$1 WHERE id=$2 AND consumed_at_ms IS NULL AND attempts < max_attempts RETURNING id",
		},
		{
			name:  "INSERT OR IGNORE + RETURNING：ON CONFLICT 必须插在 RETURNING 之前",
			input: "INSERT OR IGNORE INTO password_history(user_id,password_hash,created_at_ms) VALUES(?,?,?) RETURNING user_id",
			want:  "INSERT INTO password_history(user_id,password_hash,created_at_ms) VALUES($1,$2,$3) ON CONFLICT DO NOTHING RETURNING user_id",
		},
		{
			name:    "拒绝 AUTOINCREMENT",
			input:   "SELECT AUTOINCREMENT FROM t WHERE id=?",
			wantErr: "AUTOINCREMENT",
		},
		{
			name:    "拒绝既有的 $ 占位符（避免编号冲突）",
			input:   "SELECT id FROM users WHERE id=$1",
			wantErr: "$ 占位符",
		},
		{
			name:    "拒绝未闭合引号",
			input:   "SELECT id FROM users WHERE name='x",
			wantErr: "未闭合",
		},
		{
			name:    "拒绝 SQLite 拼接运算符",
			input:   "SELECT a||b FROM t WHERE id=?",
			wantErr: "||",
		},
		{
			name:    "拒绝 PRAGMA",
			input:   "PRAGMA foreign_keys=ON",
			wantErr: "PRAGMA",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := TranslateRepositorySQL(testCase.input)
			if testCase.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), testCase.wantErr) {
					t.Fatalf("期望错误包含 %q，实际 err=%v got=%q", testCase.wantErr, err, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("翻译失败: %v", err)
			}
			if got != testCase.want {
				t.Fatalf("翻译结果 = %q，期望 %q", got, testCase.want)
			}
		})
	}
}

// TestReturningIsNotSQLiteOnly 确认 RETURNING 不再被当作 SQLite 专有语法拒绝：
// PostgreSQL 与 SQLite 都支持它，参数编号在 RETURNING 之前保持连续。
func TestReturningIsNotSQLiteOnly(t *testing.T) {
	for _, query := range []string{
		"INSERT INTO t(a) VALUES(?) RETURNING id",
		"UPDATE t SET a=? WHERE id=? RETURNING a",
		"INSERT INTO t(a) VALUES(?) ON CONFLICT(a) DO UPDATE SET a=excluded.a RETURNING id",
	} {
		if err := CheckForbiddenSQLiteDialect(query); err != nil {
			t.Errorf("RETURNING 不应被禁用词检查拒绝: %v（SQL: %s）", err, query)
		}
		if _, err := TranslateRepositorySQL(query); err != nil {
			t.Errorf("RETURNING SQL 应可翻译: %v（SQL: %s）", err, query)
		}
	}
}

// TestTranslateDeterministic 确认同一输入两次翻译结果完全一致（驱动的语义依赖该确定性）。
func TestTranslateDeterministic(t *testing.T) {
	query := "INSERT OR IGNORE INTO t(a,b) VALUES(?,?) ON CONFLICT(a) DO UPDATE SET b=excluded.b"
	first, err := TranslateRepositorySQL(query)
	if err != nil {
		t.Fatalf("第一次翻译失败: %v", err)
	}
	for index := 0; index < 5; index++ {
		again, err := TranslateRepositorySQL(query)
		if err != nil {
			t.Fatalf("第 %d 次翻译失败: %v", index, err)
		}
		if again != first {
			t.Fatalf("翻译不确定: %q vs %q", first, again)
		}
	}
}

// TestNamedValueConversion 确认 Go 侧绑定值转换为 SQLite 存储模型对应的 PostgreSQL 值。
func TestNamedValueConversion(t *testing.T) {
	moment := time.Date(2026, 11, 20, 0, 0, 0, 0, time.FixedZone("CST", 8*3600))
	cases := []struct {
		name  string
		input driver.NamedValue
		want  interface{}
	}{
		{"true", driver.NamedValue{Value: true}, int64(1)},
		{"false", driver.NamedValue{Value: false}, int64(0)},
		{"时间转 UTC 毫秒", driver.NamedValue{Value: moment}, moment.UTC().UnixMilli()},
		{"字符串不变", driver.NamedValue{Value: "x"}, "x"},
		{"nil 不变", driver.NamedValue{Value: nil}, nil},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			value := testCase.input
			convertNamedValue(&value)
			if value.Value != testCase.want {
				t.Fatalf("转换结果 = %#v (%T)，期望 %#v (%T)", value.Value, value.Value, testCase.want, testCase.want)
			}
		})
	}
}

// TestMapError 验证 SQLSTATE -> 存储错误类别映射（静态结论，未对真实服务器逐码实测）。
func TestMapError(t *testing.T) {
	if mapError(nil) != nil {
		t.Fatal("nil 错误应返回 nil")
	}
	var contextErr error = context.DeadlineExceeded
	if !errors.Is(mapError(contextErr), context.DeadlineExceeded) {
		t.Error("上下文错误应原样返回")
	}
	if !errors.Is(mapError(driver.ErrBadConn), storage.ErrUnavailable) {
		t.Error("driver.ErrBadConn 应映射为 ErrUnavailable")
	}
	cases := []struct {
		code string
		want error
	}{
		{"23505", storage.ErrUniqueViolation},
		{"40001", storage.ErrBusy},
		{"40P01", storage.ErrBusy},
		{"55P03", storage.ErrBusy},
		{"23503", storage.ErrConstraint},
		{"23514", storage.ErrConstraint},
		{"22P02", storage.ErrConstraint},
		{"P0001", storage.ErrConstraint},
		{"42501", storage.ErrPermission},
		{"28P01", storage.ErrPermission},
		{"08006", storage.ErrUnavailable},
		{"3D000", storage.ErrUnavailable},
		{"42P01", storage.ErrUnavailable},
		{"53100", storage.ErrDiskFull},
		{"22P05", storage.ErrUnavailable},
		{"42601", storage.ErrUnavailable},
	}
	for _, testCase := range cases {
		mapped := mapError(&pq.Error{Code: pqerror.Code(testCase.code)})
		if !errors.Is(mapped, testCase.want) {
			t.Errorf("SQLSTATE %s 映射 = %v，期望 %v", testCase.code, mapped, testCase.want)
		}
		if mapped.Error() == "" || strings.Contains(mapped.Error(), "pq:") {
			t.Errorf("SQLSTATE %s 的公开文本不应包含驱动细节: %q", testCase.code, mapped.Error())
		}
	}
	// 未归类错误不得暴露原始驱动文本。
	raw := &pq.Error{Code: pqerror.Code("XX999"), Message: "secret detail should not leak"}
	if strings.Contains(mapError(raw).Error(), "secret") {
		t.Error("公开错误文本泄漏了原始驱动错误")
	}
}

// TestOptionsValidate 校验配置默认值与 TLS fail-closed 策略。
func TestOptionsValidate(t *testing.T) {
	if _, err := (Options{}).validate(); err == nil {
		t.Fatal("空配置必须被拒绝")
	}
	base := DefaultOptions("127.0.0.1", "login", "login")
	normalized, err := base.validate()
	if err != nil {
		t.Fatalf("默认配置应合法: %v", err)
	}
	if normalized.SSLMode != "verify-full" {
		t.Fatalf("默认 SSLMode = %q，期望 verify-full", normalized.SSLMode)
	}
	if normalized.Port != DefaultPort || normalized.MaxOpenConns != DefaultMaxOpenConns {
		t.Fatalf("默认值未补齐: %+v", normalized)
	}
	// 低于 verify-full 的模式必须显式 AllowInsecure。
	for _, mode := range []string{"disable", "allow", "prefer", "require", "verify-ca"} {
		candidate := base
		candidate.SSLMode = mode
		if _, err := candidate.validate(); err == nil {
			t.Errorf("sslmode=%s 未显式 AllowInsecure 时应拒绝", mode)
		}
		candidate.AllowInsecure = true
		if _, err := candidate.validate(); err != nil {
			t.Errorf("sslmode=%s + AllowInsecure=true 应接受: %v", mode, err)
		}
	}
	for _, mode := range []string{"verify-full", ""} {
		candidate := base
		candidate.SSLMode = mode
		if _, err := candidate.validate(); err != nil {
			t.Errorf("sslmode=%q 应接受: %v", mode, err)
		}
	}
	invalid := base
	invalid.SSLMode = "bogus"
	if _, err := invalid.validate(); err == nil {
		t.Error("非法 sslmode 必须被拒绝")
	}
	invalid = base
	invalid.MaxOpenConns = MaxAllowedOpenConns + 1
	if _, err := invalid.validate(); err == nil {
		t.Error("超过连接池上限必须被拒绝")
	}
	invalid = base
	invalid.Port = 70000
	if _, err := invalid.validate(); err == nil {
		t.Error("非法端口必须被拒绝")
	}
	invalid = base
	invalid.Host = "bad host!"
	if _, err := invalid.validate(); err == nil {
		t.Error("非法主机名必须被拒绝")
	}
}

// TestSearchPathSafe 确认 search_path 收紧策略。
func TestSearchPathSafe(t *testing.T) {
	cases := []struct {
		value string
		safe  bool
	}{
		{"public", true},
		{`public, pg_catalog`, true},
		{`"public"`, true},
		{`"$user", public`, false},
		{"public, attacker_schema", false},
		{"attacker_schema, public", false},
		{"", false},
	}
	for _, testCase := range cases {
		if got := searchPathSafe(testCase.value); got != testCase.safe {
			t.Errorf("searchPathSafe(%q) = %v，期望 %v", testCase.value, got, testCase.safe)
		}
	}
}

// TestBackupCapabilityUnsupported 确认在线备份能力如实声明不支持，且不造假备份。
func TestBackupCapabilityUnsupported(t *testing.T) {
	store := &Store{}
	capability := store.BackupCapability()
	if capability.Supported {
		t.Fatal("PostgreSQL 在线备份本版本必须声明不支持")
	}
	if capability.Limitation == "" || capability.Mechanism == "" || capability.Unverified == "" {
		t.Fatal("备份能力声明必须说明机制、限制与未验证范围")
	}
	if err := store.CreateOnlineBackup(context.Background(), "target"); !errors.Is(err, ErrOnlineBackupUnsupported) {
		t.Fatalf("CreateOnlineBackup 应返回 ErrOnlineBackupUnsupported，实际 %v", err)
	}
	if err := store.RestoreOnlineBackup(context.Background(), "source"); !errors.Is(err, ErrOnlineBackupUnsupported) {
		t.Fatalf("RestoreOnlineBackup 应返回 ErrOnlineBackupUnsupported，实际 %v", err)
	}
}

// TestMigrationLockKey 确认 advisory lock 键确定、稳定且为正数。
func TestMigrationLockKey(t *testing.T) {
	first := (&Store{options: Options{Database: "login"}}).MigrationLockKey()
	second := (&Store{options: Options{Database: "login"}}).MigrationLockKey()
	other := (&Store{options: Options{Database: "login2"}}).MigrationLockKey()
	if first <= 0 || other <= 0 {
		t.Fatalf("advisory lock 键必须为正数: %d/%d", first, other)
	}
	if first != second {
		t.Fatal("同一数据库的 lock 键必须确定")
	}
	if first == other {
		t.Fatal("不同数据库不应共享同一把迁移锁")
	}
}
