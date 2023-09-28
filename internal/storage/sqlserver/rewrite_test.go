package sqlserver

import (
	"database/sql/driver"
	"net/url"
	"strings"
	"testing"
	"time"
)

func testResolver(table string) ([]string, error) {
	switch table {
	case "password_history":
		return []string{"user_id", "password_hash"}, nil
	case "backup_jobs":
		return []string{"job_id"}, nil
	}
	return nil, nil
}

// TestPlaceholderTranslation 覆盖 ? -> @p1..@pn、引号/注释/方括号跳过与既有参数拒绝。
func TestPlaceholderTranslation(t *testing.T) {
	translated, err := TranslateRepositorySQL(
		"SELECT id, '?' AS literal, [weird?name] FROM t WHERE a=? AND b=? -- ? in comment\n", testResolver)
	if err != nil {
		t.Fatalf("翻译失败: %v", err)
	}
	for _, want := range []string{"@p1", "@p2", "'?'", "[weird?name]", "-- ? in comment"} {
		if !strings.Contains(translated, want) {
			t.Errorf("翻译结果缺少 %q：%s", want, translated)
		}
	}
	if _, err := TranslateRepositorySQL("SELECT id FROM t WHERE id=@p1", testResolver); err == nil {
		t.Error("既有 @ 参数应被拒绝（编号冲突）")
	}
	if _, err := TranslateRepositorySQL("SELECT id FROM t WHERE id=$1", testResolver); err == nil {
		t.Error("既有 $ 占位符应被拒绝")
	}
	// 字符串/注释里形似 @pN 的文本不得被参数序列校验误判为真实参数。
	translated, err = TranslateRepositorySQL("SELECT id FROM t WHERE note='@p9' AND id=? -- @p7\n", testResolver)
	if err != nil {
		t.Fatalf("字符串/注释中的 @pN 文本被误判为参数: %v", err)
	}
	if !strings.Contains(translated, "'@p9'") || !strings.Contains(translated, "-- @p7") {
		t.Errorf("字符串/注释中的 @pN 文本不应被改写：%s", translated)
	}
}

// TestUpsertTranslation 覆盖 ON CONFLICT DO NOTHING/DO UPDATE -> MERGE。
func TestUpsertTranslation(t *testing.T) {
	cases := []struct {
		name  string
		query string
		wants []string
	}{
		{
			name: "do nothing",
			query: `INSERT INTO users(id,username,username_normalized) VALUES(?,?,?)
ON CONFLICT(username_normalized) DO NOTHING`,
			wants: []string{
				"MERGE INTO [users] WITH (HOLDLOCK) AS target",
				"ON target.[username_normalized] = source.[username_normalized]",
				"WHEN NOT MATCHED THEN INSERT ([id], [username], [username_normalized])",
				"VALUES (source.[id], source.[username], source.[username_normalized]);",
			},
		},
		{
			name: "do update with excluded and row_version",
			query: `INSERT INTO password_credentials(user_id,hash_scheme,row_version,updated_at_ms)
VALUES(?,?,1,?) ON CONFLICT(user_id) DO UPDATE SET hash_scheme=excluded.hash_scheme,
row_version=password_credentials.row_version+1, updated_at_ms=excluded.updated_at_ms`,
			wants: []string{
				"WHEN MATCHED THEN UPDATE SET",
				"[hash_scheme] = source.[hash_scheme]",
				"[row_version] = target.[row_version]+1",
				"[updated_at_ms] = source.[updated_at_ms]",
			},
		},
		{
			// 步骤 210 N1：冲突目标带 partial unique index 的 WHERE 谓词时必须翻译为
			// MERGE（谓词只服务 SQLite 索引选择），并保留 delivery_id 的保旧语义。
			name: "conflict target WHERE with delivery preservation",
			query: `INSERT INTO security_notifications(id,dedup_key,delivery_id) VALUES(?,?,?)
ON CONFLICT(dedup_key) WHERE dedup_key IS NOT NULL DO UPDATE SET
delivery_id=COALESCE(excluded.delivery_id, delivery_id)`,
			wants: []string{
				"WHEN MATCHED THEN UPDATE SET",
				"[delivery_id] = COALESCE(source.[delivery_id], target.[delivery_id])",
			},
		},
		{
			name: "insert select",
			query: `INSERT INTO group_members(group_id,user_id,created_at_ms)
SELECT ?,?,? WHERE EXISTS(SELECT 1 FROM users WHERE id=? AND status='active')
ON CONFLICT(group_id,user_id) DO NOTHING`,
			wants: []string{
				"SELECT @p1 AS [group_id], @p2 AS [user_id], @p3 AS [created_at_ms] WHERE EXISTS",
				"ON target.[group_id] = source.[group_id] AND target.[user_id] = source.[user_id]",
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			translated, err := TranslateRepositorySQL(testCase.query, testResolver)
			if err != nil {
				t.Fatalf("翻译失败: %v", err)
			}
			for _, want := range testCase.wants {
				if !strings.Contains(translated, want) {
					t.Errorf("翻译结果缺少 %q：\n%s", want, translated)
				}
			}
			if strings.Contains(translated, "ON CONFLICT") || strings.Contains(translated, "excluded.") {
				t.Errorf("翻译结果仍含 SQLite upsert 语法：\n%s", translated)
			}
		})
	}
	// DO UPDATE ... WHERE 未实现翻译，必须 fail-closed。
	if _, err := TranslateRepositorySQL(
		`INSERT INTO t(a,b) VALUES(?,?) ON CONFLICT(a) DO UPDATE SET b=excluded.b WHERE b IS NULL`, testResolver); err == nil {
		t.Error("ON CONFLICT DO UPDATE ... WHERE 应明确拒绝")
	}
}

// TestInsertOrIgnoreTranslation 覆盖 INSERT OR IGNORE -> MERGE（冲突键来自迁移主键）。
func TestInsertOrIgnoreTranslation(t *testing.T) {
	translated, err := TranslateRepositorySQL(
		`INSERT OR IGNORE INTO backup_jobs(job_id,kind,origin,created_at_ms) VALUES(?,?,?,?)`, testResolver)
	if err != nil {
		t.Fatalf("翻译失败: %v", err)
	}
	if !strings.Contains(translated, "MERGE INTO [backup_jobs]") ||
		!strings.Contains(translated, "ON target.[job_id] = source.[job_id]") {
		t.Errorf("INSERT OR IGNORE 未翻译为带主键 ON 条件的 MERGE：\n%s", translated)
	}
	if _, err := TranslateRepositorySQL(`INSERT OR IGNORE INTO backup_jobs(job_id) VALUES(?)`, nil); err == nil {
		t.Error("缺少冲突键解析器时应 fail-closed")
	}
}

// TestRowidAndLimitTranslation 覆盖 rowid 代理列与 LIMIT/OFFSET 分页。
func TestRowidAndLimitTranslation(t *testing.T) {
	translated, err := TranslateRepositorySQL(
		`DELETE FROM password_history WHERE user_id=? AND rowid NOT IN (
SELECT rowid FROM password_history WHERE user_id=? ORDER BY created_at_ms DESC,rowid DESC LIMIT ?)`, testResolver)
	if err != nil {
		t.Fatalf("翻译失败: %v", err)
	}
	for _, want := range []string{"[_rowid]", "OFFSET 0 ROWS FETCH NEXT @p3 ROWS ONLY"} {
		if !strings.Contains(translated, want) {
			t.Errorf("rowid/LIMIT 翻译缺少 %q：%s", want, translated)
		}
	}
	if strings.Contains(strings.ToLower(translated), "rowid") && !strings.Contains(translated, "[_rowid]") {
		t.Errorf("翻译后仍含裸 rowid：%s", translated)
	}

	for _, testCase := range []struct {
		query string
		want  string
	}{
		{"SELECT id FROM t WHERE x=? ORDER BY created_at_ms DESC LIMIT ? OFFSET ?", "OFFSET @p3 ROWS FETCH NEXT @p2 ROWS ONLY"},
		{"SELECT id FROM t WHERE x=? LIMIT 1", "ORDER BY (SELECT NULL) OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY"},
		{"SELECT COUNT(*) FROM (SELECT 1 FROM t WHERE x=? LIMIT ?)", "OFFSET 0 ROWS FETCH NEXT @p2 ROWS ONLY"},
	} {
		translated, err := TranslateRepositorySQL(testCase.query, nil)
		if err != nil {
			t.Fatalf("翻译失败（%s）: %v", testCase.query, err)
		}
		if !strings.Contains(translated, testCase.want) {
			t.Errorf("LIMIT 翻译缺少 %q：\n%s", testCase.want, translated)
		}
	}
	if _, err := TranslateRepositorySQL("SELECT id FROM t LIMIT -1", nil); err == nil {
		t.Error("LIMIT -1（SQLite 不限行数）未实现翻译，应 fail-closed")
	}
}

// TestReturningRegisteredAsGap 验证 RETURNING 被登记为 T-SQL OUTPUT 缺口，而不是被
// 误标为 SQLite 语法；INSERT/upsert 改写不得静默丢弃 RETURNING。
func TestReturningRegisteredAsGap(t *testing.T) {
	for _, query := range []string{
		"UPDATE t SET a=? WHERE id=? RETURNING id",
		"INSERT INTO t(a,b) VALUES(?,?) RETURNING id",
		"INSERT OR IGNORE INTO backup_jobs(job_id) VALUES(?) RETURNING job_id",
		"INSERT INTO users(id) VALUES(?) ON CONFLICT(id) DO NOTHING RETURNING id",
		"INSERT INTO users(id) VALUES(?) ON CONFLICT(id) DO UPDATE SET id=excluded.id RETURNING id",
		"INSERT INTO t(a) SELECT ? FROM t2 RETURNING a",
	} {
		_, err := TranslateRepositorySQL(query, testResolver)
		if err == nil {
			t.Errorf("RETURNING 应 fail-closed（不得静默丢弃）：%s", query)
			continue
		}
		message := err.Error()
		if !strings.Contains(message, "OUTPUT") {
			t.Errorf("错误信息应说明 T-SQL 需要 OUTPUT，实际：%v（SQL: %s）", err, query)
		}
		if strings.Contains(message, "SQLite 语法") {
			t.Errorf("RETURNING 不是 SQLite 专有语法，不应误标：%v（SQL: %s）", err, query)
		}
	}
	// 非 RETURNING 的意外尾随子句同样必须显式报错，不能被 upsert 改写静默丢弃。
	if _, err := TranslateRepositorySQL("INSERT OR IGNORE INTO backup_jobs(job_id) VALUES(?) FOO BAR", testResolver); err == nil {
		t.Error("INSERT OR IGNORE 的意外尾随子句应显式报错")
	}
	if _, err := TranslateRepositorySQL("INSERT INTO t(a) VALUES(?) ON CONFLICT(a) DO NOTHING FOO", testResolver); err == nil {
		t.Error("ON CONFLICT DO NOTHING 的意外尾随子句应显式报错")
	}
}

// TestForbiddenSyntax 验证无法等价翻译的 SQLite 专有语法全部 fail-closed。
func TestForbiddenSyntax(t *testing.T) {
	for _, query := range []string{
		"SELECT json_extract(a,'$.x') FROM t",
		"SELECT json_valid(a) FROM t",
		"INSERT OR REPLACE INTO t(a) VALUES(?)",
		"SELECT strftime('%s','now') FROM t",
		"SELECT a||b FROM t",
		"SELECT IFNULL(a,b) FROM t",
		"SELECT IFNULL(a,b) FROM t",
		"SELECT a FROM t WITHOUT ROWID",
		"PRAGMA foreign_keys",
		"SELECT a FROM t WHERE a GLOB 'x*'",
	} {
		if _, err := TranslateRepositorySQL(query, testResolver); err == nil {
			t.Errorf("无法等价翻译的 SQLite 语法应被拒绝：%s", query)
		}
	}
	if err := CheckForbiddenSQLiteDialect("SELECT json_valid(x) FROM t"); err == nil {
		t.Error("禁用词检查应拒绝 json_valid")
	}
	if err := CheckForbiddenSQLiteDialect("SELECT id FROM t WHERE id=?"); err != nil {
		t.Errorf("标准 SQL 不应被禁用词检查拒绝: %v", err)
	}
}

// TestTranslateDeterministic 验证翻译是确定性的（同样输入同样输出）。
func TestTranslateDeterministic(t *testing.T) {
	query := "INSERT INTO t(a,b) VALUES(?,?) ON CONFLICT(a) DO UPDATE SET b=excluded.b"
	first, err := TranslateRepositorySQL(query, testResolver)
	if err != nil {
		t.Fatalf("翻译失败: %v", err)
	}
	for round := 0; round < 5; round++ {
		translated, err := TranslateRepositorySQL(query, testResolver)
		if err != nil || translated != first {
			t.Fatalf("翻译不确定（第 %d 轮）: %v\n%s\n%s", round, err, first, translated)
		}
	}
}

// TestNamedValueConversion 验证 bool->0/1、time.Time->UTC 毫秒绑定值转换。
func TestNamedValueConversion(t *testing.T) {
	boolValue := driver.NamedValue{Ordinal: 1, Value: true}
	convertNamedValue(&boolValue)
	if boolValue.Value != int64(1) {
		t.Errorf("bool true 应转换为 int64(1)，实际 %#v", boolValue.Value)
	}
	moment := time.Date(2026, 11, 20, 1, 2, 3, 0, time.FixedZone("x", 8*3600))
	timeValue := driver.NamedValue{Ordinal: 2, Value: moment}
	convertNamedValue(&timeValue)
	if timeValue.Value != moment.UTC().UnixMilli() {
		t.Errorf("time.Time 应转换为 UTC 毫秒，实际 %#v", timeValue.Value)
	}
}

// TestOptionsValidation 覆盖传输安全默认值与弱化必须显式 AllowInsecure 的规则。
func TestOptionsValidation(t *testing.T) {
	base := DefaultOptions("127.0.0.1", "sa", "login")
	if _, err := base.validate(); err != nil {
		t.Fatalf("默认配置应合法: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*Options)
		ok     bool
	}{
		{"默认强制加密", func(o *Options) {}, true},
		{"trust 未显式允许", func(o *Options) { o.TrustServerCertificate = true }, false},
		{"trust 显式允许本地测试", func(o *Options) { o.AllowInsecure = true; o.TrustServerCertificate = true }, true},
		{"禁用加密未显式允许", func(o *Options) { o.DisableEncryption = true }, false},
		{"禁用加密显式允许本地测试", func(o *Options) { o.AllowInsecure = true; o.DisableEncryption = true }, true},
		{"禁用加密同时信任证书", func(o *Options) {
			o.AllowInsecure = true
			o.DisableEncryption = true
			o.TrustServerCertificate = true
		}, false},
		{"TLS 1.1 始终拒绝", func(o *Options) { o.AllowInsecure = true; o.TLSMinVersion = "1.1" }, false},
		{"TLS 1.3 允许", func(o *Options) { o.TLSMinVersion = "1.3" }, true},
		{"证书二选一", func(o *Options) { o.CACertificate = "ca.pem"; o.ServerCertificate = "srv.pem" }, false},
		{"空主机拒绝", func(o *Options) { o.Host = "" }, false},
		{"超大连接池拒绝", func(o *Options) { o.MaxOpenConns = 100 }, false},
		{"数据库名不能为空", func(o *Options) { o.Database = "" }, false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			options := base
			testCase.mutate(&options)
			_, err := options.validate()
			if testCase.ok && err != nil {
				t.Errorf("应通过校验，实际错误: %v", err)
			}
			if !testCase.ok && err == nil {
				t.Error("应拒绝该配置，实际通过")
			}
		})
	}
}

// TestBuildMSSQLConfigDefaults 验证默认 DSN 强制加密、完整证书校验、TLS≥1.2，且密码
// 只进入驱动配置（不进入 DSN 字符串）。
func TestBuildMSSQLConfigDefaults(t *testing.T) {
	options := DefaultOptions("db.example", "login_user", "login")
	options.Password = "super-secret-value"
	normalized, err := options.validate()
	if err != nil {
		t.Fatalf("默认配置应合法: %v", err)
	}
	config, err := buildMSSQLConfig(normalized)
	if err != nil {
		t.Fatalf("构造配置失败: %v", err)
	}
	if config.Encryption == 0 {
		t.Error("默认必须启用加密（encrypt=true）")
	}
	if config.TrustServerCertificate {
		t.Error("默认必须校验服务器证书（trustservercertificate=false）")
	}
	if config.Password != "super-secret-value" {
		t.Error("密码应只放在驱动配置中")
	}
	if config.TLSConfig != nil && config.TLSConfig.MinVersion < 0x0303 {
		t.Errorf("默认 TLS 版本应 ≥1.2（0x0303），实际 %#x", config.TLSConfig.MinVersion)
	}
	// 构造的 DSN 字符串不得包含密码（密码只放 Config.Password）。
	values := url.Values{}
	values.Set("database", normalized.Database)
	dsn := buildMSSQLDSN(normalized, values)
	if strings.Contains(dsn, "super-secret-value") {
		t.Errorf("连接 DSN 不应包含密码: %s", dsn)
	}
}

// TestMigrationLockName 验证 applock 资源名长度/前缀/确定性。
func TestMigrationLockName(t *testing.T) {
	store := &Store{options: DefaultOptions("db", "u", "login")}
	name := store.MigrationLockName()
	if !strings.HasPrefix(name, migrationLockPrefix+"login:") {
		t.Errorf("锁资源名前缀/数据库名不符合预期: %s", name)
	}
	if len(name) > migrationLockResourceMax {
		t.Errorf("锁资源名超过 255 字符: %d", len(name))
	}
	other := &Store{options: DefaultOptions("db", "u", "other")}
	if other.MigrationLockName() == name {
		t.Error("不同数据库应得到不同锁资源名")
	}
}
