package migrate

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	appmigrations "github.com/kagurazakayashi/EvernightLogin/migrations"
)

func TestLoadMigrations(t *testing.T) {
	files := fstest.MapFS{
		"0002_second_step.sql": {
			Data: []byte("-- 普通说明注释\nCREATE TABLE second (id TEXT);\nCREATE TABLE second_more (id TEXT);\n"),
		},
		"0001_first_step.sql": {
			Data: []byte("-- +migrate non-transactional\nCREATE TABLE first (id TEXT);\n"),
		},
		"0003_whole_file.sql": {
			Data: []byte("-- +migrate whole-file\nCREATE TRIGGER sample BEFORE INSERT ON first BEGIN SELECT 1; END;\n"),
		},
		"README.md": {Data: []byte("忽略非 SQL 文件")},
	}
	migrations, err := LoadMigrations(files)
	if err != nil {
		t.Fatalf("LoadMigrations() 失败：%v", err)
	}
	if len(migrations) != 3 {
		t.Fatalf("迁移数量 = %d，期望 3", len(migrations))
	}

	if migrations[0].Version != "0001" || migrations[0].Description != "first step" {
		t.Errorf("第一项 = %+v", migrations[0])
	}
	if !migrations[0].NonTransactional {
		t.Error("0001 应标记为非事务迁移")
	}
	if len(migrations[0].Statements) != 1 {
		t.Errorf("0001 语句数 = %d", len(migrations[0].Statements))
	}
	if migrations[1].Version != "0002" || migrations[1].NonTransactional {
		t.Errorf("第二项 = %+v", migrations[1])
	}
	if len(migrations[1].Statements) != 2 {
		t.Errorf("0002 语句数 = %d，期望 2", len(migrations[1].Statements))
	}
	if len(migrations[2].Statements) != 1 {
		t.Errorf("whole-file 迁移语句数 = %d，期望 1", len(migrations[2].Statements))
	}
	if len(migrations[0].Checksum) != 64 {
		t.Errorf("校验和长度 = %d，期望 64", len(migrations[0].Checksum))
	}
	if migrations[0].Checksum == migrations[1].Checksum {
		t.Error("不同内容应产生不同校验和")
	}
}

func TestLoadMigrationsChecksumChangesWithContent(t *testing.T) {
	first, err := LoadMigrations(fstest.MapFS{
		"0001_test.sql": {Data: []byte("CREATE TABLE a (id TEXT);\n")},
	})
	if err != nil {
		t.Fatalf("LoadMigrations() 失败：%v", err)
	}
	second, err := LoadMigrations(fstest.MapFS{
		"0001_test.sql": {Data: []byte("CREATE TABLE a (id TEXT); -- 改注释\n")},
	})
	if err != nil {
		t.Fatalf("LoadMigrations() 失败：%v", err)
	}
	if first[0].Checksum == second[0].Checksum {
		t.Error("即使只改注释，校验和也应变化")
	}
}

func TestLoadMigrationsRejectsInvalid(t *testing.T) {
	cases := []struct {
		name    string
		files   fstest.MapFS
		wantErr error
	}{
		{
			name:    "文件名不合法",
			files:   fstest.MapFS{"1_bad.sql": {Data: []byte("SELECT 1;")}},
			wantErr: ErrInvalidMigration,
		},
		{
			name: "版本重复",
			files: fstest.MapFS{
				"0001_a.sql": {Data: []byte("SELECT 1;")},
				"0001_b.sql": {Data: []byte("SELECT 2;")},
			},
			wantErr: ErrDuplicateMigrationVersion,
		},
		{
			name:    "未知指令",
			files:   fstest.MapFS{"0001_bad.sql": {Data: []byte("-- +migrate mystery\nSELECT 1;")}},
			wantErr: ErrInvalidMigration,
		},
		{
			name:    "没有 SQL",
			files:   fstest.MapFS{"0001_empty.sql": {Data: []byte("-- 只有注释\n")}},
			wantErr: ErrInvalidMigration,
		},
		{
			name:    "字符串未闭合",
			files:   fstest.MapFS{"0001_broken.sql": {Data: []byte("SELECT 'unterminated;")}},
			wantErr: ErrInvalidMigration,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := LoadMigrations(test.files)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("错误 = %v，期望 errors.Is(%v)", err, test.wantErr)
			}
		})
	}

	if _, err := LoadMigrations(nil); !errors.Is(err, ErrInvalidMigration) {
		t.Errorf("nil 文件系统错误 = %v", err)
	}
}

func TestSplitStatements(t *testing.T) {
	script := `
CREATE TABLE things (id TEXT, note TEXT DEFAULT 'semi;colon');
-- 行注释中;的分号不切分
INSERT INTO things VALUES('a;b', "column;name");
/* 块注释 ; 不切分 */
UPDATE things SET note = 'it''s; ok' WHERE id = [weird;name];
`
	statements, err := SplitStatements(script)
	if err != nil {
		t.Fatalf("SplitStatements() 失败：%v", err)
	}
	if len(statements) != 3 {
		t.Fatalf("语句数 = %d，期望 3：%#v", len(statements), statements)
	}
	if !strings.Contains(statements[0], "'semi;colon'") {
		t.Errorf("第一句字符串内容被破坏：%q", statements[0])
	}
	if !strings.Contains(statements[1], "'a;b'") || !strings.Contains(statements[1], `"column;name"`) {
		t.Errorf("第二句引号内容被破坏：%q", statements[1])
	}
	if !strings.Contains(statements[2], "'it''s; ok'") || !strings.Contains(statements[2], "[weird;name]") {
		t.Errorf("第三句转义内容被破坏：%q", statements[2])
	}
	for _, statement := range statements {
		if strings.Contains(statement, "--") || strings.Contains(statement, "/*") {
			t.Errorf("语句中不应包含注释：%q", statement)
		}
	}
}

func TestSplitStatementsErrors(t *testing.T) {
	cases := []string{
		"SELECT 'unterminated",
		"SELECT \"unterminated",
		"SELECT `unterminated",
		"SELECT [unterminated",
		"SELECT 1; /* unterminated",
	}
	for _, script := range cases {
		if _, err := SplitStatements(script); err == nil {
			t.Errorf("SplitStatements(%q) 应失败", script)
		}
	}

	statements, err := SplitStatements("-- 只有注释\n/* 也是注释 */\n")
	if err != nil {
		t.Fatalf("纯注释脚本不应报错：%v", err)
	}
	if len(statements) != 0 {
		t.Errorf("纯注释脚本语句数 = %d", len(statements))
	}
}

func TestLoadEmbeddedMigrations(t *testing.T) {
	migrations, err := LoadMigrations(appmigrations.SQLite)
	if err != nil {
		t.Fatalf("加载内嵌迁移失败：%v", err)
	}
	// 期望数量从同一嵌入迁移源动态计算，避免新增迁移后硬编码计数/版本清单漂移；
	// 保留结构性断言：数量=嵌入 SQL 文件数、版本严格升序且唯一、四位数字编号、
	// 每项有可执行语句与合法校验和、首项为 0001。
	files, err := fs.Glob(appmigrations.SQLite, "*.sql")
	if err != nil {
		t.Fatalf("枚举嵌入迁移文件失败：%v", err)
	}
	if len(migrations) != len(files) {
		t.Fatalf("内嵌迁移数量 = %d，期望嵌入 SQL 文件数 %d", len(migrations), len(files))
	}
	if len(migrations) == 0 {
		t.Fatal("内嵌迁移为空")
	}
	seen := make(map[string]struct{}, len(migrations))
	for index, migration := range migrations {
		if len(migration.Version) != 4 {
			t.Errorf("第 %d 个迁移版本 = %q，期望四位数字编号", index, migration.Version)
		}
		for _, digit := range migration.Version {
			if digit < '0' || digit > '9' {
				t.Errorf("第 %d 个迁移版本 = %q，期望四位数字编号", index, migration.Version)
				break
			}
		}
		if _, exists := seen[migration.Version]; exists {
			t.Errorf("迁移版本重复：%s", migration.Version)
		}
		seen[migration.Version] = struct{}{}
		if index > 0 && migrations[index-1].Version >= migration.Version {
			t.Errorf("迁移版本未严格升序：%q 在 %q 之后",
				migration.Version, migrations[index-1].Version)
		}
		if len(migration.Statements) == 0 {
			t.Errorf("迁移 %s 没有可执行语句", migration.Version)
		}
		if len(migration.Checksum) != 64 {
			t.Errorf("迁移 %s 校验和长度 = %d", migration.Version, len(migration.Checksum))
		}
	}
	if migrations[0].Version != "0001" {
		t.Errorf("首个迁移版本 = %q，期望 0001", migrations[0].Version)
	}
	if len(migrations[0].Statements) < 10 {
		t.Errorf("0001 语句数 = %d，期望包含多张表和索引", len(migrations[0].Statements))
	}
	if len(migrations[1].Statements) != 3 {
		t.Errorf("0002 语句数 = %d，期望建表与两个索引", len(migrations[1].Statements))
	}
	if len(migrations[2].Statements) != 6 {
		t.Errorf("0003 语句数 = %d，期望建表与五个索引", len(migrations[2].Statements))
	}
	if len(migrations[3].Statements) != 3 {
		t.Errorf("0004 语句数 = %d，期望建表与两个索引", len(migrations[3].Statements))
	}
	if len(migrations[4].Statements) != 8 {
		t.Errorf("0005 语句数 = %d，期望三张表、两个新增列与三个索引", len(migrations[4].Statements))
	}
}
