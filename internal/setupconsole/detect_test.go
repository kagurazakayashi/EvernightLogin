package setupconsole

// 步骤277：状态检测的定向测试。覆盖无配置/坏配置/数据库缺失/结构待迁移/root 缺失/
// 正常就绪，并验证检测对数据库文件是只读的（文件摘要不变）。

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// writeConfig 在临时目录写一份最小合法配置。
func writeConfig(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "login.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("写入配置: %v", err)
	}
	return path
}

// minimalConfigYAML 返回带临时数据库路径的最小配置。
func minimalConfigYAML(databasePath string) string {
	return fmt.Sprintf("database:\n  driver: sqlite\n  path: %q\n", databasePath)
}

// createMigratedDatabase 创建并迁移一个临时 SQLite 数据库；withRoot 为真时补写 root。
func createMigratedDatabase(t *testing.T, path string, withRoot bool) {
	t.Helper()
	ctx := context.Background()
	store, err := storagesqlite.Open(ctx, storagesqlite.Options{Path: path, WAL: true})
	if err != nil {
		t.Fatalf("打开临时数据库: %v", err)
	}
	defer func() { _ = store.Close() }()
	migrationList, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := store.Migrate(ctx, migrationList); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	if !withRoot {
		return
	}
	db := store.DB()
	now := int64(1764139200000)
	const rootID = "usr_00000000000000000000000000000001"
	if _, err := db.ExecContext(ctx, `INSERT INTO users(
id,username,username_normalized,nickname,biography,avatar_ref,language,timezone,status,
is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'','',NULL,'zh-CN','Asia/Shanghai','active',1,1,1,?,?)`,
		rootID, "root", "root", now, now); err != nil {
		t.Fatalf("写入 root 用户: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO root_initializations(
singleton,root_user_id,state,setup_credential_id,started_by,
created_at_ms,updated_at_ms,verified_at_ms,ready_at_ms)
VALUES(1,?,'ready',NULL,'local-setup',?,?,?,?)`, rootID, now, now, now, now); err != nil {
		t.Fatalf("写入 root_initializations: %v", err)
	}
}

// fileSHA256 计算文件摘要（用于只读性断言）。
func fileSHA256(t *testing.T, path string) [32]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取数据库文件: %v", err)
	}
	return sha256.Sum256(data)
}

func TestDetectStateBranches(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	t.Run("no config", func(t *testing.T) {
		detection := Detect(ctx, DetectOptions{ConfigPath: filepath.Join(dir, "missing.yaml")})
		if detection.Kind != StateNoConfig {
			t.Fatalf("状态 = %s，期望 no-config", detection.Kind)
		}
	})
	t.Run("syntax error", func(t *testing.T) {
		configPath := writeConfig(t, dir, "server: [\n")
		detection := Detect(ctx, DetectOptions{ConfigPath: configPath})
		if detection.Kind != StateConfigInvalid || len(detection.Issues) == 0 {
			t.Fatalf("状态 = %s issues=%d，期望 config-invalid 且有诊断",
				detection.Kind, len(detection.Issues))
		}
		if detection.Issues[0].Suggestion == "" {
			t.Fatal("配置诊断缺少修复建议")
		}
	})
	t.Run("duplicate key", func(t *testing.T) {
		configPath := writeConfig(t, dir, "database:\n  path: a.db\n  path: b.db\n")
		detection := Detect(ctx, DetectOptions{ConfigPath: configPath})
		if detection.Kind != StateConfigInvalid {
			t.Fatalf("重复键状态 = %s，期望 config-invalid", detection.Kind)
		}
	})
	t.Run("unknown field", func(t *testing.T) {
		configPath := writeConfig(t, dir, "server:\n  unknown_field_x: 1\n")
		detection := Detect(ctx, DetectOptions{ConfigPath: configPath})
		if detection.Kind != StateConfigInvalid {
			t.Fatalf("未知字段状态 = %s，期望 config-invalid", detection.Kind)
		}
	})
	t.Run("database section missing", func(t *testing.T) {
		configPath := writeConfig(t, dir, "logging:\n  level: info\n")
		detection := Detect(ctx, DetectOptions{ConfigPath: configPath})
		if detection.Kind != StateDatabaseNotConf {
			t.Fatalf("状态 = %s，期望 db-not-configured（无 database 段）", detection.Kind)
		}
	})
	t.Run("database missing", func(t *testing.T) {
		configPath := writeConfig(t, dir, minimalConfigYAML(filepath.Join(dir, "nope.db")))
		detection := Detect(ctx, DetectOptions{ConfigPath: configPath})
		if detection.Kind != StateDatabaseMissing {
			t.Fatalf("状态 = %s，期望 db-missing", detection.Kind)
		}
	})
	t.Run("migration pending empty database", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "empty.db")
		store, err := storagesqlite.Open(ctx, storagesqlite.Options{Path: dbPath})
		if err != nil {
			t.Fatalf("创建空库: %v", err)
		}
		_ = store.Close()
		configPath := writeConfig(t, dir, minimalConfigYAML(dbPath))
		detection := Detect(ctx, DetectOptions{ConfigPath: configPath})
		if detection.Kind != StateMigrationPending {
			t.Fatalf("状态 = %s，期望 migration-pending", detection.Kind)
		}
	})
	t.Run("root missing on migrated database", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "migrated.db")
		createMigratedDatabase(t, dbPath, false)
		configPath := writeConfig(t, dir, minimalConfigYAML(dbPath))
		detection := Detect(ctx, DetectOptions{ConfigPath: configPath})
		if detection.Kind != StateRootMissing {
			t.Fatalf("状态 = %s，期望 root-missing（applied=%d/%d）",
				detection.Kind, detection.AppliedCount, detection.LatestCount)
		}
	})
	t.Run("ready and read-only", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "ready.db")
		createMigratedDatabase(t, dbPath, true)
		configPath := writeConfig(t, dir, minimalConfigYAML(dbPath))
		before := fileSHA256(t, dbPath)
		detection := Detect(ctx, DetectOptions{ConfigPath: configPath})
		if detection.Kind != StateReady {
			t.Fatalf("状态 = %s（%s），期望 ready", detection.Kind, detection.Summary)
		}
		if detection.RootUserID == "" {
			t.Fatal("就绪状态缺少 root 用户 ID")
		}
		after := fileSHA256(t, dbPath)
		if before != after {
			t.Fatal("状态检测修改了数据库文件内容（应只读）")
		}
	})
}

func TestDetectDBUnreachable(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	// 目录冒充数据库路径：存在但无法作为数据库打开。
	dirPath := filepath.Join(dir, "db-dir")
	if err := os.Mkdir(dirPath, 0o700); err != nil {
		t.Fatalf("创建目录: %v", err)
	}
	configPath := writeConfig(t, dir, minimalConfigYAML(dirPath))
	detection := Detect(ctx, DetectOptions{ConfigPath: configPath})
	if detection.Kind != StateDatabaseDown {
		t.Fatalf("状态 = %s，期望 db-unreachable", detection.Kind)
	}
}

// TestDetectDoesNotCreateDatabase 验证检测不会创建缺失的数据库文件。
func TestDetectDoesNotCreateDatabase(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "will-not-exist.db")
	configPath := writeConfig(t, dir, minimalConfigYAML(dbPath))
	detection := Detect(ctx, DetectOptions{ConfigPath: configPath})
	if detection.Kind != StateDatabaseMissing {
		t.Fatalf("状态 = %s，期望 db-missing", detection.Kind)
	}
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatalf("检测创建了数据库文件: %v", err)
	}
}

// TestDetectInvalidSQLiteFile 覆盖损坏/非 SQLite 文件分类为 db-invalid（N-M1-1）：
// 不能误判为 migration-pending/root-missing；检测不得修复或写文件。
func TestDetectInvalidSQLiteFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "corrupt.db")
	junk := bytes.Repeat([]byte{0x41, 0x42, 0x43, 0x00}, 512)
	if err := os.WriteFile(dbPath, junk, 0o600); err != nil {
		t.Fatalf("写入非 SQLite 文件: %v", err)
	}
	configPath := writeConfig(t, dir, minimalConfigYAML(dbPath))
	before := fileSHA256(t, dbPath)
	detection := Detect(ctx, DetectOptions{ConfigPath: configPath})
	if detection.Kind != StateDatabaseInvalid {
		t.Fatalf("损坏文件状态 = %s，期望 db-invalid（摘要：%s）",
			detection.Kind, detection.Summary)
	}
	if detection.RootUserID != "" {
		t.Fatal("损坏数据库不应伪造 root 用户")
	}
	joined := strings.Join(detection.Details, " ")
	if !strings.Contains(joined, "SQLITE_NOTADB") && !strings.Contains(joined, "SQLITE_CORRUPT") {
		t.Fatalf("损坏文件缺少底层稳定错误码: %s", joined)
	}
	if after := fileSHA256(t, dbPath); before != after {
		t.Fatal("状态检测修改了损坏数据库文件")
	}
}

// TestDetectEmptyFileIsMigrationPending 空文件是合法空 SQLite 库 → migration-pending。
func TestDetectEmptyFileIsMigrationPending(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "empty-file.db")
	if err := os.WriteFile(dbPath, nil, 0o600); err != nil {
		t.Fatalf("写入空文件: %v", err)
	}
	configPath := writeConfig(t, dir, minimalConfigYAML(dbPath))
	detection := Detect(ctx, DetectOptions{ConfigPath: configPath})
	if detection.Kind != StateMigrationPending {
		t.Fatalf("空文件状态 = %s，期望 migration-pending（摘要：%s）",
			detection.Kind, detection.Summary)
	}
}

// TestDetectTruncatedSQLiteFile 截断的 SQLite 文件不得被当成未迁移空库。
func TestDetectTruncatedSQLiteFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "truncated.db")
	createMigratedDatabase(t, dbPath, false)
	data, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("读取原始数据库: %v", err)
	}
	if err := os.WriteFile(dbPath, data[:len(data)/2], 0o600); err != nil {
		t.Fatalf("截断数据库: %v", err)
	}
	configPath := writeConfig(t, dir, minimalConfigYAML(dbPath))
	detection := Detect(ctx, DetectOptions{ConfigPath: configPath})
	if detection.Kind != StateDatabaseInvalid && detection.Kind != StateDatabaseDown {
		t.Fatalf("截断数据库状态 = %s，期望 db-invalid/db-unreachable（摘要：%s）",
			detection.Kind, detection.Summary)
	}
}
