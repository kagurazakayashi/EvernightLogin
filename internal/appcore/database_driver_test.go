package appcore_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/config"
	"github.com/kagurazakayashi/EvernightLogin/internal/appcore"
	"github.com/kagurazakayashi/EvernightLogin/internal/serverapp"
)

// unwiredDatabaseConfig 构造通过正式校验的非 SQLite 配置（仅配置与适配代码存在）。
func unwiredDatabaseConfig(t *testing.T, driver config.DatabaseDriver,
	databasePath string) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Database.Driver = driver
	cfg.Database.Path = ""
	cfg.Database.WAL = false
	cfg.Database.BusyTimeoutMS = 0
	cfg.Database.Host = "127.0.0.1"
	cfg.Database.Port = 0 // 使用驱动默认端口
	cfg.Database.Username = "evernightlogin"
	cfg.Database.Database = "evernightlogin"
	cfg.Database.TLSMode = driver.DefaultTLSMode()
	_ = databasePath
	if err := cfg.Validate(); err != nil {
		t.Fatalf("非 SQLite 配置应可保存/校验，实际失败: %v", err)
	}
	return cfg
}

func TestOpenStoreRejectsUnwiredDriversFailClosed(t *testing.T) {
	drivers := []config.DatabaseDriver{config.DatabaseDriverMySQL,
		config.DatabaseDriverPostgreSQL, config.DatabaseDriverSQLServer}
	for _, driver := range drivers {
		t.Run(string(driver), func(t *testing.T) {
			instanceDir := t.TempDir()
			cfg := unwiredDatabaseConfig(t, driver, filepath.Join(instanceDir, "database", "login.db"))
			store, err := appcore.OpenStore(context.Background(), cfg, nil)
			if store != nil {
				_ = store.Close()
				t.Fatal("非 SQLite 驱动不得返回可用存储")
			}
			if !errors.Is(err, appcore.ErrDatabaseDriverNotWired) {
				t.Fatalf("应返回稳定 ErrDatabaseDriverNotWired，实际: %v", err)
			}
			if !strings.Contains(err.Error(), "本轮未接入运行") ||
				!strings.Contains(err.Error(), "仅配置与适配代码存在") {
				t.Fatalf("错误应说明运行未接入语义，实际: %v", err)
			}
			// fail-closed 不得创建 SQLite 文件或数据库目录。
			if _, statErr := os.Stat(filepath.Join(instanceDir, "database")); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("非 SQLite 打开不得创建数据库目录: %v", statErr)
			}
		})
	}
}

func TestServerappOpenStorePropagatesUnwiredDriverError(t *testing.T) {
	instanceDir := t.TempDir()
	cfg := unwiredDatabaseConfig(t, config.DatabaseDriverMySQL,
		filepath.Join(instanceDir, "database", "login.db"))
	store, err := serverapp.OpenStore(context.Background(), cfg, nil)
	if store != nil {
		_ = store.Close()
		t.Fatal("经 serverapp.OpenStore 也不得返回可用存储")
	}
	if !errors.Is(err, appcore.ErrDatabaseDriverNotWired) {
		t.Fatalf("最小运行入口应传递 fail-closed 错误，实际: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(instanceDir, "database")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("fail-closed 时不得创建数据库目录: %v", statErr)
	}
}

func TestOpenStoreSQLiteBehaviorUnchanged(t *testing.T) {
	instanceDir := t.TempDir()
	cfg := config.Default()
	cfg.Database.Path = filepath.Join(instanceDir, "database", "login.db")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("SQLite 默认配置应通过校验: %v", err)
	}
	store, err := appcore.OpenStore(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("SQLite 打开应保持可用，实际: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("关闭 SQLite 存储失败: %v", err)
	}
	if _, statErr := os.Stat(cfg.Database.Path); statErr != nil {
		t.Fatalf("SQLite 路径行为应保持（文件已创建）: %v", statErr)
	}
}

// TestOpenStoreRejectsLoadedNetworkDriverConfig 验证从 YAML 加载的网络驱动配置
// （driver-aware 默认语义生效后）仍由运行入口明确 fail-closed，不建文件。
func TestOpenStoreRejectsLoadedNetworkDriverConfig(t *testing.T) {
	instanceDir := t.TempDir()
	yamlText := "database:\n  driver: mysql\n  host: db.example.test\n  username: u\n" +
		"  password:\n    env: LOGIN_DATABASE_PASSWORD\n  name: n\n  tls_mode: \"true\"\n" +
		"logging:\n  level: info\n"
	cfg, err := config.Load(config.LoadOptions{YAML: []byte(yamlText)})
	if err != nil {
		t.Fatalf("网络驱动 YAML 应可加载: %v", err)
	}
	if cfg.Database.Driver != config.DatabaseDriverMySQL {
		t.Fatalf("驱动解析错误: %s", cfg.Database.Driver)
	}
	store, err := appcore.OpenStore(context.Background(), cfg, nil)
	if store != nil {
		_ = store.Close()
		t.Fatal("网络驱动不得返回可用存储")
	}
	if !errors.Is(err, appcore.ErrDatabaseDriverNotWired) {
		t.Fatalf("应返回 fail-closed 错误，实际: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(instanceDir, "database")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("不得创建数据库目录: %v", statErr)
	}
}
