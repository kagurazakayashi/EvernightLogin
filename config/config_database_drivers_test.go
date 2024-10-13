package config

import (
	"strings"
	"testing"
)

// 本文件覆盖 driver-aware 数据库配置语义（C4/282 收尾）：
//   - sqlite 行为完全不变；
//   - mysql/postgres/sqlserver 不应用 sqlite 专属 path/wal/busy_timeout_ms，
//     缺失 host/username/name 有明确字段错误；
//   - 旧配置（未写 database 段）仍得到 sqlite 默认值。

func networkDatabaseYAML(driver, extra string) string {
	return "database:\n  driver: " + driver + "\n  host: db.example.test\n" +
		"  port: 3306\n  username: login-service\n  password:\n    env: LOGIN_DATABASE_PASSWORD\n" +
		"  name: login\n  tls_mode: " + defaultNetworkTLS(driver) + "\n" + extra +
		"logging:\n  level: info\n"
}

func defaultNetworkTLS(driver string) string {
	switch driver {
	case "mysql":
		return "\"true\""
	case "postgres":
		return "verify-full"
	case "sqlserver":
		return "\"1.2\""
	default:
		return "\"true\""
	}
}

func TestLoadNetworkDriverConfigs(t *testing.T) {
	for _, driver := range []DatabaseDriver{DatabaseDriverMySQL,
		DatabaseDriverPostgreSQL, DatabaseDriverSQLServer} {
		t.Run(string(driver), func(t *testing.T) {
			cfg, err := Load(LoadOptions{YAML: yamlBytes(networkDatabaseYAML(string(driver), ""))})
			if err != nil {
				t.Fatalf("完整 %s 配置应加载成功: %v", driver, err)
			}
			if cfg.Database.Driver != driver {
				t.Fatalf("驱动 = %s，期望 %s", cfg.Database.Driver, driver)
			}
			// sqlite 专属默认值不得应用到网络驱动。
			if cfg.Database.Path != "" || cfg.Database.WAL || cfg.Database.BusyTimeoutMS != 0 {
				t.Fatalf("网络驱动不应继承 sqlite 专属字段: %+v", cfg.Database)
			}
			if cfg.Database.Host != "db.example.test" || cfg.Database.Username != "login-service" ||
				cfg.Database.Database != "login" {
				t.Fatalf("网络驱动连接字段丢失: %+v", cfg.Database)
			}
			if cfg.Database.Password.Kind != SecretSourceEnv ||
				cfg.Database.Password.Name != "LOGIN_DATABASE_PASSWORD" {
				t.Fatalf("密码来源解析错误: %+v", cfg.Database.Password)
			}
		})
	}
}

func TestLoadNetworkDriverIgnoresSQLiteFields(t *testing.T) {
	extra := "  path: database/should-be-ignored.db\n  wal: true\n  busy_timeout_ms: 5000\n"
	cfg, err := Load(LoadOptions{YAML: yamlBytes(networkDatabaseYAML("postgres", extra))})
	if err != nil {
		t.Fatalf("网络驱动中的 sqlite 专属字段应被忽略而不是误报: %v", err)
	}
	if cfg.Database.Path != "" || cfg.Database.WAL || cfg.Database.BusyTimeoutMS != 0 {
		t.Fatalf("sqlite 专属字段不得应用到网络驱动: %+v", cfg.Database)
	}
}

func TestLoadNetworkDriverMissingFields(t *testing.T) {
	base := map[string]string{
		"host":     "database:\n  driver: mysql\n  username: u\n  name: n\n",
		"username": "database:\n  driver: mysql\n  host: h.example.test\n  name: n\n",
		"name":     "database:\n  driver: mysql\n  host: h.example.test\n  username: u\n",
	}
	for missing, yamlText := range base {
		t.Run(missing, func(t *testing.T) {
			_, err := Load(LoadOptions{YAML: yamlBytes(yamlText)})
			if err == nil {
				t.Fatalf("缺少 %s 应报错", missing)
			}
			field := "database." + missing
			if missing == "name" {
				field = "database.name"
			}
			if !strings.Contains(err.Error(), field) {
				t.Fatalf("错误应包含字段 %s，实际: %v", field, err)
			}
		})
	}
	// 缺密码来源仍允许（由适配器连接策略决定），但若给出密码来源必须合法；
	// TLS 缺省时使用驱动安全默认值。
	if _, err := Load(LoadOptions{YAML: yamlBytes(
		"database:\n  driver: mysql\n  host: h.example.test\n  username: u\n  name: n\n")}); err != nil {
		t.Fatalf("未提供密码来源时配置应仍可保存（运行未接入）: %v", err)
	}
}

func TestLoadSQLiteBehaviorUnchanged(t *testing.T) {
	// 旧配置（未写 database 段）保持 sqlite 默认值。
	legacy, err := Load(LoadOptions{YAML: yamlBytes("logging:\n  level: info\n")})
	if err != nil {
		t.Fatalf("旧配置应保持兼容: %v", err)
	}
	if legacy.Database.Driver != DatabaseDriverSQLite ||
		legacy.Database.Path != "database/login.db" ||
		!legacy.Database.WAL || legacy.Database.BusyTimeoutMS != 5000 {
		t.Fatalf("sqlite 默认值行为改变: %+v", legacy.Database)
	}
	// 显式 sqlite 字段仍按原语义校验并生效。
	cfg, err := Load(LoadOptions{YAML: yamlBytes(
		"database:\n  driver: sqlite\n  path: data/login.db\n  wal: false\n  busy_timeout_ms: 1234\n")})
	if err != nil {
		t.Fatalf("sqlite 显式配置应加载成功: %v", err)
	}
	if cfg.Database.Path != "data/login.db" || cfg.Database.WAL ||
		cfg.Database.BusyTimeoutMS != 1234 {
		t.Fatalf("sqlite 显式字段未生效: %+v", cfg.Database)
	}
	// sqlite 仍不接受网络连接字段。
	if _, err := Load(LoadOptions{YAML: yamlBytes(
		"database:\n  driver: sqlite\n  host: db.example.test\n")}); err == nil ||
		!strings.Contains(err.Error(), "database.host") {
		t.Fatalf("sqlite 配置网络字段应报明确错误: %v", err)
	}
}

func TestProgrammaticNonSQLiteConfigIgnoresSQLiteDefaults(t *testing.T) {
	cfg := Default()
	cfg.Database.Driver = DatabaseDriverMySQL
	cfg.Database.Host = "db.example.test"
	cfg.Database.Username = "login-service"
	cfg.Database.Database = "login"
	cfg.Database.TLSMode = "true"
	// 程序化配置里遗留的 sqlite 默认值不参与网络驱动校验（加载路径会清空）。
	if err := cfg.Validate(); err != nil {
		t.Fatalf("程序化网络驱动配置应通过校验: %v", err)
	}
}
