package appcore

// 配置加载与规范化：独立服务（cmd/login-server 经 internal/serverapp）与公开嵌入
// 入口（app.Open）共用同一套严格加载规则，避免两种运行方式对同一份 YAML 得出
// 不同的数据库路径、驱动或校验结论。
//
// 本文件只做纯配置处理：不打开数据库、不创建目录、不启动任何后台逻辑。

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/config"
)

// LoadConfigFile 严格加载并校验 YAML 配置，然后应用可选的数据库路径覆盖。
//
// 加载失败（未知字段、重复键、类型错误、越界值、非法组合）一律返回错误，且
// 加载器本身不产生监听、数据库或文件写入副作用。配置文件路径与数据库路径统一
// 规范为绝对路径，防止服务因工作目录变化使用不同数据库。当前真实存储实现只有
// SQLite，因此非 SQLite 驱动在这里直接拒绝，而不是装配出一个打不开的运行时。
func LoadConfigFile(configPath, databasePath string) (config.Config, error) {
	if strings.TrimSpace(configPath) == "" {
		return config.Config{}, fmt.Errorf("缺少 --config 配置文件路径")
	}
	absoluteConfig, err := filepath.Abs(configPath)
	if err != nil {
		return config.Config{}, fmt.Errorf("配置文件路径无效: %w", err)
	}
	if info, statErr := os.Stat(absoluteConfig); statErr != nil || !info.Mode().IsRegular() {
		return config.Config{}, fmt.Errorf("配置文件不存在或不是普通文件: %s", absoluteConfig)
	}
	cfg, err := config.Load(config.LoadOptions{YAMLFile: absoluteConfig})
	if err != nil {
		return config.Config{}, fmt.Errorf("配置加载失败: %w", err)
	}
	return PrepareConfig(cfg, databasePath)
}

// PrepareConfig 对已加载配置应用数据库路径覆盖并做最终校验。
//
// 共用规则：
//   - 当前版本只有 SQLite 真实实现，其他驱动在装配前明确拒绝；
//   - databasePath 非空时覆盖配置中的数据库路径（命令行/宿主显式覆盖）；
//   - 数据库路径规范为绝对路径，避免进程工作目录变化导致打开不同数据库；
//   - 覆盖后再次整体校验，防止通过路径覆盖绕过配置规则。
func PrepareConfig(cfg config.Config, databasePath string) (config.Config, error) {
	if !cfg.Database.Driver.Valid() || cfg.Database.Driver != config.DatabaseDriverSQLite {
		return config.Config{}, fmt.Errorf("当前版本只支持 sqlite 数据库驱动，实际为 %q",
			string(cfg.Database.Driver))
	}
	if strings.TrimSpace(databasePath) != "" {
		cfg.Database.Path = databasePath
	}
	absoluteDatabase, err := filepath.Abs(cfg.Database.Path)
	if err != nil {
		return config.Config{}, fmt.Errorf("数据库路径无效: %w", err)
	}
	cfg.Database.Path = filepath.Clean(absoluteDatabase)
	if err := cfg.Validate(); err != nil {
		return config.Config{}, fmt.Errorf("最终配置校验失败: %w", err)
	}
	return cfg, nil
}
