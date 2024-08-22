package serverapp

// 基础配置/密钥/迁移的共享实现已抽取到 internal/appcore（独立服务与公开嵌入
// 入口 app.Open 共用同一套规则）。本文件保留 serverapp 内部调用点所需的薄封装，
// 只做委托，不再维护第二套实现，避免两种运行方式对同一数据库得出不同结论。

import (
	"context"
	"fmt"
	"github.com/kagurazakayashi/EvernightLogin/config"
	"github.com/kagurazakayashi/EvernightLogin/internal/appcore"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"
)

// LoadConfig 严格加载并校验 YAML 配置，然后应用可选的数据库路径覆盖。
// 实现见 internal/appcore.LoadConfigFile（与嵌入模式共用）。
func LoadConfig(configPath, databasePath string) (config.Config, error) {
	return appcore.LoadConfigFile(configPath, databasePath)
}

// LoadKeyring 解析主密钥环：配置中的 secrets.master_key 优先，其次显式文件路径；
// allowCreate 为 true 时文件不存在则生成受保护主密钥环。
// 实现见 internal/appcore.LoadKeyring（与嵌入模式共用）。
func LoadKeyring(ctx context.Context, cfg config.Config, masterKeyFile string,
	allowCreate bool, now func() time.Time) (*secrets.Keyring, string, error) {
	return appcore.LoadKeyring(ctx, cfg, masterKeyFile, allowCreate, now)
}

// CheckMigrated 只读检查数据库迁移状态；实现见 internal/appcore.CheckMigrated。
func CheckMigrated(ctx context.Context, store *sqlite.Store) (pending []string, err error) {
	return appcore.CheckMigrated(ctx, store)
}

// ApplyMigrations 执行全部未应用的数据库迁移并返回本次应用数量。
// 实现见 internal/appcore.ApplyMigrations。
func ApplyMigrations(ctx context.Context, store *sqlite.Store) (int, error) {
	return appcore.ApplyMigrations(ctx, store)
}

// csrfOrigins 从显式公开地址与监听地址推导 CSRF 允许来源。
//
// CSRF 中间件只接受精确来源，不做通配匹配。推导范围刻意保守：显式配置的
// public_base_url，加上回环监听地址对应的本机来源（http 或 https）。通配监听
// 地址无法在启动前知道浏览器实际使用的来源，此时要求部署方配置 public_base_url；
// 一个来源都推导不出时启动失败，绝不退化为"不校验来源"。
func csrfOrigins(cfg config.Config) ([]string, error) {
	origins := make([]string, 0, 8)
	seen := make(map[string]struct{}, 8)
	add := func(candidate string) {
		if candidate == "" {
			return
		}
		if _, exists := seen[candidate]; exists {
			return
		}
		seen[candidate] = struct{}{}
		origins = append(origins, candidate)
	}
	if strings.TrimSpace(cfg.Server.PublicBaseURL) != "" {
		parsed, err := url.Parse(cfg.Server.PublicBaseURL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return nil, fmt.Errorf("server.public_base_url 无法解析为来源")
		}
		add(parsed.Scheme + "://" + parsed.Host)
	}
	scheme := "http"
	if cfg.Server.TLSEnabled() {
		scheme = "https"
	}
	for _, raw := range cfg.Server.ListenAddresses() {
		host, port, err := net.SplitHostPort(raw)
		if err != nil || port == "0" {
			continue
		}
		loopback := host == "" || host == "::" || host == "0.0.0.0" ||
			strings.EqualFold(host, "localhost") || strings.HasPrefix(host, "127.") || host == "::1"
		if !loopback {
			continue
		}
		for _, candidateHost := range []string{"127.0.0.1", "localhost", "[::1]"} {
			add(scheme + "://" + candidateHost + ":" + port)
		}
	}
	if len(origins) == 0 {
		return nil, fmt.Errorf("无法推导 CSRF 允许来源：请配置 server.public_base_url，" +
			"或使用回环监听地址")
	}
	sort.Strings(origins)
	return origins, nil
}
