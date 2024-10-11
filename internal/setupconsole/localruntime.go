package setupconsole

// 本地维护会话：以 OS 账户对实例配置/数据/密钥的访问授权为信任根（AGENTS §14），
// 复用生产领域服务与存储，不新建第二套账户/密码/权限核心，不向 Web/HTTP/普通 Go
// 门面暴露 local 绕过。
//
// 与 WS1 契约（.ai/lead/round12-ws1-interfaces.md）：
//   - OpenLocalRuntime 依赖 Detection；状态不满足时返回 ErrLocalRuntimeUnavailable；
//   - WriteGuard 由 281 排他锁/主服务检测注入；nil 时只读打开（后续步骤限制写）；
//   - Close 幂等，只关闭本次 OpenBase 自建的存储/日志等资源。
//
// 路径解析（本地控制台语义）：配置中的 database.path / secrets.master_key 若为
// 相对路径，按配置文件所在目录解析；避免控制台工作目录不同导致连到错误实例。

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/config"
	"github.com/kagurazakayashi/EvernightLogin/internal/serverapp"
)

// LocalRuntimeOptions 是本地维护会话参数；由 cmd/login-setup 本地入口构造。
type LocalRuntimeOptions struct {
	// ConfigPath 是已选实例配置文件路径；必须与 Detection.ConfigPath 一致。
	ConfigPath string
	// OperatorID 是稳定 ASCII 本地操作者标识（如 OS 用户/机器摘要）；进入审计。
	OperatorID string
	// Migrate 为 false（默认）：迁移未完成时 fail-closed，控制台先显示待迁移；
	// 只有 WS2 的显式迁移动作可传 true。
	Migrate bool
	// MasterKeyFile 显式主密钥文件路径；空时按配置 secrets.master_key/实例目录候选解析。
	MasterKeyFile string
	// WriteGuard 由 281 排他锁/主服务检测注入；只读操作不取写门，写操作必须通过。
	// nil 表示未接锁（M1 前本地入口或只读诊断会话），不传给存储层（避免只读被拒）。
	WriteGuard func(context.Context) (func(), error)
	Now        func() time.Time
	Logger     *slog.Logger
}

// LocalRuntime 是本地维护会话，实现 WS3Session。
type LocalRuntime struct {
	base       *serverapp.Base
	services   *WS3Services
	operatorID string
	config     config.Config
	closed     bool
}

// OpenLocalRuntime 以本地维护身份打开实例领域服务；不监听端口、不启动任务调度、
// 不自动迁移（除非 Migrate=true）。状态不满足时返回包装 ErrLocalRuntimeUnavailable
// 的稳定错误，调用方按 Detection.Kind 展示原因。
func OpenLocalRuntime(ctx context.Context, detection Detection,
	options LocalRuntimeOptions) (*LocalRuntime, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(options.OperatorID) == "" {
		return nil, fmt.Errorf("%w: 缺少本地操作者标识", ErrLocalRuntimeUnavailable)
	}
	if !validLocalOperatorID(options.OperatorID) {
		return nil, fmt.Errorf("%w: 本地操作者标识格式无效", ErrLocalRuntimeUnavailable)
	}
	configPath := strings.TrimSpace(detection.ConfigPath)
	if options.ConfigPath != "" && filepath.Clean(options.ConfigPath) != filepath.Clean(configPath) {
		return nil, fmt.Errorf("%w: 配置路径与状态检测不一致", ErrLocalRuntimeUnavailable)
	}
	switch detection.Kind {
	case StateReady, StateRootMissing:
		// 允许打开：root-missing 时用户/MFA/审计画面仍可只读/救援，创建 root 归 WS2。
	case StateMigrationPending:
		if !options.Migrate {
			return nil, fmt.Errorf("%w: 数据库结构待迁移（需显式迁移动作）",
				ErrLocalRuntimeUnavailable)
		}
	default:
		return nil, fmt.Errorf("%w: 实例状态为 %s，需要先完成配置/数据库/root",
			ErrLocalRuntimeUnavailable, detection.Kind.Label())
	}
	if !detection.ConfigLoaded {
		return nil, fmt.Errorf("%w: 配置未成功加载", ErrLocalRuntimeUnavailable)
	}
	cfg, err := resolveLocalRuntimeConfig(detection.ConfigPath, detection.Config)
	if err != nil {
		return nil, err
	}
	masterKeyFile := strings.TrimSpace(options.MasterKeyFile)
	if !cfg.Secrets.MasterKey.IsSet() && masterKeyFile == "" {
		masterKeyFile, err = defaultLocalMasterKeyFile(detection.ConfigPath)
		if err != nil {
			return nil, err
		}
	}
	now := options.Now
	logger := options.Logger
	base, err := serverapp.OpenBase(ctx, serverapp.BaseOptions{
		Config:        cfg,
		ConfigPath:    detection.ConfigPath,
		MasterKeyFile: masterKeyFile,
		Migrate:       options.Migrate,
		Now:           now,
		Logger:        logger,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLocalRuntimeUnavailable, err)
	}
	runtime := &LocalRuntime{
		base:       base,
		operatorID: options.OperatorID,
		config:     cfg,
	}
	// 维护日志是危险写的前置条件；打开失败时保持 nil，写操作 fail-closed，
	// 只读诊断仍可用（NO-1 LOW-1）。
	var maint *ws3MaintRecorder
	if absoluteConfig, absErr := filepath.Abs(detection.ConfigPath); absErr == nil {
		recorder, recordErr := newWS3MaintRecorder(filepath.Dir(absoluteConfig))
		if recordErr == nil {
			maint = recorder
		}
	}
	services, err := newWS3Services(base, options.OperatorID, options.WriteGuard, maint)
	if err != nil {
		closeErr := base.Close(context.Background())
		return nil, errors.Join(fmt.Errorf("%w: %v", ErrLocalRuntimeUnavailable, err), closeErr)
	}
	runtime.services = services
	return runtime, nil
}

// Services 返回本地维护领域适配器（不可变；调用时绑定操作者）。
func (r *LocalRuntime) Services() *WS3Services {
	if r == nil {
		return nil
	}
	return r.services
}

// Config 返回已加载配置的只读副本。
func (r *LocalRuntime) Config() config.Config {
	if r == nil {
		return config.Config{}
	}
	return r.config
}

// OperatorID 返回本地维护操作者标识。
func (r *LocalRuntime) OperatorID() string {
	if r == nil {
		return ""
	}
	return r.operatorID
}

// Close 关闭本地维护会话；幂等，只关闭本次 OpenBase 自建资源。
func (r *LocalRuntime) Close(ctx context.Context) error {
	if r == nil || r.closed {
		return nil
	}
	r.closed = true
	if ctx == nil {
		ctx = context.Background()
	}
	if r.base != nil {
		return r.base.Close(ctx)
	}
	return nil
}

// resolveLocalRuntimeConfig 把相对数据库/密钥路径按配置文件目录解析，返回副本。
func resolveLocalRuntimeConfig(configPath string, cfg config.Config) (config.Config, error) {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return cfg, nil
	}
	absoluteConfig, err := filepath.Abs(configPath)
	if err != nil {
		return cfg, fmt.Errorf("%w: 配置路径无效", ErrLocalRuntimeUnavailable)
	}
	instanceDir := filepath.Dir(absoluteConfig)
	if path := strings.TrimSpace(cfg.Database.Path); path != "" && !filepath.IsAbs(path) {
		cfg.Database.Path = filepath.Join(instanceDir, path)
	}
	return cfg, nil
}

// defaultLocalMasterKeyFile 在配置未设置 secrets.master_key 时按实例目录查找主密钥：
// <configDir>/secrets/master.key（独立部署约定），其次 <configDir>/master.key。
func defaultLocalMasterKeyFile(configPath string) (string, error) {
	absoluteConfig, err := filepath.Abs(strings.TrimSpace(configPath))
	if err != nil {
		return "", fmt.Errorf("%w: 配置路径无效", ErrLocalRuntimeUnavailable)
	}
	instanceDir := filepath.Dir(absoluteConfig)
	candidates := []string{
		filepath.Join(instanceDir, "secrets", "master.key"),
		filepath.Join(instanceDir, "master.key"),
	}
	for _, candidate := range candidates {
		info, statErr := os.Stat(candidate)
		if statErr == nil && info.Mode().IsRegular() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("%w: 未找到主密钥文件（尝试 %s）；请使用 --master-key-file 或配置 secrets.master_key",
		ErrLocalRuntimeUnavailable, strings.Join(candidates, "、"))
}

// validLocalOperatorID 校验本地操作者标识：非空、<=128、可见 ASCII、无控制字符。
// 它是审计字段，不是授权令牌；授权来自本地入口装配本身。
func validLocalOperatorID(operatorID string) bool {
	operatorID = strings.TrimSpace(operatorID)
	if operatorID == "" || len(operatorID) > 128 {
		return false
	}
	for _, r := range operatorID {
		if r < 0x20 || r == 0x7f || r > 0x7e {
			return false
		}
	}
	return true
}
