package setupconsole

// 步骤 284（预设部分）：系统预设角色/权限的显式安装与账户方案依赖检查。
//
// 边界：
//   - 只复用正式 preset 服务与默认目录安装系统预设，不复制角色/权限定义；
//   - 安装与“恢复预设”区分：本文件只做首次/升级安装；恢复差异由 WS3/WS4 画面处理；
//   - 本地维护身份仅在本机控制台装配；委派检查器只放行显式本地管理员 actor，
//     其他身份一律拒绝（fail-closed）。

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/config"
	"github.com/kagurazakayashi/EvernightLogin/internal/appcore"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	"github.com/kagurazakayashi/EvernightLogin/internal/preset"
	presetsqlite "github.com/kagurazakayashi/EvernightLogin/internal/preset/sqlite"
)

// 284 预设安装错误。
var (
	// ErrPresetInstallFailed 表示系统预设安装失败（数据库/审计错误原样保留原因）。
	ErrPresetInstallFailed = errors.New("系统预设安装失败")
	// ErrPresetRolesMissing 表示账户方案依赖的预设角色尚未安装。
	ErrPresetRolesMissing = errors.New("账户方案依赖的预设角色尚未安装")
)

// PresetInstallResult 是系统预设安装的真实结果。
type PresetInstallResult struct {
	ScopeID            string
	CatalogVersion     string
	PreviousVersion    string
	Initialized        bool
	Upgraded           bool
	UpToDate           bool
	CreatedPermissions []string
	CreatedRoles       []string
	CreatedGroups      []string
}

// PresetInstallOptions 是系统预设安装的本地维护参数。
type PresetInstallOptions struct {
	ConfigPath  string
	InstanceDir string
	OperatorID  string
	Purpose     string
	Lock        *MaintenanceLock
	Now         func() time.Time
	Logger      *slog.Logger
}

// EnsureSystemPresets 在排他维护锁下安装/升级系统预设角色与权限；幂等。
func EnsureSystemPresets(ctx context.Context, cfg config.Config,
	options PresetInstallOptions) (PresetInstallResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	result := PresetInstallResult{}
	if err := cfg.Validate(); err != nil {
		return result, fmt.Errorf("%w: 配置未通过校验", ErrPresetInstallFailed)
	}
	instanceDir := strings.TrimSpace(options.InstanceDir)
	if instanceDir == "" && strings.TrimSpace(options.ConfigPath) != "" {
		absoluteConfig, err := filepath.Abs(options.ConfigPath)
		if err != nil {
			return result, fmt.Errorf("%w: 配置路径无效", ErrPresetInstallFailed)
		}
		instanceDir = filepath.Dir(absoluteConfig)
	}
	if instanceDir == "" {
		return result, fmt.Errorf("%w: 缺少实例目录", ErrPresetInstallFailed)
	}
	absoluteInstance, err := filepath.Abs(instanceDir)
	if err != nil {
		return result, fmt.Errorf("%w: 实例目录无效", ErrPresetInstallFailed)
	}
	operatorID := strings.TrimSpace(options.OperatorID)
	if operatorID == "" {
		return result, fmt.Errorf("%w: 缺少本地操作者标识", ErrIdentityInvalid)
	}
	lock := options.Lock
	if lock == nil {
		identity, identityErr := LocalMaintenanceIdentity(absoluteInstance)
		if identityErr != nil {
			return result, identityErr
		}
		purpose := strings.TrimSpace(options.Purpose)
		if purpose == "" {
			purpose = "安装系统预设角色与权限"
		}
		acquired, lockErr := AcquireMaintenanceLock(ctx, LockRequest{
			InstanceDir: absoluteInstance, Purpose: purpose, Operator: identity})
		if lockErr != nil {
			return result, lockErr
		}
		lock = acquired
	}
	defer func() { _ = lock.Release() }()
	now := options.Now
	if now == nil {
		now = time.Now
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	masterKeyFile := defaultDBMasterKeyFile(absoluteInstance)
	if !cfg.Secrets.MasterKey.IsSet() {
		if _, _, keyErr := appcore.LoadKeyring(ctx, cfg, masterKeyFile, false, now); keyErr != nil {
			return result, fmt.Errorf("%w: 加载主密钥失败: %v", ErrPresetInstallFailed, keyErr)
		}
	}
	store, err := appcore.OpenStore(ctx, cfg, nil)
	if err != nil {
		return result, fmt.Errorf("%w: 打开数据库失败: %v", ErrPresetInstallFailed, err)
	}
	defer func() { _ = store.Close() }()
	auditRecorder, err := appcore.NewAuditRecorder(ctx, store, logger, now)
	if err != nil {
		return result, fmt.Errorf("%w: 构造审计失败: %v", ErrPresetInstallFailed, err)
	}
	presetStore, err := presetsqlite.New(store)
	if err != nil {
		return result, fmt.Errorf("%w: 构造预设存储失败: %v", ErrPresetInstallFailed, err)
	}
	service, err := preset.New(preset.Options{Store: presetStore, Audit: auditRecorder,
		Transfers: localBootstrapGuard{}, Now: now, Logger: logger})
	if err != nil {
		return result, fmt.Errorf("%w: 构造预设服务失败: %v", ErrPresetInstallFailed, err)
	}
	caller, err := preset.LocalBootstrapCaller(operatorID)
	if err != nil {
		return result, fmt.Errorf("%w: 本地预设操作者标识无效", ErrPresetInstallFailed)
	}
	installed, err := service.Install(ctx, caller, preset.InstallRequest{ScopeID: "system"})
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrPresetInstallFailed, err)
	}
	return PresetInstallResult{ScopeID: installed.ScopeID, CatalogVersion: installed.CatalogVersion,
		PreviousVersion: installed.PreviousVersion, Initialized: installed.Initialized,
		Upgraded: installed.Upgraded, UpToDate: installed.UpToDate,
		CreatedPermissions: installed.CreatedPermissions, CreatedRoles: installed.CreatedRoles,
		CreatedGroups: installed.CreatedGroups}, nil
}

// localBootstrapGuard 是仅用于本地初始化装配的委派检查器：只放行显式本地管理员
// actor；普通用户/匿名/伪造身份一律拒绝，不提供“默认全部放行”实现。
type localBootstrapGuard struct{}

func (localBootstrapGuard) allow(actor audit.Actor) error {
	if actor.Type != audit.ActorLocalAdmin {
		return errors.New("本地初始化只允许本地管理员维护身份")
	}
	if err := actor.Validate(); err != nil {
		return errors.New("本地管理员维护身份无效")
	}
	return nil
}

func (g localBootstrapGuard) CheckPermissionAccess(ctx context.Context, tx audit.Tx,
	actor audit.Actor, scopeID string, permissions []delegation.PermissionRef,
	targets []delegation.Target) error {
	return g.allow(actor)
}

func (g localBootstrapGuard) CheckAssignment(ctx context.Context, tx audit.Tx,
	actor audit.Actor, scopeID string, permissions []delegation.PermissionRef,
	target delegation.Target) error {
	return g.allow(actor)
}

func (g localBootstrapGuard) CheckPermissionActivation(ctx context.Context, tx audit.Tx,
	actor audit.Actor, scopeID string, permissions []delegation.PermissionRef,
	targets []delegation.Target) error {
	return g.allow(actor)
}

func (g localBootstrapGuard) CheckScopeRestoration(ctx context.Context, tx audit.Tx,
	actor audit.Actor, scopeID string) error {
	return g.allow(actor)
}
