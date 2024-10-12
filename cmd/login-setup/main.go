// login-setup 是 EvernightLogin 的本地维护控制台入口（第12轮 277–302）。
//
// 定位：类 BIOS 的全屏 CUI，可由本机终端或已建立的 SSH 终端使用；不监听端口、
// 不新增匿名 HTTP 管理服务。启动不依赖完整生产 Runtime：无配置、坏配置、无数据库、
// 数据库不可达、结构待迁移、root 缺失都会显示状态并允许退出/后续修复。
//
// 集成：WS1 主框架 + WS2 初始化画面（282–285）+ WS3 本地维护画面（286–291）+
// WS4 备份/服务画面（292+）。各工作流通过 RegisterWS2/RegisterWS3/RegisterWS4
// 注册；WS3 的本地维护会话 opener 在本入口装配（OS 身份 + 按写入持排他维护锁 +
// OpenLocalRuntime），不来自 HTTP 请求或可序列化令牌。
//
// 锁语义：只读查看不预持排他锁（不阻塞主服务启动/操作）；每次真正写事务前由
// storage WriteGuard 即时获取「控制台互斥锁 + 主服务未运行」证明，写入结束释放。
// 主服务在查看期间启动时，后续写入会 fail-closed（ErrServiceRunning），不会直写
// 正在服务的库。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/setupconsole"
)

func main() {
	var configPath string
	var masterKeyFile string
	var showVersion bool
	flag.BoolVar(&showVersion, "version", false, "打印版本信息后退出")
	flag.StringVar(&configPath, "config", "", "login.yaml 配置路径（默认尝试当前目录 login.yaml）")
	flag.StringVar(&masterKeyFile, "master-key-file", "",
		"可选：本地维护会话使用的主密钥环文件（默认按配置/实例目录解析）")
	flag.Parse()
	if showVersion {
		// 版本信息可安全打印，不含秘密；发布校验/运维排查使用。
		fmt.Println("login-setup " + login.CurrentBuildInfo().String())
		return
	}
	if configPath == "" {
		if _, err := os.Stat("login.yaml"); err == nil {
			configPath = "login.yaml"
		}
	}
	ctx := context.Background()
	// 非交互子命令：命令及参数、JSON、确认串与秘密通道由子命令处理；不需要 PTY，
	// 不弹交互框。非交互模式同样只装配本地 OS 维护身份，不接受请求自报 local/root。
	if args := flag.Args(); len(args) > 0 {
		os.Exit(runNonInteractive(args, cliEnv{ctx: ctx, stdin: os.Stdin,
			stdout: os.Stdout, stderr: os.Stderr, configPath: configPath,
			masterKeyFile: masterKeyFile}))
	}
	stdinFD := int(os.Stdin.Fd())
	stdoutFD := int(os.Stdout.Fd())
	if term.IsTerminal(stdinFD) && term.IsTerminal(stdoutFD) {
		terminal := setupconsole.NewANSITerminal(os.Stdin, os.Stdout)
		app := setupconsole.NewApp(terminal, configPath, nil)
		// 启动即做一次只读检测，让菜单可用性（WS3 等）与状态行反映真实实例。
		app.RefreshDetection(ctx)
		if err := registerMaintenanceScreens(ctx, app, masterKeyFile); err != nil {
			fmt.Fprintln(os.Stderr, "维护画面注册失败：", err)
			os.Exit(1)
		}
		if err := app.Run(ctx); err != nil {
			// 错误只写诊断信息，不含秘密/路径内容之外的内部细节。
			fmt.Fprintln(os.Stderr, "控制台异常退出：", err)
			os.Exit(1)
		}
		return
	}
	result := setupconsole.RunPlain(ctx, os.Stdin, os.Stdout, configPath)
	os.Exit(result.ExitCode)
}

// registerMaintenanceScreens 注册 WS2/WS3/WS4 画面与本地维护会话 opener。
func registerMaintenanceScreens(ctx context.Context, app *setupconsole.App,
	masterKeyFile string) error {
	if err := setupconsole.RegisterWS2(app); err != nil {
		return fmt.Errorf("WS2 初始化画面: %w", err)
	}
	open := func(openCtx context.Context) (setupconsole.WS3Session, error) {
		return openLocalMaintenanceSession(openCtx, app, masterKeyFile)
	}
	if err := setupconsole.RegisterWS3(app, open); err != nil {
		return fmt.Errorf("WS3 维护画面: %w", err)
	}
	if err := setupconsole.RegisterWS4(app); err != nil {
		return fmt.Errorf("WS4 备份/服务画面: %w", err)
	}
	_ = ctx
	return nil
}

// openLocalMaintenanceSession 装配一次本地维护会话：
// 只读检测 → OS 维护身份 → OpenLocalRuntime。会话本身不预持排他锁；
// 写入通过 WriteGuard 在每次真实写事务前即时取锁（控制台互斥 + 主服务未运行），
// 写结束释放。任何一步失败都 fail-closed。
func openLocalMaintenanceSession(ctx context.Context, app *setupconsole.App,
	masterKeyFile string) (setupconsole.WS3Session, error) {
	detection := app.RefreshDetection(ctx)
	instanceDir, err := instanceDirectory(detection.ConfigPath)
	if err != nil {
		return nil, err
	}
	identity, err := setupconsole.LocalMaintenanceIdentity(instanceDir)
	if err != nil {
		return nil, err
	}
	guard, err := maintenanceWriteGuard(instanceDir,
		resolveDatabasePath(detection.DatabasePath, instanceDir), identity)
	if err != nil {
		return nil, err
	}
	runtime, err := setupconsole.OpenLocalRuntime(ctx, detection, setupconsole.LocalRuntimeOptions{
		ConfigPath:    detection.ConfigPath,
		OperatorID:    localOperatorID(identity),
		MasterKeyFile: strings.TrimSpace(masterKeyFile),
		WriteGuard:    guard,
	})
	if err != nil {
		return nil, err
	}
	return runtime, nil
}

// maintenanceWriteGuard 返回 storage 写门闸：每次写事务前取得实例排他维护锁，
// 写结束释放。只读操作不调用该门闸，因此查看画面不阻塞主服务。
func maintenanceWriteGuard(instanceDir, databasePath string,
	identity setupconsole.MaintenanceIdentity) (func(context.Context) (func(), error), error) {
	if strings.TrimSpace(instanceDir) == "" {
		return nil, fmt.Errorf("维护写入缺少实例目录")
	}
	return func(ctx context.Context) (func(), error) {
		lock, err := setupconsole.AcquireMaintenanceLock(ctx, setupconsole.LockRequest{
			InstanceDir:  instanceDir,
			DatabasePath: databasePath,
			Purpose:      "local maintenance write transaction",
			Operator:     identity,
		})
		if err != nil {
			return nil, err
		}
		return func() { _ = lock.Release() }, nil
	}, nil
}

// instanceDirectory 返回配置文件所在目录（按需绝对化）；未选择配置时 fail-closed。
func instanceDirectory(configPath string) (string, error) {
	trimmed := strings.TrimSpace(configPath)
	if trimmed == "" {
		return "", fmt.Errorf("未选择实例配置路径，无法打开本地维护会话（先选择 login.yaml）")
	}
	absolute, err := filepath.Abs(trimmed)
	if err != nil {
		return "", fmt.Errorf("实例配置路径无效: %w", err)
	}
	return filepath.Dir(absolute), nil
}

// resolveDatabasePath 把检测到的数据库路径解析为绝对路径；空值返回空（只加强控制台锁）。
func resolveDatabasePath(databasePath, instanceDir string) string {
	trimmed := strings.TrimSpace(databasePath)
	if trimmed == "" {
		return ""
	}
	if filepath.IsAbs(trimmed) {
		return trimmed
	}
	return filepath.Join(instanceDir, trimmed)
}

// localOperatorID 把 OS 维护身份转成稳定 ASCII 审计标识（<=128，无控制字符）。
func localOperatorID(identity setupconsole.MaintenanceIdentity) string {
	user := asciiOperatorPart(identity.OSUser)
	machine := asciiOperatorPart(identity.Machine)
	operatorID := "local-os:" + user + "@" + machine
	if len(operatorID) > 128 {
		operatorID = operatorID[:128]
	}
	return operatorID
}

// asciiOperatorPart 清理非可见 ASCII 字符；空值使用 unknown。
func asciiOperatorPart(value string) string {
	var builder strings.Builder
	for _, character := range strings.TrimSpace(value) {
		if character >= 0x20 && character <= 0x7e {
			builder.WriteRune(character)
		} else {
			builder.WriteByte('_')
		}
	}
	cleaned := strings.Trim(builder.String(), "_")
	if cleaned == "" {
		return "unknown"
	}
	return cleaned
}
