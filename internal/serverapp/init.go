package serverapp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/errs"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/bootstrap"
	bootstrapsqlite "github.com/kagurazakayashi/EvernightLogin/internal/bootstrap/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/maintenance"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"golang.org/x/term"
)

const (
	// MaxInitPasswordBytes 是首次初始化受理的密码最大字节数（与认证服务的
	// MaxPasswordBytes 对齐的宽松上限，真实策略由 authn 密码策略判定）。
	MaxInitPasswordBytes = 1024
	// maxPasswordFileBytes 是受保护密码文件读取上限，避免把超大文件读进内存。
	maxPasswordFileBytes = 4096
)

// InitOptions 是 login-server init 的显式参数。
type InitOptions struct {
	// ConfigPath 是必需 YAML 配置文件路径。
	ConfigPath string
	// DatabasePath 覆盖配置里的 database.path。
	DatabasePath string
	// MasterKeyFile 是主密钥环文件路径：配置未设置 secrets.master_key 时必填；
	// 文件不存在时生成新密钥环并以平台受保护权限写入（只写路径，不使用明文密钥
	// 命令行参数）。
	MasterKeyFile string
	// OperatorID 是本地受控操作者标识；空值使用操作系统本地管理员身份推导值。
	OperatorID string
	// MaintenanceStateDir 覆盖库外维护状态目录；空则使用与 serve 相同的默认位置。
	MaintenanceStateDir string
	// PasswordFile 是可选受保护密码文件（非 Windows 要求仅所有者可读写）；
	// 与 StandardInput 二选一，命令行不提供明文密码参数。
	PasswordFile string
	// StandardInput 是交互式终端或受保护 stdin；终端下密码不回显并二次确认。
	StandardInput io.Reader
	// StandardOutput/StandardError 是结果与提示输出；nil 使用 os 标准流。
	StandardOutput io.Writer
	StandardError  io.Writer
	// Now 是可注入时钟；nil 使用 time.Now。
	Now func() time.Time
}

// ensureUninitialized 只读检查数据库是否尚未初始化：已有初始化记录或 root 时
// 返回明确拒绝；返回的 bootstrap 存储可复用于后续认证服务装配。
func ensureUninitialized(ctx context.Context, store *storagesqlite.Store) (
	*bootstrapsqlite.Store, error) {
	bootstrapStore, err := bootstrapsqlite.New(store)
	if err != nil {
		return nil, fmt.Errorf("构造首次初始化存储失败: %w", err)
	}
	if record, found, lookErr := bootstrapStore.GetInitialization(ctx); lookErr != nil {
		return nil, fmt.Errorf("读取首次初始化状态失败: %w", lookErr)
	} else if found {
		return nil, fmt.Errorf("实例已完成首次初始化（状态 %s），拒绝重复初始化", record.State)
	}
	if rootAccount, rootFound, lookErr := bootstrapStore.GetRootAccount(ctx); lookErr != nil {
		return nil, fmt.Errorf("读取 root 账户失败: %w", lookErr)
	} else if rootFound {
		return nil, fmt.Errorf("数据库已存在 root 账户（%s）但缺少初始化记录，本命令不会自动接管；"+
			"请由本地管理员按运维手册人工确认", rootAccount.UserID)
	}
	return bootstrapStore, nil
}

// localOperatorID 返回默认本地受控操作者标识（与维护模块同一推导规则）。
func localOperatorID() string {
	return maintenance.LocalOperator().ID
}

// readPasswordLine 从非交互 stdin 读取一行有界密码（去掉行尾 CR/LF）。
func readPasswordLine(reader io.Reader) (string, error) {
	if reader == nil {
		return "", fmt.Errorf("缺少密码输入")
	}
	buffered := bufio.NewReader(io.LimitReader(reader, MaxInitPasswordBytes+2))
	line, err := buffered.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("读取密码失败: %w", err)
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return "", fmt.Errorf("密码不能为空")
	}
	if len(line) > MaxInitPasswordBytes {
		return "", fmt.Errorf("密码超过 %d 字节上限", MaxInitPasswordBytes)
	}
	return line, nil
}

// promptPassword 在真实终端上不回显地读取密码并二次确认；非终端输入只读一行。
//
// 密码只存在于内存并在使用后由调用方立即丢弃，不写日志、审计、命令行参数或
// 临时文件；提示信息只写到 StandardError。
func promptPassword(options InitOptions) (password string, err error) {
	if options.PasswordFile != "" {
		absolutePath, pathErr := filepath.Abs(options.PasswordFile)
		if pathErr != nil {
			return "", fmt.Errorf("密码文件路径无效: %w", pathErr)
		}
		if protectErr := secrets.CheckProtectedFile(absolutePath); protectErr != nil {
			return "", fmt.Errorf("密码文件权限不符合要求（必须仅所有者可读写）: %w", protectErr)
		}
		file, openErr := os.Open(absolutePath)
		if openErr != nil {
			// 错误信息不回显完整路径，避免把受保护目录结构写进终端/日志。
			if errors.Is(openErr, os.ErrNotExist) {
				return "", fmt.Errorf("密码文件不存在")
			}
			return "", fmt.Errorf("打开密码文件失败（权限不足或路径不可访问）")
		}
		defer file.Close()
		raw, readErr := io.ReadAll(io.LimitReader(file, maxPasswordFileBytes+1))
		if readErr != nil {
			return "", fmt.Errorf("读取密码文件失败: %w", readErr)
		}
		if len(raw) > maxPasswordFileBytes {
			return "", fmt.Errorf("密码文件超过 %d 字节上限", maxPasswordFileBytes)
		}
		password = strings.TrimRight(string(raw), "\r\n")
		if password == "" {
			return "", fmt.Errorf("密码文件内容为空")
		}
		return password, nil
	}
	stdin := options.StandardInput
	if stdin == nil {
		stdin = os.Stdin
	}
	stderr := options.StandardError
	if stderr == nil {
		stderr = os.Stderr
	}
	file, isFile := stdin.(*os.File)
	if !isFile || !term.IsTerminal(int(file.Fd())) {
		return readPasswordLine(stdin)
	}
	fmt.Fprint(stderr, "请输入 root 正式密码（输入不回显）: ")
	first, readErr := term.ReadPassword(int(file.Fd()))
	fmt.Fprintln(stderr)
	if readErr != nil {
		return "", fmt.Errorf("读取密码失败: %w", readErr)
	}
	if len(first) == 0 {
		return "", fmt.Errorf("密码不能为空")
	}
	fmt.Fprint(stderr, "请再次输入以确认: ")
	second, readErr := term.ReadPassword(int(file.Fd()))
	fmt.Fprintln(stderr)
	if readErr != nil {
		return "", fmt.Errorf("读取确认密码失败: %w", readErr)
	}
	if string(first) != string(second) {
		return "", fmt.Errorf("两次输入的密码不一致")
	}
	if len(first) > MaxInitPasswordBytes {
		return "", fmt.Errorf("密码超过 %d 字节上限", MaxInitPasswordBytes)
	}
	return string(first), nil
}

// RunInit 执行首次安全初始化：创建/迁移数据库、加载或生成主密钥环、创建唯一
// root（受限待配置状态）、兑换一次性配置凭证、设置正式密码，并输出下一步指引。
//
// 安全边界：
//   - 只接受本地受控操作者（本机进程 + --operator 显式标识），不提供 HTTP/匿名
//     入口；root 用户名固定保留值，不接受命令行明文密码/密钥。
//   - 重复初始化返回明确的"已初始化"错误，不重建 root、不覆盖状态。
//   - 初始化成功状态为 setup_verified：正式密码已落库、security_version 已递增，
//     但仍要求强认证绑定；本命令不签发会话，也不伪造强认证已完成。
//   - 一次性配置凭证只在本进程内存中兑换一次，其明文从不输出、不落盘。
//   - 主密钥环缺失且允许生成时，只把密钥材料写入受保护文件，标准输出只打印路径。
func RunInit(ctx context.Context, options InitOptions) (exitErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	stdout := options.StandardOutput
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := options.StandardError
	if stderr == nil {
		stderr = os.Stderr
	}
	cfg, err := LoadConfig(options.ConfigPath, options.DatabasePath)
	if err != nil {
		return err
	}
	logger, err := newLogger(cfg, stderr)
	if err != nil {
		return err
	}
	operatorID := strings.TrimSpace(options.OperatorID)
	if operatorID == "" {
		operatorID = localOperatorID()
	}
	store, err := OpenStore(ctx, cfg, nil)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			exitErr = errors.Join(exitErr, fmt.Errorf("关闭数据库失败: %w", closeErr))
		}
	}()
	// L1：先只读检查迁移状态。已迁移的数据库先做初始化前置检查，重复 init 在
	// 执行迁移、生成主密钥、提示输入密码之前就失败（不产生任何副作用）。
	pending, err := CheckMigrated(ctx, store)
	if err != nil {
		return err
	}
	if len(pending) == 0 {
		if _, err := ensureUninitialized(ctx, store); err != nil {
			return err
		}
	}
	applied, err := ApplyMigrations(ctx, store)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "数据库: %s（本次应用迁移 %d 个）\n", cfg.Database.Path, applied)
	// 迁移完成后再确认一次：重复 init 必须尽早失败，绝不因为重复执行而生成新的
	// 主密钥（那会破坏既有部署的解密材料）。
	precheckStore, err := ensureUninitialized(ctx, store)
	if err != nil {
		return err
	}
	keyring, keyPath, err := LoadKeyring(ctx, cfg, options.MasterKeyFile, true, now)
	if err != nil {
		return err
	}
	if keyPath != "" {
		fmt.Fprintf(stdout, "主密钥环文件: %s（仅所有者可读写，请与备份材料分开保存）\n", keyPath)
	}
	// init 是本地受控初始化入口：显式创建库外维护状态，使之后的 serve 在状态
	// 缺失时能安全 fail-closed（而不是被迫自动创建或无法启动）。
	maintenanceStateDir := options.MaintenanceStateDir
	if maintenanceStateDir == "" {
		maintenanceStateDir = defaultMaintenanceStateDir(cfg.Database.Path)
	}
	maintenanceController, maintenanceCreated, err := openMaintenance(ctx, cfg, keyring,
		maintenanceStateDir, logger, now, true)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "库外维护状态: %s（serve 启动时要求存在；删除会导致拒绝启动）\n",
		maintenanceStateDir)
	defer func() {
		if closeErr := maintenanceController.Close(); closeErr != nil {
			exitErr = errors.Join(exitErr, fmt.Errorf("关闭维护状态失败: %w", closeErr))
		}
		// 初始化失败时清理本次创建的维护状态目录，避免失败路径留下半配置残留。
		if exitErr != nil && maintenanceCreated {
			_ = os.RemoveAll(maintenanceStateDir)
		}
	}()
	auditRecorder, err := NewAuditRecorder(ctx, store, logger, now)
	if err != nil {
		return err
	}
	deps := Deps{Config: cfg, ConfigPath: options.ConfigPath, Store: store, Keyring: keyring,
		Audit: auditRecorder, Logger: logger, Now: now}
	bootstrapService, caller, err := BuildBootstrapService(deps, operatorID)
	if err != nil {
		return err
	}
	status, err := bootstrapService.Status(ctx, caller)
	if err != nil {
		return fmt.Errorf("读取首次初始化状态失败: %w", err)
	}
	switch status.State {
	case bootstrap.StateUninitialized:
		// 继续：唯一允许创建的窗口。
	case bootstrap.StateExistingRoot:
		return fmt.Errorf("数据库已存在 root 账户但缺少初始化记录，本命令不会自动接管；" +
			"请由本地管理员按运维手册人工确认")
	default:
		return fmt.Errorf("实例已完成首次初始化（状态 %s），拒绝重复初始化", status.State)
	}

	password, err := promptPassword(options)
	if err != nil {
		return err
	}
	initializeResult, err := bootstrapService.Initialize(ctx, caller, bootstrap.InitializeRequest{})
	if err != nil {
		if errors.Is(err, bootstrap.ErrAlreadyInitialized) {
			return fmt.Errorf("实例已完成首次初始化，拒绝重复初始化")
		}
		return fmt.Errorf("创建 root 失败: %w", err)
	}
	grant, err := bootstrapService.RedeemSetupCredential(ctx, caller,
		bootstrap.RedeemSetupCredentialRequest{
			CredentialID: initializeResult.SetupCredential.ID,
			Secret:       initializeResult.SetupCredential.Secret.Reveal(),
		})
	if err != nil {
		return fmt.Errorf("兑换一次性配置凭证失败（root 已创建，可重新签发凭证继续）: %w", err)
	}
	authnService, err := newAuthnService(deps, precheckStore, SecurityHooks{})
	if err != nil {
		return err
	}
	authnCaller, err := authn.LocalAdminCaller(operatorID)
	if err != nil {
		return fmt.Errorf("构造本地认证操作者失败: %w", err)
	}
	requestID := errs.NewRequestID()
	passwordResult, err := authnService.SetRootPassword(ctx, authnCaller,
		authn.SetRootPasswordRequest{RootUserID: grant.RootUserID,
			NewPassword: password, RequestID: requestID})
	if err != nil {
		return fmt.Errorf("写入 root 正式密码失败（root 已创建并处于受限待配置状态，"+
			"请使用本地恢复流程继续，不要重复执行 init）: %w", err)
	}
	password = ""
	_ = initializeResult
	_ = grant
	printInitSummary(stdout, operatorID, keyPath, passwordResult)
	logger.Info("首次初始化完成",
		"root_user_id", passwordResult.RootUserID,
		"state", string(passwordResult.State),
		"security_version", passwordResult.SecurityVersion,
		"operator", operatorID, "request_id", requestID)
	return nil
}

// printInitSummary 输出不含秘密的初始化结果与下一步指引。
func printInitSummary(stdout io.Writer, operatorID, keyPath string,
	passwordResult authn.RootPasswordResult) {
	fmt.Fprintln(stdout, "")
	fmt.Fprintln(stdout, "首次安全初始化完成：")
	fmt.Fprintf(stdout, "  root 用户 ID: %s\n", passwordResult.RootUserID)
	fmt.Fprintf(stdout, "  root 用户名: %s（保留名，不可被普通账户占用）\n", bootstrap.RootUsername)
	fmt.Fprintf(stdout, "  初始化状态: %s（%s）\n", string(passwordResult.State),
		passwordResult.State.Description())
	fmt.Fprintf(stdout, "  security_version: %d\n", passwordResult.SecurityVersion)
	fmt.Fprintf(stdout, "  配置操作者: %s\n", operatorID)
	if passwordResult.StrongAuthRequired {
		fmt.Fprintln(stdout, "  仍要求强认证绑定（MFA/Passkey）：绑定完成前 root 不能用于完整登录。")
	}
	fmt.Fprintln(stdout, "")
	fmt.Fprintln(stdout, "下一步：")
	fmt.Fprintln(stdout, "  1. 确认主密钥与数据库文件权限仅服务账号可访问；主密钥与备份分开保存。")
	if keyPath != "" {
		fmt.Fprintf(stdout, "     主密钥文件: %s\n", keyPath)
	}
	fmt.Fprintln(stdout, "  2. 用 login-server serve --config <配置> 启动服务；默认只监听 127.0.0.1。")
	fmt.Fprintln(stdout, "  3. 访问内置登录页确认服务可用；root 强认证绑定与维护/恢复流程见运维文档。")
	fmt.Fprintln(stdout, "  4. 不要重复执行 init：重复初始化会被拒绝，也不会重建 root。")
}
