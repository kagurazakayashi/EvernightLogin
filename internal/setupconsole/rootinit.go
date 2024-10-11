package setupconsole

// 步骤 283：唯一 root 创建与初始化进度恢复。
//
// 边界（AGENTS §14.1/§14.2/§14.4）：
//   - 复用生产 bootstrap/authn 正式流程：唯一 root 标识、初始化记录、一次性配置
//     凭证、正式密码写入与审计；不直接写数据库、不伪造 root 身份；
//   - root 用户名固定为保留名 root（稳定 UserID 不依赖用户名）；本地控制台可在
//     后续本地维护画面（287）改名，创建阶段不接受自定义用户名冒充；
//   - 取消/中断可重入：pending_setup 重新签发一次性凭证；setup_verified 允许本地
//     重设密码（例如展示前崩溃）；ready 不再改动；
//   - 强认证未配置时状态保持 setup_verified（受限配置流程），本地控制台不被 root
//     自身 MFA 缺失锁死；
//   - 密码只存在于调用参数/一次性结果中，不写日志、审计、配置文件或临时文件。

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"path/filepath"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/config"
	"github.com/kagurazakayashi/EvernightLogin/errs"
	"github.com/kagurazakayashi/EvernightLogin/internal/appcore"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/bootstrap"
	"github.com/kagurazakayashi/EvernightLogin/internal/serverapp"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// 283 错误。
var (
	// ErrRootAlreadyInitialized 表示 root 已完整初始化，不能重复创建/覆盖。
	ErrRootAlreadyInitialized = errors.New("实例已有完整 root，拒绝重复创建")
	// ErrRootExistingUnmanaged 表示数据库存在 root 但缺少初始化记录，必须人工确认。
	ErrRootExistingUnmanaged = errors.New("数据库存在 root 但缺少初始化记录，本画面不会自动接管")
	// ErrRootUsernameFixed 表示创建阶段只接受保留用户名 root；改名在本地维护画面进行。
	ErrRootUsernameFixed = errors.New("root 保留用户名固定为 root；创建后可在本地维护画面改名")
	// ErrRootPasswordWeak 表示密码未通过正式密码策略。
	ErrRootPasswordWeak = errors.New("root 密码未通过密码策略")
)

// RootInitRequest 是 root 创建/恢复输入。
type RootInitRequest struct {
	// Username 只接受空值或保留名 root；其他值返回 ErrRootUsernameFixed。
	Username string
	// Nickname 是 root 昵称；空值使用正式流程默认昵称。
	Nickname string
	// Language/Timezone 可空，使用正式流程默认值。
	Language string
	Timezone string
	// Password 是操作者输入的强密码；空值且 GeneratePassword=true 时自动生成。
	Password string
	// GeneratePassword 为真且 Password 为空时生成高熵临时密码。
	GeneratePassword bool
	// ResetExistingPassword 为真时，对已处于 setup_verified 的 root 执行本地重设
	// 密码（用于上次展示前崩溃等恢复）；默认 false 只读并返回既有状态。
	ResetExistingPassword bool
}

// RootInitOptions 是本地维护参数。
type RootInitOptions struct {
	ConfigPath  string
	InstanceDir string
	OperatorID  string
	Purpose     string
	// MasterKeyFile 显式主密钥文件路径；空时按配置 secrets.master_key 或实例目录
	// 约定解析。root 创建阶段不生成新主密钥（数据库已有初始化材料）。
	MasterKeyFile string
	// Lock 是已持有的排他维护锁；nil 时按 OperatorID/InstanceDir 自行取得。
	Lock *MaintenanceLock
	Now  func() time.Time
	// Logger 记录状态，不含密码/凭证秘密。
	Logger *slog.Logger
}

// RootInitResult 是 root 创建/恢复结果；GeneratedPassword 只在本次调用内存中存在，
// 调用方展示一次后必须丢弃，绝不落盘。
type RootInitResult struct {
	State              bootstrap.State
	StateDescription   string
	RootUserID         string
	RootUsername       string
	RootExists         bool
	Created            bool
	Reentry            bool
	PasswordReset      bool
	StrongAuthRequired bool
	RequiredSteps      []string
	SecurityVersion    int64
	PendingStrongAuth  bool
	// GeneratedPassword 只在自动生成密码时非空；一次展示，禁止日志/审计/持久化。
	GeneratedPassword string
	// Note 是可展示的后续依赖说明。
	Note string
}

// RootInitStatus 是只读的 root 初始化状态快照。
type RootInitStatus struct {
	State            bootstrap.State
	StateDescription string
	RootExists       bool
	RootUserID       string
	RootUsername     string
}

// InspectRootInitialization 只读查询 root 初始化状态，不创建/解密密码。
func InspectRootInitialization(ctx context.Context, cfg config.Config, options RootInitOptions) (RootInitStatus, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := cfg.Validate(); err != nil {
		return RootInitStatus{}, fmt.Errorf("配置未通过校验: %w", err)
	}
	runtime, err := openRootInitRuntime(ctx, cfg, options)
	if err != nil {
		return RootInitStatus{}, err
	}
	defer runtime.close()
	status, err := runtime.bootstrap.Status(ctx, runtime.bootstrapCaller)
	if err != nil {
		return RootInitStatus{}, fmt.Errorf("读取初始化状态失败: %w", err)
	}
	result := RootInitStatus{State: status.State, StateDescription: status.State.Description(),
		RootExists: status.RootExists, RootUserID: status.RootUserID, RootUsername: status.RootUsername}
	return result, nil
}

// InitializeRoot 创建/恢复唯一 root。成功返回真实状态；任何失败都不伪造成功。
func InitializeRoot(ctx context.Context, cfg config.Config, request RootInitRequest,
	options RootInitOptions) (RootInitResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := cfg.Validate(); err != nil {
		return RootInitResult{}, fmt.Errorf("配置未通过校验: %w", err)
	}
	username := strings.TrimSpace(request.Username)
	if username != "" && !strings.EqualFold(username, bootstrap.RootUsername) {
		return RootInitResult{}, ErrRootUsernameFixed
	}
	password := request.Password
	if strings.TrimSpace(password) == "" {
		if !request.GeneratePassword {
			return RootInitResult{}, fmt.Errorf("%w: 请提供强密码或选择自动生成", ErrRootPasswordWeak)
		}
		generated, genErr := generateRootPassword()
		if genErr != nil {
			return RootInitResult{}, fmt.Errorf("生成 root 密码失败: %w", genErr)
		}
		password = generated
	}
	policy := authn.DefaultPasswordPolicy()
	if err := policy.Check(password, []string{bootstrap.RootUsername, request.Nickname}); err != nil {
		return RootInitResult{}, fmt.Errorf("%w: %v", ErrRootPasswordWeak, err)
	}
	runtime, err := openRootInitRuntime(ctx, cfg, options)
	if err != nil {
		return RootInitResult{}, err
	}
	defer runtime.close()
	defer func() { password = "" }()

	status, err := runtime.bootstrap.Status(ctx, runtime.bootstrapCaller)
	if err != nil {
		return RootInitResult{}, fmt.Errorf("读取初始化状态失败: %w", err)
	}
	result := RootInitResult{State: status.State, StateDescription: status.State.Description(),
		RootUserID: status.RootUserID, RootUsername: status.RootUsername, RootExists: status.RootExists}
	switch status.State {
	case bootstrap.StateExistingRoot:
		return result, ErrRootExistingUnmanaged
	case bootstrap.StateReady:
		return result, fmt.Errorf("%w：状态 %s", ErrRootAlreadyInitialized, status.State)
	case bootstrap.StateSetupVerified:
		result.Reentry = true
		if !request.ResetExistingPassword {
			result.Note = "root 已创建且正式密码已设置；如需本地重设密码，请明确选择“重设 root 密码”。"
			return result, nil
		}
		// 明确重设：复用正式 SetRootPassword，旧密码不被读取或回显。
		requestID := errs.NewRequestID()
		passwordResult, setErr := runtime.authn.SetRootPassword(ctx, runtime.authnCaller,
			authn.SetRootPasswordRequest{RootUserID: status.RootUserID,
				NewPassword: password, RequestID: requestID})
		if setErr != nil {
			return result, fmt.Errorf("本地重设 root 密码失败: %w", setErr)
		}
		result.PasswordReset = true
		result.State = passwordResult.State
		result.StateDescription = passwordResult.State.Description()
		result.StrongAuthRequired = passwordResult.StrongAuthRequired
		result.SecurityVersion = passwordResult.SecurityVersion
		result.RequiredSteps = describeRootSteps(passwordResult.RequiredSteps)
		result.PendingStrongAuth = passwordResult.StrongAuthRequired
		result.GeneratedPassword = generatedPasswordOnly(request, password)
		result.Note = "密码已重设；旧会话/凭证按正式流程失效。"
		return result, nil
	case bootstrap.StatePendingSetup:
		result.Reentry = true
		reissued, reissueErr := runtime.bootstrap.ReissueSetupCredential(ctx,
			runtime.bootstrapCaller, bootstrap.ReissueSetupCredentialRequest{})
		if reissueErr != nil {
			return result, fmt.Errorf("重新签发一次性配置凭证失败: %w", reissueErr)
		}
		if redeemErr := runtime.redeem(ctx, reissued.SetupCredential.ID,
			reissued.SetupCredential.Secret.Reveal()); redeemErr != nil {
			return result, fmt.Errorf("兑换一次性配置凭证失败: %w", redeemErr)
		}
		passwordResult, setErr := runtime.authn.SetRootPassword(ctx, runtime.authnCaller,
			authn.SetRootPasswordRequest{RootUserID: status.RootUserID,
				NewPassword: password, RequestID: errs.NewRequestID()})
		if setErr != nil {
			return result, fmt.Errorf("写入 root 正式密码失败（可重新进入本画面继续）: %w", setErr)
		}
		result.Created = true
		result.State = passwordResult.State
		result.StateDescription = passwordResult.State.Description()
		result.StrongAuthRequired = passwordResult.StrongAuthRequired
		result.SecurityVersion = passwordResult.SecurityVersion
		result.RequiredSteps = describeRootSteps(passwordResult.RequiredSteps)
		result.PendingStrongAuth = passwordResult.StrongAuthRequired
		result.GeneratedPassword = generatedPasswordOnly(request, password)
		result.Note = "已从受限待配置状态恢复：root 已创建并写入正式密码；强认证配置前仍受限。"
		return result, nil
	case bootstrap.StateUninitialized:
		initializeResult, initErr := runtime.bootstrap.Initialize(ctx, runtime.bootstrapCaller,
			bootstrap.InitializeRequest{RootNickname: strings.TrimSpace(request.Nickname),
				RootLanguage: strings.TrimSpace(request.Language),
				RootTimezone: strings.TrimSpace(request.Timezone)})
		if initErr != nil {
			if errors.Is(initErr, bootstrap.ErrAlreadyInitialized) {
				return result, ErrRootAlreadyInitialized
			}
			return result, fmt.Errorf("创建唯一 root 失败: %w", initErr)
		}
		if redeemErr := runtime.redeem(ctx, initializeResult.SetupCredential.ID,
			initializeResult.SetupCredential.Secret.Reveal()); redeemErr != nil {
			return result, fmt.Errorf("兑换一次性配置凭证失败（root 已创建，可重新进入继续）: %w", redeemErr)
		}
		passwordResult, setErr := runtime.authn.SetRootPassword(ctx, runtime.authnCaller,
			authn.SetRootPasswordRequest{RootUserID: initializeResult.Root.ID,
				NewPassword: password, RequestID: errs.NewRequestID()})
		if setErr != nil {
			return result, fmt.Errorf("写入 root 正式密码失败（root 已创建并受限，可重新进入继续）: %w", setErr)
		}
		result.RootUserID = passwordResult.RootUserID
		result.RootUsername = bootstrap.RootUsername
		result.RootExists = true
		result.Created = true
		result.State = passwordResult.State
		result.StateDescription = passwordResult.State.Description()
		result.StrongAuthRequired = passwordResult.StrongAuthRequired
		result.SecurityVersion = passwordResult.SecurityVersion
		result.RequiredSteps = describeRootSteps(passwordResult.RequiredSteps)
		result.PendingStrongAuth = passwordResult.StrongAuthRequired
		result.GeneratedPassword = generatedPasswordOnly(request, password)
		result.Note = "root 已创建并写入正式密码；完成强认证配置前不能用于完整远程登录，本地控制台不受影响。"
		return result, nil
	default:
		return result, fmt.Errorf("未知初始化状态: %q", status.State)
	}
}

// rootInitRuntime 是 root 创建所需的正式生产装配（存储/密钥/审计/认证/bootstrap）。
type rootInitRuntime struct {
	store           *storagesqlite.Store
	authn           *authn.Service
	authnCaller     authn.Caller
	bootstrap       *bootstrap.Service
	bootstrapCaller bootstrap.Caller
	lock            *MaintenanceLock
	logger          *slog.Logger
}

func (r *rootInitRuntime) redeem(ctx context.Context, credentialID, secret string) error {
	if r == nil || r.bootstrap == nil {
		return errors.New("初始化服务未装配")
	}
	_, err := r.bootstrap.RedeemSetupCredential(ctx, r.bootstrapCaller,
		bootstrap.RedeemSetupCredentialRequest{CredentialID: credentialID, Secret: secret})
	return err
}

func (r *rootInitRuntime) close() {
	if r == nil {
		return
	}
	if r.lock != nil {
		_ = r.lock.Release()
		r.lock = nil
	}
	if r.store != nil {
		_ = r.store.Close()
		r.store = nil
	}
}

// openRootInitRuntime 打开 root 初始化所需的正式生产装配；任一步失败都返回错误。
func openRootInitRuntime(ctx context.Context, cfg config.Config, options RootInitOptions) (*rootInitRuntime, error) {
	instanceDir := strings.TrimSpace(options.InstanceDir)
	if instanceDir == "" {
		if configPath := strings.TrimSpace(options.ConfigPath); configPath != "" {
			absoluteConfig, err := filepath.Abs(configPath)
			if err != nil {
				return nil, fmt.Errorf("配置路径无效: %w", err)
			}
			instanceDir = filepath.Dir(absoluteConfig)
		}
	}
	if instanceDir == "" {
		return nil, errors.New("缺少实例目录，无法取得维护锁")
	}
	absoluteInstance, err := filepath.Abs(instanceDir)
	if err != nil {
		return nil, fmt.Errorf("实例目录无效: %w", err)
	}
	operatorID := strings.TrimSpace(options.OperatorID)
	if operatorID == "" {
		return nil, fmt.Errorf("%w: 缺少本地操作者标识", ErrIdentityInvalid)
	}
	lock := options.Lock
	if lock == nil {
		identity, identityErr := LocalMaintenanceIdentity(absoluteInstance)
		if identityErr != nil {
			return nil, identityErr
		}
		purpose := strings.TrimSpace(options.Purpose)
		if purpose == "" {
			purpose = "创建或恢复唯一 root"
		}
		acquired, lockErr := AcquireMaintenanceLock(ctx, LockRequest{
			InstanceDir: absoluteInstance, Purpose: purpose, Operator: identity})
		if lockErr != nil {
			return nil, lockErr
		}
		lock = acquired
	}
	runtime := &rootInitRuntime{lock: lock}
	success := false
	defer func() {
		if !success {
			runtime.close()
		}
	}()
	now := options.Now
	if now == nil {
		now = time.Now
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	runtime.logger = logger
	masterKeyFile := strings.TrimSpace(options.MasterKeyFile)
	if !cfg.Secrets.MasterKey.IsSet() && masterKeyFile == "" {
		masterKeyFile = defaultDBMasterKeyFile(absoluteInstance)
	}
	keyring, _, err := appcore.LoadKeyring(ctx, cfg, masterKeyFile, false, now)
	if err != nil {
		return nil, fmt.Errorf("加载主密钥失败: %w", err)
	}
	store, err := appcore.OpenStore(ctx, cfg, nil)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %w", err)
	}
	runtime.store = store
	auditRecorder, err := appcore.NewAuditRecorder(ctx, store, logger, now)
	if err != nil {
		return nil, fmt.Errorf("构造审计失败: %w", err)
	}
	deps := serverapp.Deps{Config: cfg, ConfigPath: options.ConfigPath, Store: store,
		Keyring: keyring, Audit: auditRecorder, Logger: logger, Now: now}
	services, err := serverapp.BuildServices(deps)
	if err != nil {
		return nil, fmt.Errorf("装配认证服务失败: %w", err)
	}
	bootstrapService, bootstrapCaller, err := serverapp.BuildBootstrapService(deps, operatorID)
	if err != nil {
		return nil, fmt.Errorf("装配首次初始化服务失败: %w", err)
	}
	authnCaller, err := authn.LocalAdminCaller(operatorID)
	if err != nil {
		return nil, fmt.Errorf("构造本地认证操作者失败: %w", err)
	}
	runtime.authn = services.Authn
	runtime.authnCaller = authnCaller
	runtime.bootstrap = bootstrapService
	runtime.bootstrapCaller = bootstrapCaller
	success = true
	return runtime, nil
}

// describeRootSteps 把正式流程的 RequiredSteps 转为中文短句。
func describeRootSteps(steps []authn.Step) []string {
	labels := make([]string, 0, len(steps))
	for _, step := range steps {
		labels = append(labels, describeRootStep(step))
	}
	return labels
}

// generatedPasswordOnly 只在自动生成密码时返回一次性明文；手输密码不回显。
func generatedPasswordOnly(request RootInitRequest, password string) string {
	if strings.TrimSpace(request.Password) != "" {
		return ""
	}
	return password
}

// describeRootStep 把正式流程的步骤标识转为可展示中文。
func describeRootStep(step authn.Step) string {
	switch step {
	case authn.StepStrongAuthSetup:
		return "绑定强认证因素（TOTP/Passkey）"
	case authn.StepSecondFactor:
		return "完成第二因素验证"
	case authn.StepPasswordChange:
		return "首次登录修改密码"
	default:
		return string(step)
	}
}

// generateRootPassword 生成满足默认策略的高熵临时密码（至少 20 字符，含多类字符）。
func generateRootPassword() (string, error) {
	const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	const lower = "abcdefghijkmnopqrstuvwxyz"
	const digits = "23456789"
	const symbols = "!@#$%^&*-_=+"
	groups := []string{upper, lower, digits, symbols}
	var builder strings.Builder
	builder.Grow(24)
	for _, group := range groups {
		ch, err := randomRune(group)
		if err != nil {
			return "", err
		}
		builder.WriteRune(ch)
	}
	all := upper + lower + digits + symbols
	for i := 0; i < 20; i++ {
		ch, err := randomRune(all)
		if err != nil {
			return "", err
		}
		builder.WriteRune(ch)
	}
	password := builder.String()
	// 洗牌避免固定字符类别位置。
	runes := []rune(password)
	for i := len(runes) - 1; i > 0; i-- {
		index, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", err
		}
		j := int(index.Int64())
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes), nil
}

func randomRune(alphabet string) (rune, error) {
	runes := []rune(alphabet)
	index, err := rand.Int(rand.Reader, big.NewInt(int64(len(runes))))
	if err != nil {
		return 0, err
	}
	return runes[index.Int64()], nil
}
