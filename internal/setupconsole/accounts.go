package setupconsole

// 步骤 284：常用账户类型与批量初始化方案。
//
// 边界：
//   - root 已存在时只展示其特殊资格，不创建第二个 root；
//   - 账户类型复用已安装的预设角色（system_admin/support/auditor/normal_user）；
//   - 具有“直接改名/改密客服”资格的类型依赖独立权限角色模板；当前预设目录没有
//     该模板时明确标不可用，不用更高权限角色伪造等价权限（依赖状态如实展示）；
//   - 临时密码只在创建/生成时一次展示，RequireChange=true 首次登录改密；不写日志、
//     不落盘；重复执行不覆盖已有口令或角色（仅补可加的缺失角色）；
//   - 全部写操作在排他维护锁内通过正式领域服务完成（account+authn+role），不直接
//     写数据库，不复制第二套账户/密码核心。

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/config"
	"github.com/kagurazakayashi/EvernightLogin/errs"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	accountsqlite "github.com/kagurazakayashi/EvernightLogin/internal/account/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/appcore"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
	rolesqlite "github.com/kagurazakayashi/EvernightLogin/internal/role/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/serverapp"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// 284 账户方案错误。
var (
	// ErrAccountSchemeUnavailable 表示方案依赖的角色模板尚未实现，不能伪造等价权限。
	ErrAccountSchemeUnavailable = errors.New("账户方案依赖的独立权限角色模板尚未实现")
	// ErrAccountConflict 表示目标用户名已存在（不覆盖既有账户）。
	ErrAccountConflict = errors.New("用户名已存在，未覆盖既有账户")
)

// AccountScheme 是账户类型方案（角色模板选择，不是预设恢复）。
type AccountScheme struct {
	Key         string
	Label       string
	Description string
	// RoleKeys 是系统预设角色键；root 方案不出现在可创建列表。
	RoleKeys []string
	// DirectPermissionKeys 是方案要求的独立高风险权限（用于展示/依赖检查）。
	DirectPermissionKeys []string
	// Available 为 false 时 UnavailableReason 说明真实依赖缺口。
	Available         bool
	UnavailableReason string
	RootQualification bool
}

// AccountSchemes 返回内置账户类型方案；不包含可创建的第二个 root。
func AccountSchemes() []AccountScheme {
	return []AccountScheme{
		{Key: "root", Label: "root（唯一系统所有者）", RootQualification: true,
			Description: "实例创建时产生的唯一受保护 root；不通过批量方案创建，也不可分配为普通角色。",
			Available:   true},
		{Key: "system_admin", Label: "系统管理员", RoleKeys: []string{"system_admin"},
			DirectPermissionKeys: []string{"users.username.change.other", "users.password.reset.other"},
			Description:          "预设系统管理员角色，含用户/角色管理与两项直接管理权限；高风险。",
			Available:            true},
		{Key: "support", Label: "普通客服", RoleKeys: []string{"support"},
			Description: "预设客服角色；不自动获得全局改名/改密能力。", Available: true},
		{Key: "support_direct_rename", Label: "客服（可直接改用户名）",
			RoleKeys: []string{"support"}, DirectPermissionKeys: []string{"users.username.change.other"},
			Description: "客服 + 独立直接改名权限。",
			UnavailableReason: "当前预设目录没有仅含 users.username.change.other 的客服角色模板；" +
				"不复用系统管理员角色伪造等价权限，需后续角色模板落地。",
			Available: false},
		{Key: "support_direct_reset", Label: "客服（可直接重置密码）",
			RoleKeys: []string{"support"}, DirectPermissionKeys: []string{"users.password.reset.other"},
			Description: "客服 + 独立直接重置密码权限。",
			UnavailableReason: "当前预设目录没有仅含 users.password.reset.other 的客服角色模板；" +
				"不复用系统管理员角色伪造等价权限，需后续角色模板落地。",
			Available: false},
		{Key: "auditor", Label: "审计员", RoleKeys: []string{"auditor"},
			Description: "预设审计员角色。", Available: true},
		{Key: "normal_user", Label: "普通用户", RoleKeys: []string{"normal_user"},
			Description: "预设普通用户角色。", Available: true},
	}
}

// LookupAccountScheme 按 key 查找方案。
func LookupAccountScheme(key string) (AccountScheme, bool) {
	key = strings.TrimSpace(key)
	for _, scheme := range AccountSchemes() {
		if scheme.Key == key {
			return scheme, true
		}
	}
	return AccountScheme{}, false
}

// AccountDraft 是待创建账户输入；密码不落模型/日志。
type AccountDraft struct {
	Username string
	Nickname string
	// SchemeKey 是 AccountSchemes 的 Key（不能是 root）。
	SchemeKey string
	// Password 手动密码；空值且 GeneratePassword=true 时自动生成。
	Password string
	// GeneratePassword 为真时生成临时密码并一次性返回。
	GeneratePassword bool
}

// AccountApplyOptions 是批量账户创建的本地维护参数。
type AccountApplyOptions struct {
	ConfigPath  string
	InstanceDir string
	OperatorID  string
	Purpose     string
	Lock        *MaintenanceLock
	Now         func() time.Time
}

// AccountApplyItem 是单个账户的真实结果。
type AccountApplyItem struct {
	Username        string
	SchemeKey       string
	UserID          string
	RoleKeys        []string
	Created         bool
	SkippedExisting bool
	RequireChange   bool
	// GeneratedPassword 只在自动生成且创建成功时非空；调用方一次展示后必须丢弃。
	GeneratedPassword string
}

// AccountApplyResult 是批量账户方案结果；Errors 非空表示部分/全部失败。
type AccountApplyResult struct {
	Accounts []AccountApplyItem
	Errors   []string
}

// accountAdminRuntime 是本地批量账户创建所需的正式领域服务装配。
type accountAdminRuntime struct {
	store      *storagesqlite.Store
	accounts   *account.Service
	roles      *role.Service
	authn      *authn.Service
	accountC   account.Caller
	roleC      role.Caller
	authnC     authn.Caller
	operatorID string
}

func (runtime *accountAdminRuntime) close() {
	if runtime == nil || runtime.store == nil {
		return
	}
	_ = runtime.store.Close()
	runtime.store = nil
}

// ApplyAccountScheme 在排他维护锁内按方案创建账户；root 必须已存在。
func ApplyAccountScheme(ctx context.Context, detection Detection, drafts []AccountDraft,
	options AccountApplyOptions) (AccountApplyResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	result := AccountApplyResult{}
	if detection.Kind != StateReady {
		return result, fmt.Errorf("%w: 当前实例状态为 %s，需先完成数据库与 root 创建",
			ErrLocalRuntimeUnavailable, detection.Kind.Label())
	}
	if len(drafts) == 0 {
		return result, errors.New("请选择至少一个要创建的账户")
	}
	if !detection.ConfigLoaded {
		return result, fmt.Errorf("%w: 配置未成功加载", ErrLocalRuntimeUnavailable)
	}
	instanceDir := strings.TrimSpace(options.InstanceDir)
	if instanceDir == "" {
		configPath := strings.TrimSpace(options.ConfigPath)
		if configPath == "" {
			configPath = detection.ConfigPath
		}
		if configPath != "" {
			absoluteConfig, err := filepath.Abs(configPath)
			if err != nil {
				return result, fmt.Errorf("配置路径无效: %w", err)
			}
			instanceDir = filepath.Dir(absoluteConfig)
		}
	}
	if instanceDir == "" {
		return result, errors.New("缺少实例目录，无法取得维护锁")
	}
	operatorID := strings.TrimSpace(options.OperatorID)
	if operatorID == "" {
		return result, fmt.Errorf("%w: 缺少本地操作者标识", ErrIdentityInvalid)
	}
	lock := options.Lock
	if lock == nil {
		identity, identityErr := LocalMaintenanceIdentity(instanceDir)
		if identityErr != nil {
			return result, identityErr
		}
		purpose := strings.TrimSpace(options.Purpose)
		if purpose == "" {
			purpose = "批量创建常用账户"
		}
		acquired, lockErr := AcquireMaintenanceLock(ctx, LockRequest{
			InstanceDir: instanceDir, Purpose: purpose, Operator: identity})
		if lockErr != nil {
			return result, lockErr
		}
		lock = acquired
	}
	defer func() { _ = lock.Release() }()
	runtime, err := openAccountAdminRuntime(ctx, detection.Config, instanceDir, operatorID,
		options.Now)
	if err != nil {
		return result, err
	}
	defer runtime.close()
	roles, err := runtime.roles.ListRoles(ctx, runtime.roleC,
		role.ListRequest{ScopeID: "system", Limit: 100})
	if err != nil {
		return result, fmt.Errorf("读取可分配预设角色失败: %w", err)
	}
	roleByKey := make(map[string]role.Role, len(roles.Roles))
	for _, item := range roles.Roles {
		roleByKey[item.Key] = item
	}
	for _, draft := range drafts {
		scheme, known := LookupAccountScheme(draft.SchemeKey)
		if !known {
			result.Errors = append(result.Errors, fmt.Sprintf("%s：未知账户方案 %q", draft.Username, draft.SchemeKey))
			continue
		}
		if scheme.RootQualification {
			result.Errors = append(result.Errors, "root 是唯一受保护账户，不能通过批量方案创建；请使用 root 创建画面")
			continue
		}
		if !scheme.Available {
			return result, fmt.Errorf("%w: %s（%s）", ErrAccountSchemeUnavailable, scheme.Label, scheme.UnavailableReason)
		}
		username := strings.TrimSpace(draft.Username)
		if username == "" {
			result.Errors = append(result.Errors, "账户用户名为空")
			continue
		}
		missing := make([]string, 0)
		roleIDs := make([]string, 0, len(scheme.RoleKeys))
		for _, roleKey := range scheme.RoleKeys {
			item, found := roleByKey[roleKey]
			if !found {
				missing = append(missing, roleKey)
				continue
			}
			roleIDs = append(roleIDs, item.ID)
		}
		if len(missing) > 0 {
			return result, fmt.Errorf("%w：缺少预设角色 %s；请先安装系统预设（选择角色模板≠恢复预设）",
				ErrPresetRolesMissing, strings.Join(missing, "、"))
		}
		// 重名：不覆盖既有口令/角色，只补可加的缺失角色（幂等补齐部分失败）。
		if existing, foundExisting, lookupErr := runtime.findUser(ctx, username); lookupErr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s：检查重名失败: %v", username, lookupErr))
			continue
		} else if foundExisting {
			assignErrors := runtime.assignRoles(ctx, existing.ID, roleIDs)
			result.Errors = append(result.Errors, assignErrors...)
			result.Accounts = append(result.Accounts, AccountApplyItem{Username: existing.Username,
				SchemeKey: scheme.Key, UserID: existing.ID, RoleKeys: scheme.RoleKeys,
				SkippedExisting: true, RequireChange: false})
			continue
		}
		password := draft.Password
		if strings.TrimSpace(password) == "" {
			if !draft.GeneratePassword {
				result.Errors = append(result.Errors,
					fmt.Sprintf("%s：缺少密码且未选择自动生成", username))
				continue
			}
			generated, genErr := generateRootPassword()
			if genErr != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s：生成临时密码失败", username))
				continue
			}
			password = generated
		}
		if policyErr := authn.DefaultPasswordPolicy().Check(password,
			[]string{username, strings.TrimSpace(draft.Nickname)}); policyErr != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("%s：临时密码未通过密码策略: %v", username, policyErr))
			continue
		}
		user, createErr := runtime.accounts.CreateUser(ctx, runtime.accountC, account.CreateRequest{
			Username: username, Nickname: strings.TrimSpace(draft.Nickname)})
		if createErr != nil {
			if errors.Is(createErr, account.ErrUsernameTaken) {
				result.Errors = append(result.Errors,
					fmt.Sprintf("%s：并发创建检测到重名；未覆盖既有账户", username))
				continue
			}
			result.Errors = append(result.Errors, fmt.Sprintf("%s：创建账户失败: %v", username, createErr))
			continue
		}
		if _, setErr := runtime.authn.SetPassword(ctx, runtime.authnC,
			authn.SetPasswordRequest{TargetUserID: user.ID, NewPassword: password,
				RequireChange: true, RequestID: errs.NewRequestID()}); setErr != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("%s：账户已创建但设置初始密码失败（可用本地密码维护修复）: %v", username, setErr))
			continue
		}
		item := AccountApplyItem{Username: user.Username, SchemeKey: scheme.Key,
			UserID: user.ID, RoleKeys: scheme.RoleKeys, Created: true, RequireChange: true}
		if strings.TrimSpace(draft.Password) == "" {
			item.GeneratedPassword = password
		}
		if assignErrors := runtime.assignRoles(ctx, user.ID, roleIDs); len(assignErrors) > 0 {
			result.Errors = append(result.Errors, assignErrors...)
		}
		result.Accounts = append(result.Accounts, item)
	}
	if len(result.Errors) > 0 {
		return result, fmt.Errorf("账户方案部分失败：%s", strings.Join(result.Errors, "；"))
	}
	return result, nil
}

// findUser 精确匹配用户名（大小写不敏感，与账户唯一性规则一致）。
func (runtime *accountAdminRuntime) findUser(ctx context.Context, username string) (account.User, bool, error) {
	user, err := runtime.accounts.GetUserByUsername(ctx, runtime.accountC, username)
	if err != nil {
		if errors.Is(err, account.ErrUserNotFound) {
			return account.User{}, false, nil
		}
		return account.User{}, false, err
	}
	return user, true, nil
}

// assignRoles 给账户补齐方案角色；已分配返回 false 不算失败（幂等）。
func (runtime *accountAdminRuntime) assignRoles(ctx context.Context, userID string,
	roleIDs []string) []string {
	var failures []string
	for _, roleID := range roleIDs {
		if _, err := runtime.roles.AssignUserRole(ctx, runtime.roleC, roleID, userID); err != nil {
			failures = append(failures, fmt.Sprintf("%s：分配角色 %s 失败: %v", userID, roleID, err))
		}
	}
	return failures
}

// openAccountAdminRuntime 打开正式账户/角色/认证服务；本地初始化授权器只放行本进程
// 显式本地操作者。角色敏感策略在本地维护例外下沿用既有 Guard/授权器保守校验。
func openAccountAdminRuntime(ctx context.Context, cfg config.Config, instanceDir,
	operatorID string, now func() time.Time) (*accountAdminRuntime, error) {
	if now == nil {
		now = time.Now
	}
	masterKeyFile := defaultDBMasterKeyFile(instanceDir)
	keyring, _, err := appcore.LoadKeyring(ctx, cfg, masterKeyFile, false, now)
	if err != nil {
		return nil, fmt.Errorf("加载主密钥失败: %w", err)
	}
	store, err := appcore.OpenStore(ctx, cfg, nil)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %w", err)
	}
	runtime := &accountAdminRuntime{store: store, operatorID: operatorID}
	success := false
	defer func() {
		if !success {
			runtime.close()
		}
	}()
	auditRecorder, err := appcore.NewAuditRecorder(ctx, store, discardLogger(), now)
	if err != nil {
		return nil, fmt.Errorf("构造审计失败: %w", err)
	}
	deps := serverapp.Deps{Config: cfg, Store: store, Keyring: keyring, Audit: auditRecorder,
		Now: now,
		// 本地维护身份以 OS 访问授权为信任根，不要求远程 MFA/再次认证；显式
		// 过渡开关仅用于本机初始化装配，普通远程入口不得复用。
		AllowLegacyWithoutSensitive: true}
	coreServices, err := serverapp.BuildServicesWithHooks(deps,
		serverapp.SecurityHooks{Sensitive: localMaintenanceSensitiveRunner{}})
	if err != nil {
		return nil, fmt.Errorf("装配认证服务失败: %w", err)
	}
	accountStore, err := accountsqlite.New(store)
	if err != nil {
		return nil, fmt.Errorf("构造账户存储失败: %w", err)
	}
	accountAuthorizer, err := account.NewLocalBootstrapAuthorizer([]string{operatorID})
	if err != nil {
		return nil, fmt.Errorf("构造本地账户授权器失败: %w", err)
	}
	accountService, err := account.New(account.Options{Store: accountStore,
		Audit: auditRecorder, Authorizer: accountAuthorizer, Now: now})
	if err != nil {
		return nil, fmt.Errorf("构造账户服务失败: %w", err)
	}
	roleStore, err := rolesqlite.New(store)
	if err != nil {
		return nil, fmt.Errorf("构造角色存储失败: %w", err)
	}
	roleAuthorizer, err := role.NewStaticAuthorizer(role.AuthorizerOptions{
		LocalAdminIDs: []string{operatorID}})
	if err != nil {
		return nil, fmt.Errorf("构造本地角色授权器失败: %w", err)
	}
	roleService, err := role.New(role.Options{Store: roleStore, Audit: auditRecorder,
		Authorizer: roleAuthorizer, Transfers: localBootstrapGuard{},
		AllowLegacyWithoutSensitive: true, Now: now})
	if err != nil {
		return nil, fmt.Errorf("构造角色服务失败: %w", err)
	}
	accountCaller, err := account.LocalBootstrapCaller(operatorID)
	if err != nil {
		return nil, fmt.Errorf("构造本地账户操作者失败: %w", err)
	}
	roleCaller, err := role.LocalBootstrapCaller(operatorID)
	if err != nil {
		return nil, fmt.Errorf("构造本地角色操作者失败: %w", err)
	}
	authnCaller, err := authn.LocalAdminCaller(operatorID)
	if err != nil {
		return nil, fmt.Errorf("构造本地认证操作者失败: %w", err)
	}
	runtime.accounts = accountService
	runtime.roles = roleService
	runtime.authn = coreServices.Authn
	runtime.accountC = accountCaller
	runtime.roleC = roleCaller
	runtime.authnC = authnCaller
	success = true
	return runtime, nil
}

// localMaintenanceSensitiveRunner 是本地初始化装配的敏感操作收敛实现：仅放行
// 本地管理员/系统 actor，不要求远程 MFA；普通用户与匿名一律拒绝。它只在本机
// 控制台装配中使用，不接线到生产 HTTP/普通门面。
type localMaintenanceSensitiveRunner struct{}

func (localMaintenanceSensitiveRunner) Authorize(ctx context.Context,
	caller reauth.Caller, request reauth.Request) (reauth.Result, error) {
	actor := caller.Actor()
	if actor.Type != audit.ActorLocalAdmin && actor.Type != audit.ActorSystem {
		return reauth.Result{}, errors.New("本地维护敏感操作只允许本地管理员/系统身份")
	}
	return reauth.Result{OperationID: request.OperationID, TargetType: request.TargetType,
		TargetID: request.TargetID, Description: request.Description, UserID: actor.ID,
		Method: "local_os", RequestID: request.RequestID}, nil
}

func (localMaintenanceSensitiveRunner) NotifyOutcome(ctx context.Context,
	result reauth.Result, outcome reauth.Outcome) error {
	return nil
}

// discardLogger 返回丢弃输出的静默 logger。
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}
