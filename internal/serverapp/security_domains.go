package serverapp

// 账户/安全/客服域装配：为内置页面提供真实 MFA、TOTP、Passkey、恢复代码、
// 找回密码、头像、邮箱变更、客服求助与人工恢复服务。
//
// 边界：
//   - 全部服务使用真实 internal 领域包与真实 SQLite 存储；敏感操作（TOTP/Passkey
//     绑定与解除、恢复代码生成、邮箱变更、用户名变更）经 SecurityGate 的真实
//     reauth/policy 判定，未通过即拒绝。
//   - 当前部署没有配置真实邮件发送器：MFA 邮件因素、找回密码、安全告知会以明确
//     “未配置发送器”失败并留痕，不真实外发；TOTP/Passkey 不依赖邮件。
//   - 人工恢复默认关闭（root 制度未配置），执行器是显式 fail-closed 实现：即使
//     页面发起也会返回明确“执行器未装配”，不会伪造恢复成功。
//   - 强认证初始化（root 首次绑定 Passkey）只允许真实 root，且必须先完成首次初始化
//     与正式密码设置；普通用户不得到达该流程。

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authfact"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	authnsqlite "github.com/kagurazakayashi/EvernightLogin/internal/authn/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/avatar"
	avatarsqlite "github.com/kagurazakayashi/EvernightLogin/internal/avatar/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/bootstrap"
	bootstrapsqlite "github.com/kagurazakayashi/EvernightLogin/internal/bootstrap/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/emailchange"
	emailchangesqlite "github.com/kagurazakayashi/EvernightLogin/internal/emailchange/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/manualrecovery"
	manualrecoverysqlite "github.com/kagurazakayashi/EvernightLogin/internal/manualrecovery/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/mfa"
	mfasqlite "github.com/kagurazakayashi/EvernightLogin/internal/mfa/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/passkey"
	passkeysqlite "github.com/kagurazakayashi/EvernightLogin/internal/passkey/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
	passwordresetsqlite "github.com/kagurazakayashi/EvernightLogin/internal/passwordreset/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/recovery"
	recoverysqlite "github.com/kagurazakayashi/EvernightLogin/internal/recovery/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/securitycenter"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/support"
	supportsqlite "github.com/kagurazakayashi/EvernightLogin/internal/support/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/totp"
	totpsqlite "github.com/kagurazakayashi/EvernightLogin/internal/totp/sqlite"
)

// SecurityDomains 是账户/安全/客服页面使用的真实领域服务集合。
type SecurityDomains struct {
	TOTP           *totp.Service
	Passkey        *passkey.Service
	MFA            *mfa.Service
	Recovery       *recovery.Service
	PasswordReset  *passwordreset.Service
	Avatar         *avatar.Service
	EmailChange    *emailchange.Service
	Support        *support.Service
	ManualRecovery *manualrecovery.Service
	// StrongFactors 供认证服务判断账户是否已绑定强因素（TOTP/Passkey）。
	StrongFactors authn.StrongFactorPresence
	// PasskeySecondFactor 是 MFA 第二步 Passkey 适配器（未启用时是显式拒绝实现）。
	PasskeySecondFactor mfa.SecondFactorPasskey
}

// strongFactorSource 汇总 TOTP 与 Passkey 的强因素存在性。
type strongFactorSource struct {
	totp     *totp.Service
	passkeys *passkey.Service
}

// HasStrongFactor 实现 authn.StrongFactorPresence 与 mfa.StrongFactorSource。
func (s strongFactorSource) HasStrongFactor(ctx context.Context, userID string) (bool, error) {
	if s.totp != nil {
		active, err := s.totp.HasActive(ctx, userID)
		if err != nil {
			return false, err
		}
		if active {
			return true, nil
		}
	}
	if s.passkeys != nil {
		has, err := s.passkeys.HasSecondFactor(ctx, userID)
		if err != nil {
			return false, err
		}
		if has {
			return true, nil
		}
	}
	return false, nil
}

// BuildSecurityDomains 装配账户/安全/客服域服务。
func BuildSecurityDomains(deps Deps, services *Services, managed *ManagedServices,
	gate *SecurityGate) (*SecurityDomains, error) {
	if services == nil || services.Authn == nil || services.Sessions == nil ||
		services.Credential == nil || services.BootstrapStore == nil {
		return nil, fmt.Errorf("安全域装配缺少认证/会话/凭证/初始化存储服务")
	}
	if managed == nil || managed.Checker == nil || managed.Roots == nil {
		return nil, fmt.Errorf("安全域装配缺少生产授权适配层")
	}
	if gate == nil || gate.Reauth == nil {
		return nil, fmt.Errorf("安全域装配缺少敏感操作闸门")
	}
	mailURLs, urlErr := buildMailURLs(deps.Config)
	if deps.Config.Mail.Enabled && urlErr != nil {
		return nil, fmt.Errorf("CONFIG_INVALID: %w", urlErr)
	}
	// 邮箱变更走可靠投递（任务运行时已构造）；未启用邮件时保持 nil（失败留痕，
	// 不伪造送达）。
	var emailChangeMailer emailchange.EmailSender
	if deps.Config.Mail.Enabled && deps.MailDeliveryProvider != nil {
		if deliveries := deps.MailDeliveryProvider(); deliveries != nil {
			adapter, adapterErr := emailchange.NewDeliveryEmailSender(deliveries, deps.Mail.AppDisplayName())
			if adapterErr != nil {
				return nil, fmt.Errorf("构造邮箱变更邮件适配器失败: %w", adapterErr)
			}
			emailChangeMailer = adapter
		}
	}
	now := deps.Now
	if now == nil {
		now = time.Now
	}
	sealer, err := secrets.NewSealer(deps.Keyring, deps.Logger)
	if err != nil {
		return nil, fmt.Errorf("构造安全域加密器失败: %w", err)
	}
	// 步骤 194：把真实的“强制 MFA/强认证策略”与其他强因素存在性注入三个领域服务，
	// 否则各领域的“最后可用因素不可移除”保护在生产装配中不会生效（nil 策略等于
	// 从不强制）。策略来源是 authn 存储的真实强制要求（root 恒为 true；直接或经
	// 角色被要求的账户也为 true），读取失败由领域服务 fail-closed 拒绝移除。
	authnPolicyStore, err := authnsqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造强认证要求来源失败: %w", err)
	}
	mfaPolicy, err := securitycenter.NewMFAPolicy(authnPolicyStore)
	if err != nil {
		return nil, fmt.Errorf("构造强制 MFA 策略适配器失败: %w", err)
	}
	// Passkey 服务构造时需要“其他强因素（TOTP）”来源，而 TOTP 服务在本阶段稍后
	// 构造：用可后接线的适配器避免构造循环，接线前如实报告“没有其他强因素”。
	totpOtherForPasskey := securitycenter.NewTOTPOtherStrongFactor(nil)

	var passkeyService *passkey.Service
	if deps.Config.Passkey.Enabled {
		// 管理强认证依赖 Passkey 的用户验证（UV）。preferred/discouraged 会降低
		// 强认证强度，不允许与 root/管理会话要求并存：服务端硬性拒绝而非仅靠文档。
		uv := strings.ToLower(strings.TrimSpace(deps.Config.Passkey.UserVerification))
		if uv != "" && uv != "required" {
			return nil, fmt.Errorf("Passkey 用于管理强认证时必须配置 user_verification=required"+
				"（当前为 %q；preferred/discouraged 会降低强认证强度）", uv)
		}
		passkeyStore, storeErr := passkeysqlite.New(deps.Store)
		if storeErr != nil {
			return nil, fmt.Errorf("构造 Passkey 存储失败: %w", storeErr)
		}
		passkeyConfig := passkey.Config{
			RPID:          deps.Config.Passkey.RPID,
			RPDisplayName: deps.Config.Passkey.RPDisplayName,
			Origins:       append([]string(nil), deps.Config.Passkey.AllowedOrigins...),
		}
		switch strings.ToLower(strings.TrimSpace(deps.Config.Passkey.UserVerification)) {
		case "required", "":
			passkeyConfig.UserVerification = passkey.UserVerificationRequired
		case "preferred":
			passkeyConfig.UserVerification = passkey.UserVerificationPreferred
		case "discouraged":
			passkeyConfig.UserVerification = passkey.UserVerificationDiscouraged
		default:
			return nil, fmt.Errorf("Passkey user_verification 取值无效")
		}
		passkeyService, err = passkey.New(passkey.Options{
			Store: passkeyStore, Audit: deps.Audit, Sessions: services.Sessions,
			Reauth: gate.Reauth, Config: passkeyConfig,
			// 步骤 194：强制 MFA 且没有其他强因素（活动 TOTP）时拒绝删除最后一个
			// 第二步凭证；删除后立即撤销既有会话。
			MFAPolicy:          mfaPolicy,
			OtherStrongFactors: totpOtherForPasskey,
			SessionInvalidator: services.Sessions,
			Now:                now, Logger: deps.Logger,
		})
		if err != nil {
			return nil, fmt.Errorf("构造 Passkey 服务失败: %w", err)
		}
	}

	// 步骤 194：TOTP 服务注入真实强制策略与其他强因素（活动 Passkey），并在解除
	// 后立即撤销既有会话（同事务仍会递增 security_version）。
	totpStore, err := totpsqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造 TOTP 存储失败: %w", err)
	}
	totpService, err := totp.New(totp.Options{
		Store: totpStore, Audit: deps.Audit, Sealer: sealer,
		Reauth: gate.Reauth,
		// 强制 MFA 且没有其他强因素（活动 Passkey）时拒绝移除最后强因素。
		Policy: mfaPolicy, OtherFactors: securitycenter.NewPasskeyOtherStrongFactor(passkeyService),
		// 解除强因素后立即撤销既有会话（同事务仍会递增 security_version）。
		SessionInvalidator: services.Sessions,
		IssuerName:         "EvernightLogin",
		Now:                now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造 TOTP 服务失败: %w", err)
	}
	// 完成 Passkey 方向的“其他强因素”接线（此前为避免构造循环暂为 nil）。
	totpOtherForPasskey.SetTOTP(totpService)

	manualTargets := manualRecoveryTargets{store: deps.Store, keyring: deps.Keyring, roots: managed.Roots}
	adminResetBackend := manualRecoveryMFAAdminBackend{store: deps.Store, targets: manualTargets}
	strongFactors := strongFactorSource{totp: totpService, passkeys: passkeyService}
	var passkeySecondFactor mfa.SecondFactorPasskey
	if passkeyService == nil {
		// Passkey 未启用：MFA 服务仍需要第二步适配器接口，注入显式“未启用”实现，
		// 任何 Passkey 第二步操作都返回明确错误（fail-closed），不是测试替身。
		passkeySecondFactor = disabledPasskeySecondFactor{}
	} else {
		passkeySecondFactor = passkeyService
	}
	mfaStore, err := mfasqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造 MFA 存储失败: %w", err)
	}
	mfaService, err := mfa.New(mfa.Options{
		Store: mfaStore, Audit: deps.Audit, Credentials: services.Credential,
		Sessions:           services.Sessions,
		Mailer:             deps.Mail.SenderOrDisabled(),
		Templates:          mustMailTemplates(),
		FromAddress:        deps.Mail.FromAddress().Spec,
		AppName:            deps.Mail.AppDisplayName(),
		SupportURL:         mailURLs.Support,
		TOTP:               totpService,
		Passkeys:           passkeySecondFactor,
		StrongFactorSource: strongFactors,
		StrongSetupAuthorizer: rootStrongSetupAuthorizer{
			store: services.BootstrapStore, roots: managed.Roots},
		RootReady:             rootReadyMarker{store: services.BootstrapStore},
		Revoker:               services.Sessions,
		AllowStrongAuthSetup:  true,
		StrongSetupMethods:    []authfact.Method{authfact.MethodPasskey},
		AdminResetBackend:     adminResetBackend,
		AdminResetTargetGuard: adminResetBackend.CheckAdminResetTarget,
		// 步骤 194：真实强制 MFA 策略，用于“邮件因素移除是最后一个可用因素”保护。
		Policy: mfaPolicy,
		Now:    now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造 MFA 服务失败: %w", err)
	}

	recoveryStore, err := recoverysqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造恢复存储失败: %w", err)
	}
	recoveryService, err := recovery.New(recovery.Options{
		Store: recoveryStore, Audit: deps.Audit, Keyring: deps.Keyring,
		Sessions: services.Sessions, Reauth: gate.Reauth,
		Requirements: recoveryRequirements{},
		AuthLevels:   recoveryAuthLevels{},
		Binder:       &recoveryPasskeyBinder{passkeys: passkeyService, now: now},
		Now:          now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造恢复服务失败: %w", err)
	}
	// 恢复服务同时是 session 受限恢复会话的授权闸门；装配后立即接线。
	services.Sessions.SetRecoveryGate(recoveryService)

	resetURLBase := mailURLs.PasswordReset
	if resetURLBase == "" {
		// 未启用邮件时保留形状合法的占位地址；真实发送不可用时服务会明确失败。
		resetURLBase = "http://127.0.0.1" + deps.Config.Server.PathPrefix + "/login/reset-password"
	}
	passwordResetStore, err := passwordresetsqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造找回存储失败: %w", err)
	}
	passwordResetService, err := passwordreset.New(passwordreset.Options{
		Store: passwordResetStore, Audit: deps.Audit,
		Credentials: services.Credential, Passwords: services.Authn,
		Sessions: services.Sessions, Mailer: deps.Mail.SenderOrDisabled(),
		Templates:   mustMailTemplates(),
		FromAddress: deps.Mail.FromAddress().Spec, AppName: deps.Mail.AppDisplayName(),
		SupportURL:   mailURLs.Support,
		ResetURLBase: resetURLBase,
		Now:          now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造找回密码服务失败: %w", err)
	}

	avatarDir, err := ensureControlledDir(deps.Config.Database.Path, "avatars")
	if err != nil {
		return nil, err
	}
	avatarStorage, err := avatar.NewLocalStorage(avatarDir)
	if err != nil {
		return nil, fmt.Errorf("构造头像存储失败: %w", err)
	}
	avatarStore, err := avatarsqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造头像记录存储失败: %w", err)
	}
	avatarService, err := avatar.New(avatar.Options{
		Store: avatarStore, Storage: avatarStorage, Audit: deps.Audit,
		Authorizer: avatarAuthorizer{checker: managed.Checker},
		Now:        now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造头像服务失败: %w", err)
	}

	emailChangeStore, err := emailchangesqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造邮箱变更存储失败: %w", err)
	}
	emailChangeService, err := emailchange.New(emailchange.Options{
		Store: emailChangeStore, Audit: deps.Audit,
		Credentials:         services.Credential,
		ReauthVerifier:      emailChangeReauthVerifier{recentAuthVerifier{maxAge: 10 * time.Minute, now: now}},
		Sensitive:           gate.Reauth,
		Mailer:              emailChangeMailer,
		VerificationURLBase: mailURLs.ChangeEmail,
		SupportURL:          mailURLs.Support,
		AppName:             deps.Mail.AppDisplayName(),
		Now:                 now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造邮箱变更服务失败: %w", err)
	}

	supportStore, err := supportsqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造客服求助存储失败: %w", err)
	}
	supportService, err := support.New(support.Options{
		Store: supportStore, Audit: deps.Audit,
		Authorizer:      supportStaffAuthorizer{checker: managed.Checker},
		TargetProtector: supportTargetProtector{checker: managed.Checker, roots: managed.Roots},
		Sensitive:       gate.Reauth,
		ResetSender:     passwordResetService,
		Now:             now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造客服服务失败: %w", err)
	}

	manualStore, err := manualrecoverysqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造人工恢复存储失败: %w", err)
	}
	manualPolicy := manualRecoveryPolicyFromConfig(deps.Config.ManualRecovery)
	if err := manualPolicy.Validate(); err != nil {
		return nil, fmt.Errorf("人工恢复制度配置无效: %w", err)
	}
	// 启用制度必须真实可交付：邮件发送器与真实执行器都要在启动期确认，避免
	// 运行到执行时才失败而留下“看似可用”的恢复入口。
	if manualPolicy.Enabled && (deps.Mail == nil || deps.Mail.Sender == nil) {
		return nil, fmt.Errorf("人工恢复制度启用时必须配置真实邮件发送器（mail.enabled）")
	}
	executor := manualRecoveryExecutor{
		passwordReset: passwordResetService, mfa: mfaService,
		sessions: services.Sessions, targets: manualTargets,
	}
	var notifier manualrecovery.Notifier
	if manualPolicy.Enabled {
		notifier = manualRecoveryNotifier{sender: deps.Mail.Sender, store: deps.Store,
			from: deps.Mail.FromAddress(), appName: deps.Mail.AppDisplayName()}
	}
	manualService, err := manualrecovery.New(manualrecovery.Options{
		Store: manualStore, Audit: deps.Audit,
		Reauth:   gate.Reauth,
		Staff:    manualRecoveryStaff{checker: managed.Checker},
		Targets:  manualTargets,
		Executor: executor,
		Notifier: notifier,
		Policy:   manualPolicy,
		Now:      now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造人工恢复服务失败: %w", err)
	}

	return &SecurityDomains{
		TOTP: totpService, Passkey: passkeyService, MFA: mfaService,
		Recovery: recoveryService, PasswordReset: passwordResetService,
		Avatar: avatarService, EmailChange: emailChangeService,
		Support: supportService, ManualRecovery: manualService,
		StrongFactors: strongFactors, PasskeySecondFactor: passkeySecondFactor,
	}, nil
}

// rootStrongSetupAuthorizer 只允许真实 root 进入强认证初始化闭环。
type rootStrongSetupAuthorizer struct {
	store *bootstrapsqlite.Store
	roots *hostRootChecker
}

// AuthorizeStrongSetup 实现 mfa.StrongSetupAuthorizer。
func (a rootStrongSetupAuthorizer) AuthorizeStrongSetup(ctx context.Context,
	userID, _ string) error {
	if a.roots == nil || a.store == nil {
		return errors.New("root 识别器未装配")
	}
	root, err := a.roots.isRoot(ctx, userID)
	if err != nil || !root {
		return errors.New("强认证初始化只允许真实 root")
	}
	record, found, err := a.store.GetInitialization(ctx)
	if err != nil || !found || record.RootUserID != userID {
		return errors.New("root 初始化状态不可用")
	}
	if record.State != bootstrap.StateSetupVerified && record.State != bootstrap.StateReady {
		return errors.New("root 当前状态不允许强认证初始化")
	}
	return nil
}

// recoveryRequirements 返回恢复代码流程的强度要求：默认要求强认证（fail-closed）。
type recoveryRequirements struct{}

// RecoveryStrength 实现 recovery.Requirements。
func (recoveryRequirements) RecoveryStrength(context.Context, string) (recovery.Strength, error) {
	return recovery.StrengthStrong, nil
}

// recoveryAuthLevels 返回更新恢复代码所需认证级别：默认强认证（fail-closed）。
type recoveryAuthLevels struct{}

// RequiredLevel 实现 recovery.AuthLevelRequirements。
func (recoveryAuthLevels) RequiredLevel(context.Context, string) (recovery.AuthLevel, error) {
	return recovery.AuthLevelStrong, nil
}

// avatarAuthorizer 实现 avatar.Authorizer：本人按 self.* 权限、他人按 users.* 权限。
type avatarAuthorizer struct {
	checker *permissionChecker
}

// AuthorizeAvatar 实现 avatar.Authorizer。
func (a avatarAuthorizer) AuthorizeAvatar(ctx context.Context, caller avatar.Caller,
	target avatar.Target, write bool) error {
	actor := caller.Actor()
	trusted, err := a.checker.roots.trustedActor(ctx, actor)
	if err != nil {
		return err
	}
	if trusted {
		return nil
	}
	if actor.Type != audit.ActorUser {
		return errors.New("匿名主体不允许访问头像")
	}
	if actor.ID == target.UserID {
		key := "self.profile.read"
		if write {
			key = "self.profile.update"
		}
		return a.checker.check(ctx, actor.ID, key, "system")
	}
	if target.IsRoot {
		return errors.New("root 账户头像不允许普通管理操作")
	}
	key := "users.read"
	if write {
		key = "users.update"
	}
	return a.checker.check(ctx, actor.ID, key, "system")
}

// supportStaffAuthorizer 把客服功能权限判定接到真实 authz。
type supportStaffAuthorizer struct {
	checker *permissionChecker
}

// AuthorizeStaff 实现 support.Authorizer。
func (a supportStaffAuthorizer) AuthorizeStaff(ctx context.Context,
	staffUserID, permissionKey string) (support.StaffScope, error) {
	allowed, err := a.checker.evaluate(ctx, staffUserID, permissionKey, "system")
	if err != nil {
		return support.StaffScope{}, err
	}
	if !allowed {
		return support.StaffScope{}, support.ErrAccessDenied
	}
	// 数据范围：当前装配为“系统范围全覆盖”，尚未按部门/应用细分（报告已列缺口）。
	return support.StaffScope{AllUsers: true}, nil
}

// StaffEligible 实现 support.Authorizer。
func (a supportStaffAuthorizer) StaffEligible(ctx context.Context,
	staffUserID string) (bool, error) {
	allowed, err := a.checker.evaluate(ctx, staffUserID, "support.cases.read", "system")
	return allowed, err
}

// supportTargetProtector 识别 root 与持有高权限能力的账户，禁止普通客服处理。
type supportTargetProtector struct {
	checker *permissionChecker
	roots   *hostRootChecker
}

// Protected 实现 support.TargetProtector。
func (p supportTargetProtector) Protected(ctx context.Context, targetUserID string) (bool, error) {
	root, err := p.roots.isRoot(ctx, targetUserID)
	if err != nil {
		return false, err
	}
	if root {
		return true, nil
	}
	for _, key := range []string{
		"users.update", "roles.assign", "permissions.manage",
		"applications.credentials.manage", "security.policy.manage",
	} {
		allowed, evalErr := p.checker.evaluate(ctx, targetUserID, key, "system")
		if evalErr != nil {
			return false, evalErr
		}
		if allowed {
			return true, nil
		}
	}
	return false, nil
}

// manualRecoveryStaff 实现 manualrecovery.StaffAuthorizer。
type manualRecoveryStaff struct {
	checker *permissionChecker
}

// authorize 判定工作人员在系统范围是否持有权限键。
func (m manualRecoveryStaff) authorize(ctx context.Context, staffUserID, key string) error {
	allowed, err := m.checker.evaluate(ctx, staffUserID, key, "system")
	if err != nil {
		return err
	}
	if !allowed {
		return manualrecovery.ErrAccessDenied
	}
	return nil
}

// AuthorizeRequest 实现 manualrecovery.StaffAuthorizer。
func (m manualRecoveryStaff) AuthorizeRequest(ctx context.Context, staffUserID, _ string,
	_ manualrecovery.OperationType) error {
	return m.authorize(ctx, staffUserID, "support.cases.update")
}

// AuthorizeApproval 实现 manualrecovery.StaffAuthorizer。
func (m manualRecoveryStaff) AuthorizeApproval(ctx context.Context, approverUserID, _, _ string,
	_ manualrecovery.OperationType) error {
	return m.authorize(ctx, approverUserID, "recovery.approve")
}

// AuthorizeExecution 实现 manualrecovery.StaffAuthorizer。
func (m manualRecoveryStaff) AuthorizeExecution(ctx context.Context, executorUserID, _ string,
	_ manualrecovery.OperationType) error {
	return m.authorize(ctx, executorUserID, "recovery.approve")
}

// manualRecoveryTargets 读取目标账户状态并计算可信交付指纹。
type manualRecoveryTargets struct {
	store   *storagesqlite.Store
	keyring *secrets.Keyring
	roots   *hostRootChecker
}

// LoadTarget 实现 manualrecovery.TargetGuard。
func (t manualRecoveryTargets) LoadTarget(ctx context.Context,
	userID string) (manualrecovery.TargetState, error) {
	if !account.ValidUserID(userID) {
		return manualrecovery.TargetState{}, manualrecovery.ErrTargetUnavailable
	}
	var status string
	var isRoot int
	var securityVersion int64
	err := t.store.DB().QueryRowContext(ctx,
		`SELECT status,is_root,security_version FROM users WHERE id=?`, userID).
		Scan(&status, &isRoot, &securityVersion)
	if err != nil {
		return manualrecovery.TargetState{}, manualrecovery.ErrTargetUnavailable
	}
	high, err := t.highPrivilege(ctx, userID, isRoot == 1)
	if err != nil {
		return manualrecovery.TargetState{}, err
	}
	fingerprint, err := t.deliveryFingerprint(ctx, userID)
	if err != nil {
		return manualrecovery.TargetState{}, err
	}
	return manualrecovery.TargetState{
		UserID: userID, Active: status == string(account.StatusActive),
		IsRoot: isRoot == 1, HighPrivilege: high,
		SecurityVersion: securityVersion, DeliveryFingerprint: fingerprint,
	}, nil
}

// highPrivilege 判定目标是否持有仍需保护的系统角色（root 直接视为高权限）。
func (t manualRecoveryTargets) highPrivilege(ctx context.Context, userID string, isRoot bool) (bool, error) {
	if isRoot {
		return true, nil
	}
	var count int
	err := t.store.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM user_roles WHERE user_id=?`,
		userID).Scan(&count)
	if err != nil {
		return false, errors.New("读取目标角色失败")
	}
	return count > 0, nil
}

// deliveryFingerprint 返回已验证邮箱的 HMAC 指纹（不是邮箱明文）。
func (t manualRecoveryTargets) deliveryFingerprint(ctx context.Context, userID string) (string, error) {
	var email string
	err := t.store.DB().QueryRowContext(ctx,
		`SELECT email_normalized FROM user_emails WHERE user_id=? AND verified_at_ms IS NOT NULL
		 ORDER BY updated_at_ms DESC LIMIT 1`, userID).Scan(&email)
	if err != nil {
		return "", nil // 没有已验证邮箱：指纹为空，服务会拒绝无法交付的恢复
	}
	digest, err := t.keyring.HMACDigest(t.keyring.CurrentKeyID(),
		"manual-recovery.delivery.v1", []byte(strings.ToLower(email)))
	if err != nil {
		return "", errors.New("计算交付指纹失败")
	}
	return fmt.Sprintf("%x", digest), nil
}

// failClosedRecoveryExecutor 是人工恢复执行器的显式未装配实现：归还明确错误，
// 绝不伪造“已重置密码/已撤销会话”。
type failClosedRecoveryExecutor struct{}

// Execute 实现 manualrecovery.Executor。
func (failClosedRecoveryExecutor) Execute(context.Context,
	manualrecovery.ExecutionCommand) (manualrecovery.ExecutionOutcome, error) {
	return manualrecovery.ExecutionOutcome{},
		errors.New("人工恢复执行器未装配：拒绝执行（不会伪造恢复成功）")
}

// Compensate 实现 manualrecovery.Executor。
func (failClosedRecoveryExecutor) Compensate(context.Context, manualrecovery.ExecutionCommand) error {
	return nil
}

// 编译期确认适配器满足领域契约。
var (
	_ authn.StrongFactorPresence     = strongFactorSource{}
	_ mfa.StrongFactorSource         = strongFactorSource{}
	_ mfa.StrongSetupAuthorizer      = rootStrongSetupAuthorizer{}
	_ recovery.Requirements          = recoveryRequirements{}
	_ recovery.AuthLevelRequirements = recoveryAuthLevels{}
	_ avatar.Authorizer              = avatarAuthorizer{}
	_ support.Authorizer             = supportStaffAuthorizer{}
	_ support.TargetProtector        = supportTargetProtector{}
	_ manualrecovery.StaffAuthorizer = manualRecoveryStaff{}
	_ manualrecovery.TargetGuard     = manualRecoveryTargets{}
	_ manualrecovery.Executor        = failClosedRecoveryExecutor{}
)

// disabledPasskeySecondFactor 是 Passkey 未启用时的 MFA 第二步适配器：任何操作都
// 返回明确“未启用”错误，绝不降级为其它因素或伪造成功。
type disabledPasskeySecondFactor struct{}

// HasSecondFactor 实现 mfa.SecondFactorPasskey。
func (disabledPasskeySecondFactor) HasSecondFactor(context.Context, string) (bool, error) {
	return false, nil
}

// BeginSecondFactor 实现 mfa.SecondFactorPasskey。
func (disabledPasskeySecondFactor) BeginSecondFactor(context.Context, string, string,
	string) (passkey.SecondFactorStart, error) {
	return passkey.SecondFactorStart{}, errors.New("Passkey 未启用：拒绝第二步认证")
}

// FinishSecondFactor 实现 mfa.SecondFactorPasskey。
func (disabledPasskeySecondFactor) FinishSecondFactor(context.Context,
	passkey.SecondFactorFinishRequest) (passkey.SecondFactorResult, error) {
	return passkey.SecondFactorResult{}, errors.New("Passkey 未启用：拒绝第二步认证")
}

var _ mfa.SecondFactorPasskey = disabledPasskeySecondFactor{}
