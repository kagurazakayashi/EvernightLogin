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
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
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

// strongFactorSource 汇总 TOTP 与 Passkey 的强因素存在性，并实现步骤 209 的
// “挑战创建之后真实新绑定”判定（防止用账户既有因素冒充初始化完成）。
type strongFactorSource struct {
	totp     *totp.Service
	passkeys *passkey.Service
	// store 用于查询绑定时间（totp_bindings.activated_at_ms /
	// webauthn_credentials.created_at_ms）；缺失时新鲜绑定判定 fail-closed。
	store *storagesqlite.Store
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

// StrongFactorBoundAfter 实现 mfa.StrongSetupBindingVerifier：只有当指定类别的强
// 因素在 since 之后被真实激活/创建时才返回 true。查询失败返回错误（调用方
// fail-closed），绝不把“存在既有因素”当作本次绑定。
func (s strongFactorSource) StrongFactorBoundAfter(ctx context.Context, userID string,
	method authfact.Method, since time.Time) (bool, error) {
	if s.store == nil || s.store.DB() == nil {
		return false, errors.New("强因素绑定时间存储未装配")
	}
	sinceMS := since.UTC().UnixMilli()
	var count int
	var query string
	switch method {
	case authfact.MethodTOTP:
		// 只统计 active 绑定：pending 的 TOTP 尚未完成验证码确认，不构成新因素。
		query = `SELECT COUNT(*) FROM totp_bindings
WHERE user_id=? AND status='active' AND activated_at_ms IS NOT NULL AND activated_at_ms>=?`
	case authfact.MethodPasskey, authfact.MethodSecurityKey:
		// 只统计用途允许第二步且未撤销的凭证；主登录专用凭证不满足强认证绑定。
		query = `SELECT COUNT(*) FROM webauthn_credentials
WHERE user_id=? AND revoked_at_ms IS NULL AND created_at_ms>=? AND usage IN('second_factor','both')`
	default:
		return false, nil
	}
	if err := s.store.DB().QueryRowContext(ctx, query, userID, sinceMS).Scan(&count); err != nil {
		return false, fmt.Errorf("查询强因素绑定时间失败: %w", err)
	}
	return count > 0, nil
}

// dedupeAuthfactMethods 去重方法列表（保留首次出现顺序）。
func dedupeAuthfactMethods(methods []authfact.Method) []authfact.Method {
	result := make([]authfact.Method, 0, len(methods))
	seen := make(map[authfact.Method]bool, len(methods))
	for _, method := range methods {
		if seen[method] {
			continue
		}
		seen[method] = true
		result = append(result, method)
	}
	return result
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
	// 步骤 197：可靠投递服务（任务运行时已在本函数之前构造）；仅邮件启用时使用，
	// 未启用时保持 nil 回退直接 Sender（与既有 mail disabled 语义一致）。
	var mailDeliveries *mailer.DeliveryService
	if deps.Config.Mail.Enabled && deps.MailDeliveryProvider != nil {
		mailDeliveries = deps.MailDeliveryProvider()
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
	// 步骤 188：人工恢复 MFA 重置后的强制重绑状态（登录受限 + 强因素绑定后清除）。
	rebindStore := mfaRebindRequirementStore{
		store: deps.Store, audit: deps.Audit, logger: deps.Logger,
	}
	// 步骤 209：人工恢复 MFA 重置后允许的重绑因素类别。配置显式列出（默认仅
	// passkey）；passkey 只有真实启用 Passkey 时才可用，totp 是非抗钓鱼的显式
	// 备用类别。空列表表示恢复后无法重绑，mfa_reset 申请/执行必须 fail-closed。
	rebindMethods, rebindErr := manualRecoveryRebindMethods(
		deps.Config.ManualRecovery, deps.Config.Passkey.Enabled)
	if rebindErr != nil {
		return nil, fmt.Errorf("人工恢复重绑方法配置无效: %w", rebindErr)
	}
	// 强认证初始化允许绑定的类别（服务层白名单）：Passkey 启用时含 Passkey，
	// 另加人工恢复重绑显式允许的类别。按用户真正下发/收窄由 StrongSetupMethodSource
	// 完成（root/高权限固定 Passkey）。
	strongSetupMethods := make([]authfact.Method, 0, 2)
	if deps.Config.Passkey.Enabled {
		strongSetupMethods = append(strongSetupMethods, authfact.MethodPasskey)
	}
	strongSetupMethods = append(strongSetupMethods, rebindMethods...)
	strongSetupMethods = dedupeAuthfactMethods(strongSetupMethods)
	if len(strongSetupMethods) == 0 {
		// 保持 mfa.New 的合法选项（其默认值为 Passkey）；实际是否允许某用户进入
		// 初始化由 StrongSetupMethodSource 决定，空下发会 fail-closed。
		strongSetupMethods = []authfact.Method{authfact.MethodPasskey}
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

	manualTargets := manualRecoveryTargets{store: deps.Store, keyring: deps.Keyring, roots: managed.Roots, checker: managed.Checker}
	adminResetBackend := manualRecoveryMFAAdminBackend{store: deps.Store, targets: manualTargets}
	strongFactors := strongFactorSource{totp: totpService, passkeys: passkeyService, store: deps.Store}
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
	// 同一适配器既做“受控初始化授权”，也按用户下发允许绑定的强因素类别：root/
	// 高权限固定 Passkey，人工恢复重绑用户按配置允许 passkey/totp。
	strongSetupAuthorizer := rootStrongSetupAuthorizer{
		store: services.BootstrapStore, roots: managed.Roots, rebind: rebindStore,
		rebindMethods: rebindMethods, passkeyEnabled: deps.Config.Passkey.Enabled,
		checker: managed.Checker, protectedStore: deps.Store,
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
		// 步骤 209：按用户下发本次受限初始化允许绑定的强因素类别（root/高权限固定
		// Passkey；人工恢复重绑用户按配置允许 passkey/totp），并强制校验“本次新绑定”
		// 而不是账户既有因素冒充完成。
		StrongSetupMethodSource:    strongSetupAuthorizer,
		StrongSetupBindingVerifier: strongFactors,
		StrongSetupAuthorizer:      strongSetupAuthorizer,
		RootReady:                  rootReadyMarker{store: services.BootstrapStore},
		RebindClearer:              rebindStore,
		Revoker:                    services.Sessions,
		AllowStrongAuthSetup:       true,
		StrongSetupMethods:         strongSetupMethods,
		AdminResetBackend:          adminResetBackend,
		AdminResetTargetGuard:      adminResetBackend.CheckAdminResetTarget,
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
		Deliveries:  mailDeliveries,
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
	if manualPolicy.Enabled && (deps.Mail == nil || !deps.Config.Mail.Enabled ||
		(deps.Mail.Sender == nil && mailDeliveries == nil)) {
		return nil, fmt.Errorf("人工恢复制度启用时必须配置真实邮件发送器（mail.enabled）")
	}
	executor := manualRecoveryExecutor{
		passwordReset: passwordResetService, mfa: mfaService,
		sessions: services.Sessions, targets: manualTargets,
		rebindMethods: rebindMethods,
	}
	var notifier manualrecovery.Notifier
	if manualPolicy.Enabled {
		notifier = manualRecoveryNotifier{sender: deps.Mail.Sender, deliveries: mailDeliveries,
			store: deps.Store, from: deps.Mail.FromAddress(), appName: deps.Mail.AppDisplayName(),
			supportURL: mailURLs.Support}
	}
	manualService, err := manualrecovery.New(manualrecovery.Options{
		Store: manualStore, Audit: deps.Audit,
		Reauth:              gate.Reauth,
		Staff:               manualRecoveryStaff{checker: managed.Checker, targets: manualTargets},
		Targets:             manualTargets,
		Executor:            executor,
		Notifier:            notifier,
		NotificationsQueued: notifier != nil && mailDeliveries != nil,
		Policy:              manualPolicy,
		OperationGuard: func(operation manualrecovery.OperationType) error {
			if operation == manualrecovery.OperationMFAReset && len(rebindMethods) == 0 {
				return errors.New("没有可用的强因素重绑方法（Passkey 未启用且未显式允许 TOTP）：拒绝 MFA 恢复（避免恢复后无法重绑）")
			}
			return nil
		},
		Now: now, Logger: deps.Logger,
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

// rootStrongSetupAuthorizer 只允许真实 root 与带未清除人工恢复重绑需求的用户进入
// 受限强认证初始化；同时按用户下发允许绑定的强因素类别（步骤 209）：
//   - root/高权限初始化固定只允许抗钓鱼的 Passkey，绝不因 TOTP 重绑策略降级；
//   - 人工恢复 MFA 重置后的重绑用户按配置允许的类别（passkey/totp）；
//   - 其余用户返回空列表（fail-closed，不允许自助绑定强因素）。
type rootStrongSetupAuthorizer struct {
	store  *bootstrapsqlite.Store
	roots  *hostRootChecker
	rebind mfaRebindRequirementStore
	// checker/protectedStore 用于对非 root 用户复算 protectedRecoveryTarget（R10-11 /
	// 步骤 222）：MFA 重置执行时是普通用户、重绑完成前被提升为高权限的过渡态，
	// 也必须按“高权限 → 仅 Passkey 或拒绝”处理，不能沿用重置时的普通用户类别。
	checker        *permissionChecker
	protectedStore *storagesqlite.Store
	// rebindMethods 是人工恢复重绑允许的强因素类别（已按真实可用性过滤）。
	rebindMethods []authfact.Method
	// passkeyEnabled 表示 Passkey 服务真实启用；root 初始化在没有 Passkey 时
	// fail-closed 拒绝，不降级到 TOTP。
	passkeyEnabled bool
}

// AuthorizeStrongSetup 实现 mfa.StrongSetupAuthorizer。
func (a rootStrongSetupAuthorizer) AuthorizeStrongSetup(ctx context.Context,
	userID, _ string) error {
	if a.roots == nil || a.store == nil {
		return errors.New("root 识别器未装配")
	}
	root, err := a.roots.isRoot(ctx, userID)
	if err == nil && root {
		return a.authorizeRoot(ctx, userID)
	}
	// 步骤 188：人工恢复 MFA 重置后的普通用户强制重绑：只在存在未清除需求时放行。
	if a.rebind.store != nil {
		required, rebindErr := a.rebind.MFARebindRequired(ctx, userID)
		if rebindErr != nil {
			return errors.New("强制重绑状态不可用")
		}
		if required {
			return nil
		}
	}
	return errors.New("强认证初始化未授权")
}

// authorizeRoot 保留 root 初始化状态的原有约束。
func (a rootStrongSetupAuthorizer) authorizeRoot(ctx context.Context, userID string) error {
	record, found, err := a.store.GetInitialization(ctx)
	if err != nil || !found || record.RootUserID != userID {
		return errors.New("root 初始化状态不可用")
	}
	if record.State != bootstrap.StateSetupVerified && record.State != bootstrap.StateReady {
		return errors.New("root 当前状态不允许强认证初始化")
	}
	return nil
}

// AllowedStrongSetupMethods 实现 mfa.StrongSetupMethodSource：root/高权限固定
// Passkey-only（未启用 Passkey 时拒绝，不降级 TOTP）；人工恢复重绑用户返回配置
// 允许且真实可用的类别；其他用户拒绝。
//
// R10-11（步骤 222）：非 root 用户也要复算 protectedRecoveryTarget。人工恢复 MFA
// 重置执行时目标可能仍是普通用户，但在重绑完成前被授予高权限的过渡态下，必须按
// 高权限策略只允许抗钓鱼的 Passkey（Passkey 未启用则拒绝），不能继续返回重置时
// 配置的 TOTP 类别；判定失败 fail-closed。
func (a rootStrongSetupAuthorizer) AllowedStrongSetupMethods(ctx context.Context,
	userID string) ([]authfact.Method, error) {
	if a.roots == nil || a.store == nil {
		return nil, errors.New("root 识别器未装配")
	}
	root, err := a.roots.isRoot(ctx, userID)
	if err != nil {
		return nil, errors.New("root 识别失败")
	}
	if root {
		if !a.passkeyEnabled {
			// 抗钓鱼初始化没有 Passkey：不降级到 TOTP，明确拒绝。
			return nil, errors.New("root 强认证初始化需要 Passkey")
		}
		return []authfact.Method{authfact.MethodPasskey}, nil
	}
	// 非 root 复算受保护目标：覆盖“重置后、重绑前被提升为高权限”的过渡态。
	protected, err := protectedRecoveryTarget(ctx, a.checker, a.protectedStore, a.roots, userID)
	if err != nil {
		return nil, errors.New("受保护目标判定失败")
	}
	if protected {
		if !a.passkeyEnabled {
			return nil, errors.New("高权限强认证初始化需要 Passkey")
		}
		return []authfact.Method{authfact.MethodPasskey}, nil
	}
	if a.rebind.store != nil {
		required, rebindErr := a.rebind.MFARebindRequired(ctx, userID)
		if rebindErr != nil {
			return nil, errors.New("强制重绑状态不可用")
		}
		if required {
			// 返回副本，避免调用方修改共享策略切片。
			return append([]authfact.Method(nil), a.rebindMethods...), nil
		}
	}
	return nil, errors.New("强认证初始化未授权")
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
	targets manualRecoveryTargets
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

// AuthorizeRequest 实现 manualrecovery.StaffAuthorizer：发起申请使用 recovery.request。
func (m manualRecoveryStaff) AuthorizeRequest(ctx context.Context, staffUserID, targetUserID string,
	operation manualrecovery.OperationType) error {
	if err := m.authorize(ctx, staffUserID, "recovery.request"); err != nil {
		return err
	}
	return m.checkTargetProtection(ctx, targetUserID)
}

// AuthorizeApproval 实现 manualrecovery.StaffAuthorizer：按操作类型使用
// recovery.approve / recovery.mfa.approve，并复核目标保护。
func (m manualRecoveryStaff) AuthorizeApproval(ctx context.Context, approverUserID, targetUserID,
	_ string, operation manualrecovery.OperationType) error {
	if err := m.authorize(ctx, approverUserID, operation.ApprovalPermission()); err != nil {
		return err
	}
	return m.checkTargetProtection(ctx, targetUserID)
}

// AuthorizeExecution 实现 manualrecovery.StaffAuthorizer：执行使用 recovery.execute，
// 并复核目标保护（三权分离由领域服务的 Execute 进一步校验）。
func (m manualRecoveryStaff) AuthorizeExecution(ctx context.Context, executorUserID, targetUserID string,
	_ manualrecovery.OperationType) error {
	if err := m.authorize(ctx, executorUserID, "recovery.execute"); err != nil {
		return err
	}
	return m.checkTargetProtection(ctx, targetUserID)
}

// checkTargetProtection 以真实目标状态复核 root/受保护目标；目标不可读时 fail-closed。
func (m manualRecoveryStaff) checkTargetProtection(ctx context.Context, targetUserID string) error {
	if targetUserID == "" {
		return manualrecovery.ErrAccessDenied
	}
	if m.targets.store == nil {
		return manualrecovery.ErrAccessDenied
	}
	target, err := m.targets.LoadTarget(ctx, targetUserID)
	if err != nil {
		return manualrecovery.ErrAccessDenied
	}
	if target.IsRoot || target.HighPrivilege || !target.Active {
		return manualrecovery.ErrTargetProtected
	}
	return nil
}

// manualRecoveryTargets 读取目标账户状态并计算可信交付指纹。
type manualRecoveryTargets struct {
	store   *storagesqlite.Store
	keyring *secrets.Keyring
	roots   *hostRootChecker
	checker *permissionChecker
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
	return protectedRecoveryTarget(ctx, t.checker, t.store, t.roots, userID)
}

// protectedRecoveryTarget 按 Q3 裁决统一判定受保护目标：root / 持有受保护系统权限 /
// 持有预设管理角色；读取或权限引擎失败一律按受保护（fail-closed）。
func protectedRecoveryTarget(ctx context.Context, checker *permissionChecker,
	store *storagesqlite.Store, roots *hostRootChecker, userID string) (bool, error) {
	if roots != nil {
		root, err := roots.isRoot(ctx, userID)
		if err != nil {
			return true, err
		}
		if root {
			return true, nil
		}
	}
	if store != nil {
		var presetRoles int
		err := store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM user_roles ur
JOIN roles r ON r.id=ur.role_id AND r.scope_id=ur.scope_id
WHERE ur.user_id=? AND r.scope_id='system'
AND r.role_key IN ('system_admin','user_admin','support','auditor')`, userID).Scan(&presetRoles)
		if err != nil {
			return true, err
		}
		if presetRoles > 0 {
			return true, nil
		}
	}
	if checker == nil {
		// 测试/旧装配未注入权限引擎时退回“持有任意系统角色即视为受保护”的保守判定；
		// 生产装配始终注入 checker，按真实有效权限判定。
		if store == nil {
			return true, errors.New("权限引擎未装配")
		}
		var count int
		if err := store.DB().QueryRowContext(ctx,
			`SELECT COUNT(*) FROM user_roles WHERE user_id=?`, userID).Scan(&count); err != nil {
			return true, err
		}
		return count > 0, nil
	}
	for _, key := range protectedRecoveryPermissionKeys {
		allowed, err := checker.evaluate(ctx, userID, key, "system")
		if err != nil {
			return true, err
		}
		if allowed {
			return true, nil
		}
	}
	return false, nil
}

// protectedRecoveryPermissionKeys 是与 internal/preset 目录对照维护的受保护系统权限
// 集合（宁多勿漏）；新增管理权限时同步复查。
var protectedRecoveryPermissionKeys = []string{
	"users.read", "users.create", "users.update", "users.disable", "users.delete",
	"users.export", "groups.read", "groups.manage", "roles.read", "roles.manage",
	"roles.assign", "permissions.read", "permissions.manage",
	"applications.read", "applications.create", "applications.update",
	"applications.credentials.manage", "applications.members.manage",
	"recovery.request", "recovery.approve", "recovery.mfa.approve", "recovery.execute",
	"support.cases.read", "support.cases.create", "support.cases.update",
	"sessions.revoke", "audit.read", "audit.export", "audit.purge",
	"reports.read", "reports.generate", "reports.export", "reports.schedule.manage",
	"reports.cleanup", "backups.create", "backups.read", "backups.cancel",
	"backups.export", "backups.restore", "backups.retention", "backups.cleanup",
	"security.policy.manage", "settings.manage", "diagnostics.read",
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
	_ mfa.StrongSetupBindingVerifier = strongFactorSource{}
	_ mfa.StrongSetupAuthorizer      = rootStrongSetupAuthorizer{}
	_ mfa.StrongSetupMethodSource    = rootStrongSetupAuthorizer{}
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
