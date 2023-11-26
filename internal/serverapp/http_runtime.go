package serverapp

// 共享 HTTP/页面装配（步骤 183）。
//
// 独立服务（RunServe）与公开嵌入入口（app.Open）共用本文件的同一条装配链：
// 协议域 -> 内置页面 -> 管理/托管/客服 API 挂载 -> HTTP 防护（限流/CSRF/安全头/
// 访问日志）-> 前缀组合。宿主只负责自己的监听器与 http.Server 生命周期，本文件
// 不创建监听、不启动协程。
//
// 缺依赖时一律返回错误（fail-closed）：页面/适配器缺失、协议配置非法、CSRF 来源
// 无法推导、挂载点冲突都使装配失败，绝不退化为“只有健康页”的最小服务。

import (
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin"
)

// PageOverrides 是宿主页面替换/资源覆盖选项；由 BuildPagesWithOptions 应用。
// 替换只改变页面内容与资源，不改变路由访问级别、会话/权限判定与 CSRF 校验。
type PageOverrides struct {
	HostTemplates       *login.UIHostTemplates
	HostRenderer        login.UIPageRenderer
	Brand               *login.UIBrand
	AssetOverlays       []fs.FS
	Translations        login.UICatalogProvider
	DisableBuiltinPages bool
}

// pageBuildOptions 把共享装配的页面覆盖选项转换为 pages.go 的构建参数；nil 表示
// 使用内置页面（零回归）。Prefix 始终取共享装配解析后的站内前缀，保证页面路由与
// HTTP handler 前缀一致。
func pageBuildOptions(prefix string, overrides *PageOverrides) *PageBuildOptions {
	if overrides == nil {
		return nil
	}
	return &PageBuildOptions{
		Prefix:              prefix,
		HostTemplates:       overrides.HostTemplates,
		HostRenderer:        overrides.HostRenderer,
		Brand:               overrides.Brand,
		AssetOverlays:       overrides.AssetOverlays,
		Translations:        overrides.Translations,
		DisableBuiltinPages: overrides.DisableBuiltinPages,
	}
}

// HTTPRuntimeOptions 是共享 HTTP/页面装配参数；Prefix 为空时使用配置的
// server.path_prefix。EnableProtocol 会启用配置中的协议端点（仍要求配置合法）。
type HTTPRuntimeOptions struct {
	Prefix             string
	AccessLog          io.Writer
	ExtraMounts        []HandlerMount
	EnableProtocol     bool
	EnableAdminAPI     bool
	AdminAPIPrefix     string
	EnableManagedAPI   bool
	ManagedAPIPrefix   string
	EnableAppSupport   bool
	AppSupportPrefix   string
	AppSupportAudience string
	Logger             *slog.Logger
	// PageOverrides 需要 S2 pages.go 合并窗口后才能应用；见上方说明。
	PageOverrides *PageOverrides
}

// HTTPRuntime 是共享 HTTP/页面装配结果。宿主负责监听与 http.Server，本结果不
// 持有监听器/协程；Handler 可在实例 Start 之前挂载。
type HTTPRuntime struct {
	Handler  http.Handler
	Prefix   string
	Pages    *Pages
	Protocol *ProtocolDomains
	// Mounts 是已挂载的协议/管理 API 站内路径（含站内前缀），用于诊断输出。
	Mounts []string
}

// BuildHTTPRuntime 构造共享 HTTP/页面装配；构造期不监听端口、不启动协程。
func BuildHTTPRuntime(base *Base, options HTTPRuntimeOptions) (*HTTPRuntime, error) {
	if base == nil || base.Services == nil || base.Managed == nil ||
		base.Security == nil || base.Gate == nil {
		return nil, fmt.Errorf("HTTP 装配缺少共享运行时依赖（服务/安全域/敏感闸门）")
	}
	cfg := base.Config
	prefix := strings.TrimSpace(options.Prefix)
	if prefix == "" {
		prefix = cfg.Server.PathPrefix
	}
	cfg.Server.PathPrefix = prefix
	// 协议端点由显式选项或配置启用；启用后整体重校验配置（issuer 等不合法即失败）。
	protocolRequested := options.EnableProtocol || cfg.Protocol.Enabled
	cfg.Protocol.Enabled = protocolRequested
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("嵌入式 HTTP 配置校验失败: %w", err)
	}
	deps := base.Deps
	deps.Config = cfg
	logger := options.Logger
	if logger == nil {
		logger = base.Logger
	}
	protocolDomains, err := BuildProtocolDomains(deps, base.Services, base.Managed, base.Gate)
	if err != nil {
		return nil, fmt.Errorf("装配协议域失败: %w", err)
	}
	// 供嵌入式宿主公开 Go 查询入口复用同一（本 HTTP 装配生成的）协议域实例；
	// 以 HTTP 选项覆盖后的 PathPrefix 为准，避免与 OpenBase 中的预构造实例路径不一致。
	base.Protocol = protocolDomains
	pages, err := BuildPagesWithOptions(deps, base.Services, base.Managed, base.Security,
		base.Gate, protocolDomains, pageBuildOptions(prefix, options.PageOverrides))
	if err != nil {
		return nil, fmt.Errorf("装配内置页面失败: %w", err)
	}
	mounts := append([]HandlerMount(nil), options.ExtraMounts...)
	if protocolDomains != nil {
		mounts = append(mounts, protocolDomains.protocolMounts()...)
		logger.Info("已启用 OAuth/OIDC 协议端点",
			"issuer", protocolIssuer(deps),
			"paths", protocolDomains.Protocol.Paths())
	}
	if options.EnableAdminAPI {
		adminHandler, adminPrefix, adminErr := BuildAdminAPIServer(
			deps, base.Services, base.Managed, base.Tasks, pages,
			options.AdminAPIPrefix, base.Gate)
		if adminErr != nil {
			return nil, fmt.Errorf("装配管理 JSON API 失败: %w", adminErr)
		}
		// 步骤 186：CLI 一次性再认证/确认通道挂在管理 API 外层，证明由服务端
		// 校验后把 reauth 信号注入同一次写请求的 ctx。
		cliReauth, cliErr := newCLIReauthHandler(deps, base.Services, base.Gate,
			base.Security, adminPrefix)
		if cliErr != nil {
			return nil, fmt.Errorf("装配 CLI 再认证确认通道失败: %w", cliErr)
		}
		adminHandler = cliReauth.wrap(adminHandler)
		mounts = append(mounts, HandlerMount{
			Name: "admin-api", Prefix: adminPrefix, Handler: adminHandler,
			KeepPrefix: true,
		})
		logger.Info("已启用管理 JSON API",
			"prefix", normalizePathPrefix(prefix)+adminPrefix,
			"note", "只挂载已装配领域服务路由；未装配域返回 404")
	}
	if options.EnableManagedAPI {
		managedHandler, managedPrefix, managedErr := BuildManagedAPIHTTPHandler(
			deps, base.Services, base.Managed, options.ManagedAPIPrefix)
		if managedErr != nil {
			return nil, fmt.Errorf("装配业务托管管理 API 失败: %w", managedErr)
		}
		mounts = append(mounts, HandlerMount{
			Name: "managed-api", Prefix: managedPrefix, Handler: managedHandler,
			KeepPrefix: true,
		})
		logger.Info("已启用业务应用托管管理 API",
			"prefix", normalizePathPrefix(prefix)+managedPrefix,
			"auth", "user-session-bearer-or-app-client-secret-certificate")
	}
	if options.EnableAppSupport {
		supportHandler, supportPrefix, supportErr := BuildAppSupportHandler(
			deps, base.Managed, protocolDomains, options.AppSupportAudience,
			options.AppSupportPrefix)
		if supportErr != nil {
			return nil, fmt.Errorf("装配应用受限客服 API 失败: %w", supportErr)
		}
		mounts = append(mounts, HandlerMount{
			Name: "app-support", Prefix: supportPrefix, Handler: supportHandler,
			KeepPrefix: true,
		})
		logger.Info("已启用应用受限客服 API",
			"prefix", normalizePathPrefix(prefix)+supportPrefix,
			"auth", "oauth-user-delegated-access-token")
	}
	httpOptions, err := BuildHTTPOptions(deps, pages, logger, options.AccessLog)
	if err != nil {
		return nil, fmt.Errorf("装配 HTTP 防护失败: %w", err)
	}
	assembled, err := login.NewHTTPHandler(httpOptions)
	if err != nil {
		return nil, fmt.Errorf("构造 HTTP 处理程序失败: %w", err)
	}
	withMounts, err := ComposeHandler(assembled, prefix, mounts)
	if err != nil {
		return nil, fmt.Errorf("协议/管理 API 挂载点配置无效: %w", err)
	}
	fullMounts := make([]string, 0, len(mounts))
	for _, mount := range mounts {
		fullMounts = append(fullMounts, normalizePathPrefix(prefix)+mount.Prefix)
	}
	return &HTTPRuntime{Handler: withMounts, Prefix: normalizePathPrefix(prefix),
		Pages: pages, Protocol: protocolDomains, Mounts: fullMounts}, nil
}
