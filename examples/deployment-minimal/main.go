// Command deployment-minimal 是部署文档「嵌入模式安全启动」片段的可编译检查（步骤 89）。
//
// 它按 docs/deployment/standalone-service.md 的示例，使用真实公开 API 完成：
// 加载并校验配置 -> 构造内置页面 -> 构造 HTTP Handler -> 构造监听组件（NewServer）
// -> 用同一处理器选项构造 Instance。它**只构造、不 Start、不监听端口**，用于证明
// 文档片段与真实 API 一致，并可作为独立部署前的装配自检。
//
// 运行方式（仓库根目录）：
//
//	go run ./examples/deployment-minimal -config docs/deployment/samples/login.server.example.yaml
//
// 注意：真正对外监听必须由宿主在完成身份/存储/授权装配后显式调用 Start，并遵守
// docs/deployment/standalone-service.md 的启动检查清单；本示例不启动服务。
package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/kagurazakayashi/EvernightLogin"
)

func main() {
	configPath := flag.String("config", "docs/deployment/samples/login.server.example.yaml", "YAML 配置文件路径")
	flag.Parse()
	if err := run(*configPath); err != nil {
		fmt.Fprintln(os.Stderr, "装配检查失败:", err)
		os.Exit(1)
	}
}

func run(path string) error {
	// 1. 配置：加载器只读配置与秘密来源，不监听、不打开数据库。
	cfg, err := login.Load(login.LoadOptions{YAMLFile: path})
	if err != nil {
		return fmt.Errorf("配置加载失败: %w", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// 2. 内置页面：不依赖 Node/npm，模板与静态资源来自内嵌 embed.FS。
	web, err := login.NewWebUI(login.WebUIOptions{Prefix: cfg.Server.PathPrefix, Logger: logger})
	if err != nil {
		return fmt.Errorf("页面装配失败: %w", err)
	}

	// 3. HTTP Handler：页面通过 UIHTTPOptions 注入；未提供身份解析器时依赖身份
	//    的路由默认拒绝（fail-closed）。前缀必须与监听组件一致。
	httpOptions := login.HTTPOptions{
		Prefix: cfg.Server.PathPrefix,
		Logger: logger,
		UI: &login.UIHTTPOptions{
			Handler:                   web,
			PageContentSecurityPolicy: login.DefaultUIPageContentSecurityPolicy,
		},
	}
	handler, err := login.NewHTTPHandler(httpOptions)
	if err != nil {
		return fmt.Errorf("HTTP Handler 装配失败: %w", err)
	}

	// 4. 监听组件：只校验配置与证书材料，不绑定端口（Start 才绑定）。
	srv, err := login.NewServer(login.ServerOptions{
		Config:  cfg,
		Handler: handler,
		Prefix:  cfg.Server.PathPrefix,
		Logger:  logger,
	})
	if err != nil {
		return fmt.Errorf("监听组件装配失败: %w", err)
	}

	// 5. Instance：使用同一处理器选项，宿主可通过 Mount 挂到自己的 mux；
	//    未调用 Start 时不会运行后台组件与扩展。
	inst, err := login.New(login.Options{
		Config: &cfg,
		Logger: logger,
		HTTP:   &httpOptions,
	})
	if err != nil {
		return fmt.Errorf("实例装配失败: %w", err)
	}

	fmt.Printf("装配检查通过（未监听端口）：prefix=%q handler=%T server_tls=%v instance_http_prefix=%q\n",
		cfg.Server.PathPrefix, handler, srv.TLSEnabled(), inst.HandlerPrefix())
	return nil
}
