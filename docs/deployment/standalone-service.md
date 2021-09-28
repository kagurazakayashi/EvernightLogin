# 独立服务安全启动

本文说明 login 独立服务的安全启动方式、配置与边界。

## 1. 当前状态与可用启动路径

**重要：`cmd/login-server` 目前只是命令行入口，尚未装配 HTTP 服务。**

- 它只实现 `--version` 与 `--help`；不带参数运行会返回非零退出码并明确说明功能尚未
  实现，不会伪造“启动成功”。
- 独立服务读取 YAML 后监听端口的装配代码**尚未实现**。因此本节给出的是：
  1. **当前唯一可用的真实启动路径**：由宿主用 Go API 装配（嵌入模式）；
  2. 装配完成后必须满足的启动契约与检查清单（标记为约束，不代表已由 CLI 提供）。

不要为了“先跑起来”而绕过配置校验、权限检查或 TLS 边界；当前没有安全的方式让
`login-server.exe` 对外提供 HTTP 服务。

## 2. 启动前置条件（必须逐项确认）

1. **配置有效**：启动前必须先调用 `login.Load`（或构造 `login.Config` 后调用
   `Config.Validate`），确认无未知字段、越界值或非法组合；加载器本身不产生监听、
   数据库或文件写入副作用。
2. **秘密来自受保护来源**：主密钥、PFX 密码等只能来自 `env:`/`file:` 引用或宿主
   显式选项，不能写进 YAML；非 Windows 平台的秘密文件必须仅所有者可读写。
3. **数据库可用且已迁移**：SQLite 使用 `database.path` 指定的文件；迁移必须按版本
   追加执行，不得修改已应用迁移。迁移前先做备份。
4. **网络边界明确**：默认只监听 `127.0.0.1:8080`。任何非回环明文监听都必须同时配置
   `server.tls_terminating_proxy=true`、非空 `server.trusted_proxies` 与 https 的
   `server.public_base_url`，否则构造监听组件时拒绝启动。
5. **Host 与公开地址固定**：`server.public_base_url` 决定允许的 Host；未配置时只接受
   本机回环主机名。不要从请求 Host 或转发头动态推导身份相关地址。
6. **进程账号最小权限**：只授予数据库目录、秘密目录与日志目录的必需权限；不要用
   管理员/root 账号长期运行 Web 服务。
7. **维护与恢复通道可用**：确认已准备 `cmd/loginctl` 应急恢复与备份/恢复工具，并阅读
   `first-run.md` 的防锁死要求。

## 3. 嵌入模式安全启动（当前可用）

宿主在自己的进程里完成装配，login 不监听端口、不创建后台协程，除非宿主显式
`Start`。最小骨架（与 `docs/embedding/host_integration.md` 一致）：

```go
cfg, err := login.Load(login.LoadOptions{YAMLFile: "config/login.yaml"})
if err != nil {
    return err // 配置错误必须在监听/打开数据库之前返回
}

// 运行日志只写结构化字段，不写秘密；级别/格式按配置决定。
logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

web, err := login.NewWebUI(login.WebUIOptions{Prefix: cfg.Server.PathPrefix /* 页面后端按需注入 */, Logger: logger})
if err != nil {
    return err
}

// HTTPOptions 没有 Handler 字段：处理器通过 UIHTTPOptions.Handler 注入页面，
// 其余字段是前缀、请求体上限、身份解析、访问日志与防护策略。
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
    return err
}

srv, err := login.NewServer(login.ServerOptions{
    Config:  cfg,
    Handler: handler,
    Prefix:  cfg.Server.PathPrefix,
    Logger:  logger, // 结构日志；不写秘密
})
if err != nil {
    return err
}

// Instance 使用同一处理器选项，通过 Mount/Handler 交给宿主 mux；未调用 Start
// 时不会运行后台组件与扩展。
inst, err := login.New(login.Options{Config: &cfg, Logger: logger, HTTP: &httpOptions})
if err != nil {
    return err
}
if err := inst.Start(ctx); err != nil {
    return err
}
defer inst.Close(context.Background())

if err := srv.Start(ctx); err != nil { // 绑定多个地址时全部成功才提供服务
    return err
}
defer srv.Close(context.Background())
```

**可编译检查**：上面片段按真实公开 API（`HTTPOptions`、`UIHTTPOptions.Handler`、
`NewHTTPHandler`、`NewServer`、`Instance.Mount`）写成，并在
`examples/deployment-minimal` 中逐字段实现与编译验证（只构造、不监听端口）：

```bash
go run ./examples/deployment-minimal -config docs/deployment/samples/login.server.example.yaml
```

说明：

- `login.NewServer` 会再次校验配置并拒绝不安全的监听/代理组合；`Start` 只有在所有
  监听地址绑定成功后才进入服务状态，任一失败整体回滚。
- `Instance.Start` 启动扩展与后台组件，`Close` 逆序关闭；宿主拥有的数据库、日志器、
  通知器、HTTP 服务不会被实例擅自关闭。
- HTTPS 由 `server.tls_cert_files`/`server.tls_key_files`（或 PFX）启用；客户端证书
  mTLS 由 `server.tls_client_auth` 三件套显式启用。TLS 重载只重新加载证书材料，不
  重载客户端信任配置。
- 若部署在受信任 TLS 终止代理后，必须显式设置 `tls_terminating_proxy=true` 并配置
  可信代理；这是声明，不是“自动信任所有转发头”。

## 4. 启动检查清单（装配完成后执行）

| 检查 | 期望 |
|---|---|
| 配置未知字段/重复键/类型错误 | 启动前失败，不产生监听 |
| 监听地址 | 与配置一致；`0.0.0.0`/`::` 明文必须满足代理声明条件 |
| `GET /healthz`、`GET /readyz`（按装配的处理器） | 健康与就绪分离；依赖故障时就绪失败 |
| `server.public_base_url` 与实际访问地址/前缀 | 一致；否则拒绝或 404 |
| TLS 证书与私钥权限 | 私钥仅所有者可读；证书链完整、未过期 |
| 访问日志 | 不包含 Cookie、Authorization、密码、一次性凭证 |
| 关闭 | 收到信号后在 `server.shutdown_timeout_seconds` 内完成，退出码为 0 |

## 5. 服务托管

操作系统级托管（Windows 服务、systemd、launchd）见 `service-hosting.md` 与
`samples/`。托管前必须确认进程账号、工作目录、秘密文件权限与日志轮转，不要把秘密
放进命令行参数、环境文件的可读副本或服务描述。

## 6. 已知限制

- 独立服务 HTTP 装配未实现，本文第 4 节检查清单在当前版本**无法由 `login-server`
  自动完成**；只能由宿主装配实现。
- 迁移/诊断/备份目前是本地工具（`cmd/loginctl`、`cmd/login-backup`），不是远程管理
  通道；不要把本地工具暴露到网络。
- 反代/负载均衡只提供配置样例，未做真实代理联调（见 `reverse-proxy.md`）。
- 未做多实例部署；SQLite 为单实例主库，跨实例共享会话/限流/任务协调未实现。
- TCP 代理协议（PROXY protocol）、OCSP/CRL、证书自动续期未实现。
