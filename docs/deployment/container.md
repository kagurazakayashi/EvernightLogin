# 容器部署

本文件给出 login 的容器化样例与边界。样例见 `samples/Dockerfile`、`samples/docker-compose.yml`。

## 1. 当前状态（先读）

- 项目是**纯 Go 模块**，SQLite 使用纯 Go 驱动（`modernc.org/sqlite`），因此
  `CGO_ENABLED=0` 的静态二进制可在 `scratch`/`distroless` 等最小镜像中运行。
- `cmd/login-server` 现已支持 `init`（本地首次初始化）与 `serve`（真实启动 HTTP 服务：
  配置/迁移门禁/密钥/审计/维护门禁/单实例锁/内置账户入口页/健康检查/TLS/访问日志轮转/
  后台任务运行时/优雅关闭）。容器样例
  的 `ENTRYPOINT` 仍是无参数形式，直接运行只会得到用法错误；在容器中运行需按
  `standalone-service.md` 第 3 节补 `serve --config <挂载配置>` 参数，并把
  `init` 作为一次性初始化任务单独执行（不要把 root 初始化逻辑塞进容器启动脚本）。
- 当前镜像**不是开箱即用的完整对外 OAuth2/OIDC 服务**：协议端点与管理 JSON API 已装配但
  默认关闭（需配置 `protocol.enabled`/`--enable-protocol`、`--enable-admin-api`）；
  设备码/扫码/令牌状态查询未启用；root Passkey 强认证绑定已接线但未做真机互操作；邮件
  外发仍本地禁用（限制见 `standalone-service.md` 第 6 节）。
- 备份工具 `cmd/login-backup` 与管理 CLI `cmd/loginctl` 可在容器内以独立命令运行
  （需要挂载数据库与密钥卷）。
- 本轮**未实际构建/运行容器镜像**（环境不保证有 Docker）；样例只用于表达配置契约，
  上线前必须在目标环境自行构建验证并核对 `packaging.md` 的校验清单。

## 2. 镜像设计

- 多阶段构建：`golang:1.27` 构建阶段 + `scratch`（或 `gcr.io/distroless/static`）运行阶段。
- 构建参数固定：`CGO_ENABLED=0`、`GOOS=linux`、`GOARCH=amd64|arm64`、`-trimpath`、
  `-ldflags` 注入版本/提交/构建时间。
- 运行阶段使用非 root 数字用户（例如 `65532:65532`），不包含 shell、包管理器和编译器。
- 不把秘密放进镜像层：主密钥、TLS 私钥、客户端 secret 只能通过只读挂载的秘密文件或
  运行时环境注入；构建参数与镜像历史中不得出现秘密。
- 二进制可执行文件放入 `/app/bin/`，工作目录 `/app`。

## 3. 卷与文件系统

| 路径 | 内容 | 权限建议 |
|---|---|---|
| `/app/config` | `login.yaml` 等配置 | 只读挂载，0755/0644 |
| `/app/secrets` | 主密钥文件、TLS 私钥等 | 只读挂载，仅容器用户可读，0640 或更严格 |
| `/app/data` | SQLite 数据库 | 可写卷，0700，独占访问（不要多容器共享） |
| `/app/backups` | 加密备份输出 | 可写卷，与 secrets 分离 |
| `/app/logs` | 访问日志/运行日志 | 可写卷，按轮转策略清理 |

- 根文件系统只读（`read_only: true`），需要写 `/tmp` 时使用 `tmpfs`。
- SQLite 是单实例数据库：**不要**用同一数据卷启动多个副本，也不要把 `data/` 放在网络
  文件系统上（WAL 与锁语义无法保证）。

## 4. PDF 报告的字体依赖

报告 PDF 需要 Noto Sans SC 字体，字体**不内嵌、不进镜像**（约 10.5 MB，许可证 OFL）：

1. 在镜像构建或启动前用 `scripts/fetch-report-font.ps1`（或等价流程）取得字体，并核对
   SHA-256 与字节数（脚本会强制校验）。
2. 把字体放在只读挂载（例如 `/app/assets/fonts/NotoSansSC-Regular.ttf`）。
3. 在宿主装配报告服务时通过受信配置提供 `reports.Options.FontPath`（绝对路径）与默认
   摘要校验；路径必须是常规文件、非符号链接，否则构造服务时拒绝。
4. 随发行包保留 `docs/licenses/NotoSansSC-OFL.txt`。

没有字体时不要启用 PDF 报告；渲染会因字体不可用而失败（而不是输出缺字/伪造内容）。

## 5. 样例构建命令（可复现）

```bash
# 在仓库根目录；仅 Linux 目标示例
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -X github.com/kagurazakayashi/EvernightLogin.version=<VERSION> \
  -X github.com/kagurazakayashi/EvernightLogin.commit=<COMMIT> \
  -X github.com/kagurazakayashi/EvernightLogin.buildTime=<BUILD_TIME>" \
  -o build/linux-amd64/login-server ./cmd/login-server
```

正式发布包请使用 `scripts/build-release.ps1`（Windows PowerShell 7 / Windows PowerShell
5.1 均可运行），它会统一注入版本信息并生成校验清单。

## 6. 运行须知

- `docker run --read-only --tmpfs /tmp:rw,noexec,nosuid -u 65532:65532` 只读根 + tmpfs。
- 首次启动前先做配置校验（当前用仓库内 `examples/config-load`；发布二进制尚不读取配置）。
- 反向代理/入口网关的 TLS 配置与 `trusted_proxies` 必须一致，见 `reverse-proxy.md`。
- 日志是容器标准输出还是文件按部署选择；不要在同一卷上无限追加且不轮转。
- 容器编排的健康检查只能依赖已装配的 HTTP 健康端点；当前 `login-server` 未提供服务
  端点，不要配置会产生假成功的固定健康检查。

## 7. 已知限制

- 未实际构建/运行容器镜像（本机未执行 Docker 构建），不是已验收的容器交付物。
- 未提供 Kubernetes/Helm 清单；第一版不实现多实例高可用与共享会话/限流。
- 镜像中不包含字体；PDF 报告需按第 4 节单独挂载。
- 当前镜像内的 `login-server` 不能对外提供 HTTP 服务（见第 1 节）。
