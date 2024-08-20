# login（EvernightLogin）

login 是一个用 Go 编写的**用户与身份权限系统**：既可以作为 Go 库嵌入业务程序，也可以作为
独立身份服务部署，提供账户、登录、会话、用户组/角色/权限、Passkey/TOTP、OAuth 2.0 /
OpenID Connect、审计、报告、备份恢复和管理后台。

本 README 是**人类最短上手页**：只讲定位、选择、依赖、快速开始、示例、目录、安全边界与
文档入口。完整规范与操作细节在 [`docs/`](docs/README.md)（路线图见下文“文档地图”）。

## 1. 选择形态

| 形态 | 适合 | 入口 |
|---|---|---|
| 嵌入 Go 业务 | 已有 Go 服务，想复用账户/权限/会话/审计/页面，同时自己控制进程、数据库与 HTTP 服务器 | 公开包 `github.com/kagurazakayashi/EvernightLogin` + `/app`；[嵌入文档](docs/embedding/README.md) |
| 独立身份服务 | 需要开箱即用的身份服务与内置管理页面，以独立进程部署 | `login-server` CLI；[首次部署](docs/deployment/first-run.md) |
| 两者混用 | 先嵌入跑通业务，再切独立服务或反向挂载 | 两条路径共用同一套领域服务与配置；[模式对照](docs/guide/deployment-modes.md) |

能力速览：全局账户 + 应用成员/应用内角色权限隔离（默认拒绝）；密码、Passkey、TOTP、邮件
验证码、恢复代码、邀请/注册审核；OAuth 2.0 / OIDC、设备码、APP 扫码、令牌状态查询；用户/
组/角色/权限管理、审计、统计报告、加密备份恢复、CLI 应急恢复。当前状态与机器可读能力清单见
[`docs/acceptance/capability-matrix.md`](docs/acceptance/capability-matrix.md)。

## 2. 最低依赖与平台状态

- Go 版本与 `go.mod` 一致（当前 Go 1.27.x）；`CGO_ENABLED=0` 可用；SQLite 为内置主存储。
- 构建/测试工具链固定：`CGO_ENABLED=0`、`GOTOOLCHAIN=local`、`GOWORK=off`、`GOFLAGS=-mod=readonly`、`GOMAXPROCS=2`（见 [一键构建说明](docs/deployment/one-click-build.md)）。

| 平台/数据库 | 编译 | 运行实测 |
|---|---|---|
| Windows amd64 | 已实测 | **唯一运行实测平台** |
| Windows arm64 / Linux / macOS（amd64、arm64） | 已编译 | 未运行实测 |
| SQLite | 已实测 | **唯一运行实测数据库** |
| MySQL / PostgreSQL / SQL Server | 有方言与迁移代码 | 未运行实测 |

未实测不代表不可用，也不代表已通过；上线前请在自己的目标平台按
[发布打包清单](docs/deployment/packaging.md) 复验。

## 3. 构建

从源码构建三个程序（单命令调试；Windows 下把输出路径换成 `build\login-server.exe` 等）：

```bash
CGO_ENABLED=0 go build -o build/login-server ./cmd/login-server
CGO_ENABLED=0 go build -o build/loginctl ./cmd/loginctl
CGO_ENABLED=0 go build -o build/login-backup ./cmd/login-backup
```

推荐根目录一键入口（4 个命令 × 6 个目标 = 24 项产物，含版本/commit/平台/命令入口/SHA-256
的可追溯清单与失败/取消状态）：

```powershell
.\build.ps1 -Version 0.1.0-dev          # Windows PowerShell 5.1/7
```

```sh
sh build.sh                            # POSIX：有 PowerShell 时自动委托
sh build.sh --no-powershell            # 仅 POSIX shell + Go 的原生路径
```

默认输出到 `dist/build/`（`build-summary.json`、`checklist.txt` 等），由
`scripts/verify-build.ps1` 独立校验类型/架构/哈希；发布包 per-target zip 由
`scripts/package-release.ps1` 生成并用 `scripts/verify-release.ps1` 校验。`build.ps1`/
`build.cmd` 与（检测到 PowerShell 的）`build.sh` 都委托 `scripts/build-all.ps1` 单一实现；
`build.sh --no-powershell` 使用等价的 POSIX shell + Go 原生路径。入口参数、退出码、失败/取消
与清理边界见 [一键构建与可追溯产物清单](docs/deployment/one-click-build.md)。

## 4. 快速开始 A：嵌入（约 5 分钟）

```go
import (
	"context"
	"net/http"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/app"
)

func main() {
	ctx := context.Background()
	cfg := login.Default() // 也可 login.Load(login.LoadOptions{YAMLFile: "login.yaml"})
	runtime, err := app.Open(ctx, app.Options{
		Config: &cfg, DatabasePath: "data/login.db", MasterKeyFile: "secrets/master.key",
		Migrate: true, CreateMasterKey: true, OperatorID: "my-service",
		HTTP: &app.HTTPOptions{Prefix: "/idp"},
	})
	if err != nil {
		panic(err)
	}
	defer runtime.Close(ctx) // 只关闭运行时自建资源；Close 幂等
	if err := runtime.Start(ctx); err != nil { // 后台任务必须显式启动
		panic(err)
	}

	mux := http.NewServeMux()
	if err := runtime.Mount(mux); err != nil {
		panic(err)
	}
	_ = http.ListenAndServe("127.0.0.1:8080", mux) // 监听器与生命周期归宿主
}
```

要点：`Open` 只构造运行时（`StateNew`），不监听端口、不启动后台任务；后台任务要显式
`Start`；`Close` 幂等且不关闭宿主注入的数据库/日志/通知器。完整生命周期、身份与资源所有权
边界见 [嵌入文档](docs/embedding/README.md) 与
[宿主集成指南](docs/embedding/host_integration.md)。

可运行最小示例（真实临时 SQLite、动态回环端口、有界自检）：

```powershell
cd examples/embedded-minimal
$env:CGO_ENABLED='0'; $env:GOMAXPROCS='2'
go run . -self-test -json      # 预期 status=PASS（15 项检查），退出码 0
go run . -demo                 # 显式启动演示，Ctrl+C 或 -duration 到期后清理
```

## 5. 自包含协议与安全集成测试（开发/CI）

无需外网、外部数据库或手工安装第三方软件，可直接运行真实协议/安全场景（OAuth/OIDC、
会话权限、CSRF/来源、防枚举、软件 TOTP/WebAuthn）：

```powershell
go run ./scripts/protocol-selftest -out P:\go\tmp\protocol-selftest.json -verbose
```

场景、覆盖矩阵、JSON 结果与退出码见
[`docs/deployment/protocol-selftest.md`](docs/deployment/protocol-selftest.md)。

## 5. 快速开始 B：独立部署（约 10 分钟）

1. 准备目录：`config/login.yaml`、`data/login.db`、`secrets/master.key`、`logs/` 分开存放。
2. 首次初始化（只执行一次；root 密码不回显）：

```bat
D:\login\bin\login-server.exe init --config D:\login\config\login.yaml ^
  --master-key-file D:\login\secrets\master.key --operator os:deployer@myhost
```

3. 启动服务（首次/升级后需显式迁移）：

```bat
D:\login\bin\login-server.exe serve --config D:\login\config\login.yaml ^
  --master-key-file D:\login\secrets\master.key --migrate=apply ^
  --access-log D:\login\logs\access.log
```

4. 验证与首次登录：`/healthz`、`/login` 应返回 200；浏览器用 `root` 登录后按提示在
   `/login/strong-setup` 完成 **Passkey** 强认证绑定，才能进入管理页。

最小配置、字段说明、systemd/TLS/反代、邮件与安全初始化细节见：
[首次配置](docs/deployment/first-run.md)、[独立服务启动](docs/deployment/standalone-service.md)、
[业务接入契约](docs/deployment/integration.md)、[完整配置](docs/guide/configuration.md)。

## 6. 目录说明

```text
cmd/            独立程序入口：login-server、loginctl、login-backup
app/            公开嵌入式装配（Open/生命周期/领域服务门面）
config/ errs/ httpapi/ appids/ netpolicy/ proxytrust/ passkeypolicy/ httppolicy/
correlation/    可被宿主导入的公开叶子包（配置/错误码/HTTP 契约等）
internal/       领域实现与内部装配（宿主不能导入）
migrations/     有序数据库迁移（增量、不清库）
web/            内置页面模板与静态资源（go:embed）
examples/       可运行示例（部分为独立 Go module）
scripts/        构建、校验、短测试与能力清单工具
docs/           产品文档（见“文档地图”）
tools/          本地验收辅助工具（不进入发布）
EvernightMail/  本地测试邮件服务器（独立 Git 子模块与 Go Module）
go-build-all/   通用跨平台构建工具（独立 Git 子模块与 Go Module）
```

> **重构说明**：根目录目前仍保留 `ui.go` / `ui_pages_*.go` 页面控制与视图实现、`doc.go`
> 包文档及 `alias_*.go` 兼容别名；步骤 214/215 会把页面实现迁入专门目录并收敛公开运行时
> 入口，本节目录结构会在重构提交后更新。

## 7. 三个示例与一键自检

| 示例 | 演示 | 实测命令（仓库根执行） |
|---|---|---|
| [`examples/embedded-minimal`](examples/embedded-minimal/) | 最小嵌入：打开实例→受控初始化→注册/登录→会话校验→HTTP/UI 挂载→关闭清理；`-self-test` 15 项 | `cd examples/embedded-minimal` 后 `go run . -self-test -json` → `status=PASS`，退出码 0 |
| [`examples/custom-pages-profile-sync`](examples/custom-pages-profile-sync/) | 宿主自定义页面与内置页面并存；公开 `Profile()` 资料读写/受控改名；业务投影按稳定 UserID 同步；本地邮件验证/找回；`-self-test` 23 项 | `cd examples/custom-pages-profile-sync` 后 `go run . -self-test -json` → `status=PASS`，退出码 0 |
| [`examples/external-consumer`](examples/external-consumer/) | 真正外部 Go module：仅用公开包完成配置校验、扩展注册、页面替换、HTTP 挂载、生命周期与 fail-closed 判定 | `cd examples/external-consumer` 后 `go run .` → 输出“……示例通过”，退出码 0 |

一键自检（统一短测试入口：临时目录、动态回环端口、总超时、子进程退出与清理、结构化
JSON 由入口负责）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\shorttest.ps1 -List
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\shorttest.ps1 -Scenario embedded-minimal-selftest -TimeoutSeconds 180
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\shorttest.ps1 -Scenario custom-pages-profile-sync-selftest -TimeoutSeconds 240
```

其余示例（OIDC 客户端、设备码/扫码、托管 API、客服、恢复密码消费方、RBAC 消费方等）见
[示例索引](docs/guide/README.md#11-示例索引)。

## 8. 文档地图

| 入口 | 内容 |
|---|---|
| [`docs/README.md`](docs/README.md) | **文档中心**：目录地图、阅读路径、文档约定 |
| [`docs/guide/`](docs/guide/README.md) | 产品使用主干：能力状态、快速开始、两模式、登录/OAuth、应用与权限、角色与范围、配置、客服恢复、CLI、审计报告、备份恢复、错误码与[内置 Web 管理台](docs/guide/admin-console.md) |
| [`docs/deployment/`](docs/deployment/README.md) | 首次配置、独立服务、TLS/反代、容器、服务托管、邮件子模块、协议/管理 API 接入、一键构建与发布打包 |
| [`docs/embedding/`](docs/embedding/README.md) | 作为 Go Module 嵌入：公开 API 稳定范围、生命周期与资源所有权、页面替换、示例与宿主调用边界 |
| `docs/reference/` | 人类与 AI 共用的接口参考（Go API/HTTP/CLI/权限/错误码/配置/能力映射）——**待步骤 245 建立**；当前以源码 GoDoc 与上述 guide/embedding 为准 |
| [`docs/acceptance/`](docs/acceptance/README.md) | 验收与交付核对记录、能力矩阵、[短测试入口](docs/acceptance/shorttest.md)；历史证据不改写 |
| [`docs/database/`](docs/database/存储模型与迁移设计.md) | 存储模型、迁移与方言说明 |
| [`docs/requirements/`](docs/requirements/) | 需求基线（设计目标，不等于已实现）与错误码历史手册 |
| [`docs/licenses/`](docs/licenses/THIRD_PARTY_NOTICES.md) | 第三方组件/字体/依赖的版权与许可声明 |

开发协作材料：`AGENTS.md`（仓库开发约束）、`MEMORY.md`、`.ai/`（步骤、报告与证据）是本地
开发协作材料，**不属于产品文档，也不进入发布包**；产品交付文档以 `docs/` 为准。本 README
为简体中文单语版本（历史没有其他语言版本）；新增翻译需以本文件为基准同步维护。

## 9. 安全边界速览

- **账户与应用隔离**：全局账户 + 应用成员/应用内角色权限/数据范围隔离；默认拒绝、fail-closed；功能权限不代替资源归属检查。
- **可信身份**：`LocalAdmin` 仅代表持有宿主进程控制权的可信本地代码，不能由 HTTP 参数或普通用户取得；root 是唯一受保护账户，不能作为普通角色分配。
- **账户有效期**：全局可用时间（UTC 半开区间）在身份生效和请求校验处即时判断，不依赖后台扫描；到期不等于手动禁用，续期不解除禁用；root 不受普通期限管理。
- **邮件**：测试用本地 EvernightMail/捕获器，生产需显式配置 SMTP；`mail.enabled=false` 时明确失败，不伪造成功；不要向真实第三方地址发测试邮件。
- **能力默认关闭**：OAuth/OIDC、管理 JSON API、托管 API、客服 API 需显式开关，Discovery 只声明真实能力；验收边界见 [登录与 OAuth 文档](docs/guide/login-and-oauth.md)。
- **不做的事与平台口径**：不做多租户/多实例共享状态、短信供应商、第三方社交登录、动态 Go plugin、跨数据库迁移；只有 Windows 11 + SQLite 做过运行实测，其他平台/数据库仅编译或静态检查，未测能力不写成“已验证”。

## 10. 排障与许可

排障入口：[错误码与排障](docs/guide/troubleshooting.md)、
[错误码手册](docs/requirements/login_错误码与排障手册.md)、
[本地 CLI 与应急恢复](docs/guide/root-cli.md)、[已知限制与平台口径](docs/guide/README.md#6-平台与实测口径)。

本项目采用 **MulanPSL2（木兰宽松许可证，第 2 版）**，全文见 [LICENSE](LICENSE)。项目署名严格为
`Copyright (c) KagurazakaYashi(KagurazakaMiyabi)`，不附年份；第三方组件、字体与依赖保留其原有
版权/许可声明，详见 [THIRD_PARTY_NOTICES](docs/licenses/THIRD_PARTY_NOTICES.md) 与
[`docs/licenses/`](docs/licenses/)。
