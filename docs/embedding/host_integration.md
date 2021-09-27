# 宿主集成与公开 API 稳定范围（嵌入模式）

本文面向把 EvernightLogin 作为 Go 模块嵌入自有业务的宿主开发者，说明公开 API
的稳定范围、破坏性变更策略、最小装配步骤以及生命周期/资源所有权的硬约束。

- 模块：`github.com/kagurazakayashi/EvernightLogin`（包名 `login`）。
- 本文对应步骤 88「收敛公开 Go API、扩展注册与宿主集成示例」。
- 示例：`examples/external-consumer/`（独立 Go module，只使用公开包）。

> 重要：`internal/` 下的包按 Go 的 internal 规则不能被本模块之外的代码导入。
> 宿主只能使用根包 `login` 的公开类型。若某能力只在 `internal/` 暴露，它在
> 公开包装出现之前不可被外部宿主使用；不要用复制内部代码或改 import 路径绕过。

## 1. 公开 API 稳定范围

### 1.1 稳定契约（宿主可依赖）

| 范围 | 公开符号 | 说明 |
|---|---|---|
| 实例生命周期 | `New`、`Options`、`Instance`、`State`（`StateNew`/`StateRunning`/`StateClosed`）、`Start`、`Close`、`State`、`Config`、`Logger`、`ErrAlreadyStarted`、`ErrClosed`、`ErrNotRunning` | 状态机只有 `New → Running → Closed` 一条路径，关闭后不可重启；重复 `Close` 安全 |
| 扩展注册 | `Extension`、`ExtensionInfo`、`ExtensionKind`、`MaxExtensions`、`Options.ExtensionStartTimeout`、`DefaultExtensionStartTimeout`、`Instance.Extensions` | 扩展由实例统一启动/关闭；注册信息在 `New` 校验并快照；单扩展启动带 panic 恢复与墙钟上限 |
| 宿主依赖注入 | `Options.Database`（`Database`）、`Options.Notifications`（`Notifier`、`LifecycleEvent`、`LifecycleEventKind`、`LifecycleNotifyTimeout`）、`Options.AccessControl`（`AccessController`）、`Options.Logger`/`Options.LogOutput` | 注入对象由宿主拥有；实例不关闭它们；生命周期通知在锁外发送且受 2s 上限约束 |
| HTTP 装配与挂载 | `Options.HTTP`（`HTTPOptions`）、`Options.Pages`（`WebUIOptions`）、`Instance.Handler`、`Instance.HandlerPrefix`、`Instance.Mount`、`NewHTTPHandler`、`OpenAPIDocument` | 只承诺标准 `net/http`（`http.Handler`/`http.ServeMux`）；`New` 不监听端口 |
| 就绪检查 | `Instance.Ready`、`ReadyChecker` | 未运行、数据库不可用、扩展健康检查失败时不报就绪 |
| 授权判定 | `AccessController`、`AccessRequest`、`AccessDecision`、`Permission`、`PermissionScope`、`Instance.CheckAccess` | 未注入扩展时一律拒绝（fail-closed），`system` 身份不自动放行 |
| 身份 | `Identity`、`IdentityKind`、`Identity.Validate`、`ErrIdentityInvalid`、`IdentityFromContext`、`WithIdentity`、`RequestIDFromContext` | 身份只能由可信边界建立；请求参数不能自称身份 |
| 错误 | `AppError`、`ErrorCode`、`Code*` 常量、`NewAppError`、`WithCause`/`WithRequestID`/`WithTaskID`/`WithInternalReasonCode`、`AsAppError`、`IsErrorCode`、`ErrorCodeOf`、`FromError`、`NewRequestID`、`ValidateRequestID` | 错误码集合只增不删；新增错误码属兼容扩展 |
| 配置 | `Config`、`Default`、`Validate`、`Load`、`LoadOptions`、`Fields`、`LookupField`、`Diagnostic`、`FieldValues`、`Ptr` | YAML 字段语义以配置文档为准；新增可选字段属兼容扩展 |
| 页面契约 | `NewWebUI`、`WebUIOptions`、`UIContractVersion`（`ui.v1`）、`UIRoute`、`UIPageContext`、`UIPageRenderer`、`UIHostTemplates`、`DefaultUIPageContentSecurityPolicy` 等 | 删除字段、改变路由含义、放宽安全要求必须升 `UIContractVersion` |
| 独立监听 | `NewServer`、`ServerOptions`、`Server`（`BackgroundComponent`）、`TLSStatus` 等 | 与嵌入 Handler 复用同一传输层；默认只允许回环监听 |
| 构建信息 | `CurrentBuildInfo`、版本相关公开函数 | 只读诊断信息 |

### 1.2 兼容扩展（不算破坏性变更）

- `Options` 增加新的可选字段：零值保持"不启用"语义，旧代码行为不变。
- `ExtensionKind` 增加新的分类、`ErrorCode` 增加新错误码、`UIRoute` 增加新命名路由。
- `WebUIOptions`、`HTTPOptions`、`ServerOptions` 增加可选字段。
- 文档补充、GoDoc 说明、诊断输出字段增加。

### 1.3 不承诺稳定（宿主不应依赖）

- 内置页面路由的完整集合与页面 HTML 结构（按 `ui.v1` 契约的命名路由与视图模型
  使用，不解析具体 DOM）。
- 访问日志格式、运行日志文本、诊断输出文本。
- `internal/` 下任何包（无论是否被根包间接引用）。
- `cmd/*` 进程入口的参数与输出（对外契约是 `login` 根包与配置文档）。
- 尚未公开的仓储/服务装配：真实数据库仓储、authz 引擎、会话服务等目前在
  `internal/`，宿主无法直接注入；在公开包装出现前，完整服务装配仍须在模块内
  进行（入口为 `cmd/login-server` 的后续装配步骤）。

## 2. 破坏性变更策略

模块当前尚未发布 `v1.0.0`，但公开契约按以下规则管理：

1. **安全语义只收紧不放宽**：fail-closed、资源所有权、身份来源、CSRF/限流等约束
   不得为了兼容而放宽；收紧必须记录在 `MEMORY.md` 与对应开发/审计报告。
2. **删除或改义必须显式记录**：删除公开符号、改变字段语义、改变状态机行为属于
   破坏性变更，必须在开发报告中单列，并在本文「变更记录」中追加条目；提供迁移
   说明，能保留的旧符号先标记 `Deprecated` 至少一个步骤。
3. **页面契约单独升版**：删除/改义 `ui.v1` 的命名路由、模板名或视图模型字段时，
   必须把 `UIContractVersion` 升到 `ui.v2`，并在 `NewWebUI` 拒绝旧契约或提供迁移。
4. **错误码与权限键只增不删**：已发布的错误码/权限键不删除、不复用；新增是兼容
   变更，需同步错误码注册表、机器可读文档与手册。
5. **零值兼容**：`Options`/`HTTPOptions`/`WebUIOptions` 新增字段的零值必须等价于
   "未启用/默认安全值"，不得改变已构造实例的行为。
6. **记录位置**：每个步骤的破坏性变更写入 `.ai/lead/reports/stepNN-dev.md` 与
   `MEMORY.md`；本文维护跨步骤的稳定范围与变更记录。

## 3. 最小宿主集成示例

下面是最小装配（配置 → 实例 → 挂到宿主 mux → 启动 → 就绪 → 关闭）。
完整可运行版本见 `examples/external-consumer/main.go`。

```go
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

func main() {
	// 1) 配置：YAML + 环境变量 + 显式覆盖（全部为公开 API）。
	//    生产请从受控配置目录读取，不要把秘密写进源码或日志。
	config, err := login.Load(login.LoadOptions{YAMLFile: "login.yaml"})
	if err != nil {
		fmt.Fprintln(os.Stderr, "配置无效：", err)
		os.Exit(1)
	}

	// 2) 宿主拥有的资源：数据库连接、日志器、授权判定。实例不会关闭它们。
	database := login.DatabaseFunc(func(context.Context) error { return nil })
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil)) // 实现 *slog.Logger
	authorizer := login.AccessControllerFunc(func(_ context.Context,
		request login.AccessRequest) (login.AccessDecision, error) {
		// 这里必须是宿主的真实权限判定；示例默认拒绝，绝不默认放行。
		return login.AccessDecision{Allowed: false, Reason: "permission_missing"}, nil
	})
	notifier := login.NotifierFunc(func(context.Context, login.LifecycleEvent) error {
		return nil
	})

	instance, err := login.New(login.Options{
		Config:        &config,
		Logger:        logger,
		Database:      database,
		Notifications: notifier,
		AccessControl: authorizer,
		Extensions:    []login.Extension{myStorageExtension{}},
		Pages:         &login.WebUIOptions{Prefix: "/idp"},
		HTTP:          &login.HTTPOptions{Prefix: "/idp"},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "构造实例失败：", err)
		os.Exit(1)
	}

	// 3) 挂到宿主自己的 mux；也可以直接使用 instance.Handler()。
	mux := http.NewServeMux()
	mux.HandleFunc("/", hostHome)
	if err := instance.Mount(mux); err != nil {
		fmt.Fprintln(os.Stderr, "挂载失败：", err)
		os.Exit(1)
	}

	// 4) 启动与就绪。宿主自己监听端口；实例本身不监听。
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := instance.Start(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "启动失败：", err)
		os.Exit(1)
	}
	if err := instance.Ready(ctx); err != nil {
		_ = instance.Close(ctx)
		fmt.Fprintln(os.Stderr, "未就绪：", err)
		os.Exit(1)
	}

	// 5) 关闭：宿主控制生命周期，实例只关闭自己管理的扩展/组件。
	//    database/logger/notifier/authorizer 仍需宿主自行关闭或停止使用。
	defer func() { _ = instance.Close(context.Background()) }()
	_ = http.ListenAndServe("127.0.0.1:8080", mux)
}

func hostHome(http.ResponseWriter, *http.Request) {}
```

配套实现要点：

- `login.Database` 只需 `Ping(ctx) error`；连接由宿主打开/关闭。
- `login.Notifier` 只处理生命周期事件，失败不会回滚实例；不得在通知中写秘密。
- `login.AccessController.CheckAccess` 必须基于真实会话/权限判定；返回错误表示
  判定失败，调用方会按 fail-closed 拒绝。
- 页面替换：自定义 `login.WebUIOptions.HostTemplates`/`HostRenderer`；整体关闭
  内置页面用 `DisableBuiltinPages`，但服务端认证/权限/CSRF 不会因此放宽。

## 4. 生命周期、取消与资源所有权

- 状态机：`StateNew → StateRunning → StateClosed`。`Start` 只能成功一次；失败或
  取消后实例进入 `StateClosed`，不能重试；`Close` 可重复调用且幂等。
- 启动顺序：扩展（`Options.Extensions` 声明顺序）→ 后台组件（`Options.Components`
  声明顺序）。失败回滚为整体逆序：先逆序关闭后台组件，再逆序关闭扩展。
- 关闭期限：调用方 `ctx` 与 `Config.Server.ShutdownTimeoutSeconds` 取较小值；
  超时组件仍会被尝试调用 `Close` 一次，由组件自行遵守取消。
- 取消：`Start(ctx)` 取消后先回滚已启动对象；对正在启动的扩展，Instance 会额外
  等待其在 `min(Options.ExtensionStartTimeout, ExtensionStartCancelWait)`（最多
  2s）内返回并完成自清理后再返回失败，因此正常实现取消时资源清理已完成；扩展
  忽略 ctx 且超过窗口未返回时，错误原因链明确标记「可能遗留资源」，Instance 不
  永久阻塞、不强制终止宿主协程。
- 扩展健壮性：单个扩展 `Start` 带 panic 恢复与墙钟上限
  （`Options.ExtensionStartTimeout`，默认 `DefaultExtensionStartTimeout`=30s，
  范围 100ms～10min）：panic 或超时都按启动失败处理（fail-closed）并回滚已启动
  对象；超时后同样等待扩展在 `ExtensionStartCancelWait`（2s）内返回，未返回则以
  「可能遗留资源」失败（契约要求扩展遵守 ctx）。扩展 `Close` 与后台组件 `Close`
  的 panic 都会被恢复为错误并继续逆序关闭其余对象，不会使宿主进程崩溃。
- 生命周期通知在释放实例锁之后发送，单次通知受 `LifecycleNotifyTimeout`（2s）
  约束：慢/挂起的通知器不会阻塞或死锁 `Start`/`Close`，超时后实例放弃等待并写
  告警。通知器可以读取实例公开状态，但不得在通知中反向驱动生命周期语义。
- `Handler`/`Mount` 与生命周期解耦：`Start` 之前与 `Close` 之后都可挂载和提供
  处理器；`Mount` 遇到 `http.ServeMux` 的重复/冲突 pattern 时捕获 panic 并返回
  `CONFIG_INVALID`（原因链保留冲突信息），不会把 panic 抛给宿主。
- 从未启动直接 `Close`：实例进入 `StateClosed`，并在配置通知器时发送一次
  `LifecycleClosed` 通知；重复 `Close` 不重复通知。`CheckAccess` 不要求实例已
  启动（同一 fail-closed 规则），就绪判断请用 `Ready`。
- 资源所有权：
  - 实例拥有的：扩展/组件生命周期，扩展与组件自己创建的资源；
  - 宿主拥有的：数据库连接、HTTP 服务器与监听、日志器与输出、页面资源 FS、
    密钥文件句柄、Notifier/AccessController、宿主 mux；
  - 实例**不会**关闭 `Options.Database`/`Options.Notifications`/`Options.AccessControl`，
    扩展也不得关闭宿主传入的资源。
- 没有隐式全局实例；导入本包不会启动协程、打开数据库或监听端口（无 `init()`
  副作用）。同一进程可以创建多个实例，互不共享配置、扩展或状态。

## 5. 扩展注册与失败策略

```go
type Extension interface {
	ExtensionInfo() login.ExtensionInfo // 分类/名称/版本，注册时校验
	Start(ctx context.Context) error
	Close(ctx context.Context) error
}
```

- 注册校验（`New` 时整体拒绝，不做部分注册）：分类必须已定义；名称非空且只含
  ASCII 字母/数字/`.`/`_`/`-`，≤64 字符；`kind+name` 不得重复；数量 ≤`MaxExtensions`；
  nil/typed-nil 拒绝。
- 分类：`component`、`storage`、`notification`、`authentication`、`mfa`、`page`。
- **安全敏感分类**：`authentication` 与 `mfa` 必须声明非空 `Version`；启动失败、
  健康检查失败都按整体不可用处理（fail-closed），不会降级为"跳过认证/关闭鉴权"。
- 关闭顺序与启动相反；只对成功启动过的扩展调用一次 `Close`；启动失败的扩展由
  自己清理，实例不再调用它。扩展 `Start` panic/超时按启动失败处理，`Close` panic
  会恢复为错误并继续关闭其余扩展（均不使宿主进程崩溃）。
- 本包**不提供**：伪造 root / 系统资格的方法，跳过授权判定的开关，关闭鉴权的
  选项，或用请求参数建立可信身份的入口。`Identity.Kind = system` 只是主体类型，
  不会自动获准；授权判定必须经 `AccessController`。
- 认证/MFA 扩展目前只是"注册、生命周期、失败策略"契约：根包尚未公开真实认证
  服务适配器，注册一个扩展不等于已具备生产认证能力；未装配时受限/拒绝是预期
  行为。多实例共享状态与集群协调**未实现**（仅保留分类与本文契约；不提前实现
  集群，也不引入全局单例或共享缓存）。

## 6. 外部消费验证（步骤 88 实测）

`examples/external-consumer/` 是独立 Go module（自己的 `go.mod` + `go.sum`），
通过 `replace github.com/kagurazakayashi/EvernightLogin => ../..` 引用本地仓库，
源码只导入标准库与公开包，**没有任何 `internal/` 导入**。它覆盖：配置校验、
扩展注册、页面替换、HTTP 挂载到宿主 mux（内存驱动，不监听端口）、两实例隔离、
扩展失败错误码传播、启动取消回滚、宿主资源不被关闭、未注入授权扩展时 fail-closed。

在 Windows amd64 / Go 1.27.4 / `CGO_ENABLED=0` 下的实测命令与结果：

```text
cd examples/external-consumer
go build ./...          # EXIT=0
go vet ./...            # EXIT=0
go run .                # EXIT=0，输出：
# 构建信息: devel (commit unknown, built unknown, go1.27.4)
# external-consumer 示例通过：外部模块仅用公开 API 完成配置、扩展注册、HTTP 挂载、
#   生命周期、失败传播与 fail-closed 判定
go list -f '{{join .Imports "\n"}}' .   # 直接导入仅 stdlib + github.com/kagurazakayashi/EvernightLogin
```

说明：外部模块能编译成功本身就证明公开 API 签名没有出现不可导入的 `internal`
类型；若公开签名引用 `internal` 类型，外部模块将无法编译。仓库根的
`go build ./...`/`go test ./...` 会跳过该嵌套模块（Go 对含 `go.mod` 子目录的
规则），因此外部示例需要按上面的命令单独验证。

**未实测**：所有第三方 HTTP 框架（gin/echo/chi/fiber 等）的适配；本文只承诺
标准 `net/http` 契约，宿主可自行用 `http.Handler` 适配。非 Windows 平台、`-race`、
真实监听端口/反向代理部署也未在本步实测。

## 7. 已知限制

- 完整业务服务装配（账户/认证/授权/会话/审计/报告/备份等）仍主要在 `internal/`
  内，对外公开的仓储与服务包装尚未提供；外部宿主当前可完成配置、生命周期、
  HTTP/页面挂载、身份/错误/授权判定契约与扩展注册，但不能仅靠公开包装配完整
  身份服务。`cmd/login-server` 仍为 CLI 入口，服务装配在后续步骤。
- 认证/MFA 扩展只落实注册与 fail-closed 生命周期契约，未提供生产认证适配器。
- 没有集群/多实例共享状态实现；同一进程多实例隔离已测，跨进程协调未实现。
- 真实浏览器页面交互、真实数据库驱动（外部宿主自带的 SQL 驱动）与通知外发
  未在本步验证；通知/邮件真实外发一律需宿主显式配置目标。

## 8. 变更记录

### 步骤 88（2026-11，未发布 v1 前）

新增（全部为兼容扩展，无破坏性变更；`Options` 未设置新字段时行为与之前一致）：

- `Options` 新增 `Extensions`、`Pages`、`HTTP`、`Database`、`Notifications`、`AccessControl`。
- 新增公开类型/符号：`ExtensionKind`、`ExtensionInfo`、`Extension`、`ReadyChecker`、
  `Database`/`DatabaseFunc`、`Notifier`/`NotifierFunc`、`LifecycleEvent`、
  `LifecycleEventKind`、`AccessController`/`AccessControllerFunc`、`AccessRequest`、
  `AccessDecision`、`Permission`、`PermissionScope`、`MaxExtensions` 等长度常量、
  `ErrNotRunning`。
- 新增方法：`Instance.Extensions`、`Instance.Handler`、`Instance.HandlerPrefix`、
  `Instance.Mount`、`Instance.Ready`、`Instance.CheckAccess`。
- 新增示例：`examples/external-consumer/`（独立 module）。

行为补充（不改变既有默认值）：扩展在后台组件之前启动、之后关闭；生命周期通知
为尽力而为旁路；`New` 在设置 `Options.Pages` 但未设置 `Options.HTTP` 或两者前缀
不一致时返回 `CONFIG_INVALID`。

### 步骤 88 审计后硬化（同步骤，无契约版本变更）

针对双审计 M1（Mount panic）/M2（Notifier 锁内同步调用）与生命周期健壮性低项：

- `Instance.Mount` 捕获 `http.ServeMux` 重复/冲突 pattern 的 panic，返回
  `CONFIG_INVALID` 并保留冲突信息；`Handler`/`Mount` 与生命周期解耦的行为写入
  GoDoc 与本文 §4。
- 生命周期通知移出实例锁并加 `LifecycleNotifyTimeout`（2s）上限：慢/挂起的
  `Notifier` 不会阻塞或死锁 `Start`/`Close`，通知器调用的边界写入 GoDoc。
- 扩展 `Start` 增加 panic 恢复与 `Options.ExtensionStartTimeout`（默认 30s，
  范围 100ms～10min）；扩展 `Close` panic 恢复为错误并继续关闭其余对象。
- `Options.Components` typed-nil 拒绝；`AccessRequest.AppID` 增加 ID 字符集/长度
  校验；`CheckAccess` 未启动实例语义、`Close` 从 `StateNew` 的通知语义写入 GoDoc。
- 新增硬化回归测试：重复/冲突 Mount、Start 前挂载、慢 Notifier 有界、Notifier
  回调实例方法不死锁、扩展 Start/Close panic、扩展启动超时、组件 typed-nil、
  AppID 校验、从未启动关闭只通知一次。
- 微门禁回归修复：`startExtensionSafely` 在取消/超时后**等待扩展协程返回**（上限
  `ExtensionStartCancelWait`=2s，实际取 min(启动超时, 2s)）再返回，保证扩展自清理
  完成或错误明确标记「可能遗留资源」；新增 `ExtensionStartCancelWait` 公开常量、
  取消忽略 ctx 的扩展与组件 Close panic 回归测试。`-count=10` 根包实测 0 FAIL。
