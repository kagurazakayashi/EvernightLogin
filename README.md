# login

login 提供可嵌入 Go 程序的用户与权限组件，并计划提供独立的 OAuth 2.0 / OpenID Connect 身份服务。当前只是最小可编译骨架，不是可运行的用户系统。

## 项目状态（步骤 07）

- 模块路径：`github.com/kagurazakayashi/EvernightLogin`，根包名 `login`；路径来自现有远端，首次发布后不再变更。
- 独立进程入口：`cmd/login-server`。当前只提供 `--version` 和 `--help`；不带参数运行会明确失败并返回非零，不假装服务已启动。
- 已实现：版本与构建信息；类型化配置加载器；核心实例生命周期契约；统一错误码注册表、`AppError`、请求编号校验与结构化运行日志；版本化数据库迁移机制及隔离核心表；基于 modernc SQLite 的存储基础（连接/所有权、WAL、外键、忙等待、连接池上限、事务与取消、错误映射、有界重试、迁移执行）。
- 尚未实现：SQLite 尚未接入 `login-server` 或 `Instance` 启动；HTTP 监听与访问日志、账户/认证/授权、OAuth/OIDC、Web 页面、审计数据库、备份流程和后台任务队列仍未实现。
- 代码检查只在本地运行，未配置自动远程流水线。

## 配置加载（步骤 03）

覆盖顺序固定为（后者覆盖前者）：

1. 内置默认值（`login.Default`）
2. YAML 文件或内容
3. 环境变量（固定 `LOGIN_` 前缀，名称是稳定契约）
4. 宿主显式代码选项（`login.Overrides`；指针字段用于区分显式 `false`/`0` 与未设置）

最小调用示例：

```go
cfg, err := login.Load(login.LoadOptions{
    YAMLFile: "login.yaml",
    Overrides: &login.Overrides{
        Database: login.DatabaseOverrides{WAL: login.Ptr(false)},
    },
})
if err != nil {
    // 配置非法：此处必须直接返回，不能先监听端口或打开数据库。
    return err
}
fmt.Print(cfg.Diagnostic()) // 已脱敏；秘密只显示 [REDACTED]/[UNSET]
```

配置字段与环境变量：

| 字段 | 环境变量 | 重载方式 |
|---|---|---|
| server.listen_addr | LOGIN_SERVER_LISTEN_ADDR | 需重启 |
| server.public_base_url | LOGIN_SERVER_PUBLIC_BASE_URL | 需重启 |
| server.shutdown_timeout_seconds | LOGIN_SERVER_SHUTDOWN_TIMEOUT_SECONDS | 可热更新 |
| logging.level | LOGIN_LOGGING_LEVEL | 可热更新 |
| logging.format | LOGIN_LOGGING_FORMAT | 可热更新 |
| database.driver | LOGIN_DATABASE_DRIVER | 需重启 |
| database.path | LOGIN_DATABASE_PATH | 需重启 |
| database.wal | LOGIN_DATABASE_WAL | 需重启 |
| database.busy_timeout_ms | LOGIN_DATABASE_BUSY_TIMEOUT_MS | 需重启 |
| secrets.master_key | LOGIN_SECRETS_MASTER_KEY | 需重启 |

环境变量名是稳定契约，实际列表以 `login.Fields()` 返回值为准。

校验行为：

- 未知字段、重复键、类型错误、`null`、超范围值、非法组合（例如公开地址使用 `http` 却监听非回环地址）都会在加载阶段失败，不产生监听或数据库副作用。
- YAML 只能写秘密来源引用（`secrets.master_key.file` 或 `secrets.master_key.env`）；秘密值也可来自 `LOGIN_SECRETS_MASTER_KEY` 环境变量或宿主显式选项。错误、日志和 `Diagnostic` 输出都不包含秘密内容。
- 字段变更是否需要重启由 `login.Fields()` 与 `login.DiffReload` 给出；本步不实现配置后台或自动热更新。

最小可运行示例见 `examples/config-load`（不会监听端口或写数据库）：

```bat
go run .\examples\config-load -config examples\config-load\login.example.yaml
```

## 实例生命周期（步骤 04）

核心实例使用显式依赖注入，不做全局单例，也不在 `init()` 中启动协程或监听。同一进程可以创建多个互不影响的实例。

```go
cfg, err := login.Load(login.LoadOptions{YAMLFile: "login.yaml"})
if err != nil {
    return err
}
instance, err := login.New(login.Options{Config: &cfg})
if err != nil {
    return err
}
defer instance.Close(context.Background())
// 宿主可以只使用核心能力而不调用 Start；后台组件在后续步骤接入。
if err := instance.Start(ctx); err != nil {
    return err
}
```

状态与重入规则：

| 状态 | 含义 | 可执行操作 |
|---|---|---|
| `new` | 已构造，未启动组件 | `Start`、`Close` |
| `running` | 后台组件已全部启动 | `Close`；再次 `Start` 返回 `ErrAlreadyStarted` |
| `closed` | 已关闭或启动失败 | 只能重复 `Close`（安全返回 nil）；`Start` 返回 `ErrClosed` |

- `New` 只校验配置并复制依赖，不启动组件、不监听端口、不打开数据库、不创建协程。
- `Start` 按 `Options.Components` 顺序启动；任一组件失败时，已启动组件按逆序关闭，失败组件必须自行清理；启动失败后实例进入 `closed`，不会重复启动产生多套资源。
- `Close` 按启动顺序逆序关闭，同时受调用方 `ctx` 期限与配置 `server.shutdown_timeout_seconds` 约束；可安全重复调用，关闭错误会聚合返回，但不会重复返回旧错误。
- 后台组件实现 `login.BackgroundComponent`（`Start`/`Close`）。组件只关闭自己创建的资源；宿主传入的数据库、HTTP 服务器、日志器、密钥文件句柄等由宿主关闭。测试替身只用于测试，不是生产服务。
- 实例按 `Config.Logging` 创建结构化运行日志器；宿主可用 `Options.Logger` 完全注入自己的日志器，或用 `Options.LogOutput` 只注入输出目标（默认 `io.Discard`，嵌入模式静默）。实例不会关闭宿主日志器。
- 本步没有后台任务队列；生命周期接口留给后续数据库、HTTP 和任务模块接入。

## 错误码、请求编号与运行日志（步骤 05）

- 错误码注册表与《login_错误码与排障手册》逐项一致：46 个设计码包含稳定 `code`、分类、默认公开说明和建议 HTTP 状态。未实现模块只注册约定，不伪造产生记录；测试会对照手册检查重复、缺失或含义漂移。
- `login.AppError` 分离公开信息与内部原因：`Error()`、JSON 和结构化日志只包含 code、message、request_id、task_id；内部 cause、受限内部原因码（`WithInternalReasonCode`）和堆栈不会进入公开输出，但原因链仍支持 `errors.Is`/`errors.As`。
- 未注册错误码自动回退 `INTERNAL_ERROR`；普通错误可用 `login.FromError` 包装为统一错误并生成请求编号。
- 请求编号使用 `login.NewRequestID()` 生成 `req_` 前缀编号；`login.ValidateRequestID`/`ValidateTaskID` 限制长度与字符集，拒绝换行和控制字符，供未来 HTTP 层复用。`task_id` 与受限内部 `reason_code` 字段已预留，任务编号生成在后续步骤实现。
- 运行日志使用 Go 标准库 `log/slog`，级别与格式来自配置（debug/info/warn/error，text/json）；`Secret` 与 `AppError` 实现 slog 脱敏输出，日志不写秘密、不直接展开内部原因。
- 标准 OAuth/OIDC 错误使用小写协议字段（如 `invalid_grant`、`access_denied`），由未来协议适配层映射，不注册为全大写统一业务码，也不被统一 JSON 强行覆盖。
- 本步不实现审计数据库、HTTP 访问日志或请求处理中间件。

```go
appErr := login.NewAppError(login.CodePermissionRequired, "",
    login.WithRequestID(login.NewRequestID()))
fmt.Println(appErr.Error()) // PERMISSION_REQUIRED: 缺少当前操作所需权限 request_id=...
```

## 数据库迁移与存储模型（步骤 06）

- 迁移文件位于 `migrations/`，通过 `go:embed` 内嵌；文件名 `NNNN_description.sql`，版本升序执行、版本唯一。已执行的迁移不得修改，执行器用原始文件字节的 SHA-256 拒绝内容变化。
- 迁移机制位于 `internal/storage/migrate`：已应用记录必须是当前迁移列表的严格前缀；失败会持久化失败记录并停止，再次运行返回 `ErrFailurePending`，人工核对后调用 `ClearFailure` 才能重试；排他锁与事务由具体数据库后端实现（SQLite 在步骤 07 接入）。
- 文件头支持 `-- +migrate non-transactional` 与 `-- +migrate whole-file` 指令。DDL 事务能力因数据库而异：SQLite 计划事务执行；MySQL 等隐式提交方言必须声明非事务，失败不承诺自动回滚，只记录状态并人工修复。
- 一号迁移只创建隔离核心 11 张表（全局用户、应用、scope、应用成员关系、角色、权限、用户组及关联）和唯一 system scope；认证凭证、会话、审计、任务、报告、备份等 37 张基线表按后续步骤追加迁移，不提前创建。
- 全局用户以 `users.id` 被引用，用户名只以服务层生成的 `username_normalized` 保证唯一，不用作永久外键；角色/权限/组通过 `(id,scope_id)` 复合键与复合外键限制跨 scope 组合；应用成员关系主键为 `(app_id,user_id)`。
- 时间统一 UTC 毫秒整数 `_at_ms`，布尔为 0/1 + CHECK，二进制为 BLOB，分页采用稳定排序键的键集游标，方言差异集中在后续 `internal/storage` 后端；完整约定见 [docs/database/存储模型与迁移设计.md](docs/database/存储模型与迁移设计.md)。
- 本步骤用可控内存测试后端验证迁移机制，没有连接真实数据库；SQLite 连接、事务、外键执行与真实迁移执行在步骤 07 验收。

## SQLite 存储与迁移执行（步骤 07）

- 驱动：`modernc.org/sqlite v1.62.0`（纯 Go，`CGO_ENABLED=0`）。正式迁移文件仍由 `migrations` 包内嵌，`internal/storage/sqlite.Store.Migrate` 在 SQLite 上执行。
- 打开方式：`sqlite.Open(ctx, sqlite.DefaultOptions(path))` 创建/打开文件库并验证 PRAGMA；`sqlite.WrapDB(host, options)` 包装宿主连接，宿主连接由宿主关闭，Store 不接管、不修改宿主连接池。
- 连接配置：每个连接启用 `foreign_keys=1`、`busy_timeout`（默认 5s）、`_txlock=immediate`；WAL 开启时使用 `journal_mode=WAL`、`synchronous=NORMAL`。连接池默认 4、上限 16，不盲目放大；空闲连接 5 分钟回收。
- 事务：`Store.Transaction` 成功提交、错误/panic/提交失败回滚；`IMMEDIATE` 开始即取得写锁，避免读事务升级写锁的不可重试 BUSY。`Store.WithConn` 是后续维护/在线备份的扩展入口，本步不实现备份流程。
- 并发与重试：忙/锁错误映射为可识别的 `storage.ErrBusy`；事务开始只对该类错误做有界重试（默认最多 3 次、10ms～100ms），不无限循环。唯一性、约束、权限、磁盘、损坏分别映射为 `storage` 哨兵错误，公开错误文本不含 SQL、表名、参数或文件路径（原始原因仅供受限诊断）。
- 版本冲突：按步骤 06 的 `row_version` 设计，调用方执行带 `WHERE row_version=?` 的条件更新后用 `storage.CheckVersionedUpdate` 检查受影响行数，0 行返回 `storage.ErrVersionConflict`。
- `database/login.db` 是启动包设计基线，本步不读取、不修改、不对其执行迁移；所有测试使用临时目录数据库。SQLite 尚未接入 `cmd/login-server`、`Instance` 或 CLI 初始化，后续步骤负责装配。
- 已验证（Windows amd64）：落盘重开、迁移执行/重复运行、事务提交与回滚、外键与级联删除、唯一约束、乐观版本冲突、锁等待成功/超时、有界重试、context 取消、错误映射；六目标仅编译。

## 本地检查（Windows）

在项目根目录运行：

```bat
scripts\check.cmd
```

脚本优先使用 PowerShell 7，未安装时使用 Windows PowerShell 5.1，并依次执行 gofmt 检查、`go mod verify`、`go mod tidy -diff`、`go build`、`go vet` 和 `go test`。它固定 `CGO_ENABLED=0`、`GOTOOLCHAIN=local`，构建并发取逻辑处理器数量的一半且至少为 1；任何一步失败都会返回非零。

版本与帮助：

```bat
go build ./...
go run .\cmd\login-server --version
go run .\cmd\login-server --help
```

## 包含内容

| 路径 | 用途 | 是否应提交 Git |
|---|---|---|
| AGENTS.md | AI 约束与总体结构 | 否 |
| MEMORY.md | AI 本地进度交接 | 否 |
| .ai/ | 第 01～17 步完整提示词和完整步骤标题索引 | 否 |
| go.mod、go.sum | Go 模块与依赖锁定 | 是 |
| cmd/、internal/、scripts/ | 最小入口、内部实现与本地检查命令 | 是 |
| migrations/ | 内嵌的版本化数据库迁移 SQL（当前为隔离核心表） | 是 |
| examples/ | 可运行的最小接入示例（当前为配置加载示例） | 是 |
| docs/requirements/ | 功能清单和错误码手册 | 可以 |
| docs/database/ | 数据库基线说明、表清单与检查记录 | 可以 |
| database/login.db | 已创建的空业务 SQLite 数据库 | 否，运行数据应本地保存 |
| database/0001_design_baseline.sql | 建库结构，需在开发阶段审查 | 可以 |
| tools/ | 可选的 Python 建库、只读检查工具 | 可以 |
| .gitignore | AI 文件、数据库与秘密排除规则 | 可以 |
| SHA256SUMS.txt | 启动包文件完整性清单 | 可留作交付记录 |

## 开始工作

1. 解压到新的目录，不要直接覆盖现有项目。
2. 使用 IDE 打开目录，让 AI 先读取 AGENTS.md 和 MEMORY.md。
3. 步骤 01～07 已完成；继续时按 .ai/ 中的顺序处理步骤 08，每次只把一个步骤的完整提示词交给 AI。
4. 每步结束检查修改和实际测试结果，由你自行提交代码。AI 不提交项目成果、不执行任何 git push。
5. 完成第 17 步后，提供 MEMORY.md 与必要代码状态，再生成下一部分和更新 AGENTS.md。

`database/login.db` 是启动包提供的设计基线，仅用于步骤 01/06/07 审查；Go 正式迁移已在 SQLite 存储层实现，但尚未对 `database/login.db` 执行，测试与后续初始化应使用独立数据库文件。该库没有 root 初始密码，管理员将在步骤 28 的受控初始化流程创建。

可选检查（Windows 安装 Python 3 后，在本目录执行）：

```bat
py -3 tools\check_database.py
```

从 SQL 另建一个数据库（目标文件必须不存在）：

```bat
py -3 tools\create_database.py --output database\login-new.db
py -3 tools\check_database.py database\login-new.db
```

Python 只用于启动包辅助工具，不是将来 Go 产品的运行依赖。JSON 约束需要 SQLite 提供 json_valid；若 Python 自带 SQLite 太旧或缺少该功能，工具会报错，不能静默删掉约束。

## 重要边界

- 本库是可打开、可校验的结构基线，没有业务实现；不代表权限检查和身份认证已经安全可用。
- 数据库结构覆盖后续模块，仍需第 06～07 步结合选定 Go 驱动审查和正式迁移。不得在已有业务库上重复执行建库 SQL。
- 文件中没有预置秘密、真实用户、远程服务地址或生产邮件配置。
- 启动包本身不含 go.mod；当前工作区已在步骤 02 建立 `go.mod`/`go.sum` 并锁定已验证依赖。
- .gitignore 只对未跟踪文件生效；已有仓库中被跟踪的 AI 文件需检查后处理。启动包本身没有创建 Git 仓库，也没有提交或上传代码。
