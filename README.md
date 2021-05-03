# login

login 提供可嵌入 Go 程序的用户与权限组件，并计划提供独立的 OAuth 2.0 / OpenID Connect 身份服务。当前只是最小可编译骨架，不是可运行的用户系统。

## 项目状态（步骤 16）

- 模块路径：`github.com/kagurazakayashi/EvernightLogin`，根包名 `login`；路径来自现有远端，首次发布后不再变更。
- 独立进程入口：`cmd/login-server`。当前只提供 `--version` 和 `--help`；不带参数运行会明确失败并返回非零，不假装服务已启动。
- 已实现：版本与构建信息；类型化配置加载器；核心实例生命周期契约；统一错误码注册表、`AppError`、请求编号校验与结构化运行日志；版本化数据库迁移机制及隔离核心表；基于 modernc SQLite 的存储基础（连接/所有权、WAL、外键、忙等待、连接池上限、事务与取消、错误映射、有界重试、迁移执行）；内部秘密加密包 `internal/secrets`（AES-256-GCM 认证加密、随机 nonce、用途/对象/范围绑定、主密钥环加载、Windows ACL/Unix 权限检查、轮换与可中断重加密、旧密钥退役保护）；一次性凭证服务 `internal/credential` 与 SQLite 生产仓储（用途/目标/应用绑定、高熵摘要、低熵受密钥保护验证码、原子消费、取消/替换/过期清理、可注入时钟）及迁移 0002；安全审计包 `internal/audit` 与 SQLite 持久化（可信身份、脱敏差异、失败审计独立保存、关键变更同事务、审计故障拒绝并告警）及迁移 0003；可靠单实例后台任务执行器 `internal/task` 与 SQLite 状态持久化（完整任务状态机、可信发起/执行/取消身份、并发与墙钟上限、取消上下文与子进程清理约定、重启恢复、全状态审计）及迁移 0004；定时计划（日/周/月/自定义表达式、IANA 时区与夏令时规则、停机错过策略与有界补跑、触发去重、尝试历史、有界指数退避重试与显式不可重试错误、运行前权限复验默认拒绝、暂停/恢复/删除语义）及迁移 0005；HTTP 传输层 `internal/transport` 与公开 `login.NewHTTPHandler`（标准 net/http Handler、固定前缀与严格路由、请求体类型/大小与参数规范化、统一错误 JSON/请求编号/panic 恢复/上下文取消、最小健康端点、可信身份建立与 context 传递、由错误码注册表生成的 OpenAPI、W3C Extended 脱敏访问日志与写入失败告警）；HTTP 防护层 `internal/ratelimit` 与传输层中间件（多维有界固定窗口限流、容量上限与过期清理、可信代理地址解析、昂贵请求预算、请求期限/响应超时与并发上限、精确来源 CORS、安全响应头、Cookie 会话 CSRF 契约与 Cookie 安全属性策略）；独立监听组件 `login.NewServer` 与 `internal/listener`/`internal/netpolicy`/`internal/proxytrust`（多 IPv4/IPv6 地址监听、失败整体回滚、关停释放端口、Host/公开地址限制、Forwarded 与 X-Forwarded-* 可信代理链边界、限流使用验证后的客户端地址，可交给 `Instance` 生命周期管理）；HTTPS 单向认证 `internal/tlscert`（PEM 证书链/私钥/附加 CA、PKCS#12/PFX 导入、私钥与证书匹配、证书链与用途/有效期校验、按 SNI 选择证书、未知 SNI 拒绝、安全重载与到期状态）。
- 尚未实现：SQLite、`internal/secrets`、`internal/credential`、`internal/audit`、`internal/task` 与 `internal/transport` 尚未接入 `login-server`；`cmd/login-server` 也尚未装配 `NewServer`（监听组件已可由 Go API 使用并交给 `Instance` 管理）；客户端证书 mTLS（步骤 17）、完整反向代理部署示例、账户/认证/授权、OAuth/OIDC、Web 页面、审计查询/导出/报告/清理、备份流程仍未实现。HTTP Handler 只公开健康与 OpenAPI，不提供业务或管理端点；防护层不提供绕过鉴权或 CSRF 的生产开关，任务执行器与调度器不提供网络端点，服务层授权尚未接入，也不承诺外部副作用恰好执行一次。密码哈希尚未实现，本步不把密码按可解密形式存储。
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
| server.extra_listen_addrs | LOGIN_SERVER_EXTRA_LISTEN_ADDRS | 需重启 |
| server.public_base_url | LOGIN_SERVER_PUBLIC_BASE_URL | 需重启 |
| server.path_prefix | LOGIN_SERVER_PATH_PREFIX | 需重启 |
| server.allowed_hosts | LOGIN_SERVER_ALLOWED_HOSTS | 需重启 |
| server.trusted_proxies | LOGIN_SERVER_TRUSTED_PROXIES | 需重启 |
| server.tls_terminating_proxy | LOGIN_SERVER_TLS_TERMINATING_PROXY | 需重启 |
| server.tls_cert_files | LOGIN_SERVER_TLS_CERT_FILES | 需重启 |
| server.tls_key_files | LOGIN_SERVER_TLS_KEY_FILES | 需重启 |
| server.tls_ca_file | LOGIN_SERVER_TLS_CA_FILE | 需重启 |
| server.tls_pfx_file | LOGIN_SERVER_TLS_PFX_FILE | 需重启 |
| server.tls_expiry_warning_days | LOGIN_SERVER_TLS_EXPIRY_WARNING_DAYS | 需重启 |
| server.shutdown_timeout_seconds | LOGIN_SERVER_SHUTDOWN_TIMEOUT_SECONDS | 可热更新 |
| logging.level | LOGIN_LOGGING_LEVEL | 可热更新 |
| logging.format | LOGIN_LOGGING_FORMAT | 可热更新 |
| database.driver | LOGIN_DATABASE_DRIVER | 需重启 |
| database.path | LOGIN_DATABASE_PATH | 需重启 |
| database.wal | LOGIN_DATABASE_WAL | 需重启 |
| database.busy_timeout_ms | LOGIN_DATABASE_BUSY_TIMEOUT_MS | 需重启 |
| secrets.master_key | LOGIN_SECRETS_MASTER_KEY | 需重启 |
| secrets.tls_pfx_password | LOGIN_SECRETS_TLS_PFX_PASSWORD | 需重启 |

环境变量名是稳定契约，实际列表以 `login.Fields()` 返回值为准。

校验行为：

- 未知字段、重复键、类型错误、`null`、超范围值、非法组合（例如公开地址使用 `http` 却监听非回环地址、公开地址路径与 `server.path_prefix` 不一致、启用 TLS 终止代理模式却缺少 https 公开地址或可信代理）都会在加载阶段失败，不产生监听或数据库副作用。
- 监听主机只接受 IP 字面量、`localhost` 或空（所有接口），不接受任意域名；`server.extra_listen_addrs` 与主地址去重后最多 16 个。列表型环境变量用英文逗号分隔（例如 `127.0.0.1:8081,[::1]:8081`）。
- TLS 字段组合在加载阶段校验：PEM 证书/私钥必须成对且数量一致（最多 8 对）、PEM 与 PFX 互斥、PFX 必须有受保护来源密码、PFX 不能配附加 CA、未配置 PFX 时不能单独设置 PFX 密码、本地 TLS 与 `tls_terminating_proxy` 互斥、启用本地 TLS 时公开地址必须是 https、到期告警天数范围 0～365（0 表示默认 30 天）。
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

## 秘密加密与主密钥轮换（步骤 08）

本步实现内部包 `internal/secrets`，用于 TOTP 种子等**必须还原原文**的秘密。密码与恢复代码不使用本包：它们必须用慢哈希保存，不能按可解密形式存储。

- **认证加密**：标准库 AES-256-GCM（`crypto/aes` + `cipher.NewGCM`），不自行设计密码学协议。每条密文使用 `crypto/rand` 生成的 96 位（12 字节）随机 nonce；随机源失败立即返回错误，不回退时间/计数器/固定值。每个“密钥 + 用途”组合的实际加密密钥由 HKDF-SHA256（标准库 `crypto/hkdf`）派生，不同用途不共用同一把 AEAD 密钥。`Sealer` 不持有可变共享状态，可被多个 goroutine 并发使用（共享密钥环在轮换时替换为新 `Sealer`，不原地修改）。
- **密文信封**：`"LNS1"` 魔数（4 字节）、格式版本（1 字节）、key_id 长度（1 字节）、key_id（1-64 字节）、12 字节 nonce、AES-GCM 密文与 16 字节标签。用途、对象与所属范围不写入信封，而是作为 AEAD 关联数据参与认证；解密时必须提供完全相同的绑定信息，否则认证失败。把密文复制到其他记录、用途或应用范围后无法继续使用。
- **密钥环文档**：主密钥材料来自受保护文件或宿主提供者，格式为严格 JSON；`keys` 同时保存当前写密钥与历史读密钥，`current_key_id` 指定唯一写密钥。每个密钥材料必须是 32 字节且不能全零（全零视为错误配置并拒绝）。示例（`material` 必须是真实安全随机生成的 32 字节密钥的 base64，项目不内置默认密钥）：

```json
{
  "format": "evernight-login-keyring",
  "version": 1,
  "current_key_id": "k20261114",
  "keys": [
    {
      "id": "k20261114",
      "material": "替换为32字节随机密钥的base64编码",
      "created_at": "2026-11-14T09:30:00Z"
    }
  ]
}
```

- **读写语义**：`Sealer.Seal` 只使用当前写密钥；`Sealer.Open` 可使用任一历史读密钥，因此轮换后旧密文仍可读取。密文引用密钥环中不存在的 key_id 时明确返回 `ErrKeyNotFound`，不会静默生成新密钥覆盖旧数据。
- **文件保护**：Windows 下检查实际 DACL，只允许当前进程用户、SYSTEM 与 Administrators；NULL DACL、从父目录继承的宽权限、无法识别的 ACE 类型都按不安全拒绝，不能把 Unix chmod 当成 Windows ACL。非 Windows 要求文件权限位不向组和其他用户开放（通常 0600）。`WriteProtectedFile` 先在目标目录创建临时文件、收紧权限，再写入内容并原子替换，避免秘密内容出现在权限未收紧的文件中；主密钥文件必须使用绝对路径。调用方必须同时保护密钥目录本身并限制写入者（能替换密钥文件或目录内容的操作者等同掌握主密钥），本包不承诺抵御能改写密钥目录或主机的攻击者。
- **轮换流程**：`Rotator.Rotate` 生成新随机密钥并保留全部旧密钥为历史读密钥；调用方用 `WriteProtectedFile` 持久化新文档，再创建使用新密钥环的 `Sealer`；`Rotator.Reencrypt` 将旧密钥记录逐条重加密。每条记录在存储层单独原子替换，中断后重新运行会继续处理仍是旧密钥的记录，无需进度表；每个源密钥处理完会再次扫描，仍有引用时返回 `ErrReencryptIncomplete`，不把未完成当成功。确认零引用后 `Rotator.RetireKey` 才允许移除旧密钥；仍有引用或无法确认时返回 `ErrKeyStillReferenced`，不会无提示删除旧密钥。
- **存储契约**：重加密依赖最小接口 `SealedStore`（`LoadBatch`/`Replace`）。本步只用内存测试替身验证算法与恢复语义，不提供生产数据库实现；数据库仓储与密钥环接入由后续步骤完成。
- **日志与错误**：只输出密钥编号、记录 ID、计数与失败类别，不输出密钥材料、明文或密文；错误信息同样不包含这些内容。
- **尚未接入**：根包公开 API、`Instance`、配置加载与 `cmd/login-server` 都还没有使用本包；宿主密钥提供者当前通过内部 `Provider` 接口注入，公开注入点与配置接线属于后续步骤。
- **已验证（Windows amd64）**：正常解密；密文篡改/截断/长度越界；错误密钥与缺失 key_id；错误用途/对象/范围；200 次加密 nonce 不重复；共享 `Sealer` 的 8 goroutine 并发加密/解密；随机源失败不产出密文；轮换后旧数据读取；完整的“写入受保护文件→加载→轮换→重启加载→重加密→退役→旧密文明确失败→主密钥文件丢失明确失败”流程；重加密完成、取消中断后恢复、瞬时存储错误恢复、损坏记录中止、存储未真正更新被发现；旧密钥仍有引用时拒绝退役；日志与错误不泄露明文/密钥材料；真实 Windows ACL 的显式宽权限、NULL DACL、继承宽权限被拒绝，权限过宽父目录下写入仍收紧目标文件；Unix 权限位判断逻辑（纯函数）；信封与密钥环解析器短时模糊测试无崩溃。六目标仅编译，非 Windows 未运行。

## 一次性凭证与原子消费（步骤 09）

本步新增内部包 `internal/credential`（服务与持久化契约）和 `internal/credential/sqlite`（SQLite 生产仓储），并通过 `migrations/0002_one_time_credentials.sql` 落地 `one_time_credentials` 表。目标是为注册验证、找回密码、授权确认等后续流程提供可复用的短期凭证能力；本步不创建 HTTP 接口，也不把服务接入 `Instance` 或 `cmd/login-server`。

- **凭证字段**：用途 `Purpose`、接收方/目标 `Target`、有效期 `TTL`、尝试上限 `MaxAttempts`、可选应用绑定 `AppID`；凭证 ID 为 `otc_` 加 128 位安全随机十六进制。签发结果中的 `Secret` 只返回一次，默认字符串化、JSON 与结构化日志都脱敏，投递代码必须显式调用 `Reveal`。
- **两种形态**：`KindToken` 高熵令牌（256 位安全随机、base64url；数据库只存 SHA-256 摘要，内容不匹配不消耗尝试次数，避免只知道公开 ID 的攻击者耗尽他人凭证）；`KindCode` 低熵验证码（固定 8 位十进制短码；数据库只存用主密钥环材料派生的 HMAC-SHA256 受密钥保护摘要，`key_id` 记录所用密钥；错误尝试原子递增，达到上限后失效，即使数据库泄露没有主密钥也无法离线穷举）。
- **绑定与摘要**：用途、目标、应用与凭证 ID 全部以长度前缀编码参与摘要，把记录搬到其它用途、目标或应用后验证失败；应用绑定通过外键指向 `applications(id)`，空值表示系统范围。
- **原子消费**：验证读取后用单条条件 `UPDATE` 完成判断与消费，条件包含活动状态、未过期、未达尝试上限与绑定信息；重复验证或并发验证最多一次成功，验证与消费之间没有可重放窗口。存储异常、条件消费失败或 context 取消都不会返回成功。
- **替换与取消**：`Replace` 在 SQLite IMMEDIATE 写事务内先撤销同用途、同目标、同应用的活动凭证，再插入新记录；`Cancel` 按 ID 与绑定条件撤销活动凭证。`Cleanup(retention)` 删除过期超过保留时长的记录，不自动调度、不启动后台协程。
- **错误与日志**：外部统一返回 `ErrInvalidCredential`（未知、过期、已消费、已撤销、尝试用尽与内容错误不可区分），避免泄露凭证是否存在；`InvalidReason` 与结构化日志仅供内部审计和诊断；存储异常返回 `ErrStoreUnavailable`；日志不含令牌、验证码、摘要或目标内容。
- **时钟与随机**：时间来自可注入时钟并统一截断到 UTC 毫秒，便于有效期边界测试；随机源可替换但默认使用 `crypto/rand`，失败时不签发任何凭证；比较使用 `crypto/subtle` 常量时间比较。
- **密钥轮换**：验证码记录保存 `key_id`；密钥轮换后保留历史密钥即可继续验证未过期凭证。退役旧密钥前必须确认不存在未过期的一次性凭证，本步尚未把该检查接入 `secrets.Rotator.RetireKey`。
- **尚未接入**：`Instance`、配置加载、`cmd/login-server`、HTTP、通知投递与账户流程；生产装配与业务接入由后续步骤完成。
- **已验证（Windows amd64）**：迁移 0001+0002 在 `t.TempDir()` 临时 SQLite 库执行；签发与一次性消费、重复消费、有效期边界（到期前一毫秒成功、恰好到期失败）、错误用途/目标/应用、尝试上限（数据库层有界）、6 路并发消费仅一次成功、6 路并发错误尝试不突破上限、取消、替换、应用绑定、过期清理、数据库关闭与 context 取消不返回成功、密钥轮换后未过期验证码仍可验证、日志与错误不泄露秘密；六目标仅编译，非 Windows 未运行。

## 安全审计与可靠记录（步骤 10）

本步新增内部包 `internal/audit`（审计事件模型、可信身份、脱敏差异、可靠写入与告警）与 `internal/audit/sqlite`（生产 SQLite 持久化），并追加 `migrations/0003_audit_events.sql`。本步只实现写入与可靠记录，不实现审计查询/导出后台或 HTTP 接口；普通访问日志与运行日志仍由 `internal/logging` 负责，与安全审计分开。

- **事件模型**：事件 ID、发生时间（UTC 毫秒）、操作者类型与稳定 ID、应用快照、动作、目标、结果（`success`/`failure`/`denied`）、对外错误码、受限内部原因码、`request_id`、`task_id`、脱敏变更差异（`detail_json`）与可选幂等键。
- **可信身份**：操作者由认证/授权边界或宿主显式传入，本包不读取请求体或查询参数中的自称身份。四类身份明确区分：可信用户、系统任务、本地管理员、匿名失败；匿名事件不得携带 ID，不能把系统操作或请求参数伪造成 root/其他用户。
- **字段与脱敏**：只允许接口字段入库；差异最多 16 个字段、字段名受限、单值不超过 256 字节、`detail_json` 不超过 8 KiB；密码/令牌/秘密/验证码/密钥/凭证/Cookie/授权头/摘要/种子/恢复码等字段值固定替换为 `[REDACTED]`；控制字符、非法 UTF-8、超长值直接拒绝，不存未受限大正文与秘密。
- **可靠写入**：`Record` 在独立事务中追加事件；`RecordFailure` 使用 `context.WithoutCancel` 与有限期限独立事务写入，因此业务事务回滚或请求取消后失败审计仍保存；`ExecuteCritical` 在同一个数据库事务中执行关键变更并写入成功事件，成功审计写入失败时业务回滚、返回 `ErrAuditUnavailable`（对外映射 `AUDIT_WRITE_FAILED`）并触发运行告警；业务失败回滚后由独立事务补写 failure 事件，失败审计也失败时用 `errors.Join` 返回并告警。
- **幂等**：可选 `DedupeKey` 对应唯一部分索引；已存在时 `ExecuteCritical` 返回 `ErrDuplicateEvent` 且不重复执行变更，`Record` 重复返回 `ErrDuplicateEvent`。
- **存储**：`audit_events` 按设计基线字段落地；`app_id_snapshot` 不建外键，保留事件发生时的应用快照，避免应用删除/改名后审计丢失或失真；索引覆盖时间、`request_id`、`task_id`、`action`+时间；迁移 0003 追加，不修改 0001/0002。
- **尚未接入**：审计写入尚未接入 `Instance`、认证/权限/账户流程或 HTTP；`internal/credential` 等业务模块尚未调用审计；审计查询、导出、报告、清理、外部接收端与 HTTP 访问日志留后续步骤；不暴露未鉴权审计接口。
- **已验证（Windows amd64）**：临时 SQLite 上 0001→0003 迁移；事件字段与身份四类、匿名拒绝伪造；敏感差异脱敏且无秘密入库，超长/控制字符/超量字段拒绝；重复幂等键只记录一次；关键变更与成功审计一致提交；业务失败回滚后失败审计仍保存；触发器注入成功审计故障时业务回滚、返回 `ErrAuditUnavailable` 并告警且失败审计保存；审计库关闭与 ctx 取消不返回成功；6 路并发追加不丢失。六目标仅编译，非 Windows 未运行。

## 后台任务执行与状态追踪（步骤 11）

本步新增 `internal/task`（可靠单实例后台任务执行器、状态机与语义）和 `internal/task/sqlite`（SQLite 状态持久化与同事务审计），并追加 `migrations/0004_jobs.sql`。本步不加入定时调度、重试/补偿执行或 outbox，也不开放网络/管理端点。

- **状态机**：`queued` → `running` → `succeeded`/`failed`；取消请求可让 queued 直接 `cancelled`，或让 running 进入 `cancel_requested`，处理器真实结束后进入 `cancelled`；超过墙钟上限进入 `timed_out`。四个终态不能被晚到的取消覆盖；取消请求被接受不等于任务已取消。
- **任务与身份**：唯一 `job_` 编号、任务类型、JSON 载荷、可信发起者（`user`/`system`/`local_admin`，匿名被拒绝）、执行器 `executed_by`、取消者类型/ID、取消原因与请求时间、墙钟上限、可选互斥键、错误码/安全失败说明、`request_id` 与各阶段时间戳。身份由可信调用边界传入，不提供匿名远程入口。
- **执行器**：单实例执行器，可配置并发 1～6，队列轮询（不是定时调度）；`Start` 先识别重启前遗留的 `running`/`cancel_requested` 任务，无法确认外部副作用时统一标记 `failed`（`TASK_INTERRUPTED`）并审计，然后开始领取 queued 任务；`Stop` 停止领取、以系统主体记录 `cancel_requested`、取消处理器上下文并等待退出，超期返回 `ErrShutdownTimeout` 而不是假装清理完成；queued 任务保留给下次启动继续。
- **处理器契约**：必须响应 `context` 取消与期限，使用 `exec.CommandContext` 等清理子进程，并自行保证幂等或补偿；执行器不承诺外部副作用恰好执行一次。处理器 panic 被隔离为失败终态。
- **竞争与审计**：完成与取消由数据库条件更新裁决，记录真实最终状态与取消请求人。每个状态变化（enqueued/started/succeeded/failed/cancel_requested/cancelled/timed_out/recovered/cancel_rejected）都在同一 SQLite 事务写入安全审计事件；审计写入失败时拒绝状态变化（fail-closed），并在下次启动恢复遗留状态。
- **尚未接入**：`Instance`、HTTP、服务层权限检查、定时调度、任务重试/补偿、outbox、任务查询/管理端点均未实现；本步不宣称通知/报告/备份流程可用。
- **已验证（Windows amd64）**：成功/失败/未知处理器/panic 终态；排队、运行中、停机三类取消（停机取消记录系统主体）；完成与取消竞争保持真实最终状态并拒绝晚到取消；1 秒墙钟超时；Stop 对不响应取消的处理器如实返回超时；重启恢复遗留任务为 `TASK_INTERRUPTED` 并审计；并发上限 2 与互斥键不重叠；取消时清理测试子进程；领取/入队/恢复阶段审计故障 fail-closed；载荷与 `request_id` 持久化；匿名发起/取消被拒绝。六目标仅编译，非 Windows 未运行。

## 定时计划、重试与运行前权限复验（步骤 12）

本步在同一任务状态机上增加定时计划与重试，不重造任务状态系统，并追加 `migrations/0005_schedules_attempts.sql`（`job_attempts`、`schedules`、`schedule_firings` 与 `jobs` 的重试列）。仍未接入 `Instance`/HTTP/服务层授权。

- **计划表达式**：`daily`（`HH:MM`）、`weekly`（`MON,WED HH:MM`）、`monthly`（`1,15 HH:MM` 或 `last HH:MM`）、`custom`（`15m`/`2h`/`7d`，以创建时刻为锚点的绝对间隔）。表达式创建时严格校验并规范化；时区必须是 IANA 名称；模块内嵌 `time/tzdata`，不依赖宿主机时区数据库。
- **时区与夏令时**：触发按计划所属时区的本地墙钟计算。夏令时缺口（本地时刻不存在）顺延到跳变后的第一个有效瞬间（例如纽约 02:30 在春季跳变日 03:00 触发）；重叠时刻（本地时刻出现两次）只取较早瞬间，同一墙钟时刻不重复触发；每月 29～31 日在不存在的月份跳过，月末语义使用 `last`。
- **停机错过与补跑**：`missed_policy` 为 `skip`（默认，错过不补跑，准点宽限窗口内仍触发）、`latest`（只补最近一次）或 `all`（按时间顺序有界补跑）。`max_catch_up` 限制单次 Tick 对单个计划的补跑数量，剩余触发在后续 Tick 继续，避免停机后一次性放大。
- **触发去重**：`schedule_firings` 以 `(schedule_id, scheduled_at_ms)` 为主键，记录 `enqueued`/`skipped`/`denied`；同一触发时刻在事务内只记录一次，重复触发返回未触发且不会产生第二个任务；重启、多个调度器实例与重复 Tick 均不会重复入队。
- **重试与尝试历史**：任务可设置 `max_attempts`（1～10）。可重试失败按有界指数退避（默认 1s 起、5m 封顶，无随机抖动）回到 `queued` 并设置 `next_attempt_at_ms`；`task.NonRetryable`、取消、墙钟超时、未知处理器与 panic 不重试。每次尝试写入 `job_attempts`（开始/结束/结果/错误码/执行器），重试沿用同一 `job_` 编号，重启恢复把未结束尝试标记为 `interrupted`。
- **运行前权限复验（默认拒绝）**：计划记录创建者与执行身份；所有计划默认 `permission_required=1`，只有服务层能明确证明任务低风险时才能显式豁免。触发前调用可信 `PermissionCheck`，未配置回调或复验失败时记录 `denied` 触发与审计、不入队任务；任务的 `permission_required` 也会在每次尝试前复验，重试期间被撤权同样失败且不重试。
- **暂停/恢复/删除语义**：暂停只停止后续触发，不取消已入队或运行中的任务；恢复以恢复时刻重新锚定游标，暂停期间不补跑；删除计划不取消已有任务，只停止后续触发；暂停/恢复/删除要求计划所有者、系统或本地管理员，并写入审计。
- **确定性时钟**：执行器与调度器都通过注入时钟计算时间、退避与触发时刻，测试不需真实等待；`examples/task-schedule` 用确定性时钟演示触发、去重与轻量处理器。
- **尚未接入**：`Instance`、配置、HTTP、服务层授权/查询端点、通知/报告/备份具体处理器与 outbox/补偿仍未实现；跨进程多调度器只依赖数据库唯一键与游标条件更新，不做分布式租约。
- **已验证（Windows amd64，临时 SQLite）**：日计划成功触发与执行、同一触发时刻重复 Tick/重复写入去重、调度器重启补跑、`skip`/`latest`/`all` 与 `max_catch_up` 有界补跑、跨时区准点、夏令时缺口触发、月末 31 日跳过与 `last`（含闰年）、互斥键串行执行、重试退避（20ms/40ms）与耗尽、非重试错误/未知处理器/panic 不重试、排队取消与运行中取消后不重试、运行前权限复验拒绝与恢复、重试期间撤权停止重试、暂停/恢复/删除不取消运行任务、调度器 goroutine 在 Stop 后退出；`examples/task-schedule` 实跑通过。六目标仅编译，非 Windows 未运行。

## HTTP 接口基础与访问日志（步骤 13）

本步新增内部传输层 `internal/transport` 与公开契约 `login.NewHTTPHandler`，把核心能力接到标准 `net/http`，但不开放尚未鉴权的业务或管理接口：

```go
handler, err := login.NewHTTPHandler(login.HTTPOptions{
    Prefix:          "/login",
    MaxBodyBytes:    1 << 20,
    IdentityResolver: resolver, // 由宿主用已验证会话/令牌实现；nil 时受保护路由拒绝
    AccessLogWriter: accessLog, // W3C Extended 输出；nil 表示不写访问日志
    Logger:          logger,
})
// 宿主自行创建 http.Server、监听地址、TLS 与关闭流程（步骤 14～17）。
```

- **生产路由最小化**：只注册 `GET {prefix}/healthz`（固定 `{"status":"ok"}`，不泄露配置/数据库路径/密钥/版本）与 `GET {prefix}/openapi.json`。调试路由、测试路由、未鉴权管理功能都不注册；测试路由只能由内部测试构造器注入。
- **路径与路由安全**：固定前缀必须是空或 `/segment(/segment)*`；拒绝百分号编码、重复斜杠、点段、尾斜杠、反斜杠、非 ASCII 与非规范路径，不做清理后重匹配或重定向，避免归一化绕过路由与权限；路径/查询串有长度上限。
- **请求边界与参数规范化**：`Content-Length` 超限直接 413；所有请求体统一用 `MaxBytesReader` 限制；GET 端点拒绝请求体；JSON 只接受 `application/json`（charset 仅 utf-8），拒绝未知字段、多值 JSON 和尾随内容；文本参数去首尾空白、拒绝控制字符/非法 UTF-8/超长值，稳定标识只接受 ASCII `字母数字 . _ -`，重复查询参数/请求头被拒绝（防参数走私）。
- **统一错误与编号**：错误响应为 `{"code","message","request_id"}`，错误码只来自 46 码注册表；`X-Request-ID` 在合法且唯一时复用客户端值，否则生成新编号，响应头与错误正文一致；错误/panic 不泄露原始错误文本、堆栈或请求内容。
- **异常恢复与取消**：panic 隔离为 500 `INTERNAL_ERROR` 且服务继续可用；客户端取消经 `r.Context()` 传递，访问日志记录 499（nginx 约定，非标准状态，不向客户端承诺）。
- **可信身份**：通过 `login.HTTPOptions.IdentityResolver` 从已验证会话/令牌建立 `login.Identity` 并放入请求上下文；`login.IdentityFromContext`/`WithIdentity` 提供服务层传递接口；公开健康端点不依赖身份解析，认证提供方故障时仍可探活；客户端自填 `X-User-ID`/`actor_id`/`user_id` 等字段不参与身份建立。
- **OpenAPI**：`login.OpenAPIDocument(prefix)` 与 `{prefix}/openapi.json` 同源生成，错误码 enum 与 `x-login-error-registry` 直接来自注册表，新增错误码不会漏文档；`/oauth2` 前缀保留给未来 OAuth/OIDC 标准协议响应，不使用统一错误信封。
- **W3C Extended 访问日志**：固定字段 `date time c-ip cs-method cs-uri-stem sc-status sc-bytes cs-bytes time-taken cs-version cs(User-Agent) cs(Referer) x-request-id x-error-code`；不记录查询串、认证头、Cookie 与正文，Referer 只保留来源与路径；字段按 W3C 规则转义（空格/控制字符/非 ASCII/引号/反斜杠 `%XX`），防日志注入；写入失败通过注入回调或运行日志告警，不改变响应，也不进入安全审计。
- **尚未接入**：`Instance`/`cmd/login-server` 启动、真实监听、反向代理/公开地址、TLS、mTLS、限流与 CORS/安全响应头（步骤 14～17）、业务接口与身份存储均未实现；访问日志字段配置/轮转/保留策略仍未实现。
- **已验证（Windows amd64，httptest）**：参数错误、非法 JSON/内容类型、未知字段、超大 Content-Length 与 chunked 请求体、GET 带请求体、未知路由/方法、路径编码/重复斜杠/点段/前缀绕过、panic→500 且服务可用、内部错误不泄露、客户端取消与 499、请求编号复用/拒绝注入、身份解析与客户端伪造 ID 忽略、身份失败默认拒绝、OpenAPI 与 46 码注册表逐项一致、W3C 日志字段/脱敏/注入防护/写失败告警+回调 panic 隔离、6 路并发请求与日志行数；六目标仅编译，非 Windows 未运行。

## HTTP 限流与浏览器请求防护（步骤 14）

在步骤 13 的 Handler 外增加可复用防护能力；生产路由仍只有健康检查与 OpenAPI，不注册业务、管理、调试或测试路由。基础防护默认启用（安全响应头、限流、期限/并发、精确 CORS 配置入口）；CSRF 默认关闭，必须由宿主显式提供校验器并接入会话。宿主可调整或关闭限流，但没有任何“匿名绕过鉴权/CSRF”的配置或示例。

- **多维有界限流**：按可信客户端地址、已认证用户、应用、接口和昂贵请求独立固定窗口限流。默认分别为 600/300/300/1200/30 每分钟；每个维度默认最多跟踪 4096 个键，按窗口/清理间隔删除过期条目，容量耗尽时先清理、仍不足则拒绝新键（fail-closed）；所有计数在互斥锁内完成，支持 6 路并发验证。`RateLimitOptions.Disabled` 可关闭限流，显式规则只启用设置了 `Limit` 与 `Window` 的维度。
- **可信客户端地址**：只有直连对端命中显式 `TrustedProxies` IP/CIDR 时才解析 `X-Forwarded-For`；从右向左跳过可信代理，遇到第一个不可信地址作为客户端地址；转发链过长、条目过多或任一地址非法时回退直连地址。未配置可信代理时完全忽略转发头，`X-Real-IP` 等非标准头一律不信任，客户端无法伪造限流桶或访问日志 `c-ip`。
- **身份维度**：用户/应用限流键只来自 `IdentityResolver` 建立的可信 `login.Identity`；匿名请求即使携带 `X-User-ID`、`user_id` 或 `actor_id` 也不会产生用户桶。健康端点不依赖身份解析。
- **请求/响应超时与并发上限**：默认请求期限 30 秒，处理链在独立 goroutine 中缓冲响应；墙钟到期后丢弃未完成响应并返回 504 `INTERNAL_ERROR`，访问日志按超时状态记录。并发上限默认 256，超出立即返回 429 与等待建议，不排队堆积连接。处理器必须响应 `context`；忽略取消的处理器在超时后仍可能短暂占用 goroutine，这是已记录的契约限制，不能据此声称资源已完全释放。
- **昂贵请求预算**：`HTTPProtectionOptions.ExpensivePaths` 可按完整路径标记昂贵接口，使用独立预算桶（按可信用户/应用，匿名按客户端地址），不影响普通接口计数。
- **精确 CORS**：只接受显式 `scheme://host[:port]` 精确来源，不支持通配符、正则或后缀匹配；预检校验请求方法与请求头，拒绝来源不回显 `Access-Control-Allow-Origin`。CORS 只决定浏览器是否可读取响应，不代替身份、权限或 CSRF 校验。
- **安全响应头**：默认 `X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`、API 最小 CSP（`default-src 'none'; frame-ancestors 'none'`）、`Referrer-Policy: no-referrer`、COOP/CORP、Permissions-Policy 与 `Cache-Control: no-store`；HSTS 仅在显式启用时输出。`AllowFraming` 可放宽为同源嵌入；未来扫码/授权 HTML 页面可显式提供 CSP，避免安全头破坏合法页面。
- **CSRF 契约**：为未来 Cookie 会话定义强制校验：不安全方法在检测到会话 Cookie（或显式要求全部不安全请求）时，Origin/Referer 必须命中精确允许来源，且唯一 CSRF 令牌必须通过宿主注入的 `CSRFValidator`；GET/HEAD/OPTIONS/TRACE 豁免以兼容顶层跨站授权跳转，form_post 等跨站写流程必须由协议层显式处理。CORS 允许来源不会跳过 CSRF，无会话 Cookie 的令牌认证接口不受影响。
- **Cookie 策略**：`DefaultCookiePolicy` 为 Secure、HttpOnly、SameSite=Lax、Path=/，适合同站与顶层导航；仅当协议端点确实需要跨站 Cookie 时才可显式 SameSite=None（仍必须 Secure），并必须由协议层完成来源/CSRF 校验，不能用 SameSite=None 代替 CSRF；`__Host-`/`__Secure-` 前缀规则强制满足；本步只定义并校验契约，不创建会话 Cookie。
- **错误与 OpenAPI**：限流返回 429 `RATE_LIMITED`，同时带 `Retry-After` 响应头与错误 JSON `retry_after_seconds`；OpenAPI Error schema 与 common error responses 同步记录 429/504。
- **已验证（Windows amd64，httptest）**：伪造 `X-Forwarded-For` 不改变限流键、可信代理链解析、未认证伪造 user_id 不分桶、用户/应用/接口维度隔离、昂贵预算、容量耗尽 fail-closed 与过期清理、6 路并发限流计数、429 等待建议、精确 CORS 允许/拒绝与预检、CSRF 缺令牌/错令牌/错来源/安全方法豁免/Referer 兼容/CORS 不绕过、默认与可覆盖安全头、并发上限、响应墙钟超时（含不响应 context 的处理器）、公开防护配置错误映射 CONFIG_INVALID；跨平台只编译，非 Windows 未运行。
- **尚未接入（步骤 14 当时状态）**：`Instance`/`cmd/login-server`、真实监听、多地址、TLS/mTLS、完整反向代理部署与公开地址/Issuer 校验在步骤 15～17 继续实现（多地址/代理边界见步骤 15，服务端 TLS 见步骤 16）；业务接口、身份存储与真实 Cookie 会话仍未实现；限流容量/窗口目前是进程内单实例状态，不提供共享限流适配器。

## 独立监听、可信代理与公开访问地址（步骤 15）

新增公开组件 `login.NewServer(login.ServerOptions)`，它实现 `login.BackgroundComponent`，可交给 `login.Instance` 管理启动/关闭，并复用 `login.NewHTTPHandler` 的 Handler。`NewServer` 只校验配置并构造代理边界与监听器，**不绑定端口**；`Start` 才真正监听，`Close` 释放端口。

- **多地址监听与整体回滚**：`Config.Server.ListenAddresses()` 返回“主地址 + 额外地址”的去重列表，支持 IPv4、IPv6（`[::1]:8081`）、`localhost` 与空主机 `:8080`。`Start` 依次绑定全部地址，任一失败时关闭已打开的全部监听并返回错误，不遗留半启动状态或占用端口；启动失败后不能再次启动。
- **默认限制回环、远程明文需显式授权**：默认只监听 `127.0.0.1:8080`。任何非回环（含 `0.0.0.0`、`::`）明文监听都要求显式设置 `server.tls_terminating_proxy=true`、配置可信代理与 `https` 公开地址，否则 `NewServer` 返回 `CONFIG_INVALID`；不提供“悄悄开放所有网卡”的开关。
- **Host 与公开地址**：每个请求先经代理边界校验 Host。允许列表来自 `server.allowed_hosts` 与 `server.public_base_url` 的主机；两者都为空时只接受回环主机名（`localhost`、`127.0.0.0/8`、`::1`）。不匹配返回 421 `REQ_INVALID`，语法非法返回 400；被拒绝的主机名不回显到响应或日志。公开地址、未来的 OIDC Issuer 与 WebAuthn RP ID 各自来自独立显式配置，绝不由请求 Host 或转发头动态推导。
- **可信代理边界**：只有直连对端命中 `server.trusted_proxies`（IP/CIDR）时才解析 `Forwarded`（RFC 7239）或 `X-Forwarded-For/Proto/Host`；否则全部忽略。同时存在两种头时 `Forwarded` 是唯一权威来源，畸形头 fail-closed 返回 400；地址链从右向左跳过可信代理，协议取最近一跳，主机只接受单值。边界消费后删除全部转发头，内层 Handler 与业务代码只能使用上下文中的可信客户端地址。
- **限流使用验证后的地址**：代理边界把解析出的客户端地址放入请求上下文，`internal/transport` 的地址维度限流与访问日志 `c-ip` 优先使用该地址；没有边界时（嵌入模式直接使用 Handler）仍按 `HTTPProtectionOptions.TrustedProxies` 解析。
- **路径前缀**：`Config.Server.PathPrefix` 与 `ServerOptions.Prefix` 必须一致，且 `server.public_base_url` 的路径必须与之一致；子路径前缀下 `/login/healthz` 可用而 `/healthz` 为 404。
- **关停**：`Close` 受调用方期限与 `server.shutdown_timeout_seconds` 中较小值约束，期限到达时强制关闭连接与监听，并如实返回未完成原因；关闭后端口可重新绑定。重复关闭安全。
- **已验证（Windows amd64，真实 TCP 监听）**：地址占用时整体回滚与端口释放、IPv4/IPv6 双地址监听、关停后端口重新绑定、伪造 `X-Forwarded-For`/`Forwarded` 不改变限流桶、可信代理链（含 RFC 7239 与 X-Forwarded-*）、不可信 Host 421、非法 Host 400、公开地址主机限制、子路径前缀、Instance 生命周期启动/关闭、未鉴权业务接口仍为 404。
- **尚未接入**：`cmd/login-server` 仍未装配 `NewServer`；TLS/mTLS（步骤 16～17）、业务接口、完整反向代理部署示例、Access Log 轮转与代理协议（PROXY protocol）未实现。嵌入模式若自行监听端口，Host 校验需由宿主提供等价边界。

## HTTPS 证书加载、多域名证书与安全重载（步骤 16）

在步骤 15 的监听组件上增加服务端 HTTPS 单向认证；证书材料由 `Config.Server` 显式配置，`NewServer` 在构造时完成全部加载与校验，`Start` 后监听地址提供 HTTPS。支持 PEM 证书链 + 私钥、可选附加 CA/中间证书，以及 PKCS#12/PFX 导入。客户端证书认证（mTLS）属于步骤 17，本步不启用。

- **证书材料与校验**：PEM 模式下 `server.tls_cert_files` 与 `server.tls_key_files` 一一对应（叶证书在前、中间证书依次在后），`server.tls_ca_file` 可追加共享 CA/中间证书；PFX 模式使用 `server.tls_pfx_file`，密码只能通过 `secrets.tls_pfx_password` 从受保护来源（环境变量或受保护文件）提供，不能直接写进 YAML。PFX/P12 解析使用 `software.sslmate.com/src/go-pkcs12 v0.7.4`（SSL.com 维护、纯 Go、BSD 风格许可；只用于解码，编码仅出现在测试）。加载时校验：文件格式与大小、私钥与叶证书公钥匹配、叶证书有效期与服务器认证用途、证书链签发关系与顺序（中间证书必须是 CA）、链内所有证书有效期、DNS SAN 合法且非空。
- **私钥文件保护**：PEM 私钥与 PFX 文件必须通过受保护文件检查（非 Windows 仅所有者可读写；Windows 受限 ACL）。测试证书仅生成在临时目录并使用受限权限写入，不写入项目树。
- **多域名与 SNI**：一个证书可包含多个 DNS SAN（支持 `*.example.com` 单级通配符），也可配置多个证书身份。SNI 按证书实际覆盖的名称选择；精确名称优先于通配符，未知 SNI 握手失败（返回错误而不是回退到任意证书）；没有 SNI 时使用配置顺序的第一张证书（显式记录的安全策略）。`server.public_base_url` 与 `server.allowed_hosts` 中的主机名必须被至少一张证书覆盖，否则启动配置检查失败；自签证书可以使用，但不表示客户端会自动信任，客户端必须显式信任对应 CA/证书。
- **协议与密码套件**：`tls.Config` 只设置最低 TLS 1.2，`CipherSuites`/`CurvePreferences` 留空使用 Go 标准库当前安全默认，不自行组合算法；TLS 1.1 及以下客户端握手失败。
- **安全重载**：`Server.ReloadTLS(ctx)` 重新读取全部材料并在独立快照上完整校验，成功后原子替换生效证书；任一步骤失败时保留仍在使用的旧证书、记录失败状态并告警，不中断监听或并发握手中的连接。重载按连续失败次数计数，成功清零。证书文件损坏、密码错误、私钥不符、链组织错误、证书过期等都会返回 `CONFIG_INVALID` 错误且不替换证书。
- **到期状态**：`Server.TLSStatus()` 返回加载时间、各证书 `Domains`/`NotBefore`/`NotAfter`/SHA-256 指纹/序列号/是否自签、最早到期时间、`ExpiringSoon`（`server.tls_expiry_warning_days`，范围 0～365，0 表示默认 30 天）与 `Expired`。本步只提供状态，不发送邮件/Webhook 通知，也不自动续期；后续调度/通知与证书更新流程按该状态接入，不能声称已发送告知。
- **代理边界联动**：步骤 15 审计备注已修正——内层 Handler 现在收到经过允许列表校验的有效 Host；可信代理声明的 `Forwarded`/`X-Forwarded-Proto` 必须与显式 `server.public_base_url` 协议一致，否则 fail-closed 400。
- **已验证（Windows amd64，真实 TLS 握手）**：PEM 链（根 CA→中间 CA→叶证书）加载与受信客户端握手、精确域名与通配符 SNI、未知 SNI 拒绝、TLS 1.1 拒绝、无 SNI 默认证书选择、私钥不符/畸形 PEM/非 CA 签发者/链顺序错误/重复证书/过期/未生效/缺 SAN/非法通配符拒绝、附加 CA 文件、PFX 正确与错误密码、同一 CA 重新签发后的安全重载、无效材料重载失败回退旧证书、6 路并发握手期间 8 次重载无失败、到期状态与到期告警窗口、HTTPS 真实监听下健康检查与证书主机名不匹配失败、PFX 端到端启动、非回环监听在本地 TLS 配置下允许（只构造、未真实绑定所有接口）。
- **尚未接入/未验证**：`cmd/login-server` 仍未装配 `NewServer`；客户端证书 mTLS、SNI 按域名选择不同客户端信任 CA（步骤 17）、OCSP/CRL、证书自动续期、真实 ACME/企业 CA 流程、邮件/Webhook 到期通知、TLS 会话票据策略与 HTTP/2 专项压力测试未实现；未做 race detector、真实反向代理/LB 联调、非 Windows 运行（只编译）。

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
| internal/secrets/ | 可还原秘密的认证加密、主密钥加载与密钥轮换（内部包） | 是 |
| internal/credential/ | 一次性凭证服务与 SQLite 生产仓储（内部包） | 是 |
| internal/audit/ | 安全审计事件模型、可靠写入与 SQLite 持久化（内部包） | 是 |
| internal/task/ | 后台任务执行器、定时计划、重试/尝试历史与 SQLite 持久化（内部包） | 是 |
| internal/ratelimit/ | 有界并发安全固定窗口限流器（内部包） | 是 |
| internal/transport/ | 标准 net/http Handler、路由/错误响应/身份传递/OpenAPI/访问日志、代理边界与 Host 校验（内部包） | 是 |
| internal/netpolicy/ | 监听地址、允许主机与 HTTP Host 的严格解析（内部包） | 是 |
| internal/proxytrust/ | Forwarded/X-Forwarded-* 可信代理链解析（内部包） | 是 |
| internal/listener/ | 多地址 HTTP 监听、失败整体回滚与关停释放端口（内部包） | 是 |
| internal/tlscert/ | 服务器 TLS 证书加载/链校验、SNI 选择、安全重载与到期状态（内部包） | 是 |
| migrations/ | 内嵌的版本化数据库迁移 SQL（隔离核心表、一次性凭证表、审计事件表、后台任务表与定时计划/尝试历史表） | 是 |
| examples/ | 可运行的最小接入示例（配置加载示例、定时计划示例） | 是 |
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
3. 步骤 01～16 已完成；继续时按 .ai/ 中的顺序处理步骤 17，每次只把一个步骤的完整提示词交给 AI。
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
