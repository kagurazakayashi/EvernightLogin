# 独立服务安全启动

本文说明 login 独立服务（`cmd/login-server`）的当前真实能力、启动方式、配置与边界。
文档只描述已实现并做过本机 Windows 11 + SQLite 实测的行为；未实现的能力在「已知限制」
中明确列出，不把规划写成可用。

## 1. 当前状态（先读）

| 能力 | 状态 |
|---|---|
| `login-server serve --config <path>` 真实启动 HTTP 服务 | **已实现**（本轮宿主装配 MVP） |
| `login-server init --config <path>` 首次安全初始化 | **已实现**（见 `first-run.md`） |
| 严格 YAML 配置加载/校验、数据库打开与迁移门禁 | 已实现 |
| 主密钥环/秘密来源、安全审计记录器 | 已实现 |
| 维护状态检查（启动时只提供健康与维护提示） | 已实现 |
| 内置账户入口页（登录/注册/邀请接受/邮箱验证/退出） | 已实现（真实 authn/session/registration/onboarding 服务） |
| 健康检查 `GET <prefix>/healthz`、OpenAPI `GET <prefix>/openapi.json` | 已实现 |
| TLS / mTLS、可信代理、Host 校验、访问日志、`SIGINT/SIGTERM` 有界优雅关闭 | 已实现 |
| 访问日志文件受控轮转（单文件上限 + 历史数量上限） | 已实现（文件访问日志默认启用，见第 3.5 节） |
| 单实例数据库排他锁（同一 SQLite 只允许一个 `serve`） | 已实现（跨进程文件锁，见第 3.5 节） |
| 后台任务执行器 + 定时计划调度器（`internal/task`） | 已实现（随 serve 启动；已注册邮件投递、Webhook 投递处理器） |
| 通知投递：邮件/Webhook 投递队列与 worker | 已实现（步骤 197 起业务邮件先入可靠投递队列、记 `queued` 后由 worker 投递；`queued≠delivered`，真实送达/失败以投递记录与任务终态为准）；邮件发送器仍需 `mail.enabled` + SMTP 配置，未配置时任务以明确错误失败（默认本地禁用外发）；Webhook 投递使用真实出站网络策略，但端点管理入口未开放 |
| 管理会话强认证门禁（root/高权限必须完成强认证且在新鲜度窗口内） | 已实现（页面会话层，见第 3.6 节） |
| 协议端点/管理 JSON API 装配挂载点 | 已实现（`ServeOptions.ExtraMounts` + 内置协议/管理 API 开关，见第 3.7、3.8 节） |
| 14 个页面选项（账户入口/资料/两步验证/OAuth/安全中心/用户/RBAC/应用/客服/敏感策略/审计/统计/报告/备份）：默认注册 12 个、条件注册 2 个 | 已装配（真实领域服务 + 生产授权；逐页依赖见第 3.8 节） |
| 敏感操作链（policy + reauth + 安全告知） | 已装配：导出/清理/凭证轮换/策略修改/恢复代码/邮箱变更等经真实 `internal/policy` + `internal/reauth` 判定；未通过 fail-closed |
| OAuth2/OIDC 协议 JSON 端点（授权/令牌/Discovery/JWKS/UserInfo/撤销） | 已实现，默认关闭；`protocol.enabled` 或 `--enable-protocol` 开启，见第 3.8 节 |
| 管理 JSON API（审计/报告/计划/备份/任务/错误码） | 已实现，默认关闭；`--enable-admin-api` 开启，见第 3.8 节 |
| root 强认证绑定（`/login/strong-setup` Passkey 注册） | 已接线：root 受限初始化 → 真实 Passkey ceremony → 重新登录取得强认证会话；本机未做浏览器/认证器真机互操作实测（见限制 14） |

结论：`login-server` 现在可以真实启动并服务健康检查与 14 个页面选项（默认 12、条件 2），具备单实例锁、
访问日志轮转、后台任务执行器/调度器、真实敏感操作链（policy + reauth + 告知），
并可按开关提供 OAuth2/OIDC 协议端点与管理 JSON API（均默认关闭）。邮件/Webhook 仍
**本地禁用外发**；root 强认证绑定已接线但未做浏览器/认证器真机实测。不要把「能启动」
等同于「所有部署形态与客户端互操作已验证」。

## 2. 启动前置条件（必须逐项确认）

1. **配置有效**：`serve`/`init` 都会先调用 `login.Load`（未知字段、重复键、类型错误、
   越界值、非法组合一律失败）；配置加载不产生监听、数据库或文件写入副作用。
2. **秘密来自受保护来源**：主密钥环只能来自配置里的 `secrets.master_key`（`env:`/
   `file:`）或 `--master-key-file` 指定的受保护文件；非 Windows 平台要求仅所有者可读写，
   Windows 检查受限 ACL。命令行不接受明文密钥/密码参数。
3. **数据库路径明确**：当前只支持 SQLite（`database.driver: sqlite`）；`--database`
   可覆盖配置路径。数据目录与数据库文件应只允许服务账号访问。
4. **迁移门禁**：未迁移的数据库默认**拒绝启动**；只有显式 `--migrate=apply`（或
   `--migrate`）才执行迁移。生产迁移前必须先备份。
5. **网络边界明确**：默认只监听 `127.0.0.1:8080`。非回环明文监听必须同时配置
   `server.tls_terminating_proxy=true`、非空 `server.trusted_proxies` 与 https 的
   `server.public_base_url` 或本地 TLS 证书，否则构造监听组件时拒绝启动。
6. **维护状态可判定**：库外维护状态由主密钥环做完整性校验，目录必须与数据库目录分开
   （默认：数据库目录同级的 `<数据目录名>-maintenance`）。`login-server init` 会创建它；
   从未迁移过的新数据库首次 `serve` 允许自动创建；**已有迁移记录的库上状态缺失时默认
   拒绝启动**（防止删除状态目录绕过维护门禁），只有本地受控运维显式
   `--init-maintenance-state` 才允许重建。
7. **首次初始化已完成**：数据库没有 root 时 `serve` **拒绝启动**（提示先运行 `login-server
   init`）；只有本地开发/测试可显式 `--allow-uninitialized` 放行（会产生告警，不要暴露到
   非回环网络）。
8. **进程账号最小权限**：不要用管理员/root 账号长期运行 Web 服务；只授予数据库、
   秘密、日志目录的必需权限。
9. **维护与恢复通道可用**：准备 `cmd/loginctl` 应急恢复和 `cmd/login-backup` 备份工具，
   并阅读 `first-run.md` 的防锁死要求。

## 3. 启动方式

### 3.1 首次部署：先初始化，再启动

```bat
:: 1) 校验配置（不监听、不写库；可用 loginctl 或配置文件加载器）
loginctl.exe config validate --config config\login.yaml

:: 2) 本地受控首次初始化（交互式终端输入 root 正式密码，不回显）
::    主密钥文件不存在时由本命令生成，并以平台受保护权限写入
login-server.exe init --config config\login.yaml ^
  --operator os:deployer@host --master-key-file D:\login\secrets\master.key

:: 3) 启动服务（显式执行迁移；未迁移数据库默认拒绝启动）
login-server.exe serve --config config\login.yaml ^
  --master-key-file D:\login\secrets\master.key --migrate=apply ^
  --access-log D:\login\logs\access.log
```

预期输出（不含秘密）：

- `init`：打印 root 用户 ID、`security_version`、初始化状态（`setup_verified`）与库外
  维护状态路径；不打印密码、一次性配置凭证或主密钥材料。
- `serve`：打印监听地址、路径前缀、TLS/维护模式；健康检查可用。

### 3.2 日常启动

```bat
login-server.exe serve --config config\login.yaml ^
  --master-key-file D:\login\secrets\master.key
```

已迁移且已初始化的数据库正常启动；停止使用 `Ctrl+C`（或服务管理的停止命令），
进程在 `server.shutdown_timeout_seconds`（默认 10 秒）内完成有界优雅关闭并释放监听端口。

### 3.3 命令参数

| 参数 | 适用命令 | 说明 |
|---|---|---|
| `--config <path>` | serve / init | 必需；YAML 配置路径 |
| `--database <path>` | serve / init | 覆盖 `database.path` |
| `--master-key-file <path>` | serve / init | 主密钥环文件路径；配置未设置 `secrets.master_key` 时必需。`init` 下文件不存在则生成受保护文件，`serve` 下文件必须已存在 |
| `--migrate` / `--migrate=apply` | serve | 执行数据库迁移后再启动；其他取值拒绝 |
| `--access-log <path>` | serve | W3C 访问日志文件（默认写 stderr；文件日志默认启用受控轮转，见第 3.5 节） |
| `--access-log-max-bytes <n>` | serve | 访问日志单文件字节上限；0 使用默认 64 MiB，允许 1 MiB～1 GiB |
| `--access-log-max-files <n>` | serve | 访问日志保留的历史文件数量（不含当前文件）；0 使用默认 5，允许 1～100 |
| `--maintenance-state-dir <dir>` | serve | 库外维护状态目录（必须与数据库目录分开） |
| `--maintenance-state-dir <dir>` | init | 库外维护状态目录（默认与 serve 相同） |
| `--init-maintenance-state` | serve | 显式允许在已有数据库上创建缺失的库外维护状态（默认 fail-closed；仅本地受控运维确认状态丢失原因后使用） |
| `--allow-uninitialized` | serve | 仅开发/测试：允许数据库尚未完成首次初始化时启动（默认拒绝） |
| `--allow-legacy-without-sensitive` | serve | 过渡/兼容开关：允许会话管理访问只走旧强认证闸门而不额外经敏感操作策略（敏感策略已装配；默认 false 即 fail-closed，生产不建议开启） |
| `--operator <id>` | init | 本地受控操作者标识；默认由操作系统本地管理员身份推导 |
| `--password-file <path>` | init | 受保护密码文件（仅所有者可读写）；不提供命令行明文密码 |

### 3.4 启动时输出的诊断

`serve` 只输出脱敏信息：版本、配置路径、监听地址、路径前缀、TLS/维护状态、数据库路径
（路径不是秘密）、主密钥文件路径（仅路径）、后台任务调度是否启动、额外挂载点路径。
不会输出秘密、会话、凭据或请求体内容。

### 3.5 单实例约束与访问日志轮转

- **单实例数据库锁**：`serve` 启动早期就在数据库同目录创建并获取 `<数据库文件名>.server.lock`
  的跨进程排他锁（Windows `LockFileEx` / 类 Unix `flock`）。同一 SQLite 数据库只允许一个
  `login-server serve`；第二个进程或同一进程内第二次 `serve` 会立即失败并提示「单实例约束」，
  不会出现两个进程各自调度任务/写审计的拆分状态。进程退出（含崩溃）由操作系统释放锁，
  锁文件保留最后一次持有的 PID/时间用于排障；不要手工删除锁文件来绕过检查，先确认没有
  残留进程。跨机共享同一数据库文件不受支持。
- **访问日志轮转**：使用 `--access-log` 指定文件时默认启用轮转，单文件达到
  `--access-log-max-bytes`（默认 64 MiB）后顺延为 `<日志>.1`，历史文件最多保留
  `--access-log-max-files` 个（默认 5 个，超出删除最旧），避免磁盘被无限增长的访问日志
  耗尽。轮转在单次写入前判断，不会把一条记录拆到两个文件；轮转失败只记录告警并尽量继续
  写当前文件/标准错误，不会让 HTTP 请求失败。轮转配置超出范围时拒绝启动（不静默退化为
  不轮转）。操作系统级日志设施仍可另行采集这些文件。

### 3.6 管理会话强认证门禁（root/高权限）

- 页面会话层把「普通登录会话」和「管理会话」严格区分：`UIAccessManagement` 管理页只有在
  `internal/session` 的 `AuthorizeManagement` 真实通过时才可访问，即会话必须是普通完整
  会话、已完成强认证，且强认证时间在 `StrongAuthMaxAge`（默认 15 分钟）新鲜度窗口内。
- 未完成强认证、强认证过期或处于受限初始化/受限恢复状态的会话，访问管理页一律 403；
  不会因为「密码登录成功」就获得管理会话，也没有降级旁路。
- MFA/Passkey 绑定页面已装配：root 在 `init` 后通过 `/login/strong-setup` 完成真实
  Passkey 注册并重新登录后取得管理会话；绑定前/强认证过期后管理页对 root 仍为 403
  （fail-closed）。该链路未做真实浏览器+硬件认证器互操作实测（第 6 节限制 4）；不要用
  `--allow-legacy-without-sensitive` 绕过。
- 已完成强认证的管理账户打开管理页仍需通过对应域服务的真实授权（authz/root 判定）；
  14 个页面选项中默认注册 12 个（管理/RBAC/审计/统计/报告/备份/应用/客服/敏感策略等），
  安全中心与 OAuth 页按开关条件注册；未注册页面返回 404。

### 3.7 协议端点/管理 JSON API 挂载点

- OAuth/OIDC 协议端点与管理 JSON API 已由独立包交付并由本服务接线（默认关闭，见第 3.8
  节）。装配层仍保留 `serverapp.ServeOptions.ExtraMounts`（`[]serverapp.HandlerMount`）：
  每项包含 `Name`、`Prefix`（站内相对前缀，挂在 `server.path_prefix` 之后）与 `Handler`；
  `KeepPrefix: true` 的处理器（自带固定 BasePath，如管理 API）收到的是「站内前缀+剩余
  路径」，非空 `server.path_prefix` 下不会 404。
- 集成分两步：由后续包提供 `http.Handler`，再由装配方在 `ServeOptions.ExtraMounts` 中追加
  一项；挂载点会收到去掉挂载前缀后的请求路径。非法配置（空名称、重复/嵌套前缀、覆盖
  `/healthz`、`/openapi.json`、`/_ui/` 等内置路径、nil 处理程序）会在启动时 fail-closed。
- 维护模式下不挂载额外处理程序（只放行健康检查），协议端点同样返回 503。

## 4. 启动检查清单

| 检查 | 期望 |
|---|---|
| 配置未知字段/重复键/类型错误 | 启动前失败，不产生监听 |
| 数据库未迁移且未加 `--migrate=apply` | 拒绝启动，提示待应用版本 |
| 同一数据库已有另一个 `serve` | 拒绝启动并提示单实例约束（不会监听） |
| 监听地址 | 与配置一致；默认 `127.0.0.1:8080`；非回环明文必须满足 TLS 代理/本地 TLS 条件 |
| `GET <prefix>/healthz` | 200，`{"status":"ok"}`（维护模式为 `{"status":"ok","mode":"maintenance"}`） |
| `GET <prefix>/openapi.json` | 200，最低 OpenAPI 文档（仅健康检查与文档本身） |
| `GET <prefix>/login` | 200，内置登录页（含 CSRF 隐藏字段） |
| 未注册/未启用的页面与端点 | 404（不注册假页面；协议端点未开启时同样 404）；维护模式下为 503 维护提示 |
| 访问日志 | 不包含 Cookie、Authorization、密码、一次性凭证；文件日志默认按大小/数量轮转 |
| 后台任务 | 日志出现「后台任务运行时已启动」（执行器 + 调度器 + 邮件/Webhook 处理器） |
| 协议/管理 API 挂载点 | 启动输出列出实际挂载路径；非法挂载配置启动失败 |
| TLS 证书与私钥权限 | 私钥仅所有者可读；证书链完整、未过期 |
| 关闭 | 收到 SIGINT/SIGTERM 后在 `server.shutdown_timeout_seconds` 内有界完成，退出码 0 |

## 5. 维护状态行为

- 启动时若库外维护状态为 `maintenance`：只提供健康检查与维护提示页，**不装配任何业务
  页面、会话或不安全写入**；除健康检查外的请求统一 503；维护状态下拒绝执行数据库迁移。
- 正常启动时维护门闸接入 SQLite 写事务（`internal/maintenance.Gate`）：运行中若其他
  本地流程把状态切换到维护，新的写事务会被拒绝；当前版本**不支持运行中在线切换**
  后自动停服/恢复，切换后应按运维流程重启进程（缺口见第 6 节）。
- **状态缺失 fail-closed**：已有迁移记录的数据库如果维护状态文件丢失/目录被删，`serve`
  拒绝启动，不会自动重建 normal 状态；确认原因后用 `init`（新部署）或显式
  `--init-maintenance-state`（本地受控运维）恢复。状态文件损坏（HMAC 校验失败）一律拒绝。
- 进入/退出维护与恢复代际由本地工具/恢复流程管理，没有匿名远程入口。

## 6. 已知限制（与本次 MVP 缺口一致）

1. **协议端点默认关闭且能力有限**：授权码/刷新/客户端凭证、Discovery、JWKS、UserInfo、
   撤销已实现并默认关闭；**设备码与扫码登录已按步骤 192/193 验收其已实现边界；令牌状态查询（introspection）已实现（145/160 验收边界；默认关闭；mTLS/故障等未实测）**：
   默认关闭，设备确认页/短码密钥环/资源服务注册表/扫码领取闭环尚未完成生产验收。
   第三方客户端互操作未做真实联调。
2. **管理 JSON API 默认关闭**：`--enable-admin-api` 后提供任务/错误码/审计/报告/计划/
   备份路由；审计导出/报告/备份等写操作仍要求近期再次认证（无强认证事实时 fail-closed）。
3. **页面按依赖注册**：14 个页面选项中默认注册 12 个；安全中心页要求同时启用 Passkey 与协议端点，
   OAuth 页面要求启用协议端点，否则对应页面不注册（404），避免半装配页面冒充可用。
4. **root 强认证绑定已接线但未真机互操作**：`init` 后 root 需在 `/login/strong-setup`
   完成真实 Passkey（WebAuthn）注册，再重新登录取得管理会话；自动化测试覆盖服务层与
   页面状态，但**未**在真实浏览器 + Windows Hello/YubiKey 上操作验证。绑定前管理页
   仍 403（fail-closed）。
5. **邮件/Webhook 默认不真实外发**：默认邮件发送器是显式「未配置」实现（投递/告知任务以
   明确错误失败留痕，不访问网络）；配置 `mail.enabled` + SMTP 后业务邮件先入可靠投递队列
   （`queued`，见 3.10），由 worker 受控重试投递，`queued` 不等于已送达。未配置时两步验证
   邮件因素、找回密码、安全告知不可用（TOTP/Passkey 不受影响）。Webhook 端点管理入口未开放。
   注册邮箱验证在配置要求时仍拒绝启动。
6. **后台任务调度已启动，但领域处理器有限**：执行器 + 定时计划调度器随 serve 启动，当前
   只注册邮件投递与 Webhook 投递处理器；报告计划生成、备份计划/清理、审计保留清理等
   处理器要等 `reports`/`backupadmin`/`auditops` 域服务装配后注册（否则相应管理页继续
   不注册，不伪造处理器）。
7. **数据库只支持 SQLite**：MySQL/PostgreSQL/SQL Server 适配未运行实测。
8. **单实例**：SQLite 为单实例主库，跨实例共享会话/限流/任务协调未实现。
9. **反代/负载均衡只提供配置样例**，未做真实代理联调（见 `reverse-proxy.md`）；
   TCP PROXY protocol、OCSP/CRL、证书自动续期未实现。
10. **访问日志轮转仅由本进程控制**：文件访问日志已有单文件上限与历史数量上限，但不会
    压缩、归档到远端或做长期保留；需要集中日志时仍应接部署侧日志设施。
11. **细粒度数据范围是已声明的设计边界（非缺陷、非 fail-open）**：当前数据模型没有
    部门/资源级 scope，权限判定粒度是「功能权限 + 作用域（system/application）」；
    持有某功能权限即对该作用域内全部数据可见（审计/统计/批量导出/客服同此），没有
    按部门/属主/单条资源的二次过滤。**没有权限时一律拒绝**（fail-closed），因此不是
    放行绕过，而是"全有或全无"的范围语义；不要对外宣称已实现细粒度数据权限。实现
    细粒度范围需要在数据模型层引入资源/部门归属与授权映射，属后续独立设计项。
12. **Passkey UserVerification 策略**：默认 `required`（浏览器要求 Windows Hello/
    PIN/生物识别等用户验证）；显式配置 `preferred`/`discouraged` 会降低强认证强度，
    尤其 `discouraged` 只应在明确接受风险且不用于 root/高权限账户的场景下使用，
    否则管理强认证的"用户在场验证"保证不再成立。
12. **单实例/SQLite 限制**：SQLite 为主库；同一数据库已被单实例排他锁阻止第二个
    `serve`，但跨机共享同一数据库文件、多实例会话/限流/任务协调仍不受支持，也未被测试。
13. **初始化中断语义**：`init` 若在创建 root 后、兑换凭证或设置密码前失败，会留下受限
    待配置 root（不可完整登录）；不要重复 init，按 `first-run.md` 的恢复指引处理。

## 3.8 页面、协议端点与管理 API（本轮新增）

- 页面：`ui.go` 共 14 个页面选项，默认注册 12 个，条件注册 2 个（安全中心需
  `passkey.enabled`+`protocol.enabled`，OAuth 页需 `protocol.enabled`；未满足 404），
  全部满足时 14 个。各页面使用真实领域服务与生产授权适配层；页面访问级别由页面会话
  决定（普通页要求完整会话、管理页要求强认证新鲜的管理会话、受限会话一律拒绝）。
  管理 Kind 只发给 `/admin/*` 与 `/support/*` 命名空间，避免强认证用户的普通页面被
  会话 Kind 互斥规则拒绝。
- 敏感操作：导出/清理/保留策略/凭证轮换/敏感策略修改/TOTP/Passkey/恢复代码/邮箱
  变更/受控更名统一经 `internal/policy`（内置敏感操作目录）+ `internal/reauth`
  （近期认证、一次性批准、安全告知）。缺少近期认证/批准、策略不存在、强认证不可满足
  或审计不可用时全部 fail-closed；成功后的安全告知在未配置邮件发送器时记录为明确失败。
- 协议端点（默认关闭）：配置

```yaml
protocol:
  enabled: true
  issuer: "https://login.example.com"   # 必须与 server.path_prefix 路径一致
  # enable_introspection: true          # 145/160 已验收真实 HTTP 边界；默认关闭，生产启用前按部署文档核对
  # login_path: "/login"
```

  或 `login-server serve --enable-protocol`。启用后挂载 `/.well-known/openid-configuration`、
  `/jwks`、`/oauth/authorize`、`/oauth/token`、`/oauth/userinfo`、`/oauth/revoke`
  （路径带部署前缀）。Issuer 只接受 https 或本地回环 http；关闭时这些路径 404，
  维护模式一律 503。
- 管理 JSON API（默认关闭）：`--enable-admin-api`（可选 `--admin-api-prefix`）。认证复用
  真实管理会话（每次请求重新 `AuthorizeManagement`），Cookie 会话写请求要求 CSRF 令牌；
  已挂载任务、错误码、审计查询/导出/清理、报告、报告计划、备份管理路由；未装配能力
  （如本地捕获通知测试）返回明确未启用。维护模式不挂载（503）。

## 3.9 root 强认证绑定流程（最小可用）

1. `login-server init` 创建 root 并设置正式密码（初始化状态 `setup_verified`→`ready`）。
2. root 用密码登录：因未绑定强因素，认证返回受限初始化会话（不能进入管理页）。
3. 在 `/login/strong-setup` 完成 Passkey（WebAuthn）注册；完成后受限会话被撤销。
4. 重新登录：密码 + Passkey 第二步 → 服务端记录强认证时间 → 完整会话。
5. 该会话在强认证新鲜度窗口内（默认 15 分钟）可进入管理页；过期后需重新强认证。
6. 绑定前/强认证过期后管理页仍 403；不存在只凭密码的高权限会话旁路。

### 3.10 邮件投递队列与通知状态（步骤 197）

- 四条业务邮件路径（密码找回链接、找回后安全告知、人工恢复完成通知、敏感操作告知）先写入
  可靠投递队列（复用 `mailer` 的幂等键、`MaxAttempts` 与任务 Reconcile），成功只记
  `queued`，再由 `mail_delivery` 任务 worker 投递；真实送达/失败以 `mail_deliveries`
  投递记录与任务终态为准。
- **`queued` ≠ 已送达**：页面/详情显示“完成通知已受理（待投递）”
  （`manual_recovery.notification.queued`）；`sent` 仅表示直接发送器已接受（队列不可用的
  回退路径），不用于队列路径。
- 失败按 `mail.delivery.max_attempts`（1～10，默认 3）有界重试，超过后任务失败终态
  `MAIL_DELIVERY_FAILED`；通知失败不回滚已完成的业务变更。幂等键绑定业务实例
  （如 `password-reset-<prq>`、`manual-recovery-<rcv>-<kind>`、
  `security-notice-<req>-<outcome>`），重复入队不会重复发送。
- 迁移 0049 为 `security_notifications.state` 与 `manual_recovery_executions.notification_state`
  增加 `queued` 枚举（SQLite 按既有模式重建表）。`mail.enabled=false` 时邮件能力明确拒绝；
  人工恢复启用期要求真实邮件通道（队列或 Sender），否则 fail-closed。
- **步骤 265（人工恢复通知投递关联）**：通知器不再丢弃 `mailer.Enqueue` 返回值，执行结果与
  受权读取（`GetExecution`/`GetExecutionNotification`）按稳定业务去重键
  （`manual-recovery-<申请>-<完成|失败>`）投影投递记录的实际状态
  （queued/sending/succeeded/failed/cancelled）与投递记录 ID；同一业务事件重复触发/重启
  不会产生第二封邮件；通知状态回写失败不回滚业务且可按去重键回看终态；失败执行的通知
  同样可查，不会被标记为恢复成功。`mailer` 新增只读 `DeliveryLookup` 契约（无授权判断，
  调用方先完成自身业务授权）。管理员直接改名/改密告知复用同一个
  `enqueueSecurityNotice` 入队函数（对应业务入口在本轮后续步骤实现后接线）。
- 未完成（登记 203/265）：notification 记录 `queued→delivered/failed` 终态回写、通知页与
  投递证据的**页面/公开门面**展示、已有 0048 生产库升级回归。197 未改 EvernightMail 子模块
  （固定版本见 `docs/deployment/mail-source-closure.md`）。

## 7. 服务托管

操作系统级托管（Windows 服务、systemd、launchd）见 `service-hosting.md` 与 `samples/`。
托管时必须确认进程账号、工作目录、秘密文件权限、数据库目录与日志轮转，不要把秘密放进
命令行参数、环境文件的可读副本或服务描述。托管样例中的启动命令需按第 3.2 节替换为
`serve --config ...`。

## 8. 从根 README 迁移的部署与运维速查（步骤 244 阶段 A）

> 本节原文迁移自根 `README.md` §3.4、§3.6、§3.7、§3.8、§5.1、§8.1、§8.3，保证信息不
> 丢失；根 README 将在步骤 244 阶段 B 收敛为入口页。相对链接已按本文件位置调整。

### 8.1 启动服务与验证（原 README §3.4）

```bat
D:\login\bin\login-server.exe serve --config D:\login\config\login.yaml ^
  --master-key-file D:\login\secrets\master.key ^
  --migrate=apply ^
  --access-log D:\login\logs\access.log
```

- 首次启动或升级后必须显式 `--migrate=apply`；未迁移数据库默认拒绝启动。
- 只允许一个 `serve` 进程使用同一 SQLite；第二个进程会因排他锁失败。
- 停止用 `Ctrl+C`（Linux 用 SIGTERM/SIGINT），服务在 `shutdown_timeout_seconds` 内有界
  关闭并释放端口。

验证：

```bat
curl -s -o NUL -w "%%{http_code}" http://127.0.0.1:8080/healthz
curl -s -o NUL -w "%%{http_code}" http://127.0.0.1:8080/login
```

预期 `/healthz` 和 `/login` 返回 200，未知路径 404。

### 8.2 Linux systemd 示例（原 README §3.6）

参考发布包 `deploy/evernight-login.service` 或源码
[`samples/evernight-login.service`](samples/evernight-login.service)：

```ini
[Unit]
Description=EvernightLogin
After=network.target

[Service]
Type=simple
User=login
Group=login
WorkingDirectory=/opt/login
ExecStart=/opt/login/bin/login-server serve --config /etc/login/login.yaml --master-key-file /etc/login/secrets/master.key
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/login /var/log/login

[Install]
WantedBy=multi-user.target
```

将配置/秘密放到权限受限目录（如 `/etc/login`，`0600`）；数据库/日志放 `/var/lib/login`、
`/var/log/login`。首次 `init` 用同一服务账户执行。

### 8.3 TLS 与反向代理（原 README §3.7）

- 小规模本机/内网：可直接在 `server.tls_cert_files` / `server.tls_key_files` 配置本地 TLS；
  默认最低 TLS 1.2。
- 对外推荐：nginx/Caddy 终止 TLS，应用只监听回环；配置 `server.tls_terminating_proxy: true`、
  `server.trusted_proxies` 和 https 的 `public_base_url`，否则非回环明文监听会被拒绝。
- mTLS 客户端证书、可信代理、证书到期状态等见 [standalone-service.md](standalone-service.md)
  与 [reverse-proxy.md](reverse-proxy.md)。

### 8.4 邮件配置（原 README §3.8）

生产邮件用于注册邮箱验证、邮箱变更、邮件 MFA、密码找回、客服恢复和安全告知。

1. 把 `mail.enabled` 设为 `true`，填写 SMTP 地址/TLS/发件地址；SMTP 密码只放 `env:`/`file:`。
2. 首次启动会校验配置/秘密可读性；证书校验不可关闭，测试环境通过 `trusted_roots` 追加测试 CA。
3. 开发/测试可启动本仓库的 **EvernightMail** 本地捕获器（独立子模块，仅用于测试），把
   Login 的 `mail.smtp.addr` 指向它；不要向真实第三方地址发测试邮件。
4. `mail.enabled=false` 时邮件功能会以明确错误失败，不会伪造发送成功。生产邮件实际送达、
   外部反代等仍需自行验收。

### 8.5 `login-server` 常用命令（原 README §5.1）

```bash
# 版本/帮助
login-server --version
login-server serve --help

# 首次初始化（交互式密码）
login-server init --config /etc/login/login.yaml --master-key-file /etc/login/secrets/master.key

# 启动（需先迁移；日常路径）
login-server serve --config /etc/login/login.yaml \
  --master-key-file /etc/login/secrets/master.key --migrate=apply \
  --access-log /var/log/login/access.log
```

常用 flag：`--config`、`--database`、`--master-key-file`、`--migrate=apply`、`--access-log`、
`--maintenance-state-dir`、`--enable-protocol`、`--enable-admin-api`、`--enable-managed-api`、
`--enable-app-support`。完整说明见本文第 3.3 节。

### 8.6 安全建议（原 README §8.1）

- 生产只监听回环并由可信反向代理终止 TLS；配置 `public_base_url`、可信代理和 Host 限制。
- 主密钥、数据库、备份、会话秘密分开保存；只授予服务账户最小权限。
- root/高权限管理员必须完成强认证（Passkey 等），敏感操作要求再次认证；不要关闭 fail-closed
  策略。
- 备份文件是认证加密的，但备份期间可能出现明文快照；输出目录必须由 ACL/权限保护。
- 不要把秘密、Token、恢复码写进日志、工单、截图或仓库；测试只使用合成账户和本地捕获器。
- 定期检查审计、失败登录、撤销/恢复事件；发现异常时先撤销会话/凭证，再调查。

### 8.7 升级步骤（原 README §8.3）

1. 先备份数据库、配置和主密钥；确认旧进程可回退。
2. 替换 `login-server`/`loginctl`/`login-backup` 二进制。
3. 启动时显式 `--migrate=apply`；迁移只向前，先看发布说明与备份。
4. 检查 `/healthz`、登录页、管理页和关键协议端点；出现迁移/锁/维护错误先停止并保留现场。

