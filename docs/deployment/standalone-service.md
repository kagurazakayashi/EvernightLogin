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
| 个人资料/管理/安全中心/MFA/Passkey/RBAC/应用/客服/审计/统计/报告/备份页面 | **未装配**（缺口见第 6 节） |
| OAuth2/OIDC/设备码/扫码协议 JSON 端点 | **未实现** |
| 管理 JSON API | **未实现** |

结论：`login-server` 现在可以真实启动并服务健康检查与内置账户入口页，但**还不是**
完整的对外 OAuth2/OIDC 身份服务；不要把「能启动」等同于「第一版协议能力已全部交付」。

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
7. **首次初始化已完成**：数据库没有 root 时 `serve` 仍会启动并在日志中告警，但登录页
   没有可登录账户；正式对外前必须先执行 `init`（见 `first-run.md`）。
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
| `--access-log <path>` | serve | W3C 访问日志文件（默认写 stderr；不自动轮转，由部署侧日志设施负责） |
| `--maintenance-state-dir <dir>` | serve | 库外维护状态目录（必须与数据库目录分开） |
| `--maintenance-state-dir <dir>` | init | 库外维护状态目录（默认与 serve 相同） |
| `--init-maintenance-state` | serve | 显式允许在已有数据库上创建缺失的库外维护状态（默认 fail-closed；仅本地受控运维确认状态丢失原因后使用） |
| `--allow-uninitialized` | serve | 仅开发/测试：允许数据库尚未完成首次初始化时启动（默认拒绝） |
| `--allow-legacy-without-sensitive` | serve | 过渡开关：允许会话管理访问仅走旧强认证闸门（敏感操作策略未装配；默认 fail-closed） |
| `--operator <id>` | init | 本地受控操作者标识；默认由操作系统本地管理员身份推导 |
| `--password-file <path>` | init | 受保护密码文件（仅所有者可读写）；不提供命令行明文密码 |

### 3.4 启动时输出的诊断

`serve` 只输出脱敏信息：版本、配置路径、监听地址、路径前缀、TLS/维护状态、数据库路径
（路径不是秘密）、主密钥文件路径（仅路径）。不会输出秘密、会话、凭据或请求体内容。

## 4. 启动检查清单

| 检查 | 期望 |
|---|---|
| 配置未知字段/重复键/类型错误 | 启动前失败，不产生监听 |
| 数据库未迁移且未加 `--migrate=apply` | 拒绝启动，提示待应用版本 |
| 监听地址 | 与配置一致；默认 `127.0.0.1:8080`；非回环明文必须满足 TLS 代理/本地 TLS 条件 |
| `GET <prefix>/healthz` | 200，`{"status":"ok"}`（维护模式为 `{"status":"ok","mode":"maintenance"}`） |
| `GET <prefix>/openapi.json` | 200，最低 OpenAPI 文档（仅健康检查与文档本身） |
| `GET <prefix>/login` | 200，内置登录页（含 CSRF 隐藏字段） |
| 未知路径 | 404（维护模式下为 503 维护提示） |
| TLS 证书与私钥权限 | 私钥仅所有者可读；证书链完整、未过期 |
| 访问日志 | 不包含 Cookie、Authorization、密码、一次性凭证；默认 stderr 或受控文件 |
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

1. **协议端点未实现**：OAuth2/OIDC 授权、令牌、Discovery、设备码、扫码协议 JSON 端点
   全部未装配；内置页面中的 OAuth 同意/设备码/扫码页也未注册。
2. **管理 JSON API 未实现**：没有远程管理 API；本地管理/应急走 `cmd/loginctl`。
3. **页面装配范围有限**：当前只注册账户入口页（步骤 63 域）；个人资料、管理、安全
   中心、MFA/Passkey、OAuth 同意、RBAC、应用、客服、审计、统计、报告、备份页面缺少
   宿主级授权适配器（`internal/*adapter` 中的部分适配器需要真实 authz/敏感策略/任务
   调度，本 MVP 未装配），因此不注册，避免「页面能打开但后端是伪造成功」。
4. **root 强认证绑定未接页面**：`init` 后 root 处于 `setup_verified`，要求绑定强因素
   （MFA/Passkey）后才能完整登录；绑定流程属后续步骤，因此 root 目前不能通过内置登录页
   完成登录（不会静默降级为只凭密码的高权限会话）。
5. **邮件/Webhook 不真实外发**：注册邮件验证未装配投递通道（配置要求邮箱验证时会
   fail-closed 拒绝启动）；Webhook/通知未装配。
6. **后台任务调度未装配**：报告计划、备份计划、批量导出等依赖任务调度的页面未注册。
7. **数据库只支持 SQLite**：MySQL/PostgreSQL/SQL Server 适配未运行实测。
8. **单实例**：SQLite 为单实例主库，跨实例共享会话/限流/任务协调未实现。
9. **反代/负载均衡只提供配置样例**，未做真实代理联调（见 `reverse-proxy.md`）；
   TCP PROXY protocol、OCSP/CRL、证书自动续期未实现。
10. **访问日志不自动轮转**，需部署侧日志设施控制保留与磁盘占用。
11. **敏感操作策略未装配**：会话管理访问默认 fail-closed；`--allow-legacy-without-sensitive`
    只是未装配敏感策略（步骤 39）时的显式过渡开关，不增强安全性，不应作为长期配置。
12. **单实例/SQLite 限制**：SQLite 为主库且未实现跨进程单实例锁；同一 SQLite 数据库被
    两个 `login-server` 进程以不同端口同时启动不会被阻止（会话/限流/任务不共享），
    运维必须保证同一部署目录只运行一个服务进程。
13. **初始化中断语义**：`init` 若在创建 root 后、兑换凭证或设置密码前失败，会留下受限
    待配置 root（不可完整登录）；不要重复 init，按 `first-run.md` 的恢复指引处理。

## 7. 服务托管

操作系统级托管（Windows 服务、systemd、launchd）见 `service-hosting.md` 与 `samples/`。
托管时必须确认进程账号、工作目录、秘密文件权限、数据库目录与日志轮转，不要把秘密放进
命令行参数、环境文件的可读副本或服务描述。托管样例中的启动命令需按第 3.2 节替换为
`serve --config ...`。
