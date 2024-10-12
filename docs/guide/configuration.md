# 配置参考

本文说明 login 的配置文件结构、覆盖优先级、秘密来源、全部配置字段与默认值，以及
“改完要不要重启”的分类。字段名与默认值以根包 `login.Default()` / `login.Fields()`
为准；CLI 的 `loginctl config show` 输出与它们同源。

## 1. 覆盖优先级与安全默认

配置按以下顺序合并，**后者覆盖前者**：

```text
内置默认值  <  YAML 文件  <  LOGIN_ 环境变量  <  宿主显式代码选项（Overrides）
```

- 加载入口是 Go 函数 `login.Load(login.LoadOptions{...})`；只解析与校验，**不监听端口、
  不打开数据库、不写文件**。
- 默认值刻意保守：只监听回环 `127.0.0.1:8080`、SQLite 使用 `database/login.db`、注册/
  Passkey/扫码登录默认关闭。
- YAML 中出现**未知字段、重复键、类型错误、null、越界值或非法组合**时，加载失败并返回
  `ConfigErrors`，不会返回“部分可用”的配置。字段名写错不会被静默忽略。
- 秘密只能来自受保护来源（见第 3 节），不能直接写进 YAML。
- 不用 `login.Load` 而由宿主直接构造 `login.Config` 时，必须在任何副作用之前调用
  `Config.Validate()`。

## 2. 快速查看与校验

```bat
:: 运行目录：仓库根；平台：Windows；前提：已安装 Go 1.27.x
go run ./examples/config-load -config docs/deployment/samples/login.server.example.yaml
```

预期：输出“配置有效（以下为脱敏诊断；秘密只显示脱敏状态）”和逐字段脱敏值，退出码 0；
配置文件不存在或非法时退出码 1 并打印可纠正原因。

如果使用已构建的本地工具（`loginctl.exe` 在 `PATH` 或当前目录）：

```bat
:: 查看默认配置（不读数据库、不监听端口）
loginctl config show --json

:: 校验指定 YAML（退出码 0=通过，1=配置无效，2=用法错误）
loginctl config validate --config docs\deployment\samples\login.server.example.yaml

:: 对比两份配置（输出脱敏）
loginctl config diff --old old.yaml --new new.yaml

:: 只预演修改，不写文件；去掉 --dry-run 才真正写回（自动创建 .bak 备份）
loginctl config set logging.level debug --file copy.yaml --dry-run

:: 秘密字段不能明文 set，只能写来源引用
loginctl config set-secret secrets.tls_pfx_password --source env:LOGIN_PFX_PASS --file copy.yaml
```

预期（Windows amd64 实测）：默认配置 `field_count` 为 **58**；`config set` 预演输出
`"written": false, "dry_run": true`，并给出 `class`（`hot-reloadable` 或
`restart-required`）与 `needs_restart`。

## 3. 秘密来源

秘密（主密钥、PFX 密码等）不会出现在 YAML 明文里，只写**来源引用**：

```yaml
secrets:
  master_key:
    env: LOGIN_MASTER_KEY          # 从环境变量读取
  tls_pfx_password:
    file: /etc/evernight-login/secrets/pfx-password  # 从受保护文件读取（绝对路径）
```

- `env:` 与 `file:` 只能二选一；secret 段只允许声明的秘密字段，出现其他值直接报错。
- `file:` 文件必须是**只允许所有者读写**的普通文件；非 Windows 检查 0600 类权限，
  Windows 检查受限 ACL。不符合要求时拒绝加载。
- 主密钥只能来自受保护来源；丢失主密钥意味着相关内容与备份**无法解密**，必须异地、
  离线保存。不要写进源码、日志、工单或截图。独立服务的首次初始化由
  `login-server init --master-key-file <受保护路径>` 生成受保护密钥环文件（只打印路径，
  不打印密钥材料），也可由宿主嵌入模式生成后以受保护文件提供；生成文件与备份必须分开保管。
- 环境变量读取使用固定名称（见第 4 节“环境变量”列），命名是稳定契约，不会随版本改名。

## 4. 全部字段

说明：
- “分类”是修改后如何生效：`hot-reloadable`＝重新加载配置即可（当前版本仍需宿主自行触发
  重新加载，CLI 不会替你重启服务）；`restart-required`＝必须重启进程。
- “秘密”为“是”的字段在诊断中只显示 `[REDACTED]`/`[UNSET]`。
- 未列出的配置段（邮件、报告、统计、任务、限流等）当前**不由 YAML 配置文件承载**，
  由宿主在 Go API 装配时注入；不要自造 YAML 字段，未知字段会导致加载失败。

### 4.1 服务端（`server`）

| YAML 字段 | 默认值 | 分类 | 秘密 | 环境变量 | 说明与约束 |
|---|---|---|---|---|---|
| `server.listen_addr` | `127.0.0.1:8080` | restart-required | 否 | `LOGIN_SERVER_LISTEN_ADDR` | 主监听地址 `host:port`；主机只接受 IP 字面量、`localhost` 或空 |
| `server.extra_listen_addrs` | `[]` | restart-required | 否 | `LOGIN_SERVER_EXTRA_LISTEN_ADDRS` | 额外监听地址；与主地址合计去重后最多 16 个，全部绑定成功才开始服务 |
| `server.public_base_url` | 空 | restart-required | 否 | `LOGIN_SERVER_PUBLIC_BASE_URL` | 外部可访问基础地址；其主机自动加入允许 Host；与 `path_prefix` 路径必须一致 |
| `server.path_prefix` | 空 | restart-required | 否 | `LOGIN_SERVER_PATH_PREFIX` | 固定路径前缀：空或 `/segment(/segment)*`；嵌入模式须与 `HTTPOptions.Prefix` 一致 |
| `server.allowed_hosts` | `[]` | restart-required | 否 | `LOGIN_SERVER_ALLOWED_HOSTS` | 显式允许的 Host；为空且无公开地址时只接受本机回环主机名 |
| `server.trusted_proxies` | `[]` | restart-required | 否 | `LOGIN_SERVER_TRUSTED_PROXIES` | 唯一允许提供 `Forwarded`/`X-Forwarded-*` 的直连代理 IP/CIDR；为空时完全忽略转发头 |
| `server.tls_terminating_proxy` | `false` | restart-required | 否 | `LOGIN_SERVER_TLS_TERMINATING_PROXY` | 显式声明“明文监听只部署在受信任 TLS 终止代理后”；非回环明文监听必须为 true 且要求可信代理、https 公开地址；与本地 TLS 互斥 |
| `server.tls_cert_files` | `[]` | restart-required | 否 | `LOGIN_SERVER_TLS_CERT_FILES` | PEM 证书链，第一条为叶证书；与私钥一一对应，最多 8 个 |
| `server.tls_key_files` | `[]` | restart-required | 否 | `LOGIN_SERVER_TLS_KEY_FILES` | 对应私钥 PEM；必须是受保护普通文件（权限检查不通过拒绝启动） |
| `server.tls_ca_file` | 空 | restart-required | 否 | `LOGIN_SERVER_TLS_CA_FILE` | 可选附加 CA/中间证书；PFX 模式下不允许 |
| `server.tls_pfx_file` | 空 | restart-required | 否 | `LOGIN_SERVER_TLS_PFX_FILE` | PKCS#12/PFX 证书文件；与 PEM 证书/私钥互斥，密码走秘密来源 |
| `server.tls_expiry_warning_days` | `30` | restart-required | 否 | `LOGIN_SERVER_TLS_EXPIRY_WARNING_DAYS` | 证书到期告警窗口，范围 0～365；0 表示使用默认 30；只影响状态报告 |
| `server.tls_client_auth` | `disabled` | restart-required | 否 | `LOGIN_SERVER_TLS_CLIENT_AUTH` | 客户端证书模式：`disabled`/`required`/`optional`；启用后必须同时配 CA 与身份映射 |
| `server.tls_client_ca_files` | `[]` | restart-required | 否 | `LOGIN_SERVER_TLS_CLIENT_CA_FILES` | 客户端信任 CA 的 PEM 列表，最多 8 个；不得与服务器证书链重叠 |
| `server.tls_client_identities` | `[]` | restart-required | 否 | `LOGIN_SERVER_TLS_CLIENT_IDENTITIES` | 客户端证书 DNS SAN → 可信服务身份映射，最多 32 条；有信任 CA 不等于获准接入 |
| `server.shutdown_timeout_seconds` | `10` | hot-reloadable | 否 | `LOGIN_SERVER_SHUTDOWN_TIMEOUT_SECONDS` | 安全关闭墙钟上限（秒）；关闭时与调用方 ctx 取较小值 |

### 4.2 运行日志（`logging`）

运行日志只用于运维排障，**不等于安全审计**。

| YAML 字段 | 默认值 | 分类 | 秘密 | 环境变量 | 说明 |
|---|---|---|---|---|---|
| `logging.level` | `info` | hot-reloadable | 否 | `LOGIN_LOGGING_LEVEL` | `debug`/`info`/`warn`/`error` |
| `logging.format` | `text` | hot-reloadable | 否 | `LOGIN_LOGGING_FORMAT` | `text` 或 `json` |

### 4.3 数据库（`database`）

| YAML 字段 | 默认值 | 分类 | 秘密 | 环境变量 | 说明 |
|---|---|---|---|---|---|
| `database.driver` | `sqlite` | restart-required | 否 | `LOGIN_DATABASE_DRIVER` | 当前版本只接受 `sqlite`；其他驱动名直接拒绝，避免“配置看似生效” |
| `database.path` | `database/login.db` | restart-required | 否 | `LOGIN_DATABASE_PATH` | SQLite 文件路径；加载配置不会创建文件；目录必须存在且仅服务账号可读写 |
| `database.wal` | `true` | restart-required | 否 | `LOGIN_DATABASE_WAL` | 是否启用 WAL；显式 `false` 会被保留 |
| `database.busy_timeout_ms` | `5000` | restart-required | 否 | `LOGIN_DATABASE_BUSY_TIMEOUT_MS` | 锁等待毫秒数，范围 1～600000 |
| `database.host` | 空 | restart-required | 否 | `LOGIN_DATABASE_HOST` | 非 SQLite 驱动的主机名；SQLite 下必须为空（配置了网络字段会因冲突失败） |
| `database.port` | `0` | restart-required | 否 | `LOGIN_DATABASE_PORT` | 非 SQLite 驱动端口，范围 0～65535；0 表示驱动默认端口 |
| `database.username` | 空 | restart-required | 否 | `LOGIN_DATABASE_USERNAME` | 非 SQLite 驱动用户名；启用网络驱动时不能为空 |
| `database.password` | 未配置 | restart-required | 是 | `LOGIN_DATABASE_PASSWORD` | 数据库密码秘密来源；不要写明文，按秘密来源/环境变量提供 |
| `database.name` | 空 | restart-required | 否 | `LOGIN_DATABASE_NAME` | 非 SQLite 驱动数据库名；启用网络驱动时不能为空 |
| `database.tls_mode` | 空 | restart-required | 否 | `LOGIN_DATABASE_TLS_MODE` | 数据库 TLS 模式（按驱动适配校验）；SQLite 下不适用 |

### 4.4 自主注册（`registration`，默认关闭）

| YAML 字段 | 默认值 | 分类 | 秘密 | 环境变量 | 说明 |
|---|---|---|---|---|---|
| `registration.enabled` | `false` | restart-required | 否 | `LOGIN_REGISTRATION_ENABLED` | 注册总开关；关闭时管理员创建账户不受影响 |
| `registration.require_review` | `false` | restart-required | 否 | `LOGIN_REGISTRATION_REQUIRE_REVIEW` | 为 true 时新注册账户为待审核状态 |
| `registration.require_email_verification` | `false` | restart-required | 否 | `LOGIN_REGISTRATION_REQUIRE_EMAIL_VERIFICATION` | 为 true 时注册必须完成邮箱验证；邮箱可选，不因关闭邮件能力而阻断密码注册 |
| `registration.default_role_ids` | `[]` | restart-required | 否 | `LOGIN_REGISTRATION_DEFAULT_ROLE_IDS` | 新注册账户默认角色 ID，最多 20 个；只接受存在、已启用且作用域匹配的角色，不自动加入应用 |

### 4.5a 协议端点（`protocol`，默认关闭，YAML 专用）

`protocol` 段用于 OAuth 2.0 / OpenID Connect 协议端点；`device_code_enabled` 支持环境变量 `LOGIN_PROTOCOL_DEVICE_CODE_ENABLED`，其余字段仍以 YAML/代码选项为主，字段如下；未列出的字段或非法组合会拒绝加载，启用时缺少合法 Issuer 会
拒绝启动。

| 字段 | 默认值 | 说明 |
|---|---|---|
| `protocol.enabled` | `false` | 协议端点总开关；也可用 `--enable-protocol` 覆盖 |
| `protocol.issuer` | 空 | 固定公开签发方；必须为 https（本地回环 http 例外）、无尾斜杠，路径必须与 `server.path_prefix` 一致。OIDC 客户端须把该 issuer 登记为允许 audience 并请求 `resource=<issuer>` 才能调用 UserInfo（见 `docs/deployment/integration.md` 2.4） |
| `protocol.device_code_enabled` | `false` | RFC 8628 设备码；需 `protocol.enabled=true` 且 `server.public_base_url` 可派生确认页；关闭时不声明 Discovery 能力 |
| `protocol.enable_introspection` | `false` | RFC 7662 状态查询；启用前必须登记至少一个受信资源服务，否则拒绝启动 |
| `protocol.resource_services` | 空列表 | 受信资源服务登记（`service_id/client_id/audience`，仅 YAML/代码选项）；客户端必须是 confidential、应用 active，audience 必须已在该客户端 Audiences 中登记 |
| `protocol.login_path` | 空 | 未登录访问授权端点时跳转的站内登录页路径 |

注意：Passkey 的 `passkey.user_verification` 默认 `required`；显式设为 `preferred` 或
`discouraged` 会降低强认证强度，`discouraged` 不应在使用 root 管理强认证的部署中启用。

### 4.5 Passkey / WebAuthn（`passkey`，默认关闭）

| YAML 字段 | 默认值 | 分类 | 秘密 | 环境变量 | 说明 |
|---|---|---|---|---|---|
| `passkey.enabled` | `false` | restart-required | 否 | `LOGIN_PASSKEY_ENABLED` | 关闭时不创建注册/认证挑战，也不接受 Passkey 登录 |
| `passkey.rp_id` | 空 | restart-required | 否 | `LOGIN_PASSKEY_RP_ID` | 依赖方 ID，必须是可注册域名（不能是 IP、不能带协议/端口/路径） |
| `passkey.rp_display_name` | 空 | restart-required | 否 | `LOGIN_PASSKEY_RP_DISPLAY_NAME` | 浏览器展示的依赖方名称；空时使用默认名 |
| `passkey.allowed_origins` | `[]` | restart-required | 否 | `LOGIN_PASSKEY_ALLOWED_ORIGINS` | 允许来源完整列表，最多 20 个；只接受 https 或本地开发用 `http://localhost`，主机必须是 RP ID 或其子域 |
| `passkey.user_verification` | `required` | restart-required | 否 | `LOGIN_PASSKEY_USER_VERIFICATION` | `required`/`preferred`/`discouraged`；后两者降低强度，只应在明确接受风险时设置 |

### 4.6 已登录 APP 扫码确认网页登录（`app_qr_login`，默认关闭）

| YAML 字段 | 默认值 | 分类 | 秘密 | 环境变量 | 说明 |
|---|---|---|---|---|---|
| `app_qr_login.enabled` | `false` | restart-required | 否 | `LOGIN_APP_QR_LOGIN_ENABLED` | 扫码登录总开关 |
| `app_qr_login.allowed_client_ids` | `[]` | restart-required | 否 | `LOGIN_APP_QR_LOGIN_ALLOWED_CLIENT_IDS` | 允许使用扫码登录的应用 ID（= OAuth client_id）白名单，最多 200 个；启用时必须非空 |
| `app_qr_login.request_ttl_seconds` | `120` | restart-required | 否 | `LOGIN_APP_QR_LOGIN_REQUEST_TTL_SECONDS` | 请求有效期（秒），允许 30～300 |
| `app_qr_login.claim_interval_seconds` | `1` | restart-required | 否 | `LOGIN_APP_QR_LOGIN_CLAIM_INTERVAL_SECONDS` | 发起端查询/领取最小间隔（秒），允许 1～5 |
| `protocol.device_code_enabled` | `false` | restart-required | 否 | `LOGIN_PROTOCOL_DEVICE_CODE_ENABLED` | RFC 8628 设备码；需 `protocol.enabled=true` 且 `server.public_base_url` 可派生确认页；关闭时不声明 Discovery 能力 |

### 4.7 秘密（`secrets`）

| YAML 字段 | 默认值 | 分类 | 秘密 | 环境变量 | 说明 |
|---|---|---|---|---|---|
| `secrets.master_key` | 未配置 | restart-required | 是 | `LOGIN_SECRETS_MASTER_KEY` | 主密钥材料；本包只读取与脱敏，不生成、不轮换。YAML 中只能写 `env:`/`file:` 引用 |
| `secrets.tls_pfx_password` | 未配置 | restart-required | 是 | `LOGIN_SECRETS_TLS_PFX_PASSWORD` | PFX 密码；同样只能来自受保护来源 |
| `mail.enabled` | false | restart-required | 否 | `LOGIN_MAIL_ENABLED` | 生产邮件发送总开关；关闭时不读取密码/证书、不建立网络连接，邮件能力明确拒绝 |
| `mail.smtp.addr` | 空 | restart-required | 否 | `LOGIN_MAIL_SMTP_ADDR` | SMTP 服务器 host:port；启用时必填 |
| `mail.smtp.host` | 空 | restart-required | 否 | `LOGIN_MAIL_SMTP_HOST` | EHLO/TLS ServerName；空取 addr 主机部分 |
| `mail.smtp.tls_mode` | starttls | restart-required | 否 | `LOGIN_MAIL_SMTP_TLS_MODE` | starttls\|implicit\|none；none 仅允许回环本地捕获器，绝不自动降级 |
| `mail.smtp.trusted_roots` | [] | restart-required | 否 | `LOGIN_MAIL_SMTP_TRUSTED_ROOTS` | 额外信任的 CA PEM 绝对路径；只追加系统根，不关闭证书校验 |
| `mail.smtp.username` | 空 | restart-required | 否 | `LOGIN_MAIL_SMTP_USERNAME` | SMTP 认证用户名；与密码必须同时配置或同时为空 |
| `mail.smtp.password` | 未配置 | restart-required | 是 | `LOGIN_MAIL_SMTP_PASSWORD` | SMTP 密码来源映射（`{env: NAME}` 或 `{file: 绝对路径}`）；诊断只显示已配置/未配置 |
| `mail.smtp.timeout_seconds` | 10 | restart-required | 否 | `LOGIN_MAIL_SMTP_TIMEOUT_SECONDS` | 单封发送总时限（1～120 秒） |
| `mail.smtp.allow_plaintext_local` | false | restart-required | 否 | `LOGIN_MAIL_SMTP_ALLOW_PLAINTEXT_LOCAL` | 显式允许 tls_mode=none 的回环明文连接，且不得带认证 |
| `mail.from.address` | 空 | restart-required | 否 | `LOGIN_MAIL_FROM_ADDRESS` | 发件地址 addr-spec；启用时必填 |
| `mail.from.name` | 空 | restart-required | 否 | `LOGIN_MAIL_FROM_NAME` | 发件人显示名 |
| `mail.app_name` | EvernightLogin | restart-required | 否 | `LOGIN_MAIL_APP_NAME` | 邮件品牌名（不含秘密） |
| `mail.delivery.max_attempts` | 3 | restart-required | 否 | `LOGIN_MAIL_DELIVERY_MAX_ATTEMPTS` | 最大尝试次数（含首次，1～10） |
| `mail.delivery.timeout_seconds` | 120 | restart-required | 否 | `LOGIN_MAIL_DELIVERY_TIMEOUT_SECONDS` | 单次投递任务超时（30～600 秒） |

> 环境变量名是稳定契约：新增字段只能追加新变量，不能改名已有变量。
> 秘密的环境变量既可直接提供值，也可在 YAML 中引用；诊断与错误输出始终脱敏。

> **邮件队列与通知状态（步骤 197）**：业务邮件（找回链接/找回后安全告知、人工恢复完成
> 通知、敏感操作告知）先写入可靠投递队列，状态记为 `queued`（已受理、待投递），
> **`queued` 不等于已送达**；真实送达/失败以 `mail_deliveries` 投递记录与投递任务终态为准。
> `mail.delivery.max_attempts`（1～10，默认 3）是受控重试上限，超过后为失败终态
> （`MAIL_DELIVERY_FAILED`），已完成的业务变更不回滚。同一业务实例的重复入队由幂等键去重
> （如 `password-reset-<请求ID>`、`manual-recovery-<恢复ID>-<kind>`、
> `security-notice-<请求/摘要>-<outcome>`），重试不会重复发送。`mail.enabled=false` 时
> 邮件能力明确拒绝；人工恢复启用期要求真实邮件通道（队列或发送器），否则 fail-closed。
> 迁移 `0049_notification_queued_state.sql` 为 `security_notifications.state` 与
> `manual_recovery_executions.notification_state` 增加 `queued` 枚举（已有库升级后需重启服务
> 使新状态语义生效；升级回归登记 203）。

## 5. 修改配置的正确姿势

1. **先校验再使用**：改完先 `loginctl config validate` 或 `go run ./examples/config-load`，
   不要带着无效配置启动。
2. **优先用 `loginctl config set`**（非秘密字段）：它写临时文件后重新用 `login.Load`
   校验，校验失败不会落盘，并自动保留 `.bak` 备份；写回后仍需按“分类”重启或重新加载。
3. **秘密用 `loginctl config set-secret`**：只写入 `env:`/`file:` 来源引用，命令行不出现
   明文秘密。
4. **不要手改数据库里的配置**：配置文件是唯一来源；诊断/热更新以后者为准。
5. **不要为了“跑起来”关闭安全校验**：例如把非回环明文监听配上
   `tls_terminating_proxy` 却又没有可信代理，会被真实拒绝；正确做法是补齐代理与 TLS
   配置，而不是删检查。

## 6. 常见配置错误

| 现象 | 可能原因 | 处理 |
|---|---|---|
| 启动/加载报未知字段 | YAML 字段名拼错或使用了当前版本不承载的配置段 | 对照第 4 节字段表；邮件/报告等由宿主装配，不写进 YAML |
| 报秘密来源错误 | 秘密写成了明文，或 `file:` 不是绝对路径/权限过宽 | 改为 `env:`/`file:` 引用并收紧文件权限 |
| 非回环明文监听被拒绝 | 未声明 `tls_terminating_proxy`、无可信代理或公开地址不是 https | 补齐三项条件，或改回回环监听、由本机反代处理 |
| Passkey 启用失败 | RP ID 带协议/端口/路径，或来源主机不属于 RP ID | 按第 4.5 节修正 |
| 扫码登录启用失败 | 白名单为空/含重复或非法应用 ID，或有效期越界 | 按第 4.6 节修正 |
| `CONFIG_INVALID` | 字段越界或组合冲突 | 按错误消息中的字段名逐项修正；不要打印秘密值排障 |

配置错误统一使用稳定错误码 `CONFIG_INVALID`（见 [troubleshooting.md](troubleshooting.md)）。

## 7. 公开 Go 设置接口（步骤 232）

宿主可经 `Runtime.Settings()` 使用受认证、按字段白名单的配置查询/校验/变更/状态：

```go
settings := runtime.Settings()
view, _ := settings.Fields(ctx, app.SettingsFieldsRequest{Caller: runtime.LocalAdmin()})
result, _ := settings.Update(ctx, app.SettingsUpdateRequest{
    Caller: runtime.LocalAdmin(), ExpectedVersion: view.Version,
    Changes: map[string]string{"logging.level": "debug"}, Reason: "调整日志级别",
})
status, _ := settings.Status(ctx, app.SettingsStatusRequest{Caller: runtime.LocalAdmin()})
```

语义与边界：

- 只管理 `Options.ConfigPath` 指向的 YAML 文件；内联 `Options.Config` 返回 `CONFIG_INVALID`，
  不提供“内存覆盖一切”的后门。字段元数据来自 `config.Fields()`，未知/秘密/对象列表字段
  拒绝公开写入。
- 字段分权（步骤 232 M1 收紧）：
  - 普通 `settings.manage` 仅可写 `logging.level`、`logging.format`、
    `server.shutdown_timeout_seconds` 等非安全运行设置；
  - root/受信字段（普通设置权限修改一律 `ACCESS_DENIED`）：`registration.*` 全部、
    `protocol.*`、`app_qr_login.*`、`passkey.*`、`server.public_base_url`/`path_prefix`/
    监听地址/Host/可信代理/TLS 等 `server.*`（关闭超时除外）、`database.*`、`secrets.*`、
    `mail.*` 全部、`registration.default_role_ids`；
  - **未知字段默认 root（fail-closed）**；秘密字段不可通过公开接口写入。
  秘密字段（`secrets.*`、`mail.smtp.password`）默认显示 `[REDACTED]/[UNSET]`，公开接口
  不接受任何秘密值（包括遮盖占位符），秘密来源只能由本地 `loginctl config set-secret` 修改。
- 写入使用临时文件+fsync+rename 原子替换，`ExpectedVersion` 必须是最近读取的磁盘
  SHA-256 版本，不匹配返回 `CONFLICT`；写后重新严格加载，校验/审计失败恢复旧文件并保留
  最后有效配置。设置变更写真实安全审计（不含值/秘密/路径），审计不可用 `AUDIT_WRITE_FAILED`。
- 明确区分磁盘值（`Fields().DiskValue`）、当前有效值（`Value`，进程已装配配置）与
  `Status().PendingHot/PendingRestart`。当前运行时不会自动热重载：热更新字段也标记为
  需宿主重新加载，不虚报已生效。
- root 专属敏感操作策略默认值恢复走真实 policy 服务（真实 root 用户会话+再次认证+关键
  审计+版本冲突），普通 `settings.manage` 无法获得该能力；本地 CLI 的 `config show/get/
  validate/diff/set/set-secret` 继续作为受控本地入口，`set/set-secret` 支持可选
  `--expected-version` 做并发版本冲突检查。
- HTTP：`GET /admin/v1/settings`、`GET /admin/v1/settings/status`、`POST /admin/v1/settings/validate`、
  `PUT /admin/v1/settings`、`POST /admin/v1/settings/sensitive-policy/restore`（仅真实 root + 再次认证）。
  路由复用管理 API 的会话/CSRF/envelope，每请求重新判定 settings.manage 与真实 root/受信身份；
  未配置可写 YAML 时不注册（404）。管理 API 文档见 `internal/adminapi/doc.go` 端点表。
- 页面：`/admin/settings` 设置页（可选装配；未提供后端时 404）显示脱敏字段、字段分权与
  “待宿主重载/待重启”提示，保存走同一 `internal/settings` 核心与同一 settings.manage 判定。
  秘密字段固定遮盖且页面不可提交。