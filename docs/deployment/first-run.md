# 首次配置（受限初始化）

本文说明 login 全新部署的首次安全初始化流程、当前真实可用能力与防锁死要求。

## 1. 安全模型（不可变约束）

- 唯一 root：用户名固定为保留值 `root`，普通账户规则永久禁止该名称；数据库唯一索引
  保证至多一个 root。
- 无默认密码：全新数据库没有默认密码、默认口令或硬编码凭据，也没有「演示管理员」。
- 受限初始化：root 创建后处于受限待配置状态。它必须由本机受控操作者完成一次性配置
  凭证兑换并继续配置强认证，才可能进入 `ready`；在此之前**不会签发可远程管理整个系统
  的正常高权限会话**。
- 一次性、限时、本机：初始化凭证只出现一次，服务端只保存摘要；过期、被消费、被替换
  或用途/目标不匹配时统一拒绝（不区分具体原因，避免探测）。
- 没有远程匿名初始化接口：root 只能由本地受控 CLI 流程创建；没有 HTTP 初始化端点；
  请求不能提交 `is_root`、`status`、`security_version` 或密码字段。
- 密码不从命令行参数接收：只通过交互式终端（不回显、二次确认）或受保护 stdin/文件
  （仅所有者可读写）读取，且不写入日志、审计、命令行历史或临时文件。

## 2. 当前可用状态

| 入口 | 状态 |
|---|---|
| `login-server init --config <path>` 本地受控首次初始化 | **已实现**（本轮宿主装配 MVP） |
| 领域服务 `internal/bootstrap`（`Initialize`、`RedeemSetupCredential`、`ReissueSetupCredential`、`Status`、`AuthorizeStrongSetup`） | 已实现并有定向测试 |
| HTTP 首次配置页面/接口 | **未实现**（设计上不提供匿名远程入口） |
| root 强认证（MFA/Passkey）绑定流程 | **已接线**：登录后受限初始化会话 → `/login/strong-setup` 完成真实 Passkey 注册 → 重新登录取得强认证会话；未做真实浏览器/认证器真机互操作实测 |
| 已初始化的 root 恢复通道 | `cmd/loginctl root-recover`：本地应急恢复密码/MFA，要求服务停止或维护状态并取得排他锁 |

结论：本版本可以**由本地部署者完成首次初始化**（创建唯一 root、设置正式密码、写入
`security_version`、落审计），并通过内置登录页 + `/login/strong-setup` 完成 root
强认证（Passkey）绑定后取得管理会话；这条链路已接线并有服务层/页面状态测试，但未在
真实浏览器与硬件认证器上互操作实测。初始化后不要重复执行 `init`，重复初始化会被明确
拒绝。

## 3. 真实流程（可直接执行）

### 3.1 准备主机与目录

创建并限制为服务账号可读写（示例路径按实际替换）：

```text
D:\login\config\login.yaml        配置（含域名、监听、数据库路径）
D:\login\data\login.db            SQLite 数据库（init 创建）
D:\login\secrets\master.key       主密钥环（init 生成或预先提供，仅所有者可读写）
D:\login\logs\                    访问日志/运行日志
D:\login\backups\                 备份目录（与主密钥分开保存）
```

主密钥、数据库与备份不得放在同一目录；主密钥丢失将导致对应加密数据/备份不可恢复。

### 3.2 写入并校验配置

从 `samples/login.server.example.yaml` 复制，替换占位符；秘密只通过 `env:` 或 `file:`
引用，不写进 YAML。至少确认：

- `server.listen_addr` 默认 `127.0.0.1:8080`；对外部署需按 `standalone-service.md` 配置
  TLS 或受信 TLS 终止代理。
- `database.driver: sqlite`，`database.path` 指向数据目录（不要使用仓库内
  `database/login.db` 作为生产库）。
- `secrets.master_key` 指向受保护文件，或改用 `--master-key-file` 参数。

校验（不监听、不写库）：

```bat
loginctl.exe config validate --config D:\login\config\login.yaml
```

### 3.3 执行首次初始化

```bat
:: 交互式终端：提示输入 root 正式密码（不回显，需二次确认）
:: 主密钥文件不存在时自动生成受保护文件；只打印路径，不打印密钥材料
login-server.exe init --config D:\login\config\login.yaml ^
  --operator os:deployer@host --master-key-file D:\login\secrets\master.key
```

非交互环境（CI/受控运维）从受保护文件读取密码：

```bat
:: 密码文件必须仅所有者可读写（非 Windows 0600；Windows 受限 ACL）
login-server.exe init --config D:\login\config\login.yaml ^
  --operator os:deployer@host --master-key-file D:\login\secrets\master.key ^
  --password-file D:\login\secrets\init-password.txt
```

`init` 的实际动作（顺序固定）：

1. 严格加载并校验配置；打开 SQLite 并执行全部迁移（`init` 是显式的迁移入口）；创建
   库外维护状态（状态目录默认与 `serve` 相同，缺失时 `serve` 会 fail-closed）。
2. 加载主密钥环；配置未提供且指定了 `--master-key-file` 时生成新密钥环并以受保护
   权限写入（stdout 只输出路径）。
3. 通过 `internal/bootstrap` 的本地受控流程创建唯一 root，并签发一次性、短期、绑定
   root 的配置凭证；随后在**同一进程内存中**兑换该凭证（进入 `setup_verified`），
   凭证明文从不输出、不落盘。
4. 校验并写入 root 正式密码（Argon2id 哈希），递增 `users.security_version`，写成功
   审计；密码明文只在内存中短暂存在。
5. 输出不含秘密的结果与下一步指引（含库外维护状态路径）。

**初始化失败语义（如实）**：初始化是多个真实步骤组成的流程，不是单事务覆盖全部动作。
若 `bootstrap.Initialize` 已成功创建 root，而后续“兑换一次性配置凭证”或“设置正式密码”
失败，数据库会留下一个**受限待配置 root**（`pending_setup`/`setup_verified`，没有可用
密码或强认证，不能完整登录），本命令不会自动删除或重建它。此时：

- **不要重复执行 `init`**（会因已初始化被拒绝，且不会修复状态）；
- 按错误提示使用本地受控恢复流程（`loginctl root-recover` 或重新签发一次性配置凭证）
  继续配置，并在恢复后核对审计记录与初始化状态；
- 若在“设置正式密码”前中断，root 仍处于 `setup_verified`/`pending_setup`，不构成可
  远程登录的高权限账户。

预期输出要点：`root 用户 ID`、`初始化状态: setup_verified`、`security_version`、
`仍要求强认证绑定`；**不会**输出密码、一次性配置凭证或主密钥材料。

### 3.4 启动并验证服务

```bat
login-server.exe serve --config D:\login\config\login.yaml ^
  --master-key-file D:\login\secrets\master.key --migrate=apply
```

验证：

```bat
curl -s -o NUL -w "%{http_code}" http://127.0.0.1:8080/healthz      :: 期望 200
curl -s http://127.0.0.1:8080/healthz
curl -s -o NUL -w "%{http_code}" http://127.0.0.1:8080/login        :: 期望 200
```

### 3.5 进入 ready 之前

- root 要求强认证；`init` 后 root 已设置正式密码但**未绑定强因素**，密码登录只得到
  受限初始化会话（不会降级为仅密码的高权限会话）。请通过内置 `/login/strong-setup`
  完成真实 Passkey 注册后重新登录；该链路已接线并有服务层/页面状态测试，但未做真实
  浏览器+硬件认证器互操作实测。
- **管理会话强认证门禁已生效**：页面层区分普通会话与管理会话，管理页要求会话已完成
  强认证且在 15 分钟新鲜度窗口内；root 绑定前或强认证过期后管理页一律 403
  （fail-closed）。这是预期安全行为，不要用 `--allow-legacy-without-sensitive` 绕过。
- **单实例约束**：`serve` 会对数据库文件加跨进程排他锁；同一数据库的第二个进程会立即
  失败。启动前确认没有旧的 `login-server` 进程仍在运行（尤其服务管理器重启场景）。
- **访问日志轮转**：使用 `--access-log` 时文件默认按 64 MiB/保留 5 个历史文件轮转；可用
  `--access-log-max-bytes`/`--access-log-max-files` 调整。访问日志不含 Cookie、
  Authorization 或秘密。
- 普通用户可由管理员创建/注册（注册默认关闭）。管理员创建账户与后续权限配置的完整
  远程流程属于后续步骤；本地管理工具见 `docs/guide/root-cli.md`。
- 对外暴露前确认：只监听回环或已配置 TLS/受信代理；健康检查通过；主密钥与备份分开
  保存；已准备 `loginctl root-recover` 的本地执行条件。

## 4. 防锁死检查清单

- [ ] 已准备 `cmd/loginctl root-recover` 的本地执行条件（停服/维护 + 排他锁）。
- [ ] 主密钥与备份加密材料**分开保存**，并记录丢失后果（丢失即无法恢复备份）。
- [ ] root 的强认证方式至少保留两种可用路径（例如 Passkey + 恢复代码），不要只留一种。
- [ ] 恢复代码离线保存，已使用/过期的恢复代码及时重新生成。
- [ ] 初始化过程中的密码/一次性凭证未写入日志、工单、聊天记录或截屏。
- [ ] 数据库文件、秘密文件的服务账号权限与其他账号隔离；不要把 `data/`、`secrets/`
      放进 Web 根目录或备份同步目录。
- [ ] 对外暴露前确认：只监听回环或已配置 TLS/受信代理；未初始化服务不暴露公网。
- [ ] 不要重复执行 `init`；需要重新配置 root 时使用本地恢复流程，而不是重建数据库。

## 5. 已知限制

- root 强认证绑定页面已接线（Passkey ceremony），但未做真实浏览器 + Windows Hello/
  YubiKey 真机互操作；绑定前管理页 403（fail-closed），强认证过期后同样 403。
  页面选项共 14 个：默认注册 12 个；安全中心页要求同时启用 Passkey 与协议端点、OAuth
  页面要求启用协议端点，否则对应页面不注册（404）。
- 敏感操作（导出/清理/凭证轮换/策略修改等）已接真实 policy + reauth；未满足时
  fail-closed；数据范围仍是「作用范围全覆盖」，细粒度资源范围未实现。
- 注册邮件验证投递通道未装配真实发送器：后台任务运行时的邮件投递为本地禁用（明确
  失败），配置要求邮箱验证时仍 fail-closed 拒绝启动。
- 后台任务执行器/调度器已启动，但当前只注册邮件/Webhook 投递处理器；报告/备份/审计
  等域处理器待对应服务装配。
- HTTP 初始化端点不提供（这是安全设计，不是缺口）；远程无法创建 root。
- OAuth/OIDC 协议端点与管理 JSON API 已实现但默认关闭（`protocol.enabled` /
  `--enable-protocol`、`--enable-admin-api`）；设备码与扫码登录已按 192/193 验收；令牌状态查询（introspection）已实现（145/160 验收边界；默认关闭；mTLS/故障等未实测），默认关闭。
  启用后协议发现/令牌端点真实可用，关闭时 404、维护模式 503。
- 迁移、诊断、备份命令均为本地工具，不提供远程执行；不要把本地工具包装成网络接口。

## 6. 从根 README 迁移的首次部署速查（步骤 244 阶段 A）

> 本节原文迁移自根 `README.md` §3.1、§3.2、§3.3、§3.5，保证信息不丢失；根 README
> 将在步骤 244 阶段 B 收敛为入口页。相对链接已按本文件位置调整。

### 6.1 准备目录（原 README §3.1）

建议把配置、数据、秘密和日志分开：

```text
D:\login\
  config\login.yaml
  data\login.db
  secrets\master.key
  logs\access.log
```

目录只授予运行服务的账户；主密钥、数据库、备份不要放在同一目录。单用户测试可简化，但
生产请用专用服务账户并收紧 ACL/文件权限。

### 6.2 编写最小配置（原 README §3.2）

复制发布包中的 `config/login.example.yaml` 或源码中的 `samples/login.server.example.yaml`，
保存为 `D:\login\config\login.yaml`（文件名可自定义，如 `serv.yaml`；下文统一用
`login.yaml`）。最小可用示例：

```yaml
server:
  listen_addr: "127.0.0.1:8080"
  public_base_url: "http://127.0.0.1:8080"
  shutdown_timeout_seconds: 10

logging:
  level: info
  format: text

database:
  driver: sqlite
  path: "D:/login/data/login.db"
  wal: true
  busy_timeout_ms: 5000

# 需要 OAuth/OIDC 时再启用：
# protocol:
#   enabled: true
#   issuer: "https://login.example.com"

# 需要邮件（验证/找回/告知）时再启用：
# mail:
#   enabled: true
#   smtp:
#     addr: "127.0.0.1:2525"
#     host: "localhost"
#     tls_mode: "starttls"   # starttls | implicit | none
#     username: "tester"
#     password: {env: "LOGIN_SMTP_PASSWORD"}
#   from:
#     address: "no-reply@example.com"
#     name: "EvernightLogin"
#   delivery:
#     max_attempts: 3
```

关键字段说明：

| 字段 | 说明 |
|---|---|
| `server.listen_addr` | 监听地址。默认只建议 `127.0.0.1:8080`；对外部署前先配置 TLS 或可信反向代理。 |
| `server.public_base_url` | 对外可访问的基址，OAuth issuer 派生/Passkey 来源/邮件链接依赖它，生产必须是可信 https 地址。 |
| `server.path_prefix` | 可挂在反向代理子路径下；改动后所有页面/端点路径同步。 |
| `database.path` | SQLite 文件路径；目录必须可写且只允许服务账户访问。 |
| `protocol.enabled` / `protocol.issuer` | 启用 OAuth/OIDC 协议端点；issuer 固定且必须与公开地址一致。 |
| `mail.enabled` | 生产邮件总开关；默认 false，关闭时不读取秘密、不建立网络连接。 |
| `mail.smtp.tls_mode` | `starttls`（默认）、`implicit` 或本地测试用 `none`；`none` 只允许显式回环本地。 |
| `passkey.enabled` / `rp_id` / `allowed_origins` | 启用 Passkey 时必须配置 RP ID 与允许来源；Passkey 不跨域名通用。 |
| 秘密来源 | 密码/密钥使用 `{env: NAME}` 或 `{file: 绝对路径}`，不要写明文到 YAML/命令行。 |

配置优先级为 **内置默认 < YAML < 环境变量 < 显式代码选项**；未知字段、重复键、类型错误、
越界或危险组合会拒绝启动。完整 52 个字段见 [../guide/configuration.md](../guide/configuration.md)。

### 6.3 初始化命令与非交互密码文件（原 README §3.3）

在交互式终端执行（root 密码不回显、需二次确认）：

```bat
D:\login\bin\login-server.exe init --config D:\login\config\login.yaml ^
  --master-key-file D:\login\secrets\master.key ^
  --operator os:deployer@myhost
```

没有交互终端时，可把 root 正式密码放入仅当前账户可读的受保护文件，再用 `--password-file`：

```bat
icacls D:\login\secrets\init-password.txt /inheritance:r /grant:r "%USERNAME%:F" SYSTEM:F Administrators:F
D:\login\bin\login-server.exe init --config D:\login\config\login.yaml ^
  --master-key-file D:\login\secrets\master.key ^
  --password-file D:\login\secrets\init-password.txt ^
  --operator os:deployer@myhost
```

预期：退出码 0，输出唯一 root 用户 ID、`初始化状态: setup_verified`、`security_version`、
主密钥和维护状态路径；**不输出密码、主密钥或一次性凭证**。不要重复执行 `init`；重复初始化
会被拒绝。

> `init` 会创建数据库、执行迁移、生成/加载主密钥、创建唯一 root 并设置正式密码。root 仍
> 要求绑定强认证因素。

### 6.4 首次登录与 root 强认证（原 README §3.5）

1. 浏览器打开 `http://127.0.0.1:8080/login`，用 `root` 和 init 设置的密码登录。
2. 未绑定强因素时只能进入受限初始化会话；按页面提示打开 `/login/strong-setup` 完成
   **Passkey** 注册。
3. 重新登录后取得强认证管理会话，才能访问 `/admin/*` 等管理页面。root 的管理页面要求强认证
   且在有效新鲜度窗口内。
4. 若 Passkey 不可用，`loginctl root-recover` 是本地应急恢复通道；不要在远程匿名接口上尝试
   恢复。

> 当前 root 强认证绑定已接线，但真实浏览器/硬件认证器互操作未完成最终验收；执行前请阅读
> 本文第 5 节与 [standalone-service.md](standalone-service.md) §3.9。

### 6.5 首次部署相关交叉链接

- 独立服务启动参数/单实例/日志轮转：[standalone-service.md](standalone-service.md)
- 配置字段与秘密来源：[../guide/configuration.md](../guide/configuration.md)
- 本地应急与诊断：[../guide/root-cli.md](../guide/root-cli.md)
- 备份与恢复：[../guide/backup-and-restore.md](../guide/backup-and-restore.md)
- 内置 Web 管理台操作：[../guide/admin-console.md](../guide/admin-console.md)

