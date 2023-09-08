# login（EvernightLogin）

login 是一个用 Go 编写的**用户与身份权限系统**：既可以作为 Go 库嵌入业务程序，也可以作为独立身份服务部署，提供账户、登录、会话、用户组/角色/权限、Passkey/TOTP、OAuth 2.0 / OpenID Connect、审计、报告、备份恢复和管理后台。

面向新手的产品文档在 [`docs/guide/`](docs/guide/README.md)；本 README 提供可直接照做的部署、配置和界面操作说明。完整规范以 [`docs/guide/configuration.md`](docs/guide/configuration.md)、[`docs/guide/login-and-oauth.md`](docs/guide/login-and-oauth.md)、[`docs/deployment/`](docs/deployment/README.md) 等文档为准。

## 1. 它能做什么

| 场景 | 能力 |
|---|---|
| 独立部署身份服务 | `login-server` 提供内置 Web 页面、账户登录、管理后台、OAuth 2.0 / OIDC 协议端点（默认关闭）和管理 API（默认关闭） |
| 嵌入现有 Go 业务 | 通过公开包创建实例，复用账户、权限、会话、审计和页面，不启动独立服务 |
| 统一账户与权限 | 全局账户、应用成员与应用内角色/权限隔离，默认拒绝，跨应用越权拒绝 |
| 登录方式 | 密码、Passkey/WebAuthn、TOTP、邮件验证码、恢复代码、邀请/注册审核 |
| 管理与运维 | 用户/组/角色/权限、应用与客户端凭证、审计、统计、报告、备份/恢复、CLI 应急恢复 |
| 多应用接入 | OAuth 客户端、设备码、APP 扫码（设备码/扫码已按步骤 192/193 验收其已实现边界，默认关闭；introspection 仍未交付 143） |

### 当前边界与安全声明

- **运行实测范围**：Windows 11 + SQLite；Linux/macOS 及其他数据库仅做编译/静态检查，未做运行实测。
- **加密与安全**：密码用 Argon2id 哈希，可还原秘密用主密钥加密；关键管理操作要求再次认证和真实授权；默认拒绝、fail-closed。
- **未完成/未测项**：真实浏览器与硬件认证器、第三方 OAuth/OIDC 客户端、真实手机扫码、公网反向代理/mTLS、外部 SMTP 实际送达等未做完整互操作验收。不要仅凭“服务能启动”就认为所有协议和客户端都可用。
- **协议默认关闭**：OAuth/OIDC、管理 JSON API、业务托管 API、应用客服 API 都需显式开关；设备码与扫码登录已按步骤 192/193 验收其已实现边界；令牌状态查询（introspection）仍未交付（143）
- **不做的事**：不实现多租户/多实例共享状态、短信供应商、第三方社交登录、动态插件、跨数据库迁移；第一版以 SQLite 为主。

## 2. 获取与构建

### 2.1 使用发布包（推荐给部署者）

从发布产物解压后，目录包含：

```text
bin/        login-server  loginctl  login-backup
config/     login.example.yaml 及代理样例
deploy/     systemd / Docker / Windows 服务样例
docs/       部署与接口文档
LICENSE     项目许可证
```

Windows 解压示例（PowerShell）：

```powershell
Expand-Archive .\evernight-login-<version>-windows-amd64.zip -DestinationPath D:\login
cd D:\login
.\bin\login-server.exe --version
```

Linux 解压并赋执行权限：

```bash
unzip evernight-login-<version>-linux-amd64.zip -d /opt/login
chmod +x /opt/login/bin/*
/opt/login/bin/login-server --version
```

### 2.2 从源码构建

要求 Go 版本与 `go.mod` 一致（当前 Go 1.27.x）；CGO 可关闭。

Windows（cmd）：

```bat
go build -o build\login-server.exe .\cmd\login-server
go build -o build\loginctl.exe .\cmd\loginctl
go build -o build\login-backup.exe .\cmd\login-backup
```

Linux/macOS：

```bash
CGO_ENABLED=0 go build -o build/login-server ./cmd/login-server
CGO_ENABLED=0 go build -o build/loginctl ./cmd/loginctl
CGO_ENABLED=0 go build -o build/login-backup ./cmd/login-backup
```

推荐用根目录一键入口构建两个产品的六目标（步骤 179）：`.\build.ps1 -Version 0.1.0-dev`；
产物为 24 项（4 命令 × 6 目标）与 `dist/build/build-summary.json`/`checklist.txt`，由
`scripts/verify-build.ps1` 独立校验类型/架构/哈希；发布包 12 个 per-target zip 由步骤 202 的
`scripts/package-release.ps1` 生成并用 `scripts/verify-release.ps1` 校验（见
[`docs/deployment/packaging.md`](docs/deployment/packaging.md) §1.1/§9）。上文的逐命令
`go build` 仍适用于单命令调试；`scripts/build-release.ps1` 作为旧版 Login 六目标脚本保留兼容。

## 3. 从零部署（Windows / Linux）

下面以 Windows 为例；Linux 只需把路径和可执行文件名（去掉 `.exe`）对应替换。所有示例都使用临时目录/新数据库，不要直接操作仓库内的 `database/login.db`。

### 3.1 准备目录

建议把配置、数据、秘密和日志分开：

```text
D:\login\
  config\login.yaml
  data\login.db
  secrets\master.key
  logs\access.log
```

目录只授予运行服务的账户；主密钥、数据库、备份不要放在同一目录。单用户测试可简化，但生产请用专用服务账户并收紧 ACL/文件权限。

### 3.2 编写最小配置

复制发布包中的 `config/login.example.yaml` 或源码中的 `examples/config-load/login.example.yaml`，保存为 `D:\login\config\login.yaml`（文件名可自定义，如 `serv.yaml`；下文统一用 `login.yaml`）。最小可用示例：

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

配置优先级为 **内置默认 < YAML < 环境变量 < 显式代码选项**；未知字段、重复键、类型错误、越界或危险组合会拒绝启动。完整 52 个字段见 [`docs/guide/configuration.md`](docs/guide/configuration.md)。

### 3.3 首次初始化（只执行一次）

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

预期：退出码 0，输出唯一 root 用户 ID、`初始化状态: setup_verified`、`security_version`、主密钥和维护状态路径；**不输出密码、主密钥或一次性凭证**。不要重复执行 `init`；重复初始化会被拒绝。

> `init` 会创建数据库、执行迁移、生成/加载主密钥、创建唯一 root 并设置正式密码。root 仍要求绑定强认证因素。

### 3.4 启动服务

```bat
D:\login\bin\login-server.exe serve --config D:\login\config\login.yaml ^
  --master-key-file D:\login\secrets\master.key ^
  --migrate=apply ^
  --access-log D:\login\logs\access.log
```

- 首次启动或升级后必须显式 `--migrate=apply`；未迁移数据库默认拒绝启动。
- 只允许一个 `serve` 进程使用同一 SQLite；第二个进程会因排他锁失败。
- 停止用 `Ctrl+C`（Linux 用 SIGTERM/SIGINT），服务在 `shutdown_timeout_seconds` 内有界关闭并释放端口。

验证：

```bat
curl -s -o NUL -w "%%{http_code}" http://127.0.0.1:8080/healthz
curl -s -o NUL -w "%%{http_code}" http://127.0.0.1:8080/login
```

预期 `/healthz` 和 `/login` 返回 200，未知路径 404。

### 3.5 首次登录与 root 强认证

1. 浏览器打开 `http://127.0.0.1:8080/login`，用 `root` 和 init 设置的密码登录。
2. 未绑定强因素时只能进入受限初始化会话；按页面提示打开 `/login/strong-setup` 完成 **Passkey** 注册。
3. 重新登录后取得强认证管理会话，才能访问 `/admin/*` 等管理页面。root 的管理页面要求强认证且在有效新鲜度窗口内。
4. 若 Passkey 不可用，`loginctl root-recover` 是本地应急恢复通道；不要在远程匿名接口上尝试恢复。

> 当前 root 强认证绑定已接线，但真实浏览器/硬件认证器互操作未完成最终验收；执行前请阅读 [`docs/deployment/first-run.md`](docs/deployment/first-run.md)。

### 3.6 Linux systemd 示例

参考发布包 `deploy/evernight-login.service` 或源码 [`docs/deployment/samples/evernight-login.service`](docs/deployment/samples/evernight-login.service)：

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

将配置/秘密放到权限受限目录（如 `/etc/login`，`0600`）；数据库/日志放 `/var/lib/login`、`/var/log/login`。首次 `init` 用同一服务账户执行。

### 3.7 TLS 与反向代理

- 小规模本机/内网：可直接在 `server.tls_cert_files` / `server.tls_key_files` 配置本地 TLS；默认最低 TLS 1.2。
- 对外推荐：nginx/Caddy 终止 TLS，应用只监听回环；配置 `server.tls_terminating_proxy: true`、`server.trusted_proxies` 和 https 的 `public_base_url`，否则非回环明文监听会被拒绝。
- mTLS 客户端证书、可信代理、证书到期状态等见 [`docs/deployment/standalone-service.md`](docs/deployment/standalone-service.md) 与 [`docs/deployment/reverse-proxy.md`](docs/deployment/reverse-proxy.md)。

### 3.8 邮件配置（可选）

生产邮件用于注册邮箱验证、邮箱变更、邮件 MFA、密码找回、客服恢复和安全告知。

1. 把 `mail.enabled` 设为 `true`，填写 SMTP 地址/TLS/发件地址；SMTP 密码只放 `env:`/`file:`。
2. 首次启动会校验配置/秘密可读性；证书校验不可关闭，测试环境通过 `trusted_roots` 追加测试 CA。
3. 开发/测试可启动本仓库的 **EvernightMail** 本地捕获器（独立子模块，仅用于测试），把 Login 的 `mail.smtp.addr` 指向它；不要向真实第三方地址发测试邮件。
4. `mail.enabled=false` 时邮件功能会以明确错误失败，不会伪造发送成功。生产邮件实际送达、外部反代等仍需自行验收。

## 4. 内置 Web 管理台操作指南

服务启动后，页面按配置和权限显示。管理页要求已完成强认证的管理会话；普通用户只能访问自己的页面。页面路由以实际注册为准，依赖不满足的页面可能返回 404。

### 4.1 账户与个人中心（普通用户）

| 页面 | 地址 | 常用操作 |
|---|---|---|
| 登录/注册 | `/login`、`/register` | 登录、退出；开放注册时创建账户并完成邮箱验证/审核 |
| 邮箱验证/邀请 | `/email/verify`、`/invitation/accept` | 验证邮箱、接受邀请 |
| 个人资料 | `/account/profile` | 修改昵称、简介、语言、时区、电话；上传头像 |
| 用户名/邮箱 | `/account/profile/username`、`/account/profile/email` | 受控更名；变更邮箱（需当前密码，新邮箱验证后生效） |
| 密码 | `/account/password` | 修改密码；忘记密码从登录页进入找回 |
| 安全中心 | `/account/security` | 查看/管理 MFA、TOTP、Passkey、恢复代码、会话与已授权应用 |
| 两步验证 | `/account/security/mfa` | 添加邮件验证码因素；管理已启用因素 |
| TOTP | `/account/security/totp` | 绑定/解除 TOTP，查看恢复代码 |
| Passkey | `/account/security/passkeys` | 注册、重命名、撤销 Passkey |
| 恢复代码 | `/account/security/recovery-codes` | 生成/更新恢复代码（只展示一次） |
| 会话/授权 | `/account/sessions`、`/account/grants` | 退出设备、撤回应用授权、查看活动 |
| 安全活动 | `/account/activity` | 查看本人安全事件 |

操作提示：敏感操作（改密码、邮箱变更、MFA/Passkey 变更、恢复代码）通常要求再次输入当前密码或完成强认证；确认页展示目标/范围/后果，服务端仍会重新鉴权，确认框本身不是授权。

### 4.2 管理后台（root / 授权管理员）

| 页面组 | 地址 | 操作 |
|---|---|---|
| 仪表盘 | `/admin` | 查看系统状态、关键统计和待办 |
| 用户 | `/admin/users` | 列表/创建/详情/启停/删除预览/禁停；批量导入导出；审核注册 |
| 用户组 | `/admin/groups` | 建组、改资料、增删成员、删除 |
| 角色/权限 | `/admin/roles`、`/admin/permissions` | 创建角色、组合权限、分配/撤销、启停；查看预设差异 |
| 委派/有效权限 | `/admin/delegations`、`/admin/access/effective` | 查看委派范围与实际有效权限（委派写操作按设计受限） |
| 应用 | `/admin/applications` | 新建应用（默认停用）、资料、成员、OAuth 安全接入、客户端凭证、授权、启停 |
| 应用托管策略 | 应用详情中的“托管策略”页 | 配置该应用可调用的管理 API 操作/对象/字段；只有 root/受信管理员可写 |
| 客服/恢复 | `/support/cases`、`/support/recovery` | 创建/处理工单、发起/审批人工恢复（人工恢复制度默认关闭，需 152 配置与独立审批） |
| 安全策略 | `/admin/security/policies` | 查看/修改敏感操作策略、再次认证新鲜度、通知要求、恢复默认 |
| 审计 | `/admin/audit` | 查询/详情/导出、错误诊断、root 清理与保留策略 |
| 统计/报告 | `/admin/dashboard`、`/admin/reports` | 统计看板；报告五格式（HTML/PDF/Markdown/CSV/JSON）生成、计划、下载、清理 |
| 备份 | `/admin/backups` | 热备份任务、计划、详情、下载、清理、恢复状态 |
| 通知 | `/admin/notifications/mail` | 查看/测试邮件通知配置（测试只应指向本地捕获器） |

注意：
- **应用新建**后默认停用，需要先启用并登记客户端凭证；本版本不提供应用硬删除，停用不等于删除。
- **用户/角色/应用管理**都受真实授权与数据范围约束；页面按钮隐藏不代表授权，服务端每次请求都会重新判定。
- **root 是特殊账户**，不能作为普通角色分配；root 的敏感策略、备份恢复和审计清理需强认证。
- **人工恢复**默认关闭，必须由 root 配置可执行依据/独立审批人/等待期后才能使用；客服不能读取密码、恢复码或重置链接。

## 5. 命令行工具

### 5.1 `login-server`

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

常用 flag：`--config`、`--database`、`--master-key-file`、`--migrate=apply`、`--access-log`、`--maintenance-state-dir`、`--enable-protocol`、`--enable-admin-api`、`--enable-managed-api`、`--enable-app-support`。完整说明见 [`docs/deployment/standalone-service.md`](docs/deployment/standalone-service.md)。

### 5.2 `loginctl`（本地运维/应急）

```bash
# 配置/诊断/迁移
loginctl config validate --config /etc/login/login.yaml
loginctl config show --config /etc/login/login.yaml --json
loginctl diag health --config /etc/login/login.yaml
loginctl diag ready --config /etc/login/login.yaml --state-dir /var/lib/login-maintenance --keyring-file /etc/login/secrets/master.key
loginctl migrate status --config /etc/login/login.yaml
loginctl migrate apply --config /etc/login/login.yaml --confirm MIGRATE --service-stopped

# 本地用户只读/禁用（需要本地管理员 operator 和版本）
loginctl user list --operator local-admin --config /etc/login/login.yaml
loginctl user get <user_id> --operator local-admin --config /etc/login/login.yaml
loginctl user disable <user_id> --operator local-admin --expected-version <row_version> --confirm DISABLE --config /etc/login/login.yaml

# 组/角色/应用/权限（读取与受控建组；部分写动作明确返回 MANAGEMENT_WRITE_NOT_EXPOSED）
loginctl group list --operator local-admin --config /etc/login/login.yaml
loginctl role list --operator local-admin --config /etc/login/login.yaml

# 在线管理（需要运行中的服务和管理会话文件）
loginctl audit events list --session-file /etc/login/secrets/admin-session.json --config /etc/login/login.yaml
loginctl reports history list --session-file /etc/login/secrets/admin-session.json --config /etc/login/login.yaml
loginctl backups artifacts list --session-file /etc/login/secrets/admin-session.json --config /etc/login/login.yaml
loginctl session admin-revoke --user <user_id> --reason "离职紧急下线" --confirm ADMIN-REVOKE --session-file <protected>

# root 应急恢复（服务停止/维护 + 排他锁；本地管理员边界）
loginctl root-recover --database /var/lib/login/login.db --reason "root 锁定" --service-stopped --reset-password
loginctl root-recover --database /var/lib/login/login.db --reason "MFA 丢失" --maintenance --reset-mfa
```

`loginctl` 的错误码/退出码与 JSON 输出约定见 [`docs/guide/root-cli.md`](docs/guide/root-cli.md)。

### 5.3 `login-backup`（离线备份/校验/查看）

```bash
# 创建加密热备份（SQLite 在线快照；主密钥与备份分开）
login-backup create --database /var/lib/login/login.db \
  --key-file /etc/login/secrets/master.key \
  --output /var/backups/login --operator local-admin

# 校验/查看/导出
login-backup verify --file /var/backups/login/<backup>.elnbak --key-file /etc/login/secrets/master.key
login-backup info --file /var/backups/login/<backup>.elnbak
login-backup list --file /var/backups/login/<backup>.elnbak --key-file /etc/login/secrets/master.key
login-backup preview --file ... --key-file ... --table users --limit 20
login-backup export --file ... --key-file ... --table users --format json --output /tmp/users.json
```

备份与恢复流程、DACL/路径安全、旧凭证失效边界见 [`docs/guide/backup-and-restore.md`](docs/guide/backup-and-restore.md)。恢复必须在维护模式/停服下执行，失败默认保持维护。

## 6. HTTP API 与 OAuth2/OIDC 接入

### 6.1 启用协议端点

```yaml
protocol:
  enabled: true
  issuer: "https://login.example.com"
```

```bash
login-server serve --config /etc/login/login.yaml \
  --master-key-file /etc/login/secrets/master.key \
  --enable-protocol --enable-admin-api
```

- `--enable-protocol`：OAuth/OIDC 协议端点；**默认关闭**，关闭时 404。
- `--enable-admin-api`：管理 JSON API `/admin/v1`；默认关闭。
- `--enable-managed-api`：业务托管 API `/api/managed/v1`；默认关闭。
- `--enable-app-support`：应用受限客服 API `/api/app/v1/support`；默认关闭，且需协议端点。

### 6.2 OAuth/OIDC 端点

启用后常用路径（以 `public_base_url` 为基址）：

| 端点 | 路径 | 说明 |
|---|---|---|
| Discovery | `/.well-known/openid-configuration` | 只声明真实启用能力 |
| JWKS | `/jwks` | 验签公钥 |
| 授权 | `/oauth/authorize` | 授权码 + PKCE（S256 强制） |
| 令牌 | `/oauth/token` | 授权码兑换、刷新轮换、客户端凭证 |
| UserInfo | `/oauth/userinfo` | Bearer Access Token |
| 撤销 | `/oauth/revoke` | RFC 7009 |
| 状态查询 | `/oauth/introspect` | RFC 7662，需显式启用 |
| 设备码 | `/oauth/device_authorization` | RFC 8628（步骤 192 已验收其已实现边界；真实第三方客户端未测） |
| 扫码 | `/oauth/qr/...` | 步骤 193 已验收其已实现边界（真实手机相机扫码未测） |

注意：设备码与扫码登录已按步骤 192/193 验收其已实现边界；令牌状态查询（introspection）仍未交付（143）。默认关闭；Discovery 只声明实际能力。真实第三方客户端互操作、标准 OIDC 客户端联调未完成，不能按“已全部交付”对待。详见 [`docs/guide/login-and-oauth.md`](docs/guide/login-and-oauth.md)。

### 6.3 注册应用与获取客户端

使用管理后台 `/admin/applications`（或对应管理 API）创建应用，填写名称、客户端类型（public/confidential）、回调地址、允许的 grant/scope/audience，然后登记客户端凭证。应用创建后默认停用，需要启用后再接入。

`curl` 检查 Discovery（先把 `<issuer>` 换成实际地址）：

```bash
curl -s https://login.example.com/.well-known/openid-configuration | jq
curl -s https://login.example.com/jwks | jq
```

完整参数、PKCE、刷新轮换、撤销、audience/scope 规则见 [`docs/deployment/integration.md`](docs/deployment/integration.md)。

### 6.4 管理/托管/客服 API

- 管理 API：`/admin/v1`，启用 `--enable-admin-api`，使用管理会话/CSRF；适合运维自动化，不应暴露给业务应用。
- 托管 API：`/api/managed/v1`，启用 `--enable-managed-api`；只允许应用在受限操作/对象/字段白名单内管理自己的资源，默认关闭。
- 应用客服 API：`/api/app/v1/support`，启用 `--enable-app-support`，只允许应用客服用户创建本应用工单，不能审批或执行恢复。

OpenAPI 当前只包含最小健康/错误契约，不是完整业务 API 文档；业务接口以 [`docs/deployment/managed-api.md`](docs/deployment/managed-api.md) 和源码公开契约为准。

## 7. 作为 Go Module 嵌入

```go
import login "github.com/kagurazakayashi/EvernightLogin"

instance, err := login.New(login.Options{
    // 配置、数据库、日志、通知等由宿主显式注入
})
if err != nil { /* ... */ }
if err := instance.Start(ctx); err != nil { /* ... */ }
defer instance.Close()
```

嵌入模式复用同一套账户、权限、会话、审计与页面逻辑，不自动监听端口；宿主负责数据库/密钥/HTTP 服务器所有权与关闭。可运行示例：

- `examples/external-consumer`：独立外部 Go module 使用公开 API；
- `examples/embedded-runtime`：嵌入式运行时与页面/HTTP 挂载骨架；
- `examples/config-load`：只加载/校验配置；
- `examples/ui-pages`：内置页面与替换契约；
- 其他示例见 [`examples/`](examples/) 与 [`docs/guide/README.md`](docs/guide/README.md) 的示例索引。

## 8. 安全、备份、升级与排障

### 8.1 安全建议

- 生产只监听回环并由可信反向代理终止 TLS；配置 `public_base_url`、可信代理和 Host 限制。
- 主密钥、数据库、备份、会话秘密分开保存；只授予服务账户最小权限。
- root/高权限管理员必须完成强认证（Passkey 等），敏感操作要求再次认证；不要关闭 fail-closed 策略。
- 备份文件是认证加密的，但备份期间可能出现明文快照；输出目录必须由 ACL/权限保护。
- 不要把秘密、Token、恢复码写进日志、工单、截图或仓库；测试只使用合成账户和本地捕获器。
- 定期检查审计、失败登录、撤销/恢复事件；发现异常时先撤销会话/凭证，再调查。

### 8.2 备份与恢复

1. 日常使用 `login-backup create` 做加密热备份，并定期用 `verify` 校验。
2. 恢复前先进入维护模式并创建回退备份；执行 `restore-preflight` 预演，再 `restore-apply`。
3. 失败时默认保持维护，不自动放行；恢复后旧会话/刷新令牌/恢复码/一次性凭证按设计失效。
4. 只使用临时副本演练，不要把生产库直接复制给验证脚本。

### 8.3 升级

1. 先备份数据库、配置和主密钥；确认旧进程可回退。
2. 替换 `login-server`/`loginctl`/`login-backup` 二进制。
3. 启动时显式 `--migrate=apply`；迁移只向前，先看发布说明与备份。
4. 检查 `/healthz`、登录页、管理页和关键协议端点；出现迁移/锁/维护错误先停止并保留现场。

### 8.4 常见问题

| 现象 | 常见原因与处理 |
|---|---|
| 启动提示缺少 root/未初始化 | 先执行 `login-server init`；不要用 `--allow-uninitialized` 暴露到非回环。 |
| 启动提示未迁移 | 使用 `--migrate=apply`；生产先备份。 |
| 第二个进程启动失败 | 同一 SQLite 只允许一个 `serve`；确认旧进程已退出。 |
| 管理页 403 | root/管理员需要已完成强认证；完成 `/login/strong-setup` 后重新登录；检查会话新鲜度。 |
| OAuth/管理端点 404 | 对应 `--enable-protocol`/`--enable-admin-api`/其他开关未开启；设备码/扫码已按 192/193 验收边界，introspection 仍未交付（143）。 |
| 邮件发送失败 | `mail.enabled` 未开、SMTP/CA/密码配置错误或投递失败；查看页面错误码、服务日志和 `mail_deliveries`；不要伪造成功。 |
| 维护模式 503 | 服务处于维护/恢复状态；完成 `restore-apply` 并显式 `maintenance-exit`，不要绕过。 |
| 忘记 root 密码/MFA | 使用本地 `loginctl root-recover`（停服/维护+排他锁），不要尝试远程匿名恢复。 |

完整错误码与处理建议见 [`docs/guide/troubleshooting.md`](docs/guide/troubleshooting.md) 和 [`docs/requirements/login_错误码与排障手册.md`](docs/requirements/login_错误码与排障手册.md)。

## 9. 文档索引

| 文档 | 内容 |
|---|---|
| [`docs/guide/README.md`](docs/guide/README.md) | 新手文档总览、能力状态、术语、示例索引 |
| [`docs/guide/quickstart.md`](docs/guide/quickstart.md) | Windows 从空配置到启停/诊断的最短路径 |
| [`docs/guide/configuration.md`](docs/guide/configuration.md) | 全部配置字段、默认值、秘密来源、热更新分类 |
| [`docs/guide/login-and-oauth.md`](docs/guide/login-and-oauth.md) | 登录、Passkey/MFA、OAuth/OIDC 接入 |
| [`docs/guide/applications-and-permissions.md`](docs/guide/applications-and-permissions.md) | 应用、成员、系统/应用权限与 51 个权限键 |
| [`docs/guide/roles-and-scopes.md`](docs/guide/roles-and-scopes.md) | 预设角色、用户组、作用范围、委派 |
| [`docs/guide/support-and-recovery.md`](docs/guide/support-and-recovery.md) | 客服、人工恢复、恢复代码 |
| [`docs/guide/audit-and-reports.md`](docs/guide/audit-and-reports.md) | 审计、统计、报告五格式 |
| [`docs/guide/backup-and-restore.md`](docs/guide/backup-and-restore.md) | 加密热备份、离线查看、维护恢复 |
| [`docs/guide/root-cli.md`](docs/guide/root-cli.md) | `loginctl` 本地/在线命令、退出码 |
| [`docs/guide/deployment-modes.md`](docs/guide/deployment-modes.md) | 嵌入 vs 独立服务、当前边界 |
| [`docs/deployment/`](docs/deployment/README.md) | 首次部署、standalone、TLS/反代、容器、邮件子模块、打包 |
| [`examples/`](examples/) | 可运行示例（外部 module、OIDC、扫码、托管 API、报告/任务等） |

## 10. 许可证

本项目采用 **MulanPSL2（木兰宽松许可证，第 2 版）**，全文见 [LICENSE](LICENSE)。

项目署名严格为 `Copyright (c) KagurazakaYashi(KagurazakaMiyabi)`，不附年份。第三方组件、字体与依赖保留其原有版权/许可声明，详见 [`docs/licenses/THIRD_PARTY_NOTICES.md`](docs/licenses/THIRD_PARTY_NOTICES.md) 与 [`docs/licenses/`](docs/licenses/)。
