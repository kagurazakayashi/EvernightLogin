# login

login 提供可嵌入 Go 程序的用户与权限组件，并计划提供独立的 OAuth 2.0 / OpenID Connect 身份服务。当前只是最小可编译骨架，不是可运行的用户系统。

## 项目状态（步骤 31）

- 模块路径：`github.com/kagurazakayashi/EvernightLogin`，根包名 `login`；路径来自现有远端，首次发布后不再变更。
- 独立进程入口：`cmd/login-server`。当前只提供 `--version` 和 `--help`；不带参数运行会明确失败并返回非零，不假装服务已启动。
- 本地管理命令入口：`cmd/loginctl`（步骤 48 只实现 `root-recover` 应急恢复；要求本地维护停机、显式确认与数据库目录排他锁，不提供远程入口）。
- 已实现：版本与构建信息；类型化配置加载器；核心实例生命周期契约；统一错误码注册表、`AppError`、请求编号校验与结构化运行日志；版本化数据库迁移机制及隔离核心表；基于 modernc SQLite 的存储基础（连接/所有权、WAL、外键、忙等待、连接池上限、事务与取消、错误映射、有界重试、迁移执行）；内部秘密加密包 `internal/secrets`（AES-256-GCM 认证加密、随机 nonce、用途/对象/范围绑定、主密钥环加载、Windows ACL/Unix 权限检查、轮换与可中断重加密、旧密钥退役保护）；一次性凭证服务 `internal/credential` 与 SQLite 生产仓储（用途/目标/应用绑定、高熵摘要、低熵受密钥保护验证码、原子消费、取消/替换/过期清理、可注入时钟）及迁移 0002；安全审计包 `internal/audit` 与 SQLite 持久化（可信身份、脱敏差异、失败审计独立保存、关键变更同事务、审计故障拒绝并告警）及迁移 0003；可靠单实例后台任务执行器 `internal/task` 与 SQLite 状态持久化（完整任务状态机、可信发起/执行/取消身份、并发与墙钟上限、取消上下文与子进程清理约定、重启恢复、全状态审计）及迁移 0004；定时计划（日/周/月/自定义表达式、IANA 时区与夏令时规则、停机错过策略与有界补跑、触发去重、尝试历史、有界指数退避重试与显式不可重试错误、运行前权限复验默认拒绝、暂停/恢复/删除语义）及迁移 0005；HTTP 传输层 `internal/transport` 与公开 `login.NewHTTPHandler`（标准 net/http Handler、固定前缀与严格路由、请求体类型/大小与参数规范化、统一错误 JSON/请求编号/panic 恢复/上下文取消、最小健康端点、可信身份建立与 context 传递、由错误码注册表生成的 OpenAPI、W3C Extended 脱敏访问日志与写入失败告警）；HTTP 防护层 `internal/ratelimit` 与传输层中间件（多维有界固定窗口限流、容量上限与过期清理、可信代理地址解析、昂贵请求预算、请求期限/响应超时与并发上限、精确来源 CORS、安全响应头、Cookie 会话 CSRF 契约与 Cookie 安全属性策略）；独立监听组件 `login.NewServer` 与 `internal/listener`/`internal/netpolicy`/`internal/proxytrust`（多 IPv4/IPv6 地址监听、失败整体回滚、关停释放端口、Host/公开地址限制、Forwarded 与 X-Forwarded-* 可信代理链边界、限流使用验证后的客户端地址，可交给 `Instance` 生命周期管理）；HTTPS 单向认证 `internal/tlscert`（PEM 证书链/私钥/附加 CA、PKCS#12/PFX 导入、私钥与证书匹配、证书链与用途/有效期校验、按 SNI 选择证书、未知 SNI 拒绝、安全重载与到期状态）；可选客户端证书双向认证 mTLS（`disabled`/`required`/`optional` 模式、独立客户端信任 CA、显式“证书 DNS 名称 -> 可信服务身份”映射、可选模式拒绝无效证书降级、脱敏 mTLS 状态诊断与服务身份上下文）。
- 账户领域基础 `internal/account` 与 SQLite 仓储 `internal/account/sqlite`（普通用户创建、按稳定 ID 查询、有限分页检索；用户名显示值/规范化值分离，NFKC 兼容规范化 + Unicode 大小写折叠；保留名、空白、Unicode 与长度规则；资料字段白名单；创建/读取审计与审计失败拒绝；可信本地初始化授权器，生产 HTTP 未接入）；账户状态变更与删除流程（启用/禁用/待删除/完成删除状态机、row_version 乐观并发、security_version 失效语义、root 保护、删除影响预览与关联数据明确清理策略、关键变更同事务审计）。
- 应用领域基础 `internal/app` 与 SQLite 仓储 `internal/app/sqlite`（应用登记、读取、有限分页、展示资料更新、启停状态；应用 ID 不可变；创建时同一事务写入唯一应用 scope；client_type 只在创建时确定；负责人变更不自动转移管理权限；应用管理员按显式分配仅操作已分配应用；停用写可靠审计事件，依赖方须检查应用状态；删除应用未在本步实现）；应用成员管理（受控加入既有账户、应用内成员状态启停、按应用隔离的分页/读取、应用专属资料白名单；成员状态与资料只影响指定应用，不修改全局账户或其他应用；成员移除/停用写可靠审计事件，未来会话/令牌模块须消费事件并复查当前状态）。
- 用户组领域基础 `internal/group` 与 SQLite 仓储 `internal/group/sqlite`（系统范围/应用范围用户组、稳定组 ID 与不可变 group_key、显示名称/说明可修改但 scope 不可转移、组成员批量加入/移除/分页；应用组只允许该应用有效成员，系统组管理与成员变更要求相应资格；批量成员操作上限 12 人、全有或全无；组成员变更加审计事件，角色模块接入后需消费以失效权限；删除组级联删除成员/组角色关联但不删除用户与审计历史；不实现角色分配/嵌套组/HTTP 端点）。
- 权限目录基础 `internal/permission` 与 SQLite 仓储 `internal/permission/sqlite`（系统内置/系统自定义/应用独有权限；scope+机器标识唯一定位、同名跨应用隔离；内置权限标识/含义不可改不可删、可按规则启停，root_only 敏感权限仅本地初始化操作者启停；自定义权限名称/说明/限制可改、机器标识不可变；机器可读定义含 key/分组/scope/生效对象/默认启用/敏感/builtin/enabled；被角色引用时拒绝删除；停用是拒绝而非跳过检查；不实现角色分配/授权执行/HTTP）。
- 有效权限计算引擎 `internal/authz` 与 SQLite 只读快照 `internal/authz/sqlite`（按当前账户/应用成员/直接角色/用户组角色/角色启停/权限启停/root_only 实时计算系统或应用 scope 的有效权限；禁用优先，直接与组来源合并但数据范围取交集；all/any 默认 all、未知权限拒绝；返回权限来源、角色/组/权限启停与排除原因；数据范围契约 all/none/resources/历史未声明并对资源检查 fail-closed；查询他人权限需授权，普通用户只能查自己、应用管理员仅获准应用成员、本地/系统可查普通主体；单个事务快照、无缓存、分页与来源行数有界；不实现 OAuth Token 联合校验与 HTTP）。
- 预设目录初始化 `internal/preset` 与 SQLite 生产仓储 `internal/preset/sqlite`（版本化、机器可读的预设目录：系统管理员、用户管理员、客服、审计员、普通用户五个系统角色与默认用户组；应用管理员/应用普通用户按应用创建模板生成，每个应用各自独立；每条权限都有稳定标识、中文名称、能做什么、范围与不能做什么，同一格多个权限逐条登记；不创建任何账户、不做角色分配、没有可分配的 root 角色；初始化幂等且升级不覆盖用户调整；恢复默认必须差异预览 + 服务端确认令牌再次授权 + 同一审计事务，并接入步骤 26 的 delegation.Guard；写入迁移 0007 的初始化版本记录）。
- 本地受控首次初始化 `internal/bootstrap` 与 SQLite 生产仓储 `internal/bootstrap/sqlite`（唯一 root 只由本机受信 `local_admin` 通道创建；不设默认密码、不保存密码/哈希、不签发会话或令牌；root 创建后处于受限待配置状态，只持有一条一次性、本机、短期配置凭证（用途 `root.setup` 绑定新 root 用户 ID，1 分钟～1 小时，默认 15 分钟，数据库只存摘要）；并发初始化最多一个成功、重复运行与已有 root 一律拒绝并留失败审计；root 行与迁移 0008 的初始化状态记录在同一审计事务中条件插入，失败整体回滚；初始化完成后创建入口关闭，重启只读取数据库不重建默认账户；状态查询与重新签发凭证提供本地可诊断恢复入口；`users` 与 `account`/`role`/`group` 服务层继续拒绝删除、禁用、降格与角色/组路径操作 root）。
- 正式密码与认证 `internal/authn` 与 SQLite 生产仓储 `internal/authn/sqlite`（使用 `golang.org/x/crypto` 的 Argon2id 生成带算法版本/参数/随机盐的自描述 PHC 哈希，参数有界可升级并在登录成功时条件升级；密码长度、弱密码基线、可选近期历史与“不包含账户信息”策略，不强制无依据的定期改密；支持用户名与配置允许的已验证邮箱登录；统一公开失败提示，用户/地址/操作维度限流与可恢复的渐进延迟/临时锁定，成功认证重置失败状态；root 与高权限系统角色密码正确后仍为受限待第二因素结果，MFA 未实现时绝不当作完整登录、不签发会话或 Token；新增迁移 0009）。
- 服务端会话 `internal/session` 与 SQLite 生产仓储 `internal/session/sqlite`（把密码认证结果接入会话：高熵会话秘密只返回一次、数据库只存 HMAC-SHA256 验证摘要；普通/受限会话与受限原因分列，受限会话不得访问普通业务或管理接口；空闲/绝对双重到期、登录成功轮换会话 ID 防会话固定、显式续期与退出/批量撤销；每次校验重读账户状态与 `security_version` 及（可选）应用成员状态，账户禁用/改密/成员移除立即失效；Cookie 默认 `__Host-`、Secure、HttpOnly、SameSite=Lax，会话绑定 CSRF 令牌并可直接作为既有 CSRF 中间件的校验器；管理访问额外要求强认证，MFA 未实现前保持拒绝；新增迁移 0010 `sessions`）。
- 会话设备管理（步骤 31，继续 `internal/session` 扩展）：用户本人设备/会话列表（分页、标记当前会话、只返回展示字段不返回会话秘密）、指定退出与退出全部、管理员按授权范围强制下线（应用管理员仅限获准应用会话，root 与受保护目标拒绝，无授权实现时 fail-closed）、记住我更长绝对到期、最大在线数与单设备替换策略（在登录审计事务内以单条条件更新原子维护，自动淘汰写独立审计）；新增迁移 0011 追加 `remember_me`/展示用客户端描述列与活动会话索引；管理强认证与数据范围裁剪仍未接入，管理强制下线只提供 Go API。
- 可转授权限与委派限制 `internal/delegation` 与 SQLite 生产仓储 `internal/delegation/sqlite`（把“可使用权限”与“可转授权限”分开：委派资格由受限本地初始化/系统操作者显式签发并写入迁移 0006，记录作用范围、权限、数据范围上限、目标白名单、是否允许自我/本组转授、有效期与撤回；角色组合权限、角色分配、启用角色、向已配角色的用户组增员、应用成员加入/重新启用、启用权限、启用应用等所有改变有效权限的写入路径统一经 Guard 在同一审计事务内检查，普通管理者只能转授自己当前实际持有且有有效资格的权限，数据范围必须收缩，默认禁止自我与自身所在用户组；启用角色/权限、组合权限进已分配角色与启用应用等间接路径还按实际受影响目标集合复核 allow_self 与目标白名单，启用应用无法安全校验时仅受信通道可通过；持有但不可转授、过期/撤回、目标越界、范围过宽与并发撤回均拒绝并返回可诊断错误码；数据范围收缩尚未完整落地（写入路径仍为未声明范围，非 all 上限一律 fail-closed），不实现审批引擎、再委派、数据范围写入口与委派资格 HTTP）。
- 角色领域基础 `internal/role` 与 SQLite 仓储 `internal/role/sqlite`（系统/应用角色的创建/读取/分页/资料更新/启停/受引用保护的删除；角色机器标识稳定且不能使用 root 语义；角色只组合同范围、启用、非 root_only 权限；角色可分配给可用全局账户或系统组、以及应用有效成员或同应用用户组；重复组合/分配幂等，删除前检查权限/用户/组引用；root 账户不能作为普通角色分配目标；不实现有效权限推导、可转授权限检查或 HTTP 端点）。
- 尚未实现：SQLite、`internal/secrets`、`internal/credential`、`internal/audit`、`internal/task` 与 `internal/transport` 尚未接入 `login-server`；`cmd/login-server` 也尚未装配 `NewServer`（监听组件已可由 Go API 使用并交给 `Instance` 管理）；客户端信任 CA/身份映射的热重载与 OCSP/CRL 在线撤销、完整反向代理部署示例、账户创建/查询/状态变更/删除、应用登记/资料/启停/应用成员管理、用户组与组成员、权限目录、角色与角色分配的 HTTP 与服务启动接入（`internal/account`/`internal/app`/`internal/group`/`internal/permission`/`internal/role`/`internal/authz`/`internal/delegation` 已提供基础能力）、有效权限推导与授权执行的 HTTP/令牌接入（`internal/authz` 已提供基础引擎）、首次初始化入口的 CLI/启动装配（`internal/bootstrap` 已提供受信 Go API，`cmd/loginctl` 目前只实现 root-recover 应急恢复命令，完整 CLI 未建）、密码登录/退出/会话校验的 HTTP 路由接入与启动装配（认证与受限/普通会话能力已由 `internal/authn`/`internal/session` 提供受信 Go API，步骤 30/31 未暴露 HTTP 路由；设备列表与管理员强制下线同样只有 Go API，管理强认证与数据范围裁剪尚未接入）、OAuth/OIDC 客户端凭证与回调、Web 页面、应用删除策略、审计查询/导出/报告/清理、备份流程仍未实现。委派资格签发/撤回管理 API、审批引擎、预设目录的 HTTP/CLI 管理入口（`internal/preset` 已提供受信通道初始化/恢复能力）与数据范围写入口也未实现。HTTP Handler 只公开健康与 OpenAPI，不提供业务或管理端点；防护层不提供绕过鉴权或 CSRF 的生产开关，任务执行器与调度器不提供网络端点，服务层授权尚未接入，也不承诺外部副作用恰好执行一次。密码哈希与密码验证已由 `internal/authn` 使用 Argon2id 实现；会话签发/校验/续期/撤销与受限会话语义已由 `internal/session` 实现（未暴露 HTTP 路由），MFA/管理强认证与完整管理会话尚未实现。root 的受限配置凭证兑换后可设置正式密码，但 MFA/管理强认证完成前状态保持 `setup_verified`、不会进入 `ready`，也不会签发管理员会话（`ready` 条件转换已由 `internal/bootstrap` 的 `MarkReady` 提供）。
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
| server.tls_client_auth | LOGIN_SERVER_TLS_CLIENT_AUTH | 需重启 |
| server.tls_client_ca_files | LOGIN_SERVER_TLS_CLIENT_CA_FILES | 需重启 |
| server.tls_client_identities | LOGIN_SERVER_TLS_CLIENT_IDENTITIES | 需重启 |
| server.shutdown_timeout_seconds | LOGIN_SERVER_SHUTDOWN_TIMEOUT_SECONDS | 可热更新 |
| logging.level | LOGIN_LOGGING_LEVEL | 可热更新 |
| logging.format | LOGIN_LOGGING_FORMAT | 可热更新 |
| database.driver | LOGIN_DATABASE_DRIVER | 需重启 |
| database.path | LOGIN_DATABASE_PATH | 需重启 |
| database.wal | LOGIN_DATABASE_WAL | 需重启 |
| database.busy_timeout_ms | LOGIN_DATABASE_BUSY_TIMEOUT_MS | 需重启 |
| registration.enabled | LOGIN_REGISTRATION_ENABLED | 需重启 |
| registration.require_review | LOGIN_REGISTRATION_REQUIRE_REVIEW | 需重启 |
| registration.require_email_verification | LOGIN_REGISTRATION_REQUIRE_EMAIL_VERIFICATION | 需重启 |
| registration.default_role_ids | LOGIN_REGISTRATION_DEFAULT_ROLE_IDS | 需重启 |
| passkey.enabled | LOGIN_PASSKEY_ENABLED | 需重启 |
| passkey.rp_id | LOGIN_PASSKEY_RP_ID | 需重启 |
| passkey.rp_display_name | LOGIN_PASSKEY_RP_DISPLAY_NAME | 需重启 |
| passkey.allowed_origins | LOGIN_PASSKEY_ALLOWED_ORIGINS | 需重启 |
| passkey.user_verification | LOGIN_PASSKEY_USER_VERIFICATION | 需重启 |
| app_qr_login.enabled | LOGIN_APP_QR_LOGIN_ENABLED | 需重启 |
| app_qr_login.allowed_client_ids | LOGIN_APP_QR_LOGIN_ALLOWED_CLIENT_IDS | 需重启 |
| app_qr_login.request_ttl_seconds | LOGIN_APP_QR_LOGIN_REQUEST_TTL_SECONDS | 需重启 |
| app_qr_login.claim_interval_seconds | LOGIN_APP_QR_LOGIN_CLAIM_INTERVAL_SECONDS | 需重启 |
| secrets.master_key | LOGIN_SECRETS_MASTER_KEY | 需重启 |
| secrets.tls_pfx_password | LOGIN_SECRETS_TLS_PFX_PASSWORD | 需重启 |

环境变量名是稳定契约，实际列表以 `login.Fields()` 返回值为准。

校验行为：

- 未知字段、重复键、类型错误、`null`、超范围值、非法组合（例如公开地址使用 `http` 却监听非回环地址、公开地址路径与 `server.path_prefix` 不一致、启用 TLS 终止代理模式却缺少 https 公开地址或可信代理）都会在加载阶段失败，不产生监听或数据库副作用。
- 监听主机只接受 IP 字面量、`localhost` 或空（所有接口），不接受任意域名；`server.extra_listen_addrs` 与主地址去重后最多 16 个。列表型环境变量用英文逗号分隔（例如 `127.0.0.1:8081,[::1]:8081`）。
- TLS 字段组合在加载阶段校验：PEM 证书/私钥必须成对且数量一致（最多 8 对）、PEM 与 PFX 互斥、PFX 必须有受保护来源密码、PFX 不能配附加 CA、未配置 PFX 时不能单独设置 PFX 密码、本地 TLS 与 `tls_terminating_proxy` 互斥、启用本地 TLS 时公开地址必须是 https、到期告警天数范围 0～365（0 表示默认 30 天）。
- 客户端证书认证（mTLS）字段组合在加载阶段校验：默认 `disabled`，关闭时不能配置客户端信任 CA 或身份映射（避免静默保留未使用的信任材料）；启用后必须同时配置本地 TLS 证书、`server.tls_client_ca_files` 与 `server.tls_client_identities`，客户端信任 CA 文件不能与服务器证书材料共用路径；身份映射的 DNS 名称必须是主机名（不接受 IP/通配符/端口），同一 DNS 名称不能映射到多个服务身份。环境变量中的身份映射写作 `dns-name=service-identity` 逗号分隔列表，例如 `LOGIN_SERVER_TLS_CLIENT_IDENTITIES=backup.internal=backup-agent,monitor.internal=monitor`。
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

在步骤 15 的监听组件上增加服务端 HTTPS 单向认证；证书材料由 `Config.Server` 显式配置，`NewServer` 在构造时完成全部加载与校验，`Start` 后监听地址提供 HTTPS。支持 PEM 证书链 + 私钥、可选附加 CA/中间证书，以及 PKCS#12/PFX 导入。客户端证书认证（mTLS）在步骤 17 单独实现，本步不启用。

- **证书材料与校验**：PEM 模式下 `server.tls_cert_files` 与 `server.tls_key_files` 一一对应（叶证书在前、中间证书依次在后），`server.tls_ca_file` 可追加共享 CA/中间证书；PFX 模式使用 `server.tls_pfx_file`，密码只能通过 `secrets.tls_pfx_password` 从受保护来源（环境变量或受保护文件）提供，不能直接写进 YAML。PFX/P12 解析使用 `software.sslmate.com/src/go-pkcs12 v0.7.4`（SSL.com 维护、纯 Go、BSD 风格许可；只用于解码，编码仅出现在测试）。加载时校验：文件格式与大小、私钥与叶证书公钥匹配、叶证书有效期与服务器认证用途、证书链签发关系与顺序（中间证书必须是 CA）、链内所有证书有效期、DNS SAN 合法且非空。
- **私钥文件保护**：PEM 私钥与 PFX 文件必须通过受保护文件检查（非 Windows 仅所有者可读写；Windows 受限 ACL）。测试证书仅生成在临时目录并使用受限权限写入，不写入项目树。
- **多域名与 SNI**：一个证书可包含多个 DNS SAN（支持 `*.example.com` 单级通配符），也可配置多个证书身份。SNI 按证书实际覆盖的名称选择；精确名称优先于通配符，未知 SNI 握手失败（返回错误而不是回退到任意证书）；没有 SNI 时使用配置顺序的第一张证书（显式记录的安全策略）。`server.public_base_url` 与 `server.allowed_hosts` 中的主机名必须被至少一张证书覆盖，否则启动配置检查失败；自签证书可以使用，但不表示客户端会自动信任，客户端必须显式信任对应 CA/证书。
- **协议与密码套件**：`tls.Config` 只设置最低 TLS 1.2，`CipherSuites`/`CurvePreferences` 留空使用 Go 标准库当前安全默认，不自行组合算法；TLS 1.1 及以下客户端握手失败。
- **安全重载**：`Server.ReloadTLS(ctx)` 重新读取全部材料并在独立快照上完整校验，成功后原子替换生效证书；任一步骤失败时保留仍在使用的旧证书、记录失败状态并告警，不中断监听或并发握手中的连接。重载按连续失败次数计数，成功清零。证书文件损坏、密码错误、私钥不符、链组织错误、证书过期等都会返回 `CONFIG_INVALID` 错误且不替换证书。
- **到期状态**：`Server.TLSStatus()` 返回加载时间、各证书 `Domains`/`NotBefore`/`NotAfter`/SHA-256 指纹/序列号/是否自签、最早到期时间、`ExpiringSoon`（`server.tls_expiry_warning_days`，范围 0～365，0 表示默认 30 天）与 `Expired`。本步只提供状态，不发送邮件/Webhook 通知，也不自动续期；后续调度/通知与证书更新流程按该状态接入，不能声称已发送告知。
- **代理边界联动**：步骤 15 审计备注已修正——内层 Handler 现在收到经过允许列表校验的有效 Host；可信代理声明的 `Forwarded`/`X-Forwarded-Proto` 必须与显式 `server.public_base_url` 协议一致，否则 fail-closed 400。
- **已验证（Windows amd64，真实 TLS 握手）**：PEM 链（根 CA→中间 CA→叶证书）加载与受信客户端握手、精确域名与通配符 SNI、未知 SNI 拒绝、TLS 1.1 拒绝、无 SNI 默认证书选择、私钥不符/畸形 PEM/非 CA 签发者/链顺序错误/重复证书/过期/未生效/缺 SAN/非法通配符拒绝、附加 CA 文件、PFX 正确与错误密码、同一 CA 重新签发后的安全重载、无效材料重载失败回退旧证书、6 路并发握手期间 8 次重载无失败、到期状态与到期告警窗口、HTTPS 真实监听下健康检查与证书主机名不匹配失败、PFX 端到端启动、非回环监听在本地 TLS 配置下允许（只构造、未真实绑定所有接口）。
- **尚未接入/未验证（步骤 16 当时状态）**：`cmd/login-server` 仍未装配 `NewServer`；客户端证书 mTLS（步骤 17 已实现）、SNI 按域名选择不同客户端信任 CA（未实现）、OCSP/CRL、证书自动续期、真实 ACME/企业 CA 流程、邮件/Webhook 到期通知、TLS 会话票据策略与 HTTP/2 专项压力测试未实现；未做 race detector、真实反向代理/LB 联调、非 Windows 运行（只编译）。

## 客户端证书双向认证与基础设施阶段验收（步骤 17）

在步骤 15～16 的监听、代理边界与服务器 TLS 之上增加可选的客户端证书双向认证（mTLS）；mTLS 默认关闭，基础设施能力仍不包含账户、登录与授权，不是可生产使用的身份系统。

- **三种明确模式**：`server.tls_client_auth` 取 `disabled`（默认，不请求客户端证书）、`required`（必须出示并验证客户端证书）或 `optional`（允许匿名连接，但一旦出示证书必须完整有效且已映射）。实现只使用 Go 的 `RequireAndVerifyClientCert` 与 `VerifyClientCertIfGiven`，不使用 `RequestClientCert`/`RequireAnyClientCert` 这类不验证证书的模式；可选模式下出示错误 CA、过期或未映射证书会直接握手失败，不会降级为已认证或匿名。
- **独立的客户端信任 CA**：`server.tls_client_ca_files` 是独立的客户端信任锚 PEM 文件列表（最多 8 个），与 `server.tls_ca_file` 服务器证书链完全分开：配置路径不能共用，加载后证书 DER 也不能与服务器证书链重叠（`ReloadTLS` 更换服务器证书时同样复验）。每个信任锚必须是当前有效、具备证书签发能力的 CA 证书；普通叶证书、包含私钥块的文件、重复 CA 与过期 CA 都会被拒绝。客户端证书链只在这组 CA 下验证，不使用服务器 TLS 字段或系统根证书；客户端需要随证书发送完整的中间证书链（由标准库验证），证书有效期与客户端认证用途在握手时校验。信任锚在运行中到期后，新握手会因链验证失败而默认拒绝，直到轮换 CA 并重启。
- **显式身份映射**：`server.tls_client_identities` 是“客户端叶证书 DNS SAN -> 可信服务身份”的显式映射（最多 32 条，YAML 为 `dns_name`/`service` 对象列表）。客户端证书必须包含某个已映射的 DNS 名称（精确匹配，不区分大小写，忽略结尾根域点），并且服务身份必须是稳定的小写 ASCII 标识符。仅有受信任 CA 签发不足以获准接入：未映射证书即使链有效也握手失败；同一证书命中多个不同服务身份时按歧义拒绝。映射结果通过 `login.ClientServiceIdentityFromContext` 以只读方式提供给 Handler，它不携带 root、系统资格或任何业务权限，不能替代服务层授权。
- **撤销、信任更新与已建立连接**：第一版不实现 OCSP/CRL 在线撤销。撤销一条客户端身份的方法是移除或修改 `server.tls_client_identities` 映射，轮换信任 CA 则是替换 `server.tls_client_ca_files`；两者都必须重启进程才能生效，`Server.ReloadTLS` 只重载服务器证书，不重载客户端信任配置。已建立的 TLS 连接在握手时完成一次客户端证书验证，运行期不会按请求重新校验；进程重启会关闭已有连接。TLS 1.3 会话恢复连接也不会重新发送客户端证书，但服务端会对会话中保存的已验证证书重新做链有效期与身份映射检查。
- **脱敏状态诊断**：`Server.TLSStatus().ClientAuth` 返回模式、客户端信任 CA 的主题/有效期/SHA-256 指纹/是否自签，以及生效中的身份映射；`Config.Diagnostic()` 输出 mTLS 模式、信任 CA 路径与映射，秘密仍只显示 `[REDACTED]`/`[UNSET]`。两种输出都不包含私钥、PFX 密码或证书内容。
- **嵌入式模式边界**：mTLS 只由 `login.NewServer` 的 TLS 监听建立；直接使用 `login.NewHTTPHandler` 并由宿主自行终止 TLS 时，宿主需要提供等价边界，本库不会凭空建立客户端身份。
- **已验证（Windows amd64，真实 TLS 握手）**：`required` 模式下正确映射证书可完成 HTTPS 请求并在 Handler 中读到映射身份；无证书、错误 CA、过期证书、用途错误（仅服务器认证）、未映射身份、多身份歧义证书全部握手失败；`optional` 模式下无证书匿名成功、映射证书成功、错误 CA/过期/未映射证书失败（不降级）；`disabled` 模式不请求也不接收客户端证书；服务器证书 `ReloadTLS` 轮换后客户端认证策略与身份映射保持不变，运行中直接改写客户端信任 CA 文件不生效；移除身份映射后重启（新实例）旧证书被拒绝；端口在 `Close` 后释放、已建立连接被关闭；YAML 配置加载到 mTLS 监听端到端通过；内部 `internal/tlscert` 用真实回环 TLS 覆盖 TLS 1.2/1.3 全部分支，并验证 TLS 1.3 会话恢复仍执行身份映射复查。基础设施阶段验收记录见 [docs/acceptance/基础设施阶段验收记录.md](docs/acceptance/基础设施阶段验收记录.md)。
- **尚未接入/未验证**：`cmd/login-server` 仍未装配 `NewServer`；客户端信任热重载、OCSP/CRL、供客户端证书身份使用的服务层授权映射、按 SNI 区分客户端信任 CA、真实企业 CA/ACME 流程、邮件/Webhook 到期通知、TLS 会话票据策略、HTTP/2 专项、race detector、真实反向代理/LB 联调与非 Windows 运行（只编译）仍未实现。

## 普通账户创建、查询与用户名规则（步骤 18）

新增内部账户领域服务 `internal/account` 与 SQLite 生产仓储 `internal/account/sqlite`：完成普通用户的创建、按稳定 ID 查询和有限分页检索，暂不实现密码登录、公开自主注册或 HTTP 端点。表结构使用既有迁移 0001 的 `users` 表，本步未新增迁移，也未对 `database/login.db` 执行任何操作。

- **稳定 ID 与用户名分离**：用户 ID 由服务用 `crypto/rand` 生成 `usr_` + 128 位随机数，创建后不可变；`username` 保存显示值（NFKC 兼容规范化后保留大小写），`username_normalized` 保存唯一性判定值（NFKC + Unicode 大小写折叠 + NFC）。唯一约束由数据库 `UNIQUE(username_normalized)` 保证，并发重名由事务 + `ON CONFLICT DO NOTHING` 统一映射为 `CONFLICT`，不覆盖已有用户。
- **用户名规则（稳定契约）**：先做 NFKC 兼容规范化并去掉首尾空白；长度 3～32 个码点；只允许 Unicode 字母、数字与 `.` `_` `-`，首尾必须是字母或数字；拒绝内部空白、控制/格式字符（含零宽与双向控制）、其他符号与表情；大小写折叠后比较保留名（`root`、`admin`、`system`、`管理员`、`客服` 等，见 `account.ReservedUsernames()`）。全角 `Ａlice`、`Straße`/`STRASSE` 等按规范化值判重。
- **资料白名单**：创建请求只有 `Username`/`Nickname`/`Biography`/`Language`/`Timezone`；没有 `is_root`、`status`、`security_version`、已验证标记等字段。昵称 ≤64 码点、简介 ≤1000 码点（允许换行/制表符），语言使用 BCP 47 子集并默认 `zh-CN`，时区必须是可识别的 IANA 名称并默认 `Asia/Shanghai`。本地初始化创建状态固定为 `active`，`is_root=0`、`security_version=1` 使用默认值。
- **查询与分页**：`GetUser` 只接受固定格式用户 ID；`ListUsers` 支持 `Limit`（默认 20，最大 100）、`Offset`（最大 1,000,000）、状态过滤与白名单排序（创建/更新时间、规范化用户名、ID）；排序始终追加 `id` 作为稳定次序键，拒绝任意 SQL 列、无上限列表与未知状态。不返回总条数，只用 `HasMore` 表示后续页。
- **审计与权限默认拒绝**：创建使用 `audit.ExecuteCritical`，用户插入与成功审计在同一事务提交；审计失败回滚且不返回成功，错误映射 `AUDIT_WRITE_FAILED`。按 ID 查询与列表查询也写审计，审计失败时拒绝返回数据。调用者只能通过 `LocalBootstrapCaller`/`SystemCaller` 构造；实际授权模块未就绪，本步只提供 `LocalBootstrapAuthorizer`（显式本地操作者白名单），生产 HTTP/远程调用没有默认放行路径。
- **错误映射**：使用已登记错误码，不新增码：非法用户名/资料/分页/排序/ID 与用户不存在映射 `REQ_INVALID(400)`，用户名重复映射 `CONFLICT(409)`，未授权 `ACCESS_DENIED(403)`，存储不可用 `DB_UNAVAILABLE(503)`，审计失败 `AUDIT_WRITE_FAILED(503)`，未知错误 `INTERNAL_ERROR(500)`；创建失败时失败审计的错误码按真实失败类别记录（冲突 CONFLICT、存储 DB_UNAVAILABLE、审计 AUDIT_WRITE_FAILED、内部 INTERNAL_ERROR），根包测试核对字面值与注册表一致。
- **依赖**：Unicode NFKC 规范化与大小写折叠使用 `golang.org/x/text v0.44.0`（Go 1.26 兼容、无额外运行时依赖）；未升级既有 `x/sys`。
- **已验证（Windows amd64，临时 SQLite）**：正常创建与数据库敏感列默认值、显示/规范化用户名分离、全角/大小写/`ß` 与保留名规则、资料白名单与文本伪装、大小写重名、6 路并发重名仅 1 成功、分页/偏移/排序/状态过滤与非法参数、按 ID 查询与不存在、授权默认拒绝、审计成功/失败（触发器注入）与失败回滚、日志不输出用户名/资料正文；六目标编译与交叉 vet 在 MEMORY 记录。
- **尚未实现/未验证**：HTTP/服务启动接入、密码登录/注册/邀请、邮箱与电话字段、头像与扩展资料、应用内成员禁用（全局启用/禁用/删除已在步骤 19 实现，但尚未接 HTTP/服务启动）、实际权限模型、用户列表的管理范围隔离、Unicode 同形字/混淆字符骨架检测、用户名保留名国际化扩展、多进程/高并发与非 Windows 运行；race detector 与长期压力测试未做。

## 账户状态变更、启用禁用与删除流程（步骤 19）

在步骤 18 的账户领域服务上增加全局账户状态生命周期与明确删除流程；继续使用既有 `users` 表（`status`/`row_version`/`security_version` 列），本步未新增迁移。会话、OAuth 令牌等模块尚未实现，本步只定义并写可靠审计事件/security_version 失效契约，不提供假会话接口。

- **状态机**：允许 `pending`/`active` -> `disabled`（禁用）、`disabled` -> `active`（启用）、`pending`/`active`/`disabled` -> `pending_delete`（请求删除）；`pending_delete` 不能再启用或禁用，只能完成删除；`active` 重复启用、`disabled` 重复禁用、`pending_delete` 重复请求删除都按幂等成功处理（`Changed=false`，不改版本，仍写一条成功审计便于追查）。未知命令与非法转换映射 `CONFLICT(409)`。
- **row_version 与 security_version**：所有实际状态变更要求调用方传入读取到的 `row_version`，SQL 条件更新 `WHERE status=? AND row_version=? AND is_root=0`，并发修改时只有一个生效，其余返回 `CONFLICT`。禁用与请求删除各递增 `security_version`；启用**不递减**安全版本，旧会话/令牌（未来模块）不能因解禁而恢复。完成删除直接移除用户行，`user.delete.request`/`user.delete.complete` 审计事件与安全版本递增是未来会话/令牌模块必须消费的失效依据（目前没有会话表，未实现撤销逻辑）。
- **受保护账户**：`is_root=1` 的账户不能通过普通管理流程禁用、请求删除或完成删除，返回 `ACCESS_DENIED(403)`；root 唯一约束仍由数据库保证，root 的受控创建与应急流程留给步骤 28，本步不提供任何初始化解禁或用例替身。操作者身份仍要求显式 `Authorizer`（仅 `LocalBootstrapAuthorizer` 受限本地初始化通道），未授权操作者返回 `ACCESS_DENIED`。
- **删除影响与关联策略**：`PreviewDeletion` 返回应用成员关系、角色分配、用户组关系、一次性凭证与名下应用数量，供不可逆删除前确认。完成删除在一个审计事务中：删除一次性凭证、应用成员关系、角色分配、用户组成员关系与 `users` 行；`applications.owner_user_id` 由外键置空、应用记录保留；安全审计历史保留脱敏快照。**全局账户禁用不修改应用成员关系**，应用内禁用属应用范围策略，两者分开。
- **一致性与失败回滚**：所有状态变更与完成删除使用 `audit.ExecuteCritical`，变更与成功审计同事务提交；审计失败整体回滚并返回 `AUDIT_WRITE_FAILED`。删除循环任一步失败（例如关联表触发器故障）整体回滚，用户仍为 `pending_delete`，失败审计按真实错误类别记录（DB_UNAVAILABLE 等），不会留下“用户已删但关联残留”或虚假成功。
- **错误映射**：继续使用已登记码，不新增码：非法 ID/版本/命令 `REQ_INVALID(400)`；非法状态切换与并发冲突 `CONFLICT(409)`；root/未授权 `ACCESS_DENIED(403)`；存储 `DB_UNAVAILABLE(503)`；审计 `AUDIT_WRITE_FAILED(503)`；未知 `INTERNAL_ERROR(500)`。根包测试核对字面值与注册表一致。
- **已验证（Windows amd64，临时 SQLite）**：禁用/启用/待删除状态与版本递增、重复请求幂等、非法转换、旧 row_version 冲突、4 路并发禁用仅一次生效且安全版本只增一次、root 受保护、删除预览计数、全局禁用不影响应用成员关系、完成删除清理凭证/成员/角色/组并保留应用与审计、owner 置空、重复完成返回不存在、关联删除触发器故障整体回滚且失败审计错误码正确、审计故障时状态变更/预览 fail-closed、未授权操作者拒绝；六目标编译与交叉 vet 在 MEMORY 记录。
- **尚未实现/未验证**：HTTP/`cmd/login-server` 接入、真实会话/令牌撤销（当前仅有 security_version 与审计事件契约）、密码登录与注册、应用内成员禁用流程、批量导入导出、root 受控初始化（步骤 28）、完整权限模型、删除审批/回收站/保留期限策略；未做 race detector、多进程并发与非 Windows 运行。

## 应用登记、资料管理与启停（步骤 20）

新增内部应用领域服务 `internal/app` 与 SQLite 生产仓储 `internal/app/sqlite`：完成应用登记、按应用 ID 读取、有限分页、展示资料更新与启停，并在同一审计事务中创建唯一应用作用范围。继续使用迁移 0001 的 `applications`/`scopes` 表，本步未新增迁移，也未操作 `database/login.db`。

- **ID 与作用范围一致性**：应用 ID 由服务用 `crypto/rand` 生成 `app_` + 128 位随机数，创建后不可变；创建请求不能指定 ID。创建时在同一 `audit.ExecuteCritical` 事务中写入 `applications` 行与 `scopes(id=应用 ID, kind='application', app_id=应用 ID)`，任一步失败整体回滚；读取时若应用缺少对应 scope 或 ID 不一致，按存储不一致拒绝（不返回半状态）。scope ID 约定与应用 ID 相同（1:1、稳定映射）。
- **资料白名单与规则**：创建接受名称、描述、图标引用、主页、负责人、联系方式与客户端类型；更新只接受名称/描述/图标引用/主页/负责人/联系方式，**不能修改应用 ID、client_type、status、scope**。名称 1～64 码点（单行）、描述 ≤1000 码点、联系方式 ≤256 码点单行；主页只接受 http/https 绝对 URL（不允许用户信息、空白/控制字符，验证主机）；图标引用只能是受控相对存储引用（禁止绝对路径、URL、反斜杠、`..`）。客户端类型只在创建时确定，OAuth 凭证/回调等可信客户端配置不在本步。
- **权限默认拒绝**：调用者必须来自可信构造器（本地初始化/系统/用户）并通过 `StaticAuthorizer` 显式白名单：本地管理员与显式系统操作者可管理全部应用；应用管理员只能读取/更新/启停被显式分配的应用，不能创建应用，列表自动限定为已分配应用；负责人变更只有系统/本地管理员可执行，且不会自动给学生成新的应用管理员资格。权限引擎未完成前不开放 HTTP/管理端点。
- **负责人与联系方式**：负责人必须是存在且 `active` 的账户（`applications.owner_user_id` 外键另有保护）；负责人变化只改 owner_user_id，不转移角色/权限/管理员分配。联系方式变更在审计明细中以 `[REDACTED]` 记录，运行日志不输出完整联系信息。
- **启停语义**：创建默认 `disabled`，启停通过独立命令变更（`active`/`disabled`），不提供删除；重复启停幂等成功，实际变更要求当前 `row_version` 且条件 UPDATE，冲突映射 `CONFLICT(409)`。停用不会删除应用或作用范围，依赖方必须检查应用状态；本步写入可靠审计事件，令牌/会话模块以后消费该失效信号（当前未实现令牌，不声称撤销完成）。应用删除会级联 scope/角色/成员关系，需要后续步骤先定义审计保留与数据策略，本步明确不提供，停用不等于删除。
- **一致性与错误**：创建/更新/启停使用 `audit.ExecuteCritical`，业务变更与成功审计同事务；审计失败整体回滚并返回 `AUDIT_WRITE_FAILED`。读取/列表写审计，审计失败拒绝返回数据。错误映射到已登记码：参数/应用不存在 `REQ_INVALID(400)`、状态/并发冲突 `CONFLICT(409)`、未授权 `ACCESS_DENIED(403)`、存储 `DB_UNAVAILABLE(503)`、审计 `AUDIT_WRITE_FAILED(503)`、未知 `INTERNAL_ERROR(500)`；根包测试核对字面值与注册表一致。失败审计错误码按实际错误映射（复用步骤 18 `FailureErrorCodeFor`）。
- **已验证（Windows amd64，临时 SQLite）**：登记与 scope 一致、scope 写入故障整体回滚与失败审计、字段/URL/图标规则、ID/client_type/scope 不可变、系统更新资料与负责人、应用管理员普通资料更新与改负责人拒绝、新负责人不自动获得管理权限、启停可见性/幂等/旧版本冲突/4 路并发启停仅一次生效、列表分页与排序边界、应用管理员列表/读取范围隔离、无分配用户列表为空、创建权限拒绝、审计故障 fail-closed、错误码映射；六目标编译与交叉 vet 在 MEMORY 记录。
- **尚未实现/未验证**：应用删除、OAuth 客户端凭证/回调/授权端点、Web 页面、HTTP/`cmd/login-server` 接入、完整权限引擎/app 管理员分配持久化（当前 `StaticAuthorizer` 内存配置）、应用成员管理（步骤 21 已实现基础能力）、负责人转移后的权限迁移策略、审计查询；未做 race detector、多进程并发与非 Windows 运行。

## 应用成员管理与应用内资料隔离（步骤 21）

在步骤 20 的应用领域上增加应用成员关系与应用专属资料：成员增删改查按应用隔离，加入既有账户必须受控授权，应用内禁用/移除不影响全局账户或其他应用。继续使用迁移 0001 的 `app_memberships` 表（`app_id`+`user_id` 唯一键、`status`、`profile_json`、`row_version`），本步未新增迁移，也未操作 `database/login.db`。

- **应用隔离键**：所有成员持久化操作都以 `(application_id,user_id)` 为范围，查询/列表/更新/删除的 SQL 都带应用 ID；应用 ID 与用户 ID 只接受服务生成的固定格式。仓储不提供跨应用读取接口，服务层每个操作先通过 `Authorizer` 按被操作应用判权。
- **受控加入既有账户**：`AddApplicationMember` 只接受稳定用户 ID（不接受用户名、邮箱或自助加入标记），要求调用者是本地管理员、系统操作者或该应用被显式分配的应用管理员；知道用户名/邮箱不能被用来认领账户。目标应用必须 `active`，目标账户必须存在且 `active`；重复加入返回 `CONFLICT` 且不覆盖已有成员资料。
- **应用内状态**：成员状态只有 `active`/`disabled`。应用内禁用/启用/移除只改 `app_memberships` 中该应用的一行；不会修改 `users.status` 或同一用户在其他应用中的成员关系。成员状态与全局账户状态共同检查：启用成员与更新应用资料要求应用与账户均 `active`；停用/移除属于安全清理，允许在应用停用或账户非 active 时执行。
- **应用专属资料**：`profile_json` 只含白名单字段（应用内显示名 ≤64 码点、职位 ≤64、备注 ≤500），单行字段拒绝换行/控制/格式字符，备注允许换行；存储为带版本号的规范 JSON，读取时拒绝未知版本、未知字段、未规范化值与异常 JSON（fail-closed）。资料更新只写该应用行，不写全局账户资料，也不影响其他应用。
- **并发与事务**：加入使用唯一主键 + `ON CONFLICT DO NOTHING`，重复/并发加入只有一个成功；资料更新、启停、移除使用 `row_version` 条件更新，并发只允许一个生效，其余返回 `CONFLICT`；所有关键变更在 `audit.ExecuteCritical` 事务中与成功审计一致提交，失败审计按真实错误类别映射（如重复加入 `CONFLICT`、存储故障 `DB_UNAVAILABLE`、审计故障 `AUDIT_WRITE_FAILED`）。
- **审计与失效契约**：审计记录操作者、`app_id_snapshot`、目标用户与动作：`application.member.add`/`get`/`list`/`profile.update`/`enable`/`disable`/`remove`；资料差异只记录字段名并脱敏为 `[REDACTED]`，不写应用内资料正文。成员移除/停用与应用停用事件是未来会话/令牌模块的失效信号，模块还必须在每次授权时读取当前成员状态；当前没有会话/令牌实现，本步不提供假撤销接口，也不声称全链路撤销已完成。
- **权限边界**：成员关系本身不授予任何业务功能；应用内角色、用户组与权限分配仍待后续步骤，加入应用不等于获得全部业务功能。应用管理员只能管理已显式分配应用的成员。
- **错误映射**：不新增错误码：非法 ID/分页/资料/版本、应用或成员不存在 `REQ_INVALID(400)`；重复加入、并发冲突 `CONFLICT(409)`；未授权 `ACCESS_DENIED(403)`；应用停用 `CLIENT_DISABLED(403)`；目标账户不可用 `USER_DISABLED(403)`；存储 `DB_UNAVAILABLE(503)`；审计 `AUDIT_WRITE_FAILED(503)`；未知 `INTERNAL_ERROR(500)`。根包测试核对字面值与注册表。
- **已验证（Windows amd64，临时 SQLite）**：同一用户加入两个应用时应用专属资料与状态互不影响、更新/移除不写全局资料；应用管理员只能操作被分配应用（读取/列表/加入/更新/启停/移除跨应用全部拒绝）、无分配用户与未授权用户拒绝、本地/系统操作者可管理；应用停用后加入/启用/资料更新拒绝而停用/移除允许；全局禁用账户加入/启用/资料更新拒绝而停用/移除允许；重复加入 CONFLICT 且保留首次资料；4 路并发加入/资料更新/移除只有一个成功终态、成功与失败审计数量一致、移除审计保留应用与目标用户；异常 profile_json 读取 fail-closed、审计故障整体回滚、存储故障失败审计错误码正确；六目标编译与交叉 vet 在 MEMORY 记录。
- **尚未实现/未验证**：应用成员 HTTP/`cmd/login-server` 接入、真实会话/令牌撤销（当前只有审计事件与“授权时复查成员状态”契约）、应用内角色/用户组/权限分配、邀请/注册加入流程、批量成员导入导出、应用删除时成员级联策略、成员状态历史与审计查询；未做 race detector、多进程并发与非 Windows 运行。

## 用户组与组成员管理（步骤 22）

新增内部用户组领域服务 `internal/group` 与 SQLite 生产仓储 `internal/group/sqlite`：完成系统范围与应用范围的用户组 CRUD、组成员批量加入/移除/分页，不提前实现角色分配。继续使用迁移 0001 的 `user_groups`/`group_members`（以及未来 `group_roles`）表，本步未新增迁移，也未操作 `database/login.db`。

- **稳定标识与范围不可变**：组 ID 由 `crypto/rand` 生成 `grp_`+128 位随机数；`group_key` 是稳定机器键（2～64 字节小写字母/数字与 `._-`，同 scope 唯一），创建后不可修改；显示名称与说明可修改，但更新请求不包含 scope/group_key，因此作用范围不能悄悄转移（测试核对数据库 scope/key 不变）。系统范围固定 scope `system`；应用范围 scope ID 与应用 ID 相同，组创建时要求应用存在且启用。表中没有组状态列：组在存在期间即为有效，删除即硬删除组记录；不提供停用/回收站。
- **作用域隔离与资格**：系统组只能由显式本地/系统操作者管理，应用管理员不能管理系统组；应用组只能由本地/系统操作者或该应用显式分配的应用管理员管理，跨应用读写/创建一律 `ACCESS_DENIED`。调用者只来自可信构造器，请求参数不能自称管理员或 scope。
- **成员资格**：应用组成员必须是全局 `active` 账户且在该应用具有 `app_memberships.status='active'`，应用停用后拒绝创建组/加入成员；系统组只要求全局 `active`。应用成员被停用/移除后不会自动删除既有组关系，但后续权限计算必须联合检查成员与组状态（当前角色模块未实现）。删除组不删除用户。
- **批量操作语义**：单次批量加入/移除最多 12 人，采用全有或全无审计事务；任一目标不合格/资格变化/审计失败则整批回滚，不返回部分成功。请求内重复用户 ID 去重；已存在（加入）或不存在（移除）的成员计入 `Skipped` 并幂等成功；审计逐个记录目标用户（`member_1`…）与 added/removed/skipped 统计。
- **变更与失效事件**：组成员加入/移除、组创建/资料修改/删除全部走 `audit.ExecuteCritical`，业务变更与成功审计同事务，审计失败返回 `AUDIT_WRITE_FAILED` 并回滚。组成员变更是未来权限来源，审计事件是角色/权限模块接入后必须消费以重新计算并失效有效权限的可靠信号；本步未实现角色分配、令牌/会话撤销或权限引擎，不声称权限失效全链路已完成。组名称/说明不推断权限，没有隐式超级组。
- **删除组**：硬删除 `user_groups` 行，`group_members` 与未来 `group_roles` 关联由外键级联删除；用户账户、应用与安全审计历史保留。删除/并发删除返回 `ErrGroupNotFound`，不假装成功。
- **错误映射**：继续使用已登记码，不新增码：参数/组不存在/范围无效 `REQ_INVALID(400)`；组键重复/并发冲突 `CONFLICT(409)`；未授权 `ACCESS_DENIED(403)`；应用停用 `CLIENT_DISABLED(403)`、目标账户/应用成员资格不可用 `USER_DISABLED(403)`（与 `internal/app` 同族语义）；存储 `DB_UNAVAILABLE(503)`；审计 `AUDIT_WRITE_FAILED(503)`；未知 `INTERNAL_ERROR(500)`。
- **已验证（Windows amd64，临时 SQLite）**：组 CRUD 与同 scope 组键唯一、跨 scope 同 key/同名允许、scope/group_key 更新不变；系统组/应用组权限隔离；应用组跨应用成员与停用成员/全局停用账户拒绝；应用停用后拒绝建组与加入但允许移除；批量上限/空列表/重复去重；混合不合格整批回滚；并发重复加入最终仅一条成员；移除幂等与分页；**列表空 ScopeID 默认用法（系统/本地管理员/应用管理员）、范围过滤、分页与 HasMore、无分配用户空列表**；读取组先按可管理范围鉴权再读完整记录；审计故障 fail-closed；删除组级联成员/组角色且不删用户/审计；错误码与根包注册表一致（含 CLIENT_DISABLED/USER_DISABLED）；六目标编译与交叉 vet 在 MEMORY 记录。
- **尚未实现/未验证**：角色分配、组角色权限、嵌套组（数据库无嵌套结构，本步明确不支持，因而无环路/深度传播问题）、系统/应用权限引擎持久化（`StaticAuthorizer` 内存白名单）、组成员变更触发的真实令牌/会话失效、HTTP/`cmd/login-server` 接入、审计查询；未做 race detector、多进程并发与非 Windows 运行。

## 权限目录（步骤 23）

新增内部权限目录服务 `internal/permission` 与 SQLite 生产仓储 `internal/permission/sqlite`：实现系统内置、系统自定义与应用独有权限的登记、读取、分页、资料更新、启停与受引用保护的删除，不提前实现角色分配或授权执行。继续使用迁移 0001 的 `permissions`/`role_permissions` 表，本步未新增迁移，也未操作 `database/login.db`。

- **定位与隔离**：权限以 `(scope_id, permission_key)` 共同唯一定位；系统 scope 固定 `system`，应用 scope ID 与应用 ID 相同。不同应用可有同名机器标识但互不串用；跨作用范围的读取/更新/启停/删除一律 `ACCESS_DENIED`，应用管理员不会看到系统权限或其他应用权限。
- **三类权限**：系统内置（scope=system、is_builtin=1，只能由本地/系统操作者登记）、系统自定义（scope=system、is_builtin=0）、应用独有（scope=应用 ID、is_builtin=0）。应用管理员只能登记/管理被分配应用的权限，不能创建系统权限、不能创建 builtin 或 root_only 权限，不能提升系统资格。
- **内置权限保护**：内置权限的机器标识、名称、说明、限制、root_only 语义不可修改、不可删除；只能启用/停用。`root_only` 敏感权限（内置或系统自定义）只能由受限本地初始化操作者启停，停用是拒绝操作而不是跳过检查。内置权限登记/启停均写可靠审计。
- **自定义权限**：直白名称、说明、明确限制可修改；`permission_key`、scope、builtin/root_only 不在更新请求中，因此机器标识不可变。机器标识变更必须新增权限并显式迁移引用；本步不提供隐式改名/迁移接口。
- **机器可读定义**：`Permission.Definition()` 返回 key、分组（机器标识首段）、scope/scope_kind、生效对象（system 或 application:<appID>）、直白名称、说明、明确限制、默认启用值、敏感（root_only）、builtin 与当前 enabled，供前端目录、审计和后续授权模块使用。新建权限默认 enabled=true；登记不代表创建者获得该权限。
- **字段与命名边界**：机器标识 3～128 字节、2～4 个点号分段、小写字母/数字/下划线且每段字母开头；名称 1～64 码点单行，说明 1～500 码点，限制说明 1～1000 码点；拒绝控制/格式字符与空值。
- **启停与删除**：启停幂等（重复请求 Changed=false 且仍写成功审计），实际变更写审计事务；停用后依赖方必须把该权限视为拒绝，但本步不执行授权，不能声称已撤销既有角色授权。删除自定义权限前检查 `role_permissions` 引用，有引用返回 `CONFLICT` 并拒绝；删除使用条件事务，避免并发引用被隐式级联删除。内置权限不可删除；审计历史保留。
- **错误映射**：不新增错误码：参数/不存在/scope 无效 `REQ_INVALID(400)`；机器标识冲突/引用冲突/状态冲突 `CONFLICT(409)`；未授权/内置保护 `ACCESS_DENIED(403)`；应用停用 `CLIENT_DISABLED(403)`；存储 `DB_UNAVAILABLE(503)`；审计 `AUDIT_WRITE_FAILED(503)`；未知 `INTERNAL_ERROR(500)`。
- **已验证（Windows amd64，临时 SQLite）**：三类权限登记与机器可读定义完整性；同名跨应用/跨 scope 隔离；应用管理员创建系统/内置/root_only 权限拒绝；内置权限更新/删除拒绝、启停幂等、root_only 仅本地操作者；自定义资料更新不改 key/scope；启停状态可见；被角色引用拒绝删除、解除后可删；并发同名创建仅一次成功其余 CONFLICT；列表默认/范围过滤/分页/HasMore/enabled 过滤；读取先鉴权后读；审计故障 fail-closed；错误码与根包注册表一致（含 CLIENT_DISABLED）；六目标编译与交叉 vet 在 MEMORY 记录。
- **尚未实现/未验证**：角色与 role_permissions 分配（步骤 24 已实现基础能力，有效权限推导/授权执行仍未实现）、权限删除后的角色引用迁移工具、权限目录 HTTP/`cmd/login-server` 接入、预设权限目录批量导入、权限定义版本化/变更审批；`StaticAuthorizer` 为内存白名单；未做 race detector、多进程并发与非 Windows 运行。

## 角色管理、权限组合与角色分配（步骤 24）

新增内部角色领域服务 `internal/role` 与 SQLite 生产仓储 `internal/role/sqlite`：完成系统/应用角色的增删改查、角色权限组合，以及角色到用户和用户组的分配，不提前实现有效权限推导、授权执行或可转授权限限制。继续使用迁移 0001 的 `roles`/`role_permissions`/`user_roles`/`group_roles` 表，本步未新增迁移，也未操作 `database/login.db`。

- **角色标识与范围**：角色 ID 由 `crypto/rand` 生成 `role_`+128 位随机数；`role_key` 是稳定机器标识（2～64 字节小写字母/数字与 `._-`，必须含字母、首尾为字母数字、同 scope 唯一），创建后不可修改；名称/说明/明确限制可修改，但更新请求不含 scope/role_key。系统 scope 固定 `system`，应用 scope ID 与应用 ID 相同；跨作用范围读取/更新/启停/删除一律 `ACCESS_DENIED`。
- **root 边界**：角色机器标识的任何分段都不能是 `root`（拒绝 `root`、`root.admin`、`system_root` 等），角色组合拒绝 `root_only` 敏感权限，root 账户不能作为普通角色分配目标，含 root 账户的用户组也不能分配普通角色（分配时检查组成员）。因此普通角色创建/组合/分配不能产生 root 能力。root 的特殊初始化/应急通道仍留后续受控步骤，本步不提供任何 root 用例替身。**残余路径**：若在角色已分配给某用户组之后，再由组模块把 root 账户加入该组，当前 `internal/group` 不知道角色分配，需步骤 25/26 或组模块接入时补充阻止/清理规则；本步不声称已完全封堵所有间接路径。
- **角色权限组合**：只能加入同一 scope、存在、当前启用且非 root_only 的权限；跨范围返回 `APP_SCOPE_MISMATCH`，停用/不存在返回 `REQ_INVALID`，root_only 返回 `ACCESS_DENIED`。重复组合幂等成功（Changed=false），并发由 `(role_id,permission_id)` 主键保证只有一行；权限在组合后被停用时组合关系保留，后续有效权限计算必须按当前 enabled/角色 enabled 过滤，不能把存在组合当作已授权。
- **角色分配资格**：系统角色只能分配给 `active` 且非 root 的全局账户，或系统范围用户组；应用角色只能分配给该应用 `active` 成员（应用需启用且 `app_memberships.status='active'`）或同一应用范围的用户组。应用之间、系统与应用之间的角色/组串用返回 `APP_SCOPE_MISMATCH`；非成员返回 `APP_MEMBERSHIP_REQUIRED`；账户不可用 `USER_DISABLED`，应用停用 `CLIENT_DISABLED`，角色停用时拒绝新分配（`CONFLICT`）。
- **并发、幂等与撤回**：重复/并发分配、重复组合、重复撤回均幂等（Changed=false，仍写成功审计），并发唯一键保证单行；角色启停使用 `WHERE id=? AND enabled=?` 条件更新，并发只有一个实际变更，其余 `CONFLICT`；撤回用于安全清理，即使角色/应用/账户已停用也允许执行，不修改用户/应用/成员状态。
- **删除与引用**：内置角色标识/含义不可修改、不可删除，只能启停；删除自定义角色前检查 `role_permissions`、`user_roles`、`group_roles` 引用，任一存在返回 `CONFLICT`；删除使用同一事务条件 `NOT EXISTS`，避免并发引用被隐式级联删除。审计历史保留。
- **审计与失效契约**：创建/资料更新/启停/删除/权限组合/分配/撤回全部走 `audit.ExecuteCritical`，业务变更与成功审计同事务，审计失败整体回滚返回 `AUDIT_WRITE_FAILED`；读取与列表写审计，失败拒绝返回。审计记录操作者、`app_id_snapshot`、角色目标、用户/用户组/权限 ID 与差异；组分配操作者记录在审计事件（`group_roles` 表无 assigned_by 列）。角色/分配变化是有效权限的来源，步骤 25 权限引擎必须每次读取当前角色/权限/分配状态，本步不声称权限失效全链路完成。
- **临时委派边界（步骤 26 收口）**：本步没有可转授权限与委派范围模型。应用管理员可以在被分配应用内组合任意该应用已启用（非 root_only）的权限成角色，并分配给该应用有效成员（包括自己）；系统范围与 root_only 受保护，但不能据此宣称已实现“只能转授自己持有的能力”。步骤 25 有效权限推导、步骤 26 委派限制必须对角色编辑、赋角色以及后续组员调整统一收紧，本边界已在 MEMORY 记录。
- **错误映射**：不新增错误码：非法 ID/分页/资料/版本、角色/权限/用户/用户组不存在 `REQ_INVALID(400)`；机器标识冲突/引用冲突/角色停用/并发冲突 `CONFLICT(409)`；未授权/内置保护/root_only/root 保护 `ACCESS_DENIED(403)`；跨作用范围 `APP_SCOPE_MISMATCH(403)`；非应用成员 `APP_MEMBERSHIP_REQUIRED(403)`；应用停用 `CLIENT_DISABLED(403)`；账户不可用 `USER_DISABLED(403)`；存储 `DB_UNAVAILABLE(503)`；审计 `AUDIT_WRITE_FAILED(503)`；未知 `INTERNAL_ERROR(500)`。
- **已验证（Windows amd64，临时 SQLite）**：角色创建/读取/分页/过滤；同 scope 键唯一与跨 scope 同名允许；root 语义键、非法字段、停用应用、应用内置角色与跨范围创建拒绝；资料更新不改 key/scope，内置角色更新/删除拒绝；启停幂等与状态可见；权限组合同范围成功、重复幂等、跨范围/停用/不存在/root_only 拒绝、移除幂等、权限组合后被停用仍可见 enabled=false；用户分配 active 账户成功、root/停用/待删除/不存在账户拒绝、应用角色非成员/停用成员/停用应用拒绝、重复分配幂等、撤回幂等且停用状态下可清理；用户组分配系统/同应用成功、跨范围与停用应用拒绝、重复/撤回幂等；有权限/用户/组引用删除拒绝、解除后可删、内置保护；缺少授权器不构造、拒绝策略不放行、应用管理员跨范围全部拒绝；4 路并发创建/组合/分配/启停/删除单一终态；审计故障 fail-closed、失败审计错误码与角色目标/操作者记录正确；错误码与根包注册表一致；六目标编译与交叉 vet 在 MEMORY 记录。
- **尚未实现/未验证**：有效权限推导与 all/any、授权执行/令牌联合校验、可转授权限与委派范围限制（步骤 25/26）、角色权限批量替换接口、数据范围 `data_scope_json`（当前固定 `{}`）、预设角色目录与恢复、成员/组变更自动重算或缓存失效、HTTP/`cmd/login-server` 接入、审计查询；`StaticAuthorizer` 仍是内存白名单；未做 race detector、多进程并发与非 Windows 运行。

## 有效权限计算、数据范围与权限来源查询（步骤 25）

新增内部授权计算引擎 `internal/authz` 与 SQLite 只读快照 `internal/authz/sqlite`：根据当前账户状态、应用与成员状态、直接用户角色、用户组角色、角色与权限启停，实时计算系统/应用 scope 的有效权限，返回来源与数据范围，并提供显式资源检查接口。复用迁移 0001 的 `users`/`applications`/`app_memberships`/`roles`/`role_permissions`/`permissions`/`user_roles`/`group_roles`/`group_members` 表，本步未新增迁移，也未读写 `database/login.db`。

- **计算输入与禁用优先**：计算前读取同一事务快照内的账户、应用、成员、角色、权限与分配。拒绝优先级固定为：账户不存在/非 active → `USER_DISABLED`；root 账户 → `ACCESS_DENIED`（root 不走普通权限推导）；应用不存在 → `REQ_INVALID`、应用非 active → `CLIENT_DISABLED`；应用成员缺失/非 active → `APP_MEMBERSHIP_REQUIRED`；随后才检查权限定义与来源。任一状态不满足即整体拒绝，不因角色/权限存在而放行。
- **来源合并与生效条件**：直接 `user_roles` 与经 `group_members`/`group_roles` 的组角色合并；来源必须同时满足角色 enabled、权限 enabled、非 root_only、角色 scope 与目标 scope 一致。角色停用或权限停用时来源不计入有效授权；权限被停用即使仍有角色组合也返回 `PERMISSION_DISABLED`；未知权限返回 `PERMISSION_UNKNOWN`。同名权限跨应用隔离（scope+permission_key 唯一定位），系统权限不会出现在应用 scope 计算中。
- **数据范围契约**：新增严格版本化 `data_scope_json` 契约：`{"v":1,"mode":"all"|"none"|"resources","resources":[...]}`，资源 1～64 个、≤256 字节、去重排序；历史步骤 24 写入的 `"{}"`/空值解释为 `undefined`（功能权限可用，但资源级检查默认拒绝，避免把“未声明”当“全部数据”）；非法 JSON/版本/字段/重复资源按来源排除（fail-closed）。多来源数据范围取交集：none 最严格，undefined 保持未声明，all 不限制，resources 取交集；来源越多不会扩大数据范围。
- **all/any 与来源说明**：默认 `all`，要求每个权限都满足；`any` 至少一个满足，但请求中出现未知权限仍硬拒绝。每个权限结果带 `Sources`：来源类型（直接/组）、角色 ID/key/名称、组 ID/key/名称、角色/权限启用状态、root_only、分配 data_scope、assigned_by/创建时间、`Included` 与 `ExcludedReason`（role_disabled/permission_disabled/root_only_permission/account_disabled/application_inactive/membership_required/data_scope_invalid）。
- **查询授权与不泄露**：有效权限与来源查询必须通过 `Authorizer`：普通用户只能查自己；应用管理员只能查自己获准应用内成员（非成员返回 `ACCESS_DENIED`，不借查询探测目标存在性）；本地/系统操作者可查任意普通主体；root 主体在有效权限查询中返回 `ACCESS_DENIED`，来源查询返回 `ErrRootProtected`。缺少 Store/Authorizer 时不构造；拒绝策略不放行；未接 HTTP，不提供匿名管理端点。
- **资源检查接口**：`CheckResourceAccess` 显式接收权限键与资源标识，先做功能权限检查，再按数据范围交集判断：undefined/none 默认拒绝（`RESOURCE_FORBIDDEN`），all 允许，resources 必须命中显式集合。业务资源归属不能从权限名推断；本步不实现具体业务资源表/所有权查询，数据范围写入口（角色分配 API）也尚未开放，步骤 24 的既有分配全部为 undefined。
- **一致性与边界**：所有读取在调用方 `Store.Snapshot` 打开的同一数据库事务中完成；不缓存权限结果，角色/权限/成员/应用变更在下次计算立即生效。查询固定次数（无 N+1、无递归；用户组不支持嵌套组），有效权限分页默认 20/最大 100/Offset 上限 100 万，单个权限的候选来源单次最多读取 `MaxSourceRows=512` 行；一旦截断，`Check`/`CheckResourceAccess`/`EffectivePermissions` 一律 fail-closed（`AUTHZ_UNAVAILABLE`，`CheckResult.SourceLimitReached`==true，资源检查拒绝），不会用前 512 个来源的数据范围交集错误放行；单次检查最多 32 个权限。依赖不可用时检查结果默认 `AUTHZ_UNAVAILABLE` 且 `Allowed=false`。
- **错误映射与兼容**：不新增错误码：参数/未知权限 `REQ_INVALID(400)`；未授权/root 保护 `ACCESS_DENIED(403)`；账户/应用/成员不可用 `USER_DISABLED`/`CLIENT_DISABLED`/`APP_MEMBERSHIP_REQUIRED(403)`；权限停用/未授予/root_only `PERMISSION_DISABLED`/`PERMISSION_REQUIRED`/`ACCESS_DENIED(403)`；资源级拒绝 `RESOURCE_FORBIDDEN(403)`；依赖不可用 `AUTHZ_UNAVAILABLE(503)`；根包测试核对判定码与注册表字面值/HTTP 状态。
- **已验证（Windows amd64，临时 SQLite）**：直接/组角色合并与来源说明；同 scope 多来源数据范围 all∩resources 交集、资源级命中/未命中、历史 `{}` 功能可用但资源拒绝、非法数据范围来源排除；空集合/未知权限/all/any/重复权限去重/权限数量上限；账户/应用/成员/角色/权限/root 禁用优先与错误码；同名权限跨应用隔离；成员、应用、角色、权限变更立即影响结果（无陈旧缓存）；查询自己/他人/应用管理员跨应用/非成员/本地系统操作员授权边界与不泄露；分页/HasMore/来源分页/非法参数；4 路并发检查与角色启停切换不出现半更新错误；单权限候选来源超过 512 时 Check/资源检查/有效权限查询均拒绝并置 SourceLimitReached；查询授权器并发读写不失效；六目标编译与交叉 vet 在 MEMORY 记录。
- **尚未实现/未验证**：OAuth/OIDC Token 联合校验（本步只提供将来复用的权限判断）、HTTP/`cmd/login-server` 接入、数据范围写入口与角色分配 data_scope 设置/迁移（当前既有分配 undefined）、业务资源归属表/所有权检查、权限缓存与失效策略（当前无缓存）、拒绝查询的审计事件、查询授权从持久化角色/委派模型加载（当前 `StaticAuthorizer` 内存白名单）、多进程/高并发压力、race detector 与 Linux/macOS 运行；`Authz` 的只读快照使用存储层事务，读取期间可能阻塞并发写事务，性能优化留后续。

## 可转授权限与委派限制（步骤 26）

新增内部委派域 `internal/delegation` 与 SQLite 生产仓储 `internal/delegation/sqlite`：把“可使用权限”与“可转授权限”分开，封堵角色编辑、角色分配、组成员调整、应用成员恢复、启用角色/权限/应用等间接提权路径。新增迁移 0006 的 `permission_delegations` 委派资格表（两个 JSON 列带 `json_valid` CHECK）；未操作 `database/login.db`。

- **资格与受信签发**：一条委派资格表示受信操作者允许某用户（委派者）在指定 scope 把某权限再转授给其他主体，记录 `max_data_scope_json`（数据范围上限，默认 all）、`allowed_targets_json`（目标白名单，默认不限具体目标）、`allow_self`（默认 0）、`expires_at_ms` 与 `revoked_at_ms`；`(delegator_user_id, scope_id, permission_id)` 唯一，重新签发覆盖原记录并清除撤回标记，前后值写入审计。只有受限本地初始化（`local_admin`）与系统（`system`）可信通道能签发/撤回，普通用户 `ACCESS_DENIED`；签发/撤回/读取均写安全审计，审计不可用整体回滚。资格只登记“可转授”，不改变任何主体的有效权限。
- **统一检查与同事务**：`Guard` 提供 `CheckPermissionAccess`（角色组合权限，按角色当前分配目标复核）、`CheckAssignment`（角色分配给用户/用户组并校验接收目标）、`CheckPermissionActivation`（启用角色/启用权限，按启用后重新获得权限的目标集合复核）、`CheckScopeRestoration`（启用应用，读取范围内将被恢复的权限与持有目标后复核）；用户组增员与应用成员加入/重新启用复用 `CheckAssignment`。调用方在自己的 `audit.ExecuteCritical` 事务内通过 `audit.Tx.QueryContext` 读取资格、权限定义、操作者当前持有、受影响目标与目标限制，使“检查 + 写入”处于同一一致性边界，避免检查后并发修改放行。角色/组/应用/权限四个服务包的 `Options` 新增必填 `Transfers delegation.Guard`，缺失不可构造、拒绝策略不放行。
- **持有与转授分离**：检查实际权限组合而不是角色名称/等级：操作者必须当前实际持有该权限（直接用户角色或经用户组角色来源，角色与权限均启用、非 root_only），且存在同 scope/权限的未过期未撤回资格；只有权限但无资格返回 `PERMISSION_REQUIRED`。资格过期/撤回、操作者权限被收回、应用/成员/账户状态变化后立即失效（每次事务内实时读取，无缓存）。
- **间接提权路径的目标复核**：启用角色会恢复其组合权限、启用权限会恢复角色持有者的权限、把权限组合进角色会把权限扩散给该角色当前分配的用户/用户组、启用应用会恢复该范围内被整体拒绝的权限。这些路径除委派资格外一律按“实际受影响目标集合”复核 `allow_self` 与目标白名单：被委派者不能通过停用后再启用自己（或自己所在用户组）的含权角色/权限自我提权，也不能把权限塞进已分配给白名单外用户的角色；启用应用无法安全校验时 fail-closed，只有受信通道可通过。目标集合超过 `MaxAffectedTargets=4096`、数量超限或数据损坏一律拒绝，不静默缩小校验范围。
- **数据范围收缩**：转授数据范围必须是资格上限的子集：上限 `all` 可转授 all/none/resources，上限 `resources` 只能转授其子集或 none，上限不得为 undefined，资源级上限不能转授未声明范围；越界返回 `ACCESS_DENIED`。上限与目标白名单使用严格版本化 JSON，未知字段/非法结构 fail-closed。
- **自我与目标限制**：默认禁止把权限转授给自己或自己所在的用户组（`allow_self=0`，`ACCESS_DENIED`），需要时由受信操作者显式签发；目标白名单非空时接收用户/用户组必须命中，否则 `ACCESS_DENIED`。
- **错误映射**：不新增注册错误码：非法 ID/分页/资格或权限不存在 `REQ_INVALID(400)`；缺少资格/资格过期/已撤回/已不持有 `PERMISSION_REQUIRED(403)`；自我或本组、目标不在白名单、数据范围过宽、权限不可转授、未获准 `ACCESS_DENIED(403)`；scope 串用 `APP_SCOPE_MISMATCH(403)`；应用停用 `CLIENT_DISABLED`、委派者账户不可用 `USER_DISABLED(403)`；存储 `DB_UNAVAILABLE(503)`；审计 `AUDIT_WRITE_FAILED(503)`；选项无效/未知 `INTERNAL_ERROR(500)`。`CodeOf` 对非本包错误返回空串供调用方继续映射；根包 `delegation_errorcodes_test.go` 核对登记状态、HTTP 状态与字面值。
- **已验证（Windows amd64，临时 SQLite）**：受信签发/覆盖/校验/撤回/列表与普通用户越权拒绝；允许转授的正向用例；角色组合权限、用户赋角色、用户组赋角色、启用角色、用户组增员、应用成员加入、应用成员重新启用、启用权限、启用应用每条写入路径的越权拒绝（含向自己赋权与目标越界）；被委派者启用自身/自身所在组的含权角色与权限被拒；向白名单外或自身持有者组合权限被拒且不落库；应用启用无资格被拒、有资格且目标合法通过；持有但不可转授、资格过期、资格撤回、数据范围收缩与越界、目标白名单、操作者权限被收回、scope/账户/成员状态变化；并发转授检查与撤回、受 Guard 保护的并发写入与撤回不出现半更新放行；审计故障 fail-closed；迁移 0001～0006 与 0006 结构测试；根包错误码注册表测试保持 46 码不变；六目标编译与定向 vet 在 MEMORY 记录。
- **尚未实现/未验证（如实声明）**：数据范围收缩未完整落地——`PermissionRef.DataScopeJSON` 虽已透传参与子集校验，但角色分配等写入路径仍固定写入未声明范围（`{}`），非 all 上限的委派资格因此继续 fail-closed、无法实际收缩；迁移 0006 只补 `json_valid` CHECK，不新增数据范围列，待后续步骤实现“按交集落库”。预设角色目录与恢复已由步骤 27 实现并接入同一 Guard（见下文步骤 27 小节）。审批引擎与需要审批的安全恢复（本步不做通用审批）、再委派（受信通道之外不能再签发资格）、委派资格 HTTP/CLI/管理页面、数据范围写入口、同一自然人“小号”识别（需结合目标白名单）、委派资格与令牌/会话联合校验；未做 race detector、多进程/多实例一致性与非 Windows 运行。

## 预设角色、用户组与权限初始化（步骤 27）

新增内部预设域 `internal/preset` 与 SQLite 生产仓储 `internal/preset/sqlite`：按需求 11.1/11.3/11.5 提供版本化、机器可读的预设目录及其幂等初始化与恢复默认；新增迁移 0007 的 `preset_installations` 初始化版本记录表；未操作 `database/login.db`。

- **目录内容**：47 条系统权限定义（每条都有稳定机器标识、中文名称、能做什么、生效范围、不能做什么、是否需要再次验证、默认授予角色与“业务是否已实现”标记），五个系统角色（系统管理员、用户管理员、客服、审计员、普通用户）及各自默认权限与默认用户组，应用管理员/应用普通用户两个应用创建模板角色与两个应用模板用户组。同一格列出的多个权限逐条登记、不使用隐式总开关；`root_only` 权限（恢复备份、清理审计、敏感策略）与恢复审批、备份导出、权限启停等默认不授予的权限不进入任何预设角色。
- **不创建账户与不赋权**：初始化只登记权限、角色定义和空用户组，不创建任何账户（因此没有带固定密码的工作人员账户），也不写 `user_roles`/`group_roles`/`group_members`；预设角色没有可分配的 root 语义，root 不能通过普通角色分配产生。应用模板按应用生成各自独立的角色/用户组记录（scope=应用 ID），不共用跨应用记录；应用范围默认不预置权限。
- **幂等与版本化**：`Install` 可重复执行；同一版本重复执行只补齐缺失项（`UpToDate`、不产生重复行），更高版本升级只补缺失项并把“既有角色缺少的新默认权限”列入 `DeferredRolePermissionAdds`，不覆盖用户已调整的角色组合（需求 11.1“升级不覆盖用户已调整的非核心角色”）；已安装版本高于程序目录版本时拒绝自动降级（`CONFLICT`）。已存在的预设权限只同步中文名称/说明/限制（需求允许随版本修正文案），同步写入的是**目录定义的新值**而不是库内旧记录：升级改文案后首次安装真实更新、再次安装收敛为无变化，不会永远报“说明更新”；`builtin`/`root_only` 语义不一致时返回目录冲突并整体拒绝，文案修正不扩大权限。
- **差异预览与再次授权**：`Preview` 读取当前状态并返回逐角色差异（补回/移除的权限、缺失目录项、说明更新、停用权限恢复、因通道限制跳过的 root_only 恢复、角色保护与未变化项）及汇总计数，写读取审计；同时签发绑定操作者、目录版本与差异摘要、短时有效（默认 10 分钟）且单次使用的确认令牌。`Restore` 只接受该令牌：无令牌/伪造/过期/已使用/不属于当前操作者一律 `REQ_INVALID`，预览后状态变化则 `CONFLICT` 要求重新预览——客户端布尔值不能冒充“已展示差异并再次授权”。**事务前的上述拒绝同样补写 `preset.restore_failed` 失败审计**（原因码区分缺失/伪造/过期/非本人/摘要过期），不伪造成功审计。
- **局部/整体恢复与保留自定义**：恢复必须显式选择作用范围与角色（`RoleSelection`），整体恢复必须显式 `All=true` 并在服务端展开为具体选择；空选择、同时给出整体与显式选择均拒绝。整体恢复会**跳过已停用的应用范围**并通过 `SkippedScopes` 报告原因（`application_inactive`），不再因单个停用应用让整次恢复失败；显式选择停用应用仍以 `CLIENT_DISABLED` 拒绝，错误文本带具体应用 ID 且不重复。只恢复所选作用范围的权限目录与所选角色组合，自定义角色、自定义权限、自定义组成员与未选角色一律保留。
- **同事务与 Guard 接线**：整次恢复（补齐权限/角色/用户组、同步说明、恢复停用预设权限、调整所选角色权限组合、写入版本记录）在一个 `audit.ExecuteCritical` 事务内完成，任何一步失败（含委派检查拒绝、审计不可用、状态已被并发修改）整体回滚并保留失败审计。每次角色权限新增前在同一事务内调用 `delegation.Guard.CheckPermissionAccess`（按角色当前分配目标复核），每次恢复停用预设权限前调用 `CheckPermissionActivation`（按权限持有目标复核）；受信本地/系统通道按步骤 26 既有语义放行，未来非受信管理者开放时 Guard 会拒绝超出其持有与可转授范围的写入，因此恢复不能扩大操作者可委派范围。
- **root_only 重启用治理（与 `internal/permission` 规则一致）**：`root_only` 权限（恢复备份、清理审计、敏感策略）的启停只能由受限本地初始化操作者执行（见本 README 权限目录小节“内置权限保护”：`internal/permission` 对 `caller.actor.Type != local_admin` 一律拒绝启停 root_only）。因此预设恢复中**只有 `local_admin` 可借恢复默认重新启用 root_only 权限**；`system` 与其他非本地/不可信通道一律跳过，跳过项在差异的 `SkippedRootOnlyReenables` 中明确展示并在成功审计记录 `root_only_reenable_skipped`，避免撤销 root 有意的停用。普通预设权限的重新启用仍按既有 `CheckPermissionActivation` 复核目标。
- **TOCTOU 防护**：预览时记录各作用范围目录状态（范围与应用启用状态、初始化版本、权限、角色、角色权限组合、用户组）的稳定指纹；`Restore` 在写入事务内重算同一指纹并比对，预览/复核之后到写入之前的并发修改会被 `CONFLICT`（`ErrPreviewStale`）拒绝，保证“预览内容=实际执行内容”，不会用旧计划覆盖新状态。
- **需求对齐与已声明偏差**：按需求 11.5，五个系统角色（含系统管理员、用户管理员、客服、审计员）默认权限均包含 `self.profile.read/update`、`self.credentials.manage`、`self.sessions.manage`、`self.grants.manage`（仅本人、不扩大管理范围）。两处保守偏差：应用模板角色（应用管理员/应用普通用户）仍不默认组合任何系统权限——应用范围按需求 11.2 只承载应用独有权限，`self.*` 属系统范围基础角色，跨范围组合会破坏作用域隔离；角色模板的 `DefaultGroupKey` 只声明配套默认用户组、初始化不写 `group_roles` 关联——建立“组→角色”关联属于改变有效权限的赋权写入路径，需接入会话/审批与委派复核的专门接线，当前默认组为空组（无成员），不写关联既不给任何用户赋权，也避免绕过步骤 26 的 Guard；两项偏差已记录于此与 MEMORY，待后续接线步骤实现。
- **未实现的权限不伪装成功**：目录中每条权限带 `Implemented` 标记；本步只登记定义与说明，不实现对应业务操作，业务调用必须显式检查该标记并返回未实现错误，不能返回虚假成功。
- **调用边界**：`Install`/`Preview`/`Restore` 只接受受限本地初始化（`local_admin`）与系统（`system`）调用者，身份只能由构造器生成；其他身份与零值调用者 fail-closed。应用创建后的模板生成由宿主在创建成功后调用幂等的 `InstallApplicationScope`（本包不跨领域修改应用事务）。
- **错误映射**：不新增注册错误码：非法请求/作用范围/缺少预览令牌 `REQ_INVALID(400)`；预览过期/目录冲突/拒绝降级/状态冲突 `CONFLICT(409)`；未授权 `ACCESS_DENIED(403)`；应用停用 `CLIENT_DISABLED(403)`；存储 `DB_UNAVAILABLE(503)`；审计 `AUDIT_WRITE_FAILED(503)`；选项无效/未知 `INTERNAL_ERROR(500)`。根包 `preset_errorcodes_test.go` 核对其登记状态与 HTTP 状态，注册表仍 46 码。
- **已验证（Windows amd64，临时 SQLite）**：目录自洽性与说明完整性、默认组存在性校验（角色 `DefaultGroupKey` 必须指向同作用范围默认组）、机器可读 JSON；首次初始化创建数量、无账户/无角色分配/无 root 角色、默认用户组为空组、五个系统角色均含 `self.*` 且不含 root_only；二次执行幂等不产生重复行；1.0.0→1.1.0 升级只补缺失权限、不改写用户调整并给出待恢复提示；**升级改文案后真实更新库内名称/说明，重复安装收敛为无变化且预览不再报告说明更新**；局部恢复的预览差异、令牌再次授权、审计、补回/移除权限、重新启用停用权限、保留自定义角色/权限与未选角色、令牌单次使用；预览后状态变化拒绝且库未变；**令牌缺失/伪造/过期/非本人/摘要过期均在事务前拒绝并写失败审计、无成功审计、库未变**；**恢复计划读取后注入并发修改时事务内指纹校验拒绝（旧计划不覆盖新状态）且留失败审计**；拒绝一切转授的 Guard 使恢复整体回滚且只留失败审计（证明写入路径接入同一 Guard）；**只有 local_admin 可恢复 root_only 启用状态、system 通道预览展示跳过且恢复不启用（与 permission 规则一致，审计记录 `root_only_reenable_skipped`）**；应用模板按应用隔离、停用应用拒绝且不落库、**整体恢复跳过停用应用并报告、显式选择停用应用错误带应用 ID**、显式整体恢复三个作用范围；空白/非法选择与构造依赖缺失 fail-closed；迁移 0001～0007 与 0007 结构测试；根包错误码注册表测试。
- **尚未实现/未验证**：非受信管理者的恢复入口（需要会话层、强认证与审批引擎接入；当前只开放受信通道）、密码/MFA 再次认证（本步的“再次授权”是差异预览 + 服务端确认令牌，不等于强认证）、预览令牌的跨进程/多实例共享存储（当前进程内；状态指纹校验同样依赖同一数据库事务）、恢复计划在事务外读取计算（事务内以状态指纹做条件校验，而非重算整份计划）、预设目录 HTTP/CLI/管理页面、应用创建自动调用本包模板的接线（由宿主装配步骤完成）、预设权限对应业务操作的实现（目录标记 `Implemented=false`）、默认组→角色关联的赋权接线（见上文偏差）、内置角色元数据（名称/说明）的修改入口（沿用步骤 24 内置保护，仅权限组合可调整）；未做 race detector、多进程与 Linux/macOS 运行。

## 本地受控首次初始化与唯一 root（步骤 28）

新增内部初始化域 `internal/bootstrap` 与 SQLite 生产仓储 `internal/bootstrap/sqlite`：实现本地受控首次初始化、唯一 root 身份与防误删误禁的服务规则，不开放匿名远程创建管理员的入口；新增迁移 0008 的 `root_initializations` 单例状态表；未操作 `database/login.db`，未新增依赖。

- **受限待配置状态**：初始化只由本机受信 `local_admin`（审计包定义的可信操作者类型）调用；root 创建后处于 `pending_setup`，不存明文密码也不存密码哈希，不签发会话/令牌。唯一入口是一次性、本机、短期的配置凭证（复用 `internal/credential`：用途固定 `root.setup`、目标绑定新生成的 root 用户 ID、有效期 1 分钟～1 小时默认 15 分钟、数据库只保存 32 字节摘要、单次消费）；后续正式密码与强认证由后续步骤的正式密码服务完成，强认证完成前只允许必要的安全设置（兑换只进入 `setup_verified`，不是完整管理员身份）。`Status` 读取与初始化/兑换/重签共用进程内互斥；跨进程提交窗口另在“root 存在但初始化记录缺失”时重读一次记录，避免把同一事务的 root 行与记录提交窗口误报为 `existing_root`。
- **唯一性与创建入口关闭**：`users.is_root=1` 由 0001 的 `ux_single_root` 唯一索引保证唯一；0008 的 `root_initializations` 以 `singleton=1` 主键保证单例，并以 `root_user_id` 外键 `ON DELETE RESTRICT` 形成删除纵深防御。root 行与初始化记录在同一 `audit.ExecuteCritical` 事务中条件插入（`WHERE NOT EXISTS` 条件 + 唯一约束兜底），任一失败整体回滚，不会出现“有 root 无记录”或半个 root；进程内互斥串行化初始化/兑换/重签，并发初始化最多一个成功。root 或初始化记录已存在时返回 `CONFLICT` 并写失败审计，创建入口关闭；重启只读取数据库，不会重新生成默认账户。
- **无默认密码、无永久旁路**：root 用户名固定为保留值 `root`，普通账户创建规则永久禁止该名称，避免抢占；没有默认密码、默认口令或硬编码凭据。配置凭证过期、被消费、被替换撤销、用途/目标不匹配或明文错误统一返回 `TOKEN_INVALID(401)`（不区分具体原因避免探测），凭证服务原子消费保证并发兑换最多一次成功。初始化的 HTTP/远程入口不存在，本步不接入 `cmd/login-server`。
- **可诊断恢复入口**：`Status` 返回受限状态、root 是否存在、配置凭证是否可用/过期/已消费、验证与完成时间及中文直白说明；`ReissueSetupCredential` 允许本地受控操作者对 `pending_setup`/`setup_verified` 重新签发短期凭证（`ReplaceActive` 撤销同用途旧凭证），不重建 root、不改变保护规则、`ready` 后关闭配置入口；不实现完整应急重置（root CLI 应急流程留后续步骤）。重签的已声明失败窗口：先撤销旧凭证再签发新凭证，之后才在审计事务内条件更新初始化记录；若第二步因审计不可用/并发状态变化/存储故障失败，新凭证会被尽力撤销，可能短暂没有任何可用配置凭证（fail-closed，不留未记录状态或伪造成功审计），再次调用重签即可恢复，不需要重建 root。若数据库存在 root 但无初始化记录（旧版本/人工数据），`Status` 如实报告 `existing_root`，初始化拒绝自动接管。
- **root 服务层保护与失败审计**：`internal/account` 的禁用/启用/请求删除/完成删除对 `is_root=1` 一律 `ACCESS_DENIED`（`ErrProtectedUser`），删除预览明确标记 `IsRoot`；`internal/role` 拒绝把角色分配给 root、拒绝向含 root 的组分配角色；`internal/group` 的组成员资格显式排除 root（root 不能加入任何用户组，避免“组先配角色、再把 root 拉进组”的间接赋权路径）；`internal/app` 的应用成员加入/资料更新/重新启用同样显式拒绝 root（保持既有 `USER_DISABLED` 语义，root 只能走受保护本地通道）；`users.is_root` 没有任何服务层写入口（不可降格），有效权限引擎也拒绝为 root 推导普通角色权限。上述普通管理路径的 root 拒绝均用独立事务补写 failure 审计（含真实错误码与 `root_protected`/`root_group_member_protected` 等原因码，不伪造成功审计），业务库不变；审计写入失败只会把 `AUDIT_WRITE_FAILED` 一并加入错误链并告警，拒绝照旧生效。
- **审计与错误映射**：初始化、兑换、重签、状态读取与拒绝路径都写安全审计（失败审计记录真实 `CONFLICT`/`TOKEN_INVALID` 错误码、原因码与操作者，不含凭证明文）；初始化与兑换的成功审计与业务变更同事务，审计不可用拒绝变更。不新增注册错误码：非法请求/未初始化 `REQ_INVALID(400)`；已初始化/状态冲突/root 保留名被占用 `CONFLICT(409)`；配置凭证无效 `TOKEN_INVALID(401)`；未授权 `ACCESS_DENIED(403)`；存储 `DB_UNAVAILABLE(503)`；审计 `AUDIT_WRITE_FAILED(503)`；选项无效/未知 `INTERNAL_ERROR(500)`。根包 `bootstrap_errorcodes_test.go` 核对其登记状态与 HTTP 状态，注册表仍 46 码。
- **已验证（Windows amd64，临时 SQLite）**：首次初始化只创建一个 `is_root=1` 的 active root 与单例 `pending_setup` 记录，`users` 无密码列、无密码/会话/令牌表，凭证只存 32 字节摘要且审计/状态不含明文；重复运行与已有 root（含无初始化记录的旧数据）拒绝且库不变、写失败审计；**同一 Service 6 路并发与“同一临时 SQLite 数据库、两个独立 Store/Service 实例”并发初始化均只有 1 个成功，数据库始终最多 1 个 root/1 条记录/1 条可用凭证**；错误秘密与重放兑换拒绝且状态不变，正确兑换推进到 `setup_verified`；凭证过期后拒绝并可重新签发恢复（旧凭证撤销），未初始化与 `ready` 后重签拒绝；故障注入导致根创建中途失败时整体回滚、失败尝试凭证被撤销、可用真实存储重试成功；审计不可用时初始化被拒绝且库不变、状态读取审计失败拒绝返回；模拟进程重启后状态不变、不重复创建账户/凭证；**root 在账户禁用/启用/请求删除/完成删除、角色分配、含 root 组分配角色、组成员加入、应用成员加入/重新启用全部拒绝且库不变，并各写 1 条 failure 审计（错误码/原因码与真实拒绝一致）**；迁移 0001～0008 与 0008 结构测试；根包错误码注册表测试。六目标仅编译，非 Windows 未运行；未做 race detector。
- **尚未实现/未验证**：初始化本地 CLI 命令与启动装配（`cmd/loginctl` 未建；本步只提供内部 Go API）、正式密码哈希/密码验证/强认证与 `ready` 状态转换（步骤 29）、兑换后受限配置会话的持久化绑定（当前 `SetupGrant` 仅是本进程内的服务端记录返回值，不是会话/令牌）、完整 root 应急重置已由步骤 48 的 `cmd/loginctl root-recover` 提供（本地/停机/受限重新配置）、初始化流程的 HTTP 管理与页面、多进程/多实例长期并发压力（已有“同一数据库两个独立 Store/Service 实例并发初始化仅 1 成功”回归用例，未做多进程/长稳/故障切换实测）、非 Windows 运行。


## 正式密码哈希、密码验证与认证结果（步骤 29）

新增内部认证域 `internal/authn` 与 SQLite 生产仓储 `internal/authn/sqlite`：实现正式密码哈希、密码验证与可复用的认证结果，为下一步会话签发提供可信输入；新增迁移 0009（`password_credentials`、`password_history`、`user_emails`；邮箱规范化由服务层 NFKC+Unicode 折叠+NFC 负责，数据库不依赖 SQLite `lower()` 做 Unicode 折叠）；新增一个直接依赖 `golang.org/x/crypto v0.58.0`（Go 官方维护、BSD-3-Clause；只使用其中的 Argon2id 实现），不引入其他密码学库，也未操作 `database/login.db`。

- **Argon2id 存储与可升级参数**：密码使用 `golang.org/x/crypto/argon2` 派生并以 PHC 字符串保存（`$argon2id$v=19$m=...,t=...,p=...$salt$hash`），数据库只保存该自描述编码，不保存明文、可逆密文或单独明文摘要列。默认参数取 OWASP 2023 最低推荐组合（19 MiB、2 次迭代、1 并行度、16 字节盐、32 字节摘要），工具级上下界为 8 MiB～256 MiB、1～10 次、1～8 并行度；解析历史哈希时允许低于下限以便升级、但超过上界或违反库硬性要求一律拒绝，防止损坏/恶意行造成 OOM。登录成功发现旧参数弱于当前策略时，在审计事务中条件升级（旧哈希已被并发修改则不覆盖）；升级失败只告警、不改变本次认证结论。所有 Argon2 派生/校验受有界工作槽位限制（默认并发 2、可配置 1～8）并带排队超时，超时按 `RATE_LIMITED` fail-closed，HTTP 暴露后不会因并发密码请求耗尽内存。
- **密码策略**：默认至少 12 个码点、最多 128 个码点；拒绝控制字符、全空白、内置高频弱密码词表、连续字符/键盘序列、单一字符重复与包含用户名/昵称的密码；部署可追加弱密码词。可选近期历史限制（0～10 条，默认关闭，启用时始终拒绝与当前密码相同），不强制没有依据的定期改密；管理员可标记 `must_change` 要求下次成功登录先改密。密码校验使用恒定时间比较。
- **登录标识**：用户名按 NFKC + Unicode 大小写折叠 + NFC 规范化后查询，与账户用户名唯一性口径一致；邮箱仅在“配置允许邮箱登录”开关开启且 `user_emails.verified_at_ms` 非空时参与登录，未验证邮箱永远不能登录。`NormalizeEmail` 是邮箱读写共用的规范口径，供后续注册/验证步骤复用。账户不存在、密码错误、账户禁用/待删除、未设置密码、邮箱未验证、标识格式错误的公开结果完全相同（`AUTH_FAILED`），内部审计记录真实原因；账户不存在时执行等价 Argon2 dummy 校验以减小时序差异。
- **认证结果与强认证语义**：认证结果标明已完成的认证方法、完成时间、仍需完成的步骤与 `SecurityVersion`，并明确 `Restricted`；本包不返回会话或 Token。强认证按**权限敏感度**判定：root 与直接或经用户组角色持有高敏感系统权限（用户/应用/角色/权限/审计/策略/恢复/会话管理等，含任意 root_only 权限）的账户，包括组合了这些权限的自定义系统角色持有者，密码正确时固定返回 `pending_second_factor`、`Restricted=true`、仍需“绑定强因素 + 完成第二因素”——MFA 尚未实现，这些账户不会被视为完整登录；`must_change` 账户返回 `pending_password_change`。
- **失败限制（可恢复、有界、并发安全、抗锁死）**：地址/操作维度复用 `internal/ratelimit` 的有界固定窗口**失败预算**（认证前用新增 `Peek` 只读判断，成功认证不消耗配额；失败时才计一次，容量耗尽与新键 fail-closed）。账户维度使用渐进延迟（指数增长并封顶，只延迟不阻断）。临时锁定只按“账户 + 来源前缀”组合生效，来源按 IPv4 完整地址或 IPv6 /64 聚合，因此单个来源无法锁死 root 或他人账户，也无法用 IPv6 地址轮换绕过；连续锁定按指数退避并封顶、到期自动恢复、成功认证清零。单一来源在窗口内可失败的不同标识数有上限（默认 50），防止用大量唯一标识灌满跟踪表；跟踪表容量满时只淘汰未锁定条目、绝不淘汰锁定项，全部为锁定时新键按容量拒绝（fail-closed）。未知标识同样计入，避免用限流差异探测账户存在性。失败状态只在进程内保存（重启即恢复），第一版不承诺多实例共享；时间统一 UTC 毫秒。
- **与 root 初始化共用服务**：`SetRootPassword` 只接受可信本地管理员调用，必须已通过 `bootstrap.PurposeRootSetup` 一次性凭证兑换进入 `setup_verified`（`pending_setup` 直接拒绝，`ready` 后入口关闭），复用同一密码哈希、策略、历史与审计实现。密码写入、`users.security_version` 递增、审计与“是否进入 `ready`”的条件状态更新在同一 `audit.ExecuteCritical` 事务提交；只有正式密码已落库且必需强认证已配置才调用 `bootstrap.Store.MarkReady`（0008 状态机新增的条件转换，只允许 `setup_verified`→`ready`，且 SQL 层强制要求同一事务内已存在正式密码凭证，防止无密码置 ready）。MFA 未实现，root 写入密码后仍为 `setup_verified`，返回第二因素待完成步骤；不签发会话、不伪造强认证完成。
- **审计、错误码与脱敏**：密码设置、root 密码设置、认证成功/失败、限流拒绝与哈希升级都写安全审计，密码写入成功审计与业务同事务；认证成功路径审计不可用时拒绝返回结果（fail-closed），不返回未记录的成功。日志/错误/审计差异只含用户 ID、内部原因码、安全版本、状态与 Argon2 参数摘要，不含密码、PHC 哈希、盐或一次性配置凭证秘密。不新增注册错误码：统一失败 `AUTH_FAILED(401)`，限流 `RATE_LIMITED(429)`，非法/弱密码/密码复用 `REQ_INVALID(400)`，root 初始化状态冲突 `CONFLICT(409)`，未授权 `ACCESS_DENIED(403)`，存储 `DB_UNAVAILABLE(503)`，审计 `AUDIT_WRITE_FAILED(503)`；根包 `authn_errorcodes_test.go` 核对登记状态，注册表仍 46 码。
- **已验证（Windows amd64，临时 SQLite）**：正常密码登录（含用户名大小写折叠、全角/Unicode NFKC 归一）与错误密码；错误密码与未知用户公开错误文本/错误码完全一致、审计原因不同；禁用账户密码正确仍统一失败且审计记录真实原因；已验证邮箱登录（大小写变体）、未验证邮箱与关闭邮箱登录时统一失败；渐进延迟序列、临时锁定、锁定到期恢复与成功认证后失败状态重置、未知标识同等锁定；8 路并发失败下锁定终态安全、锁定期正确密码拒绝且到期恢复；旧参数哈希登录升级为当前参数、第二次登录不重复升级；弱密码/当前密码/历史密码拒绝、参数边界与策略边界；跨用户改密/缺少当前密码/错误当前密码拒绝，root 不能走普通改密；root 初始化 pending_setup 不能设密码、兑换一次性凭证后可设置、状态保持 `setup_verified`、密码登录返回待第二因素、`ready` 后入口关闭；`MarkReady` 条件转换越级/重复拒绝；管理角色强认证要求；地址/操作维度限流独立生效；审计不可用时认证与密码写入 fail-closed 且旧密码仍有效；日志/审计/错误不出现密码、PHC 哈希或盐；迁移 0001～0009 与 0009 结构测试、根包错误码测试。未做 race detector、多进程/多实例共享失败状态、真实高流量压测与非 Windows 运行。
- **审计退修（2026-11-16，双审计 S1～S5/Q1～Q4）**：新增 Argon2 有界并发槽位与排队超时；强认证改为按高敏感系统权限（含自定义系统角色与 root_only）判定并同时返回强因素绑定/第二因素步骤；失败限制改为“IP/操作失败预算 + 账户渐进延迟 + 账户+来源临时锁定 + IPv6 /64 聚合 + 来源标识扫描阈值 + 锁定条目不淘汰”；普通用户自助改密的当前密码复核接入同一失败限制；`MarkReady` 要求正式密码凭证存在；地址限流改用只读 `Peek` 使成功不计预算；移除 0009 中与 Unicode 折叠口径冲突的 SQLite `lower()` CHECK；新增 `internal/authn/sqlite` 独立仓储测试与工作槽位/来源聚合测试。已知残余风险：账户不存在时 dummy Argon2 校验只能减小而不能完全消除时序差；密码计算排队等待中的 context 取消/超时已原样传播（不再映射为限流或凭据损坏），但认证失败路径在 ctx 已取消时仍可能跳过失败审计（拒绝仍 fail-closed）。
- **尚未实现/未验证**：会话/Token 签发与撤销（步骤 30，本步只提供认证结果）、MFA/Passkey/恢复代码验证（第二因素步骤）、邮箱注册与验证入口（步骤 33；本步只提供已验证邮箱的登录读取与统一规范化）、用户自助改密的 HTTP 接口与敏感操作再次验证策略（步骤 38/39）、完整 root 应急重置 CLI、密码找回流程；跨进程失败限制共享与分布式限流未实现；未做 race detector、非 Windows 运行与长期压力。

## 服务端会话、登录与退出（步骤 30）

新增内部会话域 `internal/session` 与 SQLite 生产仓储 `internal/session/sqlite`：把步骤 29 的密码认证结果接入服务端会话，形成普通用户密码登录与退出的完整 Go API 闭环（本步不暴露 HTTP 路由，登录/退出/校验/续期/撤销均由宿主或后续 HTTP 步骤调用）；新增迁移 0010 `sessions`。会话不是 OAuth Access Token / ID Token / Refresh Token，OAuth 模块后续另行实现。

- **秘密与存储**：会话秘密由 `crypto/rand` 生成 256 位随机值，只在签发结果中出现一次（`IssuedSession.Secret` 为 `会话ID.秘密` 形式的凭据，`Secret` 类型默认脱敏）；数据库只保存 `internal/secrets.Keyring` 以当前写密钥派生的 HMAC-SHA256 验证摘要（会话秘密与 CSRF 令牌使用不同摘要域），比较使用 `crypto/subtle` 常量时间比较，秘密原文不进入日志、审计、错误或 URL。会话 ID 是 128 位随机值且校验格式，不可预测但本身不是秘密。
- **普通与受限会话**：只有 `authn.AuthenticateResult.Outcome == complete` 且 `Restricted == false` 且 `RequiredSteps` 为空才签发普通会话；待第二因素、待强制改密只能得到受限会话，`recovery`/`initialization` 受限原因已定义但本步没有签发入口。受限会话可通过 `Validate` 取得身份，但 `AuthorizeBusiness`/`AuthorizeManagement` 一律拒绝。管理访问额外要求 `strong_auth_verified_at_ms` 非空；MFA 未实现，本步没有任何写入该字段的通道，所以普通会话也不能访问管理接口。
- **签发前重读状态**：签发时重新读取 `users.status`、`users.security_version` 与应用/成员状态，必须为 active 且安全版本与认证结果一致；不一致时统一返回 `AUTH_FAILED`（`ErrAccountNotEligible`）并写失败审计，绝不把认证结果快照当作当前状态。
- **到期、轮换与撤销**：空闲到期默认 30 分钟、绝对到期默认 12 小时（可配置且有上下界，绝对期限不得小于空闲期限）；续期只延长空闲到期且不越过绝对到期；每次校验/续期重读账户安全版本与（应用绑定会话的）应用/成员状态，禁用、请求删除、改密带来的安全版本递增、成员移除/停用、应用停用都会让既有会话立即失效。登录成功时若请求携带仍有效的旧会话，它在签发事务中被撤销并签发全新 ID 与秘密（会话固定防护）；退出与 `RevokeAllForUser` 写服务端撤销状态，立即生效且不依赖客户端删除 Cookie；签发与撤销成功审计与数据库变更在同一 `audit.ExecuteCritical` 事务提交，审计不可用时拒绝。
- **Cookie 与 CSRF**：`NewCookie` 默认 `__Host-login_session`（与 `internal/transport` 的 CSRF 默认会话 Cookie 名一致）、Secure、HttpOnly、SameSite=Lax、Path=/、不设 Domain、浏览器会话 Cookie（绝对到期由服务端控制）；`ClearCookie` 以 MaxAge<0 立即失效。会话绑定一次性返还的 CSRF 令牌，`ValidateCSRFToken` 的签名与 `internal/transport` 的 CSRFConfig.ValidateToken / 根包 `CSRFValidator` 一致，可直接接既有 CSRF 中间件；来源（Origin/Referer）允许列表仍由该中间件负责，两者不可互相替代。嵌入式 Go API 可直接传会话秘密，不强制 Cookie；会话秘密只从 Cookie 或 `Authorization: Bearer` 读取，绝不读取查询参数/表单，避免把秘密放进 URL。
- **审计、错误码与脱敏**：签发、轮换、退出与批量撤销写安全审计（目标为会话或用户稳定 ID、类别/受限原因/安全版本/到期时间与撤销原因），不写秘密、摘要或 CSRF 令牌；运行日志只含会话/用户 ID、类别、原因与到期时间。不新增注册错误码：会话无效与签发不可用映射 `AUTH_FAILED(401)`，受限/强认证要求映射 `ACCESS_DENIED(403)`，非法请求映射 `REQ_INVALID(400)`，存储 `DB_UNAVAILABLE(503)`，审计 `AUDIT_WRITE_FAILED(503)`；根包 `session_errorcodes_test.go` 核对登记状态与 Cookie/CSRF 契约一致，注册表仍 46 码。
- **已验证（Windows amd64，临时 SQLite）**：真实 `authn.Authenticate` 密码认证 → 会话签发 → 认证请求校验 → 续期 → 退出的闭环；空闲到期与绝对到期边界（续期不能越过绝对到期）；登录轮换会话 ID 且旧秘密失效（防会话固定）；Cookie 安全属性、CSRF 令牌绑定、错误令牌/无会话/URL 携带秘密拒绝、Bearer 读取；受限会话（待第二因素/待改密）业务与管理访问拒绝、普通会话管理访问因缺强认证拒绝；账户禁用、安全版本变化、应用成员停用、应用停用使会话失效；非成员与安全版本不一致拒绝签发；并发续期安全且撤销后并发续期全部失败；批量撤销共享撤销语义；秘密/CSRF 令牌篡改与跨会话拼接拒绝；清理与构造选项边界；日志与审计不含会话秘密；迁移 0001～0010 计数/结构测试与根包错误码/Cookie/CSRF 契约测试。未做 race detector、HTTP 路由级端到端联调、多进程/多实例共享撤销缓存与非 Windows 运行。

- **已知残余风险（2026-11-16 双审计记录）**：应用成员被停用再恢复后，旧应用会话在空闲到期前可重新生效（会话只比对当前应用/成员状态、不记录成员版本；权限仍每次实时复检，且攻击者仍需持有会话秘密），待后续接入应用成员版本或事务性撤销后彻底解决。本步不暴露 HTTP 路由，CSRF/来源规则目前是契约级验证（Cookie 名、令牌绑定与 `ValidateCSRFToken` 契约和既有中间件一致），未做 HTTP 路由级端到端联调；未运行 race detector、多实例共享撤销与非 Windows/长期压力测试。
- **双审计修复（2026-11-16）**：root 即使收到“完整认证”结果也拒绝签发普通会话（只能受限，MFA 未实现前）、登录轮换时旧会话撤销未生效即 fail-closed 拒绝签发并整体回滚、CSRF 令牌校验复用与 `Validate` 相同的账户状态/安全版本/应用成员检查；补 root、并发轮换、轮换失败与 CSRF 状态回归测试。

## 会话设备列表、强制下线与并发登录策略（步骤 31）

在步骤 30 的 `internal/session` 上继续扩展（不新建重复会话体系）：新增用户设备列表、指定/全部退出、管理员按授权范围强制下线、记住我、最大在线数与单设备替换策略；新增迁移 0011。仍然**不暴露 HTTP 路由**，验收走受信 Go API；管理强认证（MFA）与数据范围裁剪未接入，宿主不得把这些 API 直接暴露为未鉴权 HTTP 管理端点。

- **设备列表（`ListSessions`）**：只允许调用方出示有效普通会话后列出本人活动会话（含当前会话），分页（默认 20、上限 100，`HasMore`/`Total` 与当前会话标记）；其他用户会话不会出现。返回类型 `SessionSummary` 只含展示字段，不含会话秘密、CSRF 令牌、验证摘要或 Cookie。客户端描述字段明确为参考信息：`UserAgent` 由客户端自称、可伪造，不是可信设备身份；`Address` 是可信边界给出的来源地址提示，不是绝对地理位置，两者都不参与授权判断，写入前去除控制字符并截断。
- **用户退出（`RevokeSession`/`RevokeAllOwnSessions`）**：可退出本人指定会话、退出其他设备（保留当前）或退出全部；目标不存在、已失效或不属于调用方时按**幂等无操作**返回（不泄露他人会话是否存在），重复退出确定返回 false/0 而不是错误；撤销立即生效（`Validate`/`Renew` 失败），写 `session.revoke_own` 审计。
- **管理员强制下线（`AdminRevoke`）**：要求普通（非受限）管理会话，并经注入的 `ScopeAuthorizer` 走既有 `internal/authz` 语义检查 `sessions.revoke` 权限与作用范围，不信任客户端自称范围；`ScopeAppID` 非空时只作用于绑定该应用的会话，其他应用/全局会话按幂等无操作处理；按用户撤销时应用范围只撤销该应用会话；root 会话一律拒绝；未接线授权实现或授权拒绝时 fail-closed 返回 `ACCESS_DENIED`；成功与拒绝都写 `session.admin_revoke` 审计并记录真实操作者。`NewAuthzAuthorizer` 是生产适配器：操作者本人检查 `sessions.revoke`，应用范围追加目标保护（目标持有系统管理权限时拒绝应用管理员强制下线）。
- **记住我**：`LoginRequest.RememberMe` 使用独立的绝对到期策略（默认 7 天、可配置，只需落在 5 分钟～30 天的合理上下界内，可短于或长于普通绝对期限），空闲到期与续期规则不变；续期仍不越过绝对到期。设备列表标记 `RememberMe` 便于展示。
- **最大在线数与单设备策略（原子维护）**：`Options.MaxActiveSessions`（0 不限制）与 `Options.DevicePolicy`（`multiple` 默认 / `single`）在登录的同一 `audit.ExecuteCritical` IMMEDIATE 写事务内维护：单设备策略先撤销该账户此前全部活动会话（原因 `replaced_single_device`）再签发；最大在线数用单条条件 UPDATE 保留最近活动的前 N-1 条、撤销其余（原因 `max_active_sessions`），不存在“先查后写”的超限竞态；自动淘汰写独立 `session.eviction` 审计，任何一步失败（含淘汰审计写入失败）整体回滚，不会出现“新会话已签发但旧会话未淘汰”。
- **审计区分**：`session.revoke`（退出当前）、`session.revoke_own`（本人指定/全部退出）、`session.admin_revoke`（管理员强制下线）、`session.eviction`（并发上限/单设备自动淘汰）、`session.account_disabled_revoke`（账户禁用触发的服务端批量退出，`RevokeOnAccountDisabled`，操作者为系统主体）分别可区分；重复撤销幂等且结果确定。所有撤销只联动身份服务当前会话，**不宣称** OAuth Access/Refresh Token 或第三方业务会话已撤销。
- **强认证与范围限制（如实声明）**：管理强制下线要求会话已完成强认证（`CanAccessManagement`）；MFA 未实现，本包没有写入 `strong_auth_verified_at_ms` 的通道，因此默认 fail-closed 拒绝，只有后续管理强认证步骤接线后才放行。`AdminRevoke` 先过强认证闸门与范围级授权、再读取目标，缺强认证/缺授权实现/授权拒绝时对不存在、普通与 root 目标统一返回 `ACCESS_DENIED`，不产生存在性探测差异；应用范围授权适配器读取目标系统权限使用最大页大小，`HasMore` 或来源截断一律拒绝，受保护权限键逐项对照 `internal/preset` 目录。`user_admin` 预设角色默认含系统权限 `sessions.revoke`，但数据范围裁剪尚未完整落地，系统范围强制下线当前只以权限与 root/目标保护为闸门，数据范围收缩仍需后续步骤接入。`RevokeOnAccountDisabled` 需要宿主在 `account.Options.SessionRevoker` 显式接线；未接线时会话层仍按 `users.status` 复查拒绝旧会话，但不会主动撤销记录。
- **已验证（Windows amd64，临时 SQLite）**：设备列表分页/当前会话标记/本人范围/不返回秘密；本人指定退出、退出其他设备、退出全部与幂等重复退出；应用管理员跨应用/全局会话越界无操作、按用户撤销仅限本应用、系统范围按用户撤销、root 目标拒绝、缺强认证/缺授权实现统一拒绝且无存在性差异；8 路并发登录上限 3 时最终活动会话不超过 3、自动淘汰审计可区分、超限复核返回 `ErrConcurrentLimit` 并回滚；单设备替换旧会话立即失效且仅剩 1 条；记住我绝对期限与普通期限独立可配置、续期封顶绝对到期与选项边界；账户禁用触发退出只统计未过期活动会话并写系统主体审计（含 fake `SessionRevoker` 接线）。迁移计数/结构测试与根包错误码映射同步（注册表仍 46 码）。未做 race detector、HTTP 路由级端到端联调、真实 authz 数据范围裁剪联调与非 Windows 运行。

## 邮件发送、模板与可靠投递（步骤 32）

新增内部邮件域 `internal/mailer` 与 SQLite 投递记录 `internal/mailer/sqlite`，迁移 0012 落地 `mail_deliveries` 表；本步**不接 HTTP 页面、不接 `cmd/login-server` 装配、不默认真实外发**，验收走内部 Go API 与 `internal/testmail` 本地捕获器。

- **可注入发送接口与 SMTP 适配**：`mailer.Sender` 是业务依赖的唯一发送契约；`mailer.SMTPSender` 基于标准库 `net/smtp` 实现 STARTTLS、隐式 TLS 与显式回环明文（仅本地测试捕获器，必须显式 `AllowPlaintextLocal`），认证凭据显式配置，单封总时限与 ctx 取消（取消时主动关闭连接），失败给出稳定代码并区分可重试/不可重试（超时/不可达临时，认证失败/缺 STARTTLS/5xx 永久）。**证书校验不可关闭**：没有 `InsecureSkipVerify` 入口，测试自签证书通过 `TrustedRoots` 注入根证书完成校验。
- **模板与注入防护**：`TemplateSet` 用 `text/template` 区分邮箱验证、密码找回与敏感操作告知三种用途；数据字段拒绝 CR/LF 与控制字符，链接仅允许 http/https 且不得含凭证，渲染后主题再次做头部安全检查；`Message` 构建拒绝头部注入、主题按 RFC 2047 编码、正文用 base64 + CRLF，地址严格校验（拒绝换行、控制字符、非法域名、地址字面量与超长地址）。
- **可靠投递**：`DeliveryService` 以幂等键入队（`mail_deliveries.idempotency_key` 唯一约束，重复入队返回既有记录且不重复建任务），模板数据（验证码/一次性链接）经 `internal/secrets` 加密后以 BLOB 落库并绑定投递记录 ID，任务载荷只含记录 ID、不打印正文/秘密；状态为 queued/sending/succeeded/failed/cancelled，永久失败返回 `task.NonRetryable`，可重试失败按任务退避重试；`Retry` 只允许 failed 状态并需要授权（未配置授权器 fail-closed）；审计区分入队/入队失败/成功/失败/计划重试/受控重试。**通知失败不回滚已完成的安全操作**：投递是安全操作之后的独立任务，两者不共享事务。
- **授权与可靠性边界（审计退修）**：入队/查询/重试都接受可信 `Caller`（`SystemCaller`/`LocalAdminCaller`/`UserCaller`）并可选配置 `Authorizer` 做记录级数据范围检查；未配置授权器时只有受信 system/local_admin 主体放行（普通用户 fail-closed），幂等键只允许同归属主体取回既有记录，禁止跨调用者用幂等键探测或取回他人收件人/状态。受控重试先 CAS `failed→queued` 成功后才入队，入队失败回写 `failed` + `MAIL_QUEUE_FAILED`（不留无主 queued），任务设置 `MutexKey=投递ID` 串行化同一投递；发送成功/失败/取消的终态写入使用剥离取消的 context，保证发送中途取消后不会停在 `sending`。返回给任务层的错误只保留稳定分类/代码，不回传 SMTP 回显（避免 `failure_reason` 出现收件人）。已知限制：主密钥轮换必须保留历史密钥（queued 记录在旧密钥退役后解密失败并按不可重试失败处理，fail-closed）；多实例投递互斥与 `sending` 残留的启动对账尚未实现；`checkURL` 允许 http 仅为本地测试，生产应只生成 https 链接。
- **语义与边界**：外部邮件系统**不保证恰好一次送达**，本实现是"至少一次 + 幂等键去重"；任务重试可能产生重复邮件，业务不得把发送成功当作唯一性凭据。默认只有显式配置 SMTP 适配与测试收件地址才会真实发送；测试使用 `internal/testmail`，不向真实用户地址群发。

## 自主注册与邮箱验证（步骤 33）

新增内部注册域 `internal/registration` 与 SQLite 仓储 `internal/registration/sqlite`，迁移 0013 落地 `email_verification_tickets` 表；本步**不暴露 HTTP 路由、不接 `cmd/login-server` 装配、不签发会话**，验收走内部 Go API 与真实 `internal/authn`/`internal/credential`/`internal/audit` 依赖。

- **按配置开放**：根配置新增 `registration.enabled`（默认 false，默认拒绝）、`registration.require_review`、`registration.require_email_verification` 与 `registration.default_role_ids`，对应固定环境变量 `LOGIN_REGISTRATION_ENABLED` 等；关闭时注册返回 `AUTH_FAILED`，管理员创建账户走 `internal/account` 不受影响。
- **字段白名单与输入校验**：`RegisterRequest` 只含用户名、密码、可选邮箱与基础资料；`ParseRegisterJSON` 用严格 JSON 解码拒绝 `is_root`、系统角色、应用成员、`email_verified`、`status` 等未知字段。用户名/昵称/语言/时区复用 `internal/account` 规范化与保留名规则，密码复用 `internal/authn` 的 Argon2id 与密码策略。
- **邮箱可选**：无邮箱注册在未要求邮箱验证的配置下正常创建 active 账户并可密码登录；提供邮箱时创建未验证 `user_emails` 行并签发一次性验证入口。验证成功前 `verified_at_ms` 为 NULL，因此已验证邮箱登录/恢复能力不会启用，注册结果只表示"验证邮件是否交给发送方"，**不会宣称邮箱已验证**。
- **一次性验证入口**：令牌使用 `internal/credential` 高熵令牌（用途 `email.verify`、目标用户 ID），只消费一次；迁移 0013 的票据把用户、待验证地址、凭证 ID 与有效期绑定。重发受冷却限制并覆盖票据：先提交新票据、成功后清理旧凭证，替换目标邮箱失败（例如被占用）时旧票据与旧凭证保持原样，**不会误废仍有效的旧链接**；旧链接最终以票据绑定的凭证 ID 不匹配而失效。替换待验证地址会删除旧未验证行、使旧入口失效，并保持 `email_normalized` 唯一性（并发同邮箱只有一个成功）。完成验证在审计事务内条件更新邮箱行并删除票据，条件不满足整体拒绝、不部分修改用户。
- **防枚举与失败语义**：用户名或邮箱占用统一返回 `CONFLICT`，验证失败统一返回 `CHALLENGE_INVALID`，重发冷却返回 `RATE_LIMITED`；创建、验证入口签发与验证完成均与审计同事务，审计不可用 fail-closed。邮件发送失败只记录 `MAIL_DELIVERY_FAILED` 状态、不回滚账户或票据，可在冷却后重发；验证令牌不写入日志、审计或数据库明文。注意：注册成功与用户名/邮箱冲突在接口层仍是二值结果，HTTP 层暴露前必须让两者在响应形状、状态码与耗时上不可区分，并叠加 IP 限流/验证码/邮件频率限制（本步均未实现）。凭证消费发生在完成邮箱验证的审计事务之外：若邮箱行条件更新或审计失败，已消费的一次性令牌不会恢复，只能重新发送验证入口（fail-closed，不会误报已验证）。
- **待审核与默认角色**：`require_review` 为 true 时以 `pending` 创建账户，`internal/authn` 对非 active 账户统一拒绝正常登录（审核执行留给后续步骤）；默认角色只来自宿主可信配置且**只接受 system 作用域**（服务构造时拒绝应用作用域），由存储层校验"存在、已启用、作用域匹配"后直接写入 `user_roles`，**不自动加入任何应用成员**。应用角色作为注册默认角色需要走 `internal/role`/`internal/delegation` 的赋权与委派校验，本步未实现、也不应绕过。
- **已知限制**：注册/重发的 HTTP 路由、验证入口页面与 `cmd/login-server` 装配尚未实现（`registration.*` 配置目前只被 `Config`/`Load` 校验，没有启动装配消费者）；注册 IP 限流、CAPTCHA、邮件发送频率限制与公开错误不可区分响应未实现；过期 `email_verification_tickets` 的定时清理任务未实现（每用户单行、覆盖写，不会无限增长，但历史行需手动/后续任务清理）；已验证邮箱的变更（个人资料加邮箱）与人工审核执行留给后续步骤；`DefaultRoles` 直写 `user_roles` 仅限 system 作用域可信配置；本包不签发会话或 Token。


## 用户批量导入导出、幂等与结果报告（步骤 61）

新增 `internal/userbatch`（含 `sqlite/`）与迁移 `0039_user_batch.sql`（`user_batch_jobs`/`user_batch_rows`），在现有 `internal/account` 创建/查询白名单与 `internal/authz` 数据范围之上实现有限规模 CSV 批量导入导出；**不是任意数据库迁移/备份工具**。不提供 HTTP 路由/页面/CLI，异步执行由宿主把 Handler 注册到 `internal/task` 执行器。

- **导入格式与白名单**：仅 UTF-8 CSV（可选 BOM；拒绝 UTF-16/非法编码/空字符），默认 ≤5 MiB、≤10,000 行（硬上限 50,000）、单字段 ≤2,048 字节；表头严格白名单 `username,nickname,biography,language,timezone`（顺序无关、大小写不敏感）；未知列**整文件拒绝**，`password/password_hash/email/email_verified/phone/status/is_root/security_version/roles/permissions/mfa/totp/passkey/recovery_codes/token/user_id/...` 出现即整文件拒绝（不静默忽略）。导入只调用 `account.CreateUser` 的资料白名单，不导入密码哈希、root、管理资格、已验证状态、MFA 秘密或越权角色；`openid`/应用成员/应用内资料不在本步。
- **幂等与重复处理**：预检查（`PrecheckImport`）与正式执行分离；幂等键（8～128 可见 ASCII）绑定调用者身份+作用域+请求摘要（文件 SHA-256 + 规范化选项）：同键不同摘要 `CONFLICT`、同键同摘要返回既有任务不重复入队、不同调用者不可复用；重复用户以规范化用户名为稳定匹配键：不存在→`created`，已存在且资料相同→`skipped`，资料不同→`conflict`（**v1 不更新既有用户**），root/受保护账户→`denied`；并发/重复行由用户名唯一约束兜底，不产生第二个用户。
- **分批策略、取消与续跑**：逐行独立事务（非全文件原子），单行失败只记该行结果；任务状态 `queued/running/succeeded/partial/failed/cancelled`，`succeeded` 只表示执行完成、汇总计数展示真实成功/跳过/冲突/失败/拒绝数；每批（默认 50 行）用注入的 `Authorizer` 复验资格，中途撤权立即停止（`ACCESS_DENIED`，已提交行保留）；`Cancel` 记录真实执行人/原因，`(job_id,row_number)` 主键使重启/受控 `Retry` 续跑跳过已处理行。
- **导出与隐私**：字段只允许从默认白名单（`user_id,username,nickname,language,timezone,status,created_at,updated_at`）减少；`biography` 等自由文本默认不导出，需显式选项且策略要求近期强认证；**永不导出**邮箱/电话/密码哈希/MFA/恢复码/令牌/会话秘密；逐用户经注入的 `UserScopeAuthorizer`（生产适配 `internal/authz.CheckResourceAccess`）判定数据范围，缺失/失败 fail-closed；默认 ≤10,000 行（硬上限 100,000），超出置 `truncated` + `REPORT_DATA_INCOMPLETE`；导出文件写入宿主 `Options.OutputDir`（绝对、已存在、非符号链接）下服务端生成文件名（`O_EXCL`、0600），返回路径与 SHA-256。
- **报告与 CSV 防注入**：逐行结果 `row_number/action/error_code/reason_code/username_normalized/user_id`（不含原始行/秘密），明细有上限并标记截断；`ReportCSV` 只有任务所有者/系统可读（跨身份 `REPORT_ACCESS_DENIED`）；导出 CSV 与报告 CSV 全部文本单元格做公式注入防护（首字符 `= + - @` 或 TAB/CR/LF 时前置 `'`）。
- **权限与错误码**：新增敏感操作 `user.bulk.import`（权限键 `users.create`）/`user.bulk.export`（`users.export`），默认强认证+确认，经 `internal/reauth` 绑定操作参数摘要，拒绝路径写失败审计；错误码复用既有 48 码（`REQ_INVALID/CONFLICT/ACCESS_DENIED/EXPORT_PATH_UNSAFE/REPORT_*/TASK_*/DB_UNAVAILABLE/AUDIT_WRITE_FAILED`），不新增注册码；迁移 `0039` + 结构断言并同步 4 处迁移计数（38→39）。
- **边界/装配前置与已知限制**：与步骤 60 业务托管管理 API 分离——本步是系统管理侧批量工具，只消费调用者对 `users.create/users.export` 的资格与数据范围，不内建业务应用委托/字段级授权（宿主可用步骤 60 适配器包装）；不实现应用成员/应用内资料/角色导入；不提供 HTTP/CLI/页面、跨实例任务互斥、真实下载分发、导入文件持久化保留策略（导入文件 BLOB 在任务终态后清空）；未做真实大规模文件/race/非 Windows 验证。

- **审计修复语义（2026-11-18）**：导出 handler 使用**任务局部上限**（绝不回写共享 Service 字段，并发导出互不影响；配置保持不变）；逐行结果/报告改为**分页读取到真实总数**（SQL 单页 100、服务端按 `(job_id,row_number)` 拼接，明细上限默认 5000），`truncated` 按真实总数计算，`ListRows` 返回该值、`ReportCSV` 返回 `(CSV, truncated, error)` 并在每行 `report_truncated` 列显式标记；导入在**处理首行前**与每批复验权限、导出**每页**复验 `users.export`，中途撤权 → 任务 `failed`+`ACCESS_DENIED`（不 succeeded/不静默跳过）；`failed` 保留导入输入供受控 `Retry` 真正续跑（`succeeded/partial/cancelled` 才清空），崩溃遗留 `running` 由宿主启动时 `ReconcileInterrupted` 收敛为 `failed`（`TASK_TIMEOUT`）使 Retry 可达，任务墙钟到期 → `failed`+`TASK_TIMEOUT`（取消才写 cancelled），并提供 `CleanupExpiredInputs`；导出扫描量硬上限（任务上限 10 倍、≥1000、≤1,000,000）；构造时若配置导出目录但缺少 `UserScopeAuthorizer` 直接拒绝；`newJobID` 随机源失败返回错误而非 panic。

## 响应式页面框架、页面替换与国际化基础（步骤 62）

页面阶段起点：新增内置 Web 页面框架 `login.NewWebUI`（契约版本 **ui.v1**）与 `web/` 目录（Go `html/template` + `embed` + 原生 CSS/ES 模块；不引入 Node/npm、不加载任何第三方在线资源），迁移/错误码/依赖均未新增。页面可被宿主按命名路由替换，也可整体禁用；核心 Go API、受保护业务 API 与标准 OAuth/OIDC 端点不受影响。

- **公开契约（根包 `login`）**：`UIContractVersion`、`UIRoute`（命名路由/方法/路径/访问级别/布局/模板/模块）、`UIPageContext`（契约版本、路由、BasePath、CanonicalURL、Locale、RequestID、公开会话摘要、品牌、导航、CSRF、状态/错误/字段错误、页面 DTO `Data`）、`UIPageRenderer`、`UIHostTemplates`/`UITemplateOverride`、`UICatalogProvider`、`UISessionService`、`UINavigationProvider`、`WebUIOptions`/`NewWebUI`。内置系统页面：`system.forbidden`/`system.not_found`/`system.session_expired`/`system.error`（另仅测试/示例注册 `ui.component_preview`）。
- **替换优先级（冻结）**：宿主单页渲染器 `HostRenderer` > 宿主模板同路由覆盖 `HostTemplates` > 内置嵌入模板。宿主模板在构造时解析，语法/契约错误**启动失败**，不静默回退掩盖错误；宿主渲染器运行错误明确 500。`DisableBuiltinPages=true` 关闭内置 HTML 路由（404，不伪装成功页），宿主必须用渲染器/模板提供页面；健康与 OpenAPI 等核心 API 继续可用。
- **传输层接线**：`HTTPOptions.UI`（`Handler` + `PageContentSecurityPolicy`）把页面挂载到既有 `internal/transport`：API 精确路由（健康/OpenAPI）优先，OAuth/OIDC 保留空间仍 404，其余路径交给页面前复用同一请求编号、访问日志、客户端 IP 限流与 CSRF 中间件；HTML 显式使用页面 CSP（默认 `DefaultUIPageContentSecurityPolicy`：仅 `'self'` 脚本/样式/图片/连接、`object-src 'none'`、`base-uri 'none'`、`form-action 'self'`、`frame-ancestors 'none'`，禁止 `unsafe-inline`/`unsafe-eval`），HTML `no-store`；带内容指纹的本地静态资源 `immutable`，路径穿越/编码斜杠/反斜杠拒绝。页面请求不使用 API CORS 头，传输层不为页面建立 API Identity（页面经 `UISessionService` 自建会话摘要）。
- **会话与 CSRF**：页面不自己解析 Cookie 身份，统一经宿主注入的 `UISessionService`（生产实现应调用 `internal/session` 的 `Validate`/`AuthorizeBusiness`/`AuthorizeManagement` 与 `IssuePageCSRFToken`）；未登录/过期 → 401 状态页，受限会话 → 受限/403 状态页，页面不渲染后再靠前端禁用。**无 JavaScript 表单 CSRF**：`internal/session` 新增与会话绑定的确定性页面令牌派生 `IssuePageCSRFToken`（HMAC-SHA256，不写库；登录轮换/撤销/密钥退役自然失效；既有随机 CSRF 令牌继续有效，`ValidateCSRFToken` 对两类令牌都做活动会话复核与常数时间比较），`internal/transport` 在不安全方法上接受单一 `csrf_token` 隐藏字段（仅 `application/x-www-form-urlencoded`，读取上限 64 KiB 并恢复请求体，重复/空值/解析失败 fail-closed），仍调用同一 `ValidateCSRFToken` 并保留 Origin/Referer 校验；令牌不进 URL/localStorage/日志/审计。
- **组件与状态**：base/auth 布局（skip link、header/nav/唯一 main、登录/受限流程）、按钮、表单字段、错误摘要、横幅、表格（caption/th scope/局部横向滚动）、分页（不伪造总页数）、确认内容、加载/空/无结果/无权限/会话过期/受限/未启用/离线/冲突/成功/失败状态；原生 `<dialog>` 确认增强与异步表单防重复，卸载时清理监听；无 JS 时核心导航/表单/错误摘要仍可用。响应式断点 320/375/768/1024、4px 间距、系统字体、深浅色/强制颜色/减少动态、200% 文本使用 rem/em；不可信内容一律 `html/template` 转义，无通用 `raw_html`。
- **国际化**：内置 `web/i18n/zh-CN.json`（zh-CN 完整基线）与 `t`/`t_fmt`/`label` 模板函数、命名占位符；语言协商按 `Accept-Language`/已登录偏好（宿主可扩展）与真实提供目录，未提供语言回退 zh-CN；zh-TW/en-US/ja-JP 预留但**未提供真实翻译**，不展示语言切换、不伪翻译；键缺失回退 zh-CN 并记录键名，不记录用户秘密。品牌 `UIBrand{Name, LogoAsset, Theme}` 由宿主选项提供，Logo 仅本地资源。
- **已知限制**：真实浏览器/375/768/1024/320 视口、读屏、200% 文本与真机**未实测**（本步以服务端渲染断言、CSS 静态检查与人工清单代替，报告如实分列）；外部宿主的 session 服务实例装配需等后续 instance/HTTP 装配步骤（本步以模块内真实会话集成测试与 `examples/ui-pages` 证明契约，示例仅用公开包）；`ui.component_preview` 仅测试/示例、不进入生产导航且不代表业务完成；未新增 YAML `ui.*` 配置（品牌/替换/禁用由程序化选项控制）；页面渲染错误统一 500 页，不含堆栈；数据范围/强认证等业务授权仍由后续页面步骤逐页接入。

## 业务托管管理 API 的操作、对象与字段授权（步骤 60）

新增 `internal/managedapi`（含 `sqlite/`）与迁移 `0038_managed_api_policies.sql`，把既有用户、应用成员、用户组、角色与权限服务封装为**可委托给业务应用**的受保护管理 Go API。新增敏感操作 `managed_api.policy.manage`（默认近期强认证）。**无新增错误码**（复用既有登记码）；不注册 HTTP 全局路由、不开发页面（HTTP/页面属后续装配步骤），不新增根配置项。

- **应用级委托策略**：每个应用一行策略（默认无策略=关闭）：允许操作集合、服务身份允许操作子集、对象范围（仅应用作用域，`all` 或显式资源 ID 列表）、可读/可写字段白名单、`max_limit`/`max_offset`/`max_batch` 上限。策略由 `SetPolicy` 受信通道写入：必须 root/本地管理员/系统组件白名单 + `managed_api.policy.manage` 近期认证 + 行版本条件更新 + 同事务审计；未知操作/字段/对象类型、硬禁敏感字段、system 作用域与越界上限在写入前拒绝，非法配置不落库。
- **调用主体**：`UserPrincipal` 必须出示真实完整普通会话秘密（`internal/session` 校验）且目标应用与宿主可信上下文/会话应用一致（不一致 `RESOURCE_FORBIDDEN`）；`ServicePrincipal` 必须通过客户端 secret/证书认证（`internal/oauthclient`），主体是应用自身、不借用用户权限。请求参数不能自称用户/应用/字段权限。
- **授权流水线**：API 版本（`v1`）与 request_id → 主体/策略/操作允许检查 → 代表用户 `internal/authz` 实时权限（all 模式）与数据范围交集（**数据范围 undefined/none 一律 fail-closed**）→ 对象范围与目标检查（先授权后读目标）→ 写入字段白名单 → 分页/排序/筛选/批量上限 → 调用既有服务（真实用户 Caller 保留 `delegation.Guard` 与既有审计）→ 托管调用审计。所有列表与子资源读取（成员/组/角色/权限列表、角色权限组合、角色分配的用户/组）在投影前同时按对应对象的策略范围与代表用户数据范围过滤；列表所需对象类型未在策略中声明范围时 fail-closed 拒绝（不把"未配置"当"全部可见"）。底层既有服务返回的业务错误码（如 `CONFLICT`/`PERMISSION_REQUIRED`/`APP_MEMBERSHIP_REQUIRED`/`ACCESS_DENIED`）原样映射给调用方，不退化为 `INTERNAL_ERROR`。宿主必须把本包提供的 `DelegatedAuthorizer` 族注入既有服务：无托管 grant 的直接调用一律拒绝，防止绕过托管层。
- **字段与敏感能力**：应用资料读取（`application.get`）要求代表用户是目标应用的有效成员（非成员按成员关系缺失拒绝，服务身份为应用自身除外）；输出按对象类型固定字段表 + 策略可读白名单投影；密码哈希、MFA/TOTP 种子、恢复代码、Token/会话秘密、私钥、`is_root`、`security_version`、完整邮箱/电话为硬禁字段，永不输出也不能写进策略。写入使用明确请求类型与指针字段区分"未设置"，未授权字段直接 `REQ_INVALID`（不静默丢弃）；应用内成员资料与全局资料分离，成员资料更新只写应用内 profile。
- **服务身份默认只读**：目录中服务身份允许的操作**仅**为只读查询与"创建全新账户并建立本应用成员关系"（不授予既有权限）；成员资料写入、成员启停/移除、组成员增删、角色/权限变更等任何写操作一律不允许服务身份（`ServiceAllowed=false`，即使策略显式列出也会拒绝），避免借用受信 system 通道绕过委派 Guard 或扩大破坏面。代表用户的权限变更写操作经既有服务真实用户 Caller 走 `delegation.Guard`。
- **共享账户受控**：创建账户只能创建全新用户名并建立本应用成员关系，同一用户名已存在不会被认领/关联（明确拒绝，不按用户名绑定已有账户）；全局密码重置、MFA 解除、账户删除/禁用、root/系统资格、应用凭证、系统角色/权限、导入导出不在操作目录，直接按未知/越权拒绝。
- **分页与探测防护**：列表在既有服务作用域内分页（limit/offset 受策略与全局硬上限），排序/筛选字段必须属于对象白名单且可读，未知字段拒绝；结果再按策略对象范围与数据范围过滤；跨应用对象不进入结果；批量成员操作仅使用既有原子服务并受 `max_batch` 限制，超限直接拒绝且无部分写入；`HasMore` 如实返回。
- **审计**：每次托管调用（成功/拒绝）写 `managed_api.<operation>` 审计：真实操作者（用户或 `managed-service:<client_id>` 系统身份）、调用应用、目标对象、request_id、稳定错误码/内部原因；不记录字段值/秘密；拒绝在调用既有服务前写入。既有服务自身审计保留。策略修改与成功审计同事务。
- **已知限制**：数据范围写入路径尚未落地，角色分配默认 `{}`（undefined）→ 在托管 API 中 fail-closed（与 authz/delegation 一致），需先为管理员角色配置 `all`/`resources` 数据范围才能使用托管 API；HTTP 路由、传输层限流、OpenAPI 与页面（步骤 70）未做；`users.create_with_membership` 先建账户后建成员关系，非单事务（成员失败会记录并返回错误，不宣称全成功）；未实现多目标非原子批量写、导入导出（步骤 61 独立受控路径）；多实例/race/非 Windows 未验证。

## 应用安全事件 Webhook、重试与退出通知（步骤 59）

新增 `internal/webhook`（含 `sqlite/`）、`internal/netguard`、`internal/securityevent` 与迁移 `0037_webhook_delivery.sql`（`webhook_endpoints`/`webhook_endpoint_secrets`/`webhook_events`/`webhook_deliveries`）。实现应用级签名 Webhook：端点与签名密钥受控管理、事件幂等落库并按应用扇出、`internal/task` 承载的有界重试与失败查询、取消与受控重试；**不建 HTTP 路由/页面、不启动后台协程、不真实外发**（测试只使用本地 httptest 捕获端）。

- **端点与签名密钥**：`RegisterEndpoint/UpdateEndpoint/ListEndpoints` 要求应用启用、`Authorizer` 按应用范围判定，并经 `internal/reauth` 新增敏感操作 `application.webhook.endpoint.change`（强认证/确认，缺失 fail-closed）；URL 在登记与**每次投递前**都经 `internal/netguard` 重新校验。`RotateSecret/RevokeSecret` 使用 `application.webhook.secret.rotate`：签名密钥为 32 字节随机、明文只在创建/轮换响应出现一次，库中只存 `secrets.Sealer` 认证加密密文 + 前缀 + `sealer_key_id`；每个端点最多 2 个可用密钥，轮换把旧密钥置过渡期退役（默认 24h，边界 1min～30d），过渡期内签名头同时给出两个 `v1`，退役/撤销后旧密钥立即不再签名。
- **签名与消费方验证契约**：请求头 `X-Evernight-Event-Id/-Event-Type/-Delivery-Id/-Timestamp/-Signature`；签名头 `t=<unix>,v1=<hex>[,v1=<hex>]`，签名覆盖 `"<t>." + 实际传输的原始 body 字节`（HMAC-SHA256）；重试重新生成时间戳但事件 ID 不变。消费方应按 `examples/webhookverify` 的步骤：读取原始字节→用自己保存的密钥恒时比较任一 `v1`→校验时间窗（默认 300s）→按事件 ID 去重后再处理。**至少一次送达，可能重复，不承诺网络恰好一次**。
- **事件与退出通知接线**：`internal/securityevent` 定义最小共享事件模型；产生方在业务/审计事务**提交后**调用可选 `Emitter`（失败只记运行日志，不回滚已完成操作）：账户禁用/启用（`user.disabled/enabled`）、会话退出/批量撤销（`session.logged_out/all_revoked`）、授权撤回（`oauth.authorization.revoked`）、退出应用（`app.logout`）、应用成员变更（`app.membership.changed`）。用户级事件按“该用户仍为 active 成员的应用”扇出（上限 100 个端点，截断标记可查询）。事件 payload 为严格白名单最小字段，不含密码/令牌/会话秘密/自由文本。
- **SSRF 与资源限制**：仅 https（生产默认端口），拒绝 userinfo/片段；每次真实连接前重新解析 DNS 并要求全部结果为公网地址、直连校验过的 IP（防 DNS 重绑定）；拒绝环回/私有/链路本地/CGNAT/保留/文档/隧道网段与 IPv4-mapped；默认**不跟随重定向**（可配制 0～2 次且逐次复核）；禁用环境代理与自动解压；响应体读取上限 64KiB、单次超时默认 10s。`TestOnlyAllowLocalEndpoints` 只允许测试使用，生产禁止启用。
- **可靠投递、超时与重试语义**：事件与投递在同一 DB 事务内创建（幂等键唯一，重复 `Emit` 返回既有记录不重复投递）；每个 `(事件, endpoint)` 唯一一条投递，`internal/task` 执行有界重试（默认 5 次，1～10、指数退避）。**单次 HTTP 请求超时由服务自动推导为严格小于任务墙钟预算**（约墙钟 60%，且至少比墙钟少 2 秒、不低于 netguard 下限），因此慢/挂起端点会先以网络超时进入可重试失败；超时记录 `TASK_TIMEOUT` + `timeout` 原因：**单次 HTTP 请求超时且任务墙钟仍有余量**时未耗尽回 `queued` 按退避重试、耗尽写 `failed`；**任务墙钟到期**时执行器不会重排该任务，直接写 `failed` 使 `RetryDelivery` 可受控重试（不写 `queued` 以免卡住），**只有明确取消（context.Canceled/用户取消）才写 `cancelled`/`TASK_CANCELLED`**。2xx 成功；408/425/429/5xx 与网络错误可重试；其余 4xx/不安全重定向/端点或应用停用/无可用密钥为永久失败，终态写 `WEBHOOK_DELIVERY_FAILED` 与响应状态并可查询。**端点失效不回滚已完成撤销/禁用**。
- **明确不做**：不实现 OIDC RP-Initiated Logout / Back-Channel Logout 标准协议，Discovery 不声明 `end_session_endpoint`，本自定义 Webhook 不得冒称标准 OIDC 退出（属明确未实现范围）；不实现 Webhook 管理 HTTP 接口、跨实例投递互斥、过期记录清理任务与真实外网端点验证。
- **装配前置与已知限制**：宿主需注入 `Store/Audit/Authorizer/Sensitive/Sealer/Enqueuer`（`Canceller` 缺失时取消不可用），把 `Handler` 注册为任务类型 `webhook.delivery`，并把 `Service` 作为 `securityevent.Emitter` 注入 account/session/oauthflow/app；`token`/`webhook` 载荷不含秘密。未做真实外网投递（本地 httptest 捕获端验证签名与重试）、未做多实例/race/非 Windows；错误码注册表新增 `WEBHOOK_DELIVERY_FAILED`/`WEBHOOK_ENDPOINT_BLOCKED`（46→48，手册同步）。

## 已登录 APP 扫码确认网页登录（步骤 58）

新增 `internal/qrlogin`（含 `sqlite/`）与迁移 `0036_app_qr_login.sql`；这是与标准设备码授权（步骤 57）**分别命名、分别存储**的自定义登录流程。新增根配置 `app_qr_login.*`（默认关闭，启用时必须显式配置应用白名单）。**无新增错误码**（复用既有 46 码）；不启动监听、不注册 HTTP 全局路由、不渲染页面/二维码图片（HTTP/页面属后续装配步骤）。

- **发起端（网页）**：`Begin` 创建短时请求，返回一次性高熵领取绑定（`ClaimSecret`，库中只存 keyring HMAC-SHA256 摘要+key_id）与二维码载荷；二维码只含一次性请求标识 `evernight-login://app-qr?v=1&r=qrl_...`，**不含任何长期 Token/密码/会话秘密/领取绑定**。`ParseQRPayload` 严格校验固定 scheme/host/version 与唯一参数，拒绝 URL 主机、额外参数、userinfo/fragment/重复参数；APP 永远调用宿主配置的固定签发方地址，不信任二维码里的主机。
- **确认端（APP）**：`Describe`/`Approve`/`Deny` 必须出示真实完整普通会话（`internal/session.Validate`，受限会话拒绝）；应用作用域会话只能确认本应用请求（跨应用 `ACCESS_DENIED`）。`Approve` 按步骤 39 敏感策略经 `internal/reauth.OperationRunner`（新操作 `app.qr_login.approve`，默认近期密码认证 300 秒）要求近期认证，未接线/拒绝一律拒绝；批准在审计事务内条件更新（版本匹配、未过期、pending），绑定用户+会话+安全版本+认证方法快照，并发批准单赢家。`Deny` 不要求再次认证。
- **确认页上下文**：展示可信应用名/ID、客户端类型、请求 scope（仅展示，不是 Token 授权）、发起端 UA/地址/创建时间、有效期与固定风险提醒（"只确认本人正在登录的浏览器，不要确认他人发来的二维码"）；不展示任何秘密。
- **领取与状态**：`Status`/`Claim`/`Cancel`/`Regenerate` 均需同时提交请求标识与领取绑定；服务端强制最小查询间隔（默认 1 秒）。`Claim` 只允许 approved 且未过期：重新核对客户端/应用启用、应用白名单、账户 active 与安全版本快照、目标应用成员状态、**确认端会话仍有效**（`session.VerifyActiveSession`，撤销/过期/账户变化即拒绝），再由门控原子消费批准（approved→claimed，并发单赢家）并调用 `internal/session` 的受门控登录批准签发**目标应用会话**（只发会话，不发 Access/ID/Refresh Token，不创造通用 Token 交换后门）。重复领取返回已领取；拒绝/取消/过期分别返回稳定错误码。
- **状态与错误码**：请求状态 pending/approved/denied/cancelled/claimed，过期由 `expires_at` 惰性派生（不作为系统故障）；业务拒绝复用 `ACCESS_DENIED`/`CHALLENGE_INVALID`/`CONFLICT`/`AUTH_FAILED`/`RATE_LIMITED`/`CLIENT_DISABLED`/`DB_UNAVAILABLE`/`AUDIT_WRITE_FAILED` 等既有码，错误领取凭据与不存在统一为 `CHALLENGE_INVALID`，避免状态探测。所有创建/批准/拒绝/取消/重新生成/领取/失败均写安全审计（真实用户/系统主体、稳定 ID、request_id，不含领取绑定/二维码/会话秘密）；状态变更与成功审计同事务。
- **取消与重新生成**：`Cancel` 使 pending/approved 请求失效；`Regenerate` 在同一审计事务内取消旧请求并创建新请求（新请求标识与新领取绑定），旧二维码/旧领取绑定立即不可用。过期/终态请求惰性处理；本步不实现后台清理任务（后续维护任务可补充批量清理入口）。
- **已知限制**：①不做完整二维码钓鱼防护（任何扫码登录都要求用户核对发起端上下文并只确认本人操作，提醒文案已内置，残余社会工程风险如实声明）；②APP 与会话的绑定沿用步骤 57 语义：应用作用域会话需匹配目标应用，未绑定应用的全局普通会话可确认（用户身份来自真实会话，不由请求参数自称）；③本步只交付 Go API + 测试 + 可运行示例，HTTP 路由/传输层限流/页面（步骤 65）与 `cmd/login-server` 装配未做；④未做多实例/race/非 Windows 运行验证；⑤扫码登录不会签发 Token，后续访问令牌仍需标准 OAuth 授权流程。

## 设备码授权（Device Authorization Grant，步骤 57）

扩展 `internal/oauthflow` 实现标准 OAuth 2.0 设备授权（RFC 8628），迁移 `0035_oauth_device_authorization.sql` 落地 `oauth_device_authorizations`（高熵设备码只存无密钥 SHA-256 摘要；低熵人工短码只存**带密钥 HMAC-SHA256 摘要 + `user_code_key_id`**（密钥环缺失/不可用 fail-closed）、客户端与 Scope/audience 绑定、pending/approved/denied/cancelled/consumed 状态机、用户/会话/安全版本快照、服务端轮询间隔）。本步只提供可信 Go API，不建页面/HTTP 路由，二维码由页面层用 `verification_uri_complete` 渲染。

- **申请（设备侧）**：`BeginDeviceAuthorization` 校验客户端已登记 `urn:ietf:params:oauth:grant-type:device_code` 且应用启用；保密客户端必须完成 secret/证书认证，公开客户端只需 `client_id`；Scope/audience 必须属于客户端登记范围（audience 省略时仅唯一目标资源可默认）。返回 `device_code`（32 字节高熵，库里只存无密钥 SHA-256 摘要：256 bit 熵不可枚举）、8 字符 base20 人工短码（20^8 ≈ 34.6 bit，显示形如 `ABCD-EFGH`；低熵值**只存带密钥 HMAC-SHA256 摘要**并记录 `user_code_key_id`，密钥由宿主 `Options.DeviceUserCodeKeyring` 注入、支持密钥环轮换，绝不使用无密钥摘要）、`verification_uri`、可渲染为二维码的 `verification_uri_complete`、`expires_in`（默认 600 秒）与 `interval`（默认 5 秒）。未配置 `Options.DeviceVerificationURI` 时 fail-closed 返回 `temporarily_unavailable`，不创建无法确认的请求；启用设备流但缺少短码密钥环时 `New` 直接拒绝构造（fail-closed）。
- **确认（另一台设备浏览器）**：`DescribeDeviceAuthorization` 必须使用真实完整普通会话按短码查询，返回可信应用、Scope、audience 与有效期（应用展示名由页面层补充）；`DecideDeviceAuthorization` 显式批准或拒绝，批准前经 `internal/reauth` 敏感操作 `oauth.device.authorization.approve`（默认近期主认证 300 秒，未接线 fail-closed），批准绑定用户+会话+安全版本快照并为 `approved`；拒绝不签发任何令牌。短码输入大小写/连字符不敏感。
- **猜码限流**：无效短码查询/决定按用户维度固定窗口限流（默认 10 次/10 分钟），超限返回 `RATE_LIMITED`；短码错误统一返回 `REQ_INVALID`，不区分不存在/已决定/已过期。
- **轮询领取**：Token 端点支持 `grant_type=urn:ietf:params:oauth:grant-type:device_code`。等待返回 `authorization_pending`；快于服务端间隔返回 `slow_down` 并按上限增大间隔（持久化，`OAuthError.RetryAfter` 供宿主设置 `Retry-After`）；过期 `expired_token`；拒绝/取消 `access_denied`；设备码不存在/换客户端/已领取/确认后状态变化 `invalid_grant`。成功领取在审计事务内条件迁移 `approved→consumed`（并发单赢家，只签发一次），领取前重检用户 active、安全版本、应用成员、批准会话与客户端登记范围；客户端登记 `refresh_token` 且 Scope 含 `offline_access` 时按既有刷新族语义签发刷新令牌（族绑定设备授权请求 ID）。
- **设备取消**：`CancelDeviceAuthorization` 允许发起设备凭 `device_code`+原 `client_id`（保密客户端需客户端认证）取消仍 pending 的请求，只影响该请求本身。
- **安全边界**：设备码/短码/令牌明文不进入数据库、日志、审计或错误（低熵短码仅存带密钥 HMAC 摘要，`key_id` 随行支持密钥环轮换；短码查找按密钥环全部 key_id 计算候选摘要并对命中行做常量时间复核，密钥缺失/不可用 fail-closed）；二维码只含短码不含任何长期秘密，打开后仍需登录与显式批准，绝不自动批准；`openid` scope 在设备流中明确 `invalid_scope` 拒绝（OIDC 设备码 ID Token 未在本步实现，Discovery 不声明设备端点）。
- **装配前置与已知限制**：生产装配必须配置 `DeviceVerificationURI`（https，或回环 http）、注入 `DeviceUserCodeKeyring`（低熵短码 HMAC 摘要密钥环，需含当前写密钥与轮换期历史读密钥）与 `Reauth`，且 `token.IssuanceAuthorizer` 必须放行 `GrantDeviceCode`（`internal/token.GrantDeviceCode` 已对齐 RFC 8628 URN）；纯设备码客户端按 RFC 8628 可不登记回调地址（`internal/oauthclient` 仅对含授权码模式的客户端要求回调）。HTTP 路由/传输层限流/确认页与二维码渲染（步骤 65）、短码限流跨实例共享、过期记录清理任务、真实电视/CLI 互操作与 race/非 Windows 未验证。

## Token 与应用权限联合校验（步骤 56）

新增 `internal/tokenauthz`：面向可信资源服务/宿主上下文的联合授权判定服务与同等 HTTP 端点。**无新增迁移、无新增依赖、无新增错误码**（复用既有 46 码并核对注册表/手册映射）；不建立 HTTP 全局路由、不启动监听、不缓存权限。

- **可信调用者与 audience 映射**：`ResourceService` 只能由可信边界（mTLS 映射、客户端认证或嵌入代码）通过 `NewResourceService(serviceID, applicationID, audience)` 构造并显式声明资源所属应用与资源 audience；HTTP 端点必须注入 `ResourceServiceAuthenticator`（缺失拒绝构造），绝不接受请求体/查询参数自称的 `app_id`/audience。请求体为严格白名单 JSON（`access_token`/`permissions`/`mode`/`resource_id`），未知字段或尾随内容直接 400。
- **校验顺序**：访问凭证（类型/签名/签发方/有效期/audience，由 `internal/token` 成熟实现）→ 在线撤销状态（`RevocationChecker`，生产为 `*oauthflow.Service.AccessTokenRevoked`；未注入拒绝构造）→ 客户端登记与 `client_id`→资源应用/audience 映射（跨应用令牌 `APP_SCOPE_MISMATCH`、应用停用 `CLIENT_DISABLED`、audience 已从登记移除 `TOKEN_AUDIENCE_MISMATCH`、客户端注销 `TOKEN_INVALID`）→ 主体模型（`subject_type=user` 走 `internal/authz` 实时权限；`subject_type=service` 走注入的 `ServicePrincipalAuthorizer`）→ all/any 权限组合 → 可选数据范围资源检查。
- **权限与 scope 分开但取交集**：令牌 `scope` 只表达 OAuth 令牌授权范围，绝不映射为角色权限；业务可额外传 `required_scopes`（可选）要求令牌授权范围覆盖指定 scope，缺少时返回 `ACCESS_DENIED`（原因 `insufficient_scope`），再由当前角色权限判定业务操作权——令牌授权范围与当前权限两者任一不满足即拒绝。所需权限由业务服务端路由/可信策略确定，列表必须非空（空要求按 `REQ_INVALID` 拒绝，避免业务漏配权限要求时静默放行），上限 32 项，all 为默认、any 需显式指定；未知/停用/root_only/跨应用权限与成员缺失/账户禁用分别返回 `PERMISSION_UNKNOWN`/`PERMISSION_DISABLED`/`ACCESS_DENIED`/`APP_MEMBERSHIP_REQUIRED`/`USER_DISABLED`。
- **服务主体独立模型**：`client_credentials` 令牌不借用用户身份、不查用户权限；服务身份没有独立权限存储，必须由宿主注入策略显式判定，未注入时权限要求一律 `PERMISSION_REQUIRED`（拒绝），不能把持有服务令牌当成自动获得管理权限。
- **响应与错误码**：已成功处理的判定返回 HTTP 200 + `allow` 字段；业务拒绝为 `allow=false` + 稳定 `code`/`message`/`reason`/`request_id`（令牌验证失败时不披露主体），成功结果按需披露主体类型/主体/客户端/应用范围/scope。调用者认证失败 401 `CLIENT_AUTH_FAILED`，参数错误 400 `REQ_INVALID`，不可信调用者 403 `ACCESS_DENIED`，依赖不可用 503 `AUTHZ_UNAVAILABLE`；每次业务拒绝写受限失败审计（真实资源服务主体、稳定目标 ID、`request_id`，不含令牌原文），精确原因只向受信调用者披露。
- **无缓存与失效语义**：每次判定实时读取账户/成员/角色/权限/客户端登记与在线撤销状态，无权限或令牌状态缓存；权限撤销、成员移除、应用停用后下一次判定立即生效。依赖（令牌存储、客户端登记、撤销存储、权限存储）不可用时返回错误，业务必须默认拒绝。
- **已知限制**：业务资源归属/对象状态不能由权限名推断，可选 `resource_id` 只按已配置数据范围判定（undefined/none 拒绝），归属需业务服务或可信扩展另行校验；ID Token/Refresh Token/会话秘密不能作为业务 Access Token；HTTP 端点的限流、传输层装配与 `cmd/login-server` 路由留后续步骤（本包由宿主挂载并用其认证/限流中间件）；无多实例/race/非 Windows 实测。

## 授权撤回、令牌撤销与退出状态联动（步骤 55）

新增 `internal/oauthflow/revocation.go` 与迁移 `0034_oauth_revocation.sql`（未兑换授权码 `revoked_at_ms`、（用户,客户端）/用户级在线撤销标记、访问令牌 jti 撤销记录），复用步骤 45 的 `oauth_revocation_events` outbox 与步骤 54 刷新族/状态查询。本步只提供可信 Go API 与标准撤销端点语义，不建 HTTP 路由/页面；Webhook 通知应用自身会话留步骤 59。

- **四种退出范围明确区分**：`LogoutCurrentSession` 只撤销当前会话；`LogoutAllSessions` 撤销该用户全部身份会话；`RevokeAuthorization` 撤回某次应用授权（撤销该授权下未兑换授权码与刷新令牌族，写（用户,客户端）在线撤销标记）；`LogoutApplication` 退出某应用（该用户在该应用下未兑换授权码、全部刷新族、应用会话与在线撤销标记）。删除浏览器 Cookie 不等于调用本服务；业务应用自身会话通知不属于本步。
- **标准撤销端点（RFC 7009）**：`RevokeToken` 要求保密客户端 secret/证书认证（公开客户端凭 client_id 撤销自己的令牌），只撤销属于已认证客户端的 refresh/access 令牌；未知、已撤销、属于其他客户端的令牌**静默按成功处理**，避免存在性/归属枚举；重复撤销幂等。`token_type_hint` 只是提示，错误 hint 会被忽略并回退尝试另一种类型。撤销刷新令牌按族撤销（含全部 active 后代）**并在同一事务写（用户,客户端）在线撤销标记**，使该用户对该应用已签发的未过期 Access Token 在在线校验/状态查询与 OIDC UserInfo 中失效；这是保守的粗粒度边界，可能同时使同应用其他授权的 AT 在线失效（离线 JWT 副本仍不能即时感知）。撤销访问令牌按 jti 记录并保留到令牌自然到期。
- **撤销状态联动**：`InspectToken` 的 Access Token 分支增加在线撤销检查（jti 精确撤销 + 用户/应用级撤销时间不早于令牌签发时间即 inactive）；OIDC `UserInfo` 使用 Access Token 时接入同一在线撤销检查（`RevocationChecker` 为构造必填依赖，未注入时 `oidc.New` fail-closed 拒绝，绝不跳过检查）；刷新令牌族撤销后状态查询 `active=false`。**失效延迟约定**：访问令牌是自包含 JWT，离线验签副本无法感知撤销；资源服务必须使用本服务状态查询/在线校验或依赖短 Access Token 有效期，**不得宣称所有离线副本立即失效**。旧刷新凭证在族撤销后一律无效。
- **既有可靠事件接入**：`ApplySecurityEvent` 支持改密、恢复完成、账户禁用（用户级撤销全部刷新族/未兑换授权码并写用户级在线标记）与成员移除（按用户+客户端收敛）；`ConsumeOAuthRevocationEvents` 消费步骤 45 `oauth_revocation_events` outbox，逐事件幂等撤销并标记 processed；单事件失败累计 attempt_count 且保留 pending，可安全重试。安全版本/会话撤销仍是原有第一道失效线，不因本消费者缺失而失效。
- **审计与边界**：撤回/撤销/退出/事件消费均写审计（不记录 access/refresh token、授权码、secret 明文）；客户端认证失败 `invalid_client`，内部协议错误复用既有 46 码。`SessionRevoker` 未装配时 `Logout` fail-closed，不影响授权码/令牌端点。无令牌撤销列表对外查询、无 Webhook/应用会话通知、无 HTTP 路由/限流；离线副本即时失效、跨实例撤销推送/事务外副作用恰好一次未实现。
- **已知限制/装配前置**：宿主必须在改密/恢复完成/禁用/成员移除等既有可靠事件提交后调用 `ApplySecurityEvent`（或运行 outbox 消费者），否则仅依赖安全版本/会话失效的既有延迟；HTTP 撤销/退出端点、传输层限流、Webhook 与页面属后续步骤；非 Windows/race/多实例未验证。

## 刷新令牌轮换、重放检测与令牌状态查询（步骤 54）

扩展 `internal/oauthflow` 的 Token 端点，新增 `grant_type=refresh_token` 轮换与标准风格令牌状态查询；迁移 `0033_refresh_tokens.sql` 落地 `refresh_token_families`（令牌族：客户端/用户主体/授权请求/Scope/audience/安全版本快照/绝对有效期）与 `refresh_tokens`（只存 32 字节 SHA-256 摘要、active/used/revoked/expired、空闲/绝对到期、替换关系）。刷新令牌是高熵不透明秘密（32 字节随机 + 前缀），明文只在签发/轮换响应返回一次，不写入数据库、日志或审计。本步**不开放 HTTP 路由**，协议端点实现为内部 Go API，由后续装配步骤接线。

- **签发条件**：只有 `authorization_code`（用户）流程且客户端登记 `refresh_token`、授权 Scope 含 `offline_access` 时才签发刷新令牌族；`client_credentials` 服务令牌流程从不创建刷新令牌族，服务令牌也不能用于刷新（无 refresh 授权的客户端请求刷新返回 `unauthorized_client`）。
- **原子轮换**：刷新请求校验客户端身份与登记配置后，在同一审计事务内条件把旧令牌 `active→used` 并插入新令牌（高熵新值+新摘要）；并发刷新同一令牌只有一方成功。先签发新 Access Token、后提交刷新轮换事务：事务失败时旧令牌保持 active，调用方可安全重试（失败路径不误触发重放撤销）。
- **重放检测与遏制**：旧值再次使用（包括并发刷新失败方与网络重试）按重放处理，撤销整个令牌族（族 revoked + 全部 active 后代令牌 revoked），并写 `oauth.refresh.replayed` 审计；不设无限宽限期，族撤销后所有后代刷新令牌失效。
- **生命周期与主体状态**：族有绝对有效期（默认 30 天，1 小时～90 天），单个刷新令牌有独立空闲有效期（默认 7 天，且不超过绝对有效期）；空闲到期标记 expired 并拒绝。刷新时重新校验用户 active、安全版本与令牌族快照一致、应用成员仍 active；任一变化撤销族并拒绝（真实业务状态变化影响令牌 active 与后续刷新）。
- **Scope 与 audience 不扩大**：刷新请求只能请求原授权 Scope/audience 的子集（缺省沿用原授权）；扩大返回 `invalid_scope`/`invalid_request`；客户端错配返回 `invalid_grant`；客户端当前登记 Scope/audience 收窄后拒绝刷新，不静默放宽。
- **令牌状态查询**：`Service.InspectToken` 要求资源服务经客户端身份验证（`ResourceServerClientID`）并经注入的 `InspectAuthorizer` 授权查询指定 audience；无效/过期/撤销 Access Token 统一返回 `Active=false`（不提供区别化探测细节），刷新令牌按摘要查询族/令牌状态。披露字段默认只含 token_type/client_id/scope/audience/时间；**用户主体仅在授权器显式 `ShowSubject` 时返回**，避免其他应用探测用户身份；`active` 只表示令牌当前有效，**不等于**可执行任意业务动作（联合权限判断属下一阶段）。
- **审计与错误**：刷新签发/轮换/重放/拒绝/族撤销、状态查询成功与拒绝均写审计（真实主体/资源服务身份、族/令牌稳定 ID、原因码），不含刷新令牌明文/摘要以外秘密；协议错误遵循既有 RFC 6749 `error` 约定（invalid_request/invalid_client/unauthorized_client/invalid_grant/invalid_scope/temporarily_unavailable/server_error），不新增项目错误码。
- **已知限制**：HTTP Token/Introspection 路由/装配、Device Flow、授权码流程之外的刷新令牌签发、Access Token 撤销列表（无状态 JWT 在到期前仍有效，族撤销只阻止后续刷新）、多实例限流/清理任务、真实业务资源服务联调、race/非 Windows 未验证；`active` 不代表权限。

## Client Credentials 服务身份授权（步骤 53）

在既有 `internal/oauthflow` Token 端点增加 `client_credentials` 分支，并扩展 `internal/token` 的 Access Token 声明；**无新增迁移**（复用 0029 客户端登记、0030 签名密钥、0031 授权码表与 0032 认证事实），不另写签名算法。本步只签发服务身份 Access Token，不提供 HTTP 路由/管理 API，也不自动向管理接口开放服务身份。

- **仅保密客户端且显式登记**：Token 端点只接受 `grant_type=client_credentials`；公开客户端即使数据库被错误配置该 grant 也拒绝（`unauthorized_client`），保密客户端必须在登记项中显式包含 `client_credentials`，并必须通过 `oauthclient.VerifyClientSecret`/`VerifyClientCertificate` 认证。缺失/错误凭证统一 `invalid_client`（401），不泄露客户端是否存在或凭证轮换细节。普通用户会话不能调用 Token 服务内部接口为客户铸造服务令牌（`internal/token` 拒绝 user Caller 的 `client_credentials` 签发请求）。
- **服务主体不借用用户身份**：服务身份令牌 `sub=client_id`、`client_id=client_id`，新增声明 `subject_type=service`；用户授权码/设备码令牌为 `subject_type=user`。旧令牌缺失该声明按 user 解释，验证器对 `service` 强制 `sub==client_id`，未知值拒绝。不读取应用负责人/root 用户身份，也不为其签发用户 ID Token 或 Refresh Token；管理 API 是否接受服务身份由后续明确委托策略决定，本步不自动全开放。
- **范围只能缩减**：请求 `scope`/`resource` 必须属于客户端登记集合（`invalid_scope`/`invalid_request` 拒绝），resource 省略时仅在客户端只登记一个目标资源时使用默认值；服务令牌只包含请求的 Scope 与 audience，受资源 audience 限制。不得通过 client_credentials 获得用户 Scope、用户 ID Token 或刷新令牌。
- **状态变化**：应用停用、客户端未登记该授权类型、客户端凭证轮换/撤销都会使**后续** Token 请求失败（凭证轮换后旧 secret 立即 invalid_client、新 secret 生效）；已签发未过期 Access Token 为无状态 JWT，本步无撤销列表，不能即时吊销（步骤 54 处理刷新/撤销），不宣称已撤销既有令牌。
- **协议与审计**：成功响应为标准 `access_token`/`token_type=Bearer`/`expires_in`/`scope`，错误为标准 OAuth `error`/`error_description` 与 HTTP 状态；签发成功写 `oauth.service_token.issued` 审计（`actor_type=system`、`actor_id=oauthflow`，含 client_id/scope/audience/jti/kid，不含 secret/token 原文），失败写 `oauth.service_token.denied`；`internal/token` 自身签发审计同样以系统主体记录，运行日志包含 grant_type/subject_type 以便区分程序自身行为与用户代表行为。
- **已知限制**：无 HTTP Token 端点/限流/管理 API 服务身份策略（后续装配与明确委托策略决定）；已签发令牌无撤销列表；服务身份当前没有独立的权限存储，资源侧需按 Scope/audience + 后续服务权限策略联合判定，不能把持有服务令牌当成自动获得管理权限；HTTP/页面、非 Windows/race 未验证。

## OIDC 身份令牌、发现文档与 UserInfo（步骤 52）

新增内部 `internal/oidc` 与只读仓储 `internal/oidc/sqlite`（UserInfo 用户来源），迁移 `0032_oidc.sql` 扩展 `sessions.auth_methods_json` 与授权请求/授权码的 `auth_time_ms`/`auth_methods_json`。本步**不暴露 HTTP 路由、不装配 `cmd/login-server`**，验收走可信内部 Go API；互操作验证使用独立 go-jose 校验流程，**真实第三方 OIDC 客户端未实测**。

- **openid scope 与 ID Token 开关**：只有授权请求显式包含 `openid` 且服务配置了 OIDC 时才可能签发 ID Token；未配置 OIDC 时 openid scope 在授权请求阶段即按 `invalid_scope` 拒绝（不声明/不静默忽略未实现能力）。兑换成功后若 scope 含 openid 则同时签发 ID Token，否则响应不含 ID Token。ID Token 使用 `typ=JWT`+`token_use=id`，与 Access Token（`at+jwt`/`token_use=access`）按类型严格区分，不能互相调用。
- **真实认证事实**：登录会话新增 `auth_methods_json`，只记录服务端认证结果中的稳定方法标识；授权确认时把会话真实登录时间与方法快照写入授权请求与授权码（`auth_time_ms`/`auth_methods_json`），兑换签发 ID Token 时使用。`auth_time` 来自会话创建时间；`amr`/`acr` 由 `internal/authfact` 从这些方法映射（`pwd`/`otp`/`totp`/`mfa` 与 `urn:evernight:acr:*`），调用方不能自述或伪造强度；升级前旧会话/授权记录方法为空时 fail-closed 拒绝签发（不伪造 amr）。
- **ID Token 声明与 subject**：必需声明 `iss/sub/aud/exp/iat`，`aud` 为单一 client_id，`azp` 恒为 client_id（多值 aud 时一致）；`nonce` 原样回传；`auth_time`、`amr`、`acr` 如上。`sub` 采用**按客户端配对的稳定假名**（HMAC-SHA256(主机秘密, client_id|user_id)），同一用户对不同客户端不可关联，同一客户端跨登录稳定；Discovery `subject_types_supported=["pairwise"]`。真实用户 ID 只进内部审计/授权判定，不写入 ID Token/UserInfo。
- **发现文档**：固定公开 issuer（https；本地回环可 http；无查询/片段/userinfo、无尾斜杠），所有端点必须与 issuer 同源且路径位于 issuer 路径前缀下（拒绝 `..` 段）。只声明真实实现的授权码 + PKCE S256 + ES256 + pairwise 与已实现端点/Scope/Claims；不声明 refresh/device/revocation/end_session/introspection 等未实现能力，`claims_parameter_supported`/`request_parameter_supported` 均为 false。
- **UserInfo**：必须验证 Access Token 的签名/签发方/类型/有效期，并以 **issuer 作为 UserInfo 资源受众**（客户端登记允许 audience 需包含 issuer 才能调用），要求 `openid` scope；按 scope 裁剪：`profile` 返回 name/preferred_username/locale/zoneinfo/updated_at，`email` 返回 email+email_verified（仅当存在已验证邮箱，如实反映验证状态；无邮箱不返回）。返回 `sub` 与 ID Token 一致；不输出密码、MFA、凭证、会话或找回材料。
- **错误与审计**：openid 未配置/端点配置非法/认证事实缺失 fail-closed；UserInfo 协议错误使用标准 `invalid_token`/`insufficient_scope`/`invalid_request` 与 401/403，不泄露令牌细节；令牌、声明原文与用户秘密不进入日志/审计。
- **步骤 51 遗留收口**：(a) 移除 `AllowConfidentialWithoutPKCE`，所有授权码统一强制 PKCE S256（与 0031 表非空约束一致）；(b) `Exchange` 按客户端**当前登记**重新精确匹配回调；(c) 授权码/重定向地址改为脱敏类型（默认格式化输出 `[REDACTED]`，仅显式 `Reveal()` 可用于传输）；(d) 并发兑换失败方补写 `replayed_at_ms`；(e) `DecideAuthorization` 前重读客户端，应用停用或移除 authorization_code 时拒绝确认。
- **错误码**：复用既有 46 码（参数 `REQ_INVALID`、令牌 `TOKEN_INVALID`、越权/scope `ACCESS_DENIED`、账户 `USER_DISABLED`、存储 `DB_UNAVAILABLE`、内部 `INTERNAL_ERROR`），不新增设计码；协议层使用标准 OAuth/OIDC error。
- **已知限制**：只有授权码流程可选 ID Token；OIDC 设备码 ID Token/结束会话/撤销端点/动态注册未实现（设备码授权本身由步骤 57 实现）；`private_key_jwt` 等未选择；Authorization Endpoint/Token Endpoint/UserInfo 的 HTTP 路由与页面、真实第三方 OIDC 客户端互操作、subject 秘密轮换、方法级 UV 细分 amr（passkey UV 的 `user` 取值）与 race/非 Windows 未验证。

## OAuth 授权码、PKCE 与授权确认（步骤 51）

新增内部 `internal/oauthflow` 与 SQLite 仓储 `internal/oauthflow/sqlite`，迁移 `0031_oauth_authorization.sql` 落地 `oauth_authorization_requests`（确认请求 + 真实会话/客户端/回调/Scope/audience/state/nonce/PKCE 绑定与 pending→approved/denied 一次性决定）与 `oauth_authorization_codes`（授权码只存 SHA-256 摘要、短时一次性、消费/重放时间戳）。本步**不建浏览器 UI、不暴露 HTTP 路由/Discovery 端点、不签发刷新令牌**，验收走可信内部 Go API 与临时 SQLite。

- **授权请求校验**：`client_id` 必须已登记且所属应用启用；`redirect_uri` 复用 `internal/oauthclient` 的逐字节精确匹配/RFC 8252 回环规则；只接受 `response_type=code`，明确拒绝 `token`/`id_token`/`password` 与组合；PKCE 只接受 **S256**（43 位 base64url challenge），公开客户端与登记 `require_pkce` 的客户端强制，保密客户端默认也强制，仅显式配置 `AllowConfidentialWithoutPKCE` 时才允许省略，任何情况都拒绝 `plain`；Scope 与 resource/audience 必须属于客户端登记集合，resource 省略时仅在客户端只登记一个目标资源时使用该默认值；`state` 原样回传但不参与授权判断，`nonce` 持久化供步骤 52 OIDC 使用。
- **回调安全**：无效/未登记 `redirect_uri`、未知/停用客户端、非法 `client_id` 返回协议错误且**禁止重定向**（`OAuthError.RedirectLocation` 返回 false），错误不泄露敏感细节；其余授权端点错误只在已验证的合法回调上以标准 `error`/`error_description`/`state` 重定向，不出现开放重定向。
- **用户确认**：`BeginAuthorization` 必须绑定真实完整用户会话（`internal/session.Validate`，受限/跨应用作用域拒绝），不接受客户端自报用户；同时复核账户 active、应用成员关系与安全版本。确认请求默认 10 分钟有效，`DecideAuthorization` 重新校验同一会话/账户/成员后，按新增敏感操作 `oauth.authorization.approve` 经 `internal/reauth` 要求近期认证；未接线/拒绝时 fail-closed 不发码，**没有任何自动批准路径**。拒绝返回标准 `access_denied` 重定向且不签发授权码。
- **授权码**：确认通过后在单一审计事务内条件迁移 pending→approved 并写入授权码摘要；默认 5 分钟（上限 10 分钟）、高熵随机、一次性，绑定 user+client+精确 redirect_uri+PKCE challenge+scope+audience+会话安全版本快照。明文授权码只在确认响应/重定向中出现一次，数据库只存 SHA-256 摘要，日志与审计不含授权码/令牌。
- **Token 端点兑换**：标准 `authorization_code` 请求，保密客户端必须通过 `oauthclient.VerifyClientSecret` 或 `VerifyClientCertificate` 认证，公开客户端必须 PKCE；逐项校验绑定（client、精确 redirect_uri、code_verifier 的 S256 恒定比较、用户/会话/成员仍有效、客户端 Scope/audience 未被收紧），随后用审计事务条件消费授权码（**并发兑换单赢家**），再由 `internal/token` 以用户身份签发 Access Token。重复/并发兑换返回标准 `invalid_grant` 并记录 `replayed_at_ms`；过期、跨客户端、回调替换、错误/缺失 verifier 均按标准错误拒绝。错误响应使用 OAuth `error`/`error_description` 与规范 HTTP 状态（`invalid_client` 401，其余 400/500/503），不是项目通用业务响应格式。
- **边界与已知限制**：访问令牌是无状态 JWT，本步**没有令牌撤销列表/刷新家族**（步骤 54），因此重复兑换只记录重放，不宣称撤销已签发令牌；PKCE/回调不匹配时不消费授权码（允许客户端用正确参数重试，verifier 高熵），成功兑换后令牌签发失败会保留已消费状态（fail-closed，需重新授权）；本步不支持 password/implicit/刷新（设备码在步骤 57 独立实现）；无 HTTP 路由、传输层限流、确认页 UI（步骤 65）、过期请求/授权码清理任务；确认页数据只含 client_id、Scope、audience、回调与有效期，应用展示名需页面层按受控资料补充；非 Windows/race 未验证。
- **步骤 50 遗留收口**：明确“撤销 active 密钥后下一次签发自动引导全新 active”的语义（不降级复用 revoked 密钥，暂停签发由装配层负责）；说明 `next` 当前是轮换事务中间态、JWKS 保留 next 为未来预发布预留；签发成功审计失败改为 fail-closed（不返回令牌）；JWS 头/声明集严格拒绝重复 JSON 字段；补并发轮换单赢家测试；ID Token 增加“客户端必须登记 authorization_code/device_code grant”校验（步骤 52 使用）。
- **错误码**：协议错误使用标准 OAuth `error` 值；内部诊断只复用既有 46 码，不新增设计码。

## OAuth/OIDC 令牌核心、签名密钥轮换与 JWKS（步骤 50）

新增内部令牌域 `internal/token` 与 SQLite 仓储 `internal/token/sqlite`，迁移 `0030_token_signing_keys.sql`（`token_signing_keys`：私钥只存 AEAD 密文、公钥 JWK、next/active/retired/revoked 状态与退役保留期，active/next 部分唯一索引），并新增直接依赖 `github.com/go-jose/go-jose/v4 v4.1.9`。本步**不实现刷新令牌、不暴露 HTTP 路由/Discovery/OIDC 端点**，签发验签与 JWKS 均为可信内部 Go API。

- **成熟库与固定算法**：JWS 签名/验证使用 go-jose v4（Apache-2.0，Go 1.24+，2026-11 发布、维护活跃、无额外传递依赖），不自行实现密码学；算法固定为 **ES256**（ECDSA P-256/SHA-256），验证时以库的允许算法列表 + 头部检查拒绝其余 alg（包括 `none`/`HS256` 等）。运行时与迁移结构都只允许 ES256。
- **私钥保护与公钥发布**：签名私钥为 `crypto/rand` 生成的 ECDSA P-256，PKCS#8 编码后经 `internal/secrets.Sealer` 以用途 `oauth.signing`/对象=kid/范围=system 认证加密保存；数据库、审计、日志与 JWKS 均不出现私钥材料。`PublishedJWKS` 只输出 active、next（仅预发布、不用于验证）与保留期内 retired 的公钥 JWK（`kty/crv/kid/use/alg`，无私有字段），revoked 与超过保留期的 retired 不发布；HTTP 路由留后续步骤。
- **密钥生命周期与轮换**：状态 `next`（预发布）→ `active`（唯一签名密钥）→ `retired`（保留期内旧令牌仍可验证、公钥继续发布）；`revoked` 为紧急撤销入口（立即拒绝该密钥签发的令牌并停止发布）。`RotateSigningKey`/`RevokeSigningKey` 只允许系统/本地管理员可信调用者并写审计；轮换在同一审计事务内插入 next、退役旧 active、激活新 active，数据库部分唯一索引保证同一时刻最多一个 active/next。`KeyRetention`（默认 24 小时）必须覆盖最长令牌有效期+时钟容差，否则拒绝构造；退役保留期后旧令牌验证拒绝。
- **Access Token 与 ID Token 明确分离**：Access Token 采用 RFC 9068 约定：JOSE 头 `typ=at+jwt`，声明 `iss/aud/sub/client_id/scope/iat/nbf/exp/jti/token_use=access`；ID Token 使用 `typ=JWT`、`token_use=id`、`aud=client_id`（单一）、可选 `nonce/auth_time`。验证器同时校验 header typ 与 token_use，Access Token 不能当 ID Token 用，反之亦然。
- **验证安全边界**：只使用本地受控密钥集（kid 必须属于 active 或保留期内 retired），**不依据未验证头部请求远程密钥**：拒绝 `jku/x5u/x5c/jwk/crit` 等未受控密钥引用；固定检查 issuer、audience、类型、必需声明、有效期与可注入时钟容差（默认 1 分钟）；拒绝重复顶层声明与未知/畸形 kid；签名失败、过期、接收方不匹配、密钥撤销分别映射稳定错误码。
- **签发仅接受可信已授权上下文**：`Caller` 由宿主边界构造、不能由请求参数自称；普通用户只能为自己签发，受信系统/本地管理员代表其他主体签发必须经注入的 `IssuanceAuthorizer` 显式批准（nil 拒绝构造，fail-closed）。客户端、授权类型、Scope 与 audience 必须来自 `internal/oauthclient` 已登记配置（生产适配器 `NewOAuthClientSource` 读取客户端安全设置，应用停用返回 `CLIENT_DISABLED`），`client_credentials` 仅允许保密客户端且主体为客户端自身；刷新令牌请求明确拒绝（本步不实现）。签发/拒绝/轮换/撤销均写审计且不含令牌原文或密钥材料。
- **错误码**：只复用既有 46 码：`REQ_INVALID`/`ACCESS_DENIED`/`TOKEN_INVALID`/`TOKEN_EXPIRED`/`TOKEN_REVOKED`/`TOKEN_AUDIENCE_MISMATCH`/`CLIENT_DISABLED`/`CONFLICT`/`DB_UNAVAILABLE`/`AUDIT_WRITE_FAILED`/`INTERNAL_ERROR`。
- **已知限制**：刷新令牌（不透明秘密）、授权端点/令牌端点 HTTP 路由、Discovery/UserInfo、Token 撤销/状态查询与撤销列表、多实例密钥缓存与协调、自动轮换调度器、密钥备份/恢复演练、真实业务资源 audience 治理、OAuth 端到端流程未实现；本步签发验签组件不等于完整 OAuth/OIDC 流程；race/非 Windows 未验证。

## OAuth 客户端类型、回调规则与应用凭证管理（步骤 49）

新增内部 `internal/oauthclient` 与 SQLite 仓储 `internal/oauthclient/sqlite`，迁移 `0029_oauth_clients.sql` 落地 `oauth_clients`（与 applications 一对一的安全设置：客户端类型、授权类型、精确回调/退出回调、Scope、允许的目标资源 audience、身份验证方式、PKCE 要求、行版本）、`oauth_client_secrets`（只存前缀与 32 字节 SHA-256 摘要，支持到期/撤销/轮换过渡）与 `oauth_client_certificates`（只存公钥证书与 SHA-256 指纹，不存私钥）。应用显示资料仍在 `internal/app`，本步**不暴露 HTTP 路由、不实现授权端点/令牌签发/动态客户端注册/第三方登录**，验收走可信内部 Go API 与临时 SQLite。

- **客户端类型与合法组合**：`client_id` 使用应用稳定 ID（1:1）；客户端类型必须与 `applications.client_type` 一致且创建后不可通过资料更新改变。公开客户端没有 secret/证书，身份验证方式为空，**强制 PKCE**，禁止 `client_credentials`；保密客户端必须配置至少一种身份验证方式（`client_secret_basic`/`client_secret_post`/`tls_client_auth`），`tls_client_auth` 登记时必须同时提供公钥证书，配置 `client_secret_*` 时服务端生成并只返回一次密钥。公开客户端不得用打包密钥假装保密。明确拒绝 `password`/`implicit` 授权；`refresh_token` 只能与 `authorization_code`/设备码一起登记。
- **回调精确匹配**：只登记绝对回调地址，逐字节精确匹配（区分大小写、百分号编码、路径与查询串），**禁止片段、通配符、userinfo、子域包含与前缀匹配**（`https://app.example.com/cb` 不匹配 `.../CB`、`.../cb%2F`、`.../cb#frag`、`sub.app.example.com`、`app.example.com.evil.test`）。唯一例外是 RFC 8252 原生应用回环地址动态端口：仅公开客户端的 `http://127.0.0.1`/`[::1]` 回调忽略端口，路径与查询串仍精确；自定义私有 scheme 只允许公开客户端且格式为 `scheme:/path`；保密客户端只允许 https。退出回调使用同一规则。`MatchRedirectURI`/`MatchPostLogoutRedirectURI` 供后续授权端点复用。
- **客户端凭证**：密钥明文只在登记/轮换响应出现一次，库中只存前缀与摘要（验证使用恒定时间比较），列表只返回 ID/前缀/时间；支持有效期（默认 180 天，24 小时～5 年）、撤销与**轮换过渡**（新密钥立即生效，旧密钥在过渡期（默认 24 小时、可配置 1 分钟～30 天）内仍可用，超出退休时间或原有效期即拒绝）。证书身份验证要求证书当前有效且 SHA-256 指纹与某个未撤销登记证书精确一致；证书链信任由 TLS 层完成。仅剩一个可用凭证时拒绝撤销（先轮换，避免自锁），重复撤销幂等。
- **身份验证语义**：`VerifyClientSecret`/`VerifyClientCertificate` 成功只表示**客户端身份**成立，不代表该客户端的任意用户已认证；应用停用返回 `CLIENT_DISABLED`，其余失败统一 `CLIENT_AUTH_FAILED`（不区分未登记/类型不符/过期/撤销/错误，避免探测），成功/失败均写审计但不含密钥明文。
- **权限与再次验证**：登记/修改安全设置映射既有应用管理权限（`application.get`/`application.update`，经 `AppAuthorizer` 复用 `internal/app.Authorizer`，应用管理员仅限获准应用），凭证轮换/撤销同样要求管理权限；这些写动作还必须经步骤 38/39 `internal/reauth` 敏感策略（目录新增 `oauth.client.register`/`oauth.client.settings.change`，复用 `application.credential.rotate` 并标记已实现，默认要求近期强认证），绑定客户端 ID 与服务端计算的安全设置摘要，失败/拒绝写审计。修改安全设置使用行版本条件更新（并发单赢家），不影响应用显示资料或应用权限归属。
- **错误码**：只复用既有 46 码（参数/非法组合/回调不一致 `REQ_INVALID`，客户端身份失败 `CLIENT_AUTH_FAILED`，应用停用 `CLIENT_DISABLED`，越权 `ACCESS_DENIED`，再次验证 `REAUTH_REQUIRED`/`MFA_REQUIRED`，冲突/最后凭证 `CONFLICT`，权限服务 `AUTHZ_UNAVAILABLE`，存储 `DB_UNAVAILABLE`，审计 `AUDIT_WRITE_FAILED`），不新增设计码。
- **已知限制**：`private_key_jwt`（JWK 私钥签名断言）未实现（本步选定 TLS 客户端证书作为非密钥身份方式，后续 OIDC/JWKS 步骤接入）；授权端点/令牌签发/PKCE 挑战校验/Device Flow/Client Credentials 实际发放不在本步范围，`require_pkce` 只是登记要求；细粒度 `applications.credentials.manage` 数据范围接线与 HTTP 管理接口留后续；真实 mTLS 握手/CA 链校验、过期凭证清理任务、多实例限流、race 与非 Windows 未验证。

## root 密码与两步验证的本地应急重置（步骤 48）

新增内部 `internal/rootrecovery` 与本地命令 `cmd/loginctl root-recover`，迁移 `0028_root_recovery.sql` 落地 `root_recovery_events`（恢复操作记录 + 待补发安全告知 outbox）。本步**只补这一个本地命令**，不建完整 CLI、不暴露 HTTP 路由、不实现远程恢复、不在程序启动时自动执行恢复。

- **前置安全条件**：命令要求操作者显式确认服务已停止或处于维护状态（`--service-stopped`/`--maintenance`），并在数据库目录取得排他锁文件（`.root-recovery.lock`）；锁同时按数据库底层文件身份（卷序列号+文件索引 / dev+inode）在系统临时目录加身份锁，`filepath.EvalSymlinks` 归一真实路径，因此符号链接/硬链接的不同路径表示不能绕过互斥；同进程重入与跨进程并发都返回冲突，同一数据库同一时刻只允许一次恢复。**装配前置（必须）**：服务端目前未持有进程锁/维护标记，停机状态由操作者参数确认；后续装配 `cmd/login-server` 时必须让运行中的服务持有同一数据库目录锁或维护标记，使服务运行期间 CLI 直接拒绝。所选数据库须存在、非空、`schema_history` 与当前程序的迁移版本和校验和完全一致、唯一 root 账户存在且 active、root 初始化记录匹配；错误库/旧版本库/缺 root 在写入前拒绝，且拒绝路径不修改数据库（包括不写失败审计，避免对未知库产生任何写入）。
- **交互与范围**：新密码通过隐藏输入取得（`golang.org/x/term` 关闭回显；不走命令行参数/环境变量/日志），要求两次一致并通过 `internal/authn` 密码策略；读取后立即尽力清零 `[]byte`（Go 无法保证 string 转换副本的驻留期，属于已声明限制）。密码重置、MFA 重置、主登录 Passkey 撤销分别选择：Passkey **默认保留**，只有 `--revoke-login-passkeys` 且二次确认才撤销；整体确认使用明确确认词，取消确认不产生任何修改。**默认交互器强制 stdin 与 stdout 均为终端（TTY）**：非 TTY（管道/重定向/CI）在打开数据库前直接拒绝，固定确认词不能通过 `echo RECOVER | loginctl ...` 脚本化；仅测试通过注入 `PrompterFactory` 绕过。
- **重置语义**：成功时在同一审计事务内递增 root `security_version`（并使所有既有会话因版本不一致失效）、撤销 root 全部会话、作废其未消费一次性凭证与所有恢复代码组（恢复代码是绕过第二因素的通道，即使只重置密码也作废）、按选择重置密码/MFA 因素（邮件因素、TOTP、待处理 MFA 挑战与恢复尝试），并把 root 初始化状态复位为 `setup_verified`：root 必须重新配置强认证，流程不签发任何正常高权限会话。MFA 重置不删除 Passkey；撤销 Passkey 与重置 MFA 是独立选择。
- **审计与可靠记录**：恢复操作记录本地操作者（OS 用户/机器名，不含秘密）、原因、范围、安全版本与撤销/禁用计数；成功变更与审计一致提交，审计失败整体回滚（fail-closed）。待补发安全告知持久化到 outbox：宿主/下次启动调用 `PendingNotifications` 并经自己的通知渠道补发后 `MarkNotificationDelivered`；`MarkNotificationFailed` 累计失败次数，未达 5 次保持 pending 重试、达到上限迁移 `failed` 终态，避免无限重试。补发是**至少一次**语义：重复轮询、标记失败/崩溃后重试都可能导致同一事件重复补发，通知消费者必须按事件 ID 幂等。**当前没有自动通知消费者**，不宣称已自动发送。
- **崩溃安全与边界**：全部安全变更在单一审计事务内完成；事务中途失败（含模拟断电式）整体回滚，不留下半完成的密码/因素/会话/安全版本/初始化状态。命令不遗留后台进程、不监听端口。当前服务端未装配进程锁/维护标记，**停机状态依赖本地操作者显式确认**，后续服务装配应持有同一数据库目录锁或维护标记，使 CLI 在服务运行时直接拒绝。
- **错误码**：复用既有 46 码（未确认停机 `RESTORE_MAINTENANCE_REQUIRED`、锁冲突/状态冲突 `CONFLICT`、错误库/存储 `DB_UNAVAILABLE`、审计失败 `AUDIT_WRITE_FAILED`、参数/密码策略 `REQ_INVALID`、取消/root 不可恢复 `ACCESS_DENIED`），不新增设计码。
- **已知限制**：真实 Windows 控制台隐藏输入的自动化测试使用注入交互器（终端实现与真实 TTY 仅手工验证；非 TTY 拒绝行为有自动化测试）；服务运行检测依赖操作者确认（见上）；outbox 自动消费者/通知页面、完整 CLI 其它命令、非 Windows 平台运行未验证；密码在 Go 内存中的清零是尽力而为（string 转换副本不可控），不作为内存防取证承诺。

## 人工核验恢复、独立审批与受控执行（步骤 47）

新增内部领域 `internal/manualrecovery` 与 SQLite 仓储 `internal/manualrecovery/sqlite`，迁移 `0027_manual_recovery.sql`（`manual_recovery_requests`/`manual_recovery_approvals`/`manual_recovery_executions` 三表：内容摘要绑定、同请求唯一 active 批准、同一批准唯一执行、状态机与等待期/有效期约束），扩展 `internal/policy` 目录（新增 `support.recovery.request`/`support.recovery.execute`，`support.recovery.approve` 标记已实现）。本步**不暴露 HTTP 路由、不装配 `cmd/login-server`**；实际密码/MFA 恢复由宿主注入的 `Executor` 完成，测试使用明确标注的执行器替身，不代表真实邮件投递/凭证撤销链路实测。

- **默认关闭、root/宿主显式配置**：`Policy` 默认零值即关闭，所有阶段返回 `REQ_INVALID`（`ErrDisabled`）并写失败审计；启用必须显式配置核验依据（只允许线下证件原件核验、公证/书面声明等可复核依据，**安全问题/电话口述等弱依据不在枚举内**）、可信交付方式（第一版只允许目标此前**已验证邮箱**）、等待期（默认 24 小时，1 小时～7 天）、批准有效期（默认 48 小时，1 小时～7 天且必须大于等待期）、申请有效期（默认 7 天，1 小时～30 天）与“必须独立审批人”开关（启用时必须为 true）；启用时还必须装配通知适配器（成功/失败都要告知既有渠道）。
- **分别申请、分别授权**：密码恢复（`password_reset`）与 MFA 恢复（`mfa_reset`）是不同的操作类型，分别创建申请；审批功能权限分别为 `recovery.approve` 与 `recovery.mfa.approve`，一次批准只绑定一条请求的固定内容摘要与操作类型，不能用于任意重置。
- **申请绑定与不存敏感明文**：申请绑定目标稳定 ID、发起者、操作类型、核验依据与外部核验记录编号、证据摘要（只保存 SHA-256，不保存证件/证据明文）、原因、交付渠道与**交付地址不可逆指纹**（第一版为既有已验证邮箱的指纹，不保存邮箱明文）、目标 `security_version` 与高权限快照、可选支持工单号；服务端计算 `content_digest` 绑定全部内容，任何替换或换绑交付地址都会被检测。root 与按**实际权限**识别的高权限账户拒绝普通人工恢复（`SUPPORT_TARGET_PROTECTED`，root 由步骤 48 受控 CLI 处理）。
- **独立审批**：审批人不得为发起者或目标本人（`ACCESS_DENIED` 并写失败审计）；审批前重读目标状态（停用/变高权限/交付地址指纹变化拒绝），审批必须经步骤 38/39 敏感策略（`support.recovery.approve`，默认强认证）与功能权限；`StaffAuthorizer.AuthorizeApproval` 携带目标账户与作用域，生产适配器可限制“只能审批数据范围内目标”，范围外目标在审批路径直接拒绝。批准生成等待期起点与有效期，并绑定内容摘要与交付地址指纹。审批人资格在执行时还会重新校验：权限被撤销、批准过期或内容变化都会使批准失效（分别退回待审批或置失败）。
- **短期一次性受控执行**：执行必须在批准等待期已满且批准未过期时进行；执行前重新校验请求/批准内容摘要、审批人当前资格、执行人功能权限、目标是否变为 root/高权限/停用/安全版本变化、交付地址指纹未变，并校验申请自身未过期（`Policy` 强制申请有效期不小于等待期+批准有效期；执行权 claim SQL 同时匹配 `expires_at > now` 防竞态）。通过后在同一审计事务内条件更新 `approved→executing` 并创建唯一执行记录（**双执行竞争只有一个成功**），再调用宿主执行器完成实际恢复。执行器故障时申请/批准/执行置失败、通知既有渠道失败、不写成功审计；最终审计提交失败时尽力调用执行器补偿且绝不宣称成功。
- **成功后失效与通知**：执行成功后请求 `completed`、批准 `consumed`；执行器契约要求撤销旧密码/MFA 凭证与相关会话、必要时交付一次性恢复入口，并要求用户重新正常登录；最终审计/状态提交成功后才发送完成通知并记录通知状态（失败只记录状态与失败审计，不回滚已完成的恢复；通知绝不早于“已完成”事实）。每个阶段（申请/批准/拒绝/执行/失败/拒绝）都记录**真实操作者**与稳定 ID，审计不可覆盖；证据明文、密码、MFA 秘密、恢复代码、凭证/token 均不进入数据库/日志/审计。
- **步骤 46 遗留收口**：(a) 客服 `SendReset` 增加**客服账户维度 + 全局发起预算**双限流（默认单客服 10 分钟 5 次、全局每小时 100 次，可配置 1～50 次/1 分钟～24 小时、1～10000 次/1 分钟～24 小时），超限 `RATE_LIMITED` 并写失败审计；(b) `support.TransitionCase` 禁止人工迁移到 `sent`（`sent` 只能由 `SendReset` 在真实投递成功后内部写入），补测试；(c) 处理历史“不可覆盖”已有真实执行 `UPDATE` 被触发器拒绝的运行时用例（现有 `TestReassignAndStatusTransitionsAudited` 持续覆盖）；(d) 客服受保护权限清单改为“人工基线 + `internal/preset` 权限目录元数据自检/派生”：目录中 `RootOnly`/`RequiresReauth` 的新高权限项自动并入保护集合，基线权限缺失（目录漂移）拒绝构造授权器，补内部测试；(e) 已知信息面与信任边界（如实记录，不涉及秘密）：客服范围内 `exists/disabled/protected` 等错误码差异属于已授权客服可见的信息面，公开接口仍必须统一响应；`SendResetForSupport` 等内部受信 API 的 `system` 调用者不受客服数据范围约束，装配层必须只从受控服务路径调用，不得暴露为普通 HTTP 入口。
- **47-FIX（双审计后）**：(1) 审批授权签名加入目标账户与作用域，生产适配器可限制审批人只审批数据范围内目标（范围外拒绝并留痕）；(2) 批准与内容摘要绑定交付地址不可逆指纹，执行前重读比对，换绑邮箱即 fail-closed 并审计；(3) 执行路径校验申请 `ExpiresAt`，claim SQL 加入 `expires_at > now`，`Policy` 强制申请有效期不小于等待期+批准有效期；(4) 完成通知改到最终审计/状态提交之后，失败不会误报“已完成”；(5) 启用人工恢复必须装配通知适配器；(6) 批准被消费/失效后，历史审批人仍可查看申请（历史参与人授权），无关人员拒绝。
- **错误码**：只复用既有 46 码（`REQ_INVALID`/`ACCESS_DENIED`/`REAUTH_REQUIRED`/`MFA_REQUIRED`/`SUPPORT_TARGET_PROTECTED`/`USER_DISABLED`/`CONFLICT`/`CHALLENGE_INVALID`/`AUTHZ_UNAVAILABLE`/`DB_UNAVAILABLE`/`AUDIT_WRITE_FAILED`/`MAIL_DELIVERY_FAILED`/`INTERNAL_ERROR`）。
- **已知限制**：HTTP 路由/页面/`cmd/login-server` 装配、真实执行器（密码重置/MFA 撤销/会话与凭证失效/一次性入口交付）与真实邮件外发、数据范围写入口、审批通知与人工核验页面、清理任务、多实例限流、race 与非 Windows 未验证；执行器/授权器/目标状态读取均为宿主装配契约，测试替身只验证接口与状态机，不等于真实恢复链路实测。

## 客服求助单与向原验证邮箱发起密码找回（步骤 46）

新增内部客服域 `internal/support` 与 SQLite 仓储 `internal/support/sqlite`，迁移 `0026_support_cases.sql` 落地 `support_cases`（目标用户、创建人/当前指派客服、处理原因、状态机、脱敏邮箱快照、行版本）与 `support_case_events`（追加式处理历史：动作、真实操作者与时间、状态迁移；数据库触发器禁止 UPDATE）。本步**不暴露 HTTP 路由、不装配 `cmd/login-server`、不实现人工核验审批与执行（步骤 47）**，验收走可信内部 Go API 与临时 SQLite。

- **工作人员与强认证**：客服是普通实名操作账户（每名工作人员独立账户），登录强认证由既有 `internal/authn` 对客服等高权限角色要求；登记/转派/状态变更/发起找回四个写动作还经步骤 38/39 `internal/reauth` 的敏感策略执行前校验（目录新增 `support.case.create`/`support.case.update`/`support.reset.send`，默认要求近期**强认证**并绑定操作/目标/服务端参数摘要，成功/失败都写审计）。敏感策略执行器缺失时服务构造失败，不存在跳过强认证的装配路径；读取求助单要求已认证的完整会话加 `support.cases.read` 权限。
- **权限与数据范围**：功能权限 `support.cases.read/create/update` 与 `recovery.request` 来自 `internal/preset` 既有目录（客服角色默认拥有）；数据范围由 `internal/authz` 计算——`all` 覆盖全部普通用户，`resources` 仅显式列出的用户，**`undefined`/`none` 一律拒绝**（不把“未声明”当全部数据）。生产适配器 `NewAuthzAuthorizer`/`NewAuthzTargetProtector` 包装 `internal/authz.Service`，未接线/依赖故障 fail-closed。
- **求助单与脱敏**：记录目标稳定 ID、真实操作者、处理原因、当前指派、状态与处理历史；返回给客服的只有稳定 ID、脱敏用户名（前两字符 + `***`）、脱敏邮箱（首字符 + `***@域名`）与布尔可用性，**不返回邮箱明文、密码/MFA/凭证/找回 token**。目标定位同样只返回脱敏资料；范围外目标与不存在统一 `ACCESS_DENIED`。
- **归属与指派**：客服只能读取/操作**分配给自己的**求助单，查看他人工单统一拒绝并写失败审计（不泄露存在性）；转派要求新受理人当前具备客服资格且数据范围覆盖目标，原受理人转派后立即失去访问；登记、转派、状态变更在行版本条件更新下并发单赢家，变更与处理历史在同一审计事务提交，审计不可用时整体回滚。
- **高权限目标拒绝**：目标按**实际权限**识别——root 与持有系统管理/审批/导出等能力（`users.*`、`roles.*`、`recovery.approve`、`audit.*`、`backups.*`、`security.policy.manage` 等）的账户返回 `SUPPORT_TARGET_PROTECTED`，普通客服不能登记、定位或发起找回；识别依据是 `internal/authz` 有效权限查询，不看角色名，有效权限无法完整证明时按受保护 fail-closed。
- **发送动作复用的绑定**：`internal/passwordreset` 新增受信通道 `SendResetForSupport`：**按稳定用户 ID** 定位，收件地址只来自该用户此前已验证的邮箱（调用方不能指定或替换），复用同一高熵一次性入口/凭证摘要原子消费/邮件模板/审计；只返回“已投递”布尔，**不返回邮件链接/验证码/token**，不能指定新密码，发送本身不修改密码、安全版本与 MFA（原密码在用户完成找回前仍有效），不签发会话。按目标用户有界滑动窗口限流（默认 3 次/小时，可配置），超限返回 `RATE_LIMITED` 且不改变求助单状态。
- **缺少验证渠道**：无已验证邮箱或无密码的目标不会被“恢复”；求助单只转入 `manual_review`（人工核验待处理，审计动作 `support.case.manual_review`），本步不实现审批与执行，**不以客服确认直接恢复账户**。
- **状态机**：`pending_verification` → `sent`/`manual_review`/`closed`/`cancelled`；`sent` → `manual_review`/`closed`/`cancelled`；`manual_review` → `closed`/`cancelled`；`closed`/`cancelled` 为终态，不能再转派或变更。动作与拒绝均写审计动作 `support.case.*`。
- **错误码**：只复用既有 46 码：参数 `REQ_INVALID`，越权/归属/范围 `ACCESS_DENIED`，高权限目标 `SUPPORT_TARGET_PROTECTED`，目标不可用/禁用 `USER_DISABLED`，终态/版本冲突 `CONFLICT`，强认证/两步验证 `REAUTH_REQUIRED`/`MFA_REQUIRED`，限流 `RATE_LIMITED`，权限服务不可用 `AUTHZ_UNAVAILABLE`，存储 `DB_UNAVAILABLE`，审计 `AUDIT_WRITE_FAILED`，邮件 `MAIL_DELIVERY_FAILED`。
- **已知限制**：页面/HTTP 路由/启动装配、人工核验审批与执行（步骤 47，含 `recovery.approve`/独立审批/等待期/可信交付）、录音/证件采集/通用工单平台（明确不做）、真实邮件外发、过期求助单与历史清理任务、多实例/分布式限流、race 与非 Windows 未验证。数据范围写入口（把客服分配给哪些用户）仍待管理接口/后续步骤提供，未配置显式数据范围时客服按 fail-closed 无法处理目标。

## 修改密码、邮件找回与关联凭证失效（步骤 45）

新增 `internal/passwordreset` 与 `internal/passwordreset/sqlite`，迁移 0025 落地 `password_reset_requests`（找回请求：用户、令牌提示、受保护凭证 ID、状态、有效期，不存 token 明文）与 `oauth_revocation_events`（OAuth Token 撤销可靠事件/outbox，仅入队，消费者后续 OAuth 步骤接入）。

- **主动改密**：复用 `internal/authn.SetPassword`（当前密码复核、密码策略/历史复用、步骤 39 敏感操作策略与告知）；成功后安全版本已递增，本服务再撤销该账户**全部会话**，默认**要求重新登录**（不保留当前会话、不返回新会话）；撤销失败不回滚已成功改密（安全版本已保证旧会话失效）并写失败审计；写入 OAuth 撤销 outbox。
- **邮件找回**：只向**已验证邮箱**发送短期（默认 15 分钟）高熵一次性入口（复用 `internal/credential` 摘要保存与原子消费、`internal/mailer` 找回模板）；公开响应不区分账户存在性——未找到、无密码、禁用、root、邮件发送失败都返回同一通用结果（差异只进内部审计）。访问入口**不建立任何会话**，只用于原子消费凭证 + 设置新密码；找回**不解除 MFA/Passkey**，也不为无密码账户自动添加密码；root 密码仍只能本地受控初始化。并发/重放同一入口只有一方成功。
- **一致性**：密码写入、安全版本递增、历史与审计在 authn 事务内完成；请求状态与 outbox 在找回服务审计事务内；会话撤销在提交后执行（失败不回滚，旧会话已因安全版本失效）。禁用账户、密码策略不满足、邮件失败明确拒绝或记录原因。
- **安全告知与限流**：找回重置成功后向已验证邮箱发送“密码已通过邮件找回被重置”安全告知（不含密码/入口；投递失败只写失败审计、不回滚重置）。公开找回入口实现每邮箱/每来源有界滑动窗口限流与冷却（`Options.RatePolicy`，默认每小时 5 次），超限统一响应；命中与未命中都执行签发+取消一次性凭证等主要数据库工作以缩小时序侧信道，但发送邮件仍是命中路径独有，**残余时序差与传输层 IP 限流待 HTTP 接线**。`ResetURLBase` 必须是受控的无凭证 http(s) 绝对地址；预检查入口会校验 token secret 摘要（不消费）并计入限流。
- **入口生命周期**：新找回请求在同一事务内作废旧 pending 并撤销旧凭证；找回完成后作废该用户其余 pending；主动改密也作废全部 pending 找回入口。过期请求清理任务尚未实现（靠状态/有效期与凭证过期兜底）。
- **装配要求**：主动改密需认证事实；`authn.SetPassword` 在用户提供当前密码并复核成功后会自动把“近期 password 认证”事实注入步骤 39 敏感策略（宿主无需重复注入 `reauth.Signals`），要求 strong 的策略仍 fail-closed；管理员/system 通道仍按各自策略判定。OAuth 撤销 outbox 在密码变更提交后写入（有界重试 3 次，失败写失败审计），**不同事务**：即使 enqueue 失败，改密/重置仍已生效，outbox 可由人工/后续运维补偿；不宣称外部 Token 已撤销。
- **边界**：本步只写入 OAuth 撤销 outbox，**不宣称已撤销所有外部应用/Token**；页面/HTTP/启动装配、真实邮件投递、OAuth 撤销消费者、清理过期请求任务留后续步骤。
- **错误码**：复用既有 46 码（越权 `ACCESS_DENIED`、入口无效/过期/重放 `CHALLENGE_INVALID`、禁用账户 `USER_DISABLED`、邮件失败 `MAIL_DELIVERY_FAILED`、存储 `DB_UNAVAILABLE`、审计 `AUDIT_WRITE_FAILED` 等），不新增码。

## TOTP 绑定、验证与安全解除（步骤 41）

新增内部 TOTP 域 `internal/totp` 与 SQLite 仓储 `internal/totp/sqlite`，迁移 0021 重建 `mfa_challenges`（因素类型允许 `email`/`totp`，保留 0020 全部列）并落地 `totp_bindings`；本步**不实现二维码 UI、不暴露 HTTP 路由**，验收走可信内部 Go API。

- **标准 TOTP**：HMAC-SHA1、Base32 种子（`crypto/rand` 20 字节）与标准 `otpauth://totp/...` 导入 URI（二维码数据只提供 URI 字符串）；时间步长/窗口/位数有界可配（period 15～60 秒、窗口 0～3 步、位数 6～8），服务端使用自身时钟（可注入以便测试，生产默认真实时间）。已通过 **RFC 6238 官方测试向量**（SHA1 8 位/6 位各 6 组）与时钟窗口边界测试；测试向量通过不等于真实验证器/真机实测，页面接入时仍需人工验收。
- **种子加密保存**：种子由 `internal/secrets.Sealer` 以用途 `mfa.totp`、对象=绑定 ID、范围 `system` 的 AEAD 信封加密后落库；明文种子/URI 只出现在绑定开始响应（供当前用户展示/导入），不进入日志、审计、普通查询或导出；查询只返回元数据。
- **绑定中与已激活分离**：`pending` 绑定需近期认证（复用步骤 39 `reauth.OperationRunner`，操作 `mfa.add`）后创建；验证当前验证器验证码成功才在同一审计事务内激活并停用旧 active（重绑先验证新因素再替换旧因素，不会先删后绑导致失去因素）。确认失败递增尝试次数并写失败审计。
- **防重放**：服务端记录 `last_accepted_step`，登录验证只接受**严格更大**的时间步；同一步并发/重放通过条件更新只允许一方成功（已用多 goroutine 测试）。同一时间步在窗口内不会重复接受。
- **解除保护**：解除必须先验证当前 TOTP 验证码（证明持有），再检查宿主 `Policy.MFARequired` 与其他强因素；强制 MFA 且没有其他强因素时拒绝移除最后一个可用因素，未强制时本人可解除。
- **装配约束（宿主必读）**：`BeginBinding` 只允许从**完整（非受限）已认证会话**调用，不得把待第二因素、待改密或受限初始化会话接到绑定入口；高权限账户绑定/更换强因素必须在完成强认证后进行。`mfa.add` 默认只要求近期密码认证，服务层不额外判断会话是否完整，宿主接错入口会退化为主密码即可绑定新因素。
- **确认步防重放与绑定可用性**：确认绑定所用时间步会写入 `last_accepted_step`，该码不能立即用于登录；`mfa.add` 目录默认策略改为 **近期密码认证**（`password`+300 秒新鲜度，首次加第二因素不再被“要求强认证但未实现”卡死），`Implemented=true`；装配时 `internal/mfa` 必须与 `*internal/totp.Service` 配对注入（`Options.TOTP` 缺失时构造直接失败，避免已绑定 TOTP 的账户被当作无因素放行）。确认失败只写 failure 审计（不伪造成功审计），过期 pending 惰性清理并释放名额。
- **错误码**：只复用既有 46 码：参数/绑定问题 `REQ_INVALID`，越权 `ACCESS_DENIED`，近期认证/强因素 `REAUTH_REQUIRED`/`MFA_REQUIRED`，验证码/重放/尝试用尽 `CHALLENGE_INVALID`，限流 `RATE_LIMITED`，策略不可用 `AUTHZ_UNAVAILABLE`，存储/加密 `DB_UNAVAILABLE`，审计 `AUDIT_WRITE_FAILED`。
- **与步骤 40 的 MFA 登录接线（已接入）**：`internal/mfa.BeginLogin` 按可配置因素优先顺序（默认 **TOTP 优先于邮件**）选择第二步：账户有已激活 TOTP 时创建 `factor_type=totp` 挑战、不发送邮件，仍绑定用户/登录尝试/用途/AppID/记住我/客户端/受限会话并沿用步骤 40 的限流与尝试上限；`Verify` 对 TOTP 挑战调用 `totp.VerifyLoginCode`（服务端时间步防重放），成功后才用同一受限会话与同 AppID 等轮换完整会话，失败计入尝试上限并写失败审计，重放/跨步复用被拒绝。两者共存时默认走 TOTP；可用 `Options.FactorPreference` 调整顺序，完整的“认证方式选择策略”属步骤 43。
- **已知限制**：页面/HTTP/启动装配、真实验证器/真机实测、绑定发起传输层限流（当前仅服务内尝试上限与 pending 数上限）、恢复代码/Passkey/FIDO2、认证方式选择策略（步骤 43）、审计导出与过期清理任务未实现或未验证；race/非 Windows 未验证。

## 恢复代码、受限恢复会话与强制重新绑定（步骤 44）

新增内部恢复域 `internal/recovery` 与 SQLite 仓储 `internal/recovery/sqlite`，扩展 `internal/session` 的短时受限恢复会话签发入口，迁移 `0024_recovery_codes.sql` 落地 `recovery_code_groups`（按组管理、同一用户最多一个 active 组）、`recovery_codes`（只存 HMAC-SHA256 验证摘要）与 `recovery_attempts`（代码消费→受限恢复会话→新因素绑定的短时尝试）。本步**不暴露 HTTP 路由、不装配 `cmd/login-server`、不实现 OAuth/OIDC 令牌**，验收走可信内部 Go API；新因素绑定通过宿主注入的 `FactorBinder` 完成，测试使用明确标注的模拟验证器，**不代表真实认证器兼容性**。

- **一次性高熵代码与按组管理**：每条代码是 10 字节安全随机数的 base32 文本（80 位熵，`XXXX-XXXX-XXXX-XXXX` 分组展示，接收时忽略空格/连字符并统一大写）；生成时只向当前用户展示一次，数据库仅保存按当前密钥环 `key_id` 与账户 ID 绑定的 HMAC-SHA256 摘要（32 字节），**无法从数据库、日志或审计还原代码**。代码组按用户代次（generation）管理：重新生成在同一审计事务内把旧组置 `superseded` 并插入新组，旧代码立即失效；同一用户唯一 active 组与唯一 generation 保证并发重新生成只有一个成功。
- **原子验证与消费**：`Begin` 必须携带 `internal/authn` 的第一步真实认证结果，且该结果必须是“密码已通过、仍待第二因素”的受限结论（完整认证、非受限、无密码方法、携带强认证时间或 root 账户一律拒绝）；恢复代码只替代第二步，不替代密码。代码验证通过后，消费使用条件更新（`used_at_ms IS NULL → 非空`）并与恢复尝试创建在同一审计事务提交：并发重复使用同一代码只有一个赢家，事务失败（审计不可用等）整体回滚，代码保持可用且不产生尝试；已有进行中尝试时使用另一枚代码不会烧掉该代码；恢复代码尝试另有账户维度有界限流（默认 10 次/10 分钟，可配置 1～100 次与 1 分钟～1 小时），80 位熵下不可爆破，主要用于降噪与防滥用。
- **短时受限恢复会话**：代码成功后由 `session.IssueRecoverySession` 签发 `KindRestricted / ReasonRecovery` 会话（必须通过恢复流程注入的 `RecoverySessionGate` 复核尝试仍待绑定、未过期且尚未绑定会话），绝对到期默认 15 分钟（5～30 分钟有界），不绑定应用、不使用记住我、不携带强认证时间；该会话访问普通业务与管理接口会被 `internal/session` 既有守卫拒绝，且**不允许续期**（保持短时边界）。恢复流程只通过 `Snapshot`（核对状态/允许方式/剩余代码）、`BeginRebind`/`Complete`（绑定新安全方式）与 `Cancel`（取消退出）提供能力，不签发任何 OAuth/Token。root 恢复会话默认拒绝（`AllowRootRecoverySessions` 默认 false，root 应急恢复必须走受控本地通道）。
- **新因素验证前保留旧状态**：在 `FactorBinder.VerifyRebind` 真实验证成功前，恢复流程不删除/不降级任何旧 MFA 因素、不撤销用户既有会话、不生成新代码组；绑定计划（方法+绑定 ID）由服务端记录并与完成请求交叉校验，客户端不能跳过“开始绑定”直接完成。新因素验证失败只递增有界尝试次数并写失败审计，用尽后尝试作废并发送告知，恢复仍未完成。
- **强度要求与不降级**：宿主注入 `Requirements.RecoveryStrength` 按账户真实权限返回最低强度（未注入时默认 `StrengthStrong`，fail-closed）；强认证要求下只允许 WebAuthn 用户验证（UV）的 Passkey/安全密钥证明，TOTP 只能在要求为“第二因素”时使用，**邮件永远不是恢复流程允许的新因素**——密码 + 恢复代码不能把已绑定的安全密钥降级为邮箱。要求不可用时在消费代码前 fail-closed，避免烧掉用户代码。
- **完成后作废旧凭证并要求重新登录**：完成在同一个审计事务内：结束尝试、条件作废旧代码组（旧组已被并发撤销/取代时 fail-closed 整体回滚，不插入新 active 组）、生成新一组恢复代码、递增账户 `security_version`（使恢复前建立的会话立即失效）并写成功审计；提交后尽力撤销该用户全部会话、按策略撤销旧 MFA 因素（`FactorRevoker`）并发送不含代码明文的安全告知，随后必须使用新配置的安全方式重新正常登录（`ReloginRequired=true`）。提交后撤销失败不回滚已完成的恢复（安全版本已递增），但写失败审计；新代码只返回一次，投递失败需要用户重新登录后再次更新。
- **取消/中断安全处理**：`Cancel` 只结束尝试并尽力退出恢复会话，不删除旧因素、不作废旧组、不递增安全版本；已消费的代码不会恢复（一次性语义），用户可用剩余代码或正常方式重新登录。尝试超过有效期后在读取时惰性迁移为 `expired` 并拒绝后续操作。
- **敏感策略与防 MFA 绕过（44-FIX）**：恢复代码生成/重新生成走步骤 38/39 的 `recovery.codes.rotate` 操作与近期认证（目录条目 `Implemented=true`）。同时新增可注入的账户所需强度契约 `AuthLevelRequirements.RequiredLevel`：**已绑定强因素或高权限账户必须返回 `AuthLevelStrong`**，服务端要求 `reauth.Signals` 中携带新鲜（默认 15 分钟、可配置 1 分钟～24 小时）的强认证事实（宿主会话中间件必须把 `session.Session.StrongAuthVerifiedAt`/强认证标记映射为 `reauth.WithSignals`），否则拒绝更新恢复代码并写失败审计——避免“完整会话+密码”静默重新生成恢复代码后再用“密码+新码”替代第二因素绕过 MFA。未绑定强因素的普通账户可返回 `AuthLevelPassword` 仅要求近期主密码（避免死锁）；未注入契约时默认按 `AuthLevelStrong` fail-closed。
- **通知与审计**：恢复代码生成、代码使用、开始绑定、验证失败、完成、取消、过期与旧因素/会话撤销失败均有稳定审计动作；代码、摘要、会话秘密与绑定秘密不进入日志、审计、错误或告知正文；`MailNotifier` 复用 `internal/mailer` 告知模板只向已验证邮箱发送（测试使用本地捕获器/测试发送器，不真实外发）。
- **错误码**：只复用既有 46 码：参数问题 `REQ_INVALID`，越权/root 保护 `ACCESS_DENIED`，更新代码需近期认证 `REAUTH_REQUIRED`，受限恢复会话需重新绑定/强度不足/方式不允许 `MFA_REBIND_REQUIRED`，代码/尝试无效或过期或验证失败 `CHALLENGE_INVALID`，并发冲突 `CONFLICT`，限流 `RATE_LIMITED`，策略不可用 `AUTHZ_UNAVAILABLE`，存储/会话 `DB_UNAVAILABLE`，审计 `AUDIT_WRITE_FAILED`，告知 `MAIL_DELIVERY_FAILED`。
- **已知限制**：HTTP 路由/页面/`cmd/login-server` 装配、真实认证器与真实邮件外发、客服/管理员人工核验恢复（`recovery.request`/`recovery.approve`/`recovery.mfa.approve` 工作流与审批）、root 受控恢复 CLI、恢复代码过期清理任务、多实例限流、race 与非 Windows 未验证；`FactorBinder`/`Requirements`/`FactorRevoker` 的生产适配器需宿主装配（测试替身只验证接口契约）。

## FIDO2 第二步验证与认证方式选择策略（步骤 43）

新增内部认证事实层 `internal/authfact`，扩展 `internal/passkey` 的凭证用途与第二步认证 ceremony，扩展 `internal/mfa` 的安全密钥因素、统一选择器与强认证初始化闭环，迁移 `0023_fido2_second_factor.sql`（重建三表：凭证 usage 增加 `both`、ceremony 增加 purpose/context_id 与 second_factor 操作、MFA 挑战增加 passkey 因素/strong_setup 用途/factor_ref/require_strong）。协议与密码学仍由 `go-webauthn` 完成，本步**不实现 OAuth/OIDC amr/acr 端点、不暴露 HTTP 路由与页面**。

- **凭证用途**：Passkey 凭证用途分为 `login`（主登录）、`second_factor`（密码后的安全密钥第二步）与 `both`；用途由服务端注册 ceremony 决定并持久化，完成注册时使用挑战中保存的用途，客户端不能改写。主登录只接受 `login/both`，第二步只接受 `second_factor/both`，注册挑战/登录挑战/第二步挑战的操作类型不能互相替代；已有 0022 凭证升级后保持 `login`（不会被自动当作第二因素）。
- **FIDO2 第二步**：密码认证后由 MFA 创建第二步 WebAuthn 挑战（ceremony 绑定 MFA 挑战 ID，`allowCredentials` 只含第二步用途凭证），校验 challenge/来源/RP ID/签名/UP/UV；成功后才用同一受限会话轮换完整会话，沿用步骤 40 的 AppID/记住我/客户端绑定与限流、尝试上限、应用作用域不升级语义；非同步凭证计数器回退按可能的复制拒绝。
- **认证方式动态步骤与选择器访问控制**：`internal/authn` 通过可注入 `StrongFactorPresence` 按账户实际已绑定强因素动态给出 RequiredSteps（已绑定只需第二因素，未绑定才要求强因素初始化；未接线时保守按未绑定处理）；`mfa.AvailableSecondFactorMethods` 只允许本人（或系统可信装配层）查询，普通用户不能枚举他人可用方式。选择器语义：`internal/authfact` 统一定义方法（密码/邮件验证码/TOTP/Passkey/安全密钥/恢复代码预留）、因素类别、事实集合、强度（single/MFA/strong）、策略要求与 `Select/Eligible` 选择器、amr/acr 映射函数。选择器只返回用户实际启用且满足策略的方式：Passkey/安全密钥（UV）与密码+TOTP 可满足强认证，邮件不能单独满足强认证、也不会被选中满足强认证；同一因素验证两遍不计为两个独立因素；无可用方式时明确返回错误而不降级。`mfa.AvailableSecondFactorMethods` 提供按用户实际启用因素的可用方式列表。
- **强度与再认证衔接**：Passkey/安全密钥完成 UV、或密码+安全密钥的完整登录会在认证结果与会话中记录强认证时间；管理访问的强认证闸门按 `session.Options.StrongAuthMaxAge`（默认 15 分钟、1 分钟～24 小时）校验新鲜度，过期后必须重新强认证，**不是一次强认证永久有效**；受限结果携带强认证时间会被拒绝。`AllowTOTPForStrongAuth` 默认 false（强认证默认要求 UV，密码+TOTP 不作为管理强认证）；宿主显式开启时才接受密码+TOTP 受控备用。认证强度不机械相加；高风险操作仍按步骤 39 策略要求近期认证/确认。
- **强认证初始化闭环（受限，不公开旁路）**：要求强认证但未绑定强因素的账户，密码正确后若宿主显式启用 `AllowStrongAuthSetup`（且注入受限会话撤销器、强因素来源与 `StrongSetupAuthorizer` 受控初始化授权器），只签发**受限会话**并返回允许绑定的强因素方法（默认 Passkey，邮件永远不允许）。授权器必须是可信来源：内置 `bootstrap.Service.AuthorizeStrongSetup` 只放行 root 且状态为 pending_setup/setup_verified 的受控初始化；其他高权限账户需要宿主实现管理员一次性凭证/审批，**普通受限会话不能自助绑定攻击者可控强因素**。绑定完成后必须调用 `CompleteStrongSetup`：校验受限会话/尝试令牌/挑战、确认已真实绑定强因素、撤销受限会话并要求重新登录，全程不签发完整会话。root 既有保护不变，未启用/未授权时继续 fail-closed 返回 MFA_REQUIRED。
- **删除强因素与最后因素保护**：强制 MFA 账户删除最后一个第二步用途凭证且没有其他强因素（如 TOTP）时拒绝（CONFLICT），凭证仍为软删除并写失败审计。删除 Passkey 或解除 TOTP 都会在同一审计事务内递增用户 `security_version`（并尽力调用注入的会话撤销器），使删除前建立的会话（含记住我）在下次校验时立即失效，不能继续凭旧强认证访问管理接口。邮件因素移除沿用步骤 40 的最后因素保护。
- **已知限制**：真实浏览器/Windows Hello/YubiKey 安全密钥未实测（测试使用模拟认证器，且 mfa 侧安全密钥适配器用测试替身验证挑战/会话/策略，真实 WebAuthn 校验在 `internal/passkey` 测试中覆盖）；OAuth/OIDC amr/acr 仅内部映射未接协议端点；取消/清理初始化挑战任务、多实例限流、race 与非 Windows 未验证；恢复代码仍属后续步骤。

## Passkey 注册、登录与凭证管理（步骤 42）

新增内部 Passkey 域 `internal/passkey` 与 SQLite 仓储 `internal/passkey/sqlite`，迁移 `0022_passkey.sql` 落地 `webauthn_user_handles`（稳定随机用户句柄）、`webauthn_credentials`（公钥凭证元数据）与 `webauthn_ceremonies`（服务端挑战）；WebAuthn 协议与密码学校验使用维护中的 `github.com/go-webauthn/webauthn v0.18.2`（BSD-3-Clause，Go 1.26.0），**不自行实现 WebAuthn 密码学、不实现 FIDO2 第二因素、不暴露 HTTP 路由与完整前端**，验收走可信内部 Go API。测试使用模拟认证器，**不代表真实浏览器/Windows Hello/安全密钥实测**。

- **RP ID 与允许来源**：根配置新增 `passkey.enabled`（默认 false，默认拒绝）、`passkey.rp_id`、`passkey.rp_display_name`、`passkey.allowed_origins`、`passkey.user_verification`（默认 required）及固定环境变量 `LOGIN_PASSKEY_*`；RP ID 必须是可注册域名（拒绝 IP/协议/端口/路径），来源必须是 https（本地开发只允许 `http://localhost`）且主机属于 RP ID 或其子域，非法配置在加载/构造阶段拒绝。Passkey 不跨 RP ID 通用，多域名监听不等于可跨任意域名使用。
- **注册**：挑战只保存在服务端并一次性原子消费；新增凭证要求近期认证与 `passkey.register` 敏感策略（默认与 `mfa.add` 一致的近期主密码 300 秒 + 安全告知，避免“首个强因素无法建立”的死锁，宿主可加严为 strong）。用户句柄为 32 字节随机值，与用户 ID 无关且稳定；凭证绑定服务端挑战中的用户，客户端不能把他人的凭证登记到自己名下；`credential_id` 全表唯一，重复或跨用户注册返回 CONFLICT；注册要求可发现凭证（resident key required）。
- **登录**：支持用户名登录与可发现凭证（usernameless）登录；库校验 challenge、操作类型（注册/认证）、来源、RP ID、签名、用户在场（UP）与按策略要求的用户验证（UV），注册挑战不能用于认证、反之亦然。验证成功且满足 UV 策略的 Passkey **直接完成登录**（认证方法只有 `passkey`，不机械追加同源第二因素），会话由 `internal/session` 签发；应用作用域在开始阶段绑定到服务端挑战，完成阶段只以同一 AppID 签发并防御性复验，**不会升级为全局会话**（沿用步骤 40 修复语义）；用户名不存在、账户禁用或无凭证统一返回 `AUTH_FAILED`，不泄露账户存在性。
- **同步凭证计数器**：backup eligible（同步 Passkey）的签名计数器允许不递增并被接受；非同步凭证计数器不递增按可能的凭证复制拒绝（`AUTH_FAILED`）并写失败审计。BE/BS 备份状态元数据持久化并随登录更新。
- **凭证管理**：提供查询、重命名（显示名，不改变安全状态）与撤销；撤销要求 `passkey.remove` 近期认证，并在同一审计事务内检查不得删除最后一个可用登录方式（仍有其他 Passkey 或主密码才允许），软删除保留审计关联。
- **已知限制**：HTTP 路由/页面/`cmd/login-server` 装配、FIDO2 第二因素与完整认证方式选择策略（步骤 43）、恢复代码、MDS/attestation 证书链校验（原始 attestation 数据未持久化）、真实浏览器与真机实测、过期挑战清理任务、race 与非 Windows 验证未做；root 的 Passkey 登录仍 fail-closed（root 强认证路径待后续步骤/CLI 收口）。

## 两步验证公共流程与邮件第二步验证（步骤 40）

新增内部 MFA 状态机 `internal/mfa` 与 SQLite 仓储 `internal/mfa/sqlite`，迁移 0020 落地 `mfa_factors`（活动因素）与 `mfa_challenges`（统一挑战：用户、登录尝试摘要、用途、因素、验证码凭证、重发代数、状态机与有效期）；本步**不实现 TOTP/Passkey/FIDO2，不做页面与 HTTP 路由**，验收走可信内部 Go API。

- **统一状态机**：挑战只有 `pending` 一个起点，只能条件迁移为 `verified`/`failed`/`expired`/`cancelled`；迁移必须同时匹配尝试摘要、重发代数与未过期，并发消费与重放只有一方成功。挑战绑定用户、当前登录尝试（客户端持有的一次性尝试令牌只存摘要）、用途（登录/因素新增）与因素类型；验证码错误计数达到上限时挑战迁移为 `failed`。挑战还记录第一步的作用域/记住我/客户端描述与**受限会话 ID**，Verify 必须使用同一受限会话（同用户、同应用作用域、受限原因=待第二因素）完成，其他受限会话不能完成本挑战。
- **邮件第二步**：验证码复用 `internal/credential` 的受密钥保护低熵验证码（库中只存 HMAC 摘要、有尝试上限、有效期、原子消费；重发用 ReplaceActive 使旧码立即失效），只发送到**已验证邮箱**；`internal/mailer` 受控发送接口与模板渲染，明文验证码只出现在邮件正文，绝不进入日志、审计、错误或队列；发送失败 fail-closed。
- **第一步只拿受限状态**：启用邮件因素后，第一步密码认证成功只签发 `internal/session` 的**受限会话**；第二步验证成功后才用同一受限会话秘密轮换为完整普通会话（复用会话服务，不另建会话体系），并沿用第一步的 `AppID`/记住我/客户端描述，应用作用域登录不会在第二步后变成全局会话（签发后再次防御性校验作用域）。旧受限会话在轮换后失效；取消登录只取消挑战与验证码，已签发的受限会话不能通过普通用户撤销 API 撤销，由宿主会话管理/到期回收（不作为已认证状态）。
- **强制策略与账户限流**：宿主 `Policy.MFARequired` 为真但账户没有可用因素时，`BeginLogin` fail-closed 返回 `MFA_REQUIRED`（不签发任何会话），不能仅凭密码完整登录。账户维度有界滑动窗口限流（挑战创建/验证尝试/重发，可配置 `RatePolicy`）防无限重建挑战爆破验证码与邮件轰炸；传输层 IP/接口限流仍待 HTTP 接线。
- **高权限账户 fail-closed**：root 与持有高敏感权限的账户在密码正确后仍要求强认证（authn 返回受限/待强因素状态），邮件因素**不能**满足其强认证要求，`BeginLogin` 直接返回 `MFA_REQUIRED` 且不创建登录挑战、不签发任何会话，账户保持受限配置状态；管理强认证未实现部分继续拒绝。
- **因素管理**：新增因素必须先向已验证邮箱发送验证码并验证成功（证明渠道控制权），已有邮件因素时重复新增返回 `CONFLICT`；移除需检查宿主 `Policy`：被强制要求 MFA 时不能移除最后一个可用因素，未强制时才允许本人移除。当前只有 email 因素，TOTP/Passkey/FIDO2 后续按同一 `FactorType`/`Store`/挑战接口接入，本步不预置空实现。
- **拒绝留痕与不泄密**：高权限拒绝、无已验证邮箱、验证码错误/状态不符/作用域不符、重发冷却、挑战/验证限流、邮件发送失败（带真实用户 Actor）、因素移除被策略拒绝等路径写失败审计；审计/错误/日志不含验证码、尝试令牌或会话秘密。
- **错误码**：只复用既有 46 码：参数/因素问题 `REQ_INVALID`，越权 `ACCESS_DENIED`，高权限需强认证/需第二因素/无邮箱 `MFA_REQUIRED`，挑战/验证码/过期/尝试用尽 `CHALLENGE_INVALID`，限流 `RATE_LIMITED`，强制策略拒绝移除 `CONFLICT`，策略不可用 `AUTHZ_UNAVAILABLE`，存储/会话 `DB_UNAVAILABLE`，审计 `AUDIT_WRITE_FAILED`，邮件 `MAIL_DELIVERY_FAILED`。
- **已知限制**：TOTP/Passkey/FIDO2/恢复代码、页面、HTTP 路由、`cmd/login-server` 装配、失败告知与密码找回未实现；取消登录不撤销已签发受限会话（普通用户撤销 API 拒绝受限会话；由宿主会话管理/到期回收）；因素切换（多因素间替换/降级）与“移除需再次验证”留后续；过期挑战/验证码清理任务、跨实例限流/并发压测、race 与非 Windows 未验证；`SetRootPassword` 仍未接 Sensitive（待 CLI/装配收口）。

## 再次认证、认证强度与敏感操作安全告知（步骤 39）

新增内部再次认证包 `internal/reauth` 与 SQLite 仓储 `internal/reauth/sqlite`，迁移 0019 落地 `reauth_challenges`、`reauth_approvals`、`security_notifications`；把步骤 38 的敏感操作目录接成「执行前校验 + 执行后告知」闭环。本步**不实现 MFA/Passkey、不做页面、不暴露 HTTP 路由**，验收走可信内部 Go API 与真实本地依赖。

- **执行前收敛入口**：`OperationRunner.Authorize`（`*Service`）按当前作用域有效策略评估近期认证事实（验证时间、实际强度、是否完整认证、是否已确认）；不满足时只有**绑定调用者 + 作用域 + 稳定操作 ID + 目标 + 服务端计算的参数摘要**的短时一次性批准才能继续。批准令牌只存 SHA-256 摘要、明文只返回一次，消费是审计事务内条件更新：换对象、换参数、重复使用、过期一律拒绝。
- **挑战与批准**：`BeginChallenge` 为需要再次认证的操作创建有界尝试次数的挑战；`VerifyChallenge` 通过注入的 `PasswordVerifier` 真实验证密码（生产适配 `authn.ReauthPasswordVerifier` 复用正式密码校验、失败限流与审计），成功后产生一次性批准。挑战不是批准；密码失败递增尝试次数并写失败审计。
- **强度与完整性**：只有真实完成且可验证的方式计入，不同方法不机械相加；当前只有密码方式可用（MFA/Passkey 未实现），要求 `strong` 的操作在挑战与执行前都 fail-closed 为 `MFA_REQUIRED`，不降级为密码；高权限（root 专属）操作还要求完整认证（无待完成第二因素/改密步骤），管理强认证未满足时继续拒绝。
- **执行后告知**：策略要求告知时向**已验证邮箱**渲染 `internal/mailer` 安全告知模板并发送；无已验证邮箱、未配置发送器、投递失败、失败告知限频分别记录 `state`/原因码，**不回滚已经成功的业务变更**，也不把通知当认证。失败高风险告知按用户+操作在窗口内限频（能力与测试在 `internal/reauth`，但**业务模块的失败路径尚未调用**，仅成功路径已接线，见已知限制）。测试使用 `internal/testmail` 本地捕获器，不真实外发。
- **策略变化即时生效**：每次执行前实时读取步骤 38 有效策略，root 修改覆盖值（例如收紧认证新鲜度）后下一次判定立即按新值执行；恢复默认同样生效。
- **接入范围（已接线）**：`internal/profile` 受控更名（`profile.username.change`）；`internal/emailchange` 申请变更（`email.change.request`）与令牌确认切换（`email.change.verify`，令牌持有者是操作主体，成功后在目录策略要求时发送告知）；`internal/role` 用户/组赋角色（`permission.role.assign`）、组合/移除权限（`role.permission.change`，绑定增/删方向+权限 ID）、启用/停用角色（`role.state.change`）；`internal/group` 批量加/移除成员（`group.member.change`，绑定方向+规范化成员集合摘要）；`internal/session` 管理强制下线（`session.management.access`，仍先过既有 `CanAccessManagement` 强认证闸门）；`internal/authn.SetPassword` 设置/修改密码（用户自助 `password.change`、管理/系统通道 `password.admin_reset`）。所有绑定参数由服务端从业务字段计算（目标/范围/方向/集合/关键参数），不接受客户端自述摘要。执行前判定失败一律 fail-closed，成功路径调用 `NotifyOutcome`。既有 `delegation.Guard`、`ReauthVerifier`、强认证闸门保留且不被替代。`internal/authn` 另提供生产 `ReauthPasswordVerifier`（真实 Argon2id 密码校验/限流/审计，返回已完成与完整认证标记）作为再次认证唯一可信密码来源；密码找回/改密流程（步骤 45）本步不实现。
- **fail-closed 与过渡开关**：敏感操作的 `Options.Sensitive` 默认未注入时**直接拒绝**（不静默跳过步骤 38 策略）；只有显式 `Options.AllowLegacyWithoutSensitive`（默认 false，仅供旧装配/测试过渡）才回退既有保守闸门。生产装配必须注入 `OperationRunner`；未装配不会放行。
- **错误码**：只复用既有 46 码：参数 `REQ_INVALID`，密码失败 `AUTH_FAILED`，批准无效/过期/重放 `TOKEN_INVALID`，越权 `ACCESS_DENIED`，再次验证/确认 `REAUTH_REQUIRED`，未实现强认证 `MFA_REQUIRED`，挑战无效/过期/尝试用尽 `CHALLENGE_INVALID`，限流 `RATE_LIMITED`，策略不可用 `AUTHZ_UNAVAILABLE`，存储 `DB_UNAVAILABLE`，审计 `AUDIT_WRITE_FAILED`，告知失败 `MAIL_DELIVERY_FAILED`。
- **已知限制**：MFA/Passkey、HTTP 路由/页面/CLI 装配未实现；请求/批准/告知通过 Go API 与宿主装配验证；失败高风险告知已实现且有限频测试，但业务模块的失败路径尚未调用；`authn.SetRootPassword`（root 正式密码设置）尚未接入敏感策略（待 CLI/受控装配步骤按 `authn.root_password.setup` 收口）；`OperationRunner` 与 `PasswordVerifier` 需宿主装配，未装配时再次认证拒绝、模块保持既有保守闸门（不因未接线而放行）；未完成任务清理（过期挑战/批准）后台任务；失败告知限频为单实例进程内状态；`Authorize` 读取策略不含作用域级读取授权（策略包已记录）；未验证 race/非 Windows。

## 敏感操作策略目录、root 策略配置与恢复默认（步骤 38）

新增内部敏感策略包 `internal/policy` 与 SQLite 仓储 `internal/policy/sqlite`，迁移 0018 落地 `sensitive_policy_scopes`（每个作用域的策略版本）与 `sensitive_operation_policies`（只保存偏离默认值的覆盖行与应用声明，不复制系统默认目录）；本步**只做目录/策略配置层，不执行敏感操作、不暴露 HTTP 路由、不接 `cmd/login-server`**，执行器与页面留步骤 39 及后续，验收走可信内部 Go API 与测试。

- **稳定操作目录**：系统内置 35 个稳定操作标识，覆盖密码修改/管理员重置、MFA/Passkey/恢复代码、邮箱变更、受控更名、角色与权限调整、应用凭证轮换、敏感数据导出、备份导出/恢复、审计清理、root 恢复、客服恢复审批、会话管理强认证、「修改敏感策略」本身，以及 onboarding 邀请创建/注册审核、authn root 设置正式密码、邮箱变更确认、角色组合权限/角色启停、组成员变更、客服求助单登记/更新与向原验证邮箱发起找回、人工核验恢复申请/审批/执行，以及 OAuth 客户端安全设置登记/修改等专门操作；每条含中文名称、直白说明、默认策略、基础权限标识、是否 root 专属、是否不可取消敏感与业务是否已实现。默认策略保守：高风险/root 专属操作默认要求强认证，MFA/Passkey 未实现前这些要求 fail-closed。
- **默认与覆盖合并**：数据库只保存偏离默认值的覆盖行；读取有效策略时由目录默认值逐字段合并覆盖行，恢复默认即删除覆盖行，因此目录升级不会重写用户配置、也不会把配置误当默认值。支持读取有效策略、相对默认值的字段差异、逐项恢复与整体恢复（整体恢复只删除 override，保留应用声明操作；无覆盖时幂等成功、不递增版本、不伪造审计）。
- **版本与并发**：每个作用域（system 与各应用）独立策略版本，只有真实变更才递增；修改/恢复必须携带期望版本并在同一审计事务内条件递增，过期版本返回 `CONFLICT`，两个服务实例并发只有一成功。
- **root 与变更保护**：系统和应用策略只能由**真实 root 账户**修改（受信 system/local_admin 也不能自称 root），且必须通过宿主注入的 `ReauthVerifier`；未接线/验证失败 fail-closed 返回 `REAUTH_REQUIRED`。普通管理员、应用管理员与普通用户一律拒绝。修改与恢复默认均在同一审计事务写成功/失败审计（稳定用户 ID、操作 ID、来源、字段差异），审计失败整体回滚。
- **不可被策略取消的约束**：策略只可覆盖「是否敏感/是否要求再次验证/认证新鲜度/所需认证强度/是否需要确认/是否需要告知」六项；基础权限、root 专属限制与审计要求固定在代码目录中，取消「敏感」标记只取消额外验证/确认要求，不解除这些约束；高风险操作（移除 MFA/Passkey、恢复备份、清理审计、root 恢复、修改策略本身）标记为不可取消敏感。
- **应用作用域**：应用作用域使用独立版本与独立覆盖，与系统作用域互不影响；应用可声明自身敏感操作，但声明与配置都由 root 完成并写审计（应用管理员不能声明或修改；应用发起 + root 审核工作流留后续）。应用声明操作没有系统默认值，不能逐项恢复默认。
- **未实现验证方式 fail-closed**：服务用显式可用强度集合判断（默认只认为 none/password 可用）；要求 `strong`（MFA/Passkey）但当前环境未实现时评估返回 `MFA_REQUIRED`，不降级为密码；缺少/过期/未来时间戳的验证返回 `REAUTH_REQUIRED`，缺少确认同样拒绝。评估只表达策略层要求，不替代基础权限检查与审计。
- **既有临时保守定义的关系**：步骤 29 authn 的高敏感权限强认证要求、步骤 31 session 管理强认证门、步骤 35 profile 更名再次验证、步骤 36 emailchange 再次验证、步骤 34 onboarding 管理强认证属于操作级安全要求的临时实现；本包把它们登记为目录默认值并作为唯一策略来源，**在执行器接入（步骤 39）前既有模块的 fail-closed 行为保持不变**，不因本包存在而放宽。
- **错误码**：只复用根包已登记错误码（不新增）：参数/非法组合/未知操作/无默认值 `REQ_INVALID`，非 root 或越权 `ACCESS_DENIED`，再次验证/确认 `REAUTH_REQUIRED`，未实现强度 `MFA_REQUIRED`，版本冲突 `CONFLICT`，存储不可用 `DB_UNAVAILABLE`，审计不可用 `AUDIT_WRITE_FAILED`。
- **仅登记、由后续接线收口**：`Evaluate` 目前不做作用域读取授权（`Effective`/`Diff`/`Version` 有 `authorizeRead`），步骤 39 接线时必须限定可信调用方；应用声明操作暂无取消声明 API；`Effective`/`Diff` 分两次查询版本与覆盖（非事务一致快照）；应用作用域允许 root 覆盖内置系统操作的策略（语义为应用级调整，不改变系统策略）；race/非 Windows/HTTP 装配/authz 动态判定接线未验证。
- **已知限制**：执行器、HTTP 路由、页面、CLI 与 `cmd/login-server` 装配未实现；应用发起的敏感操作声明与 root 审核工作流未实现（当前声明只能由 root 直接完成）；未接入 `internal/authz` 做 `security.policy.manage` 动态判定（本步要求真实 root + 再次验证，语义更严格）；认证强度到会话/令牌事实的映射、告知投递接线、策略缓存与多实例并发（仅依赖数据库条件更新，未做分布式锁）未验证；未做 race/非 Windows 实测。

## 头像上传、受控存储与网络头像处理（步骤 37）

新增内部头像域 `internal/avatar` 与 SQLite 仓储 `internal/avatar/sqlite`，迁移 0017 落地 `avatars` 表（每用户一个头像、受控存储相对键唯一、内容摘要）；本步**不暴露 HTTP 路由、不接 `cmd/login-server` 装配、不做通用文件管理**，验收走内部 Go API，展示时由宿主用 `Content.SetResponseHeaders` 写响应头。

- **上传校验与重编码**：单次原始字节上限 2 MiB、单边 8～1024 像素、总像素上限 1024×1024；用 `image.DecodeConfig` 先读真实尺寸再解码，避免超小字节超大尺寸的解压膨胀；只接受 PNG/JPEG/GIF，**SVG 等主动内容默认拒绝**（声明为 `image/svg+xml` 直接拒绝，SVG 字节伪装成图片也会在解码阶段失败）；声明类型必须与真实字节一致；保存的内容是重编码结果（PNG 保持 PNG、JPEG 质量 90 重编码、GIF 只取首帧转静态 PNG），原始字节、EXIF/文本块与动画扩展块不会落盘。
- **受控存储**：目录由宿主显式指定并在构造时校验（拒绝符号链接/普通文件路径），文件名与 `ab/32位十六进制.png` 存储键全部由服务端 128 位随机数生成，`O_EXCL` 创建不覆盖；读取前校验键格式、路径未逃逸目录、文件大小与 SHA-256 摘要，文件被替换/篡改时 fail-closed；不向调用者返回存储键或本机路径。
- **引用更新与失败补偿**：新文件先写入，再在审计事务内条件更新 `users.avatar_ref`、替换 `avatars` 行（行版本冲突返回 `CONFLICT`）；数据库/审计失败会补偿删除刚写入的新文件，旧引用保持不变；事务提交后才删除旧文件，旧文件删除失败不影响已成立的替换，由 `CollectGarbage` 只清理“目录内合法存储键、数据库不再引用且修改时间早于安全窗口（默认 10 分钟，`Options.GCSafetyWindow` 可调，允许范围 30 秒～24 小时）”的文件（不触碰其他文件）。安全窗口避免与新文件落盘、数据库引用事务尚未提交的窗口竞态：在途新文件不会被误删，窗口过后仍未被引用才视为孤儿。
- **网络头像（受控抓取）**：默认仅允许 https 默认端口、无 URL 凭证、主机名可白名单；DNS 解析结果的每个地址都会校验，**拒绝环回/私有/链路本地/CGNAT/组播/保留与文档网段**，并直接连接校验过的 IP 避免 DNS 重绑定；每次重定向重新校验且限制次数（默认 3），总时限（默认 10 秒）与响应字节上限受控，关闭自动解压防止压缩炸弹；抓取到的字节走与上传完全相同的重编码流程。默认生产策略拒绝本地/明文目标；测试使用本包明确命名的 `TestOnlyAllowLocalAddresses` 开关访问本地 httptest 服务，生产/预生产不得启用。
- **授权与审计**：默认只允许本人与受信 system/local_admin 读写；跨用户展示必须先由宿主注入 `Authorizer`（未接线 fail-closed），先判权后读目标避免泄露存在性；上传/替换/清除/抓取都在安全审计中记录稳定用户 ID、头像 ID、媒体类型/大小/尺寸/来源类型（网络只记录已校验主机名，不记录完整 URL/查询串/令牌），失败审计记录稳定错误码。
- **错误码**：只复用根包已登记错误码（不新增）：参数/图片/远端内容问题 `REQ_INVALID`，非允许网络目标 `RESOURCE_FORBIDDEN`，越权 `ACCESS_DENIED`，版本冲突 `CONFLICT`，记录/文件存储不可用 `DB_UNAVAILABLE`（内部原因码区分），审计不可用 `AUDIT_WRITE_FAILED`。
- **已知限制**：HTTP 路由、页面、`cmd/login-server` 装配与 `users.avatar_ref` 外键约束未实现；`Policy`/`Network`/`GCSafetyWindow` 通过 Go `Options` 注入（未新增根配置 YAML/环境变量节）；头像更新会使 `users.row_version` 递增，客户端需重新读取；EXIF 方向不应用、不做裁剪/缩放；GIF 一律转为静态 PNG；文件存储不可用复用 `DB_UNAVAILABLE` 对外码；GC 安全窗口按单实例受控目录设计（多实例写入由窗口兜底，严格跨实例互斥未实现）；未做 race/非 Windows/真实外网抓取验证。
- **需在 HTTP/装配阶段收口的已知限制**（本步记录、不修复）：`NetworkPolicy.TestOnlyAllowLocalAddresses` 是**导出的生产配置字段**，目前仅靠 GoDoc 约束不得启用，HTTP/装配接线前应改为构造校验、独立测试构建标签或等价隔离，防止生产误启用；默认授权口径（未注入 `Authorizer`）只校验身份 ID，**不检查账户状态**，禁用/待审核用户若宿主仍传递 `Caller` 仍可修改自己头像，HTTP/装配接线时必须由宿主的会话/状态校验或注入的 `Authorizer` fail-closed 补齐。

## 已验证邮箱变更（申请、验证新地址与切换，步骤 36）

新增内部邮箱变更域 `internal/emailchange` 与 SQLite 仓储 `internal/emailchange/sqlite`，迁移 0016 落地 `email_change_requests` 表（每用户至多一条 pending 部分唯一索引）；本步**不暴露 HTTP 路由、不接 `cmd/login-server` 装配、不签发会话**，验收走内部 Go API。

- **申请与身份验证**：`RequestChange` 只允许已认证用户本人发起，并必须通过宿主注入的 `ReauthVerifier`（近期身份验证）；未接线或验证失败一律返回 `REAUTH_REQUIRED`，不接受“新邮箱自证”接管。申请绑定用户、旧已验证邮箱（无旧邮箱时为空 = 首次添加流程）与规范化新邮箱；新地址验证成功前旧 `user_emails` 行与 `verified_at_ms` 保持不变。新申请会在同一审计事务内取消旧 pending 申请（旧令牌即使仍活动也无法切换）。新邮箱已占用时自助接口返回通用请求错误（不在 HTTP 前暴露他人邮箱是否存在；HTTP 接线前仍需统一响应形状并叠加限流）。
- **验证与切换**：一次性高熵令牌（用途 `email.change.verify`、目标为申请 ID）通过邮件发送到**新地址**；`Verify` 先消费令牌，再在审计事务内校验账户状态（`active`/`pending`，禁用账户拒绝）、pending/未过期/旧邮箱版本仍匹配/新邮箱未被其他用户占用，通过后删除旧已验证行（并清理同用户同地址未验证行）、写入新已验证行并标记 completed；任一失败整体回滚。**令牌补偿**：事务失败时服务在同一 pending 申请上重新签发凭证并把新凭证 ID/令牌/入口地址返回给本次调用方（宿主应立即重投递，且不得写入日志/审计/库），避免用户白烧链接。重复点击、过期、取消、新邮箱被占用分别返回统一失效/`CHALLENGE_INVALID`/`CONFLICT`。
- **旧邮箱告知**：切换成功后按策略向旧已验证邮箱发送安全告知（`internal/mailer` 安全告知模板，只含事件/时间/支持入口，不含令牌或校验链接）；投递失败不回滚已完成切换，只记录可查询的 `notify_state`/稳定错误码。验证邮件发送失败同样只记录 `verify_state=failed` 与错误码，申请仍可重发/取消。
- **边界**：首次添加（用户无已验证邮箱）同样要求近期身份验证；无可信身份时拒绝普通自助修改并留给恢复流程；本步不解除/绕过 MFA，不提供管理员改他人邮箱的通道。审计目标使用稳定用户 ID，邮箱只记录脱敏值，令牌不入库/日志。
- **已知限制**：HTTP 路由、页面、`cmd/login-server` 装配未实现；通知与验证邮件重发/过期申请清理任务未实现；验证令牌在审计事务之前消费，事务失败时返回补偿令牌（旧链接已失效，需宿主重投递）；事务切换内已检查账户状态与旧邮箱版本，但更名/邮箱变更不会自动撤销既有会话（本步未递增 `security_version`）；旧邮箱告知通过可靠投递入队，`sent` 表示入队成功而非外部送达；未做 race/非 Windows/真实外发。

## 用户自助资料修改与管理员修改（步骤 35）

新增内部资料域 `internal/profile` 与 SQLite 仓储 `internal/profile/sqlite`，迁移 0015 为 `users` 追加 `phone`、`phone_verified_at_ms`、`username_changed_at_ms`；本步**不暴露 HTTP 路由、不接 `cmd/login-server` 装配、不签发会话**，验收走内部 Go API。

- **字段白名单与版本冲突**：只允许昵称、简介、语言、时区与可选电话；`ParseProfileJSON` 严格拒绝 `is_root`、`password`、`email_verified`、`mfa`、`roles`、`status`、`username` 等额外字段。更新使用 `expected row_version` 条件 UPDATE，并发冲突返回 `CONFLICT`，不部分修改；成功与审计同事务。
- **自助与管理员范围**：先判权后读目标，无权调用者对存在/不存在目标统一 `ACCESS_DENIED`；`UpdateSelf` 只允许本人（普通用户 `Caller`）；`UpdateUser` 默认只允许本人与受信 system/local_admin，普通用户修改他人 fail-closed；宿主可通过 `Authorizer` 注入按权限/范围的管理授权（不接强认证前不默认放行）。
- **受控更名**：复用 `account.NormalizeUsernameWithReserved` 的 NFKC/大小写折叠规则，稳定用户 ID 不变；`Policy` 采用显式三态逐字段合并安全默认（冷却默认 24 小时、`RequireReauth` 默认 true，只配置其中一个字段不会静默关闭另一个保护），未注入 `ReauthVerifier` 时普通用户 fail-closed（受信 system/local_admin 通道不受回调限制）；保留名默认沿用 `account` 清单，`Policy.ReservedNames` 可追加自定义保留名、`DisableReservedNames` 为显式受控关闭；root 目标更名被拒绝；更名受唯一性与 row_version 条件约束，并发 1 成功 1 `CONFLICT`；审计记录新旧用户名、操作者与稳定用户 ID。
- **电话**：`NormalizePhone` 支持受支持国家/地区区号（默认 CN，可配置 ISO 3166-1 alpha-2）与 `+`/`00` 国际前缀，统一保存 E.164；`phone_verified_at_ms` 本步从不写入，`PhoneVerified` 恒为 false，电话**不参与登录、找回或任何身份验证**；改电话时同事务清空该验证列，审计只记录 `[REDACTED]`。
- **审计与隔离**：简介允许换行/1000 码点，但审计只记录 `[REDACTED]` 长度摘要，避免控制字符导致误映射为存储故障；审计事件无效映射 INTERNAL_ERROR 而非 DB_UNAVAILABLE。全局资料只写 `users` 表，不写 `app_memberships.profile_json`；应用专属昵称由 `internal/app` 维护，两者互不覆盖。
- **已知限制**：`Policy` 目前通过 `profile.Options` 注入（尚未新增根配置 YAML/环境变量节，启动装配留给后续）；更名**不递增 `security_version`**（决策：会话绑定稳定用户 ID，更名不是凭据变更，旧会话继续有效属预期；如未来要求更名强制下线需单独策略）；HTTP 路由、个人资料页面、电话验证流程与 `cmd/login-server` 装配未实现。

## 受控邀请、接受邀请与注册审核（步骤 34）

新增内部入驻域 `internal/onboarding` 与 SQLite 仓储 `internal/onboarding/sqlite`，迁移 0014 落地 `invitations`、`invitation_roles`、`invitation_acceptances`、`registration_reviews` 四张表；本步**不暴露 HTTP 路由、不接 `cmd/login-server` 装配、不签发会话**，验收走内部 Go API 与真实 `internal/credential`/`internal/audit`/`internal/delegation` 依赖。

- **邀请模型**：显式记录发起者、目标邮箱（规范化值）或目标用户（二选一）、适用应用、允许的默认角色、到期与使用次数；创建/取消/查询/分页列表均要求可信 `Caller`，用户身份只能读取/取消自己发起的邀请。邀请邮件通过 `internal/mailer` 可靠投递（一次性高熵令牌 + 接受入口），通知状态（pending/sent/failed + 稳定错误码）可查询；发送失败不回滚邀请。
- **身份绑定与接受校验**：邮箱邀请要求接受账户拥有同一**已验证**邮箱，用户邀请要求接受者就是目标用户；先做无事务身份预检再消费令牌，错误身份不会白耗令牌。知道邀请 ID 不能认领已有用户。接受时按邀请者**当前**状态与权限重新校验：在同一审计事务内对“目标用户在该范围**既有有效权限** ∪ 邀请角色权限”统一调用 `delegation.Guard.CheckAssignment`，零角色邀请同样经过 Guard，因此不能借重新启用停用成员恢复其保留角色权限；邀请者失去权限、应用停用、邀请取消/过期/次数用尽都会拒绝。使用次数条件原子扣减（当前仅单次邀请，首次接受即置 accepted），`(invitation_id,user_id)` 主键拒绝重复接受；角色存在/启用/作用域在事务内校验，**已持有同一角色按幂等成功**（已有用户受邀不会因已持角色失败）；接受可创建新账户（字段白名单 + Argon2id + 目标邮箱绑定）或给已有账户加入应用成员并分配角色，失败整体回滚。
- **注册审核**：`ListPendingReviews`/`GetReview`/`ApproveRegistration`/`RejectRegistration` 只处理 `users.status='pending'`；批准在同一审计事务内把账户改为 active，可选加入应用成员/分配角色，并对“目标既有权限 ∪ 新角色权限”调用 `delegation.Guard.CheckAssignment`（审核者为操作者）；拒绝改为 disabled 并记录理由；并发审批以条件状态更新保证只有一个成功，其余返回 `CONFLICT`。审核需要管理强认证：`ManagementAuthorizer` 未接线时普通用户一律拒绝（`REAUTH_REQUIRED`），只有受信 system/local_admin 通道可按既有边界执行；实现 `ScopedManagementAuthorizer` 可按应用/角色限定范围，未实现该扩展时普通用户不能通过审核授予 system 作用域角色；申请人不能批准自己。结果通知经 `internal/mailer` 发送并记录可查询的通知状态。
- **通知与审计**：通知状态 `pending/sent/failed` 中 **sent 表示已成功交给可靠投递服务（入队成功）**，不代表外部邮件已送达；通知只发送到**已验证邮箱**（未验证地址不作为收件目标），发送失败不回滚邀请/审核主事务。审计动作区分 `invitation.create`/`invitation.cancel`/`invitation.accept`（含目标用户 ID）/`registration.approve`/`registration.reject`，失败审计记录稳定错误码，令牌与邮件正文不入库/日志。
- **已知限制**：邀请令牌是一次性凭证，当前一次邀请只允许一次接受（多次使用需按接收者分别签发，留后续步骤；服务对 `MaxUses>1` 明确拒绝）；令牌在**授权事务之前**消费，若接受在事务内因邀请者撤权、应用停用、邀请取消/过期等失败，令牌不会恢复，邀请者需重新签发（数据库侧账户/成员/角色/接受记录会整体回滚，不会部分修改；先消费可防止重放与暴力尝试）；过期邀请不会主动落库为 expired（接受时按时间拒绝，清理/状态更新任务未实现）；邀请创建授权由宿主注入 `InviteAuthorizer`（未接线时普通用户 fail-closed）；邀请/审核的 HTTP 路由、启动装配、过期记录清理任务、邀请邮件重发、审核通知重发与多级审批引擎尚未实现。

## 测试用本地邮件服务器（额外步骤 extra01）

`internal/testmail` 是**仅供测试**的本地 SMTP 接收服务器，`tools/testmaild` 是只负责装配与运行它的独立工具。它把收到的邮件保存在内存中供测试断言，**不投递、不中继、不连接任何外部邮件服务**，默认只监听 `127.0.0.1` 的随机端口；两个包都不会被 `cmd/login-server` 装配，生产邮件实现必须另行编写。本包不是产品能力，也不替代步骤 32 已实现的通用邮件投递基础设施与步骤 39 的通知业务逻辑。

支持的最小会话：EHLO/HELO、MAIL FROM、RCPT TO、DATA（含点填充还原）、RSET、NOOP、QUIT，以及可选的 AUTH PLAIN/LOGIN（显式测试凭据）与 STARTTLS（测试自签证书，默认关闭）。**安全提示**：默认不启用 AUTH；`RequireAuth` 在未加密连接上会让测试凭据以明文传输，建议只与 STARTTLS 搭配，且仅用于回环测试，不要复用任何真实密码。

常用限制：`ReadTimeout`（单次读取，默认 30s）、`SessionTimeout`（单连接总时长，默认 5 分钟）、`MaxMessageBytes`（默认 256 KiB，超出返回 552）、`MaxRecipients`（默认 50，超出返回 452）、`MaxConnections`（默认 32，超出直接 421）、`MaxMessages`（默认 500，满时返回 452，`Clear`/`Take` 释放容量）。格式错误返回对应 SMTP 错误码且服务不崩溃；读取超时或会话超时返回 421 并关闭连接。内存占用上限是 `MaxMessageBytes × MaxMessages`（默认约 128 MiB），`MaxConnections` 也会叠加并发缓冲；高负载或长时间测试请调低这些参数。

启动工具（默认回环随机端口，打印实际地址；`-auth` 可重复）：

```bat
go run .\tools\testmaild
go run .\tools\testmaild -addr 127.0.0.1:0 -auth tester:test-pass -require-auth
go run .\tools\testmaild -addr 127.0.0.1:0 -starttls
```

常用参数还有 `-max-message-bytes`、`-max-recipients`、`-max-connections`、`-max-messages`、`-read-timeout`、`-session-timeout`、`-print-body`；只有显式加 `-allow-non-loopback` 才允许监听非回环地址（`-addr :0` 这类空主机名不会被当作回环，需显式写 `127.0.0.1:0` 或加该开关）。工具在收到消息时打印信封、主题、大小与认证用户摘要（不回显密码），按 Ctrl+C 或 SIGTERM 优雅关闭并释放端口。

在 Go 测试中直接复用（后续邮件发送模块的测试把 SMTP 地址指向 `srv.Addr()`，用 `Wait`/`Messages` 断言）：

```go
srv, err := testmail.New(testmail.Options{
    Auth: &testmail.AuthOptions{Users: map[string]string{"tester": "test-pass"}},
})
if err != nil { return err }
if err := srv.Start(); err != nil { return err }
defer srv.Close()

// 发送代码会把邮件投递到 srv.Addr()；随后等待并断言内容。
msgs, err := srv.Wait(ctx, testmail.Query{To: "user@example.test"})
// 信封地址在 msgs[0].EnvelopeFrom/EnvelopeTo；原始字节在 Data，正文在 Body()；
// 解析后的头部通过 Headers 与 Header()/HeaderValues() 读取（不提供独立的
// From/To 头部字段，避免与信封地址混淆），Subject/Date 为常用字段的解析结果。
srv.Clear() // 或 Take 按条件取出
```

需要 STARTTLS 时用 `testmail.GenerateTestCertificate()` 生成自签证书注入 `Options.TLS`，测试客户端需显式信任该证书或跳过校验；AUTH 测试凭据只写在这里，不来自环境变量或配置文件。该包的"无外发"与"未被生产入口导入"有源码级测试守护（`internal/testmail/isolation_test.go`）。

运行本步测试（Windows amd64 实测）：

```bat
go test -count=1 -p 1 .\internal\testmail\
go test -count=1 -p 1 .\tools\testmaild\
```

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
| internal/account/ | 普通用户创建/查询/分页、用户名规范化与资料白名单，及账户状态与删除流程（内部包） | 是 |
| internal/app/ | 应用登记/资料/启停、作用范围一致性，与应用成员管理及应用内资料隔离（内部包） | 是 |
| internal/permission/ | 系统内置/系统自定义/应用独有权限目录与启停（内部包） | 是 |
| internal/role/ | 系统/应用角色、角色权限组合与角色到用户/用户组的分配（内部包） | 是 |
| internal/authz/ | 有效权限计算、数据范围交集、权限来源与资源检查（内部包） | 是 |
| internal/delegation/ | 可使用权限与可转授权限分离、委派资格与统一赋权检查（内部包） | 是 |
| internal/preset/ | 版本化预设角色/用户组/权限目录的幂等初始化、差异预览/再次授权恢复与默认保护（内部包） | 是 |
| internal/bootstrap/ | 本地受控首次初始化、唯一 root 受限待配置状态、一次性配置凭证、`ready` 条件转换与 root 保护规则（内部包） | 是 |
| internal/authn/ | 正式密码 Argon2id 哈希/验证与参数升级、密码策略、用户名/已验证邮箱登录、失败限制与认证结果（内部包） | 是 |
| internal/session/ | 服务端会话签发/校验/续期/撤销、普通与受限会话、空闲/绝对到期、登录轮换、Cookie 与 CSRF 绑定（内部包） | 是 |
| internal/recovery/ | 恢复代码生成/按组作废/原子消费、短时受限恢复会话与强制重新绑定（内部包） | 是 |
| internal/manualrecovery/ | 人工核验恢复申请、独立审批与一次性受控执行（默认关闭，内部包） | 是 |
| internal/testmail/ | 仅供测试的本地 SMTP 接收服务器（内存保存、查询/取出/清空、限制、可选 AUTH/STARTTLS）；不得装配进生产路径 | 是 |
| internal/tlscert/ | 服务器 TLS 证书加载/链校验、SNI 选择、安全重载与到期状态；可选客户端证书信任与身份映射（内部包） | 是 |
| migrations/ | 内嵌的版本化数据库迁移 SQL（隔离核心表、一次性凭证表、审计事件表、后台任务表、定时计划/尝试历史表、权限委派资格表、预设初始化版本表、root 初始化状态表、密码凭证/已验证邮箱表与会话表） | 是 |
| examples/ | 可运行的最小接入示例（配置加载示例、定时计划示例） | 是 |
| docs/requirements/ | 功能清单和错误码手册 | 可以 |
| docs/database/ | 数据库基线说明、表清单与检查记录 | 可以 |
| docs/acceptance/ | 基础设施阶段（步骤 01～17）验收记录与下一阶段前置条件 | 可以 |
| database/login.db | 已创建的空业务 SQLite 数据库 | 否，运行数据应本地保存 |
| database/0001_design_baseline.sql | 建库结构，需在开发阶段审查 | 可以 |
| tools/ | 可选的 Python 建库/只读检查工具，以及只用于测试的本地邮件服务器命令行入口 `tools/testmaild` | 可以 |
| .gitignore | AI 文件、数据库与秘密排除规则 | 可以 |
| SHA256SUMS.txt | 启动包文件完整性清单 | 可留作交付记录 |

## 开始工作

1. 解压到新的目录，不要直接覆盖现有项目。
2. 使用 IDE 打开目录，让 AI 先读取 AGENTS.md 和 MEMORY.md。
3. 步骤 01～30 已完成；继续时按 .ai/ 中的顺序处理步骤 31，每次只把一个步骤的完整提示词交给 AI。
4. 每步结束检查修改和实际测试结果，由你自行提交代码。AI 不提交项目成果、不执行任何 git push。
5. 第一部分（步骤 01～17，基础设施与网络边界）完成后，可用 MEMORY.md 与验收记录复核阶段状态，再继续第二部分。

`database/login.db` 是启动包提供的设计基线，仅用于步骤 01/06/07 审查；Go 正式迁移已在 SQLite 存储层实现，但尚未对 `database/login.db` 执行，测试与后续初始化应使用独立数据库文件。该库没有预置 root 初始密码；root 管理由步骤 28 的本地受控初始化流程在目标数据库上创建（一次性本机短期配置凭证，不设默认密码），正式密码由步骤 29 的密码服务在凭证兑换后设置。

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

## 账户入口页面（步骤 63）

在步骤 62 页面框架（`ui.v1`）之上新增内置账户入口页，经宿主注入的 `UIPageAuthBackend` 适配器调用真实后端服务（模块内提供 `internal/uiauthadapter` 示例装配；生产 host 按同一公开契约实现）。页面不解析 Cookie 身份、不缓存权限，每次请求重新校验。

- **路由/页面**：`auth.login`（GET/POST `/login`，密码登录；Passkey 仅入口，流程属步骤 64）、`auth.register`（GET/POST `/register`，按开关/邮箱策略展示，保留字段整单拒绝，注册不自动登录）、`auth.registration_status`（GET `/register/status`，仅通用说明，不提供匿名实时状态/存在性查询）、`auth.invitation_accept`（GET/POST `/invitation/accept`，新用户或已登录用户接受，无未消费预览时不伪造应用/角色）、`auth.email_verify`（GET 不消费、POST 才消费；成功/重复/过期统一处理）、`auth.email_verify_resend`（POST `/email/verify/resend`，复用注册服务真实冷却）、`auth.logout`（仅 POST，服务端撤销后才清 Cookie）、`auth.landing`（GET `/home`，登录后临时落地页）。全部为命名路由，BasePath 由框架统一处理。
- **登录安全语义**：按真实 `authn` 结果分支；只有 `OutcomeComplete && !Restricted && 无剩余步骤` 才签发正常会话并跳转；需要补充验证/强制改密/受限结果**不是登录成功**，页面显示受限状态、不进入业务，必要时仅下发受限会话供步骤 64 继续；公开错误不枚举账户（用户名/密码/禁用统一文案），限流显示等待提示。`return` 仅允许站内相对路径/命名路由白名单，非法值回默认落地页，防开放重定向。
- **匿名表单 CSRF**：新增 `internal/pagecsrf` 签名双提交方案（`v1:<kid>:<purpose>:<unix>:<nonce>:<sig>`，HMAC-SHA256 绑定用途、短时效默认 15 分钟、Cookie HttpOnly/Secure/SameSite=Lax、隐藏字段与 Cookie 恒时相等），transport `CSRFPolicy` 新增 `PublicFormPaths`/`PublicTokenValidator`：命中公开表单路径时即使无会话 Cookie 也强制 Origin/Referer 精确匹配 + 单一表单字段 + 匿名令牌校验；未列路径与会话 CSRF 语义不变，不全局放宽。令牌只出现在隐藏字段与 Cookie，不放 URL、不写日志；匿名令牌不阻止同一令牌在有效期内重复使用（防重放依赖服务端一次性凭证/条件状态迁移）。
- **会话/一次性秘密**：会话 Cookie 由真实 `session` 服务生成（Secure/HttpOnly/Lax/Path）；邀请/邮箱验证令牌只在 GET query 与 POST 隐藏字段出现，正文/链接/日志不回显；HTML 统一 `Cache-Control: no-store`、`Referrer-Policy: no-referrer`（transport 已有），访问日志只记路径。
- **邀请与邮箱验证限制**：invitation 未提供未消费预览接口，GET 显示通用接受表单与说明，接受后展示服务端真实应用/角色；不匿名调用 `GetInvitation`。邮箱验证重发：已登录本人走真实 self Caller；匿名链接携带 uid/cid/token 时由系统组件复用后端发送冷却（传输层 IP 限流尚未接入，属**遗留**，页面如实提示冷却/失败，不宣称已防刷）。注册审核状态无本人实时查询，仅显示本次提交结果/通用说明，不猜测账户状态。
- **后端接口/错误**：页面只新增公开扩展契约（`UIPageAuthOptions`/`UIPageAuthBackend`/`UIPageHandler`/`UIPageOutcome`/`UIFormTokenProvider`/`UIPageContext.CSRFField`，均为 `ui.v1` 向后兼容新增），未改既有 API/会话语义、未新增错误码/迁移/第三方依赖/YAML 配置。默认落地页 `/home`；管理/个人资料等页面留后续步骤。
- **验证与限制**：真实 SQLite + 真实 authn/session/registration/onboarding/credential/audit 集成测试（本地捕获邮件，不真实外发）覆盖登录成功/失败/受限分支、注册关闭/无邮箱/保留字段、邮箱验证 GET 不消费与重复拒绝、邀请接受与重复拒绝、匿名 CSRF 缺失/跨源/用途错配/Cookie 不符、落地与 return 白名单、退出；真实浏览器视口/读屏/真机、反向代理部署未实测，以服务端渲染断言 + CSS 断点/人工清单代替，不宣称已通过。

### 步骤 63 审计修复补充（2026-11-18）

- **重发验证邮件（CSRF 用途）**：邮箱验证页的“验证”和“重发”两个表单共用同一页面用途的匿名 CSRF 令牌（`/email/verify` 与 `/email/verify/resend` 均绑定 `auth.email_verify`），GET 签发的单一隐藏字段可同时用于两个 POST，不再出现重发恒 403；模块提供 `UIPageAuthPublicFormPaths` 供宿主接线。
- **匿名重发绑定校验与统一响应**：匿名声明确认重发前，在 `internal/credential` 新增只读 `Peek`（不消费、不记失败尝试）校验 `uid+cid+token` 与当前 pending 验证票据及一次性凭证绑定（票据存在/未过期/凭证 ID 与 token 恒时匹配）；绑定失败、票据不存在、用户不存在、冷却中、发送失败**对外一律呈现同一“已受理”语义**，差异只写入受限运行日志，避免账户/邮箱状态探测与借用系统身份滥发。已登录用户仍按本人 Caller 重发；后端每用户冷却继续生效，传输层 IP 限流缺失仍登记遗留。
- **重定向收紧**：`safeRelativePath` 额外拒绝 `.`/`..` 点段，避免点段规范化越过 UI BasePath/路由预期。
- 新增真实后端用例：GET→重发成功（同页 CSRF 令牌）→冷却不重发→伪造 token/不存在用户/已消费票据均统一受理且不发送；`internal/credential` 新增只读校验不影响既有消费语义。
