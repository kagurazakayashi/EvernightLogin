# login

login 提供可嵌入 Go 程序的用户与权限组件，并计划提供独立的 OAuth 2.0 / OpenID Connect 身份服务。当前只是最小可编译骨架，不是可运行的用户系统。

## 项目状态（步骤 31）

- 模块路径：`github.com/kagurazakayashi/EvernightLogin`，根包名 `login`；路径来自现有远端，首次发布后不再变更。
- 独立进程入口：`cmd/login-server`。当前只提供 `--version` 和 `--help`；不带参数运行会明确失败并返回非零，不假装服务已启动。
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
- 尚未实现：SQLite、`internal/secrets`、`internal/credential`、`internal/audit`、`internal/task` 与 `internal/transport` 尚未接入 `login-server`；`cmd/login-server` 也尚未装配 `NewServer`（监听组件已可由 Go API 使用并交给 `Instance` 管理）；客户端信任 CA/身份映射的热重载与 OCSP/CRL 在线撤销、完整反向代理部署示例、账户创建/查询/状态变更/删除、应用登记/资料/启停/应用成员管理、用户组与组成员、权限目录、角色与角色分配的 HTTP 与服务启动接入（`internal/account`/`internal/app`/`internal/group`/`internal/permission`/`internal/role`/`internal/authz`/`internal/delegation` 已提供基础能力）、有效权限推导与授权执行的 HTTP/令牌接入（`internal/authz` 已提供基础引擎）、首次初始化入口的 CLI/启动装配（`internal/bootstrap` 已提供受信 Go API，尚无 `cmd/loginctl` 本地命令）、密码登录/退出/会话校验的 HTTP 路由接入与启动装配（认证与受限/普通会话能力已由 `internal/authn`/`internal/session` 提供受信 Go API，步骤 30/31 未暴露 HTTP 路由；设备列表与管理员强制下线同样只有 Go API，管理强认证与数据范围裁剪尚未接入）、OAuth/OIDC 客户端凭证与回调、Web 页面、应用删除策略、审计查询/导出/报告/清理、备份流程仍未实现。委派资格签发/撤回管理 API、审批引擎、预设目录的 HTTP/CLI 管理入口（`internal/preset` 已提供受信通道初始化/恢复能力）与数据范围写入口也未实现。HTTP Handler 只公开健康与 OpenAPI，不提供业务或管理端点；防护层不提供绕过鉴权或 CSRF 的生产开关，任务执行器与调度器不提供网络端点，服务层授权尚未接入，也不承诺外部副作用恰好执行一次。密码哈希与密码验证已由 `internal/authn` 使用 Argon2id 实现；会话签发/校验/续期/撤销与受限会话语义已由 `internal/session` 实现（未暴露 HTTP 路由），MFA/管理强认证与完整管理会话尚未实现。root 的受限配置凭证兑换后可设置正式密码，但 MFA/管理强认证完成前状态保持 `setup_verified`、不会进入 `ready`，也不会签发管理员会话（`ready` 条件转换已由 `internal/bootstrap` 的 `MarkReady` 提供）。
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
- **尚未实现/未验证**：初始化本地 CLI 命令与启动装配（`cmd/loginctl` 未建；本步只提供内部 Go API）、正式密码哈希/密码验证/强认证与 `ready` 状态转换（步骤 29）、兑换后受限配置会话的持久化绑定（当前 `SetupGrant` 仅是本进程内的服务端记录返回值，不是会话/令牌）、完整 root 应急重置（CLI 本地重置密码/MFA 留后续步骤）、初始化流程的 HTTP 管理与页面、多进程/多实例长期并发压力（已有“同一数据库两个独立 Store/Service 实例并发初始化仅 1 成功”回归用例，未做多进程/长稳/故障切换实测）、非 Windows 运行。


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
