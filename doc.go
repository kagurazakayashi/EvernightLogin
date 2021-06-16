// Package login 提供可嵌入业务程序的用户与身份权限组件。
//
// 当前处于项目初始化阶段：本包提供模块版本与构建信息、类型化配置加载器、
// 核心实例生命周期契约（New/Start/Close、后台组件接口、资源所有权与状态
// 重入规则）、统一错误码注册表、AppError、请求编号校验与结构化运行日志基础。
// 数据库迁移机制、隔离核心表结构与 SQLite 存储基础已在 internal/storage 与
// migrations/ 实现（连接所有权、WAL、外键、忙等待、事务、错误映射与有界重试），
// 但尚未接入 Instance/服务启动。
//
// internal/secrets 已实现可还原秘密（如 TOTP 种子）的 AES-256-GCM 认证加密、
// 主密钥环加载、Windows ACL/Unix 权限检查、密钥轮换、可中断重加密与旧密钥
// 退役保护；它尚未接入 Instance、配置加载或服务启动，密码哈希仍待密码步骤实现，
// 本模块不把密码按可解密形式保存。
//
// internal/credential 已实现一次性凭证服务与 SQLite 生产仓储：用途/目标/应用绑定、
// 高熵摘要与低熵受密钥保护的验证码、签发/验证并原子消费/取消/替换/过期清理，
// 以及可注入时钟；迁移 0002 已落地 one_time_credentials 表。它同样尚未接入
// Instance、配置加载、HTTP 或通知投递。
//
// internal/audit 已实现安全审计事件模型与 SQLite 持久化：可信身份四类区分、
// 字段白名单与脱敏差异、失败审计独立保存、关键变更同事务写入、审计故障拒绝
// 关键变更并告警；迁移 0003 已落地 audit_events 表。它尚未接入 Instance、HTTP
// 或业务模块，也不提供审计查询/导出后台；普通访问日志仍与安全审计分开。
//
// internal/task 已实现可靠单实例后台任务执行器与 SQLite 状态持久化：完整任务
// 状态机、可信发起/执行/取消身份、并发与墙钟上限、取消上下文与子进程清理约定、
// 重启恢复和全状态审计；迁移 0004 已落地 jobs 表。步骤 12 在同一状态机上增加
// 定时计划（daily/weekly/monthly/custom，IANA 时区与夏令时规则、停机错过策略与
// 有界补跑、触发去重）、每次尝试历史、有界指数退避重试与显式不可重试错误、
// 运行前权限复验默认拒绝，以及暂停/恢复/删除语义；迁移 0005 落地
// job_attempts/schedules/schedule_firings 并扩展 jobs 的重试列。它仍未接入
// Instance、服务层权限检查、HTTP 或通知/报告/备份流程，也不承诺外部副作用恰好
// 执行一次。
//
// HTTP 传输层已实现标准 net/http Handler（login.NewHTTPHandler）：固定路径前缀
// 与严格路由、请求体类型/大小边界、参数规范化、统一业务错误 JSON 与请求编号、
// panic 恢复、上下文取消、最小健康端点、可信身份建立与上下文传递接口、由错误码
// 注册表生成的机器可读 OpenAPI，以及 W3C Extended 脱敏访问日志与写入失败告警。
// 步骤 14 增加 HTTP 防护层：多维有界固定窗口限流（可信客户端地址、已认证用户、
// 应用、接口与昂贵请求预算，容量上限与过期清理）、可信代理转发头解析、请求期限/
// 响应超时与并发上限、精确来源 CORS、安全响应头、Cookie 会话 CSRF 契约与 Cookie
// 安全属性策略。生产路由只有健康检查与 OpenAPI 文档；未鉴权的管理功能、调试路由
// 和测试路由都不注册，/oauth2 前缀保留给未来标准协议响应。
//
// 独立监听组件 login.NewServer 复用同一 Handler 与 Instance 生命周期：支持多个
// IPv4/IPv6 地址与端口、任一地址失败时整体回滚、关停释放端口；默认只允许回环
// 监听，非回环明文必须显式声明 TLS 终止代理模式并配置可信代理与 https 公开地址。
// 请求先经代理信任边界校验 Host，仅当直连对端命中显式可信代理时才解析
// Forwarded/X-Forwarded-* 并做确定性链解析，结果放入上下文供限流与访问日志使用；
// 外部公开地址、未来 OIDC Issuer 与 WebAuthn RP ID 都必须来自独立显式配置，
// 不能由请求 Host 动态推导。它尚未接入 cmd/login-server，也没有业务接口。
//
// HTTPS 单向认证由 internal/tlscert 与 login.Server 提供：配置本地 TLS 证书后
// 监听地址提供 HTTPS，非回环监听在 TLS 保护下允许。支持 PEM 证书链 + 私钥、
// 可选附加 CA/中间证书与 PKCS#12/PFX 导入，加载前校验私钥匹配、证书链组织、
// 服务器认证用途与有效期；按证书 DNS SAN（含单级通配符）选择 SNI，未知 SNI
// 握手失败，无 SNI 使用配置顺序第一张证书；最低 TLS 1.2，不自定义密码套件。
// Server.ReloadTLS 在完整校验后原子替换证书，失败保留旧证书并告警；
// Server.TLSStatus 提供到期状态，但本步不发送通知、不自动续期。
//
// 可选的客户端证书双向认证（mTLS，步骤 17）也在 internal/tlscert 与 login.Server
// 实现：客户端证书认证模式为 disabled（默认）/required/optional；启用后客户端
// 证书必须链到与服务器证书链完全分开的显式客户端信任 CA、处于有效期且具备客户端
// 认证用途，叶证书 DNS SAN 还必须命中显式“DNS 名称 -> 可信服务身份”映射。仅有
// 受信任 CA 签发不足以获准接入，映射也不授予 root 或业务权限；可选模式允许匿名
// 连接，但出示无效证书会直接握手失败，不会降级为匿名。映射后的服务身份以只读
// 方式通过 login.ClientServiceIdentityFromContext 提供给 Handler。客户端信任配置
// 在启动时加载，不随 Server.ReloadTLS 变化：撤销身份、轮换信任 CA 或改变策略必须
// 重启进程；第一版不实现 OCSP/CRL 在线撤销，也不承诺已建立连接在运行期重新
// 校验。
//
// 账户领域基础由 internal/account 与 internal/account/sqlite 提供：普通用户创建、
// 按稳定 ID 查询与有限分页检索；用户 ID 由服务生成且不可变，用户名显示值与
// NFKC+大小写折叠后的规范化值分开保存并受数据库唯一约束保护；资料只接受白名单
// 字段，不接受 is_root/status/security_version/已验证标记；创建与敏感查询写安全
// 审计，审计失败时拒绝操作；实际授权模块未就绪，只提供显式本地初始化授权器，
// 未接入 HTTP 或服务启动。步骤 19 增加全局账户状态机（启用/禁用/待删除/完成
// 删除）、row_version 乐观并发与 security_version 失效契约、root 保护、删除影响
// 预览与关联数据明确清理策略；会话/令牌模块尚未实现，只提供安全版本递增与可靠
// 审计事件作为后续失效依据，不提供假会话接口。
//
// 应用领域基础由 internal/app 与 internal/app/sqlite 提供：应用登记、按应用 ID
// 读取、有限分页、展示资料更新与启停；应用 ID 不可变，创建时在同一事务写入唯一
// 应用 scope（scope ID 与应用 ID 相同），读取时校验 scope 一致性；client_type 只在
// 创建时确定，资料更新白名单不包含 ID/client_type/status；负责人变更不自动转移
// 管理权限；应用管理员只能操作显式分配的应用；停用写可靠审计事件，依赖方必须
// 检查状态。本步不实现应用删除、OAuth 凭证/回调或 Web 页面。
//
// 步骤 21 在 internal/app 增加应用成员管理与应用内资料隔离：成员关系与应用专属
// 资料以 (应用 ID, 用户 ID) 为范围保存，成员状态只影响指定应用，不修改全局账户或
// 其他应用成员；加入既有账户只接受稳定用户 ID，并要求可信 Authorizer 按被操作
// 应用判权，仅知道用户名/邮箱不能认领账户；应用内启用成员与更新资料要求应用及
// 目标账户处于 active，停用/移除只影响该应用的成员行。成员加入/资料更新/启停与
// 成功审计同事务提交，移除写可靠审计事件；未来会话/令牌模块必须消费成员移除/
// 停用与应用停用事件并在每次授权时读取当前成员状态（本包没有会话/令牌实现，不
// 声称撤销全链路已完成）。成员关系本身不授予任何业务权限，角色/权限与用户组仍
// 待后续步骤。
//
// 用户组领域基础由 internal/group 与 internal/group/sqlite 提供：系统范围与应用
// 范围用户组的创建/读取/分页/资料更新/删除，以及组成员的批量加入/移除/分页；
// 组 ID 与 group_key 稳定不可变，scope 不能转移；应用组只允许该应用有效成员，
// 系统组管理需系统资格，应用组管理需应用管理员资格；批量成员操作上限 12 人且
// 全有或全无，成员变更加审计事件（角色模块接入后消费以失效权限）。删除组只
// 级联成员/组角色关联，不删除用户与审计历史。不实现角色分配、嵌套组或 HTTP。
//
// 权限目录基础由 internal/permission 与 internal/permission/sqlite 提供：系统内置、
// 系统自定义与应用独有权限的登记/读取/分页/资料更新/启停/受引用保护删除；权限以
// scope+机器标识唯一定位，同名跨应用隔离；内置权限标识与含义不可改不可删、可按
// 规则启停，root_only 敏感权限仅本地初始化操作者启停；自定义权限名称/说明/限制可改、
// 机器标识不可变；被 role_permissions 引用时拒绝删除；停用是拒绝而非跳过检查。
// 本步不实现角色分配、授权执行或权限目录 HTTP。
//
// 步骤 24 增加角色领域 internal/role 与 internal/role/sqlite：系统/应用角色的创建、
// 读取、分页、资料更新、启停与受引用保护的删除，角色权限组合，以及角色到全局
// 用户和同一作用范围用户组的分配。角色机器标识稳定且不能使用 root 语义；角色只能
// 组合同 scope、启用且非 root_only 的权限；应用角色只能分配给该应用有效成员或
// 同应用用户组；root 账户不能作为普通角色分配目标，含 root 账户的用户组也拒绝
// 分配普通角色；步骤 28 进一步在组成员资格层显式排除 root，封堵“组先配角色、再
// 把 root 拉进组”的间接路径。重复组合/分配幂等，并发由
// 唯一键与条件更新保证单一终态，关键变更与成功审计同事务。角色存在或启用不代表
// 已获得权限：有效权限推导由步骤 25 的 internal/authz 提供基础引擎（尚未接入 HTTP/
// 令牌联合校验），可转授权限限制由步骤 26 的 internal/delegation 提供（角色编辑、
// 赋角色、组增员等写入路径已统一收口，不实现 HTTP/审批引擎）。
//
// 步骤 25 增加有效权限计算引擎 internal/authz 与 internal/authz/sqlite：在同一个
// 数据库事务快照内读取账户、应用成员、直接用户角色、用户组角色、角色与权限启停，
// 按禁用优先规则计算系统或应用 scope 的有效权限，并返回来源与数据范围。直接与组
// 来源合并但数据范围取交集；all/any 默认 all，未知权限拒绝；权限来源说明包含角色、
// 用户组、排除原因与 data_scope 契约。业务资源归属不能从权限名推断，资源检查必须
// 显式传入权限键与资源标识，undefined/none 数据范围默认拒绝。候选来源超过单次上限
// 时 Check/资源检查/有效权限查询一律 fail-closed 并标记来源截断，不会用部分来源放行。
// 查询他人权限必须经 Authorizer 授权；不缓存结果，每次实时推导。本步不实现 OAuth/
// OIDC Token 联合校验、数据范围写入口、业务资源所有权表或 HTTP 接入。
//
// 步骤 26 增加可转授权限与委派限制 internal/delegation 与 internal/delegation/sqlite：
// 把“可使用权限”与“可转授权限”分开。委派资格由受限本地初始化/系统操作者显式签发并
// 写入迁移 0006 的 permission_delegations 表，记录作用范围、权限、数据范围上限、
// 目标白名单、是否允许自我/本组转授、有效期与撤回状态；持有权限本身不再隐含转授
// 资格。角色组合权限、角色分配、启用角色、向已配角色的用户组增员、应用成员加入/
// 重新启用、启用权限、启用应用等所有改变有效权限的写入路径统一经 Guard 在同一审计
// 事务内检查；普通管理者只能转授自己当前实际持有且具备未过期未撤回资格的权限，数据
// 范围必须收缩，默认禁止自我与自身所在用户组。间接提权路径（启用含权角色或权限、
// 把权限组合进已分配给他人/自身的角色、启用应用）除资格外还按“实际受影响目标集合”
// 复核 allow_self 与目标白名单；启用应用无法安全校验时仅受信通道可通过。检查失败与
// 写入同事务回滚并返回可诊断错误码。
//
// 步骤 27 增加预设目录初始化与恢复默认 internal/preset 与 internal/preset/sqlite：
// 按需求 11.1/11.3/11.5 提供版本化、机器可读的预设目录（系统管理员、用户管理员、
// 客服、审计员、普通用户五个系统角色及默认用户组；应用管理员/应用普通用户按应用
// 创建模板生成，各应用独立）。每条权限都有稳定标识、中文名称、能做什么、范围与不能
// 做什么；初始化只登记权限、角色与空用户组，不创建账户、不做角色分配，也没有可分配
// 的 root 角色。初始化幂等且升级不覆盖用户已调整的角色组合；恢复默认必须先经
// Preview 展示逐角色差异、再用服务端签发且绑定操作者/目录版本/差异摘要、短时有效
// 且单次使用的确认令牌完成再次授权，客户端布尔值不能冒充。整次恢复在一个安全审计
// 事务内完成，角色权限新增调用步骤 26 的 delegation.Guard.CheckPermissionAccess、
// 恢复停用预设权限调用 CheckPermissionActivation，受信通道按既有语义放行且未来非
// 受信管理者会被 Guard 拦在可转授范围之外；失败整体回滚只留失败审计。恢复只作用于
// 明确选择的目录/角色，保留自定义角色、自定义权限与组成员；未实现业务操作的权限在
// 目录中标记 Implemented=false，只登记说明、不返回虚假成功。预览记录各作用范围目录
// 状态的稳定指纹，恢复在写入事务内重算并比对（防 TOCTOU，预览后并发修改不会被旧计划
// 覆盖）；事务前的令牌缺失/伪造/过期/非本人/摘要过期同样写失败审计。按
// internal/permission 的 root_only 启停规则，仅受限本地受控操作者（local_admin）可在
// 恢复中重新启用 root_only 权限，system 与其他通道跳过并在差异与审计中明确记录；
// 整体恢复跳过已停用应用并报告。按需求 11.5，五个系统角色默认权限均包含仅限本人的 self.*；两处已
// 声明偏差：应用模板角色不默认组合系统权限、DefaultGroupKey 只声明配套默认组而不写
// group_roles 赋权关联（理由见 README 步骤 27 小节）。
//
// 步骤 28 增加本地受控首次初始化 internal/bootstrap 与 internal/bootstrap/sqlite：
// 唯一 root 只由本机受信 local_admin 通道创建，不设默认密码、不保存密码/哈希、不签发
// 会话或令牌。root 创建后处于受限待配置状态（pending_setup），只持有一条一次性、本机、
// 短期的配置凭证（复用 internal/credential，用途 root.setup、目标绑定新 root 用户 ID、
// 1 分钟～1 小时默认 15 分钟、数据库只存摘要）；兑换凭证只进入受限的 setup_verified
// 状态，正式密码与强认证由后续正式密码服务完成，ready 状态转换不在本步实现。root 行
// 与迁移 0008 的 root_initializations 单例记录在同一审计事务中条件插入（配合 0001 的
// ux_single_root 唯一索引），并发初始化最多一个成功，重复运行与已有 root 一律拒绝并写
// 失败审计；初始化完成后创建入口关闭，重启只读取数据库，不重新生成默认账户。Status
// 提供受限状态、凭证是否可用/过期与中文直白说明；ReissueSetupCredential 提供本地诊断
// 恢复入口，可重新签发短期凭证（不重建 root、ready 后关闭）。重签先撤销旧凭证再条件
// 更新初始化记录，第二步失败时新凭证被尽力撤销，可能短暂无可用凭证（fail-closed，再次
// 重签即可恢复，不留下未记录状态或伪造成功审计）；若数据库存在 root 但无初始化记录时
// 如实报告 existing_root 并拒绝自动接管。账户禁用/启用/请求删除/完成删除继续拒绝 root，
// 角色分配与含 root 组拒绝分配角色，组成员资格排除 root；应用成员加入/资料更新/重新启用同样排除 root（保持
// 既有 USER_DISABLED 语义）；这些普通管理路径的 root 拒绝均以独立事务补写 failure 审计
// （真实错误码与原因码，业务库不变），审计失败只把 AUDIT_WRITE_FAILED 加入错误链并告警。
// Status 与初始化/兑换/重签共用进程内互斥，并在提交窗口内重读初始化记录，避免误报
// existing_root；users.is_root 没有任何服务层写入口（不可降格）。初始化流程不提供 HTTP
// 入口，也不接入 cmd/login-server 或 CLI；同一数据库两个独立 Service 实例并发初始化仅
// 一个成功已有回归测试。
//
// 步骤 29 增加正式密码哈希、密码验证与认证结果 internal/authn 与
// internal/authn/sqlite：使用 golang.org/x/crypto 的 Argon2id 生成带算法版本、
// 有界可升级参数、随机盐与摘要的 PHC 编码哈希（新增迁移 0009 的
// password_credentials/password_history/user_emails），不保存明文或可逆密文；
// 登录成功发现旧参数弱于当前策略时在审计事务中条件升级。密码策略包含长度、
// 弱密码基线、连续/重复字符、不能包含用户名/昵称、可选近期历史（默认关闭）与
// must_change 首次改密标记，不强制没有依据的定期改密。登录支持用户名（NFKC +
// Unicode 大小写折叠 + NFC 规范化）与配置允许且 verified_at_ms 非空的邮箱；账户
// 不存在、密码错误、账户不可用、未设置密码、邮箱未验证的统一返回 AUTH_FAILED，
// 内部审计记录诊断原因，账户不存在时执行等价 Argon2 dummy 校验减小时序差异。
// 认证结果标明已完成方法、完成时间、仍需完成步骤、Restricted 与 SecurityVersion，
// 不返回会话或 Token：强认证按权限敏感度判定，root 与持有高敏感系统权限（用户/
// 应用/角色/权限/审计/策略/恢复/会话管理等，含任意 root_only 权限及组合这些权限
// 的自定义系统角色）的账户密码正确时固定为 pending_second_factor，并要求先绑定
// 强因素再完成第二因素；MFA 尚未实现，这些账户不得被当作完整登录。Argon2 派生与
// 校验受有界并发槽位与排队超时限制，超时 fail-closed。地址与操作维度使用
// internal/ratelimit 的失败预算（成功不计、失败才计数，新增只读 Peek），账户维度
// 提供有界渐进延迟与按“账户 + 来源前缀（IPv4 地址或 IPv6 /64）”的临时锁定，来源
// 标识扫描有阈值，锁定条目不参与容量淘汰，成功重置、锁定到期自动恢复，未知标识
// 同样计数，避免永久锁号、单来源锁死账户与账户存在性探测。root 正式密码由本地
// 管理员在一次性配置凭证兑换（setup_verified）后设置，密码写入、security_version
// 递增、审计与“是否进入 ready”的条件转换在同一审计事务完成；MarkReady 在 SQL 层
// 强制要求正式密码凭证存在，强认证未配置前保持 setup_verified，ready 后入口关闭。
// 密码/哈希/盐不写日志、错误或审计差异；认证成功路径审计不可用时拒绝返回结果。
//
// 步骤 30 增加服务端会话 internal/session 与 internal/session/sqlite：把步骤 29
// 的认证结果接入会话，形成普通用户密码登录与退出的完整 Go API 闭环（本步不暴露
// HTTP 路由，登录/退出/校验/续期/撤销由宿主或后续 HTTP 步骤调用，新增迁移 0010
// 的 sessions 表）。会话秘密由 crypto/rand 生成 256 位随机值并只返回一次，数据库
// 只保存 internal/secrets 派生的 HMAC-SHA256 验证摘要（会话秘密与 CSRF 令牌使用
// 不同摘要域），比较使用常量时间；秘密不进入日志、审计、错误或 URL。只有
// authn.AuthenticateResult 为 complete、非受限且无剩余步骤才签发普通会话，待第二
// 因素/待强制改密只能得到受限会话（recovery/initialization 受限原因已定义但本步
// 无签发入口），受限会话一律拒绝普通业务与管理访问；管理访问额外要求强认证时间
// 非空，MFA 未实现前没有任何写入通道，因此普通会话也不能访问管理接口。签发时重
// 读账户状态与 security_version 以及应用/成员状态，不一致按登录失败拒绝；每次
// 校验/续期都重读这些状态，账户禁用、改密递增安全版本、成员移除/停用与应用停用
// 会让既有会话立即失效。空闲到期与绝对到期双约束，续期只能延长空闲到期且不越过
// 绝对到期；登录成功如携带仍有效的旧会话，会在签发事务中撤销它并签发新 ID 与秘密
// （会话固定防护），退出与 RevokeAllForUser 写服务端撤销状态并立即生效，签发与撤销
// 的成功审计与数据库变更同事务提交，审计不可用时拒绝。浏览器 Cookie 默认
// __Host-login_session（与 internal/transport 的 CSRF 默认会话 Cookie 名一致）、
// Secure、HttpOnly、SameSite=Lax、Path=/，会话绑定 CSRF 令牌，ValidateCSRFToken
// 可直接作为既有 CSRF 中间件的校验器（来源/Origin 规则仍由该中间件负责）；嵌入式
// Go API 不强制 Cookie，会话秘密只从 Cookie 或 Authorization: Bearer 读取，绝不从
// URL/查询参数读取。会话不是 OAuth Access Token/ID Token/Refresh Token，OAuth 模块
// 后续另行实现。
//
// 步骤 31 在 internal/session 上继续扩展（不新建重复会话体系，新增迁移 0011 追加
// remember_me、展示用客户端描述列与活动会话索引）：用户可通过 ListSessions 分页查看
// 本人活动会话（标记当前会话，只返回展示字段，不含秘密/摘要/CSRF 令牌），通过
// RevokeSession/RevokeAllOwnSessions 指定退出或退出全部（目标不存在/失效/非本人时幂等
// 无操作，不泄露他人会话存在性），撤销立即生效。管理员通过 AdminRevoke 按授权范围强制
// 下线：必须出示普通会话并经 ScopeAuthorizer 走既有 internal/authz 的 sessions.revoke
// 权限与作用范围（NewAuthzAuthorizer 为生产适配器，应用范围追加受保护目标检查），应用
// 范围只能作用于绑定该应用的会话，root 会话一律拒绝，未接线授权实现时 fail-closed；
// 客户端不能自称范围。AdminRevoke 先过强认证闸门（MFA 未实现时默认 fail-closed）与
// 范围级授权、再读取目标，缺授权时对不存在/普通/root 目标统一返回 ACCESS_DENIED，
// 不产生存在性探测差异。LoginRequest.RememberMe 使用独立的可配置绝对到期（只需落在
// 5 分钟～30 天合理上下界内，可短于或长于普通绝对期限），续期仍不越过绝对到期。
// Options.MaxActiveSessions 与
// Options.DevicePolicy 在登录的同一 IMMEDIATE 审计事务内以单条条件更新原子维护：单设备
// 策略先撤销此前全部活动会话再签发，最大在线数保留最近活动的前 N-1 条并淘汰其余，自动
// 淘汰写独立 session.eviction 审计，失败整体回滚。审计动作区分 session.revoke_own、
// session.admin_revoke、session.eviction 与 session.account_disabled_revoke
// （RevokeOnAccountDisabled 由账户禁用流程调用，操作者为系统主体；需要宿主在
// account.Options.SessionRevoker 显式接线，未接线时会话层仍按 users.status 复查拒绝
// 旧会话但不会主动撤销记录），重复撤销幂等。user_admin 预设角色默认含系统权限
// sessions.revoke，但数据范围裁剪未完整落地，系统范围强制下线当前只以权限与
// root/目标保护为闸门，数据范围收缩留后续步骤。设备
// 列表中的客户端描述仅是参考：UserAgent 由客户端自称、可伪造，Address 来自可信边界，
// 都不是可信设备身份或地理位置，也不参与授权。所有撤销只联动身份服务当前会话，不宣称
// OAuth 令牌或第三方业务会话已撤销。
//
// 已知限制：数据范围收缩尚未完整落地——所有写入路径仍以“未声明”范围透传，迁移 0006
// 只保证两个 JSON 列合法，非 all 上限的委派资格一律 fail-closed（不放宽、不按最宽范围
// 解释）；预设初始化与恢复当前只接受受信本地/系统通道（非受信管理者的恢复入口需要
// 会话层、强认证与审批引擎），预览确认令牌保存在进程内，应用创建后需要宿主调用
// InstallApplicationScope 生成应用模板。本步不实现审批引擎、再委派、数据范围写入口、
// 预设目录 HTTP/CLI 或委派资格 HTTP。
//
// internal/mailer 已实现可注入邮件发送接口、首个 SMTP 适配（显式 TLS/认证、
// 时限与取消、稳定失败分类，不可关闭证书校验）、三类邮件模板（验证/找回/事件
// 告知，含头部与地址注入防护）以及基于 internal/task 的可靠投递：幂等键去重、
// SQLite 投递记录、internal/secrets 加密模板数据、受控重试与审计；迁移 0012
// 落地 mail_deliveries 表。它尚未接入 Instance/HTTP/cmd/login-server 装配，
// 默认只用本地测试捕获器，不向真实用户外发，也不承诺外部邮件恰好一次送达。
//
// internal/registration 已实现按配置开放的自主注册与可选邮箱验证后端流程（步骤 33）：
// 注册输入严格字段白名单（ParseRegisterJSON 拒绝 is_root/系统角色/已验证邮箱等未知
// 字段），密码复用 internal/authn 的 Argon2id 与策略；邮箱可选，提供时签发绑定用户与
// 待验证地址的一次性验证入口（internal/credential 高熵令牌，迁移 0013 保存绑定行），
// 验证成功后才把 user_emails.verified_at_ms 置为非空，从而启用已验证邮箱登录；重发
// 受冷却限制并覆盖旧票据（先提交新票据、成功后清理旧凭证；替换失败不误废旧链接，
// 旧链接以票据凭证 ID 不匹配失效），替换待验证地址使旧链接失效；用户名/邮箱占用统一
// 返回同一冲突错误，但接口层“注册成功 vs 冲突”仍是二值探测，HTTP 暴露前必须统一响应
// 形状/耗时并叠加 IP 限流、验证码与邮件频率限制（均未实现）。需要审核时账户以 pending
// 创建，internal/authn 对非 active 账户拒绝正常登录（审核决定由 internal/onboarding 执行）。默认角色
// 只来自宿主可信配置且仅接受 system 作用域（应用角色需走 role/delegation 赋权路径，
// 未实现），绝不自动加入应用成员；验证令牌消费发生在审计事务之外，审计失败 fail-closed
// 但需重新发送验证入口；过期票据清理任务未实现。本包不签发会话、不注册 HTTP 路由、
// 不装配到 cmd/login-server（registration.* 配置当前仅被 Config/Load 校验，尚无启动
// 装配消费者）。
//
// internal/emailchange 已实现已验证邮箱的受控变更（步骤 36）：迁移 0016 落地
// email_change_requests（每用户至多一条 pending 部分唯一索引）；申请只允许本人发起且
// 必须通过宿主注入的 ReauthVerifier（未接线/失败一律 REAUTH_REQUIRED，不能用新地址自证），
// 绑定用户、旧已验证邮箱（无旧邮箱=首次添加）与规范化新邮箱，验证成功前旧邮箱行与验证
// 状态保持不变；新申请在同一审计事务内取消旧 pending 申请；一次性高熵令牌（用途
// email.change.verify、目标申请 ID）发送到新地址，Verify 消费令牌后在审计事务内校验
// pending/未过期/旧邮箱版本/新邮箱唯一性，通过后删除旧已验证行、写入新已验证行、标记
// completed 并失效其他请求，失败整体回滚；重复点击/过期/取消/占用分别明确返回。切换
// 成功向旧已验证邮箱发送不含令牌/链接的安全告知（投递失败不回滚切换，状态可追踪）；
// 验证邮件失败仅记录状态。已知限制：HTTP 路由/启动装配、通知与验证重发、过期申请清理
// 未实现；令牌在审计事务前消费，事务失败会为同一 pending 申请补偿签发新令牌（通过
// VerifyResult 返回，宿主需重投递且不得落日志）；禁用/非 active 账户、旧邮箱版本变化、
// 新邮箱被占用均拒绝切换；不解除 MFA、不签发会话。
//
// internal/profile 已实现用户自助资料修改与获授权管理员修改（步骤 35）：迁移 0015 为
// users 追加 phone/phone_verified_at_ms/username_changed_at_ms；字段白名单只含昵称/
// 简介/语言/时区/可选电话，ParseProfileJSON 严格拒绝 is_root/password/email_verified/
// mfa/roles/status/username 等额外字段；更新用 expected row_version 条件写入，并发冲突
// 返回 CONFLICT 且不部分修改；先判权后读目标，无权调用者对存在/不存在目标统一
// ACCESS_DENIED；本人可改本人非敏感资料，管理员修改他人必须注入 Authorizer
// （未接线时普通用户 fail-closed，system/local_admin 受信通道除外）；受控更名复用
// account.NormalizeUsernameWithReserved、稳定 ID 不变，Policy 以显式三态逐字段合并
// 默认值（冷却默认 24 小时、RequireReauth 默认 true，只配一个字段不会关闭另一个保护；
// 保留名默认沿用 account 清单，ReservedNames 可追加、DisableReservedNames 为显式关闭）
// 未注入 ReauthVerifier 时用户更名拒绝；root 目标更名被拒绝；更名唯一性与版本冲突明确
// 返回；简介允许换行/1000 码点但审计只记 [REDACTED] 长度摘要，审计事件无效映射为
// INTERNAL_ERROR；电话统一 E.164、phone_verified_at_ms 从不写入且改电话时清空，
// PhoneVerified 恒 false，电话不参与登录/找回/身份验证；全局资料只写 users，不覆盖
// app_memberships.profile_json。决策：更名不递增 security_version（会话绑定稳定用户 ID，
// 更名不是凭据变更，旧会话继续有效属预期；如需更名强制下线应另立策略）。已知限制：
// Policy 目前经 profile.Options 注入，尚未新增根配置节与启动装配；HTTP 路由、资料页面、
// 电话验证流程未实现；不签发会话。
//
// internal/onboarding 已实现受控邀请、接受邀请与注册审核（步骤 34）：迁移 0014 落地
// invitations/invitation_roles/invitation_acceptances/registration_reviews；邀请明确
// 发起者、目标邮箱或目标用户、适用应用、允许角色、到期与使用次数，通知经 internal/mailer
// 可靠投递且状态可查询（sent = 已交给投递入队，且只投向已验证邮箱）；接受时先证明令牌持有
// 并做身份绑定（邮箱邀请要求接受账户拥有同一已验证邮箱，用户邀请要求目标用户本人；知道邀请
// ID 不能认领已有用户），再按邀请者当前状态与权限经 delegation.Guard 在同一审计事务内复核：
// 校验范围是目标用户在该范围既有有效权限 ∪ 邀请角色权限，零角色邀请也经过 Guard（不能借
// 重新启用停用成员恢复保留权限），已持有角色按幂等成功；应用停用/邀请取消/过期/次数用尽
// 一律拒绝。使用次数原子扣减、重复接受唯一键拒绝；接受可在同一事务创建新账户（Argon2id、
// 字段白名单）或加入应用成员并分配角色。注册审核只处理 users.status='pending'，批准/拒绝
// 与可选成员/角色变更同事务提交且批准同样经 delegation.Guard 复核；申请人不能自批，管理强
// 认证未接线时普通用户 fail-closed，实现 ScopedManagementAuthorizer 可按应用/角色限定范围，
// 未实现时普通用户不能授予 system 作用域角色。已知限制：一次性令牌使当前邀请只能单次接受
// （MaxUses>1 明确拒绝，多次邀请留后续）；令牌在授权事务之前消费，事务内因邀请者撤权/应用
// 停用/取消/过期失败时令牌不恢复、邀请者需重新签发（数据库侧整体回滚）；过期邀请不会主动
// 落库为 expired（接受时按时间拒绝，清理任务未实现）；邀请创建授权由宿主注入
// InviteAuthorizer，未接线时普通用户拒绝；HTTP 路由、启动装配、过期记录清理、邮件重发与
// 多级审批引擎未实现；本包不签发会话、不创建 root。
//
// internal/support 已实现客服求助单与向原验证邮箱发起密码找回（步骤 46）：
// 迁移 0026 落地 support_cases（目标/创建人/指派客服/原因/状态机/脱敏邮箱快照/
// 行版本）与追加式 support_case_events（动作、真实操作者与时间、状态迁移；数据库
// 触发器禁止 UPDATE，业务 API 无删除历史路径）。客服是普通实名账户且登录强认证由
// authn 对客服等高权限角色要求；登记/转派/状态变更/发起找回还经步骤 38/39 reauth
// 敏感策略（目录新增 support.case.create/update 与 support.reset.send，默认要求
// 近期强认证并绑定操作/目标/参数摘要）。功能权限 support.cases.read/create/update
// 与 recovery.request 来自 preset 目录，数据范围由 authz 计算：all 覆盖全部普通
// 用户、resources 仅列出的用户、undefined/none 拒绝；生产适配器
// NewAuthzAuthorizer/NewAuthzTargetProtector 包装 authz.Service，未接线或依赖故障
// fail-closed。客服只能访问分配给自己的求助单（他人求助单统一拒绝并写失败审计），
// 返回资料脱敏（用户名/邮箱部分遮蔽），不返回邮箱明文、密码、MFA、凭证或找回
// token。目标按实际权限识别：root 与持有系统管理/审批/导出能力的账户返回
// SUPPORT_TARGET_PROTECTED，普通客服不能处理；有效权限无法完整证明时按受保护
// fail-closed。发送动作复用 passwordreset 新增的受信通道 SendResetForSupport：
// 按稳定用户 ID 定位、收件地址只来自此前已验证邮箱、不返回链接/验证码、不能指定
// 新密码、发送不修改密码/安全版本/MFA、不签发会话；缺少验证渠道只转入
// manual_review（人工核验待处理），不以客服确认直接恢复，审批与执行由
// internal/manualrecovery（步骤 47）负责。状态与指派变更使用行版本条件更新（并发
// 单赢家）并与处理历史、审计同事务；终态不可再变更，且 sent 只能由真实发送写入。
// 步骤 47 收口：发起找回增加客服账户维度与全局发起预算双限流（超限 RATE_LIMITED
// 并写失败审计）；受保护权限集合改为“人工基线 + preset 权限目录元数据”自检/派生
// （目录新增 RootOnly/RequiresReauth 项自动纳入，基线漂移拒绝构造授权器）；客服
// 范围内的 exists/disabled/protected 错误码差异属已授权可见信息面，公开接口仍须
// 统一响应，SendResetForSupport 的 system 调用者必须由装配层限制在受控服务路径。
// 页面/HTTP/启动装配、人工核验页面、真实邮件外发、清理任务、多实例限流与 race/
// 非 Windows 未验证。
//
// internal/manualrecovery 已实现人工核验恢复、独立审批与一次性受控执行（步骤 47，
// 默认关闭）：root/宿主必须显式配置核验依据（只允许线下证件原件、公证书面声明等
// 可复核依据，安全问题/电话口述不在枚举）、可信交付（仅既有已验证邮箱）、等待期、
// 批准有效期、申请有效期与独立审批要求。密码恢复与 MFA 恢复分别申请与授权
// （recovery.approve / recovery.mfa.approve），申请绑定目标/发起者/操作/核验记录
// 编号/证据 SHA-256/原因/交付/目标安全版本与高权限快照并计算内容摘要。审批人不得
// 为发起者或目标本人，审批需近期强认证与功能权限；批准有等待期与有效期并绑定内容
// 摘要，内容替换、批准过期、审批人撤权、目标变 root/高权限/停用/版本变化均
// fail-closed；执行在审计事务内条件分配唯一执行权（并发双执行仅一个成功），由宿主
// 注入 Executor 完成真实密码/MFA 恢复与旧凭证/会话失效，成功后通知既有渠道并要求
// 重新登录；执行器故障与最终审计失败不宣称成功。迁移 0027 落地申请/批准/执行三表
// （唯一 active 批准、同一批准唯一执行、不保存证据明文/凭证）。47-FIX 收口：审批
// 授权携带目标账户与作用域并可校验数据范围；内容摘要绑定交付地址不可逆指纹、执行
// 前重读比对（换绑邮箱即失效）；执行校验申请过期且 claim 条件含 expires_at，策略
// 强制申请有效期覆盖等待期+批准有效期；完成通知改为最终提交之后发送，启用时必须
// 装配通知适配器；已消费/失效批准的历史审批人仍可查看申请。页面/HTTP/装配、真实
// 执行器与邮件外发、数据范围写入口、清理任务、race/非 Windows 未验证。
//
// internal/passwordreset 已实现主动改密与邮件找回（步骤 45）：改密复用 authn
// SetPassword 的当前密码复核/密码策略/历史/敏感操作策略，成功后安全版本递增并撤销
// 全部会话（默认重登）、写 OAuth 撤销 outbox；邮件找回只向已验证邮箱发送短期高熵
// 一次性入口（credential 摘要保存与原子消费、mailer 找回模板），公开响应不暴露账户
// 存在性，访问入口不建立会话、不解除 MFA、不为无密码账户加密码，并发/重放单赢家；
// 迁移 0025 落地找回请求（只存 token 摘要）与 OAuth 撤销 outbox（有界重试、失败可
// 审计；与密码写入不同事务，消费者后续实现）。公开找回入口按邮箱/来源限流并做等量
// 主要工作缓解时序侧信道（发信仍为命中独有，残余时序差待 HTTP 接线）；重置成功发送
// 不含密码/入口的安全告知；新请求/重置/改密都会作废旧 pending 入口；预检查校验
// token 摘要不消费。页面/HTTP/装配、真实邮件投递、outbox 消费者、过期清理留后续步骤。
//
// internal/totp 已实现标准 TOTP（RFC 6238，SHA1/Base32/otpauth URI）的绑定与登录
// 验证核心（步骤 41）：crypto/rand 生成 20 字节种子并经 internal/secrets.Sealer
// 认证加密保存（用途 mfa.totp/对象=绑定 ID/范围 system），pending 绑定需近期认证
// （reauth）并在验证验证码后于同一审计事务内激活并替换旧 active；服务端可信时间
// 与有界时间步/窗口，记录并原子推进 last_accepted_step 防同一步并发/重放；解除先
// 验证当前验证码再检查强制 MFA 与其他强因素。已通过 RFC 6238 官方测试向量与窗口
// 边界测试（不代表真实验证器/真机实测）。internal/mfa 登录第二步已接入 TOTP：按可
// 配置因素顺序（默认 TOTP 优先于邮件）创建 totp 挑战、不发送邮件，Verify 调
// totp.VerifyLoginCode 后复用步骤 40 的受限会话绑定与轮换逻辑，失败计入尝试上限，
// 重放拒绝；完整认证方式选择策略属步骤 43。mfa 必须与 TOTP 适配器配对注入（缺失
// 时构造失败，避免已绑定 TOTP 账户被当作无因素放行）；mfa.add 默认近期密码认证，
// 确认步写入 last_accepted_step 防立即复用，确认失败只写 failure 审计。页面/HTTP/
// 装配约束：BeginBinding 只能从完整（非受限）已认证会话调用，高权限账户绑定/更换
// 强因素须在完成强认证后进行（mfa.add 默认仅要求近期密码认证，服务层不判断会话
// 是否受限）。确认绑定各拒绝分支写 failure 审计。装配留后续步骤；本包不做二维码 UI。
//
// internal/authfact 与 internal/mfa 已实现 FIDO2 第二步验证与认证方式选择策略
// （步骤 43）：authfact 统一定义密码/邮件验证码/TOTP/Passkey/安全密钥方法、因素
// 类别、认证事实集合、强度（single/MFA/strong）、策略要求、选择器与 amr/acr 映射
// （只映射内部事实，不实现 OAuth/OIDC 端点）。Passkey 凭证用途扩展为
// login/second_factor/both 并由服务端注册 ceremony 决定，主登录与第二步分别按用途
// 过滤（迁移 0023 重建三表并保留既有行；已有凭证保持 login）。mfa 的第二步因素
// 选择器按“实际启用且满足策略”选择：Passkey/安全密钥（UV）优先，其次 TOTP，最后
// 邮件；强认证要求下邮件不会被选中，无可用方式明确报错不降级；密码+安全密钥/TOTP
// 或 Passkey UV 会在认证结果与会话记录强认证时间，管理访问强认证闸门据此放行。
// 要求强认证但未绑定强因素的管理账户在宿主显式启用时只能走受限初始化闭环：仅签发
// 受限会话、绑定允许的强因素、撤销受限会话并要求重新登录，不公开临时管理员旁路；
// 进入该闭环必须经宿主注入的 StrongSetupAuthorizer 受控授权（内置 bootstrap 适配器
// 只放行 root pending_setup/setup_verified，其他高权限账户需管理员一次性凭证/审批），
// 普通受限会话不能自助绑定。authn 通过可注入 StrongFactorPresence 按实际已绑定强
// 因素动态给出 RequiredSteps。删除 Passkey 或解除 TOTP 会在同事务递增
// security_version 并使既有会话失效；管理访问强认证新鲜度由 session
// StrongAuthMaxAge（默认 15 分钟）约束；AllowTOTPForStrongAuth 默认 false，
// 强认证默认要求 WebAuthn UV。删除最后一个第二步凭证且无其他强因素时按强制策略拒绝。页面/HTTP/
// 启动装配、OAuth/OIDC 协议端点、恢复代码、真实浏览器/Windows Hello/安全密钥实测
// （测试为模拟认证器与测试替身）、清理任务与 race/非 Windows 验证属后续步骤。
//
// internal/passkey 已实现 WebAuthn/Passkey 注册、用户名登录、可发现凭证登录与
// 凭证管理（步骤 42）：迁移 0022 落地 webauthn_user_handles（稳定随机用户句柄）、
// webauthn_credentials（COSE 公钥/计数器/BE/BS 等元数据）与 webauthn_ceremonies
// （服务端挑战与绑定的 AppID/记住我/客户端描述）。WebAuthn 协议与密码学校验使用
// 维护中的 github.com/go-webauthn/webauthn v0.18.2（BSD-3-Clause），不自行实现
// 密码学；挑战一次性原子消费，库校验 challenge/操作类型/来源/RP ID/签名/UP/UV；
// 注册凭证绑定服务端挑战中的用户、credential_id 全表唯一（防止把他人凭证登记
// 到自己名下），用户句柄与用户 ID 无关且稳定。同步凭证（backup eligible）计数器
// 允许不递增，非同步凭证计数器不递增按可能的复制拒绝。新增/删除凭证复用
// internal/reauth 与步骤 38 目录的 passkey.register/passkey.remove；删除前在同一
// 审计事务检查不得失去最后一个登录方式（其他 Passkey 或主密码）。验证成功且满足
// UV 策略的 Passkey 直接完成登录（不追加同源第二因素），通过 internal/session
// 签发；应用作用域在开始阶段绑定、完成阶段只以同 AppID 签发并防御性复验，不会
// 升级为全局会话。本包不暴露 HTTP 路由与页面、不实现 FIDO2 第二因素/认证方式
// 选择策略（步骤 43）、恢复代码、MDS/attestation 证书链校验与 raw attestation
// 持久化；测试使用模拟认证器，不代表真实浏览器/Windows Hello/安全密钥实测；
// root 的 Passkey 登录仍 fail-closed。
//
// internal/mfa 已实现两步验证公共状态机与邮件第二步验证（步骤 40）：迁移 0020
// 落地 mfa_factors/mfa_challenges；挑战统一绑定用户、当前登录尝试摘要、用途、因素、
// 验证码凭证与重发代数，pending 只能条件迁移一次（并发/重放单赢家）。启用邮件因素后
// 第一步密码认证只签发受限会话，第二步验证码通过（复用 internal/credential 受保护
// 低熵验证码、internal/mailer 受控发送、只发已验证邮箱）后才用同一会话秘密轮换为
// 完整普通会话（沿用第一步 AppID/记住我/客户端，应用作用域不会升级为全局会话；
// Verify 必须使用挑战绑定的同一受限会话）。高权限账户的邮件因素不能替代强认证，
// BeginLogin fail-closed 返回 MFA_REQUIRED 且不签发会话；强制策略但无可用因素同样
// fail-closed；账户维度有界挑战/验证/重发限流防爆破与邮件轰炸。因素新增需验证渠道
// 控制权，移除受宿主 Policy 强制策略约束；取消登录不撤销已签发受限会话（由宿主/
// 到期回收）。明文验证码不进入日志/审计/错误/队列；TOTP 已接入（步骤 41），
// FIDO2 第二因素、页面、HTTP 路由、装配、因素切换与过期清理留后续步骤。
//
// internal/reauth 已实现敏感操作的再次认证、认证强度判断与安全告知（步骤 39）：
// 执行前按步骤 38 有效策略实时判断近期认证（新鲜度/实际强度/完整认证/确认），
// 不满足时要求绑定调用者、作用域、稳定操作 ID、目标与服务端参数摘要的短时一次性
// 批准（令牌只存摘要、事务内条件消费，换对象/换参数/重放/过期均拒绝）；挑战使用
// 有界尝试次数并经注入的 PasswordVerifier 真实验证密码，生产适配在 internal/authn
// 复用正式密码校验、限流与审计；MFA/Passkey 未实现时要求强认证的操作 fail-closed
// 为 MFA_REQUIRED，不降级，高权限操作还要求完整认证。成功后按策略向已验证邮箱发送
// 安全告知（复用 internal/mailer 模板；无邮箱/未配置/投递失败/限频只记录状态与原因，
// 不回滚业务变更、不把通知当认证），测试使用 internal/testmail 本地捕获器。接入范围：
// internal/profile 受控更名已通过 Options.Sensitive 接入；邮箱变更、角色、会话与
// 邮箱变更申请/确认、角色赋/收角色、组合/移除角色权限、角色启停、组成员加入/移除、
// 管理强制下线与 authn 设置密码均已通过 Options.Sensitive 接入（批准绑定由服务端
// 计算的目标/范围/方向/集合/关键参数；成功路径发送告知）。敏感操作未注入敏感策略时
// 默认拒绝，只有显式 AllowLegacyWithoutSensitive（默认 false，仅供旧装配/测试过渡）
// 才回退既有保守闸门；既有委派 Guard/ReauthVerifier/强认证闸门保留且不被替代，
// authn 提供生产密码验证适配作为唯一可信密码来源。本包不做页面、不暴露 HTTP 路由、
// 不实现 MFA 与密码找回流程（属后续步骤）；authn.SetRootPassword 尚未接敏感策略（待 CLI/装配按 authn.root_password.setup 收口）；失败路径的失败告知尚未在业务模块调用，
// 过期挑战/批准清理、失败告知限频的多实例共享与 race/非 Windows 验证留后续。
//
// internal/policy 已实现可管理的敏感操作目录、root 策略配置与恢复默认（步骤 38）：
// 系统内置 31 个稳定敏感操作（密码、邮箱、MFA/Passkey、权限、应用凭证、备份、
// 审计、会话管理、root 恢复、邀请/注册审核、root 设置密码、邮箱确认、角色权限/启停、
// 组成员变更、客服求助单登记/更新与向原验证邮箱发起找回，以及策略本身），每条有
// 中文名称/说明、默认策略（是否敏感、认证新鲜度、所需认证强度、确认、告知）与
// 不可被策略覆盖的基础权限、root 专属与
// 审计约束；迁移 0018 只保存偏离默认值的覆盖行与应用声明，恢复默认即删除覆盖行，
// 每个作用域（system/应用）有独立版本，修改与恢复必须在审计事务内携带期望版本，
// 过期返回 CONFLICT；只有真实 root 且经宿主 ReauthVerifier 再次验证后可修改，普通
// 管理员与应用管理员被明确拒绝，取消敏感标记不会取消基础权限/root 限制/审计；
// 未实现的认证强度（MFA/Passkey）在评估时 fail-closed 为 MFA_REQUIRED，不降级为
// 密码。既有 authn/session/profile/emailchange/onboarding 的临时保守要求已登记为
// 目录默认值，在执行器接入前其 fail-closed 行为保持不变。本包不执行敏感操作、
// 不暴露 HTTP 路由、不装配 cmd/login-server，执行器与页面留后续步骤；应用发起声明
// 与 root 审核工作流、authz 动态权限判定接线、告知投递与多实例锁未实现；Evaluate
// 暂不做作用域读取授权，执行器接线时必须限定可信调用方。
//
// internal/avatar 已实现用户头像的受控本地上传与网络头像处理（步骤 37）：迁移 0017
// 落地 avatars（每用户一个头像、存储相对键唯一、内容摘要）；上传按真实字节校验
// 并重编码为静态 PNG/JPEG（默认拒绝 SVG 等主动内容，先读尺寸再解码防解压膨胀，
// 声明类型必须与真实内容一致），文件名/存储键全部由服务端生成并限定在宿主目录，
// 读取前校验路径未逃逸与摘要匹配；引用更新、旧头像行替换与安全审计在同一事务内，
// 数据库/审计失败补偿删除新文件，旧文件删除失败由 CollectGarbage 只清理“不再被引用
// 且修改时间早于安全窗口（默认 10 分钟、允许 30 秒～24 小时，Options.GCSafetyWindow
// 可调）”的受控文件，
// 避免误删已落盘但引用事务尚未提交的新文件（按单实例受控目录设计）。网络头像采用
// 受控抓取：仅 https 默认端口、无凭证、每次解析与重定向
// 校验目标地址并拒绝环回/私有/链路本地/CGNAT/保留网段、直接连接校验过的 IP、
// 限制重定向/时限/大小且关闭自动解压，抓取结果走同一重编码流程。默认只允许本人与
// 受信 system/local_admin（只校验身份 ID，不检查账户状态；禁用/待审核用户的可用性
// 必须由宿主会话或注入 Authorizer 在该阶段 fail-closed 补齐），跨用户展示需宿主注入
// Authorizer；本包不暴露 HTTP 路由、不装配 cmd/login-server，展示响应头由
// Content.SetResponseHeaders 提供，错误码只复用既有码；NetworkPolicy 的测试专用
// TestOnlyAllowLocalAddresses 导出的生产配置字段目前仅靠 GoDoc 约束，HTTP/装配接线前
// 应改为构造校验或构建标签隔离；头像更新会使 users.row_version 递增，HTTP 接线、
// 页面、根配置节与真实外网抓取验证留后续。
//
// 密码登录/退出/会话校验的 HTTP 路由与启动装配、自助注册 HTTP 路由与启动装配、OAuth/OIDC Token 联合校验与完整
// 授权执行、应用成员/用户组/权限目录/角色/有效权限 HTTP 接口、OAuth 凭据/回调、Web 页面与
// 备份流程尚未实现；会话能力已由 internal/session 提供受信 Go API，但管理强认证（MFA）未
// 实现前管理访问保持拒绝，设备列表与管理强制下线同样只有 Go API（未暴露 HTTP 路由），
// 数据范围裁剪也尚未接入强制下线。首次初始化也不提供 CLI 命令或启动装配（cmd/loginctl 尚未建立），
// 兑换后的受限配置会话持久化绑定与完整 root 应急重置留后续步骤。需要独立进程入口时使用
// cmd/login-server；该入口目前也只提供版本与帮助，不会假装服务已经启动。
package login
