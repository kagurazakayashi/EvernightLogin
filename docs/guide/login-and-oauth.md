# 登录、扫码与 OAuth/OIDC 接入

本文面向“我要让业务接入登录”的开发者，说明当前可用的登录方式、协议契约与真实状态。
先记住一条：**OAuth/OIDC 协议端点已装配并可按配置开关启用（默认关闭）**。标准 HTTP
客户端在启用 `protocol.enabled`（或 `--enable-protocol`）后可对接授权/令牌/Discovery/
JWKS/UserInfo/撤销端点；设备码需同时启用 `protocol.device_code_enabled`（步骤 192 已补
边界验收），APP 扫码需 `app_qr_login.enabled` + 应用白名单（步骤 193 已补双会话闭环验收），
令牌状态查询已实现（145/160 验收边界），默认关闭；边界项以对应验收记录为准。维护模式一律 503。

## 1. 术语先解释

- **OAuth 2.0**：授权协议。客户端应用向用户请求“有限范围的访问权”，服务端签发令牌。
- **OIDC（OpenID Connect）**：架在 OAuth 2.0 上的身份层，用 ID Token 告诉客户端
  “这个用户是谁”。本项目只支持授权码（`response_type=code`）流程，不支持隐式授权与
  密码授权。
- **PKCE（Proof Key for Code Exchange）**：防授权码被拦截的机制。本项目**强制 S256**。
- **Access Token（访问令牌）**：访问业务资源用；有类型、签发方、有效期、audience。
- **Refresh Token（刷新令牌）**：用于换新 Access Token；会轮换并检测重放。
- **ID Token**：OIDC 身份令牌，客户端必须校验签名、签发方、受众、有效期与 nonce。
- **JWT / JWKS**：令牌格式 / 验签公钥发布文档。客户端按 `kid` 缓存公钥，不信任令牌
  自述的密钥地址（`jku`/`x5u`/`x5c`/`jwk`）。
- **scope / audience**：申请的权限范围 / 令牌面向的目标资源。audience **不等于**
  `client_id`。
- **设备码（Device Code，RFC 8628）**：给无法输入密码的设备（电视、CLI）用的一次性
  短码登录流程。
- **服务身份（client credentials）**：服务端对服务端，用客户端 secret 取得代表“应用
  自身”的令牌，不代表任何用户。

## 2. 当前状态

| 能力 | 实现 | HTTP | 说明 |
|---|---|---|---|
| 密码登录 / 会话 | `internal/authn`、`internal/session` | 页面路由已接线（需宿主装配后端） | 服务端会话 Cookie + CSRF；不在浏览器存长期 Token |
| 两步验证（TOTP/邮件/恢复代码） | `internal/totp`、`internal/mfa`、`internal/recovery` | 页面已实现 | 受限恢复会话与强制重新绑定 |
| Passkey / WebAuthn | `internal/passkey` | 页面已实现 | 启用需配置 RP ID 与允许来源 |
| OAuth 授权码 + PKCE + 刷新 | `internal/oauthflow`、`internal/oauthclient`、`internal/token` | **已装配，默认关闭** | 示例 `examples/oidc-login`；真实 HTTP 黑盒验收待 158/160 |
| OIDC Discovery / ID Token / UserInfo | `internal/oidc` | **已装配，默认关闭** | 只声明已实现能力；UserInfo 正向 HTTP 流程已由步骤 191 补验收（见 `docs/acceptance/step191-oidc-userinfo.md`）；真实第三方客户端互操作仍未测 |
| 服务身份（client credentials） | `internal/oauthflow`、`internal/tokenauthz` | **已装配，默认关闭** | 示例 `examples/service-identity` |
| 设备码授权 | `internal/oauthflow`、`internal/protocolapi` | **已装配，默认关闭** | 设备确认页已接入；步骤 192 已补 pending/slow_down/过期/重放/错误客户端/拒绝与确认页展示验收（见 `docs/acceptance/step192-device-code.md`）；真实手机/硬件未测 |
| APP 扫码登录网页 | `internal/qrlogin`、`internal/protocolapi` | **已装配，默认关闭** | 双会话确认/领取闭环已由步骤 193 用真实内置网页验收（见 `docs/acceptance/step193-qr-login.md`）；真实手机相机扫码未测 |
| 权限联合校验 | `internal/tokenauthz` | Go 契约已实现；真实 HTTP 黑盒验收待 144 | 见第 6 节 |

完整协议细节（参数表、安全要求、对客户端校验要求）见
`docs/deployment/integration.md` 第 2～6 节；本文只给接入者必须知道的最小集。

## 3. OIDC 登录（授权码 + PKCE S256）

### 3.1 授权请求要求

| 参数 | 要求 |
|---|---|
| `response_type` | 只接受 `code` |
| `client_id` | 已登记且所属应用启用 |
| `redirect_uri` | 与登记值精确匹配 |
| `scope` | 客户端登记 scope 的子集；`openid` 表示要 OIDC 登录 |
| `resource` | 可选 audience 列表，必须属于客户端登记 audience；要用 UserInfo 必须显式传 `resource=<issuer>`（详见 `docs/deployment/integration.md` 2.4） |
| `state` | 必须回显并由客户端校验与发起值一致；缺失/串用视为失败 |
| `nonce` | 使用 `openid` 时必须传，客户端必须校验 ID Token 里的 nonce |
| `code_challenge` / `code_challenge_method` | **强制** `S256`；`plain` 或缺失拒绝 |

### 3.2 兑换与令牌

- 授权码**一次兑换**；兑换必须带匹配的 `code_verifier`（恒定时间比较）。
- 公开客户端不带 secret；保密客户端用 client secret 或 mTLS 证书认证，两者不可混用。
- 兑换可返回 Access Token、ID Token（仅 `openid`）、Refresh Token（客户端登记
  `refresh_token` 且授权含 `offline_access`）。
- Refresh Token 轮换；旧令牌重放按安全事件处理（`REFRESH_REUSE_DETECTED`），不通过
  宽限期掩盖重复使用。
- Discovery 文档只声明已实现端点；不要假设存在未声明的能力。

### 3.3 客户端必须做的校验

- ID Token：验签（JWKS）、`iss`、`aud`（等于本客户端）、`exp`/`iat`、`nonce`；拒绝
  未发布的签名算法。
- Access Token：必须是 access 类型；`aud` 必须是本业务资源；不解析未验证令牌中的权限。
- UserInfo：Access Token 的 scope 需含 `openid` 且覆盖 `profile`/`email`；`aud` 必须包含
  本服务 issuer（客户端须把 issuer 登记为允许 audience 并显式请求 `resource=<issuer>`）；
  邮箱只在已验证时返回。资源服务器 audience 的令牌调用 UserInfo 会被 401 `invalid_token`
  拒绝，这是受众隔离而非校验缺陷。
- JWKS：按 `kid` 缓存；密钥轮换后保留期内旧密钥仍可验签，保留期后拒绝。

## 4. 服务身份（client credentials）

- 只允许**保密客户端**（服务端之间）申请；浏览器/移动端不能持有 client secret。
- 令牌 `subject_type=service`，代表应用自身，不代表用户、也不自动获得任何管理权限。
- scope/audience 必须是客户端登记的子集；业务权限由宿主注入的服务主体授权器判定。
- 轮换 secret 后旧 secret 立即失效；secret 只能放服务端密钥库/受保护配置。

## 5. 设备码与扫码登录

### 5.1 设备码（RFC 8628）

端点：`POST /oauth/device_authorization`（申请）、`POST /oauth/device/cancel`（发起端取消，
本服务扩展）、`POST /oauth/token`（`grant_type=urn:ietf:params:oauth:grant-type:device_code`）；
确认走内置页面 `/oauth/device` 与 `/oauth/device/confirm`。协议端点默认关闭，需同时满足
`protocol.enabled` 与 `protocol.device_code_enabled`，只有启用时 Discovery 才声明该能力。

1. 设备用 `client_id`（保密客户端另需认证）申请，得到 `device_code`（高熵，设备保存）、
   `user_code`（短码，展示）、`verification_uri`、`verification_uri_complete`、有效期与
   轮询间隔。公开客户端不得携带任何 secret。
2. 用户在已登录页面输入短码，页面展示**正确的应用名称/标识与请求范围**后由用户显式
   批准/拒绝；确认需要真实会话与近期认证。
3. 设备轮询：未确认返回 `authorization_pending`，过快返回 `slow_down`（服务端强制间隔
   并递增，带 `Retry-After`），用户拒绝/取消返回 `access_denied`，过期返回
   `expired_token`；设备码不存在、被其他客户端提交、已领取/重放返回 `invalid_grant`；
   只能由申请时的同一客户端领取。
4. 批准后**一次性**兑换令牌（重复兑换 `invalid_grant`）；默认签发 Access Token，仅客户端
   登记 `refresh_token` 且含 `offline_access` 时签发 Refresh Token；设备码流程**不签发
   ID Token**（`openid` 在设备授权阶段被拒绝，OIDC 登录请用授权码流程）；二维码/短码中
   **不含**长期 Token。
5. 短码低熵，服务端只存带密钥的 HMAC 摘要；有频率限制与有效期；过期/取消立即失效。

步骤 192 已用真实公开客户端 + 真实回环 HTTP 服务验证上述边界，记录见
`docs/acceptance/step192-device-code.md`。

### 5.2 APP 扫码确认网页登录

端点：`POST /oauth/qr/request|status|claim|cancel|regenerate`（发起端）与
`GET /oauth/qr/prompt`、`POST /oauth/qr/decision`（确认端）；内置页面 `/login/qr`（发起端）
与 `/app/scan`（APP 确认页）。默认关闭，需 `app_qr_login.enabled` + 应用白名单。

1. 网页发起请求，二维码只承载一次性请求标识，**不承载**领取绑定或 Token。
2. 已登录 APP 用真实普通会话查看请求（应用名称/标识、范围、发起端信息、风险提示），
   核对后批准/拒绝；批准是敏感操作，要求近期认证。
3. 网页用请求标识 + 领取绑定领取；批准原子消费（并发只有一个赢家），并签发**目标应用
   会话**——**不签发 OAuth Token**。
4. 已领取/过期/取消/拒绝后不可重放；只凭二维码中的请求标识或错误领取绑定不能领取；
   其他网页/其他端无法抢领；该流程不能被改造成“任意应用换用户 Token”的通道。
5. 启用该能力需要同时满足总开关与应用白名单（见 [configuration.md](configuration.md)
   第 4.6 节），白名单为空时按配置错误拒绝启动。
6. 协议直连确认端使用 Bearer 会话秘密时不需要 CSRF 头，但状态修改必须带同源
   `Origin`/`Referer`；Cookie 会话必须额外提交会话绑定 CSRF 令牌。403 应补合法凭证与
   同源头，**不得关闭 CSRF/同源/再认证校验**（详见 `docs/deployment/integration.md` 第 6 节）。

步骤 193 已用匿名发起端网页 + 已登录 APP 两个独立会话，经真实内置网页与真实 HTTP
服务验证确认展示、批准/拒绝、原网页领取、重复确认/领取、错误领取绑定、其他网页抢领、
过期与取消语义，记录见 `docs/acceptance/step193-qr-login.md`。

## 6. Token 与权限联合校验（业务服务侧）

业务资源服务在每次访问时调用一次判定，全部满足才放行：

1. 令牌有效：类型/签名/签发方/有效期/audience/撤销状态；
2. 可信资源：`application_id` 与 `audience` 来自可信边界，令牌 `client_id` 必须映射到
   同一应用，且客户端登记 audience 仍包含该资源；
3. 主体可用：用户禁用优先拒绝；应用成员关系与应用启用状态当前有效；
4. 权限交集：令牌 scope ∩ 当前有效权限（角色/用户组/委派实时计算，不缓存），支持
   all/any 组合；空权限要求按参数错误拒绝；
5. 数据范围（可选 `resource_id`）：按数据范围交集判定；**资源归属与对象状态必须由业务
   服务另行校验**，不能用一个功能权限代替归属检查；
6. 失败审计：拒绝写失败审计；审计不可用**不改变**拒绝结果。

依赖失败必须按 503 语义处理（`AUTHZ_UNAVAILABLE`），不得降级放行。错误码见
[troubleshooting.md](troubleshooting.md)。

## 7. Token 保存边界（必须遵守）

| 位置 | 允许 | 禁止 |
|---|---|---|
| 浏览器 | 服务端会话 Cookie（HttpOnly/Secure/SameSite） | localStorage/sessionStorage 存长期 Token、Token 进 URL/日志/埋点 |
| 业务服务端 | 内存；需持久化时加密并控制访问 | 明文写盘、写工单/聊天/截图、跨环境共享 |
| 日志/审计/报告 | request_id、主体、结果、错误码等脱敏字段 | Access/ID/Refresh Token、一次性凭证、密码、MFA 秘密、二维码领取绑定 |
| 示例程序 | 进程内临时使用，不写文件、不打印明文 | 把示例输出当生产配置 |

## 8. 如何体验（当前可执行）

```bat
:: 运行目录：仓库根；平台：Windows amd64；不联网
go run .\examples\oidc-login
go run .\examples\service-identity
go run .\examples\app-qr-login
```

预期：每个示例退出码 0；使用临时 SQLite 与临时密钥，程序退出即丢弃；输出为通过行或
明确的拒绝用例结果。`examples/oidc-login` 是步骤 191 的外部客户端示例：它在
`127.0.0.1` 随机端口启动真实 HTTP 协议服务，然后以标准 HTTP 客户端完成授权码 + PKCE
→ Token → UserInfo 及拒绝用例；退出时关闭端口并删除临时库。示例中的宿主边界适配器
（授权判定、近期认证信号）是**演示用**，生产必须替换为真实实现。

## 9. 未实现/未实测（如实登记）

- **令牌状态查询（introspection）已实现（145/160 验收边界；默认关闭；mTLS/故障等未实测）**；默认关闭，Discovery 只声明已实现能力，不能按未验收能力对接。OAuth/OIDC 其他端点、管理 JSON API、托管 API 与应用客服 API 需显式开关（默认关闭），未开启时 404、维护模式 503。
- APP 扫码登录已完成双会话（匿名发起端网页 + 已登录确认端）真实内置网页与 HTTP 闭环验收（确认展示/批准/拒绝/领取/重复/抢领/过期/取消，步骤 193，见 `docs/acceptance/step193-qr-login.md`）；真实手机相机扫码与真机 APP 互操作未测。
- 设备码已完成真实公开客户端 + 真实 HTTP 回环服务的边界验收（pending/slow_down/确认页应用与范围/批准领取/重复兑换/错误客户端/拒绝/过期/取消/Discovery 一致性，步骤 192，见 `docs/acceptance/step192-device-code.md`）；真实手机/硬件与第三方客户端库互操作未测。
- OIDC UserInfo 已用真实 HTTP 协议流程验收正向接入与 audience/scope/签发方/重放/撤销/过期拒绝（步骤 191，见 `docs/acceptance/step191-oidc-userinfo.md`）；真实第三方 OIDC 客户端库互操作未测。
- 真实第三方 OIDC 客户端、移动端相机扫码、真实浏览器联调未实测。
- 刷新令牌重放/撤销/密钥轮换的跨进程与并发压力未实测。
- `internal/*` 未公开包装，外部宿主不能直接导入这些协议实现。
- 集群/多实例共享状态未实现（单实例主库）。
