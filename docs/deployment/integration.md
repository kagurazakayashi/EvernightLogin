# 业务接入契约

本文面向接入 login 的业务应用，说明当前可用的接入形态、四类认证/授权契约、示例凭证
生成方式与 Token 保存边界。协议/管理/托管/应用客服 HTTP 路由已装配但默认关闭；设备码与
扫码登录已按步骤 192/193 验收其已实现边界，令牌状态查询（introspection）已实现（145/160 验收边界；默认关闭；mTLS/故障等未实测）；
未明确标注为可用的能力不要按“已上线接口”对接。

## 1. 接入形态与当前状态

| 接入方式 | 状态 | 说明 |
|---|---|---|
| 嵌入模式（宿主 Go 进程装配 `login.Instance`） | 已实现（Go API） | 宿主自行持有数据库、会话、页面与 HTTP 服务；本模块不监听端口、不建全局实例 |
| 独立服务进程（`login-server serve`）基础 HTTP 能力 | 已实现（MVP） | 健康检查、OpenAPI 文档与内置账户入口页；配置/迁移/密钥/审计/维护门禁/单实例锁/TLS/访问日志轮转/后台任务运行时/协议与管理 API 挂载点/优雅关闭已装配 |
| 独立服务 HTTP 端点（OAuth/OIDC/管理 API/托管 API/应用客服 API） | **已装配，默认关闭；部分能力未完成验收** | `--enable-protocol`、`--enable-admin-api`、`--enable-managed-api`、`--enable-app-support` 分别开启；设备码与扫码登录已按步骤 192/193 验收其已实现边界；令牌状态查询（introspection）已实现（145/160 验收边界；默认关闭；mTLS/故障等未实测），不按未交付端点对接 |
| 本模块内示例程序（`examples/`） | 可编译运行 | 用临时 SQLite 与真实服务演示服务端语义；外部宿主**不能**导入 `internal/` 包，因此示例不等于可直接对接的 SDK |
| 外部消费示例（`examples/external-consumer`，独立 module） | 可编译运行 | 只导入公开包（配置/实例/页面/扩展），用于宿主集成 |

安全边界：**调用者身份必须来自可信边界**（mTLS 映射、客户端认证或嵌入代码），不能由
普通请求参数自称 `app_id`、`audience` 或 root。

## 2. OIDC 登录（授权码 + PKCE S256）

实现：`internal/oauthflow`（授权请求/兑换/刷新/撤销）+ `internal/oidc`（Discovery、
ID Token、UserInfo）。示例：`examples/oidc-login`。

### 2.1 授权请求契约

| 参数 | 要求 |
|---|---|
| `response_type` | 只接受 `code`；隐式授权与密码授权不支持 |
| `client_id` | 已登记、所属应用启用 |
| `redirect_uri` | 必须与登记值精确匹配（公开客户端按登记规则匹配，见 `internal/oauthclient`） |
| `scope` | 必须是客户端登记 scope 的子集；`openid` 是 OIDC 登录开关 |
| `resource` | 可选的 audience 列表，必须属于客户端登记 audience；audience 是目标资源，不等于 client_id。OIDC 客户端要用 UserInfo 时必须显式请求 `resource=<issuer>`（见 2.4） |
| `state` | **必须回传并绑定本次请求**：服务器原样回显，客户端必须校验与发起值一致；缺失或串用视为失败 |
| `nonce` | 使用 `openid` 时**必须传并在客户端校验 ID Token 的 `nonce`**；不一致视为重放/串用，拒绝该 ID Token |
| `code_challenge` / `code_challenge_method` | **强制 PKCE S256**；`plain` 或缺失一律拒绝 |

### 2.2 兑换与令牌

- 授权码一次兑换；兑换必须带匹配的 `code_verifier`（S256 恒定时间比较）。
- 公开客户端不携带 secret；保密客户端使用 client secret 或 mTLS 客户端证书认证，
  两种认证方式不可混用。
- 兑换响应可包含 Access Token、ID Token（仅 `openid`）与 Refresh Token（仅客户端登记
  `refresh_token` 且授权含 `offline_access`）。令牌默认脱敏，只有显式取值才能取得明文。
- Refresh Token 轮换并按重放语义处理；过期/撤销/轮换后的旧令牌按标准错误拒绝。
- Discovery 只声明已实现的能力，不声称未实现端点。

### 2.3 客户端校验要求

- ID Token：校验签名（JWKS）、`iss`、`aud`（必须等于本客户端）、`exp`/`iat`、`nonce`；
  不接受除已发布签名算法外的算法，不信任 `jku`/`x5u`/`x5c`/`jwk` 自述密钥。
- Access Token：类型必须是 access token（ID Token/Refresh Token/会话秘密不能冒充），
  `aud` 必须是本业务资源；不解析未验证令牌中的权限。
- UserInfo：Access Token 的 scope 必须包含 `openid` 且覆盖 `profile`/`email`，
  `aud` 必须包含本服务 issuer（见 2.4）；返回资料按 scope 裁剪，邮箱只在已验证时出现。
- JWKS 轮换：验证端应按 `kid` 缓存公钥；旧密钥在保留期内仍可验证既有令牌，保留期后
  验证拒绝。

### 2.4 UserInfo 的 audience 语义（步骤 191）

本服务把 **issuer 本身当作 UserInfo 的资源受众**：`/oauth/userinfo` 只接受 `aud` 包含
issuer 的 Access Token。接入方必须：

1. 在 OAuth 客户端登记时把 issuer（与 `protocol.issuer` 完全一致、不含尾斜杠）加入
   `Audiences`；
2. 授权请求显式带 `resource=<issuer>`。客户端只登记了一个 audience 时可省略
   `resource` 并取该默认值；登记了多个 audience（例如同时登记业务资源 audience）却
   省略时，授权端点按 `audience_required` 拒绝，避免隐式扩大受众；
3. 只把**资源服务器 audience** 的令牌用于业务 API，不要用它调用 UserInfo：
   `/oauth/userinfo` 会返回 `401 invalid_token`，这是受众隔离的设计结果，不是
   audience 校验缺陷；不要通过删除 audience 校验或放松签发方校验绕过。

ID Token 的 `aud` 恒等于客户端 `client_id`，与 UserInfo 的 Access Token 受众不是一回事；
ID Token 不能当 Access Token 使用。可运行的外部客户端流程见
`examples/oidc-login` 与 `docs/acceptance/step191-oidc-userinfo.md`。

## 3. 服务身份（client credentials / 服务主体）

实现：`internal/oauthflow` 的 client credentials 兑换 + `internal/oauthclient` 客户端
登记。示例：`examples/service-identity`。

- 仅**保密客户端**（服务端之间）可申请服务身份令牌；公开客户端/浏览器不能持有 client
  secret，不靠打包在程序里的 secret 证明身份。
- 服务令牌的 `subject_type=service`（旧令牌缺该声明时按 user 解释，因此新代码不得把
  缺失声明当作服务身份）。服务身份代表“应用自身”，不代表任何用户，不能据此获得用户
  权限。
- scope 与 audience 必须是客户端登记的子集；服务身份的业务权限由宿主显式注入的
  服务主体授权器判定（见第 4 节），持有服务令牌不等于自动获得管理权限。
- 轮换客户端 secret 后旧 secret 立即失效；secret 只能存放在服务端受保护配置/密钥库，
  不得进入浏览器、移动端包体、日志、工单或示例仓库。

## 4. 权限联合校验

实现：`internal/tokenauthz`。业务资源服务在每次访问时调用一次判定，返回
`allow=false` + 稳定错误码（业务拒绝）或 error（依赖故障，业务必须默认拒绝）。

判定语义（全部满足才放行）：

1. 访问凭证有效：类型/签名/签发方/有效期/audience/撤销状态；
2. 可信资源服务：`application_id` 与 `audience` 来自可信边界，令牌的 client_id 必须
   映射到同一应用，且该客户端登记 audience 仍包含资源 audience；
3. 主体可用：用户禁用优先拒绝；应用成员关系与应用启用状态当前有效；
4. 权限交集：令牌 scope ∩ 当前有效权限（角色/组/委派实时计算，不缓存），支持
   all/any 组合；空权限要求按参数错误拒绝，不因业务漏配而放行；
5. 数据范围（可选 `resource_id`）：按已配置数据范围交集判定；**资源归属与对象状态
   必须由业务服务另行校验**，不能用一个功能权限代替归属检查；
6. 失败审计：拒绝写失败审计；审计不可用不改变拒绝结果。

错误码（与根包注册表一致）：`TOKEN_INVALID`、`TOKEN_EXPIRED`、`TOKEN_REVOKED`、
`TOKEN_AUDIENCE_MISMATCH`、`CLIENT_DISABLED`、`USER_DISABLED`、
`APP_MEMBERSHIP_REQUIRED`、`PERMISSION_REQUIRED`、`PERMISSION_DISABLED`、
`PERMISSION_UNKNOWN`、`APP_SCOPE_MISMATCH`、`RESOURCE_FORBIDDEN`、
`AUTHZ_UNAVAILABLE` 等。依赖不可用必须按 503 语义处理，不得降级放行。

## 5. 设备码接入契约（RFC 8628）

实现：`internal/oauthflow`（申请/确认/轮询/取消）+ `internal/protocolapi`（HTTP 端点）+
内置确认页（`/oauth/device`、`/oauth/device/confirm`）。协议端点默认关闭，必须同时满足
`protocol.enabled=true` 与 `protocol.device_code_enabled=true`；只有启用时 Discovery 才
声明 `device_authorization_endpoint` 与 `device_code` grant_type，未启用时端点 404。

**HTTP 端点**：

| 端点 | 用途 |
|---|---|
| `POST /oauth/device_authorization` | 设备授权申请（公开客户端只带 `client_id`；保密客户端必须完成客户端认证） |
| `POST /oauth/device/cancel` | 发起端取消等待中的请求（本服务扩展；必须绑定申请时的同一客户端） |
| `POST /oauth/token`（`grant_type=urn:ietf:params:oauth:grant-type:device_code`） | 设备端轮询领取令牌 |
| `GET/POST /oauth/device` | 用户确认入口页（输入短码，需真实登录会话） |
| `GET/POST /oauth/device/confirm` | 确认页展示应用/请求范围并批准或拒绝 |

**协议流程与安全要求**：

1. **设备授权申请**：设备端用 `client_id`（保密客户端另需认证）提交 `scope`/`resource`。
   成功返回 `device_code`（高熵，设备端保存，不展示）、`user_code`（短码，展示给用户）、
   `verification_uri`、`verification_uri_complete`（只含短码，可渲染二维码）、
   `expires_in`、`interval`。公开客户端不得携带任何 secret。
2. **用户确认**：用户在已登录页面输入短码，服务端重新规范化定位请求；页面向用户展示
   **正确的应用名称/应用标识与请求范围**（scope 中文说明），用户显式批准或拒绝；确认页
   需要真实用户会话与近期认证，失败 fail-closed。
3. **设备轮询**：设备端用 `device_code` 轮询；未确认返回 `authorization_pending`；轮询过快
   返回 `slow_down`（服务端强制间隔并递增，响应带 `Retry-After`）；用户拒绝/发起端取消
   返回 `access_denied`；设备码过期返回 `expired_token`；设备码不存在、被其他客户端提交、
   已领取/重放返回 `invalid_grant`（不泄露归属）。
4. **Token 签发**：批准后**一次性**兑换，重复兑换返回 `invalid_grant`；同一设备码只能由
   申请时的原客户端领取。默认签发 Access Token；仅当客户端登记 `refresh_token` 且授权含
   `offline_access` 时签发 Refresh Token。设备码流程**不签发 ID Token**：`openid` scope 在
   设备授权阶段被拒绝（本服务未定义设备流 ID Token 语义），需要 OIDC 登录请用授权码流程。
   令牌只返回给原设备端，二维码/短码中**不含**任何长期 Token。
5. **安全要求**：短码低熵，服务端只保存带密钥的 HMAC 摘要（不存明文、不用无密钥摘要）；
   短码尝试有频率限制；设备码与短码都限时；取消/过期后原码立即失效；确认页不允许匿名
   批准，也不允许别的客户端替用户完成确认。

步骤 192 已用真实公开客户端与真实 HTTP 回环服务验证上述边界（pending、slow_down、
确认页应用/范围展示、批准领取、重复兑换、错误客户端、用户拒绝、过期、取消、Discovery
一致性），记录见 `docs/acceptance/step192-device-code.md`。

## 6. 扫码登录接入契约（业务 APP 扫网页二维码）

实现：`internal/qrlogin`（领域服务）+ `internal/protocolapi`（HTTP 端点与页面）+ 内置
页面。默认关闭：需 `app_qr_login.enabled=true` 且白名单应用存在并 active，否则页面与
端点返回受控“未启用”。示例：`examples/app-qr-login`（本模块内可运行，进程内完整闭环）。

**HTTP 端点**：

| 端点 | 用途 |
|---|---|
| `POST /oauth/qr/request` | 匿名发起端创建短时请求；一次性返回 `request_id`、`qr_payload`、`claim_secret` |
| `POST /oauth/qr/status` | 原发起端查询状态（`request_id` + `claim_secret`） |
| `POST /oauth/qr/claim` | 原发起端领取（`request_id` + `claim_secret`），一次性 |
| `POST /oauth/qr/cancel` / `POST /oauth/qr/regenerate` | 原发起端取消 / 重新生成（旧请求失效） |
| `GET /oauth/qr/prompt?request_id=` | 已登录 APP 读取受控确认上下文（真实完整会话） |
| `POST /oauth/qr/decision` | 已登录 APP 批准/拒绝（真实完整会话 + `expected_version`） |
| 页面 `/login/qr`、`/app/scan` | 发起端网页与 APP 确认页（内置模板，可替换） |

**合法调用方式与 403 排障（不关闭任何校验）**：

- 确认端（APP）必须使用**真实完整会话**访问 `/oauth/qr/prompt` 与 `/oauth/qr/decision`。
- 使用会话秘密作为 `Authorization: Bearer` 时属于非浏览器环境，服务器不要求 CSRF 头，
  但状态修改请求**必须携带同源 `Origin`/`Referer`**；使用浏览器 Cookie 会话时必须额外
  提交会话绑定的 CSRF 令牌（内置页面已由服务端渲染隐藏字段并绑定会话）。
- 协议直连返回 403 的常见原因：缺同源 `Origin`/`Referer`、Cookie 会话缺 CSRF、会话
  过期/不完整、APP 会话的应用范围与该扫码请求的目标应用不匹配。正确做法是补齐合法
  凭证与同源头，**不是关闭 CSRF/同源/再认证校验**。
- 领取必须使用创建响应中的 `claim_secret`；只凭二维码里的 `request_id` 不能领取，其他
  网页/其他端即使知道 `request_id` 也无法抢领。
- 页面 POST 的 CSRF/Origin 由宿主传输层统一校验；协议直连与页面路径共用同一服务语义。

**流程与安全要求**：

1. **发起端（网页）**：`Begin` 创建短时请求，拿到请求标识与**一次性领取绑定**
   （claim secret）。二维码只承载一次性请求标识，**绝不承载领取绑定或任何 Token**。
2. **确认端（APP）**：用真实普通会话读取请求描述（应用名称/标识、请求范围、发起端
   信息、风险提示），展示给用户核对后批准/拒绝；批准属于敏感操作，要求近期认证。
3. **领取**：发起端用请求标识 + 领取绑定轮询/领取；批准后原子消费批准（并发单赢家），
   并通过受门控登录批准签发**目标应用会话**——**不签发 OAuth Token**。
4. **安全要求**：二维码请求短时有效、限频；确认前必须显示正确应用与范围；确认后只允许
   绑定原发起端领取；已领取/过期/取消/拒绝后不可重放；不能把该流程变成任意应用换取用户
   Token 的通道。钓鱼风险需在部署侧配合文案提醒，无法完全消除。

步骤 193 已用两个独立会话（匿名发起端网页 + 已登录 APP 确认端）经真实内置网页与真实
HTTP 服务验证确认展示、批准/拒绝、原网页领取、重复确认/领取、错误领取绑定、其他网页
抢领、过期与取消语义，记录见 `docs/acceptance/step193-qr-login.md`。

## 7. 示例凭证与密钥生成方式

| 材料 | 生成与保存 |
|---|---|
| 应用 client secret | 由服务端安全随机生成并只存服务端（哈希/加密存储由实现决定）；部署时通过受保护配置注入业务服务，禁止写入前端、示例或日志 |
| 主密钥/密钥环 | 由首次初始化命令 `login-server init --master-key-file <受保护路径>` 生成（文件不存在时自动生成受保护密钥环，只打印路径、不打印密钥材料；已有文件时加载校验），也可由宿主嵌入模式在首次装配时生成后写入受保护文件；必须与数据库、备份分开保存，非 Windows 要求仅所有者可读写；丢失即无法解密相关数据/备份，不可恢复 |
| TLS 证书/私钥 | 生产使用企业 CA/公开 CA 签发；测试可用自签证书但只能用于隔离测试，不能作为生产示例 |
| 示例中的临时密钥 | `examples/*` 使用临时 SQLite 与临时密钥环，仅演示语义，程序退出即丢弃；不得复制到生产 |

## 8. Token 保存边界（务必遵守）

| 位置 | 允许 | 禁止 |
|---|---|---|
| 浏览器 | 服务端会话 Cookie（HttpOnly/Secure/SameSite），不把令牌放进 URL | localStorage/sessionStorage 保存长期 Token、把 Token 放进查询串、日志或埋点 |
| 业务服务端 | 内存中使用；需要持久化时加密存储并控制访问 | 明文写磁盘、写入工单/聊天/截图、跨环境共享 |
| 日志/审计/报告 | 记录请求编号、主体、结果、错误码等脱敏字段 | 记录 Access/ID/Refresh Token、一次性凭证、密码、MFA 秘密、二维码领取绑定 |
| 示例程序 | 只在进程内使用，不写文件、不打印明文 | 把示例输出当生产配置、把令牌粘贴到文档/提交记录 |

## 9. 示例运行方式与预期

```bash
# 在仓库根目录
go run ./examples/oidc-login        # 真实回环 HTTP 服务的 OIDC 外部客户端：授权码+PKCE → Token → UserInfo + 拒绝用例
go run ./examples/service-identity  # client credentials 服务身份 + 权限联合校验（含拒绝用例）
go run ./examples/app-qr-login      # 已有：APP 扫网页二维码确认登录闭环
```

每个示例都使用临时 SQLite（退出自动清理）与真实服务，不联网、不写仓库；失败时以非零
退出码结束并打印原因。`examples/oidc-login` 为了演示完整协议流程，会在 `127.0.0.1` 的
**随机端口**启动一个真实 HTTP 服务（退出即关闭并删除临时库）：服务端部分只是示例夹具，
业务应用照它的客户端部分（Discovery、PKCE、令牌兑换、JWKS 验签、UserInfo）用标准库
实现即可，不需要 import 本模块 `internal/` 包。其余示例不监听端口。

## 10. 未实现/未验证

- OAuth/OIDC 协议端点与管理 JSON API 已装配但默认关闭（`protocol.enabled`/
  `--enable-protocol`、`--enable-admin-api`、`--enable-managed-api`、`--enable-app-support`）；
  设备码与扫码登录已按步骤 192/193 验收其已实现边界；令牌状态查询（introspection）已实现（145/160 验收边界；默认关闭；mTLS/故障等未实测）；
  内置 14 个页面选项（默认 12、条件 2）。真实第三方 OIDC 客户端、移动端相机扫码、
  真实浏览器联调未实测。
- 刷新令牌重放、撤销、密钥轮换的跨进程/并发压力未实测；`internal/*` 未公开包装，外部
  宿主无法直接导入。
- 示例中的宿主边界适配器（如授权判定、近期认证信号）用于演示；生产必须接入真实实现，
  不能把示例适配器当作安全默认。

## 11. 从根 README 迁移的接入速查（步骤 244 阶段 A）

> 本节原文迁移自根 `README.md` §6（HTTP API 与 OAuth2/OIDC 接入），保证信息不丢失；根
> README 将在步骤 244 阶段 B 收敛为入口页。相对链接已按本文件位置调整。协议契约细节仍以
> 本文第 1～10 节为准。

### 11.1 启用协议端点（原 README §6.1）

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

### 11.2 OAuth/OIDC 端点（原 README §6.2）

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

注意：设备码与扫码登录已按步骤 192/193 验收其已实现边界；令牌状态查询（introspection）
已实现（145/160 验收边界；默认关闭；mTLS/故障等未实测）。默认关闭；Discovery 只声明实际
能力。真实第三方客户端互操作、标准 OIDC 客户端联调未完成，不能按“已全部交付”对待。详见
[../guide/login-and-oauth.md](../guide/login-and-oauth.md)。

### 11.3 注册应用与获取客户端（原 README §6.3）

使用管理后台 `/admin/applications`（或对应管理 API）创建应用，填写名称、客户端类型
（public/confidential）、回调地址、允许的 grant/scope/audience，然后登记客户端凭证。应用
创建后默认停用，需要启用后再接入。

`curl` 检查 Discovery（先把 `<issuer>` 换成实际地址）：

```bash
curl -s https://login.example.com/.well-known/openid-configuration | jq
curl -s https://login.example.com/jwks | jq
```

完整参数、PKCE、刷新轮换、撤销、audience/scope 规则见本文第 2～9 节。

### 11.4 管理/托管/客服 API（原 README §6.4）

- 管理 API：`/admin/v1`，启用 `--enable-admin-api`，使用管理会话/CSRF；适合运维自动化，
  不应暴露给业务应用。
- 托管 API：`/api/managed/v1`，启用 `--enable-managed-api`；只允许应用在受限操作/对象/字段
  白名单内管理自己的资源，默认关闭。
- 应用客服 API：`/api/app/v1/support`，启用 `--enable-app-support`，只允许应用客服用户创建
  本应用工单，不能审批或执行恢复。

OpenAPI 当前只包含最小健康/错误契约，不是完整业务 API 文档；业务接口以
[managed-api.md](managed-api.md)、[app-support-api.md](app-support-api.md) 和源码公开
契约为准。

