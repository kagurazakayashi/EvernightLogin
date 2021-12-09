# 业务接入契约

本文面向接入 login 的业务应用，说明当前可用的接入形态、四类认证/授权契约、示例凭证
生成方式与 Token 保存边界。HTTP 路由尚未暴露的部分会明确标注，不要按“已上线的接口”
对接。

## 1. 接入形态与当前状态

| 接入方式 | 状态 | 说明 |
|---|---|---|
| 嵌入模式（宿主 Go 进程装配 `login.Instance`） | 已实现（Go API） | 宿主自行持有数据库、会话、页面与 HTTP 服务；本模块不监听端口、不建全局实例 |
| 独立服务进程（`login-server serve`）基础 HTTP 能力 | 已实现（MVP） | 健康检查、OpenAPI 文档与内置账户入口页；配置/迁移/密钥/审计/维护门禁/单实例锁/TLS/访问日志轮转/后台任务运行时/协议与管理 API 挂载点/优雅关闭已装配 |
| 独立服务 HTTP 端点（OAuth/OIDC/设备码/扫码/管理 API） | **未实现** | 目前只有健康检查、OpenAPI 与内嵌页面路由；协议实现是受信 Go API，未暴露 HTTP 路由 |
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
| `resource` | 可选的 audience 列表，必须属于客户端登记 audience；audience 是目标资源，不等于 client_id |
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
- UserInfo：Access Token 的 scope 必须包含 `openid` 且覆盖 `profile`/`email`；
  返回资料按 scope 裁剪，邮箱只在已验证时出现。
- JWKS 轮换：验证端应按 `kid` 缓存公钥；旧密钥在保留期内仍可验证既有令牌，保留期后
  验证拒绝。

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

实现：`internal/oauthflow`（设备授权申请/确认/轮询/取消）。HTTP 端点**未暴露**；下面是
协议契约，供页面/装配完成后对接，当前仅能通过受信 Go API 调用。

1. **设备授权申请**：设备端用 `client_id`（保密客户端另需认证）提交 `scope`/`resource`。
   成功返回 `device_code`（高熵，设备端保存，不展示）、`user_code`（短码，展示给用户）、
   `verification_uri`、`verification_uri_complete`（只含短码，可渲染二维码）、
   `expires_in`、`interval`。
2. **用户确认**：用户在已登录页面输入短码，服务端重新规范化定位请求；页面必须展示
   **正确的应用与请求范围**，用户显式批准或拒绝；确认页需要真实用户会话与近期认证。
3. **设备轮询**：设备端用 `device_code` 轮询；未确认返回 `authorization_pending`，
   轮询过快返回 `slow_down`（并按协议增大间隔），过期/取消返回标准错误；只能由申请时
   的同一客户端领取。
4. **Token 签发**：批准后一次性兑换 Access/ID/Refresh Token（按客户端登记与 scope）；
   令牌只返回给原设备端，二维码/短码中**不含**任何长期 Token。
5. **安全要求**：短码低熵，服务端只保存带密钥的 HMAC 摘要（不存明文、不用无密钥摘要）；
   短码尝试有频率限制；设备码与短码都限时；取消/过期后原码立即失效。

## 6. 扫码登录接入契约（业务 APP 扫网页二维码）

实现：`internal/qrlogin`。示例：`examples/app-qr-login`（本模块内可运行）。

1. **发起端（网页）**：调用 `Begin` 创建短时请求，拿到请求标识与**一次性领取绑定**
   （claim secret）。二维码只承载一次性请求标识，**绝不承载领取绑定或任何 Token**。
2. **确认端（APP）**：用真实普通会话读取请求描述（应用、范围、发起端信息），展示给
   用户核对后批准/拒绝；批准属于敏感操作，要求近期认证。
3. **领取**：发起端用请求标识 + 领取绑定轮询/领取；批准后原子消费批准（并发单赢家），
   并通过受门控登录批准签发**目标应用会话**——**不签发 OAuth Token**。
4. **安全要求**：二维码请求短时有效、限频；确认前必须显示正确应用与范围；确认后只允许
   绑定原发起端领取；已领取/过期/取消后不可重放；不能把该流程变成任意应用换取用户
   Token 的通道。钓鱼风险需在部署侧配合文案提醒，无法完全消除。

## 7. 示例凭证与密钥生成方式

| 材料 | 生成与保存 |
|---|---|
| 应用 client secret | 由服务端安全随机生成并只存服务端（哈希/加密存储由实现决定）；部署时通过受保护配置注入业务服务，禁止写入前端、示例或日志 |
| 主密钥/密钥环 | 由受控本地管理流程生成，写入受限权限文件（非 Windows 仅所有者可读写），与数据库、备份分开保存；丢失即无法解密相关数据/备份 |
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
go run ./examples/oidc-login        # OIDC 发现、授权请求契约、ID Token/UserInfo 校验与负例
go run ./examples/service-identity  # client credentials 服务身份 + 权限联合校验（含拒绝用例）
go run ./examples/app-qr-login      # 已有：APP 扫网页二维码确认登录闭环
```

每个示例都使用临时 SQLite（退出自动清理）、确定性时钟与真实服务，不监听端口、不联网、
不写仓库；失败时以非零退出码结束并打印原因。

## 10. 未实现/未验证

- OAuth/OIDC 协议端点与管理 JSON API 已装配但默认关闭（`protocol.enabled`/
  `--enable-protocol`、`--enable-admin-api`）；设备码、扫码登录、令牌状态查询未启用；
  内置 14 个页面选项（默认 12、条件 2）。真实第三方 OIDC 客户端、移动端相机扫码、
  真实浏览器联调未实测。
- 刷新令牌重放、撤销、密钥轮换的跨进程/并发压力未实测；`internal/*` 未公开包装，外部
  宿主无法直接导入。
- 示例中的宿主边界适配器（如授权判定、近期认证信号）用于演示；生产必须接入真实实现，
  不能把示例适配器当作安全默认。
