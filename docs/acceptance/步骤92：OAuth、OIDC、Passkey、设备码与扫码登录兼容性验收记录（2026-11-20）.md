# 步骤92：OAuth、OIDC、Passkey、设备码与扫码登录兼容性验收记录（2026-11-20）

本记录只覆盖步骤 92 约定的验收范围：OAuth 2.0 / OIDC、Passkey（WebAuthn）、设备码授权、
APP 扫码登录的协议语义、错误处理与跨层授权联合校验兼容性。不泛化为全项目验收，也不代替
步骤 93～96 的页面/浏览器、安全审查与最终交付验收。

- 记录日期：2026-11-20（Asia/Shanghai）
- 验收环境：Windows 11 amd64，Go 1.27.4 windows/amd64，`CGO_ENABLED=0`，`GOMAXPROCS=2`，`go test -p 1`（串行）
- 数据库：每个用例独立 `t.TempDir()` 临时 SQLite 文件，执行仓库全部 44 个迁移；不读取、不修改 `database/login.db`
- 验收方式：**测试进程内**使用真实服务（真实 SQLite 迁移、真实令牌/会话/权限/审计服务）与真实
  `net/http` 端点（`httptest.NewServer`）；**非部署后独立服务实测**。`cmd/login-server` 当前没有
  OAuth/OIDC/设备码/扫码 HTTP 路由装配，标准客户端/浏览器/真机维度如实标为未测（见第 7 节）
- 证据代码（本步新增，仅测试文件，无产品代码改动）：
  - `internal/oauthflow/step92_acceptance_test.go`（3 个验收用例 + 8 个子用例）
  - `internal/qrlogin/step92_acceptance_test.go`（1 个验收用例）
  - `internal/tokenauthz/step92_acceptance_test.go`（4 个验收用例，含真实 HTTP 端点与 curl 标准客户端）
  - 既有协议测试套件（本步串行复跑）：`internal/oauthflow`、`internal/oidc`、`internal/qrlogin`、
    `internal/passkey`、`internal/tokenauthz`、`internal/token`、`internal/oauthclient`
  - 可运行接入示例：`examples/oidc-login`、`examples/service-identity`、`examples/app-qr-login`（`go run` EXIT=0）

## 1. 结论

- 步骤 92 约定范围内、**在当前可验收维度（测试进程内真实服务/真实 HTTP Handler/软件认证器）**下：
  **协议语义与负向错误处理全部通过；验收矩阵 77 行中 PASS 72、PARTIAL 0、FAIL 0、NOT_TESTED 5**
  （NOT_TESTED 均为外部互操作维度：部署后 HTTP 端点、标准 OAuth/OIDC 客户端/浏览器、真实认证器、
  真实手机 APP、真实 mTLS 客户端证书链路）。
- 未发现需要在步骤 92 内做"必要小修"的协议缺陷；**本步没有改动任何产品代码、迁移、错误码或依赖**，
  只新增 3 个验收测试文件与验收记录。唯一观察到的行为差异：Access Token（长 JWT）冒充授权码时由
  参数长度校验先返回 `invalid_request`（而不是 `invalid_grant`），属安全拒绝且符合标准错误字段，记录为
  非缺陷观察（见第 9 节）。
- **不宣称官方认证/合规认证**：未运行 OIDC 认证套件（如 OpenID Connect Conformance Suite）、
  FIDO Alliance 认证测试或 W3C WebAuthn 正式测试，本记录只证明项目自身协议语义与负向处理。
- 未通过"部署后服务 + 标准客户端 + 真机"完成跨设备互操作验收，该部分阻塞于独立服务 HTTP 装配缺失，
  是步骤 92 的明确未测项而非本步可修复范围。

## 2. 环境与资源边界

- 操作系统/架构：Windows 11，amd64；Go 1.27.4 windows/amd64。
- 构建/测试：`CGO_ENABLED=0`、`GOMAXPROCS=2`、`-p 1`、`-timeout 600s`；串行执行，未并发重活。
- 数据隔离：每个用例 `t.TempDir()` 临时目录 + 独立 SQLite 文件，执行全部 44 个迁移；用例结束由测试
  框架回收；未读写 `database/login.db`、未写仓库内运行时文件。
- 网络/端口：仅 `httptest.NewServer` 绑定 `127.0.0.1` 随机端口，用例内关闭；不访问外网、不启动常驻
  服务、不做真实邮件/Webhook 外发（本步未使用 SMTP 链路）。
- 禁止项遵守：未执行任何 Git 写操作；未修改步骤 84 的未提交 partial 文件
  （`README.md`、`doc.go`、`cmd/loginctl/loginctl.go`、`config_diag.go`、`internal/managecli/`）；
  未新增依赖（`go.mod`/`go.sum` 未变）；未碰 `database/login.db`。
- 临时产物：仅 Go 测试缓存内编译产物，仓库无 exe/日志/临时库；证据文本在验收记录与报告中摘要。

## 3. 验证维度定义（本记录统一口径）

| 维度 | 定义 | 本步实际执行 |
|---|---|---|
| 测试模拟器/进程内 | 测试进程内真实产品服务 + 真实 SQLite 迁移 + `httptest`/软件 ECDSA 认证器/标准 JOSE 库 | 是（主要证据） |
| 标准客户端 | 独立于被测服务的客户端实现：本机 `curl` CLI、Go 标准 `net/http` 客户端、第三方 JOSE 库 | 部分：curl 8.22.0 与 `net/http` 对真实 HTTP Handler PASS；真实浏览器/OAuth 客户端未测（无部署端点） |
| 真实设备 | 真实硬件/系统认证器（YubiKey、Windows Hello、平台 Passkey）、真实手机 APP、真实浏览器 | 未测（无硬件/无部署服务，如实标注，不冒充通过） |

## 4. 能力与验证矩阵

说明：需求 ID 引用 `docs/requirements/login_功能列表_v1.1.md`（正文版本 1.2）章节；"维度"按第 3 节口径；
证据列给出测试函数名（均可 `go test -run` 复跑）或示例命令。前置环境均为"临时 SQLite + 44 迁移 + 真实服务"，
除非另注。

### 4.1 OAuth 2.0 授权码 + PKCE（§10）

| 需求ID | 场景 | 维度 | 步骤 | 预期 | 实际 | 证据 | 结果 | 问题 |
|---|---|---|---|---|---|---|---|---|
| §10 | 授权码 + PKCE S256 完整流程（RFC 7636 附录 B 向量），state 原样回传 | 模拟器 | 发起授权→确认→兑换→验证 Access Token | 返回 code+state；令牌 aud/scope/subject 正确 | 与预期一致 | `TestAuthorizationCodeHappyPath`、`TestStep92PKCEDowngradeAndReplay` | PASS | 无 |
| §10 | PKCE plain 降级拒绝 | 模拟器 | 授权请求 `code_challenge_method=plain` | 标准 OAuth 错误 `invalid_request`，不签发授权码 | 与预期一致 | `TestAuthorizationRequestValidation/PKCE_plain`、`TestStep92PKCEDowngradeAndReplay/禁止_PKCE_plain` | PASS | 无 |
| §10 | 缺少 PKCE 拒绝（公开客户端强制） | 模拟器 | 授权请求去掉 challenge | `invalid_request` | 与预期一致 | `TestAuthorizationRequestValidation/缺少_PKCE`、`TestStep92PKCEDowngradeAndReplay/禁止缺少_PKCE` | PASS | 无 |
| §10 | 错误 code_verifier 拒绝且不消费授权码 | 模拟器 | 兑换时使用错误 verifier | `invalid_grant`；授权码仍可正确兑换 | 与预期一致 | `TestTokenExchangeValidation`、`TestStep92PKCEDowngradeAndReplay/错误_verifier_不消费授权码` | PASS | 无 |
| §10 | 授权码重放/一次性消费 | 模拟器 | 同一授权码兑换两次 | 第二次 `invalid_grant`，记录重放时间戳，消费恰好 1 次 | 与预期一致 | `TestAuthorizationCodeHappyPath`、`TestStep92PKCEDowngradeAndReplay` | PASS | 无 |
| §10 | 并发兑换单赢家 | 模拟器 | 4 并发兑换同一授权码 | 仅 1 成功，其余 `invalid_grant`，消费 1 次 | 与预期一致 | `TestExchangeConcurrentSingleWinner` | PASS | 无 |
| §10 | 未登记 redirect_uri / 兑换时替换回调 | 模拟器 | 请求未登记回调；兑换时换回调 | 发起阶段 `invalid_request` 且不重定向；兑换 `invalid_grant` | 与预期一致 | `TestAuthorizationRequestValidation/未登记回调`、`TestTokenExchangeValidation` | PASS | 无 |
| §10 | 跨客户端兑换拒绝 | 模拟器 | 用另一已登记客户端兑换授权码 | `invalid_grant` | 与预期一致 | `TestExchangeCrossClientAndClientState` | PASS | 无 |
| §10 | 过期授权码拒绝 | 模拟器 | 时钟推进超过授权码 TTL | `invalid_grant` | 与预期一致 | `TestExchangeExpiredCode` | PASS | 无 |
| §10 | 不支持隐式/密码授权 | 模拟器 | `response_type=token` / `password` | `unsupported_response_type` | 与预期一致 | `TestAuthorizationRequestValidation` | PASS | 无 |
| §10 | 拒绝授权（取消） | 模拟器 | 确认阶段拒绝 | 重定向 `error=access_denied` + state；不签发授权码 | 与预期一致 | `TestAuthorizationDenied` | PASS | 无 |
| §10 | 会话失效后兑换/批准拒绝 | 模拟器 | 撤销会话后兑换或批准 | `invalid_grant` / `access_denied`；不消费授权码 | 与预期一致 | `TestExchangeSessionInvalidated`、`TestAuthorizationSessionAndReauth` | PASS | 无 |
| §10 | 保密客户端认证（client_secret_basic 契约） | 模拟器 | 缺少/错误 secret、证书身份兑换 | 缺少或错误 secret 拒绝；证书身份契约路径可兑换 | 与预期一致（客户端认证适配器按生产契约注入） | `TestConfidentialClientAuthentication` | PASS | 真实 mTLS 链路未测（见 7.2） |

### 4.2 OIDC（§10）

| 需求ID | 场景 | 维度 | 步骤 | 预期 | 实际 | 证据 | 结果 | 问题 |
|---|---|---|---|---|---|---|---|---|
| §10 | Discovery 只声明已实现能力 | 模拟器 | 读取 Discovery | 只声明授权码 + PKCE S256 + ES256 + pairwise；不声明未实现端点能力 | 与预期一致 | `TestDiscoveryDocumentOnlyImplemented` | PASS | 无 |
| §10 | ID Token iss/aud/exp/iat/auth_time/amr/acr 与 nonce 回传 | 模拟器 | 签发并验证 ID Token | 声明与真实认证事实一致；nonce 原样回传 | 与预期一致 | `TestIDTokenClaimsPairwiseAndInterop` | PASS | 无 |
| §10 | pairwise subject（同一用户对不同客户端 sub 不同、同客户端稳定） | 模拟器 | 两个客户端签发 ID Token | sub 不同且不等于真实用户 ID；同客户端稳定 | 与预期一致 | `TestIDTokenClaimsPairwiseAndInterop` | PASS | 无 |
| §10 | 独立 JOSE 客户端从 JWKS 验签（ES256）互操作 | 标准客户端库 | 取 JWKS→解析紧凑 JWS→独立验签→读取声明 | 签名验证通过，iss/aud/nonce/exp/iat/auth_time 一致 | 与预期一致（`go-jose` 独立解析，不依赖本方验证器） | `TestIDTokenClaimsPairwiseAndInterop` | PASS | 无 |
| §10 | UserInfo scope 裁剪（openid+email / openid+profile） | 模拟器 | 按 scope 调用 UserInfo | 只返回授权字段；`email_verified` 用真实验证状态；无邮箱不返回 | 与预期一致 | `TestUserInfoScopeTrimmingAndValidation` | PASS | 无 |
| §10 | UserInfo 负向：缺 openid、错误 audience、过期、类型错误 | 模拟器 | 构造非法 Access Token | 拒绝（无 openid scope / audience 不匹配 / 过期 / 类型错误） | 与预期一致 | `TestUserInfoScopeTrimmingAndValidation` | PASS | 无 |
| §10 | UserInfo 拒绝已撤销 Access Token | 模拟器 | 撤销后调用 UserInfo | 拒绝 | 与预期一致 | `TestUserInfoRejectsRevokedAccessToken` | PASS | 无 |
| §10 | ID Token 冒充 Access Token（OIDC 服务层） | 模拟器 | 以 ID Token 调 UserInfo | 拒绝 | 与预期一致 | `TestUserInfoScopeTrimmingAndValidation` | PASS | 无 |
| §10 | ID Token 冒充 Access Token（联合判定服务层与 HTTP 层） | 模拟器/标准 HTTP | 以 ID Token 调联合判定 | `TOKEN_INVALID` 拒绝 | 与预期一致 | `TestIntegrationIDTokenAndSessionSecretRejected`、`TestStep92HTTPTokenTypeConfusion` | PASS | 无 |

### 4.3 Refresh Token 轮换、重放与撤销（§10、§9）

| 需求ID | 场景 | 维度 | 步骤 | 预期 | 实际 | 证据 | 结果 | 问题 |
|---|---|---|---|---|---|---|---|---|
| §10 | Refresh 轮换返回新令牌 | 模拟器 | 用刷新令牌轮换 | 旧令牌 used、新令牌 active；库只存摘要 | 与预期一致 | `TestRefreshTokenRotationAndReplay`、`TestStep92TokenKindMixups` | PASS | 无 |
| §10 | 旧刷新令牌重放 → 撤销整族 | 模拟器 | 重放已用刷新令牌 | `invalid_grant`；族撤销；新令牌同时失效；写重放审计 | 与预期一致 | `TestRefreshTokenRotationAndReplay`、`TestStep92TokenKindMixups` | PASS | 无 |
| §10 | 并发刷新单赢家（无宽限期掩盖重放） | 模拟器 | 并发轮换同一刷新令牌 | 仅 1 成功；失败按重放处理 | 与预期一致 | `TestRefreshConcurrentSingleWinner` | PASS | 无 |
| §10 | 刷新时 scope 扩张/客户端不匹配拒绝 | 模拟器 | 刷新请求扩大 scope、换客户端 | 拒绝 | 与预期一致 | `TestRefreshScopeExpansionAndClientMismatch` | PASS | 无 |
| §10 | 服务身份令牌不能用于刷新 | 模拟器 | 以 client_credentials 令牌刷新 | 拒绝 | 与预期一致 | `TestRefreshServiceTokenRejected` | PASS | 无 |
| §10 | 刷新空闲过期、用户停用、事务故障拒绝 | 模拟器 | 时钟推进/停用用户/注入事务失败 | 分别拒绝且不丢失真实状态 | 与预期一致 | `TestRefreshIdleExpiry`、`TestRefreshUserDisabled`、`TestRefreshTransactionFailureKeepsToken` | PASS | 无 |
| §10 | Access/Refresh Token 与授权码类型混用 | 模拟器 | Access Token 当刷新令牌/授权码，Refresh Token 当授权码 | 全部拒绝（`invalid_grant`，长 JWT 命中有界参数校验时 `invalid_request`） | 与预期一致 | `TestStep92TokenKindMixups` | PASS | 非缺陷观察见第 9 节 |
| §10 | 撤回后 Access Token 失效、撤销与状态查询 | 模拟器 | 撤销 Access/Refresh Token、查询状态 | 撤销后验证/UserInfo/联合判定拒绝；错误 hint 被忽略；状态查询隐私裁剪 | 与预期一致 | `TestRevokeTokenEndpoint`、`TestRevokeAccessTokenAndInspection`、`TestRevokeRefreshInvalidatesAccessTokensAndIgnoresWrongHint` | PASS | 无 |
| §10 | 跨用户撤销拒绝、logout scopes、安全事件撤销 | 模拟器 | 越权撤销他人令牌；按 scope 退出；安全事件触发撤销 | 拒绝越权；按范围撤销；记录审计/outbox | 与预期一致 | `TestLogoutCrossUserDenied`、`TestLogoutScopes`、`TestSecurityEventRevocationAndOutbox` | PASS | 无 |

### 4.4 Client Credentials 服务身份（§10）

| 需求ID | 场景 | 维度 | 步骤 | 预期 | 实际 | 证据 | 结果 | 问题 |
|---|---|---|---|---|---|---|---|---|
| §10 | 服务身份签发 Access Token（subject_type=service） | 模拟器 | 客户端凭证流程 | 签发成功；主体为服务客户端；与用户令牌可区分 | 与预期一致 | `TestClientCredentialsServiceToken`、`TestServiceAndUserTokensDistinct` | PASS | 无 |
| §10 | 服务身份拒绝场景 | 模拟器 | 用户调用者/未授权 scope/未登记客户端类型 | 拒绝（默认拒绝，无隐式放行） | 与预期一致 | `TestClientCredentialsRejections` | PASS | 无 |
| §10 | scope 收窄与密钥轮换 | 模拟器 | 申请收窄 scope；轮换签名密钥后旧令牌行为 | scope 按交集收窄；密钥过渡期语义正确 | 与预期一致 | `TestClientCredentialsScopeNarrowingAndRotation` | PASS | 无 |

### 4.5 设备码授权（§6.1）

| 需求ID | 场景 | 维度 | 步骤 | 预期 | 实际 | 证据 | 结果 | 问题 |
|---|---|---|---|---|---|---|---|---|
| §6.1 | 设备码完整流程（申请→另一会话确认→领取） | 模拟器 | 申请、确认、轮询兑换 | 返回验证地址/短码（XXXX-XXXX）；领取令牌 subject/client 正确；一次性 | 与预期一致 | `TestDeviceAuthorizationFullFlow` | PASS | 无 |
| §6.1 | 轮询 pending / slow_down | 模拟器 | 未确认时轮询；过快轮询 | `authorization_pending`；过快 `slow_down` | 与预期一致 | `TestDeviceAuthorizationPendingAndSlowDown`、`TestStep92DeviceCodeMixupsAndPolling` | PASS | 无 |
| §6.1 | 设备码过期 | 模拟器 | 时钟推进超过有效期 | `expired_token` | 与预期一致 | `TestDeviceAuthorizationExpired`、`TestStep92DeviceCodeMixupsAndPolling` | PASS | 无 |
| §6.1 | 拒绝与取消 | 模拟器 | 用户拒绝；发起端取消 | 标准错误 `access_denied`；取消后不可领取 | 与预期一致 | `TestDeviceAuthorizationDenyAndCancel` | PASS | 无 |
| §6.1 | 客户端替换/确认前状态变化/并发领取 | 模拟器 | 换 client_id 领取、确认后配置变化、并发轮询 | 拒绝或不一致状态不放行；并发仅 1 赢家 | 与预期一致 | `TestDeviceAuthorizationClientSubstitution`、`TestDeviceAuthorizationStateChangedBeforeClaim`、`TestDeviceAuthorizationConcurrentClaim` | PASS | 无 |
| §6.1 | 短码猜码限流、短码摘要不存明文、密钥环轮换 | 模拟器 | 大量错误短码；检查库；轮换密钥环 | 限流生效；库中为 keyed HMAC 摘要；旧码在轮换后可识别/拒绝 | 与预期一致 | `TestDeviceAuthorizationUserCodeGuessRateLimited`、`TestDeviceUserCodeDigestKeyed`、`TestDeviceUserCodeKeyringRotation` | PASS | 无 |
| §6.1 | 授权码与设备码不能互用 | 模拟器 | 设备码当授权码、授权码当设备码 | 均拒绝；原授权码仍可用 | 与预期一致 | `TestStep92DeviceCodeMixupsAndPolling/授权码与设备码不能互用` | PASS | 无 |

### 4.6 APP 扫码登录（§6.2）

| 需求ID | 场景 | 维度 | 步骤 | 预期 | 实际 | 证据 | 结果 | 问题 |
|---|---|---|---|---|---|---|---|---|
| §6.2 | 创建请求→确认页→批准→发起端领取 | 模拟器 | 完整扫码流程 | 确认页显示应用/请求范围/发起端信息；领取会话 kind=normal；审计完整且不含领取绑定明文 | 与预期一致 | `TestApproveAndClaimFlow` | PASS | 无 |
| §6.2 | 跨用户确认与领取主体绑定 | 模拟器 | 用户B确认用户A发起网页的请求 | 领取会话主体=确认者B（不混淆发起网页）；重复领取拒绝 | 与预期一致 | `TestStep92QRAcrossUserAndSingleClaim` | PASS | 无 |
| §6.2 | 确认后被停用用户领取拒绝 | 模拟器 | 批准后停用确认用户再领取 | 不签发可用会话（领取时重检账户状态） | 与预期一致 | `TestStep92QRAcrossUserAndSingleClaim` | PASS | 无 |
| §6.2 | 一次性领取/错误绑定/复制二维码/跨请求替换 | 模拟器 | 无领取绑定、错误绑定、错误请求 ID 领取 | 全部拒绝（`ErrRequestNotFound`/`ErrAlreadyClaimed`） | 与预期一致 | `TestWrongEndAndCopiedQRCode`、`TestApproveAndClaimFlow` | PASS | 无 |
| §6.2 | 拒绝/取消/重新生成/过期 | 模拟器 | 各状态迁移 | 状态为 denied/cancelled/expired；旧码失效；新码可用 | 与预期一致 | `TestDenyCancelRegenerateExpiry` | PASS | 无 |
| §6.2 | 跨应用会话/受限会话/确认端会话撤销 | 模拟器 | 用其他应用会话确认；受限会话确认；批准后撤销确认端会话 | 全部拒绝 | 与预期一致 | `TestConfirmSessionScopeAndRevocation` | PASS | 无 |
| §6.2 | 并发批准/领取单赢家 | 模拟器 | 4 并发批准、4 并发领取 | 各仅 1 成功；会话总数正确 | 与预期一致 | `TestConcurrentApproveAndClaim` | PASS | 无 |
| §6.2 | 全局会话确认、领取时重检客户端状态、必填再认证/停用 | 模拟器 | 全局会话确认；确认后再停用应用；再认证策略 | 全局会话可确认；状态变化后领取拒绝；再认证/停用拒绝 | 与预期一致 | `TestGlobalSessionMayConfirm`、`TestClaimRechecksClientState`、`TestRequiredReauthAndDisabled` | PASS | 无 |

### 4.7 Passkey / WebAuthn（§5、§7.1）

| 需求ID | 场景 | 维度 | 步骤 | 预期 | 实际 | 证据 | 结果 | 问题 |
|---|---|---|---|---|---|---|---|---|
| §5 | 注册/登录/重命名/删除与近期再认证 | 模拟器（软件 ECDSA 认证器） | 完整 ceremony | 凭证模型统一；再认证失败 fail-closed | 与预期一致 | `TestRegisterListRenameAndReauth`、`TestReauthFailClosed` | PASS | 真实认证器未测 |
| §5 | 主登录直接完成会话、无机械第二步 | 模拟器 | 用户名登录 ceremony | 签发完整会话（强认证时间、方法记录） | 与预期一致 | `TestUsernameLoginIssuesCompleteSession` | PASS | 无 |
| §5 | 允许来源/RP ID/用户验证校验 | 模拟器 | 错误 origin、错误 RP ID、UV=false | 注册与登录均拒绝 | 与预期一致 | `TestRegistrationRejectsWrongOriginAndRPIDAndUV`、`TestWrongOriginLoginRejected`、`TestSecondFactorRequiresUserVerification` | PASS | 无 |
| §7.1 | allowCredentials 只含当前用途凭证（第二步不能含主登录凭证） | 模拟器 | 开始安全密钥第二步 | allowCredentials 恰为第二步凭证；跨挑战上下文拒绝 | 与预期一致 | `TestSecondFactorCeremonyAndPurposeEnforcement` | PASS | 无 |
| §5 | discoverable 登录与错误 userHandle | 模拟器 | 无用户名登录；错误用户句柄 | 正确凭证登录；错误 userHandle 拒绝 | 与预期一致 | `TestDiscoverableLoginAndWrongUserHandle` | PASS | 无 |
| §5 | 同步凭证计数器不递增可接受（backup eligible） | 模拟器 | 同步凭证断言计数器不递增 | 不以计数器零/不递增判克隆；更新状态 | 与预期一致 | `TestSyncedCredentialCounterMayNotIncrement` | PASS | 无 |
| §5 | 非同步凭证计数器回退 → 克隆拒绝 | 模拟器 | 模拟计数器不递增的非备份凭证 | 拒绝（`ErrCloneDetected`）并记审计 | 与预期一致 | `TestSyncedCredentialCounterMayNotIncrement`（`ErrCloneDetected` 分支） | PASS | 无 |
| §5 | 凭证用途/操作类型混淆、注册重放 | 模拟器 | 注册 challenge 重放、用途混用 | 拒绝 | 与预期一致 | `TestRegistrationReplayAndOperationConfusion` | PASS | 无 |
| §5 | 凭证冲突不能认领他人凭证 | 模拟器 | 他人 credential ID 冲突 | 拒绝 | 与预期一致 | `TestCredentialConflictCannotClaimAnotherUsersCredential` | PASS | 无 |
| §5 | ceremony 过期、配置校验 fail-closed | 模拟器 | 超时 ceremony；非法配置 | 拒绝构造/拒绝完成 | 与预期一致 | `TestCeremonyExpiry`、`TestConfigValidationFailsClosed` | PASS | 无 |
| §5 | 撤销最后登录方式/强因素保护、撤销使旧会话失效 | 模拟器 | 撤销最后一个 Passkey/强因素；撤销后旧会话 | 拒绝导致不可访问的撤销；旧会话失效 | 与预期一致 | `TestRevokeProtectsLastLoginMethod`、`TestRevokeProtectsLastStrongFactor`、`TestRevokeInvalidatesExistingSessions` | PASS | 无 |
| §7.1 | MFA 第二因素使用真实 passkey ceremony（软件模拟器） | 模拟器 | 密码结果→第二步安全密钥 | 完整会话 + 强认证时间 + 方法记录 | 与预期一致 | `TestMFASecurityKeySecondFactorWithRealPasskeyCeremony` | PASS | 非真机（明确标注） |
| §5 | 真实硬件/系统认证器（YubiKey、Windows Hello、平台 Passkey） | 真实设备 | 真机注册/登录 ceremony | 与真实浏览器/OS 认证器互操作 | **未执行**（无硬件认证器/无部署 HTTPS 服务） | — | NOT_TESTED | 见 7.2 |

### 4.8 令牌与权限联合校验（§9、§10、§11）

| 需求ID | 场景 | 维度 | 步骤 | 预期 | 实际 | 证据 | 结果 | 问题 |
|---|---|---|---|---|---|---|---|---|
| §9 | 真实 JWT + 真实 SQLite 权限允许 | 模拟器 | 真实令牌调联合判定 | allow=true，主体/应用正确 | 与预期一致 | `TestIntegrationRealTokenAndPermission` | PASS | 无 |
| §9 | **当前权限撤销后立即拒绝（服务级，无缓存窗口）** | 模拟器 | 删除角色权限组合后再判定 | deny + `PERMISSION_REQUIRED` | 与预期一致 | `TestIntegrationRealTokenAndPermission` | PASS | 无 |
| §9 | **当前权限撤销后立即拒绝（真实 HTTP 端点）** | 模拟器/标准 HTTP | 同上，经 `httptest` 真实 Handler | HTTP 200 + allow=false + `PERMISSION_REQUIRED` | 与预期一致 | `TestStep92HTTPJointAuthorization` | PASS | 无 |
| §9 | 跨应用令牌/同名权限隔离 | 模拟器 | 应用一令牌访问应用二资源；同名权限跨应用 | 拒绝（`APP_SCOPE_MISMATCH`/`PERMISSION_REQUIRED`/`TOKEN_AUDIENCE_MISMATCH` 之一） | 与预期一致 | `TestIntegrationSameNamePermissionIsolation`、`TestStep92HTTPJointAuthorization` | PASS | 无 |
| §9 | 成员关系/账户状态变化即时反映 | 模拟器 | 移除成员、停用账户后判定 | 拒绝（`APP_MEMBERSHIP_REQUIRED`/`USER_DISABLED`） | 与预期一致 | `TestIntegrationMembershipAndAccountState` | PASS | 无 |
| §9 | required_scopes 与令牌 scope 交集 | 模拟器/标准 HTTP | 令牌 scope 不足 | 拒绝（`ACCESS_DENIED`，reason `insufficient_scope`） | 与预期一致 | `TestRequiredScopeIntersection`、`TestStep92HTTPJointAuthorization` | PASS | 无 |
| §9 | 数据范围（resource）判定 | 模拟器 | 越出数据范围的资源 | 拒绝（`RESOURCE_FORBIDDEN`） | 与预期一致 | `TestIntegrationDataScopeResource` | PASS | 无 |
| §9 | 依赖故障默认拒绝 | 模拟器 | 数据库/撤销检查不可用 | `AUTHZ_UNAVAILABLE`，不放行 | 与预期一致 | `TestIntegrationDatabaseOutageDenies`、`TestDependencyUnavailable`、`examples/service-identity` | PASS | 无 |
| §9 | 在线撤销令牌后联合判定拒绝 | 模拟器/标准 HTTP | 撤销检查命中 | `TOKEN_REVOKED` | 与预期一致 | `TestRevokedTokenRejected`、`TestStep92HTTPRevokedToken` | PASS | 无 |
| §10 | 联合判定 HTTP 端点：调用者认证/方法/请求体上限/请求编号 | 模拟器 | 匿名、GET、超大/非法请求体、非法 request_id | 401/405/413/400 统一错误信封；合法 X-Request-ID 复用 | 与预期一致 | `TestHTTPCallerAuthentication`、`TestHTTPRejectsUnsupportedMethodAndBadBody`、`TestHTTPBodyLimit`、`TestHTTPRequestIDHandling` | PASS | 无 |
| §9 | curl CLI 作为独立标准 HTTP 客户端调用真实端点 | 标准客户端（curl 8.22.0） | curl POST 判定请求 | 返回 allow=true，主体/客户端正确 | 与预期一致 | `TestStep92CurlStandardClient` | PASS | 本机 curl 实测，仅 127.0.0.1 |
| §10 | 部署后 OAuth/OIDC/设备码/扫码 HTTP 端点 + 标准 OIDC 客户端/浏览器互操作 | 标准客户端 | 经真实部署服务跑 Discovery/token/UserInfo/device/QR | 标准客户端闭环 | **未执行**（`cmd/login-server` 无 HTTP 服务装配与这些路由） | — | NOT_TESTED | 见 7.1 |
| §5 | 真实浏览器 WebAuthn/来源与 RP ID 实测 | 真实设备 | 浏览器 + OS 认证器 | 真实来源/证书链下 ceremony | **未执行**（无部署 HTTPS 服务/未做浏览器实测） | — | NOT_TESTED | 见 7.2 |
| §6.2 | 真实手机 APP 扫码确认 | 真实设备 | 真机扫码→确认→网页领取 | 跨设备闭环 | **未执行**（无真实手机 APP/无部署页面） | — | NOT_TESTED | 见 7.2 |
| §10 | 真实 mTLS 客户端证书链路（保密客户端证书认证） | 真实设备/部署 | 客户端证书 TLS 握手→令牌端点 | 证书身份兑换令牌 | **未执行**（测试仅按生产契约注入客户端认证适配器；无部署 TLS 服务） | — | NOT_TESTED | 见 7.2 |

矩阵统计：**PASS 72、PARTIAL 0、FAIL 0、NOT_TESTED 5（共 77 行）**。

## 5. 负向用例汇总（step92.txt 要求逐项）

| 负向类别 | 用例/证据 | 结果 |
|---|---|---|
| 重放：授权码重复兑换 | `TestAuthorizationCodeHappyPath`、`TestStep92PKCEDowngradeAndReplay` | PASS（拒绝 + 重放标记 + 审计） |
| 重放：刷新令牌旧值重用 | `TestRefreshTokenRotationAndReplay`、`TestStep92TokenKindMixups` | PASS（撤销整族、新令牌同时失效） |
| 重放：设备码重复领取 | `TestDeviceAuthorizationFullFlow` | PASS（`invalid_grant`，不再签发） |
| 重放：扫码重复领取 | `TestApproveAndClaimFlow`、`TestStep92QRAcrossUserAndSingleClaim` | PASS（`ErrAlreadyClaimed`） |
| 重放：WebAuthn 注册/操作重放 | `TestRegistrationReplayAndOperationConfusion`、`TestCeremonyExpiry` | PASS |
| 类型混用：ID Token 冒充 Access Token | `TestUserInfoScopeTrimmingAndValidation`、`TestIntegrationIDTokenAndSessionSecretRejected`、`TestStep92HTTPTokenTypeConfusion` | PASS（`TOKEN_INVALID`） |
| 类型混用：会话秘密冒充 Access Token | `TestIntegrationIDTokenAndSessionSecretRejected` | PASS |
| 类型混用：授权码/设备码互用 | `TestStep92DeviceCodeMixupsAndPolling` | PASS |
| 类型混用：Access/Refresh/授权码互用 | `TestStep92TokenKindMixups` | PASS |
| 错误回调/redirect_uri | `TestAuthorizationRequestValidation`、`TestTokenExchangeValidation`、`TestExchangeRejectsRedirectRemovedFromRegistration` | PASS（未登记回调不重定向，兑换校验精确回调） |
| PKCE 降级（plain）/缺少 PKCE | `TestAuthorizationRequestValidation`、`TestStep92PKCEDowngradeAndReplay` | PASS |
| PKCE 错误 verifier | `TestTokenExchangeValidation`、`TestStep92PKCEDowngradeAndReplay` | PASS |
| 过期：授权码/设备码/刷新令牌/ceremony | `TestExchangeExpiredCode`、`TestDeviceAuthorizationExpired`、`TestRefreshIdleExpiry`、`TestCeremonyExpiry` | PASS |
| 取消/拒绝：授权、设备码、扫码 | `TestAuthorizationDenied`、`TestDeviceAuthorizationDenyAndCancel`、`TestDenyCancelRegenerateExpiry` | PASS |
| 并发消费：授权码/设备码/刷新/扫码批准与领取 | 各并发单赢家用例（见矩阵） | PASS |
| 跨用户/跨应用越权 | `TestLogoutCrossUserDenied`、`TestConfirmSessionScopeAndRevocation`、`TestIntegrationSameNamePermissionIsolation`、`TestStep92QRAcrossUserAndSingleClaim` | PASS |
| 匿名/不可信调用者 | `TestHTTPCallerAuthentication`、`TestStep92HTTPJointAuthorization`（401）、`TestIntegrationDatabaseOutageDenies` | PASS |
| 权限联合校验：当前权限撤销后拒绝 | `TestIntegrationRealTokenAndPermission`、`TestStep92HTTPJointAuthorization` | PASS（服务级 + 真实 HTTP 端点） |

## 6. 证据命令与真实输出摘要

环境统一：`cd P:\go\src\github.com\kagurazakayashi\EvernightLogin`，`GOMAXPROCS=2 CGO_ENABLED=0
GOFLAGS=-mod=readonly GOTOOLCHAIN=local`（`GOTOOLCHAIN=local` 仅用于避免 `auto` 触发工具链下载阻塞；
不改变被测代码与构建参数）。

1. 既有协议集成测试基线（新增探针前，7 个包串行全量）：
   `go test -count=1 -p 1 -timeout 600s ./internal/oauthflow/... ./internal/oidc/... ./internal/qrlogin/... ./internal/passkey/... ./internal/tokenauthz/... ./internal/token/... ./internal/oauthclient/...`
   → 全部 `ok`：oauthflow 17.814s、oidc 2.063s、qrlogin 3.814s、passkey 9.250s、tokenauthz 2.300s、
   token 8.494s、oauthclient 2.682s；总 real 53.112s，EXIT=0。
2. 步骤 92 新增探针：
   `go test -count=1 -p 1 -timeout 240s -run 'TestStep92' -v ./internal/tokenauthz/ ./internal/oauthflow/ ./internal/qrlogin/`
   → tokenauthz：`TestStep92HTTPJointAuthorization`/`TestStep92HTTPTokenTypeConfusion`/`TestStep92HTTPRevokedToken`/
   `TestStep92CurlStandardClient` 全 PASS，ok 1.561s；oauthflow：3 个用例（8 子用例）全 PASS，ok 1.433s；
   qrlogin：`TestStep92QRAcrossUserAndSingleClaim` PASS，ok 0.544s。
3. 新增探针 + 既有套件合并复跑（最终证据）：
   同上第 1 条命令（含新增探针）→ 全部 `ok`：oauthflow 19.193s、oidc 2.180s、qrlogin 3.964s、
   passkey 9.285s、tokenauthz 3.865s、token 8.803s、oauthclient 2.415s；总 real 56.950s，EXIT=0。
   新增探针稳定性：`go test -count=3 -p 1 -run 'TestStep92' ./internal/tokenauthz/ ./internal/oauthflow/
   ./internal/qrlogin/` → 三个包全 `ok`（4.441s / 4.223s / 1.299s），无 flaky。
4. 关键子集 `-v` 证据：
   - `go test -count=1 -p 1 -run 'Test(RegisterListRenameAndReauth|...|RevokeInvalidatesExistingSessions)$' -v ./internal/passkey/`
     → 19 个用例全 `--- PASS`，ok 9.070s（覆盖矩阵 4.7 全部模拟器行）。
   - `go test -count=1 -p 1 -v ./internal/oidc/` → 4 个用例（`TestIDTokenClaimsPairwiseAndInterop`
     含独立 JOSE 验签、`TestUserInfo*`、`TestDiscoveryDocumentOnlyImplemented`、`TestConfigurationValidation`
     9 子用例）全 PASS，ok 2.099s。
5. 接入示例实跑（独立进程，非测试内断言）：
   - `go run ./examples/oidc-login` → 输出"OIDC 登录接入契约示例完成。"，EXIT=0（进程内真实 SQLite/令牌/OIDC
     服务，覆盖 Discovery、PKCE S256、ID Token 签发、JWKS 独立验签、UserInfo 裁剪、ID Token 冒充/错误
     audience/缺 openid/nonce 不匹配负例）。
   - `go run ./examples/service-identity` → "服务身份与权限联合校验示例完成。"，EXIT=0（含依赖不可用默认拒绝）。
   - `go run ./examples/app-qr-login` → 输出真实会话签发与"重复领取被拒绝（已消费）"，EXIT=0。
6. 静态门禁：`gofmt -l` 三个新增测试文件无输出；`go vet ./internal/oauthflow/ ./internal/qrlogin/
   ./internal/tokenauthz/` EXIT=0；`go vet ./...`/`go build ./...` 按项目惯例在改动包范围内通过
   （本步仅新增测试文件，无产品代码变更；根包/其他包未触碰）。
7. 标准客户端：本机 `curl 8.22.0 (Windows) libcurl/8.22.0 Schannel`，在测试内以独立进程调用真实
   `httptest` 端点 PASS（`TestStep92CurlStandardClient`）；测试同时使用 Go 标准 `net/http` 客户端。

## 7. 未测项与缺口（不冒充已验收）

### 7.1 阻塞/缺口：独立服务 HTTP 装配缺失（影响"标准客户端/部署后互操作"维度）

- 现状（读代码核对）：`cmd/login-server` 只有 `--version`/`--help`，无 HTTP 服务装配；
  `internal/transport` 当前只装配健康检查/OpenAPI 等通用中间件，`internal/tokenauthz` 提供可挂载的
  `HTTPHandler`，但 OAuth 授权/令牌端点、OIDC Discovery/UserInfo/JWKS、设备码令牌与验证端点、
  扫码请求/确认/领取端点**没有产品级 HTTP 路由装配**。
- 因此本步无法用"部署后服务 + 标准 OAuth/OIDC 客户端/浏览器/手机 APP"完成端到端互操作验收；
  该项为 NOT_TESTED，并**阻塞**"兼容性验收"中的外部客户端维度（不是本步范围内可实现/可修复的内容）。
- 本步结论只覆盖"协议语义与错误处理在真实服务/Hander 层正确"，不等于"标准客户端可直接对接"。

### 7.2 未测：真实硬件/浏览器/客户端

| 未测项 | 原因 | 影响 |
|---|---|---|
| YubiKey/外置安全密钥、Windows Hello/平台 Passkey 真实 ceremony | 本机与执行环境无可用硬件认证器；无部署 HTTPS 服务/真实浏览器 | WebAuthn 仅软件 ECDSA 模拟器覆盖；真实认证器互操作、真实来源/RP ID 证书链未验证 |
| 真实浏览器（Chrome/Edge/Firefox）与跨域来源校验实测 | 无部署页面/服务 | 来源校验只有单元测试级覆盖 |
| 真实手机 APP 扫码确认 | 项目未开发通用手机 APP（需求约定）；无部署页面 | 扫码跨设备闭环未验证 |
| 真实 mTLS/客户端证书链路 | 无部署 TLS 服务；测试按生产契约注入客户端认证适配器 | `client_secret_basic`/证书身份逻辑覆盖，实际 TLS 握手与证书映射未测 |
| 标准 OAuth/OIDC 客户端（如 oauth2c、oidc-token 等 CLI） | 无部署端点 | 见 7.1 |
| 非 Windows 平台、`-race`、多实例/反代/时钟偏移/真实网络延迟 | 项目规则只要求 Windows+SQLite 实测；本步时间与范围限制 | 不推断其他平台结论 |
| 官方认证/合规套件（OIDC Conformance、FIDO 认证） | 未运行，不宣称官方认证 | 本记录不得表述为"通过官方认证" |

### 7.3 已如实标注的测试边界

- Passkey 测试使用测试内 ECDSA 软件认证器（与真实认证器同一 webAuthn 库的 attestation/assertion
  数据格式，但**不是真机**）；真实设备维度必须另行验收。
- tokenauthz HTTP 端点的调用者认证器由测试实现（可信边界契约），生产必须由 mTLS/客户端凭证等实现。
- 在线撤销检查在 tokenauthz 集成/验收测试中为生产契约替身（`fakeRevocations`），真实撤销闭环由
  oauthflow 撤销测试覆盖；两者不互相替代。

## 8. 必要小修与问题清单

- **必要小修：无。** 本步未发现需要修改协议实现才能在验收条件下通过的缺陷；未改动产品代码。
- 非缺陷观察（记录备查）：Access Token（长 JWT）冒充授权码传入授权码兑换时，先命中有界长度参数校验
  返回 `invalid_request`（而非 `invalid_grant`）。两者都是标准 OAuth 错误字段且均拒绝，安全语义正确；
  未为"美化错误码"改动实现。
- 验收探针编写过程中出现的失败均为测试搭建问题（如跨用户扫码需要先建立第二用户应用成员关系、
  tokenauthz 请求必须包含权限列表、"权限+scope"顺序），已修正测试并在本记录如实保留排查结论，
  不是产品缺陷。

## 9. 可复跑命令

```powershell
cd P:\go\src\github.com\kagurazakayashi\EvernightLogin
$env:GOMAXPROCS="2"; $env:CGO_ENABLED="0"; $env:GOFLAGS="-mod=readonly"; $env:GOTOOLCHAIN="local"

# 本步新增探针
go test -count=1 -p 1 -timeout 240s -run 'TestStep92' -v ./internal/tokenauthz/ ./internal/oauthflow/ ./internal/qrlogin/

# 协议相关既有套件（含新增探针）串行复跑
go test -count=1 -p 1 -timeout 600s ./internal/oauthflow/... ./internal/oidc/... ./internal/qrlogin/... ./internal/passkey/... ./internal/tokenauthz/... ./internal/token/... ./internal/oauthclient/...

# 独立示例
go run ./examples/oidc-login
go run ./examples/service-identity
go run ./examples/app-qr-login
```

## 10. 结论与勾选建议

- 已按 step92.txt 生成"能力与验证矩阵"，区分测试模拟器/标准客户端/真实设备三类维度；矩阵内**没有
  必需流程 FAIL 或 PARTIAL**，发现的问题仅为外部互操作维度未测。
- 建议：**可勾选步骤 92（done）**，但勾选说明必须保留边界——"进程内真实服务/真实 HTTP Handler 的
  协议与错误处理验收通过；部署后 HTTP 端点、标准客户端/浏览器、真实认证器/手机 APP、真实 mTLS 未测，
  阻塞于独立服务 HTTP 装配与硬件/客户端缺失，不得表述为已通过标准客户端互操作或官方认证"。
- 下一步前置：要完成真正的跨客户端/跨设备互操作验收，需先装配 `cmd/login-server` 的 OAuth/OIDC/
  设备码/扫码 HTTP 路由与首次配置入口，再准备真实浏览器与认证器环境；该工作不属于步骤 92。
