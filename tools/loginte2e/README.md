# loginte2e：协议与管理 API 端到端测试客户端

`tools/loginte2e` 是面向**已运行** login 服务的黑盒测试客户端，用于 OAuth2 / OIDC /
设备码 / 扫码协议端点与管理 JSON API 的验收、回归与故障排查。它只使用标准库
（ID Token 验签用 `crypto/ecdsa`、`crypto/rsa` + base64url + JSON 自行实现），
不新增第三方依赖。

**仅测试用途**：不得被生产入口导入（`internal/loginte2e` 有静态隔离测试守护）。

## 1. 前置条件

1. **可访问的运行中服务**。`--server` 要包含部署的路径前缀（`server.path_prefix`），
   例如服务以 `--config` 部署在 `https://login.example.test/login` 时：
   `--server https://login.example.test/login`。工具按 `internal/protocolapi` 的
   固定路径拼端点（`<server>/.well-known/openid-configuration`、`<server>/oauth/...`）。
2. **协议端点已挂载**：`discovery` / `jwks` / `authcode` / `token` / `device` / `qr`
   需要宿主把 `internal/protocolapi` 挂到 `ServeOptions.ExtraMounts`。未挂载时
   这些套件如实失败（404/405 等），不会被当作通过。
3. **管理 API 已启用**（仅 `adminapi` 套件）：宿主显式 `--enable-admin-api`。
4. **客户端登记**：`authcode` / `token` / `jwks` / `qr` 需要已登记的授权码公开客户端
   （`--client-id`、`--redirect-uri`；scope 需含 `openid`，刷新轮换需 `offline_access`）；
   `device` 需要已登记设备码授权的客户端。`qr` 还要求服务端把该客户端加入扫码白名单。
5. **模拟“已登录用户”**（`authcode` / `token` / `jwks` / `qr` 的确认步骤）：
   用 `--session-cookie-file` 提供**受保护文件**中的真实浏览器会话 Cookie 或会话秘密。
   这是测试专用便利通道，工具不做交互式登录页登录。
6. **管理会话**（`adminapi`）：用 `--admin-session-file` 提供受保护文件中的管理会话
   秘密；管理 API 要求已完成强认证且在新鲜度窗口内，否则服务端 fail-closed
   （403 `REAUTH_REQUIRED`），工具会如实报告。

## 2. 构建与运行

```bat
:: 仓库根目录；任意安装 Go 1.27.x 的环境
go build ./tools/loginte2e
.\loginte2e.exe --list-suites
.\loginte2e.exe discovery --server http://127.0.0.1:8080
```

也可以直接 `go run ./tools/loginte2e <suite> ...`。开关可以写在套件名前后。

## 3. 套件

| 套件 | 验证内容 | 关键前置 |
|---|---|---|
| `discovery` | Discovery 文档可解析、issuer 合法且与 `--server` 路径一致、四类端点地址与挂载路径一致、能力声明（code/query/S256/ES256/grant types/claims 参数为 false）、JWKS 可达、未登录授权端点不自动展示同意页、GET 令牌端点 405、UserInfo 无 Bearer 401、匿名撤销被拒、device/introspect 能力声明与实际端点一致、扫码端点存在性探测 | 服务可达 |
| `jwks` | JWKS 结构/签名公钥元数据；用标准库从 JWKS 独立验证 ID Token 的 ES256 签名与 iss/aud/exp/nonce；篡改载荷、`alg=none`、nonce 不匹配必须被拒绝 | `--client-id --redirect-uri --session-cookie-file` |
| `authcode` | 授权码 + PKCE S256：plain/缺失 PKCE 被拒绝（重定向错误码或 JSON）、同意页隐藏字段解析、批准后 303 回调含 code 且 state 原样返回、拒绝后 `error=access_denied` 且无 code | 同上 |
| `token` | 缺 grant_type/未知 grant_type 被拒；授权码兑换（Bearer/expires_in/id_token/refresh_token）；授权码重放 `invalid_grant`；错误 PKCE verifier 被拒；UserInfo 返回 sub；refresh 轮换且旧令牌重放被拒；撤销后 UserInfo 401；introspect 未认证 401（声明时）/未声明 404，正例需 `--client-secret-file` | 同上 |
| `device` | device_authorization 申请（scope 自动回退）、未确认前轮询 `authorization_pending`、用户确认后领令牌、已领令牌重放 `invalid_grant`、取消后无法领令牌、缺 client_id 被拒 | `--client-id`（设备码客户端）；确认需 `--device-confirm-url` 或库注入 `DeviceConfirm` |
| `qr` | 创建请求/二维码载荷不含领取绑定或令牌、错误领取绑定被拒、pending 状态、匿名读取确认上下文 401、确认端上下文、批准、approved 状态轮询、领取写入会话 Cookie 且正文无 Token、重复领取被拒、错误绑定领取被拒、取消流程 | `--client-id --session-cookie-file`（确认端） |
| `adminapi` | `/meta`（版本/前缀/强认证与每请求重鉴权契约）、`/error-codes` 投影与过滤、匿名与无效会话 401/403、未知路径 404、POST 方法 405、重复查询参数 400、只读端点稳定状态、响应不回显会话秘密 | `--admin-session-file` |
| `all` | 按 `discovery→jwks→authcode→token→device→qr→adminapi` 顺序汇总，返回一份报告 | 取决于各套件 |

设备码与扫码的“用户确认”边界不同：

- **扫码**确认走协议端点 `/oauth/qr/prompt` + `/oauth/qr/decision`，工具用会话秘密
  Bearer 调用（HTTP 客户端无浏览器环境凭据，端点按契约不要求 CSRF 头，但仍发送
  同源 `Origin`）。
- **设备码**确认页由宿主页面层实现，协议包不提供确认页 HTTP 端点。命令行只有在
  显式给出 `--device-confirm-url` 时才用通用 HTML 表单驱动；否则该步骤如实 skip。
  库使用者可注入 `Config.DeviceConfirm` 直接调用真实领域服务完成确认（集成测试用法）。

## 4. 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--server` | `http://127.0.0.1:8080` | 被测服务基础地址，可含部署路径前缀。默认值是**本机回环明文，仅测试便利**；非回环地址必须用 https（工具拒绝） |
| `--ca-file` | 空 | 在系统根证书之外**追加**信任指定 CA（PEM）；仍完整校验证书链/主机名/有效期，**不提供**跳过 TLS 校验的开关 |
| `--timeout` | `15s` | 单个 HTTP 请求超时 |
| `--poll-timeout` | `90s` | 设备码/扫码轮询总等待上限 |
| `--json` | false | 输出 JSON 报告 |
| `--session-cookie-file` | 空 | 受保护文件：会话秘密、`Cookie:` 头或 Netscape cookies.txt |
| `--admin-session-file` | 空 | 受保护文件：管理会话秘密（Bearer 形式） |
| `--admin-base-path` | `/admin/v1` | 管理 API 站内前缀（`serverapp` 默认值） |
| `--issuer` | 空 | 期望 issuer；空则信任 Discovery 返回值 |
| `--client-id` | 空 | 被测客户端应用 ID |
| `--client-secret-file` | 空 | 受保护的保密客户端密钥（introspect 正例用） |
| `--redirect-uri` | 空 | 客户端登记的回调地址 |
| `--scope` | `openid profile email offline_access` | 授权请求 scope（空格/逗号分隔） |
| `--device-confirm-url` | 空 | 宿主设备确认页地址，支持 `{code}` 占位符 |
| `--list-suites` | - | 列出套件 |

受保护文件要求：非 Windows 权限须仅所有者可读写（通常 `0600`），Windows 检查受限
DACL；工具在读取前调用既有 `internal/secrets.CheckProtectedFile`，不满足直接拒绝。

## 5. 退出码（稳定）

| 码 | 含义 |
|---|---|
| `0` | 没有失败用例（允许 skip，例如服务未声明某个可选能力） |
| `1` | 至少一个用例失败（HTTP 响应/协议行为不符合期望） |
| `2` | 参数、配置、受保护文件读取错误（测试未真正开始） |
| `3` | 目标不可达（连接/TLS 失败），或全部用例都因前置条件被跳过 |

## 6. JSON 报告

```json
{
  "tool": "loginte2e",
  "server": "http://127.0.0.1:8080",
  "suite": "all",
  "started_at": "2026-01-02T03:04:05Z",
  "duration_ms": 1234,
  "results": [
    {"suite": "discovery", "case": "issuer", "ok": true, "status": "pass"},
    {"suite": "token", "case": "introspect_active_token", "ok": false,
     "status": "skip", "detail": "状态查询需要保密客户端：用 --client-secret-file 提供密钥"}
  ],
  "summary": {"pass": 1, "fail": 0, "skip": 1}
}
```

`ok` 只在 `pass` 时为 true；`detail` 只含状态码、稳定错误码、公开消息与端点路径，
**绝不包含**令牌、授权码、设备码、短码、领取绑定、会话秘密、Cookie 或带查询串的 URL。

## 7. 安全边界与限制（如实声明）

- 默认严格 TLS 校验（含主机名/有效期）；`--ca-file` 是在**系统根证书之外追加**
  信任指定私有 CA（不是“只信任该 CA”，也不关闭校验），没有“跳过校验”选项。
- 默认 `--server http://127.0.0.1:8080` 是本机回环明文，仅测试便利：命令行会打印
  告警；`Config` 拒绝非回环的 http 地址（必须 https），避免在网络上明文传输会话
  秘密/令牌。
- 会话/客户端秘密只从受保护文件或测试内存进入，不写日志/报告/命令行；报告输出
  有专门断言（测试会检查报告不含会话秘密与 JWT 片段）。
- 不真实外发邮件/Webhook：工具不调用通知测试等会触发投递的写操作；管理 API 套件
  只做只读调用与拒绝路径。
- **未覆盖**：真实浏览器、官方 OAuth/OIDC 客户端、真机手机 APP 互操作；交互式
  登录页/MFA 登录；`client_credentials` 正例；管理写操作（需要 confirm/原因/敏感
  策略，测试工具不应产生业务副作用）；邮件/Webhook 真实投递。
- 同意页与设备确认页在测试中由“直接构造/驱动”的方式模拟：`authcode`/`token`/
  `jwks` 用真实会话 + 最小同意页表单字段；`device` 的确认由注入函数或宿主页面
  驱动完成。这不等于生产确认页已接线或已验收。
- `discovery` 会对设备码/状态查询/扫码端点做存在性探测；扫码探测成功后会用响应中
  的领取绑定立即取消，避免留下悬挂请求。
- 工具不保证被测服务的业务正确性超出所列协议契约；管理 API 套件无法知道调用者
  的真实权限集合，因此“权限拒绝路径”只用匿名/无效会话/格式错误等稳定负例验证。

## 8. 可复用测试辅助（Go API）

实现库在 `internal/loginte2e`（模块内可导入，供 `internal/serverapp`、
`internal/protocolapi`、`internal/adminapi` 的集成测试复用）：

```go
cfg := loginte2e.Config{
    Server:        httptestServer.URL,
    ExpectedIssuer: issuer,
    ClientID:      clientID,
    RedirectURI:   redirectURI,
    SessionSecret: realSessionSecret, // 用真实会话服务签发后填入
    DeviceConfirm: func(ctx context.Context, userCode string) error {
        _, err := realFlow.DecideDeviceAuthorization(ctx, realSessionSecret,
            oauthflow.DeviceDecisionRequest{UserCode: userCode, Approve: true,
                RequestID: "req_test_device_confirm"})
        return err
    },
}
client, err := loginte2e.New(cfg)
report, err := client.Run(ctx, loginte2e.SuiteAll) // 或单个 SuiteXxx
code := report.ExitCode()
```

- `Config`：所有前置条件显式注入，不从环境或服务端读取身份。
- `Client`：`New/Close/Run/ServerBase/Config`。
- `Result`/`Report`/`Summary`：结构化结果与稳定退出码 `ExitPass/ExitFail/ExitUsage/ExitUnavailable`。
- `DeviceConfirmFunc`：库测试可用真实领域服务完成“已登录用户确认”。

## 9. 常见问题

| 现象 | 可能原因 |
|---|---|
| `issuer 路径与 --server 路径不一致` | `--server` 没带部署路径前缀，或反向代理改写了路径 |
| `Discovery 端点不可用：HTTP 404` | 宿主未挂载 `internal/protocolapi`（`ExtraMounts`） |
| `服务端未展示同意页：access_denied` | 会话文件无效/过期/受限会话，或会话 Cookie 名不匹配 |
| `admin_meta` 失败且错误码 `REAUTH_REQUIRED` | 管理会话未完成强认证/已过期；当前版本 root 可能无法取得管理会话（见部署文档限制） |
| 全部 `skip`，退出码 3 | 缺少 `--session-cookie-file`/`--admin-session-file` 或客户端配置 |
| 设备码确认步骤 skip | 未配置 `--device-confirm-url`，且协议包不提供确认页端点 |
