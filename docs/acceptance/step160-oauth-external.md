# 步骤 160：外部 OAuth 客户端、设备码与 APP 扫码登录验收矩阵（真实服务复验）

- 日期：2026-11-22（Asia/Shanghai）；平台：Windows 11 amd64；Go 1.27.1；GOMAXPROCS=4。
- 被测：父项目当前工作树构建的 `login-server`（真实 serve、临时 SQLite、回环 `127.0.0.1:19081`，启用 protocol/resource services/device code/QR/introspection）。
- 外部驱动：`tools/loginte2e` 全套件、标准 HTTP/Python 客户端、Chrome Headless CDP 浏览器（模拟已登录浏览器 Cookie；页面确认/扫码/设备确认走真实页面）。**不导入 internal**。
- 真实第三方 OAuth 客户端、真实手机 APP、真实用户手工浏览器操作仍 **NOT_TESTED**；Chrome 自动化不等同真实用户/真机。
- 证据：[docs/acceptance/evidence/step160](evidence/step160/README.txt)；证据已去除 access/refresh/id/device/claim token 与会话秘密。
- 复跑脚本：`scripts/acceptance/step160fixture/main.go`、`scripts/acceptance/step160-browser.mjs`、`scripts/acceptance/step160-device.py`、`scripts/acceptance/step160-qr.py`。

## 1. 修复内容（本轮代码）

1. **`/oauth/device` 404 修复**：`internal/serverapp/mounts.go` 对与协议挂载共享路径的设备确认页面做“页面优先、404 回退协议挂载”缓冲路由；`/oauth/device` 与 `/oauth/device/confirm` 真实可达，`/oauth/token` 等协议端点仍由挂载处理。
2. **OAuth/设备/扫码页面 CSRF 白名单**：`internal/serverapp/pages.go` 合并 `UIPageOAuthPublicFormPaths` 到公开表单路径，否则真实 serve 页面 POST 被会话 CSRF 校验恒 403。
3. **页面确认的近期强认证事实**：`internal/uiauthadapter/oauth.go` 从真实会话的 `StrongAuthVerifiedAt` 构造 `reauth.Signals`（服务端事实，不接受客户端自述），并映射设备 reauth 错误为 ACCESS_DENIED。
4. **协议确认入口同一策略**：`internal/protocolapi/{protocolapi,authorize,qr}.go` 对同意/扫码决定传递同一会话强认证信号；修复页面/协议策略不一致。

## 2. 结果矩阵

| 编号 | 场景 | 结果 | 证据 |
|---|---|---|---|
| 160-A | Discovery：固定 issuer/端点/能力 | **PASS** 12/12 | `discovery-pass.json` |
| 160-A2 | 错误 issuer 拒绝 | **PASS（负例）** | `discovery-wrong-issuer.json` |
| 160-A3 | JWKS 公钥发布 | **PASS** 2 pass / 3 会话相关 skip | `jwks-pass.json` |
| 160-B | 浏览器已登录用户同意页→批准→授权码 | **PASS**（真实页面；Chrome Headless + fixture 会话） | `browser-authcode.txt`（approve submit ok） |
| 160-B2 | 授权码兑换（PKCE S256）、access/refresh/id_token 签发 | **PASS** | `browser-authcode.txt`（token status 200） |
| 160-B3 | 刷新轮换、旧 refresh 重放拒绝 | **PASS**（refresh status 200 rotated；replay 400 invalid_grant） | `browser-authcode.txt` |
| 160-B4 | 撤销 access token 后 UserInfo 拒绝 | **PASS（撤销语义；UserInfo 失效并非 OIDC 字段通过）** | `browser-authcode.txt`（revoke 200；after revoke 401） |
| 160-B5 | PKCE plain/缺 PKCE 协议拒绝、错误回调/跨客户端 | **PARTIAL**：loginte2e 协议直连当前返回 CSRF 403/缺少稳定错误码；PKCE 逻辑由浏览器 S256 + 既有单测覆盖，协议直连路径待修 | `loginte2e-authcode.json` |
| 160-C | OIDC id_token 声明（iss/aud/sub） | **PASS**（id_token 存在，iss/aud/sub 正确） | `browser-authcode.txt` |
| 160-C2 | OIDC UserInfo 标准调用 | **FAIL/已知边界**：resource audience 的 access token 被 `/oauth/userinfo` 以 invalid_token 拒绝；当前实现要求 audience=issuer，资源 audience 令牌不能走 UserInfo。真实客户端需使用 OIDC audience 的独立授权；本轮未提供自动流程 | `browser-authcode.txt`；已作为待办 |
| 160-D | Client Credentials 签发、claims（issuer/audience/service 主体） | **PASS** | `client-credentials-meta.json`；`cc-claims.json` |
| 160-D2 | 错误 client secret | **PASS（401 invalid_client）** | `client-credentials-wrong-secret.log` |
| 160-E | Introspection 正确 audience active | **PASS** | `introspect-active.log` |
| 160-E2 | Introspection 错误 audience 拒绝 | **PASS（403 access_denied）** | `introspect-wrong-audience.log` |
| 160-F | 设备码申请、pending、取消、错误 client（协议直连） | **PASS**（loginte2e 4 pass） | `loginte2e-device.json` |
| 160-F2 | 设备确认页 GET/POST、批准、领取 token | **PASS**（真实页面 `/oauth/device` 200，CSRF，批准后 200 token） | `device-page-flow.txt` |
| 160-F3 | 设备码 slow_down/expired/一次兑换重放 | **NOT_TESTED/PARTIAL**：未单独驱动慢速/过期；领取后未重复测试 replay | 待补 |
| 160-G | QR 创建、payload 不含 claim secret、pending、prompt 会话要求、错误 claim、取消 | **PASS**（页面/协议 7 pass；脚本另证 wrong_secret 拒绝） | `qr-page-flow.txt`、`loginte2e-qr.json` |
| 160-G2 | QR 页面确认批准、原发起端领取、重复领取拒绝 | **PASS**（页面确认 200；claim 200 claimed；replay 410） | `qr-page-flow.txt` |
| 160-G3 | 跨用户窃领/绑定错误 | **PASS（负例）**：错误 claim secret 410 拒绝 | `qr-page-flow.txt` |
| 160-G4 | loginte2e 协议 QR 批准/领取路径 | **PARTIAL**：协议直连批准仍 403 ACCESS_DENIED（外部直连无页面会话 CSRF/reauth 组合），页面路径 PASS | `loginte2e-qr.json` |
| 160-H | 联合权限/audience/跨客户端 | **PARTIAL**：CC audience 与错误 audience 拒绝 PASS；用户 token 联合权限依赖授权码/协议路径，本轮页面 token 未做 tokenauthz | `tokenauthz.json`（前置 skip） |
| 160-I | 固定 issuer/回调/audience | **PASS（issuer/audience 负例）** / **PARTIAL（完整回调/跨客户端协议直连）** | discovery、browser claims、CC 证据 |
| 160-J | 真实第三方 OAuth 客户端/手机 APP/真实用户浏览器 | **NOT_TESTED** | 无真实客户端/手机/手工操作 |

## 3. 结论

- **已修复并可复验**：真实 serve `/oauth/device` 404；OAuth 页面 CSRF 白名单；浏览器同意/设备确认/扫码确认的近期强认证接线。
- **PASS 主路径**：授权码+PKCE（浏览器）、token/refresh 轮换/重放拒绝/撤销、id_token、设备码申请/pending/cancel + 页面批准领取、QR 创建/确认/领取/错误 claim/重放、CC、introspection、Discovery/JWKS、固定 issuer/audience 负例。
- **未通过/待办**：标准 OIDC UserInfo 对 resource-audience token 拒绝（产品 audience 语义限制）；loginte2e 协议直连的授权同意/设备确认/QR 批准仍受 CSRF/reauth 组合影响，页面/浏览器路径已 PASS；slow_down/expired 未单独覆盖。
- **verdict：PASS_WITH_NOTES**（主路径 + 明确 NOT_TESTED/FAIL；不宣称真实第三方/手机通过）。

## 4. 复跑摘要

```powershell
go build -o P:/go/tmp/step160-login-server.exe ./cmd/login-server
go build -o P:/go/tmp/step160-loginte2e.exe ./tools/loginte2e
go build -o P:/go/tmp/step160fixture.exe ./scripts/acceptance/step160fixture
P:/go/tmp/step160fixture.exe P:/go/tmp/step160-fixture 19081
P:/go/tmp/step160-login-server.exe serve --config P:/go/tmp/step160-fixture/config.yaml `
  --master-key-file P:/go/tmp/step160-fixture/master.key --init-maintenance-state
node scripts/acceptance/step160-browser.mjs P:/go/tmp/step160-fixture/fixture.json
python scripts/acceptance/step160-device.py P:/go/tmp/step160-fixture/fixture.json
python scripts/acceptance/step160-qr.py P:/go/tmp/step160-fixture/fixture.json
```

夹具会话的强认证会话时间在策略 300 秒窗口内；超过窗口后需要重新签发/登录，脚本会按 fail-closed 拒绝。

## 5. 证据

- `browser-authcode.txt`：浏览器授权同意、code 兑换、claims、refresh replay、revoke；已移除授权码/URL 查询串。
- `device-page-flow.txt`：设备申请、页面确认、token。
- `qr-page-flow.txt`：QR 创建、页面确认、错误 claim、领取、重放。
- `loginte2e-*.json`：协议直连套件结果（authcode/token/device/qr），用于记录 PARTIAL 原因。
- `discovery-pass.json`、`jwks-pass.json`、`discovery-wrong-issuer.json`。
- `client-credentials-meta.json`、`cc-claims.json`、`client-credentials-wrong-secret.log`。
- `introspect-active.log`、`introspect-wrong-audience.log`。
