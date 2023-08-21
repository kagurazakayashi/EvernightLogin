# 步骤 193：已登录应用扫码确认与网页领取闭环验收记录

- 步骤：193（Max，协议链验收+小修）；执行者：小肥鱼；日期：2026-11-23（Asia/Shanghai）。
- 母仓库基线：`9abc5d1261dcac8a53dd31e50036af7fbd767194`（执行时 HEAD，未提交；工作区含
  并行步骤 181 的其它改动，本步未触碰 `internal/serverapp/` 与 `app/`）。
- 环境：Windows 11 amd64、Go 1.27.4、4 逻辑 CPU（`GOMAXPROCS=2`、`-p 2`）。
- 本记录是**开发方自验证据**，不替代独立审计复验；真实手机相机扫码未测。

## 1. 目标

完成最初要求的“已登录 APP 扫网页二维码登录”闭环并验证：二维码只含一次性请求标识、
确认前展示正确应用与请求范围、确认后仅原发起端可领取、长期 Token 不进二维码、重放/
过期/错误端/错误领取绑定拒绝、取消与拒绝语义正确；同时补协议直连的**合法调用方式**
（Bearer 会话 + 同源 Origin；Cookie 会话另需 CSRF），不关闭任何校验。

## 2. 改动文件（未改嵌入链持有文件）

| 文件 | 改动 |
|---|---|
| `internal/protocolapi/qr_login_acceptance_test.go` | 新增步骤 193 验收测试：匿名发起端网页 + 已登录 APP 两个独立会话，经真实内置网页（`login.NewWebUI` + 生产页面适配器 `uiauthadapter` + 真实会话/扫码服务）完成创建/展示/批准/领取，并覆盖协议直连合法调用与全部拒绝路径 |
| `internal/loginte2e/qr.go` | CLI 扫码套件增强：确认上下文断言应用展示名/风险提示/scope 合法；新增 `qr_claim_requires_binding`（只凭 request_id 不能领取） |
| `examples/app-qr-login/main.go` | 仅更新文件头注释：注明真实部署的 HTTP 端点/内置确认网页/合法协议调用方式与步骤 193 验收记录（行为不变） |
| `docs/deployment/integration.md` | 重写扫码登录小节：HTTP 端点表、合法调用与 403 排障（Bearer+Origin / Cookie+CSRF，不关闭校验）、页面路径与步骤 193 记录 |
| `docs/guide/login-and-oauth.md` | 扫码状态行、5.2 流程/端点/合法调用、未测清单同步 |
| `docs/acceptance/README.md` | 索引增加本记录 |

未触碰：`internal/serverapp/**`、`app/**`、`config*.go`、`.gitmodules`、EvernightMail、
`database/login.db`；未执行任何 Git 写操作。

## 3. 双会话验收判据与证据

**发起端 = 匿名网页会话**（只持有服务端签发的签名状态 Cookie，不登录）；
**确认端 = 另一个独立的已登录 APP 会话**（真实普通会话 + 近期强认证事实）。
领取出的目标应用会话由真实 `internal/session` 服务签发。

| 判据 | 证据 | 结果 |
|---|---|---|
| 双会话扫码闭环 | 发起端 GET `/login/qr` 创建请求 → 确认端 GET `/app/scan?request_id=` 读取 → POST 批准 → 发起端 POST `/login/qr/poll` 见 approved → 发起端 POST `/login/qr/claim` 303 + 目标应用会话 | PASS |
| 确认前展示正确应用与范围 | 确认页 HTML 含应用名称「协议演示应用」、应用标识、scope `profile` 与中文说明「读取你的公开资料」；协议 `GET /oauth/qr/prompt` 返回 `application_name`/`scopes`/`warning` | PASS |
| 二维码不含长期 Token/领取绑定 | 发起页 HTML 不含 `claim_secret`、access/id/refresh token 字段、签名状态 Cookie 值、确认端会话秘密；协议 `qr_payload` 只含一次性 request_id（既有用例与 CLI 断言） | PASS |
| 仅原发起端可领取 | 原发起端（携带签名状态 Cookie）领取成功；另一个匿名网页（无状态 Cookie）即使知道 request_id，领取被 4xx 拒绝且不签发会话 | PASS |
| 重复确认 | 同一请求第二次 POST 批准被拒绝 | PASS |
| 重复领取 | 同一发起端第二次领取被拒绝且不再签发会话 | PASS |
| 错误领取绑定 | 协议直连用错误 `claim_secret` 领取被拒绝 | PASS |
| 用户拒绝 | 确认页 `approve=false` 后发起端轮询为 denied，领取被拒绝 | PASS |
| 发起端取消 | 取消后状态为 cancelled，领取被拒绝 | PASS |
| 过期 | 注入时钟推进 3 分钟（请求有效期 2 分钟）后轮询为 expired，领取被拒绝 | PASS |
| 错误应用 | 固定目标应用时，为其他应用创建扫码请求返回 400 | PASS |
| 协议直连合法调用（不关闭校验） | Bearer 会话秘密 + 同源 Origin：`/oauth/qr/prompt` 200、`/oauth/qr/decision` 200、`/oauth/qr/claim` 200 并签发正确会话；缺 Origin 的 decision 返回 403；重复领取与错误绑定返回 4xx | PASS |
| CLI 扫码套件 | `internal/loginte2e` QR 套件对真实 protocolapi 服务全部 PASS（Bearer+Origin 合法调用、确认上下文应用/风险/范围断言、缺领取绑定拒绝、重复领取拒绝、取消流程） | PASS |

## 4. 真实执行命令与结果

Windows PowerShell、仓库根；重负载测试在**同一调用内**取锁 → 运行 → try/finally 释放
（`heavy-lock` 当前 `FREE`；单次持锁远小于 10 分钟）：

```powershell
$env:GOMAXPROCS='2'
go vet ./internal/protocolapi ./internal/loginte2e ./tools/loginte2e
# 退出码 0

go test -count=1 -p 2 -run 'TestQRLoginPageAcceptance|TestQRLoginFlow|TestQRLoginRejections' -v ./internal/protocolapi
# PASS: TestQRLoginFlow (0.67s)、TestQRLoginRejections (0.35s)、TestQRLoginPageAcceptance (0.42s)
# ok .../internal/protocolapi 1.607s   退出码 0

go test -count=1 -p 2 -run 'TestRealProtocolAPIAuthCodeFamily' -v ./internal/loginte2e
# PASS（含 qr 子套件 1.12s，新增断言/用例已生效）  ok .../internal/loginte2e 1.654s   退出码 0

go test -count=1 -p 2 ./internal/protocolapi
# ok .../internal/protocolapi 10.657s   退出码 0（协议包全量回归）

gofmt -l internal/protocolapi internal/loginte2e tools/loginte2e
# 无输出
```

## 5. 未测/限制（如实登记）

1. **真实独立服务进程（`login-server serve` + YAML）未在本步重跑**：并行步骤 181 正在修改
   `internal/serverapp` 嵌入链，按写域纪律未触碰；协议端点与生产装配共用同一组真实服务。
   合并后建议审计用实时服务 + 浏览器再跑一次（可用 `tools/loginte2e qr` 套件 + 会话文件）。
2. **页面 POST 的传输层 CSRF/Origin 中间件未在本测试中重跑**：内置页面框架本身不校验
   CSRF，生产由 serverapp 装配的传输层校验；步骤 160 已记录真实页面 + CSRF 的扫码流程
   通过。本步聚焦双会话分离、页面数据展示与业务决定/领取路径；协议直连的 Origin/CSRF
   语义由同一测试与 CLI 套件覆盖。
3. 真实手机相机扫码、真机 APP（iOS/Android）互操作未测（无相关硬件/客户端）。
4. 未做压力/长时间测试；未真实外发邮件。

## 6. 结论（开发方自验）

- 双会话扫码闭环（匿名发起端网页 + 已登录 APP 确认端）经真实内置网页与真实 HTTP 服务
  验证通过；确认页展示正确应用与范围；领取出的目标应用会话归属确认者且只允许原发起端
  领取一次；二维码不含任何长期 Token 或领取绑定。
- 拒绝/取消/过期/重复确认/重复领取/错误领取绑定/其他网页抢领/错误应用全部按预期拒绝。
- 协议直连合法调用（Bearer + 同源 Origin；Cookie+CSRF）已明确并验证，缺 Origin 仍拒绝，
  未关闭任何校验。
- 未修改生产鉴权语义；仅新增验收测试、CLI 套件增强与文档；等待独立审计复验。
