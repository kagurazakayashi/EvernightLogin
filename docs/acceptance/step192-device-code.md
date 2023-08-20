# 步骤 192：设备码登录边界与重放验证记录

- 步骤：192（High，协议链验收+修复）；执行者：小肥鱼；日期：2026-11-23（Asia/Shanghai）。
- 母仓库基线：`9abc5d1261dcac8a53dd31e50036af7fbd767194`（执行时 HEAD，未提交；工作区含
  并行步骤 181 的其它改动，本步未触碰 `internal/serverapp/` 与 `app/`）。
- 环境：Windows 11 amd64、Go 1.27.4、4 逻辑 CPU（`GOMAXPROCS=2`、`-p 2`）。
- 本记录是**开发方自验证据**，不替代独立审计复验。

## 1. 目标

以已装配设备码流程为基础验证（必要时修复）：授权待定、polling 间隔、`slow_down`、用户
拒绝、过期、成功兑换与一次性消费；确认页显示正确应用及请求范围；不允许其它客户端领取；
Discovery 与已实现能力一致；CLI 不包含公开客户端伪密钥。时间测试用注入时钟/短配置，
不做长时间等待。

## 2. 改动文件（未改嵌入链持有文件）

| 文件 | 改动 |
|---|---|
| `internal/protocolapi/device_login_acceptance_test.go` | 新增步骤 192 验收测试：真实公开客户端 + 真实 HTTP 端点 + 真实内置确认页（真实模板/生产页面适配器/真实会话），覆盖全部判据 |
| `internal/loginte2e/device.go` | 设备码 CLI 套件新增 `device_poll_slow_down` 用例（首次轮询 pending、立即再轮询必须 `slow_down` 且带 `Retry-After`），并抽出 scope 回退辅助函数 |
| `docs/deployment/integration.md` | 重写设备码小节：HTTP 端点已装配、错误语义、一次性消费、不签发 ID Token、确认页要求 |
| `docs/guide/login-and-oauth.md` | 设备码状态行、5.1 流程与端点、未测清单同步 |
| `docs/acceptance/README.md` | 索引增加本记录 |

未触碰：`internal/serverapp/**`、`app/**`、`config*.go`、`.gitmodules`、EvernightMail、
`database/login.db`；未执行任何 Git 写操作。

## 3. 验收判据与证据

证据来源：临时 SQLite（全量迁移）+ 真实会话/审计/OAuth 客户端/令牌/授权流程服务 +
`httptest` 回环真实 HTTP 服务。设备端（公开客户端 `client_id`，无任何 secret）只通过 HTTP
端点申请/轮询/取消；用户确认走**真实内置确认页面**（`login.NewWebUI` + 生产页面适配器
`internal/uiauthadapter` + 真实登录会话），页面 HTML 由真实模板渲染真实应用名与 scope
中文说明，批准/拒绝经页面处理器调用真实 `oauthflow` 决定接口。

| 判据 | 用例/证据 | 结果 |
|---|---|---|
| 真实公开客户端完成一轮设备码登录 | `TestDeviceCodeLoginAcceptance`：`POST /oauth/device_authorization`（仅 `client_id`，无 secret）→ 确认页批准 → 按间隔轮询 `POST /oauth/token` 200，`token_type=Bearer`，Access Token 校验 `token_use=access`/`client_id`/`sub`/scope=`profile` | PASS |
| 授权待定 | 未确认轮询 → `400 authorization_pending` | PASS |
| 过快轮询 slow_down | 立即再次轮询 → `400 slow_down` + 合法 `Retry-After`；按原间隔再轮询仍 `slow_down` 且 `Retry-After` 递增（服务端强制增大间隔） | PASS |
| 到期 | 注入时钟推进 11 分钟（设备码默认 10 分钟）→ `400 expired_token` | PASS |
| 重复兑换（一次性消费） | 成功领取后同设备码再轮询 → `400 invalid_grant` | PASS |
| 错误客户端不能领取 | 另一已登记设备码客户端提交同一 `device_code` → `400 invalid_grant`（不泄露归属） | PASS |
| 用户拒绝 | 真实确认页提交 `approve=false` 后轮询 → `400 access_denied` | PASS |
| 确认页显示正确应用与请求范围 | 真实页面 HTML 包含应用展示名、应用标识、scope 值 `profile` 与中文说明「读取你的公开资料」、用户短码 | PASS |
| 发起端取消（补充） | `POST /oauth/device/cancel` 204 后轮询 → `400 access_denied` | PASS |
| Discovery 与实现一致 | 启用：声明 `device_authorization_endpoint` 与 `device_code` grant_type；未启用（`EnableDeviceFlow=false`）：不声明且端点 404 | PASS |
| CLI 不含公开客户端伪密钥 | `tools/loginte2e` 公开客户端路径只接受 `--client-id`；secret 只能来自受保护文件且仅保密客户端使用（源码核对）；`internal/loginte2e` 设备码套件对真实服务跑通（含新增 slow_down 用例） | PASS |

补充：设备码 flow 不签发 ID Token、不签发未登记 refresh_token，测试断言响应中不存在
`id_token`/`refresh_token`。

## 4. 真实执行命令与结果

Windows PowerShell、仓库根；重负载命令在**同一调用内**取锁/释放（单次持锁 << 10 分钟）：

```powershell
$env:GOMAXPROCS='2'
go vet ./internal/protocolapi ./internal/loginte2e ./tools/loginte2e
# 退出码 0

go test -count=1 -p 2 -run 'TestDeviceCodeLoginAcceptance' -v ./internal/protocolapi
# --- PASS: TestDeviceCodeLoginAcceptance (2.52s)
# ok .../internal/protocolapi 3.743s   退出码 0

go test -count=1 -p 2 -run 'TestRealProtocolAPIDeviceFlow' -v ./internal/loginte2e
# --- PASS: TestRealProtocolAPIDeviceFlow (11.88s)
# ok .../internal/loginte2e 12.469s   退出码 0（含新增 device_poll_slow_down 用例）

go test -count=1 -p 2 ./internal/protocolapi
# ok .../internal/protocolapi 25.992s   退出码 0（协议包全量回归）

gofmt -l internal/protocolapi internal/loginte2e tools/loginte2e
# 无输出
```

## 5. 未测/限制（如实登记）

1. **真实独立服务进程（`login-server serve` + YAML）未在本步重跑**：并行步骤 181 正在修改
   `internal/serverapp` 嵌入链，按写域纪律本步未触碰；协议端点与生产装配共用同一组真实
   服务。合并后建议由审计/复验用 `login-server serve` 再跑一次设备码边界。
2. **页面 POST 的传输层 CSRF/Origin 中间件未在本测试中重跑**：内置页面框架本身不校验
   CSRF，生产由 `serverapp` 装配的传输层中间件校验；步骤 160 已记录真实页面 + CSRF 的
   设备码流程通过。本步聚焦页面数据展示与业务决定路径（真实模板/生产适配器/真实会话）。
3. 真实手机/电视等硬件设备、真实第三方设备码客户端未测；CLI 侧 slow_down 已覆盖，但
   CLI 的过期/拒绝流程需人工页面配合，未做成自动化（过期由 Go 测试注入时钟覆盖）。
4. 未做压力/长时间测试；未真实外发邮件。

## 6. 结论（开发方自验）

- 设备码主流程与边界（pending、slow_down、确认页应用/范围、批准领取、一次性消费、错误
  客户端、拒绝、过期、取消）全部用真实公开客户端与真实 HTTP 服务验证通过；
- Discovery 在启用/未启用两种状态下与实现一致；CLI 不含公开客户端伪密钥；
- 未修改生产鉴权语义，仅新增验收测试、CLI 套件用例与文档；等待独立审计复验。
