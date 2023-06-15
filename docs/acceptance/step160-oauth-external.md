# 步骤 160：外部 OAuth 客户端、设备码与 APP 扫码登录验收矩阵

- 日期：2026-11-21（Asia/Shanghai）；平台：Windows 11 amd64；Go 1.27.1；GOMAXPROCS=4。
- 被测：父项目工作树构建的 `login-server`（HEAD `200bfac` 基线 + 142-145 等当前工作树改动）；临时 SQLite、回环 `127.0.0.1:19081`；`protocol.enabled`、固定 issuer、Device Code、Resource Services/Introspection、APP QR 白名单均启用。
- 客户端：`tools/loginte2e` 全套件 + 标准 `curl`/Python 解码标准 HTTP 客户端；服务端夹具见 `scripts/acceptance/step160fixture/main.go`（测试用建临时 root/应用/客户端/会话，不进入产品路径）。
- 证据目录：[docs/acceptance/evidence/step160](evidence/step160/README.txt)。证据中已移除 access/refresh/device/claim token 等秘密；会话秘密、客户端 secret、二维码领取绑定不落盘。
- 重要边界：真实第三方 OAuth 客户端、真实手机 APP、真实浏览器表单交互 **NOT_TESTED**；本矩阵的“PASS”仅指标准 HTTP 客户端对真实进程的可观察行为。

## 1. 矩阵

| 编号 | 场景/断言 | 结果 | 证据/说明 |
|---|---|---|---|
| 160-A | Discovery：固定 issuer、端点集合、能力声明 | **PASS**（12/12） | `discovery-pass.json` |
| 160-A2 | Discovery 拒绝错误 issuer（固定 issuer 校验） | **PASS（拒绝路径）** | `discovery-wrong-issuer.json`（issuer 不一致，1 fail = 负例通过） |
| 160-A3 | JWKS：公钥发布、kid/alg/use、签名可验证 | **PASS**（2 pass；3 会话相关 skip） | `jwks-pass.json` |
| 160-B | 授权码 + PKCE：缺 PKCE/plain 拒绝 | **PASS**（4 pass） | `authcode.json` |
| 160-B2 | 同意页渲染、拒绝返回 access_denied | **PASS** | `authcode.json`（consent/deny 用例） |
| 160-B3 | 已登录会话批准授权码 | **FAIL（阻塞）**：`access_denied 需要重新验证身份后确认授权` | 外部客户端没有可用的 reauth 挑战接线；非匿名/伪造放行；`authcode.json` 中 `approve_issues_code` fail |
| 160-B4 | 授权码兑换、错误 PKCE、code 重放、回调/跨客户端拒绝 | **NOT_TESTED**（被 B3 前置阻塞） | token suite 对应 skip/fail |
| 160-C | OIDC userinfo、id_token、nonce/aud | **NOT_TESTED**（被 B3 前置阻塞）；JWKS/Discovery PASS | `token.json`、`jwks-pass.json` |
| 160-D | Client Credentials：保密客户端签发 | **PASS** | `client-credentials-meta.json`；claims `iss` 固定、`aud` = 配置资源、`subject_type=service` |
| 160-D2 | Client Credentials 错误 secret / 未认证 | **PASS（拒绝路径）** | `client-credentials-wrong-secret.log`（401 invalid_client） |
| 160-E | 刷新轮换、重放拒绝、撤销 | **NOT_TESTED**（授权码前置失败） | `token.json` |
| 160-F | Introspection：正确资源 audience 查询 active token | **PASS** | `introspect-active.log`（active=true，client_id/scope/aud 正确） |
| 160-F2 | Introspection：错误 audience / 错误 client | **PASS（拒绝路径）** | `introspect-wrong-audience.log`（403 access_denied）；错误 client 401 由 token suite PKCE/认证负例覆盖 |
| 160-G | 联合权限/audience/跨客户端：用户 token + 应用权限交集 | **PARTIAL/NOT_TESTED**：CC token 的 audience/主体正确、跨 audience 拒绝；用户 token tokenauthz 因 B3 未取得 | `tokenauthz.json`（前置 skip）、claims 证据 |
| 160-H | 设备码：申请、pending、取消、错误 client | **PASS**（4 pass） | `device.json` |
| 160-H2 | 设备确认页批准并领取 token、slow_down、过期、一次兑换 | **FAIL/NOT_TESTED**：真实 serve 的 `/oauth/device` 确认页 404；slow_down/expired 未单独执行 | `device.json`（confirm fail 404）；`curl /oauth/device` 404 |
| 160-I | APP 扫码：创建、payload 不含秘密、错误 claim 拒绝、pending 状态、prompt 会话要求、取消 | **PASS**（7 pass） | `qr.json` |
| 160-I2 | 扫码批准、状态 approved、原发起端领取、重复领取/跨用户窃领拒绝 | **FAIL（阻塞）**：批准 `403 ACCESS_DENIED`（需要重新验证身份）；领取未达成 | `qr.json`（approve fail；claim 未执行） |
| 160-J | APP 扫码确认页/真实手机 APP | **NOT_TESTED** | 无真实手机/浏览器；页面 reauth 未接线 |
| 160-K | 固定回调/重定向严格校验、跨客户端 token 使用 | **PARTIAL**：Discovery issuer/PKCE 负例 PASS；授权码回调/跨客户端用例被 B3 阻塞 | `authcode.json`、`token.json` |
| 160-L | 真实第三方 OAuth 客户端互操作 | **NOT_TESTED** | 约束不允许真实外网/第三方客户端 |

## 2. 关键失败/阻塞结论

1. **授权码/QR 批准被 reauth 阻塞**：真实 serve 中同意/扫码确认需要近期强认证；外部 CLI 没有可交互的 reauth 挑战流程，测试客户端无法完成“人工强认证→批准”。服务端按策略拒绝（非安全缺陷），但导致授权码兑换、OIDC userinfo/id_token、refresh/revoke、联合权限用户路径均无法外部验收。需要在后续步骤提供受控外部 reauth/页面流程或明确的测试夹具（不可伪造放行）。
2. **设备确认页 `/oauth/device` 在真实 serve 返回 404**：`/login` 为 200，协议 `/oauth/*` 已挂载，但宿主设备确认页没有在真实服务路由中可达；疑似 `/oauth` 协议 HandlerMount 与页面命名空间重叠/页面未注册。设备确认/领取因此无法验收；需产品接线修复或调整页面路径并补真实 HTTP 用例。
3. CC/introspection 核心通过；错误 secret/audience、固定 issuer、token claims 的 audience/主体符合预期。设备申请/pending/cancel、QR 创建/payload 脱敏/错误绑定/取消、Discovery/JWKS 通过。

## 3. 复现命令（摘要）

```powershell
# 1) 构建 login-server/loginte2e 与夹具
go build -o P:/go/tmp/step160-login-server.exe ./cmd/login-server
go build -o P:/go/tmp/step160-loginte2e.exe ./tools/loginte2e
go build -o P:/go/tmp/step160fixture.exe ./scripts/acceptance/step160fixture
# 2) 初始化临时夹具（root/应用/客户端/会话；脚本只写 P:/go/tmp）
P:/go/tmp/step160fixture.exe P:/go/tmp/step160-fixture 19081
# 3) 启动真实服务（临时库/回环/维护状态初始化仅测试）
P:/go/tmp/step160-login-server.exe serve --config P:/go/tmp/step160-fixture/config.yaml `
  --master-key-file P:/go/tmp/step160-fixture/master.key --init-maintenance-state
# 4) 套件（示例；session 文件需为受保护文件）
loginte2e discovery --server http://127.0.0.1:19081 --issuer http://127.0.0.1:19081 --json
loginte2e jwks --server http://127.0.0.1:19081 --issuer http://127.0.0.1:19081 --json
loginte2e authcode --server ... --client-id <app> --redirect-uri http://127.0.0.1:9999/callback `
  --scope "openid profile offline_access" --audience https://resource.example.test/api `
  --session-cookie-file <protected-session>
loginte2e device --server ... --client-id <app> --device-confirm-url http://127.0.0.1:19081/oauth/device ...
loginte2e qr --server ... --client-id <app> --session-cookie-file <protected-session> ...
# 5) CC/introspection 标准 curl（secret 从受保护文件/环境读取，不写日志）：
curl -X POST /oauth/token grant_type=client_credentials ...
curl -u <resource-client>:<secret> -X POST /oauth/introspect --data-urlencode token=... --data-urlencode audience=...
```

所有临时服务/端口/会话/秘密在验收后清理；证据中不含 secret/token/会话秘密/领取绑定。

## 4. 证据文件

- `docs/acceptance/evidence/step160/discovery-pass.json`、`jwks-pass.json`、`discovery-wrong-issuer.json`
- `authcode.json`、`token.json`、`device.json`、`qr.json`、`tokenauthz.json`、`introspect.json`
- `client-credentials-meta.json`、`client-credentials-claims.json`、`client-credentials-wrong-secret.log`
- `introspect-active.log`、`introspect-wrong-audience.log`
- `README.txt`（各 JSON summary；已递归去除 access/refresh/id/device/claim tokens）
