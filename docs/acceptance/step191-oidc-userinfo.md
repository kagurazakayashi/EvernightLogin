# 步骤 191：OIDC UserInfo 正向接入与受众校验验收记录

- 步骤：191（High，验收+修复类）；执行者：小肥鱼；日期：2026-11-23（Asia/Shanghai）。
- 母仓库基线：`9abc5d1261dcac8a53dd31e50036af7fbd767194`（执行时 HEAD，未提交）。
- 环境：Windows 11 amd64、Go 1.27.4、4 逻辑 CPU（`GOMAXPROCS=2`、`-p 2`）。
- 本记录是**开发方自验证据**，不替代独立审计复验；判定以审计/复验记录为准。

## 1. 目标与背景

复验报告第 4 节 OIDC 行指出：步骤 160 的失败用例使用的是**资源服务器 audience**，
而 `internal/oidc/oidc.go` 明确要求 UserInfo 的 Access Token audience 包含 issuer。
因此本步不是“放松 audience 校验”，而是按既有设计完成真实接入：

1. 客户端把 issuer 登记为允许 audience，并在授权请求显式带 `resource=<issuer>`；
2. 用真实 HTTP 协议流程（授权码 + PKCE S256 → Token → UserInfo）取得正向证据；
3. 补齐错误 audience、错误签发方、过期/撤销、ID Token 误用、授权码重放等拒绝路径；
4. 修复真实接入暴露的**文档/示例**缺陷（原示例宣称“HTTP 路由尚未暴露”、UserInfo 章节
   未写 audience 要求、示例本身用直接签发的令牌充当 UserInfo 正向证据）。

## 2. 改动文件（未修改嵌入链持有文件）

| 文件 | 改动 |
|---|---|
| `internal/protocolapi/oidc_userinfo_acceptance_test.go` | 新增步骤 191 验收测试：真实 HTTP 授权码+PKCE→Token→UserInfo，覆盖全部判据 |
| `internal/protocolapi/env_test.go` | 测试环境暴露 `tokenStore/sealer`，用于构造“同一签名密钥、不同签发方”的真实令牌（错误签发方负例）；不改变生产代码 |
| `examples/oidc-login/main.go` | 重写为可运行外部客户端示例：临时 SQLite + 真实服务 + `127.0.0.1` 随机端口真实 HTTP 服务；客户端只用标准库+go-jose 完成 Discovery/PKCE/令牌兑换/JWKS 验签/UserInfo 与拒绝用例 |
| `docs/deployment/integration.md` | 新增 2.4 UserInfo audience 语义；2.1 `resource` 行、2.3 UserInfo 要求、§9 示例运行说明同步 |
| `docs/guide/login-and-oauth.md` | `resource`/UserInfo audience 要求、OIDC 状态行、§8 示例运行说明与未测清单同步 |
| `docs/acceptance/README.md` | 索引增加本记录 |
| `docs/acceptance/step191-oidc-userinfo.md` | 本记录 |

未触碰：`app/`、`internal/appcore/`、`internal/serverapp/{host,services,mounts,pages,tasks}.go`、
`ui.go`、`config*.go`、`database/login.db`、EvernightMail、EvernightMail/gitlink。
未执行任何 Git 写操作。

## 3. 验收判据与证据

证据来源：`internal/protocolapi` 测试环境的**真实** SQLite（全量迁移）、真实会话/审计/
OAuth 客户端/令牌/OIDC/授权流程服务，以及 `httptest` 回环 HTTP 服务；客户端只通过 HTTP
端点完成协议流程。正向 Access Token 均由“授权请求→同意页批准→授权码→PKCE 兑换”产生，
未使用直接签发令牌冒充正向证据。

| 判据 | 用例 | 结果 |
|---|---|---|
| UserInfo 成功（Discovery 声明真实端点） | `TestOIDCUserInfoAcceptance` 正向段：Discovery → 同意页 → 303 回调 → 令牌端点 → `GET /oauth/userinfo` 200 | PASS |
| `sub` 与 ID Token 一致 | 真实令牌服务 `VerifyIDToken` 得 `sub`，与 UserInfo `sub` 严格相等 | PASS |
| scope 字段裁剪 | 仅 `openid` 的授权码流程令牌：UserInfo 只含 `sub`，无 `name/preferred_username/locale/zoneinfo/updated_at/email/email_verified` | PASS |
| 缺少 `openid` scope | 真实流程签发 `profile email` 令牌 → `403 insufficient_scope` | PASS |
| 错误 audience | `resource=https://api.example.test`（资源服务器 audience）令牌 → `401 invalid_token` | PASS |
| 错误签发方 | 第二真实令牌服务（同一 active 签名密钥、同一 audience、issuer 不同）签发 → `401 invalid_token` | PASS |
| ID Token 误用 | ID Token 作 Bearer → `401 invalid_token` | PASS |
| 授权码重放 | 同一 code 二次兑换 → `400 invalid_grant` | PASS |
| 撤销后令牌 | 真实 `POST /oauth/revoke` 撤销访问令牌 → UserInfo `401 invalid_token` | PASS |
| 过期令牌 | 真实流程取得令牌后推进注入时钟 2 小时（越过 15 分钟有效期）→ `401 invalid_token` | PASS |
| 错误响应格式 | UserInfo 拒绝响应带 RFC 6750 `WWW-Authenticate: Bearer ...` 挑战 | PASS |

补充：既有 `TestUserInfoScopeAndRevocation`（同包）仍 PASS，未被本步改动破坏。

## 4. 真实执行命令与结果

命令均在仓库根执行，Windows PowerShell：

```powershell
# 1) 取全局重负载锁（团队纪律）
powershell -NoProfile -ExecutionPolicy Bypass -File .ai\lead\tools\heavy-lock.ps1 acquire -Owner "step191-dev" -TimeoutSec 900

# 2) 编译/静态检查
$env:GOMAXPROCS='2'; go vet ./internal/protocolapi ./examples/oidc-login
# 退出码 0

# 3) 步骤 191 验收测试
$env:GOMAXPROCS='2'; go test -count=1 -p 2 -run 'TestOIDCUserInfoAcceptance' -v ./internal/protocolapi
# --- PASS: TestOIDCUserInfoAcceptance (0.55s)
# ok .../internal/protocolapi 0.744s   退出码 0

# 4) 可运行外部客户端示例（真实回环 HTTP 服务，临时 SQLite）
$env:GOMAXPROCS='2'; go run ./examples/oidc-login
# 退出码 0；输出见第 5 节

# 5) 包级回归
$env:GOMAXPROCS='2'; go test -count=1 -p 2 ./internal/protocolapi
# ok github.com/.../internal/protocolapi 8.617s   退出码 0

# 6) 释放重负载锁
powershell -NoProfile -ExecutionPolicy Bypass -File .ai\lead\tools\heavy-lock.ps1 release -Owner "step191-dev"
```

## 5. 示例协议流程证据摘要（脱敏，不含令牌/授权码/会话秘密）

```
== 1. 启动真实 OIDC 服务（临时 SQLite + 回环 HTTP 端口）
  issuer: http://127.0.0.1:<随机端口>
  discovery: token_endpoint=.../oauth/token userinfo_endpoint=.../oauth/userinfo jwks_uri=.../jwks
== 2. 授权码 + PKCE(S256)：同意页 → 批准 → 回调授权码
  [OK] 授权码已取得（PKCE S256、state 已校验）
== 3. 令牌端点：code + verifier 兑换 Access/ID Token
  [OK] token_type=Bearer expires_in=900（令牌原文不打印）
== 4. 拉取 JWKS 并独立验证 ID Token
  [OK] ID Token 签名/iss/aud/nonce/exp 校验通过
== 5. 用 Access Token 调用 UserInfo（sub 必须与 ID Token 一致）
  [OK] UserInfo: sub=<pairwise 假名> name=Alice email=alice@example.test email_verified=true
== 6. scope 字段裁剪：只申请 openid 时只返回 sub
  [OK] 只返回 sub，profile/email 字段已裁剪
== 7. 拒绝路径：错误 audience / ID Token 误用 / 授权码重放
  [OK] 资源服务器 audience 令牌访问 UserInfo 被 401 invalid_token 拒绝
  [OK] ID Token 冒充 Access Token 被拒绝
  [OK] 授权码重放被 400 invalid_grant 拒绝
OIDC UserInfo 正向接入与受众校验示例完成。
```

程序退出时关闭回环 HTTP 服务、关闭临时数据库并删除临时目录；不联网、不写仓库。

## 6. 未测/限制（如实登记）

1. **真实第三方 OIDC 客户端库互操作未测**：示例客户端是标准库 `net/http` + `go-jose`
   手写流程，不等于 go-oidc/AppAuth 等成熟客户端库联调。
2. **真实独立服务进程（`login-server serve`）未在本步重跑**：并行步骤 180 正在修改
   `internal/serverapp` 嵌入链（`app/`、`internal/appcore/`、`serverapp/{host,services,mounts}.go`），
   按写域纪律本步未触碰该链路。协议端点与生产装配共用同一组真实服务
   （`internal/serverapp/protocol_domains.go` 注入相同的 token/oidc/oauthflow/protocolapi
   服务），但“经 CLI 启动的真实进程”证据留待合并后由审计/复验补跑。
3. **未做压力/长时间测试**；令牌过期用注入时钟推进（真实服务注入时钟），不是真实等待。
4. **未做真实浏览器手工登录**：示例的“已登录用户”由真实会话服务在进程内签发，等价于
   登录页完成后的会话；登录页交互本身不属于本步判据。

## 7. 结论（开发方自验）

- 正向：真实授权码 + PKCE → Token → UserInfo 通过；`sub` 与 ID Token 一致；scope 裁剪正确。
- 反向：错误 audience、错误签发方、缺少 openid、ID Token 误用、授权码重放、撤销、过期
  全部按标准错误拒绝，未通过删除 audience/签发方校验消除错误。
- 未修改生产鉴权语义，仅新增验收测试、示例与文档；等待独立审计复验与合并后独立进程复跑。
