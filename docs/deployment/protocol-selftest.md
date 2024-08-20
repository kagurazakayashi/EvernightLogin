# 自包含协议与安全集成测试工具（步骤 243）

`scripts/protocol-selftest` 把分散在协议、会话、CSRF、认证防枚举与 MFA 包中的真实
集成测试整理为一个可被 CI 或一键入口调用的短测试工具。它**不依赖外部网络、不安装
依赖包、不连接外部数据库**：工具只调用本仓库的 `go test -json`，被测测试使用临时
SQLite、`httptest`/动态回环端口、合成身份、软件 TOTP 与软件 WebAuthn 认证器。

## 1. 运行

```powershell
# core 场景（默认，协议 + 安全关键路径）
go run ./scripts/protocol-selftest -out P:\go\tmp\protocol-selftest.json -verbose

# 可用 PowerShell 包装入口（CI 用）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\protocol-selftest.ps1 -out P:\go\tmp\protocol-selftest.json

# 列出场景（JSON，便于 CI 发现）
go run ./scripts/protocol-selftest -list

# 验证失败退出码（注入一个确定性失败，仅诊断）
go run ./scripts/protocol-selftest -inject-failure
```

参数：`-timeout`（总超时，默认 6m）、`-per-scenario-timeout`（单场景，默认 2m）、
`-out`、`-verbose`、`-list`、`-suite core`（当前仅 core）、`-inject-failure`。

## 2. 覆盖矩阵

| 领域 | 场景（package / 测试） | 真实机制 |
|---|---|---|
| OAuth/OIDC 契约与错误码 | `internal/protocolapi`：Discovery/JWKS/Handler/PathPrefix/Route recovery | 真实协议处理器、统一错误、能力声明 |
| 授权码 + PKCE / Token / 刷新轮换 / UserInfo / OIDC | `internal/protocolapi`：Authorize、WrongPKCE、TokenEndpoint、RefreshRotation、UserInfo、OIDC | 真实 oauthflow/oidc 服务与 HTTP 协议 |
| 设备码 / QR | `internal/protocolapi`：Device、QR | RFC 8628 设备码与扫码页流程 |
| 内省 / 响应脱敏 | `internal/protocolapi`：Introspection、ResponseAndAuditDoNotLeakSecrets | 在线令牌状态与防泄漏 |
| 真实 SQLite + httptest 协议 E2E | `internal/loginte2e`：RealProtocolAPI*、DeviceConfirmer、JWKS/ID Token | 真实迁移+领域服务+协议 HTTP 端点 |
| OAuth 客户端凭证/轮换/证书 | `internal/oauthclient` | 一次性秘密、轮换窗口、证书身份 |
| 公开 Go 协议门面 | `app`：ProtocolPublicIntrospection/Revocation | 公开 Introspect/Revoke 门面 |
| 会话+应用+权限联合判定 | `app`：SessionAuthorize/Validate/DeviceManagement | 真实会话与授权内核 |
| 应用隔离 | `app`：ApplicationAdminCrossAppIsolation | 应用范围管理员跨应用拒绝 |
| CSRF/来源/CORS/安全头 | `internal/transport`、`app` EmbeddedHTTP* | Cookie 会话 CSRF、Origin/CORS、页面安全 |
| 回环 TLS / mTLS 边界 | `internal/transport` Boundary*、`internal/serverapp` LocalTLS/ResourceE2E | 回环 TLS、客户端证书身份、可信代理/Host 边界 |
| 防枚举/认证错误码 | `internal/authn`：UniformFailure/DisabledGenericFailure/Lock/Redaction | 统一失败、锁定、审计脱敏 |
| 软件 TOTP | `internal/totp`：绑定/确认/登录/RFC6238/移除失效 | 真实 TOTP 服务与敏感策略 |
| 软件 WebAuthn | `internal/passkey`：软件认证器注册/登录/UV/origin/RPID/计数器 | 真实 Passkey 服务与软件认证器 |

## 3. 结果 JSON

单项结果 schema `evernight.protocol-selftest/v1`，主要字段：

| 字段 | 含义 |
|---|---|
| `status` / `exit_code` | `pass`/`fail`/`unavailable`/`timeout` 与稳定退出码 |
| `offline` / `concurrency` | 固定 `true`/`1`（`GOPROXY=off`，顺序执行） |
| `scenarios[]` | name/package/run/areas/status/pass/fail/skip/failed[]/duration_ms/detail |
| `coverage[]` | area → 覆盖场景名 |
| `summary` | 场景计数与 pass/fail/skip |
| `cleanup` | 子进程回收/临时产物说明（工具不创建持久临时目录） |

结果不包含会话秘密、客户端秘密、令牌、授权码、设备码、CSRF 或账户隐私；失败
`detail` 只保留测试名与截断后的排障文本（仓库绝对路径替换为 `<repo>`）。

## 4. 退出码与清理

| 退出码 | 含义 |
|---|---|
| 0 | 通过（允许 skip） |
| 1 | 有失败场景或注入失败 |
| 2 | 参数/场景名错误 |
| 3 | 环境不可用（缺 go、包编译失败等） |
| 4 | 结果 JSON 写出失败 |
| 130 | 总超时 |

- 每个场景通过 `exec.CommandContext` 启动 `go test`，超时/取消会终止该子进程；测试
  自身负责回收其临时 SQLite/回环监听/子进程（`t.Cleanup`）。
- 工具不创建持久临时目录；`-keep` 仅用于诊断日志（不改变清理语义）。
- 已知边界：不启动外部 Mail 进程、不做真实浏览器/真机 WebAuthn/USB 安全密钥；
  邮件投递与真实 Mail 子进程验收由 Mail 子模块与既有 e2e 脚本覆盖。GOPROXY=off
  要求依赖已在本地模块缓存中（仓库常规开发/CI 前置条件）。
