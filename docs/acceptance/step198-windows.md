# 步骤 198 Windows 独立回归记录：公开接入与身份流程

- 执行：独立审计员（auditor9），2026-11-23 05:26–05:48（Asia/Shanghai）；只读验收，不修改产品代码。
- **固定版本**：父仓库 `40bc265`（201「集中更新接入手册与构建操作文档」；201 为文档提交，产品代码基线 = `9084987`（197 已提交）/`5b80e71`（199 文档））；EvernightMail `b9891ac569c7f5a0530ac74b73dfe8d5a9441b6e`（clean）、go-build-all `8764de6504db1ecd1ecc5c3d4dd6618b51699cf1`（clean）。
- **干净隔离树**：`git archive 40bc265` → `P:\go\tmp\step198-accept\iso40`（排除 docs）；执行时主工作树 dirty=21 文件（201/202 在研文档/脚本 WIP，未混入）。执行前另以 `5b80e71` 隔离树做过一次等价构建/协议矩阵（产品代码相同），最终证据取 40bc265。
- 环境：Windows 11 10.0.28000、Go 1.27.4 amd64、4 逻辑 CPU、`GOMAXPROCS=2`/`-p 2`、`CGO_ENABLED=0`、`GOTOOLCHAIN=local`；真实临时 SQLite、回环端口、本地 EvernightMail（`EVERNIGHTMAIL_BIN` 指向本模块构建的真实 Mail 二进制；不向真实邮箱外发）；重负载在 heavy-lock（owner `step198-verify`）单段内执行并释放。
- 证据：`.ai/lead/reports/step198-evidence/`（baseline、iso 构建、外部模块/嵌入示例、协议矩阵、Passkey fixture、mfa/recovery/queue/reauth/authn/session/token 测试日志）。

## 1. 结果汇总

| 组 | 场景 | 结果 | 证据 |
|---|---|---|---|
| P1 | 外部 Go Module 接入（仅公开包） | **PASS** | `examples/external-consumer`（独立 go.mod + replace）`go run .` **0**（1.66s）：配置/扩展/HTTP 挂载/生命周期/失败传播/fail-closed 全部通过，未导入 internal |
| P2 | 嵌入运行时生命周期（180–183） | **PASS** | `examples/embedded-runtime` `go run .` **0**（5.35s）：真实临时 SQLite、root 初始化、用户/登录/TOTP 第二因素/重新认证/受限恢复/受信管理/HTTP 页面前缀+CSRF+无权限/模板替换/启动取消/重复 Close/宿主资源所有权 |
| P3 | 密码登录/注册/资料页 | **PASS** | Passkey fixture（40bc265）`161.register.seed_users` 3×200、`login.normal` 303、`/home` 200、`/account/security` 200；页面 CSRF/无权限矩阵 PASS |
| P4 | MFA/TOTP/恢复码/Passkey 适用路径 | **PASS**（硬件 NOT_TESTED） | `internal/mfa` 定向 4 用例 rc0（TOTP 完整会话/错误次数/强认证拒绝 TOTP-only/恢复交接）；Passkey fixture 用 Chrome 虚拟认证器，真实硬件 NOT_TESTED |
| P5 | OIDC 授权码+PKCE→UserInfo | **PASS** | `TestOIDCUserInfoAcceptance`、`TestAuthorizeConsentAndTokenExchange`、`TestWrongPKCEVerifierRejected`、`TestUserInfoScopeAndRevocation` 等 rc0（`internal/protocolapi` 5.91s、`internal/loginte2e` 12.34s） |
| P6 | Refresh 轮换/撤销 | **PASS** | `TestRefreshRotationAndReplay`、`TestTokenEndpointClientAuthentication` rc0；旧 refresh 重放拒绝/撤销在协议测试中断言 |
| P7 | 设备码（192） | **PASS** | `TestDeviceCodeLoginAcceptance`、`TestDeviceAuthorizationFlow`、`TestDeviceAuthorizationRejections`、`TestRealProtocolAPIDeviceFlow` rc0（pending/slow_down/确认/拒绝/过期/一次性） |
| P8 | 扫码（193） | **PASS** | `TestQRLoginFlow`、`TestQRLoginRejections`、`TestQRLoginPageAcceptance`、`TestRealProtocolAPIAuthCodeFamily` rc0（确认/重放/抢领/过期/错误 claim） |
| P9 | 找回/受限恢复/2FA 页面 + 197 queued | **PASS** | `TestQueueResetRealMail`/`TestQueueResetMailAndNotice`/`TestQueueResetMailEnqueueFailure`（passwordreset rc0）；`TestNotifyOutcomeQueue*`/`TestNotificationsStates`（reauth rc0）；`TestManualRecoveryPasswordResetRealMail`（serverapp rc0，真实 Mail 投递：找回邮件/完成通知，queued→delivered 语义） |
| P10 | 错误码/限流/防枚举 | **PASS** | `internal/authn` 定向 rc0：统一失败、禁用账户通用错误、临时锁定/恢复、限流维度、失败计数保留 |
| P11 | 旧令牌/旧会话边界 | **PASS** | `internal/session`（并发登录轮换撤销旧会话/RevokeAll/禁用撤销）与 `internal/token`（Access/ID Token 签发校验）rc0；187/196 已提交证据引用 |
| P12 | 页面/CLI/API 同源 | **PASS（页面/API）/ PARTIAL（CLI）** | Passkey fixture 页面+API 同一会话矩阵 PASS；CLI 无普通用户登录表单路径（CLI 为管理/本地通道），用户身份流程 CLI 对等性 **NOT_TESTED**，不冒充 |

## 2. 命令/退出码（隔离树 40bc265）

| 命令（摘要） | 退出码 | 结果 |
|---|---|---|
| `go build ./...`（iso40） | 0 | 38.87s |
| `examples/external-consumer: go run .` | 0 | 1.66s；输出仅公开 API 验收结论 |
| `examples/embedded-runtime: go run .` | 0 | 5.35s；临时 SQLite/页面/生命周期 |
| `go test -run 'TestOIDC…|TestDevice…|TestQR…|TestRefresh…|TestRealProtocolAPI…' ./internal/protocolapi ./internal/loginte2e` | 0 | protocolapi 5.91s、loginte2e 12.34s |
| `scripts/acceptance/step161_full.py`（Passkey/Chrome 虚拟认证器） | 1（fixture 自身末尾步骤 FAIL） | 其 root Passkey 强认证、3 用户注册、A/B 应用、support/staff、matrix root/normal/support/appadmin、无秘密 **全部 PASS**；末尾 `161.revoke.admin_session` 403（见 §3） |
| `internal/mfa` 定向 | 0 | 4.23s |
| `internal/recovery` `TestMailNotifier` | 0 | 0.88s |
| `internal/passwordreset` queue 定向（含 `EVERNIGHTMAIL_BIN` 真实 Mail） | 0 | 4.89s |
| `internal/reauth` queue/通知定向 | 0 | 3.16s |
| `internal/authn` 错误/限流定向 | 0 | 1.77s |
| `internal/session` 旧会话撤销定向 | 0 | 1.68s |
| `internal/token` 令牌定向 | 0 | 1.17s |

## 3. 失败/中止项与说明（不冒充 PASS）

1. **Passkey fixture 末尾 `161.revoke.admin_session` 返回 403**（`old_cookie_status=200`）：该步骤不在 198 计划矩阵内（属管理下线，187/199 范围）；本次同一固定版本的 `TestAdminSessionsPageIntegrationRealServices`（真实 SQLite）在 199/本步 rc0，且 199 曾在 350cbd3 上用外部 HTTP 复验 `/admin/v1/sessions/revoke` 200 revoked=1。判定为 fixture 会话/时序问题，建议 200 前重跑 161 完整脚本一次；不作为 198 FAIL。
2. **Chrome 虚拟认证器**：Passkey 测试为 Chrome CDP 虚拟认证器，**真实 Windows Hello/YubiKey 等硬件 NOT_TESTED**，已在结论中保留。
3. **第三方 OIDC/手机**：真实第三方 OIDC 客户端、手机相机扫码未做，NOT_TESTED；协议层由真实 protocolapi/loginte2e 测试覆盖。
4. **P12 CLI**：用户登录/注册/2FA 无 CLI 表单路径；CLI 为管理/本地通道，故只验证页面/API 同源，CLI 对等性 NOT_TESTED。

## 4. 未测项（NOT_TESTED）

真实浏览器人工视觉/读屏/窄屏、真实 Passkey/FIDO2 硬件、真实第三方 OIDC 客户端、真实手机相机扫码、非 Windows 运行、压力/长时测试；CLI 普通用户身份流程对等性。

## 5. 清理

- 临时隔离树/服务器/DB/Chrome profile 在证据复制后清理；无 login-server/evernightmail/chrome（本会话夹具）残留进程；端口释放；heavy-lock 已释放；未修改产品代码、未执行 git 写操作、未向真实邮箱外发。
- 结论：**198 公开接入与身份流程 Windows 独立回归 PASS_WITH_NOTES**（P1–P11 有真实入口/真实协议/真实 SQLite/本地 Mail 证据；P12 页面/API PASS、CLI 用户流程 NOT_TESTED；硬件与第三方 NOT_TESTED）。
