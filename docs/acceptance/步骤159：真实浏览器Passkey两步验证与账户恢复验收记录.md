# 步骤 159：真实浏览器 Passkey/两步验证/账户恢复验收记录（2026-11-21）

- 平台：Windows 11；Chrome **157.0.8103.79**（headless，CDP WebAuthn 虚拟认证器）；SQLite；回环 55000
- 执行者：中肥鱼；时间：2026-11-21 22:55–23:27（Asia/Shanghai）
- 基线：HEAD `200bfac`，脏候选树；证据 `docs/acceptance/evidence/step159/`
- 结论：**PARTIAL（Passkey 注册 + TOTP 绑定/登录已修复并通过；恢复代码生成与 Passkey 登录页仍有产品缺口）**；真实硬件/Windows Hello/读屏/非 Windows NOT_TESTED。
- 本步对产品做了最小页面级 reauth 修复；未做 Git 写操作；未改 Mail。

## 1. 最小修复（页面级 reauth）

| 文件 | 修复 |
|---|---|
| `ui_pages_security.go` | 新增可选 `UIPageSecurityReauthBackend`（`BeginTOTPWithPassword`/`FinishPasskeyRegistrationWithPassword`）；`UIPasskeyFinish` 增加 `CurrentPassword`（仅本次 reauth，不落库/日志） |
| `internal/uisecurityadapter/adapter.go` | 用真实 reauth `approve` 取得一次性批准后再调用真实 TOTP/Passkey 服务；策略仍由真实 reauth 判定，缺密码/弱认证 fail-closed |
| `ui_pages_security_handlers.go` | TOTP 绑定页/Passkey finish 表单接收当前密码并调用可选 reauth 后端；未实现扩展的后端保持原契约 |
| `web/templates/page/account/security_totp.html`、`security_passkeys.html` | 增加当前密码字段；不暴露 TOTP 种子/URI（诊断用一次性 URI 显示已在验证后移除） |
| 既有假后端测试 | 适配 TOTP 表单新增 current_password 字段 |

## 2. 验收矩阵

| ID | 场景 | 结果 | 证据 |
|---|---|---|---|
| 159-A | 真实 Chrome+虚拟认证器 Passkey 注册 | **PASS** | 真实浏览器 `navigator.credentials.create` 成功；finish **200**、Passkey 列表出现 `Step159 Virtual Key`；Chrome/CDP/认证器信息见日志 |
| 159-B | 密码登录 + Passkey 登录/可发现凭证 | **PARTIAL** | 密码登录 303 PASS；Passkey 登录页仍显示“当前部署尚未启用 Passkey 登录页面”，即使账户已注册 Passkey——登录页契约未接线，Passkey 登录/可发现凭证 NOT_TESTED |
| 159-C | TOTP 绑定 | **PASS（诊断证据）** | 页面级 reauth 后 bind_start 200，生成真实 URI/种子，确认后 TOTP 页显示已启用；**诊断时为自动化临时显示了 URI，验证后已移除，不在产品中明文暴露种子** |
| 159-D | TOTP 登录第二因素 | **PASS（诊断证据）** | 密码登录 303 → `/login/second-factor`，输入下一时间步真实 TOTP 码 → **303 `/home`**；同一时间步重放被 CHALLENGE_INVALID 拒绝（符合防重放） |
| 159-E | TOTP 解除/最后因素保护 | **NOT_TESTED** | 本步时间用于注册/登录/恢复缺口定位；未执行解除与最后因素保护组合 |
| 159-F | 恢复代码生成 | **FAIL（产品）** | 绑定 TOTP 后重新登录再生成仍 400 `MFA_REQUIRED`（“当前操作需要更强制认证”）；页面 reauth 只有当前密码，恢复代码要求强认证，缺少 TOTP/Passkey 二次验证 reauth 输入 |
| 159-G | 恢复代码消费→受限→重绑重登 | **NOT_TESTED（阻塞）** | 前置生成失败 |
| 159-H | 真实硬件安全密钥/Windows Hello/读屏/真机/非 Windows | NOT_TESTED | 虚拟认证器不能冒充硬件；项目规则非 Windows 不测 |

## 3. 关键证据

- `ENV`：Chrome 157.0.8103.79 + CDP virtual authenticator（ctap2/internal/resident/UV/automaticPresence）。
- `PASSKEY_FINISH 200`、`PASSKEY_STORED true`。
- `TOTP_BIND_START 200`、`TOTP_BIND_CONFIRM 200`、`TOTP_ENABLED true`。
- `LOGIN_WITH_TOTP_STATUS 303 /login/second-factor`、`SECOND_FACTOR_SUBMIT 303 /home`。
- `RECOVERY_GENERATE 400 MFA_REQUIRED`（绑定 TOTP 前后均复现）。
- `PASSKEY_LOGIN_PAGE ... 当前部署尚未启用 Passkey 登录页面`。
- 日志：`docs/acceptance/evidence/step159/browser-after-fix.log`（已删除 TOTP 种子/URI）、`browser.log`（修复前基线）、`baseline.txt`、`sanitized-login.yaml`。

## 4. 剩余缺口/建议

1. **恢复代码生成**：需要页面级 reauth 支持“TOTP/Passkey 第二因素”而不只是当前密码；当前 `approve` 固定 Password strength，`recovery.Generate` 要求 strong，因此即使账户已绑定 TOTP 也无法生成恢复代码。建议扩展页面 reauth 挑战（TOTP code/Passkey assertion）或按账户因素状态返回可满足的挑战；不得降级为仅密码。
2. **Passkey 登录页**：账户已有 Passkey 时登录页仍显示“尚未启用 Passkey 登录页面”，需要把 Passkey 登录页面/后端契约接入 `pages.go` 登录页装配；本步未改登录页契约。
3. **TOTP 解除/最后因素保护**、恢复代码消费/受限/重绑未执行，待上述缺口修复后重跑。
4. 真实硬件安全密钥/Windows Hello/读屏/真机/非 Windows NOT_TESTED。

## 5. 边界

- 临时 Chrome/login-server/SQLite/端口已停止/清理；未读取/修改仓库 DB、真实账户或真实邮箱；未真实外发。
- 诊断时一次性 TOTP URI 仅用于自动化，验证后已从产品模板移除；证据日志已脱敏为 `[REDACTED]`。
- 未做 Git 写操作；改动仅 ui_pages_security*/uisecurityadapter/web 模板/i18n + docs/scripts 报告，供 Lead 提交。

## 6. 追加修复轮（2026-11-21 23:27，90 分钟上限）

### 已确认可工作的部分（真实 Chrome 157 + CDP 虚拟认证器）
- Passkey 注册：真实 `navigator.credentials.create` → finish 200，Passkey 列表出现 `Step159 Virtual Key`。
- TOTP 绑定：页面级 reauth 通过后 bind_start 200、confirm 200、TOTP_ENABLED true。
- TOTP 第二因素登录：密码登录 303 → `/login/second-factor` → 下一时间步动态码提交 303 `/home`；同一时间步重放被 CHALLENGE_INVALID 拒绝。
- 证据：`docs/acceptance/evidence/step159/browser-after-fix.log`（已脱敏）。

### DEFERRED-159-RECOVERY（未完成，保持 PARTIAL）
- 恢复代码生成仍 **400 MFA_REQUIRED**（绑定 TOTP 前后均复现）。
- 根因：`recovery.Generate` 要求 strong 认证，而页面级 reauth 契约/实现只支持当前密码（password strength）；没有“当前密码 + 已有 TOTP 码/Passkey 断言”的 reauth 挑战输入。扩展需改 `internal/reauth`（挑战类型/验证信号）与 `internal/serverapp` 恢复认证级别装配，超出本轮最小写域/时间，且不能降级为仅密码。
- 涉及文件：`internal/reauth/*`、`internal/uisecurityadapter/adapter.go`、`internal/serverapp/security_domains.go`（恢复认证级别/装配）、`ui_pages_security*`、模板；需新增真实第二因素 reauth 后再调用真实恢复代码服务并重测消费→受限→重绑→重登。

### DEFERRED-159-PASSKEY-LOGIN（未完成，保持 PARTIAL）
- 已有 Passkey 时登录页仍显示“当前部署尚未启用 Passkey 登录页面”；仓库中**不存在**可接线的 Passkey 密码less 登录页面路由/契约（只有 Passkey 服务 BeginLogin/FinishLogin 与 MFA 第二因素页面）。
- 不是设置一个 `PasskeyLoginPath` 即可：需新增登录页路由/模板、`UIPageAuthBackend` 契约与真实适配器（会话签发、可发现凭证/用户名登录）、`serverapp/pages.go` 页面装配；涉及 `ui_pages_auth*`/`uiauthadapter`/serverapp/模板，超出本轮写域，须另派。
- TOTP 解除/最后因素保护、恢复代码消费链路依赖上述项，未执行。

### 追加边界
- 未修改 reauth 策略、未降级 MFA、未伪造 Passkey 登录成功；临时 Chrome/login-server/SQLite/端口已清理；未改 Mail；无 Git 写操作。
- 159 整体仍 **PARTIAL，不勾选完成**；Passkey 注册与 TOTP 绑定/二因素登录为已验证可交付子项。

## 7. 最终修复轮（2026-11-22 02:0x–02:3x）：VERDICT PASS_WITH_NOTES

- 新增真实脚本 `scripts/acceptance/step159_recovery.py` + `scripts/acceptance/webauthn_session.mjs`：真实临时 SQLite/login-server/回环端口 + Chrome 157 headless + CDP 虚拟认证器；临时 TOTP seed 与合成用户；不伪造认证。
- 真实结果（证据 `docs/acceptance/evidence/step159/step159-recovery-result.json`）：
  - 注册/密码+TOTP 登录 PASS；
  - 恢复代码生成 PASS（TOTP reauth；错误 TOTP 400）；
  - 恢复代码消费进入受限恢复 PASS；
  - 绑定新 Passkey（真实 WebAuthn create）PASS，返回新代码；
  - 重新登录 Passkey 第二因素 PASS；
  - **Passkey 密码less 登录 PASS**（可发现凭证，非密码降级）；
  - 旧恢复代码重放拒绝 PASS；
  - TOTP 解除/最后因素保护：**NOT_TESTED/SKIP**（自动化页面 CSRF 未通过，产品逻辑未改）。
- 产品修复：reauth strong TOTP、MinimumStrength、root MarkReady、mfa ready-root 第二因素、Passkey 恢复 binder、session RecoveryGate、Passkey 密码less 登录页。
- **159 VERDICT：PASS_WITH_NOTES**；真实硬件/Windows Hello/读屏/非 Windows NOT_TESTED；TOTP 解除与最后因素保护为剩余精确缺口。
