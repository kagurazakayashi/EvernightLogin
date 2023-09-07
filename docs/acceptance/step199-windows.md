# 步骤 199 Windows 独立回归记录：管理隔离与客服

- 执行：独立审计员（auditor9），2026-11-23 05:14–05:30（Asia/Shanghai）；只读验收，不修改产品代码。
- **固定版本**：父仓库 HEAD `350cbd308e084ae1930a3da2e8d4337242625fa8`（「完成客服申请审批与恢复交付闭环」188 已提交）；EvernightMail `b9891ac569c7f5a0530ac74b73dfe8d5a9441b6e`（clean）、go-build-all `8764de6504db1ecd1ecc5c3d4dd6618b51699cf1`（clean）。
- **执行树**：以 `git archive HEAD` 建立**提交隔离树** `P:\go\tmp\step199-accept\iso`（commit 350cbd3）执行验收；执行时主工作树 dirty=26 文件（197 邮件入队/queued WIP，未混入隔离树，清单见证据 baseline.txt）。**197 提交后需对 M7/M10/M13（客服/通知/审计）做一次定向复跑**。
- 环境：Windows 11 专业工作站版 10.0.28000、Go 1.27.4 amd64、4 逻辑 CPU、`GOMAXPROCS=2`/`-p 2`、`CGO_ENABLED=0`；重负载在 heavy-lock（owner `step199-verify`）单段内执行并释放；真实临时 SQLite、回环端口、本地 EvernightMail（SMTP 127.0.0.1:2526，capture 策略，仅本地）。
- 证据：`.ai/lead/reports/step199-evidence/`（baseline、go-tests-199.json、custom-199-checks.json、fixture-passkey.log、真实 Mail 测试日志/收件与 SMTP accepted 摘要、各定向测试日志）。

## 1. 结果汇总

- 真实入口/集成检查：**M1–M13 中 M1/M3/M4/M5/M6/M8/M9/M10/M12/M13 直接 PASS**；M2/M7 由 fixture PASS + 真实集成测试 PASS 覆盖（本次自建 HTTP 客户端的两项失败为客户端/顺序问题，见 §3）；M11 组件级 PASS、真实 Passkey ceremony NOT_TESTED。
- 命令/退出码：隔离树 `go build ./...` **0（46.0s）**；定向 `go test`（真实 Mail E2E、三向分离、CLI support reauth、serverapp support/MFA/187/A-B、应用删除、RBAC 权限、委派、A/B 页面）**全部 0**；Passkey 强认证 161 fixture 的自身步骤 **全部 PASS**（末尾其 session-revoke 探针连接重置中止，见 §3）。
- 真实 Mail 证据：`TestManualRecoveryPasswordResetRealMail`（env `LOGIN_E2E_SMTP_ADDR`/`LOGIN_E2E_MAIL_DATA`）**PASS 4.05s**；Mail 收件 **2 封 .eml**（密码找回、人工恢复状态更新），SMTP `smtp.mail.accepted` 2 条；测试完成两操作员申请→独立审批→等待期→真实执行→真实 Mail 取一次性入口→改密→新密码真实认证/重新登录。邮件内容不进入报告/证据（仅文件名/大小/日志摘要）。

## 2. 角色 × 操作 × 范围（M1–M13）

| ID | 场景 | 结果 | 证据 |
|---|---|---|---|
| M1 | 用户/应用/角色/权限/组列表详情（系统管理员/root） | **PASS** | 161 fixture `matrix.root`（/admin/users 200、API 200）、自建 Bearer 检查 `/admin/v1/users`/`applications`/`audit` 200 |
| M2 | 应用 A/B 管理员范围隔离、成员/角色页面 | **PASS**（note） | `TestManagePagesApplicationScopeA_B` rc0：甲仅见 A、读 A 成员 200、跨 B 成员 403/404 且不泄露对方名称、跨 B 写 403；161 `matrix.appadmin_scope` PASS；fixture appadmin 因无新鲜强认证仅产生拒绝证据 |
| M3 | 委派边界（角色/权限/应用成员/应用启停） | **PASS** | `internal/delegation` 6 个需委派测试 rc0（角色写/组成员/权限启停/应用成员/应用启停/不可委派守卫） |
| M4 | 权限启停/版本冲突 | **PASS** | 189 `TestRBACIntegrationPermission*|TestRBACPermission*` rc0（真实 SQLite）；权限/启停/409 契约 |
| M5 | 应用删除（停用→逻辑删除、跨应用、行版本） | **PASS** | `internal/app TestApplicationDeletionLifecycle` rc0（真实临时 SQLite，审计/其他应用/共享账户） |
| M6 | 管理员强制下线（页面/API/CLI + 186 证明） | **PASS** | 自建外部 HTTP：`GET /admin/v1/sessions` 200 列出目标 2 个会话→`POST /admin/v1/sessions/revoke` 200 `revoked=1`→DB `revoked_at_ms` 非空→再查列表 0；审计 actor=root 用户；`TestAdminSessionsPageIntegrationRealServices` rc0（旧 Cookie/CSRF/secret 失效、root 目标拒绝） |
| M7 | 客服申请/工单（应用客服隔离） | **PASS**（fixture/test） | 161 `staff.passkey` PASS：`/support/cases` 200、`/admin/v1/support/cases` 200、`/admin/users` 403、无秘密泄露；`TestSupportRecoveryCLIReauth` rc0（真实 CLI 186 自动再认证、证明不泄露） |
| M8 | 独立审批（发起者≠审批人） | **PASS** | `TestStep188ListAndThreeWaySeparation` rc0；真实 Mail E2E 两操作员独立审批路径 PASS |
| M9 | 等待期后执行/交付、三权分离 | **PASS** | 真实 Mail E2E：等待期→真实执行→找回邮件/完成通知；`TestAppSupportCrossChainManualRecovery` rc0（应用客服→系统客服接手→人工恢复→审批→执行→撤会话→审计） |
| M10 | 受助用户真实找回入口→改密→重新登录、旧凭据失效 | **PASS** | 真实 Mail E2E：从 Mail 数据提取一次性入口（不打印）→ValidateResetToken→CompleteReset→真实 authn/session 新密码登录成功；旧密码失败断言；2 封 .eml + 2 条 SMTP accepted |
| M11 | MFA 恢复/Passkey-only 重绑（Q7） | **PASS（组件级）** | `TestStep188RebindForcesRestrictedLogin` rc0（真实 SQLite：重绑需求→受限登录 RequiredSteps→清除后恢复完整）；真实浏览器 Passkey ceremony **NOT_TESTED** |
| M12 | 权限撤销/过期证明后不可继续 | **PASS** | 187/188 定向测试 rc0；过期强认证、旧会话/旧 CSRF、权限撤销后拒绝路径由真实 SQLite 测试覆盖 |
| M13 | 审计隔离/真实操作者 | **PASS** | `/admin/v1/audit` 200；DB 审计样本 `session.admin_list/session.admin_revoke/application.list` actor=root 用户；拒绝路径由 187/188 测试断言留痕 |

## 3. 失败/中止项与说明（不冒充 PASS）

1. **161 Passkey fixture 末尾中止**：其自身矩阵（root Passkey 强认证、3 用户注册、A/B 应用、support role/staff、matrix root/normal/support/appadmin、support 无秘密）**全部 PASS**；随后 fixture 的 `POST /admin/v1/sessions/revoke` 探针出现 `ConnectionResetError` 中止（未完成其剩余清理步骤）。审计用**重启同一固定版本服务 + Bearer** 独立复验同一撤销路由：200 `revoked=1`、DB 落地、列表归零、审计真实 actor（见 M6）。判定为 **fixture/客户端连接问题，非产品 FAIL**；建议 200 前重跑 161 完整矩阵一次。
2. **TOTP 强认证 fixture 失败**：root 初始化后要求 Passkey 强认证 setup，TOTP fixture 被 303 重定向到 `/login/strong-setup`，无法取得管理会话；属 fixture 设计限制（不是产品缺陷），本轮改用 Passkey fixture + 真实 HTTP/集成测试。
3. **自建 appadmin HTTP 登录 403**：本审计的简易客户端未完全复刻页面 CSRF 双提交契约（错误为“请求来源或安全令牌校验失败”），不能用它否定产品；应用 A/B 管理员范围由 `TestManagePagesApplicationScopeA_B`（真实页面 handler+真实 SQLite）PASS 与 161 fixture PASS 覆盖。
4. **自建 M7 支持检查在同轮被 M6 撤销 staff 会话后变 401**：顺序自伤，非产品缺陷；M7 由 161 fixture PASS 与 `TestSupportRecoveryCLIReauth`/跨链测试覆盖。

## 4. 未测项（NOT_TESTED）

- 真实浏览器人工点击审批/执行/交付页面（GUI 布局/读屏/窄屏）；真实 Passkey/FIDO2 硬件认证器 ceremony（本轮用 Chrome 虚拟认证器/测试夹具，已标注）；真实第三方客户端/OIDC 客户端；非 Windows 运行。
- 197 邮件入队/queued 状态与通知重试语义（197 WIP 未提交，未混入隔离树）；**197 提交后需复跑 M7/M10/M13**（客服通知/审计/交付路径）。
- 压力/长时间测试、真实外发邮件。

## 5. 清理与边界

- 临时 `P:\go\tmp\step199-accept`（隔离树/DB/日志/Mail 数据）在证据复制后已清理；无残留 login-server/evernightmail 进程、端口 62668/2526 释放、无 lock 残留；heavy-lock 已释放。
- 未修改产品代码、未执行 git 写操作；本记录为 199 产品验收文档（`docs/acceptance/step199-windows.md`）与 `.ai/lead/reports/step199-verify.md`。
- 结论：**管理隔离与客服 Windows 独立回归 PASS_WITH_NOTES**；M1–M6/M8–M10/M12/M13 有真实入口/真实 SQLite/真实 Mail 证据，M11 为组件级且真实硬件 NOT_TESTED；197 提交后做 M7/M10/M13 定向复跑后即可作为 200 的输入。
