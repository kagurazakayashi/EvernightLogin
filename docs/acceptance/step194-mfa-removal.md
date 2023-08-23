# 步骤 194：两步验证解除与最后因素保护验收记录

- 步骤：194（Max，MFA 链验收+修复）；执行者：小肥鱼；日期：2026-11-23（Asia/Shanghai）。
- 母仓库基线：`9abc5d1261dcac8a53dd31e50036af7fbd767194`（执行时 HEAD，未提交；工作区含
  并行步骤 181 的其它改动，本步未触碰 `app/`、`config*.go` 与 181 正在改的 serverapp 文件）。
- 环境：Windows 11 amd64、Go 1.27.4、4 逻辑 CPU（`GOMAXPROCS=2`、`-p 2`）。
- S2 写域：本步**未修改** `ui.go`、`internal/serverapp/pages.go`、`web/i18n/zh-CN.json`、
  `web/templates/{layout,component}`；页面/i18n 需求清单见第 6 节。
- 本记录是开发方自验证据，不替代独立审计复验；真实硬件 Passkey/FIDO2 未测。

## 1. 目标与关键发现

目标：最后一种 MFA 手段不可移除（或要求替代绑定）、TOTP 解除流程、Passkey 关闭时
TOTP/恢复代码/会话管理仍可用、弱邮箱不得替代高权强认证、失败默认拒绝与审计；删强因素后
security_version 失效、恢复码单次消费/受限恢复/重绑。

**关键缺陷（已修复）**：三个领域服务（mfa/totp/passkey）本身都实现了“最后因素不可移除”
保护，但生产装配 `internal/serverapp/security_domains.go` **没有注入任何强制 MFA 策略、
其他强因素来源与会话撤销器**（全部为 nil）→ 生产环境下：
- TOTP 解除：`Policy=nil` 时永不判定强制，却仍可移除（最后强因素保护形同虚设）；
- Passkey 撤销：`MFAPolicy/OtherStrongFactors/SessionInvalidator=nil` 同样不生效；
- 邮件 MFA 解除：`Policy=nil` 时不受“最后一个可用因素”保护。

且 `mfa.RemoveEmailFactor` 在强制 MFA 下**一律拒绝**，多因素账户（TOTP/Passkey 仍存在）
也无法解除邮件因素。

## 2. 改动文件（未碰 S2 文件）

| 文件 | 类型 | 改动 |
|---|---|---|
| `internal/securitycenter/securitycenter.go` | 新增包 | 真实生产适配器：`MFAPolicy`（把 authn 的 `StrongAuthRequired` 投影为 mfa/totp/passkey 的强制策略；读取失败返回错误=fail-closed）、`TOTPOtherStrongFactor`/`PasskeyOtherStrongFactor`（其他强因素存在性，未启用如实返回“没有”，查询故障返回错误） |
| `internal/securitycenter/securitycenter_test.go` | 新增 | 适配器契约测试：强制/未强制、来源故障 fail-closed、typed-nil 拒绝、其他强因素存在/不存在/未启用/故障 |
| `internal/mfa/service.go` | 修改 | `RemoveEmailFactor`：强制 MFA 下若仍存在其他强因素（TOTP/Passkey）则允许解除邮件因素；无其他强因素仍拒绝；强因素查询故障 fail-closed（`ErrPolicyUnavailable`）；成功审计增加 `remaining_strong_factor` 字段 |
| `internal/mfa/service_test.go` | 修改 | 新增“多因素账户允许解除邮件因素”“强因素查询故障 fail-closed 拒绝”两用例（原有“强制且无其他因素拒绝”保留） |
| `internal/serverapp/security_domains.go` | 修改（非 181 文件） | 真装配：`authnsqlite.New(deps.Store)` 作为 `StrongAuthRequired` 来源 → `securitycenter.NewMFAPolicy`；注入 mfa.Policy、totp.Policy/OtherFactors/SessionInvalidator、passkey.MFAPolicy/OtherStrongFactors/SessionInvalidator；为避免 Passkey↔TOTP 构造循环增加后接线适配器 |

未修改：`ui.go`、`pages.go`、`web/i18n/*`、`web/templates/{layout,component}`、`app/**`、
`config*.go`、`.gitmodules`、EvernightMail；未执行 Git 写操作。

## 3. 验收判据与证据

| 判据 | 证据 | 结果 |
|---|---|---|
| 最后强制因素不可移除（邮件） | `internal/mfa` `TestAvailableSecondFactorMethodsOnlyReturnsEnabled`：强制 MFA 且无其他强因素 → `ErrFactorRequired` | PASS |
| 多因素中解除一种（邮件） | 同测试新增用例：强制 MFA + `StrongFactorSource{has:true}` → 解除成功；故障来源 → `ErrPolicyUnavailable` | PASS |
| 最后强制因素不可移除（TOTP） | `internal/totp` `TestBindConfirmLoginRebindAndRemovalProtection`：强制 MFA 且无其他强因素时拒绝移除 | PASS |
| 允许解除 TOTP | 同测试：未强制/有其他强因素时正常解除并审计 | PASS |
| 删强因素 security_version 失效 | `internal/totp` `TestRemoveBindingInvalidatesExistingSessions`：解除后既有会话失效（security_version 递增 + 会话撤销） | PASS |
| 最后强因素不可移除（Passkey） | `internal/passkey` `TestRevokeProtectsLastStrongFactor` | PASS |
| 最后登录方式保护（Passkey） | `internal/passkey` `TestRevokeProtectsLastLoginMethod` | PASS |
| 恢复码单次消费 + 受限恢复 | `internal/recovery` `TestBeginConsumesCodeAndCreatesRestrictedSession`：原子消费、受限会话、受限会话不能访问业务/管理接口 | PASS |
| 重绑完成前不能访问业务 | 同上（`AuthorizeBusiness`/`AuthorizeManagement` 均 `ErrRestrictedSession`） | PASS |
| 恢复重绑生命周期 | `internal/recovery` `TestRebindCompleteLifecycle` | PASS |
| 高权不能降级成弱邮箱/弱证明 | `internal/recovery` `TestCompleteRequiresStrongProof`（无 UV 的 Passkey 证明不允许完成高权恢复）；`TestGenerateCodesLifecycle`/`TestBeginRejectsInvalidFirstStep`（root 保护）；mfa 强认证因素选择要求 `StrengthStrong`、邮件明确不合格（`internal/mfa/service.go` 注释与状态机） | PASS |
| 生产装配真实注入强制策略 | `internal/serverapp/security_domains.go` 已注入真实策略/其他强因素/会话撤销器；`go build ./internal/serverapp` exit 0 | PASS（编译） |
| 失败默认拒绝与审计 | 各领域拒绝路径写失败审计；策略/存储/强因素查询错误 → `ErrPolicyUnavailable`/fail-closed（适配器测试与领域测试覆盖） | PASS |
| Passkey 关闭时 TOTP/恢复码/会话管理仍可用 | `internal/serverapp/pages.go` 安全中心注册条件为 MFA/TOTP/Recovery/Sessions/Reauth 存在（与 Passkey 无关）；`uisecurityadapter.GetOverview` 恒报 TOTP/Recovery/Sessions 可用、Passkey 可选；模板已显示“Passkey 未启用”而保留 TOTP/恢复码/会话入口（步骤 159 页面证据） | PASS（代码/既有页面证据） |

## 4. 真实执行命令与结果

```powershell
$env:GOMAXPROCS='2'
go vet ./internal/securitycenter ./internal/mfa
# 退出码 0

go test -count=1 -p 2 ./internal/securitycenter
# ok ... 0.664s   退出码 0

go test -count=1 -p 2 -run 'TestAvailableSecondFactorMethodsOnlyReturnsEnabled' -v ./internal/mfa
# --- PASS (8.24s)   ok ... 8.442s   退出码 0

go test -count=1 -p 2 -run 'TestBindConfirmLoginRebindAndRemovalProtection' -v ./internal/totp
# --- PASS (0.35s)   退出码 0

go test -count=1 -p 2 -run 'TestRemoveBindingInvalidatesExistingSessions' -v ./internal/totp
# --- PASS (0.33s)   退出码 0

go test -count=1 -p 2 -run 'TestRevokeProtectsLastStrongFactor|TestRevokeProtectsLastLoginMethod' -v ./internal/passkey
# 两用例 PASS   ok ... 1.850s   退出码 0

go test -count=1 -p 2 -run 'TestGenerateCodesLifecycle|TestBeginConsumesCodeAndCreatesRestrictedSession|TestBeginRejectsInvalidFirstStep|TestRebindCompleteLifecycle|TestCompleteRequiresStrongProof' -v ./internal/recovery
# 五用例 PASS   ok ... 3.528s   退出码 0

go build ./internal/serverapp
# 退出码 0（生产装配接线可编译）
```

说明：尝试取全局 heavy-lock 时被 `step184-dev` 持有（acquire 120s 超时），上述均为 <10s 的
定向单包测试，按纪律不加锁执行；未持有/未遗留任何锁。

## 5. 未测/限制（如实登记）

1. **未跑真实浏览器页面级最后因素解除 E2E**：本步受 S2 写域限制，未改页面/i18n；页面流程
   以既有步骤 159 真实 Chrome 证据（TOTP 绑定/登录、Passkey 注册）+ 本步服务层证据为准。
   建议合并窗口后由审计用真实服务跑一次“强制强制账户解除 TOTP 被拒绝”的页面级 E2E。
2. **邮件因素解除未递增 security_version/撤销全部会话**：mfa 存储当前没有用户
   security_version 更新接口（强因素 TOTP/Passkey 解除已递增并撤销会话）。邮件是弱因素，
   影响面小于强因素；已在报告残留问题登记，如需一致化需扩展 mfa.Store（另立小任务）。
3. 真实硬件 Passkey/FIDO2（YubiKey 等）未测；虚拟认证器/服务层替身已区分标注。
4. `internal/serverapp` 生产装配的**行为级**测试未跑（181 并行改同包，避免构建态冲突）；
   仅验证编译通过 + 领域/适配器单测；建议合并后跑 serverapp 集成测试或真实服务页面 E2E。
5. 未做压力/长时间测试；未真实外发邮件（邮件 MFA 相关路径未在本步触发真实发送）。

## 6. S2 待接入清单（供合并窗口转交 S2 持有者）

本步盘点后**未发现必须新增的 S2 页面/i18n**：TOTP 解除表单（动态码 + 当前密码）、邮件因素
解除（当前密码）、恢复码生成（密码 + TOTP 码）、Passkey 撤销、会话管理入口在既有模板
（`page/account/security*.html`）与 i18n 中已存在（步骤 159 已接入）。可选改进（非阻塞）：
- 在“强制 MFA 时拒绝移除最后因素”的页面错误提示中复用/确认 `error.business.MFA_REQUIRED`
  i18n 文案清晰说明“最后一个强因素不可移除”；
- 安全中心概览（`security.html`）可为“强制 MFA”账户增加只读说明（当前仅显示启用状态）。

## 7. 结论（开发方自验）

- 修复了生产装配未注入强制 MFA 策略的关键缺陷：三个领域的“最后因素不可移除”保护现在在
  真实装配中生效；多因素账户可正常解除弱因素/一种强因素；强因素解除后 security_version
  递增并撤销既有会话；恢复码单次消费、受限恢复、重绑前禁业务、高权不得弱证明均有真实
  服务测试证据。
- 未改 S2 页面/i18n；页面级最后因素拒绝 E2E 与邮件因素 security_version 一致化列为残留，
  建议审计/后续小任务处理。
- 未发现需要放松任何安全校验的需求；所有失败路径默认拒绝并写审计。
