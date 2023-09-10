# 步骤 200：最终差距核对与关闭依据（PASS_WITH_NOTES）

- 执行：独立审计员 auditor9，2026-11-23 05:40–06:00（Asia/Shanghai）；只读核对，未改产品代码。
- **最终基线**：父仓库 `778fc226`（198 已提交）、EvernightMail `b9891ac569c7f5a0530ac74b73dfe8d5a9441b6e`（clean）、go-build-all `8764de6504db1ecd1ecc5c3d4dd6618b51699cf1`（clean）。
- 200 执行时主工作树仅有 **202 发布脚本 WIP**（`scripts/package-release.ps1` 未跟踪、`scripts/verify-release.ps1` 修改，共 3 项），**未混入**本结论；202 正式打包需在 200/201 提交后的干净树执行。
- 依据：需求正文 24 章、AGENTS §6/§10–§14、复验报告 R01–R06/A01–A08/§4 七项、156–199 验收与审计记录、198/199 独立 Windows 回归、195/196/197 证据、179 构建入口。**不以“编译通过/测试数量”代替验收**。

## 1. 最终结果

- **24 章：23 章 PASS_WITH_NOTES、1 章 N/A（第一版约定不做）；无 BLOCKED 的核心必交付功能。** 不关闭的是外部环境/硬件/第三方实测与本轮明确登记的 203 项，不是隐藏的核心功能缺失。
- 轻量复核：`go run ./scripts/verify-docs` = **PASS checks=12 failures=0**；`migrations/*.sql` = **49**（含 0048/0049）；权限目录 **51 键（49 Implemented=true / 2 false）**；错误码手册 **48**；202 发布包尚未生成（无 `dist/release`，脚本为 WIP）。
- 最终结论：**PASS_WITH_NOTES，可作为正式交付前基线**；唯一待完成交付动作是 **202 正式打包 + 独立校验**（打包后补 release evidence）；G157-11 CLI 帮助与 G157-13 权限边界已按 200 收尾小修关闭。

## 2. 24 章需求 → 最终状态 → 证据/缺口

| 章 | 最终状态 | 关键证据（提交/验收/审计） | 未关闭缺口/归属 |
|---|---|---|---|
| 1 范围与原则 | PASS_WITH_NOTES | 180–183 app 门面/装配；198 P1/P2 外部 Module 与嵌入运行时独立隔离树 rc0 | 无 core 缺口；外部部署生产化 NOT_TESTED |
| 2 运行形态/集成 | PASS_WITH_NOTES | 179 构建入口；180–183 embedded；201 接入手册 | 真实宿主部署/容器 NOT_TESTED |
| 3 页面与替换 | PASS_WITH_NOTES | 161 页面矩阵；187 强制下线页；189 权限页；190 应用删除；199 M1–M13 页面矩阵 | 真实浏览器视觉/读屏/窄屏 NOT_TESTED |
| 4 用户/资料/生命周期 | PASS_WITH_NOTES | 158/159/162；198 P3 注册/资料/登录页；199 用户列表 | 邀请/导入导出边界按既有记录；真实浏览器 NOT_TESTED |
| 5 登录与认证 | PASS_WITH_NOTES | 159 真实 Chrome/CDP Passkey/TOTP；198 P3/P4/P10；194 最后因素保护 | 真实硬件 Passkey/Windows Hello NOT_TESTED |
| 6 设备码与扫码 | PASS_WITH_NOTES | 192/193 + 198 P7/P8 真实协议/真实服务；160 历史 | 第三方客户端/手机相机 NOT_TESTED；142 old gaps closed |
| 7 两步验证与恢复 | PASS_WITH_NOTES | 159/162/188/194；198 P4/P9；199 M10/M11 真实 Mail 找回；197 queued | TOTP 强认证重绑 → D203-1；真实 Passkey ceremony → D203-2 |
| 8 敏感策略与告知 | PASS_WITH_NOTES | 162/186/187/197/199；197 真实 Mail queued→delivered、入队失败不提示已发送 | queued→delivered 终态回写/通知页展示 → 203；即时视图文案已在 197 修复 |
| 9 会话/设备/令牌 | PASS_WITH_NOTES | 187 页面/CLI/API 闭环；199 M6 外部 HTTP 撤销 200+DB+审计；198 P11 旧会话/令牌 | OAuth 独立撤销未实现为设计边界（已文档化）；跨应用 HTTP E2E 有 187/199 证据 |
| 10 应用登记与 OAuth/OIDC | PASS_WITH_NOTES | 160/191/192/193 + 198 P5/P6/P7/P8 真实协议矩阵 | 第三方 OIDC 客户端 NOT_TESTED；CLI help 仍过时（G157-11 小缺陷） |
| 11 组/角色/权限 | PASS_WITH_NOTES | 156/161 三端；184 应用管理员；185/189/190；199 M2–M5/M3 委派 | 51 键中 2 个 `Implemented=false`（settings.manage/diagnostics.read，已明确不授予预设；authorization.check 经 /oauth/token/authorize 标记实现） |
| 12 Token 联合校验 | PASS_WITH_NOTES | 144/145 复验；160/191；198 P5 UserInfo/Token；协议测试 | 真实第三方资源服务/外部部署 NOT_TESTED |
| 13 应用托管管理 API | PASS_WITH_NOTES | 146–148；199 页面/API 权限边界；198 页面/API 同源 | Webhook 真实外发 NOT_TESTED；YAML 配置化残余按既有记录 |
| 14 安全审计与日志 | PASS_WITH_NOTES | 73/74/93/94；195/199 审计样本；198 M13 | 真实部署日志轮转 NOT_TESTED |
| 15 审计报告与统计 | PASS_WITH_NOTES | **195 五格式真实生成/独立解析/下载/撤销**；199 M13 | GB 级/长时调度 NOT_TESTED；queued 通知关联 → 203 |
| 16 网络/TLS/安全 | PASS_WITH_NOTES | 164 安全审查/CSRF/限流；198 P10；199 拒绝路径 | 真实反代/HTTPS/mTLS/浏览器联调 NOT_TESTED；ASVS 非认证 |
| 17 数据库与模型 | PASS_WITH_NOTES | **49 条迁移**（0048/0049 含升级回归）；158/196 真实 SQLite | 非 SQLite 运行 NOT_TESTED（约定） |
| 18 备份与恢复 | PASS_WITH_NOTES | **196 真实恢复：会话/refresh/授权码/恢复码/重置链接/一次性凭证/JWT 密钥失效**；163 历史 | GB/跨机/真实 DACL NOT_TESTED |
| 19 离线备份查看/导出 | PASS_WITH_NOTES | 83/94/196；`login-backup` 全子命令 | 硬链接/DACL 逃逸边界 NOT_TESTED（低风险） |
| 20 CLI 与 root 应急 | PASS_WITH_NOTES | 186 再认证/187/188；199 CLI support reauth rc0；198/199 | root 真机强因素 NOT_TESTED；部分写动作设计边界 |
| 21 配置/扩展/运维 | PASS_WITH_NOTES | `verify-docs` checks=12 PASS；201 配置/权限/错误码同步；198 外部扩展 | 生产热更新故障场景 NOT_TESTED |
| 22 平台/文档/验证 | PASS_WITH_NOTES | 179 构建 24/24；202 脚本骨架干跑 PASS（待正式包）；Windows 实测 | 12 zip 正式包待 202；非 Windows 运行 NOT_TESTED |
| 23 第一版不包含 | N/A | 需求 §23/设计基线 | 约定不做，不作为缺口 |
| 24 修订摘要 | DOC/PASS_WITH_NOTES | 本文件+矩阵 v2.0；201 手册；202 packaging §9 | CLI help G157-11 小缺陷待修 |

## 3. 复验报告 R01–R06 关闭依据

| 编号 | 状态 | 关闭依据（提交/验收/审计） |
|---|---|---|
| R01 完整嵌入用户系统 | **CLOSED** | 180–183 app 门面/生命周期/HTTP/受信管理；198 P1/P2 独立隔离树外部 Module+嵌入示例 rc0；199 真实 SQLite 矩阵 |
| R02 Mail 配额/保留策略 | **CLOSED（Mail）** | 167–169 提交+审计；175 Mail 独立验收（62 PASS/0 FAIL/2 NOT_TESTED，固定 `b9891ac`） |
| R03 Mail 结构化测试/工具入口 | **CLOSED（Mail）** | 170 提交+审计；175 验收 29 项 CLI/Skill/管理入口 |
| R04 Mail 统计开关矛盾 | **CLOSED（Mail）** | 167 提交+审计；175 真实运行语义 |
| R05 Mail 重复投递 Copier | **CLOSED（Mail）** | 173 提交+审计；175 真实 duplicate 副本证据 |
| R06 应用管理员不能列出应用 | **CLOSED** | 184 提交+独立审计 PASS_WITH_NOTES；199 M1/M2 复跑 A/B 范围 |

## 4. 复验报告 A01–A08 关闭依据

| 编号 | 状态 | 依据/边界 |
|---|---|---|
| A01 完整嵌入运行时缺失 | **CLOSED** | 180–183 + 198 P1/P2；模块外公开 API 真实临时 SQLite 通过 |
| A02 邮件发送器未装配 | **CLOSED** | 197 队列+188 真实 Mail；198 queued 真实 Mail；199 M10 找回投递 |
| A03 设备码/扫码未装配 | **CLOSED** | 192/193 + 198 P7/P8 真实协议；142 历史缺口关闭 |
| A04 联合校验/托管 API 未接线 | **CLOSED（有边界）** | 144/145/160 + 199；真实第三方资源服务部署 NOT_TESTED |
| A05 仅 root 可转授 | **CLOSED** | 生产委派守卫；199 M3 委派测试 rc0 |
| A06 安全中心依赖 Passkey | **CLOSED** | 已修复；198/199 安全中心/页面证据 |
| A07 人工恢复无真实执行器 | **CLOSED** | 188 实现 + 199 真实 Mail E2E（申请/审批/执行/交付） |
| A08 管理员会话撤销未装配 | **CLOSED** | 186/187 页面+CLI+证明通道；199 M6 外部 HTTP revoke 200/revoked=1/DB/审计 |

## 5. 复验报告 §4 七项关闭依据

| 项 | 状态 | 关闭依据 |
|---|---|---|
| CLI 敏感操作 | **CLOSED** | 186 再认证 + 187/188；199 CLI support reauth rc0 |
| 前端管理完整性 | **CLOSED（GUI 未测）** | 187 强制下线页/189 权限页/190 删除；199 页面矩阵；真实浏览器 NOT_TESTED |
| OIDC UserInfo | **CLOSED** | 191 真实授权码→Token→UserInfo + 错误 audience；198 P5 复跑 |
| 设备码与扫码 | **CLOSED** | 192/193 + 198 P7/P8；手机/第三方 NOT_TESTED |
| 恢复与两步验证 | **CLOSED（硬件未测）** | 188/194 + 198/199 真实 Mail；D203-1/D203-2 保留硬件/TOTP 重绑 |
| 报告和备份 | **CLOSED** | 195 五格式真实生成/下载；196 旧凭据失效/审计合并/回滚边界 |
| 需求矩阵一致性 | **CLOSED** | 本文件+`requirements-matrix-login.md` v2.0 回填，G157-16/17 关闭，旧计数清理 |

## 6. 203 清单与用户须知

1. **D203-1**：TOTP 强认证重绑完整口径（当前 Passkey-only Q7；`AllowTOTPForStrongAuth` 等未实现）——203 排期，完成前不得宣称“Passkey 或 TOTP”完整。
2. **D203-2**：真实 Windows Hello/YubiKey Passkey ceremony 与 Windows 真机重绑流程；当前 188 用存储等价验证，198 用 Chrome 虚拟认证器。
3. **203 queued→delivered 终态回写/通知页关联/去重键强绑定/升级回归**（197 已修复“入队不误标已发送”，但执行完成即时视图曾把 queued 标成 sent；197 已改文案，203 继续补终态展示）。
4. **2 个权限目录键** `settings.manage`/`diagnostics.read` 保持 `Implemented=false`（无服务端执行路径），已从预设角色默认权限移除并在权限文档标“未实现（203，不授予预设）”；`authorization.check` 已按真实端点 `/oauth/token/authorize` 置 true 且不授予预设。
5. **G157-11 已修复**：`cmd/login-server/main.go` 的 `--help`/注释已改为“设备码与扫码登录已实现（192/193 验收边界，默认关闭）；introspection 仍未交付（143）；真实邮件外发未配置”，仅文案、不改能力开关。
6. 真实第三方 OIDC 客户端、手机相机、真实浏览器 GUI/读屏、非 Windows 运行、GB 级/跨机备份、真实反代/TLS/mTLS、压力/长时测试 **NOT_TESTED**（项目约定；不是“已通过”）。

## 7. 202 发布包（占位）

- 202 脚本骨架（`scripts/package-release.ps1`/`verify-release.ps1`，dev 报告已出）尚未提交；正式 12 个 per-target zip + SHA256SUMS/build-matrix/release-summary/RELEASE-NOTES **未生成**。
- 200 不对 202 产物签验收结论；最终打包后由 Lead 确认并补 `step202-verify` 独立校验（解压/哈希/短冒烟/许可/禁止项），届时本文件与需求矩阵引用其证据。

## 8. 结论

- **无阻塞核心必交付功能**：认证/授权/应用隔离/MFA/恢复/客服/OAuth/OIDC/设备码/扫码/页面/CLI/审计报告/备份恢复/构建入口均有固定版本真实 Windows/SQLite/本地 Mail 证据。
- **PASS_WITH_NOTES**：23 章 PASS_WITH_NOTES + 1 章 N/A；残余为 203 项与 NOT_TESTED 环境边界（G157-11/G157-13 已小修关闭）；202 发布包为唯一未完成的交付动作。
- 不得以本结论宣称“全平台/全硬件/第三方全部实测通过”；202 打包后须重新引用最终发布包证据并保留本文件的 NOT_TESTED/203 清单。
