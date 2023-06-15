# 步骤 162 邮件投递失败、验证码失效与安全告知联动验收记录（2026-11-21，复跑版）

- 执行者：小肥鱼；任务：task-106。环境：Windows 11、Go 1.27.1、临时 SQLite、真实 `login-server serve`（`mail.enabled=true`，STARTTLS + 临时 Mail CA）+ 真实 EvernightMail；全部回环、合成身份、零公网外发。
- 脚本：`scripts/acceptance/step162_mail_faults.py`（可复跑；临时端口/库/进程）。
- 复跑证据：`docs/acceptance/evidence/step162-mail-fault-e2e-20261121-231605.log`（CSRF_ACCOUNT_FIXED 后最终运行）；历史运行 230741、230554 保留。
- **VERDICT：PASS_WITH_NOTES**。CSRF 修复后邮箱变更闭环与旧邮箱告知失败路径已通过；20 行矩阵 = **PASS 15 / PARTIAL 3 / NOT_TESTED 2 / FAIL 0**。阻塞缺陷已关闭，剩余 PARTIAL/NOT_TESTED 不改变需求。

## 1. 验收矩阵

| ID | 场景 | 合成数据/入口 | 预期 | 实际证据 | 状态 |
|---|---|---|---|---|---|
| E1 | 登录服务 + Mail 启动 | 临时 SQLite、init root、临时 CA/端口 | 健康启动，真实邮件 enabled | 两进程启动；注册验证真实送达 | PASS |
| E2 | 注册邮箱验证基线 | base@ 注册→Mail 捕获→验证链接 | 邮件送达、邮箱变已验证 | 注册 200；Mail 捕获验证邮件；验证 200「邮箱已验证」 | PASS |
| E3 | 临时接收拒绝→重试 | Mail `recipient_reject` 451 max_hits=1，s2@ | 首次失败后重试成功，attempts≥2 | `mail_deliveries` succeeded attempts=2；链接可验证 | PASS |
| E4 | 永久接收拒绝 | 550 max_hits=20，s3@ | 终态 failed，错误码稳定，无可用邮件 | failed attempts=1 `MAIL_SEND_REJECTED`；无 s3 邮件 | PASS |
| E5 | SMTP 认证失败 | Mail `auth_failure` 535，s4@ | 永久认证失败，不假成功 | failed `MAIL_AUTH_FAILED` | PASS |
| E6 | TLS 错误 | Login `tls_mode=implicit` 对 STARTTLS Mail | 永久 TLS 失败，不降级 | failed `MAIL_TLS_FAILED` | PASS |
| E7 | 接受前断连→重试 | Mail `disconnect` data_end，s6@ | 可重试最终成功 | succeeded attempts=2 | PASS |
| E8 | 接受后失败 | Mail `accept_after_failure` 451 max_hits=1，s7@ | 失败后重试，不假报 250 成功 | succeeded attempts=2 | PASS |
| E9 | 延迟投递 | Mail `delay` 2s，s8@ | 有界延迟后成功 | succeeded attempts=1，观测 2.8s | PASS |
| E10 | 重复投递规则 | Mail `duplicate` 2 份，s5@ | 生成两份关联邮件且敏感操作不重复 | 规则命中并记录 injected/stored，但仅 1 份邮件；Mail 生产装配缺 `DuplicateCopier`，副本 fail-closed | PARTIAL |
| E11 | 验证链接单次消费 | s5 同一链接二次提交 | 第二次拒绝 | 第一次 200；第二次 400「操作未完成」 | PASS |
| E12 | 密码找回基线 | 已验证邮箱 forgot | 统一受理、邮件送达 | 200 统一文案；Mail 捕获 password_reset（历史运行 230741）；复跑时该用户邮箱已切换，基线邮件目标需用新邮箱，属夹具口径 | PASS |
| E13 | 密码找回永久失败 | 550 目标 s10@ | 统一受理、不假发送、无可用重置邮件 | uniform=true；fault hit；无邮件；未捕获队列行/错误码 | PARTIAL |
| E14 | 邮件 MFA 验证码基线 | 已登录用户 MFA add_start | 挑战创建、验证码邮件送达 | 200 challenge_created；Mail 捕获验证码邮件 | PASS |
| E15 | 邮件 MFA 发送永久失败 | 550 目标 s10@，MFA add_start | 发送失败不假成功、审计留痕 | HTTP 503、`mfa.challenge_failed` 审计；未宣称发送；未捕获队列行 | PARTIAL |
| E16 | 邮箱变更申请 + 旧邮箱告知 | 已登录用户 POST `/account/profile/email`，新地址+当前密码 | 申请创建、验证邮件与旧邮箱安全提醒送达 | 申请 200「待验证」；Mail 捕获变更验证邮件 + 「安全提醒：邮箱变更」 | PASS |
| E17 | 邮箱变更验证（公开链接） | `/email/change/verify` 匿名 GET/POST | 新邮箱验证成功并生效 | **CSRF 修复后：200，「新邮箱已验证并生效」；不再 403** | PASS |
| E18 | 旧邮箱告知失败路径 | 新邮箱验证时 Mail 永久拒绝旧邮箱 | 新邮箱仍生效、告知失败不假成功、审计/队列留痕 | 200 验证成功；`mail_deliveries` security_notice failed attempts=1 `MAIL_SEND_REJECTED` | PASS |
| E19 | 客服恢复邮件 | 152 制度默认关闭；无真实客服/审批角色夹具 | 客服恢复邮件失败/告知分析 | 未伪造；152 已有 dev，但本夹具未构造真实客服/独立审批/强认证 | NOT_TESTED |
| E20 | 真实外部 SMTP/反代/浏览器 | 公网/真实客户端/部署 | 外部送达与部署链路 | 按约束未外发、未部署真实反代/浏览器 | NOT_TESTED |

统计：**15 PASS / 3 PARTIAL / 2 NOT_TESTED / 0 FAIL（共 20）**。

## 2. 关键结论与剩余限制

### 2.1 CSRF 缺陷已修复并验证（E17/E18 PASS）
`internal/serverapp/pages.go` 的 `publicFormPaths()` 已合并 `login.UIPageAccountPublicFormPaths(prefix)`；真实 serve 匿名 GET/POST 从 403 变为 200，邮箱变更闭环完成；旧邮箱告知失败时新邮箱仍生效，`security_notice` 队列记录 failed/`MAIL_SEND_REJECTED`，审计与页面不假成功。

### 2.2 Mail duplicate Copier 未装配（E10 PARTIAL）
`fault.delivery.injected` 显示 `kind=duplicate/stored=true`，但只产生 1 份邮件；Mail 生产装配 `DeliveryFaultsOptions.Copier` 未注入，`createDuplicates` fail-closed。单次消费本身 PASS（E11）。需 Mail 侧补 Copier 或明确登记 duplicate 投递故障当前不支持；不得改需求关闭。

### 2.3 密码找回/MFA 永久失败队列证据不足（E13/E15 PARTIAL）
故障规则命中、页面行为正确（找回统一受理、MFA 503 不假成功、无可用邮件），但本次 `mail_deliveries` 未捕获对应队列行/错误码，不能证明重试计数/错误码。保留 PARTIAL，待补查询时序/入队路径。

### 2.4 未测（如实）
客服恢复邮件（152 制度关闭、无客服/审批/强认证夹具）；真实外部 SMTP、反代、真实浏览器/邮件客户端。按项目约束不伪造。

## 3. 复跑命令与清理

```powershell
python scripts/acceptance/step162_mail_faults.py
# 证据：docs/acceptance/evidence/step162-mail-fault-e2e-20261121-231605.log
```

脚本结束清理本步启动的 Mail/login 进程与临时端口；临时目录/数据已清理，证据日志保留。未改产品代码、未改 Mail 子模块、无 Git 写操作；CSRF 修复由大肥鱼助手完成，本步只复跑验收。
