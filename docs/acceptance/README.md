# 验收记录索引

本目录保存在各阶段完成或交付核对时落盘的**验收与交付核对记录**。它们是当时环境、代码
基线下的证据快照，不随产品功能更新自动重写；与当前代码冲突时以代码与最新记录为准。

| 记录（文件名） | 内容 |
|---|---|
| `requirements-matrix-login.md` | 第一版需求矩阵：需求→代码→生产装配入口→页面/CLI/API→测试证据（24 章+不变量+缺口；PASS-A=0，非发布通过） |
| `OWASP_ASVS_第一版适用性对照.md` | OWASP ASVS 4.0.3 适用性内部自评与未覆盖项（**非认证、不宣称合规**） |
| `step156-authorization-write-e2e.md` | 管理 CLI/API 与权限一致性：真实强认证 authorized 写 E2E、版本冲突与拒绝路径 |
| `步骤158：Windows 与 SQLite 初始化、账户与权限端到端验收记录.md` | Windows+SQLite 初始化、账户/权限/客服流程端到端验收 |
| `步骤159：真实浏览器Passkey两步验证与账户恢复验收记录.md` | 真实 Chrome/CDP：Passkey 注册、TOTP、恢复码、受限恢复与密码less 登录 |
| `step160-oauth-external.md` | OAuth2/OIDC 外部互操作：Discovery/JWKS/授权码/设备码/扫码/令牌矩阵 |
| `step161-business-ui-support-isolation.md` | 业务管理前端、人工客服与应用隔离：真实强认证身份×A/B 应用矩阵 |
| `step162-邮件投递失败与验证码失效验收记录.md` | 真实 login-server + EvernightMail 故障投递：邮箱变更、找回、MFA 与失败路径 |
| `step163-audit-report-backup.md` | 审计报告、热备份、离线查看、恢复 apply/回退与旧凭据失效 |
| `step164-安全审查、依赖检查与有界并发回归记录.md` | 静态安全审查、依赖/构建/vet、有界并发与故障回归 |
| `step165-文档最终核对记录.md` | 产品文档最终核对：能力状态、配置/权限/迁移计数、链接与一致性检查 |
| `step166-release-build.md` | 最终发布验收：六目标构建、发布包校验、LICENSE/署名、Windows 冒烟 |

## 使用约定

- 这些记录不替代真实测试与发布校验；发布门禁、平台实测范围与“未验证”清单以最新记录
  与 `docs/deployment/` 的交付状态为准。
- 记录中的数字、路径、Git 提交与产物摘要都是**当时时点**的事实；后续步骤可能已改变代码
  与产物，引用时请同时注明记录来源。
- 对外交付只使用本目录与 `docs/` 下的正式产品文档；过程性草稿不随发布包。
