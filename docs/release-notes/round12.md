# Evernight / EvernightLogin {{VERSION}} 发布说明

> 本文件由步骤 302 生成；版本、构建时间、三 commit、工具 SHA256 与 12 zip 表由
> `scripts/package-release.ps1` 从真实 `build-summary.json` 注入。以下“已完成/失败/未实现/未测”
> 分开陈述；不宣称绝对安全。

## 1. 版本与可追溯性

| 项 | 值 |
|---|---|
| 版本 | {{VERSION}} |
| 构建时间（UTC） | {{BUILD_TIME}} |
| EvernightLogin commit | {{LOGIN_COMMIT}} |
| EvernightMail commit | {{MAIL_COMMIT}} |
| go-build-all commit | {{TOOL_COMMIT}} |
| go-build-all SHA256 | {{TOOL_SHA256}} |
| 目标平台 | windows/amd64, windows/arm64, linux/amd64, linux/arm64, darwin/amd64, darwin/arm64 |
| 构建条件 | Go 1.27+ windows/amd64；CGO_ENABLED=0；GOMAXPROCS=2；GOTOOLCHAIN=local；GOWORK=off；-trimpath；-buildvcs=false；-ldflags="-s -w" |

本发布为**五程序 × 六平台 = 30 个编译组合**，发布包为 **12 个 per-target zip**：
Login 每目标 1 个 zip（含 login-server/loginctl/login-backup/login-setup 四个二进制），
Mail 每目标 1 个 zip（含 evernightmail）。

## 2. 已完成

### 2.1 身份、恢复与 MFA（第 11 轮交付，合并验收 300 复核）

- 找回令牌预检查/完成一致性、客服与人工恢复三权分离、直接改名/直接重置密码（操作者本次两步验证证明、目标绑定、新口令只写不回显、must_change、旧会话/找回失效）、会话强制下线与 root 保护。
- 普通 Web/HTTP/Go/远程 CLI 的管理写操作仍要求专门权限 + 一次 MFA；本地维护控制台的受控本地例外不改变远程边界。

### 2.2 公开 Go API、授权、生命周期与分页

- 公开 Go 门面、真实 SQLite、拒绝路径与审计/再认证边界证据；分页/搜索/稳定游标、能力映射与外部消费合同测试。
- 管理 JSON API 与机器契约：265 条既有管理路由契约、直接改名/改密、错误码/安全要求/请求响应约束；`adminapi-doc -check`、`reference -check`、`verify-docs` 门禁。

### 2.3 本地维护控制台（第 12 轮 277–299）

- `login-setup` 全屏 CUI/简化文本模式/同源非交互命令：无配置、坏配置、无数据库、结构待迁移、root 缺失均可诊断与修复；实例状态检测不修改数据库。
- 配置：字段分组编辑、覆盖来源、脱敏差异、草稿校验、外部修改冲突检测、原子保存/最后有效副本、秘密占位不覆盖；配置导入导出（脱敏 YAML、主密钥加密敏感包）与保留数据的推荐配置/预设角色恢复。
- 初始化与维护：数据库设置/幂等迁移/唯一 root 创建与进度恢复、常用账户方案、推荐配置一键应用；本地用户/身份/root 密码/MFA/角色组权限/应用成员凭证会话/审计诊断任务维护；完整实例重新初始化（危险菜单、精确路径/清除保留清单、排他锁、可恢复执行日志）。
- 备份与恢复：只读备份检查/主密钥认证验证/单项受控导出、受控恢复（维护锁+预演+恢复代际+旧凭证失效）；配置应用后的服务协调（单实例锁探测、热重载/需重启分类、一键启动本控制台子进程、失败安全停止、真实地址/证书/剩余初始化展示）。
- 维护证据：CUI 与非交互命令共用的维护锁+维护日志（started/success/failed）包装；维护日志不可写时阻止关键修改。

### 2.4 Mail、构建与发布

- EvernightMail 固定提交、独立产品文档/示例配置/许可证；Mail 远端仍不含本轮固定提交，源码通过本地交付归档（bundle）取齐，证据如实记录。
- 五程序 × 六平台 30 项构建、12 zip 打包、包结构/许可证/文档/资源/示例配置校验与 Windows 5 程序冒烟；发布证据绑定源码 commit/工具链/产物大小与 SHA256。

## 3. 失败

- 最终门禁执行结果以 `release-summary.json` 与发布证据为准；执行时如有失败/跳过在此如实列出，不以历史通过充数。
- 已知 flaky（环境/时序敏感，非稳定产品失败）：Windows 临时目录清理偶发非空、备份计划触发在极高负载下超时；门禁采用隔离复跑并记录。

## 4. 未实现

- 多实例高可用、运行时 Go plugin、完整多租户、第三方身份/短信/社交登录供应商为产品设计边界，不在本轮范围。
- 非 SQLite 数据库仅保留真实结构与配置/编译校验，未做运行验证。
- 真实硬件安全密钥/Windows Hello/YubiKey、真实手机相机扫码、真实第三方 OIDC 客户端、真实邮件外发未实现自动验收。

## 5. 未测

- 仅 **Windows/amd64** 运行实测（发布包五程序短冒烟 + 从零 setup 自动场景）；Linux/macOS/Windows arm64 仅编译/类型/摘要校验，不宣称运行。
- 未运行 MySQL/PostgreSQL/SQL Server；SQLite 为运行验证存储。
- 真实浏览器 GUI/读屏/窄屏、真实反向代理/TLS/mTLS、容器运行、Windows 服务托管、真实终端硬件未在本轮实测。
- 非公开/内部不变量仍以测试与审计证据为准；通过测试数或扫描器零告警不证明绝对安全。

## 6. 依赖、许可证与排除项

- 项目许可 MulanPSL2，署名 `KagurazakaYashi(KagurazakaMiyabi)`；Mail 保留其许可证与第三方声明。
- 发布包仅含产品文档 allow-list（guide/deployment/embedding/database/requirements/licenses/reference）与示例配置；
  不包含 `.ai`、`AGENTS.md`、`MEMORY.md`、开发脚本、测试证据/秘密、运行数据库与密钥材料。

## 7. 发布包与校验

{{ZIP_TABLE}}

顶层另含 `SHA256SUMS.txt`、`build-matrix.txt`、`release-summary.json`。正式校验入口：

```powershell
build.ps1 -OutputDir <build>
scripts/package-release.ps1 -Version <v> -BuildDir <build>
scripts/verify-release.ps1 -ReleaseDir <release> -ExpectedVersion <v>
```
