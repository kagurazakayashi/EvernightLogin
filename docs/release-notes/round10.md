# Evernight / EvernightLogin {{VERSION}} 发布说明

> 本文件由步骤 248 生成；版本、构建时间、三 commit、工具 SHA256 与 12 zip 表由
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
| 构建条件 | Go 1.27.4 windows/amd64；CGO_ENABLED=0；GOMAXPROCS=2；GOTOOLCHAIN=local；GOWORK=off；-trimpath；-buildvcs=false；-ldflags="-s -w" |

## 2. 已完成

### 2.1 身份、恢复与 MFA

- 找回令牌预检查/完成一致性（204/205/206）：预检查不消费、完成改密单事务可重试、密码/邮箱安全变更使旧找回链接失效、防枚举统一失败语义；真实 SQLite + 邮件链路有成功/拒绝/并发/审计回滚证据。
- 客服恢复后的 TOTP 安全重绑（209）：MFA 恢复后受限重绑，真实密码 + TOTP，旧会话/旧因素失效路径有测试。
- 客服与人工恢复（229）：申请/审批/执行三权分离、受保护目标拒绝、等待期/批准过期、审计回滚；公开 Go 门面与真实 SQLite/本地邮件捕获证据。
- 身份恢复与应用隔离跨步骤安全回归（246）：找回全链、改密使 pending 找回失效、找回不解除 MFA、共享账户双应用成员/角色撤销即时隔离；4/4 回归 PASS，`go test ./app/` 全包 PASS。

### 2.2 公开 Go API、授权、生命周期与分页

- 能力清单与统一短测试入口（203）；公开查询 NOT_FOUND 契约（207）；嵌入入口可信来源与限流边界（208）。
- 注册/资料/邮箱生命周期公开接口（221，P0）、认证因素/安全中心（222）、用户生命周期（223）、角色/组/权限（224）、应用凭证/成员委派（225）、会话/OAuth 授权（226）、令牌内省（227）、令牌撤销（228）、审计/报告（230）、备份/恢复（231）、配置管理（232）、脱敏诊断（233）、账户有效期（234/235）均有公开 Go 门面、真实 SQLite、拒绝路径与审计/再认证边界证据。
- 分页闭环（216/217/218/219）：用户/角色、应用成员/会话、审计/报告/任务、Mail 文件/管理列表；稳定游标/授权先于分页/有界。
- 公开接口覆盖验收（236）：能力目录从 42 扩到 **43**，`capabilities -strict` **EXIT 0**，未覆盖生产面 0、分页未覆盖 0；新增 external-consumer 公开类型合同测试。
- 公开运行时契约与目录依赖收敛（215）：公共契约包/依赖检查/外部 Module 回归；质量审计 PASS_WITH_NOTES。

### 2.3 根 UI、文档与示例

- 根 UI 实现与资源迁移到公共 `ui` 包（214）；根 README/嵌入/部署/管理文档收敛（244）；人类与 AI 共用接口参考（245A/245A2）：`docs/reference` 14 文件，`reference -check` PASS，`verify-docs` checks=13。
- 最小嵌入示例（240，15 项 self-test）、自定义页面/资料同步（241，23 项）、应用委派与客服（242，11 项）、外部消费合同（236）均通过独立 module 构建/测试与统一短测试场景。
- 运维数据与示例回归（247）：真实备份→报告/审计/诊断→恢复一致性（旧会话失效、备份后数据消失、诊断脱敏）；四示例 self-test/统一入口全 PASS，新增 external-consumer 冒烟场景。

### 2.4 Mail 与构建/发布

- EvernightMail 文件/管理分页（219）、证书导入 API/CLI（237）、管理操作与 AI 使用覆盖（238）；238 安全首审 HIGH 已复验关闭。
- 一键构建入口与可追溯清单（239）：四产品 × 六目标 = 24 项，manifest/大小/SHA256/PE-ELF-Mach-O 独立校验通过。
- 本发布包由 `build.ps1`（24/24、dirty=false、warnings=[]）→ `package-release.ps1`（12 zip、产品 docs、四段发布说明）→ `verify-release.ps1`（结构/许可/摘要/Windows 冒烟）生成；发布包校验结果见第 7 节。

## 3. 失败

- 本发布构建/打包/校验未出现失败；正式 24 项构建 EXIT 0、12 zip 打包与 `verify-release` 结果见第 7 节。
- 已知低风险/边界（不阻塞本发布，登记于 `.ai/handoff/DEFERRED_ISSUES.md`）：
  - R10-16：邮箱 A→B→A 重新验证后，同 TTL 内旧找回链接可再次满足邮箱绑定（LOW；后续撤销 pending/邮箱代际）。
  - R10-18/R10-19：MFA 强初始化复算与清除间窄 TOCTOU；预提升会话 TOTP 残留属受限 fail-closed（LOW）。
  - R10-20：管理员批量导出视图对 owner/受信可见服务器绝对路径（LOW，不越权）。
  - R10-30：`uiadminadapter` Audit==nil 时跳过 requested 审计；生产装配已注入，nil 路径不触发（LOW）。
  - R10-09：人工恢复安全告知的 Enqueue 丢弃投递 ID，终态不可回查（幂等键仍防重复）。
  - R10-03/R10-05/R10-11：个别错误缺 RequestID、受限角色存在性轻微信息面、高权限升级过渡窗口未复算（LOW/INFO）。
  - R10-17：Mail 证书导入实际上限 1 MiB 与文档 24 MiB 不一致（大证书链可能被拒）。
- 已知 flaky：Windows 临时目录清理偶发 `TempDir RemoveAll cleanup: directory is not empty`（app 全量段首次出现，隔离重跑与本地 TEMP 下 PASS）；`internal/backupadmin/sqlite` 计划触发等待曾在高负载下超时，隔离复跑 PASS。均为环境/时序敏感，非稳定产品失败；正式门禁采用分段与隔离复跑并如实记录。

## 4. 未实现

- 221 完整范围：本轮仅 P0 公开 `app` 门面；独立 example 模块、HTTP/CLI/页面未做（R10-22）。
- 218 P1：安全通知分页、邮件投递记录端点/权限、通用 `/admin/tasks` 页面、迁移 0052 复合索引性能优化未做（R10-23）。
- 多实例高可用、运行时 Go plugin、第三方身份证/身份供应商、短信/第三方账号登录供应商为产品设计边界，不在本轮范围。
- 真实非 SQLite 运行：适配/翻译存在但未运行验证，归入第 5 节未测，不写成“已实现运行”。

## 5. 未测

- 仅 **Windows/amd64** 运行实测（发布包四命令短冒烟）；Linux/macOS/Windows arm64 仅编译/类型/摘要校验，不宣称运行。
- 未运行 MySQL/PostgreSQL/SQL Server；SQLite 为运行验证存储。
- 真实硬件 Passkey/Windows Hello/YubiKey、真实手机相机扫码、真实第三方 OIDC 客户端未测；软件 WebAuthn/Chrome 虚拟认证器不等于硬件互操作。
- 真实浏览器 GUI/读屏/窄屏、真实反向代理/TLS/mTLS、容器运行、Windows 服务托管、PowerShell 7 未在本机实测。
- 真实外部 SMTP/Webhook 外发未测（示例/测试使用本地捕获器）。
- GB 级/跨机备份恢复、大规模报表/通知、多实例高可用未测；恢复测试使用临时 SQLite 小数据集。
- `-race`、govulncheck/gosec 未跑（CGO/环境限制）。
- 发布包其他五个目标的真实运行、真实业务数据迁移未测；12 zip 只做文件/类型/架构/摘要/许可校验与 Windows/amd64 冒烟。

## 6. 包内容与安装

- Login 包：`bin/{login-server,loginctl,login-backup}[.exe]`、`LICENSE`、`README.md`、`THIRD_PARTY_NOTICES.txt`、产品 `docs/`（README/guide/deployment/embedding/database/requirements/licenses/reference）、`README-PACKAGE.txt`、`VERSION.txt`、`BUILDINFO.txt`、`DEPENDENCIES.txt`、包内 `SHA256SUMS.txt`。
- Mail 包：`bin/evernightmail[.exe]`、许可证/第三方声明、`evernightmail.example.yaml`、选定 Mail 文档、元数据与包内 `SHA256SUMS.txt`。
- 不随包：`docs/acceptance/`、`docs/evidence/`、`examples/`、`scripts/`、`tools/`、测试夹具/秘密、数据库/日志/密钥、开发协作材料；包内产品文档对应链接已改写。
- Linux/macOS 解压后需 `chmod +x bin/*`（zip 不保留执行位）；PDF 报告字体不随包，需外部获取。

## 7. 验证与校验

| 项 | 结果 |
|---|---|
| gofmt（1266 个跟踪 Go 文件） | 0 未格式化 |
| `go vet ./...` / `go build ./...` | EXIT 0 / EXIT 0 |
| 全量 `go test`（174 包分段：A 158s + app 重跑 37s + B1 170s + B2 149s） | PASS；app 段首轮 TempDir 清理抖动，隔离重跑与本地 TEMP 下 PASS；F3 未复现 |
| 9 个 examples module build+test | 全 EXIT 0 |
| shorttest：embedded/custom/app-delegation/external-consumer/login-server-smoke | 全 PASS；harness-timeout 预期 TIMEOUT（入口自检） |
| `verify-docs` | PASS checks=13 failures=0 |
| `capabilities -strict` | EXIT 0：43/43 implemented，missing 0，未覆盖 0，分页未覆盖 0 |
| `docs/reference -check` | PASS（14 文件；2 条口径 WARN，见审计） |
| `build.ps1` 24 项 | EXIT 0，24/24 verified，dirty=no，warnings=0；构建耗时约 325s |
| `package-release.ps1` | EXIT 0：12 zip + 产品 docs/四段 RELEASE-NOTES；输出 `dist/release/evernight-0.1.0-dev` |
| `verify-release.ps1`（非 SkipBinaryRun） | **PASS**：12 zip/顶层 SHA256SUMS/矩阵/包内文件集合/许可/元数据/PE-ELF-Mach-O/Windows amd64 四命令冒烟全部通过 |
| Windows/amd64 自包含冒烟 | `login-server --version`、`loginctl --version`、`login-backup version` 均为 `0.1.0-dev (commit 2e2cc6e7257cd9fbebfbff83ea1dac6769edf4f2)` exit 0；`login-server --help`、`evernightmail --version` exit 0 |
| 负向临时副本 | 删除 `RELEASE-NOTES.md` 四段之一 → `verify-release` exit 30；从 zip 删除 `docs/README.md` → verify 非零（文件集合/校验失败），拒绝缺 docs 包 |

顶层 `SHA256SUMS.txt` 与包内 `SHA256SUMS.txt` 均可用于校验；本说明不宣称绝对安全，未测范围见第 5 节。

## 8. 12 zip 清单

{{ZIP_TABLE}}
