# 能力真值矩阵（第 11 轮步骤 267，2026-11-26）

> 本文件是**人工核对的当前代码事实**，不是自动生成的绿表。它记录：发布说明 R10 登记项
> 在当前代码中的真实状态、第 11 轮新增能力（252/255/256/257/261/262/263/264/265/266/268）
> 的入口与证据、DEFERRED 遗留项的当前处置，以及自动能力清单
> `docs/acceptance/capability-matrix.{json,md}` 的证据分级口径。
>
> 自动矩阵由 `go run ./scripts/capabilities` 生成，状态只表示「声明面/测试/证据是否在源码
> 中解析到」；本文件补充「符号存在 ≠ 功能闭环」「正向/拒绝证据」「环境未测」「子模块不可
> 获取」的区分。**两者不一致时以当前代码与本文件的人工核对结论为准，并需重新生成矩阵。**

## 0. 基线与环境

| 项 | 值 |
|---|---|
| 核对日期 | 2026-11-26（Asia/Shanghai） |
| 父仓库 HEAD（核对时/矩阵重建基线） | `8ecdb2a`（267 提交前基线；矩阵在 `git worktree` 干净检出该 HEAD + 本步 267 文件上重建，`files_scanned=779`、页面 248/管理路由 131；提交后 HEAD 前移时 `-check` 忽略 HEAD/文件数，但页面/路由等 inventory 变化需重新生成） |
| 运行平台 | Windows 10 19045 / amd64；Go 1.27.4；GOTOOLCHAIN=local；CGO_ENABLED=0；GOMAXPROCS=2 |
| SQLite | 真实临时 SQLite 运行验证（主运行存储） |
| 子模块 | EvernightMail 固定 `aa7ccf5`（远端 main 仍 `b9891ac`，**远端不可获取**，见 §3）；go-build-all 独立模块 |
| 复跑命令 | `go run ./scripts/capabilities -strict`；`go run ./scripts/capabilities -check`（只读校验，不写文件） |

## 1. 发布说明 R10 登记项当前事实

| 编号 | 原登记 | 当前代码事实（步骤 267 核对） | 结论 |
|---|---|---|---|
| R10-03 | 原登记 `app/passwordreset.go:96` 的 `ValidateResetToken` 失败分支未携带 RequestID | 现 `validateToken` 的 CHALLENGE_INVALID 分支（`app/passwordreset.go` 约 301 行）已 `login.WithRequestID(requestID)`，`ValidateTokenWithSource` 全链带请求编号 | **已关闭**（代码证据） |
| R10-05 | 受限范围调用者可区分角色不存在与范围外 | `internal/role/role.go` 仍分别返回 `ErrRoleNotFound`/`ErrAccessDenied`；调用顺序未统一。未在本步扩大修改 | **开放**（保持原 LOW/跟踪，转 274 或后续授权步骤） |
| R10-11 | 高权限升级过渡态未复算 protectedRecoveryTarget | 第 11 轮 252/253 已改 root/强认证语义；未在本步确认该过渡态已完全复算，需 274 并发矩阵复验 | **部分/待复验**（不宣称关闭） |
| R10-15 | 回环明文 SMTP 校验恒失败 | 第 10 轮 212 已修复；当前 `config` 校验路径未见该恒失败逻辑（历史项） | **已关闭**（历史） |
| R10-17 | Mail 证书导入实际上限 1 MiB 与文档 24 MiB 不符 | 现 `EvernightMail/internal/certimport/certimport.go` 请求体上限 24 MiB、单文件上限 8 MiB（`tlscert.MaxCertificateFileBytes`）；`cli-reference.md` 已写 8 MiB/24 MiB；`api-reference.md` 第 23 行仍写「上传 16 MiB」，与实际 24 MiB 存在**文档残留不一致** | **功能已修复**；**文档残留不一致**转 276/文档步骤 |
| R10-20 | `AdminUserBatchJob.ExportPath` 暴露服务器绝对路径 | `app/userbatch_public.go:118` 仍保留 `ExportPath string` 并回填 `job.ExportPath` | **开放**（LOW，仍未脱敏，未在本步改动公共契约） |
| R10-22 | 221 仅 P0（app 门面），独立 example/HTTP/CLI/页面未做 | 第 11 轮新增门面（252/255/256/257 等）仍走 app 公开 Go 入口；221 范围的独立 example/HTTP/CLI/页面入口未闭环 | **部分完成**（不得写成全部实现） |
| R10-23 | 安全通知分页、邮件投递记录端点/权限、通用 `/admin/tasks` 页面、迁移 0052 | 263/265/266 已交付：`reauth.NotificationsPage`、`GET /admin/v1/notifications/history`、`GET /admin/v1/deliveries`、`/admin/tasks` 页面、CLI `notifications history`/`deliveries list`；keyset 查询经 EXPLAIN QUERY PLAN 验证既有索引足够，**0052 复合索引不需要** | **已关闭**（266 证据；0052 判定为不需要） |
| R10-24 | LocalAdmin 不能作为邀请发起者（FK 非空） | schema 语义未变；需产品决策，AI 不自行改 | **开放·产品决策** |
| R10-30 | `uiadminadapter` Audit==nil 时跳过 requested 审计而非 fail-closed | 当前 `SecurityPolicyAdapter.recordAudit` 在 `Audit==nil` 时返回 `AUDIT_WRITE_FAILED`（fail-closed）；但部分「拒绝/失败」审计调用为 `_ = a.recordAudit(...)` 的显式 best-effort（不改写请求结果），需按调用点区分，不能笼统说「全部 nil 分支绕过」 | **已修复为 fail-closed（主路径）**；best-effort 拒绝审计保留并在此登记 |

## 2. 第 11 轮新增能力事实（入口与证据）

| 步骤 | 能力 | 真实入口 | 证据/状态 |
|---|---|---|---|
| 252 | root 全权限与授权入口语义统一 | 权限内核 + 页面/HTTP/CLI/Go 门面共同判定 | 提交 `3c0c416`；矩阵 `rbac.*` 能力复核；root 不等于绕过认证/两步验证 |
| 255 | 操作绑定的一次两步验证证明 | `app` 操作证明门面（`OperationProofService` 等）、`internal/reauth` 直连证明、在线 CLI `admin` | `app/operation_proof_test.go`、`internal/reauth/proof_test.go`；负向：绑定不匹配/权限撤销/无 Passkey 拒绝 |
| 256/257 | 直接改用户名/直接重置密码 | `DirectUserManagementService`/`DirectPasswordManagementService`、权限 `users.username.change.other`/`users.password.reset.other`、受限改密 `RequiredPasswordChangeService`、CLI `loginctl admin` 与直接管理入口 | `app/admin_user_rename_test.go`、`app/admin_user_reset_test.go`；负向：证明绑定/目标保护/无密码目标/并发单赢家 |
| 261/262/263 | 有界模糊搜索（用户/成员、角色组权限应用、客服/报告/任务显示名） | app 列表 `Search` 字段 + 页面/CLI 搜索；授权先于搜索 | `app/admin_search_test.go`、`app/admin_domain_search_262_test.go`；已知边界 D-261-5（前进/后退旧展示）、D-263-1（空搜索+非法字段口径） |
| 264 | EvernightMail 安全搜索入口（子模块） | Mail API/CLI/页面 query（子模块独立仓库） | **子模块未纳入本仓库源码扫描**；本地工作树改动待 Lead 提交，远端固定版本不可获取 |
| 265/266 | 通知投递关联 + 安全告知/投递记录分页 + 通用任务页 | `reauth.NotificationsPage`、`GET /admin/v1/notifications/history`、`GET /admin/v1/deliveries`、`/admin/tasks`、CLI `notifications history`/`deliveries list` | 266 提交 `c5e19c7`；reauth/mailer/UI/serverapp E2E 测试；`-limit` 对齐 1..100（N-266-1 已修） |
| 268 | OpenAPI 页面契约 | `internal/transport` OpenAPI 文档生成/校验 + 页面操作文档 | `internal/transport/openapi_test.go`、`pageopenapi_test.go`；能力矩阵覆盖其测试证据（不改 transport 实现） |

## 3. DEFERRED 第 11 轮遗留项当前处置（节选，完整表在 `.ai/handoff/DEFERRED_ISSUES.md`）

| 编号 | 当前状态 | 本步核对结论 |
|---|---|---|
| D-252-1 | 开放·HIGH 产品缺口 | `preset.Install` 无生产调用点；矩阵以 `maturity=unimplemented` 条目显式暴露，**不得当已完成**（转 273/后续） |
| D-254-1 | 开放·工具建议 | 已由本步 `-check` 只读校验模式部分解决：可校验矩阵而不写 tracked 文件 |
| D-261-5 | 开放·LOW 展示层 | `popstate` 未监听，旧条件结果可能显示；服务端仍重新授权，无越权；矩阵 `search` 能力标记 partial |
| D-263-1 | 开放·LOW 口径 | 空搜索+非法字段在客服/报告路径行为不一致；本步不扩大搜索实现，登记并保留 |
| D-264-1 | 开放·LOW 保留策略 | Mail `.corrupt-*` 保留策略在子模块；**子模块未纳入源码扫描**，不在此仓库矩阵宣称完成 |
| D-257-1 | 已裁决·产品语义 | `must_change` 受限改密会话仅能改密、MFA 保留；文档/回归转 260/273/274 |
| D-249-2/D-249-3/D-250-1/D-250-INFO/D-251-*/D-253-*/D-262-*/D-265-*/D-268-*/R11-* | 按 DEFERRED 原状态 | 本步不改其代码决策；矩阵/报告不把其关联能力标为「全部完成」，环境/子模块阻塞单独分类 |

计数口径：第 11 轮 DEFERRED 增补 **33+ 条**（含 D 系列与 R11-PROC/SIG/ENV），其中产品缺口 D-252-1 为 HIGH；
本步不修改 `.ai/handoff/DEFERRED_ISSUES.md`（由小爱同学/Lead 维护），只在矩阵与本文件做真值对齐。

## 4. 环境未测与子模块不可获取（不是通过，也不是缺陷）

- **非 SQLite 运行未测**：MySQL/PostgreSQL/SQL Server 只有结构/适配与编译检查，未运行实测；SQLite 为主运行验证存储。
- **真实硬件 Passkey/Windows Hello/YubiKey 未测**：软件 WebAuthn/虚拟认证器不能代替真机互操作。
- **真实浏览器 GUI/窄屏/读屏、真实手机相机扫码、真实反向代理/TLS/mTLS、Windows 服务托管未测**。
- **真实外部 SMTP/Webhook 外发未测**：示例与测试使用本地捕获器。
- **-race/govulncheck/gosec 未跑**（Windows/CGO 环境限制）。
- **EvernightMail 固定版本 `aa7ccf5` 远端不可获取**：远端 main 仍 `b9891ac`；Mail 264 搜索/证书等改动属子模块独立仓库，**子模块未纳入本仓库源码扫描**，不计入本仓库 implemented。

## 5. 证据分级口径（矩阵已实现）

自动矩阵按以下字段/状态区分，不再用单一「implemented」掩盖局部完成：

- 声明面解析：内部服务目录、公开 Go 符号、管理 API 路由、协议点位、CLI、页面、权限、定向测试函数；
- `positive_evidence` / `rejection_evidence`：真实成功链/拒绝链证据文件标记（文件:标记文本），与测试函数存在性分开核对；
- `maturity`：`implemented`（默认）/`partial`（有已登记缺口、环境未测或子模块阻塞）/`unimplemented`（已知未实现，缺口证据必须可核验）；
- `environment_untested` / `submodule_unavailable`：环境未测与子模块/远端阻塞，报告单独成节，不计为通过；
- `-strict` 仅在 missing/未覆盖生产面/未核实证据时失败；`-check` 只读校验矩阵是否与源码+声明一致（退出码 4 = 不一致）。
  `-check` 比较语义内容，忽略易变基线（生成时间、Git HEAD/分支/脏状态、逻辑处理器/并发预算），
  避免提交前生成、提交后 HEAD 前移或换机导致假失败；真正的声明/源码/覆盖漂移仍会失败。

## 6. 当前自动矩阵结果（步骤 267 生成，2026-11-26）

| 项 | 值 |
|---|---|
| 能力条目 | 52（基线 43 + 第 11 轮新增 9） |
| `implemented` | 48 |
| `partial`（有已登记缺口/环境未测/子模块阻塞） | 3 |
| `unimplemented`（已知未实现，缺口证据已核验） | 1（`preset.install_gap`，D-252-1） |
| `missing` | 0 |
| 未覆盖生产面 | 0（app 类型 468 / 管理路由 131 / 协议点位 17 / 页面 248 / CLI 41 / 权限 53 全部被声明覆盖） |
| 分页未覆盖/参数不一致 | 0 / 0 |
| 正向/拒绝证据（文件标记核验） | 各 8 条 |
| 环境未测能力 / 子模块阻塞能力 | 2 / 1 |
| `-strict` | **EXIT 0**（无 missing/未覆盖/未核实证据） |
| `-check`（只读校验） | **EXIT 0**（现有 JSON/Markdown 与源码+声明一致；不改写文件） |

本矩阵在 `git worktree` 干净检出 `8ecdb2a` + 本步 267 文件后重建（基线 metadata 显示该检出；`-check` 忽略易变基线后 PASS）。工作树中其他并行写者的未提交页面/路由（258/270 WIP）会使脏树 `-check` 产生语义差异（EXIT 4），这属于预期：矩阵对应的是 **已提交基线 + 267 文件**，不是脏工作树。
注意：`-strict` EXIT 0 只表示「没有未解析声明/未覆盖生产面/未核实证据」，**不表示 52 项全部完成**；
矩阵同时在 `partial`/`unimplemented`/「环境未测」/「子模块不可获取」各节列出未完成与未测范围。
## 7. 本步修改与复跑

- 生成器：`scripts/capabilities/{catalog.go,report.go,main.go}` 增加 maturity/正向/拒绝证据/环境未测/子模块阻塞字段与 `-check` 只读校验、证据分级输出。
- 能力声明：`scripts/capabilities/catalog.json` 增加第 11 轮能力与缺口条目（252/255/256/257/261-263/264 子模块说明/265/266/268、D-252-1、R10-22 剩余项）。
- 生成物：`docs/acceptance/capability-matrix.json` / `.md` 重新生成；`docs/release-notes/round10.md` 增加第 11 轮勘误；`docs/acceptance/README.md` 收录本文件。
- 复跑：`go run ./scripts/capabilities -strict`（期望 EXIT 0：无 missing/未覆盖；但 summary 会显示 partial/unimplemented/环境未测，不是「全部完成」）；
  `go run ./scripts/capabilities -check`（期望 EXIT 0：矩阵与源码一致；修改声明后未重新生成则 EXIT 4）。
