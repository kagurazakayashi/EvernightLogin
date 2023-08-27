# 步骤195 验收：审计报告五格式生成下载（PASS_WITH_NOTES）

- 执行者：代码编写团队 并行主力程序员 zfyhelper9，2026-11-23 02:2x–02:4x（Asia/Shanghai）。
- 环境：Windows 11、Go 1.27.4（amd64，`GOMAXPROCS=2`/`-p 2`）、真实临时 SQLite（`internal/storage/sqlite` + 全部迁移，仅临时目录，不碰 `database/login.db`）、真实 `internal/reports.Service` 与真实 `internal/task` 执行器、预审 Noto Sans SC 静态 TTF（`%LOCALAPPDATA%\Temp\dep-review-step78\font_gstatic\NotoSansSC-Regular.ttf`，SHA-256 与 `reports.RequiredPDFFontSHA256` 一致，通过 `REPORT_TEST_FONT_PATH` 暴露给测试）。
- 结论：**PASS_WITH_NOTES**。HTML/PDF/CSV/JSON/Markdown 五种格式已用真实服务生成、下载并经**独立解析**核对（PDF 用 ToUnicode CMap 文本抽取，不依赖渲染代码路径；字体可用时不再 skip）；查看/下载/导出分别鉴权且撤销即时生效；历史报告受控；计划报告失败只写失败终态与失败审计、不污染原始审计；PDF 缺字体 fail-closed；PDF 资源限制由既有受控测试覆盖。**未发现需要修改的产品缺陷**（本步以新增验收测试 + 文档固化证据，无产品代码改动）。
- 未测/边界见 §6。

## 1. 执行命令与结果

| 命令（工作目录仓库根） | 退出码 | 结果 |
|---|---|---|
| `go build ./...` | 0 | 通过 |
| `REPORT_TEST_FONT_PATH=<预审字体> go test ./internal/reports/ -count=1` | 0 | **56 PASS / 0 FAIL / 1 SKIP**；唯一 SKIP 为 `TestWritePDFEvidenceArtifact`（需显式 evidence 输出开关，不参与本结论） |
| `REPORT_TEST_FONT_PATH=<预审字体> go test ./internal/reports/ -run 'TestStep195' -count=1 -v` | 0 | 3/3 PASS：`TestStep195FiveFormatsRealTaskExecutor`（1.45s）、`TestStep195ScheduledFailureDoesNotPolluteAudit`（0.53s）、`TestStep195PDFFailClosedWithoutFont`（0.00s） |
| `go test ./internal/reports/sqlite/ -count=1` | 0 | 9/9 PASS（真实 SQLite：调度 Tick 生命周期、历史读写、计划投影、范围拒绝等） |
| PDF 相关（字体可用，不再 skip） | 0 | 8 PASS：`TestPDFAndMarkdownSameSnapshotConsistency`、`TestPDFMultiPageTableAndHeaders`、`TestPDFMissingGlyphFailsClosed`、`TestPDFFontValidation`、`TestPDFOverlongCategoryLabelBounded`、`TestPDFRenderInputLimits`、`TestMarkdownAndPDFRenderTimeoutBounds`、`TestRenderSnapshotHonorsContext` |

完整测试套件中的其它报告测试（生成/取消/超时/审计 fail-closed/计划/历史/清理/下载令牌/通知/重试等）同样 PASS；本步未重复记录逐条名称。

## 2. 五格式矩阵（真实生成 + 独立解析）

新增测试 `TestStep195FiveFormatsRealTaskExecutor` 用真实任务执行器异步生成同一固定窗口的五格式产物，再逐格式独立解析并与 JSON 基准交叉核对：

| 格式 | 真实生成/下载 | 独立解析方式（不依赖渲染实现） | 核对要点 | 结果 |
|---|---|---|---|---|
| JSON | `OpenFile` 取真实产物，SHA-256 与产物元数据一致 | `encoding/json` 解析为通用 map | 时区/窗口/粒度一致性；`total_distinct_users`、`total_raw_events`、`failed_requests`、`failed_tasks`；排序声明 `sort=raw/order=desc`；明细行数与来源一致；类别汇总合计 == 总事件数；趋势桶合计 == 总事件数（图表与汇总同口径） | PASS |
| CSV | 同上 | `encoding/csv` 按 RFC 4180 解析（含字段内换行） | `meta` 的时区/窗口/粒度与 JSON 一致；`activity_total`/`errors_total`/`category_summary` 数值与 JSON 一致；公式注入载荷（`=cmd\|…`）被前置单引号中和；引号/逗号/换行正确转义 | PASS |
| HTML | 同上 | 正则去标签 + `html.UnescapeString` 转可见文本 | 可见文本含时区/窗口/统计数值/中文标题与类别标签；`<svg>` 图表存在；无 `<script>/<iframe>/<link>`、无外部 `src/href`、无内联事件处理器；CSP `default-src 'none'`；`<`/`>` 已实体转义（payload 未注入） | PASS |
| Markdown | 同上 | YAML front matter 解析 + 表格行/列解析 | front matter 时区与 JSON 一致、`snapshot_json_sha256` == JSON 产物摘要；明确“不可信数据边界/不可信材料/不得执行/缺失不等于 0”；`<` 转实体、竖线 `\|` 转义（payload 不破坏表格或触发 HTML）；活跃统计数值一致 | PASS |
| PDF | 同上 | 测试侧独立 PDF 解析：解压内容流、解析 ToUnicode CMap、抽取 `TJ` 文本并校验坐标不越界 | 页数 ≥2、无空白页、每页页脚；中文标题/时区/窗口/统计数值/类别标签可读；嵌入 `/FontFile2` 与 `/ToUnicode`（中文可抽取） | PASS |

## 3. 鉴权、范围与历史（服务层真实授权点）

| 用例 | 断言 |
|---|---|
| 查看（read） | 撤销 `reports.export` 后 `Get` 仍可用（查看只需 read） |
| 下载（read+export） | 撤销 export 后五种格式 `OpenFile` 全部返回 `ErrAccessDenied` |
| 历史列表/详情 | 撤销 read 后 `Get`、`OpenFile` 拒绝，历史列表不再返回该报告 |
| 撤销即时、非永久破坏 | 恢复 read+export 后查看/下载恢复可用 |
| 历史记录 | 新生成报告在 `HistoryList` 中可见且状态 `succeeded` |
| 历史回源再授权/下载令牌一次性/数据范围收缩 | 由既有 `internal/reports` 测试覆盖（`TestHistoryFallbackReauthorizesAfterRestart`、`TestDownloadTicketOneTimeExpiryAndBinding`、`TestAccessScopeDeniesOutOfScope` 等，随全量套件 PASS） |
| 真实 SQLite 历史/计划持久化 | `internal/reports/sqlite` 9/9 PASS（含 `TestSchedulerTickReportLifecycle`：到点触发→去重→停机补跑→历史落库→失权拒绝与自动停用→重启恢复） |

## 4. 定时任务失败不污染原始审计

`TestStep195ScheduledFailureDoesNotPolluteAudit`：真实计划服务创建计划 → 取真实调度载荷 → 注入统计来源失败后调用 `GenerateScheduledHandler`：

- 返回失败（任务不会被误记为成功）；
- 历史恰好一条 `failed` 记录且带失败原因，无成功记录；
- 审计事件前缀逐条不变（既有审计未被改写），新增事件中**没有** `OutcomeSuccess`（只写失败终态事件）；
- 输出目录为空，不产生可下载的半成品。

去重与失权路径另由 `internal/reports/sqlite` 的 `TestSchedulerTickReportLifecycle` 覆盖（同触发重复 Tick 不新增历史、失权不产生假报告、自动停用计划）。

## 5. PDF 资源限制与缺字体 fail-closed

| 用例 | 证据 |
|---|---|
| 缺字体 fail-closed | 未配置 `FontPath` 的服务：`PDFAvailable()=false`，请求 PDF 返回 `ErrInvalidRequest`（不生成缺字/伪扩展名 PDF），同一服务 HTML 仍可生成（`TestStep195PDFFailClosedWithoutFont`） |
| 字体校验 | 绝对路径/常规文件/非符号链接/大小边界/预审 SHA-256/非预审需显式开关/TrueType 魔数（`TestPDFFontValidation`） |
| 缺字形 fail-closed | `TestPDFMissingGlyphFailsClosed`（不会静默降级为缺字 PDF） |
| 输入规模上限 | `TestPDFRenderInputLimits`（明细行/趋势点/页数等硬上限） |
| 渲染超时/取消 | `TestMarkdownAndPDFRenderTimeoutBounds`、`TestGenerateRenderPhaseTimeout`/`Canceled`（45s 渲染墙钟上限；不长时间运行） |
| 版式边界 | `TestPDFMultiPageTableAndHeaders`、`TestPDFOverlongCategoryLabelBounded`（长标签/多页不越界裁切） |

## 6. 未测项与限制

1. **HTTP 层矩阵未在本步重跑**：本步验证的是服务层真实授权点（`Start/Get/OpenFile/HistoryList` 与审计）；真实 `login-server serve` + 管理会话下的报告下载 HTTP 路由在步骤163 补跑中已记录为 200 可达，五格式下载矩阵属页面/API 装配层，见 S2 待接入清单。
2. **统计来源与审计写入为明确标注的测试替身**（固定时间窗口 + 少量合成审计数据，符合 AGENTS §9 测试替身边界）；真实 SQLite 用于任务存储与历史往返（`internal/reports/sqlite`）。未接真实生产审计库。
3. **PDF 字体不在仓库**：验收依赖宿主提供的预审 Noto Sans SC TTF（本机临时目录）；宿主未提供时 PDF 不可用（fail-closed，符合设计）。未用其它非预审字体做生产等效验证。
4. **非 Windows 未运行**：Linux/macOS 未实测；本步全部运行在 Windows 11。
5. 未做长时间/压力测试；定时调度用短 Tick 与假时钟，不常驻运行调度器。
6. 未改产品代码（`git status` 仅有新增验收测试与文档改动）；S2 页面/i18n 无改动需求。

## 7. 复现命令

```powershell
$repo = 'P:\go\src\github.com\kagurazakayashi\EvernightLogin'
cd $repo
$env:GOMAXPROCS='2'; $env:GOFLAGS='-p=2'
$env:REPORT_TEST_FONT_PATH='<预审 NotoSansSC-Regular.ttf 的绝对路径>'
go build ./...
go test ./internal/reports/ -run 'TestStep195' -count=1 -v
go test ./internal/reports/ -count=1
go test ./internal/reports/sqlite/ -count=1
```

注意：`REPORT_TEST_FONT_PATH` 必须指向 `RequiredPDFFontSHA256` 对应的静态 TrueType 字体，否则 PDF 用例会显式 skip / 服务构造拒绝；字体缺失时 PDF fail-closed 属预期行为，应以 `TestStep195PDFFailClosedWithoutFont` 的结果为准，不把缺字体当成通过。
