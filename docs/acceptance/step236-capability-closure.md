# 步骤 236：验收公开接口覆盖与关闭未映射能力

- 执行者：中肥鱼（zhongfeiyu10）
- 日期：2026-11-25（Asia/Shanghai）
- 基线：`53d2e45`（215 收敛公开运行时契约；214 `536175b` 已迁移 UI）
- 平台：Windows 11 x64；go1.27.4；`CGO_ENABLED=0`；`GOMAXPROCS=2`；`go test -p 1`
- 写域：`scripts/capabilities/`、`docs/acceptance/`、`docs/guide/api-status.md`、
  `examples/external-consumer/`；未改产品代码、`ui/`、`app/`、`internal/`、248 WIP。

## 1. 基线（236 改动前，HEAD `53d2e45`）

```text
能力数: 42
  implemented            41
  implemented_untested   0
  missing                1（gap.unimplemented_permissions）
  unimplemented          0
未覆盖生产面: 111（app 公开类型 103 + 管理路由 8）
分页候选列表: 67（有界 64）
分页未覆盖: 6；分页参数不一致: 0
```

- 旧 `gap.unimplemented_permissions` 已过期：`diagnostics.read`/`settings.manage`
  在 `internal/preset/catalog.go` 均为 `Implemented=true` 且默认授予 `system_admin`。
- 未覆盖 app 类型分组：backup 32、diagnostics 13、settings 13、support 14、
  manual recovery 14、protocol 8、user validity 3、session 4、admin revoke 2 = 103。
- 未覆盖管理路由 8：`GET diagnostics`、`GET diagnostics/errors`、`GET diagnostics/export`、
  `GET settings`、`GET settings/status`、`POST settings/sensitive-policy/restore`、
  `POST settings/validate`、`PUT settings`。
- 分页未覆盖 6：`DiagnosticsErrorList`、`ManualRecoveryListPage`、
  `ManualRecoveryListRequest`、`SupportCasePage`、`SupportEventPage`、
  `SupportListCasesRequest`。

## 2. 本步改动

### 2.1 能力声明（2 新 + 5 扩展 = 43）

| 能力 | 动作 | 覆盖 |
|---|---|---|
| `diagnostics.operations` | 新增 | 13 公开类型 + Runtime.Diagnostics + 3 方法/3 路由/页面/`diagnostics.read`/4 测试；fixed 有界 Top-N 理由 |
| `settings.managed` | 新增 | 13 公开类型 + Runtime.Settings + 5 方法/5 路由/页面/`settings.manage`/6 测试；none 固定字段集合理由 |
| `oauth_oidc.protocol` | 扩展 | 8 协议公开类型 + Protocol/ProtocolRevocation accessor 与方法；+2 测试；协议处理仍为标准 HTTP 端点例外 |
| `backup.restore` | 扩展 | 32 备份/恢复公开类型 + 子服务 accessor/方法；+10 测试；保留 offset 分页 |
| `support.recovery` | 扩展 | 14 客服 + 14 人工恢复公开类型 + accessor/方法；+5 测试；补 support/manual recovery 分页证据 |
| `session.admin` | 扩展 | 会话撤销 4 类型 + 管理强制下线 2 类型 + 方法；+3 测试 |
| `account.user_lifecycle_public` | 扩展 | 账户有效期 3 类型 + Get/SetUserValidity；+2 测试 |

同时删除 `gap.unimplemented_permissions`。未新增第二套业务实现，未导出内部 handler。

### 2.2 扫描器

214 已回填 `ui/` 页面、`ui/pages_admin.go` 分页路径；215 后 `app/` 仍为单包多文件，
`app/pagination.go` 仍在原位，根 `alias_contracts.go`/`alias_ui.go` 保留公开别名，
因此本步 **无需修改 scanner 代码**，只更新 `catalog.json`。

### 2.3 外部消费合同测试

`examples/external-consumer` 新增：

- `public_surfaces.go`：只导入公开 `login`/`app`，编译期引用 236 收口的公开类型、
  服务接口与 Runtime 域 accessor；
- `public_contract_test.go`：真实 `app.Open`（临时 SQLite + 程序生成主密钥）成功链、
  零值/伪造 `AdminCaller` 稳定拒绝、协议未启用 fail-closed、列表分页/继续字段合同、
  公开类型不含 internal 类型或磁盘路径字段。

外部模块 `go.mod`/`go.sum` 仅补齐 app 公开导入所需的既有依赖版本（未升级产品依赖）。

## 3. clean 快照严格验证

从 `git archive HEAD`（`53d2e45`）生成临时快照，仅 overlay 本步
`scripts/capabilities/catalog.json`（scanner 无代码改动），在快照内执行：

```text
go test -count=1 -p 1 ./scripts/capabilities/     -> PASS
go run ./scripts/capabilities -strict             -> EXIT 0

能力数: 43
  implemented            43
  implemented_untested   0
  missing                0
  unimplemented          0
未覆盖生产面: 0
分页候选列表: 67（有界 64）
分页未覆盖: 0；分页参数不一致: 0
```

矩阵由工具生成后复制回仓库（未手改）：

| 文件 | 字节 | SHA-256 |
|---|---:|---|
| `docs/acceptance/capability-matrix.json` | 580376 | `d1d1bc3f5005acc72d73c2014b3d0aa02b59b11c7f29edb89c2dc9b66139da5c` |
| `docs/acceptance/capability-matrix.md` | 20683 | `005e7ca6b376692d255432839194de8bdbc0aa2db50ee9ac42b08d99376a6ea9` |

矩阵摘要：43 能力全部 implemented，matched test claims 186，未覆盖生产面 0。

## 4. 验证记录

| 命令 | 结果 |
|---|---|
| `gofmt -l scripts/capabilities examples/external-consumer` | 待 236 收尾复跑（见报告命令汇总） |
| `go test -count=1 -p 1 ./scripts/capabilities/`（快照） | PASS |
| `go run ./scripts/capabilities -strict`（快照） | EXIT 0；43/43；unmapped/uncovered/mismatch 0 |
| `cd examples/external-consumer && GOPROXY=off go build ./...` | PASS |
| `cd examples/external-consumer && GOPROXY=off go test -count=1 -p 1 ./...` | PASS（0.892s） |
| `go run ./scripts/verify-docs` | PASS（收尾复跑） |
| `go test ./internal/preset/` | PASS（收尾复跑） |

## 5. 例外与未测（不悄悄豁免）

| 项 | 结论 |
|---|---|
| OAuth/OIDC 完整协议处理 | 标准 HTTP 端点/页面为宿主契约；公开 Go 只提供内省/撤销，不导出内部 handler |
| 设备码/扫码登录 | 协议/页面流程；本步不新增 QR/设备码 Go accessor，继续登记为协议/页面例外 |
| 本地维护（root 恢复、备份恢复、root CLI） | 只允许 LocalAdmin/本地受控入口，不开放匿名 HTTP 应急入口 |
| 业务 HTTP OpenAPI 全量路径 | 不属 236，留 245 |
| 真实外部 OAuth/mTLS/非 SQLite 运行 | 本轮未做运行验证，仅静态/编译/Windows+SQLite；不虚标已验收 |
| 根包公开类型反向覆盖 | 扫描器仍只反向覆盖 app 公开类型/路由/页面/CLI/权限；不导出内部类型凑数 |

## 6. 证据

- `.ai/lead/tmp/step236/matrix-strict.log`
- 外部测试与收尾验证日志（见 `.ai/lead/reports/step236-dev.md` 命令与结果）
- 矩阵哈希见上表。
