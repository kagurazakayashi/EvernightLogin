# 第 10 轮步骤 203：机器可读能力清单与无人值守短测试入口验收记录

- 日期：2026-11-25（Asia/Shanghai）
- 平台/工具链：Windows 11（10.0.28000）x64；PowerShell 5.1.28000.3365；go1.27.4 windows/amd64；
  `CGO_ENABLED=0`；4 逻辑 CPU → 并发预算 2（`GOMAXPROCS=2`、`go build -p 2`）。
- 仓库基线：父仓库 HEAD `7557646`（`补齐嵌入式用户查询与找回密码接口`）。生成本记录时工作树
  同时存在其他并行链的未提交修改（非本步文件），因此能力清单 JSON 的 `metadata.git_dirty=true`
  是当时真实状态；本步只新增 `scripts/` 与 `docs/acceptance/` 下文件。
- 本记录为人类可读摘要；原始机器证据由本步工具生成（见文末路径与复跑命令）。
  原始 JSON 证据位于 `docs/acceptance/evidence/step203/`（该目录按 `.gitignore` 为本地证据，
  不入 Git；本文件记录其结论与复跑方式）。

## 1. 交付物

| 交付物 | 路径 | 说明 |
|---|---|---|
| 能力清单生成器 | `scripts/capabilities/`（Go，使用标准库 AST） | 只读扫描源码，与能力声明交叉核对，生成 JSON+Markdown；`-strict` 可作门禁 |
| 能力声明 | `scripts/capabilities/catalog.json` | 34 项能力：内部服务/公开 Go/管理 API/协议端点/CLI/页面/权限/分页/定向测试；含 1 项已知未实现缺口 |
| 机器可读能力清单 | `docs/acceptance/capability-matrix.json` | 自动生成；能力状态+分层证据+反向覆盖+原始盘点清单（含 68 app 公开类型、108 管理 API 路由、17 协议端点点位、241 页面命名路由、40 CLI 子命令、51 权限键、定向测试清单） |
| 人类可读摘要 | `docs/acceptance/capability-matrix.md` | 同一份数据生成，勿手改 |
| 统一短测试入口 | `scripts/shorttest.ps1` | 临时目录/动态回环端口/合成秘密/总超时/子进程退出与清理/结构化 JSON |
| 场景注册表 | `scripts/shorttest/scenarios.json` | 已登记 2 个场景：真实产品冒烟 + 入口超时自检 |
| 真实短场景 | `scripts/shorttest/scenario/login_server_smoke/` | 复用真实 `login-server init/serve`，不导入 internal、不复制业务逻辑 |
| 入口自检场景 | `scripts/shorttest/scenario/harness_timeout/` | 验证超时强制终止与清理，不是产品测试 |
| 使用/契约文档 | `docs/acceptance/shorttest.md` | 入口职责、退出码、场景契约与新增方式、未测边界 |

## 2. 能力清单：命令与结果

```powershell
$env:GOTOOLCHAIN='local'; $env:GOMAXPROCS='2'
go run ./scripts/capabilities -strict
# EXIT 0；能力数 34；implemented 33 / implemented_untested 0 / missing 0 / unimplemented 1；未覆盖生产面 0
```

核对口径（状态由源码解析结果决定，不是手写）：

- 内部服务目录必须存在且含非测试 Go 源码；
- `app_api` 必须是 app 包真实导出的类型/函数/接口方法/结构字段；
- `admin_routes` 必须能在 `internal/adminapi` 的 `add(...)` 注册或 `internal/serverapp`
  领域路由注册中解析到（本机 108 条）；
- `protocol_paths` 必须是 `internal/protocolapi` 导出的 `Path*` 常量（17 个）；
- `cli` 必须能在 `cmd/*` 与 `internal/managecli` 的 `Use:`/`args[0]` 分派中解析到（40 个）；
- `pages` 必须能在根包 `UIRoute` 字面量中解析到（当前树 241 条，支持前缀通配）；
- `permissions` 必须存在于 `internal/preset/catalog.go` 的 `PermissionDefinition` 且
  **未实现权限要求代码标记 `Implemented=false`**（本机 51 键，代码标记未实现 2 键：
  `diagnostics.read`、`settings.manage`）；
- `pagination` 的 offset/cursor 模式必须有字段证据，fixed/none 必须写明理由；
- `tests` 必须能按「包路径 + 测试函数名前缀」解析到真实测试函数；
- 反向覆盖：盘点到的生产面若未被任何能力声明覆盖会列出，`-strict` 时返回退出码 3。

结果：33 项声明能力全部解析成功并各有定向测试证据；1 项 `gap.unimplemented_permissions`
为 `unimplemented`，缺口证据（`internal/preset/catalog.go` 注释"没有对应的服务端执行路径"、
"保持 false 且"）经扫描核实。反向覆盖未发现遗漏。

该清单**只证明测试函数存在与生产装配可达**，不证明测试当前全部通过；通过性由审计员
全量回归负责。这是本步如实边界。

## 3. 统一短测试入口：命令与结果

### 3.1 真实短场景（主证据）

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\shorttest.ps1 `
  -Scenario login-server-smoke -TimeoutSeconds 240 `
  -Out docs\acceptance\evidence\step203\shorttest-login-server-smoke.json
# EXIT 0；status=PASS；14/14 检查 PASS；入口 wall≈8.8s；场景内部≈2.3s
```

检查项（全部 PASS）：

| # | 检查 | 类型 | 证据 |
|---|---|---|---|
| 1 | `init.first_run` | 成功路径 | 真实 `login-server init` exit=0，输出含 `setup_verified`，临时 SQLite 应用 49 个迁移 |
| 2 | `init.no_password_echo` | 秘密卫生 | init 输出不含随机合成 root 密码 |
| 3 | `init.repeat_rejected` | 拒绝路径 | 重复 init exit=1："实例已完成首次初始化…拒绝重复初始化" |
| 4 | `serve.healthz_ready` | 成功路径 | 动态回环端口上真实 `serve` 就绪，`GET /healthz` 200 |
| 5 | `http.healthz` | 成功路径 | 200，body `{"status":"ok"}` |
| 6 | `http.openapi` | 成功路径 | 200，返回 OpenAPI 文档 |
| 7 | `http.login_page` | 成功路径 | 200，内置登录页 HTML |
| 8 | `admin_api.disabled_404` | 拒绝路径 | `GET /admin/v1/meta` 404（未启用管理 API，fail-closed 而非放行） |
| 9 | `protocol.disabled_discovery_404` | 拒绝路径 | `GET /.well-known/openid-configuration` 404（协议未启用） |
| 10 | `protocol.disabled_jwks_404` | 拒绝路径 | `GET /jwks` 404 |
| 11 | `serve.process_exited` | 子进程退出 | 结束 serve 后进程真实退出（killed=true，exit=1），无残留 |
| 12 | `serve.port_released` | 资源清理 | serve 退出后动态端口可重新绑定 |
| 13 | `cleanup.secret_files_removed` | 秘密清理 | 随机密码文件与主密钥文件已删除 |
| 14 | `cleanup.workdir_empty` | 临时目录清理 | 场景工作目录清空并删除 |

入口统一结果同时记录：`cleanup.workdir_removed=true`、`port_released=true`、
`processes_remaining=[]`、`tracked_processes=[]`；运行后 `%TEMP%` 无 `evernight-shorttest-*`
残留目录、无 `login-server`/场景进程残留（实测）。

### 3.2 拒绝/失败路径（入口自身）

| 命令 | 预期 | 实际 |
|---|---|---|
| `-Scenario no-such-scenario` | 结构化 ERROR + exit 2 | `{"status":"ERROR","error":"未知场景: no-such-scenario","exit_code":2,...}`，exit 2 |
| `-Scenario login-server-smoke -TimeoutSeconds 2` | 参数拒绝 | `{"status":"ERROR","error":"-TimeoutSeconds 必须在 5..1800 之间，实际 2"}`，exit 2 |
| `-Scenario harness-timeout -TimeoutSeconds 20` | 子进程被强制终止、结构化 TIMEOUT、清理 | `status=TIMEOUT`，exit 1，`workdir_removed=true`，`processes_remaining=[]`，错误="场景在入口超时内未结束，已强制结束进程树" |

### 3.3 入口契约要点（细节见 `docs/acceptance/shorttest.md`）

- 临时目录：`%TEMP%\evernight-shorttest-<时间>-<随机>`，默认结束删除（`-KeepArtifacts` 保留）；
- 动态回环端口：场景绑定 `127.0.0.1:0`；入口结束后验证端口释放；
- 合成用户/秘密：随机合成 root 密码写受保护临时文件（Windows 用 icacls 去继承并只授权
  当前用户/SYSTEM/Administrators），入口与结果 JSON 不含秘密值；
- 总超时：`-TimeoutSeconds` 覆盖构建+运行+清理（5～1800，默认 180），超时用 `taskkill /T /F`
  结束本次创建的整棵子进程树；
- 结构化结果：stdout 单行 `evernight.shorttest.result/v1` JSON，含环境、检查、清理、
  日志尾部；`-Out` 落盘；
- 并发预算：`floor(逻辑处理器/2)`（本机 4→2），设置 `GOMAXPROCS` 与 `go build -p`。

## 4. 本步执行的其他定向检查

| 命令 | 结果 |
|---|---|
| `gofmt -l scripts/` | 无输出（格式干净） |
| `go vet ./scripts/capabilities/ ./scripts/shorttest/...` | EXIT 0 |
| `go build -p 2 ./scripts/capabilities ./scripts/shorttest/... ./cmd/login-server` | EXIT 0 |
| `go run ./scripts/verify-docs` | `DOCS VERIFY: PASS checks=12 failures=0` |
| `go run ./scripts/capabilities -strict` | EXIT 0（33 implemented / 1 unimplemented / 0 missing / 0 未覆盖） |

## 5. 未测与前置条件（如实登记）

- 未测：Linux/macOS 上运行本步工具与场景（本步按规程只做 Windows 实测；跨平台静态/编译
  兼容性未验证）；真实浏览器/读屏、真实硬件 Passkey、长时间并发/压力（不在本步范围）。
- 未测：能力清单的 `tests` 证据只证明"定向测试函数存在"，未在本步重新执行全量 `go test`
  （全量回归属审计员唯一重负载窗口）；矩阵中 `implemented` 不等于"测试当前全绿"。
- 前置/依赖：后续步骤新增或变更能力面（路由/页面/权限/公开 API）时，必须同步
  `scripts/capabilities/catalog.json` 与 `scripts/shorttest/scenarios.json` 的 `covers`，
  否则 `-strict` 会因 `missing`/未覆盖项返回退出码 3——这是有意设计的回归门禁。
- 记录时工作树含其他并行链未提交修改（`app/`、`internal/passwordreset/`、`internal/mfa/`、
  `ui_pages_mfa.go` 等，非本步文件）；能力清单中的页面路由数（241）与协议/管理路由
  以当时树为准，其他链提交后应重跑生成器刷新。

## 6. 复跑命令

```powershell
Set-Location P:\go\src\github.com\kagurazakayashi\EvernightLogin
$env:GOTOOLCHAIN='local'; $env:CGO_ENABLED='0'; $env:GOMAXPROCS='2'

# 能力清单（严格模式）
go run ./scripts/capabilities -strict

# 真实短场景
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\shorttest.ps1 `
  -Scenario login-server-smoke -TimeoutSeconds 240

# 入口超时自检（预期 exit 1 / TIMEOUT）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\shorttest.ps1 `
  -Scenario harness-timeout -TimeoutSeconds 20
```
