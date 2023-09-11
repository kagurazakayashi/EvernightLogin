# 发布包、跨平台构建与校验清单

本文件说明如何从源码构建 login 的本地发布包、包内容、跨平台构建状态与校验方法。
**只准备本地产物**：不创建标签、不提交、不 push、不上传、不创建远程 release。

## 1. 构建方式（可复现）

```powershell
# 在仓库根目录；Windows PowerShell 5.1 或 PowerShell 7 均可
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build-release.ps1 `
  -OutputDir P:\go\tmp\release-20261121 -Version 0.1.0-dev
```

固定条件：

- `CGO_ENABLED=0`、`GOMAXPROCS=2`（脚本固定写 2，低于项目上限「逻辑处理器数的一半」= 6，
  属更保守取值，不会超过并发约束）；
- `-trimpath`、`-buildvcs=false`；
- 通过 `-ldflags` 注入 `version`/`commit`/`buildTime`（`login.CurrentBuildInfo` 读取）；
- 每个目标独立执行三次 `go build`（`./cmd/login-server`、`./cmd/loginctl`、
  `./cmd/login-backup`），失败时如实记录失败原因，**不生成空文件占位**；
- 版本信息包含提交号与工作树是否干净，便于区分“源码构建”和“含未提交改动的构建”。

构建脚本与校验脚本都是**只读 Git**：仅 `git rev-parse`/`git status --porcelain` 读取
当前状态，不做任何 Git 写操作。

### 1.1 一键六平台构建入口（步骤179）

从仓库根目录一次构建 Login 三命令与 Mail 一命令的六目标产物（Windows/Linux/macOS ×
amd64/arm64），并做独立校验：

```powershell
# Windows：默认输出 dist/build；参数见 docs/acceptance/step179-build-entry.md
.\build.ps1 -Version 0.1.0-dev

# 单独复跑构建树校验（manifest/大小/SHA-256/PE-ELF-Mach-O 类型与架构）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-build.ps1 -BuildRoot dist\build -Version 0.1.0-dev
```

- `build.cmd` 为 cmd 包装；`build.sh` 为 POSIX 维护入口（委托 PowerShell 逻辑，本轮未在
  Linux/macOS 实测）。
- 固定条件：`go≥1.27.0`、`GOTOOLCHAIN=local`、`GOWORK=off`、`GOFLAGS=-mod=readonly`、
  `CGO_ENABLED=0`、`GOMAXPROCS=2`，工具并发由 go-build-all 夹紧到 `max(1, floor(CPU/2))`；
  两个模块串行调用，不叠加并发。
- 预检要求：无 `go.work`、两模块 `go.mod` 无 `replace`、EvernightMail 与 go-build-all
  子模块 HEAD 等于固定提交且工作树干净；工具自身构建到 `_tools/`，不进入产品清单。
- 交付接口：`dist/build/build-summary.json`（format=1）与 `dist/build/checklist.txt`，
  记录 24 项产物的路径/大小/SHA-256/类型/架构、工具与模块版本、调用耗时与警告。
- 输出目录安全：`-OutputDir` 已存在且非空时不会直接递归删除；只有目录内含本入口的
  `.build-all-root` 标记或显式传 `-ForceClean` 才允许清理，否则退出 10 并保留原目录。
- 退出码：0 成功；10 预检失败；20 工具构建失败；21 Login 构建失败；22 Mail 构建失败；
  30 manifest/聚合字段不符；31 产物缺失/类型/尺寸/SHA 不符；40 内部错误。任何必需项
  缺失或类型/哈希不符都不得返回 0。
- **发布包压缩不属于本入口**：每目标一个 zip（12 个）由步骤202 基于 24 项目录生成。

## 2. 发布包内容

每个目标一个压缩包：`evernight-login-<version>-<os>-<arch>.zip`，解压后目录结构：

```text
evernight-login-<version>-<os>-<arch>/
├── bin/
│   ├── login-server[.exe]     服务进程入口（serve：HTTP 服务；init：本地首次初始化）
│   ├── loginctl[.exe]         本地管理/应急命令
│   └── login-backup[.exe]     备份创建与离线查看工具
├── config/
│   ├── login.example.yaml     配置样例（不含真实秘密）
│   └── proxy/                 Nginx、Caddy 反向代理样例
├── deploy/                    容器、Windows 服务、systemd、launchd 样例
├── docs/deployment/           部署文档（本目录全部文件，含 samples/ 便于文档内链接）
├── docs/licenses/             THIRD_PARTY_NOTICES、字体 OFL 与依赖许可证全文
├── VERSION.txt                版本/提交/构建时间/目标/包说明
├── README.txt                 同 VERSION.txt（便于开箱查看）
├── BUILDINFO.txt              go version -m 输出与 ldflags
├── DEPENDENCIES.txt           模块依赖清单（含许可证文件名）
└── SHA256SUMS.txt             包内每个文件的 SHA-256
```

**不包含**（按构造排除，不靠事后删除）：

- AI 专用文件：`.ai/`、`.agents/`、`AGENTS.md`、`MEMORY.md`、AI 步骤提示词；
- 运行数据：`database/*.db`、`*.db-wal`/`*.db-shm`、`*.sqlite*`；
- 日志：`*.log`、`logs/`；
- 测试密钥与秘密：`*.key`、`*.pem`、`*.p12`、`*.pfx`、`.env`、`secrets/`；
- 源码与开发/测试工具：`tools/`、`examples/`、`scripts/` 等不随包；包内
  `docs/deployment/e2e-smoke.md` 引用的 `scripts/e2e-login-server.ps1` 与
  `tools/loginte2e` 只存在于源码树，发布包内仅有说明文档，不能直接执行；
- 子模块与测试夹具：`EvernightMail/`（独立测试邮件服务器子模块）、
  `internal/mailtest` 等本地邮件测试夹具不进入生产包；原 `tools/testmaild` 已在步骤 136 删除。
  生产发布不需要 Mail；Mail 仅在开发/测试和发布前本地邮件链路验证时使用；
- 仓库内的其它源码目录与构建缓存。

`EvernightMail` 子模块的前置初始化、提交顺序、脚本检查与隔离副本复现见
[docs/deployment/mail-submodule.md](mail-submodule.md)。发布脚本
`scripts/build-release.ps1` 保持只构建三个 Login 命令的显式清单，不会因仓库中存在
Mail 子模块而把 Mail/testkit 打进发布包。

脚本使用**显式复制清单**组装包内容，因此仓库里新增的文件不会被自动打进包；需要新增
运行时资源时应显式修改 `scripts/build-release.ps1` 的复制清单。

包内 `VERSION.txt`/`README.txt` 描述当前运行时边界：本包含可嵌入 Go 库与三个 CLI；
`login-server` 支持 `serve`（真实 HTTP 服务）与 `init`（本地首次初始化），OAuth2/OIDC
协议端点与管理 JSON API 已装配但默认关闭；`loginctl` 提供本地与在线管理命令；内置
Web 页面可选且可由宿主替换。

### 2.1 Unix 执行位（Linux/macOS 解压后必须处理）

当前包格式为 ZIP（由 PowerShell `Compress-Archive` 生成），**不保留 Unix 执行位**：
在 Linux/macOS 解压后 `bin/` 下文件默认没有 `+x`，直接执行会报
`Permission denied`。解压后先执行：

```bash
unzip evernight-login-<version>-linux-amd64.zip
cd evernight-login-<version>-linux-amd64
chmod +x bin/login-server bin/loginctl bin/login-backup
./bin/login-server --version
```

这是已知限制（已登记），后续可改为保留模式位的 tar.gz 或带权限的 ZIP 构建；在改进
之前请按下述步骤处理，不要把“没有执行位”误判为二进制损坏。

## 3. 版本、依赖与许可证清单

- `VERSION.txt`：`version`、`commit`、`worktree_dirty`、`build_time_utc`、目标平台、
  Go 版本、CGO 状态与包说明。
- `BUILDINFO.txt`：`go version -m bin/login-server` 的完整输出（模块版本、校验和、
  构建设置），可用于核对二进制实际链接的依赖版本。
- `DEPENDENCIES.txt`：`go list -m` 得到的模块清单，标注 main/indirect 与在模块缓存中
  找到的许可证文件名。
- `docs/licenses/THIRD_PARTY_NOTICES.md`：第三方组件与字体许可证说明（含嵌入字体
  的 SIL OFL 许可与 PDF 依赖）。
- `docs/licenses/NotoSansSC-OFL.txt`：报告 PDF 字体许可证全文（字体文件本体不随包，
  需按 `container.md` 第 4 节单独获取并校验摘要）。
- `docs/licenses/deps/<module>@<version>/`：各依赖模块缓存中的 `LICENSE`/`NOTICE`/
  `COPYING` 原文。若某模块缓存中没有许可证文件，`DEPENDENCIES.txt` 会标注
  `(none found in module cache; verify upstream)`，部署前应向上游核对。

## 4. 跨平台构建矩阵

本轮实际执行的矩阵结果（2026-11-21 从干净 HEAD `597b503` 重建，真实命令与状态，
未运行的目标不写成“通过”）：

| 目标 | 代码 | 编译（`CGO_ENABLED=0`） | 运行 |
|---|---|---|---|
| windows/amd64 | 有 | 成功（3 个二进制） | **实测通过**（解压后运行 `--version`/`--help`/无参数/备份工具/管理 CLI，见第 6 节） |
| windows/arm64 | 有 | 成功（3 个二进制） | 未运行（按项目约束只允许 Windows amd64 运行） |
| linux/amd64 | 有 | 成功（3 个二进制） | 未运行（按项目约束不做运行实测） |
| linux/arm64 | 有 | 成功（3 个二进制） | 未运行（按项目约束不做运行实测） |
| darwin/amd64 | 有 | 成功（3 个二进制） | 未运行（按项目约束不做运行实测） |
| darwin/arm64 | 有 | 成功（3 个二进制） | 未运行（按项目约束不做运行实测） |

本轮构建信息：`go1.27.1 windows/amd64`，`commit=597b503`，`worktree_dirty=no`
（构建前工作树干净，非 dirty 构建），`build_time=2026-11-20T17:37:43Z`；
6 个目标全部构建成功，无失败目标，未用空文件占位。构建输出目录：
`P:\go\tmp\release-20261121`（仓库外临时目录，不属于仓库；含 6 个 zip、顶层
`SHA256SUMS.txt`、`build-matrix.txt` 与构建/校验控制台日志）。本轮产物共 6 个
zip，合计 149,234,273 字节（约 149 MB / 142 MiB），单包 23.6–26.0 MB。

构建矩阵的完整机器可读记录也在构建输出目录的 `build-matrix.txt` 中。

## 5. SHA-256 校验清单与验证

- 顶层 `SHA256SUMS.txt`（构建输出目录）：每个目标压缩包的 SHA-256。
- 包内 `SHA256SUMS.txt`：包内每个文件的 SHA-256（清单自身除外），相对路径便于解压后
  直接校验。
- 校验脚本：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-release.ps1 `
  -ReleaseDir P:\go\tmp\release-20261121 -ExpectedVersion 0.1.0-dev
```

校验脚本会：核对顶层清单；逐包解压到临时目录；核对包内清单；检查禁止项（AI 文件、
`*.db*`/`*.sqlite*`、`*.log`、`*.key`/`*.pem`/`*.p12`/`*.pfx`、`.env`、`secrets/`；
注意正则**不含** `*.crt`/`*.cer`，证书文件需人工核对）；检查必需文件与三个二进制；
扫描文本文件（≤2 MB，跳过 `.exe`/`.zip`）中的私钥块；在 Windows 上实际运行
`windows/amd64` 二进制并检查退出码与输出，最后用真实配置加载器校验包内样例配置。

> **运行环境前提（本轮实测遇到）**：Windows PowerShell 5.1 的 `Start-Process` 在进程
> 环境同时存在大小写重复变量（如 `NO_PROXY`/`no_proxy`，MSYS2 或代理环境常见）时会报
> `Item has already been added. Key in dictionary: 'NO_PROXY'` 并中止冒烟段，脚本以退出码
> 1 结束——这是环境问题，不是产物损坏。本轮首次运行即因此 FAIL（前两节全部 PASS），
> 清理小写重复变量后重跑 `VERIFY: PASS`。若遇同样报错，先在纯 Windows 环境启动，或
> 在两节检查前清理重复变量（如 `unset no_proxy http_proxy https_proxy`）再运行。

手工核对示例（解压后）：

```powershell
# 包内清单校验（PowerShell，按相对路径逐个比对）
Get-Content .\SHA256SUMS.txt | ForEach-Object {
  $parts = $_ -split '\s+', 2
  if ($parts.Count -eq 2) {
    $actual = (Get-FileHash -LiteralPath $parts[1] -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $parts[0]) { Write-Host "MISMATCH $($parts[1])" }
  }
}
```

## 6. Windows 实测记录

执行方式：解压 `evernight-login-0.1.0-dev-windows-amd64.zip` 到临时目录，直接运行包内
二进制（不设置任何额外环境变量）；以下为本轮从干净 HEAD `597b503` 重建产物的实测输出：

| 命令 | 退出码 | 结果 |
|---|---|---|
| `bin\login-server.exe --version` | 0 | `login-server 0.1.0-dev (commit 597b503, built 2026-11-20T17:37:43Z, go1.27.1)` |
| `bin\login-server.exe --help` | 0 | 打印帮助（`serve`、`init`、`completion`、`help` 子命令；帮助文本已同步：设备码/扫码登录 192/193 验收边界、令牌状态查询 introspection 145/160 验收边界，均默认关闭；协议/管理/托管/应用客服 API 默认关闭） |
| `bin\login-server.exe`（无参数） | 1 | stderr：`错误：请使用 serve 或 init 子命令；--help 查看完整帮助`（诚实失败，不伪造启动） |
| `bin\login-backup.exe version` | 0 | `login-backup 0.1.0-dev (commit 597b503, built 2026-11-20T17:37:43Z, go1.27.1)` |
| `bin\loginctl.exe --version` | 0 | `loginctl 0.1.0-dev (commit 597b503, built 2026-11-20T17:37:43Z, go1.27.1)` |
| `go run ./examples/config-load -config <包内>\config\login.example.yaml` | 0 | 样例配置经真实配置加载器校验通过，诊断输出中 `secrets.master_key = [UNSET]`，无秘密泄露 |

`login-server serve` 与 `login-server init` 本轮**未复测**：前者会真实监听端口、后者会在
受控环境创建 root，均超出本轮「不启动服务/监听端口」的验证约束，`verify-release.ps1`
也不覆盖这两条命令。重建后的包内二进制已包含 `serve`/`init` 真实实现（见
`bin/login-server --help` 与 `docs/deployment/README.md` 第 2 节），但**发布前仍应在隔离
环境人工复测启动与初始化**（仓库样例配置的路径/秘密占位符必须先替换）。

`verify-release.ps1` 本轮 **159 项检查全部通过（`Checks run: 159, failures: 0`，
`VERIFY: PASS`，退出码 0）**：6 个压缩包 SHA-256、每包 **112 个条目**的包内校验和、
禁止项扫描、必需文件、Windows 二进制退出码与输出、样例配置校验；首次运行时因宿主环境
大小写重复变量的 `Start-Process` 报错在冒烟段 FAIL，清理重复变量后重跑通过（见第 5 节）。

## 7. 资源路径解析核对

| 资源 | 解析方式 | 结果 |
|---|---|---|
| 内置页面模板/静态资源/中文文案 | `go:embed`（`ui_embed.go`）内嵌进二进制，运行时从 `embed.FS` 读取 | 通过根包单元测试验证（`TestWebUIRenderBuiltinPages`、`TestWebUIAssetsAndI18n`） |
| 迁移脚本 | `migrations/` 内嵌（`go:embed`），启动/迁移时按版本读取 | 通过迁移加载测试与本次构建的 `go build` 验证 |
| 报告 PDF 字体 | 不内嵌；宿主通过受信配置 `reports.Options.FontPath` 提供绝对路径，构造时校验大小/SHA-256/TrueType 轮廓 | 字体文件不随包（体积/许可证约束）；`TestPDFFontValidation` 实测通过（相对路径、缺失文件、非预审摘要、非 TrueType 均被拒绝）；**本次未做真实 PDF 渲染**（本机无字体文件） |
| 运行配置 | 显式路径（`-config`/`LOGIN_*` 环境变量/代码选项），不依赖工作目录以外的隐式位置 | 样例配置经真实加载器校验通过 |

## 8. 已知限制

- 独立服务装配为 MVP：包内 `login-server` 可 `init`/`serve`；OAuth/OIDC 协议端点与管理
  JSON API 已装配但默认关闭（开关见 `standalone-service.md` 第 3.8 节）；设备码与扫码登录已按
  192/193 验收其已实现边界，令牌状态查询（introspection）已实现（145/160 验收边界；默认关闭；mTLS/故障等未实测）；14 个页面选项（默认注册 12、条件 2）；root Passkey 强认证绑定已接线
  但未做真机互操作。不要按“已上线完整 OAuth2/OIDC 服务”宣传本发布包。
- 本轮已从干净 HEAD `597b503` 重建并完成 `verify-release.ps1` 159 项校验；版本号仍为开发态
  `0.1.0-dev`，正式发布版本号需维护者决定后重建。包内文档与 `VERSION.txt`/`README.txt` 由
  构建时检出的内容和脚本文案生成；文档修正提交后按本文件第 1 节重新构建、第 5 节重新校验，
  即包含最新文档与最新运行时边界说明。
- `tools/`、`examples/`、`scripts/` 不随包；包内 `docs/deployment/e2e-smoke.md` 引用的
  `scripts/e2e-login-server.ps1` 与 `tools/loginte2e` 只存在于源码树。
- 仅 Windows amd64 允许实际运行验证；Windows arm64、Linux、macOS 只做编译检查，**未运行**。
  编译成功不等于这些平台的运行、托管或客户端互操作已验证。
- `serve`/`init` 本轮未复测（约束禁止启动服务/端口），见第 6 节；发布前需在隔离环境人工复测。
- `verify-release.ps1` 的禁止项正则覆盖 `.key`/`.pem`/`.p12`/`.pfx`，**不含** `.crt`/`.cer`；
  私钥块扫描只覆盖 ≤2 MB 的文本文件（跳过 `.exe`/`.zip`），二进制内嵌秘密不在扫描范围，
  需要时可人工核对。
- `verify-release.ps1` 在 Windows PowerShell 5.1 下要求进程环境无大小写重复变量
  （如 `NO_PROXY`/`no_proxy`），否则 `Start-Process` 报错中止冒烟段；运行前需清理重复变量
  （见第 5 节），或在纯 Windows 环境运行。
- 未构建/运行容器镜像；容器样例只是配置契约。
- 字体未随包分发，PDF 报告需要单独获取字体并配置路径。
- 发布包应由干净工作树构建（`VERSION.txt` 标注 `worktree_dirty: no`）；若为 `yes` 说明包含
  未提交改动，不得作为正式发布，应由维护者在提交后重新构建。

## 9. 双产品发布打包与独立校验（步骤202）

步骤 202 在步骤 179 的 `dist/build/` + `build-summary.json`（format=1，24/24 已验证、
无 dirty/SKIPPED/FAILED）之上生成**两个产品 x 六个目标 = 12 个 zip**。正式发布包必须由
干净最终提交的隔离树构建；本机隔离树产出的哈希只是验收快照，最终发布哈希以 Lead 在 202
提交后的干净 HEAD 重新执行为准。

### 9.1 包内容来源（以真实 `git ls-files` 为准）

旧规范中的 `config/login.example.yaml`、`config/proxy/`、`deploy/` 在仓库中**从未被跟踪**；
202 按真实存在路径调整，不伪造、不新增不存在的目录（本文第 2 节的旧布局以此节为准）：

| 包 | 内容（显式复制，非 glob 仓库） |
|---|---|
| Login | `bin/{login-server,loginctl,login-backup}[.exe]`；`LICENSE`；`README.md`；`THIRD_PARTY_NOTICES.txt`（来自 `docs/licenses/THIRD_PARTY_NOTICES.md`）；`docs/deployment/samples/` 全部样例（Caddyfile、Dockerfile、docker-compose.yml、nginx-login.conf、*.service、*.plist、install-windows-service.ps1、winsw-*.xml、login.server.example.yaml，以 `git ls-files` 为准）；`README-PACKAGE.txt`、`VERSION.txt`、`BUILDINFO.txt`、`DEPENDENCIES.txt`、包内 `SHA256SUMS.txt`。 |
| Mail | `bin/evernightmail[.exe]`；子模块 `EvernightMail/LICENSE`、`EvernightMail/README.md` → 包根 `LICENSE`/`README.md`；`EvernightMail.example.yaml` → `evernightmail.example.yaml`；`EvernightMail/THIRD_PARTY_NOTICES.md` → `THIRD_PARTY_NOTICES.txt`；选定文档 `docs/{README,config-reference,cli-reference,protocol-matrix,offline-security}.md`；`README-PACKAGE.txt`、`VERSION.txt`、`BUILDINFO.txt`、`DEPENDENCIES.txt`、包内 `SHA256SUMS.txt`。 |

明确不随包：`examples/`（含 external-consumer 示例）、`scripts/`、`tools/`、`_tools/`、
`.ai/`/AGENTS/MEMORY/步骤提示词、`database/`/DB/日志/密钥、子模块源码树、字体本体；
`docs/deployment/samples/` 以样例配置/部署文件形式进包，不自动生效。

### 9.2 打包命令

```powershell
# 前置：干净提交 + 步骤179入口（-Analyze on）重建 dist/build
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\package-release.ps1 `
  -Version 0.1.0 `
  -BuildDir dist\build `
  -BuildSummary dist\build\build-summary.json `
  -OutputDir dist\release\evernight-0.1.0
```

输出：12 个 per-target zip；顶层 `SHA256SUMS.txt`（GNU 格式、LF、字节序排序、不含自身）、
`build-matrix.txt`、`release-summary.json`（format=1，含 zip 与包内文件 size/sha256）、
`RELEASE-NOTES.md` 模板。安全边界：只读 Git/构建树，不做 commit/tag/push/upload，不启动服务/
端口，不联网；显式复制清单 + 写前禁止项扫描；任何**真实存在的必需文件**缺失退出 30，不静默省略。

### 9.3 校验命令与退出码

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-release.ps1 `
  -ReleaseDir dist\release\evernight-0.1.0 `
  -BuildSummary dist\build\build-summary.json
```

校验：顶层文件集合/校验和/矩阵；解压后文件集合、禁止项、必需许可/元数据；包内 SHA256SUMS；
PE/ELF/Mach-O magic+架构、size/sha256 对照 build-summary；Windows/amd64 四命令短冒烟
（login-server `--version`/`--help`、loginctl `--version`、login-backup `version`、
evernightmail `--version`），不启动 `serve`/`init`、不监听端口。

退出码：0 通过；10 发布目录/前置/矩阵结构不符；20 build-summary 不合格（非 24/24、dirty、
SKIPPED/FAILED）；21 解压/文件集合/禁止项；22 顶层或包内校验和不符；30 许可/元数据缺失；
31 二进制类型/架构/冒烟失败；40 内部错误。

### 9.4 隔离树验证记录（2026-11-23，HEAD `e4e6f304`）

- `git archive HEAD` 导出隔离树，补入未提交的两脚本；构建前工作树 clean。
- `build.ps1 -Version 0.1.0-dev`（-Analyze on）：**exit 0**，24/24、dirty=false、
  submodule_gitlinks Mail=`b9891ac…`/GBA=`8764de6…`、tool_sha=`571d986…`、warnings=[]。
- `package-release.ps1`：**exit 0，12 zip**；`verify-release.ps1`：**exit 0**（含 Windows/amd64
  四命令冒烟）。12 zip 大小/SHA256、顶层校验和与验证矩阵见 `docs/acceptance/step202-release.md`。
- 隔离树、临时产物已清理；正式发布包由 Lead 在 202 提交后的干净 HEAD 重新生成，哈希以最终
  产物为准。

### 9.5 已知限制

- zip 不保留 Unix 执行位，Linux/macOS 解压后需 `chmod +x bin/*`；发布说明已标注。
- 仅 Windows/amd64 运行冒烟；其他五目标只做编译/类型/SHA 检查。
- 字体文件本体不随包（仅 OFL 文本）；PDF 报告使用系统/外部字体。
- PowerShell 7 未在本机实测（仅 Windows PowerShell 5.1）。
