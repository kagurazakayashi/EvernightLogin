# 发布包、跨平台构建与校验清单

本文件说明如何从源码构建 login 的本地发布包、包内容、跨平台构建状态与校验方法。
**只准备本地产物**：不创建标签、不提交、不 push、不上传、不创建远程 release。

## 1. 构建方式（可复现）

```powershell
# 在仓库根目录；Windows PowerShell 5.1 或 PowerShell 7 均可
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build-release.ps1 `
  -OutputDir P:\go\tmp\deploy-step89 -Version 0.1.0-dev
```

固定条件：

- `CGO_ENABLED=0`、`GOMAXPROCS=2`；
- `-trimpath`、`-buildvcs=false`；
- 通过 `-ldflags` 注入 `version`/`commit`/`buildTime`（`login.CurrentBuildInfo` 读取）；
- 每个目标独立执行三次 `go build`（`./cmd/login-server`、`./cmd/loginctl`、
  `./cmd/login-backup`），失败时如实记录失败原因，**不生成空文件占位**；
- 版本信息包含提交号与工作树是否干净，便于区分“源码构建”和“含未提交改动的构建”。

构建脚本与校验脚本都是**只读 Git**：仅 `git rev-parse`/`git status --porcelain` 读取
当前状态，不做任何 Git 写操作。

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
- 仓库内的其它源码目录与构建缓存。

脚本使用**显式复制清单**组装包内容，因此仓库里新增的文件不会被自动打进包；需要新增
运行时资源时应显式修改 `scripts/build-release.ps1` 的复制清单。

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

本轮实际执行的矩阵结果（真实命令与状态，未运行的目标不写成“通过”）：

| 目标 | 代码 | 编译（`CGO_ENABLED=0`） | 运行 |
|---|---|---|---|
| windows/amd64 | 有 | 成功（3 个二进制） | **实测通过**（解压后运行 `--version`/`--help`/无参数/备份工具/管理 CLI，见第 6 节） |
| windows/arm64 | 有 | 成功（3 个二进制） | 未运行（按项目约束只允许 Windows amd64 运行） |
| linux/amd64 | 有 | 成功（3 个二进制） | 未运行（按项目约束不做运行实测） |
| linux/arm64 | 有 | 成功（3 个二进制） | 未运行（按项目约束不做运行实测） |
| darwin/amd64 | 有 | 成功（3 个二进制） | 未运行（按项目约束不做运行实测） |
| darwin/arm64 | 有 | 成功（3 个二进制） | 未运行（按项目约束不做运行实测） |

本轮构建信息：`go1.27.4 windows/amd64`，`commit=96d1a23`，`worktree_dirty=yes`
（包含步骤 84 未提交改动与步骤 89 新增文件），`build_time=2026-11-19T18:53:16Z`；
6 个目标全部构建成功，无失败目标，未用空文件占位。构建输出目录：
`P:\go\tmp\deploy-step89`（临时目录，不属于仓库）。

构建矩阵的完整机器可读记录也在构建输出目录的 `build-matrix.txt` 中。

## 5. SHA-256 校验清单与验证

- 顶层 `SHA256SUMS.txt`（构建输出目录）：每个目标压缩包的 SHA-256。
- 包内 `SHA256SUMS.txt`：包内每个文件的 SHA-256（清单自身除外），相对路径便于解压后
  直接校验。
- 校验脚本：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-release.ps1 `
  -ReleaseDir P:\go\tmp\deploy-step89 -ExpectedVersion 0.1.0-dev
```

校验脚本会：核对顶层清单；逐包解压到临时目录；核对包内清单；检查禁止项（AI 文件、
数据库、日志、密钥/证书、`.env`、`secrets/`）；检查必需文件与三个二进制；扫描文本
文件中的私钥块；在 Windows 上实际运行 `windows/amd64` 二进制并检查退出码与输出。

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
二进制（不设置任何额外环境变量）：

| 命令 | 退出码 | 结果 |
|---|---|---|
| `bin\login-server.exe --version` | 0 | 打印构建信息 |
| `bin\login-server.exe --help` | 0 | 打印帮助（列出 `serve`、`init` 子命令与参数） |
| `bin\login-server.exe`（无参数） | 1 | stderr：提示使用 `serve` 或 `init` 子命令（诚实失败，不伪造启动） |
| `bin\login-server.exe serve --config <包内>\config\login.example.yaml` | 0/1 | 配置/数据库/密钥/迁移条件满足时真实启动 HTTP 服务；缺失时明确失败（样例配置需替换路径与主密钥后使用） |
| `bin\login-server.exe init --config <包内>\config\login.example.yaml` | 0/1 | 本地受控首次初始化；重复执行返回 1（需在受控环境手动执行，不在冒烟脚本内自动建 root） |
| `bin\login-backup.exe version` | 0 | 打印构建信息 |
| `bin\loginctl.exe --version` | 0 | 打印构建信息 |
| `go run ./examples/config-load -config <包内>\config\login.example.yaml` | 0 | 样例配置经真实配置加载器校验通过，诊断输出中 `secrets.master_key = [UNSET]`，无秘密泄露 |

“启动→示例配置→停止”的说明：`login-server serve` 已能真实启动，但既有发布产物早于本轮
宿主装配，需在干净工作树重新构建后按上表复测；仓库样例配置的路径/秘密占位符必须先替换
（不监听端口、无后台进程）；上面的版本/帮助命令与配置校验是当前真实可验证的启动边界。
`verify-release.ps1` 的 159 项检查全部通过（6 个压缩包 SHA-256、每包 111 个条目的包内
校验和、禁止项扫描、必需文件、Windows 二进制退出码与输出、样例配置校验）。

## 7. 资源路径解析核对

| 资源 | 解析方式 | 结果 |
|---|---|---|
| 内置页面模板/静态资源/中文文案 | `go:embed`（`ui_embed.go`）内嵌进二进制，运行时从 `embed.FS` 读取 | 通过根包单元测试验证（`TestWebUIRenderBuiltinPages`、`TestWebUIAssetsAndI18n`） |
| 迁移脚本 | `migrations/` 内嵌（`go:embed`），启动/迁移时按版本读取 | 通过迁移加载测试与本次构建的 `go build` 验证 |
| 报告 PDF 字体 | 不内嵌；宿主通过受信配置 `reports.Options.FontPath` 提供绝对路径，构造时校验大小/SHA-256/TrueType 轮廓 | 字体文件不随包（体积/许可证约束）；`TestPDFFontValidation` 实测通过（相对路径、缺失文件、非预审摘要、非 TrueType 均被拒绝）；**本次未做真实 PDF 渲染**（本机无字体文件） |
| 运行配置 | 显式路径（`-config`/`LOGIN_*` 环境变量/代码选项），不依赖工作目录以外的隐式位置 | 样例配置经真实加载器校验通过 |

## 8. 已知限制

- 独立服务装配为 MVP：包内 `login-server` 可 `init`/`serve`；OAuth/OIDC 协议端点与管理
  JSON API 已装配但默认关闭（开关见 `standalone-service.md` 第 3.8 节）；设备码/扫码/
  令牌状态查询未启用；14 个页面选项（默认注册 12、条件 2）；root Passkey 强认证绑定已接线
  但未做真机互操作。发布包重建前不要按“已上线完整 OAuth2/OIDC 服务”宣传。
- 本轮未重新构建发布包；既有产物早于宿主装配，`--version`/帮助/无参数行为需重建后复测。
- 仅 Windows amd64 允许实际运行验证；Windows arm64、Linux、macOS 只做编译检查，**未运行**。
- 未构建/运行容器镜像；容器样例只是配置契约。
- 字体未随包分发，PDF 报告需要单独获取字体并配置路径。
- 构建包含工作树中未提交改动（若 `VERSION.txt` 标注 `worktree_dirty: yes`），发布前应由
  维护者用提交后的干净工作树重新构建。
