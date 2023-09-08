# 步骤179 验收：两项目一键六平台构建入口（PASS_WITH_NOTES）

- 执行者：代码编写团队 并行主力程序员 zfyhelper9，2026-11-23 04:3x–04:5x（Asia/Shanghai）。
- 环境：Windows 11、Go 1.27.4 amd64、`GOMAXPROCS=2`/`-p` 由工具夹紧（预算 2）、`CGO_ENABLED=0`、`GOTOOLCHAIN=local`、`GOWORK=off`、`GOFLAGS=-mod=readonly`；真实临时输出目录 `P:\go\tmp\round9-step179-full`（结束后清理）。
- 固定版本：父仓库 HEAD `ad3df992df22905dc605e2a87b1639fd4dfcd889`；EvernightMail 子模块 `b9891ac569c7f5a0530ac74b73dfe8d5a9441b6e`（175 提交）；go-build-all 子模块 `8764de6504db1ecd1ecc5c3d4dd6618b51699cf1`（179 工具提交，父 gitlink 将在 179 父提交中更新）。
- 结论：**PASS_WITH_NOTES**。真实一次命令产出 **4 产品 × 6 目标 = 24 个产物**；`scripts/verify-build.ps1` 独立校验 24/24（manifest 字段、大小、SHA-256、PE/ELF/Mach-O magic 与架构）通过；版本元数据经 `-ldflags` 注入后由真实 Windows 二进制 `--version` 验证；产物类型/架构由 magic 判定而非扩展名；失败注入（篡改/删除/换类型/坏清单/坏目标/坏命令/坏工具链）均非 0 退出且退出码符合契约。**未做**最终 zip 打包（D2：12 个 per-target zip 由 202 生成），非 Windows 入口仅静态审阅。

## 1. 入口与用法

| 文件 | 说明 |
|---|---|
| `build.ps1` | 根目录主入口（Windows PowerShell 5.1/7），透传参数到 `scripts/build-all.ps1` |
| `build.cmd` | cmd 包装，转发同一参数/退出码 |
| `build.sh` | POSIX 维护入口，委托 PowerShell 版本（单源逻辑）；**未在 Linux/macOS 实测**，仅静态审阅 |
| `scripts/build-all.ps1` | 预检 → 源码构建工具到 `_tools/` → 串行两次 go-build-all → 调校验器 → 写 `build-summary.json`/`checklist.txt` |
| `scripts/verify-build.ps1` | 独立 24 项产物校验器（manifest + 文件类型/架构/大小/SHA-256） |

```powershell
# 仓库根目录：四产品 × 六目标，输出 dist/build
.\build.ps1

# 指定版本/子集/输出目录（排障）
.\build.ps1 -Version 1.0.0 -Products login -Targets windows/amd64,linux/amd64 -OutputDir P:\go\tmp\build-out
```

退出码：0 成功；10 预检失败；20 工具构建失败；21 Login 构建失败；22 Mail 构建失败；30 manifest/聚合字段不符；31 产物缺失/类型/尺寸/SHA 不符；40 内部错误。

输出目录安全：`-OutputDir` 已存在且非空时，只有目录内含 `.build-all-root` 构建标记（本入口生成）才会自动清理；否则必须显式传 `-ForceClean`，不会直接 `Remove-Item -Recurse -Force` 用户目录。

## 2. 真实全量运行结果

命令（输出目录为临时目录，避免污染 `dist/`）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1 -OutputDir P:\go\tmp\round9-step179-full -Version 0.1.0-dev -Analyze off
```

| 项目 | 结果 |
|---|---|
| 构建命令退出码 | **0**（Login 调用 exit 0，162464 ms；Mail 调用 exit 0，44440 ms；两次串行） |
| go-build-all 工具 | 从固定源码 `8764de6` 构建到 `_tools/`，记录 SHA-256 `571d986db8263bb2f6abab2eff5c3530e7018811e0ab751016bafd9fe2ea8cdd`；不进入产品清单 |
| 聚合清单 | Login/Mail manifest 各 18/6 条结果；`exit_code=0`、`summary.failed=0/skipped=0`、`requested==effective==六目标`、`build_options{trimpath:on,buildvcs:off,ldflags非空}`、`tool_version=8764de6…`、并发预算 `budget=2` 且 `workers×per_build_p≤2` |
| 产物校验 | `verify-build.ps1` 输出 `manifests=32 ok, artifacts=24/24 ok, warnings=0 -> exit 0`；`totals expected=24 verified=24 failed=0` |
| 产物矩阵 | login-server / loginctl / login-backup / evernightmail × windows/amd64、windows/arm64、linux/amd64、linux/arm64、darwin/amd64、darwin/arm64 |
| 类型/架构判定 | 24/24 通过 magic：`PE/amd64`、`PE/arm64`、`ELF/amd64`、`ELF/arm64`、`Mach-O/amd64`、`Mach-O/arm64`（Windows PE Machine 0x8664/0xAA64；ELF e_machine 0x3E/0xB7；Mach-O cputype 0x01000007/0x0100000C） |
| 工具是否混入产品 | 否：清单仅 4 个产品；verifier 断言 `matrix.noToolArtifact` |

样例证据（已另存，路径见 §6）：`checklist.txt` 每行含 product/平台/类型/大小/SHA-256；`build-summary.json` 含 `tool/go/modules/invocations/submodule_gitlinks/checklist/totals/warnings`（`modules[]` 记录 name/root/commit/dirty，父仓库子模块指针单独记录在顶层 `submodule_gitlinks{mail,tool}`）；`verify-result.json` 含 32 项 manifest 检查与 24 项产物检查。

## 3. 版本元数据与可复现性

- 两次工具调用均传 `-trimpath -buildvcs=false -L "-s -w -X …version=0.1.0-dev -X …commit=… -X …buildTime=…"`（Login 包路径 `github.com/kagurazakayashi/EvernightLogin.{version,commit,buildTime}`；Mail 为 `…/internal/version.{Version,Commit,BuildDate}`）。
- 真实 Windows/amd64 产物运行验证：
  - `login-server --version` → `login-server 0.1.0-dev (commit ad3df99…, built 2026-11-22T20:36:13Z, go1.27.4)`；loginctl/login-backup 相同 commit/buildTime。
  - `evernightmail --version` → `EvernightMail 0.1.0-dev`，`commit: b9891ac…`，`build date: 2026-11-22T20:36:13Z`。
- `go version -m login-server.exe` 含 `build -trimpath=true`、`CGO_ENABLED=0`、`GOOS=windows`、`GOARCH=amd64`；`-buildvcs=false`/`-ldflags` 文本不被 Go 回显（以 manifest `build_options` + 运行输出为证据）。

## 4. 失败注入（校验器与入口必须非 0）

| 注入 | 预期 | 实测退出码 |
|---|---|---|
| 截断一个产物（保留文件） | 31 | **31**（`artifacts=23/24`） |
| 把产物替换为文本（类型错误） | 31 | **31** |
| 删除一个产物 | 31 | **31** |
| 篡改 manifest `summary.failed=1` | 30 | **30**（`MANIFEST FAIL: EvernightLogin.summary`） |
| 恢复被篡改产物/清单后复查 | 0 | **0**（24/24） |
| 非法目标 `-Targets nosuch/os` | 10 | **10**（预检拒绝） |
| Login 坏命令（非 main 包） | 21 | **21**（工具 exit 1 → build-all 21） |
| Mail 坏命令（非 main 包） | 22 | **22** |
| 不支持的工具链模式 `-GoToolchain exact:1.2` | 10 | **10** |
| verifier magic 自检 `verify-build.ps1 -SelfTest` | 0 | **0**（6 类二进制 + 1 个文本拒绝） |

## 5. 已知限制与注意事项

1. 本次全量运行使用了 `-Analyze off`：父仓库工作树存在其他在研步骤（188）的测试文件语法错误 `internal/serverapp/manual_recovery_integration_test.go`，会使工具默认 `go vet ./...` 预构建步骤失败；**该文件不属于 179**。默认值为 `on`；179 父提交后应在干净工作树用默认值复跑一次。
2. 父仓库工作树当时包含其他在研改动（`dirty=yes`），`build-summary.json` 已记录；正式发布需在干净提交上重建。
3. 父 gitlink 当时仍指向 175 前的 `60384c3`/178 的 `c22190a`，脚本默认警告、`-StrictGitlink` 可失败；179 父提交会同时更新两个 gitlink 到 `b9891ac`/`8764de6`。`build-summary.submodule_gitlinks{mail,tool}` 记录的是**构建时父仓库 HEAD 中真实 gitlink**，不随子模块 HEAD 猜测。
4. 非 Windows 入口（`build.sh`）仅静态审阅，未在 Linux/macOS 实机运行；项目约束为“其他平台仅编译/静态检查”。
5. **12 个 per-target zip 未生成**：按 D2 由步骤202 基于 179 的 24 项目录与 `build-summary.json` 生成。
6. 未做长时间/压力测试；单次全量构建（含两次工具调用与 24 次编译）约 3.5 分钟。

## 6. 证据与复现

- 入口/脚本：`build.ps1`、`build.cmd`、`build.sh`、`scripts/build-all.ps1`、`scripts/verify-build.ps1`。
- 发布包（12 个 per-target zip）由步骤 202 基于本步 24 项目录生成，命令/布局/校验见
  [`docs/deployment/packaging.md`](../deployment/packaging.md) §9。
- 样例证据（提交边界之外、开发记录）：`.ai/lead/reports/step179-build-summary.sample.json`、`.ai/lead/reports/step179-checklist.sample.txt`、`.ai/lead/reports/step179-verify-result.sample.json`；详细报告 `.ai/lead/reports/step179-dev.md`。
- 复现：

```powershell
cd P:\go\src\github.com\kagurazakayashi\EvernightLogin
$env:GOMAXPROCS='2'
powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1 -OutputDir P:\go\tmp\build-179
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-build.ps1 `
  -BuildRoot P:\go\tmp\build-179 -Version 0.1.0-dev `
  -LoginManifest P:\go\tmp\build-179\login\EvernightLogin.manifest.json `
  -MailManifest P:\go\tmp\build-179\mail\EvernightMail.manifest.json
```

清理：本次运行产物（约 450 MB）与冒烟/注入临时目录已在记录后删除；仓库内只保留源码与文档改动。
