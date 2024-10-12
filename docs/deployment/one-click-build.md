# 一键构建入口与可追溯产物清单（步骤 239）

本文描述父仓库根目录的一键构建入口、可追溯清单字段、失败/取消语义与清理边界。
工具链固定为 `CGO_ENABLED=0`、`GOTOOLCHAIN=local`、`GOWORK=off`、
`GOFLAGS=-mod=readonly`、`GOMAXPROCS=2`；构建本身**不执行 Git 写操作**，不读取
`database/login.db`。

## 1. 入口

| 入口 | 依赖 | 说明 |
|---|---|---|
| `build.ps1` / `build.cmd` | Windows PowerShell 5.1/7 | 推荐主入口；参数与退出码透传 `scripts/build-all.ps1` |
| `build.sh`（自动） | POSIX shell + PowerShell（若存在） | 默认自动选用 `pwsh`/`powershell`，与 `build.ps1` 使用同一逻辑 |
| `build.sh --no-powershell`（原生） | 仅 POSIX shell + Go | 仅在缺少 PowerShell 时使用：从固定源码构建 `go-build-all`，编排 Login 四程序（含 login-setup）与 Mail，生成清单/校验和 |

示例：

```powershell
# 五产品 × 六目标（默认输出 dist/build）
.\build.ps1 -Version 0.1.0-dev

# 指定子集/临时输出目录（正式验收不要污染 dist/）
.\build.ps1 -Products login -Targets windows/amd64 -OutputDir P:\go\tmp\build-239
```

```sh
# POSIX：有 PowerShell 时自动委托；--no-powershell 强制原生 Go+shell 路径
sh build.sh --no-powershell --products login --targets windows/amd64 \
  --output-dir /tmp/build-239 --version 0.1.0-dev
```

## 2. 固定版本与工具来源

| 项 | 固定值 |
|---|---|
| go-build-all 子模块 | `8764de6504db1ecd1ecc5c3d4dd6618b51699cf1` |
| EvernightMail 子模块 | `aa7ccf57f0c0a8bb000a7dff6f101983ed6219fa` |
| Go | ≥ `1.27.0`（`GOTOOLCHAIN=local`） |

构建先从**固定源码**在输出目录 `_tools/` 构建 `go-build-all`（记录 SHA-256，不进入
产品清单），再分两次串行调用：Login（`cmd/login-server`、`cmd/loginctl`、
`cmd/login-backup`、`cmd/login-setup`）与 Mail（`cmd/evernightmail`），五程序 × 六目标共 30 项产物。

## 3. 输出与可追溯清单

默认输出 `dist/build/`（可用 `-OutputDir`/`--output-dir` 指定）：

```text
dist/build/
  .build-all-root              # 构建目录标记（仅用于安全清理判定）
  _tools/                      # 固定源码构建的 go-build-all（不进入产品清单）
  login/EvernightLogin.manifest.json
  login/<command>/<goos>_<goarch>/...    # 四命令：login-server/loginctl/login-backup/login-setup
  mail/EvernightMail.manifest.json
  mail/evernightmail/<goos>_<goarch>/...
  build-summary.json           # 聚合清单（见下）
  checklist.txt                # 逐产物人读清单
  verify-result.json           # 独立校验器结果（PowerShell 路径）
  build.log                    # 本次构建 stdout 记录
```

`build-summary.json`（format=1）至少包含：

| 字段 | 含义 |
|---|---|
| `version` / `build_time` / `generated_at` / `duration_ms` | 版本、注入构建时间、生成时间、总耗时 |
| `status` / `cancelled` / `stage` / `exit_code` | `completed`/`failed`/`cancelled`、是否取消、阶段、退出码 |
| `entry.wrapper` / `entry.script` / `entry.arguments` | 真实入口（如 `build.ps1` 或 `build.sh --no-powershell`）、核心脚本、本次参数 |
| `host` | 操作系统、PowerShell/宿主信息 |
| `tool` | 固定 go-build-all commit、构建路径、工具 SHA-256 |
| `go` | Go 版本、宿主 GOOS/GOARCH、CGO/GOTOOLCHAIN/GOWORK/GOFLAGS |
| `modules[]` | Login/Mail 根、commit、`dirty` 标志 |
| `submodule_gitlinks` | 父仓库 HEAD 中真实 gitlink（mail/tool） |
| `platforms` | 本次要求的目标矩阵 |
| `invocations[]` | 每次 `go-build-all` 调用：product、exit_code、duration_ms、module_root、output_root |
| `artifacts[]` | 逐产物：product、**command 入口**、goos/goarch、type/arch、version、commit、size、SHA-256、相对 path、status |
| `checklist` / `totals` | 独立校验器逐项结果与 expected/verified/failed 汇总 |
| `warnings` | 脏工作树、gitlink 漂移等非致命告警 |

POSIX 原生路径生成结构等价的 `build-summary.json`（`entry.wrapper=build.sh`、
`host.shell=posix-sh`、`artifacts[]` 含同样字段）以及 `checklist.txt`、
`SHA256SUMS.txt`。

## 4. 退出码、失败与取消

| 退出码 | 含义 |
|---|---|
| 0 | 成功（清单/校验完成） |
| 10 | 预检/参数/输出目录/固定版本检查失败 |
| 20 | go-build-all 工具构建失败 |
| 21 / 22 | Login / Mail 构建失败 |
| 30 / 31 | manifest 聚合字段不符 / 产物缺失、类型、尺寸或 SHA-256 不符 |
| 40 | 内部错误 |
| 130 | 被取消（已写 `status=cancelled` 的部分清单） |

- 任一子构建失败立即传播非 0，并写 `status=failed` 的部分 `build-summary.json`
  （包含失败阶段/退出码/入口参数/已完成调用）；
- Ctrl+C/取消（PowerShell 入口）或 `INT`/`TERM`（POSIX 原生路径）写
  `status=cancelled` 的部分清单并退出 130；本次启动的子进程随前台构建结束，不遗留后台进程；
- 仅用于诊断/测试的显式取消钩子：设置环境变量 `LOGIN_BUILD_TEST_CANCEL=after-preflight`
  时，PowerShell 入口在预检后写取消清单并退出 130（不用于生产）。

## 5. 清理边界

- 默认 `dist/build`：只有目录内存在 `.build-all-root` 标记（本入口生成）才会被安全清理；
- 已存在且非空的非构建目录：拒绝覆盖（退出 10），需另选 `-OutputDir`/`--output-dir`；
- **不会清理** `dist/release`、用户 `bin/`、仓库源码或其他步骤产物；
- 临时目录示例：`P:\go\tmp\build-239`，验收后手动删除即可。

## 6. 验证口径

- Windows amd64：真实编译并运行 `--version` 校验注入的版本/commit/buildTime；
- Windows arm64 / Linux / macOS：交叉编译成功并记录为“已编译、未运行”；
- 产物类型/架构由 `scripts/verify-build.ps1` 用 PE/ELF/Mach-O magic 判定，不依赖扩展名；
- 失败注入（非法目标、输出目录冲突、坏命令等）必须传播非 0，不得伪造成功。

## 7. 本步实测记录（Windows 11 / Go 1.27.4）

| 项目 | 命令 | 结果 |
|---|---|---|
| 四产品 × 六目标 | `powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1 -OutputDir P:\go\tmp\build239-final -Version 0.1.0-dev -Analyze off` | exit 0；24/24 产物校验通过；`entry.wrapper=build.ps1`；summary 含 24 条 artifact（product/command/goos/goarch/version/commit/size/sha256/path） |
| Windows amd64 运行 | `login-server.exe --version`、`loginctl.exe --version`、`login-backup.exe --version`、`evernightmail.exe --version` | 版本/commit/build date 与清单一致（父 commit、Mail `aa7ccf5…`） |
| POSIX 原生路径 | `sh build.sh --no-powershell --products login --targets windows/amd64 --output-dir .ai/tmp/build239-final-sh` | exit 0；`entry.wrapper=build.sh`、`host.shell=posix-sh`、3 条 artifact 含 64 位 SHA-256；未调用 PowerShell |
| 取消 | `LOGIN_BUILD_TEST_CANCEL=after-preflight`（诊断钩子） | exit 130；summary `status=cancelled`、`cancelled=true` |
| 构建失败 | `-Products login -Commands cmd/no-such-main` | exit 21；summary `status=failed`、`stage=login-build` |
| 输出目录保护 | 对已存在且非空的普通目录使用 `-OutputDir` | exit 10，拒绝覆盖 |
| 文档校验 | `go run ./scripts/verify-docs` | PASS checks=12 |

证据小样（开发记录，不进发布包）：`.ai/lead/tmp/step239/build-summary-full.json`、
`checklist-full.txt`、`verify-result-full.json`、`build-summary-shell-login.json`、
`build-summary-cancelled.json`、`build-summary-failed.json`。
本次运行父工作树含其他并行步骤改动（`dirty=yes` 已如实记录）；正式发布需在干净提交上复跑。

## 8. 步骤 299 追加：五程序 × 六目标（30 项）

299 在既有 24 项入口上加入 `cmd/login-setup`，五程序 = Login 四程序（login-server、loginctl、
login-backup、login-setup）+ Mail（evernightmail）。2026-11-26 在当前工作树（包含本步未提交改动，
summary 如实记录 dirty=yes）执行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1 -Version 0.1.0-dev -Products all -OutputDir P:\go\tmp\r11-ws5-build30 -Jobs 4
```

结果：**exit 0；verify-build artifacts=30/30；build-summary totals=30/30/0**；清单按产品统计为
login-server 6、loginctl 6、login-backup 6、login-setup 6、evernightmail 6。Windows amd64 额外
运行 `login-setup.exe --version` 返回 `login-setup devel (commit ...)` 并退出 0；其余平台仅编译，
未运行实测。正式发布仍须在干净提交上复跑（本步只做定向/接入验证，最终全量包留最后合并步骤）。