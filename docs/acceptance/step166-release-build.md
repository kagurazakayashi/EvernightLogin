# 步骤 166 验收：构建/发布准备（脏树候选）

- 执行者：大肥鱼助手，2026-11-21 23:34–2026-11-22 00:12（Asia/Shanghai）。环境：Windows 11、Go 1.27.1、`CGO_ENABLED=0`、`GOMAXPROCS=2`（构建脚本内部）、`-trimpath`、版本注入。
- **基线声明：dirty 候选**。`build-matrix.txt` 明确记录 `commit=200bfac worktree_dirty=yes`；本候选不是干净提交基线，干净基线待用户/Lead 提交后按同一脚本重建。未做 Git 写操作、未改 Mail 子模块。
- 结论：**PASS（dirty 候选）**。六目标全部构建成功，`verify-release.ps1` 修复后真实运行 **full 183 checks / 0 failures** 与 **-SkipBinaryRun 171 checks / 0 failures**；LICENSE（Mulan PSL v2+署名）已随新候选打包并通过校验。
- 候选目录：`P:/go/tmp/login-release/20261121-235557/`；证据复制在 `docs/acceptance/evidence/step166-*`。

## 1. 构建矩阵

目标：windows/amd64、windows/arm64、linux/amd64、linux/arm64、darwin/amd64、darwin/arm64；全部 `code=built`。每个 zip 内含 `bin/login-server|loginctl|login-backup`、`VERSION.txt`、`BUILDINFO.txt`、`DEPENDENCIES.txt`、`README.txt`、`LICENSE`、`docs/licenses/THIRD_PARTY_NOTICES.md`、部署文档与示例配置。

- 版本注入：`login-server 0.1.0-dev (commit 200bfac, built 2026-11-21T15:55:59Z, go1.27.1)`（Windows 冒烟实测）。
- 顶层 `SHA256SUMS.txt` 六条；`build-matrix.txt` 记录版本/commit/dirty/go/CGO/GOMAXPROCS。
- 证据：`step166-build-matrix.txt`、`step166-SHA256SUMS.txt`、`step166-build-console.log`。

## 2. verify-release.ps1 修复（审计复跑 FAIL → PASS）

审计发现独立复跑 `-SkipBinaryRun` FAIL（Expand-Archive 路径错误），且本机 PowerShell 5.1 进程环境存在大小写重复代理变量导致 `Start-Process` 环境字典异常。修复（仅 scripts/，不改产品代码）：
1. 脚本边界清理重复 `http_proxy/HTTP_PROXY` 等大小写代理变量，避免 5.1 `Start-Process` 抛 "Item has already been added"；
2. 用 `System.IO.Compression.ZipFile::ExtractToDirectory`（2 参数重载，PS5.1 兼容）替代 `Expand-Archive`，显式创建/清理目标目录，兼容空格/中文路径与长临时路径（短 `lv-XXXXXXXX` 临时根）；
3. 移除重复 `$loginBackup` 赋值；保持所有既有检查（内容、排除策略、内层清单、私钥扫描、版本/帮助冒烟、示例配置校验）。

真实运行：
- full：**Checks run: 183, failures: 0 → VERIFY: PASS**（含 Windows amd64 冒烟与示例配置真实 loader 校验）；
- `-SkipBinaryRun`：**Checks run: 171, failures: 0 → VERIFY: PASS**。
- 旧候选（LICENSE 加入前构建）在修复脚本下仅剩 12 个 LICENSE 检查失败，证明审计的 Expand-Archive 问题已消除；新候选（LICENSE 已存在）全部通过。
- 证据：`step166-verify-full.log`、`step166-verify-skip-binrun.log`。

## 3. Windows 冒烟（解压真实 windows/amd64 包）

| 命令 | 结果 |
|---|---|
| `login-server --version` | exit 0；输出含 `0.1.0-dev`/commit |
| `login-server --help` | exit 0 |
| `login-server init --help` | exit 0 |
| `login-server serve --help` | exit 0 |
| `loginctl --version` / `help` | exit 0 |
| `login-backup version` / `help` | exit 0 |
| `login-server serve --check` | exit 1：`unknown flag: --check`（当前 serve 未实现 --check；非发布阻断，记录为已知 CLI 能力缺口） |
| LICENSE | 含 Mulan PSL v2、`Copyright (c) KagurazakaYashi(KagurazakaMiyabi)`、无年份；`docs/licenses/THIRD_PARTY_NOTICES.md`+deps 存在 |

证据：`step166-windows-smoke.log`。

## 4. 未测/限制

1. **dirty 候选**：非干净提交基线；干净基线需用户提交后重建并重跑 verify。
2. 仅 Windows amd64 做运行冒烟；linux/darwin 四目标仅交叉编译产物与包内容校验，未在对应 OS 运行（约定允许的静态/编译检查）。
3. `serve --check` 未实现（unknown flag），未用其他命令冒充；建议后续步骤补齐 `--check` 或在发布说明中明确。
4. 未做安装包/服务托管实机、未做真实反代/HTTPS 部署；未做第三方杀毒/签名验证。
5. 116/156 的 authorized E2E 仍 PARTIAL，不在本步宣称为 PASS。
