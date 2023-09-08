# EvernightMail 子模块前置、提交顺序与可复现性

本文说明 EvernightLogin 与 `EvernightMail` 子模块的开发/测试前置、构建检查、发布边界和用户提交顺序。**AI 助手不执行 git add/commit/push、不初始化或更新子模块、不创建提交引用**；下列命令均由维护者人工执行。

## 1. 两个仓库的边界

- `EvernightLogin`（父仓库，Go module `github.com/kagurazakayashi/EvernightLogin`）是身份与权限系统，包含生产 SMTP/OAuth/OIDC/SQLite。
- `EvernightMail`（独立子模块，`github.com/kagurazakayashi/EvernightMail`）是离线邮件测试服务器，只用于本地协议/邮件流程测试。父项目**生产代码不导入** Mail 的 Go 包；两者通过子进程 + 本地协议/文件交互（测试夹具）。
- 父项目自身构建、`go test`、发布包都不依赖 Mail 存在。Mail 仅供开发/测试门禁和邮件端到端验证使用。

## 1.1 Login 生产邮件配置与验收状态（2026-11-21）

- Login 的生产邮件默认 **`mail.enabled=false`**；启用后使用真实 SMTP：`mail.smtp.addr/host/tls_mode/trusted_roots/username/password/timeout_seconds`、`mail.from.*`、`mail.delivery.max_attempts/timeout_seconds` 等 14 个字段，字段级说明见 `docs/guide/configuration.md`。
- 步骤 139 安全复验 PASS_WITH_NOTES（14 个 `LOGIN_MAIL_*` 环境变量已真实生效）；140/141 已出邮件验证/找回告知 dev 报告；**162 邮件失败/验证码失效/安全告知联动尚未验收**，真实第三方外发未验收。
- 测试只连本地 EvernightMail（本文件前置），不向真实用户/第三方地址发送；SMTP 接受成功不等于外部最终送达，投递状态/重试/审计以 Login 邮件队列与 139/162 证据为准。

## 2. 新克隆/新机器前置

```powershell
# 在父仓库根目录，由维护者执行（AI 不执行 Git 写操作）
git submodule update --init --recursive EvernightMail
```

缺少 `EvernightMail/` 时，父项目仍可构建与发布；使用 `scripts/check.ps1 -Mail` 会给出准确的前置提示并失败。可先用：

```powershell
# 只读检查：.gitmodules、目录、go.mod、Go 版本、gitlink/pin 状态、可构建性
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/mail-preflight.ps1 -Build
```

`-Build` 只在临时目录构建 `EvernightMail/cmd/evernightmail` 并运行 `version` 验证；临时二进制随后删除，不写入 Mail 工作树。Mail 需要 Go 1.27+（以 Mail 自身 `go.mod` 为准）。

## 3. 开发检查命令

```powershell
# 父项目检查（不含 Mail；根 gofmt 已显式排除 EvernightMail）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check.ps1

# 父项目 + Mail 独立检查（Mail 缺失即失败；Mail 未固定/不干净给出明确警告）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check.ps1 -Mail

# 要求父 gitlink + Mail 干净提交（用于发布前可复现门禁）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check.ps1 -Mail -RequirePinned

# Mail 夹具测试（需要步骤 135/136 完成且 Mail 二进制可用；默认不随 -Mail 运行）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check.ps1 -Mail -MailTests

# 仅 Mail 前置检查，不跑父项目测试
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/mail-preflight.ps1 -Build -RequireMail -RequirePinned
```

可选环境变量：

- `EVERNIGHTMAIL_BIN`：指定一个已构建的 `evernightmail` 可执行文件；Mail 测试夹具优先使用它，避免重复构建。二进制必须来自可信构建（版本信息会记录在测试证据中）。
- `EVERNIGHTMAIL_REQUIRED=1`：夹具在缺少二进制/无法构建时失败而非跳过（`check.ps1 -Mail` 会自动设置）。

## 4. 可复现版本与用户提交顺序

父项目要固定 Mail 版本，必须由维护者按以下顺序完成（**不能把未提交的 Mail 目录称为已固定的可复现版本**）：

1. 在 `EvernightMail/` 内审查并提交 Mail 成果，推送到其远端；记录 Mail 提交号。
2. 回到父仓库，确认 `.gitmodules` 的 `EvernightMail` 条目正确（path/url/branch），添加父仓库 gitlink 指针。
3. 在父仓库提交 `.gitmodules` 与 `EvernightMail` gitlink（父提交引用 Mail 提交号）。
4. 用隔离副本复现（见 §5）。只有父 gitlink 存在且 Mail 工作树干净时，该版本才是可复现的。

检查当前状态（只读）：

```powershell
git -C EvernightMail rev-parse --verify HEAD   # 无输出/失败 = Mail 尚无提交
git ls-files --stage -- EvernightMail          # 空 = 父仓库尚无 gitlink
git status --porcelain -uall                   # 核对 .gitmodules / EvernightMail 未被意外跟踪
```

AI 助手不会创建这些提交，也不会用 `submodule add/update` 改变用户仓库；报告只列出候选与命令。

## 5. 隔离副本复现

父仓库完成 gitlink 提交后，用干净克隆/本地无硬链接副本验证（避免污染工作树）：

```powershell
$tmp = Join-Path $env:TEMP ("evernight-repro-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
git clone --recurse-submodules <parent-repo-url> $tmp
# 或本地仓库：git clone --no-hardlinks --recurse-submodules P:\go\src\github.com\kagurazakayashi\EvernightLogin $tmp
Set-Location $tmp
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check.ps1 -Mail -RequirePinned
```

若 Mail 尚未提交/gitlink 未提交，上述命令应明确失败（缺少子模块或 pin 不成立），不得据此宣称可复现。当前步骤 137 已提供脚本适配；最终回归在 Mail 提交与步骤 135/136 完成后执行。

## 6. 发布包与测试器边界

- `scripts/build-release.ps1` 只构建 `cmd/login-server`、`cmd/loginctl`、`cmd/login-backup`，**不包含** `EvernightMail`、测试夹具或测试邮件工具。
- 一键构建入口（步骤 179）`build.ps1` 在干净提交/固定 gitlink 下同时构建 Login 三命令与 Mail 的 `cmd/evernightmail`（六目标、24 项产物、`dist/build/build-summary.json`），两个模块串行调用 go-build-all；任一步失败即非 0。发布打包（步骤 202）`scripts/package-release.ps1` 按 2 产品 × 6 目标生成 12 个 zip，Mail 使用独立 `evernightmail-<version>-<os>-<arch>.zip`；Mail 独立 Windows 功能复验记录见 `EvernightMail/docs/acceptance/step175-windows.md`。
- 生产发布包不需要 Mail 的测试器；Mail 只用于开发测试与发布前邮件链路验证。发布包内不包含 `tools/`、`examples/`、`scripts/`，也不包含测试器源码或构建产物；Mail zip 只含 `bin/evernightmail`、许可证/第三方声明、样例配置与最小运行文档。
- 开发包/源码树可保留测试夹具（例如父项目 `internal/mailtest`，迁移完成后）与 Mail 子模块，但不得把它们误打进生产发布包。
- 推送/发布/上传仍由维护者人工执行；AI 不推送远端、不创建发布包上传。

## 7. 故障排查

| 现象 | 处理 |
|---|---|
| `check.ps1 -Mail` 提示子模块未初始化 | 维护者执行 `git submodule update --init --recursive EvernightMail`；确认父仓库已包含 gitlink |
| Mail 目录存在但 `HEAD` 不存在 | Mail 尚未提交；先完成 Mail 提交/推送，再更新父 gitlink |
| `-RequirePinned` 失败 | 父仓库无 gitlink、Mail 未提交或工作树不干净；按 §4 顺序提交后再验证 |
| Mail 构建失败 | 在 `EvernightMail/` 单独运行 `go build ./cmd/evernightmail`；检查 Go 1.27+；不得通过修改父项目去适配 Mail |
| 夹具找不到二进制 | 设置 `EVERNIGHTMAIL_BIN` 指向可信构建，或允许夹具在临时目录外部构建 |
