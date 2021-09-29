# 快速开始

本文给出一条**当前版本真实可执行**的最短路径：从空配置开始，校验配置、迁移一个临时
数据库、做本地诊断、装配自检。最后如实说明“从空配置到安全初始化”卡在哪里、为什么
不能跳过。

> 运行环境：Windows 11 / amd64 / Go 1.27.4（本项目唯一运行实测平台）。
> 全部命令默认**在仓库根目录**执行，示例使用 cmd 语法；PowerShell 请把
> `set X=Y` 写成 `$env:X="Y"`、把 `%TEMP%\x` 写成 `$env:TEMP\x`。
> 临时文件只放在仓库外的临时目录，不接触仓库内 `database/login.db`。

## 1. 准备

```bat
:: 确认 Go 可用；本项目要求与 go.mod 一致的 Go 版本
go version

:: 构建三个本地工具到临时目录（不写入仓库）
set GOMAXPROCS=2
set CGO_ENABLED=0
if not exist %TEMP%\login-begin mkdir %TEMP%\login-begin
go build -o %TEMP%\login-begin\ .\cmd\login-server .\cmd\loginctl .\cmd\login-backup
```

预期：`go build` 退出码 0，`%TEMP%\login-begin\` 下出现 `login-server.exe`、
`loginctl.exe`、`login-backup.exe`。

> 本文不配置任何真实秘密，也不连接真实数据库。所有数据库操作使用临时目录中的新文件。

## 2. 第 1 步：空配置时的行为

空配置不是“随便跑起来”，而是明确的默认值或明确失败：

```bat
:: 无 YAML 时，默认配置可查看（不监听端口、不打开数据库）
%TEMP%\login-begin\loginctl.exe config show --json

:: 明确指定一个不存在的 YAML：必须失败，不能静默使用默认值
go run .\examples\config-load -config %TEMP%\login-begin\does-not-exist.yaml
```

预期（Windows amd64 实测）：

- `config show --json` 退出码 0，`data.field_count` 为 `37`，秘密字段显示 `[UNSET]`；
  `hot_reloadable` 只有 `server.shutdown_timeout_seconds`、`logging.level`、
  `logging.format` 三项。
- 指定不存在的文件时退出码 1，输出“配置检查失败：配置错误(…读取 YAML 配置文件失败)”。

这证明了两点：默认值只监听本机回环；显式传入的配置路径不会因为读取失败而被默认值
静默替代。

## 3. 第 2 步：校验样例配置

```bat
%TEMP%\login-begin\loginctl.exe config validate --config docs\deployment\samples\login.server.example.yaml --json
```

预期：退出码 0，`data.valid` 为 `true`，`data.field_count` 为 `37`。

样例文件里的域名、路径、证书名都是**占位符**，`tls_terminating_proxy` 等字段只是演示
组合；真正部署前必须替换，并按 [configuration.md](configuration.md) 校正。

## 4. 第 3 步：迁移一个临时数据库

```bat
:: 新建临时目录；用环境变量把数据库指到临时文件（避免默认 database/login.db）
set LOGIN_DATABASE_PATH=%TEMP%\login-begin\data\login.db
if not exist %TEMP%\login-begin\data mkdir %TEMP%\login-begin\data

:: 1) 空库不存在时，migrate status 不会创建数据库
%TEMP%\login-begin\loginctl.exe migrate status

:: 2) 执行迁移：必须显式确认服务已停止
%TEMP%\login-begin\loginctl.exe migrate apply --confirm MIGRATE --service-stopped

:: 3) 复查版本
%TEMP%\login-begin\loginctl.exe migrate status --json
```

预期（Windows amd64 实测）：

- 第 1 条退出码 1，错误码 `DATABASE_NOT_INITIALIZED`，明确说明“不会创建新数据库”。
- 不带 `--confirm MIGRATE` 的 `migrate apply` 退出码 2，错误码 `USAGE_INVALID`。
- 带确认的 `migrate apply` 退出码 0，`data.applied` 列出 `0001`…`0044` 共 44 个迁移。
- 复查 `migrate status`：`applied_count=44`、`applied_version="0044"`、`current=true`。

迁移只作用于临时库；已应用的迁移不可改写，真实部署中迁移前必须先备份（见
[backup-and-restore.md](backup-and-restore.md)）。

## 5. 第 4 步：本地诊断

```bat
%TEMP%\login-begin\loginctl.exe diag database --json
%TEMP%\login-begin\loginctl.exe diag health --json
%TEMP%\login-begin\loginctl.exe task list --json
%TEMP%\login-begin\loginctl.exe user list --operator local-admin --json
```

预期（Windows amd64 实测）：

- `diag database`：退出码 0，`database`、`database.integrity`、`migration` 三项均为
  `ok`（若刚迁移完，版本为 `0044`）。
- `diag health`：退出码 **1**，状态 `degraded`；配置、数据库、迁移为 `ok`，`maintenance`
  为 `unverified`（没有提供 `--state-dir` 与主密钥环，无法验证维护状态）。这是**如实
  降级**，不是“坏了”。
- `task list`：退出码 0，`jobs: []`。
- `user list --operator local-admin`：退出码 0，`users: []`（新库没有账户，唯一 root
  尚未创建，见第 7 节）。

维护状态与证书、邮件诊断的完整要求见 [root-cli.md](root-cli.md) 与
`docs/deployment/standalone-service.md`。

## 6. 第 5 步：装配自检（Go 嵌入路径）

当前版本唯一能“真正启动服务”的路径是宿主用 Go API 装配。仓库提供了两个**不监听端口**
的自检示例：

```bat
:: 配置加载 + 内置页面 + HTTP Handler + 监听组件构造（只构造，不 Start）
go run .\examples\deployment-minimal -config docs\deployment\samples\login.server.example.yaml

:: 外部 module 仅用公开 API 的完整示例（独立 go.mod）
cd examples\external-consumer
go run .
```

预期（Windows amd64 实测）：

- `deployment-minimal` 退出码 0，输出“装配检查通过（未监听端口）”。
- `external-consumer` 退出码 0，输出“示例通过：外部模块仅用公开 API …”，覆盖配置、
  扩展注册、HTTP 挂载、生命周期、失败传播与 fail-closed 判定。

这两个示例证明公开 API 可编译、可装配；**它们不监听端口、不启动真实身份服务**，不能
当作已部署完成的证据。

## 7. 第 6 步（阻塞）：安全初始化

目标流程是：创建唯一 root → 获得一次性配置凭证 → 兑换凭证 → 设置正式密码并配置强认证
→ 进入 `ready`。当前版本**无法由外部部署者完成**：

| 环节 | 当前状态 | 结论 |
|---|---|---|
| 领域服务 `internal/bootstrap`（初始化/兑换/重发/状态/强认证授权） | 已实现并有测试 | 能力存在 |
| `cmd/login-server` 的首次配置 CLI/HTTP 入口 | **未实现**（只有 `--version`/`--help`） | 不能从命令行初始化 |
| HTTP 首次配置页面/接口 | **未实现**（也没有匿名远程入口） | 不能从浏览器初始化 |
| `internal/bootstrap` 的外部导入 | 不可能（Go `internal` 规则） | 外部宿主也不能直接调用 |
| 已初始化 root 的应急恢复 | `loginctl root-recover` 可用（本地、停服/维护 + 排他锁） | 仅用于已初始化实例 |

```bat
:: 实测：服务入口不会假装启动
%TEMP%\login-begin\login-server.exe
```

预期：退出码 **1**，stderr 明确说明 HTTP 监听与 OAuth/OIDC/管理接口尚未实现。
**不要**尝试用示例程序或自建脚本“先造一个 root”绕过初始化流程；那会得到一个无法证明
身份来源、也缺少受限初始化语义的账户，违反项目安全边界。

因此，本版本从空配置能安全走到的是：**配置校验 → 迁移 → 本地诊断 → 嵌入装配自检**；
再往后的“首次初始化 + 对外服务”需要“服务启动装配 + 首次配置入口”先实现（见
`docs/deployment/first-run.md` 第 2 节）。

## 8. 清理临时文件

```bat
rmdir /s /q %TEMP%\login-begin
```

确认仓库内没有新增 exe、数据库、日志或临时配置（`git status` 只应显示本次文档改动与你
原有的未提交改动）。

## 9. 命令与预期结果速查

| 命令 | 退出码 | 说明 |
|---|---|---|
| `loginctl config show --json` | 0 | 显示默认/有效配置（脱敏） |
| `loginctl config validate --config <path>` | 0/1/2 | 0 通过；1 配置无效；2 用法错误 |
| `loginctl migrate status` | 0/1 | 1 表示库不存在或版本不一致 |
| `loginctl migrate apply --confirm MIGRATE --service-stopped` | 0/1/2 | 2 表示缺少确认/参数错误 |
| `loginctl diag database` | 0/1 | 1 表示检查未通过 |
| `loginctl diag health` | 0/1 | 维护状态未验证时为 1（degraded） |
| `login-server`（无参数） | 1 | 明确报告服务功能尚未实现 |
| `go run ./examples/deployment-minimal` | 0 | 装配自检，不监听端口 |

下一步阅读：[deployment-modes.md](deployment-modes.md)（选部署形态）→
[configuration.md](configuration.md)（配好 37 个字段）→
[api-status.md](api-status.md)（宿主集成）。
