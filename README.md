# login

login 提供可嵌入 Go 程序的用户与权限组件，并计划提供独立的 OAuth 2.0 / OpenID Connect 身份服务。当前只是最小可编译骨架，不是可运行的用户系统。

## 项目状态（步骤 03）

- 模块路径：`github.com/kagurazakayashi/EvernightLogin`，根包名 `login`；路径来自现有远端，首次发布后不再变更。
- 独立进程入口：`cmd/login-server`。当前只提供 `--version` 和 `--help`；不带参数运行会明确失败并返回非零，不假装服务已启动。
- 已实现：版本与构建信息；可独立调用的类型化配置加载器（内置默认值、YAML、`LOGIN_` 环境变量和显式代码选项的合并、严格校验、脱敏诊断、热更新/重启分类）。
- 尚未实现：HTTP 监听、账户/认证/授权、数据库访问、OAuth/OIDC、Web 页面和审计；配置加载器尚未接入服务启动。
- 代码检查只在本地运行，未配置自动远程流水线。

## 配置加载（步骤 03）

覆盖顺序固定为（后者覆盖前者）：

1. 内置默认值（`login.Default`）
2. YAML 文件或内容
3. 环境变量（固定 `LOGIN_` 前缀，名称是稳定契约）
4. 宿主显式代码选项（`login.Overrides`；指针字段用于区分显式 `false`/`0` 与未设置）

最小调用示例：

```go
cfg, err := login.Load(login.LoadOptions{
    YAMLFile: "login.yaml",
    Overrides: &login.Overrides{
        Database: login.DatabaseOverrides{WAL: login.Ptr(false)},
    },
})
if err != nil {
    // 配置非法：此处必须直接返回，不能先监听端口或打开数据库。
    return err
}
fmt.Print(cfg.Diagnostic()) // 已脱敏；秘密只显示 [REDACTED]/[UNSET]
```

配置字段与环境变量：

| 字段 | 环境变量 | 重载方式 |
|---|---|---|
| server.listen_addr | LOGIN_SERVER_LISTEN_ADDR | 需重启 |
| server.public_base_url | LOGIN_SERVER_PUBLIC_BASE_URL | 需重启 |
| server.shutdown_timeout_seconds | LOGIN_SERVER_SHUTDOWN_TIMEOUT_SECONDS | 可热更新 |
| logging.level | LOGIN_LOGGING_LEVEL | 可热更新 |
| logging.format | LOGIN_LOGGING_FORMAT | 可热更新 |
| database.driver | LOGIN_DATABASE_DRIVER | 需重启 |
| database.path | LOGIN_DATABASE_PATH | 需重启 |
| database.wal | LOGIN_DATABASE_WAL | 需重启 |
| database.busy_timeout_ms | LOGIN_DATABASE_BUSY_TIMEOUT_MS | 需重启 |
| secrets.master_key | LOGIN_SECRETS_MASTER_KEY | 需重启 |

环境变量名是稳定契约，实际列表以 `login.Fields()` 返回值为准。

校验行为：

- 未知字段、重复键、类型错误、`null`、超范围值、非法组合（例如公开地址使用 `http` 却监听非回环地址）都会在加载阶段失败，不产生监听或数据库副作用。
- YAML 只能写秘密来源引用（`secrets.master_key.file` 或 `secrets.master_key.env`）；秘密值也可来自 `LOGIN_SECRETS_MASTER_KEY` 环境变量或宿主显式选项。错误、日志和 `Diagnostic` 输出都不包含秘密内容。
- 字段变更是否需要重启由 `login.Fields()` 与 `login.DiffReload` 给出；本步不实现配置后台或自动热更新。

最小可运行示例见 `examples/config-load`（不会监听端口或写数据库）：

```bat
go run .\examples\config-load -config examples\config-load\login.example.yaml
```

## 本地检查（Windows）

在项目根目录运行：

```bat
scripts\check.cmd
```

脚本优先使用 PowerShell 7，未安装时使用 Windows PowerShell 5.1，并依次执行 gofmt 检查、`go mod verify`、`go mod tidy -diff`、`go build`、`go vet` 和 `go test`。它固定 `CGO_ENABLED=0`、`GOTOOLCHAIN=local`，构建并发取逻辑处理器数量的一半且至少为 1；任何一步失败都会返回非零。

版本与帮助：

```bat
go build ./...
go run .\cmd\login-server --version
go run .\cmd\login-server --help
```

## 包含内容

| 路径 | 用途 | 是否应提交 Git |
|---|---|---|
| AGENTS.md | AI 约束与总体结构 | 否 |
| MEMORY.md | AI 本地进度交接 | 否 |
| .ai/ | 第 01～17 步完整提示词和完整步骤标题索引 | 否 |
| go.mod、go.sum | Go 模块与依赖锁定 | 是 |
| cmd/、internal/、scripts/ | 最小入口、内部实现与本地检查命令 | 是 |
| examples/ | 可运行的最小接入示例（当前为配置加载示例） | 是 |
| docs/requirements/ | 功能清单和错误码手册 | 可以 |
| docs/database/ | 数据库基线说明、表清单与检查记录 | 可以 |
| database/login.db | 已创建的空业务 SQLite 数据库 | 否，运行数据应本地保存 |
| database/0001_design_baseline.sql | 建库结构，需在开发阶段审查 | 可以 |
| tools/ | 可选的 Python 建库、只读检查工具 | 可以 |
| .gitignore | AI 文件、数据库与秘密排除规则 | 可以 |
| SHA256SUMS.txt | 启动包文件完整性清单 | 可留作交付记录 |

## 开始工作

1. 解压到新的目录，不要直接覆盖现有项目。
2. 使用 IDE 打开目录，让 AI 先读取 AGENTS.md 和 MEMORY.md。
3. 步骤 01～03 已完成；继续时按 .ai/ 中的顺序处理步骤 04，每次只把一个步骤的完整提示词交给 AI。
4. 每步结束检查修改和实际测试结果，由你自行提交代码。AI 不提交项目成果、不执行任何 git push。
5. 完成第 17 步后，提供 MEMORY.md 与必要代码状态，再生成下一部分和更新 AGENTS.md。

数据库已建好，不需要先运行任何建库命令，也没有 root 初始密码。管理员将在步骤 28 的受控初始化流程创建。

可选检查（Windows 安装 Python 3 后，在本目录执行）：

```bat
py -3 tools\check_database.py
```

从 SQL 另建一个数据库（目标文件必须不存在）：

```bat
py -3 tools\create_database.py --output database\login-new.db
py -3 tools\check_database.py database\login-new.db
```

Python 只用于启动包辅助工具，不是将来 Go 产品的运行依赖。JSON 约束需要 SQLite 提供 json_valid；若 Python 自带 SQLite 太旧或缺少该功能，工具会报错，不能静默删掉约束。

## 重要边界

- 本库是可打开、可校验的结构基线，没有业务实现；不代表权限检查和身份认证已经安全可用。
- 数据库结构覆盖后续模块，仍需第 06～07 步结合选定 Go 驱动审查和正式迁移。不得在已有业务库上重复执行建库 SQL。
- 文件中没有预置秘密、真实用户、远程服务地址或生产邮件配置。
- 启动包本身不含 go.mod；当前工作区已在步骤 02 建立 `go.mod`/`go.sum` 并锁定已验证依赖。
- .gitignore 只对未跟踪文件生效；已有仓库中被跟踪的 AI 文件需检查后处理。启动包本身没有创建 Git 仓库，也没有提交或上传代码。
