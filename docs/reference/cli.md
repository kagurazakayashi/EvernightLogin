# CLI 参考（login-server / loginctl / login-backup / login-setup）

> 命令树、flag 与退出码由 AST 扫描 `cmd/` 与 `internal/managecli/` 实际注册生成；任务导向说明见 [../guide/root-cli.md](../guide/root-cli.md)、[../guide/backup-and-restore.md](../guide/backup-and-restore.md) 与 [../deployment/standalone-service.md](../deployment/standalone-service.md)。

## 1. 通用约定

- CLI 只负责装配与命令执行；不绕过领域授权、敏感策略或审计。本地应急命令要求停服/维护 + 排他锁。
- 危险写动作要求显式确认参数（如 `--confirm ...`）或近期再次认证证明；确认框/参数存在不等于放行，服务端会重新判定。
- `--json` 输出为机器可读结果，可能包含 `request_id` 与稳定错误码；不要把输出中的秘密/令牌写日志或工单。
- 退出码 0 表示成功；非 0 的稳定含义见各程序“退出码”表（`login-server` 为 0/1；`loginctl`、`login-backup` 有细分稳定码）。脚本应依据退出码与 `--json` 结果判断，而不是解析人类文本。
- 未知子命令/参数一律拒绝并给出用法，不静默忽略。

## 程序：login-server（2 个子命令）

| 子命令 | flag 数 | 定义位置 |
|---|---|---|
| `init` | 6 | `cmd/login-server/main.go` |
| `serve` | 19 | `cmd/login-server/main.go` |

### `login-server init` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--config` | string | `` | YAML 配置文件路径（必需） |
| `--database` | string | `` | 覆盖配置中的 SQLite 数据库文件路径 |
| `--maintenance-state-dir` | string | `` | 库外维护状态目录（默认与 serve 相同） |
| `--master-key-file` | string | `` | 主密钥环文件路径；配置未设置 secrets.master_key 时必需（不存在则生成受保护文件） |
| `--operator` | string | `` | 本地受控操作者标识（默认由操作系统本地管理员身份推导） |
| `--password-file` | string | `` | 受保护密码文件路径（仅所有者可读写；不提供命令行明文密码） |

### `login-server serve` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--access-log` | string | `` | W3C 访问日志文件路径（默认写 stderr；文件日志默认受控轮转） |
| `--access-log-max-bytes` | int64 | `0` | 访问日志单文件字节上限（0 使用默认 64 MiB，允许 1 MiB～1 GiB） |
| `--access-log-max-files` | int | `0` | 访问日志保留的历史文件数量（0 使用默认 5，允许 1～100，不含当前文件） |
| `--admin-api-prefix` | string | `` | 管理 API 站内前缀（默认 /admin/v1，不允许覆盖页面命名空间） |
| `--allow-legacy-without-sensitive` | bool | `false` | 过渡开关：允许会话管理访问仅走旧强认证闸门（未装配敏感策略，默认 fail-closed） |
| `--allow-uninitialized` | bool | `false` | 仅开发/测试：允许数据库尚未完成首次初始化时启动（默认拒绝） |
| `--app-support-audience` | string | `` | 应用客服资源 OAuth audience（默认 urn:evernight:app-support） |
| `--app-support-prefix` | string | `` | 应用客服 API 站内前缀（默认 /api/app/v1/support） |
| `--config` | string | `` | YAML 配置文件路径（必需） |
| `--database` | string | `` | 覆盖配置中的 SQLite 数据库文件路径 |
| `--enable-admin-api` | bool | `false` | 启用管理 JSON API（复用管理会话/CSRF 契约；默认关闭，未启用时 404） |
| `--enable-app-support` | bool | `false` | 启用应用受限客服 API（需 OAuth 协议端点；默认关闭） |
| `--enable-managed-api` | bool | `false` | 启用业务应用托管管理 API（用户 Bearer/应用客户端认证；默认关闭，未启用时 404） |
| `--enable-protocol` | bool | `false` | 启用 OAuth 2.0 / OpenID Connect 协议端点（需配置 protocol.issuer；默认关闭，未启用时 404） |
| `--init-maintenance-state` | bool | `false` | 显式允许在已有数据库上创建缺失的库外维护状态（默认 fail-closed） |
| `--maintenance-state-dir` | string | `` | 库外维护状态目录（默认：数据库目录同级的 <数据目录名>-maintenance） |
| `--managed-api-prefix` | string | `` | 业务托管 API 站内前缀（默认 /api/managed/v1） |
| `--master-key-file` | string | `` | 主密钥环文件路径（配置未设置 secrets.master_key 时必需，必须为受保护文件） |
| `--migrate` | string | `` | 执行数据库迁移后再启动：--migrate 或 --migrate=apply（省略值等同于 apply） |

## 程序：loginctl（31 个子命令）

| 子命令 | flag 数 | 定义位置 |
|---|---|---|
| `admin` | 0 | `cmd/loginctl/loginctl.go` |
| `app` | 0 | `cmd/loginctl/loginctl.go` |
| `audit` | 0 | `cmd/loginctl/loginctl.go` |
| `backups` | 0 | `cmd/loginctl/loginctl.go` |
| `case` | 0 | `internal/managecli/online_support_cmd.go` |
| `config` | 0 | `cmd/loginctl/loginctl.go` |
| `confirm` | 0 | `cmd/loginctl/loginctl.go` |
| `deliveries` | 0 | `cmd/loginctl/loginctl.go` |
| `diag` | 0 | `cmd/loginctl/loginctl.go` |
| `group` | 0 | `cmd/loginctl/loginctl.go` |
| `maintenance-enter` | 1 | `cmd/loginctl/restore.go` |
| `maintenance-exit` | 2 | `cmd/loginctl/restore.go` |
| `migrate` | 0 | `cmd/loginctl/loginctl.go` |
| `notifications` | 0 | `cmd/loginctl/loginctl.go` |
| `notify` | 0 | `cmd/loginctl/loginctl.go` |
| `permission` | 0 | `cmd/loginctl/loginctl.go` |
| `recovery` | 0 | `internal/managecli/online_support_cmd.go` |
| `reports` | 0 | `cmd/loginctl/loginctl.go` |
| `restore-apply` | 5 | `cmd/loginctl/restore.go` |
| `restore-disposition` | 1 | `cmd/loginctl/restore.go` |
| `restore-init-state` | 3 | `cmd/loginctl/restore.go` |
| `restore-merge-audit` | 0 | `cmd/loginctl/restore.go` |
| `restore-preflight` | 2 | `cmd/loginctl/restore.go` |
| `restore-reenable` | 3 | `cmd/loginctl/restore.go` |
| `restore-review` | 1 | `cmd/loginctl/restore.go` |
| `role` | 0 | `cmd/loginctl/loginctl.go` |
| `root-recover` | 8 | `cmd/loginctl/loginctl.go` |
| `session` | 0 | `cmd/loginctl/loginctl.go` |
| `task` | 0 | `cmd/loginctl/loginctl.go` |
| `tasks` | 0 | `cmd/loginctl/loginctl.go` |
| `user` | 0 | `cmd/loginctl/loginctl.go` |

### `loginctl maintenance-enter` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--reason` | string | `` | 进入维护的原因（必填） |

### `loginctl maintenance-exit` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--force` | bool | `false` | 存在未完成恢复尝试时仍显式退出（高风险，需明确确认） |
| `--reason` | string | `` | 退出维护的原因（必填） |

### `loginctl restore-apply` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--backup` | string | `` | 待恢复备份文件路径（必填） |
| `--confirm` | string | `` | 显式确认：必须精确输入 RESTORE |
| `--json` | bool | `false` | 以 JSON 输出结果 |
| `--reason` | string | `` | 恢复原因（必填，最多 500 字符） |
| `--service-stopped` | bool | `false` | 确认 login 服务已停止或已处于维护状态（必填，降低运行中执行分脑风险） |

### `loginctl restore-disposition` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--json` | bool | `false` | 以 JSON 输出处置清单 |

### `loginctl restore-init-state` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--adopt-journal` | bool | `false` | 受控破窗：状态文件丢失但库外审计日志有历史事件时，读取日志重算锚点（高风险，需确认） |
| `--confirm` | string | `` | 显式确认：必须精确输入 RESTORE |
| `--reason` | string | `` | 初始化原因（必填） |

### `loginctl restore-preflight` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--backup` | string | `` | 待恢复备份文件路径（必填） |
| `--json` | bool | `false` | 以 JSON 输出预演结果 |

### `loginctl restore-reenable` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--kind` | string | `schedule,webhook` | 要重新启用的类型：schedule、webhook 或逗号分隔组合 |
| `--reason` | string | `` | 重新启用的原因（必填） |
| `--restore-id` | string | `` | 可选：指定恢复运行编号（默认最近一次） |

### `loginctl restore-review` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--restore-id` | string | `` | 可选：指定恢复运行编号（默认最近一次） |

### `loginctl root-recover` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--database` | string | `` | 目标 SQLite 数据库文件路径（必填） |
| `--maintenance` | bool | `false` | 确认实例处于维护状态（与 --service-stopped 至少一个为 true） |
| `--reason` | string | `` | 本地应急恢复原因（必填，最多 500 字符） |
| `--request-id` | string | `` | 可选请求编号，用于关联审计与恢复记录 |
| `--reset-mfa` | bool | `false` | 重置 root 两步验证因素（邮件/TOTP/待处理挑战） |
| `--reset-password` | bool | `false` | 重置 root 正式密码（交互式隐藏输入） |
| `--revoke-login-passkeys` | bool | `false` | 同时撤销 root 的主登录 Passkey（默认保留，需二次确认） |
| `--service-stopped` | bool | `false` | 确认 login 服务已停止（与 --maintenance 至少一个为 true） |

### `loginctl` 稳定退出码

| 常量 | 值 | 含义 |
|---|---|---|
| ExitOK | 0 | 稳定退出码：0 成功 |
| ExitError | 1 | 稳定退出码：0 成功 |
| ExitUsage | 2 | 稳定退出码：0 成功 |
| ExitCancelled | 3 | 稳定退出码：0 成功 |

## 程序：login-backup（8 个子命令）

| 子命令 | flag 数 | 定义位置 |
|---|---|---|
| `create` | 10 | `cmd/login-backup/cli.go` |
| `export` | 11 | `cmd/login-backup/viewer_cli.go` |
| `extract` | 8 | `cmd/login-backup/viewer_cli.go` |
| `info` | 2 | `cmd/login-backup/cli.go` |
| `list` | 3 | `cmd/login-backup/viewer_cli.go` |
| `preview` | 7 | `cmd/login-backup/viewer_cli.go` |
| `tables` | 3 | `cmd/login-backup/viewer_cli.go` |
| `verify` | 3 | `cmd/login-backup/cli.go` |

### `login-backup create` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--avatars` | string | `` | 可选：头像受控存储目录 |
| `--config` | string | `` | 可选：要包含进备份的 YAML 配置路径 |
| `--database` | string | `` | 目标 SQLite 数据库文件路径（必填） |
| `--json` | bool | `false` | 以 JSON 输出结果 |
| `--key-file` | string | `` | 主密钥环文件路径（必填，必须与备份分开） |
| `--operator` | string | `` | 本地操作者标识（必填，可见 ASCII） |
| `--output` | string | `` | 备份输出受控目录（必填，必须已存在） |
| `--progress` | bool | `false` | 向 stderr 输出进度 |
| `--request-id` | string | `` | 可选请求编号，用于关联审计 |
| `--timeout` | duration | `backup.DefaultTimeout` | 备份墙钟上限 |

### `login-backup export` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--columns` | string | `` | 逗号分隔字段白名单；默认全部非敏感字段 |
| `--file` | string | `` | 备份文件路径（必填） |
| `--format` | string | `backup.ExportFormatCSV` | 导出格式：csv 或 json |
| `--include-sensitive` | bool | `false` | 显式包含默认排除的高敏字段 |
| `--json` | bool | `false` | 以 JSON 输出结果摘要 |
| `--key-file` | string | `` | 主密钥环文件路径（必填） |
| `--limit` | int | `backup.DefaultExportRows` | 导出行数上限 |
| `--operator` | string | `` | 本地操作者标识（写入本地操作记录） |
| `--oplog` | string | `` | 本地操作记录文件路径（默认输出目录下） |
| `--output` | string | `` | 绝对输出文件路径（必填，默认不覆盖） |
| `--table` | string | `` | 受控目录表名（必填） |

### `login-backup extract` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--entry` | string | `` | 清单条目名（必填，可用 list 查看） |
| `--file` | string | `` | 备份文件路径（必填） |
| `--include-sensitive` | bool | `false` | 显式允许提取原始数据库条目 |
| `--json` | bool | `false` | 以 JSON 输出结果摘要 |
| `--key-file` | string | `` | 主密钥环文件路径（必填） |
| `--operator` | string | `` | 本地操作者标识（写入本地操作记录） |
| `--oplog` | string | `` | 本地操作记录文件路径（默认输出目录下） |
| `--output` | string | `` | 绝对输出文件路径（必填，默认不覆盖） |

### `login-backup info` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--file` | string | `` | 备份文件路径（必填） |
| `--json` | bool | `false` | 以 JSON 输出结果 |

### `login-backup list` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--file` | string | `` | 备份文件路径（必填） |
| `--json` | bool | `false` | 以 JSON 输出结果 |
| `--key-file` | string | `` | 主密钥环文件路径（必填） |

### `login-backup preview` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--columns` | string | `` | 逗号分隔字段白名单；默认全部非敏感字段 |
| `--file` | string | `` | 备份文件路径（必填） |
| `--include-sensitive` | bool | `false` | 显式包含默认排除的高敏字段 |
| `--json` | bool | `false` | 以 JSON 输出结果 |
| `--key-file` | string | `` | 主密钥环文件路径（必填） |
| `--limit` | int | `backup.DefaultPreviewRows` | 预览行数上限 |
| `--table` | string | `` | 受控目录表名（必填） |

### `login-backup tables` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--file` | string | `` | 备份文件路径（必填） |
| `--json` | bool | `false` | 以 JSON 输出结果 |
| `--key-file` | string | `` | 主密钥环文件路径（必填） |

### `login-backup verify` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--file` | string | `` | 备份文件路径（必填） |
| `--json` | bool | `false` | 以 JSON 输出结果 |
| `--key-file` | string | `` | 主密钥环文件路径（必填） |

### `login-backup` 稳定退出码

| 常量 | 值 | 含义 |
|---|---|---|
| ExitOK | 0 | 稳定退出码 |
| ExitError | 1 | 稳定退出码 |
| ExitUsage | 2 | 稳定退出码 |
| ExitVerifyFailed | 3 | 稳定退出码 |
| ExitDecryptFailed | 4 | 稳定退出码 |
| ExitOutputConflict | 5 | 稳定退出码 |
| ExitQueryInvalid | 6 | 稳定退出码 |
| ExitCancelled | 130 | 稳定退出码 |

## 程序：login-setup（17 个子命令）

| 子命令 | flag 数 | 定义位置 |
|---|---|---|
| `accounts apply` | 12 | `cmd/login-setup/noninteractive.go` |
| `accounts list` | 3 | `cmd/login-setup/noninteractive.go` |
| `apply` | 8 | `cmd/login-setup/noninteractive.go` |
| `check` | 3 | `cmd/login-setup/noninteractive.go` |
| `commands` | 3 | `cmd/login-setup/noninteractive.go` |
| `db init` | 6 | `cmd/login-setup/noninteractive.go` |
| `db test` | 4 | `cmd/login-setup/noninteractive.go` |
| `export config` | 6 | `cmd/login-setup/noninteractive.go` |
| `import config` | 6 | `cmd/login-setup/noninteractive.go` |
| `plan` | 4 | `cmd/login-setup/noninteractive.go` |
| `presets install` | 4 | `cmd/login-setup/noninteractive.go` |
| `recover apply` | 5 | `cmd/login-setup/noninteractive.go` |
| `recover plan` | 4 | `cmd/login-setup/noninteractive.go` |
| `root init` | 14 | `cmd/login-setup/noninteractive.go` |
| `root status` | 3 | `cmd/login-setup/noninteractive.go` |
| `selftest` | 3 | `cmd/login-setup/noninteractive.go` |
| `status` | 3 | `cmd/login-setup/noninteractive.go` |

### `login-setup accounts apply` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--config` | string | `` | login.yaml 配置路径（默认尝试当前目录 login.yaml） |
| `--confirm` | string | `` | 逐字确认串 APPLY-ACCOUNT |
| `--generate-password` | bool | `` | 生成临时密码 |
| `--generated-password-file` | string | `` | 临时密码写入的受控文件（0600，新建） |
| `--master-key-file` | string | `` | 可选：本地维护会话使用的主密钥环文件（默认按配置/实例目录解析） |
| `--nickname` | string | `` | 昵称（可空） |
| `--password-file` | string | `` | 从 0600 受限文件读取密码 |
| `--password-stdin` | bool | `` | 从标准输入读取密码 |
| `--print-generated` | bool | `` | 允许把临时密码打印到标准输出（显式通道） |
| `--scheme` | string | `` | 账户方案 key（accounts list） |
| `--username` | string | `` | 用户名 |
| `--version` | bool | `false` | 打印版本信息后退出 |

### `login-setup accounts list` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--config` | string | `` | login.yaml 配置路径（默认尝试当前目录 login.yaml） |
| `--master-key-file` | string | `` | 可选：本地维护会话使用的主密钥环文件（默认按配置/实例目录解析） |
| `--version` | bool | `false` | 打印版本信息后退出 |

### `login-setup apply` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--config` | string | `` | login.yaml 配置路径（默认尝试当前目录 login.yaml） |
| `--confirm` | string | `` | 逐字确认串 APPLY-RECOMMENDATION |
| `--conflict-policy` | string | `` | 外部修改冲突策略：fail\|reload\|use-draft |
| `--create-master-key` | bool | `` | 初始化数据库时允许新实例生成主密钥 |
| `--init-db` | bool | `` | 保存后对当前 SQLite 配置执行幂等迁移 |
| `--master-key-file` | string | `` | 可选：本地维护会话使用的主密钥环文件（默认按配置/实例目录解析） |
| `--profile` | string | `` | 推荐配置方案：local\|intranet\|embedding |
| `--version` | bool | `false` | 打印版本信息后退出 |

### `login-setup check` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--config` | string | `` | login.yaml 配置路径（默认尝试当前目录 login.yaml） |
| `--master-key-file` | string | `` | 可选：本地维护会话使用的主密钥环文件（默认按配置/实例目录解析） |
| `--version` | bool | `false` | 打印版本信息后退出 |

### `login-setup commands` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--config` | string | `` | login.yaml 配置路径（默认尝试当前目录 login.yaml） |
| `--master-key-file` | string | `` | 可选：本地维护会话使用的主密钥环文件（默认按配置/实例目录解析） |
| `--version` | bool | `false` | 打印版本信息后退出 |

### `login-setup db init` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--config` | string | `` | login.yaml 配置路径（默认尝试当前目录 login.yaml） |
| `--confirm` | string | `` | 逐字确认串 INIT-DATABASE |
| `--create-master-key` | bool | `` | 允许新实例生成受保护主密钥 |
| `--master-key-file` | string | `` | 可选：本地维护会话使用的主密钥环文件（默认按配置/实例目录解析） |
| `--sqlite-path` | string | `` | 覆盖 SQLite 数据库路径（默认取配置文件值） |
| `--version` | bool | `false` | 打印版本信息后退出 |

### `login-setup db test` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--config` | string | `` | login.yaml 配置路径（默认尝试当前目录 login.yaml） |
| `--master-key-file` | string | `` | 可选：本地维护会话使用的主密钥环文件（默认按配置/实例目录解析） |
| `--sqlite-path` | string | `` | 覆盖 SQLite 数据库路径（默认取配置文件值） |
| `--version` | bool | `false` | 打印版本信息后退出 |

### `login-setup export config` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--config` | string | `` | login.yaml 配置路径（默认尝试当前目录 login.yaml） |
| `--encrypted` | bool | `` | 导出可还原的加密敏感配置包 |
| `--masked` | bool | `` | 导出默认脱敏配置 YAML（不含秘密值） |
| `--master-key-file` | string | `` | 可选：本地维护会话使用的主密钥环文件（默认按配置/实例目录解析） |
| `--out` | string | `` | 导出目标路径（必须不存在） |
| `--version` | bool | `false` | 打印版本信息后退出 |

### `login-setup import config` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--config` | string | `` | login.yaml 配置路径（默认尝试当前目录 login.yaml） |
| `--confirm` | string | `` | 预览要求的确认串 |
| `--conflict-policy` | string | `` | 冲突策略：fail\|reload\|use-draft |
| `--file` | string | `` | 导入源（.yaml 脱敏导出或 .lncfg 加密包） |
| `--master-key-file` | string | `` | 可选：本地维护会话使用的主密钥环文件（默认按配置/实例目录解析） |
| `--version` | bool | `false` | 打印版本信息后退出 |

### `login-setup plan` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--config` | string | `` | login.yaml 配置路径（默认尝试当前目录 login.yaml） |
| `--master-key-file` | string | `` | 可选：本地维护会话使用的主密钥环文件（默认按配置/实例目录解析） |
| `--profile` | string | `` | 推荐配置方案：local\|intranet\|embedding |
| `--version` | bool | `false` | 打印版本信息后退出 |

### `login-setup presets install` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--config` | string | `` | login.yaml 配置路径（默认尝试当前目录 login.yaml） |
| `--confirm` | string | `` | 逐字确认串 INSTALL-PRESETS |
| `--master-key-file` | string | `` | 可选：本地维护会话使用的主密钥环文件（默认按配置/实例目录解析） |
| `--version` | bool | `false` | 打印版本信息后退出 |

### `login-setup recover apply` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--config` | string | `` | login.yaml 配置路径（默认尝试当前目录 login.yaml） |
| `--confirm` | string | `` | 计划要求的确认串 |
| `--master-key-file` | string | `` | 可选：本地维护会话使用的主密钥环文件（默认按配置/实例目录解析） |
| `--profile` | string | `` | 推荐运行配置方案 |
| `--version` | bool | `false` | 打印版本信息后退出 |

### `login-setup recover plan` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--config` | string | `` | login.yaml 配置路径（默认尝试当前目录 login.yaml） |
| `--master-key-file` | string | `` | 可选：本地维护会话使用的主密钥环文件（默认按配置/实例目录解析） |
| `--profile` | string | `` | 推荐运行配置方案 |
| `--version` | bool | `false` | 打印版本信息后退出 |

### `login-setup root init` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--config` | string | `` | login.yaml 配置路径（默认尝试当前目录 login.yaml） |
| `--confirm` | string | `` | 逐字确认串 INIT-ROOT |
| `--generate-password` | bool | `` | 生成高熵一次性密码 |
| `--generated-password-file` | string | `` | 一次性密码写入的受控文件（0600，新建） |
| `--language` | string | `` | 语言（可空） |
| `--master-key-file` | string | `` | 可选：本地维护会话使用的主密钥环文件（默认按配置/实例目录解析） |
| `--nickname` | string | `` | root 昵称（可空） |
| `--password-file` | string | `` | 从 0600 受限文件读取密码 |
| `--password-stdin` | bool | `` | 从标准输入读取密码（不回显） |
| `--print-generated` | bool | `` | 允许把一次性密码打印到标准输出（显式通道） |
| `--reset-existing` | bool | `` | 对已初始化 root 本地重设密码 |
| `--timezone` | string | `` | 时区（可空） |
| `--username` | string | `` | root 保留用户名（只接受 root/空） |
| `--version` | bool | `false` | 打印版本信息后退出 |

### `login-setup root status` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--config` | string | `` | login.yaml 配置路径（默认尝试当前目录 login.yaml） |
| `--master-key-file` | string | `` | 可选：本地维护会话使用的主密钥环文件（默认按配置/实例目录解析） |
| `--version` | bool | `false` | 打印版本信息后退出 |

### `login-setup selftest` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--config` | string | `` | login.yaml 配置路径（默认尝试当前目录 login.yaml） |
| `--master-key-file` | string | `` | 可选：本地维护会话使用的主密钥环文件（默认按配置/实例目录解析） |
| `--version` | bool | `false` | 打印版本信息后退出 |

### `login-setup status` 的 flag

| flag | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--config` | string | `` | login.yaml 配置路径（默认尝试当前目录 login.yaml） |
| `--master-key-file` | string | `` | 可选：本地维护会话使用的主密钥环文件（默认按配置/实例目录解析） |
| `--version` | bool | `false` | 打印版本信息后退出 |

## 嵌套子命令说明

- `loginctl` 的部分命令是命令组：`loginctl config <子命令>`、`loginctl diag <子命令>`、`loginctl user list`、`loginctl audit events list` 等；上面只展开顶层命令与其 flag，二级动作以 [../guide/root-cli.md](../guide/root-cli.md) 与 `loginctl help` 为准。
- `login-server` 使用 cobra 命令树（`serve`、`init`），全局 `--version/--help` 由框架提供。
- `login-setup` 的顶层子命令来自其显式命令表，flag 含全局 `--config`/`--master-key-file`/`--json` 与各命令附加项；需要 PTY 的是全屏 CUI，非交互命令不需要。`login-backup` 的每个子命令都有独立 flag（见上表）；离线查看/导出不连接生产库。
- Phase B 可继续补齐命令组二级动作与每命令的鉴权/审计边界；本页当前覆盖顶层命令、flag 与退出码。

## 机器可读

- [cli-commands.json](cli-commands.json)：程序/子命令/flag/退出码完整机器表。
- 生成源：`cmd/`（cobra 与 `flag.NewFlagSet`）与 `internal/managecli/`（`args[0]` 分派）。
