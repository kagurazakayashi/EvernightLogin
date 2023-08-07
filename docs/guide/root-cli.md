# 本地管理 CLI（loginctl）

`loginctl` 是 login 的**本地**管理/应急命令行工具。它不是远程管理接口：不监听端口、
不联网、不发送邮件；只在服务器本机、服务已停止或维护状态下执行敏感操作。

## 1. 通用约定

- 所有命令：`loginctl <命令组> <子命令> [参数]`；`loginctl help` 查看总览，
  `loginctl <命令组> --help` 查看子命令用法。
- `loginctl version` / `loginctl --version`：打印版本并退出 0。
- 多数命令支持 `--json`：输出统一外壳 `{"ok":bool,"command":"...","data":{...}}` 或
  `{"ok":false,"error":{"code","message","details"}}`。
- `--config <file>`：指定 YAML 配置；省略时使用环境变量 + 默认配置。
- **默认数据库保护**：未显式指定且有效路径为默认 `database/login.db` 时，数据库命令
  拒绝执行（`CONFIG_DEFAULT_DATABASE_REFUSED`，退出码 2），需显式
  `--allow-default-database`。这是为了避免误操作仓库里的基线数据库。
- 秘密（密码、主密钥、PFX 密码）**不能**作为命令行参数；只接受隐藏输入、受保护文件或
  `env:`/`file:` 来源引用。诊断输出只显示 `[REDACTED]`/`[UNSET]`。
- 写操作要么 `--dry-run` 预演，要么需要显式确认词（如 `--confirm MIGRATE`、
  `--confirm DISABLE`）；取消与超时只影响本次进程，不遗留后台进程或临时文件。

## 2. 稳定退出码

| 退出码 | 含义 |
|---|---|
| 0 | 成功完成（幂等无变化也算成功） |
| 1 | 执行失败（内部错误、存储不可用、检查未通过等） |
| 2 | 参数/用法错误，未执行任何操作 |
| 3 | 操作者取消，或目标任务处于已取消状态 |
| 4 | 未认证或认证材料无效/过期/被撤销 |
| 5 | 已认证但未获准执行（无权限、受限会话、受保护目标） |
| 6 | 并发/状态/版本冲突，需要重新读取后重试 |
| 7 | 本地等待超时（任务可能仍在运行，不代表已取消或失败） |
| 8 | 被等待/查询的任务以失败或超时终态结束 |
| 130 | Ctrl+C 中断（SIGINT） |

注意：`root-recover` 等较早的应急命令只使用 0/1/2/3；`config`/`diag`/`migrate`/`task`/
`session`/`user` 使用完整 0～8/130 集合。脚本请按具体命令的 `--help` 与本节判断。

## 3. root 应急恢复

```bat
:: 运行目录：仓库根或任意目录（工具已构建）；平台：Windows（本机执行）
loginctl root-recover --database P:\data\login.db --reason "root 密码遗忘" ^
    --service-stopped --reset-password
```

用法：

```text
loginctl root-recover --database <path> --reason <原因> \
    (--service-stopped | --maintenance) [--reset-password] [--reset-mfa] \
    [--revoke-login-passkeys] [--request-id <id>]
```

- 至少选择 `--reset-password` 或 `--reset-mfa` 之一；两者都要确认服务停止/维护状态。
- 新密码隐藏输入且需二次确认；不打印、不写日志。
- `--reset-mfa`：重置两步验证因素；`--revoke-login-passkeys` 默认关闭，只有显式指定并
  二次确认才撤销 root 主登录 Passkey。
- 只允许本地、停服/维护、排他锁下执行；不接受远程调用。成功后撤销相关凭证、更新安全
  版本并写审计（审计与写库一致，不留“假成功”）。

## 4. 迁移、诊断与配置

```bat
:: 只读：查看迁移状态；库不存在时退出码 1，不创建数据库
loginctl migrate status --config config\login.yaml

:: 执行迁移：必须确认停服；未知的更高版本拒绝降级
loginctl migrate apply --config config\login.yaml --confirm MIGRATE --service-stopped

:: 诊断：database/health/ready/certificate/mail/all；0=通过，1=有检查未通过
loginctl diag database --config config\login.yaml
loginctl diag health --config config\login.yaml --state-dir data\state --keyring-file secrets\master-key.json
loginctl diag all --config config\login.yaml --json

:: 配置：查看/校验/对比/修改（非秘密字段）/写秘密来源引用
loginctl config show --config config\login.yaml --json
loginctl config validate --config config\login.yaml
loginctl config diff --old a.yaml --new b.yaml
loginctl config set logging.level debug --file config\login.yaml --dry-run
loginctl config set-secret secrets.master_key --source file:P:\secrets\master-key --file config\login.yaml
```

诊断状态值：`ok` / `degraded` / `unavailable` / `not_configured` / `unverified`。
只有 `ok` 与 `not_configured` 视为该检查通过；`ready` 还要求维护状态可验证且为
`normal`（未提供 `--state-dir` 与 `--keyring-file` 时为 `unverified`，不假定正常）。
`diag mail` 在 CLI 未装配发件通道时明确返回 `MAIL_DIAGNOSTICS_UNAVAILABLE`，不会伪成功、
不会发送真实邮件。

## 5. 后台任务与会话

```bat
:: 任务：只读列表/详情/等待；取消只提交请求，不声称已取消
loginctl task list --config config\login.yaml --limit 20 --json
loginctl task get <job_id> --config config\login.yaml
loginctl task wait <job_id> --timeout 60s --config config\login.yaml
loginctl task cancel <job_id> --operator <本地管理员标识> --reason "取消原因" --config config\login.yaml

:: 会话：仅操作本人会话；会话秘密只从受保护文件读取
loginctl session whoami --session-file session.json --keyring-file master-key.json --config config\login.yaml
loginctl session list --session-file session.json --keyring-file master-key.json
loginctl session revoke <session_id> --session-file session.json --keyring-file master-key.json
```

`task wait` 本地等待上限 1s～24h；等待超时退出码 7，任务失败/超时终态 8，已取消 3。
`session revoke` 只能撤销本人会话；管理强制下线需要已完成强认证的管理会话，当前 CLI
明确返回不可用。

## 6. 用户只读/启停（本地管理员边界）

```bat
loginctl user list --operator <本地管理员标识> --config config\login.yaml
loginctl user get <user_id> --operator <本地管理员标识> --config config\login.yaml
loginctl user disable <user_id> --operator <本地管理员标识> --expected-version 3 ^
    --confirm DISABLE --config config\login.yaml
```

- `--operator` 是本机操作者稳定标识；授权器只允许该标识执行命令列出的动作，不冒充在线
  认证。
- 写操作必须带 `--expected-version`（来自 `user get/list` 的 `row_version`）与确认词；
  版本不匹配退出码 6。
- root 等受保护账户由账户服务拒绝变更；本命令不提供创建/删除/资料修改。

## 7. 恢复与维护（备份恢复配套）

```text
loginctl restore-preflight --database <path> --state-dir <dir> --key-file <path> \
    --backup <file> --backup-output <dir> --operator <id> [--avatars <dir>] [--config <file>]
loginctl restore-apply --database <path> ... --reason <原因> --confirm RESTORE [--json]
loginctl maintenance-enter|maintenance-exit --database <path> --state-dir <dir> --operator <id> --reason <原因>
loginctl restore-merge-audit|restore-disposition|restore-review|restore-reenable ...
loginctl restore-init-state ...
```

完整语义见 [backup-and-restore.md](backup-and-restore.md)。核心规则：先预演再执行；恢复
在维护状态与库外排他锁下进行；失败默认**保持维护**，必须显式 `maintenance-exit`。

## 8. 管理命令的真实接通范围

步骤 84 之后，`loginctl` 已接通下列命令组（此前“入口未接通、执行返回未知命令”的旧说明
已失效）：

- **本地管理**（直接操作数据库文件；`--operator` 是本地管理员稳定标识，不冒充在线认证）：
  `group`/`role`/`app`/`permission`/`notify` 的读取与受控建组等命令。角色分配、角色改权限、
  应用启停/成员变更等需要委派转授或敏感策略的写动作**未在 CLI 开放**，返回稳定错误码
  `MANAGEMENT_WRITE_NOT_EXPOSED`（退出码 5），不使用放宽替身；读取由既有领域服务授权并写审计。
- **在线管理**（经运行中的 login-server 管理 JSON API，需 `--session-file`）：`audit`、
  `reports`、`backups`、`notifications`、`tasks` 等命令。服务未启动、管理 API 未启用或对应
  领域未装配时如实返回连接失败/404/503 等稳定错误，不本地伪造成功、不直连数据库。
- 逐条用法以 `loginctl help`、`loginctl <命令组> --help` 为准；CLI 的退出码与 JSON 外壳见
  本文第 1、2 节，CLI 一致性的真实验收记录见
  `docs/acceptance/requirements-matrix-login.md` 与 `docs/acceptance/step156-authorization-write-e2e.md`。

## 9. 安全边界

- 只允许本地服务器、服务已停止或维护状态下执行敏感命令；恢复期间独占数据库目录锁。
- 不要通过 SSH 以外的任何“远程执行”方式包装这些命令，也不要暴露成 HTTP 接口。
- 不要把主密钥环文件与数据库、备份放在同一目录；不要把秘密放进命令行、环境变量副本
  或 shell 历史。
- 应急操作也会写审计；审计不可用时按失败处理，不留下“成功但没有记录”的假象。

## 在线管理读取与本地离线边界（步骤 156 dev + 审计 PARTIAL）

> 状态：步骤 156 已出 dev 报告与审计（PARTIAL，接近 PASS）：domain routes/在线只读命令/帮助/
> 未认证拒绝路径已真实测试；真实强认证成功写 E2E 与少量写面未完成。不能把“命令存在”当作
> 三端一致性最终验收；以 `loginctl help` 与最终记录为准；见 `docs/acceptance/requirements-matrix-login.md`。

- **在线只读**：`loginctl admin users|user|groups|group|roles|role|permissions|applications|application|support-cases|support-case`
  通过运行中的 `login-server` 管理 JSON API 读取，凭据只从受保护的 `--session-file` 读取；
  认证、CSRF、权限/数据范围与领域授权全部由服务端重新判定，未装配领域返回 404 而不是空成功。
  `--json` 输出统一 envelope；错误码/退出码与 audit/reports 等在线命令一致。
- **在线写入**：管理员强制下线使用 `loginctl session admin-revoke`（需强认证管理会话、确认词与理由）；
  其他管理写入口仍以服务端真实 API 为准，页面/API/CLI 共用同一授权与审计，不在本地库直写绕过。
- **本地离线命令**（`user/group/role/permission/app` 的本地管理、`root-recover`、`restore-*`、
  `maintenance-*`）：面向已认证本地管理员/应急维护边界，需要本地数据库/维护状态与 `--operator`/`--confirm`；
  它们不替代在线管理 API 的委派、数据范围与审计语义。普通在线管理请优先使用 API/页面/在线命令。
