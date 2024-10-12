# login-setup 非交互命令参考（步骤 297）

本页是 `login-setup` 非交互子命令的稳定参考，面向脚本、CI 与 AI。所有命令不需要 PTY、不弹交互
框，复用与全屏 CUI 相同的 WS1–WS4 领域服务，不建立第二套事务。命令表也可从程序自身读取：

```powershell
.\login-setup.exe commands --json     # 机器可读命令表与退出码
.\login-setup.exe selftest --json     # 短自检（只读）
```

## 1. 通用约定

- 全局参数：`--config <login.yaml>`、`--master-key-file <文件>`、`--json`、`--version`。
- 子命令一般也接受 `--config`/`--master-key-file`/`--json`；`--json` 输出单行 JSON 到标准输出，
  错误也以 JSON 输出到标准输出（`{"ok":false,"code":"...","message":"..."}`）。
- 工作目录：命令以 `--config` 所在目录为相对路径解析基准（与 CUI 在实例目录启动一致），结束后
  恢复原工作目录。
- 秘密（密码/一次性密码）**不接受命令行明文参数**，只接受：
  - `--password-stdin`：从标准输入读取一行；标准输入是真实 TTY 时使用无回显读取；
  - `--password-file <受保护文件>`：从受限文件读取第一行；要求非符号链接、普通文件、大小有界，
    非 Windows 权限不得宽于 0600，Windows 必须是无 Everyone/Users/Authenticated Users 等宽泛
    主体的受保护 DACL；不满足时拒绝读取；
  - `--generate-password`：由领域生成高熵一次性密码，必须同时指定交付通道：
    `--generated-password-file <受保护新文件>`（新建、拒绝覆盖、按平台加固 ACL/0600 并自检）
    或 `--print-generated`（显式打印到标准输出，**只能用于人类交互**）；否则在写操作前失败。
    一次性密码文件的加固失败会 fail-closed，不会留下"看起来 0600、实际宽 ACL"的文件。
- 危险写操作要求逐字确认串；未知/缺参数/错误确认不会执行写操作。

## 2. 稳定退出码

| 退出码 | 含义 |
|---|---|
| 0 | 成功（`ok=true`） |
| 1 | 命令执行失败（领域错误/保存失败/部分失败） |
| 2 | 用法错误：未知命令/子命令、缺参数、非法 flag、缺确认串、缺秘密通道 |
| 3 | 实例未就绪（`check`/`db test` 等只读诊断发现未满足） |
| 4 | 冲突/确认不匹配（导入/恢复预览未应用、配置外部修改冲突） |
| 5 | 一次性密码交付失败（无显式通道/目标已存在/写文件失败） |

错误对象字段：`ok=false`、`code`（稳定的机器可读错误码字符串，例如确认缺失、未就绪、
配置冲突、一次性密码交付失败等场景各有独立 code）、`message`（中文、脱敏）。

## 3. 命令表

| 命令 | 写 | 需要确认串 | 秘密 | 说明 |
|---|---|---|---|---|
| `status [--json]` | - | - | - | 只读状态检测（零配置可用） |
| `check [--json]` | - | - | - | 只读检查；未就绪退出 3 |
| `plan --profile local\|intranet\|embedding [--json]` | - | - | - | 推荐配置差异与操作计划，不写盘 |
| `apply --profile <key> --confirm APPLY-RECOMMENDATION [--init-db] [--create-master-key] [--conflict-policy fail\|reload\|use-draft]` | 是 | `APPLY-RECOMMENDATION` | - | 保存推荐配置；可选幂等迁移 |
| `db test [--sqlite-path <路径>] [--json]` | - | - | - | 连接/迁移状态测试，不创建数据库 |
| `db init --confirm INIT-DATABASE [--sqlite-path <路径>] [--create-master-key]` | 是 | `INIT-DATABASE` | - | 排他锁下幂等迁移 |
| `root status [--json]` | - | - | - | root 初始化状态（只读） |
| `root init --confirm INIT-ROOT (--password-stdin\|--password-file\|--generate-password) [--username root] [--nickname ...] [--reset-existing]` | 是 | `INIT-ROOT` | 密码/一次性密码 | 创建唯一 root 或本地重设密码 |
| `accounts list [--json]` | - | - | - | 账户方案清单与可用性 |
| `accounts apply --scheme <key> --username <名> --confirm APPLY-ACCOUNT (--password-stdin\|--password-file\|--generate-password)` | 是 | `APPLY-ACCOUNT` | 临时密码 | 按方案创建账户；不覆盖既有账户 |
| `presets install --confirm INSTALL-PRESETS` | 是 | `INSTALL-PRESETS` | - | 安装/升级系统预设角色与权限 |
| `export config (--masked\|--encrypted) --out <新文件> [--json]` | 是（新文件） | - | 加密包需主密钥 | 脱敏配置或可还原加密敏感配置包 |
| `import config --file <yaml\|lncfg> --confirm <预览要求串> [--conflict-policy ...]` | 是 | 预览返回的确认串 | 加密包需主密钥 | 先预览差异；确认后才应用 |
| `recover plan --profile <key> [--json]` | - | - | - | 推荐运行配置恢复差异（保留 database/secrets/server） |
| `recover apply --profile <key> --confirm RESET-RUNTIME-CONFIG` | 是 | `RESET-RUNTIME-CONFIG` | - | 应用推荐运行配置恢复 |
| `selftest [--json]` | - | - | - | 短自检：detect/config/profiles/schemes/命令表 |
| `commands [--json]` | - | - | - | 命令表与退出码 |

## 4. 示例（Windows；输出略去路径中的个人信息）

```powershell
# 只读诊断（不写文件）
.\login-setup.exe status --config .\login.yaml --json
.\login-setup.exe check  --config .\login.yaml --json   # 未就绪 -> exit 3

# 计划与确认后应用推荐配置
.\login-setup.exe plan  --profile local --config .\login.yaml --json
.\login-setup.exe apply --profile local --confirm APPLY-RECOMMENDATION --init-db --create-master-key --config .\login.yaml --json

# 数据库测试与显式初始化
.\login-setup.exe db test --config .\login.yaml --json
.\login-setup.exe db init --confirm INIT-DATABASE --create-master-key --config .\login.yaml --json

# root：从标准输入读取密码（不回显、不落命令行）
Get-Content .\root.pwd | .\login-setup.exe root init --confirm INIT-ROOT --username root --password-stdin --config .\login.yaml --json

# root：生成一次性密码到 0600 新文件（不会打印到日志）
.\login-setup.exe root init --confirm INIT-ROOT --username root --generate-password --generated-password-file .\root.generated --config .\login.yaml --json

# 账户方案：生成临时密码到受控文件
.\login-setup.exe accounts apply --scheme normal_user --username helper --generate-password --generated-password-file .\helper.generated --confirm APPLY-ACCOUNT --config .\login.yaml --json

# 预设与配置导出/导入
.\login-setup.exe presets install --confirm INSTALL-PRESETS --config .\login.yaml --json
.\login-setup.exe export config --masked --out .\masked.yaml --config .\login.yaml --json
.\login-setup.exe import config --file .\masked.yaml --confirm IMPORT-CONFIG --config .\login.yaml --json

# 推荐运行配置恢复（先 plan，再按返回确认串 apply）
.\login-setup.exe recover plan  --profile local --config .\login.yaml --json
.\login-setup.exe recover apply --profile local --confirm RESET-RUNTIME-CONFIG --config .\login.yaml --json
```

## 5. JSON 结果（脱敏形状）

- `status`：`{ok, ready, detection:{state,state_label,config_path,config_loaded,database_path,applied_migrations,latest_migrations,root_user_id,summary,details,config_issues}}`。
- `check`：`{ok, ready, detection, config_valid, config_summary}`。
- `plan`：`{ok, profile, profile_label, config_path, config_exists, config_would_change, requires_db_init, pending, notes, steps, issues}`。
- `apply`：`{ok, saved, saved_path, database_inited, steps[{name,ok,detail}], reload_result, backup_path}`。
- `db test`：`{ok, driver, database_path, config_valid, file_exists, runtime_tested, migrated, pending, message}`。
- `root init`：`{ok, created, reentry, password_reset, root_user_id, root_username, strong_auth_required, required_steps, security_version, generated_password_delivered}`；**不返回密码本身**。
- `accounts apply`：`{ok, accounts[{username,scheme,user_id,roles,created,skipped_existing,require_change,generated_password_delivered}], errors}`。
- `export`：脱敏 `{ok,kind:"masked-yaml",out,size,sha256,masked_fields}`；加密 `{ok,kind:"encrypted-package",out,size,sha256,config_sha256,key_id,format_version}`。
- `import`：`{ok, applied, reload_result, backup_path, config_valid, preview{source_kind,changed_paths,diff,warnings,blocking,required_confirm,can_apply}}`。
- `recover`：`{ok, plan{current_path,retained_sections,reset_sections,changed_paths,idempotent,required_confirm,can_apply,blocking,warnings}}`。

一次性密码文件内容只用于本地受控交付；JSON 只报告是否已交付（`generated_password_delivered`），
不包含密码。若交付文件已存在，命令拒绝覆盖（退出码 5）。`--print-generated` 与 `--json`
互斥：冲突在任何状态变更前（读密码/创建或重设账户之前）即拒绝，JSON 模式禁止把明文密码写入
标准输出/自动日志，需改用 `--generated-password-file`。

## 6. 维护锁与维护日志

`import config` 与 `recover apply` 和 CUI 的同类危险动作一样：先写维护日志 started，取得实例
排他维护锁（主服务运行中或另一控制台持锁时拒绝），执行保存，再写 success/failed；维护日志
不可写或取锁失败时不写配置。因此这两个命令在只读预览之后仍可能因锁/证据失败而返回非 0，
这是 fail-closed 设计，不是"预览成功就保证应用成功"。

## 7. 与 CUI 的一致性

- 同一 `--config`/实例目录下，`status`/`check` 与 CUI 状态画面使用同一 `Detect` 结果；
  `apply` 与推荐配置画面共用 `PlanRecommendation`/`ApplyRecommendation`；`db init` 与数据库画面共用
  正式迁移；`root init`、`accounts apply`、`presets install`、导入导出、恢复各自复用对应领域函数。
- 非交互模式仍要求本地 OS 维护身份与排他维护锁；它不会因为“命令行”而绕过授权、审计、密码策略
  或服务运行检测，也不是远程最高权限 API。

## 8. 未纳入本步的范围

- 297 只提供“同源非交互命令”，不新增匿名 HTTP 管理服务，也不把本地权限导出到普通远程管理员。
- 完整实例备份/恢复、完全重新初始化等危险动作主要走 CUI 画面与最终验收；自动化命令不提供静默
  等价物，避免误触不可逆清除。最终五程序 × 六平台全量发布包在 299 接入、在最后合并步骤统一生成。
