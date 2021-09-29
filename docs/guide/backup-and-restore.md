# 备份、校验与恢复

本文说明如何创建**一致的加密热备份**、离线校验与只读查看/导出，以及维护模式下的恢复
流程。核心安全规则：备份使用认证加密、主密钥必须与备份分开保存、恢复必须先预演。

## 1. 为什么不能直接复制数据库文件

SQLite 在服务运行时会写 WAL（预写日志），直接复制主文件可能得到**不一致**的快照。本项目
使用所选驱动支持的在线备份接口生成一致性快照，再加密打包；不会用“复制正在写的
`login.db`”冒充备份。

## 2. 备份内容与格式

- 文件扩展名 `.elnbak`，版本化容器（格式版本 v1），使用 **AES-256-GCM 认证加密**。
- 清单覆盖：格式版本、备份编号、创建时间、主机、应用版本、数据库版本（含
  `schema_history`）、条目清单（名称/类型/大小/SHA-256）、内容范围、恢复依赖。
- 条目包括：数据库快照、配置快照、附件（如启用头像目录）等；**不包含**主密钥本身。
- 主密钥/密钥环必须与备份文件**分开保存**：丢失解密材料意味着相关数据与备份无法恢复；
  本工具不会“猜”密钥。
- 备份产物是认证加密的，但**备份期间输出目录会短暂出现明文快照**；多用户 Windows 请用
  NTFS ACL（如 `icacls`）限制输出目录仅当前账户访问。

## 3. 备份工具 `login-backup`

| 命令 | 作用 | 是否需要主密钥 |
|---|---|---|
| `create` | 在线创建并加密备份 | 是（`--key-file`） |
| `verify` | 认证解密并校验清单/条目大小/SHA-256 | 是 |
| `info` | 只读明文头部做结构与密文摘要检查，**不声称认证通过** | 否 |
| `list` | 认证解密后列出格式、数据库版本、时间、条目、完整性/认证状态 | 是 |
| `tables` | 列出受限查询目录（静态表白名单）与实际可用字段 | 是 |
| `preview` | 对认证解包出的 SQLite 做受限只读预览（白名单表、受控操作符/排序/行数） | 是 |
| `export` | 把受限查询结果导出 CSV（防公式注入）或 JSON | 是 |
| `extract` | 逐项提取附件/配置/原始数据库条目 | 是 |

稳定退出码：

| 退出码 | 含义 |
|---|---|
| 0 | 成功 |
| 1 | 执行失败 |
| 2 | 参数/用法错误 |
| 3 | 备份校验失败/格式不支持 |
| 4 | 解密失败 |
| 5 | 输出冲突或输出位置不安全 |
| 6 | 受限查询/高敏确认被拒绝 |
| 130 | 已取消（临时文件与不完整输出已清理） |

示例（Windows，运行目录：仓库根或二进制所在目录）：

```bat
:: 1) 创建（需要主密钥环文件、受控输出目录；绝不能复制运行中的主数据库文件）
login-backup create --database P:\data\login.db --key-file P:\secrets\master-key.json ^
    --output P:\backups --operator local-admin --config config\login.yaml

:: 2) 校验（区分“校验失败 3”和“解密失败 4”）
login-backup verify --file P:\backups\<备份文件>.elnbak --key-file P:\secrets\master-key.json

:: 3) 不解密的头部信息（用于初步核对，不证明认证通过）
login-backup info --file P:\backups\<备份文件>.elnbak

:: 4) 认证后查看清单与内容范围
login-backup list --file P:\backups\<备份文件>.elnbak --key-file P:\secrets\master-key.json --json

:: 5) 只读预览（禁止任意 SQL；默认排除敏感字段）
login-backup preview --file P:\backups\<备份文件>.elnbak --key-file P:\secrets\master-key.json ^
    --table audit_events --where "result=failure" --order-by occurred_at_ms:desc --limit 20

:: 6) 受控导出（必须绝对路径、父目录存在、默认不覆盖）
login-backup export --file P:\backups\<备份文件>.elnbak --key-file P:\secrets\master-key.json ^
    --table audit_events --format csv --output P:\exports\audit.csv --operator local-admin
```

只读查看/导出的安全约束：

- 认证解包到私有临时目录（0700），SQLite 以 `mode=ro` + `PRAGMA query_only=1` 打开；
  不执行备份内脚本、不自动连接生产库、不联网。
- 表名只允许静态白名单（账户/应用成员/角色权限组/委派/会话元数据/OAuth 客户端元数据/
  审计/备份恢复报告运维），字段名来自认证快照的 `PRAGMA table_info`；SQL 标识符双引号、
  过滤值全部参数化；**不支持任意 SQL**。
- 操作符仅 `= != < <= > >= LIKE IN`（AND 连接）；`preview` 行数 1～200（默认 20），
  `export` 1～100000（默认 1000），超出按截断标记。
- 敏感字段默认排除；只有显式 `--include-sensitive` 才包含，且落地后先收紧文件权限
  （Windows 显式 DACL；非 Windows 要求输出目录 0700，文件 0600），失败删除空文件。
- CSV 文本单元格若以 `= + - @`、制表/回车开头会前置单引号；数值列保持数字。
- 每次 `export`/`extract` 在输出目录追加 `.login-backup-viewer-oplog.jsonl` 本地操作记录
  （时间/操作者/命令/备份编号与摘要/表或条目/行数/字节/输出摘要/敏感标记；不含数据内容、
  过滤值、密钥与绝对备份路径）。该记录**不能**防止主机管理员删除。
- 非 SQLite 备份内部数据解析未实现：`Snapshot`/只读连接对非 sqlite 返回
  `BACKUP_VERSION_UNSUPPORTED`，`list` 会输出 `snapshot_warning`，不伪称可解析。

## 4. 恢复流程（维护模式 + 预演）

恢复只允许本地应急管理员执行，命令为 `loginctl restore-*`：

```bat
:: 0) 维护状态：停服并取得排他锁（或按 command 要求先 init state）
loginctl maintenance-enter --database P:\data\login.db --state-dir P:\data\state --operator local-admin --reason "准备恢复"

:: 1) 预演：逐项检查文件/主密钥/条目摘要/格式与引擎/数据库版本/当前库有效性/
::    恢复代际/容量/附件依赖；预演失败零副作用
loginctl restore-preflight --database P:\data\login.db --state-dir P:\data\state ^
    --key-file P:\secrets\master-key.json --backup P:\backups\<备份文件>.elnbak ^
    --backup-output P:\backups --operator local-admin --avatars P:\data\avatars --config config\login.yaml

:: 2) 执行：再次确认；失败默认保持维护状态
loginctl restore-apply --database P:\data\login.db --state-dir P:\data\state ^
    --key-file P:\secrets\master-key.json --backup P:\backups\<备份文件>.elnbak ^
    --backup-output P:\backups --operator local-admin --reason "恢复原因" --confirm RESTORE ^
    --avatars P:\data\avatars --config config\login.yaml

:: 3) 后续：必要时补合并审计、查看处置、受控重新启用暂停项，成功后退出维护
loginctl restore-merge-audit --database P:\data\login.db --state-dir P:\data\state --operator local-admin
loginctl restore-disposition --database P:\data\login.db --state-dir P:\data\state --operator local-admin
loginctl restore-review --database P:\data\login.db --state-dir P:\data\state --operator local-admin
loginctl maintenance-exit --database P:\data\login.db --state-dir P:\data\state --operator local-admin --reason "恢复完成"
```

恢复语义要点：

- 预演**真实执行**：解包数据库条目到私有临时目录，真实跑迁移升级、`integrity_check`、
  `foreign_key_check`、唯一 root/系统作用域不变量检查，并统计影响范围。预演失败零副作用。
- 恢复前先创建**新的加密回退备份**（不覆盖用户原始备份），切换同目录原子改名。
- **恢复后凭证失效**：同一事务删除会话、刷新令牌、授权请求/授权码、恢复代码、邮箱验证/
  找回/换绑链接、扫码/设备码请求、一次性凭证、MFA/WebAuthn 挑战、重认证挑战、
  **全部令牌签名密钥**等，并复核这些表为空。恢复旧快照**不会**让已撤销凭证复活
  （离线 JWT 因签名密钥删除而失效；客户端已缓存 JWKS 的边界已在文档中说明）。
- 默认暂停旧调度计划/Webhook/在途任务/待发邮件/待补发通知，需审查后受控重新启用。
- 失败规则：切换前失败＝零副作用；切换后失败＝自动回退数据库与附件；**两种失败都保持
  维护状态**并保留 pending 记录，必须显式 `maintenance-exit`，不会自动放行。
- 配置快照不自动应用，只复制到待审查目录；附件逐文件替换（原文件移库外回退目录）。
- 恢复过程审计先写库外 `restore-journal.jsonl`（JSONL + SHA-256 哈希链 + fsync +
  跨进程锁），成功后幂等合并进恢复后数据库；合并失败保持维护、库外日志完整、可重试。

## 5. 当前状态与限制

| 能力 | 状态 |
|---|---|
| SQLite 一致性加密热备份、校验、离线查看/导出 | 已实现（`internal/backup` 与 `cmd/login-backup`） |
| 备份计划、保留策略、清理、备份管理页面 | 已实现（需宿主后端装配） |
| 维护模式恢复、预演、回退、凭证失效、审计合并 | 已实现 |
| **主密钥环的公开生成/保管工具** | **未提供**：`login-backup create` 需要 `--key-file`，但当前没有公开 CLI 生成密钥环；只有模块内 `internal/secrets.GenerateKeyring`。未装配的部署无法独立完成首次备份 |
| 备份/恢复 HTTP 入口 | **未实现**（页面恢复区仍占位） |
| 配置自动应用、跨进程写入门闸 | 未实现；恢复时必须停服或由宿主接线 |
| 大库性能/内存压力、真实 ENOSPC、非 Windows、`-race` | 未实测 |
| 回退备份、明文快照的安全擦除 | 未提供（删除不等于安全擦除） |

因此：现在可以准备与演练备份/校验/查看流程，但**首次生产备份前**必须先解决主密钥环
生成与保管（模块内工具或等公开工具），否则 `create` 无法安全开始。绝不要用自己拼的
口令或明文密钥替代密钥环，也不要把主密钥写进配置 YAML。
