# SQL Server 存储适配与迁移（步骤 87）

> 状态：**代码完成 / 静态检查通过 / 未连接真实 SQL Server 运行验证**。
> 本文不构成“SQL Server 兼容性已验证”的声明。首次版本不启动 SQL Server、容器或云实例，
> 迁移执行、仓储 SQL、TLS、锁与备份流程均未在真实数据库上运行。

## 1. 范围与版本基线

- 目标数据库：**Microsoft SQL Server 2019+（主版本 ≥ 15）**。SQL Server 2017 及更早、
  Azure Synapse 分析引擎不在支持范围（迁移 DDL 依赖 SQL Server 2016+ 的
  `HASHBYTES`/`ISJSON`/`DROP IF EXISTS`/`OFFSET FETCH`，版本校验按 2019 基线拒绝更旧版本）。
- 驱动：`github.com/microsoft/go-mssqldb v1.12.0`（Microsoft 官方维护，**BSD-3-Clause**；
  与任务提示中“MIT”不一致，`docs/licenses/THIRD_PARTY_NOTICES.md` 已按实际许可证登记）。
- 平台约束：与项目一致，只在 Windows 上做编译/静态/生成检查；Linux/macOS 与其他架构
  未编译验证。真实 SQL Server 运行验证需用户在隔离实例上执行（见第 10 节）。
- 设计目标：让既有 42 个 `internal/*/sqlite` 仓储包**不复制、不重写**即可指向 SQL Server；
  迁移由已提交 SQLite 迁移确定性翻译；无法等价翻译的语法一律 fail-closed。

## 2. 代码结构

| 文件 | 职责 |
|---|---|
| `internal/storage/sqlserver/sqlserver.go` | `Options` 校验、DSN/驱动配置（默认强制加密）、双连接池、服务器设置校验、`sp_getapplock` 资源名、`Open/Close/Ping` |
| `internal/storage/sqlserver/rewrite.go` | 仓储 SQL 的 SQLite→T-SQL 确定性重写（`?→@pN`、`ON CONFLICT→MERGE`、`INSERT OR IGNORE→MERGE`、`rowid→[_rowid]`、`LIMIT/OFFSET→OFFSET FETCH`）、`Prepare` 层连接器、绑定值转换 |
| `internal/storage/sqlserver/errors.go` | SQL Server 错误号 → `storage` 安全错误类别（唯一冲突/死锁/约束/权限/不可用/磁盘满） |
| `internal/storage/sqlserver/backend.go` | `migrate.Backend`：`sp_getapplock` 排他锁、`schema_history`/`schema_failures`、sys 目录漂移校验、GO 批次拆分、事务/非事务迁移 |
| `internal/storage/sqlserver/backup.go` | 备份能力声明与“不支持”稳定错误 |
| `migrations/sqlserver/sqlserver.go` | 44 条 SQLite 迁移的确定性 T-SQL 翻译器（95 表、身份列长度、索引字节预算、触发器、重命名、种子） |
| 测试（同包） | 方言/错误/配置/锁键单测、`go/ast` 仓储 SQL 全量审计、fake driver 执行路径、迁移 44 条静态验收 |

## 3. 方言映射（逐项）

| SQLite | SQL Server（本适配器生成/重写） | 说明 |
|---|---|---|
| `?` 占位符 | `@p1`、`@p2`…（命名参数，按编号绑定） | MERGE/OFFSET FETCH 会重排文本，但编号按原始出现顺序保留；既有 `@`/`$` 参数一律拒绝 |
| 标识符 | `[table]`、`[column]` 方括号 | 迁移 DDL 全部显式方括号；仓储 SQL 原样（未改列名） |
| `TEXT` | `NVARCHAR(n)` / `NVARCHAR(MAX)` + `COLLATE Latin1_General_100_BIN2` | 所有字符列显式二进制排序规则；`n` 由 CHECK 上界/身份列/索引键策略决定 |
| `BLOB` | `VARBINARY(n)` / `VARBINARY(MAX)` | SQLite `length(blob)` 计字节，映射为 `DATALENGTH` |
| `INTEGER` | `BIGINT` | 时间 UTC 毫秒、布尔 0/1、计数保持 64 位；**不改为 BIT/DATETIME2**（见第 5 节） |
| `REAL` / `NUMERIC` | `FLOAT(53)` / 不支持 | 当前迁移未使用 NUMERIC；遇到未声明类型翻译失败 |
| `json_valid(x)` | `ISJSON(x) = 1` | 非法 JSON 由 SQL Server 拒绝；SQLite NULL 通过语义一致 |
| `length(text)` | `LEN(text)` | LEN 不统计末尾空格（差异见第 5 节）；仅用于长度上界 CHECK |
| `length(blob)` | `DATALENGTH(blob)` | 字节数语义一致 |
| `AUTOINCREMENT` | `BIGINT IDENTITY(1,1)` | 仅 rowid 代理列使用 |
| 裸 `rowid` | `[_rowid]` | 4 张表追加 `_rowid BIGINT IDENTITY(1,1) NOT NULL`：`password_history`、`audit_maintenance_log`、`stats_health_samples`、`user_emails` |
| `LIMIT n` / `LIMIT n OFFSET m` | `OFFSET m ROWS FETCH NEXT n ROWS ONLY` | 同查询无 ORDER BY 时补 `ORDER BY (SELECT NULL)`（SQLite 无 ORDER BY 的 LIMIT 顺序本就未定义）；`LIMIT -1` fail-closed |
| `ON CONFLICT (k) DO NOTHING` | `MERGE INTO t WITH (HOLDLOCK) … WHEN NOT MATCHED THEN INSERT` | 33 处仓储用法全部可翻译；HOLDLOCK 串行化并发冲突判断 |
| `ON CONFLICT (k) DO UPDATE SET` | `MERGE … WHEN MATCHED THEN UPDATE SET` | `excluded.x→source.[x]`、`table.x→target.[x]`、裸目标列→`target.[列]`；`DO UPDATE … WHERE` fail-closed |
| `INSERT OR IGNORE` | `MERGE … ON 目标表主键` | 冲突键来自已提交迁移主键（`migrations/sqlserver.PrimaryKeyColumns`），不猜测；2 处仓储用法 |
| `CREATE UNIQUE INDEX … WHERE …` | 过滤唯一索引（同语法） | 11 个过滤唯一索引原样保留 |
| SQLite 触发器 `BEFORE … RAISE(ABORT)` | `AFTER` 触发器 + `;THROW 50000, N'…', 1;` | SQL Server 无 BEFORE 触发器；AFTER 抛错回滚触发语句，append-only 语义保留 |
| `ALTER TABLE … RENAME TO` | `EXEC sp_rename N'[old]', N'new'` | 4 处重建表迁移 |
| `RETURNING` | **未实现**（T-SQL 需改写为 `OUTPUT`） | 当前仓储 0 处使用；Prepare 阶段明确报“需要 OUTPUT”而不是误标 SQLite 语法 |
| `||`、`IFNULL`、`IIF`、`GLOB`、`PRAGMA`、JSON 扩展函数 | 拒绝（fail-closed） | 不允许猜测翻译 |
| 布尔 Go 绑定 `bool` | `int64(0/1)` | 与 SQLite 存储模型一致，避免 BIT 扫描类型不匹配 |
| 时间 Go 绑定 `time.Time` | `int64` UTC 毫秒 | 避免驱动编码为 datetime2/datetimeoffset |

## 4. 服务器设置校验（Open，失败即拒绝）

`Open` 在建立连接池后抽样校验（未在真实服务器运行验证）：

1. `@@VERSION` 必须包含 `Microsoft SQL Server`；含 `Synapse` 拒绝。
2. `SERVERPROPERTY('ProductMajorVersion') ≥ 15`；`EngineEdition = 6`（Azure Synapse）拒绝。
3. `DB_NAME()` 与配置数据库名一致；`Status=ONLINE`、`Updateability=READ_WRITE`。
4. 服务器存在 `Latin1_General_100_BIN2` 排序规则（`COLLATIONPROPERTY` 非空），否则迁移
   DDL 的显式 `COLLATE` 会在运行期失败。
5. 会话 SET 选项由连接器 `SessionInitSQL` 固定并在校验时复核：`ANSI_NULLS`/`QUOTED_IDENTIFIER`/
   `ANSI_WARNINGS`/`ANSI_PADDING`/`ARITHABORT`/`CONCAT_NULL_YIELDS_NULL` = ON，
   `NUMERIC_ROUNDABORT` = OFF（索引计算列/触发器要求）；`XACT_ABORT OFF`、`IMPLICIT_TRANSACTIONS OFF`。
   不设置 `NOCOUNT ON`（既有仓储依赖 `RowsAffected` 判断条件更新与幂等写入）。

## 5. 已知语义差异（不隐藏）

1. **时间/布尔列保持 BIGINT**：SQL Server 原生 `DATETIME2`/`BIT` 需要改动全部仓储的
   绑定/扫描契约，因此首次版本沿用 SQLite 存储模型（UTC 毫秒整数、0/1 整数 + CHECK）。
   数据库内没有 `DATETIME2` 字段，时区问题由应用写入的 UTC 毫秒保证；如未来改为原生类型，
   需同步修改仓储并重新评估。
2. **`UNIQUEIDENTIFIER` / `SCOPE_IDENTITY` / `OUTPUT` 不使用**：业务 ID 是服务层生成的稳定
   TEXT（如 `user_...`），不使用 `UNIQUEIDENTIFIER`；不依赖数据库自增主键，因此不使用
   `SCOPE_IDENTITY`；`RETURNING` 尚未改写为 `OUTPUT`（当前仓储 0 处使用，见方言表）。
   rowid 代理列使用 `IDENTITY` 仅用于稳定排序，不对外暴露。
3. **`LEN` 不统计末尾空格**：SQLite `length()` 计数末尾空格。当前 CHECK 均为长度上界，
   写入超长值仍会被拒绝；但“N 个字符 + 末尾空格”的边界值可能与 SQLite 判定不同。
4. **`LIKE` 大小写**：列使用 BIN2 排序规则，`LIKE` 对 ASCII 大小写敏感，而 SQLite `LIKE`
   默认大小写不敏感。当前仓储只有 1 处对固定小写 JSON 文本的 LIKE，不受影响；新增 LIKE
   查询需评估（重写器未注入 CI 排序规则）。
5. **唯一约束中的 NULL**：SQLite UNIQUE 允许多行 NULL，SQL Server 唯一索引只允许一行 NULL。
   当前唯一可空列只有 `scopes.app_id`（`system` 行 NULL、应用 scope 非 NULL，至多一行 NULL），
   静态测试 `TestUniqueNullableColumns` 会拦截新增可空唯一列。
6. **索引键字节预算 1700 字节**：主键/唯一约束一律 `NONCLUSTERED`（非聚集索引键上限 1700，
   聚集索引 900）。身份列上限 850 字符（1700/2）超限翻译失败；超预算唯一键（`verifier_hash`、
   `webhook_endpoints.url`）改用 `HASHBYTES('SHA2_256', 列)` 持久化计算列 + 唯一索引，
   只可能误报冲突、不会放过重复值；按原值等值查询不命中该摘要索引。
7. **MERGE 并发**：`MERGE … WITH (HOLDLOCK)` 是缓解 SQL Server MERGE 并发竞争的标准手段，
   但**未在真实并发下验证**；唯一约束仍是最终兜底（冲突时返回唯一性错误）。
8. **事务隔离**：仓储事务使用 `SERIALIZABLE`（最接近 SQLite 单写者串行语义）；死锁/锁超时
   （1205/1222）映射为 `ErrBusy` 交给有界重试，不静默丢更新。真实并发行为未验证。
9. **BEFORE INSERT 保护不翻译（append-only 少一层防御）**：`trg_audit_maintenance_log_no_replace`
   保护“INSERT OR REPLACE 不触发 DELETE 触发器”的 SQLite 隐患；T-SQL 没有 `INSERT OR REPLACE`
   语法、替换风险不存在，因此该触发器语义不可用、明确不生成（静态测试断言，翻译后触发器为 3 个）。
   登记影响：SQL Server 路径的 `audit_maintenance_log` 只保留 UPDATE/DELETE 两个 AFTER 触发器，
   插入侧没有该层防御；安全依赖仓储不提供替换写入（当前确实没有）与主键/唯一约束。
10. **`INSERT OR IGNORE→MERGE` 只按主键冲突等价**：SQLite `INSERT OR IGNORE` 忽略任意冲突，
    而 MERGE 的 ON 条件只覆盖目标表主键；其他唯一键、`NOT NULL`、CHECK、外键冲突仍会报错
    （fail-closed，不会静默吞掉数据错误）。当前 2 处用法（`password_history`、`backup_jobs`）
    的预期重复都是主键冲突，因此可观测结果一致；新增 `INSERT OR IGNORE` 用法必须重新评估。
11. **`sp_rename N'[old]', N'new'` 的方括号表名未运行验证**：T-SQL `sp_rename` 的对象名参数
    对 `[方括号]` 的接受方式未在真实实例验证；4 处重建表迁移使用该形式，运行验证时需优先检查
    重命名后的索引/外键/触发器归属。
12. **外键级联/延迟**：SQL Server 外键在语句结束时校验，SQLite 在 `PRAGMA foreign_keys=ON`
   时为立即校验；两者对单语句事务的可观测结果一致，跨语句时序未运行验证。

## 6. 迁移机制

- **翻译**：`migrations/sqlserver.Load()` 读取 `migrations/*.sql`（44 条），先建立最终表结构模型
  （95 表），再确定性生成 T-SQL：身份列长度、外键列类型与父列一致（109 列）、CHECK 表达式、
  `UNIQUE NONCLUSTERED`、过滤索引、`HASHBYTES` 摘要列、rowid 代理列、AFTER 触发器、
  `sp_rename`、表重建的数据搬迁 `INSERT … SELECT` 和 6 条种子 INSERT。
- **排他锁**：`sp_getapplock @Resource=<库名派生>, @LockMode='Exclusive', @LockOwner='Session',
  @LockTimeout=<MigrationLockTTL 毫秒>`；返回 0/1 成功，负数（超时 -1/取消 -2/死锁 -3）映射为
  `ErrBusy`，不执行迁移回调（fail-closed）。释放使用 `sp_releaseapplock`。
- **执行**：默认把一条迁移的全部语句与 `schema_history` 记录放入**同一事务**提交；失败整体
  回滚（SQL Server 支持事务内 DDL），不留下半完成结构。源迁移若声明
  `-- +migrate non-transactional`，则按语句顺序执行、失败保留部分结构并由
  `schema_failures` 记录（人工核对后 `ClearMigrationFailure`）。当前 44 条翻译迁移均为事务内。
- **GO 批次**：驱动不支持 `GO`（客户端批次分隔符），执行器按行首 `GO` 拆分批次后再发送；
  当前翻译迁移不含 `GO`。
- **漂移校验**：`schema_history`/`schema_failures` 通过 `sys.objects`（必须是用户表 U）、
  `sys.columns`（列顺序/类型/可空性）与 `sys.indexes`（唯一主键）核对；结构不符返回
  `ErrCorrupt`，不在未知结构上迁移。
- **失败恢复**：读取 `schema_history`/`schema_failures`；人工核对数据库对象后删除失败记录
  再重跑。不把失败的迁移标记为已应用。

## 7. 仓储覆盖清单（机器可查）

`internal/storage/sqlserver/repository_sql_test.go` 用 `go/ast` 扫描 `internal/*/sqlite` 全部
非测试源码：**42 个仓储包、575 个方法**；40 个含方言标记的 SQL 字面量（33 处 `ON CONFLICT`、
2 处 `INSERT OR IGNORE`、5 处 `rowid`）逐个送入重写器**全部成功**，且 `@pN` 数量/编号连续；
其余 543 个标准 SQL/运行时拼接片段逐个做禁用词与占位符检查（不因“无标记”跳过）；
rowid 使用表与迁移代理列表完全一致。任何无法等价翻译的语法在 Prepare 阶段显式报错。

## 8. 在线备份与恢复能力

**明确不支持**（`sqlserver.ErrOnlineBackupUnsupported`）。SQL Server 一致性备份需要
`BACKUP DATABASE … WITH COPY_ONLY, CHECKSUM` 或托管快照、相应权限与目标存储；本版本
不执行备份、不复制数据文件、不返回空备份、不声称可恢复。备份页面/CLI 必须按不支持处理，
恢复代际与库外审计锚点也未接入。

## 9. 未实测事项与已知限制

- 真实 SQL Server 2019/2022/Azure SQL 的连接/认证/TLS/证书、服务器设置校验逐分支。
- 44 条迁移真实执行（顺序、外键、重建表数据搬迁、`sp_rename`、触发器、`HASHBYTES` 计算列、
  过滤索引）；迁移失败回滚与人工恢复；多实例 `sp_getapplock` 互斥。
- 重写后仓储 SQL 真实执行（MERGE 语义/并发、`OFFSET FETCH` 分页、行数影响、
  SQL Server 错误号逐号映射）。
- 备份/恢复、性能/并发/`-race`、非 Windows 平台、托管云数据库。
- 宿主装配：根配置尚无 SQL Server 字段，`cmd/login-server` 仍只装配 SQLite；接线示例仅在
  本文与报告。
- 驱动 v1.12.0 为 BSD-3-Clause（任务提示误写 MIT）；上游活跃、无已知 CVE，但真实 TLS/认证
  路径仍需运行验证。
- 依赖图核验限制：`go list -m all` 在离线/受限网络下因 go-mssqldb 的 `go.mod` 声明的可选
  Azure AD 模块（`azure-sdk-for-go`、`azidentity` 等，root 包不导入）未全部缓存而无法完成；
  `go mod verify`、`go mod tidy -diff`、`go list -deps`（实际构建依赖）均已通过，完整模块图
  的逐模块核验留给联调环境。
- **append-only 少一层防御**：`audit_maintenance_log` 的 BEFORE INSERT “禁止替换”触发器有意不
  翻译（T-SQL 无 INSERT OR REPLACE），SQL Server 路径只有 UPDATE/DELETE 两层保护，见 §5 第 9 条。

## 10. 未来运行验证（由用户执行，不属于本步已执行结果）

```bash
# 1) 临时 SQL Server 实例（示例；版本按实际镜像标签核对；勿用于生产，勿暴露公网端口；
#    本地自签证书需 AllowInsecure=true + TrustServerCertificate=true，仅限本地测试；
#    生产必须 encrypt=true + trustservercertificate=false，并配置 CA 证书）
docker run --rm -d --name login-mssql -p 1433:1433 \
  -e ACCEPT_EULA=Y -e MSSQL_SA_PASSWORD='<本地测试强口令>' \
  mcr.microsoft.com/mssql/server:2022-latest

# 2) 等待就绪（sqlcmd 以 /opt/mssql-tools18/bin/sqlcmd 实际路径为准）
docker exec login-mssql /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P '<口令>' \
  -Q "SELECT @@VERSION; CREATE DATABASE login_static_verify;"

# 3) 未来需要新增的集成测试（当前仓库没有连接真实 SQL Server 的用例；命令在用例存在后才有意义）
#    建议覆盖：Open 各项校验接受/拒绝分支、Migrate 全 44 条、重复 Migrate 幂等、
#    失败注入后的回滚与 schema_failures/人工恢复、sp_getapplock 多实例互斥、
#    仓储关键路径（users 唯一冲突、ON CONFLICT→MERGE 幂等/更新、password_history
#    rowid 清理、审计 dedupe_key、触发器 append-only 拦截）、
#    HASHBYTES 唯一索引冲突行为、OFFSET/FETCH 分页、错误号映射、备份能力拒绝。
go test -count=1 -p 1 ./internal/storage/sqlserver/ ./migrations/sqlserver/

# 4) 停止并清理临时实例（数据不保留）
docker stop login-mssql
```

> 在真实实例验证通过之前，不得对外声明“SQL Server 兼容性已验证”，也不得把本适配器
> 用于生产数据写入。
