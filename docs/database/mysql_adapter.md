# MySQL 存储适配与迁移（步骤 85）

> 状态口径（必读）：本文件描述的是**代码完成 + 静态检查**；**没有连接真实 MySQL 运行验证**。
> 不得据此宣称“MySQL 兼容性已验证”。真实运行验证命令见第 9 节，需由用户自行拉起临时实例执行。

## 1. 范围与版本基线

- 目标：MySQL **8.0.16+**（CHECK 约束从 8.0.16 起真正执行），统一 `utf8mb4`。
- **明确拒绝 MariaDB**：0900 排序规则、生成列与 SIGNAL 行为不同；`Open` 检测到 MariaDB 直接拒绝，
  不静默降级。
- 不开发跨数据库数据迁移（只把既有 SQLite 结构翻译为 MySQL 结构）。
- 在线备份本版本**不支持**（第 8 节），不生成空备份。
- 依赖：`github.com/go-sql-driver/mysql v1.10.2`（MPL-2.0，仅 import 未改源码；
  传递 `filippo.io/edwards25519 v1.2.0`，BSD-3-Clause）。选择 1.10.2 因修复
  GHSA-9qjq-77h9-895w 等，详见 `docs/licenses/THIRD_PARTY_NOTICES.md`。

## 2. 代码结构

| 路径 | 职责 |
|---|---|
| `internal/storage/mysql/mysql.go` | 配置校验、**双连接池**（重写池给仓储；原始池给迁移 DDL/服务器校验）、服务器设置校验、Open/Close |
| 连接方向 | 仓储 SQL 走重写连接池；迁移 DDL（含 `JSON_VALID` 等 MySQL 原生语法）走未重写的原始连接池，绝不经过 `TranslateRepositorySQL` |
| `internal/storage/mysql/rewrite.go` | 仓储 SQL 的 SQLite→MySQL 确定性重写 + `database/sql` 驱动连接器（Prepare 层翻译，覆盖事务内语句） |
| `internal/storage/mysql/errors.go` | MySQL 错误码→`storage` 安全错误类别映射 |
| `internal/storage/mysql/backend.go` | `migrate.Backend`：GET_LOCK 排他锁、DDL 隐式提交、迁移记录/失败记录、information_schema 漂移校验 |
| `internal/storage/mysql/backup.go` | 备份能力声明与明确的“不支持”错误 |
| `migrations/mysql/` | 读取内嵌 SQLite 迁移，确定性翻译为 MySQL DDL（44 条、95 表） |
| `internal/storage/sqlite/store.go` | **仅新增** `WrapHostDB`、`txOptions`、`errorMapper`；SQLite 既有 SQL 与行为不变 |

仓储代码（`internal/*/sqlite`）不复制、不重写：MySQL 通过重写驱动把经过 `database/sql`
的语句翻译为 MySQL 方言，因此各模块 `Store` 实现可同时用于两种数据库。**接线由宿主完成**：
`accountsqlite.New(mysqlStore.SQLStore())`。宿主装配与真实运行本步未做。

## 3. 方言映射（逐项）

| 主题 | SQLite 既有契约 | MySQL 适配 |
|---|---|---|
| 占位符 | `?` | 保持 `?`（go-sql-driver 默认），不开客户端插值、不开多语句 |
| 标识引用 | 不加引号 | 迁移 DDL 统一反引号；仓储 SQL 原样（列名均为非保留小写标识） |
| 时间 | UTC Unix 毫秒 `INTEGER` | `BIGINT` 毫秒，语义不变；会话 `time_zone='+00:00'`，不引入 DATETIME 时区歧义 |
| 布尔 | `INTEGER 0/1` + CHECK | `BIGINT` + CHECK（不依赖 MySQL BOOLEAN 差异） |
| 二进制 | `BLOB` | 非键列 `BLOB`；键/唯一列 `VARBINARY(n)`（n 来自 CHECK 上界，未声明时 255） |
| JSON | `TEXT` + `CHECK(json_valid(...))` | `TEXT` + `CHECK(JSON_VALID(...))`，保留契约；不使用 JSON 类型避免驱动扫描差异 |
| 规范化用户名唯一性 | 服务层生成 `*_normalized`，DB 只对规范值建唯一索引 | 复制该设计。表默认 `utf8mb4_0900_as_cs`（大小写/重音敏感，接近 SQLite BINARY 过滤）；主键/唯一键/外键/不透明 ID 列显式 `COLLATE utf8mb4_0900_bin`（码点比较、NO PAD），不依赖服务器默认排序规则 |
| 外键 | 列内联 `REFERENCES` | 提升为表级 `FOREIGN KEY`（**MySQL 会静默忽略列内联 REFERENCES，必须表级**）；`ON DELETE CASCADE/RESTRICT/SET NULL` 保留；`SET DEFAULT` 明确报错 |
| 索引长度 | 无 3072 字节限制 | 按 utf8mb4 最大 4 字节/字符预算校验；超限的长文本键列改用 SHA-256 生成列 `BINARY(32)`（如 `webhook_endpoints.url`），不截断数据、不依赖前缀索引造成误冲突 |
| partial unique index | `CREATE UNIQUE INDEX ... WHERE` | `TINYINT` 虚拟生成列 `CASE WHEN <条件> THEN 1 ELSE NULL END` + 唯一索引；仅匹配行参与唯一性 |
| partial 非唯一索引 | `CREATE INDEX ... WHERE` | 退化为全表索引：查询结果等价，只失去“只索引匹配行”的体积优势（已登记差异） |
| 分页 | `LIMIT ? OFFSET ?` 键集/偏移 | 语法一致 |
| upsert | `ON CONFLICT ... DO NOTHING / DO UPDATE` | `ON DUPLICATE KEY UPDATE`；`excluded.x → VALUES(x)`；DO NOTHING 用首列自赋值，保留 MySQL 默认“重复键影响 0 行”语义 |
| INSERT OR IGNORE | 忽略冲突的幂等写入 | `INSERT IGNORE`（仓储 2 处已核对幂等写入 + 迁移种子 1 处由翻译器生成；语义差异见第 5 节） |
| rowid | 4 张表用 `rowid` 排序/清理 | 迁移追加 `_rowid BIGINT AUTO_INCREMENT` 代理列；重写器把裸 `rowid`→`_rowid` |
| 同表子查询 DELETE | 允许 | 派生表包裹，绕开 MySQL 错误 1093 |
| 事务 | 单写者、`_txlock=immediate` | `REPEATABLE-READ`（显式注入）；并发正确性继续依赖唯一约束/`row_version` 条件更新，不依赖 SQLite 全库写锁 |
| 条件更新受影响行数 | 匹配行数 | MySQL 默认是**实际变更行数**：要求每条条件 UPDATE 至少变更一列（时间戳/版本/计数/状态）。已在报告中逐条核对；无 UPDATE 语句依赖“匹配但未变更=1”的语义 |
| 触发器 | `RAISE(ABORT)` | `SIGNAL SQLSTATE '45000'`；带 `WHEN` 的转换 `IF ... THEN SIGNAL ... END IF` |

## 4. 服务器设置校验（Open，失败即拒绝）

**TLS 默认强制**：`Options.TLS` 默认 `true`（校验服务器证书）；自定义 CA 用已注册 TLS 配置名。
只有本地临时测试实例可显式 `AllowInsecure=true` 使用明文、`skip-verify` 或 `preferred`（驱动允许回退明文/不校验证书）；文档明确不得用于生产。
`character_set_connection=utf8mb4`、连接排序规则 `utf8mb4*`、`lower_case_table_names=0`、
`time_zone=+00:00/UTC`、`transaction_isolation=REPEATABLE-READ`、`sql_mode` 含 `STRICT_*`
（连接参数强制 `STRICT_ALL_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION`）。
`ClientFoundRows=false`（保住 ON CONFLICT DO NOTHING 的 0 行语义）、`MultiStatements=false`、
`InterpolateParams=false`、连接/读写超时与连接池上限有界（默认 8，上限 32）。
注意：Windows 上 MySQL 安装默认 `lower_case_table_names=1/2`，必须先改为 0 才能启动（会拒绝，
不会降级）；MySQL 8.0.20 起 `ON DUPLICATE KEY UPDATE` 中的 `VALUES(col)` 已废弃但仍可用
（本适配目标 8.0.16+，暂不用 8.0.19+ 的行别名语法以便覆盖 8.0.16）。

## 5. 已知语义差异（不隐藏）

1. `INSERT IGNORE` 与 SQLite `INSERT OR IGNORE` 都跳过冲突行，但 MySQL `INSERT IGNORE` 还会把部分
   数据错误降级为警告；仅用于仓储 2 处已核对为幂等的写入（另 1 处迁移种子由翻译器生成）。
2. `ON CONFLICT(cols)` 的目标列在 MySQL 无法限定，任何唯一键冲突都会进入 `ON DUPLICATE KEY UPDATE`；
   仓储中这些表的目标唯一键与冲突意图一致，已逐处核对。
3. partial 非唯一索引退化为全表索引（体积/执行计划差异）。
4. MySQL affected rows 只计实际变更行；条件 UPDATE 已按“至少变更一列”核对。
5. 补充 `_rowid` 代理列与 SHA-256 生成列：MySQL 物理结构比 SQLite 多出这些列/索引，业务表列集合
   以迁移 DDL 为准。
6. 触发器只在 MySQL 侧执行；直接写库工具同样受限，但拥有 SUPER/TRIGGER 权限的 DBA 可绕过数据库层
   约束——与 SQLite 的直接文件写风险同源，不能替代服务层校验。

## 6. 迁移机制

- 迁移 DDL 由**原始连接池**执行（不经过仓储 SQL 重写器）；`Backend` 的 GET_LOCK、记录表读写同池。
- `migrations/mysql.Load()` 在内存中把 44 个已提交 SQLite 迁移翻译为 MySQL（版本/描述不变，
  校验和基于翻译后语句单独计算；MySQL 与 SQLite 各自维护 `schema_history`，互不比较）。
- 翻译包含：95 张 `CREATE TABLE`（统一 `ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs`）、
  索引、外键表级化、重建表/RENAME、数据搬迁、种子 `INSERT IGNORE`、4 个触发器。
- 执行：`Backend.Lock` 用 `GET_LOCK`（连接级，DDL 隐式提交不会释放）取得跨实例排他锁；
  `EnsureBookkeeping` 创建 `schema_history`/`schema_failures` 并用 `information_schema` 核对列集合，
  旧结构漂移直接拒绝；每条迁移逐条执行 DDL 后写 `schema_history`。
- **MySQL DDL 隐式提交**：迁移标记 `NonTransactional=true`，失败不自动回滚已执行语句；执行器写入
  `schema_failures` 并停止，再次运行返回 `ErrFailurePending`，必须人工核对后
  `Store.ClearMigrationFailure(version)` 才能重试。
- 半完成检测与恢复（人工，需 DBA 权限）：
  ```sql
  SELECT version, applied_at_ms FROM schema_history ORDER BY version;
  SELECT version, failed_at_ms, error_summary FROM schema_failures;
  SELECT table_name FROM information_schema.tables
   WHERE table_schema = DATABASE() ORDER BY table_name;
  -- 与翻译后的 DDL 对照，确认失败迁移已创建/未创建的结构
  ```
  修复（补建缺失对象或回退该迁移手工创建的对象）→ 必要时先 `Store.CreateOnlineBackup` 的外部替代
  （当前不支持，需 DBA 快照）→ `ClearMigrationFailure` → 重新运行 `Store.Migrate`。
- 迁移前建议：外部一致性快照 + 记录 `SELECT VERSION()`；不可用 SQLite 的“整条迁移事务回滚”假设。

## 7. 仓储覆盖清单（机器可查）

`internal/storage/mysql/repository_sql_test.go` 用 go/ast 扫描 `internal/*/sqlite` 全部非测试源码：
当前 **42 个仓储包、575 个方法**：40 个含方言标记的 SQL 字面量（33 处 ON CONFLICT、
2 处仓储 `INSERT OR IGNORE`、5 处 rowid）逐个送入重写器全部成功；其余 543 个标准 SQL/运行时
拼接片段也逐个做**禁用词检查**（`RETURNING`/`json_extract`/`strftime`/`AUTOINCREMENT`/`GLOB`/
`PRAGMA`/`||` 等），命中即失败，不再“无标记就跳过”。任一无法等价翻译即测试失败。
rowid 使用的表与迁移代理列表必须一致（password_history、audit_maintenance_log、
stats_health_samples、user_emails）。该测试是“逐项映射”的持续证据，不是运行验证。

## 8. 在线备份与恢复能力

- `Store.BackupCapability()` 返回 `Supported=false` 并说明机制/限制/所需外部工具；
- `Store.CreateOnlineBackup` / `Store.RestoreOnlineBackup` 返回稳定错误
  `mysql.ErrOnlineBackupUnsupported`，**不创建文件、不返回成功**；
- 设计与未完成项：需要 InnoDB 一致性快照的外部工具（mydumper/mysqlpump 或 XtraBackup），
  与其版本、权限、增量/校验、恢复代际、库外审计锚点均未实现、未验证。

## 9. 未来运行验证（由用户执行，不属于本步已执行结果）

```bash
# 1) 临时实例（示例版本按实际镜像标签核对；勿用于生产，勿暴露公网端口）
docker run --rm --name evernight-mysql \
  -e MYSQL_ROOT_PASSWORD='<本地临时口令>' \
  -e MYSQL_DATABASE=evernight_test \
  -p 127.0.0.1:33060:3306 \
  mysql:8.0.43

# 2) 创建最小权限测试用户（示例；密码用本地临时值，勿写入仓库）
mysql -h127.0.0.1 -P33060 -uroot -p -e "
CREATE USER 'evernight_test'@'%' IDENTIFIED BY '<本地临时口令>';
GRANT ALL PRIVILEGES ON evernight_test.* TO 'evernight_test'@'%';"

# 3) 未来需要新增的集成测试（当前仓库没有连接真实 MySQL 的用例；下列命令在用例存在后才有意义）
#    本地容器自签证书需按文档用 AllowInsecure=true 或配置自定义 CA；生产必须 TLS。
MYSQL_TEST_DSN='evernight_test:<口令>@tcp(127.0.0.1:33060)/evernight_test' \
  GOMAXPROCS=2 go test -count=1 -p 1 -run 'MySQLIntegration' ./internal/storage/mysql/
# 建议覆盖：Open 校验拒绝/接受、Migrate 全 44 条、重复 Migrate 幂等、失败注入后 schema_failures
# 与半完成检测、repo 关键路径（users 唯一、审计 dedupe、password_history rowid 清理、备份能力拒绝）。

# 4) 停止并清理临时实例（数据不保留）
docker stop evernight-mysql
```

未验证矩阵：真实连接/认证/TLS、服务器设置校验、44 条迁移真实执行、重写后仓储 SQL 真实执行、
触发器真实拦截、错误码逐码映射、备份/恢复、性能与并发、-race、非 Windows、MariaDB/云数据库。
