-- +migrate whole-file
-- 0040 审计读取、受控导出与保留期清理。
--
-- 对应步骤 73：建立后续页面与统计使用的可靠审计数据入口。本迁移只追加结构，
-- 不修改 audit_events、jobs 等既有表的语义。
--
-- 语义：
--   - audit_retention_policy 是单行保留策略（id=1）。第一版由 root 显式设置；
--     version 用于乐观并发，避免旧页面覆盖新策略。retention_days 是保留天数；
--     早于 cutoff 的记录属于“已过保留期”，是否已被清理由查询结果区分。
--   - audit_exports 保存异步导出任务的筛选快照、授权数据范围快照、状态与脱敏
--     产物元数据。file_name 是服务端生成的受控文件名，不保存宿主绝对路径、
--     文件内容或审计正文。
--   - audit_maintenance_runs 保存 root 手动清理的请求、真实执行者、范围、截止
--     时间、边界上限、计数与结果。取消请求由任务状态表达，不等于实际取消。
--   - audit_maintenance_log 是清理过程与结果的受保护追加记录，禁止 UPDATE 与
--     DELETE；同一清理只删除 audit_events 行，不能抹除自身的清理审计。
--   - 原始审计保留（audit_events）与报告/导出产物（audit_exports + 宿主受控目录）
--     分开管理，本迁移不删除任何既有数据。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

-- 保留策略：单行，未设置时由服务返回内置默认值（不预置行，避免伪造设置时间）。
CREATE TABLE audit_retention_policy (
id INTEGER PRIMARY KEY CHECK(id=1),
retention_days INTEGER NOT NULL CHECK(retention_days BETWEEN 1 AND 3650),
version INTEGER NOT NULL CHECK(version>=1),
updated_by_type TEXT NOT NULL CHECK(updated_by_type IN('user','system','local_admin')),
updated_by_id TEXT NOT NULL,
reason TEXT,
updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms>=0)
);

-- 审计导出任务：筛选/数据范围快照 + 受控产物元数据。
CREATE TABLE audit_exports (
id TEXT PRIMARY KEY NOT NULL,
scope_kind TEXT NOT NULL CHECK(scope_kind IN('system','app')),
scope_id TEXT NOT NULL,
requested_by_type TEXT NOT NULL CHECK(requested_by_type IN('user','system','local_admin')),
requested_by_id TEXT NOT NULL,
filter_json TEXT NOT NULL CHECK(json_valid(filter_json)),
data_scope_json TEXT NOT NULL CHECK(json_valid(data_scope_json)),
format TEXT NOT NULL CHECK(format IN('csv','json')),
max_rows INTEGER NOT NULL CHECK(max_rows BETWEEN 1 AND 100000),
state TEXT NOT NULL CHECK(state IN('queued','running','succeeded','failed','cancelled')),
row_count INTEGER CHECK(row_count IS NULL OR row_count>=0),
truncated INTEGER NOT NULL DEFAULT 0 CHECK(truncated IN(0,1)),
task_id TEXT,
file_name TEXT,
file_sha256 BLOB CHECK(file_sha256 IS NULL OR length(file_sha256)=32),
file_bytes INTEGER CHECK(file_bytes IS NULL OR file_bytes>=0),
error_code TEXT,
failure_reason TEXT,
request_id TEXT,
executor_id TEXT,
created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0),
started_at_ms INTEGER,
finished_at_ms INTEGER,
expires_at_ms INTEGER
);

CREATE INDEX ix_audit_exports_scope_created_at_ms ON audit_exports(scope_id,created_at_ms);

CREATE UNIQUE INDEX ux_audit_exports_task_id ON audit_exports(task_id) WHERE task_id IS NOT NULL;

-- root 审计清理运行：请求、执行者、范围、截止时间、上限、计数与结果。
CREATE TABLE audit_maintenance_runs (
id TEXT PRIMARY KEY NOT NULL,
kind TEXT NOT NULL CHECK(kind IN('manual','policy')),
scope_kind TEXT NOT NULL CHECK(scope_kind IN('system','app')),
scope_id TEXT NOT NULL,
requested_by_type TEXT NOT NULL CHECK(requested_by_type IN('user','system','local_admin')),
requested_by_id TEXT NOT NULL,
cutoff_ms INTEGER NOT NULL CHECK(cutoff_ms>0),
batch_size INTEGER NOT NULL CHECK(batch_size BETWEEN 1 AND 5000),
max_records INTEGER NOT NULL CHECK(max_records BETWEEN 1 AND 1000000),
state TEXT NOT NULL CHECK(state IN('queued','running','succeeded','failed','cancelled')),
task_id TEXT,
scanned INTEGER NOT NULL DEFAULT 0 CHECK(scanned>=0),
cleaned INTEGER NOT NULL DEFAULT 0 CHECK(cleaned>=0),
skipped INTEGER NOT NULL DEFAULT 0 CHECK(skipped>=0),
failed INTEGER NOT NULL DEFAULT 0 CHECK(failed>=0),
batches INTEGER NOT NULL DEFAULT 0 CHECK(batches>=0),
limit_reached INTEGER NOT NULL DEFAULT 0 CHECK(limit_reached IN(0,1)),
error_code TEXT,
failure_reason TEXT,
request_id TEXT,
executor_id TEXT,
created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0),
started_at_ms INTEGER,
finished_at_ms INTEGER
);

CREATE INDEX ix_audit_maintenance_runs_created_at_ms ON audit_maintenance_runs(created_at_ms);

CREATE UNIQUE INDEX ux_audit_maintenance_runs_task_id ON audit_maintenance_runs(task_id) WHERE task_id IS NOT NULL;

-- 受保护清理审计：追加写，禁止 UPDATE/DELETE，保证清理审计不被同一次清理抹除。
CREATE TABLE audit_maintenance_log (
id TEXT PRIMARY KEY NOT NULL,
run_id TEXT,
occurred_at_ms INTEGER NOT NULL CHECK(occurred_at_ms>=0),
action TEXT NOT NULL,
actor_type TEXT NOT NULL CHECK(actor_type IN('user','system','local_admin')),
actor_id TEXT NOT NULL,
scope_kind TEXT NOT NULL CHECK(scope_kind IN('system','app')),
scope_id TEXT NOT NULL,
cutoff_ms INTEGER,
batch_index INTEGER,
scanned INTEGER,
cleaned INTEGER,
result TEXT NOT NULL,
error_code TEXT,
request_id TEXT,
task_id TEXT
);

CREATE INDEX ix_audit_maintenance_log_run ON audit_maintenance_log(run_id,occurred_at_ms);

-- INSERT OR REPLACE 在 recursive_triggers=0 时可能不触发 DELETE 触发器而替换既有行；
-- 额外在 INSERT 前检查同 ID 已存在并中止，保证只能普通追加。
CREATE TRIGGER trg_audit_maintenance_log_no_replace
BEFORE INSERT ON audit_maintenance_log
WHEN EXISTS(SELECT 1 FROM audit_maintenance_log WHERE id=NEW.id)
BEGIN
  SELECT RAISE(ABORT, 'audit_maintenance_log is append-only');
END;

CREATE TRIGGER trg_audit_maintenance_log_no_update
BEFORE UPDATE ON audit_maintenance_log
BEGIN
  SELECT RAISE(ABORT, 'audit_maintenance_log is append-only');
END;

CREATE TRIGGER trg_audit_maintenance_log_no_delete
BEFORE DELETE ON audit_maintenance_log
BEGIN
  SELECT RAISE(ABORT, 'audit_maintenance_log is append-only');
END;

-- 审计查询常用条件索引：应用/操作者/结果 + 时间，避免页面查询全表扫描。
CREATE INDEX ix_audit_events_app_occurred_at_ms ON audit_events(app_id_snapshot,occurred_at_ms);

CREATE INDEX ix_audit_events_actor_occurred_at_ms ON audit_events(actor_type,actor_id,occurred_at_ms);

CREATE INDEX ix_audit_events_outcome_occurred_at_ms ON audit_events(outcome,occurred_at_ms);
