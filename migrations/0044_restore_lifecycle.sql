-- 0044 维护模式恢复生命周期：恢复代际、恢复运行记录与恢复后暂停清单。
--
-- 对应步骤 82：在维护状态与排他锁下从加密备份恢复数据库，并防止旧凭证因数据
-- 回滚复活。本迁移只落地恢复过程需要的受控持久化结构；恢复代际的**权威副本**
-- 不在数据库中，而在库外受控目录的 restore-state 文件（见 internal/maintenance），
-- 本库内 generation 只是可查询的记录，用于检测带外回滚/替换（两者不一致时恢复
-- 前检查按 fail-closed 拒绝，不会仅凭库内记录认定代际）。
--
-- 语义：
--   - restore_generation 单行（id=1），generation 是最近一次**成功完成**的恢复代际，
--     与库外权威代际在同一次恢复后处理事务中一起前进；0 表示尚未恢复过。
--   - restore_runs 只记录**成功完成**并写入恢复后数据库的恢复运行（status 固定
--     completed）；失败/回退尝试不写入被恢复的数据库（那会修改恢复前状态），而是
--     保存在库外追加审计日志 restore-journal.jsonl 中，恢复后可靠合并。operator_type/id
--     记录真实执行者（本地应急管理员或 root 用户），不接受请求参数自称。
--   - restore_paused_items 记录恢复后被默认暂停/取消的旧调度计划、Webhook 端点、
--     任务与通知，供恢复后受控审查与重新启用；它是审查清单，不代替原对象状态。
--   - 本迁移不保存备份文件内容、主密钥材料、凭据明文或宿主绝对路径。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

-- 库内恢复代际记录（权威副本在库外受控目录；两者必须一致）。
CREATE TABLE restore_generation (
  id INTEGER PRIMARY KEY CHECK(id=1),
  generation INTEGER NOT NULL CHECK(generation >= 0),
  updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0)
);

INSERT INTO restore_generation(id,generation,updated_at_ms) VALUES(1,0,0);

-- 每次真实开始执行的恢复运行记录（成功/失败/已回退分开）。
CREATE TABLE restore_runs (
  restore_id TEXT PRIMARY KEY CHECK(length(restore_id) BETWEEN 4 AND 64),
  generation INTEGER NOT NULL CHECK(generation >= 1),
  backup_id TEXT NOT NULL DEFAULT '' CHECK(length(backup_id) <= 64),
  backup_sha256 TEXT NOT NULL DEFAULT ''
    CHECK(length(backup_sha256) = 0 OR length(backup_sha256) = 64),
  backup_schema_version TEXT NOT NULL DEFAULT ''
    CHECK(length(backup_schema_version) <= 64),
  operator_type TEXT NOT NULL CHECK(operator_type IN('user','local_admin','system')),
  operator_id TEXT NOT NULL CHECK(length(operator_id) BETWEEN 1 AND 128),
  status TEXT NOT NULL CHECK(status='completed'),
  started_at_ms INTEGER NOT NULL CHECK(started_at_ms >= 0),
  completed_at_ms INTEGER NOT NULL CHECK(completed_at_ms >= started_at_ms),
  reason TEXT NOT NULL DEFAULT '' CHECK(length(reason) <= 500),
  rollback_backup_file TEXT NOT NULL DEFAULT ''
    CHECK(length(rollback_backup_file) <= 200),
  result_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(result_json))
);

CREATE INDEX ix_restore_runs_completed ON restore_runs(completed_at_ms DESC);

-- 恢复后默认暂停/取消的对象清单（受控审查与重新启用的依据）。
CREATE TABLE restore_paused_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  restore_id TEXT NOT NULL REFERENCES restore_runs(restore_id) ON DELETE RESTRICT,
  kind TEXT NOT NULL CHECK(kind IN('schedule','webhook','job','mail','notification')),
  target_id TEXT NOT NULL CHECK(length(target_id) BETWEEN 1 AND 128),
  previous_state TEXT NOT NULL DEFAULT '' CHECK(length(previous_state) <= 64),
  paused_at_ms INTEGER NOT NULL CHECK(paused_at_ms >= 0),
  reviewed_at_ms INTEGER,
  reenabled_at_ms INTEGER,
  CHECK(reviewed_at_ms IS NULL OR reviewed_at_ms >= paused_at_ms),
  CHECK(reenabled_at_ms IS NULL OR reenabled_at_ms >= paused_at_ms),
  UNIQUE(restore_id,kind,target_id)
);

CREATE INDEX ix_restore_paused_items_restore ON restore_paused_items(restore_id,kind);
