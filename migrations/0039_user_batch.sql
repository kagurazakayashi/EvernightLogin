-- 0039 用户批量导入导出任务与结果报告（步骤 61）。
--
-- 设计边界：
--   - user_batch_jobs：一次导入/导出任务。幂等键绑定调用者（owner_type/owner_id）、
--     作用域与请求摘要（request_digest=SHA-256(文件+规范化选项)）；同幂等键不同
--     摘要按冲突拒绝，同键同摘要复用既有任务，不重复执行。导入文件内容以 BLOB
--     暂存（最多 5 MiB，任务进入终态后清空），导出只记录宿主目录下服务端生成文件
--     的路径、SHA-256、行数与截断标记，不把导出内容长期放数据库。
--   - user_batch_rows：(job_id,row_number) 主键记录逐行结果，重启/续跑时据此跳过
--     已处理行；只存稳定错误码/原因码/规范化用户名/用户 ID，不存原始行、密码哈希、
--     MFA 秘密或自由文本。明细按上限保留，超出置 truncated。
--   - 本表不保存导入的密码/哈希/root/管理资格/已验证状态/MFA 秘密：导入只走
--     internal/account.CreateUser 的资料白名单。
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

CREATE TABLE user_batch_jobs (
  id TEXT PRIMARY KEY NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN('import','export')),
  idempotency_key TEXT NOT NULL UNIQUE CHECK(length(idempotency_key) BETWEEN 8 AND 128),
  request_digest BLOB NOT NULL CHECK(length(request_digest)=32),
  owner_type TEXT NOT NULL CHECK(length(owner_type) BETWEEN 1 AND 32),
  owner_id TEXT NOT NULL CHECK(length(owner_id) BETWEEN 1 AND 64),
  scope_id TEXT NOT NULL DEFAULT 'system' CHECK(length(scope_id) BETWEEN 1 AND 64),
  state TEXT NOT NULL CHECK(state IN('queued','running','succeeded','partial','failed','cancelled')),
  total_rows INTEGER NOT NULL DEFAULT 0 CHECK(total_rows>=0),
  created_count INTEGER NOT NULL DEFAULT 0 CHECK(created_count>=0),
  skipped_count INTEGER NOT NULL DEFAULT 0 CHECK(skipped_count>=0),
  conflict_count INTEGER NOT NULL DEFAULT 0 CHECK(conflict_count>=0),
  failed_count INTEGER NOT NULL DEFAULT 0 CHECK(failed_count>=0),
  denied_count INTEGER NOT NULL DEFAULT 0 CHECK(denied_count>=0),
  truncated INTEGER NOT NULL DEFAULT 0 CHECK(truncated IN(0,1)),
  input_csv BLOB CHECK(input_csv IS NULL OR length(input_csv)<=5242880),
  export_path TEXT NOT NULL DEFAULT '',
  export_sha256 BLOB CHECK(export_sha256 IS NULL OR length(export_sha256)=32),
  export_rows INTEGER NOT NULL DEFAULT 0 CHECK(export_rows>=0),
  task_id TEXT NOT NULL DEFAULT '',
  error_code TEXT NOT NULL DEFAULT '',
  request_id TEXT NOT NULL DEFAULT '',
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  finished_at_ms INTEGER,
  CHECK(updated_at_ms>=created_at_ms)
);

CREATE INDEX ix_user_batch_jobs_owner
  ON user_batch_jobs(owner_type, owner_id, created_at_ms);
CREATE INDEX ix_user_batch_jobs_state
  ON user_batch_jobs(state, updated_at_ms);
CREATE INDEX ix_user_batch_jobs_kind
  ON user_batch_jobs(kind, created_at_ms);

CREATE TABLE user_batch_rows (
  job_id TEXT NOT NULL REFERENCES user_batch_jobs(id) ON DELETE CASCADE,
  row_number INTEGER NOT NULL CHECK(row_number>0),
  action TEXT NOT NULL CHECK(action IN('created','skipped','conflict','failed','denied')),
  error_code TEXT NOT NULL DEFAULT '' CHECK(length(error_code)<=64),
  reason_code TEXT NOT NULL DEFAULT '' CHECK(length(reason_code)<=64),
  username_normalized TEXT NOT NULL DEFAULT '' CHECK(length(username_normalized)<=256),
  user_id TEXT NOT NULL DEFAULT '' CHECK(length(user_id)<=64),
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY(job_id, row_number)
);

CREATE INDEX ix_user_batch_rows_action ON user_batch_rows(job_id, action);
