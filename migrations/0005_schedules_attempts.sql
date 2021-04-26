-- 0005 定时计划、任务尝试历史与重试。
--
-- 对应步骤 12 与设计基线 job_attempts/schedules/schedule_firings，并为可测试的
-- 调度与重试语义加入正式扩展列。本迁移只追加结构，不修改 0004 已落地的 jobs
-- 主列；jobs 的新增列通过 ALTER TABLE 追加，向后兼容已有行。
--
-- 语义：
--   - schedules.kind 是目标任务类型（例如 backup.daily），不是重复类型；
--     schedule_type 才是 daily/weekly/monthly/custom。表达式在服务层规范化后
--     存储，时区必须是 IANA 名称。
--   - schedules.permission_required 默认 1：所有计划默认要求运行前权限复验；
--     只有服务层能明确证明任务低风险时才能写 0（显式豁免）。
--   - last_scheduled_at_ms 是计划触发游标：创建或恢复时为当时时间，之后每次
--     已记录触发（入队/跳过/拒绝）推进到该触发时刻。停机错过的触发按
--     missed_policy 处理，补跑次数受 max_catch_up 限制。
--   - schedule_firings 的唯一键 (schedule_id, scheduled_at_ms) 是触发去重的
--     唯一依据；job_id 可空是因为跳过/权限拒绝的触发不会产生任务。
--   - job_attempts 保留每次尝试历史：领取任务时插入一行，结束或重试时关闭；
--     重启恢复把未关闭的尝试标记为 interrupted。
--   - jobs.next_attempt_at_ms 是退避后的最早领取时间；jobs.permission_required
--     表示执行器每次尝试前必须通过可信权限复验。
--   - 暂停/删除计划不修改 jobs；已入队或运行中的任务继续独立执行。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

CREATE TABLE job_attempts (
job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
attempt INTEGER NOT NULL CHECK(attempt>=1),
started_at_ms INTEGER NOT NULL,
finished_at_ms INTEGER,
outcome TEXT,
error_code TEXT,
executor_id TEXT,
PRIMARY KEY(job_id,attempt)
);

CREATE TABLE schedules (
id TEXT PRIMARY KEY NOT NULL,
kind TEXT NOT NULL,
schedule_type TEXT NOT NULL CHECK(schedule_type IN('daily','weekly','monthly','custom')),
expression TEXT NOT NULL,
timezone TEXT NOT NULL,
owner_type TEXT NOT NULL CHECK(owner_type IN('user','system','local_admin')),
owner_id TEXT NOT NULL,
execution_type TEXT NOT NULL CHECK(execution_type IN('user','system','local_admin')),
execution_id TEXT NOT NULL,
scope_id TEXT NOT NULL REFERENCES scopes(id),
enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN(0,1)),
permission_required INTEGER NOT NULL DEFAULT 1 CHECK(permission_required IN(0,1)),
missed_policy TEXT NOT NULL DEFAULT 'skip' CHECK(missed_policy IN('skip','latest','all')),
max_catch_up INTEGER NOT NULL DEFAULT 24 CHECK(max_catch_up>0 AND max_catch_up<=1000),
config_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(config_json)),
last_scheduled_at_ms INTEGER,
created_at_ms INTEGER NOT NULL,
updated_at_ms INTEGER NOT NULL
);

CREATE TABLE schedule_firings (
schedule_id TEXT NOT NULL REFERENCES schedules(id) ON DELETE CASCADE,
scheduled_at_ms INTEGER NOT NULL,
job_id TEXT REFERENCES jobs(id),
outcome TEXT NOT NULL CHECK(outcome IN('enqueued','skipped','denied')),
error_code TEXT,
reason_code TEXT,
created_at_ms INTEGER NOT NULL,
PRIMARY KEY(schedule_id,scheduled_at_ms)
);

ALTER TABLE jobs ADD COLUMN next_attempt_at_ms INTEGER;

ALTER TABLE jobs ADD COLUMN permission_required INTEGER NOT NULL DEFAULT 0 CHECK(permission_required IN(0,1));

CREATE INDEX ix_jobs_retry_due ON jobs(next_attempt_at_ms) WHERE state='queued' AND next_attempt_at_ms IS NOT NULL;

CREATE INDEX ix_job_attempts_open ON job_attempts(job_id) WHERE finished_at_ms IS NULL;

CREATE INDEX ix_schedules_enabled ON schedules(enabled,created_at_ms);
