-- 0004 后台任务状态。
--
-- 对应步骤 11 与设计基线 jobs 表：可靠单实例后台任务执行器的状态持久化。
-- 本步只落 jobs（排队/运行/成功/失败/取消请求/已取消/超时）；job_attempts、
-- schedules、schedule_firings、outbox_events 分别留给后续重试/调度/可靠事件步骤。
--
-- 语义：
--   - state 为受控枚举，终态（succeeded/failed/cancelled/timed_out）不能再被
--     晚到的取消覆盖；取消请求已接受只表示进入 cancel_requested，不等于已取消。
--   - initiated_by_* 是可信发起者；executed_by 是执行器稳定标识；
--     cancelled_by_* 记录取消请求人（用户、系统执行器或本地管理员），不伪装成
--     原发起人；cancellation_reason 记录取消原因。
--   - timeout_seconds 是墙钟执行上限（正整数秒）；started_at_ms 为开始执行时间，
--     实际截止 = started_at_ms + timeout_seconds*1000。
--   - started_at_ms、failure_reason 是对基线的正式扩展：基线只有 finished_at_ms
--     与 error_code，无法表达墙钟起点和安全失败说明。
--   - payload_json 只允许 JSON 对象，内容由任务处理器约定，不存秘密。
--   - mutex_key 可选：相同非空 mutex_key 的任务不能同时处于 running/cancel_requested。
--   - attempt/max_attempts 本步固定为 0/1，重试在后续步骤实现。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

CREATE TABLE jobs (
id TEXT PRIMARY KEY NOT NULL,
kind TEXT NOT NULL,
state TEXT NOT NULL CHECK(state IN('queued','running','succeeded','failed','cancel_requested','cancelled','timed_out')),
initiated_by_type TEXT NOT NULL CHECK(initiated_by_type IN('user','system','local_admin')),
initiated_by_id TEXT NOT NULL,
executed_by TEXT,
cancelled_by_type TEXT CHECK(cancelled_by_type IS NULL OR cancelled_by_type IN('user','system','local_admin')),
cancelled_by_id TEXT,
cancellation_reason TEXT,
cancel_requested_at_ms INTEGER,
started_at_ms INTEGER,
finished_at_ms INTEGER,
timeout_seconds INTEGER NOT NULL CHECK(timeout_seconds>0),
attempt INTEGER NOT NULL DEFAULT 0 CHECK(attempt>=0),
max_attempts INTEGER NOT NULL DEFAULT 1 CHECK(max_attempts>0),
mutex_key TEXT,
payload_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(payload_json)),
request_id TEXT,
error_code TEXT,
failure_reason TEXT,
created_at_ms INTEGER NOT NULL,
updated_at_ms INTEGER NOT NULL
);

CREATE INDEX ix_jobs_state_created_at_ms ON jobs(state,created_at_ms);

CREATE INDEX ix_jobs_mutex_active ON jobs(mutex_key,state) WHERE mutex_key IS NOT NULL AND state IN('running','cancel_requested');
