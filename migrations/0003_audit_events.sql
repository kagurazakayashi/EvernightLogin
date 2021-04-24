-- 0003 安全审计事件。
--
-- 对应步骤 10 与设计基线 audit_events 表。按 docs/database/存储模型与迁移设计.md
-- 的跨数据库表示约定落地：时间使用 UTC 毫秒整数；detail_json 使用 json_valid；
-- app_id_snapshot 不建外键，保留事件发生时的应用快照，避免应用删除或改名后
-- 安全审计丢失/失真。
--
-- 语义：
--   - actor_type 区分可信用户、系统任务、本地管理员与匿名失败；actor_id 是可信
--     上下文提供的稳定 ID，匿名事件不得伪造身份。
--   - outcome 表示成功/失败/拒绝；error_code 是对外错误码，reason_code 是受限
--     内部原因码；request_id/task_id 用于关联请求与后台任务。
--   - detail_json 只允许脱敏后的变更差异，不允许秘密、令牌或未受限大正文。
--   - dedupe_key 是本步骤对基线的扩展：可选幂等键，关键变更重试时防止重复记录
--     和重复执行；唯一部分索引只约束非空值。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

CREATE TABLE audit_events (
id TEXT PRIMARY KEY NOT NULL,
occurred_at_ms INTEGER NOT NULL,
actor_type TEXT NOT NULL CHECK(actor_type IN('user','system','local_admin','anonymous')),
actor_id TEXT,
app_id_snapshot TEXT,
action TEXT NOT NULL,
target_type TEXT NOT NULL,
target_id TEXT,
outcome TEXT NOT NULL CHECK(outcome IN('success','failure','denied')),
error_code TEXT,
reason_code TEXT,
request_id TEXT,
task_id TEXT,
detail_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(detail_json)),
dedupe_key TEXT
);

CREATE INDEX ix_audit_events_occurred_at_ms ON audit_events(occurred_at_ms);

CREATE INDEX ix_audit_events_request_id ON audit_events(request_id);

CREATE INDEX ix_audit_events_task_id ON audit_events(task_id);

CREATE INDEX ix_audit_events_action_occurred_at_ms ON audit_events(action,occurred_at_ms);

CREATE UNIQUE INDEX ux_audit_events_dedupe_key ON audit_events(dedupe_key) WHERE dedupe_key IS NOT NULL;
