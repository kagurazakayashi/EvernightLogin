-- 0042 报告生命周期：报告计划与报告历史/运行记录。
--
-- 对应步骤 79：定期报告与管理列表需要的持久化结构。报告生成产物本身仍由
-- internal/reports 的受控输出目录与固定统计快照负责；本迁移只落地“计划配置”与
-- “报告运行历史”两类受控元数据，不复制原始审计事实，也不保存报告产物文件内容。
--
-- 语义：
--   - 时间统一使用 UTC 毫秒整数（created_at_ms/started_at_ms/finished_at_ms/
--     expires_at_ms/retention_until_ms），展示时区由查询层按 IANA 时区换算，不在此
--     存储本地时间文本。
--   - report_plans.id 与通用定时计划编号格式一致（sch_ 前缀），用于页面核对与
--     关联；计划是“未来触发配置”，停用只停止后续触发，不删除历史。
--   - report_history.id 与既有即时报告编号格式一致（rpt_ 前缀），plan_id 为空表示
--     非计划触发的即时报告；计划删除后历史记录仍保留（plan_id 不做级联删除），
--     页面以服务端保存的脱敏名称显示。
--   - state 使用真实任务/报告状态：已提交排队、运行中、取消请求已接受、已取消、
--     完成、失败、超时。取消请求不等于实际取消，不得把两者合并。
--   - data_scope_json 只保存生成时的数据范围引用（全量/获准应用 ID 集合），用于
--     进程重启后回源历史时按调用者当前权限重新判断范围是否仍被覆盖；不是权限缓存。
--   - snapshot_json 只保存步骤 77 的聚合统计快照（已裁剪、无原始审计/凭证/秘密）；
--     artifacts_json 只保存格式、媒体类型、字节数、SHA-256 与受控文件名，不保存宿主
--     路径、内部存储地址或长期凭证。
--   - cleanup_state 区分报告文件“未到期待清理/已到期待清理/已清理”；报告文件清理
--     与原始审计删除严格分开，本表不提供原始审计清理语义。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

-- 报告计划：所有者与执行身份分开记录；执行身份在每次触发时重新复核权限。
CREATE TABLE report_plans (
id TEXT PRIMARY KEY,
name TEXT NOT NULL CHECK(length(name) > 0),
owner_type TEXT NOT NULL CHECK(owner_type IN('user','system','local_admin')),
owner_id TEXT NOT NULL CHECK(length(owner_id) > 0),
execution_actor_type TEXT NOT NULL CHECK(execution_actor_type IN('user','system','local_admin')),
execution_actor_id TEXT NOT NULL CHECK(length(execution_actor_id) > 0),
scope_id TEXT NOT NULL CHECK(length(scope_id) > 0),
scope_kind TEXT NOT NULL CHECK(scope_kind IN('system','app')),
app_id TEXT NOT NULL DEFAULT '',
template TEXT NOT NULL CHECK(length(template) > 0),
schedule_type TEXT NOT NULL CHECK(schedule_type IN('daily','weekly','monthly','custom')),
schedule_expression TEXT NOT NULL CHECK(length(schedule_expression) > 0),
time_zone TEXT NOT NULL CHECK(length(time_zone) > 0 AND time_zone <> 'Local'),
granularity TEXT NOT NULL CHECK(granularity IN('day','week','month')),
window_days INTEGER NOT NULL CHECK(window_days BETWEEN 1 AND 90),
categories_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(categories_json)),
trend_metric TEXT NOT NULL DEFAULT '',
formats_json TEXT NOT NULL CHECK(json_valid(formats_json)),
detail_rows INTEGER NOT NULL CHECK(detail_rows > 0),
missed_policy TEXT NOT NULL CHECK(missed_policy IN('skip','latest','all')),
max_catch_up INTEGER NOT NULL CHECK(max_catch_up > 0),
timeout_seconds INTEGER NOT NULL CHECK(timeout_seconds > 0),
max_attempts INTEGER NOT NULL CHECK(max_attempts > 0),
enabled INTEGER NOT NULL CHECK(enabled IN(0,1)),
version INTEGER NOT NULL CHECK(version >= 1),
created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
CHECK(updated_at_ms >= created_at_ms)
);

CREATE INDEX ix_report_plans_owner ON report_plans(owner_type, owner_id, created_at_ms DESC);
CREATE INDEX ix_report_plans_scope ON report_plans(scope_id, created_at_ms DESC);
CREATE INDEX ix_report_plans_enabled ON report_plans(enabled, updated_at_ms);

-- 报告历史/运行记录：每次报告生成（即时或计划触发）一条，状态按真实终态更新。
CREATE TABLE report_history (
id TEXT PRIMARY KEY,
plan_id TEXT NOT NULL DEFAULT '',
retry_of TEXT NOT NULL DEFAULT '',
name TEXT NOT NULL CHECK(length(name) > 0),
owner_type TEXT NOT NULL CHECK(owner_type IN('user','system','local_admin')),
owner_id TEXT NOT NULL CHECK(length(owner_id) > 0),
scope_id TEXT NOT NULL CHECK(length(scope_id) > 0),
scope_kind TEXT NOT NULL CHECK(scope_kind IN('system','app')),
app_id TEXT NOT NULL DEFAULT '',
template TEXT NOT NULL CHECK(length(template) > 0),
state TEXT NOT NULL CHECK(state IN(
'queued','running','cancel_requested','cancelled','succeeded','failed','timed_out')),
formats_json TEXT NOT NULL CHECK(json_valid(formats_json)),
categories_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(categories_json)),
trend_metric TEXT NOT NULL DEFAULT '',
detail_rows INTEGER NOT NULL CHECK(detail_rows > 0),
data_scope_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(data_scope_json)),
window_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(window_json)),
snapshot_json TEXT NOT NULL DEFAULT '' CHECK(snapshot_json = '' OR json_valid(snapshot_json)),
artifacts_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(artifacts_json)),
task_id TEXT NOT NULL DEFAULT '',
executor_id TEXT NOT NULL DEFAULT '',
error_code TEXT NOT NULL DEFAULT '',
failure_reason TEXT NOT NULL DEFAULT '',
request_id TEXT NOT NULL DEFAULT '',
created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
started_at_ms INTEGER NOT NULL DEFAULT 0 CHECK(started_at_ms >= 0),
finished_at_ms INTEGER NOT NULL DEFAULT 0 CHECK(finished_at_ms >= 0),
expires_at_ms INTEGER NOT NULL DEFAULT 0 CHECK(expires_at_ms >= 0),
retention_until_ms INTEGER NOT NULL DEFAULT 0 CHECK(retention_until_ms >= 0),
cleanup_state TEXT NOT NULL DEFAULT 'none'
CHECK(cleanup_state IN('none','pending','cleaned')),
CHECK(finished_at_ms = 0 OR finished_at_ms >= created_at_ms)
);

CREATE INDEX ix_report_history_scope_time ON report_history(scope_id, created_at_ms DESC, id);
CREATE INDEX ix_report_history_plan_time ON report_history(plan_id, created_at_ms DESC);
CREATE INDEX ix_report_history_state_time ON report_history(state, created_at_ms DESC);
CREATE INDEX ix_report_history_cleanup ON report_history(cleanup_state, expires_at_ms);
