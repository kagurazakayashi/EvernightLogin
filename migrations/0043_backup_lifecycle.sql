-- 0043 备份生命周期：备份产物、保留策略、计划附加配置、任务阶段与通知投递。
--
-- 对应步骤 81：把步骤 80 的同步备份服务接入 internal/task 调度与管理页面后需要的
-- 持久化结构。本迁移只落地“受控元数据”，不保存备份正文、明文数据库内容、主密钥
-- 材料、宿主内部路径或通知收件地址原文。
--
-- 语义：
--   - backup_artifacts 每份真实发布成功的备份一条；backup_id 与备份容器头部编号一致
--     （bkp_ 前缀）。file_name 是受控输出目录内的文件名（不含目录），页面不得把它
--     当公开路径；file_sha256 是最终产物文件的 SHA-256。
--   - verification_state 区分 verified/unverified/unknown/failed：只有服务端完成
--     认证校验才可写 verified；任务成功不等于产物存在，产物存在不等于校验通过。
--   - 最后可用备份保护由查询层按“已发布且 verification_state='verified'”的集合实时
--     计算，禁止在这里缓存会漂移的布尔标记；cleanup_state 只表示该产物是否已按保留
--     策略清理，不表示原始审计删除。
--   - retention_version 指向备份创建时生效的策略版本；策略修改不追溯改写既有产物
--     的创建时版本。
--   - backup_retention_policy 为单行（id=1）当前生效策略；数量/天数/容量 0 表示该
--     项不启用，三项全部为 0 由服务层拒绝（不允许无限保留被静默默认）。责任身份与
--     修改原因必须保存，页面显示的是历史责任身份而不是当前操作者。
--   - backup_schedules 只保存 internal/task 计划的附加展示配置（名称、失败通知），
--     计划的周期/时区/执行身份等安全字段仍以 jobs/schedules 表为唯一事实源。
--   - backup_job_state 保存任务真实阶段与进度（服务端处理器写入），stage_code 为空
--     表示处理器尚未报告阶段；进度分子/分母未知时保持 NULL，不用 0 冒充。
--   - backup_notifications 保存通知投递结果；通知失败不得删除或改写备份产物事实。
--   - 原始审计清理仍由步骤 74 的 root 专属流程负责；本迁移不包含任何审计删除结构。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

-- 已发布备份产物（受控元数据）。
CREATE TABLE backup_artifacts (
backup_id TEXT PRIMARY KEY CHECK(length(backup_id) BETWEEN 4 AND 64),
job_id TEXT NOT NULL DEFAULT '' CHECK(length(job_id) <= 64),
schedule_id TEXT NOT NULL DEFAULT '' CHECK(length(schedule_id) <= 64),
origin TEXT NOT NULL DEFAULT 'manual' CHECK(origin IN('manual','schedule','catch_up','retry','system')),
file_name TEXT NOT NULL CHECK(length(file_name) BETWEEN 1 AND 200),
size_bytes INTEGER NOT NULL CHECK(size_bytes > 0),
payload_bytes INTEGER NOT NULL CHECK(payload_bytes > 0),
file_sha256 TEXT NOT NULL CHECK(length(file_sha256) = 64),
manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256) = 64),
format_version INTEGER NOT NULL CHECK(format_version > 0),
schema_version TEXT NOT NULL CHECK(length(schema_version) > 0),
content_database INTEGER NOT NULL CHECK(content_database IN(0,1)),
content_attachments TEXT NOT NULL CHECK(content_attachments IN('included','no_references','not_configured','excluded')),
content_config TEXT NOT NULL CHECK(content_config IN('included','no_references','not_configured','excluded')),
entry_count INTEGER NOT NULL CHECK(entry_count >= 0),
hostname TEXT NOT NULL DEFAULT '' CHECK(length(hostname) <= 128),
app_version TEXT NOT NULL DEFAULT '' CHECK(length(app_version) <= 128),
verification_state TEXT NOT NULL CHECK(verification_state IN('verified','unverified','unknown','failed')),
verified_at_ms INTEGER NOT NULL DEFAULT 0 CHECK(verified_at_ms >= 0),
retention_version INTEGER NOT NULL CHECK(retention_version >= 0),
cleanup_state TEXT NOT NULL DEFAULT 'retained' CHECK(cleanup_state IN('retained','cleaned')),
cleaned_at_ms INTEGER NOT NULL DEFAULT 0 CHECK(cleaned_at_ms >= 0),
cleanup_actor_type TEXT NOT NULL DEFAULT '' CHECK(cleanup_actor_type IN('','user','system','local_admin')),
cleanup_actor_id TEXT NOT NULL DEFAULT '' CHECK(length(cleanup_actor_id) <= 64),
created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
published_at_ms INTEGER NOT NULL CHECK(published_at_ms >= 0),
request_id TEXT NOT NULL DEFAULT '' CHECK(length(request_id) <= 64),
CHECK(published_at_ms >= created_at_ms),
CHECK(cleanup_state <> 'cleaned' OR cleaned_at_ms > 0),
CHECK(verification_state <> 'verified' OR verified_at_ms > 0)
);

CREATE INDEX ix_backup_artifacts_published ON backup_artifacts(cleanup_state, published_at_ms DESC, backup_id DESC);
CREATE INDEX ix_backup_artifacts_job ON backup_artifacts(job_id);
CREATE INDEX ix_backup_artifacts_schedule ON backup_artifacts(schedule_id);

-- 当前生效的备份保留策略（单行）。
CREATE TABLE backup_retention_policy (
id INTEGER PRIMARY KEY CHECK(id = 1),
version INTEGER NOT NULL CHECK(version >= 1),
max_count INTEGER NOT NULL CHECK(max_count >= 0),
max_age_days INTEGER NOT NULL CHECK(max_age_days >= 0 AND max_age_days <= 36500),
max_total_bytes INTEGER NOT NULL CHECK(max_total_bytes >= 0),
updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
updated_by_type TEXT NOT NULL CHECK(updated_by_type IN('user','system','local_admin')),
updated_by_id TEXT NOT NULL CHECK(length(updated_by_id) > 0),
reason TEXT NOT NULL DEFAULT '' CHECK(length(reason) <= 512),
request_id TEXT NOT NULL DEFAULT '' CHECK(length(request_id) <= 64),
CHECK(max_count > 0 OR max_age_days > 0 OR max_total_bytes > 0)
);

-- 定时备份计划的附加展示配置（周期/时区/执行身份以 schedules 表为准）。
CREATE TABLE backup_schedules (
schedule_id TEXT PRIMARY KEY CHECK(length(schedule_id) BETWEEN 4 AND 64),
name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 120),
retention_version INTEGER NOT NULL CHECK(retention_version >= 0),
notify_failures INTEGER NOT NULL DEFAULT 0 CHECK(notify_failures IN(0,1)),
notify_success INTEGER NOT NULL DEFAULT 0 CHECK(notify_success IN(0,1)),
notify_target TEXT NOT NULL DEFAULT '' CHECK(length(notify_target) <= 128),
created_by_type TEXT NOT NULL CHECK(created_by_type IN('user','system','local_admin')),
created_by_id TEXT NOT NULL CHECK(length(created_by_id) > 0),
created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
CHECK(updated_at_ms >= created_at_ms)
);

-- 任务真实阶段/进度与通知投递摘要（任务状态本身以 jobs 表为准）。
CREATE TABLE backup_job_state (
job_id TEXT PRIMARY KEY CHECK(length(job_id) BETWEEN 4 AND 64),
backup_id TEXT NOT NULL DEFAULT '' CHECK(length(backup_id) <= 64),
stage_code TEXT NOT NULL DEFAULT '' CHECK(length(stage_code) <= 64),
progress_done INTEGER CHECK(progress_done IS NULL OR progress_done >= 0),
progress_total INTEGER CHECK(progress_total IS NULL OR progress_total > 0),
progress_unit TEXT NOT NULL DEFAULT '' CHECK(progress_unit IN('','pages','bytes','entries')),
notification_state TEXT NOT NULL DEFAULT 'not_configured'
CHECK(notification_state IN('not_configured','pending','accepted','failed','unknown')),
notification_error_code TEXT NOT NULL DEFAULT '' CHECK(length(notification_error_code) <= 64),
result_summary TEXT NOT NULL DEFAULT '' CHECK(result_summary = '' OR json_valid(result_summary)),
updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
CHECK(progress_done IS NULL OR progress_total IS NULL OR progress_done <= progress_total)
);

CREATE INDEX ix_backup_job_state_backup ON backup_job_state(backup_id);

-- 备份失败/成功通知的独立投递记录（失败不得改写备份产物事实）。
CREATE TABLE backup_notifications (
id TEXT PRIMARY KEY CHECK(length(id) BETWEEN 4 AND 64),
job_id TEXT NOT NULL DEFAULT '' CHECK(length(job_id) <= 64),
backup_id TEXT NOT NULL DEFAULT '' CHECK(length(backup_id) <= 64),
kind TEXT NOT NULL CHECK(kind IN('backup_succeeded','backup_failed','backup_timeout','permission_denied','cleanup_failed')),
state TEXT NOT NULL CHECK(state IN('pending','accepted','failed','unknown')),
channel TEXT NOT NULL CHECK(channel IN('mail','local')),
recipient_masked TEXT NOT NULL DEFAULT '' CHECK(length(recipient_masked) <= 200),
error_code TEXT NOT NULL DEFAULT '' CHECK(length(error_code) <= 64),
attempts INTEGER NOT NULL DEFAULT 1 CHECK(attempts >= 1),
created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
CHECK(updated_at_ms >= created_at_ms)
);

CREATE INDEX ix_backup_notifications_job ON backup_notifications(job_id, created_at_ms DESC);
CREATE INDEX ix_backup_notifications_backup ON backup_notifications(backup_id, created_at_ms DESC);

-- 备份任务索引：internal/task 的 jobs 表是任务状态唯一事实源；本表只记录“哪些
-- 任务是备份/清理任务以及来源”，用于管理页受控分页与关联，不复制状态机。
CREATE TABLE backup_jobs (
job_id TEXT PRIMARY KEY CHECK(length(job_id) BETWEEN 4 AND 64),
kind TEXT NOT NULL CHECK(kind IN('backup.create','backup.cleanup')),
origin TEXT NOT NULL CHECK(origin IN('manual','schedule','catch_up','retry','system')),
schedule_id TEXT NOT NULL DEFAULT '' CHECK(length(schedule_id) <= 64),
initiator_type TEXT NOT NULL CHECK(initiator_type IN('user','system','local_admin')),
initiator_id TEXT NOT NULL CHECK(length(initiator_id) > 0),
created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0)
);

CREATE INDEX ix_backup_jobs_created ON backup_jobs(created_at_ms DESC, job_id DESC);
CREATE INDEX ix_backup_jobs_kind ON backup_jobs(kind, created_at_ms DESC);
