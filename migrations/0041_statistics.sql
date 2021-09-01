-- 0041 可重复计算的统计数据采样与可信业务活动。
--
-- 对应步骤 75：统计后端需要的持久化结构。活跃用户与错误聚合直接从
-- audit_events（可信审计事实）在服务端聚合，不在本迁移复制原始事件；本迁移只
-- 落地两类“过程数据”：
--   - stats_health_samples：服务健康/请求错误/任务通知/数据库/证书等模块的
--     按观测时刻采样。每个模块同一观测时刻只保留一条，采样任务负责按保留期与
--     行数上限清理，限制存储增长。未来备份等未启用模块不写采样行，而不是写
--     一条“健康”假样本。
--   - stats_business_activity：应用服务端（可信来源）显式上报的业务活动事实。
--     与“成功认证活跃用户”分开统计，不使用客户端自报数据；幂等键绑定应用
--     (app_id, dedupe_key) 唯一，重复上报按幂等处理、不重复计数，也不会因为另一个
--     应用使用相同幂等键而静默丢弃本应用事件。
--
-- 语义：
--   - 时间统一使用 UTC 毫秒整数，与项目既有表示一致；展示时区由查询层按 IANA
--     时区换算，不在此处存储本地时间。
--   - detail_json 只保存脱敏、有界的模块状态补充信息（不保存连接串、凭据、
--     证书私钥或自由文本）。
--   - source 是可信来源稳定标识：当前只允许 'app_server'（由应用服务端调用统计
--     后端，浏览器/普通请求参数不能自称该来源）。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

-- 健康/状态采样：主键保证同一模块同一观测时刻不重复写入。
CREATE TABLE stats_health_samples (
module TEXT NOT NULL,
observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0),
state TEXT NOT NULL,
severity TEXT NOT NULL,
enabled INTEGER NOT NULL CHECK(enabled IN(0,1)),
source TEXT NOT NULL,
detail_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(detail_json)),
PRIMARY KEY(module, observed_at_ms)
);

CREATE INDEX ix_stats_health_samples_observed_at_ms ON stats_health_samples(observed_at_ms);

-- 可信业务活动上报事实；幂等键绑定应用唯一，避免跨应用同名键互相吞事件。
CREATE TABLE stats_business_activity (
id INTEGER PRIMARY KEY AUTOINCREMENT,
app_id TEXT NOT NULL,
user_id TEXT NOT NULL,
activity_key TEXT NOT NULL,
occurred_at_ms INTEGER NOT NULL CHECK(occurred_at_ms >= 0),
recorded_at_ms INTEGER NOT NULL CHECK(recorded_at_ms >= 0),
source TEXT NOT NULL CHECK(source IN('app_server')),
dedupe_key TEXT NOT NULL
);

CREATE UNIQUE INDEX ux_stats_business_activity_app_dedupe_key ON stats_business_activity(app_id,dedupe_key);

CREATE INDEX ix_stats_business_activity_occurred_at_ms ON stats_business_activity(occurred_at_ms);

CREATE INDEX ix_stats_business_activity_app_time ON stats_business_activity(app_id,occurred_at_ms);
