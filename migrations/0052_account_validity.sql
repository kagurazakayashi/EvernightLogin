-- 0052 账户有效期：全局账户可用时间窗口（步骤 234）
--
-- 语义：
--   - valid_from_ms / valid_until_ms 均为 UTC 毫秒、可空；NULL 表示该端不限制，
--     默认两列均为 NULL（永久有效，不改变既有账户行为）。
--   - 有效区间是半开区间 [valid_from_ms, valid_until_ms)：valid_from 当刻开始可用，
--     valid_until 当刻起不可用；两列都设置时必须 valid_until > valid_from。
--   - 到期是“计算出的不可用原因”，不修改 status；到期与手动 disabled 分离，续期
--     不自动启用被手动禁用的账户。root 不接受普通期限管理，本表不提供 DB 级豁免，
--     由领域服务在写入与读取两侧保护。
--   - 时间只用于身份生效与每次请求校验的即时判断，不依赖定时扫描；离线纯 JWT
--     验签无法感知即时到期，严格集成必须走在线授权。
--
-- 兼容：只追加两列，不修改历史迁移、不清库；不新增索引（查询按主键读取账户行）。
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

ALTER TABLE users ADD COLUMN valid_from_ms INTEGER
  CHECK(valid_from_ms IS NULL OR valid_from_ms >= 0);

ALTER TABLE users ADD COLUMN valid_until_ms INTEGER
  CHECK(valid_until_ms IS NULL OR valid_until_ms >= 0);
