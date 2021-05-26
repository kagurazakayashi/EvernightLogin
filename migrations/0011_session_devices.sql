-- 0011 会话设备信息与记住我：补充设备列表所需的客户端描述、记住我标记与
-- 活动会话索引。
--
-- 对应步骤 31 的“用户设备列表、指定/全部退出与管理员按范围强制下线”。本迁移
-- 只追加列与索引，不改动 0010 已建立的会话事实：
--   - remember_me 记录签发时是否使用“记住我”的更长绝对到期；绝对到期本身已
--     写入 absolute_expires_at_ms，本标记只用于设备列表展示与排障，不参与续期
--     判断（续期永不超过 absolute_expires_at_ms）。
--   - client_user_agent 是客户端自称的 User-Agent 摘要，仅用于展示辅助；它由
--     客户端控制、可伪造，不是可信设备身份，也不能用于任何授权判断。服务层在
--     写入前截断并去除控制字符。
--   - client_address 是可信边界（连接来源，或经既有可信代理链解析的结果）给出
--     的来源地址提示，仅用于展示；它不是绝对地理位置，不用于授权判断。服务层
--     在写入前截断并去除控制字符。
--   - 两个客户端列都不保存 Cookie、会话秘密、CSRF 令牌或任何可还原凭据；会话
--     秘密仍然只保存 0010 定义的 HMAC 验证摘要。
--   - 新增按用户/应用的活动会话索引，服务“最大在线数”“单设备替换”与设备列表
--     分页在审计事务内使用，避免全表扫描。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

ALTER TABLE sessions ADD COLUMN remember_me INTEGER NOT NULL DEFAULT 0 CHECK(remember_me IN(0,1));
ALTER TABLE sessions ADD COLUMN client_user_agent TEXT NOT NULL DEFAULT '' CHECK(length(client_user_agent)<=256);
ALTER TABLE sessions ADD COLUMN client_address TEXT NOT NULL DEFAULT '' CHECK(length(client_address)<=128);

CREATE INDEX idx_sessions_user_active ON sessions(user_id,idle_expires_at_ms,absolute_expires_at_ms);
CREATE INDEX idx_sessions_app_active ON sessions(app_id,idle_expires_at_ms,absolute_expires_at_ms);
