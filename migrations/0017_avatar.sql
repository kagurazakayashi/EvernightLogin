-- 0017 用户头像元数据与受控本地存储引用。
--
-- 对应步骤 37 的“头像上传、受控存储与网络头像处理”：
--   - avatars 只保存服务端生成的头像 ID、所属用户、受控存储目录内的相对键、
--     重编码后的真实媒体类型/字节数/尺寸/内容摘要与来源类别；不保存原始上传
--     内容、原始文件名、本机绝对路径或网络地址明文。
--   - users.avatar_ref（0001 已有列）保存当前头像 ID；它仍由本步的服务在审计
--     事务内与 avatars 行一起更新，不通过 SQLite 外键强制（旧基线值可能非空，
--     无法在不重建 users 表的情况下安全加外键约束）。读取方必须把空值视为无头像，
--     非空但 avatars 缺行时按存储不一致处理（fail-closed），不得返回未验证内容。
--   - storage_key 是形如 “ab/0123…ef.png” 的相对键，唯一约束防止同一文件被多个
--     头像引用；content_sha256 用于展示前完整性校验与 ETag，不保存明文路径。
--   - 每用户至多一个头像（user_id UNIQUE），因此替换是同一事务内的删除旧行/插入
--     新行；media_type 只允许重编码后的静态格式（SVG 等主动内容永不入库）。
--   - 本迁移不新增邮箱、密码、MFA、角色或 root 字段，也不改变应用专属资料隔离。

CREATE TABLE avatars (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  storage_key TEXT NOT NULL UNIQUE
    CHECK(length(storage_key) BETWEEN 7 AND 64),
  media_type TEXT NOT NULL
    CHECK(media_type IN('image/png','image/jpeg')),
  byte_size INTEGER NOT NULL CHECK(byte_size > 0),
  width INTEGER NOT NULL CHECK(width BETWEEN 8 AND 1024),
  height INTEGER NOT NULL CHECK(height BETWEEN 8 AND 1024),
  content_sha256 BLOB NOT NULL CHECK(length(content_sha256) = 32),
  source_kind TEXT NOT NULL CHECK(source_kind IN('upload','network')),
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL
);

CREATE INDEX ix_avatars_created_at_ms ON avatars(created_at_ms);
