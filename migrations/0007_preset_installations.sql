-- 0007 预设目录初始化记录。
--
-- 对应步骤 27 的“系统角色、用户组与权限预设目录的版本化初始化与恢复默认”。一条
-- 记录表示：某个作用范围（系统固定 "system"，应用范围 ID 等于应用 ID）已按某个
-- 预设目录版本完成初始化。记录只用于比较版本与判断是否已初始化，不改变任何主体
-- 的有效权限；恢复预置仍必须展示差异、再次授权并通过委派 Guard 检查后写入。
--
-- 语义：
--   - scope_id 主键：同一作用范围只有一条初始化记录；重新安装或恢复后更新时间。
--   - catalog_version 是最近一次成功应用的预设目录版本（形如 1.0.0）；出现比程序
--     内置目录更高的版本时拒绝自动降级（fail-closed），避免旧程序覆盖新预设。
--   - 应用模板按应用记录，不同应用各自独立，不共用跨应用记录。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

CREATE TABLE preset_installations (
scope_id TEXT PRIMARY KEY NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
catalog_version TEXT NOT NULL,
applied_at_ms INTEGER NOT NULL,
updated_at_ms INTEGER NOT NULL
);

CREATE INDEX idx_preset_installations_version ON preset_installations(catalog_version);
