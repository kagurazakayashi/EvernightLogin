-- 0006 可转授权限（委派）登记。
--
-- 对应步骤 26 的“可使用权限与可转授权限分离”。一条记录表示：受信操作者明确允许
-- 某用户（delegator）在指定作用范围内把某个权限（permission_id）再转授给其他主体。
-- 仅有权限本身不再隐含转授资格；权限停用/删除、委派撤回或过期都使资格失效。
--
-- 语义：
--   - (delegator_user_id, scope_id, permission_id) 唯一：同一用户在同一范围对同一
--     权限只有一条委派资格；重新签发覆盖原记录并清除 revoked_at_ms（审计保留前后值）。
--   - max_data_scope_json 是本次可转授的数据范围上限，默认 {"v":1,"mode":"all"}；
--     实际转授的数据范围必须是它的子集，资源级上限不能转授未声明（undefined）范围。
--   - allowed_targets_json 是目标白名单，默认 {"v":1} 表示不限制具体用户/用户组（但仍
--     受 allow_self 约束）；格式非法时检查 fail-closed。
--   - allow_self 默认 0：不允许把权限转授给自己或自己所在的用户组，用于封堵自我提权。
--   - expires_at_ms 为空表示不过期；revoked_at_ms 非空表示已撤回。
--   - 记录由可信本地/系统操作者签发，操作者与时间写入安全审计；本表只登记“可转授”
--     资格，不改变任何主体的有效权限。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

CREATE TABLE permission_delegations (
id TEXT PRIMARY KEY NOT NULL,
delegator_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
scope_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
permission_id TEXT NOT NULL,
max_data_scope_json TEXT NOT NULL DEFAULT '{"v":1,"mode":"all"}' CHECK(json_valid(max_data_scope_json)),
allowed_targets_json TEXT NOT NULL DEFAULT '{"v":1}' CHECK(json_valid(allowed_targets_json)),
allow_self INTEGER NOT NULL DEFAULT 0 CHECK(allow_self IN(0,1)),
expires_at_ms INTEGER,
revoked_at_ms INTEGER,
created_by_type TEXT NOT NULL,
created_by_id TEXT NOT NULL,
created_at_ms INTEGER NOT NULL,
updated_at_ms INTEGER NOT NULL,
UNIQUE(delegator_user_id,scope_id,permission_id),
FOREIGN KEY(permission_id,scope_id) REFERENCES permissions(id,scope_id) ON DELETE CASCADE
);

CREATE INDEX idx_permission_delegations_delegator ON permission_delegations(delegator_user_id,scope_id);

CREATE INDEX idx_permission_delegations_permission ON permission_delegations(permission_id);
