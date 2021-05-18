-- 0008 本地受控首次初始化与 root 受限待配置状态。
--
-- 对应步骤 28 的“本地受控首次初始化、唯一 root 身份与防误删误禁服务规则”。
-- 一条记录表示：本实例已完成 root 创建，但 root 仍处于受限待配置状态。root
-- 的完整能力不通过普通角色推导，也不存在默认密码：初始化只签发一条一次性、
-- 本机、短期的配置凭证（0002 表），凭证摘要由凭证服务保存，本表只引用其 ID。
--
-- 语义：
--   - singleton=1 主键保证全库只有一条初始化记录；配合 0001 已建立的
--     ux_single_root 唯一索引，数据库层面双重保证唯一 root。
--   - state 是受限状态机：
--       pending_setup    root 已创建，等待一次性配置凭证兑换（可重新签发）；
--       setup_verified   一次性配置凭证已消费，仅允许必要的安全设置，不得据此
--                        签发完整管理员会话；步骤 29 正式密码/强认证服务完成后
--                        才允许进入 ready；
--       ready            正式密码与必需强认证已配置（本步不实现该转换）。
--   - setup_credential_id 指向最近一次签发的配置凭证；不保存凭证明文或摘要。
--     凭证过期、被消费或因清理被删除时由 Vault 置 NULL（凭证本身已不可用），
--     root 身份不受影响。
--   - root_user_id 外键 ON DELETE RESTRICT：存在初始化记录时数据库层面拒绝删除
--     root 行，与 account 服务 ErrProtectedUser 形成纵深防御。
--   - started_by 是本地受控操作者稳定标识（来自可信上下文，不是请求参数）。
--   - verified_at_ms / ready_at_ms 与 state 由 CHECK 联动，避免出现“已验证但没有
--     验证时间”等自相矛盾记录。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

CREATE TABLE root_initializations (
singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
root_user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE RESTRICT,
state TEXT NOT NULL CHECK(state IN('pending_setup','setup_verified','ready')),
setup_credential_id TEXT REFERENCES one_time_credentials(id) ON DELETE SET NULL,
started_by TEXT NOT NULL,
created_at_ms INTEGER NOT NULL,
updated_at_ms INTEGER NOT NULL,
verified_at_ms INTEGER,
ready_at_ms INTEGER,
CHECK(
(state='pending_setup' AND verified_at_ms IS NULL AND ready_at_ms IS NULL)
OR (state='setup_verified' AND verified_at_ms IS NOT NULL AND ready_at_ms IS NULL)
OR (state='ready' AND verified_at_ms IS NOT NULL AND ready_at_ms IS NOT NULL)
)
);

CREATE INDEX idx_root_initializations_state ON root_initializations(state);
