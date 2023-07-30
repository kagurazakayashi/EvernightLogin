# 步骤 156 验收：管理写 API/CLI 与强认证真实 E2E

- 执行者：大肥鱼助手，2026-11-22 01:30–02:0x（Asia/Shanghai）；环境：Windows 11、Go 1.27.1、临时 SQLite/回环、真实 login-server + 真实 loginctl 二进制、Chrome/Passkey 虚拟认证器。
- 结论：**PASS_WITH_NOTES**。真实强认证管理会话下，用户/组/角色/应用创建、应用启停/资料更新（含行版本冲突 409/CONFLICT）、托管策略读取、过期强认证拒绝、强制下线/客服写已真实验证或明确 fail-closed；普通用户拒绝与部分敏感写仍为精确缺口（见下）。
- 证据：`docs/acceptance/evidence/step156/strong-auth-fixture-passkey-result.json`（夹具 `scripts/acceptance/strong_auth_fixture_passkey.py` + `scripts/acceptance/step156_cli_e2e.py`）。

## 1. 真实 E2E 结果

| 用例 | 结果 | 说明 |
|---|---|---|
| 强认证管理会话（root Passkey UV setup+relogin） | PASS | 真实 Chrome CDP 虚拟认证器；会话 cookie 转 CLI 管理会话文件 |
| `admin users` 只读 | PASS | 真实管理 API/CLI JSON |
| `admin write users` 创建用户 | PASS | 真实写入；未伪造 |
| `admin write groups` / `roles` | PASS | 角色需必填 limits；真实领域校验 |
| `admin write applications` 创建 + 启用 + 资料更新 | PASS | 更新带 owner/行版本；版本冲突返回 `CONFLICT`/退出码 6 |
| `admin application <id> managed-policy` 读取 | PASS | 返回 `not_configured`/can_write 真实策略状态 |
| 托管策略 PUT | PASS（fail-closed） | 缺少页面一次性强认证绑定/摘要时 `REQ_INVALID` 拒绝，未绕过 |
| 过期强认证（DB 会话 strong_auth 置 0） | PASS | CLI 读/写均 `REAUTH_REQUIRED` 非零退出；随后恢复时间戳 |
| 普通用户拒绝 | NOT_TESTED | 夹具未提供可登录普通用户密码凭据，未伪造 |
| `session admin-revoke` | PARTIAL | 管理会话调用返回 `ACCESS_DENIED`（敏感操作需要页面 reauth 绑定，CLI 未提供） |
| 客服 `support/cases` 写 | PARTIAL | `REAUTH_REQUIRED`（客服敏感操作需要独立强认证/审批绑定；非成功不伪造） |
| 页面同权限对比 | PASS | 强认证页面 `/admin/users|applications|roles` 200，匿名 401；与 CLI 同一管理 API |

## 2. 缺口（精确）

1. 强制下线与客服写需要**页面级敏感 reauth 绑定/独立审批**；当前 CLI 只持有管理会话文件，没有该一次性绑定，服务端 fail-closed 拒绝。建议后续加 `loginctl reauth`/一次性确认参数或专用 CLI 流程，不能放宽服务端。
2. 普通用户拒绝未做：夹具需能登录普通用户（密码/Passkey）并验证其 CLI/页面均被拒绝。
3. 应用删除、角色删除、权限创建：应用领域服务当前无删除能力（不新增假接口）；角色删除/权限创建的页面适配器契约缺失，已只补角色删除适配器/路由；权限创建与应用删除登记为缺口。
4. 写路由缺 serverapp 级完整装配集成测试（现有 adminapi 契约测试 + 真实 serve E2E 覆盖主要路径）。
