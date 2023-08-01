# 步骤 161 验收：业务管理前端、人工客服与应用隔离（PARTIAL）

- 执行者：大肥鱼助手，2026-11-21 22:5x–23:0x（Asia/Shanghai）。环境：Windows 11、Go 1.27.1、临时 SQLite、回环端口、合成身份；未改 Mail 子模块、无 Git 写操作。
- 结论：**PARTIAL**。服务/页面/管理 API 授权与客服秘密禁区由真实服务+真实 SQLite 的仓库测试覆盖并通过；真实 serve 的公开页面/未认证管理边界与浏览器公开页路径已实测；**root/系统管理员/应用管理员/客服/普通用户的真实登录矩阵因缺少“强认证管理会话夹具”未执行 → NOT_TESTED**，未用测试替身冒充。
- 原始证据：`docs/acceptance/evidence/step161-real-serve-smoke.json`（真实 serve + Chrome/Playwright；日志 `/p/go/tmp/step161-smoke.log`）。

## 1. 矩阵与状态

| 用例 | 场景/入口 | 预期 | 实际/证据 | 状态 |
|---|---|---|---|---|
| 161-A1 | root/系统管理员/应用管理员/客服/普通用户各登录真实 serve，访问 `/admin/users|/admin/roles|/admin/applications|/support` | 按真实权限显示；普通用户/客服不得读系统管理数据 | 未建立强认证管理会话夹具，未执行真实登录矩阵 | **NOT_TESTED** |
| 161-A2 | A 应用管理员读/写 B 应用数据（页面+直接 HTTP） | 403/404，不泄露存在性 | `internal/support` StaffScope 跨目标、`internal/adminapi` 路由权限测试 PASS；真实 serve A/B 登录矩阵未执行 | **PARTIAL** |
| 161-A3 | 应用管理员访问系统资格/root/他人应用 | 拒绝；root/系统资格不可被应用触及 | `internal/support`/`internal/adminapi`/页面 RBAC 权限矩阵测试 PASS；真实身份矩阵未执行 | **PARTIAL** |
| 161-B1 | 客服工单列表/详情/登记 | 只显示获准目标与脱敏字段；无完整邮箱/秘密 | `TestUIPageSupport*`（真实 support SQLite + 页面 Handler）PASS：跨客服 403、脱敏、历史追加式 | **PASS（页面/服务层）** |
| 161-B2 | 工单核验/审批/执行/拒绝/取消 | 独立审批、两权分离、等待期、幂等；失败不假成功 | `TestUIPageSupportIntegration*` PASS（真实 manualrecovery；自批拒绝、独立审批、等待期、执行、通知失败、重复执行幂等） | **PASS（页面/服务层）** |
| 161-B3 | 客服无秘密可读 | 页面/响应不出现密码、MFA 秘密、链接、验证码、Token | 页面测试禁区断言 PASS；153 报告记录 | **PASS（页面/服务层）** |
| 161-B4 | 客服恢复/审批经真实 serve HTTP | 同一权限结果、真实操作者可追踪 | 真实 serve 管理会话夹具缺失；页面层由真实服务测试覆盖 | **NOT_TESTED（真实 serve）** |
| 161-C1 | 撤销会话后旧 Cookie/旧页面请求 | 立即 401/403，不缓存成功 | `internal/session` 真实 SQLite 测试 PASS（撤销后 Validate 失败）；真实 serve 强会话未执行 | **PASS（服务层）/NOT_TESTED（serve）** |
| 161-C2 | 撤权/停用后旧页面/旧令牌 | 立即拒绝；管理员强制下线新会话有效 | `internal/session` 权限/root/强认证测试、`internal/adminapi` 路由测试 PASS；真实 serve 未执行 | **PARTIAL** |
| 161-D1 | 响应式 360/768/1024 页面 | 可读可操作，错误可复现 | 仅模板/既有页面测试；未做真实视口截图矩阵 | **NOT_TESTED** |
| 161-D2 | 错误反馈/无权限/会话过期 | 稳定错误码+中文提示，不泄内部细节 | 页面/管理 API 错误映射测试 PASS；真实 serve 浏览器登录后未测 | **PARTIAL** |
| 161-E1 | 真实 serve 健康/公开登录页 | 200，可浏览器打开 | 真实 `login-server serve`：`/healthz` 200、`/login` 200；Chrome/Playwright 打开登录页 200 有表单 | **PASS** |
| 161-E2 | 未认证管理页面/API | 页面重定向/401，API 401 AUTH_FAILED，不空成功 | `/admin/users` 401 页面；`/admin/v1/users` 401 `AUTH_FAILED`；CLI 未认证同类失败（156 证据） | **PASS** |
| 161-E3 | 注册关闭时 `/register` | 403 明确关闭，不渲染可提交表单 | 实测 403，浏览器无表单（预期） | **PASS** |

## 2. 已执行命令与证据

```text
# 真实 serve + Chrome/Playwright 公开页面/未认证边界（本次执行）
python scripts/acceptance/step161-smoke.py
→ STEP161_SMOKE_RESULT ok=true；healthz=200、login=200、register=403、admin 页面=401、admin API=401 AUTH_FAILED；
  browser: /login 200 title=EvernightLogin · 状态 hasForm=true，/register 403
证据：docs/acceptance/evidence/step161-real-serve-smoke.json

# 服务/页面矩阵（真实 SQLite + 真实 support/manualrecovery/adminapi，非 mock；测试替身仅在部分授权替身）
go test ./internal/adminapi ./internal/support ./internal/manualrecovery ./internal/uiadminadapter   PASS
go test -run 'TestUIPageSupport|TestUIPageAdmin|TestUIPageRBAC|TestUIPageApps' .                     PASS
```

## 3. 未测/限制（NOT_TESTED 风险）

1. **真实强认证管理会话夹具**：root init 后需 MFA/Passkey/受控 reauth 才能取得可管理 admin API 的会话；本步未搭建该夹具，故 A 矩阵与 B4/C1-C2 的真实 serve 路径未执行，未用普通会话冒充管理根。
2. 浏览器只验证了公开登录页与注册关闭；**管理后台/客服页面在真实浏览器中的点击矩阵**未执行（依赖同上强会话）。
3. 360/768/1024 视口真机/截图矩阵未做；真实读屏、真机移动端、完整像素 diff 均 NOT_TESTED。
4. A/B 应用隔离在**服务/页面层**由真实 SQLite + StaffScope/权限测试覆盖，但真实登录身份矩阵未执行；应用维度客服 API（154）仍属在途/部分。
5. 本步未新增产品代码；未新增迁移；未改 Mail。

## 2026-11-22 00:19 强认证夹具补跑

真实 root Passkey strong-setup + 第二因素取得管理会话后：`/admin/users`、`/admin/applications`、`/admin/roles`、`/admin/audit`、`/admin/reports` 及主要 `/admin/v1/*` 路由真实 **200**；未认证 admin 页面/API **401**，`/admin` 404。**完整角色×应用矩阵、客服页面/HTTP、撤权后旧页面/旧令牌仍 NOT_TESTED**，需多账户/多应用种子后补跑。证据：`docs/acceptance/evidence/strong-auth-fixture/`。

## 2026-11-22 02:14 最终补跑（VERDICT：PARTIAL）

详见 `docs/acceptance/evidence/step161/step161-final.md`：真实 root 强会话管理页/API、普通用户 403、A/B 应用创建、客服页面无秘密 PASS；客服员工强认证登录、app-scoped 权限隔离、管理员强制下线 NOT_TESTED/PARTIAL，161 保持 PARTIAL。
