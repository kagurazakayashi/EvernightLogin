// Package profile 实现用户自助资料修改与获授权管理员修改（步骤 35）。
//
// 边界与安全不变量：
//   - 通用资料 API 只写 users 表的昵称/简介/语言/时区/可选电话与受控用户名；不接受
//     is_root、status、security_version、邮箱验证状态、密码、MFA、角色等字段。
//   - 全局资料与应用专属资料（app_memberships.profile_json）互不覆盖；本包不写应用
//     资料，应用资料由 internal/app 维护。
//   - 本人可改本人非敏感资料；管理员修改他人资料必须由宿主注入 Authorizer，未接线时
//     普通用户对他人操作一律 fail-closed（system/local_admin 受信通道除外）。
//   - 更新使用 expected row_version 条件更新；并发冲突返回 CONFLICT，不部分修改。
//   - 更名复用 account.NormalizeUsername 的规范化/保留名规则，稳定 ID 不变；频率限制与
//     再次验证规则由 Policy 配置（默认 24 小时冷却 + 默认要求再次验证；未接线
//     ReauthVerifier 时用户更名一律拒绝，不默认免检）。trusted system/local_admin 通道
//     不受再次验证回调限制，但仍受保留名/唯一性/版本条件约束。
//   - 电话只保存 E.164 规范化值，phone_verified_at_ms 由本步从不写入；电话永不参与
//     登录、找回或身份验证（本版始终未验证）。
//   - 关键修改与审计同事务，审计以稳定用户 ID 关联并记录新旧用户名/脱敏电话。
//   - 本包不注册 HTTP 路由、不装配 cmd/login-server、不签发会话。
package profile
