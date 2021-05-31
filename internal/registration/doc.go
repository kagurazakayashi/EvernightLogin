// Package registration 实现按配置开放的自主注册与可选邮箱验证后端流程。
//
// 设计边界（步骤 33）：
//   - 注册输入只接受用户名、密码、可选邮箱与基础资料白名单；不接受系统角色、
//     应用管理资格、is_root、已验证邮箱状态等客户端自称字段。ParseRegisterJSON
//     使用严格 JSON 解码，未知字段一律拒绝。
//   - 密码沿用 internal/authn 的 Argon2id 哈希与密码策略；注册不签发会话或
//     Token，登录仍走 authn 与 session。
//   - 邮箱可选。没有邮件能力的部署可以正常完成密码注册（RequireEmailVerification
//     为 false 时）；提供邮箱且邮件能力可用时发送一次性验证入口。验证成功前
//     user_emails.verified_at_ms 保持 NULL，因此邮箱登录/找回等能力不会启用，
//     公开响应也不会宣称邮箱已验证。
//   - 验证凭证使用 internal/credential 的高熵令牌（用途 email.verify、目标为用户
//     ID），只能消费一次；待验证地址与凭证 ID 由迁移 0013 的
//     email_verification_tickets 绑定。重新发送或替换待验证地址会覆盖该行，
//     旧链接随旧凭证撤销而失效。完成验证时在审计事务内条件更新 user_emails，
//     地址已被替换、删除或不是同一行时整体拒绝，不留下部分修改。
//   - 默认角色只能来自宿主配置的可信策略（Options.DefaultRoles），由存储层按
//     “角色存在、已启用、作用域匹配”校验后写入 user_roles；绝不自动加入任何
//     应用成员或应用角色。
//   - 是否需人工审核由 Options.RequireReview 决定：需要审核时用户以 pending
//     状态创建，internal/authn 对非 active 账户拒绝正常登录（审核执行留给后续
//     步骤）；公开响应统一使用“注册冲突”错误避免枚举用户名/邮箱占用。
//   - 审计失败 fail-closed：创建、验证入口签发、邮箱验证完成都与审计同事务提交；
//     邮件发送失败不回滚账户或已签发的验证状态，只通过结果状态与重发处理。
//   - 本包不启动后台协程、不注册 HTTP 路由、不装配到 cmd/login-server。
package registration
