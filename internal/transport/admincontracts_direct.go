package transport

// 本文件登记步骤 269 第二段：直接改名（258）与直接重置密码（259）共 12 条管理
// JSON API 路由契约。它们与前三类"密码路径"明确区分：
//   - 本人改名/本人改密：目标必须是操作者自己，走本人接口与当前密码/再认证；
//   - ManualRecovery 人工恢复：独立审批流程，客服不读取/自设用户秘密；
//   - 本文件直接管理：操作者持独立权限（users.username.change.other /
//     users.password.reset.other），对受管理范围内的**其他非 root 用户**直接执行，
//     需要操作者本次操作绑定的一次性两步验证证明，不需要目标当前密码/确认/审批。
//
// 两类操作共享"发起挑战 → 确认第二步 → 取得一次性证明 → 提交"状态转移：
//   - 证明绑定操作者会话/操作/目标/本次意图，短期有效，提交即消费；
//   - 不把低熵口令或证明摘要回传/写审计；响应只返回脱敏事实；
//   - 请求体不得携带操作者身份字段（仅来自可信管理会话 caller）；
//   - root 拥有这两项已实现权限，但仍须管理会话 + 本次两步验证 + 审计；
//     非 root 操作者不能以 root 为目标，也不能越权管理范围。

// adminDirectOperations 是直接改名/直接重置密码域契约。
var adminDirectOperations = map[string]AdminOperation{
	// ===== 258 直接修改他人用户名 =====
	"POST users/{user_id}/username-verification": {
		Method: "POST", Pattern: "users/{user_id}/username-verification", Domain: "direct",
		Summary:     "发起直接改名的一次性两步验证挑战",
		Description: "为目标用户改名发起操作者本次操作绑定的两步验证挑战（users.username.change.other + 管理强认证 + 确认 + 审计）；挑战密封「新用户名」意图，响应不回显意图。",
		Permissions: []string{"users.username.change.other"},
		Sensitive:   true,
		Confirm:     true,
		Path:        []AdminParam{adminParam("user_id", "目标用户稳定 ID（不得为 root，须在可管理范围内）。")},
		Body: []AdminField{
			adminConfirmField(),
			adminBody("new_username", "string", "拟设置的新用户名（仅用于密封挑战意图；唯一性/保留名/规范化在最终提交时复核）。"),
			adminRequestIDField(),
		},
		Success: "AdminDirectProofChallenge",
		Notes: []string{
			"请求体不得包含 operator_id/operator_user_id/user_id/operator 等操作者字段（400，防冒充）。",
			"挑战短期有效、有尝试次数上限；不能跨目标/跨操作/跨新用户名复用。",
			"挑战本身不产生改名效果，只是两步验证第一步。",
		},
	},
	"POST users/{user_id}/username-verification/confirm": {
		Method: "POST", Pattern: "users/{user_id}/username-verification/confirm", Domain: "direct",
		Summary:     "直接改名两步验证（密码 + TOTP）",
		Description: "用操作者密码 + TOTP（或账户强认证策略允许的组合）确认挑战，成功后返回一次性操作证明；不返回口令/验证码。",
		Permissions: []string{"users.username.change.other"},
		Sensitive:   true,
		Confirm:     true,
		Path:        []AdminParam{adminParam("user_id", "目标用户稳定 ID。")},
		Body: []AdminField{
			adminConfirmField(),
			adminBody("challenge_id", "string", "发起挑战返回的编号。"),
			adminBodySecret("password", "操作者当前密码（第一步因素；只写，不回声、不写日志）。", 1024),
			AdminField{Name: "totp_code", Type: "string", Description: "操作者 TOTP 验证码（无密码 Passkey 账户可改用 WebAuthn 第二步；只写）。", Secret: true, MaxLength: 16},
			adminRequestIDField(),
		},
		Success: "AdminDirectProofGrant",
		Notes: []string{
			"证明只返回一次，绑定操作者会话/操作/目标/新用户名意图；不得写入日志或长期保存。",
			"失败/过期挑战由领域服务拒绝，不自动降级为只密码或免验证。",
		},
	},
	"POST users/{user_id}/username-verification/webauthn/begin": {
		Method: "POST", Pattern: "users/{user_id}/username-verification/webauthn/begin", Domain: "direct",
		Summary:     "直接改名第二步改用 Passkey/安全密钥（开始）",
		Description: "为挑战生成 WebAuthn 断言选项（RP ID/origin/挑战由服务端生成），绑定当前操作者与本次意图。",
		Permissions: []string{"users.username.change.other"},
		Sensitive:   true,
		Confirm:     true,
		Path:        []AdminParam{adminParam("user_id", "目标用户稳定 ID。")},
		Body: []AdminField{
			adminConfirmField(),
			adminBody("challenge_id", "string", "发起挑战返回的编号。"),
			adminRequestIDField(),
		},
		Success: "AdminDirectWebAuthnStart",
	},
	"POST users/{user_id}/username-verification/webauthn/confirm": {
		Method: "POST", Pattern: "users/{user_id}/username-verification/webauthn/confirm", Domain: "direct",
		Summary:     "直接改名第二步改用 Passkey/安全密钥（完成）",
		Description: "提交 WebAuthn 断言（base64）完成第二步；服务端校验 RP ID/origin/挑战/签名/用户验证后返回一次性操作证明。",
		Permissions: []string{"users.username.change.other"},
		Sensitive:   true,
		Confirm:     true,
		Path:        []AdminParam{adminParam("user_id", "目标用户稳定 ID。")},
		Body: []AdminField{
			adminConfirmField(),
			adminBody("challenge_id", "string", "发起挑战返回的编号。"),
			adminBody("ceremony_id", "string", "WebAuthn 仪式编号（服务端签发）。"),
			adminBodySecret("response_b64", "WebAuthn 断言 base64（只写，示例为合成值）。", 24*1024),
			adminRequestIDField(),
		},
		Success: "AdminDirectProofGrant",
	},
	"POST users/{user_id}/username-verification/cancel": {
		Method: "POST", Pattern: "users/{user_id}/username-verification/cancel", Domain: "direct",
		Summary:     "取消直接改名挑战",
		Description: "取消未完成的两步验证挑战（确认 + 审计）；取消不产生任何改名效果与授权。",
		Permissions: []string{"users.username.change.other"},
		Sensitive:   true,
		Confirm:     true,
		Path:        []AdminParam{adminParam("user_id", "目标用户稳定 ID。")},
		Body: []AdminField{
			adminConfirmField(),
			adminBody("challenge_id", "string", "待取消的挑战编号。"),
			adminRequestIDField(),
		},
		Success: "AdminDirectCancelResult",
	},
	"POST users/{user_id}/username": {
		Method: "POST", Pattern: "users/{user_id}/username", Domain: "direct",
		Summary:     "提交直接改名（消费一次性证明）",
		Description: "用一次性两步验证证明直接修改目标用户用户名（users.username.change.other + 确认 + 行版本 + 原因 + 审计）；证明、操作者、目标与本次新用户名必须一致，提交即消费。",
		Permissions: []string{"users.username.change.other"},
		Sensitive:   true,
		Confirm:     true,
		Reason:      true,
		Path:        []AdminParam{adminParam("user_id", "目标用户稳定 ID。")},
		Body: []AdminField{
			adminConfirmField(),
			adminBody("new_username", "string", "新用户名（最终提交时复核唯一性/保留名/Unicode 与大小写规范化）。"),
			adminBody("expected_row_version", "integer", "期望行版本；并发/版本冲突返回 409。"),
			adminBody("reason", "string", "操作原因（进入真实审计；不包含口令或证明）。"),
			adminBodySecret("proof_token", "一次性操作证明（只写；提交即消费）。", 512),
			adminRequestIDField(),
		},
		Success: "AdminDirectUsernameChangeResult",
		Notes: []string{
			"目标用户 ID、角色与历史关联不变；不能以 root 为目标，不能越过可管理范围。",
			"证明失效/换目标/换新用户名/换操作者一律拒绝；成功只返回脱敏结果，不回显证明或旧资料。",
			"root 执行同样需要本次两步验证与审计；全权限不等于免验证。",
		},
	},

	// ===== 259 直接重置他人密码 =====
	"POST users/{user_id}/password-verification": {
		Method: "POST", Pattern: "users/{user_id}/password-verification", Domain: "direct",
		Summary:     "发起直接重置密码的一次性两步验证挑战",
		Description: "为目标用户重置密码发起操作者本次操作绑定的两步验证挑战（users.password.reset.other + 管理强认证 + 确认 + 审计）；新口令仅用于服务端密封意图，不在响应/日志出现。",
		Permissions: []string{"users.password.reset.other"},
		Sensitive:   true,
		Confirm:     true,
		Path:        []AdminParam{adminParam("user_id", "目标用户稳定 ID（不得为 root，须在可管理范围内）。")},
		Body: []AdminField{
			adminConfirmField(),
			adminBodySecret("new_password", "拟设置的新口令（只用于密封挑战意图；提交时以最终请求为准复核策略/历史）。", 1024),
			adminRequestIDField(),
		},
		Success: "AdminDirectProofChallenge",
		Notes: []string{
			"请求体不得包含操作者字段；挑战绑定操作者/目标/本次新口令意图，短期有效、有尝试次数上限。",
			"挑战不改变密码；无密码 Passkey 账户不会被本接口悄悄加密码（由领域策略拒绝）。",
		},
	},
	"POST users/{user_id}/password-verification/confirm": {
		Method: "POST", Pattern: "users/{user_id}/password-verification/confirm", Domain: "direct",
		Summary:     "直接重置密码两步验证（密码 + TOTP）",
		Description: "用操作者密码 + TOTP（或强认证策略允许的组合）确认挑战，成功后返回一次性操作证明。",
		Permissions: []string{"users.password.reset.other"},
		Sensitive:   true,
		Confirm:     true,
		Path:        []AdminParam{adminParam("user_id", "目标用户稳定 ID。")},
		Body: []AdminField{
			adminConfirmField(),
			adminBody("challenge_id", "string", "发起挑战返回的编号。"),
			adminBodySecret("password", "操作者当前密码（第一步因素；只写）。", 1024),
			AdminField{Name: "totp_code", Type: "string", Description: "操作者 TOTP 验证码（无密码 Passkey 账户可改用 WebAuthn 第二步；只写）。", Secret: true, MaxLength: 16},
			adminRequestIDField(),
		},
		Success: "AdminDirectProofGrant",
	},
	"POST users/{user_id}/password-verification/webauthn/begin": {
		Method: "POST", Pattern: "users/{user_id}/password-verification/webauthn/begin", Domain: "direct",
		Summary:     "直接重置密码第二步改用 Passkey/安全密钥（开始）",
		Description: "为挑战生成 WebAuthn 断言选项，绑定当前操作者与本次重置意图。",
		Permissions: []string{"users.password.reset.other"},
		Sensitive:   true,
		Confirm:     true,
		Path:        []AdminParam{adminParam("user_id", "目标用户稳定 ID。")},
		Body: []AdminField{
			adminConfirmField(),
			adminBody("challenge_id", "string", "发起挑战返回的编号。"),
			adminRequestIDField(),
		},
		Success: "AdminDirectWebAuthnStart",
	},
	"POST users/{user_id}/password-verification/webauthn/confirm": {
		Method: "POST", Pattern: "users/{user_id}/password-verification/webauthn/confirm", Domain: "direct",
		Summary:     "直接重置密码第二步改用 Passkey/安全密钥（完成）",
		Description: "提交 WebAuthn 断言（base64）完成第二步；服务端校验通过后返回一次性操作证明。",
		Permissions: []string{"users.password.reset.other"},
		Sensitive:   true,
		Confirm:     true,
		Path:        []AdminParam{adminParam("user_id", "目标用户稳定 ID。")},
		Body: []AdminField{
			adminConfirmField(),
			adminBody("challenge_id", "string", "发起挑战返回的编号。"),
			adminBody("ceremony_id", "string", "WebAuthn 仪式编号（服务端签发）。"),
			adminBodySecret("response_b64", "WebAuthn 断言 base64（只写，示例为合成值）。", 24*1024),
			adminRequestIDField(),
		},
		Success: "AdminDirectProofGrant",
	},
	"POST users/{user_id}/password-verification/cancel": {
		Method: "POST", Pattern: "users/{user_id}/password-verification/cancel", Domain: "direct",
		Summary:     "取消直接重置密码挑战",
		Description: "取消未完成的两步验证挑战（确认 + 审计）；取消不改变密码、不产生授权。",
		Permissions: []string{"users.password.reset.other"},
		Sensitive:   true,
		Confirm:     true,
		Path:        []AdminParam{adminParam("user_id", "目标用户稳定 ID。")},
		Body: []AdminField{
			adminConfirmField(),
			adminBody("challenge_id", "string", "待取消的挑战编号。"),
			adminRequestIDField(),
		},
		Success: "AdminDirectCancelResult",
	},
	"POST users/{user_id}/password": {
		Method: "POST", Pattern: "users/{user_id}/password", Domain: "direct",
		Summary:     "提交直接重置密码（消费一次性证明）",
		Description: "用一次性两步验证证明直接为目标用户设置新口令（users.password.reset.other + 确认 + 原因 + 审计）；成功只返回脱敏结果，默认要求目标下次登录改密，并使目标旧会话/刷新凭证与旧找回授权失效。",
		Permissions: []string{"users.password.reset.other"},
		Sensitive:   true,
		Confirm:     true,
		Reason:      true,
		Path:        []AdminParam{adminParam("user_id", "目标用户稳定 ID。")},
		Body: []AdminField{
			adminConfirmField(),
			adminBodySecret("new_password", "目标新口令（只写；按密码策略/历史校验，应用哈希后落库，不回显）。", 1024),
			adminReasonField(),
			adminBodySecret("proof_token", "一次性操作证明（只写；提交即消费，绑定操作/目标/意图）。", 512),
			adminRequestIDField(),
		},
		Success: "AdminDirectPasswordResetResult",
		Notes: []string{
			"不返回旧/新口令、哈希、种子或证明；成功结果含 must_change（默认 true）、会话撤销数、旧找回请求/凭证失效数与审计 outbox 事件编号。",
			"不自动清除目标 MFA；不处理 root；不能为无密码账户未经独立授权悄悄添加密码。",
			"root 执行同样需要本次两步验证与审计；应用内权限不等于全局权限（需要系统级独立权限键）。",
		},
	},
}

// 注册到全局契约表。
func init() {
	adminOperationGroups["direct"] = adminDirectOperations
}
