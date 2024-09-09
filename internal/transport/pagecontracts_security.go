package transport

import "net/http"

// 本文件登记安全中心/会话/已授权应用页面契约（ui/pages_security.go 与
// ui/pages_security_handlers.go）。这些页面要求普通完整会话，敏感写操作还要求
// 本次操作绑定的再次认证（当前密码/TOTP/Passkey），页面按钮存在不等于授权。

// pageSecurityOperations 是 account.* 安全中心页面契约。
var pageSecurityOperations = map[string]PageOperation{
	"account.security": {
		Method: http.MethodGet, Path: "/account/security",
		Summary:          "安全中心总览",
		Description:      "渲染安全中心总览（MFA/Passkey/TOTP/恢复代码/会话/已授权应用的入口与真实状态摘要）。",
		Module:           "security",
		StateTransitions: []string{"完整会话 → 200 渲染安全概览", "无会话/会话过期 → 401"},
	},
	"account.security_mfa": {
		Method: http.MethodGet, Path: "/account/security/mfa",
		Summary:          "邮件第二因素页",
		Description:      "渲染邮件第二因素的绑定状态与操作入口；是否可作为强认证因素由服务端策略决定，页面不自行判断。",
		Module:           "security",
		StateTransitions: []string{"完整会话 → 200 渲染因素状态"},
	},
	"account.security_mfa.add_start": {
		Method: http.MethodPost, Path: "/account/security/mfa",
		Summary:     "开始绑定邮件第二因素",
		Description: "开始邮件第二因素绑定：由服务端生成挑战并以真实渠道发送验证码；本操作不改变已生效因素。",
		Module:      "security", CSRF: pageCSRFSession,
		StateTransitions: []string{"完整会话 → 生成挑战：200（发送失败如实提示，不伪造已绑定）"},
	},
	"account.security_mfa.add_confirm": {
		Method: http.MethodPost, Path: "/account/security/mfa/confirm",
		Summary:     "确认绑定邮件第二因素",
		Description: "提交挑战编号、尝试令牌与验证码完成绑定；必须真实验证，失败不改变现有因素。",
		Module:      "security", CSRF: pageCSRFSession,
		Fields: []PageField{
			pageText("challenge_id", true, 128, "服务端签发的因素绑定挑战编号。"),
			pageSecret("attempt_token", true, 128, "挑战绑定的尝试令牌（只写）。"),
			pageSecret("code", true, 64, "邮件验证码；只写，不回显。"),
		},
		StateTransitions: []string{
			"完整会话 + 挑战有效 + 验证码正确 → 绑定成功：200",
			"验证码错误/过期 → 400，不绑定",
		},
	},
	"account.security_mfa.remove": {
		Method: http.MethodPost, Path: "/account/security/mfa/remove",
		Summary:     "解除邮件第二因素",
		Description: "以当前密码复核后解除邮件第二因素；删除最后一个因素必须符合服务端强认证策略，否则拒绝。",
		Module:      "security", CSRF: pageCSRFSession,
		Fields: []PageField{
			pageSecret("current_password", true, 1024, "当前密码，用于本人敏感操作复核；只写。"),
		},
		StateTransitions: []string{
			"完整会话 + 密码正确且策略允许 → 解除成功：200",
			"密码错误 → 400/403；策略禁止删除最后因素 → 403",
		},
	},
	"account.security_totp": {
		Method: http.MethodGet, Path: "/account/security/totp",
		Summary:          "TOTP 因素页",
		Description:      "渲染 TOTP 绑定状态与绑定/解除入口；TOTP 被明确定位为不抗钓鱼因素，强认证策略以服务端为准。",
		Module:           "security",
		StateTransitions: []string{"完整会话 → 200 渲染 TOTP 状态"},
	},
	"account.security_totp.bind_start": {
		Method: http.MethodPost, Path: "/account/security/totp/bind",
		Summary:     "开始绑定 TOTP",
		Description: "以当前密码复核后生成 TOTP 绑定材料（种子只出现一次，不写日志/审计）。",
		Module:      "security", CSRF: pageCSRFSession,
		Fields: []PageField{
			pageSecret("current_password", true, 1024, "当前密码，用于本人敏感操作复核；只写。"),
		},
		StateTransitions: []string{"完整会话 + 密码正确 → 生成绑定材料：200"},
	},
	"account.security_totp.bind_confirm": {
		Method: http.MethodPost, Path: "/account/security/totp/confirm",
		Summary:     "确认绑定 TOTP",
		Description: "提交绑定编号与 TOTP 验证码完成绑定；验证必须真实成功。",
		Module:      "security", CSRF: pageCSRFSession,
		Fields: []PageField{
			pageText("binding_id", true, 128, "TOTP 绑定编号。"),
			pageSecret("code", true, 16, "TOTP 验证码；只写。"),
		},
		StateTransitions: []string{
			"完整会话 + 验证码正确 → 绑定成功：200",
			"验证码错误/过期 → 400，不绑定",
		},
	},
	"account.security_totp.remove": {
		Method: http.MethodPost, Path: "/account/security/totp/remove",
		Summary:     "解除 TOTP",
		Description: "以当前密码 + 当前 TOTP 验证码复核后解除 TOTP；删除最后一个因素按策略可能被拒绝。",
		Module:      "security", CSRF: pageCSRFSession,
		Fields: []PageField{
			pageSecret("code", true, 16, "当前 TOTP 验证码；只写。"),
			pageSecret("current_password", true, 1024, "当前密码；只写。"),
		},
		StateTransitions: []string{
			"复核通过且策略允许 → 解除成功：200",
			"验证码/密码错误 → 400/403；策略禁止 → 403",
		},
	},
	"account.security_passkeys": {
		Method: http.MethodGet, Path: "/account/security/passkeys",
		Summary:          "Passkey 凭据页",
		Description:      "渲染当前用户 Passkey 凭据列表与注册/重命名/撤销入口；列表只含公开凭据元数据，不含私钥。",
		Module:           "security",
		StateTransitions: []string{"完整会话 → 200 渲染凭据列表", "passkey.enabled=false → 页面说明不可用"},
	},
	"account.security_passkeys.register_start": {
		Method: http.MethodPost, Path: "/account/security/passkeys/register",
		Summary:     "开始注册 Passkey",
		Description: "生成 WebAuthn 注册挑战（RP ID/origin/挑战均服务端生成），挑战绑定当前会话与用途。",
		Module:      "security", CSRF: pageCSRFSession,
		StateTransitions: []string{"完整会话 → 生成注册挑战：200"},
	},
	"account.security_passkeys.register_finish": {
		Method: http.MethodPost, Path: "/account/security/passkeys/register/finish",
		Summary:     "完成注册 Passkey",
		Description: "提交 WebAuthn 注册结果并真实校验签名/挑战/用户验证；校验失败不生成凭据。",
		Module:      "security", CSRF: pageCSRFSession,
		Fields: []PageField{
			pageText("ceremony_id", true, 128, "服务端签发的 WebAuthn 挑战编号。"),
			pageSecret("passkey_response", true, 24*1024, "WebAuthn 注册结果 JSON（只写，示例为合成值）。"),
			pageText("name", false, 64, "凭据显示名（用户文本，不拼接 HTML）。"),
			pageSecret("current_password", false, 1024, "当前密码（再次认证要求时提供）；只写。"),
		},
		StateTransitions: []string{
			"完整会话 + 注册校验通过 → 凭据创建：200",
			"校验失败/挑战过期 → 400/403，不创建凭据",
		},
	},
	"account.security_passkeys.rename": {
		Method: http.MethodPost, Path: "/account/security/passkeys/rename",
		Summary:     "重命名 Passkey",
		Description: "修改当前用户某个 Passkey 的显示名；只能操作本人凭据，越权返回 403。",
		Module:      "security", CSRF: pageCSRFSession,
		Fields: []PageField{
			pageText("credential_id", true, 128, "本人 Passkey 凭据编号。"),
			pageText("name", false, 64, "新显示名。"),
		},
		StateTransitions: []string{
			"凭据属于本人 → 重命名成功：200",
			"凭据不存在/不属于本人 → 403",
		},
	},
	"account.security_passkeys.revoke": {
		Method: http.MethodPost, Path: "/account/security/passkeys/revoke",
		Summary:     "撤销 Passkey",
		Description: "以当前密码复核后撤销本人某个 Passkey；删除最后一个强因素受策略限制。",
		Module:      "security", CSRF: pageCSRFSession,
		Fields: []PageField{
			pageText("credential_id", true, 128, "本人 Passkey 凭据编号。"),
			pageSecret("current_password", true, 1024, "当前密码；只写。"),
		},
		StateTransitions: []string{
			"复核通过且策略允许 → 撤销成功：200",
			"凭据不属于本人/策略禁止 → 403",
		},
	},
	"account.security_recovery_codes": {
		Method: http.MethodGet, Path: "/account/security/recovery-codes",
		Summary:          "恢复代码库存页",
		Description:      "渲染恢复代码库存摘要（剩余数量/生成时间），不在 GET 中显示可用明文代码。",
		Module:           "security",
		StateTransitions: []string{"完整会话 → 200 渲染库存摘要（不含明文代码）"},
	},
	"account.security_recovery_codes.generate": {
		Method: http.MethodPost, Path: "/account/security/recovery-codes",
		Summary:     "重新生成恢复代码",
		Description: "以当前密码 + TOTP 复核并显式确认后重新生成恢复代码；新代码只在本响应中显示一次，旧代码立即失效。",
		Module:      "security", CSRF: pageCSRFSession,
		Fields: []PageField{
			pageSecret("current_password", true, 1024, "当前密码；只写。"),
			pageSecret("totp_code", true, 16, "当前 TOTP 验证码；只写。"),
			pageEnum("confirm", true, pageConfirmTrue, "显式确认重新生成（使旧恢复代码立即失效）。"),
		},
		StateTransitions: []string{
			"完整会话 + 双因素复核 + 确认 → 生成新代码：200（仅本次显示）",
			"复核失败/未确认 → 400/403，旧代码不变",
		},
		Notes: []string{"恢复代码明文不写日志、审计、报告；页面与响应 no-store。"},
	},
	"account.sessions": {
		Method: http.MethodGet, Path: "/account/sessions",
		Summary:     "当前会话列表",
		Description: "分页渲染当前用户的活跃会话摘要（设备/时间等），并标记当前会话；不显示会话秘密。",
		Module:      "security",
		Query: []PageField{
			pageQuery(pageInteger("page", false, "页码，从 1 开始；非法值返回 400。")),
			pageQuery(pageInteger("page_size", false, "每页条数上限 50；非法值返回 400。")),
		},
		StateTransitions: []string{"完整会话 → 200 分页渲染会话摘要", "非法分页参数 → 400"},
	},
	"account.sessions.revoke": {
		Method: http.MethodPost, Path: "/account/sessions/revoke",
		Summary:     "撤销指定会话",
		Description: "以当前密码复核后撤销本人指定会话；只能撤销本人会话，越权返回 403。",
		Module:      "security", CSRF: pageCSRFSession,
		Fields: []PageField{
			pageText("target_session_id", true, 128, "本人待撤销会话编号。"),
			pageSecret("current_password", true, 1024, "当前密码；只写。"),
		},
		StateTransitions: []string{
			"目标会话属于本人 → 撤销成功：200",
			"目标不存在/不属于本人 → 403",
		},
	},
	"account.sessions.revoke_others": {
		Method: http.MethodPost, Path: "/account/sessions/revoke-others",
		Summary:     "撤销其他会话",
		Description: "以当前密码复核后撤销本人除当前会话外的其他会话；当前会话保留。",
		Module:      "security", CSRF: pageCSRFSession,
		Fields: []PageField{
			pageSecret("current_password", true, 1024, "当前密码；只写。"),
		},
		StateTransitions: []string{
			"完整会话 + 复核通过 → 其他会话撤销：200，当前会话保留",
			"密码错误 → 400/403",
		},
	},
	"account.sessions.revoke_all": {
		Method: http.MethodPost, Path: "/account/sessions/revoke-all",
		Summary:     "撤销全部会话",
		Description: "以当前密码复核后撤销本人全部会话（含当前会话），303 回登录页并要求重新登录。",
		Module:      "security", CSRF: pageCSRFSession,
		Fields: []PageField{
			pageSecret("current_password", true, 1024, "当前密码；只写。"),
		},
		StateTransitions: []string{
			"完整会话 + 复核通过 → 全部会话撤销：303 跳转登录页",
			"密码错误 → 400/403，会话不变",
		},
	},
	"account.grants": {
		Method: http.MethodGet, Path: "/account/grants",
		Summary:     "已授权应用列表",
		Description: "分页渲染当前用户对应用的授权摘要（应用/范围/时间），不显示令牌或客户端秘密。",
		Module:      "security",
		Query: []PageField{
			pageQuery(pageInteger("page", false, "页码，从 1 开始；非法值返回 400。")),
			pageQuery(pageInteger("page_size", false, "每页条数上限 50；非法值返回 400。")),
		},
		StateTransitions: []string{"完整会话 → 200 分页渲染授权摘要", "非法分页参数 → 400"},
	},
	"account.grants.revoke": {
		Method: http.MethodPost, Path: "/account/grants/revoke",
		Summary:     "撤销应用授权",
		Description: "以当前密码复核后撤销本人对指定应用的授权，并撤销相关刷新凭证；只影响本人授权。",
		Module:      "security", CSRF: pageCSRFSession,
		Fields: []PageField{
			pageText("authorization_id", true, 128, "本人授权编号。"),
			pageSecret("current_password", true, 1024, "当前密码；只写。"),
		},
		StateTransitions: []string{
			"授权属于本人 + 复核通过 → 撤销成功：200，相关令牌失效",
			"授权不存在/不属于本人 → 403",
		},
	},
}
