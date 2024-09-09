package transport

import "net/http"

// 本文件登记 MFA 与三种恢复流程的页面操作契约：
//   - 第二因素、强因素初始化（Passkey/TOTP）；
//   - 恢复代码 + 安全因素重绑（受限恢复会话）；
//   - 邮件找回密码（请求 → 一次性令牌 → 重置）。
// 人工恢复（客服审批/执行）在 pagecontracts_support.go。

// pageMFAOperations 是 auth.* 中第二因素与恢复流程页面契约。
var pageMFAOperations = map[string]PageOperation{
	"auth.second_factor": {
		Method: http.MethodGet, Path: "/login/second-factor",
		Summary:     "第二因素确认页",
		Description: "渲染第二因素确认页（TOTP/恢复代码/Passkey 入口之一）。本页只持有受限待验证会话，不是已登录状态。",
		Module:      "mfa",
		StateTransitions: []string{
			"登录后待第二因素 → 渲染确认页（受限会话）",
			"挑战过期/状态 Cookie 无效 → 重定向登录页重新发起",
			"需要先绑定强因素 → 跳转 /login/strong-setup",
		},
		Notes: []string{"阶段二未完成前不授予业务访问；前端不能自报已验证。"},
	},
	"auth.second_factor.verify": {
		Method: http.MethodPost, Path: "/login/second-factor",
		Summary:     "第二因素验证提交",
		Description: "提交 TOTP 验证码或 WebAuthn 断言；验证通过后签发完整会话并跳转落地页。所有挑战绑定用途、目标、来源与期限。",
		Module:      "mfa", CSRF: pageCSRFAnonymous,
		Fields: []PageField{
			pageText("challenge_id", true, 128, "服务端签发的第二因素挑战编号。"),
			pageSecret("attempt_token", true, 128, "挑战绑定的尝试令牌（只写）。"),
			pageSecret("code", false, 64, "TOTP 或恢复代码；与 passkey_response 至少提供一个。"),
			pageText("passkey_ceremony_id", false, 128, "WebAuthn 挑战编号（使用 Passkey 时提供）。"),
			pageSecret("passkey_response", false, 24*1024, "WebAuthn 断言 JSON（只写，示例为合成值）。"),
		},
		StateTransitions: []string{
			"待第二因素 → 验证通过：303 跳转落地页并签发完整会话",
			"待第二因素 → 验证失败：400/403，保持受限状态可重试",
			"挑战过期：400 CHALLENGE_INVALID，需重新登录",
			"恢复代码验证通过 → 仅进入受限恢复流程，不直接恢复完整访问",
		},
		Notes: []string{"恢复代码默认代替第二步，消费后只能走受限恢复与重绑；TOTP 不等同抗钓鱼因素。"},
	},
	"auth.second_factor.resend": {
		Method: http.MethodPost, Path: "/login/second-factor/resend",
		Summary:     "重发第二因素验证码",
		Description: "按后端策略重发邮件验证码；成功时返回 200 并刷新挑战状态，失败保留可诊断的稳定错误码，不把已完成的验证当作成功。",
		Module:      "mfa", CSRF: pageCSRFAnonymous,
		Fields: []PageField{
			pageText("challenge_id", true, 128, "当前第二因素挑战编号。"),
			pageSecret("attempt_token", true, 128, "挑战绑定的尝试令牌（只写）。"),
		},
		StateTransitions: []string{
			"待第二因素 → 重发受理：200 并刷新状态 Cookie",
			"冷却/限流 → 429",
			"挑战无效/过期 → 400 CHALLENGE_INVALID",
		},
	},
	"auth.second_factor.cancel": {
		Method: http.MethodPost, Path: "/login/second-factor/cancel",
		Summary:     "取消第二因素流程",
		Description: "取消当前第二因素挑战并清理受限会话与状态 Cookie，303 返回登录页；取消不等于登录成功。",
		Module:      "mfa", CSRF: pageCSRFAnonymous,
		StateTransitions: []string{"待第二因素 → 取消：303 跳转登录页并清除受限会话/状态 Cookie"},
	},
	"auth.strong_setup": {
		Method: http.MethodGet, Path: "/login/strong-setup",
		Summary:     "强因素初始化页",
		Description: "渲染强认证因素初始化页（Passkey/TOTP）。本页只在待验证/待绑定状态下可用，绑定完成后仍需重新登录。",
		Module:      "mfa",
		StateTransitions: []string{
			"待绑定强因素 → 渲染初始化页",
			"无需绑定（已满足策略）→ 重定向第二因素确认页",
			"无有效受限会话 → 重定向登录页",
		},
	},
	"auth.strong_setup.passkey_start": {
		Method: http.MethodPost, Path: "/login/strong-setup/passkey/start",
		Summary:     "开始绑定 Passkey",
		Description: "使用当前密码复核后生成 WebAuthn 注册挑战；服务端校验 RP ID/origin/挑战/签名，注册完成必须真实验证。",
		Module:      "mfa", CSRF: pageCSRFAnonymous,
		Fields: []PageField{
			pageSecret("current_password", true, 1024, "当前密码，用于本次敏感操作复核；只写。"),
		},
		StateTransitions: []string{"待绑定 → 生成注册挑战：200，不改动已有安全状态"},
	},
	"auth.strong_setup.passkey_finish": {
		Method: http.MethodPost, Path: "/login/strong-setup/passkey/finish",
		Summary:     "完成绑定 Passkey",
		Description: "提交 WebAuthn 注册结果并完成真实校验；成功后仍按策略要求重新登录，不直接恢复完整访问。",
		Module:      "mfa", CSRF: pageCSRFAnonymous,
		Fields: []PageField{
			pageSecret("passkey_response", true, 24*1024, "WebAuthn 注册结果 JSON（只写，示例为合成值）。"),
			pageText("passkey_ceremony_id", false, 128, "注册挑战编号；服务端同时校验签名状态。"),
			pageSecret("current_password", false, 1024, "当前密码（再次复核时提供）；只写。"),
		},
		StateTransitions: []string{
			"待绑定 → 注册校验通过：200，因素绑定成功",
			"校验失败/挑战过期 → 400/403，不绑定，不放宽策略",
		},
	},
	"auth.strong_setup.totp_start": {
		Method: http.MethodPost, Path: "/login/strong-setup/totp/start",
		Summary:     "开始绑定 TOTP",
		Description: "使用当前密码复核后生成 TOTP 绑定材料（种子只返回一次且不进入日志/审计）。",
		Module:      "mfa", CSRF: pageCSRFAnonymous,
		Fields: []PageField{
			pageSecret("current_password", true, 1024, "当前密码，用于本次敏感操作复核；只写。"),
		},
		StateTransitions: []string{"待绑定 → 生成 TOTP 绑定材料：200，不改动已生效因素"},
		Notes:            []string{"TOTP 种子属于秘密，只在绑定流程中出现一次。"},
	},
	"auth.strong_setup.totp_finish": {
		Method: http.MethodPost, Path: "/login/strong-setup/totp/finish",
		Summary:     "完成绑定 TOTP",
		Description: "提交 TOTP 验证码完成绑定；验证失败不清除已有因素，也不放宽强认证策略。",
		Module:      "mfa", CSRF: pageCSRFAnonymous,
		Fields: []PageField{
			pageText("binding_id", true, 128, "TOTP 绑定编号。"),
			pageSecret("code", true, 16, "6 位 TOTP 验证码；只写。"),
			pageSecret("current_password", false, 1024, "当前密码（再次复核时提供）；只写。"),
		},
		StateTransitions: []string{
			"待绑定 → 验证通过：200，TOTP 绑定成功",
			"验证码错误/过期：400，不绑定",
		},
	},
	"auth.recovery_code": {
		Method: http.MethodGet, Path: "/login/recovery-code",
		Summary:          "恢复代码入口",
		Description:      "渲染恢复代码输入页；恢复代码只替代第二因素，不替代密码，也不直接恢复完整访问。",
		Module:           "mfa",
		StateTransitions: []string{"待第二因素 → 渲染恢复代码输入页"},
	},
	"auth.recovery_code.submit": {
		Method: http.MethodPost, Path: "/login/recovery-code",
		Summary:     "提交恢复代码",
		Description: "消费一次性恢复代码并进入受限恢复会话：必须完成新因素绑定并重新登录后才恢复正常访问，不自动清除 MFA。",
		Module:      "mfa", CSRF: pageCSRFAnonymous,
		Fields: []PageField{
			pageSecret("code", true, 256, "一次性恢复代码；只写，不回显。"),
			pageText("challenge_id", false, 128, "当前挑战编号（由签名状态 Cookie 绑定时可不填）。"),
			pageSecret("attempt_token", false, 128, "挑战尝试令牌（兼容字段，只写）。"),
		},
		StateTransitions: []string{
			"待第二因素 + 有效代码 → 303 进入受限恢复（/login/recovery/rebind）",
			"代码无效/已消费/过期 → 400 统一文案",
			"恢复完成后仍要求重新登录才恢复完整访问",
		},
		Notes: []string{"恢复代码消费后仅允许受限恢复；不能凭恢复代码直接得到正常会话。"},
	},
	"auth.recovery_rebind": {
		Method: http.MethodGet, Path: "/login/recovery/rebind",
		Summary:     "恢复因素重绑页",
		Description: "在受限恢复会话中渲染因素重绑页；页面只呈现真实恢复状态，不提供绕过策略的捷径。",
		Module:      "mfa",
		StateTransitions: []string{
			"受限恢复会话 → 渲染重绑页",
			"无受限恢复会话 → 重定向登录页",
		},
	},
	"auth.recovery_rebind.start": {
		Method: http.MethodPost, Path: "/login/recovery/rebind/start",
		Summary:     "开始重绑安全因素",
		Description: "在受限恢复会话内开始绑定新因素；方法由服务端策略校验，不接受前端自报的能力。",
		Module:      "mfa", CSRF: pageCSRFAnonymous,
		Fields: []PageField{
			pageText("method", false, 32, "绑定方式（如 totp/passkey）；空表示由服务端按策略选择。"),
		},
		StateTransitions: []string{"受限恢复会话 → 生成绑定挑战：200"},
	},
	"auth.recovery_rebind.complete": {
		Method: http.MethodPost, Path: "/login/recovery/rebind/complete",
		Summary:     "完成重绑安全因素",
		Description: "提交新因素的真实校验结果；完成后仍按策略要求重新登录，旧恢复授权同时失效。",
		Module:      "mfa", CSRF: pageCSRFAnonymous,
		Fields: []PageField{
			pageText("binding_id", true, 128, "绑定编号。"),
			pageText("method", false, 32, "绑定方式；用于服务端校验绑定类型一致。"),
			pageSecret("response", true, 24*1024, "因素绑定结果（WebAuthn 断言 JSON 等，只写）。"),
		},
		StateTransitions: []string{
			"受限恢复 + 绑定校验通过：200，因素绑定完成",
			"校验失败/过期：400，保持受限状态",
		},
	},
	"auth.recovery_cancel": {
		Method: http.MethodPost, Path: "/login/recovery/cancel",
		Summary:     "取消受限恢复",
		Description: "取消恢复流程并清理受限会话与状态 Cookie，303 返回登录页；不留下半绑定状态。",
		Module:      "mfa", CSRF: pageCSRFAnonymous,
		StateTransitions: []string{"受限恢复会话 → 取消：303 跳转登录页并清除受限 Cookie"},
	},
	"auth.password_forgot": {
		Method: http.MethodGet, Path: "/login/forgot-password",
		Summary:          "找回密码页",
		Description:      "渲染找回密码入口；公开响应防枚举，不透露账户是否存在、是否绑定邮箱或是否有 MFA。",
		Module:           "mfa",
		StateTransitions: []string{"匿名 → 渲染找回密码表单"},
	},
	"auth.password_forgot.submit": {
		Method: http.MethodPost, Path: "/login/forgot-password",
		Summary:     "找回密码提交",
		Description: "受理找回请求并按策略发送一次性找回链接；对外统一提示“已受理”，真实发送结果只写受限日志，不返回重置令牌。",
		Module:      "mfa", CSRF: pageCSRFAnonymous,
		Fields: []PageField{
			pageText("identifier", true, 254, "用户名或邮箱标识；不区分账户是否存在。"),
		},
		StateTransitions: []string{
			"匿名 → 统一受理：200 页面提示已受理",
			"限流/失败预算：429",
		},
		Notes: []string{
			"找回入口绑定用途/账户/安全代际/邮箱身份，短期且单次。",
			"邮件发送失败不把请求伪装成已投递；不向响应写入可用令牌。",
		},
	},
	"auth.password_reset": {
		Method: http.MethodGet, Path: "/login/reset-password",
		Summary:     "重置密码页",
		Description: "校验一次性找回令牌后渲染新密码表单；GET 只校验入口状态，不消费令牌。",
		Module:      "mfa",
		Query: []PageField{
			pageQuery(pageSecret("token", true, 512, "一次性找回令牌（只写，示例为合成值）。")),
		},
		StateTransitions: []string{
			"令牌有效 → 渲染新密码表单（不消费）",
			"令牌缺失/过期/已用 → 400 CHALLENGE_INVALID",
		},
	},
	"auth.password_reset.submit": {
		Method: http.MethodPost, Path: "/login/reset-password",
		Summary:     "重置密码提交",
		Description: "最终提交新密码：重新核对找回授权完整状态后变更密码，并使旧会话/刷新凭证/其他找回授权失效；不清除 MFA、不处理 root。",
		Module:      "mfa", CSRF: pageCSRFAnonymous,
		Fields: []PageField{
			pageSecret("token", true, 512, "一次性找回令牌；只写。"),
			pageSecret("new_password", true, 1024, "新密码；按密码策略与历史校验，只写、不回显。"),
			pageSecret("confirm_password", true, 1024, "新密码确认；不一致返回 400。"),
		},
		StateTransitions: []string{
			"令牌有效 + 新密码合规 → 密码变更：200，旧凭证失效",
			"弱密码/历史复用 → 400 且不消费令牌（可重试），不造成半改密",
			"令牌无效/过期/已用 → 400 CHALLENGE_INVALID",
			"并发提交：只有一个赢家，失败方不会复活已用令牌",
		},
		Notes: []string{"重置不自动清除 MFA，也不为无密码账户偷加密码；root 不走公开找回。"},
	},
}
