package transport

import "net/http"

// 本文件登记账户入口页面（登录/注册/邀请接受/邮箱验证/退出/落地页）的操作契约。
// 页面是 ui.v1 命名路由，路径相对站内前缀；方法/路径与 ui/pages_auth.go 中的
// UIRoute 字面量一致，改动路由必须同步本文件。

// pageAuthOperations 是 auth.* 账户入口页面契约。
var pageAuthOperations = map[string]PageOperation{
	"auth.login": {
		Method: http.MethodGet, Path: "/login",
		Summary:     "登录页（密码与可选 Passkey 入口）",
		Description: "渲染登录表单；已完整登录的普通会话直接重定向到落地页，受限/待第二因素会话仍只渲染登录入口，不授予业务访问。",
		Module:      "auth",
		Query: []PageField{
			pageQuery(pageText("return", false, 512, "登录成功后的站内相对路径白名单；非法值回落到默认落地页，不接受外部 URL。")),
		},
		StateTransitions: []string{
			"匿名或未完整认证 → 渲染登录表单",
			"已登录普通完整会话 → 303 跳转默认落地页或安全 return 路径",
			"受限/待第二因素会话 → 仍渲染登录入口，不当作已登录",
		},
		Notes: []string{
			"登录失败与账户不存在使用统一文案，不枚举账户。",
			"页面不解析 Cookie 身份；会话由服务端页面会话服务重新校验。",
		},
	},
	"auth.login.submit": {
		Method: http.MethodPost, Path: "/login",
		Summary:     "密码登录提交",
		Description: "提交密码登录。服务端按真实结果分支：只有完整且非受限会话才签发正常会话 Cookie 并跳转业务落地页；需要第二因素时跳转确认页；失败使用统一文案。",
		Module:      "auth", CSRF: pageCSRFAnonymous,
		Fields: []PageField{
			pageText("identifier", true, 256, "用户名或邮箱标识；服务端不区分“不存在/密码错误”的提示。"),
			pageSecret("password", true, 4096, "当前密码；只写，不回声、不写日志。"),
			pageBoolean("remember_me", false, "记住登录（延长会话期限，仍受宿主 Cookie 策略与安全版本约束）。"),
			pageText("return", false, 512, "登录成功后的站内相对路径白名单；非法值回落到默认落地页。"),
		},
		StateTransitions: []string{
			"匿名 → 完整会话：303 跳转 return/默认落地页并下发会话 Cookie",
			"匿名 → 需要第二因素：303 跳转 /login/second-factor 并下发受限会话与签名状态 Cookie",
			"匿名 → 密码/账户失败：400 统一文案，不下发会话",
			"匿名 → 失败预算/限流：429（Retry-After）",
			"受限恢复会话 → 不能凭本操作升级为完整会话",
		},
		Notes: []string{
			"第二因素挑战未完成前不签发完整会话，不跳转业务页。",
			"登录成功与失败都写安全审计；审计不可用时不放行。",
		},
	},
	"auth.passkey_login": {
		Method: http.MethodGet, Path: "/login/passkey",
		Summary:     "Passkey 无密码登录页",
		Description: "渲染 Passkey 登录入口并请求 WebAuthn 断言选项；实际的 RP ID、origin、challenge、签名与用户验证全部由服务端校验。",
		Module:      "auth",
		StateTransitions: []string{
			"匿名 → 渲染 Passkey 登录页并开始断言挑战",
			"passkey.enabled=false → 403 或页面明示不可用，不伪造可登录状态",
		},
		Notes:          []string{"浏览器只能提交断言结果，不能自报登录成功；未启用 Passkey 时入口不可用。"},
		ExtraResponses: []string{"403"},
	},
	"auth.passkey_login.finish": {
		Method: http.MethodPost, Path: "/login/passkey/finish",
		Summary:     "Passkey 无密码登录断言提交",
		Description: "提交 WebAuthn 断言结果，服务端完成 RP ID/origin/挑战/签名/用户验证后签发真实会话；未通过的断言不产生登录。",
		Module:      "auth", CSRF: pageCSRFAnonymous,
		Fields: []PageField{
			pageText("passkey_ceremony_id", true, 128, "服务端签发的一次性 WebAuthn 挑战编号。"),
			pageSecret("passkey_response", true, 24*1024, "WebAuthn 断言 JSON（只写；示例为合成值，不是可用凭证）。"),
		},
		StateTransitions: []string{
			"匿名 → 断言通过且已绑定用户：303 跳转落地页并下发完整会话",
			"匿名 → 断言失败/挑战过期：400，不签发会话",
		},
		Notes: []string{"同步凭证计数器遵循标准语义，不把零计数直接当克隆。"},
	},
	"auth.register": {
		Method: http.MethodGet, Path: "/register",
		Summary:     "自主注册页",
		Description: "渲染注册表单；registration.enabled=false 时注册关闭，本页与提交均拒绝，不伪造成功。",
		Module:      "auth",
		StateTransitions: []string{
			"匿名 → 渲染注册表单（字段按注册策略显示必填项）",
			"registration.enabled=false → 403，注册不可用",
		},
		Notes:          []string{"注册开关与邮箱验证策略来自服务端注册策略快照，不信任前端。"},
		ExtraResponses: []string{"403"},
	},
	"auth.register.submit": {
		Method: http.MethodPost, Path: "/register",
		Summary:     "自主注册提交",
		Description: "提交注册表单。成功后账号进入真实状态（待邮箱验证/待审核/可用），页面显示服务端结果；不自动登录，也不回显密码。",
		Module:      "auth", CSRF: pageCSRFAnonymous,
		Fields: []PageField{
			pageText("username", true, 256, "新用户名；全局唯一、大小写不敏感，按既有 Unicode 规范化校验。"),
			pageSecret("password", true, 4096, "新密码；只写，按密码策略与历史校验，不回显。"),
			pageSecret("password_confirm", true, 4096, "再次输入的新密码；两次不一致返回 400。"),
			pageText("email", false, 320, "可选邮箱；要求邮箱验证时必填。"),
			pageText("nickname", false, 256, "可选昵称，属于用户文本，不拼接 HTML。"),
			pageText("language", false, 64, "可选界面语言。"),
			pageText("timezone", false, 64, "可选时区。"),
		},
		StateTransitions: []string{
			"匿名 → 注册成功：200 页面展示状态（待邮箱验证/待审核/已可用）；不自动签发会话",
			"匿名 → 字段不合法/密码不一致：400",
			"匿名 → 注册关闭或不在允许范围：403",
			"匿名 → 限流：429",
		},
		Notes: []string{
			"验证/审核邮件发送失败不回滚已成立账号，但如实提示失败；发送入队不等于投递成功。",
			"响应不回显密码、哈希、验证链接或令牌。",
		},
	},
	"auth.registration_status": {
		Method: http.MethodGet, Path: "/register/status",
		Summary:          "注册状态页",
		Description:      "渲染注册审核/邮箱验证状态说明页；不枚举他人账户，也不把未验证状态表述为可用。",
		Module:           "auth",
		StateTransitions: []string{"匿名 → 渲染状态说明页（无敏感账户枚举）"},
	},
	"auth.invitation_accept": {
		Method: http.MethodGet, Path: "/invitation/accept",
		Summary:     "接受邀请页",
		Description: "使用邀请链接参数渲染接受邀请表单；GET 不消费邀请票据。无效/过期/不属于当前用户的票据统一提示，不区分具体原因。",
		Module:      "auth",
		Query: []PageField{
			pageQuery(pageText("iid", true, 128, "邀请编号。")),
			pageQuery(pageText("cid", true, 128, "邀请凭证编号。")),
			pageQuery(pageSecret("token", true, 512, "一次性邀请令牌（只写，示例为合成值）。")),
		},
		StateTransitions: []string{
			"匿名 → 渲染接受邀请表单（不消费票据）",
			"票据无效/过期/不匹配 → 400 统一文案",
		},
		Notes: []string{"邀请票据只出现在链接与隐藏字段，不进入日志或正文。"},
	},
	"auth.invitation_accept.submit": {
		Method: http.MethodPost, Path: "/invitation/accept",
		Summary:     "接受邀请提交",
		Description: "消费邀请票据。未登录时按邀请创建普通用户并接受邀请；已登录会话只接受邀请，不切换或提权为其他身份；不授予 root 或系统资格。",
		Module:      "auth", CSRF: pageCSRFAnonymous,
		Fields: []PageField{
			pageText("iid", true, 128, "邀请编号。"),
			pageText("cid", true, 128, "邀请凭证编号。"),
			pageSecret("token", true, 512, "一次性邀请令牌（只写）。"),
			pageText("username", false, 256, "未登录创建新用户时的用户名；已登录时忽略。"),
			pageSecret("password", false, 4096, "未登录创建新用户时的密码；已登录时忽略。"),
			pageSecret("password_confirm", false, 4096, "新密码确认；与 password 不一致返回 400。"),
			pageText("nickname", false, 256, "可选昵称。"),
			pageText("language", false, 64, "可选界面语言。"),
			pageText("timezone", false, 64, "可选时区。"),
		},
		StateTransitions: []string{
			"匿名 + 有效票据 → 创建普通用户并接受邀请：200 展示应用/角色结果，不自动授予系统资格",
			"已登录 + 有效票据 → 接受邀请：200，不切换身份",
			"票据无效/已用/过期 → 400 统一文案",
		},
		Notes: []string{"票单次消费与用户创建、成员关系、审计保持一致提交边界。"},
	},
	"auth.email_verify": {
		Method: http.MethodGet, Path: "/email/verify",
		Summary:     "邮箱验证入口",
		Description: "渲染邮箱验证确认页；GET 只校验参数形状、不消费验证令牌，避免邮件网关预取提前消费。",
		Module:      "auth",
		Query: []PageField{
			pageQuery(pageText("uid", true, 64, "目标用户编号。")),
			pageQuery(pageText("cid", true, 128, "验证凭证编号。")),
			pageQuery(pageSecret("token", true, 512, "一次性验证令牌（只写，示例为合成值）。")),
		},
		StateTransitions: []string{
			"验证链接参数完整 → 渲染确认页（不消费令牌）",
			"参数缺失/形状非法 → 400，不区分“不存在/已用”",
		},
		Notes: []string{"验证令牌不进入日志、正文或 URL 回显。"},
	},
	"auth.email_verify.submit": {
		Method: http.MethodPost, Path: "/email/verify",
		Summary:     "邮箱验证提交",
		Description: "消费一次性邮箱验证令牌并标记邮箱已验证；重复提交或无效令牌返回统一失败，不自动登录。",
		Module:      "auth", CSRF: pageCSRFAnonymous,
		Fields: []PageField{
			pageText("uid", true, 64, "目标用户编号。"),
			pageText("cid", true, 128, "验证凭证编号。"),
			pageSecret("token", true, 512, "一次性验证令牌（只写）。"),
		},
		StateTransitions: []string{
			"有效令牌 → 邮箱标记为已验证：200，不签发会话",
			"令牌无效/过期/已用 → 400 统一文案",
		},
	},
	"auth.email_verify_resend": {
		Method: http.MethodPost, Path: "/email/verify/resend",
		Summary:     "重发邮箱验证",
		Description: "对外统一“已受理”，不区分成功、冷却中、绑定失败或用户不存在，避免账户与票据状态探测；真实发送结果只写受限运行日志。",
		Module:      "auth", CSRF: pageCSRFAnonymous,
		StateTransitions: []string{
			"匿名 → 统一受理：200 页面提示已受理，不透露账户是否存在",
			"冷却期内重复请求 → 同样统一受理（服务端按冷却策略处理）",
			"限流 → 429",
		},
		Notes: []string{"发送入队/受理不等于收件人最终送达。"},
	},
	"auth.logout": {
		Method: http.MethodPost, Path: "/logout",
		Summary:     "退出登录",
		Description: "仅接受 POST；销毁当前会话并清除会话 Cookie，随后 303 跳转登录页。无会话时同样清理本地 Cookie，不报成功假象。",
		Module:      "auth", CSRF: pageCSRFSession,
		StateTransitions: []string{
			"已登录 → 服务端撤销当前会话：303 跳转登录页并清除 Cookie",
			"无有效会话 → 清理 Cookie 后同样跳转登录页",
		},
		Notes: []string{"GET 不被当作退出动作，避免预取/链接触发会话销毁。"},
	},
	"auth.landing": {
		Method: http.MethodGet, Path: "/home",
		Summary:     "登录落地页",
		Description: "渲染登录后的落地页；只消费服务端会话摘要（用户/应用），不缓存权限、不把导航可见性当授权。",
		Module:      "auth",
		StateTransitions: []string{
			"完整会话 → 200 渲染落地页",
			"无会话/会话过期 → 401 受限提示页",
			"受限恢复会话 → 401 或受限提示，不展示业务页",
		},
	},
}
