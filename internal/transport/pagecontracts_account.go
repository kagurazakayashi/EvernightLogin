package transport

import "net/http"

// 本文件登记个人资料/邮箱/密码与匿名邮箱验证页面契约（ui/pages_account.go）。

// pageAccountOperations 是 account.* 个人资料与凭据页面契约。
var pageAccountOperations = map[string]PageOperation{
	"account.profile": {
		Method: http.MethodGet, Path: "/account/profile",
		Summary:     "个人资料页",
		Description: "渲染当前登录用户的全局资料（昵称、简介、语言、时区、电话）与行版本；资料加载失败如实提示。",
		Module:      "account",
		Query: []PageField{
			pageQuery(pageText("status", false, 32, "一次性状态提示（如 updated）；不参与授权。")),
		},
		StateTransitions: []string{"完整会话 → 200 渲染当前用户资料", "无会话/会话过期 → 401 受限提示页"},
	},
	"account.profile.update": {
		Method: http.MethodPost, Path: "/account/profile",
		Summary:     "更新个人资料",
		Description: "按行版本更新当前用户资料；只修改表单实际提供的字段（缺省字段保持不变），成功后 303 回资料页。",
		Module:      "account", CSRF: pageCSRFSession,
		Fields: []PageField{
			pageText("nickname", false, 256, "昵称（用户文本，不拼接 HTML）；缺省表示不修改。"),
			pageText("biography", false, 1024, "个人简介；缺省表示不修改。"),
			pageText("language", false, 64, "界面语言；缺省表示不修改。"),
			pageText("timezone", false, 64, "时区；缺省表示不修改。"),
			pageText("phone", false, 64, "电话号码；缺省表示不修改。"),
			pageRowVersion(),
		},
		StateTransitions: []string{
			"完整会话 + 版本匹配 → 更新成功：303 /account/profile?status=updated",
			"行版本缺失/过期 → 409 冲突页，要求重新读取",
			"会话过期 → 401；CSRF 失败 → 403",
		},
	},
	"account.profile_username": {
		Method: http.MethodGet, Path: "/account/profile/username",
		Summary:          "受控更名页",
		Description:      "渲染当前用户改名表单与当前行版本；改名会影响登录标识，页面明确提示唯一性与冷却规则。",
		Module:           "account",
		StateTransitions: []string{"完整会话 → 渲染更名表单", "无会话 → 401"},
	},
	"account.profile_username.submit": {
		Method: http.MethodPost, Path: "/account/profile/username",
		Summary:     "提交受控更名",
		Description: "以当前密码复核 + 行版本提交本人改名；执行唯一性、保留名、Unicode/大小写规范化与冷却规则，用户 ID 与历史关联不变。",
		Module:      "account", CSRF: pageCSRFSession,
		Fields: []PageField{
			pageText("new_username", true, 256, "新用户名；全局唯一、大小写不敏感。"),
			pageSecret("current_password", true, 1024, "当前密码，用于本人敏感操作复核；只写。"),
			pageRowVersion(),
		},
		StateTransitions: []string{
			"完整会话 + 校验通过 → 改名成功：200 展示结果",
			"唯一性冲突/保留名/冷却中 → 400 或 409，明确原因",
			"行版本过期 → 409；会话过期 → 401；CSRF 失败 → 403",
		},
		Notes: []string{"本人改名不能绕过 root 保护，也不能用于修改他人用户名。"},
	},
	"account.app_profile": {
		Method: http.MethodGet, Path: "/account/app-profile",
		Summary:     "应用内资料页",
		Description: "渲染当前应用成员资料；应用来自可信会话，不接受请求参数指定其他应用。",
		Module:      "account",
		Query: []PageField{
			pageQuery(pageText("status", false, 32, "一次性状态提示（如 updated）；不参与授权。")),
		},
		StateTransitions: []string{
			"完整会话 + 已选择应用 → 200 渲染应用内资料",
			"完整会话 + 未选择应用 → 200 提示未选择应用，不伪造资料",
		},
	},
	"account.app_profile.submit": {
		Method: http.MethodPost, Path: "/account/app-profile",
		Summary:     "更新应用内资料",
		Description: "按行版本更新当前应用内的显示名/职位/备注；应用与用户均来自可信会话，越权写其他应用返回 403。",
		Module:      "account", CSRF: pageCSRFSession,
		Fields: []PageField{
			pageText("display_name", false, 256, "应用内显示名；缺省表示不修改。"),
			pageText("title", false, 256, "应用内职位/头衔；缺省表示不修改。"),
			pageText("note", false, 1024, "应用内备注；缺省表示不修改。"),
			pageRowVersion(),
		},
		StateTransitions: []string{
			"完整会话 + 应用成员关系有效 → 更新成功：303 /account/app-profile?status=updated",
			"未选择应用 → 200 提示，不写数据",
			"行版本过期 → 409；越权/成员失效 → 403",
		},
	},
	"account.profile_avatar": {
		Method: http.MethodGet, Path: "/account/profile/avatar",
		Summary:     "头像管理页",
		Description: "渲染当前用户头像与上传/移除表单；头像字节由独立受控端点输出，不内联到页面数据。",
		Module:      "account",
		Query: []PageField{
			pageQuery(pageText("status", false, 32, "一次性状态提示（如 uploaded/removed）；不参与授权。")),
		},
		StateTransitions: []string{"完整会话 → 200 渲染头像管理页"},
	},
	"account.profile_avatar.submit": {
		Method: http.MethodPost, Path: "/account/profile/avatar",
		Summary:     "上传头像",
		Description: "以 multipart 表单上传头像并校验媒体类型/大小/行版本；内容按图片重新校验，不把任意字节当作图片对外输出。",
		Module:      "account", CSRF: pageCSRFSession, RequestContentType: "multipart/form-data",
		Fields: []PageField{
			pageFileField("avatar", true, "头像文件（大小与格式受服务端限制，示例为合成文件名）。"),
			pageRowVersion(),
		},
		StateTransitions: []string{
			"完整会话 + 文件/版本有效 → 上传成功：303 /account/profile/avatar?status=uploaded",
			"文件过大/类型不支持 → 400/413/415",
			"行版本过期 → 409",
		},
		Notes: []string{"头像响应不包含原始文件路径；文件读取受服务端存储与权限约束。"},
	},
	"account.profile_avatar.remove": {
		Method: http.MethodPost, Path: "/account/profile/avatar/remove",
		Summary:     "移除头像",
		Description: "按行版本移除当前用户头像，成功后 303 回头像页。",
		Module:      "account", CSRF: pageCSRFSession,
		Fields: []PageField{pageRowVersion()},
		StateTransitions: []string{
			"完整会话 + 版本匹配 → 移除成功：303 /account/profile/avatar?status=removed",
			"行版本过期 → 409",
		},
	},
	"account.profile_avatar_image": {
		Method: http.MethodGet, Path: "/account/profile/avatar/image",
		Summary:     "读取当前用户头像字节",
		Description: "输出当前用户头像图片字节（受控 Content-Type/ETag/缓存头）；只允许本人读取，不暴露文件路径或他人头像。",
		Module:      "account", SuccessContentType: "image/*",
		StateTransitions: []string{
			"完整会话 + 已设置头像 → 200 图片字节",
			"未设置头像 → 404",
			"无会话 → 401",
		},
	},
	"account.profile_email": {
		Method: http.MethodGet, Path: "/account/profile/email",
		Summary:     "邮箱变更页",
		Description: "渲染邮箱变更状态与申请/取消表单；邮箱只在验证完成后生效，页面不显示他人邮箱。",
		Module:      "account",
		Query: []PageField{
			pageQuery(pageText("status", false, 32, "一次性状态提示（如 cancelled）；不参与授权。")),
		},
		StateTransitions: []string{"完整会话 → 200 渲染邮箱变更状态页"},
	},
	"account.profile_email.submit": {
		Method: http.MethodPost, Path: "/account/profile/email",
		Summary:     "申请邮箱变更",
		Description: "以当前密码复核 + 新邮箱提交变更申请，向新邮箱发送一次性验证链接；验证完成前旧邮箱仍生效，申请可取消。",
		Module:      "account", CSRF: pageCSRFSession,
		Fields: []PageField{
			pageText("new_email", true, 320, "新邮箱地址；必须能被真实验证后才生效。"),
			pageSecret("current_password", true, 1024, "当前密码，用于本人敏感操作复核；只写。"),
		},
		StateTransitions: []string{
			"完整会话 + 密码正确 → 申请受理：200 展示待验证状态",
			"密码错误/邮箱格式不合法 → 400",
			"已有进行中的变更 → 409",
		},
		Notes: []string{"变更申请使旧的邮箱相关找回授权失效；发送入队不等于送达。"},
	},
	"account.profile_email.cancel": {
		Method: http.MethodPost, Path: "/account/profile/email/cancel",
		Summary:     "取消邮箱变更",
		Description: "取消当前进行中的邮箱变更申请，使对应验证链接失效，303 回邮箱页。",
		Module:      "account", CSRF: pageCSRFSession,
		StateTransitions: []string{
			"存在进行中申请 → 取消成功：303 /account/profile/email?status=cancelled",
			"无进行中申请 → 200 提示，不伪造取消成功",
		},
	},
	"account.email_change_verify": {
		Method: http.MethodGet, Path: "/email/change/verify",
		Summary:     "新邮箱验证入口",
		Description: "匿名公开表单：渲染新邮箱验证确认页；GET 只校验参数形状，不消费令牌。",
		Module:      "account",
		Query: []PageField{
			pageQuery(pageText("rid", true, 128, "邮箱变更请求编号。")),
			pageQuery(pageText("cid", true, 128, "邮箱变更凭证编号。")),
			pageQuery(pageSecret("token", true, 512, "一次性验证令牌（只写，示例为合成值）。")),
		},
		StateTransitions: []string{
			"参数完整 → 渲染确认页（不消费令牌）",
			"参数缺失/形状非法 → 400",
		},
	},
	"account.email_change_verify.submit": {
		Method: http.MethodPost, Path: "/email/change/verify",
		Summary:     "新邮箱验证提交",
		Description: "消费一次性令牌完成邮箱变更；变更后旧的邮箱相关找回授权失效，页面如实显示通知是否发出（通知失败不改写已成立结果）。",
		Module:      "account", CSRF: pageCSRFAnonymous,
		Fields: []PageField{
			pageText("rid", true, 128, "邮箱变更请求编号。"),
			pageText("cid", true, 128, "邮箱变更凭证编号。"),
			pageSecret("token", true, 512, "一次性验证令牌（只写）。"),
		},
		StateTransitions: []string{
			"有效令牌 → 邮箱变更完成：200，旧邮箱不再作为身份邮箱",
			"令牌无效/过期/已用 → 400 统一文案",
		},
	},
	"account.password": {
		Method: http.MethodGet, Path: "/account/password",
		Summary:          "修改密码页",
		Description:      "渲染本人改密表单；页面不显示密码、哈希或历史密码。",
		Module:           "account",
		StateTransitions: []string{"完整会话 → 渲染改密表单", "无会话 → 401"},
	},
	"account.password.submit": {
		Method: http.MethodPost, Path: "/account/password",
		Summary:     "本人修改密码",
		Description: "以当前密码复核后设置新密码；复用密码策略/历史/哈希与事务，成功后撤销旧会话并 303 回登录页（要求重新登录）。",
		Module:      "account", CSRF: pageCSRFSession,
		Fields: []PageField{
			pageSecret("current_password", true, 1024, "当前密码；只写。"),
			pageSecret("new_password", true, 1024, "新密码；按密码策略与历史校验，只写、不回显。"),
			pageSecret("password_confirm", true, 1024, "新密码确认；两次不一致返回 400。"),
		},
		StateTransitions: []string{
			"完整会话 + 原密码正确 + 新密码合规 → 改密成功：303 跳转登录页并撤销旧会话",
			"原密码错误/新密码不合规/历史复用 → 400，不半改密",
			"会话过期 → 401；CSRF 失败 → 403",
		},
		Notes: []string{"本人改密不修改他人密码，也不清除 MFA 因素。"},
	},
}
