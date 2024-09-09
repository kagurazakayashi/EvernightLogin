package transport

import "net/http"

// 本文件登记账号自助活动（本人安全活动只读）与自定义 APP 扫码登录页面契约。
// 两类页面都在 auth./account. 命名空间下，属于本步已定义的账户/登录流程范围：
//   - account.activity*：普通用户只读本人安全活动，不提供他人/管理/清理入口；
//   - auth.qr_login*：已登录自定义 APP 扫码登录（不是 OAuth 设备码端点），
//     二维码只是短期发起凭证，不承载长期 token，领取绑定原发起端且单次。

// pageActivityQROperations 是本人活动与扫码登录页面契约。
var pageActivityQROperations = map[string]PageOperation{
	"account.activity": {
		Method: http.MethodGet, Path: "/account/activity",
		Summary:     "本人安全活动列表",
		Description: "分页渲染当前登录用户本人的安全活动记录（只读、仅本人数据范围）；筛选先于分页，游标绑定筛选条件。",
		Module:      "security",
		Query: []PageField{
			pageQuery(pageText("action", false, 64, "操作类型筛选。")),
			pageQuery(pageText("error_code", false, 64, "错误码筛选（大写）。")),
			pageQuery(pageText("request_id", false, 64, "请求编号筛选，用于受限排障。")),
			pageQuery(pageText("target_type", false, 64, "目标类型筛选。")),
			pageQuery(pageText("target_id", false, 128, "目标编号筛选。")),
			pageQuery(pageBoolean("system_only", false, "只看系统作用域事件（1/on）。")),
			pageQuery(pageText("from", false, 40, "起始时间（含），按用户时区解析。")),
			pageQuery(pageText("to", false, 40, "结束时间（不含），按用户时区解析。")),
			pageQuery(pageText("order", false, 16, "排序：occurred_desc（默认）或 occurred_asc。")),
			pageQuery(pageInteger("limit", false, "每页条数 1～100，默认 20。")),
			pageQuery(pageInteger("offset", false, "偏移分页；与 cursor 互斥。")),
			pageQuery(pageText("cursor", false, 4096, "稳定游标；切换筛选条件后旧游标失效。")),
		},
		StateTransitions: []string{
			"完整会话 → 200 分页渲染本人安全活动",
			"非法时间/分页/游标 → 400 并提示字段错误",
			"无会话/会话过期 → 401",
		},
		Notes: []string{"只返回本人数据范围，不提供他人活动、导出或清理入口。"},
	},
	"account.activity_detail": {
		Method: http.MethodGet, Path: "/account/activity/detail",
		Summary:     "本人安全活动详情",
		Description: "渲染本人单条安全活动详情；他人事件按不存在处理（服务端判定），不泄露事件归属。",
		Module:      "security",
		Query: []PageField{
			pageQuery(pageText("event_id", true, 128, "活动事件编号。")),
			pageQuery(pageText("occurred_at", false, 40, "事件发生时间提示（RFC3339Nano），用于稳定检索同编号事件。")),
		},
		StateTransitions: []string{
			"事件属于本人 → 200 渲染详情",
			"事件不属于本人/不存在 → 404 或按不存在处理",
			"缺少 event_id → 400",
		},
	},
	"auth.qr_login": {
		Method: http.MethodGet, Path: "/login/qr",
		Summary:     "自定义 APP 扫码登录页",
		Description: "匿名渲染扫码登录发起页并生成一次性二维码；二维码只承载短期发起凭证，不装长期 token，确认前不显示任何应用/范围承诺之外的信息。",
		Module:      "auth",
		StateTransitions: []string{
			"匿名 → 渲染二维码页并下发签名状态 Cookie",
			"扫码登录未启用 → 页面说明不可用，不生成可用二维码",
		},
		Notes: []string{"自定义 APP 扫码登录不是 OAuth 设备码端点；真实的确认/领取在 APP 端完成。"},
	},
	"auth.qr_login.poll": {
		Method: http.MethodPost, Path: "/login/qr/poll",
		Summary:     "轮询扫码状态",
		Description: "轮询当前二维码的扫码状态（待确认/已确认待领取/已过期/已取消）；只读取签名状态 Cookie 绑定的发起请求。",
		Module:      "auth", CSRF: pageCSRFAnonymous,
		StateTransitions: []string{
			"发起请求有效 → 200 返回当前状态并刷新状态 Cookie",
			"二维码过期/已取消 → 200 状态提示（不签发会话）",
			"限流 → 429",
		},
	},
	"auth.qr_login.claim": {
		Method: http.MethodPost, Path: "/login/qr/claim",
		Summary:     "领取扫码登录结果",
		Description: "已确认的扫码请求只能由原发起端领取一次并签发真实会话；领取后二维码失效，不能重复使用或转给他人。",
		Module:      "auth", CSRF: pageCSRFAnonymous,
		StateTransitions: []string{
			"已确认 + 原发起端 + 未领取 → 303 跳转落地页并下发会话 Cookie",
			"未确认/已领取/非原发起端 → 400/403，不签发会话",
		},
		Notes: []string{"二维码不能装长期 token；领取绑定原发起端并单次。"},
	},
	"auth.qr_login.regenerate": {
		Method: http.MethodPost, Path: "/login/qr/regenerate",
		Summary:     "刷新登录二维码",
		Description: "作废旧二维码并生成新的短期发起请求；刷新不改变登录状态。",
		Module:      "auth", CSRF: pageCSRFAnonymous,
		StateTransitions: []string{"发起请求过期/用户刷新 → 新二维码生效，旧二维码失效"},
	},
	"auth.qr_login.cancel": {
		Method: http.MethodPost, Path: "/login/qr/cancel",
		Summary:     "取消扫码登录",
		Description: "取消当前扫码登录发起请求并清理签名状态 Cookie；已确认未领取的请求不能凭本操作换取会话。",
		Module:      "auth", CSRF: pageCSRFAnonymous,
		StateTransitions: []string{"发起请求有效 → 取消：200 状态提示，旧二维码失效"},
	},
}
