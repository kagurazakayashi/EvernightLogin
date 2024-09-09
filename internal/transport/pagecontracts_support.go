package transport

import "net/http"

// 本文件登记客服求助单与人工恢复页面契约（ui/pages_support.go 与
// ui/pages_support_handlers.go）。
//
// 人工恢复是“三种恢复流程”中的第三种：客服/审计员在授权与数据中心范围内登记
// 申请、独立审批、再执行恢复；客服不读取该流程的令牌、验证码，也不读取用户自设
// 的新密码。页面只做展示与表单提交，授权/数据范围/再次认证/审计由后端真实服务
// 判定；按钮存在不等于放行。

// pageSupportOperations 是 support.* 客服与人工恢复页面契约。
var pageSupportOperations = map[string]PageOperation{
	"support.cases": {
		Method: http.MethodGet, Path: "/support/cases",
		Summary:     "客服求助单列表",
		Description: "按状态分页渲染当前操作者可管理的求助单；数据范围与字段投影由服务端授权先于分页计算。",
		Module:      "support",
		Query: []PageField{
			pageQuery(pageText("status", false, 32, "求助单状态筛选；空表示全部。")),
			pageQuery(pageInteger("offset", false, "分页偏移（从 0 开始）；非法值返回 400。")),
		},
		StateTransitions: []string{
			"管理会话 + 有查询权限 → 200 分页渲染范围内求助单",
			"无权限/范围外 → 403 或 200 空列表（不越权），不返回他人范围数据",
		},
	},
	"support.case_create": {
		Method: http.MethodGet, Path: "/support/cases/create",
		Summary:     "新建求助单页",
		Description: "渲染新建求助单表单，可按目标用户编号预查目标摘要；目标不存在/超出可管理范围时如实提示。",
		Module:      "support",
		Query: []PageField{
			pageQuery(pageText("target_user_id", false, 64, "预填目标用户编号。")),
			pageQuery(pageText("reason", false, 512, "预填求助原因（用户文本，不拼接 HTML）。")),
		},
		StateTransitions: []string{"管理会话 → 200 渲染新建表单", "目标越权/不存在 → 403 或页面错误摘要"},
	},
	"support.case_create.submit": {
		Method: http.MethodPost, Path: "/support/cases/create",
		Summary:     "提交求助单",
		Description: "登记求助单并记录真实操作者、目标与理由；隐藏字段中的操作者身份不被接受，服务端以会话为准。",
		Module:      "support", CSRF: pageCSRFSession,
		Fields: []PageField{
			pageText("action", true, 64, "求助动作类型（服务端白名单校验）。"),
			pageText("target_user_id", true, 64, "目标用户编号；必须在可管理数据范围内。"),
			pageText("reason", true, 512, "求助原因（用户文本，不拼接 HTML）。"),
			pageEnum("confirm", true, pageConfirmYes, "显式确认提交。"),
		},
		StateTransitions: []string{
			"管理会话 + 有创建权限 + 目标在范围 → 创建成功：200 跳转详情",
			"目标越权/不存在 → 403；字段不合法 → 400；再次认证不满足 → 403",
		},
		Notes: []string{"关键操作写入审计；审计不可用时不放行。"},
	},
	"support.case_detail": {
		Method: http.MethodGet, Path: "/support/cases/detail",
		Summary:     "求助单详情",
		Description: "渲染单个求助单详情与可用动作；只能读取可管理范围内的求助单。",
		Module:      "support",
		Query: []PageField{
			pageQuery(pageText("case_id", true, 128, "求助单编号。")),
		},
		StateTransitions: []string{
			"范围内求助单 → 200 渲染详情",
			"不存在/超出范围 → 403 或 404，不泄露他人数据",
		},
	},
	"support.case_reassign.submit": {
		Method: http.MethodPost, Path: "/support/cases/reassign",
		Summary:     "转派求助单",
		Description: "把范围内求助单转派给可接单客服；目标客服资格由服务端校验。",
		Module:      "support", CSRF: pageCSRFSession,
		Fields: []PageField{
			pageText("case_id", true, 128, "求助单编号。"),
			pageText("new_assignee_user_id", true, 64, "新受理客服用户编号。"),
			pageEnum("confirm", true, pageConfirmYes, "显式确认转派。"),
		},
		StateTransitions: []string{
			"范围 + 接单资格通过 → 转派成功：200",
			"目标无资格/越权 → 403",
		},
	},
	"support.case_transition.submit": {
		Method: http.MethodPost, Path: "/support/cases/transition",
		Summary:     "推进求助单状态",
		Description: "按求助单状态机推进状态并记录说明；非法状态转移被拒绝，不伪造完成状态。",
		Module:      "support", CSRF: pageCSRFSession,
		Fields: []PageField{
			pageText("case_id", true, 128, "求助单编号。"),
			pageText("to_status", true, 32, "目标状态（服务端状态机白名单校验）。"),
			pageText("note", false, 1024, "处理说明（用户文本）。"),
			pageEnum("confirm", true, pageConfirmYes, "显式确认状态变更。"),
		},
		StateTransitions: []string{
			"合法状态转移 → 成功：200",
			"非法转移/并发冲突 → 409；越权 → 403",
		},
	},
	"support.case_send.submit": {
		Method: http.MethodPost, Path: "/support/cases/send",
		Summary:     "发送求助单处理结果/重置入口",
		Description: "按求助单动作发送受控通知或重置入口；客服不提交、不读取用户的新密码，也不回显任何一次性令牌。",
		Module:      "support", CSRF: pageCSRFSession,
		Fields: []PageField{
			pageText("case_id", true, 128, "求助单编号。"),
			pageEnum("confirm", true, pageConfirmYes, "显式确认发送。"),
		},
		StateTransitions: []string{
			"范围内求助单 → 发送受理：200（入队不等于送达，失败如实提示）",
			"越权/状态不允许 → 403/409",
		},
	},
	"support.recovery_create.submit": {
		Method: http.MethodPost, Path: "/support/recovery/request",
		Summary:     "登记人工恢复申请",
		Description: "登记密码/MFA 人工恢复申请，绑定目标、操作、核验依据与交付渠道；证据摘要只提交一次、不落库明文。申请不等于批准。",
		Module:      "support", CSRF: pageCSRFSession,
		Fields: []PageField{
			pageText("target_user_id", true, 64, "恢复目标用户编号；不得为 root 或超出可管理范围。"),
			pageEnum("operation", true, []string{"password_reset", "mfa_reset"}, "恢复操作类型（密码重置/MFA 重置）。"),
			pageText("verification_basis", true, 128, "核验依据类型（服务端白名单）。"),
			pageText("verification_reference", true, 128, "核验依据引用编号；不得包含用户秘密。"),
			pageText("evidence_summary", true, 2048, "证据摘要；只提交一次、不落库明文。"),
			pageText("reason", true, 512, "申请理由。"),
			pageText("delivery", false, 64, "结果交付渠道。"),
			pageText("support_case_id", false, 128, "关联求助单编号（可选）。"),
			pageEnum("confirm", true, pageConfirmYes, "显式确认登记。"),
		},
		StateTransitions: []string{
			"有登记权限 + 目标在范围 + 核验依据合规 → 申请登记成功：200 跳转详情（待独立审批）",
			"目标越权/root → 403；字段不合法 → 400；重复申请 → 409",
		},
		Notes: []string{"申请必须经独立审批；同一操作者不能自我批准（由后端审批规则判定）。"},
	},
	"support.recovery_request": {
		Method: http.MethodGet, Path: "/support/recovery/request",
		Summary:     "人工恢复申请详情",
		Description: "渲染申请详情与参与者/候选审批人摘要；客服不读取该流程的令牌、验证码或用户自设新秘密。",
		Module:      "support",
		Query: []PageField{
			pageQuery(pageText("request_id", true, 128, "恢复申请编号。")),
		},
		StateTransitions: []string{
			"参与者且有读取权限 → 200 渲染详情",
			"不存在/超出范围 → 403/404",
		},
	},
	"support.recovery_cancel.submit": {
		Method: http.MethodPost, Path: "/support/recovery/cancel",
		Summary:     "取消人工恢复申请",
		Description: "按权限取消未执行的人工恢复申请并记录理由；取消请求与实际取消分别记录。",
		Module:      "support", CSRF: pageCSRFSession,
		Fields: []PageField{
			pageText("request_id", true, 128, "恢复申请编号。"),
			pageText("reason", true, 200, "取消理由；不能为空。"),
			pageEnum("confirm", true, pageConfirmYes, "显式确认取消。"),
		},
		StateTransitions: []string{
			"可取消状态 + 权限通过 → 取消成功：200",
			"已执行/状态不允许 → 409；越权 → 403",
		},
	},
	"support.recovery_inbox": {
		Method: http.MethodGet, Path: "/support/recovery",
		Summary:     "人工恢复工作台",
		Description: "按视图模式分页渲染人工恢复申请工作台（待审批/我发起的等）；统计与列表先按授权范围过滤。",
		Module:      "support",
		Query: []PageField{
			pageQuery(pageText("mode", false, 32, "工作台视图模式，默认 pending_approval。")),
			pageQuery(pageText("operation", false, 64, "恢复操作类型筛选。")),
			pageQuery(pageInteger("offset", false, "分页偏移；非法值按 0 处理，不越权。")),
		},
		StateTransitions: []string{"管理会话 → 200 渲染范围内工作台", "无权限 → 403"},
	},
	"support.recovery_approval": {
		Method: http.MethodGet, Path: "/support/recovery/approval",
		Summary:     "人工恢复审批页",
		Description: "渲染审批页与影响说明；申请者不能凭页面自报批准，独立审批规则由后端复核。",
		Module:      "support",
		Query: []PageField{
			pageQuery(pageText("request_id", true, 128, "恢复申请编号。")),
		},
		StateTransitions: []string{
			"有审批资格且非自我批准 → 200 渲染审批页",
			"无资格/自我批准 → 403",
		},
		Notes: []string{"审批人不能是申请发起人的同一自然人（由后端独立审批规则判定）。"},
	},
	"support.recovery_approve.submit": {
		Method: http.MethodPost, Path: "/support/recovery/approval",
		Summary:     "批准人工恢复",
		Description: "批准人工恢复申请并记录真实审批人；批准不等于执行，执行仍需独立权限与再次认证。",
		Module:      "support", CSRF: pageCSRFSession,
		Fields: []PageField{
			pageText("request_id", true, 128, "恢复申请编号。"),
			pageText("note", false, 1024, "审批说明。"),
			pageEnum("confirm", true, pageConfirmYes, "显式确认批准。"),
		},
		StateTransitions: []string{
			"独立审批通过 → 批准成功：200（仍待执行）",
			"自我批准/无资格 → 403；状态不允许 → 409",
		},
	},
	"support.recovery_reject.submit": {
		Method: http.MethodPost, Path: "/support/recovery/reject",
		Summary:     "驳回人工恢复",
		Description: "驳回人工恢复申请并记录理由；驳回后不执行任何恢复动作，旧会话与凭据不受影响。",
		Module:      "support", CSRF: pageCSRFSession,
		Fields: []PageField{
			pageText("request_id", true, 128, "恢复申请编号。"),
			pageText("reason", true, 200, "驳回理由；不能为空。"),
			pageEnum("confirm", true, pageConfirmYes, "显式确认驳回。"),
		},
		StateTransitions: []string{
			"有审批资格 → 驳回成功：200",
			"无资格 → 403；状态不允许 → 409",
		},
	},
	"support.recovery_execute": {
		Method: http.MethodGet, Path: "/support/recovery/execute",
		Summary:     "人工恢复执行确认页",
		Description: "渲染执行前影响说明与阻塞原因；执行依赖已批准状态、独立权限与再次认证，任一不满足即显示不可执行。",
		Module:      "support",
		Query: []PageField{
			pageQuery(pageText("request_id", true, 128, "恢复申请编号。")),
		},
		StateTransitions: []string{
			"已批准 + 有执行权限 → 200 渲染执行确认",
			"未批准/无权限/策略关闭 → 200 展示阻塞原因，不提供可用执行",
		},
	},
	"support.recovery_execute.submit": {
		Method: http.MethodPost, Path: "/support/recovery/execute",
		Summary:     "执行人工恢复",
		Description: "执行已批准的人工恢复：重置密码或 MFA 由后端真实服务完成并写审计；不读取/回显用户秘密，成功只返回脱敏结果，目标旧凭据失效。",
		Module:      "support", CSRF: pageCSRFSession,
		Fields: []PageField{
			pageText("request_id", true, 128, "恢复申请编号。"),
			pageEnum("confirm", true, pageConfirmYes, "显式确认执行（不可撤销的敏感操作）。"),
		},
		StateTransitions: []string{
			"已批准 + 执行权限 + 再次认证通过 → 执行成功：200 展示脱敏结果",
			"未批准/权限不足/再次认证失败 → 403；状态冲突 → 409",
		},
		Notes: []string{
			"执行不复用“已验证找回令牌”的授权路径，而是独立审批 + 绑定操作的两步验证。",
			"不向操作者返回旧密码、哈希、令牌或 MFA 种子。",
		},
	},
}
