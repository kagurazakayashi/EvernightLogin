package transport

// 本文件登记 tasks（任务）、diagnostics（配置诊断）、settings（配置管理）与
// support（客服工单/人工恢复）域的管理 API 契约。字段/响应取自
// internal/adminapi/misc.go、internal/serverapp/{diagnostics,settings,
// admin_domain_routes,admin_domain_writes,admin_domain_writes2}.go 的真实投影。

// adminTaskOperations 是 tasks 域契约。
var adminTaskOperations = map[string]AdminOperation{
	"GET tasks": {
		Method: "GET", Pattern: "tasks", Domain: "tasks",
		Summary:     "查询任务（稳定游标）",
		Description: "按 diagnostics.read 与数据范围/属主查询任务摘要（显式剔除任务载荷）；使用稳定 cursor 分页（offset 必须为 0，非零被拒绝），支持 kind/state/request_id/时间筛选。",
		Permissions: []string{"diagnostics.read"},
		Query: []AdminParam{
			adminQueryInt("limit", 1, 100, "每页条数，默认 20，最大 100。"),
			adminQuery("cursor", "稳定游标：下一页请求带 cursor。"),
			adminQuery("kind", "任务类型筛选。"),
			adminQuery("state", "任务状态筛选（服务端任务状态机）。"),
			adminQuery("request_id", "请求编号筛选。"),
			adminQuery("from", "创建时间起始（含，RFC3339）。"),
			adminQuery("to", "创建时间结束（不含，RFC3339）。"),
		},
		Success: "object",
		ExtraKeys: []string{
			"tasks:refs:AdminTaskList", "has_more:boolean", "limit:integer", "next_cursor:string",
		},
		Notes: []string{"列表级授权先于查询：普通用户只看到本人发起的任务；不返回任务载荷与秘密。"},
	},
	"GET tasks/{task_id}": {
		Method: "GET", Pattern: "tasks/{task_id}", Domain: "tasks",
		Summary:     "读取任务详情",
		Description: "按 diagnostics.read + 数据范围/属主读取任务详情与尝试历史（显式剔除任务载荷）；越权 403、不存在 404。",
		Permissions: []string{"diagnostics.read"},
		Path:        []AdminParam{adminParam("task_id", "任务编号。")},
		Success:     "object",
		ExtraKeys:   []string{"task:ref:AdminTaskDetail"},
	},
}

// adminDiagnosticsOperations 是 diagnostics 域契约。
var adminDiagnosticsOperations = map[string]AdminOperation{
	"GET diagnostics": {
		Method: "GET", Pattern: "diagnostics", Domain: "diagnostics",
		Summary:     "读取脱敏运行诊断",
		Description: "按 diagnostics.read 与明确 system/应用范围读取只读脱敏运行状态、队列、配置待重启与关联错误白名单；不含秘密。",
		Permissions: []string{"diagnostics.read"},
		Query: []AdminParam{
			adminQuery("scope", "数据范围：空或 system 表示系统范围；应用范围传应用编号。"),
		},
		Success: "AdminDiagnosticsReport",
	},
	"GET diagnostics/errors": {
		Method: "GET", Pattern: "diagnostics/errors", Domain: "diagnostics",
		Summary:     "读取关联错误",
		Description: "按 request_id 读取有界关联错误（只读脱敏，不返回审计 detail）；limit 超硬上限返回 400。",
		Permissions: []string{"diagnostics.read"},
		Query: []AdminParam{
			adminQuery("scope", "数据范围：空或 system 表示系统范围；应用范围传应用编号。"),
			adminQuery("request_id", "按请求编号关联错误（可选）。"),
			adminQueryInt("limit", 1, 50, "错误条数上限（1～50）；空使用诊断服务默认，超限返回 400。"),
		},
		Success: "AdminDiagnosticsErrors",
	},
	"GET diagnostics/export": {
		Method: "GET", Pattern: "diagnostics/export", Domain: "diagnostics",
		Summary:     "脱敏诊断导出",
		Description: "按 diagnostics.read 生成有界脱敏诊断导出（JSON 快照，可带关联错误）；不执行脚本、不返回秘密或内部连接细节。",
		Permissions: []string{"diagnostics.read"},
		Query: []AdminParam{
			adminQuery("scope", "数据范围：空或 system 表示系统范围；应用范围传应用编号。"),
			adminQuery("request_id", "可选：附带该请求编号的关联错误。"),
			adminQueryInt("limit", 1, 50, "关联错误条数上限（1～50）。"),
		},
		Success: "AdminDiagnosticsExport",
	},
}

// adminSettingsOperations 是 settings 域契约。
var adminSettingsOperations = map[string]AdminOperation{
	"GET settings": {
		Method: "GET", Pattern: "settings", Domain: "settings",
		Summary:     "读取脱敏配置字段",
		Description: "按 settings.manage 与真实 system 范围读取脱敏配置字段（秘密已遮盖）、磁盘/有效版本与待重载标记。",
		Permissions: []string{"settings.manage"},
		Success:     "AdminSettingsFields",
	},
	"GET settings/status": {
		Method: "GET", Pattern: "settings/status", Domain: "settings",
		Summary:     "读取配置状态",
		Description: "读取磁盘/有效版本、待热加载/待重启字段、宿主重载需求与最近错误码。",
		Permissions: []string{"settings.manage"},
		Success:     "AdminSettingsStatus",
	},
	"POST settings/validate": {
		Method: "POST", Pattern: "settings/validate", Domain: "settings",
		Summary:     "校验配置变更（不落盘）",
		Description: "校验拟变更字段（settings.manage；root-only 字段按真实身份拒绝）；不写磁盘、不改变当前有效值。",
		Permissions: []string{"settings.manage"},
		Body: []AdminField{
			adminBody("changes", "object", "字段名→新值的映射（字段白名单与秘密占位规则由服务端校验）。"),
		},
		Success: "object",
		ExtraKeys: []string{
			"valid:boolean", "errors:array<object>", "changed_fields:array<string>",
			"writable:boolean", "restart_required:array<string>",
		},
	},
	"PUT settings": {
		Method: "PUT", Pattern: "settings", Domain: "settings",
		Summary:     "更新配置",
		Description: "按版本乐观并发原子写入配置（settings.manage + 审计；root-only 字段按真实 root 判定）；失败保留最后有效值。",
		Permissions: []string{"settings.manage"},
		Body: []AdminField{
			adminBody("expected_version", "string", "期望的当前配置版本；不一致返回 409，需重新读取。"),
			adminBody("changes", "object", "字段名→新值的映射（秘密字段仅接受受控占位语义；不接受明文回写掩盖真实秘密）。"),
			AdminField{Name: "reason", Type: "string", Description: "操作原因（可选，进入审计）。"},
		},
		Success: "object",
		ExtraKeys: []string{
			"version:string", "previous_version:string", "changed_fields:array<string>",
			"hot_fields:array<string>", "restart_fields:array<string>",
			"applied_now:boolean", "host_reload_needed:boolean", "note:string",
		},
		Notes: []string{"区分磁盘值/当前有效值/待重启；失败不覆盖真实秘密。"},
	},
	"POST settings/sensitive-policy/restore": {
		Method: "POST", Pattern: "settings/sensitive-policy/restore", Domain: "settings",
		Summary:     "恢复敏感操作策略（仅 root）",
		Description: "仅真实 root 用户 + 再次认证（强认证因素）+ 版本冲突检查 + 关键审计；恢复后策略下限不可被普通 settings.manage 放宽。",
		RootOnly:    true,
		Sensitive:   true,
		Confirm:     true,
		Reason:      true,
		Body: []AdminField{
			adminConfirmField(),
			adminBody("scope_id", "string", "作用范围：system 或应用编号。"),
			adminBody("operation_id", "string", "敏感操作 ID（服务端目录白名单）。"),
			adminBodyOptional("all", "boolean", "true 表示恢复该范围全部操作（与 operation_id 二选一，由服务端校验）。"),
			adminBody("expected_version", "integer", "期望的策略版本；不一致返回 409。"),
			adminBodySecret("password", "当前密码（本次操作的两步验证因素之一；只写）。", 1024),
			adminBodySecret("totp_code", "当前 TOTP 验证码（无密码 Passkey 账户可用 Passkey 再次认证；只写）。", 16),
			adminReasonField(),
		},
		Success: "object",
		ExtraKeys: []string{
			"scope_id:string", "restored:boolean", "removed_overrides:integer", "version:integer",
		},
		Notes: []string{
			"root-only 属于身份能力，settings.manage 不能获得；恢复只回到目录下限，不得降低最弱认证强度。",
			"历史记录不回滚；恢复本身写关键审计。",
		},
	},
}

// adminSupportOperations 是 support 域契约（客服工单 + 人工恢复）。
var adminSupportOperations = map[string]AdminOperation{
	"GET support/cases": {
		Method: "GET", Pattern: "support/cases", Domain: "support",
		Summary:     "分页查询客服求助单",
		Description: "按 support.cases.read 与客服数据范围分页查询求助单（按状态筛选、工单编号/原因有界字面搜索）；越权不返回他人范围数据。",
		Permissions: []string{"support.cases.read"},
		Query: append(append(adminPaginationQuery(),
			adminQuery("status", "按求助单状态筛选（服务端状态机）。")),
			adminSearchQuery("id/reason 等许可字段（不搜索脱敏邮箱/用户名）")...),
		Success: "object",
		ExtraKeys: []string{
			"items:refs:AdminSupportCase", "has_more:boolean", "next_offset:integer",
		},
		Notes: []string{"响应不返回 limit/offset，只给 has_more/next_offset；越权不返回他人范围数据。"},
	},
	"GET support/cases/{case_id}": {
		Method: "GET", Pattern: "support/cases/{case_id}", Domain: "support",
		Summary:     "读取客服求助单",
		Description: "读取单个求助单详情（目标用户名/邮箱按脱敏展示）；超出数据范围按不存在处理。",
		Permissions: []string{"support.cases.read"},
		Path:        []AdminParam{adminParam("case_id", "求助单编号。")},
		Success:     "AdminSupportCase",
	},
	"POST support/cases": {
		Method: "POST", Pattern: "support/cases", Domain: "support",
		Summary:     "创建客服求助单",
		Description: "登记求助单并记录真实操作者/目标/理由（support.cases.create + 确认 + 审计）。",
		Permissions: []string{"support.cases.create"},
		Confirm:     true,
		Reason:      true,
		Body: []AdminField{
			adminConfirmField(),
			adminBody("target_user_id", "string", "目标用户编号；必须在可管理数据范围内。"),
			adminBody("reason", "string", "求助原因（用户文本，不拼接 HTML）。"),
			adminRequestIDField(),
		},
		Success: "object",
		ExtraKeys: []string{
			"id:string", "target_user_id:string", "status:string", "row_version:integer",
		},
	},
	"POST support/cases/{case_id}/send-reset": {
		Method: "POST", Pattern: "support/cases/{case_id}/send-reset", Domain: "support",
		Summary:     "发送求助单重置入口",
		Description: "按求助单发送受控重置入口/通知（support.cases.update + 确认）；客服不读取、不提交用户新密码，也不回显令牌。",
		Permissions: []string{"support.cases.update"},
		Confirm:     true,
		Path:        []AdminParam{adminParam("case_id", "求助单编号。")},
		Body: []AdminField{
			adminConfirmField(),
			adminRequestIDField(),
		},
		Success: "object",
		ExtraKeys: []string{
			"sent:boolean", "manual_review:string", "status:string",
		},
		Notes: []string{"发送受理不等于收件人送达；失败如实返回稳定错误码，不伪造已发送。"},
	},
	"POST support/cases/{case_id}/reassign": {
		Method: "POST", Pattern: "support/cases/{case_id}/reassign", Domain: "support",
		Summary:     "转派客服求助单",
		Description: "把范围内求助单转派给可接单客服（support.cases.update + 确认）；目标接单资格由服务端校验。",
		Permissions: []string{"support.cases.update"},
		Confirm:     true,
		Path:        []AdminParam{adminParam("case_id", "求助单编号。")},
		Body: []AdminField{
			adminConfirmField(),
			adminBody("new_assignee_user_id", "string", "新受理客服用户编号（须具备接单资格）。"),
			adminRequestIDField(),
		},
		Success: "object",
		ExtraKeys: []string{
			"id:string", "assignee_user_id:string",
		},
	},
	"POST support/cases/{case_id}/transition": {
		Method: "POST", Pattern: "support/cases/{case_id}/transition", Domain: "support",
		Summary:     "推进客服求助单状态",
		Description: "按求助单状态机推进状态并记录说明（support.cases.update + 确认）；非法状态转移被拒绝，不伪造完成。",
		Permissions: []string{"support.cases.update"},
		Confirm:     true,
		Path:        []AdminParam{adminParam("case_id", "求助单编号。")},
		Body: []AdminField{
			adminConfirmField(),
			adminBody("to_status", "string", "目标状态（服务端状态机白名单）。"),
			adminBodyOptional("note", "string", "处理说明（用户文本）。"),
			adminRequestIDField(),
		},
		Success: "object",
		ExtraKeys: []string{
			"id:string", "status:string",
		},
	},
	"GET support/recovery/requests": {
		Method: "GET", Pattern: "support/recovery/requests", Domain: "support",
		Summary:     "分页查询人工恢复申请",
		Description: "按参与/审批/执行关系分页查询人工恢复申请工作台（mode/operation 筛选）；普通客服只看到授权范围内的申请。",
		Permissions: []string{"support.recovery.request", "support.recovery.approve", "support.recovery.execute"},
		Query: append(adminPaginationQuery(),
			adminQuery("mode", "工作台视图：pending_approval（默认）/我的申请/待执行等（服务端枚举）。"),
			adminQuery("operation", "恢复操作类型筛选：password_reset / mfa_reset。")),
		Success: "object",
		ExtraKeys: []string{
			"items:refs:AdminRecoveryRequest", "has_more:boolean", "next_offset:integer",
		},
		Notes: []string{"响应不返回 limit/offset，只给 has_more/next_offset；普通客服只看到授权范围内申请。"},
	},
	"GET support/recovery/requests/{request_id}": {
		Method: "GET", Pattern: "support/recovery/requests/{request_id}", Domain: "support",
		Summary:     "读取人工恢复申请",
		Description: "读取申请详情（目标/发起人/操作/状态/批准/内容摘要一致性）；不含令牌、验证码或用户新秘密。",
		Permissions: []string{"support.recovery.request", "support.recovery.approve", "support.recovery.execute"},
		Path:        []AdminParam{adminParam("request_id", "人工恢复申请编号。")},
		Success:     "AdminRecoveryRequest",
	},
	"POST support/recovery/requests": {
		Method: "POST", Pattern: "support/recovery/requests", Domain: "support",
		Summary:     "登记人工恢复申请",
		Description: "登记密码/MFA 人工恢复申请并绑定目标、操作、核验依据与交付渠道（support.recovery.request + 确认 + 审计）；申请不等于批准。",
		Permissions: []string{"support.recovery.request"},
		Sensitive:   true,
		Confirm:     true,
		Reason:      true,
		Body: []AdminField{
			adminConfirmField(),
			adminBody("target_user_id", "string", "恢复目标用户编号；不得为 root 或超出可管理范围。"),
			adminBody("operation", "string", "恢复操作：password_reset / mfa_reset。"),
			adminBody("verification_basis", "string", "核验依据类型（服务端白名单）。"),
			adminBody("verification_reference", "string", "核验依据引用编号；不得包含用户秘密。"),
			adminBody("evidence_summary", "string", "证据摘要：只提交一次、不落库明文。"),
			adminBody("reason", "string", "申请理由。"),
			adminBodyOptional("delivery", "string", "结果交付渠道。"),
			adminBodyOptional("support_case_id", "string", "关联求助单编号（可选）。"),
			adminRequestIDField(),
		},
		Success: "object",
		ExtraKeys: []string{
			"id:string", "status:string", "row_version:integer",
		},
		Notes: []string{"同一申请必须经独立审批；同一操作者不能自我批准（后端审批规则判定）。"},
	},
	"POST support/recovery/{request_id}/approve": {
		Method: "POST", Pattern: "support/recovery/{request_id}/approve", Domain: "support",
		Summary:     "批准人工恢复申请",
		Description: "独立审批人批准恢复申请（support.recovery.approve + 确认）；批准不等于执行，执行仍需独立权限与再次认证。",
		Permissions: []string{"support.recovery.approve"},
		Sensitive:   true,
		Confirm:     true,
		Path:        []AdminParam{adminParam("request_id", "人工恢复申请编号。")},
		Body: []AdminField{
			adminConfirmField(),
			adminBodyOptional("note", "string", "审批说明。"),
			adminRequestIDField(),
		},
		Success: "object",
		ExtraKeys: []string{
			"id:string", "status:string", "approver_user_id:string",
		},
		Notes: []string{"审批人不能是申请发起人的同一自然人；自我批准被拒绝。"},
	},
	"POST support/recovery/{request_id}/reject": {
		Method: "POST", Pattern: "support/recovery/{request_id}/reject", Domain: "support",
		Summary:     "驳回人工恢复申请",
		Description: "驳回恢复申请并记录理由（support.recovery.approve + 确认 + 原因）；驳回后不执行任何恢复动作。",
		Permissions: []string{"support.recovery.approve"},
		Confirm:     true,
		Reason:      true,
		Path:        []AdminParam{adminParam("request_id", "人工恢复申请编号。")},
		Body: []AdminField{
			adminConfirmField(),
			adminReasonField(),
			adminRequestIDField(),
		},
		Success: "object",
		ExtraKeys: []string{
			"rejected:boolean",
		},
	},
	"POST support/recovery/{request_id}/cancel": {
		Method: "POST", Pattern: "support/recovery/{request_id}/cancel", Domain: "support",
		Summary:     "取消人工恢复申请",
		Description: "取消未执行的人工恢复申请并记录理由（support.recovery.request + 确认 + 原因）；取消请求与实际取消分别记录。",
		Permissions: []string{"support.recovery.request"},
		Confirm:     true,
		Reason:      true,
		Path:        []AdminParam{adminParam("request_id", "人工恢复申请编号。")},
		Body: []AdminField{
			adminConfirmField(),
			adminReasonField(),
			adminRequestIDField(),
		},
		Success: "object",
		ExtraKeys: []string{
			"cancelled:boolean",
		},
	},
	"POST support/recovery/{request_id}/execute": {
		Method: "POST", Pattern: "support/recovery/{request_id}/execute", Domain: "support",
		Summary:     "执行人工恢复",
		Description: "执行已批准的人工恢复（独立权限 + 再次认证 + 审批状态复核 + 关键审计）；不读取/回显用户秘密，成功只返回脱敏结果，目标旧会话/凭据失效。",
		Permissions: []string{"support.recovery.execute"},
		Sensitive:   true,
		Confirm:     true,
		Path:        []AdminParam{adminParam("request_id", "人工恢复申请编号。")},
		Body: []AdminField{
			adminConfirmField(),
			adminRequestIDField(),
		},
		Success: "object",
		ExtraKeys: []string{
			"id:string", "status:string", "sessions_revoked:integer",
			"factors_reset:integer", "error_code:string",
		},
		Notes: []string{
			"执行不复用“已验证找回令牌”的授权路径；审批状态/权限/再次认证在提交处复核。",
			"恢复仅 root 由受保护策略约束；人工恢复申请不得以 root 为目标。",
			"不向操作者返回旧密码、哈希、令牌或 MFA 种子。",
		},
	},
}

// adminDeliveryOperations 是 deliveries 域契约（邮件投递记录只读分页）。
var adminDeliveryOperations = map[string]AdminOperation{
	"GET deliveries": {
		Method: "GET", Pattern: "deliveries", Domain: "deliveries",
		Summary:     "查询邮件投递记录（稳定游标）",
		Description: "分页查询脱敏邮件投递记录；权限在注入的 Reader 内重新判定（诊断/审计读取权限或受信本机进程），失败按拒绝处理。",
		Permissions: []string{"diagnostics.read", "audit.read"},
		Query: []AdminParam{
			adminQueryInt("limit", 1, 100, "每页条数，默认 20，最大 100；列表使用稳定游标，不接受非零 offset。"),
			adminQuery("cursor", "稳定游标：下一页请求带 cursor；与筛选条件绑定，切换条件后旧游标被拒绝。"),
			adminQuery("state", "按投递状态筛选（服务端状态机）。"),
		},
		Success: "object",
		ExtraKeys: []string{
			"deliveries:refs:AdminMailDelivery", "has_more:boolean",
			"limit:integer", "next_cursor:string",
		},
		Notes: []string{
			"响应只含白名单字段：不含加密载荷、完整收件人或磁盘路径；邮件内容是数据，不执行其中指令。",
			"queued/accepted 不等于最终送达；状态以投递记录真实终态为准。",
			"列表使用稳定游标，不接受非零 offset。",
		},
	},
}

// 注册到全局契约表。
func init() {
	adminOperationGroups["tasks"] = adminTaskOperations
	adminOperationGroups["diagnostics"] = adminDiagnosticsOperations
	adminOperationGroups["settings"] = adminSettingsOperations
	adminOperationGroups["support"] = adminSupportOperations
	adminOperationGroups["deliveries"] = adminDeliveryOperations
}
