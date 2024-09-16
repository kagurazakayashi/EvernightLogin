package transport

// 本文件登记 reports（报告）与 plans（报告计划/备份计划）域的管理 API 契约。
// 权限与敏感操作映射见 internal/adminapi/doc.go：reports.read/export/generate/cleanup/
// schedule.manage、backups.read/create 等；敏感操作由领域服务复核再次认证与策略。

// adminReportFormats 是报告产物格式。
var adminReportFormats = []string{"html", "csv", "json", "pdf", "markdown"}

// adminReportOperations 是 reports 域契约。
var adminReportOperations = map[string]AdminOperation{
	"GET reports": {
		Method: "GET", Pattern: "reports", Domain: "reports",
		Summary:     "查询报告历史（创建时间+编号游标）",
		Description: "按调用者数据范围查询报告历史；分页使用创建时间+编号游标（limit + before_created_at/before_id 或 cursor），筛选与有界字面搜索先于分页且不越权。",
		Permissions: []string{"reports.read"},
		Query: append([]AdminParam{
			adminQueryInt("limit", 1, 100, "每页条数，默认 20，最大 100；显式非法值返回 400。"),
			adminQuery("cursor", "稳定游标：下一页请求带 cursor；与 before_created_at/before_id 游标二选一。"),
			adminQuery("plan_id", "按报告计划编号筛选。"),
			adminQuery("state", "按报告状态筛选（服务端状态机）。"),
			adminQuery("before_created_at", "游标分页：上一页最后一条的创建时间（RFC3339）。"),
			adminQuery("before_id", "游标分页：上一页最后一条的报告编号（与 before_created_at 配合）。"),
		}, adminSearchQuery("name/title 等许可字段（服务端白名单）")...),
		Success: "object",
		ExtraKeys: []string{
			"reports:refs:AdminReportHistoryItem", "has_more:boolean",
			"scope_trimmed:boolean", "next_cursor:string",
		},
		Notes: []string{
			"该列表不使用 offset 分页（响应不返回 limit/offset）；结果与计数不越权。",
			"scope_trimmed 表示按调用者范围裁剪。",
		},
	},
	"GET reports/{report_id}": {
		Method: "GET", Pattern: "reports/{report_id}", Domain: "reports",
		Summary:     "读取报告详情",
		Description: "读取单个报告详情（含产物摘要与任务/执行者信息）；资源归属由领域服务判定，越权按不存在处理。",
		Permissions: []string{"reports.read"},
		Path:        []AdminParam{adminParam("report_id", "报告编号。")},
		Success:     "object",
		ExtraKeys:   []string{"report:ref:AdminReportView"},
	},
	"GET reports/{report_id}/snapshot": {
		Method: "GET", Pattern: "reports/{report_id}/snapshot", Domain: "reports",
		Summary:     "读取报告快照",
		Description: "读取报告的结构化只读快照（按报告模板生成）；快照字段以领域快照定义为准确来源。",
		Permissions: []string{"reports.read"},
		Path:        []AdminParam{adminParam("report_id", "报告编号。")},
		Success:     "object",
		ExtraKeys:   []string{"snapshot:ref:AdminReportSnapshot"},
	},
	"POST reports/{report_id}/download-tickets": {
		Method: "POST", Pattern: "reports/{report_id}/download-tickets", Domain: "reports",
		Summary:     "签发一次性报告下载票据",
		Description: "为指定报告的指定格式签发一次性短期下载票据（reports.export 敏感策略 + 确认）。token 只在本次响应返回一次，不在日志/审计出现。",
		Permissions: []string{"reports.export"},
		Sensitive:   true,
		Confirm:     true,
		Download:    "ticket-issue",
		Path:        []AdminParam{adminParam("report_id", "报告编号。")},
		Body: []AdminField{
			adminConfirmField(),
			AdminField{Name: "format", Type: "string", Required: true, Enum: adminReportFormats,
				Description: "下载格式；必须是该报告实际生成的格式，否则返回 400/409。"},
		},
		Success: "object",
		ExtraKeys: []string{
			"ticket:object",
		},
		Notes: []string{
			"票据 token 一次性：兑换成功即失效；过期、已兑换或授权被撤销后兑换被拒绝。",
			"票据绑定报告/格式/调用者与签发时刻的授权结论；兑换时再次授权并重新检查产物状态。",
			"响应不包含服务器路径；下载通过 POST /reports/download-tickets/redeem 流式返回。",
		},
	},
	"POST reports/download-tickets/redeem": {
		Method: "POST", Pattern: "reports/download-tickets/redeem", Domain: "reports",
		Summary:     "兑换报告下载票据（流式下载）",
		Description: "消费一次性票据并流式返回受控产物字节；兑换时再次授权并重新检查产物状态，重复兑换/撤权后兑换被拒绝。",
		Permissions: []string{"reports.export"},
		Download:    "ticket-redeem",
		Body: []AdminField{
			adminBodySecret("token", "一次性下载票据（只写；示例为合成值，不可用于真实下载）。", 512),
		},
		Success: "download",
		Notes: []string{
			"成功响应不是 JSON 信封：返回 200 + 受控文件字节（Content-Disposition 使用稳定文件名，不含宿主路径）。",
			"票据过期/已用/授权撤销返回 400/403/409，不返回空文件假成功。",
		},
	},
	"POST reports/{report_id}/cancel": {
		Method: "POST", Pattern: "reports/{report_id}/cancel", Domain: "reports",
		Summary:     "取消报告生成任务",
		Description: "取消进行中的报告生成（确认 + 原因）；accepted 只表示受理取消，终态以报告/任务状态为准。",
		Permissions: []string{"reports.read"},
		Cancelable:  true,
		Async:       true,
		Confirm:     true,
		Reason:      true,
		Path:        []AdminParam{adminParam("report_id", "报告编号。")},
		Body:        []AdminField{adminConfirmField(), adminReasonField()},
		Success:     "AdminCancelResult",
		Notes:       []string{"取消不删除既有产物；已完成的报告不可被“取消”改写为失败。"},
	},
	"POST reports/{report_id}/retry": {
		Method: "POST", Pattern: "reports/{report_id}/retry", Domain: "reports",
		Summary:     "重试报告生成",
		Description: "对失败的报告按原计划/参数重新提交生成（reports.generate 敏感策略 + 确认 + 原因）；返回新的报告视图，受理≠完成。",
		Permissions: []string{"reports.generate"},
		Sensitive:   true,
		Confirm:     true,
		Reason:      true,
		Async:       true,
		Path:        []AdminParam{adminParam("report_id", "待重试的报告编号。")},
		Body:        []AdminField{adminConfirmField(), adminReasonField()},
		Success:     "object",
		ExtraKeys:   []string{"report:ref:AdminReportView"},
		Notes:       []string{"重试生成新任务；旧报告的终态与审计保持可追溯。"},
	},
	"GET reports/cleanup-preview": {
		Method: "GET", Pattern: "reports/cleanup-preview", Domain: "reports",
		Summary:     "报告清理预演（只读）",
		Description: "只读预演将清理的过期报告产物与释放空间；不删除任何文件，不代表已清理。",
		Permissions: []string{"reports.cleanup"},
		Success:     "object",
		ExtraKeys:   []string{"cleanup_preview:ref:AdminReportCleanupPreview"},
	},
	"POST reports/cleanup": {
		Method: "POST", Pattern: "reports/cleanup", Domain: "reports",
		Summary:     "执行报告清理",
		Description: "清理过期报告产物（reports.cleanup 敏感策略 + 确认 + 原因 + 有界目标数）；返回真实清理计数与失败明细。",
		Permissions: []string{"reports.cleanup"},
		Sensitive:   true,
		Confirm:     true,
		Reason:      true,
		Body: []AdminField{
			adminConfirmField(),
			adminReasonField(),
			AdminField{Name: "max_targets", Type: "integer",
				Description: "本次最多清理目标数（服务端有硬上限，超出拒绝）。"},
		},
		Success: "object",
		ExtraKeys: []string{
			"cleanup_result:ref:AdminReportCleanupResult",
		},
		Notes: []string{"清理结果区分 cleaned/failed/skipped；失败不伪装成功，原始审计保留。"},
	},
}

// adminPlanOperations 是 plans 域契约（报告计划 + 备份计划）。
var adminPlanOperations = map[string]AdminOperation{
	"GET report-plans": {
		Method: "GET", Pattern: "report-plans", Domain: "plans",
		Summary:     "分页查询报告计划",
		Description: "按 reports.schedule.manage 分页查询报告生成计划；支持有界字面搜索（计划名称/编号）。",
		Permissions: []string{"reports.schedule.manage"},
		Query: append(adminPaginationQuery(),
			adminSearchQuery("name 等许可字段（服务端白名单）")...),
		Success:   "list:plans:AdminReportPlan",
		ExtraKeys: []string{"next_offset"},
	},
	"POST report-plans": {
		Method: "POST", Pattern: "report-plans", Domain: "plans",
		Summary:     "创建报告计划",
		Description: "创建报告生成计划（reports.schedule.manage 敏感策略 + 确认 + 作用范围校验 + 审计）；返回创建后的计划视图。",
		Permissions: []string{"reports.schedule.manage"},
		Sensitive:   true,
		Confirm:     true,
		Body:        adminPlanWriteBody(false),
		Success:     "object",
		ExtraKeys:   []string{"plan:ref:AdminReportPlan"},
	},
	"GET report-plans/{plan_id}": {
		Method: "GET", Pattern: "report-plans/{plan_id}", Domain: "plans",
		Summary:     "读取报告计划",
		Description: "读取单个报告计划详情（含下次运行/权限状态）；越权按不存在处理。",
		Permissions: []string{"reports.schedule.manage"},
		Path:        []AdminParam{adminParam("plan_id", "报告计划编号。")},
		Success:     "object",
		ExtraKeys:   []string{"plan:ref:AdminReportPlan"},
	},
	"PUT report-plans/{plan_id}": {
		Method: "PUT", Pattern: "report-plans/{plan_id}", Domain: "plans",
		Summary:     "更新报告计划",
		Description: "按行版本乐观并发更新报告计划（敏感策略 + 确认 + 原因）；version 不一致返回 409，需重新读取。",
		Permissions: []string{"reports.schedule.manage"},
		Sensitive:   true,
		Confirm:     true,
		Path:        []AdminParam{adminParam("plan_id", "报告计划编号。")},
		Body:        adminPlanWriteBody(true),
		Success:     "object",
		ExtraKeys:   []string{"plan:ref:AdminReportPlan"},
	},
	"POST report-plans/{plan_id}/enabled": {
		Method: "POST", Pattern: "report-plans/{plan_id}/enabled", Domain: "plans",
		Summary:     "启停报告计划",
		Description: "启用/停用报告计划（敏感策略 + 确认 + 原因）；启停改变实际执行范围，原因进入真实审计。",
		Permissions: []string{"reports.schedule.manage"},
		Sensitive:   true,
		Confirm:     true,
		Reason:      true,
		Path:        []AdminParam{adminParam("plan_id", "报告计划编号。")},
		Body: []AdminField{
			adminConfirmField(),
			adminBody("enabled", "boolean", "true 启用 / false 停用。"),
			adminReasonField(),
		},
		Success:   "object",
		ExtraKeys: []string{"plan:ref:AdminReportPlan"},
	},
	"GET report-plans/{plan_id}/delete-preview": {
		Method: "GET", Pattern: "report-plans/{plan_id}/delete-preview", Domain: "plans",
		Summary:     "报告计划删除预演（只读）",
		Description: "只读预演删除计划的影响（活动任务/历史/不可逆说明）；预览不是删除授权。",
		Permissions: []string{"reports.schedule.manage"},
		Path:        []AdminParam{adminParam("plan_id", "报告计划编号。")},
		Success:     "object",
		ExtraKeys:   []string{"delete_preview:ref:AdminPlanDeletePreview"},
	},
	"DELETE report-plans/{plan_id}": {
		Method: "DELETE", Pattern: "report-plans/{plan_id}", Domain: "plans",
		Summary:     "删除报告计划",
		Description: "删除报告计划（敏感策略 + 确认 + 原因）；历史报告与原始审计不随计划删除而消失。",
		Permissions: []string{"reports.schedule.manage"},
		Sensitive:   true,
		Confirm:     true,
		Reason:      true,
		Path:        []AdminParam{adminParam("plan_id", "报告计划编号。")},
		Body:        []AdminField{adminConfirmField(), adminReasonField()},
		Success:     "AdminDeletedArtifact",
	},
	"GET backups/schedules": {
		Method: "GET", Pattern: "backups/schedules", Domain: "plans",
		Summary:     "分页查询备份计划",
		Description: "按 backups.read 分页查询备份计划（含下次运行/权限状态）。",
		Permissions: []string{"backups.read"},
		Query:       adminPaginationQuery(),
		Success:     "list:schedules:AdminBackupSchedule",
		ExtraKeys:   []string{"next_offset"},
	},
	"GET backups/schedules/{schedule_id}": {
		Method: "GET", Pattern: "backups/schedules/{schedule_id}", Domain: "plans",
		Summary:     "读取备份计划",
		Description: "读取单个备份计划详情。",
		Permissions: []string{"backups.read"},
		Path:        []AdminParam{adminParam("schedule_id", "备份计划编号。")},
		Success:     "object",
		ExtraKeys:   []string{"schedule:ref:AdminBackupSchedule"},
	},
	"POST backups/schedules": {
		Method: "POST", Pattern: "backups/schedules", Domain: "plans",
		Summary:     "创建备份计划",
		Description: "创建备份计划（backups.create 敏感策略 + 确认 + 审计）；返回创建后的计划视图。",
		Permissions: []string{"backups.create"},
		Sensitive:   true,
		Confirm:     true,
		Body:        adminBackupScheduleBody(),
		Success:     "object",
		ExtraKeys:   []string{"schedule:ref:AdminBackupSchedule"},
	},
	"PUT backups/schedules/{schedule_id}": {
		Method: "PUT", Pattern: "backups/schedules/{schedule_id}", Domain: "plans",
		Summary:     "更新备份计划",
		Description: "按行版本/保留版本更新备份计划（敏感策略 + 确认）；版本冲突返回 409。",
		Permissions: []string{"backups.create"},
		Sensitive:   true,
		Confirm:     true,
		Path:        []AdminParam{adminParam("schedule_id", "备份计划编号。")},
		Body:        adminBackupScheduleBody(),
		Success:     "object",
		ExtraKeys:   []string{"schedule:ref:AdminBackupSchedule"},
	},
	"POST backups/schedules/{schedule_id}/enabled": {
		Method: "POST", Pattern: "backups/schedules/{schedule_id}/enabled", Domain: "plans",
		Summary:     "启停备份计划",
		Description: "启用/停用备份计划（敏感策略 + 确认 + 原因）；原因进入真实审计。",
		Permissions: []string{"backups.create"},
		Sensitive:   true,
		Confirm:     true,
		Reason:      true,
		Path:        []AdminParam{adminParam("schedule_id", "备份计划编号。")},
		Body: []AdminField{
			adminConfirmField(),
			adminBody("enabled", "boolean", "true 启用 / false 停用。"),
			adminReasonField(),
		},
		Success:   "object",
		ExtraKeys: []string{"schedule:ref:AdminBackupSchedule"},
	},
	"DELETE backups/schedules/{schedule_id}": {
		Method: "DELETE", Pattern: "backups/schedules/{schedule_id}", Domain: "plans",
		Summary:     "删除备份计划",
		Description: "删除备份计划（敏感策略 + 确认 + 原因）；已生成的备份产物不随计划删除而删除。",
		Permissions: []string{"backups.create"},
		Sensitive:   true,
		Confirm:     true,
		Reason:      true,
		Path:        []AdminParam{adminParam("schedule_id", "备份计划编号。")},
		Body:        []AdminField{adminConfirmField(), adminReasonField()},
		Success:     "AdminDeletedArtifact",
	},
}

// adminPlanWriteBody 构造报告计划创建/更新请求体（update 时额外要求 version）。
func adminPlanWriteBody(update bool) []AdminField {
	fields := []AdminField{
		adminConfirmField(),
		adminBody("name", "string", "计划名称（用户文本，不拼接 HTML）。"),
		adminBody("scope_id", "string", "作用范围：system 或应用编号；必须在调用者可管理范围内。"),
		adminBody("schedule_type", "string", "调度类型（服务端白名单：cron/固定周期等）。"),
		adminBody("expression", "string", "调度表达式（按 schedule_type 解析，非法返回 400）。"),
		AdminField{Name: "time_zone", Type: "string", Description: "IANA 时区，例如 Asia/Shanghai；空使用服务端默认。"},
		AdminField{Name: "app_id", Type: "string", Description: "应用范围时的目标应用编号（与 scope_id 一致校验）。"},
		AdminField{Name: "granularity", Type: "string", Description: "统计粒度（服务端枚举）。"},
		AdminField{Name: "window_days", Type: "integer", Description: "统计窗口天数（服务端范围校验）。"},
		AdminField{Name: "categories", Type: "array", Description: "报告分类（服务端白名单）。"},
		AdminField{Name: "trend_metric", Type: "string", Description: "趋势指标（服务端枚举）。"},
		AdminField{Name: "formats", Type: "array", Description: "输出格式列表（html/csv/json/pdf/markdown，至少一种）。"},
		AdminField{Name: "detail_rows", Type: "integer", Description: "明细行数上限（服务端硬上限）。"},
		AdminField{Name: "missed_policy", Type: "string", Description: "错过调度策略（skip/catch_up 等，服务端枚举）。"},
		AdminField{Name: "max_catch_up", Type: "integer", Description: "最大补跑次数。"},
		AdminField{Name: "timeout_seconds", Type: "integer", Description: "单次生成超时秒数（服务端范围）。"},
		AdminField{Name: "max_attempts", Type: "integer", Description: "最大尝试次数。"},
		adminBodyOptional("enabled", "boolean", "创建后是否立即启用；默认按服务端策略。"),
		adminRequestIDField(),
		AdminField{Name: "reason", Type: "string", Description: "更新/审计说明（可选；创建不需要）。"},
	}
	if update {
		fields = append(fields, adminBody("version", "integer",
			"读取时的行版本；必须 >0，版本不一致返回 409（乐观并发）。"))
	}
	return fields
}

// adminBackupScheduleBody 构造备份计划创建/更新请求体。
func adminBackupScheduleBody() []AdminField {
	return []AdminField{
		adminConfirmField(),
		adminBody("name", "string", "备份计划名称。"),
		adminBody("schedule_type", "string", "调度类型（服务端白名单）。"),
		adminBody("expression", "string", "调度表达式（非法返回 400）。"),
		AdminField{Name: "time_zone", Type: "string", Description: "IANA 时区；空使用服务端默认。"},
		AdminField{Name: "missed_policy", Type: "string", Description: "错过调度策略（skip/catch_up 等）。"},
		AdminField{Name: "max_catch_up", Type: "integer", Description: "最大补跑次数。"},
		AdminField{Name: "timeout_seconds", Type: "integer", Description: "单次备份超时秒数。"},
		AdminField{Name: "max_attempts", Type: "integer", Description: "最大尝试次数。"},
		adminBody("retention_version", "integer", "读取到的备份保留策略版本；用于绑定保留语义。"),
		adminBodyOptional("notify_failures", "boolean", "失败时是否发送安全告知。"),
		adminBodyOptional("notify_success", "boolean", "成功时是否发送安全告知。"),
		AdminField{Name: "notify_target", Type: "string", Description: "告知目标（服务端白名单渠道；不包含凭据）。"},
		adminBodyOptional("enabled", "boolean", "创建后是否立即启用。"),
		adminRequestIDField(),
		AdminField{Name: "reason", Type: "string", Description: "审计说明（可选）。"},
	}
}

// 注册到全局契约表。
func init() {
	adminOperationGroups["reports"] = adminReportOperations
	adminOperationGroups["plans"] = adminPlanOperations
}
