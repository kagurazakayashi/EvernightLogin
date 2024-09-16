package transport

// 本文件登记 backups 域（备份产物/任务/下载票据/保留策略/清理）的管理 API 契约。
// 下载票据语义：签发一次性短期 token（只返回一次），兑换时再次授权并重新检查产物
// 状态与保留保护；响应只输出受控文件字节，绝不把宿主路径当下载地址。

// adminBackupOperations 是 backups 域契约。
var adminBackupOperations = map[string]AdminOperation{
	"GET backups": {
		Method: "GET", Pattern: "backups", Domain: "backups",
		Summary:     "分页查询备份产物",
		Description: "按 backups.read 分页查询备份产物元数据（大小/摘要/内容范围/校验状态/保留与可下载状态）；不返回宿主路径。",
		Permissions: []string{"backups.read"},
		Query: append(adminPaginationQuery(),
			adminQuery("schedule_id", "按备份计划编号筛选。"),
			adminQuery("job_id", "按备份任务编号筛选。"),
			adminQuery("origin", "按来源筛选（manual/schedule 等，服务端枚举）。"),
			adminQuery("verification", "按校验状态筛选（服务端枚举）。"),
			adminQuery("cleanup", "按清理状态筛选（服务端枚举）。")),
		Success: "list:backups:AdminBackupArtifact",
	},
	"GET backups/{backup_id}": {
		Method: "GET", Pattern: "backups/{backup_id}", Domain: "backups",
		Summary:     "读取备份产物",
		Description: "读取单个备份产物元数据（含校验状态、保留保护与可下载性）。",
		Permissions: []string{"backups.read"},
		Path:        []AdminParam{adminParam("backup_id", "备份产物编号。")},
		Success:     "object",
		ExtraKeys:   []string{"backup:ref:AdminBackupArtifact"},
	},
	"GET backups/capabilities": {
		Method: "GET", Pattern: "backups/capabilities", Domain: "backups",
		Summary:     "读取备份能力",
		Description: "读取当前部署的备份能力（读/建/取消/下载/保留/清理）与下载票据有效期秒数。",
		Permissions: []string{"backups.read"},
		Success:     "object",
		ExtraKeys:   []string{"capabilities:ref:AdminBackupCapabilities"},
	},
	"GET backups/jobs": {
		Method: "GET", Pattern: "backups/jobs", Domain: "backups",
		Summary:     "分页查询备份任务",
		Description: "分页查询备份/清理任务（真实状态、阶段、进度与通知状态）；进度不表示成功。",
		Permissions: []string{"backups.read"},
		Query: append(adminPaginationQuery(),
			adminQuery("kind", "任务类型筛选（备份/清理等，服务端枚举）。"),
			adminQuery("schedule_id", "按计划编号筛选。")),
		Success: "list:jobs:AdminBackupJob",
	},
	"GET backups/jobs/{job_id}": {
		Method: "GET", Pattern: "backups/jobs/{job_id}", Domain: "backups",
		Summary:     "读取备份任务",
		Description: "读取单个备份/清理任务详情（阶段、进度、尝试、通知状态、错误码）。",
		Permissions: []string{"backups.read"},
		Path:        []AdminParam{adminParam("job_id", "备份/清理任务编号。")},
		Success:     "object",
		ExtraKeys:   []string{"job:ref:AdminBackupJob"},
	},
	"POST backups": {
		Method: "POST", Pattern: "backups", Domain: "backups",
		Summary:     "提交备份任务",
		Description: "提交一次备份（backups.create 敏感策略 + 确认）；受理/去重成功不等于备份完成，需按 job_id 查询真实终态。",
		Permissions: []string{"backups.create"},
		Sensitive:   true,
		Confirm:     true,
		Async:       true,
		Body: []AdminField{
			adminConfirmField(),
			adminRequestIDField(),
		},
		Success: "object",
		ExtraKeys: []string{
			"job:ref:AdminBackupCreateResult",
		},
		Notes: []string{"existing=true 表示命中活动任务去重，未重复创建；状态以任务真实状态为准。"},
	},
	"POST backups/jobs/{job_id}/cancel": {
		Method: "POST", Pattern: "backups/jobs/{job_id}/cancel", Domain: "backups",
		Summary:     "取消备份任务",
		Description: "请求取消备份/清理任务（backups.cancel + 确认 + 原因）；accepted 只表示受理取消，终态以任务状态为准。",
		Permissions: []string{"backups.cancel"},
		Cancelable:  true,
		Async:       true,
		Confirm:     true,
		Reason:      true,
		Path:        []AdminParam{adminParam("job_id", "备份/清理任务编号。")},
		Body:        []AdminField{adminConfirmField(), adminReasonField()},
		Success:     "object",
		ExtraKeys:   []string{"cancel:ref:AdminBackupCancelResult"},
	},
	"POST backups/{backup_id}/download-tickets": {
		Method: "POST", Pattern: "backups/{backup_id}/download-tickets", Domain: "backups",
		Summary:     "签发一次性备份下载票据",
		Description: "为指定备份签发一次性短期下载票据（backups.export 敏感策略 + 确认）；token 只在本次响应返回一次，不写入日志/审计。",
		Permissions: []string{"backups.export"},
		Sensitive:   true,
		Confirm:     true,
		Download:    "ticket-issue",
		Path:        []AdminParam{adminParam("backup_id", "备份产物编号。")},
		Body: []AdminField{
			adminConfirmField(),
			adminRequestIDField(),
		},
		Success: "object",
		ExtraKeys: []string{
			"ticket:ref:AdminBackupTicket",
		},
		Notes: []string{
			"票据短期有效（有效期见 GET /backups/capabilities 的 download_ttl_seconds），一次性消费。",
			"兑换路径：POST /backups/download-tickets/redeem；兑换时再次授权并重新检查产物状态与保留保护。",
			"响应不含服务器路径；不要把它当可分享的下载地址。",
		},
	},
	"POST backups/download-tickets/redeem": {
		Method: "POST", Pattern: "backups/download-tickets/redeem", Domain: "backups",
		Summary:     "兑换备份下载票据（流式下载）",
		Description: "消费一次性备份下载票据并流式返回受控备份字节；兑换时再次授权并重新检查产物状态，重复兑换/撤权后兑换被拒绝。",
		Permissions: []string{"backups.export"},
		Download:    "ticket-redeem",
		Body: []AdminField{
			adminBodySecret("token", "一次性下载票据（只写；示例为合成值，不可用于真实下载）。", 512),
		},
		Success: "download",
		Notes: []string{
			"成功响应不是 JSON 信封：200 + 受控文件字节（Content-Disposition 使用稳定文件名，不含宿主路径）。",
			"票据过期/已用/授权撤销返回 400/403/409，不返回空文件假成功。",
		},
	},
	"GET backups/retention": {
		Method: "GET", Pattern: "backups/retention", Domain: "backups",
		Summary:     "读取备份保留策略",
		Description: "读取备份保留策略（数量/天数/字节上限、版本、最近清理摘要）。",
		Permissions: []string{"backups.read"},
		Success:     "object",
		ExtraKeys:   []string{"retention:ref:AdminBackupRetention"},
	},
	"PUT backups/retention": {
		Method: "PUT", Pattern: "backups/retention", Domain: "backups",
		Summary:     "更新备份保留策略",
		Description: "更新备份保留策略（敏感策略 + 确认 + 原因 + 版本乐观并发）；不按旧预览强删，清理在执行时重新计算候选与保护状态。",
		Permissions: []string{"backups.retention"},
		Sensitive:   true,
		Confirm:     true,
		Reason:      true,
		Body: []AdminField{
			adminConfirmField(),
			adminBody("max_count", "integer", "最多保留备份数量；0 表示不设该维度上限（受服务端策略约束）。"),
			adminBody("max_age_days", "integer", "最长保留天数；0 表示不设该维度上限（受服务端策略约束）。"),
			adminBody("max_total_bytes", "integer", "保留总字节上限；0 表示不设该维度上限（受服务端策略约束）。"),
			adminBody("expected_version", "integer", "期望的当前策略版本；版本不一致返回 409。"),
			adminReasonField(),
		},
		Success:   "object",
		ExtraKeys: []string{"retention:ref:AdminBackupRetention"},
	},
	"GET backups/cleanup-preview": {
		Method: "GET", Pattern: "backups/cleanup-preview", Domain: "backups",
		Summary:     "备份清理预演（只读）",
		Description: "只读预演将清理的备份与受保留策略保护的目标；预览不是清理授权，执行时重新计算。",
		Permissions: []string{"backups.read"},
		Success:     "object",
		ExtraKeys:   []string{"cleanup_preview:ref:AdminBackupCleanupPreview"},
	},
	"POST backups/cleanup": {
		Method: "POST", Pattern: "backups/cleanup", Domain: "backups",
		Summary:     "提交备份清理任务",
		Description: "提交清理任务（backups.create 敏感策略 + 确认）；执行时重新计算候选与保护状态，受理≠完成。",
		Permissions: []string{"backups.create"},
		Sensitive:   true,
		Confirm:     true,
		Async:       true,
		Body: []AdminField{
			adminConfirmField(),
			adminRequestIDField(),
		},
		Success: "object",
		ExtraKeys: []string{
			"job:ref:AdminBackupCreateResult",
		},
		Notes: []string{"原始安全审计不受清理影响；受保护/最后可用备份不会被清理。"},
	},
}

// 注册到全局契约表。
func init() {
	adminOperationGroups["backups"] = adminBackupOperations
}
