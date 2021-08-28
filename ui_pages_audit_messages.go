package login

// builtinAuditMessages 是步骤 74 页面处理器 error summary 与字段错误使用的中文基线文案；
// 模板静态文案仍走 i18n 键，后续语言目录可覆盖摘要文本。
var builtinAuditMessages = map[string]string{
	"audit.outcome.success":                          "成功",
	"audit.outcome.failure":                          "失败",
	"audit.outcome.denied":                           "已拒绝",
	"audit.outcome.unknown":                          "未知结果",
	"audit.actor_kind.user":                          "用户",
	"audit.actor_kind.system":                        "系统任务",
	"audit.actor_kind.local_admin":                   "本地管理员",
	"audit.actor_kind.anonymous":                     "匿名尝试",
	"audit.actor_kind.unknown":                       "未知操作者",
	"page.account.activity.load_failed":              "安全活动加载失败",
	"page.admin.audit.common.conflict":               "状态或版本已变化，请重新读取后再操作",
	"page.admin.audit.common.csrf_invalid":           "表单安全令牌无效或已过期，请刷新页面后重试。",
	"page.admin.audit.common.forbidden":              "服务端已拒绝访问",
	"page.admin.audit.common.forbidden_help":         "当前账户或应用范围不能查看此内容；可切换到已授权应用、完成要求的认证或申请相应权限。",
	"page.admin.audit.common.rate_limited":           "请求过于频繁，请稍后再试。",
	"page.admin.audit.common.reauth_required":        "需要完成再次认证后才能继续",
	"page.admin.audit.common.unavailable":            "存储或审计服务暂时不可用，请稍后重试。",
	"page.admin.audit.detail.load_failed":            "审计详情加载失败",
	"page.admin.audit.detail.not_found":              "未找到该记录",
	"page.admin.audit.detail.not_found_help":         "请核对编号与查询时间；记录也可能已按保留策略清理。",
	"page.admin.audit.detail.redacted":               "已隐藏敏感值",
	"page.admin.audit.detail.retention_expired":      "该记录可能已超过保留期",
	"page.admin.audit.detail.retention_expired_help": "请核对保留策略并调整查询时间；不能承诺可从本页面恢复。",
	"page.admin.audit.detail.stale":                  "该记录已超过保留期但仍未清理；它可能在后续清理中被删除。",
	"page.admin.audit.detail.undisclosed":            "无法说明该记录是否存在",
	"page.admin.audit.detail.undisclosed_help":       "当前请求未获披露许可；请返回获准列表、核对上下文或联系管理员。",
	"page.admin.audit.errors.load_failed":            "错误码检索失败",
	"page.admin.audit.export.cancel_failed":          "取消请求未成功；请刷新查看真实状态，不要重复提交。",
	"page.admin.audit.export.cancel_invalid":         "取消原因不能为空且不能超过 256 字节",
	"page.admin.audit.export.download_failed":        "下载未完成；任务状态没有被改为失败。",
	"page.admin.audit.export.download_missing":       "缺少导出任务编号",
	"page.admin.audit.export.failed":                 "导出任务创建失败",
	"page.admin.audit.export.invalid_format":         "不支持的导出格式",
	"page.admin.audit.export.submitted":              "导出任务已提交，任务编号为 {task_id}；尚未执行完成。",
	"page.admin.audit.exports.load_failed":           "导出任务加载失败",
	"page.admin.audit.filter.invalid_event_id":       "缺少有效的事件编号",
	"page.admin.audit.filter.invalid_help":           "请修正标出的字段后重新查询；不合法的筛选不会被静默忽略。",
	"page.admin.audit.filter.invalid_page":           "分页参数超出允许范围",
	"page.admin.audit.filter.invalid_range":          "结束日期必须晚于开始日期",
	"page.admin.audit.filter.invalid_request_id":     "请求编号格式不正确",
	"page.admin.audit.filter.invalid_summary":        "筛选条件未通过校验",
	"page.admin.audit.filter.invalid_task_id":        "任务编号格式不正确",
	"page.admin.audit.filter.invalid_time":           "日期格式应为 YYYY-MM-DD",
	"page.admin.audit.filter.invalid_value":          "该字段取值不在允许范围内",
	"page.admin.audit.list.load_failed":              "审计记录加载失败",
	"page.admin.audit.maintenance.cancel_failed":     "取消请求未成功；请刷新查看真实状态。",
	"page.admin.audit.maintenance.cancel_invalid":    "取消原因不能为空且不能超过 256 字节",
	"page.admin.audit.maintenance.forbidden":         "只有 root 可以进入审计清理",
	"page.admin.audit.maintenance.invalid_batch":     "每批条数应在 1～5000 之间",
	"page.admin.audit.maintenance.invalid_cutoff":    "截止时间格式应为 YYYY-MM-DD 且不能为空",
	"page.admin.audit.maintenance.invalid_max":       "最多删除条数应在 1～1000000 之间",
	"page.account.activity.scope_self":               "仅限你本人的安全活动记录",
	"page.admin.audit.maintenance.invalid_reason":    "清理原因不能为空且不能超过 256 字节",
	"page.admin.audit.maintenance.load_failed":       "清理页面加载失败",
	"page.admin.audit.maintenance.preview_failed":    "清理预估失败",
	"page.admin.audit.maintenance.stale_preview":     "本次确认摘要缺失或已过期，请重新预估后再提交。",
	"page.admin.audit.maintenance.start_failed":      "清理任务未能提交",
}

func init() {
	for key, message := range builtinAuditMessages {
		if _, exists := builtinAuthMessages[key]; !exists {
			builtinAuthMessages[key] = message
		}
	}
}
