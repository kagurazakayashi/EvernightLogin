package ui

// builtinStatsMessages 是步骤 76 统计看板页面处理器 error summary、字段错误与内联
// SVG 图表可访问标题/摘要/轴标签使用的中文基线文案。模板静态文案仍走 i18n 键，
// 后续语言目录可覆盖这些摘要文本；本文件只补 text() 的 zh-CN 兜底，避免用户看到
// 原始键名（模板键已注册在 web/i18n/zh-CN.json）。
var builtinStatsMessages = map[string]string{
	"page.admin.statistics.activity_title":               "成功认证去重活跃用户",
	"page.admin.statistics.category.cancelled":           "主动取消",
	"page.admin.statistics.category.denied":              "正常拒绝",
	"page.admin.statistics.category.failure":             "故障",
	"page.admin.statistics.category.pending":             "等待授权",
	"page.admin.statistics.category.unknown":             "其他或未分类",
	"page.admin.statistics.category.warning":             "警告",
	"page.admin.statistics.chart.active_y":               "成功认证去重用户数",
	"page.admin.statistics.chart_summary":                "本图与下方数据表使用同一时间区间、时区、应用范围和统计截止点；缺失区间断线显示，不插值、不补零。",
	"page.admin.statistics.common.forbidden":             "你没有权限查看此范围内的统计数据。",
	"page.admin.statistics.error_trend_title":            "错误趋势",
	"page.admin.statistics.filter.invalid_page":          "分页参数无效，请重新发起查询。",
	"page.admin.statistics.filter.invalid_range":         "结束日期必须不早于开始日期。",
	"page.admin.statistics.filter.invalid_scope":         "所选统计范围不在你的权限范围内。",
	"page.admin.statistics.filter.invalid_summary":       "筛选条件有误，请检查后重试。",
	"page.admin.statistics.filter.invalid_time":          "日期格式无效，请使用 YYYY-MM-DD。",
	"page.admin.statistics.filter.invalid_timezone":      "时区不在服务端支持的列表内，请重新选择。",
	"page.admin.statistics.filter.invalid_value":         "该项取值未登记，请重新选择。",
	"page.admin.statistics.filter.range_too_large":       "自定义时间范围超过服务端允许的最大跨度，请缩小范围。",
	"page.admin.statistics.granularity.day":              "按自然日",
	"page.admin.statistics.granularity.month":            "按自然月",
	"page.admin.statistics.granularity.week":             "按自然周（周一起始）",
	"page.admin.statistics.metric.dedup_failed_requests": "去重失败请求数",
	"page.admin.statistics.metric.dedup_failed_tasks":    "去重失败任务数",
	"page.admin.statistics.metric.raw_events":            "原始错误事件次数",
	"page.admin.statistics.module.backup":                "备份",
	"page.admin.statistics.module.certificate":           "证书",
	"page.admin.statistics.module.database":              "数据库",
	"page.admin.statistics.module.requests_errors":       "请求与错误",
	"page.admin.statistics.module.service":               "服务健康",
	"page.admin.statistics.module.tasks_notifications":   "任务与通知",
	"page.admin.statistics.module.unknown":               "未登记模块",
	"page.admin.statistics.range.custom":                 "自定义日期范围",
	"page.admin.statistics.scope.app":                    "应用",
	"page.admin.statistics.scope.system":                 "全部可查看应用",
	"page.admin.statistics.severity.critical":            "严重级",
	"page.admin.statistics.severity.error":               "故障级",
	"page.admin.statistics.severity.info":                "信息级",
	"page.admin.statistics.severity.unknown":             "未知",
	"page.admin.statistics.severity.warning":             "告警级",
	"page.admin.statistics.state.degraded":               "降级",
	"page.admin.statistics.state.healthy":                "正常",
	"page.admin.statistics.state.not_enabled":            "未启用",
	"page.admin.statistics.state.unavailable":            "不可用",
	"page.admin.statistics.state.unknown":                "未知",
	"page.admin.statistics.status.complete":              "完整",
	"page.admin.statistics.status.in_progress":           "进行中",
	"page.admin.statistics.status.not_enabled":           "未启用",
	"page.admin.statistics.status.partial":               "部分（来源截断或覆盖不完整）",
	"page.admin.statistics.status.unknown":               "未知（暂无可用数据）",
	"page.admin.statistics_errors.growth.new":            "新增",
	"page.admin.statistics_errors.growth.none":           "无变化",
	"page.admin.statistics_errors.growth.unavailable":    "比较数据不完整",
	"page.admin.statistics_errors.sort.first_seen":       "按首次发生时间排序",
	"page.admin.statistics_errors.sort.growth":           "按增幅排序",
	"page.admin.statistics_errors.sort.last_seen":        "按最近发生时间排序",
	"page.admin.statistics_errors.sort.raw_events":       "按原始事件次数排序",
	"page.admin.statistics_errors.sort.share":            "按占比排序",
	"page.admin.statistics.dashboard.load_failed":        "无法读取统计看板，请稍后重试。",
	"page.admin.statistics.statistics.load_failed":       "无法读取活跃度与错误趋势，请稍后重试。",
	"page.admin.statistics.errors.load_failed":           "无法读取错误分类明细，请稍后重试。",
}

func init() {
	for key, message := range builtinStatsMessages {
		if _, exists := builtinAuthMessages[key]; !exists {
			builtinAuthMessages[key] = message
		}
	}
}
