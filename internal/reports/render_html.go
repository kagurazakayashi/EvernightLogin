package reports

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"math"
	"strconv"
)

// renderJSON 把快照渲染为稳定 schema 的 JSON。数值字段是 JSON 数字（int64），
// 时间字段是 UTC RFC3339 字符串（见 schema.time_format）；不可用增幅省略 percent
// 而不是写 0，缺失状态用字符串表达。
func renderJSON(snapshot Snapshot) ([]byte, error) {
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("%w: JSON 序列化失败", ErrInvalidRequest)
	}
	data = append(data, '\n')
	return data, nil
}

// htmlView 是 HTML 模板的渲染视图：预格式化数字/状态文本，避免模板里做计算。
type htmlView struct {
	Snapshot      Snapshot
	GeneratedAt   string
	WindowStart   string
	WindowEnd     string
	DataCutoff    string
	RequestedBy   string
	OverallText   string
	OverallClass  string
	ActivityChart template.HTML
	ActivityBars  []htmlActivityBar
	CategoryChart template.HTML
	CategoryRows  []htmlCategoryRow
	ErrorRows     []htmlErrorRow
	TrendPoints   int
	TrendTotals   string
	Metrics       []htmlMetricRow
	Notes         []string
}

// htmlActivityBar 是活跃度数据表一行。
type htmlActivityBar struct {
	Bucket   string
	Start    string
	End      string
	Active   string
	Status   string
	StatusCl string
}

// htmlCategoryRow 是类别汇总表一行。
type htmlCategoryRow struct {
	Category string
	Severity string
	Raw      string
	Requests string
	Tasks    string
}

// htmlErrorRow 是错误明细表一行。
type htmlErrorRow struct {
	ErrorCode string
	Category  string
	Severity  string
	AppID     string
	Raw       string
	Requests  string
	Tasks     string
	Share     string
	FirstSeen string
	LastSeen  string
	Growth    string
	Status    string
}

// htmlMetricRow 是口径表一行。
type htmlMetricRow struct {
	Key        string
	Name       string
	Unit       string
	Definition string
}

// reportHTMLTemplate 是自包含离线 HTML 报告模板。模板只使用内联样式与内联 SVG，
// 不引用任何外部脚本、字体、图片或在线图表服务；所有动态文本由 html/template
// 自动转义。图表在 Go 中按数值坐标生成，SVG 内不嵌入任何原始事件内容。
const reportHTMLTemplate = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<title>统计报告 {{.Snapshot.Report.ID}}</title>
<style>
:root { color-scheme: light dark; }
body { margin: 0; padding: 24px; font-family: "Segoe UI", "Microsoft YaHei", "PingFang SC", system-ui, sans-serif; line-height: 1.6; color: #1f2328; background: #ffffff; }
main { max-width: 1040px; margin: 0 auto; }
h1 { font-size: 1.5rem; margin: 0 0 4px; }
h2 { font-size: 1.15rem; margin: 28px 0 8px; border-bottom: 1px solid #d0d7de; padding-bottom: 4px; }
p, li { font-size: 0.95rem; }
table { border-collapse: collapse; width: 100%; margin: 8px 0 4px; font-size: 0.9rem; }
th, td { border: 1px solid #d0d7de; padding: 4px 8px; text-align: left; vertical-align: top; }
th { background: #f6f8fa; font-weight: 600; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.meta td:first-child { width: 12rem; color: #57606a; }
.badge { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 0.85rem; }
.status-complete { background: #dafbe1; color: #116329; }
.status-partial { background: #fff8c5; color: #7d4e00; }
.status-unknown { background: #ffebe9; color: #a40e26; }
.status-in_progress { background: #ddf4ff; color: #0550ae; }
.status-not_enabled { background: #eaeef2; color: #57606a; }
.note { background: #fff8c5; border-left: 4px solid #d4a72c; padding: 8px 12px; margin: 8px 0; }
.muted { color: #57606a; font-size: 0.85rem; }
.svg-wrap { overflow-x: auto; border: 1px solid #d0d7de; border-radius: 6px; padding: 8px; background: #fbfcfd; }
footer { margin-top: 32px; border-top: 1px solid #d0d7de; padding-top: 12px; color: #57606a; font-size: 0.82rem; }
</style>
</head>
<body>
<main>
<h1>统计报告</h1>
<p class="muted">报告编号 <code>{{.Snapshot.Report.ID}}</code>，模板版本 {{.Snapshot.Schema.TemplateVersion}}，结构版本 {{.Snapshot.Schema.Version}}，时间格式 {{.Snapshot.Schema.TimeFormat}}</p>

<h2>报告元数据</h2>
<table class="meta">
<tr><td>生成时间</td><td>{{.GeneratedAt}}</td></tr>
<tr><td>发起身份</td><td>{{.RequestedBy}}</td></tr>
<tr><td>统计范围</td><td>{{.Snapshot.Report.Scope.Kind}} / <code>{{.Snapshot.Report.Scope.ID}}</code></td></tr>
<tr><td>应用筛选</td><td>{{if .Snapshot.Report.Filters.AppID}}<code>{{.Snapshot.Report.Filters.AppID}}</code>{{else}}（未限定单个应用）{{end}}</td></tr>
<tr><td>时区 / 粒度</td><td>{{.Snapshot.Report.Window.TimeZone}} / {{.Snapshot.Report.Window.Granularity}}</td></tr>
<tr><td>统计窗口</td><td>{{.WindowStart}} 至 {{.WindowEnd}}（左闭右开）</td></tr>
<tr><td>统计截止点</td><td>{{.DataCutoff}}</td></tr>
<tr><td>总体完整性</td><td><span class="badge {{.OverallClass}}">{{.OverallText}}</span></td></tr>
</table>

<h2>数据完整性说明</h2>
{{range .Notes}}<div class="note">{{.}}</div>
{{else}}<p>没有额外的完整性警告。</p>
{{end}}

<h2>口径定义</h2>
<table>
<tr><th>指标</th><th>名称</th><th>单位</th><th>口径</th></tr>
{{range .Metrics}}<tr><td><code>{{.Key}}</code></td><td>{{.Name}}</td><td>{{.Unit}}</td><td>{{.Definition}}</td></tr>
{{end}}</table>

<h2>登录活跃度</h2>
<p>窗口内成功认证去重用户数：<strong>{{.Snapshot.Activity.Total}}</strong> 人（去重口径：{{.Snapshot.Activity.DedupeScope}}）。</p>
<div class="svg-wrap">{{.ActivityChart}}</div>
<table>
<tr><th>时间桶</th><th>开始（UTC）</th><th>结束（UTC）</th><th class="num">活跃用户</th><th>数据状态</th></tr>
{{range .ActivityBars}}<tr><td>{{.Bucket}}</td><td>{{.Start}}</td><td>{{.End}}</td><td class="num">{{.Active}}</td><td><span class="badge {{.StatusCl}}">{{.Status}}</span></td></tr>
{{else}}<tr><td colspan="5">窗口内没有可展示的时间桶。</td></tr>
{{end}}</table>

<h2>错误统计</h2>
<table class="meta">
<tr><td>原始错误事件次数</td><td>{{.Snapshot.Errors.TotalRawEvents}}</td></tr>
<tr><td>去重失败请求数</td><td>{{.Snapshot.Errors.FailedRequests}}</td></tr>
<tr><td>去重失败任务数</td><td>{{.Snapshot.Errors.FailedTasks}}</td></tr>
<tr><td>占比分母（原始事件）</td><td>{{.Snapshot.Errors.ShareDenominator}}</td></tr>
</table>
<div class="svg-wrap">{{.CategoryChart}}</div>
<table>
<tr><th>类别</th><th>严重度</th><th class="num">原始事件</th><th class="num">去重失败请求</th><th class="num">去重失败任务</th></tr>
{{range .CategoryRows}}<tr><td>{{.Category}}</td><td>{{.Severity}}</td><td class="num">{{.Raw}}</td><td class="num">{{.Requests}}</td><td class="num">{{.Tasks}}</td></tr>
{{else}}<tr><td colspan="5">窗口内没有可展示的错误类别。</td></tr>
{{end}}</table>

<h2>错误明细（按原始事件次数降序，受权限与条数上限裁剪）</h2>
<table>
<tr><th>错误码</th><th>类别</th><th>严重度</th><th>应用</th><th class="num">原始事件</th><th class="num">去重请求</th><th class="num">去重任务</th><th class="num">占比</th><th>首次发生（UTC）</th><th>最近发生（UTC）</th><th>环比</th><th>状态</th></tr>
{{range .ErrorRows}}<tr><td><code>{{.ErrorCode}}</code></td><td>{{.Category}}</td><td>{{.Severity}}</td><td>{{.AppID}}</td><td class="num">{{.Raw}}</td><td class="num">{{.Requests}}</td><td class="num">{{.Tasks}}</td><td class="num">{{.Share}}</td><td>{{.FirstSeen}}</td><td>{{.LastSeen}}</td><td>{{.Growth}}</td><td>{{.Status}}</td></tr>
{{else}}<tr><td colspan="12">窗口内没有可展示的错误明细。</td></tr>
{{end}}</table>

<h2>趋势数据</h2>
<p>趋势数据点 {{.TrendPoints}} 个，指标 {{.Snapshot.Trend.Metric}}；每个数据点都来自同一统计快照，完整数值在 CSV/JSON 产物中可机器读取（本节不重复缩水）。</p>
<p class="muted">{{.TrendTotals}}</p>

<footer>
<p>本报告由服务端基于固定统计快照生成：图表与明细同源，离线打开不依赖网络资源。报告不含原始审计全量记录、凭证、令牌、密码、未脱敏堆栈或隐藏字段；明细字段按白名单与当前权限裁剪。数据缺失按“未知”标注，不按 0 处理。</p>
<p>报告生成时间 {{.GeneratedAt}}；本文件可能已过期，下载时服务端会再次鉴权并校验产物摘要。</p>
</footer>
</main>
</body>
</html>
`

// renderHTML 把快照渲染为自包含 UTF-8 HTML。
func renderHTML(snapshot Snapshot) ([]byte, error) {
	view := htmlView{
		Snapshot:     snapshot,
		GeneratedAt:  formatTime(snapshot.Report.GeneratedAt),
		WindowStart:  formatTime(snapshot.Report.Window.Start),
		WindowEnd:    formatTime(snapshot.Report.Window.End),
		DataCutoff:   formatTime(snapshot.Report.Window.DataCutoff),
		RequestedBy:  snapshot.Report.RequestedBy.Type + " / " + snapshot.Report.RequestedBy.ID,
		OverallText:  dataStatusText(string(snapshot.Overall)),
		OverallClass: dataStatusClass(string(snapshot.Overall)),
		Metrics:      make([]htmlMetricRow, 0, len(snapshot.Metrics)),
		Notes:        append([]string(nil), snapshot.Notes...),
		TrendPoints:  len(snapshot.Trend.Points),
		TrendTotals: fmt.Sprintf("趋势总计：原始事件 %d 次，去重失败请求 %d 个，去重失败任务 %d 个。",
			snapshot.Errors.TotalRawEvents, snapshot.Errors.FailedRequests,
			snapshot.Errors.FailedTasks),
	}
	for _, metric := range snapshot.Metrics {
		view.Metrics = append(view.Metrics, htmlMetricRow{Key: metric.Key,
			Name: metric.Name, Unit: metric.Unit, Definition: metric.Definition})
	}
	for _, point := range snapshot.Activity.Points {
		view.ActivityBars = append(view.ActivityBars, htmlActivityBar{
			Bucket: point.BucketKey, Start: formatTime(point.Start),
			End:    formatTime(point.End),
			Active: strconv.FormatInt(point.ActiveUsers, 10),
			Status: dataStatusText(point.Status), StatusCl: dataStatusClass(point.Status),
		})
	}
	for _, category := range snapshot.Errors.Categories {
		view.CategoryRows = append(view.CategoryRows, htmlCategoryRow{
			Category: categoryText(category.Category),
			Severity: severityText(category.Severity),
			Raw:      strconv.FormatInt(category.RawEvents, 10),
			Requests: strconv.FormatInt(category.FailedRequests, 10),
			Tasks:    strconv.FormatInt(category.FailedTasks, 10),
		})
	}
	for _, row := range snapshot.Errors.Rows {
		view.ErrorRows = append(view.ErrorRows, htmlErrorRow{
			ErrorCode: row.ErrorCode, Category: categoryText(row.Category),
			Severity: severityText(row.Severity), AppID: row.AppID,
			Raw:       strconv.FormatInt(row.RawEvents, 10),
			Requests:  strconv.FormatInt(row.FailedRequests, 10),
			Tasks:     strconv.FormatInt(row.FailedTasks, 10),
			Share:     formatPercent(row.Share),
			FirstSeen: formatTime(row.FirstSeen), LastSeen: formatTime(row.LastSeen),
			Growth: growthText(row.Growth), Status: dataStatusText(row.Status),
		})
	}
	view.ActivityChart = activityChartSVG(snapshot.Activity.Points)
	view.CategoryChart = categoryChartSVG(snapshot.Errors.Categories)
	tmpl, err := template.New("report").Parse(reportHTMLTemplate)
	if err != nil {
		return nil, fmt.Errorf("%w: HTML 模板解析失败", ErrInvalidRequest)
	}
	var buffer bytes.Buffer
	if err := tmpl.Execute(&buffer, view); err != nil {
		return nil, fmt.Errorf("%w: HTML 渲染失败", ErrInvalidRequest)
	}
	return buffer.Bytes(), nil
}

// activityChartSVG 生成内联 SVG 垂直柱状图（活跃用户按桶）。只使用数值坐标与
// 转义后的时间桶标识，不嵌入原始事件内容。
func activityChartSVG(points []ActivityPointData) template.HTML {
	const width = 960.0
	const height = 200.0
	const padding = 32.0
	if len(points) == 0 {
		return template.HTML(`<p>窗口内没有可绘制的时间桶。</p>`)
	}
	maxValue := int64(1)
	for _, point := range points {
		if point.ActiveUsers > maxValue {
			maxValue = point.ActiveUsers
		}
	}
	plotWidth := width - 2*padding
	plotHeight := height - 2*padding
	barWidth := plotWidth / float64(len(points))
	if barWidth > 24 {
		barWidth = 24
	}
	gap := (plotWidth - barWidth*float64(len(points))) / float64(len(points)+1)
	if gap < 1 {
		gap = 1
	}
	var builder bytes.Buffer
	builder.WriteString(fmt.Sprintf(`<svg width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="按时间桶的活跃用户柱状图">`,
		int(width), int(height), int(width), int(height)))
	builder.WriteString(fmt.Sprintf(`<line x1="%g" y1="%g" x2="%g" y2="%g" stroke="#8c959f" stroke-width="1"/>`,
		padding, height-padding, width-padding, height-padding))
	labelStride := 1
	if len(points) > 12 {
		labelStride = (len(points) + 11) / 12
	}
	for index, point := range points {
		x := padding + gap + float64(index)*(barWidth+gap)
		barHeight := plotHeight * float64(point.ActiveUsers) / float64(maxValue)
		y := height - padding - barHeight
		fill := "#2f81f7"
		if point.Status != "complete" {
			fill = "#d4a72c"
		}
		builder.WriteString(fmt.Sprintf(`<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" fill="%s"><title>%s: %d 人（%s）</title></rect>`,
			x, y, barWidth, barHeight, fill, html.EscapeString(point.BucketKey),
			point.ActiveUsers, html.EscapeString(dataStatusText(point.Status))))
		if index%labelStride == 0 {
			builder.WriteString(fmt.Sprintf(`<text x="%.2f" y="%.2f" font-size="10" fill="#57606a" text-anchor="middle">%s</text>`,
				x+barWidth/2, height-padding+14, html.EscapeString(point.BucketKey)))
		}
	}
	builder.WriteString(fmt.Sprintf(`<text x="%g" y="%g" font-size="11" fill="#57606a">峰值 %d 人</text>`,
		padding, padding-8, maxValue))
	builder.WriteString(`</svg>`)
	return template.HTML(builder.String())
}

// categoryChartSVG 生成内联 SVG 水平柱状图（按类别原始事件次数）。
func categoryChartSVG(categories []CategoryData) template.HTML {
	const width = 960.0
	const rowHeight = 26.0
	const padding = 110.0
	visible := make([]CategoryData, 0, len(categories))
	for _, category := range categories {
		visible = append(visible, category)
	}
	if len(visible) == 0 {
		return template.HTML(`<p>窗口内没有可绘制的错误类别。</p>`)
	}
	maxValue := int64(1)
	for _, category := range visible {
		if category.RawEvents > maxValue {
			maxValue = category.RawEvents
		}
	}
	height := rowHeight*float64(len(visible)) + rowHeight
	var builder bytes.Buffer
	builder.WriteString(fmt.Sprintf(`<svg width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="按类别的原始错误事件次数柱状图">`,
		int(width), int(height), int(width), int(height)))
	plotWidth := width - padding - 120
	for index, category := range visible {
		y := rowHeight*float64(index) + rowHeight/2
		barWidth := plotWidth * float64(category.RawEvents) / float64(maxValue)
		if barWidth < 0 {
			barWidth = 0
		}
		fill := "#cf222e"
		if category.Severity == "info" || category.Severity == "warning" {
			fill = "#bf8700"
		}
		builder.WriteString(fmt.Sprintf(`<text x="%g" y="%.2f" font-size="12" fill="#1f2328" text-anchor="end" dominant-baseline="middle">%s</text>`,
			padding-8, y, html.EscapeString(categoryText(category.Category))))
		builder.WriteString(fmt.Sprintf(`<rect x="%g" y="%.2f" width="%.2f" height="16" fill="%s"><title>%s: %d 次</title></rect>`,
			padding, y-8, barWidth, fill,
			html.EscapeString(categoryText(category.Category)), category.RawEvents))
		builder.WriteString(fmt.Sprintf(`<text x="%.2f" y="%.2f" font-size="11" fill="#57606a" dominant-baseline="middle">%d</text>`,
			padding+barWidth+6, y, category.RawEvents))
	}
	builder.WriteString(fmt.Sprintf(`<line x1="%g" y1="%g" x2="%g" y2="%g" stroke="#8c959f" stroke-width="1"/>`,
		padding, rowHeight/2, padding, height-rowHeight/2))
	builder.WriteString(`</svg>`)
	return template.HTML(builder.String())
}

// dataStatusText 把完整性状态翻译为中文，未知/缺失不得显示成“完整/0”。
func dataStatusText(status string) string {
	switch status {
	case "complete":
		return "完整"
	case "partial":
		return "部分（不完整）"
	case "in_progress":
		return "进行中（截止于统计时刻）"
	case "unknown":
		return "未知（不可当作 0）"
	case "not_enabled":
		return "未启用"
	default:
		return status
	}
}

// dataStatusClass 返回完整性状态样式类。
func dataStatusClass(status string) string {
	switch status {
	case "complete", "partial", "in_progress", "not_enabled":
		return "status-" + status
	default:
		return "status-unknown"
	}
}

// categoryText 把统计类别翻译为中文。
func categoryText(category string) string {
	switch category {
	case "pending":
		return "等待授权/待处理"
	case "denied":
		return "正常拒绝（保护生效）"
	case "cancelled":
		return "主动取消"
	case "warning":
		return "数据质量警告"
	case "failure":
		return "系统故障"
	case "unknown":
		return "未分类/未知"
	default:
		return category
	}
}

// severityText 把严重度翻译为中文。
func severityText(severity string) string {
	switch severity {
	case "info":
		return "信息"
	case "warning":
		return "告警"
	case "error":
		return "故障"
	case "critical":
		return "严重"
	case "unknown":
		return "未知"
	default:
		return severity
	}
}

// growthText 把增幅翻译为中文；不可计算绝不能显示为 0%。
func growthText(growth GrowthData) string {
	switch growth.Kind {
	case "new":
		return "新增（前期为 0）"
	case "none":
		return "无变化"
	case "percent":
		if growth.Percent == nil {
			return "—（不可计算）"
		}
		value := *growth.Percent
		if value > 0 {
			return "+" + formatFloat(math.Round(value*100)/100) + "%"
		}
		return formatFloat(math.Round(value*100)/100) + "%"
	case "unavailable":
		return "—（比较数据缺失/不完整）"
	default:
		return "—（未知）"
	}
}

// formatPercent 把占比格式化为两位小数百分比；分母为 0 时显示说明而不是 0%。
func formatPercent(value float64) string {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return "—"
	}
	return formatFloat(math.Round(value*10000)/100) + "%"
}
