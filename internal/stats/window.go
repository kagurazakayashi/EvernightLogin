package stats

import (
	"fmt"
	"time"

	// 内嵌 IANA 时区数据库：统计按显式 IANA 时区分桶，不能依赖运行环境是否安装
	// zoneinfo（Windows 默认没有 /usr/share/zoneinfo，宿主也可能裁剪 GOROOT）。
	_ "time/tzdata"
)

// Granularity 是时间桶粒度。
type Granularity string

const (
	// GranularityDay 是按所选时区的自然日分桶（处理夏令时 23/25 小时日）。
	GranularityDay Granularity = "day"
	// GranularityWeek 是按所选时区的自然周分桶，周一起始。
	GranularityWeek Granularity = "week"
	// GranularityMonth 是按所选时区的自然月分桶。
	GranularityMonth Granularity = "month"
)

// Valid 报告粒度是否已定义。
func (g Granularity) Valid() bool {
	return g == GranularityDay || g == GranularityWeek || g == GranularityMonth
}

// WindowRequest 是调用方请求的时间范围与粒度；零值按默认处理：UTC、最近 7 天、
// 自然日分桶。Start/End 是绝对时刻（UTC 或带偏移都按绝对时刻解释）。
type WindowRequest struct {
	TimeZone    string
	Start       time.Time
	End         time.Time
	Granularity Granularity
}

// Bucket 是一个时间桶。Start/End 是参与事件比较的绝对时刻（已裁剪到窗口边界，
// 左闭右开）；CalendarStart/CalendarEnd 是未裁剪的自然边界，用于说明“进行中”
// 与“窗口边缘部分桶”。Partial 表示桶被窗口边缘裁剪；InProgress 表示桶的自然
// 结束时间晚于统计截止点（当前未完成），不得与完整桶直接比较。
type Bucket struct {
	Start         time.Time
	End           time.Time
	CalendarStart time.Time
	CalendarEnd   time.Time
	Partial       bool
	InProgress    bool
	// Key 是稳定桶标识：日为 2006-01-02、周为 2006-Www、月为 2006-01。
	Key string
}

// Window 是规范化后的统计窗口：左闭右开 [Start, End)，按所选时区划分自然桶。
// 同一请求在相同数据与相同时钟下重复规范化得到完全相同的结果。
type Window struct {
	TimeZone    string
	Location    *time.Location
	Start       time.Time
	End         time.Time
	Granularity Granularity
	DataCutoff  time.Time
	Buckets     []Bucket
	// Clamped 表示请求的结束时间晚于统计截止点，已被裁剪到截止点。
	Clamped bool
}

// Duration 返回窗口绝对跨度。
func (w Window) Duration() time.Duration { return w.End.Sub(w.Start) }

// BucketAt 返回包含指定绝对时刻的桶；不在窗口内时返回 false。
func (w Window) BucketAt(moment time.Time) (Bucket, bool) {
	index := sortSearchBucket(w.Buckets, moment)
	if index < 0 {
		return Bucket{}, false
	}
	bucket := w.Buckets[index]
	if moment.Before(bucket.Start) || !moment.Before(bucket.End) {
		return Bucket{}, false
	}
	return bucket, true
}

// sortSearchBucket 用二分查找返回 moment 落在的桶下标；moment 早于第一个桶或
// 晚于最后桶时返回 -1。
func sortSearchBucket(buckets []Bucket, moment time.Time) int {
	low, high := 0, len(buckets)-1
	for low <= high {
		mid := low + (high-low)/2
		if moment.Before(buckets[mid].Start) {
			high = mid - 1
			continue
		}
		if !moment.Before(buckets[mid].End) {
			low = mid + 1
			continue
		}
		return mid
	}
	return -1
}

// NormalizeWindow 校验并规范化时间窗口。规则固定：
//   - 时区必须是可加载的 IANA 名称；空值按 UTC 处理，拒绝 "Local"（结果会随
//     进程环境变化）与固定偏移字符串，避免同一请求在不同机器上分桶不同；
//   - 左闭右开 [Start, End)；未指定 End 时为统计截止点，未指定 Start 时默认最近
//     7 天；结束时间晚于截止点时裁剪到截止点并标记 Clamped；
//   - 跨度不超过 3 年（MaxWindowDays），桶数不超过 400，超出直接拒绝；
//   - 桶按所选时区的自然日/自然周（周一起始）/自然月划分，边缘桶裁剪到窗口内，
//     因此跨午夜、跨周、跨月不会重复或漏计。
func NormalizeWindow(request WindowRequest, now time.Time) (Window, error) {
	if now.IsZero() {
		return Window{}, fmt.Errorf("%w: 缺少统计截止时刻", ErrInvalidRequest)
	}
	now = now.UTC()
	timeZone := request.TimeZone
	if timeZone == "" {
		timeZone = "UTC"
	}
	if timeZone == "Local" {
		return Window{}, fmt.Errorf("%w: 统计时区不能使用 Local，必须显式指定 IANA 时区", ErrInvalidRequest)
	}
	location, err := time.LoadLocation(timeZone)
	if err != nil {
		return Window{}, fmt.Errorf("%w: 统计时区不是有效的 IANA 名称", ErrInvalidRequest)
	}
	granularity := request.Granularity
	if granularity == "" {
		granularity = GranularityDay
	}
	if !granularity.Valid() {
		return Window{}, fmt.Errorf("%w: 时间桶粒度只支持 day/week/month", ErrInvalidRequest)
	}
	end := request.End
	if end.IsZero() {
		end = now
	} else {
		end = end.UTC()
	}
	clamped := false
	if end.After(now) {
		end = now
		clamped = true
	}
	start := request.Start
	if start.IsZero() {
		start = end.AddDate(0, 0, -DefaultRangeDays)
	} else {
		start = start.UTC()
	}
	if !start.Before(end) {
		return Window{}, fmt.Errorf("%w: 开始时间必须早于结束时间", ErrInvalidRequest)
	}
	if end.Sub(start) > time.Duration(MaxWindowDays)*24*time.Hour {
		return Window{}, fmt.Errorf("%w: 统计区间超过允许的最大跨度", ErrInvalidRequest)
	}
	buckets, err := buildBuckets(start, end, now, granularity, location)
	if err != nil {
		return Window{}, err
	}
	return Window{
		TimeZone: timeZone, Location: location, Start: start, End: end,
		Granularity: granularity, DataCutoff: now, Buckets: buckets, Clamped: clamped,
	}, nil
}

// buildBuckets 生成覆盖 [start, end) 的自然桶并裁剪到窗口边界。
func buildBuckets(start, end, now time.Time, granularity Granularity, location *time.Location) ([]Bucket, error) {
	calendarStart := truncateToBucket(start, granularity, location)
	buckets := make([]Bucket, 0, 8)
	for calendarStart.Before(end) {
		if len(buckets) >= MaxBucketCount {
			return nil, fmt.Errorf("%w: 时间桶数量超过上限 %d", ErrInvalidRequest, MaxBucketCount)
		}
		calendarEnd := nextBucketStart(calendarStart, granularity, location)
		if !calendarEnd.After(calendarStart) {
			return nil, fmt.Errorf("%w: 时间桶边界无法推进", ErrInvalidRequest)
		}
		clipStart := calendarStart
		if clipStart.Before(start) {
			clipStart = start
		}
		clipEnd := calendarEnd
		if clipEnd.After(end) {
			clipEnd = end
		}
		buckets = append(buckets, Bucket{
			Start: clipStart, End: clipEnd,
			CalendarStart: calendarStart, CalendarEnd: calendarEnd,
			Partial:    clipStart != calendarStart || clipEnd != calendarEnd,
			InProgress: calendarEnd.After(now),
			Key:        bucketKey(calendarStart, granularity, location),
		})
		calendarStart = calendarEnd
	}
	if len(buckets) == 0 {
		return nil, fmt.Errorf("%w: 统计区间没有可用的时间桶", ErrInvalidRequest)
	}
	return buckets, nil
}

// truncateToBucket 返回包含 moment 的自然桶起点（按 location 墙钟）。
func truncateToBucket(moment time.Time, granularity Granularity, location *time.Location) time.Time {
	local := moment.In(location)
	year, month, day := local.Date()
	switch granularity {
	case GranularityWeek:
		// 周一起始：把周一作为 0，周日作为 6。
		offset := (int(local.Weekday()) + 6) % 7
		return time.Date(year, month, day-offset, 0, 0, 0, 0, location)
	case GranularityMonth:
		return time.Date(year, month, 1, 0, 0, 0, 0, location)
	default:
		return time.Date(year, month, day, 0, 0, 0, 0, location)
	}
}

// nextBucketStart 返回下一个自然桶起点。夏令时切换可能产生 23/25 小时日，使用
// AddDate 保持墙钟边界；若个别时区在午夜跳变导致时刻不前进，则退化为加一个自然
// 日/24 小时，保证桶边界严格递增（不会死循环或重复计数）。
func nextBucketStart(current time.Time, granularity Granularity, location *time.Location) time.Time {
	var next time.Time
	switch granularity {
	case GranularityWeek:
		next = current.AddDate(0, 0, 7)
		if !next.After(current) {
			next = current.Add(7 * 24 * time.Hour)
		}
	case GranularityMonth:
		next = current.AddDate(0, 1, 0)
		if !next.After(current) {
			next = current.Add(31 * 24 * time.Hour)
		}
	default:
		next = current.AddDate(0, 0, 1)
		if !next.After(current) {
			next = current.Add(24 * time.Hour)
		}
	}
	return next.In(location)
}

// bucketKey 返回稳定桶标识。周使用 ISO 周（ISOWeek），跨年周不会与下一年重复；
// 标识只用于展示/排序与下钻，实际边界以 Start/End 绝对时刻为准。
func bucketKey(calendarStart time.Time, granularity Granularity, location *time.Location) string {
	local := calendarStart.In(location)
	switch granularity {
	case GranularityWeek:
		year, week := local.ISOWeek()
		return fmt.Sprintf("%04d-W%02d", year, week)
	case GranularityMonth:
		return local.Format("2006-01")
	default:
		return local.Format("2006-01-02")
	}
}
