package stats_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
)

// shanghai 是测试使用的固定东八区位置。
func shanghai(t *testing.T) *time.Location {
	t.Helper()
	location, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatalf("加载 Asia/Shanghai 失败: %v", err)
	}
	return location
}

// TestNormalizeWindowCrossMidnight 验证左闭右开区间与跨午夜分桶：起点事件属于
// 当日，终点事件不属于窗口；跨午夜的相邻桶不重复、不漏计。
func TestNormalizeWindowCrossMidnight(t *testing.T) {
	location := shanghai(t)
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, location)
	start := time.Date(2026, 11, 17, 0, 0, 0, 0, location)
	end := time.Date(2026, 11, 19, 0, 0, 0, 0, location)
	window, err := stats.NormalizeWindow(stats.WindowRequest{
		TimeZone: "Asia/Shanghai", Start: start, End: end,
		Granularity: stats.GranularityDay,
	}, now)
	if err != nil {
		t.Fatalf("规范化窗口失败: %v", err)
	}
	if len(window.Buckets) != 2 {
		t.Fatalf("桶数量 = %d，期望 2", len(window.Buckets))
	}
	if !window.Buckets[0].Start.Equal(start) || !window.Buckets[0].End.Equal(window.Buckets[1].Start) {
		t.Error("相邻桶不是首尾相接的半开区间")
	}
	if !window.Buckets[1].End.Equal(end) {
		t.Error("最后一个桶未结束于窗口终点")
	}
	// 终点事件（11-19 00:00）必须落在窗口外。
	if _, ok := window.BucketAt(end); ok {
		t.Error("终点时刻不应属于任何桶（左闭右开）")
	}
	moment := time.Date(2026, 11, 18, 0, 0, 0, 0, location)
	bucket, ok := window.BucketAt(moment)
	if !ok || bucket.Key != "2026-11-18" {
		t.Errorf("跨午夜时刻分桶错误: %+v ok=%v", bucket, ok)
	}
}

// TestNormalizeWindowTimezoneChangesBuckets 验证同一批绝对时刻在不同 IANA 时区
// 下落入不同自然日桶：时区切换会重新划分日/周/月，而不只是改时间文本。
func TestNormalizeWindowTimezoneChangesBuckets(t *testing.T) {
	location := shanghai(t)
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, location)
	start := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	moment := time.Date(2026, 11, 17, 0, 30, 0, 0, location) // UTC 11-16 16:30
	utcWindow, err := stats.NormalizeWindow(stats.WindowRequest{
		TimeZone: "UTC", Start: start, End: end, Granularity: stats.GranularityDay,
	}, now)
	if err != nil {
		t.Fatalf("UTC 窗口失败: %v", err)
	}
	localWindow, err := stats.NormalizeWindow(stats.WindowRequest{
		TimeZone: "Asia/Shanghai", Start: start, End: end, Granularity: stats.GranularityDay,
	}, now)
	if err != nil {
		t.Fatalf("本地窗口失败: %v", err)
	}
	utcBucket, ok := utcWindow.BucketAt(moment)
	if !ok || utcBucket.Key != "2026-11-16" {
		t.Errorf("UTC 分桶 = %+v，期望 2026-11-16", utcBucket)
	}
	localBucket, ok := localWindow.BucketAt(moment)
	if !ok || localBucket.Key != "2026-11-17" {
		t.Errorf("Asia/Shanghai 分桶 = %+v，期望 2026-11-17", localBucket)
	}
}

// TestNormalizeWindowWeekAndMonth 验证周一起始的周桶与自然月桶。
func TestNormalizeWindowWeekAndMonth(t *testing.T) {
	location := shanghai(t)
	now := time.Date(2027, 1, 5, 0, 0, 0, 0, location)
	// 2026-11-16 是周一。
	window, err := stats.NormalizeWindow(stats.WindowRequest{
		TimeZone:    "Asia/Shanghai",
		Start:       time.Date(2026, 11, 18, 0, 0, 0, 0, location),
		End:         time.Date(2026, 11, 30, 0, 0, 0, 0, location),
		Granularity: stats.GranularityWeek,
	}, now)
	if err != nil {
		t.Fatalf("周窗口失败: %v", err)
	}
	if window.Buckets[0].Key != "2026-W47" {
		t.Errorf("首个周桶 = %q，期望 2026-W47（周一起始）", window.Buckets[0].Key)
	}
	for index := 1; index < len(window.Buckets); index++ {
		if !window.Buckets[index].Start.Equal(window.Buckets[index-1].End) {
			t.Errorf("周桶 %d 与前一桶不连续", index)
		}
	}
	monthWindow, err := stats.NormalizeWindow(stats.WindowRequest{
		TimeZone:    "Asia/Shanghai",
		Start:       time.Date(2026, 11, 15, 8, 0, 0, 0, location),
		End:         time.Date(2027, 1, 2, 0, 0, 0, 0, location),
		Granularity: stats.GranularityMonth,
	}, now)
	if err != nil {
		t.Fatalf("月窗口失败: %v", err)
	}
	if monthWindow.Buckets[0].Key != "2026-11" || monthWindow.Buckets[len(monthWindow.Buckets)-1].Key != "2027-01" {
		t.Errorf("月桶 = %q ... %q", monthWindow.Buckets[0].Key,
			monthWindow.Buckets[len(monthWindow.Buckets)-1].Key)
	}
	if !monthWindow.Buckets[0].Partial {
		t.Error("窗口起点不在月边界时首个桶应标记 Partial")
	}
}

// TestNormalizeWindowRejects 验证非法时区、Local、反向区间、超长区间等边界。
func TestNormalizeWindowRejects(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name    string
		request stats.WindowRequest
	}{
		{"Local 时区", stats.WindowRequest{TimeZone: "Local"}},
		{"非法时区", stats.WindowRequest{TimeZone: "+08:00"}},
		{"未知时区", stats.WindowRequest{TimeZone: "Mars/Olympus"}},
		{"反向区间", stats.WindowRequest{Start: now, End: now.Add(-time.Hour)}},
		{"超长区间", stats.WindowRequest{Start: now.AddDate(-5, 0, 0), End: now}},
		{"非法粒度", stats.WindowRequest{Granularity: stats.Granularity("hour")}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := stats.NormalizeWindow(testCase.request, now); err == nil {
				t.Error("非法窗口未被拒绝")
			}
		})
	}
}

// TestNormalizeWindowClampsFutureEnd 验证请求结束时间晚于截止点时被裁剪并标记，
// 进行中的末桶被标记 InProgress，不会被当作完整桶。
func TestNormalizeWindowClampsFutureEnd(t *testing.T) {
	location := shanghai(t)
	now := time.Date(2026, 11, 19, 10, 30, 0, 0, location)
	window, err := stats.NormalizeWindow(stats.WindowRequest{
		TimeZone: "Asia/Shanghai",
		Start:    time.Date(2026, 11, 18, 0, 0, 0, 0, location),
		End:      time.Date(2026, 11, 21, 0, 0, 0, 0, location),
	}, now)
	if err != nil {
		t.Fatalf("规范化窗口失败: %v", err)
	}
	if !window.Clamped || !window.End.Equal(now.UTC()) {
		t.Errorf("结束时间未裁剪到截止点: %+v", window)
	}
	last := window.Buckets[len(window.Buckets)-1]
	if !last.InProgress {
		t.Error("当前未完成桶应标记 InProgress")
	}
}

// TestNormalizeWindowDeterministic 验证同一请求重复规范化结果完全一致。
func TestNormalizeWindowDeterministic(t *testing.T) {
	location := shanghai(t)
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, location)
	request := stats.WindowRequest{
		TimeZone:    "Asia/Shanghai",
		Start:       time.Date(2026, 9, 29, 0, 0, 0, 0, location),
		End:         time.Date(2026, 11, 19, 0, 0, 0, 0, location),
		Granularity: stats.GranularityDay,
	}
	first, err := stats.NormalizeWindow(request, now)
	if err != nil {
		t.Fatalf("首次规范化失败: %v", err)
	}
	second, err := stats.NormalizeWindow(request, now)
	if err != nil {
		t.Fatalf("再次规范化失败: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Error("相同请求重复规范化结果不一致")
	}
}

// TestNormalizeWindowDaylightSaving 验证夏令时切换日按墙钟自然日分桶且边界严格
// 递增（不假设每天固定 24 小时）。
func TestNormalizeWindowDaylightSaving(t *testing.T) {
	location, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatalf("加载 America/New_York 失败: %v", err)
	}
	now := time.Date(2026, 12, 1, 0, 0, 0, 0, location)
	window, err := stats.NormalizeWindow(stats.WindowRequest{
		TimeZone:    "America/New_York",
		Start:       time.Date(2026, 10, 30, 0, 0, 0, 0, location),
		End:         time.Date(2026, 11, 6, 0, 0, 0, 0, location),
		Granularity: stats.GranularityDay,
	}, now)
	if err != nil {
		t.Fatalf("夏令时窗口失败: %v", err)
	}
	if len(window.Buckets) != 7 {
		t.Fatalf("桶数量 = %d，期望 7 个自然日", len(window.Buckets))
	}
	for index := 1; index < len(window.Buckets); index++ {
		if !window.Buckets[index].Start.After(window.Buckets[index-1].Start) {
			t.Fatalf("桶 %d 边界未严格递增", index)
		}
	}
	// 2026-11-01 是纽约夏令时结束日，绝对时长为 25 小时。
	// 通过 11-01 桶的自然边界验证 DST：从 11-01 00:00 EDT 到 11-02 00:00 EST。
	var dstBucket *stats.Bucket
	for index := range window.Buckets {
		if window.Buckets[index].Key == "2026-11-01" {
			dstBucket = &window.Buckets[index]
		}
	}
	if dstBucket == nil {
		t.Fatal("缺少 2026-11-01 桶")
	}
	if duration := dstBucket.CalendarEnd.Sub(dstBucket.CalendarStart); duration != 25*time.Hour {
		t.Errorf("2026-11-01 自然日绝对时长 = %v，期望 25h", duration)
	}
}
