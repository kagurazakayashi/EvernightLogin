package task

import (
	"testing"
	"time"
)

// mustLocation 加载测试时区；内嵌 tzdata 保证测试不依赖宿主机时区数据库。
func mustLocation(t *testing.T, name string) *time.Location {
	t.Helper()
	location, err := time.LoadLocation(name)
	if err != nil {
		t.Fatalf("加载时区 %s 失败: %v", name, err)
	}
	return location
}

// parseSpec 解析计划表达式，失败直接终止测试。
func parseSpec(t *testing.T, scheduleType ScheduleType, expression, timeZone string, anchor time.Time) ScheduleSpec {
	t.Helper()
	spec, err := ParseScheduleSpec(scheduleType, expression, timeZone, anchor)
	if err != nil {
		t.Fatalf("解析 %s %q %q 失败: %v", scheduleType, expression, timeZone, err)
	}
	return spec
}

// TestParseScheduleSpecCanonical 验证四类表达式的严格解析与规范化。
func TestParseScheduleSpecCanonical(t *testing.T) {
	anchor := time.Date(2021, 4, 25, 4, 0, 0, 0, time.UTC)
	cases := []struct {
		name       string
		schedule   ScheduleType
		expression string
		timeZone   string
		want       string
	}{
		{"日计划", ScheduleTypeDaily, "02:30", "Asia/Shanghai", "02:30"},
		{"周计划规范化", ScheduleTypeWeekly, "WED,MON 02:30", "UTC", "MON,WED 02:30"},
		{"月计划", ScheduleTypeMonthly, "01,15 02:30", "UTC", "1,15 02:30"},
		{"月末", ScheduleTypeMonthly, "last 02:30", "UTC", "last 02:30"},
		{"自定义分钟", ScheduleTypeCustom, "15m", "UTC", "15m"},
		{"自定义小时", ScheduleTypeCustom, "2h", "UTC", "2h"},
		{"自定义天", ScheduleTypeCustom, "7d", "UTC", "7d"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			spec := parseSpec(t, testCase.schedule, testCase.expression, testCase.timeZone, anchor)
			if spec.Expression != testCase.want {
				t.Errorf("规范化表达式 = %q，期望 %q", spec.Expression, testCase.want)
			}
		})
	}
}

// TestParseScheduleSpecRejectsInvalid 验证非法表达式、时区与间隔被拒绝。
func TestParseScheduleSpecRejectsInvalid(t *testing.T) {
	anchor := time.Date(2021, 4, 25, 4, 0, 0, 0, time.UTC)
	cases := []struct {
		name       string
		schedule   ScheduleType
		expression string
		timeZone   string
	}{
		{"未知类型", ScheduleType("hourly"), "02:30", "UTC"},
		{"空表达式", ScheduleTypeDaily, "", "UTC"},
		{"小时越界", ScheduleTypeDaily, "24:00", "UTC"},
		{"分钟越界", ScheduleTypeDaily, "02:60", "UTC"},
		{"缺少前导零", ScheduleTypeDaily, "2:30", "UTC"},
		{"周计划缺时刻", ScheduleTypeWeekly, "MON", "UTC"},
		{"周计划非法星期", ScheduleTypeWeekly, "MON,XYZ 02:30", "UTC"},
		{"周计划重复星期", ScheduleTypeWeekly, "MON,MON 02:30", "UTC"},
		{"周计划字段过多", ScheduleTypeWeekly, "MON WED 02:30", "UTC"},
		{"月计划日为0", ScheduleTypeMonthly, "0 02:30", "UTC"},
		{"月计划日越界", ScheduleTypeMonthly, "32 02:30", "UTC"},
		{"月计划重复日", ScheduleTypeMonthly, "1,1 02:30", "UTC"},
		{"月末混数字", ScheduleTypeMonthly, "last,1 02:30", "UTC"},
		{"自定义零间隔", ScheduleTypeCustom, "0m", "UTC"},
		{"自定义未知单位", ScheduleTypeCustom, "15s", "UTC"},
		{"自定义超上限", ScheduleTypeCustom, "31d", "UTC"},
		{"自定义缺单位", ScheduleTypeCustom, "15", "UTC"},
		{"空时区", ScheduleTypeDaily, "02:30", ""},
		{"Local时区", ScheduleTypeDaily, "02:30", "Local"},
		{"未知时区", ScheduleTypeDaily, "02:30", "Mars/Olympus"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := ParseScheduleSpec(testCase.schedule, testCase.expression, testCase.timeZone, anchor); err == nil {
				t.Fatalf("%s %q %q 应被拒绝", testCase.schedule, testCase.expression, testCase.timeZone)
			}
		})
	}
	if _, err := ParseScheduleSpec(ScheduleTypeCustom, "15m", "UTC", time.Time{}); err == nil {
		t.Fatal("自定义计划缺少锚点应被拒绝")
	}
}

// TestDailyNextAndLatest 验证日计划的下一时刻与最近时刻（含跨时区换算）。
func TestDailyNextAndLatest(t *testing.T) {
	spec := parseSpec(t, ScheduleTypeDaily, "02:30", "Asia/Shanghai", time.Time{})
	shanghai := mustLocation(t, "Asia/Shanghai")

	after := time.Date(2021, 4, 25, 4, 0, 0, 0, time.UTC) // 上海 12:00
	next := spec.Next(after)
	wantNext := time.Date(2021, 4, 25, 18, 30, 0, 0, time.UTC)
	if !next.Equal(wantNext) {
		t.Fatalf("Next = %s，期望 %s", next.UTC(), wantNext)
	}
	if local := next.In(shanghai); local.Hour() != 2 || local.Minute() != 30 {
		t.Fatalf("下一触发本地时刻 = %s，期望 02:30", local)
	}
	latest, ok := spec.LatestAtOrBefore(after)
	if !ok {
		t.Fatal("日计划应始终存在最近触发")
	}
	wantLatest := time.Date(2021, 4, 24, 18, 30, 0, 0, time.UTC)
	if !latest.Equal(wantLatest) {
		t.Fatalf("LatestAtOrBefore = %s，期望 %s", latest.UTC(), wantLatest)
	}
	// 恰好到点时 Next 必须严格晚于当前时刻，Latest 取当前时刻。
	due := time.Date(2021, 4, 25, 18, 30, 0, 0, time.UTC)
	if got := spec.Next(due); !got.Equal(time.Date(2021, 4, 26, 18, 30, 0, 0, time.UTC)) {
		t.Fatalf("准点后 Next = %s，期望次日同一时刻", got.UTC())
	}
	if got, _ := spec.LatestAtOrBefore(due); !got.Equal(due) {
		t.Fatalf("准点 LatestAtOrBefore = %s，期望当前时刻", got.UTC())
	}
}

// TestDailyDSTSpringForward 验证夏令时缺口：不存在的本地时刻顺延到跳变后首个
// 有效瞬间（2021-03-14 纽约 02:30 不存在，03:00 EDT 触发）。
func TestDailyDSTSpringForward(t *testing.T) {
	spec := parseSpec(t, ScheduleTypeDaily, "02:30", "America/New_York", time.Time{})
	next := spec.Next(time.Date(2021, 3, 14, 0, 0, 0, 0, time.UTC))
	want := time.Date(2021, 3, 14, 7, 0, 0, 0, time.UTC) // 03:00 EDT
	if !next.Equal(want) {
		t.Fatalf("DST 缺口 Next = %s，期望 %s", next.UTC(), want)
	}
	local := next.In(mustLocation(t, "America/New_York"))
	if local.Hour() != 3 || local.Minute() != 0 {
		t.Fatalf("DST 缺口本地时刻 = %s，期望 03:00", local)
	}
	// 缺口前一天是正常 02:30 EST（07:30 UTC）。
	previous, ok := spec.LatestAtOrBefore(time.Date(2021, 3, 14, 6, 59, 0, 0, time.UTC))
	if !ok || !previous.Equal(time.Date(2021, 3, 13, 7, 30, 0, 0, time.UTC)) {
		t.Fatalf("DST 缺口前最近触发 = %s，期望 2021-03-13T07:30Z", previous.UTC())
	}
	// 缺口次日恢复本地 02:30 EDT（06:30 UTC），说明没有跳过整天。
	afterGap := spec.Next(want)
	if wantAfter := time.Date(2021, 3, 15, 6, 30, 0, 0, time.UTC); !afterGap.Equal(wantAfter) {
		t.Fatalf("缺口次日 Next = %s，期望 %s", afterGap.UTC(), wantAfter)
	}
}

// TestDailyDSTFallBack 验证夏令时重叠：同一本地时刻只取较早瞬间，下一触发直接
// 进入次日，不重复触发。
func TestDailyDSTFallBack(t *testing.T) {
	spec := parseSpec(t, ScheduleTypeDaily, "01:30", "America/New_York", time.Time{})
	first := spec.Next(time.Date(2021, 11, 6, 12, 0, 0, 0, time.UTC))
	wantFirst := time.Date(2021, 11, 7, 5, 30, 0, 0, time.UTC) // 01:30 EDT（较早）
	if !first.Equal(wantFirst) {
		t.Fatalf("DST 重叠 Next = %s，期望 %s", first.UTC(), wantFirst)
	}
	if local := first.In(mustLocation(t, "America/New_York")); local.Hour() != 1 || local.Minute() != 30 {
		t.Fatalf("DST 重叠本地时刻 = %s，期望 01:30", local)
	}
	// 第二次 01:30（06:30 UTC）不是新触发；Latest 仍返回较早瞬间。
	second := time.Date(2021, 11, 7, 6, 30, 0, 0, time.UTC)
	if got, _ := spec.LatestAtOrBefore(second); !got.Equal(wantFirst) {
		t.Fatalf("DST 重叠最新触发 = %s，期望较早瞬间 %s", got.UTC(), wantFirst)
	}
	nextAfterFirst := spec.Next(wantFirst)
	wantNext := time.Date(2021, 11, 8, 6, 30, 0, 0, time.UTC) // 次日 01:30 EST
	if !nextAfterFirst.Equal(wantNext) {
		t.Fatalf("DST 重叠下一次 = %s，期望 %s", nextAfterFirst.UTC(), wantNext)
	}
}

// TestWeeklySchedule 验证每周多天计划的顺序与最近触发。
func TestWeeklySchedule(t *testing.T) {
	spec := parseSpec(t, ScheduleTypeWeekly, "MON,WED 02:30", "Asia/Shanghai", time.Time{})
	// 2021-04-25 是周日；下一次是周一 2021-04-26 02:30 +08。
	next := spec.Next(time.Date(2021, 4, 25, 4, 0, 0, 0, time.UTC))
	want := time.Date(2021, 4, 25, 18, 30, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("周计划 Next = %s，期望 %s", next.UTC(), want)
	}
	// 周二凌晨的最近触发是周一 02:30。
	latest, ok := spec.LatestAtOrBefore(time.Date(2021, 4, 26, 16, 0, 0, 0, time.UTC))
	if !ok || !latest.Equal(want) {
		t.Fatalf("周计划 Latest = %s，期望 %s", latest.UTC(), want)
	}
	// 周一 02:30 之后的下一次是周三 02:30。
	nextWednesday := spec.Next(want)
	if got := nextWednesday.In(mustLocation(t, "Asia/Shanghai")); got.Weekday() != time.Wednesday || got.Hour() != 2 {
		t.Fatalf("周计划下一次 = %s，期望周三 02:30", got)
	}
}

// TestMonthlyScheduleSkippedAndLast 验证月末语义：31 日在短月跳过，last 取当月
// 最后一天。
func TestMonthlyScheduleSkippedAndLast(t *testing.T) {
	day31 := parseSpec(t, ScheduleTypeMonthly, "31 02:30", "Asia/Shanghai", time.Time{})
	// 2021-01-31 之后的下一次是 3 月 31 日，2 月没有 31 日。
	next := day31.Next(time.Date(2021, 1, 31, 3, 0, 0, 0, mustLocation(t, "Asia/Shanghai")))
	want := time.Date(2021, 3, 31, 2, 30, 0, 0, mustLocation(t, "Asia/Shanghai"))
	if !next.Equal(want) {
		t.Fatalf("31 日计划 Next = %s，期望 %s", next, want)
	}
	latest, ok := day31.LatestAtOrBefore(time.Date(2021, 2, 15, 0, 0, 0, 0, time.UTC))
	if !ok || !latest.Equal(time.Date(2021, 1, 31, 2, 30, 0, 0, mustLocation(t, "Asia/Shanghai"))) {
		t.Fatalf("31 日计划 2 月最近触发 = %s，期望 1 月 31 日", latest)
	}

	last := parseSpec(t, ScheduleTypeMonthly, "last 02:30", "America/New_York", time.Time{})
	february, ok := last.LatestAtOrBefore(time.Date(2021, 3, 1, 0, 0, 0, 0, time.UTC))
	if !ok {
		t.Fatal("月末计划应存在触发")
	}
	wantFebruary := time.Date(2021, 2, 28, 7, 30, 0, 0, time.UTC) // 02:30 EST
	if !february.Equal(wantFebruary) {
		t.Fatalf("月末计划 2 月触发 = %s，期望 %s", february.UTC(), wantFebruary)
	}
	leap, ok := last.LatestAtOrBefore(time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC))
	if !ok || !leap.Equal(time.Date(2024, 2, 29, 7, 30, 0, 0, time.UTC)) {
		t.Fatalf("闰年 2 月月末触发 = %s，期望 2 月 29 日 02:30 EST", leap.UTC())
	}
}

// TestCustomIntervalSchedule 验证自定义绝对间隔以创建时刻为锚点推进。
func TestCustomIntervalSchedule(t *testing.T) {
	anchor := time.Date(2021, 4, 25, 4, 0, 0, 0, time.UTC)
	spec := parseSpec(t, ScheduleTypeCustom, "15m", "UTC", anchor)
	if got := spec.Next(anchor); !got.Equal(anchor.Add(15 * time.Minute)) {
		t.Fatalf("自定义 Next(anchor) = %s，期望 +15m", got.UTC())
	}
	if got := spec.Next(anchor.Add(16 * time.Minute)); !got.Equal(anchor.Add(30 * time.Minute)) {
		t.Fatalf("自定义 Next(+16m) = %s，期望 +30m", got.UTC())
	}
	latest, ok := spec.LatestAtOrBefore(anchor.Add(44 * time.Minute))
	if !ok || !latest.Equal(anchor.Add(30*time.Minute)) {
		t.Fatalf("自定义 Latest(+44m) = %s，期望 +30m", latest.UTC())
	}
	if _, ok := spec.LatestAtOrBefore(anchor.Add(-time.Second)); ok {
		t.Fatal("自定义计划在锚点前不应有触发")
	}
	if got := spec.Next(anchor.Add(-time.Hour)); !got.Equal(anchor) {
		t.Fatalf("锚点前 Next = %s，期望锚点本身", got.UTC())
	}
}
