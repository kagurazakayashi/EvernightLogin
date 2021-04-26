package task

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
	// 明确内嵌 IANA 时区数据库：计划按用户时区计算触发时刻，生产环境
	// （尤其是精简 Windows/Linux 容器）不一定提供系统 zoneinfo；内嵌后
	// 时区与夏令时规则不依赖宿主机数据，代价是约 450 KiB 的二进制体积。
	_ "time/tzdata"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

const (
	// ScheduleTypeDaily 表示每天固定本地时刻。
	ScheduleTypeDaily ScheduleType = "daily"
	// ScheduleTypeWeekly 表示每周若干天的固定本地时刻。
	ScheduleTypeWeekly ScheduleType = "weekly"
	// ScheduleTypeMonthly 表示每月若干天（或最后一天）的固定本地时刻。
	ScheduleTypeMonthly ScheduleType = "monthly"
	// ScheduleTypeCustom 表示以创建时刻为锚点的固定绝对间隔。
	ScheduleTypeCustom ScheduleType = "custom"

	// MissedSkip 表示停机/延迟期间错过的触发全部跳过，只处理准点或未来触发。
	MissedSkip MissedPolicy = "skip"
	// MissedLatest 表示错过多次时只补跑最近一次，更早的跳过。
	MissedLatest MissedPolicy = "latest"
	// MissedAll 表示按时间顺序补跑所有错过触发，每次 Tick 最多 MaxCatchUp 条。
	MissedAll MissedPolicy = "all"

	// DefaultScheduleMaxCatchUp 是每次 Tick 对单个计划补跑的默认上限。
	DefaultScheduleMaxCatchUp = 24
	// MaxScheduleCatchUp 是允许配置的单次补跑上限，防止一次 Tick 放大成
	// 无界执行。
	MaxScheduleCatchUp = 1000
	// MaxScheduleExpressionBytes/MaxTimeZoneBytes 是计划字段上限。
	MaxScheduleExpressionBytes = 128
	MaxTimeZoneBytes           = 64
	// DefaultScheduleScopeID 是没有应用范围信息时使用的系统范围；服务层接入后
	// 必须按可信调用上下文填写真实 scope_id。
	DefaultScheduleScopeID = "system"
	// scheduleIDPrefix 是计划编号前缀。
	scheduleIDPrefix = "sch_"
	// scheduleIDRandomBytes 是计划编号的随机字节数（128 位）。
	scheduleIDRandomBytes = 16
	// minCustomInterval/maxCustomInterval 是自定义间隔范围。
	minCustomInterval = time.Minute
	maxCustomInterval = 30 * 24 * time.Hour
)

// ScheduleType 是计划的重复类型。
type ScheduleType string

// Valid 报告计划类型是否已定义。
func (t ScheduleType) Valid() bool {
	switch t {
	case ScheduleTypeDaily, ScheduleTypeWeekly, ScheduleTypeMonthly, ScheduleTypeCustom:
		return true
	default:
		return false
	}
}

// MissedPolicy 是停机或调度延迟造成错过触发时的处理策略。
type MissedPolicy string

// Valid 报告错过策略是否已定义。
func (p MissedPolicy) Valid() bool {
	switch p {
	case MissedSkip, MissedLatest, MissedAll:
		return true
	default:
		return false
	}
}

// Schedule 是持久化的定时计划。Owner 是计划创建者，ExecutionActor 是任务执行
// 身份；两者都必须是可信身份，匿名不允许。Enabled=false 表示暂停，暂停不会自动
// 取消已经入队或正在运行的任务。
type Schedule struct {
	ID                 string
	JobKind            string
	ScheduleType       ScheduleType
	Expression         string
	TimeZone           string
	Owner              audit.Actor
	ExecutionActor     audit.Actor
	ScopeID            string
	Enabled            bool
	PermissionRequired bool
	MissedPolicy       MissedPolicy
	MaxCatchUp         int
	Payload            json.RawMessage
	MutexKey           string
	TimeoutSeconds     int
	MaxAttempts        int
	LastScheduledAt    time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// NewScheduleRequest 是创建计划的参数。Owner 是创建者，ExecutionActor 是任务
// 执行身份；调用方（服务层）必须先验证当前调用者是否有权创建该计划。
//
// PermissionExempt 默认为 false，即所有计划默认都要求运行前权限复验；只有服务
// 层能明确证明目标任务是低风险非管理任务时才能显式豁免，并在审计中说明。
type NewScheduleRequest struct {
	JobKind          string
	ScheduleType     ScheduleType
	Expression       string
	TimeZone         string
	Owner            audit.Actor
	ExecutionActor   audit.Actor
	ScopeID          string
	Enabled          bool
	PermissionExempt bool
	MissedPolicy     MissedPolicy
	MaxCatchUp       int
	Payload          json.RawMessage
	MutexKey         string
	TimeoutSeconds   int
	MaxAttempts      int
	RequestID        string
}

// NewSchedule 是存储层创建计划的参数；Expression 已规范化，ID 由调用方用安全
// 随机源生成。
type NewSchedule struct {
	ID                 string
	JobKind            string
	ScheduleType       ScheduleType
	Expression         string
	TimeZone           string
	Owner              audit.Actor
	ExecutionActor     audit.Actor
	ScopeID            string
	Enabled            bool
	PermissionRequired bool
	MissedPolicy       MissedPolicy
	MaxCatchUp         int
	Payload            json.RawMessage
	MutexKey           string
	TimeoutSeconds     int
	MaxAttempts        int
	RequestID          string
	CreatedAt          time.Time
}

// ScheduleStateCommand 是暂停（Enable=false）或恢复（Enable=true）计划的参数。
type ScheduleStateCommand struct {
	ScheduleID string
	Actor      audit.Actor
	Reason     string
	RequestID  string
	Now        time.Time
	Enable     bool
}

// ScheduleDeleteCommand 是删除计划的参数。删除计划不会取消已入队或正在运行的
// 任务；这些任务作为独立任务继续执行。
type ScheduleDeleteCommand struct {
	ScheduleID string
	Actor      audit.Actor
	Reason     string
	RequestID  string
	Now        time.Time
}

// FireOutcome 是一次计划触发的处理结果。
type FireOutcome string

const (
	// FireEnqueued 表示本次触发成功入队一个任务。
	FireEnqueued FireOutcome = "enqueued"
	// FireSkipped 表示按错过策略跳过了该次触发。
	FireSkipped FireOutcome = "skipped"
	// FireDenied 表示运行前权限复验拒绝，未入队任务。
	FireDenied FireOutcome = "denied"
)

// Valid 报告触发结果是否已定义。
func (o FireOutcome) Valid() bool {
	switch o {
	case FireEnqueued, FireSkipped, FireDenied:
		return true
	default:
		return false
	}
}

// FireCommand 原子记录一次计划触发：唯一键 (schedule_id, scheduled_at_ms) 保证
// 同一触发时刻只能被记录一次；Job 非空时在同一事务中插入 queued 任务。
type FireCommand struct {
	ScheduleID  string
	ScheduledAt time.Time
	Job         *NewJob
	Outcome     FireOutcome
	ErrorCode   string
	ReasonCode  string
	Actor       audit.Actor
	Now         time.Time
}

// FireResult 是计划触发结果。Fired=false 表示该触发时刻已记录过（重复触发），
// 调用方不得再次入队。
type FireResult struct {
	Fired bool
	JobID string
}

// NewScheduleID 生成计划编号：sch_ 加 128 位安全随机数的十六进制表示。
func NewScheduleID() (string, error) {
	buffer := make([]byte, scheduleIDRandomBytes)
	if _, err := io.ReadFull(rand.Reader, buffer); err != nil {
		return "", fmt.Errorf("%w: 无法生成计划编号", ErrInternalRandomSource)
	}
	return scheduleIDPrefix + hex.EncodeToString(buffer), nil
}

// validateScheduleID 校验计划编号格式：sch_ 加 32 位小写十六进制。
func ValidateScheduleID(id string) error {
	if len(id) != len(scheduleIDPrefix)+2*scheduleIDRandomBytes || !strings.HasPrefix(id, scheduleIDPrefix) {
		return fmt.Errorf("%w: 计划编号格式无效", ErrInvalidRequest)
	}
	for i := len(scheduleIDPrefix); i < len(id); i++ {
		c := id[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("%w: 计划编号格式无效", ErrInvalidRequest)
		}
	}
	return nil
}

// normalizeNewScheduleRequest 填充默认值、规范化表达式并校验创建参数。
func normalizeNewScheduleRequest(request NewScheduleRequest) (NewScheduleRequest, error) {
	if err := validateToken("任务类型", request.JobKind, MaxKindBytes, true); err != nil {
		return NewScheduleRequest{}, err
	}
	if !request.ScheduleType.Valid() {
		return NewScheduleRequest{}, fmt.Errorf("%w: 计划类型无效", ErrInvalidRequest)
	}
	if err := validateTrustedActor(request.Owner); err != nil {
		return NewScheduleRequest{}, err
	}
	if err := validateTrustedActor(request.ExecutionActor); err != nil {
		return NewScheduleRequest{}, err
	}
	timeZone := strings.TrimSpace(request.TimeZone)
	if timeZone == "" {
		return NewScheduleRequest{}, fmt.Errorf("%w: 计划时区不能为空", ErrInvalidRequest)
	}
	spec, err := ParseScheduleSpec(request.ScheduleType, request.Expression, timeZone, time.Now().UTC())
	if err != nil {
		return NewScheduleRequest{}, err
	}
	scopeID := request.ScopeID
	if scopeID == "" {
		scopeID = DefaultScheduleScopeID
	}
	if err := validateToken("计划范围", scopeID, MaxKindBytes, true); err != nil {
		return NewScheduleRequest{}, err
	}
	policy := request.MissedPolicy
	if policy == "" {
		policy = MissedSkip
	}
	if !policy.Valid() {
		return NewScheduleRequest{}, fmt.Errorf("%w: 错过策略无效", ErrInvalidRequest)
	}
	maxCatchUp := request.MaxCatchUp
	if maxCatchUp == 0 {
		maxCatchUp = DefaultScheduleMaxCatchUp
	}
	if maxCatchUp < 1 || maxCatchUp > MaxScheduleCatchUp {
		return NewScheduleRequest{}, fmt.Errorf("%w: 单次补跑上限必须在 1～%d 之间", ErrInvalidRequest, MaxScheduleCatchUp)
	}
	payload := request.Payload
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	if len(payload) > MaxPayloadBytes {
		return NewScheduleRequest{}, fmt.Errorf("%w: 计划载荷超过 %d 字节", ErrInvalidRequest, MaxPayloadBytes)
	}
	if !json.Valid(payload) {
		return NewScheduleRequest{}, fmt.Errorf("%w: 计划载荷不是合法 JSON", ErrInvalidRequest)
	}
	if err := validateToken("互斥键", request.MutexKey, MaxMutexKeyBytes, false); err != nil {
		return NewScheduleRequest{}, err
	}
	timeout := request.TimeoutSeconds
	if timeout == 0 {
		timeout = DefaultTimeoutSeconds
	}
	if timeout < MinTimeoutSeconds || timeout > MaxTimeoutSeconds {
		return NewScheduleRequest{}, fmt.Errorf("%w: 任务墙钟上限必须在 %d～%d 秒之间", ErrInvalidRequest, MinTimeoutSeconds, MaxTimeoutSeconds)
	}
	maxAttempts := request.MaxAttempts
	if maxAttempts == 0 {
		maxAttempts = 1
	}
	if maxAttempts < 1 || maxAttempts > MaxJobAttempts {
		return NewScheduleRequest{}, fmt.Errorf("%w: 最大尝试次数必须在 1～%d 之间", ErrInvalidRequest, MaxJobAttempts)
	}
	if err := validateCorrelationID("请求编号", request.RequestID); err != nil {
		return NewScheduleRequest{}, err
	}
	request.TimeZone = timeZone
	request.Expression = spec.Expression
	request.ScopeID = scopeID
	request.MissedPolicy = policy
	request.MaxCatchUp = maxCatchUp
	request.Payload = payload
	request.TimeoutSeconds = timeout
	request.MaxAttempts = maxAttempts
	return request, nil
}

// ValidateNewSchedule 校验存储层收到的计划字段（表达式已由服务层规范化）。
func ValidateNewSchedule(schedule NewSchedule) error {
	if err := ValidateScheduleID(schedule.ID); err != nil {
		return err
	}
	if err := validateToken("任务类型", schedule.JobKind, MaxKindBytes, true); err != nil {
		return err
	}
	if !schedule.ScheduleType.Valid() {
		return fmt.Errorf("%w: 计划类型无效", ErrInvalidRequest)
	}
	if _, err := ParseScheduleSpec(schedule.ScheduleType, schedule.Expression, schedule.TimeZone, schedule.CreatedAt); err != nil {
		return err
	}
	if err := validateTrustedActor(schedule.Owner); err != nil {
		return err
	}
	if err := validateTrustedActor(schedule.ExecutionActor); err != nil {
		return err
	}
	if err := validateToken("计划范围", schedule.ScopeID, MaxKindBytes, true); err != nil {
		return err
	}
	if !schedule.MissedPolicy.Valid() {
		return fmt.Errorf("%w: 错过策略无效", ErrInvalidRequest)
	}
	if schedule.MaxCatchUp < 1 || schedule.MaxCatchUp > MaxScheduleCatchUp {
		return fmt.Errorf("%w: 单次补跑上限无效", ErrInvalidRequest)
	}
	if len(schedule.Payload) == 0 || len(schedule.Payload) > MaxPayloadBytes || !json.Valid(schedule.Payload) {
		return fmt.Errorf("%w: 计划载荷无效", ErrInvalidRequest)
	}
	if schedule.MutexKey != "" {
		if err := validateToken("互斥键", schedule.MutexKey, MaxMutexKeyBytes, false); err != nil {
			return err
		}
	}
	if schedule.TimeoutSeconds < MinTimeoutSeconds || schedule.TimeoutSeconds > MaxTimeoutSeconds {
		return fmt.Errorf("%w: 任务墙钟上限无效", ErrInvalidRequest)
	}
	if schedule.MaxAttempts < 1 || schedule.MaxAttempts > MaxJobAttempts {
		return fmt.Errorf("%w: 最大尝试次数无效", ErrInvalidRequest)
	}
	if schedule.CreatedAt.IsZero() {
		return fmt.Errorf("%w: 计划创建时间不能为空", ErrInvalidRequest)
	}
	if err := validateCorrelationID("请求编号", schedule.RequestID); err != nil {
		return err
	}
	return nil
}

// ValidateScheduleCommand 校验暂停/恢复/删除命令的公共字段。
func ValidateScheduleCommand(scheduleID string, actor audit.Actor, reason, requestID string) error {
	if err := ValidateScheduleID(scheduleID); err != nil {
		return err
	}
	if err := validateTrustedActor(actor); err != nil {
		return err
	}
	if err := validateReason(reason); err != nil {
		return err
	}
	return validateCorrelationID("请求编号", requestID)
}

// ScheduleSpec 是解析后的计划表达式，可计算严格晚于某时刻的下一触发时刻，以及
// 不晚于某时刻的最近触发时刻。时区与 DST 规则集中在这里：
//
//   - 日内时刻按指定 IANA 时区的本地墙钟计算；
//   - 夏令时缺口（本地时刻不存在）顺延到该日第一个有效瞬间（例如 02:30 不存在
//     时在 03:00 触发），避免每日任务整日丢失；
//   - 夏令时重叠（本地时刻出现两次）只取较早的瞬间，同一墙钟时刻只触发一次；
//   - 月中日 29～31 在不存在的月份跳过（例如 2 月 31 日），需要月末语义时使用
//     last；
//   - 自定义间隔以创建时刻为锚点按绝对时长推进，不受 DST 影响绝对间隔。
type ScheduleSpec struct {
	// Type 是计划类型。
	Type ScheduleType
	// TimeZone 是规范化后的 IANA 时区名称。
	TimeZone string
	// Expression 是规范化后的表达式。
	Expression string
	// Anchor 是自定义间隔计划的锚点（创建时刻）。
	Anchor time.Time

	location    *time.Location
	hour        int
	minute      int
	weekdays    []time.Weekday
	monthDays   []int
	lastDay     bool
	interval    time.Duration
	hasInterval bool
}

var weekdayAbbreviations = []string{"SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"}

var weekdayIndex = map[string]time.Weekday{
	"SUN": time.Sunday,
	"MON": time.Monday,
	"TUE": time.Tuesday,
	"WED": time.Wednesday,
	"THU": time.Thursday,
	"FRI": time.Friday,
	"SAT": time.Saturday,
}

// ParseScheduleSpec 解析并校验计划表达式，返回可计算触发时刻的规格。
//
// 表达式语法（严格，创建时规范化）：
//   - daily：HH:MM，例如 02:30；
//   - weekly：SUN,MON,... HH:MM，星期缩写大写，至少一天，不允许重复；
//   - monthly：1,15,... HH:MM 或 last HH:MM，日必须在 1～31，不允许重复；
//   - custom：Nm/Nh/Nd，例如 15m、2h、7d，间隔 1 分钟～30 天。
func ParseScheduleSpec(scheduleType ScheduleType, expression, timeZone string, anchor time.Time) (ScheduleSpec, error) {
	if !scheduleType.Valid() {
		return ScheduleSpec{}, fmt.Errorf("%w: 计划类型无效", ErrInvalidRequest)
	}
	timeZone = strings.TrimSpace(timeZone)
	if timeZone == "" || len(timeZone) > MaxTimeZoneBytes {
		return ScheduleSpec{}, fmt.Errorf("%w: 计划时区无效", ErrInvalidRequest)
	}
	if timeZone == "Local" {
		return ScheduleSpec{}, fmt.Errorf("%w: 计划时区必须是稳定的 IANA 时区，不能使用 Local", ErrInvalidRequest)
	}
	location, err := time.LoadLocation(timeZone)
	if err != nil {
		return ScheduleSpec{}, fmt.Errorf("%w: 无法加载计划时区", ErrInvalidRequest)
	}
	expression = strings.TrimSpace(expression)
	if expression == "" || len(expression) > MaxScheduleExpressionBytes {
		return ScheduleSpec{}, fmt.Errorf("%w: 计划表达式无效", ErrInvalidRequest)
	}
	spec := ScheduleSpec{Type: scheduleType, TimeZone: timeZone, Anchor: anchor.UTC(), location: location}
	switch scheduleType {
	case ScheduleTypeDaily:
		hour, minute, err := parseScheduleClock(expression)
		if err != nil {
			return ScheduleSpec{}, err
		}
		spec.hour, spec.minute = hour, minute
		spec.Expression = fmt.Sprintf("%02d:%02d", hour, minute)
	case ScheduleTypeWeekly:
		fields := strings.Fields(expression)
		if len(fields) != 2 {
			return ScheduleSpec{}, fmt.Errorf("%w: 每周计划表达式应为 \"星期 时:分\"", ErrInvalidRequest)
		}
		days, err := parseWeekdays(fields[0])
		if err != nil {
			return ScheduleSpec{}, err
		}
		hour, minute, err := parseScheduleClock(fields[1])
		if err != nil {
			return ScheduleSpec{}, err
		}
		spec.hour, spec.minute = hour, minute
		spec.weekdays = days
		names := make([]string, len(days))
		for index, day := range days {
			names[index] = weekdayAbbreviations[int(day)]
		}
		spec.Expression = strings.Join(names, ",") + fmt.Sprintf(" %02d:%02d", hour, minute)
	case ScheduleTypeMonthly:
		fields := strings.Fields(expression)
		if len(fields) != 2 {
			return ScheduleSpec{}, fmt.Errorf("%w: 每月计划表达式应为 \"日 时:分\"", ErrInvalidRequest)
		}
		days, lastDay, err := parseMonthDays(fields[0])
		if err != nil {
			return ScheduleSpec{}, err
		}
		hour, minute, err := parseScheduleClock(fields[1])
		if err != nil {
			return ScheduleSpec{}, err
		}
		spec.hour, spec.minute = hour, minute
		spec.monthDays, spec.lastDay = days, lastDay
		if lastDay {
			spec.Expression = fmt.Sprintf("last %02d:%02d", hour, minute)
		} else {
			names := make([]string, len(days))
			for index, day := range days {
				names[index] = fmt.Sprintf("%d", day)
			}
			spec.Expression = strings.Join(names, ",") + fmt.Sprintf(" %02d:%02d", hour, minute)
		}
	case ScheduleTypeCustom:
		interval, err := parseCustomInterval(expression)
		if err != nil {
			return ScheduleSpec{}, err
		}
		if anchor.IsZero() {
			return ScheduleSpec{}, fmt.Errorf("%w: 自定义计划需要非空的创建时刻作为锚点", ErrInvalidRequest)
		}
		spec.interval = interval
		spec.hasInterval = true
		spec.Expression = canonicalCustomInterval(interval)
	}
	return spec, nil
}

// parseScheduleClock 解析 HH:MM 形式的本地时刻。
func parseScheduleClock(value string) (int, int, error) {
	if len(value) != 5 || value[2] != ':' {
		return 0, 0, fmt.Errorf("%w: 时刻应为 HH:MM", ErrInvalidRequest)
	}
	hour, err := parseTwoDigits(value[0:2])
	if err != nil || hour > 23 {
		return 0, 0, fmt.Errorf("%w: 时刻的小时必须在 00～23 之间", ErrInvalidRequest)
	}
	minute, err := parseTwoDigits(value[3:5])
	if err != nil || minute > 59 {
		return 0, 0, fmt.Errorf("%w: 时刻的分钟必须在 00～59 之间", ErrInvalidRequest)
	}
	return hour, minute, nil
}

// parseTwoDigits 解析两位十进制数字。
func parseTwoDigits(value string) (int, error) {
	first, second := value[0], value[1]
	if first < '0' || first > '9' || second < '0' || second > '9' {
		return 0, fmt.Errorf("%w: 时刻必须是数字", ErrInvalidRequest)
	}
	return int(first-'0')*10 + int(second-'0'), nil
}

// parseWeekdays 解析并排序去重星期缩写。
func parseWeekdays(value string) ([]time.Weekday, error) {
	parts := strings.Split(value, ",")
	seen := make(map[time.Weekday]bool, len(parts))
	days := make([]time.Weekday, 0, len(parts))
	for _, part := range parts {
		day, ok := weekdayIndex[part]
		if !ok {
			return nil, fmt.Errorf("%w: 星期缩写必须是 SUN～SAT 之一", ErrInvalidRequest)
		}
		if seen[day] {
			return nil, fmt.Errorf("%w: 星期不能重复", ErrInvalidRequest)
		}
		seen[day] = true
		days = append(days, day)
	}
	sortWeekdays(days)
	return days, nil
}

// sortWeekdays 按星期顺序排序（周日为 0）。
func sortWeekdays(days []time.Weekday) {
	for i := 1; i < len(days); i++ {
		for j := i; j > 0 && days[j] < days[j-1]; j-- {
			days[j], days[j-1] = days[j-1], days[j]
		}
	}
}

// parseMonthDays 解析每月日列表或 last；返回排序去重后的日列表。
func parseMonthDays(value string) ([]int, bool, error) {
	if value == "last" {
		return nil, true, nil
	}
	parts := strings.Split(value, ",")
	seen := make(map[int]bool, len(parts))
	days := make([]int, 0, len(parts))
	for _, part := range parts {
		if part == "" || len(part) > 2 {
			return nil, false, fmt.Errorf("%w: 每月日必须在 1～31 之间", ErrInvalidRequest)
		}
		day := 0
		for i := 0; i < len(part); i++ {
			c := part[i]
			if c < '0' || c > '9' {
				return nil, false, fmt.Errorf("%w: 每月日必须是数字", ErrInvalidRequest)
			}
			day = day*10 + int(c-'0')
		}
		if day < 1 || day > 31 {
			return nil, false, fmt.Errorf("%w: 每月日必须在 1～31 之间", ErrInvalidRequest)
		}
		if seen[day] {
			return nil, false, fmt.Errorf("%w: 每月日不能重复", ErrInvalidRequest)
		}
		seen[day] = true
		days = append(days, day)
	}
	for i := 1; i < len(days); i++ {
		for j := i; j > 0 && days[j] < days[j-1]; j-- {
			days[j], days[j-1] = days[j-1], days[j]
		}
	}
	return days, false, nil
}

// parseCustomInterval 解析 Nm/Nh/Nd 间隔表达式。
func parseCustomInterval(value string) (time.Duration, error) {
	if len(value) < 2 || len(value) > 8 {
		return 0, fmt.Errorf("%w: 自定义间隔应为 Nm、Nh 或 Nd", ErrInvalidRequest)
	}
	unit := value[len(value)-1]
	number := 0
	for i := 0; i < len(value)-1; i++ {
		c := value[i]
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("%w: 自定义间隔必须是数字加 m/h/d", ErrInvalidRequest)
		}
		number = number*10 + int(c-'0')
		if number > 100000 {
			return 0, fmt.Errorf("%w: 自定义间隔过大", ErrInvalidRequest)
		}
	}
	if number < 1 {
		return 0, fmt.Errorf("%w: 自定义间隔必须大于 0", ErrInvalidRequest)
	}
	var interval time.Duration
	switch unit {
	case 'm':
		interval = time.Duration(number) * time.Minute
	case 'h':
		interval = time.Duration(number) * time.Hour
	case 'd':
		interval = time.Duration(number) * 24 * time.Hour
	default:
		return 0, fmt.Errorf("%w: 自定义间隔只支持 m/h/d", ErrInvalidRequest)
	}
	if interval < minCustomInterval || interval > maxCustomInterval {
		return 0, fmt.Errorf("%w: 自定义间隔必须在 1 分钟～30 天之间", ErrInvalidRequest)
	}
	return interval, nil
}

// canonicalCustomInterval 返回规范化的自定义间隔表达式。
func canonicalCustomInterval(interval time.Duration) string {
	switch {
	case interval%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", interval/(24*time.Hour))
	case interval%time.Hour == 0:
		return fmt.Sprintf("%dh", interval/time.Hour)
	default:
		return fmt.Sprintf("%dm", interval/time.Minute)
	}
}

// Next 返回严格晚于 after 的下一次触发时刻。
func (s ScheduleSpec) Next(after time.Time) time.Time {
	switch s.Type {
	case ScheduleTypeDaily:
		occ := s.instantOnDate(dateOf(after, s.location))
		if occ.After(after) {
			return occ
		}
		return s.instantOnDate(dateOf(after, s.location).addDays(1, s.location))
	case ScheduleTypeWeekly:
		date := dateOf(after, s.location)
		for i := 0; i < 8; i++ {
			if s.isScheduledWeekday(date) {
				occ := s.instantOnDate(date)
				if occ.After(after) {
					return occ
				}
			}
			date = date.addDays(1, s.location)
		}
		// 每周至少一天，8 天窗口必然命中；保留兜底避免返回零值。
		return s.instantOnDate(date)
	case ScheduleTypeMonthly:
		date := dateOf(after, s.location)
		for i := 0; i < 14; i++ {
			for _, occ := range s.monthInstants(date.year, date.month) {
				if occ.After(after) {
					return occ
				}
			}
			date = date.addMonths(1, s.location)
		}
		return s.instantOnDate(date)
	case ScheduleTypeCustom:
		if after.Before(s.Anchor) {
			return s.Anchor
		}
		step := after.Sub(s.Anchor)/s.interval + 1
		return s.Anchor.Add(step * s.interval)
	default:
		return time.Time{}
	}
}

// LatestAtOrBefore 返回不晚于 moment 的最近一次触发时刻；重来没有触发时刻时
// 返回 ok=false（只有自定义计划在锚点之前会如此）。
func (s ScheduleSpec) LatestAtOrBefore(moment time.Time) (time.Time, bool) {
	switch s.Type {
	case ScheduleTypeDaily:
		occ := s.instantOnDate(dateOf(moment, s.location))
		if !occ.After(moment) {
			return occ, true
		}
		return s.instantOnDate(dateOf(moment, s.location).addDays(-1, s.location)), true
	case ScheduleTypeWeekly:
		date := dateOf(moment, s.location)
		for i := 0; i < 8; i++ {
			if s.isScheduledWeekday(date) {
				occ := s.instantOnDate(date)
				if !occ.After(moment) {
					return occ, true
				}
			}
			date = date.addDays(-1, s.location)
		}
		return time.Time{}, false
	case ScheduleTypeMonthly:
		date := dateOf(moment, s.location)
		for i := 0; i < 14; i++ {
			instants := s.monthInstants(date.year, date.month)
			for index := len(instants) - 1; index >= 0; index-- {
				if !instants[index].After(moment) {
					return instants[index], true
				}
			}
			date = date.addMonths(-1, s.location)
		}
		return time.Time{}, false
	case ScheduleTypeCustom:
		if moment.Before(s.Anchor) {
			return time.Time{}, false
		}
		step := moment.Sub(s.Anchor) / s.interval
		return s.Anchor.Add(step * s.interval), true
	default:
		return time.Time{}, false
	}
}

// isScheduledWeekday 报告日期是否命中每周计划的星期集合。
func (s ScheduleSpec) isScheduledWeekday(date civilDate) bool {
	weekday := date.weekday(s.location)
	for _, candidate := range s.weekdays {
		if candidate == weekday {
			return true
		}
	}
	return false
}

// monthInstants 返回某年某月命中的触发瞬间，按时间升序；不存在的日（例如
// 2 月 31 日）直接跳过。
func (s ScheduleSpec) monthInstants(year int, month time.Month) []time.Time {
	total := daysInMonth(year, month)
	days := s.monthDays
	if s.lastDay {
		days = []int{total}
	}
	instants := make([]time.Time, 0, len(days))
	for _, day := range days {
		if day > total {
			continue
		}
		instants = append(instants, s.instantOnDate(civilDate{year: year, month: month, day: day}))
	}
	return instants
}

// instantOnDate 返回指定本地日期与时刻对应的最早瞬间。本地时刻因夏令时缺口
// 不存在时，返回该日第一个有效瞬间（即跳变瞬间），保证任务不会整日丢失。
func (s ScheduleSpec) instantOnDate(date civilDate) time.Time {
	location := s.location
	candidate := time.Date(date.year, date.month, date.day, s.hour, s.minute, 0, 0, location)
	if localWallMatches(candidate, date, s.hour, s.minute, location) {
		return candidate
	}
	// 缺口：从候选时刻向后按分钟找到第一个墙钟不早于目标时刻的瞬间，再二分到秒。
	found := candidate
	for step := 0; step < 4*60; step++ {
		if localWallAtOrAfter(found, date, s.hour, s.minute, location) {
			break
		}
		found = found.Add(time.Minute)
	}
	lower := found.Add(-time.Minute)
	for attempts := 0; attempts < 5 && localWallAtOrAfter(lower, date, s.hour, s.minute, location); attempts++ {
		lower = lower.Add(-time.Hour)
	}
	for found.Sub(lower) > time.Second {
		middle := lower.Add(found.Sub(lower) / 2)
		if localWallAtOrAfter(middle, date, s.hour, s.minute, location) {
			found = middle
		} else {
			lower = middle
		}
	}
	return found
}

// localWallMatches 报告瞬间在指定时区的本地墙钟是否正好等于目标日期与时刻。
func localWallMatches(moment time.Time, date civilDate, hour, minute int, location *time.Location) bool {
	local := moment.In(location)
	year, month, day := local.Date()
	return year == date.year && month == date.month && day == date.day &&
		local.Hour() == hour && local.Minute() == minute
}

// localWallAtOrAfter 报告瞬间的本地日期/时刻是否不早于目标日期与时刻。
func localWallAtOrAfter(moment time.Time, date civilDate, hour, minute int, location *time.Location) bool {
	local := moment.In(location)
	year, month, day := local.Date()
	if year != date.year {
		return year > date.year
	}
	if month != date.month {
		return month > date.month
	}
	if day != date.day {
		return day > date.day
	}
	if local.Hour() != hour {
		return local.Hour() > hour
	}
	return local.Minute() >= minute
}

// civilDate 是本地日历日期；所有日期推进都通过中午锚点加 AddDate，避免夏令时
// 午夜跳变影响日期计算。
type civilDate struct {
	year  int
	month time.Month
	day   int
}

// dateOf 返回瞬间在指定时区的本地日历日期。
func dateOf(moment time.Time, location *time.Location) civilDate {
	local := moment.In(location)
	year, month, day := local.Date()
	return civilDate{year: year, month: month, day: day}
}

// addDays 返回偏移若干天后的日期。
func (d civilDate) addDays(days int, location *time.Location) civilDate {
	return dateOf(time.Date(d.year, d.month, d.day, 12, 0, 0, 0, location).AddDate(0, 0, days), location)
}

// addMonths 返回偏移若干月后的日期；如果目标月份没有该日，退到该月最后一天，
// 只用于月份游标推进（具体触发日仍由 monthInstants 判断）。
func (d civilDate) addMonths(months int, location *time.Location) civilDate {
	first := time.Date(d.year, d.month, 1, 12, 0, 0, 0, location).AddDate(0, months, 0)
	year, month, _ := first.Date()
	day := d.day
	if total := daysInMonth(year, month); day > total {
		day = total
	}
	return civilDate{year: year, month: month, day: day}
}

// weekday 返回日期的星期。
func (d civilDate) weekday(location *time.Location) time.Weekday {
	return time.Date(d.year, d.month, d.day, 12, 0, 0, 0, location).Weekday()
}

// daysInMonth 返回某年某月的天数。
func daysInMonth(year int, month time.Month) int {
	return time.Date(year, month+1, 0, 12, 0, 0, 0, time.UTC).Day()
}
