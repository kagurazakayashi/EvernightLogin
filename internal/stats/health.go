package stats

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// HealthSource 是一个当前健康/状态来源。Collect 返回某个模块在观测时刻的样本；
// 返回错误表示本次无法观测，服务层按“未知”呈现，绝不默认健康。
type HealthSource interface {
	// Module 返回该来源负责的稳定模块标识（必须是 RequiredModules 之一）。
	Module() Module
	// Collect 采集当前状态。实现必须设置观测时间与来源，不返回秘密/连接串。
	Collect(ctx context.Context, now time.Time) (HealthSample, error)
}

// FuncSource 把函数适配为 HealthSource（宿主装配数据库/证书/任务队列等真实来源）。
type FuncSource struct {
	// ModuleKey 是模块稳定标识。
	ModuleKey Module
	// CollectFn 是采集函数；nil 时按未启用处理（不伪装健康）。
	CollectFn func(ctx context.Context, now time.Time) (HealthSample, error)
}

// Module 实现 HealthSource。
func (s FuncSource) Module() Module { return s.ModuleKey }

// Collect 实现 HealthSource。
func (s FuncSource) Collect(ctx context.Context, now time.Time) (HealthSample, error) {
	if s.CollectFn == nil {
		return HealthSample{}, fmt.Errorf("状态来源未实现")
	}
	return s.CollectFn(ctx, now)
}

// NotEnabledSource 是明确“未启用/未实现”的模块来源（例如未来备份指标）。它返回
// not_enabled 样本而不是健康或零值。
type NotEnabledSource struct {
	// ModuleKey 是模块稳定标识。
	ModuleKey Module
	// Reason 是未启用的真实原因（稳定原因码，不含内部地址/凭据）。
	Reason string
}

// Module 实现 HealthSource。
func (s NotEnabledSource) Module() Module { return s.ModuleKey }

// Collect 实现 HealthSource：始终给出 not_enabled，不伪造成功。
func (s NotEnabledSource) Collect(_ context.Context, now time.Time) (HealthSample, error) {
	reason := s.Reason
	if reason == "" {
		reason = "not_enabled"
	}
	return HealthSample{
		Module: s.ModuleKey, State: StateNotEnabled, Severity: SeverityInfo,
		Enabled: false, ObservedAt: now, Source: "not_enabled",
		Detail: map[string]string{"reason": safeToken(reason)},
	}, nil
}

// Pinger 是数据库连通性探测契约（生产 *storage/sqlite.Store 适配）。
type Pinger interface {
	Ping(ctx context.Context) error
}

// DatabaseSource 采集数据库可用性与延迟。它只报告可用/延迟毫秒，不返回连接串、
// 凭据或内部地址。Ping 失败按 unavailable 样本返回（不是错误），以便记录观测。
type DatabaseSource struct {
	Ping Pinger
}

// Module 实现 HealthSource。
func (s DatabaseSource) Module() Module { return ModuleDatabase }

// Collect 实现 HealthSource。
func (s DatabaseSource) Collect(ctx context.Context, now time.Time) (HealthSample, error) {
	if isNil(s.Ping) {
		return HealthSample{}, fmt.Errorf("数据库探测依赖未配置")
	}
	start := time.Now()
	err := s.Ping.Ping(ctx)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		return HealthSample{Module: ModuleDatabase, State: StateUnavailable,
			Severity: SeverityCritical, Enabled: true, ObservedAt: now, Source: "database_ping",
			Detail: map[string]string{"latency_ms": fmt.Sprintf("%d", elapsed),
				"reason": "ping_failed"}}, nil
	}
	state := StateHealthy
	severity := SeverityInfo
	if elapsed > 1000 {
		state = StateDegraded
		severity = SeverityWarning
	}
	return HealthSample{Module: ModuleDatabase, State: state, Severity: severity,
		Enabled: true, ObservedAt: now, Source: "database_ping",
		Detail: map[string]string{"latency_ms": fmt.Sprintf("%d", elapsed)}}, nil
}

// CertificateSource 采集证书到期状态。StatusFn 由宿主用真实证书管理器状态注入；
// nil 表示未采集（按未启用/未知呈现，不推断“长期有效”）。
type CertificateSource struct {
	// StatusFn 返回最早到期时间与是否有证书；没有证书时 ok=false。
	StatusFn func() (notAfter time.Time, ok bool)
	// WarningWindow 是到期告警窗口；0 使用 30 天。
	WarningWindow time.Duration
}

// Module 实现 HealthSource。
func (s CertificateSource) Module() Module { return ModuleCertificate }

// Collect 实现 HealthSource。
func (s CertificateSource) Collect(_ context.Context, now time.Time) (HealthSample, error) {
	if s.StatusFn == nil {
		return HealthSample{}, fmt.Errorf("证书状态来源未配置")
	}
	notAfter, ok := s.StatusFn()
	if !ok {
		return HealthSample{Module: ModuleCertificate, State: StateUnknown,
			Severity: SeverityUnknown, Enabled: true, ObservedAt: now, Source: "certificate_manager",
			Detail: map[string]string{"reason": "no_certificate_loaded"}}, nil
	}
	window := s.WarningWindow
	if window == 0 {
		window = 30 * 24 * time.Hour
	}
	remaining := notAfter.Sub(now)
	detail := map[string]string{
		"not_after":   notAfter.UTC().Format(time.RFC3339),
		"remaining_h": fmt.Sprintf("%d", int64(remaining.Hours())),
	}
	switch {
	case remaining <= 0:
		return HealthSample{Module: ModuleCertificate, State: StateUnavailable,
			Severity: SeverityCritical, Enabled: true, ObservedAt: now,
			Source: "certificate_manager", Detail: detail}, nil
	case remaining <= window:
		return HealthSample{Module: ModuleCertificate, State: StateDegraded,
			Severity: SeverityWarning, Enabled: true, ObservedAt: now,
			Source: "certificate_manager", Detail: detail}, nil
	default:
		return HealthSample{Module: ModuleCertificate, State: StateHealthy,
			Severity: SeverityInfo, Enabled: true, ObservedAt: now,
			Source: "certificate_manager", Detail: detail}, nil
	}
}

// moduleSeverity 返回模块状态的默认严重度（来源未显式给出时使用）。
func moduleSeverity(state ModuleState) Severity {
	switch state {
	case StateHealthy:
		return SeverityInfo
	case StateDegraded:
		return SeverityWarning
	case StateUnavailable:
		return SeverityError
	case StateNotEnabled:
		return SeverityInfo
	default:
		return SeverityUnknown
	}
}

// validateHealthSources 校验来源集合：模块必须是必需集合之一、不重复、数量受限。
func validateHealthSources(sources []HealthSource) error {
	if len(sources) > len(RequiredModules())*2 {
		return fmt.Errorf("%w: 健康来源数量超过上限", ErrOptionsInvalid)
	}
	allowed := make(map[Module]bool, len(RequiredModules()))
	for _, module := range RequiredModules() {
		allowed[module] = true
	}
	seen := make(map[Module]bool, len(sources))
	for _, source := range sources {
		if isNil(source) {
			return fmt.Errorf("%w: 健康来源为空", ErrOptionsInvalid)
		}
		module := source.Module()
		if !allowed[module] {
			return fmt.Errorf("%w: 健康来源模块未登记", ErrOptionsInvalid)
		}
		if seen[module] {
			return fmt.Errorf("%w: 健康来源模块重复", ErrOptionsInvalid)
		}
		seen[module] = true
	}
	return nil
}

// collectHealthSamples 顺序采集来源（避免并发重活），每个来源有独立超时；来源
// 失败返回未知样本，不返回错误中断整次采集。函数返回失败模块列表。
func collectHealthSamples(ctx context.Context, sources []HealthSource, now time.Time,
	timeout time.Duration) ([]HealthSample, []Module) {
	samples := make([]HealthSample, 0, len(sources))
	failed := make([]Module, 0, 2)
	for _, source := range sources {
		module := source.Module()
		callCtx := ctx
		cancel := func() {}
		if timeout > 0 {
			callCtx, cancel = context.WithTimeout(ctx, timeout)
		}
		sample, err := source.Collect(callCtx, now)
		cancel()
		if err != nil {
			failed = append(failed, module)
			samples = append(samples, HealthSample{Module: module, State: StateUnknown,
				Severity: SeverityUnknown, Enabled: true, ObservedAt: now,
				Source: "collection_failed", Detail: map[string]string{"reason": "collection_failed"}})
			continue
		}
		if sample.Module != module {
			failed = append(failed, module)
			samples = append(samples, HealthSample{Module: module, State: StateUnknown,
				Severity: SeverityUnknown, Enabled: true, ObservedAt: now,
				Source: "invalid_sample", Detail: map[string]string{"reason": "module_mismatch"}})
			continue
		}
		if sample.ObservedAt.IsZero() {
			sample.ObservedAt = now
		}
		if sample.Source == "" {
			sample.Source = safeToken(string(module))
		}
		if sample.Severity == "" {
			sample.Severity = moduleSeverity(sample.State)
		}
		if err := validateHealthSample(sample); err != nil {
			failed = append(failed, module)
			samples = append(samples, HealthSample{Module: module, State: StateUnknown,
				Severity: SeverityUnknown, Enabled: true, ObservedAt: now,
				Source: "invalid_sample", Detail: map[string]string{"reason": "invalid_sample"}})
			continue
		}
		samples = append(samples, sample)
	}
	return samples, failed
}

// assembleHealth 把已采集样本补全为必需模块集合：没有来源的必需模块以未知呈现；
// 未来备份在没有真实来源时明确标为未启用，不伪造成功。
func assembleHealth(samples []HealthSample, now time.Time) []HealthSample {
	byModule := make(map[Module]HealthSample, len(samples))
	for _, sample := range samples {
		byModule[sample.Module] = sample
	}
	result := make([]HealthSample, 0, len(RequiredModules()))
	for _, module := range RequiredModules() {
		if sample, exists := byModule[module]; exists {
			result = append(result, sample)
			continue
		}
		if module == ModuleBackup {
			result = append(result, HealthSample{Module: module, State: StateNotEnabled,
				Severity: SeverityInfo, Enabled: false, ObservedAt: now,
				Source: "not_enabled", Detail: map[string]string{"reason": "backup_not_implemented"}})
			continue
		}
		result = append(result, HealthSample{Module: module, State: StateUnknown,
			Severity: SeverityUnknown, Enabled: false, ObservedAt: now,
			Source: "not_collected", Detail: map[string]string{"reason": "source_not_configured"}})
	}
	return result
}

// Health 返回当前观测健康快照。系统状态是观测时刻快照，不是历史趋势；历史筛选
// 不影响它。健康模块是系统级数据，只允许系统作用范围查询（应用范围拒绝，避免
// 向应用管理员泄露全系统基础设施状态）。
func (s *Service) Health(ctx context.Context, request HealthRequest) (HealthResult, error) {
	scope, err := s.authorize(ctx, request.Caller, request.ScopeID)
	if err != nil {
		return HealthResult{}, err
	}
	if scope.scope.Kind != "system" {
		// 已获应用授权但向系统级健康模块越范围读取：拒绝并留痕，避免静默。
		s.recordDenied(ctx, request.Caller.Actor(), scope.scope.ID, "health_scope_not_system")
		return HealthResult{}, ErrAccessDenied
	}
	now := s.now()
	samples, _ := collectHealthSamples(ctx, s.opts.HealthSources, now, 5*time.Second)
	modules := assembleHealth(samples, now)
	notEnabled := make([]Module, 0, 1)
	for _, sample := range modules {
		if sample.State == StateNotEnabled {
			notEnabled = append(notEnabled, sample.Module)
		}
	}
	return HealthResult{Modules: modules, ObservedAt: now, Completeness: Completeness{
		RetentionDays: s.retentionDays, ModulesNotEnabled: notEnabled,
	}}, nil
}

// HealthHistory 返回健康采样历史与采样空档。空档按预期间隔判定（相邻样本间隔
// 超过 2 倍预期间隔视为空档），不插值、不补零。
func (s *Service) HealthHistory(ctx context.Context,
	request HealthHistoryRequest) (HealthHistoryResult, error) {
	scope, err := s.authorize(ctx, request.Caller, request.ScopeID)
	if err != nil {
		return HealthHistoryResult{}, err
	}
	if scope.scope.Kind != "system" {
		// 采样历史同属系统级数据，应用范围拒绝与当前健康一致必须留痕。
		s.recordDenied(ctx, request.Caller.Actor(), scope.scope.ID, "health_scope_not_system")
		return HealthHistoryResult{}, ErrAccessDenied
	}
	window, err := NormalizeWindow(request.Window, s.now())
	if err != nil {
		return HealthHistoryResult{}, err
	}
	completeness, err := s.retentionInfo(ctx)
	if err != nil {
		return HealthHistoryResult{}, err
	}
	page, err := s.opts.Store.QueryHealthSamples(ctx, HealthSampleQuery{
		From: window.Start, To: window.End, Limit: MaxFactRows,
	})
	if err != nil {
		return HealthHistoryResult{}, fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	completeness = finalizeCompleteness(completeness, window, scope, page.Truncated, nil)
	completeness.SamplingGaps = samplingGaps(page.Samples, s.sampleInterval, window)
	return HealthHistoryResult{Window: window, Samples: page.Samples,
		Completeness: completeness, GeneratedAt: s.now()}, nil
}

// samplingGaps 计算按模块的采样空档。只有同一模块相邻样本间隔超过 2 倍预期间隔
// 才产生空档；空档区间为 (前一观测+间隔, 后一观测)，不把首个样本之前当作空档
// （那属于“无采样历史”，由完整性字段另行说明）。
func samplingGaps(samples []HealthSample, interval time.Duration,
	window Window) []MissingInterval {
	if interval <= 0 {
		interval = time.Minute
	}
	byModule := make(map[Module][]time.Time, len(RequiredModules()))
	for _, sample := range samples {
		byModule[sample.Module] = append(byModule[sample.Module], sample.ObservedAt)
	}
	modules := make([]Module, 0, len(byModule))
	for module := range byModule {
		modules = append(modules, module)
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i] < modules[j] })
	gaps := make([]MissingInterval, 0)
	for _, module := range modules {
		moments := byModule[module]
		sort.Slice(moments, func(i, j int) bool { return moments[i].Before(moments[j]) })
		for index := 1; index < len(moments); index++ {
			previous, current := moments[index-1], moments[index]
			if current.Sub(previous) <= 2*interval {
				continue
			}
			gapStart := previous.Add(interval)
			if gapStart.Before(window.Start) {
				gapStart = window.Start
			}
			gapEnd := current
			if gapEnd.After(window.End) {
				gapEnd = window.End
			}
			if gapStart.Before(gapEnd) {
				gaps = append(gaps, MissingInterval{Start: gapStart, End: gapEnd,
					Reason: "sampling_gap:" + string(module)})
			}
		}
	}
	sort.Slice(gaps, func(i, j int) bool {
		if !gaps[i].Start.Equal(gaps[j].Start) {
			return gaps[i].Start.Before(gaps[j].Start)
		}
		return gaps[i].Reason < gaps[j].Reason
	})
	return gaps
}
