package stats

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// ErrSamplingInProgress 表示上一次采样尚未结束，本次采样被跳过。采样不做排队，
// 避免慢来源堆积占用资源。
var ErrSamplingInProgress = errors.New("上一次健康采样仍在进行")

// SamplerOptions 是健康采样任务的依赖与资源边界。
type SamplerOptions struct {
	// Store 是统计存储；必填。
	Store Store
	// Sources 是健康状态来源；模块必须已登记且不重复。
	Sources []HealthSource
	// Now 是注入时钟；nil 使用 time.Now。
	Now func() time.Time
	// RetentionDays 是采样保留天数；0 使用默认 30 天，上限 365 天。
	RetentionDays int
	// MaxSamplesPerRun 是单次采样最多写入行数；0 使用默认 512。
	MaxSamplesPerRun int
	// SourceTimeout 是单个来源的采集超时；0 使用 5 秒。
	SourceTimeout time.Duration
	// MaxRunDuration 是单次采样总墙钟上限；0 使用 60 秒。
	MaxRunDuration time.Duration
	Logger         *slog.Logger
}

// SampleRunResult 是一次采样的结果。
type SampleRunResult struct {
	// SampledAt 是本次观测时刻（同批样本共用，便于按时刻聚合）。
	SampledAt time.Time
	// Modules 是实际写入的模块数量。
	Modules int
	// Missing 是没有来源的必需模块（不写假样本）。
	Missing []Module
	// Failed 是采集失败/样本无效的模块（写入未知状态样本并在此列出）。
	Failed []Module
	// Truncated 表示来源数量超过单次写入上限，多出的模块未写入。
	Truncated bool
	// Pruned 是本次清理的过期采样行数。
	Pruned int64
}

// Sampler 是有界、可重入保护的健康采样任务。它不启动后台协程；宿主按需要周期
// 调用 RunOnce，并负责调度、停机与锁文件/多实例互斥。
type Sampler struct {
	opts          SamplerOptions
	retentionDays int
	maxSamples    int
	sourceTimeout time.Duration
	maxRun        time.Duration
	logger        *slog.Logger
	mu            sync.Mutex
}

// NewSampler 校验依赖与边界并构造采样任务。
func NewSampler(options SamplerOptions) (*Sampler, error) {
	if isNil(options.Store) {
		return nil, fmt.Errorf("%w: 统计存储为空", ErrOptionsInvalid)
	}
	if err := validateHealthSources(options.Sources); err != nil {
		return nil, err
	}
	retentionDays := options.RetentionDays
	if retentionDays == 0 {
		retentionDays = DefaultSampleRetentionDays
	}
	if retentionDays < 1 || retentionDays > MaxSampleRetentionDays {
		return nil, fmt.Errorf("%w: 采样保留天数超出范围", ErrOptionsInvalid)
	}
	maxSamples := options.MaxSamplesPerRun
	if maxSamples == 0 {
		maxSamples = DefaultMaxSamplesPerRun
	}
	if maxSamples < len(RequiredModules()) || maxSamples > DefaultMaxSamplesPerRun {
		return nil, fmt.Errorf("%w: 单次采样行数上限超出范围", ErrOptionsInvalid)
	}
	sourceTimeout := options.SourceTimeout
	if sourceTimeout == 0 {
		sourceTimeout = 5 * time.Second
	}
	if sourceTimeout < time.Second || sourceTimeout > time.Minute {
		return nil, fmt.Errorf("%w: 单来源采集超时超出范围", ErrOptionsInvalid)
	}
	maxRun := options.MaxRunDuration
	if maxRun == 0 {
		maxRun = time.Minute
	}
	if maxRun < sourceTimeout || maxRun > 10*time.Minute {
		return nil, fmt.Errorf("%w: 单次采样总时限超出范围", ErrOptionsInvalid)
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	return &Sampler{opts: options, retentionDays: retentionDays, maxSamples: maxSamples,
		sourceTimeout: sourceTimeout, maxRun: maxRun, logger: logger}, nil
}

// RunOnce 执行一次有界采样：
//   - TryLock 保证同一采样器实例单次运行，重叠调用返回 ErrSamplingInProgress；
//   - 总墙钟受 MaxRunDuration 限制，单来源受 SourceTimeout 限制，顺序采集；
//   - 只写入实际采集到的样本，缺少来源的必需模块不写假样本；
//   - 写入后按保留期清理过期采样，单次删除受 MaxPruneBatch 限制，限制存储增长；
//   - 不使用 context.Background 逃避调用方取消：调用方取消时立即停止。
func (s *Sampler) RunOnce(ctx context.Context) (SampleRunResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !s.mu.TryLock() {
		return SampleRunResult{}, ErrSamplingInProgress
	}
	defer s.mu.Unlock()
	clock := s.opts.Now
	if clock == nil {
		clock = time.Now
	}
	sampledAt := clock().UTC().Truncate(time.Millisecond)
	runCtx, cancel := context.WithTimeout(ctx, s.maxRun)
	defer cancel()
	samples, failed := collectHealthSamples(runCtx, s.opts.Sources, sampledAt, s.sourceTimeout)
	result := SampleRunResult{SampledAt: sampledAt, Failed: failed}
	if len(samples) > s.maxSamples {
		samples = samples[:s.maxSamples]
		result.Truncated = true
	}
	provided := make(map[Module]bool, len(samples))
	for _, sample := range samples {
		provided[sample.Module] = true
	}
	for _, module := range RequiredModules() {
		if provided[module] {
			continue
		}
		result.Missing = append(result.Missing, module)
	}
	if len(samples) > 0 {
		if err := s.opts.Store.InsertHealthSamples(runCtx, samples); err != nil {
			return result, fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
		}
		result.Modules = len(samples)
	}
	pruneCutoff := sampledAt.AddDate(0, 0, -s.retentionDays)
	pruned, err := s.opts.Store.PruneHealthSamples(runCtx, pruneCutoff, MaxPruneBatch)
	if err != nil {
		// 采样已写入成功；清理失败不回滚采样，返回错误提醒宿主重试清理。
		return result, fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	result.Pruned = pruned
	return result, nil
}
