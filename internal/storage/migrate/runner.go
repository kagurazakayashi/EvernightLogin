package migrate

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	// failureRecordTimeout 限制失败记录写入的墙钟时间；即使迁移 ctx 已取消，也要
	// 尽力留下失败状态，但不能无限等待。
	failureRecordTimeout = 10 * time.Second
	// maxErrorSummaryRunes 是持久化错误摘要的最大字符数，避免写入超长或含换行的文本。
	maxErrorSummaryRunes = 500
)

// AppliedMigration 是一条已应用迁移的持久化记录。
type AppliedMigration struct {
	Version          string
	Description      string
	Checksum         string
	AppliedAt        time.Time
	NonTransactional bool
}

// FailedMigration 是一条迁移失败记录。失败记录与已应用记录分开保存；再次运行会
// 拒绝继续，直到人工核对数据库状态后调用 Runner.ClearFailure。
type FailedMigration struct {
	Version      string
	Description  string
	Checksum     string
	FailedAt     time.Time
	ErrorSummary string
}

// Backend 是迁移执行器依赖的存储契约，由具体数据库实现（SQLite 在步骤 07 接入）。
//
// 契约要求：
//
//   - Lock 必须提供跨进程/跨连接的迁移排他锁；同一数据库同一时刻只能有一个迁移
//     持有者。ctx 取消时必须释放并返回错误。
//   - EnsureBookkeeping 幂等创建迁移记录表（已应用与失败记录）；迁移记录表属于
//     基础设施结构，不进入用户迁移历史。
//   - LoadApplied 返回已应用记录，按 Version 升序；LoadFailed 返回当前失败记录。
//   - Apply 执行一个迁移：支持事务的数据库必须在同一事务中执行语句并写入
//     AppliedMigration，失败时回滚；非事务迁移允许部分执行，但必须返回错误，由
//     执行器记录失败状态。不得在失败时写入已应用记录。
//   - RecordFailure 在失败事务之外持久化失败记录；ClearFailure 在人工确认后删除
//     指定版本失败记录。
//   - 所有方法都必须响应 ctx 取消。错误文本可能被写入失败摘要，后端不得包含
//     数据库凭据、密钥或其他秘密。
type Backend interface {
	Lock(ctx context.Context, fn func(ctx context.Context) error) error
	EnsureBookkeeping(ctx context.Context) error
	LoadApplied(ctx context.Context) ([]AppliedMigration, error)
	LoadFailed(ctx context.Context) ([]FailedMigration, error)
	Apply(ctx context.Context, statements []string, record AppliedMigration) error
	RecordFailure(ctx context.Context, record FailedMigration) error
	ClearFailure(ctx context.Context, version string) error
}

// Result 是一次迁移运行的结果。失败时返回已成功应用的子集，便于诊断。
type Result struct {
	Applied  []AppliedMigration
	UpToDate bool
}

// Option 配置 Runner。
type Option func(*Runner)

// WithClock 注入时间源，便于测试校验 applied_at/failed_at 记录；生产保持 nil 使用
// 当前 UTC 时间。
func WithClock(now func() time.Time) Option {
	return func(runner *Runner) {
		if now != nil {
			runner.now = now
		}
	}
}

// Runner 按版本顺序执行迁移。Runner 不持有数据库连接，也不实现方言 SQL；这些由
// Backend 提供。Runner 本身可在同一进程内并发调用，排他由 Backend.Lock 保证。
type Runner struct {
	backend    Backend
	migrations []Migration
	versioned  map[string]Migration
	now        func() time.Time
}

// NewRunner 校验迁移集合并构造执行器。迁移必须按四位数字版本升序排列、版本唯一、
// 每条迁移至少含一条语句且有校验和；返回未知指令或文件名等错误时不得运行迁移。
func NewRunner(backend Backend, migrations []Migration, options ...Option) (*Runner, error) {
	if backend == nil {
		return nil, fmt.Errorf("%w：迁移后端为空", ErrInvalidMigration)
	}
	if err := validateMigrationSet(migrations); err != nil {
		return nil, err
	}
	versioned := make(map[string]Migration, len(migrations))
	for _, migration := range migrations {
		versioned[migration.Version] = migration
	}
	runner := &Runner{
		backend:    backend,
		migrations: append([]Migration(nil), migrations...),
		versioned:  versioned,
		now:        time.Now,
	}
	for _, option := range options {
		if option != nil {
			option(runner)
		}
	}
	return runner, nil
}

// Migrations 返回当前迁移定义的副本，供诊断与测试使用。
func (r *Runner) Migrations() []Migration {
	migrations := make([]Migration, len(r.migrations))
	copy(migrations, r.migrations)
	return migrations
}

// Run 在排他锁内执行所有待应用迁移。
//
// 行为：
//   - 已应用记录必须是当前迁移列表的前缀，且每个 checksum 与当前文件一致；
//     顺序不符、版本未知或校验和不一致时拒绝运行。
//   - 存在失败记录时拒绝运行并返回 ErrFailurePending，避免在未知结构上继续叠加。
//   - 已全部应用时返回 UpToDate=true，不重复执行任何迁移。
//   - 某条迁移执行失败时持久化失败记录（尽力在 ctx 取消后仍写入），停止后续迁移，
//     返回已应用子集与错误；再次运行仍会拒绝，直到 ClearFailure。
func (r *Runner) Run(ctx context.Context) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	var result Result
	err := r.backend.Lock(ctx, func(lockCtx context.Context) error {
		if err := lockCtx.Err(); err != nil {
			return err
		}
		if err := r.backend.EnsureBookkeeping(lockCtx); err != nil {
			return fmt.Errorf("初始化迁移记录失败: %w", err)
		}
		applied, err := r.backend.LoadApplied(lockCtx)
		if err != nil {
			return fmt.Errorf("读取已应用迁移失败: %w", err)
		}
		if err := r.validateApplied(applied); err != nil {
			return err
		}
		failed, err := r.backend.LoadFailed(lockCtx)
		if err != nil {
			return fmt.Errorf("读取迁移失败记录失败: %w", err)
		}
		if err := r.validateFailures(failed, applied); err != nil {
			return err
		}

		pending := r.migrations[len(applied):]
		for _, migration := range pending {
			if err := lockCtx.Err(); err != nil {
				return err
			}
			record := AppliedMigration{
				Version:          migration.Version,
				Description:      migration.Description,
				Checksum:         migration.Checksum,
				AppliedAt:        r.now().UTC(),
				NonTransactional: migration.NonTransactional,
			}
			if err := r.backend.Apply(lockCtx, migration.Statements, record); err != nil {
				failure := FailedMigration{
					Version:      migration.Version,
					Description:  migration.Description,
					Checksum:     migration.Checksum,
					FailedAt:     r.now().UTC(),
					ErrorSummary: summarizeError(err),
				}
				recordCtx, cancel := context.WithTimeout(context.WithoutCancel(lockCtx), failureRecordTimeout)
				recordErr := r.backend.RecordFailure(recordCtx, failure)
				cancel()
				if recordErr != nil {
					return errors.Join(
						fmt.Errorf("迁移 %s 执行失败: %w", migration.Version, err),
						fmt.Errorf("记录迁移失败状态失败: %w", recordErr),
					)
				}
				return fmt.Errorf("迁移 %s（%s）执行失败: %w",
					migration.Version, migration.FileName, err)
			}
			result.Applied = append(result.Applied, record)
		}
		result.UpToDate = len(result.Applied) == 0
		return nil
	})
	if err != nil {
		return result, err
	}
	return result, nil
}

// ClearFailure 删除指定版本的失败记录，使下一次 Run 可以重试。
//
// 它只应在人工核对数据库结构（事务回滚或手动修复）后调用；执行器无法判断失败
// 迁移是否留下了部分结构，不能自动清理或自动重试。
func (r *Runner) ClearFailure(ctx context.Context, version string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := r.versioned[version]; !ok {
		return fmt.Errorf("%w：失败记录版本 %s 不存在", ErrInvalidMigration, version)
	}
	return r.backend.Lock(ctx, func(lockCtx context.Context) error {
		if err := lockCtx.Err(); err != nil {
			return err
		}
		if err := r.backend.EnsureBookkeeping(lockCtx); err != nil {
			return fmt.Errorf("初始化迁移记录失败: %w", err)
		}
		return r.backend.ClearFailure(lockCtx, version)
	})
}

// validateApplied 校验已应用迁移是当前迁移列表的严格前缀，并逐项比较校验和。
func (r *Runner) validateApplied(applied []AppliedMigration) error {
	records := append([]AppliedMigration(nil), applied...)
	sort.Slice(records, func(left, right int) bool {
		return records[left].Version < records[right].Version
	})

	seen := make(map[string]bool, len(records))
	if len(records) > len(r.migrations) {
		return fmt.Errorf("%w：已应用 %d 条，当前迁移定义 %d 条",
			ErrMigrationOrder, len(records), len(r.migrations))
	}
	for index, record := range records {
		if seen[record.Version] {
			return fmt.Errorf("%w：已应用记录版本 %s 重复",
				ErrMigrationHistoryInvalid, record.Version)
		}
		seen[record.Version] = true

		migration, ok := r.versioned[record.Version]
		if !ok {
			return fmt.Errorf("%w：版本 %s", ErrUnknownAppliedMigration, record.Version)
		}
		if migration.Checksum != record.Checksum {
			return fmt.Errorf("%w：版本 %s（已应用 %s，当前 %s）",
				ErrChecksumMismatch, record.Version, shortChecksum(record.Checksum), shortChecksum(migration.Checksum))
		}
		if index >= len(r.migrations) || r.migrations[index].Version != record.Version {
			return fmt.Errorf("%w：第 %d 条已应用版本为 %s，期望 %s",
				ErrMigrationOrder, index+1, record.Version, expectedVersion(r.migrations, index))
		}
	}
	return nil
}

// validateFailures 拒绝在存在失败记录时继续；失败记录必须对应已定义且未应用的
// 迁移，否则历史已矛盾，需要人工处理。
func (r *Runner) validateFailures(failed []FailedMigration, applied []AppliedMigration) error {
	if len(failed) == 0 {
		return nil
	}
	appliedVersions := make(map[string]bool, len(applied))
	for _, record := range applied {
		appliedVersions[record.Version] = true
	}
	versions := make([]string, 0, len(failed))
	for _, failure := range failed {
		if _, ok := r.versioned[failure.Version]; !ok {
			return fmt.Errorf("%w：失败记录版本 %s 不在当前迁移文件中",
				ErrMigrationHistoryInvalid, failure.Version)
		}
		if appliedVersions[failure.Version] {
			return fmt.Errorf("%w：版本 %s 已应用但仍存在失败记录",
				ErrMigrationHistoryInvalid, failure.Version)
		}
		versions = append(versions, failure.Version)
	}
	sort.Strings(versions)
	return fmt.Errorf("%w：%s；请人工核对数据库状态后调用 ClearFailure",
		ErrFailurePending, strings.Join(versions, "、"))
}

// expectedVersion 返回给定下标期望的版本，用于错误信息。
func expectedVersion(migrations []Migration, index int) string {
	if index < 0 || index >= len(migrations) {
		return "（无）"
	}
	return migrations[index].Version
}

// shortChecksum 只显示校验和前缀，避免错误信息过长。
func shortChecksum(checksum string) string {
	if len(checksum) <= 12 {
		return checksum
	}
	return checksum[:12] + "..."
}

// summarizeError 把错误压成单行、限制长度后用于失败记录。它不能保证清除所有
// 敏感信息，因此 Backend 的错误不得包含凭据、密钥或完整 SQL 参数。
func summarizeError(err error) string {
	if err == nil {
		return "未知错误"
	}
	var builder strings.Builder
	previousSpace := false
	for _, character := range err.Error() {
		if character < 0x20 || character == 0x7f {
			character = ' '
		}
		if character == ' ' {
			if previousSpace {
				continue
			}
			previousSpace = true
		} else {
			previousSpace = false
		}
		builder.WriteRune(character)
	}
	summary := strings.TrimSpace(builder.String())
	if summary == "" {
		return "未知错误"
	}
	runes := []rune(summary)
	if len(runes) > maxErrorSummaryRunes {
		summary = string(runes[:maxErrorSummaryRunes-3]) + "..."
	}
	return summary
}
