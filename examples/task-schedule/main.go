// Command task-schedule 演示定时计划、触发去重与轻量任务处理器的本地接线。
//
// 示例使用确定性时钟手动推进时间并直接调用 Scheduler.Tick，不启动真实调度
// 循环，也不连接外部数据库或等待真实时间：临时 SQLite 数据库在退出时删除。
// 运行方式：go run ./examples/task-schedule
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	tasksqlite "github.com/kagurazakayashi/EvernightLogin/internal/task/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// demoClock 是确定性时钟；示例手动 Set 时间，不依赖真实等待。
type demoClock struct {
	now time.Time
}

// Now 返回当前示例时间。
func (c *demoClock) Now() time.Time { return c.now }

// Set 设置示例时间。
func (c *demoClock) Set(moment time.Time) { c.now = moment.UTC() }

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "示例失败:", err)
		os.Exit(1)
	}
}

// run 执行完整示例；所有资源在函数返回前关闭，临时目录自动删除。
func run() error {
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "login-task-schedule-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(filepath.Join(dir, "demo.db")))
	if err != nil {
		return err
	}
	defer raw.Close()
	migrationSet, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		return err
	}
	if _, err := raw.Migrate(ctx, migrationSet); err != nil {
		return err
	}

	clock := &demoClock{now: time.Date(2021, 4, 25, 4, 0, 0, 0, time.UTC)} // 上海 12:00
	store, err := tasksqlite.New(raw, tasksqlite.Options{Now: clock.Now})
	if err != nil {
		return err
	}
	executed := make(chan string, 4)
	executor, err := task.New(store, task.Options{
		Handlers: map[string]task.Handler{
			// 轻量示例处理器：只记录任务编号，不做真实外部副作用。
			"demo.echo": func(ctx context.Context, job task.Job) error {
				select {
				case executed <- job.ID:
				default:
				}
				return nil
			},
		},
		ExecutorID:      "demo-executor-1",
		MaxConcurrent:   1,
		PollInterval:    task.MinPollInterval,
		ShutdownTimeout: 3 * time.Second,
		Now:             clock.Now,
	})
	if err != nil {
		return err
	}
	if err := executor.Start(ctx); err != nil {
		return err
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = executor.Stop(stopCtx)
	}()

	scheduler, err := task.NewScheduler(task.SchedulerOptions{
		Store:       store,
		SchedulerID: "demo-scheduler-1",
		Executor:    executor,
		// 示例展示无需权限复验的非管理任务；生产管理任务必须配置可信回调。
		Now: clock.Now,
	})
	if err != nil {
		return err
	}
	executionActor := audit.Actor{Type: audit.ActorUser, ID: "demo-owner"}
	schedule, err := scheduler.Create(ctx, task.NewScheduleRequest{
		JobKind:          "demo.echo",
		ScheduleType:     task.ScheduleTypeDaily,
		Expression:       "02:30",
		TimeZone:         "Asia/Shanghai",
		Owner:            executionActor,
		ExecutionActor:   executionActor,
		Enabled:          true,
		PermissionExempt: true,
		TimeoutSeconds:   30,
		MaxAttempts:      1,
	})
	if err != nil {
		return err
	}
	fmt.Printf("已创建计划 %s：每天 02:30（Asia/Shanghai），已启用\n", schedule.ID)

	// 未到期：Tick 不触发。
	if err := scheduler.Tick(ctx); err != nil {
		return err
	}
	// 确定性地把时钟推进到上海次日 02:30（UTC 前一日 18:30）。
	due := time.Date(2021, 4, 25, 18, 30, 0, 0, time.UTC)
	clock.Set(due)
	if err := scheduler.Tick(ctx); err != nil {
		return err
	}
	firstJob, err := waitExecuted(executed)
	if err != nil {
		return err
	}
	fmt.Printf("到点任务已执行：%s\n", firstJob)

	// 同一触发时刻重复 Tick 不会重复入队；次日准点再触发一次。
	if err := scheduler.Tick(ctx); err != nil {
		return err
	}
	clock.Set(due.Add(24 * time.Hour))
	if err := scheduler.Tick(ctx); err != nil {
		return err
	}
	secondJob, err := waitExecuted(executed)
	if err != nil {
		return err
	}
	if secondJob == firstJob {
		return errors.New("同一触发时刻被重复入队")
	}
	fmt.Printf("次日任务已执行：%s（同一触发时刻未重复入队）\n", secondJob)
	fmt.Println("示例完成：确定性时钟、计划触发与触发去重均按预期工作。")
	return nil
}

// waitExecuted 等待示例处理器报告一次执行，超时返回错误。
func waitExecuted(executed <-chan string) (string, error) {
	select {
	case jobID := <-executed:
		return jobID, nil
	case <-time.After(5 * time.Second):
		return "", errors.New("等待示例处理器超时")
	}
}
