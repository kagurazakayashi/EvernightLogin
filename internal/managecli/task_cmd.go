// 本文件实现 `loginctl task` 命令：后台任务只读查询、等待与取消请求。
//
// 语义边界：
//   - 任务提交成功不等于完成；cancel 只提交取消请求，输出必须区分“已接受请求”
//     与“实际已取消”。
//   - wait 在本地墙钟上限内轮询真实任务状态；超时只代表本次等待结束，任务可能
//     仍在运行，退出码与“任务失败/超时终态”分开。
//   - 所有命令只使用当前进程内的轮询与 ctx 取消，不启动常驻协程、不遗留进程；
//     Ctrl+C 立即结束等待并返回 130。
//   - 输出不含任务载荷（payload）正文，只含状态与可追溯标识。
package managecli

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	tasksqlite "github.com/kagurazakayashi/EvernightLogin/internal/task/sqlite"
)

// taskCommandUsage 是 task 组帮助。
const taskCommandUsage = `用法：
  loginctl task list [--config <file>] [--state <s>] [--kind <k>] [--limit N] [--json]
  loginctl task get <job_id> [--config <file>] [--json]
  loginctl task wait <job_id> [--timeout 60s] [--config <file>] [--json]
  loginctl task cancel <job_id> --operator <id> --reason <原因> [--config <file>] [--json]

说明：
  - list/get/wait 只读；cancel 只提交取消请求，输出 accepted/state，不声称已取消。
  - wait 的本地等待上限 1s～24h（默认 60s）；等待超时退出码 7（任务可能仍在运行），
    终态失败/超时退出码 8，被取消退出码 3。
  - 输出不含任务载荷正文。`

// 任务等待与列表的本地边界。
const (
	defaultTaskWait      = 60 * time.Second
	minTaskWait          = time.Second
	maxTaskWait          = 24 * time.Hour
	taskPollInitial      = 100 * time.Millisecond
	taskPollMax          = time.Second
	taskListDefaultLimit = 20
	taskListMaxLimit     = 100
)

// taskOutput 是任务的可公开投影（不含 payload）。
type taskOutput struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"`
	State          string `json:"state"`
	InitiatorType  string `json:"initiator_type"`
	InitiatorID    string `json:"initiator_id"`
	ExecutorID     string `json:"executor_id,omitempty"`
	Attempt        int    `json:"attempt"`
	MaxAttempts    int    `json:"max_attempts"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	ErrorCode      string `json:"error_code,omitempty"`
	FailureReason  string `json:"failure_reason,omitempty"`
	RequestID      string `json:"request_id,omitempty"`
	CreatedAt      string `json:"created_at"`
	StartedAt      string `json:"started_at,omitempty"`
	FinishedAt     string `json:"finished_at,omitempty"`
	Deadline       string `json:"deadline,omitempty"`
}

// newTaskOutput 把任务投影为可公开输出；时间统一 RFC3339（UTC）。
func newTaskOutput(job task.Job) taskOutput {
	output := taskOutput{ID: job.ID, Kind: job.Kind, State: string(job.State),
		InitiatorType: string(job.Initiator.Type), InitiatorID: job.Initiator.ID,
		ExecutorID: job.ExecutorID, Attempt: job.Attempt, MaxAttempts: job.MaxAttempts,
		TimeoutSeconds: job.TimeoutSeconds, ErrorCode: job.ErrorCode,
		FailureReason: job.FailureReason, RequestID: job.RequestID,
		CreatedAt: formatTime(job.CreatedAt)}
	if !job.StartedAt.IsZero() {
		output.StartedAt = formatTime(job.StartedAt)
	}
	if !job.FinishedAt.IsZero() {
		output.FinishedAt = formatTime(job.FinishedAt)
	}
	if job.TimeoutSeconds > 0 {
		output.Deadline = formatTime(job.Deadline())
	}
	return output
}

// formatTime 输出 UTC RFC3339 时间；零值输出空串。
func formatTime(moment time.Time) string {
	if moment.IsZero() {
		return ""
	}
	return moment.UTC().Format(time.RFC3339Nano)
}

// runTask 分派 task 子命令。
func (r *runner) runTask(args []string) int {
	r.usageText = taskCommandUsage
	if len(args) == 0 {
		return r.helpText("task", taskCommandUsage)
	}
	subcommand, rest := args[0], args[1:]
	r.command = "task " + subcommand
	switch subcommand {
	case "list":
		return r.runTaskList(rest)
	case "get":
		return r.runTaskGet(rest)
	case "wait":
		return r.runTaskWait(rest)
	case "cancel":
		return r.runTaskCancel(rest)
	case "help", "-h", "--help":
		return r.helpText("task", taskCommandUsage)
	default:
		return r.usage("未知的 task 子命令 %q（可用：list/get/wait/cancel）", subcommand)
	}
}

// openTaskStore 打开配置指向的数据库并包装任务存储；调用方负责关闭 raw。
// readOnly 为 true 时以只读意图打开（list/get/wait），不主动切换 WAL。
func (r *runner) openTaskStore(values map[string]string,
	readOnly bool) (*storagesqlite.Store, *tasksqlite.Store, int) {
	config, exit := r.loadEffectiveConfig(values)
	if exit != ExitOK {
		return nil, nil, exit
	}
	var raw *storagesqlite.Store
	if readOnly {
		raw, exit = r.openDatabaseReadOnly(config)
	} else {
		raw, exit = r.openDatabase(config)
	}
	if exit != ExitOK {
		return nil, nil, exit
	}
	taskStore, err := tasksqlite.New(raw, tasksqlite.Options{Now: r.options.Now})
	if err != nil {
		_ = raw.Close()
		return nil, nil, r.fail("TASK_STORE_UNAVAILABLE", ExitError, "无法构造任务存储", nil)
	}
	return raw, taskStore, ExitOK
}

// runTaskList 列出最近任务（只读；不含 payload）。
func (r *runner) runTaskList(args []string) int {
	values, positional, err := parseFlags(args, []flagDef{
		{name: "config", value: true}, {name: "json"}, {name: "state", value: true},
		{name: "kind", value: true}, {name: "limit", value: true},
	})
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 0 {
		return r.usage("task list 不接受位置参数")
	}
	r.json = boolFlag(values, "json")
	limit, err := parseLimit(values, taskListDefaultLimit, taskListMaxLimit)
	if err != nil {
		return r.usage("%v", err)
	}
	state := stringFlag(values, "state")
	if state != "" && !task.State(state).Valid() {
		return r.usage("--state 不是已定义的任务状态")
	}
	kind := strings.TrimSpace(values["kind"])
	if len(kind) > 128 {
		return r.usage("--kind 过长")
	}
	raw, taskStore, exit := r.openTaskStore(values, true)
	if exit != ExitOK {
		return exit
	}
	defer func() { _ = raw.Close() }()
	query := `SELECT id FROM jobs WHERE 1=1`
	var arguments []any
	if state != "" {
		query += " AND state = ?"
		arguments = append(arguments, state)
	}
	if kind != "" {
		query += " AND kind = ?"
		arguments = append(arguments, kind)
	}
	query += " ORDER BY created_at_ms DESC, id DESC LIMIT ?"
	arguments = append(arguments, limit+1)
	rows, err := raw.DB().QueryContext(r.ctx, query, arguments...)
	if err != nil {
		return r.fail("DB_UNAVAILABLE", ExitError, "查询任务列表失败", nil)
	}
	ids := make([]string, 0, limit+1)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return r.fail("DB_UNAVAILABLE", ExitError, "读取任务编号失败", nil)
		}
		ids = append(ids, id)
	}
	rowErr := rows.Err()
	rows.Close()
	if rowErr != nil {
		return r.fail("DB_UNAVAILABLE", ExitError, "读取任务编号失败", nil)
	}
	hasMore := len(ids) > limit
	if hasMore {
		ids = ids[:limit]
	}
	items := make([]taskOutput, 0, len(ids))
	for _, id := range ids {
		job, found, err := taskStore.Get(r.ctx, id)
		if err != nil {
			return r.fail("DB_UNAVAILABLE", ExitError, "读取任务记录失败", nil)
		}
		if !found {
			continue
		}
		items = append(items, newTaskOutput(job))
	}
	output := map[string]any{"jobs": items, "has_more": hasMore, "limit": limit}
	if r.json {
		return r.succeed(output)
	}
	if len(items) == 0 {
		fmt.Fprintln(r.stdout, "没有匹配的任务。")
		return ExitOK
	}
	for _, item := range items {
		fmt.Fprintf(r.stdout, "%s  %s  %s  kind=%s  attempt=%d/%d  created=%s\n",
			item.ID, item.State, item.InitiatorID, item.Kind, item.Attempt,
			item.MaxAttempts, item.CreatedAt)
	}
	if hasMore {
		fmt.Fprintln(r.stdout, "（还有更多结果；请用 --limit 或状态/类型筛选缩小范围）")
	}
	return ExitOK
}

// runTaskGet 读取单个任务状态。
func (r *runner) runTaskGet(args []string) int {
	values, positional, err := parseFlags(args, []flagDef{
		{name: "config", value: true}, {name: "json"},
	})
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 1 {
		return r.usage("用法：loginctl task get <job_id> [--config <file>] [--json]")
	}
	r.json = boolFlag(values, "json")
	jobID := strings.TrimSpace(positional[0])
	if err := task.ValidateJobID(jobID); err != nil {
		return r.usage("任务编号格式无效")
	}
	raw, taskStore, exit := r.openTaskStore(values, true)
	if exit != ExitOK {
		return exit
	}
	defer func() { _ = raw.Close() }()
	job, found, err := taskStore.Get(r.ctx, jobID)
	if err != nil {
		return r.fail("DB_UNAVAILABLE", ExitError, "读取任务失败", nil)
	}
	if !found {
		return r.fail("TASK_NOT_FOUND", ExitError, "任务不存在", nil)
	}
	output := newTaskOutput(job)
	if r.json {
		return r.succeed(output)
	}
	fmt.Fprintf(r.stdout, "任务：%s\n状态：%s\n类型：%s\n发起者：%s/%s\n尝试：%d/%d\n",
		output.ID, output.State, output.Kind, output.InitiatorType,
		output.InitiatorID, output.Attempt, output.MaxAttempts)
	if output.ErrorCode != "" {
		fmt.Fprintf(r.stdout, "错误码：%s\n", output.ErrorCode)
	}
	if output.FailureReason != "" {
		fmt.Fprintf(r.stdout, "失败原因：%s\n", output.FailureReason)
	}
	fmt.Fprintf(r.stdout, "创建：%s；开始：%s；结束：%s\n",
		output.CreatedAt, valueOrDash(output.StartedAt), valueOrDash(output.FinishedAt))
	return ExitOK
}

// valueOrDash 把空值显示为“-”。
func valueOrDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

// runTaskWait 在本地墙钟上限内等待任务进入终态。
func (r *runner) runTaskWait(args []string) int {
	values, positional, err := parseFlags(args, []flagDef{
		{name: "config", value: true}, {name: "json"}, {name: "timeout", value: true},
	})
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 1 {
		return r.usage("用法：loginctl task wait <job_id> [--timeout 60s] [--config <file>] [--json]")
	}
	r.json = boolFlag(values, "json")
	jobID := strings.TrimSpace(positional[0])
	if err := task.ValidateJobID(jobID); err != nil {
		return r.usage("任务编号格式无效")
	}
	waitTimeout := defaultTaskWait
	if raw := stringFlag(values, "timeout"); raw != "" {
		parsed, parseErr := time.ParseDuration(raw)
		if parseErr != nil {
			return r.usage("--timeout 必须是时长（例如 60s、5m），且不超过 24h")
		}
		if parsed < minTaskWait || parsed > maxTaskWait {
			return r.usage("--timeout 必须在 1s～24h 之间")
		}
		waitTimeout = parsed
	}
	raw, taskStore, exit := r.openTaskStore(values, true)
	if exit != ExitOK {
		return exit
	}
	defer func() { _ = raw.Close() }()
	deadline := time.Now().Add(waitTimeout)
	pollInterval := taskPollInitial
	for {
		job, found, err := taskStore.Get(r.ctx, jobID)
		if err != nil {
			return r.fail("DB_UNAVAILABLE", ExitError, "读取任务失败", nil)
		}
		if !found {
			return r.fail("TASK_NOT_FOUND", ExitError, "任务不存在", nil)
		}
		if job.State.Terminal() {
			output := newTaskOutput(job)
			exitCode := ExitOK
			code := ""
			message := ""
			switch job.State {
			case task.StateSucceeded:
				exitCode = ExitOK
			case task.StateCancelled:
				exitCode = ExitCancelled
				code = "TASK_CANCELLED"
				message = "任务已取消"
			case task.StateFailed:
				exitCode = ExitTaskFailed
				code = "TASK_FAILED"
				message = "任务失败"
			case task.StateTimedOut:
				exitCode = ExitTaskFailed
				code = "TASK_TIMEOUT"
				message = "任务执行超时"
			}
			if r.json {
				envelope := jsonEnvelope{OK: exitCode == ExitOK, Command: r.command, Data: output}
				if exitCode != ExitOK {
					envelope.Error = &jsonError{Code: code, Message: message, Details: output}
					envelope.Data = nil
				}
				r.writeEnvelope(envelope)
			} else {
				fmt.Fprintf(r.stdout, "任务 %s 结束：%s\n", output.ID, output.State)
				if output.ErrorCode != "" {
					fmt.Fprintf(r.stdout, "错误码：%s\n", output.ErrorCode)
				}
			}
			return exitCode
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			output := newTaskOutput(job)
			if r.json {
				r.writeEnvelope(jsonEnvelope{OK: false, Command: r.command,
					Error: &jsonError{Code: "WAIT_TIMEOUT",
						Message: "本地等待超时；任务可能仍在运行", Details: output}})
			} else {
				fmt.Fprintf(r.stdout, "等待超时：任务 %s 当前状态 %s，可能仍在运行。\n",
					output.ID, output.State)
			}
			return ExitTimeout
		}
		if pollInterval > remaining {
			pollInterval = remaining
		}
		timer := time.NewTimer(pollInterval)
		select {
		case <-r.ctx.Done():
			timer.Stop()
			return ExitInterrupted
		case <-timer.C:
		}
		if pollInterval < taskPollMax {
			pollInterval *= 2
			if pollInterval > taskPollMax {
				pollInterval = taskPollMax
			}
		}
	}
}

// runTaskCancel 提交取消请求；输出真实接受状态，不把请求当作已取消。
func (r *runner) runTaskCancel(args []string) int {
	values, positional, err := parseFlags(args, []flagDef{
		{name: "config", value: true}, {name: "json"}, {name: "operator", value: true},
		{name: "reason", value: true},
	})
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 1 {
		return r.usage("用法：loginctl task cancel <job_id> --operator <id> --reason <原因> " +
			"[--config <file>] [--json]")
	}
	r.json = boolFlag(values, "json")
	jobID := strings.TrimSpace(positional[0])
	if err := task.ValidateJobID(jobID); err != nil {
		return r.usage("任务编号格式无效")
	}
	operator := stringFlag(values, "operator")
	reason := stringFlag(values, "reason")
	if operator == "" || reason == "" {
		return r.usage("--operator 与 --reason 必填")
	}
	caller, err := account.LocalBootstrapCaller(operator)
	if err != nil {
		return r.usage("--operator 本地管理员标识无效（只允许可见 ASCII 稳定标识）")
	}
	raw, taskStore, exit := r.openTaskStore(values, false)
	if exit != ExitOK {
		return exit
	}
	defer func() { _ = raw.Close() }()
	result, err := taskStore.RequestCancel(r.ctx, task.CancelCommand{JobID: jobID,
		Actor: caller.Actor(), Reason: reason, Now: r.options.Now()})
	if err != nil {
		code, exitCode := taskError(err)
		return r.fail(code, exitCode, "取消请求未被接受："+err.Error(), nil)
	}
	output := map[string]any{"accepted": result.Accepted,
		"already_requested": result.AlreadyRequested, "state": string(result.State)}
	if r.json {
		return r.succeed(output)
	}
	if result.Accepted {
		fmt.Fprintf(r.stdout, "已提交取消请求；任务当前状态：%s（请求被接受不等于已取消）。\n",
			result.State)
	} else {
		fmt.Fprintf(r.stdout, "取消请求未产生新的变更；任务当前状态：%s。\n", result.State)
	}
	return ExitOK
}

// taskError 把任务领域错误映射为稳定错误码与退出码。
func taskError(err error) (string, int) {
	switch {
	case errors.Is(err, task.ErrTaskNotFound):
		return "TASK_NOT_FOUND", ExitError
	case errors.Is(err, task.ErrTaskTerminal):
		return "TASK_CANCEL_CONFLICT", ExitConflict
	case errors.Is(err, task.ErrUntrustedActor):
		return "ACCESS_DENIED", ExitForbidden
	case errors.Is(err, task.ErrInvalidRequest):
		return "REQ_INVALID", ExitUsage
	case errors.Is(err, task.ErrStoreUnavailable):
		return "DB_UNAVAILABLE", ExitError
	default:
		return "INTERNAL_ERROR", ExitError
	}
}
