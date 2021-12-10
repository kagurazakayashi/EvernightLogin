package managecli

// 本文件覆盖 `loginctl task`：只读列表/详情、异步等待成功与本地超时、取消请求
// 与终态冲突；验证输出不含任务载荷、退出码区分“等待超时”和“任务失败”。

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	tasksqlite "github.com/kagurazakayashi/EvernightLogin/internal/task/sqlite"
)

// taskTestEnv 是任务命令测试环境。
type taskTestEnv struct {
	configPath string
	store      *tasksqlite.Store
}

// newTaskTestEnv 构造临时数据库与任务存储。
func newTaskTestEnv(t *testing.T) *taskTestEnv {
	t.Helper()
	databasePath, raw := newTestDatabase(t)
	store, err := tasksqlite.New(raw, tasksqlite.Options{
		Now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatalf("构造任务存储: %v", err)
	}
	return &taskTestEnv{configPath: writeConfigFile(t, t.TempDir(), databasePath), store: store}
}

// enqueueJob 入队一个测试任务，返回任务 ID。
func (env *taskTestEnv) enqueueJob(t *testing.T, kind string) string {
	t.Helper()
	id, err := task.NewJobID()
	if err != nil {
		t.Fatalf("生成任务 ID: %v", err)
	}
	if _, err := env.store.Enqueue(context.Background(), task.NewJob{ID: id,
		Kind: kind, Initiator: audit.Actor{Type: audit.ActorLocalAdmin, ID: "test-operator"},
		Payload: json.RawMessage(`{}`), TimeoutSeconds: 60, MaxAttempts: 1,
		CreatedAt: testNow}); err != nil {
		t.Fatalf("入队任务: %v", err)
	}
	return id
}

// TestTaskListAndGet 验证列表/详情只读输出且不含载荷正文。
func TestTaskListAndGet(t *testing.T) {
	env := newTaskTestEnv(t)
	jobID := env.enqueueJob(t, "test.kind")
	stdout, stderr, exit := runCLI(t, "task", "list", "--config", env.configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("task list 退出码 = %d，stderr=%s", exit, stderr)
	}
	data := decodeEnvelope(t, stdout)["data"].(map[string]any)
	jobs, _ := data["jobs"].([]any)
	if len(jobs) != 1 {
		t.Fatalf("任务列表 = %v", data)
	}
	item := jobs[0].(map[string]any)
	if item["id"] != jobID || item["state"] != "queued" {
		t.Fatalf("任务投影 = %v", item)
	}
	if _, hasPayload := item["payload"]; hasPayload {
		t.Fatal("任务输出不应包含载荷")
	}
	stdout, _, exit = runCLI(t, "task", "get", jobID, "--config", env.configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("task get 退出码 = %d", exit)
	}
	if decodeEnvelope(t, stdout)["data"].(map[string]any)["id"] != jobID {
		t.Fatalf("详情输出 = %s", stdout)
	}
	// 不存在的任务返回明确错误码。
	stdout, _, exit = runCLI(t, "task", "get", taskMissingID(), "--config",
		env.configPath, "--json")
	if exit != ExitError {
		t.Fatalf("缺失任务退出码 = %d，期望 %d", exit, ExitError)
	}
	if code := envelopeErrorCode(t, decodeEnvelope(t, stdout)); code != "TASK_NOT_FOUND" {
		t.Fatalf("错误码 = %s", code)
	}
}

// taskMissingID 返回格式合法但不存在任务 ID。
func taskMissingID() string {
	return "job_00000000000000000000000000000000"
}

// TestTaskWaitSucceeds 验证异步等待在任务完成后返回 0 与真实状态。
func TestTaskWaitSucceeds(t *testing.T) {
	env := newTaskTestEnv(t)
	jobID := env.enqueueJob(t, "test.kind")
	// 通过真实存储状态机把任务推进到成功终态。
	claimed, ok, err := env.store.Claim(context.Background(), "executor-test", testNow)
	if err != nil || !ok {
		t.Fatalf("领取任务: ok=%v err=%v", ok, err)
	}
	if _, err := env.store.Complete(context.Background(), task.Completion{
		JobID: claimed.ID, State: task.StateSucceeded, ExecutorID: "executor-test",
		Now: testNow}); err != nil {
		t.Fatalf("完成任务: %v", err)
	}
	stdout, stderr, exit := runCLI(t, "task", "wait", jobID, "--timeout", "5s",
		"--config", env.configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("wait 退出码 = %d，stderr=%s", exit, stderr)
	}
	if decodeEnvelope(t, stdout)["data"].(map[string]any)["state"] != "succeeded" {
		t.Fatalf("wait 输出 = %s", stdout)
	}
}

// TestTaskWaitLocalTimeout 验证本地等待超时返回 7 且任务仍在运行（不是失败）。
func TestTaskWaitLocalTimeout(t *testing.T) {
	env := newTaskTestEnv(t)
	jobID := env.enqueueJob(t, "test.kind")
	stdout, _, exit := runCLI(t, "task", "wait", jobID, "--timeout", "1s",
		"--config", env.configPath, "--json")
	if exit != ExitTimeout {
		t.Fatalf("等待超时退出码 = %d，期望 %d", exit, ExitTimeout)
	}
	envelope := decodeEnvelope(t, stdout)
	if envelope["ok"] != false {
		t.Fatalf("超时外壳 = %v", envelope)
	}
	if code := envelopeErrorCode(t, envelope); code != "WAIT_TIMEOUT" {
		t.Fatalf("错误码 = %s", code)
	}
	details := envelope["error"].(map[string]any)["details"].(map[string]any)
	if details["state"] != "queued" {
		t.Fatalf("超时详情应显示任务仍在等待: %v", details)
	}
}

// TestTaskWaitFailureExitCode 验证任务失败终态使用退出码 8 与 TASK_FAILED。
func TestTaskWaitFailureExitCode(t *testing.T) {
	env := newTaskTestEnv(t)
	jobID := env.enqueueJob(t, "test.kind")
	claimed, ok, err := env.store.Claim(context.Background(), "executor-test", testNow)
	if err != nil || !ok {
		t.Fatalf("领取任务: ok=%v err=%v", ok, err)
	}
	if _, err := env.store.Complete(context.Background(), task.Completion{
		JobID: claimed.ID, State: task.StateFailed, ExecutorID: "executor-test",
		ErrorCode: "TEST_FAILED", FailureReason: "测试失败", Now: testNow}); err != nil {
		t.Fatalf("完成任务: %v", err)
	}
	stdout, _, exit := runCLI(t, "task", "wait", jobID, "--timeout", "5s",
		"--config", env.configPath, "--json")
	if exit != ExitTaskFailed {
		t.Fatalf("任务失败退出码 = %d，期望 %d", exit, ExitTaskFailed)
	}
	if code := envelopeErrorCode(t, decodeEnvelope(t, stdout)); code != "TASK_FAILED" {
		t.Fatalf("错误码 = %s", code)
	}
}

// TestTaskCancelRequestAndConflict 验证取消请求被接受后再次取消返回冲突。
func TestTaskCancelRequestAndConflict(t *testing.T) {
	env := newTaskTestEnv(t)
	jobID := env.enqueueJob(t, "test.kind")
	stdout, stderr, exit := runCLI(t, "task", "cancel", jobID, "--operator", "local-admin",
		"--reason", "测试取消", "--config", env.configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("取消请求退出码 = %d，stderr=%s", exit, stderr)
	}
	data := decodeEnvelope(t, stdout)["data"].(map[string]any)
	if data["accepted"] != true || data["state"] != "cancelled" {
		t.Fatalf("取消结果 = %v", data)
	}
	// 终态任务再次取消应返回冲突退出码 6。
	stdout, _, exit = runCLI(t, "task", "cancel", jobID, "--operator", "local-admin",
		"--reason", "重复取消", "--config", env.configPath, "--json")
	if exit != ExitConflict {
		t.Fatalf("终态取消退出码 = %d，期望 %d；输出 %s", exit, ExitConflict, stdout)
	}
	if code := envelopeErrorCode(t, decodeEnvelope(t, stdout)); code != "TASK_CANCEL_CONFLICT" {
		t.Fatalf("错误码 = %s", code)
	}
}

// TestTaskCancelRejectsUntrustedOperator 验证非法本地操作者被拒绝。
func TestTaskCancelRejectsUntrustedOperator(t *testing.T) {
	env := newTaskTestEnv(t)
	jobID := env.enqueueJob(t, "test.kind")
	_, _, exit := runCLI(t, "task", "cancel", jobID, "--operator", "含 空格?",
		"--reason", "测试", "--config", env.configPath)
	if exit != ExitUsage {
		t.Fatalf("非法操作者退出码 = %d，期望 %d", exit, ExitUsage)
	}
}
