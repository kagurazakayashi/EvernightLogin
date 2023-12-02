// 无人值守短测试场景：应用委派管理与客服示例（examples/app-delegation-support）。
//
// 只使用标准库：构建真实外部示例模块并运行其 -self-test -json，核验结构化结果、
// 构建产物与临时目录清理；不监听端口、不访问网络。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	scenarioID         = "app-delegation-support-selftest"
	exampleModuleDir   = "examples/app-delegation-support"
	exampleSchema      = "evernight.app-delegation-support.selftest/v1"
	minExampleChecks   = 10
	scenarioResultPath = "evernight.shorttest.scenario-result/v1"
)

type check struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type exampleResult struct {
	Schema         string  `json:"schema"`
	Status         string  `json:"status"`
	DataDir        string  `json:"data_dir"`
	DataDirRemoved bool    `json:"data_dir_removed"`
	Checks         []check `json:"checks"`
	Error          string  `json:"error"`
}

type scenarioResult struct {
	Schema     string  `json:"schema"`
	Scenario   string  `json:"scenario"`
	Status     string  `json:"status"`
	Checks     []check `json:"checks"`
	DurationMS int64   `json:"duration_ms"`
	Error      string  `json:"error,omitempty"`
}

type options struct {
	workDir    string
	timeout    time.Duration
	resultPath string
}

func runScenario() int {
	var opts options
	var timeoutRaw string
	flag.StringVar(&opts.workDir, "workdir", "", "入口临时目录")
	flag.StringVar(&timeoutRaw, "timeout", "120", "总超时（秒）")
	flag.StringVar(&opts.resultPath, "result", "", "结果 JSON 输出路径")
	flag.Parse()
	seconds, parseErr := strconv.Atoi(strings.TrimSpace(timeoutRaw))
	if parseErr != nil || seconds <= 0 {
		seconds = 120
	}
	opts.timeout = time.Duration(seconds) * time.Second
	startedAt := time.Now()
	report := scenarioResult{Schema: scenarioResultPath, Scenario: scenarioID,
		Status: "PASS", Checks: []check{}}
	fail := func(id string, err error) int {
		report.Status = "FAIL"
		report.Checks = append(report.Checks, check{ID: id, Status: "FAIL",
			Detail: err.Error()})
		report.Error = err.Error()
		return finish(report, startedAt, opts, 1)
	}
	if opts.workDir == "" {
		return fail("arguments", errors.New("-workdir 必填"))
	}
	repoRoot, err := findRepoRoot()
	if err != nil {
		return fail("repo_root", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()
	binary := filepath.Join(opts.workDir, "app-delegation-support.exe")
	buildCtx, buildCancel := context.WithTimeout(ctx, minDuration(opts.timeout, 90*time.Second))
	defer buildCancel()
	build := exec.CommandContext(buildCtx, "go", "build", "-o", binary, ".")
	build.Dir = filepath.Join(repoRoot, exampleModuleDir)
	build.Env = append(os.Environ(), "GOMAXPROCS=2", "CGO_ENABLED=0")
	var buildOutput bytes.Buffer
	build.Stdout, build.Stderr = &buildOutput, &buildOutput
	if err := build.Run(); err != nil {
		return fail("example.build", fmt.Errorf("构建示例失败: %v: %s", err,
			strings.TrimSpace(buildOutput.String())))
	}
	report.Checks = append(report.Checks, check{ID: "example.build", Status: "PASS",
		Detail: "外部 Module 构建成功"})
	runCtx, runCancel := context.WithTimeout(ctx, minDuration(opts.timeout, 90*time.Second))
	defer runCancel()
	run := exec.CommandContext(runCtx, binary, "-self-test", "-json")
	var stdout, stderr bytes.Buffer
	run.Stdout, run.Stderr = &stdout, &stderr
	if err := run.Run(); err != nil {
		return fail("example.run", fmt.Errorf("示例自检失败: %v: %s", err,
			strings.TrimSpace(stderr.String())))
	}
	var example exampleResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout.String())), &example); err != nil {
		return fail("example.result_json", fmt.Errorf("示例输出不是合法 JSON: %v", err))
	}
	if example.Schema != exampleSchema || example.Status != "PASS" {
		return fail("example.result_schema", fmt.Errorf("schema/status=%q/%q 错误=%q",
			example.Schema, example.Status, example.Error))
	}
	if len(example.Checks) < minExampleChecks {
		return fail("example.result_schema", fmt.Errorf("只输出 %d 项检查（期望≥%d）",
			len(example.Checks), minExampleChecks))
	}
	for _, item := range example.Checks {
		if item.Status != "PASS" {
			return fail("example.check", fmt.Errorf("检查 %s=%s %s", item.ID, item.Status,
				item.Detail))
		}
	}
	report.Checks = append(report.Checks, check{ID: "example.result_schema", Status: "PASS",
		Detail: fmt.Sprintf("checks=%d", len(example.Checks))})
	if example.DataDir == "" || !example.DataDirRemoved || pathExists(example.DataDir) {
		return fail("cleanup.example_data_dir", fmt.Errorf(
			"临时数据目录未清理: %q", example.DataDir))
	}
	report.Checks = append(report.Checks, check{ID: "cleanup.example_data_dir",
		Status: "PASS", Detail: "临时 SQLite 数据目录已删除"})
	if err := os.Remove(binary); err != nil && !os.IsNotExist(err) {
		return fail("cleanup.artifact", err)
	}
	if pathExists(binary) {
		return fail("cleanup.artifact", errors.New("构建产物仍在"))
	}
	report.Checks = append(report.Checks, check{ID: "cleanup.artifact", Status: "PASS",
		Detail: "构建产物已删除"})
	report.Status = "PASS"
	return finish(report, startedAt, opts, 0)
}

func main() {
	os.Exit(runScenario())
}

func finish(report scenarioResult, startedAt time.Time, opts options, code int) int {
	report.DurationMS = time.Since(startedAt).Milliseconds()
	payload, _ := json.Marshal(report)
	fmt.Println(string(payload))
	if opts.resultPath != "" {
		_ = os.WriteFile(opts.resultPath, append(payload, '\n'), 0o600)
	}
	return code
}

func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		content, readErr := os.ReadFile(filepath.Join(dir, "go.mod"))
		if readErr == nil && strings.Contains(string(content),
			"module github.com/kagurazakayashi/EvernightLogin") {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("未找到仓库根")
		}
		dir = parent
	}
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
