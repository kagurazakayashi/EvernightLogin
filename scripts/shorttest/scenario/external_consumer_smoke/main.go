// 无人值守短测试场景：external-consumer 示例（examples/external-consumer）。
// 只使用标准库：构建外部 Module 并运行，核对示例成功输出与构建产物清理。
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
	scenarioID       = "external-consumer-smoke"
	exampleModuleDir = "examples/external-consumer"
	scenarioSchema   = "evernight.shorttest.scenario-result/v1"
)

type check struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type scenarioResult struct {
	Schema     string  `json:"schema"`
	Scenario   string  `json:"scenario"`
	Status     string  `json:"status"`
	Checks     []check `json:"checks"`
	DurationMS int64   `json:"duration_ms"`
	Error      string  `json:"error,omitempty"`
}

func runScenario() int {
	var workDir, resultPath, timeoutRaw string
	flag.StringVar(&workDir, "workdir", "", "入口临时目录")
	flag.StringVar(&resultPath, "result", "", "结果 JSON 输出路径")
	flag.StringVar(&timeoutRaw, "timeout", "60", "总超时（秒）")
	flag.Parse()
	seconds, err := strconv.Atoi(strings.TrimSpace(timeoutRaw))
	if err != nil || seconds <= 0 {
		seconds = 60
	}
	startedAt := time.Now()
	report := scenarioResult{Schema: scenarioSchema, Scenario: scenarioID,
		Status: "PASS", Checks: []check{}}
	fail := func(id string, cause error) int {
		report.Status = "FAIL"
		report.Checks = append(report.Checks, check{ID: id, Status: "FAIL",
			Detail: cause.Error()})
		report.Error = cause.Error()
		return finish(report, startedAt, resultPath, 1)
	}
	if workDir == "" {
		return fail("arguments", errors.New("-workdir 必填"))
	}
	repoRoot, err := findRepoRoot()
	if err != nil {
		return fail("repo_root", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(seconds)*time.Second)
	defer cancel()
	binary := filepath.Join(workDir, "external-consumer.exe")
	buildCtx, buildCancel := context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
	defer buildCancel()
	build := exec.CommandContext(buildCtx, "go", "build", "-o", binary, ".")
	build.Dir = filepath.Join(repoRoot, exampleModuleDir)
	build.Env = append(os.Environ(), "GOMAXPROCS=2", "CGO_ENABLED=0")
	var buildOut bytes.Buffer
	build.Stdout, build.Stderr = &buildOut, &buildOut
	if err := build.Run(); err != nil {
		return fail("example.build", fmt.Errorf("构建失败: %v: %s", err,
			strings.TrimSpace(buildOut.String())))
	}
	report.Checks = append(report.Checks, check{ID: "example.build", Status: "PASS",
		Detail: "外部 Module 构建成功"})
	runCtx, runCancel := context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
	defer runCancel()
	run := exec.CommandContext(runCtx, binary)
	run.Dir = filepath.Join(repoRoot, exampleModuleDir)
	var stdout, stderr bytes.Buffer
	run.Stdout, run.Stderr = &stdout, &stderr
	if err := run.Run(); err != nil {
		return fail("example.run", fmt.Errorf("示例运行失败: %v: %s", err,
			strings.TrimSpace(stderr.String())))
	}
	output := stdout.String()
	if !strings.Contains(output, "external-consumer 示例通过") {
		return fail("example.output", fmt.Errorf("成功输出缺少标识: %s",
			strings.TrimSpace(output)))
	}
	report.Checks = append(report.Checks, check{ID: "example.output", Status: "PASS",
		Detail: "示例成功输出包含公开 API 完成标识"})
	if err := os.Remove(binary); err != nil && !os.IsNotExist(err) {
		return fail("cleanup.artifact", err)
	}
	if _, err := os.Stat(binary); err == nil {
		return fail("cleanup.artifact", errors.New("构建产物仍在"))
	}
	report.Checks = append(report.Checks, check{ID: "cleanup.artifact", Status: "PASS",
		Detail: "构建产物已删除"})
	return finish(report, startedAt, resultPath, 0)
}

func main() {
	os.Exit(runScenario())
}

func finish(report scenarioResult, startedAt time.Time, resultPath string, code int) int {
	report.DurationMS = time.Since(startedAt).Milliseconds()
	payload, _ := json.Marshal(report)
	fmt.Println(string(payload))
	if resultPath != "" {
		_ = os.WriteFile(resultPath, append(payload, '\n'), 0o600)
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
