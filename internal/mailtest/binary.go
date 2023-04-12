// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightMail is licensed under Mulan PSL v2.

package mailtest

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

var (
	buildMu      sync.Mutex
	buildOnce    sync.Once
	builtBinary  string
	buildError   error
	buildRoot    string
	buildCleanup bool
)

// resolveBinary 按显式路径 → EVERNIGHTMAIL_BIN → 从子模块构建 的顺序定位二进制。
func resolveBinary(t testing.TB, opts Options) (string, error) {
	t.Helper()
	if path := strings.TrimSpace(opts.BinPath); path != "" {
		return ensureBinary(path)
	}
	if path := strings.TrimSpace(os.Getenv("EVERNIGHTMAIL_BIN")); path != "" {
		return ensureBinary(path)
	}
	buildOnce.Do(func() {
		builtBinary, buildError = buildSubmoduleBinary(t)
	})
	if buildError != nil {
		return "", buildError
	}
	return builtBinary, nil
}

// ensureBinary 校验二进制存在且是普通文件。
func ensureBinary(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return "", fmt.Errorf("evernightmail 二进制不可用（%s）: %w", absolute, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("evernightmail 二进制不是普通文件（%s）", absolute)
	}
	return absolute, nil
}

// buildSubmoduleBinary 从父项目内的 EvernightMail 子模块构建测试用二进制。
func buildSubmoduleBinary(t testing.TB) (string, error) {
	root, err := repositoryRoot()
	if err != nil {
		return "", err
	}
	mailDir := filepath.Join(root, "EvernightMail")
	if info, statErr := os.Stat(filepath.Join(mailDir, "cmd", "evernightmail")); statErr != nil || !info.IsDir() {
		return "", fmt.Errorf("EvernightMail 子模块源码不可用（%s）；请 git submodule update --init EvernightMail 或设置 EVERNIGHTMAIL_BIN", mailDir)
	}
	dir, err := os.MkdirTemp(os.Getenv("GOTMPDIR"), "mailtest-bin-")
	if err != nil {
		return "", err
	}
	buildRoot = dir
	buildCleanup = true
	binaryName := "evernightmail"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	output := filepath.Join(dir, binaryName)
	parallel := runtime.NumCPU() / 2
	if parallel < 1 {
		parallel = 1
	}
	command := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", output, "./cmd/evernightmail")
	command.Dir = mailDir
	env := os.Environ()
	env = appendFilteredEnv(env, "CGO_ENABLED", "0")
	env = appendFilteredEnv(env, "GOMAXPROCS", fmt.Sprint(parallel))
	env = appendFilteredEnv(env, "GOFLAGS", "-mod=readonly")
	command.Env = env
	var outputBuffer bytes.Buffer
	command.Stdout = &outputBuffer
	command.Stderr = &outputBuffer
	if err := command.Run(); err != nil {
		_ = os.RemoveAll(dir)
		buildRoot = ""
		return "", fmt.Errorf("从 EvernightMail 子模块构建测试二进制失败: %w（输出: %s）", err, truncateText(strings.TrimSpace(outputBuffer.String()), 800))
	}
	return output, nil
}

// appendFilteredEnv 覆盖指定环境变量（保留其他变量），避免 GOFLAGS 等重复。
func appendFilteredEnv(env []string, name, value string) []string {
	prefix := name + "="
	filtered := make([]string, 0, len(env)+1)
	for _, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return append(filtered, prefix+value)
}

// repositoryRoot 返回父项目根目录（internal/mailtest 的上三级）。
func repositoryRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("无法定位 mailtest 源码路径")
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(file)))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return "", fmt.Errorf("无法从 %s 定位父项目根目录: %w", file, err)
	}
	return root, nil
}

// CleanupBuiltBinary 删除本进程缓存的自动构建二进制；测试包可在 TestMain 结束时调用。
func CleanupBuiltBinary() {
	buildMu.Lock()
	defer buildMu.Unlock()
	if !buildCleanup || buildRoot == "" {
		return
	}
	_ = os.RemoveAll(buildRoot)
	buildRoot = ""
	buildCleanup = false
	builtBinary = ""
}
