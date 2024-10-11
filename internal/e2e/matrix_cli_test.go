package e2e

// 步骤 274 矩阵五：直接管理 CLI（258 改名 / 259 重置口令）真实二进制。
//
// 用当前源码构建自包含 `loginctl` 二进制，对真实嵌入式 HTTP 管理 API 执行：
//   - 258 `admin rename-user`：一次两步验证后提交改名；输出脱敏、不泄露管理密码/TOTP；
//   - 259 `admin reset-password`：新口令来自受保护文件，一次两步验证后提交，must_change；
//   - D-274-1 回归：省略 --expected-row-version 时自动读取扁平 data.row_version 成功改名；\n//   - 负向：缺少 --confirm 的用法错误；无权限普通用户会话被服务端拒绝（稳定错误码/退出码）；
//   - 会话文件/新口令文件均按平台要求收紧权限（secrets.ProtectFile），不进入命令行参数。

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	loginapp "github.com/kagurazakayashi/EvernightLogin/app"
)

// cliEnvelope 解析 CLI --json 输出外壳（成功为 ok/data；失败为 error.code 嵌套）。
func cliEnvelope(t *testing.T, stdout string) map[string]any {
	t.Helper()
	trimmed := strings.TrimSpace(stdout)
	if trimmed == "" {
		t.Fatalf("CLI --json 输出为空")
	}
	var envelope map[string]any
	if err := json.Unmarshal([]byte(trimmed), &envelope); err != nil {
		t.Fatalf("CLI --json 输出不是 JSON: %v，输出=%s", err, truncate(trimmed))
	}
	return envelope
}

// TestMatrixCLIDirectManagement 覆盖真实 CLI 的成功与拒绝路径。
func TestMatrixCLIDirectManagement(t *testing.T) {
	env := openEnvHTTP(t)
	server := startHTTP(t, env.Runtime)
	operatorSession, operatorTOTP := httpDirectOperator(t, env)
	binary := buildLoginctl(t)
	sessionFile := writeProtectedSecret(t, env.Dir, "cli-session.secret",
		string(operatorSession))
	base := []string{"--server", server.URL, "--session-file", sessionFile, "--json"}

	// 1) 258 CLI 改名：stdin 提供管理密码与 TOTP；结果脱敏。
	renameTarget := createUser(t, env.Runtime, "cli-rename-target", targetPassword)
	env.Clock.Advance(30 * time.Second)
	renameArgs := append([]string{"admin", "rename-user", renameTarget.ID,
		"--new-username", "cli-renamed", "--reason", "步骤274 CLI 矩阵",
		"--expected-row-version", strconv.FormatInt(
			userRowVersion(t, env.DBPath, renameTarget.ID), 10),
		"--confirm", "RENAME-USER"}, base...)
	renameResult := runCLI(t, binary, renameArgs,
		operatorPassword+"\n"+totpCode(t, env.Clock, operatorTOTP)+"\n")
	if renameResult.Exit != 0 {
		t.Fatalf("CLI 改名退出码 = %d，stdout=%s stderr=%s", renameResult.Exit,
			truncate(renameResult.Stdout), truncate(renameResult.Stderr))
	}
	renameEnvelope := cliEnvelope(t, renameResult.Stdout)
	if ok, _ := renameEnvelope["ok"].(bool); !ok {
		t.Fatalf("CLI 改名输出 ok=false: %s", truncate(renameResult.Stdout))
	}
	if strings.Contains(renameResult.Stdout, operatorPassword) ||
		strings.Contains(renameResult.Stdout, totpCode(t, env.Clock, operatorTOTP)) {
		t.Fatal("CLI 改名输出泄露管理密码/TOTP")
	}
	renamed, err := env.Runtime.Admin().GetUserByUsername(context.Background(),
		loginapp.AdminUserByUsernameRequest{Caller: env.Runtime.LocalAdmin(),
			Username: "cli-renamed", RequestID: login.NewRequestID()})
	if err != nil || renamed.ID != renameTarget.ID {
		t.Fatalf("CLI 改名后数据库未落到目标 ID: %+v err=%v", renamed, err)
	}

	// 2) 259 CLI 重置口令：新口令只来自受保护文件；提交后 must_change。
	resetTarget := createUser(t, env.Runtime, "cli-reset-target", targetPassword)
	resetPasswordFile := writeProtectedSecret(t, env.Dir, "cli-new-password.secret",
		directPasswordB)
	env.Clock.Advance(30 * time.Second)
	resetArgs := append([]string{"admin", "reset-password", resetTarget.ID,
		"--reason", "步骤274 CLI 矩阵", "--confirm", "RESET-PASSWORD",
		"--new-password-file", resetPasswordFile}, base...)
	resetResult := runCLI(t, binary, resetArgs,
		operatorPassword+"\n"+totpCode(t, env.Clock, operatorTOTP)+"\n")
	if resetResult.Exit != 0 {
		t.Fatalf("CLI 重置退出码 = %d，stdout=%s stderr=%s", resetResult.Exit,
			truncate(resetResult.Stdout), truncate(resetResult.Stderr))
	}
	resetEnvelope := cliEnvelope(t, resetResult.Stdout)
	if ok, _ := resetEnvelope["ok"].(bool); !ok {
		t.Fatalf("CLI 重置输出 ok=false: %s", truncate(resetResult.Stdout))
	}
	if strings.Contains(resetResult.Stdout, directPasswordB) ||
		strings.Contains(resetResult.Stdout, operatorPassword) {
		t.Fatal("CLI 重置输出泄露新口令/管理密码")
	}
	restricted, loginErr := env.Runtime.Auth().Login(context.Background(),
		loginapp.LoginRequest{Username: "cli-reset-target", Password: directPasswordB,
			ClientIP: "127.0.0.1", RequestID: login.NewRequestID()})
	if loginErr != nil || !restricted.Restricted {
		t.Fatalf("CLI 重置后新口令登录应为受限改密: err=%v result=%+v",
			loginErr, restricted)
	}

	// 3) 负向：缺少 --confirm（用法错误，退出码 2，不发请求）。
	missingConfirm := append([]string{"admin", "rename-user", renameTarget.ID,
		"--new-username", "cli-no-confirm", "--reason", "缺少确认"}, base...)
	usageResult := runCLI(t, binary, missingConfirm, "")
	if usageResult.Exit != 2 {
		t.Fatalf("CLI 缺少 --confirm 退出码 = %d，期望 2，stderr=%s", usageResult.Exit,
			truncate(usageResult.Stderr))
	}

	// 4) 负向：无权限普通用户会话被服务端拒绝（稳定错误码 + 非零退出码）。
	createUser(t, env.Runtime, "cli-ordinary", targetPassword)
	ordinarySession := loginFull(t, env.Runtime, "cli-ordinary", targetPassword).SessionSecret
	ordinaryFile := writeProtectedSecret(t, env.Dir, "cli-ordinary-session.secret",
		string(ordinarySession))
	deniedArgs := []string{"admin", "rename-user", renameTarget.ID,
		"--new-username", "cli-denied", "--reason", "无权限",
		"--confirm", "RENAME-USER", "--server", server.URL,
		"--session-file", ordinaryFile, "--json"}
	env.Clock.Advance(30 * time.Second)
	deniedResult := runCLI(t, binary, deniedArgs,
		operatorPassword+"\n"+totpCode(t, env.Clock, operatorTOTP)+"\n")
	if deniedResult.Exit == 0 {
		t.Fatalf("无权限 CLI 改名不应成功: %s", truncate(deniedResult.Stdout))
	}
	deniedEnvelope := cliEnvelope(t, deniedResult.Stdout)
	if ok, _ := deniedEnvelope["ok"].(bool); ok {
		t.Fatalf("无权限 CLI 输出 ok=true: %s", truncate(deniedResult.Stdout))
	}
	if cliFailureCode(deniedEnvelope) == "" {
		t.Fatalf("无权限 CLI 输出缺少稳定错误码: %s", truncate(deniedResult.Stdout))
	}
	// 确认拒绝未产生改名。
	if _, err := env.Runtime.Admin().GetUserByUsername(context.Background(),
		loginapp.AdminUserByUsernameRequest{Caller: env.Runtime.LocalAdmin(),
			Username: "cli-denied", RequestID: login.NewRequestID()}); !loginapp.IsNotFound(err) {
		t.Fatalf("无权限 CLI 改名产生了结果: %v", err)
	}
}

// cliFailureCode 读取 CLI 失败外壳中的稳定错误码（兼容 error.code 与平铺 code）。
func cliFailureCode(envelope map[string]any) string {
	if nested, ok := envelope["error"].(map[string]any); ok {
		if code, _ := nested["code"].(string); code != "" {
			return code
		}
	}
	code, _ := envelope["code"].(string)
	return code
}

// TestMatrixCLIRenameAutoRowVersion 覆盖 258 CLI 省略 `--expected-row-version` 的
// 自动版本读取路径（D-274-1 回归）。
//
// 历史：C2 之前 `loginctl admin rename-user` 读取 `data.user.row_version`，但真实
// 管理 API 的 GET 用户路由返回扁平对象（`data.id/username/row_version`），导致
// ROW_VERSION_MISSING 失败。C2 修复后 CLI 读取扁平 `data.row_version`，本用例断言
// 省略版本参数时可成功改名（显式版本路径由上方 TestMatrixCLIDirectManagement 覆盖）。
func TestMatrixCLIRenameAutoRowVersion(t *testing.T) {
	env := openEnvHTTP(t)
	server := startHTTP(t, env.Runtime)
	operatorSession, operatorTOTP := httpDirectOperator(t, env)
	binary := buildLoginctl(t)
	sessionFile := writeProtectedSecret(t, env.Dir, "cli-auto-version-session.secret",
		string(operatorSession))
	target := createUser(t, env.Runtime, "cli-auto-version-target", targetPassword)
	env.Clock.Advance(30 * time.Second)
	result := runCLI(t, binary, []string{"admin", "rename-user", target.ID,
		"--new-username", "cli-auto-version-renamed", "--reason", "D-274-1 自动版本读取回归",
		"--confirm", "RENAME-USER", "--server", server.URL,
		"--session-file", sessionFile, "--json"},
		operatorPassword+"\n"+totpCode(t, env.Clock, operatorTOTP)+"\n")
	if result.Exit != 0 {
		t.Fatalf("CLI 自动版本改名退出码 = %d，stdout=%s stderr=%s", result.Exit,
			truncate(result.Stdout), truncate(result.Stderr))
	}
	envelope := cliEnvelope(t, result.Stdout)
	if ok, _ := envelope["ok"].(bool); !ok {
		t.Fatalf("CLI 自动版本改名输出 ok=false: %s", truncate(result.Stdout))
	}
	if strings.Contains(result.Stdout, operatorPassword) ||
		strings.Contains(result.Stdout, totpCode(t, env.Clock, operatorTOTP)) {
		t.Fatal("CLI 输出泄露管理密码或 TOTP")
	}
	renamed, err := env.Runtime.Admin().GetUserByUsername(context.Background(),
		loginapp.AdminUserByUsernameRequest{Caller: env.Runtime.LocalAdmin(),
			Username: "cli-auto-version-renamed", RequestID: login.NewRequestID()})
	if err != nil || renamed.ID != target.ID {
		t.Fatalf("自动版本改名后数据库未落到目标 ID: %+v err=%v", renamed, err)
	}
	if _, err := env.Runtime.Admin().GetUserByUsername(context.Background(),
		loginapp.AdminUserByUsernameRequest{Caller: env.Runtime.LocalAdmin(),
			Username: "cli-auto-version-target", RequestID: login.NewRequestID()}); !loginapp.IsNotFound(err) {
		t.Fatalf("旧用户名应不再存在: %v", err)
	}
}
