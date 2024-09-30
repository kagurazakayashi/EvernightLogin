package e2e

// 步骤 274 矩阵一：直接修改他人用户名 / 直接重置他人密码的授权与证明边界。
//
// 覆盖（公开 Go 门面 + 真实临时 SQLite）：
//   - 操作者矩阵：持有两项权限的系统管理员、仅持单项权限、无权限普通用户；
//   - 目标矩阵：本人/root 目标拒绝；普通他人/高权限非 root 目标按当前产品语义允许；
//   - 证明矩阵：空令牌、换目标、换新值、过期、重放均拒绝且不产生变更；
//   - 两项直接管理权限互不替代（发起证明与执行都被拒绝）；
//   - 权限行停用后拒绝；
//   - 有限并发：同一目标两份不同意图证明只允许一个赢家；
//   - 更名后稳定 ID 与全局唯一用户名保持。

import (
	"context"
	"sync"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	loginapp "github.com/kagurazakayashi/EvernightLogin/app"
)

// directOperatorFixture 准备“持有两项直接管理权限且已绑定 TOTP 的系统管理员”。
func directOperatorFixture(t *testing.T) (env *harnessEnv, operatorID string,
	operatorSession []byte, operatorTOTP string) {
	t.Helper()
	env = openEnv(t)
	operator, secret := enrollTOTP(t, env.Runtime, env.Clock, "matrix-operator", operatorPassword)
	grantSystemPermissions(t, env.Runtime, operator.ID, "matrix-both-role",
		"users.username.change.other", "users.password.reset.other")
	session := loginWithTOTP(t, env.Runtime, env.Clock, "matrix-operator",
		operatorPassword, secret)
	return env, operator.ID, session, secret
}

// TestMatrixDirectManagementActorsTargetsProofs 覆盖操作者/目标/证明主矩阵。
func TestMatrixDirectManagementActorsTargetsProofs(t *testing.T) {
	ctx := context.Background()
	env, operatorID, operatorSession, operatorTOTP := directOperatorFixture(t)
	runtime, clock := env.Runtime, env.Clock
	root := ensureRoot(t, runtime)
	ordinary := createUser(t, runtime, "matrix-ordinary", targetPassword)
	ordinarySession := loginFull(t, runtime, "matrix-ordinary", targetPassword).SessionSecret
	highPriv := createUser(t, runtime, "matrix-highpriv", targetPassword)
	grantSystemPermissions(t, runtime, highPriv.ID, "matrix-highpriv-role",
		"users.read", "users.update")
	if !checkPermission(t, runtime, highPriv.ID, "users.read") {
		t.Fatal("高权限目标用户未获得 users.read（夹具失败）")
	}
	caller := runtime.AdminSession(operatorSession)

	// 1) 两项权限齐备：普通他人改名与重置都成功；ID 稳定、旧名不可解析。
	t.Run("both permissions on ordinary target", func(t *testing.T) {
		token := beginUsernameProof(t, runtime, clock, operatorSession, operatorTOTP,
			ordinary.ID, "matrix-ordinary-renamed")
		profile, err := changeUsername(t, runtime, env.DBPath, caller, ordinary.ID,
			"matrix-ordinary-renamed", "步骤274矩阵：改名", token)
		if err != nil {
			t.Fatalf("直接改名失败: %v", err)
		}
		if profile.UserID != ordinary.ID || profile.Username != "matrix-ordinary-renamed" {
			t.Fatalf("改名后 ID/用户名不稳定: %+v", profile)
		}
		if _, err := runtime.Admin().GetUserByUsername(ctx,
			loginapp.AdminUserByUsernameRequest{Caller: runtime.LocalAdmin(),
				Username: "matrix-ordinary", RequestID: login.NewRequestID()}); !loginapp.IsNotFound(err) {
			t.Fatalf("旧用户名仍可解析: %v", err)
		}
		resolved, err := runtime.Admin().GetUserByUsername(ctx,
			loginapp.AdminUserByUsernameRequest{Caller: runtime.LocalAdmin(),
				Username: "matrix-ordinary-renamed", RequestID: login.NewRequestID()})
		if err != nil || resolved.ID != ordinary.ID {
			t.Fatalf("新用户名未解析到同一稳定 ID: %+v err=%v", resolved, err)
		}
		resetToken := beginPasswordProof(t, runtime, clock, operatorSession, operatorTOTP,
			ordinary.ID, directPasswordA)
		result, err := runtime.DirectPasswordManagement().ResetUserPassword(ctx,
			loginapp.AdminResetUserPasswordRequest{Caller: caller, TargetUserID: ordinary.ID,
				NewPassword: directPasswordA, Reason: "步骤274矩阵：重置口令",
				ProofToken: resetToken, RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("直接重置口令失败: %v", err)
		}
		if !result.MustChange || result.SecurityVersion <= 1 {
			t.Fatalf("重置结果缺少 must_change/安全版本递增: %+v", result)
		}
	})

	// 2) 权限独立性：单项权限不能执行另一操作。
	t.Run("permissions are independent", func(t *testing.T) {
		renameOnly, renameSecret := enrollTOTP(t, runtime, clock,
			"matrix-rename-only", operatorPassword)
		grantSystemPermissions(t, runtime, renameOnly.ID, "matrix-rename-only-role",
			"users.username.change.other")
		resetOnly, resetSecret := enrollTOTP(t, runtime, clock,
			"matrix-reset-only", operatorPassword)
		grantSystemPermissions(t, runtime, resetOnly.ID, "matrix-reset-only-role",
			"users.password.reset.other")
		renameSession := loginWithTOTP(t, runtime, clock, "matrix-rename-only",
			operatorPassword, renameSecret)
		resetSession := loginWithTOTP(t, runtime, clock, "matrix-reset-only",
			operatorPassword, resetSecret)
		if _, err := runtime.OperationProof().Begin(ctx, loginapp.OperationProofBeginRequest{
			Caller: runtime.AdminSession(renameSession), TargetUserID: ordinary.ID,
			Operation: loginapp.OperationProofPasswordReset, NewPassword: directPasswordB,
			RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeAccessDenied) {
			t.Fatalf("仅改名权限发起改密证明 = %v，期望 ACCESS_DENIED", err)
		}
		if _, err := runtime.OperationProof().Begin(ctx, loginapp.OperationProofBeginRequest{
			Caller: runtime.AdminSession(resetSession), TargetUserID: ordinary.ID,
			Operation: loginapp.OperationProofUsernameChange, NewUsername: "matrix-denied",
			RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeAccessDenied) {
			t.Fatalf("仅重置权限发起改名证明 = %v，期望 ACCESS_DENIED", err)
		}
		renameToken := beginUsernameProof(t, runtime, clock, renameSession,
			renameSecret, ordinary.ID, "matrix-cross-capability")
		if _, err := runtime.DirectPasswordManagement().ResetUserPassword(ctx,
			loginapp.AdminResetUserPasswordRequest{
				Caller: runtime.AdminSession(renameSession), TargetUserID: ordinary.ID,
				NewPassword: directPasswordB, Reason: "越权尝试", ProofToken: renameToken,
				RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
			login.CodeAccessDenied) {
			t.Fatalf("改名权限直接重置口令 = %v，期望 ACCESS_DENIED", err)
		}
	})

	// 3) 无权限普通用户：两种操作都拒绝。
	t.Run("ordinary user denied", func(t *testing.T) {
		if _, err := changeUsername(t, runtime, env.DBPath,
			runtime.AdminSession(ordinarySession), highPriv.ID, "matrix-denied-rename",
			"无权限", "x"); !login.IsErrorCode(err, login.CodeAccessDenied) {
			t.Fatalf("普通用户改名 = %v，期望 ACCESS_DENIED", err)
		}
		if _, err := runtime.DirectPasswordManagement().ResetUserPassword(ctx,
			loginapp.AdminResetUserPasswordRequest{
				Caller: runtime.AdminSession(ordinarySession), TargetUserID: highPriv.ID,
				NewPassword: directPasswordB, Reason: "无权限", ProofToken: "x",
				RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
			login.CodeAccessDenied) {
			t.Fatalf("普通用户重置口令 = %v，期望 ACCESS_DENIED", err)
		}
	})

	// 4) 目标保护：本人/root 拒绝；高权限非 root 目标按 257 INFO-1 语义允许。
	t.Run("target protection", func(t *testing.T) {
		if _, err := runtime.OperationProof().Begin(ctx, loginapp.OperationProofBeginRequest{
			Caller: caller, TargetUserID: operatorID,
			Operation: loginapp.OperationProofUsernameChange, NewUsername: "matrix-self",
			RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
			login.CodeReqInvalid) {
			t.Fatalf("本人目标发起证明 = %v，期望 REQ_INVALID", err)
		}
		if _, err := changeUsername(t, runtime, env.DBPath, caller, root.UserID,
			"matrix-root-rename", "root 目标", "x"); !login.IsErrorCode(err,
			login.CodeAccessDenied) {
			t.Fatalf("root 目标改名 = %v，期望 ACCESS_DENIED", err)
		}
		if _, err := runtime.DirectPasswordManagement().ResetUserPassword(ctx,
			loginapp.AdminResetUserPasswordRequest{Caller: caller, TargetUserID: root.UserID,
				NewPassword: directPasswordB, Reason: "root 目标", ProofToken: "x",
				RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
			login.CodeAccessDenied) {
			t.Fatalf("root 目标重置口令 = %v，期望 ACCESS_DENIED", err)
		}
		token := beginUsernameProof(t, runtime, clock, operatorSession, operatorTOTP,
			highPriv.ID, "matrix-highpriv-renamed")
		profile, err := changeUsername(t, runtime, env.DBPath, caller, highPriv.ID,
			"matrix-highpriv-renamed", "高权限目标", token)
		if err != nil {
			t.Fatalf("高权限非 root 目标改名（当前产品语义应允许）: %v", err)
		}
		if profile.UserID != highPriv.ID {
			t.Fatalf("高权限目标改名后 ID 改变: %+v", profile)
		}
		if !checkPermission(t, runtime, highPriv.ID, "users.read") {
			t.Fatal("改名后高权限目标的角色/权限丢失")
		}
	})

	// 5) 证明绑定与新鲜度。
	t.Run("proof binding and freshness", func(t *testing.T) {
		proofTarget := createUser(t, runtime, "matrix-proof-target", targetPassword)
		otherTarget := createUser(t, runtime, "matrix-other-target", targetPassword)
		if _, err := changeUsername(t, runtime, env.DBPath, caller, proofTarget.ID,
			"matrix-empty-proof", "无证明", ""); !login.IsErrorCode(err,
			login.CodeTokenInvalid) {
			t.Fatalf("空证明改名 = %v，期望 TOKEN_INVALID", err)
		}
		crossTargetToken := beginUsernameProof(t, runtime, clock, operatorSession,
			operatorTOTP, proofTarget.ID, "matrix-bound-name")
		if _, err := changeUsername(t, runtime, env.DBPath, caller, otherTarget.ID,
			"matrix-bound-name", "换目标", crossTargetToken); !login.IsErrorCode(err,
			login.CodeTokenInvalid) {
			t.Fatalf("证明换目标 = %v，期望 TOKEN_INVALID", err)
		}
		if _, err := changeUsername(t, runtime, env.DBPath, caller, proofTarget.ID,
			"matrix-different-name", "换新值", crossTargetToken); !login.IsErrorCode(err,
			login.CodeTokenInvalid) {
			t.Fatalf("证明换新值 = %v，期望 TOKEN_INVALID", err)
		}
		if _, err := changeUsername(t, runtime, env.DBPath, caller, proofTarget.ID,
			"matrix-bound-name", "正确绑定", crossTargetToken); err != nil {
			t.Fatalf("正确绑定重试失败: %v", err)
		}
		// 重放同一意图：同名校验可能先于证明拒绝（REQ_INVALID）或证明已消费
		//（TOKEN_INVALID）；两者都不得产生第二次变更。
		if _, err := changeUsername(t, runtime, env.DBPath, caller, proofTarget.ID,
			"matrix-bound-name", "重放", crossTargetToken); err == nil {
			t.Fatal("证明重放不应成功")
		} else if !login.IsErrorCode(err, login.CodeTokenInvalid) &&
			!login.IsErrorCode(err, login.CodeReqInvalid) {
			t.Fatalf("证明重放 = %v，期望 TOKEN_INVALID/REQ_INVALID", err)
		}
		expiredTarget := createUser(t, runtime, "matrix-expired-target", targetPassword)
		expiredToken := beginUsernameProof(t, runtime, clock, operatorSession,
			operatorTOTP, expiredTarget.ID, "matrix-expired-name")
		// 推进超过证明批准有效期（默认 5 分钟，硬上限 10 分钟），但小于会话空闲期。
		clock.Advance(11 * time.Minute)
		if _, err := changeUsername(t, runtime, env.DBPath, caller, expiredTarget.ID,
			"matrix-expired-name", "过期证明", expiredToken); !login.IsErrorCode(err,
			login.CodeTokenInvalid) {
			t.Fatalf("过期证明 = %v，期望 TOKEN_INVALID", err)
		}
		if _, err := runtime.Admin().GetUserByUsername(ctx,
			loginapp.AdminUserByUsernameRequest{Caller: runtime.LocalAdmin(),
				Username: "matrix-expired-name", RequestID: login.NewRequestID()}); !loginapp.IsNotFound(err) {
			t.Fatalf("过期证明执行了改名: %v", err)
		}
	})

	// 6) 权限撤销：停用权限行后拒绝（准备前撤销；事务内窗口见 255 F1 定向测试）。
	t.Run("permission revocation", func(t *testing.T) {
		revokeTarget := createUser(t, runtime, "matrix-revoke-target", targetPassword)
		permission := findOrCreateSystemPermission(t, runtime,
			"users.username.change.other")
		executeSQL(t, env.DBPath,
			`UPDATE permissions SET enabled=0 WHERE id='`+permission.ID+`'`)
		if checkPermission(t, runtime, operatorID, "users.username.change.other") {
			t.Fatal("权限停用后 CheckPermission 仍允许")
		}
		if _, err := changeUsername(t, runtime, env.DBPath, caller, revokeTarget.ID,
			"matrix-revoked", "权限撤销", "x"); !login.IsErrorCode(err,
			login.CodeAccessDenied) {
			t.Fatalf("权限撤销后改名 = %v，期望 ACCESS_DENIED", err)
		}
		executeSQL(t, env.DBPath,
			`UPDATE permissions SET enabled=1 WHERE id='`+permission.ID+`'`)
	})

	// 7) 有限并发：同一目标两份不同新名证明并发，只允许一个赢家。
	t.Run("limited concurrency single winner", func(t *testing.T) {
		concurrentTarget := createUser(t, runtime, "matrix-concurrent-target", targetPassword)
		tokenA := beginUsernameProof(t, runtime, clock, operatorSession, operatorTOTP,
			concurrentTarget.ID, "matrix-concurrent-a")
		tokenB := beginUsernameProof(t, runtime, clock, operatorSession, operatorTOTP,
			concurrentTarget.ID, "matrix-concurrent-b")
		version := userRowVersion(t, env.DBPath, concurrentTarget.ID)
		type outcome struct {
			name string
			err  error
		}
		results := make(chan outcome, 2)
		start := make(chan struct{})
		var group sync.WaitGroup
		for _, item := range []struct{ name, token string }{
			{"matrix-concurrent-a", tokenA}, {"matrix-concurrent-b", tokenB}} {
			item := item
			group.Add(1)
			go func() {
				defer group.Done()
				<-start
				_, err := runtime.DirectUserManagement().ChangeUserUsername(ctx,
					loginapp.AdminChangeUserUsernameRequest{Caller: caller,
						TargetUserID: concurrentTarget.ID, NewUsername: item.name,
						ExpectedRowVersion: version, Reason: "并发单赢家",
						ProofToken: item.token, RequestID: login.NewRequestID()})
				results <- outcome{name: item.name, err: err}
			}()
		}
		close(start)
		group.Wait()
		close(results)
		successes := 0
		winner := ""
		for item := range results {
			if item.err == nil {
				successes++
				winner = item.name
				continue
			}
			if !login.IsErrorCode(item.err, login.CodeConflict) {
				t.Fatalf("并发失败方错误 = %v，期望 CONFLICT", item.err)
			}
		}
		if successes != 1 || winner == "" {
			t.Fatalf("并发改名结果 = %d 个赢家，期望 1", successes)
		}
		resolved, err := runtime.Admin().GetUserByUsername(ctx,
			loginapp.AdminUserByUsernameRequest{Caller: runtime.LocalAdmin(),
				Username: winner, RequestID: login.NewRequestID()})
		if err != nil || resolved.ID != concurrentTarget.ID {
			t.Fatalf("并发赢家用户名未解析到目标 ID: %+v err=%v", resolved, err)
		}
	})
}
