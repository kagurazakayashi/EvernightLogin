package app_test

// 步骤 207 外部模块视角测试：只导入公开包（根包 login 与公开门面 app）验证
// “已授权但目标不存在”的稳定公开语义。文件刻意不导入任何 internal 包，证明宿主
// 判断未找到时既不需要、也不能依赖 internal/account。

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/app"
)

func TestPublicNotFoundContractFromExternalModule(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cfg := login.Default()
	cfg.Registration.Enabled = true
	runtime, err := app.Open(ctx, app.Options{
		Config: &cfg, DatabasePath: filepath.Join(dir, "login.db"),
		MasterKeyFile: filepath.Join(dir, "master.key"), CreateMasterKey: true,
		Migrate: true, OperatorID: "external-module-test", Now: time.Now,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })

	created, err := runtime.Users().Create(ctx, app.CreateUserRequest{
		Username: "alice", Password: "K8$wR3!nB6@yF1#v", Nickname: "Alice",
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("创建用户失败: %v", err)
	}

	const requestID = "req_external_not_found"
	admin := runtime.Admin()
	if _, err := admin.GetUserByUsername(ctx, app.AdminUserByUsernameRequest{
		Caller:    runtime.LocalAdmin(),
		Username:  "nobody-external",
		RequestID: requestID,
	}); err == nil {
		t.Fatal("不存在的用户名应返回未找到错误")
	} else {
		if !app.IsNotFound(err) {
			t.Fatalf("外部模块 IsNotFound = false，实际 %T: %v", err, err)
		}
		if !errors.Is(err, app.ErrNotFound) {
			t.Fatalf("外部模块 errors.Is(err, app.ErrNotFound) = false: %v", err)
		}
		notFound, ok := app.AsNotFound(err)
		if !ok {
			t.Fatalf("外部模块 AsNotFound 失败，实际 %T", err)
		}
		if notFound.Code() != app.NotFoundCode || app.NotFoundCode != "NOT_FOUND" {
			t.Fatalf("外部模块未找到码 = %q，期望 %q", notFound.Code(), app.NotFoundCode)
		}
		if notFound.RequestID != requestID {
			t.Fatalf("外部模块未找到请求编号 = %q，期望 %q",
				notFound.RequestID, requestID)
		}
		if notFound.HTTPStatus() != 404 {
			t.Fatalf("外部模块未找到 HTTP 状态 = %d，期望 404", notFound.HTTPStatus())
		}
		// 未找到不能被投影成 REQ_INVALID 参数错误，否则宿主无法区分两者。
		if _, isAppError := login.AsAppError(err); isAppError {
			t.Fatalf("未找到语义不应被投影成 *login.AppError（会与 REQ_INVALID 混淆）: %v", err)
		}
	}

	// 参数非法仍是公开 REQ_INVALID，与未找到可区分。
	if _, err := admin.GetUserByUsername(ctx, app.AdminUserByUsernameRequest{
		Caller: runtime.LocalAdmin(), Username: "   ", RequestID: requestID,
	}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("空用户名应返回 REQ_INVALID，实际 %v", err)
	} else if app.IsNotFound(err) {
		t.Fatalf("参数非法不能被当成未找到: %v", err)
	}

	// 正常存在查询仍成功，证明契约不把一切查询都变成未找到。
	if user, err := admin.GetUserByUsername(ctx, app.AdminUserByUsernameRequest{
		Caller: runtime.LocalAdmin(), Username: "ALICE",
		RequestID: login.NewRequestID(),
	}); err != nil || user.ID != created.ID {
		t.Fatalf("已存在用户查询异常: user=%+v err=%v", user, err)
	}
}
