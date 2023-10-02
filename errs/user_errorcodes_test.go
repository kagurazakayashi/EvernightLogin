package errs

import (
	"errors"
	"fmt"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
)

// TestAccountErrorCodesRegistered 验证账户领域错误映射到已登记错误码，防止
// internal/account 的字面值与根包注册表/手册漂移。
func TestAccountErrorCodesRegistered(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode account.ErrorCode
		wantHTTP int
	}{
		{name: "非法请求", err: fmt.Errorf("%w: bad name", account.ErrInvalidRequest), wantCode: account.CodeReqInvalid, wantHTTP: 400},
		{name: "用户不存在", err: account.ErrUserNotFound, wantCode: account.CodeReqInvalid, wantHTTP: 400},
		{name: "用户名重复", err: account.ErrUsernameTaken, wantCode: account.CodeConflict, wantHTTP: 409},
		{name: "未获准", err: account.ErrAccessDenied, wantCode: account.CodeAccessDenied, wantHTTP: 403},
		{name: "受保护账户", err: account.ErrProtectedUser, wantCode: account.CodeAccessDenied, wantHTTP: 403},
		{name: "非法状态切换", err: account.ErrInvalidTransition, wantCode: account.CodeConflict, wantHTTP: 409},
		{name: "状态并发冲突", err: account.ErrStateConflict, wantCode: account.CodeConflict, wantHTTP: 409},
		{name: "存储不可用", err: account.ErrStoreUnavailable, wantCode: account.CodeDBUnavailable, wantHTTP: 503},
		{name: "审计不可用", err: account.ErrAuditUnavailable, wantCode: account.CodeAuditWriteFailed, wantHTTP: 503},
		{name: "未知错误", err: errors.New("unclassified"), wantCode: account.CodeInternalError, wantHTTP: 500},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := account.CodeOf(test.err)
			if got != test.wantCode {
				t.Fatalf("CodeOf(%v) = %q，期望 %q", test.err, got, test.wantCode)
			}
			definition, ok := LookupErrorCode(ErrorCode(got))
			if !ok {
				t.Fatalf("错误码 %q 未在根包注册表登记", got)
			}
			if definition.HTTPStatus != test.wantHTTP {
				t.Errorf("错误码 %q HTTP 状态 = %d，期望 %d", got, definition.HTTPStatus, test.wantHTTP)
			}
		})
	}

	// 字面值必须与根包常量一致，避免 internal 包私自引入新码。
	if string(account.CodeConflict) != string(CodeConflict) ||
		string(account.CodeReqInvalid) != string(CodeReqInvalid) ||
		string(account.CodeAccessDenied) != string(CodeAccessDenied) ||
		string(account.CodeDBUnavailable) != string(CodeDBUnavailable) ||
		string(account.CodeAuditWriteFailed) != string(CodeAuditWriteFailed) ||
		string(account.CodeInternalError) != string(CodeInternalError) {
		t.Fatal("internal/account 错误码字面值与根包注册表不一致")
	}
}
