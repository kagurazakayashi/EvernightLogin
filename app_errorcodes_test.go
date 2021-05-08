package login

import (
	"errors"
	"fmt"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/app"
)

// TestApplicationErrorCodesRegistered 验证应用领域（含应用成员）错误映射到已登记
// 错误码，且内部字面值与根包注册表一致。
func TestApplicationErrorCodesRegistered(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode app.ErrorCode
		wantHTTP int
	}{
		{name: "非法请求", err: fmt.Errorf("%w: bad", app.ErrInvalidRequest), wantCode: app.CodeReqInvalid, wantHTTP: 400},
		{name: "应用不存在", err: app.ErrApplicationNotFound, wantCode: app.CodeReqInvalid, wantHTTP: 400},
		{name: "成员关系不存在", err: app.ErrMemberNotFound, wantCode: app.CodeReqInvalid, wantHTTP: 400},
		{name: "目标账户不存在", err: app.ErrTargetUserNotFound, wantCode: app.CodeReqInvalid, wantHTTP: 400},
		{name: "状态冲突", err: app.ErrStateConflict, wantCode: app.CodeConflict, wantHTTP: 409},
		{name: "非法状态切换", err: app.ErrInvalidTransition, wantCode: app.CodeConflict, wantHTTP: 409},
		{name: "重复加入成员", err: app.ErrMemberExists, wantCode: app.CodeConflict, wantHTTP: 409},
		{name: "未获准", err: app.ErrAccessDenied, wantCode: app.CodeAccessDenied, wantHTTP: 403},
		{name: "应用已停用", err: app.ErrApplicationInactive, wantCode: app.CodeClientDisabled, wantHTTP: 403},
		{name: "目标账户不可用", err: app.ErrUserNotEligible, wantCode: app.CodeUserDisabled, wantHTTP: 403},
		{name: "存储不可用", err: app.ErrStoreUnavailable, wantCode: app.CodeDBUnavailable, wantHTTP: 503},
		{name: "审计不可用", err: app.ErrAuditUnavailable, wantCode: app.CodeAuditWriteFailed, wantHTTP: 503},
		{name: "未知错误", err: errors.New("unclassified"), wantCode: app.CodeInternalError, wantHTTP: 500},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := app.CodeOf(test.err)
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
	if string(app.CodeReqInvalid) != string(CodeReqInvalid) ||
		string(app.CodeConflict) != string(CodeConflict) ||
		string(app.CodeAccessDenied) != string(CodeAccessDenied) ||
		string(app.CodeClientDisabled) != string(CodeClientDisabled) ||
		string(app.CodeUserDisabled) != string(CodeUserDisabled) ||
		string(app.CodeDBUnavailable) != string(CodeDBUnavailable) ||
		string(app.CodeAuditWriteFailed) != string(CodeAuditWriteFailed) ||
		string(app.CodeInternalError) != string(CodeInternalError) {
		t.Fatal("internal/app 错误码字面值与根包注册表不一致")
	}
}
