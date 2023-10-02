package errs

import (
	"errors"
	"fmt"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/group"
)

// TestGroupErrorCodesRegistered 验证用户组领域错误映射到已登记错误码。
func TestGroupErrorCodesRegistered(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode group.ErrorCode
		wantHTTP int
	}{
		{name: "非法请求", err: fmt.Errorf("%w: bad", group.ErrInvalidRequest), wantCode: group.CodeReqInvalid, wantHTTP: 400},
		{name: "用户组不存在", err: group.ErrGroupNotFound, wantCode: group.CodeReqInvalid, wantHTTP: 400},
		{name: "作用范围无效", err: group.ErrScopeInvalid, wantCode: group.CodeReqInvalid, wantHTTP: 400},
		{name: "成员不合格", err: group.ErrMemberNotEligible, wantCode: group.CodeUserDisabled, wantHTTP: 403},
		{name: "应用不可用", err: group.ErrApplicationInactive, wantCode: group.CodeClientDisabled, wantHTTP: 403},
		{name: "组键冲突", err: group.ErrGroupKeyTaken, wantCode: group.CodeConflict, wantHTTP: 409},
		{name: "并发冲突", err: group.ErrStateConflict, wantCode: group.CodeConflict, wantHTTP: 409},
		{name: "未获准", err: group.ErrAccessDenied, wantCode: group.CodeAccessDenied, wantHTTP: 403},
		{name: "存储不可用", err: group.ErrStoreUnavailable, wantCode: group.CodeDBUnavailable, wantHTTP: 503},
		{name: "审计不可用", err: group.ErrAuditUnavailable, wantCode: group.CodeAuditWriteFailed, wantHTTP: 503},
		{name: "未知错误", err: errors.New("unclassified"), wantCode: group.CodeInternalError, wantHTTP: 500},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := group.CodeOf(test.err)
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
	if string(group.CodeReqInvalid) != string(CodeReqInvalid) ||
		string(group.CodeConflict) != string(CodeConflict) ||
		string(group.CodeAccessDenied) != string(CodeAccessDenied) ||
		string(group.CodeClientDisabled) != string(CodeClientDisabled) ||
		string(group.CodeUserDisabled) != string(CodeUserDisabled) ||
		string(group.CodeDBUnavailable) != string(CodeDBUnavailable) ||
		string(group.CodeAuditWriteFailed) != string(CodeAuditWriteFailed) ||
		string(group.CodeInternalError) != string(CodeInternalError) {
		t.Fatal("internal/group 错误码字面值与根包注册表不一致")
	}
}
