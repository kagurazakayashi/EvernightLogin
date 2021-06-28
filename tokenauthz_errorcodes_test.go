package login

import (
	"errors"
	"fmt"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/tokenauthz"
)

// TestTokenAuthorizationErrorCodesRegistered 验证联合授权判定使用的错误码全部
// 已在根包注册表登记、HTTP 映射与手册一致，且字面值不漂移；本步不新增错误码。
func TestTokenAuthorizationErrorCodesRegistered(t *testing.T) {
	decisionCodes := []struct {
		code     tokenauthz.ErrorCode
		wantHTTP int
	}{
		{tokenauthz.CodeReqInvalid, 400},
		{tokenauthz.CodeAccessDenied, 403},
		{tokenauthz.CodeTokenInvalid, 401},
		{tokenauthz.CodeTokenExpired, 401},
		{tokenauthz.CodeTokenRevoked, 401},
		{tokenauthz.CodeTokenAudienceMismatch, 403},
		{tokenauthz.CodeClientAuthFailed, 401},
		{tokenauthz.CodeClientDisabled, 403},
		{tokenauthz.CodeUserDisabled, 403},
		{tokenauthz.CodeAppMembershipRequired, 403},
		{tokenauthz.CodePermissionRequired, 403},
		{tokenauthz.CodePermissionDisabled, 403},
		{tokenauthz.CodePermissionUnknown, 400},
		{tokenauthz.CodeAppScopeMismatch, 403},
		{tokenauthz.CodeResourceForbidden, 403},
		{tokenauthz.CodeAuthzUnavailable, 503},
		{tokenauthz.CodeInternalError, 500},
	}
	for _, test := range decisionCodes {
		definition, ok := LookupErrorCode(ErrorCode(test.code))
		if !ok {
			t.Errorf("判定错误码 %q 未在根包注册表登记", test.code)
			continue
		}
		if definition.HTTPStatus != test.wantHTTP {
			t.Errorf("错误码 %q HTTP 状态 = %d，期望 %d", test.code, definition.HTTPStatus, test.wantHTTP)
		}
		if got := tokenauthz.MessageOf(test.code); got == "" {
			t.Errorf("错误码 %q 缺少直白中文说明", test.code)
		} else if got != definition.DefaultMessage {
			t.Errorf("错误码 %q 说明 = %q，与注册表默认消息 %q 不一致", test.code, got, definition.DefaultMessage)
		}
	}

	cases := []struct {
		name     string
		err      error
		wantCode tokenauthz.ErrorCode
		wantHTTP int
	}{
		{"非法请求", fmt.Errorf("%w: bad", tokenauthz.ErrInvalidRequest), tokenauthz.CodeReqInvalid, 400},
		{"不可信调用者", tokenauthz.ErrCallerUntrusted, tokenauthz.CodeAccessDenied, 403},
		{"依赖不可用", fmt.Errorf("%w: db", tokenauthz.ErrUnavailable), tokenauthz.CodeAuthzUnavailable, 503},
		{"未分类错误", errors.New("unclassified"), tokenauthz.CodeInternalError, 500},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			code := tokenauthz.CodeOf(test.err)
			if code != test.wantCode {
				t.Fatalf("CodeOf(%v) = %q，期望 %q", test.err, code, test.wantCode)
			}
			definition, ok := LookupErrorCode(ErrorCode(code))
			if !ok {
				t.Fatalf("错误码 %q 未登记", code)
			}
			if definition.HTTPStatus != test.wantHTTP {
				t.Errorf("错误码 %q HTTP 状态 = %d，期望 %d", code, definition.HTTPStatus, test.wantHTTP)
			}
		})
	}

	// 字面值必须与根包注册表一致（不得自造新码或改变既有码含义）。
	literals := []struct {
		internal tokenauthz.ErrorCode
		root     ErrorCode
	}{
		{tokenauthz.CodeReqInvalid, CodeReqInvalid},
		{tokenauthz.CodeAccessDenied, CodeAccessDenied},
		{tokenauthz.CodeTokenInvalid, CodeTokenInvalid},
		{tokenauthz.CodeTokenExpired, CodeTokenExpired},
		{tokenauthz.CodeTokenRevoked, CodeTokenRevoked},
		{tokenauthz.CodeTokenAudienceMismatch, CodeTokenAudienceMismatch},
		{tokenauthz.CodeClientAuthFailed, CodeClientAuthFailed},
		{tokenauthz.CodeClientDisabled, CodeClientDisabled},
		{tokenauthz.CodeUserDisabled, CodeUserDisabled},
		{tokenauthz.CodeAppMembershipRequired, CodeAppMembershipRequired},
		{tokenauthz.CodePermissionRequired, CodePermissionRequired},
		{tokenauthz.CodePermissionDisabled, CodePermissionDisabled},
		{tokenauthz.CodePermissionUnknown, CodePermissionUnknown},
		{tokenauthz.CodeAppScopeMismatch, CodeAppScopeMismatch},
		{tokenauthz.CodeResourceForbidden, CodeResourceForbidden},
		{tokenauthz.CodeAuthzUnavailable, CodeAuthzUnavailable},
		{tokenauthz.CodeInternalError, CodeInternalError},
	}
	for _, literal := range literals {
		if string(literal.internal) != string(literal.root) {
			t.Errorf("错误码字面值不一致：internal=%q root=%q", literal.internal, literal.root)
		}
	}
}
