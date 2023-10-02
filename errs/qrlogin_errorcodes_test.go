package errs

import (
	"errors"
	"fmt"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/qrlogin"
)

// TestQRLoginErrorCodesRegistered 验证扫码登录判定/拒绝错误码全部复用既有已登记
// 错误码（不新增码），并核对 HTTP 映射与字面值一致性。
func TestQRLoginErrorCodesRegistered(t *testing.T) {
	codes := []struct {
		code     qrlogin.ErrorCode
		wantHTTP int
	}{
		{qrlogin.CodeReqInvalid, 400},
		{qrlogin.CodeAuthFailed, 401},
		{qrlogin.CodeAccessDenied, 403},
		{qrlogin.CodeChallengeInvalid, 400},
		{qrlogin.CodeConflict, 409},
		{qrlogin.CodeRateLimited, 429},
		{qrlogin.CodeClientDisabled, 403},
		{qrlogin.CodeDBUnavailable, 503},
		{qrlogin.CodeAuditWriteFailed, 503},
		{qrlogin.CodeInternalError, 500},
	}
	for _, test := range codes {
		definition, ok := LookupErrorCode(ErrorCode(test.code))
		if !ok {
			t.Errorf("扫码登录错误码 %q 未在根包注册表登记", test.code)
			continue
		}
		if definition.HTTPStatus != test.wantHTTP {
			t.Errorf("错误码 %q HTTP 状态 = %d，期望 %d", test.code, definition.HTTPStatus, test.wantHTTP)
		}
	}

	cases := []struct {
		name     string
		err      error
		wantCode qrlogin.ErrorCode
	}{
		{"非法请求", fmt.Errorf("%w: bad", qrlogin.ErrInvalidRequest), qrlogin.CodeReqInvalid},
		{"功能未启用", qrlogin.ErrQRLoginDisabled, qrlogin.CodeAccessDenied},
		{"跨应用或未授权", qrlogin.ErrAccessDenied, qrlogin.CodeAccessDenied},
		{"用户拒绝", qrlogin.ErrRequestDenied, qrlogin.CodeAccessDenied},
		{"应用不可用", qrlogin.ErrClientUnavailable, qrlogin.CodeClientDisabled},
		{"确认端会话无效", qrlogin.ErrSessionInvalid, qrlogin.CodeAuthFailed},
		{"请求不存在", qrlogin.ErrRequestNotFound, qrlogin.CodeChallengeInvalid},
		{"请求过期", qrlogin.ErrRequestExpired, qrlogin.CodeChallengeInvalid},
		{"请求已取消", qrlogin.ErrRequestCancelled, qrlogin.CodeChallengeInvalid},
		{"尚未批准", qrlogin.ErrRequestNotApproved, qrlogin.CodeChallengeInvalid},
		{"已经领取", qrlogin.ErrAlreadyClaimed, qrlogin.CodeChallengeInvalid},
		{"版本冲突", qrlogin.ErrVersionConflict, qrlogin.CodeConflict},
		{"限流", qrlogin.ErrRateLimited, qrlogin.CodeRateLimited},
		{"存储不可用", qrlogin.ErrStoreUnavailable, qrlogin.CodeDBUnavailable},
		{"审计不可用", qrlogin.ErrAuditUnavailable, qrlogin.CodeAuditWriteFailed},
		{"未分类", errors.New("unclassified"), qrlogin.CodeInternalError},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := qrlogin.CodeOf(test.err); got != test.wantCode {
				t.Fatalf("CodeOf(%v) = %q，期望 %q", test.err, got, test.wantCode)
			}
			if _, ok := LookupErrorCode(ErrorCode(qrlogin.CodeOf(test.err))); !ok {
				t.Fatalf("错误码 %q 未登记", qrlogin.CodeOf(test.err))
			}
		})
	}

	// 字面值与根包注册表一致（不得改变既有码含义或自造新码）。
	literals := []struct {
		internal qrlogin.ErrorCode
		root     ErrorCode
	}{
		{qrlogin.CodeReqInvalid, CodeReqInvalid},
		{qrlogin.CodeAuthFailed, CodeAuthFailed},
		{qrlogin.CodeAccessDenied, CodeAccessDenied},
		{qrlogin.CodeChallengeInvalid, CodeChallengeInvalid},
		{qrlogin.CodeConflict, CodeConflict},
		{qrlogin.CodeRateLimited, CodeRateLimited},
		{qrlogin.CodeClientDisabled, CodeClientDisabled},
		{qrlogin.CodeDBUnavailable, CodeDBUnavailable},
		{qrlogin.CodeAuditWriteFailed, CodeAuditWriteFailed},
		{qrlogin.CodeInternalError, CodeInternalError},
	}
	for _, literal := range literals {
		if string(literal.internal) != string(literal.root) {
			t.Errorf("错误码字面值不一致：internal=%q root=%q", literal.internal, literal.root)
		}
	}
}
