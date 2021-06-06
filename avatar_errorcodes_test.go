package login

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/avatar"
)

// TestAvatarErrorCodesRegistered 验证头像领域只复用根包已登记错误码（46 个），
// 不新增错误码；远程目标被策略拒绝与普通请求错误分别映射到既有码。
func TestAvatarErrorCodesRegistered(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode avatar.ErrorCode
		wantHTTP int
	}{
		{name: "非法请求", err: fmt.Errorf("%w: bad", avatar.ErrInvalidRequest), wantCode: avatar.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "图片无效", err: avatar.ErrInvalidImage, wantCode: avatar.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "图片过大", err: avatar.ErrImageTooLarge, wantCode: avatar.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "类型不支持", err: avatar.ErrUnsupportedMedia, wantCode: avatar.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "拒绝 SVG", err: avatar.ErrSVGNotAllowed, wantCode: avatar.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "类型不一致", err: avatar.ErrContentTypeMismatch, wantCode: avatar.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "远程不可用", err: avatar.ErrRemoteUnavailable, wantCode: avatar.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "远程目标被拒", err: avatar.ErrRemoteBlocked, wantCode: avatar.CodeResourceForbidden, wantHTTP: http.StatusForbidden},
		{name: "无权访问", err: avatar.ErrAccessDenied, wantCode: avatar.CodeAccessDenied, wantHTTP: http.StatusForbidden},
		{name: "用户不存在", err: avatar.ErrUserNotFound, wantCode: avatar.CodeChallengeInvalid, wantHTTP: http.StatusBadRequest},
		{name: "版本冲突", err: avatar.ErrVersionConflict, wantCode: avatar.CodeConflict, wantHTTP: http.StatusConflict},
		{name: "文件存储不可用", err: avatar.ErrStorageUnavailable, wantCode: avatar.CodeDBUnavailable, wantHTTP: http.StatusServiceUnavailable},
		{name: "记录存储不可用", err: avatar.ErrStoreUnavailable, wantCode: avatar.CodeDBUnavailable, wantHTTP: http.StatusServiceUnavailable},
		{name: "审计不可用", err: avatar.ErrAuditUnavailable, wantCode: avatar.CodeAuditWriteFailed, wantHTTP: http.StatusServiceUnavailable},
		{name: "选项无效", err: avatar.ErrOptionsInvalid, wantCode: avatar.CodeInternalError, wantHTTP: http.StatusInternalServerError},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := avatar.CodeOf(test.err)
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
	if len(RegisteredErrorCodes()) != 46 {
		t.Errorf("错误码注册表数量 = %d，期望 46（头像模块不新增错误码）", len(RegisteredErrorCodes()))
	}
}
